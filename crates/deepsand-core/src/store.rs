//! Persistence for projects, grants and settings.
//!
//! One JSON document, written atomically. It is deliberately human-readable:
//! the grants list is the sandbox's entire authority surface, and an operator
//! should be able to audit it with a text editor.

use crate::error::{Result, SandboxError};
use crate::model::*;
use crate::paths::{self, PathGuards};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Upper bound on shares per project. Beyond this the operator is almost
/// certainly looking at a runaway loop rather than a real need, and every grant
/// costs review attention.
pub const MAX_GRANTS_PER_PROJECT: usize = 64;

#[derive(Debug)]
pub struct Store {
    /// Set when `state.json` could not be read and the rolling backup was used instead.
    ///
    /// Surfaced so the app can say so. Recovering silently would leave the operator
    /// wondering why a recent change is missing.
    recovered_from_backup: bool,
    /// The set-aside file this state was rescued from, when it came from one.
    recovered_from_salvage: Option<PathBuf>,
    /// Whether `save` may promote the current `state.json` into the backup slot.
    ///
    /// True for every store that came from a file -- the live one, the rolling backup, a
    /// set-aside copy -- and for a genuine first run, where whatever is in the file was
    /// written by this app moments ago and there is nothing to protect.
    ///
    /// False only for a substitute: a store built because the saved configuration could
    /// not be read at all. Its state is a guess, and copying a guess into the backup slot
    /// is how an empty state became the only state an operator had left.
    may_rotate_backup: bool,
    data_dir: PathBuf,
    guards: PathGuards,
    state: StoreDocument,
}

impl Store {
    /// Platform default: `%LOCALAPPDATA%\Deepsand\data`,
    /// `~/.local/share/Deepsand`, `~/Library/Application Support/Deepsand`.
    ///
    /// The trailing `data` segment matters on Windows. The NSIS installer with
    /// `installMode: currentUser` puts the program in `%LOCALAPPDATA%\Deepsand`,
    /// so using that same directory for state would mix `deepsand-app.exe` and
    /// `uninstall.exe` in with the operator's projects and grants. Keeping user
    /// data one level down separates the two, and means the uninstaller only
    /// removes what it installed instead of taking the project database with it.
    pub fn default_data_dir() -> PathBuf {
        directories::BaseDirs::new()
            .map(|b| b.data_local_dir().join("Deepsand").join("data"))
            .unwrap_or_else(|| PathBuf::from(".deepsand"))
    }

    pub fn default_data_dir_for(home: &Path) -> PathBuf {
        if cfg!(windows) {
            home.join("AppData")
                .join("Local")
                .join("Deepsand")
                .join("data")
        } else if cfg!(target_os = "macos") {
            home.join("Library")
                .join("Application Support")
                .join("Deepsand")
        } else {
            home.join(".local").join("share").join("Deepsand")
        }
    }

    pub fn load(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let data_dir = data_dir.into();
        let home = directories::BaseDirs::new()
            .map(|b| b.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let deepcode_config = home.join(".deepcode");
        let guards = PathGuards::new(&home, &data_dir, &deepcode_config);

        std::fs::create_dir_all(&data_dir)?;
        restict_permissions(&data_dir);

        let state_path = data_dir.join("state.json");
        let rolling = data_dir.join("state.json.bak");

        // Everything this function returns came from a file or from a first run, so
        // rotation is allowed. Only `fallback` sets this false. See `save`.
        let may_rotate_backup = true;
        let mut recovered_from_backup = false;
        let mut recovered_from_salvage: Option<PathBuf> = None;
        let mut corrupt: Option<SandboxError> = None;

        let mut state = match read_state(&state_path) {
            ReadOutcome::Loaded(parsed) => Some(parsed),
            ReadOutcome::Missing => None,
            // Deliberately *not* treated as corruption, and deliberately not replaced
            // with defaults: the bytes may be fine and the file merely unopenable right
            // now. Refusing to start loses nothing; starting empty and saving loses
            // everything, which is exactly what happened before this branch existed.
            ReadOutcome::Unreadable(message) => {
                return Err(SandboxError::StateUnreadable {
                    path: state_path.clone(),
                    message,
                })
            }
            // Written by a different version. Reported and left exactly where it is: the
            // file is intact, and it is probably the only copy of what it says.
            ReadOutcome::Incompatible(message) => {
                return Err(SandboxError::StateIncompatible {
                    path: state_path.clone(),
                    message,
                })
            }
            ReadOutcome::Corrupt(message) => {
                // Keep the file: it is worthless to the app but it may be salvageable by
                // hand, and overwriting it would destroy that chance.
                let aside = data_dir.join(format!("state.corrupt-{}.json", crate::now_ms()));
                let _ = std::fs::rename(&state_path, &aside);
                corrupt = Some(SandboxError::StateCorrupt {
                    path: state_path.clone(),
                    message: format!(
                        "{} It was moved to {} so nothing is lost.",
                        message,
                        aside.display()
                    ),
                });
                None
            }
        };

        // The rolling backup holds the last state that was written successfully. Trying
        // it turns a crash from "everything is gone" into "one change is missing".
        if state.is_none() {
            if let ReadOutcome::Loaded(parsed) = read_state(&rolling) {
                recovered_from_backup = true;
                state = Some(parsed);
            }
        }

        // Then the dated copies, newest first. Both the live file and its rolling backup can
        // be lost to one crash, and this is what survives it: the state as of an earlier day,
        // named in the notice so the operator can see how far back it goes.
        if state.is_none() {
            for (path, _) in snapshots(&data_dir) {
                if let ReadOutcome::Loaded(parsed) = read_state(&path) {
                    if !parsed.projects.is_empty() {
                        recovered_from_salvage = Some(path);
                        state = Some(parsed);
                        break;
                    }
                }
            }
        }

        // Then the copies this app set aside as corrupt. Two rules, and the second one was
        // learned the hard way: on a real data directory, an *empty but valid* rolling
        // backup answered first and the rescue never ran, so the operator was shown an
        // empty project list while five projects sat in the file beside it.
        //
        // So a set-aside copy is preferred when the live file had to be set aside *and*
        // what we have so far has no projects -- an empty answer is far more likely to be
        // wreckage than an operator with no projects left, and the notice names the file
        // that was used.
        //
        // Deliberately not "the copy with the most projects" in general: an operator who
        // deletes a project and then crashes would find it resurrected from an older copy,
        // which is its own kind of corruption. The richest copy only wins among copies
        // that were already set aside, where there is nothing better to go on.
        if corrupt.is_some() && state.as_ref().map_or(true, |doc| doc.projects.is_empty()) {
            if let Some((path, parsed)) = best_salvage(&data_dir) {
                if !parsed.projects.is_empty() {
                    recovered_from_backup = false;
                    recovered_from_salvage = Some(path);
                    state = Some(parsed);
                }
            }
        }

        let mut state = match state {
            Some(parsed) => parsed,
            None => match corrupt {
                // A file existed and neither the backup nor any set-aside copy could be
                // read. The caller decides what to say; a silent default here is what
                // made the loss invisible last time.
                Some(err) => return Err(err),
                // No file at all: a first run.
                None => StoreDocument::default(),
            },
        };
        Self::migrate(&mut state);
        state.version = STATE_VERSION;

        let store = Self {
            data_dir,
            guards,
            state,
            recovered_from_backup,
            recovered_from_salvage,
            may_rotate_backup,
        };
        store.save()?;
        store.snapshot_if_stale();
        Ok(store)
    }

    /// Keep a dated copy of the state, at most one a day, and the newest few of those.
    ///
    /// One rolling backup is not enough against the failure this machine produces: it lost the
    /// contents of `state.json` twice, and one crash can catch a file and its rotation
    /// together. This is what is left when both are gone -- the state as of some earlier day --
    /// and the file is a few KB, written from the file that was just read successfully.
    ///
    /// Best effort by design: nothing here may stop the app from starting.
    fn snapshot_if_stale(&self) {
        const KEEP: usize = 5;
        const DAY_MS: i64 = 24 * 60 * 60 * 1000;

        // Nothing worth keeping yet. A first run would otherwise fill the day's slot with an
        // empty state, and the copy that matters -- taken once the operator has projects --
        // would wait until tomorrow.
        if self.state.projects.is_empty() {
            return;
        }

        let existing = snapshots(&self.data_dir);
        if let Some((_, newest)) = existing.first() {
            let age = crate::now_ms() - *newest as i64;
            if age < DAY_MS {
                return;
            }
        }
        let Ok(bytes) = std::fs::read(self.data_dir.join("state.json")) else {
            return;
        };
        // An empty or NUL-filled file is exactly the thing this is protection against, and
        // copying it would put the damage in the slot that is supposed to survive it.
        if bytes.is_empty() || bytes.contains(&0) {
            return;
        }
        let _ = std::fs::write(
            snapshot_path(&self.data_dir, crate::now_ms().max(0) as u64),
            bytes,
        );
        // Keep the newest KEEP including the one just written.
        for (old, _) in existing.into_iter().skip(KEEP.saturating_sub(1)) {
            let _ = std::fs::remove_file(old);
        }
    }

    /// A store that opens without having read anything, for the case where the saved
    /// configuration could not be read at all.
    ///
    /// It exists so the app can still start and explain itself, and it is the reason
    /// `save` has a rotation rule: this store's state is a substitute, not the record,
    /// and letting it into the backup slot would destroy the last good copy while
    /// pretending to help.
    pub fn fallback(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let home = directories::BaseDirs::new()
            .map(|b| b.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let deepcode_config = home.join(".deepcode");
        let guards = PathGuards::new(&home, &data_dir, &deepcode_config);
        let mut state = StoreDocument::default();
        Self::migrate(&mut state);
        state.version = STATE_VERSION;
        Self {
            data_dir,
            guards,
            state,
            recovered_from_backup: false,
            recovered_from_salvage: None,
            may_rotate_backup: false,
        }
    }

    /// Whether this store was recovered from the rolling backup.
    pub fn recovered_from_backup(&self) -> bool {
        self.recovered_from_backup
    }

    /// The set-aside copy this store was rescued from, when it was rescued rather than
    /// loaded. Reported so the operator is told which file came back.
    pub fn recovered_from_salvage(&self) -> Option<&Path> {
        self.recovered_from_salvage.as_deref()
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn guards(&self) -> &PathGuards {
        &self.guards
    }

    pub fn state(&self) -> &StoreDocument {
        &self.state
    }

    pub fn settings(&self) -> &AppSettings {
        &self.state.settings
    }

    pub fn settings_mut(&mut self) -> &mut AppSettings {
        &mut self.state.settings
    }

/// Bring a store forward across a change in what the defaults mean.
///
/// Hardening used to be opt-in and defaulted to off, so a normal installation ran
/// Docker's permissive profile -- the one that permits `AF_VSOCK`. Existing stores are
/// moved across once. This is a deliberate change to an operator's setting and is only
/// defensible because the old value was the default nobody chose, and because running
/// without this control is what made the escape possible.

fn migrate(state: &mut StoreDocument) {
    if state.version >= STATE_VERSION {
        return;
    }
    if state.settings.security.seccomp == crate::model::SeccompProfile::Default {
        state.settings.security.seccomp = crate::model::SeccompProfile::Hardened;
    }
}

    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        let path = self.data_dir.join("state.json");
        let tmp = self.data_dir.join("state.json.tmp");
        let json = serde_json::to_string_pretty(&self.state)?;

        // Flush before renaming. The rename is atomic but not durable on its own: the
        // directory entry can be committed while the contents are still buffered, and a
        // power loss then yields a file of the right size full of NULs. That is exactly
        // how the previous state file was destroyed.
        {
            use std::io::Write as _;
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }

        // The previous good file becomes the rolling backup, written the same way so it
        // can never be a half-file either.
        //
        // Only when this store's state actually came from a file. A fallback store is a
        // substitute for something that could not be read, and copying a substitute into
        // the backup slot destroys the last good copy while looking careful.
        if self.may_rotate_backup && path.exists() {
            let backup = self.data_dir.join("state.json.bak");
            let staged = self.data_dir.join("state.json.bak.tmp");
            if std::fs::copy(&path, &staged).is_ok() {
                if let Ok(handle) = std::fs::OpenOptions::new().write(true).open(&staged) {
                    let _ = handle.sync_all();
                }
                let _ = std::fs::rename(&staged, &backup);
            }
        }

        std::fs::rename(&tmp, &path)?;
        restict_permissions(&self.data_dir);
        Ok(())
    }

    /* --------------------------------------------------------------------- */
    /* Projects                                                              */
    /* --------------------------------------------------------------------- */

    pub fn projects(&self) -> &[Project] {
        &self.state.projects
    }

    pub fn project(&self, id: &str) -> Result<&Project> {
        self.state
            .projects
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(|| SandboxError::ProjectNotFound(id.to_string()))
    }

    pub fn project_mut(&mut self, id: &str) -> Result<&mut Project> {
        self.state
            .projects
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| SandboxError::ProjectNotFound(id.to_string()))
    }

    pub fn create_project(&mut self, name: &str, root_dir: &str) -> Result<Project> {
        let name = name.trim();
        if name.is_empty() {
            return Err(SandboxError::path("the project needs a name"));
        }
        if name.len() > 120 {
            return Err(SandboxError::path("the project name is too long"));
        }

        let root = paths::canonical_existing_dir(root_dir)?;
        paths::guard_mountable(&root, &self.guards)?;

        // Two projects sharing a root, or a root nested inside another
        // project's root, would silently widen access through the side door.
        for existing in &self.state.projects {
            let existing_root = PathBuf::from(&existing.root_dir);
            if paths::overlaps(&existing_root, &root) {
                return Err(SandboxError::policy(format!(
                    "'{}' overlaps the working directory of project '{}' ({}). Pick a directory that is not inside another project.",
                    root.display(),
                    existing.name,
                    existing_root.display()
                )));
            }
        }

        let taken: Vec<String> = self.state.projects.iter().map(|p| p.slug.clone()).collect();
        let slug = paths::unique_slug(&paths::slugify(name), |c| taken.iter().any(|t| t == c));

        let project = Project {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            slug,
            root_dir: root.to_string_lossy().to_string(),
            created_at_ms: crate::now_ms(),
            network: self.state.settings.default_network.clone(),
            limits: self.state.settings.default_limits.clone(),
            // Left empty on purpose: an empty override means "inherit", so the
            // operator's own ~/.deepcode/settings.json keeps working. Deepsand's
            // defaults apply only when the host configuration says nothing.
            credentials: Credentials {
                source: CredentialSource::InheritHost,
                ..Credentials::default()
            },
            deepcode_mode: DeepCodeMode::AllowAll,
            allowed_roots: Vec::new(),
            requests_enabled: true,
            notes: String::new(),
            reasoning_effort: ReasoningEffort::default(),
            // `None` rather than the defaults spelled out, so a project keeps
            // tracking the catalogue: adding a utility to the defaults should reach
            // every project that never expressed an opinion about tools.
            tools: None,
        };

        self.state.grants.insert(project.id.clone(), Vec::new());
        self.state.projects.push(project.clone());
        self.ensure_project_dirs(&project.id)?;
        self.save()?;
        Ok(project)
    }

    pub fn update_project(&mut self, project: Project) -> Result<()> {
        let index = self
            .state
            .projects
            .iter()
            .position(|p| p.id == project.id)
            .ok_or_else(|| SandboxError::ProjectNotFound(project.id.clone()))?;
        self.state.projects[index] = project;
        self.save()
    }

    pub fn delete_project(&mut self, id: &str) -> Result<()> {
        let index = self
            .state
            .projects
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| SandboxError::ProjectNotFound(id.to_string()))?;
        self.state.projects.remove(index);
        self.state.grants.remove(id);
        self.save()?;
        // Leave the on-disk project directory alone: it holds session history
        // the operator may still want, and deleting it is not reversible.
        Ok(())
    }

    /// Per-project scratch space: spools, generated config, snapshots.
    pub fn project_dir(&self, project_id: &str) -> PathBuf {
        self.data_dir.join("projects").join(project_id)
    }

    pub fn requests_dir(&self, project_id: &str) -> PathBuf {
        self.project_dir(project_id).join("ipc").join("requests")
    }

    pub fn responses_dir(&self, project_id: &str) -> PathBuf {
        self.project_dir(project_id).join("ipc").join("responses")
    }

    pub fn state_dir(&self, project_id: &str) -> PathBuf {
        self.project_dir(project_id).join("state")
    }

    pub fn config_dir(&self, project_id: &str) -> PathBuf {
        self.project_dir(project_id).join("config")
    }

    pub fn audit_log(&self, project_id: &str) -> PathBuf {
        self.project_dir(project_id).join("permissions.log")
    }

    pub fn ensure_project_dirs(&self, project_id: &str) -> Result<()> {
        for dir in [
            self.requests_dir(project_id),
            self.responses_dir(project_id),
            self.state_dir(project_id),
            self.config_dir(project_id),
        ] {
            std::fs::create_dir_all(&dir)?;
        }
        Ok(())
    }

    /* --------------------------------------------------------------------- */
    /* Grants                                                                */
    /* --------------------------------------------------------------------- */

    pub fn grants(&self, project_id: &str) -> Vec<Grant> {
        self.state.grants.get(project_id).cloned().unwrap_or_default()
    }

    /// Grants that are still in force, dropping any that have expired.
    pub fn active_grants(&self, project_id: &str) -> Vec<Grant> {
        let now = crate::now_ms();
        self.grants(project_id).into_iter().filter(|g| !g.is_expired(now)).collect()
    }

    pub fn prune_expired_grants(&mut self) -> Result<usize> {
        let now = crate::now_ms();
        let mut removed = 0;
        for grants in self.state.grants.values_mut() {
            let before = grants.len();
            grants.retain(|g| !g.is_expired(now));
            removed += before - grants.len();
        }
        if removed > 0 {
            self.save()?;
        }
        Ok(removed)
    }

    /// Validate and record a new share.
    ///
    /// Everything is re-checked here even when the UI already checked it, so
    /// that no code path can add a grant the guards would refuse.
    pub fn add_grant(
        &mut self,
        project_id: &str,
        host_path: &str,
        access: Access,
        label: &str,
        purpose: &str,
        source: GrantSource,
    ) -> Result<Grant> {
        let project = self.project(project_id)?.clone();
        let root = paths::canonical_existing_dir(host_path)?;
        paths::guard_mountable(&root, &self.guards)?;

        let workspace = PathBuf::from(&project.root_dir);
        if paths::is_within(&workspace, &root) {
            return Err(SandboxError::policy(format!(
                "{} is already inside the project workspace ({}), so DeepCode can already reach it.",
                root.display(),
                workspace.display()
            )));
        }

        let existing = self.grants(project_id);
        if existing.len() >= MAX_GRANTS_PER_PROJECT {
            return Err(SandboxError::policy(format!(
                "this project already has {MAX_GRANTS_PER_PROJECT} shares. Remove some before adding more."
            )));
        }
        for grant in &existing {
            let other = PathBuf::from(&grant.host_path);
            if paths::overlaps(&other, &root) {
                return Err(SandboxError::policy(format!(
                    "{} overlaps the existing share {} ({}). Nested mounts shadow each other, so Deepsand refuses them.",
                    root.display(),
                    grant.label,
                    other.display()
                )));
            }
        }
        if paths::is_within(&root, &workspace) {
            return Err(SandboxError::policy(format!(
                "{} contains the project workspace. Share a narrower directory instead.",
                root.display()
            )));
        }

        let default_label = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "shared".to_string());
        let label = if label.trim().is_empty() { default_label } else { label.trim().to_string() };

        let taken: Vec<String> = existing.iter().map(|g| g.slug.clone()).collect();
        let slug = paths::unique_slug(&paths::slugify(&label), |c| taken.iter().any(|t| t == c));

        let grant = Grant {
            id: uuid::Uuid::new_v4().to_string(),
            project_id: project_id.to_string(),
            host_path: root.to_string_lossy().to_string(),
            container_path: paths::container_mount_path(&slug),
            slug,
            access,
            label,
            purpose: purpose.trim().to_string(),
            source,
            created_at_ms: crate::now_ms(),
            expires_at_ms: None,
        };

        self.state
            .grants
            .entry(project_id.to_string())
            .or_default()
            .push(grant.clone());
        self.save()?;
        Ok(grant)
    }

    pub fn update_grant_access(&mut self, project_id: &str, grant_id: &str, access: Access) -> Result<Grant> {
        let grants = self
            .state
            .grants
            .get_mut(project_id)
            .ok_or_else(|| SandboxError::GrantNotFound(grant_id.to_string()))?;
        let grant = grants
            .iter_mut()
            .find(|g| g.id == grant_id)
            .ok_or_else(|| SandboxError::GrantNotFound(grant_id.to_string()))?;
        grant.access = access;
        let out = grant.clone();
        self.save()?;
        Ok(out)
    }

    pub fn revoke_grant(&mut self, project_id: &str, grant_id: &str) -> Result<Grant> {
        let grants = self
            .state
            .grants
            .get_mut(project_id)
            .ok_or_else(|| SandboxError::GrantNotFound(grant_id.to_string()))?;
        let index = grants
            .iter()
            .position(|g| g.id == grant_id)
            .ok_or_else(|| SandboxError::GrantNotFound(grant_id.to_string()))?;
        let removed = grants.remove(index);
        self.save()?;
        Ok(removed)
    }

    pub fn find_grant_by_host_path(&self, project_id: &str, host_path: &Path) -> Option<Grant> {
        self.grants(project_id)
            .into_iter()
            .find(|g| paths::is_within(Path::new(&g.host_path), host_path))
    }

    /// Append a line to the project's permission audit log.
    pub fn append_audit(&self, project_id: &str, line: &str) {
        use std::io::Write;
        let path = self.audit_log(project_id);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(file, "{} {}", crate::iso_from_ms(crate::now_ms()), line);
        }
    }

    pub fn read_audit(&self, project_id: &str, limit: usize) -> Vec<String> {
        let path = self.audit_log(project_id);
        let Ok(raw) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        // Read as text: a torn write can leave a line of NULs, and this list is read by a
        // person looking for what happened. It shows the lines that were written, or nothing.
        let mut lines: Vec<String> = raw
            .lines()
            .filter_map(crate::docker::sanitize_output_line)
            .collect();
        if lines.len() > limit {
            lines = lines.split_off(lines.len() - limit);
        }
        lines
    }

    pub fn duplicate_grant_views(&self) -> BTreeMap<String, usize> {
        self.state
            .grants
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect()
    }
}

/// `state.snapshot-<epoch ms>.json`, the dated copies `Store::snapshot_if_stale` keeps.
fn snapshot_path(data_dir: &Path, stamp: u64) -> PathBuf {
    data_dir.join(format!("state.snapshot-{stamp}.json"))
}

/// Every dated copy in the directory, newest first.
fn snapshots(data_dir: &Path) -> Vec<(PathBuf, u64)> {
    let mut found: Vec<(PathBuf, u64)> = std::fs::read_dir(data_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            let stamp = name
                .strip_prefix("state.snapshot-")?
                .strip_suffix(".json")?
                .parse()
                .ok()?;
            Some((entry.path(), stamp))
        })
        .collect();
    found.sort_by(|a, b| b.1.cmp(&a.1));
    found
}

/// Best-effort tightening of the state directory so the grants file is not
/// world-readable. On Windows this is a no-op because ACLs are inherited.
fn restict_permissions(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(dir) {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            let _ = std::fs::set_permissions(dir, perms);
        }
        let state = dir.join("state.json");
        if state.exists() {
            if let Ok(meta) = std::fs::metadata(&state) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&state, perms);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// What happened when the state file was read.
///
/// Four outcomes rather than `Option`, because the difference between them is the
/// difference between destroying an operator's projects and not:
///
/// * `Missing` and `Loaded` are ordinary.
/// * `Unreadable` means the bytes may be perfectly good and the file could not be
///   opened this instant. On Windows that is routinely transient -- an indexer, a
///   backup tool, or the rename in `save` holding the file for a moment -- so it is
///   retried, and then reported. It is *not* corruption, and treating it as corruption
///   renamed a valid five-project state aside and let the app start empty. That was a
///   real data loss, not a theoretical one.
/// * `Corrupt` means the bytes were read and could not be understood, which is what the
///   keep-aside path is for.
/// * `Incompatible` means the bytes *are* JSON and this build cannot map them onto its own
///   shape: an unknown variant, a missing field, a version from the future. That is a
///   version skew, not damage, and it must not be destroyed either. The file is exactly
///   what some other build of Deepsand wrote, and it is probably the only copy.
enum ReadOutcome {
    Loaded(StoreDocument),
    Missing,
    Unreadable(String),
    Corrupt(String),
    Incompatible(String),
}

/// Whether a parse failure looks like a file written by a different version of Deepsand
/// rather than a damaged one.
///
/// A file from another version is JSON; it just says something this build does not know.
/// serde reports that in a few recognisable ways, listed here. Anything else -- NULs, a
/// truncated write, a stray byte -- is left to be handled as damage.
fn is_version_skew(raw: &str, message: &str) -> bool {
    if !raw.trim_start().starts_with('{') {
        return false;
    }
    let markers = [
        "unknown variant",
        "missing field",
        "invalid type",
        "unknown field",
    ];
    if markers.iter().any(|marker| message.contains(marker)) {
        return true;
    }
    // A version from the future is the same problem stated plainly.
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.get("version").and_then(|version| version.as_u64()))
        .map(|version| version > STATE_VERSION as u64)
        .unwrap_or(false)
}

/// Parse a state file.
///
/// A zero-length file, or one full of NULs left by a power loss, parses as `Corrupt`:
/// the caller has set-aside copies and a rolling backup to try.
fn read_state(path: &Path) -> ReadOutcome {
    // A read that fails for a reason other than "there is no file" is retried before it
    // is believed. A sharing violation lasts milliseconds; believing the first one is
    // what cost an operator their projects.
    let mut last: Option<String> = None;
    for attempt in 0..3 {
        match std::fs::read_to_string(path) {
            Ok(raw) => {
                // The version is left as it was found: `migrate` needs it to tell an old
                // file from a current one, and clobbering it here made every file look
                // current.
                return match serde_json::from_str::<StoreDocument>(&raw) {
                    // Parsed, but written by a newer build. Loading it would be worse than
                    // refusing it: the fields this build does not know are dropped in
                    // memory, and the next save writes them gone.
                    Ok(doc) if doc.version > STATE_VERSION => ReadOutcome::Incompatible(format!(
                        "it records version {}, and this build understands {STATE_VERSION}",
                        doc.version
                    )),
                    Ok(doc) => ReadOutcome::Loaded(doc),
                    Err(err) => {
                        let message = err.to_string();
                        // JSON that this build cannot map is a version skew, not damage,
                        // and the two have different responses: a skew is reported and
                        // left alone, damage is set aside.
                        if is_version_skew(&raw, &message) {
                            ReadOutcome::Incompatible(message)
                        } else {
                            ReadOutcome::Corrupt(message)
                        }
                    }
                };
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return ReadOutcome::Missing,
            Err(err) => {
                last = Some(err.to_string());
                if attempt < 2 {
                    std::thread::sleep(std::time::Duration::from_millis(60));
                }
            }
        }
    }
    ReadOutcome::Unreadable(last.unwrap_or_else(|| "the file could not be opened".to_string()))
}

/// The richest state this data directory still holds, for the case where both the live
/// file and the rolling backup are unusable.
///
/// Only files this app set aside itself are considered -- `state.corrupt-*.json`. They
/// were kept on the promise that nothing is lost silently, and until now nothing ever
/// read them again, so a keep-aside copy was a loss with better paperwork. Files an
/// operator put there by hand are deliberately not considered: guessing which of those
/// is authoritative is not this function's decision to make.
///
/// The one with the most projects wins, and the newest wins a tie. Projects are what an
/// operator cannot re-create from memory; settings they can.
fn best_salvage(data_dir: &Path) -> Option<(PathBuf, StoreDocument)> {
    let entries = std::fs::read_dir(data_dir).ok()?;
    let mut best: Option<(PathBuf, StoreDocument, usize, std::time::SystemTime)> = None;

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("state.corrupt-") || !name.ends_with(".json") {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(doc) = serde_json::from_str::<StoreDocument>(&raw) else {
            continue;
        };
        let modified = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        let projects = doc.projects.len();
        let better = match &best {
            Some((_, _, best_projects, best_time)) => {
                projects > *best_projects || (projects == *best_projects && modified > *best_time)
            }
            None => true,
        };
        if better {
            best = Some((path, doc, projects, modified));
        }
    }

    best.map(|(path, doc, _, _)| (path, doc))
}

#[cfg(test)]
mod durability_tests {
    use super::*;

    /// A scratch data directory. Unique per call, because the test binary runs these in
    /// parallel and a shared directory would have them overwriting each other.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("deepsand-store-{name}-{}", crate::now_ms()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// The exact failure that was reported: a crash left `state.json` of the right size
    /// and full of NULs, because the rename was durable and the contents were not. The
    /// rolling backup is what stands between that and losing every project.
    #[test]
    fn a_nul_filled_state_file_falls_back_to_the_rolling_backup() {
        let dir = scratch("nul");

        let store = Store::load(&dir).expect("first run");
        // A second save promotes the first file to the backup.
        store.save().expect("second save");
        assert!(
            dir.join("state.json.bak").exists(),
            "a backup must exist after a second save"
        );

        let size = std::fs::metadata(dir.join("state.json")).unwrap().len() as usize;
        std::fs::write(dir.join("state.json"), vec![0u8; size]).expect("write NULs");

        let recovered = Store::load(&dir).expect("must recover rather than fail");
        assert!(
            recovered.recovered_from_backup(),
            "the store must report where it came from"
        );
        // And the unreadable file is kept, in case it can be salvaged by hand.
        let evidence = std::fs::read_dir(&dir).unwrap().flatten().any(|entry| {
            entry.file_name().to_string_lossy().starts_with("state.corrupt-")
        });
        assert!(evidence, "the unreadable file should have been preserved");
    }

    /// With nothing to fall back on, an unreadable file must be reported rather than
    /// silently replaced with defaults -- which is what made the loss invisible.
    #[test]
    fn an_unreadable_state_with_no_backup_is_reported() {
        let dir = scratch("no-backup");
        std::fs::write(dir.join("state.json"), vec![0u8; 64]).unwrap();
        assert!(
            Store::load(&dir).is_err(),
            "an unreadable file with no backup must not default silently"
        );
    }

    /// A missing file is a first run.
    #[test]
    fn a_missing_state_file_is_a_first_run() {
        let dir = scratch("fresh");
        let store = Store::load(&dir).expect("a first run must succeed");
        assert!(!store.recovered_from_backup());
    }

    /// A state file that cannot be *opened* is not a state file that is malformed.
    ///
    /// This is the bug that cost an operator five projects. A read that failed for a
    /// transient reason -- a sharing violation while another handle had the file, which
    /// is routine on Windows -- was treated as corruption, and the response to
    /// corruption is to move the file aside and carry on with an empty state. A
    /// directory in the file's place is used here because it fails to open every time,
    /// which is the honest way to test "could not be read" without racing a real lock.
    #[test]
    fn a_state_file_that_cannot_be_opened_is_not_corruption() {
        let dir = scratch("unopenable");
        std::fs::create_dir_all(dir.join("state.json")).unwrap();

        let err = Store::load(&dir).expect_err("an unopenable state must stop the load");
        assert!(
            matches!(err, SandboxError::StateUnreadable { .. }),
            "expected StateUnreadable, got {err:?}"
        );

        // And nothing was moved aside, which is the part that destroyed data: the file
        // may be perfectly good, so it must be left exactly where it is.
        let set_aside = std::fs::read_dir(&dir).unwrap().flatten().any(|entry| {
            entry.file_name().to_string_lossy().starts_with("state.corrupt-")
        });
        assert!(!set_aside, "a file that could not be read must not be treated as corrupt");
        assert!(dir.join("state.json").is_dir(), "the file must still be there");
    }

    /// Build a state holding `count` projects and return its serialised bytes.
    fn state_with_projects(dir: &Path, count: usize) -> String {
        let mut store = Store::load(dir).expect("donor store");
        // Beside the data directory, never inside it: the guard refuses a workspace that
        // overlaps the state directory, which is exactly what it is for.
        let workspaces = dir
            .parent()
            .expect("parent")
            .join(format!("{}-ws", dir.file_name().unwrap().to_string_lossy()));
        for index in 0..count {
            let workspace = workspaces.join(format!("p{index}"));
            std::fs::create_dir_all(&workspace).expect("workspace dir");
            store
                .create_project(&format!("project {index}"), &workspace.to_string_lossy())
                .expect("create project");
        }
        store.save().expect("save donor");
        std::fs::read_to_string(dir.join("state.json")).expect("read donor state")
    }

    /// The real incident, end to end: a valid state was misjudged as corrupt and set
    /// aside, and the app then started empty. It must come back by itself.
    #[test]
    fn a_valid_state_misjudged_as_corrupt_comes_back_by_itself() {
        let donor = scratch("salvage-donor");
        let good = state_with_projects(&donor, 3);

        let dir = scratch("salvage");
        // What the app had set aside when it decided the file was unreadable...
        std::fs::write(dir.join("state.corrupt-1.json"), &good).unwrap();
        // ...and what was left in its place, which is what a torn write leaves behind.
        std::fs::write(dir.join("state.json"), vec![0u8; 64]).unwrap();

        let store = Store::load(&dir).expect("must rescue rather than start empty");
        assert_eq!(store.projects().len(), 3, "the projects must come back");
        assert!(
            store.recovered_from_salvage().is_some(),
            "and the app must be able to say where they came from"
        );
    }

    /// When several set-aside copies exist, the one with the most projects wins: projects
    /// are what an operator cannot re-create from memory, and settings they can.
    #[test]
    fn salvage_prefers_the_copy_with_the_most_projects() {
        let donor = scratch("salvage-rank-donor");
        let big = state_with_projects(&donor, 4);
        let small = state_with_projects(&scratch("salvage-rank-small"), 1);

        let dir = scratch("salvage-rank");
        std::fs::write(dir.join("state.corrupt-1000.json"), &small).unwrap();
        std::fs::write(dir.join("state.corrupt-2000.json"), &big).unwrap();
        std::fs::write(dir.join("state.json"), vec![0u8; 32]).unwrap();

        let store = Store::load(&dir).expect("must rescue");
        assert_eq!(store.projects().len(), 4, "the richer copy must win");
    }

    /// The property that keeps a mixed-version installation working: what this build
    /// writes, every build still in circulation can read.
    ///
    /// The mode was renamed from `restricted` to `allowlisted` everywhere a person reads
    /// it, and the on-disk name deliberately stayed at the older one. A state file that
    /// says `allowlisted` is unreadable to a build that predates the rename, and an
    /// unreadable file was being treated as a corrupt one -- five projects, twice.
    #[test]
    fn an_older_build_can_read_what_this_one_writes() {
        let dir = scratch("compatible-name");
        let workspaces = dir.parent().unwrap().join(format!(
            "{}-ws",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(&workspaces).unwrap();

        let mut store = Store::load(&dir).expect("store");
        let project = store
            .create_project("website", &workspaces.to_string_lossy())
            .expect("project");
        store
            .project_mut(&project.id)
            .expect("project")
            .network = crate::model::NetworkPolicy::Allowlisted { allow: vec![] };
        store.save().expect("save");

        let written = std::fs::read_to_string(dir.join("state.json")).expect("read");
        assert!(
            written.contains("\"mode\": \"restricted\""),
            "the on-disk name must stay at the one older builds know: {written}"
        );
        assert!(
            !written.contains("\"allowlisted\""),
            "the newer name must not reach the file while an older build may read it"
        );

        // And the newer spelling is still read, so a file written by a build that used
        // it -- which is what this build did until now -- keeps its mode rather than
        // being rejected as an unknown variant.
        let newer_spelling = written.replace("\"restricted\"", "\"allowlisted\"");
        assert!(newer_spelling.contains("allowlisted"));
        let other = scratch("compatible-name-newer");
        std::fs::write(other.join("state.json"), &newer_spelling).unwrap();
        let read_back = Store::load(&other).expect("a file using the newer name must load");
        assert_eq!(
            read_back.project(&project.id).expect("project").network,
            crate::model::NetworkPolicy::Allowlisted { allow: vec![] }
        );

        // And it still round-trips to the mode the operator chose.
        let reloaded = Store::load(&dir).expect("reload");
        assert_eq!(
            reloaded.project(&project.id).expect("project").network,
            crate::model::NetworkPolicy::Allowlisted { allow: vec![] },
            "the mode must survive the older spelling"
        );
    }

    /// A file from a different version is not a damaged file. It is reported and left
    /// exactly where it is, because it is probably the only copy of what it says.
    #[test]
    fn a_state_file_from_a_newer_build_is_reported_and_left_alone() {
        let donor = scratch("newer-donor");
        let mut newer: serde_json::Value =
            serde_json::from_str(&state_with_projects(&donor, 1)).expect("json");
        newer["version"] = serde_json::json!(crate::model::STATE_VERSION + 7);
        // Something this build has never heard of, as a future version would have.
        newer["projects"][0]["network"] = serde_json::json!({ "mode": "some-future-mode" });

        let dir = scratch("newer");
        std::fs::write(
            dir.join("state.json"),
            serde_json::to_string_pretty(&newer).unwrap(),
        )
        .unwrap();

        let err = Store::load(&dir).expect_err("a file from the future must not be loaded");
        assert!(
            matches!(err, SandboxError::StateIncompatible { .. }),
            "expected StateIncompatible, got {err:?}"
        );
        assert!(dir.join("state.json").exists(), "the file must be left in place");
        let set_aside = std::fs::read_dir(&dir).unwrap().flatten().any(|entry| {
            entry.file_name().to_string_lossy().starts_with("state.corrupt-")
        });
        assert!(!set_aside, "a version skew must not be filed as corruption");
    }

    /// The case the replay against a real data directory found, which the tests above
    /// did not: a rolling backup that is perfectly readable and completely empty. It is
    /// what a previous recovery leaves behind, and it used to answer first, so the rescue
    /// never ran and the operator saw an empty project list with their projects in the
    /// file beside it.
    #[test]
    fn an_empty_rolling_backup_does_not_hide_a_set_aside_copy() {
        let donor = scratch("empty-backup-donor");
        let good = state_with_projects(&donor, 3);

        let dir = scratch("empty-backup");
        let empty = {
            // A valid state with no projects, written by the app itself.
            let fresh = scratch("empty-backup-fresh");
            std::fs::read_to_string(Store::load(&fresh).unwrap().data_dir().join("state.json")).unwrap()
        };
        std::fs::write(dir.join("state.corrupt-1.json"), &good).unwrap();
        std::fs::write(dir.join("state.json"), vec![0u8; 64]).unwrap();
        std::fs::write(dir.join("state.json.bak"), empty).unwrap();

        let store = Store::load(&dir).expect("must rescue");
        assert_eq!(
            store.projects().len(),
            3,
            "an empty backup must not stand in for a set-aside copy that has projects"
        );
        assert!(store.recovered_from_salvage().is_some());
        assert!(!store.recovered_from_backup(), "and it must name the right source");
    }

    /// A substitute store -- one built because nothing could be read -- must never
    /// promote its guess into the backup slot. That is the difference between "the app
    /// looks emptier than it should" and "the last good copy is gone".
    /// A healthy load keeps a dated copy, and a second load while it is fresh does not add
    /// another: the point is one a day, not one a start.
    #[test]
    fn a_healthy_load_keeps_a_dated_copy_and_does_not_add_another_while_it_is_fresh() {
        let dir = scratch("snapshot-once");
        let workspaces = dir.parent().unwrap().join(format!(
            "{}-ws",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(&workspaces).unwrap();

        {
            let mut store = Store::load(&dir).expect("first run");
            store
                .create_project("kept", &workspaces.to_string_lossy())
                .expect("project");
            store.save().expect("save");
            store.snapshot_if_stale();
        }
        assert_eq!(snapshots(&dir).len(), 1, "one dated copy");

        let _ = Store::load(&dir).expect("second load");
        assert_eq!(
            snapshots(&dir).len(),
            1,
            "still one: it is a day's copy, not a start's"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The case this exists for: the live file and the rolling backup are both gone, and the
    /// dated copy is what brings the projects back.
    #[test]
    fn a_state_lost_with_its_backup_comes_back_from_a_dated_copy() {
        let dir = scratch("snapshot-recovery");
        let workspaces = dir.parent().unwrap().join(format!(
            "{}-ws",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(&workspaces).unwrap();
        {
            let mut store = Store::load(&dir).expect("first run");
            // A first run keeps no dated copy: an empty one would hold the day's slot.
            assert!(snapshots(&dir).is_empty(), "nothing worth keeping yet");
            store
                .create_project("kept", &workspaces.to_string_lossy())
                .expect("a project to lose");
            store.save().expect("save");
            store.snapshot_if_stale();
        }
        assert_eq!(
            snapshots(&dir).len(),
            1,
            "a dated copy of the state that has something in it"
        );

        // Now lose both the live file and its rotation, the way a crash does: right size, no
        // contents.
        for name in ["state.json", "state.json.bak"] {
            let path = dir.join(name);
            if let Ok(raw) = std::fs::read(&path) {
                std::fs::write(&path, vec![0u8; raw.len()]).unwrap();
            }
        }

        let recovered = Store::load(&dir).expect("a dated copy is enough");
        assert_eq!(recovered.projects().len(), 1, "the project came back");
        assert_eq!(recovered.projects()[0].name, "kept");
        assert!(
            recovered
                .recovered_from_salvage()
                .is_some_and(|path| path.file_name().unwrap().to_string_lossy().starts_with("state.snapshot-")),
            "and the notice names the dated copy it used"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_dated_copies_are_pruned_to_the_newest_few() {
        let dir = scratch("snapshot-prune");
        let workspaces = dir.parent().unwrap().join(format!(
            "{}-ws",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(&workspaces).unwrap();
        {
            let mut store = Store::load(&dir).expect("first run");
            store
                .create_project("kept", &workspaces.to_string_lossy())
                .expect("project");
            store.save().expect("save");
        }
        // Seven copies, all older than a day: the next load writes one more and prunes.
        for n in 1..=7u64 {
            let stamp = (crate::now_ms().max(0) as u64).saturating_sub(n * 86_400_000);
            std::fs::write(snapshot_path(&dir, stamp), "{}").unwrap();
        }
        let _ = Store::load(&dir).expect("a load with old copies");

        let kept = snapshots(&dir);
        assert!(kept.len() <= 5, "kept {} dated copies", kept.len());
        assert!(
            kept.iter().any(|(path, _)| std::fs::metadata(path).is_ok()),
            "and the ones it kept are files"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An audit line that is not text is not shown. The same failure that filled a Dockerfile
    /// with NULs can land in this file, and it is the one the operator reads to find out what
    /// happened.
    #[test]
    fn an_audit_line_of_nuls_is_not_shown() {
        let dir = std::env::temp_dir().join(format!("deepsand-audit-{}", crate::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::load(dir.clone()).expect("a store in an empty directory");
        // The audit path is derived from the project id, so the file is all this needs.
        let path = store.audit_log("p1");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, format!("granted read\n{}\n\n", "\0".repeat(4096))).unwrap();

        let lines = store.read_audit("p1", 50);
        assert_eq!(lines, vec!["granted read".to_string()], "got {lines:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_substitute_store_never_overwrites_the_rolling_backup() {
        let dir = scratch("substitute");
        let good = state_with_projects(&dir, 2);
        std::fs::write(dir.join("state.json.bak"), &good).unwrap();

        let substitute = Store::fallback(&dir);
        substitute.save().expect("the app must still be usable");

        let after = std::fs::read_to_string(dir.join("state.json.bak")).unwrap();
        assert_eq!(after, good, "the rolling backup must survive a substitute");
        assert!(dir.join("state.json").exists(), "and the app must still write its own file");
    }
}
