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

        let mut state = None;
        let mut failure = None;
        if state_path.exists() {
            match Self::read_state(&state_path) {
                Some(parsed) => state = Some(parsed),
                // Keep the unreadable file: it is worthless to the app but it may be
                // salvageable by hand, and overwriting it would destroy that chance.
                None => {
                    let aside = data_dir.join(format!("state.corrupt-{}.json", crate::now_ms()));
                    let _ = std::fs::rename(&state_path, &aside);
                    failure = Some(SandboxError::StateCorrupt {
                        path: state_path.clone(),
                        message: format!(
                            "the file could not be read. It was moved to {} so nothing is lost silently.",
                            aside.display()
                        ),
                    });
                }
            }
        }

        // The rolling backup holds the last state that was written successfully. Trying
        // it turns a crash from "everything is gone" into "one change is missing".
        let mut recovered = false;
        if state.is_none() && rolling.exists() {
            if let Some(parsed) = Self::read_state(&rolling) {
                recovered = true;
                state = Some(parsed);
            }
        }

        let mut state = match state {
            Some(parsed) => parsed,
            None => match failure {
                // A file existed and neither it nor the backup could be read. The
                // caller decides what to say; a silent default here is what made the
                // loss invisible last time.
                Some(err) => return Err(err),
                None => StoreDocument::default(),
            },
        };
        Self::migrate(&mut state);
        state.version = STATE_VERSION;

        let store = Self {
            data_dir,
            guards,
            state,
            recovered_from_backup: recovered,
        };
        store.save()?;
        Ok(store)
    }

    /// Whether this store was recovered from the rolling backup.
    pub fn recovered_from_backup(&self) -> bool {
        self.recovered_from_backup
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

/// Parse a state file, or `None` if it cannot be read or understood.
///
/// A zero-length file, or one full of NULs left by a power loss, lands here rather than
/// propagating a parse error: the caller has a backup to try, and the reason it is
/// unreadable is not something that can be acted on.
fn read_state(path: &Path) -> Option<StoreDocument> {
    let raw = std::fs::read_to_string(path).ok()?;
    // The version is left as it was found: `migrate` needs it to tell an old file from a
    // current one, and clobbering it here made every file look current.
    serde_json::from_str(&raw).ok()
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
        if path.exists() {
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
        let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
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
}
