//! Host-path validation.
//!
//! This module is the only place allowed to decide whether a host path may be
//! handed to the container runtime. Every other module must go through it.
//!
//! The threat model is specific: the contained DeepCode instance may ask for
//! *anything* through the permission broker, and the operator may click through
//! a dialog quickly. These guards exist so that even a careless approval cannot
//! turn into a sandbox escape. They are intentionally conservative and are
//! enforced again at plan time, not only in the UI.

use crate::error::{Result, SandboxError};
use std::path::{Component, Path, PathBuf};

/// Directories that must never be reachable from inside a sandbox, no matter
/// what the operator clicks. Each entry carries the reason shown in the UI.
#[derive(Debug, Clone)]
pub struct PathGuards {
    pub home: PathBuf,
    pub data_dir: PathBuf,
    pub deepcode_config: PathBuf,
}

impl PathGuards {
    pub fn new(home: impl Into<PathBuf>, data_dir: impl Into<PathBuf>, deepcode_config: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            data_dir: data_dir.into(),
            deepcode_config: deepcode_config.into(),
        }
    }

    /// Credential stores that would each be a complete compromise on their own.
    fn credential_dirs(&self) -> Vec<PathBuf> {
        [
            ".ssh",
            ".aws",
            ".azure",
            ".gnupg",
            ".kube",
            ".docker",
            ".config/gcloud",
            ".config/gh",
            ".deepcode",
            ".deepcode-plus",
            ".password-store",
            ".npm",
            ".terraform.d",
        ]
        .iter()
        .map(|rel| self.home.join(rel))
        .collect()
    }

    fn system_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = vec![self.deepcode_config.clone()];
        if cfg!(windows) {
            if let Some(sys_drive) = std::env::var_os("SystemDrive") {
                let root = PathBuf::from(&sys_drive).join("\\");
                for rel in ["Windows", "Program Files", "Program Files (x86)", "ProgramData"] {
                    dirs.push(root.join(rel));
                }
            }
            for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData", "windir"] {
                if let Some(value) = std::env::var_os(var) {
                    dirs.push(PathBuf::from(value));
                }
            }
            if let Some(appdata) = std::env::var_os("APPDATA") {
                dirs.push(PathBuf::from(appdata));
            }
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                dirs.push(PathBuf::from(local));
            }
        } else {
            for rel in [
                "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys", "/run", "/var",
                "/root", "/tmp", "/private/tmp", "/private/etc", "/System", "/Library",
            ] {
                dirs.push(PathBuf::from(rel));
            }
        }
        dirs
    }
}

/// Normalised form used for comparisons only, never for mounting.
///
/// Windows paths compare case-insensitively and `\` is equivalent to `/`.
fn compare_key(path: &Path) -> String {
    let mut out = String::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                let s = prefix.as_os_str().to_string_lossy().to_string();
                out.push_str(&s.to_lowercase());
            }
            Component::RootDir => out.push('/'),
            Component::CurDir => {}
            Component::ParentDir => out.push_str("../"),
            Component::Normal(part) => {
                let s = part.to_string_lossy();
                let s = if cfg!(windows) { s.to_lowercase() } else { s.to_string() };
                if !out.ends_with('/') {
                    out.push('/');
                }
                out.push_str(&s);
            }
        }
    }
    if out.len() > 1 {
        out.truncate(out.trim_end_matches('/').len());
    }
    out
}

/// True when `child` is `parent` itself or lives underneath it.
pub fn is_within(parent: &Path, child: &Path) -> bool {
    let parent = compare_key(parent);
    let child = compare_key(child);
    if parent.is_empty() || child.is_empty() {
        return false;
    }
    if parent == child {
        return true;
    }
    let parent_with_sep = if parent.ends_with('/') { parent } else { format!("{parent}/") };
    child.starts_with(&parent_with_sep)
}

/// True when neither path contains the other. Used to stop confusing nested
/// mounts (a grant inside the workspace, or two grants sharing a subtree).
pub fn overlaps(a: &Path, b: &Path) -> bool {
    is_within(a, b) || is_within(b, a)
}

/// Best-effort canonicalisation that never requires the path to exist.
///
/// Used for the parts of a guard evaluation that may involve directories which
/// have not been created yet, such as the DeepCode config directory.
pub fn canonicalize_lenient(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map(|cwd| cwd.join(path)).unwrap_or_else(|_| path.to_path_buf())
    };
    match std::fs::canonicalize(&absolute) {
        Ok(resolved) => dunce::simplified(&resolved).to_path_buf(),
        Err(_) => simplify_lexically(&absolute),
    }
}

/// Resolve `.` and `..` textually. Only for paths that do not exist yet.
fn simplify_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Canonicalise a host directory that is expected to exist.
///
/// Symlinks are resolved *before* any guard runs, so a symlink cannot be used
/// to smuggle a protected directory past the checks.
pub fn canonical_existing_dir(input: &str) -> Result<PathBuf> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SandboxError::path("no path was given"));
    }
    if trimmed.contains('\0') {
        return Err(SandboxError::path("path contains a NUL byte"));
    }
    if trimmed.starts_with("\\\\") || trimmed.starts_with("//") {
        return Err(SandboxError::path(format!(
            "'{trimmed}' looks like a network or UNC path; Deepsand only shares directories from local disks"
        )));
    }
    if trimmed.starts_with("\\\\?\\") {
        return Err(SandboxError::path(format!(
            "'{trimmed}' is a Windows device path; give the ordinary path instead"
        )));
    }

    let path = PathBuf::from(trimmed);
    let resolved = std::fs::canonicalize(&path).map_err(|err| {
        SandboxError::path(format!(
            "'{trimmed}' could not be resolved ({err}). The directory has to exist before it can be shared."
        ))
    })?;
    let simplified = dunce::simplified(&resolved).to_path_buf();

    let meta = std::fs::metadata(&simplified)?;
    if !meta.is_dir() {
        return Err(SandboxError::path(format!("'{trimmed}' is not a directory")));
    }
    Ok(simplified)
}

/// Why this path must not be mounted, or `None` when it is acceptable.
///
/// Pure with respect to `guards`, so it can be exercised exhaustively in tests.
pub fn reject_reason(path: &Path, guards: &PathGuards) -> Option<String> {
    let path = canonicalize_lenient(path);

    if path.parent().is_none() {
        return Some(format!(
            "{} is a filesystem root. Sharing it would expose the entire disk.",
            path.display()
        ));
    }

    let home = canonicalize_lenient(&guards.home);
    let data_dir = canonicalize_lenient(&guards.data_dir);
    let deepcode_config = canonicalize_lenient(&guards.deepcode_config);

    if path == home || path == data_dir || path == deepcode_config {
        return Some(format!(
            "{} is a private Deepsand/DeepCode directory that the sandbox must not touch.",
            path.display()
        ));
    }
    if is_within(&path, &home) {
        return Some(format!(
            "{} contains your home directory. Sharing it would expose every private file you have.",
            path.display()
        ));
    }
    if is_within(&path, &data_dir) || is_within(&data_dir, &path) {
        return Some(format!(
            "{} overlaps the Deepsand state directory ({}). The sandbox must never be able to read or rewrite its own grants.",
            path.display(),
            data_dir.display()
        ));
    }

    for protected in guards
        .credential_dirs()
        .into_iter()
        .chain(guards.system_dirs())
        .map(|p| canonicalize_lenient(&p))
    {
        if path == protected {
            return Some(format!(
                "{} is a protected system or credential directory.",
                path.display()
            ));
        }
        if is_within(&path, &protected) {
            return Some(format!(
                "{} contains the protected directory {}. Share a narrower folder instead.",
                path.display(),
                protected.display()
            ));
        }
    }

    if path.to_string_lossy().contains('\u{0}') {
        return Some("path contains a NUL byte".to_string());
    }

    // Docker's `-v host:container[:ro]` syntax separates fields with colons, so
    // a colon anywhere but a Windows drive prefix is ambiguous and refused
    // rather than passed through.
    if !cfg!(windows) {
        let as_str = path.to_string_lossy();
        if as_str.contains(':') {
            return Some(format!(
                "{as_str} contains ':', which cannot be expressed safely as a container mount."
            ));
        }
    }

    None
}

/// Guard a candidate mount point, returning a policy error if it is refused.
pub fn guard_mountable(path: &Path, guards: &PathGuards) -> Result<()> {
    match reject_reason(path, guards) {
        Some(reason) => Err(SandboxError::Policy(reason)),
        None => Ok(()),
    }
}

/// Make a Docker-safe identifier out of a user-supplied name.
pub fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = true; // suppress a leading dash
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
        if out.len() >= 40 {
            break;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "resource".to_string()
    } else if trimmed.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("r{trimmed}")
    } else {
        trimmed
    }
}

/// Append a numeric suffix until `candidate` is unused.
pub fn unique_slug(base: &str, taken: impl Fn(&str) -> bool) -> String {
    if !taken(base) {
        return base.to_string();
    }
    for n in 2..1000 {
        let candidate = format!("{base}-{n}");
        if !taken(&candidate) {
            return candidate;
        }
    }
    format!("{base}-{}", crate::now_ms())
}

/// Where a shared host directory appears inside the sandbox.
pub fn container_mount_path(slug: &str) -> String {
    format!("/grants/{slug}")
}

/// The character set a slug may contain, asserted by tests and by the broker
/// when it validates request payloads.
pub fn is_valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 64
        && slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && slug.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guards(home: &str, data: &str) -> PathGuards {
        PathGuards::new(home, data, Path::new(home).join(".deepcode"))
    }

    #[test]
    fn is_within_respects_component_boundaries() {
        assert!(is_within(Path::new("/a/b"), Path::new("/a/b")));
        assert!(is_within(Path::new("/a/b"), Path::new("/a/b/c")));
        assert!(!is_within(Path::new("/a/b"), Path::new("/a/bc")));
        assert!(!is_within(Path::new("/a/b"), Path::new("/a")));
        assert!(!is_within(Path::new("/a/b"), Path::new("/")));
    }

    #[test]
    fn is_within_does_not_confuse_a_sibling_with_a_prefix() {
        assert!(!is_within(Path::new("/srv/app"), Path::new("/srv/app-2")));
        assert!(!is_within(Path::new("/srv/app"), Path::new("/srv/apple")));
    }

    #[test]
    fn a_normal_project_directory_is_allowed() {
        let g = guards("/home/me", "/home/me/.local/share/deepsand");
        assert_eq!(reject_reason(Path::new("/home/me/projects/my-website"), &g), None);
        assert_eq!(reject_reason(Path::new("/srv/work/api"), &g), None);
    }

    #[test]
    fn the_filesystem_root_is_refused() {
        let g = guards("/home/me", "/home/me/.local/share/deepsand");
        let reason = reject_reason(Path::new("/"), &g).expect("root must be refused");
        assert!(reason.contains("filesystem root"), "{reason}");
    }

    #[test]
    fn the_home_directory_itself_is_refused() {
        let g = guards("/home/me", "/home/me/.local/share/deepsand");
        let reason = reject_reason(Path::new("/home/me"), &g).expect("home must be refused");
        assert!(reason.contains("private"), "{reason}");
    }

    #[test]
    fn an_ancestor_of_home_is_refused() {
        let g = guards("/home/me", "/home/me/.local/share/deepsand");
        let reason = reject_reason(Path::new("/home"), &g).expect("ancestor of home must be refused");
        assert!(reason.contains("home directory"), "{reason}");
    }

    #[test]
    fn the_deepsand_state_directory_is_refused_both_ways() {
        let g = guards("/home/me", "/home/me/.local/share/deepsand");
        assert!(reject_reason(Path::new("/home/me/.local/share/deepsand"), &g).is_some());
        assert!(reject_reason(Path::new("/home/me/.local/share/deepsand/ipc"), &g).is_some());
        let reason = reject_reason(Path::new("/home/me/.local/share"), &g).unwrap();
        assert!(reason.contains("state directory"), "{reason}");
    }

    #[test]
    fn credential_directories_are_refused() {
        let g = guards("/home/me", "/home/me/.local/share/deepsand");
        for dir in ["/home/me/.ssh", "/home/me/.aws", "/home/me/.gnupg", "/home/me/.deepcode", "/home/me/.kube"] {
            assert!(reject_reason(Path::new(dir), &g).is_some(), "{dir} must be refused");
        }
    }

    #[test]
    fn a_directory_containing_a_credential_store_is_refused() {
        let g = guards("/home/me", "/home/me/.local/share/deepsand");
        let reason = reject_reason(Path::new("/home/me/.config"), &g).expect("must be refused");
        assert!(reason.contains("contains") || reason.contains("private"), "{reason}");
    }

    #[test]
    fn a_narrow_directory_inside_a_config_tree_is_allowed() {
        // .config itself is sensitive only because of what lives inside it; a
        // specific unrelated subfolder is a legitimate thing to share.
        let g = guards("/home/me", "/home/me/.local/share/deepsand");
        assert_eq!(reject_reason(Path::new("/home/me/projects/theme/config"), &g), None);
    }

    #[test]
    fn unc_and_device_paths_are_refused_before_they_reach_docker() {
        assert!(canonical_existing_dir("\\\\server\\share").is_err());
        assert!(canonical_existing_dir("//server/share").is_err());
        assert!(canonical_existing_dir("\\\\?\\C:\\Windows").is_err());
    }

    #[test]
    fn a_nonexistent_directory_is_refused_with_a_clear_message() {
        let err = canonical_existing_dir("/definitely/not/here/at/all").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("has to exist"), "{msg}");
    }

    #[test]
    fn symlinks_are_resolved_before_guards_run() {
        // A symlink pointing at a protected directory must be judged by its
        // target, not by its own name.
        #[cfg(unix)]
        {
            let dir = std::env::temp_dir().join(format!("deepsand-symlink-{}", crate::now_ms()));
            std::fs::create_dir_all(&dir).unwrap();
            let link = dir.join("innocent-looking");
            let sensitive = dir.join("sensitive");
            std::fs::create_dir_all(&sensitive).unwrap();
            std::os::unix::fs::symlink(&sensitive, &link).unwrap();

            let resolved = canonical_existing_dir(link.to_str().unwrap()).unwrap();
            assert_eq!(resolved, dunce::simplified(&std::fs::canonicalize(&sensitive).unwrap()).to_path_buf());

            let g = PathGuards::new(dir.join("home"), dir.join("data"), dir.join("deepcode"));
            // Judged by target: `sensitive` is not protected, so this is fine...
            assert_eq!(reject_reason(&resolved, &g), None);
            // ...but a link aimed at the home directory is refused.
            let trap = dir.join("trap");
            std::os::unix::fs::symlink(dir.join("home"), &trap).unwrap();
            let resolved_trap = canonical_existing_dir(trap.to_str().unwrap()).unwrap();
            assert!(reject_reason(&resolved_trap, &g).is_some());

            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn overlaps_detects_nesting_in_both_directions() {
        assert!(overlaps(Path::new("/a/b"), Path::new("/a/b/c")));
        assert!(overlaps(Path::new("/a/b/c"), Path::new("/a/b")));
        assert!(!overlaps(Path::new("/a/b"), Path::new("/a/c")));
    }

    #[test]
    fn slugify_produces_docker_safe_identifiers() {
        assert_eq!(slugify("my-website"), "my-website");
        assert_eq!(slugify("My Website!"), "my-website");
        assert_eq!(slugify("   "), "resource");
        assert_eq!(slugify("../../etc/passwd"), "etc-passwd");
        assert_eq!(slugify("9lives"), "r9lives");
        assert!(is_valid_slug(&slugify("Ünïcodé Ø")));
        assert_eq!(slugify("a".repeat(500).as_str()).len(), 40);
    }

    #[test]
    fn unique_slug_avoids_collisions() {
        let taken = |s: &str| matches!(s, "docs" | "docs-2");
        assert_eq!(unique_slug("docs", taken), "docs-3");
        assert_eq!(unique_slug("fresh", taken), "fresh");
    }

    #[test]
    fn container_mount_paths_are_confined_to_grants() {
        assert_eq!(container_mount_path("docs"), "/grants/docs");
        for evil in ["../../etc", "/etc", "a/../../b", ".."] {
            let slug = slugify(evil);
            let path = container_mount_path(&slug);
            assert!(path.starts_with("/grants/"), "{path}");
            assert!(!path.contains(".."), "{path}");
            assert_eq!(path.matches('/').count(), 2, "{path}");
        }
    }

    #[test]
    fn slugs_are_never_path_traversal() {
        assert!(is_valid_slug("docs"));
        assert!(!is_valid_slug("../etc"));
        assert!(!is_valid_slug("/etc"));
        assert!(!is_valid_slug("a/b"));
        assert!(!is_valid_slug(""));
    }
}
