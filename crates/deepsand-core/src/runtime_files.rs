//! The runtime files, and what to do when the copy on disk stops being text.
//!
//! What happened, because it is not obvious from the symptom: an installed `Dockerfile` was
//! 18,412 bytes of NULs -- exactly the size of the real file, with no data in it. The only
//! thing the operator saw was Docker refusing the build with `dockerfile parse error on line
//! 1: unknown instruction:`, which names a Dockerfile they never wrote and cannot act on. The
//! same machine had already lost the contents of `state.json` and the tail of `build.log` the
//! same way. A crash between the metadata of a write and its data leaves the size behind and
//! the contents as NULs, and that is what this module exists for.
//!
//! The bytes are embedded below, so the app can repair its own copy from the binary it is
//! already running. The repair is deliberately narrow: **only** a file that is not text at all
//! (it holds NUL bytes), is empty where content belongs, or is missing, is replaced. A file that
//! merely *differs* is not touched -- that is a developer's edit, or a runtime tree from another
//! build, and overwriting it would be a much worse bug than the one being fixed.

use std::path::{Path, PathBuf};

/// Everything this build ships as its runtime, so that damage on disk can be repaired from the
/// binary itself.
///
/// Every file under `runtime/`, listed rather than discovered: `include_bytes!` happens at
/// compile time, so adding a file to `runtime/` means adding a line here, and a path that is
/// wrong fails the build instead of failing on somebody's machine.
const SHIPPED: &[(&str, &[u8])] = &[
    (".dockerignore", include_bytes!("../../../runtime/.dockerignore")),
    ("Dockerfile", include_bytes!("../../../runtime/Dockerfile")),
    ("README.md", include_bytes!("../../../runtime/README.md")),
    (
        "bin/deepsand-mcp-bridge.mjs",
        include_bytes!("../../../runtime/bin/deepsand-mcp-bridge.mjs"),
    ),
    (
        "bin/deepsand-display.sh",
        include_bytes!("../../../runtime/bin/deepsand-display.sh"),
    ),
    ("bin/entrypoint.sh", include_bytes!("../../../runtime/bin/entrypoint.sh")),
    ("bin/netfilter.sh", include_bytes!("../../../runtime/bin/netfilter.sh")),
    ("gitconfig", include_bytes!("../../../runtime/gitconfig")),
    ("scripts/build-image.mjs", include_bytes!("../../../runtime/scripts/build-image.mjs")),
    ("scripts/make-icon.mjs", include_bytes!("../../../runtime/scripts/make-icon.mjs")),
    (
        "scripts/test-mcp-bridge.mjs",
        include_bytes!("../../../runtime/scripts/test-mcp-bridge.mjs"),
    ),
    (
        "seccomp-hardened.json",
        include_bytes!("../../../runtime/seccomp-hardened.json"),
    ),
    (
        "skills/deepsand-permissions/SKILL.md",
        include_bytes!("../../../runtime/skills/deepsand-permissions/SKILL.md"),
    ),
    (
        "skills/deepsand-toolbox/SKILL.md",
        include_bytes!("../../../runtime/skills/deepsand-toolbox/SKILL.md"),
    ),
];

/// One shipped file that cannot be used as it stands.
#[derive(Debug, Clone, PartialEq)]
pub enum Damage {
    /// Not there at all.
    Missing { path: PathBuf },
    /// There, with the right size, and no contents: NUL bytes throughout.
    Nuls { path: PathBuf, size: u64 },
    /// There and empty, where the shipped file has contents.
    Empty { path: PathBuf },
}

impl Damage {
    pub fn path(&self) -> &Path {
        match self {
            Damage::Missing { path } | Damage::Nuls { path, .. } | Damage::Empty { path } => path,
        }
    }

    /// The sentence an operator reads.
    pub fn describe(&self) -> String {
        match self {
            Damage::Missing { path } => format!("{} is missing", path.display()),
            Damage::Empty { path } => format!("{} is empty", path.display()),
            Damage::Nuls { path, size } => format!(
                "{} is {size} bytes of NULs -- the size of a write whose contents never arrived",
                path.display()
            ),
        }
    }
}

/// What this build ships for a relative path, if anything.
pub fn shipped(relative: &str) -> Option<&'static [u8]> {
    SHIPPED
        .iter()
        .find(|(name, _)| *name == relative)
        .map(|(_, bytes)| *bytes)
}

/// Every shipped file that is not readable text in `dir`.
///
/// Extra files in the directory are not this function's business: a backup left beside the
/// Dockerfile does not break a build. Public so the headless CLI can report it.
pub fn audit(dir: &Path) -> Vec<Damage> {
    let mut damage = Vec::new();
    for (relative, shipped) in SHIPPED {
        let path = dir.join(relative);
        let Ok(bytes) = std::fs::read(&path) else {
            damage.push(Damage::Missing { path });
            continue;
        };
        if bytes.contains(&0) {
            // Not text. No Dockerfile, script or profile holds a NUL byte.
            damage.push(Damage::Nuls {
                path,
                size: bytes.len() as u64,
            });
        } else if bytes.is_empty() && !shipped.is_empty() {
            damage.push(Damage::Empty { path });
        }
    }
    damage
}

/// Put the shipped bytes back for anything `audit` reports, and say what was repaired.
///
/// Returns the paths relative to `dir`, so the operator is told which files were replaced
/// rather than left to wonder what changed under them.
pub fn repair(dir: &Path) -> crate::Result<Vec<String>> {
    let damaged = audit(dir);
    let mut repaired = Vec::new();
    for damage in damaged {
        let relative = damage
            .path()
            .strip_prefix(dir)
            .map(|rest| rest.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        let Some(bytes) = shipped(&relative) else {
            return Err(crate::SandboxError::policy(format!(
                "{} is damaged and this build does not carry a copy of it; reinstall Deepsand",
                damage.path().display()
            )));
        };
        if let Some(parent) = damage.path().parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                crate::SandboxError::policy(format!(
                    "could not recreate {}: {err}",
                    parent.display()
                ))
            })?;
        }
        std::fs::write(damage.path(), bytes).map_err(|err| {
            crate::SandboxError::policy(format!(
                "could not repair {}: {err}",
                damage.path().display()
            ))
        })?;
        repaired.push(relative);
    }
    Ok(repaired)
}

#[cfg(test)]
mod damage_tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("deepsand-runtime-{name}-{}", crate::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The failure that prompted this, with its own size: a Dockerfile of NULs, the size of the
    /// real one, and nothing in it.
    #[test]
    fn a_dockerfile_of_nuls_is_reported_with_its_size() {
        let dir = scratch("nuls");
        let size = shipped("Dockerfile").unwrap().len();
        std::fs::write(dir.join("Dockerfile"), vec![0u8; size]).unwrap();

        let damage = audit(&dir);
        let dockerfile = damage
            .iter()
            .find(|entry| entry.path().ends_with("Dockerfile"))
            .expect("the Dockerfile is the point");
        assert_eq!(
            dockerfile,
            &Damage::Nuls {
                path: dir.join("Dockerfile"),
                size: size as u64
            }
        );
        assert!(dockerfile.describe().contains("NULs"));
        assert!(dockerfile.describe().contains(&size.to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repair_puts_the_shipped_bytes_back_and_then_finds_nothing() {
        let dir = scratch("repair");
        std::fs::write(dir.join("Dockerfile"), vec![0u8; 4096]).unwrap();
        std::fs::write(dir.join("bin").join("netfilter.sh"), "").ok(); // no bin/ yet: create it
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join("bin").join("netfilter.sh"), Vec::<u8>::new()).unwrap();

        let repaired = repair(&dir).expect("repairing from this build's copy");
        assert!(repaired.contains(&"Dockerfile".to_string()), "{repaired:?}");
        assert!(repaired.contains(&"bin/netfilter.sh".to_string()), "{repaired:?}");

        assert_eq!(
            std::fs::read(dir.join("Dockerfile")).unwrap(),
            shipped("Dockerfile").unwrap()
        );
        assert!(
            audit(&dir).is_empty(),
            "everything this build ships is now readable: {:?}",
            audit(&dir)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The property that matters most: a file that merely differs is somebody's edit, not damage.
    /// Repairing those would be a much worse bug than the one this fixes.
    #[test]
    fn a_file_that_merely_differs_is_not_damage_and_is_not_touched() {
        let dir = scratch("differs");
        let mine = b"# a Dockerfile of my own\nFROM scratch\n";
        std::fs::write(dir.join("Dockerfile"), mine).unwrap();

        assert!(
            !audit(&dir).iter().any(|d| d.path().ends_with("Dockerfile")),
            "a text file that differs is not damage"
        );
        let _ = repair(&dir).unwrap();
        assert_eq!(std::fs::read(dir.join("Dockerfile")).unwrap(), mine);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_is_reported_and_restored() {
        let dir = scratch("missing");
        let damage = audit(&dir);
        assert!(
            damage.iter().any(|d| d.path().ends_with("gitconfig")),
            "everything missing is reported: {damage:?}"
        );
        let repaired = repair(&dir).unwrap();
        assert!(repaired.contains(&"gitconfig".to_string()), "{repaired:?}");
        assert_eq!(
            std::fs::read(dir.join("gitconfig")).unwrap(),
            shipped("gitconfig").unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_file_where_content_belongs_is_reported_and_restored() {
        let dir = scratch("empty");
        std::fs::write(dir.join("seccomp-hardened.json"), "").unwrap();
        assert!(audit(&dir)
            .iter()
            .any(|d| matches!(d, Damage::Empty { .. }) && d.path().ends_with("seccomp-hardened.json")));
        repair(&dir).unwrap();
        assert!(std::fs::read(dir.join("seccomp-hardened.json"))
            .unwrap()
            .starts_with(b"{"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The list has to be the whole tree. A file added to `runtime/` and forgotten here would
    /// be unrepairable exactly when it is needed, and nothing else would notice.
    #[test]
    fn every_file_in_the_runtime_directory_is_embedded() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("runtime");
        let mut on_disk = Vec::new();
        let mut stack = vec![source.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("the runtime directory").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    on_disk.push(
                        path.strip_prefix(&source)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                    );
                }
            }
        }
        on_disk.sort();

        let mut embedded: Vec<String> = SHIPPED.iter().map(|(name, _)| (*name).to_string()).collect();
        embedded.sort();

        assert_eq!(
            on_disk, embedded,
            "every file under runtime/ has to be embedded, and nothing else"
        );
        // And this is the source tree, not the installed one: the bytes are compile-time.
        for (name, bytes) in SHIPPED {
            assert!(
                !bytes.is_empty(),
                "{name} is embedded empty, which would repair damage by writing damage"
            );
        }
    }

    /// Every file the app ships is covered: a relative path it reports has to be one it can
    /// repair, or the repair is a promise it cannot keep.
    #[test]
    fn everything_audited_can_be_repaired_from_this_build() {
        let dir = scratch("coverage");
        for damage in audit(&dir) {
            let relative = damage
                .path()
                .strip_prefix(&dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            assert!(
                shipped(&relative).is_some(),
                "{relative} is reported as damaged but this build carries no copy of it"
            );
        }
        assert!(!SHIPPED.is_empty(), "the runtime is shipped, or this is all decoration");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
