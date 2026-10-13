//! Watching the operator's own DeepCode settings file.
//!
//! Several things the window shows are answers that come *from* that file: what "Defer to
//! Config" resolves to, whether the thinking switch is deferring, and the credentials provenance
//! in a project's settings. The backend reads the file fresh every time it is used -- nothing
//! caches it -- so it always acts on the current version. What goes stale is the window, which
//! asked once when it opened, and went on showing the old answer after the file changed.
//!
//! Polling rather than a filesystem watcher, deliberately. Editors save by writing a temporary
//! file and renaming it over the target, which a watcher on the file itself reports as a
//! deletion and then nothing; watching the directory instead means either depending on another
//! crate for one small thing or reimplementing its platform handling. Three seconds of latency
//! for a file a person edits by hand is not worth any of that.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use tauri::{AppHandle, Emitter};

use crate::state::AppState;

/// Emitted when the file the host's DeepCode configuration lives in changes.
///
/// The window re-reads what depends on it rather than being told the values: the answer is the
/// backend's to give, and sending it twice would be two sources of truth.
pub const HOST_CONFIG_CHANGED: &str = "host-config://changed";

/// How the file looked the last time it was checked.
///
/// The digest is the part that makes this exact. A timestamp and a length are what a watcher
/// usually compares, and both can be unchanged by a real edit: an editor that writes the same
/// number of bytes inside one filesystem timestamp tick leaves nothing else to notice. The file
/// is a couple of kilobytes, and this is once every three seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    exists: bool,
    modified: Option<SystemTime>,
    len: u64,
    digest: String,
}

fn fingerprint(path: &PathBuf) -> Fingerprint {
    match std::fs::read(path) {
        Ok(bytes) => {
            let modified = std::fs::metadata(path).ok().and_then(|meta| meta.modified().ok());
            Fingerprint {
                exists: true,
                modified,
                len: bytes.len() as u64,
                digest: deepsand_core::seccomp::digest(&bytes),
            }
        }
        // Not there, or not readable: either way there is nothing to report beyond that.
        Err(_) => Fingerprint {
            exists: false,
            modified: None,
            len: 0,
            digest: String::new(),
        },
    }
}

#[cfg(test)]
mod watcher_tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("deepsand-watch-{name}-{}", deepsand_core::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("settings.json")
    }

    #[test]
    fn a_missing_file_is_a_state_rather_than_an_error() {
        let path = scratch("missing");
        assert!(!fingerprint(&path).exists);
    }

    /// The case a timestamp-and-length comparison misses: same size, same tick, different
    /// contents. `.modified()` is included for tidiness, but the digest is what decides.
    #[test]
    fn an_edit_of_the_same_length_is_still_a_change() {
        let path = scratch("same-length");
        std::fs::write(&path, r#"{"model": "aaaa"}"#).unwrap();
        let before = fingerprint(&path);
        std::fs::write(&path, r#"{"model": "bbbb"}"#).unwrap();
        let after = fingerprint(&path);

        assert_eq!(before.len, after.len, "the lengths are the same");
        assert_ne!(before.digest, after.digest);
        assert_ne!(before, after, "so the fingerprint has to differ");
    }

    /// And a file that is deleted is a change too: deferring to a configuration that is gone
    /// resolves to something else.
    #[test]
    fn deleting_the_file_is_a_change() {
        let path = scratch("deleted");
        std::fs::write(&path, "{}").unwrap();
        let before = fingerprint(&path);
        assert!(before.exists);
        std::fs::remove_file(&path).unwrap();
        assert_ne!(before, fingerprint(&path));
    }
}

/// Start watching. Returns immediately; the polling happens on its own thread.
pub fn watch(app: AppHandle, interval: Duration) {
    std::thread::spawn(move || {
        let path = deepsand_core::credentials::host_settings_path();
        // Whatever is there when the app opens is the state it opened with, not a change.
        let mut last = fingerprint(&path);
        tracing::info!(path = %path.display(), "watching the DeepCode settings file");
        loop {
            std::thread::sleep(interval);
            let current = fingerprint(&path);
            if current == last {
                continue;
            }
            tracing::info!(
                path = %path.display(),
                exists = current.exists,
                "the DeepCode settings file changed"
            );
            last = current;

            // A running sandbox reads its settings file per run, so the values that come from
            // this file are pushed to it here, the same way a change made in the window is.
            // Failure is not news: the file is saved, and the next start picks it up.
            let state = tauri::Manager::state::<AppState>(&app);
            let running: Vec<String> = state
                .sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .keys()
                .cloned()
                .collect();
            for project_id in running {
                match crate::commands::push_live_settings(&state, &project_id) {
                    Ok(true) => tracing::info!(project = %project_id, "pushed the changed settings into the running sandbox"),
                    Ok(false) => {}
                    Err(err) => tracing::warn!(project = %project_id, "could not push the changed settings: {err}"),
                }
            }

            let _ = app.emit(HOST_CONFIG_CHANGED, serde_json::json!({}));
        }
    });
}
