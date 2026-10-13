//! Self-updates.
//!
//! Deliberately **not** the updater plugin's own JavaScript bindings. The webview is
//! given no ambient authority over the host anywhere else in this app -- see
//! `docs/SECURITY.md` -- and an update is the most powerful thing a webview could ask
//! for, since installing one replaces the binary. So the plugin is initialised in Rust
//! and the UI reaches it through two commands of our own, which cannot be called by a
//! remote client (they are absent from the remote command table) and which refuse to do
//! anything at all in a development build.
//!
//! What makes this safe is not the transport being HTTPS but the signature: the updater
//! verifies a minisign signature against the public key pinned in `tauri.conf.json`
//! before installing anything, so a compromised account or a hijacked release cannot
//! push an update that will install. The private key exists only in the operator's
//! `~/.tauri` directory and in the repository's `TAURI_SIGNING_PRIVATE_KEY` secret.
//!
//! The residual risk is worth stating plainly: whoever holds that private key can sign
//! an update that every installed copy will accept, and losing it means no further
//! updates can ever be delivered to an already-installed app. Treat it like a code
//! signing certificate, not like a build artifact.

use std::sync::Mutex;

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_updater::{Update, UpdaterExt};

/// Download progress, for the UI to show something moving.
pub const UPDATE_PROGRESS: &str = "update://progress";

/// The update that was found and described to the operator, held until they install it.
///
/// Not `Debug`, because `tauri_plugin_updater::Update` is not, and nothing here needs to
/// print it.
#[derive(Default)]
pub struct PendingUpdate(Mutex<Option<Update>>);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub version: String,
    /// The release notes, which `tauri-action` fills from the release body.
    pub notes: String,
    /// RFC 3339, when the release announced one.
    pub date: Option<String>,
}

/// The result of asking, which is three-valued on purpose.
///
/// "No update" and "could not ask" are different answers, and reporting a dead network
/// or a rate-limited GitHub as `update: None` would tell the operator they are up to
/// date when nothing was checked.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheck {
    pub current_version: String,
    pub update: Option<UpdateInfo>,
    pub error: Option<String>,
}

/// Development builds must not replace themselves.
///
/// A dev build reports the version in `Cargo.toml`, which trails whatever was released
/// last, so it would cheerfully offer to install a release over the binary being worked
/// on -- and installing it would replace the build the developer is running.
fn development_build() -> bool {
    cfg!(debug_assertions)
}

const DEV_BUILD_NOTE: &str =
    "This is a development build, so it does not check for updates. Run a release build to test them.";

#[tauri::command]
pub async fn check_for_updates(
    app: AppHandle,
    pending: State<'_, PendingUpdate>,
) -> Result<UpdateCheck, String> {
    Ok(check_impl(&app, &pending).await)
}

pub async fn check_impl(app: &AppHandle, pending: &PendingUpdate) -> UpdateCheck {
    let current_version = app.package_info().version.to_string();

    if development_build() {
        return UpdateCheck {
            current_version,
            update: None,
            error: Some(DEV_BUILD_NOTE.to_string()),
        };
    }

    let updater = match app.updater() {
        Ok(updater) => updater,
        Err(err) => {
            return UpdateCheck {
                current_version,
                update: None,
                error: Some(format!("The updater is not configured: {err}")),
            }
        }
    };

    match updater.check().await {
        Ok(Some(update)) => {
            let info = UpdateInfo {
                version: update.version.clone(),
                notes: update.body.clone().unwrap_or_default(),
                date: update.date.map(|date| date.to_string()),
            };
            // Held so the install can use exactly the update that was described to the
            // operator, rather than checking again and possibly finding a different one.
            *pending.0.lock().unwrap_or_else(|p| p.into_inner()) = Some(update);
            UpdateCheck {
                current_version,
                update: Some(info),
                error: None,
            }
        }
        Ok(None) => UpdateCheck {
            current_version,
            update: None,
            error: None,
        },
        Err(err) => UpdateCheck {
            current_version,
            update: None,
            error: Some(describe(&err)),
        },
    }
}

#[tauri::command]
pub async fn install_update(app: AppHandle, pending: State<'_, PendingUpdate>) -> Result<(), String> {
    install_impl(&app, &pending).await
}

pub async fn install_impl(app: &AppHandle, pending: &PendingUpdate) -> Result<(), String> {
    if development_build() {
        return Err(DEV_BUILD_NOTE.to_string());
    }

    // Taken rather than borrowed: a second click while the download is running must find
    // nothing to install, not start a second download of the same update.
    let update = pending
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
        .ok_or_else(|| "No update has been checked for yet. Check first, then install.".to_string())?;

    let announced = update.version.clone();
    let handle = app.clone();
    let mut downloaded: u64 = 0;
    let mut announced_bytes: u64 = 0;

    let result = update
        .download_and_install(
            |chunk_length, content_length| {
                downloaded += chunk_length as u64;
                // One event per chunk would be thousands of events for a hundred
                // megabytes; one per megabyte is smooth enough to watch and cheap enough
                // not to compete with the download.
                if downloaded - announced_bytes >= 1024 * 1024 || content_length == Some(downloaded) {
                    announced_bytes = downloaded;
                    let _ = handle.emit(
                        UPDATE_PROGRESS,
                        Progress::Downloading {
                            downloaded,
                            total: content_length,
                        },
                    );
                }
            },
            || {
                // Between the download finishing and the install starting, which is
                // exactly the moment the UI should stop saying "downloading".
                let _ = handle.emit(UPDATE_PROGRESS, Progress::Installing);
            },
        )
        .await;

    if let Err(err) = result {
        // Put it back so the operator can try again without re-checking, which matters
        // when the failure was transient -- a dropped connection, a laptop that slept.
        *pending.0.lock().unwrap_or_else(|p| p.into_inner()) = Some(update);
        return Err(format!("Could not install {announced}: {}", describe(&err)));
    }

    tracing::info!(version = %announced, "update installed, restarting");
    // Never returns. On Windows the installer has already replaced the files; on macOS
    // and Linux the bundle has been swapped underneath this process.
    app.restart();
}

/// Progress as the UI receives it: tagged, so the two phases cannot be confused.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "phase")]
pub enum Progress {
    Downloading { downloaded: u64, total: Option<u64> },
    Installing,
}

/// Errors from the updater are long and nested; the UI shows this one line.
fn describe(err: &tauri_plugin_updater::Error) -> String {
    let text = err.to_string();
    let first = text.lines().next().unwrap_or("").trim().to_string();
    if first.is_empty() {
        "the update check failed".to_string()
    } else {
        first
    }
}
