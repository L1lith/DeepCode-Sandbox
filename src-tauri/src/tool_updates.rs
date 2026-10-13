//! Asking the registries whether the tools a cache entry holds have moved on.
//!
//! What this does and does not do is the point. It asks npm and crates.io about the versions the
//! cache recorded when it was filled, and when something has moved it *empties that entry* --
//! which means the next build installs the tools again and refills the cache from what it built.
//! It never installs anything itself: that needs Docker and an image, and a check that runs on a
//! timer has no business starting a build.
//!
//! The DeepCode CLI is not part of this, deliberately: it is refreshed on every build already,
//! so a cache entry being "out of date" never means the CLI is.

use std::time::Duration;

use tauri::{AppHandle, Emitter as _};

use crate::state::AppState;

/// Emitted when a check finishes, carrying what it found.
pub const TOOL_UPDATES_CHECKED: &str = "tool-updates://checked";

/// How long after startup the first check runs.
///
/// Not immediately: the first seconds of a launch belong to the window, the state and the Docker
/// probe, and a handful of HTTP requests should not be in that queue.
pub const FIRST_CHECK_DELAY: Duration = Duration::from_secs(30);

/// How many names to ask about per registry per entry. A guard against a pathological cache
/// turning a background check into a hundred requests.
const MAX_PER_REGISTRY: usize = 40;

/// The check at startup and then on a timer, until the app exits.
pub fn watch(app: AppHandle, interval: Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(FIRST_CHECK_DELAY);
        loop {
            if enabled(&app) {
                check(app.clone(), false);
            }
            std::thread::sleep(interval);
        }
    });
}

/// Whether the operator wants these checks.
///
/// Read on every cycle rather than once, so turning the setting off stops the next one instead
/// of needing a restart.
fn enabled(app: &AppHandle) -> bool {
    let state = tauri::Manager::state::<AppState>(app);
    crate::commands::tool_updates_enabled(&state)
}

/// Ask about every entry that is due (or every entry, when the operator asked).
///
/// Returns one sentence per entry that had something to say, which the window shows and the log
/// keeps.
pub fn check(app: AppHandle, ignore_due: bool) -> Vec<String> {
    let cache_root = {
        let state = tauri::Manager::state::<AppState>(&app);
        crate::commands::tool_cache_root(&state)
    };
    let now = deepsand_core::now_ms();
    let mut notes: Vec<String> = Vec::new();

    let Ok(entries) = std::fs::read_dir(&cache_root) else {
        return notes;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        if !ignore_due
            && !deepsand_core::toolcache::check_is_due(deepsand_core::toolcache::last_checked(
                &dir, now,
            ))
        {
            continue;
        }
        let (npm, cargo) = deepsand_core::toolcache::read_versions(&dir);
        if npm.is_empty() && cargo.is_empty() {
            // Filled before this existed, or by a build that could not list its tools. There is
            // nothing to compare, and recording a check would hide that from the next cycle.
            continue;
        }

        let mut latest = deepsand_core::toolcache::Versions::new();
        let mut answered = 0usize;
        for name in npm.keys().take(MAX_PER_REGISTRY) {
            if let Some(version) = fetch(&deepsand_core::toolcache::npm_metadata_url(name), false) {
                latest.insert(name.clone(), version);
                answered += 1;
            }
        }
        for name in cargo.keys().take(MAX_PER_REGISTRY) {
            if let Some(version) = fetch(&deepsand_core::toolcache::crate_metadata_url(name), true) {
                latest.insert(name.clone(), version);
                answered += 1;
            }
        }
        if answered == 0 {
            // Nothing was reachable. Not a check, and not a reason to record one: the next cycle
            // will try again rather than waiting out the interval.
            tracing::debug!("the tool registries could not be reached; leaving the cache alone");
            continue;
        }

        let mut moved = deepsand_core::toolcache::outdated(&npm, &latest);
        moved.extend(deepsand_core::toolcache::outdated(&cargo, &latest));
        let _ = deepsand_core::toolcache::mark_checked(&dir, now);

        if moved.is_empty() {
            tracing::info!(answered, "the cached tools are current");
            continue;
        }
        // Emptying the entry is the whole action: the next build installs what has moved and
        // refills this cache, and until then the tools that are already built keep working.
        crate::commands::empty_tool_cache(&dir);
        let described: Vec<String> = moved
            .iter()
            .map(|(name, held, offered)| format!("{name} {held} -> {offered}"))
            .collect();
        let note = format!(
            "{} cached tool(s) have moved on ({}). The next build will install them again.",
            described.len(),
            described.join(", ")
        );
        tracing::info!(%note, "the tools cache was emptied so a build can refresh it");
        notes.push(note);
    }

    if !notes.is_empty() {
        let _ = app.emit(
            TOOL_UPDATES_CHECKED,
            serde_json::json!({ "notes": notes, "checkedAt": now }),
        );
    }
    notes
}

/// Ask one registry about one name, and read the version out of the answer.
///
/// Every failure is `None`: a registry that is down, slow, rate-limiting or answering something
/// unexpected is a name this check says nothing about, not a failure of the check.
fn fetch(url: &str, crates_io: bool) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .ok()?;
    let response = tauri::async_runtime::block_on(async {
        let mut request = client.get(url);
        if crates_io {
            // crates.io asks for this, and answers robots without it.
            request = request.header("User-Agent", "Deepsand (tool version check)");
        }
        request.send().await
    })
    .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = tauri::async_runtime::block_on(response.text()).ok()?;
    if crates_io {
        deepsand_core::toolcache::parse_crate_latest(&body)
    } else {
        deepsand_core::toolcache::parse_npm_latest(&body)
    }
}
