//! One instance of Deepsand, and what to do about an earlier one that has stopped working.
//!
//! The window is the app's lifetime: the operator closes it, the process cleans up and exits.
//! That broke on a real machine, in a way worth spelling out because the symptom was that the
//! app **would not start at all**:
//!
//! * The cleanup after the window closes runs on the UI thread and shells out to Docker
//!   (`shutdown_cleanup`). Docker Desktop restarted underneath it, the call never returned,
//!   and the process sat there with no window and a blocked event loop. `lib.rs` bounds that
//!   cleanup now, so this cannot be produced again.
//! * The single-instance plugin hands a new launch to whatever process already exists and
//!   then exits. Handed to a process with no window and a stuck UI thread, the launch
//!   disappears: no window, no error, nothing to read. That is what this module is for -- a
//!   launch that finds such a process clears it first, so the plugin finds nothing to hand
//!   off to.
//!
//! The evidence that a running instance is *working* is a heartbeat written **from the UI
//! thread**, through `run_on_main_thread`. A process whose event loop is stuck stops beating,
//! which is exactly the condition that used to be invisible. A process that has stopped
//! beating and has no visible window is a zombie: it cannot show anything, so it is cleared.
//! A process that has stopped beating but still has a window is left alone -- the operator
//! can see it, and stealing it would be worse than waiting.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long the UI thread may go without proving itself before the instance counts as stuck.
const STALE_MS: i64 = 6_000;
/// How often the UI thread proves itself.
const BEAT_MS: u64 = 2_000;

/// What a running instance records about itself.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Record {
    pub pid: u32,
    pub last_beat_ms: i64,
    pub window_visible: bool,
}

/// What a launch should do about an instance that is already there.
#[derive(Debug, PartialEq)]
pub enum Action {
    /// Leave it to the single-instance plugin: either it is working, or the operator can see
    /// it and can tell it is not.
    HandOff,
    /// It cannot answer and has nothing on screen. Clear it and start.
    ClearZombie,
}

/// The decision, as a function of the record and the clock, so that it can be tested without
/// processes or windows.
pub fn decide(existing: Option<&Record>, now_ms: i64) -> Action {
    match existing {
        // Nothing to go on. An older build of Deepsand writes no record, and refusing to
        // start because of a process we cannot identify would be worse than a handoff.
        None => Action::HandOff,
        // Still beating: it is running.
        Some(record) if now_ms.saturating_sub(record.last_beat_ms) <= STALE_MS => Action::HandOff,
        // Stuck, but with a window: the operator can see it, and it may yet recover.
        Some(record) if record.window_visible => Action::HandOff,
        // Stuck with nothing on screen: this is the one that eats launches.
        Some(_) => Action::ClearZombie,
    }
}

/// The outcome of asking to be the instance.
#[derive(Debug)]
pub enum Claim {
    /// This process holds the lock and is the instance. The file must stay alive: the lock is
    /// released when it is dropped, which is how the next launch knows this one is gone.
    Primary(std::fs::File),
    /// A zombie was cleared, and this process now holds the lock.
    Cleared(std::fs::File, u32),
    /// Another instance holds the lock and is working. The plugin will hand this launch to it.
    Secondary,
    /// Another instance holds the lock, is stuck, and would not die. Start anyway, without the
    /// single-instance plugin: an app that refuses to open because of a process the operator
    /// cannot see is the bug being fixed here.
    TakeOverUncleared(u32),
}

fn lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join("instance.lock")
}

fn record_path(data_dir: &Path) -> PathBuf {
    data_dir.join("instance.json")
}

pub fn read_record(data_dir: &Path) -> Option<Record> {
    let raw = std::fs::read_to_string(record_path(data_dir)).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn write_record(data_dir: &Path, record: &Record) {
    if let Ok(raw) = serde_json::to_string(record) {
        let _ = std::fs::write(record_path(data_dir), raw);
    }
}

/// Take the instance lock if it is free.
fn try_claim(data_dir: &Path) -> Option<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path(data_dir))
        .ok()?;
    match file.try_lock() {
        Ok(()) => Some(file),
        Err(_) => None,
    }
}

/// End a process that cannot end itself.
fn terminate(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let mut command = if cfg!(windows) {
        let mut command = std::process::Command::new("taskkill");
        command.args(["/PID", &pid.to_string(), "/F"]);
        command
    } else {
        let mut command = std::process::Command::new("kill");
        command.args(["-9", &pid.to_string()]);
        command
    };
    // Never pop a console window when Deepsand runs as a GUI app on Windows.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Ask to be the instance, clearing an earlier one that cannot answer.
pub fn claim(data_dir: &Path) -> Claim {
    if let Some(lock) = try_claim(data_dir) {
        return Claim::Primary(lock);
    }

    let existing = read_record(data_dir);
    match decide(existing.as_ref(), deepsand_core::now_ms()) {
        Action::HandOff => {
            tracing::info!(
                pid = existing.as_ref().map(|record| record.pid).unwrap_or_default(),
                "another Deepsand is already running; this launch will be handed to it"
            );
            Claim::Secondary
        }
        Action::ClearZombie => {
            let pid = existing.map(|record| record.pid).unwrap_or_default();
            tracing::warn!(
                pid,
                "an earlier Deepsand is still running with no window and an unresponsive UI \
                 thread; clearing it so this launch can open"
            );
            let killed = terminate(pid);
            // The lock is released when that process dies. Wait for it briefly: a killed
            // process is reaped quickly, but nothing here is instantaneous.
            for _ in 0..40 {
                std::thread::sleep(Duration::from_millis(50));
                if let Some(lock) = try_claim(data_dir) {
                    tracing::warn!(pid, killed, "cleared the earlier Deepsand");
                    return Claim::Cleared(lock, pid);
                }
            }
            tracing::error!(
                pid,
                killed,
                "an earlier Deepsand is stuck and could not be cleared; starting anyway, without \
                 the single-instance guard. If the app misbehaves, end that process by hand."
            );
            Claim::TakeOverUncleared(pid)
        }
    }
}

/// Prove, from the UI thread, that this instance is still running.
///
/// The beat is *not* written by this thread. It is written by a closure scheduled onto the
/// main thread, so a process whose event loop has stopped turning stops beating, which is the
/// state that used to be undetectable. Visibility is read there too, so the record says
/// whether the app has anything on screen at the moment it last managed to look.
pub fn start_heartbeat(app: &tauri::AppHandle, data_dir: PathBuf) {
    // `get_webview_window` and `is_visible` come from this trait.
    use tauri::Manager as _;

    let handle = app.clone();
    std::thread::spawn(move || {
        let pid = std::process::id();
        loop {
            std::thread::sleep(Duration::from_millis(BEAT_MS));
            let for_beat = handle.clone();
            let dir = data_dir.clone();
            let _ = handle.run_on_main_thread(move || {
                let window_visible = for_beat
                    .get_webview_window("main")
                    .and_then(|window| window.is_visible().ok())
                    .unwrap_or(false);
                write_record(
                    &dir,
                    &Record {
                        pid,
                        last_beat_ms: deepsand_core::now_ms(),
                        window_visible,
                    },
                );
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(last_beat_ms: i64, window_visible: bool) -> Record {
        Record {
            pid: 4242,
            last_beat_ms,
            window_visible,
        }
    }

    #[test]
    fn a_healthy_instance_is_handed_the_launch() {
        assert_eq!(decide(Some(&record(10_000, true)), 11_000), Action::HandOff);
        assert_eq!(decide(Some(&record(10_000, false)), 11_000), Action::HandOff);
    }

    /// The reported bug: a process that stopped beating and has nothing on screen swallowed
    /// every launch, because the plugin handed the launch to it and exited.
    #[test]
    fn a_stuck_instance_with_no_window_is_cleared() {
        assert_eq!(
            decide(Some(&record(10_000, false)), 10_000 + STALE_MS + 1),
            Action::ClearZombie
        );
    }

    /// A window the operator can see is not stolen, even if the UI thread is stuck: they can
    /// tell it is not working, and replacing it could lose what it is doing.
    #[test]
    fn a_stuck_instance_with_a_window_is_left_alone() {
        assert_eq!(
            decide(Some(&record(10_000, true)), 10_000 + STALE_MS + 1),
            Action::HandOff
        );
    }

    /// An older build writes no record, and an unidentifiable process is not a zombie.
    #[test]
    fn a_missing_record_is_not_evidence_of_a_zombie() {
        assert_eq!(decide(None, 999_999), Action::HandOff);
    }

    #[test]
    fn a_record_round_trips_through_the_file_it_lives_in() {
        let dir = std::env::temp_dir().join(format!("deepsand-instance-{}", deepsand_core::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let written = record(1234, true);
        write_record(&dir, &written);
        assert_eq!(read_record(&dir).as_ref(), Some(&written));

        // Corrupt or absent is "nothing to go on", never a panic.
        std::fs::write(record_path(&dir), "{ not json").unwrap();
        assert_eq!(read_record(&dir), None);
        std::fs::remove_file(record_path(&dir)).unwrap();
        assert_eq!(read_record(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The whole point, with a real second process: a launch that finds an instance stuck
    /// with nothing on screen clears it and takes the lock.
    ///
    /// The helper is a process rather than another handle in this one because that is the
    /// difference being tested -- a lock held here is not a lock held by somebody else. It is
    /// skipped where no interpreter is available to hold one; on the machine this was written
    /// for (and in the failure that prompted it) it runs.
    #[test]
    fn a_zombie_holding_the_lock_is_cleared_and_the_lock_is_taken() {
        let dir = std::env::temp_dir().join(format!("deepsand-zombie-{}", deepsand_core::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        // The file has to exist before the helper opens it.
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(lock_path(&dir))
            .unwrap();

        const HELPER: &str = r#"
import json, msvcrt, os, sys, time
lock = sys.argv[1]
handle = open(lock, "r+")
msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
record = {"pid": os.getpid(), "last_beat_ms": 0, "window_visible": False}
open(os.path.join(os.path.dirname(lock), "instance.json"), "w").write(json.dumps(record))
time.sleep(120)
"#;

        let mut child = match std::process::Command::new("python")
            .arg("-c")
            .arg(HELPER)
            .arg(lock_path(&dir))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                eprintln!("skipped: no python to hold the lock ({err})");
                return;
            }
        };

        // Wait until the helper really holds it, rather than assuming it is quick.
        let mut held = false;
        for _ in 0..60 {
            std::thread::sleep(Duration::from_millis(50));
            if try_claim(&dir).is_none() {
                held = true;
                break;
            }
        }
        if !held {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the helper never took the lock, so this proves nothing");
        }

        match claim(&dir) {
            Claim::Cleared(_lock, pid) => {
                assert_eq!(pid, child.id(), "the pid in the record is the process cleared")
            }
            other => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("a stuck, windowless instance must be cleared, got {other:?}");
            }
        }

        // And it is gone, not merely asked to go.
        std::thread::sleep(Duration::from_millis(500));
        let exited = child.try_wait().map(|status| status.is_some()).unwrap_or(true);
        if !exited {
            let _ = child.kill();
        }
        assert!(exited, "the zombie should have been terminated");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The lock is what makes "is an instance already running?" answerable without trusting a
    /// pid, and a held lock is not the same thing as a live process: this one outlives the
    /// process that wrote it, which is fine because the record says whether it was working.
    #[test]
    fn the_lock_is_held_until_the_file_is_dropped() {
        let dir = std::env::temp_dir().join(format!("deepsand-lock-{}", deepsand_core::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = try_claim(&dir).expect("the first claim takes it");
        assert!(try_claim(&dir).is_none(), "a second claim must not");
        drop(first);
        assert!(try_claim(&dir).is_some(), "dropping it releases the lock");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
