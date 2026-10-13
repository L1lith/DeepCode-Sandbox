//! Deepsand core.
//!
//! Everything the desktop app needs in order to run DeepCode inside a container
//! it cannot leave:
//!
//! * [`paths`] validates every host path before it can become a mount.
//! * [`policy`] turns a project plus its grants into an exact `docker run`
//!   argument vector, with no escape hatches.
//! * [`docker`] is a thin, argument-safe wrapper around the Docker CLI.
//! * [`store`] persists projects, grants and settings.
//! * [`broker`] watches the request spool and answers it, which is how the
//!   contained DeepCode asks for more permissions.
//! * [`proxy`] is the allowlisting egress proxy used by the `restricted`
//!   network mode.
//! * [`session`] owns the PTY that the terminal pane renders.
//! * [`seccomp`] proves the profile being applied is the profile the image carries.

pub mod allowlist;
pub mod broker;
pub mod covered;
pub mod credentials;
pub mod docker;
pub mod error;
pub mod model;
pub mod paths;
pub mod remote;
pub mod policy;
pub mod proxy;
pub mod seccomp;
pub mod session;
pub mod secrets;
pub mod settings;
pub mod store;
pub mod tools;

pub use error::{Result, SandboxError};

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch. All timestamps in Deepsand use this so
/// the SolidJS frontend can format them with `new Date(ms)` directly.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Format a millisecond timestamp as an RFC 3339 UTC string.
pub fn iso_from_ms(ms: i64) -> String {
    // Deliberately hand-rolled: the only requirement is a stable, sortable,
    // human-readable stamp for state snapshots and audit lines.
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Days since 1970-01-01 -> civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}
