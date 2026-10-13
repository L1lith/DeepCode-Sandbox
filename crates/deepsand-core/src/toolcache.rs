//! The tools cache: the built tools, kept on the host so an image build does not compile and
//! download them again.
//!
//! What is cached and what is not, and why:
//!
//! * **cargo installs** -- compiled from source, minutes of work, the biggest win.
//! * **npm globals** (including the DeepCode CLI) -- registry round-trips and unpacking.
//! * **not apt packages** -- the build already has cache mounts for `/var/cache/apt` and
//!   `/var/lib/apt/lists`, so apt re-resolves but does not re-download, and copying installed
//!   system packages out of an image and back in is the fiddliest thing here for the smallest
//!   gain.
//!
//! The cache is filled *from a successful image build*, not by a parallel install: the tools in
//! it are then exactly what that image has, which is the property that keeps the cache honest.
//! A build that fails while using the cache drops it, so a bad entry heals itself.
//!
//! The key is the part that has to be right. Too wide and a stale binary is copied in; too
//! narrow and the cache never hits. It covers the platform, the tool selection, the version of
//! the install steps themselves, and a fingerprint of the tools layer in the Dockerfile -- so
//! editing the installer invalidates the cache, and editing anything else in the runtime does
//! not. That second half matters: the image tag changes on every runtime edit, and without a
//! narrower key the tools would be recompiled every time somebody fixed a comment.

use std::path::{Path, PathBuf};

/// Bump this when the *install steps* change in a way the fingerprint cannot see, or when a
/// cached entry would otherwise be wrong for a reason no input describes.
pub const TOOL_CACHE_VERSION: u32 = 1;

/// Where the cache lives for one key, inside the app's data directory.
pub fn cache_dir(data_dir: &Path, key: &str) -> PathBuf {
    data_dir.join("buildcache").join(key)
}

/// The key for one build's tools.
///
/// `arch` comes from the daemon (`linux/amd64`, `linux/arm64`) because a binary built for one
/// will not run on the other, and `selection` is the sorted tool list, because two projects with
/// different tools need different caches.
pub fn cache_key(arch: &str, selection: &[String], tools_layer: &str) -> String {
    let mut sorted: Vec<&str> = selection.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let material = format!(
        "v{TOOL_CACHE_VERSION}\n{arch}\n{}\n{}",
        sorted.join(","),
        tools_layer
    );
    // Short enough to read in a directory listing, long enough that a collision is not a thing
    // to think about: this is compared for equality, never guessed.
    crate::seccomp::digest(material.as_bytes())[..16].to_string()
}

/// A fingerprint of the tools layer in the Dockerfile: the `RUN` whose cache mounts install the
/// tools, up to the instruction's last continuation line.
///
/// Extracted rather than hashing the whole file for the reason in the module comment: the image
/// tag already changes on every runtime edit, and this must not.
pub fn tools_layer_fingerprint(dockerfile: &str) -> String {
    let marker = "RUN --mount=type=cache,target=/var/cache/apt";
    let Some(start) = dockerfile.find(marker) else {
        return String::new();
    };
    let mut body = String::new();
    for line in dockerfile[start..].lines() {
        body.push_str(line.trim_end_matches('\r'));
        body.push('\n');
        // A continued instruction is the whole instruction; the first line that does not end in
        // a backslash ends it.
        if !line.trim_end().ends_with('\\') {
            break;
        }
    }
    crate::seccomp::digest(body.as_bytes())[..16].to_string()
}

/// How old a cache entry may be before it is treated as absent.
///
/// The tools are installed as `@latest`, so an entry does not stay current by itself, and the
/// point of a cache is not to freeze them forever. This is the "only when necessary" half of
/// that: a key that changes invalidates at once (a different selection, a changed installer,
/// another platform), and this covers the one thing no key can see -- time passing.
///
/// The DeepCode CLI is deliberately *not* covered by it. It is refreshed on every build, bounded
/// by npm's fetch limits and non-fatal when a copy already exists, because for that one tool
/// "latest" is the point of the refresh.
pub const TOOL_CACHE_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(14 * 24 * 60 * 60);

/// The file whose contents say when an entry was filled.
pub const FILLED_MARKER: &str = "filled-at";

/// Whether an entry of this age is still worth using.
pub fn cache_is_fresh(age: std::time::Duration) -> bool {
    age < TOOL_CACHE_MAX_AGE
}

/// Record that a build has just filled this entry with its own tools.
pub fn mark_filled(dir: &Path, now_ms: i64) -> std::io::Result<()> {
    std::fs::write(dir.join(FILLED_MARKER), now_ms.to_string())
}

/// How long ago this entry was filled, or `None` when it never was.
pub fn filled_age(dir: &Path, now_ms: i64) -> Option<std::time::Duration> {
    let raw = std::fs::read_to_string(dir.join(FILLED_MARKER)).ok()?;
    let filled: i64 = raw.trim().parse().ok()?;
    let age_ms = now_ms.saturating_sub(filled).max(0);
    Some(std::time::Duration::from_millis(age_ms as u64))
}

/// Whether the entry in this directory may be used for a build right now.
///
/// Three things have to hold, and each is a way this went wrong in the design rather than in
/// theory: it has tools in it, it says when it was filled, and that was recent enough. An
/// entry with no marker is not used -- something wrote the directory without the tools in it,
/// and a directory timestamp is a guess.
pub fn cache_is_usable(dir: &Path, now_ms: i64) -> bool {
    let has_tools = dir.join("bin").is_dir() || dir.join("node_modules").is_dir();
    has_tools && filled_age(dir, now_ms).is_some_and(cache_is_fresh)
}

#[cfg(test)]
mod tool_cache_tests {
    use super::*;
    use std::time::Duration;

    fn selection(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    /// The property the cache lives or dies by: same inputs, same key.
    #[test]
    fn the_same_build_inputs_give_the_same_key() {
        let a = cache_key("linux/amd64", &selection(&["rg", "jq"]), "abc123");
        let b = cache_key("linux/amd64", &selection(&["jq", "rg"]), "abc123");
        assert_eq!(a, b, "the order of the tool list is not part of the key");
        assert_eq!(a.len(), 16);
    }

    /// Every input that changes what gets built has to change the key.
    #[test]
    fn every_input_that_changes_the_tools_changes_the_key() {
        let base = cache_key("linux/amd64", &selection(&["rg"]), "abc123");
        assert_ne!(base, cache_key("linux/arm64", &selection(&["rg"]), "abc123"));
        assert_ne!(base, cache_key("linux/amd64", &selection(&["rg", "jq"]), "abc123"));
        assert_ne!(base, cache_key("linux/amd64", &selection(&["rg"]), "def456"));
    }

    /// The fingerprint follows the tools layer and nothing else -- the reason it is extracted
    /// rather than hashing the Dockerfile.
    #[test]
    fn the_fingerprint_follows_the_tools_layer_and_not_the_rest_of_the_file() {
        let dockerfile = "\
FROM node:22-bookworm-slim
COPY bin/ /usr/local/lib/deepsand/
RUN --mount=type=cache,target=/var/cache/apt \\
    --mount=type=cache,target=/root/.npm \\
    set -eux; \\
    apt-get install -y jq;
COPY skills/ /home/deepcode/.agents/skills/
RUN npm install -g something-else
";
        let before = tools_layer_fingerprint(dockerfile);
        assert!(!before.is_empty());

        // Editing something after the tools layer leaves it alone.
        let edited = dockerfile.replace("something-else", "something-else-2");
        assert_eq!(before, tools_layer_fingerprint(&edited));

        // Editing the install steps does not.
        let changed = dockerfile.replace("apt-get install -y jq", "apt-get install -y jq zip");
        assert_ne!(before, tools_layer_fingerprint(&changed));
    }

    #[test]
    fn a_dockerfile_with_no_tools_layer_has_no_fingerprint() {
        assert!(tools_layer_fingerprint("FROM scratch\n").is_empty());
    }

    #[test]
    fn the_cache_lives_under_the_data_directory() {
        let dir = cache_dir(Path::new("/data"), "0123456789abcdef");
        assert!(dir.ends_with("buildcache/0123456789abcdef"));
    }

    /// The freshness half of the rule, on its own: this is the part that decides whether an
    /// entry that *is* keyed correctly still gets used.
    #[test]
    fn an_entry_is_used_until_it_is_too_old_and_then_it_is_not() {
        assert!(cache_is_fresh(Duration::from_secs(0)));
        assert!(cache_is_fresh(Duration::from_secs(13 * 24 * 60 * 60)));
        assert!(!cache_is_fresh(TOOL_CACHE_MAX_AGE));
        assert!(!cache_is_fresh(Duration::from_secs(30 * 24 * 60 * 60)));
        // Two weeks: rare enough that the install cost is occasional, short enough that a tool
        // does not drift for a whole release cycle.
        assert!(TOOL_CACHE_MAX_AGE >= Duration::from_secs(7 * 24 * 60 * 60));
        assert!(TOOL_CACHE_MAX_AGE <= Duration::from_secs(30 * 24 * 60 * 60));
    }

    /// A directory with the right shape but no marker is not usable: nothing says the tools in
    /// it are the ones this key asked for.
    #[test]
    fn an_entry_with_no_marker_is_not_used() {
        let root = fresh_dir("toolcache-nomarker");
        let dir = root.join("entry");
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        assert!(!cache_is_usable(&dir, 1_000));
        assert_eq!(filled_age(&dir, 1_000), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Filling an entry, and then reading it back, is what the app does around a build.
    #[test]
    fn a_filled_entry_is_usable_and_becomes_unusable_with_age() {
        let root = fresh_dir("toolcache-filled");
        let dir = root.join("entry");
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let now = 1_700_000_000_000i64;
        mark_filled(&dir, now).unwrap();

        assert!(cache_is_usable(&dir, now));
        assert!(cache_is_usable(&dir, now + 5 * 24 * 60 * 60 * 1000));

        let old = now + 15 * 24 * 60 * 60 * 1000;
        assert!(!cache_is_usable(&dir, old), "older than the limit is not used");
        assert_eq!(filled_age(&dir, old).unwrap().as_secs(), 15 * 24 * 60 * 60);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The app asks "is there anything cached here" with the directory it is about to hand the
    /// build, so an empty one has to mean no.
    #[test]
    fn an_empty_directory_is_not_a_cache() {
        let root = fresh_dir("toolcache-empty");
        let dir = root.join("entry");
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        mark_filled(&dir, 1_000).unwrap();
        // A marker with no tools in it is still not a cache.
        let bare = root.join("bare");
        std::fs::create_dir_all(&bare).unwrap();
        mark_filled(&bare, 1_000).unwrap();
        assert!(!cache_is_usable(&bare, 1_000));
        assert!(cache_is_usable(&dir, 1_000), "a marked, populated entry is a cache");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A directory of its own under the system temp directory, so tests do not collide.
    fn fresh_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("deepsand-{name}-{}", crate::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
