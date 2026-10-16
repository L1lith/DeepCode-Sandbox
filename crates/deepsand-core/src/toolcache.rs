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
///
/// The layer is identified by the `toolcache` bind mount, which is the one thing only that layer
/// has. It used to be identified by its apt cache mount -- and the *base* image's apt layer has
/// exactly that mount too, and comes first, so this fingerprinted the base layer and nothing else.
/// The consequence was not theoretical: it meant a change to the install steps did not invalidate
/// an entry, so a fix to those steps would be applied to a build that then reused the entry the
/// broken version had filled. The fixture in the test below was the reason it went unnoticed --
/// it had no base layer in front, so its first apt-mounting `RUN` really was the tools layer.
pub fn tools_layer_fingerprint(dockerfile: &str) -> String {
    let marker = "--mount=type=bind,from=toolcache";
    let Some(found) = dockerfile.find(marker) else {
        return String::new();
    };
    // Back up to the `RUN` this mount belongs to, so the digest covers the whole instruction
    // rather than starting in the middle of its options.
    let start = dockerfile[..found].rfind("RUN ").unwrap_or(found);
    let mut body = String::new();
    for line in dockerfile[start..].lines() {
        let trimmed = line.trim_end();
        // A comment inside a continued instruction does not end it -- that is Docker's own rule,
        // and this layer is full of them. Stopping at the first one, as this did, meant the digest
        // covered only the mount list at the top of the instruction: the gate and the installs
        // below it were outside the fingerprint, so a change to them left the key alone.
        let comment = trimmed.trim_start().starts_with('#');
        body.push_str(line.trim_end_matches('\r'));
        body.push('\n');
        // Otherwise a continued instruction is the whole instruction, and the first line that
        // does not end in a backslash ends it.
        if !comment && !trimmed.ends_with('\\') {
            break;
        }
    }
    crate::seccomp::digest(body.as_bytes())[..16].to_string()
}

/// The directory for one key, made ready for a build.
///
/// Three things belong together and are therefore one function: the directory is created (the
/// build mounts it as a context, so it has to exist), an entry that has aged past its limit is
/// *emptied* (the age rule), and the path is returned.
///
/// The shape is the point. These used to be three steps in the caller, and the caller logged the
/// second one while leaving the entry in place -- so the two-week rule was documented, reported,
/// and not actually enforced for two commits. A rule that lives in the code that applies it
/// cannot be forgotten by the code that uses it.
pub fn prepare_entry(data_dir: &Path, key: &str, now_ms: i64) -> PathBuf {
    let dir = cache_dir(data_dir, key);
    let _ = std::fs::create_dir_all(dir.join("bin"));
    let _ = std::fs::create_dir_all(dir.join("node_modules"));
    if dir.join(FILLED_MARKER).exists() && !cache_is_usable(&dir, now_ms) {
        clear_entry(&dir);
    }
    dir
}

/// Empty an entry, keeping the directory the build context points at.
pub fn clear_entry(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir.join("bin"));
    let _ = std::fs::remove_dir_all(dir.join("node_modules"));
    let _ = std::fs::remove_file(dir.join(FILLED_MARKER));
    let _ = std::fs::create_dir_all(dir.join("bin"));
    let _ = std::fs::create_dir_all(dir.join("node_modules"));
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

/// The versions one cache entry holds, by name.
pub type Versions = std::collections::BTreeMap<String, String>;

/// Where the two listings are kept, inside a cache entry. They are the output of the tools
/// themselves (`npm ls`, `cargo install --list`) taken when the entry was filled, so what is
/// compared against the registries is what the cache actually has rather than what it was
/// supposed to get.
pub const NPM_VERSIONS_FILE: &str = "versions-npm.json";
pub const CARGO_VERSIONS_FILE: &str = "versions-cargo.txt";
/// When the registries were last asked about this entry.
pub const CHECKED_MARKER: &str = "checked-at";

/// How often the registries are asked again.
///
/// Six hours: a tool released while somebody is working is rare, the check is a handful of HTTP
/// requests, and the cost of being a few hours behind is nothing next to the cost of asking on
/// every launch of a long-running app.
pub const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

/// Whether an entry is due to be checked, given when it last was.
///
/// `None` means never, which is due: an entry filled before this feature existed still has a
/// version listing written into it by the next fill, and until the registries have been asked
/// once there is nothing to compare.
pub fn check_is_due(last: Option<std::time::Duration>) -> bool {
    last.is_none_or(|age| age >= CHECK_INTERVAL)
}

/// The two listings in an entry, npm first.
pub fn read_versions(dir: &Path) -> (Versions, Versions) {
    let npm = std::fs::read_to_string(dir.join(NPM_VERSIONS_FILE))
        .map(|raw| parse_npm_versions(&raw))
        .unwrap_or_default();
    let cargo = std::fs::read_to_string(dir.join(CARGO_VERSIONS_FILE))
        .map(|raw| parse_cargo_versions(&raw))
        .unwrap_or_default();
    (npm, cargo)
}

/// The globals from `npm ls -g --depth=0 --json`.
///
/// Only the top level: the point is the tools, not the tree under them, and a transitive
/// dependency moving is not a reason to rebuild an image.
pub fn parse_npm_versions(json: &str) -> Versions {
    let mut out = Versions::new();
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json) else {
        return out;
    };
    if let Some(deps) = parsed.get("dependencies").and_then(|value| value.as_object()) {
        for (name, detail) in deps {
            if let Some(version) = detail.get("version").and_then(|value| value.as_str()) {
                out.insert(name.clone(), version.to_string());
            }
        }
    }
    out
}

/// The crates from `cargo install --list`, which is written for a human:
///
/// ```text
/// jq v0.4.0:
///     jq
/// ripgrep v14.1.0:
///     rg
/// ```
pub fn parse_cargo_versions(text: &str) -> Versions {
    let mut out = Versions::new();
    for line in text.lines() {
        let trimmed = line.trim();
        // A package line names the package and its version and ends with a colon; the lines
        // under it are the binaries it installed, which are not packages at all.
        if !trimmed.ends_with(':') || trimmed.contains(char::is_whitespace) == false {
            continue;
        }
        let mut parts = trimmed.trim_end_matches(':').split_whitespace();
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(version) = version.strip_prefix('v') else {
            continue;
        };
        if parts.next().is_some() {
            continue;
        }
        out.insert(name.to_string(), version.to_string());
    }
    out
}

/// Where to ask npm about one package, and how to read the answer.
pub fn npm_metadata_url(name: &str) -> String {
    format!("https://registry.npmjs.org/{name}/latest")
}

pub fn parse_npm_latest(json: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(json).ok()?;
    Some(parsed.get("version")?.as_str()?.to_string())
}

/// Where to ask crates.io about one crate, and how to read the answer.
pub fn crate_metadata_url(name: &str) -> String {
    format!("https://crates.io/api/v1/crates/{name}")
}

pub fn parse_crate_latest(json: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(json).ok()?;
    Some(
        parsed
            .get("crate")?
            .get("max_stable_version")?
            .as_str()?
            .to_string(),
    )
}

/// Which cached tools have moved on.
///
/// Compared for *difference* rather than by ordering the versions: a version string is not a
/// number, and the question that matters is only whether the one in the cache is still the one
/// the registry offers. A name the registry did not answer for is left alone rather than
/// counted as out of date.
pub fn outdated(cached: &Versions, latest: &Versions) -> Vec<(String, String, String)> {
    let mut moved: Vec<(String, String, String)> = cached
        .iter()
        .filter_map(|(name, held)| {
            let offered = latest.get(name)?;
            (offered != held).then(|| (name.clone(), held.clone(), offered.clone()))
        })
        .collect();
    moved.sort();
    moved
}

/// Record that the registries have been asked about this entry.
pub fn mark_checked(dir: &Path, now_ms: i64) -> std::io::Result<()> {
    std::fs::write(dir.join(CHECKED_MARKER), now_ms.to_string())
}

/// How long ago this entry was checked, or `None` when it never was.
pub fn last_checked(dir: &Path, now_ms: i64) -> Option<std::time::Duration> {
    let raw = std::fs::read_to_string(dir.join(CHECKED_MARKER)).ok()?;
    let checked: i64 = raw.trim().parse().ok()?;
    let age_ms = now_ms.saturating_sub(checked).max(0);
    Some(std::time::Duration::from_millis(age_ms as u64))
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
    ///
    /// The fixture is shaped like the real file, which this test's first version was not: it had
    /// no base layer, so its first `RUN` carrying an apt cache mount really was the tools layer.
    /// The real Dockerfile's base apt layer carries that same mount and comes first, so the
    /// fingerprint covered the base layer -- and a change to the install steps left the key
    /// alone, which is the one thing this function exists to prevent. A fix to those steps would
    /// then have been applied by a build that reused the entry the broken version filled, which
    /// is how this was found.
    #[test]
    fn the_fingerprint_follows_the_tools_layer_and_not_the_rest_of_the_file() {
        let dockerfile = "\
FROM node:22-bookworm-slim
RUN --mount=type=cache,target=/var/cache/apt \\\
    --mount=type=cache,target=/var/lib/apt/lists \\\
    set -eux; \\\
    apt-get install -y ca-certificates iptables tini;
COPY bin/ /usr/local/lib/deepsand/
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \\\
    --mount=type=cache,target=/root/.npm,sharing=locked \\\
    --mount=type=bind,from=toolcache,target=/toolcache \\\
    set -eux; \\\
    apt-get install -y jq;
COPY skills/ /home/deepcode/.agents/skills/
RUN npm install -g something-else
";
        let before = tools_layer_fingerprint(dockerfile);
        assert!(!before.is_empty());

        // Editing something after the tools layer leaves it alone.
        let edited = dockerfile.replace("something-else", "something-else-2");
        assert_eq!(before, tools_layer_fingerprint(&edited));

        // So does editing the base layer in front of it: a different layer, a different concern.
        let base = dockerfile.replace(
            "apt-get install -y ca-certificates iptables tini",
            "apt-get install -y ca-certificates iptables tini less",
        );
        assert_eq!(before, tools_layer_fingerprint(&base));

        // Editing the install steps does not.
        let changed = dockerfile.replace("apt-get install -y jq", "apt-get install -y jq zip");
        assert_ne!(before, tools_layer_fingerprint(&changed));

        // Including the part that decides whether a cache entry is used at all: a fix to that
        // logic has to produce a key that does not name an entry the broken version filled.
        let gated = dockerfile.replace("apt-get install -y jq", "npm ls -g --depth=0 jq");
        assert_ne!(before, tools_layer_fingerprint(&gated));
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

    /// The npm listing, in the shape `npm ls -g --depth=0 --json` really produces.
    #[test]
    fn the_npm_listing_gives_the_names_and_versions() {
        let fixture = r#"{
          "dependencies": {
            "@vegamo/deepcode-cli": { "version": "1.2.3" },
            "typescript": { "version": "5.6.2", "overridden": false }
          }
        }"#;
        let parsed = parse_npm_versions(fixture);
        assert_eq!(parsed.get("typescript").map(String::as_str), Some("5.6.2"));
        assert_eq!(
            parsed.get("@vegamo/deepcode-cli").map(String::as_str),
            Some("1.2.3"),
            "a scoped name is a name"
        );
        assert!(parse_npm_versions("not json").is_empty());
    }

    /// The cargo listing, which is written for a human and has to be read carefully: the lines
    /// under a package are its binaries, not more packages.
    #[test]
    fn the_cargo_listing_gives_the_packages_and_not_their_binaries() {
        let fixture = "jq v0.4.0:\n    jq\nripgrep v14.1.0:\n    rg\n";
        let parsed = parse_cargo_versions(fixture);
        assert_eq!(parsed.get("jq").map(String::as_str), Some("0.4.0"));
        assert_eq!(parsed.get("ripgrep").map(String::as_str), Some("14.1.0"));
        assert_eq!(parsed.len(), 2, "rg and jq are binaries, not packages");
    }

    /// The two registry answers, and the URLs they come from.
    #[test]
    fn the_registry_answers_are_read_from_the_fields_that_hold_them() {
        assert_eq!(
            npm_metadata_url("typescript"),
            "https://registry.npmjs.org/typescript/latest"
        );
        assert_eq!(
            parse_npm_latest(r#"{"name":"typescript","version":"5.6.2"}"#).as_deref(),
            Some("5.6.2")
        );
        assert_eq!(
            crate_metadata_url("ripgrep"),
            "https://crates.io/api/v1/crates/ripgrep"
        );
        assert_eq!(
            parse_crate_latest(r#"{"crate":{"max_stable_version":"14.1.0"}}"#).as_deref(),
            Some("14.1.0")
        );
        assert_eq!(parse_npm_latest("{}"), None);
        assert_eq!(parse_crate_latest("{}"), None);
    }

    /// What "out of date" means: differs, and the registry answered.
    #[test]
    fn only_tools_the_registry_has_moved_are_out_of_date() {
        let mut cached = Versions::new();
        cached.insert("typescript".into(), "5.6.2".into());
        cached.insert("ripgrep".into(), "14.1.0".into());
        cached.insert("unanswered".into(), "1.0.0".into());

        let mut latest = Versions::new();
        latest.insert("typescript".into(), "5.7.0".into());
        latest.insert("ripgrep".into(), "14.1.0".into());

        let moved = outdated(&cached, &latest);
        assert_eq!(moved.len(), 1, "equal is not out of date, unanswered is not either");
        assert_eq!(moved[0].0, "typescript");
        assert_eq!(moved[0].1, "5.6.2");
        assert_eq!(moved[0].2, "5.7.0");
    }

    /// The cadence: a check is due when it has never happened, and every six hours after.
    #[test]
    fn a_check_is_due_when_it_has_never_happened_or_has_gone_stale() {
        assert!(check_is_due(None));
        assert!(!check_is_due(Some(Duration::from_secs(60))));
        assert!(!check_is_due(Some(CHECK_INTERVAL - Duration::from_secs(1))));
        assert!(check_is_due(Some(CHECK_INTERVAL)));
        assert!(check_is_due(Some(Duration::from_secs(48 * 60 * 60))));
        assert!(CHECK_INTERVAL >= Duration::from_secs(60 * 60), "not every few minutes");
    }

    /// The age rule, as the build actually experiences it: a stale entry is empty by the time
    /// the caller gets the path, which is what was missing when only the caller knew the rule.
    #[test]
    fn a_stale_entry_is_emptied_before_the_build_that_would_have_used_it() {
        let root = fresh_dir("toolcache-prepare");
        let now = 1_700_000_000_000i64;
        let dir = prepare_entry(&root, "stale00000000000", now);
        std::fs::write(dir.join("bin").join("tool"), "built once").unwrap();
        mark_filled(&dir, now).unwrap();
        assert!(cache_is_usable(&dir, now));

        // Two weeks and a day later, the same key is prepared for the next build.
        let later = now + 15 * 24 * 60 * 60 * 1000;
        let again = prepare_entry(&root, "stale00000000000", later);
        assert_eq!(again, dir);
        assert!(
            !again.join("bin").join("tool").exists(),
            "the stale tools are gone, so this build installs and refills"
        );
        assert!(!again.join(FILLED_MARKER).exists(), "and it is no longer marked filled");
        assert!(again.join("bin").is_dir(), "the directory the context mounts is still there");
        assert!(again.join("node_modules").is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The other half: a fresh entry is left exactly as it was, because recompiling tools that
    /// are current is the whole cost this cache exists to avoid.
    #[test]
    fn a_fresh_entry_is_left_alone() {
        let root = fresh_dir("toolcache-fresh");
        let now = 1_700_000_000_000i64;
        let dir = prepare_entry(&root, "fresh00000000000", now);
        std::fs::write(dir.join("bin").join("tool"), "built once").unwrap();
        mark_filled(&dir, now).unwrap();

        let soon = now + 60 * 60 * 1000;
        let again = prepare_entry(&root, "fresh00000000000", soon);
        assert!(again.join("bin").join("tool").exists(), "still there");
        assert!(again.join(FILLED_MARKER).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An entry that was never filled is just a directory waiting to be one, and nothing is
    /// removed from it: there is nothing to remove.
    #[test]
    fn an_unfilled_entry_is_only_made_ready() {
        let root = fresh_dir("toolcache-ready");
        let dir = prepare_entry(&root, "empty00000000000", 1_000);
        assert!(dir.join("bin").is_dir());
        assert!(dir.join("node_modules").is_dir());
        assert!(!cache_is_usable(&dir, 1_000), "and it is still not a cache");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A directory of its own under the system temp directory, so tests do not collide.
    fn fresh_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("deepsand-{name}-{}", crate::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
