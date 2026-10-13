//! Proving that the seccomp profile being applied is the profile the image carries.
//!
//! The daemon does not read the profile out of the image. `--security-opt=seccomp=` is
//! resolved on the **host**, so the file that decides what the sandbox may do is the
//! host's copy — while the copy inside the image is only ever read by someone auditing
//! it. Those are two artifacts, built at different times, possibly from different
//! working trees, and until this module existed nothing compared them.
//!
//! Round 3 of the escape assessment found the gap by measuring it. `AF_VSOCK` was
//! refused, because the applied profile had the socket-family rules; the profile inside
//! the image contained no `socket` rule at all and would not have refused it. So the
//! behavioural fix was real but could not be attributed to the artifact the project
//! ships and versions, and anyone rebuilding from the image would have measured an
//! escape.
//!
//! The remedy is a digest. The Dockerfile writes the SHA-256 of the copied profile
//! beside it, and [`verify`] compares that with the digest of the bytes the host is
//! about to hand to the daemon. A mismatch, a missing digest or a malformed one is a
//! refusal rather than a warning: a sandbox whose hardening cannot be attributed to the
//! image it is running is a sandbox whose hardening nobody can audit.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{Result, SandboxError};

/// The image's own copy of the profile, and the digest written beside it by the
/// Dockerfile. Both are read out of a running image, never from the host.
pub const IMAGE_PROFILE_PATH: &str = "/usr/local/lib/deepsand/seccomp-hardened.json";
pub const IMAGE_DIGEST_PATH: &str = "/usr/local/lib/deepsand/seccomp-hardened.sha256";

/// Locate the `runtime/` directory the image is built from.
///
/// There used to be three of these, one each in the desktop planner, the image builder and
/// the headless CLI, and they did not agree: two looked for the profile beside the
/// executable rather than in its `runtime/` subdirectory. Disagreeing about which tree the
/// runtime lives in is how the profile being applied and the profile inside the image came
/// from different trees -- R3-A of the escape assessment. One resolver, one answer.
pub fn runtime_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::var_os("DEEPSAND_RUNTIME_DIR") {
        candidates.push(PathBuf::from(dir));
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("runtime"));
    }
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(PathBuf::from))
    {
        candidates.push(exe_dir.join("runtime"));
        candidates.push(exe_dir.join("resources").join("runtime"));
        candidates.push(exe_dir.join("_up_").join("runtime"));
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.join("Dockerfile").is_file())
}

/// The hardened profile inside [`runtime_dir`], when hardening is on and the file is there.
pub fn profile_path(hardened: bool) -> Option<PathBuf> {
    if !hardened {
        return None;
    }
    let candidate = runtime_dir()?.join("seccomp-hardened.json");
    candidate.is_file().then_some(candidate)
}

/// SHA-256 of these bytes, lowercase hex.
pub fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// SHA-256 of a profile on disk.
pub fn digest_of(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).map_err(|err| {
        SandboxError::policy(format!(
            "hardening is on, but the seccomp profile could not be read from {}: {err}",
            path.display()
        ))
    })?;
    Ok(digest(&bytes))
}

/// Pull a digest out of the image's digest file.
///
/// `sha256sum` writes `<hex>  <path>`, so only the first field is the digest. Anything
/// that is not exactly 64 hex characters is treated as absent rather than guessed at:
/// a digest that cannot be read is a digest that cannot vouch for anything.
pub fn parse_digest_file(raw: &str) -> Option<String> {
    let first = raw.split_whitespace().next()?.to_ascii_lowercase();
    let well_formed = first.len() == 64 && first.bytes().all(|byte| byte.is_ascii_hexdigit());
    well_formed.then_some(first)
}

/// Compare the profile the host will apply against the digest the image carries.
///
/// Returns the digest on success. Every failure mode is an error, including an
/// unreadable or malformed digest file, because "I could not check" and "the check
/// passed" must not look the same to a caller.
pub fn verify(profile: &Path, in_image_digest_file: &str) -> Result<String> {
    let applied = digest_of(profile)?;
    let Some(in_image) = parse_digest_file(in_image_digest_file) else {
        return Err(SandboxError::policy(format!(
            "hardening is on, but the runtime image does not carry a readable seccomp digest \
             (expected 64 hex characters at {IMAGE_DIGEST_PATH}). The image predates the digest \
             being written, or it was built from a different runtime directory. Rebuild the \
             image before starting the sandbox: until then no one can tell whether the profile \
             being applied is the profile the image was built with."
        )));
    };
    if applied != in_image {
        return Err(SandboxError::policy(format!(
            "the seccomp profile being applied is not the one the image carries, so the \
             hardening cannot be attributed to the image that is running.\n  \
             applied   : {applied}  ({})\n  in image  : {in_image}  ({IMAGE_PROFILE_PATH})\n\
             One of the two is stale. Rebuild the runtime image, and check that the runtime \
             directory in use is the one you think it is.",
            profile.display()
        )));
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("deepsand-seccomp-{name}-{}", crate::now_ms()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn the_digest_is_the_sha256_of_the_bytes() {
        // The empty-input vector, so this is a real check of the hash and not just of the
        // formatting.
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(digest(b"abc").len(), 64);
        assert_ne!(digest(b"abc"), digest(b"abd"));
    }

    #[test]
    fn a_digest_file_is_read_as_its_first_field() {
        let hex = "a".repeat(64);
        assert_eq!(parse_digest_file(&format!("{hex}  /usr/local/x\n")), Some(hex.clone()));
        assert_eq!(parse_digest_file(&format!("  {hex}\n")), Some(hex.clone()));
        // Uppercase is the same digest, and sha256sum output on some systems is upper.
        assert_eq!(parse_digest_file(&hex.to_uppercase()), Some(hex));
    }

    #[test]
    fn an_unreadable_digest_is_absent_rather_than_guessed() {
        assert_eq!(parse_digest_file(""), None);
        assert_eq!(parse_digest_file("\n"), None);
        assert_eq!(parse_digest_file("not a digest"), None);
        // One character short, and one long: both are treated as missing.
        assert_eq!(parse_digest_file(&"a".repeat(63)), None);
        assert_eq!(parse_digest_file(&"a".repeat(65)), None);
        // Right length, wrong alphabet.
        assert_eq!(parse_digest_file(&"z".repeat(64)), None);
    }

    #[test]
    fn a_matching_profile_is_accepted() {
        let dir = scratch("match");
        let profile = dir.join("seccomp-hardened.json");
        std::fs::write(&profile, b"{\"defaultAction\":\"SCMP_ACT_ALLOW\"}").unwrap();

        let applied = digest_of(&profile).expect("digest");
        let verified = verify(&profile, &format!("{applied}  {IMAGE_PROFILE_PATH}\n"))
            .expect("the image carries the same bytes");
        assert_eq!(verified, applied);
    }

    #[test]
    fn a_stale_image_is_refused_and_says_which_side_is_which() {
        // This is round 3's finding as a test: the applied profile had the socket rules,
        // the image did not. The message has to name both digests, or the operator cannot
        // tell which artifact to rebuild.
        let dir = scratch("mismatch");
        let profile = dir.join("seccomp-hardened.json");
        std::fs::write(&profile, b"applied profile, with socket rules").unwrap();

        let err = verify(&profile, &format!("{}  x\n", "b".repeat(64)))
            .expect_err("a mismatch must refuse");
        let text = err.to_string();
        assert!(text.contains("not the one the image carries"), "{text}");
        assert!(text.contains(&"b".repeat(64)), "the image digest is named: {text}");
        assert!(
            text.contains(&digest_of(&profile).unwrap()),
            "the applied digest is named: {text}"
        );
        assert!(text.contains("Rebuild"), "{text}");
    }

    #[test]
    fn an_image_without_a_digest_is_refused_rather_than_assumed_old() {
        let dir = scratch("nodigest");
        let profile = dir.join("seccomp-hardened.json");
        std::fs::write(&profile, b"{}").unwrap();

        let err = verify(&profile, "").expect_err("a missing digest must refuse");
        assert!(err.to_string().contains("Rebuild the image"), "{err}");
    }

    #[test]
    fn a_missing_profile_is_refused() {
        let dir = scratch("missing");
        let err = verify(&dir.join("nope.json"), &"a".repeat(64))
            .expect_err("an unreadable profile must refuse");
        assert!(err.to_string().contains("could not be read"), "{err}");
    }
}
