//! Per-project secrets: encrypted at rest, injected as environment variables, and
//! redacted from anything the operator or the agent might read.
//!
//! # Threat model, stated plainly
//!
//! The key lives in the operating system's keystore (DPAPI on Windows, Keychain on
//! macOS, Secret Service on Linux) via `keyring`. That protects a secret against
//! *casual* disclosure: a copy of the data directory, a synced folder, a backup, a
//! support bundle. It does **not** protect against anything running as the operator,
//! which can read the keystore too — an agent that has escaped the sandbox and is
//! running as the user could ask for the key exactly as Deepsand does.
//!
//! So this is confidentiality at rest, not a boundary. The boundary remains the
//! container, and the reason secrets are worth encrypting is that the *file* travels
//! further than the process does.
//!
//! `DEEPSAND_SECRETS_KEY` is a fallback for a machine with no keystore (a headless
//! CI box, a container). It is a degraded mode with the same threat model as writing
//! the key next to the ciphertext, so it is opt-in and never chosen silently.
//!
//! # What is never done
//!
//! * Secret values are never written to the audit log, to stdout, or into a plan.
//! * They are never passed as `docker run -e`, which would expose them in the
//!   process argument list where any local user could read them. They go through an
//!   `--env-file` instead, written 0600.
//! * A secret name cannot shadow anything the sandbox needs. `PATH`, `HOME`,
//!   `DEEPSAND_*` and friends are refused, so a secret cannot become a hijack.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SandboxError};

/// Length of the ChaCha20-Poly1305 key.
const KEY_BYTES: usize = 32;
/// Where the key is kept in the OS keystore.
const KEYRING_SERVICE: &str = "deepsand";
/// The filename inside a project directory.
const FILE: &str = "secrets.json";
/// Env var name read when the keystore is unavailable.
pub const ENV_KEY: &str = "DEEPSAND_SECRETS_KEY";

/// Names a secret may not use, because the sandbox or the entrypoint relies on them.
///
/// Without this, `set("PATH", ...)` would be a way to break the sandbox's own tooling
/// and `set("DEEPSAND_NETWORK_MODE", ...)` would be a way to try to change the egress
/// policy from inside the data directory.
const RESERVED: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "PWD",
    "TERM",
    "HOSTNAME",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "IFS",
    "BASH_ENV",
    "ENV",
];

/// A cipher from a 32-byte key. The length is fixed by the type, so the only way
/// this fails is a programming error rather than bad input.
fn new_cipher(key: [u8; KEY_BYTES]) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| SandboxError::policy("the secrets key is the wrong length"))
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    v: u32,
    /// Base64 nonce. Fresh for every save, so two saves of the same map differ.
    nonce: String,
    /// Base64 ciphertext, authenticated.
    data: String,
}

/// One project's secrets.
pub struct Secrets {
    path: PathBuf,
    cipher: ChaCha20Poly1305,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque: a Secret in a log line must never print a key.
        f.debug_struct("Secrets").field("path", &self.path).finish()
    }
}

/// Whether a name is a usable environment variable and not something reserved.
pub fn validate_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(SandboxError::policy("a secret needs a name"));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(SandboxError::policy(format!(
            "'{name}' is not a usable environment variable name: it must start with a letter or an \
             underscore."
        )));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(SandboxError::policy(format!(
            "'{name}' is not a usable environment variable name: use letters, digits and \
             underscores only."
        )));
    }
    let upper = name.to_ascii_uppercase();
    if RESERVED.contains(&upper.as_str()) || upper.starts_with("DEEPSAND_") {
        return Err(SandboxError::policy(format!(
            "'{name}' is reserved. A secret must not shadow a variable the sandbox relies on, or it \
             could change how the sandbox itself behaves."
        )));
    }
    Ok(name.to_string())
}

/// Names a secret may not use, for the form to refuse up front rather than after a
/// failed submit.
pub fn reserved_names() -> Vec<String> {
    let mut names: Vec<String> = RESERVED.iter().map(|name| (*name).to_string()).collect();
    names.push("DEEPSAND_*".to_string());
    names
}

impl Secrets {
    /// Open (or start) the store for one project.
    pub fn open(data_dir: &Path, project_id: &str) -> Result<Self> {
        let path = data_dir.join("projects").join(project_id).join(FILE);
        Ok(Self {
            cipher: new_cipher(key_for(data_dir)?)?,
            path,
        })
    }

    /// The names held, sorted. Reading the names still needs the key, because the
    /// whole map is one ciphertext.
    pub fn names(&self) -> Result<Vec<String>> {
        Ok(self.load()?.into_keys().collect())
    }

    /// Every name and value. Used to build the sandbox's environment file.
    pub fn all(&self) -> Result<BTreeMap<String, String>> {
        self.load()
    }

    /// Whether anything is stored at all, without needing the key.
    pub fn exists(data_dir: &Path, project_id: &str) -> bool {
        data_dir
            .join("projects")
            .join(project_id)
            .join(FILE)
            .is_file()
    }

    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        let name = validate_name(name)?;
        if value.is_empty() {
            return Err(SandboxError::policy(format!(
                "'{name}' has an empty value. Use remove if you meant to delete it."
            )));
        }
        let mut map = self.load()?;
        map.insert(name, value.to_string());
        self.save(&map)
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        let mut map = self.load()?;
        map.remove(name.trim());
        self.save(&map)
    }

    fn load(&self) -> Result<BTreeMap<String, String>> {
        if !self.path.is_file() {
            return Ok(BTreeMap::new());
        }
        let raw = std::fs::read_to_string(&self.path)
            .map_err(|err| SandboxError::policy(format!("could not read the secrets file: {err}")))?;
        if raw.trim().is_empty() {
            return Ok(BTreeMap::new());
        }
        let envelope: Envelope = serde_json::from_str(&raw).map_err(|err| {
            SandboxError::policy(format!(
                "the secrets file could not be parsed ({err}). It may have been written by a newer \
                 Deepsand, or damaged."
            ))
        })?;
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(&envelope.nonce)
            .map_err(|_| SandboxError::policy("the secrets file has a malformed nonce"))?;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&envelope.data)
            .map_err(|_| SandboxError::policy("the secrets file has malformed contents"))?;
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), data.as_slice())
            .map_err(|_| {
            SandboxError::policy(
                "the secrets for this project could not be decrypted with the key in your operating \
                 system's keystore. If the key was rotated or the keystore entry was removed, the \
                 stored secrets are unrecoverable and will need to be re-entered.",
                )
            })?;
        serde_json::from_slice(&plaintext).map_err(|err| {
            SandboxError::policy(format!("the decrypted secrets were not readable: {err}"))
        })
    }

    fn save(&self, map: &BTreeMap<String, String>) -> Result<()> {
        let plaintext = serde_json::to_vec(map)
            .map_err(|err| SandboxError::policy(format!("could not encode the secrets: {err}")))?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|_| SandboxError::policy("could not encrypt the secrets"))?;
        let envelope = Envelope {
            v: 1,
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
            data: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                SandboxError::policy(format!("could not create the project directory: {err}"))
            })?;
        }
        let encoded = serde_json::to_string_pretty(&envelope)
            .map_err(|err| SandboxError::policy(format!("could not encode the secrets: {err}")))?;
        // Written through a temporary file so a crash cannot leave a half-written
        // store that would then fail to decrypt at all.
        let staging = self.path.with_extension("json.new");
        std::fs::write(&staging, encoded.as_bytes()).map_err(|err| {
            SandboxError::policy(format!("could not write the secrets file: {err}"))
        })?;
        restrict(&staging);
        // Contents before name. A rename is atomic but not durable on its own: without this,
        // a crash can commit the name and lose the data, leaving a file of NULs at the right
        // size -- which is exactly how this machine lost a Dockerfile, the state file and the
        // tail of a log. Of everything here, secrets are the least recoverable: the file is
        // encrypted, so a damaged one cannot be salvaged by reading it.
        if let Ok(handle) = std::fs::OpenOptions::new().write(true).open(&staging) {
            let _ = handle.sync_all();
        }
        std::fs::rename(&staging, &self.path).map_err(|err| {
            SandboxError::policy(format!("could not replace the secrets file: {err}"))
        })?;
        Ok(())
    }

    /// The `.env` file handed to `docker run --env-file`, not to `-e`.
    ///
    /// Written 0600 in the project's own directory. `-e` would put every value in the
    /// process argument list, where any local user could read it with `ps`.
    pub fn write_env_file(&self, dir: &Path) -> Result<Option<PathBuf>> {
        let map = self.all()?;
        let path = dir.join("secrets.env");
        if map.is_empty() {
            // Remove a stale file, so a secret that was deleted does not linger in
            // an environment file the next container would still be handed.
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        }
        let mut body = String::new();
        for (name, value) in &map {
            // Values are not quoted: docker's env-file treats the rest of the line
            // literally, and quoting would become part of the value.
            body.push_str(name);
            body.push('=');
            body.push_str(value);
            body.push('\n');
        }
        std::fs::write(&path, body.as_bytes()).map_err(|err| {
            SandboxError::policy(format!("could not write the sandbox environment file: {err}"))
        })?;
        restrict(&path);
        Ok(Some(path))
    }

    /// Replace every occurrence of a stored value with a marker.
    ///
    /// Longest first, so a secret that contains another secret is not partially
    /// replaced and left half-visible.
    pub fn redact(&self, text: &str) -> String {
        let mut values: Vec<String> = self.all().map(|map| map.into_values().collect()).unwrap_or_default();
        values.retain(|value| value.len() >= 4);
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        let mut out = text.to_string();
        for value in values {
            if out.contains(&value) {
                out = out.replace(&value, "[redacted]");
            }
        }
        out
    }

    /// The values alone, for handing to the proxy so a blocked request cannot log one.
    pub fn values(&self) -> Vec<String> {
        let mut values: Vec<String> = self.all().map(|map| map.into_values().collect()).unwrap_or_default();
        values.retain(|value| value.len() >= 4);
        values
    }
}

/// Best-effort 0600. Not fatal when it fails: on Windows the mode bits are largely
/// advisory, and the directory is already per-user.
fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// The encryption key, from the OS keystore, or from the environment as a fallback.
fn key_for(data_dir: &Path) -> Result<[u8; KEY_BYTES]> {
    // Scoped per installation, so two Deepsand data directories do not share a key.
    let account = format!("secrets:{}", short_hash(&data_dir.display().to_string()));

    match keyring::Entry::new(KEYRING_SERVICE, &account) {
        Ok(entry) => match entry.get_password() {
            Ok(stored) => {
                if let Some(key) = decode_key(&stored) {
                    return Ok(key);
                }
                // A keystore entry we cannot read is not something to silently
                // replace: the stored secrets are encrypted with it.
                return Err(SandboxError::policy(
                    "the key in your operating system's keystore is not a valid Deepsand secrets key. \
                     Remove the keystore entry for 'deepsand' if you are happy to lose the stored \
                     secrets, then set them again.",
                ));
            }
            Err(keyring::Error::NoEntry) => {
                // First run: make one and keep it.
                let mut key = [0u8; KEY_BYTES];
                getrandom::getrandom(&mut key).map_err(|_| {
                    SandboxError::policy("the OS entropy source is unavailable, so a key cannot be made")
                })?;
                let encoded = encode(&key);
                if let Err(err) = entry.set_password(&encoded) {
                    return Err(SandboxError::policy(format!(
                        "a new secrets key could not be saved to your operating system's keystore \
                         ({err}). Set {ENV_KEY} instead to run without a keystore."
                    )));
                }
                return Ok(key);
            }
            Err(err) => {
                // A keystore that exists but refuses (locked, or a headless session)
                // falls through to the environment rather than failing outright.
                tracing::warn!("the OS keystore could not be read ({err}); checking {ENV_KEY}");
            }
        },
        Err(err) => {
            tracing::warn!("the OS keystore is unavailable ({err}); checking {ENV_KEY}");
        }
    }

    if let Ok(raw) = std::env::var(ENV_KEY) {
        if let Some(key) = decode_key(&raw) {
            return Ok(key);
        }
        return Err(SandboxError::policy(format!(
            "{ENV_KEY} is set but is not a 32-byte key. It should be 64 hex characters, or base64 for \
             32 bytes."
        )));
    }

    Err(SandboxError::policy(format!(
        "no encryption key is available. Deepsand keeps secrets encrypted at rest, so it needs a key: \
         normally it stores one in your operating system's keystore, which this session could not \
         reach. Set {ENV_KEY} to a 64-character hex value to use secrets without a keystore. This is a \
         degraded mode: the key then sits wherever that variable does, with the same protection as the \
         encrypted file."
    )))
}

fn encode(key: &[u8; KEY_BYTES]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_key(raw: &str) -> Option<[u8; KEY_BYTES]> {
    let raw = raw.trim();
    // Hex first: it is what we write, and unambiguous.
    if raw.len() == KEY_BYTES * 2 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut key = [0u8; KEY_BYTES];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16).ok()?;
        }
        return Some(key);
    }
    // Then base64, because a key pasted from a secrets manager usually is.
    let decoded = base64::engine::general_purpose::STANDARD.decode(raw).ok()?;
    if decoded.len() == KEY_BYTES {
        let mut key = [0u8; KEY_BYTES];
        key.copy_from_slice(&decoded);
        return Some(key);
    }
    None
}

/// A short, stable digest for naming a keystore entry after a data directory.
fn short_hash(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key that does not touch the real keystore or the environment.
    fn test_secrets(dir: &Path) -> Secrets {
        let mut key = [0u8; KEY_BYTES];
        getrandom::getrandom(&mut key).unwrap();
        Secrets {
            path: dir.join("projects").join("p1").join(FILE),
            cipher: new_cipher(key).unwrap(),
        }
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("deepsand-secrets-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /* --- names ------------------------------------------------------------ */

    #[test]
    fn ordinary_names_are_accepted_and_trimmed() {
        assert_eq!(validate_name("  STRIPE_KEY ").unwrap(), "STRIPE_KEY");
        assert_eq!(validate_name("_private").unwrap(), "_private");
        assert_eq!(validate_name("A1").unwrap(), "A1");
    }

    #[test]
    fn a_name_that_is_not_an_environment_variable_is_refused() {
        for bad in ["1KEY", "MY-KEY", "MY KEY", "MY.KEY", "", "   "] {
            assert!(validate_name(bad).is_err(), "{bad} should be refused");
        }
    }

    /// A secret must not be able to change how the sandbox itself works.
    #[test]
    fn a_reserved_name_is_refused() {
        for bad in ["PATH", "path", "HOME", "LD_PRELOAD", "DEEPSAND_UID", "deepsand_x"] {
            let err = validate_name(bad).expect_err(bad);
            assert!(err.to_string().contains("reserved"), "{bad}: {err}");
        }
    }

    /* --- round trip ------------------------------------------------------- */

    #[test]
    fn secrets_round_trip() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        secrets.set("STRIPE_KEY", "sk_live_example").unwrap();
        secrets.set("DATABASE_URL", "postgres://user:pw@host/db").unwrap();

        assert_eq!(secrets.names().unwrap(), ["DATABASE_URL", "STRIPE_KEY"]);
        let all = secrets.all().unwrap();
        assert_eq!(all["STRIPE_KEY"], "sk_live_example");
    }

    #[test]
    fn an_empty_store_is_not_an_error() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        assert!(secrets.all().unwrap().is_empty());
        assert!(secrets.names().unwrap().is_empty());
    }

    #[test]
    fn setting_the_same_name_twice_replaces_it() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        secrets.set("KEY", "first").unwrap();
        secrets.set("KEY", "second").unwrap();
        assert_eq!(secrets.all().unwrap()["KEY"], "second");
        assert_eq!(secrets.names().unwrap().len(), 1);
    }

    #[test]
    fn removing_a_secret_works_and_removing_a_missing_one_is_harmless() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        secrets.set("KEY", "value").unwrap();
        secrets.remove("KEY").unwrap();
        assert!(secrets.all().unwrap().is_empty());
        secrets.remove("NEVER_EXISTED").unwrap();
    }

    #[test]
    fn an_empty_value_is_refused() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        assert!(secrets.set("KEY", "").is_err());
    }

    /* --- encryption ------------------------------------------------------- */

    /// The whole point: the file on disk must not contain the value.
    #[test]
    fn the_value_is_not_readable_in_the_file() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        secrets.set("STRIPE_KEY", "sk_live_supersecret").unwrap();
        let raw = std::fs::read_to_string(&secrets.path).unwrap();
        assert!(!raw.contains("sk_live_supersecret"), "the value is in the clear");
        assert!(!raw.contains("STRIPE_KEY"), "even the name is in the clear");
    }

    #[test]
    fn the_same_map_encrypts_differently_each_time() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        secrets.set("KEY", "value").unwrap();
        let first = std::fs::read_to_string(&secrets.path).unwrap();
        secrets.set("KEY", "value").unwrap();
        let second = std::fs::read_to_string(&secrets.path).unwrap();
        assert_ne!(first, second, "a fresh nonce must be used for every save");
    }

    #[test]
    fn a_tampered_file_is_detected_rather_than_read() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        secrets.set("KEY", "value").unwrap();

        // Flip a byte of the ciphertext.
        let raw = std::fs::read_to_string(&secrets.path).unwrap();
        let mut envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let data = envelope["data"].as_str().unwrap().to_string();
        let mut bytes = base64::engine::general_purpose::STANDARD.decode(&data).unwrap();
        bytes[0] ^= 0x01;
        envelope["data"] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&bytes));
        std::fs::write(&secrets.path, envelope.to_string()).unwrap();

        assert!(secrets.all().is_err(), "authentication must reject a modified file");
    }

    #[test]
    fn a_file_encrypted_with_another_key_cannot_be_read() {
        let dir = temp_dir();
        let first = test_secrets(&dir);
        first.set("KEY", "value").unwrap();
        let second = test_secrets(&dir);
        assert!(second.all().is_err(), "a different key must not decrypt it");
    }

    #[test]
    fn a_damaged_file_is_reported_not_ignored() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        std::fs::create_dir_all(secrets.path.parent().unwrap()).unwrap();
        std::fs::write(&secrets.path, "{ not json").unwrap();
        assert!(secrets.all().is_err());
    }

    /* --- the environment file --------------------------------------------- */

    #[test]
    fn the_env_file_holds_the_values_and_is_removed_when_empty() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        let env_dir = dir.join("config");
        std::fs::create_dir_all(&env_dir).unwrap();

        assert!(secrets.write_env_file(&env_dir).unwrap().is_none());
        secrets.set("STRIPE_KEY", "sk_live_x").unwrap();
        let path = secrets.write_env_file(&env_dir).unwrap().expect("a file once secrets exist");
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body, "STRIPE_KEY=sk_live_x\n");

        secrets.remove("STRIPE_KEY").unwrap();
        assert!(secrets.write_env_file(&env_dir).unwrap().is_none());
        assert!(!path.exists(), "a stale environment file must not be left behind");
    }

    /* --- redaction --------------------------------------------------------- */

    #[test]
    fn a_stored_value_is_redacted_from_text() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        secrets.set("STRIPE_KEY", "sk_live_supersecret").unwrap();
        let line = "curl -H 'Authorization: Bearer sk_live_supersecret' https://api.example";
        let redacted = secrets.redact(line);
        assert!(!redacted.contains("sk_live_supersecret"), "{redacted}");
        assert!(redacted.contains("[redacted]"), "{redacted}");
    }

    #[test]
    fn redaction_leaves_ordinary_text_alone() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        secrets.set("KEY", "sk_live_supersecret").unwrap();
        let line = "npm install react";
        assert_eq!(secrets.redact(line), line);
    }

    /// A short value would redact half the output, so it is not redacted at all.
    #[test]
    fn a_very_short_value_is_not_redacted() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        secrets.set("SHORT", "abc").unwrap();
        assert_eq!(secrets.redact("abcdef"), "abcdef");
        assert!(secrets.values().is_empty());
    }

    /// If one secret contains another, the longer must be replaced first or the
    /// shorter one's replacement would leave the rest of the longer value visible.
    #[test]
    fn the_longest_value_is_redacted_first() {
        let dir = temp_dir();
        let secrets = test_secrets(&dir);
        secrets.set("LONG", "abcdefghij").unwrap();
        secrets.set("SHORT", "abcdef").unwrap();
        let redacted = secrets.redact("token=abcdefghij");
        assert!(!redacted.contains("ghij"), "{redacted}");
    }
}
