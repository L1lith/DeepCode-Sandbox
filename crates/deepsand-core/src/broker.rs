//! The permission broker.
//!
//! The sandbox talks to Deepsand through two directories:
//!
//! ```text
//!   host: <data>/projects/<id>/ipc/requests   ->  container: /deepsand/ipc/requests    (rw)
//!   host: <data>/projects/<id>/ipc/responses  ->  container: /deepsand/ipc/responses   (ro)
//! ```
//!
//! The container can write requests and read answers. It cannot write answers,
//! because that directory is mounted read-only — which is the entire security
//! model of the permission system, in one mount flag.
//!
//! Everything arriving on the request side is treated as hostile input: it is
//! produced by a process inside the sandbox. Requests are therefore validated
//! hard (name shape, size, identifier agreement, payload sanity) and are never
//! treated as authorisation for anything. They only describe what the operator
//! is about to be asked.

use crate::error::{Result, SandboxError};
use crate::model::*;
use std::path::{Path, PathBuf};

/// Generous for a request, tiny for an attacker trying to fill the host disk.
pub const MAX_REQUEST_BYTES: u64 = 64 * 1024;
/// Distinct outstanding requests before the broker stops surfacing new ones.
pub const MAX_PENDING_REQUESTS: usize = 25;
/// Longest identifier we will accept in a file name.
pub const MAX_REQUEST_ID_LEN: usize = 80;

#[derive(Debug, Clone)]
pub struct BrokerDirs {
    pub requests: PathBuf,
    pub responses: PathBuf,
    pub state: PathBuf,
}

#[derive(Debug)]
pub struct Broker {
    dirs: BrokerDirs,
}

/// A request that failed validation, kept so the UI can explain what happened.
#[derive(Debug, Clone)]
pub struct RejectedRequest {
    pub file: String,
    pub reason: String,
}

impl Broker {
    pub fn new(data_dir: &Path, project_id: &str) -> Self {
        let base = data_dir.join("projects").join(project_id);
        Self {
            dirs: BrokerDirs {
                requests: base.join("ipc").join("requests"),
                responses: base.join("ipc").join("responses"),
                state: base.join("state"),
            },
        }
    }

    pub fn from_dirs(dirs: BrokerDirs) -> Self {
        Self { dirs }
    }

    pub fn dirs(&self) -> &BrokerDirs {
        &self.dirs
    }

    pub fn ensure(&self) -> Result<()> {
        for dir in [&self.dirs.requests, &self.dirs.responses, &self.dirs.state] {
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    /// Ids of requests currently sitting in the spool.
    pub fn open_request_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .scan()
            .into_iter()
            .map(|request| request.id)
            .collect();
        ids.sort();
        ids
    }

    /// Read and validate everything in the request spool.
    pub fn scan(&self) -> Vec<PermissionRequest> {
        self.scan_detailed().0
    }

    /// Like [`Self::scan`], but also reports the files that were thrown away.
    pub fn scan_detailed(&self) -> (Vec<PermissionRequest>, Vec<RejectedRequest>) {
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();

        let entries = match std::fs::read_dir(&self.dirs.requests) {
            Ok(entries) => entries,
            Err(_) => return (accepted, rejected),
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !is_request_file(&name) {
                // `.part` temporaries and anything else are not ours.
                continue;
            }
            match self.read_request(&entry.path(), &name) {
                Ok(request) => accepted.push(request),
                Err(reason) => rejected.push(RejectedRequest { file: name, reason: reason.to_string() }),
            }
        }

        accepted.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        // Surface the oldest MAX_PENDING and report the rest as rejected so a
        // flood never buries the operator under dialogs.
        if accepted.len() > MAX_PENDING_REQUESTS {
            let overflow = accepted.split_off(MAX_PENDING_REQUESTS);
            for request in overflow {
                rejected.push(RejectedRequest {
                    file: request_file_name(&request.id),
                    reason: format!(
                        "more than {MAX_PENDING_REQUESTS} requests are already waiting for a decision"
                    ),
                });
            }
        }
        (accepted, rejected)
    }

    fn read_request(&self, path: &Path, name: &str) -> Result<PermissionRequest> {
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > MAX_REQUEST_BYTES {
            return Err(SandboxError::Broker(format!(
                "request is {} bytes, which is larger than the {MAX_REQUEST_BYTES} byte limit",
                metadata.len()
            )));
        }
        if !metadata.is_file() {
            return Err(SandboxError::Broker("not a regular file".to_string()));
        }

        let raw = std::fs::read_to_string(path)?;
        let mut parsed: PermissionRequest = serde_json::from_str(&raw)
            .map_err(|err| SandboxError::Broker(format!("payload is not a valid request: {err}")))?;

        let stem = name.trim_end_matches(".json");
        if parsed.id != stem {
            return Err(SandboxError::Broker(format!(
                "the file is named '{stem}' but declares id '{}'; refusing a request whose identity disagrees with its name",
                parsed.id
            )));
        }
        if !is_safe_request_id(&parsed.id) {
            return Err(SandboxError::Broker(format!("unsafe request id '{}'", parsed.id)));
        }

        // The claimed path is only ever used to prefill a dialog, but a bogus
        // one would make the operator approve the wrong thing, so it is dropped
        // rather than shown when it is obviously not a host path.
        parsed.args = sanitize_args(parsed.args);

        Ok(parsed)
    }

    /// Write the operator's decision. This is the *only* thing the sandbox is
    /// allowed to read from Deepsand, and it is always written here, on the
    /// host, after a human decision.
    pub fn answer(&self, response: &PermissionResponse) -> Result<()> {
        if !is_safe_request_id(&response.id) {
            return Err(SandboxError::Broker(format!(
                "refusing to answer a request with unsafe id '{}'",
                response.id
            )));
        }
        std::fs::create_dir_all(&self.dirs.responses)?;
        let target = self.dirs.responses.join(response_file_name(&response.id));
        let tmp = self
            .dirs
            .responses
            .join(format!(".{}.part", response.id.trim_start_matches("req_")));
        std::fs::write(&tmp, serde_json::to_string_pretty(response)?)?;
        std::fs::rename(&tmp, &target)?;
        Ok(())
    }

    /// Remove a request file once it has been answered, so the spool reflects
    /// reality and the sandbox's own `deepsand_check_request` polls correctly.
    pub fn clear_request(&self, id: &str) {
        if !is_safe_request_id(id) {
            return;
        }
        let _ = std::fs::remove_file(self.dirs.requests.join(request_file_name(id)));
    }

    pub fn clear_all_requests(&self) {
        if let Ok(entries) = std::fs::read_dir(&self.dirs.requests) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if is_request_file(&name) || name.ends_with(".part") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    /// Delete answer files older than the newest `keep`, so the reply channel
    /// does not grow without bound across a long session.
    pub fn prune_responses(&self, keep: usize) {
        let Ok(entries) = std::fs::read_dir(&self.dirs.responses) else {
            return;
        };
        let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.ends_with(".json") {
                    return None;
                }
                let modified = entry.metadata().ok()?.modified().ok()?;
                Some((modified, entry.path()))
            })
            .collect();
        if files.len() <= keep {
            return;
        }
        files.sort_by_key(|(modified, _)| *modified);
        let excess = files.len() - keep;
        for (_, path) in files.into_iter().take(excess) {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Write what the sandbox is allowed to know about itself.
    pub fn write_snapshots(&self, sandbox: &SandboxSnapshot, grants: &GrantsSnapshot) -> Result<()> {
        std::fs::create_dir_all(&self.dirs.state)?;
        write_json(&self.dirs.state.join("sandbox.json"), sandbox)?;
        write_json(&self.dirs.state.join("grants.json"), grants)?;
        Ok(())
    }

    /// Last `keep` audit lines for the diagnostics panel.
    pub fn tail_responses(&self, keep: usize) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.dirs.responses) else {
            return Vec::new();
        };
        let mut lines: Vec<String> = entries
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .collect();
        if lines.len() > keep {
            lines = lines.split_off(lines.len() - keep);
        }
        lines
    }
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(value)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Prefixes that exist only *inside* the sandbox. A request naming one of these
/// as a host path is either confused or trying to prefill the dialog with
/// something the operator would misread.
const CONTAINER_PATH_PREFIXES: &[&str] = &[
    "/workspace",
    "/grants",
    "/deepsand",
    "/etc/deepsand",
    "/home/deepcode",
    "/usr/local/lib/deepsand",
];

/// True when a claimed path is one of the sandbox's own paths rather than a
/// path on the operator's machine.
pub fn is_container_path(path: &str) -> bool {
    let normalised = path.trim().replace('\\', "/");
    let normalised = normalised.trim_end_matches('/');
    CONTAINER_PATH_PREFIXES
        .iter()
        .any(|prefix| normalised == *prefix || normalised.starts_with(&format!("{prefix}/")))
}

/// Strip anything from a request payload that could mislead the operator.
fn sanitize_args(args: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::Object(mut map) = args else {
        return serde_json::Value::Object(serde_json::Map::new());
    };

    let truncate = |value: &mut serde_json::Value, limit: usize| {
        if let serde_json::Value::String(text) = value {
            if text.contains('\u{0}') {
                *text = text.replace('\u{0}', "");
            }
            // Count characters, not bytes: a multi-byte path could otherwise
            // blow past the limit, and slicing by byte index could split a
            // character and panic.
            let length = text.chars().count();
            if length > limit {
                // Keep the tail - the interesting part of a path is at the end.
                let keep = limit.saturating_sub(1);
                let tail: String = text
                    .chars()
                    .rev()
                    .take(keep)
                    .collect::<Vec<char>>()
                    .into_iter()
                    .rev()
                    .collect();
                *text = format!("…{tail}");
            }
            *text = text.trim().to_string();
        }
    };

    for (key, limit) in [
        ("host_path", 1024usize),
        ("description", 512),
        ("purpose", 1024),
        ("kind", 16),
        ("access", 8),
    ] {
        if let Some(value) = map.get_mut(key) {
            truncate(value, limit);
        }
    }

    // A sandbox that writes "/workspace" or "/grants/x" into `host_path` is
    // either confused or trying to make the dialog prefill a container path.
    // Drop it so the operator sees an empty field and has to choose.
    //
    // Note this matches the *known container prefixes* rather than "any
    // absolute path": on Linux and macOS every legitimate host path is
    // absolute, so a blanket test would break the whole flow there.
    let drop_container_path = map
        .get("host_path")
        .and_then(|v| v.as_str())
        .is_some_and(is_container_path);
    if drop_container_path {
        map.remove("host_path");
    }

    for key in ["access", "kind"] {
        if let Some(value) = map.get(key).and_then(|v| v.as_str()) {
            let ok = match key {
                "access" => matches!(value, "read" | "write"),
                _ => matches!(value, "file" | "directory"),
            };
            if !ok {
                map.remove(key);
            }
        }
    }

    serde_json::Value::Object(map)
}

/// Request identifiers are generated by the bridge, but the file could have
/// been written by anything inside the sandbox, so the shape is enforced.
pub fn is_safe_request_id(id: &str) -> bool {
    let body = match id.strip_prefix("req_") {
        Some(body) => body,
        None => return false,
    };
    !body.is_empty()
        && id.len() <= MAX_REQUEST_ID_LEN
        && body.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

pub fn is_request_file(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".json") else {
        return false;
    };
    if name.starts_with('.') {
        return false;
    }
    is_safe_request_id(stem)
}

pub fn request_file_name(id: &str) -> String {
    format!("{id}.json")
}

pub fn response_file_name(id: &str) -> String {
    format!("{id}.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Access, PermissionResponse, RequestKind};

    struct Fixture {
        dir: PathBuf,
        broker: Broker,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir()
                .join(format!("deepsand-broker-{}", uuid::Uuid::new_v4()));
            let broker = Broker::new(&dir, "p1");
            broker.ensure().unwrap();
            Self { dir, broker }
        }

        fn write_request(&self, id: &str, kind: &str, host_path: Option<&str>) -> PathBuf {
            let mut args = serde_json::json!({
                "purpose": "to finish the task",
            });
            if let Some(path) = host_path {
                args["host_path"] = serde_json::Value::String(path.into());
            }
            // No `token`: the protocol does not carry one any more, because nothing ever
            // checked it and a credential-shaped field implies a control that is not there.
            let payload = serde_json::json!({
                "v": 1,
                "id": id,
                "kind": kind,
                "project": "p1",
                "workspace": "/workspace",
                "args": args,
                "created_at": crate::iso_from_ms(crate::now_ms()),
            });
            let path = self.broker.dirs().requests.join(format!("{id}.json"));
            std::fs::write(&path, serde_json::to_string(&payload).unwrap()).unwrap();
            path
        }

        fn write_raw(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.broker.dirs().requests.join(name);
            std::fs::write(&path, contents).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn request_ids_must_be_well_formed() {
        assert!(is_safe_request_id("req_mv42fxlf_8f4ca4d6ca7e"));
        assert!(!is_safe_request_id("req_"));
        assert!(!is_safe_request_id("mv42fxlf"));
        assert!(!is_safe_request_id("req_../../etc/passwd"));
        assert!(!is_safe_request_id("req_../evil"));
        assert!(!is_safe_request_id("req_UPPER"));
        assert!(!is_safe_request_id("req_a/b"));
        assert!(!is_safe_request_id("req_a\\b"));
        assert!(!is_safe_request_id(&format!("req_{}", "a".repeat(200))));
    }

    #[test]
    fn request_files_are_recognised_by_name_only() {
        assert!(is_request_file("req_abc_123.json"));
        assert!(!is_request_file("req_abc_123.json.part"));
        assert!(!is_request_file(".req_abc.part"));
        assert!(!is_request_file("sandbox.json"));
        assert!(!is_request_file("req_bad!.json"));
        assert!(!is_request_file("../../../etc/passwd"));
        assert!(!is_request_file("req_ok.txt"));
    }

    #[test]
    fn a_well_formed_request_is_accepted() {
        let fixture = Fixture::new();
        fixture.write_request("req_aaa_1111", "directory_access", Some("/home/me/notes"));

        let requests = fixture.broker.scan();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.kind, RequestKind::DirectoryAccess);
        assert_eq!(request.claimed_host_path(), Some("/home/me/notes"));
        assert_eq!(request.requested_access(), Access::ReadOnly, "read is the safe default");
        assert_eq!(request.purpose().as_deref(), Some("to finish the task"));
    }

    #[test]
    fn an_id_that_disagrees_with_the_file_name_is_rejected() {
        let fixture = Fixture::new();
        fixture.write_raw(
            "req_bbb_2222.json",
            &serde_json::json!({
                "id": "req_someone_else",
                "kind": "directory_access",
                "args": {}
            })
            .to_string(),
        );
        let (accepted, rejected) = fixture.broker.scan_detailed();
        assert!(accepted.is_empty());
        assert_eq!(rejected.len(), 1);
        assert!(rejected[0].reason.contains("disagrees with its name"), "{}", rejected[0].reason);
    }

    #[test]
    fn hostile_file_names_never_reach_the_filesystem() {
        let fixture = Fixture::new();
        // A file literally named with traversal characters cannot be created on
        // a sane filesystem, so the interesting case is the *id* inside a
        // legitimately named file.
        fixture.write_raw(
            "req_ccc_3333.json",
            &serde_json::json!({
                "id": "req_ccc_3333",
                "kind": "directory_access",
                "args": { "host_path": "../../../../etc/shadow" }
            })
            .to_string(),
        );
        // That parses (the traversal is data, not a path operation) but the
        // broker never uses it as a path: it is only ever shown to a human.
        let requests = fixture.broker.scan();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].claimed_host_path(), Some("../../../../etc/shadow"));

        // Answering must still resolve to a file inside the responses dir.
        fixture.broker.answer(&PermissionResponse::deny("req_ccc_3333", "no")).unwrap();
        let written = fixture.broker.dirs().responses.join("req_ccc_3333.json");
        assert!(written.exists());
        let canonical = std::fs::canonicalize(&written).unwrap();
        let responses_root = std::fs::canonicalize(fixture.broker.dirs().responses.clone()).unwrap();
        assert!(canonical.starts_with(&responses_root));
    }

    #[test]
    fn an_unsafe_id_cannot_be_answered() {
        let fixture = Fixture::new();
        let err = fixture
            .broker
            .answer(&PermissionResponse::deny("req_../escape", "no"))
            .unwrap_err();
        assert!(err.to_string().contains("unsafe id"), "{err}");
        assert!(!fixture.broker.dirs().responses.join("..").join("escape.json").exists());
    }

    #[test]
    fn an_oversized_request_is_rejected() {
        let fixture = Fixture::new();
        let huge = "x".repeat((MAX_REQUEST_BYTES as usize) + 16);
        fixture.write_raw(
            "req_big_1.json",
            &serde_json::json!({ "id": "req_big_1", "kind": "directory_access", "args": { "purpose": huge } })
                .to_string(),
        );
        let (accepted, rejected) = fixture.broker.scan_detailed();
        assert!(accepted.is_empty());
        assert!(rejected[0].reason.contains("larger than"), "{}", rejected[0].reason);
    }

    #[test]
    fn unparseable_and_unknown_kinds_are_rejected_without_crashing() {
        let fixture = Fixture::new();
        fixture.write_raw("req_bad_1.json", "{ not json");
        fixture.write_raw(
            "req_bad_2.json",
            &serde_json::json!({ "id": "req_bad_2", "kind": "give_me_root", "args": {} }).to_string(),
        );
        let (accepted, rejected) = fixture.broker.scan_detailed();
        assert!(accepted.is_empty());
        assert_eq!(rejected.len(), 2);
    }

    #[test]
    fn a_claimed_container_path_is_dropped_so_it_cannot_prefill_the_dialog() {
        let fixture = Fixture::new();
        for evil in ["/workspace/../etc", "/grants/other", "/deepsand/state"] {
            let id = format!("req_p_{}", evil.replace(['/', '.'], ""));
            fixture.write_request(&id, "directory_access", Some(evil));
            let requests = fixture.broker.scan();
            let request = requests.iter().find(|r| r.id == id).unwrap();
            assert_eq!(request.claimed_host_path(), None, "{evil} should have been dropped");
        }
    }

    #[test]
    fn a_claimed_host_path_keeps_its_tail_when_absurdly_long() {
        let fixture = Fixture::new();
        let long = format!("C:\\{}", "a".repeat(5000));
        fixture.write_request("req_long_1", "directory_access", Some(&long));
        let request = fixture.broker.scan().into_iter().next().unwrap();
        let claimed = request.claimed_host_path().unwrap();
        assert!(claimed.chars().count() <= 1024, "length was {}", claimed.chars().count());
        assert!(claimed.starts_with('…'));
    }

    #[test]
    fn a_path_that_only_looks_like_a_container_path_is_kept() {
        // Regression guard: on Linux and macOS every legitimate host path is
        // absolute, so a naive "starts with /" rule would discard all of them.
        for fine in [
            "/srv/data/brand",
            "/home/me/notes",
            "/workspace-notes",
            "/deepsandy",
            "C:\\Users\\me\\Documents\\brand",
            "D:/work/brand",
        ] {
            let fixture = Fixture::new();
            fixture.write_request("req_ok_1", "directory_access", Some(fine));
            let request = fixture.broker.scan().into_iter().next().unwrap();
            assert_eq!(request.claimed_host_path(), Some(fine), "{fine} should have been kept");
        }
    }

    #[test]
    fn a_phone_book_of_requests_cannot_bury_the_operator() {
        let fixture = Fixture::new();
        for index in 0..(MAX_PENDING_REQUESTS + 10) {
            fixture.write_request(
                &format!("req_flood_{index:03}"),
                "directory_access",
                Some("/home/me/x"),
            );
        }
        let (accepted, rejected) = fixture.broker.scan_detailed();
        assert_eq!(accepted.len(), MAX_PENDING_REQUESTS);
        assert_eq!(rejected.len(), 10);
        assert!(rejected[0].reason.contains("already waiting"), "{}", rejected[0].reason);
    }

    #[test]
    fn answering_writes_a_response_the_sandbox_can_read() {
        let fixture = Fixture::new();
        fixture.write_request("req_ddd_4444", "directory_access", Some("/home/me/brand"));

        fixture
            .broker
            .answer(&PermissionResponse::allow(
                "req_ddd_4444",
                "granted, be careful",
                Some(GrantSpec {
                    host_path: "/home/me/brand".into(),
                    container_path: "/grants/brand".into(),
                    access: Access::ReadWrite,
                }),
                true,
            ))
            .unwrap();

        let text = std::fs::read_to_string(fixture.broker.dirs().responses.join("req_ddd_4444.json")).unwrap();
        let parsed: PermissionResponse = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.decision, "allow");
        assert!(parsed.restart_required);
        assert_eq!(parsed.grant.as_ref().unwrap().container_path, "/grants/brand");

        // A partial write must never be observable.
        assert!(!fixture.broker.dirs().responses.join(".ddd_4444.part").exists());
    }

    /// The spool cannot tell a request the bridge wrote from one the agent wrote, so the
    /// operator's decision is the whole control. That makes "a decision is required" an
    /// invariant rather than a UI detail: surfacing a request must never answer it, or a
    /// forged request becomes a silent grant.
    #[test]
    fn a_request_is_never_answered_without_an_explicit_decision() {
        let fixture = Fixture::new();
        fixture.write_request("req_fff_6666", "directory_access", Some("/home/me/secrets"));
        let response = fixture.broker.dirs().responses.join("req_fff_6666.json");

        // Reading the queue is what the dialog does. It is not a decision.
        let pending = fixture.broker.scan();
        assert_eq!(pending.len(), 1);
        assert!(
            !response.exists(),
            "showing a request to the operator must not answer it"
        );

        // Writing snapshots, clearing and answering other ids are also not decisions.
        fixture.broker.clear_request("req_nothing_0000");
        fixture.broker.prune_responses(1);
        assert!(!response.exists(), "nothing short of an answer may grant anything");

        // Only an explicit answer produces a response the sandbox can read.
        fixture
            .broker
            .answer(&PermissionResponse::deny("req_fff_6666", "not this one"))
            .unwrap();
        let parsed: PermissionResponse =
            serde_json::from_str(&std::fs::read_to_string(&response).unwrap()).unwrap();
        assert_eq!(parsed.decision, "deny");
        assert!(parsed.grant.is_none());
    }

    #[test]
    fn clearing_a_request_makes_the_sandbox_see_it_as_answered() {
        let fixture = Fixture::new();
        fixture.write_request("req_eee_5555", "locate_resource", None);
        assert_eq!(fixture.broker.open_request_ids(), vec!["req_eee_5555".to_string()]);

        fixture.broker.answer(&PermissionResponse::deny("req_eee_5555", "no")).unwrap();
        fixture.broker.clear_request("req_eee_5555");

        assert!(fixture.broker.open_request_ids().is_empty());
        assert!(!fixture.broker.dirs().requests.join("req_eee_5555.json").exists());
        assert!(fixture.broker.dirs().responses.join("req_eee_5555.json").exists());
    }

    #[test]
    fn clearing_is_safe_for_ids_that_could_escape_the_spool() {
        let fixture = Fixture::new();
        let outside = fixture.dir.join("outside.json");
        std::fs::write(&outside, "keep me").unwrap();
        fixture.broker.clear_request("req_../../outside");
        assert!(outside.exists(), "a traversal id must not delete anything");
    }

    #[test]
    fn responses_are_pruned_to_a_bounded_number() {
        let fixture = Fixture::new();
        for index in 0..12 {
            let id = format!("req_prune_{index:03}");
            fixture.broker.answer(&PermissionResponse::deny(&id, "no")).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        fixture.broker.prune_responses(5);
        let remaining: Vec<String> = std::fs::read_dir(&fixture.broker.dirs().responses)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(remaining.len(), 5, "{remaining:?}");
        // The newest survive.
        assert!(remaining.contains(&"req_prune_011.json".to_string()));
    }

    #[test]
    fn snapshots_describe_the_sandbox_to_itself() {
        let fixture = Fixture::new();
        let project = Project {
            id: "p1".into(),
            name: "my-website".into(),
            slug: "my-website".into(),
            root_dir: "/tmp/ws".into(),
            created_at_ms: 0,
            network: NetworkPolicy::Internet,
            limits: Default::default(),
            credentials: Default::default(),
            deepcode_mode: Default::default(),
            allowed_roots: vec![],
            notes: String::new(),
            reasoning_effort: Default::default(),
            tools: None,
        };
        let sandbox = crate::settings::build_sandbox_snapshot(
            &project,
            &[],
            &project.network,
            vec!["req_open_1".into()],
            vec!["note".into()],
        );
        let grants = crate::settings::build_grants_snapshot(&project, &[]);
        fixture.broker.write_snapshots(&sandbox, &grants).unwrap();

        let text = std::fs::read_to_string(fixture.broker.dirs().state.join("sandbox.json")).unwrap();
        let parsed: SandboxSnapshot = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.network_mode, "internet");
        assert_eq!(parsed.workspace_mount, "/workspace");
        assert_eq!(parsed.open_requests, vec!["req_open_1".to_string()]);
        assert!(fixture.broker.dirs().state.join("grants.json").exists());
    }

    #[test]
    fn a_spool_that_does_not_exist_scans_as_empty_rather_than_failing() {
        let dir = std::env::temp_dir()
            .join(format!("deepsand-broker-missing-{}", uuid::Uuid::new_v4()));
        let broker = Broker::new(&dir, "ghost");
        assert!(broker.scan().is_empty());
        assert!(broker.open_request_ids().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_passes_through_valid_choices() {
        let args = serde_json::json!({
            "host_path": "C:\\Users\\me\\brand",
            "purpose": "palette",
            "access": "write",
            "kind": "file",
        });
        let clean = sanitize_args(args);
        assert_eq!(clean["access"], "write");
        assert_eq!(clean["kind"], "file");
        assert_eq!(clean["host_path"], "C:\\Users\\me\\brand");

        // Invalid enumerations are removed rather than coerced.
        let dirty = sanitize_args(serde_json::json!({
            "access": "root",
            "kind": "everything",
        }));
        assert!(dirty.get("access").is_none());
        assert!(dirty.get("kind").is_none());
    }
}
