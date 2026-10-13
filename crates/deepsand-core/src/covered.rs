//! Requests the sandbox never needed to make, because it already has the thing.
//!
//! Asking for a directory that is inside `/workspace` already, or for a host that is
//! already on the allowlist, is the most common way the contained model wastes the
//! operator's attention — and every one of those prompts trains the operator to
//! approve without reading, which is the opposite of what the dialog is for. The
//! MCP bridge's own instructions tell the model to check `deepsand_sandbox_info`
//! first; this is the host-side backstop for when it does not.
//!
//! # The bar is "certain", not "probably"
//!
//! Automatically refusing a request is a decision made *for* the operator, so it may
//! only happen when there is nothing left to decide. Three rules follow from that:
//!
//! * Coverage is judged against the sandbox's own snapshot — the same
//!   [`SandboxSnapshot`] the bridge reads — so the answer is "what the sandbox can
//!   already see", not "what the host believes it built".
//! * A write request is not covered by a read-only grant. The agent would still be
//!   blocked, so a refusal saying "you already have this" would be false.
//! * Anything that cannot be decided exactly is left alone. A wildcard pattern, a
//!   `locate_resource` request, or a path that is inside nothing, all go to the
//!   operator: this module exists to remove noise, never to guess.
//!
//! The refusal is a `deny` rather than an `allow` on purpose. An automatic `allow`
//! would be a grant the operator never made, and the sandbox's whole permission model
//! is that a human decides; telling the model where the thing already is achieves the
//! same unblocking without inventing consent.

use crate::allowlist::{Allowlist, HostMatcher, Rule, RuleKind};
use crate::model::{Access, PermissionRequest, RequestKind, SandboxSnapshot};
use crate::paths;
use std::path::Path;

/// A request that can be refused without the operator, and what to tell them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlreadyCovered {
    /// Shown to the model. Names where it already has the thing, so it can continue
    /// rather than retry or give up.
    pub message: String,
}

impl AlreadyCovered {
    fn new(message: String) -> Self {
        Self { message }
    }
}

/// Is this request certainly satisfied by what the sandbox already has?
///
/// `workspace_root` is the project directory on the host, which the snapshot records
/// only as its in-container mount point.
pub fn already_covered(
    request: &PermissionRequest,
    workspace_root: &Path,
    snapshot: &SandboxSnapshot,
) -> Option<AlreadyCovered> {
    match request.kind {
        RequestKind::DirectoryAccess => covered_directory(request, workspace_root, snapshot),
        RequestKind::NetworkAccess => covered_network(request, snapshot),
        RequestKind::ToolInstall => covered_tools(request, snapshot),
        // "I need something but do not know where it is" has no target to compare, so
        // there is nothing here that can be certain.
        RequestKind::LocateResource => None,
    }
}

fn covered_directory(
    request: &PermissionRequest,
    workspace_root: &Path,
    snapshot: &SandboxSnapshot,
) -> Option<AlreadyCovered> {
    let claimed = request.claimed_host_path()?;
    let resolved = paths::canonicalize_lenient(Path::new(claimed));
    // The workspace first: it is mounted read-write and ignores the grants entirely.
    let workspace_root = paths::canonicalize_lenient(workspace_root);

    let already = |container_root: &str, host_root: &Path, access: Access| -> Option<String> {
        if !paths::is_within(host_root, &resolved) && resolved != host_root {
            return None;
        }
        // A write request needs somewhere it can actually write.
        if request.requested_access() == Access::ReadWrite && access == Access::ReadOnly {
            return None;
        }
        let mount = container_root.trim_end_matches('/');
        let tail = resolved
            .strip_prefix(host_root)
            .ok()
            .map(|rest| rest.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        let tail = tail.trim_start_matches('/');
        let path = if tail.is_empty() {
            mount.to_string()
        } else {
            format!("{mount}/{tail}")
        };
        Some(path)
    };

    if let Some(path) = already(&snapshot.workspace_mount, &workspace_root, Access::ReadWrite) {
        return Some(AlreadyCovered::new(format!(
            "You already have this: '{claimed}' is inside this sandbox's working directory, which is \
             mounted read-write at '{path}'. Use that path directly and do not ask again."
        )));
    }

    for grant in &snapshot.grants {
        let host_root = paths::canonicalize_lenient(Path::new(&grant.host_path));
        if let Some(path) = already(&grant.container_path, &host_root, grant.access) {
            let access = if grant.access == Access::ReadWrite { "read-write" } else { "read-only" };
            return Some(AlreadyCovered::new(format!(
                "You already have this: '{claimed}' is inside a directory that is already shared with \
                 this sandbox ({access}) at '{path}'. Use that path directly and do not ask again."
            )));
        }
    }

    None
}

fn covered_network(
    request: &PermissionRequest,
    snapshot: &SandboxSnapshot,
) -> Option<AlreadyCovered> {
    let patterns = request.requested_patterns();
    if patterns.is_empty() {
        return None;
    }
    let list = Allowlist::parse_lenient(&snapshot.egress_allowlist).0;

    let mut already_on_the_list: Vec<String> = Vec::new();
    for pattern in &patterns {
        // A pattern that will not parse, a deny rule, a path prefix, a wildcard or a
        // regexe all mean the question is not the simple one this function can answer.
        let rule = Rule::parse(pattern).ok()?;
        if rule.kind != RuleKind::Allow || rule.path_prefix.is_some() {
            return None;
        }
        let covered = match &rule.matcher {
            HostMatcher::Exact(host) => list.decide(host, None, rule.port),
            HostMatcher::Address(address) => {
                list.decide(&address.to_string(), None, rule.port)
            }
            HostMatcher::Subdomain(_) | HostMatcher::Any | HostMatcher::Regex(_) => {
                return None
            }
        };
        if !covered.is_allowed() {
            return None;
        }
        already_on_the_list.push(pattern.trim().to_string());
    }

    if already_on_the_list.is_empty() {
        return None;
    }
    Some(AlreadyCovered::new(format!(
        "You already have this: {} is already on this project's network allowlist, so the request \
         would add nothing. The connection should work as it is -- if it failed, the reason is \
         something else (a wrong port, a wrong path, or the server being down), not the allowlist.",
        already_on_the_list.join(", ")
    )))
}

fn covered_tools(request: &PermissionRequest, snapshot: &SandboxSnapshot) -> Option<AlreadyCovered> {
    let tools = request.requested_tools();
    if tools.is_empty() {
        return None;
    }
    let missing: Vec<&String> = tools
        .iter()
        .filter(|id| !snapshot.tools.iter().any(|have| have == *id))
        .collect();
    if !missing.is_empty() {
        return None;
    }
    Some(AlreadyCovered::new(format!(
        "You already have this: {} is already installed in this sandbox's image. Run it directly \
         rather than asking for it again -- `deepsand_sandbox_info` lists what is available.",
        tools.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PermissionRequest, SandboxGrant};

    fn snapshot(tools: &[&str], allow: &[&str]) -> SandboxSnapshot {
        SandboxSnapshot {
            project_id: "p1".into(),
            project_name: "my-website".into(),
            container_name: "deepsand-my-website".into(),
            image: "deepsand/runtime:test".into(),
            workspace_mount: "/workspace".into(),
            network_mode: "allowlisted".into(),
            egress_allowlist: allow.iter().map(|s| (*s).to_string()).collect(),
            tools: tools.iter().map(|s| (*s).to_string()).collect(),
            started_at_ms: 0,
            grants: vec![SandboxGrant {
                host_path: "/home/me/brand-assets".into(),
                container_path: "/grants/brand-assets".into(),
                access: Access::ReadOnly,
                label: "brand".into(),
            }],
            open_requests: Vec::new(),
            requests_enabled: true,
            requests_disabled_message: String::new(),
            notes: Vec::new(),
        }
    }

    fn request(kind: RequestKind, args: serde_json::Value) -> PermissionRequest {
        PermissionRequest {
            id: "req_aaa_1111".into(),
            kind,
            project: "p1".into(),
            workspace: "/workspace".into(),
            args,
            created_at: "2026-10-12T00:00:00Z".into(),
            pid: None,
        }
    }

    #[test]
    fn a_directory_inside_the_workspace_is_already_covered() {
        let snapshot = snapshot(&[], &[]);
        let covered = already_covered(
            &request(
                RequestKind::DirectoryAccess,
                serde_json::json!({ "host_path": "/work/site/src", "access": "write" }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .expect("a subdirectory of the workspace needs no request");
        // The message has to name the path it already has, or the model cannot act on it.
        assert!(covered.message.contains("/workspace/src"), "{}", covered.message);
    }

    #[test]
    fn the_workspace_itself_is_already_covered() {
        let snapshot = snapshot(&[], &[]);
        assert!(already_covered(
            &request(
                RequestKind::DirectoryAccess,
                serde_json::json!({ "host_path": "/work/site", "access": "read" }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .is_some());
    }

    #[test]
    fn a_subdirectory_of_a_grant_is_already_covered() {
        let snapshot = snapshot(&[], &[]);
        let covered = already_covered(
            &request(
                RequestKind::DirectoryAccess,
                serde_json::json!({ "host_path": "/home/me/brand-assets/logos", "access": "read" }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .expect("a subdirectory of a granted directory needs no request");
        assert!(
            covered.message.contains("/grants/brand-assets/logos"),
            "{}",
            covered.message
        );
        assert!(covered.message.contains("read-only"), "{}", covered.message);
    }

    /// The case that must not be auto-refused: the model would still be blocked, so
    /// "you already have this" would be a lie.
    #[test]
    fn a_write_request_for_a_read_only_grant_is_not_covered() {
        let snapshot = snapshot(&[], &[]);
        assert!(already_covered(
            &request(
                RequestKind::DirectoryAccess,
                serde_json::json!({ "host_path": "/home/me/brand-assets/logo.svg", "access": "write" }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .is_none());
        // ...but the same path read-only is.
        assert!(already_covered(
            &request(
                RequestKind::DirectoryAccess,
                serde_json::json!({ "host_path": "/home/me/brand-assets/logo.svg", "access": "read" }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .is_some());
    }

    #[test]
    fn a_directory_outside_everything_is_left_to_the_operator() {
        let snapshot = snapshot(&[], &[]);
        assert!(already_covered(
            &request(
                RequestKind::DirectoryAccess,
                serde_json::json!({ "host_path": "/etc", "access": "read" }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .is_none());
    }

    /// A lookalike path must not be read as "inside": `/work/site-other` is not
    /// `/work/site`. This is the same class of bug as a suffix hostname match.
    #[test]
    fn a_sibling_directory_with_a_shared_prefix_is_not_covered() {
        let snapshot = snapshot(&[], &[]);
        assert!(already_covered(
            &request(
                RequestKind::DirectoryAccess,
                serde_json::json!({ "host_path": "/work/site-other", "access": "read" }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .is_none());
    }

    #[test]
    fn a_host_already_on_the_allowlist_is_already_covered() {
        let snapshot = snapshot(&[], &["registry.npmjs.org", "192.168.1.50:5432"]);
        let host = already_covered(
            &request(
                RequestKind::NetworkAccess,
                serde_json::json!({ "patterns": ["registry.npmjs.org"], "purpose": "npm install" }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .expect("an allowlisted host needs no request");
        assert!(host.message.contains("registry.npmjs.org"), "{}", host.message);

        let address = already_covered(
            &request(
                RequestKind::NetworkAccess,
                serde_json::json!({ "patterns": ["192.168.1.50:5432"] }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .expect("an allowlisted address needs no request");
        assert!(address.message.contains("192.168.1.50:5432"), "{}", address.message);
    }

    /// The port matters: asking for a port the entry does not name is a real request,
    /// and it must reach the operator rather than being waved through.
    #[test]
    fn a_host_on_the_allowlist_at_another_port_is_not_covered() {
        let snapshot = snapshot(&[], &["192.168.1.50:5432"]);
        assert!(already_covered(
            &request(
                RequestKind::NetworkAccess,
                serde_json::json!({ "patterns": ["192.168.1.50:6379"] }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .is_none());
    }

    /// A wildcard request covers several hosts at once; whether all of them are already
    /// allowed is a question this function does not answer, so it must not answer at all.
    #[test]
    fn a_wildcard_or_unparseable_pattern_is_left_to_the_operator() {
        let snapshot = snapshot(&[], &["*.example.com", "example.com"]);
        for pattern in ["*.example.com", "re:^api\\.example\\.com$", "!example.com"] {
            assert!(
                already_covered(
                    &request(
                        RequestKind::NetworkAccess,
                        serde_json::json!({ "patterns": [pattern] }),
                    ),
                    Path::new("/work/site"),
                    &snapshot,
                )
                .is_none(),
                "{pattern} must not be auto-refused"
            );
        }
    }

    /// One covered pattern and one not: the request as a whole is not covered, because
    /// the model is asking for something it does not have.
    #[test]
    fn a_partly_covered_network_request_is_not_covered() {
        let snapshot = snapshot(&[], &["registry.npmjs.org"]);
        assert!(already_covered(
            &request(
                RequestKind::NetworkAccess,
                serde_json::json!({ "patterns": ["registry.npmjs.org", "crates.io"] }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .is_none());
    }

    #[test]
    fn a_tool_that_is_already_installed_is_already_covered() {
        let snapshot = snapshot(&["node", "python"], &[]);
        let covered = already_covered(
            &request(RequestKind::ToolInstall, serde_json::json!({ "tools": ["node"] })),
            Path::new("/work/site"),
            &snapshot,
        )
        .expect("an installed tool needs no request");
        assert!(covered.message.contains("node"), "{}", covered.message);

        // A tool that is not there is a genuine request.
        assert!(already_covered(
            &request(RequestKind::ToolInstall, serde_json::json!({ "tools": ["rust"] })),
            Path::new("/work/site"),
            &snapshot,
        )
        .is_none());
        // As is a mixed request: the sandbox does not have everything it asked for.
        assert!(already_covered(
            &request(RequestKind::ToolInstall, serde_json::json!({ "tools": ["node", "rust"] })),
            Path::new("/work/site"),
            &snapshot,
        )
        .is_none());
    }

    #[test]
    fn a_locate_resource_request_is_never_auto_refused() {
        let snapshot = snapshot(&[], &[]);
        assert!(already_covered(
            &request(
                RequestKind::LocateResource,
                serde_json::json!({ "description": "the brand assets" }),
            ),
            Path::new("/work/site"),
            &snapshot,
        )
        .is_none());
    }

    /// A request with no usable target is not evidence of anything, and must not be
    /// treated as covered merely because there is nothing to compare.
    #[test]
    fn a_request_with_no_target_is_left_alone() {
        let snapshot = snapshot(&["node"], &["example.com"]);
        for kind in [
            RequestKind::DirectoryAccess,
            RequestKind::NetworkAccess,
            RequestKind::ToolInstall,
        ] {
            assert!(
                already_covered(&request(kind, serde_json::json!({})), Path::new("/work/site"), &snapshot)
                    .is_none(),
                "{kind:?} with no args must not be auto-refused"
            );
        }
    }
}
