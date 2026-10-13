//! Remote access to the Deepsand GUI over HTTP.
//!
//! The desktop UI is a Tauri webview, so making it reachable from another device
//! means serving the same frontend plus an HTTP translation of the command surface.
//! That is a control plane: whoever holds a server's token can drive sandboxes, read
//! terminal output, and — if the server is configured to allow it — mount host
//! directories into containers.
//!
//! This module is the part that decides *what a remote client may do*. It is kept
//! separate from the HTTP plumbing so the decisions are unit-testable, because the
//! plumbing is easy to get right once and the policy is easy to get wrong quietly.
//!
//! # Defaults
//!
//! * Every field of [`RemoteCapabilities`] beyond viewing is **off**, so a server
//!   that is enabled by accident is a window rather than a control plane. In
//!   particular `grant_permissions` is off: answering a permission request is how
//!   the sandbox boundary is widened, and that should not be reachable from a
//!   device you may not control.
//! * Binding defaults to **loopback only**. The intended deployment is a reverse
//!   proxy on the same machine terminating TLS and doing real authentication;
//!   Deepsand's token is a second factor for that, not a substitute for it.
//! * An unrecognised command is **refused**, never allowed. A command added later
//!   is therefore unreachable remotely until it is classified here on purpose.
//!
//! # Why the token is not the whole story
//!
//! Plain HTTP means the token crosses the network in cleartext. That is why the
//! default bind is loopback and why TLS is offered: with a reverse proxy in front,
//! the token never leaves the machine. See `docs/SECURITY.md`.

use serde::{Deserialize, Serialize};

/// Loopback, not `0.0.0.0`. See the module docs.
pub const DEFAULT_BIND: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 47821;
/// 256 bits. Overkill for a bearer token over loopback, cheap either way, and it
/// makes brute force pointless even if the server is exposed deliberately.
pub const TOKEN_BYTES: usize = 32;

/// What a remote client is allowed to do.
///
/// Every field is opt-in, and the default is "look but do not change the security
/// posture". A remote client on an unconfigured server can watch a sandbox and read
/// its state, and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RemoteCapabilities {
    /// Start, stop, restart a sandbox, and type into or resize its terminal.
    pub control: bool,
    /// Answer permission requests, and change what a project may reach: directory
    /// grants and the network allowlist.
    ///
    /// This is the capability to widen the sandbox boundary, which is why it is
    /// separate from `control` and off by default. A stolen token without it can
    /// drive an existing sandbox but cannot open new doors.
    pub grant_permissions: bool,
    /// Create and delete projects.
    pub manage_projects: bool,
    /// Change the security posture: network mode, hardening settings, credentials,
    /// and the remote access configuration itself.
    pub change_security: bool,
}

impl Default for RemoteCapabilities {
    fn default() -> Self {
        Self {
            control: true,
            grant_permissions: false,
            manage_projects: false,
            change_security: false,
        }
    }
}

impl RemoteCapabilities {
    /// Everything on, for an operator who has decided to trust the client fully.
    pub fn unrestricted() -> Self {
        Self {
            control: true,
            grant_permissions: true,
            manage_projects: true,
            change_security: true,
        }
    }

    pub fn allows(self, capability: Capability) -> bool {
        match capability {
            // Reading is never gated: a server that cannot be read is not a server.
            Capability::View => true,
            Capability::Control => self.control,
            Capability::GrantPermissions => self.grant_permissions,
            Capability::ManageProjects => self.manage_projects,
            Capability::ChangeSecurity => self.change_security,
        }
    }

    /// A short list of the capabilities that are on, for a UI to summarise.
    pub fn enabled_names(self) -> Vec<&'static str> {
        let mut names = vec!["view"];
        if self.control {
            names.push("control");
        }
        if self.grant_permissions {
            names.push("grant permissions");
        }
        if self.manage_projects {
            names.push("manage projects");
        }
        if self.change_security {
            names.push("change security");
        }
        names
    }
}

/// What a server exposes.
///
/// A per-project server is how an operator shares one project without handing over
/// the rest, which is the difference between "let me check on my build from my
/// phone" and "give me the machine".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "projectId")]
pub enum RemoteScope {
    /// Every project.
    App,
    /// Exactly one project, by id.
    Project(String),
}

impl RemoteScope {
    pub fn allows_project(&self, project_id: &str) -> bool {
        match self {
            RemoteScope::App => true,
            RemoteScope::Project(only) => only == project_id,
        }
    }

    pub fn is_app(&self) -> bool {
        matches!(self, RemoteScope::App)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemoteTls {
    /// Plain HTTP. Only sensible behind a reverse proxy on the same machine.
    Off,
    /// A self-signed certificate, for reaching the server directly without the
    /// token crossing the network in cleartext. The browser will warn.
    SelfSigned,
}

impl Default for RemoteTls {
    fn default() -> Self {
        RemoteTls::Off
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteServerConfig {
    pub id: String,
    /// Shown in the UI so several servers can be told apart.
    pub label: String,
    pub scope: RemoteScope,
    pub bind: String,
    pub port: u16,
    pub tls: RemoteTls,
    pub capabilities: RemoteCapabilities,
    /// The bearer token. Never logged, and redacted in anything that is rendered.
    pub token: String,
}

impl RemoteServerConfig {
    /// A new server with a fresh token and the safe defaults.
    pub fn new(id: impl Into<String>, label: impl Into<String>, scope: RemoteScope) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            scope,
            bind: DEFAULT_BIND.to_string(),
            port: DEFAULT_PORT,
            tls: RemoteTls::default(),
            capabilities: RemoteCapabilities::default(),
            token: generate_token(),
        }
    }

    /// The address a client would use, for display. Deliberately does not include
    /// the token, so the string is safe to log and to show.
    pub fn display_url(&self) -> String {
        let scheme = match self.tls {
            RemoteTls::Off => "http",
            RemoteTls::SelfSigned => "https",
        };
        let host = if self.bind == "0.0.0.0" || self.bind == "::" {
            "localhost".to_string()
        } else {
            self.bind.clone()
        };
        format!("{scheme}://{host}:{}", self.port)
    }

    /// Whether this configuration is only reachable from this machine.
    pub fn is_loopback(&self) -> bool {
        self.bind
            .parse::<std::net::IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(self.bind.eq_ignore_ascii_case("localhost"))
    }

    /// The token with everything but the first and last four characters hidden.
    pub fn redacted_token(&self) -> String {
        redact_token(&self.token)
    }

    /// Regenerate the token in place, returning the new value.
    pub fn regenerate_token(&mut self) -> String {
        self.token = generate_token();
        self.token.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RemoteAccessSettings {
    /// Whether the remote access feature is visible at all.
    ///
    /// Off by default, and the whole section is hidden in the UI while it is off.
    /// This gates *visibility*, not just behaviour: an operator who has not opted
    /// in never sees a form inviting them to open an HTTP port.
    ///
    /// It is also not reachable over HTTP, so a leaked token cannot switch it on.
    pub enabled: bool,
    /// Whether servers come back up by themselves after Deepsand restarts.
    ///
    /// Default false: a window opened for one afternoon should not still be open a
    /// month later. An operator who wants a permanently reachable instance can turn
    /// it on, and the UI says so plainly.
    pub persist_across_restarts: bool,
    /// Failed token attempts before a client address is locked out.
    pub lockout_after_failures: u32,
    pub servers: Vec<RemoteServerConfig>,
}

impl Default for RemoteAccessSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            persist_across_restarts: false,
            // Low enough to matter, high enough that a fumbled paste does not lock
            // the operator out of their own server.
            lockout_after_failures: 10,
            servers: Vec::new(),
        }
    }
}

impl RemoteAccessSettings {
    pub fn server(&self, id: &str) -> Option<&RemoteServerConfig> {
        self.servers.iter().find(|server| server.id == id)
    }

    pub fn server_mut(&mut self, id: &str) -> Option<&mut RemoteServerConfig> {
        self.servers.iter_mut().find(|server| server.id == id)
    }

    /// Servers that are configured to start with the app.
    pub fn startup_servers(&self) -> Vec<&RemoteServerConfig> {
        if self.enabled && self.persist_across_restarts {
            self.servers.iter().collect()
        } else {
            Vec::new()
        }
    }
}

/// What a command needs to be reachable remotely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    View,
    Control,
    GrantPermissions,
    ManageProjects,
    ChangeSecurity,
}

/// Why a remote request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteDenial {
    /// The command is not exposed over HTTP at all. This is the answer for
    /// anything not classified below, so a newly added command is unreachable
    /// until somebody decides otherwise on purpose.
    NotExposed,
    /// The server's capabilities do not include what the command needs.
    MissingCapability(Capability),
    /// A project-scoped server was asked about a different project.
    WrongProject,
    /// The request did not carry a usable project, but the server is scoped to one.
    NoProject,
}

impl RemoteDenial {
    /// A message safe to return to the client: it must not reveal whether a
    /// project it cannot see exists.
    pub fn message(self) -> String {
        match self {
            RemoteDenial::NotExposed => {
                "This command is not available over remote access.".to_string()
            }
            RemoteDenial::MissingCapability(Capability::Control) => {
                "This server does not allow controlling sandboxes.".to_string()
            }
            RemoteDenial::MissingCapability(Capability::GrantPermissions) => {
                "This server does not allow granting permissions.".to_string()
            }
            RemoteDenial::MissingCapability(Capability::ManageProjects) => {
                "This server does not allow creating or deleting projects.".to_string()
            }
            RemoteDenial::MissingCapability(Capability::ChangeSecurity) => {
                "This server does not allow changing security settings.".to_string()
            }
            RemoteDenial::MissingCapability(Capability::View) => {
                "This server does not allow reading that.".to_string()
            }
            RemoteDenial::WrongProject | RemoteDenial::NoProject => {
                "This server is limited to a single project.".to_string()
            }
        }
    }
}

/// Classify a command for remote use.
///
/// `project_arg` names the request field that identifies the project, when the
/// command is about one. It is used to confine a project-scoped server.
///
/// Returning `None` means "not reachable remotely", which includes anything not
/// listed: the safe direction for a table like this is to grow deliberately.
pub fn requirement(command: &str) -> Option<(Capability, Option<&'static str>)> {
    use Capability::*;
    Some(match command {
        // --- reading -------------------------------------------------------
        "app_info" => (View, None),
        "docker_status" => (View, None),
        "list_projects" => (View, None),
        "get_project" => (View, Some("projectId")),
        "session_status" => (View, Some("projectId")),
        "list_grants" => (View, Some("projectId")),
        "audit_log" => (View, Some("projectId")),
        "preview_plan" => (View, Some("projectId")),
        "list_pending_requests" => (View, None),
        "get_settings" => (View, None),
        "network_presets" => (View, None),
        "project_allowlist" => (View, Some("projectId")),
        "startup_error" => (View, None),
        "host_config_summary" => (View, None),
        // Reading a path on the host is reconnaissance: it answers "does this
        // directory exist", which is useful for choosing what to go after. It is
        // part of the granting flow, so it travels with that capability rather
        // than with viewing.
        "path_check" => (GrantPermissions, None),

        // --- driving a sandbox ---------------------------------------------
        "start_session" => (Control, Some("projectId")),
        "stop_session" => (Control, Some("projectId")),
        "restart_session" => (Control, Some("projectId")),
        "write_to_session" => (Control, Some("projectId")),
        "resize_session" => (Control, Some("projectId")),

        // --- widening the boundary -----------------------------------------
        "answer_request" => (GrantPermissions, None),
        "add_grant" => (GrantPermissions, Some("projectId")),
        "set_grant_access" => (GrantPermissions, Some("projectId")),
        "revoke_grant" => (GrantPermissions, Some("projectId")),
        "set_project_allowlist" => (GrantPermissions, Some("projectId")),

        // --- the shape of the app ------------------------------------------
        "create_project" => (ManageProjects, None),
        "delete_project" => (ManageProjects, Some("projectId")),

        // --- security posture ----------------------------------------------
        "update_project_settings" => (ChangeSecurity, Some("projectId")),
        // Turning asking off is a change to the security posture: it is what stops the
        // sandbox widening its own access, so a remote client needs the same capability
        // as changing the network mode or the allowlist.
        "set_requests_enabled" => (ChangeSecurity, Some("projectId")),
        "set_settings" => (ChangeSecurity, None),
        "set_egress_allowlist" => (ChangeSecurity, None),
        "build_runtime_image" => (ChangeSecurity, None),
        "cleanup_orphans" => (ChangeSecurity, None),
        // Deliberately absent rather than gated:
        //  * `reveal_data_dir` opens a folder window on the host, which means
        //    nothing to a remote client and would act on the wrong machine.
        //  * the remote-access configuration commands are desktop-only, so a
        //    stolen token cannot extend its own reach or rotate itself away from
        //    the operator.
        _ => return None,
    })
}

/// The single entry point the HTTP layer uses.
///
/// Takes the command name, the project it names if any, and the server the request
/// arrived on.
pub fn authorize(
    command: &str,
    target_project: Option<&str>,
    scope: &RemoteScope,
    capabilities: RemoteCapabilities,
) -> Result<(), RemoteDenial> {
    let Some((capability, project_arg)) = requirement(command) else {
        return Err(RemoteDenial::NotExposed);
    };

    if !capabilities.allows(capability) {
        return Err(RemoteDenial::MissingCapability(capability));
    }

    let expects_project = project_arg.is_some();
    if let RemoteScope::Project(only) = scope {
        // A project-scoped server may only ever act on its own project. A command
        // that names a different one is refused identically to one that names
        // nothing, so the client cannot tell whether another project exists.
        match target_project {
            Some(target) if target == only => {}
            Some(_) => return Err(RemoteDenial::WrongProject),
            None => {
                // Listing everything is fine; acting on "the" project without
                // naming it is not, because there is more than one in the app.
                if expects_project {
                    return Err(RemoteDenial::NoProject);
                }
            }
        }
    }

    Ok(())
}

/// Generate a fresh token: 32 random bytes as lowercase hex.
///
/// Panics only if the OS has no entropy source, which is not a state in which
/// issuing a predictable token would be an improvement.
pub fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::getrandom(&mut bytes).expect("the OS entropy source must be available");
    let mut out = String::with_capacity(TOKEN_BYTES * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// Compare a presented token against the expected one without leaking, through
/// timing, how many leading characters were right.
///
/// The length check returns early, which does leak the length. That is fine here:
/// tokens are generated with a fixed length, so an attacker learns nothing they
/// did not already know, and the alternative (hashing both sides) buys nothing
/// against a 256-bit random secret.
pub fn token_matches(expected: &str, presented: &str) -> bool {
    let expected = expected.as_bytes();
    let presented = presented.as_bytes();
    if expected.len() != presented.len() || expected.is_empty() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(presented.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Pull a bearer token out of an `Authorization` header value.
pub fn bearer_token(header: Option<&str>) -> Option<&str> {
    let value = header?.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

fn redact_token(token: &str) -> String {
    if token.len() <= 8 {
        return "…".to_string();
    }
    format!("{}…{}", &token[..4], &token[token.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(control: bool, grant: bool, manage: bool, security: bool) -> RemoteCapabilities {
        RemoteCapabilities {
            control,
            grant_permissions: grant,
            manage_projects: manage,
            change_security: security,
        }
    }

    /* --------------------------------------------------------------------- */
    /* Tokens                                                                */
    /* --------------------------------------------------------------------- */

    #[test]
    fn tokens_are_long_hex_and_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), TOKEN_BYTES * 2);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two tokens must never collide");
    }

    #[test]
    fn tokens_compare_correctly() {
        let token = generate_token();
        assert!(token_matches(&token, &token));
        assert!(!token_matches(&token, ""));
        assert!(!token_matches(&token, &token[..token.len() - 1]));
        let mut wrong = token.clone();
        wrong.pop();
        wrong.push(if token.ends_with('a') { 'b' } else { 'a' });
        assert!(!token_matches(&token, &wrong));
    }

    #[test]
    fn an_empty_expected_token_never_matches() {
        // A server that somehow ended up with no token must not be open to
        // everyone presenting an empty string.
        assert!(!token_matches("", ""));
    }

    #[test]
    fn regenerating_changes_the_token_and_returns_the_new_one() {
        let mut server = RemoteServerConfig::new("s1", "Laptop", RemoteScope::App);
        let first = server.token.clone();
        let second = server.regenerate_token();
        assert_ne!(first, second);
        assert_eq!(server.token, second);
    }

    #[test]
    fn a_token_is_redacted_for_display() {
        let server = RemoteServerConfig::new("s1", "Laptop", RemoteScope::App);
        let redacted = server.redacted_token();
        assert!(redacted.contains('…'));
        assert!(!redacted.contains(&server.token));
        assert!(redacted.starts_with(&server.token[..4]));
    }

    #[test]
    fn a_display_url_never_contains_the_token() {
        let server = RemoteServerConfig::new("s1", "Laptop", RemoteScope::App);
        let url = server.display_url();
        assert_eq!(url, "http://127.0.0.1:47821");
        assert!(!url.contains(&server.token));
    }

    #[test]
    fn bearer_headers_are_parsed_defensively() {
        assert_eq!(bearer_token(Some("Bearer abc123")), Some("abc123"));
        assert_eq!(bearer_token(Some("bearer  abc123 ")), Some("abc123"));
        assert_eq!(bearer_token(Some("Basic abc123")), None);
        assert_eq!(bearer_token(Some("Bearer")), None);
        assert_eq!(bearer_token(Some("Bearer ")), None);
        assert_eq!(bearer_token(None), None);
    }

    /* --------------------------------------------------------------------- */
    /* Defaults are the safe ones                                            */
    /* --------------------------------------------------------------------- */

    #[test]
    fn a_new_server_is_loopback_with_minimal_rights() {
        let server = RemoteServerConfig::new("s1", "Laptop", RemoteScope::App);
        assert_eq!(server.bind, "127.0.0.1");
        assert!(server.is_loopback());
        assert!(server.capabilities.control);
        // The three that widen access or change posture are off.
        assert!(!server.capabilities.grant_permissions);
        assert!(!server.capabilities.manage_projects);
        assert!(!server.capabilities.change_security);
    }

    #[test]
    fn loopback_detection_covers_the_usual_spellings() {
        let mut server = RemoteServerConfig::new("s1", "Laptop", RemoteScope::App);
        assert!(server.is_loopback());
        server.bind = "localhost".into();
        assert!(server.is_loopback());
        server.bind = "::1".into();
        assert!(server.is_loopback());
        server.bind = "192.168.1.10".into();
        assert!(!server.is_loopback());
        server.bind = "0.0.0.0".into();
        assert!(!server.is_loopback());
    }

    #[test]
    fn servers_do_not_come_back_after_a_restart_by_default() {
        let settings = RemoteAccessSettings::default();
        assert!(!settings.persist_across_restarts);
        assert!(settings.startup_servers().is_empty());
    }

    /* --------------------------------------------------------------------- */
    /* An unrecognised command is never allowed                              */
    /* --------------------------------------------------------------------- */

    #[test]
    fn an_unknown_command_is_refused_even_with_every_capability() {
        let all = caps(true, true, true, true);
        for command in ["", "nonexistent", "rm -rf /", "delete_everything"] {
            assert_eq!(
                authorize(command, None, &RemoteScope::App, all),
                Err(RemoteDenial::NotExposed),
                "the command table must deny by default: {command}"
            );
        }
    }

    #[test]
    fn the_remote_configuration_commands_are_not_reachable_at_all() {
        // A stolen token must not be able to extend its own reach or lock the
        // operator out by rotating the token.
        let all = caps(true, true, true, true);
        for command in [
            "set_remote_access",
            "regenerate_remote_token",
            "create_remote_server",
            "stop_remote_server",
        ] {
            assert_eq!(
                authorize(command, None, &RemoteScope::App, all),
                Err(RemoteDenial::NotExposed)
            );
        }
    }

    #[test]
    fn reveal_data_dir_is_desktop_only() {
        let all = caps(true, true, true, true);
        assert_eq!(
            authorize("reveal_data_dir", None, &RemoteScope::App, all),
            Err(RemoteDenial::NotExposed)
        );
    }

    /* --------------------------------------------------------------------- */
    /* Capabilities                                                          */
    /* --------------------------------------------------------------------- */

    #[test]
    fn viewing_is_allowed_by_the_default_capabilities() {
        let default = RemoteCapabilities::default();
        for command in ["list_projects", "app_info", "list_pending_requests"] {
            assert!(
                authorize(command, None, &RemoteScope::App, default).is_ok(),
                "{command} should be readable by default"
            );
        }
    }

    #[test]
    fn answering_a_permission_request_needs_grant_permissions() {
        let default = RemoteCapabilities::default();
        assert_eq!(
            authorize("answer_request", None, &RemoteScope::App, default),
            Err(RemoteDenial::MissingCapability(Capability::GrantPermissions))
        );
        let granting = caps(true, true, false, false);
        assert!(authorize("answer_request", None, &RemoteScope::App, granting).is_ok());
    }

    #[test]
    fn controlling_a_sandbox_needs_control() {
        let read_only = caps(false, false, false, false);
        for command in ["start_session", "stop_session", "write_to_session"] {
            assert_eq!(
                authorize(command, Some("p1"), &RemoteScope::App, read_only),
                Err(RemoteDenial::MissingCapability(Capability::Control)),
                "{command} should need control"
            );
        }
    }

    /// The distinction that matters most: driving a sandbox is not the same as
    /// being able to mount a new host directory into one.
    #[test]
    fn control_alone_cannot_widen_the_sandbox_boundary() {
        let control_only = caps(true, false, false, false);
        for command in [
            "add_grant",
            "revoke_grant",
            "set_grant_access",
            "set_project_allowlist",
            "answer_request",
            "path_check",
        ] {
            let result = authorize(command, Some("p1"), &RemoteScope::App, control_only);
            assert!(
                matches!(result, Err(RemoteDenial::MissingCapability(_))),
                "{command} must not be reachable with control alone, got {result:?}"
            );
        }
    }

    #[test]
    fn changing_security_needs_its_own_capability() {
        let control_and_grant = caps(true, true, false, false);
        for command in ["set_settings", "set_egress_allowlist", "update_project_settings"] {
            assert_eq!(
                authorize(command, Some("p1"), &RemoteScope::App, control_and_grant),
                Err(RemoteDenial::MissingCapability(Capability::ChangeSecurity)),
                "{command} should need change_security"
            );
        }
    }

    #[test]
    fn project_management_needs_its_own_capability() {
        let control = caps(true, false, false, false);
        assert_eq!(
            authorize("create_project", None, &RemoteScope::App, control),
            Err(RemoteDenial::MissingCapability(Capability::ManageProjects))
        );
        assert_eq!(
            authorize("delete_project", Some("p1"), &RemoteScope::App, control),
            Err(RemoteDenial::MissingCapability(Capability::ManageProjects))
        );
    }

    #[test]
    fn a_fully_unrestricted_server_can_do_everything_classified() {
        let all = RemoteCapabilities::unrestricted();
        for command in [
            "list_projects",
            "start_session",
            "answer_request",
            "add_grant",
            "create_project",
            "set_settings",
        ] {
            assert!(
                authorize(command, Some("p1"), &RemoteScope::App, all).is_ok(),
                "{command} should be allowed"
            );
        }
    }

    /* --------------------------------------------------------------------- */
    /* Project scoping                                                       */
    /* --------------------------------------------------------------------- */

    #[test]
    fn a_project_server_only_serves_its_own_project() {
        let scope = RemoteScope::Project("p1".into());
        let all = RemoteCapabilities::unrestricted();
        assert!(authorize("get_project", Some("p1"), &scope, all).is_ok());
        assert_eq!(
            authorize("get_project", Some("p2"), &scope, all),
            Err(RemoteDenial::WrongProject)
        );
    }

    #[test]
    fn a_project_server_refuses_project_commands_that_name_no_project() {
        let scope = RemoteScope::Project("p1".into());
        let all = RemoteCapabilities::unrestricted();
        assert_eq!(
            authorize("start_session", None, &scope, all),
            Err(RemoteDenial::NoProject)
        );
    }

    #[test]
    fn a_project_server_can_still_list_projects_and_read_the_app() {
        // Listing is how a client knows what it is connected to; it is not an
        // action on another project.
        let scope = RemoteScope::Project("p1".into());
        let all = RemoteCapabilities::unrestricted();
        for command in ["list_projects", "app_info", "get_settings"] {
            assert!(
                authorize(command, None, &scope, all).is_ok(),
                "{command} should be reachable"
            );
        }
    }

    /// The refusal must not distinguish "another project exists" from "no project
    /// given", so a scoped client cannot enumerate the app's projects.
    #[test]
    fn a_scoped_refusal_does_not_reveal_whether_the_project_exists() {
        let scope = RemoteScope::Project("p1".into());
        let all = RemoteCapabilities::unrestricted();
        let wrong = authorize("get_project", Some("p2"), &scope, all).unwrap_err();
        let missing = authorize("start_session", None, &scope, all).unwrap_err();
        assert_eq!(wrong.message(), missing.message());
    }

    #[test]
    fn an_app_server_is_unaffected_by_the_scoping_rules() {
        let all = RemoteCapabilities::unrestricted();
        assert!(authorize("get_project", Some("anything"), &RemoteScope::App, all).is_ok());
        assert!(authorize("list_projects", None, &RemoteScope::App, all).is_ok());
    }

    #[test]
    fn scope_membership_is_exact() {
        assert!(RemoteScope::App.allows_project("p1"));
        assert!(RemoteScope::Project("p1".into()).allows_project("p1"));
        assert!(!RemoteScope::Project("p1".into()).allows_project("p2"));
        // No prefix matching: "p1" must not admit "p10".
        assert!(!RemoteScope::Project("p1".into()).allows_project("p10"));
    }

    /* --------------------------------------------------------------------- */
    /* Settings round-trip                                                   */
    /* --------------------------------------------------------------------- */

    #[test]
    fn remote_settings_round_trip_through_json() {
        let mut settings = RemoteAccessSettings::default();
        settings.persist_across_restarts = true;
        settings
            .servers
            .push(RemoteServerConfig::new("s1", "Phone", RemoteScope::Project("p1".into())));
        let encoded = serde_json::to_string(&settings).expect("serialisable");
        let decoded: RemoteAccessSettings = serde_json::from_str(&encoded).expect("deserialisable");
        assert_eq!(decoded, settings);
        assert_eq!(decoded.server("s1").unwrap().scope, RemoteScope::Project("p1".into()));
    }

    #[test]
    fn a_settings_file_without_the_new_fields_still_loads() {
        // Forward compatibility: an app settings file written before remote access
        // existed must not fail to parse.
        let decoded: RemoteAccessSettings = serde_json::from_str("{}").expect("defaults apply");
        assert_eq!(decoded, RemoteAccessSettings::default());
    }

    #[test]
    fn enabled_capability_names_are_useful_for_a_ui() {
        assert_eq!(RemoteCapabilities::default().enabled_names(), ["view", "control"]);
        assert_eq!(
            RemoteCapabilities::unrestricted().enabled_names().len(),
            5
        );
    }
}
