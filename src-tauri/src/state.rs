//! Shared application state for the Tauri command surface.
//!
//! The desktop app is a thin shell: every rule about what a sandbox may contain
//! lives in `deepsand-core`, and the commands in `commands.rs` only wire that
//! core to the webview. Nothing here decides policy.

use deepsand_core::broker::{Broker, RejectedRequest};
use deepsand_core::docker::Docker;
use deepsand_core::model::*;
use deepsand_core::proxy::EgressProxy;
use deepsand_core::session::Session;
use deepsand_core::store::Store;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/* ------------------------------------------------------------------------- */
/* Event names, shared verbatim with the frontend                             */
/* ------------------------------------------------------------------------- */

pub mod events {
    /// Raw terminal bytes: `{ projectId, data }`
    pub const TERMINAL_OUTPUT: &str = "terminal://output";
    /// The container stopped: `{ projectId, code }`
    pub const TERMINAL_EXIT: &str = "terminal://exit";
    /// `{ projectId, status }`
    pub const SESSION_STATUS: &str = "session://status";
    /// A new permission request: `PermissionRequestView`
    pub const BROKER_REQUEST: &str = "broker://request";
    /// A request was answered: `{ requestId, decision }`
    pub const BROKER_RESOLVED: &str = "broker://resolved";
    /// A request file was discarded: `RejectedRequestView`
    pub const BROKER_REJECTED: &str = "broker://rejected";
    /// Image build output: `{ line }`
    pub const BUILD_LOG: &str = "build://log";
    /// Image build finished: `{ ok, detail }`
    pub const BUILD_DONE: &str = "build://done";
    /// How far along a runtime image build is.
    ///
    /// Separate from the log: the log is for reading, this is for a bar. Only emitted
    /// when the build reports a step, so a subscriber can tell "no news" from
    /// "finished".
    pub const BUILD_PROGRESS: &str = "build://progress";
    /// Any persisted change: the frontend re-reads what it needs.
    pub const STATE_CHANGED: &str = "state://changed";
    /// The egress proxy refused a host: `BlockedEgressView`
    pub const EGRESS_BLOCKED: &str = "egress://blocked";
}

/* ------------------------------------------------------------------------- */
/* Payloads                                                                   */
/* ------------------------------------------------------------------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectView {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub root_dir: String,
    pub created_at_ms: i64,
    pub network: NetworkPolicy,
    pub limits: ResourceLimits,
    pub credentials: Credentials,
    pub deepcode_mode: DeepCodeMode,
    pub allowed_roots: Vec<String>,
    pub notes: String,
    /// Derived, for the sidebar and header.
    pub container_name: String,
    pub running: bool,
    pub workspace_exists: bool,
    pub grant_count: usize,
    pub pending_requests: usize,
}

impl ProjectView {
    pub fn new(project: &Project, running: bool, grant_count: usize, pending_requests: usize) -> Self {
        Self {
            id: project.id.clone(),
            name: project.name.clone(),
            slug: project.slug.clone(),
            root_dir: project.root_dir.clone(),
            created_at_ms: project.created_at_ms,
            network: project.network.clone(),
            limits: project.limits.clone(),
            credentials: project.credentials.clone(),
            deepcode_mode: project.deepcode_mode,
            allowed_roots: project.allowed_roots.clone(),
            notes: project.notes.clone(),
            container_name: project.container_name(),
            running,
            workspace_exists: std::path::Path::new(&project.root_dir).is_dir(),
            grant_count,
            pending_requests,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanPreview {
    pub text: String,
    pub warnings: Vec<String>,
    pub mount_count: usize,
    pub network_mode: String,
    pub image: String,
    pub container_name: String,
    pub credential_provenance: String,
    pub api_key_present: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathCheck {
    pub allowed: bool,
    pub resolved: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatus {
    pub project_id: String,
    pub running: bool,
    pub command_line: Option<String>,
    pub container_name: String,
    pub network_mode: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestView {
    pub id: String,
    pub project_id: String,
    pub project_name: String,
    pub kind: String,
    /// "DeepCode is trying to access C:\\Users\\me\\brand"
    pub title: String,
    pub description: String,
    pub purpose: Option<String>,
    pub requested_access: String,
    pub requested_kind: String,
    /// True when the sandbox named a path, so the dialog can prefill it.
    pub has_claimed_path: bool,
    pub claimed_path: Option<String>,
    /// Populated when a path was named and it is refused by policy, so the
    /// dialog can explain *why* before the operator even tries.
    pub claimed_path_rejection: Option<String>,
    pub received_at: String,
    /// When Deepsand first surfaced this dialog, so the UI can age it.
    pub surfaced_at_ms: i64,
    /// A reminder that everything above was written by the sandbox.
    ///
    /// The request spool is mounted writable, so this text is a claim by something that
    /// may be compromised. The host validates its shape and re-checks every path before
    /// anything is granted, but none of that can make the content true, and a dialog that
    /// does not say so invites the operator to read it as a finding.
    pub provenance: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RejectedRequestView {
    pub project_id: String,
    pub file: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockedEgressView {
    pub host: String,
    pub port: u16,
    pub at_ms: i64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub data_dir: String,
    pub docker: DockerStatus,
    pub host_config: std::collections::BTreeMap<String, String>,
    pub settings: AppSettings,
}

/// One stored secret, as the table renders it.
///
/// The value is deliberately absent. The table is drawn from this, and a value that
/// never reaches the UI cannot be leaked by the UI -- there is no "reveal" that could
/// be left switched on or captured in a screenshot.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretView {
    pub name: String,
    /// A fixed placeholder, so the table shows that something is stored without
    /// showing how long it is or what it starts with.
    pub masked: String,
    /// The length, which is the one thing worth knowing for spotting a truncated paste.
    pub length: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretListView {
    pub project_id: String,
    pub secrets: Vec<SecretView>,
    /// False when the store could not be opened at all, with the reason.
    pub available: bool,
    pub unavailable_reason: Option<String>,
    /// True when a sandbox is running, so a change needs a restart to be seen.
    pub restart_needed: bool,
    /// Reserved names the operator cannot use, so the form can say so up front.
    pub reserved: Vec<String>,
}

/// One entry in the tool catalogue, as the Tools tab renders it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolView {
    pub id: String,
    pub label: String,
    pub description: String,
    /// "Utilities", "Languages", "Package managers", "Capabilities".
    pub category: String,
    pub provider: String,
    /// On for a new project unless switched off.
    pub default_on: bool,
    pub enabled: bool,
    /// False when the tool cannot be installed into this image at all.
    pub available: bool,
    /// Why not, so a disabled row explains itself instead of being mysterious.
    pub unavailable_reason: Option<String>,
    /// Hosts the tool opens in the network filter while it is enabled.
    pub hosts: Vec<String>,
    /// The base image the tool needs, so a disabled row can say what it needs rather
    /// than just being greyed out.
    pub requires: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffortOption {
    pub value: String,
    pub label: String,
    /// What the state means, for the tooltip. "Default" in particular needs a
    /// sentence: on its own it does not say what it defers to.
    pub description: String,
}

/// The Tools tab: the catalogue, the selection, and what it adds up to.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCatalogView {
    pub project_id: String,
    pub tools: Vec<ToolView>,
    /// Hosts the enabled tools contribute to the sandbox's allowlist.
    pub effective_hosts: Vec<String>,
    /// The image tag this selection builds to.
    pub image: String,
    /// The image tag the project is currently running, when it is running.
    pub running_image: Option<String>,
}

/// The thinking-intensity switch's state and its three options.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffortView {
    pub project_id: String,
    pub value: String,
    pub options: Vec<EffortOption>,
    /// False when the project is inheriting an explicit override from its own
    /// credentials, in which case this switch would not be what decides.
    pub controlling: bool,
    /// True when a sandbox is running and did **not** receive the change, so a
    /// restart is needed. Normally false: the setting is pushed into the running
    /// sandbox, because the CLI reads its settings file per run.
    pub restart_needed: bool,
    /// True when this project defers to the operator's own `settings.json`, so the
    /// switch is not what decides.
    pub deferring: bool,
    /// Whether a running sandbox received the change, as well as it being saved.
    pub applied_live: bool,
}

/// One configured remote server, as the UI needs to see it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteServerView {
    pub id: String,
    pub label: String,
    /// "app" or "project".
    pub scope_kind: String,
    pub project_id: Option<String>,
    pub bind: String,
    pub port: u16,
    pub tls: String,
    pub capabilities: deepsand_core::remote::RemoteCapabilities,
    /// Shown so the operator can copy it. This is the one place a full token is
    /// rendered, and it is a local-only command that a remote client cannot reach.
    pub token: String,
    pub redacted_token: String,
    pub display_url: String,
    pub loopback_only: bool,
    pub running: bool,
    /// The address actually bound, which differs from the configured port when the
    /// port was requested as 0.
    pub bound_addr: Option<String>,
}

/// The whole remote access section of the settings screen.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteAccessView {
    /// The feature toggle. While false the UI hides this section entirely.
    pub enabled: bool,
    pub persist_across_restarts: bool,
    pub lockout_after_failures: u32,
    pub servers: Vec<RemoteServerView>,
    /// Where the built frontend was found, so a missing UI is diagnosable.
    pub ui_dir: Option<String>,
}

/// A project's network allowlist, with the inherited global entries shown
/// alongside it so the operator can see the full picture without being able to
/// edit the global list from a project screen.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowlistView {
    pub project_id: String,
    /// The project's network mode, so a UI can say whether any of this applies.
    pub mode: String,
    pub allowlisted: bool,
    /// Entries belonging to this project. These are the ones the operator edits.
    pub project: Vec<String>,
    /// Operator-wide entries, inherited by every project. Read-only in this view.
    pub global: Vec<String>,
    /// What is actually enforced: the union, deduplicated.
    pub effective: Vec<String>,
    /// Entries that will not parse, and so are doing nothing.
    pub problems: Vec<String>,
    /// Entries that parse but widen access a great deal.
    pub risky: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantView {
    pub id: String,
    pub project_id: String,
    pub host_path: String,
    pub container_path: String,
    pub slug: String,
    pub access: Access,
    pub label: String,
    pub purpose: String,
    pub source: String,
    pub created_at_ms: i64,
    pub exists: bool,
}

impl From<&Grant> for GrantView {
    fn from(grant: &Grant) -> Self {
        Self {
            id: grant.id.clone(),
            project_id: grant.project_id.clone(),
            host_path: grant.host_path.clone(),
            container_path: grant.container_path.clone(),
            slug: grant.slug.clone(),
            access: grant.access,
            label: grant.label.clone(),
            purpose: grant.purpose.clone(),
            source: match grant.source {
                GrantSource::User => "you added it".to_string(),
                GrantSource::Request => "DeepCode asked".to_string(),
                GrantSource::AllowedRoot => "pre-declared root".to_string(),
            },
            created_at_ms: grant.created_at_ms,
            exists: std::path::Path::new(&grant.host_path).is_dir(),
        }
    }
}

/// What the operator chose in the dialog.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionPayload {
    pub request_id: String,
    /// "allow" or "deny"
    pub decision: String,
    #[serde(default)]
    pub message: String,
    /// The path the operator selected. Required for a locate request, and
    /// overrides whatever the sandbox claimed for a directory request.
    #[serde(default)]
    pub host_path: Option<String>,
    /// Patterns the operator approved, which may be narrower than what was asked
    /// for. Absent means "as requested".
    #[serde(default)]
    pub patterns: Option<Vec<String>>,
    /// Tool ids the operator approved, which may be fewer than what was asked for.
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    #[serde(default)]
    pub access: Option<String>,
    /// Restart the sandbox immediately so the new mount takes effect.
    #[serde(default)]
    pub restart: Option<bool>,
}

/* ------------------------------------------------------------------------- */
/* Live session bookkeeping                                                   */
/* ------------------------------------------------------------------------- */

pub struct LiveSession {
    pub session: Session,
    pub container_name: String,
    pub network_mode: String,
    pub warnings: Vec<String>,
    pub command_line: String,
}

/// Controls a project's broker thread.
pub struct BrokerControl {
    pub stop: Arc<AtomicBool>,
    pub seen: Arc<Mutex<HashSet<String>>>,
}

pub struct AppState {
    pub store: Mutex<Store>,
    pub docker: Mutex<Option<Docker>>,
    pub sessions: Mutex<HashMap<String, LiveSession>>,
    /// request id -> the pending request, mirrored for the frontend.
    pub pending: Mutex<HashMap<String, PermissionRequest>>,
    pub pending_order: Mutex<Vec<String>>,
    pub brokers: Mutex<HashMap<String, BrokerControl>>,
    pub proxies: Mutex<HashMap<String, Arc<EgressProxy>>>,
    /// Running HTTP servers, keyed by server id, so the UI can report what is
    /// listening and stop it again.
    pub remote_servers: Mutex<HashMap<String, crate::remote_server::RunningServer>>,
    /// Projects with a start already in flight.
    ///
    /// Starting is not atomic -- the session is only registered once the container is
    /// up -- so without this two overlapping starts would both proceed and the second
    /// would fail on the container name.
    pub starting: Mutex<std::collections::HashSet<String>>,
    /// The image id whose seccomp profile has already been checked against the profile
    /// being applied, with the digest that was found.
    ///
    /// Reading the digest out of an image means starting a throwaway container, so it is
    /// done once per image build rather than once per sandbox start. It is keyed by image
    /// id, which changes on every rebuild, so a rebuilt or re-tagged image is re-checked.
    pub verified_seccomp: Mutex<Option<(String, String)>>,
    /// One producer (the session callbacks) and two consumers (the desktop event
    /// channel and any remote SSE subscriber), so the two views cannot drift.
    pub remote_events: tokio::sync::broadcast::Sender<crate::remote_server::RemoteEvent>,
    pub startup_error: Mutex<Option<String>>,
}

/// Released on drop, so a start that returns early or panics does not leave the
/// project locked out.
pub struct StartGuard<'a> {
    state: &'a AppState,
    project_id: String,
}

impl Drop for StartGuard<'_> {
    fn drop(&mut self) {
        self.state
            .starting
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.project_id);
    }
}

impl AppState {
    pub fn new(store: Store, startup_error: Option<String>) -> Self {
        Self {
            store: Mutex::new(store),
            docker: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            pending_order: Mutex::new(Vec::new()),
            brokers: Mutex::new(HashMap::new()),
            proxies: Mutex::new(HashMap::new()),
            remote_servers: Mutex::new(HashMap::new()),
            starting: Mutex::new(std::collections::HashSet::new()),
            verified_seccomp: Mutex::new(None),
            // Sized for a burst of terminal output; a slow subscriber lags and is
            // told so rather than blocking the sandbox's output path.
            remote_events: tokio::sync::broadcast::channel(2048).0,
            startup_error: Mutex::new(startup_error),
        }
    }

    /// Locate the Docker CLI once and reuse it.
    pub fn docker(&self) -> deepsand_core::Result<Docker> {
        if let Some(docker) = self.docker.lock().unwrap().clone() {
            return Ok(docker);
        }
        let docker = Docker::locate()?;
        *self.docker.lock().unwrap() = Some(docker.clone());
        Ok(docker)
    }

    /// Take the start lock for a project, or `None` if a start is already running.
    ///
    /// The returned guard releases it on drop, so an early return or a panic cannot
    /// leave a project permanently unstartable.
    pub fn begin_start(&self, project_id: &str) -> Option<StartGuard<'_>> {
        {
            let mut set = self.starting.lock().unwrap_or_else(|p| p.into_inner());
            if !set.insert(project_id.to_string()) {
                return None;
            }
        }
        Some(StartGuard {
            state: self,
            project_id: project_id.to_string(),
        })
    }

    /// Container names a live session owns, which is what "not an orphan" means.
    pub fn live_container_names(&self) -> Vec<String> {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|live| live.container_name.clone())
            .collect()
    }

    pub fn is_running(&self, project_id: &str) -> bool {
        self.sessions.lock().unwrap().contains_key(project_id)
    }

    pub fn broker(&self, project_id: &str) -> Broker {
        let store = self.store.lock().unwrap();
        Broker::new(store.data_dir(), project_id)
    }

    /// Register a request in the pending set. Returns false if it was already
    /// known, so the UI is never asked twice about the same thing.
    pub fn register_request(&self, request: PermissionRequest) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if pending.contains_key(&request.id) {
            return false;
        }
        self.pending_order.lock().unwrap().push(request.id.clone());
        pending.insert(request.id.clone(), request);
        true
    }

    pub fn resolve_request(&self, request_id: &str) -> Option<PermissionRequest> {
        let removed = self.pending.lock().unwrap().remove(request_id);
        if removed.is_some() {
            self.pending_order.lock().unwrap().retain(|id| id != request_id);
        }
        removed
    }

    /// Pending requests in arrival order.
    pub fn pending_requests(&self) -> Vec<PermissionRequest> {
        let order = self.pending_order.lock().unwrap().clone();
        let pending = self.pending.lock().unwrap();
        order.iter().filter_map(|id| pending.get(id).cloned()).collect()
    }

    /// Forget requests whose files have disappeared, so a stale dialog cannot
    /// be answered after the sandbox has moved on.
    pub fn reconcile_pending(&self, project_id: &str, open_ids: &[String]) {
        let stale: Vec<String> = {
            let pending = self.pending.lock().unwrap();
            pending
                .iter()
                .filter(|(_, request)| request.project == project_id && !open_ids.contains(&request.id))
                .map(|(id, _)| id.clone())
                .collect()
        };
        for id in stale {
            self.resolve_request(&id);
        }
    }

    pub fn stop_broker(&self, project_id: &str) {
        if let Some(control) = self.brokers.lock().unwrap().remove(project_id) {
            control.stop.store(true, Ordering::Relaxed);
        }
        // Anything still pending for that project is gone with the container.
        let ids: Vec<String> = self
            .pending_requests()
            .into_iter()
            .filter(|r| r.project == project_id)
            .map(|r| r.id)
            .collect();
        for id in ids {
            self.resolve_request(&id);
        }
    }

    pub fn rejected_for(&self, project_id: &str) -> (Vec<PermissionRequest>, Vec<RejectedRequest>) {
        self.broker(project_id).scan_detailed()
    }
}
