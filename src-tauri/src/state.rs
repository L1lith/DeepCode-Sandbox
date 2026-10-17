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
    /// Emitted while a launch waits for an image build, with the image, and cleared with a
    /// null.
    ///
    /// Deliberately not `BUILD_LOG`: that one opens the progress bar and only `BUILD_DONE`
    /// closes it, so a notice sent that way left the bar open with nothing left to close it.
    /// This one is paired -- set when the wait begins, cleared when it ends, whatever the
    /// outcome -- so the window can treat it as a state rather than as a message.
    pub const BUILD_WAIT: &str = "build://wait";
    /// Tools finished building and were copied into a sandbox that had started without them.
    pub const TOOLS_ARRIVED: &str = "build://tools-arrived";
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
    /// Whether this project starts itself when Deepsand starts.
    pub resume_on_launch: bool,
    /// Where this project's standing instructions come from. The window shows it as a three-way
    /// control; what the model is actually told is decided once, in the core, by
    /// `settings::resolve_user_prompt`.
    pub user_prompt_mode: UserPromptMode,
    /// This project's own instructions, shown when the mode is `Custom`. Sent to nobody while the
    /// mode is something else, but kept so switching back finds it where it was left.
    pub user_prompt: String,
    /// Whether the sandbox may ask for permissions at all. Surfaced so the Permissions
    /// tab can show and change it, and so a request dialog can offer to turn it off.
    pub requests_enabled: bool,
    /// Derived, for the sidebar and header.
    pub container_name: String,
    pub running: bool,
    /// Whether this process has this project's sandbox frozen, which it does while a permission
    /// dialog is open so the agent cannot work ahead of the decision. From memory rather than
    /// from Docker: this is on the path of every project list, and an inspect per project there
    /// would cost more than the whole rest of the list.
    pub paused: bool,
    pub workspace_exists: bool,
    pub grant_count: usize,
    pub pending_requests: usize,
}

impl ProjectView {
    pub fn new(
        project: &Project,
        running: bool,
        paused: bool,
        grant_count: usize,
        pending_requests: usize,
    ) -> Self {
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
            resume_on_launch: project.resume_on_launch,
            user_prompt_mode: project.user_prompt_mode,
            user_prompt: project.user_prompt.clone(),
            notes: project.notes.clone(),
            requests_enabled: project.requests_enabled,
            container_name: project.container_name(),
            running,
            paused,
            workspace_exists: std::path::Path::new(&project.root_dir).is_dir(),
            grant_count,
            pending_requests,
        }
    }
}

/// How much disk the selected project's folder occupies.
///
/// Separate from [`ProjectView`] on purpose: measuring a large folder walks it, and the project
/// list is read on every refresh. This is asked for once per selection, off the UI thread.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectDiskUsage {
    pub project_id: String,
    /// Total bytes of the regular files under the project folder.
    pub bytes: u64,
    /// False when some entry could not be read; `bytes` is then a lower bound.
    pub complete: bool,
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
    /// The secret a request named, so the dialog can prefill the fields the operator
    /// confirms or replaces. Both are claims by the sandbox.
    pub secret_name: Option<String>,
    pub secret_value: Option<String>,
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
    /// Whether this binary was built for development rather than release.
    ///
    /// From the backend rather than the frontend, because the two can disagree and the backend is
    /// the one that knows: a release build runs against the same window, and a debug build
    /// (`app:build:debug`) is a local build even though it is served as built assets rather than by
    /// the dev server. The window shows it beside the version, so a bug reported from a screenshot
    /// says which kind of build produced it.
    pub dev: bool,
    pub data_dir: String,
    /// `None` until the window has asked (`docker_status`). Probing here would put three
    /// Docker CLI calls in front of the first paint, and nothing the first paint draws needs
    /// an answer to them.
    pub docker: Option<DockerStatus>,
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
    /// False when the operator has switched this secret off: still stored, not in the
    /// sandbox environment.
    pub enabled: bool,
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
    /// What switching this on costs, when that is worth knowing before it is switched on: the
    /// browser adds most of a gigabyte to the image and a couple of minutes to the build, and a
    /// switch sitting next to a one-line description does not say so.
    pub cost_note: Option<String>,
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

/// What came of attaching files the operator pasted or dropped into the terminal.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    /// Paths to type into the terminal, in the order they arrived. Inside the sandbox: what the
    /// agent and the CLI can actually read.
    pub paths: Vec<String>,
    /// What could not be attached, each with its reason, to be shown rather than thrown:
    /// attaching three files and losing all three because the fourth was a directory is worse
    /// than attaching three and saying why not the fourth.
    pub problems: Vec<String>,
}

/// A project's model setting, as the header's dropdown needs it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelView {
    pub project_id: String,
    /// The project's own model, or `None` when it defers to configuration.
    pub value: Option<String>,
    /// True when nothing is overriding the configured model.
    pub deferring: bool,
    /// What configuration resolves to right now, shown beside "Defer to Config" so the
    /// operator can see what deferring to it means today.
    pub configured: String,
    /// What the configured API offers. Empty until it has been asked, or when it cannot be
    /// reached -- in which case `problem` says why, because a dropdown that is simply missing
    /// its list looks like a bug in the app rather than a problem with the API.
    pub options: Vec<deepsand_core::models::ModelChoice>,
    pub problem: Option<String>,
    pub applied_live: bool,
    pub restart_needed: bool,
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
    /// What the operator settled on for a secret request. Either may be empty: the
    /// sandbox's own suggestion is used when the operator changed nothing, and a name
    /// with no value is refused with an explanation rather than stored empty.
    #[serde(default)]
    pub secret_name: Option<String>,
    #[serde(default)]
    pub secret_value: Option<String>,
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
    /// The same handle the waiter thread holds. It is what lets an exit be matched to *this*
    /// session rather than to whichever session the project has by the time the waiter runs.
    pub life: Arc<SessionLife>,
    /// When this PTY was created. An exit soon after it is a crash, not a session that did
    /// some work and then finished, and the restart budget treats the two differently.
    pub started_at: std::time::Instant,
}

/// The part of a session that outlives its PTY.
///
/// Two facts, both written by one side and read by the other:
///
/// * `expected` is set by `stop_session_internal` *before* the PTY is killed, so a deliberate
///   stop is never mistaken for a crash and restarted.
/// * `exited` is set by the waiter thread, so a process that was already gone before its
///   session could be registered is not announced as running.
#[derive(Default)]
pub struct SessionLife {
    pub exited: AtomicBool,
    pub expected: AtomicBool,
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
    /// Sandboxes that started before their tools existed, by the image being built for them.
    ///
    /// Keyed by image rather than by project because that is what the build knows when it
    /// finishes: one build can have several projects waiting on it, and the queue is drained
    /// when that build succeeds.
    pub tools_arriving: Mutex<HashMap<String, Vec<String>>>,
    /// Images currently being built. Two builds of one image share one build log and one
    /// tag, and a second writer behind a first writer's file offset is how a log acquires a
    /// gap of NULs: whatever the second one writes lands where the first one had got to.
    pub building: Mutex<std::collections::HashSet<String>>,
    /// request id -> the pending request, mirrored for the frontend.
    pub pending: Mutex<HashMap<String, PermissionRequest>>,
    pub pending_order: Mutex<Vec<String>>,
    pub brokers: Mutex<HashMap<String, BrokerControl>>,
    pub proxies: Mutex<HashMap<String, Arc<EgressProxy>>>,
    /// Projects whose sandbox this process has frozen.
    ///
    /// Only ever the answer Docker gave, never the intent: a pause that failed (a container that
    /// is not running cannot be frozen) must not make the window say the sandbox is held when it
    /// is not. `start_broker` freezes on a request that reaches the dialog and thaws when there
    /// is nothing left to decide; `stop_session_internal` clears it, so a stopped project is
    /// never remembered as frozen.
    pub frozen: Mutex<std::collections::HashSet<String>>,
    /// Running HTTP servers, keyed by server id, so the UI can report what is
    /// listening and stop it again.
    pub remote_servers: Mutex<HashMap<String, crate::remote_server::RunningServer>>,
    /// Projects with a start already in flight.
    ///
    /// Starting is not atomic -- the session is only registered once the container is
    /// up -- so without this two overlapping starts would both proceed and the second
    /// would fail on the container name.
    pub starting: Mutex<std::collections::HashSet<String>>,
    /// Whether the last container-start attempt found the daemon reachable but its container
    /// runtime not answering. `docker version` can succeed while `docker run` hangs, and this
    /// is how the status strip can say so without running a container on every poll.
    pub runtime_wedged: std::sync::atomic::AtomicBool,
    /// The last model list read from the configured API, with the base URL and key it was
    /// read with.
    ///
    /// Kept because the header asks on every project switch and the answer changes only when
    /// the credentials do; the key is digested rather than stored, because the point of the
    /// cache is to avoid repeating a request, not to keep a second copy of a secret around.
    pub models: Mutex<Option<(String, Vec<deepsand_core::models::ModelChoice>)>>,
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
    /// A counter per project, bumped by every deliberate stop or replacement.
    ///
    /// A scheduled automatic restart remembers the value it was planned under and abandons
    /// itself if it changed. A Stop that arrives while the restart is waiting is an answer,
    /// and an automatic restart that overrode it would be the machine doing what the operator
    /// just said not to.
    pub stop_epochs: Mutex<HashMap<String, u64>>,
    /// A counter per project, bumped by every start attempt.
    ///
    /// A Run that is waiting for a tools build uses it to notice that a newer start -- the
    /// "Start now without tools" button, or another Run -- has taken over, and returns
    /// without starting a container. Without it the first Run would start a sandbox seconds
    /// after the operator had asked for a different one.
    pub start_epochs: Mutex<HashMap<String, u64>>,
    /// Consecutive unexpected exits from sessions that did not last long enough to count as
    /// healthy. Bounds a crash loop: a sandbox that cannot stay up must not be rebuilt for ever.
    pub early_exits: Mutex<HashMap<String, u32>>,
    /// Set once shutdown has begun. A scheduled restart checks this before starting a container.
    pub shutting_down: AtomicBool,
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
            tools_arriving: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            pending_order: Mutex::new(Vec::new()),
            brokers: Mutex::new(HashMap::new()),
            proxies: Mutex::new(HashMap::new()),
            remote_servers: Mutex::new(HashMap::new()),
            starting: Mutex::new(std::collections::HashSet::new()),
            frozen: Mutex::new(std::collections::HashSet::new()),
        runtime_wedged: std::sync::atomic::AtomicBool::new(false),
            building: Mutex::new(std::collections::HashSet::new()),
            verified_seccomp: Mutex::new(None),
            models: Mutex::new(None),
            // Sized for a burst of terminal output; a slow subscriber lags and is
            // told so rather than blocking the sandbox's output path.
            remote_events: tokio::sync::broadcast::channel(2048).0,
            startup_error: Mutex::new(startup_error),
            stop_epochs: Mutex::new(HashMap::new()),
            start_epochs: Mutex::new(HashMap::new()),
            early_exits: Mutex::new(HashMap::new()),
            shutting_down: AtomicBool::new(false),
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

    /// Whether this process has the project's sandbox frozen.
    pub fn is_frozen(&self, project_id: &str) -> bool {
        self.frozen.lock().unwrap_or_else(|p| p.into_inner()).contains(project_id)
    }

    /// Record that the project's sandbox is frozen now.
    pub fn mark_frozen(&self, project_id: &str) {
        self.frozen.lock().unwrap_or_else(|p| p.into_inner()).insert(project_id.to_string());
    }

    /// Forget that the project's sandbox is frozen, returning whether it was.
    pub fn clear_frozen(&self, project_id: &str) -> bool {
        self.frozen.lock().unwrap_or_else(|p| p.into_inner()).remove(project_id)
    }

    pub fn is_running(&self, project_id: &str) -> bool {
        self.sessions.lock().unwrap().contains_key(project_id)
    }

    /// Remove a session only if it is the one whose PTY just closed.
    ///
    /// An exit callback runs on the waiter thread, which can wake up long after a Stop, a
    /// restart, or another start has replaced this session. Matching the per-session
    /// [`SessionLife`] is what keeps a stale waiter from tearing down its successor.
    pub fn take_session_if_current(
        &self,
        project_id: &str,
        life: &Arc<SessionLife>,
    ) -> Option<LiveSession> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        match sessions.get(project_id) {
            Some(live) if Arc::ptr_eq(&live.life, life) => sessions.remove(project_id),
            _ => None,
        }
    }

    /// The deliberate-stop clock for a project; see [`AppState::stop_epochs`].
    pub fn stop_epoch(&self, project_id: &str) -> u64 {
        self.stop_epochs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(project_id)
            .copied()
            .unwrap_or(0)
    }

    /// Record that the project was stopped or replaced on purpose.
    pub fn bump_stop_epoch(&self, project_id: &str) {
        let mut epochs = self.stop_epochs.lock().unwrap_or_else(|p| p.into_inner());
        let epoch = epochs.entry(project_id.to_string()).or_insert(0);
        *epoch = epoch.wrapping_add(1);
    }

    /// The start clock for a project; see [`AppState::start_epochs`].
    pub fn start_epoch(&self, project_id: &str) -> u64 {
        self.start_epochs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(project_id)
            .copied()
            .unwrap_or(0)
    }

    /// Record a new start attempt and return the value that attempt owns.
    pub fn bump_start_epoch(&self, project_id: &str) -> u64 {
        let mut epochs = self.start_epochs.lock().unwrap_or_else(|p| p.into_inner());
        let epoch = epochs.entry(project_id.to_string()).or_insert(0);
        *epoch = epoch.wrapping_add(1);
        *epoch
    }

    /// Count an unexpected exit, unless the session lasted long enough to be healthy.
    ///
    /// Returns the number of consecutive early exits, which is what bounds the restart loop.
    pub fn note_early_exit(&self, project_id: &str, healthy: bool) -> u32 {
        let mut counts = self.early_exits.lock().unwrap_or_else(|p| p.into_inner());
        if healthy {
            counts.remove(project_id);
            return 0;
        }
        let count = counts.entry(project_id.to_string()).or_insert(0);
        *count = count.saturating_add(1);
        *count
    }

    /// An explicit start wipes the crash-loop verdict: the operator asked for this one.
    pub fn clear_early_exits(&self, project_id: &str) {
        self.early_exits
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(project_id);
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
