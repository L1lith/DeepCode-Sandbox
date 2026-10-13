//! The Tauri command surface.
//!
//! Every command is a thin adapter: it takes webview input, calls into
//! `deepsand-core` (which owns all the rules), and returns serialisable data or
//! emits an event. If a behaviour matters for containment it lives in the core,
//! not here — that is what makes `deepsandctl` and the GUI provably equivalent.

use crate::state::*;
use deepsand_core::allowlist;
use deepsand_core::broker::Broker;
use deepsand_core::credentials::{self, ResolvedCredentials};
use deepsand_core::docker::Docker;
use deepsand_core::model::*;
use deepsand_core::paths;
use deepsand_core::policy::{self, MountKind, PlanInput, RunPlan};
use deepsand_core::proxy::{EgressProxy, ProxyConfig};
use deepsand_core::session::{Session, SessionOptions};
use deepsand_core::settings as container_settings;
use deepsand_core::store::Store;
use deepsand_core::now_ms;
use base64::Engine as _;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};

type CmdResult<T> = Result<T, String>;

fn fail(err: impl std::fmt::Display) -> String {
    err.to_string()
}

/// Accepts either a Tauri `State<AppState>` (what a command receives) or a plain
/// `&AppState` (what the remote HTTP layer can supply). Without this the shared
/// helpers would have to be duplicated for the two callers.
trait AsAppState {
    fn app_state(&self) -> &AppState;
}

impl AsAppState for AppState {
    fn app_state(&self) -> &AppState {
        self
    }
}

impl AsAppState for State<'_, AppState> {
    fn app_state(&self) -> &AppState {
        self.inner()
    }
}

// Inside a `*_impl` body the parameter is already `&AppState`, but the code there
// was written against a `State`, so it passes `&state`. Rather than rewrite every
// such call site, accept the extra reference too.
impl AsAppState for &AppState {
    fn app_state(&self) -> &AppState {
        self
    }
}

fn store<'a>(state: &'a impl AsAppState) -> std::sync::MutexGuard<'a, Store> {
    state.app_state().store.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/* ------------------------------------------------------------------------- */
/* Application info                                                          */
/* ------------------------------------------------------------------------- */

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> CmdResult<AppInfo> {
    app_info_impl(&state)
}

pub fn app_info_impl(state: &AppState) -> CmdResult<AppInfo> {

    let store = store(&state);
    let settings = store.settings().clone();
    let data_dir = store.data_dir().to_path_buf();
    drop(store);

    let docker = match state.docker() {
        Ok(docker) => docker.probe(&settings.image),
        Err(err) => DockerStatus {
            available: false,
            detail: err.to_string(),
            ..DockerStatus::default()
        },
    };

    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        data_dir: data_dir.display().to_string(),
        docker,
        host_config: credentials::describe_host_config(&credentials::read_host_config()),
        settings,
    })
}

#[tauri::command]
pub fn docker_status(state: State<'_, AppState>) -> CmdResult<DockerStatus> {
    docker_status_impl(&state)
}

pub fn docker_status_impl(state: &AppState) -> CmdResult<DockerStatus> {

    let image = store(&state).settings().image.clone();
    Ok(match state.docker() {
        Ok(docker) => docker.probe(&image),
        Err(err) => DockerStatus {
            available: false,
            detail: err.to_string(),
            ..DockerStatus::default()
        },
    })
}

/* ------------------------------------------------------------------------- */
/* Projects                                                                  */
/* ------------------------------------------------------------------------- */

fn project_view(state: &impl AsAppState, project: &Project) -> ProjectView {
    let running = state.app_state().is_running(&project.id);
    let store = store(state);
    let grant_count = store.active_grants(&project.id).len();
    drop(store);
    let pending = state
        .app_state()
        .pending_requests()
        .into_iter()
        .filter(|request| request.project == project.id)
        .count();
    ProjectView::new(project, running, grant_count, pending)
}

#[tauri::command]
pub fn list_projects(state: State<'_, AppState>) -> CmdResult<Vec<ProjectView>> {
    list_projects_impl(&state)
}

pub fn list_projects_impl(state: &AppState) -> CmdResult<Vec<ProjectView>> {

    let projects: Vec<Project> = store(&state).projects().to_vec();
    Ok(projects.iter().map(|p| project_view(&state, p)).collect())
}

#[tauri::command]
pub fn get_project(state: State<'_, AppState>, project_id: String) -> CmdResult<ProjectView> {
    get_project_impl(&state, project_id)
}

pub fn get_project_impl(state: &AppState, project_id: String) -> CmdResult<ProjectView> {

    let project = store(&state).project(&project_id).cloned().map_err(fail)?;
    Ok(project_view(&state, &project))
}

#[tauri::command]
pub fn create_project(state: State<'_, AppState>, name: String, root_dir: String) -> CmdResult<ProjectView> {
    create_project_impl(&state, name, root_dir)
}

pub fn create_project_impl(state: &AppState, name: String, root_dir: String) -> CmdResult<ProjectView> {

    let mut store = store(&state);
    let project = store.create_project(&name, &root_dir).map_err(fail)?;
    drop(store);
    Ok(project_view(&state, &project))
}

#[tauri::command]
pub fn update_project_settings(state: State<'_, AppState>, project_id: String, network: Option<NetworkPolicy>, limits: Option<ResourceLimits>, deepcode_mode: Option<DeepCodeMode>, notes: Option<String>, credentials: Option<Credentials>) -> CmdResult<ProjectView> {
    update_project_settings_impl(&state, project_id, network, limits, deepcode_mode, notes, credentials)
}

pub fn update_project_settings_impl(state: &AppState, project_id: String, network: Option<NetworkPolicy>, limits: Option<ResourceLimits>, deepcode_mode: Option<DeepCodeMode>, notes: Option<String>, credentials: Option<Credentials>) -> CmdResult<ProjectView> {

    let mut store = store(&state);
    {
        let project = store.project_mut(&project_id).map_err(fail)?;
        if let Some(network) = network {
            project.network = network;
        }
        if let Some(limits) = limits {
            project.limits = limits;
        }
        if let Some(mode) = deepcode_mode {
            project.deepcode_mode = mode;
        }
        if let Some(notes) = notes {
            project.notes = notes;
        }
        if let Some(credentials) = credentials {
            project.credentials = credentials;
        }
    }
    store.save().map_err(fail)?;
    let project = store.project(&project_id).cloned().map_err(fail)?;
    drop(store);
    Ok(project_view(&state, &project))
}

#[tauri::command]
pub fn set_requests_enabled(
    app: AppHandle,
    state: State<'_, AppState>,
    project_id: String,
    enabled: bool,
) -> CmdResult<ProjectView> {
    set_requests_enabled_impl(&app, &state, project_id, enabled)
}

/// Turn permission requests on or off for one project.
///
/// Turning it off also answers every request that is already waiting, with the
/// explanation the model needs, because "stop asking me" that leaves a dialog on screen
/// has not done the thing the operator asked for. Turning it back on does not resurrect
/// them: the sandbox has already been told no, and asking again is the model's business.
///
/// The bridge checks the same flag before submitting, but that check is a courtesy — the
/// bridge is a child of the agent's own process. This is the control, and it refuses a
/// request the sandbox hand-wrote into the spool exactly like any other.
pub fn set_requests_enabled_impl(
    app: &AppHandle,
    state: &AppState,
    project_id: String,
    enabled: bool,
) -> CmdResult<ProjectView> {
    let message = deepsand_core::model::REQUESTS_DISABLED_MESSAGE;

    let (project, pending) = {
        let mut guard = state.store.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .project_mut(&project_id)
            .map_err(fail)?
            .requests_enabled = enabled;
        guard.save().map_err(fail)?;
        let project = guard.project(&project_id).cloned().map_err(fail)?;
        let pending: Vec<PermissionRequest> = state
            .pending_requests()
            .into_iter()
            .filter(|request| request.project == project_id)
            .collect();
        (project, pending)
    };

    // A running sandbox is told immediately, so an honest bridge stops submitting rather
    // than writing requests that would be refused the moment they arrived.
    let broker = state.broker(&project_id);
    let _ = broker.set_requests_enabled(enabled, message);

    if !enabled {
        for request in &pending {
            let _ = broker.answer(&PermissionResponse::deny(&request.id, message));
            broker.clear_request(&request.id);
            if let Ok(store) = state.store.lock() {
                store.append_audit(
                    &project_id,
                    &format!("DENY  {} (requests turned off)", request.description()),
                );
            }
            let _ = app.emit(
                events::BROKER_RESOLVED,
                serde_json::json!({
                    "requestId": request.id,
                    "decision": "deny",
                    "auto": true,
                    "reason": message,
                }),
            );
        }
    }

    let _ = app.emit(
        events::STATE_CHANGED,
        serde_json::json!({ "reason": "requests-enabled-changed" }),
    );
    Ok(project_view(state, &project))
}

#[tauri::command]
pub fn delete_project(state: State<'_, AppState>, project_id: String) -> CmdResult<()> {
    delete_project_impl(&state, project_id)
}

pub fn delete_project_impl(state: &AppState, project_id: String) -> CmdResult<()> {

    state.stop_session_internal(&project_id);
    let mut store = store(&state);
    store.delete_project(&project_id).map_err(fail)
}

#[tauri::command]
pub fn path_check(state: State<'_, AppState>, path: String) -> CmdResult<PathCheck> {
    path_check_impl(&state, path)
}

pub fn path_check_impl(state: &AppState, path: String) -> CmdResult<PathCheck> {

    let store = store(&state);
    let guards = store.guards().clone();
    drop(store);

    match paths::canonical_existing_dir(&path) {
        Ok(resolved) => match paths::reject_reason(&resolved, &guards) {
            Some(reason) => Ok(PathCheck {
                allowed: false,
                resolved: Some(resolved.display().to_string()),
                reason: Some(reason),
            }),
            None => Ok(PathCheck {
                allowed: true,
                resolved: Some(resolved.display().to_string()),
                reason: None,
            }),
        },
        Err(err) => Ok(PathCheck { allowed: false, resolved: None, reason: Some(err.to_string()) }),
    }
}

/* ------------------------------------------------------------------------- */
/* Grants                                                                    */
/* ------------------------------------------------------------------------- */

#[tauri::command]
pub fn list_grants(state: State<'_, AppState>, project_id: String) -> CmdResult<Vec<GrantView>> {
    list_grants_impl(&state, project_id)
}

pub fn list_grants_impl(state: &AppState, project_id: String) -> CmdResult<Vec<GrantView>> {

    let store = store(&state);
    Ok(store.active_grants(&project_id).iter().map(GrantView::from).collect())
}

#[tauri::command]
pub fn add_grant(state: State<'_, AppState>, project_id: String, host_path: String, access: Access, label: Option<String>, purpose: Option<String>) -> CmdResult<GrantView> {
    add_grant_impl(&state, project_id, host_path, access, label, purpose)
}

pub fn add_grant_impl(state: &AppState, project_id: String, host_path: String, access: Access, label: Option<String>, purpose: Option<String>) -> CmdResult<GrantView> {

    let mut store = store(&state);
    let grant = store
        .add_grant(
            &project_id,
            &host_path,
            access,
            label.as_deref().unwrap_or_default(),
            purpose.as_deref().unwrap_or_default(),
            GrantSource::User,
        )
        .map_err(fail)?;
    store.append_audit(
        &project_id,
        &format!("ALLOW {} {} -> {} (added by the operator)", grant.access.label(), grant.host_path, grant.container_path),
    );
    Ok(GrantView::from(&grant))
}

#[tauri::command]
pub fn set_grant_access(state: State<'_, AppState>, project_id: String, grant_id: String, access: Access) -> CmdResult<GrantView> {
    set_grant_access_impl(&state, project_id, grant_id, access)
}

pub fn set_grant_access_impl(state: &AppState, project_id: String, grant_id: String, access: Access) -> CmdResult<GrantView> {

    let mut store = store(&state);
    let grant = store.update_grant_access(&project_id, &grant_id, access).map_err(fail)?;
    store.append_audit(
        &project_id,
        &format!("CHANGE {} -> {} ({})", grant.host_path, grant.access.label(), grant.container_path),
    );
    Ok(GrantView::from(&grant))
}

#[tauri::command]
pub fn revoke_grant(state: State<'_, AppState>, project_id: String, grant_id: String) -> CmdResult<()> {
    revoke_grant_impl(&state, project_id, grant_id)
}

pub fn revoke_grant_impl(state: &AppState, project_id: String, grant_id: String) -> CmdResult<()> {

    let mut store = store(&state);
    let grant = store.revoke_grant(&project_id, &grant_id).map_err(fail)?;
    store.append_audit(
        &project_id,
        &format!("REVOKE {} (was {})", grant.host_path, grant.container_path),
    );
    Ok(())
}

#[tauri::command]
pub fn audit_log(state: State<'_, AppState>, project_id: String, limit: Option<usize>) -> CmdResult<Vec<String>> {
    audit_log_impl(&state, project_id, limit)
}

pub fn audit_log_impl(state: &AppState, project_id: String, limit: Option<usize>) -> CmdResult<Vec<String>> {

    let store = store(&state);
    Ok(store.read_audit(&project_id, limit.unwrap_or(200)))
}

/* ------------------------------------------------------------------------- */
/* Plan preview                                                              */
/* ------------------------------------------------------------------------- */

/// Build (and write) the sandbox configuration without starting anything.
/// Build the plan that will run.
///
/// `proxy` and `network_gateway` are passed in rather than derived here, because in
/// restricted mode the proxy has to be *started* before a plan can exist: `plan_run`
/// refuses to produce a restricted plan with no proxy, since a restricted sandbox
/// whose proxy is missing has no egress path at all. Passing them in also means the
/// plan is built once, with the proxy it will actually use.
/// The hosts a sandbox must always be able to reach, whatever its network mode:
/// the model endpoint from the resolved credentials.
///
/// Without this, `none` would mean "nothing at all including your model" and
/// default-deny restricted projects could not reach the API they exist to call.
fn model_hosts(project: &Project, app: &AppSettings) -> Vec<String> {
    let host = credentials::read_host_config();
    let resolved = credentials::resolve(project, app, &host);
    let mut hosts: Vec<String> = allowlist::host_from_url(&resolved.base_url).into_iter().collect();

    // Tool hosts are derived from the selection rather than stored, so switching a
    // tool off removes its domains in the same operation that removes the tool. The
    // search tool is the case that matters: turning it off has to close the API it
    // was reaching, not leave it open from an earlier session.
    hosts.extend(deepsand_core::tools::hosts_for(project.tools.as_deref()));
    hosts.sort();
    hosts.dedup();
    hosts
}

/// One project's secrets, or `None` when the store cannot be opened.
///
/// A missing keystore is not fatal here: the project simply gets no secrets, which is
/// the same outcome as having none. The UI is where the operator is told why.
fn open_secrets(state: &impl AsAppState, project_id: &str) -> Option<deepsand_core::secrets::Secrets> {
    let data_dir = store(state).data_dir().to_path_buf();
    match deepsand_core::secrets::Secrets::open(&data_dir, project_id) {
        Ok(secrets) => Some(secrets),
        Err(err) => {
            tracing::warn!("secrets unavailable for project {project_id}: {err}");
            None
        }
    }
}

/// The model API's addresses, resolved on the host.
///
/// A thin wrapper over the core helper, kept because the call site reads better with the
/// reason attached: a sandbox in `none` or `restricted` mode cannot resolve the name
/// itself, and the client does not use the proxy, so its addresses have to be allowed
/// explicitly.
fn model_endpoints(base_url: &str) -> Vec<String> {
    deepsand_core::allowlist::endpoints_for_url(base_url)
}

fn prepare_plan(
    state: &impl AsAppState,
    project_id: &str,
    resume: bool,
    assume_daemon: bool,
    proxy: Option<&deepsand_core::policy::ProxyEndpoint>,
    network_gateway: Option<String>,
    required_hosts: &[String],
) -> CmdResult<(RunPlan, ResolvedCredentials, Vec<String>)> {
    let (project, grants, app_settings, data_dir, guards) = {
        let store = store(state);
        store.ensure_project_dirs(project_id).map_err(fail)?;
        (
            {
                // Merge here so the plan, the snapshot and the proxy all agree.
                let project = store.project(project_id).cloned().map_err(fail)?;
                let app = store.settings().clone();
                with_effective_allowlist(&project, &app)
            },
            store.active_grants(project_id),
            store.settings().clone(),
            store.data_dir().to_path_buf(),
            store.guards().clone(),
        )
    };

    let daemon = match state.app_state().docker() {
        Ok(docker) => docker.probe(&app_settings.image),
        Err(err) => DockerStatus {
            available: false,
            detail: err.to_string(),
            ..DockerStatus::default()
        },
    };

    let broker = Broker::new(&data_dir, project_id);
    broker.ensure().map_err(fail)?;

    let host = credentials::read_host_config();
    let resolved = credentials::resolve(&project, &app_settings, &host);

    let mut sandbox = container_settings::build_sandbox_snapshot(
        &project,
        &grants,
        &project.network,
        broker.open_request_ids(),
        resolved.warnings.clone(),
    );

    // The snapshot describes the *image*, not the settings that asked for it. Those can
    // have changed since the image was built -- and an older image may predate the label
    // entirely -- so the label is authoritative and its absence is reported rather than
    // papered over with the configured list.
    let image = with_runtime_revision(deepsand_core::tools::image_for(
        &app_settings.image,
        project.tools.as_deref(),
    ));
    sandbox.image = image.clone();
    let label = state
        .app_state()
        .docker()
        .ok()
        .and_then(|docker| docker.image_label(&image, "deepsand.tools"));
    match label {
        Some(label) => {
            sandbox.tools = label
                .split(',')
                .map(|tool| tool.trim().to_string())
                .filter(|tool| !tool.is_empty())
                .collect();
        }
        None => {
            sandbox.notes.push(
                "The tool list above is what this project is configured to want. The image \
                 itself could not be inspected, so it is not known whether it matches -- run \
                 the sandbox and check with `command -v`, rather than trusting the list."
                    .to_string(),
            );
        }
    }
    sandbox.notes.push(
        "The model API key is readable from inside this sandbox, in the DeepCode settings \
         it authenticates with. That is not a boundary this sandbox can hold: the process \
         you control is the process that talks to the model. Treat the key as visible to \
         anything running here."
            .to_string(),
    );
    let grants_snapshot = container_settings::build_grants_snapshot(&project, &grants);
    let settings_json =
        container_settings::build_deepcode_settings(&project, &grants, &resolved, 45_000);

    let project_dir = broker.dirs().state.parent().map(PathBuf::from);
    let config_dir = project_dir
        .as_ref()
        .map(|p| p.join("config"))
        .unwrap_or_else(|| data_dir.join("projects").join(project_id).join("config"));
    let state_dir = broker.dirs().state.clone();

    // Written fresh on every plan, so a deleted secret cannot linger in a file the
    // next container would still be handed.
    let endpoints = model_endpoints(&resolved.base_url);

    let secrets_env_file = open_secrets(state, project_id)
        .and_then(|secrets| secrets.write_env_file(&config_dir).ok().flatten());

    container_settings::write_project_config(
        &config_dir,
        &state_dir,
        &settings_json,
        &container_settings::build_agents_md(&project, &grants, &project.network, &resolved),
        &sandbox,
        &grants_snapshot,
    )
    .map_err(fail)?;

    let mut warnings: Vec<String> = Vec::new();
    let daemon_reachable = daemon.available;
    let docker_status = if assume_daemon && !daemon.available {
        warnings.push(
            "the Docker daemon is not reachable, so this is a preview only. Start Docker Desktop to run it."
                .to_string(),
        );
        DockerStatus { available: true, ..daemon.clone() }
    } else {
        daemon
    };

    let seccomp = seccomp_profile_path(&app_settings);
    if matches!(app_settings.security.seccomp, SeccompProfile::Hardened) && seccomp.is_none() {
        warnings.push(
            "the hardened seccomp profile was requested but runtime/seccomp-hardened.json could not be found."
                .to_string(),
        );
    }

    // The daemon applies the host's copy of the profile, so the copy inside the image is
    // only ever read by an auditor. Refuse to start when the two disagree: a sandbox whose
    // hardening cannot be attributed to the image it is running is a sandbox nobody can
    // audit, and this is exactly the drift R3-A of the escape assessment found.
    if let Some(profile) = seccomp.as_deref() {
        if daemon_reachable {
            verify_seccomp_profile(state.app_state(), &app_settings.image, profile)
                .map_err(|err| fail(err))?;
        }
    }

    let plan = policy::plan_run(&PlanInput {
        project: &project,
        grants: &grants,
        app: &app_settings,
        docker_status: &docker_status,
        data_dir: &data_dir,
        guards: &guards,
        seccomp_host_path: seccomp.as_deref(),
        proxy,
        network_gateway,
        required_hosts,
        secrets_env_file: secrets_env_file.as_deref(),
        model_endpoints: &endpoints,
        mcp_wait_ms: 45_000,
        resume,
    })
    .map_err(fail)?;

    Ok((plan, resolved, warnings))
}

fn seccomp_profile_path(settings: &AppSettings) -> Option<PathBuf> {
    // One resolver for the runtime tree, shared with the image builder and the headless CLI.
    // This used to be a second search order that looked beside the executable rather than in
    // its `runtime/` subdirectory, which is one of the ways the applied profile and the
    // shipped profile could come from different trees -- R3-A of the escape assessment.
    deepsand_core::seccomp::profile_path(matches!(
        settings.security.seccomp,
        SeccompProfile::Hardened
    ))
}

/// Compare the seccomp profile about to be applied with the digest the image carries.
///
/// The daemon resolves `--security-opt=seccomp=` on the host, so the file inside the image
/// is only ever read by someone auditing it. Nothing compared the two until R3-A of the
/// escape assessment measured a container where the applied profile had the socket-family
/// rules and the shipped profile had none.
///
/// The digest file is cached per image id: reading it means starting a throwaway container,
/// so it happens once per image build rather than once per start. The host profile is
/// re-hashed on every call, because that is cheap and it is the half that can change.
fn verify_seccomp_profile(
    state: &AppState,
    image: &str,
    profile: &Path,
) -> deepsand_core::Result<String> {
    let docker = state.docker()?;
    let Some(image_id) = docker.image_id(image) else {
        // No image yet, so there is nothing to compare against. `start_session` builds the
        // image before it plans, so this is only reachable from an explicit preview.
        return Ok(String::new());
    };

    let cached = state
        .verified_seccomp
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();

    let digest_file = match cached {
        Some((verified_id, raw)) if verified_id == image_id => raw,
        _ => {
            let raw =
                docker.read_file_from_image(image, deepsand_core::seccomp::IMAGE_DIGEST_PATH)?;
            *state
                .verified_seccomp
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = Some((image_id, raw.clone()));
            raw
        }
    };

    deepsand_core::seccomp::verify(profile, &digest_file)
}

#[tauri::command]
pub fn preview_plan(state: State<'_, AppState>, project_id: String) -> CmdResult<PlanPreview> {
    preview_plan_impl(&state, project_id)
}

pub fn preview_plan_impl(state: &AppState, project_id: String) -> CmdResult<PlanPreview> {

    let required_hosts = {
        let store = store(&state);
        let project = store.project(&project_id).cloned().map_err(fail)?;
        let app = store.settings().clone();
        model_hosts(&project, &app)
    };

    // A running project already has its proxy, and the run path *reuses* that instance
    // rather than starting another, so a preview built with it is the command that will
    // actually run -- same address, same port.
    //
    // Before it is running the address does not exist yet: the port is whatever the kernel
    // hands back when the proxy binds, which is why a plan for a proxied mode is refused
    // rather than shown with an invented port. The refusal used to be a dead end, because
    // this lookup did not happen even after the project was started.
    let live_endpoint = state
        .proxies
        .lock()
        .unwrap()
        .get(&project_id)
        .map(|proxy| proxy.endpoint(PROXY_HOSTNAME));
    let live_gateway = live_endpoint.as_ref().map(|_| PROXY_HOSTNAME.to_string());

    let (plan, resolved, warnings) = prepare_plan(
        &state,
        &project_id,
        false,
        true,
        live_endpoint.as_ref(),
        live_gateway,
        &required_hosts,
    )
    .map_err(|err| {
        // The generic message names an internal component and tells the operator to
        // start the project, which is only useful once they can. Say what is true and
        // what to do about it.
        if err.contains("egress proxy") {
            "This project is in allowlisted network mode and its egress proxy is not running, \
             so the command does not exist yet: the proxy's port is assigned when it starts, \
             and the command has to name it. Start the project once, then ask again -- the \
             proxy it is using will be the one the plan names."
                .to_string()
        } else {
            err
        }
    })?;
    // The command carries `--last` only when the operator starts a *resumable* session, and
    // that is their choice at the button rather than a property of the project, so a preview
    // can only be exact for one of the two. Say which one this is when the other is
    // possible, rather than letting a warning-free preview imply there is only one command.
    let can_resume = state
        .docker()
        .ok()
        .and_then(|docker| gather_launch(&state, &project_id).ok().map(|launch| (docker, launch)))
        .is_some_and(|(docker, launch)| docker.volume_has_session_index(&launch.volume, &launch.image));

    let mut warnings: Vec<String> = warnings.into_iter().chain(plan.warnings.clone()).collect();
    if can_resume {
        warnings.insert(
            0,
            "This project has a session that can be resumed, and Resuming adds `--last` to the \
             command below. This is the command for a fresh start."
                .to_string(),
        );
    }

    Ok(PlanPreview {
        text: plan.describe(),
        warnings,
        mount_count: plan.mounts.len(),
        network_mode: plan.network_mode.clone(),
        image: plan.image.clone(),
        container_name: plan.container_name.clone(),
        credential_provenance: resolved.provenance.clone(),
        api_key_present: resolved.api_key.is_some(),
    })
}

/* ------------------------------------------------------------------------- */
/* Sessions                                                                  */
/* ------------------------------------------------------------------------- */

#[tauri::command]
pub fn session_status(state: State<'_, AppState>, project_id: String) -> CmdResult<SessionStatus> {
    session_status_impl(&state, project_id)
}

pub fn session_status_impl(state: &AppState, project_id: String) -> CmdResult<SessionStatus> {

    let project = store(&state).project(&project_id).cloned().map_err(fail)?;
    let sessions = state.sessions.lock().unwrap();
    Ok(match sessions.get(&project_id) {
        Some(live) => SessionStatus {
            project_id: project_id.clone(),
            running: true,
            command_line: Some(live.command_line.clone()),
            container_name: live.container_name.clone(),
            network_mode: live.network_mode.clone(),
            warnings: live.warnings.clone(),
        },
        None => SessionStatus {
            project_id: project_id.clone(),
            running: false,
            command_line: None,
            container_name: project.container_name(),
            network_mode: project.network.mode_str().to_string(),
            warnings: Vec::new(),
        },
    })
}

/// Everything needed to start a session, gathered without holding a lock.
struct Launch {
    project: Project,
    container_name: String,
    volume: String,
    image: String,
    root_dir: PathBuf,
}

fn gather_launch(state: &impl AsAppState, project_id: &str) -> CmdResult<Launch> {
    let store = store(state);
    let project = store.project(project_id).cloned().map_err(fail)?;
    let app_settings = store.settings().clone();
    // Per-project image, because the tools are baked in and two projects may want
    // different ones.
let image = with_runtime_revision(deepsand_core::tools::image_for(
        &app_settings.image,
        project.tools.as_deref(),
    ));
    // The launch record feeds the proxy, so its allowlist has to be the merged one.
    let project = with_effective_allowlist(&project, &app_settings);
    Ok(Launch {
        container_name: project.container_name(),
        volume: project.state_volume(),
        root_dir: PathBuf::from(&project.root_dir),
        project,
        image,
    })
}

#[tauri::command]
pub async fn start_session(app: AppHandle, state: State<'_, AppState>, project_id: String, resume: Option<bool>) -> CmdResult<SessionStatus> {
    start_session_impl(&app, &state, project_id, resume).await
}

pub async fn start_session_impl(app: &AppHandle, state: &AppState, project_id: String, resume: Option<bool>) -> CmdResult<SessionStatus> {

    // Serialise starts. Two overlapping ones would each stop the other's half-built
    // container and then both run, and the second would fail on the container name.
    let Some(_start_guard) = state.begin_start(&project_id) else {
        return Err(
            "this project is already starting. Give the sandbox a moment to come up before starting it \
             again."
                .to_string(),
        );
    };

    // A session may already be live; stop it first so start is idempotent.
    state.stop_session_internal(&project_id);

    let launch = gather_launch(&state, &project_id)?;

    let docker = state.docker().map_err(fail)?;
    docker
        .volume_create(&launch.volume)
        .map_err(|err| format!("could not create the session volume: {err}"))?;

    // The first Run for a tool selection has no image yet. Build it here rather than
    // refusing: "run this project" plainly means "make it runnable", and the operator
    // should not have to discover a separate build button first.
    if !docker.image_present(&launch.image) {
        // `spawn_blocking`, because a build takes minutes and `start_session` is async:
        // blocking a runtime worker for that long would stall unrelated commands.
        let handle = app.clone();
        let for_build = project_id.clone();
        let image = launch.image.clone();
        let _ = app.emit(
            events::BUILD_LOG,
            serde_json::json!({ "line": format!("Building {image} for the first time. This happens once per tool selection.") }),
        );
        let built = tauri::async_runtime::spawn_blocking(move || {
            let state = tauri::Manager::state::<AppState>(&handle);
            build_runtime_image_impl(&handle, &state, Some(for_build), None)
        })
        .await;
        match built {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                let _ = app.emit(
                    events::BUILD_DONE,
                    serde_json::json!({ "ok": false, "detail": err.clone() }),
                );
                return Err(format!(
                    "the runtime image for this project could not be built, so the sandbox cannot start: {err}"
                ));
            }
            Err(err) => {
                return Err(format!("the image build could not be completed: {err}"));
            }
        }
        let _ = app.emit(events::BUILD_DONE, serde_json::json!({ "ok": true, "detail": "" }));
    }

    let wants_resume = resume.unwrap_or(true);
    let can_resume = wants_resume && docker.volume_has_session_index(&launch.volume, &launch.image);

    // Restricted egress: the allowlisting proxy has to exist BEFORE the plan is
    // built, because a restricted plan without a proxy is refused outright. This is
    // the order the code needs; getting it backwards means restricted mode can never
    // start at all.
    let mut restricted_proxy: Option<(deepsand_core::policy::ProxyEndpoint, String)> = None;
    let required_hosts = {
        let store = store(&state);
        let app = store.settings().clone();
        model_hosts(&launch.project, &app)
    };

    // `none` and `restricted` both run behind the proxy. `none` reaches the model
    // endpoint and nothing else; `restricted` adds whatever the project allows.
    if launch.project.network.uses_proxy() {
        let mut allow: Vec<String> = if launch.project.network.honours_allowlist() {
            launch.project.network.allowlist().to_vec()
        } else {
            Vec::new()
        };
        allow.extend(required_hosts.iter().cloned());
        // The per-project network is still created, because it keeps projects on
        // separate bridges. It is no longer where the proxy listens.
        let network = launch.project.network_name();
        {
            let docker = docker.clone();
            let network = network.clone();
            tauri::async_runtime::spawn_blocking(move || docker.network_ensure(&network))
                .await
                .map_err(|err| err.to_string())?
                .map_err(fail)?;
        }

        // Bind to the *host* loopback, not the project network's bridge gateway.
        //
        // On a native Linux daemon the bridge gateway (172.x.0.1) is an address on
        // the host, so binding there works. On Docker Desktop that bridge is inside
        // the Linux VM and the host has no interface on it, so the bind fails with
        // WSAEADDRNOTAVAIL (10049) and restricted mode cannot start at all.
        //
        // Loopback is an address the host really owns, and the container reaches it
        // through `host.docker.internal`, which Docker Desktop forwards to the host.
        // The port is ephemeral (the proxy binds :0) and is passed to the sandbox in
        // DEEPSAND_PROXY_ADDR, so there is no port to reserve.
        let bind: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        // An already-running proxy is reused rather than replaced, so starting a
        // stopped session does not break a proxy another client is using.
        let existing = state.proxies.lock().unwrap().get(&project_id).cloned();
        let proxy = match existing {
            Some(proxy) => {
                proxy.set_allowlist(allow.clone()).await;
                proxy
            }
            None => {
                let started = EgressProxy::start(ProxyConfig {
                    bind,
                    allow: allow.clone(),
                    ..ProxyConfig::default()
                })
                .await
                .map_err(fail)?;
                let started = Arc::new(started);
                state
                    .proxies
                    .lock()
                    .unwrap()
                    .insert(project_id.clone(), Arc::clone(&started));
                started
            }
        };
        restricted_proxy = Some((
            proxy.endpoint(PROXY_HOSTNAME),
            PROXY_HOSTNAME.to_string(),
        ));
    }

    let (plan, resolved, mut warnings) = prepare_plan(
        &state,
        &project_id,
        can_resume,
        false,
        restricted_proxy.as_ref().map(|(endpoint, _)| endpoint),
        restricted_proxy.as_ref().map(|(_, gateway)| gateway.clone()),
        &required_hosts,
    )?;

    // Preflight: can the container actually read the host directories it is
    // about to mount?
    //
    // Docker Desktop must register every host path it is asked to bind-mount, and
    // when that registration is missing or its IPC call times out the mount does
    // NOT fail -- the directory appears inside the container but every entry in it
    // appears as a zero-length directory. DeepCode would then start against an
    // apparently empty workspace, with no credentials and no sandbox description,
    // and nothing would say why. Refusing here, with the explanation, is far
    // kinder than starting a sandbox that silently cannot work.
    for mount in plan.mounts.iter().filter(|m| {
        !m.volume
            && (m.kind.must_be_read_only()
                || matches!(m.kind, MountKind::Workspace | MountKind::Grant))
    }) {
        let dir = std::path::PathBuf::from(&mount.source);
        let check = docker.check_host_sharing(&dir, &plan.image);
        if !check.ok {
            return Err(format!(
                "The {:?} directory {} cannot be read by a container.\n\n{}",
                mount.kind,
                dir.display(),
                check.detail
            ));
        }
    }

    if resolved.api_key.is_none() {
        return Err(
            "no API key is configured for this project, so the sandboxed DeepCode would refuse to start. Add one \
             in Settings, or configure ~/.deepcode/settings.json."
                .to_string(),
        );
    }

    let command_line = format!(
        "{} {}",
        docker.program().display(),
        plan.args.join(" ")
    );

    // A container can outlive the app that created it: `--rm` fires when the
    // container exits, so one left running by a killed Deepsand holds this name
    // forever. Freeing it here is the difference between "Run" working and an error
    // the operator can do nothing about.
    if let Some(previous) = docker.reclaim_container_name(&launch.container_name) {
        warnings.push(format!(
            "cleared a sandbox container left over from a previous run of this project ({previous})"
        ));
    }

    let session = start_container(&app, &project_id, &docker, &launch, plan.args.clone(), warnings.clone())?;

    state.sessions.lock().unwrap().insert(
        project_id.clone(),
        LiveSession {
            session,
            container_name: launch.container_name.clone(),
            network_mode: launch.project.network.mode_str().to_string(),
            warnings: warnings.clone(),
            command_line: command_line.clone(),
        },
    );

    start_broker(app, state, &project_id);

    let _ = app.emit(
        events::SESSION_STATUS,
        serde_json::json!({ "projectId": project_id, "status": "running" }),
    );

    Ok(SessionStatus {
        project_id,
        running: true,
        command_line: Some(command_line),
        container_name: launch.container_name,
        network_mode: launch.project.network.mode_str().to_string(),
        warnings,
    })
}

/// Turn Docker's container-name conflict into something the operator can act on.
///
/// It should now be unreachable -- the name is reclaimed before every run -- so if it
/// appears it means something outside Deepsand created a container with this name, and
/// saying so is more useful than repeating Docker's own message.
fn explain_run_failure(container_name: &str, message: String) -> String {
    if message.contains("is already in use by container") {
        return format!(
            "a container named '{container_name}' already exists and could not be cleared. Run \
             `docker rm -f {container_name}` in a terminal, then try again. This usually means another \
             Deepsand window is using the same project.\n\n{message}"
        );
    }
    message
}

/// Start the container.
///
/// Deliberately does nothing after spawning. An earlier version polled for the
/// container before returning, to catch a name conflict reactively; that starved the
/// terminal handshake -- `docker run -t` waits for the terminal to answer `ESC[6n`,
/// xterm.js supplies that answer, and the frontend only starts pumping once this
/// command has returned -- so the container was never created at all and the start took
/// seventeen seconds. The pre-flight reclaim below is what clears a taken name, and it
/// runs before anything the terminal needs.
fn start_container(
    app: &AppHandle,
    project_id: &str,
    docker: &Docker,
    launch: &Launch,
    args: Vec<String>,
    warnings: Vec<String>,
) -> CmdResult<Session> {
    spawn_session(app, project_id, docker, launch, args, warnings)
        .map_err(|err| explain_run_failure(&launch.container_name, err))
}

/// Docker's wording for "that name is in use". Matched on the fragment rather than the
/// whole sentence, which varies with the Docker version.
///
/// Only reached when the *spawn* fails, which a name conflict does not do -- see
/// `start_container`. Kept because it costs nothing and covers a Docker that behaves
/// differently from the one this was written against.
#[allow(dead_code)]
fn is_name_conflict(message: &str) -> bool {
    message.contains("is already in use by container")
}

fn spawn_session(
    app: &AppHandle,
    project_id: &str,
    docker: &Docker,
    launch: &Launch,
    args: Vec<String>,
    warnings: Vec<String>,
) -> CmdResult<Session> {
    let _ = warnings;
    let output_app = app.clone();
    let output_project = project_id.to_string();
    let exit_app = app.clone();
    let exit_project = project_id.to_string();

    // One producer, two consumers: the desktop webview listens on Tauri's event
    // channel, and any remote SSE subscriber reads the broadcast channel. Both get
    // the identical payload from this one place, so the two views cannot drift.
    let event_tx = { tauri::Manager::state::<AppState>(app).remote_events.clone() };

    // Redaction happens here, at the one point session output leaves the host, so it
    // covers the desktop terminal and any remote subscriber identically.
    //
    // It works per chunk. A PTY read can split arbitrarily, so a secret straddling a
    // chunk boundary could in principle slip through; the values are also fixed at
    // session start, so a secret added mid-session is not covered until the next
    // start. Both are stated rather than papered over.
    let secrets = {
        let state = tauri::Manager::state::<AppState>(app);
        open_secrets(&state, project_id).map(|store| store.values())
    };
    let redact = move |chunk: &[u8]| -> Vec<u8> {
        let Some(values) = secrets.as_ref() else {
            return chunk.to_vec();
        };
        if values.is_empty() {
            return chunk.to_vec();
        }
        let text = String::from_utf8_lossy(chunk);
        let mut redacted = text.to_string();
        let mut hit = false;
        for value in values {
            if redacted.contains(value.as_str()) {
                redacted = redacted.replace(value.as_str(), "[redacted]");
                hit = true;
            }
        }
        if hit {
            redacted.into_bytes()
        } else {
            // Untouched when nothing matched, so the byte stream stays exact and a
            // TUI is unaffected in the common case.
            chunk.to_vec()
        }
    };
    let output_tx = event_tx.clone();
    let exit_tx = event_tx;

    Session::spawn(
        SessionOptions {
            program: docker.program().to_path_buf(),
            args,
            cwd: launch.root_dir.clone(),
            env: vec![],
            rows: 40,
            cols: 120,
        },
        move |chunk| {
            // Base64 because a PTY read can split a UTF-8 sequence; decoding on
            // the far side into a Uint8Array keeps the TUI byte-exact.
            let data =
                base64::engine::general_purpose::STANDARD.encode(redact(chunk));
            let payload = serde_json::json!({ "projectId": output_project, "data": data });
            let _ = output_app.emit(events::TERMINAL_OUTPUT, payload.clone());
            let _ = output_tx.send(crate::remote_server::RemoteEvent {
                event: events::TERMINAL_OUTPUT.to_string(),
                payload,
            });
        },
        move |code| {
            let payload = serde_json::json!({ "projectId": exit_project, "code": code });
            let _ = exit_app.emit(events::TERMINAL_EXIT, payload.clone());
            let _ = exit_tx.send(crate::remote_server::RemoteEvent {
                event: events::TERMINAL_EXIT.to_string(),
                payload,
            });
        },
    )
    .map_err(fail)
}

impl AppState {
    /// Stop a session without going through the webview. Also idempotent.
    pub fn stop_session_internal(&self, project_id: &str) {
        if let Some(mut live) = self.sessions.lock().unwrap().remove(project_id) {
            live.session.kill();
        }
        self.stop_broker(project_id);
        if let Some(proxy) = self.proxies.lock().unwrap().remove(project_id) {
            proxy.shutdown();
        }
        if let Ok(docker) = self.docker() {
            // `--rm` usually handles this, but a container killed mid-flight can
            // survive; removing by name guarantees the next start is clean.
            let name = self
                .store
                .lock()
                .ok()
                .and_then(|store| store.project(project_id).ok().map(|p| p.container_name()));
            if let Some(name) = name {
                docker.remove_container(&name);
            }
        }
    }
}

#[tauri::command]
pub fn stop_session(app: AppHandle, state: State<'_, AppState>, project_id: String) -> CmdResult<()> {
    stop_session_impl(&app, &state, project_id)
}

pub fn stop_session_impl(app: &AppHandle, state: &AppState, project_id: String) -> CmdResult<()> {

    state.stop_session_internal(&project_id);
    let _ = app.emit(
        events::SESSION_STATUS,
        serde_json::json!({ "projectId": project_id, "status": "stopped" }),
    );
    Ok(())
}

#[tauri::command]
pub async fn restart_session(app: AppHandle, state: State<'_, AppState>, project_id: String) -> CmdResult<SessionStatus> {
    restart_session_impl(&app, &state, project_id).await
}

pub async fn restart_session_impl(app: &AppHandle, state: &AppState, project_id: String) -> CmdResult<SessionStatus> {

    state.stop_session_internal(&project_id);
    start_session_impl(app, state, project_id, Some(true)).await
}

#[tauri::command]
pub fn write_to_session(state: State<'_, AppState>, project_id: String, data: String) -> CmdResult<()> {
    write_to_session_impl(&state, project_id, data)
}

pub fn write_to_session_impl(state: &AppState, project_id: String, data: String) -> CmdResult<()> {

    let mut sessions = state.sessions.lock().unwrap();
    let live = sessions.get_mut(&project_id).ok_or_else(|| {
        format!("no sandbox is running for {project_id}")
    })?;
    live.session.send(data.as_bytes()).map_err(fail)
}

#[tauri::command]
pub fn resize_session(state: State<'_, AppState>, project_id: String, rows: u16, cols: u16) -> CmdResult<()> {
    resize_session_impl(&state, project_id, rows, cols)
}

pub fn resize_session_impl(state: &AppState, project_id: String, rows: u16, cols: u16) -> CmdResult<()> {

    let sessions = state.sessions.lock().unwrap();
    match sessions.get(&project_id) {
        Some(live) => live.session.resize(rows, cols).map_err(fail),
        // Not an error: the frontend may lay out before the container starts.
        None => Ok(()),
    }
}

/* ------------------------------------------------------------------------- */
/* Permission broker                                                         */
/* ------------------------------------------------------------------------- */

/// Why this request never needs the operator, or `None` if it does.
///
/// Two things are answered here rather than shown:
///
/// * The project has had asking turned off. This is the real control for that setting —
///   the bridge checks it too, but the bridge is a child of the agent's own process, so a
///   request written straight into the spool has to be refused here as well.
/// * The sandbox already has what it is asking for, judged against the snapshot it was
///   itself given. Judging against the *snapshot* rather than against the store's idea of
///   the mounts is the point: the question is what the sandbox can see.
///
/// The `&'static str` is the audit tag, so the two cases are distinguishable in a log
/// without parsing the message.
fn auto_refusal(
    app: &AppHandle,
    project_id: &str,
    request: &PermissionRequest,
) -> Option<(String, &'static str)> {
    let (project, grants) = {
        let state = app.state::<AppState>();
        let store = state.store.lock().ok()?;
        (store.project(project_id).ok()?.clone(), store.grants(project_id))
    };

    if !project.requests_enabled {
        return Some((
            deepsand_core::model::REQUESTS_DISABLED_MESSAGE.to_string(),
            "requests are turned off",
        ));
    }

    let snapshot = container_settings::build_sandbox_snapshot(
        &project,
        &grants,
        &project.network,
        Vec::new(),
        Vec::new(),
    );
    deepsand_core::covered::already_covered(request, Path::new(&project.root_dir), &snapshot)
        .map(|covered| (covered.message, "already covered"))
}

fn request_view(state: &impl AsAppState, request: &PermissionRequest) -> PermissionRequestView {
    let project_name = store(state)
        .project(&request.project)
        .map(|p| p.name.clone())
        .unwrap_or_else(|_| "(unknown project)".to_string());

    let claimed_path = request.claimed_host_path().map(str::to_string);

    // Pre-flight the claimed path so the dialog can explain a refusal up front
    // instead of letting the operator approve something that will be rejected.
    let claimed_path_rejection = claimed_path.as_ref().and_then(|path| {
        let store_guard = store(state);
        let guards = store_guard.guards().clone();
        drop(store_guard);
        match paths::canonical_existing_dir(path) {
            Ok(resolved) => paths::reject_reason(&resolved, &guards),
            Err(err) => Some(err.to_string()),
        }
    });

    let title = match request.kind {
        RequestKind::DirectoryAccess => format!(
            "DeepCode is trying to access {}",
            claimed_path.clone().unwrap_or_else(|| request.description())
        ),
        RequestKind::LocateResource => format!(
            "DeepCode is requesting access to {}",
            request.description()
        ),
        RequestKind::NetworkAccess => format!(
            "DeepCode is asking to reach {}",
            request.description()
        ),
        RequestKind::ToolInstall => format!(
            "DeepCode is asking for a tool: {}",
            request.description()
        ),
    };

    PermissionRequestView {
        id: request.id.clone(),
        project_id: request.project.clone(),
        project_name,
        kind: request.kind.as_str().to_string(),
        title,
        description: request.description(),
        purpose: request.purpose(),
        requested_access: match request.requested_access() {
            Access::ReadOnly => "read".into(),
            Access::ReadWrite => "write".into(),
        },
        requested_kind: request.requested_kind().to_string(),
        has_claimed_path: claimed_path.is_some(),
        claimed_path,
        claimed_path_rejection,
        received_at: request.created_at.clone(),
        surfaced_at_ms: now_ms(),
        provenance: "Requested by the sandbox. Everything here -- the path, the wording, \
                     the purpose -- was written by the contained process, and the spool it \
                     writes to is forgeable by anything running inside it. Deepsand has \
                     checked the shape and re-checked the path; it cannot check that the \
                     reason is honest."
            .to_string(),
    }
}

#[tauri::command]
pub fn list_pending_requests(state: State<'_, AppState>) -> CmdResult<Vec<PermissionRequestView>> {
    list_pending_requests_impl(&state)
}

pub fn list_pending_requests_impl(state: &AppState) -> CmdResult<Vec<PermissionRequestView>> {

    Ok(state
        .pending_requests()
        .iter()
        .map(|request| request_view(&state, request))
        .collect())
}

#[tauri::command]
pub fn answer_request(app: AppHandle, state: State<'_, AppState>, payload: DecisionPayload) -> CmdResult<bool> {
    answer_request_impl(&app, &state, payload)
}

pub fn answer_request_impl(app: &AppHandle, state: &AppState, payload: DecisionPayload) -> CmdResult<bool> {

    let request_id = payload.request_id.clone();
    let request = state
        .resolve_request(&request_id)
        .ok_or_else(|| format!("request {request_id} is no longer waiting for a decision"))?;

    let broker = state.broker(&request.project);
    let allow = payload.decision.eq_ignore_ascii_case("allow");
    let access = match payload.access.as_deref() {
        Some("write") => Access::ReadWrite,
        Some("read") => Access::ReadOnly,
        _ => request.requested_access(),
    };
    let operator_path = payload
        .host_path
        .clone()
        .filter(|p| !p.trim().is_empty())
        .or_else(|| request.claimed_host_path().map(str::to_string));

    // Named `guard`, not `store`, so it never shadows the `store()` helper.
    let mut guard = state.store.lock().unwrap_or_else(|p| p.into_inner());

    if !allow {
        broker
            .answer(&PermissionResponse::deny(&request_id, payload.message.clone()))
            .map_err(fail)?;
        broker.clear_request(&request_id);
        guard.append_audit(
            &request.project,
            &format!(
                "DENY  {} ({})",
                request.description(),
                if payload.message.is_empty() { "no reason given" } else { &payload.message }
            ),
        );
        drop(guard);
        let _ = app.emit(
            events::BROKER_RESOLVED,
            serde_json::json!({ "requestId": request_id, "decision": "deny" }),
        );
        return Ok(false);
    }

    // Network and tool requests change what the project can reach, not what it can
    // see, so they are answered before a directory is required. Both are refused with
    // a reason rather than applied blindly, so the operator is told why nothing
    // happened instead of being left guessing.
    match request.kind {
        RequestKind::NetworkAccess => {
            let patterns = payload
                .patterns
                .clone()
                .filter(|list| !list.is_empty())
                .unwrap_or_else(|| request.requested_patterns());

            // The same engine that enforces the list validates it, so an entry that
            // could never match is refused here rather than stored as a dead rule the
            // operator believes is in force.
            let validation = allowlist::validate(&patterns);
            let in_allowlisted_mode =
                matches!(guard.project(&request.project).map(|p| &p.network), Ok(NetworkPolicy::Allowlisted { .. }));

            let refusal = if !validation.is_acceptable() {
                Some(validation.problems.join("; "))
            } else if !in_allowlisted_mode {
                // Refused rather than acted on: the only way an entry could take
                // effect is by switching the project's whole network mode, which
                // would restrict everything else as a side effect of approving one
                // host. That is the operator's decision to make deliberately.
                Some(format!(
                    "This project is not in allowlisted network mode, so an allowlist entry would have no \
                     effect. Switch the project to 'Allowlisted' first. Asked for: {}",
                    patterns.join(", ")
                ))
            } else {
                None
            };

            if let Some(message) = refusal {
                broker
                    .answer(&PermissionResponse::deny(&request_id, &message))
                    .map_err(fail)?;
                broker.clear_request(&request_id);
                guard.append_audit(
                    &request.project,
                    &format!("DENY  network {} ({message})", patterns.join(", ")),
                );
                drop(guard);
                let _ = app.emit(
                    events::BROKER_RESOLVED,
                    serde_json::json!({ "requestId": request_id, "decision": "deny" }),
                );
                return Ok(false);
            }

            {
                let project = guard.project_mut(&request.project).map_err(fail)?;
                let mut entries = match &project.network {
                    NetworkPolicy::Allowlisted { allow } => allow.clone(),
                    _ => Vec::new(),
                };
                entries.extend(patterns.iter().cloned());
                entries.sort();
                entries.dedup();
                project.network = NetworkPolicy::Allowlisted { allow: entries };
            }
            guard.save().map_err(fail)?;
            guard.append_audit(
                &request.project,
                &format!("ALLOW network {}", patterns.join(", ")),
            );
            drop(guard);

            broker
                .answer(&PermissionResponse::allow(
                    &request_id,
                    format!(
                        "Approved. These destinations are now reachable for this project: {}.                          Retry the command that was blocked; it does not need a restart.",
                        patterns.join(", ")
                    ),
                    None,
                    false,
                ))
                .map_err(fail)?;
            broker.clear_request(&request_id);

            // Push the new list into the live proxy so the agent's next attempt
            // succeeds without a restart.
            {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state = tauri::Manager::state::<AppState>(&handle);
                    refresh_proxies(&state).await;
                });
            }

            let _ = app.emit(
                events::BROKER_RESOLVED,
                serde_json::json!({ "requestId": request_id, "decision": "allow" }),
            );
            return Ok(true);
        }

        RequestKind::ToolInstall => {
            let requested = payload
                .tools
                .clone()
                .filter(|list| !list.is_empty())
                .unwrap_or_else(|| request.requested_tools());

            // Refuse anything unknown or impossible, with the catalogue's own reason,
            // rather than storing an id the build would silently drop.
            let mut refusal = None;
            for id in &requested {
                match deepsand_core::tools::find(id) {
                    None => {
                        refusal = Some(format!("'{id}' is not a tool Deepsand knows about."));
                        break;
                    }
                    Some(tool) => {
                        if let Some(reason) = deepsand_core::tools::unavailable_reason(tool) {
                            refusal = Some(reason);
                            break;
                        }
                    }
                }
            }

            if let Some(message) = refusal {
                broker
                    .answer(&PermissionResponse::deny(&request_id, &message))
                    .map_err(fail)?;
                broker.clear_request(&request_id);
                guard.append_audit(
                    &request.project,
                    &format!("DENY  tool {} ({message})", requested.join(", ")),
                );
                drop(guard);
                let _ = app.emit(
                    events::BROKER_RESOLVED,
                    serde_json::json!({ "requestId": request_id, "decision": "deny" }),
                );
                return Ok(false);
            }

            let applied = {
                let project = guard.project_mut(&request.project).map_err(fail)?;
                let mut ids: Vec<String> =
                    deepsand_core::tools::resolve(project.tools.as_deref())
                        .iter()
                        .map(|tool| tool.id.to_string())
                        .collect();
                ids.extend(requested.iter().cloned());
                ids.sort();
                ids.dedup();
                project.tools = Some(ids.clone());
                ids
            };
            guard.save().map_err(fail)?;
            guard.append_audit(
                &request.project,
                &format!(
                    "ALLOW tool {} (image rebuild needed before it is installed)",
                    requested.join(", ")
                ),
            );
            drop(guard);

            broker
                .answer(&PermissionResponse::allow(
                    &request_id,
                    format!(
                        "Approved: {}. The tool is added to this project, but it is baked into the                          container image, so it will not be on PATH until the image has been rebuilt                          and the sandbox restarted. Do not try to install it yourself in the meantime;                          it would not persist.",
                        applied.join(", ")
                    ),
                    None,
                    // Signals to the operator that a rebuild is outstanding.
                    true,
                ))
                .map_err(fail)?;
            broker.clear_request(&request_id);
            let _ = app.emit(
                events::BROKER_RESOLVED,
                serde_json::json!({ "requestId": request_id, "decision": "allow" }),
            );
            return Ok(true);
        }

        // Directory needs were already handled above.
        RequestKind::DirectoryAccess | RequestKind::LocateResource => {}
    }

    let Some(host_path) = operator_path else {
        let message = "no directory was chosen, so there was nothing to share";
        broker.answer(&PermissionResponse::deny(&request_id, message)).map_err(fail)?;
        broker.clear_request(&request_id);
        guard.append_audit(&request.project, &format!("DENY  {} ({message})", request.description()));
        drop(guard);
        let _ = app.emit(
            events::BROKER_RESOLVED,
            serde_json::json!({ "requestId": request_id, "decision": "deny" }),
        );
        return Ok(false);
    };

    // Everything is re-validated here. The UI already checked it, but a grant
    // must never be able to enter the store that the guards would refuse.
    let grant_result = guard.add_grant(
        &request.project,
        &host_path,
        access,
        "",
        request.purpose().as_deref().unwrap_or_default(),
        GrantSource::Request,
    );
    drop(guard);

    match grant_result {
        Ok(grant) => {
            broker
                .answer(&PermissionResponse::allow(
                    &request_id,
                    payload.message.clone(),
                    Some(GrantSpec {
                        host_path: grant.host_path.clone(),
                        container_path: grant.container_path.clone(),
                        access: grant.access,
                    }),
                    true,
                ))
                .map_err(fail)?;
            broker.clear_request(&request_id);
            store(&state).append_audit(
                &request.project,
                &format!(
                    "ALLOW {} {} -> {} ({})",
                    grant.access.label(),
                    grant.host_path,
                    grant.container_path,
                    request.description()
                ),
            );
            let _ = app.emit(
                events::BROKER_RESOLVED,
                serde_json::json!({
                    "requestId": request_id,
                    "decision": "allow",
                    "hostPath": grant.host_path,
                    "containerPath": grant.container_path,
                }),
            );

            // A new bind mount cannot be added to a live container, so the
            // sandbox is recreated and its session resumed. That happens on a
            // background task so the dialog closes immediately rather than
            // waiting out the hand-off grace period.
            let auto = {
                let guard = store(&state);
                guard.settings().auto_restart_on_grant
            };
            let wants_restart = payload.restart.unwrap_or(auto);
            if wants_restart && state.is_running(&request.project) {
                let restart_app = app.clone();
                let project_id = request.project.clone();
                tauri::async_runtime::spawn(restart_after_grant(restart_app, project_id));
            }
            let _ = app.emit(events::STATE_CHANGED, serde_json::json!({ "reason": "grant-added" }));
            Ok(true)
        }
        Err(err) => {
            let message = err.to_string();
            broker
                .answer(&PermissionResponse::deny(&request_id, &message))
                .map_err(fail)?;
            broker.clear_request(&request_id);
            store(&state).append_audit(
                &request.project,
                &format!("DENY  {} (refused by policy: {message})", request.description()),
            );
            let _ = app.emit(
                events::BROKER_RESOLVED,
                serde_json::json!({ "requestId": request_id, "decision": "deny", "reason": message }),
            );
            Err(message)
        }
    }
}

/// Replace a running sandbox so a newly approved mount takes effect.
///
/// Runs as its own task so the operator's dialog is not held open: the
/// in-container MCP bridge needs a moment to deliver the approval to the model
/// before the container it lives in disappears.
async fn restart_after_grant(app: AppHandle, project_id: String) {
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let state = app.state::<AppState>();
    state.stop_session_internal(&project_id);
    let _ = start_session(app.clone(), state, project_id, Some(true)).await;
}

/// Background thread that surfaces requests from a running sandbox.
fn start_broker(app: &AppHandle, state: &AppState, project_id: &str) {
    let stop = Arc::new(AtomicBool::new(false));
    let control = BrokerControl { stop: Arc::clone(&stop), seen: Arc::new(Mutex::new(Default::default())) };
    if state.brokers.lock().unwrap().insert(project_id.to_string(), control).is_some() {
        // An older thread is still winding down; the stop flag above is what
        // matters, and the new thread re-reads the spool from scratch.
    }

    let app = app.clone();
    let project_id = project_id.to_string();
    let data_dir = state.store.lock().unwrap().data_dir().to_path_buf();

    std::thread::Builder::new()
        .name(format!("deepsand-broker-{project_id}"))
        .spawn(move || {
            let broker = Broker::new(&data_dir, &project_id);
            if broker.ensure().is_err() {
                return;
            }
            let mut announced: HashMap<String, ()> = HashMap::new();
            while !stop.load(Ordering::Relaxed) {
                let (requests, rejected) = broker.scan_detailed();

                {
                    let state = app.state::<AppState>();
                    let open: Vec<String> = requests.iter().map(|r| r.id.clone()).collect();
                    state.reconcile_pending(&project_id, &open);

                    for bad in rejected {
                        let _ = app.emit(
                            events::BROKER_REJECTED,
                            serde_json::json!({
                                "projectId": project_id,
                                "file": bad.file,
                                "reason": bad.reason,
                            }),
                        );
                    }

                    for request in requests {
                        if announced.contains_key(&request.id) {
                            continue;
                        }
                        announced.insert(request.id.clone(), ());

                        // Asking for something the sandbox already has -- or asking at all,
                        // when the operator has turned requests off -- is answered here
                        // rather than shown: a prompt with nothing to decide trains the
                        // operator to approve without reading. The bar is "certain", so
                        // anything ambiguous still reaches them.
                        if let Some((message, reason)) = auto_refusal(&app, &project_id, &request)
                        {
                            let _ = broker.answer(&PermissionResponse::deny(&request.id, &message));
                            broker.clear_request(&request.id);
                            if let Ok(store) = app.state::<AppState>().store.lock() {
                                store.append_audit(
                                    &project_id,
                                    &format!(
                                        "DENY  {} ({reason}: {})",
                                        request.kind.as_str(),
                                        request.id
                                    ),
                                );
                            }
                            let _ = app.emit(
                                events::BROKER_RESOLVED,
                                serde_json::json!({
                                    "requestId": request.id,
                                    "decision": "deny",
                                    "auto": true,
                                    "reason": message,
                                }),
                            );
                            continue;
                        }

                        let view = request_view(&app.state::<AppState>(), &request);
                        app.state::<AppState>().register_request(request);
                        let _ = app.emit(events::BROKER_REQUEST, &view);
                    }
                }

                // The proxy's refusals are surfaced so the operator can allow a
                // host without having to read logs.
                let blocked = {
                    let state = app.state::<AppState>();
                    let proxies = state.proxies.lock().unwrap();
                    proxies.get(&project_id).map(|p| p.blocked())
                };
                if let Some(blocked) = blocked {
                    for entry in blocked {
                        let _ = app.emit(
                            events::EGRESS_BLOCKED,
                            serde_json::json!({
                                "host": entry.host,
                                "port": entry.port,
                                "atMs": entry.at_ms,
                                "reason": entry.reason,
                            }),
                        );
                    }
                    if let Some(proxy) = app.state::<AppState>().proxies.lock().unwrap().get(&project_id) {
                        proxy.clear_blocked();
                    }
                }

                std::thread::sleep(Duration::from_millis(400));
            }
        })
        .ok();
}

/* ------------------------------------------------------------------------- */
/* Settings and maintenance                                                  */
/* ------------------------------------------------------------------------- */

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> CmdResult<AppSettings> {
    get_settings_impl(&state)
}

pub fn get_settings_impl(state: &AppState) -> CmdResult<AppSettings> {

    Ok(store(&state).settings().clone())
}

#[tauri::command]
pub fn set_settings(state: State<'_, AppState>, settings: AppSettings) -> CmdResult<AppSettings> {
    set_settings_impl(&state, settings)
}

pub fn set_settings_impl(state: &AppState, settings: AppSettings) -> CmdResult<AppSettings> {

    let mut store = store(&state);
    *store.settings_mut() = settings;
    store.save().map_err(fail)?;
    Ok(store.settings().clone())
}

#[tauri::command]
pub async fn set_egress_allowlist(state: State<'_, AppState>, hosts: Vec<String>) -> CmdResult<Vec<String>> {
    set_egress_allowlist_impl(&state, hosts).await
}

pub async fn set_egress_allowlist_impl(state: &AppState, hosts: Vec<String>) -> CmdResult<Vec<String>> {

    let cleaned = accept_allowlist(&hosts)?;

    {
        let mut guard = state.store.lock().unwrap_or_else(|p| p.into_inner());
        guard.settings_mut().egress_allowlist = cleaned.clone();
        guard.save().map_err(fail)?;
    }

    refresh_proxies(&state).await;
    Ok(cleaned)
}

/// Re-push each running proxy's **effective** allowlist, so an operator can unblock
/// a host without restarting the sandbox.
///
/// This deliberately does not send the global list on its own. Doing that discards
/// every project's own entries from its live proxy, and a later restart brings them
/// back from the project record -- so the same host would work, then stop working,
/// then work again. Each proxy is given the union instead, which is also what it
/// was started with and what the next start will use.
async fn refresh_proxies(state: &impl AsAppState) {
    let running: Vec<(String, Arc<EgressProxy>)> = {
        let guard = state.app_state().proxies.lock().unwrap();
        guard
            .iter()
            .map(|(id, proxy)| (id.clone(), Arc::clone(proxy)))
            .collect()
    };
    if running.is_empty() {
        return;
    }

    let per_project: HashMap<String, Vec<String>> = {
        let store = store(state);
        let global = store.settings().egress_allowlist.clone();
        running
            .iter()
            .map(|(id, _)| {
                let project_entries = match store.project(id).map(|project| &project.network) {
                    Ok(NetworkPolicy::Allowlisted { allow }) => allow.clone(),
                    _ => Vec::new(),
                };
                let (merged, problems) = allowlist::effective(&global, &project_entries);
                for problem in &problems {
                    tracing::warn!("allowlist entry ignored for project {id}: {problem}");
                }
                (id.clone(), merged.to_entries())
            })
            .collect()
    };

    for (id, proxy) in running {
        if let Some(entries) = per_project.get(&id) {
            proxy.set_allowlist(entries.clone()).await;
        }
    }
}

/// A project whose restricted allowlist is the merged global + project list.
///
/// The merge happens here, once, so the plan, the sandbox snapshot the agent reads,
/// and the proxy env all agree on the same list. A project that is not in
/// restricted mode is returned untouched, since nothing consults its allowlist.
fn with_effective_allowlist(project: &Project, app: &AppSettings) -> Project {
    let mut effective = project.clone();
    if let NetworkPolicy::Allowlisted { allow } = &project.network {
        let (merged, problems) = allowlist::effective(&app.egress_allowlist, allow);
        for problem in &problems {
            tracing::warn!("allowlist entry ignored for project {}: {problem}", project.id);
        }
        effective.network = NetworkPolicy::Allowlisted {
            allow: merged.to_entries(),
        };
    }
    effective
}

/// Build the view a UI renders for one project's allowlist.
fn allowlist_view(project: &Project, global: &[String]) -> AllowlistView {
    let (project_entries, mode) = match &project.network {
        NetworkPolicy::Allowlisted { allow } => (allow.clone(), "allowlisted".to_string()),
        other => (Vec::new(), other.mode_str().to_string()),
    };
    let allowlisted = matches!(project.network, NetworkPolicy::Allowlisted { .. });

    let (merged, mut problems) = allowlist::effective(global, &project_entries);
    let effective = merged.to_entries();
    // Malformed entries were dropped by the lenient parse, so validation runs over
    // what survived -- which is what catches a blanket `*`.
    let validation = allowlist::validate(&effective);
    problems.extend(validation.problems);

    AllowlistView {
        project_id: project.id.clone(),
        mode,
        allowlisted,
        project: project_entries,
        global: global.to_vec(),
        effective,
        problems,
        risky: validation.risky,
    }
}

fn view_for(state: &impl AsAppState, project_id: &str) -> CmdResult<AllowlistView> {
    let store = store(state);
    let global = store.settings().egress_allowlist.clone();
    let project = store.project(project_id).map_err(fail)?;
    Ok(allowlist_view(project, &global))
}

/// The name a sandbox uses to reach the egress proxy running on the host.
///
/// Docker Desktop injects this automatically; the plan also maps it with
/// `--add-host`, so a native Linux daemon resolves it too.
const PROXY_HOSTNAME: &str = "host.docker.internal";

/* ------------------------------------------------------------------------- */
/* Remote access                                                             */
/* ------------------------------------------------------------------------- */

/// The whole remote access section, including which servers are actually up.
pub fn get_remote_access_impl(state: &AppState) -> CmdResult<RemoteAccessView> {
    Ok(remote_access_view(state))
}

fn remote_access_view(state: &AppState) -> RemoteAccessView {
    let settings = store(state).settings().remote.clone();
    let running = state.remote_servers.lock().unwrap_or_else(|p| p.into_inner());

    let servers = settings
        .servers
        .iter()
        .map(|server| {
            let live = running.get(&server.id);
            RemoteServerView {
                id: server.id.clone(),
                label: server.label.clone(),
                scope_kind: match &server.scope {
                    deepsand_core::remote::RemoteScope::App => "app".to_string(),
                    deepsand_core::remote::RemoteScope::Project(_) => "project".to_string(),
                },
                project_id: match &server.scope {
                    deepsand_core::remote::RemoteScope::App => None,
                    deepsand_core::remote::RemoteScope::Project(id) => Some(id.clone()),
                },
                bind: server.bind.clone(),
                port: server.port,
                tls: match server.tls {
                    deepsand_core::remote::RemoteTls::Off => "off".to_string(),
                    deepsand_core::remote::RemoteTls::SelfSigned => "selfSigned".to_string(),
                },
                capabilities: server.capabilities,
                token: server.token.clone(),
                redacted_token: server.redacted_token(),
                display_url: server.display_url(),
                loopback_only: server.is_loopback(),
                running: live.is_some(),
                bound_addr: live.map(|l| l.addr.to_string()),
            }
        })
        .collect();

    RemoteAccessView {
        enabled: settings.enabled,
        persist_across_restarts: settings.persist_across_restarts,
        lockout_after_failures: settings.lockout_after_failures,
        servers,
        ui_dir: crate::remote_server::ui_dir().map(|dir| dir.display().to_string()),
    }
}

/// Save the remote configuration and bring the running servers in line with it.
///
/// Reconciliation is by comparison, not by restarting everything: a server whose
/// configuration is unchanged keeps running, because restarting it would drop every
/// connected client. A server whose configuration changed can only take effect on a
/// new listener, so it is stopped and started again.
pub async fn set_remote_access_impl(
    app: &AppHandle,
    state: &AppState,
    settings: deepsand_core::remote::RemoteAccessSettings,
) -> CmdResult<RemoteAccessView> {
    if settings.enabled {
        // A port already in use should be reported now, not silently at the next
        // launch when nobody is looking.
        let mut seen: Vec<(String, u16)> = Vec::new();
        for server in &settings.servers {
            if server.tls != deepsand_core::remote::RemoteTls::Off {
                // Refuse rather than quietly serving plain HTTP when TLS was asked
                // for, which would be a silent downgrade of the only thing standing
                // between the network and the token.
                return Err(format!(
                    "'{}': self-signed TLS is not implemented yet. Run this server on loopback and \
                     let a reverse proxy terminate TLS.",
                    server.label
                ));
            }
            let key = (server.bind.clone(), server.port);
            if seen.contains(&key) {
                return Err(format!(
                    "'{}' would listen on {}:{} which another server already uses.",
                    server.label, server.bind, server.port
                ));
            }
            seen.push(key);
        }
    }

    {
        let mut guard = state.store.lock().unwrap_or_else(|p| p.into_inner());
        guard.settings_mut().remote = settings.clone();
        guard.save().map_err(fail)?;
    }

    reconcile_remote_servers(app, state).await;
    Ok(remote_access_view(state))
}

/// Start, stop and restart servers so the running set matches the saved settings.
pub async fn reconcile_remote_servers(app: &AppHandle, state: &AppState) {
    let settings = store(state).settings().remote.clone();

    // What should be listening.
    let wanted: Vec<deepsand_core::remote::RemoteServerConfig> = if settings.enabled {
        settings.servers.clone()
    } else {
        Vec::new()
    };

    // Stop anything that is gone or has changed.
    let to_stop: Vec<String> = {
        let running = state.remote_servers.lock().unwrap_or_else(|p| p.into_inner());
        running
            .iter()
            .filter(|(id, live)| {
                wanted
                    .iter()
                    .find(|candidate| &&candidate.id == id)
                    .map(|candidate| &live.config != candidate)
                    .unwrap_or(true)
            })
            .map(|(id, _)| id.clone())
            .collect()
    };
    for id in to_stop {
        let removed = {
            let mut running = state.remote_servers.lock().unwrap_or_else(|p| p.into_inner());
            running.remove(&id)
        };
        if let Some(live) = removed {
            live.stop();
            tracing::info!("remote server '{id}' stopped");
        }
    }

    // Start anything wanted that is not already up.
    for config in wanted {
        let already = {
            let running = state.remote_servers.lock().unwrap_or_else(|p| p.into_inner());
            running.contains_key(&config.id)
        };
        if already {
            continue;
        }
        match crate::remote_server::start(app, config.clone(), settings.lockout_after_failures).await {
            Ok(live) => {
                let mut running = state.remote_servers.lock().unwrap_or_else(|p| p.into_inner());
                running.insert(config.id.clone(), live);
            }
            Err(err) => {
                // Recorded rather than returned, so one bad server does not stop the
                // others from coming up; the UI shows which are running.
                tracing::warn!("remote server '{}' could not start: {err}", config.id);
            }
        }
    }
}

/// Stop every remote server, for app shutdown.
pub fn stop_all_remote_servers(state: &AppState) {
    let mut running = state.remote_servers.lock().unwrap_or_else(|p| p.into_inner());
    for (_, live) in running.drain() {
        live.stop();
    }
}

#[tauri::command]
pub fn get_remote_access(state: State<'_, AppState>) -> CmdResult<RemoteAccessView> {
    get_remote_access_impl(&state)
}

#[tauri::command]
pub async fn set_remote_access(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: deepsand_core::remote::RemoteAccessSettings,
) -> CmdResult<RemoteAccessView> {
    set_remote_access_impl(&app, &state, settings).await
}

/// The shipped allowlist presets, so a UI can offer them without duplicating the
/// entries in TypeScript and letting the two drift apart.
#[tauri::command]
pub fn network_presets() -> Vec<serde_json::Value> {
    allowlist::presets()
        .into_iter()
        .map(|(name, entries)| {
            serde_json::json!({
                "name": name,
                "entries": entries,
            })
        })
        .collect()
}

/// The per-project allowlist, with the inherited global entries alongside it.
#[tauri::command]
pub fn project_allowlist(state: State<'_, AppState>, project_id: String) -> CmdResult<AllowlistView> {
    project_allowlist_impl(&state, project_id)
}

pub fn project_allowlist_impl(state: &AppState, project_id: String) -> CmdResult<AllowlistView> {

    view_for(&state, &project_id)
}

/// Replace a project's own allowlist entries.
///
/// The global list is not touched: this is the project-scoped half of the pair, and
/// the whole point of having both is that a permission granted for one project does
/// not silently widen every other one.
#[tauri::command]
pub async fn set_project_allowlist(state: State<'_, AppState>, project_id: String, entries: Vec<String>) -> CmdResult<AllowlistView> {
    set_project_allowlist_impl(&state, project_id, entries).await
}

pub async fn set_project_allowlist_impl(state: &AppState, project_id: String, entries: Vec<String>) -> CmdResult<AllowlistView> {

    let cleaned = accept_allowlist(&entries)?;

    {
        let mut store = store(&state);
        let project = store.project_mut(&project_id).map_err(fail)?;
        match project.network {
            NetworkPolicy::Allowlisted { ref mut allow } => *allow = cleaned,
            // Saving into a mode that never consults an allowlist would store
            // entries that do nothing. The UI shows `allowlisted: false` and offers
            // the switch, so refuse here rather than accept a silent no-op.
            _ => {
                return Err(
                    "This project is not using the allowlisted network mode, so an allowlist would                      have no effect. Switch the project to 'restricted' first."
                        .to_string(),
                )
            }
        }
        store.save().map_err(fail)?;
    }

    refresh_proxies(&state).await;
    view_for(&state, &project_id)
}

/// Validate an allowlist before storing it.
///
/// This replaces a sanitiser that understood only bare hostnames. It silently
/// discarded any entry containing a character outside `[a-z0-9._-*]`, which meant
/// `!deny.example`, `re:^api\.example\.com$` and `github.com/org/repo` were all
/// dropped without a word -- the entry appeared saved and enforced nothing.
///
/// Now the entry syntax is parsed by the same engine that enforces it, so an entry
/// is either accepted and effective, or refused with the reason. A blanket `*` is
/// refused rather than flagged, because it is the one entry that makes the list
/// meaningless and the unrestricted network mode already exists for that intent.
fn accept_allowlist(hosts: &[String]) -> CmdResult<Vec<String>> {
    let entries: Vec<String> = hosts
        .iter()
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect();

    let validation = allowlist::validate(&entries);
    if !validation.is_acceptable() {
        return Err(validation.problems.join("\n"));
    }
    Ok(entries)
}

/* ------------------------------------------------------------------------- */
/* Tools                                                                     */
/* ------------------------------------------------------------------------- */

fn tool_view(tool: &deepsand_core::tools::Tool, selected: &[String]) -> ToolView {
    let reason = deepsand_core::tools::unavailable_reason(tool);
    ToolView {
        id: tool.id.to_string(),
        label: tool.label.to_string(),
        description: tool.description.to_string(),
        category: tool.category.label().to_string(),
        provider: tool.provider.label().to_string(),
        default_on: tool.default_on,
        enabled: selected.iter().any(|id| id == tool.id),
        available: reason.is_none(),
        unavailable_reason: reason,
        hosts: tool.hosts.iter().map(|host| (*host).to_string()).collect(),
        requires: tool.base.label().to_string(),
    }
}

/// The catalogue as it applies to one project, with the current selection.
pub fn list_tools_impl(state: &AppState, project_id: &str) -> CmdResult<ToolCatalogView> {
    let (selection, base_image) = {
        let store = store(state);
        let project = store.project(project_id).map_err(fail)?;
        (project.tools.clone(), store.settings().image.clone())
    };

    // The resolved set, so an entry that is selected but unavailable shows as not
    // enabled rather than as a lie about what the image contains.
    let selected: Vec<String> = deepsand_core::tools::resolve(selection.as_deref())
        .iter()
        .map(|tool| tool.id.to_string())
        .collect();

    let tools = deepsand_core::tools::CATALOG
        .iter()
        .map(|tool| tool_view(tool, &selected))
        .collect();

    let running_image = state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(project_id)
        .map(|live| live.container_name.clone());

    Ok(ToolCatalogView {
        project_id: project_id.to_string(),
        tools,
        effective_hosts: deepsand_core::tools::hosts_for(selection.as_deref()),
        image: with_runtime_revision(deepsand_core::tools::image_for(&base_image, selection.as_deref())),
        running_image,
    })
}

#[tauri::command]
pub fn list_tools(state: State<'_, AppState>, project_id: String) -> CmdResult<ToolCatalogView> {
    list_tools_impl(&state, &project_id)
}

/// Replace a project's tool selection.
///
/// The running proxies are refreshed afterwards, which is what makes switching the
/// search tool close its domains immediately rather than at the next restart: the
/// allowlist is recomputed from the new selection and pushed to the live listener.
pub async fn set_project_tools_impl(
    state: &AppState,
    project_id: &str,
    ids: Vec<String>,
) -> CmdResult<ToolCatalogView> {
    // Refuse an unavailable tool rather than storing an id that will be silently
    // dropped at build time, and refuse an unknown one rather than storing a typo.
    for id in &ids {
        let Some(tool) = deepsand_core::tools::find(id) else {
            return Err(format!("'{id}' is not a tool Deepsand knows about."));
        };
        if let Some(reason) = deepsand_core::tools::unavailable_reason(tool) {
            return Err(reason);
        }
    }

    {
        let mut store = store(state);
        let project = store.project_mut(project_id).map_err(fail)?;
        // Stored explicitly rather than as `None`, so switching every tool off is a
        // decision the project records instead of looking like never having chosen.
        project.tools = Some(ids);
        store.save().map_err(fail)?;
    }

    refresh_proxies(state).await;
    list_tools_impl(state, project_id)
}

#[tauri::command]
pub async fn set_project_tools(
    state: State<'_, AppState>,
    project_id: String,
    ids: Vec<String>,
) -> CmdResult<ToolCatalogView> {
    set_project_tools_impl(&state, &project_id, ids).await
}

/* ------------------------------------------------------------------------- */
/* Thinking intensity                                                        */
/* ------------------------------------------------------------------------- */

/// Write the current thinking settings into the project's `settings.json`, and into
/// a running sandbox if there is one. Returns whether a running sandbox was updated.
fn push_effort(state: &AppState, project_id: &str) -> CmdResult<bool> {
    let (config_dir, container, resolved) = {
        let store = store(state);
        let project = store.project(project_id).map_err(fail)?.clone();
        let app = store.settings().clone();
        let config_dir = store
            .data_dir()
            .join("projects")
            .join(project_id)
            .join("config");
        let host = credentials::read_host_config();
        let resolved = credentials::resolve(&project, &app, &host);
        let container = state
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(project_id)
            .map(|live| live.container_name.clone());
        (config_dir, container, resolved)
    };

    // Read-modify-write rather than regenerate. The file already holds the model, the
    // token and the permissions, and reproducing that here would be a second
    // implementation of `build_deepcode_settings`, free to drift from the first.
    let path = config_dir.join("settings.json");
    let mut root: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));

    if let Some(map) = root.as_object_mut() {
        map.insert(
            "thinkingEnabled".into(),
            serde_json::Value::Bool(resolved.thinking_enabled),
        );
        map.insert(
            "reasoningEffort".into(),
            serde_json::Value::String(resolved.reasoning_effort.clone()),
        );
    }

    let bytes = serde_json::to_vec_pretty(&root)
        .map_err(|err| format!("could not encode the settings: {err}"))?;
    if config_dir.exists() {
        std::fs::write(&path, &bytes)
            .map_err(|err| format!("could not update {}: {err}", path.display()))?;
    }

    let Some(container) = container else {
        return Ok(false);
    };
    // A missing daemon is not a failure: the setting is saved, and the next start
    // will pick it up.
    let Ok(docker) = state.docker() else {
        return Ok(false);
    };
    match docker.write_into_container(&container, "/home/deepcode/.deepcode/settings.json", &bytes) {
        Ok(()) => Ok(true),
        Err(err) => {
            // A warning rather than an error: the setting is saved either way, and
            // reporting a hard failure would make a cosmetic problem look fatal.
            tracing::warn!("could not push the thinking setting into {container}: {err}");
            Ok(false)
        }
    }
}

pub fn get_effort_impl(state: &AppState, project_id: &str) -> CmdResult<EffortView> {
    let project = store(state).project(project_id).map_err(fail)?.clone();
    let controlling = project.credentials.reasoning_effort.is_none();
    let running = state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains_key(project_id);
    // Set by the setter after it pushes; a plain read means nothing was pushed.
    let applied_live = false;
    Ok(EffortView {
        project_id: project_id.to_string(),
        value: project.reasoning_effort.as_str().to_string(),
        deferring: project.reasoning_effort.is_deferring(),
        options: ReasoningEffort::ALL
            .iter()
            .map(|effort| EffortOption {
                value: effort.as_str().to_string(),
                label: effort.label().to_string(),
                description: effort.description().to_string(),
            })
            .collect(),
        controlling,
        // Only a real problem when the sandbox did not receive the change, which the
        // setter reports by overriding this after a failed push.
        restart_needed: running && !applied_live,
        applied_live,
    })
}

#[tauri::command]
pub fn get_effort(state: State<'_, AppState>, project_id: String) -> CmdResult<EffortView> {
    get_effort_impl(&state, &project_id)
}

/// Change how hard the model thinks.
///
/// Saved and written into the project's generated configuration in one step, so the
/// switch does not need a separate Save: what the operator sees is already on disk.
///
/// Note that DeepCode reads its configuration when it starts, so an in-flight sandbox
/// keeps the effort it began with until it is restarted. The switch is immediate for
/// the sandbox's configuration, not for the model conversation already in progress.
pub fn set_effort_impl(
    state: &AppState,
    project_id: &str,
    value: &str,
) -> CmdResult<EffortView> {
    let effort = ReasoningEffort::parse(value).ok_or_else(|| {
        format!(
            "'{value}' is not a thinking intensity. Expected one of none, low, high, max, default."
        )
    })?;

    {
        let mut store = store(state);
        let project = store.project_mut(project_id).map_err(fail)?;
        project.reasoning_effort = effort;
        store.save().map_err(fail)?;
    }

    // Applied now, not at the next start: the CLI reads its settings file per run,
    // so rewriting the file the sandbox reads is enough.
    let applied_live = push_effort(state, project_id)?;

    let mut view = get_effort_impl(state, project_id)?;
    view.applied_live = applied_live;
    view.restart_needed = view.restart_needed && !applied_live;
    Ok(view)
}

#[tauri::command]
pub fn set_effort(
    state: State<'_, AppState>,
    project_id: String,
    value: String,
) -> CmdResult<EffortView> {
    set_effort_impl(&state, &project_id, &value)
}

/* ------------------------------------------------------------------------- */
/* Secrets                                                                   */
/* ------------------------------------------------------------------------- */

fn secret_view(name: &str, value: &str) -> SecretView {
    SecretView {
        name: name.to_string(),
        // A fixed run of dots rather than a partial reveal: a preview is a leak that
        // looks like a convenience.
        masked: "\u{2022}".repeat(12),
        length: value.chars().count(),
    }
}

pub fn list_secrets_impl(state: &AppState, project_id: &str) -> CmdResult<SecretListView> {
    // Check the project exists first, so a typo is a clear error rather than an
    // empty table.
    {
        let store = store(state);
        store.project(project_id).map_err(fail)?;
    }
    let restart_needed = state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains_key(project_id);

    let secrets = match open_secrets(state, project_id) {
        Some(store) => store,
        None => {
            return Ok(SecretListView {
                project_id: project_id.to_string(),
                secrets: Vec::new(),
                available: false,
                unavailable_reason: Some(
                    "Deepsand could not open the encryption key for your secrets. It normally keeps one \
                     in your operating system's keystore. Set DEEPSAND_SECRETS_KEY to a 64-character \
                     hex value to run without a keystore, and restart Deepsand."
                        .to_string(),
                ),
                restart_needed,
                reserved: deepsand_core::secrets::reserved_names(),
            });
        }
    };

    let view = secret_view_list(&secrets, project_id, restart_needed);
    Ok(view)
}

fn secret_view_list(
    secrets: &deepsand_core::secrets::Secrets,
    project_id: &str,
    restart_needed: bool,
) -> SecretListView {
    match secrets.all() {
        Ok(map) => SecretListView {
            project_id: project_id.to_string(),
            secrets: map.iter().map(|(name, value)| secret_view(name, value)).collect(),
            available: true,
            unavailable_reason: None,
            restart_needed,
            reserved: deepsand_core::secrets::reserved_names(),
        },
        Err(err) => SecretListView {
            project_id: project_id.to_string(),
            secrets: Vec::new(),
            available: false,
            unavailable_reason: Some(err.to_string()),
            restart_needed,
            reserved: deepsand_core::secrets::reserved_names(),
        },
    }
}

#[tauri::command]
pub fn list_secrets(state: State<'_, AppState>, project_id: String) -> CmdResult<SecretListView> {
    list_secrets_impl(&state, &project_id)
}

/// Store or replace one secret.
///
/// The value is written and then dropped: it is never echoed back, never logged, and
/// the returned view contains only the name and a length.
pub fn set_secret_impl(
    state: &AppState,
    project_id: &str,
    name: &str,
    value: &str,
) -> CmdResult<SecretListView> {
    {
        let store = store(state);
        let project = store.project(project_id).map_err(fail)?;
        let name = name.trim().to_string();
        // The audit log records that a secret changed, never its value.
        store.append_audit(
            &project.id,
            &format!("SET   secret {name}"),
        );
        store.save().map_err(fail)?;
    }

    let secrets = open_secrets(state, project_id).ok_or_else(|| {
        "Deepsand could not open the encryption key for your secrets, so nothing was saved.".to_string()
    })?;
    secrets.set(name, value).map_err(fail)?;

    let restart_needed = state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains_key(project_id);
    Ok(secret_view_list(&secrets, project_id, restart_needed))
}

#[tauri::command]
pub fn set_secret(
    state: State<'_, AppState>,
    project_id: String,
    name: String,
    value: String,
) -> CmdResult<SecretListView> {
    set_secret_impl(&state, &project_id, &name, &value)
}

pub fn delete_secret_impl(
    state: &AppState,
    project_id: &str,
    name: &str,
) -> CmdResult<SecretListView> {
    {
        let store = store(state);
        let project = store.project(project_id).map_err(fail)?;
        store.append_audit(&project.id, &format!("REMOVE secret {name}"));
        store.save().map_err(fail)?;
    }

    let secrets = open_secrets(state, project_id).ok_or_else(|| {
        "Deepsand could not open the encryption key for your secrets, so nothing was removed."
            .to_string()
    })?;
    secrets.remove(name).map_err(fail)?;

    let restart_needed = state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains_key(project_id);
    Ok(secret_view_list(&secrets, project_id, restart_needed))
}

#[tauri::command]
pub fn delete_secret(
    state: State<'_, AppState>,
    project_id: String,
    name: String,
) -> CmdResult<SecretListView> {
    delete_secret_impl(&state, &project_id, &name)
}

/* ------------------------------------------------------------------------- */
/* Starting with the computer                                                */
/* ------------------------------------------------------------------------- */

/// The binary to register, which is this executable.
fn autostart_entry() -> Result<auto_launch::AutoLaunch, String> {
    let exe = std::env::current_exe().map_err(|err| format!("could not locate the Deepsand binary: {err}"))?;
    auto_launch::AutoLaunchBuilder::new()
        .set_app_name("Deepsand")
        .set_app_path(&exe.to_string_lossy())
        // macOS has no equivalent of a Run key, so this is ignored elsewhere.
        .set_use_launch_agent(true)
        .build()
        .map_err(|err| format!("could not prepare the autostart entry: {err}"))
}

/// Whether the operating system is currently set to start Deepsand.
///
/// Read from the OS rather than from the settings file, because the two can diverge:
/// an operator who removes the entry by hand should see that reflected rather than
/// being told a setting is on when it is not.
pub fn start_at_login_impl() -> CmdResult<bool> {
    let entry = autostart_entry()?;
    entry.is_enabled().map_err(|err| format!("could not read the autostart state: {err}"))
}

#[tauri::command]
pub fn get_start_at_login() -> CmdResult<bool> {
    start_at_login_impl()
}

pub fn set_start_at_login_impl(state: &AppState, enabled: bool) -> CmdResult<bool> {
    let entry = autostart_entry()?;
    let applied = if enabled {
        entry.enable().map(|_| true).map_err(|err| {
            format!(
                "could not add Deepsand to your startup items ({err}). On Linux this needs a desktop \
                 session with a writable autostart directory."
            )
        })?
    } else {
        entry.disable().map(|_| false).map_err(|err| {
            format!("could not remove Deepsand from your startup items ({err})")
        })?
    };

    // Only stored once the OS has accepted it, so the setting and the machine agree.
    {
        let mut store = store(state);
        store.settings_mut().start_at_login = applied;
        store.save().map_err(fail)?;
    }
    Ok(applied)
}

#[tauri::command]
pub fn set_start_at_login(state: State<'_, AppState>, enabled: bool) -> CmdResult<bool> {
    set_start_at_login_impl(&state, enabled)
}

#[tauri::command]
pub fn host_config_summary() -> CmdResult<std::collections::BTreeMap<String, String>> {
    Ok(credentials::describe_host_config(&credentials::read_host_config()))
}

#[tauri::command]
pub fn build_runtime_image(
    app: AppHandle,
    state: State<'_, AppState>,
    project_id: Option<String>,
    build_tools: Option<bool>,
) -> CmdResult<()> {
    build_runtime_image_impl(&app, &state, project_id, build_tools)
}

/// Build the runtime image for a project's tool selection.
///
/// The tag and the build arguments both come from `deepsand_core::tools`, so the
/// image that is produced is the one the plan will ask for. Building a different tag
/// than the plan expects is the kind of mismatch that only shows up as "it says the
/// image is missing" much later.
pub fn build_runtime_image_impl(
    app: &AppHandle,
    state: &AppState,
    project_id: Option<String>,
    build_tools: Option<bool>,
) -> CmdResult<()> {

    let docker = state.docker().map_err(fail)?;
    let selection = match &project_id {
        Some(id) => store(&state).project(id).map_err(fail)?.tools.clone(),
        // No project named: build the defaults, which is what a first-run build is.
        None => None,
    };
    let base = store(&state).settings().image.clone();
    let image = with_runtime_revision(deepsand_core::tools::image_for(&base, selection.as_deref()));

    let plan = deepsand_core::tools::install_plan(selection.as_deref());

    /// Join for the Dockerfile, which splits on commas.
    fn csv(values: &[String]) -> String {
        values.join(",")
    }

    let build_args: Vec<(&str, String)> = vec![
        ("INSTALL_TOOLS", deepsand_core::tools::build_argument(selection.as_deref())),
        ("APT_PACKAGES", csv(&plan.apt)),
        ("NPM_GLOBALS", csv(&plan.npm)),
        ("CARGO_INSTALLS", csv(&plan.cargo)),
        ("WITH_NODE_REPO", u8::from(plan.node_repo).to_string()),
        ("WITH_RUSTUP", u8::from(plan.rustup).to_string()),
        ("WITH_GO", u8::from(plan.go).to_string()),
        ("WITH_BREW", u8::from(plan.brew).to_string()),
        ("WITH_NIX", u8::from(plan.nix).to_string()),
        (
            "INSTALL_BUILD_TOOLS",
            u8::from(build_tools.unwrap_or(false)).to_string(),
        ),
        // Changes every build, so the DeepCode install layer is never reused and
        // "latest" means latest now rather than latest when the layer was cached.
        ("DEEPCODE_REFRESH", deepsand_core::now_ms().to_string()),
    ];

    let context = runtime_context_dir().ok_or_else(|| {
        "the runtime/ directory (Dockerfile and entrypoint) could not be found. Set DEEPSAND_RUNTIME_DIR to its \
         location."
            .to_string()
    })?;

    // The log goes to a file as well as to the window. The window's copy dies with the
    // window, which is exactly when somebody wants to read it.
    let log_path = store(&state).data_dir().join("build.log");

    let app_handle = AppHandle::clone(app);
    std::thread::spawn(move || {
        let app_for_log = AppHandle::clone(&app_handle);
        let image_for_event = image.clone();
        // Truncated per build: the previous build's output is not context, it is noise.
        let mut log = std::fs::File::create(&log_path).ok();
        let result = docker.build(&context, &image, &build_args, move |line| {
            if let Some(file) = log.as_mut() {
                use std::io::Write as _;
                let _ = writeln!(file, "{line}");
            }
            let _ = app_for_log.emit(events::BUILD_LOG, serde_json::json!({ "line": line }));
            // Emitted only when the line reports a step, so the bar moves on real
            // progress and an idle build does not look stalled at 0%.
            if let Some((step, total)) = deepsand_core::docker::parse_build_step(&line) {
                let _ = app_for_log.emit(
                    events::BUILD_PROGRESS,
                    serde_json::json!({
                        "image": image_for_event,
                        "step": step,
                        "total": total,
                    }),
                );
            }
        });
        let _ = app_handle.emit(
            events::BUILD_DONE,
            match result {
                Ok(()) => serde_json::json!({ "ok": true, "image": image }),
                Err(err) => serde_json::json!({
                    "ok": false,
                    "detail": format!("{err}\n\nThe full build log is {}.", log_path.display()),
                }),
            },
        );
    });

    let _ = build_tools;
    Ok(())
}

/// Locate the `runtime/` directory (Dockerfile, entrypoint, MCP bridge).
///
/// The packaged installer ships it as a bundle resource, which lands next to the
/// executable; a `cargo run`/`tauri dev` session finds it in the source tree. The
/// `_up_` variants cover Tauri's escaping convention for resources sourced from
/// outside `src-tauri/`.
/// Append the runtime revision to an image tag.
///
/// Kept separate from `tools::image_for` so the pure catalogue stays pure: the revision
/// needs the filesystem, and the tools module deliberately does not touch it.
fn with_runtime_revision(tag: String) -> String {
    match runtime_context_dir().map(|dir| runtime_revision(&dir)) {
        Some(revision) if !revision.is_empty() => format!("{tag}-{revision}"),
        _ => tag,
    }
}

/// A short hash of the runtime scripts, which the image tag includes.
///
/// The tag otherwise depends only on the tool selection, so editing `netfilter.sh` or
/// the entrypoint changed nothing from the tag's point of view: the app kept using an
/// image built from the previous scripts. That is not cosmetic. When the app and the
/// image disagree about how a sandbox should be started, the disagreement surfaces as a
/// refusal to start -- which is how `none` mode broke, with a proxy the app no longer
/// started being demanded by an image that had not been rebuilt.
///
/// Returns an empty string when the scripts cannot be read, so a missing runtime
/// directory degrades to the old behaviour rather than to a tag that changes randomly.
fn runtime_revision(runtime: &std::path::Path) -> String {
    use std::collections::BTreeMap;

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(runtime.join("bin")) {
        for entry in entries.flatten() {
            if let Ok(bytes) = std::fs::read(entry.path()) {
                files.insert(entry.file_name().to_string_lossy().to_string(), bytes);
            }
        }
    }
    // Every file the image is built from, not just the scripts. The seccomp profile was
    // left out of this and that is exactly how it went stale: editing it produced an
    // identical tag, so the image was never rebuilt and kept serving the old one. A
    // revision that does not cover an input is a revision that lies.
    for name in ["Dockerfile", "seccomp-hardened.json", "gitconfig"] {
        match std::fs::read(runtime.join(name)) {
            Ok(bytes) => {
                files.insert(name.to_string(), bytes);
            }
            Err(_) if name == "Dockerfile" => return String::new(),
            Err(_) => {}
        }
    }
    // The skills are installed into the image too.
    if let Ok(entries) = std::fs::read_dir(runtime.join("skills")) {
        for entry in entries.flatten() {
            let skill = entry.path().join("SKILL.md");
            if let Ok(bytes) = std::fs::read(&skill) {
                files.insert(format!("skills/{}", entry.file_name().to_string_lossy()), bytes);
            }
        }
    }
    if files.is_empty() {
        return String::new();
    }

    // FNV-1a over the names and contents, in sorted order so the result does not depend
    // on directory iteration.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for (name, bytes) in files {
        for byte in name.bytes().chain(bytes).chain(std::iter::once(0)) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("r{hash:08x}")
}

/// Locate the `runtime/` directory (Dockerfile, entrypoint, MCP bridge, seccomp profile).
///
/// Delegates to the core so this, the profile resolver and the headless CLI cannot
/// disagree about which tree the runtime lives in.
fn runtime_context_dir() -> Option<PathBuf> {
    deepsand_core::seccomp::runtime_dir()
}

/// Remove managed containers, volumes and networks that no live project owns.
#[tauri::command]
pub fn cleanup_orphans(state: State<'_, AppState>) -> CmdResult<Vec<String>> {
    cleanup_orphans_impl(&state)
}

/// Everything to do before the process goes away.
///
/// Called from both the window-destroyed handler and `RunEvent::Exit`, so it has to be
/// safe to run twice: every step is idempotent, and every step is best-effort. Failing
/// to clean up must never be the reason the app will not close.
pub fn shutdown_cleanup(state: &AppState) {
    let project_ids: Vec<String> = {
        let store = store(state);
        store.projects().iter().map(|project| project.id.clone()).collect()
    };
    for project_id in project_ids {
        // Stops the PTY and removes the container by name.
        state.stop_session_internal(&project_id);
    }

    // Never leave an HTTP port open once the window is gone: the window is the only
    // place the operator can see or stop it.
    stop_all_remote_servers(state);

    // Anything still carrying Deepsand's label belongs to a session that was lost --
    // a panic, or a start that failed after the container was created. Nothing is
    // running any more, so everything left is residue.
    if let Ok(removed) = cleanup_orphans_impl(state) {
        if !removed.is_empty() {
            tracing::info!(count = removed.len(), "removed sandbox containers on exit");
        }
    }
}

pub fn cleanup_orphans_impl(state: &AppState) -> CmdResult<Vec<String>> {

    let docker = state.docker().map_err(fail)?;
    // "Keep" means a container a live session owns. Passing every known project's
    // container name -- as this used to -- meant a stale container from a project that
    // still exists was never treated as an orphan, however long it had been dead, and
    // it went on holding the name.
    let expected = state.live_container_names();
    Ok(docker.prune_orphans(&expected))
}

#[tauri::command]
pub fn reveal_data_dir(state: State<'_, AppState>) -> CmdResult<String> {
    reveal_data_dir_impl(&state)
}

pub fn reveal_data_dir_impl(state: &AppState) -> CmdResult<String> {

    Ok(store(&state).data_dir().display().to_string())
}

#[tauri::command]
pub fn startup_error(state: State<'_, AppState>) -> CmdResult<Option<String>> {
    startup_error_impl(&state)
}

pub fn startup_error_impl(state: &AppState) -> CmdResult<Option<String>> {

    Ok(state.startup_error.lock().unwrap().clone())
}

/// Load the store, falling back to a store that has read nothing so the app can still
/// open and explain itself when the saved configuration is unusable.
///
/// The fallback must come from `Store::fallback` and not from a second `Store::load`.
/// A second load finds the damaged file already moved aside, mistakes that for a first
/// run, and writes an empty state over a situation that was still recoverable -- which
/// is exactly how an operator lost five projects while the app showed a notice telling
/// them to re-add those projects.
pub fn load_store() -> (Store, Option<String>) {
    let data_dir = Store::default_data_dir();
    match Store::load(data_dir.clone()) {
        Ok(store) if store.recovered_from_salvage().is_some() => {
            let from = store
                .recovered_from_salvage()
                .map(|path| path.display().to_string())
                .unwrap_or_default();
            let notice = format!(
                "Deepsand's saved configuration could not be read, so it was recovered from {from}, \
                 a copy that had been set aside earlier. Your projects and permissions are there. \
                 Check anything you changed most recently: the recovered copy may predate it."
            );
            (store, Some(notice))
        }
        Ok(store) if store.recovered_from_backup() => {
            let notice = "Deepsand's saved configuration could not be read, so the previous copy was \
                          restored from state.json.bak. Your projects and permissions are there; any \
                          change made after that copy was saved is not. The unreadable file was kept \
                          beside it as state.corrupt-*.json."
                .to_string();
            (store, Some(notice))
        }
        Ok(store) => (store, None),
        // Malformed beyond recovery, or present but not openable. The app still has to
        // open, but it must not write a fresh empty state over the last good copy.
        // `Store::fallback` is what stops that: it refuses to rotate the backup.
        Err(err) => {
            let notice = format!(
                "Deepsand could not read its saved configuration: {err}\n\nNothing has been deleted. \
                 The live file and every copy set aside earlier are still in {}:\n{}\n\nDeepsand has \
                 started with an empty configuration so you can look around, and it will not \
                 overwrite those files or the rolling backup while you do. Report this with the list \
                 above before re-adding anything by hand.",
                data_dir.display(),
                set_aside_list(&data_dir)
            );
            (Store::fallback(data_dir), Some(notice))
        }
    }
}


/// Every state file kept beside the live one, newest first.
///
/// For a notice that has to tell an operator where their data went. Naming the files is
/// the difference between "your projects are gone" and "your projects are in this list";
/// the second one is usually true.
fn set_aside_list(data_dir: &std::path::Path) -> String {
    let mut found: Vec<(std::time::SystemTime, String)> = std::fs::read_dir(data_dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| {
                    let name = entry.file_name().to_string_lossy().to_string();
                    name.starts_with("state.") && name.ends_with(".json")
                })
                .filter_map(|entry| {
                    let modified = entry.metadata().ok()?.modified().ok()?;
                    Some((modified, entry.file_name().to_string_lossy().to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    found.sort_by(|a, b| b.0.cmp(&a.0));
    if found.is_empty() {
        return "  (no state files found)".to_string();
    }
    found
        .into_iter()
        .map(|(modified, name)| {
            let stamp = modified
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_secs())
                .unwrap_or_default();
            format!("  {name}  (mtime {stamp})")
        })
        .collect::<Vec<_>>()
        .join("\n")
}
