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

    // Deliberately not a Docker probe. This is the first call the window makes, and a probe
    // is three Docker CLI invocations (~0.4 s here, and 1.5 s before they were overlapped) --
    // time the UI spent with nothing drawn, to learn something no part of the first paint
    // needs. `None` is "not checked yet": the window asks with `docker_status` once it is up,
    // and the status strip says so until then rather than claiming the daemon is down.
    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        data_dir: data_dir.display().to_string(),
        docker: None,
        host_config: credentials::describe_host_config(&credentials::read_host_config()),
        settings,
    })
}

#[tauri::command]
pub async fn docker_status(app: AppHandle) -> CmdResult<DockerStatus> {
    // Async, because the probe is several docker CLI calls and a sync command runs them on the
    // main thread: one wedged daemon call froze the entire window for its whole timeout. A
    // blocked worker is invisible; a blocked main thread is a window that does not repaint.
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = tauri::Manager::state::<AppState>(&handle);
        docker_status_impl(&state)
    })
    .await
    .map_err(|err| format!("the docker check could not be completed: {err}"))?
}

pub fn docker_status_impl(state: &AppState) -> CmdResult<DockerStatus> {

    let image = store(&state).settings().image.clone();
    let mut status = match state.docker() {
        Ok(docker) => docker.probe(&image),
        Err(err) => DockerStatus {
            available: false,
            detail: err.to_string(),
            ..DockerStatus::default()
        },
    };
    if state.runtime_wedged.load(std::sync::atomic::Ordering::SeqCst) {
        status.available = false;
        status.detail =
            "Docker Desktop is running, but its container runtime is not answering. Restart Docker Desktop."
                .to_string();
    }
    Ok(status)
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
pub fn update_project_settings(state: State<'_, AppState>, project_id: String, network: Option<NetworkPolicy>, limits: Option<ResourceLimits>, deepcode_mode: Option<DeepCodeMode>, notes: Option<String>, credentials: Option<Credentials>, resume_on_launch: Option<bool>) -> CmdResult<ProjectView> {
    update_project_settings_impl(
        &state,
        project_id,
        network,
        limits,
        deepcode_mode,
        notes,
        credentials,
        resume_on_launch,
    )
}

pub fn update_project_settings_impl(state: &AppState, project_id: String, network: Option<NetworkPolicy>, limits: Option<ResourceLimits>, deepcode_mode: Option<DeepCodeMode>, notes: Option<String>, credentials: Option<Credentials>, resume_on_launch: Option<bool>) -> CmdResult<ProjectView> {

    let mut store = store(&state);
    {
        let project = store.project_mut(&project_id).map_err(fail)?;
        if let Some(network) = network {
            project.network = network;
        }
        if let Some(limits) = limits {
            project.limits = limits;
        }
        if let Some(resume) = resume_on_launch {
            project.resume_on_launch = resume;
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

    // Before anything reads the image: the probe below, the profile check, the snapshot the
    // sandbox reads and the plan itself all have to agree on which image this is. The tag in
    // settings is only the stem the project's tag is derived from, and `image_present` has to
    // mean "this project's image is there", not "some image with that stem is".
    let app_settings = container_settings::settings_for_project(&app_settings, project.tools.as_deref());

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
    let image = app_settings.image.clone();
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
pub async fn preview_plan(app: AppHandle, project_id: String) -> CmdResult<PlanPreview> {
    // Async for the same reason docker_status is: the plan touches docker (the live proxy and the
    // seccomp check), and a sync command would run that on the main thread.
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = tauri::Manager::state::<AppState>(&handle);
        preview_plan_impl(&state, project_id)
    })
    .await
    .map_err(|err| format!("the plan could not be previewed: {err}"))?
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
    // Per-project image, because the tools are baked in and two projects may want different
    // ones. Shared with the plan so the image this builds is the image the plan names.
    let app_settings = container_settings::settings_for_project(store.settings(), project.tools.as_deref());
    let image = app_settings.image.clone();
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
pub async fn start_session(
    app: AppHandle,
    state: State<'_, AppState>,
    project_id: String,
    resume: Option<bool>,
    // Start now, with the tools built behind the session instead of in front of it.
    without_tools: Option<bool>,
) -> CmdResult<SessionStatus> {
    start_session_impl(&app, &state, project_id, resume, without_tools.unwrap_or(false)).await
}

pub async fn start_session_impl(
    app: &AppHandle,
    state: &AppState,
    project_id: String,
    resume: Option<bool>,
    without_tools: bool,
) -> CmdResult<SessionStatus> {

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

    let mut launch = gather_launch(&state, &project_id)?;
    tracing::info!(image = %launch.image, "start: launch gathered");

    let docker = state.docker().map_err(fail)?;
    tracing::info!("start: docker located");
    docker
        .volume_create(&launch.volume)
        .map_err(|err| format!("could not create the session volume: {err}"))?;

    // Started without waiting for the tools: the sandbox runs on the image with no tools in it,
    // and the image this project actually wants is built behind it. What arrives later is copied
    // into the running container -- the compiled binaries and the npm globals, which are the ones
    // that take minutes. An apt package is a set of files in several places and cannot arrive
    // this way, so a selection containing one still needs a restart.
        tracing::info!("start: image ready");
    // One container start, on a five-second leash, answers the only question that matters
    // here: can Docker actually start containers? On this machine the daemon has answered
    // version/images/build while docker run hung, so every later check is blind to the
    // wedge. Failing now, with the fix named, is kinder than a minute of probes timing out.
    if !docker.runtime_answers(&launch.image) {
        state.app_state().runtime_wedged.store(true, std::sync::atomic::Ordering::SeqCst);
        return Err(
            "Docker Desktop is running, but its container runtime is not answering: a container \
             could not be started in five seconds. Restart Docker Desktop, then try again."
                .to_string(),
        );
    }
    state.app_state().runtime_wedged.store(false, std::sync::atomic::Ordering::SeqCst);
if without_tools {
        let settings =
            container_settings::settings_for_project(store(&state).settings(), Some(&[] as &[String]));
        launch.image = settings.image;
    }

    // The first Run for a tool selection has no image yet. Build it here rather than
    // refusing: "run this project" plainly means "make it runnable", and the operator
    // should not have to discover a separate build button first.
        tracing::info!("start: checking the image");
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
            build_runtime_image_impl(&handle, &state, Some(for_build), None, without_tools)
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

    if without_tools {
        // Recorded against the image the project actually wants, because that is what the build
        // knows when it finishes.
        let wanted = container_settings::settings_for_project(
            store(&state).settings(),
            store(&state).project(&project_id).map_err(fail)?.tools.as_deref(),
        )
        .image;
        {
            let mut queue = state.tools_arriving.lock().unwrap_or_else(|p| p.into_inner());
            queue.entry(wanted.clone()).or_default().push(project_id.clone());
        }
        let handle = app.clone();
        let for_build = project_id.clone();
        let image_for_log = wanted;
        std::thread::spawn(move || {
            // A short wait for the sandbox to exist, because the tools are copied into it. A few
            // seconds of polling is cheaper than threading a callback through the rest of the
            // start path, and the build takes minutes anyway.
            for _ in 0..60 {
                let running = {
                    let state = tauri::Manager::state::<AppState>(&handle);
                    let sessions = state.sessions.lock().unwrap_or_else(|p| p.into_inner());
                    sessions.contains_key(&for_build)
                };
                if running {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            let _ = handle.emit(
                events::BUILD_LOG,
                serde_json::json!({ "line": format!("Building {image_for_log} while the sandbox runs.") }),
            );
            let state = tauri::Manager::state::<AppState>(&handle);
            let _ = build_runtime_image_impl(&handle, &state, Some(for_build), None, false);
        });
    }

        tracing::info!("start: deciding whether to resume");
let wants_resume = resume.unwrap_or(true);
    let can_resume = wants_resume && docker.volume_has_session_index(&launch.volume, &launch.image);

    // Restricted egress: the allowlisting proxy has to exist BEFORE the plan is
    // built, because a restricted plan without a proxy is refused outright. This is
    // the order the code needs; getting it backwards means restricted mode can never
    // start at all.
        tracing::info!(network = %launch.project.network_name(), "start: setting up egress");
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

        tracing::info!("start: plan ready; probing the mounts");
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

        tracing::info!("start: mounts verified; checking credentials");
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

        tracing::info!("start: credentials ready; entering Session::spawn");
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
pub async fn stop_session(app: AppHandle, project_id: String) -> CmdResult<()> {
    // Async: stopping removes the container and kills the PTY, both of which can block.
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = tauri::Manager::state::<AppState>(&handle);
        stop_session_impl(&handle, &state, project_id)
    })
    .await
    .map_err(|err| format!("the sandbox could not be stopped: {err}"))?
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
    start_session_impl(app, state, project_id, Some(true), false).await
}

#[tauri::command]
pub async fn write_to_session(app: AppHandle, project_id: String, data: String) -> CmdResult<()> {
    // Async: a keystroke is written into the PTY, which on Windows is a ConPTY call that can block.
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = tauri::Manager::state::<AppState>(&handle);
        write_to_session_impl(&state, project_id, data)
    })
    .await
    .map_err(|err| format!("the keystroke could not be delivered: {err}"))?
}

pub fn write_to_session_impl(state: &AppState, project_id: String, data: String) -> CmdResult<()> {

    let mut sessions = state.sessions.lock().unwrap();
    let live = sessions.get_mut(&project_id).ok_or_else(|| {
        format!("no sandbox is running for {project_id}")
    })?;
    live.session.send(data.as_bytes()).map_err(fail)
}

#[tauri::command]
pub async fn resize_session(app: AppHandle, project_id: String, rows: u16, cols: u16) -> CmdResult<()> {
    // Async for the same reason writes are: a terminal resize is a ConPTY call.
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = tauri::Manager::state::<AppState>(&handle);
        resize_session_impl(&state, project_id, rows, cols)
    })
    .await
    .map_err(|err| format!("the terminal could not be resized: {err}"))?
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
    let claimed_secret_name = request.secret_name();
    let claimed_secret_value = request.secret_value();

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
        RequestKind::Secret => match request.secret_name() {
            Some(name) => format!("DeepCode is asking for a secret: {name}"),
            None => "DeepCode is asking for a secret to be added to this project".to_string(),
        },
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
        secret_name: claimed_secret_name,
        secret_value: claimed_secret_value,
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

        RequestKind::Secret => {
            // What the operator settled on wins over what the sandbox claimed: the request
            // is a prefill, not an instruction, and the operator may have replaced either
            // half of it in the dialog.
            let name = payload
                .secret_name
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .or_else(|| request.secret_name())
                .unwrap_or_default();
            let value = payload
                .secret_value
                .clone()
                .filter(|value| !value.is_empty())
                .or_else(|| request.secret_value())
                .unwrap_or_default();

            let refusal = if name.is_empty() {
                Some(
                    "a secret needs a name, and neither the operator nor the sandbox supplied one."
                        .to_string(),
                )
            } else {
                match deepsand_core::secrets::validate_name(&name) {
                    Err(err) => Some(format!("that name cannot be used as a secret: {err}")),
                    Ok(name) if deepsand_core::secrets::reserved_names().contains(&name) => {
                        Some(format!("{name} is reserved by Deepsand and cannot be set as a secret."))
                    }
                    Ok(name) if value.is_empty() => Some(format!(
                        "{name} was approved without a value, so there is nothing to hand to the sandbox yet."
                    )),
                    Ok(_) => None,
                }
            };

            if let Some(refusal) = refusal {
                let _ = app.emit(
                    events::BROKER_RESOLVED,
                    serde_json::json!({ "requestId": request_id, "decision": "deny" }),
                );
                broker.answer(&PermissionResponse::deny(&request_id, &refusal)).map_err(fail)?;
                return Ok(false);
            }

            let data_dir = store(&state).data_dir().to_path_buf();
            let secrets =
                deepsand_core::secrets::Secrets::open(&data_dir, &request.project).map_err(fail)?;
            secrets.set(&name, &value).map_err(fail)?;

            let message = format!(
                "{name} is saved for this project and is handed to the sandbox as an environment \
                 variable. A sandbox that is already running keeps the environment it started with, \
                 so restart the project to pick it up."
            );
            broker
                .answer(
                    &PermissionResponse::allow(&request_id, &message, None, true).with_secret(
                        deepsand_core::model::SecretSpec { name, value },
                    ),
                )
                .map_err(fail)?;
            tracing::info!("a secret was added from an approved request");
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
    let _ = start_session(app.clone(), state, project_id, Some(true), None).await;
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
    let (selection, project_image) = {
        let store = store(state);
        let project = store.project(project_id).map_err(fail)?;
        (
            project.tools.clone(),
            container_settings::settings_for_project(store.settings(), project.tools.as_deref()).image,
        )
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
        image: project_image,
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
pub(crate) fn push_live_settings(state: &AppState, project_id: &str) -> CmdResult<bool> {
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

    // Read-modify-write rather than regenerate, so a live change cannot drop a setting it
    // did not come here to change. The file already holds the model, the
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
        // The model lives in the settings' `env` block, which is where the CLI reads it from.
        // Written from the resolved credentials, so clearing a project's override puts the
        // configured model back rather than leaving the last choice behind.
        let env = map
            .entry("env")
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let Some(env) = env.as_object_mut() {
            env.insert(
                "MODEL".into(),
                serde_json::Value::String(resolved.model.clone()),
            );
        }
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
    let applied_live = push_live_settings(state, project_id)?;

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
/* Cancelling a build                                                        */
/* ------------------------------------------------------------------------- */

/// Stop a build that is running.
///
/// The operator's own control: installing tools takes minutes and can stall, and until now the
/// only way out of a stalled build was to close the app -- which, before `terminate_our_clients`,
/// left the build running behind it. Passing no image stops whatever is being built.
pub fn cancel_build_impl(image: Option<String>) -> CmdResult<Vec<String>> {
    let targets = match image {
        Some(image) => vec![image],
        None => deepsand_core::docker::builds_in_flight(),
    };
    let mut stopped = Vec::new();
    for tag in targets {
        if deepsand_core::docker::cancel_build(&tag) {
            stopped.push(tag);
        }
    }
    Ok(stopped)
}

#[tauri::command]
pub async fn cancel_build(app: AppHandle, image: Option<String>) -> CmdResult<Vec<String>> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _ = tauri::Manager::state::<AppState>(&handle);
        cancel_build_impl(image)
    })
    .await
    .map_err(|err| format!("the build could not be cancelled: {err}"))?
}

/* ------------------------------------------------------------------------- */
/* Attachments                                                               */
/* ------------------------------------------------------------------------- */

/// Where things pasted or dropped into the terminal land inside the sandbox.
///
/// The sandbox's own state directory rather than the workspace: a screenshot is not part of the
/// repository, the agent can read this path, and it survives with the session volume.
const ATTACHMENTS_DIR: &str = "/home/deepcode/.deepcode/attachments";

/// The largest attachment. These bytes travel through the app's memory and then through
/// `docker exec`'s stdin, so a dropped disk image should be a message rather than a hang.
const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;

/// A safe name for an attachment, prefixed so two pastes never collide.
///
/// The suggestion comes from a filename or from whatever the webview decided to call a pasted
/// image, so it is reduced to its last component and to characters that cannot mean anything to
/// a shell or a path.
fn attachment_name(suggested: &str, stamp: u64) -> String {
    let last = suggested
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("file")
        .to_string();
    let cleaned: String = last
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    let cleaned = cleaned.trim_matches('.').to_string();
    if cleaned.is_empty() {
        format!("{stamp}-file")
    } else {
        format!("{stamp}-{cleaned}")
    }
}

/// The container to put an attachment in, or an explanation of why there is none.
fn attachment_container(state: &AppState, project_id: &str) -> CmdResult<String> {
    state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(project_id)
        .map(|live| live.container_name.clone())
        .ok_or_else(|| {
            "There is no sandbox running for this project, so there is nowhere inside it to put \
             that. Start the project, then paste or drop it again."
                .to_string()
        })
}

/// Put bytes inside the running sandbox and return the path to type into the terminal.
fn put_attachment(
    state: &AppState,
    container: &str,
    suggested: &str,
    bytes: &[u8],
) -> CmdResult<String> {
    if bytes.len() as u64 > MAX_ATTACHMENT_BYTES {
        return Err(format!(
            "{} is {} MB, and the limit for something pasted or dropped in is {} MB.",
            suggested,
            bytes.len() / (1024 * 1024),
            MAX_ATTACHMENT_BYTES / (1024 * 1024)
        ));
    }
    let docker = state.docker().map_err(fail)?;
    let path = format!(
        "{ATTACHMENTS_DIR}/{}",
        attachment_name(suggested, deepsand_core::now_ms().max(0) as u64)
    );
    docker
        .make_dirs_in_container(container, ATTACHMENTS_DIR)
        .map_err(|err| format!("could not prepare the sandbox's attachments directory: {err}"))?;
    docker
        .write_into_container(container, &path, bytes)
        .map_err(|err| format!("could not write {suggested} into the sandbox: {err}"))?;
    Ok(path)
}

/// Attach paths from a drop: a file already inside the workspace is named where the sandbox
/// already sees it, and anything else is copied in.
pub fn attach_paths_impl(
    state: &AppState,
    project_id: &str,
    paths: Vec<String>,
) -> CmdResult<AttachmentView> {
    let project = store(state).project(project_id).map_err(fail)?.clone();
    let container = attachment_container(state, project_id)?;
    let root = std::fs::canonicalize(&project.root_dir).ok();
    let workspace_mount = deepsand_core::model::Project::workspace_mount();

    let mut view = AttachmentView {
        paths: Vec::new(),
        problems: Vec::new(),
    };

    for raw in paths {
        // Canonical first: a symlink or a `..` must not be able to name something outside the
        // workspace and be treated as if it were inside it.
        let Ok(canonical) = std::fs::canonicalize(&raw) else {
            view.problems.push(format!("{raw} could not be read"));
            continue;
        };

        // Already inside the workspace: the sandbox sees the same file, so the path it needs is
        // the mount path, and nothing is copied.
        if let Some(root) = &root {
            if let Ok(relative) = canonical.strip_prefix(root) {
                if !relative.as_os_str().is_empty() {
                    view.paths.push(format!(
                        "{workspace_mount}/{}",
                        relative.to_string_lossy().replace('\\', "/")
                    ));
                    continue;
                }
            }
        }

        let meta = match std::fs::metadata(&canonical) {
            Ok(meta) => meta,
            Err(err) => {
                view.problems.push(format!("{raw} could not be read: {err}"));
                continue;
            }
        };
        let name = canonical
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());

        if meta.is_dir() {
            // Copying a tree is a different feature with different questions (how big, how
            // deep, what to do about links), so this says so rather than half-doing it.
            view.problems.push(format!(
                "{name} is a directory. Drop a file, or put the directory in the project folder, \
                 where the sandbox can already see it."
            ));
            continue;
        }
        let bytes = match std::fs::read(&canonical) {
            Ok(bytes) => bytes,
            Err(err) => {
                view.problems.push(format!("{name} could not be read: {err}"));
                continue;
            }
        };
        match put_attachment(state, &container, &name, &bytes) {
            Ok(path) => view.paths.push(path),
            Err(err) => view.problems.push(err),
        }
    }

    Ok(view)
}

#[tauri::command]
pub fn attach_paths(
    state: State<'_, AppState>,
    project_id: String,
    paths: Vec<String>,
) -> CmdResult<AttachmentView> {
    attach_paths_impl(&state, &project_id, paths)
}

/// Attach bytes with no path of their own: what a pasted image or file gives the window.
pub fn attach_bytes_impl(
    state: &AppState,
    project_id: &str,
    name: String,
    base64_data: String,
) -> CmdResult<AttachmentView> {
    use base64::Engine as _;
    let container = attachment_container(state, project_id)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(base64_data.as_bytes())
        .map_err(|err| format!("{name} did not arrive intact: {err}"))?;

    let mut view = AttachmentView {
        paths: Vec::new(),
        problems: Vec::new(),
    };
    match put_attachment(state, &container, &name, &bytes) {
        Ok(path) => view.paths.push(path),
        Err(err) => view.problems.push(err),
    }
    Ok(view)
}

#[tauri::command]
pub fn attach_bytes(
    state: State<'_, AppState>,
    project_id: String,
    name: String,
    base64_data: String,
) -> CmdResult<AttachmentView> {
    attach_bytes_impl(&state, &project_id, name, base64_data)
}

/* ------------------------------------------------------------------------- */
/* Model                                                                     */
/* ------------------------------------------------------------------------- */

/// The dropdown's view of a project: what it runs, what configuration says, and what its API
/// offers.
fn model_view(state: &AppState, project_id: &str) -> CmdResult<ModelView> {
    let (chosen, configured, running) = {
        let store = store(state);
        let project = store.project(project_id).map_err(fail)?.clone();
        let app = store.settings().clone();
        let host = credentials::read_host_config();
        let resolved = credentials::resolve(&project, &app, &host);
        let running = state
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(project_id);
        (
            project
                .credentials
                .model
                .clone()
                .filter(|model| !model.trim().is_empty()),
            resolved.model,
            running,
        )
    };

    let options = state
        .models
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .map(|(_, choices)| choices.clone())
        .unwrap_or_default();

    Ok(ModelView {
        project_id: project_id.to_string(),
        deferring: chosen.is_none(),
        value: chosen,
        configured,
        options,
        problem: None,
        // A plain read pushed nothing; the setter overrides this.
        applied_live: false,
        restart_needed: running,
    })
}

pub fn get_model_impl(state: &AppState, project_id: &str) -> CmdResult<ModelView> {
    model_view(state, project_id)
}

#[tauri::command]
pub fn get_model(state: State<'_, AppState>, project_id: String) -> CmdResult<ModelView> {
    get_model_impl(&state, &project_id)
}

/// Choose the model, or go back to deferring.
///
/// Saved and pushed in one step, like the thinking switch, so what the operator sees is what is
/// on disk. DeepCode reads its configuration when it starts, so a conversation already in
/// progress keeps the model it began with until the sandbox is restarted.
pub fn set_model_impl(
    state: &AppState,
    project_id: &str,
    model: Option<String>,
) -> CmdResult<ModelView> {
    let value = model
        .map(|model| model.trim().to_string())
        .filter(|model| !model.is_empty());

    {
        let mut store = store(state);
        let project = store.project_mut(project_id).map_err(fail)?;
        project.credentials.model = value.clone();
        store.save().map_err(fail)?;
    }

    let applied_live = push_live_settings(state, project_id)?;
    let mut view = model_view(state, project_id)?;
    view.applied_live = applied_live;
    view.restart_needed = view.restart_needed && !applied_live;
    Ok(view)
}

#[tauri::command]
pub fn set_model(
    state: State<'_, AppState>,
    project_id: String,
    model: Option<String>,
) -> CmdResult<ModelView> {
    set_model_impl(&state, &project_id, model)
}

/// Ask the project's own API which models it offers.
///
/// The request is made here rather than in the window because it is signed with the API key,
/// and that key belongs to the sandbox's configuration rather than to the frontend. A list that
/// cannot be read is not an error the operator has to act on: the answer comes back with
/// `problem` set, so the dropdown still offers the two choices that need no list at all.
pub async fn list_models_impl(state: &AppState, project_id: &str) -> CmdResult<ModelView> {
    let (base_url, api_key) = {
        let store = store(state);
        let project = store.project(project_id).map_err(fail)?.clone();
        let app = store.settings().clone();
        let host = credentials::read_host_config();
        let resolved = credentials::resolve(&project, &app, &host);
        (resolved.base_url.trim().to_string(), resolved.api_key)
    };

    let mut view = model_view(state, project_id)?;
    if base_url.is_empty() {
        view.problem = Some(
            "No base URL is configured for this project's API, so its models cannot be listed."
                .into(),
        );
        return Ok(view);
    }
    let Some(api_key) = api_key.filter(|key| !key.trim().is_empty()) else {
        view.problem = Some(
            "No API key is configured for this project's API, so its models cannot be listed. \
             Custom still works: type a model name and it is used as it is."
                .into(),
        );
        return Ok(view);
    };

    // The key is digested, never kept: this cache exists to avoid repeating a request, not to
    // hold a second copy of a secret.
    let cache_key = format!(
        "{base_url}|{}",
        deepsand_core::seccomp::digest(api_key.as_bytes())
    );
    {
        let cached = state.models.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((key, choices)) = cached.as_ref() {
            if *key == cache_key && !choices.is_empty() {
                view.options = choices.clone();
                return Ok(view);
            }
        }
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            view.problem = Some(format!("could not prepare the request: {err}"));
            return Ok(view);
        }
    };

    let mut problem = None;
    for url in deepsand_core::models::model_endpoints(&base_url) {
        match client
            .get(&url)
            .bearer_auth(&api_key)
            .header("accept", "application/json")
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                let choices = deepsand_core::models::parse_models(&body);
                if status.is_success() && !choices.is_empty() {
                    *state.models.lock().unwrap_or_else(|p| p.into_inner()) =
                        Some((cache_key.clone(), choices.clone()));
                    view.options = choices;
                    return Ok(view);
                }
                // Why it failed decides what to advise: no enumeration at all is a reason to
                // use Custom, a refused key is a reason to fix the key.
                problem = Some(deepsand_core::models::listing_problem(&url, status.as_u16(), &body));
            }
            Err(err) => {
                problem = Some(format!("{url} could not be reached: {err}"));
            }
        }
    }

    tracing::warn!("could not list models for {project_id}: {problem:?}");
    view.problem = Some(
        problem.unwrap_or_else(|| "the model list could not be read".to_string())
            + ". Custom still works: type a model name and it is used as it is.",
    );
    Ok(view)
}

#[tauri::command]
pub async fn list_models(state: State<'_, AppState>, project_id: String) -> CmdResult<ModelView> {
    list_models_impl(&state, &project_id).await
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

/// The argument that tells a background launch apart from a normal one.
///
/// The operating system starts the same binary either way: "in the background" is this one word
/// rather than a second program.
pub const BACKGROUND_ARG: &str = "--minimized";

/// Whether this process was started by the operating system in the background.
pub fn started_in_background() -> bool {
    std::env::args().any(|arg| arg == BACKGROUND_ARG)
}

/// The binary to register, which is this executable, and how it should start.
fn autostart_entry(mode: StartupMode) -> Result<auto_launch::AutoLaunch, String> {
    let exe = std::env::current_exe()
        .map_err(|err| format!("could not locate the Deepsand binary: {err}"))?;
    let mut builder = auto_launch::AutoLaunchBuilder::new();
    builder
        .set_app_name("Deepsand")
        .set_app_path(&exe.to_string_lossy())
        // macOS has no equivalent of a Run key, so this is ignored elsewhere.
        .set_use_launch_agent(true);
    if mode.starts_hidden() {
        // The app shows its window unless it is told not to, so `Background` is the same binary
        // with one argument rather than a second way of running.
        builder.set_args(&[BACKGROUND_ARG]);
    }
    builder
        .build()
        .map_err(|err| format!("could not prepare the autostart entry: {err}"))
}

/// The startup mode, as the operating system and the settings file agree on it.
///
/// The operating system is the truth for *whether* there is an entry -- an operator who removes
/// it by hand should see that rather than being contradicted -- and the settings file is the
/// truth for *how* it starts, which the OS cannot express beyond the argument it was given.
pub fn startup_mode_impl(state: &AppState) -> CmdResult<String> {
    let entry = autostart_entry(StartupMode::Foreground)?;
    let enabled = entry
        .is_enabled()
        .map_err(|err| format!("could not read the autostart state: {err}"))?;
    if !enabled {
        return Ok(StartupMode::Off.as_str().to_string());
    }
    let stored = store(state).settings().startup;
    // An entry that exists while the setting says off was written by something else, or before
    // there was a mode to store: showing it as foreground is what it will actually do.
    let mode = if stored.is_on() {
        stored
    } else {
        StartupMode::Foreground
    };
    Ok(mode.as_str().to_string())
}

pub fn set_startup_mode_impl(state: &AppState, mode: StartupMode) -> CmdResult<String> {
    // Cleared first, always: an entry already there carries the arguments of the mode it was
    // made for, and enabling over it would keep them -- which is how "start hidden" would
    // outlive being turned off.
    autostart_entry(StartupMode::Off)?
        .disable()
        .map_err(|err| format!("could not remove the old startup entry ({err})"))?;
    if mode.is_on() {
        autostart_entry(mode)?.enable().map_err(|err| {
            format!(
                "could not add Deepsand to your startup items ({err}). On Linux this needs a \
                 desktop session with a writable autostart directory."
            )
        })?;
    }

    // Only stored once the machine has accepted it, so the setting and the machine agree.
    {
        let mut store = store(state);
        store.settings_mut().startup = mode;
        store.save().map_err(fail)?;
    }
    Ok(mode.as_str().to_string())
}

#[tauri::command]
pub fn get_startup_mode(state: State<'_, AppState>) -> CmdResult<String> {
    startup_mode_impl(&state)
}

#[tauri::command]
pub fn set_startup_mode(state: State<'_, AppState>, mode: String) -> CmdResult<String> {
    let mode =
        StartupMode::from_str(&mode).ok_or_else(|| format!("unknown startup mode {mode:?}"))?;
    set_startup_mode_impl(&state, mode)
}

/// Whether closing the window hides Deepsand instead of stopping it.
pub fn closes_to_tray(state: &AppState) -> bool {
    store(state).settings().close_to_tray
}

/// Set that, and put the tray icon where it is now needed -- or take it away.
#[tauri::command]
pub fn set_close_to_tray(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> CmdResult<bool> {
    {
        let mut store = store(state.inner());
        store.settings_mut().close_to_tray = enabled;
        store.save().map_err(fail)?;
    }
    crate::tray::set_visible(&app, enabled);
    Ok(enabled)
}

/// Ask the registries now, whatever the cadence says.
///
/// This is the button in Settings: the operator asking rather than the app deciding, so it works
/// whether or not the automatic checks are turned on.
#[tauri::command]
pub fn check_tool_updates_now(app: tauri::AppHandle) -> CmdResult<Vec<String>> {
    Ok(crate::tool_updates::check(app, true))
}

#[tauri::command]
pub fn host_config_summary() -> CmdResult<std::collections::BTreeMap<String, String>> {
    Ok(credentials::describe_host_config(&credentials::read_host_config()))
}

#[tauri::command]
pub async fn build_runtime_image(
    app: AppHandle,
    project_id: Option<String>,
    build_tools: Option<bool>,
) -> CmdResult<()> {
    // Async: a build takes minutes, and a sync command runs on the main thread -- one Build click
    // used to freeze the entire window for the whole build.
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = tauri::Manager::state::<AppState>(&handle);
        build_runtime_image_impl(&handle, &state, project_id, build_tools, false)
    })
    .await
    .map_err(|err| format!("the build could not be started: {err}"))?
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
    // Build with no tools selected at all. This is the image a sandbox can start on immediately:
    // the runtime and the DeepCode CLI, but none of the tools being compiled. `Some(&[])` is a
    // meaningful selection rather than a missing one, and it hashes to its own tag, so this is a
    // different image from the one the project will end up with.
    no_tools: bool,
) -> CmdResult<()> {

    let docker = state.docker().map_err(fail)?;
    let selection = if no_tools {
        Some(Vec::new())
    } else {
        match &project_id {
            Some(id) => store(&state).project(id).map_err(fail)?.tools.clone(),
            // No project named: build the defaults, which is what a first-run build is.
            None => None,
        }
    };
    let image = container_settings::settings_for_project(store(&state).settings(), selection.as_deref()).image;

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
    // Owned, because the build runs on a thread that cannot borrow the state.
    let data_dir = store(&state).data_dir().to_path_buf();

    // One build per image, enforced here because everything that builds goes through this
    // function: the Activity tab's button, and a Run whose image is missing. Two builds of
    // one image share a tag and one build log file, and the log from a real failure has two
    // copies of the same RPC error in it at different offsets -- the second copy is the
    // second writer, with a gap of NULs where it skipped ahead.
    //
    // A caller that arrives second *waits* rather than failing: it is usually a Run, and its
    // image is being built right now by the build the operator started a moment earlier.
    if !begin_build(state, &image) {
        let line = format!(
            "a build of {image} is already running; waiting for it instead of starting another"
        );
        let _ = app.emit(events::BUILD_LOG, serde_json::json!({ "line": line }));
        // Half an hour: a tooled image with a Rust CLI in it takes minutes, and a build that
        // has stopped making progress is what the timeout is for.
        if !wait_for_build(state, &image, std::time::Duration::from_secs(1800)) {
            return Err(format!(
                "a build of {image} is already running and has not finished; it may be stuck. \
                 Its output is in the Activity tab."
            ));
        }
        // The build that was running may have failed. Its image either exists now or the
        // caller is about to need one that does not.
        if !state.docker().map_err(fail)?.image_present(&image) {
            return Err(format!(
                "the build of {image} that was already running finished without producing the \
                 image. Its output is in the Activity tab."
            ));
        }
        return Ok(());
    }

    let app_handle = AppHandle::clone(app);
    std::thread::spawn(move || {
        let app_for_log = AppHandle::clone(&app_handle);
        let image_for_event = image.clone();
        // Truncated per build: the previous build's output is not context, it is noise. The
        // header names the build, so a log that was cut short is still identifiable, and
        // every line is flushed: the log's whole job is to survive the failure it describes.
        let log = std::sync::Mutex::new(open_build_log(&log_path, &image, &build_args));

        // `flush` on a `File` is a no-op -- the bytes are already with the OS -- so the only
        // thing that makes this durable is the sync before the outcome is announced, below.
        let write = |line: &str| {
            if let Ok(mut guard) = log.lock() {
                if let Some(file) = guard.as_mut() {
                    use std::io::Write as _;
                    let _ = writeln!(file, "{line}");
                }
            }
        };
        if log.lock().map(|guard| guard.is_none()).unwrap_or(false) {
            let _ = app_for_log.emit(
                events::BUILD_LOG,
                serde_json::json!({
                    "line": format!(
                        "the build log could not be written to {}; output follows in this window only",
                        log_path.display()
                    )
                }),
            );
        }

        // Before anything is built: the files it is built from are read from disk, and this has
        // been a machine that lost the contents of writes while keeping their sizes. An
        // installed Dockerfile of 18,412 NULs is answered by Docker with `dockerfile parse
        // error on line 1: unknown instruction:`, which names nothing an operator can act on
        // and cannot be fixed by trying again. The bytes this build carries are the repair.
        match deepsand_core::runtime_files::repair(&context) {
            Ok(repaired) if !repaired.is_empty() => {
                let line = format!(
                    "the runtime files in {} were damaged -- the size of a write survived, its \
                     contents did not -- and have been repaired from this build's own copy: {}",
                    context.display(),
                    repaired.join(", ")
                );
                write(&line);
                tracing::warn!("{line}");
                let _ = app_for_log.emit(events::BUILD_LOG, serde_json::json!({ "line": line }));
            }
            Ok(_) => {}
            Err(err) => {
                let detail = format!(
                    "{err}\n\nThe files the image is built from are unreadable and could not be \
                     repaired from this build's own copy. Reinstalling Deepsand replaces them."
                );
                write(&detail);
                let state = tauri::Manager::state::<AppState>(&app_handle);
                end_build(&state, &image);
                let _ = app_handle.emit(
                    events::BUILD_DONE,
                    serde_json::json!({ "ok": false, "detail": detail }),
                );
                return;
            }
        }

        // A build that dies because the daemon went away is retried once, after the daemon
        // comes back. The layer cache survives it, so the second attempt resumes rather than
        // starting over -- and the alternative is an operator reading an RPC error and
        // clicking the button again, which is what this failure used to cost.
        let mut attempt = 0;
        // Filled by the loop below and read after it: the tools are copied into this directory
        // once the outcome is known.
        // Bound outside the retry loop below, which always assigns it before anything reads
        // it: the initial value exists only because it has to be bound out here.
        #[allow(unused_assignments)]
        let mut tool_cache = std::path::PathBuf::new();
        let result = loop {
            attempt += 1;
            // The tools cache for this build. The key covers the platform, the selection and a
    // fingerprint of the install steps; freshness covers the one thing a key cannot see, which
    // is time passing. An entry that is stale is emptied rather than deleted: the directory is
    // the build context, so it has to exist either way.
    tool_cache = {
        let arch = docker.server_platform().unwrap_or_default();
        let selection: Vec<String> = plan
            .apt
            .iter()
            .chain(plan.npm.iter())
            .chain(plan.cargo.iter())
            .cloned()
            .collect();
        let fingerprint = std::fs::read_to_string(context.join("Dockerfile"))
            .map(|dockerfile| deepsand_core::toolcache::tools_layer_fingerprint(&dockerfile))
            .unwrap_or_default();
        let key = deepsand_core::toolcache::cache_key(&arch, &selection, &fingerprint);
        // One call, because the age rule and the emptying are the same rule: the version in the
        // caller logged it and moved on, and the stale entry was copied in anyway.
        let dir = deepsand_core::toolcache::prepare_entry(&data_dir, &key, deepsand_core::now_ms());
        if !dir.join(deepsand_core::toolcache::FILLED_MARKER).exists() {
            tracing::debug!("no tools cache for this key yet; this build installs and fills one");
        }
        dir
    };

    let outcome = docker.build(&context, &image, &build_args, &tool_cache, |line| {
                write(&line);
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
            match outcome {
                Err(err)
                    if attempt == 1
                        && !deepsand_core::docker::is_our_own_stop(&err.to_string())
                        && deepsand_core::docker::is_daemon_interruption(&err.to_string()) =>
                {
                    let line = "the Docker daemon stopped answering during the build. That is not \
                                the Dockerfile's doing and the layer cache survives it, so this is \
                                being retried once after the daemon comes back.";
                    write(line);
                    let _ = app_for_log.emit(events::BUILD_LOG, serde_json::json!({ "line": line }));
                    if wait_for_daemon(&docker, std::time::Duration::from_secs(180), &write) {
                        let line = "the daemon is answering again; retrying the build";
                        write(line);
                        let _ =
                            app_for_log.emit(events::BUILD_LOG, serde_json::json!({ "line": line }));
                        continue;
                    }
                    break Err(format!(
                        "{err}\n\nThe Docker daemon stopped answering mid-build and did not come \
                         back within three minutes. Nothing is wrong with the image or the \
                         project: start Docker again and build once more."
                    ));
                }
                other => break other.map_err(|err| err.to_string()),
            }
        };

        // The tools cache, decided by the outcome.
        //
        // Filled only from a build that actually produced the tools, and emptied only when a
        // build *used* it and failed for a reason that is about the build rather than about
        // Docker -- a daemon that went away is neither the cache's fault nor the build's, and
        // emptying on one of those would throw away minutes of compiling for nothing.
        match &result {
            Ok(()) => {
                let line = if fill_tool_cache(&docker, &image, &tool_cache) {
                    "deepsand: the tools cache was filled from this build"
                } else {
                    "deepsand: could not fill the tools cache; the next build installs again"
                };
                write(line);
                let _ = app_handle.emit(events::BUILD_LOG, serde_json::json!({ "line": line }));
            }
            Err(err) => {
                let used = tool_cache
                    .join(deepsand_core::toolcache::FILLED_MARKER)
                    .exists();
                if used
                    && !deepsand_core::docker::is_daemon_interruption(err)
                    && !deepsand_core::docker::is_our_own_stop(err)
                {
                    empty_tool_cache(&tool_cache);
                    let line = "deepsand: the build failed while using cached tools, so the cache \
                                was emptied and the next build installs them again";
                    write(line);
                    let _ =
                        app_handle.emit(events::BUILD_LOG, serde_json::json!({ "line": line }));
                }
            }
        }

        // Sandboxes that started before their tools existed: copy them in now. Only on success,
        // and only into a session that is still running -- a project stopped since gets the tools
        // from the image the next time it starts.
        if result.is_ok() {
            let waiting: Vec<String> = {
                let state = tauri::Manager::state::<AppState>(&app_handle);
                let mut queue = state.tools_arriving.lock().unwrap_or_else(|p| p.into_inner());
                queue.remove(&image).unwrap_or_default()
            };
            for project_id in waiting {
                let state = tauri::Manager::state::<AppState>(&app_handle);
                let container = state
                    .sessions
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&project_id)
                    .map(|live| live.container_name.clone());
                let Some(container) = container else {
                    continue;
                };
                let copied = docker
                    .copy_into_container(&container, &tool_cache.join("bin"), "/usr/local/bin")
                    .and_then(|_| {
                        docker.copy_into_container(
                            &container,
                            &tool_cache.join("node_modules"),
                            "/usr/local/lib/node_modules",
                        )
                    })
                    .is_ok();
                let line = if copied {
                    "deepsand: the tools finished building and were copied into the running sandbox"
                } else {
                    "deepsand: the tools finished building but could not be copied in; restart the project to pick them up"
                };
                write(line);
                let _ = app_handle.emit(events::BUILD_LOG, serde_json::json!({ "line": line }));
                if copied {
                    let _ = app_handle.emit(
                        events::TOOLS_ARRIVED,
                        serde_json::json!({ "projectId": project_id, "image": image }),
                    );
                }
            }
        }

        // The image is no longer being built, whatever happened.
        end_build(&tauri::Manager::state::<AppState>(&app_handle), &image);

        // Pushed to disk before the outcome is announced. The log's whole job is to be read
        // after a failure -- including a failure that takes the machine with it -- and up to
        // this point it has only reached the OS's cache.
        if let Ok(guard) = log.lock() {
            if let Some(file) = guard.as_ref() {
                let _ = file.sync_data();
            }
        }
        let _ = app_handle.emit(
            events::BUILD_DONE,
            match result {
                Ok(()) => serde_json::json!({ "ok": true, "image": image }),
                Err(err) => serde_json::json!({
                    "ok": false,
                    "detail": format!("{err}{}", log_note(&log_path, &log)),
                }),
            },
        );
    });

    let _ = build_tools;
    Ok(())
}

/// Copy the tools an image has just built into the cache for its key.
///
/// A container made from the image itself, with the cache directory mounted, so what lands in
/// the cache is exactly what that image has -- the property that keeps the cache honest. Filling
/// it from a parallel install would be faster and would eventually disagree with the image.
///
/// Returns whether it worked. A failure here costs the next build its speed; it never touches
/// the build that has just succeeded, which is why the caller only writes a line about it.
fn fill_tool_cache(
    docker: &deepsand_core::docker::Docker,
    image: &str,
    dir: &std::path::Path,
) -> bool {
    let script = "mkdir -p /cache/bin /cache/node_modules \
                  && cp -a /usr/local/bin/. /cache/bin/ \
                  && cp -a /usr/local/lib/node_modules/. /cache/node_modules/ \
                  && { npm ls -g --depth=0 --json > /cache/versions-npm.json 2>/dev/null || true; } \
                  && { cargo install --list > /cache/versions-cargo.txt 2>/dev/null || true; }";
    let args: Vec<String> = [
        "run",
        "--rm",
        "-v",
        &format!("{}:/cache", dir.display()),
        "--entrypoint",
        "/bin/sh",
        image,
        "-c",
        script,
    ]
    .iter()
    .map(|part| part.to_string())
    .collect();
    if let Err(err) = docker.run(&args) {
        tracing::warn!(%err, "could not fill the tools cache");
        return false;
    }
    // The marker is written by the app, not the container: the rule that reads it runs on the
    // host's clock, and one clock is enough.
    deepsand_core::toolcache::mark_filled(dir, deepsand_core::now_ms()).is_ok()
}

/// Whether the operator wants Deepsand asking the registries about cached tools.
pub fn tool_updates_enabled(state: &AppState) -> bool {
    store(state).settings().check_tool_updates
}

/// Where cache entries live, for the check that reads them.
pub fn tool_cache_root(state: &AppState) -> std::path::PathBuf {
    store(state).data_dir().join("buildcache")
}

/// Empty a cache entry, keeping the directory the build context points at.
///
/// The rule itself lives in `toolcache::clear_entry`, next to the age limit that calls it; this
/// is the name the app's own paths use.
pub(crate) fn empty_tool_cache(dir: &std::path::Path) {
    deepsand_core::toolcache::clear_entry(dir);
}

/// Claim an image for building. False means somebody else has it.
fn begin_build(state: &AppState, image: &str) -> bool {
    state
        .building
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(image.to_string())
}

/// Release an image, whatever the build did.
fn end_build(state: &AppState, image: &str) {
    state
        .building
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(image);
}

/// Wait for a build that is already running to release its image.
///
/// Returns false if it is still running when the budget runs out, which is the only honest
/// thing to say about a build that has stopped reporting progress.
fn wait_for_build(state: &AppState, image: &str, budget: std::time::Duration) -> bool {
    let started = std::time::Instant::now();
    loop {
        let busy = state
            .building
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(image);
        if !busy {
            return true;
        }
        if started.elapsed() >= budget {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

/// Start a build log, with a header naming the build it belongs to.
///
/// The header is not decoration: without it, a log that was truncated by a crash or filled
/// by a second writer cannot be told from one that simply ends, and this file has been both.
fn open_build_log(
    path: &Path,
    image: &str,
    build_args: &[(&str, String)],
) -> Option<std::fs::File> {
    use std::io::Write as _;

    let mut file = std::fs::File::create(path).ok()?;
    let _ = writeln!(file, "Deepsand runtime image build");
    let _ = writeln!(file, "  started (epoch ms): {}", deepsand_core::now_ms());
    let _ = writeln!(file, "  image             : {image}");
    for (key, value) in build_args {
        let _ = writeln!(file, "  {key}={value}");
    }
    let _ = writeln!(file, "--- docker build output ---");
    let _ = file.flush();
    Some(file)
}

/// What to append to a failure about the log file: only promise a log that exists.
fn log_note(path: &Path, log: &std::sync::Mutex<Option<std::fs::File>>) -> String {
    match log.lock() {
        Ok(guard) if guard.is_some() => format!("\n\nThe full build log is {}.", path.display()),
        _ => format!(
            "\n\n(The build log at {} could not be written; the output is above.)",
            path.display()
        ),
    }
}

/// Wait for the Docker daemon to answer again, up to `budget`.
///
/// One `docker version` per attempt rather than a full probe: this is a liveness question,
/// and a probe is three CLI invocations.
fn wait_for_daemon(
    docker: &deepsand_core::docker::Docker,
    budget: std::time::Duration,
    note: &impl Fn(&str),
) -> bool {
    let started = std::time::Instant::now();
    let mut announced = false;
    loop {
        let args = vec![
            "version".to_string(),
            "--format".to_string(),
            "{{.Server.Version}}".to_string(),
        ];
        if docker.try_run(&args).is_some_and(|out| !out.is_empty()) {
            return true;
        }
        if started.elapsed() >= budget {
            return false;
        }
        if !announced {
            note("waiting for the Docker daemon to come back…");
            announced = true;
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}

/// Locate the `runtime/` directory (Dockerfile, entrypoint, MCP bridge).
///
/// The packaged installer ships it as a bundle resource, which lands next to the
/// executable; a `cargo run`/`tauri dev` session finds it in the source tree. The
/// `_up_` variants cover Tauri's escaping convention for resources sourced from
/// outside `src-tauri/`.
/// Locate the `runtime/` directory (Dockerfile, entrypoint, MCP bridge, seccomp profile).
///
/// Delegates to the core so this, the profile resolver and the headless CLI cannot
/// disagree about which tree the runtime lives in.
fn runtime_context_dir() -> Option<PathBuf> {
    deepsand_core::seccomp::runtime_dir()
}

/// Remove managed containers, volumes and networks that no live project owns.
#[tauri::command]
pub async fn cleanup_orphans(app: AppHandle) -> CmdResult<Vec<String>> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = tauri::Manager::state::<AppState>(&handle);
        cleanup_orphans_impl(&state)
    })
    .await
    .map_err(|err| format!("orphans could not be cleaned up: {err}"))?
}

/// Everything to do before the process goes away.
///
/// Called from both the window-destroyed handler and `RunEvent::Exit`, so it has to be
/// safe to run twice: every step is idempotent, and every step is best-effort. Failing
/// to clean up must never be the reason the app will not close.
pub fn shutdown_cleanup(state: &AppState) {
    // Anything the polite shutdown could not finish is ended here, before this function
    // returns: the app is about to exit, and on Windows nothing else will. This is what stops a
    // `docker build` that has stopped answering from outliving the app that started it and
    // holding the image tag the next build waits on -- one was found still running an hour and
    // a half later.
    let stopped = deepsand_core::docker::terminate_our_clients();
    if !stopped.is_empty() {
        tracing::warn!(?stopped, "ended docker clients that were still running");
    }

    let project_ids: Vec<String> = {
        let store = store(state);
        store.projects().iter().map(|project| project.id.clone()).collect()
    };
    // Which projects were running, recorded before anything is stopped: this is what the
    // per-project "resume on application start" setting acts on, and this is the last moment that
    // knows. Written for every project, changed or not, because a project stopped by hand this
    // session has to be remembered as stopped.
    {
        let mut store = store(state);
        let mut changed = false;
        for project_id in &project_ids {
            let running = state
                .sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key(project_id);
            if let Ok(project) = store.project_mut(project_id) {
                if project.was_running != running {
                    project.was_running = running;
                    changed = true;
                }
            }
        }
        if changed {
            if let Err(err) = store.save() {
                tracing::warn!(%err, "could not record which projects were running");
            }
        }
    }

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
pub fn log_ui_event(level: String, message: String) -> CmdResult<()> {
    log_ui_event_impl(&level, &message)
}

/// Write something the window showed the operator into the app's log.
///
/// Error boxes are the app's own account of what went wrong, and they existed only as a toast
/// in the webview: dismissed by a click, gone when the window closed, and impossible to paste
/// into a bug report. This is the one place they become durable, and it takes the text the
/// operator actually saw rather than a re-derivation of it.
///
/// The message is filtered the same way build output is: a log whose purpose is to be read
/// should not be filled by a read that did not happen.
pub fn log_ui_event_impl(level: &str, message: &str) -> CmdResult<()> {
    let message = deepsand_core::docker::sanitize_output_line(message).unwrap_or_default();
    if message.trim().is_empty() {
        return Ok(());
    }
    match level {
        "error" => tracing::error!("[window] {message}"),
        "warn" => tracing::warn!("[window] {message}"),
        _ => tracing::info!("[window] {message}"),
    }
    Ok(())
}

/// Where the app writes what it says about itself, so the window can offer it.
#[tauri::command]
pub fn log_file_path(state: State<'_, AppState>) -> CmdResult<String> {
    log_file_path_impl(&state)
}

pub fn log_file_path_impl(state: &AppState) -> CmdResult<String> {
    Ok(store(&state).data_dir().join("deepsand.log").display().to_string())
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
