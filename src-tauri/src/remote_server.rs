//! The HTTP surface that exposes the GUI to another device.
//!
//! Binds loopback by default, requires a bearer token on every API call, and
//! answers each request by calling the same `*_impl` function the desktop commands
//! call. Nothing here reimplements any behaviour; it only decides whether a caller
//! is allowed to reach it, using `deepsand_core::remote`.
//!
//! The UI is served from the same origin as the API, so the browser needs no CORS
//! exemption and the token never appears in a cross-origin request.
//!
//! # What is deliberately not here
//!
//! * No TLS in this pass. The intended deployment is a reverse proxy on the same
//!   machine terminating TLS, which is also where real authentication belongs;
//!   `RemoteTls::SelfSigned` is accepted by the settings model and reported as
//!   unsupported rather than silently treated as plain HTTP.
//! * No way to change the remote configuration over HTTP. Those commands are not
//!   in the authorization table at all, so a leaked token cannot widen its own
//!   reach or rotate itself away from the operator.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Query, State as AxumState};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use deepsand_core::remote::{self, RemoteDenial, RemoteScope, RemoteServerConfig, RemoteTls};
use futures_util::stream::Stream;
use serde::Deserialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager};
use tower_http::services::{ServeDir, ServeFile};

use crate::commands;
use crate::state::{events, AppState};

/// One event forwarded to remote subscribers.
#[derive(Debug, Clone)]
pub struct RemoteEvent {
    pub event: String,
    pub payload: Value,
}

/// A running server, kept in `AppState` so it can be stopped and inspected.
pub struct RunningServer {
    pub config: RemoteServerConfig,
    pub addr: SocketAddr,
    pub task: tauri::async_runtime::JoinHandle<()>,
}

impl RunningServer {
    pub fn stop(&self) {
        self.task.abort();
    }
}

#[derive(Debug, Deserialize)]
pub struct CommandRequest {
    pub command: String,
    #[serde(default)]
    pub args: Value,
}

#[derive(Debug, Deserialize)]
struct TokenQuery {
    /// Present only so an SSE connection, which cannot set headers from the browser
    /// EventSource API, has a way to authenticate. See the note in `authorize`.
    token: Option<String>,
}

#[derive(Clone)]
struct ServerCtx {
    app: AppHandle,
    server: Arc<RemoteServerConfig>,
    failures: Arc<Mutex<HashMap<SocketAddr, Failure>>>,
    /// Taken from the settings when the server starts, so the counter and the
    /// setting cannot disagree.
    lockout_after_failures: u32,
}

/// Failed attempts from one address, and when the last one was.
#[derive(Debug, Clone, Copy)]
struct Failure {
    count: u32,
    last: Instant,
}

/// How long a lockout lasts once it is reached.
///
/// Long enough that guessing is hopeless, short enough that an operator who
/// mistypes their own token is not shut out for the afternoon. Successful
/// authentication clears the record outright.
const LOCKOUT_COOLDOWN: Duration = Duration::from_secs(300);

/// Whether this address has exhausted its attempts.
fn is_locked_out(failures: &Arc<Mutex<HashMap<SocketAddr, Failure>>>, peer: SocketAddr, limit: u32) -> bool {
    if limit == 0 {
        // Zero means "do not lock anyone out", which an operator may want on a
        // loopback-only server where the token is a formality.
        return false;
    }
    let mut guard = failures.lock().unwrap_or_else(|p| p.into_inner());
    match guard.get(&peer) {
        Some(failure) if failure.count >= limit => {
            if failure.last.elapsed() >= LOCKOUT_COOLDOWN {
                // Cooldown elapsed: forget it, so the address gets a fresh budget
                // rather than being locked out permanently.
                guard.remove(&peer);
                false
            } else {
                true
            }
        }
        _ => false,
    }
}

fn record_failure(failures: &Arc<Mutex<HashMap<SocketAddr, Failure>>>, peer: SocketAddr) {
    let mut guard = failures.lock().unwrap_or_else(|p| p.into_inner());
    let entry = guard.entry(peer).or_insert(Failure { count: 0, last: Instant::now() });
    entry.count += 1;
    entry.last = Instant::now();
    // Bound the map: a hostile client with many addresses must not grow it without
    // limit. Anything this old is past the cooldown anyway.
    if guard.len() > 256 {
        let stale: Vec<SocketAddr> = guard
            .iter()
            .filter(|(_, failure)| failure.last.elapsed() > LOCKOUT_COOLDOWN)
            .map(|(addr, _)| *addr)
            .collect();
        for addr in stale {
            guard.remove(&addr);
        }
    }
}

fn clear_failures(failures: &Arc<Mutex<HashMap<SocketAddr, Failure>>>, peer: SocketAddr) {
    failures
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&peer);
}

/// A self-signed certificate for this machine, generated once and cached.
///
/// Cached rather than regenerated per start, because a browser that was told to trust
/// the certificate would otherwise have to be told again every time Deepsand restarts.
///
/// The subject alternative names cover loopback and the local hostname, which is what
/// an operator on the same network actually types. They do **not** cover every address
/// the machine might have: a certificate is for names, and pretending otherwise would
/// mean a certificate that silently fails to match.
fn self_signed_config(app: &AppHandle, bound: SocketAddr) -> Result<axum_server::tls_rustls::RustlsConfig, String> {
    let data_dir = {
        let state = tauri::Manager::state::<crate::state::AppState>(app);
        let store = state.store.lock().unwrap_or_else(|p| p.into_inner());
        store.data_dir().to_path_buf()
    };
    let dir = data_dir.join("tls");
    std::fs::create_dir_all(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    let cert_path = dir.join("deepsand-cert.pem");
    let key_path = dir.join("deepsand-key.pem");

    if !cert_path.is_file() || !key_path.is_file() {
        let hostname = hostname();
        let mut names = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
        if let Some(name) = hostname.clone() {
            names.push(name);
        }
        // The address it is actually bound to, when it is a specific one, so the
        // certificate matches what the operator was told to visit.
        if !bound.ip().is_loopback() && !bound.ip().is_unspecified() {
            names.push(bound.ip().to_string());
        }

        let generated = rcgen::generate_simple_self_signed(names)
            .map_err(|err| format!("could not generate a self-signed certificate: {err}"))?;
        std::fs::write(&cert_path, generated.cert.pem())
            .map_err(|err| format!("could not write the certificate: {err}"))?;
        std::fs::write(&key_path, generated.key_pair.serialize_pem())
            .map_err(|err| format!("could not write the certificate key: {err}"))?;
        // The key is private, even though the certificate is not.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }
    }

    // Built inside the runtime, because `from_pem_file` needs one.
    let cert = cert_path.clone();
    let key = key_path.clone();
    tauri::async_runtime::block_on(async move {
        axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .map_err(|err| {
                format!(
                    "the TLS certificate at {} could not be loaded ({err}). Delete the 'tls' folder in \
                     the Deepsand data directory to have one generated again.",
                    dir.display()
                )
            })
    })
}

/// The machine's hostname, when the OS will give it up.
fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .map(|name| name.trim().to_lowercase())
        .filter(|name| !name.is_empty())
}

/// Start one server. Returns the bound address so the UI can show what it is
/// listening on, which matters when the port was requested as 0.
pub async fn start(
    app: &AppHandle,
    config: RemoteServerConfig,
    lockout_after_failures: u32,
) -> Result<RunningServer, String> {
    let addr: SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .map_err(|_| format!("'{}:{}' is not a usable address", config.bind, config.port))?;

    // A std listener, because `axum-server` takes one; it is made non-blocking and
    // handed to tokio by the TLS path.
    let listener = std::net::TcpListener::bind(addr)
        .map_err(|err| format!("could not listen on {addr}: {err}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("could not set the listener to non-blocking: {err}"))?;
    let bound = listener
        .local_addr()
        .map_err(|err| format!("could not read the bound address: {err}"))?;

    // Prepared before the task starts, so a certificate problem is reported to the
    // operator rather than appearing as a server that quietly never comes up.
    let tls_config = match config.tls {
        RemoteTls::Off => None,
        RemoteTls::SelfSigned => Some(self_signed_config(app, bound)?),
    };

    let ctx = ServerCtx {
        app: app.clone(),
        server: Arc::new(config.clone()),
        failures: Arc::new(Mutex::new(HashMap::new())),
        lockout_after_failures,
    };

    let router = Router::new()
        .route("/api/ping", get(ping))
        .route("/api/command", post(run_command))
        .route("/api/events", get(stream_events))
        .fallback_service(static_files());

    let task = tauri::async_runtime::spawn(async move {
        // `into_make_service_with_connect_info` is what makes the client address
        // available to a handler, which the lockout needs. Both paths use it, so the
        // lockout cannot be bypassed by switching on TLS.
        let service = router
            .with_state(ctx)
            .into_make_service_with_connect_info::<SocketAddr>();

        let served = match tls_config {
            Some(tls) => axum_server::from_tcp_rustls(listener, tls).serve(service).await,
            None => match tokio::net::TcpListener::from_std(listener) {
                Ok(listener) => axum::serve(listener, service).await,
                Err(err) => {
                    tracing::warn!("remote server could not take the listener: {err}");
                    return;
                }
            },
        };
        if let Err(err) = served {
            tracing::warn!("remote server stopped: {err}");
        }
    });

    tracing::info!(
        "remote access listening on {bound} (scope {:?}, {:?})",
        config.scope,
        config.capabilities.enabled_names()
    );

    Ok(RunningServer {
        config,
        addr: bound,
        task,
    })
}

/* ------------------------------------------------------------------------- */
/* Authentication                                                            */
/* ------------------------------------------------------------------------- */

/// Compare the presented token against the server's, in constant time.
///
/// The token may arrive as `Authorization: Bearer …`, as `X-Deepsand-Token`, or as
/// a `?token=` query parameter. The query form exists for one reason: the browser
/// `EventSource` API cannot set request headers, so an SSE subscriber has no other
/// way to authenticate. It is accepted only on `/api/events`, and the tradeoff is
/// documented in `docs/SECURITY.md` — a token in a URL can reach a proxy's access
/// log, which is exactly why loopback and a reverse proxy you control are the
/// intended deployment.
fn presented_token(headers: &HeaderMap, query: Option<&TokenQuery>) -> Option<String> {
    if let Some(value) = headers.get("x-deepsand-token").and_then(|v| v.to_str().ok()) {
        let value = value.trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    if let Some(token) = remote::bearer_token(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
    ) {
        return Some(token.to_string());
    }
    query.and_then(|q| q.token.clone()).filter(|t| !t.is_empty())
}

fn deny(code: StatusCode, message: impl Into<String>) -> Response {
    (code, Json(json!({ "error": message.into() }))).into_response()
}

/* ------------------------------------------------------------------------- */
/* Handlers                                                                  */
/* ------------------------------------------------------------------------- */

/// Unauthenticated, so a client can tell "wrong token" from "server down" without
/// having to guess. It reveals only that a Deepsand remote server is here.
async fn ping() -> impl IntoResponse {
    Json(json!({ "deepsand": true, "version": env!("CARGO_PKG_VERSION") }))
}

async fn run_command(
    AxumState(ctx): AxumState<ServerCtx>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CommandRequest>,
) -> Response {
    if is_locked_out(&ctx.failures, peer, ctx.lockout_after_failures) {
        return deny(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed attempts from this address. Try again shortly.",
        );
    }

    let Some(presented) = presented_token(&headers, None) else {
        record_failure(&ctx.failures, peer);
        return deny(
            StatusCode::UNAUTHORIZED,
            "A token is required. Send it as an Authorization: Bearer header.",
        );
    };
    if !remote::token_matches(&ctx.server.token, &presented) {
        record_failure(&ctx.failures, peer);
        // Deliberately does not say whether the token was close.
        return deny(StatusCode::UNAUTHORIZED, "That token is not valid.");
    }
    clear_failures(&ctx.failures, peer);

    let state = ctx.app.state::<AppState>();

    // Capability and scope, from the single table in deepsand-core.
    let project_arg = remote::requirement(&request.command)
        .and_then(|(_, project_arg)| project_arg);
    let target = project_arg
        .and_then(|key| request.args.get(key))
        .and_then(|value| value.as_str());

    if let Err(denial) = remote::authorize(
        &request.command,
        target,
        &ctx.server.scope,
        ctx.server.capabilities,
    ) {
        let code = match denial {
            RemoteDenial::NotExposed => StatusCode::NOT_FOUND,
            _ => StatusCode::FORBIDDEN,
        };
        return deny(code, denial.message());
    }

    match dispatch(&ctx.app, &state, &request.command, &request.args).await {
        Ok(value) => Json(json!({ "ok": true, "value": value })).into_response(),
        Err(message) => deny(StatusCode::BAD_REQUEST, message),
    }
}

/// Server-sent events: terminal output, session exits and permission requests.
///
/// The desktop frontend uses Tauri's event channel for the same payloads. Here they
/// come from a broadcast channel that the session callbacks also publish to, so
/// there is one producer and two consumers rather than two code paths.
async fn stream_events(
    AxumState(ctx): AxumState<ServerCtx>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Response {
    if is_locked_out(&ctx.failures, peer, ctx.lockout_after_failures) {
        return deny(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed attempts from this address. Try again shortly.",
        );
    }

    let Some(presented) = presented_token(&headers, Some(&query)) else {
        record_failure(&ctx.failures, peer);
        return deny(StatusCode::UNAUTHORIZED, "A token is required.");
    };
    if !remote::token_matches(&ctx.server.token, &presented) {
        record_failure(&ctx.failures, peer);
        return deny(StatusCode::UNAUTHORIZED, "That token is not valid.");
    }
    clear_failures(&ctx.failures, peer);

    let state = ctx.app.state::<AppState>();
    let scope = ctx.server.scope.clone();
    let receiver = state.remote_events.subscribe();

    let stream = event_stream(receiver, scope);
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Filter the broadcast channel down to what this server may see, so a
/// project-scoped server is never handed another project's terminal output.
///
/// Written with `unfold` rather than a `yield`-based generator so the crate
/// dependency list stays what it is for one function.
fn event_stream(
    receiver: tokio::sync::broadcast::Receiver<RemoteEvent>,
    scope: RemoteScope,
) -> impl Stream<Item = Result<Event, std::convert::Infallible>> {
    futures_util::stream::unfold((receiver, scope), |(mut receiver, scope)| async move {
        loop {
            match receiver.recv().await {
                Ok(remote_event) => {
                    if !event_visible(&remote_event, &scope) {
                        continue;
                    }
                    let data = serde_json::to_string(&remote_event.payload)
                        .unwrap_or_else(|_| "null".to_string());
                    let event = Event::default().event(remote_event.event).data(data);
                    return Some((Ok(event), (receiver, scope)));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    // A slow subscriber misses events rather than stalling the
                    // sandbox's output path. Worth a log because it means the view
                    // has a hole in it.
                    tracing::warn!("remote event subscriber lagged, dropped {skipped} events");
                }
                // The sender lives in AppState for the life of the process, so this
                // only happens at shutdown.
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

fn event_visible(remote_event: &RemoteEvent, scope: &RemoteScope) -> bool {
    if scope.is_app() {
        return true;
    }
    match remote_event.payload.get("projectId").and_then(|value| value.as_str()) {
        Some(project_id) => scope.allows_project(project_id),
        // An event without a project cannot be attributed, so a scoped server does
        // not get it.
        None => false,
    }
}

/* ------------------------------------------------------------------------- */
/* Static files                                                              */
/* ------------------------------------------------------------------------- */

/// Where the built frontend lives. Mirrors how the runtime directory is found:
/// resource-bundled first, then the repository layout for `cargo run`.
pub fn ui_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("DEEPSAND_UI_DIR") {
        let path = PathBuf::from(dir);
        if path.join("index.html").is_file() {
            return Some(path);
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("ui"));
            candidates.push(dir.join("_up_").join("dist"));
            candidates.push(dir.join("..").join("dist"));
        }
    }
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("dist"));

    candidates
        .into_iter()
        .find(|candidate| candidate.join("index.html").is_file())
}

fn static_files() -> ServeDir<ServeFile> {
    match ui_dir() {
        Some(dir) => {
            let index = dir.join("index.html");
            tracing::info!("serving the remote UI from {}", dir.display());
            ServeDir::new(dir).fallback(ServeFile::new(index))
        }
        None => {
            // Not fatal: the API still works, which is enough for a client that
            // already has the frontend. Warn rather than fail so a missing dist
            // does not stop remote access entirely.
            tracing::warn!(
                "the built frontend (dist/) could not be found, so the remote server will serve \
                 the API but not the UI. Run `npm run build`."
            );
            let placeholder = std::env::temp_dir().join("deepsand-no-ui.html");
            let _ = std::fs::write(
                &placeholder,
                "<!doctype html><meta charset=utf-8><title>Deepsand</title>\
                 <body style=\"font:16px system-ui;padding:2rem\">\
                 <h1>Deepsand remote access</h1>\
                 <p>The API is running, but the frontend was not built into this installation, \
                 so there is no UI to serve. Run <code>npm run build</code> and rebuild the app.\
                 </body>",
            );
            ServeDir::new(std::env::temp_dir()).fallback(ServeFile::new(placeholder))
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Dispatch                                                                  */
/* ------------------------------------------------------------------------- */

fn arg<T: serde::de::DeserializeOwned>(args: &Value, key: &str) -> Result<T, String> {
    serde_json::from_value(args.get(key).cloned().unwrap_or(Value::Null))
        .map_err(|err| format!("argument '{key}': {err}"))
}

fn optional<T: serde::de::DeserializeOwned>(args: &Value, key: &str) -> Result<Option<T>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Option::Some)
            .map_err(|err| format!("argument '{key}': {err}")),
    }
}

fn to_value<T: serde::Serialize>(value: T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|err| format!("could not serialise the reply: {err}"))
}

/// Call the same function the desktop command calls.
///
/// Adding a command here is what makes it reachable; the authorization table in
/// `deepsand_core::remote` is what decides whether a caller may use it. Both have to
/// agree, so an entry here is not by itself a grant.
async fn dispatch(
    app: &AppHandle,
    state: &AppState,
    command: &str,
    args: &Value,
) -> Result<Value, String> {
    match command {
        // --- reading -------------------------------------------------------
        "app_info" => to_value(commands::app_info_impl(state)?),
        "docker_status" => to_value(commands::docker_status_impl(state)?),
        "list_projects" => to_value(commands::list_projects_impl(state)?),
        "get_project" => to_value(commands::get_project_impl(state, arg(args, "projectId")?)?),
        "session_status" => to_value(commands::session_status_impl(state, arg(args, "projectId")?)?),
        "list_grants" => to_value(commands::list_grants_impl(state, arg(args, "projectId")?)?),
        "audit_log" => to_value(commands::audit_log_impl(
            state,
            arg(args, "projectId")?,
            optional(args, "limit")?,
        )?),
        "preview_plan" => to_value(commands::preview_plan_impl(state, arg(args, "projectId")?)?),
        "list_pending_requests" => to_value(commands::list_pending_requests_impl(state)?),
        "get_settings" => to_value(commands::get_settings_impl(state)?),
        "network_presets" => to_value(commands::network_presets()),
        "project_allowlist" => {
            to_value(commands::project_allowlist_impl(state, arg(args, "projectId")?)?)
        }
        "startup_error" => to_value(commands::startup_error_impl(state)?),
        "host_config_summary" => to_value(commands::host_config_summary()?),
        "path_check" => to_value(commands::path_check_impl(state, arg(args, "path")?)?),

        // --- driving a sandbox ---------------------------------------------
        "start_session" => {
            to_value(commands::start_session_impl(
                app,
                state,
                arg(args, "projectId")?,
                optional(args, "resume")?,
                // Remote callers get the same two choices the window has: waiting for the tools,
                // or starting now and having them copied in. `optional` keeps an older client
                // working, which never sends it.
                optional(args, "withoutTools")?.unwrap_or(false),
            )
            .await?)
        }
        "stop_session" => to_value(commands::stop_session_impl(app, state, arg(args, "projectId")?)?),
        "restart_session" => {
            to_value(commands::restart_session_impl(app, state, arg(args, "projectId")?).await?)
        }
        "write_to_session" => to_value(commands::write_to_session_impl(
            state,
            arg(args, "projectId")?,
            arg(args, "data")?,
        )?),
        "resize_session" => to_value(commands::resize_session_impl(
            state,
            arg(args, "projectId")?,
            arg(args, "rows")?,
            arg(args, "cols")?,
        )?),

        // --- widening the boundary -----------------------------------------
        "answer_request" => to_value(commands::answer_request_impl(
            app,
            state,
            arg(args, "payload")?,
        )?),
        "add_grant" => to_value(commands::add_grant_impl(
            state,
            arg(args, "projectId")?,
            arg(args, "hostPath")?,
            arg(args, "access")?,
            optional(args, "label")?,
            optional(args, "purpose")?,
        )?),
        "set_grant_access" => to_value(commands::set_grant_access_impl(
            state,
            arg(args, "projectId")?,
            arg(args, "grantId")?,
            arg(args, "access")?,
        )?),
        "revoke_grant" => to_value(commands::revoke_grant_impl(
            state,
            arg(args, "projectId")?,
            arg(args, "grantId")?,
        )?),
        "set_project_allowlist" => {
            to_value(commands::set_project_allowlist_impl(state, arg(args, "projectId")?, arg(args, "entries")?).await?)
        }

        // --- the shape of the app ------------------------------------------
        "create_project" => to_value(commands::create_project_impl(
            state,
            arg(args, "name")?,
            arg(args, "rootDir")?,
        )?),
        "delete_project" => to_value(commands::delete_project_impl(state, arg(args, "projectId")?)?),

        // --- security posture ----------------------------------------------
        "update_project_settings" => to_value(commands::update_project_settings_impl(
            state,
            arg(args, "projectId")?,
            optional(args, "network")?,
            optional(args, "limits")?,
            optional(args, "deepcodeMode")?,
            optional(args, "notes")?,
            optional(args, "credentials")?,
        )?),
        "set_requests_enabled" => to_value(commands::set_requests_enabled_impl(
            &app,
            state,
            arg(args, "projectId")?,
            arg(args, "enabled")?,
        )?),
        "set_settings" => to_value(commands::set_settings_impl(state, arg(args, "settings")?)?),
        "set_egress_allowlist" => {
            to_value(commands::set_egress_allowlist_impl(state, arg(args, "hosts")?).await?)
        }
        "build_runtime_image" => {
            to_value(commands::build_runtime_image_impl(
            app,
            state,
            optional(args, "projectId")?,
            optional(args, "buildTools")?,
            false,
        )?)
        }
        "cleanup_orphans" => to_value(commands::cleanup_orphans_impl(state)?),

        // Anything else was already refused by `remote::authorize`, so reaching here
        // means the table and this match have drifted apart.
        other => Err(format!("'{other}' is not implemented for remote access.")),
    }
}

/* ------------------------------------------------------------------------- */
/* Events                                                                    */
/* ------------------------------------------------------------------------- */

/// The event names a remote subscriber may receive. Kept next to the server so the
/// set is visible in one place.
pub fn forwarded_events() -> [&'static str; 3] {
    [
        events::TERMINAL_OUTPUT,
        events::TERMINAL_EXIT,
        events::BROKER_REQUEST,
    ]
}
