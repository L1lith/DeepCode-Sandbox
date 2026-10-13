//! Deepsand - a Docker-contained DeepCode desktop sandbox.
//!
//! # What this application is
//!
//! Deepsand lets an operator create projects and run DeepCode inside a container
//! that can only see the project directory plus whatever the operator explicitly
//! shares. The container has no path to the rest of the machine: no docker
//! socket, no home directory, no capabilities after startup.
//!
//! # Where the rules live
//!
//! * [`deepsand_core::policy`] builds the one and only `docker run` argument
//!   vector, and refuses to build an unsafe one.
//! * [`deepsand_core::paths`] decides which host paths may ever be mounted.
//! * `runtime/` implements the in-container half: privilege drop, kernel-level
//!   egress rules, and the MCP bridge the sandboxed model asks through.
//!
//! The commands in [`commands`] are adapters only. That is deliberate: it means
//! the desktop app and the headless `deepsandctl` cannot drift apart, because
//! neither of them contains any policy of its own.

pub mod commands;
pub mod remote_server;
mod state;
mod update;

use state::AppState;
use tauri::Manager;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("deepsand=info,warn")),
        )
        .with_target(false)
        .init();

    let (store, startup_error) = commands::load_store();
    let data_dir = store.data_dir().display().to_string();
    let state = AppState::new(store, startup_error);

    tauri::Builder::default()
        // Must be registered before anything else: it decides whether this process
        // becomes the instance at all. Two windows would fight over the same container
        // names, and each one's startup sweep would kill the other's sandboxes.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            use tauri::Manager as _;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        // Initialised so our own two commands can reach it. The webview never calls the
        // plugin directly: see `update` for why replacing the binary is not something to
        // hand the frontend a permission for.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(update::PendingUpdate::default())
        .manage(state)
        .setup(move |app| {
            tracing::info!(version = version(), data_dir = %data_dir, "deepsand starting");

            // Bring up any remote server that is configured to survive a restart.
            // Off by default, so this is normally a no-op; when it does run the
            // operator has asked for it explicitly.
            let should_start = {
                let state = tauri::Manager::state::<AppState>(app);
                let settings = state
                    .store
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .settings()
                    .remote
                    .clone();
                !settings.startup_servers().is_empty()
            };
            // Leftover containers from a previous, killed run. Nothing is running yet,
            // this early in startup, so anything Deepsand owns is an orphan by
            // definition. Best effort: a Docker that is not up yet must not stop the
            // app from opening, and pressing Run will reclaim the name anyway.
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    // After the window has had a moment. This sweeps Docker for leftovers,
                    // and every Docker CLI call it makes is one the first paint cannot make:
                    // on this machine that is 180-600 ms per invocation. Nothing can Run
                    // before the operator has a window, and Run reclaims the name anyway.
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    let state = tauri::Manager::state::<AppState>(&handle);
                    if let Ok(removed) = commands::cleanup_orphans_impl(&state) {
                        if !removed.is_empty() {
                            tracing::info!(
                                count = removed.len(),
                                "cleared sandbox containers left over from a previous run"
                            );
                        }
                    }
                });
            }

            // Docker is regularly started *after* Deepsand, and nothing used to look at
            // it again: the app kept reporting whatever it saw at launch, so the only way
            // out was restarting it. This watches for it appearing.
            //
            // Five seconds while it is down, thirty while it is up, so a machine that has
            // no Docker pays a cheap check and one that has it is still noticed if it
            // stops. Probing runs Docker, so it goes on a blocking thread rather than
            // occupying an async worker.
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    // The emit below comes from this trait; the app handle does not have
                    // the method without the import.
                    use tauri::Emitter as _;
                    let mut last: Option<bool> = None;
                    loop {
                        // The window asks `docker_status` as soon as it is up, so waiting a
                        // moment before this loop's first probe means Docker is asked once
                        // rather than twice during the same second of startup. From then on
                        // this is the watcher, which is what it is for.
                        if last.is_none() {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        }
                        let probe = handle.clone();
                        let available = tauri::async_runtime::spawn_blocking(move || {
                            let state = tauri::Manager::state::<AppState>(&probe);
                            commands::docker_status_impl(&state)
                                .map(|status| status.available)
                                .unwrap_or(false)
                        })
                        .await
                        .unwrap_or(false);

                        // Announced only when it changes, and not for the first reading:
                        // the launch path has already reported that one.
                        if last != Some(available) {
                            if let Some(was) = last {
                                tracing::info!(was, now = available, "docker availability changed");
                                let _ = handle.emit(
                                    crate::state::events::STATE_CHANGED,
                                    serde_json::json!({ "reason": "docker" }),
                                );
                            }
                            last = Some(available);
                        }

                        let wait = if available { 30 } else { 5 };
                        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                    }
                });
            }

            if should_start {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    // Resolved inside the task, from the handle, so this is the one
                    // shared AppState rather than a copy of it.
                    let state = tauri::Manager::state::<AppState>(&handle);
                    commands::reconcile_remote_servers(&handle, &state).await;
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window must not leave a container running with the
            // operator's project mounted: stop every session first.
            if let tauri::WindowEvent::Destroyed = event {
                let state = window.state::<AppState>();
                commands::shutdown_cleanup(&state);
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::docker_status,
            commands::list_projects,
            commands::get_project,
            commands::create_project,
            commands::update_project_settings,
            commands::set_requests_enabled,
            commands::delete_project,
            commands::path_check,
            commands::list_grants,
            commands::add_grant,
            commands::set_grant_access,
            commands::revoke_grant,
            commands::audit_log,
            commands::preview_plan,
            commands::session_status,
            commands::start_session,
            commands::stop_session,
            commands::restart_session,
            commands::write_to_session,
            commands::resize_session,
            commands::list_pending_requests,
            commands::answer_request,
            commands::get_settings,
            commands::set_settings,
            commands::set_egress_allowlist,
            commands::network_presets,
            commands::get_start_at_login,
            commands::set_start_at_login,
            commands::list_secrets,
            commands::set_secret,
            commands::delete_secret,
            commands::list_tools,
            commands::set_project_tools,
            commands::get_effort,
            commands::set_effort,
            commands::get_remote_access,
            commands::set_remote_access,
            commands::project_allowlist,
            commands::set_project_allowlist,
            commands::host_config_summary,
            commands::build_runtime_image,
            commands::cleanup_orphans,
            commands::reveal_data_dir,
            commands::startup_error,
            // Self-updates. Desktop-only with the plugin, and absent from the remote
            // command table on purpose: a remote client must not be able to replace the
            // binary on the host it reached.
            update::check_for_updates,
            update::install_update,
        ])
        .build(tauri::generate_context!())
        .expect("deepsand failed to start")
        .run(|app_handle, event| {
            // The window handler covers a closed window; this covers quitting by any
            // other route. Both run `shutdown_cleanup`, which is idempotent.
            //
            // Neither can help against `taskkill`, which runs no handler at all --
            // that case is what the reclaim before `docker run` and the sweep at the
            // next startup are for.
            if let tauri::RunEvent::Exit = event {
                use tauri::Manager as _;
                let state = app_handle.state::<AppState>();
                commands::shutdown_cleanup(&state);
            }
        });
}
