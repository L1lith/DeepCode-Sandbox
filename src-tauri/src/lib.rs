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
mod host_config;
mod tool_updates;
mod tray;
mod instance;
pub mod remote_server;
mod state;
mod update;

use state::AppState;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Send log output to `deepsand.log` as well as stdout, and log panics.
///
/// A Windows release build has no console, so `tracing` output -- the only account this app
/// gives of itself -- went nowhere. A launch that failed silently therefore stayed silent:
/// there was nothing to read, on the machine where it happened. The file is truncated when it
/// grows past 2 MB, keeping one previous copy, so it cannot fill a disk.
fn init_logging(data_dir: &std::path::Path) {
    use std::io::Write as _;

    let path = data_dir.join("deepsand.log");
    let previous = data_dir.join("deepsand.log.1");
    if std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0) > 2 * 1024 * 1024 {
        let _ = std::fs::rename(&path, &previous);
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok();

    let writer = file.map(|file| TeeWriter(std::sync::Arc::new(std::sync::Mutex::new(file))));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("deepsand=info,warn")),
        )
        .with_target(false);
    // `try_init`, not `init`: a second call must not panic. Startup is the wrong place to
    // find out that something already installed a subscriber.
    if let Some(writer) = writer {
        let _ = subscriber.with_writer(writer).try_init();
    } else {
        let _ = subscriber.try_init();
    }

    // A panic in a command or a worker thread used to leave no trace anywhere.
    let fallback = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("panic: {info}");
        fallback(info);
    }));

    let _ = writeln!(std::io::stdout(), "deepsand logging to {}", path.display());
}

/// Writes to stdout and to the log file, so the terminal and the file agree.
#[derive(Clone)]
struct TeeWriter(std::sync::Arc<std::sync::Mutex<std::fs::File>>);

impl std::io::Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::stdout().write_all(buf);
        if let Ok(mut file) = self.0.lock() {
            let _ = file.write_all(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::stdout().flush();
        if let Ok(mut file) = self.0.lock() {
            let _ = file.flush();
        }
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TeeWriter {
    type Writer = TeeWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[cfg(test)]
mod logging_tests {
    use super::*;

    /// The claim this exists for: an error the operator saw in the window is in the log file
    /// afterwards, so it can be read and copied when the box is long gone.
    ///
    /// One test rather than two because it installs a subscriber, and a process has one: the
    /// second test to run would have written into the first test's file and failed for a
    /// reason that has nothing to do with what it is testing.
    #[test]
    fn what_the_window_showed_is_written_to_the_log_file() {
        let dir = std::env::temp_dir().join(format!("deepsand-log-{}", deepsand_core::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();

        init_logging(&dir);
        commands::log_ui_event_impl("error", "Could not build the plan\nthe daemon said no")
            .expect("logging a message is not an error itself");
        commands::log_ui_event_impl("warn", "the allowlist entry was ignored").unwrap();
        // A message that is not text is not written at all, which is the rule the build log
        // taught the hard way: NULs are not content.
        commands::log_ui_event_impl("error", &"\0".repeat(4096)).unwrap();

        let written = std::fs::read_to_string(dir.join("deepsand.log")).unwrap_or_default();
        assert!(
            written.contains("[window] Could not build the plan"),
            "the box's text has to be in the log, got: {written}"
        );
        assert!(
            written.contains("the daemon said no"),
            "and all of it, not just the first line"
        );
        assert!(written.contains("[window] the allowlist entry was ignored"));
        assert!(!written.contains('\0'), "NULs are not content");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let (store, startup_error) = commands::load_store();
    let data_dir_path = store.data_dir().to_path_buf();
    let data_dir = data_dir_path.display().to_string();

    // Logging goes to a file as well as to stdout, because on Windows a release build has no
    // stdout: everything this app said about itself went nowhere, which is why a launch that
    // died silently could not be diagnosed from the machine it died on.
    init_logging(&data_dir_path);
    tracing::info!(version = version(), data_dir = %data_dir, pid = std::process::id(), "deepsand starting");

    // Before the builder, because `tauri_plugin_single_instance` hands a launch to whatever
    // process already exists and exits. Handed to a process with no window and a stuck UI
    // thread, the launch disappears entirely -- no window, no error. Clearing such a process
    // here means the plugin finds nothing to hand off to.
    let claim = instance::claim(&data_dir_path);
    let single_instance = match &claim {
        instance::Claim::TakeOverUncleared(pid) => {
            tracing::error!(pid, "starting without the single-instance guard");
            false
        }
        instance::Claim::Primary(_) | instance::Claim::Cleared(_, _) | instance::Claim::Secondary => true,
    };
    // The lock lives as long as this binding: dropping it is how the next launch knows this
    // one is gone.
    let _instance_lock = match claim {
        instance::Claim::Primary(lock) => Some(lock),
        instance::Claim::Cleared(lock, pid) => {
            tracing::warn!(pid, "started by clearing an earlier Deepsand that had stopped responding");
            Some(lock)
        }
        _ => None,
    };

    let state = AppState::new(store, startup_error);

    let mut builder = tauri::Builder::default();
    if single_instance {
        // Registered first among the plugins that do anything: it decides whether this process
        // becomes the instance at all. Two windows would fight over the same container names,
        // and each one's startup sweep would kill the other's sandboxes. Skipped only when an
        // earlier instance is stuck and could not be cleared, because an app that refuses to
        // open at all is worse than two that have to be sorted out by hand.
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
                // A second launch is somebody asking for the window -- from the Start menu, a
                // shortcut, or a file manager -- and there is one process, so the launch is handed
                // here. Doing nothing left them with no window and no sign of one, because the
                // instance they already had was in the tray.
                tray::show_main_window(app);
            use tauri::Manager as _;
            tracing::info!("another launch was handed to this instance; showing the window");
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }));
    }
    builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        // Initialised so our own two commands can reach it. The webview never calls the
        // plugin directly: see `update` for why replacing the binary is not something to
        // hand the frontend a permission for.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(update::PendingUpdate::default())
        .manage(state)
        .setup(move |app| {
            // Proves from the UI thread that this instance is running, so a later launch can
            // tell "already running" from "stuck with nothing on screen".
            instance::start_heartbeat(app.handle(), data_dir_path.clone());

            // The host's own DeepCode settings file is read fresh by the backend on every use,
            // so what goes stale is only what the window was told. Three seconds is the latency
            // of a person noticing; see the module for why this polls rather than watches.
            host_config::watch(app.handle().clone(), std::time::Duration::from_secs(3));

            tracing::info!(version = version(), data_dir = %data_dir, "deepsand starting");

            // Bring up any remote server that is configured to survive a restart.
            // Off by default, so this is normally a no-op; when it does run the
            // operator has asked for it explicitly.
            // Projects marked to come back on their own. Docker gets a moment first, because a
            // session cannot start without it and the daemon is often still coming up at login.
            // `was_running` was written when the app last ended, for whatever was running then.
            {
                let handle = app.handle().clone();
                let wanted: Vec<String> = {
                    let state = tauri::Manager::state::<AppState>(app);
                    let store = state.store.lock().unwrap_or_else(|p| p.into_inner());
                    store
                        .projects()
                        .iter()
                        .filter(|project| project.resume_on_launch && project.was_running)
                        .map(|project| project.id.clone())
                        .collect()
                };
                if !wanted.is_empty() {
                    tracing::info!(?wanted, "starting the projects marked to resume");
                    std::thread::spawn(move || {
                        for _ in 0..30 {
                            let ready = {
                                let state = tauri::Manager::state::<AppState>(&handle);
                                state.docker().is_ok()
                            };
                            if ready {
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_secs(2));
                        }
                        for project_id in wanted {
                            let state = tauri::Manager::state::<AppState>(&handle);
                            let outcome = tauri::async_runtime::block_on(commands::start_session_impl(
                                &handle,
                                &state,
                                project_id.clone(),
                                Some(true),
                                false,
                            ));
                            match outcome {
                                Ok(_) => tracing::info!(project = %project_id, "resumed"),
                                Err(err) => tracing::warn!(project = %project_id, %err, "could not resume"),
                            }
                        }
                    });
                }
            }

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

            // The tray icon, when hiding is possible, and the hidden start itself. Both are
            // decided here rather than in the window's own event because this is the first
            // moment there is an app to attach either to.
            let state = tauri::Manager::state::<AppState>(app.handle());
            let started_hidden = commands::started_in_background();
            if tray::wanted(commands::closes_to_tray(&state), started_hidden) {
                if let Err(err) = tray::install(app.handle()) {
                    tracing::warn!(%err, "could not put the tray icon in place");
                }
            }
            // The tool check: once after startup, then on a timer. It does nothing at all when
            // the operator has turned it off, and it reads that setting each cycle so turning it
            // off stops the next one rather than needing a restart.
            tool_updates::watch(
                app.handle().clone(),
                deepsand_core::toolcache::CHECK_INTERVAL,
            );

            if started_hidden {
                if let Some(window) = tauri::Manager::get_webview_window(app.handle(), "main") {
                    let _ = window.hide();
                    tracing::info!("started in the background; the tray icon opens the window");
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window must not leave a container running with the operator's
            // project mounted: stop every session first.
            // Closing hides instead of stopping when the operator has asked for that. This
            // branch never runs `shutdown_cleanup`, which is the whole difference: the
            // sandboxes keep running, and the tray icon is how the window comes back.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let app = tauri::Manager::app_handle(window);
                let state = tauri::Manager::state::<AppState>(app);
                if commands::closes_to_tray(&state) {
                    api.prevent_close();
                    let _ = window.hide();
                    tracing::info!("the window was hidden; Deepsand is still running");
                }
            }
            if let tauri::WindowEvent::Destroyed = event {
                // Bounded, and then the process ends either way.
                //
                // This runs on the UI thread and `shutdown_cleanup` shells out to Docker. With
                // Docker Desktop restarting underneath it, that call never returned: the
                // process sat there with no window and a blocked event loop, and because the
                // single-instance plugin hands every later launch to whatever process already
                // exists, the app then looked like it would not start at all. Ten seconds is
                // enough for a list of containers to be stopped; past it, exiting is the safer
                // failure -- the containers left behind are removed by the next start's sweep.
                let app = tauri::Manager::app_handle(window).clone();
                let (done_tx, done_rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let state = tauri::Manager::state::<AppState>(&app);
                    commands::shutdown_cleanup(&state);
                    let _ = done_tx.send(());
                });
                if done_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .is_err()
                {
                    tracing::warn!(
                        "shutdown cleanup did not finish within ten seconds; exiting anyway"
                    );
                }
                tracing::info!("deepsand exiting");
                std::process::exit(0);
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::docker_status,
            commands::log_ui_event,
            commands::log_file_path,
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
            commands::get_startup_mode,
            commands::set_startup_mode,
            commands::set_close_to_tray,
            commands::check_tool_updates_now,
            commands::list_secrets,
            commands::set_secret,
            commands::delete_secret,
            commands::list_tools,
            commands::set_project_tools,
            commands::get_effort,
            commands::get_model,
            commands::cancel_build,
            commands::attach_paths,
            commands::attach_bytes,
            commands::set_model,
            commands::list_models,
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
