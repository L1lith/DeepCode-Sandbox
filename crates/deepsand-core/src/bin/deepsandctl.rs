//! `deepsandctl` - drive a Deepsand sandbox without the desktop app.
//!
//! Everything the GUI does is available here. That keeps the core honest (no
//! behaviour can hide in the frontend), and it means the sandbox can be
//! exercised, scripted and reviewed on a machine with no display.
//!
//! ```text
//!   deepsandctl doctor
//!   deepsandctl project add "my-website" .
//!   deepsandctl plan my-website              # print the exact docker run argv
//!   deepsandctl run my-website               # attach the sandbox to this terminal
//!   deepsandctl watch my-website             # act as the permission broker
//!   deepsandctl grants my-website add ~/brand --write
//! ```

use deepsand_core::broker::Broker;
use deepsand_core::credentials;
use deepsand_core::docker::Docker;
use deepsand_core::model::*;
use deepsand_core::policy::{self, MountKind, PlanInput};
use deepsand_core::session::{Session, SessionOptions};
use deepsand_core::settings as container_settings;
use deepsand_core::store::Store;
use deepsand_core::{paths, Result, SandboxError};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

/// How the CLI answers permission requests when there is no human on the other
/// end. Deliberately deny-by-default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovePolicy {
    Deny,
    GrantRead,
    GrantWrite,
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("error: {err}");
            match err {
                SandboxError::Policy(_) => 2,
                SandboxError::Path(_) => 2,
                _ => 1,
            }
        }
    };
    std::process::exit(code);
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();

    // Global option: --data-dir <path>
    let mut data_dir = Store::default_data_dir();
    if let Some(index) = args.iter().position(|a| a == "--data-dir") {
        if index + 1 >= args.len() {
            return Err(SandboxError::Other(anyhow::anyhow!("--data-dir needs a path")));
        }
        data_dir = PathBuf::from(args.remove(index + 1));
        args.remove(index);
    }

    let command = args.first().cloned().unwrap_or_else(|| "help".to_string());
    let rest = if args.is_empty() { Vec::new() } else { args[1..].to_vec() };

    match command.as_str() {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "version" | "--version" | "-V" => {
            println!("deepsandctl {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "doctor" => cmd_doctor(&data_dir),
        "project" | "projects" => cmd_project(&data_dir, &rest),
        "grants" | "grant" => cmd_grants(&data_dir, &rest),
        "plan" => cmd_plan(&data_dir, &rest),
        "run" => cmd_run(&data_dir, &rest),
        "watch" => cmd_watch(&data_dir, &rest),
        "requests" => cmd_requests(&data_dir, &rest),
        "network" => cmd_network(&data_dir, &rest),
        other => Err(SandboxError::Other(anyhow::anyhow!(
            "unknown command '{other}'. Run `deepsandctl help`."
        ))),
    }
}

fn print_help() {
    println!(
        "\
deepsandctl - drive a Deepsand sandbox without the desktop app

USAGE
  deepsandctl [--data-dir <path>] <command> [args]

COMMANDS
  doctor                        Check Docker, the runtime image and the data directory
  project add <name> <dir>      Create a project whose working directory is <dir>
  project list                  List projects
  project show <name|id>        Show one project in full
  project remove <name|id>      Forget a project (its session volume is kept)
  grants <project>              List the permissions a project currently has
  grants <project> add <dir> [--write] [--label <label>] [--purpose <text>]
  grants <project> rm <slug>    Revoke a permission
  plan <project>                Print the exact `docker run` argument vector
  run <project> [--resume] [--approve deny|read|write]
                                Start the sandbox attached to this terminal
  watch <project>               Be the permission broker: show and answer requests
  requests <project>            List requests currently waiting for a decision
  network <project> [mode]      Show or change the egress policy
                                (none|internet|allowlisted|full)

NOTES
  `run` and `watch` are meant to be used together in two terminals: `run`
  attaches the container to one, `watch` acts as the human approval side on the
  other. With `--approve deny` (the default) `run` refuses everything itself,
  which is the safe way to smoke-test.
"
    );
}

/* ------------------------------------------------------------------------- */
/* doctor                                                                    */
/* ------------------------------------------------------------------------- */

fn cmd_doctor(data_dir: &Path) -> Result<()> {
    println!("deepsandctl {}", env!("CARGO_PKG_VERSION"));
    println!("data directory : {}", data_dir.display());

    let store = Store::load(data_dir.to_path_buf())?;
    println!("projects       : {}", store.projects().len());

    let docker_status = match Docker::locate() {
        Ok(docker) => docker.probe(store.settings().image.as_str()),
        Err(err) => {
            println!("docker         : UNAVAILABLE ({err})");
            return Ok(());
        }
    };

    println!("docker client  : {}", or_unknown(&docker_status.client_version));
    println!("docker server  : {}", or_unknown(&docker_status.server_version));
    println!("docker platform: {}", or_unknown(&docker_status.operating_system));
    println!("docker desktop : {}", docker_status.desktop);
    println!("daemon ready   : {}", docker_status.available);
    println!(
        "runtime image  : {} ({})",
        store.settings().image,
        if docker_status.image_present { "present" } else { "MISSING - run `deepsandctl` after building it" }
    );
    if !docker_status.detail.is_empty() {
        println!("note           : {}", docker_status.detail);
    }

    // The profile that will actually be applied, and whether it is the profile the image
    // carries. The daemon resolves `--security-opt=seccomp=` on the host, so this is the
    // only place the two halves are ever compared -- R3-A of the escape assessment.
    let hardening = matches!(store.settings().security.seccomp, SeccompProfile::Hardened);
    match deepsand_core::seccomp::profile_path(hardening) {
        Some(profile) if docker_status.image_present => match Docker::locate() {
            Ok(docker) => {
                if let Err(err) =
                    verify_profile_against_image(&docker, store.settings().image.as_str(), &profile)
                {
                    println!("seccomp image  : MISMATCH - {err}");
                }
            }
            Err(err) => println!("seccomp        : cannot be checked ({err})"),
        },
        Some(profile) => println!(
            "seccomp        : {} (the runtime image is not present, so the applied profile could not be compared with it)",
            profile.display()
        ),
        None => println!(
            "seccomp        : none (hardening is off, or runtime/seccomp-hardened.json is missing)"
        ),
    }

    println!();
    println!("host file sharing (required: the project directory is bind-mounted):");
    match Docker::locate() {
        Ok(docker) => {
            let probe_dir = store
                .projects()
                .first()
                .map(|p| PathBuf::from(&p.root_dir))
                .filter(|p| p.is_dir())
                .unwrap_or_else(|| data_dir.to_path_buf());
            let check = docker.check_host_sharing(&probe_dir, store.settings().image.as_str());
            println!("  directory : {}", probe_dir.display());
            println!("  readable  : {}", if check.ok { "yes" } else { "NO" });
            if !check.ok {
                println!("  {}", check.detail.replace('\n', "\n  "));
            }
        }
        Err(err) => println!("  skipped   : docker CLI not found ({err})"),
    }

    println!();
    println!("credential source: {}", credentials::host_settings_path().display());
    let host = credentials::read_host_config();
    println!("  present      : {}", host.present);
    println!("  model        : {}", host.model.as_deref().unwrap_or("(unset)"));
    println!("  base URL     : {}", host.base_url.as_deref().unwrap_or("(unset)"));
    println!("  api key      : {}", host.masked_api_key().unwrap_or_else(|| "(unset)".into()));
    if let Some(err) = &host.error {
        println!("  error        : {err}");
    }

    println!();
    println!("hardening in effect for new projects:");
    let security = &store.settings().security;
    println!("  read-only rootfs   : {}", security.read_only_rootfs);
    println!("  no-new-privileges  : {}", security.no_new_privileges);
    println!("  seccomp            : {:?}", security.seccomp);
    println!("  apparmor requested : {}", security.apparmor);
    println!("  netfilter required : {}", security.netfilter_required);
    if docker_status.desktop {
        // The seccomp profile *is* attached here -- the code that skipped it on Docker
        // Desktop was removed, and `the_seccomp_profile_is_attached_even_on_docker_desktop`
        // covers it. AppArmor genuinely is not available in the VM, so the note says only
        // that, rather than repeating a claim that was wrong about the profile.
        println!("  note               : Docker Desktop runs the daemon in a VM. The seccomp");
        println!("                       profile is still attached; AppArmor is not available.");
    }
    Ok(())
}

fn or_unknown(value: &str) -> &str {
    if value.is_empty() {
        "(unknown)"
    } else {
        value
    }
}

/* ------------------------------------------------------------------------- */
/* projects                                                                  */
/* ------------------------------------------------------------------------- */

fn cmd_project(data_dir: &Path, args: &[String]) -> Result<()> {
    let mut store = Store::load(data_dir.to_path_buf())?;
    match args.first().map(String::as_str) {
        Some("add") => {
            if args.len() < 3 {
                return Err(SandboxError::Other(anyhow::anyhow!(
                    "usage: deepsandctl project add <name> <directory>"
                )));
            }
            let project = store.create_project(&args[1], &args[2])?;
            println!("created project '{}' ({})", project.name, project.id);
            println!("  workspace     : {}", project.root_dir);
            println!("  container     : {}", project.container_name());
            println!("  network       : {}", project.network.mode_str());
            println!();
            println!("next: `deepsandctl plan {}` to review the sandbox before starting it.", project.slug);
            Ok(())
        }
        Some("list") | None => {
            if store.projects().is_empty() {
                println!("no projects yet. Create one with `deepsandctl project add <name> <dir>`.");
                return Ok(());
            }
            println!("{:<24} {:<9} {:<10} {}", "NAME", "SLUG", "NETWORK", "WORKSPACE");
            for project in store.projects() {
                println!(
                    "{:<24} {:<9} {:<10} {}",
                    truncate(&project.name, 24),
                    truncate(&project.slug, 9),
                    project.network.mode_str(),
                    project.root_dir
                );
            }
            Ok(())
        }
        Some("show") => {
            let project = resolve_project(&store, args.get(1))?.clone();
            println!("{} ({})", project.name, project.id);
            println!("  workspace      : {}", project.root_dir);
            println!("  container      : {}", project.container_name());
            println!("  state volume   : {}", project.state_volume());
            println!("  network        : {}", project.network.mode_str());
            println!("  deepcode mode  : {:?}", project.deepcode_mode);
            println!("  created        : {}", deepsand_core::iso_from_ms(project.created_at_ms));
            println!(
                "  limits         : {} MiB, {} cpus, {} pids, {} MiB /tmp",
                project.limits.memory_mb,
                project.limits.cpus,
                project.limits.pids_limit,
                project.limits.tmpfs_mb
            );
            let app = store.settings().clone();
            let host = credentials::read_host_config();
            let resolved = credentials::resolve(&project, &app, &host);
            println!("  credentials    : from {}", resolved.provenance);
            println!("  model          : {}", resolved.model);
            println!("  base URL       : {}", resolved.base_url);
            println!("  api key        : {}", if resolved.api_key.is_some() { "set" } else { "MISSING" });
            for warning in &resolved.warnings {
                println!("  warning        : {warning}");
            }
            let grants = store.active_grants(&project.id);
            println!("  permissions    : {} granted", grants.len());
            for grant in grants {
                println!(
                    "    - {:<10} {:<24} -> {}",
                    grant.access.label(),
                    truncate(&grant.label, 24),
                    grant.container_path
                );
            }
            Ok(())
        }
        Some("remove") | Some("rm") => {
            let project = resolve_project(&store, args.get(1))?.clone();
            store.delete_project(&project.id)?;
            println!("removed '{}'. Its session volume {} was left in place.", project.name, project.state_volume());
            Ok(())
        }
        Some(other) => Err(SandboxError::Other(anyhow::anyhow!("unknown project subcommand '{other}'"))),
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let kept: String = value.chars().take(width.saturating_sub(1)).collect();
    format!("{kept}…")
}

fn resolve_project<'a>(store: &'a Store, needle: Option<&String>) -> Result<&'a Project> {
    let needle = needle.ok_or_else(|| SandboxError::Other(anyhow::anyhow!("a project name or id is required")))?;
    store
        .projects()
        .iter()
        .find(|p| &p.id == needle || &p.slug == needle || &p.name == needle)
        .ok_or_else(|| SandboxError::ProjectNotFound(needle.clone()))
}

/* ------------------------------------------------------------------------- */
/* grants                                                                    */
/* ------------------------------------------------------------------------- */

fn cmd_grants(data_dir: &Path, args: &[String]) -> Result<()> {
    let mut store = Store::load(data_dir.to_path_buf())?;
    let project = resolve_project(&store, args.first())?.clone();
    let sub = args.get(1).map(String::as_str);

    match sub {
        Some("add") => {
            let raw = args
                .get(2)
                .ok_or_else(|| SandboxError::Other(anyhow::anyhow!("usage: grants <project> add <directory>")))?;
            let access = if args.iter().any(|a| a == "--write" || a == "-w") {
                Access::ReadWrite
            } else {
                Access::ReadOnly
            };
            let label = flag_value(args, "--label").unwrap_or_default();
            let purpose = flag_value(args, "--purpose").unwrap_or_default();
            let grant = store.add_grant(&project.id, raw, access, &label, &purpose, GrantSource::User)?;
            println!(
                "granted {} access to {}\n  visible inside the sandbox at {}",
                grant.access.label(),
                grant.host_path,
                grant.container_path
            );
            println!();
            println!("This share takes effect the next time the sandbox container is created.");
            Ok(())
        }
        Some("rm") | Some("remove") => {
            let slug = args
                .get(2)
                .ok_or_else(|| SandboxError::Other(anyhow::anyhow!("usage: grants <project> rm <slug>")))?;
            let grants = store.grants(&project.id);
            let grant = grants
                .iter()
                .find(|g| &g.slug == slug || &g.id == slug)
                .ok_or_else(|| SandboxError::GrantNotFound(slug.clone()))?
                .clone();
            store.revoke_grant(&project.id, &grant.id)?;
            println!("revoked {} ({})", grant.label, grant.container_path);
            Ok(())
        }
        _ => {
            let grants = store.active_grants(&project.id);
            if grants.is_empty() {
                println!("'{}' has no shared directories beyond its workspace ({}).", project.name, project.root_dir);
                return Ok(());
            }
            println!("{:<24} {:<10} {:<24} {}", "LABEL", "ACCESS", "SANDBOX PATH", "HOST PATH");
            for grant in grants {
                println!(
                    "{:<24} {:<10} {:<24} {}",
                    truncate(&grant.label, 24),
                    grant.access.label(),
                    grant.container_path,
                    grant.host_path
                );
            }
            Ok(())
        }
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

/* ------------------------------------------------------------------------- */
/* plan                                                                     */
/* ------------------------------------------------------------------------- */

fn cmd_plan(data_dir: &Path, args: &[String]) -> Result<()> {
    let store = Store::load(data_dir.to_path_buf())?;
    let project = resolve_project(&store, args.first())?.clone();
    // `--offline` lets an operator review exactly what would run, and inspect
    // the generated configuration, on a machine where Docker is not running.
    let offline = args.iter().any(|a| a == "--offline");
    let plan = build_plan(&store, &project, false, offline)?;

    // Build the whole report first and emit it in one write, so a consumer that
    // closes early cannot leave half a plan on screen.
    let mut report = plan.describe();
    report.push_str("\nGenerated configuration lives in:\n");
    for path in [
        store.config_dir(&project.id).join("settings.json"),
        store.config_dir(&project.id).join("AGENTS.md"),
        store.state_dir(&project.id).join("sandbox.json"),
    ] {
        report.push_str(&format!("  {}\n", path.display()));
    }
    emit(&report);
    Ok(())
}

/// Print to stdout, tolerating a closed pipe.
///
/// `deepsandctl plan <project> | head` is an entirely reasonable thing to do,
/// and Rust's default `println!` behaviour is to panic when the reader goes
/// away. A CLI should just stop quietly.
fn emit(text: &str) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(text.as_bytes());
    let _ = lock.flush();
}

/// Assemble a plan for a project, writing the generated configuration first so
/// the mounts the plan names actually exist.
fn build_plan(store: &Store, project: &Project, resume: bool, offline: bool) -> Result<policy::RunPlan> {
    let (docker_status, docker) = if offline {
        (
            DockerStatus {
                available: true,
                client_version: "(offline review)".into(),
                server_version: "(offline review)".into(),
                operating_system: if cfg!(windows) { "Docker Desktop (assumed)" } else { "Linux (assumed)" }.into(),
                desktop: cfg!(windows) || cfg!(target_os = "macos"),
                image_present: false,
                detail: "reviewed with --offline; nothing was started".into(),
            },
            None,
        )
    } else {
        let docker = Docker::locate()?;
        (docker.probe(&store.settings().image), Some(docker))
    };

    store.ensure_project_dirs(&project.id)?;
    let broker = Broker::new(store.data_dir(), &project.id);
    broker.ensure()?;

    let grants = store.active_grants(&project.id);
    let host = credentials::read_host_config();
    if let Some(err) = &host.error {
        eprintln!("warning: {err}");
    }
    let resolved = credentials::resolve(project, store.settings(), &host);

    let sandbox = container_settings::build_sandbox_snapshot(
        project,
        &grants,
        &project.network,
        broker.open_request_ids(),
        resolved.warnings.clone(),
    );
    let grants_snapshot = container_settings::build_grants_snapshot(project, &grants);

    let settings_json =
        container_settings::build_deepcode_settings(project, &grants, &resolved, 45_000);

    container_settings::write_project_config(
        &store.config_dir(&project.id),
        &store.state_dir(&project.id),
        &settings_json,
        &container_settings::build_agents_md(project, &grants, &project.network, &resolved),
        &sandbox,
        &grants_snapshot,
    )?;

    let seccomp = seccomp_path(store);
    // The daemon reads its profile from the host, so check that it is the profile the image
    // carries before anything starts. Refusing here is the point: a sandbox whose hardening
    // cannot be attributed to the image it runs is a sandbox nobody can audit (R3-A).
    if let (Some(profile), Some(docker)) = (seccomp.as_deref(), docker.as_ref()) {
        if docker_status.image_present {
            verify_profile_against_image(docker, store.settings().image.as_str(), profile)?;
        }
    }
    // The model endpoint is not optional in any mode, so it is passed separately
    // from the project's own allowlist.
    let model_addrs: Vec<String> = deepsand_core::allowlist::endpoints_for_url(&resolved.base_url);
    let required_hosts: Vec<String> = deepsand_core::allowlist::host_from_url(&resolved.base_url)
        .into_iter()
        .collect();
    policy::plan_run(&PlanInput {
        project,
        grants: &grants,
        app: store.settings(),
        docker_status: &docker_status,
        data_dir: store.data_dir(),
        guards: store.guards(),
        seccomp_host_path: seccomp.as_deref(),
        proxy: None,
        network_gateway: None,
        required_hosts: &required_hosts,
        secrets_env_file: None,
        model_endpoints: &model_addrs,
        mcp_wait_ms: 45_000,
        resume,
    })
}

/// Locate the hardened seccomp profile, if this installation has one.
///
/// Shares the core resolver, so this agrees with the desktop app about which runtime tree
/// the profile comes from rather than searching a set of places of its own.
fn seccomp_path(store: &Store) -> Option<PathBuf> {
    deepsand_core::seccomp::profile_path(matches!(
        store.settings().security.seccomp,
        SeccompProfile::Hardened
    ))
}

/// Check the profile being applied against the digest the image carries (R3-A).
///
/// Fails closed: a missing digest file, a malformed one and a mismatch are all refusals,
/// because "I could not check" must not be usable as "the check passed".
fn verify_profile_against_image(docker: &Docker, image: &str, profile: &Path) -> Result<()> {
    let in_image = docker.read_file_from_image(image, deepsand_core::seccomp::IMAGE_DIGEST_PATH)?;
    let digest = deepsand_core::seccomp::verify(profile, &in_image)?;
    println!(
        "seccomp        : {} (sha256 {}...)",
        profile.display(),
        &digest[..12.min(digest.len())]
    );
    Ok(())
}

/* ------------------------------------------------------------------------- */
/* run                                                                      */
/* ------------------------------------------------------------------------- */

fn cmd_run(data_dir: &Path, args: &[String]) -> Result<()> {
    let store = Store::load(data_dir.to_path_buf())?;
    let project = resolve_project(&store, args.first())?.clone();

    let policy = match flag_value(args, "--approve").as_deref() {
        Some("read") => ApprovePolicy::GrantRead,
        Some("write") => ApprovePolicy::GrantWrite,
        _ => ApprovePolicy::Deny,
    };

    let docker = Docker::locate()?;
    docker.volume_create(&project.state_volume())?;

    let resume_requested = args.iter().any(|a| a == "--resume");
    let resume = resume_requested
        && docker.volume_has_session_index(&project.state_volume(), &store.settings().image);
    if resume_requested && !resume {
        eprintln!("note: --resume was requested but no previous session exists; starting fresh.");
    }

    let plan = build_plan(&store, &project, resume, false)?;
    for warning in &plan.warnings {
        eprintln!("warning: {warning}");
    }

    eprintln!("starting {} ({})", project.name, project.container_name());
    eprintln!("workspace {} -> {}", project.root_dir, Project::workspace_mount());

    // The broker loop runs beside the container, exactly as the GUI's does.
    let broker_store_dir = store.data_dir().to_path_buf();
    let broker_project = project.clone();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        broker_loop(broker_store_dir, broker_project, policy, stop_rx, false);
    });

    let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>();
    let (exit_tx, exit_rx) = mpsc::channel::<i32>();

    let session = Session::spawn(
        SessionOptions {
            program: docker.program().to_path_buf(),
            args: plan.args.clone(),
            cwd: PathBuf::from(&project.root_dir),
            env: vec![],
            rows: 40,
            cols: 120,
        },
        move |chunk| {
            let _ = output_tx.send(chunk.to_vec());
        },
        move |code| {
            let _ = exit_tx.send(code);
        },
    )?;

    // Stream the sandbox's output until it exits.
    //
    // This used to break out of the loop on the first poll timeout, so `run`
    // returned after ~50 ms having printed nothing. A poll timeout means "no
    // output yet", not "the session is over" — only the exit channel firing, or
    // the output channel closing, means that.
    let mut stdout = std::io::stdout();
    let mut exit_code: Option<i32> = None;
    loop {
        match output_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(chunk) => {
                let _ = stdout.write_all(&chunk);
                let _ = stdout.flush();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            // The PTY closed and every writer is gone, so the sandbox stopped.
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if let Ok(code) = exit_rx.try_recv() {
            exit_code = Some(code);
            // Drain whatever the container printed on its way out.
            while let Ok(chunk) = output_rx.try_recv() {
                let _ = stdout.write_all(&chunk);
            }
            let _ = stdout.flush();
            break;
        }
    }

    let code = exit_code.or_else(|| exit_rx.try_recv().ok()).unwrap_or(-1);
    let _ = stop_tx.send(());
    eprintln!("[deepsand] sandbox exited with code {code}");
    if code != 0 {
        eprintln!("[deepsand] command: {}", session.command_line());
    }
    Ok(())
}

/* ------------------------------------------------------------------------- */
/* watch                                                                    */
/* ------------------------------------------------------------------------- */

fn cmd_watch(data_dir: &Path, args: &[String]) -> Result<()> {
    let store = Store::load(data_dir.to_path_buf())?;
    let project = resolve_project(&store, args.first())?.clone();
    println!(
        "watching for permission requests from '{}' (project {}). Ctrl+C to stop.",
        project.name, project.id
    );
    let (_stop_tx, stop_rx) = mpsc::channel::<()>();
    broker_loop(store.data_dir().to_path_buf(), project, ApprovePolicy::Deny, stop_rx, true);
    Ok(())
}

/// The headless equivalent of the GUI's broker: surface requests, get a
/// decision, write the answer, record the grant.
fn broker_loop(
    data_dir: PathBuf,
    project: Project,
    policy: ApprovePolicy,
    stop: mpsc::Receiver<()>,
    interactive: bool,
) {
    let mut store = match Store::load(data_dir) {
        Ok(store) => store,
        Err(err) => {
            eprintln!("[broker] cannot open the Deepsand store: {err}");
            return;
        }
    };
    let broker = Broker::new(store.data_dir(), &project.id);
    if let Err(err) = broker.ensure() {
        eprintln!("[broker] cannot prepare the spool: {err}");
        return;
    }

    loop {
        if stop.try_recv().is_ok() {
            return;
        }

        let (requests, rejected) = broker.scan_detailed();
        for bad in rejected {
            eprintln!("[broker] ignored {}: {}", bad.file, bad.reason);
        }

        for request in requests {
            eprintln!(
                "\n[broker] DeepCode is asking for: {}\n         purpose: {}\n         asks for: {} access\n         id: {}",
                request.description(),
                request.purpose().unwrap_or_else(|| "(none given)".into()),
                request.requested_access().label(),
                request.id
            );

            let decision = if interactive {
                prompt_decision(&request)
            } else {
                match policy {
                    ApprovePolicy::Deny => Decision::Deny("the headless broker denies by default".into()),
                    ApprovePolicy::GrantRead => Decision::Allow(request.requested_access(), None),
                    ApprovePolicy::GrantWrite => Decision::Allow(Access::ReadWrite, None),
                }
            };

            match decision {
                Decision::Deny(reason) => {
                    let _ = broker.answer(&PermissionResponse::deny(&request.id, &reason));
                    store.append_audit(&project.id, &format!("DENY  {} ({})", request.description(), reason));
                    eprintln!("[broker] denied.");
                }
                Decision::Allow(access, chosen_path) => {
                    let host_path = chosen_path.or_else(|| request.claimed_host_path().map(str::to_string));
                    let Some(host_path) = host_path else {
                        let _ =
                            broker.answer(&PermissionResponse::deny(&request.id, "no directory was provided"));
                        eprintln!("[broker] denied: no directory was named and none was chosen.");
                        continue;
                    };

                    match store.add_grant(
                        &project.id,
                        &host_path,
                        access,
                        "",
                        request.purpose().as_deref().unwrap_or_default(),
                        GrantSource::Request,
                    ) {
                        Ok(grant) => {
                            let _ = broker.answer(&PermissionResponse::allow(
                                &request.id,
                                "",
                                Some(GrantSpec {
                                    host_path: grant.host_path.clone(),
                                    container_path: grant.container_path.clone(),
                                    access: grant.access,
                                }),
                                true,
                            ));
                            store.append_audit(
                                &project.id,
                                &format!(
                                    "ALLOW {} {} -> {} ({})",
                                    grant.access.label(),
                                    grant.host_path,
                                    grant.container_path,
                                    request.description()
                                ),
                            );
                            eprintln!(
                                "[broker] granted {} -> {}. Restart the sandbox to attach it.",
                                grant.host_path, grant.container_path
                            );
                        }
                        Err(err) => {
                            let message = format!("{err}");
                            let _ = broker.answer(&PermissionResponse::deny(&request.id, &message));
                            store.append_audit(
                                &project.id,
                                &format!("DENY  {} (refused by policy: {message})", request.description()),
                            );
                            eprintln!("[broker] refused: {message}");
                        }
                    }
                }
            }
            broker.clear_request(&request.id);
        }

        std::thread::sleep(Duration::from_millis(400));
    }
}

enum Decision {
    Allow(Access, Option<String>),
    Deny(String),
}

fn prompt_decision(request: &PermissionRequest) -> Decision {
    println!();
    println!("  [a] allow read-only   [w] allow read-write   [c] choose a folder   [d] deny");
    print!("  decision [d]: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return Decision::Deny("no answer was read".into());
    }
    match line.trim().to_ascii_lowercase().as_str() {
        "a" => Decision::Allow(Access::ReadOnly, None),
        "w" => Decision::Allow(Access::ReadWrite, None),
        "c" => {
            print!("  path on this machine: ");
            let _ = std::io::stdout().flush();
            let mut path = String::new();
            if std::io::stdin().read_line(&mut path).is_err() {
                return Decision::Deny("no path was read".into());
            }
            let trimmed = path.trim().to_string();
            if trimmed.is_empty() {
                Decision::Deny("no path was given".into())
            } else {
                Decision::Allow(request.requested_access(), Some(trimmed))
            }
        }
        _ => Decision::Deny("the operator denied this request".into()),
    }
}

/* ------------------------------------------------------------------------- */
/* requests / network                                                        */
/* ------------------------------------------------------------------------- */

fn cmd_requests(data_dir: &Path, args: &[String]) -> Result<()> {
    let store = Store::load(data_dir.to_path_buf())?;
    let project = resolve_project(&store, args.first())?.clone();
    let broker = Broker::new(store.data_dir(), &project.id);
    let (requests, rejected) = broker.scan_detailed();

    if requests.is_empty() {
        println!("no requests are waiting for a decision.");
    }
    for request in &requests {
        println!("{}", request.id);
        println!("  kind     : {}", request.kind.as_str());
        println!("  wants    : {}", request.description());
        println!("  access   : {}", request.requested_access().label());
        println!("  purpose  : {}", request.purpose().unwrap_or_else(|| "(none)".into()));
        println!("  received : {}", request.created_at);
    }
    for bad in rejected {
        println!("ignored {}: {}", bad.file, bad.reason);
    }

    println!();
    println!("recent decisions:");
    for line in store.read_audit(&project.id, 10) {
        println!("  {line}");
    }
    Ok(())
}

fn cmd_network(data_dir: &Path, args: &[String]) -> Result<()> {
    let mut store = Store::load(data_dir.to_path_buf())?;
    let project = resolve_project(&store, args.first())?.clone();

    match args.get(1).map(String::as_str) {
        None => {
            println!("'{}' egress policy: {}", project.name, project.network.mode_str());
            match &project.network {
                NetworkPolicy::None => println!("  the container gets no interfaces beyond loopback"),
                NetworkPolicy::Internet => {
                    println!("  public internet reachable; host, LAN, link-local and cloud metadata blocked")
                }
                NetworkPolicy::Allowlisted { allow } => {
                    println!("  only DNS and the Deepsand allowlist proxy are reachable");
                    for host in allow {
                        println!("    - {host}");
                    }
                }
                NetworkPolicy::Full => println!("  unrestricted egress, including the host machine"),
            }
            Ok(())
        }
        Some(mode) => {
            let parsed = match mode {
                "none" => NetworkPolicy::None,
                "internet" => NetworkPolicy::Internet,
                "full" => NetworkPolicy::Full,
                "restricted" | "allowlisted" => NetworkPolicy::Allowlisted {
                    allow: store.settings().egress_allowlist.clone(),
                },
                other => {
                    return Err(SandboxError::Other(anyhow::anyhow!(
                        "unknown network mode '{other}'; expected none, internet, allowlisted or full"
                    )))
                }
            };
            let project_mut = store.project_mut(&project.id)?;
            project_mut.network = parsed;
            store.save()?;
            println!("'{}' egress policy is now {}", project.name, mode);
            Ok(())
        }
    }
}

/* ------------------------------------------------------------------------- */
/* helpers used by tests                                                     */
/* ------------------------------------------------------------------------- */

/// Convenience for reviewers: print the mounts a plan would create, grouped.
pub fn summarise_mounts(plan: &policy::RunPlan) -> String {
    let mut out = String::new();
    for kind in [
        MountKind::Workspace,
        MountKind::Grant,
        MountKind::Requests,
        MountKind::Responses,
        MountKind::State,
        MountKind::Config,
        MountKind::HomeVolume,
    ] {
        let count = plan.mounts.iter().filter(|m| m.kind == kind).count();
        out.push_str(&format!("  {kind:?}: {count}\n"));
    }
    out
}

/// Report whether a path may be shared. Used by `--check` style invocations.
pub fn check_path(data_dir: &Path, candidate: &str) -> Result<()> {
    let store = Store::load(data_dir.to_path_buf())?;
    let resolved = paths::canonical_existing_dir(candidate)?;
    paths::guard_mountable(&resolved, store.guards())?;
    println!("{} is allowed to be shared", resolved.display());
    Ok(())
}
