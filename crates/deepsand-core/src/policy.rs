//! Turns a project and its grants into an exact `docker run` argument vector.
//!
//! This is the security-critical module. Every containment guarantee Deepsand
//! makes is either expressed here or enforced by a file in `runtime/`, and the
//! argument vector is the complete, auditable statement of what the sandbox is:
//! there is no second path that starts a container.
//!
//! Design rules, in priority order:
//!
//! 1. **Only what was granted is mounted.** No host root, no docker socket, no
//!    user home, no package cache. The mount list is the whole boundary.
//! 2. **Nothing can be gained after start.** All capabilities are dropped,
//!    `no-new-privileges` is set, and the root filesystem is read-only, so the
//!    entrypoint's one privileged moment (installing egress rules) cannot be
//!    repeated by anything inside.
//! 3. **The sandbox never designs its own permissions.** Grants are read from
//!    the host store and re-validated here, so a compromised sandbox cannot
//!    smuggle a mount in through the request spool.

use crate::docker::{LABEL_MANAGED, LABEL_PROJECT_PREFIX};
use crate::error::{Result, SandboxError};
use crate::model::*;
use crate::paths::{self, PathGuards};
pub use crate::proxy::ProxyEndpoint;
use crate::settings;
use std::path::{Path, PathBuf};

/// What a mount is for. Used for validation, display and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountKind {
    /// The project directory. Always present, always read-write.
    Workspace,
    /// A host directory the operator approved.
    Grant,
    /// The sandbox's write-only channel to the broker.
    Requests,
    /// The broker's reply channel. Must be read-only.
    Responses,
    /// Sandbox self-description. Must be read-only.
    State,
    /// Generated DeepCode configuration (`settings.json` and `AGENTS.md`).
    /// Must be read-only.
    ///
    /// This is mounted as a *directory* rather than as two individual files, for
    /// two reasons. Docker Desktop on Windows presents host paths through a
    /// `grpcfuse` bridge that turns a single-file bind mount into an empty
    /// *directory* inside the container, so `/etc/deepsand/settings.json` would
    /// never exist and DeepCode would silently start with no credentials.
    /// And on every platform, a single-file bind keeps the inode it was created
    /// against, so an editor that saves by renaming leaves the container reading
    /// a stale file. Mounting the parent directory avoids both.
    Config,
    /// Named volume holding DeepCode's own sessions. Writable, but not a host
    /// path: it is opaque to the host and cannot reach one.
    HomeVolume,
}

impl MountKind {
    /// Mounts that must never be writable. Asserted by tests.
    pub fn must_be_read_only(self) -> bool {
        matches!(
            self,
            MountKind::Responses | MountKind::State | MountKind::Config
        )
    }
}

#[derive(Debug, Clone)]
pub struct MountSpec {
    pub kind: MountKind,
    /// Host path, or a volume name when `volume` is true.
    pub source: String,
    pub target: String,
    pub writable: bool,
    pub volume: bool,
}

impl MountSpec {
    /// The `-v` argument. Uses Docker's colon form rather than `--mount`
    /// because the CSV parsing of `--mount` would be confused by a comma in a
    /// directory name, while `-v` treats everything up to the last colon as the
    /// source.
    pub fn volume_arg(&self) -> String {
        format!(
            "{}:{}{}",
            self.source,
            self.target,
            if self.writable { "" } else { ":ro" }
        )
    }

    pub fn describe(&self) -> String {
        format!(
            "{:>13}  {:<55} -> {}{}",
            format!("{:?}", self.kind),
            self.source,
            self.target,
            if self.writable { "  (read-write)" } else { "  (read-only)" }
        )
    }
}

/// Inputs the plan is derived from. Everything comes from the host.
pub struct PlanInput<'a> {
    pub project: &'a Project,
    pub grants: &'a [Grant],
    pub app: &'a AppSettings,
    pub docker_status: &'a DockerStatus,
    pub data_dir: &'a Path,
    pub guards: &'a PathGuards,
    /// Absolute host path to `seccomp-hardened.json`, when hardening is on and
    /// the daemon can actually read host paths.
    pub seccomp_host_path: Option<&'a Path>,
    pub proxy: Option<&'a ProxyEndpoint>,
    /// Gateway address of the project's bridge network, for `restricted` mode.
    pub network_gateway: Option<String>,
    /// The model API's addresses as `ip:port`, resolved on the host.
    ///
    /// Passed as an explicit netfilter allowance because the sandboxed client does not
    /// use the egress proxy -- it builds its own dispatcher and ignores `HTTP_PROXY` --
    /// so a proxy-only policy cuts it off from the model entirely.
    pub model_endpoints: &'a [String],
    /// A file of `NAME=value` lines to hand the container as its environment.
    ///
    /// A file rather than `-e` pairs, because `-e` puts secret values into the
    /// process argument list where any local user can read them.
    pub secrets_env_file: Option<&'a Path>,
    ///
    /// Without this a default-deny sandbox cannot reach the model it is supposed to
    /// be running, which is the one destination that can never be optional.
    pub required_hosts: &'a [String],
    pub session_token: &'a str,
    /// How long the in-container bridge waits before reporting "pending".
    pub mcp_wait_ms: u32,
    /// Verified to be true only when the session volume really has an index.
    pub resume: bool,
}

#[derive(Debug, Clone)]
pub struct RunPlan {
    pub args: Vec<String>,
    pub container_name: String,
    pub mounts: Vec<MountSpec>,
    pub env: Vec<(String, String)>,
    pub warnings: Vec<String>,
    pub image: String,
    pub network_mode: String,
}

impl RunPlan {
    /// Human-readable rendering used by the "what will Deepsand run?" panel.
    ///
    /// The stored argv starts with the `run` subcommand because that is what is
    /// handed to the Docker CLI; the rendering drops it so the preview reads as
    /// a single `docker run ...` invocation.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        out.push_str("docker run \\\n");
        let body = if self.args.first().map(String::as_str) == Some("run") {
            &self.args[1..]
        } else {
            &self.args[..]
        };
        for arg in body {
            out.push_str(&format!("  {} \\\n", quote(arg)));
        }
        out.push('\n');
        out.push_str("Mounts (this list is the entire boundary):\n");
        if self.mounts.is_empty() {
            out.push_str("  (none)\n");
        }
        for mount in &self.mounts {
            out.push_str(&format!("  {}\n", mount.describe()));
        }
        if !self.warnings.is_empty() {
            out.push_str("\nWarnings:\n");
            for warning in &self.warnings {
                out.push_str(&format!("  * {warning}\n"));
            }
        }
        out
    }
}

fn quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_/.:=@,+{}".contains(c))
    {
        return arg.to_string();
    }
    if arg.contains('\'') {
        format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        format!("'{arg}'")
    }
}

/// The default command run inside the sandbox.
///
/// `--last` is only added when the caller has verified that a resumable session
/// exists, because the CLI exits(1) when it does not.
pub fn default_command(resume: bool) -> Vec<String> {
    let mut cmd = vec!["deepcode".to_string()];
    if resume {
        cmd.push("--last".to_string());
    }
    cmd
}

/// Build the plan. Returns an error rather than a weakened sandbox.
pub fn plan_run(input: &PlanInput<'_>) -> Result<RunPlan> {
    let project = input.project;
    let mut warnings: Vec<String> = Vec::new();

    /* --- validate the workspace, again ---------------------------------- */
    let workspace = paths::canonical_existing_dir(&project.root_dir)?;
    paths::guard_mountable(&workspace, input.guards)?;
    let workspace = dunce::simplified(&workspace).to_path_buf();

    let mut mounts: Vec<MountSpec> = Vec::new();
    mounts.push(MountSpec {
        kind: MountKind::Workspace,
        source: host_source(&workspace),
        target: Project::workspace_mount().to_string(),
        writable: true,
        volume: false,
    });

    /* --- grants, re-validated ------------------------------------------- */
    for grant in input.grants {
        let path = PathBuf::from(&grant.host_path);
        let resolved = match paths::canonical_existing_dir(&grant.host_path) {
            Ok(p) => p,
            Err(err) => {
                warnings.push(format!(
                    "share '{}' was skipped: {} Re-approve or remove it in Settings > Permissions.",
                    grant.label, err
                ));
                continue;
            }
        };
        // The guards run again at plan time so that a grant recorded before a
        // policy change can never be honoured afterwards.
        if let Err(err) = paths::guard_mountable(&resolved, input.guards) {
            warnings.push(format!("share '{}' was skipped: {err}", grant.label));
            continue;
        }
        if paths::is_within(&workspace, &resolved) {
            warnings.push(format!(
                "share '{}' was skipped: it is already inside the workspace.",
                grant.label
            ));
            continue;
        }
        if !paths::is_valid_slug(&grant.slug) {
            warnings.push(format!("share '{}' was skipped: its slug is not valid.", grant.label));
            continue;
        }
        if mounts.iter().any(|m| m.target == grant.container_path) {
            warnings.push(format!(
                "share '{}' was skipped: another share already uses {}.",
                grant.label, grant.container_path
            ));
            continue;
        }
        let _ = path; // the original string is only used for display
        mounts.push(MountSpec {
            kind: MountKind::Grant,
            source: host_source(&resolved),
            target: grant.container_path.clone(),
            writable: grant.access.is_write(),
            volume: false,
        });
    }

    /* --- Deepsand's own channels ---------------------------------------- */
    let project_dir = input.data_dir.join("projects").join(&project.id);
    let requests = project_dir.join("ipc").join("requests");
    let responses = project_dir.join("ipc").join("responses");
    let state_dir = project_dir.join("state");
    let config_dir = project_dir.join("config");

    mounts.push(MountSpec {
        kind: MountKind::Requests,
        source: host_source(&requests),
        target: settings::CONTAINER_REQUESTS.to_string(),
        // Writable: this is how the sandbox asks for things.
        writable: true,
        volume: false,
    });
    mounts.push(MountSpec {
        kind: MountKind::Responses,
        source: host_source(&responses),
        target: settings::CONTAINER_RESPONSES.to_string(),
        // READ-ONLY, and this is the linchpin of the whole permission model:
        // the sandbox can ask, but it cannot answer.
        writable: false,
        volume: false,
    });
    mounts.push(MountSpec {
        kind: MountKind::State,
        source: host_source(&state_dir),
        target: settings::CONTAINER_STATE.to_string(),
        writable: false,
        volume: false,
    });
    mounts.push(MountSpec {
        kind: MountKind::Config,
        // The whole directory, not the two files inside it. See the doc comment
        // on `MountKind::Config`: a single-file bind mount becomes an empty
        // directory under Docker Desktop's grpcfuse, and is stale-prone
        // everywhere else.
        source: host_source(&config_dir),
        target: settings::CONTAINER_CONFIG_DIR.to_string(),
        writable: false,
        volume: false,
    });
    mounts.push(MountSpec {
        kind: MountKind::HomeVolume,
        source: project.state_volume(),
        target: settings::CONTAINER_HOME_CONFIG.to_string(),
        writable: true,
        volume: true,
    });

    /* --- refuse anything that would punch a hole ------------------------ */
    audit_mounts(&mounts, input.data_dir)?;

    /* --- environment ---------------------------------------------------- */
    let mut env: Vec<(String, String)> = vec![
        ("DEEPSAND_NETWORK_MODE".into(), project.network.mode_str().to_string()),
        (
            "DEEPSAND_NETFILTER_OPTIONAL".into(),
            if input.app.security.netfilter_required { "0" } else { "1" }.to_string(),
        ),
        ("DEEPSAND_PROJECT".into(), project.id.clone()),
        ("DEEPSAND_UID".into(), settings::SANDBOX_UID.to_string()),
        ("DEEPSAND_GID".into(), settings::SANDBOX_GID.to_string()),
    ];

    if project.network.uses_proxy() {
        match (input.proxy, input.network_gateway.as_deref()) {
            (Some(proxy), Some(gateway)) => {
                // `none` means the model API and nothing else, so the project's own
                // list is not consulted; `restricted` uses it.
                let allow: Vec<String> = if project.network.honours_allowlist() {
                    match &project.network {
                        NetworkPolicy::Restricted { allow } => allow.clone(),
                        _ => Vec::new(),
                    }
                } else {
                    Vec::new()
                };
                let addr = format!("{gateway}:{}", proxy.port);
                env.push(("DEEPSAND_PROXY_ADDR".into(), addr.clone()));
                for key in [
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "http_proxy",
                    "https_proxy",
                    "npm_config_proxy",
                    "npm_config_https_proxy",
                    "YARN_HTTP_PROXY",
                ] {
                    env.push((key.into(), format!("http://{addr}")));
                }
                env.push(("NO_PROXY".into(), String::new()));

                if allow.is_empty() && input.required_hosts.is_empty() {
                    warnings.push(format!(
                        "{} network mode is on but no host is allowed, so nothing at all is reachable \
                         - not even the model API.",
                        project.network.mode_str()
                    ));
                }
            }
            _ => {
                return Err(SandboxError::policy(
                    "restricted network mode needs the Deepsand egress proxy, but none is running. Start the project \
                     again, or switch the project to 'internet' or 'none' in Settings.",
                ));
            }
        }
    }

    /* --- network flags -------------------------------------------------- */
    // `none` deliberately does NOT use `--network=none` any more. With no
    // interfaces the sandbox cannot reach the proxy on the host, so it could not
    // reach its own model API and the mode was unusable. It runs on the normal
    // bridge instead, and the in-container rules restrict it to the proxy -- the
    // same shape as restricted mode.
    let network_args: Vec<String> = Vec::new();

    /* --- capabilities --------------------------------------------------- */
    // These four are only needed by the entrypoint's startup sequence. It drops
    // every one of them from its own bounding set before exec'ing DeepCode, and
    // nothing else in the container ever runs as root.
    let mut cap_args: Vec<String> = vec![
        "--cap-drop=ALL".into(),
        "--cap-add=CHOWN".into(),   // adopt the freshly created state volume
        "--cap-add=SETUID".into(),  // drop to uid 1000
        "--cap-add=SETGID".into(),
    ];
    if project.network.needs_netfilter() {
        // Only ever in the container's own network namespace, and revoked
        // before DeepCode starts.
        cap_args.push("--cap-add=NET_ADMIN".into());
    }

    /* --- security options ---------------------------------------------- */
    let mut sec_args: Vec<String> = Vec::new();
    if input.app.security.no_new_privileges {
        sec_args.push("--security-opt=no-new-privileges".into());
    }
    // The Docker CLI reads this file and inlines the JSON into the request, so it
    // works even when the daemon runs in a VM and cannot see host paths. Verified by
    // inspecting a container created this way: HostConfig.SecurityOpt carries the whole
    // profile. The previous check for Docker Desktop was based on the opposite belief
    // and quietly disabled the control.
    if input.app.security.seccomp == SeccompProfile::Hardened {
        match input.seccomp_host_path {
            Some(path) => {
                sec_args.push(format!("--security-opt=seccomp={}", path.display()));
            }
            None => {
                // Fail closed rather than run a weaker sandbox than was asked for.
                return Err(SandboxError::Policy(
                    "hardened seccomp was requested but the profile could not be found, so the sandbox \
                     would be started without the control that denies AF_VSOCK and the user-namespace \
                     exploit class. Restore seccomp-hardened.json, or switch hardening off in Settings \
                     to run without it deliberately."
                        .to_string(),
                ));
            }
        }
    }
    if input.app.security.apparmor {
        if input.docker_status.desktop {
            warnings.push(
                "AppArmor is not enforced by Docker Desktop on this platform, so the default profile is not applied."
                    .to_string(),
            );
        } else {
            sec_args.push("--security-opt=apparmor=docker-default".into());
        }
    }

    /* --- assemble ------------------------------------------------------- */
    let limits = &project.limits;
    let image = input.app.image.clone();

    let mut args: Vec<String> = vec!["run".into()];

    // The model API, by address: the one destination that must work in every mode,
    // because a sandbox that cannot reach its model cannot do anything at all.
    if !input.model_endpoints.is_empty() {
        env.push((
            "DEEPSAND_MODEL_ADDRS".into(),
            input.model_endpoints.join(","),
        ));
    }

    // Secrets reach the sandbox through the environment, and only this way: never on
    // the command line, never in the plan's own text.
    if let Some(path) = input.secrets_env_file {
        args.push("--env-file".into());
        args.push(path.display().to_string());
    }

    // `host.docker.internal` is how a restricted sandbox reaches the egress proxy on
    // the host. Docker Desktop adds that name by itself; a native Linux daemon does
    // not, so map it to the gateway -- the daemon resolves `host-gateway`, so this is
    // correct on both and the container never needs to learn the host's address.
    if project.network.uses_proxy() {
        args.push("--add-host=host.docker.internal:host-gateway".into());
    }
    args.push("--rm".into());
    args.push("-i".into());
    args.push("-t".into());
    args.push("--init".into());
    args.push("--name".into());
    args.push(project.container_name());
    args.push("--hostname".into());
    args.push("deepsand".into());
    args.push("--label".into());
    args.push(LABEL_MANAGED.to_string());
    args.push("--label".into());
    args.push(format!("{LABEL_PROJECT_PREFIX}{}", project.id));
    args.push("--workdir".into());
    args.push(Project::workspace_mount().to_string());
    // Root for exactly as long as the entrypoint needs, then irreversible drop.
    args.push("--user".into());
    args.push("0:0".into());

    if input.app.security.read_only_rootfs {
        args.push("--read-only".into());
        args.push("--tmpfs".into());
        args.push(format!(
            "/tmp:rw{}nosuid,nodev,size={}m",
            if input.app.security.tmpfs_noexec { ",noexec," } else { "," },
            limits.tmpfs_mb
        ));
        args.push("--tmpfs".into());
        args.push("/run:rw,nosuid,nodev,size=16m".to_string());
    } else {
        warnings.push(
            "the root filesystem is writable for this project. That is a downgrade from the default; only the mounts \
             are still guaranteed."
                .to_string(),
        );
    }

    args.extend(cap_args);
    args.extend(sec_args);
    args.extend(network_args);

    args.push(format!("--pids-limit={}", limits.pids_limit));
    args.push(format!("--memory={}m", limits.memory_mb));
    // Equal to --memory, which disables swap for the container.
    args.push(format!("--memory-swap={}m", limits.memory_mb));
    args.push(format!("--cpus={}", limits.cpus));
    args.push("--ulimit".into());
    args.push("nofile=8192:16384".into());
    args.push(format!("--stop-timeout={}", limits.stop_timeout_s));

    for (key, value) in &env {
        args.push("--env".into());
        args.push(format!("{key}={value}"));
    }
    for mount in &mounts {
        args.push("-v".into());
        args.push(mount.volume_arg());
    }

    args.push(image.clone());
    args.extend(default_command(input.resume));

    /* --- cross-checks --------------------------------------------------- */
    if !input.docker_status.available {
        return Err(SandboxError::DockerUnavailable(
            "the Docker daemon is not reachable, so the sandbox cannot be started.".to_string(),
        ));
    }
    if !input.app.security.netfilter_required {
        warnings.push(
            "kernel-level egress rules are optional for this installation: if the sandbox cannot install them it \
             will still start, and the network policy will not be enforced."
                .to_string(),
        );
    }
    if let Some(network) = match &project.network {
        NetworkPolicy::Full => Some("full"),
        _ => None,
    } {
        warnings.push(format!(
            "network mode '{network}' places no restriction on egress, so the sandbox can reach this machine's \
             network services. Filesystem isolation is unaffected."
        ));
    }

    Ok(RunPlan {
        args,
        container_name: project.container_name(),
        mounts,
        env,
        warnings,
        image,
        network_mode: project.network.mode_str().to_string(),
    })
}

/// Convert a host path into the form Docker expects as a bind source.
fn host_source(path: &Path) -> String {
    // `dunce::simplified` already stripped `\\?\`; forward slashes are accepted
    // by the Docker CLI on every platform and avoid escaping questions.
    path.to_string_lossy().replace('\\', "/")
}

/// Final defensive sweep over the assembled mount list.
///
/// These are invariants, not policy: if one of them is ever violated the bug is
/// in Deepsand itself, so the correct response is to refuse to start rather
/// than to run a sandbox with a hole in it.
fn audit_mounts(mounts: &[MountSpec], data_dir: &Path) -> Result<()> {
    let socket_markers = ["docker.sock", "docker_engine", "//./pipe/docker", "containerd.sock", "podman.sock"];

    for mount in mounts {
        let source_lower = mount.source.to_lowercase();

        for marker in socket_markers {
            if source_lower.contains(marker) {
                return Err(SandboxError::policy(format!(
                    "refusing to mount '{}': it looks like a container runtime socket, which would hand the sandbox \
                     control of the host's Docker daemon.",
                    mount.source
                )));
            }
        }

        if mount.kind.must_be_read_only() && mount.writable {
            return Err(SandboxError::policy(format!(
                "internal error: the {:?} mount must be read-only but the plan made it writable.",
                mount.kind
            )));
        }

        if mount.target == "/" || mount.target.starts_with("/proc") || mount.target.starts_with("/sys") {
            return Err(SandboxError::policy(format!(
                "refusing to mount over the container's own '{}'.",
                mount.target
            )));
        }

        if mount.kind == MountKind::Grant && !mount.target.starts_with(&format!("{}/", settings::CONTAINER_GRANTS_ROOT))
        {
            return Err(SandboxError::policy(format!(
                "internal error: grant mount target '{}' is outside {}.",
                mount.target,
                settings::CONTAINER_GRANTS_ROOT
            )));
        }

        if !mount.volume {
            let source = PathBuf::from(&mount.source);
            if !source.is_absolute() {
                return Err(SandboxError::policy(format!(
                    "refusing to mount the relative path '{}'.",
                    mount.source
                )));
            }
        }
    }

    // The sandbox's own writable channels must never overlap its read-only ones.
    let state_root = data_dir
        .join("projects")
        .to_string_lossy()
        .replace('\\', "/")
        .to_lowercase();
    for mount in mounts {
        if !mount.volume && mount.writable && mount.source.to_lowercase().starts_with(&state_root) {
            if mount.kind != MountKind::Requests {
                return Err(SandboxError::policy(format!(
                    "internal error: {:?} is writable inside Deepsand's own state directory.",
                    mount.kind
                )));
            }
        }
    }

    let mut targets: Vec<&str> = mounts.iter().map(|m| m.target.as_str()).collect();
    targets.sort_unstable();
    for pair in targets.windows(2) {
        if pair[0] == pair[1] {
            return Err(SandboxError::policy(format!(
                "internal error: two mounts target the same path '{}'.",
                pair[0]
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_guards(root: &Path) -> PathGuards {
        PathGuards::new(root.join("home"), root.join("data"), root.join("home").join(".deepcode"))
    }

    fn docker_status() -> DockerStatus {
        DockerStatus {
            available: true,
            desktop: true,
            ..DockerStatus::default()
        }
    }

    struct Fixture {
        dir: PathBuf,
        project: Project,
        grants: Vec<Grant>,
        app: AppSettings,
        guards: PathGuards,
        data_dir: PathBuf,
        /// A profile file that exists. Hardening is the default now and a missing profile
        /// stops the plan, so a fixture without one would be testing the refusal instead
        /// of whatever the test is named after.
        seccomp_profile: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("deepsand-policy-{name}-{}", crate::now_ms()));
            let _ = std::fs::create_dir_all(&dir);
            let seccomp_profile = dir.join("seccomp-hardened.json");
            let _ = std::fs::write(&seccomp_profile, "{}");
            let home = dir.join("home");
            let data_dir = dir.join("data");
            let workspace = dir.join("projects").join("my-website");
            std::fs::create_dir_all(&workspace).unwrap();
            std::fs::create_dir_all(&data_dir).unwrap();
            std::fs::create_dir_all(&home).unwrap();
            std::fs::create_dir_all(data_dir.join("projects").join("p1").join("ipc").join("requests")).unwrap();
            std::fs::create_dir_all(data_dir.join("projects").join("p1").join("ipc").join("responses")).unwrap();
            std::fs::create_dir_all(data_dir.join("projects").join("p1").join("state")).unwrap();
            std::fs::create_dir_all(data_dir.join("projects").join("p1").join("config")).unwrap();

            let project = Project {
                id: "p1".into(),
                name: "my-website".into(),
                slug: "my-website".into(),
                root_dir: workspace.to_string_lossy().to_string(),
                created_at_ms: 0,
                network: NetworkPolicy::Internet,
                limits: ResourceLimits::default(),
                credentials: Credentials::default(),
                deepcode_mode: DeepCodeMode::AllowAll,
                allowed_roots: vec![],
                notes: String::new(),
                reasoning_effort: Default::default(),
                tools: None,
            };

            Self {
                guards: test_guards(&dir),
                project,
                grants: vec![],
                app: AppSettings::default(),
                data_dir,
                dir,
                seccomp_profile,
            }
        }

        fn app(&self) -> AppSettings {
            self.app.clone()
        }

        fn input<'a>(
            &'a self,
            app: &'a AppSettings,
            status: &'a DockerStatus,
        ) -> PlanInput<'a> {
            PlanInput {
                project: &self.project,
                grants: &self.grants,
                app,
                docker_status: status,
                data_dir: &self.data_dir,
                guards: &self.guards,
                seccomp_host_path: Some(&self.seccomp_profile),
                proxy: None,
                network_gateway: None,
            required_hosts: &[],
            secrets_env_file: None,
            model_endpoints: &[],
                session_token: "tok",
                mcp_wait_ms: 45_000,
                resume: false,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn arg_value<'a>(plan: &'a RunPlan, flag: &str) -> Option<&'a str> {
        plan.args.windows(2).find(|w| w[0] == flag).map(|w| w[1].as_str())
    }

    fn has_pair(plan: &RunPlan, flag: &str, value: &str) -> bool {
        plan.args.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    #[test]
    fn a_plan_never_mounts_a_container_runtime_socket() {
        let fixture = Fixture::new("no-socket");
        let app = fixture.app();
        let status = docker_status();
        let plan = plan_run(&fixture.input(&app, &status)).unwrap();

        let joined = plan.args.join(" ").to_lowercase();
        for marker in ["docker.sock", "docker_engine", "containerd.sock", "podman.sock", "/var/run/docker"] {
            assert!(!joined.contains(marker), "plan mentions {marker}: {joined}");
        }
    }

    #[test]
    fn the_default_plan_is_strongly_hardened() {
        let fixture = Fixture::new("hardened");
        let app = fixture.app();
        let status = docker_status();
        let plan = plan_run(&fixture.input(&app, &status)).unwrap();

        assert!(plan.args.iter().any(|a| a == "--read-only"));
        assert!(plan.args.iter().any(|a| a == "--cap-drop=ALL"));
        assert!(plan.args.iter().any(|a| a == "--security-opt=no-new-privileges"));
        assert!(plan.args.iter().any(|a| a == "--init"));
        assert!(plan.args.iter().any(|a| a == "--rm"));
        assert!(plan.args.iter().any(|a| a == "--pids-limit=512"));
        assert!(plan.args.iter().any(|a| a == "--memory=4096m"));
        assert!(plan.args.iter().any(|a| a == "--memory-swap=4096m"));
        assert!(plan.args.iter().any(|a| a == "--cpus=2"));
    }

    #[test]
    fn only_the_workspace_and_grants_are_mounted_from_the_host_filesystem() {
        let mut fixture = Fixture::new("mount-set");
        let shared = fixture.dir.join("shared-theme");
        std::fs::create_dir_all(&shared).unwrap();
        fixture.grants = vec![Grant {
            id: "g1".into(),
            project_id: "p1".into(),
            host_path: shared.to_string_lossy().to_string(),
            container_path: "/grants/shared-theme".into(),
            slug: "shared-theme".into(),
            access: Access::ReadOnly,
            label: "shared-theme".into(),
            purpose: "theme".into(),
            source: GrantSource::Request,
            created_at_ms: 0,
            expires_at_ms: None,
        }];

        let app = fixture.app();
        let status = docker_status();
        let plan = plan_run(&fixture.input(&app, &status)).unwrap();

        let bind_sources: Vec<&str> = plan
            .mounts
            .iter()
            .filter(|m| !m.volume)
            .map(|m| m.source.as_str())
            .collect();

        let workspace = dunce::simplified(&std::fs::canonicalize(&fixture.project.root_dir).unwrap())
            .to_string_lossy()
            .replace('\\', "/");
        assert!(bind_sources.contains(&workspace.as_str()), "{bind_sources:?}");
        assert!(
            bind_sources.iter().any(|s| s.ends_with("/shared-theme")),
            "{bind_sources:?}"
        );
        // Everything else must live under Deepsand's private project directory.
        let project_dir = fixture.data_dir.join("projects").join("p1").to_string_lossy().replace('\\', "/");
        let shared_normalised = dunce::simplified(&std::fs::canonicalize(&shared).unwrap())
            .to_string_lossy()
            .replace('\\', "/");

        // A bind source may only be one of exactly three things: the workspace,
        // a directory the operator granted, or one of Deepsand's own runtime
        // files for this project. Anything else would mean the boundary had
        // grown a hole.
        for source in &bind_sources {
            assert!(
                *source == workspace
                    || *source == shared_normalised
                    || source.starts_with(&format!("{project_dir}/")),
                "unexpected host mount: {source}"
            );
        }
        // workspace + 1 grant + requests + responses + state + config = 6 binds,
        // plus the session-state named volume.
        assert_eq!(bind_sources.len(), 6, "unexpected bind mounts: {bind_sources:#?}");
        assert_eq!(
            plan.mounts.iter().filter(|m| m.volume).count(),
            1,
            "the session state volume should be the only named volume"
        );
    }

    #[test]
    fn the_reply_channel_can_never_be_written_by_the_sandbox() {
        let fixture = Fixture::new("reply-ro");
        let app = fixture.app();
        let status = docker_status();
        let plan = plan_run(&fixture.input(&app, &status)).unwrap();

        let responses = plan.mounts.iter().find(|m| m.kind == MountKind::Responses).unwrap();
        assert!(!responses.writable, "the response spool must be read-only");
        assert!(responses.volume_arg().ends_with(":ro"));

        let requests = plan.mounts.iter().find(|m| m.kind == MountKind::Requests).unwrap();
        assert!(requests.writable);

        for kind in [MountKind::State, MountKind::Config] {
            let mount = plan.mounts.iter().find(|m| m.kind == kind).unwrap();
            assert!(!mount.writable, "{kind:?} must be read-only");
            assert!(mount.volume_arg().ends_with(":ro"), "{kind:?} must carry :ro");
        }
    }

    /// The configuration must be mounted as a directory, not as the two files
    /// inside it. Docker Desktop on Windows presents a single-file bind mount as
    /// an empty directory, so a per-file mount leaves `/etc/deepsand/settings.json`
    /// non-existent and DeepCode starts with no credentials.
    #[test]
    fn the_configuration_is_mounted_as_a_directory_not_as_files() {
        let fixture = Fixture::new("config-mount");
        let app = fixture.app();
        let status = docker_status();
        let plan = plan_run(&fixture.input(&app, &status)).unwrap();

        let config = plan
            .mounts
            .iter()
            .find(|m| m.kind == MountKind::Config)
            .expect("a Config mount must exist");
        assert_eq!(config.target, settings::CONTAINER_CONFIG_DIR);
        assert_eq!(
            config.source,
            host_source(
                &fixture
                    .data_dir
                    .join("projects")
                    .join(&fixture.project.id)
                    .join("config")
            )
        );
        assert!(
            !config.target.ends_with("settings.json"),
            "the config mount must be the directory, not a file inside it"
        );
        assert!(
            !config.source.ends_with("settings.json"),
            "the config mount source must be the directory, not a file inside it"
        );
        assert_eq!(
            plan.mounts
                .iter()
                .filter(|m| m.target.starts_with("/etc/deepsand"))
                .count(),
            1,
            "there must be exactly one mount under /etc/deepsand"
        );
    }

    #[test]
    fn a_writable_reply_channel_is_rejected_as_an_internal_error() {
        let fixture = Fixture::new("reply-rw-guard");
        let mounts = vec![MountSpec {
            kind: MountKind::Responses,
            source: "/tmp/x".into(),
            target: settings::CONTAINER_RESPONSES.into(),
            writable: true,
            volume: false,
        }];
        let err = audit_mounts(&mounts, &fixture.data_dir).unwrap_err();
        assert!(err.to_string().contains("read-only"), "{err}");
    }

    #[test]
    fn a_docker_socket_mount_is_rejected_as_an_internal_error() {
        let fixture = Fixture::new("socket-guard");
        for source in ["/var/run/docker.sock", "//./pipe/docker_engine", "/run/containerd/containerd.sock"] {
            let mounts = vec![MountSpec {
                kind: MountKind::Grant,
                source: source.into(),
                target: "/grants/x".into(),
                writable: false,
                volume: false,
            }];
            let err = audit_mounts(&mounts, &fixture.data_dir).unwrap_err();
            assert!(err.to_string().contains("runtime socket"), "{source}: {err}");
        }
    }

    #[test]
    fn grant_mounts_must_stay_under_the_grants_root() {
        let fixture = Fixture::new("grant-root");
        let mounts = vec![MountSpec {
            kind: MountKind::Grant,
            source: "/tmp/x".into(),
            target: "/etc/shadow".into(),
            writable: false,
            volume: false,
        }];
        let err = audit_mounts(&mounts, &fixture.data_dir).unwrap_err();
        assert!(err.to_string().contains("outside /grants"), "{err}");
    }

    #[test]
    fn a_second_writable_mount_inside_deepsand_state_is_rejected() {
        let fixture = Fixture::new("state-guard");
        // The request spool is the *only* writable thing Deepsand exposes from
        // its own state directory. Anything else writable in there would let
        // the sandbox edit its own permissions or the settings it is given.
        let mounts = vec![MountSpec {
            kind: MountKind::Workspace,
            source: fixture
                .data_dir
                .join("projects")
                .join("p1")
                .join("config")
                .to_string_lossy()
                .replace('\\', "/"),
            target: "/workspace".into(),
            writable: true,
            volume: false,
        }];
        let err = audit_mounts(&mounts, &fixture.data_dir).unwrap_err();
        assert!(err.to_string().contains("state directory"), "{err}");
    }

    #[test]
    fn capabilities_are_dropped_then_re_added_only_where_needed() {
        let fixture = Fixture::new("caps");
        let app = fixture.app();
        let status = docker_status();

        // internet mode needs NET_ADMIN for the kernel-level egress rules.
        let mut project = fixture.project.clone();
        project.network = NetworkPolicy::Internet;
        let input = PlanInput {
            project: &project,
            grants: &[],
            app: &app,
            docker_status: &status,
            data_dir: &fixture.data_dir,
            guards: &fixture.guards,
            seccomp_host_path: Some(&fixture.seccomp_profile),
            proxy: None,
            network_gateway: None,
            required_hosts: &[],
            secrets_env_file: None,
            model_endpoints: &[],
            session_token: "t",
            mcp_wait_ms: 1000,
            resume: false,
        };
        let plan = plan_run(&input).unwrap();
        assert!(plan.args.iter().any(|a| a == "--cap-add=NET_ADMIN"));

        // full mode does not: no rules are installed at all.
        let mut project_full = fixture.project.clone();
        project_full.network = NetworkPolicy::Full;
        let input = PlanInput { project: &project_full, ..input };
        let plan = plan_run(&input).unwrap();
        assert!(!plan.args.iter().any(|a| a == "--cap-add=NET_ADMIN"));
        assert!(plan.args.iter().any(|a| a == "--cpus=2"));

    }

    /// Secrets reach the sandbox through an env file, never through `-e`.
    ///
    /// `-e` would put every value into the process argument list, where `ps` shows it
    /// to any local user. This test is the thing that keeps that from regressing.
    #[test]
    fn secrets_are_passed_as_a_file_and_never_as_a_flag() {
        let fixture = Fixture::new("secrets-env-file");
        let app = fixture.app();
        let status = docker_status();
        let env_file = std::path::PathBuf::from("/data/projects/p1/config/secrets.env");

        let plan = plan_run(&PlanInput {
            project: &fixture.project,
            grants: &[],
            app: &app,
            docker_status: &status,
            data_dir: &fixture.data_dir,
            guards: &fixture.guards,
            seccomp_host_path: Some(&fixture.seccomp_profile),
            proxy: None,
            network_gateway: None,
            required_hosts: &[],
            secrets_env_file: Some(&env_file),
            model_endpoints: &[],
            session_token: "t",
            mcp_wait_ms: 1000,
            resume: false,
        })
        .expect("a plan with an env file");

        assert!(
            has_pair(&plan, "--env-file", "/data/projects/p1/config/secrets.env"),
            "the env file must be handed to docker: {:?}",
            plan.args
        );

        // And no `--env` pair that is not one of the sandbox's own variables, which
        // would mean something value-shaped leaked onto the command line.
        let suspicious: Vec<&String> = plan
            .args
            .windows(2)
            .filter(|pair| pair[0] == "--env")
            .map(|pair| &pair[1])
            .filter(|value| !value.starts_with("DEEPSAND_"))
            .collect();
        assert!(
            suspicious.is_empty(),
            "only the sandbox's own variables may be passed with -e: {suspicious:?}"
        );
    }

    /// A plan without secrets must not carry a stale `--env-file`, or a container
    /// would be handed whatever the last run left behind.
    #[test]
    fn no_env_file_means_no_argument() {
        let fixture = Fixture::new("no-secrets");
        let app = fixture.app();
        let status = docker_status();

        let plan = plan_run(&PlanInput {
            project: &fixture.project,
            grants: &[],
            app: &app,
            docker_status: &status,
            data_dir: &fixture.data_dir,
            guards: &fixture.guards,
            seccomp_host_path: Some(&fixture.seccomp_profile),
            proxy: None,
            network_gateway: None,
            required_hosts: &[],
            secrets_env_file: None,
            model_endpoints: &[],
            session_token: "t",
            mcp_wait_ms: 1000,
            resume: false,
        })
        .expect("a plan");

        assert!(!plan.args.iter().any(|arg| arg == "--env-file"));
    }

    /// `none` means the model endpoint and nothing else, and it must refuse to build
    /// a plan without the proxy for the same reason restricted mode does.
    #[test]
    fn none_mode_requires_the_proxy_and_reaches_only_the_model() {
        let fixture = Fixture::new("none-mode");
        let app = fixture.app();
        let status = docker_status();

        let mut project = fixture.project.clone();
        project.network = NetworkPolicy::None;

        let required = vec!["api.deepseek.com".to_string()];
        let endpoints = vec!["203.0.113.7:443".to_string()];

        let build = |proxy: Option<&ProxyEndpoint>, endpoints: &[String]| {
            plan_run(&PlanInput {
                project: &project,
                grants: &[],
                app: &app,
                docker_status: &status,
                data_dir: &fixture.data_dir,
                guards: &fixture.guards,
                seccomp_host_path: Some(&fixture.seccomp_profile),
                proxy,
                network_gateway: proxy.map(|_| "host.docker.internal".to_string()),
                required_hosts: &required,
                secrets_env_file: None,
                model_endpoints: endpoints,
                session_token: "t",
                mcp_wait_ms: 1000,
                resume: false,
            })
        };

        // `none` no longer needs a proxy. It used to demand one, which was the bug the
        // operator hit first: the mode refused to start over a component it has no use
        // for, and the proxy could not carry the model traffic anyway.
        let plan = build(None, &endpoints).expect("none must plan without a proxy");

        // It keeps an interface, because that is how it reaches the model.
        assert!(
            !plan.args.iter().any(|a| a == "--network=none"),
            "none must keep an interface so it can reach the model API"
        );
        assert!(plan.args.iter().any(|a| a == "--cap-add=NET_ADMIN"));

        // The model's address is what makes it work, and it is passed through as an
        // address rather than a name because the container cannot resolve one.
        assert!(has_pair(&plan, "--env", "DEEPSAND_MODEL_ADDRS=203.0.113.7:443"));

        // And nothing proxy-shaped, since nothing would use it.
        assert!(!plan.args.iter().any(|a| a == "--add-host=host.docker.internal:host-gateway"));
        let proxy_env = plan
            .args
            .windows(2)
            .filter(|pair| pair[0] == "--env")
            .map(|pair| pair[1].clone())
            .filter(|value| value.starts_with("HTTP_PROXY") || value.starts_with("DEEPSAND_PROXY_ADDR"))
            .collect::<Vec<_>>();
        assert!(proxy_env.is_empty(), "none must not export a proxy: {proxy_env:?}");

        // Without endpoints there is nothing to allow, and the plan still builds -- the
        // netfilter warns instead of the start failing.
        assert!(build(None, &[]).is_ok());
    }

    #[test]
    fn restricted_mode_requires_the_proxy_and_wires_up_the_environment() {
        let fixture = Fixture::new("restricted");
        let mut app = fixture.app();
        app.egress_allowlist = vec!["api.deepseek.com".into()];
        let status = docker_status();

        let mut project = fixture.project.clone();
        project.network = NetworkPolicy::Restricted { allow: app.egress_allowlist.clone() };

        // Without a proxy the plan must refuse rather than silently allow.
        let bare = PlanInput {
            project: &project,
            grants: &[],
            app: &app,
            docker_status: &status,
            data_dir: &fixture.data_dir,
            guards: &fixture.guards,
            seccomp_host_path: Some(&fixture.seccomp_profile),
            proxy: None,
            network_gateway: None,
            required_hosts: &[],
            secrets_env_file: None,
            model_endpoints: &[],
            session_token: "t",
            mcp_wait_ms: 1000,
            resume: false,
        };
        let err = plan_run(&bare).unwrap_err();
        assert!(err.to_string().contains("egress proxy"), "{err}");

        let proxy = ProxyEndpoint { host: "172.28.0.1".into(), port: 8917 };
        let wired = PlanInput {
            proxy: Some(&proxy),
            network_gateway: Some("172.28.0.1".into()),
            required_hosts: &[],
            secrets_env_file: None,
            model_endpoints: &[],
            ..bare
        };
        let plan = plan_run(&wired).unwrap();
        assert!(has_pair(&plan, "--env", "DEEPSAND_PROXY_ADDR=172.28.0.1:8917"));
        assert!(has_pair(&plan, "--env", "HTTPS_PROXY=http://172.28.0.1:8917"));
        assert!(has_pair(&plan, "--env", "http_proxy=http://172.28.0.1:8917"));
        // The proxy address is the only thing the netfilter script will allow,
        // so it must have been communicated.
        assert!(plan.env.iter().any(|(k, _)| k == "DEEPSAND_PROXY_ADDR"));
    }

    #[test]
    fn the_workspace_is_validated_again_at_plan_time() {
        let mut fixture = Fixture::new("revalidate");
        let app = fixture.app();
        let status = docker_status();

        // Simulate a project whose root was later repointed at the home dir.
        fixture.project.root_dir = fixture.guards.home.to_string_lossy().to_string();
        std::fs::create_dir_all(&fixture.guards.home).unwrap();
        let err = plan_run(&fixture.input(&app, &status)).unwrap_err();
        assert!(matches!(err, SandboxError::Policy(_)), "{err}");
    }

    #[test]
    fn a_grant_that_became_forbidden_is_skipped_with_a_warning_not_mounted() {
        let mut fixture = Fixture::new("grant-skip");
        let app = fixture.app();
        let status = docker_status();

        // A grant pointing at the home directory can only have got into the
        // store through a bug or a hand-edited file; the plan must ignore it.
        fixture.grants = vec![Grant {
            id: "g1".into(),
            project_id: "p1".into(),
            host_path: fixture.guards.home.to_string_lossy().to_string(),
            container_path: "/grants/home".into(),
            slug: "home".into(),
            access: Access::ReadWrite,
            label: "home".into(),
            purpose: String::new(),
            source: GrantSource::User,
            created_at_ms: 0,
            expires_at_ms: None,
        }];
        std::fs::create_dir_all(&fixture.guards.home).unwrap();

        let plan = plan_run(&fixture.input(&app, &status)).unwrap();
        assert!(
            !plan.mounts.iter().any(|m| m.kind == MountKind::Grant),
            "the forbidden grant must not be mounted"
        );
        assert!(plan.warnings.iter().any(|w| w.contains("skipped")), "{:?}", plan.warnings);
    }

    #[test]
    fn resume_is_opt_in_and_uses_last() {
        let fixture = Fixture::new("resume");
        let app = fixture.app();
        let status = docker_status();

        let plan = plan_run(&fixture.input(&app, &status)).unwrap();
        assert_eq!(plan.args.last().unwrap(), "deepcode");
        assert!(!plan.args.iter().any(|a| a == "--last"));

        let input = PlanInput { resume: true, ..fixture.input(&app, &status) };
        let plan = plan_run(&input).unwrap();
        assert_eq!(plan.args.last().unwrap(), "--last");
        assert_eq!(plan.args[plan.args.len() - 2], "deepcode");
    }

    #[test]
    fn the_image_is_always_the_last_non_command_argument() {
        let fixture = Fixture::new("image-order");
        let mut app = fixture.app();
        app.image = "deepsand/runtime:9.9.9".into();
        let status = docker_status();
        let plan = plan_run(&fixture.input(&app, &status)).unwrap();
        let position = plan.args.iter().position(|a| a == &plan.image).unwrap();
        assert_eq!(position, plan.args.len() - 2);
    }

    #[test]
    fn a_plan_is_refused_when_the_daemon_is_down() {
        let fixture = Fixture::new("no-daemon");
        let app = fixture.app();
        let status = DockerStatus { available: false, ..DockerStatus::default() };
        let err = plan_run(&fixture.input(&app, &status)).unwrap_err();
        assert!(matches!(err, SandboxError::DockerUnavailable(_)), "{err}");
    }

    #[test]
    fn resource_limits_are_reflected_exactly() {
        let mut fixture = Fixture::new("limits");
        fixture.project.limits = ResourceLimits {
            memory_mb: 1024,
            cpus: 1.5,
            pids_limit: 128,
            tmpfs_mb: 512,
            stop_timeout_s: 3,
        };
        let app = fixture.app();
        let status = docker_status();
        let plan = plan_run(&fixture.input(&app, &status)).unwrap();

        assert!(plan.args.iter().any(|a| a == "--memory=1024m"));
        assert!(plan.args.iter().any(|a| a == "--memory-swap=1024m"));
        assert!(plan.args.iter().any(|a| a == "--cpus=1.5"));
        assert!(plan.args.iter().any(|a| a == "--pids-limit=128"));
        assert!(plan.args.iter().any(|a| a == "--stop-timeout=3"));
        let tmpfs = arg_value(&plan, "--tmpfs").unwrap();
        assert!(tmpfs.starts_with("/tmp:") && tmpfs.contains("size=512m"), "{tmpfs}");
    }

    #[test]
    fn the_read_only_rootfs_can_only_be_disabled_with_a_warning() {
        let fixture = Fixture::new("rw-rootfs");
        let mut app = fixture.app();
        app.security.read_only_rootfs = false;
        let status = docker_status();
        let plan = plan_run(&fixture.input(&app, &status)).unwrap();
        assert!(!plan.args.iter().any(|a| a == "--read-only"));
        assert!(plan.warnings.iter().any(|w| w.contains("downgrade")), "{:?}", plan.warnings);
    }

    /// The profile is attached on Docker Desktop as well.
    ///
    /// This used to assert the opposite -- that it was skipped there -- which is what
    /// left the sandbox running Docker's weaker built-in profile on the platform the
    /// operator actually uses. The Docker CLI reads the file and inlines the JSON, so
    /// the daemon never needs to see the path.
    #[test]
    fn the_seccomp_profile_is_attached_even_on_docker_desktop() {
        let fixture = Fixture::new("seccomp-desktop");
        let mut app = fixture.app();
        app.security.seccomp = SeccompProfile::Hardened;
        let status = DockerStatus { available: true, desktop: true, ..DockerStatus::default() };

        let profile = fixture.dir.join("seccomp.json");
        std::fs::write(&profile, "{}").unwrap();
        let input = PlanInput { seccomp_host_path: Some(&profile), ..fixture.input(&app, &status) };

        let plan = plan_run(&input).expect("a desktop daemon must still get the profile");
        assert!(
            plan.args.iter().any(|a| a.starts_with("--security-opt=seccomp=")),
            "the hardened profile must be attached on Docker Desktop: {:?}",
            plan.args
        );
        assert!(
            !plan.warnings.iter().any(|w| w.contains("built-in profile")),
            "there is nothing to warn about now: {:?}",
            plan.warnings
        );
    }

    /// Hardening without the profile stops the start.
    ///
    /// This control denies `AF_VSOCK` and the user-namespace exploit class. Continuing
    /// without it produces a sandbox that looks the same and is not.
    #[test]
    fn hardening_without_a_profile_fails_rather_than_weakening_silently() {
        let fixture = Fixture::new("seccomp-missing");
        let mut app = fixture.app();
        app.security.seccomp = SeccompProfile::Hardened;
        let status = docker_status();

        let input = PlanInput { seccomp_host_path: None, ..fixture.input(&app, &status) };
        let error = plan_run(&input).expect_err("a missing profile must stop the start");
        let message = error.to_string();
        assert!(message.contains("seccomp"), "{message}");
        assert!(
            message.contains("Settings"),
            "the message should say how to proceed: {message}"
        );
    }

    #[test]
    fn full_network_mode_says_so_explicitly() {
        let mut fixture = Fixture::new("full-net");
        fixture.project.network = NetworkPolicy::Full;
        let app = fixture.app();
        let status = docker_status();
        let plan = plan_run(&fixture.input(&app, &status)).unwrap();
        assert!(plan.warnings.iter().any(|w| w.contains("unrestricted") || w.contains("no restriction")));
        assert!(!plan.args.iter().any(|a| a.starts_with("--network=")));
    }

    #[test]
    fn the_plan_renders_as_something_a_human_can_audit() {
        let fixture = Fixture::new("describe");
        let app = fixture.app();
        let status = docker_status();
        let plan = plan_run(&fixture.input(&app, &status)).unwrap();
        let text = plan.describe();
        assert!(text.contains("docker run"));
        assert!(text.contains("--read-only"));
        assert!(text.contains("/workspace"));
        assert!(text.contains("read-only"));
        assert!(text.contains("Mounts"));
    }

    #[test]
    fn displayed_arguments_are_quoted_so_a_path_with_spaces_is_unambiguous() {
        assert_eq!(quote("--read-only"), "--read-only");
        assert_eq!(quote("/home/me/my project"), "'/home/me/my project'");
        assert_eq!(quote("it's"), "\"it's\"");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn two_projects_cannot_share_a_container_name() {
        let fixture = Fixture::new("names");
        let a = fixture.project.container_name();
        let mut other = fixture.project.clone();
        other.slug = "other".into();
        assert_ne!(a, other.container_name());
        assert!(a.starts_with("deepsand-"));
    }
}
