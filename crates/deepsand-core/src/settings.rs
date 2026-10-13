//! Generates everything Deepsand hands to the sandbox at start time.
//!
//! Three artefacts, all derived from host state so that the sandbox never has
//! to be trusted about its own configuration:
//!
//! * `config/settings.json` — mounted read-only at `/etc/deepsand/settings.json`
//!   and copied by the entrypoint into `$HOME/.deepcode/settings.json`.
//! * `config/AGENTS.md` — the standing instructions that teach the contained
//!   DeepCode how its sandbox behaves. Mounted read-only and copied to
//!   `$HOME/.deepcode/AGENTS.md`, which the CLI loads automatically.
//! * `state/sandbox.json` + `state/grants.json` — mounted read-only and read by
//!   the in-container MCP bridge when the model asks what it can reach.

use crate::credentials::ResolvedCredentials;
use crate::error::Result;
use crate::model::*;
use std::path::Path;

/* Paths inside the sandbox. These are a contract shared with runtime/bin. */

/// DeepCode's native location for user-level standing instructions.
pub const CONTAINER_HOME: &str = "/home/deepcode";
/// Persisted by a named volume so sessions survive a container recreation.
pub const CONTAINER_HOME_CONFIG: &str = "/home/deepcode/.deepcode";
/// The mounted configuration *directory*. The host `config/` directory is bound
/// here in its entirety and the two files below are read out of it, rather than
/// each file being bound individually: Docker Desktop's Windows file bridge
/// turns a single-file bind mount into an empty directory, which would leave
/// DeepCode starting with no credentials and no standing instructions.
pub const CONTAINER_CONFIG_DIR: &str = "/etc/deepsand";
pub const CONTAINER_SETTINGS: &str = "/etc/deepsand/settings.json";
pub const CONTAINER_AGENTS: &str = "/etc/deepsand/AGENTS.md";
pub const CONTAINER_MCP_BRIDGE: &str = "/usr/local/lib/deepsand/deepsand-mcp-bridge.mjs";
pub const CONTAINER_REQUESTS: &str = "/deepsand/ipc/requests";
pub const CONTAINER_RESPONSES: &str = "/deepsand/ipc/responses";
pub const CONTAINER_STATE: &str = "/deepsand/state";
pub const CONTAINER_GRANTS_ROOT: &str = "/grants";

/// The unprivileged uid the entrypoint drops to. Must match the image.
pub const SANDBOX_UID: u32 = 1000;
pub const SANDBOX_GID: u32 = 1000;

/// Permission scopes that are harmless inside the container itself, and so are
/// pre-allowed when the operator chooses DeepCode's strict mode. Everything the
/// sandbox boundary is actually there to protect is a *host* resource, not one
/// of these.
const STRICT_ALLOW: &[&str] = &[
    "read-in-cwd",
    "write-in-cwd",
    "delete-in-cwd",
    "read-in-tmp",
    "write-in-tmp",
    "query-git-log",
    "mutate-git-log",
    "read-out-cwd",
];

/// Build the `settings.json` the sandboxed CLI will read.
///
/// There is deliberately no session token here. One used to be injected as
/// `DEEPSAND_SESSION_TOKEN` and echoed into every permission request, but nothing ever
/// checked it: the sandbox can read its own environment and its own settings, and the
/// bridge that writes a request is a child process of the agent making it, so a value the
/// bridge can read is a value the agent can read. It was a credential-shaped value that
/// authenticated nothing, and it is gone rather than left implying a control. See
/// `docs/SECURITY.md`, "The request spool is not authenticated".
pub fn build_deepcode_settings(
    project: &Project,
    grants: &[Grant],
    creds: &ResolvedCredentials,
    mcp_wait_ms: u32,
) -> serde_json::Value {
    let mut root = serde_json::Map::new();

    crate::credentials::apply_to_settings_json(creds, &mut root);

    // The sandbox is a container the operator cannot see inside of; telemetry
    // and debug logs would only add noise and outbound traffic.
    root.insert("telemetryEnabled".into(), serde_json::Value::Bool(false));
    root.insert("debugLogEnabled".into(), serde_json::Value::Bool(false));

    // `addWorkingDirs` is what makes granted directories count as "inside the
    // workspace" for DeepCode's own scope classification, so a granted path
    // does not also trip its out-of-cwd prompts.
    let working_dirs: Vec<serde_json::Value> = grants
        .iter()
        .map(|g| serde_json::Value::String(g.container_path.clone()))
        .collect();

    let mut permissions = serde_json::Map::new();
    match project.deepcode_mode {
        DeepCodeMode::AllowAll => {
            // The container is the boundary. Prompting for /etc/passwd would be
            // theatre, and every prompt costs the operator attention that is
            // better spent on the permission dialogs that do matter.
            permissions.insert("defaultMode".into(), serde_json::Value::String("allowAll".into()));
        }
        DeepCodeMode::Strict => {
            permissions.insert("defaultMode".into(), serde_json::Value::String("askAll".into()));
            permissions.insert(
                "allow".into(),
                serde_json::Value::Array(
                    STRICT_ALLOW.iter().map(|s| serde_json::Value::String((*s).into())).collect(),
                ),
            );
            permissions.insert(
                "ask".into(),
                serde_json::Value::Array(
                    ["read-out-cwd", "write-out-cwd", "delete-out-cwd", "network", "mcp"]
                        .iter()
                        .map(|s| serde_json::Value::String((*s).into()))
                        .collect(),
                ),
            );
        }
    }
    permissions.insert("addWorkingDirs".into(), serde_json::Value::Array(working_dirs));
    root.insert("permissions".into(), serde_json::Value::Object(permissions));

    // The bridge is the sandbox's only channel back to the operator.
    let mut bridge_env = serde_json::Map::new();
    bridge_env.insert(
        "DEEPSAND_IPC_REQUESTS".into(),
        serde_json::Value::String(CONTAINER_REQUESTS.into()),
    );
    bridge_env.insert(
        "DEEPSAND_IPC_RESPONSES".into(),
        serde_json::Value::String(CONTAINER_RESPONSES.into()),
    );
    bridge_env.insert("DEEPSAND_STATE_DIR".into(), serde_json::Value::String(CONTAINER_STATE.into()));
    bridge_env.insert(
        "DEEPSAND_WORKSPACE".into(),
        serde_json::Value::String(Project::workspace_mount().into()),
    );
    bridge_env.insert("DEEPSAND_PROJECT".into(), serde_json::Value::String(project.id.clone()));
    bridge_env.insert("DEEPSAND_WAIT_MS".into(), serde_json::Value::String(mcp_wait_ms.to_string()));

    let mut servers = serde_json::Map::new();
    servers.insert(
        "deepsand".into(),
        serde_json::json!({
            "command": "node",
            "args": [CONTAINER_MCP_BRIDGE],
            "env": serde_json::Value::Object(bridge_env),
        }),
    );
    root.insert("mcpServers".into(), serde_json::Value::Object(servers));

    serde_json::Value::Object(root)
}

/// Standing instructions the contained DeepCode reads on every session.
///
/// This exists because the most likely failure mode is not malice, it is a
/// helpful model burning a turn trying to `find / -name "my-website"` or
/// concluding a file "does not exist" when it is simply outside the sandbox.
pub fn build_agents_md(
    project: &Project,
    grants: &[Grant],
    network_mode: &NetworkPolicy,
    creds: &ResolvedCredentials,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# You are running inside the Deepsand sandbox for project \"{}\"\n\n\
         Deepsand runs you inside a Docker container. That container is your whole universe. The\n\
         operator explicitly asked for it to be impossible for you to leave, so:\n\n\
         * Your workspace is `{}`. It is the *only* directory that existed before the session started.\n",
        project.name,
        Project::workspace_mount()
    ));

    if grants.is_empty() {
        out.push_str(
            "* No extra host directories have been shared with you. Anything you cannot see under\n  \
             `/workspace` or `/deepsand` does not exist here.\n",
        );
    } else {
        out.push_str("* These host directories have been shared with you (read-only unless stated):\n");
        for grant in grants {
            out.push_str(&format!(
                "  - `{}` -> {} ({})\n",
                grant.host_path,
                grant.container_path,
                grant.access.label()
            ));
        }
    }

    out.push_str(&format!(
        "\n## Network\n\n{} This is enforced inside your container, not by policy that\n\
         you could reason your way around. It is an *address* filter: it decides which\n\
         IPv4 and IPv6 destinations are reachable. It is not a statement about every way\n\
         out of the sandbox, so do not read it as one.\n",
        match network_mode {
            NetworkPolicy::None =>
                "Only the model API is reachable; there is no other route out, including\n\
                 loopback."
                    .to_string(),
            NetworkPolicy::Internet =>
                "You can reach the public internet over IP. The host machine, the local network and\n\
                 cloud metadata addresses (169.254.169.254) are refused by an address filter."
                    .to_string(),
            NetworkPolicy::Allowlisted { allow } => format!(
                "Your egress is allowlisted: a hostname you are allowed goes through a filtering \
                 proxy, and an address the operator named (such as `192.168.1.50:5432`) is reached \
                 directly. You can only reach: {}.",
                if allow.is_empty() { "nothing yet".to_string() } else { allow.join(", ") }
            ),
            NetworkPolicy::Full =>
                "You have unrestricted network access, including the host machine, because the\n\
                 operator chose that explicitly."
                    .to_string(),
        }
    ));

    // Said before the list of request tools rather than after it: a sandbox that cannot ask
    // should not be told how to, or it spends the turn composing a request that is refused
    // on arrival.
    if !project.requests_enabled {
        out.push_str(
            "\n## Permission requests are off\n\n\
             The operator has turned permission requests off for this project. None of the\n\
             `deepsand_request_*` tools will reach them, and nothing you try will change that.\n\
             Work with what you already have, and say plainly what you could not do.\n",
        );
    }

    out.push_str(
        "\n## When you need something you cannot reach\n\n\
         Do **not** hunt for it. Do not guess that it does not exist. Ask:\n\n\
         * `deepsand_sandbox_info` - see what you can currently reach. Call this before concluding a\n  \
           path is missing.\n\
         * `deepsand_request_directory_access` - you know the path on the operator's machine (for\n  \
           example `C:\\\\Users\\\\me\\\\Documents\\\\brand`). The operator sees a dialog naming that exact path.\n\
         * `deepsand_request_resource` - you know what you need but not where it lives (\"the\n  \
           my-website repo\"). The operator gets a folder picker so they can locate it for you.\n\
         * `deepsand_check_request` - collect the answer if the operator was slow to respond.\n\n\
         When the operator approves new access, Deepsand recreates your container to attach the new\n\
         mount and resumes this session. The approved directory appears under `/grants/<name>`.\n\n\
         A refusal is final. Do not retry it, and do not look for another route - there genuinely is\n\
         not one.\n\n\
         A skill named `deepsand-permissions` is installed in this sandbox. Load it whenever you\n  \
         are unsure which request to make, or before concluding that something is unreachable; it\n  \
         covers the `PENDING` case and how to read an approval reply.\n",
    );

    if !creds.warnings.is_empty() {
        out.push_str("\n## Configuration warnings\n\n");
        for warning in &creds.warnings {
            out.push_str(&format!("* {warning}\n"));
        }
    }

    out.push_str(&format!(
        "\n## Identity\n\nModel: `{}`. Sandbox project id: `{}`.\n",
        creds.model, project.id
    ));

    out
}

/// What the bridge reports about the sandbox.
pub fn build_sandbox_snapshot(
    project: &Project,
    grants: &[Grant],
    network_mode: &NetworkPolicy,
    open_requests: Vec<String>,
    notes: Vec<String>,
) -> SandboxSnapshot {
    SandboxSnapshot {
        project_id: project.id.clone(),
        project_name: project.name.clone(),
        container_name: project.container_name(),
        image: String::new(),
        workspace_mount: Project::workspace_mount().to_string(),
        network_mode: network_mode.mode_str().to_string(),
        egress_allowlist: network_mode.allowlist().to_vec(),
        requests_enabled: project.requests_enabled,
        // Only meaningful when the flag is off, and empty when it is on: the bridge
        // keys off the flag and relays this text, so an empty string here is the
        // "nothing to say" case rather than a second, weaker signal.
        requests_disabled_message: if project.requests_enabled {
            String::new()
        } else {
            crate::model::REQUESTS_DISABLED_MESSAGE.to_string()
        },
        tools: crate::tools::resolve(project.tools.as_deref())
            .iter()
            .map(|tool| tool.id.to_string())
            .collect(),
        started_at_ms: crate::now_ms(),
        grants: grants.iter().map(SandboxGrant::from).collect(),
        open_requests,
        notes,
    }
}

pub fn build_grants_snapshot(project: &Project, grants: &[Grant]) -> GrantsSnapshot {
    GrantsSnapshot {
        project_id: project.id.clone(),
        generated_at_ms: crate::now_ms(),
        grants: grants.iter().map(SandboxGrant::from).collect(),
    }
}

/// Write the generated configuration into the project's private scratch space.
///
/// The files land in the *host* data directory and are mounted read-only into
/// the container. Nothing here is ever written into the user's project.
pub fn write_project_config(
    config_dir: &Path,
    state_dir: &Path,
    settings_json: &serde_json::Value,
    agents_md: &str,
    sandbox: &SandboxSnapshot,
    grants: &GrantsSnapshot,
) -> Result<()> {
    std::fs::create_dir_all(config_dir)?;
    std::fs::create_dir_all(state_dir)?;

    write_json(&config_dir.join("settings.json"), settings_json)?;
    std::fs::write(config_dir.join("AGENTS.md"), agents_md)?;
    write_json(&state_dir.join("sandbox.json"), sandbox)?;
    write_json(&state_dir.join("grants.json"), grants)?;

    // settings.json holds the operator's API key in the clear, exactly as their
    // own ~/.deepcode/settings.json does. It lives in Deepsand's private data
    // directory and never in the user's project, and is locked down further
    // here so other local accounts cannot read it.
    restrict(config_dir, 0o700);
    restrict(&config_dir.join("settings.json"), 0o600);
    Ok(())
}

/// Best-effort tightening of who can read a file or directory on the host.
///
/// On unix this is a mode. On Windows it has to be an ACL: mode bits do not exist there,
/// and the previous implementation was a no-op on the assumption that the profile
/// directory's inherited permissions were already narrow. Nothing verified that, and the
/// files were in fact readable well beyond the current user. This removes inheritance and
/// grants the current account explicitly, so the result does not depend on what the
/// parent happened to inherit.
fn restrict(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(mode);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(windows)]
    {
        use std::process::Command;
        // `/inheritance:r` drops the inherited entries; `/grant:r` replaces this
        // account's entry rather than adding to it. The current user keeps full control,
        // so this cannot lock the app out of its own file, and anything the account does
        // not already have is removed.
        let who = std::env::var("USERNAME").unwrap_or_default();
        if !who.is_empty() {
            use std::os::windows::process::CommandExt as _;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            let _ = Command::new("icacls")
                .arg(path)
                .arg("/inheritance:r")
                .arg("/grant:r")
                .arg(format!("{who}:F"))
                .creation_flags(CREATE_NO_WINDOW)
                .output();
        }
        let _ = mode;
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, mode);
    }
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(value)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
