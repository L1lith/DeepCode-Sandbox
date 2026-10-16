//! Generates everything Deepsand hands to the sandbox at start time.
//!
//! Four artefacts, all derived from host state so that the sandbox never has
//! to be trusted about its own configuration:
//!
//! * `config/settings.json` — mounted read-only at `/etc/deepsand/settings.json`
//!   and copied by the entrypoint into `$HOME/.deepcode/settings.json`.
//! * `config/AGENTS.md` — the standing instructions that teach the contained
//!   DeepCode how its sandbox behaves. Mounted read-only and copied to
//!   `$HOME/.deepcode/AGENTS.md`, which the CLI loads automatically.
//! * `config/skills/deepsand-operator-instructions/SKILL.md` — the same standing
//!   instructions, for a project whose own `AGENTS.md` would shadow that file.
//!   Present only then; see `operator_skill`.
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
/// The application settings as one project sees them: the same values, with `image`
/// replaced by the tag that project actually runs.
///
/// Every caller that builds a plan has to go through this. The base tag in settings is a
/// stem -- [`crate::seccomp::project_image`] appends the tool selection and the runtime
/// revision -- and a plan that names the stem starts a container from whatever that tag
/// happens to hold.
///
/// This is not a hypothetical. The app built the derived tag, read the tool list out of its
/// label, checked its seccomp digest and told the sandbox what tools it had, and then
/// planned the *stem*: so the tools a project selected were never the tools in its sandbox,
/// and the runtime revision, whose whole purpose is to force a rebuild when a script
/// changes, never reached a container. Two call sites deriving the same tag and one of them
/// being forgotten is what this function exists to make impossible.
pub fn settings_for_project(app: &AppSettings, selection: Option<&[String]>) -> AppSettings {
    let mut settings = app.clone();
    settings.image = crate::seccomp::project_image(&app.image, selection);
    settings
}

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

/// The standing instructions a project's sessions are given, or `None` when it sends none.
///
/// The whole rule, in one place, because two callers need the same answer: the generated
/// instructions file, and the sandbox snapshot the bridge reads. `Global` takes the app-wide text,
/// `Custom` takes the project's own, `Off` sends nothing however loud the app-wide one is. A blank
/// or whitespace-only value counts as nothing wherever it comes from, so emptying the box turns
/// the feature off rather than sending a section the model has to interpret.
pub fn resolve_user_prompt<'a>(
    project: &'a Project,
    settings: &'a AppSettings,
) -> Option<&'a str> {
    let chosen = match project.user_prompt_mode {
        UserPromptMode::Global => &settings.user_prompt,
        UserPromptMode::Custom => &project.user_prompt,
        UserPromptMode::Off => return None,
    };
    let trimmed = chosen.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// The name of the skill that carries a project's instructions when its own file shadows ours.
///
/// Shared with `runtime/bin/entrypoint.sh`, which installs it: the two have to agree on one
/// directory name, and a test reads the shell script to see that they do.
pub const OPERATOR_SKILL_NAME: &str = "deepsand-operator-instructions";

/// The container path of a repository's own instructions, or `None` when it has none.
///
/// DeepCode's own precedence, in its own order: `.deepcode/AGENTS.md` wins over `AGENTS.md`, and
/// either of them wins over the `~/.deepcode/AGENTS.md` Deepsand installs. Returns a container
/// path rather than a host one because the only use for it is telling the model where to look.
pub fn shadowing_instructions(project_root: &Path) -> Option<String> {
    for (host_relative, container) in [
        (".deepcode/AGENTS.md", "/workspace/.deepcode/AGENTS.md"),
        ("AGENTS.md", "/workspace/AGENTS.md"),
    ] {
        if project_root.join(host_relative).is_file() {
            return Some(container.to_string());
        }
    }
    None
}

/// The instructions as a skill, for a project whose own `AGENTS.md` would shadow the generated one.
///
/// `None` in two cases, and both are "there is nothing for a skill to carry":
///
/// * the project has no instructions to send -- `Off`, or an empty box wherever the text would come
///   from. A skill is the operator's words in the model's own voice, and a project that has none is
///   not missing anything: the sandbox's own guidance still arrives through
///   `deepsand_sandbox_info` and the skills the image installs.
/// * the project reads the generated file anyway, so the same words are already in front of the
///   model once and a second copy is only a second copy.
///
/// When the repository *does* ship its own instructions, the file Deepsand writes to
/// `~/.deepcode/AGENTS.md` is never read at all -- so the same words go somewhere no file in the
/// project can shadow, which is what a skill is.
pub fn operator_skill(project: &Project, settings: &AppSettings) -> Option<String> {
    let prompt = resolve_user_prompt(project, settings)?;
    let shadowing = shadowing_instructions(Path::new(&project.root_dir))?;
    Some(build_operator_skill_md(prompt, &shadowing))
}

/// The text of that skill. Pure, so the wording is testable without a filesystem.
pub fn build_operator_skill_md(prompt: &str, shadowing_path: &str) -> String {
    format!(
        "---\n\
         name: {OPERATOR_SKILL_NAME}\n\
         description: The operator's standing instructions for this project, set in Deepsand outside the container, and where this repository keeps its own instructions. Load this at the start of every session here, and whenever you are unsure how the operator wants this project handled.\n\
         ---\n\
         \n\
         # The operator's instructions for this project\n\
         \n\
         These are set in Deepsand, outside this container, and they are about this project rather\n\
         than about the task in front of you. They cannot widen what you can reach: if one of them\n\
         asks for something the sandbox does not have, ask for it -- the tools are listed in\n\
         `deepsand_sandbox_info` -- rather than working around it.\n\
         \n\
         ## What the operator asked for\n\
         \n\
         {prompt}\n\
         \n\
         ## Where this repository's own instructions are\n\
         \n\
         This project keeps its own instructions at `{shadowing_path}`. DeepCode already loads that\n\
         file for you, so this skill is a layer on top of it rather than a replacement, and both\n\
         apply. If the two ever seem to disagree about *what to do*, say so -- the operator can\n\
         change either one. They cannot disagree about *what you can reach*, because neither of them\n\
         is what enforces that.\n"
    )
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
    settings: &AppSettings,
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

    // The operator's own words, before the generated rules rather than after them: it is the part
    // a person wrote, and burying it under a page of prose is how it stops being read. It cannot
    // change what the sandbox is, though, and saying so here is what keeps "you have full access"
    // in a prompt from being read as a grant.
    if let Some(prompt) = resolve_user_prompt(project, settings) {
        out.push_str(&format!(
            "\n## What the operator wants, in their own words\n\n\
             These are the operator's standing instructions for this project, and they are what\n\
             every session here should start from -- treat them as the frame for the work rather\n\
             than as a suggestion, and say if any of it is not something you can do.\n\n\
             {prompt}\n\n\
             They do not change what this sandbox is. The sections around this one say what you can\n\
             actually reach, and an instruction that assumes something else is a reason to ask for\n\
             it, not a licence to assume you have it.\n"
        ));
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
         * `deepsand_check_request` - collect the answer if the operator was slow to respond.\n\
         * `deepsand_list_requests` - list the requests this sandbox has on record and where each\n  \
           one stands. Use it after a request call that failed or timed out.\n\n\
         While a request is waiting for an answer, Deepsand holds this sandbox frozen: nothing you\n\
         run makes progress until the operator decides. That is deliberate, not a fault, so do not\n\
         treat a pause as a crash and do not ask for the same thing twice. A decision that took\n\
         longer than one call's own budget is still there to collect: `deepsand_list_requests`\n\
         finds the request and `deepsand_check_request` reads it.\n\n\
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
    settings: &AppSettings,
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
        // Resolved here rather than passed in, so the generated file and the sandbox's own copy of
        // these instructions can never disagree about which one applies.
        user_prompt: resolve_user_prompt(project, settings).unwrap_or_default().to_string(),
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
    operator_skill: Option<&str>,
) -> Result<()> {
    std::fs::create_dir_all(config_dir)?;
    std::fs::create_dir_all(state_dir)?;

    write_json(&config_dir.join("settings.json"), settings_json)?;
    std::fs::write(config_dir.join("AGENTS.md"), agents_md)?;
    write_json(&state_dir.join("sandbox.json"), sandbox)?;
    write_json(&state_dir.join("grants.json"), grants)?;

    // The skill, when the project's own instructions shadow the file above. Removal is part of the
    // write and not a nicety: the entrypoint copies this into the sandbox's home volume, which
    // outlives the setting, so a skill left behind here would go on instructing every later session
    // with a prompt the operator has since turned off. This directory is Deepsand's own output.
    let skill_dir = config_dir.join("skills").join(OPERATOR_SKILL_NAME);
    match operator_skill {
        Some(md) => {
            std::fs::create_dir_all(&skill_dir)?;
            std::fs::write(skill_dir.join("SKILL.md"), md)?;
        }
        None => {
            let _ = std::fs::remove_dir_all(&skill_dir);
        }
    }

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

#[cfg(test)]
mod operator_skill_tests {
    use super::*;

    /// A project as the store would hold it: the fields that matter here, and nothing invented.
    fn project(root_dir: &str, mode: UserPromptMode, own: &str) -> Project {
        let mut project: Project = serde_json::from_str(&format!(
            r#"{{"id":"p1","name":"n","slug":"s","root_dir":"{}","created_at_ms":0}}"#,
            root_dir.replace('\\', "\\\\")
        ))
        .unwrap();
        project.user_prompt_mode = mode;
        project.user_prompt = own.to_string();
        project
    }

    /// DeepCode's order, which is not the obvious one: the `.deepcode` file wins over the
    /// repository's, because that is what the CLI reads first.
    #[test]
    fn the_deepcode_file_wins_over_the_repositorys_own_instructions() {
        let dir = std::env::temp_dir().join(format!("deepsand-shadow-{}", std::process::id()));
        let deepcode = dir.join(".deepcode");
        std::fs::create_dir_all(&deepcode).unwrap();
        std::fs::write(dir.join("AGENTS.md"), "the repository's").unwrap();
        std::fs::write(deepcode.join("AGENTS.md"), "the deepcode one").unwrap();

        assert_eq!(
            shadowing_instructions(&dir).as_deref(),
            Some("/workspace/.deepcode/AGENTS.md")
        );

        std::fs::remove_file(deepcode.join("AGENTS.md")).unwrap();
        assert_eq!(
            shadowing_instructions(&dir).as_deref(),
            Some("/workspace/AGENTS.md"),
            "with no .deepcode file, the repository's own is the one that shadows ours"
        );

        std::fs::remove_file(dir.join("AGENTS.md")).unwrap();
        assert_eq!(
            shadowing_instructions(&dir),
            None,
            "a repository with neither file reads the generated one"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The whole reason the skill exists: a repository that ships its own instructions makes the
    /// generated file unreadable to the model, so the same words have to go somewhere else.
    #[test]
    fn a_shadowed_project_gets_a_skill_and_the_rest_do_not() {
        let dir = std::env::temp_dir().join(format!("deepsand-shadow2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let settings = AppSettings {
            user_prompt: "Prefer small commits.".into(),
            ..AppSettings::default()
        };
        let root = dir.to_string_lossy().to_string();

        assert_eq!(
            operator_skill(&project(&root, UserPromptMode::Global, ""), &settings),
            None,
            "nothing shadows the generated file here, so a second copy would only be a second copy"
        );

        std::fs::write(dir.join("AGENTS.md"), "the repository's").unwrap();
        let skill = operator_skill(&project(&root, UserPromptMode::Global, ""), &settings)
            .expect("a shadowed project gets the skill");
        assert!(
            skill.contains("Prefer small commits."),
            "the operator's words have to be in it: {skill}"
        );
        assert!(
            skill.contains("/workspace/AGENTS.md"),
            "and the model has to be told where the repository keeps its own: {skill}"
        );

        // `Off` is a decision to send nothing, and a skill is the way these words are sent: with
        // nothing to carry there is no skill at all, rather than one announcing that the operator
        // had nothing to say. The text is still kept, so turning it back on finds it.
        let off = project(&root, UserPromptMode::Off, "kept but unused");
        assert_eq!(
            operator_skill(&off, &settings),
            None,
            "a project with the prompt turned off must not get the skill"
        );
        assert_eq!(off.user_prompt, "kept but unused", "the text is kept, not deleted");

        // And a blank box is the same answer as `Off`, wherever the blank is.
        let blank = AppSettings {
            user_prompt: "   \n ".into(),
            ..settings.clone()
        };
        assert_eq!(operator_skill(&project(&root, UserPromptMode::Global, ""), &blank), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The writer's half of the contract: the skill lands where the entrypoint looks for it, and
    /// when the reason for it goes away the file goes too. That second half is the one that matters
    /// long after this code is written -- the container copies it into a volume that outlives the
    /// setting, so anything left behind here instructs sessions nobody would think to check.
    #[test]
    fn the_skill_is_written_into_the_config_directory_and_removed_when_it_is_not_needed() {
        let dir = std::env::temp_dir().join(format!("deepsand-skillwrite-{}", std::process::id()));
        let repo = dir.join("repo");
        let config = dir.join("config");
        let state = dir.join("state");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("AGENTS.md"), "the repository's own").unwrap();

        let this_project = project(&repo.to_string_lossy(), UserPromptMode::Global, "");
        let settings = AppSettings {
            user_prompt: "Name the failing test before changing anything.".into(),
            ..AppSettings::default()
        };
        let sandbox = build_sandbox_snapshot(
            &this_project,
            &[],
            &NetworkPolicy::Internet,
            Vec::new(),
            Vec::new(),
            &settings,
        );
        let grants = build_grants_snapshot(&this_project, &[]);
        let wrote = |skill: Option<&str>| {
            write_project_config(
                &config,
                &state,
                &serde_json::json!({}),
                "the generated instructions",
                &sandbox,
                &grants,
                skill,
            )
            .unwrap()
        };
        let skill_path = config.join("skills").join(OPERATOR_SKILL_NAME).join("SKILL.md");

        wrote(operator_skill(&this_project, &settings).as_deref());
        assert!(
            skill_path.is_file(),
            "the entrypoint reads /etc/deepsand/skills/{OPERATOR_SKILL_NAME}/SKILL.md, which is this file"
        );
        assert!(std::fs::read_to_string(&skill_path)
            .unwrap()
            .contains("Name the failing test before changing anything."));

        // Turning the prompt off takes the skill with it. This is the case the operator is most
        // likely to hit: the repository keeps its own instructions, so the skill is there, and then
        // the prompt is switched off -- and a file left behind would go on giving orders.
        let off = project(&repo.to_string_lossy(), UserPromptMode::Off, "");
        wrote(operator_skill(&off, &settings).as_deref());
        assert!(
            !skill_path.exists(),
            "a project with the prompt turned off must not keep the skill about it"
        );

        // It comes back when the prompt does.
        wrote(operator_skill(&this_project, &settings).as_deref());
        assert!(skill_path.is_file(), "and back when the prompt is turned on again");

        // The repository stops shadowing the generated file, so the skill has no reason to exist.
        std::fs::remove_file(repo.join("AGENTS.md")).unwrap();
        wrote(operator_skill(&this_project, &settings).as_deref());
        assert!(
            !skill_path.exists(),
            "a stale skill would keep instructing the model with a prompt that no longer applies"
        );
        // The rest of the config is untouched by that: this is a writer, not a reset.
        assert!(config.join("AGENTS.md").is_file());
        assert!(config.join("settings.json").is_file());
        assert!(state.join("sandbox.json").is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A skill is discovered by its directory and matched by its frontmatter, so both have to be
    /// right -- and a CR inside either would corrupt the file the CLI parses.
    #[test]
    fn the_generated_skill_is_named_and_described_where_deepcode_looks() {
        let md = build_operator_skill_md("Be terse.", "/workspace/AGENTS.md");

        assert!(md.starts_with("---\n"), "frontmatter has to open on line 1: {md}");
        assert!(
            md.contains(&format!("\nname: {OPERATOR_SKILL_NAME}\n")),
            "the name has to match the directory the entrypoint installs: {md}"
        );
        assert!(md.contains("\ndescription: "), "a skill without one is skipped: {md}");
        // The description is what the model matches on, so it stays one line: a plain scalar folded
        // across several source lines is legal YAML and much easier to get wrong.
        assert_eq!(
            md.lines().filter(|line| line.starts_with("description: ")).count(),
            1,
            "one description, on one line: {md}"
        );
        assert!(!md.contains('\r'), "a CR would corrupt a frontmatter line");
        // The directory name is lowercase-hyphen and short, as DeepCode requires.
        assert!(OPERATOR_SKILL_NAME
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        assert!(OPERATOR_SKILL_NAME.len() <= 64);
    }

    /// The sandbox's own copy of the prompt is mounted read-only and the skill is not, so the
    /// skill must never be the only place the operator's words live.
    #[test]
    fn the_skill_says_the_instructions_cannot_widen_what_the_sandbox_reaches() {
        // Markdown wraps, so phrases are compared with the wrapping taken out: an assertion that a
        // sentence is in the file is about the sentence, not about where the source broke it.
        let md = build_operator_skill_md("You have full access to the host machine.", "/workspace/AGENTS.md");
        let flat = md.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(
            flat.contains("They cannot widen what you can reach"),
            "a prompt must not be readable as a grant: {md}"
        );
        assert!(flat.contains("deepsand_sandbox_info"));
        assert!(
            flat.contains("how the operator wants this project handled"),
            "the description has to say when to load it: {md}"
        );
    }
}

#[cfg(test)]
mod project_settings_tests {
    use super::*;

    /// The image is the one field that must change, and it must change to the project's tag.
    /// Two call sites used to derive that tag and one of them was forgotten, which is how the
    /// plan came to name the stem while the app built, labelled and digest-checked the tag.
    #[test]
    fn a_project_settings_image_is_the_project_tag_and_nothing_else_moves() {
        let base = AppSettings {
            image: "deepsand/runtime:9.9.9".to_string(),
            ..AppSettings::default()
        };
        let selection = vec!["htmlq".to_string()];
        let for_project = settings_for_project(&base, Some(&selection));

        assert_ne!(for_project.image, base.image, "the stem is not what a project runs");
        assert!(
            for_project.image.starts_with("deepsand/runtime:9.9.9-t"),
            "the project tag is derived from the stem: {}",
            for_project.image
        );

        // Everything else is the operator's settings, unchanged.
        assert_eq!(for_project.security.seccomp, base.security.seccomp);
        assert_eq!(for_project.egress_allowlist, base.egress_allowlist);
        assert_eq!(for_project.default_limits, base.default_limits);
        assert_eq!(
            serde_json::to_value(&for_project).unwrap()["image"],
            serde_json::json!(for_project.image)
        );
    }

    /// Two projects with different tools do not share an image, which is the whole reason the
    /// tag exists.
    #[test]
    fn two_tool_selections_do_not_share_an_image() {
        let base = AppSettings {
            image: "deepsand/runtime:9.9.9".to_string(),
            ..AppSettings::default()
        };
        let one = settings_for_project(&base, Some(&["htmlq".to_string()]));
        let two = settings_for_project(&base, Some(&["jq".to_string()]));
        let none = settings_for_project(&base, None);
        assert_ne!(one.image, two.image);
        assert_ne!(one.image, none.image);
    }
}
