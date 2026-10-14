//! Serializable domain types shared by the desktop app, the headless CLI and
//! every on-disk artefact Deepsand writes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Bumped when the meaning of a stored default changes.
///
/// 2: hardening became the default. Stores written before this are migrated once, because
/// the old value was the default nobody chose and running without the seccomp profile is
/// what made the vsock escape reachable.
pub const STATE_VERSION: u32 = 2;

/// How a shared host path is exposed inside the sandbox.
///
/// Serialises as `"read"` / `"write"` so it matches the vocabulary the
/// in-container MCP bridge uses with the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    #[default]
    #[serde(rename = "read")]
    ReadOnly,
    #[serde(rename = "write")]
    ReadWrite,
}

impl Access {
    pub fn is_write(self) -> bool {
        matches!(self, Access::ReadWrite)
    }

    /// The `:ro` suffix Docker expects, or an empty string.
    pub fn volume_suffix(self) -> &'static str {
        if self.is_write() {
            ""
        } else {
            ":ro"
        }
    }

    pub fn label(self) -> &'static str {
        if self.is_write() {
            "read-write"
        } else {
            "read-only"
        }
    }
}

/// Egress policy for a sandbox.
///
/// `Allowlisted` is the default: DNS, the model endpoint, the hosts on the operator's
/// allowlist, and any local address the allowlist names, and nothing else. `Internet`
/// allows anything that is not on the local network. `Full` is an explicit opt-out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// `--network none`.
    None,
    /// Public egress allowed; host, LAN, link-local and metadata blocked.
    Internet,
    /// Only DNS, the model endpoint, and what the allowlist names are reachable.
    ///
    /// **Written to disk as `restricted`**, the name this mode had before the allowlist
    /// could express addresses and ports. Reading accepts both names; writing uses the
    /// older one, deliberately.
    ///
    /// The reason is a real data loss, twice over. The state file lives in a directory
    /// shared by the installed app and any development build, and an older build cannot
    /// read a variant it has never heard of: it reports the *whole file* as corrupt, sets
    /// it aside, and starts with an empty project list -- five projects, in the incident
    /// that led here. Keeping the on-disk name at the older of the two means every build
    /// in circulation can read what this one writes. `allowlisted` is what the mode is
    /// called everywhere a person reads it: the UI, the plan preview, and the snapshot
    /// the bridge is handed.
    ///
    /// So changing this name again means either reading the new one as well (an alias, as
    /// here) or waiting until no build that predates it is installed anywhere.
    #[serde(rename = "restricted", alias = "allowlisted")]
    Allowlisted {
        #[serde(default)]
        allow: Vec<String>,
    },
    /// No policy applied at all, including the host's own network.
    Full,
}

impl Default for NetworkPolicy {
    /// Default-deny: a new project may reach the model endpoint, its enabled tools'
    /// hosts, and the global allowlist (the package registries), and nothing else.
    ///
    /// This is the default because the alternative is a sandbox that can reach the
    /// operator's whole network by accident. `Internet` is still one click away and
    /// is the honest choice for work that genuinely needs the open web; the point is
    /// that it should be chosen rather than inherited.
    ///
    /// Projects created before this change keep whatever mode they were stored with,
    /// so nothing silently starts being blocked.
    fn default() -> Self {
        NetworkPolicy::Allowlisted { allow: Vec::new() }
    }
}

impl NetworkPolicy {
    pub fn mode_str(&self) -> &'static str {
        match self {
            NetworkPolicy::None => "none",
            NetworkPolicy::Internet => "internet",
            NetworkPolicy::Allowlisted { .. } => "allowlisted",
            NetworkPolicy::Full => "full",
        }
    }

    /// Whether the container needs `CAP_NET_ADMIN` so the entrypoint can
    /// install kernel-level rules.
    /// Whether the in-container egress rules have to be installed.
    ///
    /// `none` is included: it no longer means "no interfaces", it means "only the
    /// model API", and enforcing that needs the same rules as allowlisted mode.
    pub fn needs_netfilter(&self) -> bool {
        matches!(
            self,
            NetworkPolicy::None | NetworkPolicy::Internet | NetworkPolicy::Allowlisted { .. }
        )
    }

    /// Whether egress goes through the Deepsand proxy running on the host.
    ///
    /// True for `none` as well as `allowlisted`, because a sandbox that may reach
    /// exactly one destination reaches it the same way it reaches many.
    /// Whether this mode needs the allowlisting egress proxy.
    ///
    /// Only `allowlisted` does. `none` means "the model API and nothing else", which the
    /// model's own addresses already express, and the proxy cannot deliver the model
    /// anyway: the client builds its own dispatcher and ignores `HTTP_PROXY`.
    pub fn uses_proxy(&self) -> bool {
        matches!(self, NetworkPolicy::Allowlisted { .. })
    }

    /// Whether the project's own allowlist is consulted on top of the mandatory
    /// hosts. `none` deliberately ignores it: that mode means the model API and
    /// nothing else, whatever the project has listed.
    pub fn honours_allowlist(&self) -> bool {
        matches!(self, NetworkPolicy::Allowlisted { .. })
    }

    pub fn allowlist(&self) -> &[String] {
        match self {
            NetworkPolicy::Allowlisted { allow } => allow,
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// Read `~/.deepcode/settings.json` from the operator's machine each start.
    InheritHost,
    /// Use the credentials stored on the project.
    Project,
}

impl Default for CredentialSource {
    fn default() -> Self {
        CredentialSource::InheritHost
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(default)]
    pub source: CredentialSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    /// Extra variables merged into the generated `settings.json` `env` block.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra_env: BTreeMap<String, String>,
}

impl Credentials {
    pub fn has_api_key(&self) -> bool {
        self.api_key.as_ref().is_some_and(|k| !k.trim().is_empty())
    }

    /// Never log or display a key in full.
    pub fn masked_api_key(&self) -> Option<String> {
        let key = self.api_key.as_deref()?.trim();
        if key.is_empty() {
            return None;
        }
        let tail: String = key.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
        Some(format!("****{tail}"))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub memory_mb: u64,
    /// Fractional CPUs, e.g. `2.0`.
    pub cpus: f32,
    pub pids_limit: u32,
    pub tmpfs_mb: u64,
    pub stop_timeout_s: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: 4096,
            cpus: 2.0,
            pids_limit: 512,
            tmpfs_mb: 2048,
            stop_timeout_s: 10,
        }
    }
}

/// How strict DeepCode's own in-container permission prompts should be.
///
/// The container is the real boundary, so `AllowAll` is the sane default and
/// keeps the TUI free of prompts that cannot actually protect anything the
/// sandbox boundary does not already protect. `Strict` surfaces DeepCode's
/// native prompts in the terminal pane for operators who want the extra
/// friction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeepCodeMode {
    AllowAll,
    Strict,
}

impl Default for DeepCodeMode {
    fn default() -> Self {
        DeepCodeMode::AllowAll
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningEffort {
    /// Not thinking at all. Serialised as `none`, which is what the operator asked
    /// for; the CLI expresses it as `thinkingEnabled: false` rather than as an effort
    /// value, so [`Self::as_str`] returns something the CLI would reject as an effort
    /// and the settings writer translates it instead.
    Off,
    Low,
    High,
    Max,
    /// Defer to the host's `settings.json`. The switch stops deciding.
    Default,
}

impl Default for ReasoningEffort {
    fn default() -> Self {
        // Deferring, so a project nobody has touched behaves the way the operator's
        // own DeepCode installation does.
        ReasoningEffort::Default
    }
}

impl ReasoningEffort {
    /// Every state, in the order the switch presents them: least to most thinking.
    pub const ALL: [ReasoningEffort; 5] = [
        ReasoningEffort::Off,
        ReasoningEffort::Low,
        ReasoningEffort::High,
        ReasoningEffort::Max,
        ReasoningEffort::Default,
    ];

    /// The wire and storage value. `none` is not a `reasoningEffort` the CLI accepts;
    /// it is `thinkingEnabled: false`. See [`Self::is_thinking`].
    pub fn as_str(self) -> &'static str {
        match self {
            ReasoningEffort::Off => "none",
            ReasoningEffort::Low => "low",
            ReasoningEffort::High => "high",
            ReasoningEffort::Max => "max",
            ReasoningEffort::Default => "default",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" | "off" => Some(ReasoningEffort::Off),
            "low" => Some(ReasoningEffort::Low),
            "high" => Some(ReasoningEffort::High),
            "max" => Some(ReasoningEffort::Max),
            "default" => Some(ReasoningEffort::Default),
            _ => None,
        }
    }

    /// Whether thinking happens at all. `none` is the only state where it does not.
    pub fn is_thinking(self) -> bool {
        !matches!(self, ReasoningEffort::Off)
    }

    /// Whether the switch decides, or defers to the host's settings file.
    pub fn is_deferring(self) -> bool {
        matches!(self, ReasoningEffort::Default)
    }

    /// The `reasoningEffort` to write. Only meaningful when thinking is on; when it
    /// is off the value is ignored by the CLI, so the cheapest valid one is written.
    pub fn effort_value(self) -> &'static str {
        match self {
            ReasoningEffort::Low => "low",
            ReasoningEffort::Max => "max",
            // `none` is not a valid effort, and `default` is resolved before it gets
            // here. `high` is the documented fallback.
            ReasoningEffort::Off | ReasoningEffort::High | ReasoningEffort::Default => "high",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ReasoningEffort::Off => "Off",
            ReasoningEffort::Low => "Quick",
            ReasoningEffort::High => "Balanced",
            ReasoningEffort::Max => "Deep",
            ReasoningEffort::Default => "Default",
        }
    }

    /// A sentence for the tooltip, because "Default" alone does not say what it does.
    pub fn description(self) -> &'static str {
        match self {
            ReasoningEffort::Off => "Do not think before answering. Fastest, and least careful.",
            ReasoningEffort::Low => "A little thinking. Good for small, well-specified edits.",
            ReasoningEffort::High => "Moderate thinking. The sensible default for real work.",
            ReasoningEffort::Max => "Think as hard as the model can. Slowest and most expensive.",
            ReasoningEffort::Default => {
                "Leave it to your DeepCode settings.json. Falls back to Balanced if that file \
                 says nothing."
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// How hard the model is asked to think before answering.
///
/// The three values are DeepCode's own (`ReasoningEffort = "low" | "high" | "max"`),
/// not an invented scale, so the switch in the GUI maps onto the setting the CLI
/// actually reads rather than onto something Deepsand would have to translate.
pub struct Project {
    pub id: String,
    pub name: String,
    /// Docker-safe short name used for container, volume and network names.
    pub slug: String,
    /// Canonical absolute host path that becomes `/workspace`.
    pub root_dir: String,
    pub created_at_ms: i64,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub limits: ResourceLimits,
    #[serde(default)]
    pub credentials: Credentials,
    #[serde(default)]
    pub deepcode_mode: DeepCodeMode,
    /// Optional pre-declared roots. When a requested path falls inside one of
    /// these the grant is applied without a container restart.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_roots: Vec<String>,
    /// How hard the model should think. Read when the sandbox's configuration is
    /// generated, so a change takes effect for the next session.
    #[serde(default)]
    pub reasoning_effort: ReasoningEffort,
    /// Tool ids switched on for this project's image.
    ///
    /// `None` means "the catalogue defaults". An explicit list is honoured as given,
    /// including an empty one, so switching every tool off is expressible rather
    /// than being indistinguishable from never having chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
    /// Secrets that are stored but deliberately not handed to the sandbox.
    ///
    /// Kept on the project rather than in the encrypted store: the store is one map of name
    /// to value, and whether a secret may be used is a decision about the project rather than
    /// part of the secret. Names are matched exactly, as environment variables are.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_secrets: Vec<String>,
    /// Whether the sandbox may ask for anything at all.
    ///
    /// On by default, and that default is the point: a sandbox that cannot ask is a
    /// sandbox that stops at the first thing it does not have, so turning this off is
    /// a deliberate choice the operator makes — most often from a request dialog that
    /// has become noise, which is why the dialog can set it too.
    ///
    /// This is enforced on the host as well as advertised to the bridge: the spool is
    /// writable by the sandbox, so a bridge that honours the flag is a courtesy to the
    /// model, not the control. See `docs/SECURITY.md`, "The request spool is not
    /// authenticated".
    #[serde(default = "yes")]
    pub requests_enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    /// Start this project again when Deepsand starts, if it was running when it last ended.
    ///
    /// Off by default: a sandbox is a privilege and a resource, and coming back on its own is a
    /// thing an operator asks for rather than something they discover. What it acts on is
    /// `was_running` below, not "has a session volume" -- a project stopped by hand last week must
    /// not come back because it once ran.
    #[serde(default)]
    pub resume_on_launch: bool,
    /// Whether this project's session was live the last time the app ended.
    ///
    /// Written on shutdown, for every project, so that a project stopped by hand is remembered as
    /// stopped. This is state rather than a setting, which is why nothing in the window writes it.
    #[serde(default)]
    pub was_running: bool,
}

impl Project {
    pub fn container_name(&self) -> String {
        format!("deepsand-{}", self.slug)
    }

    pub fn state_volume(&self) -> String {
        format!("deepsand-state-{}", self.slug)
    }

    pub fn network_name(&self) -> String {
        format!("deepsand-net-{}", self.slug)
    }

    /// The container path that arbitrary DeepCode generated names never land in.
    pub fn workspace_mount() -> &'static str {
        "/workspace"
    }

    /// True when `path` falls inside a pre-declared root, which means granting
    /// it needs no new bind mount and therefore no container recreation.
    pub fn path_is_predeclared(&self, path: &std::path::Path) -> bool {
        self.allowed_roots
            .iter()
            .any(|root| crate::paths::is_within(std::path::Path::new(root), path))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantSource {
    /// Added by the operator from the settings panel.
    User,
    /// Approved by the operator in response to a DeepCode request.
    Request,
    /// Derived from a pre-declared allowed root.
    AllowedRoot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub project_id: String,
    /// Canonical absolute host path.
    pub host_path: String,
    /// Where it appears inside the sandbox, always under `/grants`.
    pub container_path: String,
    pub slug: String,
    #[serde(default)]
    pub access: Access,
    /// Short human label shown in the UI.
    #[serde(default)]
    pub label: String,
    /// Why it was granted, shown in the permissions panel.
    #[serde(default)]
    pub purpose: String,
    #[serde(default = "Grant::default_source")]
    pub source: GrantSource,
    pub created_at_ms: i64,
    /// Set for time-boxed grants; the broker revokes them once past.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
}

impl Grant {
    fn default_source() -> GrantSource {
        GrantSource::User
    }

    pub fn is_expired(&self, now_ms: i64) -> bool {
        self.expires_at_ms.is_some_and(|t| now_ms >= t)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompProfile {
    /// Whatever the container runtime ships by default.
    Default,
    /// Deepsand's additive denylist, from `runtime/seccomp-hardened.json`.
    Hardened,
}

impl Default for SeccompProfile {
    /// Hardened.
    ///
    /// This is what a store without the field deserialises to, so leaving it on
    /// `Default` would have quietly kept the permissive profile for every existing
    /// project however the struct literal was written.
    fn default() -> Self {
        SeccompProfile::Hardened
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    #[serde(default)]
    pub seccomp: SeccompProfile,
    /// Mount the root filesystem read-only. Turning this off is a downgrade.
    #[serde(default = "yes")]
    pub read_only_rootfs: bool,
    /// Refuse to start a sandbox if the kernel-level egress policy could not be
    /// applied.
    #[serde(default = "yes")]
    pub netfilter_required: bool,
    #[serde(default = "yes")]
    pub no_new_privileges: bool,
    /// Ask the runtime for an AppArmor profile. Only meaningful on Linux hosts.
    #[serde(default = "yes")]
    pub apparmor: bool,
    /// Mount `/tmp` with `noexec`. Off by default because some toolchains
    /// execute from temporary directories.
    #[serde(default)]
    pub tmpfs_noexec: bool,
}

fn yes() -> bool {
    true
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            // Hardened, not Docker's default. This control is what denies AF_VSOCK and
            // the non-IP socket families, and a default installation was running without
            // it -- which is how the sandbox in the assessment could open a vsock socket
            // and reach the VM's root shell. A security control that is off unless
            // somebody turns it on is not a control.
            seccomp: SeccompProfile::Hardened,
            read_only_rootfs: true,
            netfilter_required: true,
            no_new_privileges: true,
            apparmor: true,
            tmpfs_noexec: false,
        }
    }
}

/// What Deepsand should do when the operator logs in.
///
/// Three options rather than a switch, because "start with the computer" and "start with the
/// computer and take over the screen" are different intentions. `Background` is for an operator
/// who wants their sandboxes and their tray icon waiting without a window appearing over
/// whatever they were doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StartupMode {
    #[default]
    Off,
    /// Start at login with no window; the tray icon is the way in.
    Background,
    /// Start at login with the window showing, which is what the earlier boolean meant.
    Foreground,
}

impl StartupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            StartupMode::Off => "off",
            StartupMode::Background => "background",
            StartupMode::Foreground => "foreground",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "false" | "no" => Some(StartupMode::Off),
            "background" | "tray" | "minimised" | "minimized" => Some(StartupMode::Background),
            "foreground" | "window" | "on" | "true" | "yes" => Some(StartupMode::Foreground),
            _ => None,
        }
    }

    /// Whether the operating system should have a startup entry at all.
    pub fn is_on(self) -> bool {
        !matches!(self, StartupMode::Off)
    }

    /// Whether the window should stay hidden when started this way.
    pub fn starts_hidden(self) -> bool {
        matches!(self, StartupMode::Background)
    }
}

impl std::fmt::Display for StartupMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for StartupMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Reads the three names, and the boolean this replaced.
///
/// `start_at_login: true` used to mean "start with the computer", which is the default here:
/// losing it silently because the field grew a third state would be a small betrayal of whoever
/// had turned it on.
impl<'de> serde::Deserialize<'de> for StartupMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StartupMode;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a startup mode (off, background, foreground), or the boolean it replaced")
            }

            fn visit_bool<E: serde::de::Error>(self, on: bool) -> Result<StartupMode, E> {
                Ok(if on {
                    StartupMode::Foreground
                } else {
                    StartupMode::Off
                })
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<StartupMode, E> {
                StartupMode::from_str(value).ok_or_else(|| {
                    serde::de::Error::custom(format!("unknown startup mode {value:?}"))
                })
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Runtime image tag.
    #[serde(default = "default_image")]
    pub image: String,
    #[serde(default)]
    pub default_network: NetworkPolicy,
    #[serde(default)]
    pub default_limits: ResourceLimits,
    #[serde(default)]
    pub security: SecuritySettings,
    /// Hosts the `Restricted` network mode's proxy is allowed to reach.
    #[serde(default = "default_egress_allowlist")]
    pub egress_allowlist: Vec<String>,
    /// Restart the sandbox automatically when a new grant is approved.
    #[serde(default = "yes")]
    pub auto_restart_on_grant: bool,
    /// Show a desktop notification when DeepCode asks for something.
    #[serde(default = "yes")]
    pub notify_on_request: bool,
    /// Default API base URL when neither the project nor the host config sets one.
    #[serde(default = "default_base_url")]
    pub default_base_url: String,
    #[serde(default = "default_model")]
    pub default_model: String,
    /// Directory Deepsand keeps its own state in. `None` means the platform
    /// default data directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<String>,
    /// Servers that expose this GUI over HTTP, and how much each may do.
    #[serde(default)]
    pub remote: crate::remote::RemoteAccessSettings,
    /// Start Deepsand when the operator logs in, and how.
    ///
    /// Off by default, and deliberately independent of
    /// `remote.persist_across_restarts`: wanting the app ready when you sit down is
    /// a different intention from wanting a network-reachable control plane that is
    /// already listening.
    ///
    /// The alias is the boolean this replaced, and the custom deserializer above reads it: an
    /// existing `start_at_login: true` becomes `Foreground`, which is what it meant.
    #[serde(default, alias = "start_at_login")]
    pub startup: StartupMode,
    /// Whether Deepsand may ask the registries about the tools it has cached.
    ///
    /// On by default, and the switch turns off *both* the check at startup and the periodic one,
    /// which is what the setting says: an operator who does not want the app talking to npm and
    /// crates.io on its own behalf should not have to find two controls. The button in Settings
    /// still works -- that is the operator asking.
    #[serde(default = "yes")]
    pub check_tool_updates: bool,
    /// Whether the window's close button hides Deepsand instead of stopping it.
    ///
    /// Off by default, because the surprising behaviour is hiding: an operator who closes the
    /// window expects their sandboxes to stop, and one who does not gets a machine quietly
    /// running containers they cannot see.
    #[serde(default)]
    pub close_to_tray: bool,
}

fn default_image() -> String {
    "deepsand/runtime:0.1.0".to_string()
}

fn default_base_url() -> String {
    "https://api.deepseek.com".to_string()
}

fn default_model() -> String {
    "deepseek-v4-flash".to_string()
}

/// Registries the contained DeepCode plausibly needs, plus the model API.
fn default_egress_allowlist() -> Vec<String> {
    vec![
        "api.deepseek.com".to_string(),
        "registry.npmjs.org".to_string(),
        "pypi.org".to_string(),
        "files.pythonhosted.org".to_string(),
        "github.com".to_string(),
        "codeload.github.com".to_string(),
        "raw.githubusercontent.com".to_string(),
        "objects.githubusercontent.com".to_string(),
        "registry-1.docker.io".to_string(),
    ]
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            image: default_image(),
            default_network: NetworkPolicy::default(),
            default_limits: ResourceLimits::default(),
            security: SecuritySettings::default(),
            egress_allowlist: default_egress_allowlist(),
            auto_restart_on_grant: true,
            notify_on_request: true,
            default_base_url: default_base_url(),
            default_model: default_model(),
            data_dir: None,
            remote: crate::remote::RemoteAccessSettings::default(),
            startup: StartupMode::Off,
            close_to_tray: false,
            check_tool_updates: true,
        }
    }
}

/// The complete persisted state of the Deepsand installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreDocument {
    #[serde(default = "default_state_version")]
    pub version: u32,
    #[serde(default)]
    pub settings: AppSettings,
    #[serde(default)]
    pub projects: Vec<Project>,
    /// project id -> grants
    #[serde(default)]
    pub grants: BTreeMap<String, Vec<Grant>>,
}

fn default_state_version() -> u32 {
    STATE_VERSION
}

impl Default for StoreDocument {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            settings: AppSettings::default(),
            projects: Vec::new(),
            grants: BTreeMap::new(),
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Data created by, or shown to, the sandbox                                  */
/* ------------------------------------------------------------------------- */

/// What a running sandbox is allowed to know about itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSnapshot {
    pub project_id: String,
    pub project_name: String,
    pub container_name: String,
    pub image: String,
    pub workspace_mount: String,
    pub network_mode: String,
    pub egress_allowlist: Vec<String>,
    /// Whether this sandbox may ask for permissions at all.
    ///
    /// The bridge reads this and refuses to submit when it is false, so the model finds
    /// out immediately instead of waiting out its whole budget for an answer that will
    /// never come. The host enforces the same flag on the way in, because the spool is
    /// writable by the sandbox and a bridge-side check is therefore a courtesy rather
    /// than a control.
    #[serde(default = "yes")]
    pub requests_enabled: bool,
    /// Exactly what to tell the model when `requests_enabled` is false. Carried here so
    /// the bridge relays the host's words rather than keeping a second copy that can
    /// drift from the ones used when the host refuses an incoming request.
    #[serde(default)]
    pub requests_disabled_message: String,
    /// Tools this sandbox's image was built with, so the agent can check what it has
    /// instead of guessing or trying to install something itself.
    #[serde(default)]
    pub tools: Vec<String>,
    pub started_at_ms: i64,
    pub grants: Vec<SandboxGrant>,
    /// Requests currently awaiting an operator decision.
    #[serde(default)]
    pub open_requests: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// The subset of a grant the sandbox is told about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxGrant {
    pub host_path: String,
    pub container_path: String,
    pub access: Access,
    pub label: String,
}

impl From<&Grant> for SandboxGrant {
    fn from(grant: &Grant) -> Self {
        Self {
            host_path: grant.host_path.clone(),
            container_path: grant.container_path.clone(),
            access: grant.access,
            label: if grant.label.is_empty() {
                grant.slug.clone()
            } else {
                grant.label.clone()
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantsSnapshot {
    pub project_id: String,
    pub generated_at_ms: i64,
    pub grants: Vec<SandboxGrant>,
}

/* ------------------------------------------------------------------------- */
/* Permission requests coming out of the sandbox                              */
/* ------------------------------------------------------------------------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    /// "DeepCode is trying to access <path>"
    DirectoryAccess,
    /// "DeepCode is requesting access to <thing>", location unknown
    LocateResource,
    /// "DeepCode is asking to reach <host>"
    NetworkAccess,
    /// "DeepCode is asking for a tool to be installed"
    ToolInstall,
    /// "DeepCode is asking for a secret to be added to the project"
    ///
    /// The one kind whose answer carries data back to the model besides a yes: the
    /// name and value the operator settled on travel in the response, because the
    /// point of a project secret is that the sandbox is given it.
    Secret,
}

impl RequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestKind::DirectoryAccess => "directory_access",
            RequestKind::LocateResource => "locate_resource",
            RequestKind::NetworkAccess => "network_access",
            RequestKind::ToolInstall => "tool_install",
            RequestKind::Secret => "secret",
        }
    }
}

/// A validated request from the sandbox. Never trusted for authorisation: the
/// fields are only used to prefill the dialog the operator has to confirm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub id: String,
    pub kind: RequestKind,
    // No `token`. One used to be carried here and nothing ever read it, which made the
    // spool look authenticated when it is not: the bridge that writes a request is a
    // child of the agent's own process, so no value it can read is beyond the agent.
    // See docs/SECURITY.md, "The request spool is not authenticated".
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub workspace: String,
    #[serde(default)]
    pub args: serde_json::Value,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub pid: Option<u32>,
}

impl PermissionRequest {
    /// Path the sandbox claims it wants, if it named one. Display only.
    pub fn claimed_host_path(&self) -> Option<&str> {
        self.args
            .get("host_path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// Plain-language description of what is wanted.
    pub fn description(&self) -> String {
        let from = |key: &str| {
            self.args
                .get(key)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        match self.kind {
            RequestKind::DirectoryAccess => self
                .claimed_host_path()
                .map(str::to_string)
                .or_else(|| from("description"))
                .unwrap_or_else(|| "(unspecified location)".to_string()),
            RequestKind::LocateResource => from("description")
                .or_else(|| self.claimed_host_path().map(str::to_string))
                .unwrap_or_else(|| "(unspecified resource)".to_string()),
            RequestKind::NetworkAccess => {
                let patterns = self.requested_patterns();
                if patterns.is_empty() {
                    from("description").unwrap_or_else(|| "(unspecified destination)".to_string())
                } else {
                    patterns.join(", ")
                }
            }
            RequestKind::ToolInstall => {
                let tools = self.requested_tools();
                if tools.is_empty() {
                    from("description").unwrap_or_else(|| "(unspecified tool)".to_string())
                } else {
                    tools.join(", ")
                }
            }
            RequestKind::Secret => match self.secret_name() {
                Some(name) => {
                    if self.secret_value().is_some_and(|value| !value.is_empty()) {
                        format!("{name} (with a value)")
                    } else {
                        format!("{name} (value needed)")
                    }
                }
                None => from("description").unwrap_or_else(|| "(unnamed secret)".to_string()),
            },
        }
    }

    pub fn purpose(&self) -> Option<String> {
        self.args
            .get("purpose")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    /// What the sandbox asked for, defaulting to the safe option.
    pub fn requested_access(&self) -> Access {
        match self.args.get("access").and_then(|v| v.as_str()) {
            Some("write") => Access::ReadWrite,
            _ => Access::ReadOnly,
        }
    }

    /// Hosts or patterns a network request asks to reach.
    ///
    /// Read from untrusted input, so they are only ever *offered* to the operator.
    /// The host still validates whatever it is handed before it becomes a rule.
    pub fn requested_patterns(&self) -> Vec<String> {
        self.string_list("patterns")
    }

    /// The secret name the sandbox asked for, if it named one. Display and prefill only.
    pub fn secret_name(&self) -> Option<String> {
        self.args
            .get("name")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
    }

    /// The value the sandbox offered, if it offered one. The operator may replace it.
    pub fn secret_value(&self) -> Option<String> {
        self.args
            .get("value")
            .and_then(|value| value.as_str())
            .map(str::to_string)
    }

    /// Tool ids a tool request asks for.
    pub fn requested_tools(&self) -> Vec<String> {
        self.string_list("tools")
    }

    fn string_list(&self, key: &str) -> Vec<String> {
        match self.args.get(key) {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect(),
            // A single value is accepted too, because a model that forgot the array
            // form should produce a usable dialog rather than an empty one.
            Some(serde_json::Value::String(one)) => {
                let one = one.trim();
                if one.is_empty() {
                    Vec::new()
                } else {
                    vec![one.to_string()]
                }
            }
            _ => Vec::new(),
        }
    }

    /// Why the agent says it needs this, shown in the dialog.
    pub fn justification(&self) -> Option<String> {
        self.purpose()
    }

    pub fn requested_kind(&self) -> &str {
        match self.args.get("kind").and_then(|v| v.as_str()) {
            Some("file") => "file",
            _ => "directory",
        }
    }
}

/// The operator's answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantSpec {
    pub host_path: String,
    pub container_path: String,
    pub access: Access,
}

/// The secret an approved request settled on, as it is handed back to the model.
///
/// The value is included on purpose. A project secret exists to be given to the agent:
/// it is written into the sandbox environment, so the agent can already read it there.
/// Withholding it from the response would only make the agent open a file to find what
/// the operator had just approved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretSpec {
    pub name: String,
    pub value: String,
}

/// What the model is told when the operator has turned requests off.
///
/// One string with two readers: the host uses it when it refuses an incoming request,
/// and it travels in the snapshot so the bridge can relay the same words when it
/// declines to submit one. A model given two explanations for one setting will go and
/// try the second one.
pub const REQUESTS_DISABLED_MESSAGE: &str =
    "The operator has turned off permission requests for this project, so this request \
     cannot be made and will not reach them. Do not ask again and do not look for \
     another way in: continue with what you have, and say plainly what you could not \
     do. Requests can be turned back on in the project's Permissions tab.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionResponse {
    pub v: u32,
    pub id: String,
    /// `allow` or `deny`.
    pub decision: String,
    #[serde(default)]
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<GrantSpec>,
    /// Present when an approved request was to add a secret, so the model is told what
    /// the secret ended up being called and what it holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretSpec>,
    #[serde(default)]
    pub restart_required: bool,
    pub answered_at_ms: i64,
}

impl PermissionResponse {
    /// The same answer, with the secret the operator settled on attached for the model.
    pub fn with_secret(mut self, secret: SecretSpec) -> Self {
        self.secret = Some(secret);
        self
    }

    pub fn allow(id: impl Into<String>, message: impl Into<String>, grant: Option<GrantSpec>, restart_required: bool) -> Self {
        Self {
            v: 1,
            id: id.into(),
            decision: "allow".to_string(),
            message: message.into(),
            grant,
            secret: None,
            restart_required,
            answered_at_ms: crate::now_ms(),
        }
    }

    pub fn deny(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            v: 1,
            id: id.into(),
            decision: "deny".to_string(),
            message: message.into(),
            grant: None,
            secret: None,
            restart_required: false,
            answered_at_ms: crate::now_ms(),
        }
    }
}

/// Hosts the egress proxy refused, so the operator can allowlist them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedEgress {
    pub host: String,
    pub port: u16,
    pub at_ms: i64,
    pub reason: String,
}

/// Result of probing the local Docker installation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DockerStatus {
    pub available: bool,
    pub client_version: String,
    pub server_version: String,
    pub operating_system: String,
    /// True for Docker Desktop, where host paths are not visible to the daemon
    /// and therefore `--security-opt seccomp=<host path>` cannot be used.
    pub desktop: bool,
    pub image_present: bool,
    pub detail: String,
}


#[cfg(test)]
mod reasoning_effort_tests {
    use super::ReasoningEffort;

    #[test]
    fn every_state_round_trips_through_its_wire_value() {
        for state in ReasoningEffort::ALL {
            assert_eq!(
                ReasoningEffort::parse(state.as_str()),
                Some(state),
                "{} did not round trip",
                state.as_str()
            );
        }
    }

    #[test]
    fn the_five_wire_values_are_the_documented_ones() {
        let values: Vec<&str> = ReasoningEffort::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(values, ["none", "low", "high", "max", "default"]);
    }

    /// `none` is not a `reasoningEffort` the CLI accepts. Writing it would produce a
    /// settings file where thinking silently stays on.
    #[test]
    fn off_is_never_written_as_an_effort() {
        assert_ne!(ReasoningEffort::Off.effort_value(), "none");
        for state in ReasoningEffort::ALL {
            let value = state.effort_value();
            assert!(
                ["low", "high", "max"].contains(&value),
                "{} produced '{}', which the CLI would discard",
                state.as_str(),
                value
            );
        }
    }

    #[test]
    fn off_is_the_only_state_that_stops_thinking() {
        assert!(!ReasoningEffort::Off.is_thinking());
        for state in ReasoningEffort::ALL.iter().filter(|s| **s != ReasoningEffort::Off) {
            assert!(state.is_thinking(), "{} should think", state.as_str());
        }
    }

    #[test]
    fn only_default_defers() {
        assert!(ReasoningEffort::Default.is_deferring());
        for state in ReasoningEffort::ALL.iter().filter(|s| **s != ReasoningEffort::Default) {
            assert!(!state.is_deferring(), "{} should not defer", state.as_str());
        }
    }

    /// The operator asked for `high` as the fallback, not the CLI's `max`.
    #[test]
    fn the_fallback_is_high_not_max() {
        assert_eq!(ReasoningEffort::Default.effort_value(), "high");
    }

    #[test]
    fn a_new_project_defers() {
        assert_eq!(ReasoningEffort::default(), ReasoningEffort::Default);
    }

    #[test]
    fn lowercase_and_padded_values_are_accepted() {
        assert_eq!(ReasoningEffort::parse("  MAX "), Some(ReasoningEffort::Max));
        assert_eq!(ReasoningEffort::parse("None"), Some(ReasoningEffort::Off));
    }

    #[test]
    fn a_value_the_cli_cannot_use_is_rejected_rather_than_guessed() {
        for bad in ["", "medium", "highest", "true", "1", "off-the-record"] {
            assert_eq!(ReasoningEffort::parse(bad), None, "{bad} should not parse");
        }
    }

    #[test]
    fn every_state_has_a_label_and_an_explanation() {
        for state in ReasoningEffort::ALL {
            assert!(!state.label().trim().is_empty());
            assert!(
                state.description().len() > 20,
                "{} needs a real explanation for the tooltip",
                state.as_str()
            );
        }
    }
}

/// The network mode was called `restricted` before the allowlist could express
/// addresses and ports. The rename is a pure name change, so the migration *is* the
/// serde aliases: both spellings of the mode load, and the older one is what gets written
/// so that every build in circulation can read the file. These tests are what make that a
/// fact rather than a hope, because a state file that no longer loads is an operator's
/// projects gone.
#[cfg(test)]
mod startup_mode_tests {
    use super::*;

    /// The three names round-trip, and the default is off.
    #[test]
    fn every_startup_mode_survives_a_round_trip() {
        assert_eq!(StartupMode::default(), StartupMode::Off, "off is the default");
        for mode in [
            StartupMode::Off,
            StartupMode::Background,
            StartupMode::Foreground,
        ] {
            let text = serde_json::to_string(&mode).unwrap();
            assert_eq!(text, format!("\"{}\"", mode.as_str()));
            let back: StartupMode = serde_json::from_str(&text).unwrap();
            assert_eq!(back, mode);
        }
    }

    /// The boolean this replaced, so nobody's autostart silently turns off.
    #[test]
    fn the_boolean_this_replaced_is_still_read() {
        let on: StartupMode = serde_json::from_str("true").unwrap();
        assert_eq!(on, StartupMode::Foreground);
        let off: StartupMode = serde_json::from_str("false").unwrap();
        assert_eq!(off, StartupMode::Off);
    }

    /// An older state file uses the old *key*, which the field aliases.
    #[test]
    fn a_settings_file_with_the_old_key_still_parses() {
        let settings: AppSettings =
            serde_json::from_str(r#"{"start_at_login": true}"#).unwrap();
        assert_eq!(settings.startup, StartupMode::Foreground);
        let other: AppSettings = serde_json::from_str(r#"{"startup": "background"}"#).unwrap();
        assert_eq!(other.startup, StartupMode::Background);
        assert!(other.startup.starts_hidden());
        assert!(!other.startup.starts_hidden() || other.startup.is_on());
    }

    /// A mode nobody recognises is an error rather than a silent "off": this controls whether
    /// the app starts with the machine, and guessing wrong is worse than saying so.
    #[test]
    fn an_unknown_mode_is_an_error() {
        assert!(serde_json::from_str::<StartupMode>("\"sometimes\"").is_err());
        assert_eq!(StartupMode::from_str("  Background "), Some(StartupMode::Background));
        assert_eq!(StartupMode::from_str("tray"), Some(StartupMode::Background));
        assert_eq!(StartupMode::from_str("nonsense"), None);
    }

    /// Closing to the tray is off unless somebody says otherwise.
    #[test]
    fn closing_to_the_tray_is_off_by_default() {
        let settings: AppSettings = serde_json::from_str("{}").unwrap();
        assert!(!settings.close_to_tray);
        assert_eq!(settings.startup, StartupMode::Off);
    }
}

#[cfg(test)]
mod network_policy_tests {
    use super::*;

    /// Both spellings are read; the **older** one is written.
    ///
    /// The rename was meant to normalise the file on the next save, and that is the one
    /// thing it must not do. A build that predates the rename cannot read `allowlisted`,
    /// and a file it cannot read is a file it reports as corrupt: it is set aside, and the
    /// app starts with an empty project list. That happened twice, to five projects, with
    /// the installed app and a development build sharing one data directory.
    ///
    /// Writing the older name is what makes every build in circulation able to read what
    /// this one writes. `allowlisted` stays the name people see.
    #[test]
    fn both_mode_names_are_read_and_the_older_one_is_written() {
        let from_old: NetworkPolicy =
            serde_json::from_str(r#"{"mode":"restricted","allow":["registry.npmjs.org"]}"#)
                .expect("a state file written before the rename must still load");
        assert_eq!(from_old.mode_str(), "allowlisted");
        assert_eq!(from_old.allowlist(), ["registry.npmjs.org"]);

        // The newer spelling still loads, so a file this build wrote until now keeps its
        // mode instead of being rejected as an unknown variant.
        let from_new: NetworkPolicy =
            serde_json::from_str(r#"{"mode":"allowlisted","allow":["registry.npmjs.org"]}"#)
                .expect("a file using the newer spelling must still load");
        assert_eq!(from_new, from_old);

        // And what gets written is the spelling an older build understands.
        let written = serde_json::to_string(&from_old).unwrap();
        assert!(written.contains(r#""mode":"restricted""#), "{written}");
        assert!(
            !written.contains("allowlisted"),
            "an older build must be able to read this: {written}"
        );
        assert_eq!(serde_json::from_str::<NetworkPolicy>(&written).unwrap(), from_old);
    }

    #[test]
    fn the_default_is_allowlisted_and_is_the_strict_one() {
        let default = NetworkPolicy::default();
        assert!(matches!(default, NetworkPolicy::Allowlisted { .. }));
        assert_eq!(default.mode_str(), "allowlisted");
        // The default consults the project list and goes through the proxy: a default
        // that ignored the list would be a mode that silently reaches nothing.
        assert!(default.honours_allowlist());
        assert!(default.uses_proxy());
        assert!(default.needs_netfilter());
    }

    /// `internet` and `full` are the modes where the list is not consulted, and they
    /// must say so, or an entry would sit in the UI appearing to do something.
    #[test]
    fn only_the_allowlisted_mode_honours_the_list() {
        for mode in [NetworkPolicy::None, NetworkPolicy::Internet, NetworkPolicy::Full] {
            assert!(!mode.honours_allowlist(), "{mode:?} must not claim to honour a list");
            assert!(mode.allowlist().is_empty());
        }
    }
}

/// The switch that lets the operator stop being asked.
#[cfg(test)]
mod request_gate_tests {
    use super::*;

    /// The default is *on*, and that has to survive the field not existing: a project
    /// stored before this switch was added must not silently become one that cannot ask,
    /// or the sandbox stops at the first missing thing with no way to say why.
    #[test]
    fn a_project_that_predates_the_switch_can_still_ask() {
        let raw = r#"{"id":"p1","name":"n","slug":"s","root_dir":"/w","created_at_ms":0}"#;
        let project: Project = serde_json::from_str(raw).unwrap();
        assert!(project.requests_enabled);
        // And a snapshot that predates it is likewise permissive, because the bridge
        // reads this field to decide whether to submit at all.
        let snapshot: SandboxSnapshot = serde_json::from_str(
            r#"{"project_id":"p1","project_name":"n","container_name":"c","image":"i",
                "workspace_mount":"/workspace","network_mode":"allowlisted",
                "egress_allowlist":[],"started_at_ms":0,"grants":[]}"#,
        )
        .unwrap();
        assert!(snapshot.requests_enabled);
        assert!(snapshot.requests_disabled_message.is_empty());
    }

    /// Off is off, and the explanation travels with the flag: the bridge relays this text
    /// rather than keeping its own copy, so there is one sentence for the model to hear
    /// whichever way it finds out.
    #[test]
    fn the_message_travels_with_the_flag() {
        let mut project: Project = serde_json::from_str(
            r#"{"id":"p1","name":"n","slug":"s","root_dir":"/w","created_at_ms":0,
                "requests_enabled":false}"#,
        )
        .unwrap();
        let snapshot = crate::settings::build_sandbox_snapshot(
            &project,
            &[],
            &project.network,
            Vec::new(),
            Vec::new(),
        );
        assert!(!snapshot.requests_enabled);
        assert_eq!(snapshot.requests_disabled_message, REQUESTS_DISABLED_MESSAGE);
        // The message has to say the two things that stop the model trying again.
        assert!(snapshot.requests_disabled_message.contains("Do not ask again"));
        assert!(snapshot.requests_disabled_message.contains("Permissions tab"));

        project.requests_enabled = true;
        let snapshot = crate::settings::build_sandbox_snapshot(
            &project,
            &[],
            &project.network,
            Vec::new(),
            Vec::new(),
        );
        assert!(snapshot.requests_enabled);
        assert!(
            snapshot.requests_disabled_message.is_empty(),
            "an enabled sandbox has nothing to be told about a disabled one"
        );
    }
}

/// What the sandbox is *told* about the switch, in the file it reads first. The bridge
/// and the host enforce it; this is the part that stops the model wasting a turn.
#[cfg(test)]
mod agents_md_gate_tests {
    use super::*;
    use crate::credentials::ResolvedCredentials;
    use std::collections::BTreeMap;

    fn creds() -> ResolvedCredentials {
        ResolvedCredentials {
            model: "test-model".into(),
            base_url: "https://api.example.com".into(),
            api_key: Some("k".into()),
            thinking_enabled: true,
            reasoning_effort: "high".into(),
            extra_env: BTreeMap::new(),
            provenance: "test".into(),
            warnings: Vec::new(),
        }
    }

    fn project(requests_enabled: bool) -> Project {
        serde_json::from_str(&format!(
            r#"{{"id":"p1","name":"n","slug":"s","root_dir":"/w","created_at_ms":0,
                 "requests_enabled":{requests_enabled}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn the_sandbox_is_told_when_it_cannot_ask() {
        let off = crate::settings::build_agents_md(
            &project(false),
            &[],
            &NetworkPolicy::Allowlisted { allow: vec![] },
            &creds(),
        );
        assert!(
            off.contains("Permission requests are off"),
            "the sandbox must be told before it composes a request: {off}"
        );

        let on = crate::settings::build_agents_md(
            &project(true),
            &[],
            &NetworkPolicy::Allowlisted { allow: vec![] },
            &creds(),
        );
        assert!(
            !on.contains("Permission requests are off"),
            "a sandbox that can ask must not be told otherwise: {on}"
        );
        assert!(on.contains("deepsand_request_directory_access"));
    }

    /// The allowlist has two enforcement paths, and the description the sandbox reads has
    /// to say so: claiming every byte goes through the proxy is untrue now that an address
    /// entry is reached directly.
    #[test]
    fn the_allowlisted_description_names_both_paths() {
        let md = crate::settings::build_agents_md(
            &project(true),
            &[],
            &NetworkPolicy::Allowlisted { allow: vec!["registry.npmjs.org".into()] },
            &creds(),
        );
        assert!(md.contains("proxy"), "{md}");
        assert!(
            md.contains("reached directly"),
            "an address entry is not proxied, and the sandbox must not be told it is: {md}"
        );
    }
}
