//! Where the sandboxed DeepCode gets its model credentials.
//!
//! Default is "whatever the operator already uses": the host's
//! `~/.deepcode/settings.json`. A project may override any field. The key is
//! never written into the project directory, never baked into the image, and
//! only ever lands in a `:ro` mount that the entrypoint copies into the
//! container's own home volume.

use crate::error::Result;
use crate::model::{AppSettings, CredentialSource, Credentials, Project};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// The DeepCode CLI reads `<home>/.deepcode/settings.json` first of all.
pub fn host_settings_path() -> PathBuf {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().join(".deepcode").join("settings.json"))
        .unwrap_or_else(|| PathBuf::from(".deepcode/settings.json"))
}

/// What we could learn from the operator's own DeepCode configuration.
#[derive(Debug, Clone, Default)]
pub struct HostConfig {
    pub path: PathBuf,
    pub present: bool,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub thinking_enabled: Option<bool>,
    pub reasoning_effort: Option<String>,
    pub error: Option<String>,
}

impl HostConfig {
    pub fn masked_api_key(&self) -> Option<String> {
        let key = self.api_key.as_deref()?.trim();
        if key.is_empty() {
            return None;
        }
        let tail: String = key.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
        Some(format!("****{tail}"))
    }
}

/// Read the host's DeepCode settings, tolerating a missing or malformed file.
pub fn read_host_config() -> HostConfig {
    let path = host_settings_path();
    let mut out = HostConfig { path: path.clone(), ..Default::default() };

    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(_) => return out,
    };
    out.present = true;

    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(err) => {
            out.error = Some(format!("{} could not be parsed: {err}", path.display()));
            return out;
        }
    };

    let env = parsed.get("env");
    let str_at = |value: &serde_json::Value, key: &str| -> Option<String> {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    if let Some(env) = env {
        out.model = str_at(env, "MODEL");
        out.base_url = str_at(env, "BASE_URL");
        out.api_key = str_at(env, "API_KEY");
    }
    // Top-level fields win over `env`, matching the CLI's own precedence.
    if let Some(model) = str_at(&parsed, "model") {
        out.model = Some(model);
    }
    if let Some(thinking) = parsed.get("thinkingEnabled").and_then(|v| v.as_bool()) {
        out.thinking_enabled = Some(thinking);
    }
    if let Some(effort) = str_at(&parsed, "reasoningEffort") {
        out.reasoning_effort = Some(effort);
    }
    out
}

/// The effective credentials for one sandbox, plus how they were chosen.
#[derive(Debug, Clone, Default)]
pub struct ResolvedCredentials {
    pub model: String,
    pub base_url: String,
    pub api_key: Option<String>,
    pub thinking_enabled: bool,
    pub reasoning_effort: String,
    pub extra_env: BTreeMap<String, String>,
    /// Human-readable provenance, shown in the settings panel.
    pub provenance: String,
    pub warnings: Vec<String>,
}

/// Does this environment variable name look like it carries a credential?
///
/// `Credentials::extra_env` is a passthrough an operator can set on a project, and it exists
/// for the things a project genuinely needs — a proxy, a registry URL, a locale. It must not
/// double as a way to hand unrelated keys to the sandbox: every tool the agent runs inherits
/// this environment, so anything in it is readable by the agent, and round 3 of the escape
/// assessment found credential-shaped values readable inside the sandbox as a result.
///
/// This is a name heuristic, not a boundary. The boundary is the container; the point here is
/// only to stop the passthrough being an accidental disclosure channel. The model API key is
/// *not* covered by this: the CLI takes it from `env.API_KEY`, so it has to be there, and it
/// is documented as visible to the agent rather than pretended otherwise.
fn is_credential_shaped(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    const FRAGMENTS: [&str; 11] = [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "APIKEY",
        "API_KEY",
        "PRIVATE_KEY",
        "ACCESS_KEY",
        "CREDENTIAL",
        "SESSION_KEY",
        "AUTH",
    ];
    const PREFIXES: [&str; 12] = [
        "AWS_",
        "AZURE_",
        "GCP_",
        "GOOGLE_",
        "GITHUB_",
        "GH_",
        "GITLAB_",
        "OPENAI_",
        "ANTHROPIC_",
        "DEEPSEEK_",
        "DEEPSAND_",
        "OPENSSH_",
    ];
    FRAGMENTS.iter().any(|fragment| upper.contains(fragment))
        || PREFIXES.iter().any(|prefix| upper.starts_with(prefix))
}

/// Split a passthrough environment into what may travel and what may not.
fn filter_extra_env(
    extra: &BTreeMap<String, String>,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut keep = BTreeMap::new();
    let mut dropped = Vec::new();
    for (name, value) in extra {
        if is_credential_shaped(name) {
            dropped.push(name.clone());
        } else {
            keep.insert(name.clone(), value.clone());
        }
    }
    (keep, dropped)
}

/// Merge, in order of increasing precedence:
///   1. Deepsand's own defaults
///   2. the host's `~/.deepcode/settings.json`   (when the project inherits)
///   3. the project's explicit overrides
pub fn resolve(project: &Project, app: &AppSettings, host: &HostConfig) -> ResolvedCredentials {
    let mut out = ResolvedCredentials {
        model: app.default_model.clone(),
        base_url: app.default_base_url.clone(),
        api_key: None,
        // The base is the fallback for `default`: thinking on, moderate effort. The
        // host's settings.json may override both below, which is what `default`
        // means; a state that is not `default` overrides the host instead.
        thinking_enabled: true,
        reasoning_effort: project.reasoning_effort.effort_value().to_string(),
        extra_env: BTreeMap::new(),
        provenance: "Deepsand defaults".to_string(),
        warnings: Vec::new(),
    };

    let mut layers: Vec<&str> = vec!["Deepsand defaults"];

    let inherit = matches!(project.credentials.source, CredentialSource::InheritHost);
    if inherit && host.present {
        if let Some(model) = &host.model {
            out.model = model.clone();
        }
        if let Some(base_url) = &host.base_url {
            out.base_url = base_url.clone();
        }
        if let Some(key) = &host.api_key {
            out.api_key = Some(key.clone());
        }
        if let Some(thinking) = host.thinking_enabled {
            out.thinking_enabled = thinking;
        }
        if let Some(effort) = &host.reasoning_effort {
            out.reasoning_effort = effort.clone();
        }

        // The switch beats the host's file, unless it is deferring. Applying it here,
        // after the host merge, is what makes an explicit choice stick; leaving the
        // host's value in place for `default` is what makes `default` meaningful.
        if !project.reasoning_effort.is_deferring() {
            out.thinking_enabled = project.reasoning_effort.is_thinking();
            out.reasoning_effort = project.reasoning_effort.effort_value().to_string();
        }
        layers.push("host ~/.deepcode/settings.json");
    } else if inherit {
        out.warnings.push(format!(
            "no DeepCode configuration was found at {}, so the built-in defaults are being used",
            host.path.display()
        ));
    }
    if let Some(err) = &host.error {
        out.warnings.push(err.clone());
    }

    // Layer 3: explicit project overrides always win.
    let mut overrode = false;
    let creds: &Credentials = &project.credentials;
    if let Some(model) = non_empty(&creds.model) {
        out.model = model;
        overrode = true;
    }
    if let Some(base_url) = non_empty(&creds.base_url) {
        out.base_url = base_url;
        overrode = true;
    }
    if let Some(key) = non_empty(&creds.api_key) {
        out.api_key = Some(key);
        overrode = true;
    }
    if let Some(thinking) = creds.thinking_enabled {
        out.thinking_enabled = thinking;
        overrode = true;
    }
    if let Some(effort) = non_empty(&creds.reasoning_effort) {
        out.reasoning_effort = effort;
        overrode = true;
    }
    // The passthrough is filtered, not trusted: see `is_credential_shaped`. Dropping a name
    // is announced rather than silent, because an operator who relied on it needs to know
    // why their tool stopped seeing a variable.
    let (extra_env, dropped_env) = filter_extra_env(&creds.extra_env);
    out.extra_env = extra_env;
    if !dropped_env.is_empty() {
        out.warnings.push(format!(
            "{} environment variable(s) in the host DeepCode configuration look like credentials \
             and were not passed into the sandbox: {}. The agent can read the sandbox's environment, \
             so a key that has nothing to do with this project would be readable there.",
            dropped_env.len(),
            dropped_env.join(", ")
        ));
    }
    if overrode {
        layers.push("this project's overrides");
    }

    if !matches!(out.reasoning_effort.as_str(), "low" | "high" | "max") {
        out.warnings.push(format!(
            "reasoningEffort '{}' is not one of low/high/max; DeepCode will fall back to its default",
            out.reasoning_effort
        ));
        out.reasoning_effort = "max".to_string();
    }

    if out.api_key.as_ref().is_none_or(|k| k.trim().is_empty()) {
        out.warnings.push(
            "no API key is configured, so the sandboxed DeepCode will refuse to start. Add one in Settings, or \
             configure ~/.deepcode/settings.json on this machine."
                .to_string(),
        );
    }

    out.provenance = layers.join(" -> ");
    out
}

fn non_empty(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Summarise the host configuration for the settings panel without leaking the
/// key itself.
pub fn describe_host_config(host: &HostConfig) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert("path".into(), host.path.display().to_string());
    map.insert("present".into(), host.present.to_string());
    map.insert("model".into(), host.model.clone().unwrap_or_else(|| "(unset)".into()));
    map.insert("baseUrl".into(), host.base_url.clone().unwrap_or_else(|| "(unset)".into()));
    map.insert(
        "apiKey".into(),
        host.masked_api_key().unwrap_or_else(|| "(unset)".into()),
    );
    map.insert(
        "thinkingEnabled".into(),
        host.thinking_enabled.map(|b| b.to_string()).unwrap_or_else(|| "(unset)".into()),
    );
    map.insert(
        "reasoningEffort".into(),
        host.reasoning_effort.clone().unwrap_or_else(|| "(unset)".into()),
    );
    if let Some(err) = &host.error {
        map.insert("error".into(), err.clone());
    }
    map
}

/// Write a `settings.json` for the sandboxed CLI. Only called from
/// [`crate::settings`]; kept here so credential handling stays in one place.
pub(crate) fn apply_to_settings_json(creds: &ResolvedCredentials, target: &mut serde_json::Map<String, serde_json::Value>) {
    let mut env = serde_json::Map::new();
    env.insert("MODEL".into(), serde_json::Value::String(creds.model.clone()));
    env.insert("BASE_URL".into(), serde_json::Value::String(creds.base_url.clone()));
    if let Some(key) = &creds.api_key {
        env.insert("API_KEY".into(), serde_json::Value::String(key.clone()));
    }
    for (key, value) in &creds.extra_env {
        env.insert(key.clone(), serde_json::Value::String(value.clone()));
    }
    target.insert("env".into(), serde_json::Value::Object(env));
    target.insert("thinkingEnabled".into(), serde_json::Value::Bool(creds.thinking_enabled));
    target.insert(
        "reasoningEffort".into(),
        serde_json::Value::String(creds.reasoning_effort.clone()),
    );
}

/// Read a saved settings file back, used by tests and by the "verify" action.
pub fn read_settings_file(path: &std::path::Path) -> Result<serde_json::Value> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DeepCodeMode, NetworkPolicy, ResourceLimits};

    fn project() -> Project {
        Project {
            id: "p1".into(),
            name: "my-website".into(),
            slug: "my-website".into(),
            root_dir: "/projects/my-website".into(),
            created_at_ms: 0,
            network: NetworkPolicy::Internet,
            limits: ResourceLimits::default(),
            credentials: Credentials::default(),
            deepcode_mode: DeepCodeMode::AllowAll,
            allowed_roots: vec![],
            reasoning_effort: Default::default(),
            tools: None,
            notes: String::new(),
        }
    }

    #[test]
    fn credential_shaped_names_are_recognised_whatever_their_case() {
        for name in [
            "API_KEY",
            "api_key",
            "OPENAI_API_KEY",
            "GH_TOKEN",
            "github_token",
            "AWS_SECRET_ACCESS_KEY",
            "MY_PASSWORD",
            "SERVICE_ACCOUNT_CREDENTIAL",
            "GCP_CREDENTIALS",
            "NPM_AUTH_TOKEN",
        ] {
            assert!(is_credential_shaped(name), "{name} should be recognised");
        }
    }

    #[test]
    fn ordinary_passthrough_names_are_left_alone() {
        // The point of the passthrough: a project may legitimately need these.
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "NPM_CONFIG_REGISTRY",
            "CARGO_HOME",
            "LANG",
            "TZ",
            "MODEL",
            "BASE_URL",
        ] {
            assert!(!is_credential_shaped(name), "{name} must survive");
        }
    }

    #[test]
    fn the_passthrough_drops_credentials_and_keeps_the_rest() {
        let mut extra = BTreeMap::new();
        extra.insert("HTTP_PROXY".to_string(), "http://proxy:3128".to_string());
        extra.insert("AWS_SECRET_ACCESS_KEY".to_string(), "shhh".to_string());
        extra.insert("GH_TOKEN".to_string(), "shhh".to_string());

        let (kept, dropped) = filter_extra_env(&extra);
        assert_eq!(kept.keys().collect::<Vec<_>>(), vec!["HTTP_PROXY"]);
        assert_eq!(dropped, vec!["AWS_SECRET_ACCESS_KEY", "GH_TOKEN"]);
    }

    #[test]
    fn resolve_announces_what_it_dropped_rather_than_dropping_it_silently() {
        // An operator whose tool stopped seeing a variable needs to know why, and the
        // warning must name the variable without ever naming its value.
        let mut project = project();
        project.credentials.extra_env.insert(
            "OPENAI_API_KEY".to_string(),
            "sk-not-a-real-key".to_string(),
        );
        project
            .credentials
            .extra_env
            .insert("HTTP_PROXY".to_string(), "http://proxy:3128".to_string());

        let resolved = resolve(&project, &AppSettings::default(), &HostConfig::default());

        assert_eq!(
            resolved.extra_env.keys().collect::<Vec<_>>(),
            vec!["HTTP_PROXY"],
            "the credential-shaped name must not reach the sandbox"
        );
        let warning = resolved
            .warnings
            .iter()
            .find(|w| w.contains("OPENAI_API_KEY"))
            .expect("the drop is announced");
        assert!(
            !warning.contains("sk-not-a-real-key"),
            "the warning names the variable, never the value: {warning}"
        );
    }
}
