//! The model list: where to ask for it, and how to read the answer.
//!
//! The list comes from the API the project is already configured to use, so the two things
//! worth pinning down are both pure: which URL to ask, and which ids a reply contains. The
//! request itself is the app's (`src-tauri`), because the key that signs it must not reach the
//! window.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One model the API offers: the id to run, and the name to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelChoice {
    /// What goes into `MODEL`, and therefore what the sandbox runs.
    pub id: String,
    /// What a person reads in the dropdown. Falls back to the id when the API has no name.
    pub name: String,
}

impl ModelChoice {
    fn new(id: &str, name: Option<&str>) -> Option<Self> {
        let id = id.trim();
        if id.is_empty() {
            return None;
        }
        let name = name.map(str::trim).filter(|name| !name.is_empty());
        Some(Self {
            id: id.to_string(),
            name: name.unwrap_or(id).to_string(),
        })
    }
}

/// Where to ask for the model list, in the order to try.
///
/// OpenAI-compatible APIs disagree about whether the version belongs to the base URL:
/// `https://api.deepseek.com/models` and `https://api.openai.com/v1/models` are both correct,
/// for services whose configured base is `https://api.deepseek.com` and `https://api.openai.com/v1`
/// respectively. So the configured base is tried first, and `/v1/models` is tried as well when
/// the base does not already name a version. A base that is itself the endpoint is used as it is.
pub fn model_endpoints(base_url: &str) -> Vec<String> {
    let base = base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Vec::new();
    }
    if base.ends_with("/models") {
        return vec![base.to_string()];
    }
    let mut endpoints = vec![format!("{base}/models")];
    if !base.ends_with("/v1") {
        endpoints.push(format!("{base}/v1/models"));
    }
    endpoints
}

/// The models in a `/models` reply, sorted by name.
///
/// Sorted because a provider's order is not something to rely on (some list hundreds), and
/// because the same list in the same order every time is what makes a dropdown usable. Wrapped
/// replies are read as they come: `{"data": [{"id": …}]}`, `{"models": [{"name": …}]}`, or a bare
/// array of either. Anything else is an empty list rather than an error -- the caller decides
/// what to say, and "no models" is not a failure.
pub fn parse_models(body: &str) -> Vec<ModelChoice> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let mut out: Vec<ModelChoice> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    let mut take = |value: &serde_json::Value| {
        let choice = match value {
            serde_json::Value::String(id) => ModelChoice::new(id, None),
            serde_json::Value::Object(map) => {
                let id = map
                    .get("id")
                    .or_else(|| map.get("model"))
                    .or_else(|| map.get("name"))
                    .and_then(|value| value.as_str());
                let name = map
                    .get("name")
                    .or_else(|| map.get("display_name"))
                    .and_then(|value| value.as_str());
                id.and_then(|id| ModelChoice::new(id, name))
            }
            _ => None,
        };
        if let Some(choice) = choice {
            if seen.insert(choice.id.clone()) {
                out.push(choice);
            }
        }
    };

    let list = value
        .get("data")
        .or_else(|| value.get("models"))
        .unwrap_or(&value);
    match list {
        serde_json::Value::Array(entries) => entries.iter().for_each(|entry| take(entry)),
        // `{"data": {"models": [...]}}`, which one provider does.
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Array(entries)) = map.get("models") {
                entries.iter().for_each(|entry| take(entry));
            }
        }
        _ => {}
    }

    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

#[cfg(test)]
mod model_list_tests {
    use super::*;

    /// The shape this was written against, taken from a real reply from the configured API.
    const DEEPSEEK: &str = r#"{"object":"list","data":[
        {"id":"deepseek-flash","object":"model","owned_by":"deepseek","name":"DeepSeek-V4.1-Flash"},
        {"id":"deepseek-v4-pro","object":"model","owned_by":"deepseek","name":"DeepSeek-V4-Pro"}
    ]}"#;

    #[test]
    fn a_real_reply_yields_the_names_and_the_ids() {
        // Order is the sorting test's business; this one is about reading the pair out of the
        // reply at all, so it does not depend on it.
        let models = parse_models(DEEPSEEK);
        assert_eq!(models.len(), 2);
        let pairs: Vec<(&str, &str)> = models
            .iter()
            .map(|m| (m.name.as_str(), m.id.as_str()))
            .collect();
        assert!(pairs.contains(&("DeepSeek-V4.1-Flash", "deepseek-flash")), "{pairs:?}");
        assert!(pairs.contains(&("DeepSeek-V4-Pro", "deepseek-v4-pro")), "{pairs:?}");
    }

    #[test]
    fn a_model_without_a_name_is_known_by_its_id() {
        let models = parse_models(r#"{"data":[{"id":"gpt-5"}]}"#);
        assert_eq!(models[0].name, "gpt-5");
        assert_eq!(models[0].id, "gpt-5");
    }

    #[test]
    fn the_other_wrappers_are_read_too() {
        assert_eq!(parse_models(r#"["b","a"]"#).len(), 2);
        assert_eq!(parse_models(r#"{"models":[{"name":"local"}]}"#)[0].id, "local");
        assert_eq!(
            parse_models(r#"{"data":{"models":[{"id":"nested"}]}}"#)[0].id,
            "nested"
        );
    }

    #[test]
    fn the_list_is_sorted_by_name_and_deduplicated() {
        let models = parse_models(r#"{"data":[{"id":"b"},{"id":"a"},{"id":"b"}]}"#);
        assert_eq!(
            models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn a_body_that_is_not_a_model_list_is_empty_rather_than_an_error() {
        assert!(parse_models("").is_empty());
        assert!(parse_models("<html>not json</html>").is_empty());
        assert!(parse_models(r#"{"error":{"message":"bad key"}}"#).is_empty());
        assert!(parse_models(r#"{"data":[{"object":"model"}]}"#).is_empty());
    }

    #[test]
    fn the_endpoint_is_joined_the_way_the_configured_base_needs() {
        assert_eq!(
            model_endpoints("https://api.deepseek.com"),
            vec![
                "https://api.deepseek.com/models".to_string(),
                "https://api.deepseek.com/v1/models".to_string()
            ]
        );
        // A base that already names the version gets one candidate, not a doubled one.
        assert_eq!(
            model_endpoints("https://api.openai.com/v1"),
            vec!["https://api.openai.com/v1/models".to_string()]
        );
        // Trailing slashes and a pasted endpoint are both tolerated.
        assert_eq!(
            model_endpoints("https://example.test/v1/"),
            vec!["https://example.test/v1/models".to_string()]
        );
        assert_eq!(
            model_endpoints("https://example.test/v1/models"),
            vec!["https://example.test/v1/models".to_string()]
        );
        assert!(model_endpoints("   ").is_empty());
    }
}
