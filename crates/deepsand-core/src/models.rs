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

/// What to say when a model list cannot be read.
///
/// A provider that does not implement `/models` is not a failure of this app, and the difference
/// matters to whoever reads it: "this API has no model list to ask for" is a reason to use
/// Custom, while "the key was refused" is a reason to fix the key. Kept here, beside the
/// parsing, because it is the same kind of decision -- reading a reply and saying what it means
/// -- and it is the part that is worth a test per case.
///
/// Every message says what to do next. The dropdown still has Defer and Custom either way, so
/// none of these is fatal; they exist so the operator is never guessing why a list is short.
pub fn listing_problem(url: &str, status: u16, body: &str) -> String {
    match status {
        401 | 403 => format!(
            "{url} refused the API key ({status}). Check it in Secrets, or choose a model with \
             Custom"
        ),
        404 | 405 | 501 => format!(
            "{url} does not offer a model list ({status}), so this API cannot be enumerated. \
             Choose a model with Custom"
        ),
        429 => format!(
            "{url} is rate limiting ({status}). Try again in a moment, or choose a model with \
             Custom"
        ),
        500..=599 => format!(
            "{url} failed with {status}, which is its own error rather than a configuration \
             problem. Try again later, or choose a model with Custom"
        ),
        200..=299 => format!(
            "{url} answered without any models in it. Choose a model with Custom"
        ),
        other => format!(
            "{url} answered {other}{}. Choose a model with Custom",
            api_error_hint(body)
        ),
    }
}

/// The API's own words, when its reply has any -- ": invalid api key" is worth more to the
/// operator than "401". Only ever a short excerpt, and only from JSON, so an HTML error page
/// cannot arrive in the middle of a sentence.
fn api_error_hint(body: &str) -> String {
    const LIMIT: usize = 200;
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return String::new();
    };
    let message = ["error", "message", "detail"]
        .iter()
        .find_map(|key| value.get(*key))
        .and_then(|found| match found {
            serde_json::Value::Object(map) => map
                .get("message")
                .or_else(|| map.get("msg"))
                .and_then(|value| value.as_str())
                .map(str::to_string),
            serde_json::Value::String(text) => Some(text.clone()),
            _ => None,
        });
    match message {
        Some(message) if !message.trim().is_empty() => {
            let trimmed: String = message.trim().chars().take(LIMIT).collect();
            format!(": {}", without_token_like_runs(&trimmed))
        }
        _ => String::new(),
    }
}

/// Replace anything shaped like a token with `[redacted]`.
///
/// An API's error message is worth repeating -- "invalid api key" is more use than "401" -- but
/// these messages are echoed into the window and into the log, and the log is documented as
/// carrying no credentials. Providers sometimes quote the key they refused (DeepSeek masks it;
/// nothing makes that a rule), so a long run with both letters and digits in it is not repeated.
/// A false positive costs a phrase in a diagnostic message; a false negative puts a key in a
/// file that gets sent to somebody.
fn without_token_like_runs(message: &str) -> String {
    message
        .split(' ')
        .map(|word| {
            let looks_like_a_token = word.chars().count() >= 16
                && word.chars().any(|c| c.is_ascii_digit())
                && word.chars().any(|c| c.is_ascii_alphabetic());
            if looks_like_a_token {
                "[redacted]"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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

    /// One case per way this goes wrong. The point of each message is that it tells the operator
    /// something they can act on, and none of them is a dead end: Custom always works.
    #[test]
    fn every_way_the_list_can_fail_says_what_to_do_about_it() {
        let url = "https://api.example.test/models";

        let refused = listing_problem(url, 401, "{}");
        assert!(refused.contains("refused the API key"), "{refused}");
        assert!(refused.contains("Custom"), "every message offers the way out: {refused}");

        // The case the report asked about: no enumeration at all.
        for status in [404, 405, 501] {
            let unsupported = listing_problem(url, status, "");
            assert!(
                unsupported.contains("does not offer a model list"),
                "{status}: {unsupported}"
            );
            assert!(unsupported.contains("Custom"), "{unsupported}");
        }

        let empty = listing_problem(url, 200, r#"{"object":"list","data":[]}"#);
        assert!(empty.contains("without any models"), "{empty}");

        let rate_limited = listing_problem(url, 429, "");
        assert!(rate_limited.contains("rate limiting"), "{rate_limited}");

        let broken = listing_problem(url, 503, "");
        assert!(broken.contains("its own error"), "{broken}");
    }

    #[test]
    fn an_apis_own_wording_is_repeated_rather_than_replaced() {
        let problem = listing_problem(
            "https://api.example.test/models",
            400,
            r#"{"error":{"message":"invalid model list request"}}"#,
        );
        assert!(problem.contains("answered 400"), "{problem}");
        assert!(problem.contains("invalid model list request"), "{problem}");

        // A body that is not JSON, or has nothing to say, adds nothing.
        assert_eq!(api_error_hint("<html>502</html>"), "");
        assert_eq!(api_error_hint("{}"), "");
    }

    /// The log is documented as carrying no credentials, and an API's own error message is the
    /// one place a key can arrive in it uninvited. DeepSeek masks the key it refuses; this does
    /// not depend on that.
    #[test]
    fn a_key_quoted_back_by_the_api_does_not_reach_the_message() {
        let problem = listing_problem(
            "https://api.example.test/models",
            400,
            r#"{"error":{"message":"Your api key sk-abc123def456ghi789jkl is invalid"}}"#,
        );
        assert!(problem.contains("is invalid"), "the useful part stays: {problem}");
        assert!(problem.contains("[redacted]"), "{problem}");
        assert!(
            !problem.contains("sk-abc123def456ghi789jkl"),
            "the key must not survive: {problem}"
        );

        // Ordinary words are left alone, including ones with digits.
        assert_eq!(without_token_like_runs("invalid model list request"), "invalid model list request");
        assert_eq!(without_token_like_runs("HTTP 2 404"), "HTTP 2 404");
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
