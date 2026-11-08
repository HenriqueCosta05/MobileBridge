//! Redaction of sensitive values before events are persisted or displayed (SEC-003 to SEC-005).
//!
//! Redaction runs inside the recording pipeline, so secrets never reach disk when it is enabled.
//! Invalid custom rules are rejected rather than skipped: security-sensitive configuration fails closed.

use std::borrow::Cow;

use regex::{Captures, Regex, RegexSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::event::Event;

/// A user-supplied rule, as read from configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionRuleSpec {
    pub name: String,
    pub pattern: String,
    #[serde(default = "default_replacement")]
    pub replacement: String,
}

fn default_replacement() -> String {
    "[REDACTED]".to_string()
}

#[derive(Debug, Error)]
#[error("invalid redaction rule '{name}': {reason}")]
pub struct RedactionRuleError {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
struct RedactionRule {
    name: String,
    pattern: Regex,
    replacement: String,
}

#[derive(Debug, Clone)]
pub struct Redactor {
    rules: Vec<RedactionRule>,
    /// All rule patterns, used to find in one scan which rules apply to a text.
    any_rule: RegexSet,
}

/// Built-in rules for credentials, tokens and personal identifiers commonly seen in logs.
/// Replacements keep the leading key so the redacted output stays readable.
const BUILT_IN_RULES: [(&str, &str, &str); 6] = [
    (
        "bearer-token",
        r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}",
        "$1 [REDACTED]",
    ),
    (
        "basic-auth",
        r"(?i)\b(basic)\s+[A-Za-z0-9+/]{8,}={0,2}",
        "$1 [REDACTED]",
    ),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}",
        "[REDACTED-JWT]",
    ),
    (
        "secret-assignment",
        r#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|session[_-]?id)(["']?\s*[:=]\s*["']?)[^\s"',;&}]+"#,
        "$1$2[REDACTED]",
    ),
    (
        "url-credential-parameter",
        r"(?i)([?&](?:access_token|refresh_token|token|key|api_key|password|sig|signature)=)[^&\s]+",
        "$1[REDACTED]",
    ),
    (
        "email-address",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "[REDACTED-EMAIL]",
    ),
];

impl Redactor {
    /// A redactor that changes nothing. Only used when the user explicitly opts out.
    pub fn disabled() -> Self {
        Self {
            rules: Vec::new(),
            any_rule: RegexSet::empty(),
        }
    }

    /// Fails when the combined set exceeds the regex size limits, even if each rule compiles alone.
    fn from_rules(rules: Vec<RedactionRule>) -> Result<Self, RedactionRuleError> {
        let any_rule =
            RegexSet::new(rules.iter().map(|rule| rule.pattern.as_str())).map_err(|error| {
                RedactionRuleError {
                    name: "(all rules combined)".to_string(),
                    reason: error.to_string(),
                }
            })?;
        Ok(Self { rules, any_rule })
    }

    pub fn with_built_in_rules() -> Self {
        let rules = BUILT_IN_RULES
            .iter()
            .map(|(name, pattern, replacement)| RedactionRule {
                name: (*name).to_string(),
                // Built-in patterns are covered by tests, so a failure here is a programming error.
                pattern: Regex::new(pattern)
                    .unwrap_or_else(|error| panic!("built-in rule {name}: {error}")),
                replacement: (*replacement).to_string(),
            })
            .collect();
        // The built-in set is small and covered by tests, so failing here is a programming error.
        Self::from_rules(rules).unwrap_or_else(|error| panic!("{error}"))
    }

    /// Appends custom rules, failing on the first invalid pattern.
    pub fn with_custom_rules(
        self,
        specs: &[RedactionRuleSpec],
    ) -> Result<Self, RedactionRuleError> {
        let mut rules = self.rules;
        for spec in specs {
            let pattern = Regex::new(&spec.pattern).map_err(|error| RedactionRuleError {
                name: spec.name.clone(),
                reason: error.to_string(),
            })?;
            rules.push(RedactionRule {
                name: spec.name.clone(),
                pattern,
                replacement: spec.replacement.clone(),
            });
        }
        Self::from_rules(rules)
    }

    pub fn rule_names(&self) -> Vec<String> {
        self.rules.iter().map(|rule| rule.name.clone()).collect()
    }

    pub fn is_enabled(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Redacts the message, raw payload and string attributes of an event.
    /// Returns how many replacements were made.
    pub fn apply(&self, event: &mut Event) -> usize {
        let mut replacements = self.redact_in_place(&mut event.message);
        if let Some(raw) = event.raw.as_mut() {
            replacements += self.redact_in_place(raw);
        }
        for value in event.attributes.values_mut() {
            if let Value::String(text) = value {
                replacements += self.redact_in_place(text);
            }
        }
        replacements
    }

    fn redact_in_place(&self, text: &mut String) -> usize {
        let (redacted, replacements) = self.redact(text);
        let changed = match redacted {
            Cow::Owned(changed) => Some(changed),
            Cow::Borrowed(_) => None,
        };
        if let Some(changed) = changed {
            *text = changed;
        }
        replacements
    }

    /// Returns the redacted text (borrowed when nothing matched) and the number of replacements.
    pub fn redact<'t>(&self, text: &'t str) -> (Cow<'t, str>, usize) {
        let applicable = self.any_rule.matches(text);
        let mut current = Cow::Borrowed(text);
        let mut replacements = 0;
        for index in applicable.iter() {
            let rule = &self.rules[index];
            let replaced = rule
                .pattern
                .replace_all(&current, |captures: &Captures<'_>| {
                    replacements += 1;
                    let mut expanded = String::new();
                    captures.expand(&rule.replacement, &mut expanded);
                    expanded
                });
            let changed = match replaced {
                Cow::Owned(changed) => Some(changed),
                Cow::Borrowed(_) => None,
            };
            if let Some(changed) = changed {
                current = Cow::Owned(changed);
            }
        }
        (current, replacements)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact(text: &str) -> String {
        Redactor::with_built_in_rules().redact(text).0.into_owned()
    }

    #[test]
    fn redacts_bearer_tokens_but_keeps_the_scheme() {
        assert_eq!(
            redact("Authorization: Bearer abcDEF123456.xyz"),
            "Authorization: Bearer [REDACTED]"
        );
    }

    #[test]
    fn redacts_secret_assignments_in_several_syntaxes() {
        assert_eq!(redact("password=hunter22 ok"), "password=[REDACTED] ok");
        assert_eq!(
            redact(r#"{"api_key": "k-123"}"#),
            r#"{"api_key": "[REDACTED]"}"#
        );
    }

    #[test]
    fn redacts_jwts_emails_and_url_tokens() {
        let jwt = "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl";
        assert_eq!(redact(&format!("token {jwt}")), "token [REDACTED-JWT]");
        assert_eq!(
            redact("user ana@example.com logged in"),
            "user [REDACTED-EMAIL] logged in"
        );
        assert_eq!(
            redact("GET /cb?code=1&access_token=abc123"),
            "GET /cb?code=1&access_token=[REDACTED]"
        );
    }

    #[test]
    fn leaves_ordinary_diagnostic_text_untouched() {
        let text = "Displayed com.example/.MainActivity: +412ms";
        let (redacted, replacements) = Redactor::with_built_in_rules().redact(text);
        assert_eq!(replacements, 0);
        assert!(
            matches!(redacted, Cow::Borrowed(_)),
            "clean text must not be copied"
        );
    }

    #[test]
    fn a_rule_set_beyond_the_size_limit_is_an_error_not_a_panic() {
        let huge = RedactionRuleSpec {
            name: "huge".into(),
            pattern: r"\w{1000}".into(),
            replacement: "x".into(),
        };
        let specs = vec![huge; 50];
        assert!(
            Redactor::with_built_in_rules()
                .with_custom_rules(&specs)
                .is_err()
        );
    }

    #[test]
    fn rejects_invalid_custom_patterns() {
        let spec = RedactionRuleSpec {
            name: "broken".into(),
            pattern: "(".into(),
            replacement: "x".into(),
        };
        let error = Redactor::with_built_in_rules()
            .with_custom_rules(&[spec])
            .expect_err("invalid pattern must fail");
        assert_eq!(error.name, "broken");
    }

    #[test]
    fn applies_custom_rules_after_built_in_ones() {
        let spec = RedactionRuleSpec {
            name: "customer".into(),
            pattern: r"CUST-\d+".into(),
            replacement: "[CUSTOMER]".into(),
        };
        let redactor = Redactor::with_built_in_rules()
            .with_custom_rules(&[spec])
            .expect("valid rule");
        assert_eq!(
            redactor.redact("order for CUST-991").0,
            "order for [CUSTOMER]"
        );
    }
}
