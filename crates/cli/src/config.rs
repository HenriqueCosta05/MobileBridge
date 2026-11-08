//! Optional TOML configuration file (CLI-006, SEC-003).
//!
//! Unknown keys and invalid values are errors rather than warnings: a mistyped redaction rule must not
//! silently turn redaction off.

use std::path::{Path, PathBuf};
use std::time::Duration;

use mobile_bridge_android::providers::perfetto::{TraceOptions, validate_category};
use mobile_bridge_core::redact::{RedactionRuleSpec, Redactor};
use serde::{Deserialize, Deserializer};

use crate::cli::parse_duration;
use crate::error::CliError;

const CONFIG_FILE: &str = "config.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub record: RecordConfig,
    #[serde(default)]
    pub trace: TraceConfig,
    #[serde(default)]
    pub redaction: RedactionConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordConfig {
    pub collectors: Option<Vec<String>>,
    #[serde(default, deserialize_with = "optional_duration")]
    pub duration: Option<Duration>,
    #[serde(default, deserialize_with = "optional_duration")]
    pub sample_interval: Option<Duration>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceConfig {
    #[serde(default, deserialize_with = "optional_duration")]
    pub max_duration: Option<Duration>,
    pub buffer_mb: Option<u32>,
    pub categories: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionConfig {
    /// Apply the built-in rules for tokens, credentials and e-mail addresses.
    #[serde(default = "enabled")]
    pub built_in: bool,
    #[serde(default)]
    pub rules: Vec<RedactionRuleSpec>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            built_in: true,
            rules: Vec::new(),
        }
    }
}

fn enabled() -> bool {
    true
}

/// Reads durations written like the command line accepts them (`30s`, `5m`, ...).
fn optional_duration<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Duration>, D::Error> {
    let text = String::deserialize(deserializer)?;
    parse_duration(&text)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

fn invalid(error: impl std::fmt::Display) -> CliError {
    CliError::failure(format!("invalid configuration: {error}"))
}

impl Config {
    /// Loads an explicitly given file (which must exist) or the default file (which may be absent).
    pub fn load(explicit: Option<&Path>) -> Result<(Self, Option<PathBuf>), CliError> {
        let path = match explicit {
            Some(path) => path.to_path_buf(),
            None => match default_path().filter(|path| path.is_file()) {
                Some(path) => path,
                None => return Ok((Self::default(), None)),
            },
        };
        let text = std::fs::read_to_string(&path).map_err(|error| {
            CliError::failure(format!(
                "cannot read configuration {}: {error}",
                path.display()
            ))
        })?;
        let config: Self = toml::from_str(&text).map_err(|error| {
            CliError::failure(format!("invalid configuration {}: {error}", path.display()))
        })?;
        config.validate()?;
        Ok((config, Some(path)))
    }

    fn validate(&self) -> Result<(), CliError> {
        for category in self.trace.categories.iter().flatten() {
            validate_category(category).map_err(invalid)?;
        }
        self.redactor().map(|_| ())
    }

    pub fn redactor(&self) -> Result<Redactor, CliError> {
        let base = if self.redaction.built_in {
            Redactor::with_built_in_rules()
        } else {
            Redactor::disabled()
        };
        base.with_custom_rules(&self.redaction.rules)
            .map_err(invalid)
    }

    pub fn trace_options(&self) -> TraceOptions {
        let defaults = TraceOptions::default();
        TraceOptions {
            max_duration: self.trace.max_duration.unwrap_or(defaults.max_duration),
            buffer_mb: self.trace.buffer_mb.unwrap_or(defaults.buffer_mb),
            categories: self.trace.categories.clone().unwrap_or(defaults.categories),
        }
    }
}

pub fn default_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("mobile-bridge").join(CONFIG_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, CliError> {
        let config: Config =
            toml::from_str(text).map_err(|error| CliError::failure(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn an_empty_file_uses_safe_defaults() {
        let config = parse("").expect("valid");
        assert!(config.redaction.built_in);
        assert!(config.redactor().expect("redactor").is_enabled());
    }

    #[test]
    fn custom_rules_and_record_settings_are_read() {
        let config = parse(
            r#"
            [record]
            duration = "2m"
            [[redaction.rules]]
            name = "customer"
            pattern = 'CUST-\d+'
            "#,
        )
        .expect("valid");
        assert_eq!(config.record.duration, Some(Duration::from_secs(120)));
        assert!(
            config
                .redactor()
                .expect("redactor")
                .rule_names()
                .contains(&"customer".to_string())
        );
    }

    #[test]
    fn unknown_keys_and_invalid_patterns_are_rejected() {
        assert!(parse("[redaction]\nbuiltin = false\n").is_err());
        assert!(parse("[[redaction.rules]]\nname = \"x\"\npattern = \"(\"\n").is_err());
        assert!(parse("[trace]\ncategories = [\"sched;reboot\"]\n").is_err());
        assert!(parse("[record]\nduration = \"forever\"\n").is_err());
    }
}
