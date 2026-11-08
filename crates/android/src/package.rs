//! Validated Android application identifiers.

use std::fmt;
use std::str::FromStr;

/// An Android package name such as `com.example.app`.
///
/// Validation follows the Android rules (dot-separated segments of letters, digits and underscores, each
/// starting with a letter, at least two segments). It also guarantees the value is safe to embed in an
/// `adb shell` command line.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageName(String);

impl PackageName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The application a process belongs to: `com.example:remote` belongs to `com.example`.
    pub fn owning_app_of(process_name: &str) -> &str {
        process_name.split(':').next().unwrap_or(process_name)
    }
}

impl FromStr for PackageName {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let segments: Vec<&str> = text.split('.').collect();
        let valid_segment = |segment: &&str| {
            let mut chars = segment.chars();
            chars
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        };
        if text.len() <= 255 && segments.len() >= 2 && segments.iter().all(valid_segment) {
            Ok(Self(text.to_string()))
        } else {
            Err(format!(
                "'{text}' is not a valid Android package name (expected something like com.example.app)"
            ))
        }
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_regular_package_names() {
        assert!("com.example.app".parse::<PackageName>().is_ok());
        assert!("org.mozilla.firefox_beta".parse::<PackageName>().is_ok());
    }

    #[test]
    fn rejects_names_that_could_inject_shell_syntax() {
        for bad in [
            "com.example; reboot",
            "com.example $(id)",
            "single",
            "com..x",
            "1com.x",
            "com.x/y",
        ] {
            assert!(
                bad.parse::<PackageName>().is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn secondary_processes_belong_to_their_package() {
        assert_eq!(
            PackageName::owning_app_of("com.example:remote"),
            "com.example"
        );
        assert_eq!(PackageName::owning_app_of("com.example"), "com.example");
    }
}
