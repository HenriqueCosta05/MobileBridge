//! Structured event filtering (EVT-007, MON-013, DIA-006) and retention policy for recordings (APP-009).

use serde::{Deserialize, Serialize};

use crate::event::{Domain, Event, Severity};

/// Conjunction of criteria; an empty criterion matches everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFilter {
    pub apps: Vec<String>,
    pub pids: Vec<u32>,
    /// Matched case-insensitively against the event subsystem (for example a logcat tag).
    pub subsystems: Vec<String>,
    pub domains: Vec<Domain>,
    pub kinds: Vec<String>,
    pub min_severity: Option<Severity>,
    /// Case-insensitive substring of the message.
    pub text: Option<String>,
}

impl EventFilter {
    pub fn matches(&self, event: &Event) -> bool {
        matches_any(&self.apps, event.app.as_ref())
            && matches_any(&self.pids, event.pid.as_ref())
            && self.matches_subsystem(event)
            && matches_any(&self.domains, Some(&event.domain))
            && matches_any(&self.kinds, Some(&event.kind))
            && self
                .min_severity
                .is_none_or(|minimum| event.severity >= minimum)
            && self.matches_text(event)
    }

    fn matches_subsystem(&self, event: &Event) -> bool {
        self.subsystems.is_empty()
            || event.subsystem.as_deref().is_some_and(|subsystem| {
                self.subsystems
                    .iter()
                    .any(|wanted| wanted.eq_ignore_ascii_case(subsystem))
            })
    }

    fn matches_text(&self, event: &Event) -> bool {
        self.text.as_deref().is_none_or(|needle| {
            event
                .message
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
        })
    }
}

fn matches_any<T: PartialEq>(wanted: &[T], actual: Option<&T>) -> bool {
    wanted.is_empty() || actual.is_some_and(|value| wanted.contains(value))
}

/// Which events a recording keeps on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode", content = "apps")]
pub enum Retention {
    /// Keep everything the collectors produce.
    All,
    /// Keep events attributed to the target apps, plus non-log events not attributed to any app
    /// (collector status, markers, traces, device-wide state). Log lines of unrelated processes and
    /// other apps' lifecycle events are dropped to limit collection of other apps' data (SEC-005).
    TargetApps(Vec<String>),
}

impl Retention {
    /// Decides from the domain and app alone, so dropped observations are never turned into events.
    pub fn retains(&self, domain: Domain, app: Option<&str>) -> bool {
        match self {
            Self::All => true,
            Self::TargetApps(apps) => {
                (domain != Domain::Log && app.is_none())
                    || app.is_some_and(|app| apps.iter().any(|wanted| wanted == app))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::test_support::event_at;
    use crate::event::{Observation, kinds};

    fn log(app: Option<&str>, tag: &str, severity: Severity, message: &str) -> Event {
        let mut observation = Observation::new(Domain::Log, kinds::LOG, message)
            .with_subsystem(tag)
            .with_severity(severity)
            .with_pid(10);
        observation.app = app.map(str::to_string);
        event_at(1, 0, observation)
    }

    #[test]
    fn empty_filter_matches_everything() {
        assert!(EventFilter::default().matches(&log(None, "Tag", Severity::Debug, "x")));
    }

    #[test]
    fn criteria_are_combined_with_and() {
        let filter = EventFilter {
            apps: vec!["com.example".into()],
            min_severity: Some(Severity::Warning),
            ..EventFilter::default()
        };
        assert!(filter.matches(&log(Some("com.example"), "Tag", Severity::Error, "boom")));
        assert!(!filter.matches(&log(Some("com.example"), "Tag", Severity::Info, "fine")));
        assert!(!filter.matches(&log(Some("com.other"), "Tag", Severity::Error, "boom")));
    }

    #[test]
    fn subsystem_and_text_match_case_insensitively() {
        let filter = EventFilter {
            subsystems: vec!["activitymanager".into()],
            text: Some("START".into()),
            ..EventFilter::default()
        };
        assert!(filter.matches(&log(None, "ActivityManager", Severity::Info, "Start proc")));
        assert!(!filter.matches(&log(None, "ActivityManager", Severity::Info, "Killing")));
    }

    #[test]
    fn target_app_retention_keeps_target_and_unattributed_events_only() {
        let retention = Retention::TargetApps(vec!["com.example".into()]);
        assert!(retention.retains(Domain::Log, Some("com.example")));
        assert!(!retention.retains(Domain::Log, Some("com.other")));
        assert!(!retention.retains(Domain::Log, None));
        assert!(retention.retains(Domain::Marker, None));
        assert!(retention.retains(Domain::Lifecycle, Some("com.example")));
        assert!(!retention.retains(Domain::Lifecycle, Some("com.other")));
    }
}
