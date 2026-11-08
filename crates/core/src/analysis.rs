//! Timeline reconstruction and evidence-linked findings (DIA-001, DIA-003, DIA-005, DIA-006, DIA-010).
//!
//! Every finding names the events that support it and labels its basis. A failure the OS reported is an
//! observation; events that happened shortly before it are only correlated in time, never presented as
//! its cause.

use std::fmt;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::event::{Event, Severity, kinds};
use crate::filter::EventFilter;
use crate::session::{CollectorStatus, SessionManifest, SessionStatus, StoredEvents};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    /// Directly reported by a source.
    Observation,
    /// Computed from observations (for example a missing manifest finalization).
    Derivation,
    /// Related by time or identity only; not proof of causation.
    Correlation,
}

impl fmt::Display for Basis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Observation => "observation",
            Self::Derivation => "derivation",
            Self::Correlation => "correlation",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    AppCrash,
    NativeCrash,
    Anr,
    CollectionGap,
    InterruptedRecording,
}

impl fmt::Display for FindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AppCrash => "app crash",
            Self::NativeCrash => "native crash",
            Self::Anr => "ANR",
            Self::CollectionGap => "collection gap",
            Self::InterruptedRecording => "interrupted recording",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub basis: Basis,
    pub severity: Severity,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// Sequences of the events that directly support the finding.
    pub evidence: Vec<u64>,
    /// Sequences of events shortly before a failure; correlated in time only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preceding: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisOptions {
    /// How far back to look for events that preceded a failure.
    pub preceding_window: TimeDelta,
    /// Maximum number of preceding events attached to a failure.
    pub preceding_limit: usize,
    /// Failure reports of the same kind and app closer than this are one failure
    /// (Android, for example, reports a crash both in the crash log and in the event log).
    pub duplicate_window: TimeDelta,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            preceding_window: TimeDelta::seconds(10),
            preceding_limit: 20,
            duplicate_window: TimeDelta::seconds(3),
        }
    }
}

/// Events in chronological order, optionally filtered (DIA-001, DIA-006).
/// Orders by best-known time, then by arrival sequence, so ties keep the order they were collected in.
pub fn timeline<'e>(events: &'e [Event], filter: &EventFilter) -> Vec<&'e Event> {
    let mut ordered: Vec<&Event> = events
        .iter()
        .filter(|event| filter.matches(event))
        .collect();
    ordered.sort_by(|a, b| {
        a.time
            .best()
            .cmp(&b.time.best())
            .then(a.sequence.cmp(&b.sequence))
    });
    ordered
}

pub fn analyze(
    manifest: &SessionManifest,
    stored: &StoredEvents,
    options: &AnalysisOptions,
) -> Vec<Finding> {
    let ordered = timeline(&stored.events, &EventFilter::default());
    let mut findings = failure_findings(&ordered, options);
    findings.extend(collector_gap_findings(&ordered));
    findings.extend(aborted_collector_findings(manifest));
    findings.extend(interruption_finding(manifest, stored));
    findings
}

fn failure_findings(ordered: &[&Event], options: &AnalysisOptions) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    for (index, event) in ordered.iter().enumerate() {
        let Some((kind, verb)) = failure_kind(event) else {
            continue;
        };
        if let Some(existing) = findings
            .iter_mut()
            .find(|finding| is_same_failure(finding, kind, event, options))
        {
            existing.evidence.push(event.sequence);
            continue;
        }
        findings.push(Finding {
            kind,
            basis: Basis::Observation,
            severity: Severity::Fatal,
            summary: failure_summary(verb, event),
            time: Some(event.time.best()),
            app: event.app.clone(),
            evidence: vec![event.sequence],
            preceding: preceding_events(&ordered[..index], event, options),
        });
    }
    findings
}

/// The finding kind of a failure event, with the verb that describes it.
fn failure_kind(event: &Event) -> Option<(FindingKind, &'static str)> {
    match event.kind.as_str() {
        kinds::APP_CRASH => Some((FindingKind::AppCrash, "crashed")),
        kinds::NATIVE_CRASH => Some((FindingKind::NativeCrash, "crashed in native code")),
        kinds::ANR => Some((FindingKind::Anr, "stopped responding (ANR)")),
        _ => None,
    }
}

fn is_same_failure(
    finding: &Finding,
    kind: FindingKind,
    event: &Event,
    options: &AnalysisOptions,
) -> bool {
    finding.kind == kind
        && finding.app == event.app
        && finding
            .time
            .is_some_and(|time| event.time.best() - time <= options.duplicate_window)
}

fn failure_summary(verb: &str, event: &Event) -> String {
    let subject = event.app.as_deref().unwrap_or("an application");
    format!("{subject} {verb}: {}", event.message)
}

/// Most recent related events inside the window before a failure (DIA-003).
fn preceding_events(earlier: &[&Event], failure: &Event, options: &AnalysisOptions) -> Vec<u64> {
    let window_start = failure.time.best() - options.preceding_window;
    let mut related: Vec<u64> = earlier
        .iter()
        .rev()
        .filter(|event| event.time.best() >= window_start)
        .filter(|event| is_related_to(event, failure))
        .take(options.preceding_limit)
        .map(|event| event.sequence)
        .collect();
    related.reverse();
    related
}

fn is_related_to(event: &Event, failure: &Event) -> bool {
    let same_app = event.app.is_some() && event.app == failure.app;
    let same_pid = event.pid.is_some() && event.pid == failure.pid;
    let notable = event.severity >= Severity::Warning || event.kind == kinds::MARKER;
    same_app || same_pid || notable
}

fn collector_gap_findings(ordered: &[&Event]) -> Vec<Finding> {
    ordered
        .iter()
        .filter(|event| event.kind == kinds::COLLECTOR_FAILED)
        .map(|event| Finding {
            kind: FindingKind::CollectionGap,
            basis: Basis::Observation,
            severity: Severity::Warning,
            summary: format!(
                "{}; evidence from this source is missing from this point on",
                event.message
            ),
            time: Some(event.time.best()),
            app: None,
            evidence: vec![event.sequence],
            preceding: Vec::new(),
        })
        .collect()
}

/// Aborted collectors have no failure event, because they were cancelled; the manifest records them.
fn aborted_collector_findings(manifest: &SessionManifest) -> Vec<Finding> {
    manifest
        .collectors
        .iter()
        .filter(|collector| collector.status == CollectorStatus::Aborted)
        .map(|collector| Finding {
            kind: FindingKind::CollectionGap,
            basis: Basis::Observation,
            severity: Severity::Warning,
            summary: format!(
                "collector {} was cancelled during shutdown; its final evidence may be incomplete",
                collector.provider
            ),
            time: manifest.ended_at,
            app: None,
            evidence: Vec::new(),
            preceding: Vec::new(),
        })
        .collect()
}

fn interruption_finding(manifest: &SessionManifest, stored: &StoredEvents) -> Option<Finding> {
    if manifest.status != SessionStatus::Recording {
        return None;
    }
    let mut summary = String::from(
        "the session was never finalized: the recording is still running or was interrupted, \
         so collector results and artifacts may be missing",
    );
    if !stored.unreadable_lines.is_empty() {
        summary.push_str(&format!(
            "; {} unreadable event line(s) were skipped",
            stored.unreadable_lines.len()
        ));
    }
    Some(Finding {
        kind: FindingKind::InterruptedRecording,
        basis: Basis::Derivation,
        severity: Severity::Warning,
        summary,
        time: stored.events.last().map(|event| event.time.best()),
        app: None,
        evidence: Vec::new(),
        preceding: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::test_support::event_at;
    use crate::event::{Domain, Observation};
    use crate::session::test_support::manifest;

    fn completed_manifest() -> SessionManifest {
        let mut manifest = manifest("s1", 0);
        manifest.status = SessionStatus::Completed;
        manifest
    }

    fn log(sequence: u64, second: i64, app: &str, severity: Severity, message: &str) -> Event {
        event_at(
            sequence,
            second,
            Observation::new(Domain::Log, kinds::LOG, message)
                .with_app(app)
                .with_severity(severity),
        )
    }

    fn crash(sequence: u64, second: i64, app: &str) -> Event {
        event_at(
            sequence,
            second,
            Observation::new(
                Domain::Lifecycle,
                kinds::APP_CRASH,
                "java.lang.IllegalStateException",
            )
            .with_app(app)
            .with_severity(Severity::Fatal),
        )
    }

    fn analyze_events(events: Vec<Event>) -> Vec<Finding> {
        let stored = StoredEvents {
            events,
            unreadable_lines: Vec::new(),
        };
        analyze(&completed_manifest(), &stored, &AnalysisOptions::default())
    }

    #[test]
    fn ordinary_logs_produce_no_findings() {
        let events = vec![
            log(0, 0, "com.example", Severity::Info, "started"),
            log(1, 1, "com.example", Severity::Warning, "slow response"),
        ];
        assert!(analyze_events(events).is_empty());
    }

    #[test]
    fn a_crash_is_an_observation_linked_to_its_evidence() {
        let findings = analyze_events(vec![crash(5, 0, "com.example")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::AppCrash);
        assert_eq!(findings[0].basis, Basis::Observation);
        assert_eq!(findings[0].evidence, vec![5]);
    }

    #[test]
    fn duplicate_reports_of_one_crash_are_merged() {
        let findings = analyze_events(vec![crash(1, 0, "com.example"), crash(2, 1, "com.example")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, vec![1, 2]);
    }

    #[test]
    fn distant_crashes_are_separate_findings() {
        let findings = analyze_events(vec![
            crash(1, 0, "com.example"),
            crash(2, 60, "com.example"),
        ]);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn related_events_inside_the_window_precede_the_failure() {
        let events = vec![
            log(0, 0, "com.example", Severity::Info, "too early"),
            log(1, 25, "com.other", Severity::Info, "unrelated and quiet"),
            log(2, 26, "com.example", Severity::Info, "loading profile"),
            log(3, 27, "com.other", Severity::Error, "system error"),
            crash(4, 30, "com.example"),
        ];
        let findings = analyze_events(events);
        assert_eq!(findings[0].preceding, vec![2, 3]);
    }

    #[test]
    fn timeline_orders_by_time_then_sequence() {
        let events = vec![
            log(0, 5, "a", Severity::Info, "late"),
            log(1, 1, "a", Severity::Info, "early"),
            log(2, 1, "a", Severity::Info, "early, collected later"),
        ];
        let ordered: Vec<u64> = timeline(&events, &EventFilter::default())
            .iter()
            .map(|event| event.sequence)
            .collect();
        assert_eq!(ordered, vec![1, 2, 0]);
    }

    #[test]
    fn collector_failures_become_collection_gaps() {
        let failed = event_at(
            3,
            0,
            Observation::new(
                Domain::Collector,
                kinds::COLLECTOR_FAILED,
                "collector logcat stopped",
            ),
        );
        let findings = analyze_events(vec![failed]);
        assert_eq!(findings[0].kind, FindingKind::CollectionGap);
        assert_eq!(findings[0].evidence, vec![3]);
    }

    #[test]
    fn an_unfinalized_session_is_reported_as_interrupted() {
        let stored = StoredEvents {
            events: Vec::new(),
            unreadable_lines: vec![12],
        };
        let findings = analyze(&manifest("s1", 0), &stored, &AnalysisOptions::default());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::InterruptedRecording);
        assert_eq!(findings[0].basis, Basis::Derivation);
        assert!(findings[0].summary.contains("1 unreadable"));
    }
}
