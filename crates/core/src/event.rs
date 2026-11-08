//! Normalized event model shared by every platform adapter (EVT-002 to EVT-006).
//!
//! Collectors produce [`Observation`]s; the recording pipeline stamps them with session identity,
//! ordering and host timing to produce [`Event`]s. Serialization is deterministic: struct fields keep
//! their declared order and attributes use a sorted map (NFR-006).

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Version of the serialized event schema. Bump on any incompatible change.
pub const EVENT_SCHEMA_VERSION: u32 = 1;

/// Normalized event kinds. Adapters map platform-specific records onto these names.
pub mod kinds {
    pub const LOG: &str = "log";
    pub const PROCESS_RUNNING: &str = "process_running";
    pub const PROCESS_STARTED: &str = "process_started";
    pub const PROCESS_DIED: &str = "process_died";
    pub const APP_FOREGROUND: &str = "app_foreground";
    pub const APP_BACKGROUND: &str = "app_background";
    pub const APP_CRASH: &str = "app_crash";
    pub const NATIVE_CRASH: &str = "native_crash";
    pub const ANR: &str = "anr";
    pub const PERMISSION_STATE: &str = "permission_state";
    pub const PERMISSION_CHANGED: &str = "permission_changed";
    pub const RESOURCE_SAMPLE: &str = "resource_sample";
    pub const MARKER: &str = "marker";
    pub const ARTIFACT_CAPTURED: &str = "artifact_captured";
    pub const COLLECTOR_STARTED: &str = "collector_started";
    pub const COLLECTOR_FINISHED: &str = "collector_finished";
    pub const COLLECTOR_FAILED: &str = "collector_failed";
    pub const COLLECTION_GAP: &str = "collection_gap";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Verbose,
    Debug,
    Info,
    Warning,
    Error,
    Fatal,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verbose => "verbose",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }

    /// Single-letter form used in compact terminal output.
    pub fn letter(self) -> char {
        match self {
            Self::Verbose => 'V',
            Self::Debug => 'D',
            Self::Info => 'I',
            Self::Warning => 'W',
            Self::Error => 'E',
            Self::Fatal => 'F',
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.to_ascii_lowercase().as_str() {
            "v" | "verbose" => Ok(Self::Verbose),
            "d" | "debug" => Ok(Self::Debug),
            "i" | "info" => Ok(Self::Info),
            "w" | "warn" | "warning" => Ok(Self::Warning),
            "e" | "error" => Ok(Self::Error),
            "f" | "fatal" => Ok(Self::Fatal),
            _ => Err(format!(
                "unknown severity '{text}' (expected verbose, debug, info, warning, error or fatal)"
            )),
        }
    }
}

/// Broad area of OS behavior an event belongs to. Used for filtering (MON-013, DIA-006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    Log,
    Lifecycle,
    Process,
    Resource,
    Permission,
    Trace,
    System,
    Marker,
    Collector,
}

impl Domain {
    pub const ALL: [Domain; 9] = [
        Self::Log,
        Self::Lifecycle,
        Self::Process,
        Self::Resource,
        Self::Permission,
        Self::Trace,
        Self::System,
        Self::Marker,
        Self::Collector,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Lifecycle => "lifecycle",
            Self::Process => "process",
            Self::Resource => "resource",
            Self::Permission => "permission",
            Self::Trace => "trace",
            Self::System => "system",
            Self::Marker => "marker",
            Self::Collector => "collector",
        }
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Domain {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|domain| domain.as_str().eq_ignore_ascii_case(text))
            .ok_or_else(|| {
                let names: Vec<&str> = Self::ALL.iter().map(|d| d.as_str()).collect();
                format!(
                    "unknown domain '{text}' (expected one of: {})",
                    names.join(", ")
                )
            })
    }
}

/// What a collector saw, before the pipeline assigns session identity and ordering.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub domain: Domain,
    pub kind: String,
    pub severity: Severity,
    /// Timestamp reported by the device-side source, when it provides one.
    pub device_time: Option<DateTime<Utc>>,
    /// Sub-stream within the provider, for example a logcat buffer name.
    pub stream: Option<String>,
    pub app: Option<String>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub subsystem: Option<String>,
    pub message: String,
    pub attributes: BTreeMap<String, Value>,
    /// Original source record, preserved verbatim (EVT-003).
    pub raw: Option<String>,
}

impl Observation {
    pub fn new(domain: Domain, kind: &str, message: impl Into<String>) -> Self {
        Self {
            domain,
            kind: kind.to_string(),
            severity: Severity::Info,
            device_time: None,
            stream: None,
            app: None,
            pid: None,
            tid: None,
            subsystem: None,
            message: message.into(),
            attributes: BTreeMap::new(),
            raw: None,
        }
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_device_time(mut self, time: DateTime<Utc>) -> Self {
        self.device_time = Some(time);
        self
    }

    pub fn with_tid(mut self, tid: u32) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Reclassifies an observation, for example a log line recognized as a crash report.
    pub fn retyped(mut self, domain: Domain, kind: &str) -> Self {
        self.domain = domain;
        self.kind = kind.to_string();
        self
    }

    pub fn with_stream(mut self, stream: impl Into<String>) -> Self {
        self.stream = Some(stream.into());
        self
    }

    pub fn with_app(mut self, app: impl Into<String>) -> Self {
        self.app = Some(app.into());
        self
    }

    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn with_subsystem(mut self, subsystem: impl Into<String>) -> Self {
        self.subsystem = Some(subsystem.into());
        self
    }

    pub fn with_attribute(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.attributes.insert(key.to_string(), value.into());
        self
    }

    pub fn with_raw(mut self, raw: impl Into<String>) -> Self {
        self.raw = Some(raw.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSource {
    /// Identifier of the provider that produced the event.
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventTime {
    /// Time reported by the device source. Device and host clocks may differ.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DateTime<Utc>>,
    /// Host wall-clock time when the pipeline received the event.
    pub host: DateTime<Utc>,
    /// Host monotonic nanoseconds since the session started; never goes backwards (EVT-004).
    pub monotonic_ns: u64,
}

impl EventTime {
    /// Best available wall-clock time: the device time when known, the host time otherwise.
    pub fn best(&self) -> DateTime<Utc> {
        self.device.unwrap_or(self.host)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub schema_version: u32,
    pub session_id: String,
    /// Position of the event in the session, assigned in arrival order (EVT-006).
    pub sequence: u64,
    pub device_id: String,
    pub domain: Domain,
    pub kind: String,
    pub severity: Severity,
    pub time: EventTime,
    pub source: EventSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// Session-level identity the pipeline attaches to every observation (EVT-005).
#[derive(Debug, Clone)]
pub struct EventStamp<'a> {
    pub session_id: &'a str,
    pub device_id: &'a str,
    pub provider: &'a str,
    pub sequence: u64,
    pub host_time: DateTime<Utc>,
    pub monotonic_ns: u64,
}

impl Event {
    pub fn from_observation(observation: Observation, stamp: EventStamp<'_>) -> Self {
        Self {
            schema_version: EVENT_SCHEMA_VERSION,
            session_id: stamp.session_id.to_string(),
            sequence: stamp.sequence,
            device_id: stamp.device_id.to_string(),
            domain: observation.domain,
            kind: observation.kind,
            severity: observation.severity,
            time: EventTime {
                device: observation.device_time,
                host: stamp.host_time,
                monotonic_ns: stamp.monotonic_ns,
            },
            source: EventSource {
                provider: stamp.provider.to_string(),
                stream: observation.stream,
            },
            app: observation.app,
            pid: observation.pid,
            tid: observation.tid,
            subsystem: observation.subsystem,
            message: observation.message,
            attributes: observation.attributes,
            raw: observation.raw,
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use chrono::TimeZone;

    /// Builds an event at `second` seconds after a fixed epoch, for deterministic tests.
    pub fn event_at(sequence: u64, second: i64, observation: Observation) -> Event {
        let time = Utc
            .timestamp_opt(1_700_000_000 + second, 0)
            .single()
            .expect("valid time");
        Event::from_observation(
            observation.with_device_time(time),
            EventStamp {
                session_id: "s1",
                device_id: "dev1",
                provider: "test",
                sequence,
                host_time: time,
                monotonic_ns: u64::try_from(second).unwrap_or(0) * 1_000_000_000,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::event_at;
    use super::*;

    fn sample_event() -> Event {
        event_at(
            7,
            3,
            Observation::new(Domain::Log, kinds::LOG, "hello")
                .with_severity(Severity::Warning)
                .with_app("com.example")
                .with_pid(42)
                .with_attribute("zeta", 1)
                .with_attribute("alpha", "a")
                .with_raw("raw line"),
        )
    }

    #[test]
    fn serialization_round_trips_and_preserves_raw_payload() {
        let event = sample_event();
        let json = serde_json::to_string(&event).expect("serialize");
        let parsed: Event = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, event);
        assert_eq!(parsed.raw.as_deref(), Some("raw line"));
    }

    #[test]
    fn serialization_is_deterministic_with_sorted_attributes() {
        let json = serde_json::to_string(&sample_event()).expect("serialize");
        assert_eq!(
            json,
            serde_json::to_string(&sample_event()).expect("serialize")
        );
        let alpha = json.find("\"alpha\"").expect("alpha present");
        let zeta = json.find("\"zeta\"").expect("zeta present");
        assert!(alpha < zeta);
    }

    #[test]
    fn severity_parses_letters_and_names() {
        assert_eq!("W".parse::<Severity>(), Ok(Severity::Warning));
        assert_eq!("fatal".parse::<Severity>(), Ok(Severity::Fatal));
        assert!("loud".parse::<Severity>().is_err());
    }

    #[test]
    fn domain_parse_rejects_unknown_names_with_the_valid_list() {
        let error = "kernel".parse::<Domain>().expect_err("unknown domain");
        assert!(error.contains("lifecycle"));
    }
}
