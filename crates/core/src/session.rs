//! Local persistence of diagnostic sessions (SES-006, SES-008, SES-010, NFR-005, SEC-001, SEC-007, SEC-008).
//!
//! Layout of one session directory:
//!
//! ```text
//! <root>/<session-id>/
//!   session.json   manifest, replaced atomically (write to a temporary file, then rename)
//!   events.jsonl   one event per line, appended and flushed whenever the event queue drains
//!   artifacts/     raw evidence saved by providers (traces, service dumps)
//! ```
//!
//! An interrupted recording leaves a manifest in the `recording` state and, at worst, a truncated last
//! line in `events.jsonl`; [`SessionStore::read_events`] tolerates and reports that line.

use std::fmt;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::device::{Capability, DeviceMetadata};
use crate::event::{Domain, Event};
use crate::filter::Retention;
use crate::pipeline::RecordingSummary;
use crate::private_fs;
use crate::provider::ArtifactRef;

pub const MANIFEST_FILE: &str = "session.json";
pub const EVENTS_FILE: &str = "events.jsonl";
pub const ARTIFACTS_DIR: &str = "artifacts";
pub const MANIFEST_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session '{0}' was not found")]
    NotFound(String),
    #[error("session id '{prefix}' is ambiguous; it matches: {}", matches.join(", "))]
    Ambiguous {
        prefix: String,
        matches: Vec<String>,
    },
    #[error("there are no recorded sessions")]
    Empty,
    #[error("'{0}' is not a valid session id")]
    InvalidId(String),
    #[error("a session with id '{0}' already exists")]
    AlreadyExists(String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: malformed JSON: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

fn io_error(path: &Path) -> impl FnOnce(std::io::Error) -> SessionError + '_ {
    move |source| SessionError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Still recording, or the recording process was interrupted before finalizing.
    Recording,
    Completed,
    /// Completed, but at least one collector failed.
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    DurationElapsed,
    UserRequested,
    CollectorsFinished,
    /// Writing events failed (for example, the disk is full).
    PersistenceFailed,
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DurationElapsed => "duration elapsed",
            Self::UserRequested => "stopped by the user",
            Self::CollectorsFinished => "all collectors finished",
            Self::PersistenceFailed => "writing events failed",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorStatus {
    Completed,
    Failed,
    /// Did not stop within the shutdown grace period and was cancelled.
    Aborted,
    /// Not started, because its capability probe found it cannot run on the device.
    Skipped,
}

impl fmt::Display for CollectorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Aborted => "aborted",
            Self::Skipped => "skipped",
        })
    }
}

/// How one provider ended (ARC-007).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorOutcome {
    pub provider: String,
    pub status: CollectorStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub events_emitted: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl CollectorOutcome {
    /// True when the collector started but its evidence may be incomplete.
    pub fn did_not_finish(&self) -> bool {
        matches!(
            self.status,
            CollectorStatus::Failed | CollectorStatus::Aborted
        )
    }

    /// Records a collector that was selected but cannot run on the device.
    pub fn skipped(provider: &str, reason: &str) -> Self {
        Self {
            provider: provider.to_string(),
            status: CollectorStatus::Skipped,
            error: Some(reason.to_string()),
            events_emitted: 0,
            notes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub host_os: String,
    pub host_arch: String,
}

impl ToolInfo {
    pub fn current(name: &str, version: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            host_os: std::env::consts::OS.to_string(),
            host_arch: std::env::consts::ARCH.to_string(),
        }
    }
}

/// Collection settings as requested by the user, recorded for reproducibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingConfiguration {
    pub collectors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u64>,
    pub retention: Retention,
    /// Names of the redaction rules applied; empty when redaction was disabled.
    pub redaction_rules: Vec<String>,
    pub queue_capacity: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionManifest {
    pub format_version: u32,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub status: SessionStatus,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<StopReason>,
    pub tool: ToolInfo,
    pub device: DeviceMetadata,
    pub target_apps: Vec<String>,
    pub configuration: RecordingConfiguration,
    pub capabilities: Vec<Capability>,
    pub collectors: Vec<CollectorOutcome>,
    pub artifacts: Vec<ArtifactRef>,
    pub event_count: u64,
    pub redaction_count: u64,
    /// Domains present in the recorded events, for quick filtering of session lists.
    pub domains: Vec<Domain>,
}

/// What is known about a session when its recording starts.
pub struct SessionStart {
    pub name: Option<String>,
    pub started_at: DateTime<Utc>,
    pub tool: ToolInfo,
    pub device: DeviceMetadata,
    pub target_apps: Vec<String>,
    pub configuration: RecordingConfiguration,
    pub capabilities: Vec<Capability>,
    /// Selected collectors that will not run, recorded so the manifest explains their absence.
    pub skipped_collectors: Vec<CollectorOutcome>,
}

impl SessionManifest {
    /// The manifest written when a recording starts, with a newly generated id.
    pub fn recording(start: SessionStart) -> Self {
        Self {
            format_version: MANIFEST_FORMAT_VERSION,
            id: new_session_id(start.started_at),
            name: start.name,
            status: SessionStatus::Recording,
            started_at: start.started_at,
            ended_at: None,
            stop_reason: None,
            tool: start.tool,
            device: start.device,
            target_apps: start.target_apps,
            configuration: start.configuration,
            capabilities: start.capabilities,
            collectors: start.skipped_collectors,
            artifacts: Vec::new(),
            event_count: 0,
            redaction_count: 0,
            domains: Vec::new(),
        }
    }

    /// Applies the outcome of a recording. The session is partial when a collector did not finish or
    /// events could not be written.
    pub fn finish(&mut self, summary: &RecordingSummary, ended_at: DateTime<Utc>) {
        let incomplete =
            summary.consumer_error.is_some() || !summary.incomplete_collectors().is_empty();
        self.status = if incomplete {
            SessionStatus::Partial
        } else {
            SessionStatus::Completed
        };
        self.ended_at = Some(ended_at);
        self.stop_reason = Some(summary.stop_reason);
        self.collectors.extend(summary.collectors.iter().cloned());
        self.collectors.sort_by(|a, b| a.provider.cmp(&b.provider));
        self.artifacts.clone_from(&summary.artifacts);
        self.event_count = summary.event_count;
        self.redaction_count = summary.redaction_count;
        self.domains.clone_from(&summary.domains);
    }
}

/// Sortable by start time, readable, and unique enough for one user's local sessions.
pub fn new_session_id(started_at: DateTime<Utc>) -> String {
    let suffix = (started_at.timestamp_subsec_nanos() ^ std::process::id()) & 0xffff;
    format!("{}-{suffix:04x}", started_at.format("%Y%m%d-%H%M%S"))
}

#[derive(Debug, Default)]
pub struct SessionListing {
    pub manifests: Vec<SessionManifest>,
    /// Session directories whose manifest could not be read.
    pub unreadable: Vec<PathBuf>,
}

/// Events read back from disk, with lines that could not be parsed.
#[derive(Debug, Default)]
pub struct StoredEvents {
    pub events: Vec<Event>,
    /// 1-based line numbers of unreadable lines; a single trailing one indicates an interrupted write.
    pub unreadable_lines: Vec<usize>,
}

pub struct SessionStore {
    root: PathBuf,
}

impl SessionStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn session_dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    /// Creates the session directory and writes the initial manifest.
    pub fn create(&self, manifest: &SessionManifest) -> Result<SessionWriter, SessionError> {
        validate_id(&manifest.id)?;
        private_fs::create_dir_all(&self.root).map_err(io_error(&self.root))?;
        let dir = self.session_dir(&manifest.id);
        // A non-recursive create fails on an id collision instead of mixing two recordings.
        private_fs::create_dir(&dir).map_err(|source| match source.kind() {
            std::io::ErrorKind::AlreadyExists => SessionError::AlreadyExists(manifest.id.clone()),
            _ => io_error(&dir)(source),
        })?;
        let artifacts = dir.join(ARTIFACTS_DIR);
        private_fs::create_dir(&artifacts).map_err(io_error(&artifacts))?;
        write_manifest(&dir, manifest)?;
        let events_path = dir.join(EVENTS_FILE);
        let file = private_fs::open_append(&events_path).map_err(io_error(&events_path))?;
        Ok(SessionWriter {
            dir,
            events_path,
            events: BufWriter::new(file),
        })
    }

    /// Lists sessions by start time. Sessions whose manifest cannot be read are reported separately,
    /// so one damaged session does not hide the others.
    pub fn list(&self) -> Result<SessionListing, SessionError> {
        let mut listing = SessionListing::default();
        if !self.root.exists() {
            return Ok(listing);
        }
        for entry in fs::read_dir(&self.root).map_err(io_error(&self.root))? {
            let path = entry.map_err(io_error(&self.root))?.path();
            if path.join(MANIFEST_FILE).is_file() {
                match read_manifest(&path) {
                    Ok(manifest) => listing.manifests.push(manifest),
                    Err(_) => listing.unreadable.push(path),
                }
            }
        }
        listing.manifests.sort_by(|a, b| {
            a.started_at
                .cmp(&b.started_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        listing.unreadable.sort();
        Ok(listing)
    }

    /// Resolves `latest`, a full id, or an unambiguous id prefix to a session id.
    pub fn resolve(&self, reference: &str) -> Result<String, SessionError> {
        // An exact id works even when its manifest is damaged, so the session can still be deleted.
        if validate_id(reference).is_ok()
            && self.session_dir(reference).join(MANIFEST_FILE).is_file()
        {
            return Ok(reference.to_string());
        }
        let ids: Vec<String> = self
            .list()?
            .manifests
            .into_iter()
            .map(|manifest| manifest.id)
            .collect();
        if reference == "latest" {
            return ids.last().cloned().ok_or(SessionError::Empty);
        }
        let matches: Vec<String> = ids
            .into_iter()
            .filter(|id| id.starts_with(reference))
            .collect();
        match matches.as_slice() {
            [] => Err(SessionError::NotFound(reference.to_string())),
            [only] => Ok(only.clone()),
            _ => Err(SessionError::Ambiguous {
                prefix: reference.to_string(),
                matches,
            }),
        }
    }

    pub fn manifest(&self, id: &str) -> Result<SessionManifest, SessionError> {
        validate_id(id)?;
        let dir = self.session_dir(id);
        if !dir.join(MANIFEST_FILE).is_file() {
            return Err(SessionError::NotFound(id.to_string()));
        }
        read_manifest(&dir)
    }

    pub fn read_events(&self, id: &str) -> Result<StoredEvents, SessionError> {
        validate_id(id)?;
        let path = self.session_dir(id).join(EVENTS_FILE);
        let file = File::open(&path).map_err(io_error(&path))?;
        let mut stored = StoredEvents::default();
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(io_error(&path))?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str(&line) {
                Ok(event) => stored.events.push(event),
                Err(_) => stored.unreadable_lines.push(index + 1),
            }
        }
        Ok(stored)
    }

    /// Permanently removes a session directory and all its artifacts (SEC-008).
    pub fn delete(&self, id: &str) -> Result<(), SessionError> {
        validate_id(id)?;
        let dir = self.session_dir(id);
        if !dir.join(MANIFEST_FILE).is_file() {
            return Err(SessionError::NotFound(id.to_string()));
        }
        fs::remove_dir_all(&dir).map_err(io_error(&dir))
    }
}

/// Appends events for a session being recorded and finalizes its manifest.
pub struct SessionWriter {
    dir: PathBuf,
    events_path: PathBuf,
    events: BufWriter<File>,
}

impl SessionWriter {
    pub fn artifact_dir(&self) -> PathBuf {
        self.dir.join(ARTIFACTS_DIR)
    }

    /// Buffers one event as a JSON line; [`Self::flush`] writes buffered lines to disk.
    pub fn append(&mut self, event: &Event) -> Result<(), SessionError> {
        let path = &self.events_path;
        serde_json::to_writer(&mut self.events, event).map_err(|source| SessionError::Json {
            path: path.clone(),
            source,
        })?;
        self.events.write_all(b"\n").map_err(io_error(path))
    }

    pub fn flush(&mut self) -> Result<(), SessionError> {
        self.events.flush().map_err(io_error(&self.events_path))
    }

    pub fn finalize(mut self, manifest: &SessionManifest) -> Result<(), SessionError> {
        self.events.flush().map_err(io_error(&self.events_path))?;
        self.events
            .get_ref()
            .sync_all()
            .map_err(io_error(&self.events_path))?;
        write_manifest(&self.dir, manifest)
    }
}

/// Session ids are generated by the tool; rejecting anything else prevents path traversal.
fn validate_id(id: &str) -> Result<(), SessionError> {
    let valid = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(())
    } else {
        Err(SessionError::InvalidId(id.to_string()))
    }
}

fn read_manifest(dir: &Path) -> Result<SessionManifest, SessionError> {
    let path = dir.join(MANIFEST_FILE);
    let text = fs::read_to_string(&path).map_err(io_error(&path))?;
    serde_json::from_str(&text).map_err(|source| SessionError::Json { path, source })
}

fn write_manifest(dir: &Path, manifest: &SessionManifest) -> Result<(), SessionError> {
    let path = dir.join(MANIFEST_FILE);
    let temporary = dir.join(format!("{MANIFEST_FILE}.tmp"));
    let json = serde_json::to_string_pretty(manifest).map_err(|source| SessionError::Json {
        path: path.clone(),
        source,
    })?;
    let mut file = private_fs::create_or_truncate(&temporary).map_err(io_error(&temporary))?;
    file.write_all(json.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(io_error(&temporary))?;
    fs::rename(&temporary, &path).map_err(io_error(&path))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use chrono::TimeZone;

    pub fn manifest(id: &str, started_second: i64) -> SessionManifest {
        let mut manifest = SessionManifest::recording(SessionStart {
            name: None,
            started_at: Utc
                .timestamp_opt(1_700_000_000 + started_second, 0)
                .single()
                .expect("valid time"),
            tool: ToolInfo::current("mobile-bridge", "0.0.0-test"),
            device: DeviceMetadata {
                id: "dev1".into(),
                ..DeviceMetadata::default()
            },
            target_apps: vec!["com.example".into()],
            configuration: RecordingConfiguration {
                collectors: vec!["test".into()],
                duration_seconds: None,
                retention: Retention::All,
                redaction_rules: Vec::new(),
                queue_capacity: 16,
            },
            capabilities: Vec::new(),
            skipped_collectors: Vec::new(),
        });
        manifest.id = id.to_string();
        manifest
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::manifest;
    use super::*;
    use crate::event::test_support::event_at;
    use crate::event::{Observation, kinds};

    fn store() -> (tempfile::TempDir, SessionStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = SessionStore::new(dir.path().join("sessions"));
        (dir, store)
    }

    fn log_event(sequence: u64) -> Event {
        event_at(
            sequence,
            0,
            Observation::new(Domain::Log, kinds::LOG, format!("line {sequence}")),
        )
    }

    #[test]
    fn recorded_events_and_manifest_round_trip() {
        let (_dir, store) = store();
        let mut writer = store.create(&manifest("s1", 0)).expect("create");
        writer.append(&log_event(0)).expect("append");
        writer.append(&log_event(1)).expect("append");
        let mut finished = manifest("s1", 0);
        finished.status = SessionStatus::Completed;
        finished.event_count = 2;
        writer.finalize(&finished).expect("finalize");

        assert_eq!(store.manifest("s1").expect("manifest"), finished);
        let stored = store.read_events("s1").expect("events");
        assert_eq!(stored.events, vec![log_event(0), log_event(1)]);
        assert!(stored.unreadable_lines.is_empty());
    }

    #[test]
    fn a_truncated_last_line_is_reported_instead_of_failing() {
        let (_dir, store) = store();
        let mut writer = store.create(&manifest("s1", 0)).expect("create");
        writer.append(&log_event(0)).expect("append");
        drop(writer);
        let events_path = store.session_dir("s1").join(EVENTS_FILE);
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&events_path)
            .expect("open");
        file.write_all(b"{\"schema_version\":1,\"sess")
            .expect("write partial line");

        let stored = store.read_events("s1").expect("events");
        assert_eq!(stored.events.len(), 1);
        assert_eq!(stored.unreadable_lines, vec![2]);
        assert_eq!(
            store.manifest("s1").expect("manifest").status,
            SessionStatus::Recording
        );
    }

    #[test]
    fn resolve_accepts_latest_full_ids_and_unique_prefixes() {
        let (_dir, store) = store();
        store.create(&manifest("20240101-a", 0)).expect("create");
        store.create(&manifest("20240102-b", 10)).expect("create");
        assert_eq!(store.resolve("latest").expect("latest"), "20240102-b");
        assert_eq!(store.resolve("20240101-a").expect("full"), "20240101-a");
        assert_eq!(store.resolve("20240101").expect("prefix"), "20240101-a");
        assert!(matches!(
            store.resolve("2024"),
            Err(SessionError::Ambiguous { .. })
        ));
        assert!(matches!(
            store.resolve("nope"),
            Err(SessionError::NotFound(_))
        ));
    }

    #[test]
    fn an_existing_session_is_never_reused() {
        let (_dir, store) = store();
        store.create(&manifest("s1", 0)).expect("create");
        assert!(matches!(
            store.create(&manifest("s1", 0)),
            Err(SessionError::AlreadyExists(_))
        ));
    }

    #[test]
    fn a_damaged_manifest_is_listed_apart_and_can_still_be_deleted() {
        let (_dir, store) = store();
        store.create(&manifest("good", 0)).expect("create");
        store.create(&manifest("bad", 1)).expect("create");
        fs::write(store.session_dir("bad").join(MANIFEST_FILE), "{ not json").expect("damage");

        let listing = store.list().expect("list");
        assert_eq!(listing.manifests.len(), 1);
        assert_eq!(listing.unreadable, vec![store.session_dir("bad")]);
        assert_eq!(store.resolve("latest").expect("latest"), "good");
        store
            .delete(&store.resolve("bad").expect("exact id"))
            .expect("delete");
    }

    #[test]
    fn delete_removes_the_session_directory() {
        let (_dir, store) = store();
        store.create(&manifest("s1", 0)).expect("create");
        store.delete("s1").expect("delete");
        assert!(!store.session_dir("s1").exists());
        assert!(matches!(store.delete("s1"), Err(SessionError::NotFound(_))));
    }

    #[test]
    fn ids_that_could_escape_the_store_are_rejected() {
        let (_dir, store) = store();
        assert!(matches!(
            store.delete("../etc"),
            Err(SessionError::InvalidId(_))
        ));
        assert!(matches!(
            store.manifest("a/b"),
            Err(SessionError::InvalidId(_))
        ));
    }

    fn summary(collectors: Vec<CollectorOutcome>) -> RecordingSummary {
        RecordingSummary {
            stop_reason: StopReason::DurationElapsed,
            collectors,
            artifacts: Vec::new(),
            event_count: 3,
            redaction_count: 0,
            domains: vec![Domain::Log],
            consumer_error: None,
        }
    }

    fn outcome(provider: &str, status: CollectorStatus) -> CollectorOutcome {
        CollectorOutcome {
            provider: provider.into(),
            status,
            error: None,
            events_emitted: 0,
            notes: Vec::new(),
        }
    }

    #[test]
    fn a_collector_that_did_not_finish_makes_the_session_partial() {
        let mut finished = manifest("s1", 0);
        finished.finish(
            &summary(vec![outcome("perfetto", CollectorStatus::Failed)]),
            Utc::now(),
        );
        assert_eq!(finished.status, SessionStatus::Partial);
        assert_eq!(finished.event_count, 3);
        assert_eq!(finished.stop_reason, Some(StopReason::DurationElapsed));
    }

    #[test]
    fn skipped_collectors_are_kept_but_do_not_make_the_session_partial() {
        let mut finished = manifest("s1", 0);
        finished
            .collectors
            .push(CollectorOutcome::skipped("perfetto", "not installed"));
        finished.finish(
            &summary(vec![outcome("logcat", CollectorStatus::Completed)]),
            Utc::now(),
        );
        assert_eq!(finished.status, SessionStatus::Completed);
        let providers: Vec<&str> = finished
            .collectors
            .iter()
            .map(|c| c.provider.as_str())
            .collect();
        assert_eq!(providers, ["logcat", "perfetto"]);
    }

    #[cfg(unix)]
    #[test]
    fn session_files_are_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = store();
        store.create(&manifest("s1", 0)).expect("create");
        let mode =
            |path: PathBuf| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode(store.session_dir("s1")), 0o700);
        assert_eq!(mode(store.session_dir("s1").join(EVENTS_FILE)), 0o600);
        assert_eq!(mode(store.session_dir("s1").join(MANIFEST_FILE)), 0o600);
    }
}
