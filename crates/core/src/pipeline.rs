//! Recording engine: runs providers concurrently and turns their observations into ordered, redacted,
//! persisted events (ARC-004 to ARC-007, SES-001 to SES-004, EVT-009).
//!
//! Each provider runs in its own task. A provider that fails or panics is recorded as such and the
//! other providers keep collecting. Shutdown is cooperative: providers get a stop signal and a grace
//! period to finish (for example to pull a trace file) before they are cancelled.

use std::collections::{BTreeSet, HashMap};
use std::future::pending;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::{mpsc, watch};
use tokio::task::{Id, JoinError, JoinSet};
use tokio::time::{Instant, sleep_until};

use crate::event::{Domain, Event, EventStamp, Observation, Severity, kinds};
use crate::filter::Retention;
use crate::provider::{
    ArtifactRef, EventSink, Provider, ProviderContext, ProviderError, ProviderReport, SinkItem,
    StopSignal,
};
use crate::redact::Redactor;
use crate::session::{CollectorOutcome, CollectorStatus, SessionError, SessionWriter, StopReason};

/// Provider id used for events the engine itself creates.
pub const ENGINE_PROVIDER: &str = "engine";
const MARKER_PROVIDER: &str = "marker";
const MARKER_QUEUE_CAPACITY: usize = 64;

/// Receives every recorded event: the session writer, a live terminal stream, a test buffer.
pub trait EventConsumer {
    fn consume(&mut self, event: &Event) -> Result<(), String>;

    /// Called whenever the event queue is drained, and once at the end of the recording.
    fn flush(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// Events are buffered and flushed when the queue drains, so an interruption loses at most the
/// events of one burst while a burst costs one write instead of one per event.
impl EventConsumer for SessionWriter {
    fn consume(&mut self, event: &Event) -> Result<(), String> {
        self.append(event)
            .map_err(|error: SessionError| error.to_string())
    }

    fn flush(&mut self) -> Result<(), String> {
        SessionWriter::flush(self).map_err(|error| error.to_string())
    }
}

pub struct RecordingSetup {
    pub session_id: String,
    pub device_id: String,
    pub artifact_dir: PathBuf,
    pub duration: Option<Duration>,
    pub queue_capacity: usize,
    pub shutdown_grace: Duration,
    pub retention: Retention,
    pub redactor: Redactor,
}

/// Handles the caller keeps to steer a running recording.
#[derive(Clone)]
pub struct RecordingControls {
    stop: Arc<watch::Sender<bool>>,
    markers: mpsc::Sender<String>,
}

impl RecordingControls {
    pub fn request_stop(&self) {
        self.stop.send_replace(true);
    }

    /// Adds a manual marker (SES-004) from a plain thread, such as a stdin reader. Must not be called
    /// from async code. Fails only when the recording has already ended.
    pub fn blocking_add_marker(&self, note: String) -> Result<(), String> {
        self.markers
            .blocking_send(note)
            .map_err(|_| "the recording has ended".to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingSummary {
    pub stop_reason: StopReason,
    pub collectors: Vec<CollectorOutcome>,
    pub artifacts: Vec<ArtifactRef>,
    pub event_count: u64,
    pub redaction_count: u64,
    pub domains: Vec<Domain>,
    /// Set when a consumer (usually persistence) failed and the recording was stopped early.
    pub consumer_error: Option<String>,
}

impl RecordingSummary {
    /// Collectors whose evidence may be incomplete because they failed or were cancelled.
    pub fn incomplete_collectors(&self) -> Vec<&str> {
        self.collectors
            .iter()
            .filter(|collector| collector.did_not_finish())
            .map(|collector| collector.provider.as_str())
            .collect()
    }
}

pub struct Recorder {
    setup: RecordingSetup,
    providers: Vec<Arc<dyn Provider>>,
    user_stop: watch::Receiver<bool>,
    markers: mpsc::Receiver<String>,
}

impl Recorder {
    pub fn new(
        setup: RecordingSetup,
        providers: Vec<Arc<dyn Provider>>,
    ) -> (Self, RecordingControls) {
        let (stop_sender, user_stop) = watch::channel(false);
        let (marker_sender, markers) = mpsc::channel(MARKER_QUEUE_CAPACITY);
        let recorder = Self {
            setup,
            providers,
            user_stop,
            markers,
        };
        let controls = RecordingControls {
            stop: Arc::new(stop_sender),
            markers: marker_sender,
        };
        (recorder, controls)
    }

    pub async fn run(self, consumers: &mut [&mut dyn EventConsumer]) -> RecordingSummary {
        let Self {
            setup,
            providers,
            mut user_stop,
            mut markers,
        } = self;
        let started = Instant::now();
        let mut session = SessionState::new(&setup, started);
        let (observation_sender, mut observations) = mpsc::channel(setup.queue_capacity.max(1));
        let (provider_stop, provider_stop_receiver) = watch::channel(false);
        let mut tasks = JoinSet::new();
        let mut task_providers: HashMap<Id, &'static str> = HashMap::new();

        for provider in providers {
            let id = provider.id();
            session.record_collector_started(id, consumers);
            let context = ProviderContext {
                sink: EventSink::new(id, observation_sender.clone()),
                stop: StopSignal::new(provider_stop_receiver.clone()),
                artifact_dir: setup.artifact_dir.clone(),
                redactor: setup.redactor.clone(),
            };
            let handle = tasks.spawn(async move { provider.run(context).await });
            task_providers.insert(handle.id(), id);
        }
        drop(observation_sender);

        let deadline = setup.duration.map(|duration| started + duration);
        let mut grace_deadline: Option<Instant> = None;
        let mut stop_sent = false;
        let mut observations_closed = false;
        let mut markers_closed = false;

        loop {
            if session.stop_reason.is_none() && tasks.is_empty() {
                session.stop_reason = Some(StopReason::CollectorsFinished);
            }
            if session.stop_reason.is_some() && !stop_sent {
                provider_stop.send_replace(true);
                grace_deadline = Some(Instant::now() + setup.shutdown_grace);
                stop_sent = true;
            }
            if observations_closed && tasks.is_empty() {
                break;
            }
            let accepting_input = session.stop_reason.is_none();

            tokio::select! {
                biased;
                item = observations.recv(), if !observations_closed => match item {
                    Some(SinkItem { provider, observation }) => {
                        session.count_emitted(provider);
                        session.record(provider, observation, consumers);
                        if observations.is_empty() {
                            session.flush(consumers);
                        }
                    }
                    None => observations_closed = true,
                },
                joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                    if let Some(joined) = joined {
                        session.record_collector_end(&task_providers, joined, consumers);
                    }
                }
                note = markers.recv(), if accepting_input && !markers_closed => match note {
                    Some(note) => session.record_marker(note, consumers),
                    None => markers_closed = true,
                },
                () = stop_requested(&mut user_stop), if accepting_input => {
                    session.stop_reason = Some(StopReason::UserRequested);
                }
                () = sleep_until_optional(deadline), if accepting_input => {
                    session.stop_reason = Some(StopReason::DurationElapsed);
                }
                () = sleep_until_optional(grace_deadline), if grace_deadline.is_some() && !tasks.is_empty() => {
                    tasks.abort_all();
                    grace_deadline = None;
                }
            }
        }

        session.flush(consumers);
        session.into_summary()
    }
}

async fn stop_requested(receiver: &mut watch::Receiver<bool>) {
    if receiver.wait_for(|stop| *stop).await.is_err() {
        // The controls were dropped, so no one can request a stop any more.
        pending::<()>().await;
    }
}

async fn sleep_until_optional(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => pending::<()>().await,
    }
}

type JoinedProvider = (Id, Result<ProviderReport, ProviderError>);

/// Mutable bookkeeping of one recording, kept out of the select loop for readability.
struct SessionState<'a> {
    setup: &'a RecordingSetup,
    started: Instant,
    next_sequence: u64,
    redaction_count: u64,
    domains: BTreeSet<Domain>,
    emitted: HashMap<&'static str, u64>,
    collectors: Vec<CollectorOutcome>,
    artifacts: Vec<ArtifactRef>,
    stop_reason: Option<StopReason>,
    consumer_error: Option<String>,
}

impl<'a> SessionState<'a> {
    fn new(setup: &'a RecordingSetup, started: Instant) -> Self {
        Self {
            setup,
            started,
            next_sequence: 0,
            redaction_count: 0,
            domains: BTreeSet::new(),
            emitted: HashMap::new(),
            collectors: Vec::new(),
            artifacts: Vec::new(),
            stop_reason: None,
            consumer_error: None,
        }
    }

    fn count_emitted(&mut self, provider: &'static str) {
        *self.emitted.entry(provider).or_default() += 1;
    }

    fn record(
        &mut self,
        provider: &str,
        observation: Observation,
        consumers: &mut [&mut dyn EventConsumer],
    ) {
        if self.consumer_error.is_some()
            || !self
                .setup
                .retention
                .retains(observation.domain, observation.app.as_deref())
        {
            return;
        }
        let elapsed = self.started.elapsed();
        let mut event = Event::from_observation(
            observation,
            EventStamp {
                session_id: &self.setup.session_id,
                device_id: &self.setup.device_id,
                provider,
                sequence: self.next_sequence,
                host_time: Utc::now(),
                monotonic_ns: u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
            },
        );
        self.redaction_count += self.setup.redactor.apply(&mut event) as u64;
        self.next_sequence += 1;
        self.domains.insert(event.domain);
        for consumer in consumers.iter_mut() {
            if let Err(error) = consumer.consume(&event) {
                return self.fail_consumer(error);
            }
        }
    }

    fn flush(&mut self, consumers: &mut [&mut dyn EventConsumer]) {
        if self.consumer_error.is_some() {
            return;
        }
        for consumer in consumers.iter_mut() {
            if let Err(error) = consumer.flush() {
                return self.fail_consumer(error);
            }
        }
    }

    fn fail_consumer(&mut self, error: String) {
        self.consumer_error = Some(error);
        self.stop_reason
            .get_or_insert(StopReason::PersistenceFailed);
    }

    fn record_marker(&mut self, note: String, consumers: &mut [&mut dyn EventConsumer]) {
        let message = if note.trim().is_empty() {
            format!("marker {}", self.next_sequence)
        } else {
            note.trim().to_string()
        };
        self.record(
            MARKER_PROVIDER,
            Observation::new(Domain::Marker, kinds::MARKER, message),
            consumers,
        );
    }

    fn record_collector_started(
        &mut self,
        provider: &'static str,
        consumers: &mut [&mut dyn EventConsumer],
    ) {
        self.emitted.insert(provider, 0);
        let observation = Observation::new(
            Domain::Collector,
            kinds::COLLECTOR_STARTED,
            format!("collector {provider} started"),
        )
        .with_attribute("collector", provider);
        self.record(ENGINE_PROVIDER, observation, consumers);
    }

    fn record_collector_end(
        &mut self,
        task_providers: &HashMap<Id, &'static str>,
        joined: Result<JoinedProvider, JoinError>,
        consumers: &mut [&mut dyn EventConsumer],
    ) {
        let (task_id, result) = match joined {
            Ok((task_id, result)) => (
                task_id,
                result.map_err(|error| (CollectorStatus::Failed, error.to_string())),
            ),
            Err(join_error) => (join_error.id(), Err(describe_join_error(&join_error))),
        };
        let provider = task_providers.get(&task_id).copied().unwrap_or("unknown");
        let (status, error, notes) = match result {
            Ok(report) => {
                self.artifacts.extend(report.artifacts);
                (CollectorStatus::Completed, None, report.notes)
            }
            Err((status, error)) => (status, Some(error), Vec::new()),
        };
        let outcome = CollectorOutcome {
            provider: provider.to_string(),
            status,
            error,
            events_emitted: self.emitted.get(provider).copied().unwrap_or(0),
            notes,
        };
        self.record(
            ENGINE_PROVIDER,
            collector_end_observation(&outcome),
            consumers,
        );
        self.collectors.push(outcome);
    }

    fn into_summary(mut self) -> RecordingSummary {
        self.collectors.sort_by(|a, b| a.provider.cmp(&b.provider));
        RecordingSummary {
            stop_reason: self.stop_reason.unwrap_or(StopReason::CollectorsFinished),
            collectors: self.collectors,
            artifacts: self.artifacts,
            event_count: self.next_sequence,
            redaction_count: self.redaction_count,
            domains: self.domains.into_iter().collect(),
            consumer_error: self.consumer_error,
        }
    }
}

fn describe_join_error(error: &JoinError) -> (CollectorStatus, String) {
    if error.is_cancelled() {
        (
            CollectorStatus::Aborted,
            "did not stop within the shutdown grace period".to_string(),
        )
    } else {
        (
            CollectorStatus::Failed,
            "the collector panicked".to_string(),
        )
    }
}

fn collector_end_observation(outcome: &CollectorOutcome) -> Observation {
    let provider = &outcome.provider;
    let observation = match (&outcome.status, &outcome.error) {
        (CollectorStatus::Completed, _) => Observation::new(
            Domain::Collector,
            kinds::COLLECTOR_FINISHED,
            format!("collector {provider} finished"),
        ),
        (_, error) => Observation::new(
            Domain::Collector,
            kinds::COLLECTOR_FAILED,
            format!(
                "collector {provider} stopped: {}; no further {provider} events were collected",
                error.as_deref().unwrap_or("unknown error")
            ),
        )
        .with_severity(Severity::Error),
    };
    observation
        .with_attribute("collector", provider.as_str())
        .with_attribute("events_emitted", outcome.events_emitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Capability;
    use async_trait::async_trait;

    #[derive(Default)]
    struct CollectedEvents(Vec<Event>);

    impl EventConsumer for CollectedEvents {
        fn consume(&mut self, event: &Event) -> Result<(), String> {
            self.0.push(event.clone());
            Ok(())
        }
    }

    impl CollectedEvents {
        fn kinds_from(&self, provider: &str) -> Vec<&str> {
            self.0
                .iter()
                .filter(|event| event.source.provider == provider)
                .map(|event| event.kind.as_str())
                .collect()
        }
    }

    struct FailingConsumer;

    impl EventConsumer for FailingConsumer {
        fn consume(&mut self, _event: &Event) -> Result<(), String> {
            Err("disk full".to_string())
        }
    }

    enum Behavior {
        EmitThenWaitForStop(usize),
        EmitThenFinish(usize),
        Fail,
        Panic,
        IgnoreStop,
    }

    struct FakeProvider {
        id: &'static str,
        behavior: Behavior,
    }

    fn provider(id: &'static str, behavior: Behavior) -> Arc<dyn Provider> {
        Arc::new(FakeProvider { id, behavior })
    }

    impl FakeProvider {
        async fn emit(&self, context: &ProviderContext, count: usize) -> Result<(), ProviderError> {
            for index in 0..count {
                let observation =
                    Observation::new(Domain::Log, kinds::LOG, format!("{} {index}", self.id));
                context.sink.emit(observation).await?;
            }
            Ok(())
        }
    }

    #[async_trait]
    impl Provider for FakeProvider {
        fn id(&self) -> &'static str {
            self.id
        }

        async fn probe(&self) -> Capability {
            Capability::available(self.id, "fake")
        }

        async fn run(&self, mut context: ProviderContext) -> Result<ProviderReport, ProviderError> {
            match self.behavior {
                Behavior::EmitThenWaitForStop(count) => {
                    self.emit(&context, count).await?;
                    context.stop.requested().await;
                }
                Behavior::EmitThenFinish(count) => self.emit(&context, count).await?,
                Behavior::Fail => return Err(ProviderError::Source("device disconnected".into())),
                Behavior::Panic => panic!("provider bug"),
                Behavior::IgnoreStop => pending::<()>().await,
            }
            Ok(ProviderReport::default())
        }
    }

    fn setup(duration_ms: u64) -> RecordingSetup {
        RecordingSetup {
            session_id: "s1".into(),
            device_id: "dev1".into(),
            artifact_dir: std::env::temp_dir(),
            duration: Some(Duration::from_millis(duration_ms)),
            queue_capacity: 1,
            shutdown_grace: Duration::from_millis(100),
            retention: Retention::All,
            redactor: Redactor::disabled(),
        }
    }

    async fn record(
        setup: RecordingSetup,
        providers: Vec<Arc<dyn Provider>>,
    ) -> (RecordingSummary, CollectedEvents) {
        let (recorder, _controls) = Recorder::new(setup, providers);
        let mut collected = CollectedEvents::default();
        let summary = recorder.run(&mut [&mut collected]).await;
        (summary, collected)
    }

    fn outcome<'s>(summary: &'s RecordingSummary, provider: &str) -> &'s CollectorOutcome {
        summary
            .collectors
            .iter()
            .find(|outcome| outcome.provider == provider)
            .expect("collector outcome present")
    }

    #[tokio::test]
    async fn stops_when_the_duration_elapses_and_keeps_every_event_despite_a_tiny_queue() {
        let (summary, collected) = record(
            setup(50),
            vec![provider("logs", Behavior::EmitThenWaitForStop(500))],
        )
        .await;
        assert_eq!(summary.stop_reason, StopReason::DurationElapsed);
        assert_eq!(collected.kinds_from("logs").len(), 500);
        assert_eq!(outcome(&summary, "logs").status, CollectorStatus::Completed);
        assert_eq!(outcome(&summary, "logs").events_emitted, 500);
    }

    #[tokio::test]
    async fn sequences_are_contiguous_in_arrival_order() {
        let (_, collected) = record(
            setup(20),
            vec![provider("logs", Behavior::EmitThenFinish(20))],
        )
        .await;
        let sequences: Vec<u64> = collected.0.iter().map(|event| event.sequence).collect();
        assert_eq!(sequences, (0..sequences.len() as u64).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn a_failing_collector_does_not_stop_the_others() {
        let providers = vec![
            provider("broken", Behavior::Fail),
            provider("logs", Behavior::EmitThenWaitForStop(3)),
        ];
        let (summary, collected) = record(setup(50), providers).await;
        assert_eq!(summary.stop_reason, StopReason::DurationElapsed);
        assert_eq!(outcome(&summary, "broken").status, CollectorStatus::Failed);
        assert_eq!(
            outcome(&summary, "broken").error.as_deref(),
            Some("device disconnected")
        );
        assert_eq!(outcome(&summary, "logs").status, CollectorStatus::Completed);
        assert!(
            collected
                .0
                .iter()
                .any(|event| event.kind == kinds::COLLECTOR_FAILED)
        );
    }

    #[tokio::test]
    async fn a_panicking_collector_is_reported_as_failed() {
        let (summary, _) = record(setup(20), vec![provider("buggy", Behavior::Panic)]).await;
        assert_eq!(outcome(&summary, "buggy").status, CollectorStatus::Failed);
        assert_eq!(
            outcome(&summary, "buggy").error.as_deref(),
            Some("the collector panicked")
        );
    }

    #[tokio::test]
    async fn a_collector_ignoring_stop_is_aborted_after_the_grace_period() {
        let (summary, _) = record(setup(20), vec![provider("stuck", Behavior::IgnoreStop)]).await;
        assert_eq!(outcome(&summary, "stuck").status, CollectorStatus::Aborted);
    }

    #[tokio::test]
    async fn ends_early_when_every_collector_finishes() {
        let (summary, _) = record(
            setup(60_000),
            vec![provider("logs", Behavior::EmitThenFinish(2))],
        )
        .await;
        assert_eq!(summary.stop_reason, StopReason::CollectorsFinished);
    }

    #[tokio::test]
    async fn user_stop_and_markers_are_recorded() {
        let mut no_deadline = setup(0);
        no_deadline.duration = None;
        let (recorder, controls) = Recorder::new(
            no_deadline,
            vec![provider("logs", Behavior::EmitThenWaitForStop(1))],
        );
        let steering = tokio::task::spawn_blocking(move || {
            controls
                .blocking_add_marker("tapped login".into())
                .expect("marker accepted");
            std::thread::sleep(Duration::from_millis(20));
            controls.request_stop();
        });
        let mut collected = CollectedEvents::default();
        let summary = recorder.run(&mut [&mut collected]).await;
        steering.await.expect("steering task");

        assert_eq!(summary.stop_reason, StopReason::UserRequested);
        let marker = collected
            .0
            .iter()
            .find(|event| event.kind == kinds::MARKER)
            .expect("marker");
        assert_eq!(marker.message, "tapped login");
    }

    #[tokio::test]
    async fn retention_and_redaction_apply_before_consumers_see_events() {
        struct SecretProvider;
        #[async_trait]
        impl Provider for SecretProvider {
            fn id(&self) -> &'static str {
                "logs"
            }
            async fn probe(&self) -> Capability {
                Capability::available("logs", "fake")
            }
            async fn run(&self, context: ProviderContext) -> Result<ProviderReport, ProviderError> {
                let target = Observation::new(Domain::Log, kinds::LOG, "password=hunter22")
                    .with_app("com.example");
                let other =
                    Observation::new(Domain::Log, kinds::LOG, "unrelated").with_app("com.other");
                context.sink.emit(target).await?;
                context.sink.emit(other).await?;
                Ok(ProviderReport::default())
            }
        }
        let mut redacting = setup(1000);
        redacting.retention = Retention::TargetApps(vec!["com.example".into()]);
        redacting.redactor = Redactor::with_built_in_rules();
        let (summary, collected) = record(redacting, vec![Arc::new(SecretProvider)]).await;

        let logs: Vec<&Event> = collected
            .0
            .iter()
            .filter(|event| event.domain == Domain::Log)
            .collect();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].message, "password=[REDACTED]");
        assert_eq!(summary.redaction_count, 1);
    }

    #[tokio::test]
    async fn a_persistence_failure_stops_the_recording() {
        let (recorder, _controls) = Recorder::new(
            setup(60_000),
            vec![provider("logs", Behavior::EmitThenWaitForStop(5))],
        );
        let summary = recorder.run(&mut [&mut FailingConsumer]).await;
        assert_eq!(summary.stop_reason, StopReason::PersistenceFailed);
        assert_eq!(summary.consumer_error.as_deref(), Some("disk full"));
    }
}
