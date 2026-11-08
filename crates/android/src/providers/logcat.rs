//! Logcat collector (AND-003, MON-002, MON-005, MON-011, APP-005 to APP-008).
//!
//! Streams the main, system, crash and events buffers. Lines are kept as log events with their raw text;
//! lines that report lifecycle facts (process start and death, crashes, ANRs, the resumed activity) are
//! normalized into lifecycle and process events instead.

use std::collections::HashMap;

use async_trait::async_trait;
use mobile_bridge_core::device::Capability;
use mobile_bridge_core::event::{Domain, Observation, Severity, kinds};
use mobile_bridge_core::provider::{Provider, ProviderContext, ProviderError, ProviderReport};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

use super::{LOGCAT, list_processes, source_error};
use crate::adb::DeviceConnection;
use crate::package::PackageName;
use crate::parse::logcat::{LogLine, LogRecord, LogTime, event_log_fields, parse_log_line};
use crate::parse::processes::ProcessInfo;

/// `-v epoch` needs Android 7.0.
const EPOCH_FORMAT_MIN_API: u32 = 24;
const BUFFERS: [&str; 4] = ["main", "system", "crash", "events"];
const READABLE_BUFFER_PREFIX: &str = "buffer:";
/// Event-log tags that carry lifecycle facts; other event-log lines stay plain log events.
const LIFECYCLE_TAGS: [&str; 7] = [
    "am_proc_start",
    "am_proc_died",
    "am_kill",
    "am_crash",
    "am_anr",
    "wm_set_resumed_activity",
    "am_set_resumed_activity",
];

pub struct LogcatProvider {
    device: DeviceConnection,
    target: Option<PackageName>,
    api_level: Option<u32>,
}

/// What one startup round trip tells about the device's logcat.
#[derive(Debug, PartialEq, Eq)]
struct StreamSetup {
    readable_buffers: Vec<&'static str>,
    device_epoch_seconds: Option<u64>,
}

impl LogcatProvider {
    pub fn new(
        device: DeviceConnection,
        target: Option<PackageName>,
        api_level: Option<u32>,
    ) -> Self {
        Self {
            device,
            target,
            api_level,
        }
    }

    fn supports_epoch_format(&self) -> bool {
        self.api_level
            .is_some_and(|api| api >= EPOCH_FORMAT_MIN_API)
    }

    /// Finds the readable buffers and the device clock in a single adb round trip.
    async fn stream_setup(&self) -> Result<StreamSetup, ProviderError> {
        let command = format!(
            "for b in {}; do logcat -d -t 1 -b $b >/dev/null 2>&1 && echo {READABLE_BUFFER_PREFIX}$b; done; date +%s",
            BUFFERS.join(" ")
        );
        let output = self.device.shell(&command).await.map_err(source_error)?;
        Ok(parse_stream_setup(&output))
    }

    fn command(&self, setup: &StreamSetup) -> String {
        let format = if self.supports_epoch_format() {
            "-v threadtime -v epoch"
        } else {
            "-v threadtime"
        };
        // Starting at the device's current time skips lines logged before the recording started. Only
        // Android 7+ accepts an epoch time for -T; older releases fall back to the last line.
        let start = match setup.device_epoch_seconds {
            Some(seconds) if self.supports_epoch_format() => format!("-T {seconds}.0"),
            _ => "-T 1".to_string(),
        };
        format!(
            "logcat {format} -b {} {start}",
            setup.readable_buffers.join(",")
        )
    }
}

fn parse_stream_setup(output: &str) -> StreamSetup {
    let readable_buffers = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix(READABLE_BUFFER_PREFIX))
        .filter_map(|name| BUFFERS.iter().copied().find(|buffer| *buffer == name))
        .collect();
    let device_epoch_seconds = output
        .lines()
        .rev()
        .find_map(|line| line.trim().parse().ok());
    StreamSetup {
        readable_buffers,
        device_epoch_seconds,
    }
}

#[async_trait]
impl Provider for LogcatProvider {
    fn id(&self) -> &'static str {
        LOGCAT
    }

    async fn probe(&self) -> Capability {
        match self.device.shell("logcat -d -t 1").await {
            Ok(output) if output.trim().is_empty() => Capability::degraded(
                LOGCAT,
                "logcat runs but returned no lines",
                "Some vendor builds disable logging by default; check the vendor's developer or log settings.",
            ),
            Ok(_) if !self.supports_epoch_format() => Capability::degraded(
                LOGCAT,
                "available; this Android version cannot report UTC timestamps, so device-local times are kept as text",
                "Use a device with Android 7.0 (API 24) or newer for precise timestamps.",
            ),
            Ok(_) => Capability::available(LOGCAT, "main, system, crash and events buffers"),
            Err(error) => Capability::unavailable(LOGCAT, error.to_string(), error.remediation()),
        }
    }

    async fn run(&self, mut context: ProviderContext) -> Result<ProviderReport, ProviderError> {
        let (processes, setup) = tokio::join!(list_processes(&self.device), self.stream_setup());
        let setup = setup?;
        let mut normalizer =
            LogcatNormalizer::new(self.target.clone(), &processes.unwrap_or_default());
        if setup.readable_buffers.is_empty() {
            return Err(ProviderError::Source("no logcat buffer is readable".into()));
        }
        let mut report = ProviderReport::default();
        if setup.readable_buffers.len() < BUFFERS.len() {
            report.notes.push(format!(
                "only these logcat buffers were readable: {}",
                setup.readable_buffers.join(", ")
            ));
        }

        let mut child = self
            .device
            .spawn_shell(&self.command(&setup))
            .map_err(source_error)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ProviderError::Source("logcat output is not available".into()))?;
        let mut lines = BufReader::new(stdout);
        let mut line = Vec::new();

        loop {
            line.clear();
            tokio::select! {
                () = context.stop.requested() => {
                    // Killing the local adb client closes the connection, which ends logcat on the device.
                    let _ = child.kill().await;
                    return Ok(report);
                }
                read = lines.read_until(b'\n', &mut line) => {
                    if read? == 0 {
                        let mut stderr = String::new();
                        if let Some(mut pipe) = child.stderr.take() {
                            let _ = pipe.read_to_string(&mut stderr).await;
                        }
                        return Err(ProviderError::Source(format!(
                            "logcat stopped unexpectedly (the device may have disconnected){}",
                            if stderr.trim().is_empty() { String::new() } else { format!(": {}", stderr.trim()) }
                        )));
                    }
                    for observation in normalizer.normalize(&String::from_utf8_lossy(&line)) {
                        context.sink.emit(observation).await?;
                    }
                }
            }
        }
    }
}

/// Turns logcat lines into observations, tracking which process belongs to which app.
pub struct LogcatNormalizer {
    target: Option<PackageName>,
    process_names: HashMap<u32, String>,
    foreground: Option<String>,
    buffer: Option<String>,
}

impl LogcatNormalizer {
    pub fn new(target: Option<PackageName>, initial_processes: &[ProcessInfo]) -> Self {
        Self {
            target,
            process_names: initial_processes
                .iter()
                .map(|process| (process.pid, process.name.clone()))
                .collect(),
            foreground: None,
            buffer: None,
        }
    }

    pub fn normalize(&mut self, line: &str) -> Vec<Observation> {
        let raw = line.trim_end_matches(['\r', '\n']);
        match parse_log_line(raw) {
            LogLine::BufferStart(buffer) => {
                self.buffer = Some(buffer);
                Vec::new()
            }
            LogLine::Unrecognized if raw.trim().is_empty() => Vec::new(),
            LogLine::Unrecognized => vec![
                Observation::new(Domain::Log, kinds::LOG, raw)
                    .with_severity(Severity::Verbose)
                    .with_attribute("unparsed", true)
                    .with_raw(raw),
            ],
            LogLine::Record(record) => self.normalize_record(&record, raw),
        }
    }

    fn normalize_record(&mut self, record: &LogRecord, raw: &str) -> Vec<Observation> {
        let observation = self.base_observation(record, raw);
        if LIFECYCLE_TAGS.contains(&record.tag.as_str())
            && let Some(observations) = self.lifecycle_from_event_log(record, &observation)
        {
            return observations;
        }
        let observation = match classify_failure(record) {
            Some((kind, app)) => {
                let failure = observation
                    .retyped(Domain::Lifecycle, kind)
                    .with_severity(Severity::Fatal);
                match app {
                    Some(app) => failure.with_app(app),
                    None => failure,
                }
            }
            None => observation,
        };
        vec![observation]
    }

    fn base_observation(&self, record: &LogRecord, raw: &str) -> Observation {
        let mut observation = Observation::new(Domain::Log, kinds::LOG, record.message.clone())
            .with_severity(record.severity)
            .with_subsystem(record.tag.clone())
            .with_pid(record.pid)
            .with_tid(record.tid)
            .with_raw(raw);
        if let Some(buffer) = &self.buffer {
            observation = observation.with_stream(buffer.clone());
        }
        observation = match &record.time {
            LogTime::Utc(time) => observation.with_device_time(*time),
            LogTime::DeviceLocal(text) => {
                observation.with_attribute("device_local_time", text.clone())
            }
        };
        self.attribute_app(observation, record)
    }

    /// Attributes a line to the app of its process. A line from another process (typically
    /// system_server) that names the target app is attributed to the target, keeping the process name.
    fn attribute_app(&self, observation: Observation, record: &LogRecord) -> Observation {
        let process_app = self
            .process_names
            .get(&record.pid)
            .map(|name| PackageName::owning_app_of(name));
        let mentioned_target = self
            .target
            .as_ref()
            .map(PackageName::as_str)
            .filter(|target| process_app != Some(*target) && mentions(&record.message, target));
        match (mentioned_target, process_app) {
            (Some(target), process_app) => {
                let observation = observation
                    .with_app(target)
                    .with_attribute("attribution", "message_mention");
                match process_app {
                    Some(process_app) => observation.with_attribute("logging_process", process_app),
                    None => observation,
                }
            }
            (None, Some(process_app)) => observation.with_app(process_app),
            (None, None) => observation,
        }
    }

    /// Normalizes a lifecycle event-log entry; `None` when its fields do not have the expected shape.
    fn lifecycle_from_event_log(
        &mut self,
        record: &LogRecord,
        template: &Observation,
    ) -> Option<Vec<Observation>> {
        let fields = event_log_fields(&record.message);
        match record.tag.as_str() {
            "am_proc_start" => self.process_started(&fields, template),
            "am_proc_died" => self.process_died(&fields, template, None),
            "am_kill" => self.process_died(&fields, template, Some(trailing_fields(&fields, 4))),
            "am_crash" => crash_reported(&fields, template),
            "am_anr" => anr_reported(&fields, template),
            _ => Some(self.resumed_activity_changed(&fields, template)),
        }
    }

    /// `am_proc_start: [user, pid, uid, process, start reason, component]`
    fn process_started(
        &mut self,
        fields: &[&str],
        template: &Observation,
    ) -> Option<Vec<Observation>> {
        let (pid, process) = (field(fields, 1).parse().ok()?, field(fields, 3));
        self.process_names.insert(pid, process.to_string());
        let started = derived(
            template,
            Domain::Process,
            kinds::PROCESS_STARTED,
            format!("process {process} started"),
        )
        .with_app(PackageName::owning_app_of(process))
        .with_pid(pid)
        .with_attribute("process", process)
        .with_attribute("start_reason", field(fields, 4))
        .with_attribute("component", field(fields, 5));
        Some(vec![started])
    }

    /// `am_proc_died: [user, pid, process, ...]` and `am_kill: [user, pid, process, adj, reason]`
    fn process_died(
        &mut self,
        fields: &[&str],
        template: &Observation,
        kill_reason: Option<String>,
    ) -> Option<Vec<Observation>> {
        let (pid, process) = (field(fields, 1).parse().ok()?, field(fields, 2));
        self.process_names.remove(&pid);
        let died = derived(
            template,
            Domain::Process,
            kinds::PROCESS_DIED,
            format!("process {process} died"),
        )
        .with_app(PackageName::owning_app_of(process))
        .with_pid(pid)
        .with_attribute("process", process);
        Some(vec![match kill_reason {
            Some(reason) => died.with_attribute("reason", reason),
            None => died,
        }])
    }

    /// `wm_set_resumed_activity: [user, package/activity, reason]`; reports only changes of app.
    fn resumed_activity_changed(
        &mut self,
        fields: &[&str],
        template: &Observation,
    ) -> Vec<Observation> {
        let package = field(fields, 1).split('/').next().unwrap_or_default();
        if package.is_empty() || self.foreground.as_deref() == Some(package) {
            return Vec::new();
        }
        let transition = |kind: &str, app: &str, verb: &str| {
            derived(
                template,
                Domain::Lifecycle,
                kind,
                format!("{app} moved to the {verb}"),
            )
            .with_app(app)
            .with_attribute("basis", "derived from a resumed-activity change")
        };
        let mut observations = Vec::new();
        if let Some(previous) = self.foreground.replace(package.to_string()) {
            observations.push(transition(kinds::APP_BACKGROUND, &previous, "background"));
        }
        observations.push(transition(kinds::APP_FOREGROUND, package, "foreground"));
        observations
    }
}

/// `am_crash: [user, pid, process, flags, exception, message, file, line]`
fn crash_reported(fields: &[&str], template: &Observation) -> Option<Vec<Observation>> {
    let (pid, process) = (field(fields, 1).parse().ok()?, field(fields, 2));
    let exception = field(fields, 4);
    let message = format!("{exception}: {}", field(fields, 5));
    let crash = derived(template, Domain::Lifecycle, kinds::APP_CRASH, message)
        .with_severity(Severity::Fatal)
        .with_app(PackageName::owning_app_of(process))
        .with_pid(pid)
        .with_attribute("exception", exception);
    Some(vec![crash])
}

/// `am_anr: [user, pid, package, flags, reason]`
fn anr_reported(fields: &[&str], template: &Observation) -> Option<Vec<Observation>> {
    let (pid, package) = (field(fields, 1).parse().ok()?, field(fields, 2));
    let message = format!("ANR in {package}: {}", trailing_fields(fields, 4));
    let anr = derived(template, Domain::Lifecycle, kinds::ANR, message)
        .with_severity(Severity::Fatal)
        .with_app(PackageName::owning_app_of(package))
        .with_pid(pid);
    Some(vec![anr])
}

fn field<'f>(fields: &[&'f str], index: usize) -> &'f str {
    fields.get(index).copied().unwrap_or_default()
}

/// Rejoins free-text fields that the comma split broke apart.
fn trailing_fields(fields: &[&str], from: usize) -> String {
    fields
        .get(from..)
        .map(|rest| rest.join(","))
        .unwrap_or_default()
}

/// An observation derived from a source line: same origin and raw text, new meaning.
fn derived(template: &Observation, domain: Domain, kind: &str, message: String) -> Observation {
    let mut observation = template.clone().retyped(domain, kind);
    observation.message = message;
    observation
}

/// Recognizes failure reports in the main and crash buffers; returns the kind and, if named, the app.
fn classify_failure(record: &LogRecord) -> Option<(&'static str, Option<String>)> {
    let message = record.message.as_str();
    match record.tag.as_str() {
        "AndroidRuntime" if message.starts_with("FATAL EXCEPTION") => {
            Some((kinds::APP_CRASH, None))
        }
        "libc" if message.starts_with("Fatal signal") => {
            Some((kinds::NATIVE_CRASH, native_crash_process(message)))
        }
        "ActivityManager" => message.strip_prefix("ANR in ").map(|rest| {
            let package = rest.split([' ', '(']).next().unwrap_or_default();
            (
                kinds::ANR,
                Some(PackageName::owning_app_of(package).to_string()),
            )
        }),
        _ => None,
    }
}

/// Extracts `com.example` from `Fatal signal 11 (SIGSEGV), ... in tid 77 (RenderThread), pid 77 (com.example)`.
fn native_crash_process(message: &str) -> Option<String> {
    let after_pid = &message[message.rfind(", pid ")?..];
    let name = after_pid.split_once('(')?.1.split(')').next()?;
    Some(PackageName::owning_app_of(name).to_string())
}

/// True when `package` appears in `text` as a whole identifier: `com.example` matches
/// `com.example/.Main` and `com.example.MainActivity`, but not `com.example2` or `org.com.example`.
fn mentions(text: &str, package: &str) -> bool {
    let is_identifier = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(package).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + package.len()..].chars().next();
        !before.is_some_and(|c| is_identifier(c) || c == '.') && !after.is_some_and(is_identifier)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalizer() -> LogcatNormalizer {
        let processes = vec![ProcessInfo {
            pid: 4000,
            ppid: None,
            user: None,
            name: "com.example".into(),
        }];
        LogcatNormalizer::new(Some("com.example".parse().expect("package")), &processes)
    }

    fn only(observations: Vec<Observation>) -> Observation {
        assert_eq!(observations.len(), 1, "{observations:?}");
        observations.into_iter().next().expect("one observation")
    }

    #[test]
    fn attributes_logs_to_apps_by_pid_and_keeps_the_raw_line() {
        let line = "1700000000.100  4000  4001 I Example: loaded";
        let observation = only(normalizer().normalize(line));
        assert_eq!(observation.kind, kinds::LOG);
        assert_eq!(observation.app.as_deref(), Some("com.example"));
        assert_eq!(observation.raw.as_deref(), Some(line));
        assert!(observation.device_time.is_some());
    }

    #[test]
    fn attributes_system_lines_that_mention_the_target_app() {
        let observation = only(normalizer().normalize(
            "1700000000.1  1000  1100 I ActivityManager: Force stopping com.example appid=10123",
        ));
        assert_eq!(observation.app.as_deref(), Some("com.example"));
        assert_eq!(observation.attributes["attribution"], "message_mention");
    }

    #[test]
    fn a_mention_of_the_target_wins_over_the_logging_process() {
        let mut normalizer = normalizer();
        normalizer
            .process_names
            .insert(1000, "system_server".into());
        let observation = only(normalizer.normalize(
            "1700000000.1  1000  1100 I ActivityManager: Killing 4000:com.example/u0a123",
        ));
        assert_eq!(observation.app.as_deref(), Some("com.example"));
        assert_eq!(observation.attributes["logging_process"], "system_server");
    }

    #[test]
    fn does_not_attribute_a_longer_package_that_shares_a_prefix() {
        let observation = only(
            normalizer()
                .normalize("1700000000.1  1000  1100 I ActivityManager: Start com.example2"),
        );
        assert_eq!(observation.app, None);
    }

    #[test]
    fn process_start_updates_attribution_for_later_lines() {
        let mut normalizer = normalizer();
        normalizer.normalize("--------- beginning of events");
        let started = only(normalizer.normalize(
            "1700000000.1  1000  1100 I am_proc_start: [0,5000,10123,com.example:remote,service,{com.example/.Sync}]",
        ));
        assert_eq!(started.kind, kinds::PROCESS_STARTED);
        assert_eq!(started.domain, Domain::Process);
        assert_eq!(started.pid, Some(5000));
        assert_eq!(started.app.as_deref(), Some("com.example"));

        normalizer.normalize("--------- beginning of main");
        let later = only(normalizer.normalize("1700000000.2  5000  5001 D Sync: tick"));
        assert_eq!(later.app.as_deref(), Some("com.example"));
    }

    #[test]
    fn process_death_is_normalized_with_the_kill_reason() {
        let died =
            only(normalizer().normalize(
                "1700000000.1  1000  1100 I am_kill: [0,4000,com.example,900,empty #17]",
            ));
        assert_eq!(died.kind, kinds::PROCESS_DIED);
        assert_eq!(died.attributes["reason"], "empty #17");
    }

    #[test]
    fn java_crashes_are_recognized_in_both_buffers() {
        let mut normalizer = normalizer();
        let fatal = only(
            normalizer
                .normalize("1700000000.1  4000  4000 E AndroidRuntime: FATAL EXCEPTION: main"),
        );
        assert_eq!(fatal.kind, kinds::APP_CRASH);
        assert_eq!(fatal.app.as_deref(), Some("com.example"));
        assert_eq!(fatal.severity, Severity::Fatal);

        let event_log = only(normalizer.normalize(
            "1700000000.2  1000  1100 I am_crash: [0,4000,com.example,948459078,java.lang.IllegalStateException,boom,Main.kt,12]",
        ));
        assert_eq!(event_log.kind, kinds::APP_CRASH);
        assert_eq!(event_log.message, "java.lang.IllegalStateException: boom");
    }

    #[test]
    fn native_crashes_and_anrs_name_the_affected_app() {
        let mut normalizer = normalizer();
        let native = only(normalizer.normalize(
            "1700000000.1  4100  4200 F libc: Fatal signal 11 (SIGSEGV), code 1, fault addr 0x0 in tid 4200 (RenderThread), pid 4100 (com.example)",
        ));
        assert_eq!(native.kind, kinds::NATIVE_CRASH);
        assert_eq!(native.app.as_deref(), Some("com.example"));

        let anr = only(normalizer.normalize(
            "1700000000.2  1000  1100 E ActivityManager: ANR in com.example (com.example/.MainActivity)",
        ));
        assert_eq!(anr.kind, kinds::ANR);
        assert_eq!(anr.app.as_deref(), Some("com.example"));
    }

    #[test]
    fn foreground_changes_produce_background_and_foreground_transitions() {
        let mut normalizer = normalizer();
        let first = normalizer
            .normalize("1700000000.1  1000  1100 I wm_set_resumed_activity: [0,com.example/.MainActivity,resumeTopActivity]");
        assert_eq!(
            first.iter().map(|o| o.kind.as_str()).collect::<Vec<_>>(),
            [kinds::APP_FOREGROUND]
        );

        let repeated = normalizer
            .normalize("1700000000.2  1000  1100 I wm_set_resumed_activity: [0,com.example/.Other,resumeTopActivity]");
        assert!(repeated.is_empty());

        let switched = normalizer
            .normalize("1700000000.3  1000  1100 I wm_set_resumed_activity: [0,com.android.launcher3/.Launcher,x]");
        let summary: Vec<(&str, Option<&str>)> = switched
            .iter()
            .map(|o| (o.kind.as_str(), o.app.as_deref()))
            .collect();
        assert_eq!(
            summary,
            [
                (kinds::APP_BACKGROUND, Some("com.example")),
                (kinds::APP_FOREGROUND, Some("com.android.launcher3"))
            ]
        );
    }

    #[test]
    fn unknown_event_log_tags_stay_log_events() {
        let mut normalizer = normalizer();
        normalizer.normalize("--------- beginning of events");
        let observation =
            only(normalizer.normalize("1700000000.1  1000  1100 I battery_level: [87,4100,250]"));
        assert_eq!(observation.kind, kinds::LOG);
        assert_eq!(observation.stream.as_deref(), Some("events"));
    }

    fn provider(api_level: u32) -> LogcatProvider {
        LogcatProvider::new(
            crate::adb::Adb::at("adb").device("SERIAL"),
            None,
            Some(api_level),
        )
    }

    #[test]
    fn epoch_start_times_are_only_used_where_logcat_accepts_them() {
        let setup = StreamSetup {
            readable_buffers: vec!["main"],
            device_epoch_seconds: Some(1_700_000_000),
        };
        assert_eq!(
            provider(34).command(&setup),
            "logcat -v threadtime -v epoch -b main -T 1700000000.0"
        );
        assert_eq!(
            provider(23).command(&setup),
            "logcat -v threadtime -b main -T 1"
        );
    }

    #[test]
    fn stream_setup_reads_buffers_and_device_time_from_one_output() {
        let setup = parse_stream_setup("buffer:main\nbuffer:events\nbuffer:bogus\n1700000000\n");
        assert_eq!(
            setup,
            StreamSetup {
                readable_buffers: vec!["main", "events"],
                device_epoch_seconds: Some(1_700_000_000),
            }
        );
        assert_eq!(
            parse_stream_setup("buffer:main\n").device_epoch_seconds,
            None
        );
    }

    #[test]
    fn unparsed_lines_are_kept_rather_than_dropped() {
        let observation = only(normalizer().normalize("garbled \u{fffd} output"));
        assert_eq!(observation.attributes["unparsed"], true);
    }
}
