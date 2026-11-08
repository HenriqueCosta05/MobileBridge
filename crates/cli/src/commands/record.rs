//! `record`: runs a diagnostic session (SES-001 to SES-004, SES-006, SES-010, EVT-009, MON-012).

use std::io::BufRead;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use mobile_bridge_android::providers::{CollectorOptions, CollectorSelection, select_collectors};
use mobile_bridge_android::{AndroidDevice, PackageName};
use mobile_bridge_core::device::Capability;
use mobile_bridge_core::filter::Retention;
use mobile_bridge_core::pipeline::{
    EventConsumer, Recorder, RecordingControls, RecordingSetup, RecordingSummary,
};
use mobile_bridge_core::provider::{Provider, probe_all};
use mobile_bridge_core::redact::Redactor;
use mobile_bridge_core::session::{
    CollectorOutcome, RecordingConfiguration, SessionManifest, SessionStart, ToolInfo,
};
use serde::Serialize;

use crate::cli::{OutputFormat, RecordArgs};
use crate::context::Context;
use crate::error::{CliError, ExitStatus};
use crate::output::{self, EventStream, StreamStyle};

const QUEUE_CAPACITY: usize = 4096;
/// Time collectors get to finish after a stop, long enough to stop and pull a system trace.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(60);
/// Lets a trace outlive a timed recording slightly, so the recording, not perfetto, decides when to stop.
const TRACE_DURATION_MARGIN: Duration = Duration::from_secs(15);
const INTERRUPTED_EXIT_CODE: i32 = 130;

pub async fn run(context: &Context, args: RecordArgs) -> Result<(), CliError> {
    let redactor = redactor(context, args.no_redact)?;
    let adapter = context.adapter()?;
    let device = context.open_device(&adapter).await?;
    let target = resolve_target(&device, args.app.as_deref()).await?;
    let duration = args.duration.or(context.config.record.duration);
    let selection = select_collectors(requested_collectors(context, &args), target.is_some())
        .map_err(CliError::failure)?;
    if !args.collectors.is_empty() {
        for (collector, reason) in &selection.skipped {
            output::warning(&format!("skipping {collector}: {reason}"));
        }
    }
    let options = collector_options(context, &args, target.clone(), duration);
    let collectors = prepare_collectors(&device, &selection, &options).await;
    if collectors.runnable.is_empty() {
        return Err(CliError::new(
            ExitStatus::Unsupported,
            "none of the selected collectors can run on this device",
        )
        .with_remediation("Run 'mobile-bridge devices show' to see why."));
    }

    let retention = match (&target, args.all_logs) {
        (Some(target), false) => Retention::TargetApps(vec![target.to_string()]),
        _ => Retention::All,
    };
    let mut manifest = SessionManifest::recording(SessionStart {
        name: args.name.clone(),
        started_at: Utc::now(),
        tool: ToolInfo::current(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        device: device.metadata().clone(),
        target_apps: target.iter().map(ToString::to_string).collect(),
        configuration: RecordingConfiguration {
            collectors: collectors
                .runnable
                .iter()
                .map(|provider| provider.id().to_string())
                .collect(),
            duration_seconds: duration.map(|duration| duration.as_secs()),
            retention: retention.clone(),
            redaction_rules: redactor.rule_names(),
            queue_capacity: QUEUE_CAPACITY,
        },
        capabilities: collectors.capabilities,
        skipped_collectors: collectors.skipped,
    });
    let store = context.store()?;
    let mut writer = store.create(&manifest)?;

    let setup = RecordingSetup {
        session_id: manifest.id.clone(),
        device_id: manifest.device.id.clone(),
        artifact_dir: writer.artifact_dir(),
        duration,
        queue_capacity: QUEUE_CAPACITY,
        shutdown_grace: SHUTDOWN_GRACE,
        retention,
        redactor,
    };
    let (recorder, controls) = Recorder::new(setup, collectors.runnable);
    handle_interrupts(controls.clone());
    let reads_markers = context.is_interactive() && context.output.is_human();
    if reads_markers {
        read_markers_from_stdin(controls);
    }
    announce(&manifest, duration, reads_markers);

    let mut stream = live_stream(&args, context.global.format);
    let summary = {
        let mut consumers: Vec<&mut dyn EventConsumer> = vec![&mut writer];
        if let Some(stream) = stream.as_mut() {
            consumers.push(stream);
        }
        recorder.run(&mut consumers).await
    };

    manifest.finish(&summary, Utc::now());
    writer.finalize(&manifest)?;
    report(
        context,
        &store.session_dir(&manifest.id),
        &manifest,
        &summary,
    )
}

fn redactor(context: &Context, disabled: bool) -> Result<Redactor, CliError> {
    if disabled {
        output::warning(
            "redaction is disabled; credentials and personal data will be stored as collected",
        );
        return Ok(Redactor::disabled());
    }
    context.config.redactor()
}

async fn resolve_target(
    device: &AndroidDevice,
    app: Option<&str>,
) -> Result<Option<PackageName>, CliError> {
    let Some(app) = app else {
        output::warning(
            "no --app given: recording device-wide evidence; process sampling is disabled",
        );
        return Ok(None);
    };
    let package: PackageName = app.parse().map_err(CliError::failure)?;
    if !device.is_installed(&package).await? {
        return Err(CliError::new(
            ExitStatus::NotFound,
            format!(
                "'{package}' is not installed on device {}",
                device.metadata().id
            ),
        )
        .with_remediation(
            "Run 'mobile-bridge apps list --third-party' to see installed applications.",
        ));
    }
    Ok(Some(package))
}

/// Collectors named on the command line, else in the configuration; empty means all of them.
fn requested_collectors<'a>(context: &'a Context, args: &'a RecordArgs) -> &'a [String] {
    if args.collectors.is_empty() {
        context
            .config
            .record
            .collectors
            .as_deref()
            .unwrap_or_default()
    } else {
        &args.collectors
    }
}

fn collector_options(
    context: &Context,
    args: &RecordArgs,
    target: Option<PackageName>,
    duration: Option<Duration>,
) -> CollectorOptions {
    let defaults = CollectorOptions::default();
    let mut trace = context.config.trace_options();
    if let Some(duration) = duration {
        trace.max_duration = duration + TRACE_DURATION_MARGIN;
    }
    CollectorOptions {
        target,
        sample_interval: args
            .sample_interval
            .or(context.config.record.sample_interval)
            .unwrap_or(defaults.sample_interval),
        trace,
    }
}

/// Providers that can run, every capability probed, and the selected collectors that will not run.
struct PreparedCollectors {
    runnable: Vec<Arc<dyn Provider>>,
    capabilities: Vec<Capability>,
    skipped: Vec<CollectorOutcome>,
}

/// Probes the selected collectors and keeps those that can run, explaining the others (DEV-009).
async fn prepare_collectors(
    device: &AndroidDevice,
    selection: &CollectorSelection,
    options: &CollectorOptions,
) -> PreparedCollectors {
    let mut prepared = PreparedCollectors {
        runnable: Vec::new(),
        capabilities: device.device_capabilities().await,
        skipped: selection
            .skipped
            .iter()
            .map(|(collector, reason)| CollectorOutcome::skipped(collector, reason))
            .collect(),
    };
    for probed in probe_all(device.providers(selection, options)).await {
        let capability = probed.capability;
        let hint = capability
            .remediation
            .as_deref()
            .map(|hint| format!(" ({hint})"))
            .unwrap_or_default();
        if capability.is_usable() {
            if !hint.is_empty() {
                output::warning(&format!("{}: {}{hint}", capability.id, capability.detail));
            }
            prepared.runnable.push(probed.provider);
        } else {
            output::warning(&format!(
                "skipping {}: {}{hint}",
                capability.id, capability.detail
            ));
            prepared.skipped.push(CollectorOutcome::skipped(
                &capability.id,
                &capability.detail,
            ));
        }
        prepared.capabilities.push(capability);
    }
    prepared
}

/// The live view of the recording (EVT-009); none with --no-stream or when one JSON document is expected.
fn live_stream(args: &RecordArgs, format: OutputFormat) -> Option<EventStream> {
    let style = match format {
        _ if args.no_stream => return None,
        OutputFormat::Json => return None,
        OutputFormat::Jsonl => StreamStyle::JsonLines,
        OutputFormat::Human => StreamStyle::Text,
    };
    Some(EventStream::new(style, args.stream_severity))
}

/// First Ctrl-C stops gracefully; a second one quits and leaves the session unfinalized.
fn handle_interrupts(controls: RecordingControls) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            output::status(
                "Stopping: letting collectors finish (press Ctrl-C again to quit immediately)...",
            );
            controls.request_stop();
        }
        if tokio::signal::ctrl_c().await.is_ok() {
            output::status("Interrupted: the session was not finalized and may be incomplete.");
            std::process::exit(INTERRUPTED_EXIT_CODE);
        }
    });
}

/// Each line typed while recording becomes a marker (SES-004). A plain thread is used because blocking
/// stdin reads would otherwise keep the async runtime from shutting down.
fn read_markers_from_stdin(controls: RecordingControls) {
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if controls.blocking_add_marker(line).is_err() {
                break;
            }
        }
    });
}

fn announce(manifest: &SessionManifest, duration: Option<Duration>, reads_markers: bool) {
    let device = manifest
        .device
        .model
        .as_deref()
        .unwrap_or(&manifest.device.id);
    let target = manifest
        .target_apps
        .first()
        .map(|app| format!(" for {app}"))
        .unwrap_or_default();
    let until = duration.map_or_else(
        || "until Ctrl-C".to_string(),
        |duration| format!("for {}s (Ctrl-C stops earlier)", duration.as_secs()),
    );
    output::status(&format!(
        "Recording session {} on {device}{target} {until}. Collectors: {}.",
        manifest.id,
        manifest.configuration.collectors.join(", ")
    ));
    if reads_markers {
        output::status("Type a note and press Enter to add a marker.");
    }
}

#[derive(Debug, Serialize)]
struct RecordResult<'a> {
    session_id: &'a str,
    path: String,
    status: mobile_bridge_core::session::SessionStatus,
    stop_reason: Option<mobile_bridge_core::session::StopReason>,
    event_count: u64,
    redaction_count: u64,
    collectors: &'a [CollectorOutcome],
    artifacts: &'a [mobile_bridge_core::provider::ArtifactRef],
}

impl<'a> RecordResult<'a> {
    fn new(manifest: &'a SessionManifest, session_dir: &Path) -> Self {
        Self {
            session_id: &manifest.id,
            path: session_dir.display().to_string(),
            status: manifest.status,
            stop_reason: manifest.stop_reason,
            event_count: manifest.event_count,
            redaction_count: manifest.redaction_count,
            collectors: &manifest.collectors,
            artifacts: &manifest.artifacts,
        }
    }
}

fn report(
    context: &Context,
    session_dir: &Path,
    manifest: &SessionManifest,
    summary: &RecordingSummary,
) -> Result<(), CliError> {
    let result = RecordResult::new(manifest, session_dir);
    match context.global.format {
        OutputFormat::Human => output::status(&render_result(&result)),
        OutputFormat::Json => context.output.item(&result, |_| String::new())?,
        // The JSON lines on stdout are the event stream; a summary object would break that contract.
        OutputFormat::Jsonl => {}
    }
    if let Some(error) = &summary.consumer_error {
        return Err(CliError::failure(format!(
            "the recording stopped early: {error}"
        )));
    }
    let incomplete = summary.incomplete_collectors();
    if incomplete.is_empty() {
        return Ok(());
    }
    Err(CliError::new(
        ExitStatus::Partial,
        format!(
            "evidence is incomplete: collectors {} did not complete",
            incomplete.join(", ")
        ),
    )
    .with_remediation(format!(
        "See 'mobile-bridge sessions show {}'.",
        manifest.id
    )))
}

fn render_result(result: &RecordResult<'_>) -> String {
    let stop_reason = result
        .stop_reason
        .map(|reason| reason.to_string())
        .unwrap_or_default();
    let mut lines = vec![
        String::new(),
        format!("Session {} saved to {}", result.session_id, result.path),
        format!(
            "  {} events, {} redactions, stopped because: {stop_reason}",
            result.event_count, result.redaction_count
        ),
    ];
    lines.extend(output::collector_lines(result.collectors));
    lines.extend(output::artifact_lines(result.artifacts));
    lines.push(format!(
        "Next: mobile-bridge sessions analyze {}",
        result.session_id
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(no_stream: bool) -> RecordArgs {
        RecordArgs {
            app: None,
            duration: None,
            collectors: Vec::new(),
            name: None,
            all_logs: false,
            no_redact: false,
            no_stream,
            stream_severity: None,
            sample_interval: None,
        }
    }

    #[test]
    fn events_stream_as_text_or_json_lines_but_not_inside_a_json_document() {
        assert!(live_stream(&args(false), OutputFormat::Human).is_some());
        assert!(live_stream(&args(false), OutputFormat::Jsonl).is_some());
        assert!(live_stream(&args(false), OutputFormat::Json).is_none());
        assert!(live_stream(&args(true), OutputFormat::Human).is_none());
    }
}
