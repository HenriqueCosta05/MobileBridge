//! `sessions` subcommands: list, show, events, timeline, analyze, export, delete.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::Path;

use mobile_bridge_core::analysis::{AnalysisOptions, Finding, analyze, timeline};
use mobile_bridge_core::event::Event;
use mobile_bridge_core::export::{write_archive, write_json, write_jsonl};
use mobile_bridge_core::filter::EventFilter;
use mobile_bridge_core::private_fs;
use mobile_bridge_core::session::{SessionManifest, SessionStatus, SessionStore, StoredEvents};
use serde::Serialize;

use super::devices::render_capabilities;
use crate::cli::{ExportFormat, FilterArgs};
use crate::context::Context;
use crate::error::{CliError, ExitStatus};
use crate::output::{self, event_line, local_time, print_stdout, table};

pub fn list(context: &Context) -> Result<(), CliError> {
    let listing = context.store()?.list()?;
    for path in &listing.unreadable {
        output::warning(&format!(
            "skipping {}: its session.json cannot be read",
            path.display()
        ));
    }
    let manifests = listing.manifests;
    context.output.list(&manifests, |manifests| {
        if manifests.is_empty() {
            return "No sessions recorded yet. Start one with 'mobile-bridge record --app <package>'.".into();
        }
        let rows: Vec<Vec<String>> = manifests
            .iter()
            .map(|manifest| {
                vec![
                    manifest.id.clone(),
                    local_time(manifest.started_at),
                    status_label(manifest.status).to_string(),
                    manifest.device.model.clone().unwrap_or_else(|| manifest.device.id.clone()),
                    manifest.target_apps.join(",").chars().take(40).collect(),
                    manifest.event_count.to_string(),
                    manifest.name.clone().unwrap_or_default(),
                ]
            })
            .collect();
        table(&["ID", "STARTED", "STATUS", "DEVICE", "APP", "EVENTS", "NAME"], &rows)
    })
}

fn status_label(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Recording => "recording/interrupted",
        SessionStatus::Completed => "completed",
        SessionStatus::Partial => "partial",
    }
}

pub fn show(context: &Context, reference: &str) -> Result<(), CliError> {
    let store = context.store()?;
    let manifest = store.manifest(&store.resolve(reference)?)?;
    context
        .output
        .item(&manifest, |manifest| render_manifest(manifest, &store))
}

fn render_manifest(manifest: &SessionManifest, store: &SessionStore) -> String {
    let device = &manifest.device;
    let mut lines = vec![
        format!("Session:     {}", manifest.id),
        format!("Name:        {}", manifest.name.as_deref().unwrap_or("-")),
        format!("Status:      {}", status_label(manifest.status)),
        format!("Started:     {}", local_time(manifest.started_at)),
        format!(
            "Ended:       {}",
            manifest.ended_at.map_or_else(|| "-".into(), local_time)
        ),
        format!(
            "Stop reason: {}",
            manifest
                .stop_reason
                .map_or_else(|| "-".into(), |reason| reason.to_string())
        ),
        format!(
            "Device:      {} {} (Android {}, API {})",
            device.manufacturer.as_deref().unwrap_or("?"),
            device.model.as_deref().unwrap_or(&device.id),
            device.os_version.as_deref().unwrap_or("?"),
            device
                .api_level
                .map_or_else(|| "?".into(), |api| api.to_string())
        ),
        format!(
            "Apps:        {}",
            if manifest.target_apps.is_empty() {
                "-".into()
            } else {
                manifest.target_apps.join(", ")
            }
        ),
        format!(
            "Events:      {} ({} redactions)",
            manifest.event_count, manifest.redaction_count
        ),
        format!(
            "Redaction:   {}",
            if manifest.configuration.redaction_rules.is_empty() {
                "disabled".to_string()
            } else {
                manifest.configuration.redaction_rules.join(", ")
            }
        ),
        format!("Location:    {}", store.session_dir(&manifest.id).display()),
        String::new(),
    ];
    let rows: Vec<Vec<String>> = manifest
        .collectors
        .iter()
        .map(|collector| {
            vec![
                collector.provider.clone(),
                collector.status.to_string(),
                collector.events_emitted.to_string(),
                collector.error.clone().unwrap_or_default(),
            ]
        })
        .collect();
    lines.push(table(&["COLLECTOR", "STATUS", "EVENTS", "ERROR"], &rows));
    for collector in &manifest.collectors {
        lines.extend(
            collector
                .notes
                .iter()
                .map(|note| format!("  {}: {note}", collector.provider)),
        );
    }
    if !manifest.artifacts.is_empty() {
        lines.push(String::new());
        lines.extend(output::artifact_lines(&manifest.artifacts));
    }
    lines.push(String::new());
    lines.push(render_capabilities(&manifest.capabilities));
    lines.join("\n")
}

/// Which order to print events in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOrder {
    /// Arrival order, as recorded.
    Collection,
    /// By best-known timestamp (DIA-001).
    Chronological,
}

pub fn events(
    context: &Context,
    reference: &str,
    filter_args: FilterArgs,
    order: EventOrder,
) -> Result<(), CliError> {
    let (_, stored) = load(context, reference)?;
    let limit = filter_args.limit;
    let filter = event_filter(filter_args);
    let mut selected: Vec<&Event> = match order {
        EventOrder::Collection => stored
            .events
            .iter()
            .filter(|event| filter.matches(event))
            .collect(),
        EventOrder::Chronological => timeline(&stored.events, &filter),
    };
    if let Some(limit) = limit {
        selected.truncate(limit);
    }
    context.output.list(&selected, |events| {
        if events.is_empty() {
            return "No events match.".into();
        }
        events
            .iter()
            .map(|event| event_line(event))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

fn event_filter(args: FilterArgs) -> EventFilter {
    EventFilter {
        apps: args.apps,
        pids: args.pids,
        subsystems: args.subsystems,
        domains: args.domains,
        kinds: args.kinds,
        min_severity: args.min_severity,
        text: args.grep,
    }
}

fn load(context: &Context, reference: &str) -> Result<(SessionManifest, StoredEvents), CliError> {
    let store = context.store()?;
    let id = store.resolve(reference)?;
    load_resolved(&store, &id)
}

fn load_resolved(
    store: &SessionStore,
    id: &str,
) -> Result<(SessionManifest, StoredEvents), CliError> {
    let manifest = store.manifest(id)?;
    let stored = store.read_events(id)?;
    if !stored.unreadable_lines.is_empty() {
        output::warning(&format!(
            "{} unreadable line(s) in the event log were skipped (lines {:?})",
            stored.unreadable_lines.len(),
            stored.unreadable_lines
        ));
    }
    Ok((manifest, stored))
}

#[derive(Debug, Serialize)]
struct AnalysisReport<'a> {
    session_id: &'a str,
    findings: &'a [Finding],
    unreadable_lines: &'a [usize],
}

pub fn analyze_session(context: &Context, reference: &str) -> Result<(), CliError> {
    let (manifest, stored) = load(context, reference)?;
    let findings = analyze(&manifest, &stored, &AnalysisOptions::default());
    let report = AnalysisReport {
        session_id: &manifest.id,
        findings: &findings,
        unreadable_lines: &stored.unreadable_lines,
    };
    context.output.item(&report, |report| {
        render_findings(report.findings, &stored.events)
    })
}

fn render_findings(findings: &[Finding], events: &[Event]) -> String {
    if findings.is_empty() {
        return "No crashes, ANRs or collection gaps were found in the recorded evidence.\n\
                This does not prove their absence: only what the collectors could observe was analyzed."
            .into();
    }
    let by_sequence: HashMap<u64, &Event> =
        events.iter().map(|event| (event.sequence, event)).collect();
    let render_events = |sequences: &[u64]| -> Vec<String> {
        sequences
            .iter()
            .filter_map(|sequence| by_sequence.get(sequence))
            .map(|event| format!("      {}", event_line(event)))
            .collect()
    };
    let mut lines = Vec::new();
    for (index, finding) in findings.iter().enumerate() {
        let time = finding.time.map(local_time).unwrap_or_default();
        lines.push(format!(
            "{}. [{}] {} {time}\n   {}",
            index + 1,
            finding.basis,
            finding.kind,
            finding.summary
        ));
        if !finding.evidence.is_empty() {
            lines.push("   evidence:".into());
            lines.extend(render_events(&finding.evidence));
        }
        if !finding.preceding.is_empty() {
            lines.push("   preceding events (correlated in time only, not a proven cause):".into());
            lines.extend(render_events(&finding.preceding));
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

pub fn export(
    context: &Context,
    reference: &str,
    format: ExportFormat,
    destination: &Path,
    force: bool,
) -> Result<(), CliError> {
    let store = context.store()?;
    let id = store.resolve(reference)?;
    let written = match format {
        ExportFormat::Archive => write_archive(&store.session_dir(&id), &id, destination),
        ExportFormat::Json | ExportFormat::Jsonl => {
            let (manifest, stored) = load_resolved(&store, &id)?;
            let open = if force {
                private_fs::create_or_truncate
            } else {
                private_fs::create_new
            };
            open(destination).and_then(|file| match format {
                ExportFormat::Json => write_json(&manifest, &stored.events, file),
                _ => write_jsonl(&stored.events, file),
            })
        }
    };
    written.map_err(|error| export_error(destination, &error))?;
    output::status(&format!(
        "Exported session {id} to {}. It may contain sensitive data; share it with care.",
        destination.display()
    ));
    Ok(())
}

fn export_error(destination: &Path, error: &io::Error) -> CliError {
    let error_message = CliError::failure(format!(
        "cannot export to {}: {error}",
        destination.display()
    ));
    if error.kind() == io::ErrorKind::AlreadyExists {
        error_message.with_remediation(
            "Choose another --output path, or pass --force (json and jsonl only).",
        )
    } else {
        error_message
    }
}

pub fn delete(context: &Context, reference: &str, confirmed: bool) -> Result<(), CliError> {
    let store = context.store()?;
    let id = store.resolve(reference)?;
    if !confirmed {
        if !context.is_interactive() {
            return Err(CliError::failure(format!(
                "refusing to delete session {id} without confirmation"
            ))
            .with_remediation("Pass --yes to delete without a prompt."));
        }
        eprint!("Permanently delete session {id} and all its artifacts? [y/N] ");
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return Err(CliError::new(ExitStatus::Failure, "deletion cancelled"));
        }
    }
    store.delete(&id)?;
    print_stdout(&format!("Deleted session {id}."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_analysis_says_absence_is_not_proven() {
        assert!(render_findings(&[], &[]).contains("does not prove"));
    }
}
