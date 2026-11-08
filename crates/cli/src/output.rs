//! Rendering of command results as human-readable text, JSON or JSONL (CLI-003, CLI-004).
//!
//! Results go to stdout; progress and warnings go to stderr, so machine-readable output stays clean.

use std::io::{self, Write};

use chrono::{DateTime, Local, Utc};
use mobile_bridge_core::event::{Event, Severity};
use mobile_bridge_core::pipeline::EventConsumer;
use mobile_bridge_core::provider::ArtifactRef;
use mobile_bridge_core::session::CollectorOutcome;
use serde::Serialize;

use crate::cli::OutputFormat;
use crate::error::CliError;

#[derive(Debug, Clone, Copy)]
pub struct Output {
    format: OutputFormat,
}

impl Output {
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    pub fn is_human(self) -> bool {
        self.format == OutputFormat::Human
    }

    /// Prints a collection: an array in JSON, one object per line in JSONL.
    pub fn list<T: Serialize>(
        self,
        items: &[T],
        human: impl FnOnce(&[T]) -> String,
    ) -> Result<(), CliError> {
        match self.format {
            OutputFormat::Human => print_stdout(&human(items)),
            OutputFormat::Json => print_stdout(&to_pretty_json(&items)?),
            OutputFormat::Jsonl => {
                for item in items {
                    print_stdout(&to_json_line(item)?)?;
                }
                Ok(())
            }
        }
    }

    /// Prints one result object.
    pub fn item<T: Serialize>(
        self,
        item: &T,
        human: impl FnOnce(&T) -> String,
    ) -> Result<(), CliError> {
        match self.format {
            OutputFormat::Human => print_stdout(&human(item)),
            OutputFormat::Json => print_stdout(&to_pretty_json(item)?),
            OutputFormat::Jsonl => print_stdout(&to_json_line(item)?),
        }
    }
}

fn to_pretty_json<T: Serialize + ?Sized>(value: &T) -> Result<String, CliError> {
    serde_json::to_string_pretty(value).map_err(|error| CliError::failure(error.to_string()))
}

pub fn to_json_line<T: Serialize + ?Sized>(value: &T) -> Result<String, CliError> {
    serde_json::to_string(value).map_err(|error| CliError::failure(error.to_string()))
}

/// Writes a line to stdout. A closed pipe (for example `| head`) ends the program quietly.
pub fn print_stdout(text: &str) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    let written = if text.is_empty() {
        Ok(())
    } else {
        writeln!(stdout, "{}", text.trim_end_matches('\n')).and_then(|()| stdout.flush())
    };
    match written {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => std::process::exit(0),
        other => other.map_err(CliError::from),
    }
}

pub fn status(message: &str) {
    eprintln!("{message}");
}

pub fn warning(message: &str) {
    eprintln!("warning: {message}");
}

/// Formats rows as left-aligned columns separated by two spaces.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if let Some(width) = widths.get_mut(index) {
                *width = (*width).max(cell.chars().count());
            }
        }
    }
    let format_row = |cells: Vec<&str>| {
        let last = cells.len().saturating_sub(1);
        cells
            .iter()
            .enumerate()
            .map(|(index, cell)| {
                if index == last {
                    (*cell).to_string()
                } else {
                    format!("{cell:<width$}", width = widths[index])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut lines = vec![format_row(headers.to_vec())];
    lines.extend(
        rows.iter()
            .map(|row| format_row(row.iter().map(String::as_str).collect())),
    );
    lines.join("\n")
}

pub fn local_time(time: DateTime<Utc>) -> String {
    time.with_timezone(&Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

/// One-line rendering of an event for terminals.
pub fn event_line(event: &Event) -> String {
    let time = event
        .time
        .best()
        .with_timezone(&Local)
        .format("%H:%M:%S%.3f");
    let origin = match (&event.subsystem, event.pid) {
        (Some(subsystem), Some(pid)) => format!("{subsystem}[{pid}]"),
        (Some(subsystem), None) => subsystem.clone(),
        (None, Some(pid)) => format!("{}[{pid}]", event.kind),
        (None, None) => event.kind.clone(),
    };
    let app = event
        .app
        .as_deref()
        .map(|app| format!(" {app}"))
        .unwrap_or_default();
    format!(
        "{time} #{:<6} {} {:<10} {origin}{app}: {}",
        event.sequence,
        event.severity.letter(),
        event.domain.as_str(),
        event.message
    )
}

/// One line per collector outcome, with its notes.
pub fn collector_lines(collectors: &[CollectorOutcome]) -> Vec<String> {
    let mut lines = Vec::new();
    for collector in collectors {
        let error = collector
            .error
            .as_deref()
            .map(|error| format!(" - {error}"))
            .unwrap_or_default();
        lines.push(format!(
            "  collector {:<10} {}, {} events{error}",
            collector.provider, collector.status, collector.events_emitted
        ));
        lines.extend(
            collector
                .notes
                .iter()
                .map(|note| format!("      note: {note}")),
        );
    }
    lines
}

pub fn artifact_lines(artifacts: &[ArtifactRef]) -> Vec<String> {
    artifacts
        .iter()
        .map(|artifact| {
            format!(
                "  artifact {} ({} KiB): {}",
                artifact.path,
                artifact.bytes / 1024,
                artifact.description
            )
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamStyle {
    Text,
    JsonLines,
}

/// Prints events live while recording (EVT-009).
pub struct EventStream {
    style: StreamStyle,
    minimum: Option<Severity>,
}

impl EventStream {
    pub fn new(style: StreamStyle, minimum: Option<Severity>) -> Self {
        Self { style, minimum }
    }
}

impl EventConsumer for EventStream {
    fn consume(&mut self, event: &Event) -> Result<(), String> {
        if self.minimum.is_some_and(|minimum| event.severity < minimum) {
            return Ok(());
        }
        let line = match self.style {
            StreamStyle::JsonLines => to_json_line(event).map_err(|error| error.message)?,
            StreamStyle::Text => event_line(event),
        };
        print_stdout(&line).map_err(|error| error.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_align_every_column_but_the_last() {
        let rendered = table(
            &["ID", "STATE", "MODEL"],
            &[
                vec!["A1".into(), "ready".into(), "Pixel 7".into()],
                vec!["LONGSERIAL".into(), "offline".into(), "-".into()],
            ],
        );
        assert_eq!(
            rendered,
            "ID          STATE    MODEL\nA1          ready    Pixel 7\nLONGSERIAL  offline  -"
        );
    }
}
