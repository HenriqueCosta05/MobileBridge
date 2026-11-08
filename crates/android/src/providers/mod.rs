//! Android instrumentation providers. Each implements the core [`Provider`] contract, so the engine
//! runs them without knowing anything about Android (ARC-002, ARC-008).

use std::sync::Arc;
use std::time::Duration;

use mobile_bridge_core::provider::{Provider, ProviderError};

use crate::adb::{AdbError, DeviceConnection};
use crate::package::PackageName;
use crate::parse::processes::{ProcessInfo, parse_process_list};

pub mod logcat;
pub mod perfetto;
pub mod processes;
pub mod services;

pub const LOGCAT: &str = "logcat";
pub const PROCESSES: &str = "processes";
pub const PERFETTO: &str = "perfetto";
pub const SERVICES: &str = "services";

/// A collector the Android adapter offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectorSpec {
    pub id: &'static str,
    /// Whether the collector only works for a specific application.
    pub needs_target: bool,
}

pub const COLLECTORS: [CollectorSpec; 4] = [
    CollectorSpec {
        id: LOGCAT,
        needs_target: false,
    },
    CollectorSpec {
        id: PROCESSES,
        needs_target: true,
    },
    CollectorSpec {
        id: PERFETTO,
        needs_target: false,
    },
    CollectorSpec {
        id: SERVICES,
        needs_target: false,
    },
];

/// Validated collector choice: what will be built, and what was left out and why.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CollectorSelection {
    pub chosen: Vec<CollectorSpec>,
    pub skipped: Vec<(&'static str, String)>,
}

/// Validates requested collector names; an empty request selects every collector (MON-012).
/// Collectors needing a target app are skipped, with a reason, when there is none.
pub fn select_collectors(
    requested: &[String],
    has_target: bool,
) -> Result<CollectorSelection, String> {
    let mut selection = CollectorSelection::default();
    let specs: Vec<CollectorSpec> = if requested.is_empty() {
        COLLECTORS.to_vec()
    } else {
        requested
            .iter()
            .map(|name| collector_spec(name))
            .collect::<Result<_, _>>()?
    };
    for spec in specs {
        if selection.chosen.contains(&spec)
            || selection.skipped.iter().any(|(id, _)| *id == spec.id)
        {
            continue;
        }
        if spec.needs_target && !has_target {
            selection
                .skipped
                .push((spec.id, "needs a target application (--app)".to_string()));
        } else {
            selection.chosen.push(spec);
        }
    }
    Ok(selection)
}

fn collector_spec(name: &str) -> Result<CollectorSpec, String> {
    COLLECTORS
        .iter()
        .copied()
        .find(|spec| spec.id == name)
        .ok_or_else(|| {
            let names: Vec<&str> = COLLECTORS.iter().map(|spec| spec.id).collect();
            format!(
                "unknown collector '{name}' (available: {})",
                names.join(", ")
            )
        })
}

#[derive(Debug, Clone)]
pub struct CollectorOptions {
    pub target: Option<PackageName>,
    pub sample_interval: Duration,
    pub trace: perfetto::TraceOptions,
}

impl Default for CollectorOptions {
    fn default() -> Self {
        Self {
            target: None,
            sample_interval: Duration::from_secs(2),
            trace: perfetto::TraceOptions::default(),
        }
    }
}

/// Builds the providers of a validated selection. A collector needing a target is only part of a
/// selection when there is one, which [`select_collectors`] guarantees.
pub fn build_providers(
    device: &DeviceConnection,
    api_level: Option<u32>,
    selection: &CollectorSelection,
    options: &CollectorOptions,
) -> Vec<Arc<dyn Provider>> {
    let target = options.target.clone();
    selection
        .chosen
        .iter()
        .filter_map(|spec| -> Option<Arc<dyn Provider>> {
            Some(match spec.id {
                LOGCAT => Arc::new(logcat::LogcatProvider::new(
                    device.clone(),
                    target.clone(),
                    api_level,
                )),
                PROCESSES => Arc::new(processes::ProcessMonitor::new(
                    device.clone(),
                    target.clone()?,
                    options.sample_interval,
                )),
                PERFETTO => Arc::new(perfetto::PerfettoProvider::new(
                    device.clone(),
                    api_level,
                    target.clone(),
                    options.trace.clone(),
                )),
                SERVICES => Arc::new(services::ServiceSnapshots::new(
                    device.clone(),
                    target.clone(),
                )),
                _ => return None,
            })
        })
        .collect()
}

/// The `ps` invocation that works on a device: toybox (Android 8+) or legacy toolbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessListing {
    Toybox,
    Legacy,
}

impl ProcessListing {
    fn command(self) -> &'static str {
        match self {
            Self::Toybox => "ps -A -o PID,PPID,USER,NAME",
            Self::Legacy => "ps",
        }
    }

    /// Detects the working variant and returns its first listing.
    pub async fn detect(device: &DeviceConnection) -> Result<(Self, Vec<ProcessInfo>), AdbError> {
        let toybox = parse_process_list(
            &device
                .shell(Self::Toybox.command())
                .await
                .unwrap_or_default(),
        );
        if !toybox.is_empty() {
            return Ok((Self::Toybox, toybox));
        }
        let legacy = parse_process_list(&device.shell(Self::Legacy.command()).await?);
        Ok((Self::Legacy, legacy))
    }

    pub async fn list(self, device: &DeviceConnection) -> Result<Vec<ProcessInfo>, AdbError> {
        Ok(parse_process_list(&device.shell(self.command()).await?))
    }
}

/// Lists processes once, with whichever `ps` variant the device supports.
pub async fn list_processes(device: &DeviceConnection) -> Result<Vec<ProcessInfo>, AdbError> {
    ProcessListing::detect(device)
        .await
        .map(|(_, processes)| processes)
}

pub(crate) fn source_error(error: AdbError) -> ProviderError {
    ProviderError::Source(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn chosen(selection: &CollectorSelection) -> Vec<&'static str> {
        selection.chosen.iter().map(|spec| spec.id).collect()
    }

    #[test]
    fn every_collector_is_selected_by_default_when_there_is_a_target() {
        let selection = select_collectors(&[], true).expect("valid");
        assert_eq!(chosen(&selection), [LOGCAT, PROCESSES, PERFETTO, SERVICES]);
        assert!(selection.skipped.is_empty());
    }

    #[test]
    fn target_only_collectors_are_skipped_with_a_reason_without_a_target() {
        let selection = select_collectors(&[], false).expect("valid");
        assert!(!chosen(&selection).contains(&PROCESSES));
        assert_eq!(selection.skipped[0].0, PROCESSES);
    }

    #[test]
    fn duplicates_collapse_and_unknown_names_list_the_valid_ones() {
        let selection = select_collectors(&names(&["logcat", "logcat"]), true).expect("valid");
        assert_eq!(chosen(&selection), [LOGCAT]);
        let error = select_collectors(&names(&["strace"]), true).expect_err("unknown");
        assert!(error.contains("logcat"));
    }
}
