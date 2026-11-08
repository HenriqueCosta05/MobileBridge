//! Process and resource monitor for the target app (APP-002, APP-004, APP-006, MON-004).
//!
//! Polls the process table and `/proc` at a fixed interval, so process start and death times are
//! accurate only to that interval; logcat's event log reports them precisely when available.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use async_trait::async_trait;
use mobile_bridge_core::device::Capability;
use mobile_bridge_core::event::{Domain, Observation, Severity, kinds};
use mobile_bridge_core::provider::{Provider, ProviderContext, ProviderError, ProviderReport};

use super::{PROCESSES, ProcessListing, source_error};
use crate::adb::DeviceConnection;
use crate::package::PackageName;
use crate::parse::processes::{
    ProcessInfo, ProcessSample, ResourceSnapshot, parse_resource_snapshot,
    resource_sampling_command,
};

/// Android's USER_HZ, the unit of CPU times in `/proc/<pid>/stat`.
const CLOCK_TICKS_PER_SECOND: f64 = 100.0;

pub struct ProcessMonitor {
    device: DeviceConnection,
    target: PackageName,
    interval: Duration,
}

impl ProcessMonitor {
    pub fn new(device: DeviceConnection, target: PackageName, interval: Duration) -> Self {
        Self {
            device,
            target,
            interval,
        }
    }

    fn target_processes(&self, processes: Vec<ProcessInfo>) -> BTreeMap<u32, String> {
        processes
            .into_iter()
            .filter(|process| PackageName::owning_app_of(&process.name) == self.target.as_str())
            .map(|process| (process.pid, process.name))
            .collect()
    }

    async fn sample(&self, pids: &[u32]) -> Result<Option<ResourceSnapshot>, ProviderError> {
        if pids.is_empty() {
            return Ok(None);
        }
        let output = self
            .device
            .shell(&resource_sampling_command(pids))
            .await
            .map_err(source_error)?;
        Ok(parse_resource_snapshot(&output))
    }

    fn process_observation(&self, change: ProcessChange, pid: u32, name: &str) -> Observation {
        Observation::new(
            Domain::Process,
            change.kind(),
            format!("process {name} (pid {pid}) {}", change.verb()),
        )
        .with_app(self.target.as_str())
        .with_pid(pid)
        .with_attribute("process", name)
        .with_attribute("basis", "process table poll")
        .with_attribute("poll_interval_ms", self.interval.as_millis() as u64)
    }

    fn resource_observation(
        &self,
        sample: &ProcessSample,
        cpu_percent: Option<f64>,
    ) -> Observation {
        let mut parts = Vec::new();
        let mut observation =
            Observation::new(Domain::Resource, kinds::RESOURCE_SAMPLE, String::new())
                .with_app(self.target.as_str())
                .with_pid(sample.pid)
                .with_attribute("cpu_ticks", sample.cpu_ticks);
        if let Some(cpu) = cpu_percent {
            parts.push(format!("cpu {cpu:.1}%"));
            observation = observation
                .with_attribute("cpu_percent", (cpu * 10.0).round() / 10.0)
                .with_attribute(
                    "cpu_percent_basis",
                    "share of one core, derived from /proc/<pid>/stat deltas",
                );
        }
        if let Some(rss) = sample.rss_kb {
            parts.push(format!("rss {} MiB", rss / 1024));
            observation = observation.with_attribute("rss_kb", rss);
        }
        if let Some(threads) = sample.threads {
            observation = observation.with_attribute("threads", threads);
        }
        observation.message = format!("pid {}: {}", sample.pid, parts.join(", "));
        observation
    }

    fn unreadable_observation(&self, pid: u32) -> Observation {
        Observation::new(
            Domain::Collector,
            kinds::COLLECTION_GAP,
            format!("resource counters of pid {pid} could not be read; the process exited or is not accessible"),
        )
        .with_severity(Severity::Warning)
        .with_app(self.target.as_str())
        .with_pid(pid)
    }
}

#[async_trait]
impl Provider for ProcessMonitor {
    fn id(&self) -> &'static str {
        PROCESSES
    }

    async fn probe(&self) -> Capability {
        let (processes, uptime) = tokio::join!(
            ProcessListing::detect(&self.device),
            self.device.shell("cat /proc/uptime")
        );
        match (processes, uptime) {
            (Ok((_, list)), Ok(_)) if !list.is_empty() => {
                Capability::available(PROCESSES, "process table and /proc CPU and memory counters")
            }
            (Err(error), _) | (_, Err(error)) => {
                Capability::unavailable(PROCESSES, error.to_string(), error.remediation())
            }
            _ => Capability::unavailable(PROCESSES, "the process table could not be read", None),
        }
    }

    async fn run(&self, mut context: ProviderContext) -> Result<ProviderReport, ProviderError> {
        let (listing, mut processes) = ProcessListing::detect(&self.device)
            .await
            .map_err(source_error)?;
        let mut tracker = ProcessTracker::default();
        let mut cpu = CpuCalculator::default();
        let mut reported_unreadable = BTreeSet::new();
        loop {
            let current = self.target_processes(processes);
            for (change, pid, name) in tracker.update(&current) {
                context
                    .sink
                    .emit(self.process_observation(change, pid, &name))
                    .await?;
            }

            let pids: Vec<u32> = current.keys().copied().collect();
            if let Some(snapshot) = self.sample(&pids).await? {
                for sample in &snapshot.samples {
                    let observation =
                        self.resource_observation(sample, cpu.percent(&snapshot, sample));
                    context.sink.emit(observation).await?;
                }
                for pid in snapshot
                    .unreadable
                    .iter()
                    .filter(|pid| reported_unreadable.insert(**pid))
                {
                    context.sink.emit(self.unreadable_observation(*pid)).await?;
                }
                cpu.remember(&snapshot);
            }

            tokio::select! {
                () = context.stop.requested() => break,
                () = tokio::time::sleep(self.interval) => {}
            }
            processes = listing.list(&self.device).await.map_err(source_error)?;
        }
        Ok(ProviderReport {
            artifacts: Vec::new(),
            notes: vec![format!(
                "process start and stop times are accurate to the {} ms polling interval",
                self.interval.as_millis()
            )],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessChange {
    /// Already running when monitoring started.
    Running,
    Started,
    Died,
}

impl ProcessChange {
    fn kind(self) -> &'static str {
        match self {
            Self::Running => kinds::PROCESS_RUNNING,
            Self::Started => kinds::PROCESS_STARTED,
            Self::Died => kinds::PROCESS_DIED,
        }
    }

    fn verb(self) -> &'static str {
        match self {
            Self::Running => "is running",
            Self::Started => "started",
            Self::Died => "is no longer running",
        }
    }
}

/// Detects processes appearing and disappearing between polls.
#[derive(Default)]
struct ProcessTracker {
    known: Option<BTreeMap<u32, String>>,
}

impl ProcessTracker {
    /// Returns the changes since the previous poll. The first poll reports what is already running.
    fn update(&mut self, current: &BTreeMap<u32, String>) -> Vec<(ProcessChange, u32, String)> {
        let Some(known) = self.known.replace(current.clone()) else {
            return current
                .iter()
                .map(|(pid, name)| (ProcessChange::Running, *pid, name.clone()))
                .collect();
        };
        let started = current
            .iter()
            .filter(|(pid, _)| !known.contains_key(pid))
            .map(|(pid, name)| (ProcessChange::Started, *pid, name.clone()));
        let died = known
            .iter()
            .filter(|(pid, _)| !current.contains_key(pid))
            .map(|(pid, name)| (ProcessChange::Died, *pid, name.clone()));
        died.chain(started).collect()
    }
}

/// Derives CPU usage from consecutive samples of the same process.
#[derive(Default)]
struct CpuCalculator {
    previous_uptime: f64,
    previous_ticks: BTreeMap<u32, u64>,
}

impl CpuCalculator {
    fn percent(&self, snapshot: &ResourceSnapshot, sample: &ProcessSample) -> Option<f64> {
        let previous_ticks = *self.previous_ticks.get(&sample.pid)?;
        let elapsed = snapshot.uptime_seconds - self.previous_uptime;
        if elapsed <= 0.0 || sample.cpu_ticks < previous_ticks {
            return None;
        }
        let cpu_seconds = (sample.cpu_ticks - previous_ticks) as f64 / CLOCK_TICKS_PER_SECOND;
        Some(cpu_seconds / elapsed * 100.0)
    }

    fn remember(&mut self, snapshot: &ResourceSnapshot) {
        self.previous_uptime = snapshot.uptime_seconds;
        self.previous_ticks = snapshot
            .samples
            .iter()
            .map(|sample| (sample.pid, sample.cpu_ticks))
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(entries: &[(u32, &str)]) -> BTreeMap<u32, String> {
        entries
            .iter()
            .map(|(pid, name)| (*pid, (*name).to_string()))
            .collect()
    }

    #[test]
    fn the_first_poll_reports_running_processes_then_changes_only() {
        let mut tracker = ProcessTracker::default();
        let first = tracker.update(&table(&[(10, "com.example")]));
        assert_eq!(
            first,
            vec![(ProcessChange::Running, 10, "com.example".to_string())]
        );
        assert!(tracker.update(&table(&[(10, "com.example")])).is_empty());

        let restarted = tracker.update(&table(&[(11, "com.example")]));
        assert_eq!(
            restarted,
            vec![
                (ProcessChange::Died, 10, "com.example".to_string()),
                (ProcessChange::Started, 11, "com.example".to_string())
            ]
        );
    }

    fn snapshot(uptime: f64, ticks: u64) -> ResourceSnapshot {
        ResourceSnapshot {
            uptime_seconds: uptime,
            samples: vec![ProcessSample {
                pid: 10,
                cpu_ticks: ticks,
                threads: None,
                rss_kb: None,
            }],
            unreadable: Vec::new(),
        }
    }

    #[test]
    fn cpu_usage_needs_two_samples_and_is_derived_from_tick_deltas() {
        let mut cpu = CpuCalculator::default();
        let first = snapshot(100.0, 1_000);
        assert_eq!(cpu.percent(&first, &first.samples[0]), None);
        cpu.remember(&first);

        // 50 ticks = 0.5 s of CPU over 2 s of uptime.
        let second = snapshot(102.0, 1_050);
        let percent = cpu.percent(&second, &second.samples[0]).expect("percent");
        assert!((percent - 25.0).abs() < 1e-9);
    }

    #[test]
    fn a_reused_pid_with_fewer_ticks_reports_no_cpu_value() {
        let mut cpu = CpuCalculator::default();
        cpu.remember(&snapshot(100.0, 5_000));
        let reused = snapshot(102.0, 10);
        assert_eq!(cpu.percent(&reused, &reused.samples[0]), None);
    }
}
