//! Perfetto system trace capture (AND-004, MON-008, MON-010).
//!
//! Starts the on-device `perfetto` client in the background with a lightweight atrace/ftrace config,
//! asks it to stop when the recording ends, and pulls the trace into the session artifacts. The trace
//! is preserved as raw evidence; its contents are not converted into events yet (open it in
//! <https://ui.perfetto.dev>).

use std::time::Duration;

use async_trait::async_trait;
use mobile_bridge_core::device::Capability;
use mobile_bridge_core::event::{Domain, Observation, kinds};
use mobile_bridge_core::provider::{
    ArtifactRef, Provider, ProviderContext, ProviderError, ProviderReport,
};

use super::{PERFETTO, source_error};
use crate::adb::{AdbError, DeviceConnection};
use crate::package::PackageName;

/// The perfetto command-line client ships with Android 9; it is enabled by default from Android 10.
const MIN_API: u32 = 28;
const TRACING_ENABLED_BY_DEFAULT_API: u32 = 29;
/// The only directory where the shell user can write traces on production builds.
const DEVICE_TRACE_DIR: &str = "/data/misc/perfetto-traces";
const ARTIFACT_NAME: &str = "trace.perfetto-trace";
/// How long perfetto may take to finish writing the trace after it is asked to stop.
const STOP_TIMEOUT_SECONDS: u64 = 20;
const PULL_TIMEOUT: Duration = Duration::from_secs(300);

pub const DEFAULT_CATEGORIES: [&str; 9] = [
    "sched",
    "freq",
    "idle",
    "am",
    "wm",
    "gfx",
    "view",
    "binder_driver",
    "dalvik",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceOptions {
    /// Upper bound for the trace; perfetto stops by itself at this point.
    pub max_duration: Duration,
    /// Ring-buffer size; when full, the oldest data is overwritten.
    pub buffer_mb: u32,
    pub categories: Vec<String>,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            max_duration: Duration::from_secs(600),
            buffer_mb: 64,
            categories: DEFAULT_CATEGORIES
                .iter()
                .map(|category| (*category).to_string())
                .collect(),
        }
    }
}

/// Trace categories end up in a shell command, so only plain identifiers are accepted.
pub fn validate_category(category: &str) -> Result<(), String> {
    let valid = !category.is_empty()
        && category
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if valid {
        Ok(())
    } else {
        Err(format!("'{category}' is not a valid trace category"))
    }
}

pub struct PerfettoProvider {
    device: DeviceConnection,
    api_level: Option<u32>,
    target: Option<PackageName>,
    options: TraceOptions,
}

impl PerfettoProvider {
    pub fn new(
        device: DeviceConnection,
        api_level: Option<u32>,
        target: Option<PackageName>,
        options: TraceOptions,
    ) -> Self {
        Self {
            device,
            api_level,
            target,
            options,
        }
    }

    fn start_command(&self, remote_path: &str) -> String {
        let mut command = format!(
            "perfetto --background -o {remote_path} -t {}s -b {}mb",
            self.options.max_duration.as_secs().max(1),
            self.options.buffer_mb
        );
        if let Some(target) = &self.target {
            command.push_str(&format!(" -a {target}"));
        }
        for category in &self.options.categories {
            command.push(' ');
            command.push_str(category);
        }
        command
    }

    /// Asks perfetto to stop and waits on the device, in one adb call, until it has written the trace.
    async fn stop_tracing(&self, pid: u32) -> Result<(), ProviderError> {
        // The loop polls every 0.2 s; an already exited perfetto (maximum duration reached) is fine.
        let polls = STOP_TIMEOUT_SECONDS * 5;
        let command = format!(
            "kill -TERM {pid} 2>/dev/null; i=0; while kill -0 {pid} 2>/dev/null && [ $i -lt {polls} ]; \
             do sleep 0.2; i=$((i+1)); done; kill -0 {pid} 2>/dev/null && echo running"
        );
        let timeout = Duration::from_secs(STOP_TIMEOUT_SECONDS + 10);
        let output = self
            .device
            .shell_with_timeout(&command, timeout)
            .await
            .unwrap_or_default();
        if output.contains("running") {
            return Err(ProviderError::Source(format!(
                "perfetto (pid {pid}) did not finish writing the trace within {STOP_TIMEOUT_SECONDS} seconds"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl Provider for PerfettoProvider {
    fn id(&self) -> &'static str {
        PERFETTO
    }

    async fn probe(&self) -> Capability {
        let api = self.api_level.unwrap_or(0);
        if api < MIN_API {
            return Capability::unavailable(
                PERFETTO,
                format!(
                    "system tracing with perfetto requires Android 9 (API {MIN_API}); this device reports API {api}"
                ),
                None,
            );
        }
        match self.device.shell("command -v perfetto").await {
            Ok(path) if !path.trim().is_empty() => {}
            Ok(_) | Err(AdbError::CommandFailed { .. }) => {
                return Capability::unavailable(
                    PERFETTO,
                    "the perfetto client is not installed on this device",
                    None,
                );
            }
            Err(error) => {
                return Capability::unavailable(PERFETTO, error.to_string(), error.remediation());
            }
        }
        if api < TRACING_ENABLED_BY_DEFAULT_API {
            let enabled = self
                .device
                .shell("getprop persist.traced.enable")
                .await
                .unwrap_or_default();
            if enabled.trim() != "1" {
                return Capability::unavailable(
                    PERFETTO,
                    "the tracing service is disabled on this Android 9 device",
                    Some("Enable it with 'adb shell setprop persist.traced.enable 1'.".into()),
                );
            }
        }
        Capability::available(
            PERFETTO,
            format!("categories: {}", self.options.categories.join(" ")),
        )
    }

    async fn run(&self, mut context: ProviderContext) -> Result<ProviderReport, ProviderError> {
        let unique = chrono::Utc::now().timestamp_millis();
        let remote_path = format!("{DEVICE_TRACE_DIR}/mobile-bridge-{unique}.perfetto-trace");
        let output = self
            .device
            .shell(&self.start_command(&remote_path))
            .await
            .map_err(source_error)?;
        let pid: u32 = output
            .lines()
            .rev()
            .find_map(|line| line.trim().parse().ok())
            .ok_or_else(|| {
                ProviderError::Source(format!("perfetto did not start: {}", output.trim()))
            })?;

        context.stop.requested().await;
        let stop_result = self.stop_tracing(pid).await;
        let local_path = context.artifact_dir.join(ARTIFACT_NAME);
        let pulled = self
            .device
            .pull(&remote_path, &local_path, PULL_TIMEOUT)
            .await;
        // Ignored error: a leftover file on the device is harmless, and failing here would hide the trace.
        let _ = self.device.shell(&format!("rm -f {remote_path}")).await;
        pulled.map_err(source_error)?;
        stop_result?;

        let artifact = ArtifactRef::adopt(
            PERFETTO,
            &context.artifact_dir,
            ARTIFACT_NAME,
            "Perfetto system trace",
        )?;
        let observation = Observation::new(
            Domain::Trace,
            kinds::ARTIFACT_CAPTURED,
            format!(
                "system trace saved to {} ({} KiB)",
                artifact.path,
                artifact.bytes / 1024
            ),
        )
        .with_attribute("path", artifact.path.as_str())
        .with_attribute("bytes", artifact.bytes)
        .with_attribute("categories", self.options.categories.join(" "));
        context.sink.emit(observation).await?;

        Ok(ProviderReport {
            artifacts: vec![artifact],
            notes: vec![format!(
                "trace events are not converted into session events; open {ARTIFACT_NAME} in https://ui.perfetto.dev. \
                 The {} MB ring buffer keeps the most recent data if it fills up.",
                self.options.buffer_mb
            )],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adb::Adb;

    fn provider(target: Option<&str>) -> PerfettoProvider {
        PerfettoProvider::new(
            Adb::at("adb").device("SERIAL"),
            Some(34),
            target.map(|package| package.parse().expect("package")),
            TraceOptions {
                max_duration: Duration::from_secs(30),
                buffer_mb: 32,
                categories: vec!["sched".into(), "am".into()],
            },
        )
    }

    #[test]
    fn start_command_includes_limits_target_app_and_categories() {
        assert_eq!(
            provider(Some("com.example")).start_command("/data/misc/perfetto-traces/x"),
            "perfetto --background -o /data/misc/perfetto-traces/x -t 30s -b 32mb -a com.example sched am"
        );
    }

    #[test]
    fn categories_with_shell_syntax_are_rejected() {
        assert!(validate_category("binder_driver").is_ok());
        assert!(validate_category("sched;reboot").is_err());
        assert!(validate_category("").is_err());
    }
}
