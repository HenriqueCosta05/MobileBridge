//! System service snapshots at the start and end of a recording (AND-005, AND-006, MON-003).
//!
//! Saves `dumpsys` output for the target package, its memory, battery and connectivity as raw artifacts,
//! and turns the package's permission grants into permission events, including changes during the
//! recording.

use std::time::Duration;

use async_trait::async_trait;
use mobile_bridge_core::device::Capability;
use mobile_bridge_core::event::{Domain, Observation, Severity, kinds};
use mobile_bridge_core::provider::{
    ArtifactRef, Provider, ProviderContext, ProviderError, ProviderReport,
};

use super::SERVICES;
use crate::adb::DeviceConnection;
use crate::package::PackageName;
use crate::parse::permissions::{
    PermissionKind, PermissionTable, parse_permissions, permission_changes,
};

pub struct ServiceSnapshots {
    device: DeviceConnection,
    target: Option<PackageName>,
}

/// One `dumpsys` call whose output is kept as an artifact.
struct Snapshot {
    /// Used in the artifact file name.
    name: &'static str,
    command: String,
    description: String,
}

impl ServiceSnapshots {
    pub fn new(device: DeviceConnection, target: Option<PackageName>) -> Self {
        Self { device, target }
    }

    fn snapshots(&self) -> Vec<Snapshot> {
        let mut snapshots = Vec::new();
        if let Some(target) = &self.target {
            snapshots.push(Snapshot {
                name: "package",
                command: format!("dumpsys package {target}"),
                description: format!("package state of {target}"),
            });
            snapshots.push(Snapshot {
                name: "meminfo",
                command: format!("dumpsys meminfo {target}"),
                description: format!("memory usage of {target}"),
            });
        }
        for service in ["battery", "connectivity"] {
            snapshots.push(Snapshot {
                name: service,
                command: format!("dumpsys {service}"),
                description: format!("{service} service state"),
            });
        }
        snapshots
    }

    /// Captures every snapshot in one adb call; returns the package dump, if any, for permission parsing.
    async fn capture(
        &self,
        phase: &str,
        context: &ProviderContext,
        report: &mut ProviderReport,
    ) -> Option<String> {
        let snapshots = self.snapshots();
        let output = match self
            .device
            .shell_with_timeout(&snapshot_command(&snapshots), SNAPSHOT_TIMEOUT)
            .await
        {
            Ok(output) => output,
            Err(error) => {
                report
                    .notes
                    .push(format!("service snapshots failed at {phase}: {error}"));
                return None;
            }
        };
        let mut package_dump = None;
        for (snapshot, section) in snapshots
            .iter()
            .zip(split_sections(&output, snapshots.len()))
        {
            let file_name = format!("dumpsys-{}-{phase}.txt", snapshot.name);
            let description = format!("{} ({phase})", snapshot.description);
            let (redacted, _) = context.redactor.redact(section);
            match ArtifactRef::write(
                SERVICES,
                &context.artifact_dir,
                &file_name,
                redacted.as_bytes(),
                &description,
            ) {
                Ok(artifact) => report.artifacts.push(artifact),
                Err(error) => report
                    .notes
                    .push(format!("could not save {file_name}: {error}")),
            }
            if snapshot.name == "package" {
                package_dump = Some(section.to_string());
            }
        }
        package_dump
    }

    fn permission_observation(&self, kind: &str, message: String) -> Observation {
        let observation = Observation::new(Domain::Permission, kind, message);
        match &self.target {
            Some(target) => observation.with_app(target.as_str()),
            None => observation,
        }
    }
}

/// Prefix of the line printed before each snapshot, so one shell output can be split per service.
const SECTION_MARKER: &str = "@@mobile-bridge-snapshot@@";
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(90);

/// One shell command running every snapshot in sequence. Running them one after another, rather than
/// in parallel, keeps the load on the device low (NFR-001). Errors are kept in the section text.
fn snapshot_command(snapshots: &[Snapshot]) -> String {
    snapshots
        .iter()
        .map(|snapshot| format!("echo {SECTION_MARKER}; {} 2>&1", snapshot.command))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Splits the output of [`snapshot_command`] into one section per snapshot; missing ones are empty.
fn split_sections(output: &str, count: usize) -> Vec<&str> {
    let mut sections: Vec<&str> = output
        .split(&format!("{SECTION_MARKER}\n"))
        .skip(1)
        .map(|section| section.trim_end_matches('\n'))
        .collect();
    sections.resize(count, "");
    sections
}

#[async_trait]
impl Provider for ServiceSnapshots {
    fn id(&self) -> &'static str {
        SERVICES
    }

    async fn probe(&self) -> Capability {
        match self.device.shell("dumpsys -l").await {
            Ok(services) if services.contains("package") => Capability::available(
                SERVICES,
                "dumpsys snapshots of package, memory, battery and connectivity",
            ),
            Ok(_) => Capability::degraded(
                SERVICES,
                "dumpsys did not list the package service",
                "Snapshots may be incomplete on this build.",
            ),
            Err(error) => Capability::unavailable(SERVICES, error.to_string(), error.remediation()),
        }
    }

    async fn run(&self, mut context: ProviderContext) -> Result<ProviderReport, ProviderError> {
        let mut report = ProviderReport::default();
        let initial = self
            .capture("start", &context, &mut report)
            .await
            .map(|dump| parse_permissions(&dump));
        if let Some(table) = &initial {
            for observation in permission_state_observations(self, table) {
                context.sink.emit(observation).await?;
            }
        }

        context.stop.requested().await;

        let last = self
            .capture("end", &context, &mut report)
            .await
            .map(|dump| parse_permissions(&dump));
        if let (Some(before), Some(after)) = (&initial, &last) {
            for change in permission_changes(before, after) {
                let describe = |state: Option<bool>| match state {
                    Some(true) => "granted",
                    Some(false) => "denied",
                    None => "absent",
                };
                let from = describe(change.before.as_ref().map(|state| state.granted));
                let to = describe(change.after.as_ref().map(|state| state.granted));
                let observation = self
                    .permission_observation(
                        kinds::PERMISSION_CHANGED,
                        format!("{} changed from {from} to {to}", change.name),
                    )
                    .with_severity(Severity::Warning)
                    .with_attribute("permission", change.name.as_str())
                    .with_attribute("before", from)
                    .with_attribute("after", to)
                    .with_attribute("basis", "difference between start and end snapshots");
                context.sink.emit(observation).await?;
            }
        }
        Ok(report)
    }
}

/// One event per runtime permission; install-time permissions are summarized in one event.
fn permission_state_observations(
    provider: &ServiceSnapshots,
    table: &PermissionTable,
) -> Vec<Observation> {
    let mut observations: Vec<Observation> = table
        .iter()
        .filter(|(_, state)| state.kind == PermissionKind::Runtime)
        .map(|(name, state)| {
            let verb = if state.granted {
                "granted"
            } else {
                "not granted"
            };
            provider
                .permission_observation(kinds::PERMISSION_STATE, format!("{name} is {verb}"))
                .with_attribute("permission", name.as_str())
                .with_attribute("granted", state.granted)
                .with_attribute("permission_type", PermissionKind::Runtime.as_str())
        })
        .collect();
    let install_granted: Vec<&str> = table
        .iter()
        .filter(|(_, state)| state.kind == PermissionKind::Install && state.granted)
        .map(|(name, _)| name.as_str())
        .collect();
    if !install_granted.is_empty() {
        observations.push(
            provider
                .permission_observation(
                    kinds::PERMISSION_STATE,
                    format!("{} install-time permissions granted", install_granted.len()),
                )
                .with_attribute("permission_type", PermissionKind::Install.as_str())
                .with_attribute("permissions", install_granted.join(",")),
        );
    }
    observations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adb::Adb;
    use crate::parse::permissions::PermissionState;

    fn provider(target: Option<&str>) -> ServiceSnapshots {
        ServiceSnapshots::new(
            Adb::at("adb").device("SERIAL"),
            target.map(|package| package.parse().expect("package")),
        )
    }

    #[test]
    fn one_command_output_is_split_back_into_snapshots() {
        let snapshots = provider(None).snapshots();
        let command = snapshot_command(&snapshots);
        assert_eq!(
            command,
            "echo @@mobile-bridge-snapshot@@; dumpsys battery 2>&1; echo @@mobile-bridge-snapshot@@; dumpsys connectivity 2>&1"
        );
        let output =
            "@@mobile-bridge-snapshot@@\nlevel: 80\n@@mobile-bridge-snapshot@@\nNetwork: wifi\n";
        assert_eq!(split_sections(output, 2), ["level: 80", "Network: wifi"]);
        assert_eq!(split_sections("", 2), ["", ""]);
    }

    #[test]
    fn package_snapshots_are_only_taken_for_a_target_app() {
        let names = |provider: ServiceSnapshots| {
            provider
                .snapshots()
                .iter()
                .map(|s| s.name)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(provider(Some("com.example"))),
            ["package", "meminfo", "battery", "connectivity"]
        );
        assert_eq!(names(provider(None)), ["battery", "connectivity"]);
    }

    #[test]
    fn runtime_permissions_are_listed_and_install_permissions_summarized() {
        let mut table = PermissionTable::new();
        table.insert(
            "android.permission.CAMERA".into(),
            PermissionState {
                kind: PermissionKind::Runtime,
                granted: false,
            },
        );
        table.insert(
            "android.permission.INTERNET".into(),
            PermissionState {
                kind: PermissionKind::Install,
                granted: true,
            },
        );
        let observations = permission_state_observations(&provider(Some("com.example")), &table);
        let messages: Vec<&str> = observations.iter().map(|o| o.message.as_str()).collect();
        assert_eq!(
            messages,
            [
                "android.permission.CAMERA is not granted",
                "1 install-time permissions granted"
            ]
        );
        assert!(
            observations
                .iter()
                .all(|o| o.app.as_deref() == Some("com.example"))
        );
    }
}
