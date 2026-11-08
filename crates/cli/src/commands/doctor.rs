//! `doctor`: checks the host and the device before a recording (CLI-009, SEC-006).

use mobile_bridge_android::{Adb, AndroidAdapter};
use mobile_bridge_core::device::{Capability, CapabilityStatus};
use serde::Serialize;

use super::devices::device_report;
use crate::context::{Context, choose_device};
use crate::error::{CliError, ExitStatus};
use crate::output::table;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CheckStatus {
    Ok,
    /// Not needed for baseline collection; reported for completeness.
    Info,
    Warning,
    Failed,
    /// A host dependency is missing, so nothing else can be checked.
    Missing,
}

#[derive(Debug, Serialize)]
struct Check {
    name: String,
    status: CheckStatus,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<String>,
}

impl Check {
    fn new(
        name: &str,
        status: CheckStatus,
        detail: impl Into<String>,
        remediation: Option<String>,
    ) -> Self {
        Self {
            name: name.to_string(),
            status,
            detail: detail.into(),
            remediation,
        }
    }

    fn ok(name: &str, detail: impl Into<String>) -> Self {
        Self::new(name, CheckStatus::Ok, detail, None)
    }

    fn from_error(name: &str, status: CheckStatus, error: CliError) -> Self {
        Self::new(name, status, error.message, error.remediation)
    }

    fn from_capability(capability: Capability) -> Self {
        let status = match capability.status {
            CapabilityStatus::Available => CheckStatus::Ok,
            _ if !capability.required => CheckStatus::Info,
            CapabilityStatus::Degraded | CapabilityStatus::Unavailable => CheckStatus::Warning,
        };
        Self::new(
            &capability.id,
            status,
            capability.detail,
            capability.remediation,
        )
    }
}

pub async fn run(context: &Context) -> Result<(), CliError> {
    let mut checks = vec![
        Check::ok(
            "host",
            format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        ),
        config_check(context),
        storage_check(context),
    ];
    match adb_check().await {
        Ok((adb, check)) => {
            checks.push(check);
            checks.extend(device_checks(context, &AndroidAdapter::new(adb)).await);
        }
        Err(check) => checks.push(check),
    }
    let status = overall_status(&checks);
    context.output.list(&checks, render_checks)?;
    if status == ExitStatus::Success {
        Ok(())
    } else {
        Err(CliError::new(status, "some checks did not pass"))
    }
}

fn overall_status(checks: &[Check]) -> ExitStatus {
    let any = |status: CheckStatus| checks.iter().any(|check| check.status == status);
    if any(CheckStatus::Missing) {
        ExitStatus::DependencyMissing
    } else if any(CheckStatus::Failed) {
        ExitStatus::Failure
    } else {
        ExitStatus::Success
    }
}

fn config_check(context: &Context) -> Check {
    let detail = context.config_path.as_ref().map_or_else(
        || "no configuration file; using defaults (redaction of credentials, tokens and e-mails is on)".to_string(),
        |path| format!("loaded {}", path.display()),
    );
    Check::ok("configuration", detail)
}

/// Verifies that sessions can be written where they will be stored (SEC-001).
fn storage_check(context: &Context) -> Check {
    let result = context.data_dir().and_then(|dir| {
        mobile_bridge_core::private_fs::create_dir_all(&dir)?;
        let probe = dir.join(".write-test");
        std::fs::write(&probe, b"")?;
        std::fs::remove_file(&probe)?;
        Ok(dir)
    });
    match result {
        Ok(dir) => Check::ok(
            "storage",
            format!("sessions are stored locally in {}", dir.display()),
        ),
        Err(error) => Check::from_error(
            "storage",
            CheckStatus::Failed,
            error.with_remediation("Pass --data-dir with a writable directory."),
        ),
    }
}

async fn adb_check() -> Result<(Adb, Check), Check> {
    let adb = Adb::locate()
        .map_err(|error| Check::from_error("adb", CheckStatus::Missing, error.into()))?;
    let version = adb
        .version()
        .await
        .map_err(|error| Check::from_error("adb", CheckStatus::Failed, error.into()))?;
    let check = Check::ok("adb", format!("{version} ({})", adb.program().display()));
    Ok((adb, check))
}

async fn device_checks(context: &Context, adapter: &AndroidAdapter) -> Vec<Check> {
    let mut checks = Vec::new();
    if let Err(check) = collect_device_checks(context, adapter, &mut checks).await {
        checks.push(check);
    }
    checks
}

/// Adds one check per connected device, then the capabilities of the target device. Stops with the
/// check that explains why it could not go further.
async fn collect_device_checks(
    context: &Context,
    adapter: &AndroidAdapter,
    checks: &mut Vec<Check>,
) -> Result<(), Check> {
    let devices = adapter
        .devices()
        .await
        .map_err(|error| Check::from_error("devices", CheckStatus::Failed, error.into()))?;
    for device in &devices {
        let status = if device.state.is_ready() {
            CheckStatus::Ok
        } else {
            CheckStatus::Warning
        };
        let detail = format!("{} via {}", device.state, device.connection);
        checks.push(Check::new(
            &format!("device {}", device.id),
            status,
            detail,
            device.remediation.clone(),
        ));
    }
    let chosen = choose_device(&devices, context.global.device.as_deref())
        .map_err(|error| Check::from_error("target device", CheckStatus::Warning, error))?;
    let device = adapter
        .open(&chosen.id)
        .await
        .map_err(|error| Check::from_error("target device", CheckStatus::Failed, error.into()))?;
    let capabilities = device_report(context, &device, None).await.capabilities;
    checks.extend(capabilities.into_iter().map(Check::from_capability));
    Ok(())
}

fn render_checks(checks: &[Check]) -> String {
    let rows: Vec<Vec<String>> = checks
        .iter()
        .map(|check| {
            let status = match check.status {
                CheckStatus::Ok => "ok",
                CheckStatus::Info => "info",
                CheckStatus::Warning => "warning",
                CheckStatus::Failed => "FAILED",
                CheckStatus::Missing => "MISSING",
            };
            vec![status.to_string(), check.name.clone(), check.detail.clone()]
        })
        .collect();
    let mut text = table(&["STATUS", "CHECK", "DETAIL"], &rows);
    let hints: Vec<String> = checks
        .iter()
        .filter_map(|check| {
            check
                .remediation
                .as_ref()
                .map(|hint| format!("  {}: {hint}", check.name))
        })
        .collect();
    if !hints.is_empty() {
        text.push_str("\n\nHow to fix:\n");
        text.push_str(&hints.join("\n"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(status: CheckStatus) -> Check {
        Check::new("x", status, "detail", None)
    }

    #[test]
    fn a_missing_dependency_wins_over_other_results() {
        let checks = [check(CheckStatus::Failed), check(CheckStatus::Missing)];
        assert_eq!(overall_status(&checks), ExitStatus::DependencyMissing);
    }

    #[test]
    fn warnings_alone_do_not_fail_the_doctor() {
        assert_eq!(
            overall_status(&[check(CheckStatus::Warning)]),
            ExitStatus::Success
        );
        assert_eq!(
            overall_status(&[check(CheckStatus::Failed)]),
            ExitStatus::Failure
        );
    }

    #[test]
    fn unavailable_optional_capabilities_are_informational() {
        let optional = Capability::unavailable("root", "not rooted", None).optional();
        assert_eq!(Check::from_capability(optional).status, CheckStatus::Info);
        let required = Capability::unavailable("perfetto", "missing", None);
        assert_eq!(
            Check::from_capability(required).status,
            CheckStatus::Warning
        );
    }
}
