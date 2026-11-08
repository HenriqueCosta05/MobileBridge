//! Shared setup for commands: configuration, storage location, adb and device selection.

use std::io::IsTerminal;
use std::path::PathBuf;

use mobile_bridge_android::{Adb, AndroidAdapter, AndroidDevice};
use mobile_bridge_core::device::DeviceSummary;
use mobile_bridge_core::session::SessionStore;

use crate::cli::GlobalOptions;
use crate::config::Config;
use crate::error::{CliError, ExitStatus};
use crate::output::Output;

pub struct Context {
    pub global: GlobalOptions,
    pub output: Output,
    pub config: Config,
    pub config_path: Option<PathBuf>,
}

impl Context {
    pub fn new(global: GlobalOptions) -> Result<Self, CliError> {
        let (config, config_path) = Config::load(global.config.as_deref())?;
        Ok(Self {
            output: Output::new(global.format),
            global,
            config,
            config_path,
        })
    }

    pub fn data_dir(&self) -> Result<PathBuf, CliError> {
        self.global
            .data_dir
            .clone()
            .or_else(|| dirs::data_local_dir().map(|dir| dir.join("mobile-bridge")))
            .ok_or_else(|| {
                CliError::failure("cannot determine a data directory for sessions")
                    .with_remediation("Pass --data-dir or set MOBILE_BRIDGE_DATA_DIR.")
            })
    }

    pub fn store(&self) -> Result<SessionStore, CliError> {
        Ok(SessionStore::new(self.data_dir()?.join("sessions")))
    }

    /// True when it is acceptable to prompt the user or read markers from stdin (CLI-002).
    pub fn is_interactive(&self) -> bool {
        !self.global.no_input && std::io::stdin().is_terminal()
    }

    pub fn adapter(&self) -> Result<AndroidAdapter, CliError> {
        Ok(AndroidAdapter::new(Adb::locate()?))
    }

    /// Resolves the target device and opens it.
    pub async fn open_device(&self, adapter: &AndroidAdapter) -> Result<AndroidDevice, CliError> {
        let devices = adapter.devices().await?;
        let chosen = choose_device(&devices, self.global.device.as_deref())?;
        Ok(adapter.open(&chosen.id).await?)
    }
}

/// Picks the device to use: the requested one, or the only ready one.
pub fn choose_device<'d>(
    devices: &'d [DeviceSummary],
    requested: Option<&str>,
) -> Result<&'d DeviceSummary, CliError> {
    let listing = || {
        devices
            .iter()
            .map(|device| format!("{} ({})", device.id, device.state))
            .collect::<Vec<_>>()
            .join(", ")
    };
    if let Some(requested) = requested {
        let device = devices
            .iter()
            .find(|device| device.id == requested)
            .ok_or_else(|| {
                let known = if devices.is_empty() {
                    "none".to_string()
                } else {
                    listing()
                };
                CliError::new(
                    ExitStatus::DeviceUnavailable,
                    format!("device '{requested}' is not connected"),
                )
                .with_remediation(format!("Connected devices: {known}."))
            })?;
        return ensure_ready(device);
    }
    let ready: Vec<&DeviceSummary> = devices
        .iter()
        .filter(|device| device.state.is_ready())
        .collect();
    match (ready.as_slice(), devices) {
        ([only], _) => Ok(only),
        ([], []) => Err(CliError::new(
            ExitStatus::DeviceUnavailable,
            "no Android device is connected",
        )
        .with_remediation(
            "Connect a device with USB debugging enabled, then run 'mobile-bridge devices list'.",
        )),
        ([], [single]) => ensure_ready(single),
        ([], _) => Err(CliError::new(
            ExitStatus::DeviceUnavailable,
            format!("no connected device is ready: {}", listing()),
        )
        .with_remediation(
            "Run 'mobile-bridge devices list' for the steps to make a device ready.",
        )),
        (_, _) => Err(CliError::new(
            ExitStatus::DeviceUnavailable,
            format!("several devices are ready: {}", listing()),
        )
        .with_remediation("Choose one with --device <SERIAL> or MOBILE_BRIDGE_DEVICE.")),
    }
}

fn ensure_ready(device: &DeviceSummary) -> Result<&DeviceSummary, CliError> {
    if device.state.is_ready() {
        return Ok(device);
    }
    let error = CliError::new(
        ExitStatus::DeviceUnavailable,
        format!("device '{}' is {}", device.id, device.state),
    );
    Err(match &device.remediation {
        Some(remediation) => error.with_remediation(remediation.clone()),
        None => error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobile_bridge_core::device::{Connection, DeviceState, Platform};

    fn device(id: &str, state: DeviceState) -> DeviceSummary {
        DeviceSummary {
            id: id.into(),
            platform: Platform::Android,
            state,
            reported_state: state.to_string(),
            connection: Connection::Usb,
            model: None,
            remediation: (!state.is_ready())
                .then(|| "Allow USB debugging on the device.".to_string()),
        }
    }

    #[test]
    fn the_only_ready_device_is_chosen_automatically() {
        let devices = [
            device("A", DeviceState::Unauthorized),
            device("B", DeviceState::Ready),
        ];
        assert_eq!(choose_device(&devices, None).expect("chosen").id, "B");
    }

    #[test]
    fn several_ready_devices_require_an_explicit_choice() {
        let devices = [
            device("A", DeviceState::Ready),
            device("B", DeviceState::Ready),
        ];
        let error = choose_device(&devices, None).expect_err("ambiguous");
        assert!(error.message.contains("several devices"));
        assert_eq!(choose_device(&devices, Some("B")).expect("chosen").id, "B");
    }

    #[test]
    fn an_unready_device_explains_how_to_fix_it() {
        let devices = [device("A", DeviceState::Unauthorized)];
        let error = choose_device(&devices, None).expect_err("not ready");
        assert_eq!(error.status, ExitStatus::DeviceUnavailable);
        assert!(
            error
                .remediation
                .as_deref()
                .is_some_and(|hint| hint.contains("Allow USB debugging"))
        );
    }

    #[test]
    fn unknown_and_missing_devices_are_reported() {
        assert!(
            choose_device(&[], None)
                .expect_err("none")
                .message
                .contains("no Android device")
        );
        let devices = [device("A", DeviceState::Ready)];
        let error = choose_device(&devices, Some("Z")).expect_err("unknown");
        assert!(
            error
                .remediation
                .as_deref()
                .is_some_and(|hint| hint.contains("A (ready)"))
        );
    }
}
