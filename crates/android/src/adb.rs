//! Thin, typed wrapper around the `adb` executable (AND-001).
//!
//! `adb shell` joins its arguments into a command line that the device shell interprets. Callers must
//! therefore only build shell commands from constants, integers and validated values such as
//! [`crate::package::PackageName`]; never from free-form user input.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::Duration;

use mobile_bridge_core::device::DeviceState;
use thiserror::Error;
use tokio::process::{Child, Command};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);
const ADB_ENV_OVERRIDE: &str = "MOBILE_BRIDGE_ADB";

#[derive(Debug, Error)]
pub enum AdbError {
    #[error("adb was not found (searched: {})", searched.join(", "))]
    NotFound { searched: Vec<String> },
    #[error("could not start {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("'adb {command}' did not finish within {} seconds", timeout.as_secs())]
    Timeout { command: String, timeout: Duration },
    #[error("no Android device is connected")]
    NoDevices,
    #[error("device '{0}' is not connected")]
    DeviceNotFound(String),
    #[error("device '{0}' has not authorized this computer for USB debugging")]
    Unauthorized(String),
    #[error("device '{0}' is offline")]
    Offline(String),
    #[error("'adb {command}' failed{}: {stderr}", exit_code.map(|code| format!(" with exit code {code}")).unwrap_or_default())]
    CommandFailed {
        command: String,
        exit_code: Option<i32>,
        stderr: String,
    },
}

impl AdbError {
    /// A concrete next step for the user (CLI-005).
    pub fn remediation(&self) -> Option<String> {
        let text = match self {
            Self::NotFound { .. } => {
                "Install Android SDK Platform-Tools and put 'adb' on PATH, set ANDROID_HOME, \
                 or point MOBILE_BRIDGE_ADB at the adb executable."
            }
            Self::NoDevices | Self::DeviceNotFound(_) => {
                "Connect the device with a data-capable USB cable, enable Developer options and USB debugging, \
                 then run 'mobile-bridge devices list'."
            }
            Self::Unauthorized(_) => {
                return device_state_remediation(DeviceState::Unauthorized).map(str::to_string);
            }
            Self::Offline(_) => {
                return device_state_remediation(DeviceState::Offline).map(str::to_string);
            }
            Self::Timeout { .. } => "Check that the device is unlocked and responsive, then retry.",
            Self::Spawn { .. } | Self::CommandFailed { .. } => return None,
        };
        Some(text.to_string())
    }
}

/// What the user can do to make an Android device in `state` usable (DEV-007).
pub fn device_state_remediation(state: DeviceState) -> Option<&'static str> {
    match state {
        DeviceState::Ready => None,
        DeviceState::Unauthorized => Some(
            "Unlock the device and accept the 'Allow USB debugging' prompt for this computer. \
             If no prompt appears, revoke USB debugging authorizations in Developer options and reconnect.",
        ),
        DeviceState::Offline => Some(
            "Reconnect the cable or run 'adb kill-server' and try again. The device may still be booting.",
        ),
        DeviceState::MissingHostPermissions => Some(
            "The host user cannot open the USB device. On Linux, install udev rules for Android devices \
             and add your user to the 'plugdev' group.",
        ),
        DeviceState::Unavailable => Some(
            "The device is in a mode that does not allow debugging (for example recovery or bootloader). \
             Boot it normally.",
        ),
    }
}

#[derive(Debug, Clone)]
pub struct Adb {
    program: PathBuf,
}

impl Adb {
    pub fn at(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    /// Finds adb in, by priority: `MOBILE_BRIDGE_ADB`, `ANDROID_HOME`/`ANDROID_SDK_ROOT` platform-tools,
    /// then `PATH`. `adb.exe` is also accepted on PATH so a Windows SDK can be used from WSL.
    pub fn locate() -> Result<Self, AdbError> {
        let candidates = adb_candidates(|name| std::env::var_os(name));
        candidates
            .iter()
            .find(|candidate| candidate.is_file())
            .map(|found| Self::at(found.clone()))
            .ok_or_else(|| AdbError::NotFound {
                searched: candidates
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
            })
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub async fn version(&self) -> Result<String, AdbError> {
        let output = self.run(&["version"], DEFAULT_TIMEOUT).await?;
        Ok(output.lines().next().unwrap_or_default().trim().to_string())
    }

    pub async fn devices_output(&self) -> Result<String, AdbError> {
        self.run(&["devices", "-l"], DEFAULT_TIMEOUT).await
    }

    pub fn device(&self, serial: &str) -> DeviceConnection {
        DeviceConnection {
            adb: self.clone(),
            serial: serial.to_string(),
        }
    }

    async fn run(&self, args: &[&str], timeout: Duration) -> Result<String, AdbError> {
        let command_line = args.join(" ");
        let child = self
            .command(args)
            .spawn()
            .map_err(|source| self.spawn_error(source))?;
        let output = tokio::time::timeout(timeout, child.wait_with_output())
            .await
            .map_err(|_| AdbError::Timeout {
                command: command_line.clone(),
                timeout,
            })?
            .map_err(|source| self.spawn_error(source))?;
        interpret_output(&command_line, output)
    }

    /// An adb invocation with piped output that is killed if its handle is dropped.
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }

    /// A Windows `adb.exe` used from WSL needs Windows paths; `wslpath` converts the (existing) parent
    /// directory, so the file itself does not have to exist yet.
    async fn host_path(&self, path: &Path) -> Result<String, AdbError> {
        if !self.is_windows_binary_on_unix() {
            return Ok(path.display().to_string());
        }
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return Ok(path.display().to_string());
        };
        let output = Command::new("wslpath")
            .arg("-w")
            .arg(parent)
            .output()
            .await
            .map_err(|source| AdbError::Spawn {
                program: "wslpath".into(),
                source,
            })?;
        let windows_parent = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() || windows_parent.is_empty() {
            return Err(AdbError::CommandFailed {
                command: format!("wslpath -w {}", parent.display()),
                exit_code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        Ok(format!("{windows_parent}\\{}", name.to_string_lossy()))
    }

    fn is_windows_binary_on_unix(&self) -> bool {
        !cfg!(windows)
            && self
                .program
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    }

    fn spawn_error(&self, source: std::io::Error) -> AdbError {
        AdbError::Spawn {
            program: self.program.display().to_string(),
            source,
        }
    }
}

fn adb_candidates(environment: impl Fn(&str) -> Option<OsString>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(explicit) = environment(ADB_ENV_OVERRIDE) {
        candidates.push(PathBuf::from(explicit));
    }
    for sdk_variable in ["ANDROID_HOME", "ANDROID_SDK_ROOT"] {
        if let Some(sdk) = environment(sdk_variable) {
            let tools = PathBuf::from(sdk).join("platform-tools");
            candidates.push(tools.join(executable_name()));
        }
    }
    let path = environment("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&path) {
        candidates.push(directory.join(executable_name()));
        if !cfg!(windows) {
            candidates.push(directory.join("adb.exe"));
        }
    }
    candidates
}

fn executable_name() -> &'static str {
    if cfg!(windows) { "adb.exe" } else { "adb" }
}

fn interpret_output(command: &str, output: Output) -> Result<String, AdbError> {
    let stdout = String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n");
    if output.status.success() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(AdbError::CommandFailed {
        command: command.to_string(),
        exit_code: output.status.code(),
        stderr: if stderr.is_empty() {
            stdout.trim().to_string()
        } else {
            stderr
        },
    })
}

/// Recognizes the device-state errors adb reports on stderr.
fn classify_device_error(serial: &str, error: AdbError) -> AdbError {
    let AdbError::CommandFailed { stderr, .. } = &error else {
        return error;
    };
    let message = stderr.to_ascii_lowercase();
    if message.contains("unauthorized") {
        AdbError::Unauthorized(serial.to_string())
    } else if message.contains("offline") {
        AdbError::Offline(serial.to_string())
    } else if message.contains("no devices/emulators found") {
        AdbError::NoDevices
    } else if message.contains("not found") && message.contains("device") {
        AdbError::DeviceNotFound(serial.to_string())
    } else {
        error
    }
}

/// Commands addressed to one device serial.
#[derive(Debug, Clone)]
pub struct DeviceConnection {
    adb: Adb,
    serial: String,
}

impl DeviceConnection {
    /// Runs a shell command on the device and returns its standard output.
    pub async fn shell(&self, command: &str) -> Result<String, AdbError> {
        self.shell_with_timeout(command, DEFAULT_TIMEOUT).await
    }

    pub(crate) async fn shell_with_timeout(
        &self,
        command: &str,
        timeout: Duration,
    ) -> Result<String, AdbError> {
        self.run(&["shell", command], timeout).await
    }

    /// Starts a long-running shell command whose output is streamed. The process is killed on drop.
    pub fn spawn_shell(&self, command: &str) -> Result<Child, AdbError> {
        self.adb
            .command(&["-s", &self.serial, "shell", command])
            .spawn()
            .map_err(|source| self.adb.spawn_error(source))
    }

    /// Copies a file from the device to the host.
    pub async fn pull(
        &self,
        remote: &str,
        local: &Path,
        timeout: Duration,
    ) -> Result<(), AdbError> {
        let local = self.adb.host_path(local).await?;
        self.run(&["pull", remote, &local], timeout)
            .await
            .map(|_| ())
    }

    async fn run(&self, args: &[&str], timeout: Duration) -> Result<String, AdbError> {
        let mut addressed = vec!["-s", self.serial.as_str()];
        addressed.extend_from_slice(args);
        self.adb
            .run(&addressed, timeout)
            .await
            .map_err(|error| classify_device_error(&self.serial, error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(stderr: &str) -> AdbError {
        AdbError::CommandFailed {
            command: "shell true".into(),
            exit_code: Some(1),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn device_errors_are_classified_from_adb_messages() {
        assert!(matches!(
            classify_device_error(
                "X",
                failed("adb: device unauthorized.\nThis adb server's $ADB_VENDOR_KEYS")
            ),
            AdbError::Unauthorized(_)
        ));
        assert!(matches!(
            classify_device_error("X", failed("error: device offline")),
            AdbError::Offline(_)
        ));
        assert!(matches!(
            classify_device_error("X", failed("adb: device 'X' not found")),
            AdbError::DeviceNotFound(_)
        ));
        assert!(matches!(
            classify_device_error("X", failed("adb: no devices/emulators found")),
            AdbError::NoDevices
        ));
    }

    #[test]
    fn other_failures_keep_their_original_message() {
        let error = classify_device_error(
            "X",
            failed("/system/bin/sh: perfetto: inaccessible or not found"),
        );
        assert!(matches!(error, AdbError::CommandFailed { .. }));
    }

    #[test]
    fn user_facing_errors_offer_remediation() {
        assert!(
            AdbError::NotFound { searched: vec![] }
                .remediation()
                .is_some()
        );
        assert!(AdbError::Unauthorized("X".into()).remediation().is_some());
    }

    #[tokio::test]
    async fn native_adb_receives_host_paths_unchanged() {
        let path = Path::new("/tmp/session/artifacts/trace.perfetto-trace");
        assert_eq!(
            Adb::at("/usr/bin/adb").host_path(path).await.expect("path"),
            path.display().to_string()
        );
        assert_eq!(
            Adb::at("C:/sdk/adb.exe").is_windows_binary_on_unix(),
            !cfg!(windows)
        );
    }

    #[test]
    fn candidates_follow_override_then_sdk_then_path_order() {
        let environment = |name: &str| match name {
            ADB_ENV_OVERRIDE => Some(OsString::from("/custom/adb")),
            "ANDROID_HOME" => Some(OsString::from("/sdk")),
            "PATH" => Some(OsString::from("/usr/bin")),
            _ => None,
        };
        let candidates = adb_candidates(environment);
        assert_eq!(candidates[0], PathBuf::from("/custom/adb"));
        assert_eq!(
            candidates[1],
            PathBuf::from("/sdk/platform-tools").join(executable_name())
        );
        assert_eq!(
            candidates[2],
            PathBuf::from("/usr/bin").join(executable_name())
        );
    }
}
