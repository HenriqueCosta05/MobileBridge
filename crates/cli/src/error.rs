//! User-facing errors with remediation (CLI-005) and machine-readable exit codes (NFR-014).

use std::fmt;
use std::process::ExitCode;

use mobile_bridge_android::AdbError;
use mobile_bridge_core::session::SessionError;

/// Documented exit codes. Clap itself exits with 2 on usage errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Success = 0,
    Failure = 1,
    DeviceUnavailable = 3,
    DependencyMissing = 4,
    /// The command finished, but some collectors failed or evidence is incomplete.
    Partial = 5,
    Unsupported = 6,
    NotFound = 7,
}

impl From<ExitStatus> for ExitCode {
    fn from(status: ExitStatus) -> Self {
        ExitCode::from(status as u8)
    }
}

#[derive(Debug)]
pub struct CliError {
    pub status: ExitStatus,
    pub message: String,
    pub remediation: Option<String>,
}

impl CliError {
    pub fn new(status: ExitStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            remediation: None,
        }
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self::new(ExitStatus::Failure, message)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error: {}", self.message)?;
        if let Some(remediation) = &self.remediation {
            write!(f, "\n  hint: {remediation}")?;
        }
        Ok(())
    }
}

impl From<AdbError> for CliError {
    fn from(error: AdbError) -> Self {
        let status = match error {
            AdbError::NotFound { .. } | AdbError::Spawn { .. } => ExitStatus::DependencyMissing,
            AdbError::NoDevices
            | AdbError::DeviceNotFound(_)
            | AdbError::Unauthorized(_)
            | AdbError::Offline(_)
            | AdbError::Timeout { .. } => ExitStatus::DeviceUnavailable,
            AdbError::CommandFailed { .. } => ExitStatus::Failure,
        };
        Self {
            status,
            remediation: error.remediation(),
            message: error.to_string(),
        }
    }
}

impl From<SessionError> for CliError {
    fn from(error: SessionError) -> Self {
        let (status, remediation) = match &error {
            SessionError::NotFound(_) | SessionError::Empty => (
                ExitStatus::NotFound,
                Some("Run 'mobile-bridge sessions list' to see recorded sessions."),
            ),
            SessionError::Ambiguous { .. } => {
                (ExitStatus::Failure, Some("Type more characters of the id."))
            }
            _ => (ExitStatus::Failure, None),
        };
        Self {
            status,
            message: error.to_string(),
            remediation: remediation.map(str::to_string),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::failure(error.to_string())
    }
}
