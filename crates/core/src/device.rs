//! Platform-neutral device identity, connection state and capability model (DEV-001 to DEV-009).

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Android,
    Ios,
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Android => "android",
            Self::Ios => "ios",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Connection {
    Usb,
    Network,
    Emulator,
    Unknown,
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Usb => "usb",
            Self::Network => "network",
            Self::Emulator => "emulator",
            Self::Unknown => "unknown",
        })
    }
}

/// Whether the host may use the device for diagnostics (DEV-007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    Ready,
    Unauthorized,
    Offline,
    MissingHostPermissions,
    Unavailable,
}

impl DeviceState {
    pub fn is_ready(self) -> bool {
        self == Self::Ready
    }
}

impl fmt::Display for DeviceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ready => "ready",
            Self::Unauthorized => "unauthorized",
            Self::Offline => "offline",
            Self::MissingHostPermissions => "missing host permissions",
            Self::Unavailable => "unavailable",
        })
    }
}

/// A connected device as reported by the platform's discovery tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub id: String,
    pub platform: Platform,
    pub state: DeviceState,
    /// State string exactly as the platform tool reported it.
    pub reported_state: String,
    pub connection: Connection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Platform-specific step that makes a device that is not ready usable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Identity and build information of a device (DEV-004, AND-002).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DeviceMetadata {
    pub id: String,
    pub platform: Option<Platform>,
    pub manufacturer: Option<String>,
    pub brand: Option<String>,
    pub model: Option<String>,
    pub os_version: Option<String>,
    /// Android SDK API level; absent on other platforms.
    pub api_level: Option<u32>,
    pub abi: Option<String>,
    pub build_fingerprint: Option<String>,
    pub security_patch: Option<String>,
    pub build_type: Option<String>,
    pub is_emulator: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Available,
    /// Usable with reduced fidelity or after a prerequisite is met.
    Degraded,
    Unavailable,
}

impl fmt::Display for CapabilityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Available => "available",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        })
    }
}

/// Result of probing whether an instrumentation capability works on a device (DEV-009, AND-010).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub status: CapabilityStatus,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// False for capabilities that baseline collection does not need (for example elevated access).
    #[serde(default = "required_by_default")]
    pub required: bool,
}

fn required_by_default() -> bool {
    true
}

impl Capability {
    pub fn available(id: &str, detail: impl Into<String>) -> Self {
        Self::new(id, CapabilityStatus::Available, detail, None)
    }

    pub fn degraded(id: &str, detail: impl Into<String>, remediation: impl Into<String>) -> Self {
        Self::new(
            id,
            CapabilityStatus::Degraded,
            detail,
            Some(remediation.into()),
        )
    }

    pub fn unavailable(id: &str, detail: impl Into<String>, remediation: Option<String>) -> Self {
        Self::new(id, CapabilityStatus::Unavailable, detail, remediation)
    }

    fn new(
        id: &str,
        status: CapabilityStatus,
        detail: impl Into<String>,
        remediation: Option<String>,
    ) -> Self {
        Self {
            id: id.to_string(),
            status,
            detail: detail.into(),
            remediation,
            required: true,
        }
    }

    /// Marks a capability that baseline collection works without.
    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    pub fn is_usable(&self) -> bool {
        self.status != CapabilityStatus::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degraded_capability_is_still_usable_but_unavailable_is_not() {
        assert!(Capability::degraded("trace", "old API", "upgrade").is_usable());
        assert!(!Capability::unavailable("trace", "missing", None).is_usable());
    }
}
