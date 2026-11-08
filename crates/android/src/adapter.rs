//! Entry point of the Android adapter: device discovery, metadata, application discovery and
//! capability detection (DEV-001 to DEV-009, APP-001 to APP-004, AND-001, AND-002, AND-007 to AND-010).

use std::sync::Arc;

use mobile_bridge_core::device::{Capability, DeviceMetadata, DeviceSummary};
use mobile_bridge_core::provider::Provider;

use crate::adb::{Adb, AdbError, DeviceConnection};
use crate::package::PackageName;
use crate::parse::devices::parse_device_list;
use crate::parse::packages::{InstalledPackage, parse_package_list};
use crate::parse::processes::ProcessInfo;
use crate::parse::properties::{metadata_from_properties, parse_properties};
use crate::providers::{self, CollectorOptions, CollectorSelection};

/// Oldest Android release the adapter is designed for: Android 5.0 (API 21).
pub const MIN_SUPPORTED_API: u32 = 21;
pub const ROOT_CAPABILITY: &str = "root";
pub const OS_VERSION_CAPABILITY: &str = "os_version";

pub struct AndroidAdapter {
    adb: Adb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageScope {
    All,
    ThirdParty,
}

impl AndroidAdapter {
    pub fn new(adb: Adb) -> Self {
        Self { adb }
    }

    pub async fn devices(&self) -> Result<Vec<DeviceSummary>, AdbError> {
        Ok(parse_device_list(&self.adb.devices_output().await?))
    }

    /// Opens a ready device and reads its metadata.
    pub async fn open(&self, serial: &str) -> Result<AndroidDevice, AdbError> {
        let connection = self.adb.device(serial);
        let properties = parse_properties(&connection.shell("getprop").await?);
        let metadata = metadata_from_properties(serial, &properties);
        Ok(AndroidDevice {
            connection,
            metadata,
        })
    }
}

pub struct AndroidDevice {
    connection: DeviceConnection,
    metadata: DeviceMetadata,
}

impl AndroidDevice {
    pub fn metadata(&self) -> &DeviceMetadata {
        &self.metadata
    }

    pub async fn installed_packages(
        &self,
        scope: PackageScope,
    ) -> Result<Vec<InstalledPackage>, AdbError> {
        let flags = match scope {
            PackageScope::All => "",
            PackageScope::ThirdParty => " -3",
        };
        // --show-versioncode needs Android 9; older releases reject unknown options, so add it conditionally.
        let api = self.metadata.api_level.unwrap_or(0);
        // -U needs Android 8 and --show-versioncode Android 9; older releases reject unknown options.
        let uid_flag = if api >= 26 { " -U" } else { "" };
        let version_flag = if api >= 28 { " --show-versioncode" } else { "" };
        let output = self
            .connection
            .shell(&format!("pm list packages{uid_flag}{version_flag}{flags}"))
            .await?;
        Ok(parse_package_list(&output))
    }

    pub async fn is_installed(&self, package: &PackageName) -> Result<bool, AdbError> {
        let output = self.connection.shell(&format!("pm path {package}")).await;
        match output {
            Ok(paths) => Ok(paths.lines().any(|line| line.starts_with("package:"))),
            // `pm path` exits with an error for unknown packages.
            Err(AdbError::CommandFailed { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub async fn processes(&self) -> Result<Vec<ProcessInfo>, AdbError> {
        providers::list_processes(&self.connection).await
    }

    pub fn providers(
        &self,
        selection: &CollectorSelection,
        options: &CollectorOptions,
    ) -> Vec<Arc<dyn Provider>> {
        providers::build_providers(
            &self.connection,
            self.metadata.api_level,
            selection,
            options,
        )
    }

    /// Capabilities of the device itself, independent of any collector (DEV-009, AND-010).
    pub async fn device_capabilities(&self) -> Vec<Capability> {
        vec![self.os_version_capability(), self.root_capability().await]
    }

    fn os_version_capability(&self) -> Capability {
        match self.metadata.api_level {
            Some(api) if api >= MIN_SUPPORTED_API => Capability::available(
                OS_VERSION_CAPABILITY,
                format!(
                    "Android {} (API {api})",
                    self.metadata.os_version.as_deref().unwrap_or("?")
                ),
            ),
            Some(api) => Capability::unavailable(
                OS_VERSION_CAPABILITY,
                format!("API {api} is older than the minimum supported API {MIN_SUPPORTED_API}"),
                None,
            ),
            None => Capability::degraded(
                OS_VERSION_CAPABILITY,
                "the Android API level could not be determined",
                "Collector-specific checks still apply; results on this device are untested.",
            ),
        }
    }

    /// Reports whether elevated access might exist. It is never used: baseline collection works without
    /// root (AND-007), and running `su` could show a prompt on the device or change its behavior.
    async fn root_capability(&self) -> Capability {
        let build_type = self.metadata.build_type.as_deref().unwrap_or("unknown");
        let su_present = self
            .connection
            .shell("command -v su")
            .await
            .is_ok_and(|output| !output.trim().is_empty());
        let detail = match (build_type, su_present) {
            ("userdebug" | "eng", _) => format!("{build_type} build: 'adb root' may be possible"),
            (_, true) => "an 'su' binary is present".to_string(),
            _ => "no root access detected".to_string(),
        };
        Capability::unavailable(
            ROOT_CAPABILITY,
            format!(
                "{detail}; privileged collection is not implemented, all collectors run unprivileged"
            ),
            None,
        )
        .optional()
    }
}
