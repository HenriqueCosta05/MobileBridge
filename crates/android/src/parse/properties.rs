//! Parsing of `getprop` output into device metadata (DEV-004, AND-002).

use std::collections::BTreeMap;

use mobile_bridge_core::device::{DeviceMetadata, Platform};

pub fn parse_properties(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once("]: [")?;
            let key = key.strip_prefix('[')?;
            let value = value.strip_suffix(']')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

pub fn metadata_from_properties(
    serial: &str,
    properties: &BTreeMap<String, String>,
) -> DeviceMetadata {
    let get = |key: &str| {
        properties
            .get(key)
            .filter(|value| !value.is_empty())
            .cloned()
    };
    let hardware = get("ro.hardware").unwrap_or_default();
    let is_emulator = get("ro.kernel.qemu").as_deref() == Some("1")
        || get("ro.boot.qemu").as_deref() == Some("1")
        || ["goldfish", "ranchu"]
            .iter()
            .any(|name| hardware.contains(name));
    DeviceMetadata {
        id: serial.to_string(),
        platform: Some(Platform::Android),
        manufacturer: get("ro.product.manufacturer"),
        brand: get("ro.product.brand"),
        model: get("ro.product.model"),
        os_version: get("ro.build.version.release"),
        api_level: get("ro.build.version.sdk").and_then(|sdk| sdk.parse().ok()),
        abi: get("ro.product.cpu.abi"),
        build_fingerprint: get("ro.build.fingerprint"),
        security_patch: get("ro.build.version.security_patch"),
        build_type: get("ro.build.type"),
        is_emulator,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GETPROP: &str = "\
[ro.build.fingerprint]: [google/panther/panther:14/UQ1A.240205.004/11269751:user/release-keys]
[ro.build.type]: [user]
[ro.build.version.release]: [14]
[ro.build.version.sdk]: [34]
[ro.build.version.security_patch]: [2024-02-05]
[ro.hardware]: [panther]
[ro.product.brand]: [google]
[ro.product.cpu.abi]: [arm64-v8a]
[ro.product.manufacturer]: [Google]
[ro.product.model]: [Pixel 7]
[persist.sys.empty]: []
";

    #[test]
    fn extracts_identity_and_build_information() {
        let metadata = metadata_from_properties("ABC", &parse_properties(GETPROP));
        assert_eq!(metadata.manufacturer.as_deref(), Some("Google"));
        assert_eq!(metadata.model.as_deref(), Some("Pixel 7"));
        assert_eq!(metadata.os_version.as_deref(), Some("14"));
        assert_eq!(metadata.api_level, Some(34));
        assert_eq!(metadata.abi.as_deref(), Some("arm64-v8a"));
        assert_eq!(metadata.security_patch.as_deref(), Some("2024-02-05"));
        assert!(!metadata.is_emulator);
    }

    #[test]
    fn empty_values_are_treated_as_unknown() {
        let properties = parse_properties(GETPROP);
        assert_eq!(
            properties.get("persist.sys.empty").map(String::as_str),
            Some("")
        );
        let metadata = metadata_from_properties("ABC", &BTreeMap::new());
        assert_eq!(metadata.model, None);
        assert_eq!(metadata.api_level, None);
    }

    #[test]
    fn recognizes_emulators() {
        let properties = parse_properties("[ro.hardware]: [ranchu]\n");
        assert!(metadata_from_properties("emulator-5554", &properties).is_emulator);
    }
}
