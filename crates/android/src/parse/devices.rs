//! Parsing of `adb devices -l` (DEV-001, DEV-002, DEV-003, DEV-007).

use mobile_bridge_core::device::{Connection, DeviceState, DeviceSummary, Platform};

use crate::adb::device_state_remediation;

pub fn parse_device_list(output: &str) -> Vec<DeviceSummary> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with('*') && !line.starts_with("List of devices")
        })
        .filter_map(parse_device_line)
        .collect()
}

fn parse_device_line(line: &str) -> Option<DeviceSummary> {
    let (serial, rest) = line.split_once(char::is_whitespace)?;
    let rest = rest.trim_start();
    let (reported_state, details) = split_state(rest);
    let property = |key: &str| {
        details
            .split_whitespace()
            .find_map(|token| token.strip_prefix(key)?.strip_prefix(':'))
            .map(str::to_string)
    };
    let state = device_state(&reported_state);
    Some(DeviceSummary {
        id: serial.to_string(),
        platform: Platform::Android,
        state,
        connection: connection(serial, property("usb").is_some()),
        model: property("model").map(|model| model.replace('_', " ")),
        remediation: device_state_remediation(state).map(str::to_string),
        reported_state,
    })
}

/// The state is one word, except for "no permissions ...", whose explanation runs until the first property.
fn split_state(rest: &str) -> (String, &str) {
    if rest.starts_with("no permissions") {
        let end = rest
            .find(" usb:")
            .or_else(|| rest.find(" transport_id:"))
            .unwrap_or(rest.len());
        return (rest[..end].to_string(), &rest[end..]);
    }
    match rest.split_once(char::is_whitespace) {
        Some((state, details)) => (state.to_string(), details),
        None => (rest.to_string(), ""),
    }
}

fn device_state(reported: &str) -> DeviceState {
    match reported {
        "device" => DeviceState::Ready,
        "unauthorized" | "authorizing" => DeviceState::Unauthorized,
        "offline" | "connecting" => DeviceState::Offline,
        state if state.starts_with("no permissions") => DeviceState::MissingHostPermissions,
        _ => DeviceState::Unavailable,
    }
}

fn connection(serial: &str, has_usb_path: bool) -> Connection {
    if serial.starts_with("emulator-") {
        Connection::Emulator
    } else if has_usb_path {
        Connection::Usb
    } else if serial.contains(':') || serial.contains("._adb-tls-connect.") {
        Connection::Network
    } else {
        Connection::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTPUT: &str = "\
* daemon not running; starting now at tcp:5037
* daemon started successfully
List of devices attached
R58M123ABC             device usb:1-1 product:beyond1 model:SM_G973F device:beyond1 transport_id:1
emulator-5554          device product:sdk_gphone64 model:sdk_gphone64_x86_64 device:emu64x transport_id:2
192.168.0.5:5555       unauthorized transport_id:3
0123456789ABCDEF       no permissions (missing udev rules? user is in the plugdev group); see [http://developer.android.com/tools/device.html] usb:1-2 transport_id:4
ZY22ABC                recovery usb:1-3 transport_id:5

";

    #[test]
    fn parses_every_listed_device_and_skips_daemon_noise() {
        let devices = parse_device_list(OUTPUT);
        let ids: Vec<&str> = devices.iter().map(|device| device.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "R58M123ABC",
                "emulator-5554",
                "192.168.0.5:5555",
                "0123456789ABCDEF",
                "ZY22ABC"
            ]
        );
    }

    #[test]
    fn maps_states_connections_and_models() {
        let devices = parse_device_list(OUTPUT);
        assert_eq!(devices[0].state, DeviceState::Ready);
        assert_eq!(devices[0].connection, Connection::Usb);
        assert_eq!(devices[0].model.as_deref(), Some("SM G973F"));
        assert_eq!(devices[1].connection, Connection::Emulator);
        assert_eq!(devices[2].state, DeviceState::Unauthorized);
        assert_eq!(devices[2].connection, Connection::Network);
        assert_eq!(devices[3].state, DeviceState::MissingHostPermissions);
        assert_eq!(devices[3].connection, Connection::Usb);
        assert_eq!(devices[4].state, DeviceState::Unavailable);
    }

    #[test]
    fn only_devices_that_are_not_ready_carry_remediation() {
        let devices = parse_device_list(OUTPUT);
        assert!(
            devices
                .iter()
                .all(|device| device.remediation.is_some() == !device.state.is_ready())
        );
    }

    #[test]
    fn an_empty_list_means_no_devices() {
        assert!(parse_device_list("List of devices attached\n\n").is_empty());
    }
}
