//! `devices list` and `devices show` (DEV-001 to DEV-009).

use std::collections::BTreeMap;
use std::time::Duration;

use mobile_bridge_android::providers::{CollectorOptions, select_collectors};
use mobile_bridge_android::{AndroidDevice, PackageName};
use mobile_bridge_core::device::{Capability, DeviceMetadata, DeviceSummary};
use mobile_bridge_core::provider::probe_all;
use serde::Serialize;

use crate::context::Context;
use crate::error::CliError;
use crate::output::{self, print_stdout, table, to_json_line};

const WATCH_INTERVAL: Duration = Duration::from_secs(1);

pub async fn list(context: &Context, watch: bool) -> Result<(), CliError> {
    let adapter = context.adapter()?;
    let devices = adapter.devices().await?;
    if watch {
        return watch_devices(context, &adapter, devices).await;
    }
    context.output.list(&devices, render_devices)
}

fn render_devices(devices: &[DeviceSummary]) -> String {
    if devices.is_empty() {
        return "No devices connected. Connect a device with USB debugging enabled.".to_string();
    }
    let rows: Vec<Vec<String>> = devices
        .iter()
        .map(|device| {
            vec![
                device.id.clone(),
                device.state.to_string(),
                device.connection.to_string(),
                device.model.clone().unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    let mut text = table(&["SERIAL", "STATE", "CONNECTION", "MODEL"], &rows);
    for device in devices {
        if let Some(remediation) = &device.remediation {
            text.push_str(&format!("\n\n{}: {remediation}", device.id));
        }
    }
    text
}

#[derive(Debug, Serialize)]
struct DeviceChange<'a> {
    change: &'static str,
    device: &'a DeviceSummary,
}

/// Polls the device list and reports connections, disconnections and state changes (DEV-005).
async fn watch_devices(
    context: &Context,
    adapter: &mobile_bridge_android::AndroidAdapter,
    initial: Vec<DeviceSummary>,
) -> Result<(), CliError> {
    let mut known: BTreeMap<String, DeviceSummary> = BTreeMap::new();
    let mut current = initial;
    if context.output.is_human() {
        output::status("Watching for device changes; press Ctrl-C to stop.");
    }
    loop {
        let current_ids: BTreeMap<String, DeviceSummary> = current
            .into_iter()
            .map(|device| (device.id.clone(), device))
            .collect();
        for (id, device) in &current_ids {
            let change = match known.get(id) {
                None => Some("connected"),
                Some(previous) if previous.state != device.state => Some("state_changed"),
                Some(_) => None,
            };
            if let Some(change) = change {
                report_change(context, change, device)?;
            }
        }
        for (id, device) in &known {
            if !current_ids.contains_key(id) {
                report_change(context, "disconnected", device)?;
            }
        }
        known = current_ids;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            () = tokio::time::sleep(WATCH_INTERVAL) => {}
        }
        current = adapter.devices().await?;
    }
}

fn report_change(
    context: &Context,
    change: &'static str,
    device: &DeviceSummary,
) -> Result<(), CliError> {
    if context.output.is_human() {
        let time = chrono::Local::now().format("%H:%M:%S");
        let model = device.model.as_deref().unwrap_or("unknown model");
        print_stdout(&format!(
            "{time} {change:<13} {} ({model}) {}",
            device.id, device.state
        ))
    } else {
        print_stdout(&to_json_line(&DeviceChange { change, device })?)
    }
}

#[derive(Debug, Serialize)]
pub struct DeviceReport {
    pub metadata: DeviceMetadata,
    pub capabilities: Vec<Capability>,
}

pub async fn show(context: &Context, app: Option<String>) -> Result<(), CliError> {
    let adapter = context.adapter()?;
    let device = context.open_device(&adapter).await?;
    let target = app
        .map(|app| app.parse::<PackageName>().map_err(CliError::failure))
        .transpose()?;
    let report = device_report(context, &device, target).await;
    context.output.item(&report, render_report)
}

pub async fn device_report(
    context: &Context,
    device: &AndroidDevice,
    target: Option<PackageName>,
) -> DeviceReport {
    let selection = select_collectors(&[], target.is_some()).unwrap_or_default();
    let options = CollectorOptions {
        target,
        trace: context.config.trace_options(),
        ..CollectorOptions::default()
    };
    let mut capabilities = device.device_capabilities().await;
    let probed = probe_all(device.providers(&selection, &options)).await;
    capabilities.extend(probed.into_iter().map(|probed| probed.capability));
    DeviceReport {
        metadata: device.metadata().clone(),
        capabilities,
    }
}

fn render_report(report: &DeviceReport) -> String {
    let metadata = &report.metadata;
    let field = |value: &Option<String>| value.clone().unwrap_or_else(|| "unknown".into());
    let mut lines = vec![
        format!("Serial:          {}", metadata.id),
        format!("Manufacturer:    {}", field(&metadata.manufacturer)),
        format!("Model:           {}", field(&metadata.model)),
        format!(
            "Android:         {} (API {})",
            field(&metadata.os_version),
            metadata
                .api_level
                .map_or_else(|| "unknown".into(), |api| api.to_string())
        ),
        format!("ABI:             {}", field(&metadata.abi)),
        format!("Security patch:  {}", field(&metadata.security_patch)),
        format!("Build type:      {}", field(&metadata.build_type)),
        format!(
            "Emulator:        {}",
            if metadata.is_emulator { "yes" } else { "no" }
        ),
        String::new(),
    ];
    lines.push(render_capabilities(&report.capabilities));
    lines.join("\n")
}

pub fn render_capabilities(capabilities: &[Capability]) -> String {
    let rows: Vec<Vec<String>> = capabilities
        .iter()
        .map(|capability| {
            vec![
                capability.id.clone(),
                capability.status.to_string(),
                capability.detail.clone(),
            ]
        })
        .collect();
    let mut text = table(&["CAPABILITY", "STATUS", "DETAIL"], &rows);
    for capability in capabilities {
        if let Some(remediation) = &capability.remediation {
            text.push_str(&format!("\n  {}: {remediation}", capability.id));
        }
    }
    text
}
