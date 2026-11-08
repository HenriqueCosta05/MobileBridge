//! `apps list` and `apps processes` (APP-001 to APP-004).

use std::collections::BTreeMap;

use mobile_bridge_android::parse::processes::ProcessInfo;
use mobile_bridge_android::{PackageName, PackageScope};
use serde::Serialize;

use crate::context::Context;
use crate::error::CliError;
use crate::output::table;

#[derive(Debug, Serialize)]
struct AppRow {
    package: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_code: Option<u64>,
    pids: Vec<u32>,
}

pub async fn list(
    context: &Context,
    third_party: bool,
    running: bool,
    filter: Option<String>,
) -> Result<(), CliError> {
    let adapter = context.adapter()?;
    let device = context.open_device(&adapter).await?;
    let scope = if third_party {
        PackageScope::ThirdParty
    } else {
        PackageScope::All
    };
    let packages = device.installed_packages(scope).await?;
    let pids = pids_by_app(&device.processes().await?);
    let rows: Vec<AppRow> = packages
        .into_iter()
        .filter(|package| {
            filter
                .as_deref()
                .is_none_or(|text| package.name.contains(text))
        })
        .map(|package| AppRow {
            pids: pids.get(&package.name).cloned().unwrap_or_default(),
            package: package.name,
            uid: package.uid,
            version_code: package.version_code,
        })
        .filter(|row| !running || !row.pids.is_empty())
        .collect();
    context.output.list(&rows, render_apps)
}

fn pids_by_app(processes: &[ProcessInfo]) -> BTreeMap<String, Vec<u32>> {
    let mut map: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for process in processes {
        map.entry(PackageName::owning_app_of(&process.name).to_string())
            .or_default()
            .push(process.pid);
    }
    map
}

fn render_apps(rows: &[AppRow]) -> String {
    if rows.is_empty() {
        return "No matching applications.".to_string();
    }
    let optional = |value: Option<String>| value.unwrap_or_else(|| "-".into());
    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let pids: Vec<String> = row.pids.iter().map(u32::to_string).collect();
            vec![
                row.package.clone(),
                optional(row.uid.map(|uid| uid.to_string())),
                optional(row.version_code.map(|version| version.to_string())),
                if pids.is_empty() {
                    "-".into()
                } else {
                    pids.join(",")
                },
            ]
        })
        .collect();
    table(&["PACKAGE", "UID", "VERSION", "PIDS"], &table_rows)
}

pub async fn processes(context: &Context, app: Option<String>) -> Result<(), CliError> {
    let adapter = context.adapter()?;
    let device = context.open_device(&adapter).await?;
    let processes: Vec<ProcessInfo> = device
        .processes()
        .await?
        .into_iter()
        .filter(|process| {
            app.as_deref()
                .is_none_or(|app| PackageName::owning_app_of(&process.name) == app)
        })
        .collect();
    context.output.list(&processes, |processes| {
        let rows: Vec<Vec<String>> = processes
            .iter()
            .map(|process| {
                vec![
                    process.pid.to_string(),
                    process
                        .ppid
                        .map_or_else(|| "-".into(), |ppid| ppid.to_string()),
                    process.user.clone().unwrap_or_else(|| "-".into()),
                    process.name.clone(),
                ]
            })
            .collect();
        table(&["PID", "PPID", "USER", "NAME"], &rows)
    })
}
