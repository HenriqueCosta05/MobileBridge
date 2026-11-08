//! End-to-end test of the main workflow against a fake adb (`tests/fixtures/fake-adb`): record a
//! session, then inspect, analyze, export and delete it. The fixture is a POSIX shell script, so the
//! test runs on Unix hosts only.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

struct Harness {
    data_dir: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        Self {
            data_dir: tempfile::tempdir().expect("temp dir"),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mobile-bridge"))
            .args(args)
            .arg("--no-input")
            .env("MOBILE_BRIDGE_ADB", fake_adb())
            .env("MOBILE_BRIDGE_DATA_DIR", self.data_dir.path())
            .env(
                "MOBILE_BRIDGE_CONFIG",
                self.data_dir.path().join("no-config.toml"),
            )
            .env_remove("MOBILE_BRIDGE_DEVICE")
            .output()
            .expect("run mobile-bridge")
    }

    fn run_ok(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn json(&self, args: &[&str]) -> Value {
        serde_json::from_slice(&self.run_ok(args).stdout).expect("json output")
    }

    fn json_lines(&self, args: &[&str]) -> Vec<Value> {
        String::from_utf8_lossy(&self.run_ok(args).stdout)
            .lines()
            .map(|line| serde_json::from_str(line).expect("json line"))
            .collect()
    }

    fn record(&self) -> String {
        let output = self.run(&[
            "record",
            "--app",
            "com.example",
            "--duration",
            "2s",
            "--no-stream",
            "--format",
            "json",
        ]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "record failed: {stderr}");
        let result: Value = serde_json::from_slice(&output.stdout).expect("record result");
        result["session_id"]
            .as_str()
            .expect("session id")
            .to_string()
    }
}

fn fake_adb() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-adb")
}

fn messages(events: &[Value]) -> Vec<String> {
    events
        .iter()
        .map(|event| event["message"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// The config path points at a missing file, which must be reported rather than ignored.
#[test]
fn a_missing_explicit_config_file_is_an_error() {
    let harness = Harness::new();
    let output = harness.run(&["sessions", "list"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read configuration"));
}

#[test]
fn records_analyzes_exports_and_deletes_a_session() {
    let harness = Harness::new();
    std::fs::write(harness.data_dir.path().join("no-config.toml"), "").expect("empty config");

    let devices = harness.json(&["devices", "list", "--format", "json"]);
    assert_eq!(devices[0]["id"], "FAKE123");
    assert_eq!(devices[0]["state"], "ready");

    let id = harness.record();
    let manifest = harness.json(&["sessions", "show", "latest", "--format", "json"]);
    assert_eq!(manifest["id"], id.as_str());
    assert_eq!(manifest["status"], "completed");
    assert_eq!(manifest["device"]["model"], "Pixel 7");
    assert_eq!(manifest["target_apps"][0], "com.example");

    let events = harness.json_lines(&["sessions", "events", &id, "--format", "jsonl"]);
    let all_messages = messages(&events);
    assert!(
        all_messages
            .iter()
            .any(|m| m == "login with token=[REDACTED]"),
        "{all_messages:?}"
    );
    assert!(!all_messages.iter().any(|m| m.contains("abc123secret")));
    assert!(
        !all_messages.iter().any(|m| m.contains("unrelated line")),
        "other apps' logs must be dropped"
    );
    assert!(
        events
            .iter()
            .any(|event| event["kind"] == "permission_state")
    );
    assert!(
        events
            .iter()
            .any(|event| event["kind"] == "resource_sample")
    );

    let crashes = harness.json_lines(&[
        "sessions",
        "events",
        &id,
        "--kind",
        "app_crash",
        "--format",
        "jsonl",
    ]);
    assert_eq!(crashes.len(), 2, "both crash reports are kept as evidence");

    let analysis = harness.json(&["sessions", "analyze", &id, "--format", "json"]);
    let findings = analysis["findings"].as_array().expect("findings");
    assert_eq!(
        findings.len(),
        1,
        "the two reports describe one crash: {findings:?}"
    );
    assert_eq!(findings[0]["kind"], "app_crash");
    assert_eq!(findings[0]["basis"], "observation");
    assert_eq!(findings[0]["evidence"].as_array().map(Vec::len), Some(2));

    let archive = harness.data_dir.path().join("export.tar.gz");
    let archive_arg = archive.display().to_string();
    let export = harness.run(&["sessions", "export", &id, "--output", &archive_arg]);
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert!(archive.metadata().expect("archive").len() > 0);
    let again = harness.run(&["sessions", "export", &id, "--output", &archive_arg]);
    assert_eq!(
        again.status.code(),
        Some(1),
        "an existing export must not be overwritten"
    );

    let refused = harness.run(&["sessions", "delete", &id]);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "deletion needs confirmation"
    );
    let deleted = harness.run(&["sessions", "delete", &id, "--yes"]);
    assert!(deleted.status.success());
    assert_eq!(
        harness.run(&["sessions", "show", &id]).status.code(),
        Some(7)
    );
}

#[test]
fn unknown_apps_and_devices_fail_with_specific_exit_codes() {
    let harness = Harness::new();
    std::fs::write(harness.data_dir.path().join("no-config.toml"), "").expect("empty config");

    let missing_app = harness.run(&["record", "--app", "com.missing", "--duration", "1s"]);
    assert_eq!(missing_app.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&missing_app.stderr).contains("apps list --third-party"));

    let missing_device = harness.run(&["devices", "show", "--device", "NOPE"]);
    assert_eq!(missing_device.status.code(), Some(3));
}
