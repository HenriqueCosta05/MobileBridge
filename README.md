# mobile-bridge

A Rust command-line tool for recording and analyzing how mobile applications interact with the operating
system on **physical devices**. It collects evidence from the platform's supported diagnostic sources,
normalizes it into one event model, stores it as a portable local session, and links every finding to the
events that support it.

> **Status: Milestone 1 (Android collection MVP), pre-release.** Android works on non-rooted devices
> through adb. iOS support is planned (see [Platform capabilities](docs/PLATFORM_CAPABILITIES.md)).

## What it collects (Android)

| Collector   | Source                                      | Produces                                                                 |
|-------------|---------------------------------------------|--------------------------------------------------------------------------|
| `logcat`    | `logcat` main, system, crash, events buffers | logs; process start/death, crashes, native crashes, ANRs, foreground/background |
| `processes` | `ps` and `/proc` polling (needs `--app`)    | running processes of the app, CPU and memory samples                    |
| `perfetto`  | on-device `perfetto` client (Android 9+)    | a system trace file saved as an artifact (open it in ui.perfetto.dev)   |
| `services`  | `dumpsys` at session start and end          | permission states and changes; raw package, memory, battery and connectivity dumps |

Every event keeps its raw source line. Collectors are probed first, and one that can't run on the device
is skipped with an explanation. A collector that fails mid-session is recorded as a collection gap, and
the other collectors keep going.

## Install

Requirements: Rust 1.99+ (pinned in `rust-toolchain.toml`) and [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools)
(`adb`). On the device, enable **Developer options → USB debugging** and accept the authorization prompt.

```bash
cargo install --locked --path crates/cli
```

`adb` is looked up in `MOBILE_BRIDGE_ADB`, then `ANDROID_HOME`/`ANDROID_SDK_ROOT`, then `PATH`. From WSL,
the Windows `adb.exe` on `PATH` is used as well, since USB devices are not visible to Linux `adb` in WSL
without extra setup.

## Quick start

```bash
mobile-bridge doctor                                   # check host, adb and device capabilities
mobile-bridge apps list --third-party                  # find the package name
mobile-bridge record --app com.example.app -t 2m       # record; type a note + Enter to add a marker
mobile-bridge sessions analyze latest                  # crashes, ANRs, gaps, with their evidence
mobile-bridge sessions timeline latest --app com.example.app --min-severity warning
mobile-bridge sessions export latest --output session.tar.gz
```

## Commands

| Command | Purpose |
|---|---|
| `doctor` | Checks the host, adb, storage, devices and every collector's capability on the target device. |
| `devices list [--watch]` | Lists devices and their authorization state; `--watch` reports connections and state changes. |
| `devices show [--app PKG]` | Device metadata (manufacturer, model, Android version, API level, ABI, patch level) and capabilities. |
| `apps list [--third-party] [--running] [--filter TEXT]` | Installed packages with uid, version and running PIDs. |
| `apps processes [--app PKG]` | Running processes. |
| `record [--app PKG] [-t DURATION] [--collectors a,b] [--all-logs] [--no-redact]` | Records a session, streaming events live. Ctrl-C stops gracefully. |
| `sessions list \| show \| events \| timeline \| analyze \| export \| delete` | Works with recorded sessions. A session is referenced by id, unique id prefix, or `latest`. |
| `completions <shell>` | Prints a shell completion script. |

Global options: `--device SERIAL` (or `MOBILE_BRIDGE_DEVICE`), `--format human|json|jsonl`,
`--data-dir`, `--config`, `--no-input`. Results go to stdout and messages to stderr, so `--format json`
output can be piped.

Event filters (`events`, `timeline`): `--app`, `--pid`, `--subsystem`/`--tag`, `--domain`, `--kind`,
`--min-severity`, `--grep`, `--limit`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General failure (invalid input, I/O error, cancelled) |
| 2 | Command-line usage error |
| 3 | Device unavailable (not connected, unauthorized, offline, ambiguous) |
| 4 | Dependency missing (adb not found) |
| 5 | Partial: the session was saved, but some collectors failed |
| 6 | Unsupported: no selected collector can run on the device |
| 7 | Not found (session, or application not installed) |
| 130 | Recording interrupted with a second Ctrl-C; the session is left unfinalized |

## Privacy

- Everything is stored locally (`--data-dir`, by default the user's local data directory). Nothing is uploaded.
- Session directories are created with owner-only permissions on Unix (`0700`/`0600`).
- Credentials, bearer tokens, JWTs, secret assignments, URL token parameters and e-mail addresses are
  redacted **before** events and text artifacts (dumpsys snapshots) are written. `--no-redact` turns this
  off explicitly. Binary Perfetto traces cannot be redacted; leave out the `perfetto` collector if that
  matters.
- With `--app`, log lines and lifecycle events of unrelated apps are not stored. `--all-logs` keeps them.
- `sessions delete` removes a session and all its artifacts.

## Configuration

Optional TOML file (`--config`, `MOBILE_BRIDGE_CONFIG`, or `<config dir>/mobile-bridge/config.toml`).
Unknown keys and invalid values are rejected.

```toml
[record]
collectors = ["logcat", "processes", "services"]
duration = "2m"
sample_interval = "2s"

[trace]
max_duration = "10m"
buffer_mb = 64
categories = ["sched", "freq", "am", "wm", "gfx", "view"]

[redaction]
built_in = true
[[redaction.rules]]
name = "customer-id"
pattern = 'CUST-\d+'
replacement = "[CUSTOMER]"
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Platform capabilities and limitations](docs/PLATFORM_CAPABILITIES.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
