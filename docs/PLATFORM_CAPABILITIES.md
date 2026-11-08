# Platform capabilities and limitations

mobile-bridge only uses documented, supported developer interfaces and never bypasses OS security
boundaries. Run `mobile-bridge devices show` or `mobile-bridge doctor` to see what a specific device
supports: every collector is probed before recording, and unavailable ones are reported, not faked.

## Host platforms

| Host | Status |
|---|---|
| Linux | Supported; CI runs the full test suite. |
| macOS | Supported; CI runs the full test suite. |
| Windows | Builds and runs; CI runs the unit tests. The end-to-end test needs a POSIX shell and is skipped. Session files rely on the user profile's ACLs instead of Unix permission bits. |
| WSL | Works with the Windows `adb.exe` on `PATH` (Linux adb in WSL cannot see USB devices without usbipd). |

## Android

Baseline requirements: USB debugging enabled and this computer authorized. Root is **not** required
or used.

| Capability | Requirement | Notes |
|---|---|---|
| Device discovery, metadata | any version | From `adb devices -l` and `getprop`. Wireless debugging devices are listed as `network`. |
| Installed apps, processes | any version | `ps -A` on Android 8+, legacy `ps` before. `--show-versioncode` on Android 9+. |
| Logcat | Android 5+ (API 21) | Android 7+ (API 24) gives UTC timestamps (`-v epoch`). Older releases keep device-local time as text, and no device time is claimed. |
| Lifecycle events | events buffer readable | Process start/death (`am_proc_start`, `am_proc_died`, `am_kill`), crashes (`am_crash`, `AndroidRuntime`), native crashes (`libc` fatal signal), ANRs (`am_anr`, `ActivityManager`), foreground changes (`wm_set_resumed_activity`). Event-log formats change between releases. Unknown formats stay plain log events. |
| CPU and memory | `/proc/<pid>` readable by the shell user | Polled (default every 2 s). CPU is the share of one core, from `/proc/<pid>/stat` deltas with USER_HZ = 100. Memory is VmRSS, not PSS. |
| System trace | Android 9+ (API 28) | Android 9 needs `adb shell setprop persist.traced.enable 1`. The trace is saved as an artifact and not yet converted into events. The ring buffer keeps the most recent data. |
| Permissions | `dumpsys package` | Runtime permission states at start, and changes between start and end. Changes are detected by snapshot difference, so their exact time is unknown. |
| Root / privileged mode | not implemented | Detected and reported only (`userdebug`/`eng` builds, `su` present). |

### Known limitations

- Logcat and the process table show other apps' activity. With `--app`, unrelated log lines are dropped
  before storage. Use `--all-logs` only when you need them.
- Attribution of a log line to an app uses its PID, or a mention of the target package by system
  processes (marked `attribution: message_mention`). It is evidence, not proof.
- Some vendor builds disable or restrict logging. The `logcat` probe reports when it returns no lines.
- Polling detects processes that live shorter than the sampling interval only through logcat's event log.

## iOS

Not implemented yet (Milestone 3). Planned scope: device discovery and pairing/trust prerequisites,
accessible device logs, sysdiagnose and MetricKit ingestion, Xcode/Instruments workflows. Stock iOS does
not give third-party tools arbitrary access to other processes, system calls, memory or private app
data. mobile-bridge will report these limits explicitly instead of attempting undocumented access.

## Compatibility matrix

Status of verification on physical devices. Only rows that were actually tested are marked verified.

| Device | Android (API) | Collectors verified | Date |
|---|---|---|---|
| (none yet) | | Parsers verified against captured fixtures; end-to-end flow verified against a simulated adb | 2026-11-08 |

Contributions of verified rows are welcome (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
