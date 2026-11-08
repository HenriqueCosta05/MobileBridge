# Architecture

mobile-bridge is a Cargo workspace with three crates. Dependencies point inwards: the CLI depends on the
adapters and the core, adapters depend on the core, and the core depends on neither (ARC-002).

```text
crates/cli      mobile-bridge            command parsing, output, configuration, wiring
crates/android  mobile-bridge-android    adb client, pure parsers, Android providers
crates/core     mobile-bridge-core       event model, provider contract, pipeline, sessions, analysis
```

## Core concepts

**Observation → Event.** A provider emits `Observation`s: what it saw, with an optional device timestamp
and the raw source record. The pipeline turns each one into an `Event` by adding the session id, device
id, provider id, a contiguous `sequence` (arrival order), host wall time and host monotonic nanoseconds.
Serialization is deterministic: fields keep their declared order and attributes use a `BTreeMap`.

**Normalized kinds.** Adapters map platform records onto shared kinds (`app_crash`, `anr`,
`process_started`, `permission_changed`, …; see `core::event::kinds`). Analysis only knows these kinds, so
the same rules can apply to iOS evidence later.

**Provider contract.** `core::provider::Provider` has three methods: `id`, `probe` (a capability check
that collects nothing), and `run(ProviderContext)`. A new provider is a new type implementing the trait
in an adapter crate. The core does not change (ARC-003, ARC-008).

## Recording pipeline

```text
provider task ─┐
provider task ─┼─ bounded mpsc (EventSink) ─► Recorder loop ─► retention ─► redaction ─► consumers
provider task ─┘                                  ▲                                     (SessionWriter,
            stop: watch channel ◄─────────────────┤                                      live stream)
            markers / stop request: RecordingControls
```

- **Concurrency and isolation (ARC-004, ARC-006, ARC-007).** Each provider runs in its own Tokio task.
  If a provider returns an error or panics, it is recorded as `failed`, a `collector_failed` event marks
  the gap, and the other providers continue.
- **Backpressure (ARC-005, NFR-004).** `EventSink::emit` waits while the queue (capacity 4096) is full.
  The wait propagates to the source (for example, logcat output is read more slowly). Memory stays
  bounded and nothing is dropped silently.
- **Shutdown.** A duration, a user stop (Ctrl-C), all providers finishing, or a persistence failure starts
  the stop. Providers get a stop signal and a grace period (60 s in the CLI, enough to stop and pull a
  trace). Providers still running after that are cancelled and recorded as `aborted`.
- **Retention and redaction (SEC-003 to SEC-005).** Both run before any consumer sees an event, so
  secrets and other apps' log lines never reach disk unless the user opts in.

## Sessions on disk

```text
<data dir>/sessions/<id>/
  session.json   manifest: device metadata, configuration, capabilities, collector outcomes, artifacts
  events.jsonl   one event per line, flushed per event
  artifacts/     raw evidence (perfetto trace, dumpsys output)
```

The manifest is written atomically (temporary file + rename) at the start and the end. A crash in the
middle leaves a `recording` manifest and, at worst, one truncated event line. Readers skip and report
that line, and analysis reports the session as interrupted (NFR-005). Session ids are validated as plain
path components, so a reference like `../x` cannot escape the store.

## Analysis

`core::analysis` builds a timeline ordered by the best-known time (device time, else host time), then by
sequence. It produces findings, each with a `basis`:

- `observation`: the OS reported it (crash, ANR, collector failure).
- `derivation`: computed (for example, a session that was never finalized).
- `correlation`: related only by time. Events preceding a failure are listed as correlated, never as the cause.

Android reports one crash in both the crash buffer and the event log; reports of the same kind and app
within 3 s are merged into one finding with several evidence events.

## Android adapter

- `adb.rs`: locates adb, runs commands with timeouts, and maps adb's stderr to typed errors with
  remediation. `adb shell` commands are only built from constants, integers and validated values
  (`PackageName`, trace categories), because the device shell interprets the joined command line.
- `parse/`: pure parsers for `devices -l`, `getprop`, `pm list packages`, `ps` (toybox and legacy
  layouts), `/proc` samples, logcat lines (epoch and legacy formats) and `dumpsys package` permissions.
  They are tested against captured output.
- `providers/`: `logcat`, `processes`, `perfetto` and `services`.

## Testing

- Unit tests next to the code; parsers use fixtures, so most tests need no device.
- `crates/cli/tests/record_workflow.rs` runs the real binary end to end against
  `tests/fixtures/fake-adb`, a shell script that answers like a device.
- Behavior that depends on real devices, vendors and Android versions still needs physical-device
  testing; see the compatibility matrix in [PLATFORM_CAPABILITIES.md](PLATFORM_CAPABILITIES.md).
