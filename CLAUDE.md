# mobile-bridge

Rust CLI for collecting and analyzing OS-level diagnostic evidence from physical Android and iOS devices.
The requirements package (144 requirements, IDs like `AND-003`, `SES-006`) lives outside the repo at
`/mnt/c/Users/Henri/Documents/HQCostaWorkspace/Projects/OpenSource/mobile-bridge`
(`docs/REQUIREMENTS_INDEX.md`, `docs/PRIORITIES_AND_DELIVERY.md`). Current target: Milestone 1, the Android collection MVP.

## Quality gate (mandatory before any code delivery)

"Delivery" means committing, pushing, opening or updating a PR, tagging a release, or telling the user
that code work is done. A change is not deliverable until all three stages pass. Never bypass the gate
(`--no-verify`, `#[allow(...)]` added just to silence the gate, skipped or `#[ignore]`d tests) unless the user
explicitly asks; if you do, say so.

### Stage 1: automated checks

```bash
./scripts/quality-gate.sh
```

It runs, failing fast: `cargo fmt --check`, `cargo clippy -D warnings` (with the lints in `Cargo.toml`:
no `unsafe`, `unwrap`, `dbg!`, `todo!`, `unimplemented!` outside tests), `cargo test`, `cargo doc -D warnings`,
and `cargo audit` when installed. All of it runs with `--locked` (NFR-007). The same script runs in the
`.githooks/pre-commit` hook (enable it with `git config core.hooksPath .githooks`) and in CI on Linux, macOS
and Windows (`.github/workflows/ci.yml`, OSS-007). A skipped step must be reported as skipped, never as passed.

### Stage 2: review (from skills)

Run these on the diff, in order, and fix what they confirm:

1. **clean-code skill:** go through its review checklist (names, small functions, no duplication, no flag
   arguments, explicit error handling, tests for changed behavior). Changed behavior needs tests, including at
   least one failure or limitation path (the requirement acceptance criteria require this).
2. **`/simplify`:** reuse, simplification and efficiency cleanups.
3. **`/code-review medium`:** correctness. Fix confirmed findings and re-run Stage 1. Use `high` for changes to
   the event pipeline, session persistence or concurrency. Use `max`/`ultra` only when the user asks.
4. **`/security-review`:** required when the change touches process or command execution (adb), file
   persistence or permissions, redaction, export, config parsing or anything network-related (SEC-*).

### Stage 3: delivery evidence

- Report what ran and how it ended (pass, fail, skipped), the requirement IDs covered, and any remaining risks
  or assumptions (clean-code "Output expectations").
- Commits use Conventional Commits and **must not carry Claude attribution** (no `Co-Authored-By: Claude`, no
  "Generated with Claude Code"). This is a global rule, enforced by `~/.claude/hooks/no-claude-attribution.py`.
- Behavior that needs a physical device and was not exercised on one must be stated as unverified.

## Project rules

- Evidence before inference: never fabricate unavailable data. Unsupported capability is reported as
  unsupported, not as an empty success.
- Platform-specific code stays behind the adapter/provider boundary (ARC-002, ARC-003).
- Keep serialized output deterministic (`BTreeMap`, fixed field order; NFR-006).
- Parsers of device output are pure functions tested against fixtures, so most tests need no device.
