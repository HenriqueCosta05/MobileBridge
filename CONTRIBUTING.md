# Contributing

Thanks for helping! Bug reports, device compatibility results, parsers for new output formats and new
providers are all welcome.

## Development setup

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it automatically.

```bash
git config core.hooksPath .githooks   # run the quality gate before every commit
./scripts/quality-gate.sh             # format, lint, tests, docs, dependency advisories
```

The gate is the same one CI runs on Linux, macOS and Windows. A pull request must pass it.

## Guidelines

- **Evidence before inference.** Never report unavailable data as an empty success. Unsupported
  capabilities are reported as unsupported, with a remediation when one exists.
- **Keep platform code in adapters.** The core must not know about adb, logcat or Android tags.
- **Parsers are pure functions** tested against captured output. When you fix a parsing bug, add the line
  that broke it as a fixture.
- **Shell safety.** Anything interpolated into an `adb shell` command must be a constant, an integer, or a
  validated type such as `PackageName`.
- **Tests.** Cover the normal path and at least one failure or limitation path.
- Mention the requirement IDs a change implements (for example `AND-003`) in the pull request.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.

## Adding a provider

1. Implement `mobile_bridge_core::provider::Provider` in an adapter crate.
2. Make `probe` check real prerequisites without collecting anything.
3. Emit normalized kinds from `core::event::kinds` where they apply, keep the raw record, and return
   errors instead of silently stopping.
4. Register it in the adapter's provider builder and document it in `docs/PLATFORM_CAPABILITIES.md`.

## Reporting device compatibility

Run `mobile-bridge doctor --format json` and a short `record`, then open an issue with the device model,
Android version and the doctor output. Remove anything you consider sensitive first.
