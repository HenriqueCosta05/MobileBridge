#!/usr/bin/env bash
# Automated quality gate. Every step must pass before code is delivered
# (commit, push, PR or release). See CLAUDE.md "Quality gate" for the review stage.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

step() { printf '\n==> %s\n' "$1"; }

step "Format (cargo fmt)"
cargo fmt --all -- --check

step "Lint (cargo clippy, warnings are errors)"
cargo clippy --workspace --all-targets --locked -- -D warnings

step "Test (cargo test)"
cargo test --workspace --locked

step "Docs (cargo doc, warnings are errors)"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --quiet

step "Dependency advisories (cargo audit)"
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit --deny warnings
else
    echo "SKIPPED: cargo-audit is not installed (cargo install cargo-audit --locked). CI runs this step."
fi

printf '\nQuality gate passed.\n'
