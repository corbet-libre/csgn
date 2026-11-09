#!/usr/bin/env bash
set -euo pipefail
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"

python3 .github/check-first-party.py
rustc --version
wasmtime --version
bash .ci/update-our-crates.sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo test --locked --all-features
cargo test --locked --no-default-features
cargo check --locked --target wasm32-unknown-unknown
cargo check --locked --target wasm32-unknown-unknown --no-default-features
cargo check --locked --target wasm32-unknown-unknown --all-features
CARGO_TARGET_WASM32_WASIP1_RUNNER=wasmtime cargo test --locked --target wasm32-wasip1 --no-default-features --test it -- --test-threads=1
CARGO_TARGET_WASM32_WASIP1_RUNNER=wasmtime cargo test --locked --target wasm32-wasip1 --features volatile-signer --test it -- --test-threads=1

rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '/tests/' --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --text --output-path coverage.txt
)
python3 .github/test-source-coverage.py
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
