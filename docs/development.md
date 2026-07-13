# Development Checks

Run the Splash-owned quality gate:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

The Makepad compatibility import is deliberately outside the workspace lint
scope. Verify it explicitly after an upstream import or vendor patch:

```sh
cargo test --manifest-path vendor/makepad/Cargo.toml -p makepad-script
cargo test --manifest-path vendor/makepad/Cargo.toml -p makepad-regex
```

This keeps failures in source owned by Splash actionable while preserving
separate behavioral coverage for the imported VM.

## Syntax fuzzing

The standalone `fuzz` package differentially exercises the canonical profile
and the vendored VM parser. It uses a 16 KiB source cap and a 2,048-token cap,
then asserts that every source accepted by the canonical preflight is also
accepted by the VM parser. Its tracked `.splash` seeds cover canonical
dataflow, deferred tools, loops, and lambdas; generated corpus entries and
crash artifacts stay local.

Install `cargo-fuzz` once, then run the target with nightly Rust:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run syntax -- -max_total_time=60 -max_len=16384 -dict=dictionaries/syntax.dict
```

If AddressSanitizer's libFuzzer runtime does not initialize on a target, use
`--sanitizer none` as a coverage-only fallback. It keeps the differential
assertion but does not provide memory-safety instrumentation:

```sh
cargo +nightly fuzz run --sanitizer none syntax -- -max_total_time=60 -max_len=16384 -dict=dictionaries/syntax.dict
```

Reproduce a saved failure from the same directory with:

```sh
cargo +nightly fuzz run syntax artifacts/syntax/<artifact>
```
