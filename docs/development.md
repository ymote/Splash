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

## Language server

`splash-lsp` is a host-only stdio server for editor clients. It advertises
UTF-16 positions, full document synchronization, syntax diagnostics,
whole-document canonical formatting, and top-level `fn`/`let` document symbols
for valid canonical source:

```sh
cargo run -p splash-lsp
```

It receives document text through LSP notifications only. It does not read the
document URI, evaluate Splash code, construct a capability host, resolve
imports, or load a Rust adapter. The server retains at most 128 open documents
and refuses to retain document text above the normal 256 KiB Splash source cap.

## Syntax fuzzing

The standalone `fuzz` package has two bounded targets. `syntax` differentially
exercises the canonical profile and the vendored VM parser with a 16 KiB source
cap and a 2,048-token cap. It asserts that every source accepted by the
canonical preflight is also accepted by the VM parser, and that successful
canonical formatting stays accepted and idempotent. It also checks that every
accepted source's top-level declaration outline has ordered, non-overlapping,
UTF-8-boundary-safe spans that contain the exact declared identifier.
`execution` starts a fresh, capability-free runtime for each syntactically
accepted input with an 8 KiB source cap, 1,024-token cap, 4,096 instruction
cap, one-instruction deadline sampling, and a 32 ms terminal execution
deadline. Script-level errors from
unavailable modules are expected. It creates `Runtime<(), ()>`, so no
capability or Rust adapter can run; a panic or hang is a fuzz failure.
`execution` explicitly collects its fresh VM after evaluation so retained heap
state cannot mask resource behavior. Their tracked `.splash` seeds cover
canonical dataflow, deferred tools, loops, lambdas, and an intentional
instruction-limit case; generated corpus entries and crash artifacts stay
local.

CI compiles both targets and performs a short 128-run coverage-only smoke pass
with `--sanitizer none`. Run the longer local commands below with the default
sanitizer whenever the platform supports it.

Install `cargo-fuzz` once, then run the target with nightly Rust:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run syntax -- -max_total_time=60 -max_len=16384 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run execution -- -max_total_time=60 -max_len=8192 -dict=dictionaries/syntax.dict
```

If AddressSanitizer's libFuzzer runtime does not initialize on a target, use
`--sanitizer none` as a coverage-only fallback. It keeps the differential
and resource-boundary assertions but does not provide memory-safety
instrumentation:

```sh
cargo +nightly fuzz run --sanitizer none syntax -- -max_total_time=60 -max_len=16384 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run --sanitizer none execution -- -max_total_time=60 -max_len=8192 -dict=dictionaries/syntax.dict
```

Reproduce a saved failure from the same directory with:

```sh
cargo +nightly fuzz run syntax artifacts/syntax/<artifact>
cargo +nightly fuzz run execution artifacts/execution/<artifact>
```
