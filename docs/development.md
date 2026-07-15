# Development Checks

Run the Splash-owned quality gate:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo check --locked -p splash-sandbox --tests --target aarch64-unknown-linux-gnu
cargo check --locked -p splash-sandbox --tests --target riscv64gc-unknown-linux-gnu
cargo check --locked -p splash-sandbox --tests --target x86_64-pc-windows-gnu
```

The Linux target checks compile the real Bubblewrap and cgroup paths on the two
architectures supported by CI. The Windows check compiles the explicit
unsupported-platform path and prevents Linux-only runner dependencies from
leaking into non-Linux builds; it does not provide a Windows containment
backend.

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

The standalone `fuzz` package has six bounded targets. `syntax` differentially
exercises the canonical profile and the vendored VM parser with a 16 KiB source
cap and a 2,048-token cap. It asserts that every source accepted by the
canonical preflight is also accepted by the VM parser, and that successful
canonical formatting stays accepted and idempotent. It also checks that every
accepted source's top-level declaration outline has ordered, non-overlapping,
UTF-8-boundary-safe spans that contain the exact declared identifier.
The same target validates the direct tool-call hint outline: its retained count
must not exceed the fixed cap, its spans must be ordered UTF-8 boundaries
within the source, and any decoded literal name must correspond to a direct
string-literal span. The outline remains a source-review aid rather than an
authorization mechanism.
`execution` starts a fresh, capability-free runtime for each syntactically
accepted input with an 8 KiB source cap, 1,024-token cap, 4,096 instruction
cap, one-instruction deadline sampling, and a 32 ms terminal execution
deadline. Script-level errors from
unavailable modules are expected. It creates `Runtime<(), ()>`, so no
capability or Rust adapter can run; a panic or hang is a fuzz failure.
`execution` explicitly collects its fresh VM after evaluation so retained heap
state cannot mask resource behavior. Their tracked `.splash` seeds cover
canonical dataflow, deferred tools, loops, lambdas, and an intentional
instruction-limit case. `workflow_draft` feeds bounded UTF-8 JSON into the
data-only `WorkflowDraft` decoder, then checks that every accepted draft
round-trips through the current wire format and produces exactly one review
entry per retained step. The same input also probes bounded `WorkflowData` as
fresh JSON input and as persisted `{input, outputs}` context; every accepted
context must round-trip and preserve its binding fingerprint. Its tracked JSON
seeds start from a valid one-step draft and a dataflow context; generated
corpus entries and crash artifacts stay local. When the same JSON document is
both a compilable schema and accepted fresh data, the target also runs a pure
one-step `WorkflowDataContract` workflow and asserts that a validated input
survives as the schema-validated output. This covers contract construction,
approval, and bounded output retention without fuzzing authority-grant
selection.
`capability_lease` creates one permitted local adapter and one registered but
ungranted adapter for every input. It executes source under a one-call
`text.echo` lease, drives only bounded local host-pump work, and asserts that
the ungranted adapter never runs, the permitted adapter cannot exceed its
lease budget, and pending work stays within its cap. Its tracked seeds cover a
computed ungranted name and a permitted deferred call.
`workflow_external_operation` decodes arbitrary bounded durable ledgers and
round-trips every accepted record. It also builds a two-call external workflow
with a bounded fuzz-derived text or JSON payload, then exercises the durable
prepare/persist/claim bridge. It checks oversized nonces do not create intent,
repeated preparation is idempotent, stale exact claims cannot consume the next
queued external call, raw payload markers never enter persisted ledgers, wrong
authenticated worker message kinds cannot mutate state, and replayed worker
responses do not advance the ledger revision. The target intentionally never
runs an external adapter. Its tracked `.seed` files cover JSON and text
payloads, oversized nonces, stale claims, wrong worker message kinds, and each
terminal workflow-operation state.
`workflow_event_journal` feeds bounded UTF-8 documents into the durable
workflow-event journal decoder. Every accepted journal must re-encode and
round-trip under the maximum journal retention capacity. The target then appends
one fixed valid event at the decoded cursor and verifies the bounded retention
and current-format encoding remain valid. It never creates a capability host,
runs an adapter, or treats telemetry as execution authority. Its tracked JSON
seeds cover a valid journal and an invalid sequence boundary.
`json_line_worker` feeds bounded arbitrary bytes through small, variable
`BufReader` capacities, optionally appends a line terminator, and attempts two
successive authenticated-frame reads. Every framing, UTF-8, size, or protocol
error must poison the channel before another read. The target owns only in-memory
I/O and never starts a worker or invokes a capability.

CI compiles all seven targets and performs a short 128-run coverage-only smoke pass
with `--sanitizer none`. Run the longer local commands below with the default
sanitizer whenever the platform supports it.

Install `cargo-fuzz` once, then run the target with nightly Rust:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run syntax -- -max_total_time=60 -max_len=16384 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run execution -- -max_total_time=60 -max_len=8192 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run workflow_draft -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run capability_lease -- -max_total_time=60 -max_len=8192
cargo +nightly fuzz run workflow_external_operation -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run workflow_event_journal -- -max_total_time=60 -max_len=196608
cargo +nightly fuzz run json_line_worker -- -max_total_time=60 -max_len=1048578
```

If AddressSanitizer's libFuzzer runtime does not initialize on a target, use
`--sanitizer none` as a coverage-only fallback. It keeps the differential
and resource-boundary assertions but does not provide memory-safety
instrumentation:

```sh
cargo +nightly fuzz run --sanitizer none syntax -- -max_total_time=60 -max_len=16384 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run --sanitizer none execution -- -max_total_time=60 -max_len=8192 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run --sanitizer none workflow_draft -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run --sanitizer none capability_lease -- -max_total_time=60 -max_len=8192
cargo +nightly fuzz run --sanitizer none workflow_external_operation -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run --sanitizer none workflow_event_journal -- -max_total_time=60 -max_len=196608
cargo +nightly fuzz run --sanitizer none json_line_worker -- -max_total_time=60 -max_len=1048578
```

Reproduce a saved failure from the same directory with:

```sh
cargo +nightly fuzz run syntax artifacts/syntax/<artifact>
cargo +nightly fuzz run execution artifacts/execution/<artifact>
cargo +nightly fuzz run workflow_draft artifacts/workflow_draft/<artifact>
cargo +nightly fuzz run capability_lease artifacts/capability_lease/<artifact>
cargo +nightly fuzz run workflow_external_operation artifacts/workflow_external_operation/<artifact>
cargo +nightly fuzz run workflow_event_journal artifacts/workflow_event_journal/<artifact>
cargo +nightly fuzz run json_line_worker artifacts/json_line_worker/<artifact>
```
