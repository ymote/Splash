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
architectures supported by CI, including the Landlock pre-exec runner. On a
Linux host with a Landlock-enabled kernel, also run:

```sh
cargo test --locked -p splash-sandbox --test landlock_runner
```

That integration test verifies that an allowlisted fixed runner cannot execute
an unlisted target and that a staged seccomp filter persists into its fixed
target after Landlock setup. It treats a kernel without the hard-required
Landlock API as an unavailable runtime rather than a passing enforcement
result. The Windows check compiles the explicit unsupported-platform path and
prevents Linux-only runner dependencies from leaking into non-Linux builds; it
does not provide a Windows containment backend.

To verify the positive Linux project-quota path, first provision one directory
on a filesystem with generic project quotas: assign a nonzero project ID, set
the inheritance bit, and configure nonzero hard byte and inode limits. Then run
the ignored integration test with that root and its installed hard limits:

```sh
SPLASH_PROJECT_QUOTA_TEST_ROOT=/srv/splash/quota-test \
SPLASH_PROJECT_QUOTA_TEST_ID=42 \
SPLASH_PROJECT_QUOTA_TEST_MAXIMUM_BYTES=268435456 \
SPLASH_PROJECT_QUOTA_TEST_MAXIMUM_INODES=16384 \
cargo test --locked -p splash-sandbox --test linux_project_quota -- --ignored
```

The test only reads and validates quota state; it never enables, changes, or
disables quota enforcement. It must fail rather than be skipped when that
explicit host-provisioned fixture is invalid.

The Makepad compatibility import is deliberately outside the workspace lint
scope. Verify it explicitly after an upstream import or vendor patch:

```sh
cargo test --manifest-path vendor/makepad/Cargo.toml -p makepad-script
cargo test --manifest-path vendor/makepad/Cargo.toml -p makepad-regex
```

This keeps failures in source owned by Splash actionable while preserving
separate behavioral coverage for the imported VM.

## Sustained fuzzing

Pull-request CI runs short 128-input smoke campaigns for every fuzz target.
The separate `Sustained Fuzzing` workflow runs daily and can be started
manually from GitHub Actions. It gives the differential `syntax` target and
the bounded `execution` target ten minutes each, the `lsp_document` target two
minutes for source and bounded advisory initialization/configuration-refresh
parsing, and the variable-limit `execution_limits`
target and no-spawn `bubblewrap_policy` target three minutes each, all with
per-input timeout and RSS ceilings. A failure uploads its ignored
`fuzz/artifacts` directory for 14 days.

Triage a downloaded crash before adding it to the repository:

```sh
cd fuzz
RUSTFLAGS='--cfg fuzzing' cargo +nightly fuzz run --sanitizer none syntax artifacts/syntax/crash-<sha>
RUSTFLAGS='--cfg fuzzing' cargo +nightly fuzz tmin --sanitizer none syntax artifacts/syntax/crash-<sha>
```

Then add a focused unit or integration regression and, when it improves the
campaign, a reviewed text, JSON, or `.seed` input under `fuzz/corpus`. Do not
commit raw generated corpus entries or `fuzz/artifacts`; they can include
unreviewed input and are intentionally ignored. Keep vendor parser fixes
documented in `vendor/makepad/PATCHES.md`.

## Language server

`splash-lsp` is a host-only stdio server for editor clients. It advertises
UTF-16 positions, full document synchronization, syntax diagnostics,
whole-document canonical formatting, top-level `fn`/`let` document symbols,
same-document lexical definition/reference requests, binding-kind hover, and
symbol highlights, lexical completion, and guarded rename:

```sh
cargo run -p splash-lsp
```

It receives document text through LSP notifications plus optional bounded
initialization metadata. It does not read the document URI, evaluate Splash
code, construct a capability host, resolve arbitrary imported modules, or load
a Rust adapter. The grammar-aware lexical index covers the final binding
introduced by `use`, named functions, `let`, function and lambda parameters,
and `for` bindings already introduced in a visible runtime scope. It does not
infer forward references, general types, arbitrary aliases, mutations, record keys, or
arbitrary member fields. A
definition retained before the fixed 4,096-occurrence budget is exhausted
remains available for definition and hover, while reference and highlight
requests fail instead of returning a partial set from a truncated index.
Highlights are neutral resolved occurrences of one lexical binding because the
index does not classify assignment reads and writes.

Completion uses a separate lazily cached report. Expression-position
identifiers, including unresolved partial names, are retained as sites; binding
declarations, import paths, record keys, and member names are not sites. At a
site the server returns every retained lexical binding whose half-open
visibility interval contains the token start, deduplicated by the innermost
binding and sorted by name. It does not filter by the current spelling, so LSP
client caching and backspace remain correct. Every item replaces the complete
identifier. Invalid source is considered only through the first syntax
diagnostic, and only sites ending at or before that boundary are usable.
Symbols and sites have independent 4,096-entry caps; either truncation sets
`isIncomplete`. A retained site remains usable when only the site list is
truncated. When symbols are truncated the server returns no candidates, because
an omitted inner definition could shadow a retained outer binding.

For an exact visible `let binding = { ... }` initializer, the server separately
retains a bounded static record shape and exact `let alias = binding` or
`let alias = binding.child` edges. At a direct `binding.field` site or a direct
`binding.child.field` site whose `child: { ... }` value is an exact literal,
including a lexical alias chain of at most 16 hops with at most one child
selection, it can complete the literal's field names, hover a known field, and
navigate to that field key. Each alias target resolves at its original source
position, preserving lexical shadowing. This is source-only advisory metadata,
not runtime type inference: it does not follow parenthesized or computed
aliases, parenthesized or computed child values, deeper child aliases or paths,
assignments, control flow, function returns, imported values, or runtime data.
Duplicate parent record fields discard every child shape, and duplicate child
fields discard that child shape. The LSP stops using a shape after an earlier
direct write or a potentially mutating member, index, call, or escape path
through the root or any retained root or child alias resolving to that root. The
report retains at most 1,024 root shapes, 4,096 aggregate root-and-child fields,
and 1,024 direct alias edges. A truncated shape report marks a retained member
completion `isIncomplete`; a truncated alias report returns no static field
items, marks completion incomplete, and disables static field hover and
definition. Static field hover and definition also fail closed when the lexical
index is truncated, because an omitted earlier reference could be a mutation.

The server separately recognizes a complete, lexically visible `use mod.tool`
binding before the safe syntax boundary. At a direct `tool.` member site it
offers only `call`, `call_json`, `start`, and `start_json`, with an exact member
replacement edit. It does not offer those members for a shadowed `tool`, a
different import path, chained property access, or source after the first
diagnostic. This uses no catalog or adapter lookup, and a suggestion never
implies a capability grant.

An editor integration may provide an advisory projection of the host's current
tool catalog during LSP initialization or later through
`workspace/didChangeConfiguration`. The server reads only
`initializationOptions.splash.toolCatalog` or `settings.splash.toolCatalog`;
this is an array compatible with the `name`, `format`, and `description` fields
emitted by `CapabilityRuntime::tool_catalog()` or `splash catalog`:

```json
{
  "splash": {
    "toolCatalog": [
      {
        "name": "text.echo",
        "format": "text",
        "description": "Returns text unchanged."
      },
      {
        "name": "math.add",
        "format": "json",
        "description": "Adds two integer fields."
      }
    ]
  }
}
```

For an exact visible `use mod.tool` binding, the LSP completes the first string
literal argument of direct `tool.call` and `tool.start` from `text` entries,
and direct `tool.call_json` and `tool.start_json` from `json` entries. It
replaces only the literal contents. A current-line unterminated literal can
receive this completion while it is being typed, but comments, ordinary
strings, later arguments, shadowed bindings, and other import paths do not.

This metadata is retained only by the LSP; the server never reads a catalog
from a URI, file, environment, adapter, or capability runtime. It treats both
initialization options and configuration updates as advisory client input, not
as a current or trusted policy snapshot. An omitted `toolCatalog` configuration
key retains its prior projection, JSON `null` explicitly clears it, and an
invalid format, duplicate name, malformed entry, or over-limit replacement
discards only the tool catalog and marks matching completion `isIncomplete`; no
partial catalog is presented. A valid empty array is a complete empty catalog.
It retains at most 128 entries, 512 KiB of names and descriptions, 128-byte
lowercase tool names, and 4 KiB descriptions. A completion, description, or
matching envelope format never grants a lease: runtime reservation and an
active capability lease remain the authority boundary.

An editor integration may separately provide an advisory module-interface
projection through `initializationOptions.splash.moduleCatalog` or a later
`settings.splash.moduleCatalog` configuration update:

```json
{
  "splash": {
    "moduleCatalog": [
      {
        "path": "mod.app.weather",
        "description": "Host-provided weather module."
      },
      {
        "path": "mod.app.weather.current",
        "description": "Returns current forecast data.",
        "callMode": "deferred",
        "callShape": "single_json",
        "inputFields": [
          {"name": "location", "type": "string", "required": true}
        ],
        "outputFields": [
          {"name": "temperature", "type": "number", "required": true}
        ]
      }
    ]
  }
}
```

The LSP completes the current segment in a direct statement-position `use
mod.*` path, and bounded catalog paths below a direct visible imported-module
binding. It does not offer metadata-defined members for `mod.tool`, which keeps
its fixed four language methods. The server neither reads a module URI or file,
nor resolves, validates, installs, or loads a module; it also does not inspect
runtime exports or infer general fields. An omitted `moduleCatalog` key retains
its prior projection, JSON `null` explicitly clears it, and a malformed update
makes only module completion unavailable. Tool and module updates are
independent of each other and of the atomic workflow-data pair. A malformed
`settings` value or non-object `settings.splash` invalidates all advisory
catalogs so the server cannot retain stale metadata.

Each descriptor must use a canonical `mod.*` path with at least one following
identifier, at most 16 path segments and 256 path bytes, plus an optional
4 KiB description and optional exact-leaf `callMode` of `synchronous` or
`deferred`, plus an optional exact-leaf `callShape` of `single_json` and its
optional compact `inputFields` and `outputFields` record views. A mode-bearing
path must be at least `mod.<module>.<method>`; a shape requires a mode and
record fields require that shape. Each field has a canonical identifier up to
128 bytes, one fixed JSON type, an explicit Boolean `required` bit, and an
optional 4 KiB description. The LSP retains at most 256 descriptors, 1,024
aggregate input fields, 1,024 aggregate output fields, and 512 KiB of
path/description/call-mode/call-shape/field bytes. Paths below the fixed
`mod.tool` namespace are rejected. A malformed recognized call mode, shape, or
field projection, a shape without a mode, record fields without a shape,
duplicate path, malformed descriptor, or over-limit projection is discarded as
a whole and marks matching completion `isIncomplete`; no partial interface is
presented. See [Editor module interface
projection](module-catalog.md) for the complete contract. A deferred member is
labeled as returning a promise, but the LSP never inserts `await()` or makes a
host binding available or authorizes a capability.

The LSP also serves bounded `textDocument/signatureHelp` for a direct visible
`mod.tool` call and an exact visible advisory module leaf with both `callMode`
and `callShape: "single_json"`. Fixed `mod.tool` signatures describe their text
or JSON bridge; only that explicit shape gives a direct module one
JSON-compatible `input` and synchronous or deferred result label. Mode-only
metadata still completes and hovers, but has no assumed arity. The cursor
scanner accepts an in-progress string argument, but rejects a cursor inside a
comment, mismatched delimiters, deep nesting, shadowed receivers, truncated
scope/import metadata, and unknown paths. It never reads a runtime, resolves a
module, or grants authority. When a shaped leaf also supplies `inputFields` or
`outputFields`, its plain-text hover and signature documentation list bounded
field names, fixed JSON types, required bits, and optional descriptions. It can
additionally complete an undeclared top-level key only in that leaf's first
direct literal record argument from `inputFields`, after the same visible-import
and exact-leaf checks. For an exact original binding
`let result = imported.method(input)` on a synchronous leaf, or the exact
deferred `.await()` form, it also completes and hovers top-level
`result.field` names from `outputFields`. It follows exact local
`let alias = result` chains of at most 16 hops, but rejects computed/deeper
aliases, mutations and escapes, nested result chains, parenthesized/computed
initializers, extra arguments, mismatched call mode, and source beyond the
safe diagnostic prefix. It does not inspect a runtime value, evaluate JSON
Schema, or validate a contract.

For an approved dataflow authoring session, an editor integration may also
provide a bounded projection through
`initializationOptions.splash.workflowDataCatalog`. It is a normalized list of
input fields and named step-output fields, derived by the host from its own
`WorkflowDataContract` or approved plan. The LSP completes only direct,
unshadowed `workflow.input.*` and `workflow.outputs.<stepId>.*` paths, and
hovers known projected fields with plain-text documentation. It neither
introduces `workflow` when the projection is absent nor independently claims
that a planned output is in the runtime completed prefix. A host linked with
`splash-workflow` can generate a validated projection from a bound dataflow
prefix, checkpoint, or the exact retained state of a suspended continuation.
When the host also provides
`workflowDataStepContext`, the LSP accepts only an exact ordered prefix of the
projected output IDs and the next projected step ID, then filters output
completion and hover to that prefix. The generated update is runtime-confirmed
at the host boundary, while a local or imported `workflow` binding still wins
over editor metadata. Malformed, duplicate, or over-limit catalog metadata, or
malformed step context, is discarded as a whole and produces an incomplete
empty result for a matching path. A host may atomically replace the complete
workflow catalog/context pair through `workspace/didChangeConfiguration`; a
relevant partial or malformed refresh likewise discards the workflow projection
instead of retaining prior data. The LSP never validates data, loads a schema or
checkpoint, approves a plan, issues a lease, or authorizes a tool. See [Editor
workflow-data projection](workflow-data-catalog.md) for the exact wire shape
and bounds. A host may explicitly clear a terminal or unavailable projection by
sending both workflow keys as JSON `null`; one null or a partial pair fails
closed.

Rename is advertised only when the editor supports versioned
`documentChanges`. It refuses import path edits and truncated reports, validates
the new name with the canonical lexer, reparses the rewritten source, and
requires its complete lexical report to equal the remapped original report.
This prevents indexed capture and shadowing drift; it does not claim module,
field, type, reflection, or forward-reference semantics. Returned edits carry
the exact open-document version.

Lexical navigation and completion reports are lazily cached per document
version and discarded on a full change or close. The server retains at most 128
open documents and refuses to retain document text above the normal 256 KiB
Splash source cap.

## Syntax fuzzing

The standalone `fuzz` package has thirteen bounded targets. `syntax` differentially
exercises the canonical profile and the vendored VM parser under a rotating set
of valid resource profiles, from 64 bytes, 8 tokens, and 2 nesting levels up
to a 16 KiB source cap, a 2,048-token cap, and a 64-level nesting cap. It also
sends every bounded UTF-8 input through the broader VM-compatibility preflight,
so inherited parser paths remain covered even when canonical validation rejects
the source. It asserts that every source accepted by the canonical preflight is
also accepted by the VM parser, and that successful canonical formatting stays
accepted and idempotent. It also checks
that every accepted source's top-level declaration outline has ordered,
non-overlapping, UTF-8-boundary-safe spans that contain the exact declared
identifier.
The same target validates the direct tool-call hint outline: its retained count
must not exceed the fixed cap, its spans must be ordered UTF-8 boundaries
within the source, and any decoded literal name must correspond to a direct
string-literal span. The outline remains a source-review aid rather than an
authorization mechanism.
The target also validates the bounded lexical symbol index: definitions are
ordered, every retained definition and resolved reference is an exact UTF-8
identifier span, and the combined count never exceeds 4,096 occurrences.
For every bounded UTF-8 input, including invalid source, it also checks lexical
completion site ordering and identity, half-open visibility intervals, valid
prefix boundaries, independent symbol/site caps, and truncation signals. The
same invalid-source coverage validates bounded source-only import reports:
every retained `mod.<path>` spelling and final binding span is ordered,
UTF-8-safe, within the safe prefix, and structurally consistent; truncation is
explicit at the fixed import cap. It also validates direct literal-record root
and exact child shape spans, unique field names, direct alias binding, target,
and optional child-selector spans, safe-prefix boundaries, and the separate
shape, aggregate root-and-child field, and alias caps.
`lsp_document` feeds bounded UTF-8 source through the production language
server's document lifecycle. It opens one fixed local URI, requests formatting,
outlining, completion, hover, definition, references, highlights, and guarded
rename across at most 33 UTF-8-boundary positions plus an invalid UTF-16
position, replaces the whole document to invalidate lazy reports, repeats the
requests, and closes the document. It accepts at most 16 KiB of fuzzer source
and has reviewed source `.splash` and advisory-configuration `.json` seeds.
For a parsed JSON value, it also exercises the bounded initialization and
configuration-refresh projection around a fixed document. The server uses a
fixed bounded advisory module catalog, including shaped direct-method input
field metadata, only to exercise catalog completion, top-level input-key
completion, hover, and signature help: the target never starts stdio, reads the
URI, resolves modules, evaluates Splash, creates a capability host, or invokes
an adapter.
`execution` starts a fresh, capability-free runtime for each syntactically
accepted input with an 8 KiB source cap, 1,024-token cap, 64-level nesting
cap, 8 KiB individual-string cap, 1,024 live operand values, 256 active call
frames, 4,096 instruction cap, one-instruction deadline sampling, and a 32 ms
terminal execution deadline. Script-level errors from
unavailable modules are expected. It creates `Runtime<(), ()>`, so no
capability or Rust adapter can run; a panic or hang is a fuzz failure.
`execution` explicitly collects its fresh VM after evaluation so retained heap
state cannot mask resource behavior. Their tracked `.splash` seeds cover
canonical dataflow, deferred tools, loops, lambdas, recoverable error control
flow, intentional instruction-limit behavior, and exponential string growth.
`execution_limits` rotates valid source, individual-string, retained-heap,
operand-stack, call-frame, syntax, instruction, sampling, and deadline profiles
through a fresh capability-free runtime. Equal soft and hard deadlines must terminate rather than leave a
resumable evaluation. Its cooperative one-nanosecond soft-budget profile may
yield, but it must then refuse a later `set_limits` request so the continuation
keeps its original resource contract. A completed evaluation must accept the
replacement profile.
The target collects the VM after each case and never installs an adapter or
capability. Its reviewed `.splash` seeds cover a cooperative budget yield and a
tight instruction limit. `bubblewrap_policy` maps at most 64 fuzz bytes onto
only host-derived Bubblewrap and runtime paths, host-authored file-root
registrations, private tmpfs modes, aggregate tmpfs limits, aggregate Linux
project-quota policy state, and opaque manifest selectors. It never calls
`spawn`, launches Bubblewrap, or probes a live filesystem quota. The target
asserts that every modeled unsafe configuration fails compilation: an unknown
or unsupported resource, an active writable host root without explicit
unbounded-write acknowledgement, under bounded-write mode, or under an
aggregate project-quota policy without a verified quota binding; missing
user-namespace lockdown for bounded-write mode; unbounded private `/tmp` where
a bound is required; or bounded tmpfs capacity above the selected aggregate
maximum. For a successful plan it verifies exact manifest retention, the fixed
networkless/cleared-environment/capability-drop arguments, and selection of
only the requested roots. Its reviewed `.seed` corpus covers ordinary,
bounded, accepted and rejected aggregate, and unsupported-resource
configurations. `rollback_anchor_service` sends each bounded fuzz input both
through the trusted client response decoder and through the embeddable service
request dispatcher backed by a process-local test anchor. It never starts a
listener or claims that the test backend is durable; every accepted server
response must remain within the fixed protocol response limit. Its reviewed
JSON seeds include valid load and compare-and-swap requests as well as client
response shapes. `workflow_draft` feeds
bounded UTF-8 JSON into the data-only `WorkflowDraft` decoder, then checks that
every accepted draft
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
`capability_audit_journal` feeds bounded UTF-8 documents into the optional
durable capability-audit journal decoder. Every accepted journal must re-encode
and round-trip under its maximum retention capacity; a second data-derived
capacity exercises the decoder's bounded-retention rejection path. It never
creates a capability runtime, runs an adapter, or treats telemetry as execution
authority. Its tracked JSON seeds cover a valid allowed audit event and an
inconsistent retention boundary.
`cross_stream_telemetry` constructs bounded capability-audit and workflow-event
batches under byte-derived source cursors and aggregate capacities. It checks
source-family isolation, explicit non-one segment registration, exact replay
and gap rejection, aggregate eviction cursors, and source continuity after an
aggregate clear. It runs only a fixed local `text.echo` adapter to construct
audit telemetry; fuzz input never becomes Splash source, a tool name, or a
tool payload.
`durable_cross_stream_telemetry` feeds bounded UTF-8 documents through the
authenticated aggregate-journal decoder. Every accepted journal must re-encode
and round-trip under the maximum retention capacity, then accept one fixed
valid workflow event at a persisted source cursor when a source slot remains.
It never creates a capability host, runs an adapter, or treats aggregate
telemetry as recovery or authority.
`json_line_worker` feeds bounded arbitrary bytes through small, variable
`BufReader` capacities, optionally appends a line terminator, and attempts two
successive authenticated-frame reads. Every framing, UTF-8, size, or protocol
error must poison the channel before another read. The target owns only in-memory
I/O and never starts a worker or invokes a capability.

CI compiles all thirteen targets and performs a short 128-run coverage-only
smoke pass with `--sanitizer none`, plus separate short AddressSanitizer
campaigns for the LSP document lifecycle and Bubblewrap policy compiler. Run
the longer local commands below with the default sanitizer whenever the
platform supports it.

Install `cargo-fuzz` once, then run the target with nightly Rust:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run syntax -- -max_total_time=60 -max_len=16384 -dict=dictionaries/syntax.dict
RUSTFLAGS='--cfg fuzzing' cargo +nightly fuzz run lsp_document -- -max_total_time=60 -max_len=16384 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run execution -- -max_total_time=60 -max_len=8192 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run execution_limits -- -max_total_time=60 -max_len=8192 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run bubblewrap_policy -- -max_total_time=60 -max_len=64
cargo +nightly fuzz run workflow_draft -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run capability_lease -- -max_total_time=60 -max_len=8192
cargo +nightly fuzz run workflow_external_operation -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run workflow_event_journal -- -max_total_time=60 -max_len=196608
cargo +nightly fuzz run capability_audit_journal -- -max_total_time=60 -max_len=196608
cargo +nightly fuzz run cross_stream_telemetry -- -max_total_time=60 -max_len=4096
cargo +nightly fuzz run durable_cross_stream_telemetry -- -max_total_time=60 -max_len=196608
cargo +nightly fuzz run json_line_worker -- -max_total_time=60 -max_len=1048578
```

If AddressSanitizer's libFuzzer runtime does not initialize on a target, use
`--sanitizer none` as a coverage-only fallback. It keeps the differential
and resource-boundary assertions but does not provide memory-safety
instrumentation:

```sh
cargo +nightly fuzz run --sanitizer none syntax -- -max_total_time=60 -max_len=16384 -dict=dictionaries/syntax.dict
RUSTFLAGS='--cfg fuzzing' cargo +nightly fuzz run --sanitizer none lsp_document -- -max_total_time=60 -max_len=16384 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run --sanitizer none execution -- -max_total_time=60 -max_len=8192 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run --sanitizer none execution_limits -- -max_total_time=60 -max_len=8192 -dict=dictionaries/syntax.dict
cargo +nightly fuzz run --sanitizer none workflow_draft -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run --sanitizer none capability_lease -- -max_total_time=60 -max_len=8192
cargo +nightly fuzz run --sanitizer none workflow_external_operation -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run --sanitizer none workflow_event_journal -- -max_total_time=60 -max_len=196608
cargo +nightly fuzz run --sanitizer none capability_audit_journal -- -max_total_time=60 -max_len=196608
cargo +nightly fuzz run --sanitizer none cross_stream_telemetry -- -max_total_time=60 -max_len=4096
cargo +nightly fuzz run --sanitizer none durable_cross_stream_telemetry -- -max_total_time=60 -max_len=196608
cargo +nightly fuzz run --sanitizer none json_line_worker -- -max_total_time=60 -max_len=1048578
```

Reproduce a saved failure from the same directory with:

```sh
cargo +nightly fuzz run syntax artifacts/syntax/<artifact>
RUSTFLAGS='--cfg fuzzing' cargo +nightly fuzz run lsp_document artifacts/lsp_document/<artifact>
cargo +nightly fuzz run execution artifacts/execution/<artifact>
cargo +nightly fuzz run execution_limits artifacts/execution_limits/<artifact>
cargo +nightly fuzz run workflow_draft artifacts/workflow_draft/<artifact>
cargo +nightly fuzz run capability_lease artifacts/capability_lease/<artifact>
cargo +nightly fuzz run workflow_external_operation artifacts/workflow_external_operation/<artifact>
cargo +nightly fuzz run workflow_event_journal artifacts/workflow_event_journal/<artifact>
cargo +nightly fuzz run capability_audit_journal artifacts/capability_audit_journal/<artifact>
cargo +nightly fuzz run cross_stream_telemetry artifacts/cross_stream_telemetry/<artifact>
cargo +nightly fuzz run durable_cross_stream_telemetry artifacts/durable_cross_stream_telemetry/<artifact>
cargo +nightly fuzz run json_line_worker artifacts/json_line_worker/<artifact>
```
