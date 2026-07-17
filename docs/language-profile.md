# Splash Language Profile v0.2

This profile defines the portable, LLM-oriented subset exercised by the
standalone runtime. [Splash Grammar v0.2](grammar.md) is the normative source
producer contract. The `grammar_v0_2.splash` fixture is the normative
grammar-version regression, while `workflow_language.splash` exercises the
broader runtime profile. The v0.1 fixture remains a backward-compatibility
regression. Parser features outside the grammar and fixtures remain inherited
compatibility features until separately specified.

## Source contract

Provide normal Splash source. The runtime adds its own internal terminal
marker, so generated code must not depend on Makepad widget-host framing.
Before generating source, an LLM host may call `splash profile`. Its versioned
JSON response identifies the canonical profile, grammar path, default bounded
preflight and execution limits, effect-free CLI operations, and the authority
model. It creates no capability runtime and does not read source. The response
is metadata only: it is neither a complete grammar nor a substitute for the
normative [Splash Grammar v0.2](grammar.md), a host tool catalog, a capability
grant, or workflow approval. A host must supply its own current catalog
separately before an agent can propose effectful calls. Within one
`schema_version`, response objects may gain additive fields; integrations must
consume named fields and ignore unknown ones. A breaking response change must
use a new schema version.

For a multi-step proposal, call `splash workflow-schema` before producing a
workflow draft JSON document. It emits a JSON Schema draft plus an `x-splash`
extension for the decoder's aggregate source, wire-byte, and unique-step-ID
bounds. It describes only the data-only proposal envelope; it cannot select
tools, grants, dataflow schemas, approvals, checkpoints, results, or external
operation handles. Submit the resulting document to `splash workflow-review`
for effect-free syntax and direct-call review, then let the trusted host decide
whether to create a plan and issue any authority.

`workflow-review` returns JSON even when the draft envelope itself is rejected:
its finite `draft.error.code` is suitable for agent repair loops and omits raw
source and invalid identifiers. A decoded envelope has `draft.valid: true`;
the separate top-level `valid` then reports the canonical syntax status of its
steps. Neither result grants a capability or approves a workflow.

Run `splash check <file>` before execution when an LLM or editor produced the
source. The check enforces the canonical v0.2 grammar rather than merely
accepting the larger Makepad compatibility parser. Syntax preflight never
resolves imports, creates a host, or grants a tool capability. A source that
the canonical profile rejects never enters the inherited tokenizer or parser.
The default preflight budget is 256 KiB of source, 32,768 lexical tokens, and
128 syntax-nesting levels; an embedded host can lower all three through
`ExecutionLimits`.

`splash format <file>` applies the same profile and compatibility checks, then
writes canonical whitespace to standard output without evaluating source or
creating a capability host. It preserves comments and literal spellings;
`splash format --check <file>` is the non-writing CI/editor form. Format before
requesting execution, then use `splash check` when a structured diagnostic
report is needed. Formatted output is capped at four times the configured
source budget.

For effect-free editor or generator structure, Rust hosts can call
`splash_core::top_level_declarations` or its named, limit-aware variant. The
API applies the same bounded profile and VM compatibility checks as syntax
preflight, then returns byte spans for valid top-level `fn` and `let`
declarations only. It produces no recovery outline for invalid source and does
not resolve imports, construct a capability host, or execute source.
`splash outline <file>` exposes that result as structured JSON for local LLM
and editor-tool workflows; it emits diagnostics and exits nonzero when the
source is invalid.

For same-document navigation, Rust hosts can call
`splash_core::lexical_symbol_report` or its named, limit-aware variant. The
grammar-aware index records the final binding introduced by `use`, named
functions, `let`, function and lambda parameters, and `for` bindings, then
associates references resolved after each binding is introduced in the visible
runtime scope. Symbols are sorted by definition byte position and every span is
an exact UTF-8 identifier boundary. The combined definition/reference count is
fixed at 4,096 and `truncated` makes an incomplete result explicit. Invalid or
VM-incompatible source produces an empty report.

For bounded source-only import metadata, Rust hosts can call
`splash_core::module_import_report` or its named, limit-aware variant. Each
retained entry names the exact `mod.<path>` segments plus byte spans for the
full path and its final binding. It retains at most 1,024 complete imports and
sets `truncated` when later imports in the safe prefix were omitted. On an
incomplete editor snapshot, it retains only imports ending at or before
`valid_prefix_end_byte`; it never loads, resolves, or validates a referenced
module. A reported path is therefore not evidence that a Rust adapter exists,
that a tool appears in the current catalog, or that any capability was granted.

This is a conservative lexical service, not a module or type checker. It does
not load imported modules, infer forward references, resolve record keys or
member fields, evaluate source, create a capability host, or authorize a tool.
The LSP can serve a retained definition from a truncated report, but rejects a
reference request instead of presenting an incomplete set as exhaustive. It
also exposes binding-kind hover for a retained occurrence and neutral
same-document highlights; a truncated report cannot produce an exhaustive
highlight set. A client with versioned-document-edit support can also request a
guarded same-document rename. Splash validates the new name through
`splash_core::is_canonical_identifier`, reparses the bounded rewritten source,
and returns a version-bound edit only when the complete remapped lexical report
is identical apart from the selected name and shifted spans. Import paths and
truncated reports are not renameable. This is a fail-closed indexed lexical
guarantee, not module, field, type, reflection, forward-reference, or runtime
semantic analysis.

For same-document completion, Rust hosts can call
`splash_core::lexical_completion_report` or its named, limit-aware variant.
The report retains expression-position identifier sites separately from the
lexical symbols and gives every symbol a half-open byte interval in which the
binding is visible. A declaration becomes visible only after its initializer,
so `let value = value` does not resolve or complete the initializer from the
new binding. Same-scope redeclaration closes the old interval when the new
binding becomes visible, and leaving a function, lambda, or loop scope closes
its bindings before the following identifier.

Completion metadata is bounded independently to 4,096 sites and 4,096 retained
definition/reference occurrences, with a truncation signal for each. On
invalid or incomplete source, `valid_prefix_end_byte` is the first syntax
diagnostic byte; a consumer may use only sites ending at or before that
boundary. This permits a partial identifier immediately before an end-of-file
diagnostic without assigning meaning to later recovery tokens. The report does
not provide keywords, builtins, tool-catalog names, arbitrary imported-module
exports, types, record keys, or member fields, and it carries no runtime values
or authority. The LSP uses the separate import report only to recognize an
exact visible `use mod.tool` binding and suggest the four fixed language
methods `call`, `call_json`, `start`, and `start_json`. It never reads the host
catalog for those suggestions, and their presence is neither module resolution
nor a capability grant. An editor integration may separately provide a
bounded advisory projection through `initializationOptions.splash.toolCatalog`
or a later `settings.splash.toolCatalog` configuration update. That LSP-only
metadata can complete
the first literal name of a direct visible `tool.call`/`tool.start` from `text`
entries, or `tool.call_json`/`tool.start_json` from `json` entries. It is not
part of the core report, never causes a runtime/catalog lookup, and cannot make
a tool current, installed, approved, or callable. Consumers must not derive
candidates from a symbol-truncated report: an omitted inner definition may
shadow a retained outer binding. The LSP therefore returns an incomplete empty
candidate set in that case.

An editor may separately supply `initializationOptions.splash.moduleCatalog`
or a later `settings.splash.moduleCatalog` update: a bounded list of canonical
`mod.*` paths plus optional plain-text descriptions. This LSP-only
projection can complete the current segment of a direct statement-position
`use mod.*` path, or bounded catalog paths below a direct visible imported-module
binding. It is not part of the core report and does not load a source file,
resolve or validate a module, inspect runtime exports, infer arbitrary fields,
or make a Rust adapter current or callable. `mod.tool` remains a fixed language
surface and never receives metadata-defined members. The client-supplied
projection is advisory, potentially stale, and never authority; an omitted key
retains the prior projection, JSON `null` explicitly clears it, and malformed,
duplicate, or over-limit input is discarded as a whole and makes matching
completion incomplete. Tool and module updates are independent of each other
and of the atomic workflow-data pair. A malformed `settings` value or non-object
`settings.splash` clears all advisory catalogs. See [Editor module interface
projection](module-catalog.md) for the exact wire shape and limits.

For dataflow authoring, an editor may instead supply the separate bounded
`initializationOptions.splash.workflowDataCatalog` projection. It contains only
host-selected input fields and per-step output fields, and can complete direct
unshadowed `workflow.input.*` and `workflow.outputs.<stepId>.*` paths plus hover
known fields. It is not a JSON Schema loader or a runtime data snapshot: the
editor cannot infer that an output has completed, validate an input, approve a
workflow, issue a capability lease, or make a Rust adapter callable. Missing
metadata does not create a `workflow` namespace; malformed or over-limit
metadata is discarded as a whole and returns an incomplete empty match. A
visible local or imported `workflow` binding shadows it. An optional
`workflowDataStepContext` can structurally identify the host-declared projected
completed prefix and next projected step, which filters output completion and
hover. `splash-workflow` can derive this pair from a validated dataflow prefix,
checkpoint, or suspended continuation, but the editor still cannot inspect or
authorize runtime state. Invalid context discards the full workflow projection.
A host can atomically replace both values through `workspace/didChangeConfiguration`;
a partial or malformed relevant refresh also discards the workflow projection.
Sending both values as JSON `null` explicitly clears a terminal projection.
See [Editor workflow-data projection](workflow-data-catalog.md) for the exact
wire shape, limits, and non-authority boundary.

For a pre-approval effect summary, hosts can call
`splash_core::tool_call_hint_report` or `tool_call_hint_report_named`; `splash
tool-calls <file>` exposes the same result as structured JSON. The report
retains at most 1,024 direct sites and marks `truncated` when later sites were
omitted. A hint recognizes only the direct source spelling `tool.call`,
`tool.start`, `tool.call_json`, or `tool.start_json`, with a decoded name only
when the first argument is a direct string literal. It does not resolve
imports, aliases, shadowing, control flow, or runtime values, and it never
evaluates source or creates a capability host. It is therefore a review
presentation, not static authorization: the host must still issue a capability
lease and runtime reservation validates every actual call.

For an ordered LLM workflow, `WorkflowPlan::review` returns one data-only
`WorkflowStepReview` per trusted step. Each item contains the step ID,
canonical syntax report, and direct tool-call hints only when that step is
valid. `tool_calls_truncated` records whether that step's result was capped by
the core 1,024-site or workflow-wide 4,096-site limit. This keeps an invalid
step distinguishable from a valid step with no direct calls. The review uses no
capability host, never evaluates source, and does not issue an approval or
lease. A host may use it to prepare a human or policy review surface before calling
`approve_with_step_capability_leases` or the host-policy convenience API
`approve_with_step_capability_policies`, but it must not derive authority from
hints: aliases, reachability, and computed names remain runtime checks. The
policy form checks its named bindings to trusted plan steps before issuing
non-serializable runtime leases; it is not Splash-visible authority.

An LLM can submit the ordered source list through the bounded versioned
`WorkflowDraft` JSON format before any engine-owned plan exists. Its
`review` path and the `splash workflow-review` CLI command return the same
per-step syntax and bounded hint data without creating a capability runtime.
The draft contains no grant or approval and must still pass a separate trusted
host policy decision; see [Workflow drafts](workflow-drafts.md).

`Runtime::eval` and `CapabilityRuntime::eval` enforce the same profile before
execution. `check_vm_compatibility` and its named variant are bounded,
effect-free inherited-parser checks for trusted Makepad migration or UI-host
code; they do not resolve imports, install modules, or grant authority.
`Runtime::eval_vm_compatibility` runs that check before it evaluates, but none
of these compatibility APIs may be exposed to generated source or a capability
host. The standalone compatibility path rejects Makepad `@(index)` host-value
tokens; Rust values enter Splash only through reviewed host adapters.
`WorkflowEngine` preserves a preflight failure as a step-scoped
`WorkflowError::StepRejected` with the structured syntax report.
Its retained event records only the diagnostic count, truncation flag, and
completed-prefix count so long-lived workflow telemetry does not cache source
diagnostic text.

The canonical checker and the vendored VM parser are separate implementations.
Every canonical source first passes the profile, then uses the same bounded VM
preflight as trusted compatibility validation before evaluation; the shipped
core and capability-host fixtures exercise that path with real execution and
tool bindings. The `syntax` fuzz target differentially
checks canonical preflight, VM parsing, and formatting. The separate
capability-free `execution` target runs accepted programs under strict source,
token, instruction, and wall-clock bounds. This is regression coverage, not a
claim that the two parsers are formally equivalent. Sustained parser/VM
differential fuzzing and corpus triage remain release requirements before the
language profile is stable.

The current profile supports:

- `let` declarations and mutation.
- Functions with `fn`, arguments, `return`, and lexical closures.
- Numbers, strings, booleans, arrays, and record literals.
- Field access, array operations, conditionals, loops, and assertions.
- Recoverable `try protected catch fallback` expressions without an error
  binding or transactional rollback.
- Module imports through `use mod.<name>`.
- Host-defined tools through `use mod.tool`, `tool.call(name, input)`, and
  `tool.start(name, input).await()`.
- JSON envelope tools through `tool.call_json(name, value)` and
  `tool.start_json(name, value).await()`.

Example:

```splash
use mod.tool

let summary = tool.call("text.echo", "summarize the release notes")
summary
```

## Effect rules

The core runtime does not install `mod.fs`, `mod.run`, or `mod.net`. A script
cannot acquire authority by importing a name. The host must create a runtime
with a registered tool policy before `tool.call` or `tool.start` can succeed.

For an operator-approved execution, a host can issue a process-local
`CapabilityLease` and use `CapabilityRuntime::eval_with_capability_lease`, or
place the lease in a workflow approval. The lease can only narrow registered
tool names and call budgets, records the exact host catalog fingerprint, and
checks every call when it is reserved. Consequently, using a computed string
as the `name` argument does not bypass approval. A lease remains active across
`await` and the resulting continuation; it is a host-side authority object,
not a Splash value or a serialized credential.

The v0.1 tool contract accepts string input and returns string output.
`tool.call` is synchronous. `tool.start` reserves the same capability and
returns an opaque promise; `await()` pauses the current script until the
trusted host delivers its result. For host-pump tools, one default
`CapabilityRuntime::pump` tick runs at most one tool; `pump_up_to` is
available for an explicitly bounded batch. The default pending-promise cap is
64 and may be lowered by an embedded host.

`ToolPolicy::json` opts a capability into a structured boundary. The input and
output must each be a JSON object or array. `call_json` and `start_json`
serialize the supplied Splash record or array, while their results remain JSON
strings that generated code must turn back into values with `parse_json()`.
This preserves a simple Rust bridge through `serde_json::Value` without
allowing scripts to import crates directly.

Hosts can register a `JsonToolContract` to enforce bounded schemas for those
JSON envelopes. Contract checks run before the handler and before output
returns to Splash; metadata-only schemas in the catalog do not enforce input
or output. The exact supported subset is defined in
[JSON tool contracts](schema-contracts.md).

For an approved `WorkflowEngine` dataflow run, the host may inject a bounded
JSON `workflow` value with `input` and completed-prefix `outputs` fields. It
is reconstructed by the host for each step and is not a capability, module,
or ambient global available to ordinary evaluation. The context is bound to
the workflow approval and remains stable through `await`; a computed tool name
read from it still passes through the active capability lease. Completed script
values must convert to bounded JSON before they can become a later step's
output. A host can bind a `WorkflowDataContract` with a compiled input schema
and one ordered output schema for every trusted plan step. The host validates
the input before approval and each output before it becomes a later step's
data; the contract is not Splash-visible, serializable, or selected from a
workflow draft or checkpoint. Contract-aware checkpoints retain only its
digest and require the matching host-rebuilt contract during resume. See
[Workflow drafts](workflow-drafts.md) and
[Workflow checkpoints](workflow-checkpoints.md).

The promise API is cooperative. It does not grant a script a thread, a task
runtime, or a way to invoke an adapter without the host's pump. Structured
values and streaming dataflow remain additive, versioned host APIs rather than
implicit VM effects.

An external-only tool is a separate deferred mode selected by the host. It
cannot be called synchronously and has no in-process handler. The host claims
the pending invocation, dispatches it through its own adapter, and completes
or cancels it later. This does not expose an external API to Splash source;
the script still sees only its promise. See [External tools](external-tools.md).

A host may configure a maximum deferred duration per tool. The duration starts
when start reserves the operation. The host uses expire_timed_out_tools from
its event loop to resolve due external work; pump also rejects expired local
queued work before its handler runs. This does not interrupt a Rust handler
that is already executing.

For external tools, retry policy is also owned by the host. Splash source has
no retry primitive: a host may make a bounded retry of an already claimed
operation, preserving its idempotency key, but that does not create another
script-visible call or grant new authority. `try/catch` may select a fallback
after the terminal promise fails, but it cannot request a worker retry or prove
that an uncertain external effect did not occur.

An external tool may also emit bounded progress chunks to the host after it is
claimed. Those chunks are optionally redacted by trusted Rust code and never
become a Splash value or a script-level stream; `await()` still resolves only
the terminal result. See [External tools](external-tools.md) for the host
streaming contract.

For a live claimed external operation, the host may use an authenticated worker
reconciliation request to observe `running` or apply a terminal result. This
is entirely outside the language: Splash source cannot see the operation key,
worker frame, status poll, or progress state. The host still validates a
terminal payload against the registered text/JSON contract before it resumes
`await()`. A reconciliation result does not restore a promise after a process
restart; durable workflow policy remains host-owned.

A runtime evaluates one script at a time. A host must resume a paused script
before evaluating new source on that runtime; independent workflows should use
separate runtime instances.

Workflow restart state is also host-owned. Splash source cannot create or load
a checkpoint, and a persisted checkpoint never restores variables, promises,
or tool authority. The host reconstructs a trusted plan and explicitly approves
the remaining suffix; see [Workflow checkpoints](workflow-checkpoints.md).
For a live external `await`, the workflow engine retains its nonserializable
approval and returns `StepSuspended`; the trusted host must claim and complete
or cancel that exact operation through the engine before the workflow can
continue. This is not a restart mechanism or an authority grant to the
external adapter.
For uncertain external effects, a host may additionally keep a
[durable operation ledger](workflow-operations.md), but the script cannot read
or mutate its keys, input digest, worker observation, or restart policy.

## LLM generation rules

- Generate source only; do not add Makepad widget wrappers or `runsplash`
  fences when targeting the CLI/runtime.
- Follow the [canonical grammar](grammar.md), run `splash format`, then use
  `splash check` before requesting execution.
- Do not use Makepad compatibility syntax such as `var`, `match`, the legacy
  catch-less `try`/`ok` form, typed or destructuring declarations,
  single-quoted strings, range operators, or whitespace-separated record
  members; `splash check` rejects it.
- Import `mod.tool` before calling a tool.
- Use canonical `try protected catch fallback` for bounded local recovery. The
  fallback cannot inspect the error, and hard instruction/deadline termination
  remains uncatchable. End each block branch with a value-producing expression;
  use `nil` when the branch has no other result. Parenthesize a record literal
  used as the whole protected or fallback branch.
- Treat a denied tool call as a catchable runtime error that is still audited.
  Do not retry by attempting filesystem, process, or network imports.
- Do not assume a caught tool failure rolled back an effect or refunded its
  call budget. Invoke another effectful fallback only when trusted host policy
  defines that recovery as safe.
- Do not generate retry loops for external tools; the host applies its bounded
  retry policy and reports the final result through the existing promise.
- Do not assume external progress output is readable from Splash source; use
  the terminal promise result supplied by the host.
- Keep effectful work in named tools and pure transformations in Splash code.
- Generate against the host-supplied tool catalog only; descriptions and
  schemas do not grant access to unlisted tools.
- Use the effect-free `tool-calls` outline to present direct candidate calls to
  an operator, but do not treat it as proof of the executed tool set. Dynamic
  names and aliases are resolved only by the runtime capability boundary.
- Treat an approval as a bound set of names and call limits, including when a
  tool name comes from a computed string; it cannot be widened from Splash.
- Await a deferred tool result before using it; do not assume `start` performs
  an effect until a host pump or external completion has delivered its result.
- Use record or array envelopes for JSON tools, then call `parse_json()` on
  their returned strings before reading fields.
