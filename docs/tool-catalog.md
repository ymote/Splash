# Host Tool Catalog

An LLM orchestrator should build its prompt from
`CapabilityRuntime::tool_catalog()`, not from a hard-coded list of ambient
commands. The catalog contains only capabilities registered on that runtime,
in stable name order.

Each `ToolDescriptor` includes the name, envelope format, dispatch mode, call,
attempt, and byte limits, description, optional JSON input/output schemas, and
`contract_enforced`. `contract_enforced: true` means the published schemas run
at the Rust tool boundary before handler invocation and before output returns.
`false` means any schemas are prompt metadata only; text tools always report
`false`. `max_attempts` is the host-only bound for an external operation; it
does not give Splash source a retry API. The runtime does not install catalog
access into `mod.tool`: a script cannot discover or mint capabilities by
inspecting descriptions.

Registered names are lowercase ASCII identifiers containing letters, digits,
`.`, `_`, or `-`, and are limited to 128 bytes. This keeps catalog entries,
leases, deferred handles, and retained audit labels bounded. An unrecognized
script-provided name that is invalid or oversized is represented in the audit
view by a fixed-length BLAKE3 digest label rather than copied verbatim. The
label is scoped to a live runtime session when operating-system entropy or a
host-supplied capability session nonce is available. A no-entropy local-only
runtime uses only a process-local session counter, so its labels can repeat
after restart and are not a confidentiality boundary.

For a UI or LLM review step, a host may pair the catalog with
`splash_core::tool_call_hint_report` or `splash tool-calls <file>`. That
outline retains at most 1,024 direct sites and exposes truncation explicitly;
it is deliberately limited to direct source spelling and does not resolve
aliases, shadowing, flow, or computed names. It is never sufficient to approve
a call: the lease and reservation-time policy checks remain the authority
boundary. It recognizes only direct `mod.tool` calls. A host that uses direct
capability modules must separately review the fixed module-to-tool mapping and
grant the target tool name; the runtime still enforces that lease at the
underlying tool reservation.

`CapabilityCatalogLimits` bounds the whole host-visible catalog, not just an
individual descriptor. The default permits at most 128 registered tools and a
512 KiB serialized catalog. Registration that would exceed either limit fails
before the descriptor or handler is retained. Hosts with a deliberately larger
reviewed catalog, or a tighter embedded allocation budget, select their limits
when they create the runtime:

```rust
use splash_capabilities::{CapabilityCatalogLimits, CapabilityRuntime};
use splash_core::ExecutionLimits;

let runtime = CapabilityRuntime::with_limits_pending_and_catalog(
    ExecutionLimits::default(),
    32,
    CapabilityCatalogLimits {
        max_tools: 24,
        max_serialized_bytes: 96 * 1024,
    },
)?;
```

`mobile::MobileRuntimeBuilder::with_limits_and_catalog` applies the same
immutable aggregate bounds before a mobile or embedded catalog is sealed.
Neither bound is script-visible authority, and neither makes arbitrary tool
metadata safe to trust.

When a deferred deadline is configured, max_deferred_millis is also present in
the catalog. It is a host scheduling constraint, not an instruction for a
script to add a timer or retry loop.

When `stream` is present, it describes the host-only chunk limits for an
external tool: maximum chunks, source bytes per chunk, aggregate source bytes,
and aggregate bytes released after redaction. The setting does not make a
stream readable from `mod.tool`; it tells a worker adapter how much bounded
progress output it may send through the host lifecycle.

```rust
use splash_capabilities::{json, JsonToolContract, ToolMetadata, ToolPolicy};

let contract = JsonToolContract::new(
    json!({
        "type": "object",
        "properties": {"left": {"type": "integer"}},
        "required": ["left"],
        "additionalProperties": false
    }),
    json!({
        "type": "object",
        "properties": {"total": {"type": "integer"}},
        "required": ["total"],
        "additionalProperties": false
    }),
)?;

runtime.register_validated_json_tool(
    ToolPolicy::json("math.add"),
    ToolMetadata::new("Adds an integer field."),
    contract,
    |request| Ok(serde_json::json!({"total": 42})),
)?;
```

Contracts use Splash's bounded executable schema subset, so the catalog schema
shown here is enforced at the tool boundary. See [JSON tool contracts](schema-contracts.md)
for the supported keywords and limits. `ToolMetadata::with_input_schema` and
`with_output_schema` remain available when a host needs non-enforcing prompt
metadata only.

## Direct Capability Modules

For static, LLM-friendly dataflow, a host can expose a reviewed JSON tool as a
flat direct module method. This removes the JSON-string round trip from source:

```rust
use splash_capabilities::CapabilityModule;

runtime.register_capability_module(
    CapabilityModule::new("arithmetic", "Reviewed arithmetic adapters.")
        .with_method("add", "math.add"),
)?;
```

```splash
use mod.arithmetic

let math = arithmetic
let result = math.add({left: 20, right: 22})
result.total
```

This is not a general import system or Rust package bridge. A direct module is
setup-only, has one canonical identifier segment, and its methods map one-to-one
to existing tools. `with_method` accepts only a synchronous `host_pump` JSON
tool with an executable input/output contract; it accepts one bounded JSON
record or array and returns decoded bounded JSON. A host can instead choose
`with_deferred_method` for an existing contract-enforced JSON tool. That
method returns a bounded promise and `await()` returns decoded bounded JSON;
it may use either host-pump or external dispatch, but still reserves the same
underlying target tool. In both modes the target retains its call limit,
metadata, audit entry, JSON validation, and active capability-lease check.
Prompt-only schemas, text tools, duplicate target aliases, existing VM module
names, dynamic libraries, and script-selected crates remain unavailable.
After the host has installed the fixed methods, Splash freezes both the direct
module object and `mod.tool`; a script cannot rewrite a reviewed method through
the import or any local alias, either during the current evaluation or for a
later evaluation on the same runtime.

```splash
use mod.remote_math

let result = remote_math.add({left: 20, right: 22}).await()
result.total
```

The host decides the mode during setup; source cannot turn a synchronous method
into a deferred one or select a dispatch backend. The host-visible module
catalog and every `direct_module_calls` review hint include `mode` as either
`"synchronous"` or `"deferred"`, and that mode is included in the capability
lease fingerprint.

`CapabilityModuleLimits` defaults to 32 modules, 128 methods, and a 256 KiB
bound across every retained direct-module catalog representation, with fixed
hard ceilings of 128 modules, 256 methods, and 512 KiB. That includes the
host-visible LSP interface projection and the exact mapping serialization
retained for capability-lease fingerprints. The combined module and method
projection is also capped at 256 entries so it can be passed to the LSP
unchanged. Schema-derived input-field metadata and output-field metadata are
each independently capped at 1,024 aggregate fields so the generated LSP
projection stays within the same fail-closed editor bounds.
`CapabilityRuntime::with_limits_pending_catalog_and_module_limits` lets a
constrained host lower those bounds. Every direct target's configured
input and output byte limits must fit the runtime JSON bridge: the smaller of
`ExecutionLimits::max_source_bytes` and 64 KiB. JSON container depth is also
bounded by the smaller of `max_syntax_nesting` and 64. The module catalog seals
when a lease is issued or source is first evaluated, so a new syntax alias
cannot appear under an existing approval. The stable module name, description,
method name, mode, target tool, call shape, and any compact schema-derived
input- or output-field projection are also included in the capability catalog
fingerprint recorded by that lease, binding a reviewed direct call to its exact
underlying capability and invocation behavior.

`CapabilityRuntime::capability_module_catalog()` returns the reviewed mapping
for a host prompt or operator UI. `module_interface_catalog()` returns bounded
`{path, description, callMode?, callShape?, inputFields?, outputFields?}`
entries accepted by the advisory LSP `moduleCatalog` projection. Direct method
entries carry their host-selected `synchronous` or `deferred` mode and
`single_json` call shape, so the editor can label a deferred call as returning
a promise and offer a bounded one-value signature without guessing its argument
contract. When an executable input or output schema is an explicit object whose
entire property set uses canonical Splash identifiers and defines a `properties`
map, the projection also carries the corresponding bounded
field/type/required view with optional plain-text property descriptions. An
output property explicitly typed as an object with a complete direct
`properties` map retains one nested `fields` level; deeper output structure is
omitted. Scalar, array, missing-properties, noncanonical-key, and partial
retained shapes omit that view. The LSP presents both views in direct-leaf hover and signature
documentation, and can complete an undeclared top-level key in the first direct
literal-record argument from `inputFields`. It can additionally complete and
hover root `result.field` names and one explicit object-child path such as
`result.summary.total` from `outputFields` only for an exact root synchronous
`let result = imported.method(input)` binding or its exact deferred `.await()`
form. It also follows exact local `let alias = result` chains of at most 16
hops. It never inserts `await()`, completes nested input keys or result paths
below that child level, follows computed/deeper aliases or arbitrary result
chains, evaluates a schema, or gives an editor authority. Neither API is
installed into Splash source. The sealed
`mobile::MobileRuntimeBuilder` and
`splash_workflow::mobile::MobileWorkflowBuilder` expose the same registration
path before `build`; the workflow facade retains only its immutable mapping,
metadata projections, and named step-policy approval surface.

For an LLM or operator review surface that must connect source syntax to a
reviewed target capability, call
`CapabilityRuntime::capability_module_call_hint_report_named`. It recognizes
an exact `binding.method(...)` whose receiver is scope-resolved to an exact
visible `use mod.<name>` import or a bounded exact local root-alias chain of at
most 16 hops, and whose flat module and method match this runtime's configured
direct-module catalog. Every reference in that import-alias group must be
another exact group alias or a direct member call; this whole-source check
rejects function-captured calls when a later statement could rewrite the
receiver before invocation. Writes, member aliases, indexing, arbitrary
escapes, computed receivers, or incomplete metadata fail
closed. Each advisory result keeps the source location separate from the
underlying tool name, so a policy UI can display both without treating the
local alias as a grant. It never evaluates source, seals the catalog, issues a lease, or proves
reachability. An incomplete source-level lexical/import/alias index reports
`truncated` and publishes no partial scope-resolved mapping. The development
CLI exposes the same optional projection as `direct_module_calls` from
`splash tool-calls --allow-json-add` and
`splash workflow-review --allow-json-add`; it is only the reviewed demo host
catalog.

For an approval flow, a host can issue a `CapabilityLease` from a selected
subset of this catalog and call `eval_with_capability_lease`, or pass that lease
to `WorkflowEngine::approve_with_capability_lease`. A lease is local to one
runtime and records a catalog fingerprint, including direct module mappings,
allowed names, and narrower per-tool call limits. A dynamic Splash value used
as a tool name is checked when the call is reserved, not inferred from source
text. Changing the catalog after issuing a lease invalidates it before
execution; an active suspended evaluation also prevents catalog registration
until it finishes.

`WorkflowEngine::approve_with_step_capability_leases` accepts an ordered
vector with one lease per plan step. It validates every lease before approving
the plan, activates only the current lease, and retains that same lease while
the step awaits an external result. The resume counterpart accepts only the
unexecuted checkpoint suffix, so a restart receives fresh current-policy
authority without reissuing authority for an attested completed prefix. These
APIs reject a short or long vector; source-level tool-call hints remain
non-authoritative and do not create or select grants.

When a host needs only static per-step grants, it can instead construct an
ordered `WorkflowStepCapabilityPolicy` for each trusted plan step and call
`approve_with_step_capability_policies`. The policy includes the expected step
ID, so the engine checks the count and every ordered ID before it issues any
lease from the current catalog. `approve_resume_with_step_capability_policies`
uses the same rule for the unexecuted checkpoint suffix only. Policies are
host-side Rust configuration, deliberately non-serializable, and do not grant
authority by themselves. Build them from trusted host policy, not LLM output
or tool-call hints. Hosts needing `ToolCallAuthorizer` should issue manual
leases with `issue_capability_lease_with_authorizer` and use the lease APIs.

`WorkflowPlan::review` organizes those same bounded direct-call hints by
trusted step and includes each step's canonical syntax status. A workflow
retains at most 4,096 hints overall and marks a step as truncated when it omits
direct sites. It is useful for displaying an LLM-generated plan to an operator
before lease issuance, but its ordinary `mod.tool` hints do not infer aliases,
flow, or computed names and cannot be used as the grant-selection mechanism.
The separate direct-module projection can recognize only the bounded exact
root-alias form above; the runtime validates every actual call against the
active step lease when it reserves the tool.

Dispatch is `host_pump` for a local Rust handler and `external` for a
deferred-only tool. An external tool can only be used with `tool.start` or
`tool.start_json`; the host claims and completes it through the lifecycle
described in [External tools](external-tools.md).

The development CLI exposes the same host catalog as JSON:

```sh
cargo run -p splash-cli -- catalog --allow-echo --allow-json-add
```

## Editor projection

An editor integration may pass that JSON array through
`initializationOptions.splash.toolCatalog` when it starts `splash-lsp`, or
replace it later through `workspace/didChangeConfiguration`. The LSP consumes
only each descriptor's `name`, `format`, and `description`; it ignores dispatch,
limits, schemas, and every other field. This lets the editor complete a direct
visible tool-name literal with the correct text or JSON call form without
making the LSP a capability client.

For a refresh, send a complete replacement under `settings.splash.toolCatalog`:

```json
{
  "settings": {
    "splash": {
      "toolCatalog": [
        {
          "name": "text.echo",
          "format": "text",
          "description": "Returns text unchanged."
        }
      ]
    }
  }
}
```

The editor projection is advisory even when the integration supplied it from a
current host catalog. It is not a runtime query, a catalog fingerprint check, a
lease, or an approval. An omitted `toolCatalog` key keeps the prior projection;
JSON `null` explicitly clears it. A malformed, duplicate, or oversized
replacement discards only the tool projection and makes matching completion
incomplete rather than presenting a partial catalog. A valid empty array is a
complete empty catalog. Tool refreshes do not alter `moduleCatalog` or the
atomic workflow-data pair. A malformed `settings` value or non-object
`settings.splash` clears all advisory catalogs. The LSP retains at most 128
entries and 512 KiB of names/descriptions. Runtime policy still checks the
actual dynamic name against the active catalog and capability lease at
reservation time.

Refreshable authoring metadata for host-defined `mod.*` interfaces is
intentionally separate from this tool catalog. It uses
`initializationOptions.splash.moduleCatalog` or a configuration refresh, cannot
discover or approve a tool, and is documented in [Editor module interface
projection](module-catalog.md).
