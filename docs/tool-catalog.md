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
view by a fixed-length, session-scoped BLAKE3 digest label rather than copied
verbatim.

For a UI or LLM review step, a host may pair the catalog with
`splash_core::tool_call_hint_report` or `splash tool-calls <file>`. That
outline retains at most 1,024 direct sites and exposes truncation explicitly;
it is deliberately limited to direct source spelling and does not resolve
aliases, shadowing, flow, or computed names. It is never sufficient to approve
a call: the lease and reservation-time policy checks remain the authority
boundary.

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

For an approval flow, a host can issue a `CapabilityLease` from a selected
subset of this catalog and call `eval_with_capability_lease`, or pass that lease
to `WorkflowEngine::approve_with_capability_lease`. A lease is local to one
runtime and records a catalog fingerprint, allowed names, and narrower
per-tool call limits. A dynamic Splash value used as a tool name is checked
when the call is reserved, not inferred from source text. Changing the catalog
after issuing a lease invalidates it before execution; an active suspended
evaluation also prevents catalog registration until it finishes.

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
before lease issuance, but it does not infer aliases, flow, or computed names
and cannot be used as the grant-selection mechanism. The runtime validates the
actual call against the active step lease when it reserves the tool.

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
