# Workflow Drafts

`WorkflowDraft` is Splash's bounded, data-only interchange format for an LLM
or an operator to propose an ordered workflow. It is intentionally earlier in
the lifecycle than a `WorkflowPlan`: decoding a draft cannot create a runtime,
inspect a tool catalog, issue a lease, approve a plan, invoke an adapter, or
resume an operation.

## Wire Format

The current JSON format is version `1` and accepts exactly these fields:

```json
{
  "format_version": 1,
  "steps": [
    {
      "id": "prepare",
      "source": "use mod.tool\nlet note = tool.call(\"text.echo\", \"draft\")"
    }
  ]
}
```

Unknown fields are rejected at both the document and step levels. The format
has no field for a tool grant, capability lease, approval, checkpoint, tool
result, runtime identity, external operation ID, or durable ledger. A decoded
draft is therefore input data, not a credential.

Draft JSON is capped at 2 MiB before decoding. It holds at most 1,024 steps,
uses the normal ASCII step-ID rules, and retains at most 1 MiB of aggregate
decoded source. `WorkflowDraft::from_json_with_max_bytes` lets an embedded
host impose an even smaller ingress limit; it cannot raise the 2 MiB hard
limit. The bounded step decoder skips surplus array entries instead of
retaining an unbounded vector before rejecting the draft.

## Producer Schema

`splash workflow-schema` emits the machine-readable JSON Schema producer
contract for this envelope without reading a draft, creating a runtime, or
registering a capability. Its `x-splash` extension states bounds that ordinary
JSON Schema cannot express: aggregate decoded source bytes, total wire bytes,
unique IDs across object items, ordered-step semantics, the canonical source
profile, and the fact that the document carries no authority. The schema is
intended to help an LLM or editor construct the proposal;
`WorkflowDraft::from_json` remains authoritative and a host may use
`from_json_with_max_bytes` to impose a lower ingress limit.

The schema's `source` field is only a string at the draft boundary. Canonical
Splash syntax is checked separately during `review`; a valid JSON envelope is
not a valid, approved, or executable workflow.

## Host Lifecycle

```rust
use splash_workflow::{WorkflowDraft, WorkflowEngine};

let draft = WorkflowDraft::from_json(untrusted_llm_json)?;
let review = draft.review()?;

// The host evaluates its own policy from the trusted plan and review surface.
// Direct tool-call hints are not sufficient to select authority.
let policies = host_selects_step_policies(&review)?;
let plan = engine.plan_draft(draft)?;
let approval = engine.approve_with_step_capability_policies(&plan, policies)?;
engine.execute(&plan, approval)?;
```

`review` returns canonical syntax status and direct `mod.tool` call hints for
each step without evaluation. It retains at most 1,024 hints from a step and
4,096 across the review; `tool_calls_truncated` is true when a step has one or
more omitted direct sites. It is useful for an operator or policy UI, but it
does not resolve aliases, control flow, or computed names. The runtime still
checks every actual call against the active lease. Hosts that need a custom
per-invocation `ToolCallAuthorizer` issue manual leases instead of using the
policy convenience API.

`WorkflowEngine::plan_draft` turns the already bounded draft into an
engine-owned plan and records only a `Planned` event. It does not validate
source semantics, issue authority, or approve execution. A host can reject a
draft after review without creating an approval, then discard it.

## Bounded Dataflow

`WorkflowData` adds an optional, host-owned JSON context to an approved plan.
It is not part of the draft wire format and it is not a capability. A fresh
context has one input value; each successful step contributes one JSON result.
Scripts see a host-injected `workflow` value with this fixed shape:

```splash
let request = workflow.input
let prepared = workflow.outputs.prepare
```

The aggregate `{ input, outputs }` context is capped at 64 KiB and 64 JSON
levels. A result must be JSON-representable and fit within that aggregate cap;
functions, handles, cycles, non-finite numbers, and non-string object keys are
rejected. A rejected output stops the workflow before a later step starts.
The host reconstructs and injects a new prefix for every step, then clears it
after that step reaches a terminal state. A local or external `await` retains
the exact same context until its continuation completes.

The context is bound to approval by value, alongside the selected per-step
leases. It can influence a dynamic tool name, but it cannot make that name
authorized: the active lease still checks the registered name and call budget
when the call is reserved.

```rust
use splash_workflow::{WorkflowData, WorkflowEngine};

let data = WorkflowData::from_input_json(r#"{"left":20,"right":22}"#)?;
let approval = engine.approve_dataflow_with_step_capability_policies(
    &plan,
    data,
    host_selected_step_policies,
)?;
let completed = engine.execute_dataflow(&plan, approval)?;

assert_eq!(completed.output("prepare"), Some(&serde_json::json!({"total": 42})));
```

`WorkflowData::to_json` and `from_json` use a separate versioned host-data
envelope with `format_version`, `input`, and `outputs` fields. A context that
has executed under a dataflow contract also retains that contract's digest in
an optional `contract_fingerprint` field; it never retains schema source.
These transport APIs do not create an approval or restore a promise. Raw data
stays out of `WorkflowEvent` and capability audit entries; hosts decide whether
and where to persist or display it.

## Dataflow Schema Contracts

When a later authorized tool must receive only a particular data shape, bind a
`WorkflowDataContract` to the dataflow approval. It has one compiled input
schema and one compiled output schema for every trusted plan step, in the
exact trusted-plan order. The host builds it from `splash_schema::JsonSchema`;
it is neither draft JSON nor Splash-visible configuration.

```rust
use splash_schema::JsonSchema;
use splash_workflow::{WorkflowDataContract, WorkflowStepOutputContract};

let contract = WorkflowDataContract::new(
    JsonSchema::compile(serde_json::json!({
        "type": "object",
        "properties": {
            "left": {"type": "integer"},
            "right": {"type": "integer"}
        },
        "required": ["left", "right"],
        "additionalProperties": false
    }))?,
    [WorkflowStepOutputContract::new(
        "prepare",
        JsonSchema::compile(serde_json::json!({
            "type": "object",
            "properties": {"total": {"type": "integer"}},
            "required": ["total"],
            "additionalProperties": false
        }))?,
    )],
)?;

let approval = engine.approve_dataflow_with_contract_and_step_capability_policies(
    &plan,
    data,
    contract,
    host_selected_step_policies,
)?;
```

Input validation occurs before the policy convenience API issues any lease.
Each terminal step value is converted to bounded JSON, checked against that
step's output schema, and only then added to `workflow.outputs`. A violation
records only a failed-step diagnostic count, clears the injected global, and
stops the plan before a later step or its lease becomes active. The contract is
retained across a local or external `await` with the approval-bound context.

Contracts must cover every step even when a step is pure. Their compiled
schema sources plus bound step IDs are capped at 256 KiB in aggregate. The
contract is trusted host configuration and intentionally has no Serde format:
an LLM cannot insert, select, or weaken it through a draft, input, result, or
checkpoint. Contract-bound execution stamps only its digest onto the retained
`WorkflowData`, so `dataflow_checkpoint_after` automatically carries it into
checkpoint JSON and prevents an uncontracted resume from silently dropping the
earlier policy. For a manually reconstructed context that lacks the digest,
use `dataflow_checkpoint_after_with_contract`, which binds the supplied
mutable context before creating the checkpoint. The sealed mobile facade
exposes the corresponding
`approve_dataflow_with_contract_and_step_capability_policies` method without a
mutable runtime escape.

## CLI Review

Review a draft without creating a capability runtime:

```sh
cargo run -p splash-cli -- workflow-review examples/release_workflow_draft.json
```

The command prints JSON with each step's ID, canonical syntax diagnostics,
bounded direct tool-call hints, and `tool_calls_truncated`. A decoded envelope
has `draft.valid: true` even when one of its source steps is invalid; the
top-level `valid` field then remains false and the relevant step carries the
bounded diagnostics. A malformed or structurally invalid envelope instead
returns `draft.valid: false`, an empty `steps` list, and a finite error `code`
without echoing raw source or an invalid step ID. The command exits nonzero for
either kind of rejection. It does not print or infer grants and never evaluates
the draft.

The default command creates no capability runtime. A host that has already
selected a direct-module catalog may add a separate advisory projection for
exact direct module calls and their mapped underlying tools. The development
CLI demonstrates that bounded projection with `--allow-json-add`, which adds
`direct_module_calls` and `direct_module_calls_truncated` to each valid step.
It still does not create a grant: the host must select the underlying tool name
when it later approves the plan.

## CLI Demonstration Execution

The development CLI also exposes a deliberately narrow local execution path:

```sh
cargo run -p splash-cli -- workflow-run --allow-echo --allow-json-add \
  --grant prepare:text.echo:1 --grant calculate:math.add:1 \
  examples/local_workflow_draft.json
```

Pass `--input` to use the dataflow path with an explicit JSON input file:

```sh
cargo run -p splash-cli -- workflow-run --allow-json-add \
  --input examples/dataflow_input.json \
  --grant prepare:math.add:1 \
  examples/dataflow_workflow_draft.json
```

Each `--grant` uses `step-id:tool-name:max-calls`. The CLI creates an empty
policy for every plan step, then adds only the explicitly supplied grants.
Consequently, a capability call without a matching flag is denied by the
active lease even if its name was visible in the fixed demo catalog. A grant
for an absent step or a capability not enabled through `--allow-echo` or
`--allow-json-add` is rejected before approval. The demonstration accepts at
most 4,096 explicit grant flags.

This command is a local development demonstration, not an LLM policy engine.
It has no external tools, worker transport, filesystem, network, subprocess,
or crate-selection adapter. It emits bounded in-memory audit and step-status
data, not durable operation evidence. Production hosts must review a draft and
construct `WorkflowStepCapabilityPolicy` values from trusted policy rather
than use source hints or pass LLM-supplied grants through to execution.

When its draft envelope is malformed or structurally invalid, `workflow-run`
also returns a rejected JSON status with the same nested review rejection
object before it creates the demo runtime. This is a structured input result,
not an approval, capability decision, or execution record.

With `--input`, the direct CLI result includes the input, completed outputs,
and context fingerprint for local inspection. That output is intentionally
different from workflow telemetry: audit and event entries still contain only
bounded metadata, never those raw values. Treat the CLI output as application
data and avoid sending it to an untrusted log sink.
