# Worker Adapter Runtime

`splash-worker` is the worker-side Rust runtime for one authenticated Splash
capability session. It is intended for mobile, embedded, and desktop hosts
that want dynamic Splash workflows to invoke a small, explicit catalog of
trusted Rust adapters without giving Splash source access to the Rust crate
graph or ambient OS APIs.

It is a protocol and sequencing layer, not a sandbox. An in-process use has
the privileges of its embedding process. Production hosts must still put it
behind a platform containment backend, provision the session key through a
trusted bootstrap channel, resolve opaque resource selectors in host policy,
and supply authenticated rollback-resistant journal storage. A Linux Bubblewrap
worker can receive its host-generated key in a bounded private-pipe preamble
before JSON frames begin; that is not key exchange or worker attestation.

## Integration Boundary

The host creates a `WorkerSession` only after it has received the
host-authenticated `open_session` frame. It supplies four trusted inputs:

- a `WorkerAdapterRegistry` with one Rust adapter per capability name;
- a `WorkerOperationJournal` and `WorkerJournalRevision` loaded atomically for
  one opaque tenant or policy scope;
- `WorkerSessionAdmission`, which binds the authenticated session to that
  scope, rejects stale or replayed session IDs, and issues the current
  single-writer fencing lease; and
- `WorkerJournalStore`, which compare-and-swaps journal state before an effect
  and after every worker observation while enforcing that lease.

```rust
use splash_worker::{
    AuthenticatedWorkerJournalStore, WorkerAdapter, WorkerAdapterRegistry,
    WorkerSession, WorkerSessionAdmission,
    WorkerSessionLimits,
};

// `journal_store` derives a record key from its host-owned namespace and scope,
// then wraps AuthenticatedStore<B> where B implements the fenced,
// rollback-protected backend contract. `admission` reserves its token atomically
// through journal_store.reserve_fence() or an equivalent trusted lease service;
// it never derives a token from current_fence() + 1.
let snapshot = journal_store.load()?;
let (restored_journal, restored_revision) = snapshot.into_parts();
let mut worker = WorkerSession::open(
    worker_authenticator,
    opening_frame,
    restored_journal,
    restored_revision,
    adapters,
    WorkerSessionLimits::default(),
    &mut admission,
)?;

let response = worker.handle(host_frame, &mut journal_store)?;
```

`AuthenticatedWorkerJournalStore` is a usable bridge, not a platform backend:
the host still supplies the platform's fenced rollback-protected store and the
single monotonic lease authority. The bridge derives one record key from its
namespace and scope, preventing arbitrary scope/key pairings.
`VolatileMemoryStore` is suitable only for tests and development.

The admission authority must reserve each token atomically from that backend or
from an equally durable external coordinator. Reading the current fence and
adding one is not safe across concurrent hosts. Scope selection must also be
bound to the authenticated tenant or policy identity before the bridge is
created; the bridge validates syntax and key binding, not caller identity. The
authority must reserve the token for the same bridge record that the session
will later persist. A bare `u64` fence cannot detect a host accidentally
reserving for one record and wiring the session to another.

The adapter registry is intentionally explicit. An adapter receives the
attenuated `CapabilityGrant` with each request and may resolve only the grant's
opaque resource selectors through its embedding policy. It must not interpret
script input as a file path, executable, network origin, credential, or crate
name. This is how Splash uses the Rust ecosystem: a host compiles narrow,
reviewed adapters against its chosen crates and exposes only their bounded data
contracts to scripts. JSON payloads are object/array envelopes with a 32-level
maximum nesting depth in addition to their grant byte limits.

For a reviewed adapter that needs a credential, use the bounded
[`secret_broker`](secret-broker.md) contract rather than adding a secret
identifier to its JSON payload. `CapabilitySecretBroker` checks the exact
host-configured `(tool, secret-id)` binding and the active
`ResourceKind::Secret` grant before it calls a host-owned provider. The adapter
receives bytes only inside a callback and must not return them in a worker
result. This is a host-side authorization and lifetime boundary; it does not
replace a platform credential store or process containment.

## Typed Rust adapters

`TypedJsonWorkerAdapter` adapts a statically linked Rust function with Serde
types for an ordinary `invoke` request. It is a convenience for a reviewed
crate integration, not dynamic crate loading or a sandbox:

```rust
use serde::{Deserialize, Serialize};
use splash_worker::{
    TypedJsonWorkerAdapter, WorkerAdapterRegistry, WorkerInvocationSafety,
};

#[derive(Deserialize)]
struct AddInput {
    left: i64,
    right: i64,
}

#[derive(Serialize)]
struct AddOutput {
    total: i64,
}

let mut adapters = WorkerAdapterRegistry::default();
adapters.register(
    "math.add",
    TypedJsonWorkerAdapter::new(
        WorkerInvocationSafety::ReadOnly,
        |input: AddInput, _grant| {
            Ok(AddOutput {
                total: input.left + input.right,
            })
        },
    ),
)?;
```

The adapter rejects non-object/array JSON envelopes and failed Serde
conversions. Register its host-facing counterpart with
`register_validated_protocol_json_tool` and a `JsonToolContract`; the host
must validate the same wire data before it reaches the worker and after the
worker serializes a result. The worker adapter does not own or infer JSON
Schema policy. It supports only `invoke`, so a crash-sensitive external effect
still needs a custom adapter using the durable dispatch and reconciliation
methods.

The runtime denies an adapter path until the adapter declares its contract.
`WorkerAdapter::invocation_safety` must name `ReadOnly` or
`IndependentlyIdempotent` before `invoke` can run.
`WorkerAdapter::durable_operation_contract` must name a bounded
`Reconciliation` strategy before dispatch or compensation can run. It covers
dispatch status recovery by `operation_key`; compensation additionally needs
the adapter-specific/manual recovery policy described below. The stronger
`ProviderIdempotencyAndReconciliation` contract also requires forwarding the
exact host `operation_key` unchanged to the provider's idempotency mechanism.
These declarations are an explicit review surface; they do not make an
unreviewed Rust adapter safe.

`WorkerAdapter::invoke` deliberately has no durable journal entry. It is only
available after the read-only/idempotent declaration above. A crash-sensitive
external effect must go through `dispatch_operation`, which is a host-controlled
workflow path rather than a directly script-created operation.

## Effect Ordering

For `dispatch_operation` and `compensate_operation`, the runtime performs:

1. authenticate the frame and reauthorize it against the active manifest;
2. update the journal to `pending` and durably persist that admission;
3. call the registered adapter exactly once for a new admission;
4. record the adapter status and durably persist the observation; and
5. seal a matching authenticated result.

An existing operation or compensation never calls the adapter again. Its
identity is the exact tool, durable key, and canonical input fingerprint; a
changed input or tool fails closed rather than receiving a cached outcome. Its
stored state is revalidated against the current grant before it is returned.
An existing `pending` state returns a pending/indeterminate error, never a
synthesized success, and requires recovery.
`WorkerAdapterError::Indeterminate`, an invalid post-effect observation, or a
failed post-effect journal write produces an indeterminate runtime error. The
runtime restores its in-memory journal to the last known state. A persistence
failure also poisons the session, so the host must discard it and open a fresh
authenticated session from an atomically loaded journal and revision before
bounded reconciliation or adapter-specific/manual recovery. It must not resend
the effect as a new operation.

`reconcile_operation` has both worker-side per-tool and whole-session budgets,
independent of the ordinary capability call budget. The runtime only
reconciles a tool and operation key already owned by its journal, persists the
observed state before it replies, and rejects contradictory terminal
transitions. This prevents a worker adapter from becoming an unbounded status
oracle or a source of unbounded journal write amplification.

External exactly-once behavior remains adapter/provider specific. The runtime
provides write-ahead intent, never reruns an existing durable key, and forces
reconciliation for ambiguity. A durable adapter must also expose bounded status
recovery by `operation_key`; when its provider supports idempotency keys, it
must pass that exact key through rather than inventing a provider-local retry
identity.

Compensation recovery is deliberately narrower. After an indeterminate
compensation, the host reuses the exact existing compensation intent under a
fresh approval and invokes an adapter-specific status or manual-recovery
policy. Splash does not define a universal inverse-status API.

## Authenticated In-Process Transport

The optional `splash-capabilities` feature `in-process-worker` provides
`InProcessAuthenticatedWorkerTransport` for an application that embeds a
fixed worker adapter catalog in the same process. It dispatches every ordinary
tool invocation through the real authenticated-frame lifecycle:

1. the host authenticator seals `invoke`;
2. `WorkerSession` opens, authorizes, and handles it; and
3. the host authenticator opens the matching `result`.

The constructor requires a host-role authenticator and the same public session
ID as the opened worker session. Pass the exact host authenticator that sealed
that worker's `open_session` frame; the first dispatch verifies the shared
secret key through the normal frame tag.

```rust
use splash_capabilities::in_process_worker::InProcessAuthenticatedWorkerTransport;

let transport = InProcessAuthenticatedWorkerTransport::new(
    host_authenticator,
    worker_session,
    journal_store,
)?;
```

This is an integration convenience, not a containment boundary. The worker
and its adapters retain the application process's ambient authority, and a
memory-corruption or arbitrary-code-execution compromise crosses this adapter
boundary directly. Use it only for a static, reviewed, app-provided adapter
catalog with no arbitrary executable, filesystem, network-origin, plugin, or
crate selectors. Untrusted local effects still require a separately contained
worker and a real IPC transport.

`WorkerTransport` intentionally carries only ordinary `invoke` messages.
Durable dispatch, reconciliation, and compensation use the separate,
host-controlled one-shot transport described below, together with the
authenticated rollback-resistant journal and ledger storage contracts. This
adapter does not weaken either requirement.

## Bounded JSON-Line Transport

The optional `splash-capabilities` feature `json-line-worker` provides a
`JsonLineWorkerChannel<R, W>` for a host-owned buffered reader and writer,
plus `AuthenticatedFrameWorkerTransport<C>` for ordinary `invoke`/`result`
calls and `OneShotAuthenticatedOperationWorkerTransport<C>` for exactly one
durable dispatch, reconciliation, or compensation exchange. It is the pipe
boundary for a worker process that the host has already started and placed in
an appropriate platform sandbox; it does not spawn, attest, or contain that
process itself.

Session startup remains explicit because `open_session` is one-way. The host
seals and sends it using the same `SessionAuthenticator` that it then moves
into the authenticated call transport:

```rust
use std::io::BufReader;

use splash_capabilities::json_line_worker::{
    AuthenticatedFrameWorkerTransport, JsonLineWorkerChannel, WorkerFrameChannel,
};
use splash_capabilities::WorkerMessage;

let mut channel = JsonLineWorkerChannel::new(BufReader::new(child_stdout), child_stdin);
let opening = host_authenticator.seal(WorkerMessage::OpenSession { manifest })?;
channel.send_frame(opening)?;
let transport = AuthenticatedFrameWorkerTransport::new(host_authenticator, channel)?;
```

Each line is bounded to the protocol's 1 MiB frame limit before decoding. A
write, flush, read, malformed frame, oversized frame, invalid response, or
authentication failure poisons the channel or transport. The host must discard
it with the session and open a fresh session instead of retrying on the same
stream.

### One-shot durable recovery exchange

`OneShotAuthenticatedOperationWorkerTransport` owns the advanced host
authenticator, creates a fresh `SessionAuthorizer` from the supplied manifest,
and performs exactly one `dispatch_operation`, `reconcile_operation`, or
`compensate_operation` request. It seals the request, opens the response, and
checks the grant, request identity, output contract, and compensation binding
before it returns a verified result. A successful exchange consumes it; any
failure poisons it. It is deliberately not a general recovery channel or an
unbounded status oracle.

For a post-stop effect, discard and reap the old worker first. Reload and
validate the authenticated host ledger, start a fresh contained worker that
loads its fenced durable journal, open a new authenticated session, then build
a reconciliation request from the current input. The one-shot transport owns
the frame sealing, so use `operation_reconcile_request` rather than
`prepare_authenticated_operation_reconciliation` for this path:

```rust
use std::io::BufReader;

use splash_capabilities::json_line_worker::{
    JsonLineWorkerChannel, OneShotAuthenticatedOperationWorkerTransport, WorkerFrameChannel,
};
use splash_capabilities::WorkerMessage;

let mut channel = JsonLineWorkerChannel::new(BufReader::new(child_stdout), child_stdin);
let opening = host_authenticator.seal(WorkerMessage::OpenSession {
    manifest: manifest.clone(),
})?;
channel.send_frame(opening)?;

let request = engine.operation_reconcile_request(
    &plan,
    &ledger,
    &operation_key,
    &current_input,
    host_authenticator.session_id(),
    "reconcile-1",
)?;
let mut transport = OneShotAuthenticatedOperationWorkerTransport::new(
    manifest,
    host_authenticator,
    channel,
)?;
let result = transport.reconcile_operation(request.clone())?;
let state = engine.apply_verified_operation_reconciliation(
    &plan,
    &mut ledger,
    &request,
    &result,
)?;
persist_ledger_compare_and_swap(ledger.to_json()?)?;
```

Do not re-dispatch an ambiguous effect through this transport. A `running`
result, changed input, invalid current policy, contradictory ledger state, or
transport failure remains a host recovery decision. The transport does not
restart a VM, resolve a promise, select compensation, or make a terminal
observation sufficient to run a workflow suffix.

On Linux, `splash-workflow/bubblewrap-recovery` provides the higher-level,
reconciliation-only composition for this sequence. It requires a reaping proof
from the stopped worker, reserves a fenced authenticated host-ledger writer,
starts a differently keyed Bubblewrap session under an optional preserved
cgroup-v2 policy, performs one watchdog-bounded exchange, reaps that worker,
and compare-and-swap persists the observation. See
[Bubblewrap post-stop recovery](bubblewrap-recovery.md). The worker must still
load its own fenced durable journal and satisfy fresh-session admission.

The baseline `AuthenticatedFrameWorkerTransport` performs synchronous I/O, so
it cannot deliver an in-band `cancel` while blocked on a result. On Linux, the
optional `bubblewrap-watchdog` feature connects a
`BubblewrapWorkerLifecycle::into_watchdog` lifecycle to the generic
`BoundedWorkerTransport`. It arms a trusted host-selected nonzero deadline
before each `invoke`; `BubblewrapWorkerSessionDeadline` can additionally bound
the worker's total lifetime from spawn, including idle time. Either expiry
force-stops and reaps Bubblewrap from a separate host thread. An explicit host
lifecycle control can do the same. Those outcomes remain indeterminate, poison
the transport, and require reconciliation for any durable effect.

Protocol v5 adds a separate opt-in path for cooperative ordinary calls.
`CancellableWorkerSessionDriver` runs an explicitly registered
`CancellableWorkerAdapter` outside its authenticated frame loop, which lets
the loop receive one exact `cancel` while the adapter runs. The adapter sees a
`WorkerCancellationToken`; polling the token is not acknowledgement. It may
return `CancellationAcknowledged` only after it has stopped the effect and can
guarantee no result follows. The driver refuses mixed manifests containing a
normal synchronous adapter.

On the host, `MultiplexedAuthenticatedWorkerTransport` owns independent
directional authentication state and remains responsive to cancellation while
one call is active. `SupervisedMultiplexedWorkerSession` binds that transport
to a session-matched watchdog, arms before dispatch, and resolves the watchdog
race before exposing a worker event. A positive authenticated acknowledgement
can confirm runtime cancellation only when supervision reports the call
completed first. Any deadline, force-stop, EOF, authentication error, or
transport failure remains indeterminate. Durable dispatch and recovery stay on
the one-shot journaled path; they are never cancelled through this ordinary
call driver. Other platforms must supply their own session-bound process, I/O,
deadline, cancellation, and resource policy.

## Mobile and Embedded Profiles

The base capability and JSON-line transport path has no async runtime, thread,
socket, filesystem, process, or allocator-specific dependency. The optional
Linux `bubblewrap-watchdog` feature deliberately adds a platform process
lifecycle dependency and is not part of the mobile or embedded profile. The
base path can sit behind an app-owned message loop or an embedded transport as
long as the host enforces frame-size limits, adapter I/O timeouts, storage
semantics, and containment appropriate to the target.

For direct mobile and embedded scripting, use
`splash_capabilities::mobile::MobileRuntimeBuilder`. It accepts reviewed local
adapters during setup, and `build()` consumes it to yield a `MobileRuntime`
with canonical evaluation, bounded host pumping, catalog inspection, audit
inspection, and explicit garbage collection only. The resulting profile has no
API to register more tools, claim or complete external work, or attach a worker
transport. Structured adapters require an executable `JsonToolContract`.
`MobileRuntimeBuilder::register_capability_module` can also expose one of those
contract-enforced local JSON adapters as a fixed direct `mod.<name>` method
before `build()` seals the profile; it retains the adapter's policy and audit
checks rather than adding ambient application APIs.
`MobileRuntimeBuilder::with_limits_and_catalog` additionally lets the app set
an immutable maximum descriptor count and serialized catalog size before any
adapter is registered. `with_max_audit_events(NonZeroUsize)` sets the bounded
in-memory audit capacity during setup, up to 8,192 entries. Its ordered audit
view exposes an eviction counter; `MobileRuntime::audit_since(cursor)` exports
only contiguous retained records and rejects a cursor overtaken by eviction.
For durable audit retention, an embedding application can send that export to
the optional host-owned `CapabilityAuditStore` outside the sealed mobile API.
Treat a rejected export as an observability gap rather than silently skipping
history. See [capability audit export](capability-audits.md).

```rust
use splash_capabilities::{
    json, JsonToolContract, ToolMetadata, ToolPolicy,
    mobile::MobileRuntimeBuilder,
};

let contract = JsonToolContract::new(
    json!({"type": "object", "properties": {"name": {"type": "string"}},
           "required": ["name"], "additionalProperties": false}),
    json!({"type": "object", "properties": {"message": {"type": "string"}},
           "required": ["message"], "additionalProperties": false}),
)?;
let mut builder = MobileRuntimeBuilder::new()?;
builder.register_json_tool(
    ToolPolicy::json("device.greet"),
    ToolMetadata::new("Formats a device-local greeting."),
    contract,
    |request| {
        let name = request.input["name"].as_str().unwrap_or_default();
        Ok(json!({"message": format!("hello {name}")}))
    },
)?;
let mut runtime = builder.build();

let report = runtime.eval(
    "use mod.tool\nlet reply = tool.call_json(\"device.greet\", {name: \"Ada\"})\nreply",
)?;
assert!(report.completed());
runtime.collect_garbage(); // Schedule this at an app-selected idle point.
```

`MobileRuntimeBuilder` is catalog governance, not process or OS containment.
Do not expose arbitrary executable, filesystem, network-origin, plugin, or
crate selectors through an adapter. The adapter set remains part of the trusted
computing base: an unreviewed or compromised Rust adapter has the embedding
app's authority despite the sealed catalog. Rust code can choose a lower-level
runtime instead, so only expose the mobile profile to code that must honor this
contract. `collect_garbage()` is intentionally explicit because a full VM
sweep can take time proportional to the live heap; use it at an application
idle point to reclaim settled promise records.

For an ordered mobile or embedded workflow, use
`splash_workflow::mobile::MobileWorkflowBuilder` instead. It repeats the
setup-only local adapter boundary, then returns a facade that can plan a
bounded `WorkflowDraft`, issue only named `WorkflowStepCapabilityPolicy`
grants, checkpoint, and execute. It has no mutable `CapabilityRuntime`,
manual lease, full-catalog approval, external claim/completion, or worker
transport API. Local host-pump adapters are driven by workflow execution; a
streaming/external policy is rejected during static setup.

```rust
use splash_capabilities::{CapabilityLeaseGrant, ToolMetadata, ToolPolicy};
use splash_workflow::{
    mobile::MobileWorkflowBuilder, WorkflowDraft, WorkflowStep,
    WorkflowStepCapabilityPolicy,
};

let mut builder = MobileWorkflowBuilder::new()?;
builder.register_text_tool(
    ToolPolicy::new("text.echo"),
    ToolMetadata::new("Returns app-local text."),
    |request| Ok(request.input.clone()),
)?;
let mut workflow = builder.build();

let draft = WorkflowDraft::new(vec![WorkflowStep::new(
    "prepare",
    "use mod.tool\ntool.call(\"text.echo\", \"release\")",
)])?;
let plan = workflow.plan_draft(draft)?;
let approval = workflow.approve_with_step_capability_policies(
    &plan,
    vec![WorkflowStepCapabilityPolicy::new(
        "prepare",
        [CapabilityLeaseGrant::new("text.echo", 1)],
    )],
)?;
workflow.execute(&plan, approval)?;
```

This facade is catalog governance, not OS containment or a substitute for a
platform storage anchor. It is appropriate only for reviewed app-local
adapters whose effects are safe to run in the embedding application's process.

The authenticated in-process worker transport remains available for a fixed
worker protocol catalog. It is appropriate when the application needs worker
framing, but it has the same non-containment limitation.
On embedded systems, select a small static adapter catalog and provide a
platform durable store only when the hardware offers an authenticated
anti-rollback primitive and atomic monotonic compare-and-swap. Otherwise use
the runtime for bounded non-durable calls and treat durable effects as
unavailable rather than claiming a storage guarantee the device cannot
provide.

See [worker protocol](worker-protocol.md), [worker durable
operations](worker-operations.md), [durable worker
compensation](worker-compensation.md), and [authenticated durable
storage](durable-storage.md) for the surrounding contracts.
