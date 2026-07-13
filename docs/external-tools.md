# External Tools

An external tool is a deferred-only capability with no Rust handler inside the
Splash interpreter process. It is registered with
CapabilityRuntime::register_external_tool or one of the JSON variants.

External tools are intentionally unavailable to tool.call and tool.call_json.
Those synchronous calls are denied before they consume a tool call. A script
must create a promise with tool.start or tool.start_json and await it.

## Host lifecycle

1. A script starts the granted external tool. The runtime validates input,
   reserves the call budget, and retains one pending-promise slot.
2. The host calls claim_next_external_tool. This returns a host-owned opaque
   ID, the validated input, format, call index, attempt limit, stable
   idempotency key, terminal-output byte limit, optional stream policy, and
   any remaining deadline in milliseconds.
3. The host dispatches that invocation to its own worker or platform adapter.
4. The host calls complete_external_tool with the result, or
   cancel_external_tool when it decides the work must stop.

Pump never invokes claimed or unclaimed external tools. A successful external
completion uses the same output byte limit, JSON envelope validation, optional
JSON contract validation, and audit path as a host-pumped tool handler.

~~~rust
use splash_capabilities::{CapabilityRuntime, ToolMetadata, ToolPolicy};

let mut runtime = CapabilityRuntime::default();
runtime.register_external_tool_with_metadata(
    ToolPolicy::new("text.remote"),
    ToolMetadata::new("Runs in a host-managed worker."),
)?;

let initial = runtime.eval(
    "use mod.tool
     use mod.std.assert
     let output = tool.start(\"text.remote\", \"release\").await()
     assert(output == \"done\")",
)?;
assert!(initial.suspended);

let invocation = runtime.claim_next_external_tool().expect("pending worker call");
let resumed = runtime
    .complete_external_tool(invocation.id, Ok("done".to_owned()))?
    .expect("the script was awaiting the result");
assert!(resumed.completed());
~~~

The pending-promise limit configured with with_limits_and_pending bounds all
local and external operations together. A host may claim several operations up
to that limit and complete them in any order.

Once claimed, an operation remains reserved until the host completes or
cancels it even if the script drops its promise handle, preserving the audit
record and preventing unbounded orphaned work.

CapabilityRuntime remains single-threaded. The host can copy invocation fields
into its worker request while retaining the opaque ID locally, then complete
the operation on the event loop that owns the runtime. For keyed protocol
workers, prefer the authenticated reconciliation bridge below instead of
manually trusting a returned request ID. When present,
remaining_deadline_millis should also be applied by the worker adapter.

## Host-owned retries

`ToolPolicy::max_attempts` bounds external dispatch attempts for one deferred
operation and defaults to `1`. After a worker reports a retryable failure, the
host may call `retry_external_tool` with `RetryClass::Transient` or
`RetryClass::RateLimited`. It returns the next invocation directly: the
operation remains claimed, so it is not returned again by
`claim_next_external_tool`.

~~~rust
use splash_capabilities::RetryClass;

let first = runtime.claim_next_external_tool().expect("pending worker call");
let retry = runtime.retry_external_tool(first.id, RetryClass::Transient)?;
assert_eq!(retry.id, first.id);
assert_eq!(retry.idempotency_key, first.idempotency_key);
assert_eq!(retry.attempt, 2);
~~~

The retry preserves its input, call index, opaque host ID, and idempotency key.
It does not create another Splash call or consume another tool call budget.
The runtime records an `AuditOutcome::RetryScheduled` event with the host's
retry class. Reaching the attempt bound returns `RetryLimitReached`; the host
must then complete or cancel the claimed operation. A retry after the deferred
deadline returns `DeadlineElapsed`; the event loop should resolve it through
`expire_timed_out_tools`.

`idempotency_key` is safe to pass to an authenticated worker as a downstream
deduplication key. It is stable for all attempts of one operation and unique
within this runtime process, but it is not an authorization credential and is
not durable across host restarts. Retain the opaque `ExternalToolId` locally.
Durable workflows should use a persisted workflow or operation identity in
addition to this per-runtime key. Do not retry a non-idempotent worker unless
the worker deduplicates requests using that key or another durable operation
identity. `splash-workflow` provides a plan-bound
[durable operation ledger](workflow-operations.md) for that host-owned
identity and restart policy. A contained worker can accept that identity in an
authenticated [durable operation dispatch](worker-operations.md), then persist
its own replay-safe journal before it invokes an effectful adapter.

## Authenticated reconciliation

When a worker connection is interrupted or a host needs to poll an operation
that remains claimed, use the keyed reconciliation bridge instead of treating
a worker status payload as a completion. The request contains the tool and
non-authorizing operation key, never the opaque `ExternalToolId`. The host
keeps that ID locally and the worker returns an authenticated status bound to
the exact request.

~~~rust
use splash_capabilities::{
    CapabilityRuntime, ExternalReconciliation, OperationReconcileResult,
    OperationStatus, SessionAuthenticator, SessionKey, SessionRole,
    ToolPolicy, WorkerMessage, WorkerPayload,
};
use splash_protocol::AUTH_TAG_BYTES;

let mut runtime = CapabilityRuntime::default();
runtime.register_external_tool(ToolPolicy::new("text.remote"))?;
let initial = runtime.eval(
    "use mod.tool\n\
     tool.start(\"text.remote\", \"release\").await()",
)?;
assert!(initial.suspended);

let key = SessionKey::from_bytes([7; AUTH_TAG_BYTES])?;
let mut host_auth = SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host)?;
let mut worker_auth = SessionAuthenticator::new("worker-1", key, SessionRole::Worker)?;

let invocation = runtime.claim_next_external_tool().expect("pending worker call");
let outbound = runtime.prepare_authenticated_external_reconciliation(
    invocation.id,
    "reconcile-1",
    &mut host_auth,
)?;

// A real transport serializes outbound.frame with to_json_line(), sends it,
// then returns an AuthenticatedWorkerMessage decoded from the worker response.
let WorkerMessage::ReconcileOperation { request } = worker_auth.open(outbound.frame)? else {
    unreachable!("host sent a reconciliation request");
};
let result = OperationReconcileResult::new(
    request.session_id,
    request.request_id,
    request.tool,
    request.operation_key,
    OperationStatus::Succeeded {
        payload: WorkerPayload::Text("done".to_owned()),
    },
)?;
let response = worker_auth.seal(WorkerMessage::ReconciledOperation { result })?;

match runtime.reconcile_authenticated_external_tool(
    invocation.id,
    &outbound.request,
    &mut host_auth,
    response,
)? {
    ExternalReconciliation::Running => {}
    ExternalReconciliation::Resolved(resumed) => {
        let _completed_script = resumed;
    }
}
~~~

`prepare_authenticated_external_reconciliation` requires the host role and
creates the request frame with the session authenticator. The matching receive
method verifies the keyed tag, directional sequence, and worker role before it
inspects the message. It then checks the request and result fields against the
currently claimed operation and applies text/JSON output validation and any
registered JSON contract before resolving the promise. A `running` result
leaves the promise pending and writes no terminal audit event.

The key must be provisioned through a trusted host-to-worker bootstrap path;
the protocol is not a key exchange, encrypted transport, or OS sandbox. This
bridge only reconciles a live runtime. It intentionally cannot restore an
`ExternalToolId`, promise, or VM state after a process restart. Persist and
authenticate a durable operation identity separately, then use workflow policy
to decide how a new runtime handles any interrupted effect.

## Host-visible output streaming

Streaming is opt-in and only applies to external deferred tools. Configure a
`ToolStreamPolicy` before registration, then optionally install one trusted
redactor for the tool. The redactor receives raw worker text and returns the
only text released to the caller of `push_external_tool_chunk`.
`set_external_stream_redactor` must run before the tool's first `tool.start`;
the runtime rejects later changes so an operation cannot change redaction
behavior mid-lifecycle.

~~~rust
use splash_capabilities::{ToolPolicy, ToolStreamPolicy};

let policy = ToolPolicy::new("text.remote").with_stream(
    ToolStreamPolicy::new(
        32,       // chunks per operation
        4 * 1024, // source bytes per chunk
        64 * 1024, // aggregate source bytes
        64 * 1024, // aggregate bytes after redaction
    ),
);
runtime.register_external_tool(policy)?;
runtime.set_external_stream_redactor("text.remote", |chunk| {
    chunk.replace("internal-token", "[redacted]")
})?;

let invocation = runtime.claim_next_external_tool().expect("pending worker call");
let chunk = runtime.push_external_tool_chunk(invocation.id, "worker progress")?;
let _host_visible_text = chunk.text;
~~~

`ToolStreamPolicy` bounds the number of chunks, source bytes per chunk,
aggregate source bytes, and aggregate bytes after redaction. The runtime does
not retain chunk payloads: it returns a typed `ExternalToolStreamChunk` to the
host and records only byte counts and `streamed` or `stream_denied` audit
outcomes. A chunk must arrive after claim and before completion, cancellation,
or expiry. Stream counters span all retries of the operation; attempts cannot
reset them. `StreamLimitExceeded` is a backpressure signal: the worker adapter
must stop forwarding chunks or apply its own bounded pause/cancellation policy,
not retry the rejected chunk indefinitely.

Chunks are separate from the terminal result passed to `complete_external_tool`:
the terminal result still obeys the regular output-size, JSON-envelope, and
optional executable-schema checks. A JSON tool may therefore stream text
progress while its final result must remain a valid JSON envelope matching its
contract. Splash source cannot read, await, or subscribe to chunks; it sees
only the terminal promise result.

The redactor is trusted, synchronous Rust code. Keep it deterministic and
bounded for mobile or embedded event loops. It is not a worker sandbox, and a
receiving UI, log sink, or LLM adapter must still treat even redacted worker
output as untrusted data.

## Deadlines

Set ToolPolicy::max_deferred_duration before registering the tool to bound a
deferred operation from the moment tool.start reserves it. The host should
schedule CapabilityRuntime::expire_timed_out_tools from its event loop at the
next deadline. Expired external operations receive a timeout result through
the same audit and promise path as a normal completion. A result delivered
after its deadline is also converted to a timeout, even if the expiry tick was
late.

For host-pump tools, pump checks the deadline before it invokes the Rust
handler. A deadline cannot interrupt a handler that has already started or
cancel a worker process by itself. A contained adapter must apply its own I/O
deadline and lifecycle policy. For a synchronous Linux Bubblewrap JSON-line
worker, `BoundedWorkerTransport` can arm a host-owned watchdog that force-stops
the worker at a deadline, but that result is indeterminate rather than a
cooperative cancellation acknowledgement.

## Cancellation and containment

Cancellation is host-directed. It consumes the reserved call budget and records
the audit outcome as cancelled; a later completion for the same ID is rejected.
It does not kill an OS process or network request on its own. The host must
translate cancellation into its worker transport and platform containment
mechanism. The current single-flight JSON-line worker transport cannot deliver
`WorkerMessage::Cancel` while an invocation is blocked; a Linux Bubblewrap host
can force-stop it through the watchdog, then discard the session and reconcile
any durable effect instead of claiming the effect was cancelled.

External dispatch is a capability boundary, not an OS sandbox. A production
adapter still needs an authenticated transport and a separately contained
worker with the filesystem, executable, network, and secret policy appropriate
to that tool.
