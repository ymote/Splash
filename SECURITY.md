# Security Model

Splash treats generated scripts, tool descriptions, and tool inputs as
untrusted. The runtime has two separate security boundaries:

1. The language boundary exposes no ambient filesystem, process, network, or
   platform APIs. Scripts can reach a tool only through `tool.call` or an
   explicitly host-controlled `tool.start(...).await()` promise.
2. The execution boundary must contain any adapter with OS effects. A future
   production local-tool adapter will run in a dedicated worker with a
   platform-specific sandbox, not in the interpreter process.

`splash-protocol` defines the portable, attenuated handoff from a policy host
to that future worker. It validates manifests, request uniqueness, formats,
byte limits, and call budgets. Its `SessionAuthenticator` can also bind each
worker frame to a host-provisioned BLAKE3 session key, directional role, and
strict sequence number, rejecting tampering, reflection, and replay before a
message is used. It does not establish or protect that key, attest a worker,
encrypt transport, or enforce an operating-system policy itself. The host must
provide a trusted bootstrap channel and containment backend before an
effectful adapter is considered contained.

`ProtocolWorkerClient` connects that validation layer to a host-owned
`WorkerTransport`; its registration rejects a local policy that is broader than
the worker grant. This still does not make an in-process transport isolated.

Each registered tool declares a stable identifier and limits for calls, input
bytes, and output bytes. Calls are recorded in an ordered audit log. Unknown,
over-budget, or malformed calls fail before a tool handler is invoked.

JSON capabilities are an explicit policy type. They accept only JSON object or
array envelopes: envelope validation happens before the Rust handler is called,
and before a result is returned to Splash. `JsonToolContract` adds an
executable, bounded schema subset at the same boundary. Input contract failure
does not invoke a handler or consume a call; output contract failure does not
reach Splash. This is a data contract, not a way to deserialize arbitrary Rust
types or grant a script access to a crate.

Host-pump deferred tool promises are bounded per runtime and run only when the
trusted host calls `CapabilityRuntime::pump`; one default pump tick processes
at most one tool. Hosts may choose a bounded batch with `pump_up_to`. They
are cooperative scheduling, not a threading or isolation mechanism. A paused
script with no runnable capability work must be resumed by a host that
understands the relevant suspension source.

External-only tools add a host-managed completion path. They have no
in-process handler and are denied to synchronous calls. A trusted host claims
each operation, then explicitly completes or cancels it; the runtime reuses
the normal output validation and audit boundary. This does not terminate a
worker or enforce an operating-system policy. The host must bind cancellation
to its transport and enforce containment outside this process.

External retries are also host-only. A script receives no retry API and cannot
spend another capability call by requesting another attempt. For each claimed
operation, the host may use its stable `idempotency_key` when forwarding an
attempt to a worker. That key is a correlation and deduplication value, not a
capability token or authorization credential; the opaque `ExternalToolId`
must remain owned by the host. Hosts that need replay across restarts must
persist their own workflow identity and authenticate every worker request with
the keyed protocol frame or an equivalent transport mechanism. An adapter must
not retry a non-idempotent effect unless its worker performs deduplication
using that key or an equivalent durable identity.

Authenticated reconciliation can query a live claimed operation without
serializing its `ExternalToolId`. `CapabilityRuntime` creates an authenticated
request carrying only the session, tool, request ID, and operation key, then
opens a matching worker response before it applies `running`, `succeeded`,
`failed`, or `cancelled`. The result must match both that request and the
currently claimed operation; a successful payload also passes through the
existing output limit and JSON-contract boundary. This does not make a
promise, operation handle, or VM state restartable. A durable host workflow
must persist and authenticate its own operation identity, then decide whether
to reconcile, retry, compensate, or fail before it constructs a fresh runtime.

An external tool may opt into bounded host-visible output chunks. The runtime
accepts chunks only for a claimed operation, applies source-byte, aggregate,
and post-redaction limits, and returns only the redacted text to the host.
Chunks are not installed as a Splash API or buffered as script-visible state.
A redactor is trusted host Rust code, not generated script code; it must remain
small and non-blocking, and it cannot substitute for a contained worker or
output validation by the receiving UI, log, or LLM adapter. Stream limits span
all retries of the same operation, so a retry cannot reset an output budget.
The redactor is frozen once the tool reserves its first call, preventing a
mid-operation configuration change from altering the release policy.

Hosts can set a deferred deadline on each tool policy. Expiration is enforced
before a queued host-pump handler begins and through
CapabilityRuntime::expire_timed_out_tools for external work. It cannot stop a
Rust handler that is already blocking; effectful adapters still need their own
I/O deadline and containment policy. A result delivered after the deferred
deadline is rejected as timed out.

One v0.1 runtime is single-flight: a host must resume or discard a suspended
evaluation before submitting new source to that runtime instance. Hosts that
need independent concurrent workflows should use separate runtime instances.

Workflow plans are approved by the Rust host. An approval is bound to one plan
and consumed by execution, so a script cannot manufacture approval for another
workflow or resume a rejected plan by mutating its own state. Plans are also
bound to their creating workflow engine; another engine cannot approve,
checkpoint, or execute a foreign plan object.

Workflow checkpoints are bounded data-only records of a completed step prefix.
They bind to the ordered trusted plan through a BLAKE3 fingerprint, but include
no approval, grant, VM state, output, promise, or external operation handle.
Loading one cannot run a workflow: the host must recreate the plan and current
capability policy, authenticate its durable storage, and explicitly issue a
fresh checkpoint-bound approval. A checkpoint is not proof that its prefix ran
or that an interrupted step is safe to replay; hosts must use idempotency,
reconciliation, or compensation for effects around the restart boundary.

This baseline does not yet provide filesystem adapters, network adapters,
secret storage, worker-process isolation, signed packages, full JSON Schema,
or mobile policy backends. Those features must not be inferred from the
presence of the VM.

Tool descriptions and schemas are available only through the host-side
catalog. They are not script-visible authority. Schemas registered solely as
`ToolMetadata` remain prompt metadata; only `JsonToolContract` is executable.
