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

`splash-worker` is the worker-side implementation of that protocol boundary.
It accepts only an explicitly registered Rust adapter for a granted capability,
requires host admission to bind a fresh authenticated session to its tenant
journal scope, and persists durable intent before an adapter effect through a
monotonic compare-and-swap journal revision and a current host-issued fencing
lease. The scope is host-selected and the admission boundary must validate the
session/scope tenant binding together; a store rejects leases from superseded
workers. It restores its in-memory journal and poisons the session when
persistence fails; a post-effect failure also returns an indeterminate error
and requires a fresh authenticated reload before bounded reconciliation or
adapter-specific recovery. A duplicate pending operation remains pending and
an exact durable key is bound to its canonical tool input, so changed input
fails closed. It does not isolate adapters: embedding it in the interpreter
process, a mobile app, or an unrestricted service leaves it with that process's
ambient authority. Its journal-store trait is a contract, not a file/database
implementation or anti-rollback mechanism.

`AuthenticatedWorkerJournalStore` connects the runtime to
`AuthenticatedStore` plus `FencedRollbackProtectedStore`. It authenticates the
journal bytes and binds each write to a record key, current revision, scope,
and fencing token, but it inherits the backend's durability and anti-rollback
guarantees. `VolatileMemoryStore` covers integration tests only and must never
be treated as a production worker journal backend.

The bridge derives its record key from a host-owned namespace and journal
scope. A new admission must atomically reserve a nonzero token through the
backend or an equivalently durable lease service; never calculate a token from
`current_fence + 1` after a separate read. Fence state and data must share the
same record key, and the backend must revalidate exact token equality in its
atomic compare-and-swap. Provision an `AuthenticatedStore` key only to the
trusted storage coordinator or a narrowly scoped storage client. Do not place
a general storage key in an untrusted contained adapter process merely because
that process hosts a worker session. The bridge intentionally exposes no
general-purpose authenticated-store handle or caller-selected record key. The
host admission authority must reserve a fence for this exact bridge record;
the runtime cannot infer a record binding from a raw `u64` token.

The optional `AnchoredSqliteStore` persists payload candidates locally but
accepts them only when a host `RollbackAnchor` has committed their revision,
content hash, and fence. SQLite is not that anchor and does not become one by
being opened with durable settings. A real anchor must be linearizable and
survive both its own failover and local-database rollback. All writers must
share that anchor and one SQLite file. Host recovery after an anchor outage
must stop new admissions, reserve a fresh opaque recovery fence, then discard
only unanchored candidates through the backend API. Never recover by deleting
the SQLite file or by rebuilding anchor state from it.

Worker adapters must explicitly declare read-only/idempotent safety before the
non-durable `invoke` path is enabled, and a bounded reconciliation contract
before durable dispatch or compensation is enabled. A declaration is a trusted
Rust-code review obligation, not proof of external exactly-once behavior. A
durable adapter must recover status by the host operation key and pass that key
to a provider idempotency mechanism when one exists. The runtime's ordering
prevents a duplicate adapter invocation for an existing journal key, but it
cannot make an external provider idempotent or queryable.

`ProtocolWorkerClient` connects that validation layer to a host-owned
`WorkerTransport`; its registration rejects a local policy that is broader than
the worker grant. This still does not make an in-process transport isolated.

Each registered tool declares a stable identifier and limits for calls, input
bytes, and output bytes. Calls are recorded in an ordered audit log. Unknown,
over-budget, over-depth, or malformed calls fail before a tool handler is
invoked.

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

`WorkflowOperationLedger` records durable external-operation intent separately
from a checkpoint. Each record is bound to the trusted plan and retains only a
tool, step, non-authorizing operation key, input digest, and worker-observed
state. Reconciliation request construction requires the exact current input
bytes and fails closed when their digest differs. The preferred derived key
also binds the plan, step, tool, input, and host-supplied durable nonce, so a
host should not reuse it for a different logical effect. A ledger revision is
only a host-facing compare-and-swap or watermark hook: it does not authenticate
storage, prevent rollback by itself, validate a worker output, restore a VM
promise, or authorize a workflow restart. Those decisions remain with an
authenticated storage backend and fresh host policy.
The persisted input fingerprint is an unkeyed correlation digest, not encrypted
secret storage; hosts must pass opaque secret selectors rather than credential
values into the ledger identity.

An operation ledger may hold one compensation intent only after its original
operation is durably `succeeded`. That intent binds a separate `cmp-` key,
canonical-input digest, tenant scope, and active capability-grant fingerprint;
it never stores raw compensation input, output, an approval, or a grant.
Compensation approvals are process-local, one-use, session-bound host values.
They must be issued only after the intent is durably persisted and must be
reissued after a restart for the exact same record. A changed tenant, key,
input, or grant fails closed. The ledger cannot prove an inverse effect is
semantically correct or automatically restart a workflow.
`CompensationGrantVerifier` is invoked by the workflow host before approval
and again before frame sealing, so a production host must connect it to current
tenant policy, revocation, and any grant-lease state rather than treating a
stored fingerprint as a still-valid capability.

`splash-storage` authenticates host-owned record bytes with a provisioned
BLAKE3 key and binds them to an opaque record namespace, name, revision, and
key ID. It supports verification-key rotation, but it does not encrypt payloads
or generate, transfer, or protect storage keys. Its `RollbackProtectedStore`
trait is deliberately strict: an implementation must atomically return a
record with its durable revision floor, and atomically advance that floor with
a successful compare-and-swap. The included `VolatileMemoryStore` is only a
process-local test/development implementation, not a durable backend. A file,
database, or mobile key-value adapter must not claim rollback protection unless
it has a separate platform trust anchor and the required atomic semantics.
Generated Splash source receives neither a store nor a key.

Worker protocol v4 adds authenticated operation-dispatch and explicit
compensation frames. A contained worker's `WorkerOperationJournal` records
the tool, key, canonical-input digest, state, and at most one compensation
record before its adapter runs an effect. A compensation is admitted only for
a succeeded original operation under the same tool and tenant scope, with an
exact active-grant fingerprint and a separately bounded nonzero compensation
grant. An exact duplicate returns the stored compensation state; a changed
tool, key, input, grant, scope, or contradictory terminal result is rejected.
The host should reconcile an ambiguous response rather than blindly
re-dispatching or creating another inverse effect. This remains a worker
idempotency primitive, not semantic rollback, key exchange, process
containment, or authorization granted to Splash source. The journal retains
terminal result data for idempotent replies, so its storage may need encryption
in addition to authentication. The canonical-input digest is an unkeyed
correlation value, so operation payloads must contain opaque secret selectors
rather than credential values.

This baseline does not yet provide filesystem adapters, network adapters,
secret storage, worker-process isolation, signed packages, full JSON Schema,
or mobile policy backends. Those features must not be inferred from the
presence of the VM.

Tool descriptions and schemas are available only through the host-side
catalog. They are not script-visible authority. Schemas registered solely as
`ToolMetadata` remain prompt metadata; only `JsonToolContract` is executable.
