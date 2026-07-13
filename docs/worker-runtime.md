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
and supply authenticated rollback-resistant journal storage.

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

`WorkerTransport` currently carries only ordinary `invoke` messages. Durable
operation dispatch, reconciliation, and compensation need their own
host-controlled transport API and the authenticated rollback-resistant journal
storage contract; this adapter does not weaken either requirement.

## Bounded JSON-Line Transport

The optional `splash-capabilities` feature `json-line-worker` provides a
`JsonLineWorkerChannel<R, W>` for a host-owned buffered reader and writer,
plus `AuthenticatedFrameWorkerTransport<C>` for ordinary `invoke`/`result`
calls. It is the pipe boundary for a worker process that the host has already
started and placed in an appropriate platform sandbox; it does not spawn,
attest, or contain that process itself.

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
stream. The channel performs synchronous I/O, so the host must also enforce
worker I/O deadlines, cancellation delivery, process termination, and resource
limits through its platform backend.

## Mobile and Embedded Profiles

The crate has no async runtime, thread, socket, filesystem, process, or
allocator-specific dependency. It can sit behind an app-owned message loop or
an embedded transport as long as the host enforces frame-size limits, adapter
I/O timeouts, storage semantics, and containment appropriate to the target.

On mobile, the recommended profile is app-provided adapters only: do not
expose arbitrary executable, filesystem, or network selectors to the worker.
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
