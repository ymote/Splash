# Authenticated Durable Storage

`splash-storage` is a host-only record boundary for checkpoints, workflow
operation ledgers, and other non-script state. It protects a serialized record
against tampering and transplant to a different logical record key. It does
not grant a script storage access, expose a storage key, encrypt data, create a
database, or contain an operating-system effect.

## Record Envelope

`AuthenticatedStore` seals each payload with a provisioned 32-byte BLAKE3 key.
The tag binds all of the following through length-delimited binary fields:

- the envelope format version;
- an opaque record namespace and name;
- the storage key ID and record revision; and
- the complete payload bytes.

The stored JSON envelope is only a transport representation. Opening it
checks size bounds, canonical base64, the key ID, its matching backend
revision, and the keyed tag before returning payload bytes. A record copied to
another namespace or name fails authentication even if its envelope is valid.

Payload authentication is not encryption. Do not persist credential values or
other secrets in a record merely because it has a tag. Use opaque secret
selectors and a platform-provided encrypted secret facility where appropriate.

## Rollback Contract

An authentication tag cannot reveal that an attacker restored an old but valid
record. `RollbackProtectedStore` therefore has a stronger host-backend
contract:

1. `load` returns the record and its revision floor as one consistent snapshot.
2. For a live record, its revision equals that floor. An absent record has a
   zero floor.
3. A successful compare-and-swap writes the replacement and advances the
   floor to its new revision atomically.
4. The floor is itself durable and rollback-resistant through a platform trust
   anchor.

`AuthenticatedStore` fails closed when the snapshot violates that contract:
an old record below the floor is a rollback, and a newer record above the floor
means the backend did not advance its anchor. An ordinary file, SQLite row, or
key-value entry does not meet this contract by itself. A production backend
needs a transactional trusted service, hardware monotonic counter, or an
equivalent platform primitive that survives storage rollback.

`VolatileMemoryStore` implements the API only to exercise the semantics in
tests and local development. It loses both bytes and its floor at process exit,
so it is never a production rollback defense.

## Anchored SQLite

The optional `sqlite` feature provides
`splash_storage::sqlite::AnchoredSqliteStore`. It uses SQLite for local
transactional payload storage and a host-provided `RollbackAnchor` for the
separate durable, rollback-resistant commitment. SQLite alone remains an
ordinary local database and is not a trust anchor.

```toml
splash-storage = { version = "0.1", features = ["sqlite"] }
```

```rust
use splash_storage::{
    sqlite::AnchoredSqliteStore, AuthenticatedStore, StorageKeyring,
};

// `platform_anchor` must implement RollbackAnchor through a real platform
// monotonic authority or transactional trusted service.
let backend = AnchoredSqliteStore::open("/host-owned/splash.sqlite", platform_anchor)?;
let store = AuthenticatedStore::new(backend, storage_keyring);
```

For each write, the adapter first commits an immutable SQLite candidate with
`synchronous=FULL`, then atomically advances the anchor to that candidate's
revision, content commitment, and fencing state. A candidate left by a crash
before the anchor transition is ignored. If the anchor has advanced but the
SQLite file is later restored, missing or substituted payload bytes fail closed
because they no longer match the anchor's exact record commitment.

All local writers must use the same SQLite file and the same linearizable
`RollbackAnchor`. Do not use independent SQLite replicas on separate hosts as
a shared durable store; use a transactional trusted service or a backend built
for that topology. Keep the database parent directory policy-controlled: an
anchor detects data rollback but does not make an attacker-controlled path or
filesystem safe to write.

SQLite candidates are bounded per record. If an anchor outage leaves enough
uncommitted candidates to reach the bound, stop new admissions, reserve a
fresh recovery fence, then discard only candidates not committed by the anchor:

```rust
let recovery = backend.reserve_recovery_fence(&record_key)?;
let discarded = backend.discard_unanchored_candidates(recovery)?;
```

The opaque recovery fence is bound to one record and can be used once. It
prevents older in-flight fenced writers from promoting a candidate after it is
discarded. A host must still stop new admissions before recovery. The adapter
does not bootstrap a trust anchor from an existing SQLite file; migration must
write a new trusted anchor state through the selected platform authority.

`VolatileRollbackAnchor` exists only for tests and local development. A real
`RollbackAnchor` must atomically and monotonically preserve the revision,
content commitment, and fence across restart, storage rollback, and anchor
failover.

## Fenced Writers

`FencedRollbackProtectedStore` extends the rollback contract for a record that
can have more than one potential worker writer. A host-issued monotonic fencing
token is made current before an authenticated compare-and-swap checks the
record revision. A fenced write succeeds only when its supplied token is the
exact current token; a lower token is rejected. A higher token remains current
even when its caller discovers a stale revision and must reload. That sequence
prevents an older session from writing after a newer session has been admitted.

The token is not a capability or secret. Its authority comes from the host's
admission service and the backend enforcing the same monotonically increasing
value. `VolatileMemoryStore` exercises the API in tests only; it is not a
durable source of fences or rollback protection.

The backend exposes `reserve_fence` to atomically persist and return the next
nonzero token for one record. Admission and recovery must use that operation,
or a separate lease authority with the same atomic per-record allocation
guarantee. Never issue `current_fence() + 1` after a separate read: two hosts
can observe the same fence and receive the same token. `current_fence` is for
inspection and audit only. Never reset a fence to zero.

The fence and data record use the same structured `StorageRecordKey`. A fenced
compare-and-swap must revalidate exact token equality inside one atomic backend
operation; a separate fence read followed by a write leaves a time-of-check,
time-of-use gap. The fence backend and its failover behavior are therefore a
security trust anchor. Once a record has a nonzero fence, a plain
compare-and-swap must fail rather than bypass the fenced write path.

`splash-worker::WorkerJournalStore` has the same production requirement for a
worker operation journal: `persist` must atomically compare the loaded
`WorkerJournalRevision`, commit the new journal, and advance that revision
through an authenticated rollback-resistant durable store, while rejecting an
expired `WorkerJournalLease` from a superseded worker session. It is
intentionally a narrow callback so the runtime cannot turn a file, SQLite row,
or in-memory cache into a trusted backend by itself. Any persistence failure
poisons the worker session; a failed post-effect write also returns an
indeterminate worker error. Discard the session and reopen from a fresh atomic
snapshot before bounded reconciliation or explicit adapter/operator policy.

The admission service and the store must share one monotonic lease authority
for each journal scope. On one host this may be a transaction guarded by the
same durable backend; across hosts it needs a trusted coordination service or
platform monotonic primitive. A process-local counter is not a fencing source.

`AuthenticatedWorkerJournalStore` is the concrete bridge from this generic
fenced storage boundary to `WorkerJournalStore`. It binds one host-owned
namespace and journal scope to one deterministic `StorageRecordKey`, loads a
verified journal together with its authenticated revision, and persists it through
`AuthenticatedStore::compare_and_swap_fenced`. It deliberately requires a
`FencedRollbackProtectedStore`; an unfenced file, SQLite row, or ordinary
key-value store cannot instantiate the bridge as a production durable worker
store. The host must identity-bind the selected journal scope before
constructing the bridge; its syntax validation alone does not establish tenant
isolation. The bridge exposes only that selected record's journal operations,
not its underlying general-purpose authenticated store.

## Key Rotation

`StorageKeyring` has one active write key plus prior verification keys. To
rotate, add a fresh key ID with `rotate_to`, then read and rewrite each record
with `AuthenticatedStore::replace`. The rewrite moves it to the active key and
advances the revision. Retire an old key only after every record using it has
been rewritten or intentionally expired.

Key IDs are metadata, not secrets. Generate each 32-byte key with an
OS-provided CSPRNG and provision it only to the trusted host and its selected
storage backend. This crate does not perform key exchange, key wrapping, or
key attestation.

## Native Keyring Loading

The optional `keyring` feature can load **pre-provisioned** 32-byte storage
keys from the native credential store on macOS, iOS, and Windows. It uses the
platform Keychain or Credential Manager through `keyring-rs`; it is unavailable
on Linux and embedded targets rather than falling back to an in-process mock
credential store.

```toml
splash-storage = { version = "0.1", features = ["keyring"] }
```

```rust
use splash_storage::{
    platform_keyring::{PlatformKeyringEntry, PlatformKeyringKeyring}, StorageKeyId,
};

let active = PlatformKeyringEntry::new(
    StorageKeyId::new("storage-v2")?,
    "com.ymote.splash",
    "workflow-storage-v2",
)?;
let previous = PlatformKeyringEntry::new(
    StorageKeyId::new("storage-v1")?,
    "com.ymote.splash",
    "workflow-storage-v1",
)?;
let storage_keyring = PlatformKeyringKeyring::new(active, vec![previous])?.load()?;
```

Each configured service/account pair must already contain exactly 32 binary
secret bytes. The module only reads them: it never generates, writes, rotates,
or deletes a credential. Provision the active key through an app installer,
MDM, enrollment flow, or another platform-specific trusted host process; use a
separate location for every key ID. This keeps key enrollment and recovery out
of script-visible code and avoids silent first-run key races. On supported
targets the loader calls the explicit native credential implementation rather
than `keyring-rs`'s process-configurable default builder, so an in-process mock
cannot become a production fallback.

Native credential storage protects key material, not the version of a durable
record. It does **not** implement `RollbackAnchor`, provide linearizable
compare-and-swap for anchor state, or make a local SQLite file rollback-proof.
Continue to supply a trusted monotonic anchor for `AnchoredSqliteStore`.

## Workflow Integration

Persist the serialized ledger under a stable host record key before dispatch
and after each reconciliation or compensation mutation. A compensation intent
must be written with compare-and-swap storage before the host issues its
one-use approval or sends a worker frame. On restart, open the authenticated
record first, parse the ledger, recreate the trusted plan, and validate both
the plan binding and the ledger's own revision policy.

~~~rust
use splash_storage::StorageRecordKey;
use splash_workflow::WorkflowOperationLedger;

let record_key = StorageRecordKey::new("workflow-ledger", "release-42")?;
let stored = store.load(&record_key)?.expect("host-created ledger record");
let ledger_json = std::str::from_utf8(stored.payload())?;
let ledger = WorkflowOperationLedger::from_json(ledger_json)?;
engine.validate_operation_ledger(&recreated_plan, &ledger)?;
~~~

When the ledger changes, use the authenticated record revision returned by the
previous load as the compare-and-swap expectation. The storage revision guards
the envelope; `WorkflowOperationLedger::revision` remains the workflow's own
monotonic operation record and should also be checked against any host policy.
