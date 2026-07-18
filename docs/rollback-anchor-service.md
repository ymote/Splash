# Transactional Rollback-Anchor Service

`splash_storage::rollback_anchor_service` defines a bounded host-only protocol
for a separately trusted transactional service. It is intended for deployments
where the service retains rollback-resistant per-record state outside the
rollback domain of a local SQLite payload file.

The protocol is not a Splash capability, tool, or general HTTP API. Storage
record keys, service URLs, and authentication values remain host configuration.
No generated source can select an endpoint, issue a request, inspect anchor
state, or obtain a token.

## Client Setup

The optional HTTPS transport is fixed to one complete host-selected endpoint.
It requires HTTPS, disables environment proxies and redirects, sends only
bounded JSON POSTs, accepts only bounded JSON 2xx responses, and does not
expose its endpoint or token through `Debug`.

```toml
[dependencies]
splash-storage = { path = "../splash-storage", features = ["sqlite", "https-rollback-anchor"] }
```

```rust
use splash_storage::{
    https_rollback_anchor::{
        HttpsRollbackAnchorAuthorization, HttpsRollbackAnchorTransport,
    },
    rollback_anchor_service::TrustedServiceRollbackAnchor,
    sqlite::AnchoredSqliteStore,
};

let authorization = HttpsRollbackAnchorAuthorization::bearer(host_provisioned_bearer_token)?;
let transport = HttpsRollbackAnchorTransport::new(
    "https://anchor.example.invalid/v1/splash-anchor",
    Some(authorization),
)?;
let anchor = TrustedServiceRollbackAnchor::new(transport);
let backend = AnchoredSqliteStore::open("/host-owned/splash.sqlite", anchor)?;
# let _ = backend;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The bearer token must come from trusted host provisioning, such as an app
enrollment flow or a native credential backend. It is not stored in an
authenticated record and is not a Splash secret API. A host can omit bearer
authentication when its independently configured transport authentication is
sufficient.

The optional HTTPS feature uses Rustls' `ring` provider. Android builds require
the matching Android NDK compiler to be configured for Cargo; the feature is
not a pure-Rust cross-compile dependency.

The client does not pin DNS results, contain OS egress, attest the remote
service, or make a service correct merely because TLS succeeds. HTTPS provides
transport authentication for the configured host name; the service's durable
state and deployment trust model remain separate requirements.

## Wire Protocol

Every request and response is a UTF-8 JSON object no larger than 4 KiB. The
protocol version is currently `1`. Revisions and fences are canonical decimal
strings rather than JSON numbers, so every `u64` value survives JavaScript and
other JSON implementations without precision loss:

- `"0"` is the only zero spelling.
- Nonzero values contain ASCII decimal digits with no leading zero.
- `record_commitment` is `null` exactly when `revision_floor` is `"0"`.
- A non-null commitment is the unpadded URL-safe Base64 encoding of exactly 32
  bytes.

The host client sends either:

```json
{
  "version": 1,
  "operation": "load",
  "key": {"namespace": "workflow-ledger", "name": "release-42"}
}
```

or:

```json
{
  "version": 1,
  "operation": "compare_and_swap",
  "key": {"namespace": "workflow-ledger", "name": "release-42"},
  "expected": {
    "revision_floor": "1",
    "record_commitment": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "fencing_token": "4"
  },
  "replacement": {
    "revision_floor": "2",
    "record_commitment": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    "fencing_token": "5"
  }
}
```

A `load` response must be:

```json
{
  "version": 1,
  "outcome": "state",
  "state": {
    "revision_floor": "2",
    "record_commitment": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    "fencing_token": "5"
  }
}
```

A compare-and-swap response is either `{"version":1,"outcome":"stored"}`
or `{"version":1,"outcome":"conflict","actual":{...}}`, where `actual`
is a complete state object. The client rejects a response shape intended for the
wrong request.

## Service Requirements

For every exact `(namespace, name)` key, the service must:

1. Persist the complete state durably outside the rollback domain of the local
   payload store.
2. Atomically replace `expected` only when it is current, returning the exact
   observed state on conflict.
3. Reject a lower revision, a lower fencing token, or a changed commitment at
   the same revision.
4. Return only after a successful state transition is durable and
   rollback-resistant through its own transactional, hardware, or equivalent
   authority.
5. Disable stale-response caching for the endpoint and treat failed or
   ambiguous requests as indeterminate rather than as a successful commit.

`TrustedServiceRollbackAnchor` validates outgoing transitions and keeps a
process-local observed-state floor to detect a regressing response during one
process lifetime. That cache is defense in depth only: it is lost on restart
and cannot replace the service's durable monotonic authority.

The client also refuses to send a compare-and-swap whose `expected` state
regresses a state already observed in this process. A host that has observed a
newer state must reload or reconcile before it retries; it must not blindly
retry an older expectation.

The client redacts service transport errors and response bytes. Hosts should
retain service diagnostics in their own protected observability system rather
than exposing them to worker or Splash diagnostics.
