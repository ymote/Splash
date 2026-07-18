# Capability-Bound Worker Secrets

`splash_worker::secret_broker` provides a narrow host-side secret-delivery
contract for reviewed Rust worker adapters. It is not a Splash API: generated
source cannot name a secret, enumerate bindings, retrieve bytes, or invoke a
provider.

## Authority model

Trusted host setup creates each exact `SecretAccessBinding` from:

- one registered worker tool name; and
- one opaque `ResourceKind::Secret` identifier.

The host gives that binding to the one reviewed adapter that needs it and
constructs `CapabilitySecretBroker` with a finite set of such bindings plus a
host-owned `SecretProvider`. When the adapter receives an invocation, it calls
`with_secret` using the active `CapabilityGrant` and its retained binding. The
broker validates all of the following before it asks the provider for bytes:

1. the supplied grant is structurally valid;
2. the exact binding was retained during trusted setup;
3. the binding's tool equals the active grant's tool; and
4. the grant contains the same opaque `Secret` resource identifier.

An invalid grant, another tool, another secret ID, or an unconfigured binding
fails before the provider runs. The broker has no binding iterator, direct
secret getter, or mutable provider accessor. `SecretValue` is binary, bounded
to 64 KiB, redacted from `Debug`, and zeroizes its owned buffer on drop. Its
bytes are available only inside a callback, although trusted adapter code must
still avoid copying, logging, or serializing them.

```rust
use splash_protocol::{CapabilityGrant, ResourceKind, ResourceSelector};
use splash_worker::secret_broker::{
    CapabilitySecretBroker, SecretAccessBinding, SecretProvider, SecretValue,
};

#[derive(Default)]
struct HostProvider;

impl SecretProvider for HostProvider {
    type Error = std::convert::Infallible;

    fn resolve(&mut self, identifier: &str) -> Result<SecretValue, Self::Error> {
        assert_eq!(identifier, "release.token");
        Ok(SecretValue::new(b"host-provisioned-token".to_vec()).expect("bounded test value"))
    }
}

let binding = SecretAccessBinding::new("release.publish", "release.token")?;
let mut broker = CapabilitySecretBroker::new(HostProvider, [binding.clone()])?;

// The host-created worker session supplies this grant. Splash source never
// constructs a CapabilityGrant or chooses its resource selectors.
let mut grant = CapabilityGrant::json("release.publish");
grant.resources.insert(ResourceSelector::new(
    ResourceKind::Secret,
    "release.token",
)?);

broker.with_secret(&grant, &binding, |token| {
    // Pass the bytes directly to the reviewed Rust client. Do not return them
    // in ToolPayload, write them to a log, or include them in a URL.
    assert!(!token.is_empty());
})?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

An adapter normally maps broker failure to its finite `WorkerAdapterError` and
does not expose provider details to the worker protocol or Splash diagnostics.
The adapter must retain its binding in trusted Rust configuration; it must not
derive the binding from a JSON request, a tool payload, a file, or another
generated value.

## Native credential provider

On macOS, iOS, and Windows, `splash-capabilities` can provide the broker's
`SecretProvider` using a fixed mapping to pre-provisioned native credentials:

```toml
[dependencies]
splash-capabilities = { path = "../splash-capabilities", features = ["platform-keyring-worker-secret-provider"] }
```

`PlatformKeyringSecretResolver` reuses the fixed opaque secret-ID to
service/account mapping used by the endpoint-secret integration. It performs
no lookup during construction, is read-only, exposes no mapping accessors, and
does not fall back to keyring-rs's process-local mock store. It returns bounded
binary values so the provider is suitable for non-HTTP credentials as well as
text tokens. Linux and embedded targets fail closed with `UnsupportedTarget`.
The broker still has to receive the exact binding and current grant before this
provider is asked to load a value.

```rust
use splash_capabilities::platform_keyring_secret_resolver::{
    PlatformKeyringSecretEntry, PlatformKeyringSecretResolver,
};
use splash_worker::secret_broker::{CapabilitySecretBroker, SecretAccessBinding};

let binding = SecretAccessBinding::new("release.publish", "release.token")?;
let provider = PlatformKeyringSecretResolver::new(vec![
    PlatformKeyringSecretEntry::new(
        "release.token",
        "com.example.splash",
        "release-publish",
    )?,
])?;
let broker = CapabilitySecretBroker::new(provider, [binding])?;
# let _ = broker;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Boundary

The broker does not implement a platform credential store, enroll credentials,
attest a device, make a local process safe, or establish an operating-system
secret boundary. A host must implement `SecretProvider` with a target-appropriate
backend such as a native credential store, hardware-backed service, or a
separately contained broker. The provider is responsible for authenticating
its lookup, retaining no more secret data than needed, and returning a newly
owned bounded `SecretValue` for each call.

The capability grant is still only an authorization signal. A trusted adapter
that copies secret bytes into untrusted memory or sends them through an
uncontained network client defeats this boundary. For effectful local tools,
combine the exact secret binding with a target-specific containment backend and
an independently reviewed adapter.
