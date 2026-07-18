//! Capability-bound secret delivery for trusted worker adapters.
//!
//! This module intentionally has no Splash-callable API. A host configures an
//! exact `(tool, secret-id)` binding, gives the opaque binding to a reviewed
//! Rust adapter, and supplies a host-owned [`SecretProvider`]. During a worker
//! invocation, [`CapabilitySecretBroker`] resolves a secret only when the
//! active [`CapabilityGrant`] carries that same `ResourceKind::Secret`
//! selector. It never treats script input as a secret identifier and does not
//! expose a lookup or enumeration API.
//!
//! The broker is an authorization and lifetime boundary, not a platform secret
//! store or operating-system containment mechanism. Hosts must still use an
//! appropriate credential backend and ensure that the receiving adapter does
//! not log, serialize, or otherwise disclose the bytes it receives.

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};

use splash_protocol::{CapabilityGrant, ProtocolError, ResourceKind, ResourceSelector};
use zeroize::Zeroizing;

/// Maximum exact tool/secret bindings retained by one broker.
///
/// This matches the protocol's maximum grants per worker manifest, keeping
/// broker configuration bounded independently from the host's secret backend.
pub const MAX_CAPABILITY_SECRET_BINDINGS: usize = 128;
/// Maximum byte length of one secret resolved through the broker.
pub const MAX_CAPABILITY_SECRET_BYTES: usize = 64 * 1024;

/// An opaque host-configured secret binding for one worker tool.
///
/// The identifiers are host metadata, not secret bytes. They are redacted from
/// `Debug` to avoid accidentally turning logs into a secret-inventory API.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct SecretAccessBinding {
    tool: String,
    secret_identifier: String,
}

impl SecretAccessBinding {
    /// Creates one exact host-owned tool/secret binding.
    ///
    /// The tool name uses the worker capability profile and the secret
    /// identifier uses the protocol's opaque resource-selector profile.
    pub fn new(
        tool: impl Into<String>,
        secret_identifier: impl Into<String>,
    ) -> Result<Self, SecretAccessBindingError> {
        let tool = tool.into();
        CapabilityGrant::text(tool.clone())
            .validate()
            .map_err(SecretAccessBindingError::InvalidTool)?;
        let secret_identifier = secret_identifier.into();
        ResourceSelector::new(ResourceKind::Secret, secret_identifier.clone())
            .map_err(SecretAccessBindingError::InvalidSecretIdentifier)?;
        Ok(Self {
            tool,
            secret_identifier,
        })
    }

    /// Returns the host-selected tool name for this binding.
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Returns the host-selected opaque secret identifier for this binding.
    ///
    /// This accessor is for trusted resolver configuration only. It does not
    /// make the identifier discoverable from Splash source or worker protocol
    /// diagnostics.
    pub fn secret_identifier(&self) -> &str {
        &self.secret_identifier
    }
}

impl fmt::Debug for SecretAccessBinding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretAccessBinding(REDACTED)")
    }
}

/// Invalid configuration for a [`SecretAccessBinding`].
pub enum SecretAccessBindingError {
    InvalidTool(ProtocolError),
    InvalidSecretIdentifier(ProtocolError),
}

impl fmt::Debug for SecretAccessBindingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTool(_) => formatter.write_str("SecretAccessBindingError::InvalidTool"),
            Self::InvalidSecretIdentifier(_) => {
                formatter.write_str("SecretAccessBindingError::InvalidSecretIdentifier")
            }
        }
    }
}

impl Display for SecretAccessBindingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTool(_) => {
                formatter.write_str("secret binding has an invalid worker tool name")
            }
            Self::InvalidSecretIdentifier(_) => {
                formatter.write_str("secret binding has an invalid opaque secret identifier")
            }
        }
    }
}

// `ProtocolError` can contain the rejected host identifier. Do not make that
// configuration metadata available through a generic error-chain logger.
impl std::error::Error for SecretAccessBindingError {}

/// One bounded secret value delivered to a trusted adapter.
///
/// Values are binary so providers can handle protocol tokens, key material, or
/// other non-text credentials. The buffer is zeroized when dropped. Callers
/// can access it only through [`Self::with_bytes`]; copying the bytes outside
/// that callback remains the responsibility of trusted adapter code.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Creates one bounded nonempty secret value.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, SecretValueError> {
        let value = Zeroizing::new(value.into());
        if value.is_empty() {
            return Err(SecretValueError::EmptyValue);
        }
        if value.len() > MAX_CAPABILITY_SECRET_BYTES {
            return Err(SecretValueError::ValueTooLarge {
                actual: value.len(),
                maximum: MAX_CAPABILITY_SECRET_BYTES,
            });
        }
        Ok(Self(value))
    }

    /// Borrows the secret bytes only for the duration of `callback`.
    pub fn with_bytes<R>(&self, callback: impl FnOnce(&[u8]) -> R) -> R {
        callback(&self.0)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue(REDACTED)")
    }
}

/// Rejection while creating a [`SecretValue`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretValueError {
    EmptyValue,
    ValueTooLarge { actual: usize, maximum: usize },
}

impl Display for SecretValueError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValue => formatter.write_str("secret value must not be empty"),
            Self::ValueTooLarge { actual, maximum } => write!(
                formatter,
                "secret value has {actual} bytes, exceeding the {maximum}-byte broker limit"
            ),
        }
    }
}

impl std::error::Error for SecretValueError {}

/// Host-owned backend that resolves one preconfigured opaque secret ID.
///
/// Implementations must treat `secret_identifier` as host configuration. They
/// must not interpret it as a path, URL, command, or generated-source value.
/// A provider should return a newly owned [`SecretValue`] for each resolution.
pub trait SecretProvider {
    type Error;

    fn resolve(&mut self, secret_identifier: &str) -> Result<SecretValue, Self::Error>;
}

impl<F, E> SecretProvider for F
where
    F: for<'a> FnMut(&'a str) -> Result<SecretValue, E>,
{
    type Error = E;

    fn resolve(&mut self, secret_identifier: &str) -> Result<SecretValue, Self::Error> {
        self(secret_identifier)
    }
}

/// A bounded host-owned secret broker for worker adapters.
///
/// The broker owns both the resolver and its finite exact bindings. It exposes
/// no resolver accessor, binding iterator, or direct value getter. A reviewed
/// adapter must retain the exact [`SecretAccessBinding`] it was configured to
/// use and call [`Self::with_secret`] with the current worker grant.
pub struct CapabilitySecretBroker<P> {
    provider: P,
    bindings: BTreeSet<SecretAccessBinding>,
}

impl<P> CapabilitySecretBroker<P> {
    /// Creates a broker with a host-owned provider and exact allowed bindings.
    pub fn new<I>(
        provider: P,
        bindings: I,
    ) -> Result<Self, CapabilitySecretBrokerConfigurationError>
    where
        I: IntoIterator<Item = SecretAccessBinding>,
    {
        let mut retained = BTreeSet::new();
        for binding in bindings {
            if retained.contains(&binding) {
                return Err(CapabilitySecretBrokerConfigurationError::DuplicateBinding);
            }
            if retained.len() == MAX_CAPABILITY_SECRET_BINDINGS {
                return Err(CapabilitySecretBrokerConfigurationError::CapacityExceeded {
                    maximum: MAX_CAPABILITY_SECRET_BINDINGS,
                });
            }
            retained.insert(binding);
        }
        Ok(Self {
            provider,
            bindings: retained,
        })
    }

    /// Returns how many exact tool/secret bindings this broker retains.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Returns whether the broker has no configured bindings.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

impl<P: SecretProvider> CapabilitySecretBroker<P> {
    /// Resolves a configured secret only for one exact capability grant.
    ///
    /// The method first validates the supplied grant, then checks that the
    /// binding was retained by this broker, that its tool matches the grant,
    /// and that the grant contains the exact `Secret` resource. The provider
    /// is not called unless all checks pass. The value is borrowed only by the
    /// supplied callback and is zeroized when the provider result drops.
    pub fn with_secret<R>(
        &mut self,
        grant: &CapabilityGrant,
        binding: &SecretAccessBinding,
        callback: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, CapabilitySecretBrokerError<P::Error>> {
        grant
            .validate()
            .map_err(CapabilitySecretBrokerError::InvalidGrant)?;
        if !self.bindings.contains(binding) {
            return Err(CapabilitySecretBrokerError::UnconfiguredBinding);
        }
        if grant.tool != binding.tool {
            return Err(CapabilitySecretBrokerError::ToolNotGranted);
        }
        if !grant.resources.iter().any(|resource| {
            resource.kind == ResourceKind::Secret && resource.id == binding.secret_identifier
        }) {
            return Err(CapabilitySecretBrokerError::SecretNotGranted);
        }
        let secret = self
            .provider
            .resolve(&binding.secret_identifier)
            .map_err(CapabilitySecretBrokerError::Provider)?;
        Ok(secret.with_bytes(callback))
    }
}

impl<P> fmt::Debug for CapabilitySecretBroker<P> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilitySecretBroker")
            .field("binding_count", &self.bindings.len())
            .finish_non_exhaustive()
    }
}

/// Invalid configuration for a [`CapabilitySecretBroker`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilitySecretBrokerConfigurationError {
    DuplicateBinding,
    CapacityExceeded { maximum: usize },
}

impl Display for CapabilitySecretBrokerConfigurationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateBinding => formatter.write_str("duplicate worker secret binding"),
            Self::CapacityExceeded { maximum } => {
                write!(
                    formatter,
                    "worker secret broker exceeds its {maximum}-binding limit"
                )
            }
        }
    }
}

impl std::error::Error for CapabilitySecretBrokerConfigurationError {}

/// Failure while resolving a secret through [`CapabilitySecretBroker`].
pub enum CapabilitySecretBrokerError<E> {
    InvalidGrant(ProtocolError),
    UnconfiguredBinding,
    ToolNotGranted,
    SecretNotGranted,
    Provider(E),
}

impl<E> fmt::Debug for CapabilitySecretBrokerError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGrant(_) => {
                formatter.write_str("CapabilitySecretBrokerError::InvalidGrant")
            }
            Self::UnconfiguredBinding => {
                formatter.write_str("CapabilitySecretBrokerError::UnconfiguredBinding")
            }
            Self::ToolNotGranted => {
                formatter.write_str("CapabilitySecretBrokerError::ToolNotGranted")
            }
            Self::SecretNotGranted => {
                formatter.write_str("CapabilitySecretBrokerError::SecretNotGranted")
            }
            Self::Provider(_) => {
                formatter.write_str("CapabilitySecretBrokerError::Provider(REDACTED)")
            }
        }
    }
}

impl<E> Display for CapabilitySecretBrokerError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGrant(_) => formatter.write_str("worker capability grant is invalid"),
            Self::UnconfiguredBinding => {
                formatter.write_str("worker secret binding is not configured")
            }
            Self::ToolNotGranted => {
                formatter.write_str("worker secret binding is not authorized for this tool")
            }
            Self::SecretNotGranted => {
                formatter.write_str("worker secret resource is not present in this grant")
            }
            Self::Provider(_) => formatter.write_str("worker secret provider failed"),
        }
    }
}

// Both protocol and provider failures can carry host configuration or backend
// details. The broker's public error is deliberately a redacted boundary.
impl<E: 'static> std::error::Error for CapabilitySecretBrokerError<E> {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ProviderError {
        Unavailable,
    }

    impl Display for ProviderError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            formatter.write_str("provider backend unavailable")
        }
    }

    impl std::error::Error for ProviderError {}

    #[derive(Default)]
    struct RecordingProvider {
        values: BTreeMap<String, Vec<u8>>,
        calls: Vec<String>,
        unavailable: bool,
    }

    impl RecordingProvider {
        fn with_value(identifier: &str, value: &[u8]) -> Self {
            Self {
                values: BTreeMap::from([(identifier.to_owned(), value.to_vec())]),
                ..Self::default()
            }
        }
    }

    impl SecretProvider for RecordingProvider {
        type Error = ProviderError;

        fn resolve(&mut self, secret_identifier: &str) -> Result<SecretValue, Self::Error> {
            self.calls.push(secret_identifier.to_owned());
            if self.unavailable {
                return Err(ProviderError::Unavailable);
            }
            let value = self
                .values
                .get(secret_identifier)
                .ok_or(ProviderError::Unavailable)?;
            SecretValue::new(value.clone()).map_err(|_| ProviderError::Unavailable)
        }
    }

    fn binding() -> SecretAccessBinding {
        SecretAccessBinding::new("release.publish", "release.token").unwrap()
    }

    fn granted_secret(tool: &str, secret_identifier: &str) -> CapabilityGrant {
        let mut grant = CapabilityGrant::json(tool);
        grant
            .resources
            .insert(ResourceSelector::new(ResourceKind::Secret, secret_identifier).unwrap());
        grant
    }

    #[test]
    fn validates_bindings_and_zeroizing_secret_values() {
        assert!(matches!(
            SecretAccessBinding::new("bad/tool", "release.token"),
            Err(SecretAccessBindingError::InvalidTool(_))
        ));
        assert!(matches!(
            SecretAccessBinding::new("release.publish", "bad/secret"),
            Err(SecretAccessBindingError::InvalidSecretIdentifier(_))
        ));
        assert!(matches!(
            SecretValue::new(Vec::new()),
            Err(SecretValueError::EmptyValue)
        ));
        assert!(matches!(
            SecretValue::new(vec![0; MAX_CAPABILITY_SECRET_BYTES + 1]),
            Err(SecretValueError::ValueTooLarge { .. })
        ));

        let binding = binding();
        let value = SecretValue::new(b"release-token".to_vec()).unwrap();
        assert_eq!(value.with_bytes(|bytes| bytes.to_vec()), b"release-token");
        assert_eq!(format!("{binding:?}"), "SecretAccessBinding(REDACTED)");
        assert_eq!(format!("{value:?}"), "SecretValue(REDACTED)");
        assert!(!format!("{binding:?}").contains("release.token"));
        assert!(!format!("{value:?}").contains("release-token"));

        let error = SecretAccessBinding::new("release.publish", "bad/secret").unwrap_err();
        assert!(!format!("{error:?}").contains("bad/secret"));
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn resolves_only_an_exact_tool_and_secret_resource_binding() {
        let binding = binding();
        let provider = RecordingProvider::with_value("release.token", b"release-token");
        let mut broker = CapabilitySecretBroker::new(provider, [binding.clone()]).unwrap();
        let grant = granted_secret("release.publish", "release.token");

        let observed = broker
            .with_secret(&grant, &binding, |bytes| bytes.to_vec())
            .unwrap();
        assert_eq!(observed, b"release-token");
        assert_eq!(broker.provider.calls, ["release.token"]);
        let debug = format!("{broker:?}");
        assert!(debug.contains("binding_count"));
        assert!(!debug.contains("release.token"));
    }

    #[test]
    fn rejects_unconfigured_or_ungranted_bindings_before_resolution() {
        let binding = binding();
        let other_binding = SecretAccessBinding::new("release.publish", "other.token").unwrap();
        let provider = RecordingProvider::with_value("release.token", b"release-token");
        let mut broker = CapabilitySecretBroker::new(provider, [binding.clone()]).unwrap();

        let missing_resource = CapabilityGrant::json("release.publish");
        assert!(matches!(
            broker.with_secret(&missing_resource, &binding, |_| ()),
            Err(CapabilitySecretBrokerError::SecretNotGranted)
        ));

        let mut wrong_resource_kind = CapabilityGrant::json("release.publish");
        wrong_resource_kind
            .resources
            .insert(ResourceSelector::new(ResourceKind::FileRoot, "release.token").unwrap());
        assert!(matches!(
            broker.with_secret(&wrong_resource_kind, &binding, |_| ()),
            Err(CapabilitySecretBrokerError::SecretNotGranted)
        ));

        let wrong_tool = granted_secret("release.read", "release.token");
        assert!(matches!(
            broker.with_secret(&wrong_tool, &binding, |_| ()),
            Err(CapabilitySecretBrokerError::ToolNotGranted)
        ));

        let exact_grant = granted_secret("release.publish", "other.token");
        assert!(matches!(
            broker.with_secret(&exact_grant, &other_binding, |_| ()),
            Err(CapabilitySecretBrokerError::UnconfiguredBinding)
        ));
        assert!(broker.provider.calls.is_empty());
    }

    #[test]
    fn rejects_invalid_grants_and_redacts_provider_failures() {
        let binding = binding();
        let mut broker = CapabilitySecretBroker::new(
            RecordingProvider {
                unavailable: true,
                ..RecordingProvider::with_value("release.token", b"release-token")
            },
            [binding.clone()],
        )
        .unwrap();
        let mut invalid_grant = granted_secret("release.publish", "release.token");
        invalid_grant.max_calls = 0;
        assert!(matches!(
            broker.with_secret(&invalid_grant, &binding, |_| ()),
            Err(CapabilitySecretBrokerError::InvalidGrant(_))
        ));
        assert!(broker.provider.calls.is_empty());

        let grant = granted_secret("release.publish", "release.token");
        let error = broker.with_secret(&grant, &binding, |_| ()).unwrap_err();
        assert!(matches!(error, CapabilitySecretBrokerError::Provider(_)));
        assert_eq!(error.to_string(), "worker secret provider failed");
        assert!(!error.to_string().contains("provider backend unavailable"));
        assert!(!format!("{error:?}").contains("provider backend unavailable"));
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(broker.provider.calls, ["release.token"]);
    }

    #[test]
    fn bounds_and_deduplicates_broker_configuration() {
        let binding = binding();
        assert_eq!(
            CapabilitySecretBroker::new(RecordingProvider::default(), [binding.clone(), binding])
                .unwrap_err(),
            CapabilitySecretBrokerConfigurationError::DuplicateBinding
        );

        let bindings = (0..=MAX_CAPABILITY_SECRET_BINDINGS)
            .map(|index| {
                SecretAccessBinding::new("release.publish", format!("release-{index}")).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            CapabilitySecretBroker::new(RecordingProvider::default(), bindings).unwrap_err(),
            CapabilitySecretBrokerConfigurationError::CapacityExceeded {
                maximum: MAX_CAPABILITY_SECRET_BINDINGS,
            }
        );
    }
}
