//! Read-only host-secret resolution from native credential stores.
//!
//! This module deliberately maps only host-configured opaque secret IDs to
//! host-configured credential-store locators. Splash cannot select either a
//! locator or an identifier, and the resolver does not create, modify, rotate,
//! or delete credentials. It uses the explicit native keyring implementation
//! for macOS, iOS, and Windows, then fails closed on every other target rather
//! than falling back to keyring-rs's process-local mock store. The optional
//! HTTP resolver exposes only strict header-safe values; the optional worker
//! provider exposes bounded binary values only through a capability-bound
//! [`splash_worker::secret_broker::SecretProvider`] callback.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

#[cfg(all(
    feature = "platform-keyring-secret-resolver",
    any(target_os = "macos", target_os = "ios", target_os = "windows", test)
))]
use zeroize::Zeroize;

#[cfg(feature = "platform-keyring-secret-resolver")]
use crate::http_endpoint_catalog::{
    HttpEndpointSecret, HttpEndpointSecretError, HttpEndpointSecretResolver,
};
#[cfg(feature = "platform-keyring-worker-secret-provider")]
use splash_worker::secret_broker::{SecretProvider, SecretValue};

/// Maximum number of credential-store locations retained by one resolver.
pub const MAX_PLATFORM_KEYRING_SECRET_ENTRIES: usize = 128;
/// Maximum byte length of a native credential-store service or account locator.
pub const MAX_PLATFORM_KEYRING_SECRET_LOCATOR_BYTES: usize = 128;

/// One host-selected native credential-store location for a host secret.
///
/// The opaque secret ID, service, and account are intentionally not exposed by
/// accessors or `Debug`: they remain trusted setup configuration and never
/// become tool metadata or Splash data.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct PlatformKeyringSecretEntry {
    secret_identifier: String,
    service: String,
    account: String,
}

impl PlatformKeyringSecretEntry {
    /// Creates one validated mapping from a fixed opaque secret ID to one
    /// native credential-store service and account.
    pub fn new(
        secret_identifier: impl Into<String>,
        service: impl Into<String>,
        account: impl Into<String>,
    ) -> Result<Self, PlatformKeyringSecretEntryError> {
        let secret_identifier = secret_identifier.into();
        if !is_valid_secret_identifier(&secret_identifier) {
            return Err(PlatformKeyringSecretEntryError::InvalidSecretIdentifier);
        }
        let service = service.into();
        if !is_valid_locator(&service) {
            return Err(PlatformKeyringSecretEntryError::InvalidService);
        }
        let account = account.into();
        if !is_valid_locator(&account) {
            return Err(PlatformKeyringSecretEntryError::InvalidAccount);
        }
        Ok(Self {
            secret_identifier,
            service,
            account,
        })
    }
}

impl fmt::Debug for PlatformKeyringSecretEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlatformKeyringSecretEntry(REDACTED)")
    }
}

/// Invalid native credential-store entry configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformKeyringSecretEntryError {
    InvalidSecretIdentifier,
    InvalidService,
    InvalidAccount,
}

impl Display for PlatformKeyringSecretEntryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretIdentifier => formatter
                .write_str("platform credential-store secret ID must be a bounded lowercase token"),
            Self::InvalidService => formatter
                .write_str("platform credential-store service must be a bounded lowercase token"),
            Self::InvalidAccount => formatter
                .write_str("platform credential-store account must be a bounded lowercase token"),
        }
    }
}

impl std::error::Error for PlatformKeyringSecretEntryError {}

/// A bounded, read-only resolver for host-provisioned credentials.
///
/// Constructing this resolver validates only its static mapping. It does not
/// probe a native credential store. A native lookup happens only when the
/// selected HTTP resolver or worker secret provider needs a configured binding
/// for a valid invocation.
pub struct PlatformKeyringSecretResolver {
    entries: BTreeMap<String, PlatformKeyringSecretEntry>,
}

impl PlatformKeyringSecretResolver {
    /// Validates a fixed set of host-secret credential locations.
    pub fn new(
        entries: Vec<PlatformKeyringSecretEntry>,
    ) -> Result<Self, PlatformKeyringSecretResolverError> {
        if entries.len() > MAX_PLATFORM_KEYRING_SECRET_ENTRIES {
            return Err(PlatformKeyringSecretResolverError::CapacityExceeded {
                maximum: MAX_PLATFORM_KEYRING_SECRET_ENTRIES,
            });
        }

        let mut configured = BTreeMap::new();
        for entry in entries {
            if configured.contains_key(&entry.secret_identifier) {
                return Err(PlatformKeyringSecretResolverError::DuplicateSecretIdentifier);
            }
            if configured
                .values()
                .any(|existing| same_credential_locator(existing, &entry))
            {
                return Err(PlatformKeyringSecretResolverError::DuplicateCredentialLocator);
            }
            configured.insert(entry.secret_identifier.clone(), entry);
        }
        Ok(Self {
            entries: configured,
        })
    }

    /// Returns whether this build can access an explicit native credential store.
    ///
    /// Linux and embedded targets are deliberately unsupported instead of
    /// selecting keyring-rs's process-local mock credential store.
    pub const fn is_supported_target() -> bool {
        cfg!(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "windows"
        ))
    }

    /// Returns the number of opaque secret bindings retained here.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no secret bindings are retained here.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Debug for PlatformKeyringSecretResolver {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlatformKeyringSecretResolver")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Failure while configuring a native credential-store resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformKeyringSecretResolverError {
    CapacityExceeded { maximum: usize },
    DuplicateSecretIdentifier,
    DuplicateCredentialLocator,
}

impl Display for PlatformKeyringSecretResolverError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded { maximum } => write!(
                formatter,
                "platform credential-store secret resolver exceeds its maximum of {maximum} entries"
            ),
            Self::DuplicateSecretIdentifier => {
                formatter.write_str("platform credential-store secret ID is already configured")
            }
            Self::DuplicateCredentialLocator => {
                formatter.write_str("multiple host secrets use one credential-store location")
            }
        }
    }
}

impl std::error::Error for PlatformKeyringSecretResolverError {}

#[cfg(feature = "platform-keyring-secret-resolver")]
impl HttpEndpointSecretResolver for PlatformKeyringSecretResolver {
    fn resolve_http_endpoint_secret(
        &mut self,
        identifier: &str,
    ) -> Result<HttpEndpointSecret, HttpEndpointSecretError> {
        let entry = self
            .entries
            .get(identifier)
            .ok_or(HttpEndpointSecretError::NotFound)?;

        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
        {
            load_http_endpoint_secret(entry)
        }

        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "windows")))]
        {
            let _ = entry;
            Err(HttpEndpointSecretError::PlatformCredentialStoreUnavailable)
        }
    }
}

/// Failure while resolving a worker secret from the native credential store.
///
/// The error intentionally omits opaque IDs and locator details. A
/// [`splash_worker::secret_broker::CapabilitySecretBroker`] also maps it to a
/// generic adapter-side failure rather than exposing it to Splash source.
#[cfg(feature = "platform-keyring-worker-secret-provider")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformKeyringWorkerSecretProviderError {
    NotFound,
    UnsupportedTarget,
    CredentialStoreFailure,
    InvalidStoredValue,
}

#[cfg(feature = "platform-keyring-worker-secret-provider")]
impl Display for PlatformKeyringWorkerSecretProviderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("configured worker secret was not found"),
            Self::UnsupportedTarget => formatter.write_str(
                "native worker secret loading is supported only on macOS, iOS, and Windows",
            ),
            Self::CredentialStoreFailure => {
                formatter.write_str("native worker credential-store lookup failed")
            }
            Self::InvalidStoredValue => {
                formatter.write_str("native worker credential-store value is invalid")
            }
        }
    }
}

#[cfg(feature = "platform-keyring-worker-secret-provider")]
impl std::error::Error for PlatformKeyringWorkerSecretProviderError {}

/// Implements the worker's capability-bound binary [`SecretProvider`] using
/// the same fixed native credential mappings as the HTTP resolver.
///
/// This implementation remains read-only and does not fall back to keyring-rs
/// mock storage. The worker broker still verifies the exact configured
/// `(tool, secret-id)` binding and `ResourceKind::Secret` grant before this
/// resolver is called.
#[cfg(feature = "platform-keyring-worker-secret-provider")]
impl SecretProvider for PlatformKeyringSecretResolver {
    type Error = PlatformKeyringWorkerSecretProviderError;

    fn resolve(&mut self, identifier: &str) -> Result<SecretValue, Self::Error> {
        let entry = self
            .entries
            .get(identifier)
            .ok_or(PlatformKeyringWorkerSecretProviderError::NotFound)?;

        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
        {
            let secret = load_platform_secret_bytes(entry)
                .map_err(|_| PlatformKeyringWorkerSecretProviderError::CredentialStoreFailure)?;
            worker_secret_from_platform_bytes(secret)
        }

        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "windows")))]
        {
            let _ = entry;
            Err(PlatformKeyringWorkerSecretProviderError::UnsupportedTarget)
        }
    }
}

fn is_valid_locator(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PLATFORM_KEYRING_SECRET_LOCATOR_BYTES
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' => index != 0 || byte != b'.',
            _ => false,
        })
}

fn is_valid_secret_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PLATFORM_KEYRING_SECRET_LOCATOR_BYTES
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' => index != 0 || byte != b'.',
            _ => false,
        })
}

fn same_credential_locator(
    left: &PlatformKeyringSecretEntry,
    right: &PlatformKeyringSecretEntry,
) -> bool {
    left.service == right.service && left.account == right.account
}

#[cfg(all(
    feature = "platform-keyring-worker-secret-provider",
    any(target_os = "macos", target_os = "ios", target_os = "windows", test)
))]
fn worker_secret_from_platform_bytes(
    secret: Vec<u8>,
) -> Result<SecretValue, PlatformKeyringWorkerSecretProviderError> {
    SecretValue::new(secret)
        .map_err(|_| PlatformKeyringWorkerSecretProviderError::InvalidStoredValue)
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
use ::keyring::credential::CredentialApi;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlatformKeyringReadError {
    CredentialStoreFailure,
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
fn load_platform_secret_bytes(
    entry: &PlatformKeyringSecretEntry,
) -> Result<Vec<u8>, PlatformKeyringReadError> {
    #[cfg(target_os = "macos")]
    let credential =
        ::keyring::macos::MacCredential::new_with_target(None, &entry.service, &entry.account)
            .map_err(|_| PlatformKeyringReadError::CredentialStoreFailure)?;
    #[cfg(target_os = "ios")]
    let credential =
        ::keyring::ios::IosCredential::new_with_target(None, &entry.service, &entry.account)
            .map_err(|_| PlatformKeyringReadError::CredentialStoreFailure)?;
    #[cfg(target_os = "windows")]
    let credential =
        ::keyring::windows::WinCredential::new_with_target(None, &entry.service, &entry.account)
            .map_err(|_| PlatformKeyringReadError::CredentialStoreFailure)?;
    credential
        .get_secret()
        .map_err(|_| PlatformKeyringReadError::CredentialStoreFailure)
}

#[cfg(feature = "platform-keyring-secret-resolver")]
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
fn load_http_endpoint_secret(
    entry: &PlatformKeyringSecretEntry,
) -> Result<HttpEndpointSecret, HttpEndpointSecretError> {
    let secret = load_platform_secret_bytes(entry)
        .map_err(|_| HttpEndpointSecretError::PlatformCredentialStoreFailure)?;
    secret_from_platform_bytes(secret)
}

#[cfg(all(
    feature = "platform-keyring-secret-resolver",
    any(target_os = "macos", target_os = "ios", target_os = "windows", test)
))]
fn secret_from_platform_bytes(
    secret: Vec<u8>,
) -> Result<HttpEndpointSecret, HttpEndpointSecretError> {
    match String::from_utf8(secret) {
        Ok(secret) => {
            HttpEndpointSecret::new(secret).map_err(|_| HttpEndpointSecretError::InvalidStoredValue)
        }
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(HttpEndpointSecretError::InvalidStoredValue)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(identifier: &str, service: &str, account: &str) -> PlatformKeyringSecretEntry {
        PlatformKeyringSecretEntry::new(identifier, service, account)
            .expect("test credential locator is valid")
    }

    #[test]
    fn entries_reject_invalid_opaque_ids_and_credential_locators() {
        assert_eq!(
            PlatformKeyringSecretEntry::new("bad/id", "com.example.splash", "release").unwrap_err(),
            PlatformKeyringSecretEntryError::InvalidSecretIdentifier
        );
        assert_eq!(
            PlatformKeyringSecretEntry::new("release.auth", ".com.example.splash", "release")
                .unwrap_err(),
            PlatformKeyringSecretEntryError::InvalidService
        );
        assert_eq!(
            PlatformKeyringSecretEntry::new("release.auth", "com.example.splash", "Release User")
                .unwrap_err(),
            PlatformKeyringSecretEntryError::InvalidAccount
        );
    }

    #[test]
    fn resolver_rejects_duplicate_ids_locators_and_excess_entries() {
        assert_eq!(
            PlatformKeyringSecretResolver::new(vec![
                entry("release.auth", "com.example.splash", "release"),
                entry("release.auth", "com.example.splash", "preview"),
            ])
            .unwrap_err(),
            PlatformKeyringSecretResolverError::DuplicateSecretIdentifier
        );
        assert_eq!(
            PlatformKeyringSecretResolver::new(vec![
                entry("release.auth", "com.example.splash", "release"),
                entry("preview.auth", "com.example.splash", "release"),
            ])
            .unwrap_err(),
            PlatformKeyringSecretResolverError::DuplicateCredentialLocator
        );

        let entries = (0..=MAX_PLATFORM_KEYRING_SECRET_ENTRIES)
            .map(|index| {
                entry(
                    &format!("secret-{index}"),
                    "com.example.splash",
                    &format!("user-{index}"),
                )
            })
            .collect();
        assert_eq!(
            PlatformKeyringSecretResolver::new(entries).unwrap_err(),
            PlatformKeyringSecretResolverError::CapacityExceeded {
                maximum: MAX_PLATFORM_KEYRING_SECRET_ENTRIES,
            }
        );
    }

    #[test]
    fn resolver_redacts_all_locator_configuration() {
        let entry = entry("release.auth", "com.example.splash", "release-user");
        let resolver = PlatformKeyringSecretResolver::new(vec![entry.clone()])
            .expect("single locator is valid");
        let entry_debug = format!("{entry:?}");
        let resolver_debug = format!("{resolver:?}");
        for private_value in ["release.auth", "com.example.splash", "release-user"] {
            assert!(!entry_debug.contains(private_value));
            assert!(!resolver_debug.contains(private_value));
        }
        assert_eq!(resolver.len(), 1);
        assert!(!resolver.is_empty());
    }

    #[cfg(feature = "platform-keyring-secret-resolver")]
    #[test]
    fn platform_secret_bytes_are_strict_header_values() {
        assert!(secret_from_platform_bytes(b"test-token-42".to_vec()).is_ok());
        assert_eq!(
            secret_from_platform_bytes(b"line\nbreak".to_vec()).unwrap_err(),
            HttpEndpointSecretError::InvalidStoredValue
        );
        assert_eq!(
            secret_from_platform_bytes(vec![0xff]).unwrap_err(),
            HttpEndpointSecretError::InvalidStoredValue
        );
        assert_eq!(
            secret_from_platform_bytes(Vec::new()).unwrap_err(),
            HttpEndpointSecretError::InvalidStoredValue
        );
    }

    #[cfg(all(
        feature = "platform-keyring-secret-resolver",
        not(any(target_os = "macos", target_os = "ios", target_os = "windows"))
    ))]
    #[test]
    fn unsupported_targets_fail_closed_without_a_mock_credential_store() {
        let mut resolver = PlatformKeyringSecretResolver::new(vec![entry(
            "release.auth",
            "com.example.splash",
            "release",
        )])
        .expect("configuration does not access the native store");
        assert!(!PlatformKeyringSecretResolver::is_supported_target());
        assert!(matches!(
            resolver.resolve_http_endpoint_secret("release.auth"),
            Err(HttpEndpointSecretError::PlatformCredentialStoreUnavailable)
        ));
        assert!(matches!(
            resolver.resolve_http_endpoint_secret("missing.auth"),
            Err(HttpEndpointSecretError::NotFound)
        ));
    }

    #[cfg(all(
        feature = "platform-keyring-worker-secret-provider",
        not(any(target_os = "macos", target_os = "ios", target_os = "windows"))
    ))]
    #[test]
    fn worker_provider_fails_closed_without_a_mock_credential_store() {
        let mut resolver = PlatformKeyringSecretResolver::new(vec![entry(
            "release.auth",
            "com.example.splash",
            "release",
        )])
        .expect("configuration does not access the native store");
        assert!(matches!(
            SecretProvider::resolve(&mut resolver, "release.auth"),
            Err(PlatformKeyringWorkerSecretProviderError::UnsupportedTarget)
        ));
        assert!(matches!(
            SecretProvider::resolve(&mut resolver, "missing.auth"),
            Err(PlatformKeyringWorkerSecretProviderError::NotFound)
        ));
    }

    #[cfg(feature = "platform-keyring-worker-secret-provider")]
    #[test]
    fn worker_provider_retains_binary_values_without_header_coercion() {
        let value = worker_secret_from_platform_bytes(vec![0, 0xff]).unwrap();
        assert_eq!(value.with_bytes(|bytes| bytes.to_vec()), vec![0, 0xff]);
        assert!(matches!(
            worker_secret_from_platform_bytes(Vec::new()),
            Err(PlatformKeyringWorkerSecretProviderError::InvalidStoredValue)
        ));
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
    #[test]
    fn supported_targets_do_not_probe_credentials_during_configuration() {
        let resolver = PlatformKeyringSecretResolver::new(vec![entry(
            "release.auth",
            "com.example.splash",
            "release",
        )])
        .expect("configuration does not access the native store");
        assert!(PlatformKeyringSecretResolver::is_supported_target());
        assert_eq!(resolver.len(), 1);
    }
}
