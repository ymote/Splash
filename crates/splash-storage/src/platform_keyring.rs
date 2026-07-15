//! Read-only loading of host-provisioned storage keys from native keyrings.
//!
//! This module deliberately retrieves only pre-existing binary credentials.
//! It never generates, writes, rotates, or deletes platform credentials: those
//! operations need host-specific enrollment and recovery policy. Native
//! credential stores protect key material but do not provide the linearizable,
//! rollback-resistant compare-and-swap required by [`crate::RollbackAnchor`].

use std::fmt::{self, Display, Formatter};

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows", test))]
use zeroize::Zeroize;

use crate::{is_valid_token, StorageKeyId, StorageKeyring, MAX_STORAGE_RECORD_NAME_BYTES};
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows", test))]
use crate::{StorageKey, STORAGE_KEY_BYTES};

/// Maximum byte length for a native credential-store service or account name.
pub const MAX_PLATFORM_KEYRING_IDENTIFIER_BYTES: usize = MAX_STORAGE_RECORD_NAME_BYTES;

/// One host-owned credential-store location for a versioned storage key.
///
/// The service and account are opaque host configuration, never Splash data.
/// They use the same bounded lowercase identifier profile as storage record
/// keys so an empty Keychain wildcard can never be requested accidentally.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PlatformKeyringEntry {
    key_id: StorageKeyId,
    service: String,
    account: String,
}

impl PlatformKeyringEntry {
    /// Creates one validated platform credential-store location.
    pub fn new(
        key_id: StorageKeyId,
        service: impl Into<String>,
        account: impl Into<String>,
    ) -> Result<Self, PlatformKeyringEntryError> {
        let service = service.into();
        if !is_valid_token(&service, MAX_PLATFORM_KEYRING_IDENTIFIER_BYTES) {
            return Err(PlatformKeyringEntryError::InvalidService);
        }
        let account = account.into();
        if !is_valid_token(&account, MAX_PLATFORM_KEYRING_IDENTIFIER_BYTES) {
            return Err(PlatformKeyringEntryError::InvalidAccount);
        }
        Ok(Self {
            key_id,
            service,
            account,
        })
    }

    /// Returns the metadata identifier written into authenticated envelopes.
    pub fn key_id(&self) -> &StorageKeyId {
        &self.key_id
    }

    /// Returns the host-selected native credential-store service.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns the host-selected native credential-store account.
    pub fn account(&self) -> &str {
        &self.account
    }
}

/// Invalid platform credential-store entry configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformKeyringEntryError {
    InvalidService,
    InvalidAccount,
}

impl Display for PlatformKeyringEntryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidService => formatter
                .write_str("platform credential-store service must be a bounded lowercase token"),
            Self::InvalidAccount => formatter
                .write_str("platform credential-store account must be a bounded lowercase token"),
        }
    }
}

impl std::error::Error for PlatformKeyringEntryError {}

/// A host-selected active storage key plus prior verification-only keys.
///
/// Use a separate native credential-store entry for every key ID. Constructing
/// this value does not access the platform store; [`Self::load`] is the only
/// operation that retrieves key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformKeyringKeyring {
    active: PlatformKeyringEntry,
    read_entries: Vec<PlatformKeyringEntry>,
}

impl PlatformKeyringKeyring {
    /// Validates a keyring configuration before any native credential lookup.
    pub fn new(
        active: PlatformKeyringEntry,
        read_entries: Vec<PlatformKeyringEntry>,
    ) -> Result<Self, PlatformKeyringKeyringError> {
        for (index, entry) in read_entries.iter().enumerate() {
            if entry.key_id == active.key_id
                || read_entries[..index]
                    .iter()
                    .any(|existing| existing.key_id == entry.key_id)
            {
                return Err(PlatformKeyringKeyringError::DuplicateKeyId(
                    entry.key_id.clone(),
                ));
            }
            if same_locator(entry, &active)
                || read_entries[..index]
                    .iter()
                    .any(|existing| same_locator(existing, entry))
            {
                return Err(PlatformKeyringKeyringError::DuplicateCredentialLocator);
            }
        }
        Ok(Self {
            active,
            read_entries,
        })
    }

    /// Returns whether this build can access a native credential store.
    ///
    /// The `keyring` feature is intentionally unsupported on Linux and
    /// embedded targets rather than falling back to keyring-rs's in-process
    /// mock store.
    pub const fn is_supported_target() -> bool {
        cfg!(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "windows"
        ))
    }

    /// Returns the configured active storage-key entry.
    pub fn active(&self) -> &PlatformKeyringEntry {
        &self.active
    }

    /// Returns the configured verification-only storage-key entries.
    pub fn read_entries(&self) -> &[PlatformKeyringEntry] {
        &self.read_entries
    }

    /// Retrieves all configured pre-provisioned keys into a storage keyring.
    ///
    /// Every stored secret must be exactly [`STORAGE_KEY_BYTES`] binary bytes.
    /// No key material is retained in this configuration after loading.
    pub fn load(&self) -> Result<StorageKeyring, PlatformKeyringKeyringError> {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
        {
            let active_key = load_entry(&self.active)?;
            let mut keyring = StorageKeyring::new(self.active.key_id.clone(), active_key);
            for entry in &self.read_entries {
                let key = load_entry(entry)?;
                let key_id = entry.key_id.clone();
                keyring
                    .add_read_key(key_id.clone(), key)
                    .map_err(|_| PlatformKeyringKeyringError::DuplicateKeyId(key_id))?;
            }
            Ok(keyring)
        }

        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "windows")))]
        {
            Err(PlatformKeyringKeyringError::UnsupportedTarget)
        }
    }
}

/// Failure while configuring or loading a platform credential-store keyring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformKeyringKeyringError {
    DuplicateKeyId(StorageKeyId),
    DuplicateCredentialLocator,
    UnsupportedTarget,
    CredentialStore {
        key_id: StorageKeyId,
    },
    InvalidSecretLength {
        key_id: StorageKeyId,
        actual: usize,
        expected: usize,
    },
}

impl Display for PlatformKeyringKeyringError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKeyId(key_id) => {
                write!(formatter, "duplicate platform storage key ID: {key_id}")
            }
            Self::DuplicateCredentialLocator => {
                formatter.write_str("multiple platform storage keys use one credential location")
            }
            Self::UnsupportedTarget => formatter.write_str(
                "native platform keyring loading is supported only on macOS, iOS, and Windows",
            ),
            Self::CredentialStore { key_id } => {
                write!(formatter, "platform credential-store access failed for storage key {key_id}")
            }
            Self::InvalidSecretLength {
                key_id,
                actual,
                expected,
            } => write!(
                formatter,
                "platform credential for storage key {key_id} has {actual} bytes; expected {expected}"
            ),
        }
    }
}

impl std::error::Error for PlatformKeyringKeyringError {}

fn same_locator(left: &PlatformKeyringEntry, right: &PlatformKeyringEntry) -> bool {
    left.service == right.service && left.account == right.account
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
use ::keyring::credential::CredentialApi;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
fn load_entry(entry: &PlatformKeyringEntry) -> Result<StorageKey, PlatformKeyringKeyringError> {
    #[cfg(target_os = "macos")]
    let credential =
        ::keyring::macos::MacCredential::new_with_target(None, entry.service(), entry.account())
            .map_err(|_| PlatformKeyringKeyringError::CredentialStore {
                key_id: entry.key_id.clone(),
            })?;
    #[cfg(target_os = "ios")]
    let credential =
        ::keyring::ios::IosCredential::new_with_target(None, entry.service(), entry.account())
            .map_err(|_| PlatformKeyringKeyringError::CredentialStore {
                key_id: entry.key_id.clone(),
            })?;
    #[cfg(target_os = "windows")]
    let credential =
        ::keyring::windows::WinCredential::new_with_target(None, entry.service(), entry.account())
            .map_err(|_| PlatformKeyringKeyringError::CredentialStore {
                key_id: entry.key_id.clone(),
            })?;
    let secret =
        credential
            .get_secret()
            .map_err(|_| PlatformKeyringKeyringError::CredentialStore {
                key_id: entry.key_id.clone(),
            })?;
    storage_key_from_secret(entry, secret)
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows", test))]
fn storage_key_from_secret(
    entry: &PlatformKeyringEntry,
    mut secret: Vec<u8>,
) -> Result<StorageKey, PlatformKeyringKeyringError> {
    if secret.len() != STORAGE_KEY_BYTES {
        let error = PlatformKeyringKeyringError::InvalidSecretLength {
            key_id: entry.key_id.clone(),
            actual: secret.len(),
            expected: STORAGE_KEY_BYTES,
        };
        secret.zeroize();
        return Err(error);
    }
    let mut bytes = [0; STORAGE_KEY_BYTES];
    bytes.copy_from_slice(&secret);
    secret.zeroize();
    Ok(StorageKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key_id: &str, service: &str, account: &str) -> PlatformKeyringEntry {
        PlatformKeyringEntry::new(StorageKeyId::new(key_id).unwrap(), service, account).unwrap()
    }

    #[test]
    fn entry_rejects_empty_or_noncanonical_credential_identifiers() {
        let key_id = StorageKeyId::new("storage-v1").unwrap();
        assert_eq!(
            PlatformKeyringEntry::new(key_id.clone(), "", "host").unwrap_err(),
            PlatformKeyringEntryError::InvalidService
        );
        assert_eq!(
            PlatformKeyringEntry::new(key_id, "com.ymote.splash", "Host User").unwrap_err(),
            PlatformKeyringEntryError::InvalidAccount
        );
    }

    #[test]
    fn configuration_rejects_duplicate_ids_and_credential_locations() {
        let active = entry("storage-v2", "com.ymote.splash", "active");
        let duplicate_id = entry("storage-v2", "com.ymote.splash", "previous");
        assert_eq!(
            PlatformKeyringKeyring::new(active.clone(), vec![duplicate_id]).unwrap_err(),
            PlatformKeyringKeyringError::DuplicateKeyId(StorageKeyId::new("storage-v2").unwrap())
        );

        let duplicate_locator = entry("storage-v1", "com.ymote.splash", "active");
        assert_eq!(
            PlatformKeyringKeyring::new(active, vec![duplicate_locator]).unwrap_err(),
            PlatformKeyringKeyringError::DuplicateCredentialLocator
        );
    }

    #[test]
    fn binary_credential_material_must_have_the_storage_key_length() {
        let entry = entry("storage-v1", "com.ymote.splash", "active");
        assert!(storage_key_from_secret(&entry, vec![7; STORAGE_KEY_BYTES]).is_ok());
        assert_eq!(
            storage_key_from_secret(&entry, vec![7; STORAGE_KEY_BYTES - 1]).unwrap_err(),
            PlatformKeyringKeyringError::InvalidSecretLength {
                key_id: StorageKeyId::new("storage-v1").unwrap(),
                actual: STORAGE_KEY_BYTES - 1,
                expected: STORAGE_KEY_BYTES,
            }
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "windows")))]
    #[test]
    fn unsupported_targets_do_not_use_a_mock_credential_store() {
        let configuration = PlatformKeyringKeyring::new(
            entry("storage-v1", "com.ymote.splash", "active"),
            Vec::new(),
        )
        .unwrap();
        assert!(!PlatformKeyringKeyring::is_supported_target());
        assert_eq!(
            configuration.load().unwrap_err(),
            PlatformKeyringKeyringError::UnsupportedTarget
        );
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
    #[test]
    fn supported_targets_do_not_probe_or_mutate_credentials_during_configuration() {
        let configuration = PlatformKeyringKeyring::new(
            entry("storage-v1", "com.ymote.splash", "active"),
            Vec::new(),
        )
        .unwrap();
        assert!(PlatformKeyringKeyring::is_supported_target());
        assert_eq!(configuration.active().account(), "active");
        assert!(configuration.read_entries().is_empty());
    }
}
