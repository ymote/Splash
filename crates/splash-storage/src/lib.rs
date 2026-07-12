#![forbid(unsafe_code)]

//! Host-only authenticated durable-record boundary for Splash.
//!
//! Splash source never receives a storage handle or a key. Hosts inject a
//! [`RollbackProtectedStore`] whose snapshot and compare-and-swap operations
//! are backed by a trusted persistence and anti-rollback mechanism. This crate
//! authenticates bytes and binds them to a record location; it does not encrypt
//! data or turn an ordinary key-value store into an anti-rollback backend.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Byte length of a BLAKE3 storage authentication key.
pub const STORAGE_KEY_BYTES: usize = blake3::KEY_LEN;
/// Maximum byte length of a persisted key identifier.
pub const MAX_STORAGE_KEY_ID_BYTES: usize = 64;
/// Maximum byte length of a storage-record namespace.
pub const MAX_STORAGE_RECORD_NAMESPACE_BYTES: usize = 64;
/// Maximum byte length of a storage-record name.
pub const MAX_STORAGE_RECORD_NAME_BYTES: usize = 128;
/// Maximum plaintext payload accepted by one authenticated record.
pub const MAX_AUTHENTICATED_PAYLOAD_BYTES: usize = 256 * 1024;
/// Maximum serialized envelope accepted from a storage backend.
pub const MAX_AUTHENTICATED_RECORD_BYTES: usize = 384 * 1024;
/// Current authenticated-record wire format version.
pub const AUTHENTICATED_RECORD_FORMAT_VERSION: u8 = 1;
/// Byte length of a BLAKE3 authentication tag.
pub const AUTHENTICATED_RECORD_TAG_BYTES: usize = blake3::OUT_LEN;

/// A 32-byte host-owned key used to authenticate storage envelopes.
///
/// The key intentionally has no serializer, display implementation, or byte
/// accessor. It is not a capability token and must be provisioned to the host
/// through a trusted platform mechanism.
pub struct StorageKey {
    bytes: [u8; STORAGE_KEY_BYTES],
}

impl StorageKey {
    pub fn from_bytes(bytes: [u8; STORAGE_KEY_BYTES]) -> Self {
        Self { bytes }
    }
}

impl Clone for StorageKey {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes }
    }
}

impl Drop for StorageKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for StorageKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("StorageKey([REDACTED])")
    }
}

/// A stable, non-secret identifier for one storage key version.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StorageKeyId(String);

impl StorageKeyId {
    pub fn new(value: impl Into<String>) -> Result<Self, StorageKeyIdError> {
        let value = value.into();
        if !is_valid_token(&value, MAX_STORAGE_KEY_ID_BYTES) {
            return Err(StorageKeyIdError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for StorageKeyId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Rejection from [`StorageKeyId::new`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageKeyIdError {
    Invalid,
}

impl Display for StorageKeyIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("storage key ID must be a bounded lowercase token")
    }
}

impl std::error::Error for StorageKeyIdError {}

/// Identifies a single host-owned durable record.
///
/// Namespace and name are opaque host identities, not filesystem paths,
/// connection strings, secret values, or script-visible identifiers.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StorageRecordKey {
    namespace: String,
    name: String,
}

impl StorageRecordKey {
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, StorageRecordKeyError> {
        let namespace = namespace.into();
        if !is_valid_token(&namespace, MAX_STORAGE_RECORD_NAMESPACE_BYTES) {
            return Err(StorageRecordKeyError::InvalidNamespace);
        }
        let name = name.into();
        if !is_valid_token(&name, MAX_STORAGE_RECORD_NAME_BYTES) {
            return Err(StorageRecordKeyError::InvalidName);
        }
        Ok(Self { namespace, name })
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Rejection from [`StorageRecordKey::new`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageRecordKeyError {
    InvalidNamespace,
    InvalidName,
}

impl Display for StorageRecordKeyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNamespace => {
                formatter.write_str("storage namespace must be a bounded lowercase token")
            }
            Self::InvalidName => {
                formatter.write_str("storage record name must be a bounded lowercase token")
            }
        }
    }
}

impl std::error::Error for StorageRecordKeyError {}

/// Host-owned signing and verification keys, including prior read keys.
///
/// `rotate_to` retains the old active key for verification. Rewriting a loaded
/// record with [`AuthenticatedStore::replace`] then seals it under the new
/// active key and advances its revision.
pub struct StorageKeyring {
    active_key_id: StorageKeyId,
    keys: BTreeMap<StorageKeyId, StorageKey>,
}

impl StorageKeyring {
    pub fn new(active_key_id: StorageKeyId, active_key: StorageKey) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(active_key_id.clone(), active_key);
        Self {
            active_key_id,
            keys,
        }
    }

    pub fn active_key_id(&self) -> &StorageKeyId {
        &self.active_key_id
    }

    /// Adds a verification-only or future active key.
    pub fn add_read_key(
        &mut self,
        key_id: StorageKeyId,
        key: StorageKey,
    ) -> Result<(), StorageKeyringError> {
        if self.keys.contains_key(&key_id) {
            return Err(StorageKeyringError::DuplicateKeyId(key_id));
        }
        self.keys.insert(key_id, key);
        Ok(())
    }

    /// Adds a new key and makes it active for subsequent writes.
    pub fn rotate_to(
        &mut self,
        key_id: StorageKeyId,
        key: StorageKey,
    ) -> Result<(), StorageKeyringError> {
        self.add_read_key(key_id.clone(), key)?;
        self.active_key_id = key_id;
        Ok(())
    }

    /// Removes a retired verification key. The active key cannot be removed.
    pub fn retire(&mut self, key_id: &StorageKeyId) -> Result<(), StorageKeyringError> {
        if *key_id == self.active_key_id {
            return Err(StorageKeyringError::ActiveKeyCannotBeRetired);
        }
        if self.keys.remove(key_id).is_none() {
            return Err(StorageKeyringError::UnknownKeyId(key_id.clone()));
        }
        Ok(())
    }

    fn active_key(&self) -> &StorageKey {
        self.keys
            .get(&self.active_key_id)
            .expect("active storage key is always inserted with its ID")
    }

    fn verification_key(&self, key_id: &StorageKeyId) -> Option<&StorageKey> {
        self.keys.get(key_id)
    }
}

impl fmt::Debug for StorageKeyring {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageKeyring")
            .field("active_key_id", &self.active_key_id)
            .field("key_count", &self.keys.len())
            .finish()
    }
}

/// Errors while maintaining a [`StorageKeyring`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageKeyringError {
    DuplicateKeyId(StorageKeyId),
    UnknownKeyId(StorageKeyId),
    ActiveKeyCannotBeRetired,
}

impl Display for StorageKeyringError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKeyId(key_id) => write!(formatter, "duplicate storage key ID: {key_id}"),
            Self::UnknownKeyId(key_id) => write!(formatter, "unknown storage key ID: {key_id}"),
            Self::ActiveKeyCannotBeRetired => {
                formatter.write_str("the active storage key cannot be retired")
            }
        }
    }
}

impl std::error::Error for StorageKeyringError {}

/// Bytes and revision returned by a storage backend.
///
/// Backend implementors should return this only as part of an atomic
/// [`StorageSnapshot`]. The byte limit still applies when the authenticated
/// wrapper opens it.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredRecord {
    revision: u64,
    bytes: Vec<u8>,
}

impl fmt::Debug for StoredRecord {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredRecord")
            .field("revision", &self.revision)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

impl StoredRecord {
    pub fn new(revision: u64, bytes: Vec<u8>) -> Self {
        Self { revision, bytes }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// An atomically consistent record and its trusted anti-rollback floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageSnapshot {
    record: Option<StoredRecord>,
    revision_floor: u64,
}

impl StorageSnapshot {
    pub fn new(record: Option<StoredRecord>, revision_floor: u64) -> Self {
        Self {
            record,
            revision_floor,
        }
    }

    pub fn record(&self) -> Option<&StoredRecord> {
        self.record.as_ref()
    }

    pub fn revision_floor(&self) -> u64 {
        self.revision_floor
    }
}

/// Result of an atomic storage compare-and-swap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompareAndSwapOutcome {
    /// The replacement was committed and the durable floor was advanced in the
    /// same backend operation.
    Stored { revision_floor: u64 },
    /// The record changed between the caller's snapshot and the attempted
    /// compare-and-swap.
    Conflict {
        actual_revision: Option<u64>,
        revision_floor: u64,
    },
}

/// Host-provided persistence plus a rollback-resistant revision anchor.
///
/// `load` must return the record and its revision floor from one consistent
/// snapshot. For a live record, its revision must equal the floor. An absent
/// record must have a zero floor. A successful `compare_and_swap` must persist
/// the replacement and advance its floor to the replacement revision atomically
/// before reporting [`CompareAndSwapOutcome::Stored`]. The floor must survive
/// process restart and storage rollback through a platform trust anchor, such
/// as a transactional trusted service, hardware monotonic counter, or an
/// equivalent platform primitive.
///
/// [`VolatileMemoryStore`] implements this trait only for tests and local
/// development. It is deliberately not a durable or rollback-resistant
/// production backend.
pub trait RollbackProtectedStore {
    type Error;

    fn load(&self, key: &StorageRecordKey) -> Result<StorageSnapshot, Self::Error>;

    fn compare_and_swap(
        &mut self,
        key: &StorageRecordKey,
        expected_revision: Option<u64>,
        replacement: StoredRecord,
    ) -> Result<CompareAndSwapOutcome, Self::Error>;
}

/// The verified payload returned by [`AuthenticatedStore::load`] and writes.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedRecord {
    revision: u64,
    key_id: StorageKeyId,
    payload: Vec<u8>,
}

impl fmt::Debug for AuthenticatedRecord {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRecord")
            .field("revision", &self.revision)
            .field("key_id", &self.key_id)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl AuthenticatedRecord {
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn key_id(&self) -> &StorageKeyId {
        &self.key_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Authenticates records supplied by a host-owned rollback-protected backend.
pub struct AuthenticatedStore<B> {
    backend: B,
    keyring: StorageKeyring,
}

impl<B> AuthenticatedStore<B>
where
    B: RollbackProtectedStore,
{
    pub fn new(backend: B, keyring: StorageKeyring) -> Self {
        Self { backend, keyring }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn keyring(&self) -> &StorageKeyring {
        &self.keyring
    }

    pub fn keyring_mut(&mut self) -> &mut StorageKeyring {
        &mut self.keyring
    }

    pub fn into_parts(self) -> (B, StorageKeyring) {
        (self.backend, self.keyring)
    }

    /// Loads and verifies the current record against both its key and trusted
    /// revision floor.
    pub fn load(
        &self,
        key: &StorageRecordKey,
    ) -> Result<Option<AuthenticatedRecord>, AuthenticatedStoreError<B::Error>> {
        let snapshot = self
            .backend
            .load(key)
            .map_err(AuthenticatedStoreError::Backend)?;
        self.open_snapshot(key, snapshot)
    }

    /// Creates an absent record at revision one.
    pub fn create(
        &mut self,
        key: &StorageRecordKey,
        payload: &[u8],
    ) -> Result<AuthenticatedRecord, AuthenticatedStoreError<B::Error>> {
        self.compare_and_swap(key, None, payload)
    }

    /// Replaces a verified record at exactly `expected_revision`.
    pub fn replace(
        &mut self,
        key: &StorageRecordKey,
        expected_revision: u64,
        payload: &[u8],
    ) -> Result<AuthenticatedRecord, AuthenticatedStoreError<B::Error>> {
        self.compare_and_swap(key, Some(expected_revision), payload)
    }

    /// Atomically writes an authenticated replacement after verifying the
    /// current record and its rollback floor.
    pub fn compare_and_swap(
        &mut self,
        key: &StorageRecordKey,
        expected_revision: Option<u64>,
        payload: &[u8],
    ) -> Result<AuthenticatedRecord, AuthenticatedStoreError<B::Error>> {
        if payload.len() > MAX_AUTHENTICATED_PAYLOAD_BYTES {
            return Err(AuthenticatedStoreError::PayloadTooLarge {
                actual: payload.len(),
                maximum: MAX_AUTHENTICATED_PAYLOAD_BYTES,
            });
        }

        let snapshot = self
            .backend
            .load(key)
            .map_err(AuthenticatedStoreError::Backend)?;
        let current = self.open_snapshot(key, snapshot)?;
        match (expected_revision, current.as_ref()) {
            (None, None) => {}
            (None, Some(current)) => {
                return Err(AuthenticatedStoreError::WriteConflict {
                    expected: None,
                    actual: Some(current.revision),
                    revision_floor: current.revision,
                });
            }
            (Some(expected), Some(current)) if expected == current.revision => {}
            (Some(expected), Some(current)) => {
                return Err(AuthenticatedStoreError::WriteConflict {
                    expected: Some(expected),
                    actual: Some(current.revision),
                    revision_floor: current.revision,
                });
            }
            (Some(expected), None) => {
                return Err(AuthenticatedStoreError::WriteConflict {
                    expected: Some(expected),
                    actual: None,
                    revision_floor: 0,
                });
            }
        }

        let previous_revision = expected_revision.unwrap_or(0);
        let revision = previous_revision
            .checked_add(1)
            .ok_or(AuthenticatedStoreError::RevisionExhausted)?;
        let replacement = self.seal(key, revision, payload)?;
        let outcome = self
            .backend
            .compare_and_swap(key, expected_revision, replacement)
            .map_err(AuthenticatedStoreError::Backend)?;
        match outcome {
            CompareAndSwapOutcome::Stored { revision_floor } => {
                if revision_floor != revision {
                    return Err(AuthenticatedStoreError::RevisionFloorMismatch {
                        record_revision: revision,
                        revision_floor,
                    });
                }
                Ok(AuthenticatedRecord {
                    revision,
                    key_id: self.keyring.active_key_id().clone(),
                    payload: payload.to_vec(),
                })
            }
            CompareAndSwapOutcome::Conflict {
                actual_revision,
                revision_floor,
            } => {
                validate_revision_pair(actual_revision, revision_floor)?;
                Err(AuthenticatedStoreError::WriteConflict {
                    expected: expected_revision,
                    actual: actual_revision,
                    revision_floor,
                })
            }
        }
    }

    fn open_snapshot(
        &self,
        key: &StorageRecordKey,
        snapshot: StorageSnapshot,
    ) -> Result<Option<AuthenticatedRecord>, AuthenticatedStoreError<B::Error>> {
        let record_revision = snapshot.record.as_ref().map(StoredRecord::revision);
        validate_revision_pair(record_revision, snapshot.revision_floor)?;
        let Some(record) = snapshot.record else {
            return Ok(None);
        };
        if record.bytes.len() > MAX_AUTHENTICATED_RECORD_BYTES {
            return Err(AuthenticatedStoreError::RecordTooLarge {
                actual: record.bytes.len(),
                maximum: MAX_AUTHENTICATED_RECORD_BYTES,
            });
        }
        let envelope: StoredEnvelope = serde_json::from_slice(&record.bytes)
            .map_err(|_| AuthenticatedStoreError::InvalidEnvelope)?;
        if envelope.format_version != AUTHENTICATED_RECORD_FORMAT_VERSION {
            return Err(AuthenticatedStoreError::UnsupportedFormat(
                envelope.format_version,
            ));
        }
        if envelope.revision == 0 {
            return Err(AuthenticatedStoreError::InvalidRevision);
        }
        if envelope.revision != record.revision {
            return Err(AuthenticatedStoreError::RevisionMismatch {
                backend: record.revision,
                envelope: envelope.revision,
            });
        }
        let key_id = StorageKeyId::new(envelope.key_id)
            .map_err(|_| AuthenticatedStoreError::InvalidKeyId)?;
        let payload = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(envelope.payload.as_bytes())
            .map_err(|_| AuthenticatedStoreError::InvalidEnvelope)?;
        if payload.len() > MAX_AUTHENTICATED_PAYLOAD_BYTES {
            return Err(AuthenticatedStoreError::PayloadTooLarge {
                actual: payload.len(),
                maximum: MAX_AUTHENTICATED_PAYLOAD_BYTES,
            });
        }
        if base64::engine::general_purpose::STANDARD_NO_PAD.encode(&payload) != envelope.payload {
            return Err(AuthenticatedStoreError::InvalidEnvelope);
        }
        let actual_tag = decode_tag(&envelope.auth_tag)
            .ok_or(AuthenticatedStoreError::InvalidAuthenticationTag)?;
        let verification_key = self
            .keyring
            .verification_key(&key_id)
            .ok_or(AuthenticatedStoreError::UnknownKeyId)?;
        let expected_tag = authenticated_record_tag(
            verification_key,
            key,
            envelope.format_version,
            &key_id,
            envelope.revision,
            &payload,
        );
        if expected_tag.ct_eq(&actual_tag).unwrap_u8() != 1 {
            return Err(AuthenticatedStoreError::InvalidAuthenticationTag);
        }
        Ok(Some(AuthenticatedRecord {
            revision: envelope.revision,
            key_id,
            payload,
        }))
    }

    fn seal(
        &self,
        key: &StorageRecordKey,
        revision: u64,
        payload: &[u8],
    ) -> Result<StoredRecord, AuthenticatedStoreError<B::Error>> {
        let key_id = self.keyring.active_key_id();
        let tag = authenticated_record_tag(
            self.keyring.active_key(),
            key,
            AUTHENTICATED_RECORD_FORMAT_VERSION,
            key_id,
            revision,
            payload,
        );
        let envelope = StoredEnvelope {
            format_version: AUTHENTICATED_RECORD_FORMAT_VERSION,
            key_id: key_id.as_str().to_owned(),
            revision,
            payload: base64::engine::general_purpose::STANDARD_NO_PAD.encode(payload),
            auth_tag: encode_tag(&tag),
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| AuthenticatedStoreError::Encoding)?;
        if bytes.len() > MAX_AUTHENTICATED_RECORD_BYTES {
            return Err(AuthenticatedStoreError::RecordTooLarge {
                actual: bytes.len(),
                maximum: MAX_AUTHENTICATED_RECORD_BYTES,
            });
        }
        Ok(StoredRecord::new(revision, bytes))
    }
}

/// Errors emitted by [`AuthenticatedStore`].
#[derive(Debug)]
pub enum AuthenticatedStoreError<E> {
    Backend(E),
    PayloadTooLarge {
        actual: usize,
        maximum: usize,
    },
    RecordTooLarge {
        actual: usize,
        maximum: usize,
    },
    Encoding,
    InvalidEnvelope,
    UnsupportedFormat(u8),
    InvalidKeyId,
    UnknownKeyId,
    InvalidRevision,
    RevisionMismatch {
        backend: u64,
        envelope: u64,
    },
    InvalidAuthenticationTag,
    RollbackDetected {
        record_revision: Option<u64>,
        revision_floor: u64,
    },
    RevisionFloorMismatch {
        record_revision: u64,
        revision_floor: u64,
    },
    RevisionExhausted,
    WriteConflict {
        expected: Option<u64>,
        actual: Option<u64>,
        revision_floor: u64,
    },
}

impl<E: Display> Display for AuthenticatedStoreError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(error) => write!(formatter, "storage backend error: {error}"),
            Self::PayloadTooLarge { actual, maximum } => {
                write!(formatter, "storage payload is {actual} bytes; maximum is {maximum}")
            }
            Self::RecordTooLarge { actual, maximum } => write!(
                formatter,
                "authenticated storage record is {actual} bytes; maximum is {maximum}"
            ),
            Self::Encoding => formatter.write_str("could not encode authenticated storage record"),
            Self::InvalidEnvelope => formatter.write_str("invalid authenticated storage envelope"),
            Self::UnsupportedFormat(version) => {
                write!(formatter, "unsupported authenticated storage format: {version}")
            }
            Self::InvalidKeyId => formatter.write_str("invalid authenticated storage key ID"),
            Self::UnknownKeyId => formatter.write_str("unknown authenticated storage key ID"),
            Self::InvalidRevision => {
                formatter.write_str("authenticated storage record has an invalid revision")
            }
            Self::RevisionMismatch { backend, envelope } => write!(
                formatter,
                "storage revision mismatch: backend {backend}, envelope {envelope}"
            ),
            Self::InvalidAuthenticationTag => {
                formatter.write_str("invalid authenticated storage tag")
            }
            Self::RollbackDetected {
                record_revision,
                revision_floor,
            } => write!(
                formatter,
                "storage rollback detected: record revision {record_revision:?}, floor {revision_floor}"
            ),
            Self::RevisionFloorMismatch {
                record_revision,
                revision_floor,
            } => write!(
                formatter,
                "storage revision floor mismatch: record {record_revision}, floor {revision_floor}"
            ),
            Self::RevisionExhausted => formatter.write_str("storage revision is exhausted"),
            Self::WriteConflict {
                expected,
                actual,
                revision_floor,
            } => write!(
                formatter,
                "storage compare-and-swap conflict: expected {expected:?}, actual {actual:?}, floor {revision_floor}"
            ),
        }
    }
}

impl<E> std::error::Error for AuthenticatedStoreError<E> where E: std::error::Error + 'static {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredEnvelope {
    format_version: u8,
    key_id: String,
    revision: u64,
    payload: String,
    auth_tag: String,
}

/// Process-local implementation for tests and development only.
///
/// It demonstrates the atomic trait semantics but loses all state on process
/// exit, so it cannot protect a production workflow against restart or storage
/// rollback.
#[derive(Debug, Default)]
pub struct VolatileMemoryStore {
    records: BTreeMap<StorageRecordKey, StoredRecord>,
    revision_floors: BTreeMap<StorageRecordKey, u64>,
}

impl RollbackProtectedStore for VolatileMemoryStore {
    type Error = VolatileMemoryStoreError;

    fn load(&self, key: &StorageRecordKey) -> Result<StorageSnapshot, Self::Error> {
        Ok(StorageSnapshot::new(
            self.records.get(key).cloned(),
            self.revision_floors.get(key).copied().unwrap_or(0),
        ))
    }

    fn compare_and_swap(
        &mut self,
        key: &StorageRecordKey,
        expected_revision: Option<u64>,
        replacement: StoredRecord,
    ) -> Result<CompareAndSwapOutcome, Self::Error> {
        let actual_revision = self.records.get(key).map(StoredRecord::revision);
        let revision_floor = self.revision_floors.get(key).copied().unwrap_or(0);
        if actual_revision != expected_revision || actual_revision.unwrap_or(0) != revision_floor {
            return Ok(CompareAndSwapOutcome::Conflict {
                actual_revision,
                revision_floor,
            });
        }
        let expected_replacement_revision = expected_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(VolatileMemoryStoreError::RevisionExhausted)?;
        if replacement.revision != expected_replacement_revision {
            return Err(VolatileMemoryStoreError::InvalidReplacementRevision {
                expected: expected_replacement_revision,
                actual: replacement.revision,
            });
        }
        self.records.insert(key.clone(), replacement);
        self.revision_floors
            .insert(key.clone(), expected_replacement_revision);
        Ok(CompareAndSwapOutcome::Stored {
            revision_floor: expected_replacement_revision,
        })
    }
}

/// Errors specific to [`VolatileMemoryStore`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolatileMemoryStoreError {
    RevisionExhausted,
    InvalidReplacementRevision { expected: u64, actual: u64 },
}

impl Display for VolatileMemoryStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RevisionExhausted => formatter.write_str("storage revision is exhausted"),
            Self::InvalidReplacementRevision { expected, actual } => write!(
                formatter,
                "invalid replacement revision: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for VolatileMemoryStoreError {}

fn validate_revision_pair<E>(
    record_revision: Option<u64>,
    revision_floor: u64,
) -> Result<(), AuthenticatedStoreError<E>> {
    match record_revision {
        None if revision_floor == 0 => Ok(()),
        None => Err(AuthenticatedStoreError::RollbackDetected {
            record_revision: None,
            revision_floor,
        }),
        Some(0) => Err(AuthenticatedStoreError::InvalidRevision),
        Some(record_revision) if record_revision < revision_floor => {
            Err(AuthenticatedStoreError::RollbackDetected {
                record_revision: Some(record_revision),
                revision_floor,
            })
        }
        Some(record_revision) if record_revision > revision_floor => {
            Err(AuthenticatedStoreError::RevisionFloorMismatch {
                record_revision,
                revision_floor,
            })
        }
        Some(_) => Ok(()),
    }
}

fn authenticated_record_tag(
    key: &StorageKey,
    record_key: &StorageRecordKey,
    format_version: u8,
    key_id: &StorageKeyId,
    revision: u64,
    payload: &[u8],
) -> [u8; AUTHENTICATED_RECORD_TAG_BYTES] {
    let mut hasher = blake3::Hasher::new_keyed(&key.bytes);
    hasher.update(b"splash-storage-record-v1");
    hasher.update(&[format_version]);
    update_component(&mut hasher, record_key.namespace.as_bytes());
    update_component(&mut hasher, record_key.name.as_bytes());
    update_component(&mut hasher, key_id.as_str().as_bytes());
    hasher.update(&revision.to_be_bytes());
    update_component(&mut hasher, payload);
    *hasher.finalize().as_bytes()
}

fn update_component(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn encode_tag(tag: &[u8; AUTHENTICATED_RECORD_TAG_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(tag.len() * 2);
    for byte in tag {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_tag(value: &str) -> Option<[u8; AUTHENTICATED_RECORD_TAG_BYTES]> {
    if value.len() != AUTHENTICATED_RECORD_TAG_BYTES * 2 {
        return None;
    }
    let mut decoded = [0; AUTHENTICATED_RECORD_TAG_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn is_valid_token(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_key(name: &str) -> StorageRecordKey {
        StorageRecordKey::new("workflow-ledger", name).unwrap()
    }

    fn store() -> AuthenticatedStore<VolatileMemoryStore> {
        let key_id = StorageKeyId::new("storage-v1").unwrap();
        let key = StorageKey::from_bytes([7; STORAGE_KEY_BYTES]);
        AuthenticatedStore::new(
            VolatileMemoryStore::default(),
            StorageKeyring::new(key_id, key),
        )
    }

    #[test]
    fn writes_authenticated_records_with_compare_and_swap() {
        let mut store = store();
        let key = record_key("release-42");

        let created = store.create(&key, b"first payload").unwrap();
        assert_eq!(created.revision(), 1);
        assert_eq!(created.key_id().as_str(), "storage-v1");
        assert_eq!(created.payload(), b"first payload");
        assert_eq!(store.load(&key).unwrap(), Some(created.clone()),);

        assert!(matches!(
            store.replace(&key, 0, b"stale payload"),
            Err(AuthenticatedStoreError::WriteConflict {
                expected: Some(0),
                actual: Some(1),
                revision_floor: 1,
            })
        ));
        let replaced = store.replace(&key, 1, b"second payload").unwrap();
        assert_eq!(replaced.revision(), 2);
        assert_eq!(store.load(&key).unwrap(), Some(replaced));
    }

    #[test]
    fn rejects_tampering_and_record_transplants() {
        let mut store = store();
        let first_key = record_key("release-42");
        let second_key = record_key("release-43");
        store.create(&first_key, b"first payload").unwrap();
        store.create(&second_key, b"second payload").unwrap();

        let second_record = store.backend().records.get(&second_key).cloned().unwrap();
        store
            .backend_mut()
            .records
            .insert(first_key.clone(), second_record);
        assert!(matches!(
            store.load(&first_key),
            Err(AuthenticatedStoreError::InvalidAuthenticationTag)
        ));

        let mut first_record = store.backend().records.get(&first_key).cloned().unwrap();
        let mut envelope: serde_json::Value = serde_json::from_slice(&first_record.bytes).unwrap();
        envelope["payload"] = serde_json::json!("dGFtcGVyZWQ");
        first_record.bytes = serde_json::to_vec(&envelope).unwrap();
        store
            .backend_mut()
            .records
            .insert(first_key.clone(), first_record);
        assert!(matches!(
            store.load(&first_key),
            Err(AuthenticatedStoreError::InvalidAuthenticationTag)
        ));
    }

    #[test]
    fn rejects_a_record_rolled_back_below_its_trusted_floor() {
        let mut store = store();
        let key = record_key("release-42");
        store.create(&key, b"first payload").unwrap();
        let old_record = store.backend().records.get(&key).cloned().unwrap();
        store.replace(&key, 1, b"second payload").unwrap();

        store.backend_mut().records.insert(key.clone(), old_record);
        assert!(matches!(
            store.load(&key),
            Err(AuthenticatedStoreError::RollbackDetected {
                record_revision: Some(1),
                revision_floor: 2,
            })
        ));
    }

    #[test]
    fn rotation_reads_old_records_and_rewrites_with_the_active_key() {
        let mut store = store();
        let key = record_key("release-42");
        let original = store.create(&key, b"payload").unwrap();
        let old_key_id = original.key_id().clone();
        let new_key_id = StorageKeyId::new("storage-v2").unwrap();
        store
            .keyring_mut()
            .rotate_to(
                new_key_id.clone(),
                StorageKey::from_bytes([9; STORAGE_KEY_BYTES]),
            )
            .unwrap();

        assert_eq!(store.load(&key).unwrap(), Some(original.clone()));
        let rewritten = store
            .replace(&key, original.revision(), original.payload())
            .unwrap();
        assert_eq!(rewritten.revision(), 2);
        assert_eq!(rewritten.key_id(), &new_key_id);
        assert_eq!(store.load(&key).unwrap(), Some(rewritten));

        store.keyring_mut().retire(&old_key_id).unwrap();
    }

    #[test]
    fn enforces_payload_and_revision_floor_bounds() {
        let mut store = store();
        let key = record_key("release-42");
        assert!(matches!(
            store.create(&key, &[0; MAX_AUTHENTICATED_PAYLOAD_BYTES + 1]),
            Err(AuthenticatedStoreError::PayloadTooLarge {
                actual,
                maximum: MAX_AUTHENTICATED_PAYLOAD_BYTES,
            }) if actual == MAX_AUTHENTICATED_PAYLOAD_BYTES + 1
        ));

        store.create(&key, b"payload").unwrap();
        store.backend_mut().revision_floors.insert(key.clone(), 0);
        assert!(matches!(
            store.load(&key),
            Err(AuthenticatedStoreError::RevisionFloorMismatch {
                record_revision: 1,
                revision_floor: 0,
            })
        ));
    }

    #[test]
    fn rejects_invalid_storage_identifiers() {
        assert_eq!(
            StorageKeyId::new("Storage v1").unwrap_err(),
            StorageKeyIdError::Invalid
        );
        assert_eq!(
            StorageRecordKey::new("workflow-ledger", "release 42").unwrap_err(),
            StorageRecordKeyError::InvalidName
        );
    }
}
