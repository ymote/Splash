//! SQLite payload storage paired with a trusted rollback-protection anchor.
//!
//! SQLite supplies local transactional durability and multi-process writer
//! serialization. It does not prevent a database-file rollback. An
//! [`AnchoredSqliteStore`] therefore stores each payload version locally but
//! accepts it only when a host-provided [`RollbackAnchor`] has durably
//! committed the matching revision and content hash.

use std::fmt::{self, Display, Formatter};
use std::path::Path;
use std::time::Duration;

use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};

use crate::{
    CompareAndSwapOutcome, FencedRollbackProtectedStore, RollbackAnchor,
    RollbackAnchorCompareAndSwapOutcome, RollbackAnchorState, RollbackAnchorStateError,
    RollbackProtectedStore, StorageRecordKey, StorageSnapshot, StoredRecord,
    MAX_AUTHENTICATED_RECORD_BYTES, ROLLBACK_ANCHOR_COMMITMENT_BYTES,
};

/// Maximum time SQLite waits for another local process to finish a write.
pub const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum uncommitted candidate payloads retained for one key and revision.
pub const MAX_PENDING_SQLITE_CANDIDATES: usize = 16;
/// Maximum anchor-CAS retries for a monotonic fence transition.
pub const MAX_ANCHOR_CAS_RETRIES: usize = 8;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS splash_storage_versions (
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    revision BLOB NOT NULL CHECK(length(revision) = 8),
    commitment BLOB NOT NULL CHECK(length(commitment) = 32),
    record BLOB NOT NULL,
    PRIMARY KEY(namespace, name, revision, commitment)
) WITHOUT ROWID;
";

/// Local SQLite record storage protected by a host-owned [`RollbackAnchor`].
///
/// A successful write first commits an immutable local candidate row, then
/// atomically advances the anchor to that row's revision and commitment. If a
/// crash occurs before the anchor advance, the candidate is ignored on the
/// next load. If local storage is restored after a successful anchor advance,
/// the missing or mismatched committed row is rejected.
///
/// The anchor is the production trust boundary. This type is only
/// rollback-protected when `A` is backed by a real durable monotonic authority.
/// SQLite itself provides neither that authority nor confidential storage.
pub struct AnchoredSqliteStore<A> {
    connection: Connection,
    anchor: A,
}

/// One freshly reserved fence that authorizes local candidate recovery.
///
/// This value is opaque and single-use. It proves that
/// [`AnchoredSqliteStore::reserve_recovery_fence`] advanced the exact record's
/// durable fence before local candidates can be discarded.
pub struct AnchoredSqliteRecoveryFence {
    key: StorageRecordKey,
    fencing_token: u64,
}

enum PersistCandidateOutcome {
    Stored,
    AnchorChanged(RollbackAnchorState),
}

impl fmt::Debug for AnchoredSqliteRecoveryFence {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnchoredSqliteRecoveryFence")
            .field("key", &self.key)
            .field("fencing_token", &"[REDACTED]")
            .finish()
    }
}

impl<A> AnchoredSqliteStore<A> {
    /// Opens or creates a SQLite database with conservative durability
    /// settings and initializes the Splash schema.
    ///
    /// The path is interpreted as a filesystem path, not a SQLite URI. Hosts
    /// must keep its parent directory under their policy-controlled ownership.
    pub fn open(path: impl AsRef<Path>, anchor: A) -> Result<Self, rusqlite::Error> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(path, flags)?;
        Self::from_connection(connection, anchor)
    }

    /// Creates an in-memory store for tests and local development.
    ///
    /// An in-memory payload database cannot be a production durable backend,
    /// even when supplied with a production anchor.
    pub fn open_in_memory(anchor: A) -> Result<Self, rusqlite::Error> {
        Self::from_connection(Connection::open_in_memory()?, anchor)
    }

    /// Configures an existing SQLite connection for anchored Splash storage.
    ///
    /// This supports host-selected SQLite VFS implementations while retaining
    /// the schema and durability settings required by this adapter.
    pub fn from_connection(connection: Connection, anchor: A) -> Result<Self, rusqlite::Error> {
        connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(SCHEMA)?;
        Ok(Self { connection, anchor })
    }

    /// Returns the host-owned rollback anchor.
    pub fn anchor(&self) -> &A {
        &self.anchor
    }

    /// Returns the host-owned rollback anchor for maintenance or recovery.
    pub fn anchor_mut(&mut self) -> &mut A {
        &mut self.anchor
    }

    /// Consumes the store and returns its rollback anchor.
    pub fn into_anchor(self) -> A {
        self.anchor
    }
}

impl<A> fmt::Debug for AnchoredSqliteStore<A> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnchoredSqliteStore")
            .finish_non_exhaustive()
    }
}

impl<A> AnchoredSqliteStore<A>
where
    A: RollbackAnchor,
{
    fn load_anchor_state(
        &self,
        key: &StorageRecordKey,
    ) -> Result<RollbackAnchorState, AnchoredSqliteStoreError<A::Error>> {
        self.anchor
            .load(key)
            .map_err(AnchoredSqliteStoreError::Anchor)
    }

    fn checked_anchor_state(
        &self,
        key: &StorageRecordKey,
    ) -> Result<RollbackAnchorState, AnchoredSqliteStoreError<A::Error>> {
        let state = self.load_anchor_state(key)?;
        self.record_at_anchor(key, state)?;
        Ok(state)
    }

    fn record_at_anchor(
        &self,
        key: &StorageRecordKey,
        state: RollbackAnchorState,
    ) -> Result<Option<StoredRecord>, AnchoredSqliteStoreError<A::Error>> {
        let revision = state.revision_floor();
        let Some(commitment) = state.record_commitment() else {
            return Ok(None);
        };
        let revision_bytes = revision.to_be_bytes();
        // Guard the SQLite value before asking rusqlite to materialize it as a
        // Vec. The payload database can be restored or tampered with, while
        // the anchor commitment is public metadata rather than a size bound.
        let record_length: i64 = self
            .connection
            .query_row(
                "SELECT length(CAST(record AS BLOB)) FROM splash_storage_versions
                 WHERE namespace = ?1 AND name = ?2 AND revision = ?3 AND commitment = ?4",
                params![
                    key.namespace(),
                    key.name(),
                    revision_bytes.as_slice(),
                    commitment.as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(AnchoredSqliteStoreError::Sqlite)?
            .ok_or(AnchoredSqliteStoreError::AnchorRecordMissing { revision })?;
        let record_length = usize::try_from(record_length).unwrap_or(usize::MAX);
        if record_length > MAX_AUTHENTICATED_RECORD_BYTES {
            return Err(AnchoredSqliteStoreError::StoredRecordTooLarge {
                actual: record_length,
                maximum: MAX_AUTHENTICATED_RECORD_BYTES,
            });
        }
        // Repeat the byte-length predicate on the fetch. This fails closed if
        // an uncontrolled SQLite file changes after the preflight query.
        let bytes = self
            .connection
            .query_row(
                "SELECT CAST(record AS BLOB) FROM splash_storage_versions
                 WHERE namespace = ?1 AND name = ?2 AND revision = ?3 AND commitment = ?4
                   AND length(CAST(record AS BLOB)) <= ?5",
                params![
                    key.namespace(),
                    key.name(),
                    revision_bytes.as_slice(),
                    commitment.as_slice(),
                    MAX_AUTHENTICATED_RECORD_BYTES as i64,
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(AnchoredSqliteStoreError::Sqlite)?
            .ok_or(AnchoredSqliteStoreError::AnchorRecordMissing { revision })?;
        let record = StoredRecord::new(revision, bytes);
        if record_commitment(key, &record) != commitment {
            return Err(AnchoredSqliteStoreError::AnchorRecordCommitmentMismatch { revision });
        }
        Ok(Some(record))
    }

    fn expected_matches(state: RollbackAnchorState, expected_revision: Option<u64>) -> bool {
        match (state.revision_floor(), expected_revision) {
            (0, None) => true,
            (actual @ 1.., Some(expected)) => actual == expected,
            _ => false,
        }
    }

    fn conflict(state: RollbackAnchorState) -> CompareAndSwapOutcome {
        CompareAndSwapOutcome::Conflict {
            actual_revision: (state.revision_floor() != 0).then_some(state.revision_floor()),
            revision_floor: state.revision_floor(),
        }
    }

    fn validate_replacement(
        current: RollbackAnchorState,
        replacement: &StoredRecord,
    ) -> Result<(), AnchoredSqliteStoreError<A::Error>> {
        if replacement.bytes().len() > MAX_AUTHENTICATED_RECORD_BYTES {
            return Err(AnchoredSqliteStoreError::StoredRecordTooLarge {
                actual: replacement.bytes().len(),
                maximum: MAX_AUTHENTICATED_RECORD_BYTES,
            });
        }
        let expected = current
            .revision_floor()
            .checked_add(1)
            .ok_or(AnchoredSqliteStoreError::RevisionExhausted)?;
        if replacement.revision() != expected {
            return Err(AnchoredSqliteStoreError::InvalidReplacementRevision {
                expected,
                actual: replacement.revision(),
            });
        }
        Ok(())
    }

    fn persist_candidate(
        &mut self,
        key: &StorageRecordKey,
        current: RollbackAnchorState,
        replacement: &StoredRecord,
        commitment: [u8; ROLLBACK_ANCHOR_COMMITMENT_BYTES],
    ) -> Result<PersistCandidateOutcome, AnchoredSqliteStoreError<A::Error>> {
        let revision_bytes = replacement.revision().to_be_bytes();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AnchoredSqliteStoreError::Sqlite)?;
        // Recovery advances the anchor before acquiring this SQLite write
        // lock. Recheck while the lock is held so a superseded writer cannot
        // insert a new orphan after recovery has discarded old candidates.
        let actual = self
            .anchor
            .load(key)
            .map_err(AnchoredSqliteStoreError::Anchor)?;
        if actual != current {
            return Ok(PersistCandidateOutcome::AnchorChanged(actual));
        }
        prune_history(&transaction, key, current).map_err(AnchoredSqliteStoreError::Sqlite)?;
        let existing = transaction
            .query_row(
                "SELECT record FROM splash_storage_versions
                 WHERE namespace = ?1 AND name = ?2 AND revision = ?3 AND commitment = ?4",
                params![
                    key.namespace(),
                    key.name(),
                    revision_bytes.as_slice(),
                    commitment.as_slice(),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(AnchoredSqliteStoreError::Sqlite)?;
        if let Some(existing) = existing {
            if existing != replacement.bytes() {
                return Err(AnchoredSqliteStoreError::CandidateCommitmentCollision {
                    revision: replacement.revision(),
                });
            }
            transaction
                .commit()
                .map_err(AnchoredSqliteStoreError::Sqlite)?;
            return Ok(PersistCandidateOutcome::Stored);
        }
        let current_revision = current.revision_floor().to_be_bytes();
        let pending: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM splash_storage_versions
                 WHERE namespace = ?1 AND name = ?2 AND revision > ?3",
                params![key.namespace(), key.name(), current_revision.as_slice()],
                |row| row.get(0),
            )
            .map_err(AnchoredSqliteStoreError::Sqlite)?;
        if pending >= MAX_PENDING_SQLITE_CANDIDATES as i64 {
            return Err(AnchoredSqliteStoreError::PendingCandidateLimit {
                maximum: MAX_PENDING_SQLITE_CANDIDATES,
            });
        }
        transaction
            .execute(
                "INSERT INTO splash_storage_versions(namespace, name, revision, commitment, record)
                 VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    key.namespace(),
                    key.name(),
                    revision_bytes.as_slice(),
                    commitment.as_slice(),
                    replacement.bytes(),
                ],
            )
            .map_err(AnchoredSqliteStoreError::Sqlite)?;
        transaction
            .commit()
            .map_err(AnchoredSqliteStoreError::Sqlite)?;
        Ok(PersistCandidateOutcome::Stored)
    }

    fn advance_anchor(
        &mut self,
        key: &StorageRecordKey,
        current: RollbackAnchorState,
        next: RollbackAnchorState,
    ) -> Result<RollbackAnchorCompareAndSwapOutcome, AnchoredSqliteStoreError<A::Error>> {
        self.anchor
            .compare_and_swap(key, current, next)
            .map_err(AnchoredSqliteStoreError::Anchor)
    }

    /// Reserves a fresh fence for recovery of one record's local candidates.
    ///
    /// Stop new admissions for `key` before calling this method. The returned
    /// value is accepted exactly once by [`Self::discard_unanchored_candidates`]
    /// and prevents a writer admitted under an older fence from promoting a
    /// candidate while recovery removes it.
    pub fn reserve_recovery_fence(
        &mut self,
        key: &StorageRecordKey,
    ) -> Result<AnchoredSqliteRecoveryFence, AnchoredSqliteStoreError<A::Error>> {
        let fencing_token = FencedRollbackProtectedStore::reserve_fence(self, key)?;
        Ok(AnchoredSqliteRecoveryFence {
            key: key.clone(),
            fencing_token,
        })
    }

    /// Discards local candidate payloads that are not committed by the current
    /// rollback anchor.
    ///
    /// This is a recovery operation for a key that accumulated candidates after
    /// anchor failures. Stop new admissions for the key, then pass the opaque
    /// result from [`Self::reserve_recovery_fence`]. Its fresh fence prevents
    /// any older in-flight writer from advancing a candidate after this method
    /// deletes it. The method retains exactly the payload committed by the
    /// current anchor, if any.
    pub fn discard_unanchored_candidates(
        &mut self,
        recovery: AnchoredSqliteRecoveryFence,
    ) -> Result<usize, AnchoredSqliteStoreError<A::Error>> {
        let key = recovery.key;
        let current = self.checked_anchor_state(&key)?;
        if recovery.fencing_token != current.fencing_token() {
            return Err(AnchoredSqliteStoreError::FencingTokenRejected {
                current: current.fencing_token(),
                supplied: recovery.fencing_token,
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AnchoredSqliteStoreError::Sqlite)?;
        let deleted = discard_unanchored_candidates(&transaction, &key, current)
            .map_err(AnchoredSqliteStoreError::Sqlite)?;
        transaction
            .commit()
            .map_err(AnchoredSqliteStoreError::Sqlite)?;
        Ok(deleted)
    }

    fn compare_and_swap_under_fence(
        &mut self,
        key: &StorageRecordKey,
        expected_revision: Option<u64>,
        replacement: StoredRecord,
        fencing_token: Option<u64>,
    ) -> Result<CompareAndSwapOutcome, AnchoredSqliteStoreError<A::Error>> {
        let current = self.checked_anchor_state(key)?;
        match fencing_token {
            Some(fencing_token) => {
                if fencing_token == 0 {
                    return Err(AnchoredSqliteStoreError::InvalidFencingToken);
                }
                if fencing_token != current.fencing_token() {
                    return Err(AnchoredSqliteStoreError::FencingTokenRejected {
                        current: current.fencing_token(),
                        supplied: fencing_token,
                    });
                }
            }
            None if current.fencing_token() != 0 => {
                return Err(AnchoredSqliteStoreError::FencingRequired {
                    current: current.fencing_token(),
                });
            }
            None => {}
        }
        if !Self::expected_matches(current, expected_revision) {
            return Ok(Self::conflict(current));
        }
        Self::validate_replacement(current, &replacement)?;
        let commitment = record_commitment(key, &replacement);
        match self.persist_candidate(key, current, &replacement, commitment)? {
            PersistCandidateOutcome::Stored => {}
            PersistCandidateOutcome::AnchorChanged(actual) => {
                self.record_at_anchor(key, actual)?;
                match fencing_token {
                    Some(fencing_token) if fencing_token != actual.fencing_token() => {
                        return Err(AnchoredSqliteStoreError::FencingTokenRejected {
                            current: actual.fencing_token(),
                            supplied: fencing_token,
                        });
                    }
                    None if actual.fencing_token() != 0 => {
                        return Err(AnchoredSqliteStoreError::FencingRequired {
                            current: actual.fencing_token(),
                        });
                    }
                    _ => return Ok(Self::conflict(actual)),
                }
            }
        }
        let next = current
            .with_record_commitment(replacement.revision(), commitment)
            .map_err(AnchoredSqliteStoreError::InvalidAnchorState)?;
        match self.advance_anchor(key, current, next)? {
            RollbackAnchorCompareAndSwapOutcome::Stored => Ok(CompareAndSwapOutcome::Stored {
                revision_floor: replacement.revision(),
            }),
            RollbackAnchorCompareAndSwapOutcome::Conflict { actual } => {
                self.record_at_anchor(key, actual)?;
                if let Some(fencing_token) = fencing_token {
                    if fencing_token != actual.fencing_token() {
                        return Err(AnchoredSqliteStoreError::FencingTokenRejected {
                            current: actual.fencing_token(),
                            supplied: fencing_token,
                        });
                    }
                }
                Ok(Self::conflict(actual))
            }
        }
    }
}

impl<A> RollbackProtectedStore for AnchoredSqliteStore<A>
where
    A: RollbackAnchor,
{
    type Error = AnchoredSqliteStoreError<A::Error>;

    fn load(&self, key: &StorageRecordKey) -> Result<StorageSnapshot, Self::Error> {
        let state = self.load_anchor_state(key)?;
        let record = self.record_at_anchor(key, state)?;
        Ok(StorageSnapshot::new(record, state.revision_floor()))
    }

    fn compare_and_swap(
        &mut self,
        key: &StorageRecordKey,
        expected_revision: Option<u64>,
        replacement: StoredRecord,
    ) -> Result<CompareAndSwapOutcome, Self::Error> {
        self.compare_and_swap_under_fence(key, expected_revision, replacement, None)
    }
}

impl<A> FencedRollbackProtectedStore for AnchoredSqliteStore<A>
where
    A: RollbackAnchor,
{
    fn current_fence(&self, key: &StorageRecordKey) -> Result<u64, Self::Error> {
        Ok(self.load_anchor_state(key)?.fencing_token())
    }

    fn reserve_fence(&mut self, key: &StorageRecordKey) -> Result<u64, Self::Error> {
        for _ in 0..MAX_ANCHOR_CAS_RETRIES {
            let current = self.checked_anchor_state(key)?;
            let fencing_token = current
                .fencing_token()
                .checked_add(1)
                .ok_or(AnchoredSqliteStoreError::FencingTokenExhausted)?;
            let next = current.with_fencing_token(fencing_token);
            if matches!(
                self.advance_anchor(key, current, next)?,
                RollbackAnchorCompareAndSwapOutcome::Stored
            ) {
                return Ok(fencing_token);
            }
        }
        Err(AnchoredSqliteStoreError::AnchorContention)
    }

    fn establish_fence(
        &mut self,
        key: &StorageRecordKey,
        fencing_token: u64,
    ) -> Result<(), Self::Error> {
        if fencing_token == 0 {
            return Err(AnchoredSqliteStoreError::InvalidFencingToken);
        }
        for _ in 0..MAX_ANCHOR_CAS_RETRIES {
            let current = self.checked_anchor_state(key)?;
            if fencing_token < current.fencing_token() {
                return Err(AnchoredSqliteStoreError::FencingTokenRejected {
                    current: current.fencing_token(),
                    supplied: fencing_token,
                });
            }
            if fencing_token == current.fencing_token() {
                return Ok(());
            }
            let next = current.with_fencing_token(fencing_token);
            match self.advance_anchor(key, current, next)? {
                RollbackAnchorCompareAndSwapOutcome::Stored => return Ok(()),
                RollbackAnchorCompareAndSwapOutcome::Conflict { actual } => {
                    self.record_at_anchor(key, actual)?;
                    if fencing_token < actual.fencing_token() {
                        return Err(AnchoredSqliteStoreError::FencingTokenRejected {
                            current: actual.fencing_token(),
                            supplied: fencing_token,
                        });
                    }
                    if fencing_token == actual.fencing_token() {
                        return Ok(());
                    }
                }
            }
        }
        Err(AnchoredSqliteStoreError::AnchorContention)
    }

    fn compare_and_swap_fenced(
        &mut self,
        key: &StorageRecordKey,
        expected_revision: Option<u64>,
        replacement: StoredRecord,
        fencing_token: u64,
    ) -> Result<CompareAndSwapOutcome, Self::Error> {
        self.compare_and_swap_under_fence(key, expected_revision, replacement, Some(fencing_token))
    }
}

/// Error emitted by [`AnchoredSqliteStore`].
#[derive(Debug)]
pub enum AnchoredSqliteStoreError<E> {
    Anchor(E),
    Sqlite(rusqlite::Error),
    InvalidAnchorState(RollbackAnchorStateError),
    AnchorRecordMissing { revision: u64 },
    AnchorRecordCommitmentMismatch { revision: u64 },
    StoredRecordTooLarge { actual: usize, maximum: usize },
    RevisionExhausted,
    InvalidReplacementRevision { expected: u64, actual: u64 },
    FencingRequired { current: u64 },
    InvalidFencingToken,
    FencingTokenExhausted,
    FencingTokenRejected { current: u64, supplied: u64 },
    AnchorContention,
    PendingCandidateLimit { maximum: usize },
    CandidateCommitmentCollision { revision: u64 },
}

impl<E: Display> Display for AnchoredSqliteStoreError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anchor(error) => write!(formatter, "rollback anchor failure: {error}"),
            Self::Sqlite(error) => write!(formatter, "SQLite storage failure: {error}"),
            Self::InvalidAnchorState(error) => {
                write!(formatter, "invalid rollback anchor state: {error}")
            }
            Self::AnchorRecordMissing { revision } => write!(
                formatter,
                "SQLite payload for anchored revision {revision} is missing or was rolled back"
            ),
            Self::AnchorRecordCommitmentMismatch { revision } => write!(
                formatter,
                "SQLite payload for anchored revision {revision} does not match its commitment"
            ),
            Self::StoredRecordTooLarge { actual, maximum } => write!(
                formatter,
                "stored record exceeds SQLite adapter limit: {actual} bytes, maximum {maximum}"
            ),
            Self::RevisionExhausted => formatter.write_str("storage revision is exhausted"),
            Self::InvalidReplacementRevision { expected, actual } => write!(
                formatter,
                "invalid replacement revision: expected {expected}, got {actual}"
            ),
            Self::FencingRequired { current } => write!(
                formatter,
                "fenced storage record requires the current fencing token {current}"
            ),
            Self::InvalidFencingToken => formatter.write_str("fencing token must be nonzero"),
            Self::FencingTokenExhausted => formatter.write_str("fencing token space is exhausted"),
            Self::FencingTokenRejected { current, supplied } => write!(
                formatter,
                "stale fencing token: current {current}, supplied {supplied}"
            ),
            Self::AnchorContention => {
                formatter.write_str("rollback anchor remained contended after bounded retries")
            }
            Self::PendingCandidateLimit { maximum } => write!(
                formatter,
                "SQLite pending candidate limit reached: maximum {maximum}; reserve a fresh fence and discard unanchored candidates before retrying"
            ),
            Self::CandidateCommitmentCollision { revision } => write!(
                formatter,
                "SQLite candidate commitment collision at revision {revision}"
            ),
        }
    }
}

impl<E> std::error::Error for AnchoredSqliteStoreError<E> where E: std::error::Error + 'static {}

fn prune_history(
    transaction: &Transaction<'_>,
    key: &StorageRecordKey,
    current: RollbackAnchorState,
) -> Result<(), rusqlite::Error> {
    let revision = current.revision_floor();
    if revision == 0 {
        return Ok(());
    }
    let revision_bytes = revision.to_be_bytes();
    let Some(commitment) = current.record_commitment() else {
        return Ok(());
    };
    transaction.execute(
        "DELETE FROM splash_storage_versions
         WHERE namespace = ?1 AND name = ?2
           AND (revision < ?3 OR (revision = ?3 AND commitment <> ?4))",
        params![
            key.namespace(),
            key.name(),
            revision_bytes.as_slice(),
            commitment.as_slice(),
        ],
    )?;
    Ok(())
}

fn discard_unanchored_candidates(
    transaction: &Transaction<'_>,
    key: &StorageRecordKey,
    current: RollbackAnchorState,
) -> Result<usize, rusqlite::Error> {
    let revision = current.revision_floor();
    if revision == 0 {
        return transaction.execute(
            "DELETE FROM splash_storage_versions WHERE namespace = ?1 AND name = ?2",
            params![key.namespace(), key.name()],
        );
    }
    let revision_bytes = revision.to_be_bytes();
    let Some(commitment) = current.record_commitment() else {
        return Ok(0);
    };
    transaction.execute(
        "DELETE FROM splash_storage_versions
         WHERE namespace = ?1 AND name = ?2
           AND NOT (revision = ?3 AND commitment = ?4)",
        params![
            key.namespace(),
            key.name(),
            revision_bytes.as_slice(),
            commitment.as_slice(),
        ],
    )
}

fn record_commitment(
    key: &StorageRecordKey,
    record: &StoredRecord,
) -> [u8; ROLLBACK_ANCHOR_COMMITMENT_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"splash-storage/anchored-sqlite-record/v1");
    hash_field(&mut hasher, key.namespace().as_bytes());
    hash_field(&mut hasher, key.name().as_bytes());
    hasher.update(&record.revision().to_be_bytes());
    hash_field(&mut hasher, record.bytes());
    *hasher.finalize().as_bytes()
}

fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{
        RollbackAnchor, RollbackAnchorCompareAndSwapOutcome, StorageRecordKey,
        VolatileRollbackAnchor,
    };

    static NEXT_TEMP_DATABASE: AtomicU64 = AtomicU64::new(0);

    #[derive(Default)]
    struct ConflictOnceAnchor {
        states: BTreeMap<StorageRecordKey, RollbackAnchorState>,
        conflict_once: bool,
    }

    impl ConflictOnceAnchor {
        fn conflict_once() -> Self {
            Self {
                states: BTreeMap::new(),
                conflict_once: true,
            }
        }
    }

    impl RollbackAnchor for ConflictOnceAnchor {
        type Error = Infallible;

        fn load(&self, key: &StorageRecordKey) -> Result<RollbackAnchorState, Self::Error> {
            Ok(self
                .states
                .get(key)
                .copied()
                .unwrap_or_else(RollbackAnchorState::initial))
        }

        fn compare_and_swap(
            &mut self,
            key: &StorageRecordKey,
            expected: RollbackAnchorState,
            replacement: RollbackAnchorState,
        ) -> Result<RollbackAnchorCompareAndSwapOutcome, Self::Error> {
            let actual = self.load(key)?;
            if actual != expected {
                return Ok(RollbackAnchorCompareAndSwapOutcome::Conflict { actual });
            }
            if self.conflict_once {
                self.conflict_once = false;
                return Ok(RollbackAnchorCompareAndSwapOutcome::Conflict { actual });
            }
            self.states.insert(key.clone(), replacement);
            Ok(RollbackAnchorCompareAndSwapOutcome::Stored)
        }
    }

    #[derive(Default)]
    struct RejectRecordAdvanceAnchor {
        states: BTreeMap<StorageRecordKey, RollbackAnchorState>,
    }

    impl RollbackAnchor for RejectRecordAdvanceAnchor {
        type Error = Infallible;

        fn load(&self, key: &StorageRecordKey) -> Result<RollbackAnchorState, Self::Error> {
            Ok(self
                .states
                .get(key)
                .copied()
                .unwrap_or_else(RollbackAnchorState::initial))
        }

        fn compare_and_swap(
            &mut self,
            key: &StorageRecordKey,
            expected: RollbackAnchorState,
            replacement: RollbackAnchorState,
        ) -> Result<RollbackAnchorCompareAndSwapOutcome, Self::Error> {
            let actual = self.load(key)?;
            if actual != expected || replacement.revision_floor() > actual.revision_floor() {
                return Ok(RollbackAnchorCompareAndSwapOutcome::Conflict { actual });
            }
            self.states.insert(key.clone(), replacement);
            Ok(RollbackAnchorCompareAndSwapOutcome::Stored)
        }
    }

    fn key() -> StorageRecordKey {
        StorageRecordKey::new("workflow-ledger", "release-42").unwrap()
    }

    fn record(revision: u64, bytes: &[u8]) -> StoredRecord {
        StoredRecord::new(revision, bytes.to_vec())
    }

    fn in_memory_store() -> AnchoredSqliteStore<VolatileRollbackAnchor> {
        AnchoredSqliteStore::open_in_memory(VolatileRollbackAnchor::default()).unwrap()
    }

    fn temporary_database_path(test_name: &str) -> PathBuf {
        let sequence = NEXT_TEMP_DATABASE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "splash-storage-{test_name}-{}-{sequence}.sqlite",
            std::process::id()
        ));
        remove_database(&path);
        path
    }

    fn remove_database(path: &Path) {
        for suffix in ["", "-journal", "-shm", "-wal"] {
            let file_name = format!("{}{}", path.display(), suffix);
            let _ = fs::remove_file(file_name);
        }
    }

    #[test]
    fn persists_committed_payloads_across_a_sqlite_reopen() {
        let path = temporary_database_path("reopen");
        let key = key();
        let mut store =
            AnchoredSqliteStore::open(&path, VolatileRollbackAnchor::default()).unwrap();
        assert_eq!(
            store
                .compare_and_swap(&key, None, record(1, b"first payload"))
                .unwrap(),
            CompareAndSwapOutcome::Stored { revision_floor: 1 }
        );
        let anchor = store.into_anchor();

        let reopened = AnchoredSqliteStore::open(&path, anchor).unwrap();
        let snapshot = reopened.load(&key).unwrap();
        assert_eq!(snapshot.revision_floor(), 1);
        assert_eq!(snapshot.record().unwrap().bytes(), b"first payload");

        remove_database(&path);
    }

    #[test]
    fn rejects_a_sqlite_file_restored_below_the_anchor() {
        let path = temporary_database_path("rollback");
        let backup = path.with_extension("before-rollback.sqlite");
        let key = key();
        let mut store =
            AnchoredSqliteStore::open(&path, VolatileRollbackAnchor::default()).unwrap();
        store
            .compare_and_swap(&key, None, record(1, b"first payload"))
            .unwrap();
        let anchor = store.into_anchor();
        fs::copy(&path, &backup).unwrap();

        let mut store = AnchoredSqliteStore::open(&path, anchor).unwrap();
        store
            .compare_and_swap(&key, Some(1), record(2, b"second payload"))
            .unwrap();
        let anchor = store.into_anchor();
        fs::copy(&backup, &path).unwrap();

        let reopened = AnchoredSqliteStore::open(&path, anchor).unwrap();
        assert!(matches!(
            reopened.load(&key),
            Err(AnchoredSqliteStoreError::AnchorRecordMissing { revision: 2 })
        ));

        remove_database(&path);
        remove_database(&backup);
    }

    #[test]
    fn rejects_an_oversized_anchored_blob_before_materializing_it() {
        let mut store = in_memory_store();
        let key = key();
        store
            .compare_and_swap(&key, None, record(1, b"first payload"))
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE splash_storage_versions
                 SET record = zeroblob(?1)
                 WHERE namespace = ?2 AND name = ?3",
                params![
                    (MAX_AUTHENTICATED_RECORD_BYTES + 1) as i64,
                    key.namespace(),
                    key.name(),
                ],
            )
            .unwrap();

        assert!(matches!(
            store.load(&key),
            Err(AnchoredSqliteStoreError::StoredRecordTooLarge {
                actual,
                maximum: MAX_AUTHENTICATED_RECORD_BYTES,
            }) if actual == MAX_AUTHENTICATED_RECORD_BYTES + 1
        ));
    }

    #[test]
    fn ignores_an_unanchored_candidate_after_an_anchor_conflict() {
        let mut store =
            AnchoredSqliteStore::open_in_memory(ConflictOnceAnchor::conflict_once()).unwrap();
        let key = key();

        assert_eq!(
            store
                .compare_and_swap(&key, None, record(1, b"candidate"))
                .unwrap(),
            CompareAndSwapOutcome::Conflict {
                actual_revision: None,
                revision_floor: 0,
            }
        );
        assert_eq!(store.load(&key).unwrap().record(), None);
        assert_eq!(
            store
                .compare_and_swap(&key, None, record(1, b"candidate"))
                .unwrap(),
            CompareAndSwapOutcome::Stored { revision_floor: 1 }
        );
        assert_eq!(
            store.load(&key).unwrap().record().unwrap().bytes(),
            b"candidate"
        );
    }

    #[test]
    fn requires_none_to_create_an_absent_record() {
        let mut store = in_memory_store();
        let key = key();

        assert_eq!(
            store
                .compare_and_swap(&key, Some(0), record(1, b"invalid create expectation"))
                .unwrap(),
            CompareAndSwapOutcome::Conflict {
                actual_revision: None,
                revision_floor: 0,
            }
        );
    }

    #[test]
    fn discards_orphaned_candidates_after_a_fresh_recovery_fence() {
        let mut store =
            AnchoredSqliteStore::open_in_memory(RejectRecordAdvanceAnchor::default()).unwrap();
        let key = key();
        let first_fence = store.reserve_fence(&key).unwrap();
        assert_eq!(first_fence, 1);

        for candidate in 0..MAX_PENDING_SQLITE_CANDIDATES {
            let payload = format!("candidate-{candidate}");
            assert_eq!(
                store
                    .compare_and_swap_fenced(&key, None, record(1, payload.as_bytes()), first_fence)
                    .unwrap(),
                CompareAndSwapOutcome::Conflict {
                    actual_revision: None,
                    revision_floor: 0,
                }
            );
        }
        assert!(matches!(
            store.compare_and_swap_fenced(&key, None, record(1, b"over-limit"), first_fence),
            Err(AnchoredSqliteStoreError::PendingCandidateLimit {
                maximum: MAX_PENDING_SQLITE_CANDIDATES,
            })
        ));

        let recovery_fence = store.reserve_recovery_fence(&key).unwrap();
        assert_eq!(
            store.discard_unanchored_candidates(recovery_fence).unwrap(),
            MAX_PENDING_SQLITE_CANDIDATES
        );
        assert!(matches!(
            store.compare_and_swap_fenced(&key, None, record(1, b"stale writer"), first_fence),
            Err(AnchoredSqliteStoreError::FencingTokenRejected {
                current: 2,
                supplied: 1,
            })
        ));
        assert_eq!(
            store
                .compare_and_swap_fenced(&key, None, record(1, b"new candidate"), 2)
                .unwrap(),
            CompareAndSwapOutcome::Conflict {
                actual_revision: None,
                revision_floor: 0,
            }
        );
    }

    #[test]
    fn stale_writer_cannot_repopulate_candidates_after_recovery() {
        let mut store =
            AnchoredSqliteStore::open_in_memory(RejectRecordAdvanceAnchor::default()).unwrap();
        let key = key();
        let first_fence = store.reserve_fence(&key).unwrap();
        let stale_state = store.checked_anchor_state(&key).unwrap();
        assert_eq!(stale_state.fencing_token(), first_fence);

        let recovery = store.reserve_recovery_fence(&key).unwrap();
        assert_eq!(store.discard_unanchored_candidates(recovery).unwrap(), 0);

        let replacement = record(1, b"stale candidate");
        assert!(matches!(
            store
                .persist_candidate(
                    &key,
                    stale_state,
                    &replacement,
                    record_commitment(&key, &replacement),
                )
                .unwrap(),
            PersistCandidateOutcome::AnchorChanged(actual)
                if actual.fencing_token() == first_fence + 1
        ));
        let candidates: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM splash_storage_versions WHERE namespace = ?1 AND name = ?2",
                params![key.namespace(), key.name()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(candidates, 0);
    }

    #[test]
    fn preserves_compare_and_swap_and_fencing_semantics() {
        let mut store = in_memory_store();
        let key = key();
        let first_fence = store.reserve_fence(&key).unwrap();
        assert_eq!(first_fence, 1);
        assert!(matches!(
            store.compare_and_swap(&key, None, record(1, b"unfenced writer")),
            Err(AnchoredSqliteStoreError::FencingRequired { current: 1 })
        ));
        assert_eq!(
            store
                .compare_and_swap_fenced(&key, None, record(1, b"first payload"), first_fence)
                .unwrap(),
            CompareAndSwapOutcome::Stored { revision_floor: 1 }
        );
        assert_eq!(
            store
                .compare_and_swap_fenced(&key, None, record(2, b"stale payload"), first_fence)
                .unwrap(),
            CompareAndSwapOutcome::Conflict {
                actual_revision: Some(1),
                revision_floor: 1,
            }
        );

        let second_fence = store.reserve_fence(&key).unwrap();
        assert_eq!(second_fence, 2);
        assert!(matches!(
            store.compare_and_swap_fenced(&key, Some(1), record(2, b"stale writer"), first_fence,),
            Err(AnchoredSqliteStoreError::FencingTokenRejected {
                current: 2,
                supplied: 1,
            })
        ));
        assert_eq!(
            store
                .compare_and_swap_fenced(&key, Some(1), record(2, b"current writer"), second_fence,)
                .unwrap(),
            CompareAndSwapOutcome::Stored { revision_floor: 2 }
        );
    }
}
