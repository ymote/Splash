//! Authenticated bounded telemetry persistence for workflow events.
//!
//! A [`crate::durable_events::WorkflowEventStore`] writes only validated [`WorkflowEvent`] telemetry
//! through [`splash_storage::AuthenticatedStore`]. It is deliberately separate
//! from [`crate::WorkflowEngine`]: an unavailable telemetry sink must not turn
//! a completed tool call or an external effect into a different execution
//! outcome. Event replay is for operators and audit export only. It cannot
//! recreate an approval, lease, suspended VM promise, worker session, or an
//! external effect.

use std::collections::VecDeque;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};
use splash_storage::{
    AuthenticatedStore, AuthenticatedStoreError, RollbackProtectedStore, StorageRecordKey,
};

use crate::{
    is_valid_operation_token, WorkflowEvent, WorkflowEventBatch, WorkflowEventBatchError,
    MAX_DURABLE_WORKFLOW_EVENTS, MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES,
    MAX_DURABLE_WORKFLOW_EVENT_STORE_RETRIES, WORKFLOW_EVENT_JOURNAL_FORMAT_VERSION,
};

/// A host-selected identity for one contiguous telemetry stream.
///
/// A process restart must use a fresh stream ID unless the host can also
/// restore the engine's source event cursor. This avoids confusing two
/// independent in-memory event histories that both begin at sequence one.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkflowEventStreamId(String);

impl WorkflowEventStreamId {
    /// Creates a bounded non-secret host telemetry-stream identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, WorkflowEventStreamIdError> {
        let value = value.into();
        if !is_valid_operation_token(&value) {
            return Err(WorkflowEventStreamIdError::Invalid);
        }
        Ok(Self(value))
    }

    /// Returns the opaque host-selected stream identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), WorkflowEventStreamIdError> {
        if is_valid_operation_token(&self.0) {
            Ok(())
        } else {
            Err(WorkflowEventStreamIdError::Invalid)
        }
    }
}

impl Display for WorkflowEventStreamId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Rejection for an invalid host telemetry-stream identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowEventStreamIdError {
    Invalid,
}

impl Display for WorkflowEventStreamIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("workflow event stream ID must be a bounded lowercase token")
    }
}

impl std::error::Error for WorkflowEventStreamIdError {}

/// A bounded, data-only telemetry journal that can be authenticated by a host
/// storage backend.
///
/// The journal stores no Splash source, tool input/output, secret, capability
/// grant, approval, worker session key, or runtime promise. `dropped_events`
/// describes retention eviction only. It never changes workflow authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkflowEventJournal {
    format_version: u8,
    stream_id: WorkflowEventStreamId,
    first_sequence: u64,
    next_sequence: u64,
    dropped_events: u64,
    events: VecDeque<WorkflowEvent>,
}

impl WorkflowEventJournal {
    /// Creates an empty journal for one host-selected stream.
    pub fn new(stream_id: WorkflowEventStreamId) -> Self {
        Self {
            format_version: WORKFLOW_EVENT_JOURNAL_FORMAT_VERSION,
            stream_id,
            first_sequence: 1,
            next_sequence: 1,
            dropped_events: 0,
            events: VecDeque::new(),
        }
    }

    /// Decodes a journal with the supplied host retention capacity.
    ///
    /// Decoding validates only bounded telemetry data. It does not authorize
    /// or resume a workflow.
    pub fn from_json_with_capacity(
        document: &str,
        max_events: NonZeroUsize,
    ) -> Result<Self, WorkflowEventJournalError> {
        validate_capacity(max_events)?;
        if document.len() > MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES {
            return Err(WorkflowEventJournalError::TooLarge {
                actual: document.len(),
                maximum: MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES,
            });
        }
        let wire: WorkflowEventJournalWire = serde_json::from_str(document)
            .map_err(|_| WorkflowEventJournalError::InvalidEncoding)?;
        let journal = Self {
            format_version: wire.format_version,
            stream_id: WorkflowEventStreamId::new(wire.stream_id)
                .map_err(WorkflowEventJournalError::InvalidStreamId)?,
            first_sequence: wire.first_sequence,
            next_sequence: wire.next_sequence,
            dropped_events: wire.dropped_events,
            events: wire.events,
        };
        journal.validate(max_events)?;
        Ok(journal)
    }

    /// Encodes the validated data-only journal for authenticated host storage.
    pub fn to_json(&self) -> Result<String, WorkflowEventJournalError> {
        let encoded = serde_json::to_string(self)
            .map_err(|_| WorkflowEventJournalError::SerializationFailed)?;
        if encoded.len() > MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES {
            return Err(WorkflowEventJournalError::TooLarge {
                actual: encoded.len(),
                maximum: MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES,
            });
        }
        Ok(encoded)
    }

    /// Returns the immutable host-selected stream identity.
    pub fn stream_id(&self) -> &WorkflowEventStreamId {
        &self.stream_id
    }

    /// Returns the earliest retained source event sequence.
    pub const fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    /// Returns the source cursor immediately after the latest observed event.
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Returns the number of events evicted from this journal's retention
    /// window.
    pub const fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Returns retained events in source order.
    pub fn events(&self) -> std::collections::vec_deque::Iter<'_, WorkflowEvent> {
        self.events.iter()
    }

    /// Appends a contiguous engine-exported batch, checking duplicates and
    /// gaps before mutating the journal.
    ///
    /// Replaying an exact retained overlap is idempotent. A batch that begins
    /// before the journal's retained range is rejected rather than duplicated,
    /// because its old events can no longer be compared safely.
    pub fn append_batch(
        &mut self,
        batch: &WorkflowEventBatch,
        max_events: NonZeroUsize,
    ) -> Result<usize, WorkflowEventJournalError> {
        validate_capacity(max_events)?;
        batch
            .validate()
            .map_err(WorkflowEventJournalError::InvalidBatch)?;
        if batch.is_empty() {
            return Err(WorkflowEventJournalError::EmptyBatch);
        }
        self.validate(max_events)?;

        let mut candidate = self.clone();
        let appended = candidate.append_batch_inner(batch)?;
        if appended == 0 {
            return Ok(0);
        }
        candidate.trim_to_limits(max_events)?;
        candidate.validate(max_events)?;
        *self = candidate;
        Ok(appended)
    }

    fn append_batch_inner(
        &mut self,
        batch: &WorkflowEventBatch,
    ) -> Result<usize, WorkflowEventJournalError> {
        let source_first = batch.first_sequence();
        if source_first > self.next_sequence {
            return Err(WorkflowEventJournalError::SourceSequenceGap {
                expected: self.next_sequence,
                actual: source_first,
            });
        }
        if source_first < self.first_sequence {
            return Err(WorkflowEventJournalError::ReplayBeforeRetention {
                supplied: source_first,
                first_retained: self.first_sequence,
            });
        }

        let overlap_end = batch.next_sequence().min(self.next_sequence);
        for sequence in source_first..overlap_end {
            let existing_index = usize::try_from(sequence - self.first_sequence)
                .map_err(|_| WorkflowEventJournalError::InvalidSequence)?;
            let incoming_index = usize::try_from(sequence - source_first)
                .map_err(|_| WorkflowEventJournalError::InvalidSequence)?;
            let existing = self
                .events
                .get(existing_index)
                .ok_or(WorkflowEventJournalError::InvalidSequence)?;
            let incoming = batch
                .records()
                .get(incoming_index)
                .ok_or(WorkflowEventJournalError::InvalidSequence)?;
            if existing != incoming.event() {
                return Err(WorkflowEventJournalError::OverlappingEventMismatch { sequence });
            }
        }

        if batch.next_sequence() <= self.next_sequence {
            return Ok(0);
        }

        let append_from = usize::try_from(self.next_sequence - source_first)
            .map_err(|_| WorkflowEventJournalError::InvalidSequence)?;
        let records = batch.records();
        let appended = records
            .get(append_from..)
            .ok_or(WorkflowEventJournalError::InvalidSequence)?;
        for record in appended {
            self.events.push_back(record.event().clone());
        }
        self.next_sequence = batch.next_sequence();
        Ok(appended.len())
    }

    fn trim_to_limits(
        &mut self,
        max_events: NonZeroUsize,
    ) -> Result<(), WorkflowEventJournalError> {
        while self.events.len() > max_events.get()
            || self.encoded_len()? > MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES
        {
            if self.events.len() == 1 {
                return Err(WorkflowEventJournalError::TooLarge {
                    actual: self.encoded_len()?,
                    maximum: MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES,
                });
            }
            self.events
                .pop_front()
                .ok_or(WorkflowEventJournalError::InvalidSequence)?;
            self.first_sequence = self.first_sequence.saturating_add(1);
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        Ok(())
    }

    fn validate(&self, max_events: NonZeroUsize) -> Result<(), WorkflowEventJournalError> {
        validate_capacity(max_events)?;
        if self.format_version != WORKFLOW_EVENT_JOURNAL_FORMAT_VERSION {
            return Err(WorkflowEventJournalError::UnsupportedFormatVersion {
                actual: self.format_version,
                expected: WORKFLOW_EVENT_JOURNAL_FORMAT_VERSION,
            });
        }
        self.stream_id
            .validate()
            .map_err(WorkflowEventJournalError::InvalidStreamId)?;
        if self.first_sequence == 0 || self.next_sequence == 0 {
            return Err(WorkflowEventJournalError::InvalidSequence);
        }
        if self.events.len() > max_events.get() {
            return Err(WorkflowEventJournalError::TooManyEvents {
                actual: self.events.len(),
                maximum: max_events.get(),
            });
        }

        let mut expected = self.first_sequence;
        for event in &self.events {
            if expected == u64::MAX {
                return Err(WorkflowEventJournalError::InvalidSequence);
            }
            event
                .validate_for_durable_replay()
                .map_err(WorkflowEventJournalError::InvalidEvent)?;
            expected = expected
                .checked_add(1)
                .ok_or(WorkflowEventJournalError::InvalidSequence)?;
        }
        if expected != self.next_sequence {
            return Err(WorkflowEventJournalError::InvalidSequence);
        }
        let encoded_len = self.encoded_len()?;
        if encoded_len > MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES {
            return Err(WorkflowEventJournalError::TooLarge {
                actual: encoded_len,
                maximum: MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES,
            });
        }
        Ok(())
    }

    fn encoded_len(&self) -> Result<usize, WorkflowEventJournalError> {
        serde_json::to_vec(self)
            .map(|encoded| encoded.len())
            .map_err(|_| WorkflowEventJournalError::SerializationFailed)
    }
}

/// Private wire representation used only by the bounded decoder.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowEventJournalWire {
    format_version: u8,
    stream_id: String,
    first_sequence: u64,
    next_sequence: u64,
    dropped_events: u64,
    events: VecDeque<WorkflowEvent>,
}

fn validate_capacity(max_events: NonZeroUsize) -> Result<(), WorkflowEventJournalError> {
    if max_events.get() > MAX_DURABLE_WORKFLOW_EVENTS {
        return Err(WorkflowEventJournalError::CapacityTooLarge {
            requested: max_events.get(),
            maximum: MAX_DURABLE_WORKFLOW_EVENTS,
        });
    }
    Ok(())
}

/// Rejection while decoding, extending, or encoding a durable event journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowEventJournalError {
    CapacityTooLarge {
        requested: usize,
        maximum: usize,
    },
    TooManyEvents {
        actual: usize,
        maximum: usize,
    },
    TooLarge {
        actual: usize,
        maximum: usize,
    },
    InvalidEncoding,
    SerializationFailed,
    UnsupportedFormatVersion {
        actual: u8,
        expected: u8,
    },
    InvalidStreamId(WorkflowEventStreamIdError),
    StreamMismatch {
        expected: WorkflowEventStreamId,
        actual: WorkflowEventStreamId,
    },
    InvalidSequence,
    EmptyBatch,
    InvalidBatch(WorkflowEventBatchError),
    InvalidEvent(crate::WorkflowEventValidationError),
    SourceSequenceGap {
        expected: u64,
        actual: u64,
    },
    ReplayBeforeRetention {
        supplied: u64,
        first_retained: u64,
    },
    OverlappingEventMismatch {
        sequence: u64,
    },
}

impl Display for WorkflowEventJournalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityTooLarge { requested, maximum } => write!(
                formatter,
                "durable workflow event capacity {requested} exceeds the hard limit of {maximum}"
            ),
            Self::TooManyEvents { actual, maximum } => write!(
                formatter,
                "durable workflow event journal has {actual} events; maximum is {maximum}"
            ),
            Self::TooLarge { actual, maximum } => write!(
                formatter,
                "durable workflow event journal is {actual} bytes; maximum is {maximum}"
            ),
            Self::InvalidEncoding => formatter.write_str("invalid durable workflow event journal"),
            Self::SerializationFailed => {
                formatter.write_str("durable workflow event journal could not be encoded")
            }
            Self::UnsupportedFormatVersion { actual, expected } => write!(
                formatter,
                "unsupported durable workflow event format {actual}; expected {expected}"
            ),
            Self::InvalidStreamId(error) => write!(formatter, "invalid workflow event stream ID: {error}"),
            Self::StreamMismatch { expected, actual } => write!(
                formatter,
                "workflow event journal stream {actual} does not match configured stream {expected}"
            ),
            Self::InvalidSequence => formatter.write_str("invalid durable workflow event sequence"),
            Self::EmptyBatch => formatter.write_str("durable workflow event batch is empty"),
            Self::InvalidBatch(error) => write!(formatter, "invalid workflow event batch: {error}"),
            Self::InvalidEvent(error) => write!(formatter, "invalid workflow event: {error}"),
            Self::SourceSequenceGap { expected, actual } => write!(
                formatter,
                "workflow event source sequence gap: expected {expected}, got {actual}"
            ),
            Self::ReplayBeforeRetention {
                supplied,
                first_retained,
            } => write!(
                formatter,
                "workflow event replay starts at {supplied}, before retained sequence {first_retained}"
            ),
            Self::OverlappingEventMismatch { sequence } => write!(
                formatter,
                "workflow event replay does not match retained event sequence {sequence}"
            ),
        }
    }
}

impl std::error::Error for WorkflowEventJournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidStreamId(error) => Some(error),
            Self::InvalidBatch(error) => Some(error),
            Self::InvalidEvent(error) => Some(error),
            _ => None,
        }
    }
}

/// Authenticated durable workflow-event journal storage.
///
/// The host owns the storage record key, event stream identity, capacity, and
/// backend. A production backend must satisfy the rollback-protected storage
/// contract; [`splash_storage::VolatileMemoryStore`] is suitable only for
/// tests and local development.
pub struct WorkflowEventStore<B> {
    storage: AuthenticatedStore<B>,
    record_key: StorageRecordKey,
    stream_id: WorkflowEventStreamId,
    max_events: NonZeroUsize,
}

impl<B> WorkflowEventStore<B>
where
    B: RollbackProtectedStore,
{
    /// Creates an event recorder with a host-owned authenticated storage slot.
    pub fn new(
        storage: AuthenticatedStore<B>,
        record_key: StorageRecordKey,
        stream_id: WorkflowEventStreamId,
        max_events: NonZeroUsize,
    ) -> Result<Self, WorkflowEventJournalError> {
        validate_capacity(max_events)?;
        Ok(Self {
            storage,
            record_key,
            stream_id,
            max_events,
        })
    }

    /// Returns the host-selected record key for this telemetry stream.
    pub fn record_key(&self) -> &StorageRecordKey {
        &self.record_key
    }

    /// Returns the immutable telemetry stream identity.
    pub fn stream_id(&self) -> &WorkflowEventStreamId {
        &self.stream_id
    }

    /// Returns the configured maximum retained events.
    pub const fn max_events(&self) -> usize {
        self.max_events.get()
    }

    /// Returns the authenticated storage wrapper for host maintenance.
    pub fn storage(&self) -> &AuthenticatedStore<B> {
        &self.storage
    }

    /// Returns the authenticated storage wrapper for host maintenance.
    pub fn storage_mut(&mut self) -> &mut AuthenticatedStore<B> {
        &mut self.storage
    }

    /// Consumes the recorder and returns its authenticated storage wrapper.
    pub fn into_storage(self) -> AuthenticatedStore<B> {
        self.storage
    }

    /// Loads the current journal after authenticating and validating it.
    pub fn load(
        &self,
    ) -> Result<Option<PersistedWorkflowEventJournal>, WorkflowEventStoreError<B::Error>> {
        let Some(record) = self
            .storage
            .load(&self.record_key)
            .map_err(WorkflowEventStoreError::Storage)?
        else {
            return Ok(None);
        };
        let document = std::str::from_utf8(record.payload()).map_err(|_| {
            WorkflowEventStoreError::Journal(WorkflowEventJournalError::InvalidEncoding)
        })?;
        let journal = WorkflowEventJournal::from_json_with_capacity(document, self.max_events)
            .map_err(WorkflowEventStoreError::Journal)?;
        if journal.stream_id != self.stream_id {
            return Err(WorkflowEventStoreError::Journal(
                WorkflowEventJournalError::StreamMismatch {
                    expected: self.stream_id.clone(),
                    actual: journal.stream_id,
                },
            ));
        }
        Ok(Some(PersistedWorkflowEventJournal {
            storage_revision: record.revision(),
            journal,
        }))
    }

    /// Appends one nonempty contiguous engine-exported batch.
    ///
    /// Exact retained replays are idempotent. The recorder retries optimistic
    /// storage conflicts only a bounded number of times; a host must treat a
    /// final contention or replay-gap error as an observability failure rather
    /// than using telemetry as an execution authority.
    pub fn append_batch(
        &mut self,
        batch: &WorkflowEventBatch,
    ) -> Result<PersistedWorkflowEventJournal, WorkflowEventStoreError<B::Error>> {
        if batch.is_empty() {
            return Err(WorkflowEventStoreError::Journal(
                WorkflowEventJournalError::EmptyBatch,
            ));
        }
        batch.validate().map_err(|error| {
            WorkflowEventStoreError::Journal(WorkflowEventJournalError::InvalidBatch(error))
        })?;

        for attempt in 0..MAX_DURABLE_WORKFLOW_EVENT_STORE_RETRIES {
            let existing = self.load()?;
            let (expected_revision, mut journal) = match existing {
                Some(existing) => (Some(existing.storage_revision), existing.journal),
                None => (None, WorkflowEventJournal::new(self.stream_id.clone())),
            };
            let appended = journal
                .append_batch(batch, self.max_events)
                .map_err(WorkflowEventStoreError::Journal)?;
            if appended == 0 {
                let Some(storage_revision) = expected_revision else {
                    return Err(WorkflowEventStoreError::Journal(
                        WorkflowEventJournalError::InvalidSequence,
                    ));
                };
                return Ok(PersistedWorkflowEventJournal {
                    storage_revision,
                    journal,
                });
            }

            let payload = journal
                .to_json()
                .map_err(WorkflowEventStoreError::Journal)?;
            let write = match expected_revision {
                Some(revision) => {
                    self.storage
                        .replace(&self.record_key, revision, payload.as_bytes())
                }
                None => self.storage.create(&self.record_key, payload.as_bytes()),
            };
            match write {
                Ok(record) => {
                    return Ok(PersistedWorkflowEventJournal {
                        storage_revision: record.revision(),
                        journal,
                    });
                }
                Err(AuthenticatedStoreError::WriteConflict { .. })
                    if attempt + 1 < MAX_DURABLE_WORKFLOW_EVENT_STORE_RETRIES =>
                {
                    continue;
                }
                Err(AuthenticatedStoreError::WriteConflict { .. }) => {
                    return Err(WorkflowEventStoreError::Contended {
                        attempts: MAX_DURABLE_WORKFLOW_EVENT_STORE_RETRIES,
                    });
                }
                Err(error) => return Err(WorkflowEventStoreError::Storage(error)),
            }
        }

        Err(WorkflowEventStoreError::Contended {
            attempts: MAX_DURABLE_WORKFLOW_EVENT_STORE_RETRIES,
        })
    }
}

/// A journal paired with the authenticated storage revision that committed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedWorkflowEventJournal {
    storage_revision: u64,
    journal: WorkflowEventJournal,
}

impl PersistedWorkflowEventJournal {
    /// Returns the authenticated storage revision for this journal snapshot.
    pub const fn storage_revision(&self) -> u64 {
        self.storage_revision
    }

    /// Returns the validated data-only telemetry journal.
    pub fn journal(&self) -> &WorkflowEventJournal {
        &self.journal
    }
}

/// Failure while loading or writing an authenticated workflow-event journal.
#[derive(Debug)]
pub enum WorkflowEventStoreError<E> {
    Storage(AuthenticatedStoreError<E>),
    Journal(WorkflowEventJournalError),
    Contended { attempts: usize },
}

impl<E: Display> Display for WorkflowEventStoreError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "workflow event storage error: {error}"),
            Self::Journal(error) => write!(formatter, "workflow event journal error: {error}"),
            Self::Contended { attempts } => write!(
                formatter,
                "workflow event storage remained contended after {attempts} bounded attempts"
            ),
        }
    }
}

impl<E> std::error::Error for WorkflowEventStoreError<E> where E: std::error::Error + 'static {}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use splash_storage::{
        StorageKey, StorageKeyId, StorageKeyring, VolatileMemoryStore, STORAGE_KEY_BYTES,
    };

    use super::*;
    use crate::{WorkflowEvent, WorkflowEventRecord};

    fn capacity() -> NonZeroUsize {
        NonZeroUsize::new(8).unwrap()
    }

    fn stream_id() -> WorkflowEventStreamId {
        WorkflowEventStreamId::new("release-42-attempt-1").unwrap()
    }

    fn event(sequence: u64, plan_id: u64) -> WorkflowEventRecord {
        WorkflowEventRecord::new(sequence, WorkflowEvent::Started { plan_id }).unwrap()
    }

    fn batch(records: Vec<WorkflowEventRecord>, next_sequence: u64) -> WorkflowEventBatch {
        WorkflowEventBatch::new(records, next_sequence).unwrap()
    }

    fn store() -> WorkflowEventStore<VolatileMemoryStore> {
        let storage = AuthenticatedStore::new(
            VolatileMemoryStore::default(),
            StorageKeyring::new(
                StorageKeyId::new("storage-v1").unwrap(),
                StorageKey::from_bytes([41; STORAGE_KEY_BYTES]),
            ),
        );
        WorkflowEventStore::new(
            storage,
            StorageRecordKey::new("workflow-events", "release-42-attempt-1").unwrap(),
            stream_id(),
            capacity(),
        )
        .unwrap()
    }

    #[test]
    fn journal_round_trips_without_sensitive_workflow_data() {
        let mut journal = WorkflowEventJournal::new(stream_id());
        journal
            .append_batch(&batch(vec![event(1, 1)], 2), capacity())
            .unwrap();
        let encoded = journal.to_json().unwrap();
        assert!(!encoded.contains("private input"));
        assert!(!encoded.contains("secret-token"));
        let restored = WorkflowEventJournal::from_json_with_capacity(&encoded, capacity()).unwrap();
        assert_eq!(restored, journal);
        assert_eq!(restored.first_sequence(), 1);
        assert_eq!(restored.next_sequence(), 2);
    }

    #[test]
    fn journal_requires_contiguous_sources_and_exact_overlaps() {
        let mut journal = WorkflowEventJournal::new(stream_id());
        journal
            .append_batch(&batch(vec![event(1, 1)], 2), capacity())
            .unwrap();

        assert_eq!(
            journal
                .append_batch(&batch(vec![event(3, 1)], 4), capacity())
                .unwrap_err(),
            WorkflowEventJournalError::SourceSequenceGap {
                expected: 2,
                actual: 3,
            }
        );
        assert_eq!(
            journal
                .append_batch(&batch(vec![event(1, 2)], 2), capacity())
                .unwrap_err(),
            WorkflowEventJournalError::OverlappingEventMismatch { sequence: 1 }
        );
        assert_eq!(
            journal
                .append_batch(&batch(vec![event(1, 1)], 2), capacity())
                .unwrap(),
            0
        );
    }

    #[test]
    fn journal_rejects_replay_that_predates_retention() {
        let small = NonZeroUsize::new(1).unwrap();
        let mut journal = WorkflowEventJournal::new(stream_id());
        journal
            .append_batch(&batch(vec![event(1, 1), event(2, 1)], 3), small)
            .unwrap();
        assert_eq!(journal.first_sequence(), 2);
        assert_eq!(journal.dropped_events(), 1);
        assert_eq!(
            journal
                .append_batch(&batch(vec![event(1, 1)], 2), small)
                .unwrap_err(),
            WorkflowEventJournalError::ReplayBeforeRetention {
                supplied: 1,
                first_retained: 2,
            }
        );
    }

    #[test]
    fn authenticated_store_persists_and_deduplicates_an_exact_batch() {
        let mut store = store();
        let events = batch(vec![event(1, 1), event(2, 1)], 3);
        let first = store.append_batch(&events).unwrap();
        assert_eq!(first.storage_revision(), 1);
        assert_eq!(first.journal().events().count(), 2);

        let replay = store.append_batch(&events).unwrap();
        assert_eq!(replay.storage_revision(), 1);
        assert_eq!(replay.journal(), first.journal());

        let restored = store.load().unwrap().unwrap();
        assert_eq!(restored, first);
    }

    #[test]
    fn storage_rejects_a_different_stream_identity() {
        let mut store = store();
        store.append_batch(&batch(vec![event(1, 1)], 2)).unwrap();
        let storage = store.into_storage();
        let wrong = WorkflowEventStore::new(
            storage,
            StorageRecordKey::new("workflow-events", "release-42-attempt-1").unwrap(),
            WorkflowEventStreamId::new("release-42-attempt-2").unwrap(),
            capacity(),
        )
        .unwrap();
        assert!(matches!(
            wrong.load(),
            Err(WorkflowEventStoreError::Journal(
                WorkflowEventJournalError::StreamMismatch { .. }
            ))
        ));
    }

    #[test]
    fn decoding_rejects_unbounded_or_invalid_event_metadata() {
        let oversized = "x".repeat(MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES + 1);
        assert!(matches!(
            WorkflowEventJournal::from_json_with_capacity(&oversized, capacity()),
            Err(WorkflowEventJournalError::TooLarge { .. })
        ));

        let invalid = r#"{"format_version":1,"stream_id":"release-42","first_sequence":1,"next_sequence":2,"dropped_events":0,"events":[{"type":"step_succeeded","plan_id":1,"step_id":"BAD"}]}"#;
        assert!(matches!(
            WorkflowEventJournal::from_json_with_capacity(invalid, capacity()),
            Err(WorkflowEventJournalError::InvalidEvent(_))
        ));
    }
}
