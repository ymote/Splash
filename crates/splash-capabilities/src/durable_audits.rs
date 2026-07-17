//! Authenticated bounded persistence for capability audit telemetry.
//!
//! A [`crate::durable_audits::CapabilityAuditStore`] writes only validated
//! [`AuditEvent`] telemetry through [`splash_storage::AuthenticatedStore`]. It is
//! deliberately separate from [`crate::CapabilityRuntime`]: an unavailable
//! telemetry sink cannot change a capability decision, external operation,
//! cancellation, or adapter effect. Reading the journal is for operators and audit export only.

use std::collections::VecDeque;
use std::fmt::{self, Display, Formatter};
use std::num::{NonZeroU64, NonZeroUsize};

use serde::{Deserialize, Serialize};
use splash_storage::{
    AuthenticatedStore, AuthenticatedStoreError, RollbackProtectedStore, StorageRecordKey,
};

use crate::{
    is_valid_tool_name, AuditEvent, AuditEventBatch, AuditOutcome, RetryClass,
    CAPABILITY_AUDIT_JOURNAL_FORMAT_VERSION, MAX_DURABLE_CAPABILITY_AUDIT_EVENTS,
    MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES, MAX_DURABLE_CAPABILITY_AUDIT_STORE_RETRIES,
    UNRECOGNIZED_AUDIT_TOOL_PREFIX,
};

/// A host-selected identity for one contiguous capability-audit stream.
///
/// A new capability runtime starts its audit event sequence at one. Hosts must
/// choose a new stream ID unless they can also restore the runtime cursor, so
/// two independent histories cannot be confused in one durable record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CapabilityAuditStreamId(String);

impl CapabilityAuditStreamId {
    /// Creates a bounded non-secret host telemetry-stream identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, CapabilityAuditStreamIdError> {
        let value = value.into();
        if !is_valid_tool_name(&value) {
            return Err(CapabilityAuditStreamIdError::Invalid);
        }
        Ok(Self(value))
    }

    /// Returns the opaque host-selected stream identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), CapabilityAuditStreamIdError> {
        if is_valid_tool_name(&self.0) {
            Ok(())
        } else {
            Err(CapabilityAuditStreamIdError::Invalid)
        }
    }
}

impl Display for CapabilityAuditStreamId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Rejection for an invalid host capability-audit stream identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityAuditStreamIdError {
    Invalid,
}

impl Display for CapabilityAuditStreamIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("capability audit stream ID must be a bounded lowercase token")
    }
}

impl std::error::Error for CapabilityAuditStreamIdError {}

/// A bounded data-only journal that can be authenticated by a host storage
/// backend.
///
/// The journal stores no Splash source, tool input/output, stream chunks,
/// credentials, grants, approvals, worker keys, or VM promises. It never
/// grants a capability, recreates an operation, proves an effect, or resumes a
/// workflow.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityAuditJournal {
    format_version: u8,
    stream_id: CapabilityAuditStreamId,
    segment_start_event_sequence: u64,
    first_event_sequence: u64,
    next_event_sequence: u64,
    dropped_audit_events: u64,
    events: VecDeque<AuditEvent>,
}

impl CapabilityAuditJournal {
    /// Creates an empty journal for one host-selected capability-audit stream.
    pub fn new(stream_id: CapabilityAuditStreamId) -> Self {
        Self::new_from_event_sequence(stream_id, NonZeroU64::MIN)
    }

    /// Creates an empty journal for a host-defined source segment.
    ///
    /// Use this only with a fresh stream identity when source retention has
    /// already evicted earlier audit records. The segment-start cursor records
    /// that pre-existing source gap without presenting it as journal eviction.
    pub fn new_from_event_sequence(
        stream_id: CapabilityAuditStreamId,
        segment_start_event_sequence: NonZeroU64,
    ) -> Self {
        let segment_start_event_sequence = segment_start_event_sequence.get();
        Self {
            format_version: CAPABILITY_AUDIT_JOURNAL_FORMAT_VERSION,
            stream_id,
            segment_start_event_sequence,
            first_event_sequence: segment_start_event_sequence,
            next_event_sequence: segment_start_event_sequence,
            dropped_audit_events: 0,
            events: VecDeque::new(),
        }
    }

    /// Decodes a journal with the supplied host retention capacity.
    ///
    /// Decoding validates only bounded telemetry. It never authorizes a tool
    /// or treats a stored audit outcome as external-effect recovery evidence.
    pub fn from_json_with_capacity(
        document: &str,
        max_events: NonZeroUsize,
    ) -> Result<Self, CapabilityAuditJournalError> {
        validate_capacity(max_events)?;
        if document.len() > MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES {
            return Err(CapabilityAuditJournalError::TooLarge {
                actual: document.len(),
                maximum: MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES,
            });
        }
        let wire: CapabilityAuditJournalWire = serde_json::from_str(document)
            .map_err(|_| CapabilityAuditJournalError::InvalidEncoding)?;
        let journal = Self {
            format_version: wire.format_version,
            stream_id: CapabilityAuditStreamId::new(wire.stream_id)
                .map_err(CapabilityAuditJournalError::InvalidStreamId)?,
            segment_start_event_sequence: wire.segment_start_event_sequence,
            first_event_sequence: wire.first_event_sequence,
            next_event_sequence: wire.next_event_sequence,
            dropped_audit_events: wire.dropped_audit_events,
            events: wire.events.into_iter().map(Into::into).collect(),
        };
        journal.validate(max_events)?;
        Ok(journal)
    }

    /// Encodes the validated data-only journal for authenticated host storage.
    pub fn to_json(&self) -> Result<String, CapabilityAuditJournalError> {
        let encoded = serde_json::to_string(self)
            .map_err(|_| CapabilityAuditJournalError::SerializationFailed)?;
        if encoded.len() > MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES {
            return Err(CapabilityAuditJournalError::TooLarge {
                actual: encoded.len(),
                maximum: MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES,
            });
        }
        Ok(encoded)
    }

    /// Returns the immutable host-selected stream identity.
    pub fn stream_id(&self) -> &CapabilityAuditStreamId {
        &self.stream_id
    }

    /// Returns the first source cursor assigned to this durable segment.
    ///
    /// This can exceed one only when a fresh host stream begins after a known
    /// source-retention gap. It is not a capability identity or authority.
    pub const fn segment_start_event_sequence(&self) -> u64 {
        self.segment_start_event_sequence
    }

    /// Returns the earliest retained source audit event sequence.
    pub const fn first_event_sequence(&self) -> u64 {
        self.first_event_sequence
    }

    /// Returns the source cursor immediately after the latest observed event.
    pub const fn next_event_sequence(&self) -> u64 {
        self.next_event_sequence
    }

    /// Returns how many records journal retention evicted.
    pub const fn dropped_audit_events(&self) -> u64 {
        self.dropped_audit_events
    }

    /// Returns retained audit events in source order.
    pub fn events(&self) -> std::collections::vec_deque::Iter<'_, AuditEvent> {
        self.events.iter()
    }

    /// Appends a contiguous runtime-exported batch after checking duplicates
    /// and gaps before mutating the journal.
    ///
    /// Exact retained overlap replay is idempotent. A batch that begins before
    /// retained journal history is rejected because old records can no longer
    /// be compared safely.
    pub fn append_batch(
        &mut self,
        batch: &AuditEventBatch,
        max_events: NonZeroUsize,
    ) -> Result<usize, CapabilityAuditJournalError> {
        validate_capacity(max_events)?;
        validate_batch(batch).map_err(CapabilityAuditJournalError::InvalidBatch)?;
        if batch.is_empty() {
            return Err(CapabilityAuditJournalError::EmptyBatch);
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
        batch: &AuditEventBatch,
    ) -> Result<usize, CapabilityAuditJournalError> {
        let source_first = batch.first_event_sequence();
        if source_first > self.next_event_sequence {
            return Err(CapabilityAuditJournalError::SourceSequenceGap {
                expected: self.next_event_sequence,
                actual: source_first,
            });
        }
        if source_first < self.first_event_sequence {
            return Err(CapabilityAuditJournalError::ReplayBeforeRetention {
                supplied: source_first,
                first_retained: self.first_event_sequence,
            });
        }

        let overlap_end = batch.next_event_sequence().min(self.next_event_sequence);
        for event_sequence in source_first..overlap_end {
            let existing_index = usize::try_from(event_sequence - self.first_event_sequence)
                .map_err(|_| CapabilityAuditJournalError::InvalidSequence)?;
            let incoming_index = usize::try_from(event_sequence - source_first)
                .map_err(|_| CapabilityAuditJournalError::InvalidSequence)?;
            let existing = self
                .events
                .get(existing_index)
                .ok_or(CapabilityAuditJournalError::InvalidSequence)?;
            let incoming = batch
                .events()
                .get(incoming_index)
                .ok_or(CapabilityAuditJournalError::InvalidSequence)?;
            if existing != incoming {
                return Err(CapabilityAuditJournalError::OverlappingEventMismatch {
                    event_sequence,
                });
            }
        }

        if batch.next_event_sequence() <= self.next_event_sequence {
            return Ok(0);
        }

        let append_from = usize::try_from(self.next_event_sequence - source_first)
            .map_err(|_| CapabilityAuditJournalError::InvalidSequence)?;
        let events = batch
            .events()
            .get(append_from..)
            .ok_or(CapabilityAuditJournalError::InvalidSequence)?;
        self.events.extend(events.iter().cloned());
        self.next_event_sequence = batch.next_event_sequence();
        Ok(events.len())
    }

    fn trim_to_limits(
        &mut self,
        max_events: NonZeroUsize,
    ) -> Result<(), CapabilityAuditJournalError> {
        while self.events.len() > max_events.get()
            || self.encoded_len()? > MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES
        {
            if self.events.len() == 1 {
                return Err(CapabilityAuditJournalError::TooLarge {
                    actual: self.encoded_len()?,
                    maximum: MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES,
                });
            }
            self.events
                .pop_front()
                .ok_or(CapabilityAuditJournalError::InvalidSequence)?;
            self.first_event_sequence = self
                .first_event_sequence
                .checked_add(1)
                .ok_or(CapabilityAuditJournalError::InvalidSequence)?;
            self.dropped_audit_events = self
                .dropped_audit_events
                .checked_add(1)
                .ok_or(CapabilityAuditJournalError::InvalidSequence)?;
        }
        Ok(())
    }

    fn validate(&self, max_events: NonZeroUsize) -> Result<(), CapabilityAuditJournalError> {
        validate_capacity(max_events)?;
        if self.format_version != CAPABILITY_AUDIT_JOURNAL_FORMAT_VERSION {
            return Err(CapabilityAuditJournalError::UnsupportedFormatVersion {
                actual: self.format_version,
                expected: CAPABILITY_AUDIT_JOURNAL_FORMAT_VERSION,
            });
        }
        self.stream_id
            .validate()
            .map_err(CapabilityAuditJournalError::InvalidStreamId)?;
        if self.segment_start_event_sequence == 0
            || self.first_event_sequence == 0
            || self.next_event_sequence == 0
        {
            return Err(CapabilityAuditJournalError::InvalidSequence);
        }
        if self.first_event_sequence
            != self
                .segment_start_event_sequence
                .checked_add(self.dropped_audit_events)
                .ok_or(CapabilityAuditJournalError::InvalidSequence)?
        {
            return Err(CapabilityAuditJournalError::InvalidSequence);
        }
        if self.events.len() > max_events.get() {
            return Err(CapabilityAuditJournalError::TooManyEvents {
                actual: self.events.len(),
                maximum: max_events.get(),
            });
        }

        let mut expected = self.first_event_sequence;
        for event in &self.events {
            if expected == u64::MAX {
                return Err(CapabilityAuditJournalError::InvalidSequence);
            }
            if event.event_sequence != expected {
                return Err(CapabilityAuditJournalError::InvalidSequence);
            }
            validate_event(event).map_err(CapabilityAuditJournalError::InvalidEvent)?;
            expected = expected
                .checked_add(1)
                .ok_or(CapabilityAuditJournalError::InvalidSequence)?;
        }
        if expected != self.next_event_sequence {
            return Err(CapabilityAuditJournalError::InvalidSequence);
        }
        let encoded_len = self.encoded_len()?;
        if encoded_len > MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES {
            return Err(CapabilityAuditJournalError::TooLarge {
                actual: encoded_len,
                maximum: MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES,
            });
        }
        Ok(())
    }

    fn encoded_len(&self) -> Result<usize, CapabilityAuditJournalError> {
        serde_json::to_vec(self)
            .map(|encoded| encoded.len())
            .map_err(|_| CapabilityAuditJournalError::SerializationFailed)
    }
}

/// Private wire representation for untrusted durable journal input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityAuditJournalWire {
    format_version: u8,
    stream_id: String,
    segment_start_event_sequence: u64,
    first_event_sequence: u64,
    next_event_sequence: u64,
    dropped_audit_events: u64,
    events: VecDeque<CapabilityAuditEventWire>,
}

/// Private wire representation that keeps [`AuditEvent`] non-deserializable.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityAuditEventWire {
    event_sequence: u64,
    sequence: u64,
    tool: String,
    input_bytes: usize,
    output_bytes: usize,
    outcome: AuditOutcome,
    retry_class: Option<RetryClass>,
}

impl From<CapabilityAuditEventWire> for AuditEvent {
    fn from(wire: CapabilityAuditEventWire) -> Self {
        Self {
            event_sequence: wire.event_sequence,
            sequence: wire.sequence,
            tool: wire.tool,
            input_bytes: wire.input_bytes,
            output_bytes: wire.output_bytes,
            outcome: wire.outcome,
            retry_class: wire.retry_class,
        }
    }
}

fn validate_capacity(max_events: NonZeroUsize) -> Result<(), CapabilityAuditJournalError> {
    if max_events.get() > MAX_DURABLE_CAPABILITY_AUDIT_EVENTS {
        return Err(CapabilityAuditJournalError::CapacityTooLarge {
            requested: max_events.get(),
            maximum: MAX_DURABLE_CAPABILITY_AUDIT_EVENTS,
        });
    }
    Ok(())
}

fn validate_batch(batch: &AuditEventBatch) -> Result<(), CapabilityAuditBatchError> {
    if batch.next_event_sequence == 0 {
        return Err(CapabilityAuditBatchError::InvalidNextEventSequence);
    }
    let Some(first) = batch.events.first() else {
        return Ok(());
    };
    if first.event_sequence == 0 || first.event_sequence == u64::MAX {
        return Err(CapabilityAuditBatchError::InvalidEventSequence);
    }

    let mut expected = first.event_sequence;
    for event in &batch.events {
        if event.event_sequence != expected || event.event_sequence == u64::MAX {
            return Err(CapabilityAuditBatchError::NonContiguousEventSequence);
        }
        validate_event(event).map_err(CapabilityAuditBatchError::InvalidEvent)?;
        expected = expected
            .checked_add(1)
            .ok_or(CapabilityAuditBatchError::InvalidNextEventSequence)?;
    }
    if expected != batch.next_event_sequence {
        return Err(CapabilityAuditBatchError::InvalidNextEventSequence);
    }
    Ok(())
}

fn validate_event(event: &AuditEvent) -> Result<(), CapabilityAuditEventValidationError> {
    if event.event_sequence == 0 || event.event_sequence == u64::MAX {
        return Err(CapabilityAuditEventValidationError::InvalidEventSequence);
    }
    if !is_valid_audit_tool_label(&event.tool) {
        return Err(CapabilityAuditEventValidationError::InvalidTool);
    }
    match (event.outcome, event.retry_class) {
        (AuditOutcome::RetryScheduled, Some(_)) => {}
        (AuditOutcome::RetryScheduled, None) => {
            return Err(CapabilityAuditEventValidationError::RetryClassRequired)
        }
        (_, Some(_)) => return Err(CapabilityAuditEventValidationError::RetryClassUnexpected),
        (_, None) => {}
    }
    if !matches!(
        event.outcome,
        AuditOutcome::Allowed | AuditOutcome::Streamed
    ) && event.output_bytes != 0
    {
        return Err(CapabilityAuditEventValidationError::UnexpectedOutputBytes);
    }
    Ok(())
}

fn is_valid_audit_tool_label(value: &str) -> bool {
    if is_valid_tool_name(value) {
        return true;
    }
    let Some(digest) = value.strip_prefix(UNRECOGNIZED_AUDIT_TOOL_PREFIX) else {
        return false;
    };
    digest.len() == blake3::OUT_LEN * 2
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Invalid decoded or supplied capability-audit metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityAuditEventValidationError {
    InvalidEventSequence,
    InvalidTool,
    RetryClassRequired,
    RetryClassUnexpected,
    UnexpectedOutputBytes,
}

impl Display for CapabilityAuditEventValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEventSequence => {
                formatter.write_str("invalid capability audit event sequence")
            }
            Self::InvalidTool => formatter.write_str("invalid capability audit tool label"),
            Self::RetryClassRequired => {
                formatter.write_str("retry-scheduled capability audit event requires a retry class")
            }
            Self::RetryClassUnexpected => formatter
                .write_str("only retry-scheduled capability audit events may carry a retry class"),
            Self::UnexpectedOutputBytes => {
                formatter.write_str("capability audit outcome cannot carry output bytes")
            }
        }
    }
}

impl std::error::Error for CapabilityAuditEventValidationError {}

/// Invalid source ordering or metadata in an exported capability-audit batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityAuditBatchError {
    InvalidEventSequence,
    InvalidNextEventSequence,
    NonContiguousEventSequence,
    InvalidEvent(CapabilityAuditEventValidationError),
}

impl Display for CapabilityAuditBatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEventSequence => {
                formatter.write_str("invalid capability audit batch event sequence")
            }
            Self::InvalidNextEventSequence => {
                formatter.write_str("invalid capability audit batch next event sequence")
            }
            Self::NonContiguousEventSequence => {
                formatter.write_str("capability audit batch event sequences are not contiguous")
            }
            Self::InvalidEvent(error) => {
                write!(formatter, "invalid capability audit event: {error}")
            }
        }
    }
}

impl std::error::Error for CapabilityAuditBatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEvent(error) => Some(error),
            _ => None,
        }
    }
}

/// Rejection while decoding, extending, or encoding a durable capability-audit
/// journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityAuditJournalError {
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
    InvalidStreamId(CapabilityAuditStreamIdError),
    StreamMismatch {
        expected: CapabilityAuditStreamId,
        actual: CapabilityAuditStreamId,
    },
    SegmentStartMismatch {
        expected: u64,
        actual: u64,
    },
    InvalidSequence,
    EmptyBatch,
    InvalidBatch(CapabilityAuditBatchError),
    InvalidEvent(CapabilityAuditEventValidationError),
    SourceSequenceGap {
        expected: u64,
        actual: u64,
    },
    ReplayBeforeRetention {
        supplied: u64,
        first_retained: u64,
    },
    OverlappingEventMismatch {
        event_sequence: u64,
    },
}

impl Display for CapabilityAuditJournalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityTooLarge { requested, maximum } => write!(
                formatter,
                "durable capability audit capacity {requested} exceeds the hard limit of {maximum}"
            ),
            Self::TooManyEvents { actual, maximum } => write!(
                formatter,
                "durable capability audit journal has {actual} events; maximum is {maximum}"
            ),
            Self::TooLarge { actual, maximum } => write!(
                formatter,
                "durable capability audit journal is {actual} bytes; maximum is {maximum}"
            ),
            Self::InvalidEncoding => formatter.write_str("invalid durable capability audit journal"),
            Self::SerializationFailed => {
                formatter.write_str("durable capability audit journal could not be encoded")
            }
            Self::UnsupportedFormatVersion { actual, expected } => write!(
                formatter,
                "unsupported durable capability audit format {actual}; expected {expected}"
            ),
            Self::InvalidStreamId(error) => write!(formatter, "invalid capability audit stream ID: {error}"),
            Self::StreamMismatch { expected, actual } => write!(
                formatter,
                "capability audit journal stream {actual} does not match configured stream {expected}"
            ),
            Self::SegmentStartMismatch { expected, actual } => write!(
                formatter,
                "capability audit journal segment starts at {actual}, expected {expected}"
            ),
            Self::InvalidSequence => formatter.write_str("invalid durable capability audit sequence"),
            Self::EmptyBatch => formatter.write_str("durable capability audit batch is empty"),
            Self::InvalidBatch(error) => write!(formatter, "invalid capability audit batch: {error}"),
            Self::InvalidEvent(error) => write!(formatter, "invalid capability audit event: {error}"),
            Self::SourceSequenceGap { expected, actual } => write!(
                formatter,
                "capability audit source sequence gap: expected {expected}, got {actual}"
            ),
            Self::ReplayBeforeRetention {
                supplied,
                first_retained,
            } => write!(
                formatter,
                "capability audit replay starts at {supplied}, before retained sequence {first_retained}"
            ),
            Self::OverlappingEventMismatch { event_sequence } => write!(
                formatter,
                "capability audit replay does not match retained event sequence {event_sequence}"
            ),
        }
    }
}

impl std::error::Error for CapabilityAuditJournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidStreamId(error) => Some(error),
            Self::InvalidBatch(error) => Some(error),
            Self::InvalidEvent(error) => Some(error),
            _ => None,
        }
    }
}

/// Authenticated durable capability-audit journal storage.
///
/// The host owns the storage record key, stream identity, capacity, and
/// backend. A production backend must satisfy the rollback-protected storage
/// contract; [`splash_storage::VolatileMemoryStore`] is suitable only for
/// tests and local development.
pub struct CapabilityAuditStore<B> {
    storage: AuthenticatedStore<B>,
    record_key: StorageRecordKey,
    stream_id: CapabilityAuditStreamId,
    segment_start_event_sequence: NonZeroU64,
    max_events: NonZeroUsize,
}

impl<B> CapabilityAuditStore<B>
where
    B: RollbackProtectedStore,
{
    /// Creates a recorder with one host-owned authenticated storage slot.
    pub fn new(
        storage: AuthenticatedStore<B>,
        record_key: StorageRecordKey,
        stream_id: CapabilityAuditStreamId,
        max_events: NonZeroUsize,
    ) -> Result<Self, CapabilityAuditJournalError> {
        Self::new_from_event_sequence(storage, record_key, stream_id, NonZeroU64::MIN, max_events)
    }

    /// Creates a recorder for a fresh source segment that begins at a known
    /// nonzero source cursor.
    ///
    /// This is for a fresh host stream after an explicit audit-retention gap.
    /// Do not use it to skip records silently in an existing stream.
    pub fn new_from_event_sequence(
        storage: AuthenticatedStore<B>,
        record_key: StorageRecordKey,
        stream_id: CapabilityAuditStreamId,
        segment_start_event_sequence: NonZeroU64,
        max_events: NonZeroUsize,
    ) -> Result<Self, CapabilityAuditJournalError> {
        validate_capacity(max_events)?;
        Ok(Self {
            storage,
            record_key,
            stream_id,
            segment_start_event_sequence,
            max_events,
        })
    }

    /// Returns the host-selected record key for this telemetry stream.
    pub fn record_key(&self) -> &StorageRecordKey {
        &self.record_key
    }

    /// Returns the immutable telemetry stream identity.
    pub fn stream_id(&self) -> &CapabilityAuditStreamId {
        &self.stream_id
    }

    /// Returns the first source cursor configured for this durable segment.
    pub const fn segment_start_event_sequence(&self) -> u64 {
        self.segment_start_event_sequence.get()
    }

    /// Returns the configured maximum retained audit events.
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
    ) -> Result<Option<PersistedCapabilityAuditJournal>, CapabilityAuditStoreError<B::Error>> {
        let Some(record) = self
            .storage
            .load(&self.record_key)
            .map_err(CapabilityAuditStoreError::Storage)?
        else {
            return Ok(None);
        };
        let document = std::str::from_utf8(record.payload()).map_err(|_| {
            CapabilityAuditStoreError::Journal(CapabilityAuditJournalError::InvalidEncoding)
        })?;
        let journal = CapabilityAuditJournal::from_json_with_capacity(document, self.max_events)
            .map_err(CapabilityAuditStoreError::Journal)?;
        if journal.stream_id != self.stream_id {
            return Err(CapabilityAuditStoreError::Journal(
                CapabilityAuditJournalError::StreamMismatch {
                    expected: self.stream_id.clone(),
                    actual: journal.stream_id,
                },
            ));
        }
        if journal.segment_start_event_sequence != self.segment_start_event_sequence.get() {
            return Err(CapabilityAuditStoreError::Journal(
                CapabilityAuditJournalError::SegmentStartMismatch {
                    expected: self.segment_start_event_sequence.get(),
                    actual: journal.segment_start_event_sequence,
                },
            ));
        }
        Ok(Some(PersistedCapabilityAuditJournal {
            storage_revision: record.revision(),
            journal,
        }))
    }

    /// Appends one nonempty contiguous runtime-exported audit batch.
    ///
    /// Exact retained replay is idempotent. A final storage contention, source
    /// gap, or retention gap is an observability failure; it cannot decide a
    /// capability, external effect, workflow continuation, or compensation.
    pub fn append_batch(
        &mut self,
        batch: &AuditEventBatch,
    ) -> Result<PersistedCapabilityAuditJournal, CapabilityAuditStoreError<B::Error>> {
        if batch.is_empty() {
            return Err(CapabilityAuditStoreError::Journal(
                CapabilityAuditJournalError::EmptyBatch,
            ));
        }
        validate_batch(batch).map_err(|error| {
            CapabilityAuditStoreError::Journal(CapabilityAuditJournalError::InvalidBatch(error))
        })?;

        for attempt in 0..MAX_DURABLE_CAPABILITY_AUDIT_STORE_RETRIES {
            let existing = self.load()?;
            let (expected_revision, mut journal) = match existing {
                Some(existing) => (Some(existing.storage_revision), existing.journal),
                None => (
                    None,
                    CapabilityAuditJournal::new_from_event_sequence(
                        self.stream_id.clone(),
                        self.segment_start_event_sequence,
                    ),
                ),
            };
            let appended = journal
                .append_batch(batch, self.max_events)
                .map_err(CapabilityAuditStoreError::Journal)?;
            if appended == 0 {
                let Some(storage_revision) = expected_revision else {
                    return Err(CapabilityAuditStoreError::Journal(
                        CapabilityAuditJournalError::InvalidSequence,
                    ));
                };
                return Ok(PersistedCapabilityAuditJournal {
                    storage_revision,
                    journal,
                });
            }

            let payload = journal
                .to_json()
                .map_err(CapabilityAuditStoreError::Journal)?;
            let write = match expected_revision {
                Some(revision) => {
                    self.storage
                        .replace(&self.record_key, revision, payload.as_bytes())
                }
                None => self.storage.create(&self.record_key, payload.as_bytes()),
            };
            match write {
                Ok(record) => {
                    return Ok(PersistedCapabilityAuditJournal {
                        storage_revision: record.revision(),
                        journal,
                    });
                }
                Err(AuthenticatedStoreError::WriteConflict { .. })
                    if attempt + 1 < MAX_DURABLE_CAPABILITY_AUDIT_STORE_RETRIES =>
                {
                    continue;
                }
                Err(AuthenticatedStoreError::WriteConflict { .. }) => {
                    return Err(CapabilityAuditStoreError::Contended {
                        attempts: MAX_DURABLE_CAPABILITY_AUDIT_STORE_RETRIES,
                    });
                }
                Err(error) => return Err(CapabilityAuditStoreError::Storage(error)),
            }
        }

        Err(CapabilityAuditStoreError::Contended {
            attempts: MAX_DURABLE_CAPABILITY_AUDIT_STORE_RETRIES,
        })
    }
}

/// A journal paired with the authenticated storage revision that committed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCapabilityAuditJournal {
    storage_revision: u64,
    journal: CapabilityAuditJournal,
}

impl PersistedCapabilityAuditJournal {
    /// Returns the authenticated storage revision for this journal snapshot.
    pub const fn storage_revision(&self) -> u64 {
        self.storage_revision
    }

    /// Returns the validated data-only telemetry journal.
    pub fn journal(&self) -> &CapabilityAuditJournal {
        &self.journal
    }
}

/// Failure while loading or writing a capability-audit journal.
#[derive(Debug)]
pub enum CapabilityAuditStoreError<E> {
    Storage(AuthenticatedStoreError<E>),
    Journal(CapabilityAuditJournalError),
    Contended { attempts: usize },
}

impl<E: Display> Display for CapabilityAuditStoreError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "capability audit storage error: {error}"),
            Self::Journal(error) => write!(formatter, "capability audit journal error: {error}"),
            Self::Contended { attempts } => write!(
                formatter,
                "capability audit storage remained contended after {attempts} bounded attempts"
            ),
        }
    }
}

impl<E> std::error::Error for CapabilityAuditStoreError<E> where E: std::error::Error + 'static {}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU64, NonZeroUsize};

    use crate::{CapabilityRuntime, ToolPolicy, UNRECOGNIZED_AUDIT_TOOL_PREFIX};
    use splash_storage::{
        StorageKey, StorageKeyId, StorageKeyring, VolatileMemoryStore, STORAGE_KEY_BYTES,
    };

    use super::*;

    fn capacity() -> NonZeroUsize {
        NonZeroUsize::new(8).unwrap()
    }

    fn stream_id() -> CapabilityAuditStreamId {
        CapabilityAuditStreamId::new("release-42-attempt-1").unwrap()
    }

    fn event(event_sequence: u64, sequence: u64, outcome: AuditOutcome) -> AuditEvent {
        AuditEvent {
            event_sequence,
            sequence,
            tool: "text.echo".to_owned(),
            input_bytes: 5,
            output_bytes: if matches!(outcome, AuditOutcome::Allowed) {
                5
            } else {
                0
            },
            outcome,
            retry_class: matches!(outcome, AuditOutcome::RetryScheduled)
                .then_some(RetryClass::Transient),
        }
    }

    fn batch(events: Vec<AuditEvent>, next_event_sequence: u64) -> AuditEventBatch {
        AuditEventBatch {
            events,
            next_event_sequence,
        }
    }

    fn store() -> CapabilityAuditStore<VolatileMemoryStore> {
        store_from_event_sequence(NonZeroU64::MIN)
    }

    fn store_from_event_sequence(
        segment_start_event_sequence: NonZeroU64,
    ) -> CapabilityAuditStore<VolatileMemoryStore> {
        let storage = AuthenticatedStore::new(
            VolatileMemoryStore::default(),
            StorageKeyring::new(
                StorageKeyId::new("storage-v1").unwrap(),
                StorageKey::from_bytes([43; STORAGE_KEY_BYTES]),
            ),
        );
        CapabilityAuditStore::new_from_event_sequence(
            storage,
            StorageRecordKey::new("capability-audits", "release-42-attempt-1").unwrap(),
            stream_id(),
            segment_start_event_sequence,
            capacity(),
        )
        .unwrap()
    }

    #[test]
    fn journal_round_trips_without_sensitive_capability_data() {
        let mut journal = CapabilityAuditJournal::new(stream_id());
        journal
            .append_batch(
                &batch(
                    vec![
                        event(1, 0, AuditOutcome::Allowed),
                        event(2, 0, AuditOutcome::RetryScheduled),
                    ],
                    3,
                ),
                capacity(),
            )
            .unwrap();
        let encoded = journal.to_json().unwrap();
        assert!(!encoded.contains("private input"));
        assert!(!encoded.contains("secret-token"));
        let restored =
            CapabilityAuditJournal::from_json_with_capacity(&encoded, capacity()).unwrap();
        assert_eq!(restored, journal);
        assert_eq!(restored.first_event_sequence(), 1);
        assert_eq!(restored.next_event_sequence(), 3);
    }

    #[test]
    fn journal_requires_contiguous_sources_and_exact_overlaps() {
        let mut journal = CapabilityAuditJournal::new(stream_id());
        journal
            .append_batch(
                &batch(vec![event(1, 0, AuditOutcome::Allowed)], 2),
                capacity(),
            )
            .unwrap();

        assert_eq!(
            journal
                .append_batch(
                    &batch(vec![event(3, 1, AuditOutcome::Allowed)], 4),
                    capacity()
                )
                .unwrap_err(),
            CapabilityAuditJournalError::SourceSequenceGap {
                expected: 2,
                actual: 3,
            }
        );
        assert_eq!(
            journal
                .append_batch(
                    &batch(vec![event(1, 1, AuditOutcome::Allowed)], 2),
                    capacity()
                )
                .unwrap_err(),
            CapabilityAuditJournalError::OverlappingEventMismatch { event_sequence: 1 }
        );
        assert_eq!(
            journal
                .append_batch(
                    &batch(vec![event(1, 0, AuditOutcome::Allowed)], 2),
                    capacity()
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn journal_rejects_replay_that_predates_retention() {
        let small = NonZeroUsize::new(1).unwrap();
        let mut journal = CapabilityAuditJournal::new(stream_id());
        journal
            .append_batch(
                &batch(
                    vec![
                        event(1, 0, AuditOutcome::Allowed),
                        event(2, 1, AuditOutcome::Allowed),
                    ],
                    3,
                ),
                small,
            )
            .unwrap();
        assert_eq!(journal.first_event_sequence(), 2);
        assert_eq!(journal.dropped_audit_events(), 1);
        assert_eq!(
            journal
                .append_batch(&batch(vec![event(1, 0, AuditOutcome::Allowed)], 2), small)
                .unwrap_err(),
            CapabilityAuditJournalError::ReplayBeforeRetention {
                supplied: 1,
                first_retained: 2,
            }
        );
    }

    #[test]
    fn journal_records_a_fresh_source_segment_after_a_known_gap() {
        let start = NonZeroU64::new(7).unwrap();
        let mut journal = CapabilityAuditJournal::new_from_event_sequence(stream_id(), start);
        journal
            .append_batch(
                &batch(vec![event(7, 0, AuditOutcome::Allowed)], 8),
                capacity(),
            )
            .unwrap();

        assert_eq!(journal.segment_start_event_sequence(), 7);
        assert_eq!(journal.first_event_sequence(), 7);
        assert_eq!(journal.next_event_sequence(), 8);
        assert_eq!(journal.dropped_audit_events(), 0);
    }

    #[test]
    fn journal_rejects_inconsistent_audit_metadata_before_mutation() {
        let mut journal = CapabilityAuditJournal::new(stream_id());
        let invalid = AuditEvent {
            event_sequence: 1,
            sequence: 0,
            tool: "text.echo".to_owned(),
            input_bytes: 5,
            output_bytes: 1,
            outcome: AuditOutcome::Denied,
            retry_class: None,
        };
        assert_eq!(
            journal
                .append_batch(&batch(vec![invalid], 2), capacity())
                .unwrap_err(),
            CapabilityAuditJournalError::InvalidBatch(CapabilityAuditBatchError::InvalidEvent(
                CapabilityAuditEventValidationError::UnexpectedOutputBytes,
            ))
        );
        assert!(journal.events().next().is_none());
    }

    #[test]
    fn authenticated_store_persists_and_deduplicates_an_exact_batch() {
        let mut store = store();
        let events = batch(
            vec![
                event(1, 0, AuditOutcome::Allowed),
                event(2, 0, AuditOutcome::RetryScheduled),
            ],
            3,
        );
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
    fn authenticated_store_accepts_runtime_exported_audits() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        assert!(runtime
            .eval("use mod.tool\ntool.call(\"text.echo\", \"hello\")")
            .unwrap()
            .succeeded());
        assert!(runtime
            .eval(
                "use mod.tool\n\
                 try {\n\
                     tool.call(\"INVALID\", \"secret-token\")\n\
                 } catch {\n\
                     nil\n\
                 }",
            )
            .unwrap()
            .completed());

        let batch = runtime.audit_since(1).unwrap();
        assert_eq!(batch.events().len(), 2);
        assert!(batch.events()[1]
            .tool
            .starts_with(UNRECOGNIZED_AUDIT_TOOL_PREFIX));
        assert_eq!(batch.events()[1].input_bytes, "secret-token".len());
        assert_eq!(batch.events()[1].output_bytes, 0);

        let persisted = store().append_batch(&batch).unwrap();
        assert_eq!(persisted.journal().next_event_sequence(), 3);
        assert_eq!(persisted.journal().events().count(), 2);
        assert!(!persisted
            .journal()
            .to_json()
            .unwrap()
            .contains("secret-token"));
    }

    #[test]
    fn store_can_begin_a_fresh_segment_after_runtime_audit_eviction() {
        let mut policy = ToolPolicy::new("text.echo");
        policy.max_calls = 2;
        let mut runtime = CapabilityRuntime::default();
        runtime
            .set_max_audit_events(NonZeroUsize::new(1).unwrap())
            .unwrap();
        runtime
            .register_tool(policy, |request| Ok(request.input.clone()))
            .unwrap();
        for input in ["first", "second"] {
            assert!(runtime
                .eval(&format!(
                    "use mod.tool\ntool.call(\"text.echo\", \"{input}\")"
                ))
                .unwrap()
                .succeeded());
        }

        let batch = runtime.audit_since(2).unwrap();
        assert_eq!(batch.first_event_sequence(), 2);
        let mut store = store_from_event_sequence(NonZeroU64::new(2).unwrap());
        let persisted = store.append_batch(&batch).unwrap();
        assert_eq!(persisted.journal().segment_start_event_sequence(), 2);
        assert_eq!(persisted.journal().next_event_sequence(), 3);
        assert_eq!(store.load().unwrap().unwrap(), persisted);
    }

    #[test]
    fn storage_rejects_a_different_stream_identity() {
        let mut store = store();
        store
            .append_batch(&batch(vec![event(1, 0, AuditOutcome::Allowed)], 2))
            .unwrap();
        let storage = store.into_storage();
        let wrong = CapabilityAuditStore::new(
            storage,
            StorageRecordKey::new("capability-audits", "release-42-attempt-1").unwrap(),
            CapabilityAuditStreamId::new("release-42-attempt-2").unwrap(),
            capacity(),
        )
        .unwrap();
        assert!(matches!(
            wrong.load(),
            Err(CapabilityAuditStoreError::Journal(
                CapabilityAuditJournalError::StreamMismatch { .. }
            ))
        ));
    }

    #[test]
    fn storage_rejects_a_different_segment_start() {
        let mut store = store();
        store
            .append_batch(&batch(vec![event(1, 0, AuditOutcome::Allowed)], 2))
            .unwrap();
        let storage = store.into_storage();
        let wrong = CapabilityAuditStore::new_from_event_sequence(
            storage,
            StorageRecordKey::new("capability-audits", "release-42-attempt-1").unwrap(),
            stream_id(),
            NonZeroU64::new(2).unwrap(),
            capacity(),
        )
        .unwrap();
        assert!(matches!(
            wrong.load(),
            Err(CapabilityAuditStoreError::Journal(
                CapabilityAuditJournalError::SegmentStartMismatch {
                    expected: 2,
                    actual: 1,
                }
            ))
        ));
    }

    #[test]
    fn decoding_rejects_unbounded_or_invalid_audit_metadata() {
        let excessive_capacity =
            NonZeroUsize::new(MAX_DURABLE_CAPABILITY_AUDIT_EVENTS + 1).unwrap();
        assert!(matches!(
            CapabilityAuditJournal::from_json_with_capacity("{}", excessive_capacity),
            Err(CapabilityAuditJournalError::CapacityTooLarge { .. })
        ));

        let oversized = "x".repeat(MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES + 1);
        assert!(matches!(
            CapabilityAuditJournal::from_json_with_capacity(&oversized, capacity()),
            Err(CapabilityAuditJournalError::TooLarge { .. })
        ));

        let invalid = r#"{"format_version":1,"stream_id":"release-42","segment_start_event_sequence":1,"first_event_sequence":1,"next_event_sequence":2,"dropped_audit_events":0,"events":[{"event_sequence":1,"sequence":0,"tool":"BAD","input_bytes":1,"output_bytes":0,"outcome":"allowed"}]}"#;
        assert!(matches!(
            CapabilityAuditJournal::from_json_with_capacity(invalid, capacity()),
            Err(CapabilityAuditJournalError::InvalidEvent(
                CapabilityAuditEventValidationError::InvalidTool
            ))
        ));

        let invalid_retry = r#"{"format_version":1,"stream_id":"release-42","segment_start_event_sequence":1,"first_event_sequence":1,"next_event_sequence":2,"dropped_audit_events":0,"events":[{"event_sequence":1,"sequence":0,"tool":"text.echo","input_bytes":1,"output_bytes":0,"outcome":"allowed","retry_class":"transient"}]}"#;
        assert!(matches!(
            CapabilityAuditJournal::from_json_with_capacity(invalid_retry, capacity()),
            Err(CapabilityAuditJournalError::InvalidEvent(
                CapabilityAuditEventValidationError::RetryClassUnexpected
            ))
        ));

        let inconsistent_retention = r#"{"format_version":1,"stream_id":"release-42","segment_start_event_sequence":1,"first_event_sequence":2,"next_event_sequence":2,"dropped_audit_events":0,"events":[]}"#;
        assert!(matches!(
            CapabilityAuditJournal::from_json_with_capacity(inconsistent_retention, capacity()),
            Err(CapabilityAuditJournalError::InvalidSequence)
        ));

        let unknown_field = r#"{"format_version":1,"stream_id":"release-42","segment_start_event_sequence":1,"first_event_sequence":1,"next_event_sequence":1,"dropped_audit_events":0,"events":[],"unexpected":true}"#;
        assert!(matches!(
            CapabilityAuditJournal::from_json_with_capacity(unknown_field, capacity()),
            Err(CapabilityAuditJournalError::InvalidEncoding)
        ));
    }
}
