//! Authenticated bounded persistence for cross-stream telemetry.
//!
//! [`CrossStreamTelemetryStore`] accepts contiguous capability-audit and
//! workflow-event source batches and assigns a durable aggregate sequence in
//! host receipt order. It retains telemetry only: records cannot approve,
//! resume, retry, reconcile, compensate, or prove an effect.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};
use splash_capabilities::{
    AuditEvent, AuditEventBatch, AuditEventValidationError, AuditOutcome, RetryClass,
};
use splash_storage::{
    AuthenticatedStore, AuthenticatedStoreError, RollbackProtectedStore, StorageRecordKey,
};

use super::{
    CrossStreamTelemetryBatch, CrossStreamTelemetryCursorError, CrossStreamTelemetryEvent,
    CrossStreamTelemetryKind, CrossStreamTelemetryLog, CrossStreamTelemetryRecord,
    CrossStreamTelemetrySource, CrossStreamTelemetrySourceError, CrossStreamTelemetrySourceState,
    MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS, MAX_CROSS_STREAM_TELEMETRY_SOURCES,
};
use crate::{WorkflowEvent, WorkflowEventBatch, WorkflowEventValidationError};

/// Current durable cross-stream telemetry journal format.
pub const CROSS_STREAM_TELEMETRY_JOURNAL_FORMAT_VERSION: u8 = 1;
/// Maximum aggregate records retained by one durable cross-stream journal.
pub const MAX_DURABLE_CROSS_STREAM_TELEMETRY_EVENTS: usize = 1_024;
/// Maximum serialized bytes retained by one durable cross-stream journal.
pub const MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES: usize = 192 * 1024;
/// Bounded authenticated compare-and-swap attempts for one journal mutation.
pub const MAX_DURABLE_CROSS_STREAM_TELEMETRY_STORE_RETRIES: usize = 4;

/// A host-selected identity for one durable cross-stream telemetry journal.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CrossStreamTelemetryStreamId(String);

impl CrossStreamTelemetryStreamId {
    /// Creates a bounded non-secret aggregate stream identity.
    pub fn new(value: impl Into<String>) -> Result<Self, CrossStreamTelemetryStreamIdError> {
        let value = value.into();
        if !super::is_valid_source_id(&value) {
            return Err(CrossStreamTelemetryStreamIdError::Invalid);
        }
        Ok(Self(value))
    }

    /// Returns the opaque host-selected identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), CrossStreamTelemetryStreamIdError> {
        if super::is_valid_source_id(&self.0) {
            Ok(())
        } else {
            Err(CrossStreamTelemetryStreamIdError::Invalid)
        }
    }
}

impl Display for CrossStreamTelemetryStreamId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Rejection for an invalid durable aggregate stream identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossStreamTelemetryStreamIdError {
    Invalid,
}

impl Display for CrossStreamTelemetryStreamIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("cross-stream telemetry stream ID must be a bounded lowercase token")
    }
}

impl std::error::Error for CrossStreamTelemetryStreamIdError {}

/// A bounded data-only journal for host-receipt-order telemetry.
///
/// Source cursor state survives aggregate retention eviction, so a later
/// source batch must still be contiguous. The journal is not a checkpoint,
/// approval, capability lease, worker session, or operation ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossStreamTelemetryJournal {
    format_version: u8,
    stream_id: CrossStreamTelemetryStreamId,
    first_aggregate_sequence: u64,
    next_aggregate_sequence: u64,
    dropped_events: u64,
    sources: BTreeMap<CrossStreamTelemetrySource, CrossStreamTelemetrySourceState>,
    events: VecDeque<CrossStreamTelemetryRecord>,
}

impl CrossStreamTelemetryJournal {
    /// Creates an empty durable aggregate journal.
    pub fn new(stream_id: CrossStreamTelemetryStreamId) -> Self {
        Self {
            format_version: CROSS_STREAM_TELEMETRY_JOURNAL_FORMAT_VERSION,
            stream_id,
            first_aggregate_sequence: 1,
            next_aggregate_sequence: 1,
            dropped_events: 0,
            sources: BTreeMap::new(),
            events: VecDeque::new(),
        }
    }

    /// Decodes one bounded data-only journal from authenticated host storage.
    ///
    /// Decoding validates telemetry only. It never authorizes a capability or
    /// treats a historical record as effect-recovery evidence.
    pub fn from_json_with_capacity(
        document: &str,
        max_events: NonZeroUsize,
    ) -> Result<Self, CrossStreamTelemetryJournalError> {
        validate_capacity(max_events)?;
        if document.len() > MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES {
            return Err(CrossStreamTelemetryJournalError::TooLarge {
                actual: document.len(),
                maximum: MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES,
            });
        }
        let wire: CrossStreamTelemetryJournalDecodeWire = serde_json::from_str(document)
            .map_err(|_| CrossStreamTelemetryJournalError::InvalidEncoding)?;
        let journal = Self::try_from(wire)?;
        journal.validate(max_events)?;
        Ok(journal)
    }

    /// Encodes the validated telemetry journal for authenticated host storage.
    pub fn to_json(&self) -> Result<String, CrossStreamTelemetryJournalError> {
        let encoded = serde_json::to_string(&CrossStreamTelemetryJournalEncodeWire::from(self))
            .map_err(|_| CrossStreamTelemetryJournalError::SerializationFailed)?;
        if encoded.len() > MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES {
            return Err(CrossStreamTelemetryJournalError::TooLarge {
                actual: encoded.len(),
                maximum: MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES,
            });
        }
        Ok(encoded)
    }

    /// Returns the immutable host-selected aggregate stream identity.
    pub fn stream_id(&self) -> &CrossStreamTelemetryStreamId {
        &self.stream_id
    }

    /// Returns the earliest retained aggregate receipt cursor.
    pub const fn first_aggregate_sequence(&self) -> u64 {
        self.first_aggregate_sequence
    }

    /// Returns the aggregate cursor immediately after the newest observed
    /// record, including records evicted from retention.
    pub const fn next_aggregate_sequence(&self) -> u64 {
        self.next_aggregate_sequence
    }

    /// Returns how many aggregate records retention evicted.
    pub const fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Returns retained aggregate records in host receipt order.
    pub fn events(&self) -> CrossStreamTelemetryLog<'_> {
        CrossStreamTelemetryLog {
            entries: &self.events,
        }
    }

    /// Returns the number of persisted source segments.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Returns one persisted source segment's exact next cursor.
    pub fn source_state(
        &self,
        source: &CrossStreamTelemetrySource,
    ) -> Option<CrossStreamTelemetrySourceState> {
        self.sources.get(source).copied()
    }

    /// Exports retained aggregate records after a host-maintained cursor.
    ///
    /// An evicted cursor fails instead of yielding a partial timeline. The
    /// returned records remain telemetry only.
    pub fn events_since(
        &self,
        next_aggregate_sequence: u64,
    ) -> Result<CrossStreamTelemetryBatch, CrossStreamTelemetryCursorError> {
        if next_aggregate_sequence == 0 {
            return Err(CrossStreamTelemetryCursorError::InvalidCursor);
        }
        if next_aggregate_sequence < self.first_aggregate_sequence {
            return Err(CrossStreamTelemetryCursorError::Evicted {
                requested: next_aggregate_sequence,
                earliest_available: self.first_aggregate_sequence,
            });
        }
        if next_aggregate_sequence > self.next_aggregate_sequence {
            return Err(CrossStreamTelemetryCursorError::Ahead {
                requested: next_aggregate_sequence,
                next_available: self.next_aggregate_sequence,
            });
        }
        let skipped = usize::try_from(next_aggregate_sequence - self.first_aggregate_sequence)
            .map_err(|_| CrossStreamTelemetryCursorError::InvalidCursor)?;
        Ok(CrossStreamTelemetryBatch {
            records: self.events.iter().skip(skipped).cloned().collect(),
            next_aggregate_sequence: self.next_aggregate_sequence,
        })
    }

    /// Registers an ordinary source segment beginning at source cursor one.
    ///
    /// Persist this registration before ingesting a batch when a host needs a
    /// crash-safe explicit source segment boundary.
    pub fn register_source(
        &mut self,
        source: CrossStreamTelemetrySource,
        max_events: NonZeroUsize,
    ) -> Result<CrossStreamTelemetrySourceState, CrossStreamTelemetryJournalError> {
        self.register_source_at(source, 1, max_events)
    }

    /// Registers a fresh explicit source segment at one nonzero source cursor.
    ///
    /// Use this after a surfaced source-history gap, or when restoring an
    /// already-persisted source cursor before a new host process resumes
    /// ingestion. It cannot hide omitted source records.
    pub fn register_source_at(
        &mut self,
        source: CrossStreamTelemetrySource,
        next_source_sequence: u64,
        max_events: NonZeroUsize,
    ) -> Result<CrossStreamTelemetrySourceState, CrossStreamTelemetryJournalError> {
        validate_capacity(max_events)?;
        self.validate(max_events)?;
        let mut candidate = self.clone();
        let state = candidate.register_source_at_inner(source, next_source_sequence)?;
        candidate.validate(max_events)?;
        *self = candidate;
        Ok(state)
    }

    /// Ingests one contiguous capability-audit source batch and assigns new
    /// durable aggregate receipt cursors to its novel records.
    ///
    /// An exact retained source replay is idempotent. A source gap, a replay
    /// predating aggregate retention, or malformed metadata fails closed.
    pub fn ingest_audit_batch(
        &mut self,
        source: &CrossStreamTelemetrySource,
        batch: &AuditEventBatch,
        max_events: NonZeroUsize,
    ) -> Result<usize, CrossStreamTelemetryJournalError> {
        if source.kind() != CrossStreamTelemetryKind::CapabilityAudit {
            return Err(CrossStreamTelemetryJournalError::SourceKindMismatch {
                expected: CrossStreamTelemetryKind::CapabilityAudit,
                actual: source.kind(),
            });
        }
        if batch.is_empty() {
            return Err(CrossStreamTelemetryJournalError::EmptyBatch);
        }
        if batch.events().len() > MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS {
            return Err(CrossStreamTelemetryJournalError::BatchTooLarge {
                actual: batch.events().len(),
                maximum: MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS,
            });
        }
        let records = batch
            .events()
            .iter()
            .map(|event| {
                (
                    event.event_sequence,
                    CrossStreamTelemetryEvent::CapabilityAudit(event.clone()),
                )
            })
            .collect();
        self.ingest_source_records(
            source,
            batch.first_event_sequence(),
            batch.next_event_sequence(),
            records,
            max_events,
        )
    }

    /// Ingests one contiguous workflow-event source batch and assigns new
    /// durable aggregate receipt cursors to its novel records.
    pub fn ingest_workflow_batch(
        &mut self,
        source: &CrossStreamTelemetrySource,
        batch: &WorkflowEventBatch,
        max_events: NonZeroUsize,
    ) -> Result<usize, CrossStreamTelemetryJournalError> {
        if source.kind() != CrossStreamTelemetryKind::Workflow {
            return Err(CrossStreamTelemetryJournalError::SourceKindMismatch {
                expected: CrossStreamTelemetryKind::Workflow,
                actual: source.kind(),
            });
        }
        if batch.is_empty() {
            return Err(CrossStreamTelemetryJournalError::EmptyBatch);
        }
        if batch.records().len() > MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS {
            return Err(CrossStreamTelemetryJournalError::BatchTooLarge {
                actual: batch.records().len(),
                maximum: MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS,
            });
        }
        let records = batch
            .records()
            .iter()
            .map(|record| {
                (
                    record.sequence(),
                    CrossStreamTelemetryEvent::Workflow(record.event().clone()),
                )
            })
            .collect();
        self.ingest_source_records(
            source,
            batch.first_sequence(),
            batch.next_sequence(),
            records,
            max_events,
        )
    }

    fn ingest_source_records(
        &mut self,
        source: &CrossStreamTelemetrySource,
        first_source_sequence: u64,
        next_source_sequence: u64,
        records: Vec<(u64, CrossStreamTelemetryEvent)>,
        max_events: NonZeroUsize,
    ) -> Result<usize, CrossStreamTelemetryJournalError> {
        validate_capacity(max_events)?;
        validate_source_records(
            source,
            first_source_sequence,
            next_source_sequence,
            &records,
        )?;
        self.validate(max_events)?;

        let mut candidate = self.clone();
        let appended = candidate.append_source_records(
            source,
            first_source_sequence,
            next_source_sequence,
            &records,
        )?;
        if appended == 0 {
            return Ok(0);
        }
        candidate.trim_to_limits(max_events)?;
        candidate.validate(max_events)?;
        *self = candidate;
        Ok(appended)
    }

    fn register_source_at_inner(
        &mut self,
        source: CrossStreamTelemetrySource,
        next_source_sequence: u64,
    ) -> Result<CrossStreamTelemetrySourceState, CrossStreamTelemetryJournalError> {
        if next_source_sequence == 0 {
            return Err(CrossStreamTelemetryJournalError::InvalidSourceState);
        }
        if self.sources.contains_key(&source) {
            return Err(CrossStreamTelemetryJournalError::SourceAlreadyRegistered);
        }
        if self.sources.len() == MAX_CROSS_STREAM_TELEMETRY_SOURCES {
            return Err(CrossStreamTelemetryJournalError::TooManySources {
                maximum: MAX_CROSS_STREAM_TELEMETRY_SOURCES,
            });
        }
        let state = CrossStreamTelemetrySourceState {
            segment_start_sequence: next_source_sequence,
            next_source_sequence,
        };
        self.sources.insert(source, state);
        Ok(state)
    }

    fn append_source_records(
        &mut self,
        source: &CrossStreamTelemetrySource,
        first_source_sequence: u64,
        next_source_sequence: u64,
        records: &[(u64, CrossStreamTelemetryEvent)],
    ) -> Result<usize, CrossStreamTelemetryJournalError> {
        if !self.sources.contains_key(source) {
            if first_source_sequence != 1 {
                return Err(
                    CrossStreamTelemetryJournalError::SourceStartRequiresRegistration {
                        first_sequence: first_source_sequence,
                    },
                );
            }
            self.register_source_at_inner(source.clone(), 1)?;
        }

        let state = self
            .sources
            .get(source)
            .copied()
            .ok_or(CrossStreamTelemetryJournalError::MissingSourceState)?;
        if first_source_sequence > state.next_source_sequence {
            return Err(CrossStreamTelemetryJournalError::SourceSequenceGap {
                expected: state.next_source_sequence,
                actual: first_source_sequence,
            });
        }

        let retained: Vec<_> = self
            .events
            .iter()
            .filter(|record| record.source == *source)
            .cloned()
            .collect();
        if first_source_sequence < state.next_source_sequence {
            let Some(first_retained) = retained.first() else {
                return Err(CrossStreamTelemetryJournalError::ReplayBeforeRetention {
                    supplied: first_source_sequence,
                    first_retained: state.next_source_sequence,
                });
            };
            if first_source_sequence < first_retained.source_sequence {
                return Err(CrossStreamTelemetryJournalError::ReplayBeforeRetention {
                    supplied: first_source_sequence,
                    first_retained: first_retained.source_sequence,
                });
            }
            let overlap_end = next_source_sequence.min(state.next_source_sequence);
            for source_sequence in first_source_sequence..overlap_end {
                let existing_index =
                    usize::try_from(source_sequence - first_retained.source_sequence)
                        .map_err(|_| CrossStreamTelemetryJournalError::InvalidSourceBatch)?;
                let incoming_index = usize::try_from(source_sequence - first_source_sequence)
                    .map_err(|_| CrossStreamTelemetryJournalError::InvalidSourceBatch)?;
                let existing = retained
                    .get(existing_index)
                    .ok_or(CrossStreamTelemetryJournalError::InvalidSourceBatch)?;
                let incoming = records
                    .get(incoming_index)
                    .ok_or(CrossStreamTelemetryJournalError::InvalidSourceBatch)?;
                if existing.event != incoming.1 {
                    return Err(CrossStreamTelemetryJournalError::OverlappingEventMismatch {
                        source_sequence,
                    });
                }
            }
        }

        if next_source_sequence <= state.next_source_sequence {
            return Ok(0);
        }
        let append_from = usize::try_from(state.next_source_sequence - first_source_sequence)
            .map_err(|_| CrossStreamTelemetryJournalError::InvalidSourceBatch)?;
        let appended = records
            .get(append_from..)
            .ok_or(CrossStreamTelemetryJournalError::InvalidSourceBatch)?;
        for (source_sequence, event) in appended {
            self.record(source.clone(), *source_sequence, event.clone())?;
        }
        self.sources
            .get_mut(source)
            .ok_or(CrossStreamTelemetryJournalError::MissingSourceState)?
            .next_source_sequence = next_source_sequence;
        Ok(appended.len())
    }

    fn record(
        &mut self,
        source: CrossStreamTelemetrySource,
        source_sequence: u64,
        event: CrossStreamTelemetryEvent,
    ) -> Result<(), CrossStreamTelemetryJournalError> {
        if self.next_aggregate_sequence == u64::MAX {
            return Err(CrossStreamTelemetryJournalError::AggregateSequenceExhausted);
        }
        self.events.push_back(CrossStreamTelemetryRecord {
            aggregate_sequence: self.next_aggregate_sequence,
            source,
            source_sequence,
            event,
        });
        self.next_aggregate_sequence = self
            .next_aggregate_sequence
            .checked_add(1)
            .ok_or(CrossStreamTelemetryJournalError::AggregateSequenceExhausted)?;
        Ok(())
    }

    fn trim_to_limits(
        &mut self,
        max_events: NonZeroUsize,
    ) -> Result<(), CrossStreamTelemetryJournalError> {
        while self.events.len() > max_events.get() {
            self.evict_oldest()?;
        }
        while self.encoded_len()? > MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES {
            if self.events.len() == 1 {
                return Err(CrossStreamTelemetryJournalError::TooLarge {
                    actual: self.encoded_len()?,
                    maximum: MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES,
                });
            }
            self.evict_oldest()?;
        }
        Ok(())
    }

    fn evict_oldest(&mut self) -> Result<(), CrossStreamTelemetryJournalError> {
        self.events
            .pop_front()
            .ok_or(CrossStreamTelemetryJournalError::InvalidAggregateSequence)?;
        self.first_aggregate_sequence = self
            .first_aggregate_sequence
            .checked_add(1)
            .ok_or(CrossStreamTelemetryJournalError::InvalidAggregateSequence)?;
        self.dropped_events = self
            .dropped_events
            .checked_add(1)
            .ok_or(CrossStreamTelemetryJournalError::InvalidAggregateSequence)?;
        Ok(())
    }

    fn validate(&self, max_events: NonZeroUsize) -> Result<(), CrossStreamTelemetryJournalError> {
        validate_capacity(max_events)?;
        if self.format_version != CROSS_STREAM_TELEMETRY_JOURNAL_FORMAT_VERSION {
            return Err(CrossStreamTelemetryJournalError::UnsupportedFormatVersion {
                actual: self.format_version,
                expected: CROSS_STREAM_TELEMETRY_JOURNAL_FORMAT_VERSION,
            });
        }
        self.stream_id
            .validate()
            .map_err(CrossStreamTelemetryJournalError::InvalidStreamId)?;
        if self.first_aggregate_sequence == 0 || self.next_aggregate_sequence == 0 {
            return Err(CrossStreamTelemetryJournalError::InvalidAggregateSequence);
        }
        if self.first_aggregate_sequence
            != self
                .dropped_events
                .checked_add(1)
                .ok_or(CrossStreamTelemetryJournalError::InvalidAggregateSequence)?
        {
            return Err(CrossStreamTelemetryJournalError::InvalidAggregateSequence);
        }
        if self.sources.len() > MAX_CROSS_STREAM_TELEMETRY_SOURCES {
            return Err(CrossStreamTelemetryJournalError::TooManySources {
                maximum: MAX_CROSS_STREAM_TELEMETRY_SOURCES,
            });
        }
        if self.events.len() > max_events.get() {
            return Err(CrossStreamTelemetryJournalError::TooManyEvents {
                actual: self.events.len(),
                maximum: max_events.get(),
            });
        }

        for state in self.sources.values() {
            if state.segment_start_sequence == 0
                || state.next_source_sequence == 0
                || state.segment_start_sequence > state.next_source_sequence
            {
                return Err(CrossStreamTelemetryJournalError::InvalidSourceState);
            }
        }

        let mut expected_aggregate_sequence = self.first_aggregate_sequence;
        let mut last_source_sequence = BTreeMap::new();
        let mut retained_events_by_source = BTreeMap::new();
        for record in &self.events {
            validate_record(record)?;
            if record.aggregate_sequence != expected_aggregate_sequence
                || record.aggregate_sequence == u64::MAX
            {
                return Err(CrossStreamTelemetryJournalError::InvalidAggregateSequence);
            }
            let state = self
                .sources
                .get(&record.source)
                .ok_or(CrossStreamTelemetryJournalError::MissingSourceState)?;
            if record.source_sequence < state.segment_start_sequence
                || record.source_sequence >= state.next_source_sequence
            {
                return Err(CrossStreamTelemetryJournalError::InvalidSourceState);
            }
            if let Some(previous) =
                last_source_sequence.insert(record.source.clone(), record.source_sequence)
            {
                let expected = previous
                    .checked_add(1)
                    .ok_or(CrossStreamTelemetryJournalError::InvalidSourceState)?;
                if record.source_sequence != expected {
                    return Err(CrossStreamTelemetryJournalError::InvalidSourceState);
                }
            }
            let retained_count = retained_events_by_source
                .entry(record.source.clone())
                .or_insert(0_u64);
            *retained_count = retained_count
                .checked_add(1)
                .ok_or(CrossStreamTelemetryJournalError::InvalidSourceState)?;
            expected_aggregate_sequence = expected_aggregate_sequence
                .checked_add(1)
                .ok_or(CrossStreamTelemetryJournalError::InvalidAggregateSequence)?;
        }
        if expected_aggregate_sequence != self.next_aggregate_sequence {
            return Err(CrossStreamTelemetryJournalError::InvalidAggregateSequence);
        }
        for (source, last) in last_source_sequence {
            let expected = last
                .checked_add(1)
                .ok_or(CrossStreamTelemetryJournalError::InvalidSourceState)?;
            if self
                .sources
                .get(&source)
                .ok_or(CrossStreamTelemetryJournalError::MissingSourceState)?
                .next_source_sequence
                != expected
            {
                return Err(CrossStreamTelemetryJournalError::InvalidSourceState);
            }
        }
        let mut evicted_source_events = 0_u64;
        for (source, state) in &self.sources {
            let observed = state
                .next_source_sequence
                .checked_sub(state.segment_start_sequence)
                .ok_or(CrossStreamTelemetryJournalError::InvalidSourceState)?;
            let retained = retained_events_by_source.get(source).copied().unwrap_or(0);
            let evicted = observed
                .checked_sub(retained)
                .ok_or(CrossStreamTelemetryJournalError::InvalidSourceState)?;
            evicted_source_events = evicted_source_events
                .checked_add(evicted)
                .ok_or(CrossStreamTelemetryJournalError::InvalidSourceState)?;
        }
        if evicted_source_events != self.dropped_events {
            return Err(CrossStreamTelemetryJournalError::InvalidSourceState);
        }
        if self.encoded_len()? > MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES {
            return Err(CrossStreamTelemetryJournalError::TooLarge {
                actual: self.encoded_len()?,
                maximum: MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES,
            });
        }
        Ok(())
    }

    fn encoded_len(&self) -> Result<usize, CrossStreamTelemetryJournalError> {
        serde_json::to_vec(&CrossStreamTelemetryJournalEncodeWire::from(self))
            .map(|encoded| encoded.len())
            .map_err(|_| CrossStreamTelemetryJournalError::SerializationFailed)
    }
}

fn validate_capacity(max_events: NonZeroUsize) -> Result<(), CrossStreamTelemetryJournalError> {
    if max_events.get() > MAX_DURABLE_CROSS_STREAM_TELEMETRY_EVENTS {
        return Err(CrossStreamTelemetryJournalError::CapacityTooLarge {
            requested: max_events.get(),
            maximum: MAX_DURABLE_CROSS_STREAM_TELEMETRY_EVENTS,
        });
    }
    Ok(())
}

fn validate_source_records(
    source: &CrossStreamTelemetrySource,
    first_source_sequence: u64,
    next_source_sequence: u64,
    records: &[(u64, CrossStreamTelemetryEvent)],
) -> Result<(), CrossStreamTelemetryJournalError> {
    if records.is_empty()
        || records.len() > MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS
        || first_source_sequence == 0
        || next_source_sequence == 0
    {
        return Err(CrossStreamTelemetryJournalError::InvalidSourceBatch);
    }
    let mut expected = first_source_sequence;
    for (source_sequence, event) in records {
        if *source_sequence != expected || *source_sequence == u64::MAX {
            return Err(CrossStreamTelemetryJournalError::InvalidSourceBatch);
        }
        if source.kind() != event.kind() {
            return Err(CrossStreamTelemetryJournalError::SourceKindMismatch {
                expected: source.kind(),
                actual: event.kind(),
            });
        }
        validate_event(event)?;
        expected = expected
            .checked_add(1)
            .ok_or(CrossStreamTelemetryJournalError::InvalidSourceBatch)?;
    }
    if expected != next_source_sequence {
        return Err(CrossStreamTelemetryJournalError::InvalidSourceBatch);
    }
    Ok(())
}

fn validate_record(
    record: &CrossStreamTelemetryRecord,
) -> Result<(), CrossStreamTelemetryJournalError> {
    if record.aggregate_sequence == 0
        || record.aggregate_sequence == u64::MAX
        || record.source_sequence == 0
        || record.source_sequence == u64::MAX
    {
        return Err(CrossStreamTelemetryJournalError::InvalidAggregateSequence);
    }
    if record.source.kind() != record.event.kind() {
        return Err(CrossStreamTelemetryJournalError::SourceKindMismatch {
            expected: record.source.kind(),
            actual: record.event.kind(),
        });
    }
    validate_event(&record.event)
}

fn validate_event(
    event: &CrossStreamTelemetryEvent,
) -> Result<(), CrossStreamTelemetryJournalError> {
    match event {
        CrossStreamTelemetryEvent::CapabilityAudit(event) => event
            .validate_for_durable_telemetry()
            .map_err(CrossStreamTelemetryJournalError::InvalidAuditEvent),
        CrossStreamTelemetryEvent::Workflow(event) => event
            .validate_for_durable_replay()
            .map_err(CrossStreamTelemetryJournalError::InvalidWorkflowEvent),
    }
}

/// Rejection while decoding, extending, or encoding a durable cross-stream
/// telemetry journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossStreamTelemetryJournalError {
    CapacityTooLarge {
        requested: usize,
        maximum: usize,
    },
    TooManyEvents {
        actual: usize,
        maximum: usize,
    },
    TooManySources {
        maximum: usize,
    },
    BatchTooLarge {
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
    InvalidStreamId(CrossStreamTelemetryStreamIdError),
    StreamMismatch {
        expected: CrossStreamTelemetryStreamId,
        actual: CrossStreamTelemetryStreamId,
    },
    InvalidSource(CrossStreamTelemetrySourceError),
    SourceAlreadyRegistered,
    InvalidSourceState,
    MissingSourceState,
    InvalidAggregateSequence,
    InvalidSourceBatch,
    EmptyBatch,
    AggregateSequenceExhausted,
    SourceStartRequiresRegistration {
        first_sequence: u64,
    },
    SourceSequenceGap {
        expected: u64,
        actual: u64,
    },
    ReplayBeforeRetention {
        supplied: u64,
        first_retained: u64,
    },
    OverlappingEventMismatch {
        source_sequence: u64,
    },
    SourceKindMismatch {
        expected: CrossStreamTelemetryKind,
        actual: CrossStreamTelemetryKind,
    },
    InvalidAuditEvent(AuditEventValidationError),
    InvalidWorkflowEvent(WorkflowEventValidationError),
    NoPersistedJournalForNoop,
}

impl Display for CrossStreamTelemetryJournalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityTooLarge { requested, maximum } => write!(
                formatter,
                "durable cross-stream telemetry capacity {requested} exceeds the hard limit of {maximum}"
            ),
            Self::TooManyEvents { actual, maximum } => write!(
                formatter,
                "durable cross-stream telemetry journal has {actual} events; maximum is {maximum}"
            ),
            Self::TooManySources { maximum } => write!(
                formatter,
                "durable cross-stream telemetry journal has more than {maximum} source segments"
            ),
            Self::BatchTooLarge { actual, maximum } => write!(
                formatter,
                "cross-stream telemetry source batch has {actual} events; maximum is {maximum}"
            ),
            Self::TooLarge { actual, maximum } => write!(
                formatter,
                "durable cross-stream telemetry journal is {actual} bytes; maximum is {maximum}"
            ),
            Self::InvalidEncoding => formatter.write_str("invalid durable cross-stream telemetry journal"),
            Self::SerializationFailed => {
                formatter.write_str("durable cross-stream telemetry journal could not be encoded")
            }
            Self::UnsupportedFormatVersion { actual, expected } => write!(
                formatter,
                "unsupported durable cross-stream telemetry format {actual}; expected {expected}"
            ),
            Self::InvalidStreamId(error) => write!(formatter, "invalid cross-stream telemetry stream ID: {error}"),
            Self::StreamMismatch { expected, actual } => write!(
                formatter,
                "cross-stream telemetry journal stream {actual} does not match configured stream {expected}"
            ),
            Self::InvalidSource(error) => write!(formatter, "invalid cross-stream telemetry source: {error}"),
            Self::SourceAlreadyRegistered => {
                formatter.write_str("cross-stream telemetry source is already registered")
            }
            Self::InvalidSourceState => formatter.write_str("invalid cross-stream telemetry source state"),
            Self::MissingSourceState => formatter.write_str("cross-stream telemetry record has no source state"),
            Self::InvalidAggregateSequence => {
                formatter.write_str("invalid durable cross-stream aggregate sequence")
            }
            Self::InvalidSourceBatch => {
                formatter.write_str("invalid cross-stream telemetry source batch")
            }
            Self::EmptyBatch => formatter.write_str("durable cross-stream telemetry batch is empty"),
            Self::AggregateSequenceExhausted => {
                formatter.write_str("durable cross-stream aggregate sequence is exhausted")
            }
            Self::SourceStartRequiresRegistration { first_sequence } => write!(
                formatter,
                "cross-stream source begins at {first_sequence}; register that segment explicitly"
            ),
            Self::SourceSequenceGap { expected, actual } => write!(
                formatter,
                "cross-stream source sequence gap: expected {expected}, got {actual}"
            ),
            Self::ReplayBeforeRetention {
                supplied,
                first_retained,
            } => write!(
                formatter,
                "cross-stream source replay starts at {supplied}, before retained sequence {first_retained}"
            ),
            Self::OverlappingEventMismatch { source_sequence } => write!(
                formatter,
                "cross-stream source replay does not match retained event sequence {source_sequence}"
            ),
            Self::SourceKindMismatch { expected, actual } => write!(
                formatter,
                "cross-stream telemetry expected {} source data but received {} source data",
                expected.label(),
                actual.label()
            ),
            Self::InvalidAuditEvent(error) => write!(formatter, "invalid capability audit event: {error}"),
            Self::InvalidWorkflowEvent(error) => write!(formatter, "invalid workflow event: {error}"),
            Self::NoPersistedJournalForNoop => {
                formatter.write_str("cross-stream telemetry no-op has no persisted journal")
            }
        }
    }
}

impl std::error::Error for CrossStreamTelemetryJournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidStreamId(error) => Some(error),
            Self::InvalidSource(error) => Some(error),
            Self::InvalidAuditEvent(error) => Some(error),
            Self::InvalidWorkflowEvent(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct CrossStreamTelemetryJournalEncodeWire<'a> {
    format_version: u8,
    stream_id: &'a str,
    first_aggregate_sequence: u64,
    next_aggregate_sequence: u64,
    dropped_events: u64,
    sources: Vec<CrossStreamTelemetrySourceStateWire<'a>>,
    events: Vec<CrossStreamTelemetryRecordWire<'a>>,
}

impl<'a> From<&'a CrossStreamTelemetryJournal> for CrossStreamTelemetryJournalEncodeWire<'a> {
    fn from(journal: &'a CrossStreamTelemetryJournal) -> Self {
        Self {
            format_version: journal.format_version,
            stream_id: journal.stream_id.as_str(),
            first_aggregate_sequence: journal.first_aggregate_sequence,
            next_aggregate_sequence: journal.next_aggregate_sequence,
            dropped_events: journal.dropped_events,
            sources: journal
                .sources
                .iter()
                .map(|(source, state)| CrossStreamTelemetrySourceStateWire {
                    source: CrossStreamTelemetrySourceWire::from(source),
                    segment_start_sequence: state.segment_start_sequence,
                    next_source_sequence: state.next_source_sequence,
                })
                .collect(),
            events: journal
                .events
                .iter()
                .map(CrossStreamTelemetryRecordWire::from)
                .collect(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossStreamTelemetryJournalDecodeWire {
    format_version: u8,
    stream_id: String,
    first_aggregate_sequence: u64,
    next_aggregate_sequence: u64,
    dropped_events: u64,
    sources: Vec<CrossStreamTelemetrySourceStateWireOwned>,
    events: Vec<CrossStreamTelemetryRecordWireOwned>,
}

#[derive(Serialize)]
struct CrossStreamTelemetrySourceWire<'a> {
    kind: CrossStreamTelemetryKind,
    id: &'a str,
}

impl<'a> From<&'a CrossStreamTelemetrySource> for CrossStreamTelemetrySourceWire<'a> {
    fn from(source: &'a CrossStreamTelemetrySource) -> Self {
        Self {
            kind: source.kind,
            id: source.id(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossStreamTelemetrySourceWireOwned {
    kind: CrossStreamTelemetryKind,
    id: String,
}

impl TryFrom<CrossStreamTelemetrySourceWireOwned> for CrossStreamTelemetrySource {
    type Error = CrossStreamTelemetryJournalError;

    fn try_from(wire: CrossStreamTelemetrySourceWireOwned) -> Result<Self, Self::Error> {
        CrossStreamTelemetrySource::new(wire.kind, wire.id)
            .map_err(CrossStreamTelemetryJournalError::InvalidSource)
    }
}

#[derive(Serialize)]
struct CrossStreamTelemetrySourceStateWire<'a> {
    source: CrossStreamTelemetrySourceWire<'a>,
    segment_start_sequence: u64,
    next_source_sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossStreamTelemetrySourceStateWireOwned {
    source: CrossStreamTelemetrySourceWireOwned,
    segment_start_sequence: u64,
    next_source_sequence: u64,
}

#[derive(Serialize)]
struct CrossStreamTelemetryRecordWire<'a> {
    aggregate_sequence: u64,
    source: CrossStreamTelemetrySourceWire<'a>,
    source_sequence: u64,
    event: CrossStreamTelemetryEventWire<'a>,
}

impl<'a> From<&'a CrossStreamTelemetryRecord> for CrossStreamTelemetryRecordWire<'a> {
    fn from(record: &'a CrossStreamTelemetryRecord) -> Self {
        Self {
            aggregate_sequence: record.aggregate_sequence,
            source: CrossStreamTelemetrySourceWire::from(&record.source),
            source_sequence: record.source_sequence,
            event: CrossStreamTelemetryEventWire::from(&record.event),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossStreamTelemetryRecordWireOwned {
    aggregate_sequence: u64,
    source: CrossStreamTelemetrySourceWireOwned,
    source_sequence: u64,
    event: CrossStreamTelemetryEventWireOwned,
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "event", rename_all = "snake_case")]
enum CrossStreamTelemetryEventWire<'a> {
    CapabilityAudit(AuditEventWire<'a>),
    Workflow(&'a WorkflowEvent),
}

impl<'a> From<&'a CrossStreamTelemetryEvent> for CrossStreamTelemetryEventWire<'a> {
    fn from(event: &'a CrossStreamTelemetryEvent) -> Self {
        match event {
            CrossStreamTelemetryEvent::CapabilityAudit(event) => {
                Self::CapabilityAudit(AuditEventWire::from(event))
            }
            CrossStreamTelemetryEvent::Workflow(event) => Self::Workflow(event),
        }
    }
}

#[derive(Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    content = "event",
    rename_all = "snake_case"
)]
enum CrossStreamTelemetryEventWireOwned {
    CapabilityAudit(AuditEventWireOwned),
    Workflow(WorkflowEvent),
}

impl From<CrossStreamTelemetryEventWireOwned> for CrossStreamTelemetryEvent {
    fn from(wire: CrossStreamTelemetryEventWireOwned) -> Self {
        match wire {
            CrossStreamTelemetryEventWireOwned::CapabilityAudit(event) => {
                Self::CapabilityAudit(event.into())
            }
            CrossStreamTelemetryEventWireOwned::Workflow(event) => Self::Workflow(event),
        }
    }
}

#[derive(Serialize)]
struct AuditEventWire<'a> {
    event_sequence: u64,
    sequence: u64,
    tool: &'a str,
    input_bytes: usize,
    output_bytes: usize,
    outcome: AuditOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_class: Option<RetryClass>,
}

impl<'a> From<&'a AuditEvent> for AuditEventWire<'a> {
    fn from(event: &'a AuditEvent) -> Self {
        Self {
            event_sequence: event.event_sequence,
            sequence: event.sequence,
            tool: &event.tool,
            input_bytes: event.input_bytes,
            output_bytes: event.output_bytes,
            outcome: event.outcome,
            retry_class: event.retry_class,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditEventWireOwned {
    event_sequence: u64,
    sequence: u64,
    tool: String,
    input_bytes: usize,
    output_bytes: usize,
    outcome: AuditOutcome,
    #[serde(default)]
    retry_class: Option<RetryClass>,
}

impl From<AuditEventWireOwned> for AuditEvent {
    fn from(wire: AuditEventWireOwned) -> Self {
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

impl TryFrom<CrossStreamTelemetryJournalDecodeWire> for CrossStreamTelemetryJournal {
    type Error = CrossStreamTelemetryJournalError;

    fn try_from(wire: CrossStreamTelemetryJournalDecodeWire) -> Result<Self, Self::Error> {
        let stream_id = CrossStreamTelemetryStreamId::new(wire.stream_id)
            .map_err(CrossStreamTelemetryJournalError::InvalidStreamId)?;
        let mut sources = BTreeMap::new();
        for state in wire.sources {
            let source = state.source.try_into()?;
            let source_state = CrossStreamTelemetrySourceState {
                segment_start_sequence: state.segment_start_sequence,
                next_source_sequence: state.next_source_sequence,
            };
            if sources.insert(source, source_state).is_some() {
                return Err(CrossStreamTelemetryJournalError::SourceAlreadyRegistered);
            }
        }
        let mut events = VecDeque::new();
        for record in wire.events {
            events.push_back(CrossStreamTelemetryRecord {
                aggregate_sequence: record.aggregate_sequence,
                source: record.source.try_into()?,
                source_sequence: record.source_sequence,
                event: record.event.into(),
            });
        }
        Ok(Self {
            format_version: wire.format_version,
            stream_id,
            first_aggregate_sequence: wire.first_aggregate_sequence,
            next_aggregate_sequence: wire.next_aggregate_sequence,
            dropped_events: wire.dropped_events,
            sources,
            events,
        })
    }
}

/// Authenticated storage for one host-owned durable cross-stream journal.
pub struct CrossStreamTelemetryStore<B> {
    storage: AuthenticatedStore<B>,
    record_key: StorageRecordKey,
    stream_id: CrossStreamTelemetryStreamId,
    max_events: NonZeroUsize,
}

impl<B> CrossStreamTelemetryStore<B>
where
    B: RollbackProtectedStore,
{
    /// Creates a host-owned authenticated cross-stream telemetry recorder.
    pub fn new(
        storage: AuthenticatedStore<B>,
        record_key: StorageRecordKey,
        stream_id: CrossStreamTelemetryStreamId,
        max_events: NonZeroUsize,
    ) -> Result<Self, CrossStreamTelemetryJournalError> {
        validate_capacity(max_events)?;
        Ok(Self {
            storage,
            record_key,
            stream_id,
            max_events,
        })
    }

    /// Returns the host-selected storage record key.
    pub fn record_key(&self) -> &StorageRecordKey {
        &self.record_key
    }

    /// Returns the immutable aggregate stream identity.
    pub fn stream_id(&self) -> &CrossStreamTelemetryStreamId {
        &self.stream_id
    }

    /// Returns the configured aggregate retention capacity.
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

    /// Loads the current authenticated durable aggregate journal.
    pub fn load(
        &self,
    ) -> Result<
        Option<PersistedCrossStreamTelemetryJournal>,
        CrossStreamTelemetryStoreError<B::Error>,
    > {
        let Some(record) = self
            .storage
            .load(&self.record_key)
            .map_err(CrossStreamTelemetryStoreError::Storage)?
        else {
            return Ok(None);
        };
        let document = std::str::from_utf8(record.payload()).map_err(|_| {
            CrossStreamTelemetryStoreError::Journal(
                CrossStreamTelemetryJournalError::InvalidEncoding,
            )
        })?;
        let journal =
            CrossStreamTelemetryJournal::from_json_with_capacity(document, self.max_events)
                .map_err(CrossStreamTelemetryStoreError::Journal)?;
        if journal.stream_id != self.stream_id {
            return Err(CrossStreamTelemetryStoreError::Journal(
                CrossStreamTelemetryJournalError::StreamMismatch {
                    expected: self.stream_id.clone(),
                    actual: journal.stream_id,
                },
            ));
        }
        Ok(Some(PersistedCrossStreamTelemetryJournal {
            storage_revision: record.revision(),
            journal,
        }))
    }

    /// Persists an ordinary source segment before a host begins ingestion.
    pub fn register_source(
        &mut self,
        source: CrossStreamTelemetrySource,
    ) -> Result<PersistedCrossStreamTelemetryJournal, CrossStreamTelemetryStoreError<B::Error>>
    {
        self.register_source_at(source, 1)
    }

    /// Persists an explicit source segment before a host begins ingestion at a
    /// non-one cursor.
    pub fn register_source_at(
        &mut self,
        source: CrossStreamTelemetrySource,
        next_source_sequence: u64,
    ) -> Result<PersistedCrossStreamTelemetryJournal, CrossStreamTelemetryStoreError<B::Error>>
    {
        let max_events = self.max_events;
        self.mutate(|journal| {
            let _ = journal.register_source_at(source.clone(), next_source_sequence, max_events)?;
            Ok(((), true))
        })
        .map(|(persisted, ())| persisted)
    }

    /// Ingests one capability-audit source batch through authenticated storage.
    pub fn ingest_audit_batch(
        &mut self,
        source: &CrossStreamTelemetrySource,
        batch: &AuditEventBatch,
    ) -> Result<PersistedCrossStreamTelemetryJournal, CrossStreamTelemetryStoreError<B::Error>>
    {
        let max_events = self.max_events;
        self.mutate(|journal| {
            let appended = journal.ingest_audit_batch(source, batch, max_events)?;
            Ok((appended, appended != 0))
        })
        .map(|(persisted, _)| persisted)
    }

    /// Ingests one workflow-event source batch through authenticated storage.
    pub fn ingest_workflow_batch(
        &mut self,
        source: &CrossStreamTelemetrySource,
        batch: &WorkflowEventBatch,
    ) -> Result<PersistedCrossStreamTelemetryJournal, CrossStreamTelemetryStoreError<B::Error>>
    {
        let max_events = self.max_events;
        self.mutate(|journal| {
            let appended = journal.ingest_workflow_batch(source, batch, max_events)?;
            Ok((appended, appended != 0))
        })
        .map(|(persisted, _)| persisted)
    }

    fn mutate<T, F>(
        &mut self,
        mut mutation: F,
    ) -> Result<(PersistedCrossStreamTelemetryJournal, T), CrossStreamTelemetryStoreError<B::Error>>
    where
        F: FnMut(
            &mut CrossStreamTelemetryJournal,
        ) -> Result<(T, bool), CrossStreamTelemetryJournalError>,
    {
        for attempt in 0..MAX_DURABLE_CROSS_STREAM_TELEMETRY_STORE_RETRIES {
            let existing = self.load()?;
            let (expected_revision, mut journal) = match existing {
                Some(existing) => (Some(existing.storage_revision), existing.journal),
                None => (
                    None,
                    CrossStreamTelemetryJournal::new(self.stream_id.clone()),
                ),
            };
            let (output, changed) =
                mutation(&mut journal).map_err(CrossStreamTelemetryStoreError::Journal)?;
            if !changed {
                let Some(storage_revision) = expected_revision else {
                    return Err(CrossStreamTelemetryStoreError::Journal(
                        CrossStreamTelemetryJournalError::NoPersistedJournalForNoop,
                    ));
                };
                return Ok((
                    PersistedCrossStreamTelemetryJournal {
                        storage_revision,
                        journal,
                    },
                    output,
                ));
            }

            let payload = journal
                .to_json()
                .map_err(CrossStreamTelemetryStoreError::Journal)?;
            let write = match expected_revision {
                Some(revision) => {
                    self.storage
                        .replace(&self.record_key, revision, payload.as_bytes())
                }
                None => self.storage.create(&self.record_key, payload.as_bytes()),
            };
            match write {
                Ok(record) => {
                    return Ok((
                        PersistedCrossStreamTelemetryJournal {
                            storage_revision: record.revision(),
                            journal,
                        },
                        output,
                    ));
                }
                Err(AuthenticatedStoreError::WriteConflict { .. })
                    if attempt + 1 < MAX_DURABLE_CROSS_STREAM_TELEMETRY_STORE_RETRIES =>
                {
                    continue;
                }
                Err(AuthenticatedStoreError::WriteConflict { .. }) => {
                    return Err(CrossStreamTelemetryStoreError::Contended {
                        attempts: MAX_DURABLE_CROSS_STREAM_TELEMETRY_STORE_RETRIES,
                    });
                }
                Err(error) => return Err(CrossStreamTelemetryStoreError::Storage(error)),
            }
        }

        Err(CrossStreamTelemetryStoreError::Contended {
            attempts: MAX_DURABLE_CROSS_STREAM_TELEMETRY_STORE_RETRIES,
        })
    }
}

/// A durable aggregate journal paired with its authenticated storage revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCrossStreamTelemetryJournal {
    storage_revision: u64,
    journal: CrossStreamTelemetryJournal,
}

impl PersistedCrossStreamTelemetryJournal {
    /// Returns the authenticated storage revision for this snapshot.
    pub const fn storage_revision(&self) -> u64 {
        self.storage_revision
    }

    /// Returns the validated durable telemetry journal.
    pub fn journal(&self) -> &CrossStreamTelemetryJournal {
        &self.journal
    }
}

/// Failure while loading or writing a durable cross-stream telemetry journal.
#[derive(Debug)]
pub enum CrossStreamTelemetryStoreError<E> {
    Storage(AuthenticatedStoreError<E>),
    Journal(CrossStreamTelemetryJournalError),
    Contended { attempts: usize },
}

impl<E: Display> Display for CrossStreamTelemetryStoreError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "cross-stream telemetry storage error: {error}"),
            Self::Journal(error) => write!(formatter, "cross-stream telemetry journal error: {error}"),
            Self::Contended { attempts } => write!(
                formatter,
                "cross-stream telemetry storage remained contended after {attempts} bounded attempts"
            ),
        }
    }
}

impl<E> std::error::Error for CrossStreamTelemetryStoreError<E> where E: std::error::Error + 'static {}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use splash_capabilities::{AuditEventBatch, CapabilityRuntime, ToolPolicy};
    use splash_storage::{
        StorageKey, StorageKeyId, StorageKeyring, VolatileMemoryStore, STORAGE_KEY_BYTES,
    };

    use super::*;
    use crate::WorkflowEventRecord;

    fn capacity() -> NonZeroUsize {
        NonZeroUsize::new(8).expect("test capacity is nonzero")
    }

    fn stream_id() -> CrossStreamTelemetryStreamId {
        CrossStreamTelemetryStreamId::new("release-42-attempt-1").expect("test stream ID is valid")
    }

    fn source(kind: CrossStreamTelemetryKind, id: &str) -> CrossStreamTelemetrySource {
        CrossStreamTelemetrySource::new(kind, id).expect("test source ID is valid")
    }

    fn workflow_batch(records: &[(u64, u64)]) -> WorkflowEventBatch {
        let next_sequence = records.last().map_or(1, |(sequence, _)| sequence + 1);
        WorkflowEventBatch::new(
            records
                .iter()
                .map(|(sequence, plan_id)| {
                    WorkflowEventRecord::new(
                        *sequence,
                        WorkflowEvent::Started { plan_id: *plan_id },
                    )
                    .expect("test workflow event is valid")
                })
                .collect(),
            next_sequence,
        )
        .expect("test workflow batch is contiguous")
    }

    fn audit_batch(input: &str) -> AuditEventBatch {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .expect("test tool registration succeeds");
        assert!(runtime
            .eval(&format!(
                "use mod.tool\ntool.call(\"text.echo\", \"{input}\")"
            ))
            .expect("audit-producing evaluation succeeds")
            .succeeded());
        runtime.audit_since(1).expect("test audit is retained")
    }

    fn store() -> CrossStreamTelemetryStore<VolatileMemoryStore> {
        let storage = AuthenticatedStore::new(
            VolatileMemoryStore::default(),
            StorageKeyring::new(
                StorageKeyId::new("storage-v1").expect("test key ID is valid"),
                StorageKey::from_bytes([47; STORAGE_KEY_BYTES]),
            ),
        );
        CrossStreamTelemetryStore::new(
            storage,
            StorageRecordKey::new("cross-stream-telemetry", "release-42-attempt-1")
                .expect("test storage key is valid"),
            stream_id(),
            capacity(),
        )
        .expect("test durable store configuration is valid")
    }

    #[test]
    fn journal_round_trips_interleaved_sources_without_tool_input() {
        let workflow_source = source(CrossStreamTelemetryKind::Workflow, "workflow.release.1");
        let audit_source = source(CrossStreamTelemetryKind::CapabilityAudit, "audit.release.1");
        let workflow = workflow_batch(&[(1, 1)]);
        let audit = audit_batch("secret-token");
        let mut journal = CrossStreamTelemetryJournal::new(stream_id());

        assert_eq!(
            journal
                .ingest_workflow_batch(&workflow_source, &workflow, capacity())
                .expect("workflow source batch is accepted"),
            1
        );
        assert_eq!(
            journal
                .ingest_audit_batch(&audit_source, &audit, capacity())
                .expect("audit source batch is accepted"),
            1
        );
        assert_eq!(journal.events().len(), 2);
        assert_eq!(journal.events()[0].aggregate_sequence(), 1);
        assert_eq!(journal.events()[0].source(), &workflow_source);
        assert_eq!(journal.events()[1].aggregate_sequence(), 2);
        assert_eq!(journal.events()[1].source(), &audit_source);
        assert_eq!(journal.next_aggregate_sequence(), 3);
        assert_eq!(
            journal.source_state(&workflow_source),
            Some(CrossStreamTelemetrySourceState {
                segment_start_sequence: 1,
                next_source_sequence: 2,
            })
        );
        assert_eq!(
            journal.source_state(&audit_source),
            Some(CrossStreamTelemetrySourceState {
                segment_start_sequence: 1,
                next_source_sequence: 2,
            })
        );

        let encoded = journal.to_json().expect("journal encodes");
        assert!(!encoded.contains("secret-token"));
        let restored = CrossStreamTelemetryJournal::from_json_with_capacity(&encoded, capacity())
            .expect("journal round trip decodes");
        assert_eq!(restored, journal);
    }

    #[test]
    fn journal_requires_exact_source_history_and_reports_retention_gaps() {
        let workflow_source = source(CrossStreamTelemetryKind::Workflow, "workflow.release.2");
        let first = workflow_batch(&[(1, 1)]);
        let mut journal = CrossStreamTelemetryJournal::new(stream_id());
        journal
            .ingest_workflow_batch(&workflow_source, &first, capacity())
            .expect("initial source batch is accepted");

        assert_eq!(
            journal
                .ingest_workflow_batch(&workflow_source, &workflow_batch(&[(3, 1)]), capacity())
                .expect_err("source gap is rejected"),
            CrossStreamTelemetryJournalError::SourceSequenceGap {
                expected: 2,
                actual: 3,
            }
        );
        assert_eq!(
            journal
                .ingest_workflow_batch(&workflow_source, &workflow_batch(&[(1, 2)]), capacity())
                .expect_err("mismatched replay is rejected"),
            CrossStreamTelemetryJournalError::OverlappingEventMismatch { source_sequence: 1 }
        );
        assert_eq!(
            journal
                .ingest_workflow_batch(&workflow_source, &first, capacity())
                .expect("exact retained replay is accepted"),
            0
        );
        assert_eq!(
            journal
                .ingest_workflow_batch(
                    &workflow_source,
                    &workflow_batch(&[(1, 1), (2, 1)]),
                    capacity(),
                )
                .expect("retained overlap with a new suffix is accepted"),
            1
        );
        assert_eq!(
            journal
                .source_state(&workflow_source)
                .map(|state| state.next_source_sequence()),
            Some(3)
        );

        let small = NonZeroUsize::new(1).expect("small test capacity is nonzero");
        let mut retained = CrossStreamTelemetryJournal::new(stream_id());
        retained
            .ingest_workflow_batch(&workflow_source, &workflow_batch(&[(1, 1), (2, 1)]), small)
            .expect("source batch is accepted");
        assert_eq!(retained.first_aggregate_sequence(), 2);
        assert_eq!(retained.dropped_events(), 1);
        let restored = CrossStreamTelemetryJournal::from_json_with_capacity(
            &retained.to_json().expect("retained journal encodes"),
            small,
        )
        .expect("retained journal restores");
        assert_eq!(restored, retained);
        assert_eq!(
            retained
                .events_since(1)
                .expect_err("evicted aggregate cursor fails"),
            CrossStreamTelemetryCursorError::Evicted {
                requested: 1,
                earliest_available: 2,
            }
        );
        assert_eq!(
            retained
                .ingest_workflow_batch(&workflow_source, &workflow_batch(&[(1, 1)]), small)
                .expect_err("replay before source retention is rejected"),
            CrossStreamTelemetryJournalError::ReplayBeforeRetention {
                supplied: 1,
                first_retained: 2,
            }
        );
    }

    #[test]
    fn journal_requires_an_explicit_segment_for_known_source_gaps() {
        let workflow_source = source(CrossStreamTelemetryKind::Workflow, "workflow.release.3");
        let resumed = workflow_batch(&[(7, 1)]);
        let mut journal = CrossStreamTelemetryJournal::new(stream_id());

        assert_eq!(
            journal
                .ingest_workflow_batch(&workflow_source, &resumed, capacity())
                .expect_err("implicit source gap is rejected"),
            CrossStreamTelemetryJournalError::SourceStartRequiresRegistration { first_sequence: 7 }
        );
        assert_eq!(
            journal
                .register_source_at(workflow_source.clone(), 7, capacity())
                .expect("explicit source segment is recorded"),
            CrossStreamTelemetrySourceState {
                segment_start_sequence: 7,
                next_source_sequence: 7,
            }
        );
        assert_eq!(
            journal
                .ingest_workflow_batch(&workflow_source, &resumed, capacity())
                .expect("registered source batch is accepted"),
            1
        );
        assert_eq!(
            journal.source_state(&workflow_source),
            Some(CrossStreamTelemetrySourceState {
                segment_start_sequence: 7,
                next_source_sequence: 8,
            })
        );
        let restored = CrossStreamTelemetryJournal::from_json_with_capacity(
            &journal.to_json().expect("journal encodes"),
            capacity(),
        )
        .expect("journal restores");
        assert_eq!(
            restored.source_state(&workflow_source),
            journal.source_state(&workflow_source)
        );
    }

    #[test]
    fn retention_accounts_for_evictions_across_interleaved_sources() {
        let small = NonZeroUsize::new(1).expect("small test capacity is nonzero");
        let workflow_source = source(CrossStreamTelemetryKind::Workflow, "workflow.release.4");
        let audit_source = source(CrossStreamTelemetryKind::CapabilityAudit, "audit.release.4");
        let mut journal = CrossStreamTelemetryJournal::new(stream_id());

        journal
            .ingest_workflow_batch(&workflow_source, &workflow_batch(&[(1, 1)]), small)
            .expect("first workflow event is accepted");
        journal
            .ingest_audit_batch(&audit_source, &audit_batch("first"), small)
            .expect("audit event is accepted");
        journal
            .ingest_workflow_batch(&workflow_source, &workflow_batch(&[(2, 1)]), small)
            .expect("second workflow event is accepted");

        assert_eq!(journal.events().len(), 1);
        assert_eq!(journal.first_aggregate_sequence(), 3);
        assert_eq!(journal.dropped_events(), 2);
        assert_eq!(
            journal
                .source_state(&workflow_source)
                .map(|state| state.next_source_sequence()),
            Some(3)
        );
        assert_eq!(
            journal
                .source_state(&audit_source)
                .map(|state| state.next_source_sequence()),
            Some(2)
        );
        let restored = CrossStreamTelemetryJournal::from_json_with_capacity(
            &journal.to_json().expect("interleaved journal encodes"),
            small,
        )
        .expect("interleaved journal restores");
        assert_eq!(restored, journal);
    }

    #[test]
    fn authenticated_store_persists_interleaved_sources_and_deduplicates_replays() {
        let workflow_source = source(CrossStreamTelemetryKind::Workflow, "workflow.release.4");
        let audit_source = source(CrossStreamTelemetryKind::CapabilityAudit, "audit.release.4");
        let workflow = workflow_batch(&[(1, 1)]);
        let audit = audit_batch("secret-token");
        let mut store = store();

        let first = store
            .ingest_workflow_batch(&workflow_source, &workflow)
            .expect("workflow batch persists");
        assert_eq!(first.storage_revision(), 1);
        let second = store
            .ingest_audit_batch(&audit_source, &audit)
            .expect("audit batch persists");
        assert_eq!(second.storage_revision(), 2);
        assert_eq!(second.journal().events().len(), 2);

        let replay = store
            .ingest_audit_batch(&audit_source, &audit)
            .expect("exact persisted replay is a no-op");
        assert_eq!(replay.storage_revision(), 2);
        assert_eq!(replay.journal(), second.journal());
        assert_eq!(store.load().expect("store loads").as_ref(), Some(&second));

        let storage = store.into_storage();
        let wrong_stream = CrossStreamTelemetryStore::new(
            storage,
            StorageRecordKey::new("cross-stream-telemetry", "release-42-attempt-1")
                .expect("test storage key is valid"),
            CrossStreamTelemetryStreamId::new("release-42-attempt-2")
                .expect("different stream ID is valid"),
            capacity(),
        )
        .expect("test durable store configuration is valid");
        assert!(matches!(
            wrong_stream.load(),
            Err(CrossStreamTelemetryStoreError::Journal(
                CrossStreamTelemetryJournalError::StreamMismatch { .. }
            ))
        ));
    }

    #[test]
    fn decoding_rejects_unbounded_and_invalid_telemetry_metadata() {
        let excessive_capacity = NonZeroUsize::new(MAX_DURABLE_CROSS_STREAM_TELEMETRY_EVENTS + 1)
            .expect("excessive test capacity is nonzero");
        assert!(matches!(
            CrossStreamTelemetryJournal::from_json_with_capacity("{}", excessive_capacity),
            Err(CrossStreamTelemetryJournalError::CapacityTooLarge { .. })
        ));

        let oversized = "x".repeat(MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES + 1);
        assert!(matches!(
            CrossStreamTelemetryJournal::from_json_with_capacity(&oversized, capacity()),
            Err(CrossStreamTelemetryJournalError::TooLarge { .. })
        ));

        let invalid_workflow = r#"{"format_version":1,"stream_id":"release-42","first_aggregate_sequence":1,"next_aggregate_sequence":2,"dropped_events":0,"sources":[{"source":{"kind":"workflow","id":"workflow.release"},"segment_start_sequence":1,"next_source_sequence":2}],"events":[{"aggregate_sequence":1,"source":{"kind":"workflow","id":"workflow.release"},"source_sequence":1,"event":{"kind":"workflow","event":{"type":"step_succeeded","plan_id":1,"step_id":"BAD"}}}]}"#;
        assert!(matches!(
            CrossStreamTelemetryJournal::from_json_with_capacity(invalid_workflow, capacity()),
            Err(CrossStreamTelemetryJournalError::InvalidWorkflowEvent(_))
        ));

        let inconsistent_source_state = r#"{"format_version":1,"stream_id":"release-42","first_aggregate_sequence":1,"next_aggregate_sequence":1,"dropped_events":0,"sources":[{"source":{"kind":"workflow","id":"workflow.release"},"segment_start_sequence":1,"next_source_sequence":2}],"events":[]}"#;
        assert!(matches!(
            CrossStreamTelemetryJournal::from_json_with_capacity(
                inconsistent_source_state,
                capacity(),
            ),
            Err(CrossStreamTelemetryJournalError::InvalidSourceState)
        ));

        let unknown_event_field = r#"{"format_version":1,"stream_id":"release-42","first_aggregate_sequence":1,"next_aggregate_sequence":2,"dropped_events":0,"sources":[{"source":{"kind":"workflow","id":"workflow.release"},"segment_start_sequence":1,"next_source_sequence":2}],"events":[{"aggregate_sequence":1,"source":{"kind":"workflow","id":"workflow.release"},"source_sequence":1,"event":{"kind":"workflow","event":{"type":"started","plan_id":1},"unexpected":true}}]}"#;
        assert!(matches!(
            CrossStreamTelemetryJournal::from_json_with_capacity(unknown_event_field, capacity(),),
            Err(CrossStreamTelemetryJournalError::InvalidEncoding)
        ));

        let unknown_field = r#"{"format_version":1,"stream_id":"release-42","first_aggregate_sequence":1,"next_aggregate_sequence":1,"dropped_events":0,"sources":[],"events":[],"unexpected":true}"#;
        assert!(matches!(
            CrossStreamTelemetryJournal::from_json_with_capacity(unknown_field, capacity()),
            Err(CrossStreamTelemetryJournalError::InvalidEncoding)
        ));
    }
}
