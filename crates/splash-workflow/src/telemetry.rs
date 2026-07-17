//! Bounded host-side aggregation of capability and workflow telemetry.
//!
//! [`CrossStreamTelemetryAggregator`] assigns a local aggregate sequence in
//! the exact order that a host ingests already-contiguous source batches. It
//! does not infer wall-clock order, causality, durable replay, approval, or an
//! adapter-effect outcome. Source identifiers are host-owned and a source gap
//! must be explicit rather than silently skipped.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;
use std::ops::Index;

use splash_capabilities::{AuditEvent, AuditEventBatch};

use crate::{WorkflowEvent, WorkflowEventBatch};

/// Default number of cross-stream telemetry records retained in memory.
pub const DEFAULT_MAX_CROSS_STREAM_TELEMETRY_EVENTS: usize = 1_024;
/// Absolute maximum number of cross-stream telemetry records retained in one
/// aggregator.
pub const MAX_CROSS_STREAM_TELEMETRY_EVENTS: usize = 8_192;
/// Maximum distinct host-named source streams retained in one aggregator.
pub const MAX_CROSS_STREAM_TELEMETRY_SOURCES: usize = 128;
/// Maximum UTF-8 byte length of one host-selected source identifier.
pub const MAX_CROSS_STREAM_TELEMETRY_SOURCE_ID_BYTES: usize = 128;
/// Maximum events accepted from one source batch before aggregation.
pub const MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS: usize = MAX_CROSS_STREAM_TELEMETRY_EVENTS;

/// The source-specific telemetry family carried by one aggregate record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CrossStreamTelemetryKind {
    CapabilityAudit,
    Workflow,
}

impl CrossStreamTelemetryKind {
    const fn label(self) -> &'static str {
        match self {
            Self::CapabilityAudit => "capability audit",
            Self::Workflow => "workflow",
        }
    }
}

/// A host-owned identity for one contiguous telemetry source.
///
/// A capability runtime and a workflow engine each begin their source-local
/// sequence at one. Hosts must therefore use a fresh source identifier when a
/// runtime history is recreated or when they deliberately begin after a known
/// observability gap.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CrossStreamTelemetrySource {
    kind: CrossStreamTelemetryKind,
    id: String,
}

impl CrossStreamTelemetrySource {
    /// Creates one bounded, non-secret host source identity.
    pub fn new(
        kind: CrossStreamTelemetryKind,
        id: impl Into<String>,
    ) -> Result<Self, CrossStreamTelemetrySourceError> {
        let id = id.into();
        if !is_valid_source_id(&id) {
            return Err(CrossStreamTelemetrySourceError::InvalidIdentifier);
        }
        Ok(Self { kind, id })
    }

    /// Returns the source telemetry family.
    pub const fn kind(&self) -> CrossStreamTelemetryKind {
        self.kind
    }

    /// Returns the opaque host-selected source identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Rejection for an invalid cross-stream telemetry source identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossStreamTelemetrySourceError {
    InvalidIdentifier,
}

impl Display for CrossStreamTelemetrySourceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier => formatter.write_str(
                "cross-stream telemetry source identifiers must be bounded lowercase tokens",
            ),
        }
    }
}

impl std::error::Error for CrossStreamTelemetrySourceError {}

/// Source cursor state retained by a cross-stream telemetry aggregator.
///
/// `segment_start_sequence` is one for an ordinary source. A larger value can
/// appear only after the host explicitly calls
/// [`CrossStreamTelemetryAggregator::register_source_at`], making a known
/// source-history gap visible to the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossStreamTelemetrySourceState {
    segment_start_sequence: u64,
    next_source_sequence: u64,
}

impl CrossStreamTelemetrySourceState {
    /// Returns the explicit source cursor at which this aggregation segment
    /// began.
    pub const fn segment_start_sequence(self) -> u64 {
        self.segment_start_sequence
    }

    /// Returns the exact source cursor required for the next batch.
    pub const fn next_source_sequence(self) -> u64 {
        self.next_source_sequence
    }
}

/// One retained telemetry payload without any authority-bearing runtime state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossStreamTelemetryEvent {
    CapabilityAudit(AuditEvent),
    Workflow(WorkflowEvent),
}

impl CrossStreamTelemetryEvent {
    /// Returns the source telemetry family for this payload.
    pub const fn kind(&self) -> CrossStreamTelemetryKind {
        match self {
            Self::CapabilityAudit(_) => CrossStreamTelemetryKind::CapabilityAudit,
            Self::Workflow(_) => CrossStreamTelemetryKind::Workflow,
        }
    }

    /// Returns the capability-audit payload when this is an audit record.
    pub fn audit(&self) -> Option<&AuditEvent> {
        match self {
            Self::CapabilityAudit(event) => Some(event),
            Self::Workflow(_) => None,
        }
    }

    /// Returns the workflow payload when this is a workflow record.
    pub fn workflow(&self) -> Option<&WorkflowEvent> {
        match self {
            Self::CapabilityAudit(_) => None,
            Self::Workflow(event) => Some(event),
        }
    }
}

/// One host-receipt-ordered cross-stream telemetry record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossStreamTelemetryRecord {
    aggregate_sequence: u64,
    source: CrossStreamTelemetrySource,
    source_sequence: u64,
    event: CrossStreamTelemetryEvent,
}

impl CrossStreamTelemetryRecord {
    /// Returns the aggregator-local receipt-order cursor.
    pub const fn aggregate_sequence(&self) -> u64 {
        self.aggregate_sequence
    }

    /// Returns the host-owned source identity.
    pub fn source(&self) -> &CrossStreamTelemetrySource {
        &self.source
    }

    /// Returns the source-local event cursor.
    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    /// Returns the bounded telemetry payload.
    pub fn event(&self) -> &CrossStreamTelemetryEvent {
        &self.event
    }
}

/// An owned aggregate range exported after a host-maintained cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossStreamTelemetryBatch {
    records: Vec<CrossStreamTelemetryRecord>,
    next_aggregate_sequence: u64,
}

impl CrossStreamTelemetryBatch {
    /// Returns records in host receipt order.
    pub fn records(&self) -> &[CrossStreamTelemetryRecord] {
        &self.records
    }

    /// Returns the aggregate cursor immediately after this batch.
    pub const fn next_aggregate_sequence(&self) -> u64 {
        self.next_aggregate_sequence
    }

    /// Returns whether this export has no retained records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Rejection while configuring or ingesting cross-stream telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossStreamTelemetryError {
    CapacityTooLarge {
        requested: usize,
        maximum: usize,
    },
    BatchTooLarge {
        actual: usize,
        maximum: usize,
    },
    TooManySources {
        maximum: usize,
    },
    SourceAlreadyRegistered,
    InvalidSourceBatch,
    SourceStartRequiresRegistration {
        first_sequence: u64,
    },
    SourceSequenceReplay {
        expected: u64,
        actual: u64,
    },
    SourceSequenceGap {
        expected: u64,
        actual: u64,
    },
    SourceKindMismatch {
        expected: CrossStreamTelemetryKind,
        actual: CrossStreamTelemetryKind,
    },
}

impl Display for CrossStreamTelemetryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityTooLarge { requested, maximum } => write!(
                formatter,
                "cross-stream telemetry capacity {requested} exceeds its maximum of {maximum}"
            ),
            Self::BatchTooLarge { actual, maximum } => write!(
                formatter,
                "cross-stream telemetry batch has {actual} events but may contain at most {maximum}"
            ),
            Self::TooManySources { maximum } => write!(
                formatter,
                "cross-stream telemetry has reached its maximum of {maximum} sources"
            ),
            Self::SourceAlreadyRegistered => {
                formatter.write_str("cross-stream telemetry source is already registered")
            }
            Self::InvalidSourceBatch => {
                formatter.write_str("cross-stream telemetry source batch is not contiguous")
            }
            Self::SourceStartRequiresRegistration { first_sequence } => write!(
                formatter,
                "cross-stream telemetry source begins at {first_sequence}; register that segment explicitly"
            ),
            Self::SourceSequenceReplay { expected, actual } => write!(
                formatter,
                "cross-stream telemetry source replay begins at {actual}; expected {expected}"
            ),
            Self::SourceSequenceGap { expected, actual } => write!(
                formatter,
                "cross-stream telemetry source gap begins at {actual}; expected {expected}"
            ),
            Self::SourceKindMismatch { expected, actual } => write!(
                formatter,
                "cross-stream telemetry expected {} source data but received {} source data",
                expected.label(),
                actual.label()
            ),
        }
    }
}

impl std::error::Error for CrossStreamTelemetryError {}

/// Rejection while exporting aggregate telemetry after a host-maintained cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrossStreamTelemetryCursorError {
    InvalidCursor,
    Evicted {
        requested: u64,
        earliest_available: u64,
    },
    Ahead {
        requested: u64,
        next_available: u64,
    },
}

impl Display for CrossStreamTelemetryCursorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCursor => {
                formatter.write_str("cross-stream telemetry aggregate cursor is invalid")
            }
            Self::Evicted {
                requested,
                earliest_available,
            } => write!(
                formatter,
                "cross-stream telemetry cursor {requested} was evicted; earliest available is {earliest_available}"
            ),
            Self::Ahead {
                requested,
                next_available,
            } => write!(
                formatter,
                "cross-stream telemetry cursor {requested} is ahead of the next available sequence {next_available}"
            ),
        }
    }
}

impl std::error::Error for CrossStreamTelemetryCursorError {}

/// Read-only view of bounded aggregate telemetry in host receipt order.
#[derive(Clone, Copy, Debug)]
pub struct CrossStreamTelemetryLog<'a> {
    entries: &'a VecDeque<CrossStreamTelemetryRecord>,
}

impl<'a> CrossStreamTelemetryLog<'a> {
    /// Returns the number of retained aggregate records.
    pub fn len(self) -> usize {
        self.entries.len()
    }

    /// Returns whether there are no retained aggregate records.
    pub fn is_empty(self) -> bool {
        self.entries.is_empty()
    }

    /// Returns one retained record by its zero-based in-memory index.
    pub fn get(self, index: usize) -> Option<&'a CrossStreamTelemetryRecord> {
        self.entries.get(index)
    }

    /// Returns the oldest retained aggregate record.
    pub fn first(self) -> Option<&'a CrossStreamTelemetryRecord> {
        self.entries.front()
    }

    /// Returns the newest retained aggregate record.
    pub fn last(self) -> Option<&'a CrossStreamTelemetryRecord> {
        self.entries.back()
    }

    /// Iterates retained aggregate records in host receipt order.
    pub fn iter(self) -> std::collections::vec_deque::Iter<'a, CrossStreamTelemetryRecord> {
        self.entries.iter()
    }

    /// Returns both contiguous portions of the underlying ring buffer.
    pub fn as_slices(
        self,
    ) -> (
        &'a [CrossStreamTelemetryRecord],
        &'a [CrossStreamTelemetryRecord],
    ) {
        self.entries.as_slices()
    }
}

impl<'a> IntoIterator for CrossStreamTelemetryLog<'a> {
    type Item = &'a CrossStreamTelemetryRecord;
    type IntoIter = std::collections::vec_deque::Iter<'a, CrossStreamTelemetryRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl Index<usize> for CrossStreamTelemetryLog<'_> {
    type Output = CrossStreamTelemetryRecord;

    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

/// Bounded host-receipt-order aggregation of multiple telemetry streams.
///
/// The aggregator is an observability helper only. It is not a durable sink,
/// an authenticated journal, a source of wall-clock or causal ordering, or an
/// authority to approve, resume, reconcile, retry, compensate, or replay an
/// effect.
#[derive(Debug)]
pub struct CrossStreamTelemetryAggregator {
    entries: VecDeque<CrossStreamTelemetryRecord>,
    sources: BTreeMap<CrossStreamTelemetrySource, CrossStreamTelemetrySourceState>,
    max_events: NonZeroUsize,
    first_aggregate_sequence: u64,
    next_aggregate_sequence: u64,
    dropped_events: u64,
}

impl Default for CrossStreamTelemetryAggregator {
    fn default() -> Self {
        Self::with_event_capacity(
            NonZeroUsize::new(DEFAULT_MAX_CROSS_STREAM_TELEMETRY_EVENTS)
                .expect("default cross-stream telemetry capacity is nonzero"),
        )
        .expect("default cross-stream telemetry capacity is bounded")
    }
}

impl CrossStreamTelemetryAggregator {
    /// Creates an empty aggregator with a host-selected bounded retention
    /// capacity.
    pub fn with_event_capacity(
        max_events: NonZeroUsize,
    ) -> Result<Self, CrossStreamTelemetryError> {
        if max_events.get() > MAX_CROSS_STREAM_TELEMETRY_EVENTS {
            return Err(CrossStreamTelemetryError::CapacityTooLarge {
                requested: max_events.get(),
                maximum: MAX_CROSS_STREAM_TELEMETRY_EVENTS,
            });
        }
        Ok(Self {
            entries: VecDeque::new(),
            sources: BTreeMap::new(),
            max_events,
            first_aggregate_sequence: 1,
            next_aggregate_sequence: 1,
            dropped_events: 0,
        })
    }

    /// Registers an ordinary source segment beginning at source cursor one.
    pub fn register_source(
        &mut self,
        source: CrossStreamTelemetrySource,
    ) -> Result<CrossStreamTelemetrySourceState, CrossStreamTelemetryError> {
        self.register_source_at(source, 1)
    }

    /// Registers an explicit new source segment beginning at one nonzero
    /// source cursor.
    ///
    /// Use this only after the host has surfaced an export/retention gap and
    /// assigned a fresh source identity. It does not repair, hide, or infer the
    /// omitted source records.
    pub fn register_source_at(
        &mut self,
        source: CrossStreamTelemetrySource,
        next_source_sequence: u64,
    ) -> Result<CrossStreamTelemetrySourceState, CrossStreamTelemetryError> {
        if next_source_sequence == 0 {
            return Err(CrossStreamTelemetryError::InvalidSourceBatch);
        }
        if self.sources.contains_key(&source) {
            return Err(CrossStreamTelemetryError::SourceAlreadyRegistered);
        }
        if self.sources.len() == MAX_CROSS_STREAM_TELEMETRY_SOURCES {
            return Err(CrossStreamTelemetryError::TooManySources {
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

    /// Ingests one contiguous capability-audit batch from its exact source
    /// cursor.
    pub fn ingest_audit_batch(
        &mut self,
        source: &CrossStreamTelemetrySource,
        batch: &AuditEventBatch,
    ) -> Result<(), CrossStreamTelemetryError> {
        self.ensure_source_kind(source, CrossStreamTelemetryKind::CapabilityAudit)?;
        validate_batch_len(batch.events().len())?;
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
        self.ingest_records(
            source,
            batch.first_event_sequence(),
            batch.next_event_sequence(),
            records,
        )
    }

    /// Ingests one contiguous workflow-event batch from its exact source
    /// cursor.
    pub fn ingest_workflow_batch(
        &mut self,
        source: &CrossStreamTelemetrySource,
        batch: &WorkflowEventBatch,
    ) -> Result<(), CrossStreamTelemetryError> {
        self.ensure_source_kind(source, CrossStreamTelemetryKind::Workflow)?;
        validate_batch_len(batch.records().len())?;
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
        self.ingest_records(
            source,
            batch.first_sequence(),
            batch.next_sequence(),
            records,
        )
    }

    /// Returns retained aggregate records after one host-maintained aggregate
    /// cursor.
    ///
    /// A cursor overtaken by retention eviction fails rather than presenting a
    /// partial timeline. The returned batch is still telemetry only and cannot
    /// establish an effect, approval, or workflow state.
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
            records: self.entries.iter().skip(skipped).cloned().collect(),
            next_aggregate_sequence: self.next_aggregate_sequence,
        })
    }

    /// Returns the bounded aggregate in host receipt order.
    pub fn events(&self) -> CrossStreamTelemetryLog<'_> {
        CrossStreamTelemetryLog {
            entries: &self.entries,
        }
    }

    /// Returns the configured aggregate retention capacity.
    pub const fn max_events(&self) -> usize {
        self.max_events.get()
    }

    /// Returns how many aggregate records were dropped because of retention or
    /// aggregate sequence exhaustion.
    pub const fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Returns the number of registered source segments.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Returns one source's required next cursor and explicit segment start.
    pub fn source_state(
        &self,
        source: &CrossStreamTelemetrySource,
    ) -> Option<CrossStreamTelemetrySourceState> {
        self.sources.get(source).copied()
    }

    /// Clears only the retained aggregate view and its local drop counter.
    ///
    /// Source cursor state remains intact, so a later batch must still be
    /// contiguous with the already-ingested source history. This never changes
    /// workflow authority, durable journals, or source runtimes.
    pub fn clear_events(&mut self) {
        self.entries.clear();
        self.dropped_events = 0;
        self.first_aggregate_sequence = self.next_aggregate_sequence;
    }

    fn ensure_source_kind(
        &self,
        source: &CrossStreamTelemetrySource,
        expected: CrossStreamTelemetryKind,
    ) -> Result<(), CrossStreamTelemetryError> {
        if source.kind == expected {
            Ok(())
        } else {
            Err(CrossStreamTelemetryError::SourceKindMismatch {
                expected,
                actual: source.kind,
            })
        }
    }

    fn ingest_records(
        &mut self,
        source: &CrossStreamTelemetrySource,
        first_source_sequence: u64,
        next_source_sequence: u64,
        records: Vec<(u64, CrossStreamTelemetryEvent)>,
    ) -> Result<(), CrossStreamTelemetryError> {
        validate_source_batch(first_source_sequence, next_source_sequence, &records)?;
        self.advance_source(source, first_source_sequence, next_source_sequence)?;
        for (source_sequence, event) in records {
            self.record(source.clone(), source_sequence, event);
        }
        Ok(())
    }

    fn advance_source(
        &mut self,
        source: &CrossStreamTelemetrySource,
        first_source_sequence: u64,
        next_source_sequence: u64,
    ) -> Result<(), CrossStreamTelemetryError> {
        if let Some(state) = self.sources.get_mut(source) {
            let expected = state.next_source_sequence;
            if first_source_sequence < expected {
                return Err(CrossStreamTelemetryError::SourceSequenceReplay {
                    expected,
                    actual: first_source_sequence,
                });
            }
            if first_source_sequence > expected {
                return Err(CrossStreamTelemetryError::SourceSequenceGap {
                    expected,
                    actual: first_source_sequence,
                });
            }
            state.next_source_sequence = next_source_sequence;
            return Ok(());
        }
        if first_source_sequence != 1 {
            return Err(CrossStreamTelemetryError::SourceStartRequiresRegistration {
                first_sequence: first_source_sequence,
            });
        }
        self.register_source_at(source.clone(), 1)?;
        let state = self
            .sources
            .get_mut(source)
            .expect("newly registered cross-stream source is retained");
        state.next_source_sequence = next_source_sequence;
        Ok(())
    }

    fn record(
        &mut self,
        source: CrossStreamTelemetrySource,
        source_sequence: u64,
        event: CrossStreamTelemetryEvent,
    ) {
        // `u64::MAX` remains a cursor-only sentinel. Preserve aggregate
        // sequence uniqueness by recording loss rather than wrapping.
        if self.next_aggregate_sequence == u64::MAX {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return;
        }
        if self.entries.len() == self.max_events.get() {
            self.entries.pop_front();
            self.dropped_events = self.dropped_events.saturating_add(1);
            self.first_aggregate_sequence = self.first_aggregate_sequence.saturating_add(1);
        }
        self.entries.push_back(CrossStreamTelemetryRecord {
            aggregate_sequence: self.next_aggregate_sequence,
            source,
            source_sequence,
            event,
        });
        self.next_aggregate_sequence = self.next_aggregate_sequence.saturating_add(1);
    }
}

fn is_valid_source_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CROSS_STREAM_TELEMETRY_SOURCE_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn validate_source_batch(
    first_source_sequence: u64,
    next_source_sequence: u64,
    records: &[(u64, CrossStreamTelemetryEvent)],
) -> Result<(), CrossStreamTelemetryError> {
    validate_batch_len(records.len())?;
    if first_source_sequence == 0 || next_source_sequence == 0 {
        return Err(CrossStreamTelemetryError::InvalidSourceBatch);
    }
    if records.is_empty() {
        return (first_source_sequence == next_source_sequence)
            .then_some(())
            .ok_or(CrossStreamTelemetryError::InvalidSourceBatch);
    }

    let mut expected = first_source_sequence;
    for (source_sequence, _) in records {
        if *source_sequence != expected || *source_sequence == 0 || *source_sequence == u64::MAX {
            return Err(CrossStreamTelemetryError::InvalidSourceBatch);
        }
        expected = expected
            .checked_add(1)
            .ok_or(CrossStreamTelemetryError::InvalidSourceBatch)?;
    }
    (expected == next_source_sequence)
        .then_some(())
        .ok_or(CrossStreamTelemetryError::InvalidSourceBatch)
}

fn validate_batch_len(length: usize) -> Result<(), CrossStreamTelemetryError> {
    if length > MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS {
        return Err(CrossStreamTelemetryError::BatchTooLarge {
            actual: length,
            maximum: MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use splash_capabilities::{CapabilityRuntime, ToolPolicy};

    use super::*;
    use crate::{WorkflowEventRecord, WorkflowStep};

    fn source(kind: CrossStreamTelemetryKind, id: &str) -> CrossStreamTelemetrySource {
        CrossStreamTelemetrySource::new(kind, id).expect("source ID is valid")
    }

    fn workflow_batch(sequences: &[u64]) -> WorkflowEventBatch {
        WorkflowEventBatch::new(
            sequences
                .iter()
                .map(|sequence| {
                    WorkflowEventRecord::new(*sequence, WorkflowEvent::Started { plan_id: 1 })
                        .expect("workflow event is valid")
                })
                .collect(),
            sequences.last().map_or(1, |sequence| sequence + 1),
        )
        .expect("workflow batch is contiguous")
    }

    #[test]
    fn aggregates_audit_and_workflow_batches_in_host_receipt_order() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .expect("tool registration succeeds");
        assert!(runtime
            .eval("use mod.tool\ntool.call(\"text.echo\", \"release\")")
            .expect("audit-producing evaluation succeeds")
            .completed());
        let audit_batch = runtime.audit_since(1).expect("audit batch is retained");

        let mut engine = crate::WorkflowEngine::new(CapabilityRuntime::default());
        engine
            .plan(vec![WorkflowStep::new("prepare", "let ready = true")])
            .expect("workflow plan succeeds");
        let workflow_batch = engine.events_since(1).expect("workflow batch is retained");

        let workflow_source = source(CrossStreamTelemetryKind::Workflow, "workflow.release.1");
        let audit_source = source(CrossStreamTelemetryKind::CapabilityAudit, "audit.release.1");
        let mut aggregator = CrossStreamTelemetryAggregator::default();
        aggregator
            .ingest_workflow_batch(&workflow_source, &workflow_batch)
            .expect("workflow batch is accepted");
        aggregator
            .ingest_audit_batch(&audit_source, &audit_batch)
            .expect("audit batch is accepted");

        assert_eq!(aggregator.events().len(), 2);
        assert_eq!(aggregator.source_count(), 2);
        assert_eq!(aggregator.events()[0].aggregate_sequence(), 1);
        assert_eq!(aggregator.events()[1].aggregate_sequence(), 2);
        assert_eq!(aggregator.events()[0].source(), &workflow_source);
        assert_eq!(aggregator.events()[1].source(), &audit_source);
        assert!(matches!(
            aggregator.events()[0].event(),
            CrossStreamTelemetryEvent::Workflow(WorkflowEvent::Planned { .. })
        ));
        assert!(matches!(
            aggregator.events()[1].event(),
            CrossStreamTelemetryEvent::CapabilityAudit(_)
        ));
        assert_eq!(
            aggregator.source_state(&workflow_source),
            Some(CrossStreamTelemetrySourceState {
                segment_start_sequence: 1,
                next_source_sequence: 2,
            })
        );
        assert_eq!(
            aggregator.source_state(&audit_source),
            Some(CrossStreamTelemetrySourceState {
                segment_start_sequence: 1,
                next_source_sequence: 2,
            })
        );

        let exported = aggregator
            .events_since(1)
            .expect("aggregate export succeeds");
        assert_eq!(exported.records().len(), 2);
        assert_eq!(exported.next_aggregate_sequence(), 3);
    }

    #[test]
    fn rejects_source_replay_and_gaps_but_allows_an_explicit_new_segment() {
        let workflow_source = source(CrossStreamTelemetryKind::Workflow, "workflow.release.2");
        let first = workflow_batch(&[1]);
        let mut aggregator = CrossStreamTelemetryAggregator::default();
        aggregator
            .ingest_workflow_batch(&workflow_source, &first)
            .expect("first source batch is accepted");
        assert_eq!(
            aggregator.ingest_workflow_batch(&workflow_source, &first),
            Err(CrossStreamTelemetryError::SourceSequenceReplay {
                expected: 2,
                actual: 1,
            })
        );
        let third = workflow_batch(&[3]);
        assert_eq!(
            aggregator.ingest_workflow_batch(&workflow_source, &third),
            Err(CrossStreamTelemetryError::SourceSequenceGap {
                expected: 2,
                actual: 3,
            })
        );

        let segmented_source = source(CrossStreamTelemetryKind::Workflow, "workflow.release.3");
        assert_eq!(
            aggregator.ingest_workflow_batch(&segmented_source, &third),
            Err(CrossStreamTelemetryError::SourceStartRequiresRegistration { first_sequence: 3 })
        );
        assert_eq!(
            aggregator
                .register_source_at(segmented_source.clone(), 3)
                .expect("explicit source segment is accepted"),
            CrossStreamTelemetrySourceState {
                segment_start_sequence: 3,
                next_source_sequence: 3,
            }
        );
        aggregator
            .ingest_workflow_batch(&segmented_source, &third)
            .expect("explicit source segment accepts its first batch");
        assert_eq!(
            aggregator.source_state(&segmented_source),
            Some(CrossStreamTelemetrySourceState {
                segment_start_sequence: 3,
                next_source_sequence: 4,
            })
        );
    }

    #[test]
    fn bounds_aggregate_retention_and_detects_evicted_cursors() {
        let workflow_source = source(CrossStreamTelemetryKind::Workflow, "workflow.release.4");
        let mut aggregator = CrossStreamTelemetryAggregator::with_event_capacity(
            NonZeroUsize::new(2).expect("capacity is nonzero"),
        )
        .expect("bounded capacity is accepted");
        aggregator
            .ingest_workflow_batch(&workflow_source, &workflow_batch(&[1, 2, 3]))
            .expect("workflow batch is accepted");

        assert_eq!(aggregator.events().len(), 2);
        assert_eq!(aggregator.dropped_events(), 1);
        assert_eq!(aggregator.events()[0].aggregate_sequence(), 2);
        assert_eq!(aggregator.events()[1].aggregate_sequence(), 3);
        assert_eq!(
            aggregator.events_since(1),
            Err(CrossStreamTelemetryCursorError::Evicted {
                requested: 1,
                earliest_available: 2,
            })
        );
        let retained = aggregator
            .events_since(2)
            .expect("retained export succeeds");
        assert_eq!(
            retained
                .records()
                .iter()
                .map(CrossStreamTelemetryRecord::source_sequence)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(retained.next_aggregate_sequence(), 4);

        aggregator.clear_events();
        assert!(aggregator.events().is_empty());
        assert_eq!(aggregator.dropped_events(), 0);
        assert_eq!(
            aggregator.source_state(&workflow_source),
            Some(CrossStreamTelemetrySourceState {
                segment_start_sequence: 1,
                next_source_sequence: 4,
            })
        );
        assert_eq!(
            aggregator.events_since(3),
            Err(CrossStreamTelemetryCursorError::Evicted {
                requested: 3,
                earliest_available: 4,
            })
        );
    }

    #[test]
    fn rejects_invalid_source_configuration_and_kind_mismatch() {
        assert_eq!(
            CrossStreamTelemetrySource::new(CrossStreamTelemetryKind::Workflow, "UPPER"),
            Err(CrossStreamTelemetrySourceError::InvalidIdentifier)
        );
        let workflow_source = source(CrossStreamTelemetryKind::Workflow, "workflow.release.5");
        let mut aggregator = CrossStreamTelemetryAggregator::default();
        assert_eq!(
            aggregator.register_source_at(workflow_source.clone(), 0),
            Err(CrossStreamTelemetryError::InvalidSourceBatch)
        );
        let capacity_error = CrossStreamTelemetryAggregator::with_event_capacity(
            NonZeroUsize::new(MAX_CROSS_STREAM_TELEMETRY_EVENTS + 1).expect("capacity is nonzero"),
        )
        .expect_err("oversized capacity is rejected");
        assert_eq!(
            capacity_error,
            CrossStreamTelemetryError::CapacityTooLarge {
                requested: MAX_CROSS_STREAM_TELEMETRY_EVENTS + 1,
                maximum: MAX_CROSS_STREAM_TELEMETRY_EVENTS,
            }
        );
        let audit_source = source(CrossStreamTelemetryKind::CapabilityAudit, "audit.release.5");
        assert_eq!(
            aggregator.ingest_workflow_batch(&audit_source, &workflow_batch(&[1])),
            Err(CrossStreamTelemetryError::SourceKindMismatch {
                expected: CrossStreamTelemetryKind::Workflow,
                actual: CrossStreamTelemetryKind::CapabilityAudit,
            })
        );

        let oversized = WorkflowEventBatch::new(
            (1..=u64::try_from(MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS + 1)
                .expect("batch capacity fits in u64"))
                .map(|sequence| {
                    WorkflowEventRecord::new(sequence, WorkflowEvent::Started { plan_id: 1 })
                        .expect("workflow event is valid")
                })
                .collect(),
            u64::try_from(MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS + 2)
                .expect("next source cursor fits in u64"),
        )
        .expect("oversized workflow batch is source-valid");
        assert_eq!(
            aggregator.ingest_workflow_batch(&workflow_source, &oversized),
            Err(CrossStreamTelemetryError::BatchTooLarge {
                actual: MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS + 1,
                maximum: MAX_CROSS_STREAM_TELEMETRY_BATCH_EVENTS,
            })
        );
    }
}
