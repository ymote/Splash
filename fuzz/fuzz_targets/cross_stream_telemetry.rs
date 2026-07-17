#![no_main]

use std::num::NonZeroUsize;

use libfuzzer_sys::fuzz_target;
use splash_capabilities::{CapabilityRuntime, ToolPolicy};
use splash_workflow::{
    telemetry::{
        CrossStreamTelemetryAggregator, CrossStreamTelemetryCursorError, CrossStreamTelemetryError,
        CrossStreamTelemetryKind, CrossStreamTelemetrySource,
    },
    WorkflowEvent, WorkflowEventBatch, WorkflowEventRecord,
};

const MAX_FUZZ_INPUT_BYTES: usize = 4 * 1024;
const MAX_FUZZ_WORKFLOW_RECORDS: usize = 8;
const MAX_FUZZ_AUDIT_EVENTS: usize = 4;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    // Exercise hostile source metadata separately from the valid fixed
    // sources that drive the aggregation invariants below.
    let invalid_source_end = data.len().min(129);
    let _ = CrossStreamTelemetrySource::new(
        CrossStreamTelemetryKind::Workflow,
        String::from_utf8_lossy(&data[..invalid_source_end]).into_owned(),
    );

    let workflow_start = u64::from(byte(data, 0) % 16) + 1;
    let workflow_records = usize::from(byte(data, 1) % MAX_FUZZ_WORKFLOW_RECORDS as u8) + 1;
    let workflow_batch = make_workflow_batch(workflow_start, workflow_records);

    let audit_events = usize::from(byte(data, 2) % MAX_FUZZ_AUDIT_EVENTS as u8) + 1;
    let audit_batch = audit_batch(audit_events);

    let aggregate_capacity = NonZeroUsize::new(usize::from(byte(data, 3) % 4) + 1)
        .expect("fuzz-selected aggregate capacity is nonzero");
    let mut aggregator = CrossStreamTelemetryAggregator::with_event_capacity(aggregate_capacity)
        .expect("small aggregate capacity is valid");

    let audit_source = source(CrossStreamTelemetryKind::CapabilityAudit, "audit.fuzz");
    let workflow_source = source(CrossStreamTelemetryKind::Workflow, "workflow.fuzz");
    let unregistered_source = source(CrossStreamTelemetryKind::Workflow, "workflow.unregistered");

    // A source that begins after one must be made explicit. The rejected input
    // does not create a source entry or consume any aggregate capacity.
    let skipped_batch = make_workflow_batch(2, 1);
    assert_eq!(
        aggregator.ingest_workflow_batch(&unregistered_source, &skipped_batch),
        Err(CrossStreamTelemetryError::SourceStartRequiresRegistration { first_sequence: 2 })
    );
    assert_eq!(aggregator.source_count(), 0);

    // A telemetry family mismatch is rejected before source registration.
    assert!(matches!(
        aggregator.ingest_workflow_batch(&audit_source, &workflow_batch),
        Err(CrossStreamTelemetryError::SourceKindMismatch { .. })
    ));

    if workflow_start != 1 {
        let state = aggregator
            .register_source_at(workflow_source.clone(), workflow_start)
            .expect("a bounded explicit source segment is valid");
        assert_eq!(state.segment_start_sequence(), workflow_start);
        assert_eq!(state.next_source_sequence(), workflow_start);
    }

    if byte(data, 4) & 1 == 0 {
        aggregator
            .ingest_audit_batch(&audit_source, &audit_batch)
            .expect("first audit batch is contiguous");
        aggregator
            .ingest_workflow_batch(&workflow_source, &workflow_batch)
            .expect("first workflow batch is contiguous");
    } else {
        aggregator
            .ingest_workflow_batch(&workflow_source, &workflow_batch)
            .expect("first workflow batch is contiguous");
        aggregator
            .ingest_audit_batch(&audit_source, &audit_batch)
            .expect("first audit batch is contiguous");
    }

    assert_eq!(
        aggregator
            .source_state(&workflow_source)
            .expect("workflow source is retained")
            .next_source_sequence(),
        workflow_batch.next_sequence()
    );
    assert_eq!(
        aggregator
            .source_state(&audit_source)
            .expect("audit source is retained")
            .next_source_sequence(),
        audit_batch.next_event_sequence()
    );

    assert!(matches!(
        aggregator.ingest_workflow_batch(&workflow_source, &workflow_batch),
        Err(CrossStreamTelemetryError::SourceSequenceReplay { .. })
    ));
    let gap_start = workflow_batch.next_sequence() + 1;
    let gap_batch = make_workflow_batch(gap_start, 1);
    assert_eq!(
        aggregator.ingest_workflow_batch(&workflow_source, &gap_batch),
        Err(CrossStreamTelemetryError::SourceSequenceGap {
            expected: workflow_batch.next_sequence(),
            actual: gap_start,
        })
    );

    let ingested = audit_batch.events().len() + workflow_batch.records().len();
    let retained = ingested.min(aggregate_capacity.get());
    assert_eq!(aggregator.events().len(), retained);
    assert_eq!(
        aggregator.dropped_events(),
        u64::try_from(ingested - retained).expect("small fuzz count fits in u64")
    );

    let first_aggregate_sequence =
        u64::try_from(ingested - retained + 1).expect("small fuzz count fits in u64");
    let batch = aggregator
        .events_since(first_aggregate_sequence)
        .expect("the earliest retained aggregate cursor exports");
    assert_eq!(batch.records().len(), retained);
    assert_eq!(
        batch.next_aggregate_sequence(),
        u64::try_from(ingested + 1).expect("small fuzz count fits in u64")
    );
    for (offset, record) in batch.records().iter().enumerate() {
        assert_eq!(
            record.aggregate_sequence(),
            first_aggregate_sequence + u64::try_from(offset).expect("small fuzz offset fits")
        );
        assert_eq!(record.source().kind(), record.event().kind());
    }
    if ingested > retained {
        assert!(matches!(
            aggregator.events_since(1),
            Err(CrossStreamTelemetryCursorError::Evicted { .. })
        ));
    }
    assert!(matches!(
        aggregator.events_since(u64::try_from(ingested + 2).expect("small fuzz count fits in u64")),
        Err(CrossStreamTelemetryCursorError::Ahead { .. })
    ));

    let workflow_next = workflow_batch.next_sequence();
    aggregator.clear_events();
    assert!(aggregator.events().is_empty());
    assert!(aggregator
        .events_since(u64::try_from(ingested + 1).expect("small fuzz count fits in u64"))
        .expect("the current aggregate cursor remains valid")
        .is_empty());
    assert_eq!(
        aggregator
            .source_state(&workflow_source)
            .expect("clear retains workflow source cursor")
            .next_source_sequence(),
        workflow_next
    );

    let continuation = make_workflow_batch(workflow_next, 1);
    aggregator
        .ingest_workflow_batch(&workflow_source, &continuation)
        .expect("clear does not reset source-contiguity requirements");
    assert_eq!(aggregator.events().len(), 1);
    assert_eq!(aggregator.events()[0].source_sequence(), workflow_next);
});

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or_default()
}

fn source(kind: CrossStreamTelemetryKind, id: &str) -> CrossStreamTelemetrySource {
    CrossStreamTelemetrySource::new(kind, id).expect("fixed fuzz source ID is valid")
}

fn make_workflow_batch(first_sequence: u64, count: usize) -> WorkflowEventBatch {
    let records = (0..count)
        .map(|offset| {
            let sequence = first_sequence + u64::try_from(offset).expect("small fuzz offset fits");
            WorkflowEventRecord::new(sequence, WorkflowEvent::Started { plan_id: 1 })
                .expect("fixed workflow event is valid")
        })
        .collect();
    WorkflowEventBatch::new(
        records,
        first_sequence + u64::try_from(count).expect("small fuzz count fits"),
    )
    .expect("fixed workflow batch is contiguous")
}

fn audit_batch(event_count: usize) -> splash_capabilities::AuditEventBatch {
    let mut runtime = CapabilityRuntime::default();
    let mut policy = ToolPolicy::new("text.echo");
    policy.max_calls = MAX_FUZZ_AUDIT_EVENTS;
    runtime
        .register_tool(policy, |request| Ok(request.input.clone()))
        .expect("fixed fuzz adapter registers");
    for _ in 0..event_count {
        let mut report = runtime
            .eval("use mod.tool\ntool.call(\"text.echo\", \"fuzz\")")
            .expect("fixed fuzz source evaluates");
        for _ in 0..2 {
            if report.completed() {
                break;
            }
            let pumped = runtime
                .pump()
                .expect("fixed local adapter pump resumes a valid evaluation");
            let Some(resumed) = pumped.resumed.into_iter().last() else {
                break;
            };
            report = resumed;
        }
        assert!(report.completed(), "{:?}", report.diagnostics);
    }
    runtime
        .audit_since(1)
        .expect("fresh fixed capability audit is retained")
}
