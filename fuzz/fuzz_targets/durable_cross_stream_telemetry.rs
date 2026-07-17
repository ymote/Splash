#![no_main]

use std::num::NonZeroUsize;

use libfuzzer_sys::fuzz_target;
use splash_workflow::{
    telemetry::{
        durable::{
            CrossStreamTelemetryJournal, MAX_DURABLE_CROSS_STREAM_TELEMETRY_EVENTS,
            MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES,
        },
        CrossStreamTelemetryKind, CrossStreamTelemetrySource, MAX_CROSS_STREAM_TELEMETRY_SOURCES,
    },
    WorkflowEvent, WorkflowEventBatch, WorkflowEventRecord,
};

fuzz_target!(|data: &[u8]| {
    let Ok(document) = std::str::from_utf8(data) else {
        return;
    };
    if document.len() > MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES {
        return;
    }

    let maximum_capacity = NonZeroUsize::new(MAX_DURABLE_CROSS_STREAM_TELEMETRY_EVENTS)
        .expect("the durable cross-stream telemetry cap is nonzero");
    let Ok(mut journal) =
        CrossStreamTelemetryJournal::from_json_with_capacity(document, maximum_capacity)
    else {
        return;
    };

    let encoded = journal
        .to_json()
        .expect("a bounded decoded cross-stream journal must re-encode");
    assert!(encoded.len() <= MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES);
    let decoded = CrossStreamTelemetryJournal::from_json_with_capacity(&encoded, maximum_capacity)
        .expect("a current-format cross-stream journal encoding must decode");
    assert_eq!(decoded, journal);

    let requested_capacity = usize::from(data.first().copied().unwrap_or_default())
        % MAX_DURABLE_CROSS_STREAM_TELEMETRY_EVENTS
        + 1;
    let requested_capacity = NonZeroUsize::new(requested_capacity)
        .expect("the fuzz-selected durable cross-stream capacity is nonzero");
    let _ = CrossStreamTelemetryJournal::from_json_with_capacity(document, requested_capacity);

    let source =
        CrossStreamTelemetrySource::new(CrossStreamTelemetryKind::Workflow, "workflow.fuzz.append")
            .expect("the fixed fuzz source is valid");
    let source_state = journal.source_state(&source);
    if source_state.is_none() && journal.source_count() == MAX_CROSS_STREAM_TELEMETRY_SOURCES {
        return;
    }
    let source_sequence = source_state.map_or(1, |state| state.next_source_sequence());
    if source_sequence == u64::MAX || journal.next_aggregate_sequence() == u64::MAX {
        return;
    }

    let event = WorkflowEventRecord::new(source_sequence, WorkflowEvent::Started { plan_id: 1 })
        .expect("the fixed fuzz workflow event is valid");
    let batch = WorkflowEventBatch::new(vec![event], source_sequence + 1)
        .expect("one fixed fuzz workflow event is contiguous");
    assert_eq!(
        journal
            .ingest_workflow_batch(&source, &batch, maximum_capacity)
            .expect("a batch at the persisted source cursor appends"),
        1
    );
    let encoded = journal
        .to_json()
        .expect("an extended cross-stream journal must re-encode");
    assert!(encoded.len() <= MAX_DURABLE_CROSS_STREAM_TELEMETRY_JOURNAL_BYTES);
    let restored = CrossStreamTelemetryJournal::from_json_with_capacity(&encoded, maximum_capacity)
        .expect("an extended cross-stream journal must round-trip");
    assert_eq!(restored, journal);
});
