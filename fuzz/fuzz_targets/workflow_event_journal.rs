#![no_main]

use std::num::NonZeroUsize;

use libfuzzer_sys::fuzz_target;
use splash_workflow::{
    durable_events::WorkflowEventJournal, WorkflowEvent, WorkflowEventBatch, WorkflowEventRecord,
    MAX_DURABLE_WORKFLOW_EVENTS, MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES,
};

fuzz_target!(|data: &[u8]| {
    let Ok(document) = std::str::from_utf8(data) else {
        return;
    };
    if document.len() > MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES {
        return;
    }

    let capacity = NonZeroUsize::new(MAX_DURABLE_WORKFLOW_EVENTS)
        .expect("the durable workflow event cap is nonzero");
    let Ok(journal) = WorkflowEventJournal::from_json_with_capacity(document, capacity) else {
        return;
    };

    let encoded = journal
        .to_json()
        .expect("a bounded decoded event journal must re-encode");
    assert!(encoded.len() <= MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES);
    let decoded = WorkflowEventJournal::from_json_with_capacity(&encoded, capacity)
        .expect("an event journal's current-format encoding must decode");
    assert_eq!(decoded, journal);

    if journal.next_sequence() == u64::MAX {
        return;
    }
    let sequence = journal.next_sequence();
    let appended_event = WorkflowEventRecord::new(sequence, WorkflowEvent::Started { plan_id: 1 })
        .expect("the fixed fuzz event is valid");
    let batch = WorkflowEventBatch::new(vec![appended_event], sequence + 1)
        .expect("one fixed event forms a contiguous batch");
    let mut appended = journal.clone();
    assert_eq!(
        appended
            .append_batch(&batch, capacity)
            .expect("a batch beginning at the current cursor appends"),
        1
    );
    let encoded = appended
        .to_json()
        .expect("an appended bounded event journal must re-encode");
    assert!(encoded.len() <= MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES);
    let restored = WorkflowEventJournal::from_json_with_capacity(&encoded, capacity)
        .expect("an appended event journal must round-trip");
    assert_eq!(restored, appended);
});
