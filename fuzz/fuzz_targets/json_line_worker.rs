#![no_main]

use std::io::{BufReader, Cursor};

use libfuzzer_sys::fuzz_target;
use splash_capabilities::json_line_worker::{
    JsonLineWorkerChannel, WorkerFrameChannel, MAX_WIRE_FRAME_BYTES,
};

const MAX_FUZZ_INPUT_BYTES: usize = MAX_WIRE_FRAME_BYTES + 2;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let (control, frame) = data
        .split_first()
        .map_or((0, &[][..]), |(control, rest)| (*control, rest));
    let mut bytes = frame.to_vec();
    if control & 1 != 0 {
        bytes.push(b'\n');
    }
    let buffer_capacity = usize::from((control >> 1) & 0x3f).saturating_add(1);
    let reader = BufReader::with_capacity(buffer_capacity, Cursor::new(bytes));
    let mut channel = JsonLineWorkerChannel::new(reader, Vec::new());

    let first = channel.receive_frame();
    if first.is_err() {
        assert!(channel.is_poisoned());
        return;
    }

    let second = channel.receive_frame();
    if second.is_err() {
        assert!(channel.is_poisoned());
    }
});
