#![no_main]

use libfuzzer_sys::fuzz_target;

// The LSP source is formatted in its owning package rather than by this
// standalone fuzz manifest.
#[rustfmt::skip]
#[allow(dead_code)]
#[path = "../../crates/splash-lsp/src/main.rs"]
mod splash_lsp;

const MAX_FUZZ_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }
    if let Ok(settings) = serde_json::from_slice::<serde_json::Value>(data) {
        splash_lsp::fuzz_exercise_advisory_configuration(&settings);
    }

    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };

    splash_lsp::fuzz_exercise_document(source);
});
