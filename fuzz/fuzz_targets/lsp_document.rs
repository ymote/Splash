#![no_main]

use libfuzzer_sys::fuzz_target;

// The LSP source is formatted in its owning package rather than by this
// standalone fuzz manifest.
#[rustfmt::skip]
#[allow(dead_code)]
#[path = "../../crates/splash-lsp/src/main.rs"]
mod splash_lsp;

const MAX_FUZZ_SOURCE_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    if source.len() > MAX_FUZZ_SOURCE_BYTES {
        return;
    }

    splash_lsp::fuzz_exercise_document(source);
});
