#![no_main]

use libfuzzer_sys::fuzz_target;
use splash_core::{check_syntax_named, fuzzing, ExecutionLimits};

const MAX_FUZZ_SOURCE_BYTES: usize = 16 * 1024;
const MAX_FUZZ_SYNTAX_TOKENS: usize = 2 * 1024;

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    if source.len() > MAX_FUZZ_SOURCE_BYTES {
        return;
    }

    let limits = ExecutionLimits {
        max_source_bytes: MAX_FUZZ_SOURCE_BYTES,
        max_syntax_tokens: MAX_FUZZ_SYNTAX_TOKENS,
        ..ExecutionLimits::default()
    };
    let profile = fuzzing::check_canonical_profile(source, limits)
        .expect("the fuzz limits are always valid for canonical preflight");
    let full = check_syntax_named("fuzz.splash", source, limits)
        .expect("the fuzz limits are always valid for full syntax checking");

    if profile.valid {
        assert!(
            full.valid,
            "canonical profile accepted source that the VM parser rejected: {source:?}\n{:?}",
            full.diagnostics
        );
    }
});
