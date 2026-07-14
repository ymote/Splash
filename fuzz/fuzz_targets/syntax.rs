#![no_main]

use libfuzzer_sys::fuzz_target;
use splash_core::{
    check_syntax_named, format_source_named, fuzzing, top_level_declarations_named,
    ExecutionLimits, RuntimeError, TopLevelDeclaration, TopLevelDeclarationKind,
};

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

        let declarations = top_level_declarations_named("fuzz.splash", source, limits)
            .expect("the fuzz limits are always valid for bounded outlining");
        assert_outline_invariants(source, &declarations);

        match format_source_named("fuzz.splash", source, limits) {
            Ok(formatted) => {
                let formatted_limits = ExecutionLimits {
                    max_source_bytes: formatted.len().max(1),
                    ..limits
                };
                let formatted_report =
                    check_syntax_named("formatted-fuzz.splash", &formatted, formatted_limits)
                        .expect("formatted source uses valid fuzz limits");
                assert!(
                    formatted_report.valid,
                    "formatter emitted source rejected by the profile or VM: {formatted:?}\n{:?}",
                    formatted_report.diagnostics
                );
                assert_eq!(
                    format_source_named("formatted-fuzz.splash", &formatted, formatted_limits)
                        .expect("valid formatted source must remain formatable"),
                    formatted,
                    "formatter output is not idempotent"
                );
            }
            Err(RuntimeError::FormattedSourceTooLarge { .. }) => {}
            Err(error) => panic!("formatter rejected canonical source: {error}"),
        }
    }
});

fn assert_outline_invariants(source: &str, declarations: &[TopLevelDeclaration]) {
    let mut previous_end_byte = 0_usize;

    for declaration in declarations {
        assert!(
            previous_end_byte <= declaration.declaration_start_byte,
            "top-level declaration spans overlap: {declarations:?}"
        );
        assert!(
            declaration.declaration_start_byte <= declaration.selection_start_byte
                && declaration.selection_start_byte <= declaration.selection_end_byte
                && declaration.selection_end_byte <= declaration.declaration_end_byte
                && declaration.declaration_end_byte <= source.len(),
            "outline contains an unordered or out-of-bounds span: {declaration:?}"
        );
        for offset in [
            declaration.declaration_start_byte,
            declaration.selection_start_byte,
            declaration.selection_end_byte,
            declaration.declaration_end_byte,
        ] {
            assert!(
                source.is_char_boundary(offset),
                "outline span is not a UTF-8 boundary: {declaration:?}"
            );
        }
        assert_eq!(
            &source[declaration.selection_start_byte..declaration.selection_end_byte],
            declaration.name,
            "outline selection does not match its declared name"
        );
        let expected_keyword = match declaration.kind {
            TopLevelDeclarationKind::Function => "fn",
            TopLevelDeclarationKind::Let => "let",
        };
        assert!(
            source[declaration.declaration_start_byte..declaration.declaration_end_byte]
                .starts_with(expected_keyword),
            "outline span does not begin with its declaration keyword: {declaration:?}"
        );
        previous_end_byte = declaration.declaration_end_byte;
    }
}
