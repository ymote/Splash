#![no_main]

use libfuzzer_sys::fuzz_target;
use splash_core::{
    check_syntax_named, check_vm_compatibility_named, format_source_named, fuzzing,
    is_canonical_identifier, lexical_completion_report_named, lexical_symbol_report_named,
    module_import_report_named, tool_call_hint_report_named, top_level_declarations_named,
    ExecutionLimits, LexicalCompletionReport, LexicalSymbol, ModuleImportReport, RuntimeError,
    ToolCallHint, TopLevelDeclaration, TopLevelDeclarationKind, MAX_LEXICAL_COMPLETION_SITES,
    MAX_LEXICAL_SYMBOL_OCCURRENCES, MAX_MODULE_IMPORTS, MAX_SYNTAX_DIAGNOSTICS,
    MAX_TOOL_CALL_HINTS,
};

const MAX_FUZZ_SOURCE_BYTES: usize = 16 * 1024;
const MAX_FUZZ_SYNTAX_TOKENS: usize = 2 * 1024;
const MAX_FUZZ_SYNTAX_NESTING: usize = 64;

fuzz_target!(|data: &[u8]| {
    let Ok(unbounded_source) = std::str::from_utf8(data) else {
        return;
    };
    if unbounded_source.len() > MAX_FUZZ_SOURCE_BYTES {
        return;
    }

    let limits = fuzz_limits(data);
    let source = bounded_prefix(unbounded_source, limits.max_source_bytes);
    let profile = fuzzing::check_canonical_profile(source, limits)
        .expect("the fuzz limits are always valid for canonical preflight");
    let full = check_syntax_named("fuzz.splash", source, limits)
        .expect("the fuzz limits are always valid for full syntax checking");
    let compatibility = check_vm_compatibility_named("fuzz.splash", source, limits)
        .expect("the fuzz limits are always valid for VM compatibility checking");
    assert!(compatibility.diagnostics.len() <= MAX_SYNTAX_DIAGNOSTICS);
    let completion_report = lexical_completion_report_named("fuzz.splash", source, limits)
        .expect("the fuzz limits are always valid for bounded completion metadata");
    assert_completion_invariants(source, &completion_report);
    let import_report = module_import_report_named("fuzz.splash", source, limits)
        .expect("the fuzz limits are always valid for bounded import metadata");
    assert_module_import_invariants(source, &import_report);

    if profile.valid {
        assert!(
            compatibility.valid,
            "canonical profile accepted source that the VM compatibility preflight rejected: {source:?}\n{:?}",
            compatibility.diagnostics
        );
        assert!(
            full.valid,
            "canonical profile accepted source that the VM parser rejected: {source:?}\n{:?}",
            full.diagnostics
        );

        let declarations = top_level_declarations_named("fuzz.splash", source, limits)
            .expect("the fuzz limits are always valid for bounded outlining");
        assert_outline_invariants(source, &declarations);

        let tool_call_report = tool_call_hint_report_named("fuzz.splash", source, limits)
            .expect("the fuzz limits are always valid for bounded tool-call outlining");
        assert!(tool_call_report.hints.len() <= MAX_TOOL_CALL_HINTS);
        if tool_call_report.truncated {
            assert_eq!(tool_call_report.hints.len(), MAX_TOOL_CALL_HINTS);
        }
        assert_tool_call_hint_invariants(source, &tool_call_report.hints);

        let lexical_report = lexical_symbol_report_named("fuzz.splash", source, limits)
            .expect("the fuzz limits are always valid for bounded lexical indexing");
        let lexical_occurrences = lexical_report.symbols.len()
            + lexical_report
                .symbols
                .iter()
                .map(|symbol| symbol.references.len())
                .sum::<usize>();
        assert!(lexical_occurrences <= MAX_LEXICAL_SYMBOL_OCCURRENCES);
        if lexical_report.truncated {
            assert_eq!(lexical_occurrences, MAX_LEXICAL_SYMBOL_OCCURRENCES);
        }
        assert_lexical_symbol_invariants(source, &lexical_report.symbols);
        assert_eq!(completion_report.symbols, lexical_report.symbols);
        assert_eq!(
            completion_report.symbols_truncated,
            lexical_report.truncated
        );
        assert_eq!(completion_report.valid_prefix_end_byte, source.len());
        assert_eq!(import_report.valid_prefix_end_byte, source.len());

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

fn fuzz_limits(data: &[u8]) -> ExecutionLimits {
    match data.first().copied().unwrap_or_default() % 4 {
        0 => ExecutionLimits {
            max_source_bytes: 64,
            max_syntax_tokens: 8,
            max_syntax_nesting: 2,
            ..ExecutionLimits::default()
        },
        1 => ExecutionLimits {
            max_source_bytes: 512,
            max_syntax_tokens: 64,
            max_syntax_nesting: 4,
            ..ExecutionLimits::default()
        },
        2 => ExecutionLimits {
            max_source_bytes: 4 * 1024,
            max_syntax_tokens: 512,
            max_syntax_nesting: 16,
            ..ExecutionLimits::default()
        },
        _ => ExecutionLimits {
            max_source_bytes: MAX_FUZZ_SOURCE_BYTES,
            max_syntax_tokens: MAX_FUZZ_SYNTAX_TOKENS,
            max_syntax_nesting: MAX_FUZZ_SYNTAX_NESTING,
            ..ExecutionLimits::default()
        },
    }
}

fn bounded_prefix(source: &str, maximum_bytes: usize) -> &str {
    let mut end = source.len().min(maximum_bytes);
    while end > 0 && !source.is_char_boundary(end) {
        end -= 1;
    }
    &source[..end]
}

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

fn assert_module_import_invariants(source: &str, report: &ModuleImportReport) {
    assert!(report.imports.len() <= MAX_MODULE_IMPORTS);
    if report.truncated {
        assert_eq!(report.imports.len(), MAX_MODULE_IMPORTS);
    }
    assert!(report.valid_prefix_end_byte <= source.len());
    assert!(source.is_char_boundary(report.valid_prefix_end_byte));

    let mut previous_start_byte = 0_usize;
    for import in &report.imports {
        assert!(
            import.path.len() >= 2 && import.path.first().is_some_and(|segment| segment == "mod"),
            "import path is not a complete mod path: {import:?}"
        );
        assert!(
            previous_start_byte <= import.path_span.start_byte
                && import.path_span.start_byte < import.path_span.end_byte
                && import.path_span.end_byte <= report.valid_prefix_end_byte,
            "import path span is unordered or exceeds the safe prefix: {import:?}"
        );
        assert!(
            import.path_span.start_byte <= import.binding.start_byte
                && import.binding.start_byte < import.binding.end_byte
                && import.binding.end_byte == import.path_span.end_byte,
            "import binding span is not the final path segment: {import:?}"
        );
        for offset in [
            import.path_span.start_byte,
            import.path_span.end_byte,
            import.binding.start_byte,
            import.binding.end_byte,
        ] {
            assert!(
                source.is_char_boundary(offset),
                "import span is not a UTF-8 boundary: {import:?}"
            );
        }
        assert_eq!(
            &source[import.path_span.start_byte..import.path_span.end_byte],
            import.path.join("."),
            "import path span does not match its segments: {import:?}"
        );
        assert_eq!(
            &source[import.binding.start_byte..import.binding.end_byte],
            import.path.last().expect("complete import has a binding"),
            "import binding span does not match its final segment: {import:?}"
        );
        assert!(
            import
                .path
                .iter()
                .all(|segment| is_canonical_identifier(segment)),
            "import path contains a non-canonical identifier: {import:?}"
        );
        previous_start_byte = import.path_span.start_byte;
    }
}

fn assert_tool_call_hint_invariants(source: &str, hints: &[ToolCallHint]) {
    let mut previous_start_byte = 0_usize;

    for hint in hints {
        assert!(
            previous_start_byte <= hint.callee_start_byte
                && hint.callee_start_byte <= hint.callee_end_byte
                && hint.callee_end_byte <= source.len(),
            "tool-call hint has unordered or out-of-bounds callee span: {hint:?}"
        );
        for offset in [hint.callee_start_byte, hint.callee_end_byte] {
            assert!(
                source.is_char_boundary(offset),
                "tool-call callee span is not a UTF-8 boundary: {hint:?}"
            );
        }
        assert_eq!(
            &source[hint.callee_start_byte..hint.callee_end_byte],
            format!("tool.{}", hint.kind.as_str()),
            "tool-call callee span does not match its method: {hint:?}"
        );
        assert!(
            hint.line >= 1 && hint.column >= 1,
            "tool-call hint has a zero-based source location: {hint:?}"
        );

        match (hint.literal_name_start_byte, hint.literal_name_end_byte) {
            (Some(start_byte), Some(end_byte)) => {
                assert!(
                    hint.callee_end_byte <= start_byte
                        && start_byte <= end_byte
                        && end_byte <= source.len(),
                    "tool-call literal span is unordered or out of bounds: {hint:?}"
                );
                assert!(
                    source.is_char_boundary(start_byte) && source.is_char_boundary(end_byte),
                    "tool-call literal span is not a UTF-8 boundary: {hint:?}"
                );
                let literal = &source[start_byte..end_byte];
                assert!(
                    literal.starts_with('"') && literal.ends_with('"'),
                    "tool-call literal span is not a string literal: {hint:?}"
                );
            }
            (None, None) => assert!(
                hint.literal_name.is_none(),
                "a decoded tool name must have a literal span: {hint:?}"
            ),
            _ => panic!("tool-call literal span is only partially present: {hint:?}"),
        }

        previous_start_byte = hint.callee_start_byte;
    }
}

fn assert_lexical_symbol_invariants(source: &str, symbols: &[LexicalSymbol]) {
    let mut previous_definition_start = 0_usize;
    let mut all_spans = Vec::new();

    for symbol in symbols {
        assert!(
            previous_definition_start <= symbol.definition.start_byte
                && symbol.definition.start_byte < symbol.definition.end_byte
                && symbol.definition.end_byte <= source.len(),
            "lexical definition span is unordered or out of bounds: {symbol:?}"
        );
        assert_symbol_span(source, symbol, symbol.definition);
        assert!(
            symbol.definition.end_byte <= symbol.visibility_start_byte
                && symbol.visibility_start_byte <= symbol.visibility_end_byte
                && symbol.visibility_end_byte <= source.len(),
            "lexical visibility interval is unordered or out of bounds: {symbol:?}"
        );
        assert!(
            source.is_char_boundary(symbol.visibility_start_byte)
                && source.is_char_boundary(symbol.visibility_end_byte),
            "lexical visibility interval is not on UTF-8 boundaries: {symbol:?}"
        );
        all_spans.push(symbol.definition);
        let mut previous_reference_start = symbol.definition.end_byte;
        for reference in &symbol.references {
            assert!(
                previous_reference_start <= reference.start_byte
                    && reference.start_byte < reference.end_byte
                    && reference.end_byte <= source.len(),
                "lexical reference span is unordered, empty, or out of bounds: {symbol:?}"
            );
            assert_symbol_span(source, symbol, *reference);
            assert!(
                symbol.visibility_start_byte <= reference.start_byte
                    && reference.end_byte <= symbol.visibility_end_byte,
                "lexical reference falls outside its binding visibility: {symbol:?}"
            );
            all_spans.push(*reference);
            previous_reference_start = reference.start_byte;
        }
        previous_definition_start = symbol.definition.start_byte;
    }

    all_spans.sort_unstable_by_key(|span| span.start_byte);
    for spans in all_spans.windows(2) {
        assert!(
            spans[0].end_byte <= spans[1].start_byte,
            "lexical symbol occurrences overlap: {spans:?}"
        );
    }
}

fn assert_completion_invariants(source: &str, report: &LexicalCompletionReport) {
    let occurrences = report.symbols.len()
        + report
            .symbols
            .iter()
            .map(|symbol| symbol.references.len())
            .sum::<usize>();
    assert!(occurrences <= MAX_LEXICAL_SYMBOL_OCCURRENCES);
    if report.symbols_truncated {
        assert_eq!(occurrences, MAX_LEXICAL_SYMBOL_OCCURRENCES);
    }
    assert!(report.sites.len() <= MAX_LEXICAL_COMPLETION_SITES);
    if report.sites_truncated {
        assert_eq!(report.sites.len(), MAX_LEXICAL_COMPLETION_SITES);
    }
    assert!(report.valid_prefix_end_byte <= source.len());
    assert!(source.is_char_boundary(report.valid_prefix_end_byte));
    assert_lexical_symbol_invariants(source, &report.symbols);

    let mut previous_start_byte = 0_usize;
    for site in &report.sites {
        assert!(
            previous_start_byte <= site.start_byte
                && site.start_byte < site.end_byte
                && site.end_byte <= source.len(),
            "completion site is unordered, empty, or out of bounds: {site:?}"
        );
        assert!(
            source.is_char_boundary(site.start_byte) && source.is_char_boundary(site.end_byte),
            "completion site is not on UTF-8 boundaries: {site:?}"
        );
        assert!(
            is_canonical_identifier(&source[site.start_byte..site.end_byte]),
            "completion site is not a canonical identifier: {site:?}"
        );
        previous_start_byte = site.start_byte;
    }
}

fn assert_symbol_span(source: &str, symbol: &LexicalSymbol, span: splash_core::SourceSpan) {
    assert!(
        source.is_char_boundary(span.start_byte) && source.is_char_boundary(span.end_byte),
        "lexical symbol span is not a UTF-8 boundary: {symbol:?}"
    );
    assert_eq!(
        &source[span.start_byte..span.end_byte],
        symbol.name,
        "lexical symbol span does not match its name"
    );
}
