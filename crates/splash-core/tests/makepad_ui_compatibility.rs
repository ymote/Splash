use splash_core::{
    check_syntax,
    vm::{self, parser::ScriptParser, tokenizer::ScriptTokenizer},
};

const MAKEPAD_UI_COUNTER: &str = include_str!("../../../examples/makepad_ui_counter.splash");

#[test]
fn makepad_ui_counter_is_accepted_by_the_vendored_vm_parser() {
    let mut base = vm::ScriptVmBase::new();
    let mut tokenizer = ScriptTokenizer::default();
    tokenizer.tokenize(&format!("{MAKEPAD_UI_COUNTER}\n;"), &mut base.heap);

    let mut parser = ScriptParser::default();
    parser.set_emit_errors(false);
    parser.parse(
        &tokenizer,
        "examples/makepad_ui_counter.splash",
        (0, 0),
        &[],
    );

    assert!(!parser.had_error, "{:?}", parser.diagnostics);
}

#[test]
fn makepad_ui_counter_remains_outside_the_canonical_workflow_profile() {
    let report = check_syntax(MAKEPAD_UI_COUNTER).unwrap();

    assert!(!report.valid, "unexpectedly accepted Makepad UI source");
}
