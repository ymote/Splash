//! Reproductions from the September 2026 language review (#9–#18).
use serde_json::{json, Value};
use splash_core::{ExecutionLimits, Runtime, RuntimeError, RuntimeJsonError};

fn evaluate(source: &str) -> Value {
    let mut runtime = Runtime::default();
    let result = runtime
        .eval(source)
        .unwrap_or_else(|e| panic!("{source}: {e:?}"));
    assert!(result.completed(), "{source}: {:?}", result.diagnostics);
    runtime
        .script_value_as_json(result.value, 65536, 64)
        .unwrap()
}

#[test]
fn cyclic_and_shared_graph_equality_terminates() {
    // Run the crash reproduction in a child so a future stack overflow or
    // runaway native comparison produces a bounded, ordinary test failure.
    const CHILD: &str = "SPLASH_EQUALITY_REGRESSION_CHILD";
    if std::env::var_os(CHILD).is_some() {
        for source in [
            "let a=[nil];a[0]=a;let b=[nil];b[0]=b;a==b",
            "let a={next:nil};a.next=a;let b={next:nil};b.next=b;a==b",
            "let a=[0];let b=[0];let i=0;while i<29 {a=[a,a];b=[b,b];i+=1;};a==b",
            "let a=[0];let b=[0];let i=0;while i<1000 {a=[a];b=[b];i+=1;};a==b",
        ] {
            assert_eq!(evaluate(source), json!(true));
        }
        assert_eq!(
            evaluate("let a={next:nil,tag:1};a.next=a;let b={next:nil,tag:2};b.next=b;a!=b"),
            json!(true)
        );
        return;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cyclic_and_shared_graph_equality_terminates",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("equality exceeded five seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn native_equality_consumes_instruction_fuel_and_cannot_be_caught() {
    let mut runtime = Runtime::with_limits(
        (),
        (),
        ExecutionLimits {
            instruction_limit: 512,
            budget_sample_interval: 1,
            ..Default::default()
        },
    )
    .unwrap();
    let result = runtime.eval("use mod.std.array; let a=array.range(0,1000);let b=array.range(0,1000);try {a==b;} catch {true;}").unwrap();
    assert!(!result.completed());
    assert!(
        result.diagnostics.iter().any(|d| d.contains("equality")),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn equality_has_an_independent_native_work_ceiling() {
    let mut runtime = Runtime::with_limits(
        (),
        (),
        ExecutionLimits {
            instruction_limit: 1_000_000,
            soft_timeout: std::time::Duration::from_secs(5),
            hard_timeout: std::time::Duration::from_secs(5),
            ..Default::default()
        },
    )
    .unwrap();
    let values = json!((0..40_000).collect::<Vec<_>>());
    runtime.set_json_global("a", &values, 512_000, 64).unwrap();
    runtime.set_json_global("b", &values, 512_000, 64).unwrap();
    let result = runtime.eval("try {a==b;} catch {true;}").unwrap();
    assert!(!result.completed());
    assert!(result.diagnostics.iter().any(|d| d.contains("equality")));
}

#[test]
fn uncaught_errors_stop_and_caught_errors_recover() {
    for source in [
        "use mod.std;std.assert(false);42",
        "missing;42",
        "nil();42",
        "use mod.std;fn f(){std.assert(false);return 7;};f();42",
    ] {
        let mut runtime = Runtime::default();
        let result = runtime.eval(source).unwrap();
        assert!(!result.completed(), "{source}");
        assert!(!result.diagnostics.is_empty());
        let next = runtime.eval("42").unwrap();
        assert!(next.completed(), "{:?}", next.diagnostics);
    }
    assert_eq!(
        evaluate("use mod.std;fn f(){std.assert(false);return 7;};try {f();} catch {42;}"),
        json!(42)
    );
}

#[test]
fn logical_precedence_matches_boolean_algebra_and_skips_effects() {
    for a in [false, true] {
        for b in [false, true] {
            for c in [false, true] {
                assert_eq!(evaluate(&format!("{a} || {b} && {c}")), json!(a || b && c));
                assert_eq!(evaluate(&format!("{a} && {b} || {c}")), json!(a && b || c));
            }
        }
    }
    assert_eq!(evaluate("let n=0;true||false&&(n=1);n"), json!(0));
    assert_eq!(
        evaluate("[true == 2 > 1, false != 2 > 1, 1 < 2 == true]"),
        json!([true, true, true])
    );
}

#[test]
fn logical_not_does_not_depend_on_number_storage() {
    assert_eq!(
        evaluate("[!1,!(1+0),!0,!(0+0),!(-1),!true,!false,!nil]"),
        json!([false, false, true, true, false, false, true, true])
    );
}

#[test]
fn conditional_block_values_survive_statement_separators() {
    for source in [
        "let x=if true {1;} else {2;};x",
        "let x=if false {1;} else {2;};x-1",
        "let x=if true {\n1\n} else {\n2\n}\nx",
        "let x=if true {\r\n1\r\n} else {\r\n2\r\n}\r\nx",
        "let x=if true {1; /* tail */ ;} else {2;};x",
        "let x=if true {if false {0;} else {1;};} else {2;};x",
        "let x=if true {try {1;} catch {2;};} else {3;};x",
    ] {
        assert_eq!(evaluate(source), json!(1), "{source}");
    }
    for source in [
        "if true {} else {1;}",
        "if true {let a=1;} else {2;}",
        "if false {1;} else {}",
    ] {
        assert_eq!(evaluate(source), Value::Null, "{source}");
    }
}

#[test]
fn invalid_array_indices_never_read_or_mutate_element_zero() {
    for index in ["-1", "0.9", "nil", "true", "\"x\"", "\"0\"", "0/0"] {
        assert_eq!(
            evaluate(&format!(
                "try {{[10,20][{index}];}} catch {{\"bad index\";}}"
            )),
            json!("bad index")
        );
        for operation in ["=99", "+=1", "-=1", "*=2", "/=2"] {
            assert_eq!(
                evaluate(&format!(
                    "let a=[10,20];try {{a[{index}]{operation};nil;}} catch {{nil;}};a"
                )),
                json!([10, 20]),
                "{index}{operation}"
            );
        }
    }
    assert_eq!(
        evaluate("let a=[10,20];a[1.0]=30;[a[0],a[1+0]]"),
        json!([10, 30])
    );
}

#[test]
fn numeric_string_conversion_is_uniform_and_invalid_text_is_nan() {
    assert_eq!(
        evaluate("[\"2\"-1,\"00000002\"-1,\"12345678\"-1]"),
        json!([1, 1, 12345677])
    );
    for text in ["x", "abcdefgh"] {
        assert_eq!(evaluate(&format!("let n=\"{text}\"-1;n!=n")), json!(true));
    }
}

#[test]
fn json_integer_boundaries_reject_loss_instead_of_rounding() {
    assert_eq!(
        evaluate("use mod.std.json;json.parse(\"[9007199254740991,-9007199254740991]\")"),
        json!([9007199254740991_i64, -9007199254740991_i64])
    );
    for value in [
        "9007199254740992",
        "9007199254740993",
        "-9007199254740993",
        "18446744073709551615",
        "1e20",
    ] {
        assert!(Runtime::default().eval(value).is_err(), "literal {value}");
        assert_eq!(evaluate(&format!("use mod.std.json;try {{json.parse(\"{{\\\"id\\\":{value}}}\");}} catch {{\"unsafe\";}}")), json!("unsafe"));
    }
    let mut runtime = Runtime::default();
    runtime
        .set_json_global("input", &json!({"id":"9007199254740993"}), 65536, 64)
        .unwrap();
    assert!(runtime
        .set_json_global("input", &json!({"id":9007199254740993_u64}), 65536, 64)
        .is_err());
    let unchanged = runtime.eval("input.id").unwrap();
    assert_eq!(
        runtime
            .script_value_as_json(unchanged.value, 65536, 64)
            .unwrap(),
        json!("9007199254740993")
    );
    let result = runtime.eval("9007199254740991+2").unwrap();
    assert_eq!(
        runtime.script_value_as_json(result.value, 65536, 64),
        Err(RuntimeError::JsonData(RuntimeJsonError::UnsafeInteger))
    );
    assert!(splash_core::serialize_bounded_json(&json!(u64::MAX), 65536, 64).is_ok());
}

#[test]
fn direct_vm_logging_is_denied_even_in_compatibility_mode() {
    let mut runtime = Runtime::default();
    assert!(runtime.eval("~\"private marker\"").is_err());
    let result = runtime
        .eval_vm_compatibility("~\"private marker\"")
        .unwrap();
    assert!(!result.completed());
    assert!(result
        .diagnostics
        .iter()
        .any(|d| d.contains("logging is disabled")));
}
