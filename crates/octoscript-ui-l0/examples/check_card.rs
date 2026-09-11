fn main() {
    let path = std::env::args().nth(1).expect("card");
    let card = std::fs::read_to_string(&path).expect("read");
    let r = octoscript_ui_l0::check_ui_l0_named("activity", &card);
    println!("  valid = {}  level = {:?}", r.valid, r.level);
    for d in &r.diagnostics {
        println!("  {}:{} {}", d.line, d.column, d.message);
    }
}
