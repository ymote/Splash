use splash_ui_l0::{check_ui_l0_named, kit, realize, RealizeLimits};

#[test]
fn waypoint_progress_and_instructions_use_the_same_route() {
    let card = r#"
source here sys.gps()
source origin sys.search(query: "Saratoga High School", count: 1, fields: [name, lat, lon])
source dest sys.search(query: "NVIDIA", count: 1, fields: [name, lat, lon])
source stop sys.search(query: "Apple Park", count: 1, fields: [name, lat, lon])
source step sys.step(from_lat: origin.0.lat, from_lon: origin.0.lon,
    to_lat: dest.0.lat, to_lon: dest.0.lon, at_lat: here.lat, at_lon: here.lon,
    via: [stop.0.lat, stop.0.lon], fields: [instruction, remaining, eta])
view root Surface {
    TextBody(text: step.instruction)
    TextCaption(value: step.remaining)
    TextHero(value: step.eta)
    Map(mode: .drive, from: origin, to: dest, via: stop, at: here)
}
"#;
    let checked = check_ui_l0_named("nav", card);
    assert!(checked.valid, "{:?}", checked.diagnostics);
    let report = realize(card, &serde_json::json!({}), RealizeLimits::default());
    let lowered = kit::lower(&report.complete_root().unwrap());
    assert!(lowered.contains("sys.navprog("));
    assert!(lowered.contains("sys.navstep("));
    // Each live instruction asks navstep and navprog about the same waypoint;
    // map geometry needs it too. A direct-route progress value cannot be mixed
    // with a route through the stop.
    assert!(lowered.matches("sys.searchnum(\"Apple Park\", 0, \"lat\")").count() >= 7, "{lowered}");
    assert!(lowered.matches("sys.searchnum(\"Apple Park\", 0, \"lon\")").count() >= 7, "{lowered}");
}
