//! Host-registered theme/component packs. The ledger supplies content and
//! structure; the host owns style tokens, native roles and placement contracts.
//! No filesystem, VM, renderer, or ambient asset access lives in this layer.
use crate::{NodeValue, UiNode};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

fn value(v: &NodeValue) -> Result<Value, String> {
    match v {
        NodeValue::Text(v) | NodeValue::Token(v) => Ok(v.clone().into()),
        NodeValue::Number(v) => serde_json::Number::from_f64(*v)
            .map(Value::Number)
            .ok_or_else(|| "non-finite kit property".into()),
        NodeValue::Bool(v) => Ok((*v).into()),
        _ => Err("unresolved or unsupported kit property".into()),
    }
}

/// Splash uses bare property names; string contents remain JSON escaped.
pub fn literal(v: &Value) -> String {
    match v {
        Value::Object(m) => format!(
            "{{{}}}",
            m.iter()
                .map(|(k, v)| format!("{k}: {}", literal(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Array(a) => format!("[{}]", a.iter().map(literal).collect::<Vec<_>>().join(", ")),
        Value::Null => "nil".into(),
        _ => v.to_string(),
    }
}

pub fn arguments(node: &UiNode) -> String {
    let args: Map<String, Value> = node
        .args
        .iter()
        .filter_map(|(k, v)| value(v).ok().map(|v| (k.clone(), v)))
        .collect();
    literal(&Value::Object(args))
}

pub fn contains(root: &UiNode) -> bool {
    root.kind == "Kit" || root.children.iter().any(contains)
}

fn resolve(v: &Value, tokens: &Value) -> Result<Value, String> {
    if let Some(key) = v.get("$token").and_then(Value::as_str) {
        return tokens
            .get(key)
            .and_then(|t| t.get("value"))
            .cloned()
            .ok_or_else(|| format!("missing kit token {key}"));
    }
    Ok(v.clone())
}

/// Resolve every Kit instance, checking identity, role, props and layout.
/// Unknown references fail the whole card. Children come ONLY from the ledger.
pub fn tree(root: &UiNode, pack: &Value, data: &Value) -> Result<Value, String> {
    if pack["schema_version"] != 1 {
        return Err("unsupported kit schema".into());
    }
    fn visit(
        n: &UiNode,
        pack: &Value,
        data: &Value,
        seen: &mut BTreeSet<String>,
    ) -> Result<Value, String> {
        if n.kind != "Kit" {
            return Err(format!(
                "native pack requires a Kit component, got {}",
                n.kind
            ));
        }
        let args: Map<String, Value> = n
            .args
            .iter()
            .map(|(k, v)| value(v).map(|v| (k.clone(), v)))
            .collect::<Result<_, _>>()?;
        let name = args
            .get("component")
            .and_then(Value::as_str)
            .ok_or("missing component")?;
        let instance = args
            .get("instance")
            .and_then(Value::as_str)
            .ok_or("missing instance")?;
        // A shared compound owns its hierarchy. Its one public identity binds
        // local part names to source-qualified identities in checked host data.
        let id = if let Some(part) = args.get("part") {
            let part = part.as_str().ok_or("invalid kit part")?;
            let parts = &data["$kit"]["instances"][instance]["parts"];
            if parts["p0"] != instance {
                return Err("compound root identity mismatch".into());
            }
            parts[part]
                .as_str()
                .ok_or_else(|| format!("missing kit part {instance}/{part}"))?
        } else {
            instance
        };
        if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || id.is_empty()
            || !seen.insert(id.into())
        {
            return Err(format!("invalid or duplicate kit instance {id}"));
        }
        let component = pack["components"]
            .get(name)
            .ok_or_else(|| format!("unknown kit component {name}"))?;
        let placement = data["$kit"]["placements"]
            .get(id)
            .ok_or_else(|| format!("missing kit placement {id}"))?;
        if placement["component"] != name {
            return Err(format!("component/placement mismatch for {id}"));
        }
        let mut attrs = Map::new();
        for (key, v) in component["style"]
            .as_object()
            .ok_or("missing component style")?
        {
            attrs.insert(key.clone(), resolve(v, &pack["tokens"])?);
        }
        for (key, v) in placement["layout"]
            .as_object()
            .ok_or("missing component layout")?
        {
            if !["x", "y", "w", "h", "src", "image_width", "image_height"].contains(&key.as_str()) {
                return Err(format!("unregistered layout property {key}"));
            }
            if key != "src" && !v.as_f64().is_some_and(|n| n.is_finite()) {
                return Err(format!("invalid layout {key}"));
            }
            attrs.insert(key.clone(), v.clone());
        }
        let props = component["props"]
            .as_object()
            .ok_or("missing component props")?;
        for (key, v) in args
            .iter()
            .filter(|(k, _)| !matches!(k.as_str(), "component" | "instance" | "part"))
        {
            if key == "index" && !v.as_f64().is_some_and(|n| n >= -1. && n.fract() == 0.) {
                return Err("kit index must be an integer >= -1".into());
            }
            let property = props
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{name} has no prop {key}"))?;
            let v = if v.is_boolean() {
                Value::from(i32::from(v.as_bool().unwrap()))
            } else {
                v.clone()
            };
            attrs.insert(property.into(), v);
        }
        for key in props.keys() {
            if !args.contains_key(key) {
                return Err(format!("{name} requires {key}"));
            }
        }
        if !n.children.is_empty() && component["slot"] != true {
            return Err(format!("{name} has no child slot"));
        }
        attrs.insert("id".into(), id.into());
        if component["slot"] == true {
            attrs.insert(
                "c".into(),
                Value::Array(
                    n.children
                        .iter()
                        .map(|n| visit(n, pack, data, seen))
                        .collect::<Result<_, _>>()?,
                ),
            );
        }
        Ok(Value::Object(attrs))
    }
    visit(root, pack, data, &mut BTreeSet::new())
}

pub fn lower(root: &UiNode, pack: &Value, data: &Value) -> Result<String, String> {
    Ok(format!(
        "let node = {}\nnode\n",
        literal(&tree(root, pack, data)?)
    ))
}

/// The standard semantic L0 roles use the same measured theme tokens as the
/// imported variants. Sizes in this older role kit are Makepad points.
pub fn theme_source(pack: &Value) -> String {
    let mappings = [
        ("color.surface.page", "l0_base", 1.),
        ("color.surface.panel", "l0_sheet", 1.),
        ("color.content.primary", "l0_text", 1.),
        ("color.action.primary", "l0_accent", 1.),
        ("typography.body.font_src", "l0_font_src", 1.),
        ("typography.body.size", "font_body", 0.75),
        ("typography.body.size", "font_row", 0.75),
        ("typography.title.size", "font_title", 0.75),
        ("typography.caption.size", "font_caption", 0.75),
        ("shape.surface.radius", "radius_panel", 1.),
    ];
    let mut out = String::new();
    for (token, name, scale) in mappings {
        if let Some(v) = pack["tokens"][token].get("value") {
            let v = if scale != 1. {
                v.as_f64()
                    .map(|n| Value::from(n * scale))
                    .unwrap_or(v.clone())
            } else {
                v.clone()
            };
            out.push_str(&format!("let {name} = {}\n", literal(&v)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (UiNode, Value, Value) {
        let card="theme camo\ncomponent Caption(id: text, label: text) {view Kit(component: \"caption\", instance: id, text: label)}\nview root Caption(id: \"title\", label: \"line 1\\n\\\"quoted\\\" \\u2603\")";
        let report = crate::realize(card, &serde_json::json!({}), Default::default());
        let root = report.complete_root().unwrap().clone();
        let pack = serde_json::json!({"schema_version":1,"tokens":{"ink":{"value":4294967295u64}},
            "components":{"caption":{"style":{"t":"text","color":{"$token":"ink"}},"props":{"text":"text"},"slot":false}}});
        let data = serde_json::json!({"$kit":{"placements":{"title":{"component":"caption","layout":{"x":0,"y":0,"w":100,"h":40}}}}});
        (root, pack, data)
    }
    #[test]
    fn copy_escapes_survive_components_and_theme_tokens_resolve() {
        let (root, pack, data) = fixture();
        let out = tree(&root, &pack, &data).unwrap();
        assert_eq!(out["text"], "line 1\n\"quoted\" ☃");
        assert_eq!(out["color"], 4294967295u64);
        let mut light = pack.clone();
        light["tokens"]["ink"]["value"] = Value::from(4278190080u64);
        assert_eq!(tree(&root, &light, &data).unwrap()["color"], 4278190080u64);
    }
    #[test]
    fn unknown_components_tokens_props_and_placements_fail_closed() {
        let (root, pack, data) = fixture();
        let mut bad = pack.clone();
        bad["tokens"] = serde_json::json!({});
        assert!(tree(&root, &bad, &data)
            .unwrap_err()
            .contains("missing kit token"));
        let mut bad = pack.clone();
        bad["components"] = serde_json::json!({});
        assert!(tree(&root, &bad, &data)
            .unwrap_err()
            .contains("unknown kit component"));
        let mut bad = pack.clone();
        bad["components"]["caption"]["props"] = serde_json::json!({});
        assert!(tree(&root, &bad, &data)
            .unwrap_err()
            .contains("has no prop text"));
        let mut bad = data.clone();
        bad["$kit"]["placements"]["title"]["component"] = "other".into();
        assert!(tree(&root, &pack, &bad).unwrap_err().contains("mismatch"));
        let mut bad = data.clone();
        bad["$kit"]["placements"]["title"]["layout"]["t"] = "image".into();
        assert!(tree(&root, &pack, &bad)
            .unwrap_err()
            .contains("unregistered layout property"));
    }
    #[test]
    fn compound_parts_preserve_identity_and_reject_broken_host_bindings() {
        let (mut root, pack, mut data) = fixture();
        root.args
            .push(("part".into(), NodeValue::Text("p1".into())));
        data["$kit"]["instances"]["title"] =
            serde_json::json!({"parts":{"p0":"title","p1":"caption"}});
        data["$kit"]["placements"]["caption"] = data["$kit"]["placements"]["title"].clone();
        assert_eq!(tree(&root, &pack, &data).unwrap()["id"], "caption");
        let mut bad = data.clone();
        bad["$kit"]["instances"]["title"]["parts"]["p0"] = "someone_else".into();
        assert!(tree(&root, &pack, &bad)
            .unwrap_err()
            .contains("root identity"));
        let mut bad = data.clone();
        bad["$kit"]["instances"]["title"]["parts"]["p1"] = Value::Null;
        assert!(tree(&root, &pack, &bad)
            .unwrap_err()
            .contains("missing kit part"));
        let mut bad = data.clone();
        bad["$kit"]["placements"]["caption"]["component"] = "other".into();
        assert!(tree(&root, &pack, &bad).unwrap_err().contains("mismatch"));
    }
    #[test]
    fn semantic_selection_index_preserves_declared_negative_initial() {
        let card="state choice { shape: number, initial: -1 }\ncomponent Tabs(selected_index: number) {view Kit(component: \"tabs\", instance: \"tabs\", index: selected_index)}\nview root Tabs(selected_index: choice)";
        let report = crate::realize(card, &serde_json::json!({}), Default::default());
        let pack = serde_json::json!({"schema_version":1,"tokens":{},"components":{"tabs":{
            "style":{"t":"stack"},"props":{"index":"kit_index"},"slot":false}}});
        let data = serde_json::json!({"$kit":{"placements":{"tabs":{"component":"tabs","layout":{"w":100,"h":40}}}}});
        let lowered = tree(report.complete_root().unwrap(), &pack, &data).unwrap();
        assert_eq!(lowered["kit_index"].as_f64(), Some(-1.));
    }
}
