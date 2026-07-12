# Host Tool Catalog

An LLM orchestrator should build its prompt from
`CapabilityRuntime::tool_catalog()`, not from a hard-coded list of ambient
commands. The catalog contains only capabilities registered on that runtime,
in stable name order.

Each `ToolDescriptor` includes the name, envelope format, call and byte
limits, description, and optional JSON input/output schema hints. The runtime
does not install catalog access into `mod.tool`: a script cannot discover or
mint capabilities by inspecting descriptions.

```rust
use splash_capabilities::{ToolMetadata, ToolPolicy};

let metadata = ToolMetadata::new("Adds two integer fields.")
    .with_input_schema(serde_json::json!({"type": "object"}))
    .with_output_schema(serde_json::json!({"type": "object"}));

runtime.register_json_tool_with_metadata(
    ToolPolicy::json("math.add"),
    metadata,
    |request| Ok(serde_json::json!({"total": 42})),
)?;
```

Schemas are bounded JSON-object metadata intended for prompt construction and
operator tooling. They are not JSON Schema validation and do not replace the
adapter's own input/output checks. A future schema-validation layer will make
those contracts executable.

The development CLI exposes the same host catalog as JSON:

```sh
cargo run -p splash-cli -- catalog --allow-echo --allow-json-add
```
