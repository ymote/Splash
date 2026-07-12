# Host Tool Catalog

An LLM orchestrator should build its prompt from
`CapabilityRuntime::tool_catalog()`, not from a hard-coded list of ambient
commands. The catalog contains only capabilities registered on that runtime,
in stable name order.

Each `ToolDescriptor` includes the name, envelope format, dispatch mode, call
and byte limits, description, and optional JSON input/output schemas. The
runtime does not install catalog access into `mod.tool`: a script cannot
discover or mint capabilities by inspecting descriptions.

```rust
use splash_capabilities::{json, JsonToolContract, ToolMetadata, ToolPolicy};

let contract = JsonToolContract::new(
    json!({
        "type": "object",
        "properties": {"left": {"type": "integer"}},
        "required": ["left"],
        "additionalProperties": false
    }),
    json!({
        "type": "object",
        "properties": {"total": {"type": "integer"}},
        "required": ["total"],
        "additionalProperties": false
    }),
)?;

runtime.register_validated_json_tool(
    ToolPolicy::json("math.add"),
    ToolMetadata::new("Adds an integer field."),
    contract,
    |request| Ok(serde_json::json!({"total": 42})),
)?;
```

Contracts use Splash's bounded executable schema subset, so the catalog schema
shown here is enforced at the tool boundary. See [JSON tool contracts](schema-contracts.md)
for the supported keywords and limits. `ToolMetadata::with_input_schema` and
`with_output_schema` remain available when a host needs non-enforcing prompt
metadata only.

Dispatch is `host_pump` for a local Rust handler and `external` for a
deferred-only tool. An external tool can only be used with `tool.start` or
`tool.start_json`; the host claims and completes it through the lifecycle
described in [External tools](external-tools.md).

The development CLI exposes the same host catalog as JSON:

```sh
cargo run -p splash-cli -- catalog --allow-echo --allow-json-add
```
