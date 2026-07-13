# JSON Tool Contracts

`JsonToolContract::new(input_schema, output_schema)` compiles a bounded,
executable schema subset for a JSON tool. Register it with
`CapabilityRuntime::register_validated_json_tool` or
`register_validated_protocol_json_tool`. The typed Rust bridge also requires a
contract through `register_typed_json_tool`.

The runtime validates the ordinary JSON object/array envelope first, then the
input contract before reserving a call or invoking the handler. It validates
the output envelope and output contract before returning a result to Splash.
Rejected input is recorded as denied and does not consume the tool's call
budget. The same path is used by synchronous calls and deferred calls, whether
they are host-pumped or externally completed.

## Supported subset

- Types: `null`, `boolean`, `number`, `integer`, `string`, `array`, and
  `object`.
- Object constraints: `properties`, `required`, and boolean
  `additionalProperties`.
- Array constraints: one `items` schema, `minItems`, and `maxItems`.
- Scalar constraints: `minimum`, `maximum`, `minLength`, `maxLength`, and
  `enum`.
- Non-enforcing annotations: `title`, `description`, `default`, `examples`,
  `$schema`, and `$id`.

All other keywords are rejected during construction. In particular, this is
not general JSON Schema: `$ref`, schema composition (`allOf`, `anyOf`,
`oneOf`, `not`), regex patterns, conditional schemas, and schema-valued
`additionalProperties` are unavailable.

The implementation limits each schema source to 32 KiB, nesting to 32 schema
levels, properties per object to 128, and enum values to 128.

## Registration

```rust
use splash_capabilities::{json, JsonToolContract, ToolError, ToolMetadata, ToolPolicy};

let contract = JsonToolContract::new(
    json!({
        "type": "object",
        "properties": {
            "left": {"type": "integer"},
            "right": {"type": "integer"}
        },
        "required": ["left", "right"],
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
    ToolMetadata::new("Adds two integer fields."),
    contract,
    |request| {
        let left = request.input["left"]
            .as_i64()
            .ok_or_else(|| ToolError::Denied("left must be an integer".to_owned()))?;
        let right = request.input["right"]
            .as_i64()
            .ok_or_else(|| ToolError::Denied("right must be an integer".to_owned()))?;
        Ok(json!({"total": left + right}))
    },
)?;
```

The contract schemas are copied into the host-side tool catalog. In contrast,
schemas attached only through `ToolMetadata::with_input_schema` or
`with_output_schema` remain prompt metadata and do not perform validation.

## Typed Rust adapters

`register_typed_json_tool` and `register_typed_json_tool_with_metadata` are
the ergonomic bridge for a reviewed Rust crate API. They convert the already
validated input envelope to a `Deserialize` type and serialize a `Serialize`
output type. There is intentionally no uncontracted typed registration API.

```rust
use serde::{Deserialize, Serialize};
use splash_capabilities::{json, JsonToolContract, ToolMetadata, ToolPolicy};

#[derive(Deserialize)]
struct AddInput {
    left: i64,
    right: i64,
}

#[derive(Serialize)]
struct AddOutput {
    total: i64,
}

runtime.register_typed_json_tool_with_metadata(
    ToolPolicy::json("math.add"),
    ToolMetadata::new("Adds two integer fields."),
    JsonToolContract::new(
        json!({
            "type": "object",
            "properties": {
                "left": {"type": "integer"},
                "right": {"type": "integer"}
            },
            "required": ["left", "right"],
            "additionalProperties": false
        }),
        json!({
            "type": "object",
            "properties": {"total": {"type": "integer"}},
            "required": ["total"],
            "additionalProperties": false
        }),
    )?,
    |input: AddInput| Ok(AddOutput {
        total: input.left + input.right,
    }),
)?;
```

The schema is still the wire authority: Splash validates it before Serde
deserializes input and after Serde serializes output. This catches drift such
as a Rust default for an omitted required field, Serde's default acceptance of
unknown fields, incompatible enum encodings, and numeric-range differences.
Keep the schema and Rust representation aligned; `additionalProperties:
false` remains necessary when unknown input fields are not part of the
capability. Serde attributes such as `deny_unknown_fields` are useful defense
in depth, but do not replace the executable contract.
