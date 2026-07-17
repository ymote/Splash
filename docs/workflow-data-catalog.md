# Editor workflow-data projection

`splash-lsp` receives a bounded authoring projection through
`initializationOptions.splash.workflowDataCatalog`. A host can later replace a
complete workflow projection and current-step context through the standard LSP
configuration notification described below. The server never connects to an
engine itself.

This is not a JSON Schema transport. A host derives this compact projection
from its own trusted `WorkflowDataContract`, approved plan, or equivalent
application configuration before it starts the LSP session. The LSP never
loads a schema, follows a reference, reads a workflow checkpoint, or connects
to a workflow engine.

For a host using `splash-workflow`, `WorkflowDataLspProjection` builds this
exact wire shape from a contract-bound `WorkflowData` prefix. It validates the
plan/contract binding, the data contract, the completed prefix, and the stored
contract digest before it emits metadata. The preferred live path is
`WorkflowEngine::suspended_dataflow_lsp_projection`: it derives the catalog
and current step from the engine's retained suspended continuation rather than
from host-reconstructed counters. A durable host can use
`WorkflowDataLspProjection::from_checkpoint` after validating a checkpoint and
its separately retained dataflow context.

```rust
let splash = if let Some(projection) = engine.suspended_dataflow_lsp_projection(&plan)? {
    serde_json::to_value(projection)?
} else {
    serde_json::json!({
        "workflowDataCatalog": null,
        "workflowDataStepContext": null
    })
};
let settings = serde_json::json!({
    "settings": {
        "splash": splash
    }
});
```

The serialized projection contains no input values, output values, source
text, approval, lease, tool identity, or schema source. It contains only field
types and descriptions plus the direct-member-addressable completed prefix and
current step. The host still delivers those bytes to the editor; the LSP can
only validate their structure and remains non-authoritative.

```json
{
  "splash": {
    "workflowDataCatalog": {
      "inputFields": [
        {
          "name": "left",
          "type": "integer",
          "description": "Left operand."
        },
        {
          "name": "right",
          "type": "integer"
        }
      ],
      "outputs": [
        {
          "stepId": "prepare",
          "fields": [
            {
              "name": "total",
              "type": "integer",
              "description": "Calculated sum."
            }
          ]
        },
        {
          "stepId": "calculate",
          "fields": [
            {
              "name": "sum",
              "type": "integer"
            }
          ]
        }
      ]
    },
    "workflowDataStepContext": {
      "currentStepId": "calculate",
      "completedOutputStepIds": ["prepare"]
    }
  }
}
```

`inputFields` and `outputs` are required arrays. Every output has a required
canonical Splash `stepId` and a required `fields` array. Each field has a
canonical Splash identifier `name`, one of `any`, `null`, `boolean`, `number`,
`integer`, `string`, `array`, or `object` as `type`, and an optional plain-text
`description`. Unknown descriptor properties are ignored.

This is deliberately the direct-member-addressable subset of a workflow
contract. Runtime workflow step IDs and JSON property keys may be broader than
Splash identifiers, but a value such as `release-publish` cannot be represented
by `workflow.outputs.release-publish`. A host must send only projected names
that have a valid direct Splash spelling; the LSP rejects the complete supplied
projection rather than inventing aliases or silently presenting a partial map.

## Per-step completed prefix

When an editor is authoring one projected workflow step, the host may include
`workflowDataStepContext` beside `workflowDataCatalog`. It has a required
identifier-addressable `currentStepId` and a required
`completedOutputStepIds` array. The catalog `outputs` array is an ordered
projected step sequence for this purpose; completion presentation remains
alphabetical, but context validation uses the supplied order.

The completed array must exactly equal the initial catalog output IDs, and
`currentStepId` must equal the next catalog output ID. In the example above,
only `workflow.outputs.prepare.*` completes or hovers while authoring
`calculate`; `calculate` and later projected outputs are omitted. This prevents
the editor from suggesting a later projected output merely because its static
field schema is known.

The ordering is only over the direct-member-addressable projection. A host can
omit runtime step IDs that cannot appear after `.`, but must then provide the
prefix and current step in that reduced projected order.

`WorkflowDataLspProjection` intentionally retains only addressable completed
outputs and the current addressable step, never future workflow outputs. At the
first step, the catalog therefore contains that current step but completion
shows no output yet. After a later suspension, a new projection adds the
completed output and the new current step. If the actual current step cannot be
spelled as a direct Splash member, or if the projected prefix exceeds the LSP
bounds, construction fails so an integration does not send stale metadata.

The LSP cannot independently verify that an arbitrary client-provided position
matches a live workflow engine, plan, or checkpoint. A projection produced by
the workflow API is runtime-confirmed at its host boundary, not proof that the
editor process itself has authority over workflow state.

## Configuration refresh

After an authoritative host workflow transition, an editor integration can
send `workspace/didChangeConfiguration` with a `settings.splash` object that
contains both `workflowDataCatalog` and `workflowDataStepContext` in exactly
the shapes above. This is a complete replacement, not a patch: the server
validates the new catalog and context together before making either visible.

```json
{
  "settings": {
    "splash": {
      "workflowDataCatalog": {
        "inputFields": [],
        "outputs": [
          {"stepId": "prepare", "fields": []},
          {"stepId": "calculate", "fields": []}
        ]
      },
      "workflowDataStepContext": {
        "currentStepId": "calculate",
        "completedOutputStepIds": ["prepare"]
      }
    }
  }
}
```

An update that mentions either workflow key must contain both. A malformed
`settings` value, malformed `splash` object, invalid catalog, invalid context,
or partial pair discards the full workflow projection and returns incomplete
empty workflow matches rather than retaining stale fields. A well-formed
configuration update with neither workflow key is ignored, so unrelated editor
settings do not change the current projection.

To explicitly clear a previous projection after a terminal workflow, a
non-dataflow suspension, or a failed projection build, send both keys with JSON
`null`. This is a valid atomic clear rather than a malformed replacement:

```json
{
  "settings": {
    "splash": {
      "workflowDataCatalog": null,
      "workflowDataStepContext": null
    }
  }
}
```

One `null` with a non-null or absent peer remains a partial update and fails
closed. The clear state intentionally returns incomplete empty `workflow`
matches instead of retaining stale metadata.

The notification is only a delivery path for host metadata. The server does not
read a workflow engine, plan, checkpoint, or runtime data and cannot verify
that the new position reflects live execution. A host that uses the workflow
projection API performs that validation before the notification is sent.

The LSP completes only these direct, unshadowed paths:

- `workflow.`: `input` and `outputs`
- `workflow.input.`: projected input fields
- `workflow.outputs.`: projected step IDs
- `workflow.outputs.<stepId>.`: projected output fields

It hovers known input and output fields, using plain text even for host-supplied
descriptions. It deliberately offers no definition because catalog metadata has
no source location. It does not complete deeper paths, infer object shapes,
follow aliases, resolve modules, or analyze runtime values. A visible local or
imported binding named `workflow` shadows the projection.

An absent projection does not introduce a `workflow` namespace. A supplied but
malformed projection is discarded in full and makes matching completion return
an empty `isIncomplete` result. This distinguishes unavailable advisory
metadata from a valid empty contract without presenting a partial schema.
A malformed `workflowDataStepContext`, including one supplied without a valid
catalog, discards the full workflow-data projection for the same reason.

The server retains at most 128 output entries, 1,024 input/output fields in
total, and 512 KiB of normalized step IDs, names, types, and descriptions.
Names and step IDs are limited to 128 bytes; descriptions are limited to
4 KiB. Duplicate field names within one object, duplicate step IDs, unsupported
types, malformed arrays, and every over-limit projection fail closed.

This projection is static between initialization or explicit configuration
refreshes and is advisory client input. The workflow API can generate an exact
runtime-confirmed host update, but the LSP still does not validate
`workflow.input`, issue a capability lease, approve a workflow, expose a tool,
or make a Rust adapter callable. Runtime data validation and capability
approval remain host-owned boundaries.
