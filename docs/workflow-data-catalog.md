# Editor workflow-data projection

`splash-lsp` can receive a bounded, static authoring projection of a host's
workflow data contract through
`initializationOptions.splash.workflowDataCatalog`.

This is not a JSON Schema transport. A host derives this compact projection
from its own trusted `WorkflowDataContract`, approved plan, or equivalent
application configuration before it starts the LSP session. The LSP never
loads a schema, follows a reference, reads a workflow checkpoint, or connects
to a workflow engine.

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
prefix and current step in that reduced projected order. The LSP cannot verify
that the host-provided position matches a live workflow engine, plan, or
checkpoint.

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

This projection is static for one LSP session and is advisory client input. It
does not validate `workflow.input`, prove that an output has entered the
runtime completed prefix, issue a capability lease, approve a workflow, expose
a tool, or make a Rust adapter callable. Runtime data validation and capability
approval remain host-owned boundaries.
