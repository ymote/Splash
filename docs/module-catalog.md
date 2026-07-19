# Editor Module Interface Projection

`splash-lsp` can receive a small description of host-defined `mod.*` paths
when an editor starts it or through a later configuration refresh. This is
authoring metadata only. It does not make Splash a package loader, create a
Rust adapter, or prove that a module exists in the runtime selected for a
document.

## Initialization and refresh format

Pass `initializationOptions.splash.moduleCatalog` as an array of full module
paths. Each descriptor accepts `path`, an optional `description`, and an
optional `callMode` of `"synchronous"` or `"deferred"`, plus an optional
`callShape` of `"single_json"`, plus optional `inputFields` and `outputFields`;
unknown unrelated fields are ignored.
`callMode` is advisory presentation metadata for an exact leaf method path,
not a runtime declaration. `callShape` explicitly says that a direct method
has one JSON-compatible argument; it must appear with `callMode` and never
creates a runtime contract. `inputFields` is a compact literal-record view for
that one argument, while `outputFields` is the same compact view for the
declared JSON result. Both require `callShape: "single_json"`. A path with
`callMode` must have at least three segments (`mod.<module>.<method>`) and
cannot also be a parent of another catalog path.

```json
{
  "splash": {
    "moduleCatalog": [
      {
        "path": "mod.app.weather",
        "description": "Host-provided weather module."
      },
      {
        "path": "mod.app.weather.current",
        "description": "Returns the current forecast data.",
        "callMode": "deferred",
        "callShape": "single_json",
        "inputFields": [
          {
            "name": "location",
            "type": "string",
            "required": true,
            "description": "Canonical location to query."
          },
          {"name": "units", "type": "string", "required": false}
        ],
        "outputFields": [
          {
            "name": "temperature",
            "type": "number",
            "required": true,
            "description": "Current temperature in the selected units."
          }
        ]
      }
    ]
  }
}
```

Every path must start with `mod`, have at least one following canonical Splash
identifier, contain at most 16 segments, and fit in 256 bytes. The LSP keeps at
most 256 descriptors, 1,024 aggregate input fields, 1,024 aggregate output
fields, and 512 KiB of retained path, description, call-mode, call-shape, and
field bytes. A descriptor description and a field description each cap at 4
KiB. Every input or output field requires a canonical Splash identifier up to
128 bytes, one of the fixed
`any`, `null`, `boolean`, `number`, `integer`, `string`, `array`, or `object`
types, and an explicit Boolean `required` value. A malformed recognized
`callMode`, `callShape`, `inputFields`, or `outputFields`, a mode on a
non-method path, a shape without a mode, record fields without a shape,
duplicate, malformed, or over-limit input is discarded as a whole;
completion at a matching site then returns no candidates with `isIncomplete:
true`.

The fixed `mod.tool` namespace is excluded from this metadata format. A path
whose first segment after `mod` is `tool` is rejected rather than treated as a
host-defined interface descriptor.

When a host configures a runtime direct capability module, it can pass
`CapabilityRuntime::module_interface_catalog()` directly as this projection.
For example, a reviewed runtime binding for `use mod.arithmetic` and
`arithmetic.add(...)` produces `mod.arithmetic` and `mod.arithmetic.add`
entries; a direct method includes its host-selected `callMode` and
`callShape: "single_json"`. When its executable input or output schema is an
explicit object with a `properties` map whose declared property and required
names use canonical Splash identifiers, it also projects `inputFields` or
`outputFields` with the schema field type, required bit, and optional plain-text
description. Array, scalar, missing-properties, noncanonical-key, and otherwise
incomplete record shapes omit the corresponding view rather than exposing a
partial one. The runtime module is still configured separately during host
setup; this returned list is only a bounded snapshot for editor completion,
hover, and explicit signature metadata, not runtime discovery or authority.

A host can replace the complete projection later through
`workspace/didChangeConfiguration` using the same array under
`settings.splash.moduleCatalog`:

```json
{
  "settings": {
    "splash": {
      "moduleCatalog": [
        {
          "path": "mod.app.weather",
          "description": "Host-provided weather module."
        }
      ]
    }
  }
}
```

An omitted `moduleCatalog` key preserves the prior projection; JSON `null`
explicitly clears it. A malformed, duplicate, or over-limit replacement makes
only module completion unavailable rather than retaining stale paths. A valid
empty array is a complete empty projection. Module refreshes do not alter
`toolCatalog` or the atomic workflow-data pair. A malformed `settings` value or
non-object `settings.splash` clears all advisory catalogs.

## Completion and hover behavior

The LSP can complete the current segment in a direct statement-position import
such as `use mod.` or `use mod.app.`. It also completes immediate static
children after a direct, visible imported module binding or a stable exact
local root alias, including a bounded chain of catalog paths below that binding:

```splash
use mod.app.weather
let weather_api = weather
weather_api.
weather_api.current.
```

Only immediate children at the selected catalog path are exposed. Intermediate
namespaces inferred from a deeper path have no borrowed leaf description. The
LSP replaces exactly the current path or member segment and renders descriptions
as plain text. An exact `callMode: "deferred"` leaf is labeled as returning a
promise and documents that the generated call needs `await()`; a synchronous
leaf is labeled as synchronous. The LSP never inserts `await()` or changes
source beyond the selected identifier segment. A chain has at most 16
identifier segments. It must begin at the visible binding from a direct
`use mod.*` statement or a qualifying exact root alias.

This is an editor-only, source-only alias rule. An alias such as
`let weather_api = weather` is accepted only through exact root `let alias =
binding` edges, for at most 16 hops, with complete lexical/import/alias
metadata. Other than the active queried receiver, every reference in the
resolved import-alias group must remain an exact group alias or direct member
call; writes, member extraction,
parenthesized/computed edges, and other escapes make completion, hover,
input-key completion, result-field metadata, and signature help fail closed.
It never resolves a module, evaluates source, or creates authority. The fixed
`mod.tool` API deliberately does not use this alias rule.

Hovering an exact catalog leaf reached through the same visible import or
qualifying alias path returns its canonical catalog path, any plain-text
description or call-mode note, any compact input- and output-record field
lists, and the advisory authority boundary. Inferred namespaces and unresolved,
shadowed, or non-direct paths have no catalog hover.

For an exact visible leaf with `callShape: "single_json"` and `inputFields`,
the server also completes an undeclared top-level key while the cursor is in the
first direct literal-record argument, such as
`weather.current({loc})` or `weather_api.current({loc})`. It replaces only
that key identifier and does not
insert an object, a value, or `await()`. The recognizer rejects a nested record,
second argument, string or comment cursor, mismatched/deep delimiters,
duplicate prior key, truncated import metadata, shadowed receiver, malformed
record prefix, or unknown/unshaped leaf. It does not evaluate JSON Schema,
infer a value or nested shape, read a runtime, validate a contract, or grant a
capability.

For an exact source binding on that same shaped leaf, the LSP can also use
`outputFields` for a top-level result member: a synchronous leaf must appear
exactly as `let result = weather.current(input)` or
`let result = weather_api.current(input)`, while a deferred leaf uses the same
exact direct form ending in `.await()`. At
`result.field`, it completes projected field names and hovers known fields with
plain-text metadata. It also follows exact local `let alias = result` chains of
at most 16 hops, so `alias.field` receives the same advisory metadata. The
recognizer accepts exactly one completed balanced argument and one direct
imported member call. It rejects zero or multiple arguments, parenthesized or
computed initializers or aliases, deeper alias chains, other postfix chains,
prior non-alias bare uses, mutations, possible escapes, nested result paths,
shadowed imports, truncated metadata, and source beyond the first diagnostic.
This is not result-type inference or runtime inspection; an output suggestion
does not validate a result, load a module, or grant a capability.

The server also advertises `textDocument/signatureHelp`. An exact visible leaf
through the same import-or-qualifying-alias rule, with both `callMode` and
`callShape: "single_json"`, has a one-argument `input`
signature and labels its result as either a JSON value or a promise of one.
Mode-only metadata remains useful for completion and hover, but gets no
invented arity or value contract. The scanner is bounded by the source and
canonical nesting limits, accepts an in-progress string argument, and refuses a
cursor inside a comment, mismatched/deep delimiters, truncated scope or import
metadata, shadowed receivers, and unknown or unshaped paths. Signature help
uses the same plain-text advisory description and compact input/output field
lists as hover; it does not resolve a module, inspect a runtime, validate an
adapter contract, or authorize a call. The separate input-key completion is
limited to the one top-level literal-record position described above. The
separate output-field feature is limited to the exact result binding and
bounded local alias chain described above and never follows arbitrary member
chains. Neither feature performs JSON Schema evaluation, runtime value
inspection, or contract validation.

`mod.tool` remains a fixed language surface: only a direct visible
`use mod.tool` binding offers `call`, `call_json`, `start`, and `start_json`,
regardless of this projection. The projection is also refused for a shadowed
binding, a receiver that does not begin at a visible import or qualifying alias,
comments, strings, or source after the first syntax diagnostic.

## Security and authority

This bounded catalog lookup is not general imported-module resolution or type
inference. The LSP does not read module files, URIs, the environment, a Rust
registry, a capability runtime, or a live catalog. It does not validate an
imported path, load a module, inspect exports, infer general record fields, or
authorize a tool. The metadata, including `callMode`, `callShape`, and
`inputFields` and `outputFields`, is client-supplied, potentially stale, and
advisory even when an integration generated it from trusted host configuration.
Those field lists are static presentation metadata, not a JSON Schema payload
or contract proof.
Configuration refresh only replaces editor metadata; it never validates a live
runtime.

Runtime module binding and all capability decisions remain host-owned. In
particular, a suggested `mod.tool` call target is still checked against the
current runtime catalog and active capability lease.
