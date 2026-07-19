# Editor Module Interface Projection

`splash-lsp` can receive a small description of host-defined `mod.*` paths
when an editor starts it or through a later configuration refresh. This is
authoring metadata only. It does not make Splash a package loader, create a
Rust adapter, or prove that a module exists in the runtime selected for a
document.

## Initialization and refresh format

Pass `initializationOptions.splash.moduleCatalog` as an array of full module
paths. Each descriptor accepts `path`, an optional `description`, and an
optional `callMode` of `"synchronous"` or `"deferred"`; unknown unrelated
fields are ignored. `callMode` is advisory presentation metadata for an exact
leaf method path, not a runtime declaration. A path with `callMode` must have
at least three segments (`mod.<module>.<method>`) and cannot also be a parent
of another catalog path.

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
        "callMode": "deferred"
      }
    ]
  }
}
```

Every path must start with `mod`, have at least one following canonical Splash
identifier, contain at most 16 segments, and fit in 256 bytes. The LSP keeps at
most 256 descriptors, 512 KiB of retained path, description, and call-mode
bytes, and a 4 KiB description per descriptor. A malformed recognized
`callMode`, a mode on a non-method path, duplicate, malformed, or over-limit
input is discarded as a whole;
completion at a matching site then returns no candidates with `isIncomplete:
true`.

The fixed `mod.tool` namespace is excluded from this metadata format. A path
whose first segment after `mod` is `tool` is rejected rather than treated as a
host-defined interface descriptor.

When a host configures a runtime direct capability module, it can pass
`CapabilityRuntime::module_interface_catalog()` directly as this projection.
For example, a reviewed runtime binding for `use mod.arithmetic` and
`arithmetic.add(...)` produces `mod.arithmetic` and `mod.arithmetic.add`
entries; a direct method includes its host-selected `callMode`. The runtime
module itself is still configured separately during host setup; this returned
list is only a bounded snapshot for editor completion and hover, not runtime
discovery or authority.

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
children after a direct, visible imported module binding, including a bounded
chain of catalog paths below that binding:

```splash
use mod.app.weather
weather.
weather.current.
```

Only immediate children at the selected catalog path are exposed. Intermediate
namespaces inferred from a deeper path have no borrowed leaf description. The
LSP replaces exactly the current path or member segment and renders descriptions
as plain text. An exact `callMode: "deferred"` leaf is labeled as returning a
promise and documents that the generated call needs `await()`; a synchronous
leaf is labeled as synchronous. The LSP never inserts `await()` or changes
source beyond the selected identifier segment. A chain has at most 16
identifier segments, and it must begin at the visible binding from a direct
`use mod.*` statement.

Hovering an exact catalog leaf reached through the same visible-import path
returns its canonical catalog path, any plain-text description or call-mode
note, and the advisory authority boundary. Inferred namespaces and unresolved,
shadowed, or non-direct paths have no catalog hover.

`mod.tool` remains a fixed language surface: a visible `use mod.tool` binding
offers only `call`, `call_json`, `start`, and `start_json`, regardless of this
projection. The projection is also refused for a shadowed binding, a receiver
that does not begin at a visible import, comments, strings, or source after the
first syntax diagnostic.

## Security and authority

This bounded catalog lookup is not general imported-module resolution or type
inference. The LSP does not read module files, URIs, the environment, a Rust
registry, a capability runtime, or a live catalog. It does not validate an
imported path, load a module, inspect exports, infer record fields, or authorize
a tool. The metadata, including `callMode`, is client-supplied, potentially
stale, and advisory even when an integration generated it from trusted host
configuration. Configuration refresh only replaces editor metadata; it never
validates a live runtime.

Runtime module binding and all capability decisions remain host-owned. In
particular, a suggested `mod.tool` call target is still checked against the
current runtime catalog and active capability lease.
