# Editor Module Interface Projection

`splash-lsp` can receive a small description of host-defined `mod.*` paths
when an editor starts it or through a later configuration refresh. This is
authoring metadata only. It does not make Splash a package loader, create a
Rust adapter, or prove that a module exists in the runtime selected for a
document.

## Initialization and refresh format

Pass `initializationOptions.splash.moduleCatalog` as an array of full module
paths. Each descriptor accepts only `path` and an optional `description`;
unknown fields are ignored.

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
        "description": "Returns the current forecast data."
      }
    ]
  }
}
```

Every path must start with `mod`, have at least one following canonical Splash
identifier, contain at most 16 segments, and fit in 256 bytes. The LSP keeps at
most 256 descriptors, 512 KiB of retained path and description bytes, and a
4 KiB description per descriptor. Duplicate, malformed, or over-limit input is
discarded as a whole; completion at a matching site then returns no candidates
with `isIncomplete: true`.

The fixed `mod.tool` namespace is excluded from this metadata format. A path
whose first segment after `mod` is `tool` is rejected rather than treated as a
host-defined interface descriptor.

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

## Completion behavior

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
as plain text. A chain has at most 16 identifier segments, and it must begin at
the visible binding from a direct `use mod.*` statement.

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
a tool. The metadata is client-supplied, potentially stale, and advisory even
when an integration generated it from trusted host configuration. Configuration
refresh only replaces editor metadata; it never validates a live runtime.

Runtime module binding and all capability decisions remain host-owned. In
particular, a suggested `mod.tool` call target is still checked against the
current runtime catalog and active capability lease.
