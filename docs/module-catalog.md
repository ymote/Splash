# Editor Module Interface Projection

`splash-lsp` can receive a small, static description of host-defined
`mod.*` paths when an editor starts it. This is authoring metadata only. It
does not make Splash a package loader, create a Rust adapter, or prove that a
module exists in the runtime selected for a document.

## Initialization format

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

## Completion behavior

The LSP can complete the current segment in a direct statement-position import
such as `use mod.` or `use mod.app.`. It also completes immediate static
children after a direct, visible imported module binding:

```splash
use mod.app.weather
weather.
```

Only immediate children are exposed. Intermediate namespaces inferred from a
deeper path have no borrowed leaf description. The LSP replaces exactly the
current path or member segment and renders descriptions as plain text.

`mod.tool` remains a fixed language surface: a visible `use mod.tool` binding
offers only `call`, `call_json`, `start`, and `start_json`, regardless of this
projection. The projection is also refused for a shadowed binding, a chained
receiver, comments, strings, or source after the first syntax diagnostic.

## Security and authority

This is not general imported-module resolution or type inference. The LSP does
not read module files, URIs, the environment, a Rust registry, a capability
runtime, or a live catalog. It does not validate an imported path, load a
module, inspect exports, infer record fields, or authorize a tool. The metadata
is static for one LSP session, client-supplied, potentially stale, and advisory
even when an integration generated it from trusted host configuration.

Runtime module binding and all capability decisions remain host-owned. In
particular, a suggested `mod.tool` call target is still checked against the
current runtime catalog and active capability lease.
