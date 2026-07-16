# Fixed-file catalogs

`splash_capabilities::fixed_file_catalog::FixedFileCatalog` is a narrow local
text-file capability for hosts that need to expose a reviewed static data set
to dynamic Splash workflows. It is not a general filesystem API.

## Authority model

During trusted Rust setup, the host adds each file under a canonical opaque
identifier:

```rust
use splash_capabilities::{
    fixed_file_catalog::{FixedFileCatalog, FixedFileCatalogLimits},
    CapabilityRuntime, ToolMetadata, ToolPolicy,
};
use std::path::Path;

fn register_release_notes(
    runtime: &mut CapabilityRuntime,
    app_data_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = FixedFileCatalog::new(FixedFileCatalogLimits {
        max_entries: 8,
        max_file_bytes: 32 * 1024,
    })?;
    catalog.insert_path("release.notes", app_data_dir.join("release-notes.txt"))?;

    let mut policy = ToolPolicy::new("file.read");
    policy.max_calls = 2;
    policy.max_output_bytes = 32 * 1024;
    runtime.register_fixed_file_catalog_tool(
        policy,
        ToolMetadata::new("Reads one reviewed release note by opaque identifier."),
        catalog,
    )?;
    Ok(())
}
```

Splash can then use only the registered tool and opaque identifier:

```splash
use mod.tool

let notes = tool.call("file.read", "release.notes")
notes
```

Identifiers match `^[a-z0-9_-][a-z0-9_.-]{0,127}$`. They are labels, never
paths. The adapter does not expose directory listing, globbing, metadata,
handles, write access, symlink traversal from source, or a way to add entries
after registration. The host must decide which identifiers, if any, are given
to an LLM outside the Splash language boundary. One granted catalog tool can
read every entry in that catalog. Use separate tools/catalogs or a trusted
input-aware capability authorizer when different files need different grants.

`insert_path` opens the host-chosen path once and stores the resulting file
descriptor. `insert_open_file` is available when the host has already opened
and verified the file through a platform-specific policy. In either case, the
path is not stored or consulted during a later read. Replacing the path after
registration does not redirect the catalog entry.

The catalog accepts regular files only. It bounds entry count and each read;
the default is 64 entries and 64 KiB per file, and the hard limits are 1,024
entries and 4 MiB per file. A registered tool uses the smaller of the catalog
read limit and its `ToolPolicy::max_output_bytes`, while the policy also bounds
identifier input bytes and call count.

## Failure and disclosure behavior

The host-side `FixedFileCatalog::read` API returns detailed configuration and
I/O errors for trusted logs. The Splash tool converts them to generic denied or
failed messages. It does not return a local path, an operating-system error,
or explicit catalog-membership detail to script source. A successful call does
of course reveal that its identifier was granted; use unguessable identifiers
and tight call budgets when that discovery channel matters. Capability audit
events retain the tool name and byte counts, not the identifier or file content.

The returned content must be valid UTF-8. Oversized, invalid UTF-8, and I/O
failures fail the call rather than truncating or coercing data.

The byte bound is not a wall-clock I/O bound. A host must select local,
trusted files with acceptable latency; a file on a slow or remote filesystem
can still block the adapter. Use a contained worker with its own deadline and
platform policy for broader or potentially blocking local effects.

## Security boundary

Descriptor pinning fixes file identity, not content. Another actor that can
write the selected file after setup can change later read results. Hosts should
select immutable or otherwise trusted files when that matters, and treat
mutable data as untrusted input before it influences another effectful tool.

This adapter does not contain the embedding process, enforce a filesystem
mount policy, mediate executable paths, broker secrets, or create a network
policy. An adapter that needs broader local effects still requires a
platform-specific contained worker and a reviewed capability design.

For mobile and embedded applications, pass the catalog to either
`mobile::MobileRuntimeBuilder::register_fixed_file_catalog_tool` or
`splash_workflow::mobile::MobileWorkflowBuilder::register_fixed_file_catalog_tool`
before `build()`. Each builder consumes it during setup, so dynamic source or
workflow steps cannot change the catalog afterward.
