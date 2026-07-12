# Upstream Policy

`vendor/makepad/` is a compatibility import from Makepad, not an ambient
runtime dependency. The initial import is pinned to:

```text
makepad/makepad dev
4f9ce7a8bb3fd19e5c61dcf13edd2e6d4a04cefc
```

Only the language VM, parser, derive crate, and their direct leaf
dependencies are imported. Makepad widgets, platform scripting, filesystem,
process, timer, and network modules are intentionally excluded.

The vendor tree is intentionally excluded from the Splash Cargo workspace.
It remains a path dependency of `splash-core`, but its upstream lint backlog
does not dilute the lint gate for Splash-owned crates. Run its test suite
explicitly with `cargo test --manifest-path vendor/makepad/Cargo.toml -p makepad-script`.

Upstream changes are reviewed and imported as explicit commits. New host
capabilities belong in `crates/splash-capabilities`, never in the vendored VM.

Local behavioral-neutral vendor patches are documented in
`vendor/makepad/PATCHES.md` and must be reapplied or retired during each
upstream update.
