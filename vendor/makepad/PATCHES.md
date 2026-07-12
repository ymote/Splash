# Local Vendor Patches

## `regex/src/utf8.rs`: Clippy-compatible iterator entry

The upstream iterator wrapped an inner non-terminating loop in `while let`.
Every inner path either returned an item or continued the inner loop, so the
outer loop could never advance to a second iteration. Splash replaces that
outer loop with `self.range_stack.pop()?`, preserving the single-pop behavior
while satisfying Clippy's `never_loop` denial on Rust 1.95.
