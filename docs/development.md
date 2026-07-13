# Development Checks

Run the Splash-owned quality gate:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

The Makepad compatibility import is deliberately outside the workspace lint
scope. Verify it explicitly after an upstream import or vendor patch:

```sh
cargo test --manifest-path vendor/makepad/Cargo.toml -p makepad-script
cargo test --manifest-path vendor/makepad/Cargo.toml -p makepad-regex
```

This keeps failures in source owned by Splash actionable while preserving
separate behavioral coverage for the imported VM.
