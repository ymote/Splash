# Splash

Splash is a capability-first scripting runtime for dynamic workflows, tool
orchestration, and data transformation. It starts from the Makepad Splash VM
and keeps UI support optional rather than making UI the language boundary.

## Current baseline

- A standalone, vendored VM and parser with upstream provenance.
- A bounded evaluator with source, instruction, and deadline limits.
- A deny-by-default tool host: scripts can call only explicitly registered
  tools through `mod.tool`.
- Audited tool calls with input/output and call-count limits.
- A small `splash` CLI for local evaluation and the workflow example.

No filesystem, subprocess, raw socket, HTTP server, or Makepad platform
module is loaded by default. A capability check in the VM is not an OS
sandbox; adapters that execute local tools must run in a separately contained
worker before they are suitable for untrusted workloads.

## Example

```splash
use mod.tool

let summary = tool.call("text.echo", "plan the release")
summary
```

The host, not the script, decides whether `text.echo` exists and what it can
access.

```sh
cargo run -p splash-cli -- eval --allow-echo 'use mod.tool tool.call("text.echo", "hello")'
```

## Workspace

- `splash-core`: bounded VM wrapper and diagnostics.
- `splash-capabilities`: explicit tool policy, audit log, and safe host bridge.
- `splash-workflow`: host-owned planning, approval, and sequential execution.
- `splash-cli`: local development CLI.
- `vendor/makepad`: provenance-preserving compatibility import.

See [SECURITY.md](SECURITY.md) for the current threat model and [UPSTREAM.md](UPSTREAM.md)
for the import boundary.
