# Security Model

Splash treats generated scripts, tool descriptions, and tool inputs as
untrusted. The runtime has two separate security boundaries:

1. The language boundary exposes no ambient filesystem, process, network, or
   platform APIs. Scripts can reach a tool only through `tool.call` or an
   explicitly host-pumped `tool.start(...).await()` promise.
2. The execution boundary must contain any adapter with OS effects. A future
   production local-tool adapter will run in a dedicated worker with a
   platform-specific sandbox, not in the interpreter process.

Each registered tool declares a stable identifier and limits for calls, input
bytes, and output bytes. Calls are recorded in an ordered audit log. Unknown,
over-budget, or malformed calls fail before a tool handler is invoked.

JSON capabilities are an explicit policy type. They accept only JSON object or
array envelopes: input validation happens before the Rust handler is called,
and output validation happens before a result is returned to Splash. This is a
data contract, not a way to deserialize arbitrary Rust types or grant a script
access to a crate.

Deferred tool promises are bounded per runtime and run only when the trusted
host calls `CapabilityRuntime::pump`; one default pump tick processes at most
one tool. Hosts may choose a bounded batch with `pump_up_to`. They are
cooperative scheduling, not a threading or isolation mechanism. A paused
script with no runnable capability work must be resumed by a host that
understands the relevant suspension source.

One v0.1 runtime is single-flight: a host must resume or discard a suspended
evaluation before submitting new source to that runtime instance. Hosts that
need independent concurrent workflows should use separate runtime instances.

Workflow plans are approved by the Rust host. An approval is bound to one plan
and consumed by execution, so a script cannot manufacture approval for another
workflow or resume a rejected plan by mutating its own state.

This baseline does not yet provide filesystem adapters, network adapters,
secret storage, worker-process isolation, signed packages, JSON-schema
validation, or mobile policy backends. Those features must not be inferred
from the presence of the VM.
