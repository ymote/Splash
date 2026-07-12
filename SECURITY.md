# Security Model

Splash treats generated scripts, tool descriptions, and tool inputs as
untrusted. The runtime has two separate security boundaries:

1. The language boundary exposes no ambient filesystem, process, network, or
   platform APIs. Scripts can reach a tool only through `tool.call`.
2. The execution boundary must contain any adapter with OS effects. A future
   production local-tool adapter will run in a dedicated worker with a
   platform-specific sandbox, not in the interpreter process.

Each registered tool declares a stable identifier and limits for calls, input
bytes, and output bytes. Calls are recorded in an ordered audit log. Unknown,
over-budget, or malformed calls fail before a tool handler is invoked.

Workflow plans are approved by the Rust host. An approval is bound to one plan
and consumed by execution, so a script cannot manufacture approval for another
workflow or resume a rejected plan by mutating its own state.

This baseline does not yet provide filesystem adapters, network adapters,
secret storage, worker-process isolation, signed packages, or mobile policy
backends. Those features must not be inferred from the presence of the VM.
