# External Tools

An external tool is a deferred-only capability with no Rust handler inside the
Splash interpreter process. It is registered with
CapabilityRuntime::register_external_tool or one of the JSON variants.

External tools are intentionally unavailable to tool.call and tool.call_json.
Those synchronous calls are denied before they consume a tool call. A script
must create a promise with tool.start or tool.start_json and await it.

## Host lifecycle

1. A script starts the granted external tool. The runtime validates input,
   reserves the call budget, and retains one pending-promise slot.
2. The host calls claim_next_external_tool. This returns a host-owned opaque
   ID, the validated input, format, call index, output byte limit, and any
   remaining deadline in milliseconds.
3. The host dispatches that invocation to its own worker or platform adapter.
4. The host calls complete_external_tool with the result, or
   cancel_external_tool when it decides the work must stop.

Pump never invokes claimed or unclaimed external tools. A successful external
completion uses the same output byte limit, JSON envelope validation, optional
JSON contract validation, and audit path as a host-pumped tool handler.

~~~rust
use splash_capabilities::{CapabilityRuntime, ToolMetadata, ToolPolicy};

let mut runtime = CapabilityRuntime::default();
runtime.register_external_tool_with_metadata(
    ToolPolicy::new("text.remote"),
    ToolMetadata::new("Runs in a host-managed worker."),
)?;

let initial = runtime.eval(
    "use mod.tool
     use mod.std.assert
     let output = tool.start(\"text.remote\", \"release\").await()
     assert(output == \"done\")",
)?;
assert!(initial.suspended);

let invocation = runtime.claim_next_external_tool().expect("pending worker call");
let resumed = runtime
    .complete_external_tool(invocation.id, Ok("done".to_owned()))?
    .expect("the script was awaiting the result");
assert!(resumed.completed());
~~~

The pending-promise limit configured with with_limits_and_pending bounds all
local and external operations together. A host may claim several operations up
to that limit and complete them in any order.

Once claimed, an operation remains reserved until the host completes or
cancels it even if the script drops its promise handle, preserving the audit
record and preventing unbounded orphaned work.

CapabilityRuntime remains single-threaded. The host can copy the invocation
fields into a worker request while retaining its opaque ID locally, then map
the authenticated worker request ID back to that ID when it completes. Its
completion must be delivered back to the event loop that owns the runtime.
When present, remaining_deadline_millis should also be applied by the worker
adapter.

## Deadlines

Set ToolPolicy::max_deferred_duration before registering the tool to bound a
deferred operation from the moment tool.start reserves it. The host should
schedule CapabilityRuntime::expire_timed_out_tools from its event loop at the
next deadline. Expired external operations receive a timeout result through
the same audit and promise path as a normal completion. A result delivered
after its deadline is also converted to a timeout, even if the expiry tick was
late.

For host-pump tools, pump checks the deadline before it invokes the Rust
handler. A deadline cannot interrupt a handler that has already started or
cancel a worker process by itself; adapters must apply their own I/O deadline
and translate timeout into worker cancellation.

## Cancellation and containment

Cancellation is host-directed. It consumes the reserved call budget and records
the audit outcome as cancelled; a later completion for the same ID is rejected.
It does not kill an OS process or network request on its own. The host must
translate cancellation into its worker transport and platform containment
mechanism.

External dispatch is a capability boundary, not an OS sandbox. A production
adapter still needs an authenticated transport and a separately contained
worker with the filesystem, executable, network, and secret policy appropriate
to that tool.
