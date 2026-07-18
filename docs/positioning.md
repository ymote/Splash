# Positioning and Feasibility

Splash is a capability-first scripting runtime for generated workflows,
tool orchestration, and bounded data transformation. It is intentionally not a
general-purpose replacement for Python or JavaScript in every environment.

The practical target is narrower and more defensible: a small dynamic language
that an LLM can generate, a host can review and authorize, and a Rust
application can execute without importing ambient process authority into the
script.

## Difference From Makepad Splash

Makepad's Splash implementation is a VM and language substrate used by the
Makepad UI ecosystem. It accepts compatibility syntax and is designed to be
embedded by a trusted application. Upstream modules and host bindings can be
appropriate for a UI runtime, but they are not a stable capability boundary for
untrusted generated programs.

This repository vendors that substrate with provenance, then defines a
separate portable language contract and host model:

| Area | Makepad-oriented substrate | Splash runtime profile |
| --- | --- | --- |
| Source contract | Broad compatibility parser | Published canonical v0.2 grammar, preflighted before execution |
| Primary use | UI/runtime embedding | Dynamic workflows, dataflow, and reviewed tool calls |
| Effects | Determined by the embedding host | Deny-by-default registered capabilities only |
| Async behavior | VM-host integration detail | Bounded host-pumped promises and explicit external lifecycle |
| Error recovery | Inherited frame-local `try` form | Canonical cross-function `try/catch` with uncatchable hard limits and no rollback |
| Rust integration | Native bindings chosen by app | Schema-checked, policy-bound Rust adapters and typed Serde bridges |
| Workflow control | Application-specific | Host-owned plans, approvals, bounded JSON dataflow, per-step leases, checkpoints, and ledgers |
| Generated source | Trusted-host decision | Syntax review, bounded source, direct-call hints, and runtime enforcement |
| Containment claim | Outside a VM's scope | Explicitly outside the VM; effectful workers need platform containment |

The canonical profile rejects Makepad-only compatibility forms for normal
execution. A trusted host may use the explicit compatibility escape hatch for
migration, but generated code must never receive it.

## What Is Feasible Now

Splash is suitable today when an application owns a small, reviewed capability
catalog and needs dynamic behavior without shipping a full Python or
JavaScript runtime:

- Mobile application workflows over app-provided local Rust adapters.
- Embedded gateways that transform bounded JSON, route requests, and coordinate
  sensors or services through fixed adapters.
- Fixed outbound JSON calls to host-selected HTTPS endpoints, addressed only by
  opaque IDs with fixed methods, paths, and queries. This is useful for small
  mobile or edge workflows. A host-held credential can be resolved and injected
  only into one configured HTTPS endpoint without becoming script-visible. An
  optional explicit native resolver reads exact pre-provisioned credentials on
  macOS, iOS, and Windows and fails closed elsewhere. This is not arbitrary web
  access, a general secret API, or egress containment.
- LLM-proposed tool sequences submitted as data-only drafts, reviewed by a
  host, and executed under named per-step grants with bounded initial input,
  completed-step JSON outputs, and host-selected schemas for each boundary.
- Local automation where an adapter is narrowly scoped, auditable, and either
  intrinsically safe or delegated to a separately contained worker.

The sealed mobile profiles prevent the scripting-facing host from registering
new adapters after setup. The workflow facade adds plan, checkpoint, and
named-policy execution without exposing mutable registration, manual lease
issuance, or external-dispatch APIs. This is useful catalog governance for
mobile and embedded applications, but it is not OS containment.

## What It Does Not Replace

Do not position Splash as a universal Python or JavaScript replacement. It
does not currently provide a package manager, direct crate imports, browser or
Node compatibility, a standard filesystem/network/process API, a mature async
runtime, a broad numerical ecosystem, or a stable language specification beyond
the documented v0.2 profile. The VM and host APIs also use `std`; bare-metal
`no_std` firmware is not a supported target.

Rust ecosystem access is deliberately indirect. The embedding application
chooses, reviews, and links Rust crates, then exposes a small adapter with an
explicit name, call budget, input/output bounds, and optional executable JSON
contract. This preserves Rust reuse without letting generated source select an
arbitrary crate, executable, file path, URL, or secret.

For an application that needs arbitrary packages, browser APIs, extensive data
science libraries, dynamic module loading, or developer-facing REPL
ergonomics, Python or JavaScript remains the appropriate choice. Splash should
compete in the constrained orchestration niche: smaller deployment surface,
deterministic language profile, host-controlled effects, and integration with
the Rust application that already owns the device or service.

## Security Model

There are three distinct boundaries. They must not be conflated.

1. The canonical grammar and evaluator bound source, syntax work, individual
   string construction, tracked retained Splash VM storage, instructions, and
   evaluation time. They reduce interpreter resource risk; the heap bound is
   not a process-wide allocator quota and they do not authorize effects.
2. The capability runtime registers a finite catalog, validates every dynamic
   tool name at reservation time, and uses approval-bound leases that survive
   `await`. Approval-bound workflow data can influence a call but cannot widen
   that lease. A host may bind input and per-step output schemas so unexpected
   generated data cannot reach a later authorized step. This is the
   authorization boundary.
3. The operating system or device platform contains adapters that have ambient
   effects. This is the containment boundary. The current Linux Bubblewrap
   backend is one optional implementation; mobile, Windows, macOS, embedded
   Linux, and bare-metal environments require their own enforceable backend or
   must restrict Splash to safe in-process adapters.

An adapter is trusted native code. A lease can prevent an unapproved Splash
call, but it cannot make a permitted Rust handler less privileged than the
process that runs it. Hosts must keep capability names narrow, schemas
bounded, and adapter implementations independently reviewed.

## Delivery Gates

Before calling Splash a production replacement for a scripting layer in a
specific product, demonstrate all of the following for that product and
target:

1. Freeze a tool catalog and test that generated scripts cannot widen it,
   including across deferred completion and workflow resume.
2. Define bounded input, output, pending-work, source, individual-string,
   tracked aggregate-heap, instruction, and event-retention budgets from the target
   device's memory and latency limits, including the aggregate dataflow context
   and contract schemas when workflows pass JSON results.
3. Run effectful adapters in a target-specific containment backend, or prove
   that each in-process adapter has no harmful ambient authority.
4. Provide a durable checkpoint, idempotency, and reconciliation policy for
   every external effect that can outlive a process.
5. Fuzz the canonical parser/VM boundary and capability inputs with the
   product's adapter catalog, then triage failures before release.
6. Obtain an independent security review for effectful adapters and the
   selected containment backend.

The roadmap tracks platform containment, durable storage anchors, additional
semantic editor support, and sustained fuzzing separately. Those are release gates,
not capabilities implied by the presence of a VM sandbox.
