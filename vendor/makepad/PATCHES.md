# Local Vendor Patches

## `regex/src/utf8.rs`: Clippy-compatible iterator entry

The upstream iterator wrapped an inner non-terminating loop in `while let`.
Every inner path either returned an item or continued the inner loop, so the
outer loop could never advance to a second iteration. Splash replaces that
outer loop with `self.range_stack.pop()?`, preserving the single-pop behavior
while satisfying Clippy's `never_loop` denial on Rust 1.95.

## `platform/script`: canonical `try/catch` and cross-call unwinding

Splash Grammar v0.2 publishes `try protected catch fallback`. The upstream
parser already emits `TRY_*` opcodes for the compatibility form
`try protected fallback [ok success]`, so Splash keeps those opcodes and makes
`catch` a one-shot contextual separator before the fallback. It is not a
global keyword: an identifier named `catch` remains valid, including as the
first fallback token. Parser checkpoint state retains whether the separator
was already consumed so append-only streaming cannot reinterpret a later
identifier as another separator. The legacy catch-less form remains available
only through the trusted compatibility entry point. Legacy source that used a
bare identifier named `catch` as its fallback must parenthesize that identifier
to disambiguate it from the v0.2 separator.

Canonical block branches retain their final expression as the `try` value,
including when canonical source terminates that expression with a newline. The
parser removes the inherited `pop-to-me` marker before recomputing jump
distances. The VM's `TRY_ERR` success path uses that encoded relative distance
directly; the upstream extra increment skipped an enclosing opcode such as
`let` when no optional `ok` branch existed. The parser now encodes the extra
guard skip only when legacy `ok` is present. These fixes let both protected and
fallback values participate safely in larger expressions without changing the
legacy `ok` control paths.

Upstream error handling checks only the current call frame for a try frame.
Splash searches active call frames, unwinds failed script calls to the nearest
try-owning frame, restores that frame's instruction body, and then applies the
existing try-frame cleanup and jump. Hard VM bails remain outside this path.

Loop back-edges now discard iteration-local try frames, operand values,
temporary scopes, and call-builder state before starting the next iteration.
The active loop frame and any enclosing try frame remain intact. This matches
the existing break cleanup and prevents `continue` from leaving an abandoned
handler that could catch a later iteration's error and re-enter an effectful
fallback. Hard time-budget bails drain their diagnostic before unwinding, as
instruction-limit bails already did, and malformed `OK_END` bytecode now bails
when no try frame exists.

The focused regressions cover legacy syntax, block and expression branches,
nested and cross-function recovery, a contextual `catch` identifier, parser
checkpoint restoration, loop control-flow cleanup, and uncatchable instruction
and hard-time limits.
Capability and workflow tests separately verify that recovery cannot erase an
audit, refund a call, widen a lease, or bypass a dataflow output contract.

## `platform/script`: re-entrant VM and raw-pointer hardening

The inherited interpreter cached a raw pointer into a body's opcode vector
across native calls. Native handlers receive `&mut ScriptVm` and can re-enter
evaluation, including replacing the current body's parser, which invalidates
that pointer. Splash copies each opcode through a scoped `RefCell` borrow
instead; the borrow ends before dispatch, so re-entrant host code remains
supported without retaining a dangling pointer.

`ScriptThreads` now validates externally selected thread indexes before it
updates its cached raw pointer, and its accessors use release-mode assertions
instead of debug-only null checks. Invalid host input therefore fails
deterministically rather than forming or dereferencing an out-of-bounds
pointer. `ScriptHandleGc` downcasts now use `Any::type_id`, so a handle
implementation cannot forge a type match by overriding a trait method.
