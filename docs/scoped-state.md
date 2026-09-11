# Octoscript Language Contract: Scoped State

**Status:** proposed. Nothing here is implemented.

**Superseded in part — read this first.** `ui-profile-l0.md` §5.10 classifies state by owner and
reaches a different arrangement than §7 below assumes. §7 has L0's lowering emit its own state
declarations and transitions into the VM. Under §5.10 the state that would live in the VM is
kind 2 — component-local — which is a candidate for belonging to the *component kit*, declared
there rather than in an L0 card. If that move happens, the cells here are the kit's and L0 never
mentions them.

What survives regardless: §3's per-instance cell keyed by an opaque emitter-supplied key, §3.1's
collision rule, §4's redraw-on-write, and §5's lifetime. What needs rewriting is §7, and the
question of *who emits* the declaration. §5.10.1 adds an obligation this document does not
carry: whoever owns the cells must be handed instance identity, because L0 rebuilds subtrees on
data changes and a cell that cannot be re-found is a cell that is lost.

`UPSTREAM.md` permits a behavioural change to the vendored VM "only when [it]
implements a published Octoscript language contract". This is that contract. It is
deliberately narrow: it publishes the smallest state mechanism that lets an
interaction be handled locally, and defers everything that can be deferred.

**This contract has more than one implementer.** Octoscript's vendored VM
(`vendor/makepad/platform/script`, pinned to upstream `4f9ce7a8`) and the VM that
ships on device in octos-one (`makepad/platform/script`) are independent
lineages — neither contains the other's history. That is a deliberate position,
not an accident awaiting a merge, and it has one consequence that governs
everything below: **a contract is only as real as the conformance that holds its
implementations together.** §9 is therefore not an appendix. It is the part
that makes the rest true.

Nothing in §2–§6 names a VM, a crate or a language. If a sentence here can only
be satisfied by one implementation, that sentence is a defect.

---

## 1. What Octoscript has today, and why it is not enough

Octoscript has no state in the VM. What looks like state is two separate mechanisms
that never meet:

| | mechanism | where it lives |
|---|---|---|
| read | `{{state.q}}` | textual substitution when the card is seeded |
| write | `agent.notify("set", {key: "sel", value: "1"})` | a host callback out of the VM |

So a tap leaves the VM, reaches the host, and the host re-seeds the entire card.
Nothing in the program holds a value between those two points. `{{state.q}}` is
not a binding — by the time the VM sees the source, the interpolation has already
happened and the text is a literal.

Three consequences follow, and each is a reason for this contract:

**Every interaction costs a whole card.** Toggling a row rebuilds and re-seeds
the program. That is the correct cost for "the user asked for something new" and
a poor one for "the user expanded a row".

**State cannot be per-instance.** The namespace is flat, so seven rows each
needing an `expanded` flag must synthesise seven distinct names — the manual
keying that component models exist to remove. A card author who gets the keying
wrong gets two rows sharing one flag, silently.

**Every render backend must re-solve it.** Octoscript lowers to three backends
(`octoscript-oh`, `octoscript-android`, `octoscript-makepad`). State handled above the DSL is
handled three times; state handled in the DSL is handled once.

---

## 2. What this contract publishes

Exactly three things: a way to declare a cell, a way to read it, and a way to
write it. Everything else — persistence, migration, reactivity beyond redraw — is
out of scope and named as such in §7.

### 2.1 Declaration

```
state <name> : <shape> = <literal>
```

`shape` is one of `text`, `number`, `bool`. A declaration is a *statement*, valid
where statements are valid, and its position determines the cell's scope (§3).

A shape is required. It is what makes a write checkable and what lets a host
reject a payload that does not fit, which is the one check that cannot be done
statically.

### 2.2 Read

A declared name reads as an ordinary value:

```
state open: bool = false
...
if open { ... }
```

This is a real binding, not interpolation. `{{state.q}}` keeps its current
meaning — seed-time substitution against host-supplied values — and the two do
not interact. A program may use both; they are different namespaces and this
contract does not merge them.

### 2.3 Write

```
state.set(<name>, <value>)
state.toggle(<name>)
```

A write updates the cell and marks its scope for redraw. It does not call the
host. Nothing else in this contract writes.

`set` requires the value to fit the declared shape. A mismatch is an error at the
write, not a coercion: coercing is how a string reaches a numeric cell and is
displayed as though it had always been a number.

---

## 3. Scope, and what identifies a cell

**A cell belongs to the innermost enclosing instance.** Octoscript's existing flat
`state.` namespace is global by construction; this one is not, and the difference
is the point of the contract.

An instance is named by an **opaque key the emitter supplies**:

```
View { l0_key: "root/for#0[NVDA]/Rowy#0" ... }
```

The VM does not interpret the key. It compares it. Everything the key must
express — declaration path, enclosing loop keys, stability across an insertion —
is decided by whatever generated the program, and the VM's only obligation is
that two different keys never share a cell and one key always finds its own.

This is deliberate. Identity is a hard problem with a settled answer one layer
up: `ui_l0` already computes `(declaration path, enclosing loop keys)` and
already emits `l0_key` on every tappable node. Re-deciding it in the VM would
create a second identity model to keep aligned with the first.

A program that supplies no key gets one global scope, which is today's
behaviour.

### 3.1 Collision is an error, not a merge

Two instances presenting the same key is a defect in the emitter. The VM reports
it rather than silently sharing a cell — the failure mode is otherwise two rows
that toggle together, which looks like a rendering bug and is not.

---

## 4. What a write triggers

A write marks its scope dirty and returns. Redraw is the host's, on its own
schedule.

This contract does **not** publish reactivity. There is no dependency tracking,
no computed value, no watcher, no effect. A cell changed; something should draw
again. That is all, and it is all that is needed to handle a tap locally.

Anything more should be a separate contract, argued separately.

---

## 5. Lifetime

**A cell lives as long as its instance is on screen.** An instance that
disappears loses its cells.

**No cell survives the program being re-seeded.** Re-seeding is how a card is
replaced; replacing a card discards its state.

**Nothing is persisted.** There is no serialization in this contract, and this is
the limitation most likely to be felt: card-level state such as "which city" or
"which stock" arguably *should* survive a restart, and under this contract it
does not.

That gap is named rather than closed because persistence needs a storage
contract, a migration story, and a decision about what a user is entitled to get
back — none of which should be smuggled in under a state mechanism.

---

## 6. What this contract deliberately does not do

**Schema versioning stays above the DSL.** `ui-profile-l0.md` §5.8 resets a cell
when its component's state schema changes, and preserves it under `keep` only
while that field's shape is unchanged. That needs declared shapes, an initial,
and a schema id — none of which the DSL carries. The VM holds cells and compares
keys; the layer that knows what a component *is* decides when to discard them.

**Expressions are unaffected.** Octoscript already has them. This contract adds no
evaluation, no operators, and no new call forms.

**`{{state.q}}` is untouched.** It keeps working exactly as it does, including
its round-trip through `agent.notify`. A program that never declares a `state`
behaves identically before and after this contract.

---

## 7. Consequences worth stating plainly

**For L0.** Its lowering currently resolves state away before emitting, so the
DSL never sees it. Under this contract, lowering would emit declarations and
transitions instead, and `InstanceStore` would shrink to whatever §5.8 still
needs. L0's transitions would then execute in the VM — as fixed shapes emitted by
trusted lowering, but executing. `ui-profile-l0.md` §1 must be narrowed to say
so, precisely, rather than claiming no execution machinery is in the path.

**For the three backends.** Each must redraw a dirty scope. That is the one
obligation this contract places on them, and it is the reason to put state here
rather than above.

**For the agent.** Interactions that are pure state changes stop reaching it. It
keeps every interaction that genuinely needs new content.

---

## 8. Open questions

| # | Question |
|---|---|
| 1 | Should `state.set` be an expression returning the new value, or a statement? A statement is narrower; an expression composes |
| 2 | Do `record` and `collection` shapes belong here, or only the three scalars? The scalars cover every reference card |
| 3 | What happens to a cell whose instance is off-screen but not destroyed — a scrolled-away row? Kept or dropped is a real UX difference |
| 4 | Should the VM expose cells for inspection, for a debugger? |
| 5 | Is a key collision fatal to the program, or reported and disambiguated as `ui_l0` currently does for duplicate loop keys? |

---

## 9. Conformance

Two independent implementations agree only if something checks that they do.
Prose does not check. The mechanism is a **corpus of cases, in a form both
implementations execute**, and a rule that a case is normative rather than
illustrative.

### 10.1 Shape of a case

A case is a program, an ordered list of events, and the expected cell values
after each. It says nothing about rendering, because rendering is where the
implementations legitimately differ:

```toml
[[case]]
id      = "toggle-is-per-instance"
program = """
  state open: bool = false
  View { l0_key: "row[a]" Button{ on_click: || state.toggle(open) } }
  View { l0_key: "row[b]" Button{ on_click: || state.toggle(open) } }
"""
events  = [ { key = "row[a]", click = 0 } ]
expect  = [ { key = "row[a]", name = "open", value = true  },
            { key = "row[b]", name = "open", value = false } ]
```

That single case is the whole point of the contract: without per-instance
scoping, `row[b]` reads `true` and the case fails. A case that both
implementations pass before the feature exists is not a conformance case.

### 10.2 What the corpus must cover

Every normative statement in §2–§6, and specifically the ones most likely to
drift because they are easy to implement *almost* right:

- a write updates only its own scope (§3)
- an absent key means one global scope, i.e. today's behaviour (§3)
- two instances presenting the same key is an error, not a merge (§3.1)
- `set` refuses a value that does not fit the declared shape (§2.3)
- a cell dies with its instance (§5)
- re-seeding discards every cell (§5)
- `{{state.q}}` and `agent.notify` behave identically to before (§6)

That last one deserves its own emphasis. **The most valuable cases are the ones
asserting nothing changed.** A state mechanism that quietly alters interpolation
or the host callback breaks every existing card, and neither implementation
would notice from cases that only exercise the new feature.

### 10.3 Where the corpus lives

In this repository, beside the contract, because the contract is the shared
artifact. Each implementation vendors or fetches it and runs it in its own test
suite. A case is added here first and fails in both implementations until each
lands the behaviour — which makes divergence visible as a failing case rather
than as a device-only bug six weeks later.

### 10.4 What conformance does not buy

It checks behaviour the corpus names. It cannot check behaviour nobody thought
to write down, and a case absent from the corpus is untested *and* unmentioned —
the same failure the L0 mutation harness had, where selecting rules by keyword
silently missed the six that mattered most.

So the corpus must be treated as the specification's tests, not as a smoke
screen: when an implementation finds a behaviour the contract does not settle,
the fix is a new case here, not a local decision there.

---

## 10. What would make this contract wrong

Written down so it can be checked rather than defended:

- If a walking skeleton — one card, one component, one bool, one toggle, on
  device — cannot be built against it, the contract is wrong.
- If per-instance identity cannot be expressed by an opaque emitter-supplied key,
  §3 is wrong and the VM needs its own identity model.
- If redraw-on-write is insufficient to make an interaction feel local, §4 is
  wrong and reactivity is not separable after all.
- If a conformance case cannot be written for a normative statement in §2–§6,
  that statement is not testable and should be cut or restated until it is.
- If the two implementations pass the corpus and still behave differently in a
  way a card can observe, the corpus is incomplete and §9.2 is missing a case.
