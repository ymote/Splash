# Splash UI Profile — Level 0

**Status:** **implemented.** Normative producer contract for generated UI source at Level 0.
Parser, validator, realizer and instance store live in `splash-core::ui_l0`; 317 tests, three
reference cards, and a card rendered on a OnePlus 6T through an unmodified host.
**Relationship to [Grammar v0.2](grammar.md):** a *sibling* canonical profile, not a subset of
the workflow language. `check_syntax` rejects UI source and `eval_vm_compatibility` must not
receive generated source, so neither canonical entry point admits a generated card. This
profile is the third path, and `check_ui_l0` is its entry point.

Realization has four independent host-selected bounds in `RealizeLimits`:
8,192 emitted nodes, depth 64, 512 items per collection, and 65,536 aggregate
work units by default. Visiting an element and entering a loop iteration each
consume work, even when a false guard or empty component emits no nodes.
Exhaustion stops expansion and sets `RealizeReport::truncated`; hosts must
treat that report as partial. These bounds apply to a single realization,
including nested loops and component expansion.

---

## 1. What Level 0 is for

A generated card is untrusted source. The workflow profile answers this by refusing UI
constructs; the compatibility parser answers it by refusing untrusted input. L0 answers it a
third way: **admit UI constructs, but admit nothing that could reach a capability.**

Sources are resolved by the runtime *before* realization and injected as data. There is no
dangerous call to block, because no call can be written.

**L0 needs no evaluator at all.** Earlier drafts of this section said an L0 *evaluator* is
handed a host surface with no modules, and that a bounded evaluator — heap, stack, call-depth,
instruction and time limits — remains mandatory. Implementing the profile showed that to be
wrong in an interesting direction: **L0 has no expression form, so there is nothing to
evaluate.** Realization is a pure walk over the parsed tree with data substituted. The
reference implementation contains no reference to the VM whatsoever.

**This paragraph is about L0 and does not extend to L1.** L1 has an expression form and
therefore an evaluator; §9.7 states what the confinement argument becomes there, and it is a
narrower claim than this one. Citing "nothing to evaluate" for a card requires first
establishing that the card is L0.

### 1.0 What Level 0 is NOT for

Measured, on the app cards this system already ships. Three of them — weather,
news, stock — are the profile's reference corpus, so "L0 expresses them" is close
to circular; they shaped every role and capability it has. The interesting
results are the others.

**Not every app wants a card at all**, and an earlier version of this section
counted as though they did. `youtube` and `web` are FIXED APPS: a person authored
the UI once, and the model supplies only an intent — which video, which song,
which query. Nothing about them is a limitation of L0, because authoring UI is
the wrong tool for them. The AMA routes an intent to the app; the app resolves it.

So the corpus divides two ways, and only the first row is L0's business:

| | who authors the UI | what the model supplies | example |
|---|---|---|---|
| **LLM-authored card** | the model, per request | the whole card | weather, news, stock, activity, nav, weather-activity |
| **Fixed app** | a person, once | an intent | youtube, web |

**Five of the six LLM-authored cards are written and admitted at L0.** The sixth,
`weather-activity`, is a composition of two that already are, and every capability
it names is catalogued — its `sys.weathernum` / `sys.placesnum` / `sys.aqinum` are
the index-and-count companions that a declared collection and `$state` replace.
It is not counted as proven, because it has not been written.

That is the number that means something. "Five of eight" would be counting two
fixed apps as failures of a language they were never meant to use.

**And the split is what §4 wants anyway.** `apps/youtube/app.md` currently tells
the model *"YOU choose the videos — the card cannot search YouTube by itself"*, so
it emits video IDs from memory. Those are FACTS, and a wrong one is a dead embed
or the wrong upload — exactly what the no-facts rule exists to prevent, and the
same failure `activity`'s "never invent a venue" and `StockPlot`'s symbol-not-a-
series both avoid. An app that takes an intent and resolves it against the real
service has no way to assert a fact that is not true.

**`activity` generalises.** It came from a spec written for a different framework
and needed one catalog entry (`sys.places`) and no profile change. Two of its
requirements came out *better* than the source: the loading guard is
`when parks.$state == .pending` rather than a `-9999` sentinel that also has to
mean "no data", and its venue list is a declared collection rather than indexed
capability calls. It also found a real defect on its first run — `suffix` applied
to `value:` and silently not to `text:`, because every use of it in the original
three pairs with `value:`.

**`nav` does not — and the reason is not what it first looks like.** The
classifier puts its shipping card at **L2**, and the card is indeed a program:
30 `let` bindings, 83 assignments, 128 conditionals, 606 arithmetic and
concatenation operators, and a `fn tick()` that recomputes route geometry every
frame.

**But most of that is compensation, not requirement.** Of tick's 157 lines, 61
re-resolve values after a fetch lands and 32 build a URL parameter by string
concatenation. Its own comments say why, seven times: *"top-level dlat/dlon
freeze at build"*, *"the top-level origin resolution FREEZES at build time —
before oq's search lands"*, *"GPS may land AFTER build, so (re)resolve it here
each tick"*. The card recomputes everything every frame because it has no way to
say **this value depends on that fetch**. Three more lines exist to disambiguate
a `-9999` sentinel that means loading *or* failed.

L0 supplies exactly those: declared sources with a dependency graph,
`<source>.$state` as four distinct states rather than a sentinel, and source
arguments the host assembles instead of the card concatenating a URL.

**And the map is composable.** Its card-facing surface is already declarative —
about ten parameters, `nav_mode`, `zoom`, `nav_route_width`, `nav_period`, no
callbacks — and `nav_period` means the widget owns its own animation, so the
moving vehicle is not the card's concern either. What the card does wrongly is
call `sys.navroute` itself, hand-build a marker string, and push both in through
imperative setters. **That is the card doing the widget's job**, and it is the
identical mistake `AqiContour` and `StockPlot` were already corrected for: the
catalog's own note on that correction says supplying the data *"put a GPU uniform
layout into the authoring language — it is not a widget contract, it is an ABI"*.

So `Map` is now a role, taking a trip rather than a route, and `Field` is now a
role, because a card with no way to receive typed text cannot have a search box —
which was the other half of why nav could not be written here.

**An earlier version of this section said the gap was structural** and that a
card like `nav` is L1 or L2 "not a reason to widen L0". That was too strong, and
wrong in the direction that stops work: it read a card's accumulated workarounds
as evidence about the language. The honest position is narrower —

| | |
|---|---|
| **L0 suits** | a card that displays declared data, branches on it, and writes declared state on a tap or a commit |
| **L0 cannot express** | a card that computes derived values, or drives its own animation loop |
| **Settled by writing it** | `nav`'s DECLARATIVE screens — search, results, route preview — rewritten against declared sources with a `Map` role, in **54 lines** against the L2 exemplar's 664, admitted at L0 |
| **Settled by writing it, second pass** | the **drive** screen — turn-by-turn navigation, at L0, in the same card. The prediction in the row this replaces held: it was a widget change, not a language change |

**Turn-by-turn was the hard case, and it is worth reading how it fell.** The row
above used to say the drive screen was "settled against the shipping card, NOT
against L0": the shipping mechanism is unambiguously L2 — a `fn tick()` calling
`ui.<id>.set_*` on widgets that must never rebuild — but only because the CARD
drove the camera by hand. The prediction was that a declared position would move
it to L0. Three things were needed, and all three were the same shape:

1. **`Map(at:)`** — a declared position for the camera to follow. `.drive` now
   means the chase camera exactly when `at:` is supplied, and the static preview
   otherwise, so the mode that MOVES is available precisely when the card said
   where the user is.
2. **`sys.step`** — the next manoeuvre and the distance left, from the trip's four
   coordinates plus the device's own two.
3. **A widget mode that follows rather than simulates.** This was the trap. The
   widget already had a `"2d"` follow camera, and pointing `.drive` at it would
   have looked like a complete feature: it drives a vehicle along the route at an
   assumed 34 mph off a looping clock. It looks exactly like navigating. Anything
   bound to it reports a trip that is not happening, and §4 does not stop applying
   because the invented value is a camera pose. `"follow"` takes its position from
   the card's declared fix and moves when, and only when, the device does.

The same fabrication was load-bearing in the L2 exemplar's banner, which fed
`sys.navstep` a progress of `sys.navsecs(period) * 15.2` — a clock times an
assumed speed — and so announced turns, and arrived on schedule, from a parked
car. `sys.step` takes the device's coordinates instead and the host projects the
fix onto the route. **What L0 forced was not a smaller nav card but a truthful
one:** the profile's own no-facts rule is what made the simulated camera
inexpressible, and the honest version cost one attribute, one capability, and one
widget mode.

**What writing it found.** Four gaps, none structural, all recorded rather than
patched over:

- **A card cannot accumulate a list.** `collection` is a *prop* shape (§5.2), not
  a state shape, and there is no append. So waypoints, favourites and any
  multi-select are inexpressible — the trip planner lost its "add a stop". This
  is the sharpest of the four because it is a whole interaction class.
- **The text roles' argument sets are an artefact of the corpus.** `suffix` and
  `glyph` exist only on `TextCaption`; `format` on Hero, Stat and Value but not
  Caption; `tint` on Stat and Value but not Hero. Each role has exactly what the
  original three cards happened to use on it, and nothing states a reason.
- **No duration format**, so a trip time cannot be written as one — `.money`,
  `.compact`, `.time` and `.date` exist but nothing spells 48 minutes.
- **`on_tap` is not on the text roles**, so a tappable label has to be wrapped in
  a `Row`. That may be right; it is not written down as a decision.

**One gap this did surface.** `activity`'s spec wants an empty state — "Nothing
close by" when a collection has no members — and L0 cannot say it. There is no
length, no count, and no emptiness predicate, so a guard cannot distinguish an
empty list from a full one. Every list-shaped card wants this. It is §8's
question 10.

### 1.1 A card names roles, not appearance

**L0 decides what a thing IS. It does not decide what it looks like, and it never names a
render backend.** `TextHero` means "the one number this card exists to show". It does not mean
white, or 62pt, or any particular font — those are a *theme's* answer to the role, and a
different theme answers differently.

Three layers, each knowing one thing:

```
L0 card        names roles              TextHero, Panel, Chip, TempBar
   ↓
theme kit      role → presentation      components/<theme>/*.splash, authored as Splash DSL
   ↓
splash-render  DSL → UiNode             evaluated in the VM, renderer-free
   ↓
backend        UiNode → native          splash-makepad · Splash-OH · Splash-Android
```

A card therefore lowers to **semantic invocations of the active theme's component kit**, never
to a backend's own widget dialect:

```
card(title)                 not   SolidView{ draw_bg.color: #0a0e14 … }
filled_button(copy.open)    not   RoundedView{ draw_bg.color: #ffffff12 … }
```

**Why this is a rule and not a preference.** A card is a ledger record that outlives the
device it was written on. If a card carries `#0a0e14`, then dark mode, a platform's native
look, and any later theme are all edits to every card ever written. Roles survive that; hex
codes do not.

It also keeps the three backends honest. The branch point is `UiNode`; anything that lowers
past it reaches one platform and silently abandons the other two.

**Some roles cannot be a theme composition.** Six of the catalogue —
`WeatherIcon`, `TempBar`, `SunArc`, `MoonPhase`, `AqiContour`, `StockPlot` — are small data
visualisations. `splash-render` states why they cannot be authored in the DSL: *a DSL node
cannot carry shader source — MPSL compiles at build time — but it can select a shader that was
compiled.* A gradient bar is a fragment shader parameterised by data, not a composition of
boxes and text.

**How they reach a backend is unsettled, and a previous version of this section settled it
wrongly.** It declared six new node kinds and asserted that `splash-render` would route them.
Five of the six are not in that consumer's tag table, and its fallback is to return `None` —
so a card's temperature bars, sun arc, moon phase and air-quality field would have been
dropped without a diagnostic. The section asserted a cross-repository contract that nobody had
checked, in the same breath as claiming an unknown role should "fail visibly".

What is true and what is not:

- **True:** these six are widget-layer concerns, and each backend's widget layer is its own.
  `TempBar` is a makepad widget with an MPSL shader; an OpenHarmony equivalent is an ArkUI
  custom component; an Android one is a Canvas view. There is no shared implementation to
  unify — only a shared name and data contract.
- **Not settled:** what that contract is. `Shader`/`Sdf` with a variant is the mechanism the
  consumer already documents and was dismissed too quickly; adding kinds is the alternative
  and obliges every backend at once.

**The order this implies.** Prove the pipeline end to end on the backend that already
implements these widgets — six of six exist and ship in octos-one today, against one in
`Splash-Makepad` — and let the vocabulary be whatever that requires. Then port to the others
against a contract that has shipped once. Defining the contract first is defining it for three
implementations, two of which do not exist, which is how the previous attempt went wrong.

**It does now, and this paragraph used to say otherwise.** `makepad::lower` still emits
makepad's widget dialect directly, with ten hardcoded colours and a font-size ramp — bypassing
the DSL, the VM, `UiNode` and two backends, and putting a theme inside the crate whose job is
deciding whether a card is safe. It is still a defect measured against this section. What
changed is that **nothing in production calls it**: octos-one's device path is
`kit::lower` → `_kit.splash` → the VM → `UiNode` → widgets, end to end, and `makepad::lower`
survives only in this crate's own tests.

All six data visualisations reach a backend through it. The warning below — that five of the
six were absent from the consumer's tag table and would be dropped without a diagnostic — was
true when it was written and is not now: each has a kit function and each has a tag.

**A first attempt at this retarget was reverted**, and its failures are recorded here because
they are the specification's failures rather than the code's. It mapped roles to consumer tags
that were never checked against the consumer: five of 23 did not exist, `role:` was emitted
where the consumer reads `variant`, `Photo` became an image node although the weather card uses
it as the *container* around the whole card, `Tile` became a `listitem` whose fields are
label/text rather than value/unit, and string tokens landed in numeric properties as zero. The
consumer holds a fixed attribute struct rather than an open bag, so roughly twenty emitted
attributes were simply unread.

Two lessons belong in the profile rather than in a commit message. **A lowering target is a
contract with a consumer, and this repository has no dependency on that consumer** — so
nothing prevents the two schemas drifting, and they did, immediately. And **a lowering must
carry semantics forward, not merely drop presentation**: the reverted attempt correctly removed
a colour palette and a font-size ramp, and incorrectly removed the interaction contract, a
chip's selected state, and formatting intent. `tint` is the instructive case — red-versus-green
is presentation, but *"this value is negative"* is meaning, and deleting the attribute lost
both.

What that changes:

| | Earlier claim | Actual |
|---|---|---|
| Host surface | empty | **absent** — no evaluator to hand one to |
| Instruction limit | mandatory | not applicable |
| Heap / stack / call-frame caps | mandatory | not applicable |
| Bounds still required | — | node count, nesting depth, collection length — all traversal bounds |

So authority confinement is structural in the strongest available sense: not a sandbox that
blocks calls, and not an evaluator with an empty module table, but **no execution machinery in
the path at all**.

**What is still not bought.** Two properties are decidable at L0 — membership in the grammar,
and absence of authority-bearing operations. **Termination is not a consequence of the grammar
alone**; §6 states the five conditions that make it hold, and traversal bounds enforce the rest.

---

## 2. Grammar

```ebnf
source        = [ header ] , { declaration } ;   (* header optional — see §7 *)

header        = "#" , "ledger" , ident , "@" , semver , { meta-line } ;
meta-line     = "#" , ident , ":" , value ;          (* level, model, profile *)

declaration   = source-decl | state-decl | event-decl | copy-decl
              | component-decl | view-decl ;

source-decl   = "source" , path , capability-query ;
state-decl    = "state"  , path , "{" , shape-spec , "}" ;
event-decl    = "event"  , ident , transition-block ;
copy-decl     = "copy"   , path , "{" , "class" , ":" , provenance , "," , locale-map , "}" ;
component-decl= "component" , Ident , "(" , [ params ] , ")" , "{" , { local } , view-body , "}" ;
view-decl     = "view"   , path , view-body ;

local         = state-decl | event-decl ;

view-body     = element ;
element       = construct | iteration | guard | reference | slot | fill ;
construct     = Constructor , [ "(" , [ arguments ] , ")" ] , [ block ] ;
slot          = "slot" , [ ident ] ;                 (* in a component body *)
fill          = "into" , ident , block ;             (* at a call site *)
reference     = path ;                               (* splices another view record *)
iteration     = "for" , ident , [ "," , ident ] , "in" , path , "key" , path , block ;
guard         = "when" , predicate , block ;
block         = "{" , { element } , "}" ;

arguments     = argument , { "," , argument } ;
argument      = ident , ":" , operand ;
operand       = path | literal | predicate ;         (* NO expressions *)

predicate     = path , [ comparator , ( path | literal | token ) ] ;
comparator    = "==" | "!=" | "<=" | ">=" ;      (* lone < and > are not parsed *)

path          = root , { "." , ident | "." , integer | "[" , path , "]" }
                     , [ "." , "$state" ] ;          (* source lifecycle, §5.9 *)
root          = ident ;

transition-block = "{" , transition , { "," , transition } , "}" ;
transition    = path , ":" , total-form ;
total-form    = "set" , "(" , ( literal | token | path | "$value" ) , ")"
                          (* literal = string | number | "true" | "false" *)
              | "toggle"                              (* boolean state only *)
              | "cycle" , "(" , token , { "," , token } , ")"
              | "clear" ;                             (* restore declared initial *)

shape-spec    = "shape" , ":" , shape , [ "," , "initial" , ":" , ( literal | path ) ]
                              , [ "," , "keep" , ":" , "true" ] ;
shape         = "text" | "number" | "bool" | "enum" , "[" , ident , { "," , ident } , "]"
              | "record" | "collection" | "event" ;   (* prop shapes, §5.2 *)
provenance    = "vocabulary" | "user-copy" | "model-copy" ;
```

### 2.0 Amendments found by the reference cards

The grammar above already incorporates eight corrections that the three reference cards in
`octos-one/docs/l0/` forced. They are listed because the process matters: the cards were
written against the first draft, and **every construct they needed that the draft lacked is a
defect in this document, not in the cards.**

| # | Missing | Needed by | Resolution |
|---|---|---|---|
| 1 | element referencing another `view` record | all three — `root` splices named blocks | `reference = path` |
| 2 | `initial` from the environment | weather — `units` defaults by locale | `initial : literal \| path` |
| 3 | constant index into a collection | news — `stories.0` is the lead story | `"." integer` in `path` |
| 4 | index by a state value | news, stock — `stories[selected]` | `"[" path "]"` in `path` |
| 5 | loop index binding | news — the rank column | optional second binder: `for s, i in …` |
| 6 | predicate as an argument value | stock — `active: range == d1` | `operand` admits `predicate` |
| 7 | event payload at the call site | news, stock — which row was tapped | `value:` argument, §3.1 |
| 8 | sub-collection of a source | news — feed skips the lead | **not granted** — see below |
| 9 | bare identifiers are ambiguous | both components — `width: rank` is a token, `text: position` is a path | tokens marked lexically, §2.2 |
| 10 | a bare boolean guard | weather — `when expanded { … }` | `predicate` admits a lone path |

**None of these introduces an expression.** Indexing is a total lookup, a predicate as an
operand is the form `when` already admits, and a loop index is supplied by the iterator. The
authority property and the absence of arithmetic both survive.

### 2.2 Tokens are lexically marked

`width: rank` and `text: position` are both `ident : ident`, but the first names a layout token
and the second a bound path. Resolving this by scope — *a path if it names a binding, else a
token* — would be a trap: declaring a prop named `fill` would silently change what
`width: fill` meant everywhere in that component.

**Tokens carry a leading dot.** `width: .fill`, `format: .money`, `align: .center`. A bare
identifier is always a path.

```ebnf
operand       = path | literal | token | predicate ;
token         = "." , ident ;
```

An earlier draft resolved this by argument shape instead — *each argument accepts either a
token set or a value, so the argument decides what a bare name means.* **That rule is
withdrawn**, because it fails on any argument admitting both, and one does: `unit: units`
follows card state while `unit: .pct` is fixed. Marking tokens removes the ambiguity
lexically, so the catalog only has to say which tokens are **legal** rather than disambiguate
what a name **means**.

The ambiguity surfaced only once components existed, because a component's props are the first
bindings whose names the card author chooses freely — both reference cards had to rename a
prop, `day` → `item` and `rank` → `position`, before it was visible at all. The `unit` case
surfaced one step later still, while cataloguing arguments. Each pass found what the previous
one could not have.

**Enum members are tokens too.** A `shape: enum[c, f]` declaration *defines* the set with bare
names; every use is dotted — `cycle(.c, .f)`, `initial: .m1`, `range == .d1`. Same rule as any
other token: a bare identifier is always a path, so an enum member can never be shadowed by a
binding of the same name.

The normative argument contract is [`ui-l0-constructors.toml`](ui-l0-constructors.toml):
which constructors exist, which arguments each admits, and which tokens are legal per
argument.

**#8 was refused.** The news card wanted `stories.rest` to skip the lead story. Granting a
derived sub-collection would be the thin end of computation — `rest` invites `filter`, which
invites a predicate expression, which invites arithmetic. The card instead binds
`sys.news(...)` twice, or the source declares `lead` and `rest` as fields. **The runtime
shapes the data; the view does not reshape it.**

### 2.1 What is absent, and deliberately

| Construct | Status | Why |
|---|---|---|
| arithmetic, string concatenation | **absent** | any expression can hide a fabricated fact (§5) |
| function definition, call | **absent** | would reintroduce unbounded work |
| `while`, unbounded `for` | **absent** | iteration is only over a declared collection |
| `ui.<id>.<method>` | **absent** | imperative widget commands are L2 |
| module access of any kind | **absent** | this is the authority property |
| assignment outside a transition | **absent** | state changes only through declared events |

**`operand` admits no expressions.** `Text(value: now.temp)` is legal; `Text(value: now.temp * 9 / 5 + 32)` is not. Unit conversion and formatting belong to the runtime (§4).

---

## 3. Transitions are total by construction

This is the point where an earlier draft of this design was wrong, and the correction is
load-bearing.

A transition written as an expression — `expanded: !expanded`, or
`units: units == c ? f : c` — **is computation**, however small. Declared storage does not
make it total or bounded, and once expressions are admitted the grammar has to answer for
recursion, unbounded numerics, and event cascades.

L0 therefore has no expression form in transitions. It has four **total forms**:

| Form | Applies to | Semantics |
|---|---|---|
| `set($value)` | any | the payload the raising element carried in its `value:` argument |
| `set(.token)` | `enum` | a declared member |
| `set("text")` | `text` | a literal |
| `set(path)` | any | a bound path, resolved from injected data |
| `toggle` | `bool` | the other value |
| `cycle(.a, .b, …)` | `enum` | successor, wrapping; members must be declared in the shape |
| `clear` | any | restore the declared `initial` |

A `set($value)` raised with no payload is a **no-op**, not a clear: falling back to the
initial would read as a deliberate reset.

Each is total on its declared shape and terminates in constant time. `units: cycle(c, f)`
replaces the ternary; `expanded: toggle` replaces the negation.

An event may name several transitions, applied **atomically as one batch** — every write is
staged and the batch commits only if all of them resolve, so a transition that cannot be
computed leaves the store exactly as it was rather than half-applied.

**A payload is checked at dispatch.** `set($value)` is the one form whose value arrives from
outside the card, so it is the one the declared shape cannot decide statically; a payload that
does not fit the target state is refused and the batch does not commit. Every other `set`
spelling is decided at check time against the declared shape. A single-assignment
rule would be wrong: production code already fires two state writes from one gesture, and the
stock reference card's `back` does the same — clearing both `selected` and `range`.

### 3.1 The event payload

An element that raises an event supplies its payload at the call site:

```
Row(on_tap: open_quote, value: m.ticker)
```

`on_tap` names a declared event; `value` is the payload the transition receives as `$value`.
Both are ordinary operands, so a payload can be a bound path or a literal but never a computed
one. An event whose transitions do not mention `$value` ignores any payload.

This replaces the string-tagging approach used by the current runtime, where a card's identity
is prepended to its event name by rewriting generated source. A card that constructs its event
name dynamically escapes that rewrite; here the event is a declared name resolved by the
runtime, so there is nothing to construct.

---

## 4. Sources, and the no-facts rule

A `source` body is a **query the runtime executes**, never a call the view makes. Views cannot
invoke it; they bind to its result.

```
source place  sys.geocode(name: state.city)
source now    sys.weather(lat: place.lat, lon: place.lon, fields: [temp, hi, lo, cond])
```

The evaluator never sees `sys.geocode`. The runtime resolves it, injects the result as data,
and the view reads `place.name`.

**Selected data arguments must be bound rather than supplied as direct literals.** The
checker enforces this syntactic rule, declared names and declared copy classes. It does
not establish the provenance or truth of every value reachable through a binding.

**What is actually enforced, and what is not:**

| Position | Rule |
|---|---|
| A `value` argument (`TextHero`, `TextStat`, `TextValue`, `TextCaption`, `Tile`) | Must be bound. A literal — string, number or token — is refused. `TextHero(value: "34 mph")` is rejected |
| Any `path`-kind argument (the drawing widgets) | Must be bound. `TempBar(lo: 5)` is rejected |
| `copy.x`, by any route | Refused when `x` is declared `model-copy` — named in a view, passed as a prop, used as a state initial, or written by a transition. A `copy.x` that is not declared at all is refused too |
| A **raw string literal** in a `text`, `label` or `glyph` position | **Accepted** |

The last row is a deliberate decision, not an oversight. A raw literal carries no declared
provenance, and by this section's own logic that makes it model-copy — so `TextTitle(text:
"Revenue: $41.2M")` passes, and a model that simply writes the string inline is unaffected by
the rule. Refusing it would mean every human-readable string is declared `copy`, which is a
real ergonomic cost and buys less than it appears to: of the eleven literals in the reference
cards, six are `glyph` symbols (`‹ ↑ ↓ ≈`) that are closed presentation vocabulary rather than
language, and translating them is meaningless.

State values now retain a runtime origin: `Authored`, `Vocabulary`, `Source`,
`UserInput`, `Host`, `Derived` or `Unknown`. The realizer carries this through loops,
component parameters, local state, source captures, schema retention and transitions.
Authored defaults remain legal in controls. In `Data` catalog arguments and numeric
`text` arguments they resolve to `Missing`; their live bindings and expressions are
suppressed too. Thus `state n { shape: number, initial: 1547 }` with
`TextHero(value: n)` checks successfully but displays an em dash until an accepted
host or user value arrives. Passing that state through components does not change
its origin. Path arguments used as query selectors (for example a stock symbol)
keep their existing binding contract.

The native host derives event origins from the realized control and its declared
event: Field commits/changes are user input; a Row carrying an authored value
retains `Authored`. JSON payloads cannot declare an origin. Legacy dispatch APIs
conservatively treat unattributed payloads as authored; trusted hosts use
`dispatch_reporting_with_origin`. A reset or literal assignment restores the
initial/authored origin. Changing only the eligibility of an origin still triggers
a redraw, even when the value is identical. Empty native text is a payload, not an
absent event. `set_cell` is a trusted host write; source captures use
`set_cell_with_origin(..., Source)`.

L1 expressions propagate origins and permit authored coefficients combined with
source/host/user values. This traces inputs, not the truth of the formula. Authored
copy classes remain declarations, and inline labels remain accepted. Neither L0
acceptance nor L1 expression validation is a proof of factual correctness.

Implicit dependencies are declared like any other source:

```
source env.locale  sys.locale()
source env.theme   sys.theme()
```

Anything reachable without a declared source is a defect by construction — which is also what
makes an L0 view's dependency set readable without evaluating it.

### 4.1 `theme` — the one presentation statement, and why it is not one

```
theme dark
```

At most one per card, and the name must be catalogued (`catalog::THEMES`: `dark`, `light`,
`glass`, `photo`, `vibrant`, `minimal`). An uncatalogued name is refused at parse time, with
the known set named.

This does not weaken the no-presentation rule, because a card declaring `theme glass` has said
nothing about what glass *is*. The kit answers it, by assembling itself in four parts:

```
_palette_dark.splash   the BASE — knobs (space_factor, radius_factor, font_base, font_step)
                       and every colour
_palette_<mood>.splash the DELTA — only what this mood changes; may move a knob
_derive.splash         every SIZE, computed from the knobs — AFTER the delta, so a mood
                       that moves a knob moves everything following from it
_kit.splash            the roles, which read those tokens and never a literal
```

So the page colour, the panel fill, the hairline, the ink, the paddings, the radii and the type
scale are all decided one layer down, and `glass` is expressed as "dark, but these fourteen
colours and `radius_factor: 1.5`". A card still cannot write `#ffffff`, a font size or a radius —
those are refused exactly as before.

The order is load-bearing and its failure is silent: `let` evaluates at its own line, so deriving
sizes in the base would leave a delta's `radius_factor` with nothing left to change, and an
assembly that omits `_derive.splash` leaves every size an undefined name — which is 0, so the
tree still builds with no padding and no type scale at all.

**Declaring a theme is not the same as reading one.** The `source env.theme sys.theme()` sketched
above is the opposite direction — a card ASKING what the ambient theme is — and it is *not
implemented*: `sys.theme` has never been in the catalog, so that line is a sketch and a card
naming it is refused. The declaration is the direction that exists, because the case that
motivated it is a user asking for a look ("dark weather tokyo"): the request names a mood, the
agent declares it, the kit renders it.

**A card must not declare a mood nobody asked for.** Choosing one unprompted is deciding
presentation by the back door. The host tells the agent when a request named a look; absent that,
the card declares nothing and gets the kit's default.

---

## 5. Components and instance identity

```
component ForecastRow(day) {
  state expanded { shape: bool, initial: false }
  event toggle   { expanded: toggle }
  view  Row {
          Text(role: Row, text: day.dayname)
          TempBar(lo: day.lo, hi: day.hi, min: week.min_lo, max: week.max_hi)
          when expanded { Detail(day: day) }
        }
}
```

Local state is declared in the ledger; **its values live only in the runtime.**

### 5.1 Identity is a path, not a position

An instance is identified by the tuple

```
( card namespace, parent instance identity, instantiation site,
  component name and version, vector of enclosing loop keys )
```

Recursive by construction, because a static declaration path is not enough: two `TripPanel`
instances each containing an unkeyed `Toggle` must not share one state cell.

**This is not React's rule.** React associates state with position in the realized tree, where
component type and keys both affect preservation. L0 binds to a declared path, so identity
survives a ledger edit that inserts a **differently named** element above — and only that.
§5.1's closing paragraph lists exactly what does and does not move the path; read it before
relying on this sentence, which states the motivation rather than the guarantee.

**Neither the card namespace nor the version is currently a key segment.** Keys begin at the
root view and append component names; the schema id is held in a separate map keyed by component
name. So the tuple above describes the intended identity, and the implementation covers the
instantiation site and enclosing loop keys only. One consequence worth knowing: two cards
sharing one store can collide, because card state lives under a single fixed key.

**"Version" means the STATE SCHEMA version** (§5.8), not the component's whole definition.
Using the definition digest would contradict §5.8 directly: a view-only edit would change
identity and reset state, which is precisely what §5.8 promises it does not do. The two are
different instruments — the schema id decides whether live state still fits, and the closure
digest (§7) tells a host that a definition was replaced at all.

**What path-based identity does and does not survive.** Insertion of a differently named
sibling is stable, because siblings are numbered within each element name. Identity moves when
the PATH moves: reordering two same-name siblings, inserting another instance of the same
component above, adding or removing an enclosing guard, loop, slot or view reference, and
changing a loop's key expression.

Only the element name and its ordinal enter a segment, so editing a guard's *condition* —
`when a` to `when b`, both true — leaves the path untouched and the state survives. An earlier
version of this paragraph said any change to an enclosing guard moved identity; that is wrong,
and wrong in the direction that matters, since it would have justified not looking. Fully edit-stable identity needs a persistent site id in the source or
edit provenance from the ledger; neither exists yet, and the numbering is an improvement on
tree position rather than a solution.

### 5.2 Props

```ebnf
params        = param , { "," , param } ;
param         = ident , ":" , shape , [ "=" , literal ] ;
```

Props are **typed by the same shape vocabulary as state**, may carry a literal default, and
are **immutable inside the component**. A prop is an input, not storage; a component that
wants to change something declares local state or raises an event.

```
component ForecastRow(day: record, unit: enum[c, f] = c, on_pick: event)
```

`record` and `collection` are added to the shape vocabulary for props, since a row receives a
whole item rather than a scalar.

### 5.3 Scope: what a component may reference

| May read | May not read |
|---|---|
| its own props | card `state` — pass it as a prop |
| its own `state` and `event` | another component's locals |
| card-scope `source` | — |
| card-scope `copy` | — |

**Sources and copy are readable; state is not.** Both are immutable and already declared
dependencies the tracker sees, so reading them creates nothing implicit. Card state is what
drives reconciliation, so it must arrive explicitly as a prop or the dependency becomes
invisible — the failure §6.2 warns about.

This is why `week.min_lo` may be read directly by a forecast row, while `units` must be passed.

### 5.4 Outputs are event props

A component raises an event the parent declared, passed in as a prop:

```
component StoryRow(story: record, on_open: event) {
  view Row(on_tap: on_open, value: story.id) { … }
}

view latest  Panel { for s, i in feed key s.id { StoryRow(story: s, on_open: open_story) } }
```

**This needs no new mechanism.** An event name is a path, `operand` already admits paths, and
the transition runs in the scope where it was *declared* — the parent's — so a child cannot
reach state it was not handed a route to. It is React's callback prop with the scoping made
explicit.

A component may only name events it declares locally or receives as props. There is no way to
raise an arbitrary event by constructing its name, because there is no expression form.

### 5.5 Slots

A single anonymous slot, marked in the component body:

```
component Panel(title: text) {
  view Col { TextCaption(text: title) slot }
}

Panel(title: "Details") { Tile(…) Tile(…) }
```

Children are realized in the parent's scope, not the component's — a child expression sees the
call site's bindings.

A component may also offer **named** slots, and a call site directs children at one with `into`:

```
component Framed(title: text) {
  view Col { TextCaption(text: title)  slot header  Rule()  slot }
}

Framed(title: "Today") {
  into header { TextRow(text: "above the rule") }
  TextRow(text: "below it")
}
```

Children written outside any `into` fill the anonymous slot, so a component with one slot needs
no ceremony and every card written before named slots existed is unchanged.

**An `into` naming a slot the component does not offer is rejected.** Its children would
otherwise render nowhere, which is the same silent-drop failure as a binding that resolves to
nothing — the card looks deliberate and the content is simply gone.

### 5.6 What is refused, and why

**Hoisted or shared state.** If two components need the same state it lives at card scope and
arrives as props, with the event declared at card scope too. Hoisting would raise an ownership
question the grammar cannot answer, and a Context-like mechanism reintroduces exactly the
invisible dependencies §6.2 exists to prevent.

**Cross-field invariants are not expressible.** Two date pickers cannot enforce
start-before-end through transitions, because total forms cannot compare. This is a real limit,
not an oversight. Where an invariant matters it belongs in the **shape**, enforced by the
runtime:

```
state start { shape: date, initial: today, max: end }
```

**That example is illustrative, not grammatical.** `date` is not one of §2's shapes, `today`
is not a literal form, and `max:` is not part of `shape-spec` — it sketches where such an
invariant would belong if the shape vocabulary grew, and nothing in the profile accepts it
today. It is retained because the *limit* it describes is real: total forms cannot compare, so
a cross-field invariant has nowhere to live at L0.

If that is insufficient, the card is L1 — and should say so rather than smuggling a
comparison into a transition.

**Per-component sources.** A component may not declare its own `source`. Sources are card-scope
and resolved before evaluation; a component instantiated *n* times would fan out *n* fetches,
with *n* determined by data. That breaks the bound §6.2 requires, and makes fetch volume a
function of a collection the model does not control.

### 5.7 Lifecycle

There are no lifecycle hooks — §2.2 rejects `useEffect` and its dependency arrays. But the
runtime needs defined behaviour, and identity (§5.1) decides all of it:

| Event | Behaviour |
|---|---|
| **Mount** — identity appears | local state initialized from `initial` |
| **Update** — identity persists, props differ | view re-realizes; **local state persists** |
| **Unmount** — identity disappears | local state discarded |

Realization reports every instance key it produced. A host passes them to `prune` after each
pass; without it the store grows for the life of the app, and a key that reappears inherits a
stale value.

**Duplicate keys are reported at realization, and the colliding instances are given distinct
identity rather than sharing one cell. Duplicate keys are an error**, surfaced as a diagnostic — never coalesced.
Silent coalescing would make two rows share one state cell, which is the failure mode keys
exist to prevent. A missing key on an iteration is a grammar error.

### 5.8 State schema versioning

A component's **state schema id** is derived from its `state` declarations — names, shapes and
initials.

**It is not part of the instance key**, and an earlier version of this section said it was. The
key is `{parent}/{component}`; the schema id is held separately, per component name, and a
schema change reconciles the live cells *in place* rather than minting a new identity. The
observable behaviour below is what the implementation does; the mechanism is not identity.

| Definition change | Effect |
|---|---|
| view or props only | schema id unchanged → **local state persists** |
| any `state` declaration added, removed, renamed or retyped | schema id changes → **new identity → state reset** |

**Reset is the default; preservation is opt-in**, never inferred. A ledger edit that adds a
field cannot be assumed compatible with live values, and guessing is how a rolled-back ledger
ends up feeding version-A state to version-B code — at which point last-known-good is no longer
known good.

**The opt-in is `keep: true`** on a state declaration:

```
state expanded { shape: bool, initial: false, keep: true }
```

A cell that opts in survives a schema change **only while its own shape is unchanged**. Adding
an unrelated field elsewhere in the component preserves it; retyping `expanded` itself resets it
regardless. Without that second condition `keep` would be precisely the "assume the old value
still fits" that this section exists to prevent — it would just have moved the guess from the
runtime to the card author, where it is no more reliable and considerably less visible.

Reset therefore remains the default in both directions: a component that says nothing behaves
exactly as before, and a component that opts in still resets on any change to the field it
opted in for.

**Consequence worth stating plainly:** folding the ledger reconstructs the *program*, not the
visible application state. Local state is disposable UI state — scroll positions, expansion
flags. Anything that must survive a definition change belongs in a `source`, not in a component.

An earlier version of this paragraph offered card state "with a declared migration" as the other
home for durable values. **There is no card-state migration** — no syntax, no implementation.
Card state is reset like any other, and §8 question 8 records this as an open question rather
than a mechanism, because durability needs a storage contract this profile does not have.
§5.12 provides that contract — durable values are *references* read as a source, not cells — but
card state itself is still not it: there is nowhere durable to put a CELL,
and there is not meant to be.

### 5.9 Source lifecycle

Every source carries a lifecycle, readable as `<source>.$state`, whose value is one of four
tokens:

| Token | Meaning |
|---|---|
| `.pending` | never resolved |
| `.ready` | resolved and current |
| `.stale` | resolved, but past its freshness budget |
| `.failed` | the fetch failed |

```
when now.$state == .pending { TextRow(text: copy.loading) }
when now.$state == .failed  { TextRow(text: copy.offline) }
```

This exists because **absence is not a state.** Without it a card can only ask whether a value
arrived, so "still loading", "the network is down" and "this field genuinely has no value" all
render the same em dash. The card then looks like working software displaying real data, which
is the worst of the three outcomes.

`$state` must be the last segment of a path, and is available **only on a source** — a local
state is not fetched and has no pending or failed. Both are rejected rather than resolving to
nothing.

The host reports the lifecycle; the card never computes it.

**The fallback, and what it assumes.** When the host reports no `$status`, a source with a
value is treated as `.ready` and one without as `.pending`. That is an inference, and this
section has just argued that absence cannot carry it — so it is sound *only* under an explicit
host contract: **a source key is present if and only if it resolved successfully and is
current.** A host that caches a stale value without reporting status will have it read as
`.ready`; one that represents a successful empty result by omitting the key will have it read
as `.pending`.

The fallback therefore exists for hosts that do not track status at all, and any host that can
distinguish these cases must report `$status` rather than rely on it. `.stale` and `.failed`
are not derivable from data by construction, which is the whole reason status reporting exists;
the fallback does not change that, it only declines to guess for the two cases that are
derivable under the invariant above.

**Cadence and freshness budget belong to the capability, not the card.** A card names what it
needs; how often `sys.weather` is worth re-fetching is a property of weather, and duplicating it
per card is how two cards on one screen disagree about how old their data is.

### 5.10 Who owns state, and what L1 must be told

L0 does not hold all the state a running card has. Three owners exist, and confusing them is
how a layer boundary gets drawn in the wrong place:

| # | State | Owner | Example | May a source depend on it? |
|---|---|---|---|---|
| 1 | **Card state** | L0 | `selected`, `city`, `units` | Yes — `sys.quote(ticker: state.selected)` |
| 2 | **Component-local state** | L0 today | `ForecastRow.expanded` | No — §5.3 keeps it out of source arguments |
| 3 | **Source lifecycle** | the host | `weather.$state` | Not applicable — it *is* the fetch's status |

**Kind 1 cannot be pushed below L0.** It is the state composition creates: `selected` is read by
the list, the detail, the header, the chart, and by two sources. It is not any component's
state, it is what *relates* them, so only the layer that composes can declare it. A component
kit cannot supply it however complete the kit is.

**Kind 2 is a candidate for moving down, and that move is not yet justified.** The argument for
it is that expansion flags and scroll offsets are widget business the composer should not have
to mention — and the reference corpus agrees, containing six kind-1 declarations and exactly
one of kind 2. The argument against is §5.10.1.

**Kind 3 was missed by an earlier draft of this section**, which offered a two-way split. It
fits neither: the host owns it, several components read it, it drives guards and refetch, and it
outlives any widget instance.

Ownership is also not the only axis. A cell has a **visibility** (private, card-shared),
an **effect** (render-only, layout, source query, navigation), and a **lifetime** (instance,
card, session). `selected` is card-shared by visibility but *navigation* by effect; `units`
looks like a durable preference. Classifying by owner alone answers where a value lives, not
how long it should, which is why question 8 in §8 stays open.

The lifetime axis here has three values and needed a fourth. §5.12 supplies it: a durable value is
not a longer-lived cell but a **reference** the host stores and a source resolves, which is why
it does not appear in this section's taxonomy at all.

#### 5.10.1 Moving kind 2 down requires a protocol, not just a move

Suppose component-local state moved to the component kit. L0 would no longer know `expanded`
exists — and L0 still decides when a subtree is rebuilt. Measured on the weather card:

```
week  changes ->  28 of  79 nodes reused     forecast rows are REPLACED
city  changes ->   0 of  79 nodes reused     whole tree rebuilt
units changes ->  13 of  79 nodes reused
```

The forecast rows read `week`. So when forecast data refreshes, L0 rebuilds those subtrees.
Today that is harmless: `expanded` lives in the instance store, keyed by instance identity and
held *outside* the tree, so it survives. Move the value down without moving identity down and a
row the user expanded collapses whenever data arrives.

**So the layers do not need a shared value store, but they do need a shared protocol** —
instance identity, mount and unmount, what survives a rebuild, and what invalidates. Precisely
*because* L0 would not own kind 2, it must hand identity down so the owner can preserve it.

That protocol does not exist. `docs/scoped-state.md` is the nearest thing and is written for
the opposite arrangement — it has L0 lowering emit its own state declarations into the VM — so
it needs rewriting around kit-owned state before it describes this.

**The identity that would have to cross is not the renderer's `key`.** Three distinct things
currently share the name:

| Name | What it is |
|---|---|
| `UiNode.key` | L0's declaration-and-loop path, used for realization and patch reuse |
| emitted `l0_key` | that same path, written as a backend attribute for tap routing |
| `Attrs.key` in `splash-render` | a kit-selected name for a slot in a process-global `BTreeMap<String, f64>` — no instance scoping, no pruning |

The third is not the first. Reusing its name for instance identity would put per-instance cells
into a global map keyed by whatever the kit chose, which is the collision §5.7 exists to
prevent.

### 5.11 Who answers a source

A `source` declares *what the card needs*, not *who fetches it*. Two answers are
now implemented, and the choice belongs to the backend rather than to the card:

| | who fetches | when it is chosen |
|---|---|---|
| **Host-answered** | the host walks `source_plan` and fills a data blob | always available; the only option for a backend with no fetch of its own |
| **Backend-answered** | lowering emits a call the backend makes itself | where the backend has a capability that answers the same question |

The card is identical either way. `source quote sys.quote(ticker: state.selected)`
followed by `quote.last` is one declaration; whether it becomes a seeded number or
a live call is decided below the language.

**Realization keeps the provenance.** `UiNode.bindings` records, per argument,
which source a value came from and which field of it — alongside the resolved
value, not instead of it. Without that, a backend that *could* fetch has no way
to know it should: by the time lowering runs, `quote.last` is just a number.

**A backend must fall back rather than guess.** `sys.quote` declares ten fields;
the makepad VM's `sys.stock` answers seven of them. The rest lower to the seeded
value, because a call the backend cannot answer renders an em dash where a real
number was available. Three findings, each from running it on a phone:

- **`open` accepts and cannot answer.** `sys.stock` takes the key and resolves
  `regularMarketOpen`, which is absent from the upstream response while
  `regularMarketDayHigh` and `…DayLow` beside it are present. A helper accepting
  a key is not evidence it can answer it.
- **Most formats do not survive.** `glyph`, `unit` and `suffix` are literals that
  concatenate around a call. A `format` mostly is not: `money` is a `"$"` prefix
  and `signed_pct` is what the VM already returns, but `signed_money` puts the
  sign outside the currency symbol and `compact` and `ratio` need the number
  itself. Those keep the seeded value.
- **Anything that measures text must measure what is DRAWN.** Emitted and drawn
  text are the same string until a value goes live, and then they diverge
  completely — `"$" + sys.stock("NVDA", "price")` is 33 characters that render as
  six. Sizing the hero by the emitted form dropped it from 40pt to 24pt and
  shifted the whole card up: a layout bug with no layout cause.

**A live card cannot be asserted by a whole-screen golden**, and the device
harness now says so per case. Where values are live the comparison is restricted
to a band that is still deterministic, and everything outside it is checked only
for having rendered. That is weaker than the old golden and true, where the old
golden would have been stronger and false — it would have been asserting a share
price.

**What this costs.** `source_plan` and its dependency ordering have no consumer
on a backend that answers its own sources, and the translation table between L0's
capability names and a backend's helper names lives in that backend's lowering.
Both are the price of reaching live data without a second fetch layer, and both
are recorded here rather than discovered later.

### 5.12 What is durable

**Status: implemented, and proved on a phone.** `sys.watchlist` with `append`
and `remove`, a versioned store at `~/.config/octos-app/user.json`, and the
write path from a tap to disk. The test that matters is the one no unit test can
run: tap a row, force-stop the app, relaunch, and the entry is still there — with
its price fetched fresh, because the file held `["ATKR"]` and nothing else.

Written before the implementation, deliberately, so the implementation had
something to diverge from. Two things did diverge and both are recorded below:
`sys.prefs` is read-only, and the tap payload had to become a live call.

This answers the storage and migration halves of §8 question 8. The third half —
what a user is *entitled* to get back — is a product decision and stays open.

#### State is a cursor, not data

`selected = "NVDA"` is not a value the card holds. It is **which entity the card
is looking at** — a reference into data the card does not own. `range = "m1"` is
which slice. Once state is read as a cursor rather than as a value, three things
that look unrelated turn out to be one thing at three lifetimes:

| | what it holds | lives for |
|---|---|---|
| `selected` | one entity reference | the card |
| a watchlist | a set of entity references | indefinitely |
| `quote(NVDA)` | the entity itself | never stored; always fetched |

A watchlist is a **persisted set of the same thing `selected` holds one of**. That
is the whole of it — not a new kind of storage, the same kind of reference at a
different lifetime. §5.10 names a cell's lifetime as instance, card or session;
this is the fourth value that axis is missing, and the reason question 8 could not
be answered under a state mechanism.

#### What is stored: references, never facts

§4's no-facts rule extends to the store, and for the same reason. A stored price is
wrong within a second of being written, and a stale number that still looks live is
precisely the failure §4 exists to prevent — the shipping card drew a seeded `$181`
open beside two live values and nothing on screen distinguished them.

So a watchlist is `["NVDA", "AAPL"]`. It is not a list of rows carrying names and
prices. **Identity is durable; facts are not**, and the store may hold only the
first. Ordering is part of identity here: the array's order is the user's order.

#### A durable collection is a source, not state

It reads as a `source`, which keeps §5 intact — state remains disposable UI state
and this never becomes a second kind of cell.

```
source watch sys.watchlist(fields: [ticker, name, last, pct])
```

**The host performs the join.** It reads the stored references, fetches the live
quotes, and returns the rows. The card never sees the store, and L0 needs no join
operator — which it does not have and must not acquire.

#### Mutation: an event may target a source

One grammar addition, and only one:

```
event add  { watch: append($value) }
event drop { watch: remove($value) }
```

The target is a source rather than a state, and the capability declares which
transitions it accepts. Dispatch routes the write to the host instead of to the
`InstanceStore`; the source goes stale and §5.9's lifecycle re-fetches it.

**This does not weaken the confinement argument.** L0 is safe because it has no
expression form to evaluate, not because taps are inert — `cycle(a, b, c)` already
advances an enum with wrapping, which is runtime logic the card names and does not
write. `append($value)` is the same shape. `remove($value)` matches an exact
payload; it does not evaluate a predicate, and it must not be allowed to.

#### Why the card cannot hold this instead

Cards are **regenerated per request**. Asking for the same app twice produces a new
card and a new session. `state watch { initial: [] }` would therefore be empty
again on the next request, and would look like it worked until someone came back.
That is the decisive argument, and it is why durability is not a state feature no
matter how convenient a list-shaped cell would be.

#### Entities, and the disagreement they remove

Today a `quote` is a node and `NVDA` is not, so two reads of the same company are
unrelated values that happen to share a ticker. That is why a percentage could
render red while the price beside it rose: the tint resolved from one snapshot and
the value from another. Normalising by entity id — one `NVDA` that a watchlist
references and a detail card reads — makes the disagreement unrepresentable rather
than something to keep in sync. It is the piece that makes this a graph rather than
a pile of records, and it is worth doing for that alone.

#### Migration

The store outlives the cards that read it, and a regenerated card will ask for a
different shape. §5.8's discipline applies unchanged: **a version stamp**, so an
old file is recognised rather than misread; **tolerate unknown fields**, so a card
asking for something never stored gets "missing" rather than a failure; and **drop
rather than guess** when a shape changes, because feeding version-A data to
version-B code produces a card that renders confidently and wrongly.

#### What the implementation changed

**`sys.prefs` is read-only.** A preference write must name WHICH preference, and
a transition targets a bare source name: `event set_units { prefs: set($value) }`
says nothing about `units`. That needs a dotted target (`prefs.units:
set($value)`), which is grammar this does not have. A card may read a preference
and not yet change one. Declaring the capability writable before the target can
be aimed would have shipped a write nobody could use.

**A tap payload had to become a live call.** `Row(on_tap: keep, value: m.ticker)`
resolved its payload at realize time while the row's own text lowered to a live
call, so the two could disagree — and with no seed blob the payload was simply
empty, so the first watchlist tap was refused. Where a payload has a source
binding the backend can answer, the lowering now emits the call:

```
l0_tap("l0:{…,\"v\":\"" + sys.movers(0, "symbol") + "\"}", …)
```

That was a pre-existing defect in every tappable bound row, not one this section
introduced. It surfaced here because a watchlist is the first feature where the
payload is the whole point rather than a convenience.

**Reorder is absent.** `move(ticker, position)` needs two payloads and `value:`
carries one. `append` and `remove` cover adding and removing; ordering is the
order things were added until the grammar grows a second slot.

#### What is deliberately not adopted

The obvious reference here is GraphQL, and two of its three ideas are worth taking:
a typed schema per capability, and normalisation by entity id. The third is not.

- **No query language.** Arguments, variables, aliases and directives are a second
  language to parse, validate and confine, and L0's entire safety claim is that
  there is nothing to evaluate. The schema and the colocation are expressible in
  the grammar that already exists.
- **No resolver graph.** GraphQL assumes one endpoint over a traversable schema.
  These capabilities are heterogeneous — Yahoo, Photon, Open-Meteo, OSRM — with no
  joins between them. The only planning value is dependency ordering, and
  `source_plan` already does that.
- **Not for over-fetching.** `sys.movers` fetches one fixed URL regardless of what
  `fields:` names, so narrowing the list saves nothing on the wire. This is adopted
  for correctness. If it is ever argued for on performance, the argument is wrong.

---

### 5.13 An initial may be CAPTURED from a source

**Status: implemented and shipped before it was specified, which is the wrong order
and is why this section exists.** `RealizeReport::captured`, the host write that
freezes it, and `state from_lat { shape: number, initial: here.lat }` in the nav card
were all live while every `initial:` in this document was a literal or a token. A
review of §7 found the same failure it was written to name: an implementation grew a
construct the specification did not describe, so nothing could say whether the
behaviour was right.

A state's `initial:` may be a **path into a source**. It means *the value that source
answered the first time this card was realized*, and it is written down at that
moment:

```
source here  sys.gps()
state from_lat { shape: number, initial: here.lat }
```

**Why a path and not a literal.** "Start from where I am" is not a fact the model may
write — §4 forbids it, and rightly: a coordinate a card carries is a place the device
is not. It is also not an ordinary read, because an ordinary read FOLLOWS. Left
resolving on every realization, `from_lat` would chase the fix: an origin that moves
as you drive, and a route re-requested before it can answer. The card being replaced
has the same requirement and meets it with an imperative one-shot assignment.

**Capture is what makes the difference expressible.** The state's value is the
source's answer *at capture time*; the source goes on reporting the present, and the
two are then separate values a card can show side by side — which is exactly what a
trip from here needs, a fixed start and a moving position.

**Who does what.** The realizer decides WHAT was captured, because it owns the
precedence between a declared initial, a stored cell and the data. The host decides
WHEN it becomes durable, because it owns the store. The rule is **write-once**: a cell
that already exists is already captured and is never overwritten by a later
realization, so a transition that writes it wins from then on. A host that skips the
write gets the following behaviour, which is a bug and not a degradation: the state
re-resolves every realization and silently becomes a live read.

**This is a host write outside a transition, and it is the only one.** §2.1 excludes
assignment outside a transition from the *card*; this is the runtime recording what it
answered, not the card assigning. The distinction is worth keeping sharp, because it
is the only seam through which a cell changes without an event, and anything else
arriving through it is a defect.

**What is NOT admitted.** The path is read once and is not re-captured when the source
changes — there is no re-arming, and a card that needs a second capture declares a
second state and an event that writes it. `initial:` still admits no expression, at L0
or at L1: `initial: here.lat * 2` is refused, because the L1 grammar admits arithmetic
in an argument value and this is a declaration.

---

## 6. What makes L0 terminate

Grammar membership alone does not bound execution. These conditions do, and an implementation
must enforce all of them:

1. **The component graph is acyclic.** No recursive or mutually recursive components.
2. **Iteration is over a runtime-provided collection**, whose length the runtime bounds before
   injection.
3. **Transitions are total forms** (§3), so a single event applies in constant time per key.
4. **Event cascades are prohibited** — a transition may not trigger another event.
5. **Node count and nesting depth are capped** at realization.

With all five, an L0 realization terminates. **Without them the grammar does not**, which is
why "L0 is decidable" is a claim about authority and grammar membership, not about
termination.

Condition 4 holds **because no admitted transition form raises an event** — `set`, `toggle`,
`cycle` and `clear` all write a state cell and nothing else, and a transition target is
validated against declared state, so an event cannot be named as a write target either.

Stating that more carefully than an earlier draft did: `Form` carries a fifth variant,
`NotTotal`, for anything outside those four, and the dispatcher ends in a catch-all rather than
matching exhaustively. **So the compiler would not force a review if a variant were added.**
The property is true of the forms that exist; it is not structurally protected. Any new `Form`
variant must be checked against this condition by hand, and one that reads a path must exclude
event-typed paths explicitly.

An earlier version of this section claimed the stronger property that "no total form can name
an event". That was false when written, because component prop types were discarded and
`set(out)` was accepted where `out` was an event prop. It is now true — prop shapes survive
parsing, and event-shaped props are excluded from the readable set — but it is true by a check
rather than by the grammar, which is the distinction worth keeping. **Any new `Form` variant
must be checked against this condition**, and any form that reads a path must exclude
event-typed ones explicitly, because nothing in the type system will do it for you.

A test enumerates the syntaxes a cascade could take — `emit e`, `e()`, `n: set(1) then e`, a
transition targeting an event — and asserts each is refused. That test is a tripwire, not the
proof.

---

## 7. Level determination

A card's level is the **maximum** required by any record, resolved over the **transitive
component closure** — not by inspecting records locally:

```
uses any construct outside §2                  →  L1 or L2
instantiates a component whose level is higher →  that level
otherwise                                      →  L0
```

Level is declared in the header and checked at append. A record needing a wider grammar is
rejected until the level is explicitly raised; escalation is never silent. **Component
versions must be pinned**, or an L0 card can be moved to L2 by a definition it references
being replaced.

The check returns a **closure digest** per declared component, sorted by name. Each digest
covers its parameters, state (including shape and initial capture path), events, and view
body, plus the transitive component and view definitions it references. Loop key paths and
whether an element is a view reference are included. Definition order at file scope and
source locations are excluded; order within a definition remains significant. A component
edit that affects a dependency therefore also changes its callers' digests.

The closure digests are versioned 64-bit FNV-1a change detectors. Every declared
component receives an entry, even unused ones. They are diagnostic/cache metadata.

`approval::ArtifactApproval` separately pins the complete source, admitted level,
policy version, profile implementation, assembled kit, and a host runtime bundle
using length-delimited BLAKE3 hashes. The Octos native host builds that bundle from
its local source/resources, patched Makepad tree (including the VM, widget layer and
capability bindings), dependency lockfile, compiler version and build configuration.
It stores each policy approval under `l0-approvals/<source digest>.json`, beneath its
configuration directory. New L0/L1 artifacts may be admitted by the installed host
policy; this is not a claim that a person manually reviewed each card.

Existing approvals are verified before source resolution or mounting, and live
session approvals are verified before dispatch or durable effects. A source,
level, kit or runtime change cannot inherit a mismatching approval. Invalid records
and I/O failures fail closed; the host never silently overwrites a mismatching pin.
Reapproval is a host operation after reviewing the changed artifact. The native app
locks compiled script sources before widget registration, so file watching or Studio
live edits cannot change the approved runtime in a running process. Layout refreshes
remain available. Runtime source data is intentionally outside the code approval:
it changes without changing the card's authority. The host and its approval storage
are trusted; this is not a signature scheme against a compromised host.

Three token tests are not sufficient and an earlier draft that used them was both incomplete
and self-contradictory. Level must be an effect judgment over the closure.

**"Maximum" is a scan, not a search.** A classifier that returns at the first construct outside
L0 reports whichever appears earliest in the source, not the highest. The nav card demonstrates
it: arithmetic on line 55 precedes `fn tick()` on line 80, so a short-circuiting classifier
calls it L1 — a card with 65 imperative widget commands. The implementation must examine every
construct and keep the widest.

---

## 8. Open questions

| # | Question |
|---|---|
| ~~1~~ | ~~Whether `when` needs `else`~~ — **settled: no.** Two complementary guards suffice and both reference cards that branch already use them (`when selected == ""` / `when selected != ""`). An `else` would need the negation of the guard, and there is no expression form to negate with; adding one for this alone would buy nothing a second `when` does not already express |
| ~~2~~ | ~~Whether `enum` shapes need ordering guarantees for `cycle`~~ — **settled: yes, declaration order is normative.** `cycle` advances to the successor in the enum's declared order and wraps, which is what keeps it total and O(1). A `cycle(…)` listing a different order is **rejected**, not reordered: otherwise the card would say one order and the runtime would run another |
| ~~3~~ | ~~How a `source` declares refresh cadence, staleness and error surfaces~~ — **settled in §5.9.** Staleness and error are a four-token lifecycle the host reports and the card reads as `<source>.$state`. Cadence is not a card concern: it belongs to the capability, since how often a fetch is worth repeating is a property of the data, not of the card displaying it |
| ~~4~~ | ~~A bounded `format()`~~ — **settled**: `format:` is a declared token and the runtime applies it. A card that wrote `"$"` or `"41.2M"` itself would be authoring a fact, and currency, grouping and compaction are locale-dependent besides |
| ~~5~~ | ~~Named slots~~ — **settled in §5.5.** `slot name` in the component, `into name { … }` at the call site, anonymous slot unchanged as the default. An `into` naming a slot that does not exist is rejected rather than silently dropping its children |
| ~~6~~ | ~~An explicit state migration~~ — **settled in §5.8.** `keep: true` opts a cell out of the schema-change reset, and only while that field's own shape is unchanged |
| ~~7~~ | ~~The closed token sets per constructor argument~~ — **settled**: `docs/ui-l0-constructors.toml` is the normative catalog, and tests assert the two agree in both directions — constructor names and shared token sets, and for source capabilities the arguments too |
| **8** | **What, if anything, is durable.** **Two thirds settled in §5.12, and shipped.** The storage contract — durable *references*, never facts, read as a source and written through a declared transition on it — and the migration story (§5.8's discipline over a versioned store) are implemented and verified across an app restart on device. What stays open is the third part, and it is not a technical question: **what a user is entitled to get back.** A watchlist obviously; a scroll position obviously not; `units` and `city` are the genuinely arguable middle, and nothing in this document can settle them. The reframe that made the rest tractable: state is a **cursor** into data rather than data, so a watchlist is a persisted set of the same thing `selected` holds one of — the fourth value §5.10's lifetime axis was missing |
| **10** | **How a card says a collection is empty.** `activity` wants "Nothing close by" when a list has no members, and L0 has no length, no count and no emptiness predicate — a guard cannot tell an empty collection from a full one, so the card silently renders nothing where it should say something. Every list-shaped card wants this. The narrow fix is a predicate against a collection's emptiness, NOT a `.count` — a count is a number, and a number in a card is one operator away from arithmetic |
| **9** | **Whether component-local state (§5.10 kind 2) moves to the component kit.** The corpus says it would cost little — six kind-1 declarations against one kind-2. §5.10.1 says it cannot move alone: identity, mount/unmount and invalidation must move with it, and that protocol is unwritten. Open until the protocol exists, not until the split looks tidy |

Questions 1–7 are settled; 8 and 9 were opened by working through where state lives. What
replaces the original seven is not a shorter list but a different kind of work: the profile is
specified and implemented, and the remaining gaps are in the surrounding system rather than in
the language.

**Known gaps, stated plainly.** `makepad::lower` violates §1.1 and does so in three ways at
once: it lowers to a *backend dialect* rather than to the theme's component kit, it decides
*presentation* (ten hardcoded colours, a font-size ramp) which belongs to a theme, and it
therefore reaches one backend of three. It also defines a second `UiNode`, duplicating the one
`splash-render` already produces.

**The replacement now exists, and does not yet replace anything.** `kit::lower` emits role calls
against `Splash-Makepad`'s `components/l0/_kit.splash` — 21 roles, each verified by building it
through `splash_render::build` in the repository where that consumer lives. The three reference
cards build (news 25 nodes, stock 11, weather 62), the emitted source carries no presentation,
and live backend calls survive, because both lowerings share one value formatter.

An earlier version of this paragraph said the fix was "to retarget it at the component kit",
which assumed a kit answering L0's roles existed. None did: `components/flutter` and
`components/material` are ports of Flutter samples, and about four of L0's roles map loosely.
The kit had to be written, and that was most of the work.

**Both reasons that kept `makepad::lower` in place are now gone, and it has no production
consumer.** They were: a card lowered through the kit has no interaction, and five of the six
data visualisations lower to a named marker rather than to a chart. The first was resolved the
way this paragraph predicted — an event travels through the `tapto` attribute the renderer
already has, its non-`set:` strings falling through to the host, so an instance key survives
with no change to the VM and `docs/scoped-state.md` was not needed for it. Taps, text commits
and per-keystroke changes all reach a card through it now. The second is resolved too: all six
visualisations have kit functions and all six are in the consumer's tag table.

`makepad::lower` is still in the crate and is still exercised by the profile tests, but the
device path calls only `kit::lower`. A verification done through `makepad::lower` therefore
proves nothing about what a phone renders, which is a mistake this repository has made before.

The review's “L0–L3” names the four implementation layers: profile/realization,
kit lowering, VM/node translation, and native widget mounting/interaction. The fourth
layer is native rendering. There is no `# level: L3` language capability profile;
that header remains rejected.

L1 and L2 **as capability levels** — the levels this document's §7 classifies, not the layers
above — are a separate matter from the kit work; the two senses of "L1" are easy to conflate and
this paragraph previously did. L2 remains specified only as "what L0 excludes", is unimplemented,
and is refused before parsing. L1 is no longer in that state: **§9 specifies the one construct
the checker admits**, and the rest of L1 is still only what L0 excludes.

An earlier version of this paragraph said `StockPlot` and `AqiContour` "lower without their data
arrays". They have no data arrays: both name what to plot and fetch it themselves, and the
catalog claiming otherwise was the defect.

**Three defects found by reviewing §5.10, now fixed.** Each was a checker gap rather than a
language question, and each is held by a mutation rule:

- **A `source` and a card `state` sharing a name is refused.** The component would have read the
  source — §5.3 was not violated and card state did not leak — but which of the two a name
  resolves to depended on lookup order rather than on anything the card said.
- **A declared source that nothing reads is refused.** An unread source is a fetch the host
  performs on every refresh for data that reaches no pixel. Two shipped in the reference cards
  and no test noticed: `series` and `aqi` both went unread the moment `StockPlot` and
  `AqiContour` began fetching their own data. Both are now gone from the cards.

  One implicit read has to be counted or this rejects correct cards: resolving `copy.x` looks up
  `env.locale.lang` to choose a translation, and no path in the card names it. A purely syntactic
  scan calls `env.locale` dead on every card with copy and no other locale binding — which was
  two of the three reference cards.

- **A state write reports what it invalidated.** `dispatch_reporting` returns a `DispatchOutcome`
  — what applied, which state paths were written, and which sources those writes made stale,
  following the cascade. The pieces existed (`stale_sources`, `source_plan`) and nothing joined
  them, so a host holding `true` could not tell what to refetch. `dispatch_with_data` keeps its
  `bool` for callers that do not need the answer.

**Fixing the second one exposed a test that passed for the wrong reason**, which is the more
useful finding. `a_source_argument_path_must_be_declared` rejected a card carrying an undeclared
path in a source argument — and its fixture ended `view root Rule()`, so the source went unread.
Once unread sources were refused, the card was rejected for *that* instead, and the test passed
with the rule it exists to protect switched off. The mutation harness reported it as unprotected
the moment the new rule landed.

Component contracts were question 1 and are now specified in §5.2–§5.8, validated by adding
components to two reference cards. That exercise produced amendment #9, which nothing had
surfaced before — props are the first bindings a card author names freely, so the
token/path ambiguity was invisible until one existed.

The reference cards in `octos-one/docs/l0/` remain the evidence: any construct they need that
this document lacks is a defect here rather than in the cards. Two of the settlements above came
from that rule rather than from argument — question 1 was answered by noticing both branching
cards had already written the complementary-guard form without anyone specifying it, and
question 7 by the cards exhausting the token sets in the course of being written.

---

## 9. Level 1 — the expression form

**Status: the construct below is implemented; this section specifies it and nothing else.**

This is **not a complete L1 profile.** L1 was specified as "what L0 excludes", and the checker
then grew the ability to admit one construct — an arithmetic expression — while that sentence
was still the whole of the definition. So the checker blessed a level no document described.
This section closes exactly that gap and no more: everything else about L1 remains "what L0
excludes", and a second construct will need its own specification before it is admitted.

Written after the implementation, which is the wrong order and is why §9.8 is as long as it is.

### 9.1 Admission

A card is admitted at L1 by **declaring it**:

```
# level: L1
```

Without the header the same card is refused, and refused with a level diagnostic rather than a
syntax error. §7's rule is unchanged — a record needing a wider grammar is rejected until the
level is explicitly raised, and escalation is never silent.

**L2 is still refused before parsing.** Imperative widget commands are a *different* grammar
rather than a wider one, and nothing below the classifier parses them, so admitting a declared
L2 card would produce a parse failure dressed as an acceptance.

**Over-declaration is accepted, and this deviates from §7.** §7 derives a card's level as the
maximum any record requires. For L1 the *declared* level wins instead: a card that says
`# level: L1` and uses no expression is reported L1, not L0. Over-declaring is the conservative
direction — it asks a host for more than the card needs, never less — but the consequence is
that a reported level is not always a derived one, and a host comparing the two will not learn
that a card outgrew its own header downwards.

### 9.2 The grammar

One production is extended. `operand` was a literal, a path or a comparison; it gains a binary
arithmetic form:

```
operand   = term , { add-op , term } ;
term      = atom , { mul-op , atom } ;
atom      = literal | path | predicate ;
add-op    = "+" | "-" ;
mul-op    = "*" | "/" | "%" ;
```

Multiplicative operators bind tighter than additive ones and both associate left, so
`temp * 9 / 5 + 32` means what it reads as. Nesting is bounded at parse by the same limit every
other nested construct uses (`DEFAULT_MAX_SYNTAX_NESTING`, 128).

**Grouping and a leading minus are both in the grammar.** `atom` also admits `"(" , operand , ")"`
and a negated atom, so `(a + b) * c` overrides the fixed precedence and `n * -1` is the ordinary
way to subtract a scaled reading. A negated *literal* is a negative literal rather than an
expression, so it stays a coefficient — which also means a bare `value: -1` is refused by §4's
original rule, as a measurement the model wrote in a position that renders one.

A comparison is the **loosest** thing in an operand, so `x == a + b` compares against the sum.

**The specified position is an argument value**, which is where the motivating cards need one:

```
TextHero(value: shares * quote.last)
```

That is the only position this section admits. What the implementation additionally parses is a
defect and is recorded in §9.8.

### 9.3 §4's no-facts rule, one level up

L0 rejects a direct literal in a value position, as described in §4. **L1 cannot use that check**, because at L1 a literal in a value
position is often legitimate — a coefficient. `temp * 9 / 5 + 32` is a formula, and `9`, `5` and
`32` are not claims about the world.

So the rule changes shape rather than relaxing:

> **An expression must read at least one declared source or state.**

`shares * quote.last` reads two and is a computation. `1547 * 3.2` reads nothing: it states a
fact wearing arithmetic, and is refused. Every path an expression reads — at any depth — is
checked against declared names exactly as a bare binding is, so an expression cannot launder an
undeclared name past the check that a plain path would fail.

The checker also rejects constants recognized by a limited structural analysis: finite
literal arithmetic, identical subexpressions subtracted or reduced modulo themselves,
identical numerator and denominator, and multiplication by a known zero. These identities
are interpreted wherever the expression is defined; missing values remain missing at
runtime. Thus `last * 0 + 1547` and `(last - 2) / (last - 2) * 1547` are refused.

An unrecognized expression is **unknown**, not proven to depend on its inputs. There is no
sampling rule: `(last - 2) * (last - 5) * (last - 11)` must be accepted even though it is zero
at all three assignments used by the former implementation. This analysis is deliberately
incomplete and does not prove factual correctness or rule out every disguised constant.

### 9.4 Evaluation

Both operands must resolve to numbers. When either does not, the expression is **missing** —
rendered as the em dash a missing binding already renders as, and never as a zero. A zero would
be a fabricated number, which is the failure the level is closest to.

| Case | Result |
|---|---|
| An operand does not resolve, or is not a number | Missing |
| Division or remainder by zero | Missing |
| A result that is not finite | Missing |
| A comparison as an operand | Missing |

Evaluation is one pass over a tree already bounded at parse. It performs no name resolution — the
operands were resolved before it runs — makes no call, and cannot reach a capability, a component
or the host.

### 9.5 Lowering

A backend receives the **shape** of an expression, not the number realization computed:
each operand is either a live capability call or a constant, and each join carries its operator.
Every join lowers to `sys.l0_math(operator, left, right)`, preserving grouping and checking
finite operands, zero divisors and finite results at each operation. Missing propagates as
an em dash through further operations. Both renderer lineages install these pure helpers.

This is not an optimisation. A value computed at realization is the answer for whatever data the
host happened to seed, and a live card is seeded with nothing — so lowering the computed number
would put arithmetic over absent data on the screen, which is §5.11's defect one level up.

### 9.6 What L1 does not change

**Termination.** §6's five conditions are untouched and still sufficient. An expression is a
finite tree bounded at parse, evaluated in one pass with no calls, no recursion into the card
and no iteration, so it contributes constant work per node and cannot raise an event.

**Reconciliation.** Every path an expression reads is registered as a dependency. Under-approximating
here would show stale data, which §5.9 is explicit about.

**Everything in §§1–5, 7 and 8** applies unchanged. L1 is L0 plus this production.

### 9.7 What this costs the confinement argument

L0's confinement claim is structural in the strongest available sense: there is no expression
form, so there is nothing to evaluate, so realization never enters an evaluator at all.

**That claim does not survive L1, and no wording should suggest it does.** L1 has an evaluator.
What replaces the L0 claim is narrower and should be stated as what it is:

> A closed arithmetic evaluator over already-resolved values — five total operators over
> floating-point numbers, no name resolution at evaluation time, no operand that can name a
> capability, no host surface reachable from it, over a tree bounded at parse.

That is still a strong property, and it is a *different* property. "No execution machinery in the
path" is an L0 property. Any argument that cites it for a card must first establish the card is
L0, which is precisely what the level in the report is for.

### 9.8 Known defects and limits

Recorded rather than patched over, in the order they would bite.

- ~~**A guard's right-hand side escapes both checks.**~~ **Fixed.** `when n == nosuch * 2` was
  *accepted*: an expression in a guard was matched only as a bare path, so it was checked against
  no declared name, was not subject to §9.3's must-read rule, and its operands were not registered
  as dependencies — while realization evaluated it anyway. A guard's right operand is now walked
  like any other operand, by the same function, so all three apply there. Two neighbouring
  under-approximations went with it: a comparison's right operand in an argument
  (`active: a == b` never re-realized when `b` moved) and, in the coarse dependency query, a state
  reaching a view only through a source argument. **A guard is still not a position this section
  admits an expression in** — the implementation parses one and now checks it correctly, which is
  a narrower gap between the two than it was, and still a gap.
- ~~**Comparison and arithmetic have no defined relative precedence.**~~ **Fixed.** A
  comparison's right side took a TERM, so it bound tighter than `+`: `active: x == a + b` parsed
  as `(x == a) + b` — arithmetic over a boolean — evaluated to missing, and nothing rejected it,
  so the card was accepted, drew blank, and gave no diagnostic. A comparison is now the loosest
  thing in an operand, which is what makes `x == a + b` mean what it reads as. Its right side is
  also checked like any other operand, since it can now hold arithmetic: an undeclared name in it
  is refused, and §9.3 reaches it, so `x == 3 * 4` compares against a fabricated number and is
  refused too.
- ~~**No grouping and no unary minus.**~~ **Fixed**, per §9.2. `(a + b) * c` and `n * -1` are both
  admitted, and a bare `value: -1` is still refused by §4's original rule.
- **Constant analysis is incomplete.** §9.3 rejects structurally recognized constants and
  leaves other expressions unknown. Neither source/state reads nor arithmetic prove truth.
- ~~**A state's `initial:` was a third position, and it discarded the expression.**~~
  **Fixed.** §9.2 admits an expression in one position; §9.8 already recorded a guard as
  a second. `initial:` was a third, and the worst of the three: the parser scanned the
  dotted path and stopped, so `initial: here.lat * 2` parsed as `here.lat` and the rest
  was dropped without a diagnostic — accepted at L1, where arithmetic is otherwise
  legal, and answering a number the card did not ask for. Refused now at both levels.
  An `initial:` is a declaration of which value to capture (§5.13), and a captured
  value is read rather than computed.
- **Arithmetic is the only construct.** No comparison chain, no conditional, no string
  operation, no aggregate over a collection. §8 question 10 — how a card says a collection is
  empty — is *not* answered here, and a count is still one operator away from the arithmetic
  this section admits, which is the reason it was left alone.
- **`Form` is unchanged**, so a transition still cannot compute. `set(shares * 2)` is not
  admitted, and §6's condition 3 continues to hold for the reason it did at L0.

### Complete rendering and runtime limits

A host must call `RealizeReport::complete_root()` before mounting, capturing state or pruning
instances. Diagnostics, duplicate keys and truncation are failures even if a partial root
exists. Duplicate loop items are omitted from that diagnostic tree and are never renamed.
Patch reuse cannot replace a truncated result or overwrite a changed subtree.

Both kit walkers admit at most 128 edges of depth and 65,536 nodes. Unknown or malformed
children reject the entire tree. Kit evaluation uses a 2,000,000-instruction budget and
rejects uncaught runtime errors even if a later expression returns a node. That instruction
budget covers VM execution, not native capability work or parsing; these trusted host and
theme operations need their own resource policy. L0/L1 source parsing additionally bounds
the resulting expression AST, including flat operator chains.
