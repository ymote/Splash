# Splash Grammar v0.2

This document specifies the portable source subset for Splash producers,
formatters, editors, and LLMs. It is intentionally narrower than the
vendored Makepad parser: compatibility syntax outside this document is not a
stable Splash language promise. `splash check` and
`splash_core::check_syntax` enforce this profile and lower canonical statement
boundaries before reporting VM parser compatibility.

The parser accepts a few legacy separator and declaration forms for Makepad
compatibility. Generated workflow source must use the canonical forms below.
Use [`splash check`](#syntax-preflight) before executing generated code.

Version 0.2 adds the canonical `try ... catch ...` expression. Every v0.1
program remains valid v0.2 source; the new form does not enable an error value,
ambient effect, or new host API.

## Lexical Rules

```ebnf
identifier       = identifier-start, { identifier-continue } ;
identifier-start = "A"..."Z" | "a"..."z" | "_" ;
identifier-continue = identifier-start | "0"..."9" ;
digit            = "0"..."9" ;
hex-digit        = digit | "a"..."f" | "A"..."F" ;

integer          = digit, { digit } ;
number           = integer, [ ".", integer ], [ exponent ] ;
exponent         = ( "e" | "E" ), [ "+" | "-" ], integer ;
string           = '"', { string-character | escape }, '"' ;
escape           = "\\", ( '"' | "\\" | "n" | "r" | "t" | unicode-escape ) ;
unicode-escape   = "u", hex-digit, hex-digit, hex-digit, hex-digit
                 | "u", "{", hex-digit, { hex-digit }, "}" ;

line-comment     = "//", { any-character-except-newline } ;
block-comment    = "/*", { any-character }, "*/" ;
```

Identifiers are case-sensitive. Unicode escapes use either exactly four
hexadecimal digits or one through six digits between braces. `if`, `elif`,
`else`, `try`, `for`, `in`, `loop`, `while`, `fn`, `let`, `return`, `break`,
`continue`, `use`, `true`, `false`, and `nil` are canonical keywords. `var`,
`match`, `ok`, `do`, `and`, `or`, `is`, `mut`, `me`, and `scope` are reserved
compatibility or contextual words and are rejected in canonical source. `catch`
is a contextual separator after a `try` branch and remains an ordinary
identifier elsewhere. A Unicode escape must encode a valid Unicode scalar
value: surrogate code points and values above `U+10FFFF` are rejected. Strings
use double quotes. A decimal point in a number must be immediately followed by
a digit; write `5 .field` or `(5).field` for intentional numeric field access.
Block-comment terminators follow the inherited streaming
tokenizer: `**/` does not form an overlapping terminator, so use a single `*`
immediately followed by `/` when closing a block comment.

## Program and Statements

```ebnf
program            = { statement, statement-end } ;
statement-end      = newline | ";" ;

statement          = import
                   | declaration
                   | function-declaration
                   | return-statement
                   | break-statement
                   | continue-statement
                   | expression ;

import             = "use", module-path ;
module-path        = "mod", ".", identifier, { ".", identifier } ;
declaration        = "let", identifier, [ "=", expression ] ;
function-declaration = "fn", identifier, parameter-list, block ;
parameter-list     = "(", [ identifier, { ",", identifier } ], ")" ;
return-statement   = "return", [ expression ] ;
break-statement    = "break" ;
continue-statement = "continue" ;
block              = "{", { statement, statement-end }, "}" ;
```

Use a newline after every top-level and block statement. Semicolons are
accepted when emitting a compact one-line program; commas are reserved for
argument, array, record-member, and parameter separation. `let` bindings may
be reassigned with an assignment operator such as `=`, `+=`, or `-=`.
Multiline records may include leading, separating, and closing newlines, but
not a trailing comma. Before canonical preflight or execution reaches the
inherited VM, Splash lowers each validated newline statement boundary to an
explicit VM semicolon. This preserves portable newline semantics even though
the inherited streaming tokenizer otherwise treats newlines as whitespace.

## Expressions

```ebnf
expression         = control-expression | assignment ;
control-expression = conditional-expression
                   | try-expression
                   | loop-expression ;
conditional-expression = "if", assignment, expression-or-block,
                         { "elif", assignment, expression-or-block },
                         [ "else", expression-or-block ] ;
try-expression     = "try", try-branch, "catch", try-branch ;
try-branch         = expression | value-block ;
value-block        = "{", { statement, statement-end },
                     expression, statement-end, "}" ;
expression-or-block = block | expression ;

loop-expression    = "for", for-bindings, "in", assignment, block
                   | "loop", block
                   | "while", assignment, block ;
for-bindings       = identifier, [ ",", identifier, [ ",", identifier ] ] ;

assignment         = logical-or, [ assignment-operator, assignment ] ;
logical-or         = logical-and, { "||", logical-and } ;
logical-and        = equality, { "&&", equality } ;
equality           = comparison, { ( "==" | "!=" ), comparison } ;
comparison         = additive, { ( "<" | "<=" | ">" | ">=" ), additive } ;
additive           = multiplicative, { ( "+" | "-" ), multiplicative } ;
multiplicative     = unary, { ( "*" | "/" | "%" ), unary } ;
unary              = [ "!" | "-" | "+" | "~" ], postfix ;
postfix            = primary,
                     { call | field-access | index-access | ".await()" } ;
call               = "(", [ expression, { ",", expression } ], ")" ;
field-access       = ".", identifier ;
index-access       = "[", expression, "]" ;

primary            = literal
                   | identifier
                   | array
                   | record
                   | "(", expression, ")"
                   | lambda ;
literal            = number | string | "true" | "false" | "nil" ;
array              = "[", [ expression, { ",", expression } ], "]" ;
record             = "{", { newline },
                     [ record-member, { record-separator, record-member }, { newline } ],
                     "}" ;
record-member      = identifier, ":", expression ;
record-separator   = ",", { newline } | newline, { newline } ;
lambda             = "||", lambda-body
                   | "|", identifier, { ",", identifier }, "|", lambda-body ;
lambda-body        = block | expression ;

assignment-operator = "=" | "+=" | "-=" | "*=" | "/=" | "%=" ;
```

The `{` immediately after `try` or `catch` always starts a value block. To use
a record literal as the whole branch, parenthesize it, for example
`try ({value: 1}) catch ({value: 0})`. A value block's final statement must be
a value-producing expression. `for`, `loop`, and `while` do not produce a
value; place an explicit `nil` or another result expression after them.

The grammar makes the portable operator precedence explicit rather than making
every inherited VM operator part of the language contract. Use parentheses
when a generated expression mixes control expressions and operators, including
when a control expression or lambda supplies an `if`/`elif`/`while` condition
or `for` iterable. For example, write `if (|| ready) { ... }` rather than an
unparenthesized lambda condition. A lambda cannot be an unparenthesized
`if`/`elif`/`else` branch; place it in a block, for example
`if ready {\n    |value| value\n}`. A tool
promise is explicitly awaited with `tool.start(...).await()`; `await` is not a
standalone keyword or scheduler.

## Recoverable Errors

`try protected catch fallback` evaluates to the protected branch's value when
that branch succeeds. An ordinary script or native-binding error unwinds
Splash function calls to the nearest active `try`, discards the error, and
evaluates the fallback branch. A fallback error can be caught only by an
enclosing `try` or otherwise reaches the host. Generated source should normally
use blocks for both branches when either branch has more than one expression.
Each branch block must end with a value-producing expression so the enclosing
`try` always has a value; write `nil` explicitly when no other value is needed.
Parenthesize a protected expression that is itself an identifier named `catch`
to disambiguate it from the separator.

The language deliberately exposes no error object, message, stack, or pattern
binding to the fallback. Assertions, type and lookup errors, denied or failed
tool calls, and a failed deferred tool after `await()` are catchable. A hard
string-allocation, heap-allocation, operand-stack, call-frame,
instruction-limit, hard evaluation deadline, or internal VM bail is not
catchable.

Recovery is control flow, not a transaction. It does not roll back a Rust
adapter effect, refund a capability call, widen a lease, erase an audit event,
or bypass a workflow input/output contract. A tool invoked by the fallback is
a separate call that must pass the same host policy. Hosts must not treat a
caught failure as proof that an external effect did not happen.

## Compatibility Boundary

`splash check` rejects Makepad-only compatibility forms even when the vendored
VM parser would accept them. This includes `var`, `match`, the legacy
catch-less `try protected fallback [ok success]` form, standalone `ok`, typed
or destructuring declarations, numeric suffixes, single-quoted strings, range
and other noncanonical operators, and record members separated only by spaces.
The checker also rejects trailing commas where this grammar does not admit
them. This keeps LLM output deterministic: valid source has one documented
producer grammar rather than an inherited parser superset.

The VM remains the execution engine, but `Runtime::eval` and
`CapabilityRuntime::eval` now enforce this profile and perform canonical
statement-boundary lowering before evaluation. The explicit
`check_vm_compatibility` and `check_vm_compatibility_named` APIs instead let a
trusted migration or UI host inspect raw inherited Makepad syntax with source,
VM-token, and delimiter-nesting bounds but without canonical lowering or
evaluation.
`Runtime::eval_vm_compatibility` uses that same preflight before it evaluates.
These compatibility APIs must not receive LLM-generated or otherwise untrusted
source, and they do not resolve imports, install modules, or grant authority.
They also reject Makepad
`@(index)` host-value tokens because standalone Splash has no host value table;
reviewed capability adapters are the Rust integration boundary. A canonical
profile rejection returns before the inherited tokenizer or parser sees the
source. The development CLI performs canonical preflight automatically for
`eval` and `run`.

The tracked [`makepad_ui_counter.splash`](../examples/makepad_ui_counter.splash)
fixture passes the bounded compatibility preflight to catch parser drift, but
it remains outside this grammar and cannot run through `splash-cli`. It
requires a Makepad UI host that supplies widget modules and `ui`; see
[Makepad UI compatibility](makepad-ui-compatibility.md).

## Canonical Workflow Source

```splash
use mod.tool
use mod.std.assert

let values = [20, 22]
let request = {left: values[0], right: values[1]}
let raw = tool.call_json("math.add", request)
let result = raw.parse_json()

fn valid_total(value) {
    return value == 42
}

assert(valid_total(result.total))
```

`use` only names a module. It never grants authority. Tool names, JSON
contracts, capabilities, and effectful execution remain host policy; the
grammar checker deliberately does not resolve them.

## Syntax Preflight

Use the CLI before evaluating a generated file:

```sh
cargo run -p splash-cli -- check workflow.splash
```

The command prints one JSON object containing `valid`, a bounded
`diagnostics` list with one-based `line` and `column` fields, and
`diagnostics_truncated`. It validates the canonical grammar first and then
checks that accepted source is compatible with the vendored VM. It never
creates a capability runtime, loads a module, invokes a tool, or executes
bytecode. By default, preflight accepts at most 256 KiB of source, 32,768
lexical tokens, and 128 nesting levels. Canonical validation applies the
nesting limit to grammar recursion; compatibility validation applies it to
structural delimiters before the vendored parser runs. Canonical source uses
that same bounded VM preflight after grammar admission, so it does not bypass
the VM tokenizer limits.

Rust hosts can call `splash_core::check_syntax` or
`splash_core::check_syntax_named`. These functions apply the normal source-size
syntax-token, and nesting limits but not instruction or deadline execution
limits because they do not execute source. Embedded hosts can lower any of
those bounds with `ExecutionLimits`.

Editor and generator tooling that needs an outline can call
`splash_core::top_level_declarations` or
`splash_core::top_level_declarations_named`. They apply the same bounded
canonical and VM-compatibility checks, then return only top-level `fn` and
`let` declarations with UTF-8 byte spans for the declaration and identifier.
Invalid source returns an empty outline; call `check_syntax` for diagnostics.
The API never evaluates source, resolves imports, or creates a capability host.

The development CLI exposes the same operation as `splash outline <file>`. It
prints JSON with `valid`, bounded diagnostics, and a `declarations` array. A
declaration has `kind` (`function` or `let`), `name`, and `declaration` and
`selection` UTF-8 byte spans. Invalid source prints its diagnostics with an
empty declaration list and exits nonzero, just as `splash check` does.

## Formatting

Format canonical source through the same profile and VM-compatibility checks:

```sh
cargo run -p splash-cli -- format workflow.splash
```

The formatter writes to standard output and never modifies the input file. It
preserves comments and the spelling of identifiers, numbers, and string
literals, while normalizing horizontal whitespace, existing-line indentation,
line endings, and trailing whitespace. It is idempotent. It rejects invalid
source and Makepad-only compatibility syntax instead of applying recovery or
rewriting it into a different language contract.

Canonical source accepts LF and CRLF line endings. A bare carriage return is
rejected because the vendored VM does not treat it as a statement separator;
formatted output uses LF.

Use `splash format --check workflow.splash` to exit nonzero when formatting
would change the source. Rust hosts can call `splash_core::format_source` or
`splash_core::format_source_named`; both use the supplied `ExecutionLimits`
source, syntax-token, and nesting bounds, cap output at four times the source
budget, and never evaluate code.

## Editor protocol

`splash-lsp` exposes the same effect-free validation and formatting operations
over stdio LSP. It uses UTF-16 positions, requests full-document sync, and
supports `textDocument/didOpen`, `textDocument/didChange`,
`textDocument/didClose`, `textDocument/formatting`,
`textDocument/documentSymbol`, `textDocument/definition`,
`textDocument/references`, `textDocument/hover`, and
`textDocument/documentHighlight`, `textDocument/completion`, and
`textDocument/signatureHelp`. When the client supports versioned
`documentChanges`, it also advertises
`textDocument/prepareRename` and `textDocument/rename`. Document symbols list
only top-level `fn` and `let` declarations after canonical syntax succeeds. The
other semantic requests use a grammar-aware same-document lexical index for the
final binding introduced by `use`, named functions, `let`, function and lambda
parameters, and `for` bindings already introduced in a visible runtime scope.
Lexical hover reports only that binding kind, and highlights use the neutral
text kind rather than claiming read/write analysis. The index is bounded to
4,096 retained definition/reference occurrences. Retained definition and hover
results remain sound after truncation, but exhaustive reference, highlight, and
rename requests fail when that bound is exceeded.

Completion sites are identifiers parsed in expression position. Declarations,
import paths, record keys, and names after `.` are excluded. The cursor may be
inside the identifier or exactly at its end. The result contains the complete
retained set of lexical bindings visible at the token start, deduplicated by
the innermost binding and sorted by name; it is deliberately not filtered by
the current token spelling. Each item carries a `textEdit` that replaces the
whole identifier. The site list has its own 4,096-entry cap, and either a
truncated symbol index or site list sets `isIncomplete`. A retained site can be
served after site-list truncation, but symbol-index truncation returns no
candidates because an omitted inner definition could shadow a retained outer
binding. In invalid source, a site is eligible only when it ends at or before
the first syntax diagnostic.

Separately, the server recognizes an exact visible direct initializer of the
form `let binding = { ... }` plus exact `let alias = binding`,
`let alias = binding.child`, or `let alias = binding.child.grandchild` source
edges. At a direct `binding.field` member site, or a direct
`binding.child.grandchild.field` site where both child values are whole
literals, including a lexical alias chain of at most 16 hops with at most two
direct alias child selections in total, whether in one edge or spread across
the chain, it offers the retained field names, hovers a known field, and
defines it at the literal key. Alias targets resolve at their source position,
preserving lexical shadowing. This is bounded source
metadata, not general type inference: it does not follow parenthesized or
computed aliases, parenthesized or computed child values, alias or member paths
beyond that two-level budget, assignments, control flow, function returns,
imports, or runtime values.
Duplicate fields at any retained literal level discard that level's nested
shape. It retains at most 1,024 root shapes, 4,096 aggregate retained literal
fields, and 1,024 alias edges. A truncated shape report marks its completion
incomplete and never exposes a partial field list for a binding. A truncated
alias report returns no static field items, marks completion incomplete, and
disables static field hover and definition. The LSP stops using a shape after an
earlier direct write or a potentially mutating member, index, call, or escape
path through the root or any retained root, child, or grandchild alias that resolves to it.
Static field hover and definition also fail closed when the lexical index is
truncated, because an omitted earlier reference could be a mutation.

Separately, the core `imported_module_call_hint_report` review API can preserve
an imported `mod.*` path through an exact local `let alias = binding` chain of
at most 16 hops for an exact `alias.method(...)` call. It examines every
reference in that import-alias group and accepts only another exact group alias
or a direct member call; writes, member aliases, indexing, calls that pass the
value onward, and incomplete alias metadata suppress the hint. This whole-group
rule also rejects a call captured in a function when a later source statement
could rewrite the receiver before invocation.
This is a bounded pre-approval presentation aid, not module resolution or
authorization. The LSP catalog behavior below can use the same stable exact
root-alias form for advisory module metadata, but remains source-only and
keeps fixed `mod.tool` suggestions limited to a direct visible import binding.

The server separately recognizes an exact visible `use mod.tool` binding. At a
direct `tool.` member site it offers the fixed `call`, `call_json`, `start`, and
`start_json` methods. An editor integration may also provide a bounded advisory
tool-catalog projection at `initializationOptions.splash.toolCatalog` or a
later `settings.splash.toolCatalog` configuration update. The LSP retains only
bounded `name`, `format`, and `description` metadata and uses it only for the
first literal argument of direct visible `tool.call`/`tool.start`
(matching `text`) or `tool.call_json`/`tool.start_json` (matching `json`). It
never reads a host runtime, URI, file, adapter, or environment to obtain that
projection, and a suggestion does not make a capability installed, approved,
or callable. An omitted key retains prior metadata, JSON `null` explicitly
clears it, and malformed, duplicate, or over-limit input is discarded as a
whole rather than presented partially.

For an exact visible imported capability-module leaf, the optional advisory
`moduleCatalog` may additionally declare `callMode`, `callShape: "single_json"`,
and compact `inputFields` and `outputFields`. Each field has a canonical
identifier, one fixed JSON type, a required bit, and optional plain-text
description. An object output field may carry one direct child `fields` list;
input fields and output children cannot. The LSP shows both bounded field lists in leaf hover and signature
help, and can complete an undeclared top-level key in the first direct
literal-record argument from `inputFields`. For an exact source binding through
a direct visible import or qualifying exact root alias, such as
`let result = receiver.method(input)` on a synchronous leaf, or the exact
`let result = receiver.method(input).await()` form on a deferred leaf, it also
completes and hovers root `result.field` names from `outputFields` and one
retained object-child path such as `result.summary.total`. It can follow exact
local `let alias = result` chains of at most 16 hops and serves the same paths
at `alias.summary.total`. The whole result-alias group, including aliases
declared after the member site, must remain stable; truncated alias metadata
makes output completion empty and incomplete. That bounded recognizer rejects
parenthesized or computed aliases, deeper alias chains, mutations or escapes,
parenthesized or computed initializers, extra arguments, other postfix chains,
result paths below that child level, shadowed imports, and source beyond the
safe diagnostic prefix. It does not complete nested input-record keys, evaluate
JSON Schema, read a runtime, validate a contract, or grant a capability. Record
fields without the exact one-JSON-value call shape, and any malformed or
over-limit field projection, fail closed with the rest of the advisory module
metadata.

For host-managed dataflow authoring, an editor may separately provide the
bounded `initializationOptions.splash.workflowDataCatalog` projection. The LSP
uses it only for direct unshadowed `workflow.input.*` and
`workflow.outputs.<stepId>.*` completion and field hover. It is static advisory
metadata, not a JSON Schema loader or a runtime snapshot: it cannot establish
that an output is completed, validate a value, approve a plan, issue a lease,
or make an adapter callable. A visible local or imported `workflow` binding
shadows it, absent metadata creates no namespace, and malformed input fails
closed. The optional `workflowDataStepContext` admits only an exact prefix of
the catalog's projected outputs and its next projected step, then filters output
completion and hover to that prefix. A host using `splash-workflow` can generate
that pair from an exact suspended continuation or validated checkpoint, but the
LSP remains unable to inspect or authorize runtime state. A host can replace the
complete pair through `workspace/didChangeConfiguration`; partial or malformed
relevant updates fail closed instead of retaining stale fields. See [Editor
workflow-data projection](workflow-data-catalog.md). Sending both workflow keys
as JSON `null` explicitly clears a prior projection after terminal state.

Rename does not edit the final segment of a `use` path. For another indexed
binding it accepts exactly one non-reserved canonical identifier, rewrites the
definition and resolved references in memory, validates the resulting canonical
and VM-compatible source, remaps every symbol span, and requires the entire new
lexical report to match. A capture or shadowing change therefore fails closed.
The returned edit targets only the client-supplied URI and carries the exact
open-document version. This preserves the indexed lexical model only; unindexed
forward references, modules, fields, types, and name-coupled runtime behavior
remain outside the claim.

The lexical service does not load or resolve imported modules, infer forward
references or general types, follow arbitrary aliases or mutations, treat
record keys or general member fields as variables, enumerate builtins, discover
a host tool catalog, or grant tool authority. The bounded direct literal-record
and direct-alias metadata above is advisory and remains separate from those
lexical bindings. The optional
initialization-time or configuration-refresh catalog projection is advisory
client metadata, not a catalog lookup. Tool and module keys refresh
independently; neither affects the atomic workflow-data pair. The server does
not open the URI supplied by the client or run source. A malformed `settings`
value or non-object `settings.splash` clears all advisory catalogs. All
diagnostics, edits, symbols, definitions, references, hovers, highlights,
completions, and rename validation derive from client-provided document text
and optional advisory metadata.
