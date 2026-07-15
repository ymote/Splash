# Splash Grammar v0.2

This document specifies the portable source subset for Splash producers,
formatters, editors, and LLMs. It is intentionally narrower than the
vendored Makepad parser: compatibility syntax outside this document is not a
stable Splash language promise. `splash check` and
`splash_core::check_syntax` enforce this profile before reporting VM parser
compatibility.

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
`match`, `ok`, and `do` are reserved compatibility words and are rejected in
canonical source. `catch` is a contextual separator after a `try` branch and
remains an ordinary identifier elsewhere. A Unicode escape must encode a valid
Unicode scalar value: surrogate code points and values above `U+10FFFF` are
rejected. Strings use double quotes.

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
not a trailing comma.

## Expressions

```ebnf
expression         = control-expression | assignment ;
control-expression = conditional-expression
                   | try-expression
                   | loop-expression ;
conditional-expression = "if", expression, expression-or-block,
                         { "elif", expression, expression-or-block },
                         [ "else", expression-or-block ] ;
try-expression     = "try", try-branch, "catch", try-branch ;
try-branch         = expression | value-block ;
value-block        = "{", { statement, statement-end },
                     expression, statement-end, "}" ;
expression-or-block = block | expression ;

loop-expression    = "for", for-bindings, "in", expression, block
                   | "loop", block
                   | "while", expression, block ;
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
when a generated expression mixes control expressions and operators. A tool
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
tool calls, and a failed deferred tool after `await()` are catchable. An
instruction-limit stop, hard evaluation deadline, or internal VM bail is not
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
`CapabilityRuntime::eval` now enforce this profile before evaluation. The
explicit `Runtime::eval_vm_compatibility` escape hatch deliberately opts a
trusted host into the inherited Makepad syntax; that method must not receive
LLM-generated or otherwise untrusted source. A profile rejection returns before
the inherited tokenizer or parser sees the source. The development CLI also
performs this preflight automatically for `eval` and `run`.

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
bytecode. Canonical profile nesting is bounded to 128 levels during this
preflight, and the default lexical-token budget is 32,768.

Rust hosts can call `splash_core::check_syntax` or
`splash_core::check_syntax_named`. These functions apply the normal source-size
and syntax-token limits but not instruction or deadline execution limits
because they do not execute source. Embedded hosts can lower either bound with
`ExecutionLimits`.

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

Use `splash format --check workflow.splash` to exit nonzero when formatting
would change the source. Rust hosts can call `splash_core::format_source` or
`splash_core::format_source_named`; both use the supplied `ExecutionLimits`
source and syntax-token bounds, cap output at four times the source budget,
and never evaluate code.

## Editor protocol

`splash-lsp` exposes the same effect-free validation and formatting operations
over stdio LSP. It uses UTF-16 positions, requests full-document sync, and
supports `textDocument/didOpen`, `textDocument/didChange`,
`textDocument/didClose`, `textDocument/formatting`,
`textDocument/documentSymbol`, `textDocument/definition`,
`textDocument/references`, `textDocument/hover`, and
`textDocument/documentHighlight`. Document symbols list only top-level `fn` and
`let` declarations after canonical syntax succeeds. The other semantic requests
use a grammar-aware same-document lexical index for the final binding introduced
by `use`, named functions, `let`, function and lambda parameters, and `for`
bindings already introduced in a visible runtime scope. Hover reports only that
lexical binding kind, and highlights use the neutral text kind rather than
claiming read/write analysis. The index is bounded to 4,096 retained
definition/reference occurrences. Retained definition and hover results remain
sound after truncation, but exhaustive reference and highlight requests fail
when that bound is exceeded.

The lexical service does not load or resolve imported modules, infer forward
references or types, treat record keys or member fields as variables, or grant
tool authority. The server does not open the URI supplied by the client or run
source; all diagnostics, edits, symbols, definitions, references, hovers, and
highlights derive from the client-provided document text.
