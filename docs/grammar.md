# Splash Grammar v0.1

This document specifies the portable source subset for Splash producers,
formatters, editors, and LLMs. It is intentionally narrower than the
vendored Makepad parser: compatibility syntax outside this document is not a
stable Splash language promise. `splash check` and
`splash_core::check_syntax` enforce this profile before reporting VM parser
compatibility.

The parser accepts a few legacy separator and declaration forms for Makepad
compatibility. Generated workflow source must use the canonical forms below.
Use [`splash check`](#syntax-preflight) before executing generated code.

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
hexadecimal digits or one through six digits between braces. `if`, `elif`, `else`, `for`, `in`, `loop`,
`while`, `fn`, `let`, `return`, `break`, `continue`, `use`, `true`, `false`,
and `nil` are reserved in canonical source. Strings use double quotes.

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
control-expression = "if", expression, expression-or-block,
                     { "elif", expression, expression-or-block },
                     [ "else", expression-or-block ]
                   | loop-expression ;
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

The grammar makes the portable operator precedence explicit rather than making
every inherited VM operator part of the language contract. Use parentheses
when a generated expression mixes control expressions and operators. A tool
promise is explicitly awaited with `tool.start(...).await()`; `await` is not a
standalone keyword or scheduler.

## Compatibility Boundary

`splash check` rejects Makepad-only compatibility forms even when the vendored
VM parser would accept them. This includes `var`, `match`, `try`/`ok`, typed or
destructuring declarations, numeric suffixes, single-quoted strings, range and
other noncanonical operators, and record members separated only by spaces.
The checker also rejects trailing commas where this grammar does not admit
them. This keeps LLM output deterministic: valid source has one documented
producer grammar rather than an inherited parser superset.

The VM remains the execution engine, but `Runtime::eval` and
`CapabilityRuntime::eval` now enforce this profile before evaluation. The
explicit `Runtime::eval_vm_compatibility` escape hatch deliberately opts a
trusted host into the inherited Makepad syntax; that method must not receive
LLM-generated or otherwise untrusted source. The development CLI also performs
this preflight automatically for `eval` and `run`.

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
preflight.

Rust hosts can call `splash_core::check_syntax` or
`splash_core::check_syntax_named`. These functions apply the normal source-size
limit but not instruction or deadline execution limits because they do not
execute source.
