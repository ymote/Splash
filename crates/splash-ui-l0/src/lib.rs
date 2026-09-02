//! **UI Profile Level 0** — a canonical Splash profile for LLM-authored UI.
//!
//! A generated card is untrusted source. L0 admits UI constructs while admitting
//! nothing that can reach a capability: constructors, bindings, keyed loops,
//! guarded branches, and components with declared local state, and **no
//! expression form at all**. With nothing to evaluate, realization is a walk
//! over the parsed tree with data substituted, and this crate contains no
//! reference to a VM. Confinement is structural rather than sandboxed.
//!
//! The normative profile is `docs/ui-profile-l0.md`; the closed constructor and
//! capability catalog is `docs/ui-l0-constructors.toml`. Where this code and
//! those documents disagree, the documents win — and a test asserts the catalog
//! agrees with the Rust table in both directions.
//!
//! # Why this is its own crate
//!
//! It depends on `serde_json` and nothing else, so any host can adopt L0 without
//! adopting a runtime. That is not a stylistic preference: `splash-core` carries
//! a vendored `makepad-script`, and an application already using a different
//! makepad lineage cannot depend on it — Cargo refuses the lockfile, because
//! both ship `makepad-error-log v1.0.0` at different paths. L0 never needed
//! that dependency; it inherited it by living in the same crate.
//!
//! Level 0 of the UI profile — parser and validator for generated card source.
//!
//! See [`docs/ui-profile-l0.md`](../../../docs/ui-profile-l0.md) for the normative
//! grammar and [`docs/ui-l0-constructors.toml`](../../../docs/ui-l0-constructors.toml)
//! for the argument contract. The catalog in [`catalog`] is the implementation's
//! copy of that TOML; a test asserts the two agree.
//!
//! ## What this establishes, and what it does not
//!
//! Two properties are decided here: **membership in the L0 grammar**, and **absence
//! of any authority-bearing operation**. The second is structural rather than
//! enforced — the grammar has no syntax for a module access or a call, so there is
//! nothing to reject; the checks for `mod.` and `ui.<id>.<method>` exist to classify
//! such source as a higher level with a useful diagnostic, not to hold a boundary.
//!
//! Termination is **not** established. It needs the five conditions in §6 of the
//! profile, of which this checks two: the component graph is acyclic, and iteration
//! is over a bound path rather than an expression. Collection length, node count and
//! nesting depth are the runtime's to bound.
//!
//! Everything is effect-free and bounded: no evaluation, no imports, no host access.

/// One one-based location. Mirrors `splash_core::SyntaxDiagnostic` in shape;
/// separate so this crate stands alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntaxDiagnostic {
    pub line: usize,
    pub column: usize,
    pub message: String,
}
/// Largest source this profile will read. Matches `splash-core`'s bound, so a
/// card refused there is refused here for the same reason.
pub const DEFAULT_MAX_SOURCE_BYTES: usize = 256 * 1024;
/// Maximum delimiter nesting. Bounds parse recursion — see the deep-path tests,
/// which exist because unbounded recursion aborted the process on a 60 KB card.
pub const DEFAULT_MAX_SYNTAX_NESTING: usize = 128;

/// The narrowest profile a source belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Level {
    /// Constructors, bindings, keyed loops, guarded branches, components with
    /// declared local state. No expression form, no reachable capability.
    L0,
    /// Adds pure expressions. Not accepted by this checker.
    L1,
    /// Full Splash, including imperative widget commands. Not accepted here.
    L2,
}

/// Result of checking source against the L0 profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UiL0Report {
    pub valid: bool,
    /// The narrowest level the source belongs to. `valid` is true only for
    /// [`Level::L0`].
    pub level: Level,
    pub diagnostics: Vec<SyntaxDiagnostic>,
    pub diagnostics_truncated: bool,
    /// The header a card declares — profile §2. `None` when it has none.
    pub header: Option<CardHeader>,
    /// Profile §7: every component the card depends on, with a digest of its
    /// definition, sorted by name.
    ///
    /// This is what a host pins. `level` is a judgment over the transitive
    /// component closure, so it is only as durable as the definitions it was
    /// computed from — replace one and an approved L0 card can silently become
    /// L2. Storing this alongside the approved level makes that detectable:
    /// a digest that moved means the level must be re-derived before the card
    /// is accepted, rather than inherited from the record it no longer matches.
    pub closure: Vec<(String, u64)>,
    /// Advisories: the card is valid and will realize, but something in it will
    /// not survive a change of theme. Separate from `diagnostics` on purpose —
    /// a lint that could refuse a card would be a rule, and these are not rules.
    pub lints: Vec<SyntaxDiagnostic>,
}

/// What a card's header declares — ledger name, version, level and profile.
///
/// §7 says "level is declared in the header and checked at append", and nothing
/// read it: every `#` line lexed as a comment, so a card could declare
/// `# level: L2` and be accepted and realized as L0. A declared level that is
/// never compared to the derived one is not a check, it is a comment.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CardHeader {
    pub ledger: Option<String>,
    pub version: Option<String>,
    pub level: Option<String>,
    pub profile: Option<String>,
    pub model: Option<String>,
    /// Fields declared more than once with different values. Last-wins made
    /// `# level: L2` followed by `# level: L0` accepted, so a card could
    /// declare whatever it needed and then declare the truth after it.
    pub contradictions: Vec<String>,
}

/// Read the header from the leading `#` lines, which the lexer discards.
pub fn parse_header(source: &str) -> Option<CardHeader> {
    let mut header = CardHeader::default();
    let mut saw_any = false;
    for line in source.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix('#') else {
            if line.is_empty() {
                continue;
            }
            break; // The header is the leading comment block only.
        };
        let rest = rest.trim();
        if let Some(decl) = rest.strip_prefix("ledger ") {
            saw_any = true;
            let (name, version) = match decl.split_once('@') {
                Some((n, v)) => (n.trim().to_string(), Some(v.trim().to_string())),
                None => (decl.trim().to_string(), None),
            };
            // A card has ONE identity. Last-wins let a record declare two.
            match (&header.ledger, &header.version) {
                (Some(first), v) if *first != name || *v != version => {
                    header.contradictions.push(format!(
                        "the header declares the ledger twice, as {first:?} and {name:?}"
                    ));
                }
                _ => {
                    header.ledger = Some(name);
                    header.version = version;
                }
            }
        } else if let Some((key, value)) = rest.split_once(':') {
            let value = value.trim().to_string();
            match key.trim() {
                "level" => {
                    saw_any = true;
                    match &header.level {
                        Some(first) if *first != value => {
                            header.contradictions.push(format!(
                                "the header declares level twice, as {first:?} and {value:?}"
                            ));
                        }
                        _ => header.level = Some(value),
                    }
                }
                "profile" => {
                    saw_any = true;
                    match &header.profile {
                        Some(first) if *first != value => {
                            header.contradictions.push(format!(
                                "the header declares profile twice, as {first:?} and {value:?}"
                            ));
                        }
                        _ => header.profile = Some(value),
                    }
                }
                "model" => {
                    // Presence counts: a header of only `model:` lines used to
                    // return None, taking any contradiction in it along too.
                    saw_any = true;
                    match &header.model {
                        Some(first) if *first != value => {
                            header.contradictions.push(format!(
                                "the header declares the model twice, as {first:?} and {value:?}"
                            ));
                        }
                        _ => header.model = Some(value),
                    }
                }
                _ => {}
            }
        }
    }
    saw_any.then_some(header)
}

/// Diagnostics retained before truncation, so a pathological source cannot grow
/// the report without bound.
pub const MAX_UI_L0_DIAGNOSTICS: usize = 64;

/// Maximum declarations retained from one card.
pub const MAX_UI_L0_DECLARATIONS: usize = 1_024;

/// Check source against the L0 profile.
pub fn check_ui_l0(source: &str) -> UiL0Report {
    check_ui_l0_named("card.l0", source)
}

/// Check source against the L0 profile, naming it for diagnostics.
pub fn check_ui_l0_named(_name: &str, source: &str) -> UiL0Report {
    let mut sink = Diagnostics::default();
    let header = parse_header(source);

    if source.len() > DEFAULT_MAX_SOURCE_BYTES {
        sink.push(
            1,
            1,
            format!(
                "source is {} bytes, over the {DEFAULT_MAX_SOURCE_BYTES}-byte limit",
                source.len()
            ),
        );
        return sink.into_report(Level::L0);
    }

    let tokens = match lex(source, &mut sink) {
        Some(tokens) => tokens,
        None => return sink.into_report(Level::L0),
    };

    // A construct outside the grammar tells us the level before parsing can
    // finish, and a level diagnostic is far more useful than "unexpected token".
    // A card that DECLARES L1 is parsed, not refused.
    //
    // §7 says a record needing a wider grammar is rejected "until the level is
    // explicitly raised" — so raising it explicitly is the whole point. Without
    // this the classifier could name L1 and never admit one, which is what
    // `roadmap.md` meant by "can name them but cannot check them". L2 stays
    // refused here: imperative widget commands are a different grammar, not a
    // wider one, and nothing below parses them.
    let declared_l1 = header
        .as_ref()
        .and_then(|h| h.level.as_deref())
        .is_some_and(|l| l.trim() == "L1");
    if let Some((level, diag)) = classify_beyond_l0(&tokens) {
        if !(declared_l1 && level == Level::L1) {
            sink.push(diag.line, diag.column, diag.message);
            let mut report = sink.into_report(level);
            report.header = header.clone();
            // Compare here too: this is the path a card that UNDER-declares its
            // level takes, and it was the one path that skipped the comparison.
            check_header(&header, level, &mut report);
            return report;
        }
    }

    let mut parser = Parser::new(&tokens, &mut sink);
    let card = parser.parse_card();
    if sink.any() {
        return sink.into_report(Level::L0);
    }

    validate(&card, &mut sink);
    let derived = if declared_l1 { Level::L1 } else { Level::L0 };
    let mut report = sink.into_report(derived);
    report.closure = component_closure(&card);
    report.header = header.clone();
    check_header(&header, report.level, &mut report);
    check_theme_portability(source, &mut report);
    report
}

/// Text that carries its own colour cannot follow a theme.
///
/// A colour-font glyph — an emoji — is painted from the emoji font with the
/// colours baked into it, so `draw_text.color` never reaches it. A card using
/// one as an icon renders correctly under exactly the polarity its author had on
/// screen, and is invisible under the other. Measured: 54 of 967 corpus cards do
/// this, and on a light ground their icons vanish entirely — four separate judge
/// verdicts named it before anyone thought to look for the cause.
///
/// This is an advisory, not a rule. The card is valid; it is just not portable,
/// and nothing else in the pipeline can tell you so.
fn check_theme_portability(source: &str, report: &mut UiL0Report) {
    // A conservative sweep of the pictographic blocks plus the variation
    // selector. Latin, CJK and punctuation are all monochrome and take the
    // theme's ink correctly, so nothing outside these ranges is a concern.
    fn pictographic(c: char) -> bool {
        matches!(c as u32,
            0x1F300..=0x1FAFF   // emoji, pictographs, symbols
            | 0x2600..=0x27BF   // misc symbols and dingbats
            | 0x1F000..=0x1F2FF // tiles, enclosed characters
            | 0xFE0F            // variation selector: "render this in colour"
        )
    }

    for (n, line) in source.lines().enumerate() {
        // Only the argument positions that end up as painted text. A comment or
        // a `query:` string never reaches a glyph.
        for key in ["text:", "glyph:"] {
            let mut rest = line;
            let mut base = 0usize;
            while let Some(at) = rest.find(key) {
                let after = &rest[at + key.len()..];
                if let Some(open) = after.find('"') {
                    let body = &after[open + 1..];
                    if let Some(close) = body.find('"') {
                        let lit = &body[..close];
                        if let Some(c) = lit.chars().find(|c| pictographic(*c)) {
                            report.lints.push(SyntaxDiagnostic {
                                line: n + 1,
                                column: base + at + 1,
                                message: format!(
                                    "{c:?} is a colour-font glyph, so it ignores the theme's \
                                     ink and stays the colour it was drawn in — this card will \
                                     render correctly in one polarity and invisibly in the \
                                     other. Use an icon role, or accept that the card is \
                                     single-theme."
                                ),
                            });
                        }
                        base += at + key.len() + open + 1 + close + 1;
                        rest = &body[close + 1..];
                        continue;
                    }
                }
                break;
            }
        }
    }
}

/// §7: a declared level must match the derived one, and escalation is never
/// silent. Reading the header without comparing it would leave the declaration
/// decorative — which is what it was.
fn check_header(header: &Option<CardHeader>, derived: Level, report: &mut UiL0Report) {
    let Some(header) = header else { return };

    for message in &header.contradictions {
        report.valid = false;
        report.diagnostics.push(SyntaxDiagnostic {
            line: 1,
            column: 1,
            message: message.clone(),
        });
    }

    if let Some(declared) = &header.level {
        let matches = match declared.trim() {
            "L0" => derived == Level::L0,
            "L1" => derived == Level::L1,
            "L2" => derived == Level::L2,
            _ => false,
        };
        if !matches {
            report.valid = false;
            report.diagnostics.push(SyntaxDiagnostic {
                line: 1,
                column: 1,
                message: format!(
                    "the header declares level {declared}, but the card requires {derived:?} \
                     — a record needing a wider grammar is rejected until the level is \
                     explicitly raised (profile §7)"
                ),
            });
        }
    }

    // The profile names which grammar the card was written against. A card
    // claiming a profile this checker does not implement must not be silently
    // accepted as though it had claimed this one.
    if let Some(profile) = &header.profile {
        if profile.trim() != "ui/l0" {
            report.valid = false;
            report.diagnostics.push(SyntaxDiagnostic {
                line: 1,
                column: 1,
                message: format!(
                    "the header declares profile {profile:?}, but this checker implements \
                     \"ui/l0\""
                ),
            });
        }
    }
}

/// A digest per component definition, sorted by name — profile §7.
///
/// The digest covers everything that can move a card's level or change what it
/// renders: params, state, events and the whole view body. It deliberately does
/// NOT cover the component's position in the file, so reordering declarations is
/// not a version change.
fn component_closure(card: &Card) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = card
        .components
        .iter()
        .map(|c| (c.name.clone(), definition_digest(c)))
        .collect();
    out.sort();
    out
}

fn definition_digest(component: &Component) -> u64 {
    fn element(e: &Element, into: &mut String) {
        into.push_str(&e.name);
        into.push('(');
        for b in &e.binders {
            into.push_str(b);
            into.push(',');
        }
        for a in &e.args {
            into.push_str(&a.name);
            into.push(':');
            into.push_str(&format!("{:?}", a.value));
            into.push(',');
        }
        if let Some(cmp) = &e.cmp {
            into.push_str(cmp);
        }
        if let Some(rhs) = &e.rhs {
            into.push_str(&format!("{rhs:?}"));
        }
        into.push('|');
        for child in &e.children {
            element(child, into);
        }
        into.push(')');
    }

    let mut acc = String::new();
    acc.push_str(&component.name);
    for p in &component.params {
        acc.push_str(&format!("{}:{:?}:{:?}", p.name, p.shape, p.default));
        acc.push(',');
    }
    for st in &component.states {
        acc.push_str(&format!(
            "{}:{:?}:{:?}:{:?}:{}",
            st.path, st.shape, st.initial, st.initial_path, st.keep
        ));
    }
    for ev in &component.events {
        acc.push_str(&ev.name);
        for t in &ev.transitions {
            acc.push_str(&format!("{}={:?}{:?}", t.target, t.form, t.tokens));
        }
    }
    element(&component.body, &mut acc);

    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in acc.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

// ─────────────────────────────────────────────────────────────────── diagnostics ──

#[derive(Default)]
struct Diagnostics {
    items: Vec<SyntaxDiagnostic>,
    truncated: bool,
}

impl Diagnostics {
    fn push(&mut self, line: usize, column: usize, message: String) {
        if self.items.len() >= MAX_UI_L0_DIAGNOSTICS {
            self.truncated = true;
            return;
        }
        self.items.push(SyntaxDiagnostic {
            line,
            column,
            message,
        });
    }

    fn at(&mut self, t: &Token, message: String) {
        self.push(t.line, t.column, message);
    }

    fn any(&self) -> bool {
        !self.items.is_empty()
    }

    fn into_report(self, level: Level) -> UiL0Report {
        UiL0Report {
            header: None,
            closure: Vec::new(),
            // Valid AT ITS LEVEL, not "is L0".
            //
            // This read `level == Level::L0`, which was right while L0 was the
            // only level this checker admitted: an L1 card reached here with no
            // diagnostics and was still reported invalid, with nothing to say
            // why. L2 is refused before parsing, so anything arriving here is L0
            // or a card that declared L1.
            valid: self.items.is_empty() && level != Level::L2,
            level,
            diagnostics: self.items,
            diagnostics_truncated: self.truncated,
            lints: Vec::new(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────── lexer ──

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Ident,
    /// A dotted token: `.fill`. Tokens are lexically marked so a bare identifier
    /// is always a path — see profile §2.2.
    Token,
    Str,
    Num,
    Punct,
    Cmp,
}

#[derive(Clone, Debug)]
struct Token {
    kind: Kind,
    text: String,
    line: usize,
    column: usize,
}

impl Token {
    fn is(&self, kind: Kind, text: &str) -> bool {
        self.kind == kind && self.text == text
    }
    fn is_kw(&self, kw: &str) -> bool {
        self.is(Kind::Ident, kw)
    }
    fn is_punct(&self, p: &str) -> bool {
        self.is(Kind::Punct, p)
    }
}

fn lex(source: &str, sink: &mut Diagnostics) -> Option<Vec<Token>> {
    let bytes: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let (mut i, mut line, mut col) = (0usize, 1usize, 1usize);

    while i < bytes.len() {
        let c = bytes[i];

        if c == '\n' {
            line += 1;
            col = 1;
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            col += 1;
            continue;
        }
        // Comments: `#` to end of line. The profile's cards use `#`; `//` is
        // rejected so a Splash-syntax card cannot be mistaken for an L0 one.
        if c == '#' || (c == '/' && i + 1 < bytes.len() && bytes[i + 1] == '/') {
            while i < bytes.len() && bytes[i] != '\n' {
                i += 1;
            }
            continue;
        }

        let (start_line, start_col) = (line, col);

        // String literal.
        if c == '"' {
            let mut text = String::new();
            i += 1;
            col += 1;
            let mut closed = false;
            while i < bytes.len() {
                if bytes[i] == '"' {
                    i += 1;
                    col += 1;
                    closed = true;
                    break;
                }
                if bytes[i] == '\n' {
                    break;
                }
                text.push(bytes[i]);
                i += 1;
                col += 1;
            }
            if !closed {
                sink.push(start_line, start_col, "unterminated string".into());
                return None;
            }
            out.push(Token {
                kind: Kind::Str,
                text,
                line: start_line,
                column: start_col,
            });
            continue;
        }

        // Dotted token, but only when a name follows — `.` between path segments
        // is punctuation and is handled below.
        if c == '.' && i + 1 < bytes.len() && is_ident_start(bytes[i + 1]) {
            // A `.` directly after an identifier, token, or `]` is a path
            // separator, not a token marker.
            let after_value = out
                .last()
                .map(|t: &Token| {
                    matches!(t.kind, Kind::Ident | Kind::Token | Kind::Num) || t.is_punct("]")
                })
                .unwrap_or(false);
            if !after_value {
                let mut text = String::from(".");
                i += 1;
                col += 1;
                while i < bytes.len() && is_ident_continue(bytes[i]) {
                    text.push(bytes[i]);
                    i += 1;
                    col += 1;
                }
                out.push(Token {
                    kind: Kind::Token,
                    text,
                    line: start_line,
                    column: start_col,
                });
                continue;
            }
        }

        // Comparators.
        if matches!(c, '=' | '!' | '<' | '>') {
            let two = i + 1 < bytes.len() && bytes[i + 1] == '=';
            // A lone `<` or `>` IS a comparator; a lone `=` or `!` is not.
            //
            // These were one rule, and it made `when a > b` — the exact form
            // §"what is not here" tells an agent to write instead of `if a > b` —
            // unparseable. `compare` has implemented `<` and `>` all along and
            // could never be reached with them, so the guards a card was told to
            // write were refused for a lexer rule about `!x`.
            //
            // Nothing else in the grammar uses an angle bracket, so there is no
            // ambiguity to preserve: no generics, no arrows, no tags.
            let one_char_cmp = matches!(c, '<' | '>');
            let text: String = if two {
                let s: String = bytes[i..i + 2].iter().collect();
                i += 2;
                col += 2;
                s
            } else {
                i += 1;
                col += 1;
                c.to_string()
            };
            // A lone `=` or `!` is punctuation. Without this `!x` lexes as Cmp
            // and the level classifier's punctuation check never fires.
            if !two && !one_char_cmp {
                out.push(Token {
                    kind: Kind::Punct,
                    text,
                    line: start_line,
                    column: start_col,
                });
            } else {
                out.push(Token {
                    kind: Kind::Cmp,
                    text,
                    line: start_line,
                    column: start_col,
                });
            }
            continue;
        }

        // Number.
        if c.is_ascii_digit() {
            let mut text = String::new();
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == '.') {
                // Stop at a `.` that starts a name — `7.foo` is a path, not a float.
                if bytes[i] == '.' && (i + 1 >= bytes.len() || !bytes[i + 1].is_ascii_digit()) {
                    break;
                }
                text.push(bytes[i]);
                i += 1;
                col += 1;
            }
            out.push(Token {
                kind: Kind::Num,
                text,
                line: start_line,
                column: start_col,
            });
            continue;
        }

        // Identifier.
        if is_ident_start(c) {
            let mut text = String::new();
            while i < bytes.len() && is_ident_continue(bytes[i]) {
                text.push(bytes[i]);
                i += 1;
                col += 1;
            }
            out.push(Token {
                kind: Kind::Ident,
                text,
                line: start_line,
                column: start_col,
            });
            continue;
        }

        // Punctuation, including operators the grammar does not admit. Those are
        // kept as tokens so `classify_beyond_l0` can report them as L1 rather
        // than as a lex failure.
        if "{}()[]:,.$+-*/%?|&".contains(c) {
            i += 1;
            col += 1;
            out.push(Token {
                kind: Kind::Punct,
                text: c.to_string(),
                line: start_line,
                column: start_col,
            });
            continue;
        }

        sink.push(start_line, start_col, format!("unexpected character {c:?}"));
        return None;
    }

    Some(out)
}

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

// ───────────────────────────────────────────────────────────── level classifier ──

/// Report the level implied by any construct outside L0, before parsing.
///
/// Level is a property of the whole card: the maximum any record requires
/// (profile §7). Component-closure resolution happens in [`validate`]; this is
/// the lexical half.
fn classify_beyond_l0(tokens: &[Token]) -> Option<(Level, SyntaxDiagnostic)> {
    let mut worst: Option<(Level, SyntaxDiagnostic)> = None;
    let mut keep = |found: Option<(Level, SyntaxDiagnostic)>| {
        if let Some((level, diag)) = found {
            let better = match &worst {
                Some((Level::L2, _)) => false,
                Some((Level::L1, _)) => level == Level::L2,
                _ => true,
            };
            if better {
                worst = Some((level, diag));
            }
        }
    };
    for (i, t) in tokens.iter().enumerate() {
        let bad = |level: Level, msg: &str| {
            Some((
                level,
                SyntaxDiagnostic {
                    line: t.line,
                    column: t.column,
                    message: msg.into(),
                },
            ))
        };

        if t.is_kw("fn") {
            keep(bad(
                Level::L2,
                "`fn` is not in L0: a function reintroduces unbounded work",
            ));
        }
        if t.is_kw("while") {
            keep(bad(
                Level::L2,
                "`while` is not in L0: iteration must be over a declared collection",
            ));
        }
        if t.is_kw("let") || t.is_kw("var") {
            keep(bad(
                Level::L2,
                "`let` is not in L0: state is declared, not bound imperatively",
            ));
        }
        if t.is_kw("mod") && tokens.get(i + 1).is_some_and(|n| n.is_punct(".")) {
            keep(bad(
                Level::L2,
                "module access is not in L0: the host surface is empty",
            ));
        }
        // `ui.<id>.<method>` — an imperative widget command.
        if t.is_kw("ui")
            && tokens.get(i + 1).is_some_and(|n| n.is_punct("."))
            && tokens.get(i + 3).is_some_and(|n| n.is_punct("."))
        {
            keep(bad(
                Level::L2,
                "imperative widget commands are L2: L0 declares a tree",
            ));
        }
        if t.kind == Kind::Punct && matches!(t.text.as_str(), "+" | "*" | "/" | "%" | "?") {
            keep(bad(
                Level::L1,
                "arithmetic and conditional expressions are not in L0: an expression can hide a fabricated fact",
            ));
        }
        // A copy class is a hyphenated NAME, not a subtraction: `class:
        // user-copy` lexes as `user`, `-`, `copy`, and reading that as
        // arithmetic made the two spellings §4 depends on unusable — the
        // provenance rule could not be written in a card at all.
        let is_class_name = tokens
            .get(i.wrapping_sub(3))
            .is_some_and(|k| k.text == "class")
            && tokens.get(i.wrapping_sub(1)).is_some_and(|p| {
                p.kind == Kind::Ident && matches!(p.text.as_str(), "user" | "model")
            });

        // `-` is only rejected between values; a negative literal is fine.
        if t.is_punct("-")
            && !is_class_name
            && tokens
                .get(i.wrapping_sub(1))
                .is_some_and(|p| matches!(p.kind, Kind::Ident | Kind::Num | Kind::Token))
        {
            keep(bad(Level::L1, "arithmetic is not in L0"));
        }
        if t.is_punct("!") {
            keep(bad(
                Level::L1,
                "negation is computation: use the `toggle` transition form",
            ));
        }
    }
    worst
}

// ────────────────────────────────────────────────────────────────────────── ast ──

#[derive(Debug, Default)]
struct Card {
    sources: Vec<SourceDecl>,
    states: Vec<StateDecl>,
    events: Vec<EventDecl>,
    /// `copy` declarations: name -> locale -> text. Authored in the ledger, so
    /// they resolve from the CARD rather than the injected data. Carrying them
    /// in the data blob duplicated what the card already said, and the two
    /// silently drifted.
    copies: Vec<CopyDecl>,
    components: Vec<Component>,
    views: Vec<View>,
    /// The card's declared theme INTENT, and the line it was declared on.
    ///
    /// A name, never a colour. §4 forbids a card stating presentation, and that
    /// does not change here: `theme dark` says which of a closed set of moods
    /// this card is in, and the layer above — the component kit — decides what
    /// dark looks like. A card that wants a look no theme name covers does not
    /// get to describe it.
    theme: Option<(String, usize)>,
    /// Axis intents declared on the same line as the mood, in source order.
    theme_axes: Vec<(String, String)>,
}

/// A declared capability dependency: the name it binds, the helper that answers
/// it, and the arguments. Parsed rather than skipped — a card that declares what
/// data it needs is useless if nothing can read the declaration.
#[derive(Clone, Debug)]
struct SourceDecl {
    name: String,
    helper: String,
    args: Vec<(String, SourceArg)>,
    line: usize,
}

/// One argument to a capability query. None of these is computed.
#[derive(Clone, Debug, PartialEq)]
pub enum SourceArg {
    /// A path into another source, card state, or a declared value.
    Path(String),
    Text(String),
    Number(f64),
    /// `fields: [temp, hi, lo]` — which fields the card needs back.
    List(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Shape {
    Text,
    Number,
    Bool,
    Enum(Vec<String>),
    /// A structured value a source returns — §5.2, a component prop shape.
    Record,
    /// An iterable a `for` walks.
    Collection,
    /// An event passed in, so a component can report outward (§5.4).
    Event,
    /// A shape the declaration did not name.
    ///
    /// `Text` and `Number` used to land here too, which made them
    /// indistinguishable: retyping a state between them changed neither the
    /// schema id nor the closure digest, so live values survived a change that
    /// should have reset them.
    Other,
}

/// Authored text, with the provenance that decides whether it may be rendered.
///
/// The provenance was parsed and thrown away — and worse, `parse_locale_map`
/// only kept entries whose value was a STRING, so `class: vocabulary` (an
/// identifier) was dropped before anything could read it. §4's "a literal in a
/// data position must be vocabulary or source-derived" was therefore not merely
/// unenforced but undecidable: nothing recorded which kind a string was.
#[derive(Clone, Debug)]
struct CopyDecl {
    name: String,
    provenance: Provenance,
    locales: Vec<(String, String)>,
}

/// Who wrote a piece of text, and therefore whether it can be trusted on screen.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Provenance {
    /// Fixed interface language — labels, units, headings. Translatable, and
    /// carries no claim about the world.
    #[default]
    Vocabulary,
    /// Text the user wrote. Theirs to be wrong about.
    UserCopy,
    /// Text the MODEL wrote. May not appear in a rendering position: this is
    /// the class §4 exists to keep off the screen, because a model-authored
    /// string is indistinguishable from a fact it invented.
    ModelCopy,
}

/// A component's declared input — §5.2.
///
/// The shape was parsed and dropped, which cost three separate defects: an
/// unknown argument at a call site could not be told from a known one, an event
/// prop could not be told from a value, and every param had to be treated as a
/// possible event name because none could be ruled out.
#[derive(Clone, Debug)]
struct Param {
    name: String,
    shape: Shape,
    /// `title: text = "Safe"`. Dropped, an omitted argument created no binding
    /// at all and lookup fell through to top-level injected data — so an
    /// unfilled prop could capture whatever the host happened to supply under
    /// the same name.
    default: Option<serde_json::Value>,
}

#[derive(Debug)]
struct StateDecl {
    path: String,
    shape: Shape,
    /// The declared `initial`. Parsed rather than discarded: without it a guard
    /// on a freshly-mounted state compares against null and takes the wrong
    /// branch on first render.
    initial: Option<serde_json::Value>,
    /// A path-valued `initial`, e.g. `initial: env.locale.temp_unit`. Held
    /// separately because it resolves against injected data at realization,
    /// not at parse. Dropping it made weather.card fall back to the enum's
    /// first member, so a device set to Fahrenheit still rendered Celsius.
    initial_path: Option<String>,
    /// `keep: true` — profile §5.8. A schema change resets local state by
    /// default; this opts one cell out, and even then only while its own shape
    /// is unchanged. Preservation is never inferred from a shape that merely
    /// looks compatible.
    keep: bool,
}

/// An event and the transition batch it applies. Profile §3: an event names
/// several transitions, applied atomically.
#[derive(Debug)]
struct EventDecl {
    name: String,
    transitions: Vec<Transition>,
}

#[derive(Debug)]
struct Transition {
    target: String,
    form: Form,
    /// `cycle` members, which must be declared in the target's enum shape.
    tokens: Vec<String>,
    line: usize,
    column: usize,
}

#[derive(Clone, Debug, PartialEq)]
enum Form {
    Set(SetSource),
    Toggle,
    Cycle,
    Clear,
    /// §5.12's two collection forms. Unlike the four above, these do NOT write a
    /// cell: the target is a source backed by a durable store, and dispatch
    /// hands the write to the host. Total for the same reason `cycle` is — the
    /// card names the operation and the runtime performs it.
    Append,
    Remove,
    /// §3's collection cousins of `cycle`: move a TEXT cell to the next/prev
    /// value of a collection field (`city: next(cities.name)`), wrapping.
    /// Total like cycle — the card names the walk, the runtime performs it —
    /// which is what a swipe gesture needs a declared transition for.
    Next(String),
    Prev(String),
    /// Anything else — an expression, which L0 has no form for.
    NotTotal(String),
}

impl Form {
    /// Whether this form writes a durable collection rather than a state cell.
    fn is_collection(&self) -> bool {
        matches!(self, Form::Append | Form::Remove)
    }
}

/// What `set(…)` assigns. Each is a value the runtime already holds; none is
/// computed, so the transition stays total.
#[derive(Clone, Debug, PartialEq)]
enum SetSource {
    /// `$value` — the payload from the element that raised the event.
    Payload,
    /// A `.token`, e.g. an enum member.
    Token(String),
    /// A string literal.
    Text(String),
    /// A bound path, resolved against the data the runtime injected.
    Path(String),
    /// A numeric literal. Without this `set(1)` parsed as `Payload` and did
    /// nothing at all when no payload was present.
    Num(f64),
    /// A boolean literal.
    Bool(bool),
}

#[derive(Debug)]
struct Component {
    name: String,
    params: Vec<Param>,
    states: Vec<StateDecl>,
    events: Vec<EventDecl>,
    body: Element,
    line: usize,
    /// Components this one instantiates, for the acyclicity check.
    instantiates: Vec<String>,
}

#[derive(Debug)]
struct View {
    name: String,
    body: Element,
}

#[derive(Clone, Debug, Default)]
struct Element {
    /// Constructor name, a referenced view/component name, or empty for a group.
    name: String,
    args: Vec<Arg>,
    children: Vec<Element>,
    /// Bindings a `for` introduces: the item and the optional index.
    binders: Vec<String>,
    line: usize,
    column: usize,
    is_reference: bool,
    /// `when` guard: comparator and right-hand operand, absent for a bare bool.
    cmp: Option<String>,
    rhs: Option<Operand>,
    /// `for` loop: the per-item key expression. Identity never comes from position.
    key_path: Option<String>,
}

#[derive(Clone, Debug)]
struct Arg {
    name: String,
    value: Operand,
    line: usize,
    column: usize,
}

#[derive(Clone, Debug)]
enum Operand {
    Path(String),
    Token(String),
    Str(String),
    Num(f64),
    /// A comparison in argument position: `active: range == .d1`.
    ///
    /// Previously this kept only the left path and discarded the comparator and
    /// right operand, so `active: range == .d1` realized as the VALUE of
    /// `range` rather than as a boolean — live in stock.card, and invisible
    /// because the device golden recorded the wrong rendering as correct.
    /// **L1 only.** Arithmetic over already-declared values: `shares * quote.last`.
    ///
    /// The model supplies the FORMULA; the runtime computes it. That split is
    /// what keeps §4's no-facts rule true one level up — a card may combine
    /// facts it declared, and still cannot state one it never observed.
    Expr {
        lhs: Box<Operand>,
        op: String,
        rhs: Box<Operand>,
    },
    Predicate {
        path: String,
        cmp: String,
        rhs: Box<Operand>,
    },
}

// ─────────────────────────────────────────────────────────────────────── parser ──

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
    sink: &'a mut Diagnostics,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token], sink: &'a mut Diagnostics) -> Self {
        Self {
            tokens,
            at: 0,
            sink,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    /// One token further on, for a decision that needs to see two: a `-` is a
    /// negative literal or a negation depending on what follows it.
    fn peek_at(&self, ahead: usize) -> Option<&Token> {
        self.tokens.get(self.at + ahead)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.at).cloned();
        if t.is_some() {
            self.at += 1;
        }
        t
    }

    fn eat_punct(&mut self, p: &str) -> bool {
        if self.peek().is_some_and(|t| t.is_punct(p)) {
            self.at += 1;
            return true;
        }
        false
    }

    fn expect_punct(&mut self, p: &str) -> bool {
        if self.eat_punct(p) {
            return true;
        }
        match self.peek().cloned() {
            Some(t) => self
                .sink
                .at(&t, format!("expected {p:?}, found {:?}", t.text)),
            None => self
                .sink
                .push(0, 0, format!("expected {p:?}, found end of source")),
        }
        false
    }

    fn ident(&mut self) -> Option<String> {
        match self.peek().cloned() {
            Some(t) if t.kind == Kind::Ident => {
                self.at += 1;
                Some(t.text)
            }
            Some(t) => {
                self.sink
                    .at(&t, format!("expected a name, found {:?}", t.text));
                None
            }
            None => {
                self.sink
                    .push(0, 0, "expected a name, found end of source".into());
                None
            }
        }
    }

    fn parse_card(&mut self) -> Card {
        let mut card = Card::default();
        let mut guard = 0usize;

        while self.peek().is_some() {
            guard += 1;
            if guard > MAX_UI_L0_DECLARATIONS {
                self.sink.push(0, 0, "too many declarations".into());
                break;
            }
            let Some(t) = self.peek().cloned() else { break };
            let before = self.at;

            match t.text.as_str() {
                "source" => {
                    self.at += 1;
                    let line = t.line;
                    if let Some(name) = self.dotted_name() {
                        let (helper, args) = self.parse_source_query();
                        card.sources.push(SourceDecl {
                            name,
                            helper,
                            args,
                            line,
                        });
                    }
                }
                "state" => {
                    self.at += 1;
                    if let Some(d) = self.parse_state() {
                        card.states.push(d);
                    }
                }
                "event" => {
                    self.at += 1;
                    if let Some(e) = self.parse_event() {
                        card.events.push(e);
                    }
                }
                "copy" => {
                    self.at += 1;
                    if let Some(n) = self.ident() {
                        let (provenance, locales) = self.parse_locale_map();
                        // Absent `class` is NOT vocabulary. Defaulting to
                        // trusted meant the rule only bit when a card
                        // volunteered the label, which a model with something to
                        // hide would simply not do.
                        let provenance = match provenance {
                            Some(p) => p,
                            None => {
                                self.sink.at(
                                    &t,
                                    format!(
                                        "copy {n:?} declares no `class`; L0 needs one of \
                                         `vocabulary`, `user-copy` or `model-copy` \
                                         (profile §4)"
                                    ),
                                );
                                Provenance::ModelCopy
                            }
                        };
                        card.copies.push(CopyDecl {
                            name: n,
                            provenance,
                            locales,
                        });
                    }
                }
                "theme" => {
                    self.at += 1;
                    let line = t.line;
                    if let Some(name) = self.ident() {
                        if let Some((first, first_line)) = &card.theme {
                            self.sink.at(
                                &t,
                                format!(
                                    "a card declares ONE theme; {first:?} was already \
                                     declared on line {first_line}"
                                ),
                            );
                            let _ = first;
                        } else if catalog::theme(&name).is_none() {
                            self.sink.at(
                                &t,
                                format!(
                                    "{name:?} is not a theme L0 admits; a card names a \
                                     catalogued mood and never a colour (profile §4). \
                                     Known: {}",
                                    catalog::THEMES.join(", ")
                                ),
                            );
                        } else {
                            card.theme = Some((name, line));
                        }
                        // Axes follow the mood ON THE SAME LINE:
                        //     theme light shape: .square accent: .amber
                        // The lexer discards newlines, so "same line" is
                        // enforced against `Token.line` rather than by grammar
                        // shape — without that check the next declaration's
                        // first identifier would be eaten as an axis name.
                        while self
                            .peek()
                            .is_some_and(|t| t.line == line && t.kind == Kind::Ident)
                            && self.peek_at(1).is_some_and(|t| t.is(Kind::Punct, ":"))
                        {
                            let axis = self.ident().unwrap_or_default();
                            self.at += 1; // the colon
                            let Some(v) = self.peek().cloned() else { break };
                            self.at += 1;
                            let value = v.text.trim_start_matches('.').to_owned();
                            match catalog::axis(&axis) {
                                None => self.sink.at(
                                    &v,
                                    format!(
                                        "{axis:?} is not a theme axis L0 admits. Known: {}",
                                        catalog::AXES
                                            .iter()
                                            .map(|(n, _)| *n)
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    ),
                                ),
                                Some(legal) if !legal.contains(&value.as_str()) => self.sink.at(
                                    &v,
                                    format!(
                                        "{value:?} is not a value {axis:?} admits; a card names \
                                         a catalogued intent and never a colour or a length \
                                         (profile §4). Known: {}",
                                        legal.join(", ")
                                    ),
                                ),
                                Some(_) => {
                                    if card.theme_axes.iter().any(|(a, _)| *a == axis) {
                                        self.sink.at(
                                            &v,
                                            format!("{axis:?} is declared twice on this theme"),
                                        );
                                    } else {
                                        card.theme_axes.push((axis, value));
                                    }
                                }
                            }
                        }
                    }
                }
                "component" => {
                    self.at += 1;
                    if let Some(c) = self.parse_component() {
                        card.components.push(c);
                    }
                }
                "view" => {
                    self.at += 1;
                    let Some(name) = self.ident() else { break };
                    let body = self.parse_element();
                    card.views.push(View { name, body });
                }
                _ => {
                    self.sink.at(
                        &t,
                        format!(
                            "expected a declaration (source, state, event, copy, theme, component, view), found {:?}",
                            t.text
                        ),
                    );
                    self.at += 1;
                }
            }

            // Never loop without consuming; a malformed card must terminate.
            if self.at == before {
                self.at += 1;
            }
        }
        card
    }

    /// `a.b.c`, `a.0.c`, `a[b]` — amendments #3 and #4. A constant index and an
    /// index by a bound path are both total lookups, so neither is an expression.
    fn dotted_name(&mut self) -> Option<String> {
        let mut name = self.ident()?;
        let mut guard = 0usize;
        loop {
            guard += 1;
            if guard > 32 {
                break;
            }
            // `.$state` — the source lifecycle suffix (§5.9). It is the one
            // segment that starts with a sigil, which is what keeps it from
            // colliding with a field a source might actually return.
            let next_is_status = self.peek().is_some_and(|t| t.is_punct("."))
                && self
                    .tokens
                    .get(self.at + 1)
                    .is_some_and(|t| t.is_punct("$"))
                && self
                    .tokens
                    .get(self.at + 2)
                    .is_some_and(|t| t.kind == Kind::Ident && t.text == "state");
            if next_is_status {
                self.at += 3;
                name.push_str(".$state");
                continue;
            }

            let next_is_segment = self.peek().is_some_and(|t| t.is_punct("."))
                && self
                    .tokens
                    .get(self.at + 1)
                    .is_some_and(|t| matches!(t.kind, Kind::Ident | Kind::Num));
            if next_is_segment {
                self.at += 1;
                let Some(seg) = self.next() else { break };
                name.push('.');
                name.push_str(&seg.text);
                continue;
            }
            if self.peek().is_some_and(|t| t.is_punct("[")) {
                if self.depth > DEFAULT_MAX_SYNTAX_NESTING {
                    if let Some(t) = self.peek().cloned() {
                        self.sink.at(&t, "nesting is too deep".into());
                    }
                    return Some(name);
                }
                self.at += 1;
                self.depth += 1;
                // The index is itself a path and must be RETAINED, not just
                // recognised: dropping it turned `stories[selected].title` into
                // `stories.title`, which resolved to nothing and rendered an
                // em dash. Held as a `[…]` segment so lookup can resolve the
                // inner path and use its value as the key.
                let index = self.dotted_name();
                self.depth -= 1;
                if let Some(index) = index {
                    name.push_str(".[");
                    name.push_str(&index);
                    name.push(']');
                }
                self.expect_punct("]");
                continue;
            }
            break;
        }
        Some(name)
    }

    /// A source body is a capability query the runtime executes. It is not
    /// evaluated here and its shape is the runtime's contract, so it is skipped
    /// to the end of its balanced parentheses.
    /// `sys.weather(lat: place.lat, fields: [temp, hi])` — the helper and its
    /// arguments. The body is a query the RUNTIME executes; the view can only
    /// bind to its result, which is what keeps the host surface empty.
    fn parse_source_query(&mut self) -> (String, Vec<(String, SourceArg)>) {
        let mut helper = String::new();
        while let Some(t) = self.peek().cloned() {
            if t.kind == Kind::Ident || t.is_punct(".") {
                helper.push_str(&t.text);
                self.at += 1;
            } else {
                break;
            }
        }

        let mut args = Vec::new();
        if !self.eat_punct("(") {
            return (helper, args);
        }
        let mut guard = 0usize;
        loop {
            guard += 1;
            if guard > 64 || self.peek().is_none() {
                break;
            }
            if self.eat_punct(")") {
                break;
            }
            let Some(name) = self.ident() else {
                self.at += 1;
                continue;
            };
            if !self.eat_punct(":") {
                break;
            }
            let value = match self.peek().cloned() {
                Some(t) if t.is_punct("[") => {
                    self.at += 1;
                    // One item per COMMA, so a dotted path stays whole.
                    //
                    // This took every Ident/Str/Num token as its own item, and a
                    // path is three of them: `via: [stop.0.lat, stop.0.lon]` became
                    // six items — `stop`, `0`, `lat`, `stop`, `0`, `lon` — so
                    // nothing resolved and the waypoint was dropped. The route then
                    // went straight from origin to destination while the card
                    // displayed a stop the trip did not visit.
                    //
                    // `fields: [id, name]` is unaffected: single-token items are
                    // still one item each.
                    let mut items: Vec<String> = Vec::new();
                    let mut current = String::new();
                    while let Some(i) = self.peek().cloned() {
                        if i.is_punct("]") {
                            break;
                        }
                        if i.is_punct(",") {
                            if !current.is_empty() {
                                items.push(std::mem::take(&mut current));
                            }
                        } else if matches!(i.kind, Kind::Ident | Kind::Str | Kind::Num) {
                            current.push_str(&i.text);
                        } else if i.is_punct(".") {
                            current.push('.');
                        }
                        self.at += 1;
                    }
                    if !current.is_empty() {
                        items.push(current);
                    }
                    self.expect_punct("]");
                    SourceArg::List(items)
                }
                Some(t) if t.kind == Kind::Str => {
                    self.at += 1;
                    SourceArg::Text(t.text)
                }
                // A NEGATIVE literal, as `parse_atom` already allows in argument
                // position. This grammar had no case for it, so `lon: -122.4194`
                // failed at the `-` with "expected a name" — which meant no card
                // could name a coordinate in the western hemisphere, or a
                // temperature below zero, without going through `sys.geocode`.
                Some(t)
                    if t.is_punct("-") && self.peek_at(1).is_some_and(|n| n.kind == Kind::Num) =>
                {
                    let n = self.peek_at(1).map(|n| n.text.clone()).unwrap_or_default();
                    self.at += 2;
                    SourceArg::Number(-n.parse::<f64>().unwrap_or(0.0))
                }
                Some(t) if t.kind == Kind::Num => {
                    self.at += 1;
                    SourceArg::Number(t.text.parse().unwrap_or(0.0))
                }
                Some(t) if t.kind == Kind::Token => {
                    self.at += 1;
                    SourceArg::Text(t.text.trim_start_matches('.').to_string())
                }
                Some(t) if t.kind == Kind::Ident => {
                    SourceArg::Path(self.dotted_name().unwrap_or(t.text))
                }
                _ => {
                    self.at += 1;
                    continue;
                }
            };
            args.push((name, value));
            if !self.eat_punct(",") {
                self.expect_punct(")");
                break;
            }
        }
        (helper, args)
    }

    fn skip_braced(&mut self) {
        if self.peek().is_some_and(|t| t.is_punct("{")) {
            self.skip_balanced("{", "}");
        }
    }

    fn skip_balanced(&mut self, open: &str, close: &str) {
        let mut depth = 0usize;
        while let Some(t) = self.peek().cloned() {
            if t.is_punct(open) {
                depth += 1;
            } else if t.is_punct(close) {
                depth -= 1;
                self.at += 1;
                if depth == 0 {
                    return;
                }
                continue;
            }
            self.at += 1;
        }
    }

    fn parse_state(&mut self) -> Option<StateDecl> {
        let path = self.dotted_name()?;
        let mut shape = Shape::Other;
        let mut initial = None;
        let mut initial_path = None;
        let mut keep = false;
        // `{ shape: enum[a, b], initial: .a, keep: true }`.
        //
        // Read the value AFTER each key rather than scanning the body for shape
        // words. Scanning meant a member of an enum could retype the state it
        // belonged to: `shape: enum[a, text]` parsed as the enum and then the
        // member `text` overwrote it, so the field accepted any string.
        if self.peek().is_some_and(|t| t.is_punct("{")) {
            let mut scan = self.at + 1;
            let mut saw_shape = false;
            while let Some(t) = self.tokens.get(scan) {
                if t.is_punct("}") {
                    break;
                }
                let is_key = t.kind == Kind::Ident
                    && self.tokens.get(scan + 1).is_some_and(|n| n.is_punct(":"));
                if !is_key {
                    scan += 1;
                    continue;
                }
                let key = t.text.clone();
                let value = self.tokens.get(scan + 2);
                match key.as_str() {
                    "shape" => {
                        saw_shape = true;
                        shape = match value.map(|v| v.text.as_str()) {
                            Some("text") => Shape::Text,
                            Some("number") => Shape::Number,
                            Some("bool") => Shape::Bool,
                            Some("record") => Shape::Record,
                            Some("collection") => Shape::Collection,
                            Some("event") => Shape::Event,
                            Some("enum") => {
                                let mut members = Vec::new();
                                let mut at = scan + 4; // past `enum` and `[`
                                while let Some(m) = self.tokens.get(at) {
                                    if m.is_punct("]") {
                                        break;
                                    }
                                    if m.kind == Kind::Ident {
                                        members.push(m.text.clone());
                                    }
                                    at += 1;
                                }
                                Shape::Enum(members)
                            }
                            Some(other) => {
                                // A misspelling used to become `Other`, which
                                // the `set` checks treat as "accepts anything" —
                                // so a typo silently disabled them.
                                let other = other.to_string();
                                if let Some(v) = value {
                                    self.sink.at(
                                        v,
                                        format!(
                                            "{other:?} is not an L0 shape; L0 has text, \
                                             number, bool, enum[…], record, collection \
                                             and event"
                                        ),
                                    );
                                }
                                Shape::Other
                            }
                            None => Shape::Other,
                        };
                    }
                    "initial" => {
                        if let Some(v) = value {
                            initial = match v.kind {
                                Kind::Str => Some(serde_json::Value::String(v.text.clone())),
                                Kind::Token => Some(serde_json::Value::String(
                                    v.text.trim_start_matches('.').to_string(),
                                )),
                                Kind::Num => {
                                    v.text.parse::<f64>().ok().map(serde_json::Value::from)
                                }
                                Kind::Ident if v.text == "true" || v.text == "false" => {
                                    Some(serde_json::Value::Bool(v.text == "true"))
                                }
                                Kind::Ident => {
                                    let mut path = v.text.clone();
                                    let mut at = scan + 3;
                                    while self.tokens.get(at).is_some_and(|t| t.is_punct("."))
                                        && self
                                            .tokens
                                            .get(at + 1)
                                            .is_some_and(|t| t.kind == Kind::Ident)
                                    {
                                        path.push('.');
                                        path.push_str(&self.tokens[at + 1].text);
                                        at += 2;
                                    }
                                    // AND NOTHING MORE. The scan above stops at the
                                    // end of the path, so `initial: here.lat * 2`
                                    // parsed as `here.lat` and the rest was
                                    // discarded — accepted at L1, silently answering
                                    // something the card did not ask for.
                                    //
                                    // §9.2 admits an expression in ONE position, an
                                    // argument value. An `initial:` is a declaration
                                    // (§5.13): it names which value to capture, and a
                                    // captured value is READ rather than computed.
                                    // Refusing is what keeps the two apart; dropping
                                    // the operator quietly is the one outcome neither
                                    // reading supports.
                                    if self.tokens.get(at).is_some_and(|t| {
                                        t.kind == Kind::Punct
                                            && matches!(
                                                t.text.as_str(),
                                                "+" | "-" | "*" | "/" | "%"
                                            )
                                    }) {
                                        let t = self.tokens[at].clone();
                                        self.sink.at(
                                            &t,
                                            format!(
                                                "`initial:` takes a value or a source path, \
                                                 not an expression — `{path} {}` was parsed as \
                                                 `{path}` and the rest discarded (profile \
                                                 §5.13, §9.2)",
                                                t.text
                                            ),
                                        );
                                    }
                                    initial_path = Some(path);
                                    None
                                }
                                _ => None,
                            };
                        }
                    }
                    "keep" => {
                        keep = value.is_some_and(|v| v.kind == Kind::Ident && v.text == "true");
                    }
                    _ => {}
                }
                scan += 1;
            }

            if !saw_shape {
                if let Some(t) = self.peek().cloned() {
                    self.sink
                        .at(&t, format!("state {path:?} declares no `shape`"));
                }
            }
            self.skip_braced();
        }

        Some(StateDecl {
            path,
            shape,
            initial,
            initial_path,
            keep,
        })
    }

    /// `{ class: vocabulary, en: "…", zh: "…" }` — the text per locale.
    fn parse_locale_map(&mut self) -> (Option<Provenance>, Vec<(String, String)>) {
        let mut out = Vec::new();
        let mut provenance = None;
        if !self.eat_punct("{") {
            return (provenance, out);
        }
        let mut guard = 0usize;
        while let Some(t) = self.peek().cloned() {
            guard += 1;
            if guard > 64 || t.is_punct("}") {
                break;
            }
            if t.kind == Kind::Ident
                && self
                    .tokens
                    .get(self.at + 1)
                    .is_some_and(|n| n.is_punct(":"))
            {
                if let Some(v) = self.tokens.get(self.at + 2) {
                    // `class:` names a provenance and its value is an
                    // IDENTIFIER, which the string-only filter below discarded.
                    if t.text == "class" {
                        // `-` lexes as punctuation, so `user-copy` arrives as
                        // the identifier `user`. Match the head rather than
                        // reassembling: the three classes differ there.
                        provenance = Some(match v.text.as_str() {
                            "user" => Provenance::UserCopy,
                            "model" => Provenance::ModelCopy,
                            "vocabulary" => Provenance::Vocabulary,
                            other => {
                                self.sink.at(
                                    v,
                                    format!(
                                        "{other:?} is not a copy class; L0 has \
                                         `vocabulary`, `user-copy` and `model-copy`"
                                    ),
                                );
                                Provenance::Vocabulary
                            }
                        });
                    } else if v.kind == Kind::Str {
                        out.push((t.text.clone(), v.text.clone()));
                    }
                }
            }
            self.at += 1;
        }
        self.expect_punct("}");
        (provenance, out)
    }

    /// `event name { path: total-form, … }`
    fn parse_event(&mut self) -> Option<EventDecl> {
        let name = self.ident()?;
        let mut transitions = Vec::new();

        if !self.eat_punct("{") {
            return Some(EventDecl { name, transitions });
        }
        let mut guard = 0usize;
        loop {
            guard += 1;
            if guard > 64 || self.peek().is_none() {
                break;
            }
            if self.eat_punct("}") {
                break;
            }
            let Some(head) = self.peek().cloned() else {
                break;
            };
            let Some(target) = self.dotted_name() else {
                self.at += 1;
                continue;
            };
            if !self.expect_punct(":") {
                break;
            }

            let (form, tokens) = self.parse_total_form();
            transitions.push(Transition {
                target,
                form,
                tokens,
                line: head.line,
                column: head.column,
            });

            if !self.eat_punct(",") {
                self.expect_punct("}");
                break;
            }
        }
        Some(EventDecl { name, transitions })
    }

    /// One of `set(v)`, `toggle`, `cycle(.a, .b)`, `clear` — profile §3. Anything
    /// else is recorded as not-total so validation can name it.
    fn parse_total_form(&mut self) -> (Form, Vec<String>) {
        let Some(t) = self.peek().cloned() else {
            return (Form::NotTotal(String::new()), Vec::new());
        };
        match t.text.as_str() {
            "toggle" => {
                self.at += 1;
                (Form::Toggle, Vec::new())
            }
            "clear" => {
                self.at += 1;
                (Form::Clear, Vec::new())
            }
            "set" => {
                self.at += 1;
                let mut source = SetSource::Payload;
                if self.peek().is_some_and(|t| t.is_punct("(")) {
                    self.at += 1;
                    if let Some(inner) = self.peek().cloned() {
                        match inner.kind {
                            Kind::Token => {
                                source = SetSource::Token(
                                    inner.text.trim_start_matches('.').to_string(),
                                );
                                self.at += 1;
                            }
                            Kind::Str => {
                                source = SetSource::Text(inner.text.clone());
                                self.at += 1;
                            }
                            Kind::Punct if inner.text == "$" => {
                                // `$value` — the payload. The name is checked:
                                // `$anything` used to be accepted as a synonym,
                                // so a typo silently became the payload.
                                self.at += 1;
                                match self.ident() {
                                    Some(name) if name == "value" => {}
                                    Some(other) => {
                                        self.sink.at(
                                            &inner,
                                            format!(
                                                "`${other}` is not a payload; L0 names it `$value`"
                                            ),
                                        );
                                    }
                                    None => {}
                                }
                            }
                            Kind::Num => {
                                source = SetSource::Num(inner.text.parse().unwrap_or(0.0));
                                self.at += 1;
                            }
                            Kind::Ident if inner.text == "true" || inner.text == "false" => {
                                source = SetSource::Bool(inner.text == "true");
                                self.at += 1;
                            }
                            Kind::Ident => {
                                source = self
                                    .dotted_name()
                                    .map(SetSource::Path)
                                    .unwrap_or(SetSource::Payload);
                            }
                            _ => {
                                self.at += 1;
                            }
                        }
                    }
                    self.expect_punct(")");
                }
                (Form::Set(source), Vec::new())
            }
            "cycle" => {
                self.at += 1;
                let mut members = Vec::new();
                if self.peek().is_some_and(|t| t.is_punct("(")) {
                    self.at += 1;
                    let mut guard = 0usize;
                    while let Some(m) = self.peek().cloned() {
                        guard += 1;
                        if guard > 64 || m.is_punct(")") {
                            break;
                        }
                        if m.kind == Kind::Token {
                            members.push(m.text.trim_start_matches('.').to_string());
                        } else if m.kind == Kind::Ident {
                            // A bare name here is a path, and a path is not a token.
                            members.push(format!("!{}", m.text));
                        }
                        self.at += 1;
                    }
                    self.expect_punct(")");
                }
                (Form::Cycle, members)
            }
            "next" | "prev" => {
                let verb = t.text.clone();
                self.at += 1;
                let mut path = None;
                if self.peek().is_some_and(|t| t.is_punct("(")) {
                    self.at += 1;
                    path = self.dotted_name();
                    self.expect_punct(")");
                }
                match path {
                    Some(p) if verb == "next" => (Form::Next(p), Vec::new()),
                    Some(p) => (Form::Prev(p), Vec::new()),
                    None => (
                        Form::NotTotal(format!(
                            "`{verb}` names a collection field, like {verb}(cities.name)"
                        )),
                        Vec::new(),
                    ),
                }
            }
            // §5.12: the two collection forms. Both take `$value` and nothing
            // else — `remove($value)` matches an exact payload rather than
            // evaluating a predicate, which is what keeps them the same shape as
            // `cycle`: runtime logic the card NAMES and does not write.
            "append" | "remove" => {
                let verb = t.text.clone();
                self.at += 1;
                let mut ok = false;
                if self.peek().is_some_and(|t| t.is_punct("(")) {
                    self.at += 1;
                    if self.peek().is_some_and(|t| t.is_punct("$")) {
                        self.at += 1;
                        match self.ident() {
                            Some(name) if name == "value" => ok = true,
                            Some(other) => self.sink.at(
                                &t,
                                format!("`${other}` is not a payload; the only one is `$value`"),
                            ),
                            None => {}
                        }
                    }
                    self.expect_punct(")");
                }
                if ok {
                    if verb == "append" {
                        (Form::Append, Vec::new())
                    } else {
                        (Form::Remove, Vec::new())
                    }
                } else {
                    (
                        Form::NotTotal(format!("{verb} takes $value and nothing else")),
                        Vec::new(),
                    )
                }
            }
            other => {
                self.at += 1;
                (Form::NotTotal(other.to_string()), Vec::new())
            }
        }
    }

    fn parse_component(&mut self) -> Option<Component> {
        let line = self.peek().map(|t| t.line).unwrap_or(0);
        let name = self.ident()?;
        let mut params = Vec::new();

        if self.eat_punct("(") {
            let mut guard = 0usize;
            while self.peek().is_some_and(|t| !t.is_punct(")")) {
                guard += 1;
                if guard > 64 {
                    break;
                }
                if let Some(t) = self.peek().cloned() {
                    if t.kind == Kind::Ident
                        && self
                            .tokens
                            .get(self.at + 1)
                            .is_some_and(|n| n.is_punct(":"))
                    {
                        // The declared shape follows the colon. `enum[a, b]`
                        // carries its members, which is what lets a token
                        // argument be checked against the prop it fills.
                        let shape = match self.tokens.get(self.at + 2) {
                            Some(k) if k.text == "text" => Shape::Text,
                            Some(k) if k.text == "number" => Shape::Number,
                            Some(k) if k.text == "bool" => Shape::Bool,
                            Some(k) if k.text == "record" => Shape::Record,
                            Some(k) if k.text == "collection" => Shape::Collection,
                            Some(k) if k.text == "event" => Shape::Event,
                            Some(k) if k.text == "enum" => {
                                let mut members = Vec::new();
                                let mut at = self.at + 4; // past `enum` and `[`
                                while let Some(m) = self.tokens.get(at) {
                                    if m.is_punct("]") {
                                        break;
                                    }
                                    if m.kind == Kind::Ident {
                                        members.push(m.text.clone());
                                    }
                                    at += 1;
                                }
                                Shape::Enum(members)
                            }
                            _ => Shape::Other,
                        };
                        // `= <literal>` after the shape.
                        let mut default = None;
                        let mut at = self.at + 3;
                        if matches!(shape, Shape::Enum(_)) {
                            // Skip `[…]`, BALANCED. Seeking the first `]` put
                            // the cursor wherever a bracket happened to be.
                            let mut depth = 0usize;
                            while let Some(t) = self.tokens.get(at) {
                                if t.is_punct("[") {
                                    depth += 1;
                                } else if t.is_punct("]") {
                                    depth -= 1;
                                    if depth == 0 {
                                        at += 1;
                                        break;
                                    }
                                }
                                at += 1;
                            }
                        }
                        if self.tokens.get(at).is_some_and(|t| t.is_punct("=")) {
                            if let Some(v) = self.tokens.get(at + 1) {
                                default = match v.kind {
                                    Kind::Str => Some(serde_json::Value::String(v.text.clone())),
                                    Kind::Token => Some(serde_json::Value::String(
                                        v.text.trim_start_matches('.').to_string(),
                                    )),
                                    Kind::Num => {
                                        v.text.parse::<f64>().ok().map(serde_json::Value::from)
                                    }
                                    Kind::Ident if v.text == "true" || v.text == "false" => {
                                        Some(serde_json::Value::Bool(v.text == "true"))
                                    }
                                    // A bare enum member: `unit: enum[c, f] = c`,
                                    // which is how §5.2 spells it and which
                                    // produced no default at all.
                                    Kind::Ident if matches!(shape, Shape::Enum(_)) => {
                                        Some(serde_json::Value::String(v.text.clone()))
                                    }
                                    _ => None,
                                };
                            }
                        }
                        params.push(Param {
                            name: t.text.clone(),
                            shape,
                            default,
                        });
                    }
                }
                self.at += 1;
            }
            self.expect_punct(")");
        }

        self.expect_punct("{");
        let mut states = Vec::new();
        let mut events = Vec::new();
        let mut body = Element::default();

        let mut guard = 0usize;
        while let Some(t) = self.peek().cloned() {
            guard += 1;
            if guard > MAX_UI_L0_DECLARATIONS || t.is_punct("}") {
                break;
            }
            match t.text.as_str() {
                "state" => {
                    self.at += 1;
                    if let Some(d) = self.parse_state() {
                        states.push(d);
                    }
                }
                "event" => {
                    self.at += 1;
                    if let Some(e) = self.parse_event() {
                        events.push(e);
                    }
                }
                "view" => {
                    self.at += 1;
                    body = self.parse_element();
                }
                _ => {
                    self.sink.at(
                        &t,
                        format!(
                            "expected state, event or view in a component, found {:?}",
                            t.text
                        ),
                    );
                    self.at += 1;
                }
            }
        }
        self.expect_punct("}");

        let mut instantiates = Vec::new();
        collect_constructors(&body, &mut instantiates);
        Some(Component {
            name,
            params,
            states,
            events,
            body,
            line,
            instantiates,
        })
    }

    fn parse_element(&mut self) -> Element {
        self.depth += 1;
        let element = self.parse_element_inner();
        self.depth -= 1;
        element
    }

    fn parse_element_inner(&mut self) -> Element {
        if self.depth > DEFAULT_MAX_SYNTAX_NESTING {
            if let Some(t) = self.peek().cloned() {
                self.sink.at(&t, "nesting is too deep".into());
            }
            return Element::default();
        }

        let Some(t) = self.peek().cloned() else {
            self.sink
                .push(0, 0, "expected an element, found end of source".into());
            return Element::default();
        };

        // `for item[, index] in path key path { … }`
        if t.is_kw("for") {
            self.at += 1;
            let mut binders = Vec::new();
            if let Some(b) = self.ident() {
                binders.push(b);
            }
            if self.eat_punct(",") {
                if let Some(b) = self.ident() {
                    binders.push(b);
                }
            }
            if !self.peek().is_some_and(|t| t.is_kw("in")) {
                if let Some(t) = self.peek().cloned() {
                    self.sink
                        .at(&t, "expected `in` after the loop binder".into());
                }
            } else {
                self.at += 1;
            }
            let collection = self.dotted_name().unwrap_or_default();
            let key_path = if self.peek().is_some_and(|t| t.is_kw("key")) {
                self.at += 1;
                self.dotted_name()
            } else {
                if let Some(t) = self.peek().cloned() {
                    self.sink.at(
                        &t,
                        "a loop must declare `key`: identity may not come from position".into(),
                    );
                }
                None
            };
            let mut element = Element {
                name: "for".into(),
                binders,
                line: t.line,
                column: t.column,
                key_path,
                ..Default::default()
            };
            element.args.push(Arg {
                name: "in".into(),
                value: Operand::Path(collection),
                line: t.line,
                column: t.column,
            });
            element.children = self.parse_block();
            return element;
        }

        // `when predicate { … }`
        if t.is_kw("when") {
            self.at += 1;
            let left = self.dotted_name().unwrap_or_default();
            // A comparison, or a bare path when the state is bool-shaped —
            // `when expanded { … }`. Neither form computes.
            let mut cmp = None;
            let mut rhs = None;
            if let Some(op) = self.peek().cloned() {
                if op.kind == Kind::Cmp {
                    self.at += 1;
                    cmp = Some(op.text.clone());
                    rhs = Some(self.parse_operand());
                }
            }
            let mut element = Element {
                name: "when".into(),
                line: t.line,
                column: t.column,
                cmp,
                rhs,
                ..Default::default()
            };
            element.args.push(Arg {
                name: "predicate".into(),
                value: Operand::Path(left),
                line: t.line,
                column: t.column,
            });
            element.children = self.parse_block();
            return element;
        }

        // `into name { … }` — a call site directing children at a named slot.
        if t.is_kw("into") {
            self.at += 1;
            let mut element = Element {
                name: "into".into(),
                line: t.line,
                column: t.column,
                ..Default::default()
            };
            if let Some(slot_name) = self.ident() {
                element.binders.push(slot_name);
            }
            element.children = self.parse_block();
            return element;
        }

        // `slot` or `slot name` — §5.5. The anonymous form is the common case;
        // a name lets a component place two groups of children.
        if t.is_kw("slot") {
            self.at += 1;
            let mut element = Element {
                name: "slot".into(),
                line: t.line,
                column: t.column,
                ..Default::default()
            };
            if self.peek().is_some_and(|n| n.kind == Kind::Ident) {
                if let Some(slot_name) = self.ident() {
                    element.binders.push(slot_name);
                }
            }
            return element;
        }

        let Some(name_tok) = self.next() else {
            return Element::default();
        };
        if name_tok.kind != Kind::Ident {
            self.sink.at(
                &name_tok,
                format!("expected an element, found {:?}", name_tok.text),
            );
            return Element::default();
        }

        // A lowercase name with no arguments references another view record.
        let is_constructor = name_tok
            .text
            .chars()
            .next()
            .is_some_and(|c| c.is_uppercase());

        let mut element = Element {
            name: name_tok.text.clone(),
            line: name_tok.line,
            column: name_tok.column,
            is_reference: !is_constructor,
            ..Default::default()
        };

        if self.peek().is_some_and(|t| t.is_punct("(")) {
            self.at += 1;
            element.args = self.parse_args();
        }
        if self.peek().is_some_and(|t| t.is_punct("{")) {
            element.children = self.parse_block();
        }
        element
    }

    fn parse_block(&mut self) -> Vec<Element> {
        let mut out = Vec::new();
        if !self.expect_punct("{") {
            return out;
        }
        let mut guard = 0usize;
        while let Some(t) = self.peek().cloned() {
            guard += 1;
            if guard > MAX_UI_L0_DECLARATIONS {
                self.sink.at(&t, "too many elements in one block".into());
                break;
            }
            if t.is_punct("}") {
                break;
            }
            let before = self.at;
            out.push(self.parse_element());
            if self.at == before {
                self.at += 1;
            }
        }
        self.expect_punct("}");
        out
    }

    fn parse_args(&mut self) -> Vec<Arg> {
        let mut out = Vec::new();
        let mut guard = 0usize;
        loop {
            guard += 1;
            if guard > 64 {
                break;
            }
            if self.peek().is_none() || self.peek().is_some_and(|t| t.is_punct(")")) {
                break;
            }
            // `Row(gap: 8, when … { … })` — a statement where an argument
            // belongs. Catch it BEFORE `ident()` eats `when` as an argument
            // name and refuses with a bare `expected ":"`, which taught the
            // model nothing (the diagnostic text IS the repair prompt).
            if self.args_stopped_by_statement() {
                return out;
            }
            let Some(name_tok) = self.peek().cloned() else {
                break;
            };
            let Some(name) = self.ident() else {
                self.at += 1;
                continue;
            };
            if !self.eat_punct(":") {
                // `TextRow(text, value)` — a comma (or the closing paren)
                // where the argument's `:` belongs. The bare
                // `expected ":", found ","` cascaded into `expected ")"` and
                // `expected an element` and buried the fix; say what an
                // argument IS instead, once.
                match self.peek().cloned() {
                    Some(t) => self.sink.at(
                        &t,
                        format!(
                            "expected \":\" after argument name `{name}`, found {:?} — every \
                             constructor argument is written `name: value` and arguments are \
                             separated by commas, e.g. `Row(gap: 8, on_tap: back)`; a bare \
                             value with no name, or a comma where the `:` belongs, is refused",
                            t.text
                        ),
                    ),
                    None => self.sink.push(
                        0,
                        0,
                        format!("expected \":\" after argument name `{name}`, found end of source"),
                    ),
                }
                // Recover to the closing paren so one mistake yields one
                // diagnostic instead of the cascade. The card is already
                // refused; the skipped tokens have nothing more to teach.
                while let Some(t) = self.peek() {
                    if t.is_punct(")") || t.is_punct("{") || t.is_punct("}") {
                        break;
                    }
                    self.at += 1;
                }
                break;
            }
            let value = self.parse_operand();
            out.push(Arg {
                name,
                value,
                line: name_tok.line,
                column: name_tok.column,
            });
            if !self.eat_punct(",") {
                break;
            }
        }
        // `Col(gap: 8\n  when … { … })` — the no-comma variant of the same
        // nesting mistake, reached when the argument loop stops without a
        // trailing comma. Leave the keyword in place: the enclosing block
        // parses the guard as the element it should have been.
        if self.args_stopped_by_statement() {
            return out;
        }
        self.expect_punct(")");
        out
    }

    /// A `when`/`for` STATEMENT keyword sitting where an argument belongs —
    /// the most common malformation in live generation runs. Emits the
    /// teaching diagnostic (guards wrap elements; they are not arguments) and
    /// answers true so `parse_args` returns without the bare
    /// `expected ")", found "when"` noise. The keyword is left unconsumed so
    /// the enclosing block still parses the guard and checks its contents.
    fn args_stopped_by_statement(&mut self) -> bool {
        let Some(t) = self.peek().cloned() else {
            return false;
        };
        let (kw, what, fix) = if t.is_kw("when") {
            (
                "when",
                "guard",
                "close the constructor's `(…)` first, then write `when path == value { … }` \
                 around the elements it guards",
            )
        } else if t.is_kw("for") {
            (
                "for",
                "loop",
                "close the constructor's `(…)` first, then write \
                 `for item in collection key item.id { … }` around the elements it repeats",
            )
        } else {
            return false;
        };
        self.sink.at(
            &t,
            format!(
                "a `{kw}` {what} cannot appear inside an argument list; {what}s wrap \
                 elements — {fix}"
            ),
        );
        true
    }

    /// An argument value, including an L1 arithmetic expression.
    ///
    /// Precedence is the usual one — `*` `/` `%` bind tighter than `+` `-` — so
    /// `cost + shares * price` means what it reads as. Left-associative.
    fn parse_operand(&mut self) -> Operand {
        let lhs = self.parse_term();
        self.parse_additive(lhs)
    }

    fn parse_additive(&mut self, mut lhs: Operand) -> Operand {
        while let Some(op) = self.peek().cloned() {
            if !(op.is_punct("+") || op.is_punct("-")) {
                break;
            }
            if self.depth > DEFAULT_MAX_SYNTAX_NESTING {
                self.sink.at(&op, "nesting is too deep".into());
                break;
            }
            self.at += 1;
            self.depth += 1;
            let rhs = self.parse_term();
            self.depth -= 1;
            lhs = Operand::Expr {
                lhs: Box::new(lhs),
                op: op.text,
                rhs: Box::new(rhs),
            };
        }
        lhs
    }

    fn parse_term(&mut self) -> Operand {
        let mut lhs = self.parse_atom();
        while let Some(op) = self.peek().cloned() {
            if !(op.is_punct("*") || op.is_punct("/") || op.is_punct("%")) {
                break;
            }
            if self.depth > DEFAULT_MAX_SYNTAX_NESTING {
                self.sink.at(&op, "nesting is too deep".into());
                break;
            }
            self.at += 1;
            self.depth += 1;
            let rhs = self.parse_atom();
            self.depth -= 1;
            lhs = Operand::Expr {
                lhs: Box::new(lhs),
                op: op.text,
                rhs: Box::new(rhs),
            };
        }
        lhs
    }

    fn parse_atom(&mut self) -> Operand {
        let Some(t) = self.peek().cloned() else {
            return Operand::Str(String::new());
        };
        // GROUPING. Precedence was fixed and unoverridable, so `(a + b) * c` —
        // the first thing an author reaches for after a formula that does not fit
        // it — could not be written at all. A `(` here is unambiguous: an
        // argument value never otherwise starts with one, because every
        // call-shaped form in the grammar (`set`, `cycle`, `append`) is reached
        // by its verb.
        if t.is_punct("(") {
            if self.depth > DEFAULT_MAX_SYNTAX_NESTING {
                self.sink.at(&t, "nesting is too deep".into());
                return Operand::Str(String::new());
            }
            self.at += 1;
            self.depth += 1;
            let inner = self.parse_operand();
            self.depth -= 1;
            self.expect_punct(")");
            return inner;
        }
        // UNARY MINUS. `x * -1` was refused, so a negative coefficient — the
        // ordinary way to subtract a scaled reading — had no spelling.
        //
        // A negated LITERAL becomes a negative literal rather than an expression,
        // so it stays a coefficient: wrapping it as `0 - 1` would make
        // `value: -1` an expression that reads nothing, which §9.3 refuses, and
        // that is the right answer for a bare `-1` but reached by the wrong
        // route. A negated PATH is arithmetic and lowers as such.
        if t.is_punct("-") {
            if self.depth > DEFAULT_MAX_SYNTAX_NESTING {
                self.sink.at(&t, "nesting is too deep".into());
                return Operand::Str(String::new());
            }
            if let Some(next) = self.peek_at(1).cloned() {
                if next.kind == Kind::Num {
                    self.at += 2;
                    return Operand::Num(-next.text.parse::<f64>().unwrap_or(0.0));
                }
            }
            self.at += 1;
            self.depth += 1;
            let inner = self.parse_atom();
            self.depth -= 1;
            return Operand::Expr {
                lhs: Box::new(Operand::Num(0.0)),
                op: "-".to_string(),
                rhs: Box::new(inner),
            };
        }
        match t.kind {
            Kind::Token => {
                self.at += 1;
                Operand::Token(t.text)
            }
            Kind::Str => {
                self.at += 1;
                Operand::Str(t.text.clone())
            }
            Kind::Num => {
                self.at += 1;
                Operand::Num(t.text.parse().unwrap_or(0.0))
            }
            Kind::Ident => {
                let path = self.dotted_name().unwrap_or_default();
                // A comparison in argument position is a predicate operand.
                if let Some(op) = self.peek().cloned() {
                    if op.kind == Kind::Cmp {
                        if self.depth > DEFAULT_MAX_SYNTAX_NESTING {
                            self.sink.at(&op, "nesting is too deep".into());
                            return Operand::Path(path);
                        }
                        self.at += 1;
                        self.depth += 1;
                        // The WHOLE right side, arithmetic included. This took a
                        // term, so a comparison bound TIGHTER than `+`: at L1
                        // `active: x == a + b` parsed as `(x == a) + b`, which is
                        // arithmetic on a boolean — it evaluated to missing, and
                        // nothing rejected it, so the card rendered blank with no
                        // diagnostic. A comparison is the loosest thing in an
                        // operand, which is what makes `x == a + b` mean what it
                        // reads as.
                        //
                        // The recursion is bounded by the depth guard above, the
                        // same one every other nested construct uses.
                        let rhs = self.parse_operand();
                        self.depth -= 1;
                        return Operand::Predicate {
                            path,
                            cmp: op.text,
                            rhs: Box::new(rhs),
                        };
                    }
                }
                Operand::Path(path)
            }
            _ => {
                self.at += 1;
                Operand::Str(String::new())
            }
        }
    }
}

/// Split a call site's children by the slot each targets.
///
/// `into header { … }` groups the elements that follow into the named slot;
/// anything outside a group goes to the anonymous one. Keeping the default
/// unnamed means a component with one slot needs no ceremony.
/// The slot names a component declares. An anonymous `slot` is `""`.
/// Resolve an operand in a comparison's right-hand position.
/// Follow a dotted path into injected data. Used for a path-valued `initial`,
/// which resolves against what the host supplied rather than at parse time.
/// A literal operand's value.
fn literal_of(operand: &Operand) -> serde_json::Value {
    match operand {
        Operand::Str(t) => serde_json::Value::String(t.clone()),
        Operand::Num(n) => serde_json::Value::from(*n),
        Operand::Token(t) => serde_json::Value::String(t.trim_start_matches('.').to_string()),
        Operand::Path(p) | Operand::Predicate { path: p, .. } => {
            serde_json::Value::String(p.clone())
        }
        // An expression has no literal form; it is computed at realization.
        Operand::Expr { .. } => serde_json::Value::Null,
    }
}

/// Every path an operand reads, however deeply nested in an expression.
fn expr_paths(operand: &Operand, out: &mut Vec<String>) {
    match operand {
        Operand::Path(p) => out.push(p.clone()),
        Operand::Predicate { path, rhs, .. } => {
            out.push(path.clone());
            expr_paths(rhs, out);
        }
        Operand::Expr { lhs, rhs, .. } => {
            expr_paths(lhs, out);
            expr_paths(rhs, out);
        }
        _ => {}
    }
}

fn data_path(data: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let mut current = data.clone();
    for segment in path.split('.') {
        current = match segment.parse::<usize>() {
            Ok(i) => current.get(i)?.clone(),
            Err(_) => current.get(segment)?.clone(),
        };
    }
    Some(current)
}

fn scope_value(scope: &ValueScope, operand: &Operand) -> Option<serde_json::Value> {
    match operand {
        Operand::Path(p) => scope.lookup(p),
        Operand::Token(t) => Some(serde_json::Value::String(
            t.trim_start_matches('.').to_string(),
        )),
        Operand::Str(s) => Some(serde_json::Value::String(s.clone())),
        Operand::Num(n) => Some(serde_json::Value::from(*n)),
        // A nested comparison is not in the grammar.
        Operand::Predicate { .. } => None,
        Operand::Expr { lhs, op, rhs } => eval_expr(scope, lhs, op, rhs),
    }
}

/// Evaluate an L1 arithmetic expression over resolved values.
///
/// Returns `None` when either side is unresolved — a missing operand must render
/// as the em dash a missing binding already does, never as a zero, which would be
/// a fabricated number wearing arithmetic.
fn eval_expr(
    scope: &ValueScope,
    lhs: &Operand,
    op: &str,
    rhs: &Operand,
) -> Option<serde_json::Value> {
    let a = scope_value(scope, lhs)?.as_f64()?;
    let b = scope_value(scope, rhs)?.as_f64()?;
    apply_op(a, op, b).map(serde_json::Value::from)
}

/// The five operators, in one place.
///
/// Shared by realization and by §9.3's degeneracy probe, so the arithmetic a
/// card is CHECKED against cannot drift from the arithmetic it is EVALUATED
/// with — which is the mistake this profile keeps finding in other shapes.
fn apply_op(a: f64, op: &str, b: f64) -> Option<f64> {
    let v = match op {
        "+" => a + b,
        "-" => a - b,
        "*" => a * b,
        // A zero divisor yields missing, not zero: a fabricated number is the
        // failure §4 exists to prevent, and it does not become acceptable
        // because arithmetic produced it.
        "/" | "%" if b == 0.0 => return None,
        "/" => a / b,
        "%" => a % b,
        _ => return None,
    };
    v.is_finite().then_some(v)
}

/// Evaluate an expression with every path resolved by `resolve`.
///
/// The shape §9.3's probe needs: the same tree, the same operators, arbitrary
/// values for the reads.
fn fold_expr(operand: &Operand, resolve: &dyn Fn(&str) -> Option<f64>) -> Option<f64> {
    match operand {
        Operand::Num(n) => Some(*n),
        Operand::Path(p) => resolve(p),
        Operand::Expr { lhs, op, rhs } => {
            apply_op(fold_expr(lhs, resolve)?, op, fold_expr(rhs, resolve)?)
        }
        // A comparison is a boolean, not a number, and arithmetic over one is
        // not in the grammar.
        _ => None,
    }
}

/// Whether an expression's value is INDEPENDENT of everything it reads.
///
/// §9.3 requires an expression to read something, which stops `1547 * 3.2` and
/// does not stop `quote.last * 0 + 1547` — one real reading laundering a
/// fabricated number past the rule. That gap was recorded as needing an argument
/// nobody had; this is the argument.
///
/// A formula is a formula because its answer MOVES when its inputs move. So the
/// expression is evaluated with its reads bound to several distinct assignments,
/// and an answer that never changes is a constant the model wrote with extra
/// steps. `temp * 9 / 5 + 32` moves; `last * 0 + 1547` does not.
///
/// Distinct values PER PATH, varied across rounds, because binding every read to
/// the same number would make `a - b` constant and condemn a correct formula.
/// Three rounds of coprime-ish values: an expression that is constant across all
/// three and not constant in general is not something the five arithmetic
/// operators can express.
///
/// Unresolvable in every round (a division by a probed zero, say) is NOT
/// degenerate — that is a partial expression, and §9.4 already renders it as
/// missing.
fn expr_is_constant(expr: &Operand) -> bool {
    let mut paths = Vec::new();
    expr_paths(expr, &mut paths);
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        // The must-read rule owns this case and reports it better.
        return false;
    }
    let mut seen: Vec<f64> = Vec::new();
    for (base, step) in [(2.0, 1.0), (5.0, 3.0), (11.0, 7.0)] {
        let resolve = |p: &str| -> Option<f64> {
            paths
                .iter()
                .position(|q| q == p)
                .map(|i| base + step * i as f64)
        };
        match fold_expr(expr, &resolve) {
            Some(v) => seen.push(v),
            None => return false,
        }
    }
    seen.windows(2).all(|w| w[0] == w[1])
}

/// Compare two resolved values. Shared by guards (`when a == b`) and by
/// predicate arguments (`active: range == .d1`), so the two cannot drift.
fn compare(left: Option<serde_json::Value>, cmp: &str, right: Option<serde_json::Value>) -> bool {
    let (Some(left), Some(right)) = (left, right) else {
        // An operand that did not resolve cannot be compared. `!=` used to
        // return true here, so a guard against an UNDECLARED name took its
        // branch; an unresolvable comparison is now simply false.
        return false;
    };
    // Two NUMBERS compare numerically, whatever JSON shape they arrived in.
    //
    // `==` was `serde_json::Value` equality, which distinguishes `1` from `1.0`.
    // So `when here.ok == 1` took its branch when the host injected a float and
    // silently did not when it injected an integer — the same guard, the same
    // card, the same value, deciding differently on a representation the card
    // cannot see. It cost the nav map: the card was correct, the checker accepted
    // it, and the map simply was not in the realized tree.
    //
    // The ordering operators already coerced through `as_f64`; only equality did
    // not, which is the half nobody tested.
    if let (Some(a), Some(b)) = (left.as_f64(), right.as_f64()) {
        return match cmp {
            "==" => a == b,
            "!=" => a != b,
            "<" => a < b,
            "<=" => a <= b,
            ">" => a > b,
            ">=" => a >= b,
            _ => false,
        };
    }
    match cmp {
        "==" => left == right,
        "!=" => left != right,
        _ => match (left.as_f64(), right.as_f64()) {
            (Some(a), Some(b)) => match cmp {
                "<" => a < b,
                "<=" => a <= b,
                ">" => a > b,
                ">=" => a >= b,
                _ => false,
            },
            _ => false,
        },
    }
}

fn slot_names(component: &Component) -> Vec<String> {
    fn walk(elements: &[Element], out: &mut Vec<String>) {
        for e in elements {
            if e.name == "slot" {
                out.push(e.binders.first().cloned().unwrap_or_default());
            }
            walk(&e.children, out);
        }
    }
    let mut out = Vec::new();
    walk(std::slice::from_ref(&component.body), &mut out);
    out
}

/// Path segments for a list of siblings, stable against insertion.
///
/// Profile §5.1 identifies an instance by its *instantiation site*, not its
/// position, "so that identity survives a ledger edit that inserts an element
/// above". A raw child index does not: inserting a `Rule()` renumbers every
/// sibling after it, and each one loses its local state — which is React's rule,
/// and precisely the rule §5.1 says L0 does not use.
///
/// Numbering within each element NAME fixes that. Two sibling `Row`s are still
/// distinct (`Row#0`, `Row#1`), so keys stay unique for hit-testing, but a
/// `Rule()` inserted above a `Toggly` leaves `Toggly#0` untouched.
fn sibling_segments(children: &[Element]) -> Vec<(String, &Element)> {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    children
        .iter()
        .map(|child| {
            let n = seen.entry(child.name.as_str()).or_insert(0);
            let segment = format!("{}#{}", child.name, *n);
            *n += 1;
            (segment, child)
        })
        .collect()
}

fn split_slots(children: &[Element]) -> Vec<(String, Vec<Element>)> {
    let mut groups: Vec<(String, Vec<Element>)> = vec![(String::new(), Vec::new())];
    for child in children {
        if child.name == "into" {
            let name = child.binders.first().cloned().unwrap_or_default();
            groups.push((name, child.children.clone()));
        } else {
            groups[0].1.push(child.clone());
        }
    }
    groups
}

fn collect_constructors(e: &Element, out: &mut Vec<String>) {
    if !e.name.is_empty() && e.name != "for" && e.name != "when" && e.name != "slot" {
        out.push(e.name.clone());
    }
    for c in &e.children {
        collect_constructors(c, out);
    }
}

// ─────────────────────────────────────────────────────────────────────── catalog ──

/// The argument contract. Mirrors `docs/ui-l0-constructors.toml`, which is the
/// human-readable spec; a test asserts the two agree.
pub mod catalog {
    /// The themes a card may declare, as MOODS rather than looks.
    ///
    /// Closed, and closed for the same reason the role list is: a theme name is
    /// a promise that every kit answers it. A card naming a mood no kit has
    /// would render in whatever the kit's default palette is and look correct,
    /// which is the §1.1 failure this list exists to make impossible — so an
    /// unknown name is refused at parse time instead.
    ///
    /// `dark` is the default and needs no declaration; it is listed so a card
    /// may say so explicitly.
    /// `vibrant` and `minimal` were declared by 43 corpus cards that could not
    /// realize — the checker refused them before they reached a colour, because
    /// the vocabulary named four moods and the generator had been writing six.
    pub const THEMES: &[&str] = &[
        "dark", "light", "glass", "photo", "vibrant", "minimal",
        // Theme PACKS — whole design systems minted from purchased kits by
        // the lab/sketch pipeline: seeds + measured scale + family + depth.
        // A pack is just a mood with luggage; every axis still composes on top.
        "atro", "atro_light",
    ];

    /// The theme AXES a card may name beside its mood, and the closed set each
    /// admits. A mood is one coordinate; these are the others.
    ///
    /// Every value is a token, never a colour, a length or a font name — the
    /// card states an INTENT and the theme decides what it looks like, which is
    /// the same contract `theme <mood>` has always had. Four moods could only
    /// ever be four looks; a corpus of 100 generated designs asked for square
    /// AND soft geometry, restrained AND vivid palettes, grotesk AND serif
    /// display, and one global setting cannot serve both sides of any of those.
    ///
    /// `shape`, `density`, `emphasis` and `icons` are knobs the palette already
    /// carries and renders — they were simply not selectable per card.
    pub const AXES: &[(&str, &[&str])] = &[
        (
            "accent",
            &[
                "neutral", "indigo", "blue", "red", "green", "amber", "cyan", "magenta", "violet",
            ],
        ),
        ("radius", &["none", "small", "large", "full"]),
        ("density", &["compact", "regular", "airy"]),
        ("emphasis", &["quiet", "clear", "poster"]),
        ("icons", &["filled", "mono"]),
        // A tiled surface grain. A NAME, like every other axis value — the card
        // states a material and the theme owns the file, for the same reason it
        // owns the colours. `Photo.src` refuses a literal because a literal in a
        // data position is a model-authored fact (§4); a texture path would be
        // the identical mistake wearing a different key.
        ("texture", &["none", "paper", "linen", "concrete", "noise", "deco", "halftone"]),
        // How a surface sits off the page. `soft` is the identity — the Material
        // lift every mood already derives from elevation — so a card naming it
        // and a card naming nothing render alike.
        ("depth", &["soft", "flat", "hard", "glow"]),
        // The typeface. `sans` is the identity. `display` is a serif headline
        // over a sans body — one axis answering what the corpus counted as two
        // separate wants (`serif_display` and `font_pair`), because a single
        // family token cannot express a pairing and a pairing is what editorial
        // design actually asks for.
        ("type", &["sans", "serif", "display"]),
        // The request's own language. A feel RESOLVES to axis defaults in the
        // host (explicit axes still override), so a card can carry the user's
        // actual word — "premium", "calm" — and re-resolve as the theme
        // library improves. Every value ships only after a blind paired judge
        // confirms it reads as its word; an unvalidated feel is the
        // disconnected knob wearing a nicer name.
        ("feel", &[
            "bright", "calm", "bold", "premium", "playful", "warm", "cool",
            "minimal", "inspirational",
        ]),
        // A seeded page colour — the lever every measurement said was missing
        // (judges named colour in 92% of failed cards; the deco teal was
        // unreachable). Each value is NINE SEED SCALARS in its fragment;
        // `_derive_color.splash` computes the palette in-kit via `mod.math`.
        // Composes with `accent:` — the accent arrives as a hue SEED and
        // `_derive_color` re-solves the ink against the seeded ground in-kit
        // (unrolled contrast search; all 112 pairs audited AA-clean).
        ("ground", &[
            "teal", "violet", "navy", "ivory", "sand", "terracotta", "wine",
            "forest", "slate", "paper", "cream", "midnight", "blush", "olive",
        ]),
    ];

    /// The legal values for an axis, or `None` if L0 has no such axis.
    pub fn axis(name: &str) -> Option<&'static [&'static str]> {
        AXES.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }

    /// The catalogued theme of that name, or `None` if L0 does not admit it.
    pub fn theme(name: &str) -> Option<&'static str> {
        THEMES.iter().copied().find(|t| *t == name)
    }

    /// What an argument admits.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ArgKind {
        /// One of a closed token set, written with a leading dot.
        Token(&'static [&'static str]),
        /// A token from the set, or a bound path.
        TokenOrPath(&'static [&'static str]),
        /// A bound path only.
        Path,
        /// A literal or a path.
        Any,
        /// A declared event name.
        Event,
        /// A number literal or a path; also admits a width token. Layout, not
        /// data — `gap: 6` and `cols: 2` are structure the card chooses.
        Number,
        /// A bound path that renders a FACT. Distinct from `Number` because
        /// `gap: 6` is layout the card is entitled to choose and
        /// `value: 41.2` is a measurement it is not (§4). Without the
        /// distinction the no-facts rule cannot be stated in the catalog at
        /// all, so both were `Number` and neither was checked.
        Data,
        /// Text literal or path.
        Text,
        /// A predicate or a bool path.
        Bool,
    }

    // `index` is not here: an index is dimensionless, so there is no honest
    // suffix — the tile's LABEL says which index it is. A token the catalog
    // admits and no lowering decorates is this layer's recurring defect.
    pub const UNIT: &[&str] = &[
        "c", "f", "pct", "speed", "pressure", "distance", "money", "duration",
    ];
    pub const FORMAT: &[&str] = &[
        "money",
        "signed_money",
        "signed_pct",
        "compact",
        "ratio",
        "time",
        "date",
    ];
    pub const WIDTH: &[&str] = &["fill", "fit", "day", "rank", "temp", "label"];

    /// How a map presents a trip. These are the shipping widget's own modes:
    /// `plan` shows the whole route, `drive` follows the vehicle, and `flat` is
    /// the same route without the 2.5D camera.
    pub const MAP_MODE: &[&str] = &["plan", "drive", "flat"];
    /// Flat or tilted, while driving — the shipping app's R8.1 chase view.
    pub const MAP_VIEW: &[&str] = &["flat", "tilted"];
    /// Where a panel sits when the card is a map.
    /// Where a panel sits on a map card. `top` is the banner, `bottom` the sheet,
    /// and `right` the control column beside the map — where a driving screen's own
    /// switches belong, because a control in the banner competes with the one thing
    /// a driver reads.
    pub const DOCK: &[&str] = &["top", "bottom", "right"];
    /// The controls a map offers. A card NAMES the affordance; the theme draws it
    /// and the backend wires it.
    ///
    /// This is the argument that let R3.6 and R3.9 exist at L0 at all. The card
    /// being replaced draws its own pill and writes
    /// `on_click: || ui.themap.nav_zoom_by("0.7")` — a method call on a named
    /// widget, which is the imperative wiring this profile exists to exclude. The
    /// split §1.1 asks for is that the CARD may not say it and the BACKEND must:
    /// "this map can be zoomed" is a capability, and the button, the glyph and the
    /// method call are all presentation.
    pub const CONTROLS: &[&str] = &["none", "zoom", "all"];
    /// What an action means. The theme decides what that looks like.
    /// `primary` is the action a screen is FOR — the one thing you came to do. The
    /// theme draws it larger; the card only says which action it is.
    pub const TONE: &[&str] = &["normal", "primary", "danger"];
    pub const ALIGN: &[&str] = &["start", "center", "end", "baseline"];
    pub const PAD: &[&str] = &["page", "tight", "none"];
    /// The semantic icon vocabulary — meanings, never drawings. Measured off
    /// the Atro corpus: a ~40-name set covered 86% of icon uses on 150
    /// commercial screens, and designers already name icons this way
    /// (`bell-S-light`); the card states the meaning, the theme decides the
    /// glyph set that answers it.
    pub const ICON: &[&str] = &[
        "activity", "alert", "arrow_down", "arrow_left", "arrow_right",
        "arrow_up", "bell", "bookmark", "calendar", "camera", "chat", "check",
        "chevron_down", "chevron_left", "chevron_right", "chevron_up", "clock",
        "close", "cloud", "edit", "filter", "heart", "home", "image", "info",
        "location", "lock", "mail", "map", "menu", "mic", "minus", "moon",
        "more", "phone", "play", "plus", "refresh", "search", "send",
        "settings", "share", "star", "sun", "trash", "user", "users", "video",
        "wifi", "zap",
    ];

    pub const ICON_SIZE: &[&str] = &["hero", "row", "tile"];
    /// A thumbnail is a list-row 16:9 tile unless the design shows a square
    /// mosaic cell — a gallery is squares, a feed row is wide.
    pub const THUMB_SHAPE: &[&str] = &["wide", "square"];

    pub type Args = &'static [(&'static str, ArgKind)];

    use ArgKind::*;

    /// Every constructor L0 admits, with the arguments each accepts.
    pub const CONSTRUCTORS: &[(&str, Args)] = &[
        ("Surface", &[("pad", Token(PAD))]),
        ("Photo", &[("src", Path), ("pad", Token(PAD))]),
        // A row-sized image. `Photo` fills its width (it is a backdrop); a list
        // row needs a fixed 16:9 tile beside its text.
        ("Thumb", &[("src", Path), ("shape", Token(THUMB_SHAPE))]),
        // A map. The card names the TRIP; the widget fetches its own route.
        //
        // The same correction `AqiContour` and `StockPlot` already took. The
        // shipping nav card calls `sys.navroute` itself, hand-builds a marker
        // string and pushes both in through imperative setters — which is the
        // card doing the widget's job, and is most of why that card classifies
        // at L2. A route is not a card's to compute.
        (
            "Map",
            &[
                ("mode", Token(MAP_MODE)),
                ("from", Path),
                ("to", Path),
                ("via", Path),
                // A SECOND fixed slot, not a list. The role parser routes arguments
                // through the expression grammar, so admitting `[a, b]` there means a
                // list literal in every operand position — a change to the whole
                // grammar for one argument. The app being replaced has exactly two
                // waypoint slots, `wp1` and `wp2`, and hides "add stop" when both are
                // full; two named arguments say the same thing and stay total.
                ("via2", Path),
                // The live position the camera follows. See `map_mode`: this is
                // what lets `.drive` mean the chase camera rather than the static
                // preview, because a followed position is a measured one.
                ("at", Path),
                // Flat or tilted while driving — the shipping app's R8.1 chase
                // view. Only meaningful with `at:`: a preview has no camera to
                // tilt, and a tilted camera with no position to follow is the
                // fabrication `map_mode` refuses.
                // A TOKEN OR A PATH, like `unit` and `width`. `view: .tilted` is
                // fixed; `view: view` follows card state, which is what makes an
                // on-map 2D/3D toggle a state and a guard instead of two whole
                // `Map` declarations per branch it multiplies with. Realization
                // resolves the path to a token before the lowering reads it, so
                // nothing downstream changes.
                ("view", TokenOrPath(MAP_VIEW)),
                ("zoom", Number),
                ("controls", Token(CONTROLS)),
                // The start as TWO NUMBERS, when there is no place to name.
                //
                // `from:` names a source that answers a coordinate, which is right
                // whenever a place was searched for. A trip that begins where the
                // DEVICE is has no such place: the position is two captured numbers
                // in card state. Without these the map fell back to geocoding the
                // empty origin — `sys.navroute(sys.searchnum("", …))` — so the
                // summary said "from here" and the line drew a route from nowhere,
                // which is the drawn-versus-reported mismatch this profile exists to
                // catch. Same shape and same reason as `sys.route`'s four numbers.
                // The trip whose COST labels the drawn route. A source, not two
                // strings: the map already draws this trip, and naming the same
                // source that answers its duration is what keeps the bubble and the
                // line describing one journey.
                ("summary", Path),
                ("from_lat", ArgKind::Data),
                ("from_lon", ArgKind::Data),
            ],
        ),
        // A text field. The ONE role that lets a card receive something the user
        // typed.
        //
        // `text` is where the value lives — declared card state, never a free
        // binding — and `on_commit` carries it as `$value` to a declared
        // transition. So typed text enters through the same total, declared path
        // as a tap, and §4's `user-copy` class already names what it is.
        (
            "Field",
            &[
                ("text", Path),
                ("placeholder", ArgKind::Data),
                ("on_commit", Event),
                // Per KEYSTROKE, where `on_commit` is per return. A search box wants
                // both: results while you type, a destination when you commit. The
                // cost is a card re-resolve per character — measured at 18-19 ms on
                // the planning screen of a OnePlus 6, which is what makes this
                // expressible rather than merely declarable.
                ("on_change", Event),
                ("width", TokenOrPath(WIDTH)),
            ],
        ),
        ("Panel", &[("dock", Token(DOCK))]),
        // Content a swipe reveals. See the catalog.
        ("Reveal", &[]),
        ("Card", &[("on_tap", Event), ("value", Any)]),
        // A column may say how WIDE, because a row of columns has to divide the
        // line somehow and only the card knows which column is the one that
        // should absorb what is left. A mover row is ticker-and-name beside a
        // price: without this every column fits its own text, and a long company
        // name wrapped to three lines beside acres of empty space
        // ("Dolby Laboratori / es"). This is layout, not styling — it says which
        // element yields, not how anything looks.
        (
            "Col",
            &[
                ("align", Token(ALIGN)),
                ("gap", Number),
                ("width", TokenOrPath(WIDTH)),
            ],
        ),
        // `width` says whether this row FILLS. It fills by default because a list
        // row must, and that defeats a centred parent — the one thing a card
        // could not say.
        (
            "Row",
            &[
                ("width", TokenOrPath(WIDTH)),
                ("align", Token(ALIGN)),
                ("gap", Number),
                ("on_tap", Event),
                ("value", Any),
            ],
        ),
        ("Grid", &[("cols", Number)]),
        ("Rule", &[]),
        // A flexible blank. Zero arguments: its whole meaning is "the height
        // that is left" — before a bottom bar it pins the bar to the bottom,
        // around a centered stack it centers the stack vertically.
        ("Space", &[]),
        (
            "TextHero",
            &[
                ("text", Text),
                ("value", Data),
                ("unit", TokenOrPath(UNIT)),
                ("format", Token(FORMAT)),
                ("on_tap", Event),
            ],
        ),
        (
            "TextTitle",
            &[("text", Text), ("width", TokenOrPath(WIDTH))],
        ),
        ("TextBody", &[("text", Text), ("width", TokenOrPath(WIDTH))]),
        (
            "TextStat",
            &[("value", Data), ("format", Token(FORMAT)), ("tint", Path)],
        ),
        ("TextRow", &[("text", Text), ("width", TokenOrPath(WIDTH))]),
        // An EYEBROW: the small tracked-caps line above a hero. The mockup
        // study priced its absence; the kit answers with tracking and caps,
        // which is presentation and therefore never the card's to spell.
        ("TextEyebrow", &[("text", Text)]),
        (
            "TextCaption",
            &[
                ("text", Text),
                ("value", Data),
                ("glyph", Text),
                ("suffix", Text),
                ("unit", TokenOrPath(UNIT)),
                ("width", TokenOrPath(WIDTH)),
            ],
        ),
        (
            "TextValue",
            &[
                ("value", Data),
                ("unit", TokenOrPath(UNIT)),
                ("format", Token(FORMAT)),
                ("tint", Path),
            ],
        ),
        (
            "Tile",
            &[
                ("label", Text),
                ("value", Data),
                ("unit", TokenOrPath(UNIT)),
                ("format", Token(FORMAT)),
            ],
        ),
        (
            // A semantic icon: the card names a MEANING from the closed set,
            // the theme's icon font answers it. The §4-compatible form of what
            // full translation showed as the largest single "cannot say"
            // (2,564 dropped icon instances across one kit's screens).
            "Icon",
            &[("name", Token(ICON)), ("size", Token(ICON_SIZE))],
        ),
        (
            // A person as initials in a tinted circle — the avatar every list
            // design carries, WITHOUT an image: kits render exactly this when a
            // photo is absent, so the no-photo form is a real design element,
            // not a degraded one. The card passes the INITIALS ("TC"), because
            // deriving them from "Tom Castle" needs string ops L0 does not have
            // and the author writing the card already knows the name.
            "Avatar",
            &[("text", Text)],
        ),
        (
            "Chip",
            &[
                ("text", Text),
                ("on_tap", Event),
                ("value", Any),
                ("active", Bool),
                // What the action MEANS. The theme decides `.danger` is red.
                ("tone", Token(TONE)),
                // `.fit` on a danger chip names the row-scoped compact variant;
                // the spanning one is the screen action (nav's Stop).
                ("width", Token(WIDTH)),
            ],
        ),
        ("WeatherIcon", &[("cond", Path), ("size", Token(ICON_SIZE))]),
        (
            "TempBar",
            &[("lo", Path), ("hi", Path), ("min", Path), ("max", Path)],
        ),
        ("SunArc", &[("rise", Path), ("set", Path), ("now", Path)]),
        ("MoonPhase", &[("phase", Path), ("illum", Path)]),
        (
            "AqiContour",
            &[("lat", Path), ("lon", Path), ("span", Number)],
        ),
        // Live satellite cloud imagery (卫星云图) over a place — the one pane the
        // shipping weather card has and L0 could not express at all. Names WHERE,
        // like every other visualisation here, and the helper answers the image,
        // so a card shows the sky without ever stating what is in it.
        ("Satellite", &[("lat", Path), ("lon", Path)]),
        (
            "StockPlot",
            &[("symbol", Path), ("range", TokenOrPath(UNIT))],
        ),
        // Several countries' World Bank series on one axis. Like StockPlot it
        // NAMES what to plot and the widget fetches it: a card that carried
        // sixty numbers would be stating facts (§4), and they would be wrong
        // the moment the series is revised.
        (
            "IndicatorPlot",
            &[("countries", Path), ("indicator", Path), ("years", Path)],
        ),
    ];

    pub fn lookup(name: &str) -> Option<Args> {
        CONSTRUCTORS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, a)| *a)
    }

    /// The CLOSED set of helpers a `source` may name, with the arguments each
    /// accepts. Mirrors `[sources.*]` in `docs/ui-l0-constructors.toml`.
    ///
    /// Without this the parser accepted any dotted name and `source_plan` handed
    /// it to the host as the function to resolve, so
    /// `source leak sys.shell(command: "cat /etc/passwd")` produced a clean,
    /// well-formed request. Confinement then rested on the host keeping its own
    /// allowlist — the policy boundary §1 claims L0 removes. A card must not be
    /// able to NAME a capability it was not granted.
    pub const SOURCES: &[(&str, &[&str])] = &[
        ("sys.geocode", &["name"]),
        // LIVE topic/movie detail from Wikipedia. Declared `source d sys.wiki(
        // query: state.title)`; a field access `d.extract` becomes the second
        // arg — `sys.wiki(query, "extract")` — exactly like `now.temp` on
        // `sys.weather`. So only the INPUT arg is listed here.
        ("sys.wiki", &["query"]),
        (
            "sys.weather",
            &["lat", "lon", "days", "fields", "aggregate", "day"],
        ),
        ("sys.daylight", &["lat", "lon"]),
        ("sys.airquality", &["lat", "lon"]),
        ("sys.moonphase", &["lat", "lon"]),
        ("sys.photo", &["query", "cond"]),
        ("sys.locale", &[]),
        ("sys.gps", &[]),
        ("sys.search", &["query", "count", "fields"]),
        // COORDINATES, not places. A route needs four numbers and an argument
        // carries one value, so `from`/`to` as place names could never be
        // resolved into a call — which is why this capability had no translation
        // and the nav card's duration and distance row was `— —` beneath a route
        // that drew correctly. Each coordinate is a read off the source that
        // found the place, which the existing argument resolution already turns
        // into a live call.
        (
            "sys.route",
            &[
                "from_lat", "from_lon", "to_lat", "to_lon", "via", "mode", "fields",
            ],
        ),
        // Where you are ON a route. Takes the trip's four coordinates and the
        // device's own two, and answers relative to them — the half of navigation
        // a route cannot give, because a route never changes as you drive it.
        (
            "sys.step",
            &[
                "from_lat", "from_lon", "to_lat", "to_lon", "at_lat", "at_lon", "fields",
            ],
        ),
        ("sys.places", &["lat", "lon", "category", "count", "fields"]),
        ("sys.news", &["count", "offset", "fields"]),
        ("sys.quakes", &["count", "offset", "fields"]),
        ("sys.news_item", &["id", "fields"]),
        // `symbols` names the UNIVERSE to rank. Without it the only universe is
        // the market-wide day-gainers screener, so "top 10 AI movers" could only
        // ever render generic gainers under an AI title -- which is what it did.
        ("sys.movers", &["count", "fields", "symbols"]),
        ("sys.quote", &["ticker", "fields"]),
        (
            "sys.series",
            &["ticker", "range", "points", "fields", "aggregate"],
        ),
        // §5.12's durable capabilities. `sys.watchlist` takes no selector — it
        // IS the user's list — and the host joins the stored tickers to live
        // quotes, so a card asks for the fields it wants to show and never
        // learns that a store exists.
        ("sys.watchlist", &["ticker", "fields"]),
        (
            "sys.indicator",
            &["countries", "indicator", "years", "fields"],
        ),
        ("sys.video", &["query", "count", "fields"]),
        ("sys.prefs", &["fields"]),
        ("sys.reading", &["fields"]),
        ("sys.topics", &["fields"]),
        ("sys.link", &["fields"]),
        // Free-text ticker lookup, so a card can offer something the top-movers
        // list does not happen to contain. `sys.search` is the PLACE search and
        // answers a different question; naming them apart is what stops a card
        // asking a geocoder for a company.
        ("sys.symbol_search", &["query", "count", "fields"]),
        // The user's saved places. Same shape as `sys.watchlist`: no selector,
        // because it IS the list, and the host joins each stored place to a
        // live reading.
        ("sys.cities", &["fields"]),
    ];

    pub fn source(name: &str) -> Option<&'static [&'static str]> {
        SOURCES.iter().find(|(n, _)| *n == name).map(|(_, a)| *a)
    }

    /// What each capability can ANSWER: the field names a card may request from
    /// it, and — for the ones that take no `fields:` — read off it.
    ///
    /// Until this existed the word "field" meant something different in four
    /// places and none was checked against another: the card's `fields:` list,
    /// the shapes `Record`/`Collection` which carried no fields at all, the
    /// adapter's hand-written key translation, and whatever the upstream JSON
    /// happens to contain. A card could request a field that does not exist and
    /// get an em dash, which reads on screen as data that has not arrived yet.
    ///
    /// These are L0's OWN names, not any backend's. `sys.weather` reaches
    /// open-meteo by raw JSON path and `sys.quote` reaches Yahoo through keys
    /// like `regularMarketPrice`; translating is the adapter's job, and putting
    /// backend spellings here would make the profile depend on one host.
    ///
    /// WHAT THIS DOES NOT CATCH. A field can be declared here, accepted by the
    /// checker, and still unanswerable by a given backend — `sys.quote` has an
    /// arm for `open` that resolves a key absent from the response it fetches,
    /// which rendered `$—` over a real price. Closing that needs a conformance
    /// test per backend asserting it answers everything declared here. This
    /// table is what such a test would check against; it is not the test.
    pub const ANSWERS: &[(&str, &[&str])] = &[
        (
            "sys.geocode",
            &[
                "lat",
                "lon",
                "name",
                "country",
                "admin1",
                "timezone",
                "population",
            ],
        ),
        (
            "sys.weather",
            &[
                "temp",
                "feels",
                "hi",
                "lo",
                "cond",
                "humidity",
                "wind",
                "pressure",
                "uv",
                "visibility",
                "precip",
                "dayname",
                "days",
            ],
        ),
        ("sys.daylight", &["rise", "set", "now"]),
        ("sys.airquality", &["aqi", "pm25", "pm10", "ozone"]),
        ("sys.moonphase", &["phase", "illumination", "name"]),
        // Live Wikipedia detail: the plot paragraph, the canonical title, the
        // one-line description, a poster/still URL. Read off `source d
        // sys.wiki(query: …)` as `d.extract`, `d.title`, … .
        // `thumbnail` is NOT offered. The page-summary endpoint returns it as a
        // nested object (`thumbnail.source`), and every lowering here reads a
        // single flat field — so a card asking for `d.thumbnail` would have got
        // an em dash with nothing able to warn it. Offering a field no backend
        // answers is the one failure this vocabulary exists to prevent; adding
        // it back needs a nested-path lowering first.
        ("sys.wiki", &["title", "extract", "description"]),
        // A photo is a URL, not a record. No field is readable off it.
        ("sys.photo", &[]),
        ("sys.locale", &["lang", "temp_unit"]),
        ("sys.gps", &["lat", "lon", "accuracy", "ok"]),
        // `label` is the secondary line — city, region, country. Without it a search
        // for "Stanford" renders five rows all reading "Stanford", which is what
        // Photon actually returns and is useless to choose between. The backend has
        // answered this field all along; the catalog simply never admitted it.
        (
            "sys.search",
            &["id", "name", "label", "query", "lat", "lon", "distance"],
        ),
        ("sys.route", &["duration", "distance", "steps"]),
        ("sys.step", &["instruction", "remaining", "progress", "eta"]),
        (
            "sys.places",
            &["id", "name", "distance", "lat", "lon", "category"],
        ),
        (
            "sys.news",
            &["id", "title", "author", "points", "comments", "url"],
        ),
        (
            "sys.quakes",
            &["id", "mag", "place", "depth", "ago", "lat", "lon"],
        ),
        (
            "sys.news_item",
            &["id", "title", "author", "points", "comments", "url"],
        ),
        (
            "sys.movers",
            &[
                "ticker", "name", "last", "change", "pct", "open", "high", "low", "prev", "volume",
                "mktcap", "pe", "currency", "exchange",
            ],
        ),
        (
            "sys.quote",
            &[
                "ticker", "name", "last", "change", "pct", "open", "high", "low", "prev", "volume",
                "mktcap", "pe", "currency", "exchange",
            ],
        ),
        // NOT `points`: a series is not a value, `StockPlot` fetches its own, and
        // nothing could lower a read of it to a call. See the TOML.
        ("sys.series", &["min", "max"]),
        // The host joins the stored tickers to live quotes, so a watchlist row
        // answers everything a quote does. The STORE holds only the ticker.
        (
            "sys.watchlist",
            &[
                "ticker", "name", "last", "change", "pct", "open", "high", "low", "prev", "volume",
                "mktcap", "pe", "currency", "exchange",
                // The membership probe, for a source that names a ticker:
                // "1" when that ticker is in the user's list, else "0".
                "has",
            ],
        ),
        // One country's reading of a World Bank indicator, indexed like every
        // other row source: `0.name`, `0.latest`, `0.change`. The SERIES is the
        // chart's to fetch; these are the numbers a card puts beside it.
        (
            "sys.indicator",
            &[
                "name", "latest", "first", "change", "min", "max", "year", "title",
            ],
        ),
        // A YouTube search result. `embed` is a player url ready to hand to
        // sys.link — a card cannot build one, because L0 has no string
        // concatenation, and that is the point.
        (
            "sys.video",
            &[
                "id", "title", "channel", "length", "views", "age", "thumb", "embed",
            ],
        ),
        ("sys.prefs", &["units", "range", "home", "work", "mode"]),
        // The reading list: SAVED story ids, joined to the story each id names.
        // The id is the identity Algolia serves forever, so a bookmarked story
        // outlives the front page it was found on.
        (
            "sys.reading",
            &["id", "title", "author", "points", "comments", "url"],
        ),
        // Followed TOPICS: the store holds a topic word ("ai", "nba"); the
        // top story beside it is searched fresh on every read, so a followed
        // topic never pins the story that was hot when it was followed.
        ("sys.topics", &["name", "top_title", "top_points", "top_id"]),
        // The in-app reader. `url` is the page currently open in the host's
        // native web overlay — "" when it is closed. A card WRITES a story's
        // url to open the reader over itself; the host owns the overlay and
        // closes it on system back, so the card never has to know how pages
        // are shown, only which page it asked for.
        ("sys.link", &["url"]),
        // Verified against the live endpoint, not its documentation: `longname`
        // comes back null for plenty of listings, so `name` falls back to
        // `shortname` in the helper. `kind` distinguishes an equity from a
        // crypto or an ETF, because a search for "nvid" returns all three and a
        // card that cannot say which is offering the user a coin.
        ("sys.symbol_search", &["ticker", "name", "exchange", "kind"]),
        // `name`, `lat` and `lon` come from the store — they IDENTIFY the place.
        // Everything else is a reading fetched at those coordinates each time it
        // is read, so a saved city can never show yesterday's temperature.
        (
            "sys.cities",
            &[
                "name", "lat", "lon", "temp", "feels", "hi", "lo", "cond", "humidity", "wind",
            ],
        ),
    ];

    /// Extra scalars `aggregate:` may ask a capability to compute over the rows
    /// it returns. Separate from `ANSWERS` because they sit at a different level
    /// — `week.min_lo` is a property of the WEEK, not of a day.
    pub const AGGREGATES: &[(&str, &[&str])] = &[
        ("sys.weather", &["min_lo", "max_hi"]),
        ("sys.series", &["min", "max"]),
    ];

    /// Capabilities backed by a durable store, and the transitions each accepts
    /// (§5.12).
    ///
    /// A capability absent from this table is READ-ONLY: a card may bind it and
    /// may not write it. That is the safe default — a fetch is not a thing a tap
    /// should be able to mutate, and listing the writable ones explicitly means
    /// granting the power is a deliberate edit rather than an omission.
    ///
    /// What is stored is REFERENCES, never facts. `sys.watchlist` holds tickers;
    /// the values beside them on screen are fetched every time. §4's no-facts
    /// rule does not stop applying because the data went to disk.
    pub const MUTABLE: &[(&str, &[&str])] = &[
        ("sys.watchlist", &["append", "remove"]),
        ("sys.cities", &["append", "remove"]),
        // A preference write has to name WHICH preference, and a transition's
        // target is a bare source name — the note that sat here said naming it
        // needed a dotted target, grammar L0 does not have. It does not: THE
        // DECLARATION ALREADY NAMES IT. A card that writes a preference declares
        // `source home_pref sys.prefs(fields: [home])`, and a source with exactly
        // one declared field leaves `home_pref: set($value)` nothing to be
        // ambiguous about. The checker enforces the exactly-one rule on any
        // written prefs source; a read-only one may still ask for several.
        ("sys.prefs", &["set", "clear"]),
        ("sys.reading", &["append", "remove"]),
        ("sys.topics", &["append", "remove"]),
        ("sys.link", &["set", "clear"]),
    ];

    pub fn mutable(name: &str) -> Option<&'static [&'static str]> {
        MUTABLE.iter().find(|(n, _)| *n == name).map(|(_, a)| *a)
    }

    pub fn answers(name: &str) -> Option<&'static [&'static str]> {
        ANSWERS.iter().find(|(n, _)| *n == name).map(|(_, a)| *a)
    }

    pub fn aggregates(name: &str) -> &'static [&'static str] {
        AGGREGATES
            .iter()
            .find(|(n, _)| *n == name)
            .map_or(&[], |(_, a)| *a)
    }
}

// ──────────────────────────────────────────────────────────────────── validation ──

fn validate(card: &Card, sink: &mut Diagnostics) {
    // A card with no `view root` has nothing to render. Realization says so,
    // but the CHECKER accepted it — and the checker is what a host asks before
    // storing a record, so an unusable card could be appended and only fail
    // when someone tried to look at it.
    if !card.views.iter().any(|v| v.name == "root") {
        sink.push(
            1,
            1,
            "a card needs a `view root`: it is the entry point a host realizes".into(),
        );
    }

    // Components must not form a cycle — profile §6, condition 1. Without this
    // an L0 realization need not terminate.
    check_component_acyclicity(card, sink);
    validate_transitions(card, sink);
    validate_sources(card, sink);

    // Which props of which components end up rendering a fact (§4).
    let data_positions = data_position_params(card);

    let view_names: Vec<&str> = card.views.iter().map(|v| v.name.as_str()).collect();
    let component_names: Vec<&str> = card.components.iter().map(|c| c.name.as_str()).collect();

    for view in &card.views {
        let mut scope = Scope::card(card);
        walk(
            &data_positions,
            &view.body,
            &mut scope,
            &view_names,
            &component_names,
            card,
            sink,
        );
    }
    for component in &card.components {
        let mut scope = Scope::component(card, component);
        walk(
            &data_positions,
            &component.body,
            &mut scope,
            &view_names,
            &component_names,
            card,
            sink,
        );
    }
}

/// Profile §3: every transition names a declared state and uses a total form.
///
/// A component's events target its OWN state. Card state is written by card-scope
/// events, which a component reaches only by receiving one as a prop (§5.4) — so
/// the transition still runs in the scope that declared it.
fn validate_transitions(card: &Card, sink: &mut Diagnostics) {
    check_state_initials(&card.states, sink, 1);
    for component in &card.components {
        check_state_initials(&component.states, sink, component.line);
        for param in &component.params {
            let Some(default) = &param.default else {
                continue;
            };
            if !value_fits_shape(&param.shape, default) {
                sink.push(
                    component.line,
                    1,
                    format!(
                        "{}.{} declares {} but a default of {default}",
                        component.name,
                        param.name,
                        shape_name(&param.shape)
                    ),
                );
            }
        }
    }

    // A path-valued `initial` is a rendering position by proxy: whatever it
    // names ends up on screen. Checking only direct `copy.x` references let
    // model-copy through by way of a state.
    let card_scope = Scope::card(card);
    for state in &card.states {
        if let Some(path) = &state.initial_path {
            check_path(path, &card_scope, 1, 1, sink);
        }
    }
    for component in &card.components {
        let scope = Scope::component(card, component);
        for state in &component.states {
            if let Some(path) = &state.initial_path {
                check_path(path, &scope, component.line, 1, sink);
            }
        }
    }

    // `set(path)` READS. Its operand must therefore be a readable name, which
    // an event is not: `set(some_event)` parses, resolves to nothing and writes
    // garbage into the cell.
    let mut card_readable: Vec<String> = card.sources.iter().map(|s| root_of(&s.name)).collect();
    card_readable.extend(card.states.iter().map(|s| root_of(&s.path)));
    card_readable.push("copy".into());
    let card_events: Vec<String> = card.events.iter().map(|e| e.name.clone()).collect();

    check_event_batch(
        &card.events,
        &card.states,
        &card_readable,
        &card_events,
        &card.copies,
        &card.sources,
        sink,
    );
    for component in &card.components {
        let mut readable: Vec<String> = card.sources.iter().map(|s| root_of(&s.name)).collect();
        readable.push("copy".into());
        // An EVENT prop is not readable — `set(out)` where `out` is an event
        // was accepted, because a param's shape was unknown so none could be
        // excluded. Now only value-shaped props are readable, and event-shaped
        // ones join the event names below.
        readable.extend(
            component
                .params
                .iter()
                .filter(|p| !matches!(p.shape, Shape::Event))
                .map(|p| p.name.clone()),
        );
        readable.extend(component.states.iter().map(|s| root_of(&s.path)));
        let mut events: Vec<String> = component.events.iter().map(|e| e.name.clone()).collect();
        events.extend(
            component
                .params
                .iter()
                .filter(|p| matches!(p.shape, Shape::Event))
                .map(|p| p.name.clone()),
        );
        check_event_batch(
            &component.events,
            &component.states,
            &readable,
            &events,
            &card.copies,
            // A component may write a durable collection too: the card's
            // sources are in scope for it (§5.3 forbids card STATE, not
            // sources), so the same rules must reach here.
            &card.sources,
            sink,
        );
    }
}

/// A shape's name, for diagnostics.
fn shape_name(shape: &Shape) -> &'static str {
    match shape {
        Shape::Text => "text",
        Shape::Number => "a number",
        Shape::Bool => "bool",
        Shape::Enum(_) => "an enum",
        Shape::Record => "a record",
        Shape::Collection => "a collection",
        Shape::Event => "an event",
        Shape::Other => "of an unnamed shape",
    }
}

/// Profile §2: a declared `initial` must fit the shape it is declared with.
/// Neither was checked against the other, so `shape: number, initial: "oops"`
/// mounted a string into a numeric cell before any event ran.
/// Whether a literal agrees with the shape it was declared alongside. Shared by
/// state initials and parameter defaults so the two cannot drift.
fn value_fits_shape(shape: &Shape, value: &serde_json::Value) -> bool {
    match (shape, value) {
        (Shape::Text, serde_json::Value::String(_)) => true,
        (Shape::Number, v) => v.is_number(),
        (Shape::Bool, serde_json::Value::Bool(_)) => true,
        (Shape::Enum(members), serde_json::Value::String(s)) => members.iter().any(|m| m == s),
        // A shape that names no literal form, or one we could not classify.
        (Shape::Record | Shape::Collection | Shape::Event | Shape::Other, _) => true,
        _ => false,
    }
}

fn check_state_initials(states: &[StateDecl], sink: &mut Diagnostics, line: usize) {
    for state in states {
        let Some(initial) = &state.initial else {
            continue;
        };
        let fits = value_fits_shape(&state.shape, initial);
        if !fits {
            sink.push(
                line,
                1,
                format!(
                    "state {:?} declares {} but an initial of {initial}",
                    state.path,
                    shape_name(&state.shape)
                ),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn check_event_batch(
    events: &[EventDecl],
    states: &[StateDecl],
    readable: &[String],
    event_names: &[String],
    copies: &[CopyDecl],
    sources: &[SourceDecl],
    sink: &mut Diagnostics,
) {
    for event in events {
        for transition in &event.transitions {
            // §5.12: a transition may target a SOURCE when that source is backed
            // by a durable store. The write leaves the card entirely — dispatch
            // hands it to the host — so none of the shape checks below apply,
            // and this is settled before them rather than inside them.
            if let Some(source) = sources.iter().find(|s| s.name == transition.target) {
                let accepted = catalog::mutable(&source.helper);
                let verb = match &transition.form {
                    Form::Append => "append",
                    Form::Remove => "remove",
                    Form::Set(_) => "set",
                    Form::Clear => "clear",
                    Form::Toggle => "toggle",
                    Form::Cycle => "cycle",
                    Form::Next(_) | Form::Prev(_) => "",
                    Form::NotTotal(_) => "",
                };
                match accepted {
                    // Read-only by default: binding a fetch is not permission to
                    // write it, and a capability earns that by being listed.
                    None => sink.push(
                        transition.line,
                        transition.column,
                        format!(
                            "{:?} is a source and cannot be written — {} is read-only. \
                             Only a capability backed by a durable store accepts a \
                             transition (profile §5.12)",
                            transition.target, source.helper
                        ),
                    ),
                    Some(verbs) if !verbs.contains(&verb) => sink.push(
                        transition.line,
                        transition.column,
                        format!(
                            "{} does not accept `{verb}`; it accepts: {}",
                            source.helper,
                            verbs.join(", ")
                        ),
                    ),
                    Some(_) => {}
                }
                // A written PREFERENCE must say which one, and the declaration
                // is what says it: the write's key is the source's single
                // declared field. A multi-field source leaves `set($value)`
                // aiming at nothing nameable.
                if source.helper == "sys.prefs"
                    && matches!(&transition.form, Form::Set(_) | Form::Clear)
                {
                    let fields = source
                        .args
                        .iter()
                        .find(|(n, _)| n == "fields")
                        .and_then(|(_, a)| match a {
                            SourceArg::List(l) => Some(l.len()),
                            _ => None,
                        })
                        .unwrap_or(0);
                    if fields != 1 {
                        sink.push(
                            transition.line,
                            transition.column,
                            format!(
                                "a written preference source must declare exactly one                                  field — the field IS the key the write lands under.                                  {:?} declares {fields}; split it: `source home_pref                                  sys.prefs(fields: [home])` writes `home` (profile §5.12)",
                                transition.target
                            ),
                        );
                    }
                }
                continue;
            }
            // A collection form on anything else is refused HERE rather than
            // falling through to the shape checks, which would report it as a
            // bad `set` on a state and send the reader looking in the wrong
            // place. There is no list-shaped cell: §5.12 is deliberate that a
            // durable collection is a source, because a card is regenerated per
            // request and a cell would be empty again the next time.
            if transition.form.is_collection() {
                sink.push(
                    transition.line,
                    transition.column,
                    format!(
                        "`append`/`remove` write a durable collection, and {:?} is not one. \
                         Declare it as a source over a store-backed capability — card state \
                         cannot hold a list, and would be reset on the next request anyway \
                         (profile §5.12)",
                        transition.target
                    ),
                );
                continue;
            }
            let Some(state) = states.iter().find(|s| s.path == transition.target) else {
                sink.push(
                    transition.line,
                    transition.column,
                    format!(
                        "{:?} is not a state declared in this scope",
                        transition.target
                    ),
                );
                continue;
            };

            match &transition.form {
                Form::NotTotal(text) => sink.push(
                    transition.line,
                    transition.column,
                    format!(
                        "{text:?} is not a total transition form; L0 admits set(…), toggle, cycle(…) and clear"
                    ),
                ),
                Form::Toggle if state.shape != Shape::Bool => sink.push(
                    transition.line,
                    transition.column,
                    format!(
                        "`toggle` needs a bool state, but {:?} is not bool",
                        transition.target
                    ),
                ),
                Form::Set(SetSource::Num(_)) if !matches!(state.shape, Shape::Number | Shape::Other) => {
                    sink.push(
                        transition.line,
                        transition.column,
                        format!(
                            "`set` writes a number, but {:?} is {}",
                            transition.target,
                            shape_name(&state.shape)
                        ),
                    );
                }
                Form::Set(SetSource::Bool(_)) if !matches!(state.shape, Shape::Bool | Shape::Other) => {
                    sink.push(
                        transition.line,
                        transition.column,
                        format!(
                            "`set` writes a bool, but {:?} is {}",
                            transition.target,
                            shape_name(&state.shape)
                        ),
                    );
                }
                Form::Set(SetSource::Token(t)) => {
                    if !matches!(state.shape, Shape::Enum(_) | Shape::Other) {
                        sink.push(
                            transition.line,
                            transition.column,
                            format!(
                                "`set` writes the token .{t}, but {:?} is {} — only an enum \
                                 has members",
                                transition.target,
                                shape_name(&state.shape)
                            ),
                        );
                    }
                    if let Shape::Enum(members) = &state.shape {
                        if !members.iter().any(|m| m == t) {
                            sink.push(
                                transition.line,
                                transition.column,
                                format!(
                                    ".{t} is not a member of {:?}'s enum; it accepts {}",
                                    transition.target,
                                    members
                                        .iter()
                                        .map(|m| format!(".{m}"))
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ),
                            );
                        }
                    }
                }
                Form::Set(SetSource::Text(_))
                    if !matches!(state.shape, Shape::Text | Shape::Other) =>
                {
                    sink.push(
                        transition.line,
                        transition.column,
                        format!(
                            "`set` writes text, but {:?} is {}",
                            transition.target,
                            shape_name(&state.shape)
                        ),
                    );
                }
                Form::Set(SetSource::Path(path)) => {
                    // §4 travels with the value: writing model-authored text
                    // into state renders it just as surely as naming it in a
                    // view, one step later.
                    if let Some(name) = path.strip_prefix("copy.") {
                        match copies.iter().find(|c| c.name == name) {
                            Some(decl) if decl.provenance == Provenance::ModelCopy => {
                                sink.push(
                                    transition.line,
                                    transition.column,
                                    format!(
                                        "copy.{name} is `model-copy` and may not be written \
                                         into state; only `vocabulary` and `user-copy` may \
                                         (profile §4)"
                                    ),
                                );
                            }
                            None => sink.push(
                                transition.line,
                                transition.column,
                                format!("copy.{name} is not declared"),
                            ),
                            _ => {}
                        }
                    }
                    let root = root_of(path);
                    if event_names.contains(&root) {
                        sink.push(
                            transition.line,
                            transition.column,
                            format!(
                                "{root:?} is an event, not a value; `set` reads a name and \
                                 cannot trigger one (profile §6.4)"
                            ),
                        );
                    } else if !readable.contains(&root) {
                        sink.push(
                            transition.line,
                            transition.column,
                            format!("{root:?} is not a readable name"),
                        );
                    }
                }
                Form::Set(_) => {}
                Form::Cycle => match &state.shape {
                    Shape::Enum(members) => {
                        for member in &transition.tokens {
                            if let Some(bare) = member.strip_prefix('!') {
                                sink.push(
                                    transition.line,
                                    transition.column,
                                    format!(
                                        "`cycle` takes tokens; {bare:?} is a path — enum members carry a leading dot"
                                    ),
                                );
                            } else if !members.contains(member) {
                                sink.push(
                                    transition.line,
                                    transition.column,
                                    format!(
                                        ".{member} is not a member of {:?}'s enum",
                                        transition.target
                                    ),
                                );
                            }
                        }
                        // Advancing uses the ENUM's declaration order (§3), so a
                        // `cycle` listing a different one would run an order the
                        // card does not say. Rejected rather than reordered:
                        // what is written must be what happens.
                        if !transition.tokens.is_empty()
                            && transition.tokens.iter().all(|t| members.contains(t))
                            && transition.tokens != *members
                        {
                            sink.push(
                                transition.line,
                                transition.column,
                                format!(
                                    "`cycle` advances in declaration order ({}), but lists {} — \
                                     reorder the enum or the cycle so they agree (profile §3)",
                                    members.join(", "),
                                    transition.tokens.join(", ")
                                ),
                            );
                        }
                    }
                    _ => sink.push(
                        transition.line,
                        transition.column,
                        format!("`cycle` needs an enum state, but {:?} is not", transition.target),
                    ),
                },
                // The collection walk: the path must name a declared source's
                // field, and the cell it moves must be text — the walked field
                // IS the value written.
                Form::Next(path) | Form::Prev(path) => {
                    if !matches!(&state.shape, Shape::Text) {
                        sink.push(
                            transition.line,
                            transition.column,
                            format!(
                                "`next`/`prev` write a text state, but {:?} is not",
                                transition.target
                            ),
                        );
                    }
                    let (root, field) = path.split_once('.').unwrap_or((path.as_str(), ""));
                    match sources.iter().find(|s| s.name == root) {
                        None => sink.push(
                            transition.line,
                            transition.column,
                            format!("`next({path})` walks a source, and {root:?} is not one"),
                        ),
                        Some(decl) => {
                            let declared = decl.args.iter().find(|(n, _)| n == "fields").and_then(
                                |(_, a)| match a {
                                    SourceArg::List(l) => Some(l),
                                    _ => None,
                                },
                            );
                            if field.is_empty()
                                || declared.is_some_and(|l| !l.iter().any(|f| f == field))
                            {
                                sink.push(
                                    transition.line,
                                    transition.column,
                                    format!(
                                        "`next({path})` walks a field {root:?} does not declare                                          — add it to the source's fields",
                                    ),
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Profile §4: a `source` may only name a catalogued capability.
///
/// This is the difference between "the host refuses to run it" and "the card
/// cannot ask". `source leak sys.shell(command: "cat /etc/passwd")` previously
/// parsed clean and reached the host as a well-formed request; confinement then
/// depended on the host keeping an allowlist that the profile claims to make
/// unnecessary.
fn validate_sources(card: &Card, sink: &mut Diagnostics) {
    // A source name and a card state name must be disjoint.
    //
    // §5.3 forbids a component from reading card state, and a collision walks
    // around the check: `check_path` asks whether the scope KNOWS a path before
    // asking whether it names forbidden state, so a source with the same name
    // answers the first question and the second is never reached. What the
    // component then reads is the SOURCE, which §5.3 permits — so nothing leaks
    // — but the card says two things and the runtime silently picks one, which
    // is not a defensible way to resolve two namespaces that must not overlap.
    for state in &card.states {
        if let Some(source) = card.sources.iter().find(|s| s.name == state.path) {
            sink.push(
                source.line,
                1,
                format!(
                    "{:?} is declared as both a source and card state. The two \
                     namespaces must be disjoint: a component may read a source \
                     but not card state (profile §5.3), so a shared name makes \
                     which one is read depend on lookup order rather than on \
                     anything the card says. Rename one",
                    state.path
                ),
            );
        }
    }

    // A declared source nothing reads is a fetch performed for nothing.
    //
    // `stock.card` shipped one: `series` went unread the moment `StockPlot`
    // began fetching its own data, and no test noticed. On device that is a
    // round trip, a parse and a cache entry per refresh, for data that reaches
    // no pixel.
    let mut read: std::collections::BTreeSet<String> = Default::default();
    let harvest = |element: &Element, read: &mut std::collections::BTreeSet<String>| {
        let (mut reads, mut pulls) = (Vec::new(), Vec::new());
        collect_reads(element, &mut reads, &mut pulls);
        read.extend(reads.iter().map(root_of));
        read.extend(pulls.iter().map(root_of));
    };
    for view in &card.views {
        harvest(&view.body, &mut read);
    }
    for component in &card.components {
        harvest(&component.body, &mut read);
    }
    // A source read by another source counts: `sys.weather(lat: place.lat)`
    // makes `place` needed even though no view names it.
    for source in &card.sources {
        for (name, arg) in &source.args {
            match arg {
                SourceArg::Path(path) => {
                    read.insert(root_of(path));
                }
                // And so does one read from inside a LIST argument.
                //
                // `sys.route(via: [stop.0.lat, stop.0.lon])` is how a trip names a
                // waypoint, and the items are paths like any other read. Counting
                // only `Path` here refused a card that used one: the stop's own
                // `sys.search` was reported as declared and never read, while the
                // route it fed was the only reason it existed.
                //
                // `fields:` is exempt — its items are the FIELD NAMES being asked
                // for (`[duration, distance]`), not paths, and treating `duration`
                // as a read of a source called `duration` would mark any source of
                // that name as used by every card in the corpus.
                SourceArg::List(items) if name != "fields" => {
                    for item in items {
                        read.insert(root_of(item));
                    }
                }
                _ => {}
            }
        }
    }
    // So does a state whose initial resolves from one.
    for state in &card.states {
        if let Some(path) = &state.initial_path {
            read.insert(root_of(path));
        }
    }
    // And a `copy` declaration reads the locale IMPLICITLY: resolving `copy.x`
    // looks up `env.locale.lang` to choose which translation to render. No path
    // in the card names it, so a purely syntactic scan calls `env.locale` dead
    // on every card that has copy but no other locale-dependent binding — which
    // is two of the three reference cards.
    if !card.copies.is_empty() {
        read.insert("env".to_owned());
        read.insert("env.locale".to_owned());
    }
    // An event WRITE is a use too: `page: set($value)` resolves against the
    // declared source to learn which capability it drives — a write-only
    // reader/link source is not dead, it is an actuator.
    for event in &card.events {
        for transition in &event.transitions {
            read.insert(root_of(&transition.target));
        }
    }
    for source in &card.sources {
        // A dotted source name (`env.locale`) is read as its own root.
        if !read.contains(&source.name) && !read.contains(&root_of(&source.name)) {
            sink.push(
                source.line,
                2,
                format!(
                    "source {:?} is declared and never read. The host fetches it \
                     on every refresh and nothing displays it — either bind it \
                     somewhere or remove the declaration",
                    source.name
                ),
            );
        }
    }

    // A source may read card state, other sources and copy — the same names a
    // view may, minus anything a component introduces.
    let scope = &Scope::card(card);
    for source in &card.sources {
        let Some(accepted) = catalog::source(&source.helper) else {
            let mut known: Vec<&str> = catalog::SOURCES.iter().map(|(n, _)| *n).collect();
            known.sort();
            sink.push(
                source.line,
                1,
                format!(
                    "{:?} is not a source capability L0 admits; a card may only name a \
                     catalogued helper (profile §4). Known: {}",
                    source.helper,
                    known.join(", ")
                ),
            );
            continue;
        };
        // A requested field must be one the capability ANSWERS.
        //
        // `fields:` was accepted as any list of words, so a card could ask for
        // something that does not exist and the host would return nothing for
        // it — an em dash, which is what a value still in flight looks like too.
        // A capability with no vocabulary declared is left alone rather than
        // treated as answering nothing.
        for (name, arg) in &source.args {
            let SourceArg::List(requested) = arg else {
                continue;
            };
            let (known, what) = match name.as_str() {
                "fields" => (catalog::answers(&source.helper), "answer"),
                "aggregate" => (Some(catalog::aggregates(&source.helper)), "aggregate"),
                _ => continue,
            };
            let Some(known) = known else { continue };
            for field in requested {
                if !known.iter().any(|k| k == field) {
                    sink.push(
                        source.line,
                        1,
                        format!(
                            "{} cannot {what} {field:?}. It {}",
                            source.helper,
                            if known.is_empty() {
                                "returns a value with no fields at all".to_owned()
                            } else {
                                format!("offers: {}", known.join(", "))
                            }
                        ),
                    );
                }
            }
        }
        for (name, arg) in &source.args {
            // The VALUE is a binding too. Checking only the argument's name let
            // a source carry any path to the host — the helper was constrained
            // and its arguments were not.
            if let SourceArg::Path(path) = arg {
                // A source addresses card state with an explicit `state.`
                // prefix — `sys.geocode(name: state.city)` — which the view
                // scope does not carry, since a view names its state directly.
                match path.strip_prefix("state.") {
                    Some(rest) => {
                        let root = root_of(rest);
                        if !card.states.iter().any(|st| root_of(&st.path) == root) {
                            sink.push(source.line, 1, format!("{root:?} is not a declared state"));
                        }
                    }
                    None => check_path(path, scope, source.line, 1, sink),
                }
            }
            if !accepted.contains(&name.as_str()) {
                sink.push(
                    source.line,
                    1,
                    format!(
                        "{:?} does not accept an argument named {name:?}; it accepts: {}",
                        source.helper,
                        if accepted.is_empty() {
                            "(none)".to_string()
                        } else {
                            accepted.join(", ")
                        }
                    ),
                );
            }
        }
    }
}

/// Profile §6, condition 1: the declaration graph must be acyclic.
///
/// This walks COMPONENTS AND VIEWS as one graph. Walking components alone
/// missed two shapes that both recurse forever at realization:
///
/// ```text
/// view a b        view b a                    two views referencing each other
/// component A { view v }  view v { A() }      a component via a view
/// ```
///
/// Both passed the old check and recursed until the node cap tripped, which is
/// a resource bound catching a structural error — and only because the caller
/// happened to set one.
fn check_component_acyclicity(card: &Card, sink: &mut Diagnostics) {
    // name -> (what it references, line)
    let mut edges: Vec<(String, Vec<String>, usize)> = Vec::new();
    for component in &card.components {
        let mut refs = component.instantiates.clone();
        let mut views = Vec::new();
        collect_references(&component.body, &mut views);
        refs.extend(views);
        edges.push((component.name.clone(), refs, component.line));
    }
    for view in &card.views {
        let mut refs = Vec::new();
        collect_constructors(&view.body, &mut refs);
        let mut views = Vec::new();
        collect_references(&view.body, &mut views);
        refs.extend(views);
        edges.push((view.name.clone(), refs, 1));
    }

    // Keep only edges that name a NODE of this graph. `collect_constructors`
    // yields every catalog constructor, so an unfiltered edge list is
    // proportional to the card's size rather than to its component graph — and
    // the traversal budget could then be exhausted by padding before the walk
    // reached a real cycle. Filtering makes the budget a backstop rather than
    // the thing that decides the answer.
    let node_names: Vec<String> = edges.iter().map(|(n, _, _)| n.clone()).collect();
    for (_, refs, _) in edges.iter_mut() {
        refs.retain(|r| node_names.contains(r));
        refs.dedup();
    }

    let referenced = |name: &str| -> Option<&Vec<String>> {
        edges.iter().find(|(n, _, _)| n == name).map(|(_, r, _)| r)
    };

    for (name, _, line) in &edges {
        let mut seen: Vec<&str> = vec![name.as_str()];
        let mut queue: Vec<&str> = referenced(name)
            .map(|r| r.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default();
        let mut steps = 0usize;
        while let Some(next) = queue.pop() {
            steps += 1;
            if steps > MAX_UI_L0_DECLARATIONS {
                break;
            }
            if next == name.as_str() {
                sink.push(
                    *line,
                    1,
                    format!(
                        "{name:?} is recursive; L0 requires an acyclic declaration graph \
                         (profile §6.1)"
                    ),
                );
                break;
            }
            if seen.contains(&next) {
                continue;
            }
            seen.push(next);
            if let Some(more) = referenced(next) {
                queue.extend(more.iter().map(|s| s.as_str()));
            }
        }
    }
}

/// Names a body SPLICES — `view` references, as distinct from component calls.
fn collect_references(element: &Element, out: &mut Vec<String>) {
    if element.is_reference {
        out.push(element.name.clone());
    }
    for child in &element.children {
        collect_references(child, out);
    }
}

/// Names visible to one record. Profile §5.3: a component sees its props, its own
/// state and events, and card-scope `source` and `copy` — but never card `state`.
struct Scope {
    roots: Vec<String>,
    /// Roots that name a source. Only these carry a `$state` lifecycle.
    source_roots: Vec<String>,
    /// Declared copy, so a rendering position can refuse model-authored text.
    copies: Vec<CopyDecl>,
    events: Vec<String>,
    /// Card state, tracked separately so reading it from a component is a
    /// specific diagnostic rather than "unknown name".
    forbidden_state: Vec<String>,
    /// For a root backed by a source that declared `fields:`, the names a
    /// reader may name off it.
    ///
    /// A card ALREADY says what it needs — `fields: [ticker, name, last]` — and
    /// nothing compared the views against it. `m.tickr` type-checked, so did
    /// `m.marketcap`, a field the host was never asked to fetch. Both render an
    /// em dash, which is indistinguishable from data that has not arrived.
    ///
    /// A root with no entry is unchecked: `sys.gps` and `sys.locale` take no
    /// field list, and a component prop is a record whose shape the card cannot
    /// see from here.
    fields: Vec<(String, Vec<String>)>,
}

/// What each source was asked for, as the names a reader may then name.
///
/// `fields:` and `aggregate:` both land in one set. They describe different
/// levels — `fields:` on a multi-day forecast describes the DAYS while
/// `aggregate:` describes the record around them — and separating them needs a
/// per-capability schema this does not have. Pooling them accepts a read at the
/// wrong level and still rejects a name the card never asked for, which is the
/// defect that ships.
fn declared_fields(card: &Card) -> Vec<(String, Vec<String>)> {
    let list = |source: &SourceDecl, want: &str| -> Option<Vec<String>> {
        source.args.iter().find_map(|(n, a)| match a {
            SourceArg::List(v) if n == want => Some(v.clone()),
            _ => None,
        })
    };
    card.sources
        .iter()
        .filter_map(|s| {
            // No `fields:` at all means the capability does not take one —
            // `sys.gps`, `sys.locale`. Unchecked rather than checked as empty.
            let mut names = list(s, "fields")?;
            names.extend(list(s, "aggregate").unwrap_or_default());
            Some((s.name.clone(), names))
        })
        .collect()
}

impl Scope {
    fn card(card: &Card) -> Self {
        let mut roots: Vec<String> = Vec::new();
        // The FULL declared name. Storing the root meant `source env.locale`
        // authorised `env.theme.secret` — an undeclared dependency the card
        // then renders, which §4 says is a defect by construction.
        roots.extend(card.sources.iter().map(|s| s.name.clone()));
        roots.extend(card.states.iter().map(|s| root_of(&s.path)));
        roots.push("copy".into());
        let events = card.events.iter().map(|e| e.name.clone()).collect();
        Self {
            roots,
            // The FULL declared name, not its root. `source env.locale` answers to
            // `env.locale.$state`; comparing against the root alone rejected that
            // while accepting `env.$state`, which names no source and has no
            // lifecycle to report.
            source_roots: card.sources.iter().map(|s| s.name.clone()).collect(),
            copies: card.copies.clone(),
            events,
            forbidden_state: Vec::new(),
            fields: declared_fields(card),
        }
    }

    fn component(card: &Card, component: &Component) -> Self {
        let mut roots: Vec<String> = Vec::new();
        roots.extend(card.sources.iter().map(|s| s.name.clone()));
        roots.push("copy".into());
        roots.extend(component.params.iter().map(|p| p.name.clone()));
        roots.extend(component.states.iter().map(|s| root_of(&s.path)));
        let mut events: Vec<String> = component.events.iter().map(|e| e.name.clone()).collect();
        // Events arrive as props too — §5.4, outputs are event props. Only the
        // ones DECLARED as events: every param used to be added here, so a
        // `text` prop could be handed to `on_tap` and a runtime string that
        // happened to match an event name would route it.
        events.extend(
            component
                .params
                .iter()
                .filter(|p| matches!(p.shape, Shape::Event))
                .map(|p| p.name.clone()),
        );
        Self {
            roots,
            source_roots: card.sources.iter().map(|s| s.name.clone()).collect(),
            copies: card.copies.clone(),
            events,
            forbidden_state: card.states.iter().map(|s| root_of(&s.path)).collect(),
            // A component sees the card's sources, so a read off one is checked
            // here too. Its own props are not: a `record` prop's shape is
            // whatever the caller passes, and §5.2 does not make the caller
            // declare it.
            fields: declared_fields(card),
        }
    }

    /// Whether `root` names something whose fields are known, and if so whether
    /// `field` is one of them.
    fn field_is_declared(&self, root: &str, field: &str) -> Option<bool> {
        let (_, names) = self.fields.iter().find(|(r, _)| r == root)?;
        Some(names.iter().any(|n| n == field))
    }

    /// Record that a source exposes a nested collection under `field`.
    ///
    /// Derived from the card rather than declared: `for d, i in week.days` is
    /// what says a forecast has `days`. Without this the loop over it would be
    /// rejected by the very rule that makes the read of `d.dayname` safe.
    fn note_structural(&mut self, path: &str) {
        let (root, field) = match path.split_once('.') {
            Some(parts) => parts,
            None => return,
        };
        if let Some((_, names)) = self.fields.iter_mut().find(|(r, _)| r == root) {
            if !names.iter().any(|n| n == field) {
                names.push(field.to_owned());
            }
        }
    }

    /// Whether `path` is covered by a declared name.
    ///
    /// A declared name matches its own segments only: `env.locale` answers
    /// `env.locale.lang` and does NOT answer `env.theme.secret`. Comparing
    /// roots made every sibling of a dotted source readable.
    fn knows(&self, path: &str) -> bool {
        self.roots.iter().any(|r| {
            path == r
                || path
                    .strip_prefix(r.as_str())
                    .is_some_and(|rest| rest.starts_with('.'))
        })
    }
}

fn root_of<S: AsRef<str>>(path: S) -> String {
    path.as_ref()
        .split('.')
        .next()
        .unwrap_or_default()
        .to_string()
}

#[allow(clippy::too_many_arguments)]
fn walk(
    data_positions: &BTreeMap<String, Vec<String>>,
    element: &Element,
    scope: &mut Scope,
    views: &[&str],
    components: &[&str],
    card: &Card,
    sink: &mut Diagnostics,
) {
    match element.name.as_str() {
        "" | "slot" | "into" => {}
        "for" => {
            // The key expression names the loop's own binder. Its first segment
            // was discarded unconditionally, so `key typo.id` behaved exactly
            // like `key item.id` — and §5.1's claim that changing a key moves
            // identity was false, because the name was never read.
            if let (Some(binder), Some(key)) = (element.binders.first(), &element.key_path) {
                let root = root_of(key);
                if root != *binder {
                    sink.push(
                        element.line,
                        element.column,
                        format!(
                            "the key names {root:?}, but this loop binds {binder:?} — a key \
                             must be a path into the item being iterated (profile §5.1)"
                        ),
                    );
                }
            }
            for binder in &element.binders {
                scope.roots.push(binder.clone());
            }
            if let Some(Arg {
                value: Operand::Path(p),
                line,
                column,
                ..
            }) = element.args.first()
            {
                // `for d, i in week.days` says a forecast HAS days. Register it
                // before checking, or the rule that makes `d.dayname` safe
                // rejects the loop that introduces `d`.
                scope.note_structural(p);
                check_path(p, scope, *line, *column, sink);
                // The item binder answers for whatever the collection's source
                // was asked for. `i` is the index and has no fields, so only the
                // first binder is bound.
                if let Some(binder) = element.binders.first() {
                    if let Some((_, names)) =
                        scope.fields.iter().find(|(r, _)| *r == root_of(p)).cloned()
                    {
                        scope.fields.push((binder.clone(), names));
                    }
                }
            }
        }
        "when" => {
            if let Some(Arg {
                value: Operand::Path(p),
                line,
                column,
                ..
            }) = element.args.first()
            {
                check_path(p, scope, *line, *column, sink);
                // The right operand is a binding too. Unchecked, an undeclared
                // name on the right resolved to nothing and the comparison
                // decided the branch on that absence.
                //
                // EVERY path in it, not just a bare one. This matched
                // `Operand::Path` alone, so `when a == nosuch * 2` was accepted
                // at L1 — an undeclared name reaching evaluation through the one
                // position that did not look inside its operand. §4's rule that
                // an expression must READ something was skipped here for the
                // same reason, so a guard could compare against a fabricated
                // literal. Both are the argument-position rules; a guard is not
                // a place they stop applying.
                if let Some(rhs) = element.rhs.as_ref() {
                    let mut paths = Vec::new();
                    expr_paths(rhs, &mut paths);
                    if matches!(rhs, Operand::Expr { .. }) {
                        if paths.is_empty() {
                            sink.push(
                                *line,
                                *column,
                                "an expression must read a declared source or state: every \
                                 operand here is a literal, which states a fact rather than \
                                 computing one (profile §4)"
                                    .to_string(),
                            );
                        } else if expr_is_constant(rhs) {
                            sink.push(
                                *line,
                                *column,
                                "this expression reads declared values and IGNORES them: its \
                                 answer is the same whatever they are, so it states a fact \
                                 rather than computing one (profile §4)"
                                    .to_string(),
                            );
                        }
                    }
                    for r in paths {
                        check_path(&r, scope, *line, *column, sink);
                    }
                }
            }
        }
        _ if element.is_reference => {
            if !views.contains(&element.name.as_str()) {
                sink.push(
                    element.line,
                    element.column,
                    format!("{:?} is not a declared view", element.name),
                );
            }
        }
        name => {
            let known = catalog::lookup(name);
            let is_component = components.contains(&name);
            if is_component {
                if let Some(component) = card.components.iter().find(|c| c.name == name) {
                    let offered = slot_names(component);
                    for child in &element.children {
                        if child.name != "into" {
                            continue;
                        }
                        let wanted = child.binders.first().cloned().unwrap_or_default();
                        if !offered.contains(&wanted) {
                            let list = if offered.iter().all(|s| s.is_empty()) {
                                "it has only an anonymous slot".to_string()
                            } else {
                                format!(
                                    "it offers: {}",
                                    offered
                                        .iter()
                                        .filter(|s| !s.is_empty())
                                        .cloned()
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                )
                            };
                            sink.push(
                                child.line,
                                child.column,
                                format!(
                                    "{name:?} has no slot named {wanted:?}, so these children \
                                     would not render — {list} (profile §5.5)"
                                ),
                            );
                        }
                    }
                }
            }
            if known.is_none() && !is_component {
                sink.push(
                    element.line,
                    element.column,
                    format!("{name:?} is not an L0 constructor or a declared component"),
                );
            }
            for arg in &element.args {
                check_arg(
                    data_positions,
                    name,
                    arg,
                    known,
                    is_component,
                    scope,
                    card,
                    sink,
                );
            }
        }
    }

    for child in &element.children {
        walk(data_positions, child, scope, views, components, card, sink);
    }

    if element.name == "for" {
        for _ in &element.binders {
            scope.roots.pop();
        }
    }
}

/// Eight parameters because a card-level check needs card-level context:
/// the catalog entry, the scope, the card, and the data-position map are all
/// consulted per argument. Splitting them into a struct would move the noise
/// rather than remove it.
#[allow(clippy::too_many_arguments)]
fn check_arg(
    data_positions: &BTreeMap<String, Vec<String>>,
    ctor: &str,
    arg: &Arg,
    known: Option<catalog::Args>,
    is_component: bool,
    scope: &Scope,
    card: &Card,
    sink: &mut Diagnostics,
) {
    use catalog::ArgKind::*;

    // A component's own props are declared by the card, not the catalog.
    let kind = match known {
        Some(args) => match args.iter().find(|(n, _)| *n == arg.name) {
            Some((_, k)) => Some(*k),
            None => {
                sink.push(
                    arg.line,
                    arg.column,
                    format!("{ctor} has no argument {:?}", arg.name),
                );
                return;
            }
        },
        None if is_component => {
            // A component's props are declared by the CARD, not the catalog —
            // but they ARE declared, so an argument the component does not
            // accept is a typo, not a pass-through. It used to be accepted and
            // then silently dropped at realization, rendering an em dash.
            if let Some(component) = card.components.iter().find(|c| c.name == ctor) {
                match component.params.iter().find(|p| p.name == arg.name) {
                    Some(param) => {
                        check_prop(ctor, arg, param, scope, sink);
                        // §4 again, one level out: a literal handed to a prop
                        // that lands in a data position is the same authored
                        // fact, just laundered.
                        if matches!(arg.value, Operand::Str(_) | Operand::Num(_))
                            && data_positions
                                .get(ctor)
                                .is_some_and(|ps| ps.contains(&arg.name))
                        {
                            sink.push(
                                arg.line,
                                arg.column,
                                format!(
                                    "{ctor}.{} reaches a data position and must be bound; \
                                     a literal passed here is a model-authored fact \
                                     (profile §4)",
                                    arg.name
                                ),
                            );
                        }
                    }
                    None => {
                        let mut names: Vec<&str> =
                            component.params.iter().map(|p| p.name.as_str()).collect();
                        names.sort();
                        sink.push(
                            arg.line,
                            arg.column,
                            format!(
                                "{ctor} has no prop {:?}; it declares: {}",
                                arg.name,
                                if names.is_empty() {
                                    "(none)".to_string()
                                } else {
                                    names.join(", ")
                                }
                            ),
                        );
                    }
                }
            }
            None
        }
        None => return,
    };

    match (&arg.value, kind) {
        (Operand::Token(tok), Some(Token(set) | TokenOrPath(set))) => {
            let bare = tok.trim_start_matches('.');
            if !set.contains(&bare) {
                sink.push(
                    arg.line,
                    arg.column,
                    format!(
                        "{tok:?} is not a legal token for {ctor}.{}; expected one of {}",
                        arg.name,
                        set.iter()
                            .map(|t| format!(".{t}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
            }
        }
        (Operand::Str(lit), Some(Path)) => {
            sink.push(
                arg.line,
                arg.column,
                format!(
                    "{ctor}.{} takes a bound path, not the literal {lit:?} — a literal in a \
                     data position is a model-authored fact (profile §4)",
                    arg.name
                ),
            );
        }
        (Operand::Num(lit), Some(Path)) => {
            sink.push(
                arg.line,
                arg.column,
                format!(
                    "{ctor}.{} takes a bound path, not the literal {lit} — a literal in a \
                     data position is a model-authored fact (profile §4)",
                    arg.name
                ),
            );
        }
        // A data position renders a fact and must be bound, not authored.
        (Operand::Token(t), Some(Data)) => {
            sink.push(
                arg.line,
                arg.column,
                format!(
                    "{ctor}.{} renders a value and must be bound; {t:?} is a token \
                     (profile §4)",
                    arg.name
                ),
            );
        }
        (Operand::Str(_) | Operand::Num(_), Some(Data)) => {
            let shown = match &arg.value {
                Operand::Num(n) => format!("{n}"),
                Operand::Str(t) => format!("{t:?}"),
                other => format!("{other:?}"),
            };
            sink.push(
                arg.line,
                arg.column,
                format!(
                    "{ctor}.{} renders a value and must be bound; {shown} is a literal the \
                     model authored (profile §4). Layout numbers like `gap:` may be literal; \
                     a measurement may not",
                    arg.name
                ),
            );
        }
        // A number position rendering a fact must be bound, not authored.
        // `TextHero(value: "34 mph")` is the case §4 exists to make
        // unrepresentable: units concatenated onto a value the model invented.
        (Operand::Str(lit), Some(Number)) => {
            sink.push(
                arg.line,
                arg.column,
                format!(
                    "{ctor}.{} renders a value and must be bound; {lit:?} is a literal, and \
                     text in a number position is a fact the model authored (profile §4). \
                     Units belong in `unit:`, formatting in `format:`",
                    arg.name
                ),
            );
        }
        (Operand::Token(tok), Some(Path)) => {
            sink.push(
                arg.line,
                arg.column,
                format!(
                    "{ctor}.{} takes a bound path, not the token {tok:?}",
                    arg.name
                ),
            );
        }
        (Operand::Path(path), Some(Token(_))) => {
            // Enum members are tokens; a bare name here is a path and cannot
            // stand in for one.
            sink.push(
                arg.line,
                arg.column,
                format!(
                    "{ctor}.{} takes a token; {path:?} is a path — tokens carry a leading dot",
                    arg.name
                ),
            );
        }
        (Operand::Path(path), Some(Event)) if !scope.events.iter().any(|e| e == path) => {
            sink.push(
                arg.line,
                arg.column,
                format!("{path:?} is not a declared event"),
            );
        }
        (Operand::Path(_), Some(Event)) => {}
        // A component prop has no catalogued kind, and may legitimately receive an
        // event name — profile §5.4, outputs are event props. Accept either.
        (Operand::Path(path), None) if scope.events.iter().any(|e| e == path) => {}
        (Operand::Path(path), _) => check_path(path, scope, arg.line, arg.column, sink),
        (Operand::Predicate { path, rhs, .. }, _) => {
            check_path(path, scope, arg.line, arg.column, sink);
            // EVERY path in the right operand, not just a bare one. Leaving it
            // unchecked is how `when selected != absent` took its branch with
            // `absent` undeclared — and now that a comparison's right side can
            // hold arithmetic, matching only `Path` would let `x == a + b` past
            // with `a` and `b` undeclared.
            let mut paths = Vec::new();
            expr_paths(rhs, &mut paths);
            // §9.3 applies to a comparison's right side too: `x == 3 * 4` computes
            // a number from nothing and compares against it.
            if matches!(rhs.as_ref(), Operand::Expr { .. }) {
                if paths.is_empty() {
                    sink.push(
                        arg.line,
                        arg.column,
                        "an expression must read a declared source or state: every operand here \
                         is a literal, which states a fact rather than computing one (profile §4)"
                            .to_string(),
                    );
                } else if expr_is_constant(rhs) {
                    sink.push(
                        arg.line,
                        arg.column,
                        "this expression reads declared values and IGNORES them: its answer is \
                         the same whatever they are, so it states a fact rather than computing \
                         one (profile §4). `x * 0 + 1547` is 1547"
                            .to_string(),
                    );
                }
            }
            for p in paths {
                check_path(&p, scope, arg.line, arg.column, sink);
            }
        }
        // §4's no-facts rule, one level up.
        //
        // L0 refuses a literal in a value position outright — a decidable,
        // structural check. L1 cannot, because a coefficient is a legitimate
        // literal: `temp * 9 / 5 + 32` is a FORMULA. So the rule becomes: an
        // expression must READ something. `1547 * 3.2` reads nothing, and is a
        // fabricated fact wearing arithmetic.
        (expr @ Operand::Expr { .. }, _) => {
            let mut paths = Vec::new();
            expr_paths(expr, &mut paths);
            if paths.is_empty() {
                sink.push(
                    arg.line,
                    arg.column,
                    "an expression must read a declared source or state: every operand here \
                     is a literal, which states a fact rather than computing one (profile §4)"
                        .to_string(),
                );
            } else if expr_is_constant(expr) {
                sink.push(
                    arg.line,
                    arg.column,
                    "this expression reads declared values and IGNORES them: its answer is the \
                     same whatever they are, so it states a fact rather than computing one \
                     (profile §4). `x * 0 + 1547` is 1547"
                        .to_string(),
                );
            }
            for p in paths {
                check_path(&p, scope, arg.line, arg.column, sink);
            }
        }
        _ => {}
    }

    let _ = card;
}

/// Check an argument against the prop it fills — §5.2.
///
/// Only the cases a card can actually get wrong and that the shape decides:
/// an event where a value belongs, a value where an event belongs, and a token
/// outside a declared enum. Anything else is left alone, because a prop shape
/// is a contract about the DATA and most positions legitimately accept a path
/// whose type is not knowable until the host answers.
/// Which of a component's params end up in a DATA position — an argument the
/// catalog declares as `Data` or `Path`, i.e. one that renders a fact.
///
/// Without this, §4 is enforced only at the literal's immediate call site, and
/// laundering it through one prop defeats it entirely:
///
/// ```text
/// component Bar(n: number) { view TempBar(lo: n, hi: n, min: n, max: n) }
/// view root Bar(n: 41.2)
/// ```
///
/// Computed to a fixpoint so passing the value through a chain of components is
/// no better a hiding place than passing it directly.
fn data_position_params(card: &Card) -> BTreeMap<String, Vec<String>> {
    let mut tainted: BTreeMap<String, Vec<String>> = BTreeMap::new();

    // Bound by the number of PARAM HOPS a value can take, not by the component
    // count. A single component whose params chain a -> b -> c -> data needs
    // three rounds, which `N + 1` with N = 1 does not allow — and the loop must
    // still terminate if the graph turns out to be cyclic, since this runs
    // before acyclicity is proven.
    let rounds = card.components.len()
        + card
            .components
            .iter()
            .map(|c| c.params.len())
            .sum::<usize>()
        + 2;
    for _ in 0..rounds {
        let mut changed = false;
        for component in &card.components {
            let names: Vec<&str> = component.params.iter().map(|p| p.name.as_str()).collect();
            let mut found: Vec<String> = Vec::new();

            fn walk(
                element: &Element,
                names: &[&str],
                tainted: &BTreeMap<String, Vec<String>>,
                out: &mut Vec<String>,
            ) {
                let known = catalog::lookup(&element.name);
                for arg in &element.args {
                    let Operand::Path(path) = &arg.value else {
                        continue;
                    };
                    let root = root_of(path);
                    if !names.iter().any(|n| *n == root) {
                        continue;
                    }
                    // Directly in a data position...
                    let direct = known
                        .and_then(|a| a.iter().find(|(n, _)| *n == arg.name))
                        .is_some_and(|(_, k)| {
                            matches!(k, catalog::ArgKind::Data | catalog::ArgKind::Path)
                        });
                    // ...or handed to another component that puts it in one.
                    let onward = tainted
                        .get(&element.name)
                        .is_some_and(|ps| ps.contains(&arg.name));
                    if (direct || onward) && !out.contains(&root) {
                        out.push(root);
                    }
                }
                for child in &element.children {
                    walk(child, names, tainted, out);
                }
            }

            walk(&component.body, &names, &tainted, &mut found);
            let entry = tainted.entry(component.name.clone()).or_default();
            for name in found {
                if !entry.contains(&name) {
                    entry.push(name);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    tainted
}

fn check_prop(ctor: &str, arg: &Arg, param: &Param, scope: &Scope, sink: &mut Diagnostics) {
    let name = &param.name;
    match (&param.shape, &arg.value) {
        // An event prop must receive an event, and nothing else may.
        (Shape::Event, Operand::Path(p)) if !scope.events.iter().any(|e| e == p) => {
            sink.push(
                arg.line,
                arg.column,
                format!("{ctor}.{name} takes an event; {p:?} is not a declared event"),
            );
        }
        (Shape::Event, Operand::Str(_) | Operand::Num(_) | Operand::Token(_)) => {
            sink.push(
                arg.line,
                arg.column,
                format!("{ctor}.{name} takes an event, not a literal"),
            );
        }
        (shape, Operand::Path(p))
            if !matches!(shape, Shape::Event) && scope.events.iter().any(|e| e == p) =>
        {
            sink.push(
                arg.line,
                arg.column,
                format!(
                    "{ctor}.{name} takes a value, but {p:?} is an event — declare the prop \
                     as `{name}: event` to pass one (profile §5.4)"
                ),
            );
        }
        (Shape::Enum(members), Operand::Token(t)) => {
            let bare = t.trim_start_matches('.');
            if !members.iter().any(|m| m == bare) {
                sink.push(
                    arg.line,
                    arg.column,
                    format!(
                        "{t:?} is not a member of {ctor}.{name}; it accepts {}",
                        members
                            .iter()
                            .map(|m| format!(".{m}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
            }
        }
        _ => {}
    }
}

fn check_path(path: &str, scope: &Scope, line: usize, column: usize, sink: &mut Diagnostics) {
    if path.is_empty() {
        return;
    }

    // `copy.x` where `x` is model-authored. §4's whole point: a model-written
    // string on screen is indistinguishable from a fact the model invented, so
    // the class exists to be refused rather than to be recorded.
    if let Some(name) = path.strip_prefix("copy.") {
        if let Some(decl) = scope.copies.iter().find(|c| c.name == name) {
            if decl.provenance == Provenance::ModelCopy {
                sink.push(
                    line,
                    column,
                    format!(
                        "copy.{name} is `model-copy` and may not be rendered; only \
                         `vocabulary` and `user-copy` may (profile §4)"
                    ),
                );
            }
        } else {
            sink.push(line, column, format!("copy.{name} is not declared"));
        }
        return;
    }

    // A `[inner]` segment holds a path of its own. Checking it here is what
    // makes `stories[typo].title` a diagnostic rather than a silent em dash.
    for segment in path.split('.') {
        if let Some(inner) = segment.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            check_path(inner, scope, line, column, sink);
        }
    }
    let root = root_of(path);

    // `<source>.$state` is the fetch lifecycle (§5.9). It is meaningful only for
    // something that is fetched — a local state has no pending or failed.
    if let Some(owner) = path.strip_suffix(".$state") {
        if scope.source_roots.iter().any(|r| r == owner) {
            return;
        }
        sink.push(
            line,
            column,
            format!("`$state` is only available on a source; {owner:?} is not one (profile §5.9)"),
        );
        return;
    }
    if path.contains("$state") {
        sink.push(
            line,
            column,
            "`$state` must be the last segment of a path (profile §5.9)".to_string(),
        );
        return;
    }

    // The whole path, so a declared name can be matched by its own segments.
    if scope.knows(path) {
        // Known root, but is the FIELD one the card asked for?
        //
        // A card declares `fields: [ticker, name, last]` and nothing compared
        // the views against it, so `m.tickr` and `m.marketcap` both passed —
        // one a typo, one a field the host was never asked to fetch. Each
        // renders an em dash, which on screen is indistinguishable from data
        // still in flight.
        if let Some((root, rest)) = path.split_once('.') {
            // A numeric segment is an INDEX into a collection, not a field:
            // `lead.0.title` takes the first story and reads its title. Treating
            // it as a field rejected every indexed read in the news card.
            let mut segments = rest
                .split('.')
                .skip_while(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()));
            let field = segments.next().unwrap_or("");
            // Only the first field segment: deeper paths reach into a record
            // whose own shape needs the per-capability schema.
            if !field.is_empty() && !field.starts_with('$') && !field.starts_with('[') {
                if let Some(false) = scope.field_is_declared(root, field) {
                    let (_, names) = scope.fields.iter().find(|(r, _)| r == root).unwrap();
                    sink.push(
                        line,
                        column,
                        format!(
                            "{root:?} was not asked for {field:?}. A source answers only the \
                             fields its declaration requests, so this renders as missing — \
                             add it to `fields:` or read one of: {}",
                            names.join(", ")
                        ),
                    );
                }
            }
        }
        return;
    }
    if scope.forbidden_state.contains(&root) {
        sink.push(
            line,
            column,
            format!(
                "a component may not read card state {root:?}; pass it as a prop (profile §5.3)"
            ),
        );
        return;
    }
    sink.push(line, column, format!("{root:?} is not a declared name"));
}

// ─────────────────────────────────────────────────────────────────── realization ──

/// An L1 expression, resolved for lowering.
///
/// A realized number is not enough: `shares * quote.last` computed at
/// realization is the answer for the data the host happened to seed, and a live
/// card has none. The backend needs the SHAPE — which operands are live calls
/// and which are constants — so it can emit arithmetic the VM evaluates against
/// data that arrives later.
#[derive(Clone, Debug, PartialEq)]
pub enum ExprPart {
    /// An operand answered by a live capability call.
    Call(SourceBinding),
    /// An operand already resolved to a constant — a coefficient, or a value no
    /// backend can answer.
    Const(String),
    Bin(Box<ExprPart>, String, Box<ExprPart>),
}

/// A realized node. Renderer-neutral: a backend maps `kind` to its own widget.
#[derive(Clone, Debug, PartialEq)]
pub struct UiNode {
    pub kind: String,
    /// Instance identity — the declaration path plus every enclosing loop key.
    /// Never derived from position, so an edit that inserts a sibling above does
    /// not rebind this node's state (profile §5.1).
    pub key: String,
    pub args: Vec<(String, NodeValue)>,
    pub children: Vec<UiNode>,
    /// For each argument whose value came from a `source`, WHICH source and
    /// which field of it — alongside the resolved value in `args`, not instead
    /// of it.
    ///
    /// Realization resolves `quote.last` against the data blob and produces a
    /// number, at which point nothing downstream can tell that number came from
    /// a fetch. A backend that can fetch for itself needs to know, so it can
    /// emit a live call rather than bake in whatever the blob happened to hold.
    /// Additive on purpose: a consumer that ignores this sees exactly what it
    /// saw before.
    pub bindings: Vec<(String, SourceBinding)>,
    /// For each argument that is an L1 expression, its resolved shape.
    pub exprs: Vec<(String, ExprPart)>,
}

/// Where an argument's value came from, with the source's own arguments already
/// resolved.
///
/// The arguments are RESOLVED, not paths: `sys.quote(ticker: state.selected)`
/// records `ticker = "NVDA"`, because the state is known at realization and the
/// backend emitting the call has no way to look it up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceBinding {
    /// The capability the card named — `sys.quote`.
    pub helper: String,
    /// Its arguments, resolved to values.
    pub args: Vec<(String, String)>,
    /// Which of those arguments hold a CALL this lowering generated rather than
    /// a value.
    ///
    /// A source argument that names another source resolves to the callee's own
    /// live call, and once both are strings a backend cannot tell the two apart.
    /// A numeric slot could guess — a coordinate is a number or it is a `sys.`
    /// call — but a TEXT slot cannot, and it has to quote a value and not quote a
    /// call. `sys.photo(query: place.name)` lowered to
    /// `sys.photo("sys.geocode(\"kyoto\", \"name\")")`, so the wallpaper was
    /// generated from the TEXT of the call. It looked right, which is why it
    /// lived so long: the service is a generative image model and the place name
    /// is inside the string it was handed, so a card asking for Kyoto got a
    /// picture of Kyoto anyway.
    ///
    /// Guessing from the string is not good enough here, because a text
    /// argument can carry what a person TYPED — `sys.video(query: state.q)` is
    /// the search box — and "starts with `sys.`" would make a typed query
    /// executable. This is the lowering stating what it built.
    pub nested: Vec<String>,
    /// The path WITHIN the source's result: `last` for `quote.last`, empty when
    /// the source itself is named.
    pub field: String,
}

/// A resolved argument value.
#[derive(Clone, Debug, PartialEq)]
pub enum NodeValue {
    Text(String),
    Number(f64),
    Bool(bool),
    /// A `.token`, carried through with its meaning intact for the backend.
    Token(String),
    /// A declared event name for the runtime to bind at dispatch — never a
    /// string constructed by the card (profile §3.1).
    Event(String),
    /// A binding that resolved to nothing. Surfaced rather than defaulted: a
    /// silently empty field is how a card renders an em dash and looks fine.
    Missing,
    /// A source's lifecycle, readable as `now.$state` — §5.9. A card can show a
    /// spinner or an error rather than an em dash, and the distinction between
    /// "not yet" and "failed" is the runtime's to report, not the card's to
    /// guess from an absent value.
    Status(SourceStatus),
}

/// Where a source is in its lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceStatus {
    /// Never resolved.
    Pending,
    /// Resolved, and current.
    Ready,
    /// Resolved, but the value is past its freshness budget.
    Stale,
    /// The fetch failed. The card may say so; it may not say why.
    Failed,
}

impl SourceStatus {
    pub fn as_token(self) -> &'static str {
        match self {
            SourceStatus::Pending => "pending",
            SourceStatus::Ready => "ready",
            SourceStatus::Stale => "stale",
            SourceStatus::Failed => "failed",
        }
    }
}

/// Traversal bounds. L0 has no expressions, so there is nothing to evaluate and
/// no instruction budget to set — these bound the walk instead.
#[derive(Clone, Copy, Debug)]
pub struct RealizeLimits {
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_collection: usize,
}

impl Default for RealizeLimits {
    fn default() -> Self {
        Self {
            max_nodes: 8_192,
            max_depth: 64,
            max_collection: 512,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RealizeReport {
    pub root: Option<UiNode>,
    pub diagnostics: Vec<SyntaxDiagnostic>,
    pub nodes: usize,
    /// A bound was reached; the tree is partial.
    pub truncated: bool,
    /// Every component instance this realization produced, plus the card cell.
    /// Pass to [`InstanceStore::prune`] to forget instances that went away —
    /// without it the store grows for the life of the app, and a key that
    /// reappears inherits a stale value (§5.7, unmount).
    pub live_keys: Vec<String>,
    /// Nodes carried over from a previous tree by [`realize_patch`] rather than
    /// rebuilt. Zero for a full realization.
    pub reused: usize,
    /// Card state whose value came from a declared `initial: <source path>` this
    /// realization — the first answer a source gave for it.
    ///
    /// A HOST should write these into the store, and that write is what makes the
    /// capture a capture. Left unwritten, an `initial:` re-resolves on every
    /// realization and the state follows its source: an origin declared as "where I
    /// am" then chases the device, and a route declared from it is re-fetched before
    /// it can answer. Written once, the state holds the value the source had when it
    /// first had one — which is what "where I was when I started" means, and what
    /// R9.5's `let` does by freezing at build without being able to wait for data.
    ///
    /// Only what an `initial_path` produced. A literal initial needs no capturing and
    /// a value already in the store is already captured.
    pub captured: Vec<(String, serde_json::Value)>,
}

/// Realize a card against resolved data.
///
/// `data` carries what the runtime fetched and holds: source results, state
/// values and copy, keyed by declaration name. **No capability is reachable from
/// here** — not because one is blocked, but because realization is a tree walk
/// and there is no evaluator to reach anything with.
pub fn realize(source: &str, data: &serde_json::Value, limits: RealizeLimits) -> RealizeReport {
    realize_inner(source, data, None, limits)
}

fn realize_inner(
    source: &str,
    data: &serde_json::Value,
    store: Option<&InstanceStore>,
    limits: RealizeLimits,
) -> RealizeReport {
    let mut sink = Diagnostics::default();

    let check = check_ui_l0_named("card.l0", source);
    if !check.valid {
        return RealizeReport {
            root: None,
            diagnostics: check.diagnostics,
            nodes: 0,
            truncated: false,
            live_keys: Vec::new(),
            reused: 0,
            captured: Vec::new(),
        };
    }

    let tokens = match lex(source, &mut sink) {
        Some(t) => t,
        None => {
            return RealizeReport {
                root: None,
                diagnostics: sink.items,
                nodes: 0,
                truncated: false,
                live_keys: Vec::new(),
                reused: 0,
                captured: Vec::new(),
            }
        }
    };
    let card = Parser::new(&tokens, &mut sink).parse_card();

    let Some(root) = card.views.iter().find(|v| v.name == "root") else {
        sink.push(1, 1, "a card needs a `view root`".into());
        return RealizeReport {
            root: None,
            diagnostics: sink.items,
            nodes: 0,
            truncated: false,
            live_keys: Vec::new(),
            reused: 0,
            captured: Vec::new(),
        };
    };

    let mut ctx = Realizer {
        depth: 0,
        card: &card,
        limits,
        nodes: 0,
        truncated: false,
        sink: &mut sink,
        store,
        live: vec![CARD_STATE_KEY.to_string()],
        slots: Vec::new(),
    };
    // Card-scope state resolves from the store first, then the injected data,
    // then its declared initial. Without this, an event that wrote card state
    // would apply and be invisible at the next realization — and a guard on a
    // state with no value at all would take the wrong branch on first render.
    let mut frames: Vec<Frame> = Vec::new();
    let mut captured: Vec<(String, serde_json::Value)> = Vec::new();
    for state in &card.states {
        let stored = store
            .and_then(|s| s.get(CARD_STATE_KEY, &state.path))
            .cloned()
            .or_else(|| data.get(&state.path).cloned())
            .or_else(|| state.initial.clone());
        let value = match stored {
            Some(v) => v,
            None => {
                // From a SOURCE, so it is a capture: report it, and the host writes
                // it once. Until that write this re-resolves every realization, and
                // a state that follows its source is not an initial value.
                match state.initial_path.as_ref().and_then(|p| data_path(data, p)) {
                    Some(v) => {
                        captured.push((state.path.clone(), v.clone()));
                        v
                    }
                    None => initial_for(&state.shape),
                }
            }
        };
        frames.push((state.path.clone(), value, None));
    }
    let mut scope = ValueScope {
        frames,
        data,
        copies: &card.copies,
    };
    let mut out = Vec::new();
    ctx.element(&root.body, &mut scope, "root", &mut out);

    let nodes = ctx.nodes;
    let truncated = ctx.truncated;
    let live_keys = std::mem::take(&mut ctx.live);
    RealizeReport {
        root: out.into_iter().next(),
        reused: 0,
        diagnostics: sink.items,
        nodes,
        truncated,
        live_keys,
        captured,
    }
}

/// Bindings introduced by loops and component props, innermost last.
/// A name bound in scope: what it is called, what it holds, and — for a loop
/// binder — where the item came from.
///
/// Named rather than left as a bare tuple because it grew a third element and
/// clippy was right that four nested types in a signature stop being readable.
type Frame = (String, serde_json::Value, Option<ItemOrigin>);

/// Which collection a loop binder iterates, and at what index.
///
/// `ItemOrigin`, not `Provenance` — that name is taken by §4's copy class, and
/// two unrelated meanings for one word in the same file is how a reader ends up
/// tracing the wrong thing.
///
/// This is what lets a backend answer a source from inside a loop: a path there
/// is rooted at the BINDER, so `m.ticker` has to be rewritten to
/// `movers.0.ticker` before it can be recognised as a source at all.
type ItemOrigin = (String, usize);

struct ValueScope<'a> {
    /// A bound name, its value, and — for a loop binder — WHERE the item came
    /// from: the source it iterates and the item's index.
    ///
    /// The provenance is what lets a backend answer a source itself from inside
    /// a loop. `m.ticker` is rooted at the binder, not at `movers`, so without
    /// this every row in a list falls back to the seeded blob while the detail
    /// view beside it goes live — which is exactly what happened.
    frames: Vec<Frame>,
    data: &'a serde_json::Value,
    copies: &'a [CopyDecl],
}

impl ValueScope<'_> {
    fn lookup(&self, path: &str) -> Option<serde_json::Value> {
        let mut segments = path.split('.');
        let root = segments.next()?;

        // `<source>.$state` is the lifecycle the runtime reported. It is data
        // like any other, so a guard can branch on it without an expression.
        if let Some(source) = path.strip_suffix(".$state") {
            // A dotted source name navigates the data, so `env.locale` looks
            // under {env: {locale: …}} rather than for a key spelled
            // "env.locale" — which is nowhere.
            let resolved = data_path(self.data, source);
            let status = self
                .data
                .get("$status")
                .and_then(|m| m.get(source))
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| {
                    // No report means: resolved if there is a value, pending if
                    // not. A host that tracks status explicitly overrides this.
                    if resolved.is_some() {
                        "ready"
                    } else {
                        "pending"
                    }
                });
            return Some(serde_json::Value::String(status.to_string()));
        }

        // `copy.<name>` is authored in the ledger, not fetched. Resolve it from
        // the card's declarations, choosing the language the runtime reported
        // and falling back to English — a card that ships zh text should not
        // render an em dash because the device is in en.
        if root == "copy" {
            let name = segments.next()?;
            let entry = self.copies.iter().find(|c| c.name == name)?;
            let lang = self
                .data
                .get("env")
                .and_then(|e| e.get("locale"))
                .and_then(|l| l.get("lang"))
                .and_then(|v| v.as_str())
                .unwrap_or("en");
            let text = entry
                .locales
                .iter()
                .find(|(k, _)| k == lang)
                .or_else(|| entry.locales.iter().find(|(k, _)| k == "en"))
                .or_else(|| entry.locales.first())?;
            return Some(serde_json::Value::String(text.1.clone()));
        }

        let mut current = match self.frames.iter().rev().find(|(n, _, _)| n == root) {
            Some((_, v, _)) => v.clone(),
            None => self.data.get(root)?.clone(),
        };
        for segment in segments {
            // `[inner]` — resolve the inner path, then index by its value.
            if let Some(inner) = segment.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                let key = self.lookup(inner)?;
                current = match &key {
                    serde_json::Value::String(k) => current.get(k.as_str())?.clone(),
                    v => current.get(v.as_u64()? as usize)?.clone(),
                };
                continue;
            }
            current = match segment.parse::<usize>() {
                Ok(index) => current.get(index)?.clone(),
                Err(_) => current.get(segment)?.clone(),
            };
        }
        Some(current)
    }
}

struct Realizer<'a> {
    card: &'a Card,
    limits: RealizeLimits,
    nodes: usize,
    /// Actual recursion depth. Previously approximated by the instance key's
    /// LENGTH, which bounded neither reliably.
    depth: usize,
    truncated: bool,
    sink: &'a mut Diagnostics,
    /// Where component-local values live. Absent means every instance sees its
    /// declared initial.
    store: Option<&'a InstanceStore>,
    /// Instance keys produced, for pruning.
    live: Vec<String>,
    /// Children passed at a component call site, realized where `slot` appears.
    /// A stack, so a component instantiated inside another's slot still sees its
    /// own children.
    slots: Vec<Vec<(String, Vec<Element>)>>,
}

impl Realizer<'_> {
    fn element(
        &mut self,
        element: &Element,
        scope: &mut ValueScope,
        key: &str,
        out: &mut Vec<UiNode>,
    ) {
        if self.nodes >= self.limits.max_nodes || self.depth >= self.limits.max_depth {
            self.truncated = true;
            return;
        }
        self.depth += 1;
        self.element_inner(element, scope, key, out);
        self.depth -= 1;
    }

    fn element_inner(
        &mut self,
        element: &Element,
        scope: &mut ValueScope,
        key: &str,
        out: &mut Vec<UiNode>,
    ) {
        match element.name.as_str() {
            "" => {}
            "slot" => {
                // Children are realized in the CALLER's scope, not the
                // component's — a child expression sees the call site's
                // bindings (§5.5). Taking the frame off the stack while
                // realizing prevents a component's own slot from re-entering.
                if let Some(groups) = self.slots.pop() {
                    // An unnamed `slot` takes the default group; `slot header`
                    // takes the group a call site directed with `into header`.
                    let wanted = element.binders.first().cloned().unwrap_or_default();
                    if let Some((_, children)) = groups.iter().find(|(n, _)| *n == wanted) {
                        for (segment, child) in sibling_segments(children) {
                            self.element(child, scope, &format!("{key}/s:{segment}"), out);
                        }
                    }
                    self.slots.push(groups);
                }
            }
            "for" => self.iteration(element, scope, key, out),
            "when" => {
                if self.guard_holds(element, scope) {
                    for (segment, child) in sibling_segments(&element.children) {
                        self.element(child, scope, &format!("{key}/w:{segment}"), out);
                    }
                }
            }
            _ if element.is_reference => {
                let card = self.card;
                match card.views.iter().find(|v| v.name == element.name) {
                    Some(view) => {
                        // Keyed by the referenced view's own name, so its nodes
                        // keep identity wherever it is spliced.
                        self.element(&view.body, scope, &format!("{key}/{}", element.name), out);
                    }
                    None => self.sink.push(
                        element.line,
                        element.column,
                        format!("{:?} is not a declared view", element.name),
                    ),
                }
            }
            name => {
                let card = self.card;
                if let Some(component) = card.components.iter().find(|c| c.name == name) {
                    self.component(component, element, scope, key, out);
                } else {
                    self.constructor(element, scope, key, out);
                }
            }
        }
    }

    fn constructor(
        &mut self,
        element: &Element,
        scope: &mut ValueScope,
        key: &str,
        out: &mut Vec<UiNode>,
    ) {
        self.nodes += 1;
        let mut node = UiNode {
            kind: element.name.clone(),
            key: key.to_string(),
            args: Vec::new(),
            children: Vec::new(),
            bindings: Vec::new(),
            exprs: Vec::new(),
        };
        for arg in &element.args {
            let value = self.value(&element.name, &arg.name, &arg.value, scope);
            if let Operand::Path(path) = &arg.value {
                if let Some(binding) = self.source_binding(path, scope) {
                    node.bindings.push((arg.name.clone(), binding));
                }
            }
            if matches!(arg.value, Operand::Expr { .. }) {
                if let Some(shape) = self.expr_shape(&arg.value, scope) {
                    node.exprs.push((arg.name.clone(), shape));
                }
            }
            node.args.push((arg.name.clone(), value));
        }
        for (segment, child) in sibling_segments(&element.children) {
            self.element(
                child,
                scope,
                &format!("{key}/{segment}"),
                &mut node.children,
            );
        }
        out.push(node);
    }

    fn component(
        &mut self,
        component: &Component,
        call: &Element,
        scope: &mut ValueScope,
        key: &str,
        out: &mut Vec<UiNode>,
    ) {
        // Props bind by name; a prop the caller omits is simply absent, and any
        // path inside the component resolves against this frame first.
        // Bind by DECLARED SHAPE. The shape was retained at parse and then
        // discarded here, which cost two bugs: an event prop was looked up as
        // data, so a state whose name collided with an event hijacked the
        // routing; and an enum token bound with its leading dot, so every
        // comparison against it inside the component was false.
        let mut bound = 0usize;
        for param in &component.params {
            let supplied = call.args.iter().find(|a| a.name == param.name);
            let value = match (supplied, &param.shape) {
                // An event names itself. It has no value in data, and looking
                // one up is how the wrong event came to fire.
                (Some(arg), Shape::Event) => match &arg.value {
                    Operand::Path(p) => serde_json::Value::String(p.clone()),
                    other => literal_of(other),
                },
                // A token is a bare member; the dot is lexical marking, not
                // part of the value.
                (Some(arg), _) => match &arg.value {
                    Operand::Token(t) => {
                        serde_json::Value::String(t.trim_start_matches('.').to_string())
                    }
                    Operand::Path(p) | Operand::Predicate { path: p, .. } => scope
                        .lookup(p)
                        .unwrap_or_else(|| serde_json::Value::String(p.clone())),
                    other => literal_of(other),
                },
                // Omitted: the declared default, or nothing. Binding a frame
                // either way is what stops lookup falling through to injected
                // data and letting the host capture an unfilled prop.
                (None, _) => param.default.clone().unwrap_or(serde_json::Value::Null),
            };
            // Carry the argument's PROVENANCE into the parameter.
            //
            // A loop binder records which collection it iterates and at what
            // index, which is what lets a row lower to a live call. Passing that
            // binder into a component — `for s in feed { StoryRow(story: s) }`,
            // the idiomatic way to factor a list — pushed the parameter frame
            // with `None`, so `story.title` inside the component had no
            // provenance and fell back to the seeded blob. A live card has no
            // blob, so every row rendered an em dash while the lead story beside
            // it, read directly as `lead.0.title`, went live.
            let provenance = match supplied.map(|a| &a.value) {
                Some(Operand::Path(p)) | Some(Operand::Predicate { path: p, .. }) => {
                    let root = p.split('.').next().unwrap_or(p);
                    scope
                        .frames
                        .iter()
                        .rev()
                        .find(|(n, _, prov)| n == root && prov.is_some())
                        .and_then(|(_, _, prov)| prov.clone())
                }
                _ => None,
            };
            scope.frames.push((param.name.clone(), value, provenance));
            bound += 1;
        }
        let instance_key = format!("{key}/{}", component.name);
        self.live.push(instance_key.clone());
        self.slots.push(split_slots(&call.children));

        // Local state resolves PER INSTANCE: from the store when it holds a
        // value for this key, otherwise from the declared initial. Two instances
        // of one component therefore never share a cell — the property the
        // component model exists to provide.
        let schema = schema_id(component);
        for state in &component.states {
            // A live cell is readable when the schema still matches, or — under
            // §5.8's opt-in — when this field asked to survive and its own shape
            // is what it was written under. The shape check is what keeps
            // `keep` from becoming the guess the reset exists to prevent.
            let live = self
                .store
                .filter(|s| {
                    s.schemas.get(&component.name).is_none_or(|k| {
                        *k == schema || state.keep && s.shape_unchanged(component, state)
                    })
                })
                .and_then(|s| s.get(&instance_key, &state.path))
                .cloned();
            let from_path = state.initial_path.as_ref().and_then(|p| scope.lookup(p));
            scope.frames.push((
                state.path.clone(),
                live.or_else(|| state.initial.clone())
                    .or(from_path)
                    .unwrap_or_else(|| initial_for(&state.shape)),
                None,
            ));
            bound += 1;
        }

        self.element(&component.body, scope, &instance_key, out);
        self.slots.pop();
        for _ in 0..bound {
            scope.frames.pop();
        }
    }

    fn iteration(
        &mut self,
        element: &Element,
        scope: &mut ValueScope,
        key: &str,
        out: &mut Vec<UiNode>,
    ) {
        let Some(Arg {
            value: Operand::Path(path),
            ..
        }) = element.args.first()
        else {
            return;
        };
        let collection = match scope.lookup(path) {
            Some(c) => c,
            // No data for this collection. If it is a SOURCE that declared how
            // many it wants, realize that many placeholder items: the card said
            // `sys.movers(count: 10)`, so ten rows is what it asked for, and a
            // backend that answers the source itself fills them in.
            //
            // Without this a card rendered with no data blob has no rows at all,
            // so nothing inside the loop is ever lowered — and a backend that
            // could have answered every field never gets asked. The count is the
            // one thing it cannot infer.
            None => match self.declared_count(path) {
                Some(n) => {
                    serde_json::Value::Array(vec![serde_json::Value::Object(Default::default()); n])
                }
                // Not a counted source: pending is the runtime's to surface, not
                // ours to invent.
                None => return,
            },
        };
        let Some(items) = collection.as_array() else {
            self.sink.push(
                element.line,
                element.column,
                format!("{path:?} is not a collection"),
            );
            return;
        };

        // §5.7: duplicate keys are an error at realization. Untracked, two items
        // with the same key produced the same instance key — one state cell
        // shared by two rows, so tapping either toggled both.
        let mut seen_keys: Vec<String> = Vec::new();

        for (index, item) in items.iter().enumerate() {
            if index >= self.limits.max_collection {
                self.truncated = true;
                break;
            }
            // The key expression is evaluated per item, and identity is the
            // enclosing key plus it — never the index.
            let item_key = element
                .key_path
                .as_deref()
                .and_then(|k| {
                    let mut segments = k.split('.');
                    segments.next()?;
                    let mut current = item.clone();
                    for segment in segments {
                        current = current.get(segment)?.clone();
                    }
                    Some(json_to_key(&current))
                })
                .unwrap_or_else(|| index.to_string());

            // Report the collision, then disambiguate so the two instances do
            // not share a cell. Rendering both with distinct identity is safer
            // than dropping one: a missing row is harder to notice than a
            // diagnostic.
            let item_key = if seen_keys.contains(&item_key) {
                self.sink.push(
                    element.line,
                    element.column,
                    format!(
                        "duplicate key {item_key:?} in this loop; keys must be unique or two \
                         instances share one state cell (profile §5.7)"
                    ),
                );
                format!("{item_key}#{index}")
            } else {
                seen_keys.push(item_key.clone());
                item_key
            };

            let mut bound = 0usize;
            if let Some(binder) = element.binders.first() {
                // The provenance a live call needs: `m.ticker` is rooted at
                // the binder, so without this every row falls back to the
                // seeded blob while the detail beside it goes live.
                scope.frames.push((
                    binder.clone(),
                    item.clone(),
                    Some((path.to_string(), index)),
                ));
                bound += 1;
            }
            if let Some(index_binder) = element.binders.get(1) {
                scope.frames.push((
                    index_binder.clone(),
                    serde_json::Value::from(index + 1),
                    None,
                ));
                bound += 1;
            }

            for (segment, child) in sibling_segments(&element.children) {
                self.element(child, scope, &format!("{key}[{item_key}]/{segment}"), out);
            }

            for _ in 0..bound {
                scope.frames.pop();
            }
        }
    }

    fn guard_holds(&mut self, element: &Element, scope: &mut ValueScope) -> bool {
        let Some(Arg {
            value: Operand::Path(path),
            ..
        }) = element.args.first()
        else {
            return false;
        };
        let left = scope.lookup(path);

        let Some(cmp) = element.cmp.as_deref() else {
            // Bare boolean guard — amendment #10.
            return matches!(left, Some(serde_json::Value::Bool(true)));
        };
        let right = element.rhs.as_ref().and_then(|r| scope_value(scope, r));
        compare(left, cmp, right)
    }

    /// If `path` roots at a declared source, what it would take to fetch.
    ///
    /// A source's own arguments are resolved here rather than passed through as
    /// paths: `sys.quote(ticker: state.selected)` becomes `ticker = "NVDA"`,
    /// because the state is known now and a backend emitting the call has no way
    /// to look it up. An argument that cannot be resolved drops the binding
    /// entirely — a fetch with a hole in it is worse than no fetch, since it
    /// would silently request the wrong thing.
    /// How many items a source said it wants, if it is a source and it said.
    ///
    /// `sys.movers(count: 10)` is the card declaring its own row count. That is
    /// the one fact a backend answering the source cannot supply for itself —
    /// it can answer field 0, field 1 and so on, but not how many to ask for.
    ///
    /// Bounded by the realization limit, because the count comes from a
    /// generated card and a card asking for ten thousand rows should get the
    /// cap rather than the request.
    /// The live call for `<source>.<field>`, when the backend answers that
    /// source itself. Used for a source argument that depends on another
    /// source, which a live card cannot resolve from data.
    /// How deep a chain of source arguments may resolve.
    ///
    /// One level was not enough. `sys.photo(cond: now.cond)` needs `now`, whose
    /// own `lat:` names `place` — so the inner resolver hit a path it would not
    /// follow, fell to a scope lookup that a live card cannot answer, and
    /// returned None. That None propagates: the OUTER binding fails too, so the
    /// photo lowered to the realized em dash and the page drew no image at all.
    /// Nothing said so, because a card with no wallpaper looks like a card whose
    /// wallpaper has not loaded.
    ///
    /// Capped rather than unbounded: a card's sources form a DAG, but the checker
    /// does not prove acyclicity of ARGUMENTS, and a cycle here would recurse
    /// until the stack ran out.
    const MAX_SOURCE_CHAIN: usize = 4;

    fn nested_source_call(&self, path: &str, scope: &ValueScope) -> Option<String> {
        self.nested_source_call_at(path, scope, 0)
    }

    fn nested_source_call_at(
        &self,
        path: &str,
        scope: &ValueScope,
        depth: usize,
    ) -> Option<String> {
        let (owner, field) = path.split_once('.')?;
        let declaration = self.card.sources.iter().find(|s| s.name == owner)?;
        let mut args = Vec::new();
        for (name, arg) in &declaration.args {
            let resolved = match arg {
                // Shortest round-trip, NOT `trim_num` — see `source_binding`.
                SourceArg::Number(n) => format!("{n}"),
                SourceArg::Text(t) => t.clone(),
                SourceArg::List(_) if name == "fields" => continue,
                // A list of PATHS resolves item by item, each to its own live
                // call, joined by a separator no call can contain.
                //
                // `sys.route(via: [stop.0.lat, stop.0.lon])` is how a trip names a
                // waypoint. Joining the raw items gave the helper the literal text
                // "stop.0.lat,stop.0.lon", which is not a coordinate, so the
                // argument was discarded and the route was computed WITHOUT the
                // stop — a card that let the user add one, drew a line that did
                // not go through it, and reported the direct trip's time.
                //
                // U+0001 rather than a comma, because a resolved call contains
                // commas of its own: `sys.searchnum("A", 0, "lat")`.
                SourceArg::List(items) => items
                    .iter()
                    .map(|item| {
                        let key = item.strip_prefix("state.").unwrap_or(item);
                        match self.nested_source_call(key, scope) {
                            Some(call) => call,
                            None => scope
                                .lookup(key)
                                .map(|v| json_to_key(&v))
                                .unwrap_or_else(|| item.clone()),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\u{1}"),
                // A parent's own argument is usually card STATE — the weather
                // fixture reads `sys.geocode(name: state.city)` — so it resolves
                // from the scope like any other path. Returning None here
                // instead meant the whole chain died at the first hop and every
                // reading below it stayed seeded.
                //
                // One level only: a path that names yet another SOURCE is not
                // resolved here, which is what keeps this from recursing.
                SourceArg::Path(p) => {
                    let key = p.strip_prefix("state.").unwrap_or(p);
                    // THE SOURCE FIRST, then the scope — the same precedence
                    // `source_binding` argues for, and for the same reason: a
                    // live card carries no blob, so a scope-first resolution
                    // silently produces a different lowering than a previewed one.
                    match (depth + 1 < Self::MAX_SOURCE_CHAIN)
                        .then(|| self.nested_source_call_at(key, scope, depth + 1))
                        .flatten()
                    {
                        Some(call) => call,
                        None => json_to_key(&scope.lookup(key)?),
                    }
                }
            };
            args.push((name.clone(), resolved));
        }
        makepad::vm_call(&SourceBinding {
            helper: declaration.helper.clone(),
            args,
            // Empty by construction: this is the ONE-LEVEL resolver, and the
            // comment above says why — a path naming yet another source is not
            // followed here, so no argument of this call is itself a call.
            nested: Vec::new(),
            field: field.to_string(),
        })
    }

    /// How many rows a loop over this source should realize before its data
    /// arrives.
    ///
    /// This matched an argument named `count` holding a bare literal, and missed
    /// the case that ships: a weather card asks `sys.weather(days: state.days)`
    /// with `state days { initial: 7 }`. The argument is called `days`, and it is
    /// a PATH rather than a literal — so a seven-day forecast realized zero rows
    /// and the card drew current conditions and nothing else. "Beijing week
    /// weather" gave one day.
    ///
    /// Both names, because `count` and `days` are the same question asked of
    /// different capabilities, and a path resolved from its declared initial,
    /// because that value is known at realization — it is the card's own state,
    /// not something the host has to send.
    fn declared_count(&self, path: &str) -> Option<usize> {
        // The loop's path may name the source or a COLLECTION FIELD of it:
        // `for m in movers` and `for d in week.days` are both loops over a
        // counted source, and matching only the bare name meant the second found
        // nothing. That is the weather card's forecast, which is the one that
        // ships.
        let root = root_of(path);
        let declaration = self
            .card
            .sources
            .iter()
            .find(|s| s.name == path || s.name == root)?;
        let (_, arg) = declaration
            .args
            .iter()
            .find(|(n, _)| n == "count" || n == "days")?;
        let n = match arg {
            SourceArg::Number(n) => *n,
            // `days: state.days` — a cursor into the card's own state, whose
            // declared initial is the number the fetch will be asked for.
            SourceArg::Path(p) => {
                let key = p.strip_prefix("state.").unwrap_or(p);
                let state = self.card.states.iter().find(|s| s.path == key)?;
                state.initial.as_ref().and_then(|v| v.as_f64())?
            }
            _ => return None,
        };
        (n >= 1.0).then(|| (n as usize).min(self.limits.max_collection))
    }

    /// Resolve an expression into live calls and constants.
    ///
    /// A `Path` the backend can answer becomes a call; anything else becomes the
    /// value realization already resolved. Returning `None` for an operand that
    /// resolves to nothing keeps a half-resolved expression from lowering — it
    /// renders as the missing binding it is.
    fn expr_shape(&self, operand: &Operand, scope: &ValueScope) -> Option<ExprPart> {
        match operand {
            Operand::Expr { lhs, op, rhs } => Some(ExprPart::Bin(
                Box::new(self.expr_shape(lhs, scope)?),
                op.clone(),
                Box::new(self.expr_shape(rhs, scope)?),
            )),
            // FULL PRECISION, not `trim_num`. `trim_num` is a DISPLAY rule — one
            // decimal, because a temperature reads as 21.4 and not 21.437 — and an
            // operand is not a display. Rounding one silently changes the
            // arithmetic: measured on device, a converter card declaring
            // `factor 0.621371` lowered to `(42 * 0.6)` and drew 42 km as 25.2
            // miles instead of 26.1. The card was right, the checker accepted it,
            // and the number on screen was wrong — which is the whole failure
            // class §1.1 exists to prevent.
            //
            // `{}` on an f64 is the shortest representation that round-trips, so
            // 42.0 still emits `42` and nothing gains spurious digits.
            Operand::Num(n) => Some(ExprPart::Const(format!("{n}"))),
            Operand::Path(p) => match self.source_binding(p, scope) {
                Some(binding) => Some(ExprPart::Call(binding)),
                None => {
                    let v = scope.lookup(p)?;
                    Some(ExprPart::Const(format!("{}", v.as_f64()?)))
                }
            },
            _ => None,
        }
    }

    fn source_binding(&self, path: &str, scope: &ValueScope) -> Option<SourceBinding> {
        // Inside a `for`, a path is rooted at the BINDER: `m.ticker`, not
        // `movers.0.ticker`. The binder's frame records which collection it
        // iterates and at what index, so rewrite through it first.
        //
        // Without this every row of a list falls back to the seeded value while
        // the detail view beside it goes live — which is precisely what the
        // stock card did, and it looks like the list is simply stale.
        let (root, rest) = path.split_once('.').unwrap_or((path, ""));
        let rewritten = scope
            .frames
            .iter()
            .rev()
            .find(|(n, _, prov)| n == root && prov.is_some())
            .and_then(|(_, _, prov)| prov.as_ref())
            .map(|(collection, index)| {
                if rest.is_empty() {
                    format!("{collection}.{index}")
                } else {
                    format!("{collection}.{index}.{rest}")
                }
            });
        let path = rewritten.as_deref().unwrap_or(path);

        // `env.locale.lang` roots at the source `env.locale`, not at `env`, so
        // match the LONGEST declared name that prefixes the path.
        let declaration = self
            .card
            .sources
            .iter()
            .filter(|s| path == s.name || path.starts_with(&format!("{}.", s.name)))
            .max_by_key(|s| s.name.len())?;

        let mut args = Vec::new();
        let mut nested: Vec<String> = Vec::new();
        for (name, arg) in &declaration.args {
            let resolved = match arg {
                SourceArg::Path(p) => {
                    // `state.x` in a source argument addresses card state; the
                    // view scope names it without the prefix.
                    let key = p.strip_prefix("state.").unwrap_or(p);
                    // A source argument that names ANOTHER SOURCE resolves to
                    // that source's own live call — `sys.places(lat: place.lat)`
                    // depends on `place`, and the dependency is exactly what L0
                    // declares, so it is emitted the way the backend will read it.
                    //
                    // THE SOURCE IS TRIED FIRST, and the order is the whole point.
                    // It used to be the other way round: the scope was consulted
                    // and the live call was the fallback for when the lookup found
                    // nothing. A live card carries no data blob, so on a device
                    // that path was taken and everything worked — and a card
                    // previewed against seed data lowered the SEED into the
                    // argument instead. Two different lowerings of one card,
                    // selected by whether a blob happened to carry the key.
                    //
                    // It surfaced on `sys.step(at_lat: here.lat)`: the progress a
                    // turn instruction is computed from lowered to `37.3`, a fixed
                    // point on the map, so every instruction was the first one
                    // forever. The seeded fix is the one value a navigation card
                    // must never be allowed to keep.
                    match self.nested_source_call(key, scope) {
                        Some(call) => {
                            // Remembered, because a backend cannot tell a call
                            // from a value once both are strings — and a TEXT
                            // slot has to quote one and not the other. See
                            // `SourceBinding::nested`.
                            nested.push(name.clone());
                            call
                        }
                        None => json_to_key(&scope.lookup(key)?),
                    }
                }
                SourceArg::Text(t) => t.clone(),
                // Shortest round-trip, NOT `trim_num`. That is a one-decimal
                // DISPLAY rule, and an ARGUMENT is not a display: it rounded
                // `sys.weather(lat: 37.7749)` to `37.8`, which is a different
                // city. Same class as the L1 operand it rounded to 0.6.
                SourceArg::Number(n) => format!("{n}"),
                // `fields:` is structural — which keys the card wants back — and
                // is not passed on. Any OTHER list is a value: `symbols: [NVDA,
                // AMD]` is the universe to rank, and the model writes it as a
                // list because every other list-shaped argument is one. Dropping
                // it silently left the card ranking the whole market under
                // whatever title it had been given.
                SourceArg::List(_) if name == "fields" => continue,
                // A list of PATHS resolves item by item, each to its own live
                // call, joined by a separator no call can contain.
                //
                // `sys.route(via: [stop.0.lat, stop.0.lon])` is how a trip names a
                // waypoint. Joining the raw items handed the helper the literal
                // text "stop.0.lat,stop.0.lon", which is not a coordinate, so the
                // argument was discarded and the route computed WITHOUT the stop:
                // a card that let the user add one, drew a line that did not pass
                // through it, and reported the direct trip's time.
                //
                // U+0001 rather than a comma, because a resolved call contains
                // commas of its own — `sys.searchnum("A", 0, "lat")`. See
                // `makepad::via_string`, which reads it back.
                //
                // A list of plain VALUES still joins with a comma: `symbols: [NVDA,
                // AMD]` is a universe to rank, and neither item resolves to a call.
                SourceArg::List(items) => {
                    let resolved: Vec<String> = items
                        .iter()
                        .map(|item| {
                            let key = item.strip_prefix("state.").unwrap_or(item);
                            self.nested_source_call(key, scope)
                                .or_else(|| scope.lookup(key).map(|v| json_to_key(&v)))
                        })
                        .collect::<Option<Vec<_>>>()
                        .unwrap_or_default();
                    if resolved.len() == items.len() {
                        resolved.join("\u{1}")
                    } else {
                        items.join(",")
                    }
                }
            };
            args.push((name.clone(), resolved));
        }
        // The field a helper is asked for is `<index>.<name>` for a row of a
        // collection, and the COLLECTION'S OWN NAME is not part of it.
        //
        // `for d in week.days` gives a binder whose provenance is the collection
        // `week.days`, so the rewrite above produces `week.days.3.cond` — which
        // is the right path for looking the value up in seeded data and the wrong
        // one to hand a helper, which wants `3.cond`. Left in, every forecast row
        // failed to translate and fell back to the realized default: seven rows
        // of the same icon and an em dash where each day's high should be.
        //
        // Only a segment that is not an index is dropped, and only when an index
        // follows it — `week.min_lo` is an aggregate on the source itself and has
        // no row.
        let mut field = path
            .strip_prefix(&declaration.name)
            .unwrap_or_default()
            .trim_start_matches('.')
            .to_string();
        if let Some((head, rest)) = field.clone().split_once('.') {
            let head_is_index = head.chars().all(|c| c.is_ascii_digit()) && !head.is_empty();
            let rest_starts_with_index = rest
                .split('.')
                .next()
                .is_some_and(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()));
            if !head_is_index && rest_starts_with_index {
                field = rest.to_string();
            }
        }
        Some(SourceBinding {
            helper: declaration.helper.clone(),
            args,
            nested,
            field,
        })
    }

    fn value(
        &mut self,
        ctor: &str,
        arg: &str,
        operand: &Operand,
        scope: &mut ValueScope,
    ) -> NodeValue {
        // An event argument carries a declared NAME through to the runtime,
        // which binds it at dispatch. Nothing about it is looked up in data, and
        // nothing about it is constructed by the card.
        let is_event = catalog::lookup(ctor)
            .and_then(|args| args.iter().find(|(n, _)| *n == arg))
            .is_some_and(|(_, k)| matches!(k, catalog::ArgKind::Event));
        if is_event {
            if let Operand::Path(p) = operand {
                // Through a component prop the name arrives bound; directly it
                // is the path itself.
                return match scope.lookup(p) {
                    Some(serde_json::Value::String(name)) => NodeValue::Event(name),
                    _ => NodeValue::Event(p.clone()),
                };
            }
        }
        match operand {
            Operand::Token(t) => NodeValue::Token(t.trim_start_matches('.').to_string()),
            Operand::Str(s) => NodeValue::Text(s.clone()),
            Operand::Num(n) => NodeValue::Number(*n),
            Operand::Predicate { path, cmp, rhs } => {
                NodeValue::Bool(compare(scope.lookup(path), cmp, scope_value(scope, rhs)))
            }
            Operand::Expr { lhs, op, rhs } => match eval_expr(scope, lhs, op, rhs) {
                Some(v) => match v.as_f64() {
                    Some(n) => NodeValue::Number(n),
                    None => NodeValue::Missing,
                },
                None => NodeValue::Missing,
            },
            Operand::Path(p) => match scope.lookup(p) {
                Some(serde_json::Value::String(s)) => NodeValue::Text(s),
                Some(serde_json::Value::Bool(b)) => NodeValue::Bool(b),
                Some(v) => match v.as_f64() {
                    Some(n) => NodeValue::Number(n),
                    None => NodeValue::Missing,
                },
                None => NodeValue::Missing,
            },
        }
    }
}

fn json_to_key(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ──────────────────────────────────────────────────────── makepad text lowering ──

/// Lower a realized tree to the Splash DSL a Makepad host renders.
///
/// **This is one backend's lowering and belongs in Splash-Makepad**, not here. It
/// lives beside the node model only until that crate is wired up; nothing in
/// [`realize`] depends on it, and a different backend consumes [`UiNode`]
/// directly rather than going through text.
///
/// The output is fully concrete: realization already substituted the runtime's
/// data, so the DSL carries values rather than `sys.*` calls. That is the ledger
/// discipline holding — the card declares questions, and only the *realized
/// output* contains answers.
pub mod makepad {
    use super::{ExprPart, NodeValue, SourceBinding, UiNode};
    use std::fmt::Write as _;

    // Matching octos-one's `plan/common.rs`, so a lowered card sits beside the
    // existing ones rather than looking like a different app.
    const BASE: &str = "#0a0e14";
    const SCRIM: &str = "#00000066";
    const PANEL: &str = "#ffffff12";
    /// A selected chip. Brighter than PANEL so "which one is active" is legible
    /// at a glance rather than a subtle tint.
    const ACTIVE: &str = "#ffffff38";
    const HAIRLINE: &str = "#ffffff1a";
    const TEXT: &str = "#ffffff";
    const SOFT: &str = "#ffffffe6";
    const DIM: &str = "#ffffff99";
    const UP: &str = "#32d74b";
    const DOWN: &str = "#ff453a";
    const PAGE_PAD: &str = "Inset{left: 20 top: 54 right: 20 bottom: 24}";

    pub fn lower(root: &UiNode) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "// name: l0-card");
        let _ = writeln!(out, "// REALIZED from an L0 ledger — do not edit.");
        element(root, 0, &mut out);
        out
    }

    /// The tap binding for a node that declares `on_tap`.
    ///
    /// `UiNode` carried the event name and the instance key all along and
    /// lowering emitted neither, so every Row, Card, Chip and TextHero rendered
    /// inert: the stock range controls could not reach `dispatch` at all. The
    /// key is what lets a tap name WHICH instance was hit, which is the whole
    /// basis of §5.1 identity.
    fn tap_binding(node: &UiNode) -> String {
        let Some(NodeValue::Event(event)) = arg(node, "on_tap") else {
            return String::new();
        };
        let mut out = format!(" l0_event: {event:?} l0_key: {:?}", node.key);
        // `value:` is the payload the event carries — `$value` at the receiving
        // transition. Without it a tap says "this happened" but not "to what".
        match arg(node, "value") {
            Some(NodeValue::Text(t)) => out.push_str(&format!(" l0_value: {t:?}")),
            Some(NodeValue::Number(n)) => out.push_str(&format!(" l0_value: {:?}", trim_num(*n))),
            Some(NodeValue::Token(t)) => out.push_str(&format!(" l0_value: {t:?}")),
            _ => {}
        }
        out
    }

    fn arg<'a>(node: &'a UiNode, name: &str) -> Option<&'a NodeValue> {
        node.args.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// A `TokenOrPath` argument, whichever it turned out to be.
    ///
    /// `unit`, `width`, `view`, `controls` and `range` each admit a token OR a path
    /// to card state, and REALIZE ERASES THE DIFFERENCE: `view: .tilted` survives as
    /// `Token("tilted")`, while `view: view` reading `.tilted` out of the state
    /// arrives as `Text("tilted")`. A reader that matches only `Token` therefore sees
    /// nothing whenever the card chose the state form and silently takes its default.
    ///
    /// That is what broke the nav card's on-map 2D/3D switch. The chip relabelled on
    /// every tap because its own guard reads the state directly, so the toggle looked
    /// live — but `view` reached the lowering as `Text` and the camera stayed flat on
    /// both settings. A control that responds and changes nothing is worse than one
    /// that is missing; the screen asserts the camera tilted and it did not.
    ///
    /// Every `TokenOrPath` read goes through here so the class cannot come back one
    /// argument at a time.
    fn token_arg<'a>(node: &'a UiNode, name: &str) -> Option<&'a str> {
        match arg(node, name) {
            Some(NodeValue::Token(t) | NodeValue::Text(t)) => Some(t.as_str()),
            _ => None,
        }
    }

    /// A value in text position. `Missing` becomes an em dash rather than an
    /// empty string, so an unresolved binding is visible on screen instead of
    /// silently rendering a blank field.
    /// What to emit for an argument: a LIVE call where the backend can answer
    /// the source itself, the realized literal otherwise.
    ///
    /// This is the difference between a card that shows whatever the host
    /// happened to seed and one that shows what is true now. Realization already
    /// resolved the value; `bindings` records where it came from, so a backend
    /// with its own fetch can go and get it instead.
    ///
    /// Falling back is not a failure mode to be minimised — `sys.quote` exposes
    /// no market cap or P/E, so those two lower to the seeded value and always
    /// will. Emitting a call the VM cannot answer would render an em dash where
    /// a real number was available.
    pub(super) fn expr_of(node: &UiNode, arg_name: &str) -> String {
        if let Some((_, shape)) = node.exprs.iter().find(|(n, _)| n == arg_name) {
            if let Some(rendered) = render_expr(shape) {
                return rendered;
            }
        }
        if let Some((_, binding)) = node.bindings.iter().find(|(n, _)| n == arg_name) {
            if let Some(call) = vm_call(binding) {
                return call;
            }
        }
        text_of(arg(node, arg_name))
    }

    /// An `ExprPart` as backend arithmetic. Parenthesised at every join, so the
    /// tree's shape survives regardless of the target VM's precedence rules.
    pub(super) fn render_expr(part: &ExprPart) -> Option<String> {
        match part {
            ExprPart::Const(v) => Some(v.clone()),
            // A live call is COERCED. Every `sys.*` helper answers with a
            // string, because a string is what a card renders and what
            // concatenation composes — `"$" + sys.stock(…)` is how every live
            // value reaches the screen. Arithmetic needs the other thing, and
            // string subtraction evaluates to NaN: measured on device, an L1
            // card drew "≈NaN°" in every row while every other value on the same
            // row was correct.
            //
            // The coercion is emitted here rather than assumed of the helpers,
            // because L1 can ask for arithmetic over any numeric field of any
            // capability and the helpers cannot all change shape for it.
            ExprPart::Call(binding) => vm_call(binding).map(|c| format!("sys.num({c})")),
            ExprPart::Bin(lhs, op, rhs) => Some(format!(
                "({} {op} {})",
                render_expr(lhs)?,
                render_expr(rhs)?
            )),
        }
    }

    /// Which member of the map family a `Map` is, in the WIDGET's vocabulary.
    ///
    /// Shared by both lowerings rather than written twice. Two backends that
    /// each decide independently what `.drive` means is the shape of every
    /// defect this profile keeps finding.
    pub(super) fn map_mode(node: &UiNode) -> &'static str {
        match arg(node, "mode") {
            // `.drive` means the chase camera EXACTLY WHEN the card declared a
            // live position for it to follow, and the static preview otherwise.
            // This is a §4 rule, not a performance compromise.
            //
            // Following needs a position that updates as the user moves. L0 has
            // no loop to supply one — that is what `fn tick()` is for, and
            // `fn tick()` is L2 — so an earlier version lowered BOTH moving modes
            // to the one that does not move. Handed a route and no position, the
            // widget animates along the polyline on a timer: it draws motion the
            // user is not making, which is a fabricated fact in the one currency
            // a map trades in, and §4 does not stop applying because the invented
            // value is a camera pose.
            //
            // It is also what made the card stutter: the widget's settle gate
            // exists because a map that keeps asking for frames "was pinning the
            // GPU at ~100%", and a timer-driven follow is permanently in motion
            // so it never settles. Measured at 69% CPU and 1.9 GB resident on a
            // OnePlus 6 for one card holding one map.
            //
            // `at:` is that missing declaration — a source answering `lat`/`lon`,
            // in practice `sys.gps`. With it, the camera follows a MEASUREMENT:
            // the frames are the ones the fix earns, so the map settles whenever
            // the user is standing still, and nothing is invented. Without it the
            // old argument holds unchanged, so a card that asks to drive and
            // declares no position still gets the honest preview.
            // `"follow"`, NOT the widget's `"2d"`. They render the same
            // projection and differ in where the camera comes from: `"2d"` drives
            // a simulated vehicle along the route at an assumed speed off a
            // looping clock, which is the fabrication this whole rule exists to
            // refuse — and a convincing one, because it looks exactly like
            // navigating. `"follow"` takes the position the card declared.
            Some(NodeValue::Token(t)) if t == "drive" && live_position(node).is_some() => {
                // Tilted is the shipping app's driving view (R8.1); flat is its
                // 2D alternative. Both follow the DECLARED position — the widget's
                // own `3d` mode drives a simulated vehicle, and pointing either of
                // these at it would reintroduce exactly the fabrication this rule
                // exists to refuse.
                match token_arg(node, "view") {
                    Some("tilted") => "follow3d",
                    _ => "follow",
                }
            }
            Some(NodeValue::Token(t)) if t == "drive" || t == "plan" => "plan",
            // `flat` and an unstated mode are the same thing to the widget: no
            // nav shader at all, which also means no route ribbon.
            _ => "",
        }
    }

    /// One axis of a `Map` endpoint, as a live call.
    ///
    /// An endpoint names a SOURCE rather than coordinates, so each is asked for
    /// its own axis — `at: here` becomes `sys.gps("lat")` and `sys.gps("lon")`.
    fn map_coord(node: &UiNode, name: &str, axis: &str) -> Option<String> {
        // An explicit `from_lat:`/`from_lon:` wins, because a card that supplied one
        // meant it: it is naming a position no search would find. Card state resolves
        // to a number at realize time, which is exactly what captured coordinates are.
        let direct = format!("{name}_{axis}");
        if let Some((_, b)) = node.bindings.iter().find(|(n, _)| *n == direct) {
            if let Some(call) = vm_call(b) {
                return Some(call);
            }
        }
        if let Some(NodeValue::Number(n)) = arg(node, &direct) {
            // FULL PRECISION, not `trim_num`. That formats to one decimal place,
            // which is right for a zoom level or a gap and catastrophic for a
            // coordinate: 37.2656 became 37.3, about 11 km at this latitude. The
            // route drew from a place a quarter of the way to San Francisco and
            // looked entirely plausible doing it.
            return Some(format!("{n}"));
        }
        let (_, binding) = node.bindings.iter().find(|(n, _)| n == name)?;
        // A collection answers `0.lat` and a scalar source answers `lat`.
        for field in [axis.to_owned(), format!("0.{axis}")] {
            let probe = SourceBinding {
                field,
                ..binding.clone()
            };
            if let Some(call) = vm_call(&probe) {
                return Some(call);
            }
        }
        None
    }

    /// A `Map`'s waypoints, as the route helpers' `lat,lon;lat,lon` argument.
    ///
    /// `via:` on a `Map` names a source the same way `from:`/`to:` do, so each axis
    /// is asked for separately and the pair is assembled by `via_string`. A source
    /// that cannot answer a coordinate yields no vias, because a map drawn through
    /// a place that could not be resolved is a map of a different trip.
    pub(super) fn map_vias(node: &UiNode) -> Option<String> {
        let mut pairs: Vec<String> = Vec::new();
        for slot in ["via", "via2"] {
            let (Some(lat), Some(lon)) =
                (map_coord(node, slot, "lat"), map_coord(node, slot, "lon"))
            else {
                continue;
            };
            pairs.push(lat);
            pairs.push(lon);
        }
        if pairs.is_empty() {
            return None;
        }
        via_string(&pairs.join("\u{1}"))
    }

    /// The live position a `Map` was told to follow, if it was told one.
    ///
    /// This is the whole difference between a camera that reports where the user
    /// is and one that invents it — see `map_mode`. Both axes must resolve: half
    /// a fix is not a position.
    pub(super) fn live_position(node: &UiNode) -> Option<(String, String)> {
        Some((map_coord(node, "at", "lat")?, map_coord(node, "at", "lon")?))
    }

    /// A `Map`'s centre and route, as live calls: `(lat, lon, polyline)`.
    ///
    /// The centre is the live position when one was declared, and the route's
    /// start otherwise — a driving map is centred on the driver, a planning map
    /// on the trip. An endpoint whose capability cannot answer a coordinate
    /// yields a neutral centre and no route, because a map drawn from a seeded
    /// position is a map of somewhere the user is not.
    pub(super) fn map_route(node: &UiNode) -> (String, String, String) {
        let coord = |name: &str, axis: &str| map_coord(node, name, axis);
        let (Some(a), Some(o)) = (coord("from", "lat"), coord("from", "lon")) else {
            return ("0".into(), "0".into(), "\"\"".into());
        };
        // The WAYPOINTS the trip passes through, as the helper's sixth argument.
        //
        // A map that omits them draws a different journey from the one the card
        // reports beside it: the line goes straight from origin to destination
        // while the duration and distance are for a route through the stop. Both
        // halves come from the same list now, rendered the same way — see
        // `via_string`.
        let vias = map_vias(node);
        let poly = match (coord("to", "lat"), coord("to", "lon")) {
            (Some(b), Some(p)) => match &vias {
                Some(v) => format!("sys.navroute({a}, {o}, {b}, {p}, \"polyline\", {v})"),
                None => format!("sys.navroute({a}, {o}, {b}, {p}, \"polyline\")"),
            },
            _ => "\"\"".to_owned(),
        };
        // The route is always the declared trip; only the CENTRE moves to the
        // driver. Centring on the fix without keeping the trip's endpoints would
        // redraw the route from wherever the user happens to be, which is a
        // different trip from the one the card states.
        match live_position(node) {
            Some((at_lat, at_lon)) => (at_lat, at_lon, poly),
            None => (a, o, poly),
        }
    }

    /// A `via:` list, as the route helpers' `lat,lon;lat,lon` argument.
    ///
    /// The items arrive already resolved to live calls and U+0001-separated (see
    /// `source_binding`), in coordinate PAIRS. An odd count is a card that named
    /// half a waypoint, and half a coordinate is not a place — so it yields no
    /// vias rather than a route through the equator.
    ///
    /// The result is a VM expression, not a string: every coordinate is a call, so
    /// the separators are concatenated around them at evaluation time. The leading
    /// `""` is what makes the first `+` a string concatenation rather than an
    /// addition of two numbers — without it a stop at 37,-122 became -85.
    /// The PINS a map stands on the route it draws: origin, each stop, destination.
    ///
    /// Built from the same coordinates as the polyline, and that is the point. The
    /// L2 card composed this string by hand and pushed it with
    /// `ui.<id>.set_route_markers(mk)`; deriving it here from the SAME resolved
    /// endpoints means the pins cannot land somewhere the line does not go.
    ///
    /// `None` when there is no complete trip — a lone origin pin on a map with no
    /// route reads as a dropped destination rather than a route still arriving.
    /// The two lines of a route's badge — its duration over its distance.
    ///
    /// Joined by `\u{1}` here rather than composed by the card, for the same reason
    /// the pin string is: it is a payload the widget parses, not text anyone reads
    /// as written. The card names WHICH trip; both halves come from that one source,
    /// so the bubble cannot describe a different journey from the line under it.
    pub(super) fn map_badge(node: &UiNode) -> Option<String> {
        let (_, binding) = node.bindings.iter().find(|(n, _)| n == "summary")?;
        let field = |f: &str| {
            vm_call(&SourceBinding {
                field: f.to_owned(),
                ..binding.clone()
            })
        };
        let (Some(dur), Some(dist)) = (field("duration"), field("distance")) else {
            return None;
        };
        // A PRINTABLE separator. `\u{1}` is the obvious choice and does not survive:
        // emitted through `{:?}` it becomes the six characters `\u{1}` in the DSL,
        // which the VM hands to the widget as literal text, so the split never fires
        // and both facts render as one run. A pipe cannot occur in a duration or a
        // distance and survives every hop as itself.
        Some(format!("{dur} + \"|\" + {dist}"))
    }

    pub(super) fn map_pins(node: &UiNode) -> Option<String> {
        // A CHASE map gets none, and this is not a preference.
        //
        // R3.12 is a plan-screen requirement: pins mark the ends of a route you are
        // looking at. A follow camera already draws the driver's puck, and in 3D the
        // widget appends pin geometry to the ribbon rather than drawing it
        // separately — measured on device, a follow3d map handed markers rendered
        // NO route and NO tiles at all, a blank beige screen. The plan map with the
        // same pins was fine, which is how it went unnoticed: I verified pins on the
        // screen the requirement is about and not on the other one.
        if live_position(node).is_some() {
            return None;
        }
        let coord = |name: &str, axis: &str| map_coord(node, name, axis);
        let (a, o) = (coord("from", "lat")?, coord("from", "lon")?);
        let (b, p) = (coord("to", "lat")?, coord("to", "lon")?);
        // kind 0 origin, 1 a stop, 2 the destination — the widget's own encoding.
        let mut out = format!("\"\" + {a} + \",\" + {o} + \",0\"");
        // The same resolution the polyline's waypoints use, so a stop that routes
        // through gets a pin and one that does not, does not — for both slots.
        for slot in ["via", "via2"] {
            if let (Some(vlat), Some(vlon)) = (coord(slot, "lat"), coord(slot, "lon")) {
                let _ = write!(out, " + \";\" + {vlat} + \",\" + {vlon} + \",1\"");
            }
        }
        let _ = write!(out, " + \";\" + {b} + \",\" + {p} + \",2\"");
        Some(out)
    }

    pub(super) fn via_string(joined: &str) -> Option<String> {
        let parts: Vec<&str> = joined.split('\u{1}').filter(|p| !p.is_empty()).collect();
        if parts.len() < 2 || !parts.len().is_multiple_of(2) {
            return None;
        }
        let mut out = String::from("\"\"");
        for (i, pair) in parts.chunks(2).enumerate() {
            if i > 0 {
                out.push_str(" + \";\"");
            }
            let _ = write!(out, " + {} + \",\" + {}", pair[0], pair[1]);
        }
        Some(out)
    }

    /// The VM helper that answers a declared capability, if one does.
    ///
    /// The names differ because the two vocabularies were designed apart: L0
    /// says `sys.quote(ticker:)` and the VM says `sys.stock(symbol, key)`. This
    /// table is the whole of the translation, and a helper or field missing from
    /// it means the seeded value is used — never a wrong call.
    /// Public so a conformance test can ask, per capability and field, whether
    /// this backend answers at all — the check §4 says is owed and that no test
    /// comparing Splash with itself can perform.
    /// The condition as the ICON's NUMBER, not as the reader's word.
    ///
    /// `cond` has two consumers and they need different things. A `TextRow` wants
    /// "Rain"; `WeatherIcon` wants the WMO code, and the kit says so in as many
    /// words — "`cond` is a NUMBER — the WMO code the forecast returns". The field
    /// lowered to `sys.weatherword` for both, so the icon was handed a string,
    /// coerced it to 0, and drew the SUN. Every icon, in every weather card, over
    /// a Beijing forecast reading 92 % rain.
    ///
    /// `vm_call` cannot tell them apart — a `SourceBinding` carries no consumer —
    /// but the ROLE does, and the kit lowering knows the role. Same path as
    /// `weatherword` deliberately: a card may show the word beside the icon, and
    /// two readings of one sky that disagree is worse than either being wrong.
    pub(super) fn icon_call(binding: &SourceBinding) -> Option<String> {
        if binding.helper != "sys.weather" {
            return None;
        }
        let (row, field) = match binding.field.split_once('.') {
            Some((i, f)) if i.parse::<u32>().is_ok() => (i, f),
            _ => ("0", binding.field.as_str()),
        };
        if field != "cond" {
            return None;
        }
        // The same day shift the weather arm applies — one sky, described once.
        let day: u32 = binding
            .args
            .iter()
            .find(|(n, _)| n == "day")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0);
        let row = &format!("{}", row.parse::<u32>().unwrap_or(0) + day);
        let num = |name: &str| -> Option<String> {
            let v = binding
                .args
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())?;
            (v.starts_with("sys.") || v.trim().parse::<f64>().is_ok()).then_some(v)
        };
        let lat = num("lat")?;
        let lon = num("lon")?;
        Some(format!(
            "sys.weathercond({lat}, {lon}, {:?})",
            format!("daily.weather_code.{row}")
        ))
    }

    pub fn vm_call(binding: &SourceBinding) -> Option<String> {
        let arg = |name: &str| {
            binding
                .args
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        // An argument bound for a NUMERIC position, or nothing.
        //
        // A numeric slot is interpolated UNQUOTED — `sys.weather({lat}, {lon}, …)` —
        // so whatever lands there is code. A string slot is safe by construction
        // because `{:?}` quotes it; this is the other half.
        //
        // Without it, `sys.weather(lat: "1 + sys.navsecs(1)")` passed the checker as a
        // perfectly ordinary L0 card and lowered to `sys.weather(1 + sys.navsecs(1),
        // …)`: arithmetic and a host call the card never declared, in a language whose
        // defining property is that it HAS no expression form. Found in review.
        //
        // Two things may appear here. A call this lowering generated, which is ours
        // and is trusted; and a literal number. Anything else is a card trying to
        // write code into a slot for a coordinate, and yields no translation at all —
        // the same outcome as an unknown field, so the value stays seeded rather than
        // becoming an injection site.
        let num = |name: &str| -> Option<String> {
            let v = arg(name)?;
            (v.starts_with("sys.") || v.trim().parse::<f64>().is_ok()).then_some(v)
        };
        // A TEXT slot, and the other half of `num`. A string slot is NOT safe by
        // construction after all: `{:?}` quotes whatever it is handed, and what
        // it was handed may be a nested CALL. `sys.photo(query: place.name)`
        // lowered to `sys.photo("sys.geocode(\"kyoto\", \"name\")")`, so the
        // wallpaper was generated from the text of the call rather than from the
        // place. Measured on the 6T — the fetched URL was
        // `image.pollinations.ai/prompt/sys.geocode%28%22ushuaia%22…`.
        //
        // It survived because it LOOKED right: the service is a generative image
        // model and the place name is inside the string it was given, so a card
        // asking for Kyoto still got a picture of Kyoto.
        //
        // `binding.nested` decides, not the shape of the string. A text argument
        // can carry what a person typed — `sys.video(query: state.q)` is the
        // search box — so "starts with `sys.`" would make a typed query
        // executable, which is the one thing this must not do.
        let text = |name: &str| -> Option<String> {
            let v = arg(name)?;
            Some(if binding.nested.iter().any(|n| n == name) {
                v
            } else {
                format!("{v:?}")
            })
        };
        match binding.helper.as_str() {
            // THE FOUR THAT ANSWERED NOTHING. Each is in the catalog, so a card may
            // declare it and the checker accepts it — and each fell through to
            // `None`, which means the realized literal, which on this host is an
            // EMPTY blob. Every field rendered an em dash with no diagnostic, and
            // `sys.locale` was reached for by six of the seven exemplars.
            //
            // A capability the catalog documents and the lowering cannot emit is
            // worse than one that is absent: absence is a checker refusal the
            // generator can read, and this was a screen that looked like working
            // software showing no data. `every_catalog_capability_lowers_to_a_call`
            // holds the whole set now.
            "sys.locale" => {
                let key = match binding.field.as_str() {
                    f @ ("lang" | "temp_unit") => f,
                    _ => return None,
                };
                Some(format!("sys.locale({key:?})"))
            }
            // Answered from the SAME front-page fetch `sys.news` reads, found by
            // `id` rather than by row. Sharing the fetch is what makes a detail
            // screen agree with the list it was opened from — a second endpoint
            // could rank differently between the tap and the read.
            "sys.news_item" => {
                let id = arg("id")?;
                let key = match binding.field.as_str() {
                    f @ ("id" | "title" | "author" | "points" | "comments" | "url") => f,
                    _ => return None,
                };
                Some(format!("sys.newsitem({id}, {key:?})"))
            }
            // §5.12's read-only half. The store is the same `user.json` the durable
            // collections live in, so a preference is one more reference the user
            // owns rather than a second kind of storage.
            "sys.prefs" => {
                let key = match binding.field.as_str() {
                    f @ ("units" | "range" | "home" | "work" | "mode") => f,
                    _ => return None,
                };
                Some(format!("sys.prefs({key:?})"))
            }
            // The extremes of the SAME close series the plot draws, off the same
            // one fetch. `points` is not here: the catalog listed it, nothing could
            // deliver a series as a value, and `StockPlot` fetches its own — so the
            // catalog dropped it rather than this pretending to answer it.
            "sys.series" => {
                let ticker = arg("ticker")?;
                let range = arg("range").unwrap_or_else(|| "\"d1\"".to_owned());
                let key = match binding.field.as_str() {
                    "min" => "low",
                    "max" => "high",
                    _ => return None,
                };
                Some(format!("sys.stockrange({ticker}, {range}, {key:?})"))
            }
            "sys.quote" => {
                let symbol = text("ticker")?;
                // What this helper can actually answer, verified against a live
                // response rather than against its documentation.
                //
                // `open` was excluded here for a while, because `sys.stock`
                // resolved it from `regularMarketOpen` — a key absent from the
                // Yahoo chart response — and emitting the call drew `$—` beside
                // two live values. That was worked around at the wrong layer:
                // falling back left a SEEDED opening price under a live one, and
                // a stale number that looks real is worse than a visible gap.
                // The helper reads the bar series now, so the call is emitted.
                //
                // Market cap and P/E are still absent from the helper outright —
                // the chart endpoint does not carry them — so those two fall back
                // and always will until something fetches them.
                //
                // Every entry here is verified against a live response rather
                // than against the helper's documentation, which is what the
                // `open` episode cost: the DSL was well-formed and the unit tests
                // were green, and only a phone showed the number was wrong.
                let key = match binding.field.as_str() {
                    "last" => "price",
                    "pct" => "changepct",
                    "volume" => "vol",
                    f @ ("name" | "change" | "changemoney" | "high" | "low" | "open") => f,
                    _ => return None,
                };
                Some(format!("sys.stock({symbol}, {key:?})"))
            }
            // A mover, by index. `sys.movers` takes the row's position rather
            // than a ticker, so the loop index has to reach here — which it does
            // because a binding inside a `for` carries the item's index in its
            // field path.
            //
            // Every field below was checked against a live screener response,
            // not against the helper's accepted-key list. That distinction is
            // why `open` is absent from `sys.quote` above: the key is accepted
            // there and the value is not in the payload, so emitting the call
            // drew `$—` where the seeded blob held a real price.
            // A place NAME resolved to a fact. `geocodenum` for the numbers the
            // other helpers take as arguments, `geocode` for the words.
            // Live Wikipedia detail. The card names a FIELD (`d.extract`); this
            // lowers it to a self-contained SPLASH EXPRESSION evaluated inside
            // the widget: concat the URL, fetch via the brokered `sys.fetch`
            // primitive, `parse_json` (a Splash string method), then a static
            // field access. The retrieval LOGIC runs as Splash; only the raw
            // socket (`sys.fetch`) is Rust. (A shared `wiki_fetch` helper in a
            // .splash file would be cleaner, but the VM isolates a widget's
            // expression from a top-level `let`, so the expression must stand
            // alone; and `vm.eval` from a capability is not re-entrant.)
            "sys.wiki" => {
                let query = text("query")?;
                match binding.field.as_str() {
                    "title" | "extract" | "description" => Some(format!(
                        "sys.fetch(\"https://en.wikipedia.org/api/rest_v1/page/summary/\" + {query}).parse_json().{}",
                        binding.field
                    )),
                    _ => None,
                }
            }
            "sys.geocode" => {
                let name = text("name")?;
                match binding.field.as_str() {
                    "lat" | "lon" => Some(format!("sys.geocodenum({name}, {:?})", binding.field)),
                    "name" | "country" | "admin1" | "timezone" => {
                        Some(format!("sys.geocode({name}, {:?})", binding.field))
                    }
                    _ => None,
                }
            }
            // The forecast. L0 names a FIELD; open-meteo wants a path, and the
            // daily ones are indexed by the row being drawn.
            "sys.weather" => {
                let lat = num("lat")?;
                let lon = num("lon")?;
                // Which day the DAILY fields describe. 0 is today; a forecast
                // row's own index rides on top, so `day: 1` shifts the whole
                // week loop too.
                let day: u32 = arg("day").and_then(|v| v.parse().ok()).unwrap_or(0);
                let (row, field) = match binding.field.split_once('.') {
                    Some((i, f)) if i.parse::<u32>().is_ok() => (i, f),
                    _ => ("0", binding.field.as_str()),
                };
                let row = &format!("{}", row.parse::<u32>().unwrap_or(0) + day);
                // There is no "current" tomorrow. A current-conditions field
                // under a future day gets NO translation — the seeded value or
                // an em dash, a visible absence — never today's reading served
                // beneath a label that says otherwise. Measured motive: a card
                // whose eyebrow said TOMORROW over `current.temperature_2m`,
                // which no screen could tell from the real thing.
                if day > 0 && matches!(field, "temp" | "feels" | "humidity" | "wind" | "pressure") {
                    return None;
                }
                let path = match field {
                    "temp" => "current.temperature_2m".to_string(),
                    "feels" => "current.apparent_temperature".to_string(),
                    "humidity" => "current.relative_humidity_2m".to_string(),
                    "wind" => "current.wind_speed_10m".to_string(),
                    "pressure" => "current.surface_pressure".to_string(),
                    "hi" => format!("daily.temperature_2m_max.{row}"),
                    "lo" => format!("daily.temperature_2m_min.{row}"),
                    "uv" => format!("daily.uv_index_max.{row}"),
                    "precip" => format!("daily.precipitation_probability_max.{row}"),
                    // The condition is a WMO code the host turns into a word, so
                    // the card never states weather it has not observed.
                    "cond" => {
                        return Some(format!(
                            "sys.weatherword({lat}, {lon}, {:?})",
                            format!("daily.weather_code.{row}")
                        ))
                    }
                    // `sys.dayname(lat, lon, n, locale)` — FOUR arguments. This
                    // emitted three, putting `"en"` in the lat slot and the row
                    // in the lon slot, so `n` coerced to 0 and every forecast row
                    // said "Today". Seven rows of it, under seven different
                    // temperatures, which is what made it look like a labelling
                    // choice rather than a bug.
                    "dayname" => return Some(format!("sys.dayname({lat}, {lon}, {row}, \"en\")")),
                    // §5.11's aggregates — properties of the WEEK, not of a day,
                    // and the reason a `TempBar` knows how long its bar should
                    // be. Untranslated, both fell back to zero: every bar drew
                    // against a range of nothing, so seven days of different
                    // temperatures all rendered the same flat line.
                    "min_lo" => return Some(format!("sys.weekmin({lat}, {lon})")),
                    "max_hi" => return Some(format!("sys.weekmax({lat}, {lon})")),
                    _ => return None,
                };
                Some(format!("sys.weather({lat}, {lon}, {path:?})"))
            }
            // Sunrise and sunset are STRINGS in the forecast the weather helper
            // already fetches; `sys.daylight` answers only the arc progress, so
            // the three L0 fields come from two different helpers.
            "sys.daylight" => {
                let lat = num("lat")?;
                let lon = num("lon")?;
                match binding.field.as_str() {
                    "rise" => Some(format!("sys.weather({lat}, {lon}, \"daily.sunrise.0\")")),
                    "set" => Some(format!("sys.weather({lat}, {lon}, \"daily.sunset.0\")")),
                    "now" => Some(format!("sys.daylight({lat}, {lon})")),
                    _ => None,
                }
            }
            "sys.moonphase" => match binding.field.as_str() {
                // The VM spells it `illum`; L0 spells it out.
                "illumination" => Some("sys.moonphase(\"illum\")".to_string()),
                "name" | "phase" => Some(format!("sys.moonphase({:?})", binding.field)),
                _ => None,
            },
            "sys.airquality" => {
                let lat = num("lat")?;
                let lon = num("lon")?;
                let path = match binding.field.as_str() {
                    "aqi" => "current.us_aqi",
                    "pm25" => "current.pm2_5",
                    "pm10" => "current.pm10",
                    "ozone" => "current.ozone",
                    _ => return None,
                };
                Some(format!("sys.airquality({lat}, {lon}, {path:?})"))
            }
            // A headline feed, indexed like the movers list.
            "sys.news" => {
                let (index, field) = binding.field.split_once('.')?;
                let row: u32 = index.parse().ok()?;
                // `offset` is why the feed starts BELOW the lead. Ignoring it
                // made row 0 of "latest" the lead story again.
                let offset: u32 = arg("offset").and_then(|v| v.parse().ok()).unwrap_or(0);
                let index = row + offset;
                let key = match field {
                    "comments" => "comments",
                    f @ ("title" | "url" | "author" | "points" | "id") => f,
                    _ => return None,
                };
                Some(format!("sys.news({index}, {key:?})"))
            }
            // The quake feed. Same row shape as `sys.news`, same `offset` reason:
            // the card shows the newest event large and the rest beneath it, and
            // without honouring the offset row 0 of the list is the lead again.
            "sys.quakes" => {
                let (index, field) = binding.field.split_once('.')?;
                let row: u32 = index.parse().ok()?;
                let offset: u32 = arg("offset").and_then(|v| v.parse().ok()).unwrap_or(0);
                let index = row + offset;
                let key = match field {
                    // The backend spells the humanized age `ago`; `id` has no
                    // backend field — the row index IS the identity, which is all
                    // a `for` key needs.
                    "ago" => "ago",
                    f @ ("mag" | "place" | "depth" | "lat" | "lon") => f,
                    "id" => return Some(format!("\"{index}\"")),
                    _ => return None,
                };
                Some(format!("sys.quakes({index}, {key:?})"))
            }
            "sys.photo" => {
                let query = text("query")?;
                // The CONDITION, when the card passes one. `cond: now.cond`
                // resolves to the forecast's own word call, so the host folds a
                // live reading into the prompt and a rainy city stops sitting
                // under a sunlit backdrop.
                //
                // Only when it is a generated call. A literal here would be the
                // card stating the weather, which is the one thing §4 forbids —
                // and a mood is only honest while the card is not asserting it.
                match binding.args.iter().find(|(n, _)| n == "cond") {
                    Some((_, c)) if binding.nested.iter().any(|n| n == "cond") => {
                        Some(format!("sys.photo({query}, {c})"))
                    }
                    _ => Some(format!("sys.photo({query})")),
                }
            }
            // The activity app's whole data surface. Missing from this table, a
            // declared `sys.places` source fell to the seeded blob -- which a
            // LIVE card does not have -- so every venue row rendered an em dash
            // and the card looked like a fetch that never landed. Measured:
            // "list museums in Kyoto" produced eight rows of "—".
            // The device's last-known fix, read synchronously from the platform
            // global. No network, so unlike every other arm here it cannot be
            // pending — but it CAN be absent, and the VM answers -9999 for a
            // number with no fix rather than an em dash. A card guards with
            // `ok` before trusting the coordinates.
            //
            // On Android this is fed by the platform LocationListener, which is
            // the same path that currently crashes the shipping activity with a
            // missing `LocationListener$-CC` desugaring class. So this arm makes
            // the card correct and does not by itself make GPS usable.
            // A TRIP's own facts — how long and how far — from the same cached
            // fetch the map's polyline comes from, so asking costs nothing extra.
            "sys.route" => {
                // `mode:` DECIDES THE DURATION, and it was being dropped.
                //
                // The argument was accepted, documented and never emitted, so a
                // card that asked how long a trip takes on foot was answered with
                // how long it takes by car — the same number under a lit "Walk"
                // chip, which is the shape of every defect this profile keeps
                // finding: accepted, rendered, confidently wrong.
                //
                // The helper's own fields are the translation. `walk` and `bike`
                // are the host's ESTIMATES from the measured distance (~5 km/h and
                // ~15 km/h), because the public OSRM server serves the driving
                // graph for every profile it is asked for — verified: `foot`,
                // `bike` and `cycling` all return the driving answer. The estimate
                // is the host's to make and to document; what §4 forbids is the
                // CARD stating a duration, and it still states nothing.
                //
                // Distance is the same geometry either way, so it does not vary.
                let mode = arg("mode").unwrap_or_default();
                let key = match binding.field.as_str() {
                    "duration" => match mode.trim() {
                        "walk" => "walk",
                        "bike" => "bike",
                        _ => "min",
                    },
                    "distance" => "km",
                    // The step list is a collection a card loops over, not a
                    // scalar a call answers.
                    _ => return None,
                };
                let a = num("from_lat")?;
                let o = num("from_lon")?;
                let b = num("to_lat")?;
                let p = num("to_lon")?;
                // The waypoints, as the helper's sixth argument: a `lat,lon;lat,lon`
                // string built from the coordinate calls the card listed. Emitted
                // as CONCATENATION rather than a literal, because each coordinate
                // is a live call and the string has to be assembled where the
                // numbers arrive.
                //
                // Omitted entirely when the card named none, so a stopless trip
                // passes "" and takes the same two-coordinate path it always did.
                let via = via_string(&arg("via").unwrap_or_default());
                match via {
                    Some(vias) => {
                        Some(format!("sys.navroute({a}, {o}, {b}, {p}, {key:?}, {vias})"))
                    }
                    None => Some(format!("sys.navroute({a}, {o}, {b}, {p}, {key:?})")),
                }
            }
            // Navigation's live half, and the one place a fabricated number was
            // load-bearing in the app this replaces.
            //
            // `sys.navstep` needs a progress-along-the-route in metres. The
            // original nav app supplied `sys.navsecs(period) * 15.2` — a looping
            // clock times an assumed 34 mph — so the card announced turns for a
            // vehicle that was moving whether or not anything was. It read as a
            // demo because it WAS one: the instruction advanced on a timer.
            //
            // `sys.navprog` answers the same slot from the device's own fix, by
            // projecting it onto the route. Every argument is now a measurement,
            // so an instruction changes because the device moved. Both helpers
            // share `sys.navroute`'s one cached fetch.
            "sys.step" => {
                let key = match binding.field.as_str() {
                    "instruction" => "instr",
                    // The helper calls it `rem`. `"remain"` is what the field is
                    // called in L0's vocabulary and would have answered "" — the
                    // helper returns the empty string for a field it does not
                    // know, so the banner would have shown a live instruction
                    // above a blank distance, which reads as "still loading"
                    // rather than "asked for the wrong key".
                    "remaining" => "rem",
                    // How long is left, in minutes. The helper spells it
                    // `remmin`; a card asks for `eta`, which is what the
                    // number MEANS to whoever is driving.
                    "eta" => "remmin",
                    "progress" => "progress",
                    _ => return None,
                };
                let a = num("from_lat")?;
                let o = num("from_lon")?;
                let b = num("to_lat")?;
                let p = num("to_lon")?;
                let at_lat = num("at_lat")?;
                let at_lon = num("at_lon")?;
                let along = format!("sys.navprog({a}, {o}, {b}, {p}, {at_lat}, {at_lon})");
                if key == "progress" {
                    return Some(along);
                }
                Some(format!("sys.navstep({a}, {o}, {b}, {p}, {along}, {key:?})"))
            }
            "sys.gps" => {
                let key = match binding.field.as_str() {
                    "accuracy" => "acc",
                    f @ ("lat" | "lon" | "ok") => f,
                    _ => return None,
                };
                Some(format!("sys.gps({key:?})"))
            }
            // Free-text PLACE search, indexed like `sys.places`. `searchnum`
            // answers the numbers, `search` the words — the same split
            // `geocode`/`geocodenum` uses, and for the same reason: a coordinate
            // fed to another call has to arrive as a number.
            "sys.search" => {
                // An UNINDEXED read is row 0.
                //
                // A `count: 1` search is one place, and a card reads it as a
                // record — `dest_place.name`, not `dest_place.0.name`. Requiring
                // the index meant the nav card's destination fell back to the
                // seed and rendered an em dash beside a correct card: the model
                // had put "Osaka Castle" in the initial state, the checker
                // accepted it, and the one thing missing was this arm's ability
                // to answer the spelling the card used.
                let (index, field) = match binding.field.split_once('.') {
                    Some((i, f)) if i.parse::<u32>().is_ok() => (i, f),
                    _ => ("0", binding.field.as_str()),
                };
                let query = text("query")?;
                match field {
                    "lat" | "lon" => Some(format!("sys.searchnum({query}, {index}, {field:?})")),
                    // `label` is the secondary line the helper has always answered —
                    // city, region, country. Five results named "Stanford" are what
                    // Photon returns for "Stanford", and without this they render as
                    // five identical rows nobody can choose between.
                    // `query` is the text that finds this hit again — what a
                    // results row must carry, or picking the third "Stanford" sets
                    // state to "Stanford" and routes to the first.
                    "name" | "label" | "query" => {
                        Some(format!("sys.search({query}, {index}, {field:?})"))
                    }
                    // `id` and `distance` have no answer in the helper, so they
                    // fall back rather than emitting a call that returns "".
                    _ => None,
                }
            }
            "sys.places" => {
                let (index, field) = binding.field.split_once('.')?;
                index.parse::<u32>().ok()?;
                let lat = num("lat")?;
                let lon = num("lon")?;
                let category = arg("category").unwrap_or_default();
                // L0 says `distance`; the VM answers `dist`. Same translation
                // job as `ticker`/`symbol` above.
                let key = match field {
                    "distance" => "dist",
                    f @ ("name" | "lat" | "lon" | "category") => f,
                    _ => return None,
                };
                Some(format!(
                    "sys.places({lat}, {lon}, {category:?}, {index}, {key:?})"
                ))
            }
            "sys.movers" => {
                let (index, field) = binding.field.split_once('.')?;
                index.parse::<u32>().ok()?;
                let key = match field {
                    "ticker" => "symbol",
                    "last" => "price",
                    "pct" => "changepct",
                    "volume" => "vol",
                    "mktcap" => "marketcap",
                    f @ ("name" | "change" | "changemoney" | "high" | "low" | "open") => f,
                    _ => return None,
                };
                let universe = binding
                    .args
                    .iter()
                    .find(|(n, _)| n == "symbols")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                Some(format!("sys.movers({index}, {key:?}, {universe:?})"))
            }
            // §5.12. Indexed like `sys.movers` — the host holds the user's list
            // in order, so a row is addressed by position — but every value
            // beside the ticker is FETCHED. The store holds only the reference,
            // which is why this lowers to a live call at all rather than to the
            // realized literal: a stored price would render stale and look live.
            "sys.watchlist" => {
                // The membership probe: `kept.has` on a watchlist source WITH
                // a ticker argument answers whether THAT ticker is in the
                // user's list — "1" or "0", synchronously from the published
                // store. It is what lets a quote page show Add or Remove.
                if binding.field == "has" {
                    let ticker = arg("ticker")?;
                    return Some(format!("sys.watchlist_has({ticker})"));
                }
                let (index, field) = binding.field.split_once('.')?;
                index.parse::<u32>().ok()?;
                let key = match field {
                    "ticker" => "symbol",
                    "last" => "price",
                    "pct" => "changepct",
                    "volume" => "vol",
                    "mktcap" => "marketcap",
                    f @ ("name" | "change" | "changemoney" | "high" | "low" | "open") => f,
                    _ => return None,
                };
                Some(format!("sys.watchlist({index}, {key:?})"))
            }
            // A saved STORY. The id is the stored reference; everything beside
            // it is fetched by that id, so a bookmark shows today's points for
            // a story saved last month.
            "sys.reading" => {
                let (index, field) = binding.field.split_once('.')?;
                index.parse::<u32>().ok()?;
                let key = match field {
                    f @ ("id" | "title" | "author" | "points" | "comments" | "url") => f,
                    _ => return None,
                };
                Some(format!("sys.reading({index}, {key:?})"))
            }
            // One search result, by row index.
            "sys.video" => {
                let (index, field) = binding.field.split_once('.')?;
                index.parse::<u32>().ok()?;
                let key = match field {
                    f @ ("id" | "title" | "channel" | "length" | "views" | "age" | "thumb"
                    | "embed") => f,
                    _ => return None,
                };
                let query = text("query")?;
                Some(format!("sys.video({query}, {index}, {key:?})"))
            }
            // One country's reading, by row index. The countries argument is the
            // card's own list, so row 0 is the first country it named.
            "sys.indicator" => {
                // `read.0.name` is a row; `read.title` is the indicator's own
                // name, which is the same for every row — so a bare field
                // reads row 0 rather than answering nothing (the card titles
                // itself with it, and it rendered an em dash).
                let (index, field) = match binding.field.split_once('.') {
                    Some((i, f)) => (i, f),
                    None => ("0", binding.field.as_str()),
                };
                index.parse::<u32>().ok()?;
                let key = match field {
                    f @ ("name" | "latest" | "first" | "change" | "min" | "max" | "year"
                    | "title") => f,
                    _ => return None,
                };
                let countries = arg("countries")?;
                let indicator = arg("indicator")?;
                let years = arg("years").unwrap_or_else(|| "30".to_owned());
                // `:?` on the two text slots — a bare interpolation put
                // `sys.indicator(CHN,IND, ...)` in the DSL, which parses as
                // two arguments and answered nothing (measured on device).
                // `years` is a numeric slot and stays unquoted.
                Some(format!(
                    "sys.indicator({countries:?}, {indicator:?}, {years}, {index}, {key:?})"
                ))
            }
            // The reader overlay's current page — published by the host the
            // same way locale and the position fix are.
            "sys.link" => {
                let key = match binding.field.as_str() {
                    f @ "url" => f,
                    _ => return None,
                };
                Some(format!("sys.link({key:?})"))
            }
            // A followed topic. `name` is the stored word; the `top_*` keys
            // are the first hit of a fresh search for it, fetched at read time
            // like every other joined value in this table.
            "sys.topics" => {
                let (index, field) = binding.field.split_once('.')?;
                index.parse::<u32>().ok()?;
                let key = match field {
                    f @ ("name" | "top_title" | "top_points" | "top_id") => f,
                    _ => return None,
                };
                Some(format!("sys.topics({index}, {key:?})"))
            }
            // A saved place. `name`/`lat`/`lon` identify it and come from the
            // store; the readings beside them are fetched, which is why this
            // lowers to a call rather than to the realized literal.
            "sys.cities" => {
                let (index, field) = binding.field.split_once('.')?;
                index.parse::<u32>().ok()?;
                let key = match field {
                    f @ ("name" | "lat" | "lon" | "temp" | "feels" | "hi" | "lo" | "cond"
                    | "humidity" | "wind") => f,
                    _ => return None,
                };
                Some(format!("sys.cities({index}, {key:?})"))
            }
            // The query is a path into declared state, so it reaches the helper
            // as whatever the user committed — the card never builds it.
            "sys.symbol_search" => {
                let (index, field) = binding.field.split_once('.')?;
                index.parse::<u32>().ok()?;
                let query = text("query")?;
                let key = match field {
                    "ticker" => "symbol",
                    f @ ("name" | "exchange" | "kind") => f,
                    _ => return None,
                };
                Some(format!("sys.symbol_search({query}, {index}, {key:?})"))
            }
            _ => None,
        }
    }

    fn text_of(value: Option<&NodeValue>) -> String {
        match value {
            Some(NodeValue::Text(s)) => format!("{s:?}"),
            Some(NodeValue::Number(n)) => format!("{:?}", trim_num(*n)),
            Some(NodeValue::Bool(b)) => format!("{b:?}"),
            Some(NodeValue::Token(t)) => format!("{t:?}"),
            Some(NodeValue::Event(_)) | None => "\"\"".into(),
            Some(NodeValue::Missing) => "\"—\"".into(),
            Some(NodeValue::Status(st)) => format!("{:?}", st.as_token()),
        }
    }

    fn num_of(value: Option<&NodeValue>) -> f64 {
        match value {
            Some(NodeValue::Number(n)) => *n,
            Some(NodeValue::Text(s)) => s.parse().unwrap_or(0.0),
            _ => 0.0,
        }
    }

    pub(super) fn trim_num(n: f64) -> String {
        if (n - n.round()).abs() < f64::EPSILON {
            format!("{}", n as i64)
        } else {
            format!("{n:.1}")
        }
    }

    /// Apply a declared `format`. This is the runtime's job, not the card's: a
    /// card that wrote "$" or "41.2M" itself would be authoring a fact, and
    /// currency, grouping and compaction are all locale-dependent besides.
    fn formatted(kind: &str, n: f64) -> String {
        let sign = if n > 0.0 { "+" } else { "" };
        match kind {
            "money" => format!("${:.2}", n),
            "signed_money" => format!("{sign}${:.2}", n),
            "signed_pct" => format!("{sign}{:.1}%", n),
            "ratio" => format!("{:.1}", n),
            "compact" => {
                let a = n.abs();
                let (v, suffix) = if a >= 1e12 {
                    (n / 1e12, "T")
                } else if a >= 1e9 {
                    (n / 1e9, "B")
                } else if a >= 1e6 {
                    (n / 1e6, "M")
                } else if a >= 1e3 {
                    (n / 1e3, "K")
                } else {
                    (n, "")
                };
                if suffix.is_empty() {
                    trim_num(v)
                } else {
                    format!("{:.1}{suffix}", v)
                }
            }
            // A float hour — 18.9 is 18:54, not "18.9".
            "time" => {
                let h = n.floor().max(0.0) as i64;
                let m = ((n - n.floor()) * 60.0).round() as i64;
                format!("{h}:{m:02}")
            }
            _ => trim_num(n),
        }
    }

    /// A value plus its unit suffix, which is a presentation concern the runtime
    /// owns — the card never wrote "°" next to a number.
    pub(super) fn valued(node: &UiNode) -> String {
        // Prefer a live call, where the backend can answer the source itself and
        // the decoration survives being concatenated around it.
        if let Some(live) = live_valued(node) {
            return live;
        }
        valued_seeded(node)
    }

    /// The live form, or `None` when any part of it does not survive.
    ///
    /// `pub(super)` because the kit's tick stamp (`live_call_of`) must compose
    /// EXACTLY this — decoration, `format:` prefix, the `signed_money`
    /// changemoney redirect, and the refusals — or the first tick redraws the
    /// value without whichever part it dropped.
    pub(super) fn live_valued(node: &UiNode) -> Option<String> {
        let decoration = decoration_of(node);
        live_value(
            node,
            &decoration.glyph,
            decoration.unit,
            &decoration.suffix,
            decoration.format.as_deref(),
        )
    }

    /// The realized value with its decoration — what is drawn when nothing goes
    /// live, and what is MEASURED even when something does.
    /// What wraps a value: a leading glyph, a unit, a trailing word, and how the
    /// number itself is formatted. Read once and shared, so the live path and
    /// the seeded path cannot disagree about what decorates what.
    struct Decoration {
        glyph: String,
        unit: &'static str,
        suffix: String,
        format: Option<String>,
    }

    fn decoration_of(node: &UiNode) -> Decoration {
        Decoration {
            unit: match token_arg(node, "unit") {
                Some("c" | "f") => "°",
                Some("pct") => "%",
                // A duration is minutes, and "34" alone is not a duration —
                // beside a distance it reads as another distance. The word is
                // the theme's to supply, not the card's: a card that wrote
                // `suffix: "min"` would be asserting the unit its own number
                // came in, and would be wrong the day the helper answers hours.
                Some("duration") => " min",
                // What the backend actually answers: open-meteo serves
                // `wind_speed_10m` in km/h and `surface_pressure` in hPa (no
                // unit override in any fetch), and the L2 reference suffixed
                // exactly these. Both tokens were catalog-legal and rendered
                // NOTHING — a bare "12.5" beside a labelled tile, which reads
                // as a number in whatever unit the reader assumes. (`index`
                // is gone from the catalog instead: an index is dimensionless,
                // so there is no honest suffix to give it.)
                Some("speed") => " km/h",
                Some("pressure") => " hPa",
                _ => "",
            },
            glyph: match arg(node, "glyph") {
                Some(NodeValue::Text(g)) => g.clone(),
                _ => String::new(),
            },
            // `suffix` is a declared unit word — "412 pts", not "412". It was in
            // the catalog and ignored here, so every score and comment count on
            // the news card rendered as a bare number.
            suffix: match arg(node, "suffix") {
                Some(NodeValue::Text(t)) => format!(" {t}"),
                _ => String::new(),
            },
            format: match arg(node, "format") {
                Some(NodeValue::Token(t)) => Some(t.clone()),
                _ => None,
            },
        }
    }

    fn valued_seeded(node: &UiNode) -> String {
        let value = arg(node, "value");
        let Decoration {
            glyph,
            unit,
            suffix,
            format: format_kind,
        } = decoration_of(node);
        // A `value:` the backend can answer goes LIVE, exactly as `text:` does.
        //
        // This branch built its string from the REALIZED literal and never
        // looked at the bindings, so every number on a card — temperature,
        // high/low, price, distance — rendered whatever the host had seeded no
        // matter how many capabilities were translated. Only `text:` went live,
        // which is why a card could show a live city name above a stale
        // temperature.
        //
        // NOT when the card declares a `format:`. Scaling and currency are
        // applied HERE, to a realized number; a live call returns a string this
        // side never sees, so going live would silently drop the format —
        // measured, `compact` stopped turning 41200000 into "41.2M". A helper
        // that formats its own output (`sys.movers` volume) already reads right;
        // one that does not keeps the seeded value until the format can travel
        // with the call.
        if format_kind.is_none() {
            // An L1 expression: emit the ARITHMETIC, so a live operand is still
            // fetched and the multiply happens against data that arrives later.
            // Realization already computed a number, but only for whatever the
            // host seeded — which for a live card is nothing.
            if let Some((_, shape)) = node.exprs.iter().find(|(n, _)| n == "value") {
                if let Some(rendered) = render_expr(shape) {
                    return decorate(rendered, &glyph, unit, &suffix);
                }
            }
            if let Some((_, binding)) = node.bindings.iter().find(|(n, _)| n == "value") {
                if let Some(call) = vm_call(binding) {
                    return decorate(call, &glyph, unit, &suffix);
                }
            }
        }
        seeded_body(node, value, &glyph, unit, &suffix, format_kind)
    }

    /// The seeded tail shared by emission and measurement: the realized
    /// literal with every decoration applied, never a live call.
    fn seeded_body(
        node: &UiNode,
        value: Option<&NodeValue>,
        glyph: &str,
        unit: &str,
        suffix: &str,
        format_kind: Option<String>,
    ) -> String {
        match value {
            Some(NodeValue::Missing) => "\"—\"".into(),
            Some(v) => {
                let body = match (v, format_kind.as_deref()) {
                    (NodeValue::Number(n), Some(kind)) => formatted(kind, *n),
                    (NodeValue::Number(n), None) => trim_num(*n),
                    (NodeValue::Text(s), _) => s.clone(),
                    _ => String::new(),
                };
                format!("{:?}", format!("{glyph}{body}{unit}{suffix}"))
            }
            // A `text:` argument decorates too. It did not, and every caption
            // in `activity.card` read "300 m" where the card said
            // "300 m away · quiet green space". Nothing caught it because every
            // `suffix` in the original three cards pairs with `value:`, and only
            // that path applied the decoration.
            None => decorate(expr_of(node, "text"), glyph, unit, suffix),
        }
    }

    /// Wrap an already-emitted text in its glyph, unit and suffix.
    ///
    /// The text may be a literal (`"300 m"`) or a live call, so the decoration
    /// is concatenated in the DSL rather than in Rust — `"a" + call + "b"` works
    /// for both, and quoting a call would draw it instead of evaluating it.
    /// This node's decoration applied to an already-built expression.
    ///
    /// The kit needs it to compose a live call for `fn tick()`: a value with a
    /// `suffix:` must be set as `call + " left"`, not as the bare call. Excluding
    /// decorated values left the most visibly moving number on a driving screen as
    /// the only reason to rebuild the card, which defeats the tick entirely.
    pub(super) fn decorated(node: &UiNode, body: String) -> String {
        let Decoration {
            glyph,
            unit,
            suffix,
            ..
        } = decoration_of(node);
        decorate(body, &glyph, unit, &suffix)
    }

    fn decorate(body: String, glyph: &str, unit: &str, suffix: &str) -> String {
        let head = glyph.to_string();
        let tail = format!("{unit}{suffix}");
        if head.is_empty() && tail.is_empty() {
            return body;
        }
        // A plain quoted literal can be spliced directly, which keeps the common
        // case readable rather than emitting `"" + "300 m" + " away"`.
        if body.starts_with('"') && body.ends_with('"') && !body[1..body.len() - 1].contains('"') {
            let inner = &body[1..body.len() - 1];
            return format!("{:?}", format!("{head}{inner}{tail}"));
        }
        let mut out = String::new();
        if !head.is_empty() {
            out.push_str(&format!("{head:?} + "));
        }
        out.push_str(&body);
        if !tail.is_empty() {
            out.push_str(&format!(" + {tail:?}"));
        }
        out
    }

    /// How large a hero should be, given what it will DRAW.
    ///
    /// A hero is defined by dominating the card rather than by a point size:
    /// "18°" fits at 62 where "$184.20" clipped off the right edge on device.
    /// Shared by both lowerings — two copies of a ramp is two ramps, and they
    /// drift.
    pub(super) fn hero_points(node: &UiNode, emitted: &str) -> u32 {
        let measured = sizing_text(node, emitted);
        // The ramp, at 70%. Every text size in the theme came down by the same
        // factor, so the hierarchy between a hero, a value and a caption is
        // unchanged — only the scale is.
        match measured.trim_matches('"').chars().count() {
            0..=4 => 43,
            5..=6 => 35,
            7..=8 => 28,
            9..=12 => 22,
            _ => 17,
        }
    }

    /// What to MEASURE when a layout decision depends on how long a value is.
    ///
    /// Emitted text and rendered text are the same thing until a value goes
    /// live, at which point they diverge completely: `"$" + sys.stock(…)` is 33
    /// characters that draw as six. Any decision made by counting the emitted
    /// form is then wrong, and wrong in a way that looks like a layout bug.
    ///
    /// So measure the realized literal, which is still in `args` and is a sound
    /// proxy for the live value's length — a share price is about as long as a
    /// share price. When nothing is bound, this IS the emitted text.
    fn sizing_text(node: &UiNode, emitted: &str) -> String {
        if node
            .bindings
            .iter()
            .any(|(n, _)| n == "value" || n == "text")
        {
            let literal = valued_literal(node);
            if !literal.is_empty() {
                return literal;
            }
        }
        emitted.to_owned()
    }

    /// The realized value with every decoration applied — exactly what would
    /// have been drawn had nothing gone live.
    ///
    /// This is `valued_seeded`'s literal tail reached DIRECTLY, skipping its
    /// live-binding branch. That branch exists for EMISSION — a bound value
    /// must go live on the wire — but measuring the emitted call is how a
    /// three-character "23°" was sized as the ~120 characters of
    /// `sys.weather(sys.geocodenum(…))` and every live hero fell to the ramp's
    /// bottom step: 17pt, on the canonical weather fixture too. Measurement
    /// wants what will be DRAWN; the seeded literal — or its "—" placeholder —
    /// is the sound proxy for that even when the wire form is a call.
    fn valued_literal(node: &UiNode) -> String {
        let Decoration {
            glyph,
            unit,
            suffix,
            format: format_kind,
        } = decoration_of(node);
        seeded_body(node, arg(node, "value"), &glyph, unit, &suffix, format_kind)
    }

    /// A `value` argument as a live call plus its decoration, or `None` to use
    /// the realized literal.
    ///
    /// The decoration is the constraint. `glyph`, `unit` and `suffix` are
    /// literals that concatenate around a call — the DSL supports
    /// `"H:" + sys.weather(…)` and hand-written cards use it. A `format` mostly
    /// does not, because it needs the NUMBER:
    ///
    /// | format | live? | why |
    /// |---|---|---|
    /// | none | yes | nothing to apply |
    /// | `money` | yes | `sys.stock` returns two decimals, so `"$"` prefixes it |
    /// | `signed_pct` | yes | the VM already returns `"+0.63%"` — applying it again would double the sign |
    /// | `signed_money` | no | the sign goes OUTSIDE the currency symbol; not a prefix |
    /// | `compact`, `ratio` | no | need the number to divide or round |
    ///
    /// Returning `None` is the safe direction: the seeded value is stale but
    /// correct, where a wrong concatenation is neither.
    fn live_value(
        node: &UiNode,
        glyph: &str,
        unit: &str,
        suffix: &str,
        format_kind: Option<&str>,
    ) -> Option<String> {
        let (_, binding) = node.bindings.iter().find(|(n, _)| n == "value")?;
        // `signed_money` puts the currency INSIDE the sign — `+$7.13` — and a
        // prefix cannot express that: `"$" + "+7.13"` is `$+7.13`. This used to
        // give up and keep the seeded value, which put a fixture's `+$3.10`
        // beside a live `+3.55%`, two numbers describing one move and
        // disagreeing. The helper composes the whole string, so the binding is
        // redirected to the field that returns it already ordered.
        let binding = &if format_kind == Some("signed_money") && binding.field == "change" {
            SourceBinding {
                field: "changemoney".to_owned(),
                ..binding.clone()
            }
        } else {
            binding.clone()
        };
        let call = vm_call(binding)?;
        let prefix = match format_kind {
            // Already whole: the helper returned the sign and the symbol in the
            // right order, so nothing may be prepended.
            None | Some("signed_pct") | Some("signed_money") => String::new(),
            Some("money") => "$".to_owned(),
            Some(_) => return None,
        };
        let mut expr = String::new();
        let head = format!("{glyph}{prefix}");
        if !head.is_empty() {
            expr.push_str(&format!("{head:?} + "));
        }
        expr.push_str(&call);
        let tail = format!("{unit}{suffix}");
        if !tail.is_empty() {
            expr.push_str(&format!(" + {tail:?}"));
        }
        Some(expr)
    }

    fn pad(depth: usize) -> String {
        "  ".repeat(depth.min(32))
    }

    fn children(node: &UiNode, depth: usize, out: &mut String) {
        for child in &node.children {
            element(child, depth + 1, out);
        }
    }

    /// A node that declares `on_tap`, wrapped so the tap can actually be
    /// received.
    ///
    /// `tap_binding` alone emits `l0_event`/`l0_key`/`l0_value` as attributes,
    /// and nothing reads them: the VM has no hit-testing for an arbitrary
    /// attribute, so every one of those cards rendered inert. The mechanism that
    /// DOES work on device is the one hand-written cards already use — a
    /// transparent `Button` overlaid on the content, calling `agent.notify`,
    /// which the host receives as `SplashAction::Notify`.
    ///
    /// So this wraps a tappable element in `flow: Overlay` and lays that button
    /// over it. The attributes stay: they cost nothing, they are what the tests
    /// assert, and they are how a lowered card can be read back.
    fn element(node: &UiNode, depth: usize, out: &mut String) {
        let Some(NodeValue::Event(event)) = arg(node, "on_tap") else {
            return element_body(node, depth, out);
        };
        let p = pad(depth);
        // The wrapper must size like what it wraps. A Chip is `width: Fit` and
        // sits in a Row of chips; wrapping it in `Fill` makes the first chip eat
        // the row. Text roles are likewise intrinsic.
        let fill = matches!(node.kind.as_str(), "Row" | "Panel" | "Card");
        let w = if fill { "Fill" } else { "Fit" };
        let _ = writeln!(out, "{p}View{{ width: {w} height: Fit flow: Overlay");
        element_body(node, depth + 1, out);
        let _ = writeln!(out, "{p}  {}", tap_button(node, event));
        let _ = writeln!(out, "{p}}}");
    }

    /// The transparent hit target. `agent.notify`'s first argument must be a
    /// LITERAL for the host's `tag_notify_calls` to prefix it with the card id —
    /// an untagged event is discarded as unattributable — so the event name
    /// travels in the payload rather than in the channel name.
    fn tap_button(node: &UiNode, event: &str) -> String {
        let value = match arg(node, "value") {
            Some(NodeValue::Text(t)) => t.clone(),
            Some(NodeValue::Number(n)) => trim_num(*n),
            Some(NodeValue::Token(t)) => t.clone(),
            _ => String::new(),
        };
        format!(
            "Button{{ width: Fill height: Fill draw_bg.color: #00000000 \
             draw_bg.color_hover: #ffffff08 draw_bg.color_focus: #00000000 \
             draw_bg.color_down: #ffffff12 draw_bg.border_size: 0.0 \
             draw_bg.border_radius: 10 text: \"\" \
             on_click: || agent.notify(\"l0\", {{key: {:?}, event: {event:?}, value: {value:?}}}) }}",
            node.key
        )
    }

    fn element_body(node: &UiNode, depth: usize, out: &mut String) {
        let p = pad(depth);
        match node.kind.as_str() {
            // A card holding a MAP is laid out the way the shipping nav card lays
            // one out: the map is the BOTTOM layer of an overlay and everything
            // else floats above it. Any other card keeps the ordinary column.
            //
            // This is not a style preference. A `MapView` is a fixed-pixel
            // full-bleed surface — `Fill`/`Fit` "resolve to 0 and hide the map",
            // so the shipping card's MANDATORY rules give every map an explicit
            // 812 — and it paints its route ribbon through the GPU nav projection
            // rather than inside a laid-out rect. Stacked in a column beneath the
            // card's own content it draws straight over it.
            //
            // Measured, both ways round. With the map in a column: the route and
            // its ribbon covered the whole screen and the FROM/TO fields, the
            // duration and the Go button were simply not visible; in the drive
            // screen the ribbon painted across the turn banner, cutting a street
            // name in half. `a2app/apps/nav` has four maps and none of them is in
            // a column — every one is the first child of a `flow: Overlay` with a
            // floating sheet on top, and that is why they work.
            //
            // So the ORDER is inverted here relative to the card's text. A card
            // reads "the trip, then the map"; the screen is "the map, with the
            // trip over it". Which layer a role belongs on is presentation, and
            // presentation is the backend's to decide — the card still says only
            // what it has and in what order it matters.
            "Surface" => {
                let map = node.children.iter().find(|c| c.kind == "Map");
                let Some(map) = map else {
                    let _ = writeln!(
                        out,
                        "{p}SolidView{{ width: Fill height: Fit flow: Down new_batch: true \
                         draw_bg.color: {BASE} padding: {PAGE_PAD}"
                    );
                    children(node, depth, out);
                    let _ = writeln!(out, "{p}}}");
                    return;
                };
                // FIXED 812, not `Fill`. The shipping card's first MANDATORY rule
                // is "root is `flow: Overlay`, `new_batch: true`, fixed
                // `height: 812`", and the reason is the same one that governs the
                // map itself: `Fill` resolves to 0 inside a `Fit` parent, and a
                // card is an item in a chat list, so its container hugs content.
                // Measured — `height: Fill` here rendered an entirely empty screen,
                // map and sheet both, which is what a height of zero looks like.
                let _ = writeln!(
                    out,
                    "{p}SolidView{{ width: Fill height: 812 flow: Overlay new_batch: true \
                     draw_bg.color: {BASE}"
                );
                element(map, depth + 1, out);
                // The floating sheet, OPAQUE, in the shipping card's own colour.
                //
                // `height: Fit` so it is only as tall as what it holds — filling
                // would put a panel over the whole map and swallow every pan and
                // pinch that missed a control.
                //
                // Opaque because the theme's ordinary panel is `#ffffff12`, 7% white,
                // which over a map is a window rather than a surface. Measured: the
                // FROM and TO fields, the duration and the distance all rendered and
                // all of them were unreadable, with the map's own road labels —
                // "Bayshore Freeway", "22", "20" — drawn across the middle of them.
                // Legible-on-anything is not something a translucent panel can be,
                // and a map is the one backdrop a card cannot predict.
                // 76 at the bottom where the shipping card uses 30. That card is a
                // full-screen app card; an L0 card is an item in the chat list, and
                // the app's composer bar sits over the bottom of it. Measured with
                // 30: the duration, the distance and the Go button were half cut off
                // behind "Reconnecting…". The sheet was positioned exactly where it
                // was asked to be.
                //
                // AT THE BOTTOM, and that is the widget's requirement rather than a
                // taste. `update_plan_preview_camera` fits the whole route and frames
                // it "into the top band above the card's summary sheet" — so a sheet
                // at the top sits exactly where the widget put the route. Measured:
                // the trip's Saratoga end was behind the panel, and the camera was
                // doing its job.
                // A `.top` panel floats in its own band, above everything. That is
                // where a turn instruction belongs and where the app this replaces
                // puts it; the summary sheet is the bottom one.
                let docked_top = |c: &UiNode| {
                    c.kind == "Panel"
                        && matches!(arg(c, "dock"), Some(NodeValue::Token(t)) if t == "top")
                };
                // A docked panel contributes its CHILDREN, not itself — the band and
                // the sheet below ARE the panel's chrome, drawn here. Emitting the
                // `Panel` too nested a second rounded fill inside each, and because
                // that inner box is full-width the sheet's centring applied to the box
                // rather than to the number in it. The kit backend had the same fault.
                let docked_children = |child: &UiNode, depth: usize, out: &mut String| {
                    for inner in &child.children {
                        element(inner, depth, out);
                    }
                };
                for child in node.children.iter().filter(|c| docked_top(c)) {
                    let _ = writeln!(
                        out,
                        "{p}  View{{ width: Fill height: Fit flow: Down align: Align{{x: 0.5 y: 0.0}} \
                         margin: Inset{{left: 8 top: 46 right: 8}}"
                    );
                    docked_children(child, depth + 2, out);
                    let _ = writeln!(out, "{p}  }}");
                }
                let _ = writeln!(
                    out,
                    "{p}  View{{ width: Fill height: Fill flow: Down align: Align{{x: 0.5 y: 1.0}}"
                );
                let _ = writeln!(
                    out,
                    "{p}    RoundedView{{ width: Fill height: Fit flow: Down \
                     draw_bg.color: #0f1620 draw_bg.border_radius: 22 \
                     align: Align{{x: 0.5}} \
                     margin: Inset{{left: 8 right: 8 bottom: 40}} \
                     padding: Inset{{left: 14 top: 4 right: 14 bottom: 8}}"
                );
                for child in node
                    .children
                    .iter()
                    .filter(|c| c.kind != "Map" && !docked_top(c))
                {
                    // Docked panels unwrap here too; anything else placed straight on
                    // the surface is emitted whole, or a lone chip floated over the
                    // map would lose the chip and keep its label.
                    if child.kind == "Panel" && arg(child, "dock").is_some() {
                        docked_children(child, depth + 3, out);
                    } else {
                        element(child, depth + 3, out);
                    }
                }
                let _ = writeln!(out, "{p}    }}");
                let _ = writeln!(out, "{p}  }}");
                let _ = writeln!(out, "{p}}}");
            }
            // The card names a TRIP; the widget draws the route.
            //
            // `Map` was admitted by the catalog and lowered by NEITHER backend,
            // so `nav.card` — which §1.0 cites as settling its central argument,
            // "the same screen as the 664-line L2 exemplar in 54 lines" — drew
            // "no makepad lowering for Map" where the map goes. Admitted at L0
            // was true; the same screen was not.
            //
            // `MapView` does not fetch its own route despite the catalog note
            // saying so: `nav_polyline` is a live field it renders and does not
            // populate. But `sys.navroute` answers the polyline, and the helper's
            // own comment prescribes exactly this pairing — so the fetch is the
            // card's declared source resolved into a call, which is the same
            // shape every other live value takes.
            "Map" => {
                let (lat, lon, poly) = map_route(node);
                let mode = map_mode(node);
                let zoom = match arg(node, "zoom") {
                    Some(NodeValue::Number(n)) => trim_num(*n),
                    _ => "15".to_owned(),
                };
                // The settings a `MapView` does not work without, taken from the
                // SHIPPING nav card rather than reasoned about — `a2app/apps/nav`
                // is a working four-map reference whose "MANDATORY rules" section
                // says why each one matters, and the values below are the ones it
                // uses.
                //
                // `use_local_mbtiles: false` is the one that bites. The widget
                // defaults to a local `.mbtiles` file for offline development, and
                // an L0 card cannot ship one — so the omission draws the land fill
                // and nothing else. Measured: a nav card whose route ribbon and
                // whose duration were both correct, over a blank beige rectangle,
                // with `local mbtiles source missing` in logcat and nothing on
                // screen saying so. The app's own emitter already carried these
                // and this backend did not, which is the same one-backend gap
                // `Field`, `Grid.cols` and `Map` itself were each found in.
                //
                // `max_zoom` differs BY MODE, as it does in the shipping card: a
                // whole-route preview is capped at 16 and a driving view goes to
                // 19. A narrow clamp also has a cost under a finger — a card
                // sitting exactly on the floor cannot pinch out, so half the
                // gesture is dead and the map reads as broken rather than clamped.
                let max_zoom = if mode == "plan" { "16.0" } else { "19.0" };
                // The ribbon is drawn in ground metres, so a route seen from the
                // whole-trip view needs a far wider line than one seen from a car.
                let ribbon = match mode {
                    "plan" => "40.0",
                    "2d" => "11.0",
                    _ => "14.0",
                };
                let _ = write!(
                    out,
                    "{p}MapView{{ width: Fill height: 812 nav_mode: {mode:?} zoom: {zoom} \
                     min_zoom: 3.0 max_zoom: {max_zoom} nav_route_width: {ribbon} \
                     nav_period: 100 use_network: true use_local_mbtiles: false \
                     center_lat: {lat} center_lon: {lon}"
                );
                if poly != "\"\"" {
                    let _ = write!(out, " nav_polyline: {poly}");
                }
                let _ = writeln!(out, " }}");
            }
            "Photo" => {
                // Overlay: photo, scrim, then the column. A `Fit` overlay takes
                // its tallest child, so the image needs a fixed height or the
                // card ends in a band of bare base colour.
                let src = match arg(node, "src") {
                    Some(NodeValue::Text(s)) => s.clone(),
                    _ => String::new(),
                };
                let _ = writeln!(
                    out,
                    "{p}SolidView{{ width: Fill height: Fit flow: Overlay new_batch: true \
                     draw_bg.color: {BASE}"
                );
                if !src.is_empty() {
                    let _ = writeln!(
                        out,
                        "{p}  Image{{ src: http_resource({src:?}) fit: ImageFit.CropToFill \
                         width: Fill height: 2000 }}"
                    );
                }
                let _ = writeln!(
                    out,
                    "{p}  SolidView{{ width: Fill height: Fill draw_bg.color: {SCRIM} }}"
                );
                let _ = writeln!(
                    out,
                    "{p}  View{{ width: Fill height: Fit flow: Down padding: {PAGE_PAD}"
                );
                children(node, depth + 1, out);
                let _ = writeln!(out, "{p}  }}");
                let _ = writeln!(out, "{p}}}");
            }
            "Col" => {
                let align =
                    matches!(arg(node, "align"), Some(NodeValue::Token(t)) if t == "center");
                let a = if align { " align: Align{x: 0.5}" } else { "" };
                let _ = writeln!(out, "{p}View{{ width: Fill height: Fit flow: Down{a}");
                children(node, depth, out);
                let _ = writeln!(out, "{p}}}");
            }
            "Row" => {
                let _ = writeln!(
                    out,
                    "{p}View{{ width: Fill height: Fit flow: Right align: Align{{y: 0.5}} spacing: 6{}",
                    tap_binding(node)
                );
                children(node, depth, out);
                let _ = writeln!(out, "{p}}}");
            }
            "Panel" | "Card" => {
                let _ = writeln!(
                    out,
                    "{p}RoundedView{{ width: Fill height: Fit flow: Down new_batch: true \
                     draw_bg.color: {PANEL} draw_bg.border_radius: 14.0 \
                     margin: Inset{{top: 16}} padding: Inset{{left: 14 right: 14 top: 12 bottom: 12}}{}",
                    tap_binding(node)
                );
                children(node, depth, out);
                let _ = writeln!(out, "{p}}}");
            }
            "Grid" => {
                // Emitted as rows of `cols` so the existing layout engine needs
                // no grid primitive.
                //
                // The column count was hardcoded to two, which is what every
                // card in the corpus asks for — so `cols:` was accepted by the
                // catalog, checked, and then ignored, and a `Grid(cols: 3)`
                // rendered as pairs with nothing saying it had been overruled.
                // Found by the conformance test rather than by a card.
                let cols = match arg(node, "cols") {
                    Some(NodeValue::Number(n)) if *n >= 1.0 => *n as usize,
                    // A grid that did not say is a grid of two, which is what
                    // the corpus means by a detail grid.
                    _ => 2,
                };
                let _ = writeln!(
                    out,
                    "{p}View{{ width: Fill height: Fit flow: Down spacing: 8"
                );
                for pair in node.children.chunks(cols) {
                    let _ = writeln!(
                        out,
                        "{p}  View{{ width: Fill height: Fit flow: Right spacing: 8"
                    );
                    for cell in pair {
                        element(cell, depth + 2, out);
                    }
                    let _ = writeln!(out, "{p}  }}");
                }
                let _ = writeln!(out, "{p}}}");
            }
            "Rule" => {
                let _ = writeln!(
                    out,
                    "{p}SolidView{{ width: Fill height: 1 draw_bg.color: {HAIRLINE} }}"
                );
            }
            "Space" => {
                let _ = writeln!(out, "{p}View{{ width: Fill height: Fill }}");
            }
            "Tile" => {
                let _ = writeln!(
                    out,
                    "{p}RoundedView{{ width: Fill height: Fit flow: Down new_batch: true \
                     draw_bg.color: {PANEL} draw_bg.border_radius: 18.0 \
                     padding: Inset{{left: 14 right: 14 top: 12 bottom: 12}} spacing: 4"
                );
                let _ = writeln!(
                    out,
                    "{p}  TextCaption{{ text: {} draw_text.color: {DIM} }}",
                    expr_of(node, "label")
                );
                let _ = writeln!(
                    out,
                    "{p}  TextStat{{ text: {} draw_text.color: {TEXT} }}",
                    valued(node)
                );
                let _ = writeln!(out, "{p}}}");
            }
            "TempBar" => {
                let _ = writeln!(
                    out,
                    "{p}TempBar{{ width: Fill height: 8 margin: Inset{{left: 10 right: 10}} \
                     draw_bg.tlo: {} draw_bg.thi: {} draw_bg.wmin: {} draw_bg.wmax: {} }}",
                    trim_num(num_of(arg(node, "lo"))),
                    trim_num(num_of(arg(node, "hi"))),
                    trim_num(num_of(arg(node, "min"))),
                    trim_num(num_of(arg(node, "max"))),
                );
            }
            "WeatherIcon" => {
                let size = matches!(arg(node, "size"), Some(NodeValue::Token(t)) if t == "hero");
                let (w, h) = if size { (64, 64) } else { (34, 26) };
                let _ = writeln!(
                    out,
                    "{p}WeatherIcon{{ width: {w} height: {h} draw_bg.cond: {} }}",
                    trim_num(num_of(arg(node, "cond")))
                );
            }
            "SunArc" => {
                let _ = writeln!(
                    out,
                    "{p}SunArc{{ width: Fill height: 90 draw_bg.rise: {} draw_bg.set: {} draw_bg.now: {} }}",
                    trim_num(num_of(arg(node, "rise"))),
                    trim_num(num_of(arg(node, "set"))),
                    trim_num(num_of(arg(node, "now"))),
                );
            }
            "MoonPhase" => {
                let _ = writeln!(
                    out,
                    "{p}MoonPhase{{ width: 64 height: 64 draw_bg.phase: {} }}",
                    trim_num(num_of(arg(node, "phase")))
                );
            }
            // Live satellite cloud imagery. An IMAGE rather than a shader, so it
            // is the one visualisation whose helper answers a URL — the widget
            // fetches what the URL points at, and the card said only where.
            "Satellite" => {
                let _ = writeln!(
                    out,
                    "{p}Image{{ width: Fill height: 190 fit: ImageFit.CropToFill \
                     src: http_resource(sys.satellite({}, {})) }}",
                    expr_of(node, "lat"),
                    expr_of(node, "lon")
                );
            }
            "AqiContour" => {
                // lat/lon/span, not a field: the widget fetches its own data.
                // Emitting `draw_bg.idx` was writing a GPU uniform from the
                // card, which is the ABI leak the widget was rewritten to end.
                let _ = writeln!(
                    out,
                    "{p}AqiContour{{ width: Fill height: 190 lat: {} lon: {} span: {} }}",
                    trim_num(num_of(arg(node, "lat"))),
                    trim_num(num_of(arg(node, "lon"))),
                    trim_num(num_of(arg(node, "span"))),
                );
            }
            "StockPlot" => {
                // The card names WHICH series; the widget fetches it. Emitting
                // neither left the chart empty on every card that used one.
                let _ = writeln!(
                    out,
                    "{p}StockPlot{{ width: Fill height: 180 symbol: {} range: {} }}",
                    text_of(arg(node, "symbol")),
                    text_of(arg(node, "range")),
                );
            }
            "Thumb" => {
                // A fixed 16:9 tile, the size a list row wants beside its text —
                // or a square mosaic cell when the card says so.
                let (w, h) = if matches!(arg(node, "shape"),
                    Some(NodeValue::Token(t)) if t == "square")
                {
                    (102, 102)
                } else {
                    (108, 61)
                };
                let _ = writeln!(
                    out,
                    "{p}Image{{ width: {w} height: {h} fit: ImageFit.CropToFill \
                     src: http_resource({}) }}",
                    expr_of(node, "src")
                );
            }
            "IndicatorPlot" => {
                // Same contract as StockPlot: the card names which countries
                // and which indicator, the widget fetches the series.
                let _ = writeln!(
                    out,
                    "{p}IndicatorPlot{{ width: Fill height: 210 countries: {} \
                     indicator: {} years: {} }}",
                    text_of(arg(node, "countries")),
                    text_of(arg(node, "indicator")),
                    expr_of(node, "years"),
                );
            }
            "Avatar" => {
                // A tinted initials circle; this backend's fixed palette stands
                // in for the theme's accent tint.
                let _ = writeln!(
                    out,
                    "{p}RoundedView{{ width: 36 height: 36 draw_bg.color: {ACTIVE} \
                     draw_bg.border_radius: 18.0 align: {{x: 0.5, y: 0.5}}"
                );
                let _ = writeln!(
                    out,
                    "{p}  TextCaption{{ text: {} draw_text.color: {TEXT} }}",
                    expr_of(node, "text")
                );
                let _ = writeln!(out, "{p}}}");
            }
            "Chip" => {
                // `active` selects the fill. Dropping it made every range chip
                // render identically, so a card could not show which was
                // selected — and the golden recorded that as correct.
                let on = matches!(arg(node, "active"), Some(NodeValue::Bool(true)));
                let (fill, ink) = if on { (ACTIVE, TEXT) } else { (PANEL, SOFT) };
                let _ = writeln!(
                    out,
                    "{p}RoundedView{{ width: Fit height: Fit draw_bg.color: {fill} \
                     draw_bg.border_radius: 12.0 padding: Inset{{left: 10 right: 10 top: 5 bottom: 5}}\
                     {}",
                    tap_binding(node)
                );
                let _ = writeln!(
                    out,
                    "{p}  TextCaption{{ text: {} draw_text.color: {ink} }}",
                    expr_of(node, "text")
                );
                let _ = writeln!(out, "{p}}}");
            }
            role if role.starts_with("Text") => {
                // `tint` colours by SIGN — the card says "tint by this number",
                // and which colours mean up and down is the runtime's to decide.
                let colour = match arg(node, "tint") {
                    Some(NodeValue::Number(n)) if *n > 0.0 => UP,
                    Some(NodeValue::Number(n)) if *n < 0.0 => DOWN,
                    _ => match role {
                        "TextCaption" => DIM,
                        "TextRow" => SOFT,
                        _ => TEXT,
                    },
                };
                // Only constrain the width when the card asked. Forcing
                // `width: Fill` made a long hero title wrap one character per
                // line — "Top Movers" became "Top / Mover / s" on device.
                let width = match token_arg(node, "width") {
                    Some("fill") => " width: Fill",
                    Some(_) => " width: Fit",
                    _ => "",
                };
                // Always through `valued`: it falls back to `text:` and
                // decorates either way.
                let body = valued(node);
                // A hero is sized for the ONE dominant value. "18°" fits at 62;
                // "$184.20" clipped off the right edge on device. Scaling to fit
                // is the runtime's call — the card says "this is the hero", not
                // "this is 62 points".
                //
                // Size from the REALIZED value, never from the emitted text. Once
                // a value lowers to a live call the emitted text is
                // `"$" + sys.stock("NVDA", "price")` — 33 characters of source
                // that render as six — so measuring it dropped the hero from 40pt
                // to 24pt and shifted the whole card up. The seeded value is a
                // sound proxy for the live one's LENGTH, which is all this needs.
                let size = if role == "TextHero" {
                    format!(
                        " draw_text.text_style.font_size: {}",
                        hero_points(node, &body)
                    )
                } else {
                    String::new()
                };
                let _ = writeln!(
                    out,
                    "{p}{role}{{{width} text: {body} draw_text.color: {colour}{size}{} }}",
                    tap_binding(node)
                );
            }
            // Content a swipe reveals — hidden until then. See the catalog.
            "Reveal" => {
                let _ = writeln!(
                    out,
                    "{p}l0reveal := View{{ width: Fill height: Fit flow: Down visible: false"
                );
                children(node, depth, out);
                let _ = writeln!(out, "{p}}}");
            }
            // The one role that lets a card receive something the user typed.
            //
            // This backend admitted `Field` and lowered none of it, so the nav
            // card's two editable rows — the whole of "the map planner cannot
            // change its origin or destination" — rendered as two red warnings.
            // The kit had it and this did not, which is the same one-backend gap
            // `Grid.cols` and `Map` were each found in: a role is admitted once
            // and must be lowered twice.
            //
            // `on_return` rather than a tap wrapper. A hit target over a text
            // input eats the focus and there is nothing left to type into, and the
            // payload here is what was TYPED — which does not exist until commit,
            // so the target is assembled at that moment. `$$` is where the typed
            // text goes.
            "Field" => {
                // A field that was not told a width FILLS, unlike a text run.
                // `Field(width: .fill)` is what every card writes and the row it
                // sits in is `Fit`, so a `Fit` field collapses to its content —
                // an empty one to nothing at all, which is a search box that
                // cannot be tapped.
                let width = match token_arg(node, "width") {
                    Some("fit") => " width: Fit",
                    _ => " width: Fill",
                };
                let target = match arg(node, "on_commit") {
                    Some(NodeValue::Event(event)) => {
                        let json = serde_json::json!({ "e": event, "k": node.key, "v": "$$" });
                        format!("l0:{json}")
                    }
                    _ => String::new(),
                };
                let (head, tail) = target.split_once("$$").unwrap_or((target.as_str(), ""));
                let commit = if target.is_empty() {
                    String::new()
                } else {
                    format!(
                        " on_return: |t| agent.notify(\"l0\", {{target: {head:?} + t + {tail:?}}})"
                    )
                };
                let _ = writeln!(
                    out,
                    "{p}TextInput{{{width} height: 48 text: {} empty_text: {}{commit} }}",
                    expr_of(node, "text"),
                    expr_of(node, "placeholder"),
                );
            }
            other => {
                // An unmapped constructor is shown, not skipped. A card that
                // silently drops a section looks correct and is not.
                let _ = writeln!(
                    out,
                    "{p}TextCaption{{ text: {:?} draw_text.color: #ffb4b4 }}",
                    format!("⚠ no makepad lowering for {other}")
                );
            }
        }
    }
}

// ────────────────────────────────────────────────────────────── instance state ──

use std::collections::BTreeMap;

/// The key card-scope state lives under. Card state has no instance, so it needs
/// a fixed cell rather than one derived from a position in the tree.
pub const CARD_STATE_KEY: &str = "@card";

/// Per-instance local state — the runtime's half of the immutable/mutable split.
///
/// The ledger declares a component's state *shape*; the values live here, keyed
/// by instance identity (§5.1). Seven `ForecastRow` instances therefore hold
/// seven independent cells, none of which appear in the card.
///
/// Nothing in the store is authored by the model. A card cannot name an
/// instance, cannot address another instance's cell, and cannot write anything
/// except through a declared transition on its own state.
#[derive(Clone, Debug, Default)]
pub struct InstanceStore {
    /// `instance-key` → field → value.
    cells: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    /// Component name → the schema id its live cells were written under.
    schemas: BTreeMap<String, u64>,
    /// Component name → state path → the shape that cell was written under.
    /// A `keep` cell is preserved across a schema change only when this still
    /// matches, so opting in never means "trust whatever was there".
    shapes: BTreeMap<String, BTreeMap<String, String>>,
}

impl InstanceStore {
    pub fn get(&self, key: &str, field: &str) -> Option<&serde_json::Value> {
        self.cells.get(key)?.get(field)
    }

    /// Write a cell. Public because a HOST owns when a captured initial becomes
    /// durable — see `RealizeReport::captured`. The realizer decides what was
    /// captured; only the host can decide it is now the state's value.
    pub fn set_cell(&mut self, key: &str, field: &str, value: serde_json::Value) {
        self.set(key, field, value);
    }

    fn set(&mut self, key: &str, field: &str, value: serde_json::Value) {
        self.cells
            .entry(key.to_string())
            .or_default()
            .insert(field.to_string(), value);
    }

    /// Whether `state` has the shape the store's live cells were written under.
    fn shape_unchanged(&self, component: &Component, state: &StateDecl) -> bool {
        self.shapes
            .get(&component.name)
            .and_then(|m| m.get(&state.path))
            .is_some_and(|old| *old == format!("{:?}", state.shape))
    }

    /// Drop every cell belonging to instances of `component`, except the fields
    /// listed in `keep` — §5.8's opt-in migration.
    fn reset_component(&mut self, component: &str, keep: &[String]) {
        let marker = format!("/{component}");
        self.cells.retain(|key, fields| {
            if !key.contains(&marker) {
                return true;
            }
            fields.retain(|field, _| keep.iter().any(|k| k == field));
            !fields.is_empty()
        });
    }

    /// Profile §5.8: a component whose state declarations changed gets a new
    /// schema id, and its live cells are dropped rather than migrated. Guessing
    /// that an old value still fits is how a rolled-back ledger feeds version-A
    /// state to version-B code.
    fn reconcile_schema(&mut self, component: &Component, schema: u64) {
        let name = component.name.as_str();
        let shapes: BTreeMap<String, String> = component
            .states
            .iter()
            .map(|s| (s.path.clone(), format!("{:?}", s.shape)))
            .collect();

        match self.schemas.get(name) {
            Some(&known) if known == schema => {}
            Some(_) => {
                // A cell survives only if it asked to AND its own shape is
                // unchanged. Opting in is a claim about one field, not a
                // blanket assertion that the old values still fit.
                let previous = self.shapes.get(name);
                let keep: Vec<String> = component
                    .states
                    .iter()
                    .filter(|s| s.keep)
                    .filter(|s| {
                        previous
                            .and_then(|p| p.get(&s.path))
                            .is_some_and(|old| *old == format!("{:?}", s.shape))
                    })
                    .map(|s| s.path.clone())
                    .collect();
                self.reset_component(name, &keep);
                self.schemas.insert(name.to_string(), schema);
                self.shapes.insert(name.to_string(), shapes);
            }
            None => {
                self.schemas.insert(name.to_string(), schema);
                self.shapes.insert(name.to_string(), shapes);
            }
        }
    }

    /// Forget instances that no longer appear — the unmount half of §5.7.
    pub fn prune(&mut self, live: &[String]) {
        self.cells.retain(|key, _| live.iter().any(|k| k == key));
    }

    pub fn len(&self) -> usize {
        self.cells.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
}

fn schema_id(component: &Component) -> u64 {
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    let mut fields: Vec<String> = component
        .states
        .iter()
        .map(|s| {
            format!(
                "{}:{:?}:{:?}:{:?}",
                s.path, s.shape, s.initial, s.initial_path
            )
        })
        .collect();
    fields.sort();
    for byte in fields.join(",").bytes() {
        acc ^= byte as u64;
        acc = acc.wrapping_mul(0x100_0000_01b3);
    }
    acc
}

fn initial_for(shape: &Shape) -> serde_json::Value {
    match shape {
        Shape::Bool => serde_json::Value::Bool(false),
        Shape::Enum(members) => members
            .first()
            .map(|m| serde_json::Value::String(m.clone()))
            .unwrap_or(serde_json::Value::Null),
        Shape::Text => serde_json::Value::String(String::new()),
        Shape::Number => serde_json::Value::from(0.0),
        Shape::Record | Shape::Collection | Shape::Event | Shape::Other => serde_json::Value::Null,
    }
}

/// Realize against a store, so component-local state resolves per instance.
///
/// [`realize`] is this with an empty store: a card with no local state behaves
/// identically either way.
pub fn realize_with_state(
    source: &str,
    data: &serde_json::Value,
    store: &InstanceStore,
    limits: RealizeLimits,
) -> RealizeReport {
    realize_inner(source, data, Some(store), limits)
}

/// Apply an event's transitions to one instance's cells.
///
/// Returns whether anything applied. The event name is resolved against the
/// component's *declarations* — a card cannot construct one, because it has no
/// expression form to build a name with.
pub fn dispatch(source: &str, store: &mut InstanceStore, instance_key: &str, event: &str) -> bool {
    dispatch_with(source, store, instance_key, event, None)
}

/// Apply an event's transitions, supplying the payload the raising element
/// carried in its `value:` argument.
///
/// The payload is data the runtime already holds — a bound path or a literal
/// resolved at realization — never anything the card computed.
pub fn dispatch_with(
    source: &str,
    store: &mut InstanceStore,
    instance_key: &str,
    event: &str,
    payload: Option<&serde_json::Value>,
) -> bool {
    dispatch_with_data(
        source,
        store,
        instance_key,
        event,
        payload,
        &serde_json::Value::Null,
    )
}

/// `dispatch_with`, plus the data a `set(path)` reads from.
///
/// Separated rather than folded in because most events do not read: `toggle`,
/// `cycle`, `clear` and `set(.token)` need nothing. Only a transition that
/// names a path needs the host's data, and passing Null simply makes that one
/// form a no-op instead of writing something wrong.
/// Apply an event's transitions, with the data a path-valued initial resolves
/// against.
///
/// Returns only whether anything applied. `dispatch_reporting` returns that plus
/// what went stale, and is what a host driving refetch should call.
pub fn dispatch_with_data(
    source: &str,
    store: &mut InstanceStore,
    instance_key: &str,
    event: &str,
    payload: Option<&serde_json::Value>,
    data: &serde_json::Value,
) -> bool {
    let (changed, durable) = dispatch_writes(source, store, instance_key, event, payload, data);
    !changed.is_empty() || !durable.is_empty()
}

/// A write to a durable collection that the HOST must perform (§5.12).
///
/// L0 reports it and never performs it, exactly as `source_plan` reports a fetch
/// it never performs. The card names a capability; only the host knows what
/// answers it, and only the host owns the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionWrite {
    /// The declared source name the card wrote through — `watch`.
    pub source: String,
    /// The capability behind it — `sys.watchlist`.
    pub helper: String,
    /// `append`, `remove`, `set` or `clear`, already checked against what the
    /// capability declares it accepts.
    pub op: String,
    /// The payload the tapped element carried. Empty for `clear`.
    pub value: String,
    /// For a KEYED capability (`sys.prefs`), the key the write lands under —
    /// the source's single declared field, which the checker guarantees exists.
    /// Empty for list capabilities, whose store is named by the helper alone.
    pub field: String,
}

/// What a dispatch did, and what it obliges the host to do next.
///
/// `dispatch_with_data` returns a bare `bool`, which is enough to know a tap was
/// not ignored and not enough to act on. §5.9 says a source parameterised by
/// state goes stale when that state changes, and a host holding only `true` has
/// no way to find out which. The pieces to compute it existed — `stale_sources`
/// and `source_plan` — and nothing joined them, so the stock card's detail view
/// worked only because its test data already contained a quote it never asked
/// for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DispatchOutcome {
    /// Whether any transition committed. False means refused or unknown — see
    /// §3, a batch that does not fully resolve does not partially apply.
    pub applied: bool,
    /// The state paths whose value MOVED, in the order the batch wrote them. A
    /// transition that writes the value already there is committed and not
    /// reported: a host rebuilds on any non-empty outcome, and rebuilding a card
    /// to redraw the identical screen is the cost of tapping a selected chip.
    pub changed: Vec<String>,
    /// The declared sources those writes invalidate, following the dependency
    /// cascade. The host should refetch these before the next realization.
    pub stale: Vec<String>,
    /// §5.12 writes the host must perform against its durable store, in order.
    /// L0 reports them and never performs them.
    pub writes: Vec<CollectionWrite>,
}

/// Apply an event and report what it invalidated.
///
/// This is `dispatch_with_data` plus the answer to "and now what?". Prefer it
/// in a host: the bool-returning form cannot drive a refetch, which is the
/// whole point of letting a source take state as an argument.
pub fn dispatch_reporting(
    source: &str,
    store: &mut InstanceStore,
    instance_key: &str,
    event: &str,
    payload: Option<&serde_json::Value>,
    data: &serde_json::Value,
) -> DispatchOutcome {
    let (changed, writes) = dispatch_writes(source, store, instance_key, event, payload, data);
    if changed.is_empty() && writes.is_empty() {
        return DispatchOutcome::default();
    }
    // `stale_sources` takes the changed names; a write to `selected` is a change
    // to `selected` as a source argument reads it.
    //
    // A durable write invalidates the source it wrote THROUGH, and anything
    // reading that source, by the same cascade. Appending to a watchlist and not
    // refetching it is a card that swallowed the tap.
    let mut names: Vec<&str> = changed.iter().map(String::as_str).collect();
    names.extend(writes.iter().map(|w| w.source.as_str()));
    let mut stale = stale_sources(source, &names);
    for w in &writes {
        if !stale.contains(&w.source) {
            stale.push(w.source.clone());
        }
    }
    DispatchOutcome {
        applied: true,
        changed,
        stale,
        writes,
    }
}

fn dispatch_writes(
    source: &str,
    store: &mut InstanceStore,
    instance_key: &str,
    event: &str,
    payload: Option<&serde_json::Value>,
    data: &serde_json::Value,
) -> (Vec<String>, Vec<CollectionWrite>) {
    let mut sink = Diagnostics::default();
    let Some(tokens) = lex(source, &mut sink) else {
        return (Vec::new(), Vec::new());
    };
    let card = Parser::new(&tokens, &mut sink).parse_card();

    // A backend dispatches with the key of the NODE that was tapped, which sits
    // inside the component rather than at its boundary — `…/Rowy/0/1`. The cell
    // belongs to the instance, so the key is truncated to the component segment.
    // Where components nest, the innermost one declaring this event wins.
    let mut owner: Option<(&Component, usize)> = None;
    for component in &card.components {
        if !component.events.iter().any(|e| e.name == event) {
            continue;
        }
        let marker = format!("/{}", component.name);
        if let Some(at) = instance_key.rfind(&marker) {
            let end = at + marker.len();
            // Only a whole segment matches: `/Row` must not match `/Rowy`.
            let whole = instance_key[end..]
                .chars()
                .next()
                .is_none_or(|c| c == '/' || c == '[');
            if whole && owner.as_ref().is_none_or(|(_, best)| end > *best) {
                owner = Some((component, end));
            }
        }
    }
    // An event declared on the CARD rather than a component targets card state,
    // which lives under a fixed key. A component event wins when both declare the
    // name, since the innermost scope owns the cell.
    let (declared, states, instance_key, schema_owner) = match owner {
        Some((component, boundary)) => match component.events.iter().find(|e| e.name == event) {
            Some(d) => (
                d,
                &component.states,
                &instance_key[..boundary],
                Some((component, schema_id(component))),
            ),
            None => return (Vec::new(), Vec::new()),
        },
        None => match card.events.iter().find(|e| e.name == event) {
            Some(d) => (d, &card.states, CARD_STATE_KEY, None),
            None => return (Vec::new(), Vec::new()),
        },
    };

    if let Some((component, schema)) = schema_owner {
        store.reconcile_schema(component, schema);
    }

    // §3: a batch is applied ATOMICALLY. Writing straight to the store as we go
    // left the earlier writes standing when a later one could not be computed —
    // a half-applied event, which is the thing atomicity exists to prevent.
    // Stage every write first, commit only if the whole batch resolves.
    // (target, next, effective current) — the third is what decides whether this
    // transition is a change at all.
    let mut staged: Vec<(String, serde_json::Value, serde_json::Value)> = Vec::new();
    // §5.12 writes are staged alongside the cells, so §3's atomicity covers both:
    // a batch that sets a preference AND appends to a list must do neither if the
    // preference cannot be resolved.
    let mut durable: Vec<CollectionWrite> = Vec::new();

    for transition in &declared.transitions {
        // A source target leaves the card. Nothing is written here — the host
        // owns the store — so this records the write and moves on, the same way
        // `source_plan` records a fetch it will never perform.
        if let Some(decl) = card.sources.iter().find(|s| s.name == transition.target) {
            let op = match &transition.form {
                Form::Append => "append",
                Form::Remove => "remove",
                Form::Clear => "clear",
                Form::Set(_) => "set",
                _ => return (Vec::new(), Vec::new()),
            };
            // All but `clear` carry the payload, so a tap without one is a no-op
            // rather than a write of nothing — the same choice `set` makes.
            let value = match (op, payload) {
                ("clear", _) => String::new(),
                (_, Some(serde_json::Value::String(v))) => v.clone(),
                (_, Some(v)) => v.to_string(),
                (_, None) => return (Vec::new(), Vec::new()),
            };
            let field = decl
                .args
                .iter()
                .find(|(n, _)| n == "fields")
                .and_then(|(_, a)| match a {
                    SourceArg::List(l) if l.len() == 1 => Some(l[0].clone()),
                    _ => None,
                })
                .unwrap_or_default();
            durable.push(CollectionWrite {
                source: decl.name.clone(),
                helper: decl.helper.clone(),
                op: op.to_owned(),
                value,
                field,
            });
            continue;
        }
        let Some(state) = states.iter().find(|s| s.path == transition.target) else {
            return (Vec::new(), Vec::new());
        };
        // The declared initial, path-valued or not. `clear` and a first `cycle`
        // both fell back to the SHAPE default here, so a card whose initial
        // comes from the host started in the wrong state.
        let declared_initial = state
            .initial
            .clone()
            .or_else(|| state.initial_path.as_ref().and_then(|p| data_path(data, p)));

        let current = staged
            .iter()
            .rev()
            .find(|(t, _, _)| *t == transition.target)
            .map(|(_, v, _)| v.clone())
            .or_else(|| store.get(instance_key, &transition.target).cloned())
            // The HOST-SEEDED value, and it has to be here because it is here in
            // the renderer.
            //
            // Card state resolves store → data → initial when the screen is drawn.
            // A transition resolved store → initial, skipping the middle, so a
            // state the host seeded was cycled from a value nobody was looking at:
            // the nav card seeded `screen: "drive"`, the drive screen rendered, and
            // `End` — a `cycle(.plan, .drive)` — read the declared initial `.plan`
            // and advanced to `.drive`. The tap applied, the store changed, the card
            // re-resolved, and it landed on the screen it was already on. Every
            // layer reported success.
            //
            // Card scope only, since that is the only scope the renderer reads the
            // blob for; a component's cells are per-instance and have no key in it.
            .or_else(|| {
                (instance_key == CARD_STATE_KEY)
                    .then(|| data.get(&transition.target).cloned())
                    .flatten()
            })
            .or_else(|| declared_initial.clone())
            .unwrap_or_else(|| initial_for(&state.shape));

        let next = match (&transition.form, &state.shape) {
            (Form::Toggle, Shape::Bool) => {
                serde_json::Value::Bool(!current.as_bool().unwrap_or(false))
            }
            (Form::Clear, shape) => declared_initial
                .clone()
                .unwrap_or_else(|| initial_for(shape)),
            (Form::Cycle, Shape::Enum(members)) if !members.is_empty() => {
                let at = current
                    .as_str()
                    .and_then(|s| members.iter().position(|m| m == s))
                    .unwrap_or(0);
                serde_json::Value::String(members[(at + 1) % members.len()].clone())
            }
            // The collection walk. Rows come from the dispatch data — the
            // host merges durable rows in before dispatch — and the walk wraps.
            // A value not in the list lands on the first (next) or last (prev)
            // row: the swipe that discovers the list starts at its edge.
            (Form::Next(path) | Form::Prev(path), Shape::Text) => {
                let forward = matches!(&transition.form, Form::Next(_));
                let (root, field) = path.split_once('.').unwrap_or((path.as_str(), ""));
                let rows: Vec<String> = data
                    .get(root)
                    .and_then(|v| v.as_array())
                    .map(|rows| {
                        rows.iter()
                            .filter_map(|r| r.get(field))
                            .filter_map(|v| v.as_str())
                            .map(|s| s.to_owned())
                            .collect()
                    })
                    .unwrap_or_default();
                if rows.is_empty() {
                    // Nothing to walk: refuse the batch so the gesture that
                    // carried it falls through instead of consuming the swipe.
                    return (Vec::new(), Vec::new());
                }
                let here = current
                    .as_str()
                    .and_then(|c| rows.iter().position(|r| r == c));
                let at = match (here, forward) {
                    (Some(i), true) => (i + 1) % rows.len(),
                    (Some(i), false) => (i + rows.len() - 1) % rows.len(),
                    (None, true) => 0,
                    (None, false) => rows.len() - 1,
                };
                serde_json::Value::String(rows[at].clone())
            }
            (Form::Set(source), _) => match source {
                SetSource::Payload => match payload {
                    // The one value that arrives from OUTSIDE, so it is the one
                    // that has to be checked at runtime: every other set form is
                    // decided against the declared shape at check time.
                    Some(v) if value_fits_shape(&state.shape, v) => v.clone(),
                    Some(_) => return (Vec::new(), Vec::new()),
                    // No payload is a no-op rather than a silent clear: falling
                    // back to the initial would look like a deliberate reset.
                    None => return (Vec::new(), Vec::new()),
                },
                // A path READS. Treating it as the payload meant
                // `n: set(config.answer)` wrote whatever the tap carried — or
                // nothing at all when it carried nothing.
                SetSource::Path(p) => match data_path(data, p) {
                    Some(v) if value_fits_shape(&state.shape, &v) => v,
                    // Unresolvable or ill-shaped: the batch cannot complete, and
                    // §3 says a batch is all or nothing.
                    _ => return (Vec::new(), Vec::new()),
                },
                SetSource::Token(t) | SetSource::Text(t) => serde_json::Value::String(t.clone()),
                SetSource::Num(n) => serde_json::Value::from(*n),
                SetSource::Bool(b) => serde_json::Value::Bool(*b),
            },
            _ => return (Vec::new(), Vec::new()),
        };
        staged.push((transition.target.clone(), next, current));
    }

    // Commit, and report what CHANGED. The targets are what a host needs to know
    // which sources went stale -- discarding them is why §5.9's invalidation
    // story had pieces that nothing joined.
    //
    // A transition that writes the value already there is not a change, and
    // reporting it as one is not free: a host rebuilds a card on any non-empty
    // outcome, so tapping the already-selected chip cost a full realize, a full
    // lowering, a full VM pass over every live call on the card, and a widget
    // rebuild -- to arrive at the identical screen. Measured on the stock card,
    // that is 11 nodes and every `sys.movers` call re-issued for nothing; the
    // weather card is 62 nodes and 28 calls.
    //
    // The comparison is against the EFFECTIVE current value -- an earlier write
    // in this same batch, else the stored cell, else the declared initial -- so
    // a first tap that selects what was already the initial is a no-op too.
    //
    // The batch is still staged and validated in full before any of this: §3's
    // atomicity is about whether a batch may partially apply, not about which of
    // its transitions moved. A batch that sets one cell to a new value and
    // another to the value it holds reports the first and rebuilds once.
    let mut written = Vec::new();
    for (target, value, previous) in staged {
        let unchanged = value == previous;
        store.set(instance_key, &target, value);
        if unchanged || written.contains(&target) {
            continue;
        }
        written.push(target);
    }
    (written, durable)
}

// ───────────────────────────────────────────────────────────────── source plan ──

/// One capability query for the host to answer, with the name its result binds.
#[derive(Clone, Debug)]
pub struct SourceRequest {
    /// The name the card binds the result to — `now`, `week`, `env.locale`.
    pub name: String,
    /// The helper that answers it — `sys.weather`. Resolving this to an actual
    /// function is the HOST's job; splash-core never calls anything.
    pub helper: String,
    pub args: Vec<(String, SourceArg)>,
    /// Names of other sources this one reads. The host must resolve those first.
    pub depends_on: Vec<String>,
}

/// What a card needs fetched, in an order that satisfies its dependencies.
#[derive(Clone, Debug, Default)]
pub struct SourcePlan {
    pub requests: Vec<SourceRequest>,
    pub diagnostics: Vec<SyntaxDiagnostic>,
}

/// Read a card's `source` declarations and order them for resolution.
///
/// Sources form a DAG: `source now sys.weather(lat: place.lat, …)` cannot be
/// fetched before `place`. The order is topological, so a host can walk the list
/// and always have what the next request refers to.
///
/// This returns *what to fetch*, never fetches it. The card names a helper; only
/// the host knows what answers it. That separation is what lets realization run
/// against an empty host surface.
/// Each state's DECLARED literal initial, by path.
///
/// A host that has to resolve a source argument BEFORE realize — `sys.indicator
/// (countries: state.countries)` has to know which countries to ask about
/// before there is a tree — cannot read it from the store (nothing has been
/// written yet) or from the seed data (an initial is a declaration, not data).
/// It is in the card, and this is how a host reads it. Path-valued initials
/// (`initial: env.locale.temp_unit`) are absent here on purpose: they resolve
/// against injected data at realization, which is after this is useful.
pub fn state_initials(source: &str) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut sink = Diagnostics::default();
    let Some(tokens) = lex(source, &mut sink) else {
        return std::collections::BTreeMap::new();
    };
    let card = Parser::new(&tokens, &mut sink).parse_card();
    card.states
        .iter()
        .filter_map(|st| st.initial.clone().map(|v| (st.path.clone(), v)))
        .collect()
}

/// The theme this card declares, or `None` for the default.
///
/// The card names a MOOD; resolving it into colours is the component kit's job
/// (§1.1's middle layer), so this hands the host a catalogued name and nothing
/// else. A name absent from [`catalog::THEMES`] never reaches here — the parser
/// refuses it — so a host may treat whatever it gets as answerable, and treat
/// `None` as "the kit's default".
///
/// Read before realize, like [`state_initials`]: the palette has to be chosen to
/// build the source the kit is concatenated into, which is earlier than a tree.
/// The theme axes a card declares beside its mood, in source order.
///
/// Read before realize for the same reason [`card_theme`] is: a host choosing
/// a palette needs the card's stated intent, and that is a fact about the
/// source rather than about a realized tree.

/// The theme's default answer for each semantic icon name — Font Awesome
/// solid codepoints, resolved AT LOWER TIME so the kit never carries a string
/// table and the card never carries a glyph.
pub fn icon_glyph(name: &str) -> &'static str {
    match name {
        "activity" => "\u{f201}",
        "alert" => "\u{f071}",
        "arrow_down" => "\u{f063}",
        "arrow_left" => "\u{f060}",
        "arrow_right" => "\u{f061}",
        "arrow_up" => "\u{f062}",
        "bell" => "\u{f0f3}",
        "bookmark" => "\u{f02e}",
        "calendar" => "\u{f073}",
        "camera" => "\u{f030}",
        "chat" => "\u{f075}",
        "check" => "\u{f00c}",
        "chevron_down" => "\u{f078}",
        "chevron_left" => "\u{f053}",
        "chevron_right" => "\u{f054}",
        "chevron_up" => "\u{f077}",
        "clock" => "\u{f017}",
        "close" => "\u{f00d}",
        "cloud" => "\u{f0c2}",
        "edit" => "\u{f304}",
        "filter" => "\u{f0b0}",
        "heart" => "\u{f004}",
        "home" => "\u{f015}",
        "image" => "\u{f03e}",
        "info" => "\u{f129}",
        "location" => "\u{f3c5}",
        "lock" => "\u{f023}",
        "mail" => "\u{f0e0}",
        "map" => "\u{f279}",
        "menu" => "\u{f0c9}",
        "mic" => "\u{f130}",
        "minus" => "\u{f068}",
        "moon" => "\u{f186}",
        "more" => "\u{f141}",
        "phone" => "\u{f095}",
        "play" => "\u{f04b}",
        "plus" => "\u{f067}",
        "refresh" => "\u{f021}",
        "search" => "\u{f002}",
        "send" => "\u{f1d8}",
        "settings" => "\u{f013}",
        "share" => "\u{f064}",
        "star" => "\u{f005}",
        "sun" => "\u{f185}",
        "trash" => "\u{f1f8}",
        "user" => "\u{f007}",
        "users" => "\u{f0c0}",
        "video" => "\u{f03d}",
        "wifi" => "\u{f1eb}",
        "zap" => "\u{f0e7}",
        _ => "\u{f128}", // question — unreachable behind the Token set
    }
}

pub fn card_theme_axes(source: &str) -> Vec<(String, String)> {
    let mut sink = Diagnostics::default();
    let Some(tokens) = lex(source, &mut sink) else {
        return Vec::new();
    };
    Parser::new(&tokens, &mut sink).parse_card().theme_axes
}

pub fn card_theme(source: &str) -> Option<String> {
    let mut sink = Diagnostics::default();
    let tokens = lex(source, &mut sink)?;
    Parser::new(&tokens, &mut sink)
        .parse_card()
        .theme
        .map(|(name, _)| name)
}

/// The ROLE the card's root view names — `Surface`, `Photo`, `Map`.
///
/// Read before realize, like [`card_theme`], and for the same reason: a host
/// choosing a palette has to know whether the page is a PHOTOGRAPH, and that is a
/// fact about the source rather than about a realized tree. The pairing matters
/// because a mood with dark ink is unreadable over an arbitrary image, so a kit
/// may legitimately answer `light` + `Photo` with its photo palette.
///
/// `None` when the card declares no `root` view — which the checker refuses, so a
/// caller seeing `None` has a card that was not going to render anyway.
pub fn card_root_role(source: &str) -> Option<String> {
    let mut sink = Diagnostics::default();
    let tokens = lex(source, &mut sink)?;
    Parser::new(&tokens, &mut sink)
        .parse_card()
        .views
        .iter()
        .find(|v| v.name == "root")
        .map(|v| v.body.name.clone())
}

/// The (source, field) pairs a card GUARDS on — `when now.precip >= 40` gives
/// `("now", "precip")`.
///
/// Guards are evaluated at realize time against injected data, and a host injects
/// list rows and little else, so a guard on a live scalar compares against
/// nothing and BOTH complementary branches are false. That renders a card with a
/// correct header and no answer, which is the §1.1 failure. A host can close it
/// by resolving exactly these before realize — exactly these, because resolving
/// every field of every source would fire a request per field per render.
///
/// NOT SUFFICIENT ON ITS OWN, and the attempt that produced this says why. A
/// guarded field is reached by a call built from its source's ARGUMENTS, and
/// those are frequently paths into another source: weather-activity guards
/// `now.precip`, `now` takes `lat: place.lat`, and `place` is a `sys.geocode`
/// scalar that is not in the blob either. Resolving guarded fields therefore
/// needs the scalar sources resolved in DEPENDENCY ORDER first — geocode, then
/// weather — which is most of what realize does. This accessor is the part that
/// is cheap and knowable; the ordering is the work.
///
/// `$state` fields are excluded: the lifecycle is already observed separately.
/// State paths are excluded because only a declared SOURCE needs fetching.
/// Guards inside a `component` are not walked — no shipped card has one, and a
/// component reads its props rather than a card-level source.
pub fn guarded_source_fields(source: &str) -> Vec<(String, String)> {
    let mut sink = Diagnostics::default();
    let Some(tokens) = lex(source, &mut sink) else {
        return Vec::new();
    };
    let card = Parser::new(&tokens, &mut sink).parse_card();
    guarded_fields_of(&card)
}

fn guarded_fields_of(card: &Card) -> Vec<(String, String)> {
    let sources: std::collections::BTreeSet<String> =
        card.sources.iter().map(|s| s.name.clone()).collect();
    let mut out: Vec<(String, String)> = Vec::new();
    fn walk(
        el: &Element,
        sources: &std::collections::BTreeSet<String>,
        out: &mut Vec<(String, String)>,
    ) {
        if el.name == "when" {
            if let Some(a) = el.args.first() {
                if let Operand::Path(p) = &a.value {
                    if let Some((head, field)) = p.split_once('.') {
                        if sources.contains(head) && !field.starts_with('$') && !field.contains('.')
                        {
                            let pair = (head.to_owned(), field.to_owned());
                            if !out.contains(&pair) {
                                out.push(pair);
                            }
                        }
                    }
                }
            }
        }
        for c in &el.children {
            walk(c, sources, out);
        }
    }
    for v in &card.views {
        walk(&v.body, &sources, &mut out);
    }
    out
}

/// One value a guard reads, and the call that answers it.
#[derive(Clone, Debug)]
pub struct GuardBinding {
    /// The source the guard names — `now`.
    pub source: String,
    /// The field within it — `precip`.
    pub field: String,
    /// What to ask, resolved exactly as it would be for a DISPLAY binding of the
    /// same path — so the branch is decided on the number the screen shows.
    pub binding: SourceBinding,
}

/// What a host must resolve BEFORE realize, so the card's value guards have
/// something to compare against.
///
/// Guards are decided during realize, against injected data. A fetched scalar is
/// not in that data — the kit resolves it lazily at draw time — so a
/// `when now.precip >= 40` compared against nothing, and so did its complement
/// `when now.precip < 40`. Both false: measured on a 6T, `weather-activity` drew
/// a correct header, a correct rain tile reading 100 %, and no verdict at all.
///
/// The FETCH POLICY this answers is the card's own: a `when` on a value is the
/// card saying it needs that value early. A card with no value guards asks for
/// nothing here and pays nothing, which is why this can be unconditional in the
/// render path where resolving every scalar of every source could not.
///
/// Dependencies come out resolved because `source_binding` already emits a
/// source argument as the callee's own live call — `now` takes `lat: place.lat`,
/// and `place` is a geocode this never has to fetch separately.
pub fn guard_bindings(
    source: &str,
    data: &serde_json::Value,
    store: &InstanceStore,
) -> Vec<GuardBinding> {
    resolved_bindings(source, data, store, guarded_fields_of)
}

/// A probe binding for each source whose LIFECYCLE a `when` reads.
///
/// `$state` was observed by walking the realized tree for bindings, which makes
/// it a property of what RENDERED rather than of the fetch. A card that gates its
/// rows on the state it is waiting for is then a closed loop:
///
/// ```text
/// when parks.$state == .pending { TextBody(text: copy.loading) }
/// when parks.$state == .ready   { Panel { for p, i in parks … } }
/// ```
///
/// no data -> pending -> the rows do not realize -> nothing binds `parks` ->
/// no status is written -> pending. Forever. Measured on the 6T: the activity
/// card for Beijing drew "Finding places nearby…" and nothing else, with
/// `L0 $state:` logging empty on every realize. It is the shipped EXEMPLAR's
/// shape, so every generated activity card inherited it, and the two apps that
/// escape do so by accident — `weather-activity` puts its `for` beside the
/// pending guard rather than behind a ready one, and `quake`'s gated feed shares
/// a helper with an ungated lead.
///
/// The field is left EMPTY: which one answers is the backend's business, and a
/// lifecycle is a property of the fetch, so any field the helper answers reports
/// the same thing.
pub fn guarded_state_bindings(
    source: &str,
    data: &serde_json::Value,
    store: &InstanceStore,
) -> Vec<GuardBinding> {
    resolved_bindings(source, data, store, guarded_states_of)
}

/// One probe binding per DECLARED source — so a host can observe each source's
/// lifecycle independently.
///
/// The alternative was observing per HELPER and stamping the worst state onto
/// every source that names it, and the nav card is why that cannot stand: it
/// declares five `sys.route` trips, and the one that is UNANSWERABLE by design
/// (`trip`, whose origin is the empty string on a from-here journey) held its
/// four siblings at `.pending` forever. `trip_here` had a real origin, a real
/// destination and a 200 route on the wire — and Go never appeared, because the
/// helper's merged state was decided by a sibling that asks a question nobody
/// posed. Measured: "Finding a route…", indefinitely, with zero failed fetches.
pub fn source_state_bindings(
    source: &str,
    data: &serde_json::Value,
    store: &InstanceStore,
) -> Vec<GuardBinding> {
    fn all_sources_of(card: &Card) -> Vec<(String, String)> {
        card.sources
            .iter()
            .map(|s| (s.name.clone(), String::new()))
            .collect()
    }
    resolved_bindings(source, data, store, all_sources_of)
}

/// Sources whose `$state` a `when` reads, as `(name, "")` — the empty field is
/// what makes each a probe rather than a value.
fn guarded_states_of(card: &Card) -> Vec<(String, String)> {
    let sources: std::collections::BTreeSet<String> =
        card.sources.iter().map(|s| s.name.clone()).collect();
    let mut out: Vec<(String, String)> = Vec::new();
    fn walk(
        el: &Element,
        sources: &std::collections::BTreeSet<String>,
        out: &mut Vec<(String, String)>,
    ) {
        if el.name == "when" {
            if let Some(a) = el.args.first() {
                if let Operand::Path(p) = &a.value {
                    if let Some(name) = p.strip_suffix(".$state") {
                        if sources.contains(name) {
                            let pair = (name.to_owned(), String::new());
                            if !out.contains(&pair) {
                                out.push(pair);
                            }
                        }
                    }
                }
            }
        }
        for c in &el.children {
            walk(c, sources, out);
        }
    }
    for v in &card.views {
        walk(&v.body, &sources, &mut out);
    }
    out
}

fn resolved_bindings(
    source: &str,
    data: &serde_json::Value,
    store: &InstanceStore,
    select: fn(&Card) -> Vec<(String, String)>,
) -> Vec<GuardBinding> {
    let mut sink = Diagnostics::default();
    let Some(tokens) = lex(source, &mut sink) else {
        return Vec::new();
    };
    let card = Parser::new(&tokens, &mut sink).parse_card();
    let wanted = select(&card);
    if wanted.is_empty() {
        return Vec::new();
    }

    // The same resolution order realize uses for card state, because a source
    // argument reaches state — `sys.geocode(name: state.city)` — and resolving
    // it differently here would ask about a different place than the card draws.
    let mut frames: Vec<Frame> = Vec::new();
    for state in &card.states {
        let value = store
            .get(CARD_STATE_KEY, &state.path)
            .cloned()
            .or_else(|| data.get(&state.path).cloned())
            .or_else(|| state.initial.clone())
            .or_else(|| state.initial_path.as_ref().and_then(|p| data_path(data, p)))
            .unwrap_or_else(|| initial_for(&state.shape));
        frames.push((state.path.clone(), value, None));
    }
    let scope = ValueScope {
        frames,
        data,
        copies: &card.copies,
    };
    let ctx = Realizer {
        depth: 0,
        card: &card,
        limits: RealizeLimits::default(),
        nodes: 0,
        truncated: false,
        sink: &mut sink,
        store: Some(store),
        live: Vec::new(),
        slots: Vec::new(),
    };
    wanted
        .into_iter()
        .filter_map(|(name, field)| {
            let path = if field.is_empty() {
                name.clone()
            } else {
                format!("{name}.{field}")
            };
            let binding = ctx.source_binding(&path, &scope)?;
            Some(GuardBinding {
                source: name,
                field,
                binding,
            })
        })
        .collect()
}

pub fn source_plan(source: &str) -> SourcePlan {
    let mut sink = Diagnostics::default();
    let Some(tokens) = lex(source, &mut sink) else {
        return SourcePlan {
            requests: Vec::new(),
            diagnostics: sink.items,
        };
    };
    let card = Parser::new(&tokens, &mut sink).parse_card();

    // The plan is what a host acts on, so the capability check has to happen
    // HERE too and not only in `check_ui_l0`. A caller that skips checking must
    // still not be handed `sys.shell` as a function to resolve.
    validate_sources(&card, &mut sink);

    let declared: Vec<&str> = card.sources.iter().map(|s| s.name.as_str()).collect();

    let mut pending: Vec<SourceRequest> = card
        .sources
        .iter()
        .filter(|decl| catalog::source(&decl.helper).is_some())
        .map(|decl| {
            let mut depends_on: Vec<String> = decl
                .args
                .iter()
                .filter_map(|(_, arg)| match arg {
                    SourceArg::Path(p) => {
                        // Match a declared name by its own segments, longest
                        // first: `env.locale.lang` depends on `env.locale`.
                        // Reducing to the root compared `env` against the full
                        // name and recorded no edge at all, so the dependent
                        // was planned before the thing it reads.
                        let mut hits: Vec<&&str> = declared
                            .iter()
                            .filter(|d| {
                                *p == ***d
                                    || p.strip_prefix(**d).is_some_and(|r| r.starts_with('.'))
                            })
                            .collect();
                        hits.sort_by_key(|d| std::cmp::Reverse(d.len()));
                        hits.first().map(|d| (**d).to_string())
                    }
                    _ => None,
                })
                .collect();
            depends_on.sort();
            depends_on.dedup();
            SourceRequest {
                name: decl.name.clone(),
                helper: decl.helper.clone(),
                args: decl.args.clone(),
                depends_on,
            }
        })
        .collect();

    // Topological order. A cycle is reported rather than resolved: two sources
    // that read each other cannot both go first, and picking one silently would
    // fetch against a value that does not exist yet.
    let mut ordered: Vec<SourceRequest> = Vec::new();
    let mut done: Vec<String> = Vec::new();
    while !pending.is_empty() {
        let ready: Vec<usize> = pending
            .iter()
            .enumerate()
            .filter(|(_, r)| r.depends_on.iter().all(|d| done.iter().any(|n| n == d)))
            .map(|(i, _)| i)
            .collect();

        if ready.is_empty() {
            for stuck in &pending {
                sink.push(
                    card.sources
                        .iter()
                        .find(|d| d.name == stuck.name)
                        .map(|d| d.line)
                        .unwrap_or(0),
                    1,
                    format!(
                        "source {:?} is in a dependency cycle with {:?}",
                        stuck.name,
                        stuck.depends_on.join(", ")
                    ),
                );
            }
            break;
        }

        for i in ready.into_iter().rev() {
            let request = pending.remove(i);
            done.push(request.name.clone());
            ordered.push(request);
        }
    }

    SourcePlan {
        requests: ordered,
        diagnostics: sink.items,
    }
}

// ─────────────────────────────────────────────────────────────── reconciliation ──

/// What one record reads, so a state write can be confined to its dependents.
#[derive(Clone, Debug)]
pub struct RecordDeps {
    /// A `view` or `component` name.
    pub record: String,
    /// Roots it reads, transitively through referenced views and instantiated
    /// components — `now`, `units`, `week`.
    pub reads: Vec<String>,
}

/// What each record reads.
///
/// L0 needs no dynamic read-tracking: it has no expression form, so every
/// binding is structurally visible and the dependency set is computable without
/// evaluating anything. That is the difference between this and the signal
/// graphs a dynamic language requires — there is no branch whose reads depend on
/// a value.
///
/// The set is transitive and deliberately **over**-approximate at the edges: a
/// record inherits everything the views it splices and the components it
/// instantiates read. Over-approximating re-realizes too much; under-
/// approximating shows stale data, and only one of those is a correctness bug.
pub fn record_dependencies(source: &str) -> Vec<RecordDeps> {
    let mut sink = Diagnostics::default();
    let Some(tokens) = lex(source, &mut sink) else {
        return Vec::new();
    };
    let card = Parser::new(&tokens, &mut sink).parse_card();

    // Direct reads, plus the records each one pulls in.
    let mut direct: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    for view in &card.views {
        let (reads, pulls) = scan_element(&view.body);
        direct.push((view.name.clone(), reads, pulls));
    }
    for component in &card.components {
        let (mut reads, pulls) = scan_element(&component.body);
        // A prop is supplied by the caller, so it is not a dependency of its own.
        reads.retain(|r| !component.params.iter().any(|p| p.name == *r));
        // Local state is a dependency: writing it must re-realize this instance.
        for state in &component.states {
            reads.push(root_of(&state.path));
        }
        direct.push((component.name.clone(), reads, pulls));
    }

    // Close over references. Bounded by record count, so a reference cycle
    // terminates rather than spinning.
    let mut out: Vec<RecordDeps> = Vec::new();
    for (name, _, _) in &direct {
        let mut reads: Vec<String> = Vec::new();
        let mut queue = vec![name.clone()];
        let mut seen: Vec<String> = Vec::new();
        let mut steps = 0usize;
        while let Some(current) = queue.pop() {
            steps += 1;
            if steps > MAX_UI_L0_DECLARATIONS || seen.contains(&current) {
                continue;
            }
            seen.push(current.clone());
            if let Some((_, r, pulls)) = direct.iter().find(|(n, _, _)| *n == current) {
                reads.extend(r.iter().cloned());
                queue.extend(pulls.iter().cloned());
            }
        }
        reads.sort();
        reads.dedup();
        out.push(RecordDeps {
            record: name.clone(),
            reads,
        });
    }
    out
}

/// The smallest set of records a backend must re-realize.
///
/// [`dirty_records`] is transitive, so `root` appears for almost any write — it
/// splices every other record, so it reads everything they read. Patching root
/// would rebuild the tree, which is the behaviour reconciliation exists to
/// avoid. A record is a **patch point** only when its OWN bindings read a
/// changed path; an ancestor that merely contains it is handled by patching the
/// descendant.
/// Which sources a change invalidates, following the cascade.
///
/// Re-fetching is the expensive half of reconciliation — realization walks a
/// ninety-node tree, a source is a network round trip — so this is what a host
/// needs after an event. `patch_points` computed it internally and discarded it,
/// which left the cheap half exposed and the costly half unreachable.
///
/// The cascade matters: `city` feeds `place`, `place` feeds `now`. A host that
/// refetched only the direct dependent would read a fresh coordinate against a
/// stale forecast.
pub fn stale_sources(source: &str, changed: &[&str]) -> Vec<String> {
    let mut sink = Diagnostics::default();
    let Some(tokens) = lex(source, &mut sink) else {
        return Vec::new();
    };
    let card = Parser::new(&tokens, &mut sink).parse_card();
    let declared: Vec<&str> = card.sources.iter().map(|s| s.name.as_str()).collect();
    invalidated_by(&card, changed)
        .into_iter()
        .filter(|n| declared.iter().any(|d| *d == n))
        .collect()
}

/// The transitive closure of what `changed` invalidates: the changed roots
/// themselves, plus every source that reads one, to a fixpoint.
fn invalidated_by(card: &Card, changed: &[&str]) -> Vec<String> {
    let mut invalidated: Vec<String> = changed.iter().map(root_of).collect();
    let mut steps = 0usize;
    loop {
        steps += 1;
        if steps > MAX_UI_L0_DECLARATIONS {
            break;
        }
        let before = invalidated.len();
        for decl in &card.sources {
            let reads_changed = decl.args.iter().any(|(_, arg)| match arg {
                SourceArg::Path(p) => {
                    // `state.city` names the state directly; `place.lat` names
                    // another source.
                    let mut parts = p.split('.');
                    let head = parts.next().unwrap_or_default();
                    let target = if head == "state" {
                        parts.next().unwrap_or_default()
                    } else {
                        head
                    };
                    invalidated.iter().any(|i| i == target)
                }
                _ => false,
            });
            if reads_changed && !invalidated.contains(&decl.name) {
                invalidated.push(decl.name.clone());
            }
        }
        if invalidated.len() == before {
            break;
        }
    }
    invalidated
}

/// Realize, reusing the subtrees a change cannot have touched.
///
/// This is what makes `patch_points` load-bearing rather than advisory. It
/// computed which records a change reaches and nothing consumed the answer, so
/// every event rebuilt the whole card.
///
/// The reuse rule is deliberately conservative: a subtree is carried over only
/// when its record is **absent** from the patch set, so a record whose
/// dependencies could not be determined is rebuilt. Being wrong in that
/// direction costs work; being wrong in the other renders a stale value, and a
/// stale value on screen is indistinguishable from a correct one.
///
/// The result must equal a full realization. A test asserts that on the same
/// card, because an optimisation that changes what is rendered is not an
/// optimisation.
pub fn realize_patch(
    source: &str,
    data: &serde_json::Value,
    store: Option<&InstanceStore>,
    previous: &UiNode,
    changed: &[&str],
    limits: RealizeLimits,
) -> RealizeReport {
    let dirty = patch_points(source, changed);
    let mut report = realize_inner(source, data, store, limits);

    if let Some(root) = report.root.as_mut() {
        report.reused = carry_over(root, previous, &dirty);
    }
    report
}

/// Copy nodes from `previous` into `next` wherever the record they belong to is
/// not dirty, and count what was carried.
///
/// Identity is the instance key, which already encodes the declaration path and
/// enclosing loop keys — the same key that decides state ownership, so reuse and
/// state agree by construction rather than by a second rule.
fn carry_over(next: &mut UiNode, previous: &UiNode, dirty: &[String]) -> usize {
    // A key names the records it passes through: `root/when#0/w:stream#0/stream`.
    let touches_dirty = |key: &str| {
        dirty
            .iter()
            .any(|d| key.split(['/', '#', '[']).any(|seg| seg == d))
    };

    // A subtree is reusable only if NOTHING inside it is dirty. Checking the
    // node's own key alone lets the root short-circuit the whole tree, because
    // `patch_points` deliberately excludes ancestors that merely *contain* a
    // change — so a clean parent above a dirty child is the normal case, not an
    // edge one.
    fn subtree_is_clean(n: &UiNode, touches_dirty: &dyn Fn(&str) -> bool) -> bool {
        !touches_dirty(&n.key)
            && n.children
                .iter()
                .all(|c| subtree_is_clean(c, touches_dirty))
    }

    if next.key == previous.key
        && next.kind == previous.kind
        && subtree_is_clean(next, &touches_dirty)
    {
        *next = previous.clone();
        return count_nodes(previous);
    }

    let mut reused = 0;
    for child in next.children.iter_mut() {
        if let Some(was) = previous.children.iter().find(|p| p.key == child.key) {
            reused += carry_over(child, was, dirty);
        }
    }
    reused
}

fn count_nodes(n: &UiNode) -> usize {
    1 + n.children.iter().map(count_nodes).sum::<usize>()
}

pub fn patch_points(source: &str, changed: &[&str]) -> Vec<String> {
    let mut sink = Diagnostics::default();
    let Some(tokens) = lex(source, &mut sink) else {
        return Vec::new();
    };
    let card = Parser::new(&tokens, &mut sink).parse_card();
    let invalidated = invalidated_by(&card, changed);

    let mut out = Vec::new();
    for view in &card.views {
        let (reads, _) = scan_element(&view.body);
        if reads.iter().any(|r| invalidated.iter().any(|i| i == r)) {
            out.push(view.name.clone());
        }
    }
    for component in &card.components {
        let (mut reads, _) = scan_element(&component.body);
        reads.retain(|r| !component.params.iter().any(|p| p.name == *r));
        for state in &component.states {
            reads.push(root_of(&state.path));
        }
        if reads.iter().any(|r| invalidated.iter().any(|i| i == r)) {
            out.push(component.name.clone());
        }
    }
    out
}

/// Which records must re-realize when these paths change.
///
/// The measurable claim behind "one event, one state change, one reconciliation
/// pass": toggling a unit should touch the records that read it, not the tree.
pub fn dirty_records(source: &str, changed: &[&str]) -> Vec<String> {
    // Follow the SOURCE cascade first, exactly as `patch_points` does.
    //
    // This filtered on the changed roots alone, so a state that reaches a view
    // only through a source argument dirtied nothing: `sys.quote(ticker: sel)`
    // read by `TextHero(value: q.last)` reported no record when `sel` changed,
    // because no record reads `sel` — they read `q`. That is the stock card's
    // whole shape, and it is the under-approximating direction, which the
    // profile is explicit shows stale data.
    //
    // `patch_points` had this and this did not, which is the more dangerous half
    // of a disagreement between two functions answering one question: the coarse
    // one is what a host reaches for first.
    let mut sink = Diagnostics::default();
    let invalidated = match lex(source, &mut sink) {
        Some(tokens) => {
            let card = Parser::new(&tokens, &mut sink).parse_card();
            invalidated_by(&card, changed)
        }
        None => changed.iter().map(root_of).collect(),
    };
    record_dependencies(source)
        .into_iter()
        .filter(|d| d.reads.iter().any(|r| invalidated.iter().any(|c| c == r)))
        .map(|d| d.record)
        .collect()
}

/// Paths read directly by an element tree, and the records it pulls in.
fn scan_element(element: &Element) -> (Vec<String>, Vec<String>) {
    let mut reads = Vec::new();
    let mut pulls = Vec::new();
    collect_reads(element, &mut reads, &mut pulls);
    reads.sort();
    reads.dedup();
    pulls.sort();
    pulls.dedup();
    (reads, pulls)
}

fn collect_reads(element: &Element, reads: &mut Vec<String>, pulls: &mut Vec<String>) {
    // A loop binder shadows: `for d in week` makes `d` local, not a dependency.
    let binders = &element.binders;

    // EVERY path an operand reads is a dependency, however it is nested.
    //
    // This matched shapes one at a time and missed two of them, in the direction
    // that is a correctness bug rather than a cost: a comparison's right operand
    // (`active: a == b` never re-realized when `b` changed) and a guard's right
    // operand beyond a bare path (`when a == b * 2` likewise). Both render a
    // stale screen, which is what this whole mechanism exists to prevent.
    //
    // `expr_paths` already walks all three forms, and is the same function §4's
    // must-read rule and the checker use — so a shape it learns is picked up
    // here for free rather than needing a third arm added in a third place.
    let collect = |operand: &Operand, reads: &mut Vec<String>| {
        let mut paths = Vec::new();
        expr_paths(operand, &mut paths);
        for p in paths {
            let root = root_of(&p);
            if !binders.contains(&root) {
                reads.push(root);
            }
        }
    };
    for arg in &element.args {
        collect(&arg.value, reads);
    }
    if let Some(rhs) = element.rhs.as_ref() {
        collect(rhs, reads);
    }

    if element.is_reference || !element.name.is_empty() {
        // A referenced view or an instantiated component contributes its own
        // reads; a plain constructor is not a record and contributes nothing.
        let n = &element.name;
        if !n.is_empty() && n != "for" && n != "when" && n != "slot" {
            pulls.push(n.clone());
        }
    }

    for child in &element.children {
        let mut child_reads = Vec::new();
        collect_reads(child, &mut child_reads, pulls);
        // Binders introduced here shadow inside this subtree only.
        for r in child_reads {
            if !binders.contains(&r) {
                reads.push(r);
            }
        }
    }
}

// ────────────────────────────────────────────── DSL lowering, consumer-checked ──

/// What a lowering produced, and what it could not.
pub struct DslReport {
    pub dsl: String,
    /// Roles with no kind in the consumer's table. A card containing one is
    /// incomplete, and saying so is the difference between a missing chart and
    /// a missing chart nobody was told about.
    pub diagnostics: Vec<SyntaxDiagnostic>,
}

/// Lower to the Splash DSL data form, reporting what could not be mapped.
///
/// The kinds and attribute names below are the consumer's, established by
/// running `splash_render::build` rather than by reading about it. Three facts
/// shaped this and each cost a revert to learn:
///
/// - `splash-render`'s tag table is closed. An unknown kind at the root rejects
///   the whole document; as a child it is dropped with no diagnostic at all.
/// - Its `Attrs` is a fixed 37-field struct, not an open bag, so an attribute
///   it does not name is simply unread. Emitting one is the same as emitting
///   nothing, only harder to notice.
/// - The root must be a literal object. A theme function call in that position
///   fails inside the VM, so a card's outermost role cannot lower to one.
///
/// Six roles have no kind here — the data visualisations. They are reported,
/// not emitted: a card that loses its temperature bars should say so.
pub fn lower_dsl_checked(root: &UiNode) -> DslReport {
    let mut out = String::from("// REALIZED from an L0 ledger — do not edit.\n");
    let mut diagnostics = Vec::new();
    emit_dsl(root, 0, &mut out, &mut diagnostics);
    out.push('\n');
    DslReport {
        dsl: out,
        diagnostics,
    }
}

/// The DSL text alone, for callers that have already checked.
pub fn lower_dsl(root: &UiNode) -> String {
    lower_dsl_checked(root).dsl
}

/// A role's kind in the consumer's table, or `None` if it has none.
///
/// Deliberately not a fallback: an unmapped role must reach the caller as a
/// diagnostic. Guessing a kind is what produced five names the consumer had
/// never heard of.
fn dsl_kind(role: &str) -> Option<&'static str> {
    Some(match role {
        "Surface" | "Col" => "column",
        "Row" => "row",
        "Grid" => "grid",
        "Panel" | "Card" => "card",
        "Rule" => "divider",
        "Space" => "column",
        "Tile" => "listitem",
        "Chip" => "chip",
        "Photo" => "image",
        "Thumb" => "image",
        "WeatherIcon" => "weathericon",
        role if role.starts_with("Text") => "text",
        // TempBar, SunArc, MoonPhase, AqiContour, StockPlot — no kind exists.
        _ => return None,
    })
}

/// Attribute names the consumer's `Attrs` actually reads. Anything else is
/// dropped on arrival, so emitting it only hides the loss.
fn dsl_attr(name: &str) -> Option<&'static str> {
    Some(match name {
        "text" => "text",
        "label" => "label",
        "src" => "src",
        "gap" => "spacing",
        "cols" => "w",
        "pad" => "pad",
        _ => return None,
    })
}

fn emit_dsl(node: &UiNode, depth: usize, out: &mut String, sink: &mut Vec<SyntaxDiagnostic>) {
    use std::fmt::Write as _;
    let pad = "  ".repeat(depth);

    let Some(kind) = dsl_kind(&node.kind) else {
        sink.push(SyntaxDiagnostic {
            line: 1,
            column: 1,
            message: format!(
                "{} has no kind in the renderer's table, so it cannot be lowered — a card \
                 using it would render without it and look complete (profile §1.1)",
                node.kind
            ),
        });
        return;
    };

    let _ = write!(out, "{pad}{{t: {kind:?}");
    for (name, value) in &node.args {
        let Some(attr) = dsl_attr(name) else { continue };
        let _ = match value {
            NodeValue::Text(s) => write!(out, ", {attr}: {s:?}"),
            NodeValue::Number(n) => write!(out, ", {attr}: {}", makepad::trim_num(*n)),
            NodeValue::Token(t) => write!(out, ", {attr}: {t:?}"),
            _ => Ok(()),
        };
    }

    if node.children.is_empty() {
        out.push_str("}\n");
        return;
    }
    out.push_str(", c: [\n");
    for child in &node.children {
        emit_dsl(child, depth + 1, out, sink);
    }
    let _ = writeln!(out, "{pad}]}}");
}

// ──────────────────────────────────────────────────────────── kit lowering ──

/// Lower a realized card to calls on the **L0 theme kit**.
///
/// This is what §1.1 asks for and what `makepad::lower` does not do. That module
/// emits a backend's own widget dialect with ten hardcoded colours and a
/// font-size ramp, so it decides presentation — a theme's job — and reaches one
/// backend of three. This emits role calls and lets the kit answer them:
///
/// ```text
/// l0_panel([ l0_caption("LEAD"), l0_body("Rust 1.95 lands") ])
///
/// not   RoundedView{ draw_bg.color: #ffffff12 draw_bg.border_radius: 14.0 … }
/// ```
///
/// **The kit is a contract with a consumer this crate cannot depend on**, and
/// that is exactly how the two reverted attempts went wrong. So the contract is
/// checked where the consumer lives: `Splash-Makepad` dev-depends on this crate
/// and builds the output through `splash_render::build`. That dependency is
/// only possible because this crate was extracted from `splash-core` and
/// depends on `serde_json` alone.
pub mod kit {
    use super::makepad;
    use super::{NodeValue, UiNode};
    use std::fmt::Write as _;

    /// The assembled script's value must be a bare VARIABLE.
    ///
    /// `fn f() { … }` followed by `f()` evaluates to nil in this VM, so a card
    /// emitted as a bare call renders as nothing at all — which looks exactly
    /// like a broken kit. Every kit in `Splash-Makepad` ends this way.
    pub fn lower(root: &UiNode) -> String {
        let mut out = String::from("// REALIZED from an L0 ledger — do not edit.\n");
        out.push_str("let node = ");
        element(root, 0, &mut out);
        out.push_str("\nnode\n");
        out
    }

    /// A card's roles, and the kit function that answers each.
    ///
    /// Returning `None` means the role has no answer in this kit — it lowers to
    /// a visible marker rather than to nothing, because a card that silently
    /// loses its temperature bars still looks complete (§1.1).
    fn kit_fn(role: &str) -> Option<&'static str> {
        Some(match role {
            "Field" => "l0_field",
            "Map" => "l0_map",
            "Surface" => "l0_surface",
            "Reveal" => "l0_reveal",
            "Col" => "l0_col",
            "Row" => "l0_row",
            "Grid" => "l0_grid",
            "Panel" => "l0_panel",
            // Card lowers separately: a CONTENT card may take the pack's
            // signature gradient (`l0_card_1/2`); a section Panel never does.
            "Card" => "l0_card",
            "Rule" => "l0_rule",
            "Space" => "l0_space",
            "Tile" => "l0_tile",
            "Chip" => "l0_chip",
            "Avatar" => "l0_avatar",
            "Icon" => "l0_icon",
            "Photo" => "l0_photo",
            "Thumb" => "l0_thumb",
            "WeatherIcon" => "l0_weathericon",
            "TempBar" => "l0_tempbar",
            "SunArc" => "l0_sunarc",
            "MoonPhase" => "l0_moonphase",
            "AqiContour" => "l0_aqicontour",
            "Satellite" => "l0_satellite",
            "StockPlot" => "l0_stockplot",
            "IndicatorPlot" => "l0_indicatorplot",
            "TextHero" => "l0_hero",
            "TextTitle" => "l0_title",
            "TextBody" => "l0_body",
            "TextRow" => "l0_row_text",
            "TextCaption" => "l0_caption",
            "TextEyebrow" => "l0_eyebrow",
            "TextValue" => "l0_value",
            "TextStat" => "l0_stat",
            _ => return None,
        })
    }

    fn arg<'a>(node: &'a UiNode, name: &str) -> Option<&'a NodeValue> {
        node.args.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// A `TokenOrPath` argument, whichever it turned out to be.
    ///
    /// `unit`, `width`, `view`, `controls` and `range` each admit a token OR a path
    /// to card state, and REALIZE ERASES THE DIFFERENCE: `view: .tilted` survives as
    /// `Token("tilted")`, while `view: view` reading `.tilted` out of the state
    /// arrives as `Text("tilted")`. A reader that matches only `Token` therefore sees
    /// nothing whenever the card chose the state form and silently takes its default.
    ///
    /// That is what broke the nav card's on-map 2D/3D switch. The chip relabelled on
    /// every tap because its own guard reads the state directly, so the toggle looked
    /// live — but `view` reached the lowering as `Text` and the camera stayed flat on
    /// both settings. A control that responds and changes nothing is worse than one
    /// that is missing; the screen asserts the camera tilted and it did not.
    ///
    /// Every `TokenOrPath` read goes through here so the class cannot come back one
    /// argument at a time.
    fn token_arg<'a>(node: &'a UiNode, name: &str) -> Option<&'a str> {
        match arg(node, name) {
            Some(NodeValue::Token(t) | NodeValue::Text(t)) => Some(t.as_str()),
            _ => None,
        }
    }

    /// A statistic's direction — the SIGN, not the colour.
    ///
    /// Red-versus-green is presentation and belongs to the kit; "this value
    /// fell" is meaning and belongs here. A lowering that dropped `tint`
    /// entirely lost both, which is why the profile calls it the instructive
    /// case.
    fn direction(node: &UiNode) -> i32 {
        match arg(node, "tint") {
            Some(NodeValue::Number(n)) if *n > 0.0 => 1,
            Some(NodeValue::Number(n)) if *n < 0.0 => -1,
            Some(NodeValue::Token(t)) if t == "up" => 1,
            Some(NodeValue::Token(t)) if t == "down" => -1,
            _ => 0,
        }
    }

    /// The tint argument, as a LIVE call where the backend can answer it.
    ///
    /// `direction` reads the realized value, which is the seeded one. Once
    /// `value:` went live the two disagreed on screen: the top-movers list drew
    /// `+29.45%` in red because the seed behind that row was negative, and
    /// `+29.20%` in green two rows down because that one was positive. Four
    /// positive rows, two of them red — two numbers describing one move,
    /// side by side, contradicting each other. That is precisely what §4 exists
    /// to prevent, and making values live without making tints live is what
    /// turned a hidden staleness into a visible contradiction.
    ///
    /// No kit change is needed: `l0_tint` branches on `dir > 0` / `dir < 0`, so
    /// it takes the SIGN of whatever it is handed and a raw change value works
    /// exactly as `1` or `-1` did.
    ///
    /// `None` means "do not tint at all" — no `tint:` was declared. A declared
    /// tint the backend cannot answer still falls back to the realized sign,
    /// which is the same choice every other binding makes.
    fn tint_expr(node: &UiNode) -> Option<String> {
        if let Some((_, binding)) = node.bindings.iter().find(|(n, _)| n == "tint") {
            if let Some(call) = makepad::vm_call(binding) {
                return Some(call);
            }
        }
        match direction(node) {
            0 => None,
            d => Some(d.to_string()),
        }
    }

    fn children(node: &UiNode, depth: usize, out: &mut String) {
        out.push_str("[\n");
        for (i, child) in node.children.iter().enumerate() {
            let _ = write!(out, "{}", "  ".repeat(depth + 1));
            element(child, depth + 1, out);
            if i + 1 < node.children.len() {
                out.push(',');
            }
            out.push('\n');
        }
        let _ = write!(out, "{}]", "  ".repeat(depth));
    }

    /// A `[...]` list from an explicit slice — the Surface layer split hands
    /// segments of children rather than a node.
    fn children_list(nodes: &[&UiNode], depth: usize, out: &mut String) {
        out.push_str("[\n");
        for (i, child) in nodes.iter().enumerate() {
            let _ = write!(out, "{}", "  ".repeat(depth + 1));
            element(child, depth + 1, out);
            if i + 1 < nodes.len() {
                out.push(',');
            }
            out.push('\n');
        }
        let _ = write!(out, "{}]", "  ".repeat(depth));
    }

    /// A tap, as the string the backend carries.
    ///
    /// JSON rather than a delimited form, because every field is data: an
    /// instance key contains colons (`w:list#0`) and slashes, and a payload is
    /// whatever the card bound. Every separator worth using has a
    /// data-dependent failure, and a failure here is a tap routed to the wrong
    /// row — which looks like a card bug and is not.
    ///
    /// The `l0:` prefix is what distinguishes it from this renderer's own
    /// `set:` verbs, which it handles internally.
    fn tap_target(node: &UiNode) -> Option<String> {
        let Some(NodeValue::Event(event)) = arg(node, "on_tap") else {
            return None;
        };
        // A payload bound to a source is emitted as a LIVE CALL, not as the
        // value realization happened to see.
        //
        // The two disagree whenever the row's text is live and its payload is
        // not, which is every card with no seed blob: the screen said `ATKR` and
        // the tap carried `""`, so the write was refused and the row read as
        // dead. Worse when a blob IS present and stale — the tap then carries a
        // different company from the one the user is looking at.
        //
        // The result is a DSL EXPRESSION, so the caller emits it unquoted.
        if let Some((_, binding)) = node.bindings.iter().find(|(n, _)| n == "value") {
            if let Some(call) = makepad::vm_call(binding) {
                let head = serde_json::json!({ "e": event, "k": node.key });
                let head = head.to_string();
                // `{"e":…,"k":…}` → `l0:{"e":…,"k":…,"v":"` + <call> + `"}`
                let open = format!("l0:{},\"v\":\"", head.trim_end_matches('}'));
                return Some(format!("{open:?} + {call} + {:?}", "\"}"));
            }
        }
        let value = match arg(node, "value") {
            Some(NodeValue::Text(t)) => t.clone(),
            Some(NodeValue::Number(n)) => makepad::trim_num(*n),
            Some(NodeValue::Token(t)) => t.clone(),
            _ => String::new(),
        };
        let json = serde_json::json!({ "e": event, "k": node.key, "v": value });
        Some(format!("{:?}", format!("l0:{json}")))
    }

    /// A visualisation's argument, as the kit takes it.
    ///
    /// A missing one is `0` rather than an omission: these functions have fixed
    /// arity, and a card that failed to supply a bound would otherwise not
    /// parse. Zero at least draws something visibly wrong, where a parse error
    /// takes the whole card down.
    /// A scalar argument — live where the backend can answer it.
    ///
    /// The bindings were never consulted here, so `WeatherIcon(cond: d.cond)`
    /// lowered the weather code realization happened to see. Against a seed blob
    /// that is right by accident; on a live card, which carries no blob, every
    /// icon in a seven-day forecast fell back to the same default. Exactly the
    /// defect `tint` had, in the other place that reads a realized value and
    /// emits a literal — and the icon is the harder one to notice, because a
    /// wrong icon looks precisely like a right one.
    fn scalar_of(node: &UiNode, name: &str) -> String {
        scalar_inner(node, name, false)
    }

    /// The same, COERCED to a number.
    ///
    /// Every `sys.*` helper answers with a string, because a string is what a
    /// card renders. A visualisation's parameters are not rendered — they drive a
    /// shader uniform, and the node model types them as numbers, so a string
    /// arrives as `None` and the uniform gets 0.
    ///
    /// Measured: a `TempBar`'s `lo`, `hi`, `min` and `max` were all live calls
    /// and all four reached the widget as zero, so seven days of different
    /// temperatures drew seven identical flat bars against a range of nothing.
    /// The same defect as an L1 operand subtracting strings, in the other place
    /// a number is needed and a string is what a helper gives.
    fn scalar_num_of(node: &UiNode, name: &str) -> String {
        scalar_inner(node, name, true)
    }

    fn scalar_inner(node: &UiNode, name: &str, numeric: bool) -> String {
        if let Some((_, binding)) = node.bindings.iter().find(|(n, _)| n == name) {
            if let Some(call) = makepad::vm_call(binding) {
                return if numeric {
                    format!("sys.num({call})")
                } else {
                    call
                };
            }
        }
        match arg(node, name) {
            Some(NodeValue::Number(n)) => makepad::trim_num(*n),
            Some(NodeValue::Text(t)) => format!("{t:?}"),
            Some(NodeValue::Token(t)) => format!("{t:?}"),
            _ => "0".into(),
        }
    }

    /// A declared width, as the kit call that applies it.
    ///
    /// Composed around the role rather than threaded into it, for the reason
    /// `tint` is: `width` is optional on every text role, and a parameter on
    /// all seven kit functions would have six passing a default forever.
    ///
    /// `fit` returns `None` because it is already this backend's default, and
    /// emitting a wrapper for it would say the same thing twice. The fixed
    /// tokens pass the TOKEN and not a pixel count: how wide a rank column is
    /// is the theme's answer, and deciding here would put styling in the
    /// lowering.
    fn width_wrap(node: &UiNode) -> Option<(&'static str, String)> {
        let t = token_arg(node, "width")?;
        match t {
            "fill" => Some(("l0_wide(", ")".into())),
            // NOT a no-op, though it is the default for a text role: `l0_row`
            // fills, so a row can only stop filling by saying so.
            "fit" => Some(("l0_fit(", ")".into())),
            "rank" | "day" | "temp" | "label" => Some(("l0_colw(", format!(", {t:?})"))),
            _ => None,
        }
    }

    /// A `Field`'s commit target, carrying what the user typed.
    ///
    /// `on_commit` is not `on_tap` and must not be wrapped in a hit target: the
    /// payload is the TEXT, which does not exist until the moment of commit, so
    /// the target is assembled at that moment from the value the backend hands
    /// back. `$$` is the placeholder the backend substitutes.
    fn commit_target(node: &UiNode) -> Option<String> {
        field_target(node, "on_commit")
    }

    /// A field's target for one of its two moments. `$$` is where the typed text
    /// goes, assembled at the moment rather than baked at lowering time.
    fn field_target(node: &UiNode, arg_name: &str) -> Option<String> {
        let Some(NodeValue::Event(event)) = arg(node, arg_name) else {
            return None;
        };
        let json = serde_json::json!({ "e": event, "k": node.key, "v": "$$" });
        Some(format!("l0:{json}"))
    }

    /// The live expression behind this node's displayed value, if it has one.
    ///
    /// Stamped onto the node by `l0_live` so the renderer can refresh it in place
    /// with `fn tick()` instead of re-resolving the ledger and re-parsing the whole
    /// document. On a driving screen a re-resolve lands inside a frame: measured on a
    /// OnePlus 6, frame hitches and card re-resolves correlate 1:1, up to 327 ms.
    ///
    /// L0 is untouched. The constraint is on what a CARD may say, and the card still
    /// says `TextRow(text: step.instruction)`; `fn tick()` belongs to the backend in
    /// exactly the way `sys.navstep` does.
    fn live_call_of(node: &UiNode) -> Option<String> {
        // A bound `value:` must TICK with the same composition it DREW with.
        // This built `decorated(vm_call(…))` — glyph/unit/suffix but never
        // `format:` — so every `.money` price lost its `$` on the first tick,
        // `.signed_money` ticked the raw `change` field the changemoney
        // redirect exists to avoid, and a `.compact`/`.ratio` value (which
        // cannot go live at all) was overwritten with the raw number the
        // format was protecting the screen from. `live_valued` IS the drawn
        // composition; the tick stamps exactly that, and refuses to stamp
        // exactly where the draw refused to go live.
        if node.bindings.iter().any(|(n, _)| n == "value") {
            return makepad::live_valued(node);
        }
        let (_, binding) = node.bindings.iter().find(|(n, _)| n == "text")?;
        let call = makepad::vm_call(binding)?;
        Some(makepad::decorated(node, call))
    }

    fn element(node: &UiNode, depth: usize, out: &mut String) {
        // A `Field` carries its own commit target and must NOT be wrapped in a
        // tap: a hit target over a text input eats the focus, and the payload
        // here is what was typed rather than what the row was bound to.
        if node.kind == "Field" {
            let _ = write!(
                out,
                "l0_field({}, {}, {:?}, {:?})",
                makepad::expr_of(node, "text"),
                makepad::expr_of(node, "placeholder"),
                commit_target(node).unwrap_or_default(),
                field_target(node, "on_change").unwrap_or_default()
            );
            return;
        }
        // A tappable node is WRAPPED. A `card`, `chip` or `image` carrying
        // `tapto` renders and does nothing — the attribute is dropped before it
        // reaches the UI — so only a container carries a tap.
        if let Some(target) = tap_target(node) {
            // The wrapper sizes like what it WRAPS.
            //
            // A filling wrapper around an intrinsic thing takes the whole line
            // and the thing sits at its left edge. The first chip in a row of
            // chips ate the row; then the weather card's hero temperature — a
            // tappable `TextHero` inside a centred column — stopped centring,
            // because what the column had to place was a full-width wrapper and
            // not the six characters inside it. The place name and the icon
            // centred correctly beside it, which is what made it look like a
            // font problem rather than a layout one.
            //
            // A text role that ASKED to fill is not intrinsic, so it keeps the
            // filling wrapper.
            let asked_to_fill = token_arg(node, "width") == Some("fill");
            let intrinsic =
                // A `.danger` chip is the exception: it SPANS the sheet, so a
                // fit-width hit target is the one thing that can hide it. It emitted
                // a `width: Fill` bar inside a `width: Fit` wrapper and the End
                // button rendered as an empty gap — the same Fill-inside-Fit trap
                // that resolves to nothing, three times over in this card now.
                (node.kind == "Chip"
                    && (!matches!(arg(node, "tone"), Some(NodeValue::Token(t)) if t == "danger")
                        // A danger chip that ASKS to fit is a row-scoped one
                        // (the compact variant below) — its hit target fits it.
                        || matches!(arg(node, "width"), Some(NodeValue::Token(t)) if t == "fit")))
                    || (node.kind.starts_with("Text") && !asked_to_fill);
            let f = if intrinsic { "l0_tap_fit" } else { "l0_tap" };
            let _ = write!(out, "{f}({target}, ");
            element_untapped(node, depth, out);
            out.push(')');
            return;
        }
        element_untapped(node, depth, out);
    }

    /// A declared child alignment, as the kit call that applies it.
    ///
    /// `start` returns `None`: it is the default, and a wrapper that restated it
    /// on every container would make the one container that asked for something
    /// indistinguishable from the dozen that did not.
    ///
    /// Which AXIS this means is the kit's to decide, not the lowering's — a
    /// column aligns horizontally and a row vertically, and only the thing
    /// holding the flow knows which it is.
    fn align_wrap(node: &UiNode) -> Option<(&'static str, String)> {
        let Some(NodeValue::Token(t)) = arg(node, "align") else {
            return None;
        };
        match t.as_str() {
            "center" | "end" => Some(("l0_aligned(", format!(", {t:?})"))),
            _ => None,
        }
    }

    /// Wrappers COMPOSE around a role — the pattern `tint` established.
    ///
    /// `width` and `align` are optional on many roles and meaningless on most,
    /// so a parameter on every kit function would have nearly all of them
    /// carrying a default forever. Each attribute the catalog admits needs an
    /// entry HERE or it is accepted by the profile and silently discarded, which
    /// is this layer's recurring defect and the reason the list is explicit.
    fn element_untapped(node: &UiNode, depth: usize, out: &mut String) {
        let wraps: Vec<(&'static str, String)> = [
            // OUTERMOST. `l0_live` only stamps the call onto the node, so where it
            // sits makes no functional difference — but the width and align helpers
            // read as a pair, and slipping between them makes both harder to see.
            live_call_of(node).map(|call| ("l0_live(", format!(", {call:?})"))),
            width_wrap(node),
            align_wrap(node),
        ]
        .into_iter()
        .flatten()
        .collect();
        for (open, _) in &wraps {
            out.push_str(open);
        }
        element_unsized(node, depth, out);
        for (_, close) in wraps.iter().rev() {
            out.push_str(close);
        }
    }

    fn element_unsized(node: &UiNode, depth: usize, out: &mut String) {
        let Some(f) = kit_fn(&node.kind) else {
            let _ = write!(out, "l0_unsupported({:?})", node.kind);
            return;
        };
        match node.kind.as_str() {
            // A card holding a MAP is a map with the card floating over it, and
            // this is the backend the DEVICE renders through — the app's path is
            // `kit::lower` -> `_kit.splash` -> eval -> `l0_widgets`, so the same
            // fix landing only in `makepad::lower` would have looked verified and
            // changed nothing on a phone. That is exactly the one-backend gap
            // `Field`, `Grid.cols` and `Map` were each found in, and the reason
            // `every_admitted_role_is_lowered_by_both_backends` exists.
            //
            // See `l0_surface_map` in the kit for why the map is the bottom layer
            // and why every number in the sheet is the shipping nav card's.
            "Surface" if node.children.iter().any(|c| c.kind == "Map") => {
                let map = node
                    .children
                    .iter()
                    .find(|c| c.kind == "Map")
                    .expect("guarded above");
                // THREE slots: the map, the band docked to the top, and the sheet at
                // the bottom. A turn instruction belongs in the top band and the
                // summary in the sheet, which is how the app this replaces arranges
                // its driving screen and how every map app does.
                let docked = |c: &UiNode, where_: &str| {
                    c.kind == "Panel"
                        && matches!(arg(c, "dock"), Some(NodeValue::Token(t)) if t == where_)
                };
                let docked_top = |c: &&UiNode| docked(c, "top");
                let docked_right = |c: &&UiNode| docked(c, "right");
                out.push_str("l0_surface_map(");
                element(map, depth, out);
                for pass in 0..3 {
                    out.push_str(", [");
                    let mut first = true;
                    for child in node.children.iter().filter(|c| {
                        c.kind != "Map"
                            && match pass {
                                0 => docked_top(c),
                                1 => docked_right(c),
                                // The sheet takes everything else, which is what an
                                // undocked panel on a map card has always meant.
                                _ => !docked_top(c) && !docked_right(c),
                            }
                    }) {
                        // A docked panel contributes its CHILDREN, not itself.
                        //
                        // `l0_surface_map` already draws the dock: the band at the
                        // top and the sheet at the bottom are its own chrome. Emitting
                        // the `Panel` as well put an `l0_panel` inside each of them —
                        // a second rounded box, with its own fill, `pady: 12` and
                        // `margintop: 16`. Three faults, one wrapper: the sheet had a
                        // visible box drawn inside it; the wrapper is `fillw`, so the
                        // sheet's `alignx` centred the wrapper and nothing inside it,
                        // and the hero went left; and the 40 extra units it added
                        // pushed the distance under the bottom of the screen.
                        // Only a DOCKED panel unwraps — that is the one whose
                        // chrome the surface has already drawn. Anything else
                        // placed directly on the surface is emitted whole, or a
                        // card that floats a lone chip over the map would have
                        // emitted the chip's children and lost the chip.
                        let docked = child.kind == "Panel" && arg(child, "dock").is_some();
                        let emit: Vec<&UiNode> = if docked {
                            child.children.iter().collect()
                        } else {
                            vec![child]
                        };
                        for one in emit {
                            if !first {
                                out.push_str(", ");
                            }
                            first = false;
                            // A side-docked Chip stands ON THE MAP, in the same
                            // column as the zoom pill and the recenter ring — so it
                            // is drawn to the ring's spec (`l0_mapchip`, 38x38)
                            // rather than as a sheet chip. The eye-test asked for
                            // the 2D/3D switch and the location button to be the
                            // same size, and a text pill in a rounded box cannot be.
                            if pass == 1 && one.kind == "Chip" {
                                // UNQUOTED, like the ordinary hit path above:
                                // `tap_target` returns a DSL EXPRESSION carrying its
                                // own quoting (and, for live payloads, a
                                // concatenated call). Debug-quoting it turned the
                                // expression into a string of escapes, the runtime
                                // target into garbage, and the dispatch into an
                                // empty event "applied to nothing".
                                if let Some(target) = tap_target(one) {
                                    let _ = write!(
                                        out,
                                        "l0_tap_fit({target}, l0_mapchip({}))",
                                        makepad::expr_of(one, "text")
                                    );
                                } else {
                                    let _ = write!(
                                        out,
                                        "l0_mapchip({})",
                                        makepad::expr_of(one, "text")
                                    );
                                }
                                continue;
                            }
                            element(one, depth + 1, out);
                        }
                    }
                    out.push(']');
                }
                // Whether anything is DOCKED at the top. The theme cannot ask a list
                // its length, and a band drawn for an empty one is a dark pill
                // floating over the map saying nothing — which is what every
                // planning screen had.
                let has_top = node.children.iter().any(|c| docked_top(&c));
                let _ = write!(out, ", {}", u8::from(has_top));
                // The controls the MAP asked for, laid out by the SURFACE: they
                // belong in the same column as anything docked to the side, below
                // the banner, and only the surface knows where that is. `none`
                // unless the card said otherwise — a map that grows buttons nobody
                // mentioned is the theme deciding what a screen offers.
                let controls = token_arg(map, "controls").unwrap_or("none").to_owned();
                let _ = write!(out, ", {controls:?}");
                // And whether anything is docked to the SIDE, for the same reason
                // `has_top` exists. The theme gives that column the dark backing the
                // zoom pill has, so a chip the card put on the map reads over pale
                // tiles instead of vanishing into them — and a card that docks
                // nothing there must not get an empty box for it.
                let has_side = node.children.iter().any(|c| docked(c, "right"));
                let _ = write!(out, ", {}", u8::from(has_side));
                out.push(')');
            }
            "Surface" => {
                // Top-level `Space()` children split the page into ALIGNED
                // layers: [pre] Space [post] pins post to the page floor; a
                // second Space centers the middle segment. Deferred fills are
                // greedy in the app's layout fork — anything walked after one
                // never fits — so the pin is alignment, not fill.
                let n_spaces = node.children.iter().filter(|c| c.kind == "Space").count();
                let n_real = node.children.len() - n_spaces;
                if (1..=2).contains(&n_spaces) && n_real > 0 {
                    let mut segs: Vec<Vec<&UiNode>> = vec![Vec::new()];
                    for c in &node.children {
                        if c.kind == "Space" {
                            segs.push(Vec::new());
                        } else {
                            segs.last_mut().expect("seeded non-empty").push(c);
                        }
                    }
                    let fname = if segs.len() == 2 { "l0_surface_pin2" } else { "l0_surface_pin3" };
                    let _ = write!(out, "{fname}(");
                    for (i, seg) in segs.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        children_list(seg, depth, out);
                    }
                    out.push(')');
                } else {
                    let _ = write!(out, "{f}(");
                    children(node, depth, out);
                    out.push(')');
                }
            }
            "Col" | "Row" => {
                // `gap` is a declared spacing, so it stays a semantic argument
                // rather than becoming a number the kit cannot reinterpret.
                match arg(node, "gap") {
                    Some(NodeValue::Number(g)) => {
                        let _ = write!(out, "{f}_gap({}, ", makepad::trim_num(*g));
                    }
                    _ => {
                        let _ = write!(out, "{f}(");
                    }
                }
                children(node, depth, out);
                out.push(')');
            }
            // A GRID IS ROWS OF `cols`, chunked HERE.
            //
            // `l0_grid` took a flat child list and the node model renders a grid
            // as a column, so a `Grid(cols: 2)` drew one tile per line — the
            // weather card's feels-like / humidity / wind / pressure / UV /
            // visibility ran six rows deep instead of three across. `cols` was
            // accepted by the catalog and honoured only by `makepad::lower`,
            // which is not the path the device renders through.
            //
            // The chunking is here rather than in the theme because the kit
            // language has no loop, and it is where `makepad::lower` already does
            // it — so both backends now divide the same way.
            "Grid" => {
                let cols = match arg(node, "cols") {
                    Some(NodeValue::Number(n)) if *n >= 1.0 => *n as usize,
                    _ => 2,
                };
                let pad = "  ".repeat(depth + 1);
                let _ = writeln!(out, "l0_col([");
                let rows: Vec<&[UiNode]> = node.children.chunks(cols).collect();
                for (r, row) in rows.iter().enumerate() {
                    let _ = writeln!(out, "{pad}l0_row([");
                    for (i, cell) in row.iter().enumerate() {
                        let _ = write!(out, "{pad}  ");
                        element(cell, depth + 2, out);
                        if i + 1 < row.len() {
                            out.push(',');
                        }
                        out.push('\n');
                    }
                    let _ = write!(out, "{pad}])");
                    if r + 1 < rows.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                let _ = write!(out, "{}])", "  ".repeat(depth));
            }
            "Panel" | "Card" => {
                let _ = write!(out, "{f}(");
                children(node, depth, out);
                out.push(')');
            }
            "Rule" | "Space" => {
                let _ = write!(out, "{f}()");
            }
            "Tile" => {
                let _ = write!(
                    out,
                    "{f}({}, {})",
                    makepad::expr_of(node, "label"),
                    makepad::valued(node)
                );
            }
            "Chip" => {
                // `.danger` is a different role in the kit, not a parameter: it is
                // full width and centred as well as red, and threading three
                // presentation decisions through one flag reads worse than naming
                // the thing.
                if matches!(arg(node, "tone"), Some(NodeValue::Token(t)) if t == "danger") {
                    // The card says the scope: `width: .fit` names the compact
                    // row-sized variant (the tap pass strips value/on_tap before
                    // this runs, so the payload cannot be the discriminator);
                    // without it a danger chip is a screen action and spans.
                    // Both are red — what destructive looks like stays the
                    // theme's call.
                    if matches!(arg(node, "width"), Some(NodeValue::Token(t)) if t == "fit") {
                        let _ = write!(
                            out,
                            "l0_chip_danger_row({})",
                            makepad::expr_of(node, "text")
                        );
                    } else {
                        let _ = write!(out, "l0_chip_danger({})", makepad::expr_of(node, "text"));
                    }
                } else if matches!(arg(node, "tone"), Some(NodeValue::Token(t)) if t == "primary") {
                    // The same reasoning as `.danger`: a primary action is bigger
                    // type AND a rounder target AND a lit fill, and threading three
                    // presentation decisions through a flag reads worse than naming
                    // the thing the theme is being asked for.
                    let _ = write!(out, "l0_chip_primary({})", makepad::expr_of(node, "text"));
                } else {
                    let on = i32::from(matches!(arg(node, "active"), Some(NodeValue::Bool(true))));
                    let _ = write!(out, "{f}({}, {on})", makepad::expr_of(node, "text"));
                }
            }
            // A `Photo` WITH children is not an image, it is the page: the
            // weather card wraps the whole card in one, and a lowering that made
            // it a leaf dropped every child. That is the mistake the reverted
            // attempt made, and it is why `l0_surface_photo` exists — image,
            // scrim, then the content, so text stays legible over whatever the
            // image turns out to be.
            // Content a swipe reveals — hidden until then. See the catalog.
            "Reveal" => {
                out.push_str("l0_reveal(");
                children(node, depth, out);
                out.push(')');
            }
            "Photo" if !node.children.is_empty() => {
                let _ = write!(out, "l0_surface_photo({}, ", makepad::expr_of(node, "src"));
                children(node, depth, out);
                out.push(')');
            }
            "Photo" => {
                let _ = write!(out, "{f}({})", makepad::expr_of(node, "src"));
            }
            "Thumb" => {
                // The shape token becomes a number: the kit picks with arithmetic,
                // not string compares.
                let sq = i32::from(
                    matches!(arg(node, "shape"), Some(NodeValue::Token(t)) if t == "square"),
                );
                let _ = write!(out, "{f}({}, {sq})", makepad::expr_of(node, "src"));
            }
            // The trip, as the kit takes it: which member of the map family, how
            // close, where to centre, and the route already resolved.
            //
            // The route is a CALL — `sys.navroute` over both endpoints' own
            // coordinate calls — so the geometry is fetched when the card draws
            // rather than baked at realization. The kit was emitting
            // `l0_unsupported("Map")` until now, which is what put an error box
            // in the middle of the nav card ON DEVICE, since the device renders
            // through this path and not through `makepad::lower`.
            "Map" => {
                let (lat, lon, poly) = makepad::map_route(node);
                // No follow FLAG is passed. `map_mode` already emits `follow` or
                // `follow3d` only when the card declared a live position, and the
                // widget reads the device's fix directly in those modes — a position
                // that changes every second is not a property, so routing it through
                // one bought nothing and cost a frozen camera when the property was a
                // constant expression. See `update_nav_camera`.
                let _ = write!(
                    out,
                    "{f}({:?}, {}, {lat}, {lon}, {poly}, {}, {})",
                    makepad::map_mode(node),
                    scalar_of(node, "zoom"),
                    // The pins. `""` rather than omitted, because the widget reads
                    // an empty marker string as "no pins" and that is exactly what a
                    // map with no complete trip has.
                    makepad::map_pins(node).unwrap_or_else(|| "\"\"".to_owned()),
                    makepad::map_badge(node).unwrap_or_else(|| "\"\"".to_owned()),
                );
            }
            "Icon" => {
                // The MEANING token resolves to the theme's glyph HERE, at
                // lower time — the kit never carries a string table and the
                // card never carries a codepoint. Size names WHERE it sits;
                // the kit's type scale decides how big that is.
                let name = match arg(node, "name") {
                    Some(NodeValue::Token(t)) => t.clone(),
                    _ => "info".to_owned(),
                };
                let size = match arg(node, "size") {
                    Some(NodeValue::Token(t)) => t.clone(),
                    _ => "row".to_owned(),
                };
                let _ = write!(out, "{f}({:?}, {size:?})", crate::icon_glyph(&name));
            }
            // `cond` is a NUMBER — the WMO code the forecast returns — and this
            // matched only `Text` and `Token`, so every one of them fell through
            // to `""`. All seven forecast rows drew the same default icon over a
            // week that was cloudy, rainy and clear on different days, and
            // nothing on screen said so: a wrong icon looks exactly like a right
            // one. `scalar_of` takes whichever the card bound.
            //
            // `size` says WHERE the icon sits — hero block, forecast row, tile —
            // and the kit decides how big each of those is.
            "WeatherIcon" => {
                let size = match arg(node, "size") {
                    Some(NodeValue::Token(t)) => t.clone(),
                    _ => "row".to_owned(),
                };
                // The ICON's reading of `cond`, falling back to whatever the
                // card bound. `scalar_of` alone gave it the WORD, which is not a
                // number, which is 0, which is the sun — always.
                let cond = node
                    .bindings
                    .iter()
                    .find(|(n, _)| n == "cond")
                    .and_then(|(_, b)| makepad::icon_call(b))
                    .unwrap_or_else(|| scalar_of(node, "cond"));
                let _ = write!(out, "{f}({cond}, {size:?})");
            }
            "TextStat" => {
                // `l0_stat` takes the direction as a parameter rather than
                // composing it, so an untinted stat passes the neutral `0`.
                let dir = tint_expr(node).unwrap_or_else(|| "0".to_owned());
                let _ = write!(out, "{f}({}, {dir})", makepad::valued(node));
            }
            // Five text roles may carry a tint, and the stock LIST tints a
            // `TextValue` while the detail tints a `TextStat`. Lowering only the
            // latter dropped the colour from every row on the list — the
            // percentages rendered white, and "this one fell" stopped being
            // said at all. `tint` is §1.1's instructive case for exactly this:
            // red-versus-green is presentation, but the SIGN is meaning.
            "TextTitle" | "TextBody" | "TextCaption" | "TextValue" if tint_expr(node).is_some() => {
                // Always through `valued`: it falls back to `text:` and
                // decorates either way. Branching here meant a `text:` carrying a
                // `suffix:` skipped the decoration entirely.
                let body = makepad::valued(node);
                let dir = tint_expr(node).unwrap_or_else(|| "0".to_owned());
                let _ = write!(out, "l0_tinted({f}({body}), {dir})");
            }
            // The five data visualisations. Each takes its declared arguments in
            // the catalog's order — no defaults, because a bar drawn against a
            // range nobody supplied is a bar drawn against zero, and it looks
            // like data.
            // The card names WHICH countries and WHICH indicator as text; the
            // widget resolves the series. Kept out of the numeric group below
            // because two of its three arguments are strings.
            "IndicatorPlot" => {
                let _ = write!(
                    out,
                    "{f}({}, {}, {})",
                    makepad::expr_of(node, "countries"),
                    makepad::expr_of(node, "indicator"),
                    scalar_num_of(node, "years")
                );
            }
            "TempBar" | "SunArc" | "MoonPhase" | "AqiContour" | "StockPlot" | "Satellite" => {
                let params: &[&str] = match node.kind.as_str() {
                    "TempBar" => &["lo", "hi", "min", "max"],
                    "SunArc" => &["rise", "set", "now"],
                    "MoonPhase" => &["phase", "illum"],
                    "AqiContour" => &["lat", "lon", "span"],
                    "Satellite" => &["lat", "lon"],
                    _ => &["symbol", "range"],
                };
                // Numeric: these drive shader uniforms, not text.
                let args: Vec<String> = params.iter().map(|p| scalar_num_of(node, p)).collect();
                let _ = write!(out, "{f}({})", args.join(", "));
            }
            // A hero is sized by the caller, because only the lowering knows
            // what will be DRAWN — a live value's text is not in the DSL.
            "TextHero" => {
                let body = makepad::valued(node);
                let _ = write!(out, "{f}({body}, {})", makepad::hero_points(node, &body));
            }
            // The remaining text roles take one string.
            _ => {
                // Always through `valued`: it falls back to `text:` and
                // decorates either way. Branching here meant a `text:` carrying a
                // `suffix:` skipped the decoration entirely.
                let body = makepad::valued(node);
                let _ = write!(out, "{f}({body})");
            }
        }
    }
}

#[cfg(test)]
mod guarded_fields_tests {
    /// A guard on a live scalar is reported; a guard on state or `$state` is not.
    #[test]
    fn only_source_fields_a_card_guards_on_are_reported() {
        let card = "source now sys.weather(lat: 1, lon: 2, fields: [temp, precip])\n\
                    state mode { shape: enum[a, b], initial: .a }\n\
                    view root Surface {\n\
                      when now.$state == .pending { Rule() }\n\
                      when mode == .a { Rule() }\n\
                      when now.precip >= 40 { Rule() }\n\
                      when now.precip < 40 { inner }\n\
                    }\n\
                    view inner Col { when now.temp < 12 { Rule() } }\n";
        let got = super::guarded_source_fields(card);
        assert!(
            got.contains(&("now".to_owned(), "precip".to_owned())),
            "{got:?}"
        );
        // Nested inside another guard's body, and inside a named view.
        assert!(
            got.contains(&("now".to_owned(), "temp".to_owned())),
            "{got:?}"
        );
        // Deduped: `precip` is guarded twice.
        assert_eq!(
            got.len(),
            2,
            "state, $state and duplicates must not appear: {got:?}"
        );
    }
}
