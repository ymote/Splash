//! Canonical Splash v0.2 source-profile validation.
//!
//! The vendored Makepad parser intentionally accepts a larger compatibility
//! language. This module accepts only the portable grammar documented by
//! Splash, without producing bytecode or evaluating source.

use std::collections::{HashMap, HashSet};

use super::{
    LexicalCompletionReport, LexicalSymbol, LexicalSymbolKind, LexicalSymbolReport, ModuleImport,
    ModuleImportReport, SourceSpan, StaticRecordField, StaticRecordShape, StaticRecordShapeReport,
    SyntaxDiagnostic, ToolCallHint, ToolCallHintReport, ToolCallKind, TopLevelDeclaration,
    TopLevelDeclarationKind, MAX_LEXICAL_COMPLETION_SITES, MAX_LEXICAL_SYMBOL_OCCURRENCES,
    MAX_MODULE_IMPORTS, MAX_STATIC_RECORD_FIELDS, MAX_STATIC_RECORD_SHAPES, MAX_SYNTAX_DIAGNOSTICS,
    MAX_TOOL_CALL_HINTS,
};

pub(super) struct ProfileReport {
    pub(super) diagnostics: Vec<SyntaxDiagnostic>,
    pub(super) diagnostics_truncated: bool,
}

pub(super) enum ProfileFormatError {
    Profile(ProfileReport),
    OutputTooLarge { actual: usize, maximum: usize },
}

/// Canonical source prepared for the inherited VM parser.
///
/// Makepad's streaming tokenizer treats newlines as whitespace. Canonical
/// Splash gives newlines statement-boundary meaning, so a validated source is
/// lowered by inserting only the VM separators that preserve those boundaries.
pub(super) struct LoweredCanonicalSource {
    pub(super) source: String,
    pub(super) inserted_statement_separators: usize,
}

#[cfg(any(fuzzing, test))]
pub(super) fn check_canonical_profile(
    source: &str,
    max_tokens: usize,
    max_nesting: usize,
) -> ProfileReport {
    let lexer = ProfileLexer::new(source, max_tokens);
    let (tokens, diagnostics, diagnostics_truncated) = lexer.tokenize();
    if !diagnostics.is_empty() || diagnostics_truncated {
        return ProfileReport {
            diagnostics,
            diagnostics_truncated,
        };
    }

    CanonicalParser::new(tokens, max_nesting).parse()
}

/// Validates canonical source and lowers its statement-ending newlines to the
/// explicit separators required by the inherited VM tokenizer.
pub(super) fn lower_canonical_source_for_vm(
    source: &str,
    max_tokens: usize,
    max_nesting: usize,
) -> Result<LoweredCanonicalSource, ProfileReport> {
    let lexer = ProfileLexer::new(source, max_tokens);
    let (tokens, diagnostics, diagnostics_truncated) = lexer.tokenize();
    if !diagnostics.is_empty() || diagnostics_truncated {
        return Err(ProfileReport {
            diagnostics,
            diagnostics_truncated,
        });
    }

    CanonicalParser::new(tokens, max_nesting).lower_for_vm(source)
}

pub(super) fn is_canonical_identifier(name: &str) -> bool {
    // `End` is appended outside the ordinary token budget, so one slot accepts
    // exactly one identifier token and no second source token.
    let lexer = ProfileLexer::new(name, 1);
    let (tokens, diagnostics, diagnostics_truncated) = lexer.tokenize();
    if !diagnostics.is_empty() || diagnostics_truncated || tokens.len() != 2 {
        return false;
    }

    matches!(
        &tokens[0].kind,
        TokenKind::Identifier(identifier)
            if identifier == name && !is_reserved_identifier(identifier)
    ) && matches!(tokens[1].kind, TokenKind::End)
}

/// Extracts declarations after the public caller has confirmed that the source
/// is canonical and compatible with the vendored parser. Reusing the profile
/// lexer keeps tooling structure aligned with canonical token rules.
pub(super) fn collect_top_level_declarations(
    source: &str,
    max_tokens: usize,
) -> Vec<TopLevelDeclaration> {
    let lexer = ProfileLexer::new(source, max_tokens);
    let (tokens, _, _) = lexer.tokenize();
    top_level_declarations_from_tokens(&tokens)
}

/// Builds a lexical index after the public caller has confirmed canonical,
/// VM-compatible source. Parsing the already bounded token stream gives the
/// collector exact binding contexts without evaluating source or imports.
pub(super) fn collect_lexical_symbols(
    source: &str,
    max_tokens: usize,
    max_nesting: usize,
) -> LexicalSymbolReport {
    let lexer = ProfileLexer::new(source, max_tokens);
    let (tokens, _, _) = lexer.tokenize();
    let collected = CanonicalParser::new(tokens, max_nesting).collect_symbols(source.len());
    LexicalSymbolReport {
        symbols: collected.symbols,
        truncated: collected.symbols_truncated,
    }
}

/// Builds completion metadata from the bounded canonical token stream.
///
/// Unlike navigation, completion may consume an invalid source prefix. The
/// public caller supplies the first diagnostic boundary, and consumers must
/// ignore sites beyond it.
pub(super) fn collect_lexical_completions(
    source: &str,
    max_tokens: usize,
    max_nesting: usize,
    valid_prefix_end_byte: usize,
) -> LexicalCompletionReport {
    let lexer = ProfileLexer::new(source, max_tokens);
    let (tokens, _, _) = lexer.tokenize();
    let collected = CanonicalParser::new(tokens, max_nesting).collect_symbols(source.len());
    LexicalCompletionReport {
        symbols: collected.symbols,
        sites: collected.completion_sites,
        symbols_truncated: collected.symbols_truncated,
        sites_truncated: collected.completion_sites_truncated,
        valid_prefix_end_byte,
    }
}

/// Extracts complete import declarations from the bounded canonical token
/// stream. The caller supplies the syntax-safe prefix boundary so this can
/// support incomplete editor snapshots without treating later recovery tokens
/// as semantic import metadata.
pub(super) fn collect_module_imports(
    source: &str,
    max_tokens: usize,
    max_nesting: usize,
    valid_prefix_end_byte: usize,
) -> ModuleImportReport {
    let lexer = ProfileLexer::new(source, max_tokens);
    let (tokens, _, _) = lexer.tokenize();
    CanonicalParser::new(tokens, max_nesting).collect_module_imports(valid_prefix_end_byte)
}

/// Collects exact direct literal-record initializers after the public caller
/// has bounded and syntax-checked the source. The parser still runs for an
/// incomplete editor snapshot, but the collector keeps only complete shapes
/// ending before the supplied safe-prefix boundary.
pub(super) fn collect_static_record_shapes(
    source: &str,
    max_tokens: usize,
    max_nesting: usize,
    valid_prefix_end_byte: usize,
) -> StaticRecordShapeReport {
    let lexer = ProfileLexer::new(source, max_tokens);
    let (tokens, _, _) = lexer.tokenize();
    CanonicalParser::new(tokens, max_nesting).collect_static_record_shapes(valid_prefix_end_byte)
}

/// Extracts direct `mod.tool` call syntax after the public caller has already
/// confirmed canonical VM-compatible source. This deliberately scans tokens
/// rather than attempting name or flow resolution: it is a bounded review hint
/// that must never become an authorization decision.
pub(super) fn collect_tool_call_hints(source: &str, max_tokens: usize) -> ToolCallHintReport {
    let lexer = ProfileLexer::new(source, max_tokens);
    let (tokens, _, _) = lexer.tokenize();
    tool_call_hints_from_tokens(source, &tokens)
}

/// Formats source after validating the canonical grammar without evaluating it.
///
/// The formatter preserves lexical token spellings and comments. It only
/// normalizes whitespace around canonical tokens, so it never has to invent a
/// second expression parser or rewrite a literal.
pub(super) fn format_canonical_source(
    source: &str,
    max_tokens: usize,
    max_nesting: usize,
    max_output_bytes: usize,
) -> Result<String, ProfileFormatError> {
    let lexer = ProfileLexer::new(source, max_tokens);
    let (tokens, diagnostics, diagnostics_truncated) = lexer.tokenize();
    if !diagnostics.is_empty() || diagnostics_truncated {
        return Err(ProfileFormatError::Profile(ProfileReport {
            diagnostics,
            diagnostics_truncated,
        }));
    }

    let profile = CanonicalParser::new(tokens.clone(), max_nesting).parse();
    if !profile.diagnostics.is_empty() || profile.diagnostics_truncated {
        return Err(ProfileFormatError::Profile(profile));
    }

    // A newline is a lexical token. Preserve validity under an exact token
    // budget by omitting only the otherwise conventional final newline when
    // the input already consumed every token slot.
    let append_terminal_newline = tokens.len() <= max_tokens;
    CanonicalFormatter::new(source, tokens, max_output_bytes, append_terminal_newline).format()
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TokenKind {
    Identifier(String),
    Number,
    StringLiteral,
    Newline,
    Semicolon,
    Comma,
    OpenCurly,
    CloseCurly,
    OpenRound,
    CloseRound,
    OpenSquare,
    CloseSquare,
    Operator(String),
    End,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Token {
    kind: TokenKind,
    line: usize,
    column: usize,
    start_byte: usize,
    end_byte: usize,
}

struct SymbolCollector {
    symbols: Vec<LexicalSymbol>,
    scopes: Vec<SymbolScope>,
    completion_sites: Vec<SourceSpan>,
    occurrences: usize,
    truncated: bool,
    completion_sites_truncated: bool,
}

struct SymbolScope {
    bindings: HashMap<String, usize>,
    defined_symbols: Vec<usize>,
}

impl SymbolScope {
    fn new() -> Self {
        Self {
            bindings: HashMap::new(),
            defined_symbols: Vec::new(),
        }
    }
}

struct CollectedLexicalData {
    symbols: Vec<LexicalSymbol>,
    completion_sites: Vec<SourceSpan>,
    symbols_truncated: bool,
    completion_sites_truncated: bool,
}

struct ModuleImportCollector {
    imports: Vec<ModuleImport>,
    truncated: bool,
    valid_prefix_end_byte: usize,
}

impl ModuleImportCollector {
    fn new(valid_prefix_end_byte: usize) -> Self {
        Self {
            imports: Vec::new(),
            truncated: false,
            valid_prefix_end_byte,
        }
    }

    fn record(&mut self, path: Vec<String>, path_span: SourceSpan, binding: SourceSpan) {
        if path_span.end_byte > self.valid_prefix_end_byte {
            return;
        }
        if self.imports.len() == MAX_MODULE_IMPORTS {
            self.truncated = true;
            return;
        }
        self.imports.push(ModuleImport {
            path,
            path_span,
            binding,
        });
    }

    fn finish(self) -> ModuleImportReport {
        ModuleImportReport {
            imports: self.imports,
            truncated: self.truncated,
            valid_prefix_end_byte: self.valid_prefix_end_byte,
        }
    }
}

struct StaticRecordShapeCollector {
    shapes: Vec<StaticRecordShape>,
    retained_fields: usize,
    truncated: bool,
    valid_prefix_end_byte: usize,
}

struct DirectRecordShape {
    fields: Vec<StaticRecordField>,
    end_byte: usize,
}

impl StaticRecordShapeCollector {
    fn new(valid_prefix_end_byte: usize) -> Self {
        Self {
            shapes: Vec::new(),
            retained_fields: 0,
            truncated: false,
            valid_prefix_end_byte,
        }
    }

    fn record(&mut self, binding: SourceSpan, shape: DirectRecordShape) {
        if shape.end_byte > self.valid_prefix_end_byte {
            return;
        }
        if self.shapes.len() == MAX_STATIC_RECORD_SHAPES
            || self.retained_fields.saturating_add(shape.fields.len()) > MAX_STATIC_RECORD_FIELDS
        {
            self.truncated = true;
            return;
        }

        self.retained_fields += shape.fields.len();
        self.shapes.push(StaticRecordShape {
            binding,
            fields: shape.fields,
        });
    }

    fn finish(self) -> StaticRecordShapeReport {
        StaticRecordShapeReport {
            shapes: self.shapes,
            truncated: self.truncated,
            valid_prefix_end_byte: self.valid_prefix_end_byte,
        }
    }
}

impl SymbolCollector {
    fn new() -> Self {
        Self {
            symbols: Vec::new(),
            scopes: vec![SymbolScope::new()],
            completion_sites: Vec::new(),
            occurrences: 0,
            truncated: false,
            completion_sites_truncated: false,
        }
    }

    fn push_scope(&mut self) {
        self.scopes.push(SymbolScope::new());
    }

    fn pop_scope(&mut self, visibility_end_byte: usize) {
        if self.scopes.len() > 1 {
            let scope = self
                .scopes
                .pop()
                .expect("a non-root lexical scope is present");
            self.close_scope(scope, visibility_end_byte);
        }
    }

    fn define(
        &mut self,
        name: String,
        definition: SourceSpan,
        kind: LexicalSymbolKind,
        visibility_start_byte: usize,
    ) {
        if !self.reserve_occurrence() {
            return;
        }

        let symbol_index = self.symbols.len();
        self.symbols.push(LexicalSymbol {
            kind,
            name: name.clone(),
            definition,
            references: Vec::new(),
            visibility_start_byte,
            visibility_end_byte: usize::MAX,
        });
        let scope = self
            .scopes
            .last_mut()
            .expect("the lexical collector always has a root scope");
        if let Some(shadowed_index) = scope.bindings.insert(name, symbol_index) {
            self.symbols[shadowed_index].visibility_end_byte = visibility_start_byte;
        }
        scope.defined_symbols.push(symbol_index);
    }

    fn reference(&mut self, name: &str, reference: SourceSpan) {
        self.record_completion_site(reference);
        if self.truncated {
            return;
        }
        let Some(symbol_index) = self
            .scopes
            .iter()
            .rev()
            .find_map(|scope| scope.bindings.get(name).copied())
        else {
            return;
        };
        if !self.reserve_occurrence() {
            return;
        }
        self.symbols[symbol_index].references.push(reference);
    }

    fn record_completion_site(&mut self, site: SourceSpan) {
        if self.completion_sites_truncated {
            return;
        }
        if self.completion_sites.len() == MAX_LEXICAL_COMPLETION_SITES {
            self.completion_sites_truncated = true;
            return;
        }
        self.completion_sites.push(site);
    }

    fn reserve_occurrence(&mut self) -> bool {
        if self.truncated {
            return false;
        }
        if self.occurrences == MAX_LEXICAL_SYMBOL_OCCURRENCES {
            self.truncated = true;
            return false;
        }
        self.occurrences += 1;
        true
    }

    fn close_scope(&mut self, scope: SymbolScope, visibility_end_byte: usize) {
        for symbol_index in scope.defined_symbols {
            let symbol = &mut self.symbols[symbol_index];
            if symbol.visibility_end_byte == usize::MAX {
                symbol.visibility_end_byte = visibility_end_byte;
            }
        }
    }

    fn finish(mut self, source_end_byte: usize) -> CollectedLexicalData {
        while let Some(scope) = self.scopes.pop() {
            self.close_scope(scope, source_end_byte);
        }
        self.symbols
            .sort_by_key(|symbol| symbol.definition.start_byte);
        CollectedLexicalData {
            symbols: self.symbols,
            completion_sites: self.completion_sites,
            symbols_truncated: self.truncated,
            completion_sites_truncated: self.completion_sites_truncated,
        }
    }
}

fn top_level_declarations_from_tokens(tokens: &[Token]) -> Vec<TopLevelDeclaration> {
    let mut declarations = Vec::new();
    let mut brace_depth = 0_usize;

    for (index, token) in tokens.iter().enumerate() {
        match &token.kind {
            TokenKind::OpenCurly => brace_depth = brace_depth.saturating_add(1),
            TokenKind::CloseCurly => brace_depth = brace_depth.saturating_sub(1),
            TokenKind::Identifier(keyword) if brace_depth == 0 && keyword == "fn" => {
                let Some(name) = tokens.get(index + 1).and_then(identifier_token) else {
                    continue;
                };
                let declaration_end_byte =
                    function_declaration_end_byte(tokens, index + 2).unwrap_or(name.end_byte);
                declarations.push(TopLevelDeclaration {
                    kind: TopLevelDeclarationKind::Function,
                    name: name.identifier.clone(),
                    declaration_start_byte: token.start_byte,
                    declaration_end_byte,
                    selection_start_byte: name.start_byte,
                    selection_end_byte: name.end_byte,
                });
            }
            TokenKind::Identifier(keyword) if brace_depth == 0 && keyword == "let" => {
                let Some(name) = tokens.get(index + 1).and_then(identifier_token) else {
                    continue;
                };
                declarations.push(TopLevelDeclaration {
                    kind: TopLevelDeclarationKind::Let,
                    name: name.identifier.clone(),
                    declaration_start_byte: token.start_byte,
                    declaration_end_byte: declaration_end_byte(tokens, index + 2, name.end_byte),
                    selection_start_byte: name.start_byte,
                    selection_end_byte: name.end_byte,
                });
            }
            _ => {}
        }
    }

    declarations
}

fn tool_call_hints_from_tokens(source: &str, tokens: &[Token]) -> ToolCallHintReport {
    let mut hints = Vec::new();
    let mut truncated = false;

    for index in 0..tokens.len() {
        let Some(kind) = direct_tool_call_kind(tokens, index) else {
            continue;
        };

        // `object.tool.call(...)` is a member access rather than the direct
        // `mod.tool` identifier. We keep the scanner intentionally narrow.
        if index > 0 && is_operator(&tokens[index - 1].kind, ".") {
            continue;
        }

        if hints.len() == MAX_TOOL_CALL_HINTS {
            truncated = true;
            continue;
        }

        let callee = &tokens[index];
        let method = &tokens[index + 2];
        let literal = tokens
            .get(index + 4)
            .filter(|token| matches!(&token.kind, TokenKind::StringLiteral));
        let (literal_name, literal_name_start_byte, literal_name_end_byte) =
            literal.map_or((None, None, None), |token| {
                (
                    decode_canonical_string_literal(source, token),
                    Some(token.start_byte),
                    Some(token.end_byte),
                )
            });

        hints.push(ToolCallHint {
            kind,
            literal_name,
            line: callee.line,
            column: callee.column,
            callee_start_byte: callee.start_byte,
            callee_end_byte: method.end_byte,
            literal_name_start_byte,
            literal_name_end_byte,
        });
    }

    ToolCallHintReport { hints, truncated }
}

fn direct_tool_call_kind(tokens: &[Token], index: usize) -> Option<ToolCallKind> {
    let tool = tokens.get(index)?;
    let separator = tokens.get(index + 1)?;
    let method = tokens.get(index + 2)?;
    let opening = tokens.get(index + 3)?;

    if !is_identifier_named(tool, "tool")
        || !is_operator(&separator.kind, ".")
        || !matches!(&opening.kind, TokenKind::OpenRound)
    {
        return None;
    }

    let TokenKind::Identifier(name) = &method.kind else {
        return None;
    };
    match name.as_str() {
        "call" => Some(ToolCallKind::Call),
        "start" => Some(ToolCallKind::Start),
        "call_json" => Some(ToolCallKind::CallJson),
        "start_json" => Some(ToolCallKind::StartJson),
        _ => None,
    }
}

fn is_identifier_named(token: &Token, expected: &str) -> bool {
    matches!(&token.kind, TokenKind::Identifier(identifier) if identifier == expected)
}

fn decode_canonical_string_literal(source: &str, token: &Token) -> Option<String> {
    let literal = source.get(token.start_byte..token.end_byte)?;
    let content = literal.strip_prefix('"')?.strip_suffix('"')?;
    let mut characters = content.chars();
    let mut decoded = String::with_capacity(content.len());

    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }

        let escaped = match characters.next()? {
            '"' => '"',
            '\\' => '\\',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => decode_unicode_escape(&mut characters)?,
            _ => return None,
        };
        decoded.push(escaped);
    }

    Some(decoded)
}

fn decode_unicode_escape(characters: &mut std::str::Chars<'_>) -> Option<char> {
    let first = characters.next()?;
    let mut digits = String::new();

    if first == '{' {
        loop {
            let character = characters.next()?;
            if character == '}' {
                break;
            }
            if !character.is_ascii_hexdigit() || digits.len() >= 6 {
                return None;
            }
            digits.push(character);
        }
        if digits.is_empty() {
            return None;
        }
    } else {
        if !first.is_ascii_hexdigit() {
            return None;
        }
        digits.push(first);
        for _ in 0..3 {
            let character = characters.next()?;
            if !character.is_ascii_hexdigit() {
                return None;
            }
            digits.push(character);
        }
    }

    u32::from_str_radix(&digits, 16)
        .ok()
        .and_then(char::from_u32)
}

struct IdentifierToken<'token> {
    identifier: &'token String,
    start_byte: usize,
    end_byte: usize,
}

fn identifier_token(token: &Token) -> Option<IdentifierToken<'_>> {
    let TokenKind::Identifier(identifier) = &token.kind else {
        return None;
    };
    Some(IdentifierToken {
        identifier,
        start_byte: token.start_byte,
        end_byte: token.end_byte,
    })
}

fn function_declaration_end_byte(tokens: &[Token], after_name: usize) -> Option<usize> {
    let opening = tokens
        .iter()
        .skip(after_name)
        .position(|token| matches!(&token.kind, TokenKind::OpenCurly))?
        + after_name;
    let mut depth = 0_usize;

    for token in &tokens[opening..] {
        match &token.kind {
            TokenKind::OpenCurly => depth = depth.saturating_add(1),
            TokenKind::CloseCurly => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(token.end_byte);
                }
            }
            _ => {}
        }
    }

    None
}

fn declaration_end_byte(tokens: &[Token], after_name: usize, initial_end_byte: usize) -> usize {
    let mut end_byte = initial_end_byte;
    let mut nesting = 0_usize;

    for token in tokens.iter().skip(after_name) {
        match &token.kind {
            TokenKind::Newline | TokenKind::Semicolon if nesting == 0 => return end_byte,
            TokenKind::End => return end_byte,
            TokenKind::OpenCurly | TokenKind::OpenRound | TokenKind::OpenSquare => {
                nesting = nesting.saturating_add(1);
            }
            TokenKind::CloseCurly | TokenKind::CloseRound | TokenKind::CloseSquare => {
                nesting = nesting.saturating_sub(1);
            }
            _ => {}
        }
        end_byte = token.end_byte;
    }

    end_byte
}

struct ProfileLexer<'source> {
    source: &'source str,
    chars: Vec<char>,
    byte_offsets: Vec<usize>,
    index: usize,
    line: usize,
    column: usize,
    max_tokens: usize,
    tokens: Vec<Token>,
    diagnostics: Vec<SyntaxDiagnostic>,
    diagnostics_truncated: bool,
    token_limit_reported: bool,
}

impl<'source> ProfileLexer<'source> {
    fn new(source: &'source str, max_tokens: usize) -> Self {
        let mut chars = Vec::new();
        let mut byte_offsets = Vec::new();
        for (byte_offset, character) in source.char_indices() {
            chars.push(character);
            byte_offsets.push(byte_offset);
        }
        byte_offsets.push(source.len());

        Self {
            source,
            chars,
            byte_offsets,
            index: 0,
            line: 1,
            column: 1,
            max_tokens,
            tokens: Vec::new(),
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            token_limit_reported: false,
        }
    }

    fn tokenize(mut self) -> (Vec<Token>, Vec<SyntaxDiagnostic>, bool) {
        while let Some(character) = self.current() {
            match character {
                ' ' | '\t' | '\u{000C}' => {
                    self.advance();
                }
                '\n' => self.emit_newline(),
                '\r' => self.emit_carriage_return_newline(),
                '/' if self.peek() == Some('/') => self.skip_line_comment(),
                '/' if self.peek() == Some('*') => self.skip_block_comment(),
                'A'..='Z' | 'a'..='z' | '_' => self.scan_identifier(),
                '0'..='9' => self.scan_number(),
                '"' => self.scan_string(),
                '\'' => self.scan_single_quoted_string(),
                '{' => self.emit_single(TokenKind::OpenCurly),
                '}' => self.emit_single(TokenKind::CloseCurly),
                '(' => self.emit_single(TokenKind::OpenRound),
                ')' => self.emit_single(TokenKind::CloseRound),
                '[' => self.emit_single(TokenKind::OpenSquare),
                ']' => self.emit_single(TokenKind::CloseSquare),
                ',' => self.emit_single(TokenKind::Comma),
                ';' => self.emit_single(TokenKind::Semicolon),
                character if is_operator_character(character) => self.scan_operator(),
                character => {
                    let (line, column) = self.location();
                    self.report(
                        line,
                        column,
                        format!(
                            "unsupported character `{character}` in the canonical Splash profile"
                        ),
                    );
                    self.advance();
                }
            }
        }

        self.tokens.push(Token {
            kind: TokenKind::End,
            line: self.line,
            column: self.column,
            start_byte: self.source.len(),
            end_byte: self.source.len(),
        });
        (self.tokens, self.diagnostics, self.diagnostics_truncated)
    }

    fn current(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.index + 1).copied()
    }

    fn location(&self) -> (usize, usize) {
        (self.line, self.column)
    }

    fn advance(&mut self) -> Option<char> {
        let character = self.current()?;
        self.index += 1;
        if character == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(character)
    }

    fn emit(
        &mut self,
        kind: TokenKind,
        line: usize,
        column: usize,
        start_index: usize,
        end_index: usize,
    ) {
        if self.tokens.len() >= self.max_tokens {
            self.report_token_limit_at(line, column);
            return;
        }
        self.tokens.push(Token {
            kind,
            line,
            column,
            start_byte: self.byte_offsets[start_index],
            end_byte: self.byte_offsets[end_index],
        });
    }

    fn report_token_limit_at(&mut self, line: usize, column: usize) {
        if self.token_limit_reported {
            return;
        }
        self.report(
            line,
            column,
            format!(
                "canonical Splash token count exceeds the maximum of {}",
                self.max_tokens
            ),
        );
        self.token_limit_reported = true;
    }

    fn emit_single(&mut self, kind: TokenKind) {
        let (line, column) = self.location();
        let start_index = self.index;
        self.advance();
        self.emit(kind, line, column, start_index, self.index);
    }

    fn emit_newline(&mut self) {
        let (line, column) = self.location();
        let start_index = self.index;
        self.advance();
        self.emit(TokenKind::Newline, line, column, start_index, self.index);
    }

    fn emit_carriage_return_newline(&mut self) {
        let (line, column) = self.location();
        if self.peek() != Some('\n') {
            self.report(
                line,
                column,
                "bare carriage returns are not supported; use `\\n` or `\\r\\n` line endings",
            );
            self.advance();
            return;
        }
        let start_index = self.index;
        self.advance();
        self.advance();
        self.emit(TokenKind::Newline, line, column, start_index, self.index);
    }

    fn scan_identifier(&mut self) {
        let (line, column) = self.location();
        let start = self.index;
        self.advance();
        while self
            .current()
            .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            self.advance();
        }
        let identifier = self.chars[start..self.index].iter().collect();
        self.emit(
            TokenKind::Identifier(identifier),
            line,
            column,
            start,
            self.index,
        );
    }

    fn scan_number(&mut self) {
        let (line, column) = self.location();
        let start = self.index;
        self.consume_ascii_digits();

        if self.current() == Some('.') {
            if self
                .peek()
                .is_some_and(|character| character.is_ascii_digit())
            {
                self.advance();
                self.consume_ascii_digits();
            } else {
                let (decimal_line, decimal_column) = self.location();
                self.report(
                    decimal_line,
                    decimal_column,
                    "numeric literal decimal points must be followed by a digit; use whitespace or parentheses before field access",
                );
            }
        }

        if self
            .current()
            .is_some_and(|character| matches!(character, 'e' | 'E'))
        {
            let (exponent_line, exponent_column) = self.location();
            self.advance();
            if self
                .current()
                .is_some_and(|character| matches!(character, '+' | '-'))
            {
                self.advance();
            }
            if self
                .current()
                .is_some_and(|character| character.is_ascii_digit())
            {
                self.consume_ascii_digits();
            } else {
                self.report(
                    exponent_line,
                    exponent_column,
                    "exponents require at least one digit",
                );
            }
        }

        if self
            .current()
            .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        {
            let (suffix_line, suffix_column) = self.location();
            self.report(
                suffix_line,
                suffix_column,
                "numeric literal suffixes are not part of the canonical Splash profile",
            );
        }

        self.emit(TokenKind::Number, line, column, start, self.index);
    }

    fn consume_ascii_digits(&mut self) {
        while self
            .current()
            .is_some_and(|character| character.is_ascii_digit())
        {
            self.advance();
        }
    }

    fn scan_string(&mut self) {
        let (line, column) = self.location();
        let start = self.index;
        self.advance();
        let mut terminated = false;

        while let Some(character) = self.current() {
            match character {
                '"' => {
                    self.advance();
                    terminated = true;
                    break;
                }
                '\\' => {
                    self.advance();
                    self.scan_escape_sequence(line, column);
                }
                '\n' | '\r' => {
                    self.report(line, column, "unterminated string literal");
                    break;
                }
                _ => {
                    self.advance();
                }
            }
        }

        if !terminated && self.current().is_none() {
            self.report(line, column, "unterminated string literal");
        }
        self.emit(TokenKind::StringLiteral, line, column, start, self.index);
    }

    fn scan_escape_sequence(&mut self, string_line: usize, string_column: usize) {
        let Some(escape) = self.current() else {
            self.report(string_line, string_column, "unterminated string literal");
            return;
        };

        match escape {
            '"' | '\\' | 'n' | 'r' | 't' => {
                self.advance();
            }
            'u' => {
                self.advance();
                self.scan_unicode_escape(string_line, string_column);
            }
            _ => {
                let (line, column) = self.location();
                self.report(
                    line,
                    column,
                    "unsupported string escape in the canonical Splash profile",
                );
                self.advance();
            }
        }
    }

    fn scan_unicode_escape(&mut self, string_line: usize, string_column: usize) {
        if self.current() == Some('{') {
            self.advance();
            let mut digits = 0_usize;
            let mut value = 0_u32;
            while self
                .current()
                .is_some_and(|character| character.is_ascii_hexdigit())
            {
                digits += 1;
                if digits <= 6 {
                    let digit = self
                        .current()
                        .and_then(|character| character.to_digit(16))
                        .expect("ASCII hexadecimal digits have a base-16 value");
                    value = value.saturating_mul(16).saturating_add(digit);
                }
                self.advance();
            }
            if !(1..=6).contains(&digits) || self.current() != Some('}') {
                self.report(
                    string_line,
                    string_column,
                    "unicode escapes must use four hexadecimal digits or `\\u{...}` with one to six hexadecimal digits",
                );
                while self
                    .current()
                    .is_some_and(|character| character != '}' && character != '\n')
                {
                    self.advance();
                }
            } else if char::from_u32(value).is_none() {
                self.report(
                    string_line,
                    string_column,
                    "unicode escapes must encode a valid Unicode scalar value",
                );
            }
            if self.current() == Some('}') {
                self.advance();
            }
            return;
        }

        let mut digits = 0_usize;
        let mut value = 0_u32;
        while digits < 4
            && self
                .current()
                .is_some_and(|character| character.is_ascii_hexdigit())
        {
            digits += 1;
            let digit = self
                .current()
                .and_then(|character| character.to_digit(16))
                .expect("ASCII hexadecimal digits have a base-16 value");
            value = value.saturating_mul(16).saturating_add(digit);
            self.advance();
        }
        if digits != 4 {
            self.report(
                string_line,
                string_column,
                "unicode escapes must use four hexadecimal digits or `\\u{...}` with one to six hexadecimal digits",
            );
        } else if char::from_u32(value).is_none() {
            self.report(
                string_line,
                string_column,
                "unicode escapes must encode a valid Unicode scalar value",
            );
        }
    }

    fn scan_single_quoted_string(&mut self) {
        let (line, column) = self.location();
        self.report(
            line,
            column,
            "only double-quoted strings are part of the canonical Splash profile",
        );
        self.advance();
        while let Some(character) = self.current() {
            if matches!(character, '\n' | '\r') {
                return;
            }
            self.advance();
            if character == '\\' {
                self.advance();
            } else if character == '\'' {
                return;
            }
        }
    }

    fn skip_line_comment(&mut self) {
        self.advance();
        self.advance();
        while self
            .current()
            .is_some_and(|character| character != '\n' && character != '\r')
        {
            self.advance();
        }
    }

    fn skip_block_comment(&mut self) {
        let (line, column) = self.location();
        self.advance();
        self.advance();
        let mut possible_terminator = false;
        while self.current().is_some() {
            if possible_terminator {
                if self.current() == Some('/') {
                    self.advance();
                    return;
                }

                // Mirror the inherited streaming tokenizer: after a failed
                // `*` terminator candidate, the current character has already
                // been consumed and cannot start an overlapping `*/` pair.
                // In particular, `**/` is not a block-comment terminator.
                possible_terminator = false;
                self.advance();
                continue;
            }
            if self.current() == Some('*') && self.peek() == Some('/') {
                self.advance();
                self.advance();
                return;
            }
            match self.current() {
                Some('*') => {
                    possible_terminator = true;
                    self.advance();
                }
                Some('\n') => self.emit_newline(),
                Some('\r') => self.emit_carriage_return_newline(),
                Some(_) => {
                    self.advance();
                }
                None => break,
            }
        }
        self.report(line, column, "unterminated block comment");
    }

    fn scan_operator(&mut self) {
        let (line, column) = self.location();
        let start = self.index;
        while self.current().is_some_and(is_operator_character) {
            self.advance();
        }
        let operator: String = self.chars[start..self.index].iter().collect();
        if is_canonical_operator(&operator) {
            self.emit(
                TokenKind::Operator(operator),
                line,
                column,
                start,
                self.index,
            );
        } else {
            self.report(
                line,
                column,
                format!("operator `{operator}` is not part of the canonical Splash profile"),
            );
        }
    }

    fn report(&mut self, line: usize, column: usize, message: impl Into<String>) {
        if self.diagnostics.len() < MAX_SYNTAX_DIAGNOSTICS {
            self.diagnostics.push(SyntaxDiagnostic {
                line,
                column,
                message: message.into(),
            });
        } else {
            self.diagnostics_truncated = true;
        }
    }
}

fn is_operator_character(character: char) -> bool {
    matches!(
        character,
        '!' | '^'
            | '&'
            | '*'
            | '+'
            | '-'
            | '|'
            | '?'
            | ':'
            | '='
            | '@'
            | '>'
            | '<'
            | '.'
            | '/'
            | '~'
            | '%'
    )
}

fn is_canonical_operator(operator: &str) -> bool {
    matches!(
        operator,
        "!" | "-"
            | "+"
            | "~"
            | "="
            | "+="
            | "-="
            | "*="
            | "/="
            | "%="
            | "||"
            | "&&"
            | "=="
            | "!="
            | "<"
            | "<="
            | ">"
            | ">="
            | "*"
            | "/"
            | "%"
            | "."
            | ":"
            | "|"
    )
}

const FORMAT_INDENT: &str = "    ";

struct CanonicalFormatter<'source> {
    source: &'source str,
    tokens: Vec<Token>,
    max_output_bytes: usize,
    append_terminal_newline: bool,
    output: String,
    indentation: usize,
    at_line_start: bool,
    previous: Option<TokenKind>,
    lambda_parameters_open: bool,
    previous_lambda_delimiter_closed: bool,
}

impl<'source> CanonicalFormatter<'source> {
    fn new(
        source: &'source str,
        tokens: Vec<Token>,
        max_output_bytes: usize,
        append_terminal_newline: bool,
    ) -> Self {
        Self {
            source,
            tokens,
            max_output_bytes,
            append_terminal_newline,
            output: String::with_capacity(source.len()),
            indentation: 0,
            at_line_start: true,
            previous: None,
            lambda_parameters_open: false,
            previous_lambda_delimiter_closed: false,
        }
    }

    fn format(mut self) -> Result<String, ProfileFormatError> {
        let source = self.source;
        let tokens = std::mem::take(&mut self.tokens);
        let mut cursor = 0;

        for token in tokens {
            if matches!(&token.kind, TokenKind::End) {
                break;
            }

            let raw_gap = &source[cursor..token.start_byte];
            let preserved_gap = self.write_raw_gap(raw_gap);
            self.ensure_output_limit()?;

            if matches!(&token.kind, TokenKind::Newline) {
                self.write_newline();
                self.ensure_output_limit()?;
                self.previous = None;
                self.previous_lambda_delimiter_closed = false;
                cursor = token.end_byte;
                continue;
            }

            if matches!(&token.kind, TokenKind::CloseCurly) {
                self.indentation = self.indentation.saturating_sub(1);
            }
            if self.at_line_start {
                self.write_indentation();
            } else if !preserved_gap
                && self.previous.as_ref().is_some_and(|previous| {
                    needs_space(
                        previous,
                        &token.kind,
                        self.previous_lambda_delimiter_closed,
                        is_operator(&token.kind, "|") && self.lambda_parameters_open,
                    )
                })
            {
                self.output.push(' ');
            }

            self.output
                .push_str(&source[token.start_byte..token.end_byte]);
            self.ensure_output_limit()?;
            if matches!(&token.kind, TokenKind::OpenCurly) {
                self.indentation += 1;
            }
            self.previous_lambda_delimiter_closed =
                is_operator(&token.kind, "|") && self.lambda_parameters_open;
            if is_operator(&token.kind, "|") {
                self.lambda_parameters_open = !self.lambda_parameters_open;
            }
            self.previous = Some(token.kind.clone());
            self.at_line_start = false;
            cursor = token.end_byte;
        }

        self.write_raw_gap(&source[cursor..]);
        self.ensure_output_limit()?;
        self.trim_trailing_horizontal_whitespace();
        if self.append_terminal_newline && !self.output.is_empty() && !self.output.ends_with('\n') {
            self.output.push('\n');
            self.ensure_output_limit()?;
        }
        Ok(self.output)
    }

    /// Preserve a comment fragment while discarding ordinary horizontal
    /// whitespace. Block comments can cross newline tokens, so a fragment may
    /// contain only the closing `*/` portion of an original comment.
    fn write_raw_gap(&mut self, gap: &str) -> bool {
        if gap.chars().all(is_horizontal_whitespace) {
            return false;
        }

        if self.at_line_start {
            self.write_indentation();
            self.output
                .push_str(gap.trim_start_matches(is_horizontal_whitespace));
        } else {
            self.output.push_str(gap);
        }
        self.at_line_start = false;
        true
    }

    fn write_indentation(&mut self) {
        if !self.at_line_start {
            return;
        }
        for _ in 0..self.indentation {
            self.output.push_str(FORMAT_INDENT);
        }
        self.at_line_start = false;
    }

    fn write_newline(&mut self) {
        self.trim_trailing_horizontal_whitespace();
        self.output.push('\n');
        self.at_line_start = true;
    }

    fn trim_trailing_horizontal_whitespace(&mut self) {
        while self
            .output
            .chars()
            .last()
            .is_some_and(is_horizontal_whitespace)
        {
            let _ = self.output.pop();
        }
    }

    fn ensure_output_limit(&self) -> Result<(), ProfileFormatError> {
        if self.output.len() > self.max_output_bytes {
            return Err(ProfileFormatError::OutputTooLarge {
                actual: self.output.len(),
                maximum: self.max_output_bytes,
            });
        }
        Ok(())
    }
}

fn is_horizontal_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\u{000C}')
}

fn needs_space(
    previous: &TokenKind,
    current: &TokenKind,
    previous_lambda_delimiter_closed: bool,
    current_lambda_delimiter_closes: bool,
) -> bool {
    if is_operator(current, "|") && current_lambda_delimiter_closes {
        return false;
    }
    if is_operator(previous, "|") {
        return previous_lambda_delimiter_closed;
    }
    // The inherited VM treats an adjacent dot after a number as part of the
    // numeric token. Preserve the canonical separator for numeric field access.
    if matches!(previous, TokenKind::Number) && is_operator(current, ".") {
        return true;
    }
    if matches!(previous, TokenKind::OpenRound | TokenKind::OpenSquare)
        || is_operator(previous, ".")
        || matches!(
            current,
            TokenKind::CloseRound
                | TokenKind::CloseSquare
                | TokenKind::CloseCurly
                | TokenKind::Comma
                | TokenKind::Semicolon
        )
        || is_operator(current, ".")
        || is_operator(current, ":")
    {
        return false;
    }

    if matches!(current, TokenKind::OpenRound) {
        return is_control_keyword(previous);
    }
    if matches!(current, TokenKind::OpenSquare) {
        return !matches!(
            previous,
            TokenKind::Identifier(_)
                | TokenKind::Number
                | TokenKind::StringLiteral
                | TokenKind::OpenRound
                | TokenKind::OpenSquare
                | TokenKind::CloseRound
                | TokenKind::CloseSquare
                | TokenKind::CloseCurly
        );
    }
    if matches!(current, TokenKind::OpenCurly) {
        return !matches!(previous, TokenKind::OpenCurly);
    }
    if matches!(previous, TokenKind::OpenCurly) {
        return false;
    }
    if matches!(previous, TokenKind::Comma | TokenKind::Semicolon) || is_operator(previous, ":") {
        return true;
    }
    if matches!(previous, TokenKind::Operator(_)) || matches!(current, TokenKind::Operator(_)) {
        return true;
    }

    true
}

fn is_operator(token: &TokenKind, operator: &str) -> bool {
    matches!(token, TokenKind::Operator(actual) if actual == operator)
}

fn is_control_keyword(token: &TokenKind) -> bool {
    matches!(token, TokenKind::Identifier(identifier) if matches!(identifier.as_str(), "if" | "elif" | "while"))
}

fn direct_record_shape_from_tokens(
    tokens: &[Token],
    opening_index: usize,
) -> Option<DirectRecordShape> {
    if !matches!(&tokens.get(opening_index)?.kind, TokenKind::OpenCurly) {
        return None;
    }

    let (fields, closing_index) = direct_record_fields(tokens, opening_index)?;
    if !matches!(
        &tokens.get(closing_index + 1)?.kind,
        TokenKind::Newline | TokenKind::Semicolon | TokenKind::CloseCurly | TokenKind::End
    ) {
        return None;
    }

    Some(DirectRecordShape {
        fields,
        end_byte: tokens.get(closing_index)?.end_byte,
    })
}

fn direct_record_fields(
    tokens: &[Token],
    opening_index: usize,
) -> Option<(Vec<StaticRecordField>, usize)> {
    let mut fields = Vec::new();
    let mut field_names = HashSet::<&str>::new();
    let mut index = opening_index.checked_add(1)?;

    loop {
        while matches!(&tokens.get(index)?.kind, TokenKind::Newline) {
            index += 1;
        }
        if matches!(&tokens.get(index)?.kind, TokenKind::CloseCurly) {
            return Some((fields, index));
        }

        let field = tokens.get(index)?;
        let TokenKind::Identifier(name) = &field.kind else {
            return None;
        };
        if is_reserved_identifier(name) {
            return None;
        }
        index += 1;
        if !matches!(&tokens.get(index)?.kind, TokenKind::Operator(operator) if operator == ":") {
            return None;
        }
        index += 1;
        if matches!(
            &tokens.get(index)?.kind,
            TokenKind::Newline | TokenKind::Comma | TokenKind::CloseCurly | TokenKind::End
        ) {
            return None;
        }

        if field_names.insert(name.as_str()) {
            fields.push(StaticRecordField {
                name: name.clone(),
                definition: SourceSpan {
                    start_byte: field.start_byte,
                    end_byte: field.end_byte,
                },
            });
        }

        let mut round_depth = 0_usize;
        let mut square_depth = 0_usize;
        let mut curly_depth = 0_usize;
        loop {
            let token = tokens.get(index)?;
            match &token.kind {
                TokenKind::OpenRound => round_depth += 1,
                TokenKind::OpenSquare => square_depth += 1,
                TokenKind::OpenCurly => curly_depth += 1,
                TokenKind::CloseRound if round_depth == 0 => return None,
                TokenKind::CloseRound => round_depth -= 1,
                TokenKind::CloseSquare if square_depth == 0 => return None,
                TokenKind::CloseSquare => square_depth -= 1,
                TokenKind::CloseCurly if curly_depth > 0 => curly_depth -= 1,
                TokenKind::CloseCurly => return Some((fields, index)),
                TokenKind::Comma | TokenKind::Newline
                    if round_depth == 0 && square_depth == 0 && curly_depth == 0 =>
                {
                    index += 1;
                    break;
                }
                TokenKind::End => return None,
                _ => {}
            }
            index += 1;
        }
    }
}

struct CanonicalParser {
    tokens: Vec<Token>,
    index: usize,
    nesting: usize,
    maximum_nesting: usize,
    diagnostics: Vec<SyntaxDiagnostic>,
    diagnostics_truncated: bool,
    symbols: Option<SymbolCollector>,
    imports: Option<ModuleImportCollector>,
    static_record_shapes: Option<StaticRecordShapeCollector>,
    vm_statement_separator_offsets: Option<Vec<usize>>,
}

impl CanonicalParser {
    fn new(tokens: Vec<Token>, maximum_nesting: usize) -> Self {
        Self {
            tokens,
            index: 0,
            nesting: 0,
            maximum_nesting,
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            symbols: None,
            imports: None,
            static_record_shapes: None,
            vm_statement_separator_offsets: None,
        }
    }

    fn parse(mut self) -> ProfileReport {
        self.parse_program();
        ProfileReport {
            diagnostics: self.diagnostics,
            diagnostics_truncated: self.diagnostics_truncated,
        }
    }

    fn lower_for_vm(mut self, source: &str) -> Result<LoweredCanonicalSource, ProfileReport> {
        self.vm_statement_separator_offsets = Some(Vec::new());
        self.parse_program();
        let profile = ProfileReport {
            diagnostics: self.diagnostics,
            diagnostics_truncated: self.diagnostics_truncated,
        };
        if !profile.diagnostics.is_empty() || profile.diagnostics_truncated {
            return Err(profile);
        }

        let offsets = self
            .vm_statement_separator_offsets
            .take()
            .expect("VM statement-separator collection was enabled");
        let inserted_statement_separators = offsets.len();
        let mut lowered = String::with_capacity(source.len() + inserted_statement_separators);
        let mut source_offset = 0_usize;

        for offset in offsets {
            debug_assert!(source_offset <= offset && offset <= source.len());
            debug_assert!(source.is_char_boundary(offset));
            lowered.push_str(&source[source_offset..offset]);
            lowered.push(';');
            source_offset = offset;
        }
        lowered.push_str(&source[source_offset..]);

        Ok(LoweredCanonicalSource {
            source: lowered,
            inserted_statement_separators,
        })
    }

    fn collect_symbols(mut self, source_end_byte: usize) -> CollectedLexicalData {
        self.symbols = Some(SymbolCollector::new());
        self.parse_program();
        self.symbols
            .take()
            .expect("symbol collection was enabled")
            .finish(source_end_byte)
    }

    fn collect_module_imports(mut self, valid_prefix_end_byte: usize) -> ModuleImportReport {
        self.imports = Some(ModuleImportCollector::new(valid_prefix_end_byte));
        self.parse_program();
        self.imports
            .take()
            .expect("module import collection was enabled")
            .finish()
    }

    fn collect_static_record_shapes(
        mut self,
        valid_prefix_end_byte: usize,
    ) -> StaticRecordShapeReport {
        self.static_record_shapes = Some(StaticRecordShapeCollector::new(valid_prefix_end_byte));
        self.parse_program();
        self.static_record_shapes
            .take()
            .expect("static record-shape collection was enabled")
            .finish()
    }

    fn parse_program(&mut self) {
        self.consume_statement_ends();
        while !self.at_end() {
            if self.at_kind(&TokenKind::CloseCurly) {
                self.report_current("unexpected `}` at top level");
                self.advance();
                continue;
            }
            let start = self.index;
            self.parse_statement();
            self.require_statement_end();
            if self.index == start {
                self.advance();
            }
        }
    }

    fn parse_block(&mut self) {
        if !self.enter_nesting() {
            return;
        }
        if !self.take_kind(&TokenKind::OpenCurly) {
            self.report_current("expected `{` to start a block");
            self.leave_nesting();
            return;
        }
        self.consume_statement_ends();
        while !self.at_end() && !self.at_kind(&TokenKind::CloseCurly) {
            let start = self.index;
            self.parse_statement();
            self.require_statement_end();
            if self.index == start {
                self.advance();
            }
        }
        if !self.take_kind(&TokenKind::CloseCurly) {
            self.report_current("expected `}` to close a block");
        }
        self.leave_nesting();
    }

    fn parse_statement(&mut self) {
        if self.at_identifier("use") {
            self.advance();
            self.parse_import();
        } else if self.at_identifier("let") {
            self.advance();
            self.parse_declaration();
        } else if self.at_identifier("fn") {
            self.advance();
            self.parse_function_declaration();
        } else if self.at_identifier("return") {
            self.advance();
            if !self.at_statement_boundary() {
                self.parse_expression();
            }
        } else if self.at_identifier("break") || self.at_identifier("continue") {
            self.advance();
        } else {
            self.parse_expression();
        }
    }

    fn parse_import(&mut self) {
        let module_token = self.index;
        if !self.take_identifier_named("mod") {
            self.report_current("expected `mod` after `use`");
            return;
        }
        if !self.take_operator(".") {
            self.report_current("expected `.` after `use mod`");
            return;
        }
        let module_start_byte = self.tokens[module_token].start_byte;
        let mut path = vec!["mod".to_owned()];
        let mut path_end_byte = self.tokens[module_token].end_byte;
        let mut binding =
            self.take_plain_identifier("expected a module identifier after `use mod.`");
        if let Some(binding) = binding {
            if let Some((segment, span)) = self.symbol_token(binding) {
                path.push(segment);
                path_end_byte = span.end_byte;
            }
        }
        while self.take_operator(".") {
            binding = self.take_plain_identifier("expected a module identifier after `.`");
            if let Some(binding) = binding {
                if let Some((segment, span)) = self.symbol_token(binding) {
                    path.push(segment);
                    path_end_byte = span.end_byte;
                }
            }
        }
        if let Some(binding) = binding {
            if self.at_import_statement_end() {
                if let Some((_, binding_span)) = self.symbol_token(binding) {
                    self.record_import(
                        path,
                        SourceSpan {
                            start_byte: module_start_byte,
                            end_byte: path_end_byte,
                        },
                        binding_span,
                    );
                }
            }
            self.define_symbol(binding, LexicalSymbolKind::Import);
        }
    }

    fn parse_declaration(&mut self) {
        let binding = self.take_plain_identifier("expected an identifier after `let`");
        let direct_record_shape = if self.take_operator("=") {
            let shape = self.direct_record_shape();
            self.parse_expression();
            shape
        } else if !self.at_statement_boundary() {
            self.report_current("expected `=` or a statement end after a `let` declaration");
            None
        } else {
            None
        };
        if let Some(binding) = binding {
            if let Some(shape) = direct_record_shape {
                self.record_static_record_shape(binding, shape);
            }
            self.define_symbol(binding, LexicalSymbolKind::Let);
        }
    }

    fn direct_record_shape(&self) -> Option<DirectRecordShape> {
        direct_record_shape_from_tokens(&self.tokens, self.index)
    }

    fn parse_function_declaration(&mut self) {
        let binding = self.take_plain_identifier("expected a function identifier after `fn`");
        if let Some(binding) = binding {
            self.define_symbol(binding, LexicalSymbolKind::Function);
        }
        self.push_symbol_scope();
        self.parse_parameter_list();
        self.parse_block();
        self.pop_symbol_scope();
    }

    fn parse_parameter_list(&mut self) {
        if !self.take_kind(&TokenKind::OpenRound) {
            self.report_current("expected `(` after a function name");
            return;
        }
        if self.take_kind(&TokenKind::CloseRound) {
            return;
        }

        loop {
            if let Some(parameter) = self.take_plain_identifier("expected a parameter identifier") {
                self.define_symbol(parameter, LexicalSymbolKind::Parameter);
            }
            if self.take_kind(&TokenKind::Comma) {
                if self.at_kind(&TokenKind::CloseRound) {
                    self.report_current(
                        "trailing commas are not part of the canonical parameter grammar",
                    );
                    self.advance();
                    return;
                }
                continue;
            }
            if !self.take_kind(&TokenKind::CloseRound) {
                self.report_current("expected `,` or `)` after a parameter");
            }
            return;
        }
    }

    fn parse_expression(&mut self) {
        if !self.enter_nesting() {
            return;
        }
        if self.at_identifier("if") {
            self.parse_if_expression();
        } else if self.at_identifier("try") {
            self.parse_try_expression();
        } else if self.at_identifier("for") {
            self.parse_for_expression();
        } else if self.at_identifier("loop") {
            self.advance();
            self.push_symbol_scope();
            self.parse_block();
            self.pop_symbol_scope();
        } else if self.at_identifier("while") {
            self.advance();
            self.push_symbol_scope();
            self.parse_condition_or_iterable("while");
            self.parse_block();
            self.pop_symbol_scope();
        } else {
            self.parse_assignment();
        }
        self.leave_nesting();
    }

    fn parse_condition_or_iterable(&mut self, context: &'static str) {
        if self.starts_control_expression() {
            self.report_current(format!(
                "a control expression used as an `{context}` condition or iterable must be parenthesized"
            ));
            return;
        }
        if self.starts_lambda_expression() {
            self.report_current(format!(
                "a lambda used as an `{context}` condition or iterable must be parenthesized"
            ));
            return;
        }
        self.parse_assignment();
    }

    fn starts_control_expression(&self) -> bool {
        ["if", "try", "for", "loop", "while"]
            .iter()
            .any(|keyword| self.at_identifier(keyword))
    }

    fn starts_lambda_expression(&self) -> bool {
        matches!(
            &self.current().kind,
            TokenKind::Operator(operator) if matches!(operator.as_str(), "|" | "||")
        )
    }

    fn parse_try_expression(&mut self) {
        self.advance();
        if self.at_identifier("catch") || self.at_expression_boundary() {
            self.report_current("expected an expression or block after `try`");
        } else {
            self.parse_try_branch("protected");
        }

        if !self.take_identifier_named("catch") {
            self.report_current("expected `catch` after the protected expression or block");
            return;
        }
        if self.at_expression_boundary() {
            self.report_current("expected an expression or block after `catch`");
        } else {
            self.parse_try_branch("fallback");
        }
    }

    fn parse_try_branch(&mut self, branch: &'static str) {
        if !self.at_kind(&TokenKind::OpenCurly) {
            self.parse_expression();
            return;
        }
        if !self.enter_nesting() {
            return;
        }
        self.advance();
        self.consume_statement_ends();
        let mut ends_with_value = false;
        while !self.at_end() && !self.at_kind(&TokenKind::CloseCurly) {
            let start = self.index;
            ends_with_value = !self.starts_non_value_try_tail();
            self.parse_statement();
            self.require_statement_end();
            if self.index == start {
                self.advance();
            }
        }
        if self.take_kind(&TokenKind::CloseCurly) {
            if !ends_with_value {
                self.report_previous(format!(
                    "try {branch} block must end with a value-producing expression; use `nil` for no value"
                ));
            }
        } else {
            self.report_current("expected `}` to close a try branch");
        }
        self.leave_nesting();
    }

    fn starts_non_value_try_tail(&self) -> bool {
        [
            "use", "let", "fn", "return", "break", "continue", "for", "loop", "while",
        ]
        .iter()
        .any(|keyword| self.at_identifier(keyword))
    }

    fn parse_if_expression(&mut self) {
        self.advance();
        if self.at_expression_boundary() {
            self.report_current("expected a condition after `if`");
        } else {
            self.parse_condition_or_iterable("if");
        }
        self.parse_conditional_branch();

        while self.at_identifier("elif") {
            self.advance();
            if self.at_expression_boundary() {
                self.report_current("expected a condition after `elif`");
            } else {
                self.parse_condition_or_iterable("elif");
            }
            self.parse_conditional_branch();
        }

        if self.at_identifier("else") {
            self.advance();
            self.parse_conditional_branch();
        }
    }

    fn parse_conditional_branch(&mut self) {
        if self.at_kind(&TokenKind::OpenCurly) {
            self.parse_block();
        } else if self.starts_lambda_expression() {
            self.report_current("a lambda used as a conditional branch must be written in a block");
        } else if self.at_expression_boundary() {
            self.report_current("expected an expression or block");
        } else {
            self.parse_expression();
        }
    }

    fn parse_for_expression(&mut self) {
        self.advance();
        let mut bindings = 0_usize;
        let mut binding_tokens = Vec::new();
        loop {
            if self.at_identifier("in") {
                break;
            }
            if let Some(binding) =
                self.take_plain_identifier("expected a binding identifier after `for`")
            {
                binding_tokens.push(binding);
            }
            bindings += 1;
            if bindings > 3 {
                self.report_previous("a `for` expression supports at most three bindings");
            }
            if self.take_kind(&TokenKind::Comma) {
                if self.at_identifier("in") {
                    self.report_current(
                        "trailing commas are not part of the canonical `for` binding grammar",
                    );
                    break;
                }
                continue;
            }
            break;
        }

        if bindings == 0 || !self.take_identifier_named("in") {
            self.report_current("expected `in` after `for` bindings");
            return;
        }
        if self.at_expression_boundary() {
            self.report_current("expected an iterable expression after `in`");
        } else {
            self.parse_condition_or_iterable("for");
        }
        self.push_symbol_scope();
        for binding in binding_tokens {
            self.define_symbol(binding, LexicalSymbolKind::LoopBinding);
        }
        self.parse_block();
        self.pop_symbol_scope();
    }

    fn parse_expression_or_block(&mut self) {
        if self.at_kind(&TokenKind::OpenCurly) {
            self.parse_block();
        } else if self.at_expression_boundary() {
            self.report_current("expected an expression or block");
        } else {
            self.parse_expression();
        }
    }

    fn parse_assignment(&mut self) {
        self.parse_logical_or();
        while self.take_any_operator(&["=", "+=", "-=", "*=", "/=", "%="]) {
            self.parse_logical_or();
        }
    }

    fn parse_logical_or(&mut self) {
        self.parse_logical_and();
        while self.take_operator("||") {
            self.parse_logical_and();
        }
    }

    fn parse_logical_and(&mut self) {
        self.parse_equality();
        while self.take_operator("&&") {
            self.parse_equality();
        }
    }

    fn parse_equality(&mut self) {
        self.parse_comparison();
        while self.take_any_operator(&["==", "!="]) {
            self.parse_comparison();
        }
    }

    fn parse_comparison(&mut self) {
        self.parse_additive();
        while self.take_any_operator(&["<", "<=", ">", ">="]) {
            self.parse_additive();
        }
    }

    fn parse_additive(&mut self) {
        self.parse_multiplicative();
        while self.take_any_operator(&["+", "-"]) {
            self.parse_multiplicative();
        }
    }

    fn parse_multiplicative(&mut self) {
        self.parse_unary();
        while self.take_any_operator(&["*", "/", "%"]) {
            self.parse_unary();
        }
    }

    fn parse_unary(&mut self) {
        self.take_any_operator(&["!", "-", "+", "~"]);
        self.parse_postfix();
    }

    fn parse_postfix(&mut self) {
        self.parse_primary();
        loop {
            if self.at_kind(&TokenKind::OpenRound) {
                self.parse_call();
            } else if self.take_operator(".") {
                self.expect_plain_identifier("expected an identifier after `.`");
            } else if self.at_kind(&TokenKind::OpenSquare) {
                self.advance();
                if self.at_kind(&TokenKind::CloseSquare) {
                    self.report_current("expected an index expression between `[` and `]`");
                } else {
                    self.parse_expression();
                }
                if !self.take_kind(&TokenKind::CloseSquare) {
                    self.report_current("expected `]` after an index expression");
                }
            } else {
                return;
            }
        }
    }

    fn parse_call(&mut self) {
        self.advance();
        if self.take_kind(&TokenKind::CloseRound) {
            return;
        }
        loop {
            self.parse_expression();
            if self.take_kind(&TokenKind::Comma) {
                if self.at_kind(&TokenKind::CloseRound) {
                    self.report_current(
                        "trailing commas are not part of the canonical call grammar",
                    );
                    self.advance();
                    return;
                }
                continue;
            }
            if !self.take_kind(&TokenKind::CloseRound) {
                self.report_current("expected `,` or `)` after a call argument");
            }
            return;
        }
    }

    fn parse_primary(&mut self) {
        match &self.current().kind {
            TokenKind::Number | TokenKind::StringLiteral => {
                self.advance();
            }
            TokenKind::Identifier(identifier)
                if matches!(identifier.as_str(), "true" | "false" | "nil") =>
            {
                self.advance();
            }
            TokenKind::Identifier(identifier) if !is_reserved_identifier(identifier) => {
                let reference = self.index;
                self.advance();
                self.reference_symbol(reference);
            }
            TokenKind::OpenSquare => self.parse_array(),
            TokenKind::OpenCurly => self.parse_record(),
            TokenKind::OpenRound => {
                self.advance();
                self.parse_expression();
                if !self.take_kind(&TokenKind::CloseRound) {
                    self.report_current("expected `)` after a parenthesized expression");
                }
            }
            TokenKind::Operator(operator) if matches!(operator.as_str(), "|" | "||") => {
                self.parse_lambda();
            }
            TokenKind::Identifier(_) => {
                self.report_current("reserved words cannot be used as expressions here");
                self.advance();
            }
            _ => {
                self.report_current("expected an expression");
                if !self.at_end() {
                    self.advance();
                }
            }
        }
    }

    fn parse_array(&mut self) {
        self.advance();
        if self.take_kind(&TokenKind::CloseSquare) {
            return;
        }
        loop {
            self.parse_expression();
            if self.take_kind(&TokenKind::Comma) {
                if self.at_kind(&TokenKind::CloseSquare) {
                    self.report_current(
                        "trailing commas are not part of the canonical array grammar",
                    );
                    self.advance();
                    return;
                }
                continue;
            }
            if !self.take_kind(&TokenKind::CloseSquare) {
                self.report_current("expected `,` or `]` after an array element");
            }
            return;
        }
    }

    fn parse_record(&mut self) {
        self.advance();
        self.consume_newlines();
        if self.take_kind(&TokenKind::CloseCurly) {
            return;
        }

        loop {
            self.expect_plain_identifier("expected a record member identifier");
            if !self.take_operator(":") {
                self.report_current("expected `:` after a record member identifier");
                return;
            }
            self.parse_expression();

            if self.take_kind(&TokenKind::Comma) {
                self.consume_newlines();
                if self.at_kind(&TokenKind::CloseCurly) {
                    self.report_current(
                        "trailing commas are not part of the canonical record grammar",
                    );
                    self.advance();
                    return;
                }
                continue;
            }
            if self.at_kind(&TokenKind::Newline) {
                self.consume_newlines();
                if self.take_kind(&TokenKind::CloseCurly) {
                    return;
                }
                continue;
            }
            if self.take_kind(&TokenKind::CloseCurly) {
                return;
            }
            self.report_current("expected `,`, a newline, or `}` after a record member");
            return;
        }
    }

    fn parse_lambda(&mut self) {
        self.push_symbol_scope();
        if self.take_operator("||") {
            self.parse_expression_or_block();
            self.pop_symbol_scope();
            return;
        }

        self.take_operator("|");
        if let Some(parameter) =
            self.take_plain_identifier("expected a lambda parameter identifier")
        {
            self.define_symbol(parameter, LexicalSymbolKind::LambdaParameter);
        }
        while self.take_kind(&TokenKind::Comma) {
            if let Some(parameter) =
                self.take_plain_identifier("expected a lambda parameter identifier after `,`")
            {
                self.define_symbol(parameter, LexicalSymbolKind::LambdaParameter);
            }
        }
        if !self.take_operator("|") {
            self.report_current("expected `|` after lambda parameters");
            self.pop_symbol_scope();
            return;
        }
        self.parse_expression_or_block();
        self.pop_symbol_scope();
    }

    fn require_statement_end(&mut self) {
        if self.at_kind(&TokenKind::Newline) || self.at_kind(&TokenKind::Semicolon) {
            self.record_vm_statement_boundary();
            self.consume_statement_ends();
        } else if !self.at_end() {
            self.report_current("expected a newline or `;` after a statement");
            self.synchronize_statement();
        }
    }

    fn synchronize_statement(&mut self) {
        while !self.at_end()
            && !self.at_kind(&TokenKind::Newline)
            && !self.at_kind(&TokenKind::Semicolon)
            && !self.at_kind(&TokenKind::CloseCurly)
        {
            self.advance();
        }
        self.consume_statement_ends();
    }

    fn consume_statement_ends(&mut self) {
        while self.at_kind(&TokenKind::Newline) || self.at_kind(&TokenKind::Semicolon) {
            self.advance();
        }
    }

    fn record_vm_statement_boundary(&mut self) {
        if self.vm_statement_separator_offsets.is_none() {
            return;
        }

        let mut boundary_end = self.index;
        let mut contains_semicolon = false;
        while let Some(token) = self.tokens.get(boundary_end) {
            match &token.kind {
                TokenKind::Newline => boundary_end += 1,
                TokenKind::Semicolon => {
                    contains_semicolon = true;
                    boundary_end += 1;
                }
                _ => break,
            }
        }

        if contains_semicolon
            || self
                .tokens
                .get(boundary_end)
                .is_none_or(|token| matches!(&token.kind, TokenKind::End))
        {
            return;
        }

        // Insert beside the next real token rather than at the first newline:
        // a newline emitted while skipping a block comment sits inside that
        // comment, where a semicolon would not reach the inherited tokenizer.
        let offset = self.tokens[boundary_end].start_byte;
        let offsets = self
            .vm_statement_separator_offsets
            .as_mut()
            .expect("VM statement-separator collection was enabled");
        if offsets.last().copied() != Some(offset) {
            offsets.push(offset);
        }
    }

    fn consume_newlines(&mut self) {
        while self.at_kind(&TokenKind::Newline) {
            self.advance();
        }
    }

    fn at_statement_boundary(&self) -> bool {
        self.at_kind(&TokenKind::Newline)
            || self.at_kind(&TokenKind::Semicolon)
            || self.at_kind(&TokenKind::CloseCurly)
            || self.at_end()
    }

    fn at_import_statement_end(&self) -> bool {
        self.at_kind(&TokenKind::Newline) || self.at_kind(&TokenKind::Semicolon) || self.at_end()
    }

    fn at_expression_boundary(&self) -> bool {
        self.at_statement_boundary()
            || self.at_kind(&TokenKind::Comma)
            || self.at_kind(&TokenKind::CloseRound)
            || self.at_kind(&TokenKind::CloseSquare)
    }

    fn at_identifier(&self, expected: &str) -> bool {
        matches!(&self.current().kind, TokenKind::Identifier(identifier) if identifier == expected)
    }

    fn take_identifier_named(&mut self, expected: &str) -> bool {
        if self.at_identifier(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect_plain_identifier(&mut self, message: &'static str) {
        self.take_plain_identifier(message);
    }

    fn take_plain_identifier(&mut self, message: &'static str) -> Option<usize> {
        match &self.current().kind {
            TokenKind::Identifier(identifier) if !is_reserved_identifier(identifier) => {
                let index = self.index;
                self.advance();
                Some(index)
            }
            _ => {
                self.report_current(message);
                None
            }
        }
    }

    fn push_symbol_scope(&mut self) {
        if let Some(symbols) = &mut self.symbols {
            symbols.push_scope();
        }
    }

    fn pop_symbol_scope(&mut self) {
        let visibility_end_byte = self.current().start_byte;
        if let Some(symbols) = &mut self.symbols {
            symbols.pop_scope(visibility_end_byte);
        }
    }

    fn define_symbol(&mut self, token_index: usize, kind: LexicalSymbolKind) {
        let Some((name, span)) = self.symbol_token(token_index) else {
            return;
        };
        let visibility_start_byte = self.current().start_byte;
        if let Some(symbols) = &mut self.symbols {
            symbols.define(name, span, kind, visibility_start_byte);
        }
    }

    fn record_import(&mut self, path: Vec<String>, path_span: SourceSpan, binding: SourceSpan) {
        if let Some(imports) = &mut self.imports {
            imports.record(path, path_span, binding);
        }
    }

    fn record_static_record_shape(&mut self, binding: usize, shape: DirectRecordShape) {
        let Some((_, binding_span)) = self.symbol_token(binding) else {
            return;
        };
        if let Some(shapes) = &mut self.static_record_shapes {
            shapes.record(binding_span, shape);
        }
    }

    fn reference_symbol(&mut self, token_index: usize) {
        let Some((name, span)) = self.symbol_token(token_index) else {
            return;
        };
        if let Some(symbols) = &mut self.symbols {
            symbols.reference(&name, span);
        }
    }

    fn symbol_token(&self, token_index: usize) -> Option<(String, SourceSpan)> {
        let token = self.tokens.get(token_index)?;
        let TokenKind::Identifier(name) = &token.kind else {
            return None;
        };
        Some((
            name.clone(),
            SourceSpan {
                start_byte: token.start_byte,
                end_byte: token.end_byte,
            },
        ))
    }

    fn at_kind(&self, expected: &TokenKind) -> bool {
        &self.current().kind == expected
    }

    fn take_kind(&mut self, expected: &TokenKind) -> bool {
        if self.at_kind(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn take_operator(&mut self, expected: &str) -> bool {
        if matches!(&self.current().kind, TokenKind::Operator(operator) if operator == expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn take_any_operator(&mut self, expected: &[&str]) -> bool {
        if matches!(&self.current().kind, TokenKind::Operator(operator) if expected.contains(&operator.as_str()))
        {
            self.advance();
            true
        } else {
            false
        }
    }

    fn current(&self) -> &Token {
        &self.tokens[self.index]
    }

    fn advance(&mut self) {
        if !self.at_end() {
            self.index += 1;
        }
    }

    fn at_end(&self) -> bool {
        self.at_kind(&TokenKind::End)
    }

    fn enter_nesting(&mut self) -> bool {
        if self.nesting >= self.maximum_nesting {
            self.report_current(format!(
                "canonical Splash nesting exceeds the maximum of {}",
                self.maximum_nesting
            ));
            false
        } else {
            self.nesting += 1;
            true
        }
    }

    fn leave_nesting(&mut self) {
        self.nesting = self.nesting.saturating_sub(1);
    }

    fn report_current(&mut self, message: impl Into<String>) {
        let token = self.current();
        self.report(token.line, token.column, message);
    }

    fn report_previous(&mut self, message: impl Into<String>) {
        let token = self
            .tokens
            .get(self.index.saturating_sub(1))
            .unwrap_or(self.current());
        self.report(token.line, token.column, message);
    }

    fn report(&mut self, line: usize, column: usize, message: impl Into<String>) {
        if self.diagnostics.len() < MAX_SYNTAX_DIAGNOSTICS {
            self.diagnostics.push(SyntaxDiagnostic {
                line,
                column,
                message: message.into(),
            });
        } else {
            self.diagnostics_truncated = true;
        }
    }
}

fn is_reserved_identifier(identifier: &str) -> bool {
    matches!(
        identifier,
        "if" | "elif"
            | "else"
            | "for"
            | "in"
            | "loop"
            | "while"
            | "fn"
            | "let"
            | "return"
            | "break"
            | "continue"
            | "use"
            | "true"
            | "false"
            | "nil"
            | "var"
            | "match"
            | "try"
            | "ok"
            | "do"
            // The inherited parser recognizes these as contextual operators,
            // bindings, or ambient values. Canonical source has no spelling
            // for those compatibility semantics, so accepting them as normal
            // identifiers would make profile admission diverge from the VM.
            | "and"
            | "or"
            | "is"
            | "mut"
            | "me"
            | "scope"
    )
}
