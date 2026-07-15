//! Canonical Splash v0.1 source-profile validation.
//!
//! The vendored Makepad parser intentionally accepts a larger compatibility
//! language. This module accepts only the portable grammar documented by
//! Splash, without producing bytecode or evaluating source.

use super::{
    SyntaxDiagnostic, ToolCallHint, ToolCallHintReport, ToolCallKind, TopLevelDeclaration,
    TopLevelDeclarationKind, MAX_SYNTAX_DIAGNOSTICS, MAX_TOOL_CALL_HINTS,
};

const MAX_CANONICAL_PROFILE_NESTING: usize = 128;

pub(super) struct ProfileReport {
    pub(super) diagnostics: Vec<SyntaxDiagnostic>,
    pub(super) diagnostics_truncated: bool,
}

pub(super) enum ProfileFormatError {
    Profile(ProfileReport),
    OutputTooLarge { actual: usize, maximum: usize },
}

pub(super) fn check_canonical_profile(source: &str, max_tokens: usize) -> ProfileReport {
    let lexer = ProfileLexer::new(source, max_tokens);
    let (tokens, diagnostics, diagnostics_truncated) = lexer.tokenize();
    if !diagnostics.is_empty() || diagnostics_truncated {
        return ProfileReport {
            diagnostics,
            diagnostics_truncated,
        };
    }

    CanonicalParser::new(tokens).parse()
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

    let profile = CanonicalParser::new(tokens.clone()).parse();
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
        let start_index = self.index;
        self.advance();
        if self.current() == Some('\n') {
            self.advance();
        } else {
            self.line += 1;
            self.column = 1;
        }
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

        if self.current() == Some('.')
            && self
                .peek()
                .is_some_and(|character| character.is_ascii_digit())
        {
            self.advance();
            self.consume_ascii_digits();
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
        while self.current().is_some() {
            if self.current() == Some('*') && self.peek() == Some('/') {
                self.advance();
                self.advance();
                return;
            }
            match self.current() {
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

struct CanonicalParser {
    tokens: Vec<Token>,
    index: usize,
    nesting: usize,
    diagnostics: Vec<SyntaxDiagnostic>,
    diagnostics_truncated: bool,
}

impl CanonicalParser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            index: 0,
            nesting: 0,
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
        }
    }

    fn parse(mut self) -> ProfileReport {
        self.parse_program();
        ProfileReport {
            diagnostics: self.diagnostics,
            diagnostics_truncated: self.diagnostics_truncated,
        }
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
        if !self.take_identifier_named("mod") {
            self.report_current("expected `mod` after `use`");
            return;
        }
        if !self.take_operator(".") {
            self.report_current("expected `.` after `use mod`");
            return;
        }
        self.expect_plain_identifier("expected a module identifier after `use mod.`");
        while self.take_operator(".") {
            self.expect_plain_identifier("expected a module identifier after `.`");
        }
    }

    fn parse_declaration(&mut self) {
        self.expect_plain_identifier("expected an identifier after `let`");
        if self.take_operator("=") {
            self.parse_expression();
        } else if !self.at_statement_boundary() {
            self.report_current("expected `=` or a statement end after a `let` declaration");
        }
    }

    fn parse_function_declaration(&mut self) {
        self.expect_plain_identifier("expected a function identifier after `fn`");
        self.parse_parameter_list();
        self.parse_block();
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
            self.expect_plain_identifier("expected a parameter identifier");
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
        } else if self.at_identifier("for") {
            self.parse_for_expression();
        } else if self.at_identifier("loop") {
            self.advance();
            self.parse_block();
        } else if self.at_identifier("while") {
            self.advance();
            self.parse_expression();
            self.parse_block();
        } else {
            self.parse_assignment();
        }
        self.leave_nesting();
    }

    fn parse_if_expression(&mut self) {
        self.advance();
        if self.at_expression_boundary() {
            self.report_current("expected a condition after `if`");
        } else {
            self.parse_expression();
        }
        self.parse_expression_or_block();

        while self.at_identifier("elif") {
            self.advance();
            if self.at_expression_boundary() {
                self.report_current("expected a condition after `elif`");
            } else {
                self.parse_expression();
            }
            self.parse_expression_or_block();
        }

        if self.at_identifier("else") {
            self.advance();
            self.parse_expression_or_block();
        }
    }

    fn parse_for_expression(&mut self) {
        self.advance();
        let mut bindings = 0_usize;
        loop {
            if self.at_identifier("in") {
                break;
            }
            self.expect_plain_identifier("expected a binding identifier after `for`");
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
            self.parse_expression();
        }
        self.parse_block();
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
                self.advance();
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
        if self.take_operator("||") {
            self.parse_expression_or_block();
            return;
        }

        self.take_operator("|");
        self.expect_plain_identifier("expected a lambda parameter identifier");
        while self.take_kind(&TokenKind::Comma) {
            self.expect_plain_identifier("expected a lambda parameter identifier after `,`");
        }
        if !self.take_operator("|") {
            self.report_current("expected `|` after lambda parameters");
            return;
        }
        self.parse_expression_or_block();
    }

    fn require_statement_end(&mut self) {
        if self.at_kind(&TokenKind::Newline) || self.at_kind(&TokenKind::Semicolon) {
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
        match &self.current().kind {
            TokenKind::Identifier(identifier) if !is_reserved_identifier(identifier) => {
                self.advance();
            }
            _ => self.report_current(message),
        }
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
        if self.nesting >= MAX_CANONICAL_PROFILE_NESTING {
            self.report_current(format!(
                "canonical Splash nesting exceeds the maximum of {MAX_CANONICAL_PROFILE_NESTING}"
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
    )
}
