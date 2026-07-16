#![forbid(unsafe_code)]

//! Stdio language server for the canonical Splash v0.2 source profile.
//!
//! The server only receives client-provided text and calls effect-free syntax,
//! formatting, outline, and lexical symbol helpers. It never reads document
//! URIs, evaluates Splash code, creates a capability host, or loads an adapter.

use std::{cell::OnceCell, collections::HashMap, error::Error, io, process::ExitCode};

use lsp_server::{Connection, ErrorCode, Message, Notification, Request, Response};
use lsp_types::{
    notification::{
        DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument, Exit,
        Notification as LspNotification, PublishDiagnostics,
    },
    request::{
        Completion, DocumentHighlightRequest, DocumentSymbolRequest, Formatting, GotoDefinition,
        HoverRequest, PrepareRenameRequest, References, Rename, Request as LspRequest,
    },
    CompletionItem, CompletionItemKind, CompletionList, CompletionOptions, CompletionParams,
    CompletionResponse, CompletionTextEdit, Diagnostic, DiagnosticSeverity,
    DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
    DocumentChanges, DocumentFormattingParams, DocumentHighlight, DocumentHighlightKind,
    DocumentHighlightParams, DocumentSymbol, DocumentSymbolParams, DocumentSymbolResponse,
    GotoDefinitionParams, GotoDefinitionResponse, Hover, HoverContents, HoverParams,
    InitializeParams, Location, MarkupContent, MarkupKind, OneOf,
    OptionalVersionedTextDocumentIdentifier, Position, PositionEncodingKind, PrepareRenameResponse,
    PublishDiagnosticsParams, Range, ReferenceParams, RenameOptions, RenameParams,
    ServerCapabilities, SymbolKind, TextDocumentEdit, TextDocumentItem, TextDocumentPositionParams,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Uri, WorkspaceEdit,
};
use splash_core::{
    check_syntax_named, format_source_named, is_canonical_identifier,
    lexical_completion_report_named, lexical_symbol_report_named, top_level_declarations_named,
    ExecutionLimits, LexicalCompletionReport, LexicalSymbol, LexicalSymbolKind,
    LexicalSymbolReport, SourceSpan, SyntaxDiagnostic, TopLevelDeclaration,
    TopLevelDeclarationKind, DEFAULT_MAX_SOURCE_BYTES, MAX_LEXICAL_SYMBOL_OCCURRENCES,
    MAX_SYNTAX_DIAGNOSTICS,
};

const MAX_OPEN_DOCUMENTS: usize = 128;
const DIAGNOSTIC_SOURCE: &str = "splash";

type ServerResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug)]
struct DocumentState {
    source: Option<String>,
    version: i32,
    lexical_report: OnceCell<Result<LexicalSymbolReport, String>>,
    completion_report: OnceCell<Result<LexicalCompletionReport, String>>,
}

#[derive(Debug, Eq, PartialEq)]
struct VersionedRenameEdits {
    uri: Uri,
    version: i32,
    edits: Vec<TextEdit>,
}

impl VersionedRenameEdits {
    fn into_workspace_edit(self) -> WorkspaceEdit {
        WorkspaceEdit {
            changes: None,
            document_changes: Some(DocumentChanges::Edits(vec![TextDocumentEdit {
                text_document: OptionalVersionedTextDocumentIdentifier::new(self.uri, self.version),
                edits: self.edits.into_iter().map(OneOf::Left).collect(),
            }])),
            change_annotations: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SpanReplacement {
    original: SourceSpan,
    replacement: SourceSpan,
}

#[derive(Default)]
struct SplashLanguageServer {
    documents: HashMap<Uri, DocumentState>,
}

impl SplashLanguageServer {
    fn open_document(&mut self, item: TextDocumentItem) -> PublishDiagnosticsParams {
        self.replace_document(item.uri, item.version, item.text)
    }

    fn change_document(
        &mut self,
        params: DidChangeTextDocumentParams,
    ) -> Option<PublishDiagnosticsParams> {
        let uri = params.text_document.uri;
        let version = params.text_document.version;
        let current = self.documents.get(&uri)?;

        if version <= current.version || params.content_changes.len() != 1 {
            return None;
        }

        let change = params.content_changes.into_iter().next()?;
        if change.range.is_some() || change.range_length.is_some() {
            return None;
        }

        Some(self.replace_document(uri, version, change.text))
    }

    fn close_document(&mut self, params: DidCloseTextDocumentParams) -> PublishDiagnosticsParams {
        let uri = params.text_document.uri;
        self.documents.remove(&uri);
        PublishDiagnosticsParams::new(uri, Vec::new(), None)
    }

    fn format_document(&self, uri: &Uri) -> Result<Vec<TextEdit>, String> {
        let state = self
            .documents
            .get(uri)
            .ok_or_else(|| "the document is not open in this Splash session".to_owned())?;
        let source = state.source.as_deref().ok_or_else(|| {
            format!("the document exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit")
        })?;
        let formatted = format_source_named(uri.as_str(), source, ExecutionLimits::default())
            .map_err(|error| format!("cannot format canonical Splash source: {error}"))?;

        if formatted == source {
            return Ok(Vec::new());
        }

        Ok(vec![TextEdit::new(
            Range::new(Position::new(0, 0), document_end_position(source)),
            formatted,
        )])
    }

    fn document_symbols(&self, uri: &Uri) -> Result<Vec<DocumentSymbol>, String> {
        let state = self
            .documents
            .get(uri)
            .ok_or_else(|| "the document is not open in this Splash session".to_owned())?;
        let source = state.source.as_deref().ok_or_else(|| {
            format!("the document exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit")
        })?;
        let declarations =
            top_level_declarations_named(uri.as_str(), source, ExecutionLimits::default())
                .map_err(|error| format!("cannot outline canonical Splash source: {error}"))?;

        Ok(declarations
            .iter()
            .map(|declaration| outline_symbol(source, declaration))
            .collect())
    }

    fn definition(&self, uri: &Uri, position: Position) -> Result<Option<Location>, String> {
        let (source, _, report) = self.lexical_symbols(uri)?;
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(None);
        };
        let Some(symbol) = symbol_at_byte(report, byte_offset) else {
            return Ok(None);
        };

        Ok(Some(symbol_location(uri, source, symbol.definition)))
    }

    fn hover(&self, uri: &Uri, position: Position) -> Result<Option<Hover>, String> {
        let (source, _, report) = self.lexical_symbols(uri)?;
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(None);
        };
        let Some((symbol, occurrence)) = symbol_occurrence_at_byte(report, byte_offset) else {
            return Ok(None);
        };

        Ok(Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: format!(
                    "**{}** `{}`",
                    lexical_symbol_kind_label(symbol.kind),
                    symbol.name
                ),
            }),
            range: Some(span_range(source, occurrence)),
        }))
    }

    fn references(
        &self,
        uri: &Uri,
        position: Position,
        include_declaration: bool,
    ) -> Result<Vec<Location>, String> {
        let (source, _, report) = self.lexical_symbols(uri)?;
        if report.truncated {
            return Err(format!(
                "the lexical index exceeds Splash's {MAX_LEXICAL_SYMBOL_OCCURRENCES}-occurrence limit"
            ));
        }
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(Vec::new());
        };
        let Some(symbol) = symbol_at_byte(report, byte_offset) else {
            return Ok(Vec::new());
        };

        let mut locations =
            Vec::with_capacity(symbol.references.len() + usize::from(include_declaration));
        if include_declaration {
            locations.push(symbol_location(uri, source, symbol.definition));
        }
        locations.extend(
            symbol
                .references
                .iter()
                .copied()
                .map(|span| symbol_location(uri, source, span)),
        );
        Ok(locations)
    }

    fn document_highlights(
        &self,
        uri: &Uri,
        position: Position,
    ) -> Result<Vec<DocumentHighlight>, String> {
        let (source, _, report) = self.lexical_symbols(uri)?;
        if report.truncated {
            return Err(format!(
                "the lexical index exceeds Splash's {MAX_LEXICAL_SYMBOL_OCCURRENCES}-occurrence limit"
            ));
        }
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(Vec::new());
        };
        let Some(symbol) = symbol_at_byte(report, byte_offset) else {
            return Ok(Vec::new());
        };

        Ok(std::iter::once(symbol.definition)
            .chain(symbol.references.iter().copied())
            .map(|span| DocumentHighlight {
                range: span_range(source, span),
                kind: Some(DocumentHighlightKind::TEXT),
            })
            .collect())
    }

    fn completion(&self, uri: &Uri, position: Position) -> Result<CompletionList, String> {
        let (source, report) = self.lexical_completions(uri)?;
        let is_incomplete = report.symbols_truncated || report.sites_truncated;
        let empty = || CompletionList {
            is_incomplete,
            items: Vec::new(),
        };
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(empty());
        };
        let Some(site) = report.sites.iter().copied().find(|site| {
            site.start_byte <= byte_offset
                && byte_offset <= site.end_byte
                && site.end_byte <= report.valid_prefix_end_byte
        }) else {
            return Ok(empty());
        };
        if report.symbols_truncated {
            return Ok(empty());
        }

        let mut visible_by_name = HashMap::<&str, &LexicalSymbol>::new();
        for symbol in &report.symbols {
            if symbol.visibility_start_byte <= site.start_byte
                && site.start_byte < symbol.visibility_end_byte
            {
                let replace = visible_by_name
                    .get(symbol.name.as_str())
                    .is_none_or(|current| {
                        (symbol.visibility_start_byte, symbol.definition.start_byte)
                            > (current.visibility_start_byte, current.definition.start_byte)
                    });
                if replace {
                    visible_by_name.insert(symbol.name.as_str(), symbol);
                }
            }
        }

        let edit_range = span_range(source, site);
        let mut items = visible_by_name
            .into_values()
            .map(|symbol| CompletionItem {
                label: symbol.name.clone(),
                kind: Some(completion_item_kind(symbol.kind)),
                detail: Some(lexical_symbol_kind_label(symbol.kind).to_owned()),
                text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                    edit_range,
                    symbol.name.clone(),
                ))),
                ..CompletionItem::default()
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.label.cmp(&right.label));

        Ok(CompletionList {
            is_incomplete,
            items,
        })
    }

    fn prepare_rename(
        &self,
        uri: &Uri,
        position: Position,
    ) -> Result<Option<PrepareRenameResponse>, String> {
        let (source, _, report) = self.lexical_symbols(uri)?;
        require_complete_lexical_report(report)?;
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(None);
        };
        let Some((symbol_index, occurrence)) =
            rename_symbol_occurrence_at_byte(report, byte_offset)
        else {
            return Ok(None);
        };
        let symbol = &report.symbols[symbol_index];
        if symbol.kind == LexicalSymbolKind::Import {
            return Ok(None);
        }

        Ok(Some(PrepareRenameResponse::RangeWithPlaceholder {
            range: span_range(source, occurrence),
            placeholder: symbol.name.clone(),
        }))
    }

    fn rename(
        &self,
        uri: &Uri,
        position: Position,
        new_name: &str,
    ) -> Result<Option<VersionedRenameEdits>, String> {
        let (source, version, report) = self.lexical_symbols(uri)?;
        require_complete_lexical_report(report)?;
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(None);
        };
        let Some((symbol_index, _)) = rename_symbol_occurrence_at_byte(report, byte_offset) else {
            return Ok(None);
        };
        let symbol = &report.symbols[symbol_index];
        if symbol.kind == LexicalSymbolKind::Import {
            return Err(
                "Splash cannot rename an import binding without changing its module path"
                    .to_owned(),
            );
        }
        if new_name == symbol.name {
            return Ok(None);
        }
        if new_name.len() > DEFAULT_MAX_SOURCE_BYTES {
            return Err(format!(
                "the rename identifier exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit"
            ));
        }
        if !is_canonical_identifier(new_name) {
            return Err(
                "the requested name is not a non-reserved canonical Splash identifier".to_owned(),
            );
        }

        let (renamed_source, replacements) = rewrite_symbol_occurrences(source, symbol, new_name)?;
        let syntax = check_syntax_named(uri.as_str(), &renamed_source, ExecutionLimits::default())
            .map_err(|error| format!("cannot validate renamed Splash source: {error}"))?;
        if !syntax.valid {
            return Err("the requested rename does not produce canonical Splash source".to_owned());
        }

        let renamed_report =
            lexical_symbol_report_named(uri.as_str(), &renamed_source, ExecutionLimits::default())
                .map_err(|error| format!("cannot index renamed Splash source: {error}"))?;
        let expected_report = remap_lexical_report(report, symbol_index, new_name, &replacements)?;
        if renamed_report != expected_report {
            return Err(
                "the requested rename would change indexed lexical binding resolution".to_owned(),
            );
        }

        Ok(Some(VersionedRenameEdits {
            uri: uri.clone(),
            version,
            edits: replacements
                .iter()
                .map(|replacement| {
                    TextEdit::new(
                        span_range(source, replacement.original),
                        new_name.to_owned(),
                    )
                })
                .collect(),
        }))
    }

    fn lexical_symbols(&self, uri: &Uri) -> Result<(&str, i32, &LexicalSymbolReport), String> {
        let state = self
            .documents
            .get(uri)
            .ok_or_else(|| "the document is not open in this Splash session".to_owned())?;
        let source = state.source.as_deref().ok_or_else(|| {
            format!("the document exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit")
        })?;
        let report = state.lexical_report.get_or_init(|| {
            lexical_symbol_report_named(uri.as_str(), source, ExecutionLimits::default())
                .map_err(|error| format!("cannot index canonical Splash source: {error}"))
        });
        match report {
            Ok(report) => Ok((source, state.version, report)),
            Err(message) => Err(message.clone()),
        }
    }

    fn lexical_completions(&self, uri: &Uri) -> Result<(&str, &LexicalCompletionReport), String> {
        let state = self
            .documents
            .get(uri)
            .ok_or_else(|| "the document is not open in this Splash session".to_owned())?;
        let source = state.source.as_deref().ok_or_else(|| {
            format!("the document exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit")
        })?;
        let report = state.completion_report.get_or_init(|| {
            lexical_completion_report_named(uri.as_str(), source, ExecutionLimits::default())
                .map_err(|error| format!("cannot complete canonical Splash source: {error}"))
        });
        match report {
            Ok(report) => Ok((source, report)),
            Err(message) => Err(message.clone()),
        }
    }

    fn replace_document(
        &mut self,
        uri: Uri,
        version: i32,
        source: String,
    ) -> PublishDiagnosticsParams {
        if !self.documents.contains_key(&uri) && self.documents.len() >= MAX_OPEN_DOCUMENTS {
            return resource_diagnostics(
                uri,
                version,
                format!(
                    "Splash LSP tracks at most {MAX_OPEN_DOCUMENTS} open documents per session"
                ),
            );
        }

        if source.len() > DEFAULT_MAX_SOURCE_BYTES {
            self.documents.insert(
                uri.clone(),
                DocumentState {
                    source: None,
                    version,
                    lexical_report: OnceCell::new(),
                    completion_report: OnceCell::new(),
                },
            );
            return resource_diagnostics(
                uri,
                version,
                format!(
                    "source is {} bytes; Splash accepts at most {DEFAULT_MAX_SOURCE_BYTES} bytes",
                    source.len()
                ),
            );
        }

        let diagnostics = syntax_diagnostics(&uri, &source);
        self.documents.insert(
            uri.clone(),
            DocumentState {
                source: Some(source),
                version,
                lexical_report: OnceCell::new(),
                completion_report: OnceCell::new(),
            },
        );
        PublishDiagnosticsParams::new(uri, diagnostics, Some(version))
    }
}

fn main() -> ExitCode {
    match run_stdio() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("splash-lsp: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_stdio() -> ServerResult<()> {
    let (connection, io_threads) = Connection::stdio();
    let result = run_connection(&connection);
    drop(connection);
    io_threads.join()?;
    result
}

fn run_connection(connection: &Connection) -> ServerResult<()> {
    let (initialize_id, initialize_value) = connection.initialize_start()?;
    let initialize_params =
        serde_json::from_value::<InitializeParams>(initialize_value).unwrap_or_default();
    let versioned_document_edits = supports_versioned_document_edits(&initialize_params);
    connection.initialize_finish(
        initialize_id,
        serde_json::json!({
            "capabilities": server_capabilities(versioned_document_edits),
        }),
    )?;

    let mut server = SplashLanguageServer::default();
    while let Ok(message) = connection.receiver.recv() {
        match message {
            Message::Request(request) => {
                if connection.handle_shutdown(&request)? {
                    return Ok(());
                }
                handle_request(connection, &server, versioned_document_edits, request)?;
            }
            Message::Notification(notification) => {
                if notification.method == Exit::METHOD {
                    return Err(io::Error::other(
                        "received an LSP exit notification before shutdown",
                    )
                    .into());
                }
                handle_notification(connection, &mut server, notification)?;
            }
            Message::Response(_) => {}
        }
    }

    Ok(())
}

fn supports_versioned_document_edits(params: &InitializeParams) -> bool {
    params
        .capabilities
        .workspace
        .as_ref()
        .and_then(|workspace| workspace.workspace_edit.as_ref())
        .and_then(|workspace_edit| workspace_edit.document_changes)
        == Some(true)
}

fn server_capabilities(versioned_document_edits: bool) -> ServerCapabilities {
    ServerCapabilities {
        position_encoding: Some(PositionEncodingKind::UTF16),
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        document_formatting_provider: Some(OneOf::Left(true)),
        document_symbol_provider: Some(OneOf::Left(true)),
        definition_provider: Some(OneOf::Left(true)),
        references_provider: Some(OneOf::Left(true)),
        hover_provider: Some(true.into()),
        document_highlight_provider: Some(OneOf::Left(true)),
        completion_provider: Some(CompletionOptions {
            resolve_provider: Some(false),
            ..CompletionOptions::default()
        }),
        rename_provider: versioned_document_edits.then(|| {
            OneOf::Right(RenameOptions {
                prepare_provider: Some(true),
                work_done_progress_options: Default::default(),
            })
        }),
        ..ServerCapabilities::default()
    }
}

fn handle_request(
    connection: &Connection,
    server: &SplashLanguageServer,
    versioned_document_edits: bool,
    request: Request,
) -> ServerResult<()> {
    let response = if request.method == Formatting::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<DocumentFormattingParams>(request.params) {
            Ok(params) => match server.format_document(&params.text_document.uri) {
                Ok(edits) => Response::new_ok(id, edits),
                Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
            },
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/formatting parameters: {error}"),
            ),
        }
    } else if request.method == DocumentSymbolRequest::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<DocumentSymbolParams>(request.params) {
            Ok(params) => match server.document_symbols(&params.text_document.uri) {
                Ok(symbols) => Response::new_ok(id, DocumentSymbolResponse::Nested(symbols)),
                Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
            },
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/documentSymbol parameters: {error}"),
            ),
        }
    } else if request.method == GotoDefinition::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<GotoDefinitionParams>(request.params) {
            Ok(params) => {
                let text_document_position = params.text_document_position_params;
                match server.definition(
                    &text_document_position.text_document.uri,
                    text_document_position.position,
                ) {
                    Ok(location) => {
                        Response::new_ok(id, location.map(GotoDefinitionResponse::Scalar))
                    }
                    Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
                }
            }
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/definition parameters: {error}"),
            ),
        }
    } else if request.method == HoverRequest::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<HoverParams>(request.params) {
            Ok(params) => {
                let text_document_position = params.text_document_position_params;
                match server.hover(
                    &text_document_position.text_document.uri,
                    text_document_position.position,
                ) {
                    Ok(hover) => Response::new_ok(id, hover),
                    Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
                }
            }
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/hover parameters: {error}"),
            ),
        }
    } else if request.method == References::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<ReferenceParams>(request.params) {
            Ok(params) => match server.references(
                &params.text_document_position.text_document.uri,
                params.text_document_position.position,
                params.context.include_declaration,
            ) {
                Ok(locations) => Response::new_ok(id, Some(locations)),
                Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
            },
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/references parameters: {error}"),
            ),
        }
    } else if request.method == DocumentHighlightRequest::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<DocumentHighlightParams>(request.params) {
            Ok(params) => {
                let text_document_position = params.text_document_position_params;
                match server.document_highlights(
                    &text_document_position.text_document.uri,
                    text_document_position.position,
                ) {
                    Ok(highlights) => Response::new_ok(id, Some(highlights)),
                    Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
                }
            }
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/documentHighlight parameters: {error}"),
            ),
        }
    } else if request.method == Completion::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<CompletionParams>(request.params) {
            Ok(params) => {
                let text_document_position = params.text_document_position;
                match server.completion(
                    &text_document_position.text_document.uri,
                    text_document_position.position,
                ) {
                    Ok(completion) => Response::new_ok(id, CompletionResponse::List(completion)),
                    Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
                }
            }
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/completion parameters: {error}"),
            ),
        }
    } else if versioned_document_edits && request.method == PrepareRenameRequest::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<TextDocumentPositionParams>(request.params) {
            Ok(params) => match server.prepare_rename(&params.text_document.uri, params.position) {
                Ok(prepared) => Response::new_ok(id, prepared),
                Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
            },
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/prepareRename parameters: {error}"),
            ),
        }
    } else if versioned_document_edits && request.method == Rename::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<RenameParams>(request.params) {
            Ok(params) => match server.rename(
                &params.text_document_position.text_document.uri,
                params.text_document_position.position,
                &params.new_name,
            ) {
                Ok(rename) => {
                    Response::new_ok(id, rename.map(VersionedRenameEdits::into_workspace_edit))
                }
                Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
            },
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/rename parameters: {error}"),
            ),
        }
    } else {
        Response::new_err(
            request.id,
            ErrorCode::MethodNotFound as i32,
            format!("unsupported Splash LSP request `{}`", request.method),
        )
    };

    send_message(connection, response.into())
}

fn handle_notification(
    connection: &Connection,
    server: &mut SplashLanguageServer,
    notification: Notification,
) -> ServerResult<()> {
    let diagnostics = match notification.method.as_str() {
        DidOpenTextDocument::METHOD => {
            serde_json::from_value::<DidOpenTextDocumentParams>(notification.params)
                .ok()
                .map(|params| server.open_document(params.text_document))
        }
        DidChangeTextDocument::METHOD => {
            serde_json::from_value::<DidChangeTextDocumentParams>(notification.params)
                .ok()
                .and_then(|params| server.change_document(params))
        }
        DidCloseTextDocument::METHOD => {
            serde_json::from_value::<DidCloseTextDocumentParams>(notification.params)
                .ok()
                .map(|params| server.close_document(params))
        }
        _ => None,
    };

    if let Some(diagnostics) = diagnostics {
        send_message(
            connection,
            Notification::new(PublishDiagnostics::METHOD.to_owned(), diagnostics).into(),
        )?;
    }

    Ok(())
}

fn send_message(connection: &Connection, message: Message) -> ServerResult<()> {
    connection.sender.send(message)?;
    Ok(())
}

fn syntax_diagnostics(uri: &Uri, source: &str) -> Vec<Diagnostic> {
    match check_syntax_named(uri.as_str(), source, ExecutionLimits::default()) {
        Ok(report) => {
            let mut diagnostics = report
                .diagnostics
                .iter()
                .map(|diagnostic| syntax_diagnostic(source, diagnostic))
                .collect::<Vec<_>>();
            if report.diagnostics_truncated {
                diagnostics.push(Diagnostic::new(
                    Range::new(Position::new(0, 0), Position::new(0, 0)),
                    Some(DiagnosticSeverity::WARNING),
                    None,
                    Some(DIAGNOSTIC_SOURCE.to_owned()),
                    format!("Splash stopped after {MAX_SYNTAX_DIAGNOSTICS} syntax diagnostics"),
                    None,
                    None,
                ));
            }
            diagnostics
        }
        Err(error) => vec![Diagnostic::new(
            Range::new(Position::new(0, 0), Position::new(0, 0)),
            Some(DiagnosticSeverity::ERROR),
            None,
            Some(DIAGNOSTIC_SOURCE.to_owned()),
            format!("Splash syntax check failed: {error}"),
            None,
            None,
        )],
    }
}

fn resource_diagnostics(uri: Uri, version: i32, message: String) -> PublishDiagnosticsParams {
    PublishDiagnosticsParams::new(
        uri,
        vec![Diagnostic::new(
            Range::new(Position::new(0, 0), Position::new(0, 0)),
            Some(DiagnosticSeverity::ERROR),
            None,
            Some(DIAGNOSTIC_SOURCE.to_owned()),
            message,
            None,
            None,
        )],
        Some(version),
    )
}

fn syntax_diagnostic(source: &str, diagnostic: &SyntaxDiagnostic) -> Diagnostic {
    let position = diagnostic_position(source, diagnostic.line, diagnostic.column);
    Diagnostic::new(
        Range::new(position, position),
        Some(DiagnosticSeverity::ERROR),
        None,
        Some(DIAGNOSTIC_SOURCE.to_owned()),
        diagnostic.message.clone(),
        None,
        None,
    )
}

fn diagnostic_position(source: &str, line: usize, column: usize) -> Position {
    let requested_line = line.saturating_sub(1);
    let mut line_index = 0;
    let mut source_line = "";

    for (index, candidate) in source.split('\n').enumerate() {
        line_index = index;
        source_line = candidate;
        if index >= requested_line {
            break;
        }
    }

    let character = source_line
        .chars()
        .take(column.saturating_sub(1))
        .fold(0_u32, |offset, character| {
            offset.saturating_add(character.len_utf16() as u32)
        });
    Position::new(to_u32(line_index), character)
}

fn document_end_position(source: &str) -> Position {
    position_at_byte(source, source.len())
}

#[allow(deprecated)]
fn outline_symbol(source: &str, declaration: &TopLevelDeclaration) -> DocumentSymbol {
    let selection_range = Range::new(
        position_at_byte(source, declaration.selection_start_byte),
        position_at_byte(source, declaration.selection_end_byte),
    );
    DocumentSymbol {
        name: declaration.name.clone(),
        detail: None,
        kind: match declaration.kind {
            TopLevelDeclarationKind::Function => SymbolKind::FUNCTION,
            TopLevelDeclarationKind::Let => SymbolKind::VARIABLE,
        },
        tags: None,
        deprecated: None,
        range: Range::new(
            position_at_byte(source, declaration.declaration_start_byte),
            position_at_byte(source, declaration.declaration_end_byte),
        ),
        selection_range,
        children: None,
    }
}

fn symbol_at_byte(report: &LexicalSymbolReport, byte_offset: usize) -> Option<&LexicalSymbol> {
    symbol_occurrence_at_byte(report, byte_offset).map(|(symbol, _)| symbol)
}

fn symbol_occurrence_at_byte(
    report: &LexicalSymbolReport,
    byte_offset: usize,
) -> Option<(&LexicalSymbol, SourceSpan)> {
    report.symbols.iter().find_map(|symbol| {
        if span_contains(symbol.definition, byte_offset) {
            return Some((symbol, symbol.definition));
        }
        symbol
            .references
            .iter()
            .copied()
            .find(|span| span_contains(*span, byte_offset))
            .map(|span| (symbol, span))
    })
}

fn span_contains(span: SourceSpan, byte_offset: usize) -> bool {
    span.start_byte <= byte_offset && byte_offset < span.end_byte
}

fn symbol_location(uri: &Uri, source: &str, span: SourceSpan) -> Location {
    Location::new(uri.clone(), span_range(source, span))
}

fn span_range(source: &str, span: SourceSpan) -> Range {
    Range::new(
        position_at_byte(source, span.start_byte),
        position_at_byte(source, span.end_byte),
    )
}

fn lexical_symbol_kind_label(kind: LexicalSymbolKind) -> &'static str {
    match kind {
        LexicalSymbolKind::Import => "import binding",
        LexicalSymbolKind::Function => "function",
        LexicalSymbolKind::Let => "binding",
        LexicalSymbolKind::Parameter => "function parameter",
        LexicalSymbolKind::LoopBinding => "loop binding",
        LexicalSymbolKind::LambdaParameter => "lambda parameter",
    }
}

fn completion_item_kind(kind: LexicalSymbolKind) -> CompletionItemKind {
    match kind {
        LexicalSymbolKind::Import => CompletionItemKind::MODULE,
        LexicalSymbolKind::Function => CompletionItemKind::FUNCTION,
        LexicalSymbolKind::Let
        | LexicalSymbolKind::Parameter
        | LexicalSymbolKind::LoopBinding
        | LexicalSymbolKind::LambdaParameter => CompletionItemKind::VARIABLE,
    }
}

fn require_complete_lexical_report(report: &LexicalSymbolReport) -> Result<(), String> {
    if report.truncated {
        Err(format!(
            "the lexical index exceeds Splash's {MAX_LEXICAL_SYMBOL_OCCURRENCES}-occurrence limit"
        ))
    } else {
        Ok(())
    }
}

fn rename_symbol_occurrence_at_byte(
    report: &LexicalSymbolReport,
    byte_offset: usize,
) -> Option<(usize, SourceSpan)> {
    symbol_occurrence_index_at_byte(report, byte_offset).or_else(|| {
        report
            .symbols
            .iter()
            .enumerate()
            .find_map(|(index, symbol)| {
                std::iter::once(symbol.definition)
                    .chain(symbol.references.iter().copied())
                    .find(|span| span.end_byte == byte_offset)
                    .map(|span| (index, span))
            })
    })
}

fn symbol_occurrence_index_at_byte(
    report: &LexicalSymbolReport,
    byte_offset: usize,
) -> Option<(usize, SourceSpan)> {
    report
        .symbols
        .iter()
        .enumerate()
        .find_map(|(index, symbol)| {
            if span_contains(symbol.definition, byte_offset) {
                return Some((index, symbol.definition));
            }
            symbol
                .references
                .iter()
                .copied()
                .find(|span| span_contains(*span, byte_offset))
                .map(|span| (index, span))
        })
}

fn rewrite_symbol_occurrences(
    source: &str,
    symbol: &LexicalSymbol,
    new_name: &str,
) -> Result<(String, Vec<SpanReplacement>), String> {
    let mut spans = std::iter::once(symbol.definition)
        .chain(symbol.references.iter().copied())
        .collect::<Vec<_>>();
    spans.sort_by_key(|span| (span.start_byte, span.end_byte));
    spans.dedup();

    let removed_bytes = spans.iter().try_fold(0_usize, |total, span| {
        span.end_byte
            .checked_sub(span.start_byte)
            .and_then(|width| total.checked_add(width))
    });
    let replacement_bytes = new_name.len().checked_mul(spans.len());
    let rewritten_len = removed_bytes
        .and_then(|removed| source.len().checked_sub(removed))
        .and_then(|retained| replacement_bytes.and_then(|added| retained.checked_add(added)))
        .ok_or_else(|| "the requested rename exceeds Splash's source-size arithmetic".to_owned())?;
    if rewritten_len > DEFAULT_MAX_SOURCE_BYTES {
        return Err(format!(
            "the renamed document would exceed Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit"
        ));
    }

    let mut rewritten = String::with_capacity(rewritten_len);
    let mut replacements = Vec::with_capacity(spans.len());
    let mut cursor = 0_usize;
    for span in spans {
        if span.start_byte < cursor || span.end_byte < span.start_byte {
            return Err("the lexical index contains overlapping rename occurrences".to_owned());
        }
        let prefix = source
            .get(cursor..span.start_byte)
            .ok_or_else(|| "the lexical index contains an invalid source span".to_owned())?;
        let occurrence = source
            .get(span.start_byte..span.end_byte)
            .ok_or_else(|| "the lexical index contains an invalid source span".to_owned())?;
        if occurrence != symbol.name {
            return Err("the lexical index occurrence does not match its symbol name".to_owned());
        }
        rewritten.push_str(prefix);
        let replacement_start = rewritten.len();
        rewritten.push_str(new_name);
        replacements.push(SpanReplacement {
            original: span,
            replacement: SourceSpan {
                start_byte: replacement_start,
                end_byte: rewritten.len(),
            },
        });
        cursor = span.end_byte;
    }
    rewritten.push_str(
        source
            .get(cursor..)
            .ok_or_else(|| "the lexical index contains an invalid source span".to_owned())?,
    );
    if rewritten.len() != rewritten_len {
        return Err("the renamed document did not match its bounded size calculation".to_owned());
    }
    Ok((rewritten, replacements))
}

fn remap_lexical_report(
    report: &LexicalSymbolReport,
    renamed_symbol_index: usize,
    new_name: &str,
    replacements: &[SpanReplacement],
) -> Result<LexicalSymbolReport, String> {
    let mut expected = report.clone();
    let symbol = expected
        .symbols
        .get_mut(renamed_symbol_index)
        .ok_or_else(|| "the rename target is absent from the lexical index".to_owned())?;
    symbol.name = new_name.to_owned();

    for symbol in &mut expected.symbols {
        symbol.definition = remap_source_span(symbol.definition, replacements)?;
        for reference in &mut symbol.references {
            *reference = remap_source_span(*reference, replacements)?;
        }
        symbol.visibility_start_byte =
            remap_source_offset(symbol.visibility_start_byte, replacements)?;
        symbol.visibility_end_byte = remap_source_offset(symbol.visibility_end_byte, replacements)?;
    }
    Ok(expected)
}

fn remap_source_offset(offset: usize, replacements: &[SpanReplacement]) -> Result<usize, String> {
    let mut removed_before = 0_usize;
    let mut added_before = 0_usize;
    for replacement in replacements {
        if offset < replacement.original.start_byte {
            continue;
        }
        if offset == replacement.original.start_byte {
            return Ok(replacement.replacement.start_byte);
        }
        if offset < replacement.original.end_byte {
            return Err("a lexical visibility boundary falls inside a rename edit".to_owned());
        }

        let original_width = replacement
            .original
            .end_byte
            .checked_sub(replacement.original.start_byte)
            .ok_or_else(|| "rename offset remapping underflowed".to_owned())?;
        let replacement_width = replacement
            .replacement
            .end_byte
            .checked_sub(replacement.replacement.start_byte)
            .ok_or_else(|| "rename offset remapping underflowed".to_owned())?;
        removed_before = removed_before
            .checked_add(original_width)
            .ok_or_else(|| "rename offset remapping overflowed".to_owned())?;
        added_before = added_before
            .checked_add(replacement_width)
            .ok_or_else(|| "rename offset remapping overflowed".to_owned())?;
        if offset == replacement.original.end_byte {
            return Ok(replacement.replacement.end_byte);
        }
    }

    offset
        .checked_sub(removed_before)
        .and_then(|value| value.checked_add(added_before))
        .ok_or_else(|| "rename offset remapping overflowed".to_owned())
}

fn remap_source_span(
    span: SourceSpan,
    replacements: &[SpanReplacement],
) -> Result<SourceSpan, String> {
    let mut removed_before = 0_usize;
    let mut added_before = 0_usize;
    for replacement in replacements {
        if replacement.original == span {
            return Ok(replacement.replacement);
        }
        if replacement.original.end_byte <= span.start_byte {
            let original_width = replacement
                .original
                .end_byte
                .checked_sub(replacement.original.start_byte)
                .ok_or_else(|| "rename span remapping underflowed".to_owned())?;
            let replacement_width = replacement
                .replacement
                .end_byte
                .checked_sub(replacement.replacement.start_byte)
                .ok_or_else(|| "rename span remapping underflowed".to_owned())?;
            removed_before = removed_before
                .checked_add(original_width)
                .ok_or_else(|| "rename span remapping overflowed".to_owned())?;
            added_before = added_before
                .checked_add(replacement_width)
                .ok_or_else(|| "rename span remapping overflowed".to_owned())?;
            continue;
        }
        if replacement.original.start_byte >= span.end_byte {
            continue;
        }
        return Err("a rename edit partially overlaps another lexical occurrence".to_owned());
    }

    let remap_offset = |offset: usize| {
        offset
            .checked_sub(removed_before)
            .and_then(|value| value.checked_add(added_before))
            .ok_or_else(|| "rename span remapping overflowed".to_owned())
    };
    Ok(SourceSpan {
        start_byte: remap_offset(span.start_byte)?,
        end_byte: remap_offset(span.end_byte)?,
    })
}

fn byte_at_position(source: &str, position: Position) -> Option<usize> {
    let mut line = 0_u32;
    let mut line_start = 0_usize;
    let mut offset = 0_usize;
    let bytes = source.as_bytes();

    while offset < bytes.len() {
        let line_end = match bytes[offset] {
            b'\r' | b'\n' => Some(offset),
            _ => None,
        };
        if let Some(line_end) = line_end {
            if line == position.line {
                return byte_at_utf16_column(&source[line_start..line_end], position.character)
                    .map(|column| line_start + column);
            }

            if bytes[offset] == b'\r' && bytes.get(offset + 1) == Some(&b'\n') {
                offset += 2;
            } else {
                offset += 1;
            }
            line = line.saturating_add(1);
            line_start = offset;
            continue;
        }

        offset += source[offset..].chars().next()?.len_utf8();
    }

    (line == position.line)
        .then(|| byte_at_utf16_column(&source[line_start..], position.character))
        .flatten()
        .map(|column| line_start + column)
}

fn byte_at_utf16_column(line: &str, character: u32) -> Option<usize> {
    let mut utf16_column = 0_u32;
    for (byte_offset, value) in line.char_indices() {
        if utf16_column == character {
            return Some(byte_offset);
        }
        utf16_column = utf16_column.checked_add(value.len_utf16() as u32)?;
        if utf16_column > character {
            return None;
        }
    }
    (utf16_column == character).then_some(line.len())
}

fn position_at_byte(source: &str, byte_offset: usize) -> Position {
    let mut line = 0_u32;
    let mut character = 0_u32;
    let mut previous_was_carriage_return = false;

    for value in source[..byte_offset].chars() {
        match value {
            '\r' => {
                line = line.saturating_add(1);
                character = 0;
                previous_was_carriage_return = true;
            }
            '\n' if previous_was_carriage_return => {
                previous_was_carriage_return = false;
            }
            '\n' => {
                line = line.saturating_add(1);
                character = 0;
                previous_was_carriage_return = false;
            }
            _ => {
                character = character.saturating_add(value.len_utf16() as u32);
                previous_was_carriage_return = false;
            }
        }
    }

    Position::new(line, character)
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use lsp_types::{
        notification::{Initialized, Notification as LspNotification},
        FormattingOptions, TextDocumentContentChangeEvent, VersionedTextDocumentIdentifier,
    };

    use super::*;

    fn test_uri() -> Uri {
        Uri::from_str("file:///workspace/example.splash").expect("valid file URI")
    }

    fn document(version: i32, text: &str) -> TextDocumentItem {
        TextDocumentItem::new(test_uri(), "splash".to_owned(), version, text.to_owned())
    }

    fn apply_text_edits(source: &str, edits: &[TextEdit]) -> String {
        let mut byte_edits = edits
            .iter()
            .map(|edit| {
                let start = byte_at_position(source, edit.range.start)
                    .expect("edit start is a valid source position");
                let end = byte_at_position(source, edit.range.end)
                    .expect("edit end is a valid source position");
                (start, end, edit.new_text.as_str())
            })
            .collect::<Vec<_>>();
        byte_edits.sort_by_key(|(start, end, _)| (*start, *end));
        for pair in byte_edits.windows(2) {
            assert!(pair[0].1 <= pair[1].0, "rename edits do not overlap");
        }

        let mut edited = source.to_owned();
        for (start, end, replacement) in byte_edits.into_iter().rev() {
            edited.replace_range(start..end, replacement);
        }
        edited
    }

    #[test]
    fn lexical_hover_labels_cover_every_binding_kind() {
        assert_eq!(
            lexical_symbol_kind_label(LexicalSymbolKind::Import),
            "import binding"
        );
        assert_eq!(
            lexical_symbol_kind_label(LexicalSymbolKind::Function),
            "function"
        );
        assert_eq!(lexical_symbol_kind_label(LexicalSymbolKind::Let), "binding");
        assert_eq!(
            lexical_symbol_kind_label(LexicalSymbolKind::Parameter),
            "function parameter"
        );
        assert_eq!(
            lexical_symbol_kind_label(LexicalSymbolKind::LoopBinding),
            "loop binding"
        );
        assert_eq!(
            lexical_symbol_kind_label(LexicalSymbolKind::LambdaParameter),
            "lambda parameter"
        );
    }

    #[test]
    fn rename_offset_remapping_handles_boundaries_eof_and_unsorted_edits() {
        let replacements = [
            SpanReplacement {
                original: SourceSpan {
                    start_byte: 10,
                    end_byte: 12,
                },
                replacement: SourceSpan {
                    start_byte: 13,
                    end_byte: 14,
                },
            },
            SpanReplacement {
                original: SourceSpan {
                    start_byte: 2,
                    end_byte: 5,
                },
                replacement: SourceSpan {
                    start_byte: 2,
                    end_byte: 8,
                },
            },
        ];

        for (original, remapped) in [(0, 0), (2, 2), (5, 8), (10, 13), (12, 14), (20, 22)] {
            assert_eq!(
                remap_source_offset(original, &replacements).unwrap(),
                remapped
            );
        }
        assert!(remap_source_offset(3, &replacements).is_err());
        assert_eq!(
            remap_source_span(
                SourceSpan {
                    start_byte: 15,
                    end_byte: 17,
                },
                &replacements,
            )
            .unwrap(),
            SourceSpan {
                start_byte: 17,
                end_byte: 19,
            }
        );

        let shorter = [SpanReplacement {
            original: SourceSpan {
                start_byte: 2,
                end_byte: 7,
            },
            replacement: SourceSpan {
                start_byte: 2,
                end_byte: 3,
            },
        }];
        assert_eq!(remap_source_offset(2, &shorter).unwrap(), 2);
        assert_eq!(remap_source_offset(7, &shorter).unwrap(), 3);
        assert_eq!(remap_source_offset(10, &shorter).unwrap(), 6);
    }

    #[test]
    fn reports_syntax_diagnostics_without_executing_source() {
        let mut server = SplashLanguageServer::default();
        let diagnostics = server.open_document(document(1, "var value = 42"));

        assert_eq!(diagnostics.version, Some(1));
        assert!(!diagnostics.diagnostics.is_empty());
        assert_eq!(
            diagnostics.diagnostics[0].source.as_deref(),
            Some(DIAGNOSTIC_SOURCE)
        );
        assert_eq!(
            diagnostics.diagnostics[0].severity,
            Some(DiagnosticSeverity::ERROR)
        );
    }

    #[test]
    fn outlines_top_level_declarations_without_reading_or_executing_source() {
        let source = "let config = {label: \"fn hidden() {}\", nested: {count: 1}}\n\
                      fn greet(name) {\n\
                          let local = name\n\
                          local\n\
                      }\n\
                      let emoji = \"\u{1f642}\"\n\
                      // let ignored = 0\n";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let symbols = server
            .document_symbols(&test_uri())
            .expect("document is open and valid");

        assert_eq!(
            symbols
                .iter()
                .map(|symbol| symbol.name.as_str())
                .collect::<Vec<_>>(),
            ["config", "greet", "emoji"]
        );
        assert_eq!(symbols[0].kind, SymbolKind::VARIABLE);
        assert_eq!(symbols[1].kind, SymbolKind::FUNCTION);
        assert_eq!(symbols[1].selection_range.start, Position::new(1, 3));
        assert_eq!(symbols[1].selection_range.end, Position::new(1, 8));
        assert_eq!(symbols[1].range.start, Position::new(1, 0));
        assert_eq!(symbols[1].range.end, Position::new(4, 1));
        assert_eq!(
            symbols[2].selection_range,
            Range::new(Position::new(5, 4), Position::new(5, 9))
        );
        assert_eq!(
            symbols[2].range,
            Range::new(Position::new(5, 0), Position::new(5, 16))
        );
    }

    #[test]
    fn suppresses_symbols_for_invalid_source_and_normalizes_crlf_positions() {
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, "fn broken("));
        assert!(server
            .document_symbols(&test_uri())
            .expect("invalid source still has an outline response")
            .is_empty());

        server.open_document(document(2, "fn crlf() {\r\n}\r\n"));
        let symbols = server
            .document_symbols(&test_uri())
            .expect("valid CRLF source has an outline response");
        assert_eq!(
            symbols[0].selection_range,
            Range::new(Position::new(0, 3), Position::new(0, 7))
        );
        assert_eq!(
            symbols[0].range,
            Range::new(Position::new(0, 0), Position::new(1, 1))
        );

        assert_eq!(
            document_end_position("let value = 1\r\n"),
            Position::new(1, 0)
        );
    }

    #[test]
    fn resolves_same_document_lexical_editor_features() {
        let source = "let marker = \"\u{1f642}\"\r\n\
                      fn echo(value) {\r\n\
                          let local = value\r\n\
                          local + value\r\n\
                      }\r\n\
                      echo(marker)";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let local_reference = source.rfind("local").expect("local reference exists");
        let definition = server
            .definition(&test_uri(), position_at_byte(source, local_reference))
            .expect("symbol index succeeds")
            .expect("local reference resolves");
        let local_definition = source.find("local").expect("local definition exists");
        assert_eq!(
            definition.range,
            Range::new(
                position_at_byte(source, local_definition),
                position_at_byte(source, local_definition + "local".len()),
            )
        );
        assert_eq!(
            server
                .definition(&test_uri(), position_at_byte(source, local_definition))
                .expect("symbol index succeeds")
                .expect("a definition resolves to itself"),
            definition
        );

        let hover = server
            .hover(&test_uri(), position_at_byte(source, local_reference))
            .expect("hover index succeeds")
            .expect("local reference has hover information");
        assert_eq!(
            hover.range,
            Some(Range::new(
                position_at_byte(source, local_reference),
                position_at_byte(source, local_reference + "local".len()),
            ))
        );
        assert_eq!(
            hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: "**binding** `local`".to_owned(),
            })
        );

        let highlights = server
            .document_highlights(&test_uri(), position_at_byte(source, local_reference))
            .expect("highlight index succeeds");
        assert_eq!(highlights.len(), 2);
        assert_eq!(
            highlights
                .iter()
                .map(|highlight| highlight.kind)
                .collect::<Vec<_>>(),
            [
                Some(DocumentHighlightKind::TEXT),
                Some(DocumentHighlightKind::TEXT),
            ]
        );
        assert_eq!(
            highlights[0].range,
            Range::new(
                position_at_byte(source, local_definition),
                position_at_byte(source, local_definition + "local".len()),
            )
        );
        assert_eq!(
            highlights[1].range,
            hover.range.expect("hover range exists")
        );

        let value_reference = source.rfind("value").expect("value reference exists");
        let without_declaration = server
            .references(
                &test_uri(),
                position_at_byte(source, value_reference),
                false,
            )
            .expect("reference index succeeds");
        assert_eq!(without_declaration.len(), 2);
        let with_declaration = server
            .references(&test_uri(), position_at_byte(source, value_reference), true)
            .expect("reference index succeeds");
        assert_eq!(with_declaration.len(), 3);
        assert_eq!(
            with_declaration[0].range,
            Range::new(Position::new(1, 8), Position::new(1, 13))
        );
    }

    #[test]
    fn prepares_and_applies_versioned_semantics_preserving_renames() {
        let source = "let value = 1\r\n\
                      fn read() {\r\n\
                          \"\u{1f642}\" + value\r\n\
                      }\r\n\
                      read() + value";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(7, source));

        let unicode_reference = source
            .find("\"\u{1f642}\" + value")
            .expect("Unicode reference line exists")
            + "\"\u{1f642}\" + ".len();
        let reference_end = unicode_reference + "value".len();
        assert_eq!(
            position_at_byte(source, unicode_reference),
            Position::new(2, 7)
        );
        let prepared = server
            .prepare_rename(&test_uri(), position_at_byte(source, reference_end))
            .expect("prepare rename succeeds")
            .expect("cursor at the identifier end remains renameable");
        assert_eq!(
            prepared,
            PrepareRenameResponse::RangeWithPlaceholder {
                range: Range::new(Position::new(2, 7), Position::new(2, 12)),
                placeholder: "value".to_owned(),
            }
        );
        let final_reference = source.rfind("value").expect("final reference exists");
        let prepared_at_eof = server
            .prepare_rename(&test_uri(), position_at_byte(source, source.len()))
            .expect("prepare at end of file succeeds")
            .expect("the final identifier remains renameable at its end");
        assert_eq!(
            prepared_at_eof,
            PrepareRenameResponse::RangeWithPlaceholder {
                range: Range::new(
                    position_at_byte(source, final_reference),
                    position_at_byte(source, source.len()),
                ),
                placeholder: "value".to_owned(),
            }
        );

        let rename = server
            .rename(
                &test_uri(),
                position_at_byte(source, reference_end),
                "renamed",
            )
            .expect("rename analysis succeeds")
            .expect("the lexical reference is renameable");
        assert_eq!(rename.uri, test_uri());
        assert_eq!(rename.version, 7);
        assert_eq!(rename.edits.len(), 3);
        assert!(rename.edits.iter().all(|edit| edit.new_text == "renamed"));
        assert_eq!(
            rename.edits[1].range,
            Range::new(Position::new(2, 7), Position::new(2, 12))
        );
        assert_eq!(
            apply_text_edits(source, &rename.edits),
            "let renamed = 1\r\nfn read() {\r\n\"\u{1f642}\" + renamed\r\n}\r\nread() + renamed"
        );

        let shortened = server
            .rename(
                &test_uri(),
                position_at_byte(source, unicode_reference),
                "v",
            )
            .expect("shortening rename analysis succeeds")
            .expect("the lexical reference is renameable");
        assert_eq!(
            apply_text_edits(source, &shortened.edits),
            "let v = 1\r\nfn read() {\r\n\"\u{1f642}\" + v\r\n}\r\nread() + v"
        );

        let function_reference = source.rfind("read").expect("function reference exists");
        let function_rename = server
            .rename(
                &test_uri(),
                position_at_byte(source, function_reference),
                "read_value",
            )
            .expect("function rename analysis succeeds")
            .expect("function reference is renameable");
        assert_eq!(function_rename.edits.len(), 2);

        assert_eq!(
            server
                .rename(
                    &test_uri(),
                    position_at_byte(source, unicode_reference),
                    "value",
                )
                .expect("an identical rename succeeds"),
            None
        );
    }

    #[test]
    fn completes_visible_lexical_bindings_with_exact_unfiltered_edits() {
        let source = "use mod.std.assert\n\
                      let apple = 1\n\
                      let apricot = 2\n\
                      fn choose(apple) {\n\
                          let local = \"🙂\" + apple\n\
                          ap\n\
                      }\n\
                      apple";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));
        let site_start = source.find("\nap\n").unwrap() + 1;
        let expected_range = Range::new(
            position_at_byte(source, site_start),
            position_at_byte(source, site_start + 2),
        );

        for cursor in [site_start, site_start + 2] {
            let completion = server
                .completion(&test_uri(), position_at_byte(source, cursor))
                .unwrap();
            assert!(!completion.is_incomplete);
            assert_eq!(
                completion
                    .items
                    .iter()
                    .map(|item| item.label.as_str())
                    .collect::<Vec<_>>(),
                ["apple", "apricot", "assert", "choose", "local"]
            );
            assert!(completion.items.iter().all(|item| {
                matches!(
                    item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                        if range == expected_range
                )
            }));
        }

        let assert_item = server
            .completion(&test_uri(), position_at_byte(source, site_start + 1))
            .unwrap()
            .items
            .into_iter()
            .find(|item| item.label == "assert")
            .unwrap();
        assert_eq!(assert_item.kind, Some(CompletionItemKind::MODULE));
        let choose_item = server
            .completion(&test_uri(), position_at_byte(source, site_start + 1))
            .unwrap()
            .items
            .into_iter()
            .find(|item| item.label == "choose")
            .unwrap();
        assert_eq!(choose_item.kind, Some(CompletionItemKind::FUNCTION));

        let final_site = source.rfind("apple").unwrap();
        let outside = server
            .completion(&test_uri(), position_at_byte(source, final_site + 1))
            .unwrap();
        assert!(outside.items.iter().all(|item| item.label != "local"));
        assert_eq!(
            outside
                .items
                .iter()
                .filter(|item| item.label == "apple")
                .count(),
            1
        );
    }

    #[test]
    fn completion_handles_incomplete_source_and_rejects_invalid_utf16_positions() {
        let source = "let marker = \"🙂\"\nlet alpha = 1\nal(";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let completion = server.completion(&test_uri(), Position::new(2, 2)).unwrap();
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "marker"]
        );
        assert!(!completion.is_incomplete);

        let mid_surrogate = server
            .completion(&test_uri(), Position::new(0, 15))
            .unwrap();
        assert!(mid_surrogate.items.is_empty());
        assert!(!mid_surrogate.is_incomplete);
        assert!(server
            .completion(&test_uri(), Position::new(99, 0))
            .unwrap()
            .items
            .is_empty());
    }

    #[test]
    fn completion_excludes_sites_after_the_first_mid_document_error() {
        let source = "let alpha = 1\nalpha\n@\nlet beta = 2\nbeta";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));
        let alpha_site = source.find("\nalpha").unwrap() + 1;
        let beta_site = source.rfind("beta").unwrap();

        let before_error = server
            .completion(&test_uri(), position_at_byte(source, alpha_site + 2))
            .unwrap();
        assert_eq!(before_error.items.len(), 1);
        assert_eq!(before_error.items[0].label, "alpha");

        let after_error = server
            .completion(&test_uri(), position_at_byte(source, beta_site + 2))
            .unwrap();
        assert!(after_error.items.is_empty());
        assert!(!after_error.is_incomplete);
    }

    #[test]
    fn completion_reports_independent_truncation_to_the_client() {
        let mut source = String::from("let value = 0\n");
        for _ in 0..=splash_core::MAX_LEXICAL_COMPLETION_SITES {
            source.push_str("missing\n");
        }
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        let first_site = source.find("\nmissing").unwrap() + 1;
        let completion = server
            .completion(&test_uri(), position_at_byte(&source, first_site))
            .unwrap();

        assert!(completion.is_incomplete);
        assert_eq!(completion.items.len(), 1);
        assert_eq!(completion.items[0].label, "value");
    }

    #[test]
    fn completion_returns_no_candidates_from_a_truncated_symbol_index() {
        let mut source = String::from("let value = 0\n");
        for _ in 0..MAX_LEXICAL_SYMBOL_OCCURRENCES {
            source.push_str("value\n");
        }
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));
        let first_site = source.find("\nvalue").unwrap() + 1;

        let completion = server
            .completion(&test_uri(), position_at_byte(&source, first_site))
            .unwrap();

        assert!(completion.is_incomplete);
        assert!(completion.items.is_empty());
    }

    #[test]
    fn rejects_renames_that_are_invalid_ambiguous_or_change_binding_resolution() {
        let source = "use mod.std.assert\n\
                      let outer = 1\n\
                      fn compute() {\n\
                          let inner = 2\n\
                          assert(inner + outer)\n\
                      }";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let inner = source.find("inner").expect("inner definition exists");
        let collision = server
            .rename(&test_uri(), position_at_byte(source, inner), "outer")
            .expect_err("capturing an outer reference must be rejected");
        assert!(collision.contains("binding resolution"));

        let local = source.find("outer").expect("outer definition exists");
        let builtin_capture = server
            .rename(&test_uri(), position_at_byte(source, local), "assert")
            .expect_err("capturing an imported call must be rejected");
        assert!(builtin_capture.contains("binding resolution"));

        for invalid in [
            "try",
            "false",
            "nil",
            "two words",
            "name/*comment*/",
            "name\nnext",
            "name\rnext",
            "name\0next",
            "\u{feff}name",
            "\u{1f642}",
        ] {
            let error = server
                .rename(&test_uri(), position_at_byte(source, inner), invalid)
                .expect_err("invalid identifier spelling must be rejected");
            assert!(error.contains("canonical Splash identifier"), "{error}");
        }

        let import = source.find("assert").expect("import binding exists");
        assert_eq!(
            server
                .prepare_rename(&test_uri(), position_at_byte(source, import))
                .expect("import prepare is bounded"),
            None
        );
        let error = server
            .rename(&test_uri(), position_at_byte(source, import), "verify")
            .expect_err("renaming an import path is not a local binding rename");
        assert!(error.contains("module path"));

        let oversized_name = "a".repeat(DEFAULT_MAX_SOURCE_BYTES);
        let error = server
            .rename(
                &test_uri(),
                position_at_byte(source, inner),
                &oversized_name,
            )
            .expect_err("renamed source remains bounded");
        assert!(error.contains("source limit"));
    }

    #[test]
    fn allows_a_rename_that_preserves_safe_lexical_shadowing() {
        let source = "let value = 1\n\
                      fn compute() {\n\
                          let inner = 2\n\
                          inner\n\
                      }\n\
                      value";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));
        let inner = source.find("inner").expect("inner definition exists");

        let rename = server
            .rename(&test_uri(), position_at_byte(source, inner), "value")
            .expect("safe shadowing analysis succeeds")
            .expect("safe local shadowing remains renameable");
        assert_eq!(rename.edits.len(), 2);
        assert_eq!(
            apply_text_edits(source, &rename.edits),
            "let value = 1\nfn compute() {\nlet value = 2\nvalue\n}\nvalue"
        );
    }

    #[test]
    fn resolves_imports_and_loop_bindings_without_cross_document_leakage() {
        let source = "use mod.std.assert\n\
                      for index in [1] {\n\
                          assert(index)\n\
                      }";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        for name in ["assert", "index"] {
            let definition_start = source.find(name).expect("definition exists");
            let reference_start = source.rfind(name).expect("reference exists");
            let location = server
                .definition(&test_uri(), position_at_byte(source, reference_start))
                .expect("symbol index succeeds")
                .expect("reference resolves");
            assert_eq!(location.uri, test_uri());
            assert_eq!(
                location.range,
                Range::new(
                    position_at_byte(source, definition_start),
                    position_at_byte(source, definition_start + name.len()),
                )
            );
        }

        let other_uri = Uri::from_str("file:///workspace/other.splash").expect("valid file URI");
        let other_source = "let index = 9\nindex";
        server.open_document(TextDocumentItem::new(
            other_uri.clone(),
            "splash".to_owned(),
            1,
            other_source.to_owned(),
        ));
        let other_location = server
            .definition(&other_uri, Position::new(1, 1))
            .expect("other document index succeeds")
            .expect("other document reference resolves");
        assert_eq!(other_location.uri, other_uri);
        assert_eq!(
            other_location.range,
            Range::new(Position::new(0, 4), Position::new(0, 9))
        );
    }

    #[test]
    fn lexical_requests_return_no_result_for_invalid_source_or_position() {
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, "fn broken("));

        assert_eq!(
            server
                .definition(&test_uri(), Position::new(0, 3))
                .expect("invalid source produces an empty index"),
            None
        );
        assert!(server
            .references(&test_uri(), Position::new(0, 3), true)
            .expect("invalid source produces an empty index")
            .is_empty());
        assert_eq!(
            server
                .hover(&test_uri(), Position::new(0, 3))
                .expect("invalid source produces an empty index"),
            None
        );
        assert!(server
            .document_highlights(&test_uri(), Position::new(0, 3))
            .expect("invalid source produces an empty index")
            .is_empty());
        assert_eq!(
            server
                .prepare_rename(&test_uri(), Position::new(0, 3))
                .expect("invalid source produces an empty index"),
            None
        );
        assert_eq!(
            server
                .rename(&test_uri(), Position::new(0, 3), "valid")
                .expect("invalid source produces an empty index"),
            None
        );

        server.open_document(document(2, "let value = 1"));
        assert_eq!(
            server
                .definition(&test_uri(), Position::new(4, 0))
                .expect("an out-of-range position has no symbol"),
            None
        );
    }

    #[test]
    fn serves_retained_definitions_but_rejects_truncated_reference_indexes() {
        let mut source = String::new();
        for index in 0..=MAX_LEXICAL_SYMBOL_OCCURRENCES {
            source.push_str(&format!("let binding{index} = 0\n"));
        }
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        assert!(server
            .definition(&test_uri(), Position::new(0, 4))
            .expect("retained definitions remain sound")
            .is_some());
        assert!(server
            .hover(&test_uri(), Position::new(0, 4))
            .expect("retained hover information remains sound")
            .is_some());
        let omitted_position = Position::new(to_u32(MAX_LEXICAL_SYMBOL_OCCURRENCES), 4);
        assert_eq!(
            server
                .definition(&test_uri(), omitted_position)
                .expect("an omitted definition produces no location"),
            None
        );
        assert_eq!(
            server
                .hover(&test_uri(), omitted_position)
                .expect("an omitted definition produces no hover"),
            None
        );
        let error = server
            .references(&test_uri(), Position::new(0, 4), true)
            .expect_err("truncated reference sets are not returned as complete results");
        assert!(error.contains("occurrence limit"));
        let error = server
            .document_highlights(&test_uri(), Position::new(0, 4))
            .expect_err("truncated highlight sets are not returned as complete results");
        assert!(error.contains("occurrence limit"));
        let error = server
            .prepare_rename(&test_uri(), Position::new(0, 4))
            .expect_err("truncated indexes cannot prepare an exhaustive rename");
        assert!(error.contains("occurrence limit"));
        let error = server
            .rename(&test_uri(), Position::new(0, 4), "renamed")
            .expect_err("truncated indexes cannot produce an exhaustive rename");
        assert!(error.contains("occurrence limit"));
    }

    #[test]
    fn converts_core_positions_to_zero_based_utf16() {
        assert_eq!(
            diagnostic_position("\u{1f642}x", 1, 3),
            Position::new(0, 3),
            "the first two Unicode scalar values occupy three UTF-16 code units"
        );
        assert_eq!(
            diagnostic_position("first\nlast", 9, 9),
            Position::new(1, 4)
        );
        assert_eq!(
            byte_at_position("\u{1f642}x\r\ny", Position::new(0, 2)),
            Some(4)
        );
        assert_eq!(
            byte_at_position("\u{1f642}x\r\ny", Position::new(0, 1)),
            None
        );
        assert_eq!(
            byte_at_position("\u{1f642}x\r\ny", Position::new(1, 0)),
            Some(7)
        );
        assert_eq!(
            byte_at_position("\u{1f642}x\r\ny", Position::new(1, 1)),
            Some(8)
        );
    }

    #[test]
    fn formats_with_one_full_document_edit() {
        let source = "fn add(left,right){\nreturn left+right\n}\nlet record={left:1,right:2}\nadd(record.left,record.right)";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let edits = server
            .format_document(&test_uri())
            .expect("format succeeds");

        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].range.start, Position::new(0, 0));
        assert_eq!(edits[0].range.end, document_end_position(source));
        assert_eq!(
            edits[0].new_text,
            "fn add(left, right) {\n    return left + right\n}\nlet record = {left: 1, right: 2}\nadd(record.left, record.right)\n"
        );
    }

    #[test]
    fn ignores_incremental_and_stale_changes_under_full_sync() {
        let mut server = SplashLanguageServer::default();
        server.open_document(document(3, "let value = 1"));

        let stale = DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier::new(test_uri(), 3),
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "let value = 2".to_owned(),
            }],
        };
        assert!(server.change_document(stale).is_none());

        let incremental = DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier::new(test_uri(), 4),
            content_changes: vec![TextDocumentContentChangeEvent {
                range: Some(Range::new(Position::new(0, 12), Position::new(0, 13))),
                range_length: None,
                text: "3".to_owned(),
            }],
        };
        assert!(server.change_document(incremental).is_none());
        let rename = server
            .rename(&test_uri(), Position::new(0, 5), "renamed")
            .expect("rename uses the last accepted full snapshot")
            .expect("the retained binding is renameable");
        assert_eq!(rename.version, 3);
        let edits = server
            .format_document(&test_uri())
            .expect("original document remains available");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].new_text, "let value = 1\n");
    }

    #[test]
    fn invalidates_the_cached_lexical_report_on_a_full_document_change() {
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, "let first = 1\nfirst"));
        assert!(server
            .definition(&test_uri(), Position::new(1, 1))
            .expect("the first lexical report is cached")
            .is_some());

        let diagnostics = server
            .change_document(DidChangeTextDocumentParams {
                text_document: VersionedTextDocumentIdentifier::new(test_uri(), 2),
                content_changes: vec![TextDocumentContentChangeEvent {
                    range: None,
                    range_length: None,
                    text: "let second = 2\nsecond".to_owned(),
                }],
            })
            .expect("a newer full document replaces the cached snapshot");
        assert!(diagnostics.diagnostics.is_empty());

        let prepared = server
            .prepare_rename(&test_uri(), Position::new(1, 1))
            .expect("the replacement document builds a fresh lexical report")
            .expect("the replacement binding is renameable");
        assert_eq!(
            prepared,
            PrepareRenameResponse::RangeWithPlaceholder {
                range: Range::new(Position::new(1, 0), Position::new(1, 6)),
                placeholder: "second".to_owned(),
            }
        );
        let rename = server
            .rename(&test_uri(), Position::new(1, 1), "updated")
            .expect("rename uses the replacement lexical report")
            .expect("the replacement binding is renameable");
        assert_eq!(rename.version, 2);
        assert_eq!(rename.edits.len(), 2);
    }

    #[test]
    fn oversized_document_can_recover_on_a_later_full_change() {
        let mut server = SplashLanguageServer::default();
        let oversized = "x".repeat(DEFAULT_MAX_SOURCE_BYTES + 1);
        let diagnostics = server.open_document(document(1, &oversized));
        assert_eq!(diagnostics.diagnostics.len(), 1);
        assert!(server.format_document(&test_uri()).is_err());
        assert!(server.document_symbols(&test_uri()).is_err());
        assert!(server.hover(&test_uri(), Position::new(0, 0)).is_err());
        assert!(server
            .document_highlights(&test_uri(), Position::new(0, 0))
            .is_err());
        assert!(server
            .prepare_rename(&test_uri(), Position::new(0, 0))
            .is_err());
        assert!(server
            .rename(&test_uri(), Position::new(0, 0), "valid")
            .is_err());

        let update = DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier::new(test_uri(), 2),
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "let value = 1".to_owned(),
            }],
        };
        let diagnostics = server
            .change_document(update)
            .expect("full replacement is accepted");
        assert!(diagnostics.diagnostics.is_empty());
        assert!(server.format_document(&test_uri()).is_ok());
        assert!(server.hover(&test_uri(), Position::new(0, 5)).is_ok());
        assert!(server
            .prepare_rename(&test_uri(), Position::new(0, 5))
            .expect("replacement source has a fresh lexical cache")
            .is_some());
    }

    #[test]
    fn announces_and_serves_bounded_editor_features_over_stdio_protocol() {
        let (server_connection, client_connection) = Connection::memory();
        let server_thread = std::thread::spawn(move || run_connection(&server_connection));

        client_connection
            .sender
            .send(
                Request::new(
                    1.into(),
                    "initialize".to_owned(),
                    serde_json::json!({
                        "capabilities": {
                            "workspace": {
                                "workspaceEdit": {"documentChanges": true}
                            }
                        }
                    }),
                )
                .into(),
            )
            .expect("initialize send succeeds");
        let initialize_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("initialize response arrives");
        let Message::Response(response) = initialize_response else {
            panic!("expected initialize response");
        };
        let capabilities = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result["capabilities"].clone(),
            lsp_server::ResponseKind::Err { error } => {
                panic!("initialize failed: {}", error.message)
            }
        };
        assert_eq!(capabilities["positionEncoding"], "utf-16");
        assert_eq!(capabilities["textDocumentSync"], 1);
        assert_eq!(capabilities["documentFormattingProvider"], true);
        assert_eq!(capabilities["documentSymbolProvider"], true);
        assert_eq!(capabilities["definitionProvider"], true);
        assert_eq!(capabilities["referencesProvider"], true);
        assert_eq!(capabilities["hoverProvider"], true);
        assert_eq!(capabilities["documentHighlightProvider"], true);
        assert_eq!(capabilities["completionProvider"]["resolveProvider"], false);
        assert_eq!(capabilities["renameProvider"]["prepareProvider"], true);

        client_connection
            .sender
            .send(Notification::new(Initialized::METHOD.to_owned(), ()).into())
            .expect("initialized send succeeds");
        client_connection
            .sender
            .send(
                Notification::new(
                    DidOpenTextDocument::METHOD.to_owned(),
                    DidOpenTextDocumentParams {
                        text_document: document(1, "let value=1\nvalue"),
                    },
                )
                .into(),
            )
            .expect("open send succeeds");

        let _diagnostics = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("diagnostics arrive after open");
        client_connection
            .sender
            .send(
                Request::new(
                    2.into(),
                    Formatting::METHOD.to_owned(),
                    DocumentFormattingParams {
                        text_document: lsp_types::TextDocumentIdentifier::new(test_uri()),
                        options: FormattingOptions::default(),
                        work_done_progress_params: lsp_types::WorkDoneProgressParams::default(),
                    },
                )
                .into(),
            )
            .expect("format send succeeds");
        let format_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("format response arrives");
        let Message::Response(response) = format_response else {
            panic!("expected formatting response");
        };
        let edits = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("format failed: {}", error.message)
            }
        };
        assert_eq!(edits[0]["newText"], "let value = 1\nvalue\n");

        client_connection
            .sender
            .send(
                Request::new(
                    3.into(),
                    DocumentSymbolRequest::METHOD.to_owned(),
                    serde_json::json!({"textDocument": {"uri": test_uri()}}),
                )
                .into(),
            )
            .expect("document symbol request send succeeds");
        let symbol_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("document symbol response arrives");
        let Message::Response(response) = symbol_response else {
            panic!("expected document symbol response");
        };
        let symbols = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("document symbol request failed: {}", error.message)
            }
        };
        assert_eq!(symbols[0]["name"], "value");
        assert_eq!(symbols[0]["kind"], 13);

        client_connection
            .sender
            .send(
                Request::new(
                    4.into(),
                    GotoDefinition::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 1}
                    }),
                )
                .into(),
            )
            .expect("definition request send succeeds");
        let definition_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("definition response arrives");
        let Message::Response(response) = definition_response else {
            panic!("expected definition response");
        };
        let definition = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("definition request failed: {}", error.message)
            }
        };
        assert_eq!(
            definition["range"]["start"],
            serde_json::json!({"line": 0, "character": 4})
        );
        assert_eq!(
            definition["range"]["end"],
            serde_json::json!({"line": 0, "character": 9})
        );

        client_connection
            .sender
            .send(
                Request::new(
                    5.into(),
                    References::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 1},
                        "context": {"includeDeclaration": true}
                    }),
                )
                .into(),
            )
            .expect("references request send succeeds");
        let references_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("references response arrives");
        let Message::Response(response) = references_response else {
            panic!("expected references response");
        };
        let references = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("references request failed: {}", error.message)
            }
        };
        assert_eq!(references.as_array().map(Vec::len), Some(2));

        client_connection
            .sender
            .send(
                Request::new(
                    6.into(),
                    HoverRequest::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 1}
                    }),
                )
                .into(),
            )
            .expect("hover request send succeeds");
        let hover_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("hover response arrives");
        let Message::Response(response) = hover_response else {
            panic!("expected hover response");
        };
        let hover = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("hover request failed: {}", error.message)
            }
        };
        assert_eq!(hover["contents"]["kind"], "markdown");
        assert_eq!(hover["contents"]["value"], "**binding** `value`");
        assert_eq!(
            hover["range"],
            serde_json::json!({
                "start": {"line": 1, "character": 0},
                "end": {"line": 1, "character": 5}
            })
        );

        client_connection
            .sender
            .send(
                Request::new(
                    7.into(),
                    DocumentHighlightRequest::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 1}
                    }),
                )
                .into(),
            )
            .expect("document highlight request send succeeds");
        let highlight_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("document highlight response arrives");
        let Message::Response(response) = highlight_response else {
            panic!("expected document highlight response");
        };
        let highlights = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("document highlight request failed: {}", error.message)
            }
        };
        assert_eq!(highlights.as_array().map(Vec::len), Some(2));
        assert_eq!(highlights[0]["kind"], 1);
        assert_eq!(highlights[1]["kind"], 1);

        client_connection
            .sender
            .send(
                Request::new(
                    70.into(),
                    Completion::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 5}
                    }),
                )
                .into(),
            )
            .expect("completion request send succeeds");
        let completion_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("completion response arrives");
        let Message::Response(response) = completion_response else {
            panic!("expected completion response");
        };
        let completion = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("completion request failed: {}", error.message)
            }
        };
        assert_eq!(completion["isIncomplete"], false);
        assert_eq!(completion["items"].as_array().map(Vec::len), Some(1));
        assert_eq!(completion["items"][0]["label"], "value");
        assert_eq!(
            completion["items"][0]["textEdit"]["range"],
            serde_json::json!({
                "start": {"line": 1, "character": 0},
                "end": {"line": 1, "character": 5}
            })
        );
        assert_eq!(completion["items"][0]["textEdit"]["newText"], "value");

        client_connection
            .sender
            .send(
                Request::new(
                    8.into(),
                    PrepareRenameRequest::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 5}
                    }),
                )
                .into(),
            )
            .expect("prepare rename request send succeeds");
        let prepare_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("prepare rename response arrives");
        let Message::Response(response) = prepare_response else {
            panic!("expected prepare rename response");
        };
        let prepared = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("prepare rename request failed: {}", error.message)
            }
        };
        assert_eq!(prepared["placeholder"], "value");
        assert_eq!(
            prepared["range"],
            serde_json::json!({
                "start": {"line": 1, "character": 0},
                "end": {"line": 1, "character": 5}
            })
        );

        client_connection
            .sender
            .send(
                Request::new(
                    9.into(),
                    Rename::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 1},
                        "newName": "renamed"
                    }),
                )
                .into(),
            )
            .expect("rename request send succeeds");
        let rename_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("rename response arrives");
        let Message::Response(response) = rename_response else {
            panic!("expected rename response");
        };
        let rename = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("rename request failed: {}", error.message)
            }
        };
        assert!(rename.get("changes").is_none());
        assert_eq!(rename["documentChanges"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            rename["documentChanges"][0]["textDocument"],
            serde_json::json!({"uri": test_uri(), "version": 1})
        );
        assert_eq!(
            rename["documentChanges"][0]["edits"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            rename["documentChanges"][0]["edits"][0]["newText"],
            "renamed"
        );

        client_connection
            .sender
            .send(Request::new(10.into(), "shutdown".to_owned(), ()).into())
            .expect("shutdown send succeeds");
        let shutdown_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown response arrives");
        assert!(matches!(shutdown_response, Message::Response(_)));
        client_connection
            .sender
            .send(Notification::new("exit".to_owned(), ()).into())
            .expect("exit send succeeds");

        server_thread
            .join()
            .expect("server thread does not panic")
            .expect("server shuts down cleanly");
    }

    #[test]
    fn malformed_or_legacy_initialization_fails_closed_without_rename() {
        let (server_connection, client_connection) = Connection::memory();
        let server_thread = std::thread::spawn(move || run_connection(&server_connection));

        client_connection
            .sender
            .send(Request::new(1.into(), "initialize".to_owned(), serde_json::json!({})).into())
            .expect("malformed initialize send succeeds");
        let initialize_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("malformed initialize still receives a response");
        let Message::Response(response) = initialize_response else {
            panic!("expected initialize response");
        };
        let capabilities = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result["capabilities"].clone(),
            lsp_server::ResponseKind::Err { error } => {
                panic!("initialize failed: {}", error.message)
            }
        };
        assert!(capabilities.get("renameProvider").is_none());

        client_connection
            .sender
            .send(Notification::new(Initialized::METHOD.to_owned(), ()).into())
            .expect("initialized send succeeds");
        client_connection
            .sender
            .send(
                Request::new(
                    2.into(),
                    Rename::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 0, "character": 0},
                        "newName": "renamed"
                    }),
                )
                .into(),
            )
            .expect("unadvertised rename request send succeeds");
        let rename_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("unadvertised rename response arrives");
        let Message::Response(response) = rename_response else {
            panic!("expected rename response");
        };
        match response.response_kind {
            lsp_server::ResponseKind::Err { error } => {
                assert_eq!(error.code, ErrorCode::MethodNotFound as i32);
            }
            lsp_server::ResponseKind::Ok { result } => {
                panic!("unadvertised rename unexpectedly succeeded: {result}")
            }
        }

        client_connection
            .sender
            .send(Request::new(3.into(), "shutdown".to_owned(), ()).into())
            .expect("shutdown send succeeds");
        let shutdown_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown response arrives");
        assert!(matches!(shutdown_response, Message::Response(_)));
        client_connection
            .sender
            .send(Notification::new(Exit::METHOD.to_owned(), ()).into())
            .expect("exit send succeeds");
        server_thread
            .join()
            .expect("server thread does not panic")
            .expect("server shuts down cleanly");
    }

    #[test]
    fn rejects_exit_without_shutdown() {
        let (server_connection, client_connection) = Connection::memory();
        let server_thread = std::thread::spawn(move || run_connection(&server_connection));

        client_connection
            .sender
            .send(
                Request::new(
                    1.into(),
                    "initialize".to_owned(),
                    serde_json::json!({"capabilities": {}}),
                )
                .into(),
            )
            .expect("initialize send succeeds");
        let _initialize_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("initialize response arrives");
        client_connection
            .sender
            .send(Notification::new(Initialized::METHOD.to_owned(), ()).into())
            .expect("initialized send succeeds");
        client_connection
            .sender
            .send(Notification::new(Exit::METHOD.to_owned(), ()).into())
            .expect("exit send succeeds");

        assert!(server_thread
            .join()
            .expect("server thread does not panic")
            .is_err());
    }

    #[test]
    fn declares_utf16_position_encoding() {
        assert_eq!(
            server_capabilities(false).position_encoding,
            Some(PositionEncodingKind::UTF16)
        );
        assert!(server_capabilities(false).rename_provider.is_none());
        assert!(matches!(
            server_capabilities(true).rename_provider,
            Some(OneOf::Right(RenameOptions {
                prepare_provider: Some(true),
                ..
            }))
        ));
    }
}
