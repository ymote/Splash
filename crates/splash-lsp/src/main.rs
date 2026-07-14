#![forbid(unsafe_code)]

//! Stdio language server for the canonical Splash v0.1 source profile.
//!
//! The server only receives client-provided text and calls effect-free syntax,
//! formatting, and outline helpers. It never reads document URIs, evaluates
//! Splash code, creates a capability host, or loads an adapter.

use std::{collections::HashMap, error::Error, io, process::ExitCode};

use lsp_server::{Connection, ErrorCode, Message, Notification, Request, Response};
use lsp_types::{
    notification::{
        DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument, Exit,
        Notification as LspNotification, PublishDiagnostics,
    },
    request::{DocumentSymbolRequest, Formatting, Request as LspRequest},
    Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DocumentFormattingParams, DocumentSymbol, DocumentSymbolParams,
    DocumentSymbolResponse, OneOf, Position, PositionEncodingKind, PublishDiagnosticsParams, Range,
    ServerCapabilities, SymbolKind, TextDocumentItem, TextDocumentSyncCapability,
    TextDocumentSyncKind, TextEdit, Uri,
};
use splash_core::{
    check_syntax_named, format_source_named, top_level_declarations_named, ExecutionLimits,
    SyntaxDiagnostic, TopLevelDeclaration, TopLevelDeclarationKind, DEFAULT_MAX_SOURCE_BYTES,
    MAX_SYNTAX_DIAGNOSTICS,
};

const MAX_OPEN_DOCUMENTS: usize = 128;
const DIAGNOSTIC_SOURCE: &str = "splash";

type ServerResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Debug)]
struct DocumentState {
    source: Option<String>,
    version: i32,
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
    connection.initialize(serde_json::to_value(server_capabilities())?)?;

    let mut server = SplashLanguageServer::default();
    while let Ok(message) = connection.receiver.recv() {
        match message {
            Message::Request(request) => {
                if connection.handle_shutdown(&request)? {
                    return Ok(());
                }
                handle_request(connection, &server, request)?;
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

fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        position_encoding: Some(PositionEncodingKind::UTF16),
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        document_formatting_provider: Some(OneOf::Left(true)),
        document_symbol_provider: Some(OneOf::Left(true)),
        ..ServerCapabilities::default()
    }
}

fn handle_request(
    connection: &Connection,
    server: &SplashLanguageServer,
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
        let edits = server
            .format_document(&test_uri())
            .expect("original document remains available");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].new_text, "let value = 1\n");
    }

    #[test]
    fn oversized_document_can_recover_on_a_later_full_change() {
        let mut server = SplashLanguageServer::default();
        let oversized = "x".repeat(DEFAULT_MAX_SOURCE_BYTES + 1);
        let diagnostics = server.open_document(document(1, &oversized));
        assert_eq!(diagnostics.diagnostics.len(), 1);
        assert!(server.format_document(&test_uri()).is_err());
        assert!(server.document_symbols(&test_uri()).is_err());

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
    }

    #[test]
    fn announces_utf16_full_sync_formatting_and_symbols_over_stdio_protocol() {
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
                        text_document: document(1, "let value=1"),
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
        assert_eq!(edits[0]["newText"], "let value = 1\n");

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
            .send(Request::new(4.into(), "shutdown".to_owned(), ()).into())
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
            server_capabilities().position_encoding,
            Some(PositionEncodingKind::UTF16)
        );
    }
}
