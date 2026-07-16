//! A bounded, host-owned catalog of fixed HTTP JSON endpoints.
//!
//! A host selects every endpoint during setup and assigns it a canonical opaque
//! identifier. Splash can request only that identifier through a registered
//! JSON tool. It never supplies a URL, method, header, query parameter, or
//! redirect target. HTTPS is required by default; an explicitly named HTTP
//! constructor exists only for trusted local or development integrations.
//!
//! This is API-level network mediation, not operating-system egress
//! containment. The embedding process can still make unrelated network calls,
//! and hosts must run effectful adapters in a target-specific containment
//! backend when that boundary is required.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::io::Read;
use std::str::FromStr;
use std::time::Duration;

use serde_json::json;
use ureq::{http::Uri, Agent};

use crate::{
    JsonToolContract, JsonToolRequest, JsonValue, ToolDataFormat, ToolError, ToolPolicy,
    ToolRegistrationError,
};

/// Default number of endpoints a fixed HTTP catalog can retain.
pub const DEFAULT_MAX_HTTP_ENDPOINT_CATALOG_ENTRIES: usize = 32;
/// Absolute maximum number of endpoints a fixed HTTP catalog can retain.
pub const MAX_HTTP_ENDPOINT_CATALOG_ENTRIES: usize = 128;
/// Default maximum script-supplied JSON request bytes for one endpoint call.
pub const DEFAULT_MAX_HTTP_ENDPOINT_REQUEST_BYTES: usize = 16 * 1024;
/// Absolute maximum script-supplied JSON request bytes for one endpoint call.
pub const MAX_HTTP_ENDPOINT_REQUEST_BYTES: usize = 256 * 1024;
/// Default maximum accepted JSON response bytes before decoding.
pub const DEFAULT_MAX_HTTP_ENDPOINT_RESPONSE_BYTES: usize = 64 * 1024;
/// Absolute maximum accepted JSON response bytes before decoding.
pub const MAX_HTTP_ENDPOINT_RESPONSE_BYTES: usize = 1024 * 1024;
/// Default maximum accepted response-header bytes.
pub const DEFAULT_MAX_HTTP_ENDPOINT_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
/// Absolute maximum accepted response-header bytes.
pub const MAX_HTTP_ENDPOINT_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
/// Maximum UTF-8 byte length of an opaque endpoint identifier.
pub const MAX_HTTP_ENDPOINT_ID_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a fixed endpoint URL.
pub const MAX_HTTP_ENDPOINT_URL_BYTES: usize = 4 * 1024;
/// Default end-to-end request deadline, including DNS and response reading.
pub const DEFAULT_HTTP_ENDPOINT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Absolute maximum end-to-end request deadline.
pub const MAX_HTTP_ENDPOINT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Fixed method selected by the embedding host for one endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpEndpointMethod {
    /// A bodyless `GET` request.
    Get,
    /// A `POST` request containing one JSON object or array supplied by Splash.
    Post,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointTransport {
    Https,
    InsecureHttp,
}

/// One host-selected URL and method in a [`HttpEndpointCatalog`].
///
/// The URL has no script-facing accessor so a tool descriptor and ordinary
/// debug output cannot accidentally turn a catalog entry into a discovered
/// ambient network target.
pub struct HttpEndpoint {
    identifier: String,
    url: String,
    method: HttpEndpointMethod,
    transport: EndpointTransport,
}

impl HttpEndpoint {
    /// Creates an HTTPS endpoint. HTTPS URLs must have a host, no credentials,
    /// and no fragment; the path and query are fixed host configuration.
    pub fn https(
        identifier: impl Into<String>,
        method: HttpEndpointMethod,
        url: impl Into<String>,
    ) -> Result<Self, HttpEndpointCatalogError> {
        Self::new(
            identifier.into(),
            method,
            url.into(),
            EndpointTransport::Https,
        )
    }

    /// Creates an explicitly insecure HTTP endpoint.
    ///
    /// This constructor is intended only for trusted local or development
    /// services. It must not be used for credentials, private data, or a
    /// general production origin policy. It still fixes the complete URL and
    /// disables redirects and environment proxies at execution time.
    pub fn insecure_http(
        identifier: impl Into<String>,
        method: HttpEndpointMethod,
        url: impl Into<String>,
    ) -> Result<Self, HttpEndpointCatalogError> {
        Self::new(
            identifier.into(),
            method,
            url.into(),
            EndpointTransport::InsecureHttp,
        )
    }

    /// Returns the opaque catalog identifier selected by the host.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Returns the fixed request method selected by the host.
    pub const fn method(&self) -> HttpEndpointMethod {
        self.method
    }

    fn new(
        identifier: String,
        method: HttpEndpointMethod,
        url: String,
        transport: EndpointTransport,
    ) -> Result<Self, HttpEndpointCatalogError> {
        if !is_valid_identifier(&identifier) {
            return Err(HttpEndpointCatalogError::InvalidIdentifier);
        }
        validate_url(&url, transport)?;
        Ok(Self {
            identifier,
            url,
            method,
            transport,
        })
    }
}

impl fmt::Debug for HttpEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpEndpoint")
            .field("identifier", &self.identifier)
            .field("method", &self.method)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

/// Host-selected bounds for a [`HttpEndpointCatalog`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpEndpointCatalogLimits {
    /// Maximum retained fixed endpoints.
    pub max_entries: usize,
    /// Maximum script-supplied JSON request bytes for one endpoint call.
    pub max_request_bytes: usize,
    /// Maximum accepted JSON response bytes before parsing.
    pub max_response_bytes: usize,
    /// Maximum accepted response-header bytes.
    pub max_response_header_bytes: usize,
    /// End-to-end request deadline, including resolution and body reading.
    pub request_timeout: Duration,
}

impl HttpEndpointCatalogLimits {
    fn validate(self) -> Result<Self, HttpEndpointCatalogError> {
        if self.max_entries == 0 {
            return Err(HttpEndpointCatalogError::InvalidLimits(
                "max_entries must be greater than zero",
            ));
        }
        if self.max_entries > MAX_HTTP_ENDPOINT_CATALOG_ENTRIES {
            return Err(HttpEndpointCatalogError::InvalidLimits(
                "max_entries exceeds the hard limit",
            ));
        }
        if self.max_request_bytes == 0 {
            return Err(HttpEndpointCatalogError::InvalidLimits(
                "max_request_bytes must be greater than zero",
            ));
        }
        if self.max_request_bytes > MAX_HTTP_ENDPOINT_REQUEST_BYTES {
            return Err(HttpEndpointCatalogError::InvalidLimits(
                "max_request_bytes exceeds the hard limit",
            ));
        }
        if self.max_response_bytes == 0 {
            return Err(HttpEndpointCatalogError::InvalidLimits(
                "max_response_bytes must be greater than zero",
            ));
        }
        if self.max_response_bytes > MAX_HTTP_ENDPOINT_RESPONSE_BYTES {
            return Err(HttpEndpointCatalogError::InvalidLimits(
                "max_response_bytes exceeds the hard limit",
            ));
        }
        if self.max_response_header_bytes == 0 {
            return Err(HttpEndpointCatalogError::InvalidLimits(
                "max_response_header_bytes must be greater than zero",
            ));
        }
        if self.max_response_header_bytes > MAX_HTTP_ENDPOINT_RESPONSE_HEADER_BYTES {
            return Err(HttpEndpointCatalogError::InvalidLimits(
                "max_response_header_bytes exceeds the hard limit",
            ));
        }
        if self.request_timeout.is_zero() {
            return Err(HttpEndpointCatalogError::InvalidLimits(
                "request_timeout must be greater than zero",
            ));
        }
        if self.request_timeout > MAX_HTTP_ENDPOINT_REQUEST_TIMEOUT {
            return Err(HttpEndpointCatalogError::InvalidLimits(
                "request_timeout exceeds the hard limit",
            ));
        }
        Ok(self)
    }
}

impl Default for HttpEndpointCatalogLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_HTTP_ENDPOINT_CATALOG_ENTRIES,
            max_request_bytes: DEFAULT_MAX_HTTP_ENDPOINT_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_HTTP_ENDPOINT_RESPONSE_BYTES,
            max_response_header_bytes: DEFAULT_MAX_HTTP_ENDPOINT_RESPONSE_HEADER_BYTES,
            request_timeout: DEFAULT_HTTP_ENDPOINT_REQUEST_TIMEOUT,
        }
    }
}

/// Host-side error while configuring or invoking a fixed endpoint catalog.
///
/// Script-facing tool failures map these cases to generic denied or failed
/// messages so endpoint membership, URLs, remote status, and transport details
/// never appear in generated source diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpEndpointCatalogError {
    InvalidLimits(&'static str),
    InvalidIdentifier,
    InvalidUrl,
    UrlCredentialsNotAllowed,
    UrlFragmentNotAllowed,
    HttpsRequired,
    InsecureHttpRequired,
    DuplicateIdentifier,
    EntryLimitExceeded { maximum: usize },
    NotFound,
    InvalidRequest,
    MissingRequestBody,
    UnexpectedRequestBody,
    RequestTooLarge { maximum: usize },
    Transport,
    UnexpectedStatus { status: u16 },
    ResponseTooLarge { maximum: usize },
    InvalidResponseJson,
}

impl Display for HttpEndpointCatalogError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(message) => formatter.write_str(message),
            Self::InvalidIdentifier => formatter.write_str("invalid HTTP endpoint identifier"),
            Self::InvalidUrl => formatter.write_str("invalid HTTP endpoint URL"),
            Self::UrlCredentialsNotAllowed => {
                formatter.write_str("HTTP endpoint URLs must not contain credentials")
            }
            Self::UrlFragmentNotAllowed => {
                formatter.write_str("HTTP endpoint URLs must not contain fragments")
            }
            Self::HttpsRequired => formatter.write_str("HTTP endpoint URL must use HTTPS"),
            Self::InsecureHttpRequired => {
                formatter.write_str("insecure HTTP endpoints must use the HTTP scheme")
            }
            Self::DuplicateIdentifier => {
                formatter.write_str("HTTP endpoint identifier is already registered")
            }
            Self::EntryLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "HTTP endpoint catalog exceeds its maximum of {maximum} entries"
                )
            }
            Self::NotFound => formatter.write_str("HTTP endpoint is not registered"),
            Self::InvalidRequest => formatter.write_str("HTTP endpoint request is invalid"),
            Self::MissingRequestBody => {
                formatter.write_str("HTTP POST endpoint request requires a JSON body")
            }
            Self::UnexpectedRequestBody => {
                formatter.write_str("HTTP GET endpoint request must not contain a body")
            }
            Self::RequestTooLarge { maximum } => {
                write!(formatter, "HTTP endpoint request exceeds {maximum} bytes")
            }
            Self::Transport => formatter.write_str("HTTP endpoint request failed"),
            Self::UnexpectedStatus { status } => {
                write!(
                    formatter,
                    "HTTP endpoint returned unexpected status {status}"
                )
            }
            Self::ResponseTooLarge { maximum } => {
                write!(formatter, "HTTP endpoint response exceeds {maximum} bytes")
            }
            Self::InvalidResponseJson => {
                formatter.write_str("HTTP endpoint response is not a JSON object or array")
            }
        }
    }
}

impl std::error::Error for HttpEndpointCatalogError {}

/// A setup-only catalog of fixed JSON HTTP endpoints selected by the host.
///
/// The catalog has no URL lookup API. Each entry retains only a host-selected
/// opaque identifier, method, and fixed URL. Consuming it through
/// `register_http_endpoint_catalog_tool` seals the endpoint set into one
/// JSON-tool handler.
pub struct HttpEndpointCatalog {
    limits: HttpEndpointCatalogLimits,
    entries: BTreeMap<String, HttpEndpoint>,
}

impl HttpEndpointCatalog {
    /// Creates an empty endpoint catalog with explicit request and response
    /// bounds.
    pub fn new(limits: HttpEndpointCatalogLimits) -> Result<Self, HttpEndpointCatalogError> {
        Ok(Self {
            limits: limits.validate()?,
            entries: BTreeMap::new(),
        })
    }

    /// Returns the immutable bounds selected while configuring the catalog.
    pub const fn limits(&self) -> HttpEndpointCatalogLimits {
        self.limits
    }

    /// Returns how many fixed endpoints the catalog currently retains.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the catalog contains no endpoints.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds one already validated host-selected endpoint.
    pub fn insert(&mut self, endpoint: HttpEndpoint) -> Result<(), HttpEndpointCatalogError> {
        if self.entries.contains_key(endpoint.identifier()) {
            return Err(HttpEndpointCatalogError::DuplicateIdentifier);
        }
        if self.entries.len() >= self.limits.max_entries {
            return Err(HttpEndpointCatalogError::EntryLimitExceeded {
                maximum: self.limits.max_entries,
            });
        }
        self.entries.insert(endpoint.identifier.clone(), endpoint);
        Ok(())
    }

    pub(crate) fn validate_tool_policy(
        &self,
        policy: &ToolPolicy,
    ) -> Result<(), ToolRegistrationError> {
        if policy.data_format != ToolDataFormat::Json {
            return Err(ToolRegistrationError::InvalidPolicy(
                "HTTP endpoint catalog tools require a JSON policy",
            ));
        }
        if policy.max_input_bytes > self.limits.max_request_bytes {
            return Err(ToolRegistrationError::InvalidPolicy(
                "HTTP endpoint catalog input limit exceeds its request limit",
            ));
        }
        if self.entries.is_empty() {
            return Err(ToolRegistrationError::InvalidPolicy(
                "HTTP endpoint catalog must contain at least one endpoint",
            ));
        }
        if policy.max_output_bytes < 2 {
            return Err(ToolRegistrationError::InvalidPolicy(
                "HTTP endpoint catalog output limit must allow a JSON envelope",
            ));
        }
        for endpoint in self.entries.values() {
            let minimum_request = match endpoint.method {
                HttpEndpointMethod::Get => json!({"endpoint": endpoint.identifier()}),
                HttpEndpointMethod::Post => {
                    json!({"endpoint": endpoint.identifier(), "body": {}})
                }
            };
            let minimum_bytes = serde_json::to_vec(&minimum_request)
                .map_err(|_| ToolRegistrationError::InvalidPolicy("HTTP request is invalid"))?
                .len();
            if minimum_bytes > policy.max_input_bytes {
                return Err(ToolRegistrationError::InvalidPolicy(
                    "HTTP endpoint identifier exceeds the tool input limit",
                ));
            }
        }
        Ok(())
    }

    /// Builds the executable structural contract published with this catalog
    /// tool. The exact allowed opaque identifiers are host-facing metadata,
    /// never a script-visible discovery API.
    pub(crate) fn tool_contract(&self) -> Result<JsonToolContract, ToolRegistrationError> {
        let identifiers: Vec<JsonValue> = self
            .entries
            .keys()
            .cloned()
            .map(JsonValue::String)
            .collect();
        JsonToolContract::new(
            json!({
                "type": "object",
                "properties": {
                    "endpoint": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_HTTP_ENDPOINT_ID_BYTES,
                        "enum": identifiers
                    },
                    "body": {}
                },
                "required": ["endpoint"],
                "additionalProperties": false
            }),
            json!({}),
        )
        .map_err(|_| {
            ToolRegistrationError::InvalidPolicy("HTTP endpoint catalog contract is invalid")
        })
    }

    pub(crate) fn into_tool_handler(
        self,
        max_output_bytes: usize,
    ) -> impl FnMut(&JsonToolRequest) -> Result<JsonValue, ToolError> + 'static {
        let agents = HttpEndpointAgents::new(self.limits);
        let max_request_bytes = self.limits.max_request_bytes;
        let max_response_bytes = self.limits.max_response_bytes.min(max_output_bytes);
        move |request| {
            self.execute(&agents, request, max_request_bytes, max_response_bytes)
                .map_err(HttpEndpointCatalogError::into_tool_error)
        }
    }

    fn execute(
        &self,
        agents: &HttpEndpointAgents,
        request: &JsonToolRequest,
        max_request_bytes: usize,
        max_response_bytes: usize,
    ) -> Result<JsonValue, HttpEndpointCatalogError> {
        let object = request
            .input
            .as_object()
            .ok_or(HttpEndpointCatalogError::InvalidRequest)?;
        if object.keys().any(|key| key != "endpoint" && key != "body") {
            return Err(HttpEndpointCatalogError::InvalidRequest);
        }
        let identifier = object
            .get("endpoint")
            .and_then(JsonValue::as_str)
            .filter(|identifier| is_valid_identifier(identifier))
            .ok_or(HttpEndpointCatalogError::InvalidRequest)?;
        let endpoint = self
            .entries
            .get(identifier)
            .ok_or(HttpEndpointCatalogError::NotFound)?;
        let body = object.get("body");
        let encoded_body = match endpoint.method {
            HttpEndpointMethod::Get => {
                if body.is_some() {
                    return Err(HttpEndpointCatalogError::UnexpectedRequestBody);
                }
                None
            }
            HttpEndpointMethod::Post => {
                let body = body.ok_or(HttpEndpointCatalogError::MissingRequestBody)?;
                if !body.is_object() && !body.is_array() {
                    return Err(HttpEndpointCatalogError::InvalidRequest);
                }
                Some(
                    serde_json::to_vec(body)
                        .map_err(|_| HttpEndpointCatalogError::InvalidRequest)?,
                )
            }
        };
        if encoded_body
            .as_ref()
            .is_some_and(|body| body.len() > max_request_bytes)
        {
            return Err(HttpEndpointCatalogError::RequestTooLarge {
                maximum: max_request_bytes,
            });
        }

        let mut response = match (endpoint.method, encoded_body) {
            (HttpEndpointMethod::Get, None) => {
                agents.for_endpoint(endpoint).get(&endpoint.url).call()
            }
            (HttpEndpointMethod::Post, Some(body)) => agents
                .for_endpoint(endpoint)
                .post(&endpoint.url)
                .header("Content-Type", "application/json")
                .send(body),
            _ => return Err(HttpEndpointCatalogError::InvalidRequest),
        }
        .map_err(|_| HttpEndpointCatalogError::Transport)?;

        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(HttpEndpointCatalogError::UnexpectedStatus { status });
        }
        if let Some(content_length) = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
        {
            if content_length > max_response_bytes {
                return Err(HttpEndpointCatalogError::ResponseTooLarge {
                    maximum: max_response_bytes,
                });
            }
        }

        let mut bytes = Vec::with_capacity(max_response_bytes.min(8 * 1024).saturating_add(1));
        let limit = u64::try_from(max_response_bytes.saturating_add(1))
            .expect("bounded HTTP response limit fits into u64");
        response
            .body_mut()
            .as_reader()
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| HttpEndpointCatalogError::Transport)?;
        if bytes.len() > max_response_bytes {
            return Err(HttpEndpointCatalogError::ResponseTooLarge {
                maximum: max_response_bytes,
            });
        }
        let output = serde_json::from_slice::<JsonValue>(&bytes)
            .map_err(|_| HttpEndpointCatalogError::InvalidResponseJson)?;
        if !output.is_object() && !output.is_array() {
            return Err(HttpEndpointCatalogError::InvalidResponseJson);
        }
        let output_bytes = serde_json::to_vec(&output)
            .map_err(|_| HttpEndpointCatalogError::InvalidResponseJson)?
            .len();
        if output_bytes > max_response_bytes {
            return Err(HttpEndpointCatalogError::ResponseTooLarge {
                maximum: max_response_bytes,
            });
        }
        Ok(output)
    }
}

impl Default for HttpEndpointCatalog {
    fn default() -> Self {
        Self::new(HttpEndpointCatalogLimits::default())
            .expect("default HTTP endpoint catalog limits are valid")
    }
}

struct HttpEndpointAgents {
    https: Agent,
    insecure_http: Agent,
}

impl HttpEndpointAgents {
    fn new(limits: HttpEndpointCatalogLimits) -> Self {
        Self {
            https: build_agent(limits, true),
            insecure_http: build_agent(limits, false),
        }
    }

    fn for_endpoint(&self, endpoint: &HttpEndpoint) -> &Agent {
        match endpoint.transport {
            EndpointTransport::Https => &self.https,
            EndpointTransport::InsecureHttp => &self.insecure_http,
        }
    }
}

fn build_agent(limits: HttpEndpointCatalogLimits, https_only: bool) -> Agent {
    Agent::config_builder()
        .https_only(https_only)
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(limits.request_timeout))
        .max_response_header_size(limits.max_response_header_bytes)
        .input_buffer_size(limits.max_response_header_bytes)
        .output_buffer_size(limits.max_response_header_bytes)
        .user_agent("")
        .accept("application/json")
        .accept_encoding("")
        .build()
        .into()
}

fn validate_url(url: &str, transport: EndpointTransport) -> Result<(), HttpEndpointCatalogError> {
    if url.is_empty() || url.len() > MAX_HTTP_ENDPOINT_URL_BYTES {
        return Err(HttpEndpointCatalogError::InvalidUrl);
    }
    if url.contains('#') {
        return Err(HttpEndpointCatalogError::UrlFragmentNotAllowed);
    }
    let uri = Uri::from_str(url).map_err(|_| HttpEndpointCatalogError::InvalidUrl)?;
    let scheme = uri
        .scheme_str()
        .ok_or(HttpEndpointCatalogError::InvalidUrl)?;
    let authority = uri
        .authority()
        .ok_or(HttpEndpointCatalogError::InvalidUrl)?;
    if authority.as_str().contains('@') {
        return Err(HttpEndpointCatalogError::UrlCredentialsNotAllowed);
    }
    match transport {
        EndpointTransport::Https if scheme == "https" => Ok(()),
        EndpointTransport::Https => Err(HttpEndpointCatalogError::HttpsRequired),
        EndpointTransport::InsecureHttp if scheme == "http" => Ok(()),
        EndpointTransport::InsecureHttp => Err(HttpEndpointCatalogError::InsecureHttpRequired),
    }
}

fn is_valid_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.len() <= MAX_HTTP_ENDPOINT_ID_BYTES
        && identifier
            .bytes()
            .enumerate()
            .all(|(index, byte)| match byte {
                b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' => index != 0 || byte != b'.',
                _ => false,
            })
}

impl HttpEndpointCatalogError {
    fn into_tool_error(self) -> ToolError {
        match self {
            Self::InvalidIdentifier
            | Self::NotFound
            | Self::InvalidRequest
            | Self::MissingRequestBody
            | Self::UnexpectedRequestBody
            | Self::RequestTooLarge { .. } => {
                ToolError::Denied("HTTP endpoint access was denied".to_owned())
            }
            _ => ToolError::Failed("HTTP endpoint request failed".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::{self, Receiver};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use super::*;
    use crate::{AuditOutcome, CapabilityRuntime, ToolMetadata};

    fn start_http_server(
        status: &'static str,
        response_body: &'static [u8],
    ) -> (String, Receiver<String>, JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener binds");
        let address = listener.local_addr().expect("listener has an address");
        let (sender, receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("catalog reaches local server");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("server read timeout is configured");
            let request = read_http_request(&mut stream);
            sender.send(request).expect("test receives request");
            let header = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            stream
                .write_all(header.as_bytes())
                .expect("server writes response header");
            stream
                .write_all(response_body)
                .expect("server writes response body");
        });
        (
            format!("http://{address}/fixed/path?mode=reviewed"),
            receiver,
            thread,
        )
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        let mut expected_total = None;
        while bytes.len() < 16 * 1024 {
            let read = stream.read(&mut buffer).expect("server reads request");
            assert!(read > 0, "client closed request before complete headers");
            bytes.extend_from_slice(&buffer[..read]);
            if expected_total.is_none() {
                if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let headers = std::str::from_utf8(&bytes[..header_end])
                        .expect("request headers are UTF-8");
                    let content_length = headers
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                        .unwrap_or_default();
                    expected_total = Some(header_end + 4 + content_length);
                }
            }
            if expected_total.is_some_and(|expected| bytes.len() >= expected) {
                break;
            }
        }
        String::from_utf8(bytes).expect("request bytes are UTF-8")
    }

    #[test]
    fn rejects_invalid_endpoint_configuration_and_growth() {
        assert!(matches!(
            HttpEndpointCatalog::new(HttpEndpointCatalogLimits {
                max_entries: 0,
                ..HttpEndpointCatalogLimits::default()
            }),
            Err(HttpEndpointCatalogError::InvalidLimits(_))
        ));
        assert!(matches!(
            HttpEndpointCatalog::new(HttpEndpointCatalogLimits {
                max_request_bytes: 0,
                ..HttpEndpointCatalogLimits::default()
            }),
            Err(HttpEndpointCatalogError::InvalidLimits(_))
        ));
        assert!(matches!(
            HttpEndpointCatalog::new(HttpEndpointCatalogLimits {
                max_request_bytes: MAX_HTTP_ENDPOINT_REQUEST_BYTES + 1,
                ..HttpEndpointCatalogLimits::default()
            }),
            Err(HttpEndpointCatalogError::InvalidLimits(_))
        ));
        assert!(matches!(
            HttpEndpoint::https("bad/id", HttpEndpointMethod::Get, "https://example.test"),
            Err(HttpEndpointCatalogError::InvalidIdentifier)
        ));
        assert!(matches!(
            HttpEndpoint::https("endpoint", HttpEndpointMethod::Get, "http://example.test"),
            Err(HttpEndpointCatalogError::HttpsRequired)
        ));
        assert!(matches!(
            HttpEndpoint::insecure_http(
                "endpoint",
                HttpEndpointMethod::Get,
                "https://example.test"
            ),
            Err(HttpEndpointCatalogError::InsecureHttpRequired)
        ));
        assert!(matches!(
            HttpEndpoint::https(
                "endpoint",
                HttpEndpointMethod::Get,
                "https://operator:secret@example.test"
            ),
            Err(HttpEndpointCatalogError::UrlCredentialsNotAllowed)
        ));
        assert!(matches!(
            HttpEndpoint::https(
                "endpoint",
                HttpEndpointMethod::Get,
                "https://example.test/path#fragment"
            ),
            Err(HttpEndpointCatalogError::UrlFragmentNotAllowed)
        ));

        let mut catalog = HttpEndpointCatalog::new(HttpEndpointCatalogLimits {
            max_entries: 1,
            ..HttpEndpointCatalogLimits::default()
        })
        .unwrap();
        catalog
            .insert(
                HttpEndpoint::https("first", HttpEndpointMethod::Get, "https://one.test").unwrap(),
            )
            .unwrap();
        assert!(matches!(
            catalog.insert(
                HttpEndpoint::https("second", HttpEndpointMethod::Get, "https://two.test").unwrap()
            ),
            Err(HttpEndpointCatalogError::EntryLimitExceeded { maximum: 1 })
        ));

        let mut policy_catalog = HttpEndpointCatalog::default();
        policy_catalog
            .insert(
                HttpEndpoint::https("status", HttpEndpointMethod::Get, "https://status.test")
                    .unwrap(),
            )
            .unwrap();
        let mut broad_policy = ToolPolicy::json("net.status");
        broad_policy.max_input_bytes = DEFAULT_MAX_HTTP_ENDPOINT_REQUEST_BYTES + 1;
        let registration_error = CapabilityRuntime::default()
            .register_http_endpoint_catalog_tool(
                broad_policy,
                ToolMetadata::new("Gets one reviewed endpoint status."),
                policy_catalog,
            )
            .expect_err("the catalog request bound is not widened by a tool policy");
        assert_eq!(
            registration_error,
            ToolRegistrationError::InvalidPolicy(
                "HTTP endpoint catalog input limit exceeds its request limit"
            )
        );
    }

    #[test]
    fn publishes_an_executable_opaque_request_contract() {
        let mut catalog = HttpEndpointCatalog::default();
        catalog
            .insert(
                HttpEndpoint::https(
                    "status",
                    HttpEndpointMethod::Get,
                    "https://api.example.test/v1/status?fixed=true",
                )
                .unwrap(),
            )
            .unwrap();

        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_http_endpoint_catalog_tool(
                ToolPolicy::json("net.status"),
                ToolMetadata::new("Gets one reviewed endpoint status."),
                catalog,
            )
            .unwrap();

        let descriptor = runtime
            .tool_catalog()
            .into_iter()
            .next()
            .expect("catalog publishes one tool");
        assert!(descriptor.contract_enforced);
        let input_schema = descriptor
            .metadata
            .input_schema
            .expect("request schema is published");
        assert_eq!(
            input_schema["properties"]["endpoint"]["enum"],
            json!(["status"])
        );
        assert_eq!(input_schema["additionalProperties"], JsonValue::Bool(false));
        assert_eq!(descriptor.metadata.output_schema, Some(json!({})));
        let published = serde_json::to_string(&input_schema).expect("schema serializes");
        assert!(!published.contains("api.example.test"));
        assert!(!published.contains("/v1/status"));
    }

    #[test]
    fn executes_only_a_fixed_post_endpoint_and_returns_json() {
        let (url, received, server) = start_http_server("200 OK", br#"{"accepted":true}"#);
        let mut catalog = HttpEndpointCatalog::default();
        catalog
            .insert(HttpEndpoint::insecure_http("submit", HttpEndpointMethod::Post, url).unwrap())
            .unwrap();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_http_endpoint_catalog_tool(
                ToolPolicy::json("net.request"),
                ToolMetadata::new("Posts reviewed JSON to one host-selected endpoint."),
                catalog,
            )
            .unwrap();

        let report = runtime
            .eval(
                "use mod.tool\n\
                 use mod.std.assert\n\
                 let raw = tool.call_json(\"net.request\", {endpoint: \"submit\", body: {value: 42}})\n\
                 let response = raw.parse_json()\n\
                 assert(response.accepted == true)",
            )
            .unwrap();

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
        let request = received
            .recv_timeout(Duration::from_secs(2))
            .expect("one fixed request reaches the server");
        server.join().expect("server completes");
        assert!(request.starts_with("POST /fixed/path?mode=reviewed HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains("content-type: application/json\r\n"));
        assert!(request.ends_with("{\"value\":42}"));
        let lower = request.to_ascii_lowercase();
        assert!(!lower.contains("authorization:"));
        assert!(!lower.contains("cookie:"));
    }

    #[test]
    fn rejects_script_selected_urls_and_redacts_endpoint_failures() {
        let mut catalog = HttpEndpointCatalog::default();
        catalog
            .insert(
                HttpEndpoint::https("approved", HttpEndpointMethod::Get, "https://example.test")
                    .unwrap(),
            )
            .unwrap();
        let mut handler = catalog.into_tool_handler(64);
        let error = handler(&JsonToolRequest {
            name: "net.request".to_owned(),
            input: json!({"endpoint": "approved", "url": "https://not-approved.test"}),
            call_index: 1,
        })
        .unwrap_err();
        assert_eq!(
            error,
            ToolError::Denied("HTTP endpoint access was denied".to_owned())
        );
        assert!(!error.to_string().contains("not-approved"));
    }

    #[test]
    fn redacts_contract_rejections_before_the_http_handler_runs() {
        let mut catalog = HttpEndpointCatalog::default();
        catalog
            .insert(
                HttpEndpoint::https("approved", HttpEndpointMethod::Get, "https://example.test")
                    .unwrap(),
            )
            .unwrap();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_http_endpoint_catalog_tool(
                ToolPolicy::json("net.request"),
                ToolMetadata::new("Gets one reviewed endpoint."),
                catalog,
            )
            .unwrap();

        let report = runtime
            .eval(
                "use mod.tool\n\
                 tool.call_json(\"net.request\", {endpoint: \"approved\", url: \"https://not-approved.test\"})",
            )
            .unwrap();

        assert!(!report.succeeded());
        let diagnostics = format!("{:?}", report.diagnostics);
        assert!(diagnostics.contains("HTTP endpoint access was denied"));
        assert!(!diagnostics.contains("not-approved"));
        assert!(!diagnostics.contains("schema"));
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn rejects_an_oversized_post_body_before_transport() {
        let mut catalog = HttpEndpointCatalog::new(HttpEndpointCatalogLimits {
            max_request_bytes: 16,
            ..HttpEndpointCatalogLimits::default()
        })
        .unwrap();
        catalog
            .insert(
                HttpEndpoint::https("submit", HttpEndpointMethod::Post, "https://example.test")
                    .unwrap(),
            )
            .unwrap();
        let mut handler = catalog.into_tool_handler(64);
        let error = handler(&JsonToolRequest {
            name: "net.request".to_owned(),
            input: json!({"endpoint": "submit", "body": {"value": "0123456789"}}),
            call_index: 1,
        })
        .unwrap_err();
        assert_eq!(
            error,
            ToolError::Denied("HTTP endpoint access was denied".to_owned())
        );
    }

    #[test]
    fn rejects_redirects_and_oversized_or_non_json_responses_without_details() {
        let (redirect_url, received, redirect_server) =
            start_http_server("302 Found", br#"{"next":"http://not-approved.test"}"#);
        let mut redirect_catalog = HttpEndpointCatalog::default();
        redirect_catalog
            .insert(
                HttpEndpoint::insecure_http("redirect", HttpEndpointMethod::Get, redirect_url)
                    .unwrap(),
            )
            .unwrap();
        let mut redirect_handler = redirect_catalog.into_tool_handler(64);
        let redirect_error = redirect_handler(&JsonToolRequest {
            name: "net.request".to_owned(),
            input: json!({"endpoint": "redirect"}),
            call_index: 1,
        })
        .unwrap_err();
        received
            .recv_timeout(Duration::from_secs(2))
            .expect("redirect response receives exactly one request");
        redirect_server.join().expect("redirect server completes");
        assert_eq!(
            redirect_error,
            ToolError::Failed("HTTP endpoint request failed".to_owned())
        );
        assert!(!redirect_error.to_string().contains("not-approved"));

        let (scalar_url, scalar_received, scalar_server) = start_http_server("200 OK", b"true");
        let mut scalar_catalog = HttpEndpointCatalog::default();
        scalar_catalog
            .insert(
                HttpEndpoint::insecure_http("scalar", HttpEndpointMethod::Get, scalar_url).unwrap(),
            )
            .unwrap();
        let mut scalar_handler = scalar_catalog.into_tool_handler(64);
        let scalar_error = scalar_handler(&JsonToolRequest {
            name: "net.request".to_owned(),
            input: json!({"endpoint": "scalar"}),
            call_index: 1,
        })
        .unwrap_err();
        scalar_received
            .recv_timeout(Duration::from_secs(2))
            .expect("scalar response receives one request");
        scalar_server.join().expect("scalar server completes");
        assert_eq!(
            scalar_error,
            ToolError::Failed("HTTP endpoint request failed".to_owned())
        );

        let (large_url, large_received, large_server) = start_http_server(
            "200 OK",
            b"{\"payload\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}",
        );
        let mut large_catalog = HttpEndpointCatalog::default();
        large_catalog
            .insert(
                HttpEndpoint::insecure_http("large", HttpEndpointMethod::Get, large_url).unwrap(),
            )
            .unwrap();
        let mut large_handler = large_catalog.into_tool_handler(64);
        let large_error = large_handler(&JsonToolRequest {
            name: "net.request".to_owned(),
            input: json!({"endpoint": "large"}),
            call_index: 1,
        })
        .unwrap_err();
        large_received
            .recv_timeout(Duration::from_secs(2))
            .expect("large response receives one request");
        large_server.join().expect("large server completes");
        assert_eq!(
            large_error,
            ToolError::Failed("HTTP endpoint request failed".to_owned())
        );
    }
}
