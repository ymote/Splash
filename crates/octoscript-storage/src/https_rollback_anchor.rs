//! Fixed HTTPS transport for a trusted rollback-anchor service.
//!
//! [`HttpsRollbackAnchorTransport`](crate::https_rollback_anchor::HttpsRollbackAnchorTransport)
//! is transport only. It pins one complete
//! host-configured HTTPS endpoint in process configuration, disables proxies
//! and redirects, and bounds JSON exchange. The endpoint's service must still
//! independently provide durable rollback-resistant compare-and-swap state for
//! [`crate::rollback_anchor_service::TrustedServiceRollbackAnchor`] to satisfy
//! the [`crate::RollbackAnchor`] contract.

use std::fmt::{self, Display, Formatter};
use std::io::Read;
use std::str::FromStr;
use std::time::Duration;

use ureq::http::{HeaderValue, Uri};
use ureq::Agent;
use zeroize::Zeroizing;

use crate::rollback_anchor_service::{
    RollbackAnchorServiceTransport, TrustedServiceRollbackAnchor,
    MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES, MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES,
};

/// Maximum fixed endpoint URL size for the HTTPS rollback-anchor transport.
pub const MAX_HTTPS_ROLLBACK_ANCHOR_ENDPOINT_BYTES: usize = 4 * 1024;
/// Maximum accepted response-header bytes for the HTTPS rollback-anchor transport.
pub const MAX_HTTPS_ROLLBACK_ANCHOR_RESPONSE_HEADER_BYTES: usize = 8 * 1024;
/// Default whole-request timeout for one HTTPS rollback-anchor exchange.
pub const DEFAULT_HTTPS_ROLLBACK_ANCHOR_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum bearer-token bytes retained in one transport configuration.
pub const MAX_HTTPS_ROLLBACK_ANCHOR_BEARER_TOKEN_BYTES: usize = 4 * 1024;

/// A convenient trusted-service anchor type backed by fixed HTTPS transport.
pub type HttpsRollbackAnchor = TrustedServiceRollbackAnchor<HttpsRollbackAnchorTransport>;

/// One host-provisioned bearer token for an HTTPS rollback-anchor service.
///
/// The token is not exposed through an accessor, `Display`, or `Debug`. It is
/// materialized as a sensitive HTTP header only for the duration of an exact
/// fixed endpoint request.
pub struct HttpsRollbackAnchorAuthorization(Zeroizing<String>);

impl HttpsRollbackAnchorAuthorization {
    /// Creates one bounded bearer-token configuration.
    pub fn bearer(token: impl Into<String>) -> Result<Self, HttpsRollbackAnchorConfigurationError> {
        let token = token.into();
        if !is_valid_bearer_token(&token) {
            return Err(HttpsRollbackAnchorConfigurationError::InvalidBearerToken);
        }
        Ok(Self(Zeroizing::new(token)))
    }

    fn header_value(&self) -> HeaderValue {
        let value = Zeroizing::new(format!("Bearer {}", self.0.as_str()));
        let mut header = HeaderValue::from_str(&value)
            .expect("a validated bearer token always produces a valid header value");
        header.set_sensitive(true);
        header
    }
}

impl fmt::Debug for HttpsRollbackAnchorAuthorization {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpsRollbackAnchorAuthorization(REDACTED)")
    }
}

/// Fixed HTTPS transport for exactly one host-owned anchor-service endpoint.
pub struct HttpsRollbackAnchorTransport {
    agent: Agent,
    endpoint: String,
    authorization: Option<HttpsRollbackAnchorAuthorization>,
}

impl HttpsRollbackAnchorTransport {
    /// Creates a transport with the default bounded request timeout.
    pub fn new(
        endpoint: impl Into<String>,
        authorization: Option<HttpsRollbackAnchorAuthorization>,
    ) -> Result<Self, HttpsRollbackAnchorConfigurationError> {
        Self::with_timeout(
            endpoint,
            authorization,
            DEFAULT_HTTPS_ROLLBACK_ANCHOR_TIMEOUT,
        )
    }

    /// Creates a transport with one explicit nonzero whole-request timeout.
    pub fn with_timeout(
        endpoint: impl Into<String>,
        authorization: Option<HttpsRollbackAnchorAuthorization>,
        request_timeout: Duration,
    ) -> Result<Self, HttpsRollbackAnchorConfigurationError> {
        if request_timeout.is_zero() {
            return Err(HttpsRollbackAnchorConfigurationError::ZeroRequestTimeout);
        }
        let endpoint = endpoint.into();
        validate_endpoint(&endpoint)?;
        Ok(Self {
            agent: build_agent(request_timeout),
            endpoint,
            authorization,
        })
    }
}

impl fmt::Debug for HttpsRollbackAnchorTransport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpsRollbackAnchorTransport")
            .field("authorization_configured", &self.authorization.is_some())
            .finish_non_exhaustive()
    }
}

impl RollbackAnchorServiceTransport for HttpsRollbackAnchorTransport {
    type Error = HttpsRollbackAnchorTransportError;

    fn exchange(
        &mut self,
        request: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        if request.len() > MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES {
            return Err(HttpsRollbackAnchorTransportError::RequestTooLarge {
                maximum: MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES,
            });
        }
        if maximum_response_bytes == 0
            || maximum_response_bytes > MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES
        {
            return Err(HttpsRollbackAnchorTransportError::InvalidResponseLimit);
        }

        let request_builder = self
            .agent
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .header("Cache-Control", "no-store")
            .header("Pragma", "no-cache");
        let mut response = match &self.authorization {
            Some(authorization) => request_builder
                .header("Authorization", authorization.header_value())
                .send(request),
            None => request_builder.send(request),
        }
        .map_err(|_| HttpsRollbackAnchorTransportError::Transport)?;

        if !(200..300).contains(&response.status().as_u16()) {
            return Err(HttpsRollbackAnchorTransportError::UnexpectedStatus);
        }
        if !response_content_type_is_json(&response) {
            return Err(HttpsRollbackAnchorTransportError::InvalidContentType);
        }
        if let Some(content_length) = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
        {
            if content_length > maximum_response_bytes {
                return Err(HttpsRollbackAnchorTransportError::ResponseTooLarge {
                    maximum: maximum_response_bytes,
                });
            }
        }

        let mut bytes = Vec::with_capacity(maximum_response_bytes.min(1024).saturating_add(1));
        let limit = u64::try_from(maximum_response_bytes.saturating_add(1))
            .expect("fixed rollback-anchor response bound fits into u64");
        response
            .body_mut()
            .as_reader()
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|_| HttpsRollbackAnchorTransportError::Transport)?;
        if bytes.len() > maximum_response_bytes {
            return Err(HttpsRollbackAnchorTransportError::ResponseTooLarge {
                maximum: maximum_response_bytes,
            });
        }
        Ok(bytes)
    }
}

/// Invalid fixed HTTPS rollback-anchor transport configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsRollbackAnchorConfigurationError {
    InvalidEndpoint,
    HttpsRequired,
    UrlCredentialsNotAllowed,
    UrlFragmentNotAllowed,
    ZeroRequestTimeout,
    InvalidBearerToken,
}

impl Display for HttpsRollbackAnchorConfigurationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => {
                formatter.write_str("rollback-anchor HTTPS endpoint is invalid")
            }
            Self::HttpsRequired => {
                formatter.write_str("rollback-anchor transport requires a fixed HTTPS endpoint")
            }
            Self::UrlCredentialsNotAllowed => {
                formatter.write_str("rollback-anchor endpoint must not contain URL credentials")
            }
            Self::UrlFragmentNotAllowed => {
                formatter.write_str("rollback-anchor endpoint must not contain a URL fragment")
            }
            Self::ZeroRequestTimeout => {
                formatter.write_str("rollback-anchor HTTPS request timeout must be nonzero")
            }
            Self::InvalidBearerToken => {
                formatter.write_str("rollback-anchor bearer token is invalid")
            }
        }
    }
}

impl std::error::Error for HttpsRollbackAnchorConfigurationError {}

/// Failure while exchanging one HTTPS rollback-anchor service request.
///
/// This error deliberately omits the endpoint, response body, status details,
/// and authorization value from both `Display` and `Debug`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsRollbackAnchorTransportError {
    RequestTooLarge { maximum: usize },
    InvalidResponseLimit,
    Transport,
    UnexpectedStatus,
    InvalidContentType,
    ResponseTooLarge { maximum: usize },
}

impl Display for HttpsRollbackAnchorTransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestTooLarge { maximum } => write!(
                formatter,
                "rollback-anchor HTTPS request exceeds the {maximum}-byte limit"
            ),
            Self::InvalidResponseLimit => {
                formatter.write_str("rollback-anchor HTTPS response limit is invalid")
            }
            Self::Transport => formatter.write_str("rollback-anchor HTTPS transport failed"),
            Self::UnexpectedStatus => {
                formatter.write_str("rollback-anchor HTTPS service returned an unexpected status")
            }
            Self::InvalidContentType => {
                formatter.write_str("rollback-anchor HTTPS service response is not JSON content")
            }
            Self::ResponseTooLarge { maximum } => write!(
                formatter,
                "rollback-anchor HTTPS response exceeds the {maximum}-byte limit"
            ),
        }
    }
}

impl std::error::Error for HttpsRollbackAnchorTransportError {}

fn build_agent(request_timeout: Duration) -> Agent {
    Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(request_timeout))
        .max_response_header_size(MAX_HTTPS_ROLLBACK_ANCHOR_RESPONSE_HEADER_BYTES)
        .input_buffer_size(MAX_HTTPS_ROLLBACK_ANCHOR_RESPONSE_HEADER_BYTES)
        .output_buffer_size(MAX_HTTPS_ROLLBACK_ANCHOR_RESPONSE_HEADER_BYTES)
        .user_agent("")
        .accept("application/json")
        .accept_encoding("")
        .build()
        .into()
}

fn validate_endpoint(endpoint: &str) -> Result<(), HttpsRollbackAnchorConfigurationError> {
    if endpoint.is_empty() || endpoint.len() > MAX_HTTPS_ROLLBACK_ANCHOR_ENDPOINT_BYTES {
        return Err(HttpsRollbackAnchorConfigurationError::InvalidEndpoint);
    }
    if endpoint.contains('#') {
        return Err(HttpsRollbackAnchorConfigurationError::UrlFragmentNotAllowed);
    }
    let uri = Uri::from_str(endpoint)
        .map_err(|_| HttpsRollbackAnchorConfigurationError::InvalidEndpoint)?;
    match uri.scheme_str() {
        Some("https") => {}
        Some(_) => return Err(HttpsRollbackAnchorConfigurationError::HttpsRequired),
        None => return Err(HttpsRollbackAnchorConfigurationError::InvalidEndpoint),
    }
    let authority = uri
        .authority()
        .ok_or(HttpsRollbackAnchorConfigurationError::InvalidEndpoint)?;
    if authority.as_str().contains('@') {
        return Err(HttpsRollbackAnchorConfigurationError::UrlCredentialsNotAllowed);
    }
    if authority.host().is_empty() {
        return Err(HttpsRollbackAnchorConfigurationError::InvalidEndpoint);
    }
    if authority.port_u16() == Some(0) {
        return Err(HttpsRollbackAnchorConfigurationError::InvalidEndpoint);
    }
    Ok(())
}

fn response_content_type_is_json(response: &ureq::http::Response<ureq::Body>) -> bool {
    response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn is_valid_bearer_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_HTTPS_ROLLBACK_ANCHOR_BEARER_TOKEN_BYTES
        && token.bytes().all(|byte| {
            matches!(
                byte,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'-'
                    | b'.'
                    | b'_'
                    | b'~'
                    | b'+'
                    | b'/'
                    | b'='
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_endpoint_configuration() {
        assert_eq!(
            HttpsRollbackAnchorTransport::new("http://anchor.example/v1", None).unwrap_err(),
            HttpsRollbackAnchorConfigurationError::HttpsRequired
        );
        assert_eq!(
            HttpsRollbackAnchorTransport::new("https://user@anchor.example/v1", None).unwrap_err(),
            HttpsRollbackAnchorConfigurationError::UrlCredentialsNotAllowed
        );
        assert_eq!(
            HttpsRollbackAnchorTransport::new("https://anchor.example/v1#fragment", None)
                .unwrap_err(),
            HttpsRollbackAnchorConfigurationError::UrlFragmentNotAllowed
        );
        assert_eq!(
            HttpsRollbackAnchorTransport::new("https://anchor.example:0/v1", None).unwrap_err(),
            HttpsRollbackAnchorConfigurationError::InvalidEndpoint
        );
        assert_eq!(
            HttpsRollbackAnchorTransport::with_timeout(
                "https://anchor.example/v1",
                None,
                Duration::ZERO,
            )
            .unwrap_err(),
            HttpsRollbackAnchorConfigurationError::ZeroRequestTimeout
        );
    }

    #[test]
    fn keeps_authorization_and_endpoint_out_of_debug_output() {
        let authorization = HttpsRollbackAnchorAuthorization::bearer("secret-token-42").unwrap();
        let authorization_debug = format!("{authorization:?}");
        assert_eq!(
            authorization_debug,
            "HttpsRollbackAnchorAuthorization(REDACTED)"
        );
        assert!(!authorization_debug.contains("secret-token-42"));

        let transport = HttpsRollbackAnchorTransport::new(
            "https://anchor.example/internal/v1",
            Some(authorization),
        )
        .unwrap();
        let debug = format!("{transport:?}");
        assert!(debug.contains("authorization_configured"));
        assert!(!debug.contains("anchor.example"));
        assert!(!debug.contains("secret-token-42"));
    }

    #[test]
    fn validates_bearer_token_syntax() {
        assert!(HttpsRollbackAnchorAuthorization::bearer("abc-._~+/=").is_ok());
        assert_eq!(
            HttpsRollbackAnchorAuthorization::bearer("token\r\ninjected").unwrap_err(),
            HttpsRollbackAnchorConfigurationError::InvalidBearerToken
        );
        assert_eq!(
            HttpsRollbackAnchorAuthorization::bearer(" ").unwrap_err(),
            HttpsRollbackAnchorConfigurationError::InvalidBearerToken
        );
    }

    #[test]
    fn rejects_zero_response_budget_before_network_io() {
        let mut transport =
            HttpsRollbackAnchorTransport::new("https://anchor.example/v1", None).unwrap();
        assert_eq!(
            transport.exchange(b"{}", 0).unwrap_err(),
            HttpsRollbackAnchorTransportError::InvalidResponseLimit
        );
    }

    #[test]
    fn rejects_oversized_requests_before_network_io() {
        let mut transport =
            HttpsRollbackAnchorTransport::new("https://anchor.example/v1", None).unwrap();
        assert_eq!(
            transport
                .exchange(
                    &vec![b'x'; MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES + 1],
                    MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES,
                )
                .unwrap_err(),
            HttpsRollbackAnchorTransportError::RequestTooLarge {
                maximum: MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES,
            }
        );
    }
}
