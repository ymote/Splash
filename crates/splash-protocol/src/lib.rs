#![forbid(unsafe_code)]

//! Portable, capability-attenuated worker messages for Splash.
//!
//! This crate deliberately does not spawn a process, open a socket, or mount a
//! filesystem. It defines the data plane a policy host can validate before it
//! hands an invocation to a platform-specific contained worker.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_WIRE_FRAME_BYTES: usize = 1_048_576;
const MAX_RESOURCES_PER_GRANT: usize = 64;

/// The format an adapter accepts and returns across the worker boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeFormat {
    Text,
    Json,
}

/// Opaque resource kind resolved by the trusted policy host.
///
/// A worker backend maps these identifiers to real paths, executable images,
/// origins, or secret handles. The protocol never treats the identifier as an
/// operating-system path or command line.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    FileRoot,
    Executable,
    NetworkOrigin,
    Secret,
}

/// One opaque resource selector granted to a tool.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ResourceSelector {
    pub kind: ResourceKind,
    pub id: String,
}

impl ResourceSelector {
    pub fn new(kind: ResourceKind, id: impl Into<String>) -> Result<Self, ProtocolError> {
        let id = id.into();
        validate_token("resource selector", &id)?;
        Ok(Self { kind, id })
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_token("resource selector", &self.id)
    }
}

/// A non-ambient capability a worker may exercise for one session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub tool: String,
    pub format: EnvelopeFormat,
    pub max_calls: u32,
    pub max_input_bytes: u32,
    pub max_output_bytes: u32,
    #[serde(default)]
    pub resources: BTreeSet<ResourceSelector>,
}

impl CapabilityGrant {
    pub fn text(tool: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            format: EnvelopeFormat::Text,
            max_calls: 1,
            max_input_bytes: 16 * 1024,
            max_output_bytes: 64 * 1024,
            resources: BTreeSet::new(),
        }
    }

    pub fn json(tool: impl Into<String>) -> Self {
        Self {
            format: EnvelopeFormat::Json,
            ..Self::text(tool)
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_token("tool", &self.tool)?;
        if self.max_calls == 0 {
            return Err(ProtocolError::InvalidGrant(
                "max_calls must be greater than zero",
            ));
        }
        if self.max_input_bytes == 0 || self.max_output_bytes == 0 {
            return Err(ProtocolError::InvalidGrant(
                "byte limits must be greater than zero",
            ));
        }
        if self.resources.len() > MAX_RESOURCES_PER_GRANT {
            return Err(ProtocolError::TooManyResources {
                maximum: MAX_RESOURCES_PER_GRANT,
            });
        }
        for resource in &self.resources {
            resource.validate()?;
        }
        Ok(())
    }

    /// Produces a grant with no more authority than this one.
    pub fn attenuate(&self, attenuation: &GrantAttenuation) -> Result<Self, ProtocolError> {
        self.validate()?;
        let max_calls = attenuation.max_calls.unwrap_or(self.max_calls);
        let max_input_bytes = attenuation.max_input_bytes.unwrap_or(self.max_input_bytes);
        let max_output_bytes = attenuation
            .max_output_bytes
            .unwrap_or(self.max_output_bytes);
        if max_calls == 0 || max_input_bytes == 0 || max_output_bytes == 0 {
            return Err(ProtocolError::InvalidGrant(
                "attenuated limits must be greater than zero",
            ));
        }
        if max_calls > self.max_calls
            || max_input_bytes > self.max_input_bytes
            || max_output_bytes > self.max_output_bytes
        {
            return Err(ProtocolError::AttenuationWidensLimits);
        }

        let resources = attenuation
            .resources
            .clone()
            .unwrap_or_else(|| self.resources.clone());
        if !resources.is_subset(&self.resources) {
            return Err(ProtocolError::AttenuationExpandsResources);
        }

        let grant = Self {
            tool: self.tool.clone(),
            format: self.format,
            max_calls,
            max_input_bytes,
            max_output_bytes,
            resources,
        };
        grant.validate()?;
        Ok(grant)
    }
}

/// Optional restrictions applied to an existing [`CapabilityGrant`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct GrantAttenuation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<BTreeSet<ResourceSelector>>,
}

/// Capability grants issued for one worker session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub protocol_version: u16,
    pub session_id: String,
    pub grants: Vec<CapabilityGrant>,
}

impl CapabilityManifest {
    pub fn new(
        session_id: impl Into<String>,
        grants: Vec<CapabilityGrant>,
    ) -> Result<Self, ProtocolError> {
        let manifest = Self {
            protocol_version: PROTOCOL_VERSION,
            session_id: session_id.into(),
            grants,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                actual: self.protocol_version,
            });
        }
        validate_token("session id", &self.session_id)?;
        let mut seen_tools = BTreeSet::new();
        for grant in &self.grants {
            grant.validate()?;
            if !seen_tools.insert(&grant.tool) {
                return Err(ProtocolError::DuplicateGrant(grant.tool.clone()));
            }
        }
        Ok(())
    }

    pub fn attenuate(&self, attenuation: &ManifestAttenuation) -> Result<Self, ProtocolError> {
        self.validate()?;
        for tool in attenuation.grants.keys() {
            if !self.grants.iter().any(|grant| &grant.tool == tool) {
                return Err(ProtocolError::UnknownTool(tool.clone()));
            }
        }
        if let Some(allowed_tools) = &attenuation.allowed_tools {
            for tool in allowed_tools {
                validate_token("tool", tool)?;
                if !self.grants.iter().any(|grant| &grant.tool == tool) {
                    return Err(ProtocolError::UnknownTool(tool.clone()));
                }
            }
        }

        let grants = self
            .grants
            .iter()
            .filter(|grant| {
                attenuation
                    .allowed_tools
                    .as_ref()
                    .is_none_or(|allowed_tools| allowed_tools.contains(&grant.tool))
            })
            .map(|grant| {
                attenuation.grants.get(&grant.tool).map_or_else(
                    || Ok(grant.clone()),
                    |restriction| grant.attenuate(restriction),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(self.session_id.clone(), grants)
    }
}

/// Restrictions applied to a complete [`CapabilityManifest`].
///
/// `allowed_tools` may only select a subset of inherited grants. Omitting it
/// retains every grant; an empty set deliberately creates a zero-capability
/// session.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManifestAttenuation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<BTreeSet<String>>,
    #[serde(default)]
    pub grants: BTreeMap<String, GrantAttenuation>,
}

/// The payload placed on a worker wire message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format", content = "value", rename_all = "snake_case")]
pub enum ToolPayload {
    Text(String),
    Json(JsonValue),
}

impl ToolPayload {
    pub fn format(&self) -> EnvelopeFormat {
        match self {
            Self::Text(_) => EnvelopeFormat::Text,
            Self::Json(_) => EnvelopeFormat::Json,
        }
    }

    pub fn validate_for(&self, format: EnvelopeFormat) -> Result<usize, ProtocolError> {
        if self.format() != format {
            return Err(ProtocolError::PayloadFormatMismatch {
                expected: format,
                actual: self.format(),
            });
        }

        match self {
            Self::Text(value) => Ok(value.len()),
            Self::Json(value) => {
                if !value.is_object() && !value.is_array() {
                    return Err(ProtocolError::InvalidJsonEnvelope);
                }
                serde_json::to_vec(value)
                    .map(|encoded| encoded.len())
                    .map_err(|error| ProtocolError::Serialization(error.to_string()))
            }
        }
    }
}

/// A capability invocation sent from a policy host to a worker.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolInvocation {
    pub protocol_version: u16,
    pub session_id: String,
    pub request_id: String,
    pub tool: String,
    pub payload: ToolPayload,
}

impl ToolInvocation {
    pub fn new(
        session_id: impl Into<String>,
        request_id: impl Into<String>,
        tool: impl Into<String>,
        payload: ToolPayload,
    ) -> Result<Self, ProtocolError> {
        let invocation = Self {
            protocol_version: PROTOCOL_VERSION,
            session_id: session_id.into(),
            request_id: request_id.into(),
            tool: tool.into(),
            payload,
        };
        invocation.validate_header()?;
        Ok(invocation)
    }

    fn validate_header(&self) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version)?;
        validate_token("session id", &self.session_id)?;
        validate_token("request id", &self.request_id)?;
        validate_token("tool", &self.tool)
    }
}

/// A worker result for a previously authorized invocation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub protocol_version: u16,
    pub session_id: String,
    pub request_id: String,
    pub payload: ToolPayload,
}

impl ToolResult {
    pub fn new(
        session_id: impl Into<String>,
        request_id: impl Into<String>,
        payload: ToolPayload,
    ) -> Result<Self, ProtocolError> {
        let result = Self {
            protocol_version: PROTOCOL_VERSION,
            session_id: session_id.into(),
            request_id: request_id.into(),
            payload,
        };
        result.validate_header()?;
        Ok(result)
    }

    fn validate_header(&self) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version)?;
        validate_token("session id", &self.session_id)?;
        validate_token("request id", &self.request_id)
    }
}

/// Framed protocol messages for a future pipe, socket, or platform IPC layer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerMessage {
    OpenSession {
        manifest: CapabilityManifest,
    },
    Invoke {
        invocation: ToolInvocation,
    },
    Result {
        result: ToolResult,
    },
    Cancel {
        protocol_version: u16,
        session_id: String,
        request_id: String,
    },
    CloseSession {
        protocol_version: u16,
        session_id: String,
    },
}

impl WorkerMessage {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::OpenSession { manifest } => manifest.validate(),
            Self::Invoke { invocation } => invocation.validate_header(),
            Self::Result { result } => result.validate_header(),
            Self::Cancel {
                protocol_version,
                session_id,
                request_id,
            } => {
                validate_protocol_version(*protocol_version)?;
                validate_token("session id", session_id)?;
                validate_token("request id", request_id)
            }
            Self::CloseSession {
                protocol_version,
                session_id,
            } => {
                validate_protocol_version(*protocol_version)?;
                validate_token("session id", session_id)
            }
        }
    }

    pub fn to_json_line(&self) -> Result<String, ProtocolError> {
        self.validate()?;
        let encoded = serde_json::to_string(self)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        if encoded.len() > MAX_WIRE_FRAME_BYTES {
            return Err(ProtocolError::WireFrameTooLarge {
                actual: encoded.len(),
                maximum: MAX_WIRE_FRAME_BYTES,
            });
        }
        Ok(encoded)
    }

    pub fn from_json_line(encoded: &str) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_WIRE_FRAME_BYTES {
            return Err(ProtocolError::WireFrameTooLarge {
                actual: encoded.len(),
                maximum: MAX_WIRE_FRAME_BYTES,
            });
        }
        let message: Self = serde_json::from_str(encoded)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        message.validate()?;
        Ok(message)
    }
}

/// An invocation the policy host has accepted for dispatch.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizedInvocation {
    invocation: ToolInvocation,
    grant: CapabilityGrant,
}

impl AuthorizedInvocation {
    pub fn invocation(&self) -> &ToolInvocation {
        &self.invocation
    }

    pub fn grant(&self) -> &CapabilityGrant {
        &self.grant
    }
}

/// Stateful host-side validation for a single capability manifest.
///
/// Authorization consumes call budget before dispatch. This intentionally
/// prevents a timed-out or crashed worker from allowing a caller to retry past
/// its grant by reusing a request budget.
pub struct SessionAuthorizer {
    manifest: CapabilityManifest,
    calls_by_tool: BTreeMap<String, u32>,
    seen_request_ids: BTreeSet<String>,
    completed_request_ids: BTreeSet<String>,
}

impl SessionAuthorizer {
    pub fn new(manifest: CapabilityManifest) -> Result<Self, ProtocolError> {
        manifest.validate()?;
        Ok(Self {
            manifest,
            calls_by_tool: BTreeMap::new(),
            seen_request_ids: BTreeSet::new(),
            completed_request_ids: BTreeSet::new(),
        })
    }

    pub fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    pub fn calls_for(&self, tool: &str) -> u32 {
        self.calls_by_tool.get(tool).copied().unwrap_or_default()
    }

    pub fn authorize(
        &mut self,
        invocation: ToolInvocation,
    ) -> Result<AuthorizedInvocation, ProtocolError> {
        invocation.validate_header()?;
        if invocation.session_id != self.manifest.session_id {
            return Err(ProtocolError::UnknownSession(invocation.session_id));
        }

        let grant = self
            .manifest
            .grants
            .iter()
            .find(|grant| grant.tool == invocation.tool)
            .cloned()
            .ok_or_else(|| ProtocolError::UnknownTool(invocation.tool.clone()))?;
        let input_bytes = invocation.payload.validate_for(grant.format)?;
        if input_bytes > grant.max_input_bytes as usize {
            return Err(ProtocolError::InputTooLarge {
                actual: input_bytes,
                maximum: grant.max_input_bytes as usize,
            });
        }

        if self.seen_request_ids.contains(&invocation.request_id) {
            return Err(ProtocolError::DuplicateRequest(invocation.request_id));
        }

        let calls = self.calls_by_tool.entry(grant.tool.clone()).or_default();
        if *calls >= grant.max_calls {
            return Err(ProtocolError::CallBudgetExhausted {
                tool: grant.tool.clone(),
                maximum: grant.max_calls,
            });
        }
        self.seen_request_ids.insert(invocation.request_id.clone());
        *calls = calls.saturating_add(1);

        Ok(AuthorizedInvocation { invocation, grant })
    }

    pub fn validate_result(
        &mut self,
        authorized: &AuthorizedInvocation,
        result: &ToolResult,
    ) -> Result<(), ProtocolError> {
        result.validate_header()?;
        if result.session_id != self.manifest.session_id {
            return Err(ProtocolError::UnknownSession(result.session_id.clone()));
        }
        if result.request_id != authorized.invocation.request_id {
            return Err(ProtocolError::RequestMismatch {
                expected: authorized.invocation.request_id.clone(),
                actual: result.request_id.clone(),
            });
        }
        if self.completed_request_ids.contains(&result.request_id) {
            return Err(ProtocolError::DuplicateResult(result.request_id.clone()));
        }
        let output_bytes = result.payload.validate_for(authorized.grant.format)?;
        if output_bytes > authorized.grant.max_output_bytes as usize {
            return Err(ProtocolError::OutputTooLarge {
                actual: output_bytes,
                maximum: authorized.grant.max_output_bytes as usize,
            });
        }
        self.completed_request_ids.insert(result.request_id.clone());
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    UnsupportedVersion {
        actual: u16,
    },
    InvalidToken {
        field: &'static str,
        value: String,
    },
    DuplicateGrant(String),
    InvalidGrant(&'static str),
    TooManyResources {
        maximum: usize,
    },
    AttenuationWidensLimits,
    AttenuationExpandsResources,
    UnknownSession(String),
    UnknownTool(String),
    DuplicateRequest(String),
    DuplicateResult(String),
    PayloadFormatMismatch {
        expected: EnvelopeFormat,
        actual: EnvelopeFormat,
    },
    InvalidJsonEnvelope,
    InputTooLarge {
        actual: usize,
        maximum: usize,
    },
    OutputTooLarge {
        actual: usize,
        maximum: usize,
    },
    CallBudgetExhausted {
        tool: String,
        maximum: u32,
    },
    RequestMismatch {
        expected: String,
        actual: String,
    },
    WireFrameTooLarge {
        actual: usize,
        maximum: usize,
    },
    Serialization(String),
}

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { actual } => {
                write!(
                    formatter,
                    "unsupported Splash worker protocol version: {actual}"
                )
            }
            Self::InvalidToken { field, value } => {
                write!(formatter, "invalid {field}: {value}")
            }
            Self::DuplicateGrant(tool) => write!(formatter, "duplicate capability grant: {tool}"),
            Self::InvalidGrant(message) => formatter.write_str(message),
            Self::TooManyResources { maximum } => {
                write!(
                    formatter,
                    "capability grant exceeds {maximum} resource selectors"
                )
            }
            Self::AttenuationWidensLimits => {
                formatter.write_str("attenuation cannot increase capability limits")
            }
            Self::AttenuationExpandsResources => {
                formatter.write_str("attenuation cannot add resource selectors")
            }
            Self::UnknownSession(session_id) => {
                write!(formatter, "unknown worker session: {session_id}")
            }
            Self::UnknownTool(tool) => write!(formatter, "tool is not granted: {tool}"),
            Self::DuplicateRequest(request_id) => {
                write!(formatter, "duplicate worker request: {request_id}")
            }
            Self::DuplicateResult(request_id) => {
                write!(formatter, "duplicate worker result: {request_id}")
            }
            Self::PayloadFormatMismatch { expected, actual } => {
                write!(
                    formatter,
                    "worker payload format mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            Self::InvalidJsonEnvelope => {
                formatter.write_str("JSON worker payload must be an object or array")
            }
            Self::InputTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "worker input is {actual} bytes; maximum is {maximum} bytes"
                )
            }
            Self::OutputTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "worker output is {actual} bytes; maximum is {maximum} bytes"
                )
            }
            Self::CallBudgetExhausted { tool, maximum } => {
                write!(
                    formatter,
                    "worker tool {tool} exhausted its {maximum} call budget"
                )
            }
            Self::RequestMismatch { expected, actual } => {
                write!(
                    formatter,
                    "worker result request mismatch: expected {expected}, got {actual}"
                )
            }
            Self::WireFrameTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "worker wire frame is {actual} bytes; maximum is {maximum} bytes"
                )
            }
            Self::Serialization(error) => {
                write!(formatter, "worker protocol serialization failed: {error}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

fn validate_token(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    const MAX_TOKEN_BYTES: usize = 128;
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(ProtocolError::InvalidToken {
            field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_protocol_version(protocol_version: u16) -> Result<(), ProtocolError> {
    if protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion {
            actual: protocol_version,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn json_grant() -> CapabilityGrant {
        let mut grant = CapabilityGrant::json("math.add");
        grant.max_calls = 2;
        grant.max_input_bytes = 128;
        grant.max_output_bytes = 128;
        grant
            .resources
            .insert(ResourceSelector::new(ResourceKind::NetworkOrigin, "math-api").unwrap());
        grant
    }

    fn manifest() -> CapabilityManifest {
        CapabilityManifest::new("session-1", vec![json_grant()]).unwrap()
    }

    #[test]
    fn rejects_duplicate_capability_grants() {
        let error =
            CapabilityManifest::new("session-1", vec![json_grant(), json_grant()]).unwrap_err();

        assert_eq!(error, ProtocolError::DuplicateGrant("math.add".to_owned()));
    }

    #[test]
    fn attenuation_only_reduces_authority() {
        let grant = json_grant();
        let kept_resource = ResourceSelector::new(ResourceKind::NetworkOrigin, "math-api").unwrap();
        let narrowed = grant
            .attenuate(&GrantAttenuation {
                max_calls: Some(1),
                max_input_bytes: Some(64),
                max_output_bytes: Some(64),
                resources: Some(BTreeSet::from([kept_resource])),
            })
            .unwrap();

        assert_eq!(narrowed.max_calls, 1);
        assert_eq!(narrowed.max_input_bytes, 64);
        assert_eq!(narrowed.resources.len(), 1);
        assert_eq!(
            grant
                .attenuate(&GrantAttenuation {
                    max_calls: Some(3),
                    ..GrantAttenuation::default()
                })
                .unwrap_err(),
            ProtocolError::AttenuationWidensLimits
        );
        assert_eq!(
            grant
                .attenuate(&GrantAttenuation {
                    resources: Some(BTreeSet::from([
                        ResourceSelector::new(ResourceKind::NetworkOrigin, "math-api").unwrap(),
                        ResourceSelector::new(ResourceKind::Secret, "api-key").unwrap(),
                    ])),
                    ..GrantAttenuation::default()
                })
                .unwrap_err(),
            ProtocolError::AttenuationExpandsResources
        );
    }

    #[test]
    fn manifest_attenuation_can_drop_tools_or_create_a_zero_capability_session() {
        let mut echo = CapabilityGrant::text("text.echo");
        echo.max_calls = 2;
        let parent = CapabilityManifest::new("session-1", vec![json_grant(), echo]).unwrap();

        let narrowed = parent
            .attenuate(&ManifestAttenuation {
                allowed_tools: Some(BTreeSet::from(["math.add".to_owned()])),
                ..ManifestAttenuation::default()
            })
            .unwrap();
        assert_eq!(narrowed.grants.len(), 1);
        assert_eq!(narrowed.grants[0].tool, "math.add");

        let zero = parent
            .attenuate(&ManifestAttenuation {
                allowed_tools: Some(BTreeSet::new()),
                ..ManifestAttenuation::default()
            })
            .unwrap();
        assert!(zero.grants.is_empty());

        let mut authorizer = SessionAuthorizer::new(zero).unwrap();
        let invocation = ToolInvocation::new(
            "session-1",
            "request-1",
            "math.add",
            ToolPayload::Json(json!({"left": 20, "right": 22})),
        )
        .unwrap();
        assert_eq!(
            authorizer.authorize(invocation).unwrap_err(),
            ProtocolError::UnknownTool("math.add".to_owned())
        );
    }

    #[test]
    fn authorizer_enforces_format_size_and_call_budget() {
        let mut authorizer = SessionAuthorizer::new(manifest()).unwrap();
        let invocation = ToolInvocation::new(
            "session-1",
            "request-1",
            "math.add",
            ToolPayload::Json(json!({"left": 20, "right": 22})),
        )
        .unwrap();

        let authorized = authorizer.authorize(invocation).unwrap();
        assert_eq!(authorizer.calls_for("math.add"), 1);
        let result = ToolResult::new(
            "session-1",
            "request-1",
            ToolPayload::Json(json!({"total": 42})),
        )
        .unwrap();
        authorizer.validate_result(&authorized, &result).unwrap();
        assert_eq!(
            authorizer
                .validate_result(&authorized, &result)
                .unwrap_err(),
            ProtocolError::DuplicateResult("request-1".to_owned())
        );

        let scalar = ToolInvocation::new(
            "session-1",
            "request-2",
            "math.add",
            ToolPayload::Json(json!(42)),
        )
        .unwrap();
        assert_eq!(
            authorizer.authorize(scalar).unwrap_err(),
            ProtocolError::InvalidJsonEnvelope
        );

        let second = ToolInvocation::new(
            "session-1",
            "request-2",
            "math.add",
            ToolPayload::Json(json!({"left": 1, "right": 2})),
        )
        .unwrap();
        authorizer.authorize(second).unwrap();
        let third = ToolInvocation::new(
            "session-1",
            "request-3",
            "math.add",
            ToolPayload::Json(json!({"left": 3, "right": 4})),
        )
        .unwrap();
        assert_eq!(
            authorizer.authorize(third).unwrap_err(),
            ProtocolError::CallBudgetExhausted {
                tool: "math.add".to_owned(),
                maximum: 2,
            }
        );
    }

    #[test]
    fn rejects_duplicate_request_identifiers() {
        let mut authorizer = SessionAuthorizer::new(manifest()).unwrap();
        let first = ToolInvocation::new(
            "session-1",
            "request-1",
            "math.add",
            ToolPayload::Json(json!({"left": 20, "right": 22})),
        )
        .unwrap();
        authorizer.authorize(first).unwrap();
        let duplicate = ToolInvocation::new(
            "session-1",
            "request-1",
            "math.add",
            ToolPayload::Json(json!({"left": 20, "right": 22})),
        )
        .unwrap();

        assert_eq!(
            authorizer.authorize(duplicate).unwrap_err(),
            ProtocolError::DuplicateRequest("request-1".to_owned())
        );
    }

    #[test]
    fn result_must_match_the_authorized_request_and_output_limit() {
        let mut authorizer = SessionAuthorizer::new(manifest()).unwrap();
        let invocation = ToolInvocation::new(
            "session-1",
            "request-1",
            "math.add",
            ToolPayload::Json(json!({"left": 20, "right": 22})),
        )
        .unwrap();
        let authorized = authorizer.authorize(invocation).unwrap();
        let wrong_request = ToolResult::new(
            "session-1",
            "request-2",
            ToolPayload::Json(json!({"total": 42})),
        )
        .unwrap();

        assert_eq!(
            authorizer
                .validate_result(&authorized, &wrong_request)
                .unwrap_err(),
            ProtocolError::RequestMismatch {
                expected: "request-1".to_owned(),
                actual: "request-2".to_owned(),
            }
        );

        let oversized = ToolResult::new(
            "session-1",
            "request-1",
            ToolPayload::Json(json!({"body": "x".repeat(256)})),
        )
        .unwrap();
        assert!(matches!(
            authorizer.validate_result(&authorized, &oversized),
            Err(ProtocolError::OutputTooLarge { .. })
        ));
    }

    #[test]
    fn worker_messages_round_trip_through_bounded_json_frames() {
        let message = WorkerMessage::OpenSession {
            manifest: manifest(),
        };
        let encoded = message.to_json_line().unwrap();
        let decoded = WorkerMessage::from_json_line(&encoded).unwrap();

        assert_eq!(decoded, message);
    }

    #[test]
    fn frame_decoding_validates_message_headers() {
        let encoded = r#"{"type":"invoke","invocation":{"protocol_version":1,"session_id":"bad session","request_id":"request-1","tool":"math.add","payload":{"format":"json","value":{"left":20,"right":22}}}}"#;

        assert!(matches!(
            WorkerMessage::from_json_line(encoded),
            Err(ProtocolError::InvalidToken {
                field: "session id",
                ..
            })
        ));
    }
}
