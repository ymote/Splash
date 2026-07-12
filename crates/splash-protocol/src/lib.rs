#![forbid(unsafe_code)]

//! Portable, capability-attenuated worker messages for Splash.
//!
//! This crate deliberately does not spawn a process, open a socket, or mount a
//! filesystem. It defines the data plane a policy host can validate before it
//! hands an invocation to a platform-specific contained worker.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub const PROTOCOL_VERSION: u16 = 3;
pub const MAX_WIRE_FRAME_BYTES: usize = 1_048_576;
pub const AUTH_TAG_BYTES: usize = blake3::OUT_LEN;
pub const MAX_OPERATION_ERROR_BYTES: usize = 4 * 1024;
/// Maximum serialized worker operation journal accepted from durable storage.
pub const MAX_WORKER_OPERATION_JOURNAL_BYTES: usize = 512 * 1024;
/// Maximum durable operation intents retained by one worker journal.
pub const MAX_WORKER_OPERATION_RECORDS: usize = 64;
/// Current serialized worker operation journal format version.
pub const WORKER_OPERATION_JOURNAL_FORMAT_VERSION: u8 = 1;
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

/// An effectful operation dispatch sent from a policy host to a contained
/// worker.
///
/// Unlike a regular [`ToolInvocation`], this carries a host-owned durable
/// `operation_key`. A worker journal must persist the intent before it runs
/// the effect and must reject reuse of the key for a different tool or input.
/// The key is a correlation and deduplication value, never authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationDispatchRequest {
    pub protocol_version: u16,
    pub session_id: String,
    pub request_id: String,
    pub tool: String,
    pub operation_key: String,
    pub payload: ToolPayload,
}

impl OperationDispatchRequest {
    pub fn new(
        session_id: impl Into<String>,
        request_id: impl Into<String>,
        tool: impl Into<String>,
        operation_key: impl Into<String>,
        payload: ToolPayload,
    ) -> Result<Self, ProtocolError> {
        let request = Self {
            protocol_version: PROTOCOL_VERSION,
            session_id: session_id.into(),
            request_id: request_id.into(),
            tool: tool.into(),
            operation_key: operation_key.into(),
            payload,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate_header(&self) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version)?;
        validate_token("session id", &self.session_id)?;
        validate_token("request id", &self.request_id)?;
        validate_token("tool", &self.tool)?;
        validate_token("operation key", &self.operation_key)
    }

    /// Validates portable request syntax before the session grant is applied.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.validate_header()?;
        self.payload.validate_for(self.payload.format()).map(|_| ())
    }

    /// Returns the stable canonical bytes that bind this dispatch input into a
    /// durable operation identity.
    pub fn canonical_input_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        canonical_operation_input_bytes(&self.payload)
    }
}

/// A host request to recover the status of one externally dispatched operation.
///
/// `operation_key` is an idempotency or durable workflow key supplied by the
/// host. It is deliberately not an authorization credential and never carries
/// a process-local host operation identifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationReconcileRequest {
    pub protocol_version: u16,
    pub session_id: String,
    pub request_id: String,
    pub tool: String,
    pub operation_key: String,
}

impl OperationReconcileRequest {
    pub fn new(
        session_id: impl Into<String>,
        request_id: impl Into<String>,
        tool: impl Into<String>,
        operation_key: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let request = Self {
            protocol_version: PROTOCOL_VERSION,
            session_id: session_id.into(),
            request_id: request_id.into(),
            tool: tool.into(),
            operation_key: operation_key.into(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the protocol header before a host dispatches this request.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version)?;
        validate_token("session id", &self.session_id)?;
        validate_token("request id", &self.request_id)?;
        validate_token("tool", &self.tool)?;
        validate_token("operation key", &self.operation_key)
    }
}

/// Worker-reported state for an externally dispatched operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OperationStatus {
    Running,
    Succeeded { payload: ToolPayload },
    Failed { message: String },
    Cancelled,
}

impl OperationStatus {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Running | Self::Cancelled => Ok(()),
            Self::Succeeded { payload } => payload.validate_for(payload.format()).map(|_| ()),
            Self::Failed { message } => {
                if message.is_empty() {
                    return Err(ProtocolError::InvalidOperationFailure);
                }
                if message.len() > MAX_OPERATION_ERROR_BYTES {
                    return Err(ProtocolError::OperationFailureTooLarge {
                        actual: message.len(),
                        maximum: MAX_OPERATION_ERROR_BYTES,
                    });
                }
                Ok(())
            }
        }
    }
}

/// An authenticated worker response to [`OperationReconcileRequest`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationReconcileResult {
    pub protocol_version: u16,
    pub session_id: String,
    pub request_id: String,
    pub tool: String,
    pub operation_key: String,
    pub status: OperationStatus,
}

impl OperationReconcileResult {
    pub fn new(
        session_id: impl Into<String>,
        request_id: impl Into<String>,
        tool: impl Into<String>,
        operation_key: impl Into<String>,
        status: OperationStatus,
    ) -> Result<Self, ProtocolError> {
        let result = Self {
            protocol_version: PROTOCOL_VERSION,
            session_id: session_id.into(),
            request_id: request_id.into(),
            tool: tool.into(),
            operation_key: operation_key.into(),
            status,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn matches_request(&self, request: &OperationReconcileRequest) -> bool {
        self.protocol_version == request.protocol_version
            && self.session_id == request.session_id
            && self.request_id == request.request_id
            && self.tool == request.tool
            && self.operation_key == request.operation_key
    }

    /// Returns whether this status reports the exact durable dispatch request.
    pub fn matches_dispatch(&self, request: &OperationDispatchRequest) -> bool {
        self.protocol_version == request.protocol_version
            && self.session_id == request.session_id
            && self.request_id == request.request_id
            && self.tool == request.tool
            && self.operation_key == request.operation_key
    }

    /// Validates a worker-reported operation state before host reconciliation.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_protocol_version(self.protocol_version)?;
        validate_token("session id", &self.session_id)?;
        validate_token("request id", &self.request_id)?;
        validate_token("tool", &self.tool)?;
        validate_token("operation key", &self.operation_key)?;
        self.status.validate()
    }
}

/// Persisted lifecycle state for one worker-side durable operation.
///
/// `Pending` means the worker recorded intent before dispatch but has not
/// recorded a worker observation. Terminal success data is retained solely so
/// a worker can return an idempotent result; persist the journal only in
/// authenticated storage appropriate for that payload's sensitivity.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WorkerOperationState {
    Pending,
    Running,
    Succeeded { payload: ToolPayload },
    Failed { message: String },
    Cancelled,
}

impl WorkerOperationState {
    /// Returns the state without exposing any retained result payload.
    pub fn kind(&self) -> WorkerOperationStateKind {
        match self {
            Self::Pending => WorkerOperationStateKind::Pending,
            Self::Running => WorkerOperationStateKind::Running,
            Self::Succeeded { .. } => WorkerOperationStateKind::Succeeded,
            Self::Failed { .. } => WorkerOperationStateKind::Failed,
            Self::Cancelled => WorkerOperationStateKind::Cancelled,
        }
    }

    /// Converts an observed worker state into its protocol status, if one
    /// exists. `Pending` deliberately has no wire status.
    pub fn as_status(&self) -> Option<OperationStatus> {
        match self {
            Self::Pending => None,
            Self::Running => Some(OperationStatus::Running),
            Self::Succeeded { payload } => Some(OperationStatus::Succeeded {
                payload: payload.clone(),
            }),
            Self::Failed { message } => Some(OperationStatus::Failed {
                message: message.clone(),
            }),
            Self::Cancelled => Some(OperationStatus::Cancelled),
        }
    }

    fn from_status(status: OperationStatus) -> Self {
        match status {
            OperationStatus::Running => Self::Running,
            OperationStatus::Succeeded { payload } => Self::Succeeded { payload },
            OperationStatus::Failed { message } => Self::Failed { message },
            OperationStatus::Cancelled => Self::Cancelled,
        }
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Pending | Self::Running | Self::Cancelled => Ok(()),
            Self::Succeeded { payload } => payload.validate_for(payload.format()).map(|_| ()),
            Self::Failed { message } => OperationStatus::Failed {
                message: message.clone(),
            }
            .validate(),
        }
    }

    fn accepts(&self, observed: &Self) -> bool {
        match self {
            Self::Pending => !matches!(observed, Self::Pending),
            Self::Running => !matches!(observed, Self::Pending),
            Self::Succeeded { .. } | Self::Failed { .. } | Self::Cancelled => self == observed,
        }
    }
}

impl fmt::Debug for WorkerOperationState {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => formatter.write_str("WorkerOperationState::Pending"),
            Self::Running => formatter.write_str("WorkerOperationState::Running"),
            Self::Succeeded { .. } => {
                formatter.write_str("WorkerOperationState::Succeeded([REDACTED])")
            }
            Self::Failed { .. } => formatter.write_str("WorkerOperationState::Failed([REDACTED])"),
            Self::Cancelled => formatter.write_str("WorkerOperationState::Cancelled"),
        }
    }
}

/// A payload-free view used in durable operation transition errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerOperationStateKind {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

/// One bounded durable operation intent retained by a contained worker.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerOperationRecord {
    tool: String,
    operation_key: String,
    input_fingerprint: String,
    state: WorkerOperationState,
}

impl WorkerOperationRecord {
    pub fn tool(&self) -> &str {
        &self.tool
    }

    pub fn operation_key(&self) -> &str {
        &self.operation_key
    }

    pub fn input_fingerprint(&self) -> &str {
        &self.input_fingerprint
    }

    pub fn state(&self) -> &WorkerOperationState {
        &self.state
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_token("tool", &self.tool)?;
        validate_token("operation key", &self.operation_key)?;
        if !is_blake3_fingerprint(&self.input_fingerprint) {
            return Err(ProtocolError::InvalidOperationFingerprint);
        }
        self.state.validate()
    }
}

impl fmt::Debug for WorkerOperationRecord {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerOperationRecord")
            .field("tool", &self.tool)
            .field("operation_key", &self.operation_key)
            .field("input_fingerprint", &self.input_fingerprint)
            .field("state", &self.state)
            .finish()
    }
}

/// Bounded worker-side state used to deduplicate durable operations.
///
/// Persist a journal before an effect reaches an adapter. A new journal record
/// returns [`WorkerOperationAdmission::Dispatch`]; an exact duplicate returns
/// its existing state and must not cause another effect. This type does not
/// write storage itself, select a tenant namespace, or authorize a tool. The
/// contained worker's host owns those boundaries.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerOperationJournal {
    format_version: u8,
    scope: String,
    records: Vec<WorkerOperationRecord>,
}

impl WorkerOperationJournal {
    /// Creates a journal for one opaque host-selected worker tenant or policy
    /// domain. Never share a scope across principals that must not deduplicate
    /// each other's durable effects.
    pub fn new(scope: impl Into<String>) -> Result<Self, ProtocolError> {
        let scope = scope.into();
        validate_token("operation journal scope", &scope)?;
        Ok(Self {
            format_version: WORKER_OPERATION_JOURNAL_FORMAT_VERSION,
            scope,
            records: Vec::new(),
        })
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Rejects a restored journal that belongs to another worker tenant or
    /// policy domain.
    pub fn validate_scope(&self, expected_scope: &str) -> Result<(), ProtocolError> {
        validate_token("operation journal scope", expected_scope)?;
        if self.scope != expected_scope {
            return Err(ProtocolError::OperationJournalScopeMismatch {
                expected: expected_scope.to_owned(),
                actual: self.scope.clone(),
            });
        }
        Ok(())
    }

    pub fn records(&self) -> &[WorkerOperationRecord] {
        &self.records
    }

    pub fn operation(&self, operation_key: &str) -> Option<&WorkerOperationRecord> {
        self.records
            .iter()
            .find(|record| record.operation_key == operation_key)
    }

    /// Encodes bounded worker-owned state for authenticated durable storage.
    pub fn to_json(&self) -> Result<String, ProtocolError> {
        self.validate_and_bound()?;
        serde_json::to_string(self).map_err(|error| ProtocolError::Serialization(error.to_string()))
    }

    /// Decodes bounded worker state from host-selected durable storage.
    ///
    /// This checks syntax and resource bounds, but the caller must authenticate
    /// the storage and scope one journal to one worker tenant or policy domain.
    pub fn from_json(encoded: &str) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_WORKER_OPERATION_JOURNAL_BYTES {
            return Err(ProtocolError::OperationJournalTooLarge {
                actual: encoded.len(),
                maximum: MAX_WORKER_OPERATION_JOURNAL_BYTES,
            });
        }
        let journal: Self = serde_json::from_str(encoded)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        journal.validate_and_bound()?;
        Ok(journal)
    }

    /// Decodes and validates a journal for one expected host-controlled scope.
    pub fn from_json_for_scope(encoded: &str, expected_scope: &str) -> Result<Self, ProtocolError> {
        let journal = Self::from_json(encoded)?;
        journal.validate_scope(expected_scope)?;
        Ok(journal)
    }

    /// Records durable intent for an authorized operation before worker
    /// dispatch. Exact duplicates return their existing state without mutation.
    pub fn admit(
        &mut self,
        authorized: &AuthorizedOperationInvocation,
    ) -> Result<WorkerOperationAdmission, ProtocolError> {
        self.validate_and_bound()?;
        let request = authorized.request();
        let input_fingerprint = worker_operation_input_fingerprint(&request.payload)?;
        if let Some(record) = self.operation(&request.operation_key) {
            ensure_operation_identity(record, request, &input_fingerprint)?;
            validate_worker_operation_state_for_grant(&record.state, authorized.grant())?;
            return Ok(WorkerOperationAdmission::Existing {
                state: record.state.clone(),
            });
        }
        if self.records.len() >= MAX_WORKER_OPERATION_RECORDS {
            return Err(ProtocolError::TooManyWorkerOperations {
                maximum: MAX_WORKER_OPERATION_RECORDS,
            });
        }

        let mut candidate = self.clone();
        candidate.records.push(WorkerOperationRecord {
            tool: request.tool.clone(),
            operation_key: request.operation_key.clone(),
            input_fingerprint,
            state: WorkerOperationState::Pending,
        });
        candidate.validate_and_bound()?;
        *self = candidate;
        Ok(WorkerOperationAdmission::Dispatch)
    }

    /// Records a worker observation after an adapter has acted on an admitted
    /// operation. Terminal states are idempotent only when their complete
    /// payload or failure message matches exactly.
    pub fn observe(
        &mut self,
        authorized: &AuthorizedOperationInvocation,
        status: OperationStatus,
    ) -> Result<WorkerOperationState, ProtocolError> {
        self.validate_and_bound()?;
        validate_operation_status_for_grant(&status, authorized.grant())?;
        let request = authorized.request();
        let input_fingerprint = worker_operation_input_fingerprint(&request.payload)?;
        let record_index = self
            .records
            .iter()
            .position(|record| record.operation_key == request.operation_key)
            .ok_or_else(|| ProtocolError::UnknownOperation(request.operation_key.clone()))?;
        let record = &self.records[record_index];
        ensure_operation_identity(record, request, &input_fingerprint)?;
        let observed = WorkerOperationState::from_status(status);
        if !record.state.accepts(&observed) {
            return Err(ProtocolError::InvalidWorkerOperationTransition {
                operation_key: request.operation_key.clone(),
                current: record.state.kind(),
                observed: observed.kind(),
            });
        }
        if record.state == observed {
            return Ok(observed);
        }

        let mut candidate = self.clone();
        candidate.records[record_index].state = observed.clone();
        candidate.validate_and_bound()?;
        *self = candidate;
        Ok(observed)
    }

    fn validate_and_bound(&self) -> Result<(), ProtocolError> {
        if self.format_version != WORKER_OPERATION_JOURNAL_FORMAT_VERSION {
            return Err(ProtocolError::UnsupportedOperationJournalVersion(
                self.format_version,
            ));
        }
        validate_token("operation journal scope", &self.scope)?;
        if self.records.len() > MAX_WORKER_OPERATION_RECORDS {
            return Err(ProtocolError::TooManyWorkerOperations {
                maximum: MAX_WORKER_OPERATION_RECORDS,
            });
        }
        let mut seen_operation_keys = BTreeSet::new();
        for record in &self.records {
            record.validate()?;
            if !seen_operation_keys.insert(&record.operation_key) {
                return Err(ProtocolError::DuplicateOperationKey(
                    record.operation_key.clone(),
                ));
            }
        }
        let encoded = serde_json::to_vec(self)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        if encoded.len() > MAX_WORKER_OPERATION_JOURNAL_BYTES {
            return Err(ProtocolError::OperationJournalTooLarge {
                actual: encoded.len(),
                maximum: MAX_WORKER_OPERATION_JOURNAL_BYTES,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for WorkerOperationJournal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerOperationJournal")
            .field("format_version", &self.format_version)
            .field("scope", &self.scope)
            .field("record_count", &self.records.len())
            .finish()
    }
}

/// Admission outcome for [`WorkerOperationJournal::admit`].
#[derive(Clone, Debug, PartialEq)]
pub enum WorkerOperationAdmission {
    /// Persist the journal before allowing the adapter to execute the effect.
    Dispatch,
    /// The exact operation already exists; do not execute it again.
    Existing { state: WorkerOperationState },
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
    DispatchOperation {
        request: OperationDispatchRequest,
    },
    OperationResult {
        result: OperationReconcileResult,
    },
    ReconcileOperation {
        request: OperationReconcileRequest,
    },
    ReconciledOperation {
        result: OperationReconcileResult,
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
            Self::DispatchOperation { request } => request.validate(),
            Self::OperationResult { result } => result.validate(),
            Self::ReconcileOperation { request } => request.validate(),
            Self::ReconciledOperation { result } => result.validate(),
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

    /// Returns the session that scopes this message.
    pub fn session_id(&self) -> &str {
        match self {
            Self::OpenSession { manifest } => &manifest.session_id,
            Self::Invoke { invocation } => &invocation.session_id,
            Self::Result { result } => &result.session_id,
            Self::DispatchOperation { request } => &request.session_id,
            Self::OperationResult { result } => &result.session_id,
            Self::ReconcileOperation { request } => &request.session_id,
            Self::ReconciledOperation { result } => &result.session_id,
            Self::Cancel { session_id, .. } | Self::CloseSession { session_id, .. } => session_id,
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

/// Which side of an authenticated worker session is sending a frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRole {
    Host,
    Worker,
}

impl SessionRole {
    fn peer(self) -> Self {
        match self {
            Self::Host => Self::Worker,
            Self::Worker => Self::Host,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Worker => "worker",
        }
    }
}

/// A host-provisioned BLAKE3 key for one worker session.
///
/// This type is intentionally neither serializable nor displayable. Establish
/// and store it through a platform-specific trusted channel, not in a Splash
/// script or worker manifest.
#[derive(Clone)]
pub struct SessionKey([u8; AUTH_TAG_BYTES]);

impl SessionKey {
    pub fn from_bytes(bytes: [u8; AUTH_TAG_BYTES]) -> Result<Self, ProtocolError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(ProtocolError::WeakSessionKey);
        }
        Ok(Self(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != AUTH_TAG_BYTES {
            return Err(ProtocolError::InvalidSessionKeyLength {
                actual: bytes.len(),
                expected: AUTH_TAG_BYTES,
            });
        }
        let mut key = [0; AUTH_TAG_BYTES];
        key.copy_from_slice(bytes);
        Self::from_bytes(key)
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionKey([redacted])")
    }
}

/// A sequence-numbered worker message carrying a keyed authentication tag.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthenticatedWorkerMessage {
    pub sequence: u64,
    pub message: WorkerMessage,
    pub auth_tag: String,
}

impl AuthenticatedWorkerMessage {
    pub fn to_json_line(&self) -> Result<String, ProtocolError> {
        self.validate_syntax()?;
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
        let frame: Self = serde_json::from_str(encoded)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        frame.validate_syntax()?;
        Ok(frame)
    }

    fn validate_syntax(&self) -> Result<(), ProtocolError> {
        if self.sequence == 0 {
            return Err(ProtocolError::InvalidSequence);
        }
        self.message.validate()?;
        decode_auth_tag(&self.auth_tag).map(|_| ())
    }
}

/// Stateful sender/receiver for one authenticated host-worker session.
///
/// Outgoing and incoming sequence numbers are independent. The sender role is
/// part of the tag, so a host cannot accept a reflected copy of its own frame.
pub struct SessionAuthenticator {
    session_id: String,
    key: SessionKey,
    role: SessionRole,
    next_outgoing_sequence: u64,
    next_incoming_sequence: u64,
}

impl SessionAuthenticator {
    pub fn new(
        session_id: impl Into<String>,
        key: SessionKey,
        role: SessionRole,
    ) -> Result<Self, ProtocolError> {
        let session_id = session_id.into();
        validate_token("session id", &session_id)?;
        Ok(Self {
            session_id,
            key,
            role,
            next_outgoing_sequence: 1,
            next_incoming_sequence: 1,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn role(&self) -> SessionRole {
        self.role
    }

    pub fn seal(
        &mut self,
        message: WorkerMessage,
    ) -> Result<AuthenticatedWorkerMessage, ProtocolError> {
        message.validate()?;
        if message.session_id() != self.session_id {
            return Err(ProtocolError::UnknownSession(
                message.session_id().to_owned(),
            ));
        }
        if self.next_outgoing_sequence == u64::MAX {
            return Err(ProtocolError::SequenceExhausted);
        }

        let sequence = self.next_outgoing_sequence;
        let auth_tag = encode_auth_tag(&authentication_tag(
            &self.key,
            &self.session_id,
            self.role,
            sequence,
            &message,
        )?);
        let frame = AuthenticatedWorkerMessage {
            sequence,
            message,
            auth_tag,
        };
        frame.to_json_line()?;
        self.next_outgoing_sequence = self.next_outgoing_sequence.saturating_add(1);
        Ok(frame)
    }

    pub fn open(
        &mut self,
        frame: AuthenticatedWorkerMessage,
    ) -> Result<WorkerMessage, ProtocolError> {
        frame.validate_syntax()?;
        let supplied_tag = decode_auth_tag(&frame.auth_tag)?;
        let expected_tag = authentication_tag(
            &self.key,
            &self.session_id,
            self.role.peer(),
            frame.sequence,
            &frame.message,
        )?;
        if !constant_time_eq(&expected_tag, &supplied_tag) {
            return Err(ProtocolError::InvalidAuthenticationTag);
        }
        if frame.message.session_id() != self.session_id {
            return Err(ProtocolError::UnknownSession(
                frame.message.session_id().to_owned(),
            ));
        }
        if frame.sequence != self.next_incoming_sequence {
            return Err(ProtocolError::UnexpectedSequence {
                expected: self.next_incoming_sequence,
                actual: frame.sequence,
            });
        }
        if self.next_incoming_sequence == u64::MAX {
            return Err(ProtocolError::SequenceExhausted);
        }
        self.next_incoming_sequence = self.next_incoming_sequence.saturating_add(1);
        Ok(frame.message)
    }
}

#[derive(Serialize)]
struct AuthenticationPayload<'a> {
    domain: &'static str,
    protocol_version: u16,
    sender: &'static str,
    sequence: u64,
    session_id: &'a str,
    message: &'a WorkerMessage,
}

fn authentication_tag(
    key: &SessionKey,
    session_id: &str,
    sender: SessionRole,
    sequence: u64,
    message: &WorkerMessage,
) -> Result<[u8; AUTH_TAG_BYTES], ProtocolError> {
    let encoded = serde_json::to_vec(&AuthenticationPayload {
        domain: "splash-worker-auth-v3",
        protocol_version: PROTOCOL_VERSION,
        sender: sender.tag(),
        sequence,
        session_id,
        message,
    })
    .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
    if encoded.len() > MAX_WIRE_FRAME_BYTES {
        return Err(ProtocolError::WireFrameTooLarge {
            actual: encoded.len(),
            maximum: MAX_WIRE_FRAME_BYTES,
        });
    }
    Ok(*blake3::keyed_hash(&key.0, &encoded).as_bytes())
}

fn encode_auth_tag(bytes: &[u8; AUTH_TAG_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(AUTH_TAG_BYTES * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_auth_tag(encoded: &str) -> Result<[u8; AUTH_TAG_BYTES], ProtocolError> {
    if encoded.len() != AUTH_TAG_BYTES * 2 {
        return Err(ProtocolError::InvalidAuthenticationTag);
    }
    let mut bytes = [0; AUTH_TAG_BYTES];
    let mut encoded_bytes = encoded.bytes();
    for byte in &mut bytes {
        let high = hex_nibble(
            encoded_bytes
                .next()
                .ok_or(ProtocolError::InvalidAuthenticationTag)?,
        )?;
        let low = hex_nibble(
            encoded_bytes
                .next()
                .ok_or(ProtocolError::InvalidAuthenticationTag)?,
        )?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, ProtocolError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ProtocolError::InvalidAuthenticationTag),
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

/// A durable operation dispatch the policy host has accepted for a worker.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizedOperationInvocation {
    request: OperationDispatchRequest,
    grant: CapabilityGrant,
}

impl AuthorizedOperationInvocation {
    pub fn request(&self) -> &OperationDispatchRequest {
        &self.request
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
        let grant = self.authorize_payload(
            &invocation.session_id,
            &invocation.request_id,
            &invocation.tool,
            &invocation.payload,
        )?;

        Ok(AuthorizedInvocation { invocation, grant })
    }

    /// Validates and reserves one durable operation dispatch against this
    /// session's capability manifest.
    pub fn authorize_operation(
        &mut self,
        request: OperationDispatchRequest,
    ) -> Result<AuthorizedOperationInvocation, ProtocolError> {
        request.validate_header()?;
        let grant = self.authorize_payload(
            &request.session_id,
            &request.request_id,
            &request.tool,
            &request.payload,
        )?;
        Ok(AuthorizedOperationInvocation { request, grant })
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

    /// Validates one initial dispatch status against an authorized durable
    /// operation. A worker may report `running` or a terminal observation; a
    /// later reconciliation uses its own request ID and is validated separately.
    pub fn validate_operation_result(
        &mut self,
        authorized: &AuthorizedOperationInvocation,
        result: &OperationReconcileResult,
    ) -> Result<(), ProtocolError> {
        result.validate()?;
        if result.session_id != self.manifest.session_id {
            return Err(ProtocolError::UnknownSession(result.session_id.clone()));
        }
        if !result.matches_dispatch(&authorized.request) {
            return Err(ProtocolError::OperationResultMismatch);
        }
        if self.completed_request_ids.contains(&result.request_id) {
            return Err(ProtocolError::DuplicateResult(result.request_id.clone()));
        }
        validate_operation_status_for_grant(&result.status, &authorized.grant)?;
        self.completed_request_ids.insert(result.request_id.clone());
        Ok(())
    }

    fn authorize_payload(
        &mut self,
        session_id: &str,
        request_id: &str,
        tool: &str,
        payload: &ToolPayload,
    ) -> Result<CapabilityGrant, ProtocolError> {
        if session_id != self.manifest.session_id {
            return Err(ProtocolError::UnknownSession(session_id.to_owned()));
        }
        let grant = self
            .manifest
            .grants
            .iter()
            .find(|grant| grant.tool == tool)
            .cloned()
            .ok_or_else(|| ProtocolError::UnknownTool(tool.to_owned()))?;
        let input_bytes = payload.validate_for(grant.format)?;
        if input_bytes > grant.max_input_bytes as usize {
            return Err(ProtocolError::InputTooLarge {
                actual: input_bytes,
                maximum: grant.max_input_bytes as usize,
            });
        }
        if self.seen_request_ids.contains(request_id) {
            return Err(ProtocolError::DuplicateRequest(request_id.to_owned()));
        }
        let calls = self.calls_by_tool.entry(grant.tool.clone()).or_default();
        if *calls >= grant.max_calls {
            return Err(ProtocolError::CallBudgetExhausted {
                tool: grant.tool.clone(),
                maximum: grant.max_calls,
            });
        }
        self.seen_request_ids.insert(request_id.to_owned());
        *calls = calls.saturating_add(1);
        Ok(grant)
    }
}

fn validate_operation_status_for_grant(
    status: &OperationStatus,
    grant: &CapabilityGrant,
) -> Result<(), ProtocolError> {
    status.validate()?;
    if let OperationStatus::Succeeded { payload } = status {
        let output_bytes = payload.validate_for(grant.format)?;
        if output_bytes > grant.max_output_bytes as usize {
            return Err(ProtocolError::OutputTooLarge {
                actual: output_bytes,
                maximum: grant.max_output_bytes as usize,
            });
        }
    }
    Ok(())
}

fn validate_worker_operation_state_for_grant(
    state: &WorkerOperationState,
    grant: &CapabilityGrant,
) -> Result<(), ProtocolError> {
    state.validate()?;
    if let Some(status) = state.as_status() {
        validate_operation_status_for_grant(&status, grant)?;
    }
    Ok(())
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
    InvalidSessionKeyLength {
        actual: usize,
        expected: usize,
    },
    WeakSessionKey,
    InvalidSequence,
    SequenceExhausted,
    UnexpectedSequence {
        expected: u64,
        actual: u64,
    },
    InvalidAuthenticationTag,
    DuplicateRequest(String),
    DuplicateResult(String),
    OperationResultMismatch,
    UnsupportedOperationJournalVersion(u8),
    OperationJournalTooLarge {
        actual: usize,
        maximum: usize,
    },
    OperationJournalScopeMismatch {
        expected: String,
        actual: String,
    },
    TooManyWorkerOperations {
        maximum: usize,
    },
    InvalidOperationFingerprint,
    DuplicateOperationKey(String),
    UnknownOperation(String),
    OperationIdentityMismatch(String),
    InvalidWorkerOperationTransition {
        operation_key: String,
        current: WorkerOperationStateKind,
        observed: WorkerOperationStateKind,
    },
    PayloadFormatMismatch {
        expected: EnvelopeFormat,
        actual: EnvelopeFormat,
    },
    InvalidJsonEnvelope,
    InvalidOperationFailure,
    OperationFailureTooLarge {
        actual: usize,
        maximum: usize,
    },
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
            Self::InvalidSessionKeyLength { actual, expected } => {
                write!(
                    formatter,
                    "worker session key is {actual} bytes; expected {expected}"
                )
            }
            Self::WeakSessionKey => formatter.write_str("worker session key must not be all zero"),
            Self::InvalidSequence => formatter.write_str("worker frame sequence must be nonzero"),
            Self::SequenceExhausted => formatter.write_str("worker frame sequence is exhausted"),
            Self::UnexpectedSequence { expected, actual } => {
                write!(
                    formatter,
                    "unexpected worker frame sequence: expected {expected}, got {actual}"
                )
            }
            Self::InvalidAuthenticationTag => {
                formatter.write_str("worker frame authentication tag is invalid")
            }
            Self::DuplicateRequest(request_id) => {
                write!(formatter, "duplicate worker request: {request_id}")
            }
            Self::DuplicateResult(request_id) => {
                write!(formatter, "duplicate worker result: {request_id}")
            }
            Self::OperationResultMismatch => {
                formatter.write_str("worker operation result does not match its dispatch")
            }
            Self::UnsupportedOperationJournalVersion(version) => {
                write!(formatter, "unsupported worker operation journal version: {version}")
            }
            Self::OperationJournalTooLarge { actual, maximum } => write!(
                formatter,
                "worker operation journal is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::OperationJournalScopeMismatch { expected, actual } => write!(
                formatter,
                "worker operation journal scope mismatch: expected {expected}, got {actual}"
            ),
            Self::TooManyWorkerOperations { maximum } => {
                write!(formatter, "worker operation journal exceeds {maximum} records")
            }
            Self::InvalidOperationFingerprint => {
                formatter.write_str("worker operation journal has an invalid input fingerprint")
            }
            Self::DuplicateOperationKey(operation_key) => {
                write!(formatter, "duplicate worker operation key: {operation_key}")
            }
            Self::UnknownOperation(operation_key) => {
                write!(formatter, "unknown worker operation: {operation_key}")
            }
            Self::OperationIdentityMismatch(operation_key) => write!(
                formatter,
                "worker operation key was reused with a different tool or input: {operation_key}"
            ),
            Self::InvalidWorkerOperationTransition {
                operation_key,
                current,
                observed,
            } => write!(
                formatter,
                "invalid worker operation transition for {operation_key}: {current:?} to {observed:?}"
            ),
            Self::PayloadFormatMismatch { expected, actual } => {
                write!(
                    formatter,
                    "worker payload format mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            Self::InvalidJsonEnvelope => {
                formatter.write_str("JSON worker payload must be an object or array")
            }
            Self::InvalidOperationFailure => {
                formatter.write_str("worker operation failure message must not be empty")
            }
            Self::OperationFailureTooLarge { actual, maximum } => write!(
                formatter,
                "worker operation failure is {actual} bytes; maximum is {maximum} bytes"
            ),
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

fn ensure_operation_identity(
    record: &WorkerOperationRecord,
    request: &OperationDispatchRequest,
    input_fingerprint: &str,
) -> Result<(), ProtocolError> {
    if record.tool != request.tool || record.input_fingerprint != input_fingerprint {
        return Err(ProtocolError::OperationIdentityMismatch(
            request.operation_key.clone(),
        ));
    }
    Ok(())
}

fn worker_operation_input_fingerprint(payload: &ToolPayload) -> Result<String, ProtocolError> {
    let input = canonical_operation_input_bytes(payload)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"splash-worker-operation-input-v1");
    hasher.update(&input);
    Ok(hasher.finalize().to_hex().to_string())
}

/// Produces the stable byte representation used for durable operation input
/// identity. Text retains its exact UTF-8 bytes; JSON is recursively
/// canonicalized with object keys in sorted order.
pub fn canonical_operation_input_bytes(payload: &ToolPayload) -> Result<Vec<u8>, ProtocolError> {
    payload.validate_for(payload.format())?;
    let mut encoded = Vec::new();
    match payload {
        ToolPayload::Text(value) => {
            encoded.extend_from_slice(b"text");
            append_worker_operation_component(&mut encoded, value.as_bytes());
        }
        ToolPayload::Json(value) => {
            encoded.extend_from_slice(b"json");
            let json = canonical_json_bytes(value)?;
            append_worker_operation_component(&mut encoded, &json);
        }
    }
    Ok(encoded)
}

fn append_worker_operation_component(encoded: &mut Vec<u8>, bytes: &[u8]) {
    encoded.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    encoded.extend_from_slice(bytes);
}

fn canonical_json_bytes(value: &JsonValue) -> Result<Vec<u8>, ProtocolError> {
    let mut encoded = Vec::new();
    write_canonical_json(value, &mut encoded)?;
    Ok(encoded)
}

fn write_canonical_json(value: &JsonValue, encoded: &mut Vec<u8>) -> Result<(), ProtocolError> {
    match value {
        JsonValue::Array(values) => {
            encoded.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    encoded.push(b',');
                }
                write_canonical_json(value, encoded)?;
            }
            encoded.push(b']');
        }
        JsonValue::Object(values) => {
            encoded.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    encoded.push(b',');
                }
                serde_json::to_writer(&mut *encoded, key)
                    .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
                encoded.push(b':');
                write_canonical_json(value, encoded)?;
            }
            encoded.push(b'}');
        }
        _ => serde_json::to_writer(encoded, value)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?,
    }
    Ok(())
}

fn is_blake3_fingerprint(value: &str) -> bool {
    value.len() == blake3::OUT_LEN * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use splash_storage::{
        AuthenticatedStore, StorageKey, StorageKeyId, StorageKeyring, StorageRecordKey,
        VolatileMemoryStore, STORAGE_KEY_BYTES,
    };

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

    fn operation_request(
        request_id: &str,
        operation_key: &str,
        payload: ToolPayload,
    ) -> OperationDispatchRequest {
        OperationDispatchRequest::new("session-1", request_id, "math.add", operation_key, payload)
            .unwrap()
    }

    #[test]
    fn operation_dispatch_is_capability_checked_and_binds_its_status() {
        let request = operation_request(
            "operation-request-1",
            "release-42-add",
            ToolPayload::Json(json!({"left": 20, "right": 22})),
        );
        let mut authorizer = SessionAuthorizer::new(manifest()).unwrap();
        let authorized = authorizer.authorize_operation(request.clone()).unwrap();
        assert_eq!(authorizer.calls_for("math.add"), 1);

        let wrong_operation = OperationReconcileResult::new(
            "session-1",
            "operation-request-1",
            "math.add",
            "other-operation",
            OperationStatus::Running,
        )
        .unwrap();
        assert_eq!(
            authorizer
                .validate_operation_result(&authorized, &wrong_operation)
                .unwrap_err(),
            ProtocolError::OperationResultMismatch
        );

        let oversized = OperationReconcileResult::new(
            "session-1",
            "operation-request-1",
            "math.add",
            "release-42-add",
            OperationStatus::Succeeded {
                payload: ToolPayload::Json(json!({"body": "x".repeat(256)})),
            },
        )
        .unwrap();
        assert!(matches!(
            authorizer.validate_operation_result(&authorized, &oversized),
            Err(ProtocolError::OutputTooLarge { .. })
        ));

        let running = OperationReconcileResult::new(
            "session-1",
            "operation-request-1",
            "math.add",
            "release-42-add",
            OperationStatus::Running,
        )
        .unwrap();
        authorizer
            .validate_operation_result(&authorized, &running)
            .unwrap();
        assert_eq!(
            authorizer
                .validate_operation_result(&authorized, &running)
                .unwrap_err(),
            ProtocolError::DuplicateResult("operation-request-1".to_owned())
        );

        let message = WorkerMessage::DispatchOperation { request };
        let encoded = message.to_json_line().unwrap();
        assert_eq!(WorkerMessage::from_json_line(&encoded).unwrap(), message);
    }

    #[test]
    fn worker_operation_journal_deduplicates_exact_dispatches() {
        let reordered_left: JsonValue = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        let reordered_right: JsonValue = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(
            worker_operation_input_fingerprint(&ToolPayload::Json(reordered_left)).unwrap(),
            worker_operation_input_fingerprint(&ToolPayload::Json(reordered_right)).unwrap(),
        );

        let request = operation_request(
            "operation-request-1",
            "release-42-add",
            ToolPayload::Json(json!({"token": "private input", "left": 20, "right": 22})),
        );
        let mut authorizer = SessionAuthorizer::new(manifest()).unwrap();
        let authorized = authorizer.authorize_operation(request.clone()).unwrap();
        let mut journal = WorkerOperationJournal::new("tenant-release").unwrap();

        assert_eq!(
            journal.admit(&authorized).unwrap(),
            WorkerOperationAdmission::Dispatch
        );
        let encoded = journal.to_json().unwrap();
        assert!(!encoded.contains("private input"));
        let restored =
            WorkerOperationJournal::from_json_for_scope(&encoded, "tenant-release").unwrap();
        assert_eq!(restored, journal);
        assert_eq!(
            WorkerOperationJournal::from_json_for_scope(&encoded, "tenant-other").unwrap_err(),
            ProtocolError::OperationJournalScopeMismatch {
                expected: "tenant-other".to_owned(),
                actual: "tenant-release".to_owned(),
            }
        );
        assert_eq!(
            journal.admit(&authorized).unwrap(),
            WorkerOperationAdmission::Existing {
                state: WorkerOperationState::Pending,
            }
        );

        assert_eq!(
            journal
                .observe(&authorized, OperationStatus::Running)
                .unwrap(),
            WorkerOperationState::Running
        );
        let succeeded = OperationStatus::Succeeded {
            payload: ToolPayload::Json(json!({"total": 42})),
        };
        assert_eq!(
            journal.observe(&authorized, succeeded.clone()).unwrap(),
            WorkerOperationState::Succeeded {
                payload: ToolPayload::Json(json!({"total": 42})),
            }
        );
        assert_eq!(
            journal.admit(&authorized).unwrap(),
            WorkerOperationAdmission::Existing {
                state: WorkerOperationState::Succeeded {
                    payload: ToolPayload::Json(json!({"total": 42})),
                },
            }
        );
        assert_eq!(
            journal.observe(&authorized, succeeded).unwrap(),
            WorkerOperationState::Succeeded {
                payload: ToolPayload::Json(json!({"total": 42})),
            }
        );
        assert_eq!(journal.records().len(), 1);
    }

    #[test]
    fn worker_operation_journal_rejects_identity_drift_and_terminal_rewrites() {
        let request = operation_request(
            "operation-request-1",
            "release-42-add",
            ToolPayload::Json(json!({"left": 20, "right": 22})),
        );
        let mut authorizer = SessionAuthorizer::new(manifest()).unwrap();
        let authorized = authorizer.authorize_operation(request).unwrap();
        let mut journal = WorkerOperationJournal::new("tenant-release").unwrap();
        journal.admit(&authorized).unwrap();

        let changed_request = operation_request(
            "operation-request-2",
            "release-42-add",
            ToolPayload::Json(json!({"left": 20, "right": 23})),
        );
        let mut changed_authorizer = SessionAuthorizer::new(manifest()).unwrap();
        let changed = changed_authorizer
            .authorize_operation(changed_request)
            .unwrap();
        assert_eq!(
            journal.admit(&changed).unwrap_err(),
            ProtocolError::OperationIdentityMismatch("release-42-add".to_owned())
        );

        journal
            .observe(
                &authorized,
                OperationStatus::Succeeded {
                    payload: ToolPayload::Json(json!({"total": 42})),
                },
            )
            .unwrap();
        assert_eq!(
            journal
                .observe(
                    &authorized,
                    OperationStatus::Failed {
                        message: "late failure".to_owned(),
                    },
                )
                .unwrap_err(),
            ProtocolError::InvalidWorkerOperationTransition {
                operation_key: "release-42-add".to_owned(),
                current: WorkerOperationStateKind::Succeeded,
                observed: WorkerOperationStateKind::Failed,
            }
        );
        assert_eq!(
            WorkerOperationJournal::from_json(&"x".repeat(MAX_WORKER_OPERATION_JOURNAL_BYTES + 1))
                .unwrap_err(),
            ProtocolError::OperationJournalTooLarge {
                actual: MAX_WORKER_OPERATION_JOURNAL_BYTES + 1,
                maximum: MAX_WORKER_OPERATION_JOURNAL_BYTES,
            }
        );
    }

    #[test]
    fn worker_operation_journal_rechecks_replayed_state_against_current_grants() {
        let request = operation_request(
            "operation-request-1",
            "release-42-add",
            ToolPayload::Json(json!({"left": 20, "right": 22})),
        );
        let mut wide_authorizer = SessionAuthorizer::new(manifest()).unwrap();
        let wide = wide_authorizer.authorize_operation(request).unwrap();
        let mut journal = WorkerOperationJournal::new("tenant-release").unwrap();
        journal.admit(&wide).unwrap();
        journal
            .observe(
                &wide,
                OperationStatus::Succeeded {
                    payload: ToolPayload::Json(json!({"body": "x".repeat(64)})),
                },
            )
            .unwrap();

        let replay = operation_request(
            "operation-request-2",
            "release-42-add",
            ToolPayload::Json(json!({"left": 20, "right": 22})),
        );
        let mut narrow_grant = json_grant();
        narrow_grant.max_output_bytes = 16;
        let narrow_manifest = CapabilityManifest::new("session-1", vec![narrow_grant]).unwrap();
        let mut narrow_authorizer = SessionAuthorizer::new(narrow_manifest).unwrap();
        let narrow = narrow_authorizer.authorize_operation(replay).unwrap();

        assert!(matches!(
            journal.admit(&narrow),
            Err(ProtocolError::OutputTooLarge { maximum: 16, .. })
        ));
    }

    #[test]
    fn worker_operation_journal_restores_from_authenticated_storage() {
        let request = operation_request(
            "operation-request-1",
            "release-42-add",
            ToolPayload::Json(json!({"left": 20, "right": 22})),
        );
        let mut authorizer = SessionAuthorizer::new(manifest()).unwrap();
        let authorized = authorizer.authorize_operation(request).unwrap();
        let mut journal = WorkerOperationJournal::new("tenant-release").unwrap();
        journal.admit(&authorized).unwrap();
        journal
            .observe(&authorized, OperationStatus::Running)
            .unwrap();

        let record_key = StorageRecordKey::new("worker-journal", "tenant-release").unwrap();
        let keyring = StorageKeyring::new(
            StorageKeyId::new("storage-v1").unwrap(),
            StorageKey::from_bytes([29; STORAGE_KEY_BYTES]),
        );
        let mut store = AuthenticatedStore::new(VolatileMemoryStore::default(), keyring);
        let encoded = journal.to_json().unwrap();
        let persisted = store.create(&record_key, encoded.as_bytes()).unwrap();
        assert_eq!(persisted.revision(), 1);

        let restored_record = store.load(&record_key).unwrap().unwrap();
        let restored_json = std::str::from_utf8(restored_record.payload()).unwrap();
        let restored =
            WorkerOperationJournal::from_json_for_scope(restored_json, "tenant-release").unwrap();
        assert_eq!(restored, journal);
        assert_eq!(
            restored.operation("release-42-add").unwrap().state(),
            &WorkerOperationState::Running
        );
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
        let encoded = format!(
            r#"{{"type":"invoke","invocation":{{"protocol_version":{PROTOCOL_VERSION},"session_id":"bad session","request_id":"request-1","tool":"math.add","payload":{{"format":"json","value":{{"left":20,"right":22}}}}}}}}"#
        );

        assert!(matches!(
            WorkerMessage::from_json_line(&encoded),
            Err(ProtocolError::InvalidToken {
                field: "session id",
                ..
            })
        ));
    }

    fn session_key(byte: u8) -> SessionKey {
        SessionKey::from_bytes([byte; AUTH_TAG_BYTES]).unwrap()
    }

    #[test]
    fn authenticated_frames_round_trip_with_directional_sequence_numbers() {
        let mut host =
            SessionAuthenticator::new("session-1", session_key(7), SessionRole::Host).unwrap();
        let mut worker =
            SessionAuthenticator::new("session-1", session_key(7), SessionRole::Worker).unwrap();
        let request = WorkerMessage::OpenSession {
            manifest: manifest(),
        };

        let outbound = host.seal(request.clone()).unwrap();
        let encoded = outbound.to_json_line().unwrap();
        let decoded = AuthenticatedWorkerMessage::from_json_line(&encoded).unwrap();

        assert_eq!(worker.open(decoded).unwrap(), request);

        let response = WorkerMessage::CloseSession {
            protocol_version: PROTOCOL_VERSION,
            session_id: "session-1".to_owned(),
        };
        let outbound = worker.seal(response.clone()).unwrap();
        assert_eq!(host.open(outbound).unwrap(), response);
    }

    #[test]
    fn authenticated_frames_reject_tampering_reflection_and_replay() {
        let mut host =
            SessionAuthenticator::new("session-1", session_key(7), SessionRole::Host).unwrap();
        let mut worker =
            SessionAuthenticator::new("session-1", session_key(7), SessionRole::Worker).unwrap();
        let frame = host
            .seal(WorkerMessage::OpenSession {
                manifest: manifest(),
            })
            .unwrap();

        let mut tampered = frame.clone();
        tampered.message = WorkerMessage::CloseSession {
            protocol_version: PROTOCOL_VERSION,
            session_id: "session-1".to_owned(),
        };
        assert_eq!(
            worker.open(tampered).unwrap_err(),
            ProtocolError::InvalidAuthenticationTag
        );
        assert_eq!(
            host.open(frame.clone()).unwrap_err(),
            ProtocolError::InvalidAuthenticationTag
        );

        worker.open(frame.clone()).unwrap();
        assert_eq!(
            worker.open(frame).unwrap_err(),
            ProtocolError::UnexpectedSequence {
                expected: 2,
                actual: 1,
            }
        );
    }

    #[test]
    fn authenticated_frames_reject_wrong_session_keys_without_advancing_state() {
        let mut host =
            SessionAuthenticator::new("session-1", session_key(7), SessionRole::Host).unwrap();
        let frame = host
            .seal(WorkerMessage::OpenSession {
                manifest: manifest(),
            })
            .unwrap();
        let mut wrong_worker =
            SessionAuthenticator::new("session-1", session_key(8), SessionRole::Worker).unwrap();
        let mut correct_worker =
            SessionAuthenticator::new("session-1", session_key(7), SessionRole::Worker).unwrap();

        assert_eq!(
            wrong_worker.open(frame.clone()).unwrap_err(),
            ProtocolError::InvalidAuthenticationTag
        );
        assert!(correct_worker.open(frame).is_ok());
        assert_eq!(
            SessionKey::from_bytes([0; AUTH_TAG_BYTES]).unwrap_err(),
            ProtocolError::WeakSessionKey
        );
        assert_eq!(
            SessionKey::from_slice(&[7; AUTH_TAG_BYTES - 1]).unwrap_err(),
            ProtocolError::InvalidSessionKeyLength {
                actual: AUTH_TAG_BYTES - 1,
                expected: AUTH_TAG_BYTES,
            }
        );
    }

    #[test]
    fn authenticated_reconciliation_binds_status_to_the_requested_operation() {
        let request = OperationReconcileRequest::new(
            "session-1",
            "reconcile-1",
            "text.remote",
            "operation-1",
        )
        .unwrap();
        let mut host =
            SessionAuthenticator::new("session-1", session_key(7), SessionRole::Host).unwrap();
        let mut worker =
            SessionAuthenticator::new("session-1", session_key(7), SessionRole::Worker).unwrap();

        let frame = host
            .seal(WorkerMessage::ReconcileOperation {
                request: request.clone(),
            })
            .unwrap();
        assert_eq!(
            worker.open(frame).unwrap(),
            WorkerMessage::ReconcileOperation {
                request: request.clone(),
            }
        );

        let result = OperationReconcileResult::new(
            "session-1",
            "reconcile-1",
            "text.remote",
            "operation-1",
            OperationStatus::Succeeded {
                payload: ToolPayload::Json(json!({"status": "done"})),
            },
        )
        .unwrap();
        let response = worker
            .seal(WorkerMessage::ReconciledOperation {
                result: result.clone(),
            })
            .unwrap();

        assert_eq!(
            host.open(response).unwrap(),
            WorkerMessage::ReconciledOperation {
                result: result.clone(),
            }
        );
        assert!(result.matches_request(&request));
        let wrong_request = OperationReconcileRequest::new(
            "session-1",
            "reconcile-2",
            "text.remote",
            "operation-1",
        )
        .unwrap();
        assert!(!result.matches_request(&wrong_request));

        assert_eq!(
            OperationReconcileResult::new(
                "session-1",
                "reconcile-1",
                "text.remote",
                "operation-1",
                OperationStatus::Failed {
                    message: String::new(),
                },
            )
            .unwrap_err(),
            ProtocolError::InvalidOperationFailure
        );
        assert_eq!(
            OperationReconcileResult::new(
                "session-1",
                "reconcile-1",
                "text.remote",
                "operation-1",
                OperationStatus::Succeeded {
                    payload: ToolPayload::Json(json!(42)),
                },
            )
            .unwrap_err(),
            ProtocolError::InvalidJsonEnvelope
        );
    }
}
