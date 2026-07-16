//! Sealed workflow runtime for mobile and embedded Splash hosts.
//!
//! [`crate::mobile::MobileWorkflowBuilder`] accepts reviewed, app-provided local adapters
//! during setup. Its [`crate::mobile::MobileWorkflowBuilder::build`] result exposes workflow
//! planning, bounded review, named per-step policies, checkpoints, bounded
//! JSON dataflow, and execution, but never the underlying
//! [`CapabilityRuntime`]. It therefore cannot register a new tool, dispatch
//! an external operation, or issue a broader manual lease after sealing.
//!
//! This is a capability boundary, not operating-system containment. App-local
//! adapters run with the embedding application's authority and must not expose
//! arbitrary executable, filesystem, network-origin, plugin, or crate
//! selectors to Splash source.

use std::num::NonZeroUsize;

use serde::{de::DeserializeOwned, Serialize};
use splash_capabilities::{
    fixed_file_catalog::FixedFileCatalog, AuditLog, CapabilityCatalogLimits, CapabilityRuntime,
    JsonToolContract, JsonValue, ToolDescriptor, ToolError, ToolMetadata, ToolPolicy,
    ToolRegistrationError, ToolRequest,
};
use splash_core::{ExecutionLimits, RuntimeError};

use crate::{
    Approval, WorkflowCheckpoint, WorkflowData, WorkflowDataContract, WorkflowDraft,
    WorkflowEngine, WorkflowError, WorkflowEventHistoryError, WorkflowEventLog, WorkflowPlan,
    WorkflowStep, WorkflowStepCapabilityPolicy, DEFAULT_MAX_WORKFLOW_EVENTS, MAX_WORKFLOW_EVENTS,
};

/// Setup-only builder for a sealed mobile or embedded workflow catalog.
///
/// The builder intentionally exposes only local adapter registration. Once
/// [`Self::build`] consumes it, no API exposes a mutable capability runtime or
/// an external-dispatch lifecycle.
pub struct MobileWorkflowBuilder {
    runtime: CapabilityRuntime,
    limits: ExecutionLimits,
    catalog_limits: CapabilityCatalogLimits,
    max_events: NonZeroUsize,
}

impl MobileWorkflowBuilder {
    /// Creates a builder with Splash's standard execution, pending-tool, and
    /// workflow-event bounds.
    pub fn new() -> Result<Self, RuntimeError> {
        Self::with_limits(
            ExecutionLimits::default(),
            splash_capabilities::DEFAULT_MAX_PENDING_TOOLS,
        )
    }

    /// Creates a builder with host-selected execution and pending-tool limits.
    ///
    /// `max_pending_tools` must be nonzero. The selected limits remain fixed
    /// for the sealed runtime's lifetime.
    pub fn with_limits(
        limits: ExecutionLimits,
        max_pending_tools: usize,
    ) -> Result<Self, RuntimeError> {
        Self::with_limits_and_catalog(
            limits,
            max_pending_tools,
            CapabilityCatalogLimits::default(),
        )
    }

    /// Creates a builder with explicit aggregate catalog limits in addition to
    /// execution and pending-tool limits.
    pub fn with_limits_and_catalog(
        limits: ExecutionLimits,
        max_pending_tools: usize,
        catalog_limits: CapabilityCatalogLimits,
    ) -> Result<Self, RuntimeError> {
        let runtime = CapabilityRuntime::with_limits_pending_and_catalog(
            limits,
            max_pending_tools,
            catalog_limits,
        )?;
        Ok(Self {
            runtime,
            limits,
            catalog_limits,
            max_events: NonZeroUsize::new(DEFAULT_MAX_WORKFLOW_EVENTS)
                .expect("default workflow event capacity is nonzero"),
        })
    }

    /// Sets the bounded in-memory capability-audit capacity before sealing.
    ///
    /// Audit eviction affects observability only. Hosts that require complete
    /// retention must export audit data into a separate durable sink.
    pub fn with_max_audit_events(
        mut self,
        max_audit_events: NonZeroUsize,
    ) -> Result<Self, RuntimeError> {
        self.runtime.set_max_audit_events(max_audit_events)?;
        Ok(self)
    }

    /// Sets the bounded in-memory workflow-event capacity before sealing.
    ///
    /// Workflow events are telemetry, not restart authority. Values above
    /// [`MAX_WORKFLOW_EVENTS`] are rejected before a runtime is created.
    pub fn with_max_workflow_events(
        mut self,
        max_events: NonZeroUsize,
    ) -> Result<Self, WorkflowEventHistoryError> {
        if max_events.get() > MAX_WORKFLOW_EVENTS {
            return Err(WorkflowEventHistoryError::CapacityTooLarge {
                requested: max_events.get(),
                maximum: MAX_WORKFLOW_EVENTS,
            });
        }
        self.max_events = max_events;
        Ok(self)
    }

    /// Registers one reviewed text adapter for the sealed local catalog.
    pub fn register_text_tool<F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&ToolRequest) -> Result<String, ToolError> + 'static,
    {
        self.runtime
            .register_tool_with_metadata(policy, metadata, handler)
    }

    /// Registers one bounded host-owned file catalog for the sealed workflow
    /// catalog.
    ///
    /// The catalog is consumed during setup, so a workflow can request only
    /// its reviewed opaque identifiers. It cannot add entries or select paths
    /// after [`Self::build`] seals the local adapter catalog.
    pub fn register_fixed_file_catalog_tool(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        catalog: FixedFileCatalog,
    ) -> Result<(), ToolRegistrationError> {
        self.runtime
            .register_fixed_file_catalog_tool(policy, metadata, catalog)
    }

    /// Registers one setup-selected HTTP endpoint catalog for the sealed
    /// workflow catalog.
    ///
    /// The catalog is consumed during setup, so a workflow can request only
    /// its reviewed opaque endpoint identifiers. It cannot select a URL,
    /// method, header, query, or redirect target after [`Self::build`] seals
    /// the local adapter catalog. This is API-level mediation, not OS
    /// containment.
    #[cfg(feature = "http-endpoint-catalog")]
    pub fn register_http_endpoint_catalog_tool(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        catalog: splash_capabilities::http_endpoint_catalog::HttpEndpointCatalog,
    ) -> Result<(), ToolRegistrationError> {
        self.runtime
            .register_http_endpoint_catalog_tool(policy, metadata, catalog)
    }

    /// Registers one setup-selected HTTPS endpoint catalog with a host-owned
    /// secret resolver for the sealed workflow catalog.
    ///
    /// The resolver is consumed during setup. Workflow steps can select only
    /// the reviewed opaque endpoint identifier through an approved tool grant;
    /// they cannot select or inspect a secret, header, URL, method, or redirect.
    #[cfg(feature = "http-endpoint-catalog")]
    pub fn register_http_endpoint_catalog_tool_with_secret_resolver<R>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        catalog: splash_capabilities::http_endpoint_catalog::HttpEndpointCatalog,
        secret_resolver: R,
    ) -> Result<(), ToolRegistrationError>
    where
        R: splash_capabilities::http_endpoint_catalog::HttpEndpointSecretResolver + 'static,
    {
        self.runtime
            .register_http_endpoint_catalog_tool_with_secret_resolver(
                policy,
                metadata,
                catalog,
                secret_resolver,
            )
    }

    /// Registers one reviewed JSON adapter with executable input and output
    /// contracts.
    pub fn register_json_tool<F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        contract: JsonToolContract,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&splash_capabilities::JsonToolRequest) -> Result<JsonValue, ToolError> + 'static,
    {
        self.runtime
            .register_validated_json_tool(policy, metadata, contract, handler)
    }

    /// Registers one reviewed typed Rust adapter with executable JSON wire
    /// contracts.
    pub fn register_typed_json_tool<I, O, F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        contract: JsonToolContract,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        I: DeserializeOwned + 'static,
        O: Serialize + 'static,
        F: FnMut(I) -> Result<O, ToolError> + 'static,
    {
        self.runtime
            .register_typed_json_tool_with_metadata(policy, metadata, contract, handler)
    }

    /// Seals the catalog and creates a workflow-only mobile runtime.
    ///
    /// The returned type does not expose adapter registration, external
    /// dispatch, manual lease issuance, or mutable runtime access.
    pub fn build(self) -> MobileWorkflowRuntime {
        let Self {
            runtime,
            limits,
            catalog_limits,
            max_events,
        } = self;
        let engine = WorkflowEngine::with_event_history_capacity(runtime, max_events)
            .expect("the builder validates workflow event capacity before sealing");
        MobileWorkflowRuntime {
            engine,
            limits,
            catalog_limits,
            max_events,
        }
    }
}

/// Host-owned workflow facade backed by a sealed local adapter catalog.
///
/// It supports planning, named least-privilege policy approval, checkpoints,
/// and sequential execution. It deliberately omits `WorkflowEngine::runtime`,
/// `runtime_mut`, manual lease APIs, and external-operation APIs, so sealed
/// mobile code cannot widen the adapter catalog after setup.
pub struct MobileWorkflowRuntime {
    engine: WorkflowEngine,
    limits: ExecutionLimits,
    catalog_limits: CapabilityCatalogLimits,
    max_events: NonZeroUsize,
}

impl MobileWorkflowRuntime {
    /// Returns the immutable source-execution limits selected at setup.
    pub const fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    /// Returns the immutable aggregate tool-catalog limits selected at setup.
    pub const fn catalog_limits(&self) -> CapabilityCatalogLimits {
        self.catalog_limits
    }

    /// Returns the immutable workflow-event capacity selected at setup.
    pub const fn max_workflow_events(&self) -> usize {
        self.max_events.get()
    }

    /// Returns the number of local deferred promises retained by the sealed
    /// runtime, including completed records awaiting VM garbage collection.
    pub fn pending_tools(&self) -> usize {
        self.engine.runtime().pending_tools()
    }

    /// Returns the configured cap for local deferred promises.
    pub fn max_pending_tools(&self) -> usize {
        self.engine.runtime().max_pending_tools()
    }

    /// Returns the immutable host-visible description of the sealed catalog.
    pub fn tool_catalog(&self) -> Vec<ToolDescriptor> {
        self.engine.runtime().tool_catalog()
    }

    /// Serializes the sealed host-visible catalog for an LLM or operator UI.
    pub fn tool_catalog_json(&self) -> Result<String, ToolError> {
        self.engine.runtime().tool_catalog_json()
    }

    /// Returns the bounded capability-audit view.
    pub fn audit(&self) -> AuditLog<'_> {
        self.engine.runtime().audit()
    }

    /// Returns the number of capability-audit events evicted from memory.
    pub fn dropped_audit_events(&self) -> u64 {
        self.engine.runtime().dropped_audit_events()
    }

    /// Returns the bounded workflow-event view.
    pub fn events(&self) -> WorkflowEventLog<'_> {
        self.engine.events()
    }

    /// Returns the number of workflow events evicted from memory.
    pub fn dropped_events(&self) -> u64 {
        self.engine.dropped_events()
    }

    /// Clears workflow telemetry without changing the catalog or authority.
    pub fn clear_events(&mut self) {
        self.engine.clear_events();
    }

    /// Creates a trusted workflow plan from host-provided steps.
    pub fn plan(&mut self, steps: Vec<WorkflowStep>) -> Result<WorkflowPlan, WorkflowError> {
        self.engine.plan(steps)
    }

    /// Converts a bounded data-only draft into a trusted mobile workflow plan.
    pub fn plan_draft(&mut self, draft: WorkflowDraft) -> Result<WorkflowPlan, WorkflowError> {
        self.engine.plan_draft(draft)
    }

    /// Approves a trusted plan with ordered host-selected policy bindings.
    ///
    /// This is the only approval form exposed by the mobile facade. Each
    /// policy can grant only names already present in the sealed catalog.
    pub fn approve_with_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        self.engine
            .approve_with_step_capability_policies(plan, policies)
    }

    /// Approves a bounded JSON dataflow context with ordered host-selected
    /// local-adapter policies.
    pub fn approve_dataflow_with_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        data: WorkflowData,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        self.engine
            .approve_dataflow_with_step_capability_policies(plan, data, policies)
    }

    /// Approves bounded JSON dataflow under a complete host-owned schema
    /// contract and ordered local-adapter policies.
    ///
    /// Contract configuration remains app code: this sealed facade does not
    /// accept a schema from Splash source or a workflow draft, and it does not
    /// expose a mutable capability runtime.
    pub fn approve_dataflow_with_contract_and_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        data: WorkflowData,
        data_contract: WorkflowDataContract,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        self.engine
            .approve_dataflow_with_contract_and_step_capability_policies(
                plan,
                data,
                data_contract,
                policies,
            )
    }

    /// Creates a bounded data-only checkpoint after a host-attested prefix.
    pub fn checkpoint_after(
        &mut self,
        plan: &WorkflowPlan,
        completed_step_count: usize,
    ) -> Result<WorkflowCheckpoint, WorkflowError> {
        self.engine.checkpoint_after(plan, completed_step_count)
    }

    /// Creates a dataflow checkpoint containing only a digest of the supplied
    /// bounded context, never its raw input or output values.
    pub fn dataflow_checkpoint_after(
        &mut self,
        plan: &WorkflowPlan,
        data: &WorkflowData,
        completed_step_count: usize,
    ) -> Result<WorkflowCheckpoint, WorkflowError> {
        self.engine
            .dataflow_checkpoint_after(plan, data, completed_step_count)
    }

    /// Creates a dataflow checkpoint bound to a host-owned schema contract.
    ///
    /// The serialized checkpoint retains only the contract digest, never its
    /// schema source or the raw dataflow context.
    pub fn dataflow_checkpoint_after_with_contract(
        &mut self,
        plan: &WorkflowPlan,
        data: &mut WorkflowData,
        data_contract: &WorkflowDataContract,
        completed_step_count: usize,
    ) -> Result<WorkflowCheckpoint, WorkflowError> {
        self.engine.dataflow_checkpoint_after_with_contract(
            plan,
            data,
            data_contract,
            completed_step_count,
        )
    }

    /// Approves the unexecuted suffix of a checkpointed plan with fresh,
    /// ordered host-selected policy bindings.
    pub fn approve_resume_with_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        self.engine
            .approve_resume_with_step_capability_policies(plan, checkpoint, policies)
    }

    /// Approves a dataflow checkpoint suffix using separately retained,
    /// fingerprint-matching context and fresh local-adapter policies.
    pub fn approve_dataflow_resume_with_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        data: WorkflowData,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        self.engine
            .approve_dataflow_resume_with_step_capability_policies(plan, checkpoint, data, policies)
    }

    /// Approves a dataflow checkpoint suffix under a host-owned schema
    /// contract and fresh local-adapter policies for the unexecuted suffix.
    pub fn approve_dataflow_resume_with_contract_and_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        data: WorkflowData,
        data_contract: WorkflowDataContract,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        self.engine
            .approve_dataflow_resume_with_contract_and_step_capability_policies(
                plan,
                checkpoint,
                data,
                data_contract,
                policies,
            )
    }

    /// Executes an approved plan through the sealed local catalog.
    ///
    /// Host-pump adapters are driven by the workflow engine. External tools
    /// cannot be registered through this builder, so a supported mobile plan
    /// cannot enter an external dispatch lifecycle.
    pub fn execute(
        &mut self,
        plan: &WorkflowPlan,
        approval: Approval,
    ) -> Result<(), WorkflowError> {
        self.engine.execute(plan, approval)
    }

    /// Executes a policy-approved bounded JSON dataflow through the sealed
    /// local catalog.
    pub fn execute_dataflow(
        &mut self,
        plan: &WorkflowPlan,
        approval: Approval,
    ) -> Result<WorkflowData, WorkflowError> {
        self.engine.execute_dataflow(plan, approval)
    }

    /// Executes the remaining suffix after checkpoint-bound policy approval.
    pub fn resume(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        approval: Approval,
    ) -> Result<(), WorkflowError> {
        self.engine.resume(plan, checkpoint, approval)
    }

    /// Executes a dataflow checkpoint suffix after matching policy approval.
    pub fn resume_dataflow(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        approval: Approval,
    ) -> Result<WorkflowData, WorkflowError> {
        self.engine.resume_dataflow(plan, checkpoint, approval)
    }

    /// Returns the current or most recently terminal host-owned dataflow
    /// context. Workflow telemetry remains data-free.
    pub fn dataflow_snapshot(&self) -> Option<&WorkflowData> {
        self.engine.dataflow_snapshot()
    }

    /// Takes the most recent terminal dataflow context.
    pub fn take_dataflow_snapshot(&mut self) -> Option<WorkflowData> {
        self.engine.take_dataflow_snapshot()
    }

    /// Reports whether a workflow execution is awaiting host intervention.
    ///
    /// This should remain false for catalogs built only through
    /// [`MobileWorkflowBuilder`], but is useful to retain as a defensive state
    /// check around failed or future integrations.
    pub fn has_suspended_execution(&self) -> bool {
        self.engine.has_suspended_execution()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(feature = "http-endpoint-catalog")]
    use std::io::{Read, Write};
    #[cfg(feature = "http-endpoint-catalog")]
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(feature = "http-endpoint-catalog")]
    use std::sync::mpsc::{self, Receiver};
    #[cfg(feature = "http-endpoint-catalog")]
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    #[cfg(feature = "http-endpoint-catalog")]
    use splash_capabilities::http_endpoint_catalog::{
        HttpEndpoint, HttpEndpointCatalog, HttpEndpointMethod, HttpEndpointSecret,
        HttpEndpointSecretStore,
    };
    use splash_capabilities::{
        fixed_file_catalog::FixedFileCatalog, json, AuditOutcome, CapabilityLeaseGrant,
        ToolStreamPolicy,
    };
    use splash_core::DEFAULT_INSTRUCTION_LIMIT;
    use splash_schema::JsonSchema;

    use super::*;
    use crate::{
        WorkflowDataContract, WorkflowEvent, WorkflowStepOutputContract, MAX_WORKFLOW_EVENTS,
    };

    #[derive(serde::Deserialize)]
    struct AddInput {
        left: i64,
        right: i64,
    }

    #[derive(serde::Serialize)]
    struct AddOutput {
        total: i64,
    }

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);

    struct TestFile {
        path: PathBuf,
    }

    impl TestFile {
        fn new(label: &str, bytes: &[u8]) -> Self {
            let sequence = NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "splash-mobile-workflow-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::write(&path, bytes).expect("test file writes");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[cfg(feature = "http-endpoint-catalog")]
    fn start_fixed_http_server() -> (String, Receiver<String>, JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("local listener binds");
        let address = listener.local_addr().expect("listener has an address");
        let (sender, receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("workflow reaches local server");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("server read timeout is configured");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while request.len() < 4 * 1024 {
                let read = stream.read(&mut buffer).expect("server reads request");
                assert!(read > 0, "client closes before complete request headers");
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            sender
                .send(String::from_utf8(request).expect("request is UTF-8"))
                .expect("test receives request");

            let body = br#"{"available":true}"#;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(header.as_bytes())
                .expect("server writes response header");
            stream.write_all(body).expect("server writes response body");
        });
        (
            format!("http://{address}/fixed/status?mode=reviewed"),
            receiver,
            server,
        )
    }

    fn add_contract() -> JsonToolContract {
        JsonToolContract::new(
            json!({
                "type": "object",
                "properties": {
                    "left": {"type": "integer"},
                    "right": {"type": "integer"}
                },
                "required": ["left", "right"],
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "properties": {"total": {"type": "integer"}},
                "required": ["total"],
                "additionalProperties": false
            }),
        )
        .expect("static schema is valid")
    }

    fn add_dataflow_contract() -> WorkflowDataContract {
        WorkflowDataContract::new(
            JsonSchema::compile(json!({
                "type": "object",
                "properties": {
                    "left": {"type": "integer"},
                    "right": {"type": "integer"}
                },
                "required": ["left", "right"],
                "additionalProperties": false
            }))
            .expect("input schema is valid"),
            [WorkflowStepOutputContract::new(
                "calculate",
                JsonSchema::compile(json!({
                    "type": "object",
                    "properties": {"total": {"type": "integer"}},
                    "required": ["total"],
                    "additionalProperties": false
                }))
                .expect("output schema is valid"),
            )],
        )
        .expect("static dataflow contract is within bounds")
    }

    #[test]
    fn seals_typed_local_adapters_behind_workflow_policy_approval() {
        let mut builder = MobileWorkflowBuilder::with_limits(
            ExecutionLimits {
                max_source_bytes: 32 * 1024,
                max_syntax_tokens: 4 * 1024,
                max_syntax_nesting: 64,
                instruction_limit: DEFAULT_INSTRUCTION_LIMIT,
                soft_timeout: Duration::from_millis(16),
                hard_timeout: Duration::from_millis(32),
                budget_sample_interval: 256,
            },
            4,
        )
        .expect("mobile limits are valid");
        builder
            .register_typed_json_tool(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds two reviewed integer fields."),
                add_contract(),
                |input: AddInput| {
                    Ok(AddOutput {
                        total: input.left + input.right,
                    })
                },
            )
            .expect("static adapter registers");

        let mut runtime = builder.build();
        let draft = WorkflowDraft::new(vec![WorkflowStep::new(
            "calculate",
            "use mod.tool\n\
             use mod.std.assert\n\
             let raw = tool.call_json(\"math.add\", {left: 20, right: 22})\n\
             let response = raw.parse_json()\n\
             assert(response.total == 42)",
        )])
        .expect("draft is bounded");
        let plan = runtime.plan_draft(draft).expect("plan is trusted");
        let approval = runtime
            .approve_with_step_capability_policies(
                &plan,
                vec![WorkflowStepCapabilityPolicy::new(
                    "calculate",
                    [CapabilityLeaseGrant::new("math.add", 1)],
                )],
            )
            .expect("policy is within the sealed catalog");

        runtime.execute(&plan, approval).expect("workflow succeeds");

        assert_eq!(runtime.limits().max_source_bytes, 32 * 1024);
        assert_eq!(runtime.limits().max_syntax_nesting, 64);
        assert_eq!(runtime.max_pending_tools(), 4);
        assert_eq!(runtime.pending_tools(), 0);
        assert_eq!(runtime.tool_catalog().len(), 1);
        assert_eq!(
            runtime.tool_catalog()[0].dispatch,
            splash_capabilities::ToolDispatch::HostPump
        );
        assert_eq!(runtime.audit().len(), 1);
        assert!(matches!(
            runtime.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn executes_bounded_dataflow_through_the_sealed_catalog() {
        let mut builder = MobileWorkflowBuilder::new().expect("default limits are valid");
        builder
            .register_typed_json_tool(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds reviewed integer fields."),
                add_contract(),
                |input: AddInput| {
                    Ok(AddOutput {
                        total: input.left + input.right,
                    })
                },
            )
            .expect("static adapter registers");
        let mut runtime = builder.build();
        let plan = runtime
            .plan(vec![WorkflowStep::new(
                "calculate",
                "use mod.tool\n\
                 let raw = tool.call_json(\"math.add\", workflow.input)\n\
                 let result = raw.parse_json()\n\
                 result",
            )])
            .expect("plan is valid");
        let data_contract = add_dataflow_contract();
        let approval = runtime
            .approve_dataflow_with_contract_and_step_capability_policies(
                &plan,
                WorkflowData::new(json!({"left": 20, "right": 22})).expect("input is bounded"),
                data_contract.clone(),
                vec![WorkflowStepCapabilityPolicy::new(
                    "calculate",
                    [CapabilityLeaseGrant::new("math.add", 1)],
                )],
            )
            .expect("policy is within the sealed catalog");

        let mut data = runtime
            .execute_dataflow(&plan, approval)
            .expect("dataflow succeeds");

        assert_eq!(data.output("calculate"), Some(&json!({"total": 42})));
        assert_eq!(runtime.dataflow_snapshot(), Some(&data));
        assert_eq!(runtime.audit().len(), 1);
        let checkpoint = runtime
            .dataflow_checkpoint_after_with_contract(&plan, &mut data, &data_contract, 1)
            .expect("contract-bound checkpoint is valid");
        let contract_fingerprint = data_contract.fingerprint();
        assert_eq!(
            checkpoint.data_contract_fingerprint(),
            Some(contract_fingerprint.as_str())
        );
    }

    #[test]
    fn drives_local_deferred_work_without_entering_external_suspension() {
        let mut builder = MobileWorkflowBuilder::new().expect("default limits are valid");
        builder
            .register_text_tool(
                ToolPolicy::new("text.echo"),
                ToolMetadata::new("Returns text through the workflow pump."),
                |request| Ok(request.input.clone()),
            )
            .expect("static adapter registers");
        let mut runtime = builder.build();
        let plan = runtime
            .plan(vec![WorkflowStep::new(
                "deferred",
                "use mod.tool\n\
                 use mod.std.assert\n\
                 let value = tool.start(\"text.echo\", \"ready\").await()\n\
                 assert(value == \"ready\")",
            )])
            .expect("trusted plan is valid");
        let approval = runtime
            .approve_with_step_capability_policies(
                &plan,
                vec![WorkflowStepCapabilityPolicy::new(
                    "deferred",
                    [CapabilityLeaseGrant::new("text.echo", 1)],
                )],
            )
            .expect("policy is within the sealed catalog");

        runtime.execute(&plan, approval).expect("workflow succeeds");

        assert!(!runtime.has_suspended_execution());
        assert_eq!(runtime.pending_tools(), 0);
        assert!(matches!(
            runtime.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn seals_fixed_file_catalogs_behind_workflow_policy_approval() {
        let file = TestFile::new("fixed-file", b"reviewed workflow data");
        let mut catalog = FixedFileCatalog::default();
        catalog
            .insert_path("guide", file.path())
            .expect("host file is registered during setup");

        let mut builder = MobileWorkflowBuilder::new().expect("default limits are valid");
        builder
            .register_fixed_file_catalog_tool(
                ToolPolicy::new("file.read"),
                ToolMetadata::new("Reads one reviewed local document."),
                catalog,
            )
            .expect("static fixed-file adapter registers");
        let mut runtime = builder.build();
        let plan = runtime
            .plan(vec![WorkflowStep::new(
                "read-guide",
                "use mod.tool\n\
                 use mod.std.assert\n\
                 assert(tool.call(\"file.read\", \"guide\") == \"reviewed workflow data\")",
            )])
            .expect("trusted plan is valid");
        let approval = runtime
            .approve_with_step_capability_policies(
                &plan,
                vec![WorkflowStepCapabilityPolicy::new(
                    "read-guide",
                    [CapabilityLeaseGrant::new("file.read", 1)],
                )],
            )
            .expect("fixed file read is explicitly approved");

        runtime.execute(&plan, approval).expect("workflow succeeds");

        assert_eq!(runtime.tool_catalog().len(), 1);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].tool, "file.read");
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
        assert!(!runtime.has_suspended_execution());
    }

    #[cfg(feature = "http-endpoint-catalog")]
    #[test]
    fn seals_fixed_http_endpoints_behind_workflow_policy_approval() {
        let (url, received, server) = start_fixed_http_server();
        let mut catalog = HttpEndpointCatalog::default();
        catalog
            .insert(
                HttpEndpoint::insecure_http("status", HttpEndpointMethod::Get, url)
                    .expect("local endpoint is configured during setup"),
            )
            .expect("endpoint is retained");

        let mut builder = MobileWorkflowBuilder::new().expect("default limits are valid");
        builder
            .register_http_endpoint_catalog_tool(
                ToolPolicy::json("net.status"),
                ToolMetadata::new("Gets one reviewed service status."),
                catalog,
            )
            .expect("static endpoint adapter registers");
        let mut runtime = builder.build();
        let plan = runtime
            .plan(vec![WorkflowStep::new(
                "check-status",
                "use mod.tool\n\
                 use mod.std.assert\n\
                 let raw = tool.call_json(\"net.status\", {endpoint: \"status\"})\n\
                 let response = raw.parse_json()\n\
                 assert(response.available == true)",
            )])
            .expect("trusted plan is valid");
        let approval = runtime
            .approve_with_step_capability_policies(
                &plan,
                vec![WorkflowStepCapabilityPolicy::new(
                    "check-status",
                    [CapabilityLeaseGrant::new("net.status", 1)],
                )],
            )
            .expect("fixed endpoint is explicitly approved");

        runtime.execute(&plan, approval).expect("workflow succeeds");

        let request = received
            .recv_timeout(Duration::from_secs(2))
            .expect("one fixed request reaches the server");
        server.join().expect("server completes");
        assert!(request.starts_with("GET /fixed/status?mode=reviewed HTTP/1.1\r\n"));
        let lower = request.to_ascii_lowercase();
        assert!(!lower.contains("authorization:"));
        assert!(!lower.contains("cookie:"));
        assert_eq!(runtime.tool_catalog().len(), 1);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].tool, "net.status");
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
        assert!(!runtime.has_suspended_execution());
    }

    #[cfg(feature = "http-endpoint-catalog")]
    #[test]
    fn seals_endpoint_secret_resolvers_without_workflow_metadata_disclosure() {
        let mut catalog = HttpEndpointCatalog::default();
        catalog
            .insert(
                HttpEndpoint::https(
                    "status",
                    HttpEndpointMethod::Get,
                    "https://api.example.test/v1/status?fixed=true",
                )
                .expect("reviewed endpoint is valid")
                .with_bearer_secret("release.auth")
                .expect("credential binds only to HTTPS"),
            )
            .expect("endpoint is retained");
        let mut secrets = HttpEndpointSecretStore::new();
        secrets
            .insert(
                "release.auth",
                HttpEndpointSecret::new("test-only-token-42").expect("test secret is valid"),
            )
            .expect("secret is retained during setup");

        let mut builder = MobileWorkflowBuilder::new().expect("default limits are valid");
        builder
            .register_http_endpoint_catalog_tool_with_secret_resolver(
                ToolPolicy::json("net.status"),
                ToolMetadata::new("Gets one reviewed service status."),
                catalog,
                secrets,
            )
            .expect("static endpoint adapter registers");
        let runtime = builder.build();

        let descriptor = runtime
            .tool_catalog_json()
            .expect("sealed workflow catalog serializes for the host");
        assert!(descriptor.contains("net.status"));
        assert!(!descriptor.contains("release.auth"));
        assert!(!descriptor.contains("test-only-token-42"));
        assert!(!descriptor.contains("api.example.test"));
    }

    #[test]
    fn dynamic_names_cannot_reach_an_ungranted_sealed_adapter() {
        let restricted_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_restricted_calls = restricted_calls.clone();
        let mut builder = MobileWorkflowBuilder::new().expect("default limits are valid");
        builder
            .register_text_tool(
                ToolPolicy::new("text.echo"),
                ToolMetadata::new("Returns text."),
                |request| Ok(request.input.clone()),
            )
            .expect("static adapter registers");
        builder
            .register_text_tool(
                ToolPolicy::new("shell.exec"),
                ToolMetadata::new("Must never run through this policy."),
                move |_| {
                    restricted_calls.set(restricted_calls.get() + 1);
                    Ok("must not run".to_owned())
                },
            )
            .expect("static adapter registers");
        let mut runtime = builder.build();
        let plan = runtime
            .plan(vec![WorkflowStep::new(
                "dynamic-call",
                "use mod.tool\nlet selected = \"shell.exec\"\ntool.call(selected, \"whoami\")",
            )])
            .expect("trusted plan is valid");
        let approval = runtime
            .approve_with_step_capability_policies(
                &plan,
                vec![WorkflowStepCapabilityPolicy::new(
                    "dynamic-call",
                    [CapabilityLeaseGrant::new("text.echo", 1)],
                )],
            )
            .expect("policy is within the sealed catalog");

        let error = runtime
            .execute(&plan, approval)
            .expect_err("call is denied");

        assert!(matches!(
            error,
            WorkflowError::StepFailed {
                ref step_id,
                completed_steps: 0,
                ..
            } if step_id == "dynamic-call"
        ));
        assert_eq!(observed_restricted_calls.get(), 0);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].tool, "shell.exec");
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn rejects_external_only_stream_configuration_during_static_setup() {
        let mut builder = MobileWorkflowBuilder::new().expect("default limits are valid");
        let policy = ToolPolicy::new("text.echo").with_stream(ToolStreamPolicy::default());

        assert!(builder
            .register_text_tool(
                policy,
                ToolMetadata::new("not an external tool"),
                |request| { Ok(request.input.clone()) }
            )
            .is_err());
    }

    #[test]
    fn named_policy_cannot_grant_an_absent_sealed_adapter() {
        let mut builder = MobileWorkflowBuilder::new().expect("default limits are valid");
        builder
            .register_text_tool(
                ToolPolicy::new("text.echo"),
                ToolMetadata::new("Returns text."),
                |request| Ok(request.input.clone()),
            )
            .expect("static adapter registers");
        let mut runtime = builder.build();
        let plan = runtime
            .plan(vec![WorkflowStep::new("pure", "let done = true")])
            .expect("trusted plan is valid");

        assert!(runtime
            .approve_with_step_capability_policies(
                &plan,
                vec![WorkflowStepCapabilityPolicy::new(
                    "pure",
                    [CapabilityLeaseGrant::new("shell.exec", 1)],
                )],
            )
            .is_err());
        assert_eq!(runtime.tool_catalog().len(), 1);
    }

    #[test]
    fn bounds_workflow_events_before_sealing() {
        let result = MobileWorkflowBuilder::new()
            .expect("default limits are valid")
            .with_max_workflow_events(
                NonZeroUsize::new(MAX_WORKFLOW_EVENTS + 1).expect("nonzero capacity"),
            );

        assert!(matches!(
            result,
            Err(WorkflowEventHistoryError::CapacityTooLarge {
                requested,
                maximum,
            }) if requested == MAX_WORKFLOW_EVENTS + 1 && maximum == MAX_WORKFLOW_EVENTS
        ));
    }
}
