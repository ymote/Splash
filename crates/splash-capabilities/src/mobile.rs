//! Static-catalog profile for mobile and embedded Splash hosts.
//!
//! A [`MobileRuntimeBuilder`] owns the setup phase for reviewed, app-provided
//! adapters. Calling [`MobileRuntimeBuilder::build`] consumes that builder and
//! yields a [`MobileRuntime`] without any registration or external-dispatch
//! API. Dynamic Splash source can still use the catalog through `mod.tool`,
//! but cannot add tools, claim work, or complete an externally dispatched
//! operation.
//!
//! This is a capability boundary, not operating-system containment. Every
//! adapter runs with the embedding application's authority. Do not expose an
//! arbitrary executable, filesystem, network-origin, plugin, or crate selector
//! through an app-provided adapter.

use serde::{de::DeserializeOwned, Serialize};
use splash_core::{Evaluation, ExecutionLimits, RuntimeError};

use crate::{
    CapabilityRuntime, JsonToolContract, JsonValue, PumpReport, ToolError, ToolMetadata,
    ToolPolicy, ToolRegistrationError, ToolRequest,
};

/// Setup-only builder for a static mobile or embedded capability catalog.
///
/// The builder has no external-tool registration methods. Structured tools
/// require an executable [`JsonToolContract`] so their input and output stay
/// bounded at the Rust adapter boundary.
pub struct MobileRuntimeBuilder {
    runtime: CapabilityRuntime,
    limits: ExecutionLimits,
}

impl MobileRuntimeBuilder {
    /// Creates a builder with Splash's standard execution and pending-tool
    /// bounds. Constrained devices can use [`Self::with_limits`] to lower both
    /// before source or adapters are accepted.
    pub fn new() -> Result<Self, RuntimeError> {
        Self::with_limits(ExecutionLimits::default(), crate::DEFAULT_MAX_PENDING_TOOLS)
    }

    /// Creates a builder with host-selected execution and pending-tool limits.
    ///
    /// `max_pending_tools` must be nonzero. The returned runtime preserves
    /// these limits for its complete lifetime because it does not expose a
    /// mutable underlying capability host.
    pub fn with_limits(
        limits: ExecutionLimits,
        max_pending_tools: usize,
    ) -> Result<Self, RuntimeError> {
        let runtime = CapabilityRuntime::with_limits_and_pending(limits, max_pending_tools)?;
        Ok(Self { runtime, limits })
    }

    /// Registers one reviewed text adapter for the static catalog.
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
        F: FnMut(&crate::JsonToolRequest) -> Result<JsonValue, ToolError> + 'static,
    {
        self.runtime
            .register_validated_json_tool(policy, metadata, contract, handler)
    }

    /// Registers one reviewed typed Rust adapter with executable JSON wire
    /// contracts. The contract validates before deserialization and after
    /// serialization, so Serde defaults cannot widen the script-visible API.
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

    /// Seals the app-provided catalog and returns a dynamic-source runtime.
    ///
    /// The resulting [`MobileRuntime`] has no method that can alter its tool
    /// catalog or begin an external operation.
    pub fn build(self) -> MobileRuntime {
        MobileRuntime {
            runtime: self.runtime,
            limits: self.limits,
        }
    }
}

/// Dynamic Splash runtime backed by a sealed, app-provided local catalog.
///
/// Use [`Self::pump`] from the application's event loop after a script has
/// suspended on `tool.start(...).await()`. One call runs at most one queued
/// adapter, preserving a bounded scheduling point on mobile and embedded
/// event loops.
pub struct MobileRuntime {
    runtime: CapabilityRuntime,
    limits: ExecutionLimits,
}

impl MobileRuntime {
    /// Evaluates canonical Splash source against the sealed tool catalog.
    pub fn eval(&mut self, source: &str) -> Result<Evaluation, RuntimeError> {
        self.runtime.eval(source)
    }

    /// Returns the immutable execution bounds selected during setup.
    pub const fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    /// Returns the maximum number of deferred local calls retained at once.
    pub fn max_pending_tools(&self) -> usize {
        self.runtime.max_pending_tools()
    }

    /// Returns the number of retained local promise records, including
    /// completed promises until the VM collects them.
    pub fn pending_tools(&self) -> usize {
        self.runtime.pending_tools()
    }

    /// Reclaims unreachable values and settled promise records at a
    /// host-selected idle point.
    ///
    /// Collection is deliberately not implicit in [`Self::pump`], because a
    /// full VM sweep is not appropriate for every event-loop tick. It can take
    /// time proportional to the live script heap.
    pub fn collect_garbage(&mut self) {
        self.runtime.collect_garbage();
    }

    /// Runs at most one queued app-provided adapter and resumes its waiter.
    pub fn pump(&mut self) -> Result<PumpReport, RuntimeError> {
        self.runtime.pump()
    }

    /// Runs at most `max_completions` queued app-provided adapters.
    pub fn pump_up_to(&mut self, max_completions: usize) -> Result<PumpReport, RuntimeError> {
        self.runtime.pump_up_to(max_completions)
    }

    /// Returns the stable host-facing descriptions of the sealed catalog.
    pub fn tool_catalog(&self) -> Vec<crate::ToolDescriptor> {
        self.runtime.tool_catalog()
    }

    /// Serializes the sealed host-facing tool catalog for an LLM orchestrator
    /// or operator UI. Splash source has no catalog-discovery API.
    pub fn tool_catalog_json(&self) -> Result<String, ToolError> {
        self.runtime.tool_catalog_json()
    }

    /// Returns the bounded audit trail accumulated by the sealed host.
    pub fn audit(&self) -> &[crate::AuditEvent] {
        self.runtime.audit()
    }

    /// Clears the host-owned audit trail without changing catalog authority.
    pub fn clear_audit(&mut self) {
        self.runtime.clear_audit();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use splash_core::{DEFAULT_INSTRUCTION_LIMIT, DEFAULT_MAX_SOURCE_BYTES};

    use super::*;
    use crate::{json, ToolDataFormat, ToolDispatch};

    #[derive(serde::Deserialize)]
    struct AddInput {
        left: i64,
        right: i64,
    }

    #[derive(serde::Serialize)]
    struct AddOutput {
        total: i64,
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

    #[test]
    fn seals_a_typed_static_catalog_for_dynamic_dataflow() {
        let mut builder = MobileRuntimeBuilder::with_limits(
            ExecutionLimits {
                max_source_bytes: 32 * 1024,
                max_syntax_tokens: 4 * 1024,
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
        let report = runtime
            .eval(
                "use mod.tool\n\
                 use mod.std.assert\n\
                 let raw = tool.call_json(\"math.add\", {left: 20, right: 22})\n\
                 let response = raw.parse_json()\n\
                 assert(response.total == 42)",
            )
            .expect("canonical dynamic workflow succeeds");

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert_eq!(runtime.limits().max_source_bytes, 32 * 1024);
        assert_eq!(runtime.max_pending_tools(), 4);
        assert_eq!(runtime.pending_tools(), 0);
        assert_eq!(runtime.tool_catalog().len(), 1);
        assert_eq!(runtime.tool_catalog()[0].format, ToolDataFormat::Json);
        assert_eq!(runtime.tool_catalog()[0].dispatch, ToolDispatch::HostPump);
    }

    #[test]
    fn pumps_a_static_adapter_one_event_loop_tick_at_a_time() {
        let mut builder = MobileRuntimeBuilder::new().expect("default limits are valid");
        builder
            .register_text_tool(
                ToolPolicy::new("text.echo"),
                ToolMetadata::new("Returns text through the app event loop."),
                |request| Ok(request.input.clone()),
            )
            .expect("static text adapter registers");
        let mut runtime = builder.build();

        let initial = runtime
            .eval(
                "use mod.tool\n\
                 use mod.std.assert\n\
                 let value = tool.start(\"text.echo\", \"ready\").await()\n\
                 assert(value == \"ready\")",
            )
            .expect("initial evaluation succeeds");
        assert!(initial.suspended);
        assert_eq!(runtime.pending_tools(), 1);

        let pumped = runtime.pump().expect("one pump succeeds");
        assert_eq!(pumped.completed, 1);
        assert_eq!(pumped.resumed.len(), 1);
        assert!(pumped.resumed[0].completed());

        // A completed promise remains accounted for until the host chooses an
        // idle point to reclaim its no-longer-reachable handle.
        assert_eq!(runtime.pending_tools(), 1);
        runtime.collect_garbage();
        assert_eq!(runtime.pending_tools(), 0);
    }

    #[test]
    fn rejects_streaming_from_a_static_catalog() {
        let mut builder = MobileRuntimeBuilder::new().expect("default limits are valid");

        let error = builder
            .register_text_tool(
                ToolPolicy::new("text.echo").with_stream(crate::ToolStreamPolicy::default()),
                ToolMetadata::new("A streaming policy is external-only."),
                |request| Ok(request.input.clone()),
            )
            .expect_err("static adapters cannot stream externally");

        assert_eq!(
            error,
            ToolRegistrationError::InvalidPolicy("stream policy requires an external tool",)
        );
    }

    #[test]
    fn preserves_canonical_source_limits_after_catalog_sealing() {
        let mut runtime = MobileRuntimeBuilder::new()
            .expect("default limits are valid")
            .build();
        let oversized = "x".repeat(DEFAULT_MAX_SOURCE_BYTES + 1);

        assert!(matches!(
            runtime.eval(&oversized),
            Err(RuntimeError::SourceTooLarge { .. })
        ));
    }
}
