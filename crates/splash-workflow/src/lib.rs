#![forbid(unsafe_code)]

//! Host-owned workflow state for Splash.
//!
//! Scripts evaluate individual steps, but they cannot mint approval or skip
//! host policy. The event log remains in-memory, while bounded data-only
//! checkpoints let a host persist an explicitly attested completed prefix and
//! require fresh approval before a restart can execute the remaining steps.

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use splash_capabilities::CapabilityRuntime;
use splash_core::RuntimeError;

static NEXT_ENGINE_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum serialized checkpoint size accepted from durable storage.
pub const MAX_WORKFLOW_CHECKPOINT_BYTES: usize = 16 * 1024;
/// Maximum number of completed step IDs a checkpoint may contain.
pub const MAX_WORKFLOW_CHECKPOINT_STEPS: usize = 1024;
/// Maximum UTF-8 byte length of a workflow step ID.
pub const MAX_WORKFLOW_STEP_ID_BYTES: usize = 128;
/// Current serialized checkpoint format version.
pub const WORKFLOW_CHECKPOINT_FORMAT_VERSION: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowStep {
    pub id: String,
    pub source: String,
}

impl WorkflowStep {
    pub fn new(id: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            source: source.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowPlan {
    engine_id: u64,
    id: u64,
    fingerprint: String,
    steps: Vec<WorkflowStep>,
}

impl WorkflowPlan {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn steps(&self) -> &[WorkflowStep] {
        &self.steps
    }

    /// Stable BLAKE3 binding of the ordered step IDs and source text.
    ///
    /// The local plan ID is intentionally excluded so a plan recreated after
    /// a process restart can validate a durable checkpoint.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Durable, data-only record of a completed workflow-step prefix.
///
/// A checkpoint never includes an approval, capability grant, tool result,
/// runtime state, or opaque external operation ID. Loading one does not grant
/// permission to execute anything: resuming always requires a fresh,
/// checkpoint-bound [`Approval`] from the current host engine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCheckpoint {
    format_version: u8,
    plan_fingerprint: String,
    completed_step_ids: Vec<String>,
}

impl WorkflowCheckpoint {
    pub fn plan_fingerprint(&self) -> &str {
        &self.plan_fingerprint
    }

    pub fn completed_step_ids(&self) -> &[String] {
        &self.completed_step_ids
    }

    pub fn completed_step_count(&self) -> usize {
        self.completed_step_ids.len()
    }

    /// Encodes the checkpoint for host-owned durable storage.
    pub fn to_json(&self) -> Result<String, WorkflowCheckpointError> {
        self.validate_syntax()?;
        let Some(upper_bound) = self.encoded_size_upper_bound() else {
            return Err(WorkflowCheckpointError::TooLarge);
        };
        if upper_bound > MAX_WORKFLOW_CHECKPOINT_BYTES {
            return Err(WorkflowCheckpointError::TooLarge);
        }
        let encoded = serde_json::to_string(self).map_err(|_| WorkflowCheckpointError::Encoding)?;
        if encoded.len() > MAX_WORKFLOW_CHECKPOINT_BYTES {
            return Err(WorkflowCheckpointError::TooLarge);
        }
        Ok(encoded)
    }

    /// Decodes a bounded checkpoint from host-owned durable storage.
    ///
    /// Decoding checks format and structural bounds only. Use
    /// [`WorkflowEngine::approve_resume`] to bind the checkpoint to a trusted
    /// plan and create a fresh approval before it can be resumed.
    pub fn from_json(encoded: &str) -> Result<Self, WorkflowCheckpointError> {
        if encoded.len() > MAX_WORKFLOW_CHECKPOINT_BYTES {
            return Err(WorkflowCheckpointError::TooLarge);
        }
        let checkpoint: Self =
            serde_json::from_str(encoded).map_err(|_| WorkflowCheckpointError::InvalidEncoding)?;
        checkpoint.validate_syntax()?;
        Ok(checkpoint)
    }

    fn for_plan(
        plan: &WorkflowPlan,
        completed_step_count: usize,
    ) -> Result<Self, WorkflowCheckpointError> {
        if completed_step_count > plan.steps.len() {
            return Err(WorkflowCheckpointError::CompletedStepCountOutOfRange {
                completed: completed_step_count,
                total: plan.steps.len(),
            });
        }
        let checkpoint = Self {
            format_version: WORKFLOW_CHECKPOINT_FORMAT_VERSION,
            plan_fingerprint: plan.fingerprint.clone(),
            completed_step_ids: plan.steps[..completed_step_count]
                .iter()
                .map(|step| step.id.clone())
                .collect(),
        };
        checkpoint.validate_syntax()?;
        Ok(checkpoint)
    }

    fn validate_for(&self, plan: &WorkflowPlan) -> Result<(), WorkflowCheckpointError> {
        self.validate_syntax()?;
        if self.plan_fingerprint != plan.fingerprint {
            return Err(WorkflowCheckpointError::PlanMismatch);
        }
        if self.completed_step_ids.len() > plan.steps.len() {
            return Err(WorkflowCheckpointError::CompletedStepCountOutOfRange {
                completed: self.completed_step_ids.len(),
                total: plan.steps.len(),
            });
        }
        if self
            .completed_step_ids
            .iter()
            .zip(&plan.steps)
            .any(|(completed, step)| completed != &step.id)
        {
            return Err(WorkflowCheckpointError::StepPrefixMismatch);
        }
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), WorkflowCheckpointError> {
        if self.format_version != WORKFLOW_CHECKPOINT_FORMAT_VERSION {
            return Err(WorkflowCheckpointError::UnsupportedVersion(
                self.format_version,
            ));
        }
        if !is_plan_fingerprint(&self.plan_fingerprint) {
            return Err(WorkflowCheckpointError::InvalidPlanFingerprint);
        }
        if self.completed_step_ids.len() > MAX_WORKFLOW_CHECKPOINT_STEPS {
            return Err(WorkflowCheckpointError::TooManyCompletedSteps);
        }
        let mut seen = BTreeSet::new();
        for step_id in &self.completed_step_ids {
            if !is_valid_step_id(step_id) {
                return Err(WorkflowCheckpointError::InvalidStepId(step_id.clone()));
            }
            if !seen.insert(step_id) {
                return Err(WorkflowCheckpointError::DuplicateStepId(step_id.clone()));
            }
        }
        Ok(())
    }

    fn encoded_size_upper_bound(&self) -> Option<usize> {
        // IDs are restricted to ASCII by `is_valid_step_id`, so JSON does not
        // need to escape them. Reserve generous fixed structural overhead.
        let mut bytes = 128usize;
        for step_id in &self.completed_step_ids {
            bytes = bytes.checked_add(step_id.len().checked_add(3)?)?;
        }
        Some(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowCheckpointError {
    TooLarge,
    Encoding,
    InvalidEncoding,
    UnsupportedVersion(u8),
    InvalidPlanFingerprint,
    TooManyCompletedSteps,
    InvalidStepId(String),
    DuplicateStepId(String),
    CompletedStepCountOutOfRange { completed: usize, total: usize },
    PlanMismatch,
    StepPrefixMismatch,
}

impl Display for WorkflowCheckpointError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("workflow checkpoint exceeds its byte limit"),
            Self::Encoding => formatter.write_str("workflow checkpoint could not be encoded"),
            Self::InvalidEncoding => formatter.write_str("workflow checkpoint is not valid JSON"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported workflow checkpoint version: {version}"
                )
            }
            Self::InvalidPlanFingerprint => {
                formatter.write_str("workflow checkpoint has an invalid plan fingerprint")
            }
            Self::TooManyCompletedSteps => {
                formatter.write_str("workflow checkpoint has too many completed steps")
            }
            Self::InvalidStepId(step_id) => {
                write!(formatter, "invalid completed workflow step id: {step_id}")
            }
            Self::DuplicateStepId(step_id) => {
                write!(formatter, "duplicate completed workflow step id: {step_id}")
            }
            Self::CompletedStepCountOutOfRange { completed, total } => write!(
                formatter,
                "workflow checkpoint records {completed} completed steps for a {total}-step plan"
            ),
            Self::PlanMismatch => {
                formatter.write_str("workflow checkpoint belongs to another plan")
            }
            Self::StepPrefixMismatch => {
                formatter.write_str("workflow checkpoint does not match the plan step prefix")
            }
        }
    }
}

impl std::error::Error for WorkflowCheckpointError {}

/// An approval can only be produced by [`WorkflowEngine::approve`] or
/// [`WorkflowEngine::approve_resume`] and is consumed by one execution call.
#[derive(Debug)]
pub struct Approval {
    engine_id: u64,
    plan_id: u64,
    nonce: u64,
    kind: ApprovalKind,
}

#[derive(Debug)]
enum ApprovalKind {
    Plan,
    Checkpoint(WorkflowCheckpoint),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowEvent {
    Planned {
        plan_id: u64,
        step_count: usize,
    },
    Approved {
        plan_id: u64,
    },
    Checkpointed {
        plan_id: u64,
        completed_steps: usize,
    },
    ResumeApproved {
        plan_id: u64,
        completed_steps: usize,
    },
    Started {
        plan_id: u64,
    },
    Resumed {
        plan_id: u64,
        completed_steps: usize,
    },
    StepSucceeded {
        plan_id: u64,
        step_id: String,
    },
    StepSuspended {
        plan_id: u64,
        step_id: String,
        completed_steps: usize,
    },
    StepFailed {
        plan_id: u64,
        step_id: String,
        diagnostics: Vec<String>,
        completed_steps: usize,
    },
    Completed {
        plan_id: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowError {
    EmptyPlan,
    InvalidStepId(String),
    DuplicateStepId(String),
    PlanOwnershipMismatch,
    ApprovalMismatch,
    Checkpoint(WorkflowCheckpointError),
    Runtime(String),
    StepSuspended {
        step_id: String,
        completed_steps: usize,
    },
    StepFailed {
        step_id: String,
        diagnostics: Vec<String>,
        completed_steps: usize,
    },
}

impl Display for WorkflowError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPlan => formatter.write_str("workflow must have at least one step"),
            Self::InvalidStepId(id) => write!(formatter, "invalid workflow step id: {id}"),
            Self::DuplicateStepId(id) => write!(formatter, "duplicate workflow step id: {id}"),
            Self::PlanOwnershipMismatch => {
                formatter.write_str("workflow plan is not owned by this engine")
            }
            Self::ApprovalMismatch => {
                formatter.write_str("approval is not valid for this workflow")
            }
            Self::Checkpoint(error) => write!(formatter, "workflow checkpoint error: {error}"),
            Self::Runtime(message) => write!(formatter, "runtime error: {message}"),
            Self::StepSuspended { step_id, .. } => {
                write!(
                    formatter,
                    "workflow step suspended without runnable tool work: {step_id}"
                )
            }
            Self::StepFailed { step_id, .. } => {
                write!(formatter, "workflow step failed: {step_id}")
            }
        }
    }
}

impl std::error::Error for WorkflowError {}

impl From<RuntimeError> for WorkflowError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error.to_string())
    }
}

pub struct WorkflowEngine {
    engine_id: u64,
    runtime: CapabilityRuntime,
    events: Vec<WorkflowEvent>,
    next_plan_id: u64,
    next_approval_nonce: u64,
}

impl WorkflowEngine {
    pub fn new(runtime: CapabilityRuntime) -> Self {
        Self {
            engine_id: NEXT_ENGINE_ID.fetch_add(1, Ordering::Relaxed),
            runtime,
            events: Vec::new(),
            next_plan_id: 1,
            next_approval_nonce: 1,
        }
    }

    pub fn runtime(&self) -> &CapabilityRuntime {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut CapabilityRuntime {
        &mut self.runtime
    }

    pub fn events(&self) -> &[WorkflowEvent] {
        &self.events
    }

    pub fn plan(&mut self, steps: Vec<WorkflowStep>) -> Result<WorkflowPlan, WorkflowError> {
        validate_steps(&steps)?;

        let plan = WorkflowPlan {
            engine_id: self.engine_id,
            id: self.next_plan_id,
            fingerprint: plan_fingerprint(&steps),
            steps,
        };
        self.next_plan_id = self.next_plan_id.saturating_add(1);
        self.events.push(WorkflowEvent::Planned {
            plan_id: plan.id,
            step_count: plan.steps.len(),
        });
        Ok(plan)
    }

    pub fn approve(&mut self, plan: &WorkflowPlan) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        let approval = self.issue_approval(plan, ApprovalKind::Plan);
        self.events
            .push(WorkflowEvent::Approved { plan_id: plan.id });
        Ok(approval)
    }

    /// Builds a serializable, data-only checkpoint after a host-attested
    /// completed prefix. This does not persist or grant any capability.
    pub fn checkpoint_after(
        &mut self,
        plan: &WorkflowPlan,
        completed_step_count: usize,
    ) -> Result<WorkflowCheckpoint, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        let checkpoint = WorkflowCheckpoint::for_plan(plan, completed_step_count)
            .map_err(WorkflowError::Checkpoint)?;
        self.events.push(WorkflowEvent::Checkpointed {
            plan_id: plan.id,
            completed_steps: checkpoint.completed_step_count(),
        });
        Ok(checkpoint)
    }

    /// Validates a durable checkpoint against a trusted plan and creates an
    /// approval that is bound to that exact checkpoint instance.
    pub fn approve_resume(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        checkpoint
            .validate_for(plan)
            .map_err(WorkflowError::Checkpoint)?;
        let approval = self.issue_approval(plan, ApprovalKind::Checkpoint(checkpoint.clone()));
        self.events.push(WorkflowEvent::ResumeApproved {
            plan_id: plan.id,
            completed_steps: checkpoint.completed_step_count(),
        });
        Ok(approval)
    }

    pub fn execute(
        &mut self,
        plan: &WorkflowPlan,
        approval: Approval,
    ) -> Result<(), WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        if !self.approval_matches(plan, &approval) || !matches!(approval.kind, ApprovalKind::Plan) {
            return Err(WorkflowError::ApprovalMismatch);
        }

        self.events
            .push(WorkflowEvent::Started { plan_id: plan.id });
        self.execute_from(plan, 0)
    }

    /// Executes only the remaining step suffix after a freshly approved,
    /// validated checkpoint. A checkpoint alone cannot invoke this method.
    pub fn resume(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        approval: Approval,
    ) -> Result<(), WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        checkpoint
            .validate_for(plan)
            .map_err(WorkflowError::Checkpoint)?;
        if !self.approval_matches(plan, &approval) {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let ApprovalKind::Checkpoint(bound_checkpoint) = &approval.kind else {
            return Err(WorkflowError::ApprovalMismatch);
        };
        if bound_checkpoint != checkpoint {
            return Err(WorkflowError::ApprovalMismatch);
        }

        self.events.push(WorkflowEvent::Resumed {
            plan_id: plan.id,
            completed_steps: checkpoint.completed_step_count(),
        });
        self.execute_from(plan, checkpoint.completed_step_count())
    }

    fn issue_approval(&mut self, plan: &WorkflowPlan, kind: ApprovalKind) -> Approval {
        let approval = Approval {
            engine_id: self.engine_id,
            plan_id: plan.id,
            nonce: self.next_approval_nonce,
            kind,
        };
        self.next_approval_nonce = self.next_approval_nonce.saturating_add(1);
        approval
    }

    fn approval_matches(&self, plan: &WorkflowPlan, approval: &Approval) -> bool {
        self.owns_plan(plan)
            && approval.engine_id == self.engine_id
            && approval.plan_id == plan.id
            && approval.nonce != 0
    }

    fn owns_plan(&self, plan: &WorkflowPlan) -> bool {
        plan.engine_id == self.engine_id
    }

    fn execute_from(
        &mut self,
        plan: &WorkflowPlan,
        completed_step_count: usize,
    ) -> Result<(), WorkflowError> {
        for (step_index, step) in plan.steps.iter().enumerate().skip(completed_step_count) {
            let mut report = self.runtime.eval(&step.source)?;
            while report.succeeded() && report.suspended {
                let pumped = self.runtime.pump()?;
                let Some(resumed) = pumped.resumed.into_iter().last() else {
                    self.events.push(WorkflowEvent::StepSuspended {
                        plan_id: plan.id,
                        step_id: step.id.clone(),
                        completed_steps: step_index,
                    });
                    return Err(WorkflowError::StepSuspended {
                        step_id: step.id.clone(),
                        completed_steps: step_index,
                    });
                };
                report = resumed;
            }
            if !report.succeeded() {
                self.events.push(WorkflowEvent::StepFailed {
                    plan_id: plan.id,
                    step_id: step.id.clone(),
                    diagnostics: report.diagnostics.clone(),
                    completed_steps: step_index,
                });
                return Err(WorkflowError::StepFailed {
                    step_id: step.id.clone(),
                    diagnostics: report.diagnostics,
                    completed_steps: step_index,
                });
            }
            self.events.push(WorkflowEvent::StepSucceeded {
                plan_id: plan.id,
                step_id: step.id.clone(),
            });
        }
        self.events
            .push(WorkflowEvent::Completed { plan_id: plan.id });
        Ok(())
    }
}

fn plan_fingerprint(steps: &[WorkflowStep]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"splash-workflow-plan-v1");
    hasher.update(&(steps.len() as u64).to_be_bytes());
    for step in steps {
        update_plan_fingerprint_component(&mut hasher, step.id.as_bytes());
        update_plan_fingerprint_component(&mut hasher, step.source.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn update_plan_fingerprint_component(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn is_plan_fingerprint(value: &str) -> bool {
    value.len() == blake3::OUT_LEN * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_valid_step_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_WORKFLOW_STEP_ID_BYTES
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn validate_steps(steps: &[WorkflowStep]) -> Result<(), WorkflowError> {
    if steps.is_empty() {
        return Err(WorkflowError::EmptyPlan);
    }

    let mut seen = BTreeSet::new();
    for step in steps {
        if !is_valid_step_id(&step.id) {
            return Err(WorkflowError::InvalidStepId(step.id.clone()));
        }
        if !seen.insert(&step.id) {
            return Err(WorkflowError::DuplicateStepId(step.id.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use splash_capabilities::ToolPolicy;

    #[test]
    fn approved_plan_executes_steps_and_records_events() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "summarize",
                "use mod.tool\ntool.call(\"text.echo\", \"release notes\")",
            )])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        engine.execute(&plan, approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn checkpoint_round_trips_as_bounded_data_without_plan_source() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![
                WorkflowStep::new("prepare", "let release = \"internal release data\""),
                WorkflowStep::new("publish", "let published = true"),
            ])
            .unwrap();

        let checkpoint = engine.checkpoint_after(&plan, 1).unwrap();
        let encoded = checkpoint.to_json().unwrap();
        let decoded = WorkflowCheckpoint::from_json(&encoded).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        let object = value.as_object().unwrap();

        assert_eq!(decoded, checkpoint);
        assert_eq!(checkpoint.plan_fingerprint(), plan.fingerprint());
        assert_eq!(checkpoint.completed_step_ids(), ["prepare"]);
        assert_eq!(object.len(), 3);
        assert!(object.contains_key("format_version"));
        assert!(object.contains_key("plan_fingerprint"));
        assert!(object.contains_key("completed_step_ids"));
        assert!(!encoded.contains("internal release data"));
        assert!(!encoded.contains("approval"));
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Checkpointed {
                plan_id,
                completed_steps: 1,
            }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn checkpoint_resume_requires_a_fresh_checkpoint_bound_approval() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new("first", "use mod.tool\ntool.call(\"text.echo\", \"one\")"),
                WorkflowStep::new("second", "use mod.tool\ntool.call(\"text.echo\", \"two\")"),
            ])
            .unwrap();
        let checkpoint = engine.checkpoint_after(&plan, 1).unwrap();

        let full_approval = engine.approve(&plan).unwrap();
        assert_eq!(
            engine
                .resume(&plan, &checkpoint, full_approval)
                .unwrap_err(),
            WorkflowError::ApprovalMismatch
        );

        let resume_approval = engine.approve_resume(&plan, &checkpoint).unwrap();
        engine.resume(&plan, &checkpoint, resume_approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert!(matches!(
            engine.events().iter().rev().nth(2),
            Some(WorkflowEvent::Resumed {
                plan_id,
                completed_steps: 1,
            }) if *plan_id == plan.id()
        ));
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn durable_checkpoint_validates_a_recreated_plan_with_fresh_capabilities() {
        let steps = vec![
            WorkflowStep::new("first", "let first = 1"),
            WorkflowStep::new("second", "use mod.tool\ntool.call(\"text.echo\", \"two\")"),
        ];
        let mut original_engine = WorkflowEngine::new(CapabilityRuntime::default());
        original_engine
            .plan(vec![WorkflowStep::new("unrelated", "let unrelated = true")])
            .unwrap();
        let original_plan = original_engine.plan(steps.clone()).unwrap();
        let encoded = original_engine
            .checkpoint_after(&original_plan, 1)
            .unwrap()
            .to_json()
            .unwrap();

        let mut restarted_runtime = CapabilityRuntime::default();
        restarted_runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut restarted_engine = WorkflowEngine::new(restarted_runtime);
        let restarted_plan = restarted_engine.plan(steps).unwrap();
        let restored = WorkflowCheckpoint::from_json(&encoded).unwrap();

        assert_ne!(original_plan.id(), restarted_plan.id());
        assert_eq!(original_plan.fingerprint(), restarted_plan.fingerprint());
        let approval = restarted_engine
            .approve_resume(&restarted_plan, &restored)
            .unwrap();
        restarted_engine
            .resume(&restarted_plan, &restored, approval)
            .unwrap();

        assert_eq!(restarted_engine.runtime().audit().len(), 1);
    }

    #[test]
    fn checkpoint_approval_binds_the_exact_prefix_and_plan() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![
                WorkflowStep::new("first", "let first = 1"),
                WorkflowStep::new("second", "let second = 2"),
            ])
            .unwrap();
        let no_steps = engine.checkpoint_after(&plan, 0).unwrap();
        let first_step = engine.checkpoint_after(&plan, 1).unwrap();
        let approval = engine.approve_resume(&plan, &no_steps).unwrap();

        assert_eq!(
            engine.resume(&plan, &first_step, approval).unwrap_err(),
            WorkflowError::ApprovalMismatch
        );

        let changed_plan = engine
            .plan(vec![
                WorkflowStep::new("first", "let first = 1"),
                WorkflowStep::new("second", "let second = 3"),
            ])
            .unwrap();
        assert_eq!(
            engine.approve_resume(&changed_plan, &no_steps).unwrap_err(),
            WorkflowError::Checkpoint(WorkflowCheckpointError::PlanMismatch)
        );
    }

    #[test]
    fn checkpoint_decoder_enforces_its_input_boundary() {
        let oversized = "x".repeat(MAX_WORKFLOW_CHECKPOINT_BYTES + 1);
        assert_eq!(
            WorkflowCheckpoint::from_json(&oversized).unwrap_err(),
            WorkflowCheckpointError::TooLarge
        );

        let invalid = r#"{
            "format_version": 1,
            "plan_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "completed_step_ids": [],
            "unexpected": true
        }"#;
        assert_eq!(
            WorkflowCheckpoint::from_json(invalid).unwrap_err(),
            WorkflowCheckpointError::InvalidEncoding
        );

        let long_step_id = "a".repeat(MAX_WORKFLOW_STEP_ID_BYTES + 1);
        let invalid_step_id = serde_json::json!({
            "format_version": WORKFLOW_CHECKPOINT_FORMAT_VERSION,
            "plan_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "completed_step_ids": [long_step_id],
        })
        .to_string();
        assert_eq!(
            WorkflowCheckpoint::from_json(&invalid_step_id).unwrap_err(),
            WorkflowCheckpointError::InvalidStepId("a".repeat(MAX_WORKFLOW_STEP_ID_BYTES + 1))
        );

        let long_step_id = "a".repeat(MAX_WORKFLOW_STEP_ID_BYTES + 1);
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        assert_eq!(
            engine
                .plan(vec![WorkflowStep::new(
                    long_step_id.clone(),
                    "let value = 1"
                )])
                .unwrap_err(),
            WorkflowError::InvalidStepId(long_step_id)
        );
    }

    #[test]
    fn failed_runs_report_a_checkpointable_completed_prefix() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new("first", "use mod.tool\ntool.call(\"text.echo\", \"one\")"),
                WorkflowStep::new("fail", "use mod.tool\ntool.call(\"shell.exec\", \"two\")"),
            ])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        let error = engine.execute(&plan, approval).unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::StepFailed {
                ref step_id,
                completed_steps: 1,
                ..
            } if step_id == "fail"
        ));
        let checkpoint = engine.checkpoint_after(&plan, 1).unwrap();
        assert_eq!(checkpoint.completed_step_ids(), ["first"]);
    }

    #[test]
    fn approval_cannot_execute_a_different_plan() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let first = engine
            .plan(vec![WorkflowStep::new("first", "let value = 1")])
            .unwrap();
        let second = engine
            .plan(vec![WorkflowStep::new("second", "let value = 2")])
            .unwrap();
        let approval = engine.approve(&first).unwrap();

        assert_eq!(
            engine.execute(&second, approval).unwrap_err(),
            WorkflowError::ApprovalMismatch
        );
    }

    #[test]
    fn approval_cannot_cross_workflow_engines() {
        let mut first_engine = WorkflowEngine::new(CapabilityRuntime::default());
        let first_plan = first_engine
            .plan(vec![WorkflowStep::new("first", "let value = 1")])
            .unwrap();
        let approval = first_engine.approve(&first_plan).unwrap();

        let mut second_engine = WorkflowEngine::new(CapabilityRuntime::default());
        let second_plan = second_engine
            .plan(vec![WorkflowStep::new("second", "let value = 2")])
            .unwrap();

        assert_eq!(
            second_engine.execute(&second_plan, approval).unwrap_err(),
            WorkflowError::ApprovalMismatch
        );
    }

    #[test]
    fn foreign_plans_cannot_be_approved_or_checkpointed() {
        let mut first_engine = WorkflowEngine::new(CapabilityRuntime::default());
        let first_plan = first_engine
            .plan(vec![WorkflowStep::new("first", "let value = 1")])
            .unwrap();
        let first_approval = first_engine.approve(&first_plan).unwrap();
        let mut second_engine = WorkflowEngine::new(CapabilityRuntime::default());

        assert_eq!(
            second_engine
                .execute(&first_plan, first_approval)
                .unwrap_err(),
            WorkflowError::PlanOwnershipMismatch
        );
        assert_eq!(
            second_engine.approve(&first_plan).unwrap_err(),
            WorkflowError::PlanOwnershipMismatch
        );
        assert_eq!(
            second_engine.checkpoint_after(&first_plan, 0).unwrap_err(),
            WorkflowError::PlanOwnershipMismatch
        );
    }

    #[test]
    fn failed_step_stops_the_remaining_plan() {
        let mut runtime = CapabilityRuntime::default();
        let mut policy = ToolPolicy::new("text.echo");
        policy.max_calls = 2;
        runtime
            .register_tool(policy, |request| Ok(request.input.clone()))
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new("first", "use mod.tool\ntool.call(\"text.echo\", \"one\")"),
                WorkflowStep::new(
                    "deny",
                    "use mod.tool\ntool.call(\"shell.exec\", \"whoami\")",
                ),
                WorkflowStep::new("not-run", "use mod.tool\ntool.call(\"text.echo\", \"two\")"),
            ])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        let error = engine.execute(&plan, approval).unwrap_err();

        assert!(matches!(error, WorkflowError::StepFailed { .. }));
        assert_eq!(engine.runtime().audit().len(), 2);
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::StepFailed { step_id, .. }) if step_id == "deny"
        ));
    }

    #[test]
    fn approved_plan_drives_a_deferred_capability_to_completion() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "deferred-echo",
                "use mod.tool\nuse mod.std.assert\nlet output = tool.start(\"text.echo\", \"release notes\").await()\nassert(output == \"release notes\")",
            )])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        engine.execute(&plan, approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(
            engine.runtime().audit()[0].outcome,
            splash_capabilities::AuditOutcome::Allowed
        );
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn approved_plan_drives_a_deferred_json_capability_to_completion() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_json_tool(ToolPolicy::json("math.add"), |request| {
                let left = request.input["left"].as_i64().unwrap();
                let right = request.input["right"].as_i64().unwrap();
                Ok(splash_capabilities::json!({"total": left + right}))
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "deferred-json-add",
                "use mod.tool\nuse mod.std.assert\nlet raw = tool.start_json(\"math.add\", {left: 20 right: 22}).await()\nlet response = raw.parse_json()\nassert(response.total == 42)",
            )])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        engine.execute(&plan, approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(
            engine.runtime().audit()[0].outcome,
            splash_capabilities::AuditOutcome::Allowed
        );
    }
}
