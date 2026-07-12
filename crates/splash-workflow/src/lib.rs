#![forbid(unsafe_code)]

//! Host-owned workflow state for Splash.
//!
//! Scripts evaluate individual steps, but they cannot mint approval or skip
//! host policy. The event log is intentionally in-memory for this baseline;
//! persistence and replay will build on these stable event types.

use std::fmt::{self, Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};

use splash_capabilities::CapabilityRuntime;
use splash_core::RuntimeError;

static NEXT_ENGINE_ID: AtomicU64 = AtomicU64::new(1);

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
    id: u64,
    steps: Vec<WorkflowStep>,
}

impl WorkflowPlan {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn steps(&self) -> &[WorkflowStep] {
        &self.steps
    }
}

/// An approval can only be produced by [`WorkflowEngine::approve`] and is
/// consumed by [`WorkflowEngine::execute`].
#[derive(Debug)]
pub struct Approval {
    engine_id: u64,
    plan_id: u64,
    nonce: u64,
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
    Started {
        plan_id: u64,
    },
    StepSucceeded {
        plan_id: u64,
        step_id: String,
    },
    StepSuspended {
        plan_id: u64,
        step_id: String,
    },
    StepFailed {
        plan_id: u64,
        step_id: String,
        diagnostics: Vec<String>,
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
    ApprovalMismatch,
    Runtime(String),
    StepSuspended {
        step_id: String,
    },
    StepFailed {
        step_id: String,
        diagnostics: Vec<String>,
    },
}

impl Display for WorkflowError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPlan => formatter.write_str("workflow must have at least one step"),
            Self::InvalidStepId(id) => write!(formatter, "invalid workflow step id: {id}"),
            Self::DuplicateStepId(id) => write!(formatter, "duplicate workflow step id: {id}"),
            Self::ApprovalMismatch => {
                formatter.write_str("approval is not valid for this workflow")
            }
            Self::Runtime(message) => write!(formatter, "runtime error: {message}"),
            Self::StepSuspended { step_id } => {
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
            id: self.next_plan_id,
            steps,
        };
        self.next_plan_id = self.next_plan_id.saturating_add(1);
        self.events.push(WorkflowEvent::Planned {
            plan_id: plan.id,
            step_count: plan.steps.len(),
        });
        Ok(plan)
    }

    pub fn approve(&mut self, plan: &WorkflowPlan) -> Approval {
        let approval = Approval {
            engine_id: self.engine_id,
            plan_id: plan.id,
            nonce: self.next_approval_nonce,
        };
        self.next_approval_nonce = self.next_approval_nonce.saturating_add(1);
        self.events
            .push(WorkflowEvent::Approved { plan_id: plan.id });
        approval
    }

    pub fn execute(
        &mut self,
        plan: &WorkflowPlan,
        approval: Approval,
    ) -> Result<(), WorkflowError> {
        if approval.engine_id != self.engine_id
            || approval.plan_id != plan.id
            || approval.nonce == 0
        {
            return Err(WorkflowError::ApprovalMismatch);
        }

        self.events
            .push(WorkflowEvent::Started { plan_id: plan.id });
        for step in &plan.steps {
            let mut report = self.runtime.eval(&step.source)?;
            while report.succeeded() && report.suspended {
                let pumped = self.runtime.pump()?;
                let Some(resumed) = pumped.resumed.into_iter().last() else {
                    self.events.push(WorkflowEvent::StepSuspended {
                        plan_id: plan.id,
                        step_id: step.id.clone(),
                    });
                    return Err(WorkflowError::StepSuspended {
                        step_id: step.id.clone(),
                    });
                };
                report = resumed;
            }
            if !report.succeeded() {
                self.events.push(WorkflowEvent::StepFailed {
                    plan_id: plan.id,
                    step_id: step.id.clone(),
                    diagnostics: report.diagnostics.clone(),
                });
                return Err(WorkflowError::StepFailed {
                    step_id: step.id.clone(),
                    diagnostics: report.diagnostics,
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

fn validate_steps(steps: &[WorkflowStep]) -> Result<(), WorkflowError> {
    if steps.is_empty() {
        return Err(WorkflowError::EmptyPlan);
    }

    let mut seen = std::collections::BTreeSet::new();
    for step in steps {
        if step.id.is_empty()
            || !step.id.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
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
        let approval = engine.approve(&plan);

        engine.execute(&plan, approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
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
        let approval = engine.approve(&first);

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
        let approval = first_engine.approve(&first_plan);

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
        let approval = engine.approve(&plan);

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
        let approval = engine.approve(&plan);

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
        let approval = engine.approve(&plan);

        engine.execute(&plan, approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(
            engine.runtime().audit()[0].outcome,
            splash_capabilities::AuditOutcome::Allowed
        );
    }
}
