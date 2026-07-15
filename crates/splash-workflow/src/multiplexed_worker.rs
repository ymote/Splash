//! Workflow completion sink for authenticated cancellable workers.
//!
//! The capabilities crate deliberately exposes worker observations separately
//! from runtime mutation. This module applies them through [`WorkflowEngine`]
//! so a completed or cancelled tool also advances (or terminally fails) the
//! retained workflow step and its approval-bound state.

use std::fmt::{self, Display, Formatter};

use splash_capabilities::bounded_worker::{
    SessionBoundWorkerExecutionSupervisor, WorkerIndeterminateCause,
};
use splash_capabilities::multiplexed_worker::{
    ExternalToolWorkerEvent, SupervisedExternalToolWorkerEvent, SupervisedMultiplexedWorkerError,
    SupervisedMultiplexedWorkerSession,
};
use splash_capabilities::{
    ExternalToolCancellationRequest, ExternalToolId, WorkerCancellationOutcome,
};

use crate::{WorkflowEngine, WorkflowError};

/// Marks the workflow operation cancellation-requested, then sends the exact
/// identity over its supervised worker session.
///
/// If transport delivery fails, the workflow intentionally remains in its
/// cancellation-requested state. The operation is indeterminate and must be
/// reconciled rather than silently made dispatchable again.
pub fn request_external_tool_cancellation<S>(
    session: &mut SupervisedMultiplexedWorkerSession<S>,
    engine: &mut WorkflowEngine,
    external_id: ExternalToolId,
    cancellation_id: impl Into<String>,
) -> WorkflowExternalToolWorkerResult<ExternalToolCancellationRequest, S::Error, S::Termination>
where
    S: SessionBoundWorkerExecutionSupervisor,
{
    if session.active_external_id() != Some(external_id) {
        return Err(WorkflowExternalToolWorkerError::BindingMismatch);
    }
    let request = engine
        .request_external_tool_cancellation(external_id)
        .map_err(WorkflowExternalToolWorkerError::Workflow)?;
    session
        .request_external_tool_cancellation(&request, cancellation_id)
        .map_err(WorkflowExternalToolWorkerError::Worker)?;
    Ok(request)
}

/// Polls one supervised worker event and applies terminal output through the
/// workflow engine rather than bypassing it through `runtime_mut()`.
pub fn poll_external_tool<S>(
    session: &mut SupervisedMultiplexedWorkerSession<S>,
    engine: &mut WorkflowEngine,
) -> WorkflowExternalToolWorkerResult<
    WorkflowExternalToolWorkerPoll<S::Termination>,
    S::Error,
    S::Termination,
>
where
    S: SessionBoundWorkerExecutionSupervisor,
{
    match session
        .poll_external_tool_event()
        .map_err(WorkflowExternalToolWorkerError::Worker)?
    {
        SupervisedExternalToolWorkerEvent::Worker(event) => {
            apply_external_tool_worker_event(engine, event)
                .map_err(WorkflowExternalToolWorkerError::Workflow)
        }
        SupervisedExternalToolWorkerEvent::Indeterminate {
            external_id,
            cause,
            termination,
        } => Ok(WorkflowExternalToolWorkerPoll::Indeterminate {
            external_id,
            cause,
            termination,
        }),
    }
}

/// Applies one already-authenticated worker event to a workflow engine.
pub fn apply_external_tool_worker_event<T>(
    engine: &mut WorkflowEngine,
    event: ExternalToolWorkerEvent,
) -> Result<WorkflowExternalToolWorkerPoll<T>, WorkflowError> {
    match event {
        ExternalToolWorkerEvent::Pending => Ok(WorkflowExternalToolWorkerPoll::Pending),
        ExternalToolWorkerEvent::CancellationTooLate => {
            Ok(WorkflowExternalToolWorkerPoll::CancellationTooLate)
        }
        ExternalToolWorkerEvent::CancellationUnsupported => {
            Ok(WorkflowExternalToolWorkerPoll::CancellationUnsupported)
        }
        ExternalToolWorkerEvent::Completed {
            external_id,
            output,
        } => {
            engine.complete_external_tool(external_id, Ok(output))?;
            Ok(WorkflowExternalToolWorkerPoll::Completed)
        }
        ExternalToolWorkerEvent::Cancelled {
            external_id,
            acknowledgement,
        } => {
            debug_assert_eq!(
                acknowledgement.outcome,
                WorkerCancellationOutcome::Acknowledged
            );
            engine.confirm_external_tool_cancellation(external_id)?;
            Ok(WorkflowExternalToolWorkerPoll::Cancelled)
        }
    }
}

/// Event-loop observation after applying a worker event through a workflow.
#[derive(Debug)]
pub enum WorkflowExternalToolWorkerPoll<T> {
    Pending,
    CancellationTooLate,
    CancellationUnsupported,
    Completed,
    Cancelled,
    /// Process lifecycle won the race. The workflow remains suspended.
    Indeterminate {
        external_id: ExternalToolId,
        cause: WorkerIndeterminateCause,
        termination: T,
    },
}

/// Failure while coordinating a supervised worker with a workflow engine.
#[derive(Debug)]
pub enum WorkflowExternalToolWorkerError<SE, ST> {
    Worker(SupervisedMultiplexedWorkerError<SE, ST>),
    Workflow(WorkflowError),
    BindingMismatch,
}

/// Result type for workflow integration with one supervised worker session.
pub type WorkflowExternalToolWorkerResult<T, SE, ST> =
    Result<T, WorkflowExternalToolWorkerError<SE, ST>>;

impl<SE: Display, ST> Display for WorkflowExternalToolWorkerError<SE, ST> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Worker(error) => write!(formatter, "supervised worker failed: {error}"),
            Self::Workflow(error) => write!(formatter, "workflow completion failed: {error}"),
            Self::BindingMismatch => {
                formatter.write_str("workflow cancellation targets another worker invocation")
            }
        }
    }
}

impl<SE, ST> std::error::Error for WorkflowExternalToolWorkerError<SE, ST>
where
    SE: std::error::Error + 'static,
    ST: fmt::Debug + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Worker(error) => Some(error),
            Self::Workflow(error) => Some(error),
            Self::BindingMismatch => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use splash_capabilities::{
        AuditOutcome, CapabilityRuntime, ToolPolicy, WorkerCancellationRequest,
        WorkerCancellationResult,
    };

    use super::*;
    use crate::{WorkflowEvent, WorkflowStep};

    fn suspended_engine() -> (WorkflowEngine, splash_capabilities::ExternalToolInvocation) {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("work.run"))
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "run",
                "use mod.tool\ntool.start(\"work.run\", \"input\").await()",
            )])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();
        assert!(matches!(
            engine.execute(&plan, approval),
            Err(WorkflowError::StepSuspended { .. })
        ));
        let invocation = engine.claim_next_external_tool().unwrap();
        (engine, invocation)
    }

    #[test]
    fn completed_worker_event_advances_the_suspended_workflow() {
        let (mut engine, invocation) = suspended_engine();
        let poll = apply_external_tool_worker_event::<()>(
            &mut engine,
            ExternalToolWorkerEvent::Completed {
                external_id: invocation.id,
                output: "done".to_owned(),
            },
        )
        .unwrap();

        assert!(matches!(poll, WorkflowExternalToolWorkerPoll::Completed));
        assert!(!engine.has_suspended_execution());
        assert_eq!(engine.runtime().audit()[0].outcome, AuditOutcome::Allowed);
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Completed { .. })
        ));
    }

    #[test]
    fn acknowledged_worker_cancellation_terminally_fails_the_suspended_step() {
        let (mut engine, invocation) = suspended_engine();
        engine
            .request_external_tool_cancellation(invocation.id)
            .unwrap();
        let request =
            WorkerCancellationRequest::new("session-1", "cancel-1", "request-1", "work.run")
                .unwrap();
        let acknowledgement =
            WorkerCancellationResult::new(&request, WorkerCancellationOutcome::Acknowledged)
                .unwrap();

        assert!(matches!(
            apply_external_tool_worker_event::<()>(
                &mut engine,
                ExternalToolWorkerEvent::Cancelled {
                    external_id: invocation.id,
                    acknowledgement,
                },
            ),
            Err(WorkflowError::StepFailed { .. })
        ));
        assert!(!engine.has_suspended_execution());
        assert_eq!(engine.runtime().audit()[1].outcome, AuditOutcome::Cancelled);
    }
}
