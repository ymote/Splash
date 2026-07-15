//! Linux Bubblewrap implementation of the generic worker lifecycle boundary.
//!
//! Enabling this module does not start a worker or make a protocol transport
//! safe by itself. The host must still construct Bubblewrap policy, provision
//! the private session bootstrap, open the authenticated session, and retain
//! recovery policy for indeterminate effects.

use splash_sandbox::bubblewrap::{
    BubblewrapWorkerInvocation, BubblewrapWorkerInvocationOutcome, BubblewrapWorkerWatchdog,
    BubblewrapWorkerWatchdogError,
};

use crate::bounded_worker::{
    SessionBoundWorkerExecutionSupervisor, WorkerExecutionSupervisor, WorkerInvocationDeadline,
    WorkerInvocationOutcome,
};

impl WorkerExecutionSupervisor for BubblewrapWorkerWatchdog {
    type Invocation = BubblewrapWorkerInvocation;
    type Termination = splash_sandbox::bubblewrap::BubblewrapTermination;
    type Error = BubblewrapWorkerWatchdogError;

    fn begin_invocation(
        &mut self,
        deadline: WorkerInvocationDeadline,
    ) -> Result<Self::Invocation, Self::Error> {
        self.begin_call(deadline.maximum())
    }

    fn finish_invocation(
        &mut self,
        invocation: Self::Invocation,
    ) -> Result<WorkerInvocationOutcome<Self::Termination>, Self::Error> {
        match self.finish_call(invocation)? {
            BubblewrapWorkerInvocationOutcome::Completed => Ok(WorkerInvocationOutcome::Completed),
            BubblewrapWorkerInvocationOutcome::DeadlineElapsed(termination) => {
                Ok(WorkerInvocationOutcome::DeadlineElapsed(termination))
            }
            BubblewrapWorkerInvocationOutcome::SessionDeadlineElapsed(termination) => {
                Ok(WorkerInvocationOutcome::SessionDeadlineElapsed(termination))
            }
            BubblewrapWorkerInvocationOutcome::Terminated(termination) => {
                Ok(WorkerInvocationOutcome::Terminated(termination))
            }
        }
    }

    fn terminate(&mut self) -> Result<Self::Termination, Self::Error> {
        BubblewrapWorkerWatchdog::terminate(self)
    }
}

impl SessionBoundWorkerExecutionSupervisor for BubblewrapWorkerWatchdog {
    fn session_id(&self) -> &str {
        self.session_id()
    }
}

/// Authenticated cancellable transport coupled to the exact Bubblewrap
/// watchdog session that owns its process lifecycle.
#[cfg(feature = "json-line-worker")]
pub type BubblewrapMultiplexedWorkerSession =
    crate::multiplexed_worker::SupervisedMultiplexedWorkerSession<BubblewrapWorkerWatchdog>;
