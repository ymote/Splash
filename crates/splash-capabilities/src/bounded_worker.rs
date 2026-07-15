//! Host-enforced lifecycle bounds for one synchronous worker transport.
//!
//! A synchronous JSON-line transport cannot deliver a cooperative `cancel`
//! frame while it is blocked waiting for a worker response. This module keeps
//! that limitation explicit: a platform supervisor force-stops the worker on
//! expiry or host termination, and the call is reported as indeterminate.
//! Callers must discard that session and reconcile any durable effect rather
//! than treating process termination as proof of cancellation.

use std::fmt::{self, Display, Formatter};
use std::time::Duration;

use crate::{WorkerInvocation, WorkerResult, WorkerTransport};

/// A nonzero wall-clock limit selected by trusted host code for one worker
/// invocation.
///
/// This value is not exposed to Splash source. It bounds the period from a
/// supervisor arming an invocation until it observes the worker transport's
/// response; it does not turn a forced process stop into an adapter-level
/// cancellation acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerInvocationDeadline {
    maximum: Duration,
}

impl WorkerInvocationDeadline {
    /// Creates a host-owned nonzero invocation deadline.
    pub fn new(maximum: Duration) -> Result<Self, WorkerInvocationDeadlineError> {
        if maximum.is_zero() {
            return Err(WorkerInvocationDeadlineError::Zero);
        }
        Ok(Self { maximum })
    }

    /// Returns the host-selected maximum duration.
    pub const fn maximum(self) -> Duration {
        self.maximum
    }
}

/// Rejection while creating a [`WorkerInvocationDeadline`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerInvocationDeadlineError {
    /// A zero-duration deadline cannot establish a usable invocation window.
    Zero,
}

impl Display for WorkerInvocationDeadlineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => {
                formatter.write_str("worker invocation deadline must be greater than zero")
            }
        }
    }
}

impl std::error::Error for WorkerInvocationDeadlineError {}

/// Result from ending a supervised worker invocation.
///
/// A termination outcome is intentionally separate from a successful worker
/// result. Even a valid response that races with a deadline or host process
/// stop is not safe to accept as proof that an adapter effect did not run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerInvocationOutcome<T> {
    /// The supervisor disarmed the deadline before it elapsed.
    Completed,
    /// The host deadline elapsed and the supervisor terminated the worker.
    DeadlineElapsed(T),
    /// The worker session lifetime elapsed and the supervisor terminated the
    /// worker. Any active adapter effect is indeterminate.
    SessionDeadlineElapsed(T),
    /// A host lifecycle control terminated the worker while the call was live.
    Terminated(T),
}

/// Platform lifecycle control required to bound a synchronous worker call.
///
/// Implementations own process lifecycle rather than protocol authority. They
/// must force-stop and reap their worker for [`Self::terminate`], and they
/// must report a deadline or external stop through
/// [`WorkerInvocationOutcome`] instead of accepting a racing result.
pub trait WorkerExecutionSupervisor {
    /// Opaque token binding one begin/finish pair.
    type Invocation;
    /// Platform-specific force-termination observation retained for trusted
    /// host recovery and audit.
    type Termination;
    /// Platform supervisor failure.
    type Error: Display;

    /// Arms a host-selected deadline before the transport sends the request.
    fn begin_invocation(
        &mut self,
        deadline: WorkerInvocationDeadline,
    ) -> Result<Self::Invocation, Self::Error>;

    /// Disarms the invocation deadline or reports a force-termination race.
    fn finish_invocation(
        &mut self,
        invocation: Self::Invocation,
    ) -> Result<WorkerInvocationOutcome<Self::Termination>, Self::Error>;

    /// Force-stops and reaps the worker after a transport or host validation
    /// failure. This does not mean an adapter effect was cancelled.
    fn terminate(&mut self) -> Result<Self::Termination, Self::Error>;
}

/// A lifecycle supervisor contract operationally bound to one authenticated
/// worker session.
///
/// Concurrent transports use this narrower contract so a watchdog for one
/// process cannot accidentally supervise frames for another session. The
/// implementer is trusted host code; returning an ID is not attestation.
/// Session identifiers are public routing identities, not authentication
/// secrets.
pub trait SessionBoundWorkerExecutionSupervisor: WorkerExecutionSupervisor {
    /// Returns the exact worker-protocol session controlled by this supervisor.
    fn session_id(&self) -> &str;
}

/// Why a bounded worker result must be treated as indeterminate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerIndeterminateCause {
    /// The host wall-clock deadline elapsed before the transport disarmed it.
    DeadlineElapsed,
    /// The worker's host-selected total session lifetime elapsed.
    SessionDeadlineElapsed,
    /// Trusted host lifecycle control force-stopped the worker.
    WorkerTerminated,
}

/// A synchronous worker transport coupled to a host-owned lifecycle
/// supervisor.
///
/// The wrapper is deliberately host-only. It never lets Splash source choose
/// a deadline, reset it, or hold lifecycle control. Any deadline or forced
/// termination poisons the session. A transport error also poisons the
/// session and requests forceful termination before it is reported.
pub struct BoundedWorkerTransport<T, S> {
    transport: T,
    supervisor: S,
    deadline: WorkerInvocationDeadline,
    poisoned: bool,
}

impl<T, S> BoundedWorkerTransport<T, S> {
    /// Wraps a transport with a trusted process lifecycle supervisor.
    pub fn new(transport: T, supervisor: S, deadline: WorkerInvocationDeadline) -> Self {
        Self {
            transport,
            supervisor,
            deadline,
            poisoned: false,
        }
    }

    /// Returns whether this transport session must be discarded.
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Returns the host-owned inner transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns the host-owned lifecycle supervisor.
    pub fn supervisor(&self) -> &S {
        &self.supervisor
    }

    /// Consumes the wrapper and returns its host-owned parts.
    pub fn into_parts(self) -> (T, S) {
        (self.transport, self.supervisor)
    }
}

impl<T, S> WorkerTransport for BoundedWorkerTransport<T, S>
where
    T: WorkerTransport,
    S: WorkerExecutionSupervisor,
{
    type Error = BoundedWorkerTransportError<T::Error, S::Error, S::Termination>;

    fn dispatch(&mut self, invocation: WorkerInvocation) -> Result<WorkerResult, Self::Error> {
        if self.poisoned {
            return Err(BoundedWorkerTransportError::Poisoned);
        }

        let active = match self.supervisor.begin_invocation(self.deadline) {
            Ok(active) => active,
            Err(error) => {
                self.poisoned = true;
                self.transport.discard();
                let termination = self.supervisor.terminate();
                return Err(BoundedWorkerTransportError::Supervisor {
                    source: error,
                    termination,
                });
            }
        };
        let result = self.transport.dispatch(invocation);
        let outcome = self.supervisor.finish_invocation(active);

        match outcome {
            Ok(WorkerInvocationOutcome::Completed) => match result {
                Ok(result) => Ok(result),
                Err(error) => {
                    self.poisoned = true;
                    self.transport.discard();
                    let termination = self.supervisor.terminate();
                    Err(BoundedWorkerTransportError::Transport {
                        source: error,
                        termination,
                    })
                }
            },
            Ok(WorkerInvocationOutcome::DeadlineElapsed(termination)) => {
                self.poisoned = true;
                self.transport.discard();
                Err(BoundedWorkerTransportError::Indeterminate {
                    cause: WorkerIndeterminateCause::DeadlineElapsed,
                    termination,
                })
            }
            Ok(WorkerInvocationOutcome::SessionDeadlineElapsed(termination)) => {
                self.poisoned = true;
                self.transport.discard();
                Err(BoundedWorkerTransportError::Indeterminate {
                    cause: WorkerIndeterminateCause::SessionDeadlineElapsed,
                    termination,
                })
            }
            Ok(WorkerInvocationOutcome::Terminated(termination)) => {
                self.poisoned = true;
                self.transport.discard();
                Err(BoundedWorkerTransportError::Indeterminate {
                    cause: WorkerIndeterminateCause::WorkerTerminated,
                    termination,
                })
            }
            Err(error) => {
                self.poisoned = true;
                self.transport.discard();
                let termination = self.supervisor.terminate();
                Err(BoundedWorkerTransportError::Supervisor {
                    source: error,
                    termination,
                })
            }
        }
    }

    fn discard(&mut self) {
        self.poisoned = true;
        self.transport.discard();
        let _ = self.supervisor.terminate();
    }
}

/// Failure from a [`BoundedWorkerTransport`].
///
/// The inner details and termination observation are trusted-host data. A
/// `ProtocolWorkerClient` intentionally maps this to a generic Splash tool
/// error, while a host that dispatches directly can retain the outcome for
/// audit and recovery.
#[derive(Debug)]
pub enum BoundedWorkerTransportError<TE, SE, ST> {
    /// The inner transport failed after the deadline was armed. The session
    /// was discarded and a forceful termination was attempted.
    Transport {
        source: TE,
        termination: Result<ST, SE>,
    },
    /// The lifecycle supervisor failed, so the session is unsafe to reuse.
    /// A forceful termination was attempted before returning.
    Supervisor {
        source: SE,
        termination: Result<ST, SE>,
    },
    /// The deadline or lifecycle control won a race with the worker result.
    /// The call may have completed and any durable effect requires recovery.
    Indeterminate {
        cause: WorkerIndeterminateCause,
        termination: ST,
    },
    /// A prior failure already made this worker session unusable.
    Poisoned,
}

impl<TE, SE, ST> BoundedWorkerTransportError<TE, SE, ST> {
    /// Returns whether the invocation may have completed despite failure.
    pub const fn is_indeterminate(&self) -> bool {
        matches!(
            self,
            Self::Transport { .. } | Self::Supervisor { .. } | Self::Indeterminate { .. }
        )
    }
}

impl<TE: Display, SE: Display, ST> Display for BoundedWorkerTransportError<TE, SE, ST> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { .. } => formatter.write_str(
                "worker transport failed; its session was discarded and termination was requested",
            ),
            Self::Supervisor { .. } => formatter
                .write_str("worker lifecycle supervisor failed; its session must be discarded"),
            Self::Indeterminate {
                cause: WorkerIndeterminateCause::DeadlineElapsed,
                ..
            } => formatter
                .write_str("worker invocation exceeded its host deadline and may have completed"),
            Self::Indeterminate {
                cause: WorkerIndeterminateCause::SessionDeadlineElapsed,
                ..
            } => formatter.write_str(
                "worker session exceeded its host deadline and its invocation may have completed",
            ),
            Self::Indeterminate {
                cause: WorkerIndeterminateCause::WorkerTerminated,
                ..
            } => formatter.write_str(
                "worker was forcefully terminated and its invocation may have completed",
            ),
            Self::Poisoned => formatter.write_str("worker transport session is poisoned"),
        }
    }
}

impl<TE, SE, ST> std::error::Error for BoundedWorkerTransportError<TE, SE, ST>
where
    TE: std::error::Error + 'static,
    SE: std::error::Error + 'static,
    ST: std::fmt::Debug,
{
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use crate::{WorkerPayload, WorkerResult};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestError;

    impl Display for TestError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            formatter.write_str("test failure")
        }
    }

    impl std::error::Error for TestError {}

    struct TestTransport {
        result: Result<WorkerResult, TestError>,
        dispatches: usize,
        discarded: bool,
    }

    impl WorkerTransport for TestTransport {
        type Error = TestError;

        fn dispatch(&mut self, _invocation: WorkerInvocation) -> Result<WorkerResult, Self::Error> {
            self.dispatches = self.dispatches.saturating_add(1);
            self.result.clone()
        }

        fn discard(&mut self) {
            self.discarded = true;
        }
    }

    struct TestSupervisor {
        finish: Result<WorkerInvocationOutcome<usize>, TestError>,
        begin_count: usize,
        finish_count: usize,
        termination_count: usize,
        observed_deadline: Option<WorkerInvocationDeadline>,
    }

    impl WorkerExecutionSupervisor for TestSupervisor {
        type Invocation = u64;
        type Termination = usize;
        type Error = TestError;

        fn begin_invocation(
            &mut self,
            deadline: WorkerInvocationDeadline,
        ) -> Result<Self::Invocation, Self::Error> {
            self.begin_count = self.begin_count.saturating_add(1);
            self.observed_deadline = Some(deadline);
            Ok(u64::try_from(self.begin_count).unwrap())
        }

        fn finish_invocation(
            &mut self,
            _invocation: Self::Invocation,
        ) -> Result<WorkerInvocationOutcome<Self::Termination>, Self::Error> {
            self.finish_count = self.finish_count.saturating_add(1);
            self.finish.clone()
        }

        fn terminate(&mut self) -> Result<Self::Termination, Self::Error> {
            self.termination_count = self.termination_count.saturating_add(1);
            Ok(self.termination_count)
        }
    }

    fn invocation() -> WorkerInvocation {
        WorkerInvocation::new(
            "worker-1",
            "request-1",
            "math.add",
            WorkerPayload::Json(serde_json::json!({"left": 20, "right": 22})),
        )
        .unwrap()
    }

    fn result() -> WorkerResult {
        WorkerResult::new(
            "worker-1",
            "request-1",
            WorkerPayload::Json(serde_json::json!({"total": 42})),
        )
        .unwrap()
    }

    fn deadline() -> WorkerInvocationDeadline {
        WorkerInvocationDeadline::new(Duration::from_secs(1)).unwrap()
    }

    fn supervisor(finish: Result<WorkerInvocationOutcome<usize>, TestError>) -> TestSupervisor {
        TestSupervisor {
            finish,
            begin_count: 0,
            finish_count: 0,
            termination_count: 0,
            observed_deadline: None,
        }
    }

    #[test]
    fn rejects_a_zero_invocation_deadline() {
        assert_eq!(
            WorkerInvocationDeadline::new(Duration::ZERO),
            Err(WorkerInvocationDeadlineError::Zero)
        );
    }

    #[test]
    fn passes_a_completed_response_without_terminating_the_worker() {
        let transport = TestTransport {
            result: Ok(result()),
            dispatches: 0,
            discarded: false,
        };
        let supervisor = supervisor(Ok(WorkerInvocationOutcome::Completed));
        let mut bounded = BoundedWorkerTransport::new(transport, supervisor, deadline());

        assert_eq!(bounded.dispatch(invocation()).unwrap(), result());
        assert!(!bounded.is_poisoned());

        let (transport, supervisor) = bounded.into_parts();
        assert_eq!(transport.dispatches, 1);
        assert!(!transport.discarded);
        assert_eq!(supervisor.begin_count, 1);
        assert_eq!(supervisor.finish_count, 1);
        assert_eq!(supervisor.termination_count, 0);
        assert_eq!(supervisor.observed_deadline, Some(deadline()));
    }

    #[test]
    fn treats_a_deadline_race_as_indeterminate_and_discards_the_session() {
        let transport = TestTransport {
            result: Ok(result()),
            dispatches: 0,
            discarded: false,
        };
        let supervisor = supervisor(Ok(WorkerInvocationOutcome::DeadlineElapsed(7)));
        let mut bounded = BoundedWorkerTransport::new(transport, supervisor, deadline());

        assert!(matches!(
            bounded.dispatch(invocation()),
            Err(BoundedWorkerTransportError::Indeterminate {
                cause: WorkerIndeterminateCause::DeadlineElapsed,
                termination: 7,
            })
        ));
        assert!(bounded.is_poisoned());

        let (transport, supervisor) = bounded.into_parts();
        assert!(transport.discarded);
        assert_eq!(supervisor.termination_count, 0);
    }

    #[test]
    fn treats_a_session_deadline_as_indeterminate_and_discards_the_session() {
        let transport = TestTransport {
            result: Ok(result()),
            dispatches: 0,
            discarded: false,
        };
        let supervisor = supervisor(Ok(WorkerInvocationOutcome::SessionDeadlineElapsed(8)));
        let mut bounded = BoundedWorkerTransport::new(transport, supervisor, deadline());

        let error = bounded.dispatch(invocation()).unwrap_err();
        assert!(error.is_indeterminate());
        assert!(matches!(
            error,
            BoundedWorkerTransportError::Indeterminate {
                cause: WorkerIndeterminateCause::SessionDeadlineElapsed,
                termination: 8,
            }
        ));
        assert!(bounded.is_poisoned());

        let (transport, supervisor) = bounded.into_parts();
        assert!(transport.discarded);
        assert_eq!(supervisor.termination_count, 0);
    }

    #[test]
    fn treats_a_host_force_stop_as_indeterminate_and_discards_the_session() {
        let transport = TestTransport {
            result: Ok(result()),
            dispatches: 0,
            discarded: false,
        };
        let supervisor = supervisor(Ok(WorkerInvocationOutcome::Terminated(9)));
        let mut bounded = BoundedWorkerTransport::new(transport, supervisor, deadline());

        let error = bounded.dispatch(invocation()).unwrap_err();
        assert!(error.is_indeterminate());
        assert!(matches!(
            error,
            BoundedWorkerTransportError::Indeterminate {
                cause: WorkerIndeterminateCause::WorkerTerminated,
                termination: 9,
            }
        ));
        assert!(bounded.is_poisoned());

        let (transport, supervisor) = bounded.into_parts();
        assert!(transport.discarded);
        assert_eq!(supervisor.termination_count, 0);
    }

    #[test]
    fn terminates_and_poisons_after_an_inner_transport_failure() {
        let transport = TestTransport {
            result: Err(TestError),
            dispatches: 0,
            discarded: false,
        };
        let supervisor = supervisor(Ok(WorkerInvocationOutcome::Completed));
        let mut bounded = BoundedWorkerTransport::new(transport, supervisor, deadline());

        let error = bounded.dispatch(invocation()).unwrap_err();
        assert!(error.is_indeterminate());
        assert!(matches!(
            error,
            BoundedWorkerTransportError::Transport {
                source: TestError,
                termination: Ok(1),
            }
        ));
        assert!(matches!(
            bounded.dispatch(invocation()),
            Err(BoundedWorkerTransportError::Poisoned)
        ));

        let (transport, supervisor) = bounded.into_parts();
        assert!(transport.discarded);
        assert_eq!(supervisor.termination_count, 1);
    }

    #[test]
    fn direct_discard_stops_the_worker_and_blocks_future_dispatch() {
        let transport = TestTransport {
            result: Ok(result()),
            dispatches: 0,
            discarded: false,
        };
        let supervisor = supervisor(Ok(WorkerInvocationOutcome::Completed));
        let mut bounded = BoundedWorkerTransport::new(transport, supervisor, deadline());

        bounded.discard();
        assert!(matches!(
            bounded.dispatch(invocation()),
            Err(BoundedWorkerTransportError::Poisoned)
        ));

        let (transport, supervisor) = bounded.into_parts();
        assert!(transport.discarded);
        assert_eq!(supervisor.termination_count, 1);
    }

    #[test]
    fn error_types_are_usable_with_infallible_supervisors() {
        fn accepts_error<E: std::error::Error>() {}
        accepts_error::<BoundedWorkerTransportError<TestError, Infallible, usize>>();
    }
}
