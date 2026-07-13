//! Bounded JSON-line transport for authenticated worker frames.
//!
//! The host owns process creation, sandboxing, and key provisioning. This
//! module only moves one already-authenticated frame at a time over supplied
//! buffered input and output handles.

use std::fmt::{self, Display, Formatter};
use std::io::{self, BufRead, Write};

use splash_protocol::MAX_WIRE_FRAME_BYTES;

use crate::{
    AuthenticatedWorkerMessage, ProtocolError, SessionAuthenticator, SessionRole, WorkerInvocation,
    WorkerMessage, WorkerResult, WorkerTransport,
};

/// Trusted byte channel for one ordered sequence of authenticated worker
/// frames.
///
/// A host sends its `open_session` frame through this channel before it wraps
/// the channel in [`AuthenticatedFrameWorkerTransport`]. The channel does not
/// authenticate a frame itself; that remains the caller's responsibility.
pub trait WorkerFrameChannel {
    type Error: Display;

    fn send_frame(&mut self, frame: AuthenticatedWorkerMessage) -> Result<(), Self::Error>;

    fn receive_frame(&mut self) -> Result<AuthenticatedWorkerMessage, Self::Error>;
}

/// A newline-delimited JSON frame channel over host-provided buffered I/O.
///
/// Every sent and received line is bounded by
/// [`MAX_WIRE_FRAME_BYTES`]. A write, flush, read, decode, or size failure
/// poisons the channel because the two peers can no longer safely agree on the
/// next frame boundary. Discard the channel and its session after such a
/// failure rather than retrying on the same stream.
pub struct JsonLineWorkerChannel<R, W> {
    reader: R,
    writer: W,
    poisoned: bool,
}

impl<R, W> JsonLineWorkerChannel<R, W> {
    /// Creates a channel from the worker's buffered output and input handles.
    ///
    /// For a child process, pass a `BufReader<ChildStdout>` as `reader` and
    /// its `ChildStdin` as `writer`. The caller must place that process in its
    /// own platform containment backend before sending effectful work.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            poisoned: false,
        }
    }

    /// Returns whether a previous failed frame exchange made this channel
    /// unusable.
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Consumes the channel and returns its host-owned I/O handles.
    pub fn into_parts(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

impl<R, W> WorkerFrameChannel for JsonLineWorkerChannel<R, W>
where
    R: BufRead,
    W: Write,
{
    type Error = JsonLineWorkerChannelError;

    fn send_frame(&mut self, frame: AuthenticatedWorkerMessage) -> Result<(), Self::Error> {
        if self.poisoned {
            return Err(JsonLineWorkerChannelError::Poisoned);
        }
        let result = self.send_frame_inner(frame);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn receive_frame(&mut self) -> Result<AuthenticatedWorkerMessage, Self::Error> {
        if self.poisoned {
            return Err(JsonLineWorkerChannelError::Poisoned);
        }
        let result = read_json_line(&mut self.reader)
            .and_then(|line| AuthenticatedWorkerMessage::from_json_line(&line).map_err(Into::into));
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

impl<R, W> JsonLineWorkerChannel<R, W>
where
    W: Write,
{
    fn send_frame_inner(
        &mut self,
        frame: AuthenticatedWorkerMessage,
    ) -> Result<(), JsonLineWorkerChannelError> {
        let line = frame
            .to_json_line()
            .map_err(JsonLineWorkerChannelError::Protocol)?;
        self.writer
            .write_all(line.as_bytes())
            .map_err(JsonLineWorkerChannelError::Io)?;
        self.writer
            .write_all(b"\n")
            .map_err(JsonLineWorkerChannelError::Io)?;
        self.writer.flush().map_err(JsonLineWorkerChannelError::Io)
    }
}

/// Error from [`JsonLineWorkerChannel`].
#[derive(Debug)]
pub enum JsonLineWorkerChannelError {
    Io(io::Error),
    Protocol(ProtocolError),
    InvalidUtf8,
    UnexpectedEndOfStream,
    Poisoned,
}

impl Display for JsonLineWorkerChannelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "worker frame I/O failed: {error}"),
            Self::Protocol(error) => write!(formatter, "worker frame is invalid: {error}"),
            Self::InvalidUtf8 => formatter.write_str("worker frame is not valid UTF-8"),
            Self::UnexpectedEndOfStream => {
                formatter.write_str("worker frame stream ended before a complete frame")
            }
            Self::Poisoned => formatter.write_str("worker frame channel is poisoned"),
        }
    }
}

impl std::error::Error for JsonLineWorkerChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::InvalidUtf8 | Self::UnexpectedEndOfStream | Self::Poisoned => None,
        }
    }
}

impl From<ProtocolError> for JsonLineWorkerChannelError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Authenticated ordinary-invocation transport over a host-provided frame
/// channel.
///
/// Construct this only after the host has sent the matching `open_session`
/// frame through `channel` and the worker has opened its session. The first
/// response verifies the shared session key, and every following response is
/// checked for its session, sender role, tag, and exact sequence number.
pub struct AuthenticatedFrameWorkerTransport<C> {
    host_authenticator: SessionAuthenticator,
    channel: C,
    poisoned: bool,
}

impl<C> AuthenticatedFrameWorkerTransport<C> {
    /// Combines a host-role authenticator with a channel that has already
    /// carried the session's opening frame.
    pub fn new(
        host_authenticator: SessionAuthenticator,
        channel: C,
    ) -> Result<Self, AuthenticatedFrameWorkerTransportInitError> {
        if host_authenticator.role() != SessionRole::Host {
            return Err(AuthenticatedFrameWorkerTransportInitError::RequiresHostAuthenticator);
        }
        Ok(Self {
            host_authenticator,
            channel,
            poisoned: false,
        })
    }

    /// Returns whether a failed exchange made this transport unsafe to reuse.
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Consumes the transport and returns its host-owned state.
    pub fn into_parts(self) -> (SessionAuthenticator, C) {
        (self.host_authenticator, self.channel)
    }
}

impl<C> WorkerTransport for AuthenticatedFrameWorkerTransport<C>
where
    C: WorkerFrameChannel,
{
    type Error = AuthenticatedFrameWorkerTransportError<C::Error>;

    fn dispatch(&mut self, invocation: WorkerInvocation) -> Result<WorkerResult, Self::Error> {
        if self.poisoned {
            return Err(AuthenticatedFrameWorkerTransportError::Poisoned);
        }
        let request = self
            .host_authenticator
            .seal(WorkerMessage::Invoke { invocation })
            .map_err(AuthenticatedFrameWorkerTransportError::Protocol)?;
        let result = self.dispatch_sealed(request);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

impl<C> AuthenticatedFrameWorkerTransport<C>
where
    C: WorkerFrameChannel,
{
    fn dispatch_sealed(
        &mut self,
        request: AuthenticatedWorkerMessage,
    ) -> Result<WorkerResult, AuthenticatedFrameWorkerTransportError<C::Error>> {
        self.channel
            .send_frame(request)
            .map_err(AuthenticatedFrameWorkerTransportError::Channel)?;
        let response = self
            .channel
            .receive_frame()
            .map_err(AuthenticatedFrameWorkerTransportError::Channel)?;
        let message = self
            .host_authenticator
            .open(response)
            .map_err(AuthenticatedFrameWorkerTransportError::Protocol)?;
        match message {
            WorkerMessage::Result { result } => Ok(result),
            _ => Err(AuthenticatedFrameWorkerTransportError::UnexpectedResponse),
        }
    }
}

/// Rejection while wiring an authenticated frame transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedFrameWorkerTransportInitError {
    RequiresHostAuthenticator,
}

impl Display for AuthenticatedFrameWorkerTransportInitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiresHostAuthenticator => formatter.write_str(
                "authenticated frame worker transport requires a host-role authenticator",
            ),
        }
    }
}

impl std::error::Error for AuthenticatedFrameWorkerTransportInitError {}

/// Failure while dispatching through an authenticated frame channel.
#[derive(Debug)]
pub enum AuthenticatedFrameWorkerTransportError<E> {
    Protocol(ProtocolError),
    Channel(E),
    UnexpectedResponse,
    Poisoned,
}

impl<E: Display> Display for AuthenticatedFrameWorkerTransportError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(
                formatter,
                "authenticated frame worker protocol failure: {error}"
            ),
            Self::Channel(_) => formatter.write_str("authenticated frame worker channel failed"),
            Self::UnexpectedResponse => {
                formatter.write_str("authenticated frame worker returned an unexpected response")
            }
            Self::Poisoned => {
                formatter.write_str("authenticated frame worker transport is poisoned")
            }
        }
    }
}

impl<E> std::error::Error for AuthenticatedFrameWorkerTransportError<E> where
    E: std::error::Error + 'static
{
}

fn read_json_line<R: BufRead>(reader: &mut R) -> Result<String, JsonLineWorkerChannelError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(JsonLineWorkerChannelError::Io)?;
        if available.is_empty() {
            return Err(JsonLineWorkerChannelError::UnexpectedEndOfStream);
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            let actual = line.len().saturating_add(newline);
            if actual > MAX_WIRE_FRAME_BYTES {
                return Err(JsonLineWorkerChannelError::Protocol(
                    ProtocolError::WireFrameTooLarge {
                        actual,
                        maximum: MAX_WIRE_FRAME_BYTES,
                    },
                ));
            }
            line.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            return String::from_utf8(line).map_err(|_| JsonLineWorkerChannelError::InvalidUtf8);
        }

        let remaining = MAX_WIRE_FRAME_BYTES
            .saturating_add(1)
            .saturating_sub(line.len());
        if remaining == 0 {
            return Err(JsonLineWorkerChannelError::Protocol(
                ProtocolError::WireFrameTooLarge {
                    actual: line.len().saturating_add(1),
                    maximum: MAX_WIRE_FRAME_BYTES,
                },
            ));
        }
        let copied = available.len().min(remaining);
        line.extend_from_slice(&available[..copied]);
        reader.consume(copied);
        if line.len() > MAX_WIRE_FRAME_BYTES {
            return Err(JsonLineWorkerChannelError::Protocol(
                ProtocolError::WireFrameTooLarge {
                    actual: line.len(),
                    maximum: MAX_WIRE_FRAME_BYTES,
                },
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use splash_protocol::{CapabilityGrant, CapabilityManifest, SessionKey, ToolPayload};

    use super::*;

    fn manifest() -> CapabilityManifest {
        CapabilityManifest::new("worker-1", vec![CapabilityGrant::json("math.add")]).unwrap()
    }

    fn invocation() -> WorkerInvocation {
        WorkerInvocation::new(
            "worker-1",
            "request-1",
            "math.add",
            ToolPayload::Json(serde_json::json!({"left": 20, "right": 22})),
        )
        .unwrap()
    }

    #[test]
    fn sends_a_json_line_and_receives_a_bounded_frame() {
        let key = SessionKey::from_bytes([1; splash_protocol::AUTH_TAG_BYTES]).unwrap();
        let mut host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let mut worker = SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap();
        let request = host
            .seal(WorkerMessage::OpenSession {
                manifest: manifest(),
            })
            .unwrap();
        let response = worker
            .seal(WorkerMessage::CloseSession {
                protocol_version: splash_protocol::PROTOCOL_VERSION,
                session_id: "worker-1".to_owned(),
            })
            .unwrap();
        let mut channel = JsonLineWorkerChannel::new(
            Cursor::new(format!("{}\n", response.to_json_line().unwrap()).into_bytes()),
            Vec::new(),
        );

        channel.send_frame(request.clone()).unwrap();
        assert_eq!(channel.receive_frame().unwrap(), response);
        let (_, written) = channel.into_parts();
        assert_eq!(
            String::from_utf8(written).unwrap(),
            format!("{}\n", request.to_json_line().unwrap())
        );
    }

    #[test]
    fn rejects_an_oversized_unterminated_frame_before_decoding() {
        let mut channel = JsonLineWorkerChannel::new(
            Cursor::new(vec![b'x'; MAX_WIRE_FRAME_BYTES + 1]),
            Vec::new(),
        );

        assert!(matches!(
            channel.receive_frame(),
            Err(JsonLineWorkerChannelError::Protocol(
                ProtocolError::WireFrameTooLarge { actual, maximum }
            )) if actual == MAX_WIRE_FRAME_BYTES + 1 && maximum == MAX_WIRE_FRAME_BYTES
        ));
        assert!(channel.is_poisoned());
    }

    #[test]
    fn poisons_the_channel_after_an_incomplete_frame() {
        let mut channel = JsonLineWorkerChannel::new(Cursor::new(Vec::new()), Vec::new());

        assert!(matches!(
            channel.receive_frame(),
            Err(JsonLineWorkerChannelError::UnexpectedEndOfStream)
        ));
        assert!(matches!(
            channel.receive_frame(),
            Err(JsonLineWorkerChannelError::Poisoned)
        ));
    }

    #[test]
    fn poisons_the_channel_after_a_write_failure() {
        let key = SessionKey::from_bytes([6; splash_protocol::AUTH_TAG_BYTES]).unwrap();
        let mut host = SessionAuthenticator::new("worker-1", key, SessionRole::Host).unwrap();
        let frame = host
            .seal(WorkerMessage::OpenSession {
                manifest: manifest(),
            })
            .unwrap();
        let mut channel = JsonLineWorkerChannel::new(Cursor::new(Vec::<u8>::new()), FailingWriter);

        assert!(matches!(
            channel.send_frame(frame.clone()),
            Err(JsonLineWorkerChannelError::Io(_))
        ));
        assert!(channel.is_poisoned());
        assert!(matches!(
            channel.send_frame(frame),
            Err(JsonLineWorkerChannelError::Poisoned)
        ));
    }

    #[test]
    fn dispatches_an_authenticated_invocation_over_json_lines() {
        let manifest = manifest();
        let key = SessionKey::from_bytes([2; splash_protocol::AUTH_TAG_BYTES]).unwrap();
        let mut host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let mut expected_host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let mut worker = SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap();
        let opening_message = WorkerMessage::OpenSession {
            manifest: manifest.clone(),
        };
        let opening = host.seal(opening_message.clone()).unwrap();
        let expected_opening = expected_host.seal(opening_message.clone()).unwrap();
        assert_eq!(opening, expected_opening);
        assert_eq!(worker.open(expected_opening).unwrap(), opening_message);

        let expected_invocation = invocation();
        let expected_request = expected_host
            .seal(WorkerMessage::Invoke {
                invocation: expected_invocation.clone(),
            })
            .unwrap();
        assert_eq!(
            worker.open(expected_request.clone()).unwrap(),
            WorkerMessage::Invoke {
                invocation: expected_invocation,
            }
        );
        let result = WorkerResult::new(
            "worker-1",
            "request-1",
            ToolPayload::Json(serde_json::json!({"total": 42})),
        )
        .unwrap();
        let response = worker
            .seal(WorkerMessage::Result {
                result: result.clone(),
            })
            .unwrap();
        let channel = JsonLineWorkerChannel::new(
            Cursor::new(format!("{}\n", response.to_json_line().unwrap()).into_bytes()),
            Vec::new(),
        );
        let mut transport = AuthenticatedFrameWorkerTransport::new(host, channel).unwrap();

        assert_eq!(transport.dispatch(invocation()).unwrap(), result);
        let (_, channel) = transport.into_parts();
        let (_, written) = channel.into_parts();
        let written = String::from_utf8(written).unwrap();
        assert_eq!(
            AuthenticatedWorkerMessage::from_json_line(written.trim_end()).unwrap(),
            expected_request
        );
    }

    #[test]
    fn poisons_the_transport_after_an_invalid_authenticated_response() {
        let manifest = manifest();
        let key = SessionKey::from_bytes([3; splash_protocol::AUTH_TAG_BYTES]).unwrap();
        let mut host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let mut expected_host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let mut worker = SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap();
        let opening_message = WorkerMessage::OpenSession {
            manifest: manifest.clone(),
        };
        let opening = host.seal(opening_message.clone()).unwrap();
        let expected_opening = expected_host.seal(opening_message).unwrap();
        assert_eq!(opening, expected_opening);
        worker.open(expected_opening).unwrap();
        let mut wrong_worker = SessionAuthenticator::new(
            "worker-1",
            SessionKey::from_bytes([4; splash_protocol::AUTH_TAG_BYTES]).unwrap(),
            SessionRole::Worker,
        )
        .unwrap();
        let invalid_response = wrong_worker
            .seal(WorkerMessage::Result {
                result: WorkerResult::new(
                    "worker-1",
                    "request-1",
                    ToolPayload::Json(serde_json::json!({"total": 42})),
                )
                .unwrap(),
            })
            .unwrap();
        let channel = JsonLineWorkerChannel::new(
            Cursor::new(format!("{}\n", invalid_response.to_json_line().unwrap()).into_bytes()),
            Vec::new(),
        );
        let mut transport = AuthenticatedFrameWorkerTransport::new(host, channel).unwrap();

        assert!(matches!(
            transport.dispatch(invocation()),
            Err(AuthenticatedFrameWorkerTransportError::Protocol(
                ProtocolError::InvalidAuthenticationTag
            ))
        ));
        assert!(transport.is_poisoned());
        assert!(matches!(
            transport.dispatch(invocation()),
            Err(AuthenticatedFrameWorkerTransportError::Poisoned)
        ));
    }

    #[test]
    fn poisons_the_transport_after_an_authenticated_unexpected_response() {
        let manifest = manifest();
        let key = SessionKey::from_bytes([7; splash_protocol::AUTH_TAG_BYTES]).unwrap();
        let mut host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let mut expected_host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let mut worker = SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap();
        let opening_message = WorkerMessage::OpenSession {
            manifest: manifest.clone(),
        };
        let opening = host.seal(opening_message.clone()).unwrap();
        let expected_opening = expected_host.seal(opening_message).unwrap();
        assert_eq!(opening, expected_opening);
        worker.open(expected_opening).unwrap();
        let response = worker
            .seal(WorkerMessage::CloseSession {
                protocol_version: splash_protocol::PROTOCOL_VERSION,
                session_id: "worker-1".to_owned(),
            })
            .unwrap();
        let channel = JsonLineWorkerChannel::new(
            Cursor::new(format!("{}\n", response.to_json_line().unwrap()).into_bytes()),
            Vec::new(),
        );
        let mut transport = AuthenticatedFrameWorkerTransport::new(host, channel).unwrap();

        assert!(matches!(
            transport.dispatch(invocation()),
            Err(AuthenticatedFrameWorkerTransportError::UnexpectedResponse)
        ));
        assert!(transport.is_poisoned());
        assert!(matches!(
            transport.dispatch(invocation()),
            Err(AuthenticatedFrameWorkerTransportError::Poisoned)
        ));
    }

    #[test]
    fn rejects_a_non_host_authenticator() {
        let authenticator = SessionAuthenticator::new(
            "worker-1",
            SessionKey::from_bytes([5; splash_protocol::AUTH_TAG_BYTES]).unwrap(),
            SessionRole::Worker,
        )
        .unwrap();

        assert!(matches!(
            AuthenticatedFrameWorkerTransport::new(
                authenticator,
                JsonLineWorkerChannel::new(Cursor::new(Vec::<u8>::new()), Vec::<u8>::new())
            ),
            Err(AuthenticatedFrameWorkerTransportInitError::RequiresHostAuthenticator)
        ));
    }

    struct FailingWriter;

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "worker exited"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
