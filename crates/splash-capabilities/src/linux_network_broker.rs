//! Linux Unix-socket transport for one reviewed HTTP catalog.
//!
//! Bubblewrap keeps its isolated network namespace. A host creates one private
//! directory containing one Unix socket, mounts that directory read-only into
//! the worker, and runs this broker outside the worker. The broker accepts
//! only the exact opaque `network_origin` identifiers retained by its session
//! `NetworkOriginAccess` and then executes one bounded endpoint or exact-origin
//! catalog request. It is not a general HTTP proxy, socket proxy, credential
//! API, or per-tool process boundary.

use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use splash_protocol::{CapabilityGrant, NetworkOriginAccess, ResourceKind};

use crate::http_endpoint_catalog::{
    HttpEndpointCatalog, HttpEndpointCatalogError, HttpEndpointSecretResolver, HttpOriginCatalog,
    NetworkCatalogExecutor, NetworkCatalogMode, MAX_HTTP_ENDPOINT_REQUEST_TIMEOUT,
    MAX_HTTP_ENDPOINT_RESPONSE_BYTES,
};
use crate::JsonValue;
use splash_sandbox::bubblewrap::{
    BubblewrapPolicyError, LinuxNetworkBrokerMount, MAX_LINUX_NETWORK_BROKER_SOCKET_PATH_BYTES,
};

/// Fixed broker protocol version for the private Unix socket.
pub const LINUX_NETWORK_BROKER_PROTOCOL_VERSION: u8 = 1;
/// Fixed filename created inside each private broker directory.
pub const LINUX_NETWORK_BROKER_SOCKET_NAME: &str = "broker.sock";
/// Default worker-visible directory for a broker socket.
pub const DEFAULT_LINUX_NETWORK_BROKER_DESTINATION: &str = "/run/splash-network";
/// Maximum complete JSON-line broker frame, including its envelope but not the
/// trailing newline.
///
/// A catalog response is itself bounded to one MiB. This leaves fixed headroom
/// for the private response envelope while preventing a worker from making the
/// host accumulate an arbitrary line.
pub const MAX_LINUX_NETWORK_BROKER_FRAME_BYTES: usize = MAX_HTTP_ENDPOINT_RESPONSE_BYTES + 1024;

const MAX_DIRECTORY_CREATION_ATTEMPTS: usize = 16;
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// The reviewed catalog shape behind a Linux network broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxNetworkBrokerCatalog {
    /// Requests carry a fixed-endpoint `endpoint` identifier.
    Endpoint,
    /// Requests carry an exact-origin `origin` identifier and bounded URL.
    Origin,
}

impl LinuxNetworkBrokerCatalog {
    const fn internal(self) -> NetworkCatalogMode {
        match self {
            Self::Endpoint => NetworkCatalogMode::Endpoint,
            Self::Origin => NetworkCatalogMode::Origin,
        }
    }

    const fn identifier_field(self) -> &'static str {
        self.internal().identifier_field()
    }
}

/// Running private host broker for one contained worker session.
///
/// Retain this handle for the entire lifetime of the contained worker. Calling
/// [`Self::shutdown`] or dropping it stops accepting requests and removes the
/// socket directory. The broker serializes requests so a host resolver and its
/// catalog remain single-threaded; a partial request can occupy the broker no
/// longer than the fixed catalog deadline.
pub struct LinuxNetworkBroker {
    mount: LinuxNetworkBrokerMount,
    catalog: LinuxNetworkBrokerCatalog,
    source_directory: PathBuf,
    shutdown: Arc<AtomicBool>,
    server_failed: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl LinuxNetworkBroker {
    /// Starts a broker for one fixed-endpoint catalog.
    ///
    /// The catalog's opaque identifiers must exactly equal `access`; a broader
    /// or narrower catalog is rejected before any socket is created. The host
    /// must pass the returned [`Self::mount`] into the same Bubblewrap policy
    /// whose manifest produced `access`.
    pub fn bind_endpoint<R>(
        parent_directory: impl AsRef<Path>,
        destination_directory: impl Into<PathBuf>,
        access: NetworkOriginAccess,
        catalog: HttpEndpointCatalog,
        secret_resolver: R,
    ) -> Result<Self, LinuxNetworkBrokerError>
    where
        R: HttpEndpointSecretResolver + Send + 'static,
    {
        let executor = NetworkCatalogExecutor::endpoint(catalog, access.clone(), secret_resolver)
            .map_err(LinuxNetworkBrokerError::Catalog)?;
        Self::start(
            parent_directory.as_ref(),
            destination_directory.into(),
            access,
            LinuxNetworkBrokerCatalog::Endpoint,
            executor,
        )
    }

    /// Starts a broker for one exact-origin catalog.
    ///
    /// The catalog's opaque identifiers must exactly equal `access`; dynamic
    /// paths and queries are still interpreted only by the catalog after it
    /// verifies the reviewed origin.
    pub fn bind_origin<R>(
        parent_directory: impl AsRef<Path>,
        destination_directory: impl Into<PathBuf>,
        access: NetworkOriginAccess,
        catalog: HttpOriginCatalog,
        secret_resolver: R,
    ) -> Result<Self, LinuxNetworkBrokerError>
    where
        R: HttpEndpointSecretResolver + Send + 'static,
    {
        let executor = NetworkCatalogExecutor::origin(catalog, access.clone(), secret_resolver)
            .map_err(LinuxNetworkBrokerError::Catalog)?;
        Self::start(
            parent_directory.as_ref(),
            destination_directory.into(),
            access,
            LinuxNetworkBrokerCatalog::Origin,
            executor,
        )
    }

    fn start<R>(
        parent_directory: &Path,
        destination_directory: PathBuf,
        access: NetworkOriginAccess,
        catalog: LinuxNetworkBrokerCatalog,
        executor: NetworkCatalogExecutor<R>,
    ) -> Result<Self, LinuxNetworkBrokerError>
    where
        R: HttpEndpointSecretResolver + Send + 'static,
    {
        debug_assert_eq!(catalog.internal(), executor.mode());
        let parent_directory = prepare_parent_directory(parent_directory)?;
        let source_directory = create_private_directory(&parent_directory)?;
        let socket = source_directory.join(LINUX_NETWORK_BROKER_SOCKET_NAME);
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(source) => {
                let _ = fs::remove_dir(&source_directory);
                return Err(LinuxNetworkBrokerError::Io {
                    operation: "bind private broker socket",
                    path: socket,
                    source,
                });
            }
        };
        if let Err(source) = set_socket_permissions(&socket) {
            drop(listener);
            let _ = fs::remove_file(&socket);
            let _ = fs::remove_dir(&source_directory);
            return Err(LinuxNetworkBrokerError::Io {
                operation: "restrict private broker socket",
                path: socket,
                source,
            });
        }
        if let Err(source) = listener.set_nonblocking(true) {
            drop(listener);
            let _ = fs::remove_file(&socket);
            let _ = fs::remove_dir(&source_directory);
            return Err(LinuxNetworkBrokerError::Io {
                operation: "configure private broker listener",
                path: socket,
                source,
            });
        }

        let mount = match LinuxNetworkBrokerMount::new(
            source_directory.clone(),
            destination_directory,
            LINUX_NETWORK_BROKER_SOCKET_NAME,
            access,
        ) {
            Ok(mount) => mount,
            Err(source) => {
                drop(listener);
                let _ = fs::remove_file(&socket);
                let _ = fs::remove_dir(&source_directory);
                return Err(LinuxNetworkBrokerError::Policy(source));
            }
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_failed = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let server_failed_flag = Arc::clone(&server_failed);
        let join = match thread::Builder::new()
            .name("splash-linux-network-broker".to_owned())
            .spawn(move || serve(listener, executor, server_shutdown, server_failed_flag))
        {
            Ok(join) => join,
            Err(source) => {
                let _ = fs::remove_file(&socket);
                let _ = fs::remove_dir(&source_directory);
                return Err(LinuxNetworkBrokerError::Io {
                    operation: "start private broker thread",
                    path: socket,
                    source,
                });
            }
        };
        Ok(Self {
            mount,
            catalog,
            source_directory,
            shutdown,
            server_failed,
            join: Some(join),
        })
    }

    /// Returns the exact mount that must be installed into the matching
    /// Bubblewrap policy.
    pub fn mount(&self) -> &LinuxNetworkBrokerMount {
        &self.mount
    }

    /// Returns the catalog shape accepted by the broker socket.
    pub const fn catalog(&self) -> LinuxNetworkBrokerCatalog {
        self.catalog
    }

    /// Stops the broker, waits for its bounded request loop, and removes its
    /// private socket directory.
    ///
    /// A worker that has already started a request may keep shutdown waiting up
    /// to the catalog's bounded deadline. Hosts should terminate/reap the
    /// contained worker before this call when they need prompt session teardown.
    pub fn shutdown(mut self) -> Result<(), LinuxNetworkBrokerShutdownError> {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> Result<(), LinuxNetworkBrokerShutdownError> {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| LinuxNetworkBrokerShutdownError::ServerPanicked)?;
        }
        let socket = self.source_directory.join(LINUX_NETWORK_BROKER_SOCKET_NAME);
        match fs::remove_file(&socket) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(LinuxNetworkBrokerShutdownError::Cleanup {
                    path: socket,
                    source,
                });
            }
        }
        match fs::remove_dir(&self.source_directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(LinuxNetworkBrokerShutdownError::Cleanup {
                    path: self.source_directory.clone(),
                    source,
                });
            }
        }
        if self.server_failed.load(Ordering::Acquire) {
            return Err(LinuxNetworkBrokerShutdownError::ServerUnavailable);
        }
        Ok(())
    }
}

impl Drop for LinuxNetworkBroker {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

/// Client used by a reviewed contained-worker adapter.
///
/// Construct this from the fixed worker-visible path returned by
/// [`LinuxNetworkBrokerMount::worker_socket_path`]. It validates that the
/// active grant includes the requested opaque `network_origin` identifier
/// before it contacts the broker. A custom worker adapter must map errors to
/// its finite adapter failure and must use durable worker methods for any
/// crash-sensitive POST effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxNetworkBrokerClient {
    socket_path: PathBuf,
    catalog: LinuxNetworkBrokerCatalog,
}

impl LinuxNetworkBrokerClient {
    /// Creates a client for one fixed worker-visible socket path.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        catalog: LinuxNetworkBrokerCatalog,
    ) -> Result<Self, LinuxNetworkBrokerClientError> {
        let socket_path = socket_path.into();
        if !is_absolute_normal_path(&socket_path)
            || socket_path.as_os_str().len() > MAX_LINUX_NETWORK_BROKER_SOCKET_PATH_BYTES
        {
            return Err(LinuxNetworkBrokerClientError::InvalidSocketPath);
        }
        Ok(Self {
            socket_path,
            catalog,
        })
    }

    /// Sends one bounded catalog request using the active worker grant.
    ///
    /// The input is revalidated by the host catalog. This local check only
    /// prevents a reviewed adapter from turning another grant's identifier into
    /// an ambient request before any socket I/O occurs.
    pub fn request(
        &self,
        grant: &CapabilityGrant,
        input: &JsonValue,
    ) -> Result<JsonValue, LinuxNetworkBrokerClientError> {
        let identifier = input
            .as_object()
            .and_then(|object| object.get(self.catalog.identifier_field()))
            .and_then(JsonValue::as_str)
            .filter(|identifier| !identifier.is_empty())
            .ok_or(LinuxNetworkBrokerClientError::Denied)?;
        if !grant.resources.iter().any(|resource| {
            resource.kind == ResourceKind::NetworkOrigin && resource.id == identifier
        }) {
            return Err(LinuxNetworkBrokerClientError::Denied);
        }
        let request = BrokerRequestRef {
            version: LINUX_NETWORK_BROKER_PROTOCOL_VERSION,
            input,
        };
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|_| LinuxNetworkBrokerClientError::Unavailable)?;
        stream
            .set_read_timeout(Some(MAX_HTTP_ENDPOINT_REQUEST_TIMEOUT))
            .map_err(|_| LinuxNetworkBrokerClientError::Unavailable)?;
        stream
            .set_write_timeout(Some(MAX_HTTP_ENDPOINT_REQUEST_TIMEOUT))
            .map_err(|_| LinuxNetworkBrokerClientError::Unavailable)?;
        write_frame(&mut stream, &request)
            .map_err(|_| LinuxNetworkBrokerClientError::Unavailable)?;
        let response = read_frame(&mut stream)
            .and_then(|bytes| {
                serde_json::from_slice::<BrokerResponse>(&bytes).map_err(invalid_frame)
            })
            .map_err(|_| LinuxNetworkBrokerClientError::Protocol)?;
        match response {
            BrokerResponse::Ok { version, output }
                if version == LINUX_NETWORK_BROKER_PROTOCOL_VERSION
                    && (output.is_object() || output.is_array()) =>
            {
                Ok(output)
            }
            BrokerResponse::Denied { version }
                if version == LINUX_NETWORK_BROKER_PROTOCOL_VERSION =>
            {
                Err(LinuxNetworkBrokerClientError::Denied)
            }
            BrokerResponse::Failed { version }
                if version == LINUX_NETWORK_BROKER_PROTOCOL_VERSION =>
            {
                Err(LinuxNetworkBrokerClientError::Failed)
            }
            BrokerResponse::Ok { .. }
            | BrokerResponse::Denied { .. }
            | BrokerResponse::Failed { .. } => Err(LinuxNetworkBrokerClientError::Protocol),
        }
    }

    /// Returns the fixed worker-visible socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the catalog shape this client sends to the broker.
    pub const fn catalog(&self) -> LinuxNetworkBrokerCatalog {
        self.catalog
    }
}

/// Failure while starting a Linux network broker.
#[derive(Debug)]
#[non_exhaustive]
pub enum LinuxNetworkBrokerError {
    ParentNotDirectory {
        path: PathBuf,
    },
    ParentNotPrivate {
        path: PathBuf,
    },
    EntropyUnavailable,
    Catalog(HttpEndpointCatalogError),
    Policy(BubblewrapPolicyError),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl Display for LinuxNetworkBrokerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParentNotDirectory { path } => write!(
                formatter,
                "Linux network broker parent {} must be an existing private directory",
                path.display()
            ),
            Self::ParentNotPrivate { path } => write!(
                formatter,
                "Linux network broker parent {} must not be group or world writable",
                path.display()
            ),
            Self::EntropyUnavailable => {
                formatter.write_str("OS entropy is unavailable for Linux network broker directory")
            }
            Self::Catalog(error) => {
                write!(formatter, "invalid Linux network broker catalog: {error}")
            }
            Self::Policy(error) => write!(formatter, "invalid Linux network broker mount: {error}"),
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "could not {operation} at Linux network broker path {}: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for LinuxNetworkBrokerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Catalog(error) => Some(error),
            Self::Policy(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::ParentNotDirectory { .. }
            | Self::ParentNotPrivate { .. }
            | Self::EntropyUnavailable => None,
        }
    }
}

/// Failure while stopping a Linux network broker.
#[derive(Debug)]
#[non_exhaustive]
pub enum LinuxNetworkBrokerShutdownError {
    ServerPanicked,
    ServerUnavailable,
    Cleanup { path: PathBuf, source: io::Error },
}

impl Display for LinuxNetworkBrokerShutdownError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerPanicked => formatter.write_str("Linux network broker server panicked"),
            Self::ServerUnavailable => {
                formatter.write_str("Linux network broker server became unavailable")
            }
            Self::Cleanup { path, source } => write!(
                formatter,
                "could not clean up Linux network broker path {}: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for LinuxNetworkBrokerShutdownError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cleanup { source, .. } => Some(source),
            Self::ServerPanicked | Self::ServerUnavailable => None,
        }
    }
}

/// Non-disclosing result returned by [`LinuxNetworkBrokerClient`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LinuxNetworkBrokerClientError {
    InvalidSocketPath,
    Denied,
    Failed,
    Unavailable,
    Protocol,
}

impl Display for LinuxNetworkBrokerClientError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSocketPath => {
                formatter.write_str("invalid Linux network broker socket path")
            }
            Self::Denied => formatter.write_str("Linux network broker access was denied"),
            Self::Failed => formatter.write_str("Linux network broker request failed"),
            Self::Unavailable => formatter.write_str("Linux network broker is unavailable"),
            Self::Protocol => formatter.write_str("Linux network broker protocol failed"),
        }
    }
}

impl std::error::Error for LinuxNetworkBrokerClientError {}

#[derive(Serialize)]
struct BrokerRequestRef<'a> {
    version: u8,
    input: &'a JsonValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerRequest {
    version: u8,
    input: JsonValue,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum BrokerResponse {
    Ok { version: u8, output: JsonValue },
    Denied { version: u8 },
    Failed { version: u8 },
}

fn serve<R>(
    listener: UnixListener,
    mut executor: NetworkCatalogExecutor<R>,
    shutdown: Arc<AtomicBool>,
    server_failed: Arc<AtomicBool>,
) where
    R: HttpEndpointSecretResolver,
{
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => serve_connection(stream, &mut executor),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(_) => {
                server_failed.store(true, Ordering::Release);
                break;
            }
        }
    }
}

fn serve_connection<R>(mut stream: UnixStream, executor: &mut NetworkCatalogExecutor<R>)
where
    R: HttpEndpointSecretResolver,
{
    let _ = stream.set_read_timeout(Some(MAX_HTTP_ENDPOINT_REQUEST_TIMEOUT));
    let _ = stream.set_write_timeout(Some(MAX_HTTP_ENDPOINT_REQUEST_TIMEOUT));
    let response = match read_frame(&mut stream)
        .and_then(|bytes| serde_json::from_slice::<BrokerRequest>(&bytes).map_err(invalid_frame))
    {
        Ok(request) if request.version == LINUX_NETWORK_BROKER_PROTOCOL_VERSION => {
            match executor.execute(request.input) {
                Ok(output) => BrokerResponse::Ok {
                    version: LINUX_NETWORK_BROKER_PROTOCOL_VERSION,
                    output,
                },
                Err(error) if error.is_access_denied() => BrokerResponse::Denied {
                    version: LINUX_NETWORK_BROKER_PROTOCOL_VERSION,
                },
                Err(_) => BrokerResponse::Failed {
                    version: LINUX_NETWORK_BROKER_PROTOCOL_VERSION,
                },
            }
        }
        Ok(_) | Err(_) => BrokerResponse::Denied {
            version: LINUX_NETWORK_BROKER_PROTOCOL_VERSION,
        },
    };
    let _ = write_frame(&mut stream, &response);
}

fn prepare_parent_directory(parent_directory: &Path) -> Result<PathBuf, LinuxNetworkBrokerError> {
    let parent_directory =
        fs::canonicalize(parent_directory).map_err(|source| LinuxNetworkBrokerError::Io {
            operation: "resolve private broker parent",
            path: parent_directory.to_path_buf(),
            source,
        })?;
    let metadata =
        fs::metadata(&parent_directory).map_err(|source| LinuxNetworkBrokerError::Io {
            operation: "inspect private broker parent",
            path: parent_directory.clone(),
            source,
        })?;
    if !metadata.is_dir() {
        return Err(LinuxNetworkBrokerError::ParentNotDirectory {
            path: parent_directory,
        });
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(LinuxNetworkBrokerError::ParentNotPrivate {
            path: parent_directory,
        });
    }
    Ok(parent_directory)
}

fn create_private_directory(parent_directory: &Path) -> Result<PathBuf, LinuxNetworkBrokerError> {
    for _ in 0..MAX_DIRECTORY_CREATION_ATTEMPTS {
        let mut entropy = [0_u8; 16];
        getrandom::fill(&mut entropy).map_err(|_| LinuxNetworkBrokerError::EntropyUnavailable)?;
        let directory = parent_directory.join(format!(
            ".splash-network-{}",
            entropy
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(LinuxNetworkBrokerError::Io {
                    operation: "create private broker directory",
                    path: directory,
                    source,
                });
            }
        }
    }
    Err(LinuxNetworkBrokerError::EntropyUnavailable)
}

fn set_socket_permissions(socket: &Path) -> io::Result<()> {
    let mut permissions = fs::metadata(socket)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(socket, permissions)
}

fn is_absolute_normal_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let mut frame = Vec::with_capacity(1024);
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "private broker stream ended before one frame",
            ));
        }
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if frame.len().saturating_add(consumed) > MAX_LINUX_NETWORK_BROKER_FRAME_BYTES + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private broker frame exceeds its fixed maximum",
            ));
        }
        frame.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if frame.last() == Some(&b'\n') {
            frame.pop();
            return Ok(frame);
        }
    }
}

struct BoundedFrameBuffer {
    bytes: Vec<u8>,
}

impl BoundedFrameBuffer {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(1024),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedFrameBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_LINUX_NETWORK_BROKER_FRAME_BYTES.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private broker frame exceeds its fixed maximum",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> io::Result<()> {
    let mut frame = BoundedFrameBuffer::new();
    serde_json::to_writer(&mut frame, value).map_err(invalid_frame)?;
    let mut frame = frame.into_bytes();
    frame.push(b'\n');
    stream.write_all(&frame)?;
    stream.flush()
}

fn invalid_frame(_error: serde_json::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "private broker frame is invalid JSON",
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;

    use serde_json::json;
    use splash_protocol::{CapabilityManifest, ResourceSelector};

    use super::*;
    use crate::http_endpoint_catalog::{
        HttpEndpoint, HttpEndpointMethod, HttpEndpointSecret, HttpEndpointSecretError,
    };

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "splash-linux-network-broker-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn access() -> NetworkOriginAccess {
        let mut grant = CapabilityGrant::json("release.read");
        grant
            .resources
            .insert(ResourceSelector::new(ResourceKind::NetworkOrigin, "release.status").unwrap());
        let manifest = CapabilityManifest::new("broker-session", vec![grant]).unwrap();
        NetworkOriginAccess::from_manifest(&manifest).unwrap()
    }

    fn grant() -> CapabilityGrant {
        let mut grant = CapabilityGrant::json("release.read");
        grant
            .resources
            .insert(ResourceSelector::new(ResourceKind::NetworkOrigin, "release.status").unwrap());
        grant
    }

    fn no_secret_resolver(
        _identifier: &str,
    ) -> Result<HttpEndpointSecret, HttpEndpointSecretError> {
        unreachable!("endpoint has no secret binding")
    }

    #[test]
    fn broker_exposes_only_its_exact_catalog_and_returns_bounded_json() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (seen_sender, seen_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let read = std::io::Read::read(&mut stream, &mut request).unwrap();
            seen_sender
                .send(String::from_utf8_lossy(&request[..read]).into_owned())
                .unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}")
                .unwrap();
        });

        let mut catalog = HttpEndpointCatalog::default();
        catalog
            .insert(
                HttpEndpoint::insecure_http(
                    "release.status",
                    HttpEndpointMethod::Get,
                    format!("http://{address}/release"),
                )
                .unwrap(),
            )
            .unwrap();
        let directory = TestDirectory::new();
        let broker = LinuxNetworkBroker::bind_endpoint(
            directory.path(),
            DEFAULT_LINUX_NETWORK_BROKER_DESTINATION,
            access(),
            catalog,
            no_secret_resolver,
        )
        .unwrap();
        let client = LinuxNetworkBrokerClient::new(
            broker
                .mount()
                .source_directory()
                .join(LINUX_NETWORK_BROKER_SOCKET_NAME),
            LinuxNetworkBrokerCatalog::Endpoint,
        )
        .unwrap();

        assert_eq!(
            client
                .request(&grant(), &json!({"endpoint": "release.status"}))
                .unwrap(),
            json!({"ok": true})
        );
        assert!(seen_receiver
            .recv()
            .unwrap()
            .starts_with("GET /release HTTP/1.1"));
        server.join().unwrap();
        broker.shutdown().unwrap();
    }

    #[test]
    fn broker_and_client_fail_closed_for_mismatched_or_ungranted_origins() {
        let directory = TestDirectory::new();
        let mut catalog = HttpEndpointCatalog::default();
        catalog
            .insert(
                HttpEndpoint::insecure_http(
                    "other.status",
                    HttpEndpointMethod::Get,
                    "http://127.0.0.1:1/status",
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            LinuxNetworkBroker::bind_endpoint(
                directory.path(),
                DEFAULT_LINUX_NETWORK_BROKER_DESTINATION,
                access(),
                catalog,
                no_secret_resolver,
            ),
            Err(LinuxNetworkBrokerError::Catalog(
                HttpEndpointCatalogError::NetworkOriginAccessMismatch
            ))
        ));

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut catalog = HttpEndpointCatalog::default();
        catalog
            .insert(
                HttpEndpoint::insecure_http(
                    "release.status",
                    HttpEndpointMethod::Get,
                    format!("http://{address}/release"),
                )
                .unwrap(),
            )
            .unwrap();
        let broker = LinuxNetworkBroker::bind_endpoint(
            directory.path(),
            DEFAULT_LINUX_NETWORK_BROKER_DESTINATION,
            access(),
            catalog,
            no_secret_resolver,
        )
        .unwrap();
        let client = LinuxNetworkBrokerClient::new(
            broker
                .mount()
                .source_directory()
                .join(LINUX_NETWORK_BROKER_SOCKET_NAME),
            LinuxNetworkBrokerCatalog::Endpoint,
        )
        .unwrap();
        let empty_grant = CapabilityGrant::json("release.read");
        assert_eq!(
            client.request(&empty_grant, &json!({"endpoint": "release.status"})),
            Err(LinuxNetworkBrokerClientError::Denied)
        );
        assert_eq!(
            LinuxNetworkBrokerClient::new(
                PathBuf::from(format!(
                    "/{}",
                    "socket".repeat(MAX_LINUX_NETWORK_BROKER_SOCKET_PATH_BYTES)
                )),
                LinuxNetworkBrokerCatalog::Endpoint,
            ),
            Err(LinuxNetworkBrokerClientError::InvalidSocketPath)
        );
        broker.shutdown().unwrap();
        drop(listener);
    }

    #[test]
    fn broker_frame_writer_stops_before_serializing_an_oversized_value() {
        let (mut stream, _) = UnixStream::pair().unwrap();
        let oversized = JsonValue::String("x".repeat(MAX_LINUX_NETWORK_BROKER_FRAME_BYTES + 1));

        let error = write_frame(&mut stream, &oversized).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
