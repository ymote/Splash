//! A bounded, host-owned catalog of descriptor-pinned text files.
//!
//! A host chooses every file during setup and assigns it a canonical opaque
//! identifier. Splash receives only that identifier through a registered
//! `tool.call`; it never supplies a filesystem path, directory, glob, or
//! file handle. `insert_path` opens the host-selected path once and retains
//! the resulting descriptor, so replacing that path later does not change the
//! catalog entry's file identity.
//!
//! This is a narrow local-data adapter, not operating-system containment. A
//! trusted host must select regular files whose contents are suitable for the
//! workflow, and treat returned content as untrusted data when another actor
//! can modify the file after it has been registered.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::{ToolDataFormat, ToolError, ToolPolicy, ToolRegistrationError, ToolRequest};

/// Default number of regular files a fixed catalog can retain.
pub const DEFAULT_MAX_FIXED_FILE_CATALOG_ENTRIES: usize = 64;
/// Absolute maximum number of regular files a fixed catalog can retain.
pub const MAX_FIXED_FILE_CATALOG_ENTRIES: usize = 1_024;
/// Default maximum UTF-8 byte length returned for one file read.
pub const DEFAULT_MAX_FIXED_FILE_BYTES: usize = 64 * 1024;
/// Absolute maximum UTF-8 byte length returned for one file read.
pub const MAX_FIXED_FILE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum UTF-8 byte length of a fixed-file catalog identifier.
pub const MAX_FIXED_FILE_ID_BYTES: usize = 128;

/// Host-selected bounds for a [`FixedFileCatalog`].
///
/// The catalog holds descriptors rather than file contents. `max_file_bytes`
/// bounds each read allocation and is applied again even when the file grows
/// after registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedFileCatalogLimits {
    pub max_entries: usize,
    pub max_file_bytes: usize,
}

impl FixedFileCatalogLimits {
    fn validate(self) -> Result<Self, FixedFileCatalogError> {
        if self.max_entries == 0 {
            return Err(FixedFileCatalogError::InvalidLimits(
                "max_entries must be greater than zero",
            ));
        }
        if self.max_entries > MAX_FIXED_FILE_CATALOG_ENTRIES {
            return Err(FixedFileCatalogError::InvalidLimits(
                "max_entries exceeds the hard limit",
            ));
        }
        if self.max_file_bytes == 0 {
            return Err(FixedFileCatalogError::InvalidLimits(
                "max_file_bytes must be greater than zero",
            ));
        }
        if self.max_file_bytes > MAX_FIXED_FILE_BYTES {
            return Err(FixedFileCatalogError::InvalidLimits(
                "max_file_bytes exceeds the hard limit",
            ));
        }
        Ok(self)
    }
}

impl Default for FixedFileCatalogLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_FIXED_FILE_CATALOG_ENTRIES,
            max_file_bytes: DEFAULT_MAX_FIXED_FILE_BYTES,
        }
    }
}

/// Host-side error while configuring or reading a fixed-file catalog.
///
/// The tool adapter deliberately converts these to generic script-facing
/// errors so paths and operating-system details are never returned to Splash.
#[derive(Debug)]
pub enum FixedFileCatalogError {
    InvalidLimits(&'static str),
    InvalidIdentifier,
    DuplicateIdentifier,
    EntryLimitExceeded { maximum: usize },
    NotRegularFile,
    Open(io::Error),
    Read(io::Error),
    NotFound,
    TooLarge { maximum: usize },
    InvalidUtf8,
}

impl Display for FixedFileCatalogError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(message) => formatter.write_str(message),
            Self::InvalidIdentifier => formatter.write_str("invalid fixed-file catalog identifier"),
            Self::DuplicateIdentifier => {
                formatter.write_str("fixed-file catalog identifier is already registered")
            }
            Self::EntryLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "fixed-file catalog exceeds its maximum of {maximum} entries"
                )
            }
            Self::NotRegularFile => {
                formatter.write_str("fixed-file catalog entries must be regular files")
            }
            Self::Open(error) => write!(
                formatter,
                "could not open fixed-file catalog entry: {error}"
            ),
            Self::Read(error) => write!(
                formatter,
                "could not read fixed-file catalog entry: {error}"
            ),
            Self::NotFound => formatter.write_str("fixed-file catalog entry is not registered"),
            Self::TooLarge { maximum } => {
                write!(
                    formatter,
                    "fixed-file catalog entry exceeds {maximum} bytes"
                )
            }
            Self::InvalidUtf8 => formatter.write_str("fixed-file catalog entry is not valid UTF-8"),
        }
    }
}

impl std::error::Error for FixedFileCatalogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open(error) | Self::Read(error) => Some(error),
            _ => None,
        }
    }
}

/// A setup-only catalog of regular files selected by the embedding host.
///
/// A catalog has no path lookup API. Each entry is retained as an opened
/// descriptor and can be read only by its opaque identifier. Consuming the
/// catalog through `register_fixed_file_catalog_tool` seals the entry set into
/// the tool handler.
pub struct FixedFileCatalog {
    limits: FixedFileCatalogLimits,
    entries: BTreeMap<String, File>,
}

impl FixedFileCatalog {
    /// Creates an empty catalog with explicit descriptor and read bounds.
    pub fn new(limits: FixedFileCatalogLimits) -> Result<Self, FixedFileCatalogError> {
        Ok(Self {
            limits: limits.validate()?,
            entries: BTreeMap::new(),
        })
    }

    /// Returns the immutable limits selected while configuring the catalog.
    pub const fn limits(&self) -> FixedFileCatalogLimits {
        self.limits
    }

    /// Returns how many descriptors the catalog currently retains.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the catalog has no registered files.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Opens one host-selected path and stores only the resulting descriptor.
    ///
    /// The path is never retained or exposed to Splash. Symlinks are resolved
    /// by the trusted host's open operation; the catalog retains the opened
    /// regular file rather than consulting the path again.
    pub fn insert_path(
        &mut self,
        identifier: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> Result<(), FixedFileCatalogError> {
        let identifier = identifier.into();
        self.validate_new_identifier(&identifier)?;
        let file = File::open(path).map_err(FixedFileCatalogError::Open)?;
        self.insert_validated_file(identifier, file)
    }

    /// Stores one already-opened regular file under a host-selected identifier.
    ///
    /// This is the preferred API when a host has already opened and verified a
    /// file through its platform-specific policy.
    pub fn insert_open_file(
        &mut self,
        identifier: impl Into<String>,
        file: File,
    ) -> Result<(), FixedFileCatalogError> {
        let identifier = identifier.into();
        self.validate_new_identifier(&identifier)?;
        self.insert_validated_file(identifier, file)
    }

    /// Reads one registered entry with the catalog's configured byte bound.
    ///
    /// This host API returns detailed errors. The script-facing adapter maps
    /// all such errors to generic messages to avoid disclosing local details.
    pub fn read(&mut self, identifier: &str) -> Result<String, FixedFileCatalogError> {
        self.read_with_limit(identifier, self.limits.max_file_bytes)
    }

    fn validate_new_identifier(&self, identifier: &str) -> Result<(), FixedFileCatalogError> {
        if !is_valid_identifier(identifier) {
            return Err(FixedFileCatalogError::InvalidIdentifier);
        }
        if self.entries.contains_key(identifier) {
            return Err(FixedFileCatalogError::DuplicateIdentifier);
        }
        if self.entries.len() >= self.limits.max_entries {
            return Err(FixedFileCatalogError::EntryLimitExceeded {
                maximum: self.limits.max_entries,
            });
        }
        Ok(())
    }

    fn insert_validated_file(
        &mut self,
        identifier: String,
        file: File,
    ) -> Result<(), FixedFileCatalogError> {
        let metadata = file.metadata().map_err(FixedFileCatalogError::Open)?;
        if !metadata.is_file() {
            return Err(FixedFileCatalogError::NotRegularFile);
        }
        self.entries.insert(identifier, file);
        Ok(())
    }

    fn read_with_limit(
        &mut self,
        identifier: &str,
        max_bytes: usize,
    ) -> Result<String, FixedFileCatalogError> {
        if !is_valid_identifier(identifier) {
            return Err(FixedFileCatalogError::InvalidIdentifier);
        }
        let file = self
            .entries
            .get_mut(identifier)
            .ok_or(FixedFileCatalogError::NotFound)?;
        file.seek(SeekFrom::Start(0))
            .map_err(FixedFileCatalogError::Read)?;

        // `max_bytes` is validated at construction and capped again when a
        // tool policy supplies a smaller output budget, so adding the sentinel
        // cannot overflow.
        let mut bytes = Vec::new();
        let mut bounded = file.take((max_bytes + 1) as u64);
        bounded
            .read_to_end(&mut bytes)
            .map_err(FixedFileCatalogError::Read)?;
        if bytes.len() > max_bytes {
            return Err(FixedFileCatalogError::TooLarge { maximum: max_bytes });
        }
        String::from_utf8(bytes).map_err(|_| FixedFileCatalogError::InvalidUtf8)
    }

    pub(crate) fn validate_tool_policy(
        &self,
        policy: &ToolPolicy,
    ) -> Result<(), ToolRegistrationError> {
        if policy.data_format != ToolDataFormat::Text {
            return Err(ToolRegistrationError::InvalidPolicy(
                "fixed-file catalog tools require a text policy",
            ));
        }
        if self.entries.is_empty() {
            return Err(ToolRegistrationError::InvalidPolicy(
                "fixed-file catalog must contain at least one entry",
            ));
        }
        if self
            .entries
            .keys()
            .map(String::len)
            .max()
            .unwrap_or_default()
            > policy.max_input_bytes
        {
            return Err(ToolRegistrationError::InvalidPolicy(
                "fixed-file catalog identifier exceeds the tool input limit",
            ));
        }
        Ok(())
    }

    pub(crate) fn into_tool_handler(
        mut self,
        max_output_bytes: usize,
    ) -> impl FnMut(&ToolRequest) -> Result<String, ToolError> + 'static {
        let max_read_bytes = self.limits.max_file_bytes.min(max_output_bytes);
        move |request| {
            self.read_with_limit(&request.input, max_read_bytes)
                .map_err(|error| error.into_tool_error())
        }
    }
}

impl Default for FixedFileCatalog {
    fn default() -> Self {
        Self::new(FixedFileCatalogLimits::default()).expect("default fixed-file limits are valid")
    }
}

fn is_valid_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.len() <= MAX_FIXED_FILE_ID_BYTES
        && identifier
            .bytes()
            .enumerate()
            .all(|(index, byte)| match byte {
                b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' => index != 0 || byte != b'.',
                _ => false,
            })
}

impl FixedFileCatalogError {
    fn into_tool_error(self) -> ToolError {
        match self {
            Self::InvalidIdentifier | Self::NotFound => {
                ToolError::Denied("fixed file access was denied".to_owned())
            }
            _ => ToolError::Failed("fixed file read failed".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{mobile::MobileRuntimeBuilder, AuditOutcome, CapabilityRuntime, ToolMetadata};

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);

    struct TestFile {
        path: PathBuf,
    }

    impl TestFile {
        fn new(label: &str, bytes: &[u8]) -> Self {
            let sequence = NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "splash-fixed-file-catalog-{label}-{}-{sequence}",
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

    #[test]
    fn reads_only_registered_canonical_identifiers() {
        let file = TestFile::new("canonical", b"reviewed notes\n");
        let mut catalog = FixedFileCatalog::default();
        catalog.insert_path("release.notes", file.path()).unwrap();

        assert_eq!(catalog.read("release.notes").unwrap(), "reviewed notes\n");
        assert!(matches!(
            catalog.read("/host/selected/path"),
            Err(FixedFileCatalogError::InvalidIdentifier)
        ));
        assert!(matches!(
            catalog.read("not-present"),
            Err(FixedFileCatalogError::NotFound)
        ));
    }

    #[test]
    fn rejects_invalid_configuration_and_catalog_growth() {
        assert!(matches!(
            FixedFileCatalog::new(FixedFileCatalogLimits {
                max_entries: 0,
                max_file_bytes: 1,
            }),
            Err(FixedFileCatalogError::InvalidLimits(_))
        ));
        assert!(matches!(
            FixedFileCatalog::new(FixedFileCatalogLimits {
                max_entries: 1,
                max_file_bytes: MAX_FIXED_FILE_BYTES + 1,
            }),
            Err(FixedFileCatalogError::InvalidLimits(_))
        ));

        let first = TestFile::new("first", b"first");
        let second = TestFile::new("second", b"second");
        let mut catalog = FixedFileCatalog::new(FixedFileCatalogLimits {
            max_entries: 1,
            max_file_bytes: 32,
        })
        .unwrap();

        assert!(matches!(
            catalog.insert_path("../not-an-id", first.path()),
            Err(FixedFileCatalogError::InvalidIdentifier)
        ));
        catalog.insert_path("first", first.path()).unwrap();
        assert!(matches!(
            catalog.insert_path("second", second.path()),
            Err(FixedFileCatalogError::EntryLimitExceeded { maximum: 1 })
        ));
        assert!(matches!(
            catalog.insert_path("first", second.path()),
            Err(FixedFileCatalogError::DuplicateIdentifier)
        ));
    }

    #[test]
    fn bounds_and_validates_file_content() {
        let oversized = TestFile::new("oversized", b"four");
        let invalid_utf8 = TestFile::new("invalid-utf8", b"\xff");
        let limits = FixedFileCatalogLimits {
            max_entries: 2,
            max_file_bytes: 3,
        };
        let mut catalog = FixedFileCatalog::new(limits).unwrap();
        catalog.insert_path("oversized", oversized.path()).unwrap();
        catalog
            .insert_path("invalid.utf8", invalid_utf8.path())
            .unwrap();

        assert!(matches!(
            catalog.read("oversized"),
            Err(FixedFileCatalogError::TooLarge { maximum: 3 })
        ));
        assert!(matches!(
            catalog.read("invalid.utf8"),
            Err(FixedFileCatalogError::InvalidUtf8)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn retains_the_opened_file_when_its_path_is_replaced() {
        let original = TestFile::new("original", b"original");
        let replacement = TestFile::new("replacement", b"replacement");
        let mut catalog = FixedFileCatalog::default();
        catalog.insert_path("document", original.path()).unwrap();

        fs::rename(replacement.path(), original.path()).expect("path replacement succeeds");

        assert_eq!(catalog.read("document").unwrap(), "original");
    }

    #[test]
    fn registers_a_redacted_text_tool_for_the_default_runtime() {
        let file = TestFile::new("runtime", b"host-selected text");
        let mut catalog = FixedFileCatalog::default();
        catalog.insert_path("document", file.path()).unwrap();

        let mut policy = ToolPolicy::new("file.read");
        policy.max_calls = 2;
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_fixed_file_catalog_tool(
                policy,
                ToolMetadata::new("Reads one host-selected text document by opaque identifier."),
                catalog,
            )
            .unwrap();

        let allowed = runtime
            .eval(
                "use mod.tool\n\
                 use mod.std.assert\n\
                 let contents = tool.call(\"file.read\", \"document\")\n\
                 assert(contents == \"host-selected text\")",
            )
            .unwrap();
        assert!(allowed.completed(), "{:?}", allowed.diagnostics);

        let denied = runtime
            .eval("use mod.tool\ntool.call(\"file.read\", \"/etc/passwd\")")
            .unwrap();
        assert!(!denied.succeeded());
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn tool_handler_redacts_unknown_identifier_details() {
        let file = TestFile::new("redacted", b"text");
        let mut catalog = FixedFileCatalog::default();
        catalog.insert_path("document", file.path()).unwrap();
        let mut handler = catalog.into_tool_handler(64);

        let error = handler(&ToolRequest {
            name: "file.read".to_owned(),
            input: "/private/host/document".to_owned(),
            call_index: 1,
        })
        .unwrap_err();

        assert_eq!(
            error,
            ToolError::Denied("fixed file access was denied".to_owned())
        );
        assert!(!error.to_string().contains("/private/host/document"));
    }

    #[test]
    fn rejects_a_non_text_or_unaddressable_catalog_tool() {
        let mut runtime = CapabilityRuntime::default();
        assert_eq!(
            runtime
                .register_fixed_file_catalog_tool(
                    ToolPolicy::new("file.read"),
                    ToolMetadata::new("Empty catalog."),
                    FixedFileCatalog::default(),
                )
                .unwrap_err(),
            ToolRegistrationError::InvalidPolicy(
                "fixed-file catalog must contain at least one entry"
            )
        );

        let file = TestFile::new("policy", b"text");
        let mut catalog = FixedFileCatalog::default();
        catalog.insert_path("document", file.path()).unwrap();

        assert_eq!(
            runtime
                .register_fixed_file_catalog_tool(
                    ToolPolicy::json("file.read"),
                    ToolMetadata::new("Invalid JSON policy."),
                    catalog,
                )
                .unwrap_err(),
            ToolRegistrationError::InvalidPolicy("fixed-file catalog tools require a text policy")
        );

        let file = TestFile::new("input-limit", b"text");
        let mut catalog = FixedFileCatalog::default();
        catalog.insert_path("document", file.path()).unwrap();
        let mut policy = ToolPolicy::new("file.read");
        policy.max_input_bytes = 3;
        assert_eq!(
            runtime
                .register_fixed_file_catalog_tool(
                    policy,
                    ToolMetadata::new("Input cannot address the catalog entry."),
                    catalog,
                )
                .unwrap_err(),
            ToolRegistrationError::InvalidPolicy(
                "fixed-file catalog identifier exceeds the tool input limit"
            )
        );
    }

    #[test]
    fn honors_the_smaller_tool_output_limit_without_truncation() {
        let file = TestFile::new("output-limit", b"four");
        let mut catalog = FixedFileCatalog::new(FixedFileCatalogLimits {
            max_entries: 1,
            max_file_bytes: 8,
        })
        .unwrap();
        catalog.insert_path("document", file.path()).unwrap();
        let mut policy = ToolPolicy::new("file.read");
        policy.max_output_bytes = 3;
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_fixed_file_catalog_tool(
                policy,
                ToolMetadata::new("Reads one bounded text document."),
                catalog,
            )
            .unwrap();

        let report = runtime
            .eval("use mod.tool\ntool.call(\"file.read\", \"document\")")
            .unwrap();

        assert!(!report.succeeded());
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Failed);
    }

    #[test]
    fn seals_a_fixed_file_tool_into_the_mobile_profile() {
        let file = TestFile::new("mobile", b"mobile document");
        let mut catalog = FixedFileCatalog::default();
        catalog.insert_path("guide", file.path()).unwrap();

        let mut builder = MobileRuntimeBuilder::new().unwrap();
        builder
            .register_fixed_file_catalog_tool(
                ToolPolicy::new("file.read"),
                ToolMetadata::new("Reads one bundled text file."),
                catalog,
            )
            .unwrap();
        let mut runtime = builder.build();

        let report = runtime
            .eval(
                "use mod.tool\n\
                 use mod.std.assert\n\
                 assert(tool.call(\"file.read\", \"guide\") == \"mobile document\")",
            )
            .unwrap();
        assert!(report.completed(), "{:?}", report.diagnostics);
    }
}
