//! Errors shared by the SDK's I/O and filesystem layers.
//!
//! A pagh syscall fails with a negative value whose magnitude is one of the
//! frozen numbers in [`libpagh::errno::Errno`]. This module turns that into a
//! std-shaped [`Error`] with a stable [`ErrorKind`], while preserving the
//! original `Errno` for callers that need the exact number.
//!
//! Operations the current ABI cannot express are reported as
//! [`ErrorKind::Unsupported`] with a message naming the missing syscall. That
//! is a deliberate, typed answer rather than a silent approximation.

use core::fmt;

use libpagh::errno::Errno;

/// The error class, modeled on `std::io::ErrorKind`.
///
/// The variants are a practical subset of std's: the ABI has no networking,
/// signals or process-spawning errors, so there is no `ConnectionRefused`,
/// `Interrupted`, `BrokenPipe` and so on. `BadFileDescriptor` is pagh-specific
/// in name; std folds the same condition into `Uncategorized` today.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum ErrorKind {
    /// The file or directory does not exist (`ENOENT`).
    NotFound,
    /// Permission bits, a read-only descriptor or an unsupported operation
    /// (`EACCES`, `EPERM`).
    PermissionDenied,
    /// The entry already exists (`EEXIST`).
    AlreadyExists,
    /// A caller-supplied argument is invalid (`EINVAL`).
    InvalidInput,
    /// Data was not valid for the operation, notably invalid UTF-8.
    InvalidData,
    /// The end of the input was reached while filling a fixed-size buffer.
    UnexpectedEof,
    /// A write returned zero bytes, so no progress can be made.
    WriteZero,
    /// The operation would block; on fd 0 this means "no byte queued yet".
    WouldBlock,
    /// The 1 MiB `brk` heap could not grow (`ENOMEM`).
    OutOfMemory,
    /// The filesystem is full (`ENOSPC`).
    StorageFull,
    /// The filesystem is mounted read-only (`EROFS`).
    ReadOnlyFilesystem,
    /// A path component is not a directory (`ENOTDIR`).
    NotADirectory,
    /// The path names a directory where a file is required (`EISDIR`).
    IsADirectory,
    /// The directory still has children (`ENOTEMPTY`).
    DirectoryNotEmpty,
    /// The name is longer than the ABI's 256-byte path limit
    /// (`ENAMETOOLONG`).
    InvalidFilename,
    /// Too many symbolic links (`ELOOP`).
    FilesystemLoop,
    /// The other end of a pipe/socket is gone (`EPIPE`).
    BrokenPipe,
    /// A file size or offset does not fit the ABI's integer (`EOVERFLOW`).
    FileTooLarge,
    /// The descriptor does not refer to an open file (`EBADF`).
    BadFileDescriptor,
    /// The ABI has no syscall for this operation (`ENOSYS`, `ENOTSUP`), or the
    /// SDK chose not to emulate it because doing so would be unsound or
    /// misleading.
    Unsupported,
    /// An I/O error that has no more specific class (`EIO`).
    Other,
    /// A kernel/libpagh drift value, or a condition with no std equivalent.
    Uncategorized,
}

impl ErrorKind {
    /// Map a frozen [`Errno`] to its error class.
    pub const fn from_errno(errno: Errno) -> ErrorKind {
        match errno {
            Errno::EPERM => ErrorKind::PermissionDenied,
            Errno::ENOENT => ErrorKind::NotFound,
            Errno::EIO => ErrorKind::Other,
            Errno::EBADF => ErrorKind::BadFileDescriptor,
            Errno::EAGAIN => ErrorKind::WouldBlock,
            Errno::ENOMEM => ErrorKind::OutOfMemory,
            Errno::EACCES => ErrorKind::PermissionDenied,
            Errno::EFAULT => ErrorKind::Uncategorized,
            Errno::EEXIST => ErrorKind::AlreadyExists,
            Errno::ENOTDIR => ErrorKind::NotADirectory,
            Errno::EISDIR => ErrorKind::IsADirectory,
            Errno::EINVAL => ErrorKind::InvalidInput,
            Errno::ENOSPC => ErrorKind::StorageFull,
            Errno::EROFS => ErrorKind::ReadOnlyFilesystem,
            Errno::ENOSYS => ErrorKind::Unsupported,
            Errno::ENOTEMPTY => ErrorKind::DirectoryNotEmpty,
            Errno::ENAMETOOLONG => ErrorKind::InvalidFilename,
            Errno::ELOOP => ErrorKind::FilesystemLoop,
            Errno::EOVERFLOW => ErrorKind::FileTooLarge,
            Errno::ENOTSUP => ErrorKind::Unsupported,
            Errno::EPIPE => ErrorKind::BrokenPipe,
            Errno::ENOTSOCK
            | Errno::EAFNOSUPPORT
            | Errno::ENETUNREACH
            | Errno::EHOSTUNREACH
            | Errno::ECONNREFUSED
            | Errno::ECONNRESET
            | Errno::EISCONN
            | Errno::ENOTCONN
            | Errno::ETIMEDOUT => ErrorKind::Uncategorized,
            Errno::ENOPROTOOPT => ErrorKind::Unsupported,
            Errno::Unknown => ErrorKind::Uncategorized,
        }
    }
}

/// An I/O or filesystem error.
///
/// It is `Copy` because it holds at most an [`Errno`], a static message and a
/// kind; cloning it never allocates. `Display` prints the ABI's own text for a
/// syscall failure, so CLI output (`cat: /x: No such file or directory`) is
/// stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    errno: Option<Errno>,
    message: Option<&'static str>,
}

impl Error {
    /// Build an error from a class and a static context message.
    pub const fn new(kind: ErrorKind, message: &'static str) -> Error {
        Error {
            kind,
            errno: None,
            message: Some(message),
        }
    }

    /// The typed "the ABI cannot do this" error.
    ///
    /// `what` should name the operation and, where useful, the missing syscall
    /// (for example `"Command::spawn: the ABI has no fork/exec"`).
    pub const fn unsupported(what: &'static str) -> Error {
        Error::new(ErrorKind::Unsupported, what)
    }

    /// The error class.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The original syscall error, when the failure came from the kernel.
    pub const fn errno(&self) -> Option<Errno> {
        self.errno
    }

    /// The original positive ABI error number, if any.
    pub const fn raw_os_error(&self) -> Option<i32> {
        match self.errno {
            Some(errno) => Some(errno.raw()),
            None => None,
        }
    }

    /// True when the operation is unsupported by the ABI (or by this SDK on
    /// purpose). Callers can use this instead of matching the message.
    pub const fn is_unsupported(&self) -> bool {
        matches!(self.kind, ErrorKind::Unsupported)
    }
}

impl From<Errno> for Error {
    fn from(errno: Errno) -> Error {
        Error {
            kind: ErrorKind::from_errno(errno),
            errno: Some(errno),
            message: None,
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            kind,
            errno: None,
            message: None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.message, self.errno) {
            // A context message plus the kernel's reason: keep both, because
            // "read-only filesystem" alone does not say which call failed.
            (Some(message), Some(errno)) => write!(f, "{message}: {errno}"),
            (Some(message), None) => f.write_str(message),
            (None, Some(errno)) => errno.fmt(f),
            (None, None) => f.write_str("unknown error"),
        }
    }
}

impl core::error::Error for Error {}

/// The SDK's fallible result type, std-shaped: `Result<T, io::Error>`.
pub type Result<T> = core::result::Result<T, Error>;

/// Convert an SDK error back to an ABI errno; custom errors become `EIO`.
impl From<Error> for Errno {
    fn from(error: Error) -> Errno {
        error.errno.unwrap_or(Errno::EIO)
    }
}
