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
/// The variants are a practical subset of std's: the ABI's networking is IPv4
/// TCP/UDP only, and a wait is not interruptible by a signal in this SDK, so
/// there is no `Interrupted`, `Deadlock` or `CrossesDevices`.
/// `BadFileDescriptor` is pagh-specific in name; std folds the same condition
/// into `Uncategorized` today.
///
/// `libpagh` 0.6.0's frozen errno table has no `EADDRINUSE`, `EADDRNOTAVAIL`,
/// `EMSGSIZE`, `ESRCH`, `EINTR`, `E2BIG`, `ENOEXEC`, `ECHILD` or
/// `EDESTADDRREQ` entry; a number outside the table arrives as
/// [`Errno::Unknown`] (raw 0, message `Unknown error (outside the pagh ABI)`).
/// 0.6.1 records the errnos the kernel always returned, so this crate supports
/// both: the variants it names directly are the 0.6.0 set, and the 0.6.1
/// additions are matched in [`ErrorKind::from_errno`] by their frozen number,
/// which keeps the build working against the pinned sibling while a newer one
/// gets the typed kinds.
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
    /// A blocking call returned early because a signal handler is about to run
    /// (`EINTR`, libpagh 0.6.1). The SDK's own wait loops do not restart on it
    /// yet, because no signal handler can be installed through this SDK.
    Interrupted,
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
    /// `execve` was given an over-long argv/envp (`E2BIG`, libpagh 0.6.1).
    ArgumentListTooLong,
    /// Too many symbolic links (`ELOOP`).
    FilesystemLoop,
    /// The other end of a pipe/socket is gone (`EPIPE`).
    BrokenPipe,
    /// A file size or offset does not fit the ABI's integer (`EOVERFLOW`).
    FileTooLarge,
    /// The descriptor does not refer to an open file (`EBADF`).
    BadFileDescriptor,
    /// The peer refused the connection (`ECONNREFUSED`).
    ConnectionRefused,
    /// The peer reset the connection (`ECONNRESET`).
    ConnectionReset,
    /// The descriptor is a socket, but not a connected one (`ENOTCONN`).
    NotConnected,
    /// The kernel's own deadline expired (`ETIMEDOUT`).
    TimedOut,
    /// There is no DHCP lease or no route to the network (`ENETUNREACH`).
    NetworkUnreachable,
    /// ARP could not resolve the next hop (`EHOSTUNREACH`).
    HostUnreachable,
    /// `bind` names a port another socket already owns (`EADDRINUSE`,
    /// libpagh 0.6.1).
    AddrInUse,
    /// `bind` names an address this interface does not hold (`EADDRNOTAVAIL`,
    /// libpagh 0.6.1).
    AddrNotAvailable,
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
    ///
    /// `unreachable_patterns` is allowed because whether the final wildcard is
    /// reachable depends on the sibling `pagh-api`'s `Errno` variant count:
    /// against 0.6.0 every variant is named above, against 0.6.1 the wildcard
    /// maps the added numbers. One build must stay warning-free with both.
    #[allow(unreachable_patterns)]
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
            Errno::ECONNREFUSED => ErrorKind::ConnectionRefused,
            Errno::ECONNRESET => ErrorKind::ConnectionReset,
            Errno::ENOTCONN => ErrorKind::NotConnected,
            Errno::ETIMEDOUT => ErrorKind::TimedOut,
            Errno::ENETUNREACH => ErrorKind::NetworkUnreachable,
            Errno::EHOSTUNREACH => ErrorKind::HostUnreachable,
            // A TLS handshake or record that did not follow TLS 1.3: the
            // connection is not usable, but nothing about the peer's identity
            // was decided here (`EKEYREJECTED` is that answer).
            Errno::EPROTO => ErrorKind::InvalidData,
            // The server certificate was rejected by the kernel's fail-closed
            // verification: no chain to the committed bundle, a SAN that does
            // not authorize the name, a validity window the clock refuses, or a
            // failed `CertificateVerify`. The peer is not who it claimed to be,
            // which is a permission-shaped refusal rather than a broken stream.
            Errno::EKEYREJECTED => ErrorKind::PermissionDenied,
            Errno::ENOTSOCK | Errno::EAFNOSUPPORT | Errno::EISCONN | Errno::Unknown => {
                ErrorKind::Uncategorized
            }
            Errno::ENOPROTOOPT => ErrorKind::Unsupported,
            // libpagh 0.6.1 records the errnos the kernel already returned.
            // Naming its variants here would make this crate fail to compile
            // against the pinned 0.6.0, so the additions are matched by their
            // frozen number: 0.6.0 never produces them (`from_raw` yields
            // `Unknown`), and 0.6.1 gets the typed kind from the same build.
            other => match other.raw() {
                // EINTR: a blocking wait was interrupted by a signal.
                4 => ErrorKind::Interrupted,
                // E2BIG: execve refused an over-long argv/envp.
                7 => ErrorKind::ArgumentListTooLong,
                // EDESTADDRREQ (sendto with no peer) and EMSGSIZE (a datagram
                // above the ABI's 1024-byte ceiling) are bad-call arguments.
                89 | 90 => ErrorKind::InvalidInput,
                // EADDRINUSE / EADDRNOTAVAIL: the bind conflict the socket
                // layer used to report as Uncategorized.
                98 => ErrorKind::AddrInUse,
                99 => ErrorKind::AddrNotAvailable,
                // ESRCH, ENOEXEC and ECHILD have no std-shaped class here.
                _ => ErrorKind::Uncategorized,
            },
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
