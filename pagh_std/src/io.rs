//! Byte-oriented I/O: the `Read`/`Write`/`Seek`/`BufRead` traits, buffered
//! adapters, the in-memory conveniences and the three console handles.
//!
//! This is a practical subset of `std::io`, not a reimplementation of it. The
//! traits use the SDK's [`Error`] (which preserves the ABI's [`Errno`]) and
//! operate directly on the frozen syscall table:
//!
//! * [`File`](crate::fs::File) is one unbuffered `read`/`write`/`lseek` per
//!   method call on the normal path; its direct `BufRead` implementation reads
//!   ahead into an 8 KiB buffer only when `fill_buf` is used;
//! * [`BufReader`] and [`BufWriter`] add userland buffering;
//! * [`Cursor`] is an in-memory reader over any `T: AsRef<[u8]>`, with
//!   [`Seek`]; [`Read::chain`] concatenates two readers; [`Tee`] mirrors a
//!   writer into a second sink;
//! * [`stdin`] blocks by retrying `EAGAIN` with `sched_yield`. The kernel's
//!   console `read(0)` is non-blocking; this handle keeps its historical yield
//!   loop (the `poll` wrapper is available separately). The console has **no
//!   EOF**: `cat` with no arguments waits forever.
//!
//! The kernel-independent half of this module lives in `io/pure.rs`, so the
//! host gate can compile and test it; this file owns the syscall-backed
//! handles, `poll` and the `print!`/`eprint!` bridges.
//!
//! `is_terminal` is still absent, and now for a demonstrated reason: the ABI's
//! `fstat` reports the console as `kind = Other` with mode `0o644`, exactly
//! what it reports for a socket, so userland cannot tell a terminal from a
//! socket; and fds 0-2 are not permanently the console either, because the
//! kernel's `dup`/`dup2`/`pipe2` can occupy them. A truthful answer needs a
//! kernel-side signal, not an SDK guess.

use core::fmt;

use libpagh::errno::Errno;
use libpagh::sys;

mod pure;

pub(crate) use self::pure::ReadBuffer;
pub use self::pure::{
    copy, empty, read_to_end, read_to_string, repeat, sink, BufRead, BufReader, BufWriter, Bytes,
    Chain, Cursor, Empty, Lines, Read, Repeat, Seek, Sink, Split, Take, Tee, Write,
    DEFAULT_BUFFER_SIZE,
};

pub use crate::error::{Error, ErrorKind, Result};
pub use libpagh::io::SeekFrom;

// ---------------------------------------------------------------------------
// Console handles
// ---------------------------------------------------------------------------

/// Console input, fd 0.
///
/// `read` blocks by retrying `EAGAIN` with `sched_yield`; see the module docs
/// for the absence of EOF.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stdin;

/// Console output, fd 1.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stdout;

/// Console diagnostics, fd 2.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stderr;

impl Stdin {
    /// A reader for fd 0.
    pub const fn new() -> Stdin {
        Stdin
    }
}

impl Stdout {
    /// A writer for fd 1.
    pub const fn new() -> Stdout {
        Stdout
    }
}

impl Stderr {
    /// A writer for fd 2.
    pub const fn new() -> Stderr {
        Stderr
    }
}

impl Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match sys::read(0, buf) {
                Ok(n) => return Ok(n),
                Err(Errno::EAGAIN) => {
                    // Keep the console reader's historical yield loop; the
                    // `poll` wrapper is available for callers that want it.
                    let _ = sys::sched_yield();
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        write_fd(1, buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        write_fd(2, buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// The process's standard input handle.
pub fn stdin() -> Stdin {
    Stdin
}

/// The process's standard output handle.
pub fn stdout() -> Stdout {
    Stdout
}

/// The process's standard error handle.
pub fn stderr() -> Stderr {
    Stderr
}

fn write_fd(fd: i32, buf: &[u8]) -> Result<usize> {
    loop {
        match sys::write(fd, buf) {
            Ok(n) => return Ok(n),
            Err(Errno::EAGAIN) => {
                let _ = sys::sched_yield();
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn write_all_fd(fd: i32, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        match write_fd(fd, buf) {
            Ok(0) => {
                return Err(Error::new(
                    ErrorKind::WriteZero,
                    "console write made no progress",
                ))
            }
            Ok(n) if n <= buf.len() => buf = &buf[n..],
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "console write claimed more bytes than given",
                ))
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

struct FdWriter(i32);

impl fmt::Write for FdWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_all_fd(self.0, s.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// Backing function for `print!`; not part of the stable surface.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    let mut writer = FdWriter(1);
    let _ = fmt::write(&mut writer, args);
}

/// Backing function for `eprint!`; not part of the stable surface.
#[doc(hidden)]
pub fn _eprint(args: fmt::Arguments<'_>) {
    let mut writer = FdWriter(2);
    let _ = fmt::write(&mut writer, args);
}

/// A `poll(2)` descriptor from the native ABI.
pub use libpagh::abi::PollFd;

/// Poll descriptors for readiness.
///
/// `timeout` is a blocking timeout; `None` waits forever. Returns the number of
/// ready descriptors (0 on timeout). The kernel's poll is non-blocking per
/// descriptor and yields in the syscall for the timeout.
pub fn poll(fds: &mut [PollFd], timeout: Option<crate::time::Duration>) -> Result<usize> {
    let millis = match timeout {
        Some(d) => {
            let ms = d.as_millis();
            if ms > i32::MAX as u128 {
                i32::MAX
            } else {
                ms as i32
            }
        }
        None => -1,
    };
    libpagh::sys::poll(fds, millis).map_err(|e| Error::from(e))
}
