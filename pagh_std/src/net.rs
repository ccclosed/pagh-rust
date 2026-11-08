//! A connected IPv4 TCP client (kernel 0.12.0+), with `std`-shaped I/O.
//!
//! The ABI has one active connection: `AF_INET` + `SOCK_STREAM`, `connect` to
//! an IPv4 literal, `read`/`write`, `shutdown`. There is no listener, UDP,
//! IPv6, DNS or TLS; `connect` returns a typed error for those cases rather
//! than pretending.
//!
//! [`TcpStream`] is pagh_std's own wrapper around the `libpagh` stream so the
//! SDK traits from [`crate::io`] can be implemented on it:
//!
//! * [`Read`] blocks on `EAGAIN` (yielding the CPU) instead of returning
//!   `WouldBlock`, which is the std-shaped contract;
//! * [`Write`] likewise retries `EAGAIN`, so `write_all` makes progress;
//! * [`BufRead`] adds an internal 8 KiB read-ahead buffer; `read_until`,
//!   `read_line`, `lines` and `split` work directly on a [`TcpStream`].
//!
//! The inherent `connect`, `fd`, `shutdown` and `read_to_end` methods are kept
//! (the last one shadows the `Read` trait method, exactly as before this
//! wrapper existed). `recv` is non-blocking in the ABI; the blocking loop lives
//! in this module and yields with `sched_yield`, the only wait primitive the
//! ABI offers besides `nanosleep`.

use alloc::vec::Vec;

use libpagh::errno::Errno;
use libpagh::sys;

use crate::error::{Error, Result};
use crate::io::{BufRead, Read, ReadBuffer, Write};

pub use libpagh::net::Ipv4;

/// A connected TCP stream (one socket descriptor).
///
/// Dropping the value calls `close`; a close error is ignored, because there is
/// nothing useful to do with it and the kernel releases the connection anyway.
/// [`TcpStream::shutdown`] closes the connection but keeps the descriptor open
/// for a final `read` (which returns `Ok(0)`, end of stream).
pub struct TcpStream {
    inner: libpagh::net::TcpStream,
    read_ahead: ReadBuffer,
}

impl TcpStream {
    /// Open a connection to `host:port`, completing the TCP handshake.
    ///
    /// IPv4 literals only: there is no DNS in this ABI. The kernel's own
    /// deadline bounds the wait; a refusal is `ECONNREFUSED`, no lease or no
    /// route `ENETUNREACH`, a silent peer `ETIMEDOUT`.
    pub fn connect(host: Ipv4, port: u16) -> Result<TcpStream> {
        let inner = libpagh::net::TcpStream::connect(host, port)?;
        Ok(TcpStream {
            inner,
            read_ahead: ReadBuffer::new(),
        })
    }

    /// The underlying socket descriptor.
    pub const fn fd(&self) -> i32 {
        self.inner.fd()
    }

    /// Close the connection (both directions; there is no half-close) while
    /// keeping the descriptor. A later `read` returns `Ok(0)`, a later `write`
    /// is `EPIPE`; dropping the stream releases the descriptor.
    pub fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown()?;
        Ok(())
    }

    /// Read until the peer closes, appending every payload chunk to `out`.
    ///
    /// This is the inherent method `libpagh` exposed before [`TcpStream`] was
    /// wrapped; it drains any `BufRead` read-ahead first, then blocks exactly
    /// like [`Read::read`]. The return type is `pagh_std::io::Result<()>`.
    pub fn read_to_end(&mut self, out: &mut Vec<u8>) -> Result<()> {
        let mut buffer = [0u8; 4096];
        loop {
            let read = <Self as Read>::read(self, &mut buffer)?;
            if read == 0 {
                return Ok(());
            }
            out.try_reserve(read)
                .map_err(|_| Error::from(Errno::ENOMEM))?;
            out.extend_from_slice(&buffer[..read]);
        }
    }

    /// The bytes currently held by the `BufRead` read-ahead buffer.
    pub fn buffered(&self) -> &[u8] {
        self.read_ahead.buffered()
    }
}

impl core::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpStream")
            .field("fd", &self.inner.fd())
            .finish()
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let Self {
            inner, read_ahead, ..
        } = self;
        read_ahead.read(buf, |out| recv_blocking(inner, out))
    }
}

impl BufRead for TcpStream {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        let Self {
            inner, read_ahead, ..
        } = self;
        read_ahead.fill(|out| recv_blocking(inner, out))
    }

    fn consume(&mut self, amt: usize) {
        self.read_ahead.consume(amt);
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        send_blocking(&mut self.inner, buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// `recv`, retrying `EAGAIN` with a yield: the std-shaped blocking read.
fn recv_blocking(inner: &mut libpagh::net::TcpStream, buf: &mut [u8]) -> Result<usize> {
    loop {
        match libpagh::io::Read::read(inner, buf) {
            Ok(read) => return Ok(read),
            Err(Errno::EAGAIN) => {
                let _ = sys::sched_yield();
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// `send`, retrying `EAGAIN` with a yield.
fn send_blocking(inner: &mut libpagh::net::TcpStream, buf: &[u8]) -> Result<usize> {
    loop {
        match libpagh::io::Write::write(inner, buf) {
            Ok(written) => return Ok(written),
            Err(Errno::EAGAIN) => {
                let _ = sys::sched_yield();
            }
            Err(error) => return Err(error.into()),
        }
    }
}
