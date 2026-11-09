//! IPv4 sockets: a TCP client, a TCP listener and UDP datagrams.
//!
//! The pagh ABI has no DNS, no IPv6 and no TLS in this layer: an address is an
//! [`Ipv4`] literal, or a [`SocketAddr`] built from one. Ports are `u16`.
//!
//! The three socket types are `pagh_std`'s own wrappers over `libpagh`'s
//! syscall layer (`libpagh::sys::{socket, bind, listen, accept, connect,
//! sendto, recvfrom, shutdown, close}`), for two reasons the SDK can state
//! plainly:
//!
//! * the ABI has **no `getsockname`**, so the address a socket was bound to is
//!   only knowable if the caller remembers the argument — the wrappers keep it
//!   and expose [`TcpListener::local_addr`] / [`UdpSocket::local_addr`];
//! * the ABI's `recv` is non-blocking while `std`'s is blocking, and a
//!   listener is either created `SOCK_NONBLOCK` or not created at all. Owning
//!   the descriptor lets one type present both the blocking and the
//!   `WouldBlock` shape without a second constructor.
//!
//! # Blocking contract
//!
//! [`TcpStream::read`](Read::read), [`TcpStream::write`](Write::write),
//! [`TcpListener::accept`] and a blocking [`UdpSocket::recv_from`] **wait**
//! rather than returning `WouldBlock`: they retry the ABI's non-blocking call
//! and yield the CPU between attempts. Every retry enters a network syscall,
//! and the kernel polls its NIC inside those calls, so the loop makes progress
//! without any other task having to poll on its behalf (the shell is parked in
//! `wait_for_process` while a program runs).
//!
//! The `*_nonblocking` / `try_*` methods and `set_nonblocking(true)` are the
//! single-poll shapes: they return [`ErrorKind::WouldBlock`] when there is
//! nothing to report.
//!
//! # What the ABI cannot do
//!
//! No DNS, no IPv6, no `getsockname`/`getpeername` (the peer address is
//! remembered from `connect`/`accept` instead), no `fcntl`, so a
//! [`TcpStream`] has no `set_nonblocking`, no `TcpStream::try_clone`, no
//! socket options, no `SO_REUSEADDR`, no half-close, and no way to learn an
//! ephemeral port chosen by `bind(0)`. The kernel's own limits apply: one
//! active-open TCP client at a time, one listener with a four-entry accept
//! queue, eight TCP connections, eight bound UDP ports, a 1024-byte UDP
//! datagram ceiling, and sixteen file descriptors per process.

use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;
use core::sync::atomic::{AtomicBool, Ordering};

use libpagh::abi::SockAddrIn;
use libpagh::errno::Errno;
use libpagh::sys;

use crate::error::{Error, ErrorKind, Result};
use crate::io::{BufRead, Read, ReadBuffer, Write};

pub use libpagh::net::Ipv4;

// ─── SocketAddr ─────────────────────────────────────────────────────────────

/// An IPv4 socket address: an [`Ipv4`] and a port.
///
/// `std::net::SocketAddr` is an enum because it also carries IPv6; this ABI has
/// only `AF_INET`, so the SDK's address is a struct and [`SocketAddr::is_ipv4`]
/// is always true. [`SocketAddr::parse`] accepts the `a.b.c.d:port` form only
/// (no host names, no `[::1]:80`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SocketAddr {
    ip: Ipv4,
    port: u16,
}

impl SocketAddr {
    /// Build an address from an IPv4 literal and a port.
    pub const fn new(ip: Ipv4, port: u16) -> SocketAddr {
        SocketAddr { ip, port }
    }

    /// The IPv4 address.
    pub const fn ip(self) -> Ipv4 {
        self.ip
    }

    /// The port, in host byte order.
    pub const fn port(self) -> u16 {
        self.port
    }

    /// Replace the address.
    pub fn set_ip(&mut self, ip: Ipv4) {
        self.ip = ip;
    }

    /// Replace the port.
    pub fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    /// Always true: the ABI has no IPv6.
    pub const fn is_ipv4(&self) -> bool {
        true
    }

    /// Always false: the ABI has no IPv6.
    pub const fn is_ipv6(&self) -> bool {
        false
    }

    /// Parse `a.b.c.d:port`.
    ///
    /// Returns `None` for anything else: no host names, no shorthand octets,
    /// no bracketed IPv6 and no missing port.
    pub fn parse(text: &str) -> Option<SocketAddr> {
        let (ip, port) = text.rsplit_once(':')?;
        let ip = Ipv4::parse(ip)?;
        let port = port.parse::<u16>().ok()?;
        Some(SocketAddr::new(ip, port))
    }
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

/// The error [`SocketAddr::from_str`] returns for a malformed address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrParseError;

impl fmt::Display for AddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid IPv4 socket address (want a.b.c.d:port)")
    }
}

impl core::error::Error for AddrParseError {}

impl FromStr for SocketAddr {
    type Err = AddrParseError;

    fn from_str(text: &str) -> core::result::Result<SocketAddr, AddrParseError> {
        SocketAddr::parse(text).ok_or(AddrParseError)
    }
}

impl From<(Ipv4, u16)> for SocketAddr {
    fn from((ip, port): (Ipv4, u16)) -> SocketAddr {
        SocketAddr::new(ip, port)
    }
}

impl From<SocketAddr> for (Ipv4, u16) {
    fn from(address: SocketAddr) -> (Ipv4, u16) {
        (address.ip, address.port)
    }
}

/// Convert the ABI's 16-byte structure to an SDK address.
fn socket_addr_of(raw: &SockAddrIn) -> SocketAddr {
    SocketAddr::new(Ipv4::new(raw.address()), raw.port())
}

/// Convert an SDK address to the ABI's 16-byte structure.
fn sockaddr_in_of(address: SocketAddr) -> SockAddrIn {
    SockAddrIn::new(address.ip().octets(), address.port())
}

/// The `EAGAIN` predicate for the retry loops, named once.
fn would_block(errno: Errno) -> bool {
    matches!(errno, Errno::EAGAIN)
}

// ─── TcpStream ──────────────────────────────────────────────────────────────

/// A connected TCP stream (one `AF_INET`/`SOCK_STREAM` descriptor).
///
/// Dropping the value calls `close`; a close error is ignored, because there is
/// nothing useful to do with it and the kernel releases the connection anyway.
/// [`TcpStream::shutdown`] closes the connection but keeps the descriptor open
/// for a final `read` (which returns `Ok(0)`, end of stream).
///
/// [`Read`]/[`Write`] block by retrying the ABI's non-blocking `recv`/`send`
/// with `sched_yield`, which is the std-shaped contract. [`BufRead`] adds an
/// 8 KiB read-ahead buffer allocated on first use.
pub struct TcpStream {
    fd: i32,
    open: bool,
    peer: SocketAddr,
    read_ahead: ReadBuffer,
}

impl TcpStream {
    /// Open a connection to `host:port`, completing the TCP handshake.
    ///
    /// IPv4 literals only: there is no DNS in this ABI. The kernel's own
    /// deadline bounds the wait; a refusal is `ECONNREFUSED`, no lease or no
    /// route `ENETUNREACH`, a silent peer `ETIMEDOUT`. This is the ABI's one
    /// active-open client: a second `connect` while this stream is open is
    /// `ENOSPC` until it is dropped (accepted server connections have their
    /// own descriptors and are not affected).
    pub fn connect(host: Ipv4, port: u16) -> Result<TcpStream> {
        let fd = sys::socket(sys::AF_INET, sys::SOCK_STREAM, 0)?;
        let stream = TcpStream {
            fd,
            open: true,
            peer: SocketAddr::new(host, port),
            read_ahead: ReadBuffer::new(),
        };
        // On error `stream` drops here, which closes the fresh descriptor
        // before the error reaches the caller.
        sys::connect(fd, &sockaddr_in_of(stream.peer))?;
        Ok(stream)
    }

    /// Wrap a descriptor the kernel returned from `accept`.
    ///
    /// The peer address comes from the `accept` call itself: the ABI has no
    /// `getpeername`.
    fn from_accepted(fd: i32, peer: SocketAddr) -> TcpStream {
        TcpStream {
            fd,
            open: true,
            peer,
            read_ahead: ReadBuffer::new(),
        }
    }

    /// The underlying socket descriptor.
    pub const fn fd(&self) -> i32 {
        self.fd
    }

    /// The peer's address, as passed to [`TcpStream::connect`] or returned by
    /// [`TcpListener::accept`].
    ///
    /// This is the SDK's record of the call, not a `getpeername` query: the
    /// ABI has no `getpeername`.
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Close the connection (both directions; there is no half-close) while
    /// keeping the descriptor. A later `read` returns `Ok(0)`, a later `write`
    /// is `EPIPE`; dropping the stream releases the descriptor.
    pub fn shutdown(&mut self) -> Result<()> {
        sys::shutdown(self.fd, sys::SHUT_RDWR)?;
        Ok(())
    }

    /// Read until the peer closes, appending every payload chunk to `out`.
    ///
    /// This is the inherent method `libpagh` exposed before the SDK wrapped the
    /// stream; it drains any `BufRead` read-ahead first, then blocks exactly
    /// like [`Read::read`].
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
            .field("fd", &self.fd)
            .field("peer", &self.peer)
            .finish()
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if self.open {
            let _ = sys::close(self.fd);
            self.open = false;
        }
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let Self { fd, read_ahead, .. } = self;
        let fd = *fd;
        read_ahead.read(buf, |out| recv_blocking(fd, out))
    }
}

impl BufRead for TcpStream {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        let Self { fd, read_ahead, .. } = self;
        let fd = *fd;
        read_ahead.fill(|out| recv_blocking(fd, out))
    }

    fn consume(&mut self, amt: usize) {
        self.read_ahead.consume(amt);
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        send_blocking(self.fd, buf)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

// ─── TcpListener ────────────────────────────────────────────────────────────

/// A listening TCP socket (one `AF_INET`/`SOCK_STREAM` descriptor).
///
/// [`TcpListener::bind`] binds `0.0.0.0:port` and listens with backlog 4;
/// [`TcpListener::bind_to`] takes an explicit address (it must be `0.0.0.0` or
/// the interface's DHCP lease, anything else is `EADDRNOTAVAIL`) and
/// [`TcpListener::bind_with_backlog`] an explicit backlog, which the kernel
/// clamps to `1..=4` because the accept queue is a fixed four-entry array. A
/// connection that completes while the queue is full is reset by the kernel.
///
/// The listener is created `SOCK_NONBLOCK` at the ABI level. [`accept`] is the
/// blocking shape and polls until a connection arrives; [`accept_nonblocking`]
/// is a single poll. Dropping the listener closes it.
///
/// [`accept`]: TcpListener::accept
/// [`accept_nonblocking`]: TcpListener::accept_nonblocking
pub struct TcpListener {
    fd: i32,
    open: bool,
    /// The address the caller asked for, or `None` for an ephemeral port the
    /// ABI cannot report (there is no `getsockname`).
    local: Option<SocketAddr>,
}

impl TcpListener {
    /// Create a stream socket, bind `0.0.0.0:port` and listen with backlog 4.
    ///
    /// Port 0 asks the kernel for an ephemeral port.
    pub fn bind(port: u16) -> Result<TcpListener> {
        TcpListener::create(Ipv4::ANY, port, 4)
    }

    /// Bind `address:port` and listen with backlog 4.
    pub fn bind_to(address: Ipv4, port: u16) -> Result<TcpListener> {
        TcpListener::create(address, port, 4)
    }

    /// Bind `address:port` and listen with an explicit backlog.
    ///
    /// The kernel clamps `backlog` to `1..=4`; the ABI has one listener and a
    /// fixed four-entry accept queue.
    pub fn bind_with_backlog(address: Ipv4, port: u16, backlog: u16) -> Result<TcpListener> {
        TcpListener::create(address, port, backlog)
    }

    fn create(address: Ipv4, port: u16, backlog: u16) -> Result<TcpListener> {
        let kind = sys::SOCK_STREAM | sys::SOCK_NONBLOCK;
        let fd = sys::socket(sys::AF_INET, kind, 0)?;
        let listener = TcpListener {
            fd,
            open: true,
            // Only an explicit port is reportable: the kernel can assign an
            // ephemeral one for port 0 and no sockcall returns it.
            local: if port == 0 {
                None
            } else {
                Some(SocketAddr::new(address, port))
            },
        };
        // On error `listener` drops here and closes the fresh descriptor.
        sys::bind(fd, &sockaddr_in_of(SocketAddr::new(address, port)))?;
        sys::listen(fd, i32::from(backlog))?;
        Ok(listener)
    }

    /// The underlying socket descriptor.
    pub const fn fd(&self) -> i32 {
        self.fd
    }

    /// The address this listener was bound to.
    ///
    /// The ABI has no `getsockname`, so this reports the address passed to
    /// [`bind`](TcpListener::bind)/[`bind_to`](TcpListener::bind_to)/
    /// [`bind_with_backlog`](TcpListener::bind_with_backlog). For an ephemeral
    /// bind (`port == 0`) there is nothing to report and the call returns a
    /// typed [`ErrorKind::Unsupported`] error rather than a made-up port.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.local.ok_or_else(|| {
            Error::unsupported(
                "TcpListener::local_addr: binds port 0 and the ABI has no getsockname",
            )
        })
    }

    /// Wait for one connection, returning its stream and peer address.
    ///
    /// This is the std-shaped blocking accept: it retries the ABI's
    /// non-blocking `accept` and yields the CPU between attempts, so it waits
    /// until a connection arrives (or forever, if none does). Each attempt
    /// polls the kernel's NIC.
    pub fn accept(&mut self) -> Result<(TcpStream, SocketAddr)> {
        loop {
            match self.try_accept() {
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    let _ = sys::sched_yield();
                }
                other => return other,
            }
        }
    }

    /// A single-poll accept: [`ErrorKind::WouldBlock`] when the accept queue is
    /// empty.
    ///
    /// The call still polls the NIC once, so a connection that is already
    /// pending is accepted immediately.
    pub fn accept_nonblocking(&mut self) -> Result<(TcpStream, SocketAddr)> {
        self.try_accept()
    }

    fn try_accept(&mut self) -> Result<(TcpStream, SocketAddr)> {
        match sys::accept(self.fd) {
            Ok((fd, peer)) => {
                let peer = socket_addr_of(&peer);
                Ok((TcpStream::from_accepted(fd, peer), peer))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// An iterator over incoming connections, std-shaped.
    ///
    /// Each item is the result of [`TcpListener::accept`], so the iterator
    /// blocks until a connection arrives and never ends on its own.
    pub fn incoming(&mut self) -> Incoming<'_> {
        Incoming { listener: self }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        if self.open {
            let _ = sys::close(self.fd);
            self.open = false;
        }
    }
}

impl core::fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpListener")
            .field("fd", &self.fd)
            .field("local", &self.local)
            .finish()
    }
}

/// Iterator returned by [`TcpListener::incoming`].
pub struct Incoming<'a> {
    listener: &'a mut TcpListener,
}

impl Iterator for Incoming<'_> {
    type Item = Result<(TcpStream, SocketAddr)>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.listener.accept())
    }
}

// ─── UdpSocket ──────────────────────────────────────────────────────────────

/// A bound UDP socket (one `AF_INET`/`SOCK_DGRAM` descriptor).
///
/// [`UdpSocket::bind`] binds `0.0.0.0:port`; the port may be 0 for an ephemeral
/// choice, but the ABI cannot report which one (no `getsockname`), so
/// [`UdpSocket::local_addr`] then fails with a typed `Unsupported` error.
/// [`UdpSocket::send_to`] names the destination on every datagram and
/// [`UdpSocket::recv_from`] returns the source address; a datagram larger than
/// the caller's buffer is truncated by the kernel, and a payload above the
/// kernel's 1024-byte ceiling is an error before anything is sent.
///
/// `set_nonblocking` is SDK-side state rather than a descriptor flag, because
/// the ABI has no `fcntl`. It switches [`recv_from`](UdpSocket::recv_from)
/// between the blocking retry loop and a single `MSG_DONTWAIT` poll; it does
/// **not** change `send_to`, which has no non-blocking shape in the ABI (UDP
/// sends can block only while ARP resolves the next hop). Use
/// [`UdpSocket::try_recv_from`] for a single poll without changing the mode.
pub struct UdpSocket {
    fd: i32,
    open: bool,
    nonblocking: AtomicBool,
    local: Option<SocketAddr>,
}

impl UdpSocket {
    /// Create a UDP socket and bind `0.0.0.0:port`.
    ///
    /// Port 0 asks the kernel for an ephemeral port; use an explicit port when
    /// the peer must reply to a known number.
    pub fn bind(port: u16) -> Result<UdpSocket> {
        UdpSocket::bind_to(Ipv4::ANY, port)
    }

    /// Create a UDP socket and bind `address:port`.
    ///
    /// `address` must be `0.0.0.0` or the interface's DHCP lease; anything else
    /// is `EADDRNOTAVAIL`. A port owned by another socket is `EADDRINUSE` (the
    /// kernel's answer; `libpagh`'s frozen errno table has no `EADDRINUSE`
    /// entry, so it arrives as the SDK's `Uncategorized` kind).
    pub fn bind_to(address: Ipv4, port: u16) -> Result<UdpSocket> {
        let fd = sys::socket(sys::AF_INET, sys::SOCK_DGRAM, 0)?;
        let socket = UdpSocket {
            fd,
            open: true,
            nonblocking: AtomicBool::new(false),
            local: if port == 0 {
                None
            } else {
                Some(SocketAddr::new(address, port))
            },
        };
        // On error `socket` drops here, closing the fresh descriptor before the
        // error reaches the caller.
        sys::bind(fd, &sockaddr_in_of(SocketAddr::new(address, port)))?;
        Ok(socket)
    }

    /// The underlying descriptor.
    pub const fn fd(&self) -> i32 {
        self.fd
    }

    /// The address this socket was bound to.
    ///
    /// As with [`TcpListener::local_addr`], this is the SDK's record of the
    /// bind argument: the ABI has no `getsockname`, and an ephemeral bind
    /// (`port == 0`) returns a typed `Unsupported` error.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.local.ok_or_else(|| {
            Error::unsupported("UdpSocket::local_addr: bound port 0 and the ABI has no getsockname")
        })
    }

    /// Whether [`UdpSocket::recv_from`] is in the non-blocking mode.
    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Relaxed)
    }

    /// Switch [`UdpSocket::recv_from`] between blocking and single-poll.
    ///
    /// Always `Ok(())`: the mode is SDK state, so there is no syscall to fail.
    /// The std signature (`&self`) is kept on purpose.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
        Ok(())
    }

    /// Send `buf` as one datagram to `address`.
    ///
    /// Returns the payload length on success. A payload above the kernel's
    /// 1024-byte limit fails before anything is sent (the kernel answers
    /// `EMSGSIZE`; `libpagh`'s frozen errno table has no entry for it, so the
    /// error arrives as the SDK's `Uncategorized` kind).
    pub fn send_to(&self, buf: &[u8], address: SocketAddr) -> Result<usize> {
        let sent = sys::sendto(self.fd, buf, &sockaddr_in_of(address))?;
        Ok(sent)
    }

    /// Wait for one datagram, returning `(bytes, source address)`.
    ///
    /// In the default blocking mode this retries the ABI's bounded receive
    /// (`recvfrom`, which polls the NIC for about 10 s per attempt) until a
    /// datagram arrives. After [`set_nonblocking(true)`](UdpSocket::set_nonblocking)
    /// it is a single `MSG_DONTWAIT` poll and an empty queue is
    /// [`ErrorKind::WouldBlock`]. A datagram larger than `buf` is truncated.
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        if self.is_nonblocking() {
            return self.try_recv_from(buf);
        }
        loop {
            match sys::recvfrom(self.fd, buf, 0) {
                Ok((read, source)) => return Ok((read, socket_addr_of(&source))),
                Err(Errno::EAGAIN) => {
                    let _ = sys::sched_yield();
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// A single-poll receive, regardless of the socket's mode:
    /// [`ErrorKind::WouldBlock`] when nothing is queued right now.
    pub fn try_recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        match sys::recvfrom(self.fd, buf, sys::MSG_DONTWAIT) {
            Ok((read, source)) => Ok((read, socket_addr_of(&source))),
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        if self.open {
            let _ = sys::close(self.fd);
            self.open = false;
        }
    }
}

impl core::fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdpSocket")
            .field("fd", &self.fd)
            .field("local", &self.local)
            .field("nonblocking", &self.is_nonblocking())
            .finish()
    }
}

// ─── blocking helpers ───────────────────────────────────────────────────────

/// `recv`, retrying `EAGAIN` with a yield: the std-shaped blocking read.
fn recv_blocking(fd: i32, buf: &mut [u8]) -> Result<usize> {
    loop {
        match sys::recv(fd, buf) {
            Ok(read) => return Ok(read),
            Err(error) if would_block(error) => {
                let _ = sys::sched_yield();
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// `send`, retrying `EAGAIN` with a yield.
fn send_blocking(fd: i32, buf: &[u8]) -> Result<usize> {
    loop {
        match sys::send(fd, buf) {
            Ok(written) => return Ok(written),
            Err(error) if would_block(error) => {
                let _ = sys::sched_yield();
            }
            Err(error) => return Err(error.into()),
        }
    }
}
