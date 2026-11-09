//! IPv4 sockets: a TCP client, a TCP listener, UDP datagrams and a stub DNS
//! resolver.
//!
//! An address is an [`Ipv4`] literal or a [`SocketAddr`] built from one; a name
//! is resolved by [`dns`] (RFC 1035 over a [`UdpSocket`]), which is the SDK's own
//! layer because the ABI has no resolver call — see [`dns`] for where the server
//! address comes from and [`TcpStream::connect_host`] / [`connect`] for the
//! `host:port` entry points. IPv6 does not exist in this ABI.
//!
//! The socket types are `pagh_std`'s own wrappers over `libpagh`'s syscall
//! layer (`libpagh::sys::{socket, bind, listen, accept, connect, sendto,
//! recvfrom, shutdown, close}` plus the two options calls `libpagh` does not
//! wrap yet), for three reasons the SDK can state plainly:
//!
//! * the ABI has **no `getsockname`**, so the address a socket was bound to is
//!   only knowable if the caller remembers the argument — the wrappers keep it
//!   and expose [`TcpListener::local_addr`] / [`UdpSocket::local_addr`];
//! * the ABI's `recv` is non-blocking while `std`'s is blocking, and a
//!   listener is either created `SOCK_NONBLOCK` or not created at all. Owning
//!   the descriptor lets one type present both the blocking and the
//!   `WouldBlock` shape without a second constructor;
//! * `SO_RCVTIMEO`/`SO_SNDTIMEO` are accepted and ignored by the kernel, so a
//!   timeout that a program can actually observe has to be enforced here
//!   ([`TcpStream::set_read_timeout`], [`UdpSocket::set_read_timeout`]).
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
//! nothing to report. A read deadline makes the wait end in
//! [`ErrorKind::WouldBlock`] too, exactly as `std` documents for
//! `set_read_timeout`.
//!
//! # What the ABI cannot do
//!
//! No IPv6, no `getsockname`/`getpeername` (the peer address is remembered from
//! `connect`/`accept` instead), no `fcntl`, no half-close, and no way to learn
//! an ephemeral port chosen by `bind(0)`. `setsockopt` exists but is a
//! validated no-op, so [`TcpStream::set_reuseaddr`] reports the ABI's answer
//! without promising address reuse. `dup` refuses sockets, so
//! [`TcpStream::try_clone`] shares one descriptor instead of duplicating it.
//! The kernel's own limits apply: one active-open TCP client at a time, one
//! listener with a four-entry accept queue, eight TCP connections, eight bound
//! UDP ports, a 1024-byte UDP datagram ceiling, and sixteen file descriptors
//! per process.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::fmt;
use core::str::FromStr;
use core::sync::atomic::{AtomicBool, Ordering};

use libpagh::abi::{PollFd, SockAddrIn};
use libpagh::errno::Errno;
use libpagh::sys;

use crate::error::{Error, ErrorKind, Result};
use crate::io::{BufRead, Read, ReadBuffer, Write};
use crate::time::{Duration, Instant};

pub mod dns;
pub mod dns_wire;

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

/// The descriptor a [`TcpStream`] shares with its clones.
///
/// WHY AN `Arc` AND NOT `dup`: the ABI's `dup(23)` refuses sockets. A second
/// descriptor for one connection would be a second owner without a reference
/// count, so the kernel maps it to `Unsupported` (`FdEntry::Unsupported` in
/// `src/user/syscall.rs`, "A dup/fork of a socket would be a second owner of one
/// connection or binding"). [`TcpStream::try_clone`] therefore shares this
/// handle instead: both values read and write the same socket, and the
/// descriptor is closed when the last handle drops.
struct StreamHandle {
    fd: i32,
}

impl StreamHandle {
    /// Hand the descriptor to a new owner: `fd` becomes [`RELEASED`], so
    /// `Drop` no longer closes it.
    ///
    /// Only sound when this is the last handle — see [`TcpStream::into_fd`].
    fn release(&mut self) -> i32 {
        let fd = self.fd;
        self.fd = RELEASED;
        fd
    }
}

/// The `fd` value of a [`StreamHandle`] whose descriptor now belongs to someone
/// else. Not a valid descriptor, so `close` can never be called on it.
const RELEASED: i32 = -1;

impl Drop for StreamHandle {
    fn drop(&mut self) {
        if self.fd != RELEASED {
            let _ = sys::close(self.fd);
        }
    }
}

/// The SDK's per-handle stream policy.
///
/// The ABI has no `fcntl`, so it cannot flip a descriptor to non-blocking after
/// creation, and its `SO_RCVTIMEO`/`SO_SNDTIMEO` are *validated and ignored*
/// (the kernel's `setsockopt` comment: "This kernel has nothing to tune"). The
/// timeout and non-blocking behaviour therefore lives here and is enforced
/// around the ABI's `EAGAIN` contract, which is real: stream `recv` is
/// non-blocking by contract and answers `-EAGAIN` when nothing is queued.
#[derive(Clone, Copy, Default)]
struct StreamPolicy {
    nonblocking: bool,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

/// A connected TCP stream (one `AF_INET`/`SOCK_STREAM` descriptor).
///
/// Dropping the value closes the descriptor — unless a [`try_clone`] handle is
/// still alive, in which case the connection stays open until the last handle
/// drops. [`TcpStream::shutdown`] closes the connection but keeps the descriptor
/// open for a final `read` (which returns `Ok(0)`, end of stream).
///
/// [`Read`]/[`Write`] block by retrying the ABI's non-blocking `recv`/`send`
/// with `sched_yield`, which is the std-shaped contract. [`BufRead`] adds an
/// 8 KiB read-ahead buffer allocated on first use; the read-ahead is per handle
/// and is *not* shared with a [`try_clone`], so bytes buffered before the clone
/// stay with the original handle.
///
/// [`try_clone`]: TcpStream::try_clone
pub struct TcpStream {
    handle: Arc<StreamHandle>,
    peer: SocketAddr,
    read_ahead: ReadBuffer,
    policy: Cell<StreamPolicy>,
}

impl TcpStream {
    /// Open a connection to `host:port`, completing the TCP handshake.
    ///
    /// IPv4 literals only — use [`TcpStream::connect_host`] or
    /// [`crate::net::connect`] for a name. The kernel's own deadline bounds the
    /// wait; a refusal is `ECONNREFUSED`, no lease or no route `ENETUNREACH`, a
    /// silent peer `ETIMEDOUT`. This is the ABI's one active-open client: a
    /// second `connect` while this stream is open is `ENOSPC` until it is
    /// dropped (accepted server connections have their own descriptors and are
    /// not affected).
    pub fn connect(host: Ipv4, port: u16) -> Result<TcpStream> {
        let fd = sys::socket(sys::AF_INET, sys::SOCK_STREAM, 0)?;
        let stream = TcpStream {
            handle: Arc::new(StreamHandle { fd }),
            peer: SocketAddr::new(host, port),
            read_ahead: ReadBuffer::new(),
            policy: Cell::new(StreamPolicy::default()),
        };
        // On error `stream` drops here, which closes the fresh descriptor
        // before the error reaches the caller.
        sys::connect(fd, &sockaddr_in_of(stream.peer))?;
        Ok(stream)
    }

    /// Open a connection to `host:port`, resolving `host` first.
    ///
    /// A dotted-quad IPv4 literal is used directly (no query is sent). Anything
    /// else goes through [`dns::resolve`], which is the ABI's own DNS gap: the
    /// SDK speaks RFC 1035 over a [`UdpSocket`] because the kernel exposes no
    /// resolver syscall and no way to read the DHCP lease (see [`dns`]).
    pub fn connect_host(host: &str, port: u16) -> Result<TcpStream> {
        let address = match Ipv4::parse(host) {
            Some(literal) => literal,
            None => dns::resolve(host)?,
        };
        TcpStream::connect(address, port)
    }

    /// Wrap a descriptor the kernel returned from `accept`.
    ///
    /// The peer address comes from the `accept` call itself: the ABI has no
    /// `getpeername`.
    fn from_accepted(fd: i32, peer: SocketAddr) -> TcpStream {
        TcpStream {
            handle: Arc::new(StreamHandle { fd }),
            peer,
            read_ahead: ReadBuffer::new(),
            policy: Cell::new(StreamPolicy::default()),
        }
    }

    /// The underlying socket descriptor.
    pub fn fd(&self) -> i32 {
        self.handle.fd
    }

    /// Take the descriptor out of this stream, leaving nothing to close.
    ///
    /// The TLS session syscalls take ownership of a connected socket's
    /// descriptor (`tls_connect`, syscall 1100), so handing ours over has to
    /// disarm this value's `Drop`: a `TcpStream` that both gave its descriptor
    /// away and closed it later would close the TLS session out from under its
    /// owner, and the number could have been reused by then.
    ///
    /// Refused, with the stream intact, when a [`try_clone`] handle still
    /// shares the descriptor (`Unsupported`: two owners cannot both hand it
    /// over) or when the `BufRead` read-ahead holds bytes (`InvalidInput`:
    /// those bytes are the caller's, and losing them between the TCP
    /// connection and the TLS handshake would corrupt the stream). Drain or
    /// drop the stream normally in either case.
    ///
    /// [`try_clone`]: TcpStream::try_clone
    pub fn into_fd(mut self) -> Result<i32> {
        if Arc::strong_count(&self.handle) != 1 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "TcpStream::into_fd: a try_clone handle still shares the descriptor",
            ));
        }
        if !self.read_ahead.buffered().is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "TcpStream::into_fd: the BufRead read-ahead holds bytes; drain them first",
            ));
        }
        let handle = Arc::get_mut(&mut self.handle).ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "TcpStream::into_fd: the descriptor is shared",
            )
        })?;
        Ok(handle.release())
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
        sys::shutdown(self.handle.fd, sys::SHUT_RDWR)?;
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

    /// Switch the SDK's read/write policy between blocking and single-shot.
    ///
    /// This is SDK state, not a descriptor flag: the ABI has no `fcntl` and the
    /// non-blocking bit is fixed by `socket()` (a stream `recv` is
    /// non-blocking by contract and answers `-EAGAIN` when nothing is queued, so
    /// the mode is which of the two answers the SDK turns that into). In
    /// non-blocking mode a read or write with nothing to do returns
    /// [`ErrorKind::WouldBlock`] immediately instead of yielding and retrying.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let mut policy = self.policy.get();
        policy.nonblocking = nonblocking;
        self.policy.set(policy);
        Ok(())
    }

    /// Whether reads and writes are in the non-blocking mode.
    pub fn is_nonblocking(&self) -> bool {
        self.policy.get().nonblocking
    }

    /// Bound a read with a deadline, or clear it with `None`.
    ///
    /// Two things happen, and they are different claims:
    ///
    /// * the ABI's `setsockopt(SO_RCVTIMEO)` is issued and its answer is
    ///   returned — a kernel that does not know the option is a typed
    ///   [`ErrorKind::Unsupported`] rather than a silent success;
    /// * the SDK enforces the deadline itself in the read path. It has to: the
    ///   kernel's `setsockopt` validates the buffer and **ignores the value**
    ///   ("the two timeouts read back as zero (the kernel's bounds are fixed)"),
    ///   so the deadline is the only thing that can make a read return early.
    ///
    /// On timeout the read fails with [`ErrorKind::WouldBlock`], matching
    /// `std::net::TcpStream`'s documented behaviour for `set_read_timeout`.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        set_socket_timeout(self.handle.fd, SO_RCVTIMEO, timeout)?;
        let mut policy = self.policy.get();
        policy.read_timeout = timeout;
        self.policy.set(policy);
        Ok(())
    }

    /// The read deadline the SDK will enforce, if any.
    pub fn read_timeout(&self) -> Option<Duration> {
        self.policy.get().read_timeout
    }

    /// Bound a write with a deadline, or clear it with `None`.
    ///
    /// The same split as [`set_read_timeout`](TcpStream::set_read_timeout):
    /// `SO_SNDTIMEO` is issued to the kernel, the deadline is enforced by the
    /// SDK, and a timeout is [`ErrorKind::WouldBlock`].
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        set_socket_timeout(self.handle.fd, SO_SNDTIMEO, timeout)?;
        let mut policy = self.policy.get();
        policy.write_timeout = timeout;
        self.policy.set(policy);
        Ok(())
    }

    /// The write deadline the SDK will enforce, if any.
    pub fn write_timeout(&self) -> Option<Duration> {
        self.policy.get().write_timeout
    }

    /// Issue `setsockopt(SO_REUSEADDR)` on this socket.
    ///
    /// The call is real and its answer is the kernel's, but the *behaviour* is
    /// not: this kernel validates `SO_REUSEADDR` and ignores it ("the options a
    /// BSD client commonly sets … are validated and ignored"), because ports are
    /// reserved at `bind` and no `TIME_WAIT` reuse policy exists. On a kernel
    /// that answered `-ENOPROTOOPT` this returns
    /// [`ErrorKind::Unsupported`]; here it returns `Ok(())` and a second `bind`
    /// of the same port still fails. The live transcript asserts both facts.
    pub fn set_reuseaddr(&self, reuse: bool) -> Result<()> {
        set_reuseaddr(self.handle.fd, reuse)
    }

    /// What the kernel reports for `getsockopt(SO_TYPE)`.
    ///
    /// A real round trip through the options ABI, and the one option whose
    /// answer is not a no-op: it is how the live transcript shows the option
    /// path works at all (`Stream` for this type, `Datagram` for a
    /// [`UdpSocket`]).
    pub fn socket_type(&self) -> Result<SocketType> {
        socket_type_of(self.handle.fd)
    }

    /// Share this socket with a second handle.
    ///
    /// **Not** `std`'s `try_clone`: std `dup`s the descriptor, while this ABI
    /// refuses to duplicate a socket, so the two handles share one descriptor
    /// and the connection closes when the last one drops. Reads and writes
    /// interleave on the same socket exactly as they would with a real `dup`;
    /// the difference is that dropping one handle does not close the descriptor
    /// out from under the other. The read-ahead buffer and the timeout /
    /// non-blocking policy are per handle, and bytes already buffered in the
    /// original's read-ahead are not visible to the clone.
    pub fn try_clone(&self) -> Result<TcpStream> {
        Ok(TcpStream {
            handle: Arc::clone(&self.handle),
            peer: self.peer,
            read_ahead: ReadBuffer::new(),
            policy: Cell::new(self.policy.get()),
        })
    }
}

impl core::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpStream")
            .field("fd", &self.handle.fd)
            .field("peer", &self.peer)
            .field("nonblocking", &self.is_nonblocking())
            .finish()
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let Self {
            handle,
            read_ahead,
            policy,
            ..
        } = self;
        let fd = handle.fd;
        let policy = policy.get();
        read_ahead.read(buf, |out| recv_with(fd, out, policy))
    }
}

impl BufRead for TcpStream {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        let Self {
            handle,
            read_ahead,
            policy,
            ..
        } = self;
        let fd = handle.fd;
        let policy = policy.get();
        read_ahead.fill(|out| recv_with(fd, out, policy))
    }

    fn consume(&mut self, amt: usize) {
        self.read_ahead.consume(amt);
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        send_with(self.handle.fd, buf, self.policy.get())
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

    /// Issue `setsockopt(SO_REUSEADDR)` on the listening socket.
    ///
    /// A real ABI call with a real answer, and an honest one: this kernel
    /// validates `SO_REUSEADDR` and ignores it (ports are reserved at `bind`,
    /// and there is no `TIME_WAIT` reuse policy), so `Ok(())` means "the ABI
    /// accepted the option", not "the port is now reusable". The live
    /// transcript shows both halves — the accepted option and the second bind
    /// that still fails. A kernel without the option is
    /// [`ErrorKind::Unsupported`].
    pub fn set_reuseaddr(&self, reuse: bool) -> Result<()> {
        set_reuseaddr(self.fd, reuse)
    }

    /// What the kernel reports for `getsockopt(SO_TYPE)`.
    pub fn socket_type(&self) -> Result<SocketType> {
        socket_type_of(self.fd)
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
    read_timeout: Cell<Option<Duration>>,
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
            read_timeout: Cell::new(None),
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
        if let Some(timeout) = self.read_timeout() {
            return self.recv_until(buf, timeout);
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

    /// A receive bounded by the SDK deadline.
    ///
    /// It cannot use the ABI's blocking `recvfrom`: that call waits roughly ten
    /// seconds per attempt and cannot be cut short, which is useless as a retry
    /// budget. `poll` on the descriptor first, then one `MSG_DONTWAIT` take.
    fn recv_until(&mut self, buf: &mut [u8], timeout: Duration) -> Result<(usize, SocketAddr)> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.try_recv_from(buf) {
                Ok(result) => return Ok(result),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::new(
                    ErrorKind::WouldBlock,
                    "UdpSocket::recv_from timed out",
                ));
            }
            let wait = deadline.saturating_duration_since(now).as_millis();
            let wait = wait.min(i32::MAX as u128).max(1) as i32;
            let mut fds = [PollFd {
                fd: self.fd,
                events: sys::POLLIN,
                revents: 0,
            }];
            sys::poll(&mut fds, wait)?;
        }
    }

    /// Bound [`recv_from`](UdpSocket::recv_from) with a deadline, or clear it.
    ///
    /// Exactly like the stream version: `setsockopt(SO_RCVTIMEO)` is issued to
    /// the ABI (whose answer is returned — the kernel here validates and ignores
    /// the value), and the deadline itself is enforced by [`recv_until`], which
    /// is the part with observable behaviour. A timeout is
    /// [`ErrorKind::WouldBlock`].
    ///
    /// [`recv_until`]: UdpSocket::recv_until
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        set_socket_timeout(self.fd, SO_RCVTIMEO, timeout)?;
        self.read_timeout.set(timeout);
        Ok(())
    }

    /// The receive deadline the SDK will enforce, if any.
    pub fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout.get()
    }

    /// What the kernel reports for `getsockopt(SO_TYPE)` (`Datagram` here).
    pub fn socket_type(&self) -> Result<SocketType> {
        socket_type_of(self.fd)
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
///
/// `policy` decides what "blocking" means: in non-blocking mode the first
/// `EAGAIN` is the answer, with a deadline the retry loop stops at the deadline,
/// and otherwise it yields and retries.
fn recv_with(fd: i32, buf: &mut [u8], policy: StreamPolicy) -> Result<usize> {
    let deadline = policy.read_timeout.map(|limit| Instant::now() + limit);
    loop {
        match sys::recv(fd, buf) {
            Ok(read) => return Ok(read),
            Err(error) if would_block(error) => {
                if policy.nonblocking {
                    return Err(Error::new(
                        ErrorKind::WouldBlock,
                        "TcpStream is in non-blocking mode",
                    ));
                }
                if let Some(deadline) = deadline {
                    if Instant::now() >= deadline {
                        return Err(Error::new(
                            ErrorKind::WouldBlock,
                            "TcpStream::read timed out",
                        ));
                    }
                }
                let _ = sys::sched_yield();
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// `send`, retrying `EAGAIN` with a yield under the same policy as
/// [`recv_with`].
fn send_with(fd: i32, buf: &[u8], policy: StreamPolicy) -> Result<usize> {
    let deadline = policy.write_timeout.map(|limit| Instant::now() + limit);
    loop {
        match sys::send(fd, buf) {
            Ok(written) => return Ok(written),
            Err(error) if would_block(error) => {
                if policy.nonblocking {
                    return Err(Error::new(
                        ErrorKind::WouldBlock,
                        "TcpStream is in non-blocking mode",
                    ));
                }
                if let Some(deadline) = deadline {
                    if Instant::now() >= deadline {
                        return Err(Error::new(
                            ErrorKind::WouldBlock,
                            "TcpStream::write timed out",
                        ));
                    }
                }
                let _ = sys::sched_yield();
            }
            Err(error) => return Err(error.into()),
        }
    }
}

// ─── socket options ─────────────────────────────────────────────────────────
//
// `libpagh` freezes the syscall numbers (`sys::SYS_SETSOCKOPT` = 208,
// `sys::SYS_GETSOCKOPT` = 209) but does not wrap them, so the SDK issues those
// two directly. The convention is `pagh-api/docs/abi.md` §2: number in `a7`,
// arguments in `a0..a5`, a negative return is `-errno`.

/// `SOL_SOCKET` option level.
const SOL_SOCKET: usize = 1;
/// `SO_REUSEADDR`.
const SO_REUSEADDR: usize = 2;
/// `SO_TYPE` (read-only).
const SO_TYPE: usize = 3;
/// `SO_RCVTIMEO`.
const SO_RCVTIMEO: usize = 20;
/// `SO_SNDTIMEO`.
const SO_SNDTIMEO: usize = 21;

/// One ABI syscall, six arguments.
///
/// SAFETY: the kernel validates every user pointer and never trusts the values
/// passed here; the block declares the syscall-clobbered registers and a memory
/// clobber, so the compiler cannot cache user memory across the call. This is
/// the same contract `libpagh::sys` implements — see that crate's `syscall6`.
#[inline]
unsafe fn raw_syscall6(
    nr: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> isize {
    let ret: isize;
    // SAFETY: `ecall` with `a7` = syscall number and `a0..a5` = arguments, per
    // the frozen RISC-V ABI; the memory clobber keeps user memory coherent.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            in("a7") nr,
        );
    }
    ret
}

/// Turn a raw syscall return into the SDK's error.
fn check_raw(ret: isize) -> Result<usize> {
    if ret < 0 {
        Err(Errno::from_raw((-ret) as i32).into())
    } else {
        Ok(ret as usize)
    }
}

/// `setsockopt(fd, SOL_SOCKET, name, value, len)`.
///
/// The option buffer must be non-null even when it is ignored: the kernel
/// validates the pointer and answers `EFAULT` for a null one.
fn setsockopt(fd: i32, name: usize, value: &[u8]) -> Result<()> {
    // SAFETY: `value` is a live slice for the duration of the call.
    let ret = unsafe {
        raw_syscall6(
            sys::SYS_SETSOCKOPT,
            fd as usize,
            SOL_SOCKET,
            name,
            value.as_ptr() as usize,
            value.len(),
            0,
        )
    };
    let _ = check_raw(ret)?;
    Ok(())
}

/// `getsockopt(fd, SOL_SOCKET, name, value, *len)` for a four-byte answer.
///
/// The kernel reads the caller's capacity from `*len` first and writes back how
/// many bytes it produced, so the length really is in/out and lives in a local
/// the kernel can update.
fn getsockopt_u32(fd: i32, name: usize) -> Result<u32> {
    let mut value = [0u8; 4];
    let mut length: u32 = 4;
    // SAFETY: `value` and `length` are live locals the kernel writes through;
    // it validates both ranges before touching them.
    let ret = unsafe {
        raw_syscall6(
            sys::SYS_GETSOCKOPT,
            fd as usize,
            SOL_SOCKET,
            name,
            value.as_mut_ptr() as usize,
            &mut length as *mut u32 as usize,
            0,
        )
    };
    let _ = check_raw(ret)?;
    Ok(u32::from_le_bytes(value))
}

/// What the kernel says a descriptor is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// `SOCK_STREAM`.
    Stream,
    /// `SOCK_DGRAM`.
    Datagram,
}

/// `getsockopt(SOL_SOCKET, SO_TYPE)` on one descriptor.
fn socket_type_of(fd: i32) -> Result<SocketType> {
    match getsockopt_u32(fd, SO_TYPE)? {
        1 => Ok(SocketType::Stream),
        2 => Ok(SocketType::Datagram),
        _other => Err(Error::new(
            ErrorKind::InvalidData,
            "getsockopt(SO_TYPE) returned a type this SDK does not know",
        )),
    }
}

/// The four-byte `int` a BSD `SO_REUSEADDR` takes.
fn set_reuseaddr(fd: i32, reuse: bool) -> Result<()> {
    let value = (reuse as i32).to_le_bytes();
    match setsockopt(fd, SO_REUSEADDR, &value) {
        Ok(()) => Ok(()),
        // "Accepted no-op" and "not implemented" must stay distinguishable: the
        // kernel answers ENOPROTOOPT for an option it does not know, and that is
        // the one answer the SDK reports as typed Unsupported.
        Err(error) if error.raw_os_error() == Some(92) => Err(Error::unsupported(
            "setsockopt(SO_REUSEADDR): this kernel has no such option",
        )),
        Err(error) => Err(error),
    }
}

/// The 16-byte `struct timespec` a BSD timeout option takes.
fn set_socket_timeout(fd: i32, name: usize, timeout: Option<Duration>) -> Result<()> {
    let timeout = timeout.unwrap_or(Duration::ZERO);
    let mut value = [0u8; 16];
    value[..8].copy_from_slice(&(timeout.as_secs() as i64).to_le_bytes());
    value[8..].copy_from_slice(&(timeout.subsec_nanos() as i64).to_le_bytes());
    setsockopt(fd, name, &value)
}

// ─── host:port ──────────────────────────────────────────────────────────────

/// Connect to `host:port`, resolving `host` through [`dns`] first.
///
/// This is the `(host:port)` shape `std::net::TcpStream::connect` accepts: a
/// dotted-quad literal is used as-is, a name goes through the SDK's RFC 1035
/// resolver. The port is mandatory; there is no default-port table.
///
/// ```ignore
/// let stream = pagh_std::net::connect("example.com:443")?;
/// ```
pub fn connect(host_port: &str) -> Result<TcpStream> {
    let (host, port) = split_host_port(host_port)?;
    TcpStream::connect_host(host, port)
}

/// Split `host:port` into its two halves, rejecting everything malformed.
///
/// Also the parser behind [`TlsStream::connect`](crate::tls::TlsStream::connect),
/// which takes the same shape and then hands the TCP stream to the kernel's
/// TLS session syscall.
pub(crate) fn split_host_port(text: &str) -> Result<(&str, u16)> {
    let (host, port) = text.rsplit_once(':').ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "expected host:port (the ABI has no default-port table)",
        )
    })?;
    if host.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "host must not be empty",
        ));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "port must be 1..=65535"))?;
    if port == 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "port must be 1..=65535",
        ));
    }
    Ok((host, port))
}
