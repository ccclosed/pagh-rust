//! A stub DNS resolver (RFC 1035), spoken over [`UdpSocket`].
//!
//! The ABI has **no** resolver syscall and no way for userland to read the DHCP
//! lease: `pagh-riscv`'s `docs/architecture.md` is explicit ("DNS-вызова из
//! userland (только `dns`-команда шелла)") and the syscall table has no
//! `getrandom`-style network-info call either. A userland program that wants to
//! resolve a name therefore has to speak DNS itself, and that is what this
//! module does: one `A` question over a UDP socket, a bounded wait, and a
//! fail-closed parser ([`super::dns_wire`]).
//!
//! ## Where the server address comes from
//!
//! That is the honest gap. In order of precedence:
//!
//! 1. `Resolver::with_servers(&[...])` — the caller names them;
//! 2. [`Resolver::system`] reads `/etc/resolv.conf`, then `/mnt/etc/resolv.conf`
//!    (the ABI mounts the guest's ext2 image at `/mnt`), taking every
//!    `nameserver <dotted-quad>` line. This is the BSD convention, and it is
//!    how the live acceptance run gets the *DHCP-leased* server: the harness
//!    reads `dns 10.0.2.3` out of the kernel's own `net` command and writes that
//!    value into the staged image, so the address the SDK queries is the one
//!    DHCP handed the machine;
//! 3. the compiled-in [`DEFAULT_SERVER`] (`10.0.2.3`), which is QEMU's
//!    user-network DNS proxy and the DHCP option 6 value on the `--net` network
//!    the kernel's tests run on. This is a documented default for a
//!    configuration-file-less program, **not** a discovered lease.
//!
//! ## Limits (all fail closed)
//!
//! * no IPv6 (`AAAA` is skipped, never returned), no `MX`/`TXT`/`SRV`;
//! * no TCP fallback: a truncated (`TC=1`) answer is [`Error::Truncated`];
//! * no caching beyond the process's own calls, and no `search`/`ndots`
//!   processing: a relative name is sent as-is;
//! * the transaction id comes from a counter seeded with the monotonic clock,
//!   so it varies between queries but is **not** unpredictable — the ABI has no
//!   entropy source, and a resolver that claimed spoofing resistance here would
//!   be lying. The parser's question-echo check is what rejects off-path
//!   datagrams that guess the id.

use alloc::vec::Vec;

use crate::error::{Error as SdkError, ErrorKind, Result};
use crate::fs;
use crate::net::{Ipv4, SocketAddr, UdpSocket};
use crate::time::{Duration, Instant};

use super::dns_wire::{self, Response, WireError};

/// The DNS server name/port every query goes to.
pub const DNS_PORT: u16 = 53;

/// The compiled-in fallback server: QEMU's user-network DNS proxy, which is
/// what the DHCP lease names on the `--net` network the live runs use.
pub const DEFAULT_SERVER: Ipv4 = Ipv4::new([10, 0, 2, 3]);

/// How long one attempt waits for a reply before moving on.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Configuration files consulted by [`Resolver::system`], in order.
pub const RESOLV_CONF_PATHS: [&str; 2] = ["/etc/resolv.conf", "/mnt/etc/resolv.conf"];

/// Why a name did not resolve. Every variant is a refusal; none is a partial
/// answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The configured server list is empty — nothing to ask.
    NoServer,
    /// The name cannot be encoded (see [`WireError::BadName`]).
    InvalidName,
    /// The UDP socket could not be created, bound, or written to.
    Io(ErrorKind),
    /// No reply arrived within `attempts * timeout`.
    Timeout,
    /// `NOERROR` with no `A` record and no `CNAME` to follow.
    NoRecords,
    /// `NXDOMAIN`: the name does not exist.
    NameError,
    /// `SERVFAIL`: the server could not answer.
    ServerFailure,
    /// `REFUSED`: the server declined to answer.
    Refused,
    /// Any other non-zero response code.
    Rcode(u8),
    /// `TC=1`: the answer did not fit a datagram and this SDK has no TCP
    /// fallback.
    Truncated,
    /// The reply was not a well-formed answer to the query we sent.
    Malformed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NoServer => f.write_str("no DNS server configured"),
            Error::InvalidName => f.write_str("not a valid DNS name"),
            Error::Io(kind) => write!(f, "socket error ({kind:?})"),
            Error::Timeout => f.write_str("no reply before the deadline"),
            Error::NoRecords => f.write_str("NOERROR with no A record"),
            Error::NameError => f.write_str("NXDOMAIN"),
            Error::ServerFailure => f.write_str("SERVFAIL"),
            Error::Refused => f.write_str("REFUSED"),
            Error::Rcode(code) => write!(f, "rcode {code}"),
            Error::Truncated => f.write_str("truncated answer (no TCP fallback)"),
            Error::Malformed => f.write_str("malformed reply"),
        }
    }
}

impl From<Error> for SdkError {
    fn from(error: Error) -> SdkError {
        let kind = match error {
            Error::NoServer => ErrorKind::Unsupported,
            Error::InvalidName => ErrorKind::InvalidInput,
            Error::Io(kind) => kind,
            Error::Timeout => ErrorKind::TimedOut,
            Error::NoRecords | Error::NameError => ErrorKind::NotFound,
            Error::Truncated | Error::Malformed => ErrorKind::InvalidData,
            Error::ServerFailure | Error::Refused | Error::Rcode(_) => ErrorKind::Other,
        };
        SdkError::new(kind, error.message())
    }
}

impl Error {
    /// A `'static` message for [`crate::error::Error::new`].
    const fn message(self) -> &'static str {
        match self {
            Error::NoServer => "dns: no DNS server configured",
            Error::InvalidName => "dns: not a valid DNS name",
            Error::Io(_) => "dns: socket error",
            Error::Timeout => "dns: no reply before the deadline",
            Error::NoRecords => "dns: NOERROR with no A record",
            Error::NameError => "dns: NXDOMAIN (no such name)",
            Error::ServerFailure => "dns: SERVFAIL",
            Error::Refused => "dns: REFUSED",
            Error::Rcode(_) => "dns: unexpected response code",
            Error::Truncated => "dns: truncated answer (no TCP fallback)",
            Error::Malformed => "dns: malformed reply",
        }
    }
}

impl From<WireError> for Error {
    fn from(error: WireError) -> Error {
        match error {
            WireError::BadName => Error::InvalidName,
            WireError::BufferTooSmall | WireError::Truncated | WireError::BadPointer => {
                Error::Malformed
            }
            WireError::NotAResponse | WireError::QuestionMismatch | WireError::BadRecord => {
                Error::Malformed
            }
        }
    }
}

/// A stub resolver: the server list, the per-attempt timeout and the retry
/// budget.
#[derive(Debug, Clone)]
pub struct Resolver {
    servers: Vec<Ipv4>,
    port: u16,
    timeout: Duration,
    attempts: u8,
}

impl Default for Resolver {
    fn default() -> Resolver {
        Resolver {
            servers: alloc::vec![DEFAULT_SERVER],
            port: DNS_PORT,
            timeout: DEFAULT_TIMEOUT,
            attempts: 2,
        }
    }
}

impl Resolver {
    /// A resolver with the compiled-in default server.
    pub fn new() -> Resolver {
        Resolver::default()
    }

    /// A resolver that asks exactly these servers, in order.
    pub fn with_servers(servers: &[Ipv4]) -> Resolver {
        Resolver {
            servers: servers.to_vec(),
            ..Resolver::default()
        }
    }

    /// The system resolver: the first configuration file that exists and names
    /// at least one server, else the compiled-in default.
    ///
    /// Returns the resolver *and* where its servers came from, so a caller (and
    /// the live transcript) can tell a configured server from the fallback
    /// instead of assuming.
    pub fn system() -> (Resolver, &'static str) {
        for path in RESOLV_CONF_PATHS {
            if let Ok(text) = fs::read_to_string(path) {
                let servers = parse_resolv_conf(&text);
                if !servers.is_empty() {
                    return (Resolver::with_servers(&servers), path);
                }
            }
        }
        (Resolver::default(), "compiled-in default")
    }

    /// The servers this resolver asks, in order.
    pub fn servers(&self) -> &[Ipv4] {
        &self.servers
    }

    /// Set the destination port (default [`DNS_PORT`]).
    ///
    /// A non-53 port is a test and diagnostic shape: it lets a caller point the
    /// resolver at a server it controls, which is the only way to prove the
    /// retry deadline end to end (a silent socket that never answers).
    pub fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    /// The destination port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Set the per-attempt timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Set how many times the server list is tried.
    pub fn set_attempts(&mut self, attempts: u8) {
        self.attempts = attempts.max(1);
    }

    /// Resolve `name` to its `A` records, following one `CNAME` chain.
    pub fn resolve_a(&self, name: &str) -> core::result::Result<Vec<Ipv4>, Error> {
        self.resolve_depth(name, 0)
    }

    /// Resolve `name` to its first `A` record.
    pub fn resolve(&self, name: &str) -> core::result::Result<Ipv4, Error> {
        self.resolve_a(name)?
            .into_iter()
            .next()
            .ok_or(Error::NoRecords)
    }

    fn resolve_depth(&self, name: &str, depth: u8) -> core::result::Result<Vec<Ipv4>, Error> {
        if self.servers.is_empty() {
            return Err(Error::NoServer);
        }
        // A name that cannot be encoded is refused before any socket exists.
        let mut query = [0u8; 512];
        let id = next_transaction_id();
        let length = dns_wire::encode_query(name, id, &mut query).map_err(Error::from)?;

        let mut last = Error::Timeout;
        for _ in 0..self.attempts {
            for &server in &self.servers {
                match self.query(server, &query[..length], id, name) {
                    Ok(response) => {
                        if response.has_address() {
                            return Ok(response
                                .addresses
                                .iter()
                                .map(|record| Ipv4::new(record.address))
                                .collect());
                        }
                        if let Some(target) = response.cname.clone() {
                            if depth >= MAX_CNAME_DEPTH {
                                return Err(Error::Malformed);
                            }
                            return self.resolve_depth(&target, depth + 1);
                        }
                        if response.rcode == dns_wire::RCODE_NOERROR {
                            return Err(Error::NoRecords);
                        }
                        return Err(rcode_error(response.rcode));
                    }
                    Err(error) => last = error,
                }
            }
        }
        Err(last)
    }

    /// One question to one server, with the reply matched by source *and* id.
    fn query(
        &self,
        server: Ipv4,
        query: &[u8],
        id: u16,
        name: &str,
    ) -> core::result::Result<Response, Error> {
        // The socket is bound to an ephemeral port: the ABI cannot report which
        // one it chose, and it does not have to — the kernel routes the reply
        // back to the descriptor.
        let mut socket = UdpSocket::bind(0).map_err(|error| Error::Io(error.kind()))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| Error::Io(error.kind()))?;
        let destination = SocketAddr::new(server, self.port);
        socket
            .send_to(query, destination)
            .map_err(|error| Error::Io(error.kind()))?;

        let deadline = Instant::now() + self.timeout;
        let mut buffer = [0u8; 1500];
        loop {
            let (read, source) = match socket.recv_from(&mut buffer) {
                Ok(datagram) => datagram,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    return if Instant::now() >= deadline {
                        Err(Error::Timeout)
                    } else {
                        // `recv_from` returned early (a stale descriptor state
                        // or a spurious wake): keep waiting inside the budget.
                        continue;
                    };
                }
                Err(error) => return Err(Error::Io(error.kind())),
            };
            // A datagram from anywhere but the server we asked is not an answer
            // to this query, whatever it contains.
            if source.ip() != server || source.port() != self.port {
                if Instant::now() >= deadline {
                    return Err(Error::Timeout);
                }
                continue;
            }
            match dns_wire::parse_response(&buffer[..read], id, name) {
                Ok(response) => {
                    if response.truncated {
                        return Err(Error::Truncated);
                    }
                    return Ok(response);
                }
                // A reply that fails the id/question checks is discarded and the
                // deadline is re-checked, so a flood of junk cannot extend the
                // wait past the budget.
                Err(_) => {
                    if Instant::now() >= deadline {
                        return Err(Error::Malformed);
                    }
                    continue;
                }
            }
        }
    }
}

/// How many `CNAME` hops one resolution follows before refusing.
const MAX_CNAME_DEPTH: u8 = 4;

/// Parse the `nameserver` lines of a `resolv.conf`-shaped file.
///
/// Only `nameserver <dotted-quad>` is understood; comments (`#`/`;`), blank
/// lines, `search`, `domain` and `options` are ignored. A malformed address is
/// skipped rather than aborting the file, and duplicates are kept (the resolver
/// tries them in order).
pub fn parse_resolv_conf(text: &str) -> Vec<Ipv4> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("");
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Some(address) = fields.next().and_then(Ipv4::parse) {
            servers.push(address);
        }
    }
    servers
}

/// Map a non-zero `RCODE` to the resolver's error.
fn rcode_error(rcode: u8) -> Error {
    match rcode {
        1 => Error::Malformed,
        2 => Error::ServerFailure,
        3 => Error::NameError,
        5 => Error::Refused,
        other => Error::Rcode(other),
    }
}

/// Transaction ids for the process, seeded from the monotonic clock.
///
/// Documented as *varying*, not unpredictable: the ABI has no entropy source
/// (see the module docs). The question-echo check in the parser is what makes a
/// guessed id insufficient.
fn next_transaction_id() -> u16 {
    use core::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    static SEED: AtomicU16 = AtomicU16::new(0);
    let mut seed = SEED.load(Ordering::Relaxed);
    if seed == 0 {
        let now = Instant::now().elapsed_millis() as u16;
        seed = now ^ 0x5bf1;
        SEED.store(seed, Ordering::Relaxed);
    }
    let previous = COUNTER.fetch_add(1, Ordering::Relaxed);
    seed.wrapping_add(previous.wrapping_mul(26544)).max(1)
}

/// Resolve `name` with the system resolver ([`Resolver::system`]).
///
/// This is the function [`crate::net::TcpStream::connect_host`] and
/// [`crate::net::connect`] use, so a name resolves the same way everywhere.
pub fn resolve(name: &str) -> Result<Ipv4> {
    // A literal needs no query at all.
    if let Some(literal) = Ipv4::parse(name) {
        return Ok(literal);
    }
    let (resolver, _source) = Resolver::system();
    resolver.resolve(name).map_err(SdkError::from)
}

/// Resolve `name` to every `A` record, with the system resolver.
pub fn resolve_all(name: &str) -> Result<Vec<Ipv4>> {
    if let Some(literal) = Ipv4::parse(name) {
        return Ok(alloc::vec![literal]);
    }
    let (resolver, _source) = Resolver::system();
    resolver.resolve_a(name).map_err(SdkError::from)
}
