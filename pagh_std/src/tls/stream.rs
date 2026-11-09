//! The kernel-backed TLS 1.3 session: a [`TcpStream`] promoted to a TLS stream
//! by `tls_connect` (syscall 1100), read and written with `tls_read`/`tls_write`
//! (1102/1101) and closed with `tls_close` (1103).
//!
//! Nothing about the handshake lives here. The kernel owns the TLS 1.3 client —
//! the key schedule, the record layer and the fail-closed verifier — so a
//! program gets an authenticated session by calling one syscall on a socket it
//! already connected. This module is the thin, honest wrapper: it connects the
//! socket, converts the descriptor's ownership, and turns the ABI's errno into
//! the SDK's [`Error`].

use alloc::string::String;
use alloc::vec::Vec;

use libpagh::sys;

use crate::error::{Error, ErrorKind, Result};
use crate::io::{Read, Write};
use crate::net::{Ipv4, SocketAddr, TcpStream};

use super::http::{self, ChunkProgress, ChunkedDecoder, HeadParse};
use super::url::Target;

/// Largest response body [`https_get`] will buffer.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// Bytes requested per `tls_read`. The kernel copies at most one page per call
/// (`TLS_COPY_CHUNK` = 4096 in `src/user/syscall.rs`), so a larger buffer only
/// wastes heap.
const READ_CHUNK: usize = 4096;

/// The sentinel in [`TlsStream::fd`] once the descriptor has been released.
const CLOSED: i32 = -1;

// ─── the stream ─────────────────────────────────────────────────────────────

/// An authenticated TLS 1.3 session over a TCP stream, carried by one
/// descriptor.
///
/// Created by [`TlsStream::connect`] (`host:port`, resolved and connected here)
/// or [`TlsStream::connect_stream`] (a socket the caller already connected).
/// Both run the kernel's fail-closed handshake: the server's chain must reach
/// the committed CA bundle, its SAN entries must authorize `host`, the clock
/// gate must pass, and `CertificateVerify` must prove possession of the leaf
/// key. There is no flag that weakens any of that — the ABI defines
/// `tls_connect`'s `flags` as 0 and answers `EINVAL` otherwise.
///
/// Nothing is buffered in userland: [`Write::write`] hands plaintext to the
/// record layer and [`Read::read`] decrypts what has arrived, so
/// [`Write::flush`] has nothing to do (it is `Ok(())`). A read **blocks**
/// (bounded by the kernel's ~20 s idle budget) until at least one byte is
/// available; `Ok(0)` is a `close_notify` from the peer, while a TCP close
/// *without* one is [`Errno::ECONNRESET`](libpagh::errno::Errno::ECONNRESET) —
/// truncation is not silently reported as end of stream.
///
/// [`TlsStream::close`] is the graceful close (`close_notify`). Dropping the
/// value calls `close(2)` instead, which releases the session without the
/// alert: `Drop` also runs at process teardown and may not wait for a peer.
#[derive(Debug)]
pub struct TlsStream {
    /// The session descriptor, or [`CLOSED`] once it has been released.
    fd: i32,
    host: String,
    peer: SocketAddr,
}

impl TlsStream {
    /// Connect to `host:port` and perform the kernel's TLS 1.3 handshake.
    ///
    /// The port is mandatory — the ABI has no default-port table — and is
    /// usually [`HTTPS_PORT`](crate::tls::HTTPS_PORT). `host` may be a
    /// dotted-quad IPv4 literal or a name, which [`TcpStream::connect_host`]
    /// resolves with the SDK's own RFC 1035 resolver; either way the *name* is
    /// what the certificate must authorize, so an IP literal is only useful when
    /// the certificate's SAN carries that address.
    ///
    /// On failure the kernel abandons the connection (RFC 8446 §6.1) and the
    /// descriptor is released here; the caller opens a new socket to retry.
    pub fn connect(host_port: &str) -> Result<TlsStream> {
        let (host, port) = crate::net::split_host_port(host_port)?;
        let socket = TcpStream::connect_host(host, port)?;
        TlsStream::connect_stream(socket, host)
    }

    /// Perform the handshake on an already-connected `socket` and take
    /// ownership of its descriptor.
    ///
    /// This is the shape a program needs when the destination is pinned (a
    /// fixed address with the server name kept for SNI and the SAN check) or
    /// when the connection was accepted from a listener rather than dialed.
    /// The socket must be a connected stream: an unconnected socket, a listener
    /// or a UDP socket is refused by the kernel (`ENOTCONN`, `EISCONN`,
    /// `ENOTSUP`) and nothing is sent.
    ///
    /// [`TcpStream::into_fd`] refuses to hand over a descriptor that a
    /// `try_clone` handle still shares, or one with bytes in its `BufRead`
    /// read-ahead — those bytes are the caller's to drain, and losing them
    /// between the TCP connection and the handshake would corrupt the TLS
    /// stream.
    pub fn connect_stream(socket: TcpStream, host: &str) -> Result<TlsStream> {
        let peer = socket.peer_addr();
        let fd = socket.into_fd()?;
        let mut stream = TlsStream {
            fd,
            host: String::from(host),
            peer,
        };
        match sys::tls_connect(fd, host) {
            Ok(()) => {
                crate::println!(
                    "tls: session up host={host} peer={peer} (kernel handshake, certificate verified)"
                );
                Ok(stream)
            }
            Err(errno) => {
                // The descriptor is a tombstone after a refused handshake (the
                // kernel already tore the TCP connection down), so release it
                // here — and mark it released first so `Drop` cannot close the
                // number a second time after the allocator reuses it.
                stream.fd = CLOSED;
                let _ = sys::close(fd);
                crate::println!(
                    "tls: FAILED stage=handshake host={host} peer={peer} cause={errno} (errno {})",
                    errno.raw()
                );
                Err(Error::from(errno))
            }
        }
    }

    /// The host name this session authenticates (SNI and the SAN check).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The peer this session is connected to.
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// The descriptor carrying the session, or `-1` after it was released.
    pub const fn fd(&self) -> i32 {
        self.fd
    }

    /// Send `close_notify`, release the session and close the descriptor.
    /// Consumes the value.
    ///
    /// `0` does not promise the peer received the alert — the kernel says so on
    /// the serial line when delivery fails — but the session is gone either
    /// way. A caller that does not care about the goodbye can simply drop the
    /// value, which calls `close(2)`.
    pub fn close(mut self) -> Result<()> {
        let fd = core::mem::replace(&mut self.fd, CLOSED);
        match sys::tls_close(fd) {
            Ok(()) => Ok(()),
            Err(errno) => {
                // `tls_close` puts a descriptor it did not recognize back
                // untouched (`EINVAL`), so release it rather than leak.
                let _ = sys::close(fd);
                Err(Error::from(errno))
            }
        }
    }

    /// Read one complete HTTP/1.1 response off this session.
    ///
    /// The session must already carry a request (this method sends nothing):
    /// write the `GET` with [`Write::write_all`], then call this, which reads
    /// the head, follows the body framing the response declares
    /// (`Content-Length`, chunked, or close-delimited) and returns as soon as
    /// the body is complete — a server that keeps the connection open does not
    /// have to close it first.
    ///
    /// A stream that ends inside a declared body is
    /// [`ErrorKind::UnexpectedEof`], never a short success. Note that the
    /// kernel also reports a TCP close *without* `close_notify` as
    /// [`Errno::ECONNRESET`](libpagh::errno::Errno::ECONNRESET), so truncation
    /// is visible either way.
    pub fn read_http_response(&mut self) -> Result<HttpResponse> {
        read_response(self)
    }

    /// One `tls_read`: the shared body of [`Read::read`].
    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match sys::tls_read(self.fd, buf) {
                Ok(read) => return Ok(read),
                // EAGAIN on a TLS descriptor is not "nothing arrived yet" —
                // `tls_read` blocks — it is another thread of this process
                // already inside a call on this session. Yield and retry, the
                // same contract `libpagh::tls` documents.
                Err(libpagh::errno::Errno::EAGAIN) => {
                    let _ = sys::sched_yield();
                }
                Err(errno) => return Err(Error::from(errno)),
            }
        }
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        if self.fd != CLOSED {
            // `close(2)`, not `tls_close(1103)`: Drop must not block waiting for
            // a peer's alert, and the kernel releases the session either way.
            let _ = sys::close(self.fd);
            self.fd = CLOSED;
        }
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.read_chunk(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        sys::tls_write(self.fd, buf).map_err(Error::from)
    }

    fn flush(&mut self) -> Result<()> {
        // The record layer is in the kernel and `tls_write` does not return
        // until it took the plaintext, so there is no userland buffer to push.
        Ok(())
    }
}

// ─── one-shot HTTPS GET ─────────────────────────────────────────────────────

/// A complete HTTP/1.1 response read through a TLS session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    /// The status code from the response line (`200`, `404`, …).
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// The decoded body — `Content-Length`-, chunked- or close-delimited.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The body length in bytes.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Take the body.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// Fetch `url` (`https://host[:port][/path]`) and return the response.
///
/// The host is resolved, connected and then authenticated by the kernel's
/// handshake — no caller-supplied clock and no entropy, because the kernel has
/// both. Any status is returned as a value: a `404` is a response, not an I/O
/// failure. Errors are the transport's, the handshake's (notably
/// [`ErrorKind::PermissionDenied`] for a rejected certificate,
/// [`ErrorKind::Unsupported`] when the machine has no wall clock and
/// [`ErrorKind::WouldBlock`] when the entropy pool has no seed) and the
/// body-framing failures.
///
/// ```ignore
/// let response = pagh_std::tls::https_get("https://example.com/")?;
/// println!("status {} body {} bytes", response.status(), response.body_len());
/// ```
pub fn https_get(url: &str) -> Result<HttpResponse> {
    https_get_impl(url, None)
}

/// As [`https_get`], but `address` pins the destination instead of resolving
/// `host`.
///
/// The TLS server name is still the URL's host, which is the shape a negative
/// test needs: "talk to *this* server while claiming to be *that* name" is
/// exactly what the kernel's SAN check exists to reject, and DNS alone cannot
/// produce it.
pub fn https_get_at(url: &str, address: Ipv4) -> Result<HttpResponse> {
    https_get_impl(url, Some(address))
}

fn https_get_impl(url: &str, address: Option<Ipv4>) -> Result<HttpResponse> {
    let target =
        Target::parse(url).map_err(|error| Error::new(ErrorKind::InvalidInput, error.message()))?;
    crate::println!(
        "tls: https_get host={} port={} path={}",
        target.host,
        target.port,
        target.path
    );
    let mut session = match address {
        Some(address) => {
            crate::println!("tls: address pinned by the caller -> {address}");
            let socket = TcpStream::connect(address, target.port)?;
            TlsStream::connect_stream(socket, &target.host)?
        }
        None => TlsStream::connect(&target.host_port())?,
    };

    let request = target.get_request();
    session.write_all(&request)?;
    session.flush()?;

    let response = session.read_http_response()?;
    crate::println!(
        "tls: fetch OK status={} body={} bytes",
        response.status,
        response.body.len()
    );
    // The response is complete, so say goodbye if the peer is still there. A
    // failed `close_notify` does not invalidate bytes that were already read
    // whole, so it is not an error here — `Drop` releases the descriptor either
    // way.
    let _ = session.close();
    Ok(response)
}

/// How the body of the response in flight is framed.
enum Framing {
    /// The head has not been parsed yet.
    Head,
    /// `Content-Length: n` — complete at `offset + n` bytes.
    Length {
        status: u16,
        offset: usize,
        length: usize,
    },
    /// `Transfer-Encoding: chunked`.
    Chunked {
        status: u16,
        decoder: ChunkedDecoder,
        /// How much of `raw` has been fed to `decoder` already.
        fed: usize,
    },
    /// Neither framing: the body ends when the peer closes the connection
    /// (legal for a `Connection: close` response).
    UntilEof { status: u16, offset: usize },
}

/// Read a complete HTTP/1.1 response off `session`.
///
/// Stops as soon as the framing says the body is complete (a server may keep
/// the connection open), and at end of stream for a close-delimited body. A
/// stream that ends inside a declared body is an error, never a short success.
fn read_response(session: &mut TlsStream) -> Result<HttpResponse> {
    let mut raw: Vec<u8> = Vec::new();
    let mut framing = Framing::Head;
    let mut buffer = [0u8; READ_CHUNK];
    loop {
        if let Some(response) = try_finish(&raw, &mut framing)? {
            return Ok(response);
        }
        let read = session.read(&mut buffer)?;
        if read == 0 {
            return finish_at_eof(&raw, &framing);
        }
        raw.try_reserve(read)
            .map_err(|_| Error::from(libpagh::errno::Errno::ENOMEM))?;
        raw.extend_from_slice(&buffer[..read]);
        if raw.len() > MAX_BODY {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "tls: the response is larger than the 8 MiB body cap",
            ));
        }
    }
}

/// Advance the framing over `raw`; `Some` once the whole response is in hand.
fn try_finish(raw: &[u8], framing: &mut Framing) -> Result<Option<HttpResponse>> {
    if matches!(framing, Framing::Head) {
        let (status, content_length, body_off, chunked) = match http::parse_http_head(raw) {
            HeadParse::Need => return Ok(None),
            HeadParse::Malformed => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "tls: the response head is malformed",
                ))
            }
            HeadParse::Done {
                status,
                content_length,
                body_off,
                chunked,
            } => (status, content_length, body_off, chunked),
        };
        if let Some(length) = content_length {
            let length = length as usize;
            if length > MAX_BODY {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "tls: Content-Length is larger than the 8 MiB body cap",
                ));
            }
            crate::println!(
                "tls: response {status}, content-length {length}, body starts at {body_off}"
            );
            *framing = Framing::Length {
                status,
                offset: body_off,
                length,
            };
        } else if chunked {
            crate::println!(
                "tls: response {status}, transfer-encoding chunked, body starts at {body_off}"
            );
            let mut decoder = ChunkedDecoder::new(MAX_BODY);
            let progress = decoder.push(&raw[body_off..]);
            let fed = raw.len();
            match progress {
                ChunkProgress::Done => {
                    return Ok(Some(HttpResponse {
                        status,
                        body: decoder.body().to_vec(),
                    }))
                }
                ChunkProgress::Malformed => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "tls: malformed chunked framing",
                    ))
                }
                ChunkProgress::Need => {}
            }
            *framing = Framing::Chunked {
                status,
                decoder,
                fed,
            };
        } else {
            crate::println!(
                "tls: response {status}, no Content-Length and no chunked framing: \
                 reading until the peer closes"
            );
            *framing = Framing::UntilEof {
                status,
                offset: body_off,
            };
        }
    }

    match framing {
        Framing::Head => Ok(None),
        Framing::Length {
            status,
            offset,
            length,
        } => {
            if raw.len() >= *offset + *length {
                Ok(Some(HttpResponse {
                    status: *status,
                    body: raw[*offset..*offset + *length].to_vec(),
                }))
            } else {
                Ok(None)
            }
        }
        Framing::Chunked {
            status,
            decoder,
            fed,
        } => {
            if raw.len() > *fed {
                let progress = decoder.push(&raw[*fed..]);
                *fed = raw.len();
                match progress {
                    ChunkProgress::Done => {
                        return Ok(Some(HttpResponse {
                            status: *status,
                            body: decoder.body().to_vec(),
                        }))
                    }
                    ChunkProgress::Malformed => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "tls: malformed chunked framing",
                        ))
                    }
                    ChunkProgress::Need => {}
                }
            }
            Ok(None)
        }
        Framing::UntilEof { .. } => Ok(None),
    }
}

/// The verdict when the peer closed the stream.
fn finish_at_eof(raw: &[u8], framing: &Framing) -> Result<HttpResponse> {
    match framing {
        Framing::UntilEof { status, offset } => Ok(HttpResponse {
            status: *status,
            body: raw[*offset..].to_vec(),
        }),
        Framing::Head => Err(Error::new(
            ErrorKind::UnexpectedEof,
            "tls: the peer closed before the response head was complete",
        )),
        Framing::Length { .. } => Err(Error::new(
            ErrorKind::UnexpectedEof,
            "tls: the peer closed before Content-Length bytes arrived",
        )),
        Framing::Chunked { .. } => Err(Error::new(
            ErrorKind::UnexpectedEof,
            "tls: the peer closed inside the chunked body",
        )),
    }
}
