//! TLS 1.3 for userland — the **kernel's** fail-closed client, wrapped in a
//! stream a program can read and write.
//!
//! pagh-riscv 0.21.0 owns a TLS 1.3 client: the handshake, the key schedule,
//! the record layer and a fail-closed verifier, exposed as four syscalls
//! (`docs/abi.md` §2):
//!
//! | nr | call | what it does |
//! |---|---|---|
//! | 1100 | `tls_connect` | handshake on a **connected** stream socket; the descriptor becomes the session |
//! | 1101 | `tls_write` | encrypt application data |
//! | 1102 | `tls_read` | decrypt application data; `0` is `close_notify` |
//! | 1103 | `tls_close` | send `close_notify`, release the session, close the descriptor |
//!
//! [`TlsStream`] is the SDK's ownership story for those four calls, and
//! [`https_get`] is the one-shot HTTPS client built on it.
//!
//! ```ignore
//! let response = pagh_std::tls::https_get("https://example.com/")?;
//! println!("status {} body {} bytes", response.status(), response.body_len());
//! ```
//!
//! # What is verified, and who verifies it
//!
//! The **kernel** does, before a single application byte can move, and there is
//! no flag anywhere in this API that changes it:
//!
//!   * the certificate chain must reach an anchor of the kernel's committed CA
//!     bundle, with every signature checked;
//!   * the `host` passed to [`TlsStream::connect`] must be authorized by a
//!     `dNSName`/`iPAddress` SAN entry (SNI and the SAN check are the same
//!     name, so "connect to this address, claim that name" is exactly what gets
//!     refused);
//!   * the certificate validity windows must contain the machine's real time,
//!     read from its RTC — not from `clock_gettime`, which on this ABI is the
//!     uptime counter;
//!   * `CertificateVerify` must prove possession of the leaf key, and the
//!     kernel independently checks that a certificate was verified *during this
//!     handshake* before it exposes the session.
//!
//! A refusal is an error here: [`ErrorKind::PermissionDenied`](crate::error::ErrorKind::PermissionDenied)
//! for a rejected certificate (`EKEYREJECTED`),
//! [`ErrorKind::InvalidData`](crate::error::ErrorKind::InvalidData) for a
//! malformed handshake (`EPROTO`),
//! [`ErrorKind::Unsupported`](crate::error::ErrorKind::Unsupported) when the
//! machine has no wall clock at all, and
//! [`ErrorKind::WouldBlock`](crate::error::ErrorKind::WouldBlock) when the
//! entropy pool has no seed. The kernel prints the specific gate on the serial line
//! (`tls: verify FAILED cause=chain|hostname|clock|signature`, `tls: user
//! session host=… REFUSED cause=NoEntropy|NoClock`).
//!
//! # No clock, no entropy, no feature flags
//!
//! 0.7.0 shipped a userland TLS 1.3 stack ([`vendored`], still available behind
//! the `vendored-tls` feature) that had to ask the caller for a wall clock and
//! 32 bytes of entropy, because the ABI had neither. Both inputs now come from
//! the kernel — `getrandom` (278) for the session keys, the RTC for the
//! validity windows — so [`TlsStream::connect`] takes nothing but a
//! `host:port`.
//!
//! # Layout
//!
//!   * [`TlsStream`] — `connect("host:port")` (resolve + connect + handshake)
//!     or `connect_stream(socket, host)`, then [`Read`](crate::io::Read) /
//!     [`Write`](crate::io::Write), `close()` or `Drop`;
//!   * [`https_get`]/[`https_get_at`] — one HTTPS request and a decoded
//!     response (`Content-Length`, chunked or close-delimited bodies);
//!   * [`http`] — the pure request/response-head codec, shared with the
//!     vendored path and exercised by the host tests;
//!   * [`vendored`] — the 0.7.0 userland implementation, feature-gated.

pub mod http;
mod stream;
pub mod url;

pub use stream::{https_get, https_get_at, HttpResponse, TlsStream};
pub use url::HTTPS_PORT;

/// The vendored 0.7.0 userland TLS 1.3 client, built only with the
/// `vendored-tls` feature (`./build.sh --vendored`).
///
/// It is a genuinely different trust shape rather than a fallback: the
/// handshake and the certificate verification run **in the process**, against
/// the committed CA bundle and the caller's clock, and nothing about them is
/// visible to or enforceable by the kernel. Use the kernel-backed
/// [`TlsStream`] unless the program itself must own the verifier — or must run
/// on a kernel older than 0.21.0, which is the one case the feature exists for.
#[cfg(feature = "vendored-tls")]
pub mod vendored;
