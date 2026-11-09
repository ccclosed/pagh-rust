//! The **vendored** TLS 1.3 client (0.7.0), kept behind the `vendored-tls`
//! feature: fail-closed server authentication performed *in userland* over a
//! [`TcpStream`](crate::net::TcpStream).
//!
//! Since 0.8.0 the default [`pagh_std::tls`](crate::tls) is the **kernel-backed**
//! one: pagh-riscv 0.21.0 owns a fail-closed TLS 1.3 client and exposes it as
//! `tls_connect`/`tls_write`/`tls_read`/`tls_close` (syscalls 1100–1103), so a
//! program no longer has to link a TLS stack, a CA bundle and five crypto
//! backends to make an authenticated HTTPS request. This module is the previous
//! implementation, kept because it is a genuinely different trust shape: the
//! handshake runs in the process, against the caller's own verifier, with a
//! caller-supplied clock — and a userland verifier is what a program needs when
//! it must pin, inspect or log the chain itself. It is compiled only when the
//! `vendored-tls` feature is enabled (`./build.sh --vendored`, or
//! `cargo build --features vendored-tls`); the default build does not pull
//! `embedded-tls` or any of the `vendor/` crates in.
//!
//! This is the userland port of the kernel's `net::tls` (pagh-riscv 0.19.0,
//! "TLS 1.3 client with fail-closed verification"): the same vendored
//! `embedded-tls` 0.19.0 (with the same deliberate local patch — see below),
//! the same committed CA bundle, and the same pure decision modules, moved here
//! so a plain program can make an authenticated HTTPS request without a kernel
//! syscall for it.
//!
//! ## What is verified before a single application byte moves
//!
//!   * **chain** — leaf → intermediates → a trust anchor from the committed
//!     [`ca_bundle::CA_BUNDLE`], with every signature checked, `cA=TRUE`
//!     enforced on every issuer, and each validity window judged against the
//!     caller's clock ([`tls_chain::verify_chain`]);
//!   * **hostname** — the connection target must be authorized by a `dNSName`
//!     or `iPAddress` SAN entry (RFC 6125, **no** CN fallback)
//!     ([`tls_auth::authenticate_server`]);
//!   * **clock** — a `now` below [`tls_chain::CLOCK_FLOOR`] (2025-01-01) is a
//!     hard refusal, so "I do not know what time it is" can never validate an
//!     expired certificate;
//!   * **CertificateVerify** — the server must prove possession of the verified
//!     leaf key over the handshake transcript ([`tls_auth::verify_certificate_verify`]).
//!
//! [`TlsStream::connect`] additionally checks, after the handshake returns,
//! that a certificate was *actually* verified during it. That is not
//! belt-and-braces for its own sake: upstream `embedded-tls` reached
//! `ApplicationData` even when the server never sent `Certificate`, so a peer
//! could skip the verifier entirely. The vendored copy carries a local patch
//! (`src/connection.rs`: `certificate_received`/`certificate_verified` gate the
//! `Finished` message) and this post-handshake check is the second, independent
//! gate — a future vendored bump cannot silently restore the fail-open path.
//!
//! ## The one input the ABI still cannot supply
//!
//! A fail-closed TLS client needs a **wall clock** and **entropy**:
//!
//!   * entropy is no longer a gap: `getrandom(278)` (pagh-riscv 0.21.0) reads
//!     the kernel's own SHA-256 pool, and [`Entropy::from_kernel`] is the
//!     recommended seed — the caller no longer has to bring 32 bytes from
//!     outside the machine. A caller that does bring its own seed (a harness
//!     reproducing a transcript, a deterministic test) still can;
//!   * the **wall clock is still a gap**: `clock_gettime(CLOCK_REALTIME)` is the
//!     uptime counter — pagh-riscv's syscall layer maps both clock ids to
//!     `timer::uptime_ms()` — and there is no RTC syscall, so a userland program
//!     cannot learn the date. [`TlsStream::connect`] therefore still takes
//!     `now_unix`, and a caller that has no clock cannot complete a handshake at
//!     all. That is the honest shape of the gap — the alternative (a clock
//!     derived from uptime) would be a TLS-looking facade with none of the
//!     guarantees, and a certificate's validity window is exactly the check it
//!     would break. The kernel-backed [`crate::tls`] does not have this
//!     limitation: the kernel reads the machine's RTC itself.
//!
//! ## Diagnostics
//!
//! Like the kernel, this module writes its decisions to the console under
//! stable markers, and the live transcript is read for exactly these lines:
//! `tls: verify FAILED cause=…`, `tls: verified leaf=sha256:… chain=… anchors=…`,
//! `tls: CertificateVerify OK`, `tls: handshake OK`, `tls: fetch OK`, and
//! `tls: FAILED stage=… cause=…`.

pub use super::http;

pub mod ca_bundle;
pub mod hostname;
pub mod tls_auth;
pub mod tls_chain;
pub mod tls_verify;
pub mod x509;

mod stream;

pub use stream::{hex, https_get, https_get_at, Entropy, Error, TlsStream, Verified, HTTPS_PORT};
