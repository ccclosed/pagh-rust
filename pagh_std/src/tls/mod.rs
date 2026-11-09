//! TLS 1.3 for userland — fail-closed server authentication over a
//! [`TcpStream`](crate::net::TcpStream).
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
//! ## The two inputs the ABI cannot supply
//!
//! A fail-closed TLS client needs a **wall clock** and **entropy**. This ABI
//! exposes neither:
//!
//!   * `clock_gettime(CLOCK_REALTIME)` is the uptime counter — `pagh-riscv`'s
//!     syscall layer maps both clock ids to `timer::uptime_ms()` — and there is
//!     no RTC syscall, so a userland program cannot know the date;
//!   * there is no `getrandom`, no `/dev/urandom` and no entropy syscall; the
//!     kernel's own pool is seeded from `/chosen/rng-seed`, which is not
//!     reachable from userland.
//!
//! The SDK therefore **requires the caller to supply both** rather than
//! inventing them: [`TlsStream::connect`] takes `now_unix` and a [`Entropy`]
//! value, and a caller that has neither cannot complete a handshake at all.
//! That is the honest shape of the gap — the alternative (a clock derived from
//! uptime, or keys derived from a fixed seed) would be a TLS-looking facade
//! with none of the guarantees. The live acceptance run supplies both from the
//! host harness: real Unix seconds and a `/dev/urandom` seed. Closing this
//! properly needs a kernel change (a `getrandom`-style syscall and a wall-clock
//! read), which is out of scope for the SDK.
//!
//! ## Diagnostics
//!
//! Like the kernel, this module writes its decisions to the console under
//! stable markers, and the live transcript is read for exactly these lines:
//! `tls: verify FAILED cause=…`, `tls: verified leaf=sha256:… chain=… anchors=…`,
//! `tls: CertificateVerify OK`, `tls: handshake OK`, `tls: fetch OK`, and
//! `tls: FAILED stage=… cause=…`.

pub mod ca_bundle;
pub mod hostname;
pub mod http;
pub mod tls_auth;
pub mod tls_chain;
pub mod tls_verify;
pub mod x509;

mod stream;

pub use stream::{hex, https_get, https_get_at, Entropy, Error, TlsStream, Verified, HTTPS_PORT};
