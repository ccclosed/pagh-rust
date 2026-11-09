//! The effectful half of [`super`]: a [`TcpStream`]-backed `embedded-tls`
//! driver, the session RNG (seeded from `getrandom` or from the caller), and
//! the `https_get` convenience fetch.
//!
//! Three small pieces bridge an async TLS state machine onto the SDK's
//! synchronous sockets; there is no async runtime here:
//!
//!   1. [`block_on`] — a single-future executor that polls until `Ready`,
//!      sleeping a millisecond between `Pending` polls;
//!   2. [`Transport`] — `embedded_io_async::Read`/`Write` over a [`TcpStream`]
//!      put into non-blocking mode, with an inactivity deadline that is re-armed
//!      on every byte moved (a slow-but-progressing transfer is never killed,
//!      only a genuine stall);
//!   3. [`Entropy`] — a ChaCha20 CSPRNG, seeded from the kernel's pool
//!      ([`Entropy::from_kernel`], `getrandom` 278) or from 32 caller-supplied
//!      bytes ([`Entropy::from_seed`]).
//!
//! Everything else ([`super::tls_auth`], [`super::tls_chain`],
//! [`super::tls_verify`], [`super::x509`]) is pure and socket-free.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use embedded_io::ErrorKind as IoErrorKind;
use embedded_tls::{
    Aes128GcmSha256, CertificateEntryRef, CertificateRef, CertificateVerifyRef, CryptoProvider,
    SignatureScheme, TlsConfig, TlsConnection, TlsContext, TlsError, TlsVerifier,
};
use rand_core::{CryptoRng, RngCore, SeedableRng};

use crate::error::{Error as SdkError, ErrorKind, Result as SdkResult};
use crate::io::{Read, Write};
use crate::net::{dns, Ipv4, SocketAddr, TcpStream};
use crate::time::{Duration, Instant};

use super::ca_bundle::CA_BUNDLE;
use super::tls_auth::{self, AuthError, LeafKey};
use super::tls_chain::{TrustAnchor, CLOCK_FLOOR};
use super::tls_verify::Tls13Scheme;

/// The IANA port for HTTPS, which is the only one this API defaults to.
pub const HTTPS_PORT: u16 = 443;

/// The width of the handshake transcript hash for [`Aes128GcmSha256`]: the hash
/// of the negotiated *cipher suite*, not of the signature scheme. A
/// `ecdsa_secp384r1_sha384` leaf signs a SHA-384 digest *of this 32-byte
/// value*, so a SHA-384 scheme is verifiable on this suite.
const CIPHER_SUITE_HASH_LEN: usize = 32;
const _: () = assert!(
    CIPHER_SUITE_HASH_LEN
        == <<<Aes128GcmSha256 as embedded_tls::TlsCipherSuite>::Hash as sha2::digest::OutputSizeUser>::OutputSize as sha2::digest::typenum::Unsigned>::USIZE,
    "CIPHER_SUITE_HASH_LEN must match the negotiated cipher suite's hash width"
);

/// TLS record buffer size: 16 KiB plus TLS record overhead, the documented
/// maximum for any TLS 1.3 record.
const RECORD_BUF: usize = 16 * 1024 + 256;

/// Application read chunk: `embedded-tls` returns at most one decrypted record
/// per read, so a full-record buffer avoids throttling the executor.
const APP_READ_BUF: usize = 16 * 1024;

/// Upper bound on a response body this module will buffer.
const MAX_TOTAL: usize = 8 * 1024 * 1024;

/// Inactivity budget for the transport, re-armed whenever bytes move.
const IDLE_TIMEOUT: Duration = Duration::from_secs(20);

// ─── errors ─────────────────────────────────────────────────────────────────

/// Why a TLS connection or HTTPS fetch did not complete. Every variant is a
/// refusal; none of them is a partial success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The caller's clock is below the certificate-validity floor
    /// ([`CLOCK_FLOOR`]), so validity cannot be judged.
    NoWallClock,
    /// The host name did not resolve ([`dns`]).
    Resolve,
    /// The TCP connection could not be established.
    Connect,
    /// The TLS handshake failed (the console line names the stage).
    Handshake,
    /// The server certificate was rejected; the label is one of `chain`,
    /// `hostname`, `no-hostname`, `leaf-key`, `clock`, `signature-scheme`,
    /// `signature`, `raw-key`.
    Certificate(&'static str),
    /// The handshake completed without a verified certificate — refused by the
    /// SDK's post-handshake check (see [`super`]).
    Unverified,
    /// A TLS record or socket read failed mid-stream.
    Transport(&'static str),
    /// The response head arrived but was not `200`.
    Status(u16),
    /// The response carried neither `Content-Length` nor chunked framing.
    UnknownLength,
    /// The stream ended before the declared body was complete.
    Incomplete,
    /// The body exceeded [`MAX_TOTAL`].
    TooLarge,
    /// A local I/O or allocation failure.
    Io(ErrorKind),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NoWallClock => f.write_str("no wall clock below the validity floor"),
            Error::Resolve => f.write_str("name resolution failed"),
            Error::Connect => f.write_str("TCP connect failed"),
            Error::Handshake => f.write_str("TLS handshake failed"),
            Error::Certificate(why) => write!(f, "certificate rejected ({why})"),
            Error::Unverified => f.write_str("handshake completed without a verified certificate"),
            Error::Transport(why) => write!(f, "transport failure ({why})"),
            Error::Status(code) => write!(f, "HTTP status {code}"),
            Error::UnknownLength => f.write_str("no Content-Length and no chunked framing"),
            Error::Incomplete => f.write_str("body incomplete"),
            Error::TooLarge => f.write_str("body too large"),
            Error::Io(kind) => write!(f, "I/O error ({kind:?})"),
        }
    }
}

impl From<Error> for SdkError {
    fn from(error: Error) -> SdkError {
        let kind = match error {
            Error::NoWallClock => ErrorKind::Unsupported,
            Error::Resolve => ErrorKind::NotFound,
            Error::Connect => ErrorKind::NotConnected,
            Error::Handshake => ErrorKind::InvalidData,
            Error::Certificate(_) | Error::Unverified => ErrorKind::PermissionDenied,
            Error::Transport(_) => ErrorKind::ConnectionReset,
            Error::Status(_) => ErrorKind::Other,
            Error::UnknownLength | Error::Incomplete => ErrorKind::UnexpectedEof,
            Error::TooLarge => ErrorKind::InvalidData,
            Error::Io(kind) => kind,
        };
        SdkError::new(kind, error.message())
    }
}

impl Error {
    /// A `'static` message for [`SdkError::new`].
    const fn message(&self) -> &'static str {
        match self {
            Error::NoWallClock => "tls: no wall clock below the certificate validity floor",
            Error::Resolve => "tls: name resolution failed",
            Error::Connect => "tls: TCP connect failed",
            Error::Handshake => "tls: handshake failed",
            Error::Certificate(_) => "tls: server certificate rejected",
            Error::Unverified => "tls: handshake completed without a verified certificate",
            Error::Transport(_) => "tls: transport failure",
            Error::Status(_) => "tls: unexpected HTTP status",
            Error::UnknownLength => "tls: response body has no framing",
            Error::Incomplete => "tls: response body incomplete",
            Error::TooLarge => "tls: response body too large",
            Error::Io(_) => "tls: I/O error",
        }
    }
}

// ─── entropy ────────────────────────────────────────────────────────────────

/// A CSPRNG seeded either from the kernel's pool or from a caller's 32 bytes.
///
/// The seed is expanded with ChaCha20 (`rand_chacha`), which is what makes 32
/// bytes enough. [`Entropy::from_kernel`] is the constructor to use on a
/// current system: `getrandom(278)` reads the kernel's SHA-256 pool, which is
/// seeded from the device tree at boot and is the same source the kernel's own
/// TLS client uses. [`Entropy::from_seed`] stays for a caller that brings its
/// own seed — a host harness reproducing a transcript, a deterministic test —
/// and the SDK cannot check what is in it: a constant seed produces predictable
/// session keys, which the type makes visible at the call site.
pub struct Entropy {
    rng: rand_chacha::ChaCha20Rng,
}

impl Entropy {
    /// Expand a 32-byte seed into the session RNG.
    pub fn from_seed(seed: [u8; 32]) -> Entropy {
        Entropy {
            rng: rand_chacha::ChaCha20Rng::from_seed(seed),
        }
    }

    /// Seed the session RNG from the kernel entropy pool (`getrandom`, 278).
    ///
    /// This is the honest source: the kernel refuses to invent randomness and
    /// answers [`Errno::EAGAIN`](libpagh::errno::Errno::EAGAIN) when the pool
    /// was never seeded, so the error is propagated rather than papered over
    /// with a counter or the clock. The 32 seed bytes are overwritten with the
    /// expanded state immediately and are dropped here.
    pub fn from_kernel() -> SdkResult<Entropy> {
        let mut seed = [0u8; 32];
        libpagh::random::fill(&mut seed)?;
        Ok(Entropy::from_seed(seed))
    }

    /// Read the seed from 64 hexadecimal characters (`[0-9a-fA-F]`).
    ///
    /// This exists for the command line, where a seed has to travel as text;
    /// it is not a recommendation to keep seeds in shell history.
    pub fn from_hex(text: &str) -> SdkResult<Entropy> {
        let bytes = text.as_bytes();
        if bytes.len() != 64 {
            return Err(SdkError::new(
                ErrorKind::InvalidInput,
                "Entropy::from_hex: expected exactly 64 hex characters (32 bytes)",
            ));
        }
        let mut seed = [0u8; 32];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            let high = hex_digit(pair[0]).ok_or_else(|| {
                SdkError::new(
                    ErrorKind::InvalidInput,
                    "Entropy::from_hex: not a hex digit",
                )
            })?;
            let low = hex_digit(pair[1]).ok_or_else(|| {
                SdkError::new(
                    ErrorKind::InvalidInput,
                    "Entropy::from_hex: not a hex digit",
                )
            })?;
            seed[index] = (high << 4) | low;
        }
        Ok(Entropy::from_seed(seed))
    }

    /// Fill `out` from the session RNG.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        RngCore::fill_bytes(&mut self.rng, out);
    }
}

/// One hexadecimal digit, or `None`.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl RngCore for Entropy {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        RngCore::fill_bytes(&mut self.rng, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for Entropy {}

// ─── what the verifier proved ───────────────────────────────────────────────

/// The result of the authentication that ran inside a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// SHA-256 of the leaf certificate's DER — the same fingerprint
    /// `openssl x509 -fingerprint -sha256` prints, so the transcript can be
    /// cross-checked against the host.
    pub leaf_sha256: [u8; 32],
    /// How many certificates the server sent (leaf first).
    pub chain_len: usize,
    /// How many trust anchors were available to build the path.
    pub anchors: usize,
    /// The Unix time the validity windows were judged against.
    pub now_unix: i64,
}

// ─── the verifier ───────────────────────────────────────────────────────────

/// The cause codes the verifier reports for a rejection.
const CAUSE_NONE: u32 = 0;
const CAUSE_CHAIN: u32 = 1;
const CAUSE_HOSTNAME: u32 = 2;
const CAUSE_NO_HOSTNAME: u32 = 3;
const CAUSE_LEAF_KEY: u32 = 4;
const CAUSE_CLOCK: u32 = 5;
const CAUSE_SIGNATURE_SCHEME: u32 = 6;
const CAUSE_SIGNATURE: u32 = 7;
const CAUSE_RAW_KEY: u32 = 8;

/// The label a [`Error::Certificate`] carries for a cause code.
fn cause_label(code: u32) -> &'static str {
    match code {
        CAUSE_CHAIN => "chain",
        CAUSE_HOSTNAME => "hostname",
        CAUSE_NO_HOSTNAME => "no-hostname",
        CAUSE_LEAF_KEY => "leaf-key",
        CAUSE_CLOCK => "clock",
        CAUSE_SIGNATURE_SCHEME => "signature-scheme",
        CAUSE_SIGNATURE => "signature",
        CAUSE_RAW_KEY => "raw-key",
        _ => "unknown",
    }
}

/// State shared between the verifier (owned by the handshake) and
/// [`TlsStream::connect`] (which reads it after the handshake returns).
#[derive(Default)]
struct Report {
    /// Set only after the full chain → hostname → clock decision succeeded.
    verified: AtomicBool,
    /// The rejection cause, or [`CAUSE_NONE`].
    cause: AtomicU32,
    /// SHA-256 of the leaf certificate, in eight 4-byte words.
    leaf: [AtomicU32; 8],
    /// How many certificates the server sent.
    chain_len: AtomicU32,
    /// How many trust anchors were available.
    anchors: AtomicU32,
}

impl Report {
    fn fail(&self, cause: u32) {
        self.cause.store(cause, Ordering::Release);
        crate::println!("tls: verify FAILED cause={}", cause_label(cause));
    }

    /// Record a successful authentication.
    fn accept(&self, leaf: &[u8; 32], chain_len: usize, anchors: usize) {
        for (word, chunk) in self.leaf.iter().zip(leaf.chunks_exact(4)) {
            word.store(
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                Ordering::Relaxed,
            );
        }
        self.chain_len.store(chain_len as u32, Ordering::Relaxed);
        self.anchors.store(anchors as u32, Ordering::Relaxed);
        self.verified.store(true, Ordering::Release);
    }

    /// The recorded leaf fingerprint.
    fn leaf(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (word, chunk) in self.leaf.iter().zip(out.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_le_bytes());
        }
        out
    }
}

/// The `embedded-tls` verifier: it adapts the handshake's borrowed certificate
/// entries and negotiated signature scheme onto the pure decision layer in
/// [`super::tls_auth`].
///
/// State is owned, not borrowed: the entries arrive as borrows of the
/// handshake's record buffers, so the leaf key and the transcript hash are
/// copied at `verify_certificate` time and used by `verify_signature` in the
/// same handshake. A verifier that was never given a certificate cannot verify a
/// signature (`TlsError::InvalidCertificate`), so "certificate first, then
/// CertificateVerify" is enforced, not assumed.
struct Verifier<'a> {
    /// The connection target from `TlsConfig::server_name`; `None` fails closed.
    host: Option<String>,
    /// The Unix time the caller supplied.
    now_unix: i64,
    /// The trust anchors, parsed from the committed bundle by the caller.
    anchors: &'a [TrustAnchor<'a>],
    /// Verified leaf key, set by `verify_certificate`.
    leaf_key: Option<LeafKey>,
    /// Handshake transcript hash at certificate time.
    transcript: Option<Vec<u8>>,
    /// Where the decision is recorded for the post-handshake check.
    report: Arc<Report>,
}

impl TlsVerifier<Aes128GcmSha256> for Verifier<'_> {
    fn set_hostname_verification(&mut self, hostname: &str) -> core::result::Result<(), TlsError> {
        self.host = Some(String::from(hostname));
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &<Aes128GcmSha256 as embedded_tls::TlsCipherSuite>::Hash,
        cert: CertificateRef,
    ) -> core::result::Result<(), TlsError> {
        // A non-X.509 entry (raw public key) is outside the authenticated
        // surface: reject rather than skip it, since the peer would otherwise
        // choose which entries count.
        let mut entries: Vec<&[u8]> = Vec::with_capacity(cert.entries.len());
        for entry in cert.entries.iter() {
            match entry {
                CertificateEntryRef::X509(der) => entries.push(der),
                CertificateEntryRef::RawPublicKey(_) => {
                    self.report.fail(CAUSE_RAW_KEY);
                    return Err(TlsError::InvalidCertificate);
                }
            }
        }

        // The clock gate: below the floor is a refusal, never a pass. The
        // caller supplies `now_unix`; there is no way to read it here.
        if self.now_unix < CLOCK_FLOOR {
            self.report.fail(CAUSE_CLOCK);
            return Err(TlsError::InvalidCertificate);
        }

        match tls_auth::authenticate_server(
            &entries,
            self.host.as_deref(),
            self.anchors,
            self.now_unix,
        ) {
            Ok(auth) => {
                self.leaf_key = Some(auth.leaf_key);
                use sha2::Digest;
                self.transcript = Some(transcript.clone().finalize().to_vec());
                let mut fingerprint = [0u8; 32];
                let mut hasher = sha2::Sha256::new();
                hasher.update(entries[0]);
                fingerprint.copy_from_slice(&hasher.finalize());
                self.report
                    .accept(&fingerprint, entries.len(), self.anchors.len());
                crate::println!(
                    "tls: verified leaf=sha256:{} chain={} anchors={} host={} now={}",
                    hex(&fingerprint),
                    entries.len(),
                    self.anchors.len(),
                    self.host.as_deref().unwrap_or("?"),
                    self.now_unix
                );
                Ok(())
            }
            Err(error) => {
                let cause = match error {
                    AuthError::Chain(_) => CAUSE_CHAIN,
                    AuthError::NoHostname => CAUSE_NO_HOSTNAME,
                    AuthError::HostnameMismatch => CAUSE_HOSTNAME,
                    AuthError::UnsupportedLeafKey => CAUSE_LEAF_KEY,
                };
                self.report.fail(cause);
                Err(TlsError::InvalidCertificate)
            }
        }
    }

    fn verify_signature(
        &mut self,
        verify: CertificateVerifyRef,
    ) -> core::result::Result<(), TlsError> {
        // Both facts must come from THIS handshake's verified certificate.
        let Some(leaf_key) = self.leaf_key.as_ref() else {
            return Err(TlsError::InvalidCertificate);
        };
        let Some(hash) = self.transcript.as_ref() else {
            return Err(TlsError::InvalidCertificate);
        };
        let scheme = tls13_scheme(verify.signature_scheme).ok_or_else(|| {
            self.report.fail(CAUSE_SIGNATURE_SCHEME);
            TlsError::InvalidSignatureScheme
        })?;
        tls_auth::verify_certificate_verify(
            scheme,
            CIPHER_SUITE_HASH_LEN,
            hash,
            verify.signature,
            leaf_key,
        )
        .map_err(|_| {
            self.report.fail(CAUSE_SIGNATURE);
            TlsError::InvalidSignature
        })?;
        crate::println!("tls: CertificateVerify OK (server proved possession of the leaf key)");
        Ok(())
    }
}

/// Map the negotiated TLS `SignatureScheme` onto the verifier's own enum.
///
/// `None` for everything the pure layer does not implement — `rsa_pkcs1_*`
/// (banned in TLS 1.3: their presence is a downgrade marker) and
/// PSS-with-PSS-key. Everything else stays reachable, including the SHA-384/512
/// schemes ([`CIPHER_SUITE_HASH_LEN`] explains why the widths differ).
fn tls13_scheme(scheme: SignatureScheme) -> Option<Tls13Scheme> {
    match scheme {
        SignatureScheme::EcdsaSecp256r1Sha256 => Some(Tls13Scheme::EcdsaSecp256r1Sha256),
        SignatureScheme::EcdsaSecp384r1Sha384 => Some(Tls13Scheme::EcdsaSecp384r1Sha384),
        SignatureScheme::Ed25519 => Some(Tls13Scheme::Ed25519),
        SignatureScheme::RsaPssRsaeSha256 => Some(Tls13Scheme::RsaPssRsaeSha256),
        SignatureScheme::RsaPssRsaeSha384 => Some(Tls13Scheme::RsaPssRsaeSha384),
        SignatureScheme::RsaPssRsaeSha512 => Some(Tls13Scheme::RsaPssRsaeSha512),
        _ => None,
    }
}

/// The `embedded-tls` crypto provider: the caller's entropy plus the
/// fail-closed verifier. `verifier()` always returns `Ok`, so upstream's
/// "no verifier ⇒ skip verification" branch cannot be reached.
struct Provider<'a> {
    rng: &'a mut Entropy,
    verifier: Verifier<'a>,
}

impl CryptoProvider for Provider<'_> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = p256::ecdsa::DerSignature;

    fn rng(&mut self) -> impl rand_core::CryptoRngCore {
        &mut *self.rng
    }

    fn verifier(
        &mut self,
    ) -> core::result::Result<&mut impl TlsVerifier<Self::CipherSuite>, TlsError> {
        Ok(&mut self.verifier)
    }
}

// ─── the transport ──────────────────────────────────────────────────────────

/// `embedded-io[-async]` over a [`TcpStream`] in non-blocking mode.
///
/// There is no reactor: each poll drains or writes what the socket will take
/// right now and re-arms the inactivity deadline whenever bytes move, so a
/// stalled peer ends in [`IoErrorKind::TimedOut`] instead of a hang.
struct Transport {
    stream: TcpStream,
    deadline: Instant,
}

impl Transport {
    fn new(stream: TcpStream) -> Transport {
        // Reads and writes must return `WouldBlock` rather than spin inside the
        // SDK: the executor decides when to poll again.
        let _ = stream.set_nonblocking(true);
        Transport {
            stream,
            deadline: Instant::now() + IDLE_TIMEOUT,
        }
    }

    /// Re-arm the inactivity deadline after observable progress.
    fn touch(&mut self) {
        self.deadline = Instant::now() + IDLE_TIMEOUT;
    }

    /// Return `true` once the inactivity budget has elapsed.
    fn timed_out(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// One non-blocking drain.
    fn poll_read_impl(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<core::result::Result<usize, IoErrorKind>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut filled = 0usize;
        let mut eof = false;
        while filled < buf.len() {
            match self.stream.read(&mut buf[filled..]) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(read) => filled += read,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                // Any other error is the socket saying it can no longer
                // deliver: end-of-stream, and let the record layer decide
                // whether the body was complete. The kind is printed because a
                // silent EOF and a reset are different failures.
                Err(error) => {
                    crate::println!("tls: socket read ended: {error}");
                    eof = true;
                    break;
                }
            }
        }
        if filled > 0 {
            self.touch();
            return Poll::Ready(Ok(filled));
        }
        if eof {
            return Poll::Ready(Ok(0));
        }
        if self.timed_out() {
            return Poll::Ready(Err(IoErrorKind::TimedOut));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// One non-blocking write.
    fn poll_write_impl(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, IoErrorKind>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.stream.write(buf) {
            Ok(0) => Poll::Ready(Err(IoErrorKind::BrokenPipe)),
            Ok(written) => {
                self.touch();
                Poll::Ready(Ok(written))
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if self.timed_out() {
                    Poll::Ready(Err(IoErrorKind::TimedOut))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Err(error) => {
                crate::println!("tls: socket write failed: {error}");
                Poll::Ready(Err(io_kind_of(error.kind())))
            }
        }
    }
}

impl embedded_io::ErrorType for Transport {
    type Error = IoErrorKind;
}

impl embedded_io_async::Read for Transport {
    async fn read(&mut self, buf: &mut [u8]) -> core::result::Result<usize, Self::Error> {
        core::future::poll_fn(move |cx| self.poll_read_impl(cx, &mut buf[..])).await
    }
}

impl embedded_io_async::Write for Transport {
    async fn write(&mut self, buf: &[u8]) -> core::result::Result<usize, Self::Error> {
        core::future::poll_fn(move |cx| self.poll_write_impl(cx, buf)).await
    }

    async fn flush(&mut self) -> core::result::Result<(), Self::Error> {
        // Egress happens inside each write; a no-op flush is correct here.
        Ok(())
    }
}

/// The SDK's error kinds, as `embedded-io` kinds (the transport's vocabulary).
///
/// `embedded-io` 0.7 has no `WouldBlock`: an async transport expresses "nothing
/// yet" as `Poll::Pending`, so the SDK's `WouldBlock` never crosses this
/// boundary, and the read/write paths translate it before it could.
fn io_kind_of(kind: ErrorKind) -> IoErrorKind {
    match kind {
        ErrorKind::NotFound => IoErrorKind::NotFound,
        ErrorKind::PermissionDenied => IoErrorKind::PermissionDenied,
        ErrorKind::AlreadyExists => IoErrorKind::AlreadyExists,
        ErrorKind::ConnectionRefused => IoErrorKind::ConnectionRefused,
        ErrorKind::ConnectionReset => IoErrorKind::ConnectionReset,
        ErrorKind::NotConnected => IoErrorKind::NotConnected,
        ErrorKind::BrokenPipe => IoErrorKind::BrokenPipe,
        ErrorKind::TimedOut => IoErrorKind::TimedOut,
        ErrorKind::InvalidInput => IoErrorKind::InvalidInput,
        ErrorKind::InvalidData | ErrorKind::UnexpectedEof => IoErrorKind::InvalidData,
        ErrorKind::WriteZero => IoErrorKind::WriteZero,
        ErrorKind::OutOfMemory => IoErrorKind::OutOfMemory,
        ErrorKind::Unsupported => IoErrorKind::Unsupported,
        _ => IoErrorKind::Other,
    }
}

// ─── the executor ───────────────────────────────────────────────────────────

/// A no-op `RawWaker`: [`block_on`] re-polls regardless, so waking only has to
/// satisfy the `Context` contract.
fn noop_raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(core::ptr::null(), &VTABLE)
}

/// Poll one future to completion.
///
/// The transport's inactivity deadline is what makes this terminate: every
/// `Pending` path re-checks it and returns `TimedOut` instead of parking
/// forever. Between polls it sleeps a millisecond so a waiting handshake does
/// not spin the CPU.
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    // SAFETY: every vtable entry is a no-op over a null data pointer, which
    // trivially upholds the `RawWaker` contract.
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => {
                let _ = crate::time::sleep(Duration::from_millis(1));
            }
        }
    }
}

// ─── the stream ─────────────────────────────────────────────────────────────

/// An authenticated TLS 1.3 session over a [`TcpStream`].
///
/// Dropping the value drops the underlying socket (the connection owns it); the
/// session is not closed with a `close_notify`, because the ABI's `shutdown` is
/// a full-duplex reset and the SDK would rather close than lie about a clean
/// TLS shutdown.
pub struct TlsStream {
    // Declaration order is the drop order, and it matters: the connection
    // borrows the record buffers below it, so it must drop first.
    conn: Option<TlsConnection<'static, Transport, Aes128GcmSha256>>,
    read_buf: Box<[u8]>,
    write_buf: Box<[u8]>,
    peer: SocketAddr,
    server_name: String,
    verified: Verified,
}

impl TlsStream {
    /// Perform a TLS 1.3 handshake on `stream`, authenticating `server_name`.
    ///
    /// `now_unix` is the current Unix time and `entropy` the session RNG; both
    /// come from the caller because the ABI exposes neither (see [`super`]).
    /// The handshake is refused unless the server's chain validates against the
    /// committed CA bundle, its SAN entries authorize `server_name`, `now_unix`
    /// is at or above [`CLOCK_FLOOR`], and the `CertificateVerify` signature
    /// checks out — and unless the verifier actually ran.
    pub fn connect(
        stream: TcpStream,
        server_name: &str,
        now_unix: i64,
        entropy: &mut Entropy,
    ) -> core::result::Result<TlsStream, Error> {
        if now_unix < CLOCK_FLOOR {
            crate::println!(
                "tls: FAILED stage=clock cause=NoWallClock ({now_unix} is below the validity floor {CLOCK_FLOOR})"
            );
            return Err(Error::NoWallClock);
        }
        let peer = stream.peer_addr();

        // Parse the committed bundle into anchors. A root that fails to parse
        // is skipped: that only narrows the trust set, which can turn an accept
        // into a reject and never the other way. An empty set fails every
        // handshake with `ChainError::NoAnchor`.
        let mut anchors: Vec<TrustAnchor<'static>> = Vec::with_capacity(CA_BUNDLE.len());
        let mut unparsable = 0usize;
        for (label, der) in CA_BUNDLE.iter() {
            match super::x509::parse_certificate(der) {
                Ok((cert, rest)) if rest.is_empty() => anchors.push(TrustAnchor {
                    subject: cert.subject,
                    key: cert.spki.key,
                }),
                _ => {
                    unparsable += 1;
                    crate::println!(
                        "tls: trust anchor {label:?} in the CA bundle does not parse; skipping it"
                    );
                }
            }
        }
        if anchors.is_empty() {
            crate::println!(
                "tls: the committed CA bundle yielded no usable trust anchors - every handshake is refused"
            );
        } else {
            crate::println!(
                "tls: CA bundle {} roots ({} unparsable), server_name={server_name}",
                anchors.len(),
                unparsable
            );
        }

        let config = TlsConfig::new().with_server_name(server_name);
        // The record buffers are the one large allocation on this path; the
        // connection borrows them for its whole life, which is why they are
        // heap boxes whose address does not move with the `TlsStream`.
        let read_buf = vec![0u8; RECORD_BUF].into_boxed_slice();
        let write_buf = vec![0u8; RECORD_BUF].into_boxed_slice();
        let (read_ptr, read_len) = (read_buf.as_ptr() as *mut u8, read_buf.len());
        let (write_ptr, write_len) = (write_buf.as_ptr() as *mut u8, write_buf.len());

        let report = Arc::new(Report::default());
        let transport = Transport::new(stream);

        // SAFETY: both `Box<[u8]>` allocations outlive the connection — they
        // are stored in the `TlsStream` returned below, declared *after* the
        // connection so they are dropped after it, and the boxes are never
        // moved out or reallocated. The `'static` lifetime asserted here is
        // therefore a promise the struct's field order and the `Drop` order
        // keep; no other reference to the buffers exists.
        let (read_slice, write_slice) = unsafe {
            (
                core::slice::from_raw_parts_mut(read_ptr, read_len),
                core::slice::from_raw_parts_mut(write_ptr, write_len),
            )
        };
        let mut tls = TlsConnection::new(transport, read_slice, write_slice);

        let result = block_on(async {
            let context = TlsContext::new(
                &config,
                Provider {
                    rng: entropy,
                    verifier: Verifier {
                        host: None,
                        now_unix,
                        anchors: &anchors,
                        leaf_key: None,
                        transcript: None,
                        report: Arc::clone(&report),
                    },
                },
            );
            tls.open(context).await.map_err(|error| {
                crate::println!("tls: FAILED stage=handshake cause=Handshake ({error:?})");
                Error::Handshake
            })
        });

        // The second gate: a handshake that completed without the verifier
        // having accepted a certificate is not a success, whatever the state
        // machine says.
        if let Err(error) = result {
            let cause = report.cause.load(Ordering::Acquire);
            if cause != CAUSE_NONE {
                return Err(Error::Certificate(cause_label(cause)));
            }
            crate::println!("tls: FAILED stage=handshake cause={error:?}");
            return Err(error);
        }
        if !report.verified.load(Ordering::Acquire) {
            crate::println!(
                "tls: FAILED stage=verify cause=Unverified (handshake completed without a verified server certificate)"
            );
            return Err(Error::Unverified);
        }

        let verified = Verified {
            leaf_sha256: report.leaf(),
            chain_len: report.chain_len.load(Ordering::Relaxed) as usize,
            anchors: report.anchors.load(Ordering::Relaxed) as usize,
            now_unix,
        };
        crate::println!("tls: handshake OK (TLS 1.3, AES-128-GCM-SHA256, server authenticated)");
        Ok(TlsStream {
            conn: Some(tls),
            read_buf,
            write_buf,
            peer,
            server_name: String::from(server_name),
            verified,
        })
    }

    /// The peer this session is connected to.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// The name the server was authenticated against (the SNI value).
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The record-buffer geometry this session was built with, in bytes:
    /// `(read, write)`.
    ///
    /// The buffers are owned by the connection (it borrows them for its whole
    /// life), so this is the only public view of them; it exists so the live
    /// transcript can record the actual allocation.
    pub fn record_buffers(&self) -> (usize, usize) {
        (self.read_buf.len(), self.write_buf.len())
    }

    /// What the handshake proved about the server.
    pub fn verified(&self) -> Verified {
        self.verified
    }

    /// Read decrypted application data, blocking until some is available.
    ///
    /// A `close_notify` from the peer — an authenticated alert, and the only
    /// clean way a TLS session ends — is reported as `Ok(0)`, the `std::io::Read`
    /// EOF contract. Every other record-layer failure is an error; a peer that
    /// disappears without the alert leaves a socket error, and a framed response
    /// (chunked or `Content-Length`) should therefore be consumed by its framing
    /// rather than by reading to end of stream.
    pub fn read(&mut self, buf: &mut [u8]) -> SdkResult<usize> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| SdkError::new(ErrorKind::NotConnected, "TlsStream is closed"))?;
        match block_on(conn.read(buf)) {
            Ok(read) => Ok(read),
            Err(TlsError::ConnectionClosed) => {
                crate::println!("tls: peer sent close_notify (clean end of stream)");
                Ok(0)
            }
            Err(error) => Err(transport_error(error)),
        }
    }

    /// Write application data through the session, blocking until it is sent.
    pub fn write_all(&mut self, buf: &[u8]) -> SdkResult<()> {
        let mut sent = 0usize;
        while sent < buf.len() {
            let written = self.write(&buf[sent..])?;
            if written == 0 {
                return Err(SdkError::new(
                    ErrorKind::WriteZero,
                    "TlsStream::write made no progress",
                ));
            }
            sent += written;
        }
        Ok(())
    }

    /// Push any buffered record to the socket.
    ///
    /// `embedded-tls` holds a partial record until it is full or flushed, so a
    /// caller that has written a complete request must flush it — the kernel
    /// side of this port does exactly the same after its `GET`.
    pub fn flush(&mut self) -> SdkResult<()> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| SdkError::new(ErrorKind::NotConnected, "TlsStream is closed"))?;
        match block_on(conn.flush()) {
            Ok(()) => Ok(()),
            Err(error) => Err(transport_error(error)),
        }
    }

    /// Write application data, blocking until some of it is sent.
    pub fn write(&mut self, buf: &[u8]) -> SdkResult<usize> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| SdkError::new(ErrorKind::NotConnected, "TlsStream is closed"))?;
        match block_on(conn.write(buf)) {
            Ok(written) => Ok(written),
            Err(error) => Err(transport_error(error)),
        }
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> SdkResult<usize> {
        TlsStream::read(self, buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> SdkResult<usize> {
        TlsStream::write(self, buf)
    }

    fn flush(&mut self) -> SdkResult<()> {
        TlsStream::flush(self)
    }
}

/// The SDK error for a `TlsError` that came out of the record layer.
///
/// A `TlsError::Io(kind)` is the transport's own answer (`TimedOut` from the
/// inactivity budget, `ConnectionReset` from a dead socket); everything else is
/// a protocol-level refusal, reported as invalid data with the state machine's
/// own name in the message so a transcript can tell them apart.
fn transport_error(error: TlsError) -> SdkError {
    use embedded_tls::TlsError as Tls;
    // The transcript's cause line should name the record layer's own verdict,
    // not just the SDK's paraphrase of it.
    crate::println!("tls: record layer error: {error:?}");
    match error {
        Tls::Io(IoErrorKind::TimedOut) => SdkError::new(
            ErrorKind::TimedOut,
            "tls: transport inactivity budget expired",
        ),
        Tls::Io(IoErrorKind::ConnectionReset) => SdkError::new(
            ErrorKind::ConnectionReset,
            "tls: connection reset by the peer",
        ),
        Tls::Io(IoErrorKind::BrokenPipe) | Tls::ConnectionClosed => {
            SdkError::new(ErrorKind::BrokenPipe, "tls: peer closed the connection")
        }
        Tls::InvalidCertificate => SdkError::new(
            ErrorKind::PermissionDenied,
            "tls: server certificate rejected",
        ),
        Tls::InvalidSignature => SdkError::new(
            ErrorKind::PermissionDenied,
            "tls: CertificateVerify signature invalid",
        ),
        Tls::InvalidSignatureScheme => SdkError::new(
            ErrorKind::PermissionDenied,
            "tls: signature scheme not accepted",
        ),
        other => SdkError::new(
            ErrorKind::InvalidData,
            match other {
                Tls::DecodeError | Tls::ParseError(_) | Tls::InvalidRecord => {
                    "tls: malformed record"
                }
                Tls::Unimplemented => "tls: unimplemented TLS feature requested",
                Tls::HandshakeAborted(_, _) | Tls::AbortHandshake(_, _) => "tls: handshake aborted",
                Tls::OutOfMemory => "tls: out of memory",
                Tls::CryptoError => "tls: cryptographic failure",
                _ => "tls: protocol failure",
            },
        ),
    }
}

impl core::fmt::Debug for TlsStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsStream")
            .field("peer", &self.peer)
            .field("server_name", &self.server_name)
            .field("leaf", &hex(&self.verified.leaf_sha256))
            .finish()
    }
}

// ─── https_get ──────────────────────────────────────────────────────────────

/// How the response body's end is determined once the head is parsed.
enum BodyMode {
    /// Classic `Content-Length`.
    Length { offset: usize, length: u64 },
    /// `Transfer-Encoding: chunked`.
    Chunked(super::http::ChunkedDecoder),
}

/// `GET https://host:port/path`, returning the response body.
///
/// The ordinary path: `host` is resolved through [`dns`] and the handshake
/// authenticates it. See [`https_get_at`] for the negative-test shape.
pub fn https_get(
    host: &str,
    port: u16,
    path: &str,
    now_unix: i64,
    entropy: &mut Entropy,
) -> core::result::Result<Vec<u8>, Error> {
    https_get_at(host, None, port, path, now_unix, entropy)
}

/// As [`https_get`], but `address` pins the destination instead of resolving
/// `host`.
///
/// The TLS server name is still `host` (SNI and the SAN check), which is the
/// shape a negative test needs: "talk to *this* server while claiming to be
/// *that* name" is exactly what certificate verification exists to reject, and
/// DNS alone cannot produce it.
pub fn https_get_at(
    host: &str,
    address: Option<Ipv4>,
    port: u16,
    path: &str,
    now_unix: i64,
    entropy: &mut Entropy,
) -> core::result::Result<Vec<u8>, Error> {
    crate::println!("tls: fetch host={host} port={port} path={path}");

    let destination = match address {
        Some(pinned) => {
            crate::println!("tls: address pinned by the caller -> {pinned}");
            pinned
        }
        None => match dns::resolve(host) {
            Ok(resolved) => {
                crate::println!("tls: resolve {host} -> {resolved}");
                resolved
            }
            Err(error) => {
                crate::println!("tls: FAILED stage=resolve cause=Resolve ({error})");
                return Err(Error::Resolve);
            }
        },
    };

    let started = Instant::now();
    let stream = TcpStream::connect(destination, port).map_err(|error| {
        crate::println!("tls: FAILED stage=connect cause=Connect ({error})");
        Error::Connect
    })?;
    crate::println!("tls: tcp connected to {destination}:{port}");

    let mut tls = TlsStream::connect(stream, host, now_unix, entropy)?;

    let request = super::http::build_get_request(host, path);
    tls.write_all(&request).map_err(|error| {
        crate::println!("tls: FAILED stage=write cause={error}");
        Error::Transport("request write")
    })?;
    tls.flush().map_err(|error| {
        crate::println!("tls: FAILED stage=flush cause={error}");
        Error::Transport("request flush")
    })?;

    // Read and decrypt, collecting the body. Two framings are understood:
    // `Content-Length` and chunked. Anything else is refused, not guessed at.
    let mut buf: Vec<u8> = Vec::new();
    let mut mode: Option<BodyMode> = None;
    let mut fed = 0usize;
    let mut tmp = vec![0u8; APP_READ_BUF];
    loop {
        let read = match tls.read(&mut tmp) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => {
                crate::println!("tls: FAILED stage=read cause={error}");
                return Err(Error::Incomplete);
            }
        };
        crate::println!("tls: read {read} bytes (total {})", buf.len() + read);
        buf.extend_from_slice(&tmp[..read]);
        if buf.len() > MAX_TOTAL {
            crate::println!("tls: FAILED stage=body cause=TooLarge");
            return Err(Error::TooLarge);
        }

        if mode.is_none() {
            match super::http::parse_http_head(&buf) {
                super::http::HeadParse::Need => {}
                super::http::HeadParse::Malformed => {
                    crate::println!("tls: FAILED stage=body cause=Incomplete (malformed head)");
                    return Err(Error::Incomplete);
                }
                super::http::HeadParse::Done {
                    status,
                    content_length,
                    body_off,
                    chunked,
                } => {
                    if status != 200 {
                        crate::println!("tls: FAILED stage=response cause=Status({status})");
                        return Err(Error::Status(status));
                    }
                    if let Some(length) = content_length {
                        crate::println!(
                            "tls: response 200, content-length {length}, body starts at {body_off}"
                        );
                        mode = Some(BodyMode::Length {
                            offset: body_off,
                            length,
                        });
                    } else if chunked {
                        crate::println!(
                            "tls: response 200, transfer-encoding chunked, body starts at {body_off}"
                        );
                        let mut decoder = super::http::ChunkedDecoder::new(MAX_TOTAL);
                        let progress = decoder.push(&buf[body_off..]);
                        fed = buf.len();
                        match progress {
                            super::http::ChunkProgress::Done => return Ok(decoder.body().to_vec()),
                            super::http::ChunkProgress::Malformed => {
                                crate::println!(
                                    "tls: FAILED stage=body cause=Incomplete (malformed chunked framing)"
                                );
                                return Err(Error::Incomplete);
                            }
                            super::http::ChunkProgress::Need => {
                                mode = Some(BodyMode::Chunked(decoder))
                            }
                        }
                    } else {
                        crate::println!("tls: FAILED stage=response cause=UnknownLength");
                        return Err(Error::UnknownLength);
                    }
                }
            }
        }

        match mode.as_mut() {
            Some(BodyMode::Length { offset, length }) => {
                let received = (buf.len().saturating_sub(*offset)) as u64;
                if received >= *length {
                    let end = *offset + *length as usize;
                    let body = buf[*offset..end].to_vec();
                    crate::println!(
                        "tls: fetch OK body={} bytes in {} ms",
                        body.len(),
                        started.elapsed().as_millis()
                    );
                    return Ok(body);
                }
            }
            Some(BodyMode::Chunked(decoder)) => {
                if buf.len() > fed {
                    let progress = decoder.push(&buf[fed..]);
                    fed = buf.len();
                    match progress {
                        super::http::ChunkProgress::Done => {
                            let body = decoder.body().to_vec();
                            crate::println!(
                                "tls: fetch OK body={} bytes in {} ms",
                                body.len(),
                                started.elapsed().as_millis()
                            );
                            return Ok(body);
                        }
                        super::http::ChunkProgress::Malformed => {
                            crate::println!(
                                "tls: FAILED stage=body cause=Incomplete (malformed chunked framing)"
                            );
                            return Err(Error::Incomplete);
                        }
                        super::http::ChunkProgress::Need => {}
                    }
                }
            }
            None => {}
        }
    }
    crate::println!("tls: FAILED stage=read cause=Incomplete (stream ended early)");
    Err(Error::Incomplete)
}

/// Lower-case hex, the form the transcript and `openssl` both print.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
