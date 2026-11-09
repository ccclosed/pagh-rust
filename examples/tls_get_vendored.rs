//! `tls_get_vendored` — the **0.7.0** userland TLS 1.3 HTTPS GET, kept as the
//! example for `pagh_std::tls::vendored` (feature `vendored-tls`).
//!
//! **Build it with `./build.sh --release --vendored`.** The default `tls_get`
//! (0.8.0) uses the kernel's TLS client and needs no feature; this one links
//! the vendored `embedded-tls` stack and its crypto backends, so the debug
//! profile comes out at 1.16 MiB — over the kernel's 1 MiB image limit — and
//! release is the profile that fits (760 KiB).
//!
//! Everything here runs in the process: the handshake, the chain walk and the
//! SAN check. That is why the caller still has to supply the wall clock (the
//! ABI's `clock_gettime` is the uptime counter), while entropy can now come
//! from the kernel (`getrandom`, 278) — pass `kernel` as the seed to use it.
//!
//! Usage:
//!
//! ```text
//! tls_get_vendored <url> <unix-seconds> <64-hex-seed|@file|kernel|none> [--ip=A.B.C.D] [--manual]
//! ```
//!
//! * `<url>` — `https://host[:port][/path]`; the host is the TLS server name
//!   (SNI and the SAN check), the port defaults to 443;
//! * `<unix-seconds>` — the wall clock the certificate validity windows are
//!   judged against. **The ABI has no wall clock** (`CLOCK_REALTIME` is the
//!   uptime counter), so it comes from the caller; the live harness passes the
//!   host's real time. Pass `0` to watch the clock gate refuse the handshake;
//! * `<64-hex-seed|@path|kernel|none>` — 32 bytes of entropy for the session
//!   RNG. `kernel` fills them from the kernel's entropy pool (`getrandom`,
//!   syscall 278, the source the kernel's own TLS client uses); `@path` reads
//!   64 hex characters from a file (the 0.7.0 live harness stages one, because
//!   the shell's input line is capped at 128 bytes); `none` watches the program
//!   refuse to invent entropy;
//! * `--ip=A.B.C.D` — pin the destination address while keeping the server name,
//!   which is how the negative tests reach "the wrong server for this name";
//! * `--manual` — drive `TlsStream` directly instead of the `https_get`
//!   helper, and print what the handshake actually proved.
//!
//! Every check is a refusal path or an evidence line, and the acceptance run
//! exercises all of them:
//!
//! | run | expected |
//! |---|---|
//! | real URL, real time, real seed | `TLS_GET PASS`, body printed |
//! | real URL with `0` seconds | refused: `stage=clock` |
//! | real URL with `none` as the seed | refused: no entropy, no socket |
//! | a self-signed local server | refused: `cause=chain` |
//! | the wrong name for a valid chain | refused: `cause=hostname` |
//!
//! Prints `TLS_GET PASS` and exits 0 only when the fetch produced a body.

#![no_std]
#![no_main]

use pagh_std::net::dns;
use pagh_std::net::{Ipv4, TcpStream};
use pagh_std::prelude::*;
use pagh_std::tls::http::{ChunkProgress, HeadParse};
use pagh_std::tls::vendored::{self as tls, TlsStream};

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let args: Vec<String> = env::args().collect();
    let mut positional: Vec<String> = Vec::new();
    let mut pinned: Option<Ipv4> = None;
    let mut manual = false;
    for argument in args.iter().skip(1) {
        if let Some(value) = argument.strip_prefix("--ip=") {
            match Ipv4::parse(value) {
                Some(address) => pinned = Some(address),
                None => {
                    eprintln!("tls_get_vendored: --ip={value}: not an IPv4 literal");
                    return 2;
                }
            }
        } else if argument == "--manual" {
            manual = true;
        } else if argument.starts_with("--") {
            eprintln!("tls_get_vendored: unknown option {argument}");
            return 2;
        } else {
            positional.push(String::from(argument.as_str()));
        }
    }
    if positional.len() != 3 {
        eprintln!(
            "usage: tls_get_vendored <url> <unix-seconds> <64-hex-seed|@file|kernel|none> \
             [--ip=A.B.C.D] [--manual]"
        );
        return 2;
    }
    let url = &positional[0];
    let now_unix: i64 = match positional[1].parse() {
        Ok(parsed) => parsed,
        Err(_) => {
            eprintln!("tls_get_vendored: <unix-seconds> must be an integer");
            return 2;
        }
    };
    let seed = &positional[2];

    // `none` is the refusal path: a caller that has no entropy gets an error,
    // not a fixed seed. It is the remaining shape of the 0.7.0 gap only for a
    // caller who refuses `kernel` — `getrandom(278)` exists and is the honest
    // source.
    if seed == "none" {
        println!(
            "tls_get_vendored: FAIL stage=entropy cause=NoEntropy (the caller supplied no seed; \
             the kernel's getrandom would be one)"
        );
        println!("TLS_GET FAIL: no entropy supplied");
        return 1;
    }
    let mut entropy = if seed == "kernel" {
        println!("tls_get_vendored: entropy = getrandom(278) -> ChaCha20");
        match tls::Entropy::from_kernel() {
            Ok(entropy) => entropy,
            Err(error) => {
                // The kernel refuses to invent randomness: an unseeded pool is
                // EAGAIN, and a program must not paper over it.
                println!("tls_get_vendored: FAIL stage=entropy cause=NoEntropy ({error})");
                println!("TLS_GET FAIL: no entropy from the kernel");
                return 1;
            }
        }
    } else {
        let (seed_text, seed_source) = match seed.strip_prefix('@') {
            Some(path) => match fs::read_to_string(path) {
                Ok(text) => (String::from(text.trim()), path),
                Err(error) => {
                    eprintln!("tls_get_vendored: seed file {path}: {error}");
                    return 2;
                }
            },
            None => (String::from(seed.as_str()), "argv"),
        };
        println!("tls_get_vendored: entropy = ChaCha20 over 32 bytes from {seed_source}");
        match tls::Entropy::from_hex(&seed_text) {
            Ok(entropy) => entropy,
            Err(error) => {
                eprintln!("tls_get_vendored: seed: {error}");
                return 2;
            }
        }
    };

    let target = match parse_url(url) {
        Ok(target) => target,
        Err(message) => {
            eprintln!("tls_get_vendored: {message}");
            return 2;
        }
    };
    println!(
        "tls_get_vendored: url={url} host={} port={} path={} now={now_unix} pinned={:?}",
        target.host, target.port, target.path, pinned
    );

    if manual {
        return manual_fetch(&target, pinned, now_unix, &mut entropy);
    }
    match tls::https_get_at(
        &target.host,
        pinned,
        target.port,
        &target.path,
        now_unix,
        &mut entropy,
    ) {
        Ok(body) => {
            report_body(&body);
            println!("TLS_GET PASS");
            0
        }
        Err(error) => {
            println!("TLS_GET FAIL: {error}");
            1
        }
    }
}

/// Drive [`TlsStream`] directly: the handshake, the authentication result it
/// carries, and one HTTP response read through the record layer.
fn manual_fetch(
    target: &Target,
    pinned: Option<Ipv4>,
    now_unix: i64,
    entropy: &mut tls::Entropy,
) -> i32 {
    let address = match pinned {
        Some(address) => address,
        None => match dns::resolve(&target.host) {
            Ok(address) => address,
            Err(error) => {
                println!("tls_get_vendored: resolve FAIL: {error}");
                println!("TLS_GET FAIL: resolve");
                return 1;
            }
        },
    };
    println!("tls_get_vendored: address {address}:{}", target.port);
    let stream = match TcpStream::connect(address, target.port) {
        Ok(stream) => stream,
        Err(error) => {
            println!("tls_get_vendored: connect FAIL: {error}");
            println!("TLS_GET FAIL: connect");
            return 1;
        }
    };
    let mut session = match TlsStream::connect(stream, &target.host, now_unix, entropy) {
        Ok(session) => session,
        Err(error) => {
            println!("tls_get_vendored: handshake FAIL: {error}");
            println!("TLS_GET FAIL: handshake");
            return 1;
        }
    };
    let verified = session.verified();
    let (read_buf, write_buf) = session.record_buffers();
    println!("tls_get_vendored: record buffers: read {read_buf} B, write {write_buf} B");
    println!(
        "tls_get_vendored: verified leaf=sha256:{} chain={} anchors={} now={} peer={} name={}",
        tls::hex(&verified.leaf_sha256),
        verified.chain_len,
        verified.anchors,
        verified.now_unix,
        session.peer_addr(),
        session.server_name()
    );
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: pagh_std/0.7.0\r\n\r\n",
        target.path, target.host
    );
    if let Err(error) = session.write_all(request.as_bytes()) {
        println!("tls_get_vendored: write FAIL: {error}");
        println!("TLS_GET FAIL: write");
        return 1;
    }
    if let Err(error) = session.flush() {
        println!("tls_get_vendored: flush FAIL: {error}");
        println!("TLS_GET FAIL: flush");
        return 1;
    }
    // The transport's inactivity budget (20 s, re-armed on every byte) is what
    // bounds this read; the ABI's own receive cannot be given a deadline.
    let mut body: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match session.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                body.extend_from_slice(&buffer[..read]);
                if body.len() > 256 * 1024 {
                    break;
                }
            }
            Err(error) => {
                println!("tls_get_vendored: read FAIL: {error}");
                println!("TLS_GET FAIL: read");
                return 1;
            }
        }
    }
    println!("tls_get_vendored: read {} response bytes", body.len());
    // Decode the framing the response actually used: `example.com` answers with
    // `Transfer-Encoding: chunked` and no `Content-Length`, so the raw bytes are
    // not the document.
    let raw = body;
    let HeadParse::Done {
        status,
        content_length,
        body_off,
        chunked,
    } = pagh_std::tls::http::parse_http_head(&raw)
    else {
        println!("tls_get_vendored: FAIL: the response head is missing or malformed");
        println!("TLS_GET FAIL: head");
        return 1;
    };
    let document: Vec<u8> = if chunked {
        let mut decoder = pagh_std::tls::http::ChunkedDecoder::new(1 << 20);
        match decoder.push(&raw[body_off..]) {
            ChunkProgress::Done => decoder.body().to_vec(),
            _ => {
                println!("tls_get_vendored: FAIL: chunked framing is incomplete");
                println!("TLS_GET FAIL: chunked");
                return 1;
            }
        }
    } else if let Some(length) = content_length {
        let end = (body_off + length as usize).min(raw.len());
        raw[body_off..end].to_vec()
    } else {
        raw[body_off..].to_vec()
    };
    let head = format!("HTTP/1.1 {status}");
    println!("tls_get_vendored: response {head}");
    if status != 200 {
        println!("TLS_GET FAIL: status");
        return 1;
    }
    report_body(&document);
    println!("TLS_GET PASS");
    0
}

/// Print the body's first line and its length: enough evidence that a real
/// document came back, without dumping a page into the transcript.
fn report_body(body: &[u8]) {
    let text = core::str::from_utf8(body).unwrap_or("<non-utf8>");
    let first = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    println!(
        "tls_get_vendored: body {} bytes, first line: {}",
        body.len(),
        first
    );
}

/// A parsed `https://host[:port][/path]`.
struct Target {
    host: String,
    port: u16,
    path: String,
}

/// Parse the small URL subset this program accepts, refusing anything else.
fn parse_url(url: &str) -> core::result::Result<Target, &'static str> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("only https:// URLs are accepted")?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .map_err(|_| "the port is not a number")?,
        ),
        None => (authority, tls::HTTPS_PORT),
    };
    if host.is_empty() {
        return Err("the URL has no host");
    }
    Ok(Target {
        host: String::from(host),
        port,
        path: String::from(path),
    })
}
