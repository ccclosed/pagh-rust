//! `tls_get` — an authenticated HTTPS GET through the **kernel's** TLS 1.3
//! client (pagh-riscv 0.21.0, syscalls 1100–1103).
//!
//! ```text
//! tls_get [url] [--ip=A.B.C.D] [--manual]
//! ```
//!
//! * `url` — `https://host[:port][/path]`, default `https://example.com/`;
//! * `--ip=A.B.C.D` — pin the destination address while keeping the URL's host
//!   as the TLS server name (SNI and the SAN check), which is how a negative
//!   test reaches "the wrong server for this name";
//! * `--manual` — drive [`pagh_std::tls::TlsStream`] directly: connect, write
//!   the request, read one HTTP response, close.
//!
//! There is no clock argument and no seed argument, and that is the point of
//! the 0.8.0 path: the kernel reads the RTC for the certificate validity
//! windows and `getrandom(278)` for the session keys. The program supplies
//! neither, and cannot turn verification off — `tls_connect` has no flag for it.
//!
//! Prints the status and the body length, and exits 0 with `TLS_GET PASS` only
//! when the fetch returned a `200` with a body.

#![no_std]
#![no_main]

use pagh_std::error::Result;
use pagh_std::net::{Ipv4, TcpStream};
use pagh_std::prelude::*;
use pagh_std::tls::{self, TlsStream};
use pagh_std::{Error, ErrorKind};

/// The URL the example fetches when the caller names none.
const DEFAULT_URL: &str = "https://example.com/";

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
                    eprintln!("tls_get: --ip={value}: not an IPv4 literal");
                    return 2;
                }
            }
        } else if argument == "--manual" {
            manual = true;
        } else if argument.starts_with("--") {
            eprintln!("tls_get: unknown option {argument}");
            return 2;
        } else {
            positional.push(String::from(argument.as_str()));
        }
    }
    let url = match positional.len() {
        0 => String::from(DEFAULT_URL),
        1 => positional[0].clone(),
        _ => {
            eprintln!("usage: tls_get [url] [--ip=A.B.C.D] [--manual]");
            return 2;
        }
    };
    println!(
        "tls_get: url={url} pinned={pinned:?} mode={}",
        if manual { "manual" } else { "https_get" }
    );

    let outcome = if manual {
        manual_fetch(&url, pinned)
    } else {
        match pinned {
            Some(address) => tls::https_get_at(&url, address),
            None => tls::https_get(&url),
        }
    };
    let response = match outcome {
        Ok(response) => response,
        Err(error) => {
            // The kernel prints the gate that refused on the serial line
            // (`tls: verify FAILED cause=…`); the errno is what userland sees.
            match error.raw_os_error() {
                Some(errno) => println!("tls_get: FAIL {error} (errno {errno})"),
                None => println!("tls_get: FAIL {error}"),
            }
            println!("TLS_GET FAIL");
            return 1;
        }
    };

    println!(
        "tls_get: status {} body {} bytes",
        response.status(),
        response.body_len()
    );
    let text = core::str::from_utf8(response.body()).unwrap_or("<non-utf8>");
    let first = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    println!("tls_get: first body line: {first}");
    if response.status() != 200 {
        println!("TLS_GET FAIL: status");
        return 1;
    }
    if response.body_len() == 0 {
        println!("TLS_GET FAIL: empty body");
        return 1;
    }
    println!("TLS_GET PASS");
    0
}

/// The stream API end to end: connect, write, read one response, close.
///
/// This is the same work `tls::https_get` does, spelled out so the example
/// exercises the stream itself rather than only the helper.
fn manual_fetch(url: &str, pinned: Option<Ipv4>) -> Result<tls::HttpResponse> {
    // `https_get` parses the URL; for the manual path, reuse the same parser
    // through the error message the public API gives for a malformed one.
    let target = tls::url::Target::parse(url)
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error.message()))?;
    println!(
        "tls_get: host={} port={} path={}",
        target.host, target.port, target.path
    );

    let mut session = match pinned {
        Some(address) => {
            println!(
                "tls_get: pinning {} while keeping the name {}",
                address, target.host
            );
            let socket = TcpStream::connect(address, target.port)?;
            TlsStream::connect_stream(socket, &target.host)?
        }
        None => TlsStream::connect(&target.host_port())?,
    };
    session.write_all(&target.get_request())?;
    let response = session.read_http_response()?;
    // `close` is the graceful path: `close_notify`, then release. Dropping the
    // value instead would call `close(2)` without the alert.
    session.close()?;
    Ok(response)
}
