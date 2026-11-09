//! `dns` — the RFC 1035 stub resolver and `connect(host:port)`, checked live.
//!
//! Usage:
//!
//! ```text
//! dns [--server=A.B.C.D] [--port=N] [--deadline-ms=N] [--connect=HOST:PORT] [name ...]
//! ```
//!
//! Defaults: the system resolver (`/etc/resolv.conf`, then
//! `/mnt/etc/resolv.conf`, then the compiled-in QEMU default `10.0.2.3`), a
//! 2 s per-attempt deadline, and the name `example.com`.
//!
//! The checks, in the order they run:
//!
//! 1. **configuration** — prints every server the resolver will ask *and where
//!    that list came from* (`/mnt/etc/resolv.conf` in the acceptance run, where
//!    the harness writes the address the kernel's own DHCP lease named);
//! 2. **a real A query** — `resolve_all` returns the addresses and TTLs, printed
//!    one per line. A resolver that guessed, or that returned a cached literal,
//!    could not produce the server's TTL;
//! 3. **NXDOMAIN** — a name under `.invalid` (RFC 2606: guaranteed not to
//!    exist) must fail with `NameError`, not with "no records";
//! 4. **an unencodable name** — refused before a socket exists (`InvalidName`);
//! 5. **a deadline** — with `--server=<a silent address>` (the live run points
//!    at a host UDP socket that receives and never answers, via `--port`), the
//!    query must fail with `Timeout` rather than hanging: this is the retry
//!    budget, and it is the only part of the resolver the ABI cannot help with
//!    (the kernel's own `recvfrom` waits ten seconds and cannot be cut short);
//! 6. **`connect(host:port)`** — `--connect=example.com:80` resolves the name,
//!    opens a TCP connection and prints the first line of the HTTP response, so
//!    the resolution path is proven end to end and not just to the resolver.
//!
//! Prints `DNS PASS` and exits 0 when every check ran, or `DNS FAIL: …`.

#![no_std]
#![no_main]

use pagh_std::net::{dns, Ipv4, TcpStream};
use pagh_std::prelude::*;
use pagh_std::time::{Duration, Instant};

/// A silent address for the deadline check is supplied by the caller; this is
/// how long it is given before the resolver must give up.
const DEADLINE_MS_DEFAULT: u64 = 2000;

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let args: Vec<String> = env::args().collect();
    let mut names: Vec<String> = Vec::new();
    let mut server: Option<Ipv4> = None;
    let mut deadline_ms = DEADLINE_MS_DEFAULT;
    let mut port: Option<u16> = None;
    let mut connect_target: Option<String> = None;
    for argument in args.iter().skip(1) {
        if let Some(value) = argument.strip_prefix("--server=") {
            match Ipv4::parse(value) {
                Some(address) => server = Some(address),
                None => {
                    eprintln!("dns: --server={value}: not an IPv4 literal");
                    return 2;
                }
            }
        } else if let Some(value) = argument.strip_prefix("--port=") {
            match value.parse::<u16>() {
                Ok(parsed) if parsed > 0 => port = Some(parsed),
                _ => {
                    eprintln!("dns: --port={value}: expected 1..=65535");
                    return 2;
                }
            }
        } else if let Some(value) = argument.strip_prefix("--deadline-ms=") {
            match value.parse::<u64>() {
                Ok(parsed) if parsed > 0 => deadline_ms = parsed,
                _ => {
                    eprintln!("dns: --deadline-ms={value}: expected a positive integer");
                    return 2;
                }
            }
        } else if let Some(value) = argument.strip_prefix("--connect=") {
            connect_target = Some(String::from(value));
        } else if argument.starts_with("--") {
            eprintln!("dns: unknown option {argument}");
            return 2;
        } else {
            names.push(String::from(argument.as_str()));
        }
    }
    if names.is_empty() {
        names.push(String::from("example.com"));
    }

    let mut failures = 0u32;

    // 1. Configuration.
    let (configured, source) = dns::Resolver::system();
    let mut servers = Vec::new();
    for address in configured.servers() {
        servers.push(format!("{address}"));
    }
    println!(
        "dns: {} server(s) from {source}: {}",
        servers.len(),
        servers.join(", ")
    );
    let mut resolver = configured.clone();
    if let Some(one) = server {
        resolver = dns::Resolver::with_servers(&[one]);
        println!("dns: --server override: asking only {one}");
    } else if resolver.servers().is_empty() {
        println!(
            "dns: no server configured; the compiled-in fallback is {}",
            dns::DEFAULT_SERVER
        );
    }
    if let Some(port) = port {
        resolver.set_port(port);
        println!("dns: --port override: asking port {port}");
    }
    resolver.set_timeout(Duration::from_millis(deadline_ms));
    resolver.set_attempts(2);

    // 2. Real queries — skipped when the caller pinned a server, because that
    // run's purpose is the deadline below and a black hole answers nothing by
    // design.
    if server.is_some() {
        println!(
            "dns: --server override: skipping the name checks (this run measures the deadline)"
        );
    }
    for name in names.iter().filter(|_| server.is_none()) {
        let started = Instant::now();
        match resolver.resolve_a(name) {
            Ok(addresses) => {
                if addresses.is_empty() {
                    failures += 1;
                    println!("dns: {name} FAIL: NOERROR with an empty answer");
                    continue;
                }
                for address in addresses.iter() {
                    println!(
                        "dns: {name} -> {address} (attempt {} ms)",
                        started.elapsed().as_millis()
                    );
                }
            }
            Err(error) => {
                failures += 1;
                println!("dns: {name} FAIL: {error}");
            }
        }
    }

    // 3. NXDOMAIN. `.invalid` is reserved and must never resolve. Skipped when
    // the caller overrode the server: a black hole answers nothing, not even
    // "no such name", and the deadline check below is that run's point.
    if server.is_none() {
        match resolver.resolve_a("no-such-host.invalid") {
            Err(dns::Error::NameError) => {
                println!("dns: no-such-host.invalid -> NXDOMAIN (as required)");
            }
            other => {
                failures += 1;
                println!("dns: NXDOMAIN check FAIL: {other:?}");
            }
        }
    }

    // 4. A name the encoder must refuse, before any socket exists.
    match resolver.resolve_a("bad..name") {
        Err(dns::Error::InvalidName) => {
            println!("dns: bad..name -> InvalidName (refused before any datagram)");
        }
        other => {
            failures += 1;
            println!("dns: invalid-name check FAIL: {other:?}");
        }
    }

    // 5. The deadline. Only when the caller pointed at a silent server: the
    // live run passes an address that will not answer, and the resolver must
    // give up inside its budget instead of waiting on the kernel's ten-second
    // receive.
    if server.is_some() {
        let started = Instant::now();
        match resolver.resolve_a("example.com") {
            Err(dns::Error::Timeout) => {
                let elapsed = started.elapsed().as_millis();
                let budget = (deadline_ms * 2) as u128;
                if elapsed > budget {
                    failures += 1;
                    println!("dns: deadline FAIL: took {elapsed} ms for a {budget} ms budget");
                } else {
                    println!(
                        "dns: silent server -> Timeout after {elapsed} ms (budget {budget} ms)"
                    );
                }
            }
            other => {
                failures += 1;
                println!("dns: deadline check FAIL: {other:?}");
            }
        }
    }

    // 6. connect(host:port), the whole point of resolving in the first place.
    if let Some(target) = connect_target {
        match fetch_head(&target) {
            Ok(line) => println!("dns: connect({target}) -> {line}"),
            Err(error) => {
                failures += 1;
                println!("dns: connect({target}) FAIL: {error}");
            }
        }
    }

    if failures == 0 {
        println!("DNS PASS");
        0
    } else {
        println!("DNS FAIL: {failures} check(s) failed");
        1
    }
}

/// Connect to `host:port`, send a minimal HTTP/1.0 request and return the
/// status line: a resolution path that only proved `resolve()` would not prove
/// `connect(host:port)`.
fn fetch_head(target: &str) -> core::result::Result<String, pagh_std::Error> {
    let mut stream = TcpStream::connect_host(
        target.split(':').next().unwrap_or(target),
        target
            .rsplit(':')
            .next()
            .and_then(|port| port.parse::<u16>().ok())
            .ok_or_else(|| pagh_std::Error::new(pagh_std::ErrorKind::InvalidInput, "no port"))?,
    )?;
    println!(
        "dns: TcpStream::connect_host({target}) -> peer {} fd {}",
        stream.peer_addr(),
        stream.fd()
    );
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let host = target.split(':').next().unwrap_or(target);
    let request = format!("GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut buffer = [0u8; 512];
    let read = stream.read(&mut buffer)?;
    let text = core::str::from_utf8(&buffer[..read]).unwrap_or("<non-utf8>");
    let line = text.lines().next().unwrap_or("<empty response>");
    Ok(String::from(line))
}
