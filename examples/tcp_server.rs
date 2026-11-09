//! `tcp_server` — a blocking TCP echo server over `pagh_std::net::TcpListener`.
//!
//! Usage: `tcp_server [port] [connections]` (defaults: port 45679, two
//! connections, then exit 0 so a scripted run has a deterministic end).
//!
//! The program exercises the whole listener API:
//!
//! 1. `TcpListener::bind` + `local_addr` (the ABI has no `getsockname`, so the
//!    SDK reports the address the caller asked for);
//! 2. `accept_nonblocking` before any client is queued — the expected answer is
//!    `WouldBlock`, which proves the call is a single poll and not a wait;
//! 3. `accept`, which blocks until a host client connects through QEMU's
//!    `--hostfwd` (or any peer on the user network);
//! 4. echo every byte back until the peer closes, then report the counts and
//!    `peer_addr`;
//! 5. accept the next connection, so a live check can prove the accept queue
//!    releases connections one at a time.
//!
//! Run it in the guest with an ext2 image that holds this ELF, e.g.
//! `run /mnt/tcp_server 45679 2`, and connect from the host through
//! `tools/run.py --net --hostfwd <host-port>:45679`.

#![no_std]
#![no_main]

use pagh_std::net::{Ipv4, SocketAddr, TcpListener, TcpStream};
use pagh_std::prelude::*;
use pagh_std::time::{Duration, Instant};

const DEFAULT_PORT: u16 = 45679;
const DEFAULT_CONNECTIONS: u32 = 2;
/// How long a single echo may take before the server gives up, so a broken
/// client cannot hang a scripted run forever.
const ECHO_DEADLINE: Duration = Duration::from_secs(30);

/// Echo one connection until the peer closes; returns the byte count.
fn echo(mut stream: TcpStream, index: u32) -> io::Result<usize> {
    println!(
        "tcp_server: connection {index}: peer_addr {}",
        stream.peer_addr()
    );
    let deadline = Instant::now() + ECHO_DEADLINE;
    let mut buffer = [0u8; 1024];
    let mut total = 0usize;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "echo deadline elapsed",
            ));
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                total += read;
                stream.write_all(&buffer[..read])?;
            }
            Err(error) => return Err(error),
        }
    }
    println!("tcp_server: connection {index}: recv {total} bytes");
    println!("tcp_server: connection {index}: echo {total} bytes");
    println!("tcp_server: connection {index}: peer closed (EOF)");
    Ok(total)
}

/// Accept one connection and echo it, reporting what happened.
///
/// `index` counts connections from 1. Returns the byte count, or the error
/// text for the caller to print and count as a failure.
fn serve_one(listener: &mut TcpListener, index: u32) -> core::result::Result<usize, String> {
    match listener.accept() {
        Ok((stream, peer)) => {
            println!("tcp_server: accept {index} from {peer}");
            echo(stream, index).map_err(|error| format!("connection {index}: echo: {error}"))
        }
        Err(error) => Err(format!("accept {index}: {error}")),
    }
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let args: Vec<String> = env::args().collect();
    let port = match args.get(1) {
        None => DEFAULT_PORT,
        Some(text) => match text.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                eprintln!("tcp_server: invalid port '{text}'");
                eprintln!("usage: tcp_server [port] [connections]");
                return 2;
            }
        },
    };
    let connections = match args.get(2) {
        None => DEFAULT_CONNECTIONS,
        Some(text) => match text.parse::<u32>() {
            Ok(count) if count > 0 => count,
            _ => {
                eprintln!("tcp_server: invalid connection count '{text}'");
                eprintln!("usage: tcp_server [port] [connections]");
                return 2;
            }
        },
    };
    if args.len() > 3 {
        eprintln!("usage: tcp_server [port] [connections]");
        return 2;
    }

    let mut failures = 0u32;

    let mut listener = match TcpListener::bind(port) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("tcp_server: bind 0.0.0.0:{port}: {error}");
            return 1;
        }
    };
    println!("tcp_server: bind 0.0.0.0:{port} backlog 4");
    match listener.local_addr() {
        Ok(address) => println!("tcp_server: local_addr {address}"),
        Err(error) => {
            println!("tcp_server: local_addr: {error}");
            failures += 1;
        }
    }
    println!("tcp_server: listening");

    // ── the non-blocking probe ─────────────────────────────────────────────
    // With no client connected yet this must be a single poll and answer
    // WouldBlock; if a client is already queued (a hostfwd client raced the
    // boot), the connection is served immediately and still counted.
    let mut served = 0u32;
    match listener.accept_nonblocking() {
        Ok((stream, peer)) => {
            println!("tcp_server: accept_nonblocking returned a queued connection from {peer}");
            served += 1;
            match echo(stream, served) {
                Ok(_) => {}
                Err(error) => {
                    println!("tcp_server: connection {served} FAIL: {error}");
                    failures += 1;
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            println!("tcp_server: accept_nonblocking -> WouldBlock (nothing queued yet)");
        }
        Err(error) => {
            println!("tcp_server: accept_nonblocking FAIL: {error}");
            failures += 1;
        }
    }

    // ── blocking accepts ───────────────────────────────────────────────────
    while served < connections {
        let index = served + 1;
        match serve_one(&mut listener, index) {
            Ok(_) => served += 1,
            Err(message) => {
                println!("tcp_server: FAIL: {message}");
                failures += 1;
                break;
            }
        }
    }

    // ── the kernel has one listener reservation: release it, then check that
    //    an ephemeral bind reports its un-knowable port as a typed
    //    Unsupported error rather than inventing a number ────────────────────
    drop(listener);
    match TcpListener::bind(0) {
        Ok(ephemeral) => match ephemeral.local_addr() {
            Err(error) if error.is_unsupported() => {
                println!("tcp_server: ephemeral bind: local_addr -> {error}");
            }
            Ok(address) => {
                println!("tcp_server: ephemeral bind reported {address} (unexpected)");
                failures += 1;
            }
            Err(error) => {
                println!("tcp_server: ephemeral local_addr FAIL: {error}");
                failures += 1;
            }
        },
        Err(error) => {
            println!("tcp_server: ephemeral bind FAIL: {error}");
            failures += 1;
        }
    }

    // A socket address round-trips through Display and FromStr.
    let parsed: Option<SocketAddr> = "10.0.2.2:1234".parse().ok();
    if parsed == Some(SocketAddr::new(Ipv4::new([10, 0, 2, 2]), 1234)) {
        println!("tcp_server: SocketAddr parse/display round-trip ok");
    } else {
        println!("tcp_server: SocketAddr round-trip FAIL: {parsed:?}");
        failures += 1;
    }

    if failures == 0 && served == connections {
        println!("TCP_SERVER PASS ({served} connection(s) echoed)");
        0
    } else {
        println!("TCP_SERVER FAIL: {failures} check(s) failed, {served}/{connections} served");
        1
    }
}
