//! `socket_opts` — socket options, non-blocking mode and `try_clone`, live.
//!
//! Usage: `socket_opts [--port=N] [--peer=HOST:PORT]`
//!
//! Defaults: listener port 45681 (the second-bind check needs a port of its
//! own) and peer `10.0.2.2:45683` (a host echo/black-hole server the live
//! harness starts; the guest reaches the host's loopback as `10.0.2.2`).
//!
//! The ABI's `setsockopt` is real but inert — the kernel validates the option
//! and ignores the value — so every check here separates the *call* from the
//! *behaviour*:
//!
//! 1. `getsockopt(SO_TYPE)` round-trips for a stream and a datagram socket;
//! 2. `set_reuseaddr(true)` is accepted by the kernel, and a second `bind` of
//!    the same port still fails: the option is answered, not honoured, and the
//!    transcript shows both halves;
//! 3. `set_nonblocking(true)` turns a read with nothing queued into an
//!    immediate `WouldBlock` (measured, so "immediate" is not a claim);
//! 4. `set_read_timeout(500 ms)` on a silent connection returns `WouldBlock`
//!    after the deadline — the SDK's own enforcement, because the kernel's
//!    `SO_RCVTIMEO` reads back as zero and its `recvfrom` waits ten seconds;
//! 5. `try_clone()` shares one descriptor (the ABI refuses `dup` on a socket):
//!    bytes written on the original come back through the clone, and dropping
//!    the clone leaves the original usable;
//! 6. the same deadlines on a `UdpSocket`, where the ABI's blocking receive is
//!    a ten-second poll that a retry budget cannot cut short.
//!
//! Prints `SOCKET_OPTS PASS` and exits 0, or `SOCKET_OPTS FAIL: …`.

#![no_std]
#![no_main]

use pagh_std::net::{SocketAddr, SocketType, TcpListener, TcpStream, UdpSocket};
use pagh_std::prelude::*;
use pagh_std::time::{Duration, Instant};

const DEFAULT_PORT: u16 = 45681;
const DEFAULT_PEER: &str = "10.0.2.2:45683";

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let args: Vec<String> = env::args().collect();
    let mut port = DEFAULT_PORT;
    let mut peer = String::from(DEFAULT_PEER);
    for argument in args.iter().skip(1) {
        if let Some(value) = argument.strip_prefix("--port=") {
            match value.parse::<u16>() {
                Ok(parsed) => port = parsed,
                Err(_) => {
                    eprintln!("socket_opts: --port={value}: expected 1..=65535");
                    return 2;
                }
            }
        } else if let Some(value) = argument.strip_prefix("--peer=") {
            peer = String::from(value);
        } else {
            eprintln!("socket_opts: unknown argument {argument}");
            return 2;
        }
    }
    let peer_address: SocketAddr = match peer.parse() {
        Ok(address) => address,
        Err(_) => {
            eprintln!("socket_opts: --peer={peer}: expected IPv4:port");
            return 2;
        }
    };

    let mut failures = 0u32;

    // 1. SO_TYPE on a listener.
    let mut listener = match TcpListener::bind(port) {
        Ok(listener) => listener,
        Err(error) => {
            println!("SOCKET_OPTS FAIL: bind({port}): {error}");
            return 1;
        }
    };
    match listener.socket_type() {
        Ok(SocketType::Stream) => {
            println!("socket_opts: getsockopt(SO_TYPE) on a listener -> Stream")
        }
        other => {
            failures += 1;
            println!("socket_opts: SO_TYPE FAIL: {other:?}");
        }
    }

    // 2. SO_REUSEADDR: accepted, and provably not honoured on this kernel.
    match listener.set_reuseaddr(true) {
        Ok(()) => println!("socket_opts: setsockopt(SO_REUSEADDR, 1) -> accepted by the ABI"),
        Err(error) => {
            failures += 1;
            println!("socket_opts: setsockopt(SO_REUSEADDR) FAIL: {error}");
        }
    }
    match TcpListener::bind(port) {
        Ok(_second) => {
            failures += 1;
            println!(
                "socket_opts: second bind({port}) SUCCEEDED - SO_REUSEADDR is not a no-op here, \
                      the transcript must be updated"
            );
        }
        Err(error) => println!(
            "socket_opts: second bind({port}) still refused ({error:?}): the option is accepted, \
             not honoured"
        ),
    }

    // 3/4/5. The stream side.
    let mut stream = match TcpStream::connect(peer_address.ip(), peer_address.port()) {
        Ok(stream) => stream,
        Err(error) => {
            println!("SOCKET_OPTS FAIL: connect({peer_address}): {error}");
            return 1;
        }
    };
    match stream.socket_type() {
        Ok(SocketType::Stream) => {
            println!("socket_opts: getsockopt(SO_TYPE) on a TcpStream -> Stream")
        }
        other => {
            failures += 1;
            println!("socket_opts: stream SO_TYPE FAIL: {other:?}");
        }
    }

    if let Err(error) = stream.set_nonblocking(true) {
        failures += 1;
        println!("socket_opts: set_nonblocking(true) FAIL: {error}");
    }
    let started = Instant::now();
    let mut buffer = [0u8; 64];
    match stream.read(&mut buffer) {
        Err(error) if error.kind() == pagh_std::ErrorKind::WouldBlock => {
            let elapsed = started.elapsed().as_millis();
            if elapsed > 50 {
                failures += 1;
                println!("socket_opts: non-blocking read FAIL: took {elapsed} ms");
            } else {
                println!("socket_opts: non-blocking read on an idle socket -> WouldBlock in {elapsed} ms");
            }
        }
        other => {
            failures += 1;
            println!("socket_opts: non-blocking read FAIL: {other:?}");
        }
    }
    stream.set_nonblocking(false).unwrap_or_else(|error| {
        failures += 1;
        println!("socket_opts: set_nonblocking(false) FAIL: {error}");
    });

    if let Err(error) = stream.set_read_timeout(Some(Duration::from_millis(500))) {
        failures += 1;
        println!("socket_opts: set_read_timeout FAIL: {error}");
    }
    let started = Instant::now();
    match stream.read(&mut buffer) {
        Err(error) if error.kind() == pagh_std::ErrorKind::WouldBlock => {
            let elapsed = started.elapsed().as_millis();
            if !(400..3000).contains(&elapsed) {
                failures += 1;
                println!("socket_opts: 500 ms deadline FAIL: returned after {elapsed} ms");
            } else {
                println!("socket_opts: 500 ms read deadline on a silent peer -> WouldBlock after {elapsed} ms");
            }
        }
        other => {
            failures += 1;
            println!("socket_opts: read deadline FAIL: {other:?}");
        }
    }
    println!(
        "socket_opts: read_timeout() reports {:?}",
        stream.read_timeout()
    );

    // 5. try_clone shares the descriptor; the echo server proves both handles
    //    address the same connection.
    match stream.try_clone() {
        Ok(mut clone) => {
            if clone.fd() != stream.fd() {
                failures += 1;
                println!(
                    "socket_opts: try_clone FAIL: fd {} != {}",
                    clone.fd(),
                    stream.fd()
                );
            } else {
                println!(
                    "socket_opts: try_clone -> shared fd {} (the ABI refuses dup on a socket)",
                    clone.fd()
                );
            }
            let payload = b"socket_opts echo probe\n";
            if let Err(error) = stream.write_all(payload) {
                failures += 1;
                println!("socket_opts: write on the original FAIL: {error}");
            }
            let _ = clone.set_read_timeout(Some(Duration::from_secs(5)));
            let mut echoed = [0u8; 64];
            let mut filled = 0usize;
            while filled < payload.len() {
                match clone.read(&mut echoed[filled..]) {
                    Ok(0) => break,
                    Ok(read) => filled += read,
                    Err(error) => {
                        failures += 1;
                        println!("socket_opts: read on the clone FAIL: {error}");
                        break;
                    }
                }
            }
            if &echoed[..filled] != payload {
                failures += 1;
                println!(
                    "socket_opts: echo FAIL: sent {:?}, received {:?}",
                    core::str::from_utf8(payload).unwrap_or("?"),
                    core::str::from_utf8(&echoed[..filled]).unwrap_or("?")
                );
            } else {
                println!("socket_opts: wrote on the original, read the echo on the clone ({filled} bytes)");
            }
            drop(clone);
            // The original must still work after the clone is gone: shared
            // ownership, not a second descriptor that closes the connection.
            if let Err(error) = stream.write_all(b"after the clone is dropped\n") {
                failures += 1;
                println!("socket_opts: original after drop FAIL: {error}");
            } else {
                println!("socket_opts: original usable after the clone dropped");
            }
        }
        Err(error) => {
            failures += 1;
            println!("socket_opts: try_clone FAIL: {error}");
        }
    }

    // 6. UDP deadlines and SO_TYPE.
    match UdpSocket::bind(0) {
        Ok(mut datagram) => {
            match datagram.socket_type() {
                Ok(SocketType::Datagram) => {
                    println!("socket_opts: getsockopt(SO_TYPE) on a UdpSocket -> Datagram")
                }
                other => {
                    failures += 1;
                    println!("socket_opts: UDP SO_TYPE FAIL: {other:?}");
                }
            }
            if let Err(error) = datagram.set_read_timeout(Some(Duration::from_millis(300))) {
                failures += 1;
                println!("socket_opts: UDP set_read_timeout FAIL: {error}");
            }
            let started = Instant::now();
            match datagram.recv_from(&mut buffer) {
                Err(error) if error.kind() == pagh_std::ErrorKind::WouldBlock => {
                    let elapsed = started.elapsed().as_millis();
                    if !(250..3000).contains(&elapsed) {
                        failures += 1;
                        println!(
                            "socket_opts: UDP 300 ms deadline FAIL: returned after {elapsed} ms"
                        );
                    } else {
                        println!("socket_opts: UDP 300 ms receive deadline -> WouldBlock after {elapsed} ms");
                    }
                }
                other => {
                    failures += 1;
                    println!("socket_opts: UDP deadline FAIL: {other:?}");
                }
            }
        }
        Err(error) => {
            failures += 1;
            println!("socket_opts: UdpSocket::bind(0) FAIL: {error}");
        }
    }

    // The listener is still live and idle: a single-poll accept says so.
    match listener.accept_nonblocking() {
        Err(error) if error.kind() == pagh_std::ErrorKind::WouldBlock => {
            println!("socket_opts: accept_nonblocking on an idle listener -> WouldBlock");
        }
        other => {
            failures += 1;
            println!("socket_opts: idle accept FAIL: {other:?}");
        }
    }

    if failures == 0 {
        println!("SOCKET_OPTS PASS");
        0
    } else {
        println!("SOCKET_OPTS FAIL: {failures} check(s) failed");
        1
    }
}
