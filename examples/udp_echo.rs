//! `udp_echo` — a UDP echo client/server fixture over `pagh_std::net::UdpSocket`.
//!
//! Usage: `udp_echo <destination-ipv4> <destination-port> [local-port]`
//! (default local port 45680). It binds the local port, sends two datagrams to
//! the destination and requires them echoed back unchanged, then exits 0.
//!
//! The program exercises:
//!
//! 1. `UdpSocket::bind`, `local_addr` (the SDK's record of the bind argument —
//!    the ABI has no `getsockname`);
//! 2. `set_nonblocking(true)` + `recv_from` → `WouldBlock` on an empty queue,
//!    proving the single-poll shape;
//! 3. the blocking `recv_from` for the first datagram (the kernel polls its NIC
//!    for up to ~10 s per attempt and the SDK retries);
//! 4. `try_recv_from` in a deadline loop for the second, larger datagram, which
//!    also exercises `time::sleep_until`;
//! 5. a payload above the kernel's 1024-byte ceiling, which must fail before
//!    anything is sent (`EMSGSIZE`; `libpagh` has no entry for that errno, so
//!    the SDK reports `Uncategorized`/`Unknown error` — printed, not hidden).
//!
//! Run it in the guest against a host UDP echo server:
//!
//! ```text
//! run /mnt/udp_echo 10.0.2.2 <host-port> 45680
//! ```
//!
//! QEMU's user network maps the guest's `10.0.2.2` to the host's `127.0.0.1`.

#![no_std]
#![no_main]

use pagh_std::net::{Ipv4, SocketAddr, UdpSocket};
use pagh_std::prelude::*;
use pagh_std::time::{sleep_until, Duration, Instant};

const DEFAULT_LOCAL_PORT: u16 = 45680;
/// No datagram may take longer than this, so a missing host server fails the
/// run instead of hanging it.
const RECEIVE_DEADLINE: Duration = Duration::from_secs(20);
/// The kernel's ceiling: `sendto` of more than 1024 payload bytes is EMSGSIZE.
const KERNEL_DATAGRAM_MAX: usize = 1024;

/// Wait for one datagram until `deadline`, polling once every 10 ms tick.
fn recv_before(
    socket: &mut UdpSocket,
    buf: &mut [u8],
    deadline: Instant,
) -> io::Result<(usize, SocketAddr)> {
    loop {
        match socket.try_recv_from(buf) {
            Ok(received) => return Ok(received),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no datagram arrived before the deadline",
                    ));
                }
                // A short nap, not the whole deadline: the NIC is only polled
                // when a syscall asks it to, and `sleep_until` bounds the wait.
                let wake = core::cmp::min(deadline, now + Duration::from_millis(10));
                sleep_until(wake)?;
            }
            Err(error) => return Err(error),
        }
    }
}

/// One round trip: send `payload`, receive the echo, verify it and its source.
///
/// A `None` deadline selects the blocking `recv_from`; `Some(deadline)` uses the
/// single-poll shape in a deadline loop.
fn round_trip(
    socket: &mut UdpSocket,
    destination: SocketAddr,
    payload: &[u8],
    label: &str,
    deadline: Option<Instant>,
) -> io::Result<()> {
    let sent = socket.send_to(payload, destination)?;
    if sent != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "send_to returned a short datagram",
        ));
    }
    println!("udp_echo: {label}: sent {sent} bytes to {destination}, waiting for the echo");

    let mut buffer = [0u8; 2048];
    let (received, source) = match deadline {
        // The blocking shape: the kernel polls the NIC inside `recvfrom`.
        None => socket.recv_from(&mut buffer)?,
        // The single-poll shape inside a deadline loop.
        Some(deadline) => recv_before(socket, &mut buffer, deadline)?,
    };
    println!("udp_echo: {label}: recv {received} bytes from {source}");
    if source != destination {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the echo came from an unexpected address",
        ));
    }
    if received != payload.len() || &buffer[..received] != payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the echoed datagram did not round-trip unchanged",
        ));
    }
    println!("udp_echo: {label}: verified ({received} bytes round-tripped)");
    Ok(())
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        eprintln!("usage: udp_echo <destination-ipv4> <destination-port> [local-port]");
        return 2;
    }
    let destination_ip = match Ipv4::parse(&args[1]) {
        Some(ip) => ip,
        None => {
            eprintln!("udp_echo: '{}' is not an IPv4 literal", args[1]);
            return 2;
        }
    };
    let destination_port = match args[2].parse::<u16>() {
        Ok(port) => port,
        Err(_) => {
            eprintln!("udp_echo: invalid destination port '{}'", args[2]);
            return 2;
        }
    };
    let local_port = match args.get(3) {
        None => DEFAULT_LOCAL_PORT,
        Some(text) => match text.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                eprintln!("udp_echo: invalid local port '{text}'");
                return 2;
            }
        },
    };
    let destination = SocketAddr::new(destination_ip, destination_port);

    let mut failures = 0u32;

    let mut socket = match UdpSocket::bind(local_port) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("udp_echo: bind 0.0.0.0:{local_port}: {error}");
            return 1;
        }
    };
    println!("udp_echo: bind 0.0.0.0:{local_port}");
    match socket.local_addr() {
        Ok(address) => println!("udp_echo: local_addr {address}"),
        Err(error) => {
            println!("udp_echo: local_addr: {error}");
            failures += 1;
        }
    }

    // ── the single-poll shape before anything is sent ──────────────────────
    if let Err(error) = socket.set_nonblocking(true) {
        println!("udp_echo: set_nonblocking(true) FAIL: {error}");
        failures += 1;
    }
    let mut probe = [0u8; 64];
    match socket.recv_from(&mut probe) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            println!("udp_echo: set_nonblocking(true); recv_from -> WouldBlock (queue empty)");
        }
        Ok((read, source)) => {
            println!("udp_echo: unexpected datagram ({read} bytes from {source}) on an idle port");
            failures += 1;
        }
        Err(error) => {
            println!("udp_echo: recv_from on an idle port FAIL: {error}");
            failures += 1;
        }
    }
    if socket.set_nonblocking(false).is_err() || socket.is_nonblocking() {
        println!("udp_echo: set_nonblocking(false) FAIL");
        failures += 1;
    } else {
        println!("udp_echo: set_nonblocking(false) restored the blocking mode");
    }

    // ── two round trips: one blocking receive, one polled ──────────────────
    if let Err(error) = round_trip(
        &mut socket,
        destination,
        b"pagh udp echo 1\n",
        "datagram 1",
        None,
    ) {
        println!("udp_echo: datagram 1 FAIL: {error}");
        failures += 1;
    }
    let mut pattern = [0u8; 300];
    for (index, byte) in pattern.iter_mut().enumerate() {
        *byte = b'a' + (index % 26) as u8;
    }
    if let Err(error) = round_trip(
        &mut socket,
        destination,
        &pattern,
        "datagram 2",
        Some(Instant::now() + RECEIVE_DEADLINE),
    ) {
        println!("udp_echo: datagram 2 FAIL: {error}");
        failures += 1;
    }

    // ── the kernel's datagram ceiling ──────────────────────────────────────
    let oversized = [0x5au8; KERNEL_DATAGRAM_MAX + 1];
    match socket.send_to(&oversized, destination) {
        Err(error) => {
            println!(
                "udp_echo: oversized send ({KERNEL_DATAGRAM_MAX} + 1 bytes) rejected: {error}"
            );
        }
        Ok(sent) => {
            println!("udp_echo: oversized send was accepted ({sent} bytes) — unexpected");
            failures += 1;
        }
    }

    // ── the address type round-trips through Display and FromStr ───────────
    match "10.0.2.2:9".parse::<SocketAddr>() {
        Ok(address) if address == SocketAddr::new(Ipv4::new([10, 0, 2, 2]), 9) => {
            println!("udp_echo: SocketAddr parse/display round-trip ok");
        }
        other => {
            println!("udp_echo: SocketAddr round-trip FAIL: {other:?}");
            failures += 1;
        }
    }

    if failures == 0 {
        println!("UDP_ECHO PASS");
        0
    } else {
        println!("UDP_ECHO FAIL: {failures} check(s) failed");
        1
    }
}
