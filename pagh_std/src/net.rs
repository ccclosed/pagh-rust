//! A connected IPv4 TCP client (kernel 0.12.0+).
//!
//! The ABI has one active connection: `AF_INET` + `SOCK_STREAM`, `connect` to
//! an IPv4 literal, `read`/`write`, `shutdown`. There is no listener, UDP,
//! IPv6, DNS or TLS; `connect` returns a typed error for those cases rather
//! than pretending.

pub use libpagh::net::{Ipv4, TcpStream};
