//! Panic and out-of-memory contract.
//!
//! # Why this module has no `#[panic_handler]`
//!
//! Rust allows exactly **one** `#[panic_handler]`, one
//! `#[global_allocator]` and one `#[alloc_error_handler]` in a crate graph.
//! `pagh_std` depends on `libpagh`, which already owns those three items (and
//! `_start`) because it is the native userland runtime. Declaring a second
//! handler here is a hard compile error (`duplicate lang item`), not a style
//! choice — and forging around it (vendoring libpagh, dropping the dependency,
//! or patching the rlib) would make the SDK *not* the layer over libpagh it
//! claims to be.
//!
//! The linked runtime already implements exactly the required contract:
//!
//! * a panic prints `program: panic at <file>:<line>:<column>` to fd 2 and
//!   exits with code **101**;
//! * allocation failure prints `program: out of memory (brk failed); requested
//!   N bytes at alignment A` to fd 2 and exits with code **102**.
//!
//! Both are verified in `docs/live-rust-sdk.txt` with the `panic` and `oom`
//! diagnostic probes. This module re-exports [`PanicInfo`] and offers
//! [`abort`] for programs that want to terminate deliberately without a panic.
//!
//! Programs must be built with `panic = "abort"` (the workspace profiles do
//! this); there is no unwinding and the kernel has no signal or DWARF backtrace
//! consumer.

pub use core::panic::PanicInfo;

/// Terminate with the conventional abort status after printing
/// `<program>: abort`.
///
/// This is not a panic: no location is recorded and the exit code is 134
/// (`128 + SIGABRT`), not 101.
pub fn abort() -> ! {
    crate::process::abort()
}
