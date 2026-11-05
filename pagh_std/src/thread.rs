//! Native threads over `clone`/`futex` (kernel 0.13.0+).
//!
//! This is the `pagh_std` face of [`libpagh::thread`]: a `Builder`, a
//! `JoinHandle` and futex helpers for a language that has no `std::thread`.
//! Threads share the process address space, heap, mmap regions and file
//! descriptors; a `JoinHandle::join` futex-waits for the child's exit code.
//!
//! Caveat inherited from the ABI: the child starts at `entry(arg)` and never
//! returns through the syscall; the closure is run by a trampoline inside
//! `libpagh`, so this is safe to use with an owned `'static` closure.

pub use libpagh::thread::{
    current_id, exit, exit_group, futex_wait, futex_wake, yield_now, Builder, JoinHandle,
    DEFAULT_STACK_SIZE,
};
