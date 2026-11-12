//! `Arc` and `Weak`: the atomically reference-counted pointer behind
//! [`pagh_std::sync::Arc`](super::Arc).
//!
//! The types themselves are `alloc`'s, re-exported so the SDK names them where
//! `std` does (`std::sync::Arc`). This file is pure `core` + `alloc` — no
//! `libpagh`, no syscall — which is why the host gate compiles it directly and
//! can exercise the re-export under real host threads.
//!
//! The ABI does not change what `Arc` means here: its atomic operations are
//! ordinary RISC-V atomics, and the SDK's futex-backed primitives are safe to
//! place behind an `Arc` because they are `Send + Sync`.

pub use alloc::sync::{Arc, Weak};
