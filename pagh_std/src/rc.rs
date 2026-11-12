//! `Rc` and `Weak`: the single-threaded reference-counted pointer at the
//! `std::rc` path.
//!
//! The types are `alloc`'s, re-exported so `pagh_std` names them where `std`
//! does (`std::rc::Rc`). Like the rest of this module, the file is pure
//! `core` + `alloc`; the host gate compiles it directly.
//!
//! `Rc` is deliberately not atomic and therefore not `Send`/`Sync`: the same
//! rule as `std`. Use [`Arc`](crate::sync::Arc) when a value crosses a thread
//! boundary — the SDK has real threads.

pub use alloc::rc::{Rc, Weak};
