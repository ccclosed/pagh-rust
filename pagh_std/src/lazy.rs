//! A single-threaded `LazyLock` over `core::cell::OnceCell`.
//!
//! This module is pure `core`; it is the part of `pagh_std::sync` that the
//! host checker compiles directly (the futex-backed primitives in `sync.rs`
//! depend on `libpagh` and the RISC-V target). `pagh_std::sync` re-exports
//! [`LazyLock`], so programs should keep using that path.
//!
//! The initializer is an `Fn` (not `FnOnce`), which keeps the implementation
//! entirely safe: no `UnsafeCell`, no `Option` take, no reentrancy panic. A
//! closure that consumes its environment by value is `FnOnce`, so it must be
//! rewritten to clone or move the captured value inside the closure, or the
//! caller can use a `OnceCell` directly.

use core::cell::OnceCell;
use core::ops::Deref;

/// A value initialized on first use.
///
/// This is the single-threaded shape of `std::sync::LazyLock`. The initializer
/// is an `Fn` (not `FnOnce`), which keeps the implementation entirely safe: no
/// `UnsafeCell`, no `Option` take, no reentrancy panic. A closure that consumes
/// its environment by value is `FnOnce`, so it must be rewritten to clone or
/// move the captured value inside the closure, or the caller can use a
/// `OnceCell` directly.
///
/// # Example
///
/// ```ignore
/// let table = LazyLock::new(|| vec![1u8, 2, 3]);
/// assert_eq!(table.len(), 3);
/// assert!(table.get().is_some());
/// ```
///
/// # Deviation from std
///
/// `std::sync::LazyLock` is thread-safe and can be placed in a `static`. This
/// one is **single-threaded**: its storage is a `core::cell::OnceCell`, so the
/// type is not `Sync` and cannot be put in a `static` or shared between the
/// SDK's native threads. The safety argument of the whole module depends on
/// that: `OnceCell::get_or_init` mutates through `&self`. When a lazily built
/// value has to be reachable from several threads, use a `static
/// OnceLock` and its `get_or_init`, or wrap a `LazyLock` in the futex-backed
/// [`Mutex`](crate::sync::Mutex).
pub struct LazyLock<T, F = fn() -> T> {
    cell: OnceCell<T>,
    init: F,
}

impl<T, F> LazyLock<T, F> {
    /// Create a lazily initialized value.
    pub const fn new(init: F) -> LazyLock<T, F> {
        LazyLock {
            cell: OnceCell::new(),
            init,
        }
    }

    /// The already-initialized value, if initialization has happened.
    pub fn get(&self) -> Option<&T> {
        self.cell.get()
    }

    /// Consume the `LazyLock` and return the initialized value, if any.
    ///
    /// This does not run the initializer.
    pub fn into_inner(self) -> Option<T> {
        self.cell.into_inner()
    }
}

impl<T, F: Fn() -> T> LazyLock<T, F> {
    /// Force initialization and return a reference to the value.
    pub fn force(this: &LazyLock<T, F>) -> &T {
        this.cell.get_or_init(|| (this.init)())
    }
}

impl<T, F: Fn() -> T> Deref for LazyLock<T, F> {
    type Target = T;

    fn deref(&self) -> &T {
        LazyLock::force(self)
    }
}

impl<T: core::fmt::Debug, F: Fn() -> T> core::fmt::Debug for LazyLock<T, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&**self, f)
    }
}

impl<T: core::fmt::Display, F: Fn() -> T> core::fmt::Display for LazyLock<T, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&**self, f)
    }
}

impl<T: Default> Default for LazyLock<T> {
    /// A `LazyLock` that initializes to `T::default()`, like `std`'s.
    fn default() -> LazyLock<T> {
        LazyLock::new(T::default)
    }
}
