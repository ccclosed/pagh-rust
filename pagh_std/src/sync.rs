//! A single-threaded `LazyLock`, plus the `core::cell` types under std names.
//!
//! pagh has no threads and the ABI has no atomics-backed synchronization
//! primitive that userland can wait on. `std::sync::Mutex`/`RwLock` would be
//! lies here, so this module deliberately does **not** provide them. What it
//! does provide is the interior mutability of `core::cell` and a one-time
//! initializer that is safe because there is exactly one thread.

pub use core::cell::{Cell, OnceCell, RefCell, UnsafeCell};

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
/// static TABLE: LazyLock<Vec<u8>> = LazyLock::new(|| vec![1, 2, 3]);
/// assert_eq!(TABLE.len(), 3);
/// ```
///
/// `LazyLock` is `Sync` when `T: Sync`/`F: Sync`; in this SDK that only matters
/// for placing it in a `static`, because no second thread exists to race with
/// the initializer.
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
