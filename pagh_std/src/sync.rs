//! A single-threaded `LazyLock`, plus the `core::cell` types under std names.
//!
//! Since kernel 0.13 the ABI has native threads and futexes, so this module also
//! provides real [`Mutex`] and [`RwLock`] primitives (at the bottom of the
//! file); the legacy single-threaded `LazyLock`/`Cell` types stay for programs
//! that do not spawn threads.

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

// ─── futex-backed synchronization (kernel 0.13+) ────────────────────────────
//
// The SDK targets a kernel that has native threads and futexes, so `Mutex` and
// `RwLock` are real rather than the std-shaped lies the first version shipped.
// They are process-private (the ABI's private futex flag), non-poisoning and
// not reentrant, matching the C library's pthread primitives.

use core::ops::DerefMut;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::thread::{futex_wait, futex_wake, yield_now};

/// A futex-backed mutual exclusion lock.
pub struct Mutex<T: ?Sized> {
    state: AtomicU32,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    /// Create a new unlocked mutex.
    pub const fn new(value: T) -> Mutex<T> {
        Mutex {
            state: AtomicU32::new(0),
            data: UnsafeCell::new(value),
        }
    }

    /// Consume the mutex and return the value.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Acquire the lock, sleeping on the futex word when contended.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        loop {
            if self
                .state
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            let _ = futex_wait(&self.state, 1, None);
        }
        MutexGuard { mutex: self }
    }

    /// Try to acquire without blocking.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(MutexGuard { mutex: self })
        } else {
            None
        }
    }

    /// Access the value without locking (single-threaded escape hatch).
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

/// RAII guard for [`Mutex`].
pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the lock is held for the guard's lifetime, so no other
        // thread can hold a `&mut` to the value.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above; `&mut self` means this guard is the only guard.
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.state.store(0, Ordering::Release);
        let _ = futex_wake(&self.mutex.state, u32::MAX);
    }
}

/// A futex-backed readers/writer lock (writer-preferring on contention).
pub struct RwLock<T: ?Sized> {
    /// Bit 0: writer held; bits 1..: reader count (increments of 2).
    state: AtomicU32,
    data: UnsafeCell<T>,
}

unsafe impl<T: ?Sized + Send> Sync for RwLock<T> {}
unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}

impl<T> RwLock<T> {
    /// Create a new unlocked lock.
    pub const fn new(value: T) -> RwLock<T> {
        RwLock {
            state: AtomicU32::new(0),
            data: UnsafeCell::new(value),
        }
    }

    /// Consume the lock and return the value.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> RwLock<T> {
    /// Acquire a shared read guard.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let current = self.state.load(Ordering::Relaxed);
            if current & 1 == 0
                && self
                    .state
                    .compare_exchange(current, current + 2, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return RwLockReadGuard { lock: self };
            }
            let _ = futex_wait(&self.state, current, None);
        }
    }

    /// Acquire an exclusive write guard.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        loop {
            if self
                .state
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return RwLockWriteGuard { lock: self };
            }
            let _ = yield_now();
        }
    }

    /// Access the value without locking.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

/// RAII read guard for [`RwLock`].
pub struct RwLockReadGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
}

impl<T: ?Sized> Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: shared access is guaranteed by the reader count.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.state.fetch_sub(2, Ordering::Release);
        let _ = futex_wake(&self.lock.state, u32::MAX);
    }
}

/// RAII write guard for [`RwLock`].
pub struct RwLockWriteGuard<'a, T: ?Sized> {
    lock: &'a RwLock<T>,
}

impl<T: ?Sized> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: exclusive ownership is guaranteed by the writer bit.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: exclusive ownership is guaranteed by the writer bit.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
        let _ = futex_wake(&self.lock.state, u32::MAX);
    }
}
