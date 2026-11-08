//! Native threads over `clone`/`futex` (kernel 0.13.0+).
//!
//! This is the `pagh_std` face of [`libpagh::thread`]: a `Builder`, a
//! `JoinHandle` and futex helpers for a language that has no `std::thread`.
//! Threads share the process address space, heap, mmap regions and file
//! descriptors; a `JoinHandle::join` futex-waits for the child's exit code.
//!
//! Caveat inherited from the ABI: the child starts at `entry(arg)` and never
//! returns through the syscall; the closure is run by a trampoline inside
//! `libpagh`, so the raw builder takes an owned `'static` closure.
//! [`scope`] is the safe way to spawn a closure that borrows stack data: it
//! erases the lifetime internally and joins every child before returning.

pub use libpagh::thread::{
    current_id, exit, exit_group, futex_wait, futex_wake, yield_now, Builder, JoinHandle,
    DEFAULT_STACK_SIZE,
};

// ─── scoped threads ─────────────────────────────────────────────────────────

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::marker::PhantomData;

use crate::error::{Error, ErrorKind, Result};
use crate::sync::Mutex;

/// A scope for threads that may borrow from the enclosing stack frame.
///
/// `thread::scope` waits for every thread spawned through this handle before it
/// returns, which is what makes the borrowed closures sound: the borrow's
/// lifetime (`'env`) is still alive, and `Scope::spawn` only requires
/// `'scope`, the lifetime of the borrow of the scope itself.
pub struct Scope<'scope, 'env> {
    /// Every spawned thread's join handle, shared with its `ScopedJoinHandle`.
    /// `None` means that handle was already joined.
    handles: RefCell<Vec<Arc<Mutex<Option<JoinHandle>>>>>,
    /// Ties the scope to the borrow checker; no value is stored here.
    marker: PhantomData<(&'scope (), &'env ())>,
}

impl<'scope, 'env> Scope<'scope, 'env> {
    fn new() -> Scope<'scope, 'env> {
        Scope {
            handles: RefCell::new(Vec::new()),
            marker: PhantomData,
        }
    }

    /// Spawn a thread that may borrow data from the surrounding scope.
    ///
    /// The closure runs on a native thread and returns its value to
    /// [`ScopedJoinHandle::join`]. The scope automatically joins every thread
    /// that the closure did not join explicitly when `thread::scope` returns.
    ///
    /// # Panics
    ///
    /// Panics if the kernel cannot create the thread (task table or memory
    /// exhausted). Use [`Scope::try_spawn`] to handle that as an error.
    pub fn spawn<F, T>(&'scope self, f: F) -> ScopedJoinHandle<'scope, T>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        self.try_spawn(f).expect("failed to spawn scoped thread")
    }

    /// Fallible form of [`Scope::spawn`].
    pub fn try_spawn<F, T>(&'scope self, f: F) -> Result<ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        let result = Arc::new(Mutex::new(None::<T>));
        let slot = Arc::new(Mutex::new(None::<JoinHandle>));

        // The child's closure must be `'static` for `libpagh::thread::Builder`.
        // Both non-static values are erased to raw pointers here and rebuilt
        // inside the child; `Scope::finish` guarantees the child is gone before
        // the scope (and the borrows it carries) end.
        let closure = Box::into_raw(Box::new(f)) as usize;
        // `Arc::into_raw` transfers the child's strong reference; the parent
        // keeps `result` and reads it after `join`.
        let child_result = Arc::into_raw(Arc::clone(&result)) as usize;

        let spawned = Builder::new().spawn(move || {
            // SAFETY: `closure` is the `Box<F>` allocated above and this
            // closure runs exactly once. `child_result` is a strong `Arc`
            // reference created by `Arc::into_raw` above. Both are owned by
            // this child now; the parent guarantees it joins before the
            // borrowed data can go away.
            let function = unsafe { Box::from_raw(closure as *mut F) };
            let result = unsafe { Arc::from_raw(child_result as *const Mutex<Option<T>>) };
            let value = function();
            *result.lock() = Some(value);
            0
        });

        match spawned {
            Ok(handle) => {
                *slot.lock() = Some(handle);
                self.handles.borrow_mut().push(Arc::clone(&slot));
                Ok(ScopedJoinHandle {
                    slot,
                    result,
                    marker: PhantomData,
                })
            }
            Err(error) => {
                // The child never existed, so both raw owners are still the
                // parent's and must be released here.
                // SAFETY: both pointers came from the `Box`/`Arc` allocations
                // above and were not given to a child.
                drop(unsafe { Box::from_raw(closure as *mut F) });
                drop(unsafe { Arc::from_raw(child_result as *const Mutex<Option<T>>) });
                Err(error.into())
            }
        }
    }

    /// Join every thread that has not been joined explicitly.
    fn finish(&self) {
        for slot in self.handles.borrow().iter() {
            let handle = slot.lock().take();
            if let Some(handle) = handle {
                let _ = handle.join();
            }
        }
    }
}

/// A join handle for a thread spawned inside [`thread::scope`].
///
/// Unlike [`JoinHandle`], this handle may carry a value that borrows from the
/// scope. Dropping it without joining is allowed: the scope joins the thread
/// before returning (and discards the value).
pub struct ScopedJoinHandle<'scope, T> {
    slot: Arc<Mutex<Option<JoinHandle>>>,
    result: Arc<Mutex<Option<T>>>,
    marker: PhantomData<&'scope ()>,
}

impl<'scope, T> ScopedJoinHandle<'scope, T> {
    /// Wait for the thread and return the closure's value.
    ///
    /// There is no panic payload to report on this target: `panic = "abort"`.
    /// An error means the kernel's join failed or the child exited without
    /// storing a value (for example because it called
    /// [`exit_group`](crate::thread::exit_group)).
    pub fn join(self) -> Result<T> {
        let handle = self.slot.lock().take();
        if let Some(handle) = handle {
            handle.join()?;
        }
        self.result
            .lock()
            .take()
            .ok_or_else(|| Error::new(ErrorKind::Other, "scoped thread produced no value"))
    }
}

/// Run `f` with a [`Scope`] and join every thread it spawned before returning.
///
/// This is the std-shaped entry point for threads that borrow stack data:
///
/// ```ignore
/// let mut values = vec![1, 2, 3];
/// thread::scope(|scope| {
///     for value in &mut values {
///         scope.spawn(move || *value += 1);
///     }
/// });
/// assert_eq!(values, [2, 3, 4]);
/// ```
///
/// # Deviations from `std::thread::scope`
///
/// * Panics abort the whole program (`panic = "abort"`); there is no unwinding
///   and therefore no panic payload returned from [`ScopedJoinHandle::join`].
/// * `Scope::spawn` panics if the kernel cannot create the thread (std does
///   too); [`Scope::try_spawn`] is the fallible form.
/// * The scope handle is single-threaded (it holds a `RefCell`), so a child
///   thread cannot spawn a sibling through the same `Scope`; spawn from the
///   thread that called [`scope`].
/// * The lifetime-erasing implementation is sound only because `scope` joins
///   every thread before returning; do not copy that trick outside this
///   module.
pub fn scope<'env, F, T>(f: F) -> T
where
    F: for<'scope> FnOnce(&'scope Scope<'scope, 'env>) -> T,
{
    let scope = Scope::new();
    let result = f(&scope);
    scope.finish();
    result
}
