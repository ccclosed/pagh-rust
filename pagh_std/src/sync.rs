//! A single-threaded `LazyLock`, plus the `core::cell` types under std names,
//! the kernel-0.13+ futex-backed synchronisation primitives, and a bounded
//! [`mpsc`] channel.
//!
//! [`LazyLock`] itself lives in the crate-internal `lazy` module so the host
//! checker can include that file without `libpagh`; it is re-exported here. The [`Mutex`],
//! [`RwLock`], [`Condvar`], [`Barrier`] and [`Once`] below are process-private,
//! non-poisoning and not reentrant, matching the C library's pthread
//! primitives.

pub use core::cell::{Cell, OnceCell, RefCell, UnsafeCell};

pub use crate::lazy::LazyLock;

pub mod mpsc;

// ─── futex-backed synchronization (kernel 0.13+) ────────────────────────────
//
// The SDK targets a kernel that has native threads and futexes, so `Mutex` and
// `RwLock` are real rather than the std-shaped lies the first version shipped.
// They are process-private (the ABI's private futex flag), non-poisoning and
// not reentrant, matching the C library's pthread primitives.

use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

use libpagh::abi::Timespec;
use libpagh::errno::Errno;
use libpagh::sys;

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

/// A condition variable paired with a [`Mutex`].
///
/// This is the std shape: [`wait`](Condvar::wait) consumes a [`MutexGuard`],
/// releases the mutex, blocks, and returns a re-acquired guard;
/// [`wait_timeout`](Condvar::wait_timeout) adds a deadline and a
/// [`WaitTimeoutResult`]; [`notify_one`](Condvar::notify_one) and
/// [`notify_all`](Condvar::notify_all) wake one or every waiter.
///
/// # Contract
///
/// The condition itself (the predicate a waiter checks) must be protected by
/// the same mutex the guard belongs to, and a notifier must change that
/// predicate while holding the mutex. The implementation then has no lost
/// wakeup in the intended pattern:
///
/// ```ignore
/// let mut guard = mutex.lock();
/// while !*guard {
///     guard = condvar.wait(guard);
/// }
/// ```
///
/// A notification delivered before `wait` can see it is not remembered by the
/// condition variable, exactly like `std::sync::Condvar`; the predicate is the
/// state that matters. Notifications not made under the mutex are allowed but
/// can be observed as a spurious return.
///
/// # Deviations from `std::sync::Condvar`
///
/// * **No poisoning.** [`Mutex`] is non-poisoning, so these methods cannot
///   report a poisoned lock.
/// * **Spurious returns.** A signal-interrupted wait (`EINTR`), a futex table
///   error (`EAGAIN`/`ENOMEM`), or a wake that races the sequence word makes
///   `wait` return the guard without a notification. The std pattern already
///   re-checks the predicate in a loop, which is the required use.
/// * **Timeout granularity.** The kernel's only timeout is the 10 ms scheduler
///   tick; a non-zero duration is rounded **up** to it. A zero duration returns
///   immediately with `timed_out() == true`. There is no realtime-clock futex
///   (`FUTEX_CLOCK_REALTIME` is rejected by the ABI).
/// * **Small static futex table.** The kernel tracks at most 32 waiters and 16
///   distinct futex addresses per boot; exhausting those slots is visible as a
///   spurious return, never as a deadlock.
/// * **Process-private.** Like the mutex, the sequence word uses
///   `FUTEX_PRIVATE_FLAG`; another process cannot wait on or wake it.
///
/// The condition variable must outlive its waiters (do not drop it while a
/// thread is blocked inside [`Condvar::wait`]); this is the same rule as std.
pub struct Condvar {
    /// Notification sequence. Waiters block while this word is unchanged.
    seq: AtomicU32,
}

impl Condvar {
    /// Create a condition variable with no waiters.
    pub const fn new() -> Condvar {
        Condvar {
            seq: AtomicU32::new(0),
        }
    }

    /// Wait for a notification, releasing `guard` while blocked.
    ///
    /// The guard is re-acquired before returning, even if the wait was
    /// interrupted or the futex reported an error (see the type-level
    /// deviations). Callers must re-check their predicate in a loop.
    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        self.wait_inner(guard, None).0
    }

    /// Wait for a notification or until `timeout` elapses.
    ///
    /// Returns the re-acquired guard and a [`WaitTimeoutResult`] that is
    /// `timed_out()` only when the kernel reported `ETIMEDOUT`. A notification
    /// that arrives at the deadline wins if the futex was woken; a signal or a
    /// table error is reported as not-timed-out and must be treated as a
    /// spurious return. The duration is rounded up to the 10 ms tick.
    pub fn wait_timeout<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout: Duration,
    ) -> (MutexGuard<'a, T>, WaitTimeoutResult) {
        let (guard, timed_out) = self.wait_inner(guard, Some(timeout));
        (guard, WaitTimeoutResult { timed_out })
    }

    /// Wake one waiter, if there is one.
    ///
    /// The sequence word is advanced even when no thread is waiting; a later
    /// waiter simply starts from the new value, so there is no stored
    /// notification (matching std).
    pub fn notify_one(&self) {
        self.seq.fetch_add(1, Ordering::Release);
        let _ = futex_wake(&self.seq, 1);
    }

    /// Wake every waiter currently blocked on this condition variable.
    pub fn notify_all(&self) {
        self.seq.fetch_add(1, Ordering::Release);
        let _ = futex_wake(&self.seq, u32::MAX);
    }

    fn wait_inner<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout: Option<Duration>,
    ) -> (MutexGuard<'a, T>, bool) {
        // Read the sequence while the caller still holds the mutex. A notifier
        // that follows the contract needs that mutex to change the predicate,
        // so it cannot increment the word between this read and the release
        // below without the waiter either seeing the new value or getting an
        // immediate `EAGAIN` from the futex's value check.
        let seq = self.seq.load(Ordering::Acquire);
        let mutex = guard.mutex;
        drop(guard);

        let timed_out = matches!(wait_on_word(&self.seq, seq, timeout), Err(Errno::ETIMEDOUT));
        (mutex.lock(), timed_out)
    }
}

/// `FUTEX_WAIT` with the timeout `Timespec` kept alive across the call.
///
/// This deliberately does not call `libpagh::thread::futex_wait` for a timed
/// wait: that helper builds its `Timespec` in a temporary scope and passes a
/// pointer to the dead local to the syscall, so the kernel reads an arbitrary
/// stack slot. Keeping the struct in this frame is the fix on the SDK side
/// (the sibling `pagh-api` crate is a separate checkout and is not patched
/// here); the kernel validates the values it actually receives.
fn wait_on_word(
    word: &AtomicU32,
    expected: u32,
    timeout: Option<Duration>,
) -> libpagh::errno::Result<i32> {
    let address = word as *const AtomicU32 as usize;
    let operation = sys::FUTEX_WAIT | sys::FUTEX_PRIVATE_FLAG;
    match timeout {
        None => sys::futex(address, operation, expected, 0),
        Some(duration) => {
            // The ABI takes a `Timespec`; clamp an absurd duration instead of
            // wrapping the cast. The kernel rounds up to its next 10 ms tick.
            let seconds = duration.as_secs().min(i64::MAX as u64) as i64;
            let timespec = Timespec {
                seconds,
                nanos: duration.subsec_nanos() as i64,
            };
            sys::futex(
                address,
                operation,
                expected,
                &timespec as *const Timespec as usize,
            )
        }
    }
}

impl Default for Condvar {
    fn default() -> Condvar {
        Condvar::new()
    }
}

/// Whether [`Condvar::wait_timeout`] returned because its deadline elapsed.
///
/// This is the same shape as `std::sync::WaitTimeoutResult`, including the
/// caveat that a spurious return is not reported as a timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitTimeoutResult {
    timed_out: bool,
}

impl WaitTimeoutResult {
    /// True when the wait ended at the requested deadline.
    pub const fn timed_out(&self) -> bool {
        self.timed_out
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

// ─── Barrier ────────────────────────────────────────────────────────────────

/// A rendezvous point for a fixed number of threads.
///
/// Every thread calls [`Barrier::wait`]; each call blocks until `n` threads
/// have arrived, then all of them are released together and the barrier resets
/// for the next generation. Exactly one thread per generation is the
/// **leader** (the one whose arrival completed the set) and learns that from
/// [`BarrierWaitResult::is_leader`].
///
/// This is the std shape with one documented deviation: `std` panics on
/// `Barrier::new(0)` (or on a later `wait`), while this implementation has no
/// panic path for it — a zero-party barrier releases every caller immediately
/// as the leader.
///
/// The wait is a futex-backed [`Condvar`] wait, so a blocked party sleeps; the
/// barrier is process-private and non-poisoning like the other primitives in
/// this module.
pub struct Barrier {
    state: Mutex<BarrierState>,
    /// Signalled when a generation completes.
    released: Condvar,
    parties: usize,
}

struct BarrierState {
    /// Threads that have arrived in the current generation.
    arrived: usize,
    /// Generation counter: a waiter blocks while this is unchanged.
    generation: usize,
}

impl Barrier {
    /// Create a barrier for `parties` threads.
    pub const fn new(parties: usize) -> Barrier {
        Barrier {
            state: Mutex::new(BarrierState {
                arrived: 0,
                generation: 0,
            }),
            released: Condvar::new(),
            parties,
        }
    }

    /// Wait until `parties` threads have called this method.
    ///
    /// Returns a result whose [`is_leader`](BarrierWaitResult::is_leader) is
    /// true for exactly one caller per generation.
    pub fn wait(&self) -> BarrierWaitResult {
        let mut state = self.state.lock();
        if self.parties == 0 {
            // Documented deviation: no panic, every caller is a leader.
            return BarrierWaitResult { leader: true };
        }
        let generation = state.generation;
        state.arrived += 1;
        if state.arrived >= self.parties {
            state.arrived = 0;
            state.generation = generation.wrapping_add(1);
            drop(state);
            self.released.notify_all();
            return BarrierWaitResult { leader: true };
        }
        while state.generation == generation {
            state = self.released.wait(state);
        }
        drop(state);
        BarrierWaitResult { leader: false }
    }

    /// The number of parties this barrier waits for.
    pub const fn parties(&self) -> usize {
        self.parties
    }
}

/// The result of [`Barrier::wait`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarrierWaitResult {
    leader: bool,
}

impl BarrierWaitResult {
    /// True for the single thread that completed the generation.
    pub const fn is_leader(&self) -> bool {
        self.leader
    }
}

// ─── Once ───────────────────────────────────────────────────────────────────

/// A one-shot initialisation primitive: [`Once::call_once`] runs its closure
/// exactly once for the whole process, however many threads call it.
///
/// The implementation is a three-state machine (incomplete / running /
/// complete) over a [`Mutex`] and a [`Condvar`]: the first caller runs the
/// closure with the lock released while the others block; when the closure
/// returns, every waiter is released and later callers return immediately.
///
/// # Contract
///
/// * The closure runs at most once, and no caller returns before it has
///   completed (successful completion is not optional: `panic = "abort"` on
///   this target, so a panicking closure kills the process rather than leaving
///   the state poisoned).
/// * **Reentrancy deadlocks**: calling `call_once` on the same `Once` from
///   inside its own closure blocks forever, exactly like
///   `std::sync::Once`. The state has no reentrant owner.
/// * No poisoning: a `Once` that was completed stays completed, and there is
///   no error return to inspect.
pub struct Once {
    state: Mutex<OnceState>,
    done: Condvar,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OnceState {
    Incomplete,
    Running,
    Complete,
}

impl Once {
    /// Create an uninitialised `Once`.
    pub const fn new() -> Once {
        Once {
            state: Mutex::new(OnceState::Incomplete),
            done: Condvar::new(),
        }
    }

    /// Run `f` once, blocking other callers until it finishes.
    pub fn call_once<F: FnOnce()>(&self, f: F) {
        let mut state = self.state.lock();
        match *state {
            OnceState::Complete => return,
            OnceState::Running => {
                // Another thread is inside the closure: wait for it to finish
                // and then report the completed state.
                while *state == OnceState::Running {
                    state = self.done.wait(state);
                }
                return;
            }
            OnceState::Incomplete => *state = OnceState::Running,
        }
        // Release the lock while the closure runs, so the other callers can
        // observe `Running` and block instead of waiting on the mutex.
        drop(state);

        f();

        *self.state.lock() = OnceState::Complete;
        self.done.notify_all();
    }

    /// True once [`Once::call_once`] has completed its closure.
    pub fn is_completed(&self) -> bool {
        *self.state.lock() == OnceState::Complete
    }
}

impl Default for Once {
    fn default() -> Once {
        Once::new()
    }
}
