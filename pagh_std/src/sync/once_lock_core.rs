//! The syscall-free state machine and storage behind
//! [`OnceLock`](super::OnceLock).
//!
//! This file is pure `core`: an `AtomicU8` state word and a `MaybeUninit<T>`
//! behind an `UnsafeCell`. The blocking half — futex park/unpark — lives in
//! `sync.rs`, because it needs `libpagh`. Keeping the protocol here means the
//! host gate compiles it and races it with real host threads (where preemption
//! exists), instead of the only evidence being a guest run.
//!
//! The only legal transitions are:
//!
//! ```text
//! EMPTY --begin (CAS)--> BUSY --publish (release)--> READY
//! READY --take (needs &mut)--> EMPTY
//! ```
//!
//! [`Core::begin`] tells the caller what to do: [`Begin::Won`] means it is the
//! single initializer and must call [`Core::publish`]; [`Begin::Busy`] means
//! another thread has claimed initialization, so the caller blocks in
//! `sync.rs`; [`Begin::Ready`] means the value is already published.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

/// No value and no initializer.
const EMPTY: u8 = 0;
/// One thread has claimed initialization and is about to publish.
const BUSY: u8 = 1;
/// The value is published and readable by every thread.
const READY: u8 = 2;

/// What [`Core::begin`] says the caller has to do.
pub(crate) enum Begin {
    /// The caller claimed initialization and must call [`Core::publish`].
    Won,
    /// Another thread is initializing; the caller must wait for it.
    Busy,
    /// A value is already published.
    Ready,
}

/// Uninitialized storage plus the state word, with no blocking and no syscalls.
pub(crate) struct Core<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

impl<T> Core<T> {
    /// An empty cell.
    pub(crate) const fn new() -> Core<T> {
        Core {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// A cell that starts out initialized, for `OnceLock::from`.
    pub(crate) fn with_value(value: T) -> Core<T> {
        Core {
            state: AtomicU8::new(READY),
            value: UnsafeCell::new(MaybeUninit::new(value)),
        }
    }

    /// The published value, if there is one. Never blocks.
    pub(crate) fn get(&self) -> Option<&T> {
        if !self.is_ready() {
            return None;
        }
        // SAFETY: `READY` is stored with `Release` after the value was written,
        // and `is_ready` loads it with `Acquire`, so the `T` is initialised.
        // No thread can write it again: only the `Begin::Won` caller publishes,
        // and that happens once.
        Some(unsafe { (*self.value.get()).assume_init_ref() })
    }

    /// The published value mutably. `&mut self` means no other thread can hold
    /// a reference to the cell, so no synchronization is needed.
    pub(crate) fn get_mut(&mut self) -> Option<&mut T> {
        if !self.is_ready() {
            return None;
        }
        // SAFETY: `READY` means the value is initialised, and `&mut self`
        // excludes every other reference to it.
        Some(unsafe { (*self.value.get()).assume_init_mut() })
    }

    /// Try to become the one initializer.
    pub(crate) fn begin(&self) -> Begin {
        match self
            .state
            .compare_exchange(EMPTY, BUSY, Ordering::Acquire, Ordering::Acquire)
        {
            Ok(_) => Begin::Won,
            Err(state) if state == READY => Begin::Ready,
            Err(_) => Begin::Busy,
        }
    }

    /// Publish the value. Only the thread that got [`Begin::Won`] may call
    /// this, and only once.
    pub(crate) fn publish(&self, value: T) {
        debug_assert_eq!(
            self.state.load(Ordering::Relaxed),
            BUSY,
            "Core::publish without a winning Core::begin"
        );
        // SAFETY: `begin` gave this caller the only BUSY claim, so no other
        // thread is writing or reading the value; readers only look at it once
        // `READY` is published below, and `&mut self` methods cannot run while
        // a `&self` call is in progress.
        unsafe { (*self.value.get()).write(value) };
        // Release: the write above is visible to every thread whose Acquire
        // load sees READY.
        self.state.store(READY, Ordering::Release);
    }

    /// True once a value is published.
    pub(crate) fn is_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == READY
    }

    /// Take the value out, returning the cell to `EMPTY`.
    ///
    /// `&mut self` is what makes this sound without synchronization: no other
    /// thread can access the cell while this borrow exists, so the transient
    /// `READY -> EMPTY` step is unobservable.
    pub(crate) fn take(&mut self) -> Option<T> {
        if !self.is_ready() {
            return None;
        }
        // SAFETY: `READY` means the value is initialised, and `&mut self`
        // excludes every other reference to it. The state goes to EMPTY
        // immediately, so a later `begin` may claim the cell again.
        let value = unsafe { (*self.value.get()).assume_init_read() };
        self.state.store(EMPTY, Ordering::Relaxed);
        Some(value)
    }

    /// Drop the value if one was published (the `Drop` path). `&mut self`
    /// again makes the exclusive access explicit.
    pub(crate) fn drop_value(&mut self) {
        if !self.is_ready() {
            return;
        }
        // SAFETY: initialised and exclusively borrowed; dropping is the only
        // thing done with the value, and the state is cleared afterwards.
        unsafe { (*self.value.get()).assume_init_drop() };
        self.state.store(EMPTY, Ordering::Relaxed);
    }
}
