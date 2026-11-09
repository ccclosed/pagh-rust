//! A **bounded** multi-producer, single-consumer channel.
//!
//! `pagh_std::sync::mpsc` is std-shaped — [`channel`], [`Sender`]/[`Receiver`],
//! [`Sender::send`], [`Receiver::recv`], `try_*` and timeout forms — with two
//! honest differences:
//!
//! * **It is bounded.** `std::sync::mpsc::channel()` is unbounded; this OS has
//!   a fixed 1 MiB bump heap that never returns memory, so an unbounded queue
//!   is a memory leak with extra steps. [`channel`] uses [`DEFAULT_CAPACITY`]
//!   (32) and [`sync_channel`] takes an explicit capacity. A full queue makes
//!   [`Sender::send`] block until the receiver takes a value, exactly like
//!   `std::sync::mpsc::sync_channel`.
//! * **Capacity 0 is clamped to 1.** std's zero-capacity rendezvous channel
//!   needs a per-send handshake this implementation does not model; asking for
//!   0 gets a one-slot buffer instead of a silent misbehavior.
//!
//! The implementation is a [`Mutex`] over a [`VecDeque`] plus two [`Condvar`]s
//! ("not empty" and "not full"), so it works across native threads and sleeps
//! on the kernel's futex rather than spinning. The queue allocates from the
//! bump heap as it grows: memory of already-dequeued values is not returned to
//! the allocator (a property of the whole SDK, see the crate docs).
//!
//! Disconnection follows std: dropping every [`Sender`] makes a blocked
//! [`Receiver::recv`] return [`RecvError`] and `try_recv` report
//! [`TryRecvError::Disconnected`]; dropping the [`Receiver`] makes `send`
//! return [`SendError`] with the value.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::fmt;
use core::time::Duration;

use crate::sync::{Condvar, Mutex};
use crate::time::Instant;

/// The queue depth [`channel`] creates.
///
/// There is no unbounded mode: the bump heap is 1 MiB and never shrinks.
pub const DEFAULT_CAPACITY: usize = 32;

/// The shared state both halves point at.
struct Inner<T> {
    state: Mutex<State<T>>,
    /// Signalled when a value is queued or the last sender drops.
    not_empty: Condvar,
    /// Signalled when a value is dequeued or the receiver drops.
    not_full: Condvar,
}

struct State<T> {
    queue: VecDeque<T>,
    /// Live senders; the receiver is disconnected when this reaches zero.
    senders: usize,
    /// Cleared when the receiver drops, which unblocks full senders.
    receiver_alive: bool,
    /// Maximum queue length; 1 when the caller asked for 0.
    capacity: usize,
}

/// The sending half of a channel.
///
/// `Sender` is `Clone` and `Send`, so several threads can feed one receiver.
/// A [`SyncSender`] is the same type under the name `std::sync::mpsc` uses for
/// the bounded case.
pub struct Sender<T> {
    inner: Arc<Inner<T>>,
}

/// The name `std::sync::mpsc` gives the bounded sender.
///
/// [`channel`] and [`sync_channel`] return this one type; there is no separate
/// unbounded sender to be confused with it.
pub type SyncSender<T> = Sender<T>;

/// The receiving half of a channel.
pub struct Receiver<T> {
    inner: Arc<Inner<T>>,
}

/// Creates a bounded channel with [`DEFAULT_CAPACITY`] slots.
///
/// The deviation from std is the bound, not the shape: `send` blocks when the
/// queue is full. Use [`sync_channel`] to choose the depth.
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    sync_channel(DEFAULT_CAPACITY)
}

/// Creates a bounded channel with `capacity` slots.
///
/// `capacity` is clamped to at least 1: a zero-capacity rendezvous channel is
/// not implemented (see the module docs).
pub fn sync_channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(Inner {
        state: Mutex::new(State {
            queue: VecDeque::new(),
            senders: 1,
            receiver_alive: true,
            capacity: if capacity == 0 { 1 } else { capacity },
        }),
        not_empty: Condvar::new(),
        not_full: Condvar::new(),
    });
    let sender = Sender {
        inner: Arc::clone(&inner),
    };
    let receiver = Receiver { inner };
    (sender, receiver)
}

impl<T> Sender<T> {
    /// Send `value`, waiting while the queue is full.
    ///
    /// Returns [`SendError`] (with the value back) when the receiver has been
    /// dropped. While the queue is full this blocks on a condition variable,
    /// so the thread sleeps on the kernel futex rather than spinning.
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        let mut state = self.inner.state.lock();
        while state.receiver_alive && state.queue.len() >= state.capacity {
            state = self.inner.not_full.wait(state);
        }
        if !state.receiver_alive {
            return Err(SendError(value));
        }
        state.queue.push_back(value);
        self.inner.not_empty.notify_one();
        Ok(())
    }

    /// Send without waiting: [`TrySendError::Full`] when the queue is full,
    /// [`TrySendError::Disconnected`] when the receiver is gone.
    pub fn try_send(&self, value: T) -> Result<(), TrySendError<T>> {
        let mut state = self.inner.state.lock();
        if !state.receiver_alive {
            return Err(TrySendError::Disconnected(value));
        }
        if state.queue.len() >= state.capacity {
            return Err(TrySendError::Full(value));
        }
        state.queue.push_back(value);
        self.inner.not_empty.notify_one();
        Ok(())
    }

    /// The channel's queue depth.
    pub fn capacity(&self) -> usize {
        self.inner.state.lock().capacity
    }

    /// The number of values waiting in the queue.
    pub fn len(&self) -> usize {
        self.inner.state.lock().queue.len()
    }

    /// True when no value is waiting.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Sender<T> {
        self.inner.state.lock().senders += 1;
        Sender {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let last = {
            let mut state = self.inner.state.lock();
            state.senders = state.senders.saturating_sub(1);
            state.senders == 0
        };
        if last {
            // Every receiver blocked in `recv` must wake up and see the
            // disconnect; a notifier that changed the predicate holds the
            // mutex, which the block above did.
            self.inner.not_empty.notify_all();
        }
    }
}

impl<T> Receiver<T> {
    /// Receive one value, waiting until one is queued.
    ///
    /// Returns [`RecvError`] once every sender has been dropped and the queue
    /// is empty. Blocked senders are woken so they can observe the disconnect
    /// when the receiver is dropped.
    pub fn recv(&self) -> Result<T, RecvError> {
        let mut state = self.inner.state.lock();
        loop {
            if let Some(value) = state.queue.pop_front() {
                self.inner.not_full.notify_one();
                return Ok(value);
            }
            if state.senders == 0 {
                return Err(RecvError);
            }
            state = self.inner.not_empty.wait(state);
        }
    }

    /// Receive one value if one is queued right now.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        let mut state = self.inner.state.lock();
        if let Some(value) = state.queue.pop_front() {
            self.inner.not_full.notify_one();
            return Ok(value);
        }
        if state.senders == 0 {
            return Err(TryRecvError::Disconnected);
        }
        Err(TryRecvError::Empty)
    }

    /// Receive one value, giving up after `timeout`.
    ///
    /// The timeout is rounded up to the kernel's 10 ms tick by the underlying
    /// [`Condvar::wait_timeout`]; a wakeup that races the deadline is reported
    /// as [`RecvTimeoutError::Timeout`] only when the kernel said so.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<T, RecvTimeoutError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.inner.state.lock();
        loop {
            if let Some(value) = state.queue.pop_front() {
                self.inner.not_full.notify_one();
                return Ok(value);
            }
            if state.senders == 0 {
                return Err(RecvTimeoutError::Disconnected);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(RecvTimeoutError::Timeout);
            }
            let (next, _) = self
                .inner
                .not_empty
                .wait_timeout(state, deadline.saturating_duration_since(now));
            state = next;
        }
    }

    /// An iterator that yields values until every sender is dropped.
    pub fn iter(&self) -> Iter<'_, T> {
        Iter { receiver: self }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.inner.state.lock().receiver_alive = false;
        // Wake every blocked sender so it sees `receiver_alive == false`.
        self.inner.not_full.notify_all();
    }
}

/// Iterator returned by [`Receiver::iter`].
pub struct Iter<'a, T> {
    receiver: &'a Receiver<T>,
}

impl<T> Iterator for Iter<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.receiver.recv().ok()
    }
}

/// Owning iterator over a receiver (the `IntoIterator` shape).
pub struct IntoIter<T> {
    receiver: Receiver<T>,
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.receiver.recv().ok()
    }
}

impl<T> IntoIterator for Receiver<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> IntoIter<T> {
        IntoIter { receiver: self }
    }
}

/// The error [`Sender::send`] returns when the receiver is gone.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SendError<T>(pub T);

impl<T> fmt::Debug for SendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SendError(..)")
    }
}

impl<T> fmt::Display for SendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sending on a closed channel")
    }
}

impl<T> core::error::Error for SendError<T> {}

/// The error [`Sender::try_send`] returns.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrySendError<T> {
    /// The queue is full; the value was not sent.
    Full(T),
    /// The receiver is gone; the value was not sent.
    Disconnected(T),
}

impl<T> fmt::Debug for TrySendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrySendError::Full(_) => f.write_str("Full(..)"),
            TrySendError::Disconnected(_) => f.write_str("Disconnected(..)"),
        }
    }
}

impl<T> fmt::Display for TrySendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrySendError::Full(_) => f.write_str("sending on a full channel"),
            TrySendError::Disconnected(_) => f.write_str("sending on a closed channel"),
        }
    }
}

impl<T> core::error::Error for TrySendError<T> {}

impl<T> From<SendError<T>> for TrySendError<T> {
    fn from(error: SendError<T>) -> TrySendError<T> {
        match error {
            SendError(value) => TrySendError::Disconnected(value),
        }
    }
}

/// The error [`Receiver::recv`] returns when every sender is gone and the
/// queue is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvError;

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("receiving on a closed channel")
    }
}

impl core::error::Error for RecvError {}

/// The error [`Receiver::try_recv`] returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TryRecvError {
    /// The queue is empty, but at least one sender is alive.
    Empty,
    /// Every sender is gone and the queue is empty.
    Disconnected,
}

impl fmt::Display for TryRecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TryRecvError::Empty => f.write_str("receiving on an empty channel"),
            TryRecvError::Disconnected => f.write_str("receiving on a closed channel"),
        }
    }
}

impl core::error::Error for TryRecvError {}

impl From<RecvError> for TryRecvError {
    fn from(_: RecvError) -> TryRecvError {
        TryRecvError::Disconnected
    }
}

/// The error [`Receiver::recv_timeout`] returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvTimeoutError {
    /// No value arrived before the deadline.
    Timeout,
    /// Every sender is gone and the queue is empty.
    Disconnected,
}

impl fmt::Display for RecvTimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvTimeoutError::Timeout => f.write_str("timed out waiting on a channel"),
            RecvTimeoutError::Disconnected => f.write_str("receiving on a closed channel"),
        }
    }
}

impl core::error::Error for RecvTimeoutError {}

impl From<RecvError> for RecvTimeoutError {
    fn from(_: RecvError) -> RecvTimeoutError {
        RecvTimeoutError::Disconnected
    }
}
