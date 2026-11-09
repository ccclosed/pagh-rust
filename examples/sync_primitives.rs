//! `sync_primitives` — live checks for `sync::mpsc`, `sync::Barrier` and
//! `sync::Once` on native threads.
//!
//! Four phases, each with an independent PASS/FAIL line:
//!
//! 1. **mpsc, bounded**: three producer threads push four values each into a
//!    channel with two slots; the main thread drains all twelve and sums them.
//!    Because the producers outrun the queue, `send` really has to block (and
//!    be woken by the receiver) rather than buffer everything.
//! 2. **mpsc, disconnection and timeouts**: `try_recv` on an empty live channel
//!    is `Empty`; dropping the senders makes `recv` return `RecvError`;
//!    `recv_timeout` on a channel with no sender returns `Disconnected`.
//! 3. **Barrier**: four threads meet twice (two generations); exactly one
//!    leader per generation, every party released both times.
//! 4. **Once**: four threads race to initialise a value; the closure runs
//!    exactly once and every thread sees `is_completed()` afterwards.
//!
//! All threads borrow stack-local primitives directly through
//! `pagh_std::thread::scope`, which joins them before the borrows end.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use pagh_std::prelude::*;
use pagh_std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
use pagh_std::sync::{Barrier, Once};
use pagh_std::thread;
use pagh_std::time::Duration;

/// Producers and the values each of them sends.
const PRODUCERS: u32 = 3;
const VALUES_PER_PRODUCER: u32 = 4;
/// Deliberately smaller than `PRODUCERS * VALUES_PER_PRODUCER`: `send` blocks.
const CHANNEL_CAPACITY: usize = 2;
/// Parties in the barrier and the `Once` race.
const PARTIES: usize = 4;

fn phase_channel(failures: &mut u32) {
    let (sender, receiver) = mpsc::sync_channel::<(u32, u32)>(CHANNEL_CAPACITY);
    println!(
        "sync_primitives: channel capacity {} (default would be {})",
        sender.capacity(),
        mpsc::DEFAULT_CAPACITY
    );

    let mut sent = 0u32;
    thread::scope(|scope| {
        for producer in 0..PRODUCERS {
            let sender = sender.clone();
            scope.spawn(move || {
                for index in 0..VALUES_PER_PRODUCER {
                    if sender.send((producer, index)).is_err() {
                        println!("sync_primitives: producer {producer} found a closed channel");
                        return;
                    }
                }
            });
        }
        // Drop the parent's own sender *after* the clones exist, so the channel
        // disconnects exactly when the last producer finishes.
        drop(sender);
        for _ in 0..(PRODUCERS * VALUES_PER_PRODUCER) {
            match receiver.recv() {
                Ok((producer, index)) => {
                    if producer >= PRODUCERS || index >= VALUES_PER_PRODUCER {
                        println!("sync_primitives: FAIL: received ({producer}, {index})");
                        *failures += 1;
                    }
                    sent += 1;
                }
                Err(error) => {
                    println!("sync_primitives: recv FAIL: {error}");
                    *failures += 1;
                    break;
                }
            }
        }
    });

    if sent == PRODUCERS * VALUES_PER_PRODUCER {
        println!("sync_primitives: mpsc: {sent} values passed through {CHANNEL_CAPACITY} slots (send blocked)");
    } else {
        println!(
            "sync_primitives: FAIL: received {sent} of {} values",
            PRODUCERS * VALUES_PER_PRODUCER
        );
        *failures += 1;
    }
    // Every sender is gone now, so the emptied channel reports a disconnect.
    match receiver.recv() {
        Err(mpsc::RecvError) => {
            println!("sync_primitives: mpsc: recv after the last sender -> RecvError")
        }
        Ok((producer, index)) => {
            println!(
                "sync_primitives: FAIL: unexpected value ({producer}, {index}) after disconnect"
            );
            *failures += 1;
        }
    }
}

fn phase_disconnect(failures: &mut u32) {
    let (sender, receiver) = mpsc::channel::<u32>();
    match receiver.try_recv() {
        Err(TryRecvError::Empty) => {
            println!("sync_primitives: mpsc: try_recv on an empty live channel -> Empty")
        }
        other => {
            println!("sync_primitives: FAIL: try_recv returned {other:?}");
            *failures += 1;
        }
    }
    // A full queue with a live receiver: try_send must report Full, not block.
    let (small_sender, small_receiver) = mpsc::sync_channel::<u32>(1);
    small_sender.send(7).expect("first send fits");
    match small_sender.try_send(8) {
        Err(mpsc::TrySendError::Full(8)) => {
            println!("sync_primitives: mpsc: try_send on a full channel -> Full (value returned)")
        }
        other => {
            println!("sync_primitives: FAIL: try_send returned {other:?}");
            *failures += 1;
        }
    }
    drop(small_receiver);
    match small_sender.try_send(9) {
        Err(mpsc::TrySendError::Disconnected(9)) => {
            println!("sync_primitives: mpsc: try_send after the receiver dropped -> Disconnected")
        }
        other => {
            println!("sync_primitives: FAIL: try_send after disconnect returned {other:?}");
            *failures += 1;
        }
    }

    drop(sender);
    match receiver.recv_timeout(Duration::from_millis(50)) {
        Err(RecvTimeoutError::Disconnected) => {
            println!("sync_primitives: mpsc: recv_timeout with no sender -> Disconnected")
        }
        other => {
            println!("sync_primitives: FAIL: recv_timeout returned {other:?}");
            *failures += 1;
        }
    }
}

fn phase_barrier(failures: &mut u32) {
    const GENERATIONS: usize = 2;
    let barrier = Barrier::new(PARTIES);
    let leaders = AtomicU32::new(0);
    let arrived = AtomicU32::new(0);

    thread::scope(|scope| {
        for party in 0..PARTIES {
            let barrier = &barrier;
            let leaders = &leaders;
            let arrived = &arrived;
            scope.spawn(move || {
                for generation in 0..GENERATIONS {
                    let result = barrier.wait();
                    if result.is_leader() {
                        leaders.fetch_add(1, Ordering::SeqCst);
                    }
                    arrived.fetch_add(1, Ordering::SeqCst);
                    let _ = (party, generation);
                }
            });
        }
    });

    let total_arrivals = arrived.load(Ordering::SeqCst);
    let total_leaders = leaders.load(Ordering::SeqCst);
    let expected_arrivals = (PARTIES * GENERATIONS) as u32;
    let expected_leaders = GENERATIONS as u32;
    println!(
        "sync_primitives: barrier: {total_arrivals} arrivals, {total_leaders} leader(s) over {GENERATIONS} generation(s)"
    );
    if total_arrivals == expected_arrivals && total_leaders == expected_leaders {
        println!(
            "sync_primitives: barrier: every party released, exactly one leader per generation"
        );
    } else {
        println!(
            "sync_primitives: FAIL: expected {expected_arrivals} arrivals and {expected_leaders} leaders"
        );
        *failures += 1;
    }
    println!("sync_primitives: barrier parties = {}", barrier.parties());
}

fn phase_once(failures: &mut u32) {
    let once = Once::new();
    let runs = AtomicU32::new(0);
    let observed = AtomicU32::new(0);

    thread::scope(|scope| {
        for _ in 0..PARTIES {
            let once = &once;
            let runs = &runs;
            let observed = &observed;
            scope.spawn(move || {
                once.call_once(|| {
                    // Run once for the whole process; the counter proves it.
                    runs.fetch_add(1, Ordering::SeqCst);
                    pagh_std::time::sleep(Duration::from_millis(20)).expect("sleep");
                });
                if once.is_completed() {
                    observed.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });

    let run_count = runs.load(Ordering::SeqCst);
    let observer_count = observed.load(Ordering::SeqCst);
    println!("sync_primitives: once: closure ran {run_count} time(s) for {PARTIES} threads");
    if run_count == 1 && observer_count == PARTIES as u32 && once.is_completed() {
        println!(
            "sync_primitives: once: exactly one run, all {PARTIES} callers saw is_completed()"
        );
    } else {
        println!(
            "sync_primitives: FAIL: runs={run_count}, completed observers={observer_count}, is_completed={}",
            once.is_completed()
        );
        *failures += 1;
    }
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut failures = 0u32;

    phase_channel(&mut failures);
    phase_disconnect(&mut failures);
    phase_barrier(&mut failures);
    phase_once(&mut failures);

    if failures == 0 {
        println!("SYNC_PRIMITIVES PASS");
        0
    } else {
        println!("SYNC_PRIMITIVES FAIL: {failures} check(s) failed");
        1
    }
}
