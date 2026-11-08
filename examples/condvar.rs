//! `condvar` — futex-backed `Condvar` + `Mutex`, with `thread::scope`.
//!
//! Three live checks:
//! 1. four scoped threads block in `Condvar::wait`, the main thread observes
//!    them (the mutex really was released), then `notify_all` releases them;
//! 2. three waiters: `notify_one` releases exactly one, `notify_all` the rest;
//! 3. `wait_timeout` returns at the deadline and hands the guard back locked.
//!
//! The threads borrow the stack-local mutexes and condvars directly, which is
//! only possible because `pagh_std::thread::scope` joins them before it
//! returns.

#![no_std]
#![no_main]

use pagh_std::prelude::*;
use pagh_std::sync::{Condvar, Mutex};
use pagh_std::thread;
use pagh_std::time::{Duration, Instant};

struct StartState {
    waiting: u32,
    start: bool,
    done: u32,
}

struct OneState {
    waiting: u32,
    go: u32,
    done: u32,
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut failures = 0u32;

    // ── phase 1: wait / notify_all, explicit joins, values from the scope ──
    let phase1 = Mutex::new(StartState {
        waiting: 0,
        start: false,
        done: 0,
    });
    let phase1_cv = Condvar::new();

    thread::scope(|scope| {
        let state = &phase1;
        let cv = &phase1_cv;
        let mut handles = Vec::new();
        for id in 0..4u32 {
            handles.push(
                scope
                    .try_spawn(move || {
                        let mut guard = state.lock();
                        guard.waiting += 1;
                        cv.notify_all();
                        while !guard.start {
                            guard = cv.wait(guard);
                        }
                        guard.done += 1;
                        cv.notify_all();
                        id
                    })
                    .expect("spawn phase 1"),
            );
        }

        let mut guard = phase1.lock();
        let deadline = Instant::now() + Duration::from_secs(5);
        while guard.waiting < 4 && Instant::now() < deadline {
            let (next, _) = phase1_cv.wait_timeout(guard, Duration::from_millis(100));
            guard = next;
        }
        if guard.waiting == 4 {
            println!("condvar: phase 1: all 4 waiters blocked and released the mutex");
        } else {
            println!(
                "condvar: phase 1 FAIL: only {} waiter(s) arrived",
                guard.waiting
            );
            failures += 1;
        }

        guard.start = true;
        phase1_cv.notify_all();
        while guard.done < 4 && Instant::now() < deadline {
            let (next, _) = phase1_cv.wait_timeout(guard, Duration::from_millis(100));
            guard = next;
        }
        if guard.done == 4 {
            println!("condvar: phase 1: notify_all woke every waiter");
        } else {
            println!("condvar: phase 1 FAIL: {} of 4 woke", guard.done);
            failures += 1;
        }
        drop(guard);

        let mut id_sum = 0u32;
        for handle in handles {
            match handle.join() {
                Ok(id) => id_sum += id,
                Err(error) => {
                    println!("condvar: phase 1 FAIL: join: {error}");
                    failures += 1;
                }
            }
        }
        if id_sum == 0 + 1 + 2 + 3 {
            println!("condvar: phase 1: scoped join returned each thread's value");
        } else {
            println!("condvar: phase 1 FAIL: thread values summed to {id_sum}");
            failures += 1;
        }
    });

    // ── phase 2: notify_one is exact, notify_all clears the rest ──────────
    let phase2 = Mutex::new(OneState {
        waiting: 0,
        go: 0,
        done: 0,
    });
    let go_cv = Condvar::new();
    let ready_cv = Condvar::new();
    let done_cv = Condvar::new();

    thread::scope(|scope| {
        let state = &phase2;
        let ready = &ready_cv;
        let go = &go_cv;
        let done = &done_cv;
        for _ in 0..3u32 {
            // Drop the handle: scope::finish must join it when the closure ends.
            let _ = scope
                .try_spawn(move || {
                    let mut guard = state.lock();
                    guard.waiting += 1;
                    ready.notify_all();
                    while guard.go == 0 {
                        guard = go.wait(guard);
                    }
                    guard.done += 1;
                    done.notify_all();
                })
                .expect("spawn phase 2");
        }

        let mut guard = phase2.lock();
        let deadline = Instant::now() + Duration::from_secs(5);
        while guard.waiting < 3 && Instant::now() < deadline {
            let (next, _) = ready_cv.wait_timeout(guard, Duration::from_millis(100));
            guard = next;
        }
        if guard.waiting == 3 {
            println!("condvar: phase 2: 3 waiters ready");
        } else {
            println!(
                "condvar: phase 2 FAIL: only {} waiter(s) arrived",
                guard.waiting
            );
            failures += 1;
        }

        guard.go = 1;
        go_cv.notify_one();
        while guard.done == 0 && Instant::now() < deadline {
            let (next, _) = done_cv.wait_timeout(guard, Duration::from_millis(100));
            guard = next;
        }
        if guard.done == 1 {
            println!("condvar: phase 2: notify_one woke exactly 1 of 3");
        } else {
            println!("condvar: phase 2 FAIL: notify_one woke {}", guard.done);
            failures += 1;
        }

        guard.go = 3;
        go_cv.notify_all();
        while guard.done < 3 && Instant::now() < deadline {
            let (next, _) = done_cv.wait_timeout(guard, Duration::from_millis(100));
            guard = next;
        }
        if guard.done == 3 {
            println!("condvar: phase 2: notify_all woke the remaining waiters");
        } else {
            println!("condvar: phase 2 FAIL: {} of 3 woke", guard.done);
            failures += 1;
        }
    });

    // ── phase 3: wait_timeout, deadline and guard re-acquisition ──────────
    let pair = Mutex::new(0u8);
    let timeout_cv = Condvar::new();
    let started = Instant::now();
    let guard = pair.lock();
    let (guard, result) = timeout_cv.wait_timeout(guard, Duration::from_millis(50));
    let elapsed = started.elapsed();
    let reacquired = pair.try_lock().is_none();
    drop(guard);

    if result.timed_out() {
        println!(
            "condvar: wait_timeout returned timed_out after {:?}",
            elapsed
        );
    } else {
        println!("condvar: phase 3 FAIL: wait_timeout did not report a timeout");
        failures += 1;
    }
    if elapsed >= Duration::from_millis(40) && elapsed < Duration::from_secs(2) {
        println!("condvar: wait_timeout respected the ~50 ms deadline");
    } else {
        println!(
            "condvar: phase 3 FAIL: elapsed {:?} outside 40 ms..2 s",
            elapsed
        );
        failures += 1;
    }
    if reacquired {
        println!("condvar: wait_timeout returned the guard re-locked");
    } else {
        println!("condvar: phase 3 FAIL: guard was not re-acquired");
        failures += 1;
    }

    // ── phase 4: scoped threads may borrow mutable stack data ────────────
    let mut borrowed = [0u32; 4];
    thread::scope(|scope| {
        for (index, slot) in borrowed.iter_mut().enumerate() {
            scope.spawn(move || {
                *slot = index as u32 + 10;
            });
        }
    });
    if borrowed == [10, 11, 12, 13] {
        println!("condvar: thread::scope let 4 threads borrow &mut stack slots");
    } else {
        println!("condvar: phase 4 FAIL: borrowed slots are {borrowed:?}");
        failures += 1;
    }

    if failures == 0 {
        println!("CONDVAR PASS");
        0
    } else {
        println!("CONDVAR FAIL: {failures} check(s) failed");
        1
    }
}
