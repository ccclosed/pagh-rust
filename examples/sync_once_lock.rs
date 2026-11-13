//! `sync_once_lock` — the 0.10.0 synchronization additions.
//!
//! Seven checks, each of which returns a `&'static str` describing the violated
//! invariant instead of printing "ok" blindly:
//!
//! 1. [`OnceLock::get_or_init`] raced by four native threads: **exactly one**
//!    initializer runs and every thread sees its value;
//! 2. a [`OnceLock::set`] race: one `Ok(())`, three `Err(value)`, and the cell
//!    keeps the winner's value (the losers block for the running initializer,
//!    like `std`);
//! 3. [`OnceLock::wait`] parks the main thread until a second thread sets the
//!    value — the futex half of the type, which the host gate cannot compile;
//! 4. `take`/`into_inner`/`Default`/re-initialization after a `take`;
//! 5. the single-threaded [`LazyLock`], including the new `Default` impl;
//! 6. `Rc`/`Weak` through the new `pagh_std::rc` re-export;
//! 7. `Arc`/`Weak` across four native threads through `pagh_std::sync::Arc`,
//!    including an `Arc<Mutex<u32>>` increment and `Arc::try_unwrap`.
//!
//! The program prints one line per area and `SYNC_ONCE_LOCK PASS`, or the failed
//! invariant and exit code 1 (`tools/live_100.py` checks both).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use pagh_std::prelude::*;
use pagh_std::rc::Rc;
use pagh_std::sync::{Arc, LazyLock, Mutex, OnceLock};
use pagh_std::thread;
use pagh_std::time;

fn once_lock_initializes_once() -> Result<(), &'static str> {
    static CELL: OnceLock<u32> = OnceLock::new();
    static INITIALIZERS: AtomicU32 = AtomicU32::new(0);
    static OBSERVERS: AtomicU32 = AtomicU32::new(0);

    thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                let value = *CELL.get_or_init(|| {
                    INITIALIZERS.fetch_add(1, Ordering::SeqCst);
                    4242
                });
                if value == 4242 {
                    OBSERVERS.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });

    if CELL.get() != Some(&4242) {
        return Err("OnceLock::get_or_init did not publish 4242");
    }
    if INITIALIZERS.load(Ordering::SeqCst) != 1 {
        return Err("more than one thread ran the once initializer");
    }
    if OBSERVERS.load(Ordering::SeqCst) != 4 {
        return Err("a thread did not observe the published value");
    }
    println!("sync_once_lock: OnceLock get_or_init ok (4 threads, 1 initializer, value 4242)");
    Ok(())
}

fn once_lock_set_race() -> Result<(), &'static str> {
    static CELL: OnceLock<u32> = OnceLock::new();
    static WINS: AtomicU32 = AtomicU32::new(0);
    static LOSES: AtomicU32 = AtomicU32::new(0);
    static WRONG_ERR: AtomicU32 = AtomicU32::new(0);

    thread::scope(|scope| {
        for candidate in [10u32, 20, 30, 40] {
            scope.spawn(move || match CELL.set(candidate) {
                Ok(()) => {
                    WINS.fetch_add(1, Ordering::SeqCst);
                }
                Err(returned) => {
                    if returned != candidate {
                        WRONG_ERR.fetch_add(1, Ordering::SeqCst);
                    }
                    LOSES.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });

    let value = match CELL.get() {
        Some(value) => *value,
        None => return Err("no thread's OnceLock::set won"),
    };
    if WINS.load(Ordering::SeqCst) != 1 {
        return Err("OnceLock::set had more than one winner");
    }
    if LOSES.load(Ordering::SeqCst) != 3 || WRONG_ERR.load(Ordering::SeqCst) != 0 {
        return Err("OnceLock::set returned the wrong Err(value) to a loser");
    }
    if ![10u32, 20, 30, 40].contains(&value) {
        return Err("OnceLock kept a value no thread offered");
    }
    println!("sync_once_lock: OnceLock set race ok (1 winner, 3 losers, value {value})");
    Ok(())
}

fn once_lock_wait_blocks() -> Result<(), &'static str> {
    let cell = OnceLock::new();
    let mut observed = 0u32;
    thread::scope(|scope| {
        scope.spawn(|| {
            // Give the main thread time to park in `wait()`.
            let _ = time::sleep(Duration::from_millis(40));
            let _ = cell.set(7u32);
        });
        observed = *cell.wait();
    });
    if observed != 7 {
        return Err("OnceLock::wait returned something other than the published 7");
    }
    println!("sync_once_lock: OnceLock wait() ok (parked until set: 7)");
    Ok(())
}

fn once_lock_take_and_reuse() -> Result<(), &'static str> {
    let mut cell = OnceLock::from(7u32);
    if cell.take() != Some(7) {
        return Err("OnceLock::from/take did not return 7");
    }
    if cell.get().is_some() {
        return Err("OnceLock still holds a value after take");
    }
    if cell.set(8).is_err() {
        return Err("OnceLock did not accept a value after take");
    }
    if cell.get() != Some(&8) {
        return Err("OnceLock lost the post-take value");
    }
    if cell.clone() != cell {
        return Err("OnceLock::clone differs from the initialized cell");
    }
    if cell.into_inner() != Some(8) {
        return Err("OnceLock::into_inner did not return 8");
    }
    let empty = OnceLock::<u32>::default();
    if empty.get().is_some() {
        return Err("OnceLock::default is initialized");
    }
    println!("sync_once_lock: OnceLock take/into_inner/clone/reuse ok");
    Ok(())
}

fn lazy_lock_single_threaded() -> Result<(), &'static str> {
    let lazy = LazyLock::new(|| 21u32 * 2);
    if *lazy != 42 {
        return Err("LazyLock::deref did not initialize to 42");
    }
    if lazy.get() != Some(&42) {
        return Err("LazyLock::get lost the initialized value");
    }
    if LazyLock::force(&lazy) != &42 {
        return Err("LazyLock::force returned the wrong reference");
    }
    let default: LazyLock<u32> = LazyLock::default();
    if *default != 0 {
        return Err("LazyLock::default is not T::default()");
    }
    if lazy.into_inner() != Some(42) {
        return Err("LazyLock::into_inner did not return 42");
    }
    println!("sync_once_lock: LazyLock single-threaded ok (42, default 0)");
    Ok(())
}

fn rc_reference_counting() -> Result<(), &'static str> {
    let rc = Rc::new(41u32);
    if Rc::strong_count(&rc) != 1 {
        return Err("a fresh Rc does not have one strong reference");
    }
    let clone = Rc::clone(&rc);
    if Rc::strong_count(&rc) != 2 || !Rc::ptr_eq(&rc, &clone) {
        return Err("Rc::clone did not share the allocation");
    }
    let weak = Rc::downgrade(&rc);
    drop(clone);
    if Rc::strong_count(&rc) != 1 {
        return Err("dropping the Rc clone did not decrement the count");
    }
    if weak.upgrade().map(|value| *value) != Some(41) {
        return Err("Rc::Weak could not upgrade while the Rc was alive");
    }
    drop(rc);
    if weak.upgrade().is_some() {
        return Err("Rc::Weak upgraded after the last Rc was dropped");
    }
    println!("sync_once_lock: Rc/Weak ok (2 -> 1 strong, Weak upgrade then None)");
    Ok(())
}

fn arc_across_threads() -> Result<(), &'static str> {
    static INCREMENTS: AtomicU32 = AtomicU32::new(0);

    let counter = Arc::new(Mutex::new(0u32));
    thread::scope(|scope| {
        for _ in 0..4 {
            let counter = Arc::clone(&counter);
            scope.spawn(move || {
                for _ in 0..100 {
                    *counter.lock() += 1;
                }
                INCREMENTS.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    let total = *counter.lock();
    if total != 400 {
        return Err("Arc<Mutex<u32>> lost increments across four threads");
    }
    if Arc::strong_count(&counter) != 1 {
        return Err("Arc::strong_count did not return to one after the joins");
    }
    let weak = Arc::downgrade(&counter);
    let unique = match Arc::try_unwrap(counter) {
        Ok(value) => value,
        Err(_) => return Err("Arc::try_unwrap failed on a uniquely owned Arc"),
    };
    if *unique.lock() != 400 {
        return Err("Arc::try_unwrap returned a different value");
    }
    if weak.upgrade().is_some() {
        return Err("Arc::Weak upgraded after the last Arc was dropped");
    }
    println!(
        "sync_once_lock: Arc/Weak across 4 threads ok ({} threads joined, value 400)",
        INCREMENTS.load(Ordering::SeqCst)
    );
    Ok(())
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut failures = 0u32;
    for (name, result) in [
        ("OnceLock get_or_init", once_lock_initializes_once()),
        ("OnceLock set race", once_lock_set_race()),
        ("OnceLock wait", once_lock_wait_blocks()),
        ("OnceLock take/reuse", once_lock_take_and_reuse()),
        ("LazyLock", lazy_lock_single_threaded()),
        ("Rc/Weak", rc_reference_counting()),
        ("Arc/Weak", arc_across_threads()),
    ] {
        if let Err(message) = result {
            eprintln!("sync_once_lock: {name}: {message}");
            failures += 1;
        }
    }
    if failures == 0 {
        println!("SYNC_ONCE_LOCK PASS");
        0
    } else {
        println!("SYNC_ONCE_LOCK FAIL: {failures} check(s) failed");
        1
    }
}
