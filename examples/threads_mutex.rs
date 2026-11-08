//! Four native threads incrementing one value under a futex-backed Mutex.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;

use pagh_std::prelude::*;
use pagh_std::sync::Mutex;
use pagh_std::thread;

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let counter = Arc::new(Mutex::new(0u32));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let counter = Arc::clone(&counter);
        handles.push(
            thread::Builder::new()
                .stack_size(32 * 1024)
                .spawn(move || {
                    for _ in 0..250 {
                        *counter.lock() += 1;
                    }
                    0
                })
                .expect("spawn"),
        );
    }
    for handle in handles {
        assert_eq!(handle.join().expect("join"), 0);
    }
    let value = *counter.lock();
    println!("counter={value}");
    if value == 1000 {
        0
    } else {
        1
    }
}
