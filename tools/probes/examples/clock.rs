//! Diagnostic probe: `Instant` and uptime-based `SystemTime`.
//!
//! Not a real program. It proves the monotonic clock advances and that
//! `SystemTime` is interpreted as uptime since `UNIX_EPOCH` (the ABI has no
//! RTC, so this is not a Unix timestamp).

#![no_std]
#![no_main]

use pagh_std::prelude::*;

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let start = Instant::now();
    let mut last = start.as_nanos();
    while start.elapsed() < Duration::from_millis(30) {
        last = Instant::now().as_nanos();
    }
    let answer = dbg!(40 + 2);
    println!("clock: dbg_return={}", answer);
    println!("clock: monotonic_advanced={}", last > start.as_nanos());
    println!("clock: elapsed_ms={}", start.elapsed().as_millis());

    if let Err(error) = time::sleep(Duration::from_millis(10)) {
        eprintln!("clock: sleep: {}", error);
        return 1;
    }
    println!("clock: slept=true");

    let system = SystemTime::now();
    match system.duration_since(UNIX_EPOCH) {
        Ok(uptime) => println!("clock: uptime_ms={}", uptime.as_millis()),
        Err(error) => {
            eprintln!("clock: {}", error);
            return 1;
        }
    }
    let later = system + Duration::from_millis(1);
    println!("clock: ordering={}", later > system);
    println!("clock: ok");
    0
}
