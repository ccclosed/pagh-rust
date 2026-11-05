//! Diagnostic probe: deliberate panic.
//!
//! Not a real program. It proves the `libpagh` panic handler's required shape
//! (`<program>: panic at <location>`, exit 101) in the live QEMU transcript.

#![no_std]
#![no_main]

use pagh_std::prelude::*;

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let values = vec![1u8, 2, 3];
    println!("panic probe: about to panic with {} values", values.len());
    panic!("deliberate panic probe");
}
