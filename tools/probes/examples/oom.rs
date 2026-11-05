//! Diagnostic probe: exhaust the 1 MiB `brk` heap.
//!
//! Not a real program. It proves the runtime's allocation-error path
//! (`out of memory ...`, exit 102) in the live QEMU transcript.

#![no_std]
#![no_main]

use pagh_std::prelude::*;

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    println!("oom probe: filling the 1 MiB brk heap");
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        bytes.extend_from_slice(&[0u8; 4096]);
    }
}
