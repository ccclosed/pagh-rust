//! Spawn /mnt/hello through the process API and report its exit status.
#![no_std]
#![no_main]

use pagh_std::prelude::*;
use pagh_std::process::Command;

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    match Command::new("/mnt/hello").status() {
        Ok(status) => {
            println!("child status: {status}");
            if status.success() { 0 } else { 1 }
        }
        Err(error) => {
            eprintln!("spawn failed: {error}");
            1
        }
    }
}
