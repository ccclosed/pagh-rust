//! Diagnostic probe: process-local `set_current_dir` + relative paths.
//!
//! Not a real program. It proves that after `env::set_current_dir("/mnt/demo")`
//! the `fs` layer resolves `alpha.txt` against the tracked directory, while the
//! kernel still has no cwd of its own.

#![no_std]
#![no_main]

use pagh_std::prelude::*;

fn run() -> io::Result<()> {
    println!("chdir: before={}", env::current_dir()?.display());
    env::set_current_dir("/mnt/demo")?;
    println!("chdir: cwd={}", env::current_dir()?.display());
    let text = fs::read_to_string("alpha.txt")?;
    print!("chdir: alpha.txt={}", text);
    let metadata = fs::metadata(".")?;
    println!("chdir: . is_dir={}", metadata.is_dir());
    Ok(())
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    match run() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("chdir: {}", error);
            1
        }
    }
}
