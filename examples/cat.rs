//! `cat` — stream files and (blocking) standard input to standard output.
//!
//! Exercises `env::args`, `fs::File`, `io::copy`, `io::stdin`/`stdout`,
//! `Write::flush` and real error reporting. With no file arguments (or with
//! `-`) it reads stdin; pagh's console has no EOF, so that form waits for input
//! forever, exactly like an interactive `cat`.

#![no_std]
#![no_main]

use pagh_std::fs::File;
use pagh_std::prelude::*;

fn usage() {
    eprintln!("usage: cat [--] [file...]");
    eprintln!("  -  read standard input (the pagh console has no EOF)");
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let args: Vec<String> = env::args().collect();
    let mut files: Vec<String> = Vec::new();
    let mut options_done = false;

    for arg in args.iter().skip(1) {
        if !options_done {
            match arg.as_str() {
                "--" => {
                    options_done = true;
                    continue;
                }
                "-h" | "--help" => {
                    usage();
                    return 0;
                }
                "-" => {}
                other if other.starts_with('-') => {
                    eprintln!("cat: unknown option '{}'", other);
                    usage();
                    return 2;
                }
                _ => {}
            }
        }
        files.push(arg.clone());
    }

    if files.is_empty() {
        files.push(String::from("-"));
    }

    let mut stdout = io::stdout();
    let mut status = 0;

    for file in &files {
        if file == "-" {
            let mut stdin = io::stdin();
            if let Err(error) = io::copy(&mut stdin, &mut stdout) {
                eprintln!("cat: -: {}", error);
                status = 1;
            }
        } else {
            match File::open(file) {
                Ok(mut input) => {
                    if let Err(error) = io::copy(&mut input, &mut stdout) {
                        eprintln!("cat: {}: {}", file, error);
                        status = 1;
                    }
                }
                Err(error) => {
                    eprintln!("cat: {}: {}", file, error);
                    status = 1;
                }
            }
        }
    }

    if let Err(error) = stdout.flush() {
        eprintln!("cat: stdout: {}", error);
        status = 1;
    }
    status
}
