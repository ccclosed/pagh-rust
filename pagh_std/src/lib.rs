//! `pagh_std` — a std-like layer for native Rust programs on **pagh-riscv**.
//!
//! # What this is, honestly
//!
//! A full `rustc`/`std` cannot run on this operating system: compiling Rust
//! needs LLVM and a host OS, and `std` assumes libc, threads, a signal stack,
//! `mmap`, a wall clock and a dynamic loader that the pagh ABI does not have.
//! What *is* fully real is **Rust the language** — generics, traits, closures,
//! iterators, pattern matching, `core`, `alloc`, `Vec`, `String`, `format!`,
//! `BTreeMap`, `BinaryHeap` — plus this crate's std-shaped wrappers over the
//! 22-syscall native ABI.
//!
//! `pagh_std` therefore does not claim to be `std`. It claims something
//! narrower and testable: file I/O, directories, arguments/environment,
//! monotonic time, paths, buffered I/O, formatting and exit codes, with the
//! unsupported operations (`thread`, `process::spawn`, networking, `fsync`,
//! `O_EXCL`, `OsStr`) exposed as typed `Unsupported` errors instead of silent
//! stubs.
//!
//! # Program shape
//!
//! A pagh program is `#![no_std] #![no_main]`, uses `pagh_std`, and defines the
//! C entry point the `libpagh` runtime calls:
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//!
//! use pagh_std::prelude::*;
//!
//! #[no_mangle]
//! pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
//!     println!("hello from {}", env::program_name());
//!     let text = fs::read_to_string("/mnt/hello.txt").unwrap_or_default();
//!     print!("{text}");
//!     0
//! }
//! ```
//!
//! The return value becomes the process exit status. The runtime, the bump
//! allocator and the panic/OOM handlers are owned by `libpagh`; see
//! [`panic`] for why a second set cannot exist in one Rust crate graph and for
//! the exact output/exit codes.
//!
//! # Runtime limits inherited from the ABI
//!
//! * one process, one image; no threads, `fork`, `exec`, signals or `wait`;
//! * 16 file descriptors (0/1/2 plus 13 opens) per run;
//! * a 1 MiB `brk` heap, bump-allocated: `dealloc` is a no-op, memory is
//!   returned only when the process exits;
//! * absolute kernel paths, maximum 256 bytes;
//! * console `read(0)` is non-blocking and has no EOF (the `io::Stdin` handle
//!   hides the non-blocking part by yielding, but EOF never arrives);
//! * no `statat`, `O_EXCL`, `O_DIRECTORY`, `O_NOFOLLOW`, `fsync`, `dup`,
//!   `mmap`, `poll`, sockets, RTC or dynamic linker.
//!
//! # Modules
//!
//! | Module | Provides |
//! |---|---|
//! | [`io`] | `Read`, `Write`, `Seek`, `BufRead`, `BufReader`, `BufWriter`, stdin/stdout/stderr, `copy`, `read_to_end`, `read_to_string`, `Error`/`ErrorKind` |
//! | [`fs`] | `File`, `OpenOptions`, `ReadDir`/`Dir`, `DirEntry`, `FileType`, `Metadata`, read/write/copy, mkdir/remove/rename/link/symlink/readlink, lexical `canonicalize` |
//! | [`env`] | `args`, `args_os` (lossy), `vars`, `var`, `current_dir`, `set_current_dir` (process-local), `temp_dir` |
//! | [`process`] | `exit`, `abort`, `id`, and a typed-`Unsupported` `Command` |
//! | [`time`] | `Duration`, monotonic `Instant`, uptime-based `SystemTime`, `UNIX_EPOCH`, `sleep` |
//! | [`path`] | `Path`, `PathBuf`, `Component`, `Components`, lexical `normalize`/`normalize_join` |
//! | [`collections`] | `Vec`, `String`, `VecDeque`, `BTreeMap`, `BTreeSet`, `BinaryHeap`, `HashMap`/`HashSet` shims |
//! | [`sync`] | `Cell`, `RefCell`, `OnceCell`, single-threaded `LazyLock`; deliberately no `Mutex`/`RwLock` |
//! | [`fmt`] | `core::fmt` re-exports; `print!`, `println!`, `eprint!`, `eprintln!`, `dbg!`, `format!`, `vec!`, `write!`, `writeln!` |
//! | [`panic`] | `PanicInfo`, `abort`; the handler contract and why `libpagh` owns it |
//! | [`ffi`] | `c_*` types and `CStr`/`CString` for a future C boundary |
//!
//! # Build
//!
//! The crate needs a sibling checkout of `pagh-api` (for `libpagh` and
//! `pagh-user.ld`) and the pinned `nightly-2026-07-12` toolchain. From the
//! repository root, `./build.sh` builds the three example ELFs; see the
//! repository README for `PAGH_API`, QEMU and the live transcript.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

extern crate alloc;

pub mod collections;
pub mod env;
pub mod error;
pub mod ffi;
pub mod fmt;
pub mod fs;
pub mod hash;
pub mod io;
pub mod panic;
pub mod path;
pub mod process;
pub mod sync;
pub mod time;

pub use crate::error::{Error, ErrorKind};

/// Implementation details used by this crate's macros; not a public API.
#[doc(hidden)]
pub mod __private {
    pub use alloc::fmt::format;
    pub use alloc::vec::from_elem;
    pub use alloc::vec::Vec;
}

/// Format a string, exactly like `std::format!`.
#[macro_export]
macro_rules! format {
    ($($arg:tt)*) => {
        $crate::__private::format(core::format_args!($($arg)*))
    };
}

/// Construct a `Vec`, exactly like `std::vec!`.
#[macro_export]
macro_rules! vec {
    () => {
        $crate::__private::Vec::new()
    };
    ($elem:expr; $n:expr) => {
        $crate::__private::from_elem($elem, $n)
    };
    ($($x:expr),+ $(,)?) => {{
        let mut vector = $crate::__private::Vec::new();
        $(vector.push($x);)+
        vector
    }};
}

/// Print to standard output.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::io::_print(core::format_args!($($arg)*))
    };
}

/// Print to standard output followed by a newline.
#[macro_export]
macro_rules! println {
    () => {
        $crate::io::_print(core::format_args!("\n"))
    };
    ($($arg:tt)*) => {{
        $crate::io::_print(core::format_args!($($arg)*));
        $crate::io::_print(core::format_args!("\n"));
    }};
}

/// Print to standard diagnostics.
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {
        $crate::io::_eprint(core::format_args!($($arg)*))
    };
}

/// Print to standard diagnostics followed by a newline.
#[macro_export]
macro_rules! eprintln {
    () => {
        $crate::io::_eprint(core::format_args!("\n"))
    };
    ($($arg:tt)*) => {{
        $crate::io::_eprint(core::format_args!($($arg)*));
        $crate::io::_eprint(core::format_args!("\n"));
    }};
}

/// Print and return the value of an expression, with file/line context.
///
/// Output goes to standard diagnostics, like `std::dbg!`.
#[macro_export]
macro_rules! dbg {
    () => {
        $crate::eprintln!("[{}:{}]", file!(), line!())
    };
    ($val:expr $(,)?) => {
        match $val {
            value => {
                $crate::eprintln!(
                    "[{}:{}:{}] {} = {:#?}",
                    file!(),
                    line!(),
                    column!(),
                    stringify!($val),
                    &value
                );
                value
            }
        }
    };
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}

/// The std-shaped prelude: traits, common types and the formatting macros.
///
/// `use pagh_std::prelude::*;` brings in `Read`/`Write` (so `read!`-style
/// method calls and `write!` work), `Vec`/`String`, `Path`/`PathBuf`, the
/// console types, `Duration`/`Instant`/`SystemTime`, the module names `env`,
/// `fs`, `process`, `time`, and the macros.
pub mod prelude {
    pub use alloc::borrow::ToOwned;
    pub use alloc::boxed::Box;
    pub use alloc::string::ToString;

    pub use crate::collections::{
        BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, String, Vec, VecDeque,
    };
    pub use crate::env::{self, args, args_os, current_dir, var, vars};
    pub use crate::fs;
    pub use crate::io::{
        self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Stderr, Stdin, Stdout, Write,
    };
    pub use crate::path::{Path, PathBuf};
    pub use crate::process;
    pub use crate::sync::{Cell, LazyLock, OnceCell, RefCell};
    pub use crate::time::{self, Duration, Instant, SystemTime, UNIX_EPOCH};

    pub use crate::{dbg, eprint, eprintln, format, print, println, vec};
}
