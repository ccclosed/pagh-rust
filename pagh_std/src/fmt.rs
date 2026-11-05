//! Re-export of `core::fmt` under the std module name.
//!
//! `pagh_std::fmt::Write` is `core::fmt::Write`; the `write!`/`writeln!` macros
//! at the crate root call the `io::Write` trait, exactly as std's do.

pub use core::fmt::*;
