//! C-like FFI vocabulary for a future C ABI boundary.
//!
//! pagh userland is not a C runtime and `libpagh` exposes no C symbols; these
//! re-exports are here because `core::ffi` already defines the types and a
//! library port that needs `c_int` should not have to add a dependency for it.
//! There is no `libc`, no `errno` global and no `malloc`.

pub use core::ffi::{
    c_char, c_double, c_float, c_int, c_long, c_longlong, c_schar, c_short, c_uchar, c_uint,
    c_ulong, c_ulonglong, c_ushort, c_void, CStr,
};

pub use alloc::ffi::CString;
