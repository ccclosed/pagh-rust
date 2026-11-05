//! Process arguments and environment.
//!
//! The kernel enters a program with `envp` containing exactly one entry,
//! `PWD=<cwd>`, and there is no syscall to change the kernel's notion of a
//! working directory. The SDK therefore implements
//! [`set_current_dir`] as **process-local `PWD` tracking**: after it returns,
//! every relative path opened through [`crate::fs`] resolves against the new
//! directory, but the shell's `pwd` and any future child process do not see
//! the change. This is documented, not hidden.
//!
//! Values are UTF-8 `String`s. pagh filenames may in principle be arbitrary
//! bytes; this SDK decodes them lossily at the directory-listing boundary, so
//! `args_os` is an alias of the same lossy view rather than a real `OsString`
//! API.

use alloc::string::String;
use core::cell::UnsafeCell;

use crate::error::{Error, ErrorKind, Result};
use crate::fs;
use crate::path::{Path, PathBuf};

/// Iterator over `argv`, including `argv[0]`.
#[derive(Clone, Copy)]
pub struct Args {
    inner: libpagh::env::Args,
}

impl Iterator for Args {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        self.inner.next()
    }
}

/// Iterator over `argv` as lossily-decoded UTF-8 strings.
///
/// This exists for std-shaped call sites. There is no `OsString`/`OsStr` in the
/// SDK, so the items are the same `String`s [`args`] yields; invalid UTF-8 has
/// already been replaced with U+FFFD by the runtime.
#[derive(Clone, Copy)]
pub struct ArgsOs {
    inner: Args,
}

impl Iterator for ArgsOs {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        self.inner.next()
    }
}

/// Iterator over `envp` as `(key, value)` pairs.
#[derive(Clone, Copy)]
pub struct Vars {
    inner: libpagh::env::Vars,
}

impl Iterator for Vars {
    type Item = (String, String);

    fn next(&mut self) -> Option<(String, String)> {
        self.inner.next()
    }
}

/// The `argv` of this process, `argv[0]` first.
///
/// The iterator re-reads the initial stack on each call; it does not allocate
/// a global argument vector.
pub fn args() -> Args {
    Args {
        inner: libpagh::env::args(),
    }
}

/// The `argv` of this process, exposed under the std `args_os` name.
///
/// Lossy by construction: the ABI gives NUL-terminated bytes and this SDK's
/// values are UTF-8 strings. See [`ArgsOs`].
pub fn args_os() -> ArgsOs {
    ArgsOs { inner: args() }
}

/// The `envp` of this process as key/value pairs.
pub fn vars() -> Vars {
    Vars {
        inner: libpagh::env::vars(),
    }
}

/// The error returned by [`var`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VarError {
    /// The variable is not present.
    NotPresent,
    /// The value was not valid UTF-8.
    ///
    /// The runtime's lossy decoder means this SDK never produces this variant
    /// itself; it stays in the type so a future real `OsString` implementation
    /// can use the same signature as std.
    NotUnicode(String),
}

impl core::fmt::Display for VarError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VarError::NotPresent => f.write_str("environment variable not found"),
            VarError::NotUnicode(_) => f.write_str("environment variable was not valid unicode"),
        }
    }
}

impl core::error::Error for VarError {}

/// Look up one environment variable.
pub fn var<K: AsRef<str>>(key: K) -> core::result::Result<String, VarError> {
    libpagh::env::var(key.as_ref()).ok_or(VarError::NotPresent)
}

/// Look up one environment variable, returning `None` when absent.
///
/// The "os" in the name is std compatibility; the value is a lossy `String`.
pub fn var_os<K: AsRef<str>>(key: K) -> Option<String> {
    libpagh::env::var(key.as_ref())
}

/// The process's program name (`argv[0]`'s basename), or `"pagh"`.
pub fn program_name() -> &'static str {
    libpagh::env::program_name()
}

/// The path of the executable, as the shell typed it.
///
/// `argv[0]` is stored verbatim by the kernel (see `pagh-riscv`'s `run`
/// contract), so this is not necessarily absolute and is not resolved against
/// the current directory.
pub fn current_exe() -> Result<PathBuf> {
    args()
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "argv[0] is absent"))
}

/// The process's working directory.
///
/// Starts at the kernel-provided `PWD`; [`set_current_dir`] changes the value
/// returned here. If `PWD` is missing or relative (a hand-built environment),
/// this falls back to `/` so path resolution still builds absolute paths.
pub fn current_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(pwd_string()))
}

/// Change this process's working directory for path resolution.
///
/// **This does not change a kernel cwd, because the ABI has none.** It checks
/// that `path` names a directory (open + `fstat`) and then records the
/// lexically-resolved absolute path in a process-local cell. Every relative
/// path passed to [`crate::fs`] afterwards resolves against it. The shell that
/// launched the program keeps its own cwd, and no child process can exist
/// (there is no `fork`/`exec`).
pub fn set_current_dir<P: AsRef<Path>>(path: P) -> Result<()> {
    let resolved = fs::resolve_path(path.as_ref());
    let metadata = fs::metadata(resolved.as_str())?;
    if !metadata.is_dir() {
        return Err(Error::from(libpagh::errno::Errno::ENOTDIR));
    }
    // SAFETY: the ABI guarantees a single-threaded process (no clone/fork,
    // no signal handlers that could re-enter), and this cell is only mutated
    // here. The old `String` is replaced while no reference to it is alive:
    // `pwd_string` clones before returning, and the metadata call above
    // completed first. No lock is needed because there is exactly one thread.
    unsafe {
        *PWD_OVERRIDE.0.get() = Some(resolved);
    }
    Ok(())
}

/// The process's temporary directory.
///
/// pagh's writable mount is `/mnt`, and this ABI has no `TMPDIR` convention
/// beyond it. The directory is not created or checked here.
pub fn temp_dir() -> PathBuf {
    PathBuf::from("/mnt")
}

/// The effective `PWD` string used for path resolution.
///
/// Crate-internal: [`crate::fs`] calls it for every relative path.
pub(crate) fn pwd_string() -> String {
    // SAFETY: single-threaded process; the cell is written only by
    // `set_current_dir`, and the shared borrow below does not outlive this
    // function (the value is cloned).
    let override_value = unsafe { &*PWD_OVERRIDE.0.get() };
    if let Some(value) = override_value {
        return value.clone();
    }
    match libpagh::env::var("PWD") {
        Some(value) if value.starts_with('/') => value,
        _ => String::from("/"),
    }
}

struct PwdOverride(UnsafeCell<Option<String>>);

// SAFETY: `UnsafeCell` is not `Sync`, but the ABI defines a single-threaded
// process: there is no `clone`, `fork`, signal handler or interrupt that can
// run Rust code concurrently. Every access is on that one thread, and the only
// mutation (`set_current_dir`) does not overlap a live borrow (`pwd_string`
// clones immediately).
unsafe impl Sync for PwdOverride {}

static PWD_OVERRIDE: PwdOverride = PwdOverride(UnsafeCell::new(None));
