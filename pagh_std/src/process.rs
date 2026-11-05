//! Process lifetime and the (currently unsupported) process-spawning API.
//!
//! pagh runs one process image at a time; the ABI has no `fork`, `exec`,
//! `clone`, `wait`, signals or `mmap`. [`exit`] and [`abort`] are real;
//! [`Command`] is a typed stub whose methods always return
//! [`ErrorKind::Unsupported`](crate::io::ErrorKind::Unsupported) rather than
//! pretending a process was started.
//!
//! A program is entered by the `libpagh` runtime as
//! `extern "C" fn main(argc, argv, envp) -> i32`; its return value becomes the
//! exit status. See the crate-level example.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::path::{Path, PathBuf};

/// Terminate the process with `code`.
///
/// This is the `exit` syscall; it does not run destructors and never returns.
pub fn exit(code: i32) -> ! {
    libpagh::sys::exit(code)
}

/// Terminate the process with the conventional abort status (134).
///
/// The ABI has no signals, so there is no `SIGABRT` to raise. This prints
/// `<program>: abort` to fd 2 and exits with `128 + SIGABRT`, which is what a
/// shell would report for an aborted program on a Unix-like system.
pub fn abort() -> ! {
    crate::io::_eprint(core::format_args!(
        "{}: abort\n",
        crate::env::program_name()
    ));
    libpagh::sys::exit(134)
}

/// The kernel task id of this process (`getpid`), or 0 if the syscall fails.
pub fn id() -> u32 {
    match libpagh::sys::getpid() {
        Ok(pid) if pid >= 0 => pid as u32,
        _ => 0,
    }
}

/// The exit status of a finished process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitStatus {
    code: Option<i32>,
}

impl ExitStatus {
    /// An exit status with the given code.
    pub const fn from_code(code: i32) -> ExitStatus {
        ExitStatus { code: Some(code) }
    }

    /// An exit status that a signal would have produced; always `None` here,
    /// because pagh has no signals.
    pub const fn from_signal(_signal: i32) -> ExitStatus {
        ExitStatus { code: None }
    }

    /// The exit code, if the process exited normally.
    pub const fn code(&self) -> Option<i32> {
        self.code
    }

    /// True when the process exited with code 0.
    pub const fn success(&self) -> bool {
        matches!(self.code, Some(0))
    }
}

impl core::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.code {
            Some(code) => write!(f, "exit status: {code}"),
            None => f.write_str("exit status: unknown"),
        }
    }
}

/// Captured output of a child process.
#[derive(Clone, Debug)]
pub struct Output {
    /// The exit status.
    pub status: ExitStatus,
    /// Bytes written to the child's stdout.
    pub stdout: Vec<u8>,
    /// Bytes written to the child's stderr.
    pub stderr: Vec<u8>,
}

/// A child process handle.
///
/// It cannot be constructed by a user: [`Command::spawn`] always fails. The
/// type exists so `Command`'s API has the std shape and so a future kernel with
/// spawn can fill it in without changing call sites.
#[derive(Debug)]
pub struct Child {
    _private: (),
}

impl Child {
    /// The child's pid; 0 because no child can exist.
    pub const fn id(&self) -> u32 {
        0
    }

    /// Unsupported without a wait syscall.
    pub fn wait(&mut self) -> Result<ExitStatus> {
        Err(Error::unsupported(
            "Child::wait: the pagh ABI has no fork/exec/wait",
        ))
    }

    /// Unsupported without signals.
    pub fn kill(&mut self) -> Result<()> {
        Err(Error::unsupported(
            "Child::kill: the pagh ABI has no fork/exec/signals",
        ))
    }

    /// Unsupported without a wait syscall.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        Err(Error::unsupported(
            "Child::try_wait: the pagh ABI has no fork/exec/wait",
        ))
    }
}

/// A builder for a child process.
///
/// Every execution method returns [`ErrorKind::Unsupported`]. The builder
/// stores its arguments so a test can inspect them and so the type is useful
/// the day the kernel grows `exec`.
#[derive(Clone, Debug)]
pub struct Command {
    program: String,
    args: Vec<String>,
    envs: Vec<(String, String)>,
    env_cleared: bool,
    current_dir: Option<PathBuf>,
}

impl Command {
    /// Create a command for `program`.
    pub fn new<P: AsRef<str>>(program: P) -> Command {
        Command {
            program: String::from(program.as_ref()),
            args: Vec::new(),
            envs: Vec::new(),
            env_cleared: false,
            current_dir: None,
        }
    }

    /// Append one argument.
    pub fn arg<A: AsRef<str>>(&mut self, arg: A) -> &mut Command {
        self.args.push(String::from(arg.as_ref()));
        self
    }

    /// Append several arguments.
    pub fn args<I, A>(&mut self, args: I) -> &mut Command
    where
        I: IntoIterator<Item = A>,
        A: AsRef<str>,
    {
        for arg in args {
            self.args.push(String::from(arg.as_ref()));
        }
        self
    }

    /// Set one environment variable for the child (stored, never used).
    pub fn env<K: AsRef<str>, V: AsRef<str>>(&mut self, key: K, value: V) -> &mut Command {
        self.envs
            .push((String::from(key.as_ref()), String::from(value.as_ref())));
        self
    }

    /// Set several environment variables for the child (stored, never used).
    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Command
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (key, value) in vars {
            self.envs
                .push((String::from(key.as_ref()), String::from(value.as_ref())));
        }
        self
    }

    /// Clear inherited environment variables (stored, never used).
    pub fn env_clear(&mut self) -> &mut Command {
        self.env_cleared = true;
        self.envs.clear();
        self
    }

    /// Set the child's working directory (stored, never used).
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Command {
        self.current_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// The program this command would run.
    pub fn get_program(&self) -> &str {
        &self.program
    }

    /// The arguments this command would pass.
    pub fn get_args(&self) -> impl Iterator<Item = &str> {
        self.args.iter().map(String::as_str)
    }

    /// The environment variables this command would set.
    pub fn get_envs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.envs
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    /// The working directory this command would use.
    pub fn get_current_dir(&self) -> Option<&Path> {
        self.current_dir.as_deref()
    }

    /// Unsupported: the ABI has no `fork`/`exec`.
    pub fn status(&mut self) -> Result<ExitStatus> {
        Err(Error::unsupported(
            "Command::status: the pagh ABI has no fork/exec",
        ))
    }

    /// Unsupported: the ABI has no `fork`/`exec`/`pipe`.
    pub fn output(&mut self) -> Result<Output> {
        Err(Error::unsupported(
            "Command::output: the pagh ABI has no fork/exec/pipe",
        ))
    }

    /// Unsupported: the ABI has no `fork`/`exec`.
    pub fn spawn(&mut self) -> Result<Child> {
        Err(Error::unsupported(
            "Command::spawn: the pagh ABI has no fork/exec",
        ))
    }
}

/// A child-process command builder; see [`Command`].
pub type Process = Command;
