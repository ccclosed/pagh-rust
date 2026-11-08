//! Process lifetime and spawning.
//!
//! The 0.16.0 ABI has `fork`/`execve`/`wait4`: [`fork`], [`execve`], [`wait`],
//! [`getppid`] expose them, and [`Command`] is implemented on top (spawn, status,
//! output with one stdout pipe). This is a single-process-image OS: the child
//! shares nothing writable after fork (deep copy) and a socket fd is `ENOTSUP`
//! in the child. There is no `SIGCHLD`; `wait` polls/blocks the syscall.
//!
//! A program is entered by the `libpagh` runtime as
//! `extern "C" fn main(argc, argv, envp) -> i32`; its return value becomes the
//! exit status. See the crate-level example.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Result;
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

    /// An exit status that a signal would have produced.
    pub const fn from_signal(_signal: i32) -> ExitStatus {
        ExitStatus { code: None }
    }

    /// Decode a raw `wait4` status: low 7 bits signal, otherwise `code << 8`.
    pub const fn from_raw(raw: i32) -> ExitStatus {
        let signal = raw & 0x7f;
        if signal == 0 {
            ExitStatus {
                code: Some(raw >> 8),
            }
        } else {
            ExitStatus { code: None }
        }
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
#[derive(Debug)]
pub struct Child {
    pid: u32,
    /// Read end of the captured stdout pipe, if any.
    stdout: Option<i32>,
}

impl Child {
    /// The child's pid.
    pub const fn id(&self) -> u32 {
        self.pid
    }

    /// Wait for the child and decode its status.
    pub fn wait(&mut self) -> Result<ExitStatus> {
        if let Some(fd) = self.stdout.take() {
            let _ = libpagh::sys::close(fd);
        }
        let (_, raw) = libpagh::sys::wait4(self.pid as i32, 0)?;
        Ok(ExitStatus::from_raw(raw))
    }

    /// Poll without blocking (`WNOHANG`); `Ok(None)` means still running.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        let (pid, raw) = libpagh::sys::wait4(self.pid as i32, libpagh::sys::WNOHANG)?;
        if pid == 0 {
            return Ok(None);
        }
        if let Some(fd) = self.stdout.take() {
            let _ = libpagh::sys::close(fd);
        }
        Ok(Some(ExitStatus::from_raw(raw)))
    }

    /// Send `SIGKILL` to the child.
    pub fn kill(&mut self) -> Result<()> {
        libpagh::sys::kill(self.pid as i32, libpagh::sys::SIGKILL)?;
        Ok(())
    }

    /// Take the captured stdout pipe (used by [`Command::output`]).
    pub fn take_stdout(&mut self) -> Option<i32> {
        self.stdout.take()
    }
}

/// `fork(2)`: returns the child pid in the parent and 0 in the child.
pub fn fork() -> Result<u32> {
    let pid = libpagh::sys::fork()?;
    Ok(pid as u32)
}

/// `execve(2)`: replace the current image; returns only on error.
pub fn execve(path: &str, argv: &[&str], envp: &[&str]) -> Result<()> {
    libpagh::sys::execve(path, argv, envp)?;
    Ok(())
}

/// `wait4(2)` without `WNOHANG`; returns the raw status.
pub fn wait(pid: u32) -> Result<ExitStatus> {
    let (_, raw) = libpagh::sys::wait4(pid as i32, 0)?;
    Ok(ExitStatus::from_raw(raw))
}

/// `wait4(2)` with `WNOHANG`; `Ok(None)` when the child is still running.
pub fn try_wait(pid: u32) -> Result<Option<ExitStatus>> {
    let (child, raw) = libpagh::sys::wait4(pid as i32, libpagh::sys::WNOHANG)?;
    if child == 0 {
        Ok(None)
    } else {
        Ok(Some(ExitStatus::from_raw(raw)))
    }
}

/// `getppid(2)`.
pub fn parent_id() -> u32 {
    match libpagh::sys::getppid() {
        Ok(pid) if pid >= 0 => pid as u32,
        _ => 0,
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

    fn argv(&self) -> Vec<&str> {
        let mut argv = Vec::with_capacity(self.args.len() + 1);
        argv.push(self.program.as_str());
        argv.extend(self.args.iter().map(String::as_str));
        argv
    }

    fn envp(&self) -> Vec<String> {
        let mut envp = Vec::with_capacity(self.envs.len());
        for (key, value) in &self.envs {
            envp.push(alloc::format!("{key}={value}"));
        }
        envp
    }

    /// Spawn the child with stdout inherited.
    pub fn spawn(&mut self) -> Result<Child> {
        self.spawn_with_stdout(false)
    }

    fn spawn_with_stdout(&mut self, capture: bool) -> Result<Child> {
        let pipe = if capture {
            Some(libpagh::sys::pipe2()?)
        } else {
            None
        };
        let pid = libpagh::sys::fork()?;
        if pid == 0 {
            // Child: wire stdout and exec. Errors are reported on stderr and
            // become 127; this process must not return into the parent's code.
            if let Some([read, write]) = pipe {
                let _ = libpagh::sys::close(read);
                let _ = libpagh::sys::dup2(write, 1);
                if write != 1 {
                    let _ = libpagh::sys::close(write);
                }
            }
            let envp = self.envp();
            let env_refs: Vec<&str> = envp.iter().map(String::as_str).collect();
            if libpagh::sys::execve(&self.program, &self.argv(), &env_refs).is_err() {
                crate::io::_eprint(core::format_args!("{}: exec failed\n", self.program));
                libpagh::sys::exit(127);
            }
            libpagh::sys::exit(127);
        }
        if let Some([read, write]) = pipe {
            let _ = libpagh::sys::close(write);
            Ok(Child {
                pid: pid as u32,
                stdout: Some(read),
            })
        } else {
            Ok(Child {
                pid: pid as u32,
                stdout: None,
            })
        }
    }

    /// Run the child to completion and return its status.
    pub fn status(&mut self) -> Result<ExitStatus> {
        let mut child = self.spawn()?;
        child.wait()
    }

    /// Run the child and capture stdout.
    pub fn output(&mut self) -> Result<Output> {
        let mut child = self.spawn_with_stdout(true)?;
        let mut stdout = Vec::new();
        if let Some(fd) = child.take_stdout() {
            let mut buf = [0u8; 4096];
            loop {
                match libpagh::sys::read(fd, &mut buf) {
                    Ok(0) => break,
                    Ok(n) if n <= buf.len() => stdout.extend_from_slice(&buf[..n]),
                    Ok(_) => break,
                    Err(libpagh::Errno::EAGAIN) => {
                        let _ = libpagh::sys::sched_yield();
                    }
                    Err(_) => break,
                }
            }
            let _ = libpagh::sys::close(fd);
        }
        let status = child.wait()?;
        Ok(Output {
            status,
            stdout,
            stderr: Vec::new(),
        })
    }
}

/// A child-process command builder; see [`Command`].
pub type Process = Command;
