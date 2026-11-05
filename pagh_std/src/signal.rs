//! POSIX-style signals (kernel 0.14.0+).
//!
//! Handlers are installed with `SigAction`; a real handler needs
//! `SA_RESTORER` and a user restorer that executes `rt_sigreturn` (libpagh
//! exposes [`libpagh::sys::rt_sigreturn`]). The kernel delivers a user signal
//! frame and interrupts `futex`/`nanosleep` waits with `EINTR`.

pub use libpagh::abi::{
    SigAction, SA_RESTORER, SIG_BLOCK, SIG_DFL, SIG_IGN, SIG_SETMASK, SIG_UNBLOCK,
};
pub use libpagh::sys::{
    kill, rt_sigaction, rt_sigprocmask, rt_sigreturn, tgkill, SIGHUP, SIGINT, SIGKILL, SIGSEGV,
    SIGTERM, SIGUSR1, SIGUSR2,
};
