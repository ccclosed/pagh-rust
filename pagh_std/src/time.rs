//! Monotonic and "system" time over `clock_gettime`.
//!
//! The kernel has no RTC and no wall-clock source: clock 0 (`CLOCK_REALTIME`)
//! and clock 1 (`CLOCK_MONOTONIC`) both count timer ticks since boot at a
//! 10 ms resolution. [`SystemTime`] is therefore **uptime-based**: its
//! [`UNIX_EPOCH`] is the boot instant, not 1970-01-01, and a program cannot
//! learn the real date. [`Instant`] is the same monotonic tick counter with an
//! opaque, `Instant`-shaped API.
//!
//! Neither type can fail to construct in normal use: a `clock_gettime` error
//! (only possible for an invalid clock id, which this module never passes) is
//! reported by `try_now` and `now` falls back to zero rather than panicking.

use core::fmt;
use core::ops::{Add, Sub};

use libpagh::abi::Timespec;
use libpagh::sys;

use crate::error::{Error, Result};

pub use core::time::Duration;

/// The Unix epoch as a [`SystemTime`].
///
/// In this SDK that is the machine's boot instant (see the module docs).
pub const UNIX_EPOCH: SystemTime = SystemTime { nanos: 0 };

fn now_nanos(clock: i32) -> core::result::Result<u64, Error> {
    let mut ts = Timespec::default();
    sys::clock_gettime(clock, &mut ts)?;
    let seconds = if ts.seconds < 0 { 0 } else { ts.seconds as u64 };
    let nanos = if ts.nanos < 0 { 0 } else { ts.nanos as u64 };
    Ok(seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(nanos.min(999_999_999)))
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Sleep for `duration` (`nanosleep`).
///
/// The kernel validates the `Timespec`, rounds **up** to its 10 ms tick and
/// waits with interrupts enabled. This is the only blocking primitive the ABI
/// offers; there is no `poll`, so there is no standard way to wait for a
/// descriptor.
pub fn sleep(duration: Duration) -> Result<()> {
    let nanos = duration.as_nanos();
    let seconds = nanos / 1_000_000_000;
    if seconds > i64::MAX as u128 {
        return Err(Error::from(libpagh::errno::Errno::EINVAL));
    }
    let remainder = (nanos % 1_000_000_000) as i64;
    let request = Timespec {
        seconds: seconds as i64,
        nanos: remainder,
    };
    sys::nanosleep(&request)?;
    Ok(())
}

/// A monotonic instant (`CLOCK_MONOTONIC`, 10 ms kernel resolution).
///
/// Arithmetic is saturating: an underflow yields zero rather than panicking,
/// because a CLI program should report a clock oddity, not abort. Use the
/// `checked_*` methods when the difference matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    nanos: u64,
}

impl Instant {
    /// The current monotonic time.
    ///
    /// Falls back to zero if `clock_gettime` fails; use [`Instant::try_now`]
    /// when the distinction matters.
    pub fn now() -> Instant {
        Self::try_now().unwrap_or(Instant { nanos: 0 })
    }

    /// The current monotonic time, with the syscall error surfaced.
    pub fn try_now() -> Result<Instant> {
        Ok(Instant {
            nanos: now_nanos(libpagh::sys::CLOCK_MONOTONIC)?,
        })
    }

    /// An instant from a raw nanosecond count.
    pub const fn from_nanos(nanos: u64) -> Instant {
        Instant { nanos }
    }

    /// The raw nanosecond count since boot.
    pub const fn as_nanos(self) -> u64 {
        self.nanos
    }

    /// Time elapsed since this instant (saturating).
    pub fn elapsed(self) -> Duration {
        Instant::now().saturating_duration_since(self)
    }

    /// Time elapsed since `earlier` (saturating; zero if `earlier` is later).
    pub fn duration_since(self, earlier: Instant) -> Duration {
        Duration::from_nanos(self.nanos.saturating_sub(earlier.nanos))
    }

    /// Time elapsed since `earlier`, or `None` if `earlier` is later.
    pub fn checked_duration_since(self, earlier: Instant) -> Option<Duration> {
        self.nanos
            .checked_sub(earlier.nanos)
            .map(Duration::from_nanos)
    }

    /// Time elapsed since `earlier`, saturating at zero.
    pub fn saturating_duration_since(self, earlier: Instant) -> Duration {
        Duration::from_nanos(self.nanos.saturating_sub(earlier.nanos))
    }

    /// Add a duration, or `None` on overflow.
    pub fn checked_add(self, duration: Duration) -> Option<Instant> {
        self.nanos
            .checked_add(duration_nanos(duration))
            .map(Instant::from_nanos)
    }

    /// Subtract a duration, or `None` on underflow.
    pub fn checked_sub(self, duration: Duration) -> Option<Instant> {
        self.nanos
            .checked_sub(duration_nanos(duration))
            .map(Instant::from_nanos)
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Instant {
        Instant::from_nanos(self.nanos.saturating_add(duration_nanos(rhs)))
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, rhs: Duration) -> Instant {
        Instant::from_nanos(self.nanos.saturating_sub(duration_nanos(rhs)))
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, rhs: Instant) -> Duration {
        self.saturating_duration_since(rhs)
    }
}

/// A "system" timestamp.
///
/// **Uptime-based:** pagh has no RTC and no Unix-epoch clock; `clock_gettime(0)`
/// counts ticks since boot just like the monotonic clock. `UNIX_EPOCH` is the
/// boot instant. [`SystemTime::duration_since(UNIX_EPOCH)`](SystemTime::duration_since)
/// therefore returns uptime, not seconds since 1970.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemTime {
    nanos: u64,
}

impl SystemTime {
    /// The current system clock (uptime on this kernel).
    ///
    /// Falls back to zero if `clock_gettime` fails.
    pub fn now() -> SystemTime {
        Self::try_now().unwrap_or(SystemTime { nanos: 0 })
    }

    /// The current system clock, with the syscall error surfaced.
    pub fn try_now() -> Result<SystemTime> {
        Ok(SystemTime {
            nanos: now_nanos(libpagh::sys::CLOCK_REALTIME)?,
        })
    }

    /// A timestamp from a raw nanosecond count.
    pub const fn from_nanos(nanos: u64) -> SystemTime {
        SystemTime { nanos }
    }

    /// The raw nanosecond count.
    pub const fn as_nanos(self) -> u64 {
        self.nanos
    }

    /// Time elapsed since this timestamp, or a [`SystemTimeError`] if it is in
    /// the future.
    pub fn elapsed(self) -> core::result::Result<Duration, SystemTimeError> {
        SystemTime::now().duration_since(self)
    }

    /// The signed difference `self - earlier`.
    ///
    /// std returns `Err` when `earlier` is later than `self`; this does the
    /// same, carrying the absolute difference in the error.
    pub fn duration_since(
        self,
        earlier: SystemTime,
    ) -> core::result::Result<Duration, SystemTimeError> {
        match self.nanos.checked_sub(earlier.nanos) {
            Some(nanos) => Ok(Duration::from_nanos(nanos)),
            None => Err(SystemTimeError {
                duration: Duration::from_nanos(earlier.nanos.saturating_sub(self.nanos)),
            }),
        }
    }

    /// The earlier of two timestamps and the distance between them, or `None`
    /// for the same instant.
    pub fn checked_duration_since(self, earlier: SystemTime) -> Option<Duration> {
        self.nanos
            .checked_sub(earlier.nanos)
            .map(Duration::from_nanos)
    }

    /// The distance from `earlier`, saturating at zero.
    pub fn saturating_duration_since(self, earlier: SystemTime) -> Duration {
        Duration::from_nanos(self.nanos.saturating_sub(earlier.nanos))
    }

    /// Add a duration, or `None` on overflow.
    pub fn checked_add(self, duration: Duration) -> Option<SystemTime> {
        self.nanos
            .checked_add(duration_nanos(duration))
            .map(SystemTime::from_nanos)
    }

    /// Subtract a duration, or `None` on underflow.
    pub fn checked_sub(self, duration: Duration) -> Option<SystemTime> {
        self.nanos
            .checked_sub(duration_nanos(duration))
            .map(SystemTime::from_nanos)
    }
}

impl Add<Duration> for SystemTime {
    type Output = SystemTime;

    fn add(self, rhs: Duration) -> SystemTime {
        SystemTime::from_nanos(self.nanos.saturating_add(duration_nanos(rhs)))
    }
}

impl Sub<Duration> for SystemTime {
    type Output = SystemTime;

    fn sub(self, rhs: Duration) -> SystemTime {
        SystemTime::from_nanos(self.nanos.saturating_sub(duration_nanos(rhs)))
    }
}

impl Sub<SystemTime> for SystemTime {
    type Output = Duration;

    fn sub(self, rhs: SystemTime) -> Duration {
        self.saturating_duration_since(rhs)
    }
}

/// Error returned by [`SystemTime::duration_since`] when the timestamp is in
/// the future.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemTimeError {
    duration: Duration,
}

impl SystemTimeError {
    /// The absolute difference between the two timestamps.
    pub const fn duration(self) -> Duration {
        self.duration
    }
}

impl fmt::Display for SystemTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "second time provided was later than self by {:?}",
            self.duration
        )
    }
}

impl core::error::Error for SystemTimeError {}
