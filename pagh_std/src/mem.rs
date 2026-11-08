//! Anonymous mappings and page-level memory helpers (kernel 0.12+).
//!
//! The ABI provides `mmap`/`munmap`/`mprotect` for a per-run anonymous window;
//! this module wraps them in an RAII [`Mapping`]. The `brk` heap remains the
//! allocator's arena; mappings are for large buffers and thread stacks.

use core::slice;

use crate::error::{Error, Result};

/// Permission flags for [`Mapping`] / [`protect`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prot(u32);

/// Readable pages.
pub const READ: Prot = Prot(libpagh::sys::PROT_READ);
/// Writable pages.
pub const WRITE: Prot = Prot(libpagh::sys::PROT_WRITE);
/// Executable pages.
pub const EXEC: Prot = Prot(libpagh::sys::PROT_EXEC);

impl Prot {
    /// Combine two permission sets.
    pub const fn or(self, other: Prot) -> Prot {
        Prot(self.0 | other.0)
    }
    /// The raw ABI bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// An RAII anonymous private mapping.
pub struct Mapping {
    addr: usize,
    len: usize,
}

impl Mapping {
    /// Map `len` bytes (rounded up to a page) with `prot`.
    pub fn anonymous(len: usize, prot: Prot) -> Result<Mapping> {
        if len == 0 {
            return Err(Error::from(crate::error::ErrorKind::InvalidInput));
        }
        let addr = libpagh::sys::mmap(
            0,
            len,
            prot.0,
            libpagh::sys::MAP_PRIVATE | libpagh::sys::MAP_ANONYMOUS,
        )?;
        Ok(Mapping { addr, len })
    }

    /// Base address of the mapping.
    pub const fn as_ptr(&self) -> *const u8 {
        self.addr as *const u8
    }

    /// Mutable base address.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.addr as *mut u8
    }

    /// Length requested at creation.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True when the mapping is zero-length (only constructible via errors).
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The mapping as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the kernel mapped `len` readable bytes for this process, and
        // `&self` keeps the mapping alive for the slice's lifetime.
        unsafe { slice::from_raw_parts(self.as_ptr(), self.len) }
    }

    /// The mapping as a mutable byte slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, and `&mut self` guarantees exclusive access.
        unsafe { slice::from_raw_parts_mut(self.as_mut_ptr(), self.len) }
    }

    /// Change page permissions.
    pub fn protect(&self, prot: Prot) -> Result<()> {
        libpagh::sys::mprotect(self.addr, self.len, prot.0)?;
        Ok(())
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let _ = libpagh::sys::munmap(self.addr, self.len);
    }
}
