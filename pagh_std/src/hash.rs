//! Hashing: re-exports from `core::hash` plus a deterministic default hasher.
//!
//! pagh has no entropy source, no `getrandom` and no `rdseed` guarantee, so
//! [`RandomState`] cannot actually be randomized. It is a stable FNV-1a
//! builder: good enough for the API shape, explicitly **not** hash-flooding
//! resistant. [`crate::collections::HashMap`] is a `BTreeMap` shim and does not
//! call this hasher at all; it exists so code written against `std::hash` keeps
//! compiling.

pub use core::hash::{BuildHasher, Hash, Hasher};

/// A deterministic, non-random `BuildHasher`.
///
/// See the module docs: without an entropy source this cannot be randomized,
/// and claiming otherwise would be worse than documenting the limitation.
#[derive(Clone, Copy, Debug, Default)]
pub struct RandomState;

impl RandomState {
    /// A new state (identical to every other one).
    pub const fn new() -> RandomState {
        RandomState
    }
}

impl BuildHasher for RandomState {
    type Hasher = DefaultHasher;

    fn build_hasher(&self) -> DefaultHasher {
        DefaultHasher::new()
    }
}

/// FNV-1a, 64-bit.
///
/// Deterministic across runs and processes. It is a hash for data structures,
/// not a cryptographic digest.
#[derive(Clone, Copy, Debug)]
pub struct DefaultHasher {
    state: u64,
}

impl DefaultHasher {
    /// The FNV-1a offset basis.
    pub const fn new() -> DefaultHasher {
        DefaultHasher {
            state: 0xcbf2_9ce4_8422_2325,
        }
    }
}

impl Default for DefaultHasher {
    fn default() -> DefaultHasher {
        DefaultHasher::new()
    }
}

impl Hasher for DefaultHasher {
    fn finish(&self) -> u64 {
        self.state
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.state ^= u64::from(*byte);
            self.state = self.state.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}
