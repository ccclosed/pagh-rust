//! Collections: `alloc`'s containers under std-shaped names, plus a
//! `HashMap`/`HashSet` shim.
//!
//! **`HashMap` is a `BTreeMap` in disguise.** The ABI gives this SDK no
//! entropy source and no threading, and a correct open-addressing table is
//! large; the shim keeps the std API (`entry`, `iter`, `insert`, …) with
//! `O(log n)` operations and deterministic iteration order. It requires
//! `K: Ord`, not `K: Hash + Eq`. [`HashSet`] is the matching `BTreeSet` shim.
//!
//! Everything else is the real `alloc` type: `Vec`, `String`, `VecDeque`,
//! `BTreeMap`, `BTreeSet`, `BinaryHeap`. There is no `LinkedList` re-export
//! because it is never the right answer; import it from `alloc` if needed.

pub use alloc::borrow::ToOwned;
pub use alloc::boxed::Box;
pub use alloc::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
pub use alloc::string::{String, ToString};
pub use alloc::vec::Vec;

mod hash_map;
mod hash_set;

pub use hash_map::{Entry, HashMap, OccupiedEntry, VacantEntry};
pub use hash_set::HashSet;
