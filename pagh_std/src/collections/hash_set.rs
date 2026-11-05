//! A documented `BTreeSet` shim named `HashSet`.
//!
//! Same tradeoff as [`super::HashMap`]: elements need `Ord`, iteration is
//! sorted, and there is no hasher. The API covers `new`, `insert`, `remove`,
//! `contains`, `iter`, `extend`, `FromIterator` and the iterator impls.

use alloc::collections::btree_set::{self, BTreeSet};
use core::fmt;
use core::iter::FromIterator;

/// A set of `T`, implemented over `BTreeSet`.
#[derive(Clone, PartialEq, Eq)]
pub struct HashSet<T> {
    inner: BTreeSet<T>,
}

impl<T: Ord> HashSet<T> {
    /// An empty set.
    pub fn new() -> HashSet<T> {
        HashSet {
            inner: BTreeSet::new(),
        }
    }

    /// An empty set; `capacity` is accepted for std compatibility and ignored.
    pub fn with_capacity(capacity: usize) -> HashSet<T> {
        let _ = capacity;
        HashSet::new()
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when the set is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Remove every element.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Insert `value`; returns whether it was newly inserted.
    pub fn insert(&mut self, value: T) -> bool {
        self.inner.insert(value)
    }

    /// Remove `value`; returns whether it was present.
    pub fn remove<Q>(&mut self, value: &Q) -> bool
    where
        T: core::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.remove(value)
    }

    /// True when `value` is present.
    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: core::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.contains(value)
    }

    /// Iterate in ascending order.
    pub fn iter(&self) -> btree_set::Iter<'_, T> {
        self.inner.iter()
    }

    /// Accepted for std compatibility; a B-tree needs no reserve.
    pub fn reserve(&mut self, _additional: usize) {}

    /// The number of elements; a B-tree has no spare capacity.
    pub fn capacity(&self) -> usize {
        self.inner.len()
    }
}

impl<T: Ord> Default for HashSet<T> {
    fn default() -> HashSet<T> {
        HashSet::new()
    }
}

impl<T: Ord> Extend<T> for HashSet<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

impl<T: Ord> FromIterator<T> for HashSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> HashSet<T> {
        HashSet {
            inner: BTreeSet::from_iter(iter),
        }
    }
}

impl<T: Ord> IntoIterator for HashSet<T> {
    type Item = T;
    type IntoIter = btree_set::IntoIter<T>;

    fn into_iter(self) -> btree_set::IntoIter<T> {
        self.inner.into_iter()
    }
}

impl<'a, T: Ord> IntoIterator for &'a HashSet<T> {
    type Item = &'a T;
    type IntoIter = btree_set::Iter<'a, T>;

    fn into_iter(self) -> btree_set::Iter<'a, T> {
        self.inner.iter()
    }
}

impl<T: fmt::Debug> fmt::Debug for HashSet<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.inner.iter()).finish()
    }
}
