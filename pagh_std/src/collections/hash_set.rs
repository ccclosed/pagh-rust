//! A real hash set over [`HashMap`].
//!
//! [`HashSet`] is a thin wrapper around `HashMap<T, ()>`: the same Robin Hood
//! table, the same deterministic FNV-1a default hasher, the same documented
//! tradeoffs ([`HashMap`] module docs). `insert`/`contains`/`remove` are
//! expected O(1) and iteration order is unspecified.

use alloc::collections::TryReserveError;
use core::borrow::Borrow;
use core::fmt;
use core::hash::{BuildHasher, Hash};
use core::iter::FromIterator;

use super::hash_map::{self, HashMap};
use crate::hash::RandomState;

/// A set of `T`, std-shaped.
pub struct HashSet<T, S = RandomState> {
    map: HashMap<T, (), S>,
}

impl<T> HashSet<T, RandomState> {
    /// An empty set using the deterministic FNV-1a [`RandomState`].
    pub fn new() -> HashSet<T, RandomState> {
        HashSet {
            map: HashMap::new(),
        }
    }

    /// An empty set with room for at least `capacity` elements.
    pub fn with_capacity(capacity: usize) -> HashSet<T, RandomState> {
        HashSet {
            map: HashMap::with_capacity(capacity),
        }
    }
}

impl<T, S> HashSet<T, S> {
    /// An empty set using `state` as the hasher.
    pub fn with_hasher(state: S) -> HashSet<T, S> {
        HashSet {
            map: HashMap::with_hasher(state),
        }
    }

    /// An empty set with room for `capacity` elements and the given hasher.
    pub fn with_capacity_and_hasher(capacity: usize, state: S) -> HashSet<T, S> {
        HashSet {
            map: HashMap::with_capacity_and_hasher(capacity, state),
        }
    }

    /// The hasher this set uses.
    pub fn hasher(&self) -> &S {
        self.map.hasher()
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when the set is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Elements that fit before the next growth.
    pub fn capacity(&self) -> usize {
        self.map.capacity()
    }

    /// Remove every element, keeping the allocation.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Reserve room for `additional` more elements (aborts on OOM, as in std).
    pub fn reserve(&mut self, additional: usize) {
        self.map.reserve(additional);
    }

    /// Fallible [`reserve`](HashSet::reserve).
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.map.try_reserve(additional)
    }

    /// Shrink the table to the smallest size that still holds every element.
    pub fn shrink_to_fit(&mut self) {
        self.map.shrink_to_fit();
    }

    /// Iterate over the elements in unspecified order.
    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            inner: self.map.keys(),
        }
    }

    /// Drain every element, leaving the set empty but keeping its allocation.
    pub fn drain(&mut self) -> Drain<'_, T> {
        Drain {
            inner: self.map.drain(),
        }
    }

    /// Keep only the elements `keep` accepts; the predicate runs exactly once
    /// per element.
    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.map.retain(|element, _| keep(element));
    }
}

impl<T, S> HashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    /// Insert `value`; returns whether it was newly inserted.
    pub fn insert(&mut self, value: T) -> bool {
        self.map.insert(value, ()).is_none()
    }

    /// True when `value` is present.
    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.contains_key(value)
    }

    /// A reference to the element equal to `value`, if present.
    pub fn get<Q>(&self, value: &Q) -> Option<&T>
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get_key_value(value).map(|(stored, _)| stored)
    }

    /// Remove `value`; returns whether it was present.
    pub fn remove<Q>(&mut self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.remove(value).is_some()
    }

    /// Remove `value` and return the stored element.
    pub fn take<Q>(&mut self, value: &Q) -> Option<T>
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.remove_entry(value).map(|(stored, ())| stored)
    }

    /// Insert `value`, returning the element it replaced (if any).
    pub fn replace(&mut self, value: T) -> Option<T> {
        let previous = self.map.remove_entry(&value).map(|(stored, ())| stored);
        self.map.insert(value, ());
        previous
    }
}

impl<T, S> Default for HashSet<T, S>
where
    S: Default,
{
    fn default() -> HashSet<T, S> {
        HashSet {
            map: HashMap::with_hasher(S::default()),
        }
    }
}

impl<T: Clone, S: Clone> Clone for HashSet<T, S> {
    fn clone(&self) -> HashSet<T, S> {
        HashSet {
            map: self.map.clone(),
        }
    }
}

impl<T, S> PartialEq for HashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    fn eq(&self, other: &HashSet<T, S>) -> bool {
        self.map == other.map
    }
}

impl<T, S> Eq for HashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
}

impl<T: fmt::Debug, S> fmt::Debug for HashSet<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl<T, S> Extend<T> for HashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        let iterator = iter.into_iter();
        let (lower, _) = iterator.size_hint();
        if lower > 0 {
            self.reserve(lower);
        }
        for value in iterator {
            self.insert(value);
        }
    }
}

impl<T, S> FromIterator<T> for HashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher + Default,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> HashSet<T, S> {
        let mut set = HashSet::with_hasher(S::default());
        set.extend(iter);
        set
    }
}

impl<T, S> IntoIterator for HashSet<T, S> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> IntoIter<T> {
        IntoIter {
            inner: self.map.into_iter(),
        }
    }
}

impl<'a, T, S> IntoIterator for &'a HashSet<T, S> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<T, S> HashSet<T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    /// Elements of `self` that are not in `other`.
    pub fn difference<'a>(&'a self, other: &'a HashSet<T, S>) -> Difference<'a, T, S> {
        Difference {
            iter: self.iter(),
            other,
        }
    }

    /// Elements present in both sets.
    pub fn intersection<'a>(&'a self, other: &'a HashSet<T, S>) -> Intersection<'a, T, S> {
        Intersection {
            iter: self.iter(),
            other,
        }
    }

    /// Elements present in either set.
    pub fn union<'a>(&'a self, other: &'a HashSet<T, S>) -> Union<'a, T, S> {
        Union {
            first: self.iter(),
            second: other.iter(),
            first_set: self,
            marker: core::marker::PhantomData,
        }
    }

    /// Elements present in exactly one of the two sets.
    pub fn symmetric_difference<'a>(
        &'a self,
        other: &'a HashSet<T, S>,
    ) -> SymmetricDifference<'a, T, S> {
        SymmetricDifference {
            difference: self.difference(other),
            reverse: other.difference(self),
        }
    }

    /// Whether every element of `self` is in `other`.
    pub fn is_subset(&self, other: &HashSet<T, S>) -> bool {
        self.iter().all(|element| other.contains(element))
    }

    /// Whether every element of `other` is in `self`.
    pub fn is_superset(&self, other: &HashSet<T, S>) -> bool {
        other.is_subset(self)
    }

    /// Whether the two sets share no element.
    pub fn is_disjoint(&self, other: &HashSet<T, S>) -> bool {
        self.iter().all(|element| !other.contains(element))
    }
}

/// Iterator over `&T`, from [`HashSet::iter`].
pub struct Iter<'a, T> {
    inner: hash_map::Keys<'a, T, ()>,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Owning iterator, from `HashSet::into_iter`.
pub struct IntoIter<T> {
    inner: hash_map::IntoIter<T, ()>,
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.inner.next().map(|(element, ())| element)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Draining iterator, from [`HashSet::drain`].
pub struct Drain<'a, T> {
    inner: hash_map::Drain<'a, T, ()>,
}

impl<T> Iterator for Drain<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.inner.next().map(|(element, ())| element)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Iterator over `self \ other`, from [`HashSet::difference`].
pub struct Difference<'a, T, S> {
    iter: Iter<'a, T>,
    other: &'a HashSet<T, S>,
}

impl<'a, T, S> Iterator for Difference<'a, T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.iter
            .by_ref()
            .find(|element| !self.other.contains(*element))
    }
}

/// Iterator over `self ∩ other`, from [`HashSet::intersection`].
pub struct Intersection<'a, T, S> {
    iter: Iter<'a, T>,
    other: &'a HashSet<T, S>,
}

impl<'a, T, S> Iterator for Intersection<'a, T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.iter
            .by_ref()
            .find(|element| self.other.contains(*element))
    }
}

/// Iterator over `self ∪ other`, from [`HashSet::union`].
pub struct Union<'a, T, S> {
    first: Iter<'a, T>,
    second: Iter<'a, T>,
    /// `second` is filtered against this set, so an element present in both
    /// sets is yielded exactly once.
    first_set: &'a HashSet<T, S>,
    /// The union of two sets over one hasher; the parameter is part of the
    /// std-shaped type name even though the iterator does not consult it.
    marker: core::marker::PhantomData<S>,
}

impl<'a, T, S> Iterator for Union<'a, T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.first.next().or_else(|| {
            self.second
                .by_ref()
                .find(|element| !self.first_set.contains(*element))
        })
    }
}

/// Iterator over the symmetric difference, from
/// [`HashSet::symmetric_difference`].
pub struct SymmetricDifference<'a, T, S> {
    difference: Difference<'a, T, S>,
    reverse: Difference<'a, T, S>,
}

impl<'a, T, S> Iterator for SymmetricDifference<'a, T, S>
where
    T: Eq + Hash,
    S: BuildHasher,
{
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.difference.next().or_else(|| self.reverse.next())
    }
}
