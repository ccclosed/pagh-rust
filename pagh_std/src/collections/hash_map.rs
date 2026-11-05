//! A documented `BTreeMap` shim named `HashMap`.
//!
//! The surface follows `std::collections::HashMap` closely enough for ordinary
//! application code: `new`, `with_capacity`, `insert`, `get`, `get_mut`,
//! `remove`, `entry`, the iterator family, `extend`, `FromIterator`, and the
//! `Index`-free read API. The differences are deliberate and documented:
//!
//! * keys need `Ord`, not `Hash + Eq`;
//! * iteration is sorted by key, not unspecified;
//! * `capacity()` reports `len()` and `reserve()` is a no-op (a B-tree has no
//!   capacity);
//! * the hasher type parameter exists for source compatibility but is not
//!   consulted. [`crate::hash::RandomState`] is deterministic anyway.

use alloc::collections::btree_map::{self, BTreeMap};
use core::borrow::Borrow;
use core::fmt;
use core::iter::FromIterator;

use crate::hash::RandomState;

/// A map from `K` to `V`, implemented over `BTreeMap`.
pub struct HashMap<K, V, S = RandomState> {
    inner: BTreeMap<K, V>,
    state: S,
}

impl<K: Ord, V> HashMap<K, V, RandomState> {
    /// An empty map.
    pub fn new() -> HashMap<K, V, RandomState> {
        HashMap {
            inner: BTreeMap::new(),
            state: RandomState,
        }
    }

    /// An empty map; `capacity` is accepted for std compatibility and ignored.
    pub fn with_capacity(capacity: usize) -> HashMap<K, V, RandomState> {
        Self::with_capacity_and_hasher(capacity, RandomState)
    }
}

impl<K: Ord, V, S> HashMap<K, V, S> {
    /// An empty map using `state` as the (unused) hasher.
    pub fn with_hasher(state: S) -> HashMap<K, V, S> {
        HashMap {
            inner: BTreeMap::new(),
            state,
        }
    }

    /// An empty map; `capacity` is ignored because the backing store is a
    /// B-tree.
    pub fn with_capacity_and_hasher(capacity: usize, state: S) -> HashMap<K, V, S> {
        let _ = capacity;
        HashMap {
            inner: BTreeMap::new(),
            state,
        }
    }

    /// The stored hasher (never consulted by this shim).
    pub fn hasher(&self) -> &S {
        &self.state
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when there are no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Remove every entry.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// The number of entries; a B-tree has no spare capacity.
    pub fn capacity(&self) -> usize {
        self.inner.len()
    }

    /// Accepted for std compatibility; a B-tree needs no reserve.
    pub fn reserve(&mut self, _additional: usize) {}

    /// Accepted for std compatibility; a B-tree needs no shrinking.
    pub fn shrink_to_fit(&mut self) {}

    /// Look up `key`.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.get(key)
    }

    /// Look up `key` mutably.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.get_mut(key)
    }

    /// Look up `key`, returning both key and value.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.get_key_value(key)
    }

    /// True when `key` is present.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.contains_key(key)
    }

    /// Insert a value, returning the previous one.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    /// Remove `key`, returning its value.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.remove(key)
    }

    /// Remove `key`, returning both key and value.
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.remove_entry(key)
    }

    /// Iterate in ascending key order.
    pub fn iter(&self) -> btree_map::Iter<'_, K, V> {
        self.inner.iter()
    }

    /// Iterate mutably in ascending key order.
    pub fn iter_mut(&mut self) -> btree_map::IterMut<'_, K, V> {
        self.inner.iter_mut()
    }

    /// Iterate over keys in ascending order.
    pub fn keys(&self) -> btree_map::Keys<'_, K, V> {
        self.inner.keys()
    }

    /// Iterate over values in ascending key order.
    pub fn values(&self) -> btree_map::Values<'_, K, V> {
        self.inner.values()
    }

    /// Iterate over values mutably in ascending key order.
    pub fn values_mut(&mut self) -> btree_map::ValuesMut<'_, K, V> {
        self.inner.values_mut()
    }

    /// Keep only entries for which `keep` returns true.
    pub fn retain<F: FnMut(&K, &mut V) -> bool>(&mut self, mut keep: F) {
        self.inner.retain(|key, value| keep(key, value));
    }

    /// Get the entry for `key` for in-place insertion or update.
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
        match self.inner.entry(key) {
            btree_map::Entry::Occupied(entry) => Entry::Occupied(OccupiedEntry(entry)),
            btree_map::Entry::Vacant(entry) => Entry::Vacant(VacantEntry(entry)),
        }
    }
}

impl<K: Ord, V, S: Default> Default for HashMap<K, V, S> {
    fn default() -> HashMap<K, V, S> {
        HashMap::with_hasher(S::default())
    }
}

impl<K: Clone + Ord, V: Clone, S: Clone> Clone for HashMap<K, V, S> {
    fn clone(&self) -> HashMap<K, V, S> {
        HashMap {
            inner: self.inner.clone(),
            state: self.state.clone(),
        }
    }
}

impl<K: fmt::Debug, V: fmt::Debug, S> fmt::Debug for HashMap<K, V, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.inner.iter()).finish()
    }
}

impl<K: PartialEq + Ord, V: PartialEq, S> PartialEq for HashMap<K, V, S> {
    fn eq(&self, other: &HashMap<K, V, S>) -> bool {
        self.inner == other.inner
    }
}

impl<K: Eq + Ord, V: Eq, S> Eq for HashMap<K, V, S> {}

impl<K: Ord, V, S> Extend<(K, V)> for HashMap<K, V, S> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

impl<K: Ord, V, S: Default> FromIterator<(K, V)> for HashMap<K, V, S> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> HashMap<K, V, S> {
        let mut map = HashMap::with_hasher(S::default());
        map.extend(iter);
        map
    }
}

impl<K: Ord, V, S> IntoIterator for HashMap<K, V, S> {
    type Item = (K, V);
    type IntoIter = btree_map::IntoIter<K, V>;

    fn into_iter(self) -> btree_map::IntoIter<K, V> {
        self.inner.into_iter()
    }
}

impl<'a, K: Ord, V, S> IntoIterator for &'a HashMap<K, V, S> {
    type Item = (&'a K, &'a V);
    type IntoIter = btree_map::Iter<'a, K, V>;

    fn into_iter(self) -> btree_map::Iter<'a, K, V> {
        self.inner.iter()
    }
}

impl<'a, K: Ord, V, S> IntoIterator for &'a mut HashMap<K, V, S> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = btree_map::IterMut<'a, K, V>;

    fn into_iter(self) -> btree_map::IterMut<'a, K, V> {
        self.inner.iter_mut()
    }
}

/// A view into one entry of a [`HashMap`].
pub enum Entry<'a, K, V> {
    /// The key is present.
    Occupied(OccupiedEntry<'a, K, V>),
    /// The key is absent.
    Vacant(VacantEntry<'a, K, V>),
}

impl<'a, K: Ord, V> Entry<'a, K, V> {
    /// The key this entry refers to.
    pub fn key(&self) -> &K {
        match self {
            Entry::Occupied(entry) => entry.key(),
            Entry::Vacant(entry) => entry.key(),
        }
    }

    /// Insert `default` if vacant; return a mutable reference to the value.
    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default),
        }
    }

    /// Insert the result of `default` if vacant.
    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default()),
        }
    }

    /// Insert `V::default()` if vacant.
    pub fn or_default(self) -> &'a mut V
    where
        V: Default,
    {
        self.or_insert_with(V::default)
    }

    /// Run `f` on the value if the entry is occupied.
    pub fn and_modify<F: FnOnce(&mut V)>(self, f: F) -> Entry<'a, K, V> {
        match self {
            Entry::Occupied(mut entry) => {
                f(entry.get_mut());
                Entry::Occupied(entry)
            }
            Entry::Vacant(entry) => Entry::Vacant(entry),
        }
    }
}

/// An occupied [`Entry`].
pub struct OccupiedEntry<'a, K, V>(btree_map::OccupiedEntry<'a, K, V>);

impl<'a, K: Ord, V> OccupiedEntry<'a, K, V> {
    /// The key of this entry.
    pub fn key(&self) -> &K {
        self.0.key()
    }

    /// The value.
    pub fn get(&self) -> &V {
        self.0.get()
    }

    /// The value, mutably.
    pub fn get_mut(&mut self) -> &mut V {
        self.0.get_mut()
    }

    /// Consume the entry and return the value mutably.
    pub fn into_mut(self) -> &'a mut V {
        self.0.into_mut()
    }

    /// Replace the value, returning the old one.
    pub fn insert(&mut self, value: V) -> V {
        self.0.insert(value)
    }

    /// Remove the entry, returning its value.
    pub fn remove(self) -> V {
        self.0.remove()
    }

    /// Remove the entry, returning key and value.
    pub fn remove_entry(self) -> (K, V) {
        self.0.remove_entry()
    }
}

/// A vacant [`Entry`].
pub struct VacantEntry<'a, K, V>(btree_map::VacantEntry<'a, K, V>);

impl<'a, K: Ord, V> VacantEntry<'a, K, V> {
    /// The key of this entry.
    pub fn key(&self) -> &K {
        self.0.key()
    }

    /// Take ownership of the key.
    pub fn into_key(self) -> K {
        self.0.into_key()
    }

    /// Insert a value and return a mutable reference to it.
    pub fn insert(self, value: V) -> &'a mut V {
        self.0.insert(value)
    }
}

impl<'a, K: Ord, V> fmt::Debug for Entry<'a, K, V>
where
    K: fmt::Debug,
    V: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Entry::Occupied(entry) => f
                .debug_tuple("Occupied")
                .field(&entry.key())
                .field(&entry.get())
                .finish(),
            Entry::Vacant(entry) => f.debug_tuple("Vacant").field(entry.key()).finish(),
        }
    }
}
