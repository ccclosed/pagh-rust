//! A real open-addressing hash map, std-shaped.
//!
//! The table is **Robin Hood linear probing over a power-of-two bucket array**,
//! with backward-shift deletion (no tombstones) and a 3/4 maximum load factor.
//! It is a genuine hash table: `get`/`insert`/`remove` hash the key with the
//! map's [`BuildHasher`], probe, and return in expected O(1). The 0.6.0
//! `BTreeMap` shim is gone — this module does not require `Ord`, never
//! re-sorts, and `capacity()` reports real spare capacity.
//!
//! ## Layout
//!
//! ```text
//! buckets: [ None, Some{hash, key, value}, None, Some{...}, ... ]   (len = 2^n)
//!              ^ probe start = hash & mask; each collision steps to the next
//!                slot; an entry that has travelled further than the entry it
//!                meets takes that slot (Robin Hood), which keeps the probe
//!                distance distribution flat and makes lookups terminate at
//!                the first entry whose distance is smaller than ours.
//! ```
//!
//! The stored `hash` is the *mixed* hash. Mixing a [`Hasher`]'s output with
//! the standard 64-bit finalizer before taking the low bits is deliberate: a
//! `Hasher` is only required to be consistent, not well distributed in its low
//! bits, and the index comes from those bits. [`crate::hash::DefaultHasher`]
//! (FNV-1a) is a fine hasher but its avalanche is weak; one multiply-shift
//! finalizer per operation removes that dependency.
//!
//! ## Differences from `std::collections::HashMap`
//!
//! These are deliberate and tested, not approximations:
//!
//! * the default hasher is the deterministic FNV-1a [`RandomState`], not a
//!   randomly seeded SipHash — pagh has no entropy source in this ABI, so
//!   "random" would be a lie. **A map keyed by attacker-controlled strings is
//!   therefore not hash-flooding resistant**; the SDK documents that instead
//!   of pretending. Pass a different [`BuildHasher`] if the keys are hostile;
//! * iteration order is unspecified (bucket order), so it changes as the table
//!   grows — exactly like std, and unlike the old sorted shim;
//! * `try_reserve`/`try_reserve_exact` are real: allocation failure is a
//!   `TryReserveError` value, not an abort (`reserve` itself still aborts on
//!   OOM, as in std);
//! * `retain` rehashes nothing (backward-shift deletion is in place), and runs
//!   the predicate exactly once per entry;
//! * no `raw_entry`, no `hashbrown`-style `HashTable` re-export, and the map
//!   is not `Send`/`Sync` beyond what its contents already imply.
//!
//! ## Memory
//!
//! One `Vec<Option<Bucket>>` per map; the bump allocator behind `alloc` never
//! returns memory, so growth re-allocates a larger array and abandons the old
//! one (documented in the crate README). `with_capacity`/`reserve` avoid the
//! intermediate steps when the size is known up front.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt;
use core::hash::{BuildHasher, Hash};
use core::iter::FromIterator;

use crate::hash::RandomState;

/// Maximum live entries per bucket, as a fraction: `len * 4 <= buckets * 3`.
const LOAD_NUMERATOR: usize = 3;
/// Denominator of [`LOAD_NUMERATOR`].
const LOAD_DENOMINATOR: usize = 4;
/// Smallest table (`2^3` buckets), so a fresh map is usable after one resize.
const MIN_BUCKETS: usize = 8;

/// One occupied slot.
struct Bucket<K, V> {
    /// The mixed hash of `key` — the probe start and the comparison shortcut.
    hash: u64,
    key: K,
    value: V,
}

/// The bucket array and its live-entry count.
///
/// Split out of [`HashMap`] so [`Entry`] (which is `Entry<'a, K, V>`, without
/// the hasher type parameter, exactly like std) can borrow the table alone.
struct Table<K, V> {
    buckets: Vec<Option<Bucket<K, V>>>,
    len: usize,
}

/// Mix a hasher's output before it becomes a bucket index.
///
/// The finalizer from SplitMix64 (Steele et al. / `java.util.SplittableRandom`):
/// two multiply-shift rounds give full avalanche, so a hasher with weak low
/// bits (FNV-1a, the SDK default) still spreads keys uniformly over the
/// buckets. Consistency matters more than quality here: equal keys hash equal,
/// so the map stays correct with *any* `Hasher`.
#[inline]
const fn mix(hash: u64) -> u64 {
    let mut x = hash;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// A map from `K` to `V`, std-shaped.
///
/// ```ignore
/// let mut counts: HashMap<&str, u32> = HashMap::new();
/// for word in text.split(' ') {
///     *counts.entry(word).or_insert(0) += 1;
/// }
/// ```
pub struct HashMap<K, V, S = RandomState> {
    table: Table<K, V>,
    state: S,
}

impl<K, V> Table<K, V> {
    /// An empty table (no allocation until the first insert).
    const fn new() -> Table<K, V> {
        Table {
            buckets: Vec::new(),
            len: 0,
        }
    }

    /// The probe mask: `buckets.len() - 1` (a power of two, or 0 when empty).
    #[inline]
    fn mask(&self) -> usize {
        self.buckets.len().wrapping_sub(1)
    }

    /// The distance `index` is from its ideal slot, `0..buckets.len()`.
    #[inline]
    fn distance(&self, index: usize, hash: u64) -> usize {
        index.wrapping_sub(hash as usize) & self.mask()
    }

    /// How many entries fit before the next resize.
    #[inline]
    fn capacity(&self) -> usize {
        if self.buckets.is_empty() {
            0
        } else {
            self.buckets.len() / LOAD_DENOMINATOR * LOAD_NUMERATOR
        }
    }

    /// Whether `len + additional` still fits under the load factor.
    #[inline]
    fn has_room_for(&self, additional: usize) -> bool {
        let wanted = match self.len.checked_add(additional) {
            Some(wanted) => wanted,
            None => return false,
        };
        wanted <= self.capacity()
    }

    /// The bucket array length needed for `wanted` entries: `2^ceil(log2(2n))`.
    fn buckets_for(wanted: usize) -> usize {
        wanted
            .saturating_mul(2)
            .next_power_of_two()
            .max(MIN_BUCKETS)
    }

    /// Allocate a fresh bucket array of `buckets` slots, fallibly.
    fn fresh_buckets(buckets: usize) -> Result<Vec<Option<Bucket<K, V>>>, TryReserveError> {
        let mut fresh: Vec<Option<Bucket<K, V>>> = Vec::new();
        fresh.try_reserve_exact(buckets)?;
        fresh.resize_with(buckets, || None);
        Ok(fresh)
    }

    /// Re-insert one bucket without duplicate checking; the table must have room.
    ///
    /// This is Robin Hood insertion: while probing, an entry whose probe
    /// distance is shorter than the traveller's yields its slot, and the
    /// traveller continues with the displaced entry. Every bucket is stored
    /// with a distance no greater than the slot it was displaced to, which is
    /// what makes lookups stop early and keeps probe lengths bounded.
    fn raw_insert(&mut self, mut bucket: Bucket<K, V>) {
        let mask = self.mask();
        let mut index = (bucket.hash as usize) & mask;
        let mut distance = 0usize;
        loop {
            match self.buckets[index].take() {
                None => {
                    self.buckets[index] = Some(bucket);
                    return;
                }
                Some(mut existing) => {
                    let existing_distance = self.distance(index, existing.hash);
                    if existing_distance < distance {
                        core::mem::swap(&mut existing, &mut bucket);
                        distance = existing_distance;
                    }
                    self.buckets[index] = Some(existing);
                    index = (index + 1) & mask;
                    distance += 1;
                }
            }
        }
    }

    /// Grow (or shrink) to exactly `buckets` slots and rehash every entry.
    fn rehash_to(&mut self, buckets: usize) {
        let old = core::mem::replace(&mut self.buckets, Vec::new());
        // An OOM here aborts through the global allocator's handler; the map
        // has already given up its old array, so there is no inconsistent
        // half-state to observe (`panic = "abort"`).
        let mut fresh: Vec<Option<Bucket<K, V>>> = Vec::new();
        fresh.resize_with(buckets, || None);
        self.buckets = fresh;
        for bucket in old.into_iter().flatten() {
            self.raw_insert(bucket);
        }
    }

    /// Grow if `additional` more entries would not fit.
    fn grow_for(&mut self, additional: usize) {
        if !self.has_room_for(additional) {
            let wanted = self.len.saturating_add(additional).max(1);
            self.rehash_to(Self::buckets_for(wanted));
        }
    }

    /// Grow if needed, fallibly; the table is left unchanged on failure.
    fn try_grow_for(&mut self, additional: usize) -> Result<(), TryReserveError> {
        let wanted = match self.len.checked_add(additional) {
            Some(wanted) => wanted,
            None => return Err(capacity_overflow()),
        };
        if wanted <= self.capacity() {
            return Ok(());
        }
        let fresh = Self::fresh_buckets(Self::buckets_for(wanted))?;
        let old = core::mem::replace(&mut self.buckets, fresh);
        for bucket in old.into_iter().flatten() {
            self.raw_insert(bucket);
        }
        Ok(())
    }

    /// Where `hash`/`key` lives, if it is present.
    fn find_index<Q>(&self, hash: u64, key: &Q) -> Option<usize>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        if self.buckets.is_empty() {
            return None;
        }
        let mask = self.mask();
        let mut index = (hash as usize) & mask;
        let mut distance = 0usize;
        loop {
            match self.buckets[index].as_ref() {
                None => return None,
                Some(bucket) => {
                    if bucket.hash == hash && bucket.key.borrow() == key {
                        return Some(index);
                    }
                    // Robin Hood invariant: if the entry at this slot has
                    // travelled less than we have, the one we are looking for
                    // would have taken this slot on its way in — it is absent.
                    if self.distance(index, bucket.hash) < distance {
                        return None;
                    }
                    index = (index + 1) & mask;
                    distance += 1;
                }
            }
        }
    }

    /// Insert `bucket`, replacing the value of an equal key.
    ///
    /// Returns the replaced value (if any) and the slot the surviving entry
    /// occupies, so entry-style callers can hand out a reference without a
    /// second lookup.
    fn insert_bucket(&mut self, hash: u64, key: K, value: V) -> (Option<V>, usize)
    where
        K: Eq,
    {
        self.grow_for(1);
        let mask = self.mask();
        let mut index = (hash as usize) & mask;
        let mut distance = 0usize;
        let mut bucket = Bucket { hash, key, value };
        loop {
            match self.buckets[index].take() {
                None => {
                    self.buckets[index] = Some(bucket);
                    self.len += 1;
                    return (None, index);
                }
                Some(mut existing) => {
                    if existing.hash == hash && existing.key == bucket.key {
                        let replaced = core::mem::replace(&mut existing.value, bucket.value);
                        self.buckets[index] = Some(existing);
                        return (Some(replaced), index);
                    }
                    let existing_distance = self.distance(index, existing.hash);
                    if existing_distance < distance {
                        core::mem::swap(&mut existing, &mut bucket);
                        distance = existing_distance;
                    }
                    self.buckets[index] = Some(existing);
                    index = (index + 1) & mask;
                    distance += 1;
                }
            }
        }
    }

    /// Insert a bucket whose key is known to be absent; returns its slot.
    ///
    /// This is [`Table::insert_bucket`] without the duplicate check, for the
    /// entry API: a [`VacantEntry`] already established that the key is not
    /// present, so no `Eq` bound is needed here (and `Entry::or_insert` must
    /// not require one, exactly like std).
    fn insert_new(&mut self, hash: u64, key: K, value: V) -> usize {
        self.grow_for(1);
        let mask = self.mask();
        let mut index = (hash as usize) & mask;
        let mut distance = 0usize;
        let mut bucket = Bucket { hash, key, value };
        loop {
            match self.buckets[index].take() {
                None => {
                    self.buckets[index] = Some(bucket);
                    self.len += 1;
                    return index;
                }
                Some(mut existing) => {
                    let existing_distance = self.distance(index, existing.hash);
                    if existing_distance < distance {
                        core::mem::swap(&mut existing, &mut bucket);
                        distance = existing_distance;
                    }
                    self.buckets[index] = Some(existing);
                    index = (index + 1) & mask;
                    distance += 1;
                }
            }
        }
    }

    /// Remove the entry at `index` (which must be occupied), shifting the
    /// following run of displaced entries back by one slot.
    ///
    /// Backward-shift deletion leaves no tombstone: the run is walked forward
    /// while every entry found has travelled at least one step, each moved into
    /// the hole; the first entry found at its ideal slot (or an empty slot)
    /// stops the walk. That entry is written back where it was, and the hole
    /// moves to the end of the run.
    fn remove_index(&mut self, index: usize) -> Option<Bucket<K, V>> {
        let removed = self.buckets.get_mut(index)?.take()?;
        self.len -= 1;
        let mask = self.mask();
        let mut hole = index;
        loop {
            let next = (hole + 1) & mask;
            match self.buckets[next].take() {
                None => break,
                Some(bucket) => {
                    if self.distance(next, bucket.hash) == 0 {
                        // At home: leave it and close the hole before it.
                        self.buckets[next] = Some(bucket);
                        break;
                    }
                    self.buckets[hole] = Some(bucket);
                    hole = next;
                }
            }
        }
        Some(removed)
    }

    /// Remove the entry for `hash`/`key`, returning key and value.
    fn remove_entry<Q>(&mut self, hash: u64, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let index = self.find_index(hash, key)?;
        let removed = self.remove_index(index)?;
        Some((removed.key, removed.value))
    }

    /// Drop every entry, keeping the allocation.
    fn clear(&mut self) {
        for slot in self.buckets.iter_mut() {
            *slot = None;
        }
        self.len = 0;
    }

    /// The bucket at `index`, which the caller knows is occupied.
    fn occupied_mut(&mut self, index: usize) -> &mut Bucket<K, V> {
        match self.buckets[index].as_mut() {
            Some(bucket) => bucket,
            // Only reachable if table bookkeeping is broken; a programmer bug,
            // not a user-input path.
            None => panic!("hash map: slot {index} is empty inside the table"),
        }
    }
}

/// The error `Vec` reports for an impossible capacity.
///
/// `TryReserveError` has no public constructor and `TryReserveErrorKind` is
/// unstable, so the portable way to produce one is to ask a `Vec` for a
/// reservation that cannot succeed and keep the error it returns.
fn capacity_overflow() -> TryReserveError {
    let mut probe: Vec<u8> = Vec::new();
    match probe.try_reserve_exact(usize::MAX) {
        Err(error) => error,
        // A `Vec<u8>` of `usize::MAX` elements overflows `isize::MAX` bytes,
        // so this is unreachable on every target this SDK builds for.
        Ok(()) => panic!("hash map: capacity overflow is not reportable"),
    }
}

impl<K, V> Table<K, V> {
    /// In-place retain, predicate called exactly once per entry.
    fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        let mut index = 0;
        while index < self.buckets.len() {
            let remove = match self.buckets[index].as_mut() {
                Some(bucket) => !keep(&bucket.key, &mut bucket.value),
                None => false,
            };
            if remove {
                // Backward-shift deletion may pull an unvisited entry into
                // `index`, so do not advance; entries at lower indices never
                // move, so nothing is visited twice.
                let _ = self.remove_index(index);
            } else {
                index += 1;
            }
        }
    }
}

impl<K, V> HashMap<K, V, RandomState> {
    /// An empty map using the deterministic FNV-1a [`RandomState`].
    pub fn new() -> HashMap<K, V, RandomState> {
        HashMap {
            table: Table::new(),
            state: RandomState::new(),
        }
    }

    /// An empty map with room for at least `capacity` entries.
    pub fn with_capacity(capacity: usize) -> HashMap<K, V, RandomState> {
        HashMap::with_capacity_and_hasher(capacity, RandomState::new())
    }
}

impl<K, V, S> HashMap<K, V, S> {
    /// An empty map using `state` as the hasher.
    pub fn with_hasher(state: S) -> HashMap<K, V, S> {
        HashMap {
            table: Table::new(),
            state,
        }
    }

    /// An empty map with room for `capacity` entries and the given hasher.
    pub fn with_capacity_and_hasher(capacity: usize, state: S) -> HashMap<K, V, S> {
        let mut map = HashMap {
            table: Table::new(),
            state,
        };
        if capacity > 0 {
            map.table.grow_for(capacity);
        }
        map
    }

    /// The hasher this map uses.
    pub fn hasher(&self) -> &S {
        &self.state
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.table.len
    }

    /// True when there are no entries.
    pub fn is_empty(&self) -> bool {
        self.table.len == 0
    }

    /// Entries that fit before the next growth.
    pub fn capacity(&self) -> usize {
        self.table.capacity()
    }

    /// Remove every entry, keeping the allocation.
    pub fn clear(&mut self) {
        self.table.clear();
    }

    /// Reserve room for `additional` more entries (aborts on OOM, as in std).
    pub fn reserve(&mut self, additional: usize) {
        self.table.grow_for(additional);
    }

    /// Fallible [`reserve`](HashMap::reserve): allocation failure is returned.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.table.try_grow_for(additional)
    }

    /// Shrink the table to the smallest size that still holds every entry.
    pub fn shrink_to_fit(&mut self) {
        let wanted = Table::<K, V>::buckets_for(self.table.len);
        if wanted < self.table.buckets.len() {
            self.table.rehash_to(wanted);
        }
    }

    /// Run `keep` on every entry and drop the ones it rejects.
    ///
    /// The predicate runs exactly once per entry; iteration order is bucket
    /// order (unspecified). Deletion is in place, with no rehash and no second
    /// allocation.
    pub fn retain<F>(&mut self, keep: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.table.retain(keep);
    }

    /// Iterate over `(&K, &V)` pairs in unspecified order.
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            inner: self.table.buckets.iter(),
        }
    }

    /// Iterate mutably over `(&K, &mut V)` pairs in unspecified order.
    pub fn iter_mut(&mut self) -> IterMut<'_, K, V> {
        IterMut {
            inner: self.table.buckets.iter_mut(),
        }
    }

    /// Iterate over the keys.
    pub fn keys(&self) -> Keys<'_, K, V> {
        Keys { inner: self.iter() }
    }

    /// Iterate over the values.
    pub fn values(&self) -> Values<'_, K, V> {
        Values { inner: self.iter() }
    }

    /// Iterate mutably over the values.
    pub fn values_mut(&mut self) -> ValuesMut<'_, K, V> {
        ValuesMut {
            inner: self.iter_mut(),
        }
    }

    /// Drain every entry, leaving the map empty but keeping its allocation.
    ///
    /// The items are owned (as in std), and the bucket array stays where it
    /// is: dropping the iterator early (or forgetting it) still empties the
    /// map and drops the entries it did not yield.
    pub fn drain(&mut self) -> Drain<'_, K, V> {
        self.table.len = 0;
        Drain {
            table: &mut self.table,
            index: 0,
        }
    }
}

impl<K, V, S> HashMap<K, V, S>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    /// The mixed hash of one key.
    fn hash_key<Q>(&self, key: &Q) -> u64
    where
        Q: Hash + ?Sized,
    {
        mix(self.state.hash_one(key))
    }

    /// The value stored for `key`.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_key(key);
        let index = self.table.find_index(hash, key)?;
        match self.table.buckets[index].as_ref() {
            Some(bucket) => Some(&bucket.value),
            None => None,
        }
    }

    /// The value stored for `key`, mutably.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_key(key);
        let index = self.table.find_index(hash, key)?;
        self.table.buckets[index]
            .as_mut()
            .map(|bucket| &mut bucket.value)
    }

    /// The stored key and value for `key`.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_key(key);
        let index = self.table.find_index(hash, key)?;
        self.table.buckets[index]
            .as_ref()
            .map(|bucket| (&bucket.key, &bucket.value))
    }

    /// Whether `key` is present.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.get(key).is_some()
    }

    /// Insert `value` under `key`, returning the previous value.
    ///
    /// The key is kept as given: an existing key is *not* replaced by the new
    /// one (its value is), matching std.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let hash = self.hash_key(&key);
        let (replaced, _) = self.table.insert_bucket(hash, key, value);
        replaced
    }

    /// Remove `key`, returning its value.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.remove_entry(key).map(|(_, value)| value)
    }

    /// Remove `key`, returning the stored key and value.
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.hash_key(key);
        self.table.remove_entry(hash, key)
    }

    /// The entry for `key`, for in-place insertion or update.
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
        let hash = self.hash_key(&key);
        match self.table.find_index(hash, &key) {
            Some(index) => Entry::Occupied(OccupiedEntry {
                table: &mut self.table,
                index,
            }),
            None => Entry::Vacant(VacantEntry {
                table: &mut self.table,
                hash,
                key: Some(key),
            }),
        }
    }
}

impl<K, V, S: Default> Default for HashMap<K, V, S> {
    fn default() -> HashMap<K, V, S> {
        HashMap::with_hasher(S::default())
    }
}

impl<K: Clone, V: Clone, S: Clone> Clone for HashMap<K, V, S> {
    fn clone(&self) -> HashMap<K, V, S> {
        let mut table = Table::new();
        table
            .buckets
            .try_reserve_exact(self.table.buckets.len())
            .ok();
        table.buckets.resize_with(self.table.buckets.len(), || None);
        table.len = self.table.len;
        for (index, slot) in self.table.buckets.iter().enumerate() {
            if let Some(bucket) = slot {
                table.buckets[index] = Some(Bucket {
                    hash: bucket.hash,
                    key: bucket.key.clone(),
                    value: bucket.value.clone(),
                });
            }
        }
        HashMap {
            table,
            state: self.state.clone(),
        }
    }
}

impl<K: fmt::Debug, V: fmt::Debug, S> fmt::Debug for HashMap<K, V, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<K, V, S> PartialEq for HashMap<K, V, S>
where
    K: Eq + Hash,
    V: PartialEq,
    S: BuildHasher,
{
    fn eq(&self, other: &HashMap<K, V, S>) -> bool {
        if self.len() != other.len() {
            return false;
        }
        // Both maps use their own hasher, so compare through the entries: the
        // values must match for every key this map holds.
        self.iter().all(|(key, value)| match other.get(key) {
            Some(other_value) => value == other_value,
            None => false,
        })
    }
}

impl<K, V, S> Eq for HashMap<K, V, S>
where
    K: Eq + Hash,
    V: Eq,
    S: BuildHasher,
{
}

impl<K, V, S> Extend<(K, V)> for HashMap<K, V, S>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        let iterator = iter.into_iter();
        // A sized source is a hint, not a promise: reserve what it advertises
        // so a bulk load does not resize once per entry.
        let (lower, _) = iterator.size_hint();
        if lower > 0 {
            self.reserve(lower);
        }
        for (key, value) in iterator {
            self.insert(key, value);
        }
    }
}

impl<K, V, S> FromIterator<(K, V)> for HashMap<K, V, S>
where
    K: Eq + Hash,
    S: BuildHasher + Default,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> HashMap<K, V, S> {
        let mut map = HashMap::with_hasher(S::default());
        map.extend(iter);
        map
    }
}

impl<K, V, S> IntoIterator for HashMap<K, V, S> {
    type Item = (K, V);
    type IntoIter = IntoIter<K, V>;

    fn into_iter(self) -> IntoIter<K, V> {
        IntoIter {
            inner: self.table.buckets.into_iter(),
        }
    }
}

impl<'a, K, V, S> IntoIterator for &'a HashMap<K, V, S> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Iter<'a, K, V> {
        self.iter()
    }
}

impl<'a, K, V, S> IntoIterator for &'a mut HashMap<K, V, S> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V>;

    fn into_iter(self) -> IterMut<'a, K, V> {
        self.iter_mut()
    }
}

impl<K, V, S, Q> core::ops::Index<&Q> for HashMap<K, V, S>
where
    K: Eq + Hash + Borrow<Q>,
    Q: Eq + Hash + ?Sized,
    S: BuildHasher,
{
    type Output = V;

    /// The value for `key`; panics when the key is absent, exactly like std.
    fn index(&self, key: &Q) -> &V {
        match self.get(key) {
            Some(value) => value,
            None => panic!("hash map: no entry found for key"),
        }
    }
}

// ─── entry API ──────────────────────────────────────────────────────────────

/// A view into one entry of a [`HashMap`].
pub enum Entry<'a, K, V> {
    /// The key is present.
    Occupied(OccupiedEntry<'a, K, V>),
    /// The key is absent.
    Vacant(VacantEntry<'a, K, V>),
}

impl<'a, K, V> Entry<'a, K, V> {
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

impl<'a, K: fmt::Debug, V: fmt::Debug> fmt::Debug for Entry<'a, K, V> {
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

/// An occupied [`Entry`], borrowed from its map's table.
pub struct OccupiedEntry<'a, K, V> {
    table: &'a mut Table<K, V>,
    index: usize,
}

impl<'a, K, V> OccupiedEntry<'a, K, V> {
    /// The key of this entry.
    pub fn key(&self) -> &K {
        match self.table.buckets[self.index].as_ref() {
            Some(bucket) => &bucket.key,
            None => panic!("hash map: occupied entry's slot is empty"),
        }
    }

    /// The value.
    pub fn get(&self) -> &V {
        match self.table.buckets[self.index].as_ref() {
            Some(bucket) => &bucket.value,
            None => panic!("hash map: occupied entry's slot is empty"),
        }
    }

    /// The value, mutably.
    pub fn get_mut(&mut self) -> &mut V {
        &mut self.table.occupied_mut(self.index).value
    }

    /// Consume the entry and return the value mutably.
    pub fn into_mut(self) -> &'a mut V {
        &mut self.table.occupied_mut(self.index).value
    }

    /// Replace the value, returning the old one.
    pub fn insert(&mut self, value: V) -> V {
        core::mem::replace(&mut self.table.occupied_mut(self.index).value, value)
    }

    /// Remove the entry, returning its value.
    pub fn remove(self) -> V {
        match self.table.remove_index(self.index) {
            Some(bucket) => bucket.value,
            None => panic!("hash map: occupied entry's slot is empty"),
        }
    }

    /// Remove the entry, returning key and value.
    pub fn remove_entry(self) -> (K, V) {
        match self.table.remove_index(self.index) {
            Some(bucket) => (bucket.key, bucket.value),
            None => panic!("hash map: occupied entry's slot is empty"),
        }
    }
}

/// A vacant [`Entry`]: the key that was looked up, and where it hashed.
pub struct VacantEntry<'a, K, V> {
    table: &'a mut Table<K, V>,
    hash: u64,
    key: Option<K>,
}

impl<'a, K, V> VacantEntry<'a, K, V> {
    /// The key of this entry.
    pub fn key(&self) -> &K {
        match self.key.as_ref() {
            Some(key) => key,
            None => panic!("hash map: vacant entry's key was taken"),
        }
    }

    /// Take ownership of the key.
    pub fn into_key(mut self) -> K {
        match self.key.take() {
            Some(key) => key,
            None => panic!("hash map: vacant entry's key was taken"),
        }
    }

    /// Insert a value and return a mutable reference to it.
    pub fn insert(mut self, value: V) -> &'a mut V {
        let key = match self.key.take() {
            Some(key) => key,
            None => panic!("hash map: vacant entry's key was taken"),
        };
        let index = self.table.insert_new(self.hash, key, value);
        &mut self.table.occupied_mut(index).value
    }
}

// ─── iterators ──────────────────────────────────────────────────────────────

/// Iterator over `(&K, &V)` pairs, from [`HashMap::iter`].
pub struct Iter<'a, K, V> {
    inner: core::slice::Iter<'a, Option<Bucket<K, V>>>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        for slot in self.inner.by_ref() {
            if let Some(bucket) = slot {
                return Some((&bucket.key, &bucket.value));
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.inner.len()))
    }
}

/// Iterator over `(&K, &mut V)` pairs, from [`HashMap::iter_mut`].
pub struct IterMut<'a, K, V> {
    inner: core::slice::IterMut<'a, Option<Bucket<K, V>>>,
}

impl<'a, K, V> Iterator for IterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        for slot in self.inner.by_ref() {
            if let Some(bucket) = slot {
                return Some((&bucket.key, &mut bucket.value));
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.inner.len()))
    }
}

/// Iterator over keys, from [`HashMap::keys`].
pub struct Keys<'a, K, V> {
    inner: Iter<'a, K, V>,
}

impl<'a, K, V> Iterator for Keys<'a, K, V> {
    type Item = &'a K;

    fn next(&mut self) -> Option<&'a K> {
        self.inner.next().map(|(key, _)| key)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Iterator over values, from [`HashMap::values`].
pub struct Values<'a, K, V> {
    inner: Iter<'a, K, V>,
}

impl<'a, K, V> Iterator for Values<'a, K, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<&'a V> {
        self.inner.next().map(|(_, value)| value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Iterator over mutable values, from [`HashMap::values_mut`].
pub struct ValuesMut<'a, K, V> {
    inner: IterMut<'a, K, V>,
}

impl<'a, K, V> Iterator for ValuesMut<'a, K, V> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<&'a mut V> {
        self.inner.next().map(|(_, value)| value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Owning iterator, from `HashMap::into_iter`.
pub struct IntoIter<K, V> {
    inner: alloc::vec::IntoIter<Option<Bucket<K, V>>>,
}

impl<K, V> Iterator for IntoIter<K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<(K, V)> {
        for slot in self.inner.by_ref() {
            if let Some(bucket) = slot {
                return Some((bucket.key, bucket.value));
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.inner.len()))
    }
}

/// Draining iterator, from [`HashMap::drain`].
pub struct Drain<'a, K, V> {
    table: &'a mut Table<K, V>,
    index: usize,
}

impl<K, V> Iterator for Drain<'_, K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<(K, V)> {
        while self.index < self.table.buckets.len() {
            let slot = &mut self.table.buckets[self.index];
            self.index += 1;
            if let Some(bucket) = slot.take() {
                return Some((bucket.key, bucket.value));
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.table.len))
    }
}

impl<K, V> Drop for Drain<'_, K, V> {
    /// Drop the entries not yielded: `drain()` emptied the map already, and a
    /// half-consumed drain must not leave live values behind an empty table.
    fn drop(&mut self) {
        while self.index < self.table.buckets.len() {
            let _ = self.table.buckets[self.index].take();
            self.index += 1;
        }
    }
}
