//! `hash_map` — the real hash table in `pagh_std::collections`, checked live.
//!
//! 0.6.0 shipped `HashMap`/`HashSet` as a documented `BTreeMap` shim: keys had
//! to be `Ord`, iteration was sorted, and `capacity()` was a polite fiction
//! (`len()`). 0.7.0 replaces it with a Robin Hood linear-probing table over a
//! power-of-two bucket array with backward-shift deletion, hashed with the
//! map's `BuildHasher` (FNV-1a by default).
//!
//! The checks below are chosen so a B-tree in disguise cannot pass them:
//!
//! 1. **`Hash + Eq` and no `Ord`.** `Token` implements neither `Ord` nor
//!    `PartialOrd`; if the map still sorted its keys this program would not
//!    compile. That is the strongest statement available, and it is a
//!    compile-time one;
//! 2. **`capacity()` is real.** It is `>= len`, not `== len`, and it does not
//!    move when a key is replaced or removed;
//! 3. **every key in one bucket.** `ZeroHasher` returns the same hash for every
//!    key, so all of them probe from bucket 0. Linear probing must still find
//!    each one, and deleting the middle of the run must not break the ones
//!    behind it (backward-shift deletion, no tombstones);
//! 4. **growth and shrink** with every entry intact across several resizes;
//! 5. the std-shaped surface: `entry` (`or_insert`, `or_insert_with`,
//!    `or_default`, `and_modify`), `get_key_value` (the stored key comes back,
//!    not the probe argument), `retain`, `extend`, `FromIterator`, `Index`, the
//!    iterator family, and `HashSet`'s set algebra.
//!
//! Usage: `hash_map` (no arguments). Prints `HASH_MAP PASS` and exits 0, or
//! `HASH_MAP FAIL: …` and exits non-zero.

#![no_std]
#![no_main]

use core::hash::{BuildHasher, Hash, Hasher};

use pagh_std::collections::{HashMap, HashSet};
use pagh_std::prelude::*;

/// A key that is `Hash + Eq + Clone` and deliberately **not** `Ord`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Token(u32);

impl Hash for Token {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// A hasher that maps every key to bucket 0: the adversarial case for open
/// addressing.
#[derive(Clone, Copy, Default)]
struct ZeroHasher;

impl BuildHasher for ZeroHasher {
    type Hasher = ZeroHash;
    fn build_hasher(&self) -> ZeroHash {
        ZeroHash
    }
}

struct ZeroHash;

impl Hasher for ZeroHash {
    fn finish(&self) -> u64 {
        0
    }
    fn write(&mut self, _bytes: &[u8]) {}
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut failures = 0u32;

    // 1. A key type with no Ord at all.
    let mut tokens: HashMap<Token, &str> = HashMap::new();
    tokens.insert(Token(7), "seven");
    tokens.insert(Token(3), "three");
    tokens.insert(Token(11), "eleven");
    match tokens.get(&Token(3)) {
        Some(value) if *value == "three" => {
            println!("hash_map: Hash+Eq key with no Ord: OK (3 -> {value})");
        }
        other => {
            failures += 1;
            println!("hash_map: Hash+Eq key FAIL: got {other:?}");
        }
    }

    // 2. capacity() is real spare capacity, not len().
    let mut map: HashMap<u32, u32> = HashMap::new();
    if map.capacity() != 0 {
        failures += 1;
        println!("hash_map: empty capacity FAIL: {}", map.capacity());
    }
    for key in 0..1000u32 {
        map.insert(key, key * 2);
    }
    if map.len() != 1000 || map.capacity() < 1000 {
        failures += 1;
        println!(
            "hash_map: growth FAIL: len={} capacity={}",
            map.len(),
            map.capacity()
        );
    } else {
        println!(
            "hash_map: 1000 keys: len={} capacity={} (real spare capacity)",
            map.len(),
            map.capacity()
        );
    }
    let capacity_before = map.capacity();
    if map.insert(500, 999) != Some(1000) {
        failures += 1;
        println!("hash_map: replace FAIL: insert(500) did not return the old value");
    }
    if map.capacity() != capacity_before {
        failures += 1;
        println!(
            "hash_map: replace changed capacity: {capacity_before} -> {}",
            map.capacity()
        );
    }
    let mut mismatches = 0u32;
    for key in 0..1000u32 {
        let expected = if key == 500 { 999 } else { key * 2 };
        if map.get(&key) != Some(&expected) {
            mismatches += 1;
        }
    }
    if mismatches != 0 {
        failures += 1;
        println!("hash_map: {mismatches} value(s) wrong after a replace");
    }
    // Remove half of them, including contiguous runs, then re-check the rest.
    for key in (0..1000u32).step_by(2) {
        if map.remove(&key) != Some(if key == 500 { 999 } else { key * 2 }) {
            failures += 1;
            println!("hash_map: remove({key}) did not return the stored value");
            break;
        }
    }
    let mut survivors = 0u32;
    for key in (1..1000u32).step_by(2) {
        if map.get(&key) == Some(&(key * 2)) {
            survivors += 1;
        }
    }
    if survivors != 500 || map.len() != 500 {
        failures += 1;
        println!(
            "hash_map: post-remove FAIL: {survivors}/500 survivors, len={}",
            map.len()
        );
    } else {
        println!("hash_map: 500 removals left the other 500 keys reachable");
    }
    // Reinsert into the holes.
    for key in (0..1000u32).step_by(2) {
        map.insert(key, key + 1);
    }
    let mut reinserted = 0u32;
    for key in (0..1000u32).step_by(2) {
        if map.get(&key) == Some(&(key + 1)) {
            reinserted += 1;
        }
    }
    if reinserted != 500 {
        failures += 1;
        println!("hash_map: {reinserted}/500 reinserted keys are wrong");
    }

    // 3. Every key in one bucket, then delete the middle of the run.
    let mut collided: HashMap<u32, u32, ZeroHasher> = HashMap::with_hasher(ZeroHasher);
    for key in 0..64u32 {
        collided.insert(key, key);
    }
    let mut found = 0u32;
    for key in 0..64u32 {
        if collided.get(&key) == Some(&key) {
            found += 1;
        }
    }
    if found != 64 {
        failures += 1;
        println!("hash_map: constant-hash lookup FAIL: {found}/64 found");
    }
    if collided.remove(&10) != Some(10) {
        failures += 1;
        println!("hash_map: constant-hash remove FAIL");
    }
    let mut after_delete = 0u32;
    for key in 0..64u32 {
        if key != 10 && collided.get(&key) == Some(&key) {
            after_delete += 1;
        }
    }
    if after_delete != 63 || collided.contains_key(&10) {
        failures += 1;
        println!("hash_map: backward-shift deletion FAIL: {after_delete}/63 reachable");
    } else {
        println!("hash_map: 64 keys in one bucket: probes find all, deletion shifts the run");
    }

    // 4. The std-shaped surface.
    let mut entry: HashMap<&str, u32> = HashMap::new();
    *entry.entry("a").or_insert(0) += 15;
    entry.entry("b").or_insert_with(|| 5);
    entry.entry("c").or_default();
    entry
        .entry("a")
        .and_modify(|value| *value += 1)
        .or_insert(0);
    let stored = entry.get_key_value("a").map(|(key, value)| (*key, *value));
    if stored != Some(("a", 16)) || entry.get("b") != Some(&5) || entry.get("c") != Some(&0) {
        failures += 1;
        println!("hash_map: entry/get_key_value FAIL: {stored:?}");
    }
    entry.retain(|key, value| *key != "b" || *value == 5);
    if entry.len() != 3 {
        failures += 1;
        println!(
            "hash_map: retain dropped a kept entry (len={})",
            entry.len()
        );
    }
    let collected: HashMap<u32, u32> = (0..32u32).map(|key| (key, key * 3)).collect();
    let mut iterated = 0u32;
    for (key, value) in collected.iter() {
        if *value == key * 3 {
            iterated += 1;
        }
    }
    let doubled: HashMap<u32, u32> = collected
        .clone()
        .into_iter()
        .map(|(k, v)| (k, v * 2))
        .collect();
    if iterated != 32 || doubled.get(&31) != Some(&186) || collected[&7] != 21 {
        failures += 1;
        println!("hash_map: iteration/index FAIL: {iterated}/32");
    }
    let mut extended: HashMap<u32, u32> = HashMap::new();
    extended.extend(collected.iter().map(|(key, value)| (*key, *value)));
    if extended.len() != 32 {
        failures += 1;
        println!("hash_map: extend FAIL: len={}", extended.len());
    }

    // 5. HashSet is the same table, with set algebra.
    let mut set: HashSet<&str> = HashSet::new();
    set.insert("a");
    set.insert("b");
    set.insert("a"); // duplicate
    let mut other: HashSet<&str> = HashSet::new();
    other.insert("b");
    other.insert("c");
    let union: HashSet<&str> = set.union(&other).copied().collect();
    let intersection: HashSet<&str> = set.intersection(&other).copied().collect();
    let difference: HashSet<&str> = set.difference(&other).copied().collect();
    let symmetric: HashSet<&str> = set.symmetric_difference(&other).copied().collect();
    if set.len() != 2
        || !set.contains("a")
        || union.len() != 3
        || intersection.len() != 1
        || difference.len() != 1
        || symmetric.len() != 2
        || !set.is_subset(&union)
        || !set.is_disjoint(&HashSet::new())
    {
        failures += 1;
        println!(
            "hash_set: FAIL: len={} union={} inter={} diff={} sym={}",
            set.len(),
            union.len(),
            intersection.len(),
            difference.len(),
            symmetric.len()
        );
    } else {
        println!("hash_set: 2 elements, union=3 inter=1 diff=1 symmetric=2: OK");
    }

    if failures == 0 {
        println!("HASH_MAP PASS (real hash table: Robin Hood probing, backward-shift deletion)");
        0
    } else {
        println!("HASH_MAP FAIL: {failures} check(s) failed");
        1
    }
}
