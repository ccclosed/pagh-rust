//! Host-only tests for the pure logic in `pagh_std`.
//!
//! `pagh_std` itself cannot be compiled for the host: `libpagh` is a bare-metal
//! RISC-V crate whose syscall module contains `ecall` assembly. The path,
//! formatting and single-threaded `LazyLock` logic, however, uses only `core` +
//! `alloc`, so this crate includes those source files directly and tests them
//! with the host toolchain:
//!
//! ```sh
//! cargo test -p pagh_hostcheck --target x86_64-unknown-linux-gnu
//! ```
//!
//! CI runs exactly that. It is not a substitute for the QEMU transcript; it is
//! the fast loop for component/display/normalization semantics.

#![allow(dead_code)]
// The included modules re-export their full public surface; this host-only
// crate uses only the parts the tests exercise.
#![allow(unused_imports)]

extern crate alloc;

#[path = "../../pagh_std/src/path.rs"]
mod path;

// These modules are also pure `core` + `alloc`; including them here means the
// host test gate covers the collection shims, the deterministic hasher and the
// single-threaded LazyLock without compiling libpagh's RISC-V syscalls.
//
// LazyLock lives in `pagh_std/src/lazy.rs` rather than `sync.rs` precisely so
// this gate can include it: `sync.rs` now also owns the futex-backed Mutex,
// RwLock and Condvar, which import `libpagh` and cannot be built for the host.
#[path = "../../pagh_std/src/hash.rs"]
mod hash;
#[path = "../../pagh_std/src/collections/hash_map.rs"]
mod hash_map;
#[path = "../../pagh_std/src/collections/hash_set.rs"]
mod hash_set;
#[path = "../../pagh_std/src/lazy.rs"]
mod lazy;

// The 0.7.0 pure layers: the RFC 1035 codec the resolver speaks, the RFC 6125
// hostname matcher the TLS verifier authorizes with, and the HTTP/1.1 head
// parser the fetch uses. All three are `core` + `alloc` only, so they are
// tested here with adversarial input instead of only against a live server.
// `hostname` belongs to the vendored (feature `vendored-tls`) verifier; it is
// included unconditionally because it is pure and the gate is cheap.
#[path = "../../pagh_std/src/net/dns_wire.rs"]
mod dns_wire;
#[path = "../../pagh_std/src/tls/vendored/hostname.rs"]
mod hostname;
#[path = "../../pagh_std/src/tls/http.rs"]
mod http;

// The 0.8.0 pure layer: the `https://host[:port][/path]` parser the
// kernel-backed `tls::https_get` feeds to `tls_connect`. It decides which name
// the certificate gets checked against, so it is exactly the kind of code that
// must be tested against adversarial input rather than only against a live URL.
#[path = "../../pagh_std/src/tls/url.rs"]
mod tls_url;

#[cfg(test)]
mod tests {
    use super::path::{normalize, normalize_join, Path, PathBuf};

    fn components(text: &str) -> alloc::vec::Vec<alloc::string::String> {
        Path::new(text)
            .components()
            .map(|component| alloc::string::String::from(component.as_str()))
            .collect()
    }

    #[test]
    fn components_match_std_shapes() {
        assert_eq!(components(""), ["."]);
        assert_eq!(components("/"), ["/"]);
        assert_eq!(components("///"), ["/"]);
        assert_eq!(components("a/b"), ["a", "b"]);
        assert_eq!(components("/a//b/"), ["/", "a", "b"]);
        assert_eq!(components("./a/../b"), [".", "a", "..", "b"]);
    }

    #[test]
    fn normalize_is_lexical() {
        assert_eq!(normalize(""), ".");
        assert_eq!(normalize("/"), "/");
        assert_eq!(normalize("a//b/./c"), "a/b/c");
        assert_eq!(normalize("/a/../b"), "/b");
        assert_eq!(normalize("/../../a"), "/a");
        assert_eq!(normalize("a/../../b"), "../b");
        assert_eq!(normalize("../a"), "../a");
        assert_eq!(normalize("a/.."), ".");
    }

    #[test]
    fn normalize_join_uses_base_only_for_relative_paths() {
        assert_eq!(normalize_join("/mnt/demo", "a/../b"), "/mnt/demo/b");
        assert_eq!(normalize_join("/mnt/demo", "/etc/../x"), "/x");
        assert_eq!(normalize_join("", "a"), "a");
        assert_eq!(normalize_join("/", "../a"), "/a");
    }

    #[test]
    fn parent_and_file_name() {
        assert_eq!(Path::new("/a/b").parent().unwrap().as_str(), "/a");
        assert_eq!(Path::new("/a").parent().unwrap().as_str(), "/");
        assert_eq!(Path::new("/").parent(), None);
        assert_eq!(Path::new("").parent(), None);
        assert_eq!(Path::new("a").parent().unwrap().as_str(), "");
        assert_eq!(Path::new("a/b/").parent().unwrap().as_str(), "a");
        assert_eq!(Path::new("/a/b").file_name(), Some("b"));
        assert_eq!(Path::new("/a/b/").file_name(), Some("b"));
        assert_eq!(Path::new("/a/..").file_name(), None);
        assert_eq!(Path::new("/").file_name(), None);
    }

    #[test]
    fn starts_with_compares_components() {
        // The empty path is a prefix of everything; a non-empty base is not a
        // prefix of it.
        assert!(Path::new("").starts_with(""));
        assert!(!Path::new("").starts_with("a"));
        assert!(Path::new("a").starts_with(""));
        // Whole components only: `a/` and `a` both match, `ab` does not.
        assert!(Path::new("a/b").starts_with("a"));
        assert!(Path::new("a/b").starts_with("a/"));
        assert!(Path::new("/a/b").starts_with("/a/b/"));
        assert!(!Path::new("a/b").starts_with("a/b/c"));
        assert!(!Path::new("a").starts_with("ab"));
        // Absolute and relative prefixes do not mix.
        assert!(Path::new("/a/b").starts_with("/"));
        assert!(!Path::new("/a/b").starts_with("a"));
        assert!(!Path::new("a/b").starts_with("/a"));
        // Repeated separators collapse and interior `.` components are
        // normalized away, exactly like std's component comparison.
        assert!(Path::new("/a//b").starts_with("/a"));
        assert!(Path::new("a/./b").starts_with("a"));
        assert!(Path::new("a/./b").starts_with("a/."));
        assert!(Path::new("./a").starts_with("."));
        assert!(!Path::new("a").starts_with("./a"));
        // `.` and `..` are ordinary components here: lexical, no filesystem.
        assert!(Path::new("a/../b").starts_with("a/.."));
        assert!(!Path::new("a/../b").starts_with("a/../.."));
    }

    #[test]
    fn strip_prefix_returns_a_borrowed_remainder() {
        // The empty prefix consumes nothing, so the whole (possibly absolute)
        // path is returned unchanged.
        assert_eq!(Path::new("").strip_prefix(""), Ok(Path::new("")));
        assert_eq!(Path::new("a").strip_prefix(""), Ok(Path::new("a")));
        assert_eq!(Path::new("/a/b").strip_prefix(""), Ok(Path::new("/a/b")));
        // The remainder is spelled as in `self` with leading separators gone.
        assert_eq!(Path::new("a/b").strip_prefix("a"), Ok(Path::new("b")));
        assert_eq!(Path::new("a/b").strip_prefix("a/"), Ok(Path::new("b")));
        assert_eq!(Path::new("a/b").strip_prefix("a/b"), Ok(Path::new("")));
        assert_eq!(Path::new("a/b/").strip_prefix("a/b"), Ok(Path::new("")));
        assert_eq!(Path::new("a//b").strip_prefix("a"), Ok(Path::new("b")));
        assert_eq!(Path::new("a/./b").strip_prefix("a"), Ok(Path::new("b")));
        assert_eq!(Path::new("a/./b").strip_prefix("a/."), Ok(Path::new("b")));
        assert_eq!(Path::new("./a").strip_prefix("."), Ok(Path::new("a")));
        assert_eq!(Path::new("a/.").strip_prefix("a"), Ok(Path::new("")));
        assert_eq!(Path::new("/a/b").strip_prefix("/"), Ok(Path::new("a/b")));
        assert_eq!(Path::new("/a//b").strip_prefix("/a"), Ok(Path::new("b")));
        assert_eq!(Path::new("//a").strip_prefix("/a"), Ok(Path::new("")));
        // `..` matches lexically, and the rest is still `..`-relative.
        assert_eq!(Path::new("a/../b").strip_prefix("a"), Ok(Path::new("../b")));
        assert_eq!(Path::new("a/../b").strip_prefix("a/.."), Ok(Path::new("b")));
        assert_eq!(Path::new("/").strip_prefix("/"), Ok(Path::new("")));
        // A component-wise mismatch is an error, never a byte prefix match.
        assert!(Path::new("a/b").strip_prefix("/a").is_err());
        assert!(Path::new("a").strip_prefix("a/b").is_err());
        assert!(Path::new("ab").strip_prefix("a").is_err());
        // The opaque error type renders like std's.
        let error = Path::new("a").strip_prefix("a/b").unwrap_err();
        assert_eq!(alloc::format!("{}", error), "prefix not found");
        assert_eq!(alloc::format!("{:?}", error), "StripPrefixError(())");
    }

    #[test]
    fn ancestors_end_with_the_empty_path() {
        fn ancestors(path: &str) -> alloc::vec::Vec<alloc::string::String> {
            Path::new(path)
                .ancestors()
                .map(|parent| alloc::string::String::from(parent.as_str()))
                .collect()
        }
        assert_eq!(ancestors(""), [""]);
        assert_eq!(ancestors("/"), ["/"]);
        assert_eq!(ancestors("a"), ["a", ""]);
        assert_eq!(ancestors("/a/b"), ["/a/b", "/a", "/"]);
        // The first item keeps the path's spelling; parents do not.
        assert_eq!(ancestors("a/b/"), ["a/b/", "a", ""]);
        assert_eq!(ancestors("/a//b"), ["/a//b", "/a", "/"]);
        assert_eq!(ancestors("a/../b"), ["a/../b", "a/..", "a", ""]);
    }

    #[test]
    fn extension_and_stem() {
        assert_eq!(Path::new("a/b.txt").extension(), Some("txt"));
        assert_eq!(Path::new("a/b.txt").file_stem(), Some("b"));
        assert_eq!(Path::new("a/archive.tar.gz").extension(), Some("gz"));
        assert_eq!(
            Path::new("a/archive.tar.gz").file_stem(),
            Some("archive.tar")
        );
        assert_eq!(Path::new(".bashrc").extension(), None);
        assert_eq!(Path::new(".bashrc").file_stem(), Some(".bashrc"));
        assert_eq!(Path::new("foo.").extension(), Some(""));
        assert_eq!(Path::new("foo.").file_stem(), Some("foo"));
        assert_eq!(Path::new("..foo").extension(), Some("foo"));
    }

    #[test]
    fn joining_and_setting_extensions() {
        let mut path = PathBuf::from("/mnt/demo");
        path.push("a.txt");
        assert_eq!(path.as_str(), "/mnt/demo/a.txt");
        path.set_extension("rs");
        assert_eq!(path.as_str(), "/mnt/demo/a.rs");
        path.set_extension("");
        assert_eq!(path.as_str(), "/mnt/demo/a");
        path.set_file_name("b/c");
        assert_eq!(path.as_str(), "/mnt/demo/b/c");
        assert_eq!(path.pop(), true);
        assert_eq!(path.as_str(), "/mnt/demo/b");
        assert_eq!(path.pop(), true);
        assert_eq!(path.as_str(), "/mnt/demo");
        assert_eq!(path.pop(), true);
        assert_eq!(path.as_str(), "/mnt");
        path.push("/absolute/replaces");
        assert_eq!(path.as_str(), "/absolute/replaces");
    }

    /// A hasher that maps every key to the same bucket: the adversarial case
    /// for linear probing, and the one a "real hash table" must survive.
    #[derive(Clone, Copy, Default)]
    struct ZeroHasher;

    impl core::hash::BuildHasher for ZeroHasher {
        type Hasher = ZeroHash;
        fn build_hasher(&self) -> ZeroHash {
            ZeroHash
        }
    }

    struct ZeroHash;

    impl core::hash::Hasher for ZeroHash {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, _bytes: &[u8]) {}
    }

    #[test]
    fn hash_map_is_a_real_hash_table() {
        use super::hash_map::HashMap;
        let mut map = HashMap::new();
        assert!(map.is_empty());
        assert_eq!(map.capacity(), 0);
        map.insert("b", 2u32);
        map.insert("a", 1);
        map.insert("c", 3);
        assert_eq!(map.len(), 3);
        assert!(map.capacity() >= 3);
        assert_eq!(map.get("a"), Some(&1));
        assert_eq!(map.get("missing"), None);
        // The stored key is the original, not the probe argument.
        assert_eq!(map.get_key_value("b"), Some((&"b", &2)));
        // Iteration reaches every entry exactly once (order is unspecified).
        let mut keys: alloc::vec::Vec<&str> = map.keys().copied().collect();
        keys.sort_unstable();
        assert_eq!(keys, ["a", "b", "c"]);
        let mut values: alloc::vec::Vec<u32> = map.values().copied().collect();
        values.sort_unstable();
        assert_eq!(values, [1, 2, 3]);

        // insert replaces the value but keeps the original key.
        assert_eq!(map.insert("a", 10), Some(1));
        assert_eq!(map.get("a"), Some(&10));
        assert_eq!(map.len(), 3);

        *map.entry("a").or_insert(0) += 5;
        let occupied_is_occupied = matches!(map.entry("a"), super::hash_map::Entry::Occupied(_));
        assert!(occupied_is_occupied);
        map.entry("d").or_insert(4);
        map.entry("e").or_insert_with(|| 5);
        map.entry("f").or_default();
        map.entry("d").and_modify(|value| *value *= 2).or_insert(0);
        assert_eq!(map.get("a"), Some(&15));
        assert_eq!(map.get("d"), Some(&8));
        assert_eq!(map.get("e"), Some(&5));
        assert_eq!(map.get("f"), Some(&0));
        assert_eq!(map.len(), 6);

        assert_eq!(map.remove("b"), Some(2));
        assert_eq!(map.remove("b"), None);
        assert!(!map.contains_key("b"));
        assert_eq!(map.get("c"), Some(&3));
        assert_eq!(map.remove_entry("c"), Some(("c", 3)));
        assert_eq!(map.len(), 4);

        map.retain(|key, value| *value > 7 || *key == "f");
        assert_eq!(map.len(), 3);
        assert_eq!(map["a"], 15);
        assert_eq!(map["d"], 8);
        assert_eq!(map["f"], 0);

        // Drain empties the map and yields every entry.
        let mut drained: alloc::vec::Vec<(alloc::string::String, u32)> = map
            .drain()
            .map(|(key, value)| (alloc::string::String::from(key), value))
            .collect();
        drained.sort_unstable();
        assert_eq!(
            drained,
            [
                (alloc::string::String::from("a"), 15),
                (alloc::string::String::from("d"), 8),
                (alloc::string::String::from("f"), 0),
            ]
        );
        assert!(map.is_empty());
        assert!(map.capacity() > 0, "drain keeps the allocation");
    }

    #[test]
    fn hash_map_survives_every_key_in_one_bucket() {
        use super::hash_map::HashMap;
        // 256 keys, all hashing to bucket 0: insertion, lookup, removal and
        // growth all have to walk a single long probe run.
        let mut map: HashMap<u32, u32, ZeroHasher> = HashMap::with_hasher(ZeroHasher);
        for key in 0..256u32 {
            assert_eq!(map.insert(key, key * 3), None);
        }
        assert_eq!(map.len(), 256);
        for key in 0..256u32 {
            assert_eq!(map.get(&key), Some(&(key * 3)));
        }
        // Remove the first half, in order, forcing backward-shift deletion to
        // close the hole from a run that never leaves its ideal slot.
        for key in 0..128u32 {
            assert_eq!(map.remove(&key), Some(key * 3));
        }
        assert_eq!(map.len(), 128);
        for key in 0..128u32 {
            assert_eq!(map.get(&key), None);
        }
        for key in 128..256u32 {
            assert_eq!(map.get(&key), Some(&(key * 3)));
        }
        // Re-insert the removed half, then remove in reverse.
        for key in 0..128u32 {
            assert_eq!(map.insert(key, key * 3 + 1), None);
        }
        for key in (0..256u32).rev() {
            assert_eq!(map.remove(&key).is_some(), true);
        }
        assert!(map.is_empty());
    }

    #[test]
    fn hash_map_grows_and_shrinks_with_every_entry_intact() {
        use super::hash_map::HashMap;
        use alloc::string::ToString;
        let mut map: HashMap<alloc::string::String, usize> = HashMap::with_capacity(4);
        for index in 0..1024usize {
            map.insert(index.to_string(), index);
        }
        assert_eq!(map.len(), 1024);
        assert!(map.capacity() >= 1024);
        let capacity_before = map.capacity();
        for index in 0..1024usize {
            assert_eq!(map.get(&index.to_string()), Some(&index));
        }
        for index in (0..1024usize).step_by(2) {
            assert_eq!(map.remove(&index.to_string()), Some(index));
        }
        assert_eq!(map.len(), 512);
        map.shrink_to_fit();
        assert!(map.capacity() < capacity_before);
        assert!(map.capacity() >= 512);
        for index in 0..1024usize {
            let expected = if index % 2 == 0 { None } else { Some(&index) };
            assert_eq!(map.get(&index.to_string()), expected);
        }
        // Cloning copies every entry and both maps stay independent.
        let clone = map.clone();
        assert_eq!(clone, map);
        map.clear();
        assert!(map.is_empty());
        assert_eq!(clone.len(), 512);
    }

    #[test]
    fn hash_map_mutators_and_iterators_agree() {
        use super::hash_map::HashMap;
        let mut map: HashMap<u32, u32> = (0..64u32).map(|key| (key, key)).collect();
        for (_, value) in map.iter_mut() {
            *value += 1;
        }
        for value in map.values_mut() {
            *value *= 2;
        }
        let mut pairs: alloc::vec::Vec<(u32, u32)> = map.iter().map(|(k, v)| (*k, *v)).collect();
        pairs.sort_unstable();
        assert_eq!(pairs.len(), 64);
        assert!(pairs.iter().all(|(key, value)| *value == (key + 1) * 2));
        let owned: HashMap<u32, u32> = map.clone().into_iter().collect();
        assert_eq!(owned, map);
        let mut reserved: HashMap<u32, u32> = HashMap::new();
        reserved.reserve(1000);
        assert!(reserved.capacity() >= 1000);
        assert!(reserved.try_reserve(10).is_ok());
    }

    #[test]
    fn hash_set_is_a_real_hash_set() {
        use super::hash_set::HashSet;
        let mut set = HashSet::new();
        assert!(set.is_empty());
        assert!(set.insert("b"));
        assert!(set.insert("a"));
        assert!(!set.insert("a"));
        assert_eq!(set.len(), 2);
        assert!(set.capacity() >= 2);
        let mut items: alloc::vec::Vec<&str> = set.iter().copied().collect();
        items.sort_unstable();
        assert_eq!(items, ["a", "b"]);
        assert_eq!(set.get("a"), Some(&"a"));
        assert_eq!(set.get("missing"), None);
        assert!(set.contains("b"));
        assert_eq!(set.take("b"), Some("b"));
        assert!(!set.contains("b"));
        assert!(!set.remove("b"));
        assert_eq!(set.replace("a"), Some("a"));
        assert_eq!(set.replace("c"), None);
        assert_eq!(set.len(), 2);

        let other: HashSet<&str> = ["c", "d"].into_iter().collect();
        let mut union: alloc::vec::Vec<&str> = set.union(&other).copied().collect();
        union.sort_unstable();
        assert_eq!(union, ["a", "c", "d"]);
        let mut difference: alloc::vec::Vec<&str> = set.difference(&other).copied().collect();
        difference.sort_unstable();
        assert_eq!(difference, ["a"]);
        let mut intersection: alloc::vec::Vec<&str> = set.intersection(&other).copied().collect();
        intersection.sort_unstable();
        assert_eq!(intersection, ["c"]);
        let mut symmetric: alloc::vec::Vec<&str> =
            set.symmetric_difference(&other).copied().collect();
        symmetric.sort_unstable();
        assert_eq!(symmetric, ["a", "d"]);
        assert!(!set.is_subset(&other));
        assert!(!set.is_disjoint(&other));
        assert!(set.is_superset(&["a", "c"].into_iter().collect::<HashSet<&str>>()));

        set.retain(|item| *item != "a");
        assert_eq!(set.len(), 1);
        let drained: alloc::vec::Vec<&str> = set.drain().collect();
        assert_eq!(drained, ["c"]);
        assert!(set.is_empty());
    }

    #[test]
    fn default_hasher_is_deterministic_fnv() {
        use super::hash::{DefaultHasher, Hasher};
        let mut first = DefaultHasher::new();
        first.write(b"pagh");
        let mut second = DefaultHasher::new();
        second.write(b"pagh");
        assert_eq!(first.finish(), second.finish());
        assert_ne!(first.finish(), DefaultHasher::new().finish());
    }

    #[test]
    fn lazy_lock_initializes_once_and_cells_work() {
        use super::lazy::LazyLock;
        use alloc::string::String;
        use core::cell::{Cell, OnceCell, RefCell};

        let lazy = LazyLock::new(|| String::from("initialized"));
        assert_eq!(&*lazy, "initialized");
        assert!(lazy.get().is_some());
        assert_eq!(&*lazy, "initialized");

        let cell = Cell::new(1);
        cell.set(2);
        assert_eq!(cell.get(), 2);

        let cell = RefCell::new(5);
        *cell.borrow_mut() += 1;
        assert_eq!(*cell.borrow(), 6);

        let once = OnceCell::new();
        assert_eq!(once.get(), None);
        assert_eq!(*once.get_or_init(|| 7), 7);
        assert_eq!(*once.get_or_init(|| 9), 7);
    }

    #[test]
    fn display_and_debug_are_utf8() {
        let path = Path::new("/mnt/привет");
        assert_eq!(path.display().to_string(), "/mnt/привет");
        assert_eq!(path.to_string_lossy(), "/mnt/привет");
        assert_eq!(alloc::format!("{}", path), "/mnt/привет");
        assert_eq!(alloc::format!("{:?}", path), "\"/mnt/привет\"");
    }
}

/// The 0.7.0 pure layers, driven directly: no socket, no clock, no server.
#[cfg(test)]
mod pure_070 {
    use super::dns_wire::{self, WireError};
    use super::hostname::{hostname_matches, ip_matches, is_ip_literal, parse_ipv4_literal};
    use super::http::{
        build_get_request, parse_http_head, ChunkProgress, ChunkedDecoder, HeadParse,
    };

    #[test]
    fn dns_query_encodes_and_the_answer_decodes() {
        let mut query = [0u8; 512];
        let length = dns_wire::encode_query("example.com", 0x4242, &mut query).unwrap();
        assert_eq!(u16::from_be_bytes([query[0], query[1]]), 0x4242);
        // RD set, QR clear, one question.
        assert_eq!(query[2], 0x01);
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);
        let (name, after) = dns_wire::decode_name(&query, 12).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(after, length - 4);
    }

    #[test]
    fn dns_names_are_refused_before_they_are_sent() {
        let mut out = [0u8; 512];
        // A single trailing dot (the FQDN root) is accepted and stripped; a
        // bare "-" is a legal RFC 1035 label even if no host is named that.
        for name in ["", ".", "a..b", "x".repeat(64).as_str(), "пример.рф", "a/b"] {
            assert!(
                dns_wire::encode_query(name, 1, &mut out).is_err(),
                "{name:?}"
            );
        }
        assert!(dns_wire::encode_query(&"x".repeat(63), 1, &mut out).is_ok());
    }

    #[test]
    fn dns_replies_are_matched_before_they_are_trusted() {
        // A NOERROR answer for example.com built by hand, then mutated into the
        // three shapes that must never be accepted.
        let mut message = alloc::vec![0u8; 12 + 17 + 16];
        message[0..2].copy_from_slice(&7u16.to_be_bytes());
        message[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        message[4..6].copy_from_slice(&1u16.to_be_bytes());
        message[6..8].copy_from_slice(&1u16.to_be_bytes());
        let mut offset = 12;
        offset += dns_wire::encode_name("example.com", &mut message[offset..]).unwrap();
        message[offset..offset + 2].copy_from_slice(&dns_wire::TYPE_A.to_be_bytes());
        message[offset + 2..offset + 4].copy_from_slice(&dns_wire::CLASS_IN.to_be_bytes());
        offset += 4;
        message[offset] = 0xC0;
        message[offset + 1] = 12;
        message[offset + 2..offset + 4].copy_from_slice(&dns_wire::TYPE_A.to_be_bytes());
        message[offset + 4..offset + 6].copy_from_slice(&dns_wire::CLASS_IN.to_be_bytes());
        message[offset + 6..offset + 10].copy_from_slice(&60u32.to_be_bytes());
        message[offset + 10..offset + 12].copy_from_slice(&4u16.to_be_bytes());
        message[offset + 12..offset + 16].copy_from_slice(&[203, 0, 113, 7]);
        message.truncate(offset + 16);

        let response = dns_wire::parse_response(&message, 7, "example.com").unwrap();
        assert_eq!(response.addresses[0].address, [203, 0, 113, 7]);
        assert_eq!(response.addresses[0].ttl, 60);
        assert!(!response.truncated);

        assert_eq!(
            dns_wire::parse_response(&message, 8, "example.com"),
            Err(WireError::NotAResponse)
        );
        assert_eq!(
            dns_wire::parse_response(&message, 7, "example.org"),
            Err(WireError::QuestionMismatch)
        );
        let mut looping = message.clone();
        looping[12] = 0xC0;
        looping[13] = 12; // a pointer to itself: never a legal compression
        assert_eq!(
            dns_wire::parse_response(&looping, 7, "example.com"),
            Err(WireError::BadPointer)
        );
        for length in 0..message.len() {
            assert!(
                dns_wire::parse_response(&message[..length], 7, "example.com").is_err(),
                "accepted a {length}-byte prefix"
            );
        }
    }

    #[test]
    fn hostname_matching_is_rfc_6125_without_cn_fallback() {
        assert!(hostname_matches(b"example.com", b"example.com"));
        assert!(hostname_matches(b"EXAMPLE.com", b"example.com"));
        assert!(hostname_matches(b"example.com", b"example.com."));
        assert!(hostname_matches(b"a.example.com", b"*.example.com"));
        assert!(!hostname_matches(b"example.com", b"*.example.com"));
        assert!(!hostname_matches(b"b.a.example.com", b"*.example.com"));
        assert!(!hostname_matches(b"a.example.com", b"w*.example.com"));
        assert!(!hostname_matches(b"example.com", b"other.com"));
        assert!(!hostname_matches(b"example.com", b""));
        // `ip_matches` compares raw octets: the caller parses the literal first
        // (`parse_ipv4_literal`), exactly as `tls_auth` does.
        assert!(ip_matches(
            &parse_ipv4_literal(b"203.0.113.7").unwrap(),
            b"\xcb\x00\x71\x07"
        ));
        assert!(!ip_matches(
            &parse_ipv4_literal(b"203.0.113.7").unwrap(),
            b"\xcb\x00\x71\x08"
        ));
        assert!(!ip_matches(b"203.0.113.7", b"\xcb\x00\x71\x07"));
        assert!(hostname_matches(b"203.0.113.7", b"203.0.113.7"));
        assert!(is_ip_literal(b"203.0.113.7"));
        assert!(!is_ip_literal(b"example.com"));
        assert_eq!(parse_ipv4_literal(b"203.0.113.7"), Some([203, 0, 113, 7]));
        assert_eq!(parse_ipv4_literal(b"203.0.113"), None);
    }

    #[test]
    fn http_head_parsing_is_bounded_and_typed() {
        assert_eq!(parse_http_head(b"HTTP/1.1 200 OK\r\n"), HeadParse::Need);
        let HeadParse::Done {
            status,
            content_length,
            body_off,
            chunked,
        } = parse_http_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX: y\r\n\r\nhello")
        else {
            panic!("complete head was not parsed");
        };
        assert_eq!((status, content_length, chunked), (200, Some(5), false));
        assert_eq!(
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX: y\r\n\r\nhello"[body_off..],
            b"hello"
        );
        assert!(matches!(
            parse_http_head(b"not http at all\r\n\r\n"),
            HeadParse::Malformed
        ));

        let request = build_get_request("example.com", "/");
        assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
        assert!(core::str::from_utf8(&request)
            .unwrap()
            .contains("Host: example.com\r\n"));

        let mut decoder = ChunkedDecoder::new(1024);
        assert_eq!(decoder.push(b"5\r\nhello\r\n"), ChunkProgress::Need);
        assert_eq!(decoder.push(b"0\r\n\r\n"), ChunkProgress::Done);
        assert_eq!(decoder.body(), b"hello");
    }
}

#[cfg(test)]
mod set_probe_release {
    use super::hash_set::HashSet;

    #[test]
    fn a_set_is_always_disjoint_from_the_empty_set() {
        let mut set: HashSet<&str> = HashSet::new();
        set.insert("a");
        set.insert("b");
        set.insert("a");
        let mut other: HashSet<&str> = HashSet::new();
        other.insert("b");
        other.insert("c");
        let union: HashSet<&str> = set.union(&other).copied().collect();
        let intersection: HashSet<&str> = set.intersection(&other).copied().collect();
        let difference: HashSet<&str> = set.difference(&other).copied().collect();
        let symmetric: HashSet<&str> = set.symmetric_difference(&other).copied().collect();
        // The exact expression the `hash_map` example evaluates — including the
        // negations. It was written without one on `is_disjoint` first, which
        // made the live check fail while every part of it looked right; this
        // test is the regression that keeps the shape honest.
        let condition = set.len() != 2
            || !set.contains("a")
            || union.len() != 3
            || intersection.len() != 1
            || difference.len() != 1
            || symmetric.len() != 2
            || !set.is_subset(&union)
            || !set.is_disjoint(&HashSet::new());
        assert!(
            !condition,
            "len={} has_a={} union={} inter={} diff={} sym={} subset={} disjoint={}",
            set.len(),
            set.contains("a"),
            union.len(),
            intersection.len(),
            difference.len(),
            symmetric.len(),
            set.is_subset(&union),
            set.is_disjoint(&HashSet::new()),
        );
    }
}

#[cfg(test)]
mod pure_080 {
    use super::tls_url::{Target, UrlError};

    #[test]
    fn urls_parse_to_host_port_and_path() {
        let target = Target::parse("https://example.com/").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.path, "/");
        assert_eq!(target.host_port(), "example.com:443");
        assert_eq!(
            target.get_request(),
            b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );

        // No path means the root document, and an explicit port wins over the
        // default; the query string stays part of the path.
        let target = Target::parse("https://example.com:8443").unwrap();
        assert_eq!(target.port, 8443);
        assert_eq!(target.path, "/");
        let target = Target::parse("https://example.com/a/b?c=d#e").unwrap();
        assert_eq!(target.path, "/a/b?c=d#e");
        assert_eq!(target.host_port(), "example.com:443");

        // A dotted-quad is a host like any other; the SAN check decides later.
        let target = Target::parse("https://10.0.2.2:4443/x").unwrap();
        assert_eq!(target.host, "10.0.2.2");
        assert_eq!(target.port, 4443);
    }

    #[test]
    fn malformed_urls_are_refused_not_guessed() {
        assert_eq!(
            Target::parse("http://example.com/"),
            Err(UrlError::NotHttps)
        );
        assert_eq!(Target::parse("https:///x"), Err(UrlError::NoHost));
        assert_eq!(
            Target::parse("https://example.com:no/"),
            Err(UrlError::BadPort)
        );
        // A port outside u16 is a parse failure, not a wrap.
        assert_eq!(
            Target::parse("https://example.com:70000/"),
            Err(UrlError::BadPort)
        );
        assert_eq!(
            Target::parse("https://user@example.com/"),
            Err(UrlError::Malformed)
        );
        assert_eq!(Target::parse(""), Err(UrlError::NotHttps));
    }

    #[test]
    fn every_port_renders_its_exact_digits() {
        // `host_port` is what `TlsStream::connect` re-parses, so the rendering
        // has to round-trip for the boundaries and for a value with zeros.
        for (url, expected) in [
            ("https://h:1/", "h:1"),
            ("https://h:80/", "h:80"),
            ("https://h:1000/", "h:1000"),
            ("https://h:65535/", "h:65535"),
            ("https://h:443/", "h:443"),
        ] {
            assert_eq!(Target::parse(url).unwrap().host_port(), expected);
        }
    }
}
