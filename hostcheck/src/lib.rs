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
//! The 0.9.0 I/O conveniences (`io::Cursor`, `Read::chain`, `Tee`) live in
//! `pagh_std/src/io/pure.rs` for the same reason: `io.rs` owns the console
//! handles and `poll` and needs `libpagh`, the pure half needs only `core` +
//! `alloc`. Two `libpagh` items are still named there, and both are pure: its
//! frozen `errno` table (included from the sibling checkout's own source, so
//! this gate sees the numbers the SDK is built against) and `SeekFrom`, which
//! is spelled out below because `libpagh::io` also holds the syscall-backed
//! handles.
//!
//! The 0.10.0 sync core follows the same rule. `OnceLock`'s atomic state
//! machine (`pagh_std/src/sync/once_lock_core.rs`) is syscall-free on purpose:
//! this gate races it with real host threads, where preemption actually exists,
//! and only the futex park/unpark half stays target-only. The `alloc` reference
//! counters the SDK now re-exports (`rc.rs`, `sync/arc.rs`) are pure too, so
//! `Arc` is also exercised across real host threads here.
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

// The kernel-independent I/O core (0.9.0): `Read`/`Write`/`Seek`/`BufRead`,
// the buffered adapters, `Cursor`, `Read::chain` and `Tee`. Everything in that
// file is `core` + `alloc` only.
#[path = "../../pagh_std/src/io/pure.rs"]
mod io_pure;

// The 0.10.0 sync core: `OnceLock`'s state word and storage (pure `core`, so
// the race protocol is testable here), and the `alloc` reference counters the
// SDK re-exports at the `std::rc`/`std::sync` paths.
#[path = "../../pagh_std/src/sync/once_lock_core.rs"]
mod once_lock_core;

#[path = "../../pagh_std/src/rc.rs"]
mod rc;

#[path = "../../pagh_std/src/sync/arc.rs"]
mod arc;

// `pagh_std/src/error.rs` is included too: it is the error type the traits
// above return. It stores a `libpagh::errno::Errno`, which is why the crate
// root re-exports the frozen table below.
#[path = "../../pagh_std/src/error.rs"]
mod error;

// `libpagh` cannot be a host dependency: its crate root is `#![no_std]` with a
// RISC-V `ecall` syscall module. The two items the pure sources name from it
// are pure, though, so the gate supplies exactly those:
//
//   * `errno` is the sibling checkout's own `errno.rs`, compiled from source.
//     The numbers and messages are therefore the ones the SDK is built
//     against, not a copy in this crate that can drift. It also brings that
//     file's own round-trip test into this suite, which is the point: the
//     table is the ABI.
//   * `io::SeekFrom` is std's three-variant enum. `libpagh::io` cannot be
//     included as a whole because the same file defines `Stdin`/`Stdout`/
//     `Stderr` over the syscalls, so this one pure type is repeated below.
//     `pagh_std::io::SeekFrom` is `libpagh::io::SeekFrom` on the target.
#[path = "../../../pagh-api/libpagh/src/errno.rs"]
pub(crate) mod libpagh_errno;
pub(crate) use libpagh_errno::Errno;

/// Host stand-in for the `libpagh::io` module: only `SeekFrom` is pure.
mod libpagh_io {
    /// Origin of a [`Seek`](super::io_pure::Seek) call, std-shaped.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SeekFrom {
        /// Offset from the start of the stream, in bytes.
        Start(u64),
        /// Offset from the end of the stream, in bytes (usually negative).
        End(i64),
        /// Offset from the current position, in bytes.
        Current(i64),
    }
}

/// The `io` path `pagh_std/src/io/pure.rs` names for `SeekFrom`, so the file
/// compiles here unchanged.
mod io {
    pub use crate::libpagh_io::SeekFrom;
}

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
        // A trailing `.` component is not a component (std's next_back): the
        // path before it is both the file name and the parent's tail.
        assert_eq!(Path::new("a/.").file_name(), Some("a"));
        assert_eq!(Path::new("a/./").file_name(), Some("a"));
        assert_eq!(Path::new("a/.").parent().unwrap().as_str(), "");
        assert_eq!(Path::new("a/./b").parent().unwrap().as_str(), "a");
        assert_eq!(Path::new("/a/./b").parent().unwrap().as_str(), "/a");
        assert_eq!(Path::new("///a").parent().unwrap().as_str(), "/");
        assert_eq!(Path::new("//").parent(), None);
        // Repeated separators and trailing dots do not survive into the parent.
        assert_eq!(Path::new("a//b//").parent().unwrap().as_str(), "a");
        assert_eq!(Path::new("../.").parent().unwrap().as_str(), "");
        assert_eq!(Path::new("/a/..").parent().unwrap().as_str(), "/a");
        // The extension family is built on `file_name`, so the same path now
        // names the file before the trailing dot.
        assert_eq!(Path::new("a.b/.").extension(), Some("b"));
        assert_eq!(Path::new("a.b/./").file_stem(), Some("a"));
        assert_eq!(Path::new("...").extension(), Some(""));
        assert_eq!(Path::new("...").file_stem(), Some(".."));
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
        // The empty prefix consumes nothing: the whole path (possibly
        // absolute) is the remainder, with trailing separators trimmed the way
        // std's `Components::as_path` trims them.
        assert_eq!(Path::new("").strip_prefix(""), Ok(Path::new("")));
        assert_eq!(Path::new("a").strip_prefix(""), Ok(Path::new("a")));
        assert_eq!(Path::new("/a/b").strip_prefix(""), Ok(Path::new("/a/b")));
        assert_eq!(Path::new("a/b//").strip_prefix(""), Ok(Path::new("a/b")));
        assert_eq!(Path::new("../").strip_prefix(""), Ok(Path::new("..")));
        assert_eq!(Path::new("..//.").strip_prefix(""), Ok(Path::new("..")));
        assert_eq!(Path::new("//a//").strip_prefix(""), Ok(Path::new("//a")));
        assert_eq!(Path::new("///").strip_prefix(""), Ok(Path::new("/")));
        // The remainder is spelled as in `self` with leading separators gone.
        assert_eq!(Path::new("a/b").strip_prefix("a"), Ok(Path::new("b")));
        assert_eq!(Path::new("a/b").strip_prefix("a/"), Ok(Path::new("b")));
        assert_eq!(Path::new("a/b").strip_prefix("a/b"), Ok(Path::new("")));
        assert_eq!(Path::new("a/b/").strip_prefix("a/b"), Ok(Path::new("")));
        assert_eq!(Path::new("a//b").strip_prefix("a"), Ok(Path::new("b")));
        assert_eq!(Path::new("a/./b").strip_prefix("a"), Ok(Path::new("b")));
        assert_eq!(Path::new("a/./b").strip_prefix("a/."), Ok(Path::new("b")));
        // Interior spelling of the *remainder* is kept; only its edges are
        // normalized (`a//b//c` keeps the `//` between `b` and `c`).
        assert_eq!(
            Path::new("a//b//c").strip_prefix("a"),
            Ok(Path::new("b//c"))
        );
        assert_eq!(
            Path::new("a/./b/./c").strip_prefix("a"),
            Ok(Path::new("b/./c"))
        );
        // Trailing separators and trailing `.` components are trimmed, like
        // std's `Components::as_path`.
        assert_eq!(Path::new("a/b/./").strip_prefix("a/b"), Ok(Path::new("")));
        assert_eq!(Path::new("a/b/.").strip_prefix("a"), Ok(Path::new("b")));
        assert_eq!(Path::new("/a//b//").strip_prefix("/a"), Ok(Path::new("b")));
        assert_eq!(Path::new("../../").strip_prefix(".."), Ok(Path::new("..")));
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

/// The 0.9.0 I/O conveniences, driven directly on the host: every seek and EOF
/// boundary of `Cursor`, both readers of `Chain` (including the empty cases and
/// the "empty buffer is not EOF" rule), the `BufRead` hand-off between them, and
/// `Tee`'s mirroring (short writes, a lying writer, flush order).
///
/// What the live run cannot do cheaply is enumerate the boundaries; that is what
/// this module is for. The live matrix (`tools/live_090.py`) proves the same
/// code compiles and runs on the kernel.
#[cfg(test)]
mod io_090 {
    use super::error::{ErrorKind, Result};
    use super::io_pure::{
        copy, read_to_end, BufRead, BufReader, BufWriter, Chain, Cursor, Read, Seek, Tee, Write,
    };
    use super::libpagh_io::SeekFrom;

    /// A writer that records every accepted byte, for the `Tee` tests.
    #[derive(Debug, Default)]
    struct Capture {
        bytes: alloc::vec::Vec<u8>,
        flushes: usize,
    }

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn cursor_reads_across_every_buffer_boundary() {
        let mut cursor = Cursor::new(b"abcdefghij".to_vec());
        assert_eq!(cursor.position(), 0);
        assert_eq!(cursor.get_ref().as_slice(), b"abcdefghij");

        let mut first = [0u8; 3];
        assert_eq!(cursor.read(&mut first).unwrap(), 3);
        assert_eq!(&first, b"abc");
        assert_eq!(cursor.position(), 3);

        // A short read is not EOF: a four-byte request continues at the exact
        // byte the previous one stopped at.
        let mut second = [0u8; 4];
        assert_eq!(cursor.read(&mut second).unwrap(), 4);
        assert_eq!(&second, b"defg");
        assert_eq!(cursor.position(), 7);

        // An empty destination must not move the cursor (and must not be
        // mistaken for EOF by anything downstream).
        assert_eq!(cursor.read(&mut []).unwrap(), 0);
        assert_eq!(cursor.position(), 7);

        let mut rest = alloc::vec::Vec::new();
        assert_eq!(cursor.read_to_end(&mut rest).unwrap(), 3);
        assert_eq!(rest, b"hij");
        assert_eq!(cursor.position(), 10);

        // Past the end: zero bytes, position unchanged.
        assert_eq!(cursor.read(&mut second).unwrap(), 0);
        assert_eq!(cursor.position(), 10);
        assert_eq!(cursor.fill_buf().unwrap(), b"");
        assert_eq!(cursor.into_inner(), b"abcdefghij".to_vec());
    }

    #[test]
    fn cursor_read_to_end_appends_and_reads_a_borrowed_slice() {
        let mut cursor = Cursor::new(b"world".to_vec());
        let mut out = b"hello ".to_vec();
        assert_eq!(cursor.read_to_end(&mut out).unwrap(), 5);
        assert_eq!(out, b"hello world");
        assert_eq!(read_to_end(&mut cursor).unwrap().len(), 0);
        assert_eq!(cursor.position(), 5);

        // `T: AsRef<[u8]>`, not just `Vec<u8>`: a borrowed slice and a `&str`
        // work with the same type.
        let mut borrowed = Cursor::new(&b"boxed"[..]);
        let mut text = alloc::string::String::new();
        assert_eq!(borrowed.read_to_string(&mut text).unwrap(), 5);
        assert_eq!(text, "boxed");

        let mut utf8 = Cursor::new("héllo");
        assert_eq!(
            read_to_end(&mut utf8).unwrap().as_slice(),
            "héllo".as_bytes()
        );
    }

    #[test]
    fn cursor_seek_start_current_end_and_position() {
        let mut cursor = Cursor::new(b"0123456789".to_vec());
        assert_eq!(cursor.seek(SeekFrom::Start(4)).unwrap(), 4);
        assert_eq!(cursor.position(), 4);
        assert_eq!(cursor.seek(SeekFrom::Current(-2)).unwrap(), 2);
        assert_eq!(cursor.seek(SeekFrom::End(-3)).unwrap(), 7);
        assert_eq!(cursor.seek(SeekFrom::End(0)).unwrap(), 10);
        assert_eq!(cursor.stream_position().unwrap(), 10);

        // `set_position` is the same thing without the return value, and
        // `rewind`/`seek_relative` are the trait's defaults over `seek`.
        cursor.set_position(1);
        assert_eq!(cursor.position(), 1);
        cursor.rewind().unwrap();
        assert_eq!(cursor.position(), 0);
        cursor.seek_relative(5).unwrap();
        assert_eq!(cursor.position(), 5);
        let mut byte = [0u8; 1];
        cursor.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'5']);
        assert_eq!(cursor.position(), 6);
    }

    #[test]
    fn cursor_seeking_past_the_end_stays_readable() {
        // std permits this: the position is kept, the window is empty, and a
        // later seek back recovers the data.
        let mut cursor = Cursor::new(b"abc".to_vec());
        assert_eq!(cursor.seek(SeekFrom::Start(100)).unwrap(), 100);
        assert_eq!(cursor.position(), 100);
        assert_eq!(cursor.read(&mut [0u8; 4]).unwrap(), 0);
        assert_eq!(cursor.fill_buf().unwrap(), b"");
        cursor.set_position(1);
        assert_eq!(cursor.fill_buf().unwrap(), b"bc");
        assert_eq!(cursor.seek(SeekFrom::Current(0)).unwrap(), 1);
        // `Start` is returned unchecked, like std, and an empty read of the
        // empty window is still an empty read.
        assert_eq!(cursor.seek(SeekFrom::Start(u64::MAX)).unwrap(), u64::MAX);
        assert_eq!(cursor.read(&mut [0u8; 1]).unwrap(), 0);
    }

    #[test]
    fn cursor_negative_or_overflowing_seeks_are_typed_errors() {
        let mut cursor = Cursor::new(b"abc".to_vec());
        for pos in [
            SeekFrom::Current(-1),
            SeekFrom::End(-4),
            SeekFrom::End(i64::MIN),
        ] {
            let error = cursor.seek(pos).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
        // A failed seek leaves the position where it was.
        assert_eq!(cursor.position(), 0);
        // The largest in-range end-relative seek lands on the same value.
        assert_eq!(
            cursor.seek(SeekFrom::End(i64::MAX)).unwrap(),
            3 + i64::MAX as u64
        );
    }

    #[test]
    fn cursor_bufread_fill_consume_and_read_until() {
        let mut cursor = Cursor::new(b"line one\nline two\n".to_vec());
        assert_eq!(cursor.fill_buf().unwrap(), &b"line one\nline two\n"[..]);
        cursor.consume(4);
        assert_eq!(cursor.position(), 4);
        assert_eq!(cursor.fill_buf().unwrap(), &b" one\nline two\n"[..]);

        // Reading through the same cursor continues inside the window.
        let mut head = [0u8; 5];
        cursor.read_exact(&mut head).unwrap();
        assert_eq!(&head, b" one\n");
        assert_eq!(cursor.position(), 9);

        // `read_until`/`read_line` are the trait's default methods over
        // `fill_buf` + `consume`.
        let mut line = alloc::vec::Vec::new();
        assert_eq!(cursor.read_until(b'\n', &mut line).unwrap(), 9);
        assert_eq!(line, b"line two\n");
        let mut tail = alloc::vec::Vec::new();
        assert_eq!(cursor.read_until(b'\n', &mut tail).unwrap(), 0);
        assert!(tail.is_empty());

        // A consume past the end is clamped by the saturating position: the
        // window is empty and no byte is invented.
        cursor.consume(usize::MAX);
        assert_eq!(cursor.fill_buf().unwrap(), b"");
        assert_eq!(cursor.read(&mut [0u8; 1]).unwrap(), 0);
    }

    #[test]
    fn cursor_lines_decode_utf8() {
        let mut cursor = Cursor::new("привет\nworld\r\n".as_bytes().to_vec());
        let mut line = alloc::string::String::new();
        assert_eq!(cursor.read_line(&mut line).unwrap(), "привет\n".len());
        assert_eq!(line, "привет\n");
        let mut line = alloc::string::String::new();
        assert_eq!(cursor.read_line(&mut line).unwrap(), "world\r\n".len());
        assert_eq!(line, "world\r\n");

        let cursor = Cursor::new(b"a\nb\r\nc".to_vec());
        let lines: alloc::vec::Vec<alloc::string::String> = cursor
            .lines()
            .map(|line| line.expect("valid UTF-8 from the fixed input"))
            .collect();
        assert_eq!(lines, ["a", "b", "c"]);
    }

    #[test]
    fn cursor_early_eof_and_invalid_utf8_are_typed() {
        let mut cursor = Cursor::new(b"abc".to_vec());
        let mut too_big = [0u8; 4];
        let error = cursor.read_exact(&mut too_big).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);

        // `read_to_string` validates before it appends: a non-UTF-8 tail leaves
        // the destination untouched.
        let mut invalid = Cursor::new(alloc::vec![0xffu8, 0xfe]);
        let mut text = alloc::string::String::new();
        let error = invalid.read_to_string(&mut text).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(text.is_empty());

        // And a valid prefix followed by an invalid byte is still an error for
        // the whole read, not a truncated string.
        let mut mixed = Cursor::new(b"ok\xff".to_vec());
        let mut text = alloc::string::String::new();
        assert_eq!(
            mixed.read_to_string(&mut text).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        assert!(text.is_empty());
    }

    #[test]
    fn cursor_composes_with_take_and_copy() {
        let mut limited = Cursor::new(b"abcdef".to_vec()).take(3);
        let mut out = alloc::vec::Vec::new();
        assert_eq!(limited.read_to_end(&mut out).unwrap(), 3);
        assert_eq!(out, b"abc");

        let mut source = Cursor::new(b"copy me".to_vec());
        let mut sink = Capture::default();
        assert_eq!(copy(&mut source, &mut sink).unwrap(), 7);
        assert_eq!(sink.bytes, b"copy me");
    }

    #[test]
    fn chain_reads_first_then_second() {
        let mut chain = Cursor::new(b"abc".to_vec()).chain(Cursor::new(b"def".to_vec()));
        let mut out = alloc::vec::Vec::new();
        assert_eq!(chain.read_to_end(&mut out).unwrap(), 6);
        assert_eq!(out, b"abcdef");

        // Neither reader is drained early: the first read stops inside `first`.
        let mut chain = Cursor::new(b"abc".to_vec()).chain(Cursor::new(b"def".to_vec()));
        let mut one = [0u8; 1];
        assert_eq!(chain.read(&mut one).unwrap(), 1);
        assert_eq!(one, [b'a']);
        assert_eq!(chain.get_ref().1.position(), 0);
        assert_eq!(chain.get_ref().0.position(), 1);
    }

    #[test]
    fn chain_over_empty_readers_collapses_to_the_other_side() {
        // Empty first, full second: the transition happens on the first read.
        let mut chain = Cursor::new(alloc::vec::Vec::<u8>::new()).chain(Cursor::new(b"xyz"));
        let mut out = alloc::vec::Vec::new();
        assert_eq!(chain.read_to_end(&mut out).unwrap(), 3);
        assert_eq!(out, b"xyz");

        // Full first, empty second.
        let mut chain = Cursor::new(b"abc".to_vec()).chain(Cursor::new(&b""[..]));
        assert_eq!(read_to_end(&mut chain).unwrap(), b"abc");

        // Both empty.
        let mut chain = Cursor::new(&b""[..]).chain(Cursor::new(&b""[..]));
        assert_eq!(read_to_end(&mut chain).unwrap(), b"");

        // Empty `&[u8]` readers chain like any other `Read`.
        let mut chain = (&b""[..]).chain(&b"hi"[..]);
        assert_eq!(read_to_end(&mut chain).unwrap(), b"hi");
    }

    #[test]
    fn chain_reads_exactly_across_the_boundary_and_reports_early_eof() {
        // Four bytes total, asked for four: the last byte comes from `second`.
        let mut chain = Cursor::new(b"ab".to_vec()).chain(Cursor::new(b"cd".to_vec()));
        let mut exact = [0u8; 4];
        chain.read_exact(&mut exact).unwrap();
        assert_eq!(&exact, b"abcd");

        // Four bytes total, asked for five: the failure is `UnexpectedEof`, not
        // a short read that looks like success.
        let mut chain = Cursor::new(b"ab".to_vec()).chain(Cursor::new(b"cd".to_vec()));
        let mut too_big = [0u8; 5];
        let error = chain.read_exact(&mut too_big).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn chain_an_empty_buffer_is_not_end_of_file() {
        // std's rule: `read(&mut [])` returns 0 and must not advance the chain
        // to its second reader, or a caller doing an empty read would silently
        // skip `first`.
        let mut chain = Cursor::new(b"ab".to_vec()).chain(Cursor::new(b"cd".to_vec()));
        assert_eq!(chain.read(&mut []).unwrap(), 0);
        let mut one = [0u8; 1];
        assert_eq!(chain.read(&mut one).unwrap(), 1);
        assert_eq!(one, [b'a']);
        assert_eq!(chain.get_ref().0.position(), 1);
        assert_eq!(chain.get_ref().1.position(), 0);
    }

    #[test]
    fn chain_bufread_hands_out_the_current_reader() {
        // Both halves are buffered, so the chain is too. `fill_buf` serves the
        // current reader's window and `consume` marks bytes of that one; the
        // hand-off happens exactly when the first window comes back empty.
        let mut chain = Cursor::new(b"ab".to_vec()).chain(Cursor::new(b"cd".to_vec()));
        assert_eq!(chain.fill_buf().unwrap(), &b"ab"[..]);
        chain.consume(1);
        assert_eq!(chain.fill_buf().unwrap(), &b"b"[..]);
        chain.consume(1);
        assert_eq!(chain.fill_buf().unwrap(), &b"cd"[..]);
        chain.consume(1);
        assert_eq!(chain.fill_buf().unwrap(), &b"d"[..]);
        chain.consume(1);
        assert_eq!(chain.fill_buf().unwrap(), b"");
        assert_eq!(chain.fill_buf().unwrap(), b"");

        // `read_until` (the trait default over `fill_buf`/`consume`) finds a
        // delimiter in the second reader.
        let mut chain = Cursor::new(b"ab".to_vec()).chain(Cursor::new(b"cd\n"));
        let mut line = alloc::vec::Vec::new();
        assert_eq!(chain.read_until(b'\n', &mut line).unwrap(), 5);
        assert_eq!(line, b"abcd\n");

        // A chain of an empty first reader still answers the second's window.
        let mut chain = Cursor::new(alloc::vec::Vec::<u8>::new()).chain(Cursor::new(b"z"));
        assert_eq!(chain.fill_buf().unwrap(), &b"z"[..]);
    }

    #[test]
    fn chain_accessors_expose_both_readers() {
        let mut chain = Cursor::new(b"a".to_vec()).chain(Cursor::new(b"b".to_vec()));
        assert_eq!(chain.get_ref().0.position(), 0);
        assert_eq!(chain.get_mut().1.get_ref().as_slice(), b"b");
        let (mut first, mut second) = chain.into_inner();
        assert_eq!(read_to_end(&mut first).unwrap(), b"a");
        assert_eq!(read_to_end(&mut second).unwrap(), b"b");
    }

    #[test]
    fn chain_of_borrowed_slices_is_a_reader() {
        fn assert_read<R: Read>() {}
        fn assert_bufread<B: BufRead>() {}
        assert_read::<Chain<Cursor<alloc::vec::Vec<u8>>, &'static [u8]>>();
        assert_bufread::<Chain<Cursor<alloc::vec::Vec<u8>>, Cursor<&'static [u8]>>>();

        let mut chain = (&b"one "[..]).chain(&b"two"[..]);
        let mut out = alloc::vec::Vec::new();
        assert_eq!(chain.read_to_end(&mut out).unwrap(), 7);
        assert_eq!(out, b"one two");
    }

    #[test]
    fn tee_writes_the_same_bytes_to_both_sinks() {
        let mut tee = Tee::new(Capture::default(), Capture::default());
        tee.write_all(b"hello ").unwrap();
        assert_eq!(tee.write(b"world").unwrap(), 5);
        tee.flush().unwrap();
        let (writer, file) = tee.into_inner();
        assert_eq!(writer.bytes, b"hello world");
        assert_eq!(file.bytes, b"hello world");
        assert_eq!(writer.flushes, 1);
        assert_eq!(file.flushes, 1);
    }

    /// A writer that accepts at most `chunk` bytes per call.
    #[derive(Debug)]
    struct Trickle {
        bytes: alloc::vec::Vec<u8>,
        chunk: usize,
    }

    impl Write for Trickle {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            let n = core::cmp::min(self.chunk, buf.len());
            self.bytes.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tee_mirrors_only_the_bytes_the_writer_accepted() {
        // The first sink is short-writing, so `write_all` calls `Tee::write`
        // repeatedly; the second sink must still receive every byte exactly
        // once, in order — that is the whole point of `write_all` inside.
        let trickle = Trickle {
            bytes: alloc::vec::Vec::new(),
            chunk: 1,
        };
        let mut tee = Tee::new(trickle, Capture::default());
        tee.write_all(b"abcdef").unwrap();
        let (writer, file) = tee.into_inner();
        assert_eq!(writer.bytes, b"abcdef");
        assert_eq!(file.bytes, b"abcdef");
        // A single short write is reported as such (the `Write` contract).
        let trickle = Trickle {
            bytes: alloc::vec::Vec::new(),
            chunk: 2,
        };
        let mut tee = Tee::new(trickle, Capture::default());
        assert_eq!(tee.write(b"xyz").unwrap(), 2);
        let (writer, file) = tee.into_inner();
        assert_eq!(writer.bytes, b"xy");
        assert_eq!(file.bytes, b"xy");
    }

    #[test]
    fn tee_refuses_a_writer_that_lies_about_its_count() {
        struct Liar;
        impl Write for Liar {
            fn write(&mut self, buf: &[u8]) -> Result<usize> {
                Ok(buf.len() + 1)
            }
            fn flush(&mut self) -> Result<()> {
                Ok(())
            }
        }
        let mut tee = Tee::new(Liar, Capture::default());
        let error = tee.write(b"ab").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        // Nothing reached the second sink: the error is found before the copy.
        assert!(tee.into_inner().1.bytes.is_empty());
    }

    #[test]
    fn tee_flushes_the_writer_before_the_file() {
        #[derive(Debug)]
        struct Logged<'a> {
            label: &'static str,
            events: &'a core::cell::RefCell<alloc::vec::Vec<&'static str>>,
        }
        impl Write for Logged<'_> {
            fn write(&mut self, buf: &[u8]) -> Result<usize> {
                self.events.borrow_mut().push(self.label);
                Ok(buf.len())
            }
            fn flush(&mut self) -> Result<()> {
                self.events.borrow_mut().push(if self.label == "writer" {
                    "flush writer"
                } else {
                    "flush file"
                });
                Ok(())
            }
        }
        let events = core::cell::RefCell::new(alloc::vec::Vec::new());
        let mut tee = Tee::new(
            Logged {
                label: "writer",
                events: &events,
            },
            Logged {
                label: "file",
                events: &events,
            },
        );
        tee.write_all(b"x").unwrap();
        tee.flush().unwrap();
        assert_eq!(
            *events.borrow(),
            ["writer", "file", "flush writer", "flush file"]
        );
    }

    #[test]
    fn bufreader_over_a_cursor_matches_direct_reads() {
        // A cursor underneath a `BufReader`: the buffer refills from the
        // cursor, and `BufReader::seek(Current(0))` has to subtract the unread
        // bytes it is holding — the accounting this adapter exists for.
        let payload = b"0123456789";
        let mut reader = BufReader::with_capacity(7, Cursor::new(payload.to_vec()));
        let mut seen = [0u8; 3];
        reader.read_exact(&mut seen).unwrap();
        assert_eq!(&seen, b"012");
        // Seven bytes were read ahead from the cursor, three of them consumed.
        assert_eq!(reader.buffer(), &b"3456"[..]);
        assert_eq!(reader.fill_buf().unwrap(), &b"3456"[..]);
        reader.consume(2);
        assert_eq!(reader.fill_buf().unwrap(), &b"56"[..]);
        // The cursor is seven bytes ahead of the logical position, so rewinding
        // to the logical position subtracts the seven unread buffered bytes.
        assert_eq!(reader.seek(SeekFrom::Current(0)).unwrap(), 5);
        let mut rest = alloc::vec::Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"56789");
        assert_eq!(reader.into_inner().into_inner(), payload.to_vec());
    }

    #[test]
    fn cursor_default_and_get_mut_can_move_the_end() {
        // `Default` is std's: an empty byte source at position 0.
        let mut empty = Cursor::<alloc::vec::Vec<u8>>::default();
        assert_eq!(empty.position(), 0);
        assert_eq!(empty.fill_buf().unwrap(), b"");
        assert_eq!(empty.read(&mut [0u8; 1]).unwrap(), 0);

        // `get_mut` exposes the buffer; growing it moves the end of file, so a
        // read started before the mutation sees the new bytes (std's behaviour
        // for a `Cursor` over an owning container).
        let mut cursor = Cursor::new(b"ab".to_vec());
        cursor.get_mut().extend_from_slice(b"cd");
        let mut all = alloc::vec::Vec::new();
        assert_eq!(cursor.read_to_end(&mut all).unwrap(), 4);
        assert_eq!(all, b"abcd");
    }

    #[test]
    fn cursor_read_to_string_crosses_the_default_chunk_boundary() {
        // `read_to_end`/`read_to_string` copy in 4096-byte chunks; a cursor has
        // to serve the tail correctly when the payload is not a multiple of
        // that, and `read_to_string` has to validate the whole run.
        let text = "é".repeat(3000); // 6000 UTF-8 bytes, one byte pair per char
        let mut cursor = Cursor::new(text.as_bytes().to_vec());
        let mut out = alloc::string::String::new();
        assert_eq!(cursor.read_to_string(&mut out).unwrap(), text.len());
        assert_eq!(out, text);
        assert_eq!(cursor.position(), text.len() as u64);
        // A second read at EOF appends nothing and reports 0.
        assert_eq!(cursor.read_to_string(&mut out).unwrap(), 0);
        assert_eq!(out, text);
    }

    #[test]
    fn chain_reads_only_the_second_reader_once_the_first_is_finished() {
        let mut chain = Cursor::new(b"ab".to_vec()).chain(Cursor::new(b"cdef".to_vec()));
        let mut exactly = [0u8; 3];
        chain.read_exact(&mut exactly).unwrap();
        assert_eq!(&exactly, b"abc");
        // The transition was consumed inside that `read_exact`; the first
        // reader is now at its end and the chain serves `second` only.
        assert_eq!(chain.read(&mut [0u8; 0]).unwrap(), 0);
        let mut rest = alloc::vec::Vec::new();
        assert_eq!(chain.read_to_end(&mut rest).unwrap(), 3);
        assert_eq!(rest, b"def");
        assert_eq!(chain.get_ref().1.position(), 4);
    }

    #[test]
    fn chain_composes_with_take_and_bufreader() {
        // `Take<Chain<..>>`: the limit is applied after the concatenation.
        let mut limited = Cursor::new(b"hello ".to_vec())
            .chain(Cursor::new(b"world".to_vec()))
            .take(8);
        let mut out = alloc::vec::Vec::new();
        assert_eq!(limited.read_to_end(&mut out).unwrap(), 8);
        assert_eq!(out, b"hello wo");

        // `BufReader<Chain<..>>`: the buffer is refilled across the hand-off.
        let mut reader = BufReader::with_capacity(
            2,
            Cursor::new(b"ab".to_vec()).chain(Cursor::new(b"cd".to_vec())),
        );
        assert_eq!(reader.fill_buf().unwrap(), &b"ab"[..]);
        let mut all = alloc::vec::Vec::new();
        reader.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"abcd");
    }

    #[test]
    fn tee_works_with_buffered_sinks_and_flushes_both() {
        // Both sinks are `BufWriter`s, so the bytes only reach the captures on
        // `flush`; `Tee::flush` has to flush the writer first and the file
        // second, and `into_inner` then hands both back in order.
        let mut tee = Tee::new(
            BufWriter::with_capacity(32, Capture::default()),
            BufWriter::with_capacity(32, Capture::default()),
        );
        tee.write_all(b"buffered").unwrap();
        assert_eq!(tee.get_ref().0.buffer(), b"buffered");
        tee.flush().unwrap();
        let (writer, file) = tee.into_inner();
        let writer = writer.into_inner().expect("writer flush");
        let file = file.into_inner().expect("file flush");
        assert_eq!(writer.bytes, b"buffered");
        assert_eq!(file.bytes, b"buffered");
        // One flush each from `Tee::flush`; `BufWriter::into_inner` flushes
        // again on its way out, which is why the count is two, not one.
        assert_eq!((writer.flushes, file.flushes), (2, 2));
    }

    #[test]
    fn cursor_matches_a_reference_model_over_random_operations() {
        // A deterministic sequence of reads, seeks and consumes against a
        // slice-plus-position model of std's Cursor. The hand-written tests
        // above pin the interesting boundaries; this one is free to wander
        // across them and catch an off-by-one the enumerated cases missed.
        fn next(state: &mut u64) -> u64 {
            // xorshift64*: deterministic, no dependency, good enough to shuffle
            // the operation order.
            let mut x = *state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            *state = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        let data: alloc::vec::Vec<u8> = (0..37u8).map(|value| value.wrapping_mul(7)).collect();
        let mut cursor = Cursor::new(data.clone());
        let mut position: u64 = 0;
        let mut state = 0x5eed_1234_abcd_9876u64;

        for step in 0..4000 {
            let choice = next(&mut state) % 6;
            match choice {
                0 | 1 => {
                    // Read into a variable-size buffer.
                    let mut buffer = [0u8; 8];
                    let length = (next(&mut state) % 9) as usize;
                    let read = cursor.read(&mut buffer[..length]).unwrap();
                    let start = core::cmp::min(position as usize, data.len());
                    let expected = core::cmp::min(length, data.len() - start);
                    assert_eq!(read, expected, "read length at step {step}");
                    assert_eq!(&buffer[..read], &data[start..start + expected]);
                    position += expected as u64;
                }
                2 => {
                    // Peek through BufRead and consume a random count.
                    {
                        let window = cursor.fill_buf().unwrap();
                        let start = core::cmp::min(position as usize, data.len());
                        assert_eq!(window, &data[start..], "fill_buf at step {step}");
                    }
                    let amount = (next(&mut state) % 12) as usize;
                    cursor.consume(amount);
                    position = position.saturating_add(amount as u64);
                }
                3 => {
                    let target = next(&mut state) % 37;
                    assert_eq!(cursor.seek(SeekFrom::Start(target)).unwrap(), target);
                    position = target;
                }
                4 => {
                    let delta = (next(&mut state) % 41) as i64 - 20;
                    let expected = position as i128 + delta as i128;
                    if expected < 0 {
                        assert_eq!(
                            cursor.seek(SeekFrom::Current(delta)).unwrap_err().kind(),
                            ErrorKind::InvalidInput,
                            "negative relative seek at step {step}"
                        );
                    } else {
                        assert_eq!(
                            cursor.seek(SeekFrom::Current(delta)).unwrap(),
                            expected as u64
                        );
                        position = expected as u64;
                    }
                }
                _ => {
                    let delta = (next(&mut state) % 41) as i64 - 20;
                    let expected = data.len() as i128 + delta as i128;
                    if expected < 0 {
                        assert_eq!(
                            cursor.seek(SeekFrom::End(delta)).unwrap_err().kind(),
                            ErrorKind::InvalidInput,
                            "negative end seek at step {step}"
                        );
                    } else {
                        assert_eq!(cursor.seek(SeekFrom::End(delta)).unwrap(), expected as u64);
                        position = expected as u64;
                    }
                }
            }
            assert_eq!(cursor.position(), position, "position at step {step}");
        }
    }

    #[test]
    fn cursor_and_chain_are_usable_through_the_trait_objects_they_share() {
        // `Read` is not object-safe (`read_to_end` needs `Self: Sized` only for
        // the adapters, not for `read`), but the concrete composition has to
        // typecheck through generic code, which is how programs use it.
        fn tally<R: Read>(reader: &mut R) -> Result<usize> {
            let mut count = 0;
            let mut byte = [0u8; 1];
            loop {
                match reader.read(&mut byte)? {
                    0 => return Ok(count),
                    n => count += n,
                }
            }
        }
        let mut chain = Cursor::new(b"abc".to_vec()).chain(Cursor::new(b"de".to_vec()));
        assert_eq!(tally(&mut chain).unwrap(), 5);
    }
}

/// The 0.10.0 sync additions, driven directly on the host.
///
/// `OnceLock` itself cannot be compiled here (its futex park/unpark lives in
/// `sync.rs` on top of `libpagh`), but its state machine can — and that is
/// where the interesting invariants are. The race test below runs six real
/// host threads through the same protocol the guest uses; the QEMU matrix
/// (`tools/live_100.py`) covers the parking half with the SDK's own threads.
#[cfg(test)]
mod sync_100 {
    use super::once_lock_core::{Begin, Core};
    use core::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn once_lock_core_walks_the_only_legal_states() {
        let mut core = Core::new();
        assert!(!core.is_ready());
        assert!(core.get().is_none());

        // The first `begin` claims the cell; a second one sees the claim and
        // must not be told it may initialize.
        assert!(matches!(core.begin(), Begin::Won));
        assert!(!core.is_ready());
        assert!(core.get().is_none());
        assert!(matches!(core.begin(), Begin::Busy));

        core.publish(41);
        assert!(core.is_ready());
        assert_eq!(core.get(), Some(&41));
        // Once published, every later claim is told the value is there.
        assert!(matches!(core.begin(), Begin::Ready));
        assert!(matches!(core.begin(), Begin::Ready));
        assert_eq!(core.get(), Some(&41));

        // `take` empties the cell and makes it claimable again.
        assert_eq!(core.take(), Some(41));
        assert!(!core.is_ready());
        assert!(core.get().is_none());
        assert!(core.take().is_none());
        assert!(matches!(core.begin(), Begin::Won));
        core.publish(7);
        assert_eq!(core.get(), Some(&7));
    }

    #[test]
    fn once_lock_core_get_mut_and_with_value() {
        let mut core = Core::with_value(5u32);
        assert!(core.is_ready());
        assert_eq!(core.get(), Some(&5));
        *core.get_mut().expect("initialized") = 6;
        assert_eq!(core.get(), Some(&6));
        // A fresh cell has no mutable access either.
        let mut empty = Core::<u32>::new();
        assert!(empty.get_mut().is_none());
    }

    #[test]
    fn once_lock_core_race_has_exactly_one_initializer() {
        /// `Core` is an `UnsafeCell` and therefore not `Sync`; the test shares
        /// it the way `OnceLock` does, so the wrapper carries the unsafety.
        struct Shared {
            core: Core<u32>,
            initializers: AtomicU32,
        }

        // SAFETY: the threads below only use the protocol `Core` documents —
        // `begin` (a CAS), `publish` by the single `Begin::Won` thread, and
        // `is_ready`/`get` (Acquire) after a Release publication. No thread
        // calls a `&mut self` method while another holds a reference.
        unsafe impl Sync for Shared {}

        let shared = Shared {
            core: Core::new(),
            initializers: AtomicU32::new(0),
        };
        let observed = AtomicU32::new(0);

        std::thread::scope(|scope| {
            for candidate in 0..6u32 {
                let shared = &shared;
                let observed = &observed;
                scope.spawn(move || loop {
                    match shared.core.begin() {
                        Begin::Won => {
                            shared.initializers.fetch_add(1, Ordering::SeqCst);
                            shared.core.publish(candidate * 3);
                            observed.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                        Begin::Busy => {
                            // Host threads are preempted, so a bounded spin is
                            // not a livelock; the guest version parks instead.
                            while !shared.core.is_ready() {
                                core::hint::spin_loop();
                            }
                            observed.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                        Begin::Ready => {
                            observed.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                    }
                });
            }
        });

        assert_eq!(
            shared.initializers.load(Ordering::SeqCst),
            1,
            "more than one thread initialized the cell"
        );
        assert_eq!(observed.load(Ordering::SeqCst), 6);
        let value = shared.core.get().expect("one thread published a value");
        assert!(
            [0u32, 3, 6, 9, 12, 15].contains(value),
            "unexpected {value}"
        );
    }

    #[test]
    fn once_lock_core_drops_the_value_exactly_once() {
        static DROPS: AtomicU32 = AtomicU32::new(0);

        struct Noisy(u32);
        impl Drop for Noisy {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut core = Core::new();
        assert!(matches!(core.begin(), Begin::Won));
        core.publish(Noisy(9));
        assert_eq!(core.get().map(|noisy| noisy.0), Some(9));
        core.drop_value();
        assert!(core.get().is_none());
        // Dropping the cell afterwards must not drop the value a second time.
        drop(core);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);

        // An empty cell's `drop_value` drops nothing.
        let mut empty = Core::<Noisy>::new();
        empty.drop_value();
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rc_is_the_alloc_rc_at_the_std_path() {
        use super::rc::{Rc, Weak};
        let rc = Rc::new(41u32);
        assert_eq!(Rc::strong_count(&rc), 1);
        let clone = Rc::clone(&rc);
        assert_eq!(Rc::strong_count(&rc), 2);
        assert!(Rc::ptr_eq(&rc, &clone));
        let weak: Weak<u32> = Rc::downgrade(&rc);
        drop(clone);
        assert_eq!(Rc::strong_count(&rc), 1);
        assert_eq!(weak.upgrade().map(|value| *value), Some(41));
        drop(rc);
        assert!(weak.upgrade().is_none());
        assert_eq!(Rc::try_unwrap(Rc::new(7u32)), Ok(7));
    }

    #[test]
    fn arc_is_the_alloc_arc_and_crosses_host_threads() {
        use super::arc::{Arc, Weak};
        use core::sync::atomic::AtomicU32;

        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Arc<AtomicU32>>();

        let counter = Arc::new(AtomicU32::new(0));
        assert_eq!(Arc::strong_count(&counter), 1);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let counter = Arc::clone(&counter);
                scope.spawn(move || {
                    counter.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        assert_eq!(counter.load(Ordering::SeqCst), 8);
        assert_eq!(Arc::strong_count(&counter), 1);

        let weak: Weak<AtomicU32> = Arc::downgrade(&counter);
        assert!(weak.upgrade().is_some());
        let unique = Arc::try_unwrap(counter).expect("the threads have joined");
        assert_eq!(unique.load(Ordering::SeqCst), 8);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn lazy_lock_default_matches_std() {
        use super::lazy::LazyLock;
        let number: LazyLock<u32> = LazyLock::default();
        assert_eq!(*number, 0);
        assert!(number.get().is_some());
        let text: LazyLock<alloc::string::String> = Default::default();
        assert!(text.is_empty());
        // The initializer runs once, and `force` returns the cached value.
        assert_eq!(LazyLock::force(&text).len(), 0);
    }
}
