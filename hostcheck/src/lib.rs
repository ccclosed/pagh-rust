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

    #[test]
    fn hash_map_is_a_sorted_btree_shim() {
        use super::hash_map::HashMap;
        let mut map = HashMap::new();
        map.insert("b", 2u32);
        map.insert("a", 1);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("a"), Some(&1));
        let keys: alloc::vec::Vec<&str> = map.keys().copied().collect();
        assert_eq!(keys, ["a", "b"]);

        *map.entry("a").or_insert(0) += 10;
        map.entry("c").or_insert(3);
        assert_eq!(map.get("a"), Some(&11));
        assert_eq!(map.get("c"), Some(&3));
        assert!(map.remove("b").is_some());
        assert!(!map.contains_key("b"));
        map.retain(|_, value| *value > 2);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn hash_set_is_a_sorted_btree_shim() {
        use super::hash_set::HashSet;
        let mut set = HashSet::new();
        assert!(set.insert("b"));
        assert!(set.insert("a"));
        assert!(!set.insert("a"));
        let items: alloc::vec::Vec<&str> = set.iter().copied().collect();
        assert_eq!(items, ["a", "b"]);
        assert!(set.contains("b"));
        assert!(set.remove("b"));
        assert!(!set.contains("b"));
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
