# pagh-rust — a std-like Rust SDK for pagh-riscv

Native Rust programs for [pagh-riscv](../pagh-riscv): compiled with `rustc` for
`riscv64gc-unknown-none-elf`, linked against [`libpagh`](../pagh-api), and run
in U-mode with `run /mnt/...`.

## The honest scope

A full `rustc`/`std` **cannot** run on this OS. Compiling Rust needs LLVM and a
host operating system; `std` assumes libc, threads, a signal stack, `mmap`, a
wall clock and a dynamic loader that the 22-syscall pagh ABI does not have.

What *is* fully real is **Rust the language** plus the `alloc` crate:

- generics, traits, closures, iterators, pattern matching, `Result`/`Option`;
- `Vec`, `String`, `VecDeque`, `BTreeMap`, `BTreeSet`, `BinaryHeap`;
- `format!`, `println!`, `write!` and the rest of `core::fmt`;
- a 1 MiB bump heap over `brk`, with `Vec`/`String` growth and OOM handling;
- this crate's std-shaped layer over files, directories, arguments, paths,
  buffered I/O, time and process exit.

`pagh_std` does **not** claim to be `std`, does not provide processes,
networking, dynamic linking or `OsStr`, and returns a typed
`io::ErrorKind::Unsupported` for operations the ABI cannot express. Those are
listed under [Limitations vs std](#limitations-vs-std).

**Live evidence:** [`docs/live-rust-sdk.txt`](docs/live-rust-sdk.txt) is a
QEMU serial transcript (kernel 0.11.0, RISC-V `virt`, a 64 MiB ext2 image) with
62/62 checks: all three examples, relative paths, filesystem mutations,
metadata, symlinks, `panic` exit 101 and OOM exit 102, plus console stdin.

## Repository layout

```
Cargo.toml                 workspace: pagh_std, hostcheck, diagnostic probes
rust-toolchain.toml        pinned nightly-2026-07-12 + riscv64gc target
.cargo/config.toml         target + pagh-user.ld + rust-lld (sibling layout)
build.sh                   builds the example ELFs (honours PAGH_API)
pagh_std/src/
  lib.rs                   crate docs, macros, prelude
  error.rs                 io::Error / ErrorKind / Result
  io.rs                    Read/Write/Seek/BufRead, buffers, console handles
  fs.rs                    File/OpenOptions/ReadDir/Metadata + fs operations
  env.rs                   args/vars/PWD tracking/temp_dir
  path.rs                  UTF-8 Path/PathBuf/Components + lexical normalize
  time.rs                  Duration, Instant, SystemTime, sleep
  process.rs               exit/abort/Command (typed Unsupported)
  collections/             alloc containers + HashMap/HashSet BTree shims
  hash.rs                  core::hash re-exports + deterministic hasher
  sync.rs                  Cell/RefCell/OnceCell/LazyLock
  fmt.rs                   core::fmt re-exports
  panic.rs                 PanicInfo/abort + the runtime contract
  ffi.rs                   c_* types, CStr/CString
examples/                  cat.rs, wc.rs, find.rs (real #![no_std] programs)
hostcheck/                 host cargo test for the pure path logic
tools/probes/              panic/oom/chdir/fsops/clock diagnostic programs
tools/live_check.py        builds, boots QEMU, runs everything, saves transcript
.github/workflows/ci.yml   fmt + RISC-V build + host tests
docs/live-rust-sdk.txt     the captured live run
```

## A program

```rust
#![no_std]
#![no_main]

use pagh_std::prelude::*;

#[no_mangle]
pub extern "C" fn main(
    _argc: i32,
    _argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    let args: Vec<String> = env::args().collect();
    println!("{}: {} argument(s)", env::program_name(), args.len() - 1);

    match fs::read_to_string("/mnt/hello.txt") {
        Ok(text) => print!("{text}"),
        Err(error) => eprintln!("read: {error}"),
    }
    0
}
```

The return value is the process exit status. The `libpagh` runtime owns
`_start`, parses `argc/argv/envp`, calls this `main`, and exits. The program
must *use* `pagh_std` (any item) so the rlib and its transitive `libpagh`
runtime are linked.

## Build

### Prerequisites

- Rustup with the pinned `nightly-2026-07-12` toolchain (the same nightly as the
  kernel and `libpagh`) and the `riscv64gc-unknown-none-elf` target.
- A sibling checkout of `pagh-api` (it provides the `libpagh` path dependency
  and `pagh-user.ld`):

```text
<parent>/
  pagh-rust/   this repository
  pagh-api/    libpagh + pagh-user.ld
  pagh-riscv/  the kernel (only needed to run the ELFs)
```

`build.sh` accepts `PAGH_API=/somewhere/pagh-api`; plain `cargo` uses the
relative path in `.cargo/config.toml` and therefore needs the sibling layout.

### Commands

```sh
./build.sh                  # dev profile: opt-level 2, strip debuginfo, checks on
./build.sh --release        # release profile
./build.sh --fixtures       # also build panic/oom/chdir/fsops/clock probes
```

Outputs (the kernel refuses images above 1 MiB; these are ~140–250 KiB):

```text
target/riscv64gc-unknown-none-elf/debug/examples/cat
target/riscv64gc-unknown-none-elf/debug/examples/wc
target/riscv64gc-unknown-none-elf/debug/examples/find
```

Equivalent Cargo invocation:

```sh
cargo build --examples -p pagh_std
```

`build.sh` passes `-C link-arg=-T<pagh-api>/pagh-user.ld -C linker=rust-lld`
(mirroring `pagh-api/.cargo/config.toml`) and the pinned toolchain/target.
The linker script places the image at `0x1_0000`, `_start` in `.text.entry`,
and produces R+X/R/R+W `PT_LOAD` segments; there is no TLS, `.init_array` or
dynamic section.

### Host tests

The pure path logic can be compiled for the host; `libpagh` itself cannot
(RISC-V `ecall` assembly). `hostcheck` includes `pagh_std/src/path.rs`
directly:

```sh
cargo test -p pagh_hostcheck --target x86_64-unknown-linux-gnu
```

CI runs that plus `cargo fmt -p pagh_std -p pagh_hostcheck -p pagh_probes --
--check`, `./build.sh --fixtures`, and a 1 MiB size check. (The package-scoped
form is deliberate: `cargo fmt --all` also formats local path dependencies, and
the sibling `pagh-api` checkout must not be modified.) It checks out `pagh-rust` and `pagh-api` as siblings.

## Run it in QEMU

Use the kernel from `pagh-riscv` and a host-built ext2 image:

```sh
mkdir -p rootfs/demo/sub
cp target/riscv64gc-unknown-none-elf/debug/examples/{cat,wc,find} rootfs/
printf 'hello from pagh-rust\nsecond line\n' > rootfs/hello.txt
printf 'alpha\n' > rootfs/demo/alpha.txt
printf 'beta\n'  > rootfs/demo/sub/beta.txt
mke2fs -q -t ext2 -F -b 4096 -d rootfs disk.img 64M

qemu-system-riscv64 -machine virt -m 256M \
  -kernel ../pagh-riscv/target/riscv64gc-unknown-none-elf/debug/pagh \
  -device ramfb -global virtio-mmio.force-legacy=false \
  -drive file=disk.img,format=raw,if=none,id=hd0 \
  -device virtio-blk-device,drive=hd0 \
  -display none -serial mon:stdio -no-reboot
```

At `pagh:rv64>`:

```text
run /mnt/cat /mnt/hello.txt
run /mnt/wc /mnt/hello.txt
run /mnt/wc -l /mnt/lines.txt
run /mnt/find /mnt/demo
run /mnt/find /mnt/demo -type f -ls
```

The shell has no quoting or redirection, so an argument cannot contain a
space, and there is no `cat < file`. Relative arguments are resolved against
the shell's `PWD` by `pagh_std`, not by the kernel (the kernel takes absolute
paths only).

### One-command live check

```sh
python3 tools/live_check.py
```

It builds the ELFs and probes, stages fixtures, creates the ext2 image with
`mke2fs -d` (no root, no host mount), boots QEMU with a UNIX serial socket,
types every command byte by byte, checks output and exit codes, runs the
console-stdin case, and rewrites `docs/live-rust-sdk.txt`. `--kernel`,
`--api`, `--skip-build`, `--keep` and `--output` are available.

The last run: **62/62 checks passed** against
`pagh-riscv 0.11.0` / QEMU 10.2.2. The transcript is the source of truth; the
summary includes `cat`, `wc`, `find`, relative paths after `cd`, `fsops`
(mkdir/write/copy/rename/hard link/symlink/readlink/truncate/remove),
`set_current_dir`, monotonic/uptime clocks, `nanosleep`, panic 101 and OOM 102.
Console stdin is tested last: `cat` with no arguments echoes `console stdin
works`, then keeps waiting because the ABI has no EOF; the script terminates
QEMU itself.

## API surface

### `pagh_std::io`

| Item | Notes |
|---|---|
| `Read` | `read`, `read_to_end`, `read_to_string`, `read_exact`, `bytes`, `take`, `by_ref`; implemented for `File`, `Stdin`, `BufReader`, `&[u8]`, `&mut R` |
| `Write` | `write`, `flush`, `write_all`, `write_fmt`, `by_ref`; `File`, `Stdout`, `Stderr`, `BufWriter`, `&mut W` |
| `Seek`, `SeekFrom` | `seek`, `stream_position`, `rewind`, `seek_relative`; regular files |
| `BufRead`, `BufReader`, `BufWriter` | `fill_buf`, `consume`, `read_until`, `read_line`, `lines`, `split`; 8 KiB default buffer, `with_capacity`, `into_inner`, `get_ref`, `get_mut` |
| `stdin`, `stdout`, `stderr` | console handles; `Stdin::read` blocks by retrying `EAGAIN` with `sched_yield`; output retries `EAGAIN` too |
| `read_to_end`, `read_to_string`, `copy` | free functions over `Read`/`Write` |
| `empty`, `repeat`, `sink` | trivial adapters |
| `Error`, `ErrorKind`, `Result` | `Error` wraps `libpagh::errno::Errno`, keeps the raw number, maps to std-shaped kinds; `Unsupported` is the typed "ABI cannot do this" |

`write!`/`writeln!` are the core prelude macros; they call
`Write::write_fmt`, so they work with every `pagh_std` sink. `println!`-style
macros ignore write errors (there is no useful recovery on fd 1); use
`writeln!(io::stdout(), ...)` when the error matters.

### `pagh_std::fs`

| Item | Notes |
|---|---|
| `File` | `open`, `create`, `create_new` (always `Unsupported`), `options`, `metadata`, `set_len`, `as_raw_fd`, `into_raw_fd`, `unsafe from_raw_fd`, `Read`/`Write`/`Seek`, closes on drop |
| `OpenOptions` | read/write/append/create/truncate/mode; `create_new` returns `Unsupported` (no `O_EXCL`) |
| `ReadDir` (`Dir`) | iterator over `getdents64`, filters `.` and `..`, yields `Result<DirEntry>`; `read_dir(path)` |
| `DirEntry` | `path`, `file_name`, `file_type`, `ino`, `metadata` (follows symlinks) |
| `FileType` | `File`, `Dir`, `Symlink`, `Other`; `is_*` |
| `Metadata` | `len`/`size`, `is_empty`, `file_type`/`kind`, `is_*`, `mode`, `ino`, `permissions` |
| `Permissions` | `from_mode`, `mode`, `readonly`, `set_readonly`; `set_permissions` is per-run only |
| operations | `read`, `read_to_string`, `write`, `create_dir`, `create_dir_all`, `remove_file`, `remove_dir`, `remove_dir_all`, `rename`, `hard_link`, `symlink`, `read_link`, `copy`, `canonicalize` (lexical), `truncate`, `metadata`, `symlink_metadata` (`Unsupported`) |

`metadata` is `openat(O_RDONLY)` + `fstat` + `close`, because there is no
`statat`; it follows symlinks and needs open permission. `create_dir_all`
accepts an existing mount root such as `/mnt` even though `mkdirat` reports
`ENOTSUP` there.

### `pagh_std::env`

`args`, `args_os` (lossy — there is no `OsString`), `vars`, `var`/`var_os`,
`VarError`, `program_name`, `current_exe`, `current_dir`, `set_current_dir`,
`temp_dir` (`/mnt`).

`set_current_dir` is **process-local `PWD` tracking**: the kernel has no cwd,
so it records the normalized path in a single-threaded cell after checking that
it is a directory. Every later relative path in `pagh_std::fs` resolves against
it; the shell's cwd and any future child do not change. `PWD` comes from the
kernel environment at startup, with `/` as the fallback.

### `pagh_std::process`

`exit(code) -> !`, `abort() -> !` (prints `<program>: abort`, exits 134),
`id()` (`getpid`), `ExitStatus`, `Output`, `Child`, `Command`.

`Command` stores its program/args/env/current_dir but `status`, `output` and
`spawn` always return `ErrorKind::Unsupported`: the ABI has no
`fork`/`exec`/`pipe`/`wait`.

### `pagh_std::time`

`Duration` (core), monotonic `Instant`, uptime-based `SystemTime`,
`UNIX_EPOCH`, `SystemTimeError`, `sleep(Duration)` (`nanosleep`, rounded up to
the 10 ms tick).

`Instant` and `SystemTime` read `clock_gettime(1)` and `clock_gettime(0)`
respectively. Both are tick counters since boot; there is no RTC, so
`SystemTime` is **not** a Unix timestamp and `UNIX_EPOCH` is the boot instant.
Arithmetic saturates rather than panicking; `checked_*` methods are available.
`Instant::now()`/`SystemTime::now()` fall back to zero if the syscall fails;
`try_now()` surfaces the error.

### `pagh_std::path`

UTF-8 `Path` (unsized, `#[repr(transparent)]` over `str`) and `PathBuf`
(`String`): `new`, `as_str`, `to_path_buf`, `join`, `parent`, `file_name`,
`file_stem`, `extension`, `with_extension`, `with_file_name`, `display`,
`components`, `is_absolute`/`is_relative`, `to_str`, `to_string_lossy`,
`push`/`pop`/`set_file_name`/`set_extension`, `normalize`, `normalize_join`,
and `Display`/`Debug`.

`components()` yields `RootDir`, `CurDir`, `ParentDir`, `Normal(&str)`;
`join` follows std (absolute replaces, no normalization), while `fs` normalizes
lexically before every syscall. No `OsStr`, no `strip_prefix`, no
`starts_with` component matching yet.

### `pagh_std::collections` and `pagh_std::hash`

Real `alloc` types: `Vec`, `String`, `VecDeque`, `BTreeMap`, `BTreeSet`,
`BinaryHeap`, plus `Box`, `ToOwned`, `ToString`. `HashMap`/`HashSet` are
**documented `BTreeMap`/`BTreeSet` shims** (the API is std-shaped; keys need
`Ord`, iteration is sorted; `capacity` is `len`). `hash` re-exports
`Hash`/`Hasher`/`BuildHasher` and provides a deterministic FNV-1a
`RandomState`/`DefaultHasher` — pagh has no entropy source, so “random” would
be a lie. The `HashMap` shim does not consult the hasher.

### `pagh_std::sync`

`Cell`, `RefCell`, `OnceCell`, `UnsafeCell` from `core::cell`, plus a
single-threaded `LazyLock<T, F>` whose initializer is `Fn` (not `FnOnce`).
There is deliberately **no `Mutex` or `RwLock`**: there is exactly one thread
and no wait primitive, so those types would be misleading.

### `pagh_std::fmt`, `panic`, `ffi`

- `fmt` re-exports `core::fmt` (`Debug`, `Display`, `Formatter`, `Arguments`,
  `Write`, …).
- `panic` re-exports `PanicInfo` and offers `abort()`. It intentionally does
  **not** declare `#[panic_handler]`; see the next section.
- `ffi` re-exports `c_void`, `c_char`, `c_int`, `c_long`, … and
  `CStr`/`CString` for a future C boundary. There is no libc, `errno` global or
  `malloc`.

## Panic, OOM and runtime ownership

`pagh_std` depends on `libpagh`, which already owns the crate graph's
`_start`, `#[global_allocator]`, `#[panic_handler]` and
`#[alloc_error_handler]`. Rust permits exactly one of each per graph
(`duplicate lang item` otherwise), so a second handler in `pagh_std` is not
possible without ceasing to be a layer over `libpagh`.

The linked runtime already provides the required observable contract:

```text
panic: panic at tools/probes/examples/panic.rs:15:5
run: /mnt/panic exited with code 101

oom: out of memory (brk failed); requested 1048576 bytes at alignment 1
run: /mnt/oom exited with code 102
```

Both lines are in `docs/live-rust-sdk.txt`, produced by the diagnostic probes.
`pagh_std::panic` documents this and re-exports the type; `process::abort()`
is available for deliberate termination (exit 134, not a panic).

The allocator is a bump allocator over `brk`: 1 MiB total, page-granular
growth, `dealloc` is a no-op, memory is reclaimed only when the process exits.
`Vec` growth therefore leaves old buffers behind; a program that allocates in a
loop can exhaust the heap even with bounded live data. OOM exits 102 rather
than panicking.

## Limitations vs std

Impossible without new kernel syscalls (shown with the SDK's typed
`Unsupported` answer where an API exists):

- **`std::thread`/`Mutex`/`RwLock`/`Condvar`**: not `std`; `pagh_std::thread`
  provides native `Builder`/`JoinHandle`/futex, single-threaded `sync` only;
- **processes**, `Command`, `fork`/`exec`/`wait`: no process model yet; signals
  are in `pagh_std::signal`, pipes in the raw `libpagh` ABI;
  syscalls; `Command::{status,output,spawn}` return `Unsupported`;
- **networking**, `TcpStream`/`UdpSocket`/DNS: the kernel has a network stack
  internally, but the frozen user ABI exposes no socket syscalls;
- **dynamic linking**, `dlopen`, shared libraries: one static ELF, no loader;
- **`OsStr`/`OsString` and non-UTF-8 paths**: the SDK stores UTF-8; directory
  names are decoded lossily (U+FFFD), so a non-UTF-8 filename cannot be opened
  by its exact bytes;
- **`mmap`** is available in the raw `libpagh` ABI (anonymous private pages);
  `pagh_std` still exposes only the `brk` heap;
- **`poll`/`select`/epoll**, `stdin` EOF: `read(0)` is non-blocking and never
  reports EOF; `io::Stdin` blocks by yielding, but `cat` with no file waits
  forever;
- **real wall-clock time**, `SystemTime::now` as Unix time, time zones, RTC:
  clock 0 is uptime at 10 ms resolution;
- **`fsync`/`fdatasync`**, `dup`/`fcntl`, `statfs`, `utimes`, `chown`,
  `O_EXCL`, `O_DIRECTORY`, `O_NOFOLLOW`, `statat`/`lstat`: no ABI for them;
  `symlink_metadata`, `create_new` and `sync_*` are `Unsupported`;
- **durable `chmod`**: `fchmodat` records bits only for the rest of the run and
  writes nothing to ext2; `mkdirat`/`openat` ignore mode;
- **`renameat2` flags** (`RENAME_NOREPLACE`/`RENAME_EXCHANGE`), cross-filesystem
  operations: flags must be 0; `/mnt` is the only mount;
- **kernel cwd**: `set_current_dir` is a userland `PWD` override only;
- **more than 16 fds**, paths longer than 256 bytes, images/images with more
  than the kernel's 1 MiB limit: kernel limits;
- **`rustc`/`cargo` on the OS**: LLVM + host OS; this SDK is the compile target,
  not an on-device toolchain.

Also deliberately not provided in this first version: `io::Cursor`,
`Read::chain`, `Tee`, file locking, `is_terminal`, `Path::starts_with` /
`strip_prefix` / `ancestors`, `OsString`, `Rc`/`Arc` re-exports, `OnceLock`,
and a real hash table. They are userland-only conveniences the SDK can grow
without a kernel change; the current surface is the part exercised by the live
transcript.

## Design notes

- **No panics on normal I/O errors.** Syscall failures become `io::Error`
  values; `read_to_string` validates UTF-8 before touching the destination;
  `BufReader`/`BufWriter` check every count they get back. Panics are reserved
  for programmer errors and the deliberate probe.
- **Every `unsafe` site has a `SAFETY:` comment.** The surface is the
  `Path`/`PathBuf` `#[repr(transparent)]` casts, the single-threaded `PWD` cell
  (`unsafe impl Sync` plus its two accesses), `BufWriter::into_inner`'s
  bitwise move, and `File::from_raw_fd`'s documented ownership contract. The
  crate is `#![deny(unsafe_op_in_unsafe_fn)]`.
- **Absolute paths at the boundary.** Every filesystem entry point calls
  `resolve_path` (against the tracked `PWD`, lexically normalized), because the
  kernel accepts absolute paths only.
- **The ABI is the contract.** Syscall numbers, `Stat`, `Timespec`, `Uname`,
  `Dirent` sizes and flags live in `libpagh`; `pagh_std` uses its wrappers,
  not hand-written `ecall`s.
- **Buffering is userland.** `File` is unbuffered; `BufReader`/`BufWriter` add
  the 8 KiB layer and are what the examples use for streaming.

## Verification summary

The transcript covers:

| Area | Evidence |
|---|---|
| args/envp/PWD | `cat`, `wc`, `find` with paths; `cd /mnt/demo` + `find .` |
| file streaming | `cat /mnt/hello.txt`, two files, missing file → exit 1 |
| buffered I/O | `wc` on a 33-byte file, 200-line file, two-file total, empty file |
| directories | `find` recursion, sorted entries, `-type f`, `-maxdepth 1`, symlink not followed |
| metadata | `find -ls` mode/size/ino; `fsops` file metadata |
| path | relative paths after `cd`; `fsops` lexical `canonicalize` |
| mutations | `fsops`: mkdir/write/copy/rename/hard link/symlink/readlink/truncate/remove_dir_all |
| env tracking | `chdir` probe: `set_current_dir`, relative read |
| time | `clock` probe: monotonic advance, `nanosleep`, uptime |
| panic/OOM | `panic` → 101; `oom` → 102 |
| stdin | `cat` no args echoes console input and stays alive (no EOF) |

`python3 tools/live_check.py` reproduces it; `docs/live-rust-sdk.txt` is the
captured run with the kernel hash and QEMU/toolchain versions in its header.

## CI

`.github/workflows/ci.yml`:

1. checks out `pagh-rust` and the sibling `pagh-api`;
2. installs the pinned toolchain, target and rustfmt;
3. runs `cargo fmt -p pagh_std -p pagh_hostcheck -p pagh_probes -- --check`
   (package-scoped because `--all` would reformat the sibling `pagh-api`);
4. runs `./build.sh --fixtures` (all examples and probes);
5. asserts every example is ≤ 1 MiB;
6. runs `cargo test -p pagh_hostcheck --target x86_64-unknown-linux-gnu --locked`;
7. uploads the three example ELFs.

The live QEMU check is intentionally not in CI: it needs the kernel checkout
and QEMU, and the transcript is the acceptance artifact for this milestone.
`tools/live_check.py` is the command to run locally.

## License

No license file is included in this repository yet; treat the code as
all-rights-reserved until one is added.