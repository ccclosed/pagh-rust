# pagh-rust — a std-like Rust SDK for pagh-riscv

Native Rust programs for [pagh-riscv](../pagh-riscv): compiled with `rustc` for
`riscv64gc-unknown-none-elf`, linked against [`libpagh`](../pagh-api), and run
in U-mode with `run /mnt/...`.

## The honest scope

A full `rustc`/`std` **cannot** run on this OS. Compiling Rust needs LLVM and a
host operating system; `std` assumes libc, a C runtime, unwinding, a signal
stack, a wall clock and a dynamic loader that the pagh ABI does not have.

What *is* fully real is **Rust the language** plus the `alloc` crate:

- generics, traits, closures, iterators, pattern matching, `Result`/`Option`;
- `Vec`, `String`, `VecDeque`, `BTreeMap`, `BTreeSet`, `BinaryHeap`, and a
  real open-addressing `HashMap`/`HashSet` (0.7.0);
- `format!`, `println!`, `write!` and the rest of `core::fmt`;
- a 1 MiB bump heap over `brk`, with `Vec`/`String` growth and OOM handling;
- this crate's std-shaped layer over files, directories, arguments, paths,
  buffered I/O, time, process exit, native/scoped threads, synchronisation
  (mutexes, rwlocks, condition variables, channels, barriers, `Once`), signals,
  and the ABI's IPv4 sockets: a TCP client, a TCP listener and UDP datagrams;
- a **DNS stub resolver** (`pagh_std::net::dns`, RFC 1035 over a `UdpSocket`)
  and `connect("host:port")`, because the ABI has no resolver call;
- **TLS 1.3** (`pagh_std::tls`) through the **kernel's own** fail-closed client
  (pagh-riscv 0.21.0: `tls_connect` 1100 / `tls_write` 1101 / `tls_read` 1102 /
  `tls_close` 1103, plus `getrandom` 278): the certificate chain must reach the
  kernel's committed CA bundle, the SAN must authorize the name, the RTC clock
  gate must pass and `CertificateVerify` must check out. `TlsStream` gives
  `connect("host:port")`, read/write/close, and `https_get` is one call. The
  program supplies **no clock and no entropy** — the kernel has both. The 0.7.0
  userland implementation (vendored `embedded-tls`) stays behind the
  off-by-default `vendored-tls` feature;
- **userland I/O conveniences** (0.9.0): `io::Cursor` over any
  `T: AsRef<[u8]>` with `Read`/`BufRead`/`Seek`, `Read::chain`, and a `Tee`
  writer that mirrors into a second sink. All three are std-shaped, need no
  syscall, and are covered by the host gate as well as by a live boot.

`pagh_std` does **not** claim to be `std`, does not provide dynamic linking or
`OsStr`, and returns a typed `io::ErrorKind::Unsupported` for operations the
ABI cannot express. Those are listed under
[Limitations vs std](#limitations-vs-std).

**Live evidence:** [`docs/live-sdk-0.9.0.txt`](docs/live-sdk-0.9.0.txt) is the
QEMU serial transcript for 0.9.0 — one boot against `pagh-riscv 0.21.0` that
runs the `io_adapters` matrix, **12/12 checks passed**: `Cursor` reads and
seeks across buffer boundaries *in the guest*, `Chain` concatenates two
cursors, the empty cases and a real `File`, and `Tee` mirrors a line into
`/mnt/io_adapters_tee.txt` and to `stdout` — read back by a *different*
program (`cat`) and counted exactly once after a second run, so the mirror is
observed rather than asserted.

The 0.8.0 transcript remains the evidence for that release:
[`docs/live-sdk-0.8.0.txt`](docs/live-sdk-0.8.0.txt) is the
QEMU serial transcript — one boot against `pagh-riscv 0.21.0`
that runs the kernel-backed TLS matrix, **32/32 checks passed**: `tls_get`
fetches `https://example.com/` with **no clock argument and no seed argument**
and prints `status 200 body 577 bytes`, while the kernel prints its own
evidence (`tls: verified leaf=sha256:85ca6ab0… chain=4 certs anchors=6
host=example.com`, `tls: CertificateVerify OK`, `tls: user session 0 open
host=example.com`); `--manual` drives `TlsStream` (connect, write, read one
response, `close`); the vendored 0.7.0 program still fetches the same page
seeded from `getrandom`; and two refusals hold the line — a self-signed chain
(`tls: verify FAILED cause=chain`) and a trusted chain pinned under the wrong
name (`cause=hostname`), both `EKEYREJECTED` (errno 129) in userland.

The 0.7.0 transcript remains the evidence for that release
([`docs/live-sdk-0.7.0.txt`](docs/live-sdk-0.7.0.txt), **55/55 checks** against
`pagh-riscv 0.19.0` / QEMU 10.2.2, still reproducible by
`tools/live_070.py` on 0.21.0):
`HASH_MAP PASS` (a `Hash + Eq` key with no `Ord`, 1000 keys → `capacity 1536`,
500 removals, 64 keys in one bucket), `DNS PASS` (a real `A` query answered by
the DHCP-leased server the script read out of the kernel's own boot log,
`NXDOMAIN`, `InvalidName`, a 1 s deadline against a host black hole, and
`connect("example.com:80")` → `HTTP/1.1 200 OK`), `SOCKET_OPTS PASS`
(`getsockopt(SO_TYPE)`, `SO_REUSEADDR` accepted *and* the second `bind` still
refused, non-blocking read, a 500 ms SDK-enforced read deadline, `try_clone`
sharing one descriptor, the UDP deadline) and `TLS_GET PASS` — a live
`https://example.com/` fetch through a TLS 1.3 handshake whose chain validates
against the committed CA bundle (`chain=4 anchors=6`, leaf
`sha256:85ca6ab0…`), plus four refusals (`stage=clock`, `stage=entropy`,
`cause=chain`, `cause=hostname`).

The earlier transcripts remain the evidence for their releases:
[`docs/live-sdk-0.6.0.txt`](docs/live-sdk-0.6.0.txt) (47/47: TCP listener, UDP,
mpsc, barrier, `Once` and the `TcpStream` client),
[`docs/live-sdk-0.5.0.txt`](docs/live-sdk-0.5.0.txt) (condvar/io-traits) and
[`docs/live-rust-sdk.txt`](docs/live-rust-sdk.txt) (62/62, the 0.4.0 surface).

## Repository layout

```
Cargo.toml                 workspace: pagh_std, hostcheck, diagnostic probes
vendor/                    byte-pinned crates (embedded-tls + the verify-only
                           crypto backends), wired through .cargo/config.toml;
                           compiled only with the `vendored-tls` feature
rust-toolchain.toml        pinned nightly-2026-07-12 + riscv64gc target
.cargo/config.toml         target + pagh-user.ld + rust-lld (sibling layout)
build.sh                   builds the example ELFs (honours PAGH_API)
pagh_std/src/
  lib.rs                   crate docs, macros, prelude
  error.rs                 io::Error / ErrorKind / Result
  io.rs                    Read/Write/Seek/BufRead, console handles, poll
  io/pure.rs               the kernel-independent I/O core: traits, buffers,
                           Cursor, Read::chain, Tee (host-tested)
  fs.rs                    File/OpenOptions/ReadDir/Metadata + fs operations
  env.rs                   args/vars/PWD tracking/temp_dir
  path.rs                  UTF-8 Path/PathBuf/Components, prefix matching, lexical normalize
  time.rs                  Duration, Instant, SystemTime, sleep/sleep_until
  process.rs               exit/abort/fork/execve/wait/Command
  collections/             alloc containers + the real HashMap/HashSet
                           (Robin Hood probing, backward-shift deletion)
  hash.rs                  core::hash re-exports + deterministic hasher
  lazy.rs                  single-threaded LazyLock (pure core; host-tested)
  sync.rs                  Cell/RefCell/OnceCell + futex Mutex/RwLock/Condvar,
                           Barrier, Once
  sync/mpsc.rs             bounded Sender/Receiver channel over Mutex+Condvar
  thread.rs                Builder/JoinHandle/futex + thread::scope
  net.rs                   Ipv4/SocketAddr, TcpStream/TcpListener/UdpSocket,
                           socket options, connect(host:port)
  net/dns.rs               the stub resolver (RFC 1035 over a UdpSocket)
  net/dns_wire.rs          the pure query/response codec (host-tested)
  tls/mod.rs               TLS 1.3 docs + the fail-closed contract (the kernel's)
  tls/stream.rs            TlsStream (connect/read/write/close) + https_get
  tls/url.rs               the pure https://host[:port][/path] parser
  tls/http.rs              the pure HTTP/1.1 request/response codec
  tls/vendored/            the 0.7.0 userland stack: stream.rs (embedded-tls),
                           Entropy, and the ported verifier + CA bundle
                           ({x509,tls_verify,tls_chain,tls_auth,hostname})
  fmt.rs                   core::fmt re-exports
  panic.rs                 PanicInfo/abort + the runtime contract
  ffi.rs                   c_* types, CStr/CString
examples/                  cat, wc, find, threads_mutex, spawn, condvar, io_traits,
                           io_adapters, tcp_server, udp_echo, sync_primitives,
                           hash_map, dns, socket_opts, tls_get,
                           tls_get_vendored (feature-gated)
hostcheck/                 host cargo test for the pure modules (path, hash,
                           collections, lazy, dns_wire, tls url/http/hostname,
                           io core + error)
tools/probes/              panic/oom/chdir/fsops/clock diagnostic programs
tools/live_check.py        builds, boots QEMU, runs the 0.4.0 filesystem matrix
tools/live_070.py          the 0.7.0 live matrix: hash map, DNS, socket
                           options, the vendored TLS 1.3 client (one boot)
tools/live_080.py          the 0.8.0 live matrix: the kernel-backed TLS
                           client, its two refusals, and the vendored path
                           seeded from getrandom (one boot, one transcript)
tools/live_090.py          the 0.9.0 live matrix: Cursor/Chain/Tee in one
                           boot, including the Tee file read back by `cat`
tools/live_net.py          the 0.6.0 network/sync live matrix (one boot, one
                           command at a time, host peers, docs/ transcript)
.github/workflows/ci.yml   fmt + RISC-V build + host tests
docs/live-rust-sdk.txt     the 0.4.0 captured live run
docs/live-sdk-0.5.0.txt    the 0.5.0 condvar/io-traits captured runs
docs/live-sdk-0.6.0.txt    the 0.6.0 network/sync captured run (47/47)
docs/live-sdk-0.7.0.txt    the 0.7.0 captured run (55/55: hash map, DNS,
                           socket options, vendored TLS 1.3)
docs/live-sdk-0.8.0.txt    the 0.8.0 captured run (32/32: kernel-backed TLS)
docs/live-sdk-0.9.0.txt    the 0.9.0 captured run (12/12: Cursor, Chain, Tee)
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
./build.sh --vendored       # also build tls_get_vendored (needs the TLS stack)
```

Outputs (the kernel refuses images above 1 MiB — `run_file_with_argv0` checks
the size before mapping anything):

```text
target/riscv64gc-unknown-none-elf/debug/examples/cat … sync_primitives   (160–240 KiB)
target/riscv64gc-unknown-none-elf/debug/examples/hash_map                194 KiB
target/riscv64gc-unknown-none-elf/debug/examples/dns                     301 KiB
target/riscv64gc-unknown-none-elf/debug/examples/socket_opts             261 KiB
target/riscv64gc-unknown-none-elf/debug/examples/tls_get                 284 KiB
target/riscv64gc-unknown-none-elf/debug/examples/io_adapters             225 KiB
target/riscv64gc-unknown-none-elf/release/examples/tls_get_vendored      760 KiB
```

**Only the vendored TLS example is release-only.** 0.8.0's `tls_get` links no
TLS stack at all — the handshake is the kernel's — so its debug image is
284 KiB and CI gates it with every other default example.
`tls_get_vendored` links the vendored `embedded-tls` and the verify-only crypto
backends (RSA, P-256/P-384, Ed25519), whose *debug* build is 1.16 MiB — over
the kernel's limit — and 760 KiB in release, which is the profile
`tools/live_070.py` uses. The two paths are sized in one CI step.

Equivalent Cargo invocation:

```sh
cargo build --examples -p pagh_std
```

`build.sh` passes `-C link-arg=-T<pagh-api>/pagh-user.ld -C linker=rust-lld`
(mirroring `pagh-api/.cargo/config.toml`) and the pinned toolchain/target. It
does **not** pass `--locked`: the only non-vendored dependency is the sibling
`pagh-api`, so the `libpagh` version recorded in `Cargo.lock` follows another
repository's release cadence, and a hard lock would turn an old commit red
whenever that library bumps. The vendored crates stay exact-pinned in
`pagh_std/Cargo.toml` and are resolved from `vendor/`, so the lock is still the
source of truth for everything the SDK links.
The linker script places the image at `0x1_0000`, `_start` in `.text.entry`,
and produces R+X/R/R+W `PT_LOAD` segments; there is no TLS, `.init_array` or
dynamic section.

### Host tests

The pure logic can be compiled for the host; `libpagh` itself cannot
(RISC-V `ecall` assembly). `hostcheck` includes the pure sources directly —
`path.rs`, `hash.rs`, `collections/{hash_map,hash_set}.rs`, `lazy.rs`,
`net/dns_wire.rs`, `tls/{url,http}.rs`, the vendored `tls/vendored/hostname.rs`
and, since 0.9.0, `error.rs` plus the kernel-independent half of the I/O
module, `io/pure.rs` — 69 checks:

```sh
cargo test -p pagh_hostcheck --target x86_64-unknown-linux-gnu
```

Two details are deliberate. `libpagh::errno::Errno` is the only type the
included sources name from the bare-metal crate, so the gate compiles the
sibling checkout's own `errno.rs` (its numbers, messages and two round-trip
tests arrive with it) instead of a copy that can drift. `SeekFrom` is the one
exception: `libpagh::io` also holds the syscall-backed console handles, so the
host crate spells out that std-shaped three-variant enum; on the target
`pagh_std::io::SeekFrom` is `libpagh::io::SeekFrom`.

CI runs that plus `cargo fmt -p pagh_std -p pagh_hostcheck -p pagh_probes --
--check`, `./build.sh --fixtures`, a 1 MiB size check for all fifteen debug
examples, and `./build.sh --release --vendored` with a size check for
`tls_get_vendored` (release-only: its debug build is over the limit). (The package-scoped
form is deliberate: `cargo fmt --all` also formats local path dependencies, and
the sibling `pagh-api` checkout must not be modified.) It checks out `pagh-rust` and `pagh-api` as siblings.

## Run it in QEMU

Use the kernel from `pagh-riscv` and a host-built ext2 image:

```sh
mkdir -p rootfs/demo/sub
cp target/riscv64gc-unknown-none-elf/debug/examples/{cat,wc,find,condvar,io_traits} rootfs/
cp target/riscv64gc-unknown-none-elf/debug/examples/{tcp_server,udp_echo,sync_primitives} rootfs/
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
run /mnt/condvar
run /mnt/io_traits
run /mnt/io_traits net 10.0.2.2 18080   # with --net and a host server
run /mnt/sync_primitives
run /mnt/udp_echo 10.0.2.2 18081 45680  # with --net and a host UDP echo server
run /mnt/tcp_server 45679 2             # with --net --hostfwd 45679:45679
run /mnt/hash_map
run /mnt/dns
run /mnt/dns --connect=example.com:80    # with --net: resolve + HTTP GET
run /mnt/dns --server=10.0.2.2 --port=45690 --deadline-ms=1000   # silent server
run /mnt/socket_opts --peer=10.0.2.2:45683                       # with --net: host echo
run /mnt/tls_get                        # https://example.com/, kernel TLS
run /mnt/tls_get https://example.com/ --manual
run /mnt/tls_get https://example.com:8443/ --ip=10.0.2.2   # pin the address
run /mnt/tls_get_vendored https://example.com/ 1794234113 kernel  # --vendored build
```

`tls_get` needs neither a clock nor a seed: the kernel does the handshake (see
[`pagh_std::tls`](#pagh_stdtls)). The vendored program is the one that still
needs the caller's clock (`<unix-seconds>`); `kernel` is its new entropy option,
which fills the seed from `getrandom(278)` instead of a staged file.

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

The last full run (tag 0.4.0): **62/62 checks passed** against
`pagh-riscv 0.11.0` / QEMU 10.2.2. The transcript is the source of truth; the
summary includes `cat`, `wc`, `find`, relative paths after `cd`, `fsops`
(mkdir/write/copy/rename/hard link/symlink/readlink/truncate/remove),
`set_current_dir`, monotonic/uptime clocks, `nanosleep`, panic 101 and OOM 102.
Console stdin is tested last: `cat` with no arguments echoes `console stdin
works`, then keeps waiting because the ABI has no EOF; the script terminates
QEMU itself.

For 0.5.0, the focused live check was the requested explicit QEMU invocation:

```sh
truncate -s 64M disk.img
mke2fs -q -t ext2 -F -b 4096 -d rootfs disk.img
cd ../pagh-riscv
python3 tools/run.py --disk /tmp/pagh-rust.img \
  --keys 'run /mnt/condvar\nrun /mnt/io_traits\nhalt\n' \
  --settle 40 --serial-log /tmp/pagh-rust-serial.log
```

On the default debug kernel both programs print `PASS` and exit 0; the exact
serial text is in `docs/live-sdk-0.5.0.txt`. A second run with `--net` and a
host echo server proves the `TcpStream` trait path.

For 0.6.0 the live check is one boot driven by `tools/live_net.py`:

```sh
python3 tools/live_net.py            # builds, boots, drives, writes docs/
python3 tools/live_net.py --skip-build --keep-work
```

It stages the release ELFs in a 64 MiB ext2 image (`mke2fs -d`, no root),
boots QEMU through `pagh-riscv/tools/run.py --net --hostfwd … --keep`, then
reconnects to the serial socket and types one command at a time — necessary
because the shell's UART ring is 16 bytes deep and the `tcp_server` host client
must not connect before the guest is listening. Host peers: a UDP echo server
(guest reaches it as `10.0.2.2:<port>`), a TCP server for `io_traits net`, and
a two-connection TCP client for `tcp_server`. The transcript is
`docs/live-sdk-0.6.0.txt`; exit status is 0 only when all 47 checks pass.

For 0.7.0 the live check is `tools/live_070.py`, four new programs in one boot:

```sh
python3 tools/live_070.py                     # builds, boots, drives, writes docs/
python3 tools/live_070.py --skip-build --keep-work
```

| program | what the boot proves |
|---|---|
| `hash_map` | a key type with `Hash + Eq` and **no `Ord`**, real spare `capacity()` (1000 keys → 1536 buckets), 500 removals with the other 500 still reachable, 64 keys forced into one bucket and a middle deletion that keeps the run reachable (backward shift, no tombstones), `entry`/`retain`/`extend`/`FromIterator`, `Index`, and `HashSet` set algebra |
| `dns` | a real `A` query answered by the **DHCP-leased** server (the script reads `dns 10.0.2.3` out of the kernel's own boot log and stages exactly that value in `/etc/resolv.conf`, so lease → configuration → query is one chain), the server's TTLs, `NXDOMAIN`, an unencodable name refused before any datagram, a deadline against a host socket that never answers, and `connect("example.com:80")` doing a real HTTP GET |
| `socket_opts` | `getsockopt(SO_TYPE)` for a stream and a datagram socket, `SO_REUSEADDR` accepted **and** shown not to change a second `bind` (the kernel validates and ignores it), a non-blocking read measured at `WouldBlock`, a 500 ms read deadline enforced by the SDK (the kernel's `SO_RCVTIMEO` reads back zero), `try_clone` sharing one descriptor with the echo read back through the clone, and the UDP receive deadline |
| `tls_get_vendored` | a live HTTPS GET of `example.com` through the **0.7.0 userland** client — TLS 1.3 handshake, chain to the committed CA bundle (`anchors=6`), SAN check, clock gate, `CertificateVerify`, 577-byte body — plus four refusals: no clock (`stage=clock`), no entropy (`stage=entropy`), a self-signed chain (`cause=chain`) and a trusted chain for the wrong name (`cause=hostname`) |

For 0.8.0 the live check is `tools/live_080.py`, the kernel-backed TLS matrix in
one boot:

```sh
python3 tools/live_080.py                     # builds, boots, drives, writes docs/
python3 tools/live_080.py --skip-build --keep-work
```

| program | what the boot proves |
|---|---|
| `tls_get` (default) | `https://example.com/` end to end with **no clock and no seed on the command line**: the SDK resolver, the TCP connect, then the kernel's fail-closed handshake — `tls: verified leaf=sha256:85ca6ab0… chain=4 certs anchors=6 host=example.com`, `tls: CertificateVerify OK`, `tls: user session 0 open host=example.com (TLS 1.3, AES-128-GCM-SHA256, server authenticated, 110 ms)`, `200` and a 577-byte body |
| `tls_get --manual` | the same fetch through `TlsStream` spelled out: `connect`, `write_all`, `read_http_response`, `close` |
| `tls_get_vendored … kernel` | the 0.7.0 userland stack still works on the new ABI and takes its seed from `getrandom(278)`; it still needs the caller's clock, which is exactly the difference the two programs make visible |
| refusals | a self-signed `example.com` on the host (`cause=chain`) and a trusted Google chain pinned under the name `example.com` (`cause=hostname`) are both refused with `EKEYREJECTED`/errno 129, so "the kernel verifies" is not an assertion but a rejection that was observed |

For 0.9.0 the live check is `tools/live_090.py`, one boot for the new
userland adapters:

```sh
python3 tools/live_090.py                     # builds, boots, drives, writes docs/
python3 tools/live_090.py --skip-build --keep-work
```

| command | what the boot proves |
|---|---|
| `run /mnt/io_adapters` | the example's three sections print `Cursor`/`Chain`/`Tee` `ok` and `IO_ADAPTERS PASS` (exit 0): `Cursor` reads and seeks across buffer boundaries in the guest, `Chain` covers two cursors, both empty cases and a real `File`, `Tee` mirrors one line to `stdout` **and** `/mnt/io_adapters_tee.txt` |
| `run /mnt/io_adapters` again | the file is truncated and rewritten, not appended (checked by the count below) |
| `run /mnt/cat /mnt/io_adapters_tee.txt` | a *different* program reads the file half; the transcript holds exactly one copy of the mirrored line and `cat` exits 0 |

## API surface

### `pagh_std::io`

| Item | Notes |
|---|---|
| `Read` | `read`, `read_to_end`, `read_to_string`, `read_exact`, `bytes`, `take`, `chain`, `by_ref`; implemented for `File`, `TcpStream`, `Stdin`, `BufReader`, `Cursor`, `Chain`, `Take`, `&[u8]`, `&mut R` |
| `Write` | `write`, `flush`, `write_all`, `write_fmt`, `by_ref`; `File`, `TcpStream`, `Stdout`, `Stderr`, `BufWriter`, `Tee`, `&mut W` |
| `Seek`, `SeekFrom` | `seek`, `stream_position`, `rewind`, `seek_relative`; regular files and `Cursor` |
| `BufRead`, `BufReader`, `BufWriter` | `fill_buf`, `consume`, `read_until`, `read_line`, `lines`, `split`; 8 KiB default buffer, `with_capacity`, `into_inner`, `get_ref`, `get_mut`; also implemented directly on `File`, `TcpStream`, `Cursor` and `Chain` |
| `Cursor<T: AsRef<[u8]>>` | in-memory reader: `Read`, `BufRead` and `Seek` (`Start`/`Current`/`End`), `new`, `position`/`set_position`, `get_ref`/`get_mut`, `into_inner`; seeking past the end is allowed (the next read is EOF) and a seek before byte 0 is `InvalidInput`, as in std |
| `Chain<T, U>` | returned by `Read::chain`; reads `first` to EOF and then `second`, never touching `second` early; `BufRead` when both halves are; `get_ref`/`get_mut`/`into_inner` |
| `Tee<W, F>` | `Write` adapter that mirrors every byte `writer` accepts into `file` with `write_all`; `new`, `get_ref`/`get_mut`, `into_inner`; `flush` flushes the writer first |
| `stdin`, `stdout`, `stderr` | console handles; `Stdin::read` blocks by retrying `EAGAIN` with `sched_yield`; output retries `EAGAIN` too |
| `read_to_end`, `read_to_string`, `copy` | free functions over `Read`/`Write` |
| `empty`, `repeat`, `sink` | trivial adapters |
| `Error`, `ErrorKind`, `Result` | `Error` wraps `libpagh::errno::Errno`, keeps the raw number, maps to std-shaped kinds; `Unsupported` is the typed "ABI cannot do this" |

`Cursor`, `Read::chain` and `Tee` are the items 0.8.0's README listed as
deliberately absent; they are userland-only and need no syscall. Two deviations
from `std` are spelled out where they live: this `Cursor` has **no `Write`
implementation** (std has one for `Cursor<&mut [u8]>`/`Cursor<Vec<u8>>`/
`Cursor<Box<[u8]>>`; here the `T: AsRef<[u8]>` reader is the whole type), and
`Tee` — which `std` only has on nightly behind `#![feature(io_tee)]` — is
stable here.

`is_terminal` remains absent, now for a checked reason rather than a policy
one: the ABI's `fstat` reports the console as `kind = Other`, mode `0o644`,
which is exactly what it reports for a socket or a pipe, and fds 0-2 are not
permanently the console either (the kernel's `dup`/`dup2`/`pipe2` can fill a
closed slot). A truthful `is_terminal` needs a kernel-side signal; the SDK will
not guess from the fd number.

`BufRead` on `File` and `TcpStream` is a pagh extension (`std` implements it
for `BufReader`, not for those concrete types). `fill_buf` reads ahead into an
8 KiB internal buffer; `Read` drains that buffer, `Seek` accounts for it, and
`File::write` rewinds over unread bytes first. `BufReader` remains the explicit
buffering layer for streaming. On a `TcpStream`, `Read`/`Write` block by
retrying `EAGAIN` with `sched_yield` (the ABI's `recv`/`send` are
non-blocking).

`write!`/`writeln!` are the core prelude macros; they call
`Write::write_fmt`, so they work with every `pagh_std` sink. `println!`-style
macros ignore write errors (there is no useful recovery on fd 1); use
`writeln!(io::stdout(), ...)` when the error matters.

### `pagh_std::fs`

| Item | Notes |
|---|---|
| `File` | `open`, `create`, `create_new` (always `Unsupported`), `options`, `metadata`, `set_len`, `as_raw_fd`, `into_raw_fd`, `unsafe from_raw_fd`, `Read`/`Write`/`Seek`/`BufRead`, closes on drop |
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
`id()` (`getpid`), `fork()`, `execve(path, argv, envp)`, `wait(pid)`,
`try_wait(pid)`, `parent_id()`, `ExitStatus` (raw wait-status decoding),
`Output`, `Child`, `Command`.

`Command::{spawn,status,output}` are real now: `spawn` forks, wires `stdout` to a
pipe when capturing, and execs the program in the child; `status` runs and waits;
`output` reads the pipe to EOF and returns stdout + status. There is no
`SIGCHLD`, so `wait`/`wait4` is the only completion mechanism; `current_dir` on
`Command` is not applied by the kernel (no chdir yet) and `env` maps to the
execve `envp` array.

### `pagh_std::time`

`Duration` (core), monotonic `Instant`, uptime-based `SystemTime`,
`UNIX_EPOCH`, `SystemTimeError`, `sleep(Duration)` (`nanosleep`, rounded up to
the 10 ms tick).

`Instant` and `SystemTime` read `clock_gettime(1)` and `clock_gettime(0)`
respectively. Both are tick counters since boot: the kernel's syscall layer maps
both clock ids to `timer::uptime_ms()`, and it exposes no wall-clock read even
though the machine has a goldfish RTC (the kernel uses it for TLS validity
windows). `SystemTime` is therefore **not** a Unix timestamp and `UNIX_EPOCH`
is the boot instant.
Arithmetic saturates rather than panicking; `checked_*` methods are available.
`Instant::now()`/`SystemTime::now()` fall back to zero if the syscall fails;
`try_now()` surfaces the error.

`time::sleep_until(deadline)` (and the `Instant::sleep_until` method) sleeps
for the remaining time and returns immediately when the deadline has passed —
the shape a bounded wait loop needs. `Instant::elapsed_millis` is the same
elapsed time as a `u64` for log lines. Both inherit the kernel's 10 ms tick:
`sleep_until` is a deadline with tick granularity, not a real-time guarantee.

### `pagh_std::path`

UTF-8 `Path` (unsized, `#[repr(transparent)]` over `str`) and `PathBuf`
(`String`): `new`, `as_str`, `to_path_buf`, `join`, `parent`, `file_name`,
`file_stem`, `extension`, `with_extension`, `with_file_name`, `display`,
`components`, `starts_with`, `strip_prefix`, `ancestors`,
`is_absolute`/`is_relative`, `to_str`, `to_string_lossy`,
`push`/`pop`/`set_file_name`/`set_extension`, `normalize`, `normalize_join`,
and `Display`/`Debug`.

`components()` yields `RootDir`, `CurDir`, `ParentDir`, `Normal(&str)` and
keeps a `CurDir` for an empty path and for every interior `.`: it is the
textual view the normalization helpers read (std skips those). The query
methods are std-exact: `starts_with`/`strip_prefix` compare whole components
(never byte prefixes), `strip_prefix` returns the remainder borrowed from the
path with its edges trimmed the way `Components::as_path` trims them, and
`parent`, `file_name`, `file_stem` and `extension` skip trailing separators and
trailing `.` components (`a/./` names `a`, `/a/./b` has parent `/a`).
`ancestors` walks the `parent()` chain down to the empty path. There is no
`OsStr` and no Windows prefix.

### `pagh_std::collections` and `pagh_std::hash`

Real `alloc` types: `Vec`, `String`, `VecDeque`, `BTreeMap`, `BTreeSet`,
`BinaryHeap`, plus `Box`, `ToOwned`, `ToString`.

`HashMap`/`HashSet` are a **real hash table** (0.7.0; the 0.6.0 `BTreeMap` shim
is gone): Robin Hood linear probing over a power-of-two bucket array with
backward-shift deletion (no tombstones) and a 3/4 maximum load factor. Keys
need `Hash + Eq`, not `Ord`; `capacity()` reports real spare capacity;
`try_reserve`/`try_reserve_exact` return a `TryReserveError` instead of
aborting; iteration order is unspecified (bucket order) and changes as the
table grows, exactly like `std`. The stored hash is mixed with a 64-bit
finalizer before the low bits are used as a bucket index, so a `Hasher` only
has to be consistent, not well distributed.

`hash` re-exports `Hash`/`Hasher`/`BuildHasher` and provides a deterministic
FNV-1a `RandomState`/`DefaultHasher` (the default `HashMap` hasher) — this
hasher never claims to be randomly seeded (it would need `getrandom` per map),
and a map keyed by
attacker-controlled strings is **not** hash-flooding resistant. The honest
statement is the documented one: pass a different `BuildHasher` if the keys are
hostile.

### `pagh_std::sync`

`Cell`, `RefCell`, `OnceCell`, `UnsafeCell` from `core::cell`, a
single-threaded `LazyLock<T, F>`, and **real futex-backed `Mutex<T>`/`RwLock<T>`**
(non-poisoning, process-private; guards implement `Deref`/`DerefMut`). They work
with native threads and sleep on the futex word rather than spinning.

`Condvar` is the std shape: `wait(guard)` releases the mutex, blocks on a
per-condvar futex sequence word, and re-acquires the mutex before returning;
`wait_timeout(guard, duration)` also returns a `WaitTimeoutResult`;
`notify_one` advances the sequence and wakes one waiter; `notify_all` wakes
every waiter. Deviations are documented on the type: no poisoning; a signal
(`EINTR`) or a full kernel futex table makes a wait return spuriously (re-check
the predicate); timeouts round **up** to the 10 ms kernel tick; there is no
realtime-clock futex. The kernel tracks at most 32 waiters and 16 futex
addresses per boot.

The timed wait builds its own `Timespec` on the call frame. This is deliberate:
`libpagh::thread::futex_wait` (0.1.0) points the kernel at a temporary that is
already dead by syscall time, so a timed wait reads an arbitrary stack value;
the SDK-side workaround is covered by the live `wait_timeout` check.

`Barrier::new(parties)` + `wait() -> BarrierWaitResult` is the std rendezvous:
every party blocks until `parties` have arrived, exactly one caller per
generation is the leader, and the generation resets. Deviation: `Barrier` never
panics — a zero-party barrier releases every caller immediately as the leader
(std panics on `new(0)`).

`Once::new()` + `call_once(f)` + `is_completed()` runs `f` exactly once for the
process: the first caller runs it with the lock released while the others
block; when it returns, every waiter is released and later callers return
immediately. Reentrancy deadlocks, exactly like `std::sync::Once` (the state has
no reentrant owner); `panic = "abort"` means a panicking closure kills the
process rather than poisoning the `Once`.

`sync::mpsc` is a **bounded** channel (`std::sync::mpsc` is unbounded): the
`VecDeque` behind it allocates from a 1 MiB bump heap that never returns
memory, so `channel()` uses `DEFAULT_CAPACITY` (32) and `sync_channel(n)`
chooses the depth (0 is clamped to 1 — no zero-capacity rendezvous). The types
are std-shaped: `Sender`/`SyncSender` (the same type, `Clone` + `Send`),
`Receiver`, `send` (blocks while full), `try_send`, `recv`, `try_recv`,
`recv_timeout`, `iter`, and the `SendError`/`RecvError`/`TrySendError`/
`TryRecvError`/`RecvTimeoutError` types. Dropping every sender disconnects a
blocked `recv`; dropping the receiver makes `send` return the value.

### `pagh_std::thread`

`Builder`, `JoinHandle`, `DEFAULT_STACK_SIZE`, `current_id`, `yield_now`,
`exit`, `exit_group`, `futex_wait`/`futex_wake`, and **`thread::scope`**.

`thread::scope` is std-shaped: the closure gets a `Scope`, `Scope::spawn`
accepts a closure that borrows stack data, the returned `ScopedJoinHandle::join`
returns the closure's value, and unjoined threads are joined automatically
before `scope` returns. `Scope::try_spawn` is the fallible form. Deviations:
`panic = "abort"` means no unwind or panic payload; the scope handle is
single-threaded (spawn from the thread that called `scope`); there is no
`Builder::spawn_scoped`. The implementation erases the closure's lifetime to
satisfy `libpagh`'s `'static` builder and joins every child before the borrows
can end; the `SAFETY` comments in `thread.rs` state that invariant.

### `pagh_std::net`

`Ipv4` (literal parse/format) and `SocketAddr` (`Ipv4` + port, `parse`,
`Display`, `FromStr`) for the ABI's IPv4-only world, plus three socket types.
All three own their descriptor and are built on `libpagh::sys`'s socket
syscalls, so the SDK can remember what the ABI cannot report (there is no
`getsockname`) and can present one blocking shape over non-blocking syscalls.

| Item | Notes |
|---|---|
| `TcpStream` | `connect` (IPv4 literal), `connect_host(host, port)` (DNS), `fd`, `peer_addr` (remembered from `connect`/`accept`), `shutdown`, `read_to_end`, `buffered`, `set_nonblocking`/`is_nonblocking`, `set_read_timeout`/`set_write_timeout` (+ getters), `set_reuseaddr`, `socket_type`, `try_clone`; `Read`/`Write`/`BufRead` with blocking retry semantics |
| `TcpListener` | `bind(port)`, `bind_to(address, port)`, `bind_with_backlog`, `fd`, `local_addr`, `set_reuseaddr`, `socket_type`, `accept`, `accept_nonblocking`, `incoming` |
| `UdpSocket` | `bind(port)`, `bind_to(address, port)`, `fd`, `local_addr`, `set_nonblocking`/`is_nonblocking` (SDK state, `&self`), `set_read_timeout`/`read_timeout`, `socket_type`, `send_to`, `recv_from`, `try_recv_from` |
| `connect("host:port")` | resolve (if it is not a literal) and connect — the `std`-shaped entry point |
| `dns` | `resolve`, `resolve_all`, `Resolver` (`with_servers`, `system`, `set_port`, `set_timeout`, `set_attempts`), `Error`, `parse_resolv_conf`; `dns_wire` is the pure codec |

`TcpListener` is created `SOCK_NONBLOCK` at the ABI level: `accept()` retries
the non-blocking accept and yields the CPU between attempts (the std blocking
contract — every retry polls the kernel's NIC), while `accept_nonblocking()`
is a single poll that answers `WouldBlock`. `local_addr` reports the address the
caller passed to `bind`/`bind_to`; an ephemeral bind (`port == 0`) returns a
typed `Unsupported` error, because no syscall can report the chosen port.
`accept` returns the peer address from the accept call itself.

`UdpSocket::recv_from` blocks (retrying the ABI's bounded ≈10 s receive);
`set_nonblocking(true)` switches it to a single `MSG_DONTWAIT` poll, and
`try_recv_from` is that poll regardless of the mode. `set_nonblocking` does not
change `send_to`: the ABI has no non-blocking send shape, and a UDP send can
block only while ARP resolves the next hop. A datagram larger than the caller's
buffer is truncated by the kernel; more than 1024 payload bytes is rejected
before anything is sent.

**Socket options.** `setsockopt`/`getsockopt` exist in the ABI but are a
validated no-op for everything except the `SO_TYPE`/`SO_ERROR` reads, so the
SDK splits the two claims: `socket_type()` is a real round trip (`Stream` or
`Datagram`), `set_reuseaddr(bool)` returns the kernel's own answer *and* the
docs say what it does not do (a second `bind` of the same port still fails —
the live transcript shows both halves), and the timeouts are issued to the ABI
while being **enforced by the SDK**, because the kernel ignores the value
(`SO_RCVTIMEO` "reads back as zero"). A read or write that passes its deadline
returns `WouldBlock`, as `std::net::TcpStream::set_read_timeout` documents. A
kernel that answered `-ENOPROTOOPT` produces a typed `Unsupported` error
instead.

**Non-blocking mode and `try_clone`.** The ABI has no `fcntl`, and a stream
`recv` is already non-blocking by contract (`-EAGAIN` when nothing is queued),
so `set_nonblocking` is SDK policy: `true` turns the first `EAGAIN` into
`WouldBlock`, `false` yields and retries. `dup` refuses sockets in this kernel
(a second descriptor for one connection would be a second owner without a
reference count), so `try_clone` is *shared ownership of one descriptor*, not
`std`'s descriptor duplication: both handles read and write the same socket and
the connection closes when the last one drops. The read-ahead buffer and the
timeout/non-blocking policy are per handle.

**DNS.** The ABI exposes neither a resolver call nor the DHCP lease, so
`pagh_std::net::dns` speaks RFC 1035 itself over a `UdpSocket`: one `A`
question, a bounded retry budget, a fail-closed parser (compression pointers
must point strictly backwards; the reply must echo the transaction id and the
question), `CNAME` following (four hops), and typed errors (`NameError`,
`ServerFailure`, `Refused`, `NoRecords`, `Timeout`, `Truncated`, `Malformed`,
`InvalidName`). The server list comes from, in order: the caller
(`Resolver::with_servers`), `/etc/resolv.conf` then `/mnt/etc/resolv.conf`
(BSD convention), or the compiled-in `10.0.2.3` — QEMU's user-network DNS and
the DHCP option 6 value on the network the live runs use. There is no IPv6, no
`AAAA`/`MX`/`TXT`, no TCP fallback for a truncated answer, and no cache. The
transaction id varies but is **not** unpredictable (a clock-seeded counter; the
resolver does not call `getrandom`), which is stated rather than implied.

The kernel's limits apply: one active-open TCP client at a time (accepted
server connections and the listener have their own descriptors), one listener
with a four-entry accept queue (backlog clamped to `1..=4`), eight TCP
connections, eight bound UDP ports, and sixteen file descriptors per process.
There is no IPv6, no `getpeername`, no `getsockname`, no `fcntl` and no
half-close in this layer.

### `pagh_std::tls`

TLS 1.3 over a `TcpStream`, built on the **kernel's** client: pagh-riscv 0.21.0
owns the handshake, the key schedule, the record layer and a fail-closed
verifier, and exposes them as four pagh-native syscalls (`docs/abi.md` §2 in
`pagh-api`):

| nr | call | what it does |
|---|---|---|
| 1100 | `tls_connect` | handshake on a **connected** stream socket; the descriptor becomes the session, with `flags` fixed at 0 — there is no "insecure" bit to set |
| 1101 | `tls_write` | encrypt application data |
| 1102 | `tls_read` | decrypt application data; `0` is the peer's `close_notify` |
| 1103 | `tls_close` | send `close_notify`, release the session, close the descriptor |

| Item | Notes |
|---|---|
| `TlsStream` | `connect("host:port")` (SDK resolver + TCP + handshake) or `connect_stream(socket, host)`; `read`, `write`, `write_all`, `flush`, `read_http_response`, `close`, `peer_addr`, `host`, `fd`; `Read`/`Write`; `Drop` closes without the alert |
| `https_get` / `https_get_at` | one `GET`, returning an `HttpResponse` with `status()`, `body()`, `body_len()`; the body framing the response declares (`Content-Length`, chunked, close-delimited) is followed, and a stream that ends inside a declared body is an error |
| `http` | the pure request builder and response-head parser (shared with the vendored path, host-tested) |
| `url` | the pure `https://host[:port][/path]` parser (host-tested) |
| `vendored` | the 0.7.0 userland stack, compiled only with the `vendored-tls` feature |

**What is verified, and by whom.** The **kernel** verifies, before a single
application byte can move: the chain must reach an anchor of its committed CA
bundle (6 curated roots: ISRG X1/X2, GTS R1/R4, SSL.com ECC/RSA 2022), the SAN
entries must authorize the `host` the caller passed (RFC 6125, **no** CN
fallback — and that name is also the SNI, so pinning an address cannot bypass
it), the certificate validity windows must contain the machine's real time from
its goldfish RTC, `CertificateVerify` must prove possession of the leaf key,
and the kernel independently requires that a certificate was verified *during
this* handshake before it hands out the session. A refusal arrives as
`EKEYREJECTED` (errno 129, `ErrorKind::PermissionDenied`) for a rejected
certificate, `EPROTO` for a malformed handshake, `ENOTSUP` when the machine has
no wall clock and `EAGAIN` when the entropy pool has no seed; the kernel prints
the exact gate on the serial line (`tls: verify FAILED cause=chain|hostname|
clock|signature`, `tls: user session host=… REFUSED cause=NoEntropy|NoClock`).

**No clock, no entropy, no flags.** 0.7.0's userland client had to ask the
caller for a wall clock and 32 bytes of entropy because the ABI had neither;
`getrandom` (278) and the RTC close that gap, and `TlsStream::connect` now
takes nothing but a `host:port`. The kernel-backed path is the default because
it is the one whose verifier a program cannot weaken, replace or forget to run.

**The vendored 0.7.0 path** (`vendored-tls` feature, module
`pagh_std::tls::vendored`) is kept for the case where the process itself must
own the verifier, or must run on a kernel older than 0.21.0. It is the same
`embedded-tls` 0.19.0 the kernel used to link, with the same deliberate local
patch (upstream reached `ApplicationData` even when the server never sent
`Certificate`, so the vendored state machine refuses `Finished` unless the
certificate was received *and* verified) and the same ported pure verifier. Its
`TlsStream::connect(stream, server_name, now_unix, &mut Entropy)` still takes
the caller's clock — `clock_gettime(CLOCK_REALTIME)` is the uptime counter and
there is no RTC syscall — which remains the honest gap in that path;
`Entropy::from_kernel()` now fills the seed from `getrandom` instead of
requiring 32 bytes from outside the machine, and `Entropy::from_seed`/`from_hex`
stay for a harness that reproduces a transcript. Its refusals print the gate
that refused (`tls: verify FAILED cause=…` with `chain`, `hostname`,
`no-hostname`, `leaf-key`, `clock`, `signature-scheme` or `signature`) and its
successes print the leaf fingerprint, chain length and anchor count, so a
transcript can be cross-checked against `openssl s_client` on the host
(`docs/live-sdk-0.7.0.txt`, re-verified on 0.21.0).


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

- **`std::thread`/scoped threads**: `pagh_std::thread` provides native
  `Builder`/`JoinHandle`/futex and `thread::scope`, but no TLS, no unwinding,
  no `Builder::spawn_scoped`, and no way to spawn from a sibling thread through
  the same `Scope`;
- **`Condvar` edge cases**: non-poisoning, no realtime-clock timeout, 10 ms
  timeout granularity, and spurious returns on signal/futex-table pressure;
- **processes without COW**: `fork` deep-copies user pages (no COW), the child's
  socket fd is `ENOTSUP` (one TCP connection), and there is no `SIGCHLD`;
  `Command::current_dir` is not applied (no `chdir` syscall); signals are in
  `pagh_std::signal`;
- **networking limits**: one active-open TCP client at a time, one listener
  with a four-entry accept queue, eight TCP connections and eight bound UDP
  ports; no `getsockname`/`getpeername` (`local_addr`/`peer_addr` are the SDK's
  record of the call), no half-close, and no way to learn an ephemeral port.
  `libpagh` 0.6.0's frozen errno table has no `EADDRINUSE`, `EADDRNOTAVAIL`,
  `EMSGSIZE`, `EINTR`, `E2BIG`, `ESRCH`, `ENOEXEC`, `ECHILD` or
  `EDESTADDRREQ`, so with that sibling a bind conflict, a non-local bind
  address and an oversized datagram arrive as `ErrorKind::Uncategorized` with
  the message `Unknown error (outside the pagh ABI)`. `pagh_std` maps the
  numbers libpagh 0.6.1 records by raw value, so once the sibling is 0.6.1 the
  same build reports `AddrInUse` / `AddrNotAvailable` / `InvalidInput` (and the
  ABI's own message text) without a source change here; `EINTR` and `E2BIG` get
  `Interrupted` and `ArgumentListTooLong`. `SO_REUSEADDR` is accepted by the
  kernel and has no effect (ports are reserved at `bind`); the SDK's timeouts
  are enforced by the SDK. `try_clone` shares one descriptor because the ABI refuses `dup`
  on a socket. IPv6 does not exist here;
- **DNS**: `pagh_std::net::dns` is a stub resolver, not a system resolver: it
  has no IPv6/`AAAA`, no `MX`/`TXT`/`SRV`, no TCP fallback for a truncated
  answer, no cache, no `search`/`ndots` processing, and a transaction id that
  varies but is not unpredictable (a clock-seeded counter, not `getrandom`). The
  ABI cannot report the DHCP lease, so the server list comes from a
  configuration file or the compiled-in `10.0.2.3` (documented, and the live run
  proves the value is the leased one);
- **TLS**: the default path has no wall-clock or entropy limitation — the
  kernel reads its RTC and its seeded pool (pagh-riscv 0.21.0) — but the
  verifier is the kernel's, so a program cannot pin a different CA set, inspect
  the chain, or see the leaf fingerprint through this API (`EKEYREJECTED` is
  the whole answer; the serial line carries the gate). The `vendored-tls`
  feature keeps the 0.7.0 userland client for that, at the cost of the caller's
  wall clock, since the ABI still has no RTC read. Absent on both paths: client
  certificates (`mTLS`), session resumption, `close_notify` on drop,
  RSA-PSS *certificate* signatures (the TLS 1.3 `CertificateVerify` PSS schemes
  are supported), pre-shared-key handshakes, and any TLS version below 1.3;
- **`mpsc` is bounded**: `channel()` holds 32 values and `sync_channel(0)` is
  clamped to 1; there is no unbounded channel and no zero-capacity rendezvous;
- **`Barrier`/`Once` deviations**: `Barrier::new(0)` waits for nobody and
  returns every caller as the leader instead of panicking, and calling
  `Once::call_once` from inside its own closure deadlocks (as in std);
- **dynamic linking**, `dlopen`, shared libraries: one static ELF, no loader;
- **`OsStr`/`OsString` and non-UTF-8 paths**: the SDK stores UTF-8; directory
  names are decoded lossily (U+FFFD), so a non-UTF-8 filename cannot be opened
  by its exact bytes;
- **`mmap`** is available in the raw `libpagh` ABI (anonymous private pages);
  `pagh_std` still exposes only the `brk` heap;
- **`select`/epoll**, `stdin` EOF: `io::poll(&mut [PollFd], timeout)` exists
  (the ABI's `poll`), but there is no `select`/`epoll`; `read(0)` is
  non-blocking and never reports EOF, so `io::Stdin` blocks by yielding and
  `cat` with no file waits forever;
- **real wall-clock time**, `SystemTime::now` as Unix time, time zones, an RTC
  read: clock 0 is uptime at 10 ms resolution, and the kernel's own RTC is not
  reachable from userland;
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

Also deliberately not provided: file locking, `is_terminal` (see
[`pagh_std::io`](#pagh_stdio): the ABI cannot distinguish the console from a
socket, and fd 0-2 are not reserved), `OsString`, `Rc`/`Arc` re-exports,
`OnceLock`, and raw-entry/nightly hash-map APIs. They are userland-only
conveniences the SDK can grow without a kernel change, except `is_terminal`,
which needs the kernel to say what a descriptor is. `io::Cursor`, `Read::chain`
and `Tee` left this list in 0.9.0 and are part of the surface below.

## Design notes

- **No panics on normal I/O errors.** Syscall failures become `io::Error`
  values; `read_to_string` validates UTF-8 before touching the destination;
  `BufReader`/`BufWriter` check every count they get back. Panics are reserved
  for programmer errors and the deliberate probe.
- **Every `unsafe` site has a `SAFETY:` comment.** The surface is the
  `Path`/`PathBuf` `#[repr(transparent)]` casts, the single-threaded `PWD` cell
  (`unsafe impl Sync` plus its two accesses), `BufWriter::into_inner`'s
  bitwise move, `File::from_raw_fd`'s documented ownership contract, and the
  lifetime-erasing raw pointers in `thread::scope` (sound because the scope
  joins every child). The crate is `#![deny(unsafe_op_in_unsafe_fn)]`.
- **Absolute paths at the boundary.** Every filesystem entry point calls
  `resolve_path` (against the tracked `PWD`, lexically normalized), because the
  kernel accepts absolute paths only.
- **The ABI is the contract.** Syscall numbers, `Stat`, `Timespec`, `Uname`,
  `Dirent` sizes and flags live in `libpagh`; `pagh_std` uses its wrappers,
  not hand-written `ecall`s.
- **The host gate compiles what it can of the I/O layer.** `io.rs` and
  `io/pure.rs` are split along the syscall boundary: the traits, buffers,
  `Cursor`, `Chain` and `Tee` need only `core` + `alloc`, so the same source
  file is compiled a second time for `x86_64` and enumerated against every
  seek/EOF boundary. The only bare-metal type the pure half names is
  `libpagh::errno::Errno`, whose source the gate compiles from the sibling
  checkout.
- **Buffering is userland.** `File` is unbuffered on the `read`/`write` path;
  `BufReader`/`BufWriter` add the explicit 8 KiB layer. `File`/`TcpStream` also
  carry an 8 KiB read-ahead buffer for their direct `BufRead` implementation,
  which is allocated only when `fill_buf` is used.

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
| Condvar | 0.5.0 transcript: 4 waiters + `notify_all`, exact `notify_one`, 50 ms `wait_timeout`, guard re-locked |
| scoped threads | 0.5.0 transcript: `thread::scope` joins explicit and dropped handles, returns values, borrows `&mut` slots |
| File traits | 0.5.0 transcript: `write_all`/`flush`/`seek`, `read_exact`/`read_to_end`, direct `BufRead` and read-ahead/write rewind |
| TCP traits | 0.5.0 network run: `TcpStream` `write_all`, `read_line`, `Read::read_to_end` against a host server; re-run in the 0.6.0 transcript after the stream wrapper was rewritten |
| TCP listener | 0.6.0 transcript: `bind`/`local_addr`, `accept_nonblocking` → `WouldBlock`, two blocking `accept`s with `peer_addr`, 224 + 400 bytes echoed to a host `--hostfwd` client, ephemeral `local_addr` → `Unsupported` |
| UDP sockets | 0.6.0 transcript: `bind`/`local_addr`, `set_nonblocking` → `WouldBlock`, 16- and 300-byte datagrams round-tripped through a host echo server, 1025-byte send rejected |
| mpsc | 0.6.0 transcript: 12 values through a 2-slot channel with blocking `send`, `try_send` Full/Disconnected, `try_recv` Empty, `recv` after disconnect, `recv_timeout` Disconnected |
| Barrier / Once | 0.6.0 transcript: 4 parties × 2 generations with exactly one leader each, and 4 threads racing one `Once` (one run, all saw `is_completed`) |
| `HashMap`/`HashSet` | 0.7.0 transcript: a `Hash + Eq` key with no `Ord`, 1000 inserts → `len=1000 capacity=1536`, 500 removals with the other 500 still reachable, 64 keys forced into one bucket then a middle deletion, `entry`/`retain`/`extend`/`FromIterator`/`Index`, set algebra |
| DNS | 0.7.0 transcript: `/mnt/etc/resolv.conf` names the DHCP-leased server (the boot log's `dns 10.0.2.3`), a real `A` query with the server's TTLs, `NXDOMAIN`, `InvalidName` before any datagram, a 1 s deadline against a host black hole, and `connect("example.com:80")` → `HTTP/1.1 200 OK` |
| socket options | 0.7.0 transcript: `SO_TYPE` → `Stream`/`Datagram`, `SO_REUSEADDR` accepted and the second `bind` still refused, non-blocking read `WouldBlock`, 500 ms read deadline and 300 ms UDP deadline enforced by the SDK, `try_clone` echo read back through the clone and the original still usable after it drops |
| vendored TLS 1.3 | 0.7.0 transcript: a live `https://example.com/` GET through the userland client — chain to the committed bundle (`chain=4 anchors=6`), leaf `sha256:85ca6ab0…`, `CertificateVerify OK`, 577-byte body — and four refusals: `stage=clock`, `stage=entropy`, `cause=chain` (self-signed `openssl s_server`) and `cause=hostname` (a trusted Google chain for `example.com`) |
| userland I/O adapters | 0.9.0 transcript: `Cursor` read/seek/position/BufRead across buffer boundaries in the guest; `Chain` over two cursors, two empty cases and a `File`+cursor pair; `Tee` mirrored 46 bytes to stdout and `/mnt/io_adapters_tee.txt`, read back by `cat` (exactly one copy after a second run) — `IO_ADAPTERS PASS`, 12/12 checks |
| kernel-backed TLS | 0.8.0 transcript: `tls_get` fetching `https://example.com/` with **no clock and no seed argument** — `tls: verified leaf=sha256:85ca6ab0… chain=4 certs anchors=6 host=example.com`, `tls: CertificateVerify OK`, `tls: user session 0 open host=example.com (TLS 1.3, AES-128-GCM-SHA256, server authenticated, 110 ms)`, `status 200 body 577 bytes` — the same fetch through `TlsStream` (`--manual`), the vendored program seeded from `getrandom`, and two refusals: `cause=chain` and `cause=hostname`, both errno 129 |

`python3 tools/live_check.py` reproduces the 0.4.0 matrix;
`docs/live-rust-sdk.txt` is that captured run. `docs/live-sdk-0.5.0.txt` is the
focused 0.5.0 run with its kernel/QEMU/toolchain header. `python3
tools/live_net.py` reproduces the 0.6.0 network/sync matrix in one boot and
rewrites `docs/live-sdk-0.6.0.txt` (47/47 checks, kernel hash and ELF hashes
included). `python3 tools/live_070.py` reproduces the 0.7.0 matrix in one boot
and rewrites `docs/live-sdk-0.7.0.txt` (**55/55 checks**, kernel and ELF
hashes included). `python3 tools/live_080.py` reproduces the 0.8.0
kernel-backed TLS matrix and rewrites `docs/live-sdk-0.8.0.txt` (**32/32
checks**); `python3 tools/live_090.py` reproduces the 0.9.0 I/O-adapter matrix
and rewrites `docs/live-sdk-0.9.0.txt` (**12/12 checks**). The host unit tests
are **69 checks** (`cargo test -p pagh_hostcheck --target x86_64-unknown-linux-gnu`):
the 40 from the earlier pure layers, 27 for the 0.9.0 I/O core, and the two
`Errno` round-trip tests that arrive with the sibling's `errno.rs` include.

## CI

`.github/workflows/ci.yml`:

1. checks out `pagh-rust` and the sibling `pagh-api`;
2. installs the pinned toolchain, target and rustfmt;
3. runs `cargo fmt -p pagh_std -p pagh_hostcheck -p pagh_probes -- --check`
   (package-scoped because `--all` would reformat the sibling `pagh-api`);
4. runs `./build.sh --fixtures` (all examples and probes);
5. asserts every example a default build produces — including `tcp_server`,
   `udp_echo`, `sync_primitives`, `io_adapters` and the kernel-backed
   `tls_get` — is ≤ 1 MiB;
6. builds `--release --vendored` and checks `tls_get_vendored` (plus the release
   sizes of the 0.7.0 examples) against the same limit;
7. runs `cargo test -p pagh_hostcheck --target x86_64-unknown-linux-gnu`
   (the pure I/O core, including `Cursor`/`Chain`/`Tee`, is part of that gate);
8. uploads the example ELFs.

Neither cargo invocation passes `--locked` (steps 4 and 7): the workspace
lockfile records the sibling `libpagh` version, which follows `pagh-api`'s
release cadence, so a hard lock would make this repository's CI red because
another repository bumped a library. The vendored TLS crates are exact-pinned
in `pagh_std/Cargo.toml` and resolved from `vendor/`, so the lock still fixes
everything the SDK actually links.

The live QEMU check is intentionally not in CI: it needs the kernel checkout
and QEMU, and the transcript is the acceptance artifact for this milestone.
`tools/live_check.py` is the command to run locally.

## License

No license file is included in this repository yet; treat the code as
all-rights-reserved until one is added.