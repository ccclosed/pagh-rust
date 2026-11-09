#!/usr/bin/env python3
"""Live-verify the pagh_std 0.7.0 surface in QEMU.

The 0.6.0 acceptance run (`tools/live_net.py`) covers the sockets and the
synchronisation primitives. This one is the acceptance run for the 0.7.0 work,
one scenario per feature, all of them in the guest and all of them on the
kernel's own launcher (`pagh-riscv/tools/run.py --net --keep`):

* `hash_map` — the real hash table (Robin Hood linear probing, backward-shift
  deletion) replacing the 0.6.0 `BTreeMap` shim: a key type with `Hash + Eq`
  and no `Ord`, a real `capacity()`, 1000 inserts with growth, 500 removals
  with the other 500 still reachable, and every key forced into one bucket;
* `dns` — the RFC 1035 stub resolver: a real A query answered by the
  **DHCP-leased** server (the script reads the lease out of the kernel's own
  boot log and writes it into the staged `resolv.conf`, so the chain
  DHCP → configuration file → SDK query is visible end to end), NXDOMAIN, an
  unencodable name refused before any datagram, a deadline against a silent
  server, and `connect(host:port)` doing a real HTTP GET;
* `socket_opts` — `getsockopt(SO_TYPE)`, `SO_REUSEADDR` accepted *and* shown
  not to change the kernel's bind behaviour, `set_nonblocking` measured,
  a 500 ms read deadline enforced by the SDK (the kernel ignores
  `SO_RCVTIMEO`), `try_clone` sharing one descriptor, and the UDP deadline;
* `tls_get_vendored` — the 0.7.0 userland TLS 1.3 stack over a `TcpStream`: a
  live HTTPS GET of `example.com` with the chain validated against the
  committed CA bundle, the SAN checked, the clock gate applied and
  `CertificateVerify` verified — plus four refusals (no clock, no entropy, a
  self-signed chain, a valid chain for the wrong name), because a verifier is
  only as good as what it rejects. Since 0.8.0 the default `tls_get` is the
  kernel-backed client (`tools/live_080.py`); this harness drives the vendored
  implementation, which is why it builds with `--vendored` and stages the
  `tls_get_vendored` example.

The guest is driven over the serial socket `run.py` leaves behind, one command
at a time, because the shell's UART ring is 16 bytes deep.

Usage::

    python3 tools/live_070.py                 # build, boot, run, write docs/
    python3 tools/live_070.py --skip-build    # reuse target/…/release/examples
    python3 tools/live_070.py --keep-work     # keep the image and serial logs

Exit status is 0 only when every check passes.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = "riscv64gc-unknown-none-elf"
PROMPT = "pagh:rv64>"

EXAMPLES = ("hash_map", "dns", "socket_opts", "tls_get_vendored")

# The guest reaches the host's loopback as 10.0.2.2 through QEMU's user network,
# so a host server needs no --hostfwd at all.
HOST_FROM_GUEST = "10.0.2.2"
GUEST_ECHO_PORT = 45683
PROOF_HOST = "example.com"
PROOF_MARKER = "Example Domain"
# A host whose chain anchors in the committed bundle (GTS Root R1) while its
# SANs do not cover PROOF_HOST: the hostname gate needs a certificate that is
# trusted but wrong.
MISMATCH_HOST = "www.google.com"
# The roots the committed CA bundle carries (pagh_std/src/tls/ca_bundle.rs): the
# SAN-negative host has to chain to one of them.
BUNDLE_ROOTS = (
    "ISRG Root X1",
    "ISRG Root X2",
    "GTS Root R1",
    "GTS Root R4",
    "SSL.com TLS ECC Root CA 2022",
    "SSL.com TLS RSA Root CA 2022",
)
RUN_TIMEOUT = 120.0
DISK_SIZE = "64M"
DNS_NAMESERVER = "10.0.2.3"
OUTPUT_DEFAULT = ROOT / "docs" / "live-sdk-0.7.0.txt"
# 32 bytes for `Entropy`, staged as `/mnt/seed` (see `make_image`).
SEED_IN_FILE = "9c1f4a7e2b8d5036af41c9e75b2d8063fe18a4c6d92b7e5308fa1c4d6e2b9075"


class Failure(RuntimeError):
    """A check failed; the caller records it and moves on."""


def die(message: str, code: int = 2) -> None:
    print(f"live_070: {message}", file=sys.stderr)
    raise SystemExit(code)


def info(message: str) -> None:
    print(f"live_070: {message}", file=sys.stderr)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def free_port() -> int:
    """Reserve an ephemeral loopback port, then release it for a guest peer."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


# ─── host peers ─────────────────────────────────────────────────────────────


class TcpEchoServer:
    """A host TCP echo server on 127.0.0.1:0, one connection at a time.

    The guest reaches it as `10.0.2.2:<port>`; it never speaks first, which is
    what the read-deadline check in `socket_opts` needs.
    """

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.sock.settimeout(1.0)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self.error: str | None = None
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.connections += 1
            with conn:
                conn.settimeout(30)
                while not self._stop.is_set():
                    try:
                        data = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not data:
                        break
                    try:
                        conn.sendall(data)
                    except OSError as error:  # pragma: no cover - host side
                        self.error = str(error)
                        break

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=5)


class UdpBlackHole:
    """A host UDP socket that receives and never answers.

    The resolver's deadline is only observable against a server that stays
    silent, and a *silent* server has to exist on purpose: port 53 of the
    gateway may or may not be closed, and the guest cannot send to its own
    address at all. The example's `--server`/`--port` pair points here.
    """

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.received = 0
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            self.received += 1

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=5)


class SelfSignedServer:
    """`openssl s_server` with a self-signed certificate for `PROOF_HOST`.

    Reached from the guest as `10.0.2.2:<port>`; its chain has no anchor in the
    committed bundle, so the handshake must be refused with `cause=chain`.
    """

    def __init__(self, work: pathlib.Path) -> None:
        self.work = work
        self.port = free_port()
        self.cert = work / "self-signed.pem"
        self.key = work / "self-signed.key"
        self.process: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        result = subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(self.key), "-out", str(self.cert),
                "-days", "2", "-subj", f"/CN={PROOF_HOST}",
                "-addext", f"subjectAltName=DNS:{PROOF_HOST}",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            die(f"openssl req failed: {result.stderr.strip()}")
        self.process = subprocess.Popen(
            [
                "openssl", "s_server", "-quiet", "-www",
                "-accept", f"0.0.0.0:{self.port}",
                "-cert", str(self.cert), "-key", str(self.key),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(0.5)
            try:
                probe.connect(("127.0.0.1", self.port))
                probe.close()
                return
            except OSError:
                probe.close()
                time.sleep(0.1)
        die("the self-signed openssl s_server never started")

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - host side
                self.process.kill()


def mismatch_host_ip() -> str:
    """The SAN-negative precondition, checked from the host before the guest runs.

    Two facts have to hold for the guest's `cause=hostname` to mean anything:
    the chain presented by `MISMATCH_HOST` must be trusted by the *system* store
    (so a bundle that contains the same root will accept the chain), and that
    chain must not authorize `PROOF_HOST` (so the hostname gate is the only one
    that can refuse). A changed internet fails here instead of silently turning
    the guest check into a pass.
    """
    address = socket.getaddrinfo(MISMATCH_HOST, 443, socket.AF_INET)[0][4][0]
    # 1. The chain must anchor in a root the committed bundle carries: the guest
    #    check is only about the SAN if the chain is otherwise acceptable, and
    #    `GTS Root R1` is the bundle's Google anchor.
    result = subprocess.run(
        [
            "openssl", "s_client", "-connect", f"{address}:443",
            "-servername", MISMATCH_HOST, "-showcerts",
        ],
        input=b"",
        capture_output=True,
        timeout=30,
    )
    text = (result.stdout + result.stderr).decode("utf-8", "replace")
    # The hosts are server-operator choices; what matters is that the chain ends
    # at a root the *committed bundle* carries, or the guest's refusal would be
    # `cause=chain` and prove nothing about the hostname gate.
    anchor = next((label for label in BUNDLE_ROOTS if label in text), None)
    if anchor is None:
        raise Failure(
            f"{MISMATCH_HOST}'s chain does not end at any committed trust anchor "
            f"({', '.join(BUNDLE_ROOTS)}); the SAN-negative check would not isolate "
            "the hostname gate"
        )
    # 2. The certificate must NOT authorize PROOF_HOST, or the guest's
    #    `cause=hostname` would be a pass dressed up as a refusal.
    context = ssl.create_default_context()
    try:
        with socket.create_connection((address, 443), timeout=20) as raw:
            with context.wrap_socket(raw, server_hostname=PROOF_HOST):
                raise Failure(
                    f"{MISMATCH_HOST} now presents a certificate valid for {PROOF_HOST}; "
                    "the SAN-negative check would not isolate the hostname gate"
                )
    except ssl.SSLCertVerificationError:
        pass  # expected: the requested name is not in the SANs
    info(f"SAN-negative precondition ok: {MISMATCH_HOST} ({address}) anchor={anchor}")
    return address


# ─── the guest's serial line ────────────────────────────────────────────────


class Guest:
    """The guest's serial line, driven one command at a time."""

    def __init__(self, path: str, timeout: float = 30.0) -> None:
        self.transcript = ""
        self._cursor = 0
        self._last_start = 0
        self._last_end = 0
        self.sock = self._connect(path, timeout)

    @staticmethod
    def _connect(path: str, timeout: float) -> socket.socket:
        deadline = time.time() + timeout
        while True:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(path)
                return sock
            except OSError:
                sock.close()
                if time.time() > deadline:
                    die(f"cannot reconnect to the serial socket {path!r}")
                time.sleep(0.05)

    def _pump(self, seconds: float) -> None:
        self.sock.settimeout(0.2)
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                return
            self.transcript += chunk.decode("utf-8", "replace")

    def expect(self, marker: str, timeout: float = RUN_TIMEOUT) -> bool:
        return self.expect_any([marker], timeout) == marker

    def expect_any(self, markers: list[str], timeout: float = RUN_TIMEOUT) -> str | None:
        """Wait for the earliest of `markers`; return which one matched."""
        start = self._cursor
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._pump(0.2)
            best: tuple[int, str] | None = None
            for marker in markers:
                index = self.transcript.find(marker, start)
                if index >= 0 and (best is None or index < best[0]):
                    best = (index, marker)
            if best is not None:
                index, marker = best
                self._last_start = start
                self._cursor = index + len(marker)
                self._last_end = self._cursor
                return marker
        self._last_start = start
        self._last_end = len(self.transcript)
        return None

    def output(self, since: int = 0) -> str:
        return self.transcript[since:]

    def mark(self) -> int:
        return len(self.transcript)

    def send_line(self, line: str, delay: float = 0.02) -> None:
        for byte in (line + "\r").encode("utf-8"):
            self.sock.sendall(bytes([byte]))
            time.sleep(delay)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# ─── build, image, boot ─────────────────────────────────────────────────────


def build(args: argparse.Namespace) -> pathlib.Path:
    if not args.skip_build:
        info("building release ELFs (./build.sh --release --vendored)")
        result = subprocess.run(
            [str(ROOT / "build.sh"), "--release", "--vendored"], cwd=ROOT, text=True
        )
        if result.returncode != 0:
            die("build.sh --release --vendored failed")
    examples = ROOT / "target" / TARGET / "release" / "examples"
    for name in EXAMPLES:
        if not (examples / name).is_file():
            die(f"{examples / name} is missing (drop --skip-build to build it)")
    return examples


def make_image(work: pathlib.Path, examples: pathlib.Path) -> pathlib.Path:
    mke2fs = shutil.which("mke2fs")
    if mke2fs is None:
        die("mke2fs (e2fsprogs) is required to build the ext2 image")
    root = work / "root"
    (root / "etc").mkdir(parents=True, exist_ok=True)
    for name in EXAMPLES:
        target = root / name
        shutil.copyfile(examples / name, target)
        target.chmod(0o755)
    # The ABI cannot tell userland what DHCP leased, so the resolver reads this
    # file; the check below proves the value in it is the leased one.
    (root / "etc" / "resolv.conf").write_text(
        f"# staged by tools/live_070.py\nnameserver {DNS_NAMESERVER}\n", encoding="utf-8"
    )
    # The session seed travels as a file: the shell's input line is capped at
    # 128 bytes, and 64 hex characters plus a URL do not fit.
    (root / "seed").write_text(SEED_IN_FILE + "\n", encoding="utf-8")
    disk = work / "disk.img"
    with disk.open("wb") as handle:
        handle.truncate(64 * 1024 * 1024)
    command = [mke2fs, "-q", "-t", "ext2", "-F", "-b", "4096", "-d", str(root), str(disk)]
    info("+ " + " ".join(command))
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        die(f"mke2fs failed: {result.stderr.strip()}")
    return disk


def boot(args: argparse.Namespace, work: pathlib.Path, disk: pathlib.Path) -> str:
    command = [
        sys.executable,
        str(args.pagh_riscv / "tools" / "run.py"),
        "--kernel", str(args.kernel),
        "--disk", str(disk),
        "--net",
        "--serial", str(work / "serial.sock"),
        "--monitor", str(work / "monitor.sock"),
        "--serial-log", str(work / "boot.log"),
        "--shot", str(work / "boot.png"),
        "--settle", "2",
        "--timeout", "120",
        "--keep",
    ]
    info("+ " + " ".join(command))
    result = subprocess.run(
        command,
        cwd=args.pagh_riscv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        die(f"tools/run.py failed with status {result.returncode}\n{result.stdout}")
    return (work / "boot.log").read_text(encoding="utf-8", errors="replace")


def stop_qemu(work: pathlib.Path) -> None:
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(str(work / "monitor.sock"))
        sock.sendall(b"quit\n")
        time.sleep(0.5)
        sock.close()
    except OSError:
        pass
    # The image path is unique to this run, so this cannot hit another QEMU.
    subprocess.run(
        ["pkill", "-f", re.escape(str(work / "disk.img"))],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# ─── the check matrix ───────────────────────────────────────────────────────


class Checks:
    def __init__(self) -> None:
        self.passed: list[str] = []
        self.failures: list[str] = []

    def check(self, condition: bool, what: str, output: str = "") -> bool:
        if condition:
            self.passed.append(what)
            info(f"PASS  {what}")
            return True
        self.failures.append(what)
        info(f"FAIL  {what}")
        if output:
            info("      last output:\n" + output.strip())
        return False


# Each program's own FAIL line, so a failing scenario ends in seconds instead
# of waiting out the whole timeout.
FAILURE_MARKERS = {
    "hash_map": "HASH_MAP FAIL",
    "dns": "DNS FAIL",
    "socket_opts": "SOCKET_OPTS FAIL",
    "tls_get_vendored": "TLS_GET FAIL",
}


def run_scenario(
    guest: Guest,
    checks: Checks,
    command: str,
    marker: str,
    extra: tuple[str, ...] = (),
) -> str:
    """Type one `run` line, wait for its verdict, return everything it printed."""
    if len(command) >= 128:
        checks.check(
            False,
            f"`{command}` fits the shell's 128-byte input line ({len(command)} bytes)",
        )
        return ""
    before = guest.mark()
    guest.send_line(command)
    words = command.split()
    program = words[1].rsplit("/", 1)[-1] if len(words) > 1 else ""
    markers = [marker]
    failure = FAILURE_MARKERS.get(program)
    if failure is not None and failure != marker:
        markers.append(failure)
    matched = guest.expect_any(markers)
    output = guest.output(before)
    if matched != marker:
        checks.check(False, f"`{command}` did not print {marker!r}", output)
        return output
    checks.check(True, f"`{command}` -> {marker}")
    for needle in extra:
        checks.check(needle in output, f"`{command}` printed {needle!r}", output)
    return output


def run_guest(
    args: argparse.Namespace, work: pathlib.Path, boot_log: str
) -> tuple[str, Checks, dict[str, object]]:
    checks = Checks()
    facts: dict[str, object] = {}

    # The DHCP lease, straight from the kernel's own boot log. The resolver's
    # configuration file has to name the server DHCP actually handed out, or the
    # whole "queries the DHCP DNS server" claim is decoration.
    lease = re.search(
        r"net\s+DHCP ip (\d+\.\d+\.\d+\.\d+)/\S+ gw (\d+\.\d+\.\d+\.\d+) dns (\d+\.\d+\.\d+\.\d+)",
        boot_log,
    )
    if lease is None:
        checks.check(False, "the boot log contains the DHCP lease line", boot_log[-2000:])
        guest_ip, dhcp_dns = "10.0.2.15", DNS_NAMESERVER
    else:
        guest_ip, gateway, dhcp_dns = lease.group(1), lease.group(2), lease.group(3)
        checks.check(True, f"boot log: DHCP ip {guest_ip} gw {gateway} dns {dhcp_dns}")
        checks.check(
            dhcp_dns == DNS_NAMESERVER,
            f"the DHCP-leased DNS server is the one staged in /etc/resolv.conf ({DNS_NAMESERVER})",
            boot_log[-2000:],
        )
    facts["guest_ip"] = guest_ip
    facts["dhcp_dns"] = dhcp_dns

    echo = TcpEchoServer()
    echo.start()
    facts["echo_port"] = echo.port
    black_hole = UdpBlackHole()
    black_hole.start()
    facts["black_hole_port"] = black_hole.port
    self_signed = SelfSignedServer(work)
    self_signed.start()
    facts["self_signed_port"] = self_signed.port
    mismatch_ip: str | None = None
    try:
        mismatch_ip = mismatch_host_ip()
    except Exception as failure:  # a host-side precondition, never a guest verdict
        checks.failures.append(f"SAN-negative precondition: {failure}")
        info(f"FAIL  SAN-negative precondition: {failure}")
    facts["mismatch_ip"] = mismatch_ip

    now_unix = int(time.time())
    facts["now_unix"] = now_unix
    info(f"session seed {SEED_IN_FILE} staged at /mnt/seed; wall clock {now_unix}")

    guest = Guest(str(work / "serial.sock"))
    try:
        # 1. The real hash map.
        run_scenario(
            guest,
            checks,
            "run /mnt/hash_map",
            "HASH_MAP PASS",
            (
                "hash_map: Hash+Eq key with no Ord: OK",
                "capacity=1536 (real spare capacity)",
                "64 keys in one bucket",
                "hash_set: 2 elements",
            ),
        )

        # 2. DNS: the system resolver, a real query, the refusals, and connect().
        output = run_scenario(
            guest,
            checks,
            "run /mnt/dns",
            "DNS PASS",
            (
                f"dns: 1 server(s) from /mnt/etc/resolv.conf: {dhcp_dns}",
                f"dns: {PROOF_HOST} -> ",
                "dns: no-such-host.invalid -> NXDOMAIN (as required)",
                "dns: bad..name -> InvalidName",
            ),
        )
        checks.check(
            "attempt" in output,
            "the A query reports the server's answer time",
            output,
        )
        run_scenario(
            guest,
            checks,
            f"run /mnt/dns --connect={PROOF_HOST}:80",
            "DNS PASS",
            ("dns: TcpStream::connect_host(", "dns: connect(", " 200 OK"),
        )
        run_scenario(
            guest,
            checks,
            f"run /mnt/dns --server={HOST_FROM_GUEST} --port={black_hole.port} --deadline-ms=1000",
            "DNS PASS",
            ("dns: silent server -> Timeout after", "budget 2100 ms"),
        )
        checks.check(
            black_hole.received >= 1,
            f"the black hole at {HOST_FROM_GUEST}:{black_hole.port} received the query",
        )

        # 3. Socket options, non-blocking mode, timeouts and try_clone.
        run_scenario(
            guest,
            checks,
            f"run /mnt/socket_opts --peer={HOST_FROM_GUEST}:{echo.port}",
            "SOCKET_OPTS PASS",
            (
                "getsockopt(SO_TYPE) on a listener -> Stream",
                "setsockopt(SO_REUSEADDR, 1) -> accepted by the ABI",
                "the option is accepted, not honoured",
                "non-blocking read on an idle socket -> WouldBlock in",
                "500 ms read deadline on a silent peer -> WouldBlock after",
                "try_clone -> shared fd",
                "wrote on the original, read the echo on the clone",
                "original usable after the clone dropped",
                "getsockopt(SO_TYPE) on a UdpSocket -> Datagram",
                "UDP 300 ms receive deadline -> WouldBlock after",
            ),
        )
        checks.check(echo.connections >= 1, "the host echo peer saw the guest's connection")

        # 4. TLS: the live fetch, then the four refusals.
        fetch = run_scenario(
            guest,
            checks,
            f"run /mnt/tls_get_vendored https://{PROOF_HOST}/ {now_unix} @/mnt/seed",
            "TLS_GET PASS",
            (
                "tls: verified leaf=sha256:",
                "tls: CertificateVerify OK",
                "tls: handshake OK",
                "tls: fetch OK",
                PROOF_MARKER,
            ),
        )
        checks.check(
            fetch.count("tls: verify FAILED") == 0,
            "the live fetch took no refusal path",
            fetch,
        )
        run_scenario(
            guest,
            checks,
            f"run /mnt/tls_get_vendored https://{PROOF_HOST}/ 0 @/mnt/seed",
            "TLS_GET FAIL",
            ("stage=clock cause=NoWallClock",),
        )
        run_scenario(
            guest,
            checks,
            f"run /mnt/tls_get_vendored https://{PROOF_HOST}/ {now_unix} none",
            "TLS_GET FAIL",
            ("stage=entropy cause=NoEntropy",),
        )
        run_scenario(
            guest,
            checks,
            f"run /mnt/tls_get_vendored https://{PROOF_HOST}:{self_signed.port}/ {now_unix} @/mnt/seed "
            f"--ip={HOST_FROM_GUEST}",
            "TLS_GET FAIL",
            ("tls: verify FAILED cause=chain", "TLS_GET FAIL: certificate rejected (chain)"),
        )
        if mismatch_ip is not None:
            run_scenario(
                guest,
                checks,
                f"run /mnt/tls_get_vendored https://{PROOF_HOST}/ {now_unix} @/mnt/seed --ip={mismatch_ip}",
                "TLS_GET FAIL",
                (
                    "tls: verify FAILED cause=hostname",
                    "TLS_GET FAIL: certificate rejected (hostname)",
                ),
            )
        run_scenario(
            guest,
            checks,
            f"run /mnt/tls_get_vendored https://{PROOF_HOST}/ {now_unix} @/mnt/seed --manual",
            "TLS_GET PASS",
            (
                "tls_get_vendored: verified leaf=sha256:",
                "chain=",
                "anchors=6",
                "tls_get_vendored: response HTTP/1.1 200",
            ),
        )
    finally:
        guest.close()
        self_signed.stop()
        echo.stop()
        black_hole.stop()

    return guest.transcript, checks, facts


# ─── transcript ─────────────────────────────────────────────────────────────


def shell_transcript(text: str) -> str:
    """Normalise CRLF for the committed transcript.

    Nothing is trimmed: the driver connects *after* `run.py` has seen the boot
    prompt, so the captured session starts at the first command the driver
    typed. Cutting at the first `pagh:rv64>` would silently drop that first
    command's output (and the header promises the whole session).
    """
    return text.replace("\r\n", "\n").replace("\r", "\n")


def write_transcript(
    path: pathlib.Path,
    args: argparse.Namespace,
    examples: pathlib.Path,
    checks: Checks,
    facts: dict[str, object],
    transcript: str,
    kernel_hash: str,
    started: str,
) -> None:
    lines = [
        "pagh-rust 0.7.0 — live QEMU acceptance transcript",
        "=" * 60,
        "",
        f"date:               {started}",
        f"kernel:             {args.kernel} sha256 {kernel_hash}",
        f"kernel launcher:    pagh-riscv/tools/run.py --net --keep (guest 10.0.2.15/24)",
        f"guest image:        `mke2fs -q -t ext2 -F -b 4096 -d <rootfs>`",
        f"staging root:       {', '.join(EXAMPLES)}, etc/resolv.conf (nameserver "
        f"{facts.get('dhcp_dns')})",
        "build:              ./build.sh --release --vendored (release profile, strip debuginfo)",
    ]
    for name in EXAMPLES:
        path_ = examples / name
        lines.append(f"release ELF:        {name} sha256 {sha256(path_)}")
    lines += [
        "",
        f"guest address:      {facts.get('guest_ip')} (DHCP, from the boot log)",
        f"DHCP DNS server:    {facts.get('dhcp_dns')} (the value staged in resolv.conf)",
        f"host echo peer:     127.0.0.1:{facts.get('echo_port')} == guest "
        f"{HOST_FROM_GUEST}:{facts.get('echo_port')}",
        f"host TLS server:    openssl s_server (self-signed {PROOF_HOST}) on "
        f"{HOST_FROM_GUEST}:{facts.get('self_signed_port')}",
        f"TLS proof host:     https://{PROOF_HOST}/ (chain -> SSL.com TLS ECC Root CA 2022)",
        f"SAN-negative host:  {MISMATCH_HOST} ({facts.get('mismatch_ip')}) — trusted chain, "
        f"wrong name",
        f"wall clock source:  host SystemTime -> argv ({facts.get('now_unix')})",
        f"entropy source:     32 bytes staged in /mnt/seed -> argv (@/mnt/seed)",
        "",
        f"checks:             {len(checks.passed)} passed, {len(checks.failures)} failed",
    ]
    for item in checks.passed:
        lines.append(f"  PASS  {item}")
    for item in checks.failures:
        lines.append(f"  FAIL  {item}")
    lines += [
        "",
        "The transcript below is the shell session from the first command the driver",
        "typed to the last (the boot banner is not replayed on reconnect); CRLF is",
        "normalized to LF.",
        "",
        "===== serial transcript =====",
        "",
        transcript.rstrip("\n"),
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    info(f"transcript {path} ({path.stat().st_size} bytes)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--skip-build", action="store_true", help="reuse the release examples")
    parser.add_argument("--keep-work", action="store_true", help="keep the image and serial logs")
    parser.add_argument("--kernel", type=pathlib.Path, default=None,
                        help="kernel ELF (default pagh-riscv debug build)")
    parser.add_argument("--pagh-riscv", type=pathlib.Path, default=ROOT.parent / "pagh-riscv")
    parser.add_argument("--output", type=pathlib.Path, default=OUTPUT_DEFAULT)
    args = parser.parse_args()
    if args.kernel is None:
        args.kernel = args.pagh_riscv / "target" / TARGET / "debug" / "pagh"
    if not args.kernel.is_file():
        die(f"no kernel at {args.kernel} (build pagh-riscv first)")

    started = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    examples = build(args)
    work = pathlib.Path(tempfile.mkdtemp(prefix="pagh-live-070-"))
    info(f"work dir {work}")
    try:
        disk = make_image(work, examples)
        boot_log = boot(args, work, disk)
        transcript, checks, facts = run_guest(args, work, boot_log)
        write_transcript(
            args.output,
            args,
            examples,
            checks,
            facts,
            shell_transcript(transcript),
            sha256(args.kernel),
            started,
        )
    finally:
        stop_qemu(work)
        if args.keep_work:
            info(f"kept {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)

    if checks.failures:
        info(f"{len(checks.failures)} check(s) failed")
        return 1
    info(f"all {len(checks.passed)} checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
