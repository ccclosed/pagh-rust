#!/usr/bin/env python3
"""Live-verify the 0.6.0 network and synchronisation surface in QEMU.

The 0.5.0 check (`tools/live_check.py`) covers the filesystem/time matrix and
the diagnostic probes. This script is the acceptance run for the new work:

* `pagh_std::net::TcpListener` — `bind`/`local_addr`/`accept_nonblocking`/
  `accept`/`peer_addr`, two connections echoed through QEMU's user network and
  a host `--hostfwd` client;
* `pagh_std::net::UdpSocket` — `bind`/`local_addr`/`set_nonblocking`/
  `send_to`/`recv_from`/`try_recv_from`, two datagrams round-tripped through a
  host UDP echo server, plus the kernel's 1024-byte ceiling;
* `pagh_std::sync::mpsc` + `Barrier` + `Once` on native threads;
* regressions: `cat`, `condvar`, and the `TcpStream` client path in
  `io_traits net` (the stream wrapper was rewritten in 0.6.0).

How it drives the guest (and why it is not one `--keys` string): the shell's
UART ring is 16 bytes deep, and a running program's output has to be watched
before the next command is typed — the `tcp_server` host client must not
connect before the guest is listening. The script therefore boots QEMU through
`pagh-riscv/tools/run.py --net --hostfwd … --keep` (the launcher the kernel's
own acceptance tests use), reconnects to the serial socket run.py leaves
behind, and types one command at a time, waiting for each verdict.

Usage::

    python3 tools/live_net.py                 # build, boot, run, write docs/
    python3 tools/live_net.py --skip-build    # reuse target/…/release/examples
    python3 tools/live_net.py --keep-work     # keep the image and serial logs

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
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = "riscv64gc-unknown-none-elf"
PROMPT = "pagh:rv64>"

# The examples this run stages. `cat` and `condvar` are the regression pair;
# the other four are the new surface plus the rewritten TcpStream client.
EXAMPLES = ("cat", "condvar", "io_traits", "sync_primitives", "tcp_server", "udp_echo")

GUEST_TCP_PORT = 45679
GUEST_UDP_PORT = 45680
RUN_TIMEOUT = 120.0
DISK_SIZE = "64M"
OUTPUT_DEFAULT = ROOT / "docs" / "live-sdk-0.6.0.txt"


class Failure(RuntimeError):
    """A check failed; the caller records it and moves on."""


def die(message: str, code: int = 2) -> None:
    print(f"live_net: {message}", file=sys.stderr)
    raise SystemExit(code)


def info(message: str) -> None:
    print(f"live_net: {message}", file=sys.stderr)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def free_port() -> int:
    """Reserve an ephemeral loopback port, then release it for QEMU hostfwd."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def command_output(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True)
    return (result.stdout or result.stderr).strip()


# ─── host peers ─────────────────────────────────────────────────────────────


class UdpEchoServer:
    """A host UDP echo server on 127.0.0.1:0 for two expected datagrams.

    QEMU's user network maps the guest's `10.0.2.2:<port>` onto this socket, so
    the guest's `send_to` arrives here and the reply goes back the same way.
    """

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(120)
        self.port = self.sock.getsockname()[1]
        self.received: list[bytes] = []
        self.error: str | None = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        try:
            while len(self.received) < 2:
                data, peer = self.sock.recvfrom(4096)
                self.received.append(data)
                self.sock.sendto(data, peer)
        except OSError as error:
            self.error = str(error)
        finally:
            self.sock.close()

    def start(self) -> None:
        self.thread.start()

    def join(self, timeout: float = 30.0) -> None:
        self.thread.join(timeout)

    @property
    def alive(self) -> bool:
        return self.thread.is_alive()


class IoTraitsServer:
    """The host TCP server `io_traits net` expects.

    It reads one request line and answers with exactly the two lines the 0.5.0
    transcript shows: `PAGH-IO-TRAITS\\n` (the `BufRead` line) followed by
    `second line\\n` (the `Read::read_to_end` body), then closes.
    """

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.sock.settimeout(120)
        self.port = self.sock.getsockname()[1]
        self.request: bytes | None = None
        self.error: str | None = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        try:
            connection, _ = self.sock.accept()
            connection.settimeout(60)
            request = b""
            while not request.endswith(b"\n"):
                chunk = connection.recv(64)
                if not chunk:
                    break
                request += chunk
            self.request = request
            connection.sendall(b"PAGH-IO-TRAITS\nsecond line\n")
            connection.shutdown(socket.SHUT_WR)
            connection.close()
        except OSError as error:
            self.error = str(error)
        finally:
            self.sock.close()

    def start(self) -> None:
        self.thread.start()

    def join(self, timeout: float = 30.0) -> None:
        self.thread.join(timeout)

    @property
    def alive(self) -> bool:
        return self.thread.is_alive()


class TcpEchoClient:
    """Two sequential host clients for the guest's `tcp_server`.

    Connection 1 sends a short payload, connection 2 a larger one; both
    half-close, read the echo to EOF and are compared byte for byte. Two
    connections prove the listener's accept queue releases one connection at a
    time.
    """

    def __init__(self, port: int, payloads: list[bytes]) -> None:
        self.port = port
        self.payloads = payloads
        self.received: list[bytes] = []
        self.error: str | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _one(self, payload: bytes) -> bytes:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(60)
        client.connect(("127.0.0.1", self.port))
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        client.close()
        return b"".join(chunks)

    def _run(self) -> None:
        try:
            for payload in self.payloads:
                self.received.append(self._one(payload))
        except OSError as error:
            self.error = str(error)

    def start(self) -> None:
        self.thread.start()

    def join(self, timeout: float = 60.0) -> None:
        self.thread.join(timeout)

    @property
    def alive(self) -> bool:
        return self.thread.is_alive()


# ─── guest serial driver ────────────────────────────────────────────────────


class Guest:
    """The guest's serial line, driven one command at a time.

    `run.py` connects first (it owns the boot marker and the screenshot); this
    class reconnects to the same socket after run.py has exited with `--keep`,
    which QEMU's `server=on` chardev accepts. Commands are typed byte by byte
    because the guest polls a 16-byte UART FIFO.
    """

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
        """Wait for `marker` in the text after the previous cursor."""
        start = self._cursor
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._pump(0.2)
            index = self.transcript.find(marker, start)
            if index >= 0:
                self._last_start = start
                self._cursor = index + len(marker)
                self._last_end = self._cursor
                return True
        self._last_start = start
        self._last_end = len(self.transcript)
        return False

    def last_output(self) -> str:
        """The text consumed by the last [`expect`] (including its marker)."""
        return self.transcript[self._last_start : self._last_end]

    def advance_cursor(self) -> None:
        self._cursor = len(self.transcript)

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
        info("building release ELFs (./build.sh --release)")
        result = subprocess.run([str(ROOT / "build.sh"), "--release"], cwd=ROOT, text=True)
        if result.returncode != 0:
            die("build.sh --release failed")
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
    root.mkdir()
    for name in EXAMPLES:
        target = root / name
        shutil.copyfile(examples / name, target)
        target.chmod(0o755)
    (root / "hello.txt").write_text(
        "hello from pagh-rust 0.6.0\nsecond line\n", encoding="utf-8"
    )
    disk = work / "disk.img"
    with disk.open("wb") as handle:
        handle.truncate(64 * 1024 * 1024)
    command = [
        mke2fs,
        "-q",
        "-t",
        "ext2",
        "-F",
        "-b",
        "4096",
        "-d",
        str(root),
        str(disk),
    ]
    info("+ " + " ".join(command))
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        die(f"mke2fs failed: {result.stderr.strip()}\n{result.stdout.strip()}")
    return disk


def boot_run_py(
    args: argparse.Namespace, work: pathlib.Path, disk: pathlib.Path, host_port: int
) -> str:
    """Boot QEMU through the kernel's own launcher and return its boot log."""
    command = [
        sys.executable,
        str(args.pagh_riscv / "tools" / "run.py"),
        "--kernel",
        str(args.kernel),
        "--disk",
        str(disk),
        "--net",
        "--hostfwd",
        f"{host_port}:{GUEST_TCP_PORT}",
        "--serial",
        str(work / "serial.sock"),
        "--monitor",
        str(work / "monitor.sock"),
        "--serial-log",
        str(work / "boot.log"),
        "--shot",
        str(work / "boot.png"),
        "--settle",
        "2",
        "--timeout",
        "120",
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
    """Power the guest off through the monitor socket, then make sure."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(str(work / "monitor.sock"))
        sock.sendall(b"quit\n")
        time.sleep(0.5)
        sock.close()
    except OSError:
        pass
    time.sleep(0.5)
    # The image path is unique to this run, so this cannot hit another QEMU.
    subprocess.run(
        ["pkill", "-f", str(work / "disk.img")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# ─── the check matrix ───────────────────────────────────────────────────────


class Checks:
    """Collects PASS/FAIL lines and stops a scenario at its first failure."""

    def __init__(self) -> None:
        self.failures: list[str] = []
        self.passed: list[str] = []

    def check(self, condition: bool, what: str, output: str = "") -> None:
        if condition:
            self.passed.append(what)
        else:
            raise Failure(f"{what}\n--- command output ---\n{output}")

    def fail(self, what: str) -> None:
        self.failures.append(what)


def run_guest(args: argparse.Namespace, work: pathlib.Path) -> tuple[str, Checks, dict[str, int]]:
    checks = Checks()
    host_port = free_port()
    ports = {"host": host_port, "udp": 0, "iotraits": 0}
    disk = make_image(work, build(args))
    boot = boot_run_py(args, work, disk, host_port)

    payloads = [
        b"pagh tcp server live test 1\n" * 8,
        bytes((0x41 + index % 26) for index in range(400)),
    ]
    udp_server = UdpEchoServer()
    iotraits_server = IoTraitsServer()
    echo_client = TcpEchoClient(host_port, payloads)
    ports["udp"] = udp_server.port
    ports["iotraits"] = iotraits_server.port

    guest = Guest(str(work / "serial.sock"))
    guest.advance_cursor()

    def scenario_cat() -> None:
        guest.send_line("run /mnt/cat /mnt/hello.txt")
        if not guest.expect("run: /mnt/cat exited with code 0", RUN_TIMEOUT):
            raise Failure("cat did not exit 0\n" + guest.last_output())
        output = guest.last_output()
        checks.check("hello from pagh-rust 0.6.0" in output, "cat printed the staged file", output)

    def scenario_condvar() -> None:
        guest.send_line("run /mnt/condvar")
        if not guest.expect("run: /mnt/condvar exited with code 0", RUN_TIMEOUT):
            raise Failure("condvar did not exit 0\n" + guest.last_output())
        output = guest.last_output()
        checks.check("CONDVAR PASS" in output, "condvar PASS (0.5.0 regression)", output)

    def scenario_sync() -> None:
        guest.send_line("run /mnt/sync_primitives")
        if not guest.expect("run: /mnt/sync_primitives exited with code 0", RUN_TIMEOUT):
            raise Failure("sync_primitives did not exit 0\n" + guest.last_output())
        output = guest.last_output()
        checks.check("SYNC_PRIMITIVES PASS" in output, "sync_primitives PASS", output)
        for marker in (
            "mpsc: 12 values passed through 2 slots (send blocked)",
            "mpsc: recv after the last sender -> RecvError",
            "mpsc: try_recv on an empty live channel -> Empty",
            "mpsc: try_send on a full channel -> Full (value returned)",
            "mpsc: try_send after the receiver dropped -> Disconnected",
            "mpsc: recv_timeout with no sender -> Disconnected",
            "barrier: every party released, exactly one leader per generation",
            "once: exactly one run, all 4 callers saw is_completed()",
        ):
            checks.check(marker in output, marker, output)

    def scenario_udp() -> None:
        udp_server.start()
        guest.send_line(f"run /mnt/udp_echo 10.0.2.2 {udp_server.port} {GUEST_UDP_PORT}")
        if not guest.expect("run: /mnt/udp_echo exited with code 0", RUN_TIMEOUT):
            raise Failure("udp_echo did not exit 0\n" + guest.last_output())
        output = guest.last_output()
        checks.check("UDP_ECHO PASS" in output, "udp_echo PASS", output)
        for marker in (
            f"udp_echo: bind 0.0.0.0:{GUEST_UDP_PORT}",
            f"udp_echo: local_addr 0.0.0.0:{GUEST_UDP_PORT}",
            "udp_echo: set_nonblocking(true); recv_from -> WouldBlock (queue empty)",
            "udp_echo: set_nonblocking(false) restored the blocking mode",
            "udp_echo: datagram 1: verified (16 bytes round-tripped)",
            "udp_echo: datagram 2: verified (300 bytes round-tripped)",
            "udp_echo: oversized send (1024 + 1 bytes) rejected:",
            "udp_echo: SocketAddr parse/display round-trip ok",
        ):
            checks.check(marker in output, marker, output)
        udp_server.join(timeout=30)
        checks.check(not udp_server.alive, "the host UDP server finished", output)
        checks.check(udp_server.error is None, f"host UDP server error: {udp_server.error}", output)
        checks.check(
            udp_server.received
            == [b"pagh udp echo 1\n", bytes((0x61 + index % 26) for index in range(300))],
            f"the host UDP server received the two expected datagrams "
            f"({[len(item) for item in udp_server.received]} bytes)",
            output,
        )

    def scenario_tcp_client() -> None:
        iotraits_server.start()
        guest.send_line(f"run /mnt/io_traits net 10.0.2.2 {iotraits_server.port}")
        if not guest.expect("run: /mnt/io_traits exited with code 0", RUN_TIMEOUT):
            raise Failure("io_traits net did not exit 0\n" + guest.last_output())
        output = guest.last_output()
        checks.check("IO_TRAITS PASS" in output, "io_traits PASS (file + TcpStream)", output)
        checks.check(
            f"io_traits: TcpStream Write/BufRead/Read ok (10.0.2.2:{iotraits_server.port})"
            in output,
            "io_traits: TcpStream traits reported ok",
            output,
        )
        iotraits_server.join(timeout=30)
        checks.check(not iotraits_server.alive, "the host io_traits server finished", output)
        checks.check(
            iotraits_server.error is None,
            f"host io_traits server error: {iotraits_server.error}",
            output,
        )
        checks.check(
            iotraits_server.request == b"PING\n",
            f"the host io_traits server read {iotraits_server.request!r}",
            output,
        )

    def scenario_tcp_server() -> None:
        guest.send_line(f"run /mnt/tcp_server {GUEST_TCP_PORT} 2")
        if not guest.expect("tcp_server: listening", RUN_TIMEOUT):
            raise Failure("tcp_server never reported listening\n" + guest.last_output())
        # The bind/local_addr lines precede the "listening" marker, so they are
        # consumed by this expect; keep its slice for the marker checks below.
        startup = guest.last_output()
        # The guest's `accept_nonblocking` probe runs right after that line;
        # one second of slack makes "nothing queued yet" unambiguous.
        time.sleep(1.0)
        echo_client.start()
        if not guest.expect("run: /mnt/tcp_server exited with code 0", RUN_TIMEOUT):
            raise Failure("tcp_server did not exit 0\n" + startup + guest.last_output())
        output = startup + guest.last_output()
        for marker in (
            "TCP_SERVER PASS",
            f"tcp_server: bind 0.0.0.0:{GUEST_TCP_PORT} backlog 4",
            f"tcp_server: local_addr 0.0.0.0:{GUEST_TCP_PORT}",
            "tcp_server: accept_nonblocking -> WouldBlock (nothing queued yet)",
            "tcp_server: accept 1 from 10.0.2.2:",
            "tcp_server: accept 2 from 10.0.2.2:",
            "tcp_server: connection 1: peer_addr 10.0.2.2:",
            "tcp_server: connection 2: peer_addr 10.0.2.2:",
            f"tcp_server: connection 1: recv {len(payloads[0])} bytes",
            f"tcp_server: connection 1: echo {len(payloads[0])} bytes",
            f"tcp_server: connection 2: recv {len(payloads[1])} bytes",
            f"tcp_server: connection 2: echo {len(payloads[1])} bytes",
            "tcp_server: connection 1: peer closed (EOF)",
            "tcp_server: connection 2: peer closed (EOF)",
            "tcp_server: ephemeral bind: local_addr -> TcpListener::local_addr: binds port 0 "
            "and the ABI has no getsockname",
            "TCP_SERVER PASS (2 connection(s) echoed)",
        ):
            checks.check(marker in output, f"tcp_server: {marker}", output)
        echo_client.join(timeout=60)
        checks.check(not echo_client.alive, "the host TCP client finished", output)
        checks.check(echo_client.error is None, f"host TCP client error: {echo_client.error}", output)
        checks.check(
            echo_client.received == payloads,
            f"the host TCP client read back both payloads "
            f"({[len(item) for item in echo_client.received]} bytes)",
            output,
        )

    def scenario_halt() -> None:
        guest.send_line("halt")
        if not guest.expect("halt: powering off", timeout=30):
            raise Failure("the guest did not power off\n" + guest.last_output())

    scenarios = (
        ("cat", scenario_cat),
        ("condvar", scenario_condvar),
        ("sync_primitives", scenario_sync),
        ("udp_echo", scenario_udp),
        ("io_traits net", scenario_tcp_client),
        ("tcp_server", scenario_tcp_server),
        ("halt", scenario_halt),
    )
    try:
        # run.py connected first (QEMU holds the guest until a client arrives),
        # so the prompt may already be behind us; an empty line asks for a fresh
        # one before the matrix starts.
        guest.send_line("")
        if not guest.expect(PROMPT, timeout=60):
            raise Failure("the guest did not print a fresh prompt after reconnecting")
        for name, scenario in scenarios:
            try:
                scenario()
            except Failure as error:
                info(f"{name}: FAIL — {error.args[0].splitlines()[0]}")
                checks.fail(f"{name}: {error.args[0]}")
    except Failure as error:
        checks.fail(f"driver: {error.args[0]}")
    finally:
        guest.close()
        stop_qemu(work)

    transcript = shell_transcript(boot + guest.transcript)
    return transcript, checks, ports


def shell_transcript(text: str) -> str:
    """Keep everything from the first shell prompt; normalize CRLF to LF."""
    index = text.find(PROMPT)
    if index < 0:
        return text
    lines = text[index:].replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines) + "\n"


# ─── transcript and report ──────────────────────────────────────────────────


def write_transcript(
    args: argparse.Namespace,
    transcript: str,
    checks: Checks,
    ports: dict[str, int],
) -> None:
    examples = ROOT / "target" / TARGET / "release" / "examples"
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rustc = command_output(["rustc", "+nightly-2026-07-12", "--version"])
    qemu = command_output(["qemu-system-riscv64", "--version"]).splitlines()[0]
    kernel_version = "unknown"
    match = re.search(
        r'^version\s*=\s*"([^"]+)"',
        (args.pagh_riscv / "Cargo.toml").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if match:
        kernel_version = match.group(1)
    git = command_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    dirty = command_output(["git", "-C", str(ROOT), "status", "--porcelain"])

    lines = [
        "pagh-rust — live SDK verification for 0.6.0",
        "===========================================",
        f"date (UTC):         {now}",
        "crate:              pagh_std 0.6.0",
        f"source state:       git {git}" + (" (working tree dirty)" if dirty else " (clean)"),
        f"toolchain:          {rustc}",
        f"target:             {TARGET}",
        f"kernel package:     pagh-riscv {kernel_version} (the kernel tree was not modified)",
        "kernel:             " + str(args.kernel),
        "                    sha256 " + sha256(args.kernel),
        f"qemu:               {qemu}",
        f"image:              64 MiB ext2: `truncate -s {DISK_SIZE}` + "
        "`mke2fs -q -t ext2 -F -b 4096 -d <rootfs>`",
        "                    staging root: " + ", ".join(EXAMPLES) + ", hello.txt",
        "build:              ./build.sh --release (release profile, strip debuginfo)",
    ]
    for name in EXAMPLES:
        lines.append(f"release ELF:        {name} sha256 {sha256(examples / name)}")
    lines += [
        "boot:               pagh-riscv/tools/run.py --net --hostfwd "
        f"127.0.0.1:{ports['host']}->guest:{GUEST_TCP_PORT} --keep",
        "guest driver:       tools/live_net.py reconnects to the serial socket and types one",
        "                    command at a time (the shell's UART ring is 16 bytes deep)",
        "host peers:         UDP echo server on 127.0.0.1:<ephemeral>, which the guest reaches",
        f"                    as 10.0.2.2:{ports['udp']}",
        f"                    io_traits TCP server, which the guest reaches as 10.0.2.2:{ports['iotraits']}",
        f"                    tcp_server client on 127.0.0.1:{ports['host']} (two connections)",
        "",
        f"checks:             {len(checks.passed)} passed, {len(checks.failures)} failed",
    ]
    for item in checks.passed:
        lines.append(f"  PASS  {item}")
    for item in checks.failures:
        lines.append(f"  FAIL  {item}")
    lines += [
        "",
        "The transcript below is the complete shell session from the first prompt; the",
        "OpenSBI/kernel boot banner is omitted and CRLF is normalized to LF.",
        "",
        "===== serial transcript =====",
        "",
        transcript.rstrip("\n"),
        "",
    ]
    output = args.output
    if not output.is_absolute():
        output = ROOT / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    info(f"transcript {output} ({output.stat().st_size} bytes)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Live-verify the 0.6.0 network/sync surface in QEMU"
    )
    parser.add_argument(
        "--pagh-riscv",
        type=pathlib.Path,
        default=ROOT.parent / "pagh-riscv",
        help="kernel checkout that owns tools/run.py",
    )
    parser.add_argument(
        "--kernel",
        type=pathlib.Path,
        default=None,
        help="kernel ELF (default <pagh-riscv>/target/…/debug/pagh)",
    )
    parser.add_argument("--skip-build", action="store_true", help="reuse built release ELFs")
    parser.add_argument("--keep-work", action="store_true", help="keep the image and serial logs")
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=OUTPUT_DEFAULT,
        help=f"transcript path (default {OUTPUT_DEFAULT})",
    )
    args = parser.parse_args()
    args.pagh_riscv = args.pagh_riscv.resolve()
    if args.kernel is None:
        args.kernel = args.pagh_riscv / "target" / TARGET / "debug" / "pagh"
    args.kernel = args.kernel.resolve()
    if not (args.pagh_riscv / "tools" / "run.py").is_file():
        die(f"{args.pagh_riscv} does not look like the pagh-riscv checkout")
    if not args.kernel.is_file():
        die(f"kernel {args.kernel} not found — build it in {args.pagh_riscv}")

    work = pathlib.Path(tempfile.mkdtemp(prefix="pagh-rust-live06-"))
    info(f"workdir {work}")
    try:
        transcript, checks, ports = run_guest(args, work)
        if checks.failures:
            print("live_net: FAIL", file=sys.stderr)
            for item in checks.failures:
                print(f"  FAIL  {item}", file=sys.stderr)
        else:
            info(f"all {len(checks.passed)} checks passed")
        write_transcript(args, transcript, checks, ports)
        return 1 if checks.failures else 0
    finally:
        if args.keep_work:
            info(f"kept workdir {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
