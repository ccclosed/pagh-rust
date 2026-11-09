#!/usr/bin/env python3
"""Live-verify the kernel-backed `pagh_std::tls` (0.8.0) in QEMU.

0.7.0's acceptance run (`tools/live_070.py`) proved a userland TLS 1.3 client
that had to be handed a wall clock and 32 bytes of entropy. pagh-riscv 0.21.0
moved the client into the kernel (`tls_connect` 1100 / `tls_write` 1101 /
`tls_read` 1102 / `tls_close` 1103, plus `getrandom` 278), and 0.8.0's
`pagh_std::tls` is the wrapper over it. This run is the acceptance for that
path, on the kernel's own launcher (`pagh-riscv/tools/run.py --net --keep`):

* `run /mnt/tls_get` — the example's default fetch of `https://example.com/`
  with **no clock argument and no seed argument**: DNS through the SDK
  resolver, TCP connect, then the kernel's fail-closed handshake (chain to the
  kernel's committed CA bundle, SAN for `example.com`, RTC clock gate,
  `CertificateVerify`). The transcript is read for the kernel's own evidence
  lines (`tls: verified leaf=sha256:…`, `tls: CertificateVerify OK`,
  `tls: user session … open … host=example.com`), the program's status/body
  length, and `TLS_GET PASS`;
* `run /mnt/tls_get --manual` — the same fetch through the `TlsStream` API
  spelled out (connect, write, read one response, `close`), which is what
  proves the stream surface rather than only the `https_get` helper;
* a **self-signed** `example.com` on the host (reached as `10.0.2.2`) must be
  refused: `tls: verify FAILED cause=chain`, `EKEYREJECTED` (errno 129) in
  userland, `TLS_GET FAIL`;
* a **trusted chain for the wrong name** must be refused too — the SAN gate
  cannot be bypassed by pinning the address, because the name the caller passes
  is the name the kernel checks. The host precondition (the chain anchors in a
  bundle root; the certificate does not authorize `example.com`) is verified
  from the host before the guest runs, and a changed internet fails the run
  instead of silently turning the check into a pass;
* `run /mnt/tls_get_vendored https://example.com/ <unix-seconds> kernel` — the
  0.7.0 userland stack (feature `vendored-tls`), kept working on the new ABI,
  seeded from `getrandom` instead of a staged file. Its clock is still the
  caller's (the ABI has no wall-clock read), which is exactly the difference the
  two programs make visible: the kernel-backed fetch needs neither input.

The staged rootfs deliberately contains **no seed file**, not even for the
vendored program: the entropy that 0.7.0 had to be given from outside now comes
from the kernel's pool, and the run's own success is the evidence.

Usage::

    python3 tools/live_080.py                 # build, boot, run, write docs/
    python3 tools/live_080.py --skip-build    # reuse target/…/release/examples
    python3 tools/live_080.py --keep-work     # keep the image and serial logs

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
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = "riscv64gc-unknown-none-elf"

EXAMPLES = ("tls_get", "tls_get_vendored")

# The guest reaches the host's loopback as 10.0.2.2 through QEMU's user network,
# so a host server needs no --hostfwd at all.
HOST_FROM_GUEST = "10.0.2.2"
PROOF_HOST = "example.com"
PROOF_MARKER = "Example Domain"
# The kernel prints this when the pool absorbed QEMU's `/chosen/rng-seed`, and
# the whole point of 0.8.0 is that TLS session keys come from there.
ENTROPY_MARKER = "bytes from /chosen/rng-seed - TLS session keys available"
# The machine's wall clock, read by the kernel (the ABI's `clock_gettime` is the
# uptime counter), is what the certificate validity windows are judged against.
RTC_MARKER = "rtc         goldfish @"
# A host whose chain anchors in the kernel's committed bundle while its SANs do
# not cover PROOF_HOST: the hostname gate needs a certificate that is trusted
# but wrong. Same choice as `tools/live_070.py`.
MISMATCH_HOST = "www.google.com"
# The roots the kernel's committed CA bundle carries
# (pagh-riscv `src/net/ca_bundle.rs`): the SAN-negative host has to chain to one
# of them, or the guest's refusal would be `cause=chain` and prove nothing.
BUNDLE_ROOTS = (
    "ISRG Root X1",
    "ISRG Root X2",
    "GTS Root R1",
    "GTS Root R4",
    "SSL.com TLS ECC Root CA 2022",
    "SSL.com TLS RSA Root CA 2022",
)
# `EKEYREJECTED` (129): the kernel's "the certificate was rejected" errno.
EKEYREJECTED = 129
RUN_TIMEOUT = 120.0
DNS_NAMESERVER = "10.0.2.3"
OUTPUT_DEFAULT = ROOT / "docs" / "live-sdk-0.8.0.txt"


class Failure(RuntimeError):
    """A check failed; the caller records it and moves on."""


def die(message: str, code: int = 2) -> None:
    print(f"live_080: {message}", file=sys.stderr)
    raise SystemExit(code)


def info(message: str) -> None:
    print(f"live_080: {message}", file=sys.stderr)


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


class SelfSignedServer:
    """`openssl s_server` with a self-signed certificate for `PROOF_HOST`.

    Reached from the guest as `10.0.2.2:<port>`; its chain has no anchor in the
    kernel's bundle, so the handshake must be refused with `cause=chain`.
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
    anchor = next((label for label in BUNDLE_ROOTS if label in text), None)
    if anchor is None:
        raise Failure(
            f"{MISMATCH_HOST}'s chain does not end at any committed trust anchor "
            f"({', '.join(BUNDLE_ROOTS)}); the SAN-negative check would not isolate "
            "the hostname gate"
        )
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

    def drain(self, seconds: float) -> None:
        """Collect whatever arrives for `seconds` more (no marker to wait for)."""
        self._pump(seconds)

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
        f"# staged by tools/live_080.py\nnameserver {DNS_NAMESERVER}\n", encoding="utf-8"
    )
    # Deliberately no `/mnt/seed`: 0.7.0 needed 32 bytes handed in from outside,
    # 0.8.0 takes its session keys from the kernel's entropy pool.
    staged = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
    info(f"staged rootfs: {', '.join(staged)}")
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
    markers = ["TLS_GET PASS", "TLS_GET FAIL"]
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

    # The DHCP lease, straight from the kernel's own boot log, so the resolver
    # configuration the guest reads can be checked against what DHCP handed out.
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

    # The kernel's entropy pool is the new source of session keys; without the
    # seed from `/chosen/rng-seed` every handshake is refused, so the boot log
    # line is the evidence that the run below proves something.
    entropy_line = next(
        (line for line in boot_log.splitlines() if ENTROPY_MARKER in line), None
    )
    checks.check(
        entropy_line is not None,
        "boot log: the kernel absorbed /chosen/rng-seed (TLS session keys available)",
        boot_log[-2000:],
    )
    facts["entropy_line"] = entropy_line.strip() if entropy_line else None
    rtc_line = next((line for line in boot_log.splitlines() if RTC_MARKER in line), None)
    checks.check(
        rtc_line is not None,
        "boot log: the kernel found the goldfish RTC (a wall clock for the validity windows)",
        boot_log[-2000:],
    )
    facts["rtc_line"] = rtc_line.strip() if rtc_line else None

    now_unix = int(time.time())
    facts["now_unix"] = now_unix

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

    guest = Guest(str(work / "serial.sock"))
    try:
        # 1. The default fetch: no clock argument, no seed argument. Everything
        #    the 0.7.0 example needed on the command line is now the kernel's.
        fetch = run_scenario(
            guest,
            checks,
            "run /mnt/tls_get",
            "TLS_GET PASS",
            (
                f"tls_get: url=https://{PROOF_HOST}/",
                "tls_get: status 200 body ",
                PROOF_MARKER,
                "tls: verified leaf=sha256:",
                "tls: CertificateVerify OK",
                "tls: user session ",
                f"tls: session up host={PROOF_HOST}",
            ),
        )
        checks.check(
            fetch.count("tls: verify FAILED") == 0,
            "the live fetch took no refusal path",
            fetch,
        )
        status = re.search(r"tls_get: status (\d+) body (\d+) bytes", fetch)
        checks.check(
            status is not None and status.group(1) == "200" and int(status.group(2)) > 0,
            "the fetch printed a 200 and a non-empty body length",
            fetch,
        )

        # 2. The same fetch through the stream API: connect, write, read one
        #    response, `close` — the surface `https_get` is built on.
        run_scenario(
            guest,
            checks,
            "run /mnt/tls_get --manual",
            "TLS_GET PASS",
            (
                "mode=manual",
                f"tls_get: host={PROOF_HOST} port=443 path=/",
                "tls_get: status 200 body ",
            ),
        )

        # 3. The 0.7.0 userland stack on the new ABI, seeded from the kernel
        #    instead of a staged file. It still takes the caller's clock, which
        #    is the gap the kernel-backed path closes.
        run_scenario(
            guest,
            checks,
            f"run /mnt/tls_get_vendored https://{PROOF_HOST}/ {now_unix} kernel",
            "TLS_GET PASS",
            (
                "tls_get_vendored: entropy = getrandom(278) -> ChaCha20",
                "tls: verified leaf=sha256:",
                "tls: CertificateVerify OK",
                "tls: handshake OK",
                "tls: fetch OK",
                PROOF_MARKER,
            ),
        )

        # 4. A chain that does not reach the kernel's bundle: refused.
        run_scenario(
            guest,
            checks,
            f"run /mnt/tls_get https://{PROOF_HOST}:{self_signed.port}/ "
            f"--ip={HOST_FROM_GUEST}",
            "TLS_GET FAIL",
            (
                "tls: verify FAILED cause=chain",
                f"tls: FAILED stage=handshake host={PROOF_HOST}",
                f"(errno {EKEYREJECTED})",
            ),
        )

        # 5. A trusted chain for the wrong name: refused. Pinning the address
        #    cannot bypass the SAN check, because the name is what is checked.
        if mismatch_ip is not None:
            run_scenario(
                guest,
                checks,
                f"run /mnt/tls_get https://{PROOF_HOST}/ --ip={mismatch_ip}",
                "TLS_GET FAIL",
                (
                    "tls: verify FAILED cause=hostname",
                    f"(errno {EKEYREJECTED})",
                ),
            )
    finally:
        # The last `run:` line is printed after the program's own verdict, so
        # give the guest a moment to flush it into the transcript.
        guest.drain(1.0)
        guest.close()
        self_signed.stop()

    return guest.transcript, checks, facts


# ─── transcript ─────────────────────────────────────────────────────────────


def shell_transcript(text: str) -> str:
    """Normalise CRLF for the committed transcript."""
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
        "pagh-rust 0.8.0 — live QEMU acceptance transcript (kernel-backed TLS)",
        "=" * 78,
        "",
        f"date:               {started}",
        f"kernel:             {args.kernel} sha256 {kernel_hash}",
        f"kernel launcher:    pagh-riscv/tools/run.py --net --keep (guest 10.0.2.15/24)",
        f"guest image:        `mke2fs -q -t ext2 -F -b 4096 -d <rootfs>`",
        f"staging root:       {', '.join(EXAMPLES)}, etc/resolv.conf (nameserver "
        f"{facts.get('dhcp_dns')}) — no seed file: session keys come from the "
        f"kernel's getrandom pool",
        "build:              ./build.sh --release --vendored (release profile, strip debuginfo)",
    ]
    for name in EXAMPLES:
        path_ = examples / name
        lines.append(f"release ELF:        {name} sha256 {sha256(path_)}")
    lines += [
        "",
        f"guest address:      {facts.get('guest_ip')} (DHCP, from the boot log)",
        f"DHCP DNS server:    {facts.get('dhcp_dns')} (the value staged in resolv.conf)",
        f"kernel clock:       {facts.get('rtc_line')}",
        f"kernel entropy:     {facts.get('entropy_line')}",
        f"host TLS server:    openssl s_server (self-signed {PROOF_HOST}) on "
        f"{HOST_FROM_GUEST}:{facts.get('self_signed_port')}",
        f"TLS proof host:     https://{PROOF_HOST}/ (chain -> a kernel bundle anchor)",
        f"SAN-negative host:  {MISMATCH_HOST} ({facts.get('mismatch_ip')}) — trusted chain, "
        f"wrong name",
        "clock and entropy:  supplied by the KERNEL (RTC + /chosen/rng-seed) for "
        "tls_get; the vendored program is given the host's clock "
        f"({facts.get('now_unix')}) and takes its seed from getrandom",
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
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--skip-build", action="store_true", help="reuse the release examples")
    parser.add_argument("--keep-work", action="store_true", help="keep the image and serial logs")
    parser.add_argument(
        "--kernel",
        type=pathlib.Path,
        default=None,
        help="kernel ELF (default pagh-riscv debug build)",
    )
    parser.add_argument("--pagh-riscv", type=pathlib.Path, default=ROOT.parent / "pagh-riscv")
    parser.add_argument("--output", type=pathlib.Path, default=OUTPUT_DEFAULT)
    args = parser.parse_args()
    if args.kernel is None:
        args.kernel = args.pagh_riscv / "target" / TARGET / "debug" / "pagh"
    if not args.kernel.is_file():
        die(f"no kernel at {args.kernel} (build pagh-riscv first)")

    started = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    examples = build(args)
    work = pathlib.Path(tempfile.mkdtemp(prefix="pagh-live-080-"))
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
