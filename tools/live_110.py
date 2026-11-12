#!/usr/bin/env python3
"""Live-verify the 0.11.0 in-memory I/O surface in QEMU (one boot).

0.11.0 adds the in-memory implementations of the SDK's `io::Write`/`io::BufRead`
traits — std's `Vec<u8>` sink, the `&mut [u8]` sink, the writer cursors
(`Cursor<Vec<u8>>`, `Cursor<&mut Vec<u8>>`, `Cursor<&mut [u8]>`,
`Cursor<[u8; N]>`, `Cursor<Box<[u8]>>`) and `BufRead for &[u8]`. The host gate
pins their partial-write/`WriteZero`/zero-padding semantics; this run is that
same code compiled for `riscv64gc-unknown-none-elf` and executed on the kernel,
one boot, with the allocations coming from the SDK's own bump heap.

What the boot proves, command by command:

* ``run /mnt/io_writers`` — seven sections print one line each and finish with
  ``IO_WRITERS PASS`` / exit 0: `Vec<u8>` accepts `write!`/`writeln!` through
  `write_fmt`; `&mut [u8]` short-writes and reports `WriteZero`; a
  `Cursor<Vec<u8>>` overwrites in place, zero-pads a seek past the end and
  reads the result back; the bounded writer cursors stop at the slice end;
  `BufRead for &[u8]` runs `fill_buf`/`consume`/`read_until`/`lines` over a
  borrowed buffer; `fmt::Write` + `str`/`String` helpers are shown on the
  target (they came from `core`/`alloc`); `copy`, `Tee` over two `Vec`s and
  `BufWriter<Vec<u8>>` compose.
* the same command a second time — the checks are deterministic, so a repeat
  PASS shows the run is repeatable rather than a one-shot allocation accident.

Usage::

    python3 tools/live_110.py                 # build, boot, run, write docs/
    python3 tools/live_110.py --skip-build    # reuse target/…/debug/examples
    python3 tools/live_110.py --keep-work     # keep the image and serial logs

Exit status is 0 only when every check passes; the transcript (including the
failure summary) is written either way.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = "riscv64gc-unknown-none-elf"
PROMPT = b"pagh:rv64>"
EXAMPLES = ("io_writers",)
DEFAULT_KERNEL = pathlib.Path(
    "/home/oleg/pagh-riscv/target/riscv64gc-unknown-none-elf/debug/pagh"
)
DEFAULT_OUTPUT = ROOT / "docs" / "live-sdk-0.11.0.txt"

def die(message: str) -> None:
    print(f"live_110: {message}", file=sys.stderr)
    raise SystemExit(2)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def kernel_package_version(kernel: pathlib.Path) -> str:
    """Read the kernel crate's version for the transcript header.

    Walk up from the kernel ELF (``target/<target>/<profile>/pagh``) to the
    checkout's Cargo.toml, so a later kernel bump cannot leave the transcript
    mislabelled.
    """
    for parent in kernel.parents:
        manifest = parent / "Cargo.toml"
        if not manifest.is_file():
            continue
        try:
            text = manifest.read_text(encoding="utf-8")
        except OSError:
            continue
        match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        if match:
            return match.group(1)
    return "unknown"


def toolchain_channel() -> str:
    text = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    match = re.search(r'^channel\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else "unknown"


def command_version(command: list[str]) -> str:
    try:
        out = subprocess.run(command, check=True, capture_output=True, text=True)
        return out.stdout.splitlines()[0].strip()
    except (OSError, subprocess.CalledProcessError, IndexError):
        return "unknown"


def build(api: str | None) -> None:
    environment = os.environ.copy()
    if api:
        environment["PAGH_API"] = api
    command = [str(ROOT / "build.sh")]
    print(f"+ {' '.join(command)}", flush=True)
    result = subprocess.run(
        command, cwd=ROOT, env=environment, capture_output=True, text=True
    )
    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        die(f"build failed (exit {result.returncode})")
    print(result.stdout.strip(), flush=True)


class Serial:
    """The guest's serial line: output one way, keystrokes the other."""

    def __init__(
        self, socket_path: str, process: subprocess.Popen, stderr_path: pathlib.Path
    ):
        self.process = process
        self.stderr_path = stderr_path
        self.raw = bytearray()
        self.sock = self._connect(socket_path)

    def _connect(self, socket_path: str) -> socket.socket:
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.process.poll() is not None:
                detail = ""
                try:
                    detail = self.stderr_path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    pass
                die(
                    f"QEMU exited during startup (status {self.process.returncode}): "
                    f"{detail}"
                )
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(socket_path)
                return sock
            except OSError:
                sock.close()
                time.sleep(0.05)
        die(f"cannot connect to QEMU's serial socket at {socket_path}")

    def pump(self, seconds: float) -> None:
        self.sock.settimeout(0.1)
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
            self.raw.extend(chunk)

    def wait_for(self, marker: bytes, start: int, timeout: float) -> int:
        deadline = time.time() + timeout
        while time.time() < deadline:
            index = self.raw.find(marker, start)
            if index != -1:
                return index
            if self.process.poll() is not None:
                break
            self.pump(0.2)
        raise TimeoutError(f"marker {marker!r} not seen; QEMU status {self.process.poll()}")

    def send(self, text: str, delay: float = 0.015) -> None:
        for byte in text.encode("utf-8"):
            self.sock.sendall(bytes([byte]))
            time.sleep(delay)

    def run(self, line: str, timeout: float = 60.0) -> str:
        start = len(self.raw)
        self.send(line + "\r")
        self.wait_for(PROMPT, start, timeout)
        self.pump(0.25)
        return (
            self.raw[start:]
            .decode("utf-8", "replace")
            .replace("\r\n", "\n")
            .replace("\r", "\n")
        )

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class Checks:
    def __init__(self) -> None:
        self.items: list[tuple[str, bool, str]] = []

    def add(self, name: str, passed: bool, detail: str = "") -> None:
        self.items.append((name, passed, detail))
        marker = "PASS" if passed else "FAIL"
        suffix = f" ({detail})" if detail and not passed else ""
        print(f"{marker}: {name}{suffix}", flush=True)

    def line(self, name: str, segment: str, expected: str) -> None:
        lines = {line.rstrip("\r") for line in segment.splitlines()}
        self.add(name, expected in lines, f"missing exact line {expected!r}")

    def contains(self, name: str, segment: str, expected: str) -> None:
        self.add(name, expected in segment, f"missing substring {expected!r}")

    def exit_code(self, name: str, segment: str, program: str, code: int) -> None:
        pattern = rf"run: {re.escape(program)} exited with code {code}\b"
        self.add(name, re.search(pattern, segment) is not None, f"missing {pattern!r}")

    @property
    def failed(self) -> list[tuple[str, bool, str]]:
        return [item for item in self.items if not item[1]]

    def summary(self) -> str:
        passed = sum(1 for _, ok, _ in self.items if ok)
        return f"{passed}/{len(self.items)} checks passed"


def stage_rootfs(example_dir: pathlib.Path) -> pathlib.Path:
    staging = ROOT / "target" / "live" / "rootfs"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    for name in EXAMPLES:
        source = example_dir / name
        if not source.is_file():
            die(f"missing built example {source} (run without --skip-build?)")
        shutil.copy2(source, staging / name)
    return staging


def make_image(staging: pathlib.Path) -> pathlib.Path:
    image = ROOT / "target" / "live" / "disk.img"
    image.parent.mkdir(parents=True, exist_ok=True)
    if image.exists():
        image.unlink()
    command = [
        "mke2fs",
        "-q",
        "-t",
        "ext2",
        "-F",
        "-b",
        "4096",
        "-d",
        str(staging),
        str(image),
        "64M",
    ]
    print(f"+ {' '.join(command)}", flush=True)
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        die(f"mke2fs failed (exit {result.returncode})")
    return image


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build pagh_std, boot pagh-riscv in QEMU and verify the "
        "0.11.0 in-memory I/O surface"
    )
    parser.add_argument(
        "--kernel",
        default=os.environ.get("PAGH_KERNEL", str(DEFAULT_KERNEL)),
        help=f"kernel ELF (default: {DEFAULT_KERNEL} or $PAGH_KERNEL)",
    )
    parser.add_argument(
        "--api",
        default=os.environ.get("PAGH_API", ""),
        help="pagh-api checkout passed to build.sh (default: sibling ../pagh-api)",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"transcript path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument("--skip-build", action="store_true", help="use existing ELFs")
    parser.add_argument("--keep-work", action="store_true", help="keep the image")
    parser.add_argument("--memory", default="256M", help="guest RAM (default 256M)")
    parser.add_argument(
        "--timeout", type=float, default=60.0, help="per-command timeout"
    )
    args = parser.parse_args()

    kernel = pathlib.Path(args.kernel).resolve()
    if not kernel.is_file():
        die(f"kernel not found: {kernel}")
    for tool in ("qemu-system-riscv64", "mke2fs"):
        if shutil.which(tool) is None:
            die(f"{tool} is not on PATH")

    if not args.skip_build:
        build(args.api or None)

    example_dir = ROOT / "target" / TARGET / "debug" / "examples"
    staging = stage_rootfs(example_dir)
    image = make_image(staging)

    socket_path = ROOT / "target" / "live" / "serial.sock"
    stderr_path = ROOT / "target" / "live" / "qemu.stderr"
    for path in (socket_path, stderr_path):
        if path.exists():
            path.unlink()

    command = [
        "qemu-system-riscv64",
        "-name",
        "pagh-riscv",
        "-machine",
        "virt",
        "-m",
        args.memory,
        "-kernel",
        str(kernel),
        "-device",
        "ramfb",
        "-global",
        "virtio-mmio.force-legacy=false",
        "-drive",
        f"file={image},format=raw,if=none,id=hd0",
        "-device",
        "virtio-blk-device,drive=hd0",
        "-display",
        "none",
        "-serial",
        f"unix:{socket_path},server=on,wait=on",
        "-no-reboot",
    ]
    print(f"+ {' '.join(command)}", flush=True)
    with stderr_path.open("w", encoding="utf-8") as stderr:
        process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=stderr, text=True
        )
        serial = Serial(str(socket_path), process, stderr_path)
        checks = Checks()
        boot_error = None
        try:
            try:
                serial.wait_for(PROMPT, 0, 90.0)
            except TimeoutError as error:
                boot_error = str(error)
                checks.add("boot: shell prompt", False, boot_error)
            else:
                checks.add("boot: shell prompt", True)

            def run(command_line: str) -> str:
                """Type one shell command, echo its segment, survive a timeout."""
                try:
                    segment = serial.run(command_line, args.timeout)
                except TimeoutError as error:
                    checks.add(f"command: {command_line}", False, str(error))
                    return ""
                print(f"\n=== {command_line}", flush=True)
                print(
                    segment,
                    end="" if segment.endswith("\n") else "\n",
                    flush=True,
                )
                return segment

            if boot_error is None:
                first = run("run /mnt/io_writers")
                if first:
                    checks.line(
                        "io_writers: IO_WRITERS PASS", first, "IO_WRITERS PASS"
                    )
                    for name, marker in [
                        (
                            "Vec<u8> sink accepts write!/write_fmt",
                            "io_writers: Vec<u8> sink ok",
                        ),
                        (
                            "&mut [u8] sink: short write + WriteZero",
                            "io_writers: &mut [u8] sink ok",
                        ),
                        (
                            "Cursor<Vec<u8>> writer: overwrite/zero-pad/read-back",
                            "io_writers: Cursor<Vec<u8>> writer ok",
                        ),
                        (
                            "bounded writer cursors stop at the end",
                            "io_writers: bounded writer cursors ok",
                        ),
                        (
                            "BufRead for &[u8]: fill_buf/consume/read_until/lines",
                            "io_writers: BufRead for &[u8] ok",
                        ),
                        (
                            "fmt::Write + String/str helpers on the target",
                            "io_writers: fmt::Write + String/str helpers ok",
                        ),
                        (
                            "copy/Tee/BufWriter compose with the in-memory sinks",
                            "io_writers: composition ok",
                        ),
                    ]:
                        checks.contains(name, first, marker)
                    checks.add(
                        "no failure path was taken",
                        "IO_WRITERS FAIL" not in first,
                        "the example reported a failed check",
                    )
                    checks.exit_code(
                        "io_writers: exit 0", first, "/mnt/io_writers", 0
                    )

                # Second run: deterministic checks and a fresh bump heap.
                second = run("run /mnt/io_writers")
                if second:
                    checks.line(
                        "second run still passes (deterministic)",
                        second,
                        "IO_WRITERS PASS",
                    )
                    checks.exit_code(
                        "second run: exit 0", second, "/mnt/io_writers", 0
                    )
        finally:
            serial.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        raw = serial.raw.decode("utf-8", "replace")

    # ── transcript ─────────────────────────────────────────────────────────
    now = datetime.datetime.now().astimezone()
    elf = example_dir / "io_writers"
    passed = sum(1 for _, ok, _ in checks.items if ok)
    header = [
        "pagh-rust 0.11.0 — live QEMU acceptance transcript (in-memory writers)",
        "=" * 78,
        "",
        f"date:               {now:%Y-%m-%d %H:%M:%S %z}",
        f"kernel:             {kernel} sha256 {sha256(kernel)}",
        f"kernel crate:       pagh-riscv {kernel_package_version(kernel)}",
        f"toolchain:          {toolchain_channel()} ({command_version(['rustup', 'run', toolchain_channel(), 'rustc', '--version'])})",
        f"qemu:               {command_version(['qemu-system-riscv64', '--version'])}",
        "guest image:        `mke2fs -q -t ext2 -F -b 4096 -d <rootfs>`",
        "staging root:       io_writers (the 0.11.0 example)",
        "build:              ./build.sh (dev profile, strip debuginfo)",
        f"debug ELF:          io_writers sha256 {sha256(elf)}",
        "",
        f"checks:             {passed} passed, {len(checks.items) - passed} failed",
    ]
    summary = [f"  {'PASS' if ok else 'FAIL'}  {name}" for name, ok, _ in checks.items]
    body = [
        "",
        "─" * 78,
        "transcript (QEMU serial)",
        "─" * 78,
        raw.rstrip("\n"),
        "",
    ]
    text = "\n".join(header + summary + body) + "\n"
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    print(f"\nwrote {output}", flush=True)
    print(checks.summary(), flush=True)

    if not args.keep_work:
        shutil.rmtree(image.parent / "rootfs", ignore_errors=True)

    return 0 if not checks.failed else 1


if __name__ == "__main__":
    raise SystemExit(main())