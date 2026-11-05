#!/usr/bin/env python3
"""Live-verify `pagh_std` in QEMU: build, ext2 image, boot, run, save transcript.

The script is deliberately a real integration test, not a smoke test:

* it builds the examples and the diagnostic probes with the pinned toolchain;
* it stages them plus fixture files in a host directory and populates a 64 MiB
  ext2 image with ``mke2fs -d`` (no host mount, no root);
* it boots the specified pagh-riscv kernel with that image attached and a UNIX
  serial socket;
* it types shell commands one byte at a time (the guest polls a 16-byte UART
  FIFO), captures output and checks exit codes/contents;
* it finishes with a console-stdin test: ``cat`` with no arguments has no EOF,
  so it stays alive after echoing the typed line and the script terminates
  QEMU itself;
* it always writes the raw transcript and a PASS/FAIL check summary to
  ``docs/live-rust-sdk.txt``, even when a check fails.

Usage::

    python3 tools/live_check.py
    python3 tools/live_check.py --kernel /path/to/pagh --keep
    python3 tools/live_check.py --skip-build --output /tmp/transcript.txt

Exit status is 0 only when every check passes. QEMU and ``mke2fs`` must be
installed; ``--help`` lists the knobs.
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
PROMPT_TEXT = "pagh:rv64>"
DEFAULT_KERNEL = pathlib.Path(
    "/home/oleg/pagh-riscv/target/riscv64gc-unknown-none-elf/debug/pagh"
)
DEFAULT_OUTPUT = ROOT / "docs" / "live-rust-sdk.txt"
EXAMPLES = ("cat", "wc", "find", "panic", "oom", "chdir", "fsops", "clock")


def die(message: str) -> None:
    print(f"live_check: {message}", file=sys.stderr)
    raise SystemExit(2)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def toolchain_channel() -> str:
    text = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    match = re.search(r'^channel\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else "unknown"


def rustc_version(channel: str) -> str:
    try:
        out = subprocess.run(
            ["rustup", "run", channel, "rustc", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def qemu_version() -> str:
    try:
        out = subprocess.run(
            ["qemu-system-riscv64", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
        return out.stdout.splitlines()[0].strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def build(api: str | None) -> None:
    environment = os.environ.copy()
    if api:
        environment["PAGH_API"] = api
    command = [str(ROOT / "build.sh"), "--fixtures"]
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
    """The guest's serial line: output in one direction, keystrokes in the other."""

    def __init__(self, socket_path: str, process: subprocess.Popen, stderr_path: pathlib.Path):
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
                    detail = self.stderr_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    pass
                die(f"QEMU exited during startup (status {self.process.returncode}): {detail}")
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
        raise TimeoutError(
            f"marker {marker!r} not seen; QEMU status {self.process.poll()}"
        )

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
        self.add(
            name,
            re.search(pattern, segment) is not None,
            f"missing {pattern!r}",
        )

    @property
    def failed(self) -> list[tuple[str, bool, str]]:
        return [item for item in self.items if not item[1]]

    def summary(self) -> str:
        passed = sum(1 for _, ok, _ in self.items if ok)
        return f"{passed}/{len(self.items)} checks passed"


def stage_rootfs(example_dir: pathlib.Path) -> pathlib.Path:
    staging = ROOT / "target" / "live" / "rootfs"
    shutil.rmtree(staging, ignore_errors=True)
    (staging / "demo" / "sub").mkdir(parents=True)
    (staging / "demo" / "empty").mkdir(parents=True)

    for name in EXAMPLES:
        source = example_dir / name
        if not source.is_file():
            die(f"missing built example {source} (run without --skip-build?)")
        shutil.copy2(source, staging / name)

    (staging / "hello.txt").write_bytes(b"hello from pagh-rust\nsecond line\n")
    (staging / "lines.txt").write_bytes(
        b"one two three\nfour five\nsix\n\nlast line without newline"
    )
    (staging / "empty.txt").write_bytes(b"")
    (staging / "demo" / "alpha.txt").write_bytes(b"alpha\n")
    (staging / "demo" / "sub" / "beta.txt").write_bytes(b"beta\n")
    os.symlink("alpha.txt", staging / "demo" / "link")
    large = "".join(f"line {index}\n" for index in range(1, 201))
    (staging / "large.txt").write_text(large, encoding="utf-8")
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
        description="Build pagh_std, boot pagh-riscv in QEMU and verify the examples"
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
    parser.add_argument("--keep", action="store_true", help="keep disk.img/rootfs")
    parser.add_argument("--memory", default="256M", help="guest RAM (default 256M)")
    parser.add_argument("--timeout", type=float, default=60.0, help="per-command timeout")
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

            checks.add("boot: shell prompt", True)

            def check_cat_hello(segment: str) -> None:
                checks.line("cat: first line", segment, "hello from pagh-rust")
                checks.line("cat: second line", segment, "second line")
                checks.exit_code("cat: exit 0", segment, "/mnt/cat", 0)

            def check_cat_multiple(segment: str) -> None:
                checks.line("cat: concatenates files", segment, "one two three")
                checks.contains(
                    "cat: last line without newline",
                    segment,
                    "last line without newline",
                )
                checks.exit_code("cat multiple: exit 0", segment, "/mnt/cat", 0)

            def check_cat_missing(segment: str) -> None:
                checks.contains(
                    "cat: reports ENOENT",
                    segment,
                    "cat: /mnt/missing.txt: No such file or directory",
                )
                checks.exit_code("cat missing: exit 1", segment, "/mnt/cat", 1)

            def check_wc_hello(segment: str) -> None:
                pattern = r"^\s*2\s+5\s+33\s+/mnt/hello\.txt$"
                checks.add(
                    "wc: 2 lines / 5 words / 33 bytes",
                    re.search(pattern, segment, re.MULTILINE) is not None,
                    f"missing {pattern!r}",
                )
                checks.exit_code("wc: exit 0", segment, "/mnt/wc", 0)

            def check_wc_large(segment: str) -> None:
                pattern = r"^\s*200\s+/mnt/large\.txt$"
                checks.add(
                    "wc -l: 200 lines",
                    re.search(pattern, segment, re.MULTILINE) is not None,
                    f"missing {pattern!r}",
                )
                checks.exit_code("wc -l: exit 0", segment, "/mnt/wc", 0)

            def check_wc_total(segment: str) -> None:
                checks.contains("wc: first file row", segment, "/mnt/hello.txt")
                checks.contains(
                    "wc: second file row", segment, "/mnt/demo/alpha.txt"
                )
                pattern = r"^\s*3\s+6\s+39\s+total$"
                checks.add(
                    "wc: total row",
                    re.search(pattern, segment, re.MULTILINE) is not None,
                    f"missing {pattern!r}",
                )
                checks.exit_code("wc total: exit 0", segment, "/mnt/wc", 0)

            def check_wc_empty(segment: str) -> None:
                pattern = r"^\s*0\s+/mnt/empty\.txt$"
                checks.add(
                    "wc -c: empty file is 0",
                    re.search(pattern, segment, re.MULTILINE) is not None,
                    f"missing {pattern!r}",
                )
                checks.exit_code("wc empty: exit 0", segment, "/mnt/wc", 0)

            def check_find(segment: str) -> None:
                expected = [
                    "/mnt/demo",
                    "/mnt/demo/alpha.txt",
                    "/mnt/demo/empty",
                    "/mnt/demo/link",
                    "/mnt/demo/sub",
                    "/mnt/demo/sub/beta.txt",
                ]
                for line in expected:
                    checks.line(f"find: {line}", segment, line)
                checks.exit_code("find: exit 0", segment, "/mnt/find", 0)

            def check_find_ls(segment: str) -> None:
                pattern_alpha = r"^\d{6}\s+\d+\s+\d+\s+/mnt/demo/alpha\.txt$"
                pattern_beta = r"^\d{6}\s+\d+\s+\d+\s+/mnt/demo/sub/beta\.txt$"
                checks.add(
                    "find -ls: alpha metadata",
                    re.search(pattern_alpha, segment, re.MULTILINE) is not None,
                    f"missing {pattern_alpha!r}",
                )
                checks.add(
                    "find -ls: beta metadata",
                    re.search(pattern_beta, segment, re.MULTILINE) is not None,
                    f"missing {pattern_beta!r}",
                )
                checks.add(
                    "find -ls: filters out dirs",
                    "/mnt/demo/sub\n" not in segment,
                    "a directory line slipped through -type f",
                )
                checks.exit_code("find -ls: exit 0", segment, "/mnt/find", 0)

            def check_find_maxdepth(segment: str) -> None:
                checks.line("find -maxdepth: root", segment, "/mnt/demo")
                checks.line("find -maxdepth: subdir", segment, "/mnt/demo/sub")
                checks.add(
                    "find -maxdepth: no grandchildren",
                    "/mnt/demo/sub/beta.txt" not in segment,
                    "maxdepth 1 descended into sub/",
                )
                checks.exit_code("find -maxdepth: exit 0", segment, "/mnt/find", 0)

            def check_find_relative(segment: str) -> None:
                checks.line("find .: root", segment, ".")
                checks.line("find .: relative child", segment, "./alpha.txt")
                checks.line("find .: relative grandchild", segment, "./sub/beta.txt")
                checks.exit_code("find .: exit 0", segment, "/mnt/find", 0)

            def check_chdir(segment: str) -> None:
                checks.contains("chdir: before", segment, "chdir: before=/")
                checks.contains("chdir: tracked cwd", segment, "chdir: cwd=/mnt/demo")
                checks.contains("chdir: relative read", segment, "chdir: alpha.txt=alpha")
                checks.exit_code("chdir: exit 0", segment, "/mnt/chdir", 0)

            def check_fsops(segment: str) -> None:
                checks.contains("fsops: read", segment, "fsops: read=alpha")
                checks.contains("fsops: readlink", segment, "fsops: readlink=a.txt")
                checks.contains(
                    "fsops: create_new Unsupported",
                    segment,
                    "fsops: create_new unsupported=true",
                )
                checks.contains(
                    "fsops: sync_all Unsupported",
                    segment,
                    "fsops: sync_all unsupported=true",
                )
                checks.contains("fsops: cleaned up", segment, "fsops: removed=true")
                checks.contains("fsops: ok", segment, "fsops: ok")
                checks.exit_code("fsops: exit 0", segment, "/mnt/fsops", 0)

            def check_clock(segment: str) -> None:
                checks.contains(
                    "clock: monotonic advances",
                    segment,
                    "clock: monotonic_advanced=true",
                )
                checks.contains("clock: dbg return", segment, "clock: dbg_return=42")
                checks.contains("clock: debug macro", segment, "40 + 2 = 42")
                checks.contains("clock: sleep", segment, "clock: slept=true")
                checks.contains("clock: uptime", segment, "clock: uptime_ms=")
                checks.contains("clock: ok", segment, "clock: ok")
                checks.exit_code("clock: exit 0", segment, "/mnt/clock", 0)

            def check_panic(segment: str) -> None:
                checks.add(
                    "panic: program: panic at location",
                    re.search(
                        r"panic: panic at .*panic\.rs:\d+:\d+", segment
                    )
                    is not None,
                    "missing 'panic: panic at <file>:<line>:<col>'",
                )
                checks.exit_code("panic: exit 101", segment, "/mnt/panic", 101)

            def check_oom(segment: str) -> None:
                checks.contains("oom: allocation failure", segment, "out of memory")
                checks.exit_code("oom: exit 102", segment, "/mnt/oom", 102)

            commands = [
                ("run /mnt/cat /mnt/hello.txt", check_cat_hello, 30),
                ("run /mnt/cat /mnt/hello.txt /mnt/lines.txt", check_cat_multiple, 30),
                ("run /mnt/cat /mnt/missing.txt", check_cat_missing, 30),
                ("run /mnt/wc /mnt/hello.txt", check_wc_hello, 30),
                ("run /mnt/wc -l /mnt/large.txt", check_wc_large, 30),
                (
                    "run /mnt/wc /mnt/hello.txt /mnt/demo/alpha.txt",
                    check_wc_total,
                    30,
                ),
                ("run /mnt/wc -c /mnt/empty.txt", check_wc_empty, 30),
                ("run /mnt/find /mnt/demo", check_find, 30),
                ("run /mnt/find /mnt/demo -type f -ls", check_find_ls, 30),
                ("run /mnt/find /mnt/demo -maxdepth 1", check_find_maxdepth, 30),
                ("cd /mnt/demo", None, 20),
                ("run /mnt/find .", check_find_relative, 30),
                ("cd /", None, 20),
                ("run /mnt/chdir", check_chdir, 30),
                ("run /mnt/fsops", check_fsops, 60),
                ("run /mnt/clock", check_clock, 60),
                ("run /mnt/panic", check_panic, 30),
                ("run /mnt/oom", check_oom, 60),
            ]

            for command_line, check, timeout in ([] if boot_error else commands):
                print(f"\n=== {command_line}", flush=True)
                try:
                    segment = serial.run(command_line, timeout=timeout)
                except TimeoutError as error:
                    checks.add(f"command: {command_line}", False, str(error))
                    segment = ""
                if segment:
                    print(segment, end="" if segment.endswith("\n") else "\n", flush=True)
                if check is not None and segment:
                    check(segment)

            # Console stdin: `cat` with no arguments blocks (no EOF in the ABI).
            print("\n=== run /mnt/cat (console stdin; no EOF, expected to block)", flush=True)
            stdin_start = len(serial.raw)
            serial.send("run /mnt/cat\r")
            time.sleep(1.0)
            serial.pump(0.5)
            serial.send("console stdin works\r")
            time.sleep(1.0)
            serial.pump(0.5)
            stdin_segment = (
                serial.raw[stdin_start:]
                .decode("utf-8", "replace")
                .replace("\r\n", "\n")
                .replace("\r", "\n")
            )
            print(stdin_segment, end="" if stdin_segment.endswith("\n") else "\n", flush=True)
            checks.contains(
                "stdin: cat echoes console bytes",
                stdin_segment,
                "console stdin works",
            )
            checks.add(
                "stdin: cat has not exited (no EOF)",
                "run: /mnt/cat" not in stdin_segment
                and PROMPT_TEXT not in stdin_segment,
                "the shell returned a prompt; console stdin unexpectedly saw EOF",
            )
        finally:
            serial.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        transcript = serial.raw.decode("utf-8", "replace")
        normalized = transcript.replace("\r\n", "\n").replace("\r", "\n")
        output = pathlib.Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)

        channel = toolchain_channel()
        header = f"""pagh-rust — live Rust SDK verification
=========================================
date (UTC):        {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}
repo:              {ROOT}
repo state:        {(subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip() or "unknown")}
toolchain:         {channel} ({rustc_version(channel)})
target:            {TARGET}
kernel:            {kernel} (sha256 {sha256(kernel)})
kernel package:    pagh-riscv 0.11.0 (Cargo.toml)
qemu:              {qemu_version()}
image:             64 MiB ext2, mke2fs -q -t ext2 -F -b 4096 -d <rootfs> disk.img 64M
build:             ./build.sh --fixtures (debug profile, opt-level 2, strip debuginfo)
checks:            {checks.summary()}

The transcript below has CRLF/CR normalized to LF. The shell prompt is
`pagh:rv64>`. A `run: <path> exited with code N` line is the kernel's own
result line, not something pagh_std prints.

===== serial transcript =====
"""
        footer = f"""
===== checks =====
{os.linesep.join(
    f'{"PASS" if ok else "FAIL"}  {name}' + (f'  [{detail}]' if detail and not ok else "")
    for name, ok, detail in checks.items
)}
{checks.summary()}
"""
        output.write_text(header + normalized + footer, encoding="utf-8")
        print(f"\nlive_check: transcript written to {output}", flush=True)
        print(f"live_check: {checks.summary()}", flush=True)
        if not args.keep:
            shutil.rmtree(staging, ignore_errors=True)
            try:
                image.unlink()
            except FileNotFoundError:
                pass
        if checks.failed:
            for name, _, detail in checks.failed:
                print(f"  FAIL {name}: {detail}", file=sys.stderr)
            return 1
        if boot_error is not None:
            return 1
        return 0


if __name__ == "__main__":
    raise SystemExit(main())