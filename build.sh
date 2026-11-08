#!/usr/bin/env bash
# Build the pagh_std examples as static RV64 ELFs for `run /mnt/...`.
#
#   ./build.sh                 debug profile (optimized, overflow checks), all examples
#   ./build.sh --release       release profile
#   ./build.sh --fixtures      also build the diagnostic probes (panic/oom/...)
#   ./build.sh --help          this text
#
# The toolchain is the pinned nightly from rust-toolchain.toml, the target is
# riscv64gc-unknown-none-elf, and the linker flags mirror pagh-api/.cargo/config:
#
#     -C link-arg=-T<pagh-api>/pagh-user.ld -C linker=rust-lld
#
# `PAGH_API` selects the sibling checkout (default: ../pagh-api). Building via
# plain `cargo` also works, but requires that sibling layout because the
# workspace .cargo/config.toml names the linker script relatively.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
TARGET=riscv64gc-unknown-none-elf
PROFILE=dev
PROFILE_DIR=debug
BUILD_FIXTURES=0

for argument in "$@"; do
    case "$argument" in
        --release)
            PROFILE=release
            PROFILE_DIR=release
            ;;
        --fixtures)
            BUILD_FIXTURES=1
            ;;
        --debug)
            PROFILE=dev
            PROFILE_DIR=debug
            ;;
        --help | -h)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "build.sh: unknown argument '$argument' (want --release, --fixtures, --help)" >&2
            exit 2
            ;;
    esac
done

TOOLCHAIN=${TOOLCHAIN:-$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")}
if [ -z "$TOOLCHAIN" ]; then
    echo "build.sh: cannot read the pinned toolchain from rust-toolchain.toml" >&2
    exit 2
fi
if ! command -v cargo >/dev/null 2>&1; then
    echo "build.sh: cargo is not on PATH (install rustup: https://rustup.rs)" >&2
    exit 2
fi

if [ -n "${PAGH_API:-}" ]; then
    API_DIR=$(cd "$PAGH_API" && pwd)
else
    API_DIR=$(cd "$ROOT/../pagh-api" && pwd)
fi
LINKER_SCRIPT="$API_DIR/pagh-user.ld"
if [ ! -f "$LINKER_SCRIPT" ]; then
    cat >&2 <<EOF
build.sh: no pagh-user.ld at $LINKER_SCRIPT
Set PAGH_API=/path/to/pagh-api or check out pagh-api next to pagh-rust:
    <parent>/pagh-rust
    <parent>/pagh-api
EOF
    exit 2
fi
if [ ! -f "$API_DIR/libpagh/Cargo.toml" ]; then
    echo "build.sh: $API_DIR does not look like pagh-api (libpagh/Cargo.toml missing)" >&2
    exit 2
fi

# RUSTFLAGS (unlike target.*.rustflags in the config file) can carry the
# absolute linker-script path, so this works for any PAGH_API location. It also
# takes precedence over the relative path in .cargo/config.toml.
export RUSTFLAGS="-C link-arg=-T$LINKER_SCRIPT -C linker=rust-lld"

echo "build.sh: toolchain $TOOLCHAIN, target $TARGET, profile $PROFILE"
echo "build.sh: pagh-api $API_DIR"
echo "build.sh: rustflags $RUSTFLAGS"

cd "$ROOT"
cargo "+$TOOLCHAIN" build --locked --target "$TARGET" --profile "$PROFILE" --examples -p pagh_std
if [ "$BUILD_FIXTURES" -eq 1 ]; then
    cargo "+$TOOLCHAIN" build --locked --target "$TARGET" --profile "$PROFILE" --examples \
        -p pagh_probes
fi

EXAMPLE_DIR="$ROOT/target/$TARGET/$PROFILE_DIR/examples"
echo
echo "ELF outputs (kernel image limit: 1 MiB):"
for name in cat wc find threads_mutex spawn condvar io_traits; do
    path="$EXAMPLE_DIR/$name"
    if [ ! -f "$path" ]; then
        echo "build.sh: expected $path to exist" >&2
        exit 1
    fi
    size=$(wc -c <"$path")
    echo "  $path ($size bytes)"
    if [ "$size" -gt 1048576 ]; then
        echo "build.sh: warning: $name is larger than the kernel's 1 MiB image limit" >&2
    fi
done
if [ "$BUILD_FIXTURES" -eq 1 ]; then
    for name in panic oom chdir fsops clock; do
        path="$EXAMPLE_DIR/$name"
        if [ -f "$path" ]; then
            echo "  $path ($(wc -c <"$path") bytes)"
        fi
    done
fi
echo
echo "Run them in the guest (see README):"
echo "  run /mnt/cat /mnt/hello.txt"
echo "  run /mnt/wc /mnt/lines.txt"
echo "  run /mnt/find /mnt/demo"
echo "  run /mnt/threads_mutex"
echo "  run /mnt/spawn"
echo "  run /mnt/condvar"
echo "  run /mnt/io_traits"
