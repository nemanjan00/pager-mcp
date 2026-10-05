#!/usr/bin/env bash
# Build mcp-pager for the WiFi Pineapple Pager (mipsel-unknown-linux-musl) and
# stage the binary into ./bin/ so payload.sh can launch it.
#
# Two build backends are supported; pick whichever matches your setup:
#
#   METHOD=cross   (default) - uses the `cross` tool (Docker/Podman). Its image
#                              for mipsel-unknown-linux-musl is soft-float, which
#                              matches the Pager. Install once: cargo install cross
#
#   METHOD=buildstd          - nightly Rust + a SOFT-FLOAT mipsel musl toolchain
#                              (for the linker), compiling std from source. The
#                              verified toolchain is the OpenWRT 24.10.1 SDK for
#                              ramips/mt76x8 (mipsel_24kc, soft-float). Set
#                              MIPSEL_CC to its gcc, e.g.
#                                mipsel-openwrt-linux-musl-gcc
#                              and export STAGING_DIR to the SDK's staging_dir.
#                              Do NOT use a hard-float musl.cc toolchain: it links
#                              but will not load on the device.
#
# Usage:
#   ./build.sh                 # cross build
#   METHOD=buildstd MIPSEL_CC=mipsel-openwrt-linux-musl-gcc ./build.sh
set -euo pipefail

TARGET="mipsel-unknown-linux-musl"
METHOD="${METHOD:-cross}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

build_cross() {
    command -v cross >/dev/null 2>&1 || {
        echo "error: 'cross' not found. Install it with:  cargo install cross" >&2
        echo "       (needs Docker or Podman running). Or use METHOD=buildstd." >&2
        exit 1
    }
    cross build --release --target "$TARGET"
}

build_buildstd() {
    : "${MIPSEL_CC:?set MIPSEL_CC to your mipsel musl gcc, e.g. mipsel-linux-musl-gcc}"
    command -v "$MIPSEL_CC" >/dev/null 2>&1 || {
        echo "error: linker '$MIPSEL_CC' not found in PATH." >&2
        exit 1
    }
    rustup toolchain list | grep -q nightly || rustup toolchain install nightly
    rustup component add rust-src --toolchain nightly
    CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER="$MIPSEL_CC" \
    RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort" \
    cargo +nightly build --release --target "$TARGET" \
        -Z build-std=std,panic_abort
}

case "$METHOD" in
    cross)    build_cross ;;
    buildstd) build_buildstd ;;
    *) echo "unknown METHOD=$METHOD (use 'cross' or 'buildstd')" >&2; exit 1 ;;
esac

mkdir -p bin
cp "target/$TARGET/release/mcp-pager" bin/mcp-pager
chmod +x bin/mcp-pager
echo
echo "Built: $(file bin/mcp-pager 2>/dev/null || echo bin/mcp-pager)"
echo "Size:  $(du -h bin/mcp-pager | cut -f1)"
echo
echo "Next: copy this whole mcp_pager/ directory to the Pager under"
echo "      /root/payloads/<category>/ (or install via the Pager UI),"
echo "      edit config.sh, and launch it."
