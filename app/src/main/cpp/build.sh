#!/usr/bin/env bash
#
# Builds the `rtn` helper for every ABI the app ships and drops the binaries into
# ../assets/rtn/<abi>/rtn, where RootTunManager extracts them at runtime.
#
# Usage:
#   NDK=/path/to/ndk ./build.sh
#
# The helpers are plain C, no dependencies beyond bionic, so this is a single
# clang invocation per ABI. Rebuilding with the NDK recorded in the README
# (28.2.13676358) reproduces the binaries checked into ../assets.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)" # repository root

sdk_dir() {
    # local.properties is what the Android Gradle Plugin uses; honour it too
    [ -f "$ROOT/local.properties" ] || return 1
    sed -n 's/^sdk\.dir=//p' "$ROOT/local.properties" | tail -n1
}

NDK="${NDK:-${ANDROID_NDK_HOME:-}}"
if [ -z "$NDK" ]; then
    SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$(sdk_dir || true)}}"
    [ -n "${SDK:-}" ] && NDK="$SDK/ndk/28.2.13676358"
fi
if [ -z "${NDK:-}" ] || [ ! -d "$NDK" ]; then
    echo "error: set NDK=/path/to/android-ndk (28.2.13676358)" >&2
    exit 1
fi

HOST_TAG=linux-x86_64
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
SRC="$HERE/rtn.c"
OUT="$HERE/../assets/rtn"
API=23 # matches minSdk

mkdir -p "$OUT"

build() {
    local abi=$1 triple=$2
    local cc="$TOOLCHAIN/${triple}${API}-clang"
    local dst="$OUT/$abi/rtn"

    if [ ! -x "$cc" ]; then
        echo "error: missing compiler $cc" >&2
        exit 1
    fi

    mkdir -p "$OUT/$abi"
    "$cc" -O2 -Wall -Wextra -fPIE -pie -o "$dst" "$SRC"
    echo "built $abi -> $dst ($(stat -c%s "$dst") bytes)"
}

build arm64-v8a  aarch64-linux-android
build armeabi-v7a armv7a-linux-androideabi
build x86_64     x86_64-linux-android
build x86        i686-linux-android

echo "done"
