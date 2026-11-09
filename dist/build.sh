#!/bin/sh
# dist/build.sh — build and package release binaries (SPEC §3.4).
#
# Usage: dist/build.sh [target ...]
#   Targets: x86_64-unknown-linux-musl  (default on Linux hosts)
#            aarch64-unknown-linux-musl (needs aarch64-linux-musl-gcc)
#            universal2-apple-darwin    (default on macOS hosts; lipo)
#            x86_64-apple-darwin aarch64-apple-darwin
#            x86_64-pc-windows-msvc     (needs an msvc host/cross)
#
# Artifacts land in dist/artifacts/ as tar.gz (unix) or zip (windows).
# Honest ceilings: cross-arch linking needs the matching toolchain on the
# host; macOS signing/notarization is out of scope here.
set -eu

cd "$(dirname "$0")/.."
mkdir -p dist/artifacts

host="$(uname -s)"
if [ "$#" -eq 0 ]; then
    case "$host" in
        Linux)  set -- x86_64-unknown-linux-musl aarch64-unknown-linux-musl ;;
        Darwin) set -- universal2-apple-darwin ;;
        *)      echo "dist: unknown host $host — pass targets explicitly" >&2; exit 2 ;;
    esac
fi

for t in "$@"; do
    case "$t" in
        universal2-apple-darwin)
            rustup target add x86_64-apple-darwin aarch64-apple-darwin >/dev/null
            cargo build --release --target x86_64-apple-darwin
            cargo build --release --target aarch64-apple-darwin
            bin="dist/artifacts/detox-rs-universal2-apple-darwin"
            lipo -create \
                target/x86_64-apple-darwin/release/detox-rs \
                target/aarch64-apple-darwin/release/detox-rs \
                -output "$bin"
            shasum -a 256 "$bin" >"$bin.sha256"
            ;;
        x86_64-pc-windows-msvc)
            rustup target add "$t" >/dev/null
            cargo build --release --target "$t"
            bin="dist/artifacts/detox-rs-$t.exe"
            cp "target/$t/release/detox-rs.exe" "$bin"
            sha256sum "$bin" >"$bin.sha256"
            ;;
        *)
            rustup target add "$t" >/dev/null
            cargo build --release --target "$t"
            bin="dist/artifacts/detox-rs-$t"
            cp "target/$t/release/detox-rs" "$bin"
            sha256sum "$bin" >"$bin.sha256"
            (cd dist/artifacts && tar -czf "$(basename "$bin").tar.gz" "$(basename "$bin")")
            ;;
    esac
    echo "dist: built $t"
done
