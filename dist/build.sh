#!/bin/sh
# dist/build.sh — build and package release binaries (SPEC §3.4).
#
# Usage: dist/build.sh [target ...]
#   Targets: x86_64-unknown-linux-musl  (default everywhere it links)
#            aarch64-unknown-linux-musl (needs aarch64-linux-musl-gcc on PATH)
#            universal2-apple-darwin    (default on macOS hosts; lipo)
#            x86_64-apple-darwin aarch64-apple-darwin
#            x86_64-pc-windows-msvc     (needs an msvc host/cross)
#
# Artifacts land in dist/artifacts/ as <name>.tar.gz + <name>.sha256
# (windows: raw .exe + .sha256). Every musl artifact is verified STATIC
# before packaging. Honest ceilings: cross-arch linking needs the matching
# toolchain on the host; macOS signing/notarization is out of scope here.
set -eu

cd "$(dirname "$0")/.."
mkdir -p dist/artifacts

host="$(uname -s)"
if [ "$#" -eq 0 ]; then
    case "$host" in
        Linux)  set -- x86_64-unknown-linux-musl ;;
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
            lipo -info "$bin" >/dev/null
            # shasum, not sha256sum: this arm only runs on Darwin hosts.
            (cd dist/artifacts && shasum -a 256 "$(basename "$bin")" >"$(basename "$bin").sha256")
            (cd dist/artifacts && tar -czf "$(basename "$bin").tar.gz" "$(basename "$bin")")
            ;;
        x86_64-pc-windows-msvc)
            rustup target add "$t" >/dev/null
            cargo build --release --target "$t"
            bin="dist/artifacts/detox-rs-$t.exe"
            cp "target/$t/release/detox-rs.exe" "$bin"
            sha256sum "$bin" >"$bin.sha256"
            ;;
        *)
            # Cross-arch musl needs the matching musl-gcc, wired into cargo
            # as the linker (the command check alone still fails at link
            # time — review finding 1).
            case "$t" in
                aarch64-*) command -v aarch64-linux-musl-gcc >/dev/null || {
                    echo "dist: $t needs aarch64-linux-musl-gcc (musl-cross-make) on PATH" >&2
                    exit 2
                }
                : "${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:=aarch64-linux-musl-gcc}"
                export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER ;;
            esac
            rustup target add "$t" >/dev/null
            cargo build --release --target "$t"
            artifact="target/$t/release/detox-rs"
            # SPEC §3.4: the artifact must be static — assert it, don't hope.
            file "$artifact" | grep -q 'static' || {
                echo "dist: $artifact is NOT static — refusing to package" >&2
                exit 2
            }
            bin="dist/artifacts/detox-rs-$t"
            cp "$artifact" "$bin"
            # Hash by basename inside the dir: sidecars must verify with
            # `sha256sum -c` FROM dist/artifacts (review finding 2).
            (cd dist/artifacts && sha256sum "$(basename "$bin")" >"$(basename "$bin").sha256")
            (cd dist/artifacts && tar -czf "$(basename "$bin").tar.gz" "$(basename "$bin")")
            ;;
    esac
    echo "dist: built $t"
done
