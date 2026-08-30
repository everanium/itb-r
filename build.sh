#!/usr/bin/env bash
#
# build.sh -- one-step build for the R binding: (re)builds libitb.so
# if absent (or when ITB_REBUILD_LIBITB=1), then installs the R
# package (compiling the C shim src/itb_r.c) into the local library
# directory .local/. Prerequisites (Go, gcc, R) must be installed
# separately; see README.md "Prerequisites".
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#                          # (use on hosts without AVX-512+VL)

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

if [[ ! -f "$DIST_DIR/libitb.so" || "${ITB_REBUILD_LIBITB:-0}" == "1" || ${#TAGS[@]} -gt 0 ]]; then
    echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
    (cd "$REPO_ROOT" && go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
        -o dist/linux-amd64/libitb.so ./cmd/cshared)
else
    echo "==> libitb.so present; skipping Go rebuild (set ITB_REBUILD_LIBITB=1 to force)"
fi

echo "==> installing the R package into .local/"
mkdir -p .local
ITB_LIBITB_DIR="$DIST_DIR" R CMD INSTALL --no-docs --library=.local . >&2

echo "==> ready: ./run_tests.sh"
