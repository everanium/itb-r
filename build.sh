#!/usr/bin/env bash
#
# build.sh -- one-step build for the R binding: (re)builds libitb3.so
# if absent (or when ITB_REBUILD_LIBITB3=1), then installs the R
# package (compiling the C shim src/libitb3r.c) into the local library
# directory .local/. Prerequisites (Go, gcc, R) must be installed
# separately; see README.md "Prerequisites".
#
# Every artefact this binding owns is removed before the build, so
# nothing in the tree predates the invocation. .local/ is wiped and
# rebuilt rather than installed over, and the install is asserted to
# have left exactly the package DESCRIPTION declares: a second package
# sitting beside it would keep a call site that names the wrong package
# resolvable, which hides the breakage instead of reporting it.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's SIMD asm kernels
#                          # (use on hosts without AVX-512+VL)
#
# Environment:
#   ITB_SKIP_CLEAN=1       # keep existing artefacts (fast iteration)
#   ITB_KEEP_DOWNLOADS=1   # keep fetched dependency trees

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

# ---- artefact wipe ---------------------------------------------------
# The build starts from nothing: every artefact this binding owns is
# removed before anything is rebuilt, so no output can predate this
# invocation. ITB_SKIP_CLEAN=1 skips the wipe for fast iteration.
#
# Fetched dependency trees and registry-resolved lock files need network
# to restore, so ITB_KEEP_DOWNLOADS=1 preserves them. That is the weaker
# guarantee: a stale dependency can still mask breakage, and only the
# artefacts this binding compiles itself are then known to be fresh.
#
# Deletion safety: clean_target takes a path relative to this binding's
# own directory. An empty path, an absolute path, or one containing ".."
# is refused outright, and the resolved target is re-checked to lie
# inside the binding directory before removal -- so the wipe cannot
# reach the shared dist/linux-amd64/libitb3.so, the user's own R library,
# or anything else outside this directory. Every removal is logged first.
BINDING_DIR="$(pwd -P)"

# Subtrees, relative to this binding, that a pattern sweep must not
# descend into. A dependency tree preserved by ITB_KEEP_DOWNLOADS sits
# inside this directory, so without this the sweep would reach into the
# very tree the flag is there to protect.
CLEAN_PRUNE=()

clean_target() {
    local rel="$1" abs res
    case "$rel" in
        ""|/*|*..*)
            echo "[clean] refusing unsafe target: '$rel'" >&2
            exit 1
            ;;
    esac
    abs="$BINDING_DIR/$rel"
    [ -e "$abs" ] || [ -L "$abs" ] || return 0
    res="$(readlink -f "$abs")"
    case "$res" in
        "$BINDING_DIR"/*) ;;
        *)
            echo "[clean] refusing target outside $BINDING_DIR: $res" >&2
            exit 1
            ;;
    esac
    echo "[clean] rm -rf $abs"
    rm -rf "$abs"
}

# Remove every entry matching a name pattern anywhere below this
# binding's directory, skipping the CLEAN_PRUNE subtrees. Matches are
# collected before the first removal so the walk is not racing the
# deletions.
clean_tree() {
    local pattern="$1" hit prune
    local -a args=("$BINDING_DIR") hits=()
    for prune in ${CLEAN_PRUNE+"${CLEAN_PRUNE[@]}"}; do
        args+=(-path "$BINDING_DIR/$prune" -prune -o)
    done
    args+=(-name "$pattern" -print0)
    while IFS= read -r -d '' hit; do
        hits+=("$hit")
    done < <(find "${args[@]}")
    for hit in "${hits[@]}"; do
        clean_target "${hit#"$BINDING_DIR"/}"
    done
}

PKG_NAME="$(awk '/^Package:/ { print $2; exit }' DESCRIPTION)"
if [[ -z "$PKG_NAME" ]]; then
    echo "build.sh: DESCRIPTION declares no Package: name" >&2
    exit 1
fi

if [[ "${ITB_SKIP_CLEAN:-0}" == "1" ]]; then
    echo "==> ITB_SKIP_CLEAN=1: keeping the existing artefacts"
else
    echo "==> removing the artefacts owned by this binding"
    # .local/ goes whole: an install left under any other package name
    # keeps that name resolvable and masks a call site that still uses
    # it, so the directory is rebuilt from empty on every invocation.
    clean_target '.local'
    clean_tree '*.o'
    clean_tree '*.so'
    clean_tree '*.Rcheck'
    clean_target 'bench/build'
    # The binding depends on R packages installed in the user's own
    # library, which is outside this directory and never touched here,
    # so there is nothing for ITB_KEEP_DOWNLOADS to preserve.
fi

if [[ ! -f "$DIST_DIR/libitb3.so" || "${ITB_REBUILD_LIBITB3:-0}" == "1" || ${#TAGS[@]} -gt 0 ]]; then
    echo "==> building libitb3.so${TAGS:+ (with ${TAGS[*]})}"
    (cd "$REPO_ROOT" && go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
        -o dist/linux-amd64/libitb3.so ./cmd/cshared)
else
    echo "==> libitb3.so present; skipping Go rebuild (set ITB_REBUILD_LIBITB3=1 to force)"
fi

echo "==> installing the R package into .local/ (also the library eitb loads)"
mkdir -p .local
ITB_LIBITB3_DIR="$DIST_DIR" R CMD INSTALL --no-docs --library=.local . >&2

# The local library must hold exactly the package this source tree
# declares. Anything else resolvable from R_LIBS can satisfy a stale
# package reference on an error path that is otherwise never exercised.
mapfile -t INSTALLED < <(cd .local && ls -A)
if [[ "${#INSTALLED[@]}" -ne 1 || "${INSTALLED[0]}" != "$PKG_NAME" ]]; then
    echo "build.sh: .local/ must contain only '$PKG_NAME', found: ${INSTALLED[*]:-<empty>}" >&2
    exit 1
fi

echo "==> ready: ./run_tests.sh"
