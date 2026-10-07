#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the R binding: runs
# the utility with every argument passed through. The utility is pure R
# over the binding's installed package, so there is nothing to compile
# here; build.sh owns libitb3.so, the package install into .local/ and
# the parse check over the sources.
#
# --vanilla keeps a user profile or a saved workspace from writing into
# the utility's own two streams, which the output contract fixes.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

export R_LIBS="$PWD/.local${R_LIBS:+:$R_LIBS}"

exec Rscript --vanilla loop/main.R "$@"
