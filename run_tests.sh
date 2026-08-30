#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the R binding. Builds and
# installs the package via build.sh, then runs the testthat suite.
# testthat must be installed (see README.md "Prerequisites").
#
# Usage:
#   ./run_tests.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

export R_LIBS="$PWD/.local${R_LIBS:+:$R_LIBS}"

exec Rscript -e 'library(itb); testthat::test_dir("tests/testthat", stop_on_failure = TRUE)'
