# Standard testthat driver for R CMD check style runs. The
# run_tests.sh entry point calls testthat::test_dir on
# tests/testthat directly with the package installed in .local/.
library(testthat)
library(libitb3r)

test_check("libitb3r")
