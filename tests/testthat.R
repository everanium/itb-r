# testthat.R — standard testthat driver for R CMD check style runs.
# The run_tests.sh entry point calls testthat::test_dir on
# tests/testthat directly with the package installed in .local/.
library(testthat)
library(itb)

test_check("itb")
