# bench.R — micro-benchmarks for the ITB R binding.
#
# Single Message encrypt and incremental Streaming encrypt throughput
# at 1 MiB / 16 MiB / 64 MiB. Wall-clock via the binding's monotonic
# itb_now() (proc.time()'s user+sys over-count the Go runtime's worker
# threads); output is a fixed-width table:
#
#     bench             size     mb_per_sec
#     message           1 MiB    <n>
#     ...
#
# Configuration is driven by environment variables so a side-by-side
# comparison with the root Go bench harness is straightforward:
#
#     ITB_NONCE_BITS      512         shipped secure default
#     ITB_KEY_BITS        1024        matches root Go BENCH3.md
#     ITB_WITH_PARALLAX   false       root Go bench runs without parallax
#     ITB_WITH_WRAPPER    false       root Go bench runs without the wrapper
#     ITB_INNER_HASH      (profile)   opaque hash name
#     ITB_MSG_PROFILE     (fallback ITB_PROFILE, then singlemsg-triple-nomac-v1)
#     ITB_STREAM_PROFILE  (fallback ITB_PROFILE, then streaming-noaead-triple-v1)
#     ITB_BENCH_MIN_SEC   5           per-case wall-clock budget (seconds)

library(itb)

SIZES <- c(1L * 2^20, 16L * 2^20, 64L * 2^20)
BENCH_MIN_ITERS <- 3L
PUMP_SLICE <- 2^20

env <- function(name, fallback) {
  v <- Sys.getenv(name, unset = "")
  if (nzchar(v)) v else fallback
}

# Reads the per-shape profile env var, falling back to ITB_PROFILE,
# then to the shape's own default.
profile_env <- function(shape_env, fallback) {
  env(shape_env, env("ITB_PROFILE", fallback))
}

bench_min_seconds <- function() {
  v <- suppressWarnings(as.numeric(env("ITB_BENCH_MIN_SEC", "5")))
  if (is.na(v) || v <= 0) 5 else v
}

# Reads the bench-shape env vars and builds the opts string. Defaults
# match the root Go BENCH3.md pin so numbers are directly comparable.
build_opts <- function() {
  args <- list(
    nonce_bits = as.integer(env("ITB_NONCE_BITS", "512")),
    key_bits = as.integer(env("ITB_KEY_BITS", "1024")),
    with_parallax = identical(env("ITB_WITH_PARALLAX", "false"), "true"),
    with_wrapper = identical(env("ITB_WITH_WRAPPER", "false"), "true")
  )
  inner <- env("ITB_INNER_HASH", "")
  if (nzchar(inner)) {
    args$inner_hash <- inner
  }
  mac <- env("ITB_MAC_NAME", "")
  if (nzchar(mac)) {
    args$mac_name <- mac
  }
  itb_opts(args)
}

# CSPRNG-fill so plaintext content matches the root Go bench
# (crypto/rand). Not in the timing loop.
random_bytes <- function(n) {
  con <- file("/dev/urandom", "rb", raw = TRUE)
  on.exit(close(con))
  s <- readBin(con, "raw", n)
  stopifnot(length(s) == n)
  s
}

size_label <- function(size) {
  if (size >= 2^20) {
    sprintf("%d MiB", size %/% 2^20)
  } else {
    sprintf("%d KiB", size %/% 2^10)
  }
}

# Runs fn until the wall-clock budget is spent (with an iteration
# floor + one untimed warm-up), then prints one table row.
bench_case <- function(name, size, fn) {
  fn() # warm-up
  budget <- bench_min_seconds()
  start <- itb_now()
  elapsed <- 0
  iters <- 0L
  while (elapsed < budget || iters < BENCH_MIN_ITERS) {
    fn()
    iters <- iters + 1L
    elapsed <- itb_now() - start
  }
  mb <- size * iters / (1024 * 1024)
  cat(sprintf("%-17s %-8s %.1f\n", name, size_label(size), mb / elapsed))
}

# One incremental encrypt-session pass: feed 1 MiB slices, drain
# available wire as it appears, then end + final drain. Zero-copy on
# both sides of the boundary: stream_write_slice feeds straight from
# `plain`'s storage (an R-side `plain[a:b]` slice would materialise a
# 4 MiB index vector plus a 1 MiB copy per chunk) and stream_read_into
# drains into the ONE reusable `scratch` buffer instead of allocating
# a fresh raw vector per read.
stream_pass <- function(pipe, plain, scratch) {
  sess <- stream_encryptor(pipe)
  off <- 0
  n <- length(plain)
  while (off < n) {
    take <- min(PUMP_SLICE, n - off)
    stream_write_slice(sess, plain, off, take)
    repeat {
      r <- stream_read_into(sess, scratch)
      if (r[1L] == 0L) break
    }
    off <- off + take
  }
  stream_end(sess)
  repeat {
    r <- stream_read_into(sess, scratch)
    if (r[2L] == 1L) break
  }
  stream_free(sess)
}

# Decrypt counterpart.
stream_dec_pass <- function(pipe, wire, scratch) {
  sess <- stream_decryptor(pipe)
  off <- 0
  n <- length(wire)
  while (off < n) {
    take <- min(PUMP_SLICE, n - off)
    stream_write_slice(sess, wire, off, take)
    repeat {
      r <- stream_read_into(sess, scratch)
      if (r[1L] == 0L) break
    }
    off <- off + take
  }
  stream_end(sess)
  repeat {
    r <- stream_read_into(sess, scratch)
    if (r[2L] == 1L) break
  }
  stream_free(sess)
}

main <- function() {
  # Bench-scale allocation churn leaks Go scratch heap unboundedly
  # without a soft memory cap + aggressive GC; the return values
  # report the previous settings, not an error.
  set_memory_limit(512 * 1024 * 1024)
  set_gc_percent(20)

  opts <- build_opts()
  cat(sprintf("%-17s %-8s mb_per_sec\n", "bench", "size"))

  pipe <- pipeline_create(profile_env("ITB_MSG_PROFILE", "singlemsg-triple-nomac-v1"), opts = opts)
  for (size in SIZES) {
    plain <- random_bytes(size)
    bench_case("message", size, function() {
      pipeline_encrypt_message(pipe, plain)
    })
    dec_wire <- pipeline_encrypt_message(pipe, plain)
    bench_case("message-dec", size, function() {
      pipeline_decrypt_message(pipe, dec_wire)
    })
    rm(plain, dec_wire)
    gc(full = TRUE)
  }
  pipeline_free(pipe)

  pipe <- pipeline_create(profile_env("ITB_STREAM_PROFILE", "streaming-noaead-triple-v1"), opts = opts)
  scratch <- raw(4L * PUMP_SLICE) # one reusable drain buffer for all sizes
  for (size in SIZES) {
    plain <- random_bytes(size)
    bench_case("stream", size, function() {
      stream_pass(pipe, plain, scratch)
    })
    dec_wire <- pipeline_encrypt_stream_one_shot(pipe, plain)
    bench_case("stream-dec", size, function() {
      stream_dec_pass(pipe, dec_wire, scratch)
    })
    rm(plain, dec_wire)
    gc(full = TRUE)
  }
  pipeline_free(pipe)

  # Whole-buffer stream: one FFI round trip through
  # pipeline_encrypt_stream_one_shot / pipeline_decrypt_stream_one_shot
  # per iteration.
  pipe <- pipeline_create(profile_env("ITB_STREAM_PROFILE", "streaming-noaead-triple-v1"), opts = opts)
  for (size in SIZES) {
    plain <- random_bytes(size)
    bench_case("stream_one_shot", size, function() {
      pipeline_encrypt_stream_one_shot(pipe, plain)
    })
    dec_wire <- pipeline_encrypt_stream_one_shot(pipe, plain)
    bench_case("stream_one_shot-dec", size, function() {
      pipeline_decrypt_stream_one_shot(pipe, dec_wire)
    })
    rm(plain, dec_wire)
    gc(full = TRUE)
  }
  pipeline_free(pipe)
}

main()
