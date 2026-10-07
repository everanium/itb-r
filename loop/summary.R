# The final summary in both renderings, and the two measurements it
# folds in that are not per-worker counters: the process resident set
# and the shared library's pool counters.

# ------------------------------------------------------------------ #
# Resident set                                                        #
# ------------------------------------------------------------------ #

# Parses one "Vm...:   1234 kB" line of /proc/self/status into bytes;
# zero on any parse failure.
status_kb <- function(line) {
  digits <- sub("^[^:]*:\\s*([0-9]+)\\s.*$", "\\1", line)
  if (!grepl("^[0-9]+$", digits)) {
    return(0)
  }
  as.numeric(digits) * 1024
}

# The process's current resident set and its high-water mark in bytes,
# from /proc/self/status (VmRSS and VmHWM, reported in kB). Both are
# zero on a platform without that file; the figures are informational
# and never enter the verdict.
read_rss <- function() {
  lines <- tryCatch(readLines("/proc/self/status", warn = FALSE),
    error = function(e) NULL, warning = function(w) NULL)
  if (is.null(lines)) {
    return(c(current = 0, peak = 0))
  }
  current <- 0
  peak <- 0
  for (line in lines) {
    if (startsWith(line, "VmRSS:")) {
      current <- status_kb(line)
    } else if (startsWith(line, "VmHWM:")) {
      peak <- status_kb(line)
    }
  }
  c(current = current, peak = peak)
}

# ------------------------------------------------------------------ #
# Pool counters                                                       #
# ------------------------------------------------------------------ #

# Pool counters. The shared library keeps process-wide monotonic totals
# at every pool checkout of its cipher core: per hash-array tier the
# starter width, checkouts, constructor misses, regrow replacements and
# bytes allocated; for the scratch byte pool and the parallax chunk
# pool the checkouts, constructor misses, regrows and regrow bytes. Two
# snapshots bracketing the main loop are differenced into per-run hit /
# miss figures that tell whether a pool keeps its items warm between
# calls or evicts them across GC cycles. The slot layout is read from
# the library: slot 0 carries the tier count T, tier i occupies the
# five slots at 1 + 5*i, and the two byte pools occupy the eight slots
# at 1 + 5*T; the vector is sized from the binding's length query,
# never from a constant.
pool_snapshot <- function() {
  tryCatch(libitb3r::pool_stats(), error = function(e) numeric(0))
}

# The differenced pool figures of one run. R vectors are one-based, so
# the library's slot n is read at index n + 1.
pool_delta <- function(warmup, steady) {
  d <- list(tiers = 0L, starter = numeric(0), get = numeric(0),
    new = numeric(0), regrow = numeric(0), new_bytes = numeric(0),
    buf = c(0, 0, 0, 0), chunk = c(0, 0, 0, 0))
  if (length(warmup) == 0L || length(steady) < 9L ||
    length(warmup) != length(steady)) {
    return(d)
  }
  tiers <- steady[1]
  if (tiers < 0 || 1 + 5 * tiers + 8 > length(steady)) {
    return(d)
  }
  d$tiers <- as.integer(tiers)
  for (i in seq_len(d$tiers)) {
    base <- 1 + 5 * (i - 1) + 1
    d$starter[i] <- steady[base]
    d$get[i] <- steady[base + 1] - warmup[base + 1]
    d$new[i] <- steady[base + 2] - warmup[base + 2]
    d$regrow[i] <- steady[base + 3] - warmup[base + 3]
    d$new_bytes[i] <- steady[base + 4] - warmup[base + 4]
  }
  tail <- 1 + 5 * d$tiers + 1
  for (i in 1:4) {
    d$buf[i] <- steady[tail + i - 1] - warmup[tail + i - 1]
    d$chunk[i] <- steady[tail + 4 + i - 1] - warmup[tail + 4 + i - 1]
  }
  d
}

# Misses over checkouts as a percentage; zero when nothing was checked
# out.
miss_percent <- function(miss, get) {
  if (get <= 0) {
    return(0)
  }
  100 * miss / get
}

# The effective GC percentage as the runtime reports it: the query form
# of the setter (a set-and-restore round trip inside the library) so
# the field is the same whether the value came from the flag, the
# environment, or the runtime default.
effective_gogc <- function(flag) {
  if (flag > 0) {
    return(flag)
  }
  libitb3r::set_gc_percent(-1L)
}

# Renders s as a JSON string literal with the escapes JSON requires.
js <- function(s) {
  out <- gsub("\\", "\\\\", s, fixed = TRUE)
  out <- gsub('"', '\\"', out, fixed = TRUE)
  out <- gsub("\n", "\\n", out, fixed = TRUE)
  out <- gsub("\r", "\\r", out, fixed = TRUE)
  out <- gsub("\t", "\\t", out, fixed = TRUE)
  paste0('"', out, '"')
}

# One compact object on one line, keys in the contract's order, floats
# with the contract's decimal counts and never in exponent form.
#
# R-specific. Every integer key is rendered with "%.0f" rather than
# "%d": the values are doubles because R's integers stop at 2^31, and
# R's own coercion to text would hand back "1e+11" for a byte total,
# which the contract forbids.
emit_json <- function(r, elapsed_ns, totals, pd, rss_growth, gomaxprocs,
                      stream_profile, msg_profile) {
  cfg <- r$cfg
  tiers <- character(0)
  for (i in seq_len(pd$tiers)) {
    if (pd$starter[i] != 0) {
      tiers[length(tiers) + 1L] <- sprintf(
        paste0('{"tier":%d,"starter":%.0f,"get":%.0f,"new":%.0f,"regrow":%.0f,',
          '"new_bytes":%.0f,"miss_percent":%.2f}'),
        i - 1L, pd$starter[i], pd$get[i], pd$new[i], pd$regrow[i],
        pd$new_bytes[i], miss_percent(pd$new[i] + pd$regrow[i], pd$get[i]))
    }
  }
  per_worker <- character(0)
  errors <- character(0)
  for (w in r$workers) {
    per_worker[length(per_worker) + 1L] <- sprintf("%.0f", w$iters)
    if (w$failed) {
      errors[length(errors) + 1L] <- js(w$error)
    }
  }
  out <- paste0(
    sprintf('{"duration_seconds":%.3f', elapsed_ns / 1e9),
    sprintf(',"iterations":%.0f', totals$iters),
    ',"per_worker_iterations":[', paste(per_worker, collapse = ","), "]",
    sprintf(',"bytes_encrypted":%.0f', totals$bytes_enc),
    sprintf(',"bytes_decrypted":%.0f', totals$bytes_dec),
    sprintf(',"encrypt_mb_per_sec":%.1f',
      mb_per_sec(totals$bytes_enc, totals$avg_enc)),
    sprintf(',"decrypt_mb_per_sec":%.1f',
      mb_per_sec(totals$bytes_dec, totals$avg_dec)),
    sprintf(',"combined_mb_per_sec":%.1f',
      mb_per_sec(totals$bytes_enc + totals$bytes_dec, elapsed_ns)),
    sprintf(',"rekeys":%.0f', r$rekeys),
    sprintf(',"blob_cycles":%.0f', r$blob_cycles),
    ',"worker_errors":[', paste(errors, collapse = ","), "]",
    sprintf(',"verdict":"%s"', if (length(errors) == 0L) "PASS" else "FAIL"),
    sprintf(',"shape":"%s"', shape_name(cfg$shape)),
    ',"stream_profile":', js(stream_profile),
    ',"message_profile":', js(msg_profile),
    ',"hash":', js(cfg$hash),
    ',"mac":', js(cfg$mac),
    sprintf(',"payload_bytes":%.0f', cfg$payload),
    sprintf(',"payload_mode":"%s"', payload_mode_name(cfg$payload_mode)),
    sprintf(',"seed":%.0f', cfg$seed),
    sprintf(',"key_bits":%.0f', cfg$key_bits),
    sprintf(',"nonce_bits":%.0f', cfg$nonce_bits),
    sprintf(',"blob_mode":%.0f', cfg$blob_mode),
    ',"drbg":', js(cfg$drbg),
    ',"drbg_auto_tier":', js(libitb3r::drbg_auto_tier()),
    sprintf(',"chunk_size_bytes":%.0f', cfg$chunk_size),
    sprintf(',"barrier_fill":%.0f', cfg$barrier_fill),
    sprintf(',"parallax":"%s"', on_off(cfg$parallax)),
    sprintf(',"wrapper":"%s"', on_off(cfg$wrapper)),
    sprintf(',"goroutines_requested":%.0f', cfg$workers_requested),
    sprintf(',"goroutines":%.0f', cfg$workers),
    sprintf(',"concurrency":"%s"', CONCURRENCY),
    sprintf(',"gogc":"%.0f"', effective_gogc(cfg$gogc)),
    sprintf(',"memlimit_bytes":%.0f', cfg$memlimit),
    sprintf(',"gomaxprocs":%.0f', gomaxprocs),
    ',"microbatch_tiers":', js(policy_label("ITB_MICROBATCH_TIERS")),
    ',"hashpool_starters":', js(policy_label("ITB_HASHPOOL_STARTERS")),
    sprintf(',"rss_warmup_bytes":%.0f', r$rss_warmup),
    sprintf(',"rss_peak_bytes":%.0f', r$rss_peak),
    sprintf(',"rss_final_bytes":%.0f', r$rss_final),
    sprintf(',"rss_growth_percent":%.2f', rss_growth),
    ',"hash_pool_tiers":[', paste(tiers, collapse = ","), "]",
    sprintf(
      paste0(',"buf_pool":{"get":%.0f,"new":%.0f,"regrow":%.0f,',
        '"regrow_bytes":%.0f,"miss_percent":%.2f}'),
      pd$buf[1], pd$buf[2], pd$buf[3], pd$buf[4],
      miss_percent(pd$buf[3], pd$buf[1])),
    sprintf(
      paste0(',"parallax_chunk_pool":{"get":%.0f,"new":%.0f,"regrow":%.0f,',
        '"regrow_bytes":%.0f,"miss_percent":%.2f}'),
      pd$chunk[1], pd$chunk[2], pd$chunk[3], pd$chunk[4],
      miss_percent(pd$chunk[3], pd$chunk[1])),
    "}\n"
  )
  emit(stdout(), out)
}

# Output contract. Both renderings are shared with the Go harness and
# every other binding's loop utility field for field: the same lines in
# the same order, the same keys in the same order, floats with a fixed
# number of decimals so the JSON is byte-identical across
# implementations. The Go harness alone adds its runtime-internal lines
# after rss: and its runtime-internal keys after parallax_chunk_pool;
# nothing here reproduces them because nothing they read is reachable
# through the C ABI.
final_summary <- function(r, elapsed_ns) {
  cfg <- r$cfg
  totals <- list(iters = 0, bytes_enc = 0, bytes_dec = 0,
    nanos_enc = 0, nanos_dec = 0)
  errors <- character(0)
  for (w in r$workers) {
    totals$iters <- totals$iters + w$iters
    totals$bytes_enc <- totals$bytes_enc + w$bytes_enc
    totals$bytes_dec <- totals$bytes_dec + w$bytes_dec
    totals$nanos_enc <- totals$nanos_enc + w$nanos_enc
    totals$nanos_dec <- totals$nanos_dec + w$nanos_dec
    if (w$failed) {
      errors[length(errors) + 1L] <- w$error
    }
  }

  # Throughput. Per-direction throughput divides the sum of every
  # worker's wall time in that direction by the worker count — the
  # equivalent single-stream wall time under N-way concurrency — so
  # each direction reports the aggregate rate it sustained rather than
  # collapsing to combined/2 (every iteration moves equal encrypt and
  # decrypt bytes, so a total-elapsed denominator would give both
  # directions the same figure). The combined rate keeps total elapsed
  # as the one-glance overall figure.
  totals$avg_enc <- if (totals$nanos_enc > 0) {
    totals$nanos_enc %/% cfg$workers
  } else {
    0
  }
  totals$avg_dec <- if (totals$nanos_dec > 0) {
    totals$nanos_dec %/% cfg$workers
  } else {
    0
  }

  rss_delta <- r$rss_final - r$rss_warmup
  rss_growth <- if (r$rss_warmup > 0) 100 * rss_delta / r$rss_warmup else 0

  pd <- pool_delta(r$pool_warmup, r$pool_steady)
  passed <- length(errors) == 0L
  gomaxprocs <- libitb3r::set_gomaxprocs(0L)
  stream_profile <- if (!is.null(r$stream_pipe)) r$stream_profile else ""
  msg_profile <- if (!is.null(r$msg_pipe)) r$msg_profile else ""

  if (cfg$json_output) {
    emit_json(r, elapsed_ns, totals, pd, rss_growth, gomaxprocs,
      stream_profile, msg_profile)
    return(if (passed) 0L else 1L)
  }

  log_line("=== FINAL ===")
  log_line(paste0("  duration: ",
    human_duration((elapsed_ns + 5e5) %/% 1e6 * 1e6)))
  parts <- vapply(r$workers, function(w) sprintf("%.0f", w$iters), "")
  log_line(sprintf("  iterations: %s = %.0f total",
    paste(parts, collapse = " + "), totals$iters))
  log_line(sprintf("  throughput: encrypt %s, decrypt %s, combined %s",
    human_rate(totals$bytes_enc, totals$avg_enc),
    human_rate(totals$bytes_dec, totals$avg_dec),
    human_rate(totals$bytes_enc + totals$bytes_dec, elapsed_ns)))
  log_line(sprintf("  bytes: %s encrypted, %s decrypted",
    human_bytes(totals$bytes_enc), human_bytes(totals$bytes_dec)))
  log_line(sprintf("  data integrity: %.0f/%.0f PASS",
    totals$iters, totals$iters))
  log_line(sprintf("  concurrency: %s, workers %.0f (requested %.0f)",
    CONCURRENCY, cfg$workers, cfg$workers_requested))
  log_line(sprintf(
    "  rss: warmup %s, peak %s, final %s (delta %s, %.1f%% growth)",
    human_bytes(r$rss_warmup), human_bytes(r$rss_peak),
    human_bytes(r$rss_final), human_bytes_signed(rss_delta), rss_growth))
  for (i in seq_len(pd$tiers)) {
    if (pd$starter[i] != 0) {
      miss <- pd$new[i] + pd$regrow[i]
      log_line(sprintf(
        paste0("  hash pool tier %d (starter %.0f): get %.0f, miss %.0f ",
          "(new %.0f + regrow %.0f), miss %.2f%%, %s allocated"),
        i - 1L, pd$starter[i], pd$get[i], miss, pd$new[i], pd$regrow[i],
        miss_percent(miss, pd$get[i]), human_bytes(pd$new_bytes[i])))
    }
  }
  log_line(sprintf(
    paste0("  buf pool: get %.0f, regrow %.0f (of which fresh %.0f), ",
      "miss %.2f%%, %s regrown"),
    pd$buf[1], pd$buf[3], pd$buf[2], miss_percent(pd$buf[3], pd$buf[1]),
    human_bytes(pd$buf[4])))
  log_line(sprintf(
    paste0("  parallax chunk pool: get %.0f, regrow %.0f ",
      "(of which fresh %.0f), miss %.2f%%, %s regrown"),
    pd$chunk[1], pd$chunk[3], pd$chunk[2],
    miss_percent(pd$chunk[3], pd$chunk[1]), human_bytes(pd$chunk[4])))
  if (r$rekeys > 0) {
    log_line(sprintf("  rekeys: %.0f", r$rekeys))
  }
  if (r$blob_cycles > 0) {
    log_line(sprintf("  blob cycles: %.0f", r$blob_cycles))
  }
  for (text in errors) {
    log_line(paste0("  ERROR: ", text))
  }
  if (passed) {
    log_line("  verdict: PASS")
    return(0L)
  }
  log_line(sprintf("  verdict: FAIL (errors=%d)", length(errors)))
  1L
}
