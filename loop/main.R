# Long-run stress harness. The loop utility holds one Pipeline handle
# per exercised cipher surface for minutes, hammers it with
# encrypt -> decrypt -> compare round-trips, rotates the outer masters
# and reopens the handle from its session blob on a schedule, and
# reports whether the process survived with every byte intact. It is
# the R binding's counterpart of the Go harness under tools/loop: the
# same flags, the same round structure, the same summary in both
# renderings.
#
# The default shape is full production: the Streaming AEAD profile with
# parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner hash,
# 1024-bit keys, and the compile-in 512-bit nonce width, driven through
# a stream session for five minutes on 16 MiB plaintexts. The worker's
# plaintext is CSPRNG-generated and held for the whole run, so any
# cross-call state leakage inside the Pipeline surfaces as a data
# mismatch rather than cancelling out.
#
# A failure is one of two things. A cipher, rekey or load call that
# returns a non-OK status is a worker error: the run stops, the summary
# lists it, the verdict is FAIL and the exit code 1. A round-trip that
# returns without error but with different bytes is a data mismatch:
# the process terminates on the spot with exit code 3, printing the
# worker, the iteration and the first differing offset, and no
# summary — the state that produced the wrong bytes is the evidence. A
# crash inside the shared library or the host runtime has no exit code
# of its own here; surfacing it is what the utility is for.
#
# Usage:
#
#   Rscript --vanilla loop/main.R --duration 5m --goroutines 1 \
#       --shape stream --hash areion512 --mac hmac-blake3 \
#       --payload-size 16MB --memlimit auto --parallax on --wrapper on

# R-specific. Rscript puts neither the script's own directory nor the
# binding's local package library on any search path, so both are
# placed there explicitly rather than through an environment variable
# the launcher would have to set — everything the launcher contributes
# has to be part of what a reader runs by hand.
LOOP_DIR <- local({
  file_arg <- grep("^--file=", commandArgs(FALSE), value = TRUE)
  path <- if (length(file_arg) > 0L) sub("^--file=", "", file_arg[1L]) else "."
  dirname(normalizePath(path, mustWork = FALSE))
})
local({
  lib <- file.path(dirname(LOOP_DIR), ".local")
  if (dir.exists(lib)) {
    .libPaths(c(normalizePath(lib), .libPaths()))
  }
})

suppressPackageStartupMessages(library(libitb3r))

source(file.path(LOOP_DIR, "size.R"), local = FALSE)
source(file.path(LOOP_DIR, "payload.R"), local = FALSE)
source(file.path(LOOP_DIR, "state.R"), local = FALSE)
source(file.path(LOOP_DIR, "ops.R"), local = FALSE)
source(file.path(LOOP_DIR, "worker.R"), local = FALSE)
source(file.path(LOOP_DIR, "summary.R"), local = FALSE)

# Profiles the shape-based pair is built against when --profile is
# empty.
DEFAULT_STREAM_PROFILE <- "streaming-aead-triple-mac-v1"
DEFAULT_MESSAGE_PROFILE <- "singlemsg-triple-mac-v1"

# The primitive supplied for the parallax palette and the outer cipher
# when a profile leaves them unnamed. AES-CMAC is PRF-grade, so it is
# sound outside the Interlocked Barrier, and it is the closest relative
# of the AES-based inner primitive whose profiles need this fill.
KEYSTREAM_FILL_CIPHER <- "aescmac"

# ------------------------------------------------------------------ #
# Flags                                                               #
# ------------------------------------------------------------------ #

KIND_INT <- 0L
KIND_INT64 <- 1L
KIND_UINT64 <- 2L
KIND_STRING <- 3L
KIND_BOOL <- 4L

# One command-line flag: its name, the type label the usage prints, its
# kind, its default, and its help text. Values are validated after the
# whole line is parsed. The table is in alphabetical order, which is
# the order the usage prints.
FLAGS <- list(
  list("barrier-fill", "int", KIND_INT, 0,
    "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)"),
  list("blob-cycle-every", "int", KIND_INT64, 0,
    "reopen each pipeline from its session blob every N iterations per worker; 0 = never"),
  list("blob-mode", "int", KIND_INT, 1,
    "container floor sizing mode: 1 (per-region, default) | 2 (per-container)"),
  list("chunk-size", "string", KIND_STRING, "0",
    "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape"),
  list("drbg", "string", KIND_STRING, "",
    "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)"),
  list("duration", "duration", KIND_STRING, "5m",
    "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0"),
  list("gogc", "int", KIND_INT, 0,
    "GC trigger percentage; 0 = leave the runtime default"),
  list("gomaxprocs", "int", KIND_INT, 0,
    "Go runtime GOMAXPROCS override; 0 = inherit from the environment"),
  list("goroutines", "int", KIND_INT, 3,
    "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1"),
  list("hash", "string", KIND_STRING, "areion512",
    "inner ITB hash primitive name"),
  list("iterations", "int", KIND_INT64, 0,
    "fixed per-worker iteration count; 0 = duration-based"),
  list("json-output", "", KIND_BOOL, FALSE,
    "print the final summary as one compact JSON object instead of log lines"),
  list("key-bits", "int", KIND_INT, 0,
    "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)"),
  list("mac", "string", KIND_STRING, "hmac-blake3",
    "MAC primitive name"),
  list("memlimit", "string", KIND_STRING, "auto",
    paste0("Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, ",
      "applied only when the runtime has no limit) or a size (e.g. 512MB)")),
  list("memprofile", "string", KIND_STRING, "",
    "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none"),
  list("nonce-bits", "int", KIND_INT, 0,
    "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)"),
  list("parallax", "string", KIND_STRING, "on",
    "parallax layer: on | off"),
  list("payload-mode", "string", KIND_STRING, "fixed",
    "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii"),
  list("payload-size", "string", KIND_STRING, "16MB",
    "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)"),
  list("profile", "string", KIND_STRING, "",
    paste0("exercise this single registered triple profile (overrides --shape ",
      "with the profile's surface); empty = shape-based profile pair")),
  list("rekey-every", "int", KIND_INT64, 0,
    "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never"),
  list("seed", "uint", KIND_UINT64, 0,
    paste0("deterministic plaintext RNG seed for bug reproduction, NOT for ",
      "security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts")),
  list("shape", "string", KIND_STRING, "stream",
    "cipher surface to exercise: stream | message | stream_one_shot | both"),
  list("wrapper", "string", KIND_STRING, "on",
    "wrapper layer: on | off")
)

INT32_MAX <- 2147483647
UINT64_MAX <- 18446744073709551615

usage <- function() {
  out <- "Usage of loop:\n"
  for (f in FLAGS) {
    name <- f[[1]]
    label <- f[[2]]
    kind <- f[[3]]
    default <- f[[4]]
    help <- f[[5]]
    out <- paste0(out, "  -", name,
      if (nzchar(label)) paste0(" ", label) else "", "\n")
    line <- paste0("    \t", help)
    # The default-value suffix follows the shape a Go flag set prints:
    # an integer default only when it is non-zero, a string default
    # only when it is non-empty.
    if (kind == KIND_INT && default != 0) {
      line <- paste0(line, sprintf(" (default %.0f)", default))
    } else if (kind == KIND_STRING && nzchar(default)) {
      line <- paste0(line, sprintf(' (default "%s")', default))
    }
    out <- paste0(out, line, "\n")
  }
  emit(stderr(), out)
}

# Parses one value into its flag slot; NULL on a malformed value.
assign_flag <- function(kind, value) {
  if (kind == KIND_INT || kind == KIND_INT64) {
    body <- if (grepl("^[+-]", value)) substring(value, 2) else value
    if (!nzchar(body) || grepl("[^0-9]", body)) {
      return(NULL)
    }
    n <- as.numeric(body)
    if (!is.finite(n)) {
      return(NULL)
    }
    if (startsWith(value, "-")) {
      n <- -n
    }
    if (kind == KIND_INT && (n > INT32_MAX || n < -INT32_MAX)) {
      return(NULL)
    }
    return(n)
  }
  if (kind == KIND_UINT64) {
    body <- if (startsWith(value, "+")) substring(value, 2) else value
    if (!nzchar(body) || grepl("[^0-9]", body)) {
      return(NULL)
    }
    n <- as.numeric(body)
    if (!is.finite(n) || n > UINT64_MAX) {
      return(NULL)
    }
    return(n)
  }
  if (kind == KIND_STRING) {
    return(value)
  }
  if (value == "true") {
    return(TRUE)
  }
  if (value == "false") {
    return(FALSE)
  }
  NULL
}

# Parses argv into the raw flag values. Accepts -name value,
# --name value, -name=value and --name=value; a boolean flag takes no
# value unless given as -name=true / -name=false. Returns
# list(rc = 0, raw), list(rc = 1) for -h / --help (usage printed), or
# list(rc = -1) after printing the error.
parse_argv <- function(argv) {
  raw <- list()
  kinds <- list()
  for (f in FLAGS) {
    raw[[f[[1]]]] <- f[[4]]
    kinds[[f[[1]]]] <- f[[3]]
  }
  i <- 1L
  while (i <= length(argv)) {
    a <- argv[i]
    if (!startsWith(a, "-") || a == "-") {
      err_line(sprintf("unexpected positional arguments: [%s]", a))
      return(list(rc = -1L))
    }
    name <- if (startsWith(a, "--")) substring(a, 3) else substring(a, 2)
    if (name == "h" || name == "help") {
      usage()
      return(list(rc = 1L))
    }
    value <- NULL
    eq <- regexpr("=", name, fixed = TRUE)
    if (eq > 0L) {
      value <- substring(name, eq + 1L)
      name <- substring(name, 1L, eq - 1L)
    }
    kind <- kinds[[name]]
    if (is.null(kind)) {
      err_line(sprintf("flag provided but not defined: -%s", name))
      usage()
      return(list(rc = -1L))
    }
    if (is.null(value)) {
      if (kind == KIND_BOOL) {
        value <- "true"
      } else if (i < length(argv)) {
        i <- i + 1L
        value <- argv[i]
      } else {
        err_line(sprintf("flag needs an argument: -%s", name))
        return(list(rc = -1L))
      }
    }
    parsed <- assign_flag(kind, value)
    if (is.null(parsed)) {
      err_line(sprintf('invalid value "%s" for flag -%s', value, name))
      return(list(rc = -1L))
    }
    raw[[name]] <- parsed
    i <- i + 1L
  }
  list(rc = 0L, raw = raw)
}

parse_on_off <- function(v) {
  if (identical(v, "on")) {
    return(TRUE)
  }
  if (identical(v, "off")) {
    return(FALSE)
  }
  NULL
}

# Whether name is in the shipped hash registry the binding enumerates.
hash_registered <- function(name) {
  names <- tryCatch(libitb3r::hash_names(), error = function(e) character(0))
  name %in% names
}

# ------------------------------------------------------------------ #
# Profile records                                                     #
# ------------------------------------------------------------------ #

# The binding hands a profile record back as its JSON text, and record
# strings are restricted to [a-z0-9-], so a quoted run is one complete
# value and a key probe is a substring search — the same reading the C
# reference does.
record_has <- function(json, key) {
  grepl(paste0('"', key, '":'), json, fixed = TRUE)
}

record_int <- function(json, key) {
  m <- regmatches(json, regexpr(paste0('"', key, '":-?[0-9]+'), json))
  if (length(m) == 0L) {
    return(0)
  }
  as.numeric(sub(paste0('"', key, '":'), "", m[1L], fixed = TRUE))
}

record_str <- function(json, key) {
  m <- regmatches(json, regexpr(paste0('"', key, '":"[^"]*"'), json))
  if (length(m) == 0L) {
    return("-")
  }
  v <- sub(paste0('^"', key, '":"'), "", m[1L])
  v <- sub('"$', "", v)
  if (nzchar(v)) v else "-"
}

record_bool <- function(json, key) {
  grepl(paste0('"', key, '":true'), json, fixed = TRUE)
}

# Resolves a registered profile to the shape family its record's mode
# exposes by reading the record through the binding's lookup: a mode
# beginning with "streaming" exposes the stream surfaces, one beginning
# with "singlemsg" the message surface, "blob-only" none. Prints the
# validation message and returns NULL on rejection.
profile_surface <- function(name) {
  json <- tryCatch(libitb3r::lookup(name), error = function(e) NULL)
  if (is.null(json)) {
    err_line(sprintf('--profile "%s" is not a registered triple profile', name))
    return(NULL)
  }
  mode <- record_str(json, "mode")
  if (startsWith(mode, "streaming")) {
    return(SHAPE_STREAM)
  }
  if (startsWith(mode, "singlemsg")) {
    return(SHAPE_MESSAGE)
  }
  err_line(sprintf('--profile "%s" carries no cipher surface (blob-only mode)',
    name))
  NULL
}

# Applies a --profile's surface to the requested shape: a
# message-surface profile forces message; a stream-surface profile
# keeps stream or stream_one_shot as requested and turns message or
# both into stream.
narrow_shape <- function(requested, surface) {
  if (surface == SHAPE_MESSAGE) {
    return(SHAPE_MESSAGE)
  }
  if (requested == SHAPE_STREAM_ONE_SHOT) {
    return(SHAPE_STREAM_ONE_SHOT)
  }
  SHAPE_STREAM
}

# ------------------------------------------------------------------ #
# Validation                                                          #
# ------------------------------------------------------------------ #

# Builds the resolved config from argv. Returns list(rc, cfg); rc is 0
# on success, 1 for help, -1 after printing "loop: <message>" for the
# first failing rule.
parse_flags <- function(argv) {
  cfg <- new_config()
  parsed <- parse_argv(argv)
  if (parsed$rc != 0L) {
    return(list(rc = parsed$rc, cfg = cfg))
  }
  raw <- parsed$raw
  fail <- function() list(rc = -1L, cfg = cfg)

  duration_ns <- parse_duration(raw[["duration"]])
  if (is.null(duration_ns) || duration_ns <= 0) {
    err_line(sprintf("--duration must be positive, got %s", raw[["duration"]]))
    return(fail())
  }
  cfg$duration_ns <- duration_ns
  cfg$iterations <- raw[["iterations"]]
  if (cfg$iterations < 0) {
    err_line(sprintf("--iterations must be >= 0, got %.0f", cfg$iterations))
    return(fail())
  }
  goroutines <- raw[["goroutines"]]
  if (goroutines < 1 || goroutines > MAX_WORKERS) {
    err_line(sprintf("--goroutines must be in 1..%d, got %.0f",
      MAX_WORKERS, goroutines))
    return(fail())
  }
  # Concurrency mode. This binding runs single, so the requested count
  # is recorded and the effective one clamped to 1; the summary reports
  # both so a fleet report cannot read a clamped run as a concurrent
  # one.
  cfg$workers_requested <- goroutines
  cfg$workers <- 1
  shape <- parse_shape(raw[["shape"]])
  if (is.null(shape)) {
    err_line(sprintf(
      '--shape must be stream | message | stream_one_shot | both, got "%s"',
      raw[["shape"]]))
    return(fail())
  }
  cfg$shape <- shape
  if (!hash_registered(raw[["hash"]])) {
    err_line(sprintf('--hash "%s" is not a registered hash primitive',
      raw[["hash"]]))
    return(fail())
  }
  cfg$hash <- raw[["hash"]]
  # Validated by Init: the C ABI enumerates no MAC names.
  cfg$mac <- raw[["mac"]]
  payload_bytes <- parse_size(raw[["payload-size"]])
  if (is.null(payload_bytes)) {
    err_line(sprintf('--payload-size: invalid size "%s"', raw[["payload-size"]]))
    return(fail())
  }
  cfg$payload <- payload_bytes
  if (cfg$payload < 1) {
    err_line("--payload-size must be at least 1 byte")
    return(fail())
  }
  if (identical(raw[["memlimit"]], "auto")) {
    cfg$memlimit_auto <- TRUE
    cfg$memlimit <- if (cfg$workers <= 3) 1073741824 else 268435456
  } else {
    memlimit <- parse_size(raw[["memlimit"]])
    if (is.null(memlimit)) {
      err_line(sprintf('--memlimit: invalid size "%s"', raw[["memlimit"]]))
      return(fail())
    }
    cfg$memlimit <- memlimit
  }
  cfg$gogc <- raw[["gogc"]]
  if (cfg$gogc < 0) {
    err_line(sprintf("--gogc must be >= 0, got %.0f", cfg$gogc))
    return(fail())
  }
  parallax <- parse_on_off(raw[["parallax"]])
  if (is.null(parallax)) {
    err_line(sprintf('--parallax must be on | off, got "%s"', raw[["parallax"]]))
    return(fail())
  }
  cfg$parallax <- parallax
  wrapper <- parse_on_off(raw[["wrapper"]])
  if (is.null(wrapper)) {
    err_line(sprintf('--wrapper must be on | off, got "%s"', raw[["wrapper"]]))
    return(fail())
  }
  cfg$wrapper <- wrapper
  cfg$profile <- raw[["profile"]]
  if (nzchar(cfg$profile)) {
    surface <- profile_surface(cfg$profile)
    if (is.null(surface)) {
      return(fail())
    }
    cfg$shape <- narrow_shape(cfg$shape, surface)
  }
  cfg$key_bits <- raw[["key-bits"]]
  if (!(cfg$key_bits %in% c(0, 512, 1024, 2048))) {
    err_line(sprintf(
      "--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got %.0f",
      cfg$key_bits))
    return(fail())
  }
  cfg$nonce_bits <- raw[["nonce-bits"]]
  if (!(cfg$nonce_bits %in% c(0, 128, 256, 512))) {
    err_line(sprintf(
      "--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got %.0f",
      cfg$nonce_bits))
    return(fail())
  }
  cfg$blob_mode <- raw[["blob-mode"]]
  if (!(cfg$blob_mode %in% c(1, 2))) {
    err_line(sprintf(
      "--blob-mode must be 1 (per-region) | 2 (per-container), got %.0f",
      cfg$blob_mode))
    return(fail())
  }
  cfg$barrier_fill <- raw[["barrier-fill"]]
  if (!(cfg$barrier_fill %in% c(0, 1, 2, 4, 8, 16, 32))) {
    err_line(sprintf(paste0("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 ",
      "(or 0 = profile default), got %.0f"), cfg$barrier_fill))
    return(fail())
  }
  # Validated by Init: the C ABI enumerates no DRBG names.
  cfg$drbg <- raw[["drbg"]]
  chunk_size <- parse_size(raw[["chunk-size"]])
  if (is.null(chunk_size)) {
    err_line(sprintf('--chunk-size: invalid size "%s"', raw[["chunk-size"]]))
    return(fail())
  }
  cfg$chunk_size <- chunk_size
  cfg$gomaxprocs <- raw[["gomaxprocs"]]
  if (cfg$gomaxprocs < 0) {
    err_line(sprintf("--gomaxprocs must be > 0 when specified, got %.0f",
      cfg$gomaxprocs))
    return(fail())
  }
  cfg$rekey_every <- raw[["rekey-every"]]
  if (cfg$rekey_every < 0) {
    err_line(sprintf("--rekey-every must be >= 0, got %.0f", cfg$rekey_every))
    return(fail())
  }
  cfg$blob_cycle_every <- raw[["blob-cycle-every"]]
  if (cfg$blob_cycle_every < 0) {
    err_line(sprintf("--blob-cycle-every must be >= 0, got %.0f",
      cfg$blob_cycle_every))
    return(fail())
  }
  payload_mode <- parse_payload_mode(raw[["payload-mode"]])
  if (is.null(payload_mode)) {
    err_line(sprintf('--payload-mode must be %s, got "%s"',
      paste(PAYLOAD_NAMES, collapse = " | "), raw[["payload-mode"]]))
    return(fail())
  }
  cfg$payload_mode <- payload_mode
  cfg$seed <- raw[["seed"]]
  cfg$json_output <- raw[["json-output"]]
  cfg$memprofile <- raw[["memprofile"]]
  list(rc = 0L, cfg = cfg)
}

# ------------------------------------------------------------------ #
# Pipelines                                                           #
# ------------------------------------------------------------------ #

# Prints the construction line with the recipe read back from the blob
# the Pipeline handed out, not echoed from the flags: every
# construction override is proven to have reached the library by the
# value the receiver would see. Record values that are empty (a No MAC
# profile's MAC, a mixed profile's single hash) print as "-".
log_pipeline_initialised <- function(profile, blob) {
  json <- tryCatch(libitb3r::inspect(blob), error = function(e) e)
  if (inherits(json, "condition")) {
    log_line(sprintf(
      "pipeline initialised: profile=%s blob=%.0f bytes (inspect: %s)",
      profile, length(blob), status_message(json)))
    return(invisible(NULL))
  }
  line <- sprintf(
    paste0("pipeline initialised: profile=%s blob=%.0f bytes hash=%s ",
      "key-bits=%.0f nonce-bits=%.0f barrier-fill=%.0f chunk-size=%.0f ",
      "mac=%s parallax=%s wrapper=%s"),
    profile, length(blob), record_str(json, "hash"),
    record_int(json, "keybits"), record_int(json, "nonce_bits"),
    record_int(json, "barrier_fill"), record_int(json, "chunk"),
    record_str(json, "mac"), on_off(record_bool(json, "parallax")),
    on_off(record_bool(json, "wrapper")))
  if (record_int(json, "container_mode") == 2) {
    line <- paste0(line, " container-mode=2")
  }
  drbg <- record_str(json, "drbg")
  if (drbg != "-") {
    line <- paste0(line, " drbg=", drbg)
  }
  log_line(line)
  invisible(NULL)
}

# Returns a copy of a wrap-layer session blob whose inner blob's "mode"
# field is set to target_mode (1 = per-region, 2 = per-container), or
# NULL when the inner blob or its mode field is not found. The wrap
# layer's profile record carries its own "mode" (a string), so the
# search starts at the inner blob ("ib"); both shipped modes are one
# digit wide, so the blob length does not change and nothing before the
# inner blob is touched. The edit is a byte replacement on the raw
# vector, the same reading the profile-record probes use, so the
# integers and base64 fields of the blob are never re-rendered.
edit_inner_blob_mode <- function(blob, target_mode) {
  ib <- grepRaw('"ib":{', blob, fixed = TRUE)
  if (length(ib) == 0L) {
    return(NULL)
  }
  off <- ib + nchar('"ib":{')
  rel <- grepRaw('"mode":', blob, offset = off, fixed = TRUE)
  if (length(rel) == 0L) {
    return(NULL)
  }
  at <- rel + nchar('"mode":')
  if (at + 1L > length(blob)) {
    return(NULL)
  }
  digit <- as.integer(blob[at])
  nxt <- as.integer(blob[at + 1L])
  if (digit < 0x31L || digit > 0x32L || (nxt >= 0x30L && nxt <= 0x39L)) {
    return(NULL)
  }
  blob[at] <- as.raw(0x30L + target_mode)
  blob
}

# Folds a keystream primitive into opts for any layer the named profile
# leaves unfilled but the operator asked for.
#
# A profile built around a primitive that is safe only inside the
# Interlocked Barrier ships with no parallax palette and no outer
# cipher: both layers run outside the barrier, where that primitive
# would stand bare, so the recipe leaves them unnamed rather than
# naming a primitive that must not key them. Engaging either layer
# therefore needs a keystream-capable primitive supplied from outside
# the recipe; without it construction fails on a palette below its
# minimum or an unnamed outer cipher, and the primitive that most
# deserves stressing becomes the one that cannot be stressed with those
# layers engaged.
#
# Overrides fold into the resolved record the blob carries, so the
# receiver rebuilds the same shape from the blob alone.
#
# Returns list(filled, opts): filled is 1 when a layer was filled, 0
# when none needed it, -1 on a lookup failure (message already
# printed).
fill_keystream_layers <- function(name, opts, want_parallax, want_wrapper) {
  json <- tryCatch(libitb3r::lookup(name), error = function(e) NULL)
  if (is.null(json)) {
    err_line(sprintf('--profile "%s" is not a registered triple profile', name))
    return(list(filled = -1L, opts = opts))
  }
  filled <- 0L
  if (want_parallax && !record_has(json, "palette")) {
    opts$parallax_palette <- rep(KEYSTREAM_FILL_CIPHER, 3)
    if (!record_has(json, "segment")) {
      # A recipe that never carried a palette never carried a segment
      # size either, and the schedule rejects zero.
      opts$parallax_segment_size <- 4093
    }
    filled <- 1L
  }
  if (want_wrapper && !record_has(json, "outer")) {
    opts$outer_cipher <- KEYSTREAM_FILL_CIPHER
    filled <- 1L
  }
  list(filled = filled, opts = opts)
}

# Constructs one Pipeline against profile with every flag-carried
# override in the opts string (zero values included — the shared
# library treats zero as "profile default"), then obtains the Init blob
# once through save: the binding's create entry does not hand the blob
# back, and the bytes are the ones Init produced. Later blob reopens
# use the retained blob; save is never called again.
build_pipeline <- function(cfg, profile) {
  opts <- list(
    inner_hash = cfg$hash,
    mac_name = cfg$mac,
    with_parallax = cfg$parallax,
    with_wrapper = cfg$wrapper,
    key_bits = cfg$key_bits,
    nonce_bits = cfg$nonce_bits,
    barrier_fill = cfg$barrier_fill,
    drbg = cfg$drbg,
    chunk_size = cfg$chunk_size
  )
  if (nzchar(cfg$profile)) {
    res <- fill_keystream_layers(cfg$profile, opts, cfg$parallax, cfg$wrapper)
    if (res$filled < 0L) {
      return(NULL)
    }
    opts <- res$opts
    if (res$filled > 0L) {
      err_line(sprintf(
        "%s leaves the requested keystream layers unnamed; %s supplied for them",
        cfg$profile, KEYSTREAM_FILL_CIPHER))
    }
  }
  pipe <- tryCatch(
    libitb3r::pipeline_create(profile, do.call(libitb3r::itb_opts, opts)),
    error = function(e) {
      err_line(sprintf("Init(%s): %s", profile, status_detail(e)))
      NULL
    })
  if (is.null(pipe)) {
    return(NULL)
  }
  blob <- tryCatch(libitb3r::pipeline_save(pipe),
    error = function(e) {
      err_line(sprintf("Save(%s): %s", profile, status_detail(e)))
      libitb3r::pipeline_free(pipe)
      NULL
    })
  if (is.null(blob)) {
    return(NULL)
  }
  if (cfg$blob_mode == 2) {
    # The sizing mode is not an Opts knob: the Init blob is edited and
    # the pipeline reopened from it, so the retained blob (the one
    # blob-cycle reopens from) carries the edited mode.
    edited <- edit_inner_blob_mode(blob, 2L)
    if (is.null(edited)) {
      err_line("rewrite blob mode: inner blob mode field not found")
      libitb3r::pipeline_free(pipe)
      return(NULL)
    }
    libitb3r::pipeline_free(pipe)
    pipe <- tryCatch(libitb3r::pipeline_load(edited),
      error = function(e) {
        err_line(sprintf("reload Mode 2 blob: %s", status_detail(e)))
        NULL
      })
    if (is.null(pipe)) {
      return(NULL)
    }
    blob <- edited
  }
  log_pipeline_initialised(profile, blob)
  list(pipe = pipe, blob = blob)
}

# ------------------------------------------------------------------ #
# Run                                                                 #
# ------------------------------------------------------------------ #

run <- function(argv) {
  parsed <- parse_flags(argv)
  if (parsed$rc == 1L) {
    return(0L)
  }
  if (parsed$rc != 0L) {
    return(2L)
  }
  cfg <- parsed$cfg
  r <- new_run(cfg)

  # Runtime shaping. A long run under allocation churn grows the Go
  # heap inside the shared library without bound unless a soft limit
  # paces the collector, so a limit is always in force: an explicit
  # --memlimit is set as given, and auto caps the heap only when the
  # runtime reports no limit at all (a limit already installed from the
  # environment is left standing). The GC percentage and GOMAXPROCS are
  # set only when their flag is non-zero — a zero flag skips the setter
  # rather than calling it with zero, because zero is a real value to
  # the GC-percent setter, and a call would clobber whatever the
  # environment installed. All of it lands before any Pipeline exists
  # so the baselines are taken under the shaped runtime, in the order
  # heap limit, GC percent, GOMAXPROCS.
  if (cfg$memlimit_auto) {
    if (libitb3r::set_memory_limit(-1) == INT64_MAX) {
      libitb3r::set_memory_limit(cfg$memlimit)
    }
  } else {
    libitb3r::set_memory_limit(cfg$memlimit)
  }
  cfg$memlimit <- libitb3r::set_memory_limit(-1)
  if (cfg$gogc > 0) {
    libitb3r::set_gc_percent(cfg$gogc)
  }
  if (cfg$gomaxprocs > 0) {
    libitb3r::set_gomaxprocs(cfg$gomaxprocs)
  }

  log_line(sprintf(
    paste0("start: duration=%s iterations=%.0f goroutines=%.0f workers=%.0f ",
      "concurrency=%s shape=%s hash=%s mac=%s payload=%s memlimit=%s ",
      "parallax=%s wrapper=%s"),
    human_duration(cfg$duration_ns), cfg$iterations, cfg$workers_requested,
    cfg$workers, CONCURRENCY, shape_name(cfg$shape), cfg$hash, cfg$mac,
    human_bytes(cfg$payload), human_bytes(cfg$memlimit),
    on_off(cfg$parallax), on_off(cfg$wrapper)))
  log_line(paste0(sprintf(
    paste0('overrides: profile="%s" key-bits=%.0f nonce-bits=%.0f ',
      "chunk-size=%s barrier-fill=%.0f gomaxprocs=%.0f rekey-every=%.0f ",
      "blob-cycle-every=%.0f payload-mode=%s seed=%.0f json-output=%s"),
    cfg$profile, cfg$key_bits, cfg$nonce_bits, human_bytes(cfg$chunk_size),
    cfg$barrier_fill, cfg$gomaxprocs, cfg$rekey_every, cfg$blob_cycle_every,
    payload_mode_name(cfg$payload_mode), cfg$seed,
    if (cfg$json_output) "true" else "false"),
    if (cfg$blob_mode != 1) sprintf(" blob-mode=%.0f", cfg$blob_mode) else "",
    if (nzchar(cfg$drbg)) paste0(" drbg=", cfg$drbg) else ""))
  log_line(sprintf("policy: microbatch-tiers=%s hashpool-starters=%s",
    policy_label("ITB_MICROBATCH_TIERS"),
    policy_label("ITB_HASHPOOL_STARTERS")))

  # Pipeline construction — one handle per exercised shape. stream and
  # stream_one_shot share the streaming handle.
  r$stream_profile <- if (nzchar(cfg$profile)) cfg$profile else DEFAULT_STREAM_PROFILE
  r$msg_profile <- if (nzchar(cfg$profile)) cfg$profile else DEFAULT_MESSAGE_PROFILE
  if (cfg$shape %in% c(SHAPE_STREAM, SHAPE_STREAM_ONE_SHOT, SHAPE_BOTH)) {
    built <- build_pipeline(cfg, r$stream_profile)
    if (is.null(built)) {
      return(1L)
    }
    r$stream_pipe <- built$pipe
    r$stream_blob <- built$blob
  }
  if (cfg$shape %in% c(SHAPE_MESSAGE, SHAPE_BOTH)) {
    built <- build_pipeline(cfg, r$msg_profile)
    if (is.null(built)) {
      return(1L)
    }
    r$msg_pipe <- built$pipe
    r$msg_blob <- built$blob
  }

  # Allocation posture. The per-worker plaintext is built once and held
  # for the whole run (rotating mode replaces it per iteration); the
  # wire and round-trip buffers are the raw vectors the binding returns
  # per call and the collector reclaims them when the iteration drops
  # them, and the pump loop accumulates its slices into one joined
  # buffer per direction. Under the default fixed CSPRNG mode every
  # worker's buffer is distinct, so cross-worker data crossover is
  # detectable; pattern modes trade that property for content
  # edge-case coverage.
  for (i in seq_len(cfg$workers)) {
    w <- new_worker(i - 1L, r)
    w$payload_mode <- cfg$payload_mode
    w$seeded <- cfg$seed != 0
    if (w$seeded) {
      set.seed(seed_worker(cfg$seed, w$id))
    }
    buf <- tryCatch(fill_payload(cfg$payload_mode, w$seeded, cfg$payload),
      error = function(e) NULL)
    if (is.null(buf)) {
      err_line("payload alloc: out of memory")
      return(1L)
    }
    w$plaintext <- buf
    r$workers[[i]] <- w
  }

  r$pool_warmup <- pool_snapshot()
  r$pool_steady <- r$pool_warmup
  if (length(r$pool_warmup) == 0L) {
    err_line("pool snapshot alloc failed")
    return(1L)
  }

  # Warmup barrier. The worker runs one iteration before the clock
  # starts, so the first-call costs (pool warm-up, lazy kernel
  # dispatch, page faults on the payload buffer) fall outside the
  # measured window, and the RSS and pool baselines taken here describe
  # a process that has already run the whole cipher path once. With one
  # worker the barrier is that worker's own first iteration; the
  # rendezvous the shared-handle bindings need has no second party to
  # wait for.
  warmup_start <- now_ns()
  warmup_ok <- warmup_worker(r$workers[[1L]])
  rss <- read_rss()
  r$rss_warmup <- rss[["current"]]
  r$rss_peak <- rss[["peak"]]
  r$pool_warmup <- pool_snapshot()
  warmup_ns <- now_ns() - warmup_start
  log_line(sprintf("warmup: %.0f workers x 1 iter completed in %s (baseline rss=%s)",
    cfg$workers, human_duration((warmup_ns + 5e7) %/% 1e8 * 1e8),
    human_bytes(r$rss_warmup)))

  r$start_ns <- now_ns()
  r$finish_ns <- r$start_ns
  if (isTRUE(warmup_ok)) {
    # Graceful stop. A stop request interrupts nothing mid-call: the
    # in-flight encrypt / decrypt / compare completes, the worker
    # returns, and the partial summary prints with the verdict the
    # completed iterations earned. Each iteration therefore runs with
    # interrupts suspended, so a Ctrl-C arriving inside one is held
    # until the iteration has finished and is then caught here, where
    # it becomes the stop request the loop checks.
    #
    # R-specific. SIGINT is the only signal base R surfaces to the
    # script, as an interrupt condition; there is no entry with which
    # to install a SIGTERM handler, so a terminate signal ends the
    # process where it stands and no summary is printed.
    tryCatch(run_worker(r$workers[[1L]]),
      interrupt = function(i) {
        r$stop <- TRUE
      })
  }
  r$finish_ns <- now_ns()

  elapsed_ns <- r$finish_ns - r$start_ns
  rss <- read_rss()
  r$rss_final <- rss[["current"]]
  r$rss_peak <- max(r$rss_peak, rss[["peak"]])
  r$pool_steady <- pool_snapshot()

  if (nzchar(cfg$memprofile)) {
    res <- tryCatch(
      {
        libitb3r::write_heap_profile(cfg$memprofile)
        TRUE
      },
      error = function(e) e)
    if (isTRUE(res)) {
      log_line(paste0("memprofile: heap profile written to ", cfg$memprofile))
    } else {
      err_line(paste0("memprofile: ", status_message(res)))
    }
  }

  code <- final_summary(r, elapsed_ns)

  if (!is.null(r$stream_pipe)) {
    libitb3r::pipeline_free(r$stream_pipe)
  }
  if (!is.null(r$msg_pipe)) {
    libitb3r::pipeline_free(r$msg_pipe)
  }
  code
}

quit(save = "no", status = run(commandArgs(trailingOnly = TRUE)),
  runLast = FALSE)
