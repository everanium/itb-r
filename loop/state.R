# Shared declarations of the loop stress harness: the cipher-surface
# selectors, the concurrency mode this binding runs, the resolved
# configuration and per-worker state constructors, and the output
# helpers every unit writes through.
#
# R-specific. R's values are copied on modification, so a counter a
# worker unit bumps in a list would not be visible to the unit that
# reads it; every piece of state a second unit both reads and writes is
# therefore an environment. A declarations unit holding what both sides
# need is the same answer the C reference reaches with its header.

# Cipher surfaces the --shape flag selects.
SHAPE_STREAM <- 0L          # session pump: begin / write / read / end
SHAPE_MESSAGE <- 1L         # Single Message: one whole-buffer call
SHAPE_STREAM_ONE_SHOT <- 2L # stream surface, one whole-buffer call
SHAPE_BOTH <- 3L            # all three, rotating by iteration number

SHAPE_NAMES <- c("stream", "message", "stream_one_shot", "both")

# --goroutines ceiling; the harness targets modest hosts and each
# worker pins payload-sized buffers for the whole run.
MAX_WORKERS <- 10L

# Concurrency mode. This binding runs single: R evaluates on one thread
# and its C API is not re-entrant from another, so no second execution
# unit can be inside a .Call at the same time — there is no threading
# entry in base R to try it with, and the parallel package answers the
# question by forking whole processes, which share no Pipeline handle.
# The single-threaded core is therefore the whole of it, and
# --goroutines above 1 is clamped to 1 rather than silently pretending
# to concurrency.
CONCURRENCY <- "single"

# Largest slice fed to a stream session per write; the drain after
# every write uses the same bound.
PUMP_SLICE <- 1048576

shape_name <- function(shape) {
  SHAPE_NAMES[shape + 1L]
}

parse_shape <- function(s) {
  i <- match(s, SHAPE_NAMES)
  if (is.na(i)) {
    return(NULL)
  }
  as.integer(i - 1L)
}

# A fresh resolved command line, every field at its zero default.
new_config <- function() {
  cfg <- new.env(parent = emptyenv())
  cfg$duration_ns <- 0      # run duration; ignored when iterations > 0
  cfg$iterations <- 0       # per-worker count incl. warmup; 0 = duration-based
  cfg$workers_requested <- 0 # the --goroutines value as given
  cfg$workers <- 0          # the effective worker count
  cfg$shape <- SHAPE_STREAM
  cfg$hash <- ""
  cfg$mac <- ""
  cfg$payload <- 0          # bytes per iteration
  cfg$memlimit <- 0         # resolved bytes; the effective limit once shaped
  cfg$memlimit_auto <- FALSE # --memlimit auto: cap only when the runtime has none
  cfg$gogc <- 0             # 0 = leave the runtime default
  cfg$parallax <- TRUE
  cfg$wrapper <- TRUE

  cfg$profile <- ""         # empty = shape-based profile pair
  cfg$key_bits <- 0         # 0 = profile default
  cfg$nonce_bits <- 0       # 0 = profile default
  cfg$blob_mode <- 1        # container floor sizing mode: 1 (per-region, default) | 2 (per-container)
  cfg$chunk_size <- 0       # 0 = profile default
  cfg$barrier_fill <- 0     # 0 = profile default
  cfg$drbg <- ""            # DRBG fill primitive; "" = profile default (auto tier)
  cfg$gomaxprocs <- 0       # 0 = inherit from the environment
  cfg$rekey_every <- 0      # per-worker iterations between rotations; 0 = never
  cfg$blob_cycle_every <- 0 # per-worker iterations between reopens; 0 = never
  cfg$payload_mode <- PAYLOAD_FIXED
  cfg$seed <- 0             # 0 = OS CSPRNG plaintexts
  cfg$json_output <- FALSE
  cfg$memprofile <- ""      # empty = none
  cfg
}

# One worker's private state: its plaintext, its counters, and the
# error it stopped on.
new_worker <- function(id, run) {
  w <- new.env(parent = emptyenv())
  w$id <- id
  w$run <- run

  w$plaintext <- raw(0)
  w$payload_mode <- PAYLOAD_FIXED
  w$seeded <- FALSE

  # Counters read by the summary after the worker has returned.
  w$iters <- 0
  w$bytes_enc <- 0
  w$bytes_dec <- 0
  w$nanos_enc <- 0
  w$nanos_dec <- 0

  w$failed <- FALSE
  w$error <- ""
  w
}

# The state the run shares: the Pipeline handles, the retained blobs,
# the stop request, and the baselines the summary reads.
new_run <- function(cfg) {
  r <- new.env(parent = emptyenv())
  r$cfg <- cfg

  r$stream_pipe <- NULL # NULL unless the shape uses it
  r$msg_pipe <- NULL    # NULL unless the shape uses it
  r$stream_profile <- ""
  r$msg_profile <- ""

  # Handle mutation. The blob Init handed out, replaced by every rekey;
  # the input of the next blob reopen.
  r$stream_blob <- raw(0)
  r$msg_blob <- raw(0)

  r$rekeys <- 0
  r$blob_cycles <- 0

  r$workers <- list()

  # Set by the duration deadline, by an interrupt, or by a failing
  # worker; checked before every iteration.
  r$stop <- FALSE

  r$start_ns <- 0
  r$finish_ns <- 0

  # Baselines taken after the warmup barrier and at shutdown.
  r$rss_warmup <- 0
  r$rss_peak <- 0
  r$rss_final <- 0
  r$pool_warmup <- numeric(0)
  r$pool_steady <- numeric(0)
  r
}

# A consumer that stops reading ends the run. The process leaves with
# status 141 and prints nothing — the reference behaviour, and what
# anyone piping into head or less expects.
#
# R-specific. R sets SIGPIPE to ignore before any user code runs and
# surfaces the failed write as an R error ("ignoring SIGPIPE signal"),
# which the default top-level handler then prints to stderr before
# leaving with status 1. Base R exposes no way to put the default
# disposition back, so the failure is caught at the one place that can
# see it — the write itself — and the process leaves with the status
# the signal would have produced, having printed nothing.
die_on_closed_consumer <- function() {
  quit(save = "no", status = 141, runLast = FALSE)
}

emit <- function(con, text) {
  tryCatch(
    {
      cat(text, file = con)
      flush(con)
    },
    error = function(e) die_on_closed_consumer(),
    warning = function(w) die_on_closed_consumer()
  )
}

# Prints one prefixed status line to stdout.
#
# The line is assembled with its newline and handed over in a single
# write, so nothing another part of the run prints can land between a
# text and the newline that terminates it.
log_line <- function(text) {
  emit(stdout(), paste0("[loop] ", text, "\n"))
}

# Prints one prefixed error line to stderr.
err_line <- function(text) {
  emit(stderr(), paste0("loop: ", text, "\n"))
}

on_off <- function(b) {
  if (isTRUE(b)) "on" else "off"
}

# Renders an encoder policy env value for the summary: the raw string
# when set, "default" when the shipped ladder applies.
policy_label <- function(name) {
  env <- Sys.getenv(name, unset = NA_character_)
  if (is.na(env)) {
    return("default")
  }
  env <- sub("^[ \t]+", "", env)
  if (nzchar(env)) env else "default"
}

# The failure detail a log line carries: the numeric status the
# binding's own surface exposes and the finished sentence the library
# left behind. Nothing is composed here — the wording arrives whole
# from the failing call.
status_detail <- function(e) {
  if (inherits(e, "itb_error")) {
    return(sprintf("status %d: %s", e$status, e$detail))
  }
  conditionMessage(e)
}

# The bare diagnostic sentence, without the numeric status: what the
# lines that name no code carry.
status_message <- function(e) {
  if (inherits(e, "itb_error")) {
    return(e$detail)
  }
  conditionMessage(e)
}

# Records the worker's error text (first error wins) and requests a
# stop of the whole run.
worker_fail <- function(w, text) {
  if (!w$failed) {
    w$error <- text
    w$failed <- TRUE
  }
  w$run$stop <- TRUE
  invisible(NULL)
}
