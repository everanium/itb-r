# Plaintext content: the payload modes, the seeded per-worker
# generator, and the buffer fill from the operating-system CSPRNG.

# Payload mode selector values for the --payload-mode flag.
#
#   - fixed: one CSPRNG-generated buffer per worker, held unchanged for
#     the whole run (the default).
#   - rotating: the buffer is regenerated before every iteration, so no
#     two encrypt calls see the same plaintext.
#   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
#     all 0xFF) probing minimum-entropy plaintext handling.
#   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
#     structured text.
PAYLOAD_FIXED <- 0L
PAYLOAD_ROTATING <- 1L
PAYLOAD_PATTERN_ZERO <- 2L
PAYLOAD_PATTERN_FF <- 3L
PAYLOAD_PATTERN_ASCII <- 4L

PAYLOAD_NAMES <- c(
  "fixed", "rotating", "pattern-zero", "pattern-ff", "pattern-ascii"
)

payload_mode_name <- function(mode) {
  PAYLOAD_NAMES[mode + 1L]
}

parse_payload_mode <- function(s) {
  i <- match(s, PAYLOAD_NAMES)
  if (is.na(i)) {
    return(NULL)
  }
  as.integer(i - 1L)
}

# Seeded plaintext. The seed makes plaintext content reproducible so a
# failing iteration can be replayed with the same bytes; it governs
# nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
# so a seeded run is a reproduction aid and never a security test. Each
# worker's stream is domain-separated by its id so seeded workers still
# hold pairwise-distinct buffers under the fixed and rotating modes.
#
# R-specific. The generator the rest of the fleet uses is splitmix64,
# whose three steps are 64-bit wrapping multiplies. R has no 64-bit
# integer type at all — its integers are 32-bit and its numerics are
# doubles with a 53-bit mantissa — so the multiplies cannot be carried
# out, and an emulation over 32-bit halves would be a different
# generator wearing the name. R's own Mersenne-Twister stream is used
# instead: seeded once per worker from the seed and the worker id, then
# drawn from without reseeding, so the run reproduces byte for byte
# under the same seed and two workers never share a stream. What the
# item asks for — determinism within this implementation and
# separation between workers — holds; what is given up is plaintext
# equality with the other bindings, which the contract does not ask
# for.
seed_worker <- function(seed, worker_id) {
  # set.seed takes a 32-bit signed integer, so a wider --seed is folded
  # into that range. The fold is deterministic, which is what the seed
  # is for.
  base <- (seed + worker_id + 1) %% 2147483647
  as.integer(base)
}

# The operating-system CSPRNG, opened once and held for the run.
#
# R-specific. R's own RNG is a userspace Mersenne Twister and is never
# used for this; the bytes come from the kernel device directly.
URANDOM <- local({
  con <- NULL
  function() {
    if (is.null(con)) {
      con <<- file("/dev/urandom", "rb", raw = TRUE)
    }
    con
  }
})

# Draws n bytes from the operating-system CSPRNG.
fill_random <- function(n) {
  parts <- list()
  got <- 0
  while (got < n) {
    piece <- readBin(URANDOM(), "raw", n = n - got)
    if (length(piece) == 0L) {
      stop("short read from /dev/urandom", call. = FALSE)
    }
    parts[[length(parts) + 1L]] <- piece
    got <- got + length(piece)
  }
  if (length(parts) == 1L) {
    return(parts[[1L]])
  }
  unlist(parts, use.names = FALSE)
}

ASCII_RAMP <- as.raw(0x41 + (0:25))

# Builds one plaintext buffer according to the payload mode. The fixed
# and rotating modes draw from the seeded generator when the run is
# seeded and from the OS CSPRNG otherwise; the pattern modes are
# deterministic regardless of the seed.
fill_payload <- function(mode, seeded, n) {
  if (mode == PAYLOAD_FIXED || mode == PAYLOAD_ROTATING) {
    if (!seeded) {
      return(fill_random(n))
    }
    return(as.raw(sample.int(256L, n, replace = TRUE) - 1L))
  }
  if (mode == PAYLOAD_PATTERN_ZERO) {
    return(raw(n))
  }
  if (mode == PAYLOAD_PATTERN_FF) {
    return(rep(as.raw(255), n))
  }
  rep_len(ASCII_RAMP, n)
}
