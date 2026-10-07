# Size and duration parsing, the monotonic clock, and the human
# renderings of sizes, rates and durations. Every rendering here is
# part of the output contract shared with the Go harness and the other
# bindings' loop utilities, so the formats are fixed to the character,
# not to taste.
#
# R-specific. R has no 64-bit integer type and its integer vectors are
# 32-bit, which every byte count and nanosecond figure here outgrows.
# All of them are doubles, exact to 2^53 — nine petabytes of payload or
# a hundred days of nanoseconds — and every rendering goes through
# sprintf with an explicit conversion, never through R's own default
# numeric formatting, which would reach for exponent notation.

# Byte-size suffixes, longest first so "KIB" is matched before "K" and
# "B" never swallows the tail of another suffix. Every multiple is
# binary.
SIZE_SUFFIXES <- list(
  list("KIB", 1024), list("KB", 1024), list("K", 1024),
  list("MIB", 1048576), list("MB", 1048576), list("M", 1048576),
  list("GIB", 1073741824), list("GB", 1073741824), list("G", 1073741824),
  list("B", 1)
)

# Duration units in the order the grammar probes them, so "ms" is taken
# before "m" and "s".
DURATION_UNITS <- list(
  list("ns", 1), list("us", 1e3), list("ms", 1e6),
  list("s", 1e9), list("m", 60e9), list("h", 3600e9)
)

INT64_MAX <- 9223372036854775807

# Parses a human byte-size string ("16MB", "1MiB", "512K",
# "1073741824") into a byte count. Every suffix is a binary multiple:
# K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
# bytes; matching is case-insensitive and surrounding whitespace is
# trimmed. Returns NULL on a malformed or negative value.
parse_size <- function(s) {
  upper <- toupper(trimws(s))
  if (!nzchar(upper)) {
    return(NULL)
  }
  mult <- 1
  digits <- upper
  for (row in SIZE_SUFFIXES) {
    suffix <- row[[1]]
    if (nchar(upper) >= nchar(suffix) &&
      substring(upper, nchar(upper) - nchar(suffix) + 1) == suffix) {
      mult <- row[[2]]
      digits <- substring(upper, 1, nchar(upper) - nchar(suffix))
      break
    }
  }
  digits <- sub("\\s+$", "", digits)
  if (!nzchar(digits) || grepl("[^0-9]", digits)) {
    return(NULL)
  }
  n <- as.numeric(digits)
  if (!is.finite(n) || n > INT64_MAX) {
    return(NULL)
  }
  if (mult > 1 && n > INT64_MAX / mult) {
    return(NULL)
  }
  n * mult
}

# Parses the Go duration grammar — a sequence of decimal numbers each
# followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
# "1h30m", "1.5s" — into nanoseconds. Returns NULL on a malformed
# string.
parse_duration <- function(s) {
  if (is.null(s) || !nzchar(s)) {
    return(NULL)
  }
  total <- 0
  pos <- 1
  n <- nchar(s)
  while (pos <= n) {
    rest <- substring(s, pos)
    digits <- regmatches(rest, regexpr("^[0-9.]+", rest))
    if (length(digits) == 0L || !nzchar(digits)) {
      return(NULL)
    }
    value <- suppressWarnings(as.numeric(digits))
    if (is.na(value) || value < 0) {
      return(NULL)
    }
    pos <- pos + nchar(digits)
    mult <- 0
    for (row in DURATION_UNITS) {
      unit <- row[[1]]
      if (substring(s, pos, pos + nchar(unit) - 1) == unit &&
        !grepl("[A-Za-z]", substring(s, pos + nchar(unit), pos + nchar(unit)))) {
        mult <- row[[2]]
        pos <- pos + nchar(unit)
        break
      }
    }
    if (mult == 0) {
      return(NULL)
    }
    total <- total + value * mult
  }
  if (total > 9.2e18) {
    return(NULL)
  }
  floor(total)
}

# The monotonic clock's origin, taken once when this unit is sourced.
# R-specific. itb_now() hands back CLOCK_MONOTONIC as a double of
# seconds, and CLOCK_MONOTONIC counts from boot, so scaling it to
# nanoseconds directly would spend the mantissa on the host's uptime.
# Every reading is taken relative to this origin instead, which keeps
# the whole of the double's precision on the run itself.
CLOCK_ORIGIN <- libitb3r::itb_now()

# Monotonic wall clock in nanoseconds, counted from process start.
now_ns <- function() {
  floor((libitb3r::itb_now() - CLOCK_ORIGIN) * 1e9)
}

# Renders a byte count with a binary-unit suffix: "1.0GiB", "16.0MiB",
# "4.0KiB", "512B".
human_bytes <- function(n) {
  if (n >= 1073741824) {
    return(sprintf("%.1fGiB", n / 1073741824))
  }
  if (n >= 1048576) {
    return(sprintf("%.1fMiB", n / 1048576))
  }
  if (n >= 1024) {
    return(sprintf("%.1fKiB", n / 1024))
  }
  sprintf("%.0fB", n)
}

# Renders a possibly-negative byte delta with an explicit sign.
human_bytes_signed <- function(n) {
  if (n < 0) {
    return(paste0("-", human_bytes(-n)))
  }
  paste0("+", human_bytes(n))
}

# Binary MiB per second over a nanosecond window; 0 when the window is
# unmeasured.
mb_per_sec <- function(byte_count, ns) {
  if (ns <= 0) {
    return(0)
  }
  byte_count / 1048576 / (ns / 1e9)
}

# Renders a throughput as "123.4MB/s" (binary MiB per second) or "n/a"
# for an unmeasured window.
human_rate <- function(byte_count, ns) {
  if (ns <= 0) {
    return("n/a")
  }
  sprintf("%.1fMB/s", mb_per_sec(byte_count, ns))
}

# The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
# with trailing zeros removed; empty for zero.
duration_fraction <- function(frac_ns) {
  if (frac_ns == 0) {
    return("")
  }
  paste0(".", sub("0+$", "", sprintf("%09.0f", frac_ns)))
}

# Renders a duration the way Go's time.Duration prints: below one
# second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
# where the hour part appears when non-zero, the minute part when the
# hour part appears or the minutes are non-zero, and the seconds carry
# their fraction with trailing zeros removed ("5s", "5.003s", "1m0s",
# "1m5.25s", "1h0m0s"). The caller rounds first.
human_duration <- function(ns) {
  ns <- abs(ns)
  if (ns == 0) {
    return("0s")
  }
  if (ns < 1e9) {
    # Scale the sub-millisecond remainder to nine digits so the
    # fraction renderer sees the same shape it does for seconds.
    return(sprintf("%.0f%sms", ns %/% 1e6, duration_fraction((ns %% 1e6) * 1000)))
  }
  hours <- ns %/% 3.6e12
  rem <- ns %% 3.6e12
  minutes <- rem %/% 6e10
  rem <- rem %% 6e10
  seconds <- rem %/% 1e9
  frac <- rem %% 1e9
  out <- if (hours > 0) sprintf("%.0fh", hours) else ""
  if (hours > 0 || minutes > 0) {
    out <- paste0(out, sprintf("%.0fm", minutes))
  }
  sprintf("%s%.0f%ss", out, seconds, duration_fraction(frac))
}
