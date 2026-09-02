# itb.R — public R API over the itb C shim (src/itb_r.c), which in
# turn proxies the libitb shared library's Triple Pipeline surface
# (ITB_Triple_*, cmd/cshared).
#
# The binding is a thin proxy: every hash-name / MAC-name /
# cipher-name / profile-name is an opaque string passed through to Go
# for validation; no ITB construction logic lives here. Byte buffers
# are raw vectors throughout (single character strings are accepted as
# plaintext inputs and converted via charToRaw).
#
# Objects are environment-backed (reference semantics) with S3 class
# attributes:
#
#   ITBPipeline         ptr (external pointer), blob (raw), profile
#   ITBStreamEncryptor  ptr, parent (the Pipeline object), ended
#   ITBStreamDecryptor  ptr, parent (the Pipeline object), ended
#
# The `parent` field is the session-parent-pin: an open stream session
# holds a reference to its Pipeline object so the R garbage collector
# cannot collect (and thereby finalize) the Pipeline while the session
# is live. The stream's external pointer additionally carries the
# Pipeline's external pointer in its protected slot, pinning at the C
# level as well.

ITB_R_VERSION <- "0.3.3"

# ---- internal helpers -------------------------------------------------

.as_bytes <- function(x, what) {
  if (is.raw(x)) {
    return(x)
  }
  if (is.character(x) && length(x) == 1L && !is.na(x)) {
    return(charToRaw(x))
  }
  stop(sprintf("itb: %s must be a raw vector or a single string", what))
}

.check_pipeline <- function(pipe) {
  if (!inherits(pipe, "ITBPipeline")) {
    stop("itb: expected an ITBPipeline object")
  }
  pipe
}

.check_stream <- function(stream) {
  if (!inherits(stream, "ITBStream")) {
    stop("itb: expected a stream session object")
  }
  stream
}

.new_stream <- function(pipe, encrypt) {
  .check_pipeline(pipe)
  s <- new.env(parent = emptyenv())
  s$ptr <- .Call(C_r_stream_begin, pipe$ptr, encrypt)
  s$parent <- pipe # session-parent-pin (R level)
  s$ended <- FALSE
  class(s) <- c(
    if (encrypt) "ITBStreamEncryptor" else "ITBStreamDecryptor",
    "ITBStream"
  )
  s
}

# ---- library-level functions ------------------------------------------

#' libitb library version string.
#' @export
version <- function() {
  .Call(C_r_version)
}

#' Shipped hash primitive roster in canonical registry order, as a
#' data.frame with `name` and `width` columns.
#' @export
hashes <- function() {
  h <- .Call(C_r_hashes)
  data.frame(name = h$name, width = h$width, stringsAsFactors = FALSE)
}

#' Built-in Triple profile names. The C ABI exposes no profile
#' enumeration; the returned vector mirrors the built-in profile
#' registry and does not include profiles added at runtime via
#' `register_profile`.
#' @export
profiles <- function() {
  .Call(C_r_profiles)
}

#' Registers a custom Triple profile from an opts string (see
#' `itb_opts`). Raises `itb_error` with status PROFILE_EXISTS when the
#' name is already registered.
#' @export
register_profile <- function(name, opts) {
  invisible(.Call(C_r_register_profile, name, opts))
}

#' Sets the Go runtime's soft memory limit in bytes; returns the
#' previous limit. Negative values query without changing.
#' @export
set_memory_limit <- function(n) {
  .Call(C_r_set_memory_limit, as.numeric(n))
}

#' Sets the Go runtime's GC percent; returns the previous percent.
#' Negative values query without changing.
#' @export
set_gc_percent <- function(n) {
  .Call(C_r_set_gc_percent, as.integer(n))
}

#' Monotonic wall-clock seconds (benchmark timing helper).
#' @export
itb_now <- function() {
  .Call(C_r_now)
}

# ---- opts builder ------------------------------------------------------

# Snake_case keys map onto the Go opts grammar; any key not in the map
# passes through unchanged (the raw escape hatch covering the
# register-profile grammar: mode, width, innerHashes, parallaxOn,
# wrapperOn, ...).
.OPTS_KEY_MAP <- c(
  nonce_bits = "nonceBits",
  key_bits = "keyBits",
  with_parallax = "withParallax",
  with_wrapper = "withWrapper",
  max_workers = "maxWorkers",
  barrier_fill = "barrierFill",
  chunk_size = "chunkSize",
  parallax_segment_size = "parallaxSegmentSize",
  mac_name = "macName",
  inner_hash = "innerHash",
  outer_cipher = "outerCipher",
  parallax_palette = "parallaxPalette",
  perm_master = "pm",
  wrap_master = "wm"
)

# Percent-encodes everything outside the URL-safe subset plus ','.
.opts_enc <- function(s) {
  chars <- strsplit(s, "", fixed = TRUE)[[1]]
  paste0(vapply(chars, function(c) {
    if (grepl("^[A-Za-z0-9._~,-]$", c)) {
      c
    } else {
      paste0(sprintf("%%%02X", as.integer(charToRaw(c))), collapse = "")
    }
  }, character(1)), collapse = "")
}

.opts_render <- function(v) {
  if (is.logical(v) && length(v) == 1L) {
    return(if (v) "true" else "false")
  }
  if (is.numeric(v) && length(v) == 1L) {
    return(sprintf("%d", as.integer(v)))
  }
  if (is.character(v)) {
    return(paste0(v, collapse = ","))
  }
  stop("itb_opts: unsupported value type: ", class(v)[1])
}

#' Builds the URL-query opts string consumed by `pipeline_create` /
#' `pipeline_open` / `register_profile` from named arguments (or a
#' single named list). No validation is performed here — every key and
#' value passes through to Go verbatim (percent-encoded); libitb
#' rejects unknown keys or bad values with a diagnostic surfaced
#' through the `itb_error` condition. Keys are emitted in sorted order
#' so the rendered string is deterministic.
#' @export
itb_opts <- function(...) {
  args <- list(...)
  if (length(args) == 1L && is.null(names(args)) && is.list(args[[1]])) {
    args <- args[[1]]
  }
  if (length(args) == 0L) {
    return("")
  }
  keys <- names(args)
  if (is.null(keys) || any(!nzchar(keys))) {
    stop("itb_opts: every argument must be named")
  }
  keys <- sort(keys)
  parts <- vapply(keys, function(k) {
    go_key <- if (k %in% names(.OPTS_KEY_MAP)) .OPTS_KEY_MAP[[k]] else k
    paste0(.opts_enc(go_key), "=", .opts_enc(.opts_render(args[[k]])))
  }, character(1))
  paste0(parts, collapse = "&")
}

# ---- hex codec (blob transport through shells / config files) ---------

#' Raw vector to lowercase hex string.
#' @export
to_hex <- function(x) {
  paste0(sprintf("%02x", as.integer(x)), collapse = "")
}

#' Hex string to raw vector.
#' @export
from_hex <- function(h) {
  if (!is.character(h) || length(h) != 1L) {
    stop("from_hex: expected a single string")
  }
  if (nchar(h) %% 2L != 0L) {
    stop("from_hex: odd-length hex string")
  }
  if (grepl("[^0-9a-fA-F]", h)) {
    stop("from_hex: non-hex character")
  }
  if (nchar(h) == 0L) {
    return(raw(0))
  }
  pairs <- substring(h, seq(1L, nchar(h), 2L), seq(2L, nchar(h), 2L))
  as.raw(strtoi(pairs, 16L))
}

# ---- Pipeline ----------------------------------------------------------

#' Creates a fresh Triple Pipeline for `profile` (fresh CSPRNG seeds).
#' When `blob` is supplied, delegates to `pipeline_open` instead. Opts
#' are a URL-query string (see `itb_opts`).
#' @export
pipeline_create <- function(profile, blob = NULL, opts = "") {
  if (!is.null(blob)) {
    return(pipeline_open(profile, blob, opts = opts))
  }
  r <- .Call(C_r_pipeline_create, profile, opts)
  p <- new.env(parent = emptyenv())
  p$ptr <- r$ptr
  p$blob <- r$blob
  p$profile <- profile
  class(p) <- "ITBPipeline"
  p
}

#' Opens a Triple Pipeline from an exported state blob (the receiving
#' side of a key exchange). `perm` / `wrap` optionally override the
#' parallax and wrapper masters (both raw vectors, both or neither).
#' @export
pipeline_open <- function(profile, blob, opts = "", perm = NULL, wrap = NULL) {
  blob <- .as_bytes(blob, "blob")
  if (!is.null(perm)) perm <- .as_bytes(perm, "perm master")
  if (!is.null(wrap)) wrap <- .as_bytes(wrap, "wrap master")
  p <- new.env(parent = emptyenv())
  p$ptr <- .Call(C_r_pipeline_open, profile, blob, opts, perm, wrap)
  p$blob <- blob
  p$profile <- profile
  class(p) <- "ITBPipeline"
  p
}

#' Single Message encrypt: one call producing a self-contained wire.
#' Returns a raw vector.
#' @export
pipeline_encrypt_message <- function(pipe, plaintext) {
  .check_pipeline(pipe)
  .Call(
    C_r_pipeline_encrypt_message, pipe$ptr,
    .as_bytes(plaintext, "plaintext")
  )
}

#' Single Message decrypt. Returns the plaintext as a raw vector.
#' @export
pipeline_decrypt_message <- function(pipe, wire) {
  .check_pipeline(pipe)
  .Call(C_r_pipeline_decrypt_message, pipe$ptr, .as_bytes(wire, "wire"))
}

#' Whole-buffer Streaming encrypt (the entire stream in one call).
#' @export
pipeline_encrypt_stream_one_shot <- function(pipe, plaintext) {
  .check_pipeline(pipe)
  .Call(
    C_r_pipeline_encrypt_stream_one_shot, pipe$ptr,
    .as_bytes(plaintext, "plaintext")
  )
}

#' Whole-buffer Streaming decrypt (the entire wire in one call).
#' @export
pipeline_decrypt_stream_one_shot <- function(pipe, wire) {
  .check_pipeline(pipe)
  .Call(
    C_r_pipeline_decrypt_stream_one_shot, pipe$ptr,
    .as_bytes(wire, "wire")
  )
}

#' The Pipeline's exported state blob (raw vector); transport it to the
#' receiving side and pass to `pipeline_open`.
#' @export
pipeline_blob <- function(pipe) {
  .check_pipeline(pipe)$blob
}

#' Rotates the parallax + wrapper masters (both raw vectors or single
#' strings) and refreshes the stored blob. Returns the new blob
#' invisibly.
#' @export
pipeline_rekey <- function(pipe, perm, wrap) {
  .check_pipeline(pipe)
  blob <- .Call(
    C_r_pipeline_rekey, pipe$ptr,
    .as_bytes(perm, "perm master"), .as_bytes(wrap, "wrap master")
  )
  pipe$blob <- blob
  invisible(blob)
}

#' Zeroes the key material and marks the Pipeline closed (idempotent);
#' subsequent cipher calls raise `itb_error` with status TRIPLE_CLOSED.
#' @export
pipeline_close <- function(pipe) {
  .check_pipeline(pipe)
  invisible(.Call(C_r_pipeline_close, pipe$ptr))
}

#' Releases the Go-side handle (closing and zeroing key material
#' first). Safe to call more than once; garbage collection covers
#' Pipelines that go out of scope without an explicit free.
#' @export
pipeline_free <- function(pipe) {
  .check_pipeline(pipe)
  invisible(.Call(C_r_pipeline_free, pipe$ptr))
}

# ---- stream sessions ---------------------------------------------------

#' Opens an incremental Streaming encrypt session on the Pipeline.
#' @export
stream_encryptor <- function(pipe) {
  .new_stream(pipe, TRUE)
}

#' Opens an incremental Streaming decrypt session on the Pipeline.
#' @export
stream_decryptor <- function(pipe) {
  .new_stream(pipe, FALSE)
}

#' Feeds bytes (raw vector or single string) into the session.
#' @export
stream_write <- function(stream, data) {
  .check_stream(stream)
  invisible(.Call(C_r_stream_write, stream$ptr, .as_bytes(data, "data")))
}

#' Signals end-of-input. Idempotent on the R side.
#' @export
stream_end <- function(stream) {
  .check_stream(stream)
  if (!stream$ended) {
    .Call(C_r_stream_end, stream$ptr)
    stream$ended <- TRUE
  }
  invisible(NULL)
}

#' Drains up to `max` produced bytes. Returns
#' `list(chunk = <raw>, finished = <logical>)`; partial drains are
#' normal and a read before `stream_end` never blocks.
#' @export
stream_read <- function(stream, max = 1048576L) {
  .check_stream(stream)
  .Call(C_r_stream_read, stream$ptr, as.integer(max))
}

#' Drains up to `length(buf)` produced bytes directly into `buf`,
#' which is written **in place** — pass a dedicated scratch raw vector
#' that is never shared with any other binding (in-place mutation
#' bypasses R's copy-on-write). Returns `integer(2)`:
#' `c(n, finished)` — `n` bytes were written into `buf[1:n]`, and
#' `finished` is `1L` once the final output byte has been drained.
#' Bytes past `n` are unspecified — the caller must not read them.
#' The allocation-free analogue of `stream_read` for drain loops.
#' @export
stream_read_into <- function(stream, buf) {
  .check_stream(stream)
  .Call(C_r_stream_read_into, stream$ptr, buf)
}

#' Feeds `data[(offset + 1):(offset + len)]` into the session straight
#' from the source vector's storage (`offset` is zero-based) — no
#' R-side slice copy, no index-vector materialisation. `data` is only
#' read; bytes outside the addressed window are never touched, and a
#' window escaping the vector (negative `offset` or `len`, or
#' `offset + len > length(data)`) raises an error before any byte is
#' fed. The allocation-free analogue of `stream_write` for chunked
#' feed loops over one large buffer.
#' @export
stream_write_slice <- function(stream, data, offset, len) {
  .check_stream(stream)
  invisible(.Call(
    C_r_stream_write_slice, stream$ptr, data,
    as.numeric(offset), as.numeric(len)
  ))
}

#' Calls `stream_end` (when not yet called) and returns every remaining
#' output byte as one raw vector.
#' @export
stream_drain_all <- function(stream) {
  .check_stream(stream)
  stream_end(stream)
  .Call(C_r_stream_drain_all, stream$ptr)
}

#' Cancels (if still running) and releases the session. Safe from any
#' state and more than once; garbage collection covers sessions that go
#' out of scope without an explicit free.
#' @export
stream_free <- function(stream) {
  .check_stream(stream)
  invisible(.Call(C_r_stream_free, stream$ptr))
}

#' Bounded-memory stream pump: moves bytes from `read_fn` through an
#' open session into `write_fn` — feed a piece, drain available output,
#' repeat; end-of-input + final drain on source EOF. `read_fn()`
#' returns a raw vector (empty or NULL at EOF); `write_fn(chunk)`
#' consumes produced bytes. The caller owns the session.
#' @export
pump <- function(stream, read_fn, write_fn) {
  .check_stream(stream)
  repeat {
    piece <- read_fn()
    if (is.null(piece) || length(piece) == 0L) {
      break
    }
    stream_write(stream, piece)
    repeat {
      r <- stream_read(stream)
      if (length(r$chunk) == 0L) {
        break
      }
      write_fn(r$chunk)
    }
  }
  stream_end(stream)
  repeat {
    r <- stream_read(stream)
    if (length(r$chunk) > 0L) {
      write_fn(r$chunk)
    }
    if (r$finished) {
      break
    }
  }
  invisible(NULL)
}

# ---- print methods -----------------------------------------------------

#' @export
print.ITBPipeline <- function(x, ...) {
  cat(sprintf(
    "<ITBPipeline profile=%s blob=%d bytes>\n",
    x$profile, length(x$blob)
  ))
  invisible(x)
}

#' @export
print.ITBStream <- function(x, ...) {
  cat(sprintf(
    "<%s profile=%s ended=%s>\n",
    class(x)[1], x$parent$profile, x$ended
  ))
  invisible(x)
}
