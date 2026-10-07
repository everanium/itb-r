# The worker: its body (one warmup iteration, the warmup barrier, the
# main loop), one iteration, the session pump loop the stream shape
# drives, and the round-trip comparison that decides between a worker
# error and a data mismatch.

# Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair and
# ITB drives the chunk loop internally; the C ABI has no reader /
# writer entry, so the caller drives it: open a session, feed slices of
# at most 1 MiB, drain whatever the session has produced after every
# write (a read before end never blocks), end, then drain until the
# session reports finished (after end, a read on an empty spool blocks
# until the terminal bytes arrive). The loop is written here rather
# than delegated to the binding's pump convenience so it stands in the
# utility, at the same place, in every language.
#
# R-specific. The slice is addressed through stream_write_slice, which
# feeds a window of the source vector without materialising it: R's
# ordinary subsetting would build a million-element index vector and a
# copy of the window for every write, which is payload-sized traffic
# the other bindings' slices do not carry.
pump <- function(pipe, encrypt, src) {
  session <- if (encrypt) {
    libitb3r::stream_encryptor(pipe)
  } else {
    libitb3r::stream_decryptor(pipe)
  }
  on.exit(libitb3r::stream_free(session), add = TRUE)
  parts <- list()
  off <- 0
  total <- length(src)
  while (off < total) {
    take <- min(PUMP_SLICE, total - off)
    libitb3r::stream_write_slice(session, src, off, take)
    off <- off + take
    repeat {
      got <- libitb3r::stream_read(session, PUMP_SLICE)
      if (length(got$chunk) == 0L) {
        break
      }
      parts[[length(parts) + 1L]] <- got$chunk
    }
  }
  libitb3r::stream_end(session)
  repeat {
    got <- libitb3r::stream_read(session, PUMP_SLICE)
    if (length(got$chunk) > 0L) {
      parts[[length(parts) + 1L]] <- got$chunk
    }
    if (isTRUE(got$finished)) {
      break
    }
  }
  if (length(parts) == 0L) {
    return(raw(0))
  }
  unlist(parts, use.names = FALSE)
}

# First offset at which a and b differ; the shorter length when one is
# a prefix of the other.
first_difference <- function(a, b) {
  n <- min(length(a), length(b))
  if (n > 0L) {
    diff <- which(a[seq_len(n)] != b[seq_len(n)])
    if (length(diff) > 0L) {
      return(diff[1L] - 1L)
    }
  }
  n
}

# Up to 16 bytes of buf from off (zero-based) as lowercase hex, or "-"
# when buf has no bytes there.
hex_window <- function(buf, off) {
  if (off >= length(buf)) {
    return("-")
  }
  last <- min(off + 16L, length(buf))
  paste(sprintf("%02x", as.integer(buf[(off + 1L):last])), collapse = "")
}

# Records a worker error for a failed cipher call.
cipher_fail <- function(w, it, shape, direction, e) {
  worker_fail(w, sprintf("g%d iter %.0f shape=%s: %s: %s",
    w$id, it, shape_name(shape), direction, status_detail(e)))
}

# One iteration. In order: refill the plaintext under rotating mode;
# take the read lock; pick the surface; encrypt (timed); decrypt
# (timed); compare the round-trip with the plaintext; bump the
# counters; release the lock. The whole round-trip is kept clear of
# handle-mutating maintenance (rekey, blob reopen), which runs after
# this returns, from the worker loop, so nothing lands between an
# encrypt and its matching decrypt. On this binding that separation
# needs no lock: the run is one thread, so the ordering is the only
# mechanism there is. Returns FALSE after recording the worker error.
iterate <- function(w, it) {
  r <- w$run

  if (w$payload_mode == PAYLOAD_ROTATING) {
    w$plaintext <- fill_payload(PAYLOAD_ROTATING, w$seeded, length(w$plaintext))
  }

  # Shape dispatch. message is one whole-buffer call on the Single
  # Message Pipeline; stream_one_shot is one whole-buffer call on the
  # streaming Pipeline (the C ABI's ITB_Triple_EncryptStream, which
  # routes to the same one-shot stream entry the Go harness calls
  # by name); stream opens a session on the same streaming Pipeline and
  # drives the chunk loop from here. Under both the three rotate by
  # iteration number so the session path and the whole-buffer path
  # alternate on one handle inside every worker — the cross-path
  # state-reuse hazard this harness exists to catch.
  shape <- r$cfg$shape
  if (shape == SHAPE_BOTH) {
    shape <- c(SHAPE_STREAM, SHAPE_MESSAGE, SHAPE_STREAM_ONE_SHOT)[it %% 3 + 1]
  }

  want <- w$plaintext
  if (shape == SHAPE_STREAM) {
    t0 <- now_ns()
    wire <- tryCatch(pump(r$stream_pipe, TRUE, want),
      error = function(e) {
        cipher_fail(w, it, shape, "encrypt", e)
        NULL
      })
    if (is.null(wire)) {
      return(FALSE)
    }
    w$nanos_enc <- w$nanos_enc + (now_ns() - t0)
    t0 <- now_ns()
    got <- tryCatch(pump(r$stream_pipe, FALSE, wire),
      error = function(e) {
        cipher_fail(w, it, shape, "decrypt", e)
        NULL
      })
    if (is.null(got)) {
      return(FALSE)
    }
    w$nanos_dec <- w$nanos_dec + (now_ns() - t0)
  } else {
    if (shape == SHAPE_MESSAGE) {
      pipe <- r$msg_pipe
      enc <- libitb3r::pipeline_encrypt_message
      dec <- libitb3r::pipeline_decrypt_message
    } else {
      pipe <- r$stream_pipe
      enc <- libitb3r::pipeline_encrypt_stream_one_shot
      dec <- libitb3r::pipeline_decrypt_stream_one_shot
    }
    t0 <- now_ns()
    wire <- tryCatch(enc(pipe, want),
      error = function(e) {
        cipher_fail(w, it, shape, "encrypt", e)
        NULL
      })
    if (is.null(wire)) {
      return(FALSE)
    }
    w$nanos_enc <- w$nanos_enc + (now_ns() - t0)
    t0 <- now_ns()
    got <- tryCatch(dec(pipe, wire),
      error = function(e) {
        cipher_fail(w, it, shape, "decrypt", e)
        NULL
      })
    if (is.null(got)) {
      return(FALSE)
    }
    w$nanos_dec <- w$nanos_dec + (now_ns() - t0)
  }

  # Failure model. A cipher call that returns a non-OK status is a
  # worker error: it is recorded, the run is asked to stop, and the
  # error is listed in the summary with the FAIL verdict. A round-trip
  # that returns OK with different bytes is a data mismatch: the
  # process terminates here, without summary, because the Pipeline
  # state that produced the wrong bytes is the evidence and nothing
  # that runs afterwards may touch it.
  if (!identical(got, want)) {
    off <- first_difference(want, got)
    emit(stderr(), sprintf(
      paste0("loop: DATA MISMATCH g%d iter %.0f shape=%s: want %.0f bytes, ",
        "got %.0f bytes, first difference at offset %.0f: want %s got %s\n"),
      w$id, it, shape_name(shape), length(want), length(got), off,
      hex_window(want, off), hex_window(got, off)))
    # R-specific. quit() is base R's only way out of a process, and it
    # runs the finalizers registered for exit before the process
    # leaves — which for this binding means the Pipeline handles are
    # released on the way. There is no immediate-termination entry to
    # reach for instead, so the state the mismatch produced does not
    # survive the exit here as it does in the languages that have one.
    # Nothing else runs: no summary is printed and no further cipher
    # call touches the handle.
    quit(save = "no", status = 3, runLast = FALSE)
  }

  w$iters <- w$iters + 1
  w$bytes_enc <- w$bytes_enc + length(want)
  w$bytes_dec <- w$bytes_dec + length(got)
  TRUE
}

# The worker body: one warmup iteration, then the main loop until a
# stop is requested, the duration deadline passes, or the fixed
# per-worker iteration budget (warmup included) is spent.
#
# Concurrency mode. This binding runs single: R evaluates on one thread
# and its C API is not re-entrant, so no second execution unit can be
# inside a .Call at the same time; base R carries no threading entry,
# and the parallel package answers the question by forking whole
# processes, which share no Pipeline handle. --goroutines is therefore
# accepted, clamped to 1, and reported next to the requested value, so
# a fleet reading the summary sees the mode rather than inferring it.
# The warmup barrier below degenerates to the single worker's own first
# iteration.
warmup_worker <- function(w) {
  tryCatch(iterate(w, 0),
    error = function(e) {
      worker_fail(w, sprintf("g%d iter 0: %s", w$id, conditionMessage(e)))
      FALSE
    })
}

# The main loop, entered after the warmup barrier has been passed and
# the baselines taken.
run_worker <- function(w) {
  r <- w$run
  cfg <- r$cfg
  it <- 1
  repeat {
    if (cfg$iterations > 0 && it >= cfg$iterations) {
      break
    }
    if (r$stop) {
      break
    }
    if (cfg$iterations == 0 && now_ns() - r$start_ns >= cfg$duration_ns) {
      break
    }
    # An iteration and the maintenance that follows it run with
    # interrupts suspended, so a Ctrl-C arriving inside either is held
    # until it has finished; the caller catches it at the loop's own
    # check point and turns it into the stop request.
    ok <- tryCatch(suspendInterrupts(iterate(w, it)),
      error = function(e) {
        worker_fail(w, sprintf("g%d iter %.0f: %s", w$id, it,
          conditionMessage(e)))
        FALSE
      })
    if (!isTRUE(ok)) {
      break
    }
    ok <- tryCatch(suspendInterrupts(worker_maintenance(w, it)),
      error = function(e) {
        worker_fail(w, sprintf("g%d iter %.0f: %s", w$id, it,
          conditionMessage(e)))
        FALSE
      })
    if (!isTRUE(ok)) {
      break
    }
    it <- it + 1
  }
  invisible(NULL)
}
