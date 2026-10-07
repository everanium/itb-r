# The maintenance operations that mutate a live Pipeline handle between
# iterations: master rotation (--rekey-every) and blob reopen
# (--blob-cycle-every).

# Byte length of each fresh master drawn for a rotation. Matches the
# size Init auto-generates for both the parallax and the wrapper
# master.
REKEY_MASTER_SIZE <- 32L

# Master rotation. Rotates the parallax + wrapper masters on every
# active Pipeline and retains the refreshed blob for subsequent blob
# reopens. Masters are drawn fresh from the OS CSPRNG on every rotation
# regardless of --seed (master rotation is pipeline keying, not
# plaintext content); a disabled layer passes no bytes, which Rekey
# ignores. The eight inner seeds and the MAC key are untouched by
# design — Rekey targets only the two outer-layer master secrets.
rekey_pipes <- function(w, it) {
  r <- w$run
  perm <- if (r$cfg$parallax) fill_random(REKEY_MASTER_SIZE) else raw(0)
  wrap <- if (r$cfg$wrapper) fill_random(REKEY_MASTER_SIZE) else raw(0)

  # Handle mutation. Rekey rewrites the outer-layer keying of a live
  # handle in place. This binding runs single, so no cipher call can be
  # in flight while it happens and no lock is needed to keep one clear
  # of it; the shared-handle bindings take a write lock here, which is
  # where one would stand.
  if (!is.null(r$stream_pipe)) {
    blob <- tryCatch(
      libitb3r::pipeline_rekey(r$stream_pipe, perm, wrap),
      error = function(e) {
        worker_fail(w, sprintf("g%d iter %.0f: Rekey(%s): %s",
          w$id, it, r$stream_profile, status_detail(e)))
        NULL
      }
    )
    if (is.null(blob)) {
      return(FALSE)
    }
    r$stream_blob <- blob
  }
  if (!is.null(r$msg_pipe)) {
    blob <- tryCatch(
      libitb3r::pipeline_rekey(r$msg_pipe, perm, wrap),
      error = function(e) {
        worker_fail(w, sprintf("g%d iter %.0f: Rekey(%s): %s",
          w$id, it, r$msg_profile, status_detail(e)))
        NULL
      }
    )
    if (is.null(blob)) {
      return(FALSE)
    }
    r$msg_blob <- blob
  }
  r$rekeys <- r$rekeys + 1
  log_line(sprintf(
    "rekey: g%d iter %.0f rotated parallax + wrapper masters (rekey #%.0f)",
    w$id, it, r$rekeys))
  TRUE
}

# Blob reopen. Reopens every active Pipeline from its retained blob: a
# fresh handle is loaded from the blob, the running handle is freed,
# and the fresh one is swapped in, so every later iteration round-trips
# through seeds and masters that survived a blob crossing. The input is
# the blob Init or the latest Rekey handed out, not a fresh Save: that
# is what a receiver holds, and reopening from it proves the handed-out
# bytes rather than the live state. The blob carries the Pipeline's
# full shape, so no override reaches the reopen. On a Load failure the
# running handle stays and the failure aborts the run.
blob_cycle_pipes <- function(w, it) {
  r <- w$run
  if (!is.null(r$stream_pipe)) {
    fresh <- tryCatch(
      libitb3r::pipeline_load(r$stream_blob),
      error = function(e) {
        worker_fail(w, sprintf("g%d iter %.0f: Load(%s): %s",
          w$id, it, r$stream_profile, status_detail(e)))
        NULL
      }
    )
    if (is.null(fresh)) {
      return(FALSE)
    }
    libitb3r::pipeline_free(r$stream_pipe)
    r$stream_pipe <- fresh
  }
  if (!is.null(r$msg_pipe)) {
    fresh <- tryCatch(
      libitb3r::pipeline_load(r$msg_blob),
      error = function(e) {
        worker_fail(w, sprintf("g%d iter %.0f: Load(%s): %s",
          w$id, it, r$msg_profile, status_detail(e)))
        NULL
      }
    )
    if (is.null(fresh)) {
      return(FALSE)
    }
    libitb3r::pipeline_free(r$msg_pipe)
    r$msg_pipe <- fresh
  }
  r$blob_cycles <- r$blob_cycles + 1
  log_line(sprintf(
    "blob-cycle: g%d iter %.0f reopened from session blob (cycle #%.0f)",
    w$id, it, r$blob_cycles))
  TRUE
}

# Runs the periodic Pipeline-mutating operations after a completed
# iteration: master rotation (--rekey-every) and blob reopen
# (--blob-cycle-every). Both intervals count per-worker iterations; the
# warmup iteration (iter 0) never triggers because the worker loop
# calls this for iter >= 1 only. Returns FALSE after recording a worker
# error.
worker_maintenance <- function(w, it) {
  cfg <- w$run$cfg
  if (cfg$rekey_every > 0 && it %% cfg$rekey_every == 0) {
    if (!rekey_pipes(w, it)) {
      return(FALSE)
    }
  }
  if (cfg$blob_cycle_every > 0 && it %% cfg$blob_cycle_every == 0) {
    if (!blob_cycle_pipes(w, it)) {
      return(FALSE)
    }
  }
  TRUE
}
