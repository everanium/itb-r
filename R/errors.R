# errors.R — condition class for the ITB R binding.
#
# Every libitb failure surfaces as a condition of class
# c("itb_error", "error", "condition") carrying three extra fields:
#
#   status  integer status code (see the `itb_status` constant list)
#   label   short human-readable status label
#   detail  the ITB_LastError diagnostic string ("" when absent)
#
# Callers branch on the status:
#
#   tryCatch(pipeline_create("no-such-profile"),
#            itb_error = function(e) stopifnot(e$status == itb_status$BAD_INPUT))

#' Named libitb status codes (mirrors cmd/cshared/internal/capi/errors.go).
#' @export
itb_status <- list(
  OK = 0L,
  BAD_HASH = 1L,
  BAD_KEY_BITS = 2L,
  BAD_HANDLE = 3L,
  BAD_INPUT = 4L,
  BUFFER_TOO_SMALL = 5L,
  ENCRYPT_FAILED = 6L,
  DECRYPT_FAILED = 7L,
  SEED_WIDTH_MIX = 8L,
  BAD_MAC = 9L,
  MAC_FAILURE = 10L,
  BLOB_MODE_MISMATCH = 19L,
  BLOB_MALFORMED = 20L,
  BLOB_VERSION_TOO_NEW = 21L,
  BLOB_TOO_MANY_OPTS = 22L,
  STREAM_TRUNCATED = 23L,
  STREAM_AFTER_FINAL = 24L,
  TRIPLE_CLOSED = 25L,
  PROFILE_EXISTS = 26L,
  INTERNAL = 99L
)

# Internal: called from the C shim (src/itb_r.c raise_status) to signal
# a classed condition. Not exported; the leading dot keeps it out of
# casual completion.
.itb_raise <- function(status, label, detail) {
  msg <- if (nzchar(detail)) {
    sprintf("itb: %s (status %d): %s", label, status, detail)
  } else {
    sprintf("itb: %s (status %d)", label, status)
  }
  stop(structure(
    class = c("itb_error", "error", "condition"),
    list(
      message = msg,
      call = sys.call(-1),
      status = as.integer(status),
      label = label,
      detail = detail
    )
  ))
}
