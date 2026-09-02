# test-itb.R — testthat suite for the ITB R binding.

library(itb)

# Deterministic non-trivial payload (seeded uniform bytes).
payload <- function(n, seed) {
  set.seed(seed)
  as.raw(sample.int(256L, n, replace = TRUE) - 1L)
}

# Runs expr and asserts it raised an itb_error with one of the
# expected statuses; returns the condition.
expect_itb_status <- function(expr, expected) {
  err <- tryCatch(
    {
      force(expr)
      NULL
    },
    itb_error = function(e) e
  )
  expect_false(is.null(err), label = "expected an itb_error, got success")
  expect_true(err$status %in% expected,
    label = sprintf(
      "unexpected status %d (%s): %s",
      err$status, err$label, conditionMessage(err)
    )
  )
  expect_gt(nchar(conditionMessage(err)), 0)
  invisible(err)
}

test_that("version reports library and binding versions", {
  v <- version()
  expect_type(v, "character")
  expect_gt(nchar(v), 0)
  expect_equal(as.character(utils::packageVersion("itb")), "0.3.3")
})

test_that("hashes returns the canonical registry order", {
  expected <- c(
    "areion256", "areion512", "blake2b256", "blake2b512",
    "blake2s", "blake3", "aescmac", "siphash24", "chacha20"
  )
  got <- hashes()
  expect_s3_class(got, "data.frame")
  expect_equal(got$name, expected)
  expect_true(all(got$width > 0))
})

test_that("profiles lists the built-in Triple profiles", {
  got <- profiles()
  expect_gt(length(got), 0)
  for (want in c(
    "singlemsg-triple-mac-v1",
    "singlemsg-triple-nomac-v1",
    "streaming-aead-triple-mac-v1",
    "streaming-noaead-triple-v1"
  )) {
    expect_true(want %in% got, label = paste("missing profile", want))
  }
})

test_that("runtime knobs query without changing", {
  expect_type(set_memory_limit(-1), "double")
  expect_type(set_gc_percent(-1L), "integer")
})

test_that("message round trip (singlemsg-triple-mac-v1)", {
  sender <- pipeline_create("singlemsg-triple-mac-v1")
  receiver <- pipeline_open("singlemsg-triple-mac-v1", pipeline_blob(sender))
  for (size in c(1L, 4L * 1024L, 256L * 1024L)) {
    plain <- payload(size, size)
    wire <- pipeline_encrypt_message(sender, plain)
    expect_gt(length(wire), 0)
    expect_false(identical(wire, plain))
    expect_identical(pipeline_decrypt_message(receiver, wire), plain)
  }
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("stream round trip (streaming-noaead-triple-v1)", {
  sender <- pipeline_create("streaming-noaead-triple-v1")
  receiver <- pipeline_open("streaming-noaead-triple-v1", pipeline_blob(sender))
  plain <- payload(96L * 1024L, 7L)

  # Encrypt incrementally: 8 KiB writes, then end + drain.
  enc <- stream_encryptor(sender)
  off <- 1L
  while (off <= length(plain)) {
    stream_write(enc, plain[off:min(off + 8191L, length(plain))])
    off <- off + 8192L
  }
  wire <- stream_drain_all(enc)
  expect_gt(length(wire), 0)
  stream_free(enc)

  # Decrypt with pathological batch sizes (17-byte feed, 23-byte
  # drain) across chunk boundaries.
  dec <- stream_decryptor(receiver)
  off <- 1L
  while (off <= length(wire)) {
    stream_write(dec, wire[off:min(off + 16L, length(wire))])
    off <- off + 17L
  }
  stream_end(dec)
  stream_end(dec) # idempotent
  parts <- list()
  repeat {
    r <- stream_read(dec, 23L)
    parts[[length(parts) + 1L]] <- r$chunk
    if (r$finished) break
  }
  expect_identical(do.call(c, parts), plain)
  stream_free(dec)
  stream_free(dec) # idempotent
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("pump helper round trip", {
  sender <- pipeline_create("streaming-noaead-triple-v1")
  receiver <- pipeline_open("streaming-noaead-triple-v1", pipeline_blob(sender))
  plain <- payload(64L * 1024L + 3L, 11L)

  reader_over <- function(s) {
    off <- 1L
    function() {
      if (off > length(s)) {
        return(NULL)
      }
      piece <- s[off:min(off + 8191L, length(s))]
      off <<- off + 8192L
      piece
    }
  }
  collector <- function() {
    acc <- list()
    list(
      write = function(chunk) acc[[length(acc) + 1L]] <<- chunk,
      bytes = function() do.call(c, acc)
    )
  }

  wire_acc <- collector()
  enc <- stream_encryptor(sender)
  pump(enc, reader_over(plain), wire_acc$write)
  stream_free(enc)
  wire <- wire_acc$bytes()

  back_acc <- collector()
  dec <- stream_decryptor(receiver)
  pump(dec, reader_over(wire), back_acc$write)
  stream_free(dec)
  expect_identical(back_acc$bytes(), plain)
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("large plaintext round trip (pattern P1, > 1 MiB)", {
  sender <- pipeline_create("singlemsg-triple-nomac-v1")
  receiver <- pipeline_open("singlemsg-triple-nomac-v1", pipeline_blob(sender))
  plain <- payload(2L * 1024L * 1024L + 17L, 3L)
  wire <- pipeline_encrypt_message(sender, plain)
  expect_identical(pipeline_decrypt_message(receiver, wire), plain)
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("unknown profile maps to BAD_INPUT", {
  err <- expect_itb_status(
    pipeline_create("no-such-profile"),
    itb_status$BAD_INPUT
  )
  expect_equal(err$label, "invalid input")
  expect_s3_class(err, "itb_error")
})

test_that("unknown opts key maps to BAD_INPUT", {
  # Typoed key (lowercase s) — Go rejects unknown keys; the binding
  # performs no validation of its own.
  expect_itb_status(
    pipeline_create("singlemsg-triple-mac-v1",
      opts = itb_opts(chunksize = 4096)
    ),
    itb_status$BAD_INPUT
  )
})

test_that("tampered wire fails authentication", {
  sender <- pipeline_create("singlemsg-triple-mac-v1")
  receiver <- pipeline_open("singlemsg-triple-mac-v1", pipeline_blob(sender))
  wire <- pipeline_encrypt_message(sender, payload(4096L, 21L))
  i <- length(wire) %/% 2L
  wire[i] <- xor(wire[i], as.raw(0xFF))
  expect_itb_status(
    pipeline_decrypt_message(receiver, wire),
    c(itb_status$MAC_FAILURE, itb_status$DECRYPT_FAILED)
  )
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("closed pipeline maps to TRIPLE_CLOSED", {
  pipe <- pipeline_create("singlemsg-triple-mac-v1")
  pipeline_close(pipe)
  pipeline_close(pipe) # idempotent
  expect_itb_status(
    pipeline_encrypt_message(pipe, "payload"),
    itb_status$TRIPLE_CLOSED
  )
  pipeline_free(pipe)
})

test_that("freed pipeline raises an R error", {
  pipe <- pipeline_create("singlemsg-triple-mac-v1")
  pipeline_free(pipe)
  pipeline_free(pipe) # idempotent
  expect_error(pipeline_encrypt_message(pipe, "x"), "already freed")
})

test_that("rekey refreshes the blob", {
  sender <- pipeline_create("singlemsg-triple-mac-v1")
  blob_before <- pipeline_blob(sender)
  pipeline_rekey(sender, payload(32L, 5L), payload(32L, 6L))
  blob_after <- pipeline_blob(sender)
  expect_false(identical(blob_after, blob_before))
  # The refreshed blob reconstructs a working receiver.
  receiver <- pipeline_open("singlemsg-triple-mac-v1", blob_after)
  wire <- pipeline_encrypt_message(sender, "post-rekey payload")
  expect_identical(
    rawToChar(pipeline_decrypt_message(receiver, wire)),
    "post-rekey payload"
  )
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("register_profile round trip and duplicate", {
  opts <- itb_opts(
    mode = "singlemsg-nomac",
    width = "256",
    innerHashes = paste(
      "blake3", "blake2s", "areion256", "blake2b256",
      "chacha20", "blake3", "blake2s", "areion256",
      sep = ","
    ),
    keyBits = "1024",
    parallaxOn = "false",
    wrapperOn = "false"
  )
  register_profile("r-binding-test-mixed", opts)
  sender <- pipeline_create("r-binding-test-mixed")
  receiver <- pipeline_open("r-binding-test-mixed", pipeline_blob(sender))
  wire <- pipeline_encrypt_message(sender, "custom profile")
  expect_identical(
    rawToChar(pipeline_decrypt_message(receiver, wire)),
    "custom profile"
  )
  expect_itb_status(
    register_profile("r-binding-test-mixed", opts),
    itb_status$PROFILE_EXISTS
  )
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("stream session pins its parent pipeline against GC", {
  sess <- local({
    pipe <- pipeline_create("streaming-noaead-triple-v1")
    stream_encryptor(pipe)
    # pipe goes out of scope here with no other R reference.
  })
  gc(full = TRUE)
  gc(full = TRUE)
  # The session's `parent` field (and the external pointer's protected
  # slot) keep the Pipeline object and its Go-side handle alive, so
  # the write still succeeds.
  stream_write(sess, charToRaw("still alive after parent went out of scope"))
  wire <- stream_drain_all(sess)
  expect_gt(length(wire), 0)
  stream_free(sess)
})

test_that("one-shot stream calls match the session shape", {
  sender <- pipeline_create("streaming-noaead-triple-v1")
  receiver <- pipeline_open("streaming-noaead-triple-v1", pipeline_blob(sender))
  plain <- payload(32L * 1024L, 13L)
  wire <- pipeline_encrypt_stream_one_shot(sender, plain)
  expect_identical(pipeline_decrypt_stream_one_shot(receiver, wire), plain)
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("opts builder rendering", {
  expect_equal(itb_opts(), "")
  expect_equal(itb_opts(list()), "")
  q <- itb_opts(
    nonce_bits = 512,
    key_bits = 1024,
    with_parallax = FALSE,
    inner_hash = "areion512",
    parallax_palette = c("chacha20", "blake3")
  )
  # Keys are emitted in sorted (snake_case) order.
  expect_equal(q, paste0(
    "innerHash=areion512&keyBits=1024&nonceBits=512",
    "&parallaxPalette=chacha20,blake3&withParallax=false"
  ))
  # Percent-encoding of non-URL-safe bytes.
  expect_equal(itb_opts(x = "a b&c"), "x=a%20b%26c")
})

test_that("hex codec", {
  expect_equal(to_hex(as.raw(c(0x00, 0xFF, 0x61, 0x62))), "00ff6162")
  expect_identical(from_hex("00ff6162"), as.raw(c(0x00, 0xFF, 0x61, 0x62)))
  p <- payload(257L, 9L)
  expect_identical(from_hex(to_hex(p)), p)
  expect_error(from_hex("0g"), "non-hex")
  expect_error(from_hex("012"), "odd-length")
})

test_that("stream_read_into partial drain reassembles the stream", {
  sender <- pipeline_create("streaming-noaead-triple-v1")
  receiver <- pipeline_open("streaming-noaead-triple-v1", pipeline_blob(sender))
  plain <- payload(256L * 1024L + 13L, 29L)

  # Encrypt: whole-buffer feed, then drain through a deliberately
  # small dedicated scratch so every read is a partial fill.
  enc <- stream_encryptor(sender)
  stream_write(enc, plain)
  stream_end(enc)
  scratch <- raw(4096L)
  parts <- list()
  repeat {
    r <- stream_read_into(enc, scratch)
    expect_lte(r[1L], length(scratch))
    if (r[1L] > 0L) parts[[length(parts) + 1L]] <- scratch[seq_len(r[1L])]
    if (r[2L] == 1L) break
  }
  wire <- do.call(c, parts)
  expect_gt(length(wire), 0L)
  # A drain after the finished flag stays clean: c(0, 1).
  expect_identical(stream_read_into(enc, scratch), c(0L, 1L))
  stream_free(enc)

  # Decrypt: feed via stream_write_slice windows over the one wire
  # vector, drain via stream_read_into — the round trip runs entirely
  # on the allocation-free primitives.
  dec <- stream_decryptor(receiver)
  off <- 0L
  while (off < length(wire)) {
    take <- min(8192L, length(wire) - off)
    stream_write_slice(dec, wire, off, take)
    off <- off + take
  }
  stream_end(dec)
  parts <- list()
  repeat {
    r <- stream_read_into(dec, scratch)
    if (r[1L] > 0L) parts[[length(parts) + 1L]] <- scratch[seq_len(r[1L])]
    if (r[2L] == 1L) break
  }
  expect_identical(do.call(c, parts), plain)
  stream_free(dec)
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("stream_write_slice rejects out-of-window slices", {
  pipe <- pipeline_create("streaming-noaead-triple-v1")
  enc <- stream_encryptor(pipe)
  data <- payload(64L, 31L)
  expect_error(stream_write_slice(enc, data, -1, 8), "out of bounds")
  expect_error(stream_write_slice(enc, data, 0, -1), "out of bounds")
  expect_error(
    stream_write_slice(enc, data, 0, length(data) + 1L),
    "out of bounds"
  )
  expect_error(stream_write_slice(enc, data, 60, 8), "out of bounds")
  # In-window slices still feed after the rejected attempts.
  stream_write_slice(enc, data, 0, length(data))
  wire <- stream_drain_all(enc)
  expect_gt(length(wire), 0L)
  stream_free(enc)
  pipeline_free(pipe)
})

test_that("stream_read_into rejects an unusable scratch buffer", {
  pipe <- pipeline_create("streaming-noaead-triple-v1")
  enc <- stream_encryptor(pipe)
  expect_error(stream_read_into(enc, raw(0)), "non-empty")
  expect_error(stream_read_into(enc, 1:4), "raw vector")
  stream_free(enc)
  pipeline_free(pipe)
})
