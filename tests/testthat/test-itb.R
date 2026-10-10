# testthat suite for the ITB R binding.

library(libitb3r)

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
      "unexpected status %d: %s", err$status, conditionMessage(err)
    )
  )
  expect_gt(nchar(conditionMessage(err)), 0)
  invisible(err)
}

test_that("version reports library and binding versions", {
  v <- version()
  expect_type(v, "character")
  expect_gt(nchar(v), 0)
  expect_equal(as.character(utils::packageVersion("libitb3r")), "0.5.5")
})

test_that("drbg_auto_tier names a fill cipher", {
  expect_true(drbg_auto_tier() %in% c("aes-256-ctr", "chacha20"))
})

test_that("profiles lists the registered Triple profiles", {
  got <- profiles()
  expect_gt(length(got), 0)
  expect_identical(got, sort(got))
  for (p in got) {
    expect_true(grepl(sprintf('"name":"%s"', p), lookup(p), fixed = TRUE))
  }
  expect_itb_status(lookup("no-such-profile"), itb_status$UNKNOWN_PROFILE)
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
  receiver <- pipeline_load(pipeline_save(sender))
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
  receiver <- pipeline_load(pipeline_save(sender))
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
  receiver <- pipeline_load(pipeline_save(sender))
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

test_that("large plaintext round trip (> 1 MiB)", {
  sender <- pipeline_create("singlemsg-triple-nomac-v1")
  receiver <- pipeline_load(pipeline_save(sender))
  plain <- payload(2L * 1024L * 1024L + 17L, 3L)
  wire <- pipeline_encrypt_message(sender, plain)
  expect_identical(pipeline_decrypt_message(receiver, wire), plain)
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("unknown profile maps to UNKNOWN_PROFILE", {
  err <- expect_itb_status(
    pipeline_create("no-such-profile"),
    itb_status$UNKNOWN_PROFILE
  )
  expect_gt(nchar(err$detail), 0)
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
  receiver <- pipeline_load(pipeline_save(sender))
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
  blob_before <- pipeline_save(sender)
  blob_after <- pipeline_rekey(sender, payload(32L, 5L), payload(32L, 6L))
  expect_false(identical(blob_after, blob_before))
  expect_identical(pipeline_save(sender), blob_after)
  # The refreshed blob reconstructs a working receiver.
  receiver <- pipeline_load(blob_after)
  wire <- pipeline_encrypt_message(sender, "post-rekey payload")
  expect_identical(
    rawToChar(pipeline_decrypt_message(receiver, wire)),
    "post-rekey payload"
  )
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("register round trip and duplicate", {
  profile <- paste0(
    '{"mode":"singlemsg-nomac","width":256,',
    '"hashes":["blake3","blake2s","areion256","blake2b256",',
    '"chacha20","blake3","blake2s","areion256"],',
    '"keybits":1024,"parallax":false,"wrapper":false}'
  )
  register("r-binding-test-mixed", profile)
  expect_true("r-binding-test-mixed" %in% profiles())
  expect_true(grepl('"hashes":["blake3"', lookup("r-binding-test-mixed"), fixed = TRUE))
  sender <- pipeline_create("r-binding-test-mixed")
  receiver <- pipeline_load(pipeline_save(sender))
  wire <- pipeline_encrypt_message(sender, "custom profile")
  expect_identical(
    rawToChar(pipeline_decrypt_message(receiver, wire)),
    "custom profile"
  )
  expect_itb_status(
    register("r-binding-test-mixed", profile),
    itb_status$PROFILE_EXISTS
  )
  # Strict record decode on the Go side: an unknown key is rejected
  # there, not by the binding.
  expect_itb_status(
    register("r-binding-test-badkey", '{"mode":"singlemsg-nomac","bogus":1}'),
    itb_status$BAD_INPUT
  )
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("save / load round trip", {
  sender <- pipeline_create("singlemsg-triple-mac-v1")
  blob <- pipeline_save(sender)
  expect_gt(length(blob), 0L)
  expect_identical(pipeline_save(sender), blob)
  receiver <- pipeline_load(blob)
  expect_identical(pipeline_save(receiver), blob)
  wire <- pipeline_encrypt_message(sender, "in-memory persist")
  expect_identical(rawToChar(pipeline_decrypt_message(receiver, wire)), "in-memory persist")
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("save_f / load_f round trip", {
  dir <- tempfile("itb-persist-")
  dir.create(dir)
  on.exit(unlink(dir, recursive = TRUE))
  path <- file.path(dir, "session.blob")
  sender <- pipeline_create("singlemsg-triple-mac-v1")
  pipeline_save_f(sender, path)
  expect_equal(as.integer(file.info(path)$mode), strtoi("600", 8L))
  receiver <- pipeline_load_f(path)
  expect_identical(pipeline_save(receiver), pipeline_save(sender))
  wire <- pipeline_encrypt_message(sender, "file persist")
  expect_identical(rawToChar(pipeline_decrypt_message(receiver, wire)), "file persist")
  expect_itb_status(pipeline_load_f(file.path(dir, "absent.blob")), itb_status$BAD_INPUT)
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("load with master override", {
  sender <- pipeline_create("singlemsg-triple-mac-v1")
  rotated <- pipeline_rekey(sender, payload(32L, 8L), payload(32L, 10L))
  receiver <- pipeline_load(pipeline_save(sender), payload(32L, 8L), payload(32L, 10L))
  expect_identical(pipeline_save(receiver), rotated)
  wire <- pipeline_encrypt_message(sender, "master override")
  expect_identical(rawToChar(pipeline_decrypt_message(receiver, wire)), "master override")
  pipeline_free(receiver)
  pipeline_free(sender)
})

test_that("inspect carries recipe plus inspection-only fields", {
  # inspect carries the registry recipe plus the blob-only nonce_bits
  # / barrier_fill inspection fields; lookup returns just the recipe.
  pipe <- pipeline_create("singlemsg-triple-mac-v1")
  record <- inspect(pipeline_save(pipe))
  looked <- lookup("singlemsg-triple-mac-v1")
  expect_true(grepl('"name":"singlemsg-triple-mac-v1"', record, fixed = TRUE))
  expect_true(grepl('"mode":"singlemsg-mac"', record, fixed = TRUE))
  expect_true(grepl('"nonce_bits":', record, fixed = TRUE))
  expect_true(grepl('"barrier_fill":', record, fixed = TRUE))
  expect_true(grepl('"name":"singlemsg-triple-mac-v1"', looked, fixed = TRUE))
  expect_false(grepl('"nonce_bits":', looked, fixed = TRUE))
  expect_false(grepl('"barrier_fill":', looked, fixed = TRUE))
  expect_itb_status(inspect("not a blob"), itb_status$BAD_INPUT)
  pipeline_free(pipe)
})

test_that("max_workers", {
  pipe <- pipeline_create("singlemsg-triple-mac-v1")
  pipeline_max_workers(pipe, 2L)
  pipeline_max_workers(pipe, -1L) # clamped to auto, never rejected
  pipeline_max_workers(pipe, 10000L) # clamped to 256
  wire <- pipeline_encrypt_message(pipe, "after cap change")
  expect_identical(rawToChar(pipeline_decrypt_message(pipe, wire)), "after cap change")
  pipeline_close(pipe)
  expect_itb_status(pipeline_max_workers(pipe, 2L), itb_status$TRIPLE_CLOSED)
  pipeline_free(pipe)
  # A negative init-time cap is clamped as well.
  neg <- pipeline_create("singlemsg-triple-mac-v1", opts = itb_opts(max_workers = -1))
  expect_identical(
    rawToChar(pipeline_decrypt_message(neg, pipeline_encrypt_message(neg, "negative cap"))),
    "negative cap"
  )
  pipeline_free(neg)
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
  receiver <- pipeline_load(pipeline_save(sender))
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
  receiver <- pipeline_load(pipeline_save(sender))
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

test_that("hash_names enumerates the shipped hash registry", {
  got <- hash_names()
  expect_type(got, "character")
  expect_gt(length(got), 0)
  for (want in c("areion512", "blake3", "aesitb128")) {
    expect_true(want %in% got, label = sprintf("missing hash primitive %s", want))
  }
  # The enumeration is what a caller validates a name against, so a
  # name outside it must be one libitb3 rejects.
  expect_false("nosuchhash" %in% got)
  expect_itb_status(
    pipeline_create("singlemsg-triple-mac-v1",
      itb_opts(inner_hash = "nosuchhash")),
    c(itb_status$BAD_HASH, itb_status$BAD_INPUT, itb_status$INTERNAL)
  )
})

test_that("set_gomaxprocs sets and queries", {
  before <- set_gomaxprocs(0L)
  expect_type(before, "integer")
  expect_gt(before, 0L)
  expect_identical(set_gomaxprocs(2L), before)
  expect_identical(set_gomaxprocs(0L), 2L)
  set_gomaxprocs(before)
  expect_identical(set_gomaxprocs(0L), before)
})

test_that("write_heap_profile writes a pprof profile", {
  path <- tempfile(fileext = ".prof")
  on.exit(unlink(path), add = TRUE)
  write_heap_profile(path)
  expect_true(file.exists(path))
  expect_gt(file.size(path), 0)
  # pprof output is a gzip stream.
  magic <- readBin(path, "raw", 2L)
  expect_identical(magic, as.raw(c(0x1f, 0x8b)))
  expect_itb_status(
    write_heap_profile("/nonexistent-directory-for-itb-tests/heap.prof"),
    itb_status$BAD_INPUT
  )
})

test_that("pool_stats reports the library's pool counters", {
  want <- pool_stats_len()
  expect_type(want, "integer")
  expect_gt(want, 0L)
  first <- pool_stats()
  expect_length(first, want)
  # Slot 1 carries the hash-array tier count, and the vector holds five
  # slots per tier plus the eight slots of the two byte pools.
  tiers <- first[1]
  expect_gt(tiers, 0)
  expect_identical(1 + 5 * tiers + 8, as.numeric(want))
  # The counters are monotonic totals since library load, so work done
  # between two snapshots can only raise them.
  pipe <- pipeline_create("singlemsg-triple-mac-v1")
  on.exit(pipeline_free(pipe), add = TRUE)
  plain <- payload(64 * 1024, 3)
  expect_identical(
    pipeline_decrypt_message(pipe, pipeline_encrypt_message(pipe, plain)), plain)
  second <- pool_stats()
  expect_true(all(second >= first))
  expect_true(any(second > first))
})

test_that("drbg round trip through a loaded blob", {
  for (name in c("csprng", "aesitb128")) {
    sender <- pipeline_create("singlemsg-triple-mac-v1",
      opts = itb_opts(drbg = name)
    )
    receiver <- pipeline_load(pipeline_save(sender))
    plain <- charToRaw(paste("drbg", name))
    expect_identical(
      pipeline_decrypt_message(receiver, pipeline_encrypt_message(sender, plain)),
      plain
    )
    back <- charToRaw(paste("reverse", name))
    expect_identical(
      pipeline_decrypt_message(sender, pipeline_encrypt_message(receiver, back)),
      back
    )
    pipeline_free(receiver)
    pipeline_free(sender)
  }
})

test_that("drbg inspect, default and unknown name", {
  pipe <- pipeline_create("singlemsg-triple-mac-v1",
    opts = itb_opts(drbg = "csprng")
  )
  expect_true(grepl('"drbg":"csprng"', inspect(pipeline_save(pipe)), fixed = TRUE))
  pipeline_free(pipe)
  # With no drbg set the record carries no drbg key, and no shipped
  # profile names one.
  plain <- pipeline_create("singlemsg-triple-mac-v1")
  expect_false(grepl('"drbg":', inspect(pipeline_save(plain)), fixed = TRUE))
  pipeline_free(plain)
  expect_false(grepl('"drbg":', lookup("singlemsg-triple-mac-v1"), fixed = TRUE))
  err <- expect_itb_status(
    pipeline_create("singlemsg-triple-mac-v1", opts = itb_opts(drbg = "nope")),
    itb_status$RECIPE_PRIMITIVE_UNKNOWN
  )
  expect_true(grepl("nope", conditionMessage(err), fixed = TRUE))
})

test_that("drbg survives a register copy", {
  pipe <- pipeline_create("singlemsg-triple-mac-v1",
    opts = itb_opts(drbg = "csprng")
  )
  # The inspection-only fields are dropped; drbg is a recipe field and
  # stays in the registered copy.
  record <- inspect(pipeline_save(pipe))
  record <- gsub('"name":"[^"]*",?', "", record)
  record <- gsub('"(nonce_bits|barrier_fill|container_mode)":[0-9]+,?', "", record)
  register("r-binding-test-drbg-copy", record)
  expect_true(grepl('"drbg":"csprng"', lookup("r-binding-test-drbg-copy"), fixed = TRUE))
  pipeline_free(pipe)
})
