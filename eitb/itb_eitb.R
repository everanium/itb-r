# itb_eitb.R — command-line demonstrator for the ITB R binding.
#
# Subcommands:
#
#     itb_eitb.R version                                library + binding versions
#     itb_eitb.R profiles                               registered profile catalogue
#     itb_eitb.R inspect <blob-hex>                     profile record of a blob
#     itb_eitb.R encrypt <profile> <in-file> <out-file> Single Message encrypt
#     itb_eitb.R decrypt <profile> <blob-hex> <in-file> <out-file>
#
# `encrypt` prints the session blob (`pipeline_save`) to stderr as
# hex; feed that hex back to `decrypt` on the receiving side, which
# reopens the session with `pipeline_load` (the profile argument only
# routes Single Message versus streaming). `profiles` lists the
# registered profile catalogue one name per line; the profiles that
# carry a cipher surface are the ones `encrypt` / `decrypt` accept.

suppressMessages(library(itb))

USAGE <- paste(
  "usage: eitb version",
  "       eitb profiles",
  "       eitb inspect <blob-hex>",
  "       eitb encrypt <profile> <in-file> <out-file>",
  "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>",
  sep = "\n"
)

read_file <- function(path) {
  con <- file(path, "rb")
  on.exit(close(con))
  readBin(con, "raw", file.size(path))
}

write_file <- function(path, data) {
  con <- file(path, "wb")
  on.exit(close(con))
  writeBin(data, con)
}

cmd_version <- function() {
  cat("libitb", version(), "\n")
  cat("itb-r", as.character(utils::packageVersion("itb")), "\n")
}

cmd_profiles <- function() {
  cat(profiles(), sep = "\n")
}

cmd_inspect <- function(blob_hex) {
  cat(inspect(from_hex(blob_hex)), "\n")
}

# Profiles whose canonical name begins with "streaming-" route
# through the one-shot streaming buffered pair instead of the Single
# Message pair.
is_streaming_profile <- function(profile) startsWith(profile, "streaming-")

# Recursively create the parent directory of `path` (mkdir -p).
ensure_parent_dir <- function(path) {
  parent <- dirname(path)
  if (nzchar(parent) && parent != ".") {
    dir.create(parent, recursive = TRUE, showWarnings = FALSE)
  }
}

cmd_encrypt <- function(profile, infile, outfile) {
  plain <- read_file(infile)
  pipe <- pipeline_create(profile)
  on.exit(pipeline_free(pipe))
  wire <- if (is_streaming_profile(profile)) {
    pipeline_encrypt_stream_one_shot(pipe, plain)
  } else {
    pipeline_encrypt_message(pipe, plain)
  }
  ensure_parent_dir(outfile)
  write_file(outfile, wire)
  message(to_hex(pipeline_save(pipe)))
  cat(sprintf(
    "encrypted %s -> %s (%d -> %d bytes)\n",
    infile, outfile, length(plain), length(wire)
  ))
}

cmd_decrypt <- function(profile, blob_hex, infile, outfile) {
  blob <- from_hex(blob_hex)
  wire <- read_file(infile)
  pipe <- pipeline_load(blob)
  on.exit(pipeline_free(pipe))
  plain <- if (is_streaming_profile(profile)) {
    pipeline_decrypt_stream_one_shot(pipe, wire)
  } else {
    pipeline_decrypt_message(pipe, wire)
  }
  ensure_parent_dir(outfile)
  write_file(outfile, plain)
  cat(sprintf(
    "decrypted %s -> %s (%d -> %d bytes)\n",
    infile, outfile, length(wire), length(plain)
  ))
}

main <- function(argv) {
  known_shape <-
    (length(argv) == 1L && argv[1] %in% c("version", "profiles")) ||
      (length(argv) == 2L && argv[1] == "inspect") ||
      (length(argv) == 4L && argv[1] == "encrypt") ||
      (length(argv) == 5L && argv[1] == "decrypt")
  if (!known_shape) {
    message(USAGE)
    return(2L)
  }
  status <- 0L
  tryCatch(
    {
      # Go-runtime pacing caps applied before any cipher work.
      set_memory_limit(512 * 1024 * 1024)
      set_gc_percent(20)
      switch(argv[1],
        version = cmd_version(),
        profiles = cmd_profiles(),
        inspect = cmd_inspect(argv[2]),
        encrypt = cmd_encrypt(argv[2], argv[3], argv[4]),
        decrypt = cmd_decrypt(argv[2], argv[3], argv[4], argv[5])
      )
    },
    error = function(e) {
      message("eitb: ", conditionMessage(e))
      status <<- 1L
    }
  )
  status
}

quit(status = main(commandArgs(trailingOnly = TRUE)), save = "no")
