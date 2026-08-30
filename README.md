# ITB R Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`), packaged as a standard R source package with a C shim
(`src/itb_r.c`) driven through R's `.Call` interface. The compiled
shim links `libitb.so` directly, and every hash-name / MAC-name /
cipher-name / profile-name is an opaque string passed through to Go
for validation — the binding carries no ITB construction logic. The
public surface is a `Pipeline` object (create / open / rekey / close,
Single Message encrypt / decrypt, whole-buffer and incremental stream
sessions), an opts query-string builder, `register_profile`, and the
Go runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make r
```

The test suite additionally needs `testthat`:

```r
install.packages("testthat", repos = "https://cloud.r-project.org")
```

Generic Linux: any R (>= 4.0) installation with a working
`R CMD INSTALL` toolchain works.

## Build

The convenience driver builds `libitb.so` (only when absent — set
`ITB_REBUILD_LIBITB=1` to force a Go rebuild) and installs the R
package into the local library directory `.local/` in one step:

```bash
./bindings/r/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/r && mkdir -p .local && \
    ITB_LIBITB_DIR="$(pwd)/../../dist/linux-amd64" \
    R CMD INSTALL --no-docs --library=.local .
```

The compiled shim embeds an rpath to the repository's
`dist/linux-amd64` directory, so `libitb.so` resolves without
`LD_LIBRARY_PATH`; set `ITB_LIBITB_DIR=<dir>` in the environment
before `R CMD INSTALL` to link against a differently-located build
(the `src/Makevars` default resolves the directory relative to the
package tree). Load the installed package with the local library on
the search path:

```bash
R_LIBS="$PWD/.local" Rscript -e 'library(itb); ...'
```

## Usage example

```r
library(itb)

sender <- pipeline_create("singlemsg-triple-mac-v1")
receiver <- pipeline_open("singlemsg-triple-mac-v1", pipeline_blob(sender))

wire <- pipeline_encrypt_message(sender, "any text or binary data")
plain <- pipeline_decrypt_message(receiver, wire)
stopifnot(identical(rawToChar(plain), "any text or binary data"))

pipeline_free(receiver)
pipeline_free(sender)
```

`itb_opts` builds the URL-query opts string overriding the profile
default per call (chunk size, outer cipher, parallax on/off, wrapper
on/off, MAC name, palette):

```r
opts <- itb_opts(chunk_size = 65536, with_wrapper = FALSE)
sender <- pipeline_create("singlemsg-triple-mac-v1", opts = opts)
receiver <- pipeline_open("singlemsg-triple-mac-v1", pipeline_blob(sender), opts = opts)
```

`pipeline_rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`pipeline_blob(sender)` handshake:

```r
pipeline_rekey(sender, as.raw(rep(0x11, 32)), as.raw(rep(0x22, 32)))
receiver <- pipeline_open("singlemsg-triple-mac-v1", pipeline_blob(sender))
```

Raw vectors are the byte-buffer type throughout: outputs are always
raw vectors; plaintext inputs also accept a single character string
(converted via `charToRaw`). Objects are environment-backed
(reference semantics) and carry finalized external pointers, so
garbage collection releases the Go-side handle when an object goes
out of scope without an explicit `pipeline_free` / `stream_free`.

Incremental streaming:

```r
pipe <- pipeline_create("streaming-noaead-triple-v1")
sess <- stream_encryptor(pipe)
stream_write(sess, part1)
stream_write(sess, part2)
wire <- stream_drain_all(sess)   # end-of-input + drain in one call
stream_free(sess)
```

The explicit loop form is `stream_write` / `stream_end` /
`stream_read`; `stream_read(sess, max)` returns
`list(chunk = <raw>, finished = <logical>)` and never blocks before
`stream_end`. The `pump(sess, read_fn, write_fn)` helper moves bytes
through a session with bounded memory. A stream session holds its
parent `Pipeline` in the object's `parent` field (and in the external
pointer's protected slot), so the R garbage collector cannot collect
the Pipeline while the session is live.

Errors are signalled as R conditions of class `itb_error` (fields
`status`, `label`, `detail`), so `tryCatch` callers branch on the
status against the `itb_status` constant list:

```r
err <- tryCatch(pipeline_create("no-such-profile"),
                itb_error = function(e) e)
stopifnot(err$status == itb_status$BAD_INPUT)
```

Options are URL-query strings built with `itb_opts(...)` (snake_case
keys map onto the Go opts grammar; unknown keys pass through verbatim
for the register-profile grammar):

```r
opts <- itb_opts(nonce_bits = 512, key_bits = 1024, chunk_size = 65536)
pipe <- pipeline_create("streaming-aead-triple-mac-v1", opts = opts)
```

Go runtime knobs: `set_memory_limit(bytes)` and `set_gc_percent(pct)`
(negative values query without changing). `hashes()` returns the
shipped hash primitive roster in canonical registry order as a
data.frame; `profiles()` returns the built-in Triple profile names.

## Testing

```bash
./bindings/r/run_tests.sh
```

testthat suite: version and roster checks, Single Message and
incremental Streaming round trips, the pump helper, a > 1 MiB
payload, error mapping (unknown profile, unknown opts key, tampered
wire, closed Pipeline, freed Pipeline, duplicate profile
registration), rekey blob refresh, the GC parent-pin, and the opts /
hex helpers.

## Benchmarking

```bash
./bindings/r/run_bench.sh                       # canonical 5 s per case
ITB_BENCH_MIN_SEC=1 ./bindings/r/run_bench.sh   # quick smoke
```

Single Message encrypt and incremental Streaming encrypt (No MAC
profiles) at 1 MiB / 16 MiB / 64 MiB, configured through the fleet's
canonical env vars (`ITB_INNER_HASH`, `ITB_KEY_BITS`,
`ITB_NONCE_BITS`, `ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`,
`ITB_PROFILE`, `ITB_BENCH_MIN_SEC`); the harness caps the Go runtime
via `set_memory_limit(512 * 1024 * 1024)` and `set_gc_percent(20)`.
See `bindings/BENCH.md` for the fleet-wide configuration authority
and comparison tables.

## eitb CLI

```bash
./bindings/r/eitb/eitb version
./bindings/r/eitb/eitb hashes
./bindings/r/eitb/eitb profiles
./bindings/r/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.itb  2> blob.hex
./bindings/r/eitb/eitb decrypt singlemsg-triple-mac-v1 "$(cat blob.hex)" out.itb back.bin
```

`encrypt` prints the session blob to stderr as hex; feed that hex back
to `decrypt` on the receiving side.

## Limitations

- **Copy-in / copy-out buffers.** R raw vectors are immutable from the
  binding's perspective; every buffer crosses the `.Call` boundary by
  copy in both directions. Single Message throughput at large payloads
  sits close to the rest of the binding fleet; the multi-call
  Streaming shape pays proportionally more per-call overhead.
- **`stream_end`, not `end`.** The end-of-input function is named
  `stream_end`; all stream verbs carry the `stream_` prefix because R
  has no method-call syntax on the environment-backed objects.
- **`version()` masks `base::version`.** Attaching the package shadows
  the base R `version` list; use `base::version` (or
  `R.version.string`) where the base object is needed.
- **`profiles()` is a mirror.** The C ABI exposes no profile
  enumeration; the returned vector mirrors the built-in profile
  registry and does not include profiles added at runtime via
  `register_profile`.
- **Streaming decrypt caveat.** Chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The binding exposes the Triple Pipeline surface only; the Low-Level
  Go-native configuration surface is not exported.
