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
public surface is a `Pipeline` object (create / load / load_f / save
/ save_f / rekey / max_workers / close,
Single Message encrypt / decrypt, whole-buffer and incremental stream
sessions), an opts query-string builder for `pipeline_create`, the
profile-catalogue functions (`inspect` / `register` / `lookup` /
`profiles`), and the
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
receiver <- pipeline_load(pipeline_save(sender))

wire <- pipeline_encrypt_message(sender, "any text or binary data")
plain <- pipeline_decrypt_message(receiver, wire)
stopifnot(identical(rawToChar(plain), "any text or binary data"))

pipeline_free(receiver)
pipeline_free(sender)

# File-backed equivalent (persist across processes):
# sender <- pipeline_create("singlemsg-triple-mac-v1")
# pipeline_save_f(sender, "session.blob")
# receiver <- pipeline_load_f("session.blob")
```

`itb_opts` builds the URL-query opts string overriding the profile
default at `pipeline_create` (chunk size, outer cipher, parallax
on/off, wrapper on/off, MAC name, palette, worker cap). The resolved
shape is written into the blob, so the receiver loads it with no opts
of its own:

```r
opts <- itb_opts(chunk_size = 65536, with_wrapper = FALSE)
sender <- pipeline_create("singlemsg-triple-mac-v1", opts = opts)
receiver <- pipeline_load(pipeline_save(sender))
```

`pipeline_rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the refreshed blob; the receiver picks up the
new masters through a fresh `pipeline_load`:

```r
rotated <- pipeline_rekey(sender, as.raw(rep(0x11, 32)), as.raw(rep(0x22, 32)))
receiver <- pipeline_load(rotated)
```

## Persisting sessions

The blob is self-describing: it carries the profile record (mode,
width, primitives, key bits, MAC, layer switches) alongside the key
material, so a session reopens from the blob alone.

```r
blob <- pipeline_save(sender)                 # current blob (raw vector)
pipeline_save_f(sender, "session.blob")       # written by libitb, mode 0600
receiver <- pipeline_load(blob)               # reopen from bytes
receiver <- pipeline_load_f("session.blob")   # reopen from file
receiver <- pipeline_load(blob, perm, wrap)   # override the masters
record <- inspect(blob)                       # profile record, no Pipeline
```

`inspect` returns the profile record as the JSON text libitb emits
(keys `name`, `mode`, `width`, `hash`, `hashes`, `keybits`, `mac`,
`tagstub`, `chunk`, `wrapper`, `outer`, `parallax`, `palette`,
`segment`; absent keys are optional fields at their zero value) — the
package carries no JSON dependency, so the text is handed over
verbatim for the caller's own decoder (e.g. `jsonlite::fromJSON`).

The shipped `itb3` command-line utility (see `cmd/itb3`) generates
session blobs on disk (JSON files) that this binding reopens through
`pipeline_load_f`, and also encrypts / decrypts files or stdio streams
from the shell. It is the openssl-style entry point for ITB; the
binding is the programmatic entry point.

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `pipeline_load` such a blob
through this binding raises an `itb_error` with
`status == itb_status$RECIPE_PRIMITIVE_UNKNOWN`.

## Profile registry

```r
profiles()                                    # sorted character vector
lookup("singlemsg-triple-mac-v1")             # record JSON; unknown -> UNKNOWN_PROFILE
register("my-profile", '{
  "mode": "singlemsg-nomac",
  "width": 256,
  "hashes": ["blake3", "blake2s", "areion256", "blake2b256",
             "chacha20", "blake3", "blake2s", "areion256"],
  "keybits": 1024,
  "parallax": false,
  "wrapper": false
}')
sender <- pipeline_create("my-profile")
```

`register` takes the same JSON record shape `inspect` / `lookup`
return; a `name` key inside it, if present, must be empty or equal to
the name argument. Every rule — name pattern, reserved prefixes,
field constraints, primitive names — is enforced by libitb; a
duplicate name raises `itb_status$PROFILE_EXISTS`.

## Runtime tuning

`pipeline_max_workers(pipe, n)` sets the worker cap on a live
Pipeline (`n <= 0` selects auto, values above 256 are clamped). The
cap is per-machine tuning and is never written to the blob, so the
receiver may pick its own worker cap after `pipeline_load`. The
`max_workers` opts key sets the same cap at `pipeline_create`.

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
stopifnot(err$status == itb_status$UNKNOWN_PROFILE)
```

Options are URL-query strings built with `itb_opts(...)` (snake_case
keys map onto the Go opts grammar; unknown keys pass through
verbatim):

```r
opts <- itb_opts(nonce_bits = 512, key_bits = 1024, chunk_size = 65536)
pipe <- pipeline_create("streaming-aead-triple-mac-v1", opts = opts)
```

`profiles()` returns every registered Triple profile name (shipped
catalogue plus `register` additions), sorted.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass a negative value to
query without changing. Long-running or allocation-heavy workloads
(benchmarks, bulk encryption) should set both — without a soft cap +
aggressive GC the Go scratch heap grows unboundedly under allocation
churn:

```r
set_memory_limit(512 * 1024 * 1024) # 512 MiB soft cap
set_gc_percent(20)                  # aggressive GC
```

## Testing

```bash
./bindings/r/run_tests.sh
```

testthat suite: version check, Single Message and incremental
Streaming round trips, the pump helper, a > 1 MiB payload, error
mapping (unknown profile, unknown opts key, tampered wire, closed
Pipeline, freed Pipeline, duplicate profile registration), rekey blob
refresh, save / load persistence (in memory and through a file),
inspect / lookup / profiles, the worker cap, the GC parent-pin, and
the opts / hex helpers.

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

## eitb utility

```bash
./bindings/r/eitb/eitb version
./bindings/r/eitb/eitb profiles
./bindings/r/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.itb  2> blob.hex
./bindings/r/eitb/eitb inspect "$(cat blob.hex)"
./bindings/r/eitb/eitb decrypt singlemsg-triple-mac-v1 "$(cat blob.hex)" out.itb back.bin
```

`encrypt` prints the session blob (`pipeline_save`) to stderr as hex;
feed that hex back to `decrypt` on the receiving side, which reopens
the session with `pipeline_load` (the profile argument only routes
Single Message versus streaming).

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
- **Profile records are JSON text.** `inspect` / `lookup` return, and
  `register` accepts, the record as the JSON string libitb exchanges;
  the package carries no JSON dependency, so decoding into a list is
  left to the caller's library of choice.
- **Streaming decrypt caveat.** Chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The binding exposes the Triple Pipeline surface only; the Low-Level
  Go-native configuration surface is not exported.
