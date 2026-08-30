/*
 * itb_r.c — R .Call shim over the libitb shared library's Triple
 * Pipeline surface (ITB_Triple_*, cmd/cshared).
 *
 * The shim is a thin proxy: every hash-name / MAC-name / cipher-name
 * / profile-name is an opaque string passed through to Go for
 * validation; no ITB construction logic lives here. Compiled by
 * R CMD INSTALL into the package's shared object and registered via
 * R_registerRoutines (NAMESPACE: useDynLib(itb, .registration = TRUE)).
 *
 * Registered .Call entry points (R-facing wrappers live in R/itb.R):
 *
 *   C_r_version()                      -> character(1)
 *   C_r_hashes()                       -> list(name = chr, width = int)
 *   C_r_profiles()                     -> character vector
 *   C_r_set_memory_limit(num)          -> numeric(1)  previous limit
 *   C_r_set_gc_percent(int)            -> integer(1)  previous percent
 *   C_r_register_profile(chr, chr)     -> NULL
 *   C_r_now()                          -> numeric(1)  monotonic seconds
 *   C_r_pipeline_create(chr, chr)      -> list(ptr = extptr, blob = raw)
 *   C_r_pipeline_open(chr, raw, chr, raw|NULL, raw|NULL) -> extptr
 *   C_r_pipeline_encrypt_message(extptr, raw)  -> raw
 *   C_r_pipeline_decrypt_message(extptr, raw)  -> raw
 *   C_r_pipeline_encrypt_stream_one_shot(extptr, raw) -> raw
 *   C_r_pipeline_decrypt_stream_one_shot(extptr, raw) -> raw
 *   C_r_pipeline_rekey(extptr, raw, raw)       -> raw (refreshed blob)
 *   C_r_pipeline_close(extptr)         -> NULL
 *   C_r_pipeline_free(extptr)          -> NULL (idempotent)
 *   C_r_stream_begin(extptr, lgl)      -> extptr (session)
 *   C_r_stream_write(extptr, raw)      -> NULL
 *   C_r_stream_end(extptr)             -> NULL
 *   C_r_stream_read(extptr, int)       -> list(chunk = raw, finished = lgl)
 *   C_r_stream_read_into(extptr, raw)  -> integer(2): c(n, finished)
 *   C_r_stream_write_slice(extptr, raw, num, num) -> NULL
 *   C_r_stream_drain_all(extptr)       -> raw
 *   C_r_stream_free(extptr)            -> NULL (idempotent)
 *
 * Handles are R external pointers carrying the libitb registry handle
 * in the pointer address slot; a GC finalizer (R_RegisterCFinalizerEx
 * with onexit = TRUE) releases the Go-side object when the R object is
 * collected without an explicit free. A stream session's external
 * pointer stores its parent Pipeline external pointer in the
 * "protected" slot, so the R GC cannot collect (and thereby finalize)
 * the Pipeline while the session is live — the C-level half of the
 * session-parent-pin (the R-level half is the object's `parent` field).
 *
 * Errors are signalled as R conditions of class "itb_error" (fields
 * status / label / message) by evaluating the package-internal helper
 * .itb_raise(status, label, message) inside the itb namespace; see
 * R/errors.R.
 *
 * Output-buffer discipline: variable-size outputs pre-allocate
 * len + len/4 + 65536 bytes (R_alloc scratch, reclaimed on .Call exit)
 * and retry once with the exact reported size when the call returns
 * BUFFER_TOO_SMALL with outLen strictly greater than the offered
 * capacity.
 */

#define R_NO_REMAP

/* clock_gettime / CLOCK_MONOTONIC under -std=c11. */
#define _POSIX_C_SOURCE 200112L

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

#include "libitb.h"

/* Cast a borrowed const input pointer to the non-const void* the cgo
 * header declares; Go copies inputs before returning. */
#define MUT(p) ((void *)(uintptr_t)(const void *)(p))

/* ---- status codes (mirrors cmd/cshared/internal/capi/errors.go) --- */

enum {
    ST_OK = 0,
    ST_BAD_HASH = 1,
    ST_BAD_KEY_BITS = 2,
    ST_BAD_HANDLE = 3,
    ST_BAD_INPUT = 4,
    ST_BUFFER_TOO_SMALL = 5,
    ST_ENCRYPT_FAILED = 6,
    ST_DECRYPT_FAILED = 7,
    ST_SEED_WIDTH_MIX = 8,
    ST_BAD_MAC = 9,
    ST_MAC_FAILURE = 10,
    ST_BLOB_MODE_MISMATCH = 19,
    ST_BLOB_MALFORMED = 20,
    ST_BLOB_VERSION_TOO_NEW = 21,
    ST_BLOB_TOO_MANY_OPTS = 22,
    ST_STREAM_TRUNCATED = 23,
    ST_STREAM_AFTER_FINAL = 24,
    ST_TRIPLE_CLOSED = 25,
    ST_PROFILE_EXISTS = 26,
    ST_INTERNAL = 99,
};

typedef struct {
    int code;
    const char *label; /* human-readable */
} status_row;

static const status_row STATUS_ROWS[] = {
    {ST_OK, "ok"},
    {ST_BAD_HASH, "unknown hash name"},
    {ST_BAD_KEY_BITS, "invalid key bits"},
    {ST_BAD_HANDLE, "invalid handle"},
    {ST_BAD_INPUT, "invalid input"},
    {ST_BUFFER_TOO_SMALL, "output buffer too small"},
    {ST_ENCRYPT_FAILED, "encrypt failed"},
    {ST_DECRYPT_FAILED, "decrypt failed"},
    {ST_SEED_WIDTH_MIX, "seed width mismatch"},
    {ST_BAD_MAC, "unknown MAC name or invalid MAC handle"},
    {ST_MAC_FAILURE, "MAC verification failed"},
    {ST_BLOB_MODE_MISMATCH, "blob mode mismatch"},
    {ST_BLOB_MALFORMED, "malformed state blob"},
    {ST_BLOB_VERSION_TOO_NEW, "blob version too new"},
    {ST_BLOB_TOO_MANY_OPTS, "too many blob export opts"},
    {ST_STREAM_TRUNCATED, "stream truncated before terminator"},
    {ST_STREAM_AFTER_FINAL, "stream chunk after terminator"},
    {ST_TRIPLE_CLOSED, "Triple Pipeline is closed"},
    {ST_PROFILE_EXISTS, "profile name already registered"},
    {ST_INTERNAL, "internal error"},
};

static const char *status_label(int code) {
    size_t i;
    for (i = 0; i < sizeof(STATUS_ROWS) / sizeof(STATUS_ROWS[0]); i++) {
        if (STATUS_ROWS[i].code == code) {
            return STATUS_ROWS[i].label;
        }
    }
    return "unknown status";
}

/* Shipped built-in Triple profile names (mirrors the profile registry
 * in triple/profile.go; the C ABI exposes no profile enumeration). */
static const char *const PROFILE_NAMES[] = {
    "streaming-aead-triple-mac-v1",
    "streaming-noaead-triple-v1",
    "singlemsg-triple-mac-v1",
    "singlemsg-triple-nomac-v1",
    "blob-triple-mac-v1",
    "streaming-aead-triple-mac-mixed-v1",
    "streaming-noaead-triple-mixed-v1",
    "singlemsg-triple-mac-mixed-v1",
    "singlemsg-triple-nomac-mixed-v1",
};

/* ---- error raising ------------------------------------------------ */

/* Copies the ITB_LastError diagnostic (NUL-stripped) into buf. */
static void last_error(char *buf, size_t cap) {
    size_t need = 0;
    int rc;
    buf[0] = '\0';
    rc = ITB_LastError(buf, cap, &need);
    if (rc != ST_OK) {
        buf[0] = '\0';
        return;
    }
    /* NUL-terminated by libitb; need counts the trailing NUL. */
    buf[cap - 1] = '\0';
}

/* Signals an R condition of class "itb_error" via the package-internal
 * helper .itb_raise (R/errors.R). Never returns: stop() inside the
 * helper longjmps past this frame (R restores the protection stack and
 * the R_alloc watermark while unwinding). */
static void raise_status(int rc) {
    char msg[2048];
    SEXP ns, call;
    last_error(msg, sizeof(msg));
    ns = R_FindNamespace(Rf_mkString("itb"));
    PROTECT(ns);
    call = PROTECT(Rf_lang4(Rf_install(".itb_raise"), Rf_ScalarInteger(rc),
                            Rf_mkString(status_label(rc)), Rf_mkString(msg)));
    Rf_eval(call, ns);
    /* Not reached; belt-and-braces if .itb_raise ever returns. */
    UNPROTECT(2);
    Rf_error("itb: %s (status %d): %s", status_label(rc), rc, msg);
}

/* ---- argument helpers ---------------------------------------------- */

static const char *arg_string(SEXP x, const char *what) {
    if (TYPEOF(x) != STRSXP || XLENGTH(x) != 1 ||
        STRING_ELT(x, 0) == NA_STRING) {
        Rf_error("itb: %s must be a single character string", what);
    }
    return CHAR(STRING_ELT(x, 0));
}

static const Rbyte *arg_raw(SEXP x, size_t *len, const char *what) {
    if (TYPEOF(x) != RAWSXP) {
        Rf_error("itb: %s must be a raw vector", what);
    }
    *len = (size_t)XLENGTH(x);
    return RAW(x);
}

static int arg_int(SEXP x, const char *what) {
    if ((TYPEOF(x) != INTSXP && TYPEOF(x) != REALSXP) || XLENGTH(x) != 1) {
        Rf_error("itb: %s must be a single number", what);
    }
    return Rf_asInteger(x);
}

/* ---- external-pointer handles -------------------------------------- */

static SEXP PIPE_TAG;   /* Rf_install("itb_pipeline") */
static SEXP STREAM_TAG; /* Rf_install("itb_stream") */

static void pipe_finalizer(SEXP ptr) {
    uintptr_t handle = (uintptr_t)R_ExternalPtrAddr(ptr);
    if (handle != 0) {
        R_ClearExternalPtr(ptr);
        ITB_Triple_Free(handle);
    }
}

static void stream_finalizer(SEXP ptr) {
    uintptr_t handle = (uintptr_t)R_ExternalPtrAddr(ptr);
    if (handle != 0) {
        R_ClearExternalPtr(ptr);
        ITB_Triple_StreamFree(handle);
    }
}

/* Wraps a libitb handle into a finalized external pointer. `prot` is
 * stored in the pointer's protected slot (the parent pin for stream
 * sessions); pass R_NilValue for pipelines. */
static SEXP make_handle(uintptr_t handle, SEXP tag, SEXP prot,
                        void (*fin)(SEXP)) {
    SEXP ptr = PROTECT(R_MakeExternalPtr((void *)handle, tag, prot));
    R_RegisterCFinalizerEx(ptr, fin, TRUE);
    UNPROTECT(1);
    return ptr;
}

static uintptr_t check_handle(SEXP ptr, SEXP tag, const char *what) {
    uintptr_t handle;
    if (TYPEOF(ptr) != EXTPTRSXP || R_ExternalPtrTag(ptr) != tag) {
        Rf_error("itb: invalid %s handle", what);
    }
    handle = (uintptr_t)R_ExternalPtrAddr(ptr);
    if (handle == 0) {
        Rf_error("itb: %s already freed", what);
    }
    return handle;
}

/* ---- variable-size output helpers ---------------------------------- */

/* Pre-allocation formula for message / one-shot stream outputs. */
static size_t out_cap(size_t payload) {
    size_t cap = payload + payload / 4 + 65536;
    return cap < 65536 ? 65536 : cap;
}

typedef int (*cipher_fn)(uintptr_t, void *, size_t, void *, size_t, size_t *);

/* Runs one buffer-in / buffer-out cipher entry with the retry-once
 * discipline; returns the produced bytes as a raw vector. Scratch
 * space comes from R_alloc, reclaimed automatically when the .Call
 * frame exits (error unwinds included). */
static SEXP cipher_call(cipher_fn fn, uintptr_t handle, const Rbyte *src,
                        size_t srclen) {
    size_t cap = out_cap(srclen);
    int attempt;
    for (attempt = 0; attempt < 2; attempt++) {
        char *buf = R_alloc(cap, 1);
        size_t n = 0;
        int rc = fn(handle, MUT(src), srclen, buf, cap, &n);
        if (rc == ST_BUFFER_TOO_SMALL && n > cap && attempt == 0) {
            cap = n;
            continue;
        }
        if (rc != ST_OK) {
            raise_status(rc);
        }
        {
            SEXP out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)n));
            memcpy(RAW(out), buf, n);
            UNPROTECT(1);
            return out;
        }
    }
    /* Second BUFFER_TOO_SMALL after an exact-size retry — surface it. */
    raise_status(ST_BUFFER_TOO_SMALL);
    return R_NilValue; /* not reached */
}

/* ---- module functions ----------------------------------------------- */

SEXP C_r_version(void) {
    size_t need = 0;
    int rc = ITB_Version(NULL, 0, &need);
    char *buf;
    if (rc != ST_OK && rc != ST_BUFFER_TOO_SMALL) {
        raise_status(rc);
    }
    if (need <= 1) {
        return Rf_mkString("");
    }
    buf = R_alloc(need, 1);
    rc = ITB_Version(buf, need, &need);
    if (rc != ST_OK) {
        raise_status(rc);
    }
    buf[need > 0 ? need - 1 : 0] = '\0';
    return Rf_mkString(buf);
}

SEXP C_r_hashes(void) {
    int count = ITB_HashCount();
    SEXP names = PROTECT(Rf_allocVector(STRSXP, count));
    SEXP widths = PROTECT(Rf_allocVector(INTSXP, count));
    SEXP out, out_names;
    int i;
    for (i = 0; i < count; i++) {
        char name[128];
        size_t n = 0;
        int rc = ITB_HashName(i, name, sizeof(name), &n);
        if (rc != ST_OK) {
            raise_status(rc);
        }
        name[n > 0 ? n - 1 : 0] = '\0';
        SET_STRING_ELT(names, i, Rf_mkChar(name));
        INTEGER(widths)[i] = ITB_HashWidth(i);
    }
    out = PROTECT(Rf_allocVector(VECSXP, 2));
    SET_VECTOR_ELT(out, 0, names);
    SET_VECTOR_ELT(out, 1, widths);
    out_names = PROTECT(Rf_allocVector(STRSXP, 2));
    SET_STRING_ELT(out_names, 0, Rf_mkChar("name"));
    SET_STRING_ELT(out_names, 1, Rf_mkChar("width"));
    Rf_setAttrib(out, R_NamesSymbol, out_names);
    UNPROTECT(4);
    return out;
}

SEXP C_r_profiles(void) {
    const int count = (int)(sizeof(PROFILE_NAMES) / sizeof(PROFILE_NAMES[0]));
    SEXP out = PROTECT(Rf_allocVector(STRSXP, count));
    int i;
    for (i = 0; i < count; i++) {
        SET_STRING_ELT(out, i, Rf_mkChar(PROFILE_NAMES[i]));
    }
    UNPROTECT(1);
    return out;
}

SEXP C_r_set_memory_limit(SEXP limit) {
    double v;
    if ((TYPEOF(limit) != REALSXP && TYPEOF(limit) != INTSXP) ||
        XLENGTH(limit) != 1) {
        Rf_error("itb: limit must be a single number");
    }
    v = Rf_asReal(limit);
    return Rf_ScalarReal((double)ITB_SetMemoryLimit((int64_t)v));
}

SEXP C_r_set_gc_percent(SEXP pct) {
    return Rf_ScalarInteger(ITB_SetGCPercent(arg_int(pct, "pct")));
}

SEXP C_r_register_profile(SEXP name, SEXP opts) {
    int rc = ITB_Triple_RegisterProfile(
        MUT(arg_string(name, "name")), MUT(arg_string(opts, "opts")));
    if (rc != ST_OK) {
        raise_status(rc);
    }
    return R_NilValue;
}

/* Monotonic wall-clock seconds (for benchmarking; proc.time()'s
 * "elapsed" has coarser resolution on some platforms and user+sys
 * over-count the Go runtime's worker threads). */
SEXP C_r_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return Rf_ScalarReal((double)ts.tv_sec + (double)ts.tv_nsec * 1e-9);
}

/* ---- Pipeline lifecycle ---------------------------------------------- */

/* Floor capacity for blob output buffers (Init / Rekey). */
#define BLOB_CAP ((size_t)(64 * 1024))

SEXP C_r_pipeline_create(SEXP profile, SEXP opts) {
    const char *prof = arg_string(profile, "profile");
    const char *o = arg_string(opts, "opts");
    size_t cap = BLOB_CAP;
    int attempt;
    for (attempt = 0; attempt < 2; attempt++) {
        char *buf = R_alloc(cap, 1);
        size_t n = 0;
        uintptr_t handle = 0;
        int rc = ITB_Triple_Init(MUT(prof), MUT(o), buf, cap, &n, &handle);
        if (rc == ST_BUFFER_TOO_SMALL && n > cap && attempt == 0) {
            /* libitb closes the undersized attempt before returning;
             * the retry re-runs Init and yields a fresh session. */
            cap = n;
            continue;
        }
        if (rc != ST_OK) {
            raise_status(rc);
        }
        {
            SEXP blob = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)n));
            SEXP ptr, out, out_names;
            memcpy(RAW(blob), buf, n);
            ptr = PROTECT(
                make_handle(handle, PIPE_TAG, R_NilValue, pipe_finalizer));
            out = PROTECT(Rf_allocVector(VECSXP, 2));
            SET_VECTOR_ELT(out, 0, ptr);
            SET_VECTOR_ELT(out, 1, blob);
            out_names = PROTECT(Rf_allocVector(STRSXP, 2));
            SET_STRING_ELT(out_names, 0, Rf_mkChar("ptr"));
            SET_STRING_ELT(out_names, 1, Rf_mkChar("blob"));
            Rf_setAttrib(out, R_NamesSymbol, out_names);
            UNPROTECT(4);
            return out;
        }
    }
    raise_status(ST_BUFFER_TOO_SMALL);
    return R_NilValue; /* not reached */
}

SEXP C_r_pipeline_open(SEXP profile, SEXP blob, SEXP opts, SEXP perm,
                       SEXP wrap) {
    const char *prof = arg_string(profile, "profile");
    size_t bloblen = 0;
    const Rbyte *blobp = arg_raw(blob, &bloblen, "blob");
    const char *o = arg_string(opts, "opts");
    size_t permlen = 0, wraplen = 0, count = 0;
    const Rbyte *permp = NULL, *wrapp = NULL;
    uintptr_t handle = 0;
    int rc;
    if (perm != R_NilValue || wrap != R_NilValue) {
        permp = arg_raw(perm, &permlen, "perm master");
        wrapp = arg_raw(wrap, &wraplen, "wrap master");
        if (permlen == 0 || wraplen == 0) {
            Rf_error("itb: master override buffers must be non-empty");
        }
        count = 2;
    }
    rc = ITB_Triple_Open(MUT(prof), MUT(blobp), bloblen, MUT(o), MUT(permp),
                         permlen, MUT(wrapp), wraplen, count, &handle);
    if (rc != ST_OK) {
        raise_status(rc);
    }
    return make_handle(handle, PIPE_TAG, R_NilValue, pipe_finalizer);
}

SEXP C_r_pipeline_encrypt_message(SEXP ptr, SEXP plaintext) {
    uintptr_t handle = check_handle(ptr, PIPE_TAG, "pipeline");
    size_t n = 0;
    const Rbyte *src = arg_raw(plaintext, &n, "plaintext");
    return cipher_call(ITB_Triple_EncryptMessage, handle, src, n);
}

SEXP C_r_pipeline_decrypt_message(SEXP ptr, SEXP wire) {
    uintptr_t handle = check_handle(ptr, PIPE_TAG, "pipeline");
    size_t n = 0;
    const Rbyte *src = arg_raw(wire, &n, "wire");
    return cipher_call(ITB_Triple_DecryptMessage, handle, src, n);
}

SEXP C_r_pipeline_encrypt_stream_one_shot(SEXP ptr, SEXP plaintext) {
    uintptr_t handle = check_handle(ptr, PIPE_TAG, "pipeline");
    size_t n = 0;
    const Rbyte *src = arg_raw(plaintext, &n, "plaintext");
    return cipher_call(ITB_Triple_EncryptStream, handle, src, n);
}

SEXP C_r_pipeline_decrypt_stream_one_shot(SEXP ptr, SEXP wire) {
    uintptr_t handle = check_handle(ptr, PIPE_TAG, "pipeline");
    size_t n = 0;
    const Rbyte *src = arg_raw(wire, &n, "wire");
    return cipher_call(ITB_Triple_DecryptStream, handle, src, n);
}

/* Rotates the parallax + wrapper masters; returns the refreshed blob
 * (the R wrapper stores it on the Pipeline object). */
SEXP C_r_pipeline_rekey(SEXP ptr, SEXP perm, SEXP wrap) {
    uintptr_t handle = check_handle(ptr, PIPE_TAG, "pipeline");
    size_t permlen = 0, wraplen = 0;
    const Rbyte *permp = arg_raw(perm, &permlen, "perm master");
    const Rbyte *wrapp = arg_raw(wrap, &wraplen, "wrap master");
    size_t cap = BLOB_CAP;
    int attempt;
    for (attempt = 0; attempt < 2; attempt++) {
        char *buf = R_alloc(cap, 1);
        size_t n = 0;
        int rc = ITB_Triple_Rekey(handle, MUT(permp), permlen, MUT(wrapp),
                                  wraplen, buf, cap, &n);
        if (rc == ST_BUFFER_TOO_SMALL && n > cap && attempt == 0) {
            cap = n;
            continue;
        }
        if (rc != ST_OK) {
            raise_status(rc);
        }
        {
            SEXP blob = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)n));
            memcpy(RAW(blob), buf, n);
            UNPROTECT(1);
            return blob;
        }
    }
    raise_status(ST_BUFFER_TOO_SMALL);
    return R_NilValue; /* not reached */
}

/* Zeroes the key material and marks the Pipeline closed (idempotent
 * Go-side); the handle stays registered until free. */
SEXP C_r_pipeline_close(SEXP ptr) {
    uintptr_t handle = check_handle(ptr, PIPE_TAG, "pipeline");
    int rc = ITB_Triple_Close(handle);
    if (rc != ST_OK) {
        raise_status(rc);
    }
    return R_NilValue;
}

/* Releases the handle (libitb closes and zeroes key material first).
 * Safe to call more than once; also runs as the GC finalizer. */
SEXP C_r_pipeline_free(SEXP ptr) {
    if (TYPEOF(ptr) != EXTPTRSXP || R_ExternalPtrTag(ptr) != PIPE_TAG) {
        Rf_error("itb: invalid pipeline handle");
    }
    pipe_finalizer(ptr);
    return R_NilValue;
}

/* ---- Stream sessions -------------------------------------------------- */

SEXP C_r_stream_begin(SEXP ptr, SEXP encrypt) {
    uintptr_t handle = check_handle(ptr, PIPE_TAG, "pipeline");
    int enc = Rf_asLogical(encrypt);
    uintptr_t sh = 0;
    int rc;
    if (enc == NA_LOGICAL) {
        Rf_error("itb: encrypt flag must be TRUE or FALSE");
    }
    rc = enc ? ITB_Triple_EncryptStreamBegin(handle, &sh)
             : ITB_Triple_DecryptStreamBegin(handle, &sh);
    if (rc != ST_OK) {
        raise_status(rc);
    }
    /* The parent Pipeline external pointer rides in the protected
     * slot: the C-level session-parent-pin. */
    return make_handle(sh, STREAM_TAG, ptr, stream_finalizer);
}

SEXP C_r_stream_write(SEXP ptr, SEXP src) {
    uintptr_t handle = check_handle(ptr, STREAM_TAG, "stream session");
    size_t n = 0;
    const Rbyte *p = arg_raw(src, &n, "data");
    int rc = ITB_Triple_StreamWrite(handle, MUT(p), n);
    if (rc != ST_OK) {
        raise_status(rc);
    }
    return R_NilValue;
}

/* Signals end-of-input. The R wrapper keeps this idempotent via the
 * object's `ended` flag. */
SEXP C_r_stream_end(SEXP ptr) {
    uintptr_t handle = check_handle(ptr, STREAM_TAG, "stream session");
    int rc = ITB_Triple_StreamEnd(handle);
    if (rc != ST_OK) {
        raise_status(rc);
    }
    return R_NilValue;
}

/* Drains up to `max` produced bytes; partial drains are normal and a
 * read before stream_end never blocks. Returns list(chunk, finished). */
SEXP C_r_stream_read(SEXP ptr, SEXP max) {
    uintptr_t handle = check_handle(ptr, STREAM_TAG, "stream session");
    int m = arg_int(max, "max");
    char *buf;
    size_t n = 0;
    int fin = 0;
    int rc;
    SEXP chunk, out, out_names;
    if (m <= 0) {
        Rf_error("itb: max must be positive");
    }
    buf = R_alloc((size_t)m, 1);
    rc = ITB_Triple_StreamRead(handle, buf, (size_t)m, &n, &fin);
    if (rc != ST_OK) {
        raise_status(rc);
    }
    chunk = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)n));
    memcpy(RAW(chunk), buf, n);
    out = PROTECT(Rf_allocVector(VECSXP, 2));
    SET_VECTOR_ELT(out, 0, chunk);
    SET_VECTOR_ELT(out, 1, Rf_ScalarLogical(fin != 0));
    out_names = PROTECT(Rf_allocVector(STRSXP, 2));
    SET_STRING_ELT(out_names, 0, Rf_mkChar("chunk"));
    SET_STRING_ELT(out_names, 1, Rf_mkChar("finished"));
    Rf_setAttrib(out, R_NamesSymbol, out_names);
    UNPROTECT(3);
    return out;
}

/* Drains up to length(buf) produced bytes directly into the caller's
 * scratch RAW vector, written in place — no per-call output
 * allocation beyond the 2-element result vector. The caller must own
 * buf exclusively (a dedicated scratch buffer never shared with other
 * R bindings); in-place mutation deliberately bypasses R's
 * copy-on-write discipline, which is why the R-facing wrapper
 * documents the buffer as scratch-only. Returns integer(2):
 * c(bytes_written, finished_flag). */
SEXP C_r_stream_read_into(SEXP ptr, SEXP buf) {
    uintptr_t handle = check_handle(ptr, STREAM_TAG, "stream session");
    size_t cap, n = 0;
    int fin = 0;
    int rc;
    SEXP out;
    if (TYPEOF(buf) != RAWSXP) {
        Rf_error("itb: buf must be a raw vector");
    }
    cap = (size_t)XLENGTH(buf);
    if (cap == 0) {
        Rf_error("itb: buf must be non-empty");
    }
    rc = ITB_Triple_StreamRead(handle, RAW(buf), cap, &n, &fin);
    if (rc != ST_OK) {
        raise_status(rc);
    }
    out = PROTECT(Rf_allocVector(INTSXP, 2));
    INTEGER(out)[0] = (int)n;
    INTEGER(out)[1] = fin ? 1 : 0;
    UNPROTECT(1);
    return out;
}

/* Feeds src[offset .. offset+len) into the session straight from the
 * source vector's storage — no R-side slice copy (and no index-vector
 * materialisation). offset is zero-based; offset / len arrive as
 * numerics so long vectors stay addressable. */
SEXP C_r_stream_write_slice(SEXP ptr, SEXP src, SEXP offset, SEXP len) {
    uintptr_t handle = check_handle(ptr, STREAM_TAG, "stream session");
    size_t srclen = 0;
    const Rbyte *p = arg_raw(src, &srclen, "data");
    double off_d = Rf_asReal(offset);
    double len_d = Rf_asReal(len);
    size_t off, l;
    int rc;
    if (ISNAN(off_d) || ISNAN(len_d) || off_d < 0 || len_d < 0 ||
        off_d + len_d > (double)srclen) {
        Rf_error("itb: slice [offset=%.0f, len=%.0f) out of bounds "
                 "for %u-byte data",
                 off_d, len_d, (unsigned)srclen);
    }
    off = (size_t)off_d;
    l = (size_t)len_d;
    rc = ITB_Triple_StreamWrite(handle, MUT(p + off), l);
    if (rc != ST_OK) {
        raise_status(rc);
    }
    return R_NilValue;
}

/* Drains every remaining output byte into one raw vector. The R
 * wrapper calls stream_end first; this only loops reads. Chunks are
 * accumulated as raw vectors on a protected pairlist, then
 * concatenated. */
SEXP C_r_stream_drain_all(SEXP ptr) {
    uintptr_t handle = check_handle(ptr, STREAM_TAG, "stream session");
    const size_t step = (size_t)1 << 20;
    SEXP acc = R_NilValue;
    PROTECT_INDEX acc_idx;
    size_t total = 0;
    SEXP out, cell;
    char *dst;
    PROTECT_WITH_INDEX(acc, &acc_idx);
    for (;;) {
        char *buf = R_alloc(step, 1);
        size_t n = 0;
        int fin = 0;
        int rc = ITB_Triple_StreamRead(handle, buf, step, &n, &fin);
        if (rc != ST_OK) {
            raise_status(rc);
        }
        if (n > 0) {
            SEXP chunk = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)n));
            memcpy(RAW(chunk), buf, n);
            /* Prepend (reversed below by back-to-front copy order). */
            REPROTECT(acc = Rf_cons(chunk, acc), acc_idx);
            UNPROTECT(1); /* chunk now reachable through acc */
            total += n;
        }
        if (fin) {
            break;
        }
    }
    out = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)total));
    dst = (char *)RAW(out) + total;
    for (cell = acc; cell != R_NilValue; cell = CDR(cell)) {
        SEXP chunk = CAR(cell);
        size_t n = (size_t)XLENGTH(chunk);
        dst -= n;
        memcpy(dst, RAW(chunk), n);
    }
    UNPROTECT(2);
    return out;
}

/* Cancels (if still running) and releases the session. Safe from any
 * state and more than once; also runs as the GC finalizer. */
SEXP C_r_stream_free(SEXP ptr) {
    if (TYPEOF(ptr) != EXTPTRSXP || R_ExternalPtrTag(ptr) != STREAM_TAG) {
        Rf_error("itb: invalid stream session handle");
    }
    stream_finalizer(ptr);
    return R_NilValue;
}

/* ---- registration ----------------------------------------------------- */

#define CALLDEF(name, n) {#name, (DL_FUNC)&name, n}

static const R_CallMethodDef CALL_DEFS[] = {
    CALLDEF(C_r_version, 0),
    CALLDEF(C_r_hashes, 0),
    CALLDEF(C_r_profiles, 0),
    CALLDEF(C_r_set_memory_limit, 1),
    CALLDEF(C_r_set_gc_percent, 1),
    CALLDEF(C_r_register_profile, 2),
    CALLDEF(C_r_now, 0),
    CALLDEF(C_r_pipeline_create, 2),
    CALLDEF(C_r_pipeline_open, 5),
    CALLDEF(C_r_pipeline_encrypt_message, 2),
    CALLDEF(C_r_pipeline_decrypt_message, 2),
    CALLDEF(C_r_pipeline_encrypt_stream_one_shot, 2),
    CALLDEF(C_r_pipeline_decrypt_stream_one_shot, 2),
    CALLDEF(C_r_pipeline_rekey, 3),
    CALLDEF(C_r_pipeline_close, 1),
    CALLDEF(C_r_pipeline_free, 1),
    CALLDEF(C_r_stream_begin, 2),
    CALLDEF(C_r_stream_write, 2),
    CALLDEF(C_r_stream_end, 1),
    CALLDEF(C_r_stream_read, 2),
    CALLDEF(C_r_stream_read_into, 2),
    CALLDEF(C_r_stream_write_slice, 4),
    CALLDEF(C_r_stream_drain_all, 1),
    CALLDEF(C_r_stream_free, 1),
    {NULL, NULL, 0},
};

void R_init_itb(DllInfo *dll);

void R_init_itb(DllInfo *dll) {
    PIPE_TAG = Rf_install("itb_pipeline");
    STREAM_TAG = Rf_install("itb_stream");
    R_registerRoutines(dll, NULL, CALL_DEFS, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
}
