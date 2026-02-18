/* fuzz_crypto.cpp — Hash and HMAC operations fuzzer (direct C API).
   Covers: _md5, _sha1, _sha2, _sha3, _blake2, _hmac, hashlib.
   Uses FuzzedDataProvider for structured input consumption.

   Hash/HMAC targets chain multiple actions (update, digest, copy, ...)
   on a single object per iteration.  One-shot targets (pbkdf2,
   file_digest, compare_digest, _hmac.compute_*) run a single call. */

#include <Python.h>
#include <stdlib.h>
#include <assert.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
int __lsan_is_turned_off(void) { return 1; }

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    PyConfig config;
    PyConfig_InitPythonConfig(&config);
    config.install_signal_handlers = 0;
    config.int_max_str_digits = 8086;
    PyStatus status;
    status = PyConfig_SetBytesString(&config, &config.program_name, *argv[0]);
    if (PyStatus_Exception(status)) goto fail;
    status = Py_InitializeFromConfig(&config);
    if (PyStatus_Exception(status)) goto fail;
    PyConfig_Clear(&config);
    return 0;
fail:
    PyConfig_Clear(&config);
    Py_ExitStatusException(status);
}
} /* extern "C" */

/* RAII wrapper for PyObject*. */
struct PyRef {
    PyObject *p;
    PyRef(PyObject *o = nullptr) : p(o) {}
    ~PyRef() { Py_XDECREF(p); }
    operator PyObject*() const { return p; }
    explicit operator bool() const { return p != nullptr; }
    PyRef(const PyRef &) = delete;
    PyRef &operator=(const PyRef &) = delete;
};

#define CHECK(x) do { if (!(x)) { PyErr_Clear(); return; } } while(0)
#define Y(s) (s).data(), (Py_ssize_t)(s).size()

/* ===================================================================
   Cached module objects, initialized once.
   =================================================================== */

static PyObject *ctor_md5, *ctor_sha1;
static PyObject *ctor_sha224, *ctor_sha256, *ctor_sha384, *ctor_sha512;
static PyObject *ctor_sha3_224, *ctor_sha3_256, *ctor_sha3_384, *ctor_sha3_512;
static PyObject *ctor_shake_128, *ctor_shake_256;
static PyObject *ctor_blake2b, *ctor_blake2s;

static PyObject **all_hash_ctors[] = {
    &ctor_md5, &ctor_sha1, &ctor_sha224, &ctor_sha256,
    &ctor_sha384, &ctor_sha512, &ctor_sha3_224, &ctor_sha3_256,
    &ctor_sha3_384, &ctor_sha3_512, &ctor_blake2b, &ctor_blake2s,
};
static constexpr int NUM_HASH_CTORS = sizeof(all_hash_ctors) / sizeof(all_hash_ctors[0]);

static PyObject **shake_ctors[] = { &ctor_shake_128, &ctor_shake_256 };
static constexpr int NUM_SHAKE_CTORS = 2;

static PyObject *hmac_compute_funcs[4];
static int num_hmac_compute_funcs = 0;

static PyObject *hashlib_new, *hashlib_pbkdf2_hmac, *hashlib_file_digest;
static PyObject *py_hmac_new, *py_hmac_digest, *py_hmac_compare_digest;
static PyObject *bytesio_ctor;

static const char *hmac_algos[] = {
    "md5", "sha224", "sha256", "sha384", "sha512", "sha3_256", "blake2s",
};
static constexpr int NUM_HMAC_ALGOS = sizeof(hmac_algos) / sizeof(hmac_algos[0]);

static const char *pbkdf2_algos[] = { "sha1", "sha256", "sha512" };
static constexpr int NUM_PBKDF2_ALGOS = 3;

static const char *hashlib_algos[] = { "md5", "sha256", "sha3_256", "sha512" };
static constexpr int NUM_HASHLIB_ALGOS = 4;

static unsigned long gc_counter = 0;
#define GC_INTERVAL 200

static PyObject *import_attr(const char *mod, const char *attr) {
    PyObject *m = PyImport_ImportModule(mod);
    if (!m) { PyErr_Print(); abort(); }
    PyObject *a = PyObject_GetAttrString(m, attr);
    Py_DECREF(m);
    if (!a) { PyErr_Print(); abort(); }
    return a;
}

static int initialized = 0;

static void init_crypto(void) {
    if (initialized) return;

    struct { PyObject **dest; const char *mod, *attr; } inits[] = {
        {&ctor_md5, "_md5", "md5"}, {&ctor_sha1, "_sha1", "sha1"},
        {&ctor_sha224, "_sha2", "sha224"}, {&ctor_sha256, "_sha2", "sha256"},
        {&ctor_sha384, "_sha2", "sha384"}, {&ctor_sha512, "_sha2", "sha512"},
        {&ctor_sha3_224, "_sha3", "sha3_224"}, {&ctor_sha3_256, "_sha3", "sha3_256"},
        {&ctor_sha3_384, "_sha3", "sha3_384"}, {&ctor_sha3_512, "_sha3", "sha3_512"},
        {&ctor_shake_128, "_sha3", "shake_128"}, {&ctor_shake_256, "_sha3", "shake_256"},
        {&ctor_blake2b, "_blake2", "blake2b"}, {&ctor_blake2s, "_blake2", "blake2s"},
    };
    for (auto &i : inits)
        *i.dest = import_attr(i.mod, i.attr);

    PyObject *hmac_mod = PyImport_ImportModule("_hmac");
    if (hmac_mod) {
        const char *names[] = { "compute_md5", "compute_sha1",
                                "compute_sha256", "compute_sha512" };
        for (auto name : names) {
            PyObject *fn = PyObject_GetAttrString(hmac_mod, name);
            if (fn) hmac_compute_funcs[num_hmac_compute_funcs++] = fn;
            else PyErr_Clear();
        }
        Py_DECREF(hmac_mod);
    } else {
        PyErr_Clear();
    }

    hashlib_new = import_attr("hashlib", "new");
    hashlib_pbkdf2_hmac = import_attr("hashlib", "pbkdf2_hmac");
    hashlib_file_digest = import_attr("hashlib", "file_digest");
    py_hmac_new = import_attr("hmac", "new");
    py_hmac_digest = import_attr("hmac", "digest");
    py_hmac_compare_digest = import_attr("hmac", "compare_digest");
    bytesio_ctor = import_attr("io", "BytesIO");

    assert(!PyErr_Occurred());
    initialized = 1;
}

/* ===================================================================
   Chained action loop — shared by hash, hmac, and hashlib targets.
   Takes a borrowed reference to a hash-like object (supports
   .update, .digest, .hexdigest, .copy, .name, .digest_size).
   =================================================================== */

static void chain_hash_actions(PyObject *h, FuzzedDataProvider &fdp) {
    for (int i = 0; fdp.remaining_bytes() > 0 && i < 100; i++) {
        switch (fdp.ConsumeIntegralInRange<int>(0, 4)) {
        case 0: { /* .update(data) */
            std::string data = fdp.ConsumeBytesAsString(
                fdp.ConsumeIntegralInRange<size_t>(0,
                    std::min(fdp.remaining_bytes(), (size_t)10000)));
            PyRef r = PyObject_CallMethod(h, "update", "y#", Y(data)); CHECK(r);
            break;
        }
        case 1: { PyRef d = PyObject_CallMethod(h, "digest", NULL);    CHECK(d); break; }
        case 2: { PyRef d = PyObject_CallMethod(h, "hexdigest", NULL); CHECK(d); break; }
        case 3: { /* .copy().digest() */
            PyRef h2 = PyObject_CallMethod(h, "copy", NULL);  CHECK(h2);
            PyRef d = PyObject_CallMethod(h2, "digest", NULL); CHECK(d);
            break;
        }
        case 4: { /* .name, .digest_size, .block_size */
            PyRef n  = PyObject_GetAttrString(h, "name");        CHECK(n);
            PyRef ds = PyObject_GetAttrString(h, "digest_size"); CHECK(ds);
            PyRef bs = PyObject_GetAttrString(h, "block_size");  CHECK(bs);
            break;
        }
        }
    }
    if (PyErr_Occurred()) PyErr_Clear();
}

/* ===================================================================
   Operations.
   =================================================================== */

/* Create hash from C module ctor, then chain actions. */
static void op_hash_chain(PyObject *ctor, FuzzedDataProvider &fdp) {
    std::string init = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(0, 10000));
    PyRef h = PyObject_CallFunction(ctor, "y#", Y(init)); CHECK(h);
    chain_hash_actions(h, fdp);
}

/* SHAKE: chain update + variable-length digest. */
static void op_shake_chain(PyObject *ctor, FuzzedDataProvider &fdp) {
    std::string init = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(0, 10000));
    PyRef h = PyObject_CallFunction(ctor, "y#", Y(init)); CHECK(h);
    for (int i = 0; fdp.remaining_bytes() > 0 && i < 100; i++) {
        switch (fdp.ConsumeIntegralInRange<int>(0, 2)) {
        case 0: {
            std::string data = fdp.ConsumeBytesAsString(
                fdp.ConsumeIntegralInRange<size_t>(0,
                    std::min(fdp.remaining_bytes(), (size_t)10000)));
            PyRef r = PyObject_CallMethod(h, "update", "y#", Y(data)); CHECK(r);
            break;
        }
        case 1: {
            int len = fdp.ConsumeIntegralInRange<int>(1, 10000);
            PyRef d = PyObject_CallMethod(h, "digest", "i", len); CHECK(d);
            break;
        }
        case 2: {
            PyRef h2 = PyObject_CallMethod(h, "copy", NULL);  CHECK(h2);
            int len = fdp.ConsumeIntegralInRange<int>(1, 10000);
            PyRef d = PyObject_CallMethod(h2, "digest", "i", len); CHECK(d);
            break;
        }
        }
    }
    if (PyErr_Occurred()) PyErr_Clear();
}

/* blake2(data, key=, salt=, person=) then chain. */
static void op_blake2_keyed(PyObject *ctor, int max_key, int max_salt,
                            int max_person, FuzzedDataProvider &fdp) {
    std::string key = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(0, max_key));
    std::string salt = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(0, max_salt));
    std::string person = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(0, max_person));
    std::string data = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(0, 10000));

    PyRef kwargs = PyDict_New();                     CHECK(kwargs);
    PyRef k = PyBytes_FromStringAndSize(Y(key));     CHECK(k);
    PyRef s = PyBytes_FromStringAndSize(Y(salt));    CHECK(s);
    PyRef p = PyBytes_FromStringAndSize(Y(person));  CHECK(p);
    PyDict_SetItemString(kwargs, "key", k);
    PyDict_SetItemString(kwargs, "salt", s);
    PyDict_SetItemString(kwargs, "person", p);

    PyRef d = PyBytes_FromStringAndSize(Y(data));              CHECK(d);
    PyRef args = PyTuple_Pack(1, (PyObject *)d);               CHECK(args);
    PyRef h = PyObject_Call(ctor, args, kwargs);               CHECK(h);
    chain_hash_actions(h, fdp);
}

/* blake2(data, digest_size=N) then chain. */
static void op_blake2_vardigest(PyObject *ctor, int max_ds,
                                FuzzedDataProvider &fdp) {
    int ds = fdp.ConsumeIntegralInRange<int>(1, max_ds);
    std::string data = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(0, 10000));

    PyRef kwargs = PyDict_New();                               CHECK(kwargs);
    PyRef dsobj = PyLong_FromLong(ds);                         CHECK(dsobj);
    PyDict_SetItemString(kwargs, "digest_size", dsobj);

    PyRef d = PyBytes_FromStringAndSize(Y(data));              CHECK(d);
    PyRef args = PyTuple_Pack(1, (PyObject *)d);               CHECK(args);
    PyRef h = PyObject_Call(ctor, args, kwargs);               CHECK(h);
    chain_hash_actions(h, fdp);
}

/* _hmac.compute_*(key, msg) — one-shot. */
static void op_hmac_compute(PyObject *func, FuzzedDataProvider &fdp) {
    std::string key = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(1, 10000));
    if (key.empty()) key.push_back('\x00');
    std::string msg = fdp.ConsumeRemainingBytesAsString();
    PyRef r = PyObject_CallFunction(func, "y#y#", Y(key), Y(msg));
    if (PyErr_Occurred()) PyErr_Clear();
}

/* hmac.new(key, digestmod=algo), then chain actions. */
static void op_pyhmac_chain(const char *algo, FuzzedDataProvider &fdp) {
    std::string key = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(1, 10000));
    if (key.empty()) key.push_back('\x00');

    PyRef kwargs = PyDict_New();                               CHECK(kwargs);
    PyRef dm = PyUnicode_FromString(algo);                     CHECK(dm);
    PyDict_SetItemString(kwargs, "digestmod", dm);
    PyRef kb = PyBytes_FromStringAndSize(Y(key));              CHECK(kb);
    PyRef args = PyTuple_Pack(1, (PyObject *)kb);              CHECK(args);
    PyRef h = PyObject_Call(py_hmac_new, args, kwargs);        CHECK(h);
    chain_hash_actions(h, fdp);
}

/* hmac.digest(key, msg, "sha256") — one-shot. */
static void op_hmac_digest(FuzzedDataProvider &fdp) {
    std::string key = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(1, 10000));
    if (key.empty()) key.push_back('\x00');
    std::string msg = fdp.ConsumeRemainingBytesAsString();
    PyRef r = PyObject_CallFunction(py_hmac_digest, "y#y#s",
        Y(key), Y(msg), "sha256");
    if (PyErr_Occurred()) PyErr_Clear();
}

/* hmac.compare_digest — one-shot. */
static void op_hmac_compare(FuzzedDataProvider &fdp) {
    std::string data = fdp.ConsumeRemainingBytesAsString();
    PyRef h = PyObject_CallFunction(py_hmac_new, "sy#s",
        "k", Y(data), "sha256");                              CHECK(h);
    PyRef dig = PyObject_CallMethod(h, "digest", NULL);        CHECK(dig);
    char padded[32] = {};
    memcpy(padded, data.data(), data.size() < 32 ? data.size() : 32);
    PyRef padobj = PyBytes_FromStringAndSize(padded, 32);      CHECK(padobj);
    PyRef r = PyObject_CallFunction(py_hmac_compare_digest, "OO",
        (PyObject *)dig, (PyObject *)padobj);
    if (PyErr_Occurred()) PyErr_Clear();
}

/* hashlib.new(algo, usedforsecurity=False), then chain actions. */
static void op_hashlib_chain(const char *algo, FuzzedDataProvider &fdp) {
    std::string init = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(0, 10000));
    PyRef kwargs = PyDict_New();                               CHECK(kwargs);
    PyDict_SetItemString(kwargs, "usedforsecurity", Py_False);
    PyRef name = PyUnicode_FromString(algo);                   CHECK(name);
    PyRef d = PyBytes_FromStringAndSize(Y(init));              CHECK(d);
    PyRef args = PyTuple_Pack(2, (PyObject *)name, (PyObject *)d); CHECK(args);
    PyRef h = PyObject_Call(hashlib_new, args, kwargs);        CHECK(h);
    chain_hash_actions(h, fdp);
}

/* hashlib.file_digest(BytesIO(data), algo) — one-shot. */
static void op_hashlib_file_digest(const char *algo, FuzzedDataProvider &fdp) {
    std::string data = fdp.ConsumeRemainingBytesAsString();
    PyRef bio = PyObject_CallFunction(bytesio_ctor, "y#", Y(data)); CHECK(bio);
    PyRef h = PyObject_CallFunction(hashlib_file_digest, "Os",
        (PyObject *)bio, algo);                                CHECK(h);
    PyRef r = PyObject_CallMethod(h, "hexdigest", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
}

/* hashlib.pbkdf2_hmac(algo, pw, salt, 1) — one-shot. */
static void op_pbkdf2(const char *algo, FuzzedDataProvider &fdp) {
    std::string salt = fdp.ConsumeBytesAsString(
        fdp.ConsumeIntegralInRange<size_t>(1, 10000));
    if (salt.empty()) salt.push_back('\x00');
    std::string pw = fdp.ConsumeRemainingBytesAsString();
    PyRef r = PyObject_CallFunction(hashlib_pbkdf2_hmac, "sy#y#i",
        algo, Y(pw), Y(salt), 1);
    if (PyErr_Occurred()) PyErr_Clear();
}

/* ===================================================================
   Dispatch.
   =================================================================== */

enum Op {
    OP_HASH_CHAIN, OP_SHAKE_CHAIN,
    OP_BLAKE2B_KEYED, OP_BLAKE2S_KEYED,
    OP_BLAKE2B_VARDIGEST, OP_BLAKE2S_VARDIGEST,
    OP_HMAC_COMPUTE, OP_PYHMAC_CHAIN,
    OP_HMAC_DIGEST, OP_HMAC_COMPARE,
    OP_HASHLIB_CHAIN, OP_HASHLIB_FILE_DIGEST, OP_PBKDF2,
    NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    assert(Py_IsInitialized());
    init_crypto();
    if (size < 1 || size > 0x100000) return 0;
    if (PyErr_Occurred()) PyErr_Clear();

    FuzzedDataProvider fdp(data, size);
    switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_HASH_CHAIN: {
        int ci = fdp.ConsumeIntegralInRange<int>(0, NUM_HASH_CTORS - 1);
        op_hash_chain(*all_hash_ctors[ci], fdp); break;
    }
    case OP_SHAKE_CHAIN: {
        int ci = fdp.ConsumeIntegralInRange<int>(0, NUM_SHAKE_CTORS - 1);
        op_shake_chain(*shake_ctors[ci], fdp); break;
    }
    case OP_BLAKE2B_KEYED:    op_blake2_keyed(ctor_blake2b, 64, 16, 16, fdp); break;
    case OP_BLAKE2S_KEYED:    op_blake2_keyed(ctor_blake2s, 32, 8, 8, fdp); break;
    case OP_BLAKE2B_VARDIGEST: op_blake2_vardigest(ctor_blake2b, 64, fdp); break;
    case OP_BLAKE2S_VARDIGEST: op_blake2_vardigest(ctor_blake2s, 32, fdp); break;
    case OP_HMAC_COMPUTE:
        if (num_hmac_compute_funcs > 0) {
            int fi = fdp.ConsumeIntegralInRange<int>(0, num_hmac_compute_funcs - 1);
            op_hmac_compute(hmac_compute_funcs[fi], fdp);
        }
        break;
    case OP_PYHMAC_CHAIN: {
        int ai = fdp.ConsumeIntegralInRange<int>(0, NUM_HMAC_ALGOS - 1);
        op_pyhmac_chain(hmac_algos[ai], fdp); break;
    }
    case OP_HMAC_DIGEST:      op_hmac_digest(fdp); break;
    case OP_HMAC_COMPARE:     op_hmac_compare(fdp); break;
    case OP_HASHLIB_CHAIN: {
        int ai = fdp.ConsumeIntegralInRange<int>(0, NUM_HASHLIB_ALGOS - 1);
        op_hashlib_chain(hashlib_algos[ai], fdp); break;
    }
    case OP_HASHLIB_FILE_DIGEST: {
        int ai = fdp.ConsumeIntegralInRange<int>(0, NUM_HASHLIB_ALGOS - 1);
        op_hashlib_file_digest(hashlib_algos[ai], fdp); break;
    }
    case OP_PBKDF2: {
        int ai = fdp.ConsumeIntegralInRange<int>(0, NUM_PBKDF2_ALGOS - 1);
        op_pbkdf2(pbkdf2_algos[ai], fdp); break;
    }
    }

    if (++gc_counter % GC_INTERVAL == 0) PyGC_Collect();
    return 0;
}
