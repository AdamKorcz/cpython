/* fuzz_decode.cpp — Binary decoders / deserializers fuzzer (direct C API).
   Covers: zlib, _bz2, _lzma, binascii, _pickle, _ssl,
           _multibytecodec, _codecs_cn, _codecs_hk, _codecs_iso2022,
           _codecs_jp, _codecs_kr, _codecs_tw, codecs, io.
   Uses FuzzedDataProvider for structured input consumption. */

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

struct PyRef {
    PyObject *p;
    PyRef(PyObject *o = nullptr) : p(o) {}
    ~PyRef() { Py_XDECREF(p); }
    operator PyObject*() const { return p; }
    explicit operator bool() const { return p != nullptr; }
    PyRef(const PyRef &) = delete;
    PyRef &operator=(const PyRef &) = delete;
    PyRef(PyRef &&o) : p(o.p) { o.p = nullptr; }
    PyRef &operator=(PyRef &&o) { Py_XDECREF(p); p = o.p; o.p = nullptr; return *this; }
};

#define CHECK(x) do { if (!(x)) { PyErr_Clear(); return; } } while(0)
#define Y(s) (s).data(), (Py_ssize_t)(s).size()

/* ===================================================================
   Cached module objects, initialized once.
   =================================================================== */

static PyObject *import_attr(const char *mod, const char *attr) {
    PyObject *m = PyImport_ImportModule(mod);
    if (!m) { PyErr_Print(); abort(); }
    PyObject *a = PyObject_GetAttrString(m, attr);
    Py_DECREF(m);
    if (!a) { PyErr_Print(); abort(); }
    return a;
}

/* zlib */
static PyObject *zlib_compress, *zlib_decompress, *zlib_decompressobj, *zlib_compressobj;
static PyObject *zlib_crc32, *zlib_adler32;

/* bz2 */
static PyObject *bz2_compress, *bz2_BZ2Decompressor;

/* lzma */
static PyObject *lzma_LZMADecompressor, *lzma_compress;
static long lzma_FORMAT_AUTO_val, lzma_FORMAT_XZ_val, lzma_FORMAT_ALONE_val;

/* binascii */
static PyObject *ba_a2b_base64, *ba_a2b_hex, *ba_a2b_uu, *ba_a2b_qp;
static PyObject *ba_a2b_ascii85, *ba_a2b_base85;
static PyObject *ba_b2a_base64, *ba_b2a_hex, *ba_b2a_uu, *ba_b2a_qp;
static PyObject *ba_b2a_ascii85, *ba_b2a_base85;
static PyObject *ba_crc32, *ba_crc_hqx, *ba_hexlify, *ba_unhexlify;

/* pickle */
static PyObject *pickle_dumps, *pickle_loads;

/* codecs */
static PyObject *codecs_decode, *codecs_encode;
static PyObject *codecs_getincrementaldecoder, *codecs_getincrementalencoder;
static PyObject *codecs_getreader;

/* ssl */
static PyObject *ssl_DER_cert_to_PEM_cert, *ssl_SSLContext;
static long ssl_PROTOCOL_TLS_CLIENT_val;

/* io */
static PyObject *bytesio_ctor;

/* pickle helper classes */
static PyObject *RestrictedUnpickler_cls, *PersistentUnpickler_cls;

static unsigned long gc_counter = 0;
#define GC_INTERVAL 200

static int initialized = 0;

static void init_decode(void) {
    if (initialized) return;

    /* zlib */
    zlib_compress = import_attr("zlib", "compress");
    zlib_decompress = import_attr("zlib", "decompress");
    zlib_decompressobj = import_attr("zlib", "decompressobj");
    zlib_compressobj = import_attr("zlib", "compressobj");
    zlib_crc32 = import_attr("zlib", "crc32");
    zlib_adler32 = import_attr("zlib", "adler32");

    /* bz2 */
    bz2_compress = import_attr("bz2", "compress");
    bz2_BZ2Decompressor = import_attr("bz2", "BZ2Decompressor");

    /* lzma */
    lzma_LZMADecompressor = import_attr("lzma", "LZMADecompressor");
    lzma_compress = import_attr("lzma", "compress");
    {
        PyObject *v;
        v = import_attr("lzma", "FORMAT_AUTO");
        lzma_FORMAT_AUTO_val = PyLong_AsLong(v); Py_DECREF(v);
        v = import_attr("lzma", "FORMAT_XZ");
        lzma_FORMAT_XZ_val = PyLong_AsLong(v); Py_DECREF(v);
        v = import_attr("lzma", "FORMAT_ALONE");
        lzma_FORMAT_ALONE_val = PyLong_AsLong(v); Py_DECREF(v);
    }

    /* binascii */
    ba_a2b_base64 = import_attr("binascii", "a2b_base64");
    ba_a2b_hex = import_attr("binascii", "a2b_hex");
    ba_a2b_uu = import_attr("binascii", "a2b_uu");
    ba_a2b_qp = import_attr("binascii", "a2b_qp");
    ba_a2b_ascii85 = import_attr("binascii", "a2b_ascii85");
    ba_a2b_base85 = import_attr("binascii", "a2b_base85");
    ba_b2a_base64 = import_attr("binascii", "b2a_base64");
    ba_b2a_hex = import_attr("binascii", "b2a_hex");
    ba_b2a_uu = import_attr("binascii", "b2a_uu");
    ba_b2a_qp = import_attr("binascii", "b2a_qp");
    ba_b2a_ascii85 = import_attr("binascii", "b2a_ascii85");
    ba_b2a_base85 = import_attr("binascii", "b2a_base85");
    ba_crc32 = import_attr("binascii", "crc32");
    ba_crc_hqx = import_attr("binascii", "crc_hqx");
    ba_hexlify = import_attr("binascii", "hexlify");
    ba_unhexlify = import_attr("binascii", "unhexlify");

    /* pickle */
    pickle_dumps = import_attr("pickle", "dumps");
    pickle_loads = import_attr("pickle", "loads");

    /* codecs */
    codecs_decode = import_attr("codecs", "decode");
    codecs_encode = import_attr("codecs", "encode");
    codecs_getincrementaldecoder = import_attr("codecs", "getincrementaldecoder");
    codecs_getincrementalencoder = import_attr("codecs", "getincrementalencoder");
    codecs_getreader = import_attr("codecs", "getreader");

    /* ssl */
    ssl_DER_cert_to_PEM_cert = import_attr("ssl", "DER_cert_to_PEM_cert");
    ssl_SSLContext = import_attr("ssl", "SSLContext");
    {
        PyObject *v = import_attr("ssl", "PROTOCOL_TLS_CLIENT");
        ssl_PROTOCOL_TLS_CLIENT_val = PyLong_AsLong(v); Py_DECREF(v);
    }

    /* io */
    bytesio_ctor = import_attr("io", "BytesIO");

    /* Suppress warnings */
    PyRun_SimpleString("import warnings; warnings.filterwarnings('ignore')");

    /* pickle helper classes via PyRun_String */
    {
        PyObject *globals = PyDict_New();
        PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins());
        PyObject *r = PyRun_String(
            "import pickle, io\n"
            "class RestrictedUnpickler(pickle.Unpickler):\n"
            "    def find_class(self, module, name):\n"
            "        raise pickle.UnpicklingError('restricted')\n"
            "class PersistentUnpickler(pickle.Unpickler):\n"
            "    def persistent_load(self, pid): return pid\n"
            "    def find_class(self, module, name):\n"
            "        raise pickle.UnpicklingError('restricted')\n",
            Py_file_input, globals, globals);
        if (!r) { PyErr_Print(); abort(); }
        Py_DECREF(r);
        RestrictedUnpickler_cls = PyDict_GetItemString(globals, "RestrictedUnpickler");
        Py_INCREF(RestrictedUnpickler_cls);
        PersistentUnpickler_cls = PyDict_GetItemString(globals, "PersistentUnpickler");
        Py_INCREF(PersistentUnpickler_cls);
        Py_DECREF(globals);
    }

    assert(!PyErr_Occurred());
    initialized = 1;
}

/* ===================================================================
   Operations — Compression
   =================================================================== */

static void op_zlib_decompress(FuzzedDataProvider &fdp) {
    static const int wbits_choices[] = {-15, 0, 15, 31, 47};
    int wbits = wbits_choices[fdp.ConsumeIntegralInRange<int>(0, 4)];
    bool use_zdict = fdp.ConsumeBool();
    std::string data = fdp.ConsumeRemainingBytesAsString();

    PyRef kwargs = PyDict_New(); CHECK(kwargs);
    PyRef wbits_obj = PyLong_FromLong(wbits); CHECK(wbits_obj);
    PyRef args_dobj = PyTuple_Pack(1, (PyObject *)wbits_obj); CHECK(args_dobj);

    if (use_zdict && data.size() > 32) {
        PyRef zdict = PyBytes_FromStringAndSize(data.data(), 32);
        CHECK(zdict);
        PyDict_SetItemString(kwargs, "zdict", zdict);
        data = data.substr(32);
    }

    PyRef dobj = PyObject_Call(zlib_decompressobj, args_dobj, kwargs);
    CHECK(dobj);

    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);
    PyRef r = PyObject_CallMethod(dobj, "decompress", "Oi",
        (PyObject *)pydata, 1048576);
    if (!r) { PyErr_Clear(); return; }

    if (fdp.remaining_bytes() > 0 || data.size() % 2 == 0) {
        PyRef flush_r = PyObject_CallMethod(dobj, "flush", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
    }

    if (data.size() % 3 == 0) {
        PyRef copy_obj = PyObject_CallMethod(dobj, "copy", NULL);
        if (copy_obj) {
            PyRef r2 = PyObject_CallMethod(copy_obj, "decompress", "Oi",
                (PyObject *)pydata, 1048576);
            if (PyErr_Occurred()) PyErr_Clear();
        } else {
            PyErr_Clear();
        }
    }
}

static void op_zlib_compress(FuzzedDataProvider &fdp) {
    int level = fdp.ConsumeIntegralInRange<int>(0, 9);
    bool use_obj = fdp.ConsumeBool();
    std::string data = fdp.ConsumeBytesAsString(
        std::min(fdp.remaining_bytes(), (size_t)10000));

    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);

    if (use_obj) {
        PyRef cobj = PyObject_CallFunction(zlib_compressobj, "i", level);
        CHECK(cobj);
        PyRef r1 = PyObject_CallMethod(cobj, "compress", "O", (PyObject *)pydata);
        CHECK(r1);
        if (data.size() % 2 == 0) {
            PyRef copy_obj = PyObject_CallMethod(cobj, "copy", NULL);
            if (copy_obj) {
                PyRef r2 = PyObject_CallMethod(copy_obj, "flush", NULL);
                if (PyErr_Occurred()) PyErr_Clear();
            } else {
                PyErr_Clear();
            }
        }
        PyRef r3 = PyObject_CallMethod(cobj, "flush", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
    } else {
        PyRef r = PyObject_CallFunction(zlib_compress, "Oi",
            (PyObject *)pydata, level);
        if (PyErr_Occurred()) PyErr_Clear();
    }
}

static void op_zlib_checksum(FuzzedDataProvider &fdp) {
    bool use_crc = fdp.ConsumeBool();
    std::string data = fdp.ConsumeRemainingBytesAsString();
    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);
    PyRef r = PyObject_CallFunction(use_crc ? zlib_crc32 : zlib_adler32,
        "O", (PyObject *)pydata);
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_bz2(FuzzedDataProvider &fdp) {
    bool do_compress = fdp.ConsumeBool();
    std::string data = fdp.ConsumeBytesAsString(
        std::min(fdp.remaining_bytes(), (size_t)10000));
    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);

    if (do_compress) {
        PyRef r = PyObject_CallFunction(bz2_compress, "O", (PyObject *)pydata);
        if (PyErr_Occurred()) PyErr_Clear();
    } else {
        PyRef dobj = PyObject_CallFunction(bz2_BZ2Decompressor, NULL);
        CHECK(dobj);
        PyRef r = PyObject_CallMethod(dobj, "decompress", "Oi",
            (PyObject *)pydata, 1048576);
        if (PyErr_Occurred()) PyErr_Clear();
    }
}

static void op_lzma_decompress(FuzzedDataProvider &fdp) {
    long fmt_vals[3];
    fmt_vals[0] = lzma_FORMAT_AUTO_val;
    fmt_vals[1] = lzma_FORMAT_XZ_val;
    fmt_vals[2] = lzma_FORMAT_ALONE_val;
    long fmt = fmt_vals[fdp.ConsumeIntegralInRange<int>(0, 2)];
    std::string data = fdp.ConsumeBytesAsString(
        std::min(fdp.remaining_bytes(), (size_t)10000));
    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);

    PyRef kwargs = PyDict_New(); CHECK(kwargs);
    PyRef fmt_obj = PyLong_FromLong(fmt); CHECK(fmt_obj);
    PyDict_SetItemString(kwargs, "format", fmt_obj);
    PyRef memlimit = PyLong_FromLong(16 * 1024 * 1024); CHECK(memlimit);
    PyDict_SetItemString(kwargs, "memlimit", memlimit);

    PyRef empty_args = PyTuple_New(0); CHECK(empty_args);
    PyRef dobj = PyObject_Call(lzma_LZMADecompressor, empty_args, kwargs);
    CHECK(dobj);

    PyRef r = PyObject_CallMethod(dobj, "decompress", "Oi",
        (PyObject *)pydata, 1048576);
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_lzma_compress(FuzzedDataProvider &fdp) {
    std::string data = fdp.ConsumeBytesAsString(
        std::min(fdp.remaining_bytes(), (size_t)10000));
    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);
    PyRef r = PyObject_CallFunction(lzma_compress, "O", (PyObject *)pydata);
    if (PyErr_Occurred()) PyErr_Clear();
}

/* ===================================================================
   Operations — Binascii
   =================================================================== */

static void op_binascii_decode(FuzzedDataProvider &fdp) {
    int which = fdp.ConsumeIntegralInRange<int>(0, 5);
    bool strict = fdp.ConsumeBool();
    std::string data = fdp.ConsumeRemainingBytesAsString();
    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);

    PyObject *funcs[] = {ba_a2b_base64, ba_a2b_hex, ba_a2b_uu,
                         ba_a2b_qp, ba_a2b_ascii85, ba_a2b_base85};

    if (which == 0 && strict) {
        PyRef kwargs = PyDict_New(); CHECK(kwargs);
        PyDict_SetItemString(kwargs, "strict_mode", Py_True);
        PyRef args = PyTuple_Pack(1, (PyObject *)pydata); CHECK(args);
        PyRef r = PyObject_Call(ba_a2b_base64, args, kwargs);
    } else {
        PyRef r = PyObject_CallFunction(funcs[which], "O", (PyObject *)pydata);
    }
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_binascii_encode(FuzzedDataProvider &fdp) {
    int which = fdp.ConsumeIntegralInRange<int>(0, 5);
    std::string data = fdp.ConsumeBytesAsString(
        std::min(fdp.remaining_bytes(), (size_t)10000));

    /* b2a_uu requires <= 45 bytes */
    if (which == 2 && data.size() > 45) data.resize(45);

    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);

    PyObject *funcs[] = {ba_b2a_base64, ba_b2a_hex, ba_b2a_uu,
                         ba_b2a_qp, ba_b2a_ascii85, ba_b2a_base85};

    if (which == 0) {
        /* b2a_base64 with optional newline kwarg */
        bool newline = fdp.ConsumeBool();
        PyRef kwargs = PyDict_New(); CHECK(kwargs);
        PyDict_SetItemString(kwargs, "newline", newline ? Py_True : Py_False);
        PyRef args = PyTuple_Pack(1, (PyObject *)pydata); CHECK(args);
        PyRef r = PyObject_Call(ba_b2a_base64, args, kwargs);
    } else if (which == 4) {
        /* b2a_ascii85 with optional foldspaces/wrapcol */
        bool foldspaces = fdp.ConsumeBool();
        PyRef kwargs = PyDict_New(); CHECK(kwargs);
        if (foldspaces)
            PyDict_SetItemString(kwargs, "foldspaces", Py_True);
        PyRef wrapcol = PyLong_FromLong(72); CHECK(wrapcol);
        PyDict_SetItemString(kwargs, "wrapcol", wrapcol);
        PyRef args = PyTuple_Pack(1, (PyObject *)pydata); CHECK(args);
        PyRef r = PyObject_Call(ba_b2a_ascii85, args, kwargs);
    } else {
        PyRef r = PyObject_CallFunction(funcs[which], "O", (PyObject *)pydata);
    }
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_binascii_checksum(FuzzedDataProvider &fdp) {
    bool use_crc32 = fdp.ConsumeBool();
    std::string data = fdp.ConsumeRemainingBytesAsString();
    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);

    if (use_crc32) {
        PyRef r = PyObject_CallFunction(ba_crc32, "O", (PyObject *)pydata);
    } else {
        PyRef r = PyObject_CallFunction(ba_crc_hqx, "Oi",
            (PyObject *)pydata, 0);
    }
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_binascii_roundtrip(FuzzedDataProvider &fdp) {
    std::string data = fdp.ConsumeRemainingBytesAsString();
    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);
    PyRef hexed = PyObject_CallFunction(ba_hexlify, "O", (PyObject *)pydata);
    CHECK(hexed);
    PyRef r = PyObject_CallFunction(ba_unhexlify, "O", (PyObject *)hexed);
    if (PyErr_Occurred()) PyErr_Clear();
}

/* ===================================================================
   Operations — Pickle
   =================================================================== */

/* Build a Python container from fuzz bytes for pickle.dumps. */
static PyObject *build_pickle_container(int type, const uint8_t *buf, size_t len) {
    if (len > 256) len = 256;
    switch (type) {
    case 0: /* raw bytes */
        return PyBytes_FromStringAndSize((const char *)buf, len);
    case 1: /* str */
        return PyUnicode_DecodeUTF8((const char *)buf, len, "replace");
    case 2: { /* list of ints */
        PyObject *lst = PyList_New((Py_ssize_t)len);
        if (!lst) return NULL;
        for (size_t i = 0; i < len; i++)
            PyList_SET_ITEM(lst, i, PyLong_FromLong(buf[i]));
        return lst;
    }
    case 3: { /* tuple of ints */
        PyObject *tup = PyTuple_New((Py_ssize_t)len);
        if (!tup) return NULL;
        for (size_t i = 0; i < len; i++)
            PyTuple_SET_ITEM(tup, i, PyLong_FromLong(buf[i]));
        return tup;
    }
    case 4: { /* set */
        PyObject *lst = PyList_New((Py_ssize_t)len);
        if (!lst) return NULL;
        for (size_t i = 0; i < len; i++)
            PyList_SET_ITEM(lst, i, PyLong_FromLong(buf[i]));
        PyObject *s = PySet_New(lst);
        Py_DECREF(lst);
        return s;
    }
    case 5: { /* frozenset */
        PyObject *lst = PyList_New((Py_ssize_t)len);
        if (!lst) return NULL;
        for (size_t i = 0; i < len; i++)
            PyList_SET_ITEM(lst, i, PyLong_FromLong(buf[i]));
        PyObject *s = PyFrozenSet_New(lst);
        Py_DECREF(lst);
        return s;
    }
    case 6: /* bytearray */
        return PyByteArray_FromStringAndSize((const char *)buf, len);
    case 7: { /* dict.fromkeys */
        PyObject *d = PyDict_New();
        if (!d) return NULL;
        for (size_t i = 0; i < len; i++) {
            PyRef key = PyLong_FromLong(buf[i]);
            if (key) PyDict_SetItem(d, key, Py_None);
        }
        return d;
    }
    default:
        return PyBytes_FromStringAndSize((const char *)buf, len);
    }
}

static void op_pickle_dumps(FuzzedDataProvider &fdp) {
    int container_type = fdp.ConsumeIntegralInRange<int>(0, 7);
    int protocol = fdp.ConsumeIntegralInRange<int>(0, 5);
    bool fix_imports = fdp.ConsumeBool();
    std::string data = fdp.ConsumeBytesAsString(
        std::min(fdp.remaining_bytes(), (size_t)10000));

    PyRef obj(build_pickle_container(container_type,
        (const uint8_t *)data.data(), data.size()));
    CHECK(obj);

    PyRef kwargs = PyDict_New(); CHECK(kwargs);
    PyRef proto = PyLong_FromLong(protocol); CHECK(proto);
    PyDict_SetItemString(kwargs, "protocol", proto);
    PyDict_SetItemString(kwargs, "fix_imports",
        fix_imports ? Py_True : Py_False);
    PyRef args = PyTuple_Pack(1, (PyObject *)obj); CHECK(args);
    PyRef r = PyObject_Call(pickle_dumps, args, kwargs);
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_pickle_loads(FuzzedDataProvider &fdp) {
    int variant = fdp.ConsumeIntegralInRange<int>(0, 2);
    std::string data = fdp.ConsumeRemainingBytesAsString();
    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);
    PyRef bio = PyObject_CallFunction(bytesio_ctor, "O", (PyObject *)pydata);
    CHECK(bio);

    PyObject *cls = nullptr;
    PyRef kwargs_ref;
    switch (variant) {
    case 0: /* RestrictedUnpickler */
        cls = RestrictedUnpickler_cls;
        break;
    case 1: /* PersistentUnpickler */
        cls = PersistentUnpickler_cls;
        break;
    case 2: { /* RestrictedUnpickler with fix_imports + encoding='bytes' */
        cls = RestrictedUnpickler_cls;
        kwargs_ref = PyRef(PyDict_New()); CHECK(kwargs_ref);
        PyDict_SetItemString(kwargs_ref, "fix_imports", Py_True);
        PyRef enc = PyUnicode_FromString("bytes"); CHECK(enc);
        PyDict_SetItemString(kwargs_ref, "encoding", enc);
        break;
    }
    }

    PyRef args = PyTuple_Pack(1, (PyObject *)bio); CHECK(args);
    PyRef unpickler = PyObject_Call(cls, args,
        kwargs_ref.p ? (PyObject *)kwargs_ref : NULL);
    CHECK(unpickler);
    PyRef r = PyObject_CallMethod(unpickler, "load", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_pickle_pickler(FuzzedDataProvider &fdp) {
    int protocol = fdp.ConsumeIntegralInRange<int>(0, 5);
    std::string data = fdp.ConsumeBytesAsString(
        std::min(fdp.remaining_bytes(), (size_t)10000));

    PyRef bio = PyObject_CallFunction(bytesio_ctor, NULL); CHECK(bio);

    /* Import pickle.Pickler */
    static PyObject *pickle_Pickler = nullptr;
    if (!pickle_Pickler) {
        pickle_Pickler = import_attr("pickle", "Pickler");
    }

    PyRef pickler = PyObject_CallFunction(pickle_Pickler, "Oi",
        (PyObject *)bio, protocol);
    CHECK(pickler);

    /* Build first object: list of bytes */
    PyRef obj1(build_pickle_container(2,
        (const uint8_t *)data.data(), data.size()));
    CHECK(obj1);

    PyRef r1 = PyObject_CallMethod(pickler, "dump", "O", (PyObject *)obj1);
    if (!r1) { PyErr_Clear(); return; }

    PyRef cm = PyObject_CallMethod(pickler, "clear_memo", NULL);
    if (PyErr_Occurred()) PyErr_Clear();

    /* Build second object: string */
    PyRef obj2 = PyUnicode_DecodeUTF8(Y(data), "replace"); CHECK(obj2);
    PyRef r2 = PyObject_CallMethod(pickler, "dump", "O", (PyObject *)obj2);
    if (PyErr_Occurred()) PyErr_Clear();

    PyRef val = PyObject_CallMethod(bio, "getvalue", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_pickle_roundtrip(FuzzedDataProvider &fdp) {
    int container_type = fdp.ConsumeIntegralInRange<int>(0, 7);
    std::string data = fdp.ConsumeBytesAsString(
        std::min(fdp.remaining_bytes(), (size_t)10000));

    PyRef obj(build_pickle_container(container_type,
        (const uint8_t *)data.data(), data.size()));
    CHECK(obj);

    PyRef dumped = PyObject_CallFunction(pickle_dumps, "O", (PyObject *)obj);
    if (!dumped) { PyErr_Clear(); return; }
    PyRef loaded = PyObject_CallFunction(pickle_loads, "O", (PyObject *)dumped);
    if (PyErr_Occurred()) PyErr_Clear();
}

/* ===================================================================
   Operations — Codecs
   =================================================================== */

static const char *codec_decoders[] = {
    "utf-7", "shift_jis", "euc-jp", "gb2312", "big5", "iso-2022-jp",
    "euc-kr", "gb18030", "big5hkscs", "charmap", "ascii", "latin-1",
    "cp1252", "unicode_escape", "raw_unicode_escape", "utf-16", "utf-32",
};
static constexpr int NUM_CODEC_DECODERS = sizeof(codec_decoders) / sizeof(codec_decoders[0]);

static const char *codec_encoders[] = {
    "shift_jis", "euc-jp", "gb2312", "big5", "iso-2022-jp", "euc-kr",
    "gb18030", "big5hkscs", "unicode_escape", "raw_unicode_escape",
    "utf-7", "utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32",
    "latin-1", "ascii", "charmap",
};
static constexpr int NUM_CODEC_ENCODERS = sizeof(codec_encoders) / sizeof(codec_encoders[0]);

static void op_codecs_decode(FuzzedDataProvider &fdp) {
    int ci = fdp.ConsumeIntegralInRange<int>(0, NUM_CODEC_DECODERS - 1);
    std::string data = fdp.ConsumeRemainingBytesAsString();
    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);
    PyRef r = PyObject_CallFunction(codecs_decode, "Oss",
        (PyObject *)pydata, codec_decoders[ci], "replace");
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_codecs_encode(FuzzedDataProvider &fdp) {
    int ci = fdp.ConsumeIntegralInRange<int>(0, NUM_CODEC_ENCODERS - 1);
    std::string data = fdp.ConsumeBytesAsString(
        std::min(fdp.remaining_bytes(), (size_t)10000));
    PyRef pystr = PyUnicode_DecodeUTF8(Y(data), "replace"); CHECK(pystr);
    PyRef r = PyObject_CallFunction(codecs_encode, "Oss",
        (PyObject *)pystr, codec_encoders[ci], "replace");
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_codecs_incremental_decode(FuzzedDataProvider &fdp) {
    static const char *inc_codecs[] = {"shift_jis", "gb18030", "utf-16"};
    int ci = fdp.ConsumeIntegralInRange<int>(0, 2);
    std::string data = fdp.ConsumeRemainingBytesAsString();
    size_t mid = data.size() / 2;

    PyRef codec_name = PyUnicode_FromString(inc_codecs[ci]); CHECK(codec_name);
    PyRef decoder_factory = PyObject_CallFunction(
        codecs_getincrementaldecoder, "O", (PyObject *)codec_name);
    CHECK(decoder_factory);

    PyRef decoder = PyObject_CallFunction(decoder_factory, "s", "replace");
    CHECK(decoder);

    PyRef half1 = PyBytes_FromStringAndSize(data.data(), mid); CHECK(half1);
    PyRef r1 = PyObject_CallMethod(decoder, "decode", "O", (PyObject *)half1);
    if (!r1) { PyErr_Clear(); return; }

    PyRef half2 = PyBytes_FromStringAndSize(data.data() + mid,
        data.size() - mid); CHECK(half2);
    PyRef r2 = PyObject_CallMethod(decoder, "decode", "Oi",
        (PyObject *)half2, 1);
    if (PyErr_Occurred()) PyErr_Clear();

    PyRef state = PyObject_CallMethod(decoder, "getstate", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
    PyRef reset = PyObject_CallMethod(decoder, "reset", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_codecs_incremental_encode(FuzzedDataProvider &fdp) {
    static const char *inc_codecs[] = {"shift_jis", "utf-8"};
    int ci = fdp.ConsumeIntegralInRange<int>(0, 1);
    std::string data = fdp.ConsumeBytesAsString(
        std::min(fdp.remaining_bytes(), (size_t)10000));

    PyRef pystr = PyUnicode_DecodeUTF8(Y(data), "replace"); CHECK(pystr);
    Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
    Py_ssize_t mid = slen / 2;

    PyRef codec_name = PyUnicode_FromString(inc_codecs[ci]); CHECK(codec_name);
    PyRef encoder_factory = PyObject_CallFunction(
        codecs_getincrementalencoder, "O", (PyObject *)codec_name);
    CHECK(encoder_factory);

    PyRef encoder = PyObject_CallFunction(encoder_factory, "s", "replace");
    CHECK(encoder);

    PyRef half1 = PyUnicode_Substring(pystr, 0, mid); CHECK(half1);
    PyRef r1 = PyObject_CallMethod(encoder, "encode", "O", (PyObject *)half1);
    if (!r1) { PyErr_Clear(); return; }

    PyRef reset_r = PyObject_CallMethod(encoder, "reset", NULL);
    if (PyErr_Occurred()) PyErr_Clear();

    PyRef half2 = PyUnicode_Substring(pystr, mid, slen); CHECK(half2);
    PyRef r2 = PyObject_CallMethod(encoder, "encode", "O", (PyObject *)half2);
    if (PyErr_Occurred()) PyErr_Clear();

    PyRef state = PyObject_CallMethod(encoder, "getstate", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
}

static void op_codecs_stream(FuzzedDataProvider &fdp) {
    std::string data = fdp.ConsumeRemainingBytesAsString();
    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);
    PyRef bio = PyObject_CallFunction(bytesio_ctor, "O", (PyObject *)pydata);
    CHECK(bio);

    PyRef reader_factory = PyObject_CallFunction(
        codecs_getreader, "s", "utf-8");
    CHECK(reader_factory);

    PyRef reader = PyObject_CallFunction(reader_factory, "Os",
        (PyObject *)bio, "replace");
    CHECK(reader);

    PyRef r = PyObject_CallMethod(reader, "read", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
}

/* ===================================================================
   Operations — SSL
   =================================================================== */

static void op_ssl_cert(FuzzedDataProvider &fdp) {
    std::string data = fdp.ConsumeRemainingBytesAsString();
    PyRef pydata = PyBytes_FromStringAndSize(Y(data)); CHECK(pydata);
    PyRef pem = PyObject_CallFunction(ssl_DER_cert_to_PEM_cert, "O",
        (PyObject *)pydata);
    if (!pem) { PyErr_Clear(); return; }

    /* Optionally try to load into SSLContext */
    PyRef ctx = PyObject_CallFunction(ssl_SSLContext, "l",
        ssl_PROTOCOL_TLS_CLIENT_val);
    if (!ctx) { PyErr_Clear(); return; }

    PyRef kwargs = PyDict_New(); CHECK(kwargs);
    PyDict_SetItemString(kwargs, "cadata", pem);
    PyRef empty_args = PyTuple_New(0); CHECK(empty_args);
    PyRef method = PyObject_GetAttrString(ctx, "load_verify_locations");
    if (!method) { PyErr_Clear(); return; }
    PyRef r = PyObject_Call(method, empty_args, kwargs);
    if (PyErr_Occurred()) PyErr_Clear();
}

/* ===================================================================
   Dispatch.
   =================================================================== */

enum Op {
    OP_ZLIB_DECOMPRESS, OP_ZLIB_COMPRESS, OP_ZLIB_CHECKSUM,
    OP_BZ2, OP_LZMA_DECOMPRESS, OP_LZMA_COMPRESS,
    OP_BINASCII_DECODE, OP_BINASCII_ENCODE, OP_BINASCII_CHECKSUM,
    OP_BINASCII_ROUNDTRIP,
    OP_PICKLE_DUMPS, OP_PICKLE_LOADS, OP_PICKLE_PICKLER,
    OP_PICKLE_ROUNDTRIP,
    OP_CODECS_DECODE, OP_CODECS_ENCODE, OP_CODECS_INCREMENTAL_DECODE,
    OP_CODECS_INCREMENTAL_ENCODE, OP_CODECS_STREAM,
    OP_SSL_CERT,
    NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    assert(Py_IsInitialized());
    init_decode();
    if (size < 1 || size > 0x100000) return 0;
    if (PyErr_Occurred()) PyErr_Clear();

    FuzzedDataProvider fdp(data, size);
    switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_ZLIB_DECOMPRESS:          op_zlib_decompress(fdp); break;
    case OP_ZLIB_COMPRESS:            op_zlib_compress(fdp); break;
    case OP_ZLIB_CHECKSUM:            op_zlib_checksum(fdp); break;
    case OP_BZ2:                      op_bz2(fdp); break;
    case OP_LZMA_DECOMPRESS:          op_lzma_decompress(fdp); break;
    case OP_LZMA_COMPRESS:            op_lzma_compress(fdp); break;
    case OP_BINASCII_DECODE:          op_binascii_decode(fdp); break;
    case OP_BINASCII_ENCODE:          op_binascii_encode(fdp); break;
    case OP_BINASCII_CHECKSUM:        op_binascii_checksum(fdp); break;
    case OP_BINASCII_ROUNDTRIP:       op_binascii_roundtrip(fdp); break;
    case OP_PICKLE_DUMPS:             op_pickle_dumps(fdp); break;
    case OP_PICKLE_LOADS:             op_pickle_loads(fdp); break;
    case OP_PICKLE_PICKLER:           op_pickle_pickler(fdp); break;
    case OP_PICKLE_ROUNDTRIP:         op_pickle_roundtrip(fdp); break;
    case OP_CODECS_DECODE:            op_codecs_decode(fdp); break;
    case OP_CODECS_ENCODE:            op_codecs_encode(fdp); break;
    case OP_CODECS_INCREMENTAL_DECODE: op_codecs_incremental_decode(fdp); break;
    case OP_CODECS_INCREMENTAL_ENCODE: op_codecs_incremental_encode(fdp); break;
    case OP_CODECS_STREAM:            op_codecs_stream(fdp); break;
    case OP_SSL_CERT:                 op_ssl_cert(fdp); break;
    }

    if (++gc_counter % GC_INTERVAL == 0) PyGC_Collect();
    return 0;
}
