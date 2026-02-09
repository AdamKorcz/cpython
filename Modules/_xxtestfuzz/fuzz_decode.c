/* fuzz_decode.c — Binary decoders / deserializers fuzzer.
   Covers: zlib, _bz2, _lzma, binascii, _pickle, _ssl,
           _multibytecodec, _codecs_cn, _codecs_hk, _codecs_iso2022,
           _codecs_jp, _codecs_kr, _codecs_tw */

#include "fuzzer_template_engine.h"

static const char *decode_setup_code =
    "import zlib, bz2, lzma, binascii, codecs, pickle, ssl, io, warnings\n"
    "warnings.filterwarnings('ignore')\n"
    "def _lzma_decomp(_data, fmt):\n"
    "    d = lzma.LZMADecompressor(format=fmt, memlimit=16*1024*1024)\n"
    "    return d.decompress(_data, max_length=1024*1024)\n"
    "class _RestrictedUnpickler(pickle.Unpickler):\n"
    "    def find_class(self, module, name):\n"
    "        raise pickle.UnpicklingError('restricted')\n"
    "class _PersistentUnpickler(pickle.Unpickler):\n"
    "    def persistent_load(self, pid): return pid\n"
    "    def find_class(self, module, name):\n"
    "        raise pickle.UnpicklingError('restricted')\n";

static const char *decode_template_sources[] = {
    /* zlib decompress — 4 wbits modes */
    "zlib.decompressobj(15).decompress(_d, max_length=1048576)\n",
    "zlib.decompressobj(-15).decompress(_d, max_length=1048576)\n",
    "zlib.decompressobj(31).decompress(_d, max_length=1048576)\n",
    "zlib.decompressobj(47).decompress(_d, max_length=1048576)\n",
    /* zlib decompress with flush — covers flush code path */
    "d = zlib.decompressobj(15); d.decompress(_d, 1048576); d.flush()\n",
    /* zlib compress + compressobj/flush — covers Compress_Type paths */
    "zlib.compress(_d)\n",
    "c = zlib.compressobj(); c.compress(_d); c.flush()\n",
    "zlib.crc32(_d)\n",
    "zlib.adler32(_d)\n",
    /* bz2 decompress + compress */
    "bz2.BZ2Decompressor().decompress(_d, max_length=1048576)\n",
    "bz2.compress(_d)\n",
    /* lzma decompress (3 formats) + compress */
    "_lzma_decomp(_d, lzma.FORMAT_AUTO)\n",
    "_lzma_decomp(_d, lzma.FORMAT_XZ)\n",
    "_lzma_decomp(_d, lzma.FORMAT_ALONE)\n",
    "lzma.compress(_d)\n",
    /* binascii — decode functions */
    "binascii.a2b_base64(_d)\n",
    "binascii.a2b_hex(_d)\n",
    "binascii.a2b_uu(_d)\n",
    "binascii.a2b_qp(_d)\n",
    "binascii.crc32(_d)\n",
    /* binascii — encode functions */
    "binascii.b2a_base64(_d)\n",
    "binascii.b2a_hex(_d)\n",
    "binascii.b2a_uu(_d[:45])\n",
    "binascii.b2a_qp(_d)\n",
    /* pickle — loads and dumps (exercises both Unpickler and Pickler) */
    "_RestrictedUnpickler(io.BytesIO(_d)).load()\n",
    "pickle.dumps(_s)\n",
    "pickle.dumps(list(_d))\n",
    "pickle.dumps({_s: list(_d[:32])})\n",
    /* pickle — protocol selection covers different Pickler paths */
    "pickle.dumps(list(_d[:64]), protocol=_d[0] % 6 if _d else 0)\n",
    /* pickle — set/frozenset (EMPTY_SET, ADDITEMS, FROZENSET opcodes) */
    "pickle.dumps(set(_d))\n",
    "pickle.dumps(frozenset(_d))\n",
    /* pickle — bytearray with protocol 5 (BYTEARRAY8 opcode) */
    "pickle.dumps(bytearray(_d), protocol=5)\n",
    /* pickle — protocol-specific branches */
    "pickle.dumps(list(_d), protocol=0)\n",
    "pickle.dumps(list(_d), protocol=1)\n",
    "pickle.dumps(list(_d), protocol=2)\n",
    "pickle.dumps(tuple(_d), protocol=3)\n",
    "pickle.dumps(tuple(_d), protocol=4)\n",
    /* pickle — round-trips (exercises both Pickler and Unpickler) */
    "pickle.loads(pickle.dumps(list(_d)))\n",
    "pickle.loads(pickle.dumps({_s: _d}))\n",
    /* pickle — Pickler with clear_memo (exercises memo proxy) */
    "f = io.BytesIO()\n"
    "p = pickle.Pickler(f, protocol=4)\n"
    "p.dump(list(_d)); p.clear_memo(); p.dump(_s)\n",
    /* ssl — DER certificate parsing */
    "ssl.DER_cert_to_PEM_cert(_d)\n",
    /* ssl — SSLContext creation + certificate loading */
    "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
    "ctx.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(_d))\n",
    /* codecs — multibyte decode */
    "codecs.decode(_d, 'utf-7', 'replace')\n",
    "codecs.decode(_d, 'shift_jis', 'replace')\n",
    "codecs.decode(_d, 'euc-jp', 'replace')\n",
    "codecs.decode(_d, 'gb2312', 'replace')\n",
    "codecs.decode(_d, 'big5', 'replace')\n",
    "codecs.decode(_d, 'iso-2022-jp', 'replace')\n",
    "codecs.decode(_d, 'euc-kr', 'replace')\n",
    "codecs.decode(_d, 'gb18030', 'replace')\n",
    "codecs.decode(_d, 'big5hkscs', 'replace')\n",
    /* codecs — multibyte encode (covers encoder paths in multibytecodec) */
    "codecs.encode(_s, 'shift_jis', 'replace')\n",
    "codecs.encode(_s, 'euc-jp', 'replace')\n",
    "codecs.encode(_s, 'gb2312', 'replace')\n",
    "codecs.encode(_s, 'big5', 'replace')\n",
    "codecs.encode(_s, 'iso-2022-jp', 'replace')\n",
    "codecs.encode(_s, 'euc-kr', 'replace')\n",
    "codecs.encode(_s, 'gb18030', 'replace')\n",
    "codecs.encode(_s, 'big5hkscs', 'replace')\n",
    /* codecs — incremental decode (covers IncrementalDecoder paths) */
    "d = codecs.getincrementaldecoder('shift_jis')('replace')\n"
    "d.decode(_d[:len(_d)//2]); d.decode(_d[len(_d)//2:], True)\n",
    "d = codecs.getincrementaldecoder('gb18030')('replace')\n"
    "d.decode(_d[:len(_d)//2]); d.decode(_d[len(_d)//2:], True)\n",
    /* zlib — decompressobj with zdict and wbits=0 */
    "zlib.decompressobj(wbits=0).decompress(_d, max_length=1048576)\n",
    "zlib.decompressobj(wbits=15, zdict=_d[:32]).decompress(_d[32:], max_length=1048576)\n",
    /* codecs — additional single-byte decoders */
    "codecs.decode(_d, 'charmap', 'replace')\n",
    "codecs.decode(_d, 'ascii', 'replace')\n",
    "codecs.decode(_d, 'latin-1', 'replace')\n",
    "codecs.decode(_d, 'cp1252', 'replace')\n",
    /* pickle — persistent_load exercising PERSID/BINPERSID opcodes */
    "_PersistentUnpickler(io.BytesIO(_d)).load()\n",

    /* pickle — fix_imports True/False */
    "pickle.dumps(_s, protocol=2, fix_imports=True)\n",
    "pickle.dumps(_s, protocol=2, fix_imports=False)\n",
    /* pickle — Unpickler with fix_imports + encoding='bytes' */
    "_RestrictedUnpickler(io.BytesIO(_d), fix_imports=True, encoding='bytes').load()\n",
    /* pickle — SETITEMS opcode via dict */
    "pickle.dumps(dict.fromkeys(_d[:32]))\n",
    /* pickle — bytearray protocol 3 vs 5 */
    "pickle.dumps(bytearray(_d), protocol=3)\n",
    /* pickle — Unpickler with buffers param (protocol 5) */
    "bufs = []; pickle.dumps(_d, protocol=5, buffer_callback=bufs.append)\n",
    /* pickle — round trip with nested structures */
    "pickle.loads(pickle.dumps([list(_d[:16]), set(_d[:8]), {_s[:8]: _d[:8]}]))\n",
    "pickle.loads(pickle.dumps(tuple(tuple(_d[i:i+4]) for i in range(0, min(len(_d), 32), 4))))\n",

    /* zlib — compressobj with various levels and wbits */
    "_lvl = (_d[0] % 10) if _d else 6\n"
    "c = zlib.compressobj(level=_lvl); c.compress(_d); c.flush()\n",
    /* zlib — decompressobj copy */
    "d1 = zlib.decompressobj(15)\n"
    "d2 = d1.copy()\n"
    "d1.decompress(_d, 1048576); d2.decompress(_d, 1048576)\n",
    /* zlib — compress with level from fuzz data */
    "zlib.compress(_d, level=(_d[0] % 10) if _d else 6)\n",

    /* codecs — incremental encoder with reset + getstate/setstate */
    "enc = codecs.getincrementalencoder('shift_jis')('replace')\n"
    "enc.encode(_s[:len(_s)//2]); enc.reset()\n"
    "enc.encode(_s[len(_s)//2:]); enc.getstate()\n",
    /* codecs — utf-16-le, utf-16-be, utf-32 */
    "codecs.encode(_s, 'utf-16-le')\n"
    "codecs.encode(_s, 'utf-16-be')\n"
    "codecs.encode(_s, 'utf-32')\n",
    /* codecs — StreamReader/StreamWriter */
    "bio = io.BytesIO(_d)\n"
    "sr = codecs.getreader('utf-8')(bio, errors='replace')\n"
    "sr.read()\n",

    /* binascii — hexlify/unhexlify round-trip */
    "h = binascii.hexlify(_d); binascii.unhexlify(h)\n",
    /* binascii — crc_hqx + b2a_base64 */
    "binascii.crc_hqx(_d, 0); binascii.b2a_base64(_d, newline=False)\n",

    /* binascii — a2b_base64 strict_mode */
    "binascii.a2b_base64(_d, strict_mode=True)\n",
    /* binascii — b2a_base64 newline=True */
    "binascii.b2a_base64(_d, newline=True)\n",

    /* codecs — escape_decode (covers escape_decode_impl) */
    "codecs.decode(_d, 'unicode_escape', 'replace')\n",
    /* codecs — escape_encode (covers escape_encode_impl) */
    "codecs.encode(_s, 'unicode_escape')\n",
    /* codecs — raw_unicode_escape encode */
    "codecs.encode(_s, 'raw_unicode_escape')\n",
    /* codecs — raw_unicode_escape decode */
    "codecs.decode(_d, 'raw_unicode_escape', 'replace')\n",
    /* codecs — utf_7 encode (covers utf_7_encode_impl) */
    "codecs.encode(_s, 'utf-7')\n",
    /* codecs — utf_8 encode (covers utf_8_encode_impl) */
    "codecs.encode(_s, 'utf-8')\n",
    /* codecs — utf_32 encode (covers utf_32_encode) */
    "codecs.encode(_s, 'utf-32')\n",
    /* codecs — utf_32 decode (covers utf_32_decode) */
    "codecs.decode(_d, 'utf-32', 'replace')\n",
    /* codecs — latin_1 encode (covers latin_1_encode_impl) */
    "codecs.encode(_s, 'latin-1', 'replace')\n",
    /* codecs — ascii encode (covers ascii_encode_impl) */
    "codecs.encode(_s, 'ascii', 'replace')\n",
    /* codecs — charmap encode (covers charmap_encode_impl) */
    "codecs.encode(_s, 'charmap', 'replace')\n",
    /* codecs — utf-16 encode */
    "codecs.encode(_s, 'utf-16')\n",
    /* codecs — utf-16 decode */
    "codecs.decode(_d, 'utf-16', 'replace')\n",
    /* codecs — incremental encoder utf-8 with state */
    "enc = codecs.getincrementalencoder('utf-8')()\n"
    "enc.encode(_s[:len(_s)//2]); enc.encode(_s[len(_s)//2:], final=True)\n"
    "enc.reset(); enc.getstate()\n",
    /* codecs — incremental decoder utf-16 with state */
    "dec = codecs.getincrementaldecoder('utf-16')('replace')\n"
    "dec.decode(_d[:len(_d)//2]); dec.decode(_d[len(_d)//2:], True)\n"
    "dec.getstate(); dec.reset()\n",

    /* pickle — Pickler.dump string + bytes (covers Pickler_dump, save_unicode, save_bytes) */
    "f = io.BytesIO()\n"
    "p = pickle.Pickler(f)\n"
    "p.dump(_s); p.dump(_d); p.dump({_s: _d})\n"
    "f.getvalue()\n",
    /* pickle — save_bytes all protocols (covers save_bytes, SHORT_BINBYTES, BINBYTES) */
    "pickle.dumps(_d, protocol=3); pickle.dumps(_d, protocol=4)\n"
    "pickle.dumps(_d, protocol=5)\n",
    /* pickle — save_unicode all protocols (covers save_unicode, SHORT_BINUNICODE, BINUNICODE) */
    "pickle.dumps(_s, protocol=0); pickle.dumps(_s, protocol=3)\n"
    "pickle.dumps(_s, protocol=4)\n",

    /* zlib — one-shot decompress (covers zlib_decompress_impl) */
    "zlib.decompress(_d)\n",
    /* zlib — one-shot decompress with wbits (covers wbits parameter handling) */
    "zlib.decompress(_d, 15)\n",
    "zlib.decompress(_d, -15)\n",
    "zlib.decompress(_d, 31)\n",
    /* zlib — compressobj copy (covers Compress_copy) */
    "c = zlib.compressobj(); c.compress(_d); c2 = c.copy(); c2.flush()\n",

    /* binascii — a2b_ascii85 (covers binascii_a2b_ascii85_impl) */
    "binascii.a2b_ascii85(_d)\n",
    /* binascii — b2a_ascii85 (covers binascii_b2a_ascii85_impl) */
    "binascii.b2a_ascii85(_d)\n",
    /* binascii — a2b_base85 (covers binascii_a2b_base85_impl) */
    "binascii.a2b_base85(_d)\n",
    /* binascii — b2a_base85 (covers binascii_b2a_base85_impl) */
    "binascii.b2a_base85(_d)\n",
    /* binascii — b2a_ascii85 with options */
    "binascii.b2a_ascii85(_d, foldspaces=True, wrapcol=72)\n",
};

#define MAX_DECODE_TEST_SIZE 0x100000
DEFINE_TEMPLATE_FUZZER(decode, MAX_DECODE_TEST_SIZE)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    assert(Py_IsInitialized());
    static int initialized = 0;
    if (!initialized) {
        if (!init_decode()) { PyErr_Print(); abort(); }
        initialized = 1;
    }
    int rv = fuzz_decode((const char *)data, size);
    if (PyErr_Occurred()) {
        PyErr_Print();
        abort();
    }
    return rv;
}
