/* fuzz_crypto.c — Hash and HMAC operations fuzzer. Covers: _hashlib, _md5, _sha1, _sha2, _sha3, _blake2, _hmac */

#include "fuzzer_template_engine.h"

static const char *crypto_setup_code =
    "import hashlib, hmac, _md5, _sha1, _sha2, _sha3, _blake2, _hmac, io\n";

static const char *crypto_template_sources[] = {
    /* hashlib via OpenSSL — covers _hashopenssl.c */
    "hashlib.md5(_d).digest()\n",
    "hashlib.sha1(_d).digest()\n",
    "hashlib.sha256(_d).digest()\n",
    "hashlib.sha512(_d).digest()\n",
    "hashlib.sha3_256(_d).digest()\n",
    "hashlib.blake2b(_d).digest()\n",
    "hashlib.blake2s(_d).digest()\n",
    /* builtin hash modules — bypass OpenSSL, cover HACL* code */
    "_md5.md5(_d).digest()\n",
    "_sha1.sha1(_d).digest()\n",
    "_sha2.sha224(_d).digest()\n",
    "_sha2.sha256(_d).digest()\n",
    "_sha2.sha384(_d).digest()\n",
    "_sha2.sha512(_d).digest()\n",
    "_sha3.sha3_224(_d).digest()\n",
    "_sha3.sha3_256(_d).digest()\n",
    "_sha3.sha3_384(_d).digest()\n",
    "_sha3.sha3_512(_d).digest()\n",
    "_sha3.shake_128(_d).digest(32)\n",
    "_sha3.shake_256(_d).digest(32)\n",
    /* builtin hash with incremental update — covers update code paths */
    "h = _md5.md5(); h.update(_d[:len(_d)//2]); h.update(_d[len(_d)//2:]); h.hexdigest()\n",
    "h = _sha2.sha256(); h.update(_d[:len(_d)//2]); h.update(_d[len(_d)//2:]); h.hexdigest()\n",
    "h = _sha3.sha3_256(); h.update(_d[:len(_d)//2]); h.update(_d[len(_d)//2:]); h.hexdigest()\n",
    "h = _blake2.blake2b(); h.update(_d[:len(_d)//2]); h.update(_d[len(_d)//2:]); h.hexdigest()\n",
    /* copy() — covers hash object copying paths */
    "h = _sha2.sha256(_d); h.copy().digest()\n",
    "h = _sha3.sha3_256(_d); h.copy().digest()\n",
    /* hmac via Python module — covers hmacmodule.c HMAC object */
    "hmac.new(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:], 'md5').digest()\n",
    "hmac.new(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:], 'sha256').digest()\n",
    "hmac.new(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:], 'sha512').digest()\n",
    "hmac.new(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:], 'sha3_256').digest()\n",
    "hmac.new(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:], 'blake2s').digest()\n",
    /* hmac incremental — covers HMAC update/copy paths */
    "h = hmac.new(_d[:len(_d)//2] or b'\\x00', digestmod='sha256')\n"
    "h.update(_d[len(_d)//2:]); h.copy().hexdigest()\n",
    /* _hmac one-shot functions — covers Hacl_HMAC / Hacl_Streaming_HMAC */
    "_hmac.compute_md5(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:])\n",
    "_hmac.compute_sha1(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:])\n",
    "_hmac.compute_sha256(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:])\n",
    "_hmac.compute_sha512(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:])\n",
    "_hmac.compute_sha3_256(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:])\n",
    "_hmac.compute_blake2s_32(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:])\n",
    "_hmac.compute_blake2b_32(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:])\n",

    /* blake2b — key + salt + person */
    "_blake2.blake2b(_d, key=_d[:64], salt=_d[:16], person=_d[:16]).digest()\n",
    /* blake2s — key + salt + person */
    "_blake2.blake2s(_d, key=_d[:32], salt=_d[:8], person=_d[:8]).digest()\n",
    /* blake2b — variable digest_size */
    "_blake2.blake2b(_d, digest_size=(_d[0] % 64 + 1) if _d else 32).digest()\n",
    /* blake2s — variable digest_size */
    "_blake2.blake2s(_d, digest_size=(_d[0] % 32 + 1) if _d else 32).digest()\n",

    /* shake_128 — variable length digest */
    "_sha3.shake_128(_d).digest((_d[0]*4+1) if _d else 32)\n",
    /* shake_256 — variable length digest */
    "_sha3.shake_256(_d).digest((_d[0]*4+1) if _d else 32)\n",
    /* SHA3 — copy + update + hexdigest */
    "h = _sha3.sha3_256(_d[:32])\n"
    "h2 = h.copy(); h2.update(_d[32:]); h2.hexdigest()\n",

    /* hashlib.new — md5 with usedforsecurity=False */
    "hashlib.new('md5', _d, usedforsecurity=False).hexdigest()\n",
    /* hashlib.new — sha256 with usedforsecurity=False */
    "hashlib.new('sha256', _d, usedforsecurity=False).hexdigest()\n",
    /* hashlib.new — sha3_256 copy */
    "hashlib.new('sha3_256', _d).copy().digest()\n",
    /* hashlib — file_digest */
    "hashlib.file_digest(io.BytesIO(_d), 'sha256').hexdigest()\n",

    /* hmac — sha384 */
    "hmac.new(_d[:32] or b'\\x00', _d[32:], 'sha384').hexdigest()\n",
    /* hmac — sha224 */
    "hmac.new(_d[:32] or b'\\x00', _d[32:], 'sha224').hexdigest()\n",
    /* hmac — compare_digest */
    "hmac.compare_digest(hmac.new(b'k', _d, 'sha256').digest(), _d[:32].ljust(32, b'\\x00'))\n",
    /* hmac — one-shot digest */
    "hmac.digest(_d[:32] or b'\\x00', _d[32:], 'sha256')\n",

    /* blake2b — copy + property access (covers copy_unlocked, get_name, get_block_size, get_digest_size) */
    "h = _blake2.blake2b(_d); h2 = h.copy(); h2.digest()\n"
    "h.name; h.block_size; h.digest_size\n",
    /* blake2s — copy + property access */
    "h = _blake2.blake2s(_d); h2 = h.copy(); h2.digest()\n"
    "h.name; h.block_size; h.digest_size\n",
    /* md5 — copy + properties (covers MD5copy, md5 property getters) */
    "h = _md5.md5(_d); h.copy().digest(); h.name; h.digest_size; h.block_size\n",
    /* sha1 — copy + properties (covers SHA1copy, sha1 property getters) */
    "h = _sha1.sha1(_d); h.copy().digest(); h.name; h.digest_size; h.block_size\n",
    /* sha512 — copy + properties (covers SHA512copy, newSHA512object) */
    "h = _sha2.sha512(_d); h.copy().digest(); h.name; h.digest_size; h.block_size\n",
    /* sha384 — copy + properties */
    "h = _sha2.sha384(_d); h.copy().digest(); h.name; h.digest_size; h.block_size\n",
    /* sha224 — copy + properties */
    "h = _sha2.sha224(_d); h.copy().digest(); h.name; h.digest_size; h.block_size\n",
    /* sha256 — copy + properties (redundant but hits property code) */
    "h = _sha2.sha256(_d); h2 = h.copy(); h2.update(_d); h2.digest()\n"
    "h.name; h.digest_size; h.block_size\n",

    /* sha1 — .update() + .hexdigest() (covers SHA1Type_update_impl, SHA1Type_hexdigest_impl) */
    "h = _sha1.sha1(); h.update(_d[:1]); h.update(_d[1:]); h.hexdigest()\n",
    /* sha512 — .update() + .hexdigest() (covers SHA512Type_update_impl, SHA512Type_hexdigest_impl) */
    "h = _sha2.sha512(); h.update(_d[:1]); h.update(_d[1:]); h.hexdigest()\n",
    /* sha384 — .update() + .hexdigest() */
    "h = _sha2.sha384(); h.update(_d[:1]); h.update(_d[1:]); h.hexdigest()\n",
    /* sha224 — .update() + .hexdigest() */
    "h = _sha2.sha224(); h.update(_d[:1]); h.update(_d[1:]); h.hexdigest()\n",
    /* sha256 — .update() + .hexdigest() (misaligned buffer for HACL paths) */
    "h = _sha2.sha256(); h.update(_d[:1]); h.update(_d[1:]); h.hexdigest()\n",
    /* md5 — misaligned multi-part update for HACL buffer alignment paths */
    "h = _md5.md5(); h.update(_d[:1]); h.update(_d[1:]); h.hexdigest()\n",

    /* hmac — HMAC.new + update + copy + digest + hexdigest (covers _hmac_new_impl, HMAC_copy, HMAC_update, HMAC_digest, HMAC_hexdigest) */
    "h = hmac.new(_d[:len(_d)//2] or b'\\x00', digestmod='sha256')\n"
    "h.update(_d[len(_d)//2:])\n"
    "h2 = h.copy(); h2.digest(); h.hexdigest()\n",
    /* hmac — HMAC with md5 (covers md5 path in hmac C module) */
    "h = hmac.new(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:], 'md5')\n"
    "h.update(_d); h.copy().hexdigest()\n",
    /* hmac — HMAC with sha512 (covers sha512 path) */
    "h = hmac.new(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:], 'sha512')\n"
    "h.update(_d); h.digest()\n",
    /* hmac — HMAC with sha3_256 (covers sha3 path) */
    "h = hmac.new(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:], 'sha3_256')\n"
    "h.update(_d); h.hexdigest()\n",
    /* hmac — HMAC with blake2s (covers blake2 path) */
    "h = hmac.new(_d[:len(_d)//2] or b'\\x00', _d[len(_d)//2:], 'blake2s')\n"
    "h.update(_d); h.copy().digest()\n",

    /* hashlib — pbkdf2_hmac (covers _hashlib_pbkdf2_hmac_impl, processes bytes) */
    "hashlib.pbkdf2_hmac('sha256', _d, _d[:16] or b'salt', 1)\n",
    /* hashlib — pbkdf2_hmac with sha1 (covers sha1 path) */
    "hashlib.pbkdf2_hmac('sha1', _d, _d[:16] or b'salt', 1)\n",
    /* hashlib — pbkdf2_hmac with sha512 */
    "hashlib.pbkdf2_hmac('sha512', _d, _d[:16] or b'salt', 1)\n",
    /* hashlib — new() + update + hexdigest (covers EVPnew, EVP_update, EVP_hexdigest) */
    "h = hashlib.new('sha256', usedforsecurity=False)\n"
    "h.update(_d); h.hexdigest()\n",
    /* hashlib — new() with copy (covers EVP_copy) */
    "h = hashlib.new('sha256', _d, usedforsecurity=False)\n"
    "h2 = h.copy(); h2.update(_d); h2.digest()\n",
    /* hashlib — file_digest processes bytes stream */
    "hashlib.file_digest(io.BytesIO(_d), 'sha512').hexdigest()\n",
};

#define MAX_CRYPTO_TEST_SIZE 0x100000

DEFINE_TEMPLATE_FUZZER(crypto, MAX_CRYPTO_TEST_SIZE)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    assert(Py_IsInitialized());
    static int initialized = 0;
    if (!initialized) {
        if (!init_crypto()) { PyErr_Print(); abort(); }
        initialized = 1;
    }
    int rv = fuzz_crypto((const char *)data, size);
    if (PyErr_Occurred()) {
        PyErr_Print();
        abort();
    }
    return rv;
}
