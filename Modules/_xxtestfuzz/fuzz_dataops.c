/* fuzz_dataops.c — Data-structure operations fuzzer. Covers: array, ctypes, mmap, locale, dbm, sqlite3 */

#include "fuzzer_template_engine.h"

static const char *dataops_setup_code =
    "import array, ctypes, mmap, locale, dbm, sqlite3\n";

static const char *dataops_template_sources[] = {
    /* array — frombytes with different type codes */
    "array.array('b').frombytes(_d)\n",
    "array.array('H').frombytes(_d)\n",
    "array.array('i').frombytes(_d)\n",
    "array.array('d').frombytes(_d)\n",
    /* array — deeper operations: reverse, tobytes, tolist, index, insert */
    "a = array.array('i', _d[:len(_d)//4*4] or b'\\x00\\x00\\x00\\x00')\n"
    "a.reverse(); a.tobytes(); a.tolist()\n"
    "a.index(a[0]) if len(a) else None\n",
    "a = array.array('d', _d[:len(_d)//8*8] or b'\\x00'*8)\n"
    "a.append(0.0); a.extend(a[:1]); a.pop(); a.tobytes()\n"
    "a.count(a[0]) if len(a) else None\n",
    "a = array.array('H', _d[:len(_d)//2*2] or b'\\x00\\x00')\n"
    "a.insert(0, 42); a.remove(42); a.byteswap(); a.tobytes()\n",
    /* ctypes — from_buffer_copy */
    "ctypes.c_char.from_buffer_copy(_d[:1].ljust(1, b'\\x00'))\n",
    "ctypes.c_int.from_buffer_copy(_d[:4].ljust(4, b'\\x00'))\n",
    "ctypes.c_double.from_buffer_copy(_d[:8].ljust(8, b'\\x00'))\n",
    /* ctypes — string buffer and array types */
    "ctypes.create_string_buffer(_d[:256])\n",
    "(ctypes.c_char * len(_d)).from_buffer_copy(_d) if _d else None\n",
    /* ctypes — Structure */
    "class _S(ctypes.Structure):\n"
    "    _fields_ = [('a', ctypes.c_int), ('b', ctypes.c_double)]\n"
    "_S.from_buffer_copy(_d[:ctypes.sizeof(_S)].ljust(ctypes.sizeof(_S), b'\\x00'))\n",
    /* mmap — write + find */
    "_m = mmap.mmap(-1, max(len(_d), 1))\n"
    "_m.write(_d[:_m.size()])\n"
    "_m.seek(0)\n"
    "_m.find(_d[:min(4, len(_d))] or b'\\x00')\n"
    "_m.close()\n",
    /* mmap — read + rfind + readline + slicing */
    "_m = mmap.mmap(-1, max(len(_d), 1))\n"
    "_m.write(_d[:_m.size()])\n"
    "_m.seek(0)\n"
    "_m.read(min(4, _m.size()))\n"
    "_m.seek(0)\n"
    "_m.rfind(_d[:min(4, len(_d))] or b'\\x00')\n"
    "_m.seek(0)\n"
    "_m.readline()\n"
    "_m[0:min(len(_d), _m.size())]\n"
    "_m.close()\n",
    /* mmap — resize + move */
    "_m = mmap.mmap(-1, max(len(_d), 1))\n"
    "_m.write(_d[:_m.size()])\n"
    "_m.resize(max(len(_d) * 2, 1))\n"
    "_m.move(0, min(1, _m.size() - 1), min(len(_d), _m.size() // 2))\n"
    "_m.close()\n",
    /* locale — strxfrm */
    "locale.strxfrm(_s)\n",
    /* locale — strcoll */
    "locale.strcoll(_s[:len(_s)//2], _s[len(_s)//2:])\n",
    /* dbm — open, write, read, keys, delete, close */
    "_db = dbm.open('/tmp/_fuzz_dbm', 'n')\n"
    "_k = _d[:max(1, len(_d)//2)]; _v2 = _d[len(_d)//2:]\n"
    "_db[_k] = _v2\n"
    "_db[_k]\n"
    "list(_db.keys())\n"
    "del _db[_k]\n"
    "_db.close()\n",
    /* dbm — multiple keys */
    "_db = dbm.open('/tmp/_fuzz_dbm2', 'n')\n"
    "for i in range(0, min(len(_d), 64), 4):\n"
    "    _db[_d[i:i+2] or b'k'] = _d[i+2:i+4] or b'v'\n"
    "for k in _db.keys(): _db[k]\n"
    "_db.close()\n",
    /* sqlite3 — basic SQL execution */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('PRAGMA max_page_count=100')\n"
    "_c.execute(_s)\n"
    "_c.close()\n",
    /* sqlite3 — table operations with parameterized queries */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('PRAGMA max_page_count=100')\n"
    "_c.execute('CREATE TABLE t(a TEXT, b BLOB)')\n"
    "_c.execute('INSERT INTO t VALUES(?, ?)', (_s, _d))\n"
    "_c.execute('SELECT * FROM t WHERE a LIKE ?', (_s[:32],))\n"
    "_c.execute('UPDATE t SET b=? WHERE a=?', (_d, _s))\n"
    "_c.execute('DELETE FROM t WHERE a=?', (_s,))\n"
    "_c.close()\n",
    /* sqlite3 — aggregate and multi-row */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('PRAGMA max_page_count=100')\n"
    "_c.execute('CREATE TABLE t(v INTEGER)')\n"
    "_c.executemany('INSERT INTO t VALUES(?)', [(b,) for b in _d[:64]])\n"
    "_c.execute('SELECT count(*), sum(v), avg(v), min(v), max(v) FROM t').fetchone()\n"
    "_c.execute('SELECT v, count(*) FROM t GROUP BY v ORDER BY v').fetchall()\n"
    "_c.close()\n",
    /* array — float typecode + buffer_info, byteswap */
    "a = array.array('f', _d[:len(_d)//4*4] or b'\\x00'*4)\n"
    "a.buffer_info(); a.byteswap(); a.tobytes(); list(a)\n",
    /* array — comparison and concatenation */
    "a1 = array.array('i', _d[:len(_d)//4*4] or b'\\x00\\x00\\x00\\x00')\n"
    "a2 = array.array('i', _d[:len(_d)//4*4] or b'\\x00\\x00\\x00\\x00')\n"
    "a1 == a2; a1 + a2; a1 * min(len(a1), 3)\n",
    /* array — fromlist */
    "a = array.array('i')\n"
    "a.fromlist([b % 256 for b in _d[:32]])\n"
    "a.tobytes()\n",
    /* array — unsigned char typecode + slice ops */
    "a = array.array('B', _d or b'\\x00')\n"
    "a[0:min(len(a),2)] = array.array('B', b'\\xff\\xfe')\n"
    "a.tobytes(); a.tolist()\n",
    /* array — long typecodes 'l', 'L', 'q', 'Q' */
    "a = array.array('l', _d[:len(_d)//4*4] or b'\\x00'*4)\n"
    "a.tobytes(); a.tolist()\n",
    "a = array.array('L', _d[:len(_d)//4*4] or b'\\x00'*4)\n"
    "a.tobytes(); a.tolist()\n",
    "a = array.array('q', _d[:len(_d)//8*8] or b'\\x00'*8)\n"
    "a.tobytes(); a.tolist()\n",
    "a = array.array('Q', _d[:len(_d)//8*8] or b'\\x00'*8)\n"
    "a.tobytes(); a.tolist()\n",
    /* array — __contains__, __iter__, __len__, __sizeof__ */
    "a = array.array('i', _d[:len(_d)//4*4] or b'\\x00'*4)\n"
    "a[0] in a; list(iter(a)); len(a); a.__sizeof__()\n",
    /* array — slice assignment */
    "a = array.array('B', _d or b'\\x00')\n"
    "a[::2] = array.array('B', bytes(len(a[::2])))\n"
    "a.tobytes()\n",
    /* sqlite3 — create_function */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('PRAGMA max_page_count=100')\n"
    "_c.create_function('fuzzfn', 1, lambda x: x)\n"
    "_c.execute('CREATE TABLE t(a TEXT)')\n"
    "_c.execute('INSERT INTO t VALUES(?)', (_s[:32],))\n"
    "_c.execute('SELECT fuzzfn(a) FROM t').fetchall()\n"
    "_c.close()\n",
    /* sqlite3 — create_aggregate */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('PRAGMA max_page_count=100')\n"
    "class _Agg:\n"
    "    def __init__(self): self.vals = []\n"
    "    def step(self, v): self.vals.append(v)\n"
    "    def finalize(self): return len(self.vals)\n"
    "_c.create_aggregate('fuzzagg', 1, _Agg)\n"
    "_c.execute('CREATE TABLE t(v INTEGER)')\n"
    "_c.executemany('INSERT INTO t VALUES(?)', [(b,) for b in _d[:32]])\n"
    "_c.execute('SELECT fuzzagg(v) FROM t').fetchone()\n"
    "_c.close()\n",
    /* sqlite3 — set_authorizer */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('PRAGMA max_page_count=100')\n"
    "_c.set_authorizer(lambda *a: sqlite3.SQLITE_OK)\n"
    "_c.execute('CREATE TABLE t(a TEXT)')\n"
    "_c.execute('INSERT INTO t VALUES(?)', (_s[:16],))\n"
    "_c.execute('SELECT * FROM t').fetchall()\n"
    "_c.close()\n",
    /* sqlite3 — Row factory */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('PRAGMA max_page_count=100')\n"
    "_c.row_factory = sqlite3.Row\n"
    "_c.execute('CREATE TABLE t(a TEXT, b INTEGER)')\n"
    "_c.execute('INSERT INTO t VALUES(?, ?)', (_s[:8], 42))\n"
    "row = _c.execute('SELECT * FROM t').fetchone()\n"
    "row['a']; row['b']; row.keys()\n"
    "_c.close()\n",
    /* sqlite3 — blob open */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('PRAGMA max_page_count=100')\n"
    "_c.execute('CREATE TABLE t(a BLOB)')\n"
    "_c.execute('INSERT INTO t VALUES(?)', (_d[:64],))\n"
    "rid = _c.execute('SELECT rowid FROM t').fetchone()[0]\n"
    "blob = _c.blobopen('main', 't', 'a', rid)\n"
    "blob.read(); blob.seek(0); blob.write(_d[:min(len(_d), 64)])\n"
    "blob.close()\n"
    "_c.close()\n",
    /* mmap — getitem, setitem with slices */
    "_m = mmap.mmap(-1, max(len(_d), 1))\n"
    "_m.write(_d[:_m.size()])\n"
    "_m[0]; _m[0:min(4, _m.size())]\n"
    "_m[0] = _d[0] if _d else 0\n"
    "_m.close()\n",
    /* mmap — flush + size + tell */
    "_m = mmap.mmap(-1, max(len(_d), 1))\n"
    "_m.write(_d[:_m.size()])\n"
    "_m.flush(); _m.size(); _m.tell()\n"
    "_m.close()\n",
    /* mmap — context manager */
    "with mmap.mmap(-1, max(len(_d), 1)) as _m:\n"
    "    _m.write(_d[:_m.size()])\n"
    "    _m.seek(0); _m.read()\n",
    /* dbm — iteration */
    "_db = dbm.open('/tmp/_fuzz_dbm3', 'n')\n"
    "for i in range(0, min(len(_d), 32), 2):\n"
    "    _db[_d[i:i+1] or b'k'] = _d[i+1:i+2] or b'v'\n"
    "for k in _db: _db[k]\n"
    "len(_db); b'k' in _db\n"
    "_db.close()\n",
    /* sqlite3 — complete_statement */
    "sqlite3.complete_statement(_s or 'SELECT 1;')\n",
    /* sqlite3 — register_adapter */
    "class _AdaptMe:\n"
    "    def __init__(self, v): self.v = v\n"
    "sqlite3.register_adapter(_AdaptMe, lambda a: str(a.v))\n"
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('CREATE TABLE t(a TEXT)')\n"
    "_c.execute('INSERT INTO t VALUES(?)', (_AdaptMe(_s[:8]),))\n"
    "_c.close()\n",
    /* sqlite3 — executescript with fuzz data */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('PRAGMA max_page_count=100')\n"
    "_c.executescript(_s or 'SELECT 1;')\n"
    "_c.close()\n",
    /* mmap — find processes bytes pattern */
    "_m = mmap.mmap(-1, max(len(_d), 1))\n"
    "_m.write(_d[:_m.size()])\n"
    "_m.seek(0)\n"
    "_m.find(_d)\n"
    "_m.close()\n",
    /* mmap — rfind processes bytes pattern */
    "_m = mmap.mmap(-1, max(len(_d), 1))\n"
    "_m.write(_d[:_m.size()])\n"
    "_m.seek(0)\n"
    "_m.rfind(_d)\n"
    "_m.close()\n",
    /* mmap — write processes bytes */
    "_m = mmap.mmap(-1, max(len(_d), 1))\n"
    "_m.write(_d[:_m.size()])\n"
    "_m.seek(0); _m.read()\n"
    "_m.close()\n",
    /* array — frombytes processes bytes */
    "a = array.array('B'); a.frombytes(_d); a.tobytes()\n",
    /* array — frombytes with int typecode */
    "_aligned = _d[:len(_d)//4*4]\n"
    "a = array.array('i'); a.frombytes(_aligned) if _aligned else None; a.tobytes()\n",
    /* sqlite3 — execute processes SQL string */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('PRAGMA max_page_count=100')\n"
    "_c.execute(_s or 'SELECT 1')\n"
    "_c.close()\n",
    /* sqlite3 — cursor.executescript processes SQL string */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.execute('PRAGMA max_page_count=100')\n"
    "_c.executescript(_s or 'SELECT 1;')\n"
    "_c.close()\n",
    /* sqlite3 — create_collation processes strings */
    "_c = sqlite3.connect(':memory:')\n"
    "_c.create_collation('fuzz', lambda a, b: (a > b) - (a < b))\n"
    "_c.execute('CREATE TABLE t(a TEXT)')\n"
    "_c.execute('INSERT INTO t VALUES(?)', (_s,))\n"
    "_c.execute('SELECT * FROM t ORDER BY a COLLATE fuzz').fetchall()\n"
    "_c.close()\n",
};

#define MAX_DATAOPS_TEST_SIZE 0x10000

DEFINE_TEMPLATE_FUZZER(dataops, MAX_DATAOPS_TEST_SIZE)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    assert(Py_IsInitialized());
    static int initialized = 0;
    if (!initialized) {
        if (!init_dataops()) { PyErr_Print(); abort(); }
        initialized = 1;
    }
    int rv = fuzz_dataops((const char *)data, size);
    if (PyErr_Occurred()) {
        PyErr_Print();
        abort();
    }
    return rv;
}
