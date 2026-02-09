/* fuzz_textops.c — Text operations fuzzer. Covers: datetime, collections, unicodedata, io.StringIO */

#include "fuzzer_template_engine.h"

static const char *textops_setup_code =
    "import datetime, collections, unicodedata, io, struct, warnings\n"
    "warnings.filterwarnings('ignore')\n";

static const char *textops_template_sources[] = {
    /* datetime — ISO parsing */
    "datetime.date.fromisoformat(_s)\n",
    "datetime.time.fromisoformat(_s)\n",
    "datetime.datetime.fromisoformat(_s)\n",
    /* datetime — strptime */
    "datetime.datetime.strptime(_s, '%Y-%m-%d %H:%M:%S')\n",
    "datetime.datetime.strptime(_s, '%Y/%m/%dT%H:%M')\n",
    /* collections — _count_elements (Counter internals) */
    "d = {}; collections._count_elements(d, _s)\n",
    /* unicodedata */
    "[unicodedata.category(c) for c in _s]\n",
    "[unicodedata.bidirectional(c) for c in _s]\n",
    "unicodedata.normalize('NFC', _s)\n"
    "unicodedata.normalize('NFD', _s)\n",
    "unicodedata.normalize('NFKC', _s)\n"
    "unicodedata.normalize('NFKD', _s)\n",
    "[unicodedata.numeric(c, -1) for c in _s]\n",
    "unicodedata.lookup(_s)\n",
    "[unicodedata.name(c, '') for c in _s]\n",
    "[unicodedata.decomposition(c) for c in _s]\n",
    "unicodedata.is_normalized('NFC', _s)\n"
    "unicodedata.is_normalized('NFD', _s)\n",
    /* io.StringIO */
    "sio = io.StringIO(); sio.write(_s); sio.seek(0); sio.read(); sio.getvalue()\n",
    "sio = io.StringIO(_s)\n"
    "list(sio)\n",
    "sio = io.StringIO(_s); sio.truncate(min(len(_s), 64)); sio.tell()\n",
    /* unicodedata — east_asian_width + mirrored */
    "[unicodedata.east_asian_width(c) for c in _s]\n"
    "[unicodedata.mirrored(c) for c in _s]\n",
    /* unicodedata — ucd_3_2_0 normalize */
    "unicodedata.ucd_3_2_0.normalize('NFC', _s)\n",
    /* unicodedata — decimal */
    "[unicodedata.decimal(c, -1) for c in _s]\n",
    /* unicodedata — combining */
    "[unicodedata.combining(c) for c in _s]\n",
    /* datetime — strftime */
    "_vals = struct.unpack('6H', _d[:12].ljust(12, b'\\x00'))\n"
    "dt = datetime.datetime(max(1, _vals[0]%9999+1), max(1, _vals[1]%12+1),\n"
    "                       max(1, _vals[2]%28+1), _vals[3]%24, _vals[4]%60, _vals[5]%60)\n"
    "dt.strftime(_s or '%Y-%m-%d %H:%M:%S')\n"
    "dt.date().strftime(_s or '%Y-%m-%d')\n"
    "dt.time().strftime(_s or '%H:%M:%S')\n",
    /* datetime — date format strings */
    "_vals = struct.unpack('3H', _d[:6].ljust(6, b'\\x00'))\n"
    "d = datetime.date(max(1, _vals[0]%9999+1), max(1, _vals[1]%12+1), max(1, _vals[2]%28+1))\n"
    "format(d, _s[:16] or '%Y-%m-%d')\n",
};

#define MAX_TEXTOPS_TEST_SIZE 0x10000

DEFINE_TEMPLATE_FUZZER(textops, MAX_TEXTOPS_TEST_SIZE)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    assert(Py_IsInitialized());
    static int initialized = 0;
    if (!initialized) {
        if (!init_textops()) { PyErr_Print(); abort(); }
        initialized = 1;
    }
    int rv = fuzz_textops((const char *)data, size);
    if (PyErr_Occurred()) {
        PyErr_Print();
        abort();
    }
    return rv;
}
