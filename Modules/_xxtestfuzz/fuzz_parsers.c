/* fuzz_parsers.c — Parser and text processing fuzzer. Covers: _json, _csv, pyexpat, timemodule, _operator, _localemodule, _opcode */

#include "fuzzer_template_engine.h"

static const char *parsers_setup_code =
    "import json, csv, io, time, operator, dis, locale, warnings\n"
    "import xml.parsers.expat\n"
    "warnings.filterwarnings('ignore')\n";

static const char *parsers_template_sources[] = {
    /* JSON — JSONEncoder options */
    "json.JSONEncoder(sort_keys=True, indent=2, ensure_ascii=False).encode(_s)\n",

    /* CSV — Sniffer */
    "csv.Sniffer().sniff(_s[:1024])\n",
    "csv.Sniffer().has_header(_s[:1024])\n",

    /* expat — utf-8 parse */
    "p = xml.parsers.expat.ParserCreate('utf-8')\n"
    "p.Parse(_d[:4096], True)\n",
    /* expat — iso-8859-1 parse */
    "p = xml.parsers.expat.ParserCreate('iso-8859-1')\n"
    "p.Parse(_d[:4096], True)\n",
    /* expat — namespace_separator */
    "p = xml.parsers.expat.ParserCreate(namespace_separator=' ')\n"
    "p.Parse(_d[:4096], True)\n",
    /* expat — all handlers */
    "p = xml.parsers.expat.ParserCreate()\n"
    "p.StartElementHandler = lambda *a: None\n"
    "p.EndElementHandler = lambda *a: None\n"
    "p.CharacterDataHandler = lambda *a: None\n"
    "p.ProcessingInstructionHandler = lambda *a: None\n"
    "p.CommentHandler = lambda *a: None\n"
    "p.StartCdataSectionHandler = lambda: None\n"
    "p.EndCdataSectionHandler = lambda: None\n"
    "p.Parse(_d[:4096], True)\n",
    /* expat — ParseFile */
    "p = xml.parsers.expat.ParserCreate()\n"
    "p.ParseFile(io.BytesIO(_d[:4096]))\n",
    /* expat — external entity */
    "p = xml.parsers.expat.ParserCreate()\n"
    "p.Parse(_d[:2048], True)\n"
    "p.GetInputContext()\n",

    /* time — strftime with fuzz input */
    "time.strftime(_s or '%Y', time.localtime())\n",
    /* time — strptime with fuzz input */
    "time.strptime(_s, '%Y-%m-%d %H:%M:%S')\n",

    /* operator — comparisons on bytes */
    "operator.lt(_d, _d[::-1]); operator.gt(_d, _d[::-1])\n"
    "operator.eq(_d, _d); operator.ne(_d, b'')\n",
    /* operator — sequence ops on bytes */
    "operator.contains(_d, _d[0] if _d else 0)\n"
    "operator.countOf(_d, _d[0] if _d else 0)\n"
    "operator.indexOf(_d, _d[0] if _d else 0) if _d else None\n"
    "operator.length_hint(_d)\n",
    /* dis — covers _opcode */
    "dis.dis(compile(_s or 'pass', '<f>', 'exec'))\n",
    /* locale — strxfrm + getlocale */
    "locale.strxfrm(_s); locale.getlocale()\n",

    /* JSON — encoder encode_string */
    "json.dumps(_s)\n",
    /* JSON — encoder encode dict of strings */
    "json.dumps({_s: _s})\n",
    /* JSON — encoder encode list of strings */
    "json.dumps([_s, _s])\n",
    /* JSON — JSONEncoder ensure_ascii=False */
    "json.JSONEncoder(ensure_ascii=False).encode(_s)\n",
    /* JSON — JSONEncoder ensure_ascii=True */
    "json.JSONEncoder(ensure_ascii=True).encode(_s)\n",
    /* JSON — JSONEncoder sort_keys + indent */
    "json.JSONEncoder(sort_keys=True, indent=2).encode({_s: _s})\n",

    /* CSV — writer writerow */
    "_out = io.StringIO()\n"
    "w = csv.writer(_out)\n"
    "w.writerow(_s.split() or [''])\n"
    "_out.getvalue()\n",
    /* CSV — writer writerows */
    "_out = io.StringIO()\n"
    "w = csv.writer(_out)\n"
    "w.writerows([line.split() or [''] for line in _s.splitlines()])\n"
    "_out.getvalue()\n",
    /* CSV — writer with tab delimiter */
    "_out = io.StringIO()\n"
    "w = csv.writer(_out, delimiter='\\t')\n"
    "w.writerow(_s.split() or [''])\n"
    "_out.getvalue()\n",
    /* CSV — DictWriter */
    "_out = io.StringIO()\n"
    "_fnames = _s.split()[:8] or ['a']\n"
    "w = csv.DictWriter(_out, fieldnames=_fnames)\n"
    "w.writeheader()\n"
    "w.writerow({f: _s for f in _fnames})\n"
    "_out.getvalue()\n",
    /* CSV — writer with QUOTE_ALL */
    "_out = io.StringIO()\n"
    "w = csv.writer(_out, quoting=csv.QUOTE_ALL)\n"
    "w.writerow(_s.split() or [''])\n"
    "_out.getvalue()\n",
    /* CSV — writer with QUOTE_NONNUMERIC */
    "_out = io.StringIO()\n"
    "w = csv.writer(_out, quoting=csv.QUOTE_NONNUMERIC)\n"
    "w.writerow(_s.split() or [''])\n"
    "_out.getvalue()\n",

    /* time — strptime with fuzz format */
    "time.strptime('2024-01-15 12:30:00', _s or '%Y-%m-%d %H:%M:%S')\n",

    /* locale — strcoll */
    "locale.strcoll(_s[:len(_s)//2], _s[len(_s)//2:])\n",

    /* operator — concat on bytes */
    "operator.concat(_d, _d)\n",
    /* operator — contains on bytes */
    "operator.contains(_d, _d[:1] if _d else b'')\n",
    /* operator — getitem on bytes */
    "operator.getitem(_d, 0) if _d else None\n"
    "operator.getitem(_d, slice(0, len(_d)//2))\n",
    /* operator — methodcaller on string */
    "operator.methodcaller('upper')(_s)\n"
    "operator.methodcaller('encode', 'utf-8')(_s)\n",
};

#define MAX_PARSERS_TEST_SIZE 0x10000

DEFINE_TEMPLATE_FUZZER(parsers, MAX_PARSERS_TEST_SIZE)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    assert(Py_IsInitialized());
    static int initialized = 0;
    if (!initialized) {
        if (!init_parsers()) { PyErr_Print(); abort(); }
        initialized = 1;
    }
    int rv = fuzz_parsers((const char *)data, size);
    if (PyErr_Occurred()) {
        PyErr_Print();
        abort();
    }
    return rv;
}
