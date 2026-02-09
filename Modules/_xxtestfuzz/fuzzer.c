/* A fuzz test for CPython.

  The only exposed function is LLVMFuzzerTestOneInput, which is called by
  fuzzers and by the _fuzz module for smoke tests.

  To build exactly one fuzz test, as when running in oss-fuzz etc.,
  build with -D _Py_FUZZ_ONE and -D _Py_FUZZ_<test_name>. e.g. to build
  LLVMFuzzerTestOneInput to only run "fuzz_builtin_float", build this file with
      -D _Py_FUZZ_ONE -D _Py_FUZZ_fuzz_builtin_float.

  See the source code for LLVMFuzzerTestOneInput for details. */

#ifndef Py_BUILD_CORE_MODULE
#  define Py_BUILD_CORE_MODULE 1
#endif

#include <Python.h>
#include <stdlib.h>
#include <inttypes.h>

/*  Fuzz PyFloat_FromString as a proxy for float(str). */
static int fuzz_builtin_float(const char* data, size_t size) {
    PyObject* s = PyBytes_FromStringAndSize(data, size);
    if (s == NULL) return 0;
    PyObject* f = PyFloat_FromString(s);
    if (PyErr_Occurred() && PyErr_ExceptionMatches(PyExc_ValueError)) {
        PyErr_Clear();
    }

    Py_XDECREF(f);
    Py_DECREF(s);
    return 0;
}

#define MAX_INT_TEST_SIZE 0x10000

/* Fuzz PyLong_FromUnicodeObject as a proxy for int(str). */
static int fuzz_builtin_int(const char* data, size_t size) {
    /* Ignore test cases with very long ints to avoid timeouts
       int("9" * 1000000) is not a very interesting test caase */
    if (size > MAX_INT_TEST_SIZE) {
        return 0;
    }
    /* Pick a random valid base. (When the fuzzed function takes extra
       parameters, it's somewhat normal to hash the input to generate those
       parameters. We want to exercise all code paths, so we do so here.) */
    int base = Py_HashBuffer(data, size) % 37;
    if (base == 1) {
        // 1 is the only number between 0 and 36 that is not a valid base.
        base = 0;
    }
    if (base == -1) {
        return 0;  // An error occurred, bail early.
    }
    if (base < 0) {
        base = -base;
    }

    PyObject* s = PyUnicode_FromStringAndSize(data, size);
    if (s == NULL) {
        if (PyErr_ExceptionMatches(PyExc_UnicodeDecodeError)) {
            PyErr_Clear();
        }
        return 0;
    }
    PyObject* l = PyLong_FromUnicodeObject(s, base);
    if (l == NULL && PyErr_ExceptionMatches(PyExc_ValueError)) {
        PyErr_Clear();
    }
    PyErr_Clear();
    Py_XDECREF(l);
    Py_DECREF(s);
    return 0;
}

/* Fuzz PyUnicode_FromStringAndSize as a proxy for unicode(str). */
static int fuzz_builtin_unicode(const char* data, size_t size) {
    PyObject* s = PyUnicode_FromStringAndSize(data, size);
    if (s == NULL && PyErr_ExceptionMatches(PyExc_UnicodeDecodeError)) {
        PyErr_Clear();
    }
    Py_XDECREF(s);
    return 0;
}


PyObject* struct_unpack_method = NULL;
PyObject* struct_pack_method = NULL;
PyObject* struct_calcsize_method = NULL;
PyObject* struct_iter_unpack_method = NULL;
PyObject* struct_unpack_from_method = NULL;
PyObject* struct_error = NULL;
/* Called by LLVMFuzzerTestOneInput for initialization */
static int init_struct_unpack(void) {
    /* Import struct module and methods */
    PyObject* struct_module = PyImport_ImportModule("struct");
    if (struct_module == NULL) {
        return 0;
    }
    struct_error = PyObject_GetAttrString(struct_module, "error");
    if (struct_error == NULL) {
        return 0;
    }
    struct_unpack_method = PyObject_GetAttrString(struct_module, "unpack");
    if (struct_unpack_method == NULL) {
        return 0;
    }
    struct_pack_method = PyObject_GetAttrString(struct_module, "pack");
    if (struct_pack_method == NULL) {
        return 0;
    }
    struct_calcsize_method = PyObject_GetAttrString(struct_module, "calcsize");
    if (struct_calcsize_method == NULL) {
        return 0;
    }
    struct_iter_unpack_method = PyObject_GetAttrString(struct_module, "iter_unpack");
    if (struct_iter_unpack_method == NULL) {
        return 0;
    }
    struct_unpack_from_method = PyObject_GetAttrString(struct_module, "unpack_from");
    if (struct_unpack_from_method == NULL) {
        return 0;
    }
    return 1;
}
/* Clear common struct exceptions */
static void clear_struct_errors(void) {
    if (PyErr_Occurred()) {
        if (PyErr_ExceptionMatches(PyExc_OverflowError) ||
            PyErr_ExceptionMatches(PyExc_SystemError) ||
            PyErr_ExceptionMatches(PyExc_MemoryError) ||
            PyErr_ExceptionMatches(struct_error)) {
            PyErr_Clear();
        }
    }
}
/* Fuzz struct module operations */
static int fuzz_struct_unpack(const char* data, size_t size) {
    /* Everything up to the first null byte is the format.
       The byte after the null selects the operation.
       Everything after that is the buffer. */
    const char* first_null = memchr(data, '\0', size);
    if (first_null == NULL) {
        return 0;
    }

    size_t format_length = first_null - data;
    const char* after_null = first_null + 1;
    size_t remaining = size - format_length - 1;

    /* Need at least 1 byte for operation selector */
    unsigned char op = 0;
    if (remaining > 0) {
        op = (unsigned char)after_null[0] % 5;
        after_null++;
        remaining--;
    }

    PyObject* pattern = PyBytes_FromStringAndSize(data, format_length);
    if (pattern == NULL) {
        return 0;
    }
    PyObject* buffer = PyBytes_FromStringAndSize(after_null, remaining);
    if (buffer == NULL) {
        Py_DECREF(pattern);
        return 0;
    }

    PyObject* result = NULL;

    switch (op) {
    case 0: /* unpack(fmt, buf) — original logic */
        result = PyObject_CallFunctionObjArgs(
            struct_unpack_method, pattern, buffer, NULL);
        clear_struct_errors();
        break;

    case 1: /* calcsize(fmt) — exercises format parsing */
        result = PyObject_CallOneArg(struct_calcsize_method, pattern);
        clear_struct_errors();
        break;

    case 2: { /* pack(fmt, *values) — exercises pack handlers */
        /* First compute the size, then unpack zeros to get the right
           number of args with correct types, then pack those back */
        PyObject* sz = PyObject_CallOneArg(struct_calcsize_method, pattern);
        if (sz == NULL) {
            clear_struct_errors();
            break;
        }
        Py_ssize_t nbytes = PyLong_AsSsize_t(sz);
        Py_DECREF(sz);
        if (nbytes < 0 || nbytes > 65536) {
            PyErr_Clear();
            break;
        }
        /* Create a zero buffer of the right size */
        PyObject* zeros = PyBytes_FromStringAndSize(NULL, nbytes);
        if (zeros == NULL) break;
        memset(PyBytes_AS_STRING(zeros), 0, nbytes);
        /* Unpack zeros to get a tuple of default values */
        PyObject* values = PyObject_CallFunctionObjArgs(
            struct_unpack_method, pattern, zeros, NULL);
        Py_DECREF(zeros);
        if (values == NULL) {
            clear_struct_errors();
            break;
        }
        /* Build args tuple: (fmt, val0, val1, ...) */
        Py_ssize_t nvals = PyTuple_GET_SIZE(values);
        PyObject* pack_args = PyTuple_New(nvals + 1);
        if (pack_args == NULL) {
            Py_DECREF(values);
            break;
        }
        Py_INCREF(pattern);
        PyTuple_SET_ITEM(pack_args, 0, pattern);
        for (Py_ssize_t i = 0; i < nvals; i++) {
            PyObject* v = PyTuple_GET_ITEM(values, i);
            Py_INCREF(v);
            PyTuple_SET_ITEM(pack_args, i + 1, v);
        }
        Py_DECREF(values);
        result = PyObject_Call(struct_pack_method, pack_args, NULL);
        Py_DECREF(pack_args);
        clear_struct_errors();
        break;
    }

    case 3: { /* iter_unpack(fmt, buf) — exercises unpackiter */
        PyObject* iter = PyObject_CallFunctionObjArgs(
            struct_iter_unpack_method, pattern, buffer, NULL);
        if (iter == NULL) {
            clear_struct_errors();
            break;
        }
        PyObject* item;
        int count = 0;
        while ((item = PyIter_Next(iter)) != NULL && count < 1000) {
            Py_DECREF(item);
            count++;
        }
        if (PyErr_Occurred()) {
            clear_struct_errors();
        }
        Py_DECREF(iter);
        break;
    }

    case 4: /* unpack_from(fmt, buf) — exercises offset handling */
        result = PyObject_CallFunctionObjArgs(
            struct_unpack_from_method, pattern, buffer, NULL);
        clear_struct_errors();
        break;
    }

    Py_XDECREF(result);
    Py_DECREF(pattern);
    Py_DECREF(buffer);
    return 0;
}


#define MAX_JSON_TEST_SIZE 0x100000

PyObject* json_loads_method = NULL;
/* Called by LLVMFuzzerTestOneInput for initialization */
static int init_json_loads(void) {
    /* Import json.loads */
    PyObject* json_module = PyImport_ImportModule("json");
    if (json_module == NULL) {
        return 0;
    }
    json_loads_method = PyObject_GetAttrString(json_module, "loads");
    return json_loads_method != NULL;
}
/* Fuzz json.loads(x) */
static int fuzz_json_loads(const char* data, size_t size) {
    /* Since python supports arbitrarily large ints in JSON,
       long inputs can lead to timeouts on boring inputs like
       `json.loads("9" * 100000)` */
    if (size > MAX_JSON_TEST_SIZE) {
        return 0;
    }
    PyObject* input_bytes = PyBytes_FromStringAndSize(data, size);
    if (input_bytes == NULL) {
        return 0;
    }
    PyObject* parsed = PyObject_CallOneArg(json_loads_method, input_bytes);
    if (parsed == NULL) {
        /* Ignore ValueError as the fuzzer will more than likely
           generate some invalid json and values */
        if (PyErr_ExceptionMatches(PyExc_ValueError) ||
        /* Ignore RecursionError as the fuzzer generates long sequences of
           arrays such as `[[[...` */
            PyErr_ExceptionMatches(PyExc_RecursionError) ||
        /* Ignore unicode errors, invalid byte sequences are common */
            PyErr_ExceptionMatches(PyExc_UnicodeDecodeError)
        ) {
            PyErr_Clear();
        }
    }
    Py_DECREF(input_bytes);
    Py_XDECREF(parsed);
    return 0;
}

#define MAX_RE_TEST_SIZE 0x10000

PyObject* re_compile_method = NULL;
PyObject* re_error_exception = NULL;
int RE_FLAG_DEBUG = 0;
/* Called by LLVMFuzzerTestOneInput for initialization */
static int init_sre_compile(void) {
    /* Import sre_compile.compile and sre.error */
    PyObject* re_module = PyImport_ImportModule("re");
    if (re_module == NULL) {
        return 0;
    }
    re_compile_method = PyObject_GetAttrString(re_module, "compile");
    if (re_compile_method == NULL) {
        return 0;
    }

    re_error_exception = PyObject_GetAttrString(re_module, "error");
    if (re_error_exception == NULL) {
        return 0;
    }
    PyObject* debug_flag = PyObject_GetAttrString(re_module, "DEBUG");
    if (debug_flag == NULL) {
        return 0;
    }
    RE_FLAG_DEBUG = PyLong_AsLong(debug_flag);
    return 1;
}
/* Fuzz re.compile(x) */
static int fuzz_sre_compile(const char* data, size_t size) {
    /* Ignore really long regex patterns that will timeout the fuzzer */
    if (size > MAX_RE_TEST_SIZE) {
        return 0;
    }
    /* We treat the first 2 bytes of the input as a number for the flags */
    if (size < 2) {
        return 0;
    }
    uint16_t flags = ((uint16_t*) data)[0];
    /* We remove the SRE_FLAG_DEBUG if present. This is because it
       prints to stdout which greatly decreases fuzzing speed */
    flags &= ~RE_FLAG_DEBUG;

    /* Pull the pattern from the remaining bytes */
    PyObject* pattern_bytes = PyBytes_FromStringAndSize(data + 2, size - 2);
    if (pattern_bytes == NULL) {
        return 0;
    }
    PyObject* flags_obj = PyLong_FromUnsignedLong(flags);
    if (flags_obj == NULL) {
        Py_DECREF(pattern_bytes);
        return 0;
    }

    /* compiled = re.compile(data[2:], data[0:2] */
    PyObject* compiled = PyObject_CallFunctionObjArgs(
        re_compile_method, pattern_bytes, flags_obj, NULL);
    /* Ignore ValueError as the fuzzer will more than likely
       generate some invalid combination of flags */
    if (compiled == NULL && PyErr_ExceptionMatches(PyExc_ValueError)) {
        PyErr_Clear();
    }
    /* Ignore some common errors thrown by sre_parse:
       Overflow, Assertion, Recursion and Index */
    if (compiled == NULL && (PyErr_ExceptionMatches(PyExc_OverflowError) ||
                             PyErr_ExceptionMatches(PyExc_AssertionError) ||
                             PyErr_ExceptionMatches(PyExc_RecursionError) ||
                             PyErr_ExceptionMatches(PyExc_IndexError))
    ) {
        PyErr_Clear();
    }
    /* Ignore re.error */
    if (compiled == NULL && PyErr_ExceptionMatches(re_error_exception)) {
        PyErr_Clear();
    }

    /* If compilation succeeded, exercise the matching engine with the
       pattern bytes themselves as match data.  This lets the fuzzer
       discover compile+match combinations that trigger deep SRE paths. */
    if (compiled != NULL) {
        PyObject* match_result = PyObject_CallMethod(
            compiled, "match", "O", pattern_bytes);
        if (match_result == NULL) {
            if (PyErr_ExceptionMatches(PyExc_RecursionError) ||
                PyErr_ExceptionMatches(PyExc_OverflowError)) {
                PyErr_Clear();
            }
        }
        Py_XDECREF(match_result);

        PyObject* search_result = PyObject_CallMethod(
            compiled, "search", "O", pattern_bytes);
        if (search_result == NULL) {
            if (PyErr_ExceptionMatches(PyExc_RecursionError) ||
                PyErr_ExceptionMatches(PyExc_OverflowError)) {
                PyErr_Clear();
            }
        }
        Py_XDECREF(search_result);
    }

    Py_DECREF(pattern_bytes);
    Py_DECREF(flags_obj);
    Py_XDECREF(compiled);
    return 0;
}

/* Some random patterns used to test re.match.
   Be careful not to add catostraphically slow regexes here, we want to
   exercise the matching code without causing timeouts.*/
static const char* regex_patterns[] = {
    /* basic patterns (original) */
    ".", "^", "abc", "abc|def", "^xxx$", "\\b", "()", "[a-zA-Z0-9]",
    "abc+", "[^A-Z]", "[x]", "(?=)", "a{z}", "a+b", "a*?", "a??", "a+?",
    "{}", "a{,}", "{", "}", "^\\(*\\d{3}\\)*( |-)*\\d{3}( |-)*\\d{4}$",
    "(?:a*)*", "a{1,2}?",
    /* lookahead / lookbehind (ASSERT / ASSERT_NOT opcodes) */
    "(?=abc)abc", "(?!xyz)...", "(?<=ab)c", "(?<!ab)c",
    /* backreferences (GROUPREF opcode) */
    "(a+)\\1", "(?P<name>a+)(?P=name)",
    /* conditional backreference (GROUPREF_EXISTS) */
    "(a)?(?(1)b|c)",
    /* character categories (CATEGORY ops) */
    "[\\w\\d\\s]+", "[\\W\\D\\S]+",
    /* possessive / atomic (Python 3.11+) */
    "(?>abc)", "a++b",
    /* flag variants */
    "(?m)^abc$", "(?s)a.b", "(?i)abc",
    /* more complex patterns */
    "(?:(?:a|b){2,4}c)+", "\\bfoo\\b.*\\bbar\\b",
    "(a(b(c)d)e)", "a(?:b|c){1,3}?d",
};
#define MAX_REGEX_PATTERNS \
    (sizeof(regex_patterns) / sizeof(regex_patterns[0]))
static size_t num_compiled_patterns = 0;
PyObject** compiled_patterns = NULL;
/* Called by LLVMFuzzerTestOneInput for initialization */
static int init_sre_match(void) {
    PyObject* re_module = PyImport_ImportModule("re");
    if (re_module == NULL) {
        return 0;
    }
    compiled_patterns = (PyObject**) PyMem_RawMalloc(
        sizeof(PyObject*) * MAX_REGEX_PATTERNS);
    if (compiled_patterns == NULL) {
        PyErr_NoMemory();
        return 0;
    }

    /* Precompile all the regex patterns on the first run for faster fuzzing.
       Skip patterns that fail to compile (e.g. possessive quantifiers on
       older Python versions) instead of aborting. */
    num_compiled_patterns = 0;
    for (size_t i = 0; i < MAX_REGEX_PATTERNS; i++) {
        PyObject* compiled = PyObject_CallMethod(
            re_module, "compile", "y", regex_patterns[i]);
        if (compiled == NULL) {
            PyErr_Clear();
            continue;
        }
        compiled_patterns[num_compiled_patterns++] = compiled;
    }
    return num_compiled_patterns > 0;
}

/* SRE operation names for dispatching */
static const char* sre_op_names[] = {
    "match", "search", "findall", "fullmatch", "split", "sub"
};
#define NUM_SRE_OPS 6

/* Fuzz re pattern operations */
static int fuzz_sre_match(const char* data, size_t size) {
    if (size < 2 || size > MAX_RE_TEST_SIZE) {
        return 0;
    }
    /* Byte 0: pattern selector, Byte 1: operation selector */
    unsigned char pat_idx = (unsigned char)data[0] % num_compiled_patterns;
    unsigned char op_idx = (unsigned char)data[1] % NUM_SRE_OPS;

    /* Pull the string to match from the remaining bytes */
    PyObject* to_match = PyBytes_FromStringAndSize(data + 2, size - 2);
    if (to_match == NULL) {
        return 0;
    }

    PyObject* pattern = compiled_patterns[pat_idx];
    PyObject* result = NULL;

    if (op_idx == 5) {
        /* sub(repl, string) — use empty bytes as replacement */
        PyObject* repl = PyBytes_FromStringAndSize("", 0);
        if (repl == NULL) {
            Py_DECREF(to_match);
            return 0;
        }
        result = PyObject_CallMethod(pattern, "sub", "OO", repl, to_match);
        Py_DECREF(repl);
    } else {
        PyObject* callable = PyObject_GetAttrString(
            pattern, sre_op_names[op_idx]);
        if (callable == NULL) {
            Py_DECREF(to_match);
            return 0;
        }
        result = PyObject_CallOneArg(callable, to_match);
        Py_DECREF(callable);
    }

    if (result == NULL) {
        if (PyErr_ExceptionMatches(PyExc_RecursionError) ||
            PyErr_ExceptionMatches(PyExc_OverflowError)) {
            PyErr_Clear();
        }
    }

    Py_XDECREF(result);
    Py_DECREF(to_match);
    return 0;
}

#define MAX_CSV_TEST_SIZE 0x100000
PyObject* csv_module = NULL;
PyObject* csv_error = NULL;
/* Called by LLVMFuzzerTestOneInput for initialization */
static int init_csv_reader(void) {
    /* Import csv and csv.Error */
    csv_module = PyImport_ImportModule("csv");
    if (csv_module == NULL) {
        return 0;
    }
    csv_error = PyObject_GetAttrString(csv_module, "Error");
    return csv_error != NULL;
}
/* Fuzz csv.reader([x]) */
static int fuzz_csv_reader(const char* data, size_t size) {
    if (size < 1 || size > MAX_CSV_TEST_SIZE) {
        return 0;
    }
    /* Ignore non null-terminated strings since _csv can't handle
       embedded nulls */
    if (memchr(data, '\0', size) == NULL) {
        return 0;
    }

    PyObject* s = PyUnicode_FromString(data);
    /* Ignore exceptions until we have a valid string */
    if (s == NULL) {
        PyErr_Clear();
        return 0;
    }

    /* Split on \n so we can test multiple lines */
    PyObject* lines = PyObject_CallMethod(s, "split", "s", "\n");
    if (lines == NULL) {
        Py_DECREF(s);
        return 0;
    }

    PyObject* reader = PyObject_CallMethod(csv_module, "reader", "N", lines);
    if (reader) {
        /* Consume all of the reader as an iterator */
        PyObject* parsed_line;
        while ((parsed_line = PyIter_Next(reader))) {
            Py_DECREF(parsed_line);
        }
    }

    /* Ignore csv.Error because we're probably going to generate
       some bad files (embedded new-lines, unterminated quotes etc) */
    if (PyErr_ExceptionMatches(csv_error)) {
        PyErr_Clear();
    }

    Py_XDECREF(reader);
    Py_DECREF(s);
    return 0;
}

#define MAX_AST_LITERAL_EVAL_TEST_SIZE 0x100000
PyObject* ast_literal_eval_method = NULL;
/* Called by LLVMFuzzerTestOneInput for initialization */
static int init_ast_literal_eval(void) {
    PyObject* ast_module = PyImport_ImportModule("ast");
    if (ast_module == NULL) {
        return 0;
    }
    ast_literal_eval_method = PyObject_GetAttrString(ast_module, "literal_eval");
    return ast_literal_eval_method != NULL;
}
/* Fuzz ast.literal_eval(x) */
static int fuzz_ast_literal_eval(const char* data, size_t size) {
    if (size > MAX_AST_LITERAL_EVAL_TEST_SIZE) {
        return 0;
    }
    /* Ignore non null-terminated strings since ast can't handle
       embedded nulls */
    if (memchr(data, '\0', size) == NULL) {
        return 0;
    }

    PyObject* s = PyUnicode_FromString(data);
    /* Ignore exceptions until we have a valid string */
    if (s == NULL) {
        PyErr_Clear();
        return 0;
    }

    PyObject* literal = PyObject_CallOneArg(ast_literal_eval_method, s);
    /* Ignore some common errors thrown by ast.literal_eval */
    if (literal == NULL && (PyErr_ExceptionMatches(PyExc_ValueError) ||
                            PyErr_ExceptionMatches(PyExc_TypeError) ||
                            PyErr_ExceptionMatches(PyExc_SyntaxError) ||
                            PyErr_ExceptionMatches(PyExc_MemoryError) ||
                            PyErr_ExceptionMatches(PyExc_RecursionError))
    ) {
        PyErr_Clear();
    }

    Py_XDECREF(literal);
    Py_DECREF(s);
    return 0;
}

#define MAX_ELEMENTTREE_PARSEWHOLE_TEST_SIZE 0x100000
PyObject* xmlparser_type = NULL;
PyObject* bytesio_type = NULL;
PyObject* treebuilder_type = NULL;
/* Called by LLVMFuzzerTestOneInput for initialization */
static int init_elementtree_parsewhole(void) {
    PyObject* elementtree_module = PyImport_ImportModule("_elementtree");
    if (elementtree_module == NULL) {
        return 0;
    }
    xmlparser_type = PyObject_GetAttrString(elementtree_module, "XMLParser");
    if (xmlparser_type == NULL) {
        Py_DECREF(elementtree_module);
        return 0;
    }
    treebuilder_type = PyObject_GetAttrString(elementtree_module, "TreeBuilder");
    Py_DECREF(elementtree_module);
    if (treebuilder_type == NULL) {
        return 0;
    }

    PyObject* io_module = PyImport_ImportModule("io");
    if (io_module == NULL) {
        return 0;
    }
    bytesio_type = PyObject_GetAttrString(io_module, "BytesIO");
    Py_DECREF(io_module);
    if (bytesio_type == NULL) {
        return 0;
    }

    return 1;
}

/* Walk an Element tree to exercise accessor and search paths */
static void walk_element_tree(PyObject* root) {
    if (root == NULL || root == Py_None) return;

    /* Access .tag, .text, .tail, .attrib */
    PyObject* tag = PyObject_GetAttrString(root, "tag");
    Py_XDECREF(tag);
    PyObject* text = PyObject_GetAttrString(root, "text");
    Py_XDECREF(text);
    PyObject* tail = PyObject_GetAttrString(root, "tail");
    Py_XDECREF(tail);
    PyObject* attrib = PyObject_GetAttrString(root, "attrib");
    Py_XDECREF(attrib);

    /* len(root) */
    Py_ssize_t n = PyObject_Length(root);
    if (n < 0) { PyErr_Clear(); }

    /* iter() — iterate children */
    PyObject* iter = PyObject_CallMethod(root, "iter", NULL);
    if (iter != NULL) {
        PyObject* child;
        int count = 0;
        while ((child = PyIter_Next(iter)) != NULL && count < 100) {
            Py_DECREF(child);
            count++;
        }
        if (PyErr_Occurred()) PyErr_Clear();
        Py_DECREF(iter);
    } else {
        PyErr_Clear();
    }

    /* find("*") and findall("*") */
    PyObject* star = PyUnicode_FromString("*");
    if (star != NULL) {
        PyObject* found = PyObject_CallMethod(root, "find", "O", star);
        Py_XDECREF(found);
        if (PyErr_Occurred()) PyErr_Clear();
        PyObject* found_all = PyObject_CallMethod(root, "findall", "O", star);
        Py_XDECREF(found_all);
        if (PyErr_Occurred()) PyErr_Clear();
        Py_DECREF(star);
    } else {
        PyErr_Clear();
    }
}

/* Fuzz _elementtree.XMLParser with multiple modes */
static int fuzz_elementtree_parsewhole(const char* data, size_t size) {
    if (size < 1 || size > MAX_ELEMENTTREE_PARSEWHOLE_TEST_SIZE) {
        return 0;
    }

    /* Byte 0 selects mode */
    unsigned char mode = (unsigned char)data[0] % 3;
    const char* xml_data = data + 1;
    size_t xml_size = size - 1;

    if (mode == 0) {
        /* Mode 0: original _parse_whole (backward compatible) */
        PyObject *input = PyObject_CallFunction(
            bytesio_type, "y#", xml_data, (Py_ssize_t)xml_size);
        if (input == NULL) { PyErr_Clear(); return 0; }

        PyObject *parser = PyObject_CallObject(xmlparser_type, NULL);
        if (parser == NULL) { PyErr_Clear(); Py_DECREF(input); return 0; }

        PyObject *result = PyObject_CallMethod(
            parser, "_parse_whole", "O", input);
        if (result == NULL) {
            PyErr_Clear();
        } else {
            Py_DECREF(result);
        }
        Py_DECREF(parser);
        Py_DECREF(input);

    } else if (mode == 1) {
        /* Mode 1: TreeBuilder with insert_comments=True, insert_pis=True */
        PyObject *kwargs = PyDict_New();
        if (kwargs == NULL) return 0;
        PyDict_SetItemString(kwargs, "insert_comments", Py_True);
        PyDict_SetItemString(kwargs, "insert_pis", Py_True);
        PyObject *empty_args = PyTuple_New(0);
        if (empty_args == NULL) { Py_DECREF(kwargs); return 0; }
        PyObject *tb = PyObject_Call(treebuilder_type, empty_args, kwargs);
        Py_DECREF(empty_args);
        Py_DECREF(kwargs);
        if (tb == NULL) { PyErr_Clear(); return 0; }

        /* Create XMLParser with target=tb */
        PyObject *parser_kwargs = PyDict_New();
        if (parser_kwargs == NULL) { Py_DECREF(tb); return 0; }
        PyDict_SetItemString(parser_kwargs, "target", tb);
        PyObject *parser_args = PyTuple_New(0);
        if (parser_args == NULL) {
            Py_DECREF(parser_kwargs); Py_DECREF(tb); return 0;
        }
        PyObject *parser = PyObject_Call(
            xmlparser_type, parser_args, parser_kwargs);
        Py_DECREF(parser_args);
        Py_DECREF(parser_kwargs);
        if (parser == NULL) { Py_DECREF(tb); PyErr_Clear(); return 0; }

        PyObject *input = PyObject_CallFunction(
            bytesio_type, "y#", xml_data, (Py_ssize_t)xml_size);
        if (input == NULL) {
            PyErr_Clear(); Py_DECREF(parser); Py_DECREF(tb); return 0;
        }
        PyObject *result = PyObject_CallMethod(
            parser, "_parse_whole", "O", input);
        if (result == NULL) {
            PyErr_Clear();
        } else {
            walk_element_tree(result);
            Py_DECREF(result);
        }
        Py_DECREF(input);
        Py_DECREF(parser);
        Py_DECREF(tb);

    } else {
        /* Mode 2: incremental feed() in 2 chunks + close() + tree walk */
        PyObject *parser = PyObject_CallObject(xmlparser_type, NULL);
        if (parser == NULL) { PyErr_Clear(); return 0; }

        size_t mid = xml_size / 2;
        PyObject *chunk1 = PyBytes_FromStringAndSize(xml_data, mid);
        if (chunk1 == NULL) { Py_DECREF(parser); return 0; }
        PyObject *r1 = PyObject_CallMethod(parser, "feed", "O", chunk1);
        Py_DECREF(chunk1);
        if (r1 == NULL) {
            PyErr_Clear();
            Py_DECREF(parser);
            return 0;
        }
        Py_DECREF(r1);

        PyObject *chunk2 = PyBytes_FromStringAndSize(
            xml_data + mid, xml_size - mid);
        if (chunk2 == NULL) { Py_DECREF(parser); return 0; }
        PyObject *r2 = PyObject_CallMethod(parser, "feed", "O", chunk2);
        Py_DECREF(chunk2);
        if (r2 == NULL) {
            PyErr_Clear();
            Py_DECREF(parser);
            return 0;
        }
        Py_DECREF(r2);

        PyObject *root = PyObject_CallMethod(parser, "close", NULL);
        if (root == NULL) {
            PyErr_Clear();
        } else {
            walk_element_tree(root);
            Py_DECREF(root);
        }
        Py_DECREF(parser);
    }

    return 0;
}

#define MAX_PYCOMPILE_TEST_SIZE 16384

static const int start_vals[] = {Py_eval_input, Py_single_input, Py_file_input};
const size_t NUM_START_VALS = sizeof(start_vals) / sizeof(start_vals[0]);

static const int optimize_vals[] = {-1, 0, 1, 2};
const size_t NUM_OPTIMIZE_VALS = sizeof(optimize_vals) / sizeof(optimize_vals[0]);

/* Fuzz `PyCompileStringExFlags` using a variety of input parameters.
 * That function is essentially behind the `compile` builtin */
static int fuzz_pycompile(const char* data, size_t size) {
    // Ignore overly-large inputs, and account for a NUL terminator
    if (size > MAX_PYCOMPILE_TEST_SIZE - 1) {
        return 0;
    }

    // Need 2 bytes for parameter selection
    if (size < 2) {
        return 0;
    }

    // Use first byte to determine element of `start_vals` to use
    unsigned char start_idx = (unsigned char) data[0];
    int start = start_vals[start_idx % NUM_START_VALS];

    // Use second byte to determine element of `optimize_vals` to use
    unsigned char optimize_idx = (unsigned char) data[1];
    int optimize = optimize_vals[optimize_idx % NUM_OPTIMIZE_VALS];

    char pycompile_scratch[MAX_PYCOMPILE_TEST_SIZE];

    // Create a NUL-terminated C string from the remaining input
    memcpy(pycompile_scratch, data + 2, size - 2);
    // Put a NUL terminator just after the copied data. (Space was reserved already.)
    pycompile_scratch[size - 2] = '\0';

    // XXX: instead of always using NULL for the `flags` value to
    // `Py_CompileStringExFlags`, there are many flags that conditionally
    // change parser behavior:
    //
    //     #define PyCF_TYPE_COMMENTS 0x1000
    //     #define PyCF_ALLOW_TOP_LEVEL_AWAIT 0x2000
    //     #define PyCF_ONLY_AST 0x0400
    //
    // It would be good to test various combinations of these, too.
    PyCompilerFlags *flags = NULL;

    PyObject *result = Py_CompileStringExFlags(pycompile_scratch, "<fuzz input>", start, flags, optimize);
    if (result == NULL) {
        /* Compilation failed, most likely from a syntax error. If it was a
           SystemError we abort. There's no non-bug reason to raise a
           SystemError. */
        if (PyErr_Occurred() && PyErr_ExceptionMatches(PyExc_SystemError)) {
            PyErr_Print();
            abort();
        }
        PyErr_Clear();
    } else {
        Py_DECREF(result);
    }

    return 0;
}

/* Run fuzzer and abort on failure. */
static int _run_fuzz(const uint8_t *data, size_t size, int(*fuzzer)(const char* , size_t)) {
    int rv = fuzzer((const char*) data, size);
    if (PyErr_Occurred()) {
        /* Fuzz tests should handle expected errors for themselves.
           This is last-ditch check in case they didn't. */
        PyErr_Print();
        abort();
    }
    /* Someday the return value might mean something, propagate it. */
    return rv;
}

/* CPython generates a lot of leak warnings for whatever reason. */
int __lsan_is_turned_off(void) { return 1; }


int LLVMFuzzerInitialize(int *argc, char ***argv) {
    PyConfig config;
    PyConfig_InitPythonConfig(&config);
    config.install_signal_handlers = 0;
    /* Raise the limit above the default allows exercising larger things
     * now that we fall back to the _pylong module for large values. */
    config.int_max_str_digits = 8086;
    PyStatus status;
    status = PyConfig_SetBytesString(&config, &config.program_name, *argv[0]);
    if (PyStatus_Exception(status)) {
        goto fail;
    }

    status = Py_InitializeFromConfig(&config);
    if (PyStatus_Exception(status)) {
        goto fail;
    }
    PyConfig_Clear(&config);

    return 0;

fail:
    PyConfig_Clear(&config);
    Py_ExitStatusException(status);
}

/* Dispatch macros for LLVMFuzzerTestOneInput.  FUZZ_TARGET handles
   lazy init + run; FUZZ_TARGET_NO_INIT handles targets that need no
   initialization step. */
#define FUZZ_TARGET(name, init_func)                                        \
    do {                                                                    \
        static int _initialized = 0;                                        \
        if (!_initialized) {                                                \
            if (!init_func()) { PyErr_Print(); abort(); }                   \
            _initialized = 1;                                               \
        }                                                                   \
        rv |= _run_fuzz(data, size, fuzz_##name);                           \
    } while (0)

#define FUZZ_TARGET_NO_INIT(name)                                           \
    rv |= _run_fuzz(data, size, fuzz_##name)

/* Fuzz test interface.
   This returns the bitwise or of all fuzz test's return values.

   All fuzz tests must return 0, as all nonzero return codes are reserved for
   future use -- we propagate the return values for that future case.
   (And we bitwise or when running multiple tests to verify that normally we
   only return 0.) */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    assert(Py_IsInitialized());

    int rv = 0;

#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_builtin_float)
    FUZZ_TARGET_NO_INIT(builtin_float);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_builtin_int)
    FUZZ_TARGET_NO_INIT(builtin_int);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_builtin_unicode)
    FUZZ_TARGET_NO_INIT(builtin_unicode);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_struct_unpack)
    FUZZ_TARGET(struct_unpack, init_struct_unpack);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_json_loads)
    FUZZ_TARGET(json_loads, init_json_loads);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_sre_compile)
    FUZZ_TARGET(sre_compile, init_sre_compile);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_sre_match)
    FUZZ_TARGET(sre_match, init_sre_match);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_csv_reader)
    FUZZ_TARGET(csv_reader, init_csv_reader);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_ast_literal_eval)
    FUZZ_TARGET(ast_literal_eval, init_ast_literal_eval);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_elementtree_parsewhole)
    FUZZ_TARGET(elementtree_parsewhole, init_elementtree_parsewhole);
#endif
#if !defined(_Py_FUZZ_ONE) || defined(_Py_FUZZ_fuzz_pycompile)
    FUZZ_TARGET_NO_INIT(pycompile);
#endif
    return rv;
}

