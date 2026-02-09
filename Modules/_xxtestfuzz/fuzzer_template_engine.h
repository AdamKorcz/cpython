/* Template-based fuzzer infrastructure for CPython fuzz targets.

   Each template fuzzer binary includes this header and defines its own
   template data (setup_code + template_sources[]).  Since each binary
   compiles exactly one .c file, all functions here are static.

   Provides: Python initialization, template compile/run, GC, LSAN. */

#ifndef FUZZER_TEMPLATE_ENGINE_H
#define FUZZER_TEMPLATE_ENGINE_H

#include <Python.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>

/* CPython generates a lot of leak warnings for whatever reason. */
int __lsan_is_turned_off(void) { return 1; }

/* Python initialization — same as the main fuzzer.c LLVMFuzzerInitialize. */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    PyConfig config;
    PyConfig_InitPythonConfig(&config);
    config.install_signal_handlers = 0;
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

/* ===================================================================
   Template-based fuzzer infrastructure.

   Instead of one fuzzer per module, we pre-compile Python code
   "templates" that call stdlib functions with the fuzz data as the
   parameter.  The first byte of fuzz input selects a template; the
   remaining bytes become _d (bytes) and _s (str, UTF-8 with
   replacement) in the template's namespace.
   =================================================================== */

static PyObject *fuzz_run_globals = NULL;
static PyObject *fuzz_run_locals = NULL;

static int init_fuzz_run_globals(void) {
    if (fuzz_run_globals != NULL)
        return 1;
    fuzz_run_globals = PyDict_New();
    if (fuzz_run_globals == NULL)
        return 0;
    PyDict_SetItemString(fuzz_run_globals, "__builtins__",
                         PyEval_GetBuiltins());
    fuzz_run_locals = PyDict_New();
    if (fuzz_run_locals == NULL)
        return 0;

    return 1;
}

/* Compile an array of Python source strings into code objects. */
static PyObject **compile_templates(const char **sources, int count) {
    PyObject **codes = (PyObject **)PyMem_RawMalloc(
        sizeof(PyObject *) * (size_t)count);
    if (codes == NULL) {
        PyErr_NoMemory();
        return NULL;
    }
    for (int i = 0; i < count; i++) {
        codes[i] = Py_CompileString(sources[i], "<fuzz>", Py_file_input);
        if (codes[i] == NULL)
            return NULL;
    }
    return codes;
}

/* Snapshot of sys.modules keys taken after init, so we can purge
   modules loaded as a side effect of fuzzing. */
static PyObject *baseline_module_keys = NULL;  /* Python set */

static void init_baseline_modules(void) {
    PyObject *sys_modules = PySys_GetObject("modules");  /* borrowed */
    if (sys_modules == NULL)
        return;
    PyObject *keys = PyDict_Keys(sys_modules);
    if (keys == NULL)
        return;
    baseline_module_keys = PySet_New(keys);
    Py_DECREF(keys);
}

/* Remove any modules from sys.modules that were not present at init. */
static void purge_new_modules(void) {
    if (baseline_module_keys == NULL)
        return;
    PyObject *sys_modules = PySys_GetObject("modules");  /* borrowed */
    if (sys_modules == NULL)
        return;
    PyObject *keys = PyDict_Keys(sys_modules);
    if (keys == NULL)
        return;
    Py_ssize_t len = PyList_GET_SIZE(keys);
    for (Py_ssize_t i = 0; i < len; i++) {
        PyObject *key = PyList_GET_ITEM(keys, i);
        if (PySet_Contains(baseline_module_keys, key) == 0)
            PyDict_DelItem(sys_modules, key);
    }
    Py_DECREF(keys);
    PyErr_Clear();  /* ignore any errors from deleting */
}

/* Clear __warningregistry__ from all loaded modules. */
static void clear_all_warning_registries(void) {
    PyObject *sys_modules = PySys_GetObject("modules");  /* borrowed ref */
    if (sys_modules == NULL || !PyDict_Check(sys_modules))
        return;

    PyObject *key, *module;
    Py_ssize_t pos = 0;
    while (PyDict_Next(sys_modules, &pos, &key, &module)) {
        if (module == NULL || module == Py_None)
            continue;
        PyObject *reg = PyObject_GetAttrString(module,
                                               "__warningregistry__");
        if (reg != NULL) {
            if (PyDict_Check(reg))
                PyDict_Clear(reg);
            Py_DECREF(reg);
        } else {
            PyErr_Clear();
        }
    }

    /* Also clear fuzz_run_globals's own __warningregistry__ */
    if (PyDict_GetItemString(fuzz_run_globals, "__warningregistry__"))
        PyDict_DelItemString(fuzz_run_globals, "__warningregistry__");
}

/* How often (in iterations) to force a full GC collection and clear
   warning registries. */
#define RUN_TEMPLATE_GC_INTERVAL 200

static int run_template(PyObject *code, const char *data, size_t size) {
    static unsigned long run_template_counter = 0;

    /* Reuse the locals dict: clear it to release all references from
       the previous iteration, then populate with fresh fuzz data. */
    PyDict_Clear(fuzz_run_locals);

    PyObject *bytes_obj = PyBytes_FromStringAndSize(data, size);
    if (bytes_obj == NULL)
        return 0;
    PyDict_SetItemString(fuzz_run_locals, "_d", bytes_obj);
    Py_DECREF(bytes_obj);

    PyObject *str_obj = PyUnicode_DecodeUTF8(data, size, "replace");
    if (str_obj != NULL) {
        PyDict_SetItemString(fuzz_run_locals, "_s", str_obj);
        Py_DECREF(str_obj);
    } else {
        PyErr_Clear();
        PyObject *empty = PyUnicode_FromString("");
        PyDict_SetItemString(fuzz_run_locals, "_s", empty);
        Py_DECREF(empty);
    }

    PyObject *result = PyEval_EvalCode(code, fuzz_run_globals,
                                       fuzz_run_locals);
    if (result == NULL) {
        if (PyErr_ExceptionMatches(PyExc_SystemError)) {
            PyErr_Print();
            abort();
        }
        PyErr_Clear();
    }
    Py_XDECREF(result);

    /* Clear locals immediately to release all template-created objects. */
    PyDict_Clear(fuzz_run_locals);

    if (++run_template_counter % RUN_TEMPLATE_GC_INTERVAL == 0) {
        clear_all_warning_registries();
        purge_new_modules();
        PyGC_Collect();
    }

    return 0;
}

/* Macro to define a template-based fuzzer.  Generates the NUM_*_TEMPLATES
   constant, the *_codes global, init_*(), and fuzz_*().  Must be placed
   after the corresponding *_template_sources[] array and *_setup_code
   string are defined. */
#define DEFINE_TEMPLATE_FUZZER(name, max_size)                              \
    static const int NUM_##name##_TEMPLATES =                               \
        (int)(sizeof(name##_template_sources)                               \
              / sizeof(name##_template_sources[0]));                        \
                                                                            \
    static PyObject **name##_codes = NULL;                                  \
                                                                            \
    static int init_##name(void) {                                          \
        if (!init_fuzz_run_globals()) return 0;                             \
        PyObject *r = PyRun_String(name##_setup_code, Py_file_input,        \
                                   fuzz_run_globals, fuzz_run_globals);      \
        if (r == NULL) return 0;                                            \
        Py_DECREF(r);                                                       \
        name##_codes = compile_templates(name##_template_sources,           \
                           NUM_##name##_TEMPLATES);                         \
        if (name##_codes == NULL) return 0;                                 \
        init_baseline_modules();                                            \
        return 1;                                                           \
    }                                                                       \
                                                                            \
    static int fuzz_##name(const char *data, size_t size) {                 \
        if (size < 1 || size > (max_size)) return 0;                        \
        int idx = (unsigned char)data[0] % NUM_##name##_TEMPLATES;          \
        return run_template(name##_codes[idx], data + 1, size - 1);         \
    }

#endif /* FUZZER_TEMPLATE_ENGINE_H */
