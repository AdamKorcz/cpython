/* fuzz_ioops.c — I/O operations fuzzer. Covers: _io/textio.c, _io/bufferedio.c, _io/fileio.c, _io/bytesio.c, _io/iobase.c, _io/stringio.c, _io/_iomodule.c */

#include "fuzzer_template_engine.h"

static const char *ioops_setup_code =
    "import io, os, tempfile, struct, warnings\n"
    "warnings.filterwarnings('ignore')\n"
    "_tmpdir = tempfile.mkdtemp(prefix='fuzz_io_')\n"
    "_tmpfile = os.path.join(_tmpdir, 'test')\n"
    "with open(_tmpfile, 'wb') as f:\n"
    "    f.write(b'A' * 4096)\n";

static const char *ioops_template_sources[] = {
    /* BytesIO — basic write/seek/read/getvalue/tell */
    "bio = io.BytesIO()\n"
    "bio.write(_d); bio.seek(0); bio.read(); bio.getvalue(); bio.tell()\n"
    "bio.close()\n",
    /* BytesIO — readline, readlines, readinto */
    "bio = io.BytesIO(_d)\n"
    "bio.readline(); bio.seek(0); bio.readlines()\n"
    "bio.seek(0); buf = bytearray(32); bio.readinto(buf)\n"
    "bio.close()\n",
    /* BytesIO — truncate + write + getvalue */
    "bio = io.BytesIO(_d)\n"
    "bio.truncate(min(len(_d), 64)); bio.write(b'XX'); bio.getvalue()\n"
    "bio.close()\n",
    /* BytesIO — getbuffer (memoryview) */
    "bio = io.BytesIO(_d)\n"
    "mv = bio.getbuffer(); bytes(mv); mv.release()\n"
    "bio.close()\n",
    /* BytesIO — read1, readinto1 */
    "bio = io.BytesIO(_d)\n"
    "bio.read1(16); bio.seek(0)\n"
    "buf = bytearray(32); bio.readinto1(buf)\n"
    "bio.close()\n",
    /* BytesIO — iteration */
    "bio = io.BytesIO(_d)\n"
    "for line in bio: pass\n"
    "bio.close()\n",
    /* BytesIO — peek via BufferedReader wrapping */
    "bio = io.BytesIO(_d)\n"
    "br = io.BufferedReader(bio)\n"
    "br.peek(16); br.read(8); br.read1(8)\n"
    "br.close()\n",
    /* BytesIO — write large + seek from end */
    "bio = io.BytesIO()\n"
    "bio.write(_d); bio.seek(-min(len(_d), 16), 2); bio.read(); bio.getvalue()\n"
    "bio.close()\n",

    /* TextIOWrapper — wrap BytesIO utf-8 */
    "bio = io.BytesIO()\n"
    "tw = io.TextIOWrapper(bio, encoding='utf-8')\n"
    "tw.write(_s); tw.seek(0); tw.read()\n"
    "tw.close()\n",
    /* TextIOWrapper — latin-1 */
    "bio = io.BytesIO()\n"
    "tw = io.TextIOWrapper(bio, encoding='latin-1')\n"
    "tw.write(_s); tw.seek(0); tw.read(); tw.seek(0); tw.readline()\n"
    "tw.close()\n",
    /* TextIOWrapper — ascii errors='replace' */
    "bio = io.BytesIO()\n"
    "tw = io.TextIOWrapper(bio, encoding='ascii', errors='replace')\n"
    "tw.write(_s); tw.seek(0); tw.read()\n"
    "tw.close()\n",
    /* TextIOWrapper — utf-16, readline */
    "bio = io.BytesIO()\n"
    "tw = io.TextIOWrapper(bio, encoding='utf-16')\n"
    "tw.write(_s); tw.seek(0); tw.readline()\n"
    "tw.close()\n",
    /* TextIOWrapper — newline modes */
    "bio = io.BytesIO()\n"
    "tw = io.TextIOWrapper(bio, encoding='utf-8', newline='\\r\\n')\n"
    "tw.write(_s); tw.seek(0); tw.read()\n"
    "tw.close()\n",
    "bio = io.BytesIO()\n"
    "tw = io.TextIOWrapper(bio, encoding='utf-8', newline='')\n"
    "tw.write(_s); tw.seek(0); tw.readlines()\n"
    "tw.close()\n",
    /* TextIOWrapper — reconfigure */
    "bio = io.BytesIO()\n"
    "tw = io.TextIOWrapper(bio, encoding='utf-8')\n"
    "tw.write(_s)\n"
    "tw.reconfigure(newline='\\n', line_buffering=True)\n"
    "tw.write(_s[:32]); tw.seek(0); tw.read()\n"
    "tw.close()\n",
    /* TextIOWrapper — detach */
    "bio = io.BytesIO(_d)\n"
    "tw = io.TextIOWrapper(bio, encoding='utf-8', errors='replace')\n"
    "tw.read(4); raw = tw.detach()\n"
    "raw.read(); raw.close()\n",
    /* TextIOWrapper — writable/readable/seekable */
    "bio = io.BytesIO(_d)\n"
    "tw = io.TextIOWrapper(bio, encoding='utf-8', errors='replace')\n"
    "tw.writable(); tw.readable(); tw.seekable()\n"
    "tw.encoding; tw.buffer\n"
    "tw.close()\n",
    /* TextIOWrapper — error handlers */
    "bio = io.BytesIO(_d)\n"
    "tw = io.TextIOWrapper(bio, encoding='ascii', errors='xmlcharrefreplace')\n"
    "tw.write(_s); tw.seek(0); tw.read()\n"
    "tw.close()\n",
    "bio = io.BytesIO(_d)\n"
    "tw = io.TextIOWrapper(bio, encoding='ascii', errors='backslashreplace')\n"
    "tw.write(_s); tw.seek(0); tw.read()\n"
    "tw.close()\n",

    /* BufferedReader — wrapping FileIO */
    "_fd = os.open(_tmpfile, os.O_RDONLY)\n"
    "fio = io.FileIO(_fd, 'r', closefd=True)\n"
    "br = io.BufferedReader(fio)\n"
    "br.read(64); br.seek(0); br.peek(16); br.read1(16)\n"
    "br.close()\n",
    /* BufferedWriter — wrapping FileIO */
    "_p = os.path.join(_tmpdir, 'bw')\n"
    "fio = io.FileIO(_p, 'w')\n"
    "bw = io.BufferedWriter(fio)\n"
    "bw.write(_d); bw.flush()\n"
    "bw.close()\n"
    "os.unlink(_p)\n",
    /* BufferedRandom — wrapping FileIO */
    "_p = os.path.join(_tmpdir, 'br')\n"
    "fio = io.FileIO(_p, 'w+b')\n"
    "brnd = io.BufferedRandom(fio)\n"
    "brnd.write(_d); brnd.seek(0); brnd.read(64); brnd.tell()\n"
    "brnd.close()\n"
    "os.unlink(_p)\n",
    /* BufferedReader with different buffer_size */
    "_fd = os.open(_tmpfile, os.O_RDONLY)\n"
    "fio = io.FileIO(_fd, 'r', closefd=True)\n"
    "br = io.BufferedReader(fio, buffer_size=64)\n"
    "br.read(32); br.read(32)\n"
    "br.close()\n",
    /* BufferedWriter — write + truncate */
    "_p = os.path.join(_tmpdir, 'bwt')\n"
    "fio = io.FileIO(_p, 'w+b')\n"
    "bw = io.BufferedRandom(fio)\n"
    "bw.write(_d); bw.truncate(64); bw.seek(0); bw.read()\n"
    "bw.close()\n"
    "os.unlink(_p)\n",
    /* BufferedRWPair */
    "r_bio = io.BytesIO(_d)\n"
    "w_bio = io.BytesIO()\n"
    "rw = io.BufferedRWPair(r_bio, w_bio)\n"
    "rw.read(32); rw.write(_d)\n"
    "rw.close()\n",
    /* raw property + detach */
    "_fd = os.open(_tmpfile, os.O_RDONLY)\n"
    "fio = io.FileIO(_fd, 'r', closefd=True)\n"
    "br = io.BufferedReader(fio)\n"
    "br.raw; raw = br.detach(); raw.close()\n",

    /* FileIO — read, readall, readinto */
    "fio = io.FileIO(_tmpfile, 'r')\n"
    "fio.read(64); fio.seek(0); fio.readall()\n"
    "fio.seek(0); buf = bytearray(64); fio.readinto(buf)\n"
    "fio.close()\n",
    /* FileIO — write, flush, tell, seek */
    "_p = os.path.join(_tmpdir, 'fio_w')\n"
    "fio = io.FileIO(_p, 'w')\n"
    "fio.write(_d); fio.flush(); fio.tell(); fio.seek(0)\n"
    "fio.close()\n"
    "os.unlink(_p)\n",
    /* FileIO — r+b mode */
    "_p = os.path.join(_tmpdir, 'fio_rw')\n"
    "with open(_p, 'wb') as f: f.write(b'X' * 256)\n"
    "fio = io.FileIO(_p, 'r+')\n"
    "fio.read(32); fio.write(_d[:32]); fio.seek(0); fio.truncate(128)\n"
    "fio.close()\n"
    "os.unlink(_p)\n",
    /* FileIO — fileno, isatty, name, mode, closefd, properties */
    "fio = io.FileIO(_tmpfile, 'r')\n"
    "fio.fileno(); fio.isatty(); fio.name; fio.mode; fio.closefd\n"
    "fio.readable(); fio.writable(); fio.seekable(); fio.closed\n"
    "fio.close()\n",

    /* io.open() various modes */
    "f = io.open(_tmpfile, 'r'); f.read(); f.close()\n",
    "f = io.open(_tmpfile, 'rb'); f.read(); f.close()\n",
    "_p = os.path.join(_tmpdir, 'ioopen_w')\n"
    "f = io.open(_p, 'w'); f.write(_s); f.close()\n"
    "os.unlink(_p)\n",
    "_p = os.path.join(_tmpdir, 'ioopen_wb')\n"
    "f = io.open(_p, 'wb'); f.write(_d); f.close()\n"
    "os.unlink(_p)\n",

    /* IncrementalNewlineDecoder */
    "dec = io.IncrementalNewlineDecoder(None, True)\n"
    "dec.decode(_s[:len(_s)//2]); dec.decode(_s[len(_s)//2:], True)\n"
    "dec.getstate(); dec.reset()\n",
    "dec = io.IncrementalNewlineDecoder(None, False)\n"
    "dec.decode(_s)\n"
    "dec.setstate(dec.getstate())\n",

    /* BytesIO — readline processes bytes (covers _io_BytesIO_readline_impl) */
    "bio = io.BytesIO(_d)\n"
    "bio.readline(); bio.readline(); bio.readline()\n"
    "bio.close()\n",
    /* BytesIO — readlines processes bytes (covers _io_BytesIO_readlines_impl) */
    "bio = io.BytesIO(_d)\n"
    "bio.readlines()\n"
    "bio.close()\n",
    /* TextIOWrapper — readline processes bytes through decoder (covers textiowrapper_read_chunk) */
    "bio = io.BytesIO(_d)\n"
    "tw = io.TextIOWrapper(bio, encoding='utf-8', errors='replace')\n"
    "tw.readline(); tw.readline(); tw.readline()\n"
    "tw.close()\n",
    /* TextIOWrapper — readlines processes bytes */
    "bio = io.BytesIO(_d)\n"
    "tw = io.TextIOWrapper(bio, encoding='utf-8', errors='replace')\n"
    "tw.readlines()\n"
    "tw.close()\n",
    /* TextIOWrapper — read with size processes bytes chunk by chunk */
    "bio = io.BytesIO(_d)\n"
    "tw = io.TextIOWrapper(bio, encoding='utf-8', errors='replace')\n"
    "tw.read(16); tw.read(16); tw.read()\n"
    "tw.close()\n",
    /* TextIOWrapper — write processes string (covers textiowrapper_write_chunk) */
    "bio = io.BytesIO()\n"
    "tw = io.TextIOWrapper(bio, encoding='utf-8')\n"
    "tw.write(_s); tw.flush()\n"
    "tw.close()\n",
    /* BufferedReader — readline processes bytes (covers _io_BufferedReader_readline_impl) */
    "br = io.BufferedReader(io.BytesIO(_d))\n"
    "br.readline(); br.readline(); br.readline()\n"
    "br.close()\n",
    /* io.open reads fuzz bytes from file (covers _io_open_impl) */
    "_p = os.path.join(_tmpdir, 'io_rd')\n"
    "with open(_p, 'wb') as f: f.write(_d)\n"
    "f = io.open(_p, 'r', errors='replace'); f.read(); f.close()\n"
    "f = io.open(_p, 'rb'); f.read(); f.close()\n"
    "os.unlink(_p)\n",
    /* StringIO — write + readline processes string */
    "sio = io.StringIO()\n"
    "sio.write(_s); sio.seek(0)\n"
    "sio.readline(); sio.readline(); sio.readline()\n"
    "sio.close()\n",
    /* StringIO — readlines processes string */
    "sio = io.StringIO(_s)\n"
    "sio.readlines()\n"
    "sio.close()\n",
};

#define MAX_IOOPS_TEST_SIZE 0x10000

DEFINE_TEMPLATE_FUZZER(ioops, MAX_IOOPS_TEST_SIZE)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    assert(Py_IsInitialized());
    static int initialized = 0;
    if (!initialized) {
        if (!init_ioops()) { PyErr_Print(); abort(); }
        initialized = 1;
    }
    int rv = fuzz_ioops((const char *)data, size);
    if (PyErr_Occurred()) {
        PyErr_Print();
        abort();
    }
    return rv;
}
