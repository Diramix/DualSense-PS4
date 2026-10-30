import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'src/native.c').read_text()
structure = source[source.index('struct VirtualPad {'):source.index('static const char *find_text')]
gap = source[source.index('static int resume_gap('):source.index('static long wall_seconds(')]
function = source[source.index('static void virtual_reset('):source.index('struct CapacityRequest')]
harness = r'''
#include <assert.h>
typedef unsigned long u64;
typedef unsigned int u32;
typedef struct { int value; } PadSample;
STRUCTURE
static int result, removed, starts, start_result, notices;
static int insert(int handle, const void *sample) { assert(handle == 42); assert(sample); return result; }
static int remove_pad(int handle) { assert(handle == 42); ++removed; return 0; }
static void record(long fd, const char *key, long value) { (void)fd; (void)key; (void)value; }
static void notify(const char *text) { assert(text); ++notices; }
static int virtual_start(long fd, struct VirtualPad *pad, int (*sleep_us)(u32)) {
    (void)fd; (void)sleep_us; ++starts;
    if (!start_result) pad->handle = 42;
    return start_result;
}
GAP
FUNCTION
int main(void) {
    assert(!resume_gap(1000, 11000, 100, 100));
    assert(resume_gap(1000, 11000, 100, 160));
    assert(resume_gap(1000, 4001001, 100, 100));
    assert(resume_gap(11000, 1000, 100, 100));
    assert(!resume_gap(1000, 11000, 0, 0));
    struct VirtualPad pad = {.handle=42, .insert=insert, .remove=remove_pad};
    PadSample sample = {0};
    u64 ok=0, failed=0;
    virtual_update(0,&pad,&sample,0,0,&ok,&failed);
    assert(ok==1 && !failed && !starts);
    result=-1;
    virtual_update(0,&pad,&sample,100,0,&ok,&failed);
    result=0;
    virtual_update(0,&pad,&sample,200,0,&ok,&failed);
    assert(!pad.failures && !removed);
    result=-1;
    for (u64 t=300;t<=500;t+=100) virtual_update(0,&pad,&sample,t,0,&ok,&failed);
    assert(removed==1 && pad.handle==-1 && !starts);
    virtual_update(0,&pad,&sample,1000499,0,&ok,&failed);
    assert(!starts);
    start_result=-1;
    virtual_update(0,&pad,&sample,1000500,0,&ok,&failed);
    assert(starts==1 && pad.handle==-1 && !notices);
    virtual_update(0,&pad,&sample,6000499,0,&ok,&failed);
    assert(starts==1);
    start_result=0;
    virtual_update(0,&pad,&sample,6000500,0,&ok,&failed);
    assert(starts==2 && pad.handle==42 && notices==1);
    result=0;
    virtual_update(0,&pad,&sample,6000600,0,&ok,&failed);
    assert(ok==3 && failed==4 && !pad.failures);
    virtual_reset(0,&pad,7000000);
    assert(pad.handle==-1 && removed==2);
    virtual_update(0,&pad,&sample,7000000,0,&ok,&failed);
    assert(pad.handle==42 && starts==3 && notices==2);
}
'''.replace('STRUCTURE', structure).replace('FUNCTION', function).replace('GAP', gap)
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory)
    (path / 'test.c').write_text(harness)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(path/'test.c'),'-o',str(path/'test')],check=True)
    subprocess.run([str(path/'test')],check=True)
print('Recovery checks passed: transient failure, lost handle, retry delay, failed recreation, successful recovery')
