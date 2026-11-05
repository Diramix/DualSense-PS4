import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'src/native.c').read_text()
scanner = source[source.index('struct PatchRequest {'):source.index('static int patch_allowlist(')]
harness = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned char u8;
SCANNER
static void put(u8 *memory, u32 offset, u32 value) {
    memory[offset - 1] = 0x3d;
    memcpy(memory + offset, &value, sizeof(value));
}
int main(void) {
    u8 *memory = calloc(1, AOB_SAFE_SCAN_END);
    assert(memory);
    u32 vids[] = {0x59bff9, 0x5b0da6, 0x5b1616, 0x5b53d8, 0x5b578d, 0x5b580b};
    u32 pids[] = {0x59c050, 0x5a36e6, 0x5ac909, 0x5b0dd6, 0x5b1649, 0x5b2c1a, 0x5b5c6e, 0x5b5cfe, 0x5b5fca};
    for (unsigned i = 0; i < 6; ++i) put(memory, vids[i], 0x44f);
    for (unsigned i = 0; i < 9; ++i) put(memory, pids[i], 0x1000);
    struct PatchRequest request = {0};
    u32 offsets[12], count = 0, lock = 0, unlock = 0;
    assert(!aob_find_allowlist_offsets((u64)memory, offsets, &count, &lock, &unlock, &request));
    assert(count == 6 && request.n_vid_found == 6 && request.n_pid_found == 9);
    for (unsigned i = 0; i < count; ++i) assert(offsets[2 * i] == vids[i]);
    for (unsigned i = 0; i < 9; ++i) {
        int expected = i == 0 || i == 3 || i == 4 || i >= 6;
        int found = 0;
        for (unsigned j = 0; j < count; ++j) found |= offsets[2 * j + 1] == pids[i];
        assert(found == expected);
    }
    free(memory);
    return 0;
}
'''.replace('SCANNER', scanner)
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory)
    (path / 'test.c').write_text(harness)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
print('Allowlist scanner accepts the six VID and nine PID candidates observed on firmware 12.50')
