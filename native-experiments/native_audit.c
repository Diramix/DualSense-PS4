typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

__attribute__((noinline)) static long call3(long number, long a, long b, long c) {
    long result;
    __asm__ volatile("syscall; jnc 1f; neg %%rax; 1:"
        : "=a"(result), "+D"(a), "+S"(b), "+d"(c)
        : "a"(number) : "rcx", "r8", "r9", "r10", "r11", "cc", "memory");
    return result;
}

__attribute__((noinline)) static long call6(long number, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long result;
    __asm__ volatile("syscall; jnc 1f; neg %%rax; 1:"
        : "=a"(result), "+D"(a), "+S"(b), "+d"(c), "+r"(r10), "+r"(r8), "+r"(r9)
        : "a"(number) : "rcx", "r11", "cc", "memory");
    return result;
}

static u64 length(const char *text) {
    u64 count = 0;
    while (text[count]) ++count;
    return count;
}

static void record(long fd, const char *name, long value) {
    char line[96];
    u64 count = 0;
    while (*name && count < 60) line[count++] = *name++;
    line[count++] = '=';
    line[count++] = '0';
    line[count++] = 'x';
    for (int shift = 60; shift >= 0; shift -= 4)
        line[count++] = "0123456789abcdef"[((u64)value >> shift) & 15];
    line[count++] = '\n';
    call3(4, fd, (long)line, count);
}

static void notify(const char *message) {
    int (*send)(int, void *, u64, int) = 0;
    if (call3(591, 0x2001, (long)"sceKernelSendNotificationRequest", (long)&send) || !send)
        return;
    u8 request[0xc30];
    for (u64 i = 0; i < sizeof(request); ++i) request[i] = 0;
    *(int *)(request + 0x10) = -1;
    u64 count = length(message);
    if (count > 1023) count = 1023;
    for (u64 i = 0; i < count; ++i) request[0x2d + i] = message[i];
    send(0, request, sizeof(request), 0);
}

struct ReadRequest { u64 offset; void *destination; u64 size; };
struct KernelArgs { void *function; struct ReadRequest *request; };
static int read_kernel(void *thread, struct KernelArgs *args) {
    (void)thread;
    u32 low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(0xc0000082));
    u64 base = (((u64)high << 32) | low) - 0x1c0;
    if ((base >> 48) != 0xffff || (base & 0x3fff)) return 22;
    struct ReadRequest *request = args->request;
    if (!request || request->size != 0x8000) return 22;
    if (*(u64 *)(base + 0x5b6d00) != 0x56415741e5894855UL) return 22;
    int (*copy)(const void *, void *, u64) = (void *)(base + 0x36c6a0);
    if (request->offset >= 48) return 22;
    u8 *out = request->destination;
    int (*lock)(void) = (void *)(base + 0x5dac00);
    void (*unlock)(void) = (void *)(base + 0x5dac60);
    lock();
    unsigned index = request->offset;
    u64 table = index < 32 ? 0x2643d50 : 0x2646f90;
    unsigned slot = index < 32 ? index : index - 32;
    u8 *context = *(void **)(base + table + slot * 8);
    int rc = 0;
    if (context && ((u64)context >> 48) == 0xffff) {
        rc = copy(context, out, 0x140);
        u8 *source = *(void **)(context + 0x10);
        u8 *state = *(void **)(context + 0x130);
        if (!rc && source && ((u64)source >> 48) == 0xffff)
            rc = copy(source, out + 0x400, 0x380);
        if (!rc && state && ((u64)state >> 48) == 0xffff) {
            u64 size = *(u32 *)context == 3 ? 0x320 : 0x140;
            rc = copy(state, out + 0x1000, size);
            if (!rc && *(u32 *)context == 3)
                rc = copy(state + 0x5e80, out + 0x1400, 0x268);
        }
    }
    if (!rc) rc = copy((void *)(base + 0x5b66f9), out + 0x1ff0, 4);
    if (!rc) rc = copy((void *)(base + 0x5ee8bf), out + 0x1ff4, 4);
    unlock();
    if (rc) return rc;
    return 0;
}
__attribute__((section(".text.entry"))) int _start(void) {
    long log = call3(5, (long)"/data/dualsense_native_audit.log", 0x601, 0600);
    if (log < 0) return 1;
    int (*version)(void *) = 0;
    struct { u64 size; char text[28]; u32 version; } info = { .size = 40 };
    long rc = call3(591, 0x2001, (long)"sceKernelGetSystemSwVersion", (long)&version);
    if (rc || !version || version(&info) || (info.version >> 16) != 0x1250) { call3(6, log, 0, 0); return 2; }
    long output = call3(5, (long)"/data/dualsense_native_audit.bin", 0x601, 0600);
    record(log, "output", output);
    if (output < 0) { call3(6, log, 0, 0); return 3; }
    u8 buffer[0x8000];
    u64 good = 0;
    for (u64 offset = 0; offset < 48; ++offset) {
        for (u64 i = 0; i < sizeof(buffer); ++i) buffer[i] = 0;
        struct ReadRequest request = {offset, buffer, sizeof(buffer)};
        rc = call3(11, (long)read_kernel, (long)&request, 0);
        if (offset == 0) { record(log, "first_read", rc); if (rc) break; }
        if (rc) record(log, "unreadable_page", offset);
        else ++good;
        long count = call3(4, output, (long)buffer, sizeof(buffer));
        if (count != sizeof(buffer)) { record(log, "write_error", count); break; }
    }
    record(log, "pages_read", good);
    call3(6, output, 0, 0);
    call3(6, log, 0, 0);
    notify("DualSense native audit finished; current controls unchanged");
    return 0;
}
