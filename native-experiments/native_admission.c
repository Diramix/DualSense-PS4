typedef __SIZE_TYPE__ NativeSize;
void *memset(void *pointer, int value, NativeSize length) {
    unsigned char *bytes = pointer;
    for (NativeSize i = 0; i < length; ++i) bytes[i] = (unsigned char)value;
    return pointer;
}
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

struct PatchRequest { int restore; };
struct PatchArgs { void *function; struct PatchRequest *request; };
static int admission(void *thread, struct PatchArgs *args) {
    (void)thread;
    u32 low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(0xc0000082));
    u64 base = (((u64)high << 32) | low) - 0x1c0;
    if ((base >> 48) != 0xffff || (base & 0x3fff) || !args->request) return 22;
    int restore = args->request->restore;
    if (restore != 0 && restore != 1) return 22;
    if (*(u64 *)(base + 0x5b6d00) != 0x56415741e5894855UL) return 22;
    const u32 offsets[2] = {0x5b66f9, 0x5ee8bf};
    int (*bt_lock)(void) = (void *)(base + 0x5a6b80);
    int (*bt_unlock)(int) = (void *)(base + 0x5a6c00);
    int (*hid_lock)(void) = (void *)(base + 0x5dac00);
    void (*hid_unlock)(void) = (void *)(base + 0x5dac60);
    u32 from = restore ? 0xce6 : 0x42f;
    u32 to = restore ? 0x42f : 0xce6;
    for (unsigned i = 0; i < 2; ++i) {
        if (*(volatile u32 *)(base + offsets[i]) != from) return 0x100 + (int)i;
    }
    for (unsigned i = 0; i < 2; ++i) {
        int rc = i ? hid_lock() : bt_lock();
        if (rc) return rc;
        u64 flags, cr0;
        __asm__ volatile("pushfq; popq %0; cli; mov %%cr0,%1" : "=r"(flags), "=r"(cr0) :: "memory");
        u64 writable = cr0 & ~(1UL << 16);
        __asm__ volatile("mov %0,%%cr0" :: "r"(writable) : "memory");
        *(volatile u32 *)(base + offsets[i]) = to;
        __asm__ volatile("mov %0,%%cr0; pushq %1; popfq" :: "r"(cr0), "r"(flags) : "memory", "cc");
        if (i) hid_unlock(); else bt_unlock(0);
    }
    return 0;
}
static int native_run(void) {
    long fd = call3(5, (long)"/data/dualsense_admission.log", 0x601, 0600);
    if (fd < 0) return 1;
    int (*sleep_us)(u32) = 0;
    int (*version)(void *) = 0;
    struct { u64 size; char text[28]; u32 version; } info = { .size = 40 };
    if (call3(591,0x2001,(long)"sceKernelGetSystemSwVersion",(long)&version) || !version || version(&info) || info.version != 0x12508001) {call3(6,fd,0,0); return 2;}
    if (call3(591,0x2001,(long)"sceKernelUsleep",(long)&sleep_us) || !sleep_us) {call3(6,fd,0,0); return 3;}
    struct PatchRequest request = {0};
    long rc = call3(11,(long)admission,(long)&request,0);
    record(fd,"admission_apply",rc);
    if (rc) {call3(6,fd,0,0); return 4;}
    notify("DualSense native registration test: reconnect controller now 180 seconds");
    for (unsigned i = 0; i < 1800; ++i) sleep_us(100000);
    request.restore = 1;
    rc = call3(11,(long)admission,(long)&request,0);
    record(fd,"admission_restore",rc);
    notify(rc ? "DualSense native registration: restore failed" : "DualSense native registration test finished; admission restored");
    call3(6,fd,0,0);
    return rc != 0;
}
__attribute__((used)) static void *native_worker(void *guard) {
    int rc = native_run();
    call3(6, (long)guard, 0, 0);
    return (void *)(long)rc;
}

__attribute__((section(".text.entry"))) int _start(void) {
    long guard = call3(97, 2, 2, 0);
    if (guard < 0) return 1;
    struct { u8 length, family; u16 port; u32 address; u8 padding[8]; } address = {
        16, 2, (37948 >> 8) | ((37948 & 255) << 8), 0x0100007f, {0}
    };
    if (call3(104, guard, (long)&address, sizeof(address)) < 0) {
        call3(6, guard, 0, 0);
        notify("DualSense admission test is already running, or its local port is unavailable");
        return 2;
    }
    void *(*map)(void *, u64, int, int, int, u64) = 0;
    int (*unmap)(void *, u64) = 0;
    int (*create)(void **, void *, void *(*)(void *), void *, const char *) = 0;
    int (*detach)(void *) = 0;
    if (call3(591, 0x2001, (long)"mmap", (long)&map) ||
        call3(591, 0x2001, (long)"munmap", (long)&unmap) ||
        call3(591, 0x2001, (long)"scePthreadCreate", (long)&create) ||
        call3(591, 0x2001, (long)"scePthreadDetach", (long)&detach) ||
        !map || !unmap || !create || !detach) {
        call3(6, guard, 0, 0);
        return 3;
    }
    const u8 *source, *end, *entry;
    __asm__ volatile("lea __image_start(%%rip),%0; lea __image_end(%%rip),%1; lea native_worker(%%rip),%2"
        : "=r"(source), "=r"(end), "=r"(entry));
    u64 size = (u64)(end - source);
    if (!size || size > 1024 * 1024) { call3(6, guard, 0, 0); return 4; }
    u64 allocation = (size + 0x3fff) & ~0x3fffUL;
    u8 *copy = map(0, allocation, 7, 0x1002, -1, 0);
    if (!copy || copy == (void *)-1) { call3(6, guard, 0, 0); return 5; }
    for (u64 i = 0; i < size; ++i) copy[i] = source[i];
    void *thread = 0;
    void *(*worker)(void *) = (void *)(copy + (entry - source));
    int rc = create(&thread, 0, worker, (void *)guard, "DualSense admission test");
    if (rc) { unmap(copy, allocation); call3(6, guard, 0, 0); return rc; }
    detach(thread);
    return 0;
}
