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

__attribute__((section(".text.entry"))) int _start(void) {
    long fd = call3(5, (long)"/data/dualsense_native.stop", 0x601, 0644);
    if (fd < 0) return 1;
    call3(6, fd, 0, 0);
    notify("DualSense native Bluetooth: stop requested");
    return 0;
}
