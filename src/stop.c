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

__attribute__((section(".text.entry"))) int _start(void) {
    long fd = call3(5, (long)"/data/dualsense_native.stop", 0x601, 0644);

    if (fd < 0) return 1;
    call3(6, fd, 0, 0);

    return 0;
}
