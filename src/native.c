
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
static int patch_allowlist(void *thread, struct PatchArgs *args) {
    (void)thread;
    u32 low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(0xc0000082));
    u64 base = (((u64)high << 32) | low) - 0x1c0;
    if ((base >> 48) != 0xffff || (base & 0x3fff) || !args->request) return 22;
    const u32 offsets[10] = {0x5b0da6,0x5b0dd6,0x5b1616,0x5b1649,0x5b53d8,0x5b5fca,0x5b578d,0x5b5c6e,0x5b580b,0x5b5cfe};
    int restore = args->request->restore;
    if (restore != 0 && restore != 1) return 22;
    int (*lock)(void) = (void *)(base + 0x5a6b80);
    int (*unlock)(int) = (void *)(base + 0x5a6c00);
    if (*(u64 *)(base + 0x5b6d00) != 0x56415741e5894855UL) return 22;
    int rc = lock();
    if (rc) return rc;
    unsigned original_count = 0, patched_count = 0;
    for (unsigned i = 0; i < 10; ++i) {
        u32 old_value = (i & 1) ? 0x1000 : 0x044f;
        u32 new_value = (i & 1) ? 0x0ce6 : 0x054c;
        u32 current = *(volatile u32 *)(base + offsets[i]);
        if (current == old_value) ++original_count;
        else if (current == new_value) ++patched_count;
        else { unlock(0); return 0x100 + (int)i; }
    }
    if (original_count && patched_count) { unlock(0); return 0x200 + (int)original_count; }
    if ((!restore && patched_count == 10) || (restore && original_count == 10)) {
        unlock(0);
        return 0;
    }
    u64 flags, cr0;
    __asm__ volatile("pushfq; popq %0; cli; mov %%cr0,%1" : "=r"(flags), "=r"(cr0) :: "memory");
    u64 writable = cr0 & ~(1UL << 16);
    __asm__ volatile("mov %0,%%cr0" :: "r"(writable) : "memory");
    for (unsigned i = 0; i < 10; ++i) {
        u32 old_value = (i & 1) ? 0x1000 : 0x044f;
        u32 new_value = (i & 1) ? 0x0ce6 : 0x054c;
        *(volatile u32 *)(base + offsets[i]) = restore ? old_value : new_value;
    }
    __asm__ volatile("mov %0,%%cr0; pushq %1; popfq" :: "r"(cr0), "r"(flags) : "memory", "cc");
    unlock(0);
    return 0;
}

#include "dualsense.h"
typedef struct {
    u32 buttons;
    u8 lx, ly, rx, ry, l2, r2;
    u16 padding;
    float orientation[4], acceleration[3], angular_velocity[3];
    u8 touch[24];
    u8 connected, alignment[3];
    u64 timestamp;
    u8 extension[16], count, unknown[15];
} PadSample;
_Static_assert(sizeof(PadSample) == 120, "PadSample size");
struct VirtualPad {
    int handle;
    int initialized;
    int (*add)(void *, int);
    unsigned failures;
    u64 retry_at;
    int (*insert)(int, const void *);
    int (*remove)(int);
    int (*feedback)(int, void *);
};
static const char *find_text(const char *text, const char *needle) {
    for (; *text; ++text) {
        unsigned i = 0;
        while (needle[i] && text[i] == needle[i]) ++i;
        if (!needle[i]) return text;
    }
    return 0;
}
static int virtual_start(long log, struct VirtualPad *out, int (*sleep_us)(u32)) {
    int (*load)(const char *, u64, void *, u32, void *, int *) = 0;
    if (call3(591, 0x2001, (long)"sceKernelLoadStartModule", (long)&load) || !load) return -1;
    int module = 0;
    int (*add)(void *, int) = 0;
    if (!out->initialized) {
    int mbus = load("/system/common/lib/libSceMbus.sprx", 0, 0, 0, 0, 0);
    record(log, "load_mbus", mbus);
    module = load("/system/common/lib/libScePad.sprx", 0, 0, 0, 0, 0);
    record(log, "load_pad", module);
    if (module < 0) return -2;
    int (*init)(void) = 0, (*privilege)(int) = 0;
    if (call3(591, module, (long)"scePadInit", (long)&init) ||
        call3(591, module, (long)"scePadSetProcessPrivilege", (long)&privilege) ||
        call3(591, module, (long)"scePadVirtualDeviceAddDevice", (long)&add) ||
        call3(591, module, (long)"scePadVirtualDeviceInsertData", (long)&out->insert) ||
        call3(591, module, (long)"scePadVirtualDeviceDeleteDevice", (long)&out->remove)) return -3;
    if (!init || !privilege || !add || !out->insert || !out->remove) return -3;
    call3(591, module, (long)"scePadVirtualDeviceGetRemoteSetting", (long)&out->feedback);
    int rc = init();
    record(log, "pad_init", rc);
    if (rc) return -4;
    rc = privilege(1);
    record(log, "pad_privilege", rc);
    if (rc) return -5;
        out->add = add;
        out->initialized = 1;
    } else add = out->add;
    long fd = call3(5, (long)"/dev/klog", 4, 0);
    record(log, "open_klog", fd);
    if (fd < 0) return -6;
    char buffer[2048];
    for (unsigned i = 0; i < 256; ++i) {
        long count = call3(3, fd, (long)buffer, sizeof(buffer));
        if (count <= 0) break;
    }
    struct { int size, user, reserved[6]; } parameter = {32, 1, {0}};
    record(log, "add_virtual_pad", add(&parameter, 3));
    char line[1024];
    unsigned used = 0;
    for (unsigned tick = 0; tick < 500 && out->handle < 0; ++tick) {
        long count = call3(3, fd, (long)buffer, sizeof(buffer));
        for (long i = 0; i < count; ++i) {
            char c = buffer[i];
            if (c == '\n') {
                line[used] = 0;
                if (find_text(line, "SCE_MBUS_EVENT_DEVICE_ADDED") && find_text(line, "[subType:2]")) {
                    const char *id = find_text(line, "DeviceId:0x");
                    if (id) {
                        id += 11;
                        u64 value = 0;
                        unsigned digits = 0;
                        while (*id && digits < 16) {
                            unsigned digit;
                            if (*id >= '0' && *id <= '9') digit = (unsigned)(*id - '0');
                            else if (*id >= 'a' && *id <= 'f') digit = (unsigned)(*id - 'a' + 10);
                            else if (*id >= 'A' && *id <= 'F') digit = (unsigned)(*id - 'A' + 10);
                            else break;
                            value = value * 16 + digit;
                            ++id;
                            ++digits;
                        }
                        if (digits && value && (u32)value < 0x80000000u) out->handle = (int)value;
                    }
                }
                used = 0;
            } else if (used < sizeof(line) - 1) line[used++] = c;
            else used = 0;
        }
        if (out->handle < 0) sleep_us(10000);
    }
    call3(6, fd, 0, 0);
    record(log, "virtual_handle", out->handle);
    return out->handle < 0 ? -7 : 0;
}


static int resume_gap(u64 previous, u64 current, long previous_wall, long current_wall) {
    return current < previous || current - previous > 3000000 ||
        (previous_wall > 0 && current_wall > 0 &&
         (current_wall < previous_wall || current_wall - previous_wall > 3));
}

static long wall_seconds(void) {
    struct { long seconds, microseconds; } time = {0, 0};
    return call3(116, (long)&time, 0, 0) ? 0 : time.seconds;
}

static void virtual_reset(long log, struct VirtualPad *pad, u64 time) {
    if (pad->handle >= 0) record(log, "retire_virtual", pad->remove(pad->handle));
    pad->handle = -1;
    pad->failures = 0;
    pad->retry_at = time;
}

static void virtual_update(long log, struct VirtualPad *pad, const PadSample *sample, u64 time,
                           int (*sleep_us)(u32), u64 *inserted, u64 *failed) {
    if (pad->handle >= 0) {
        int rc = pad->insert(pad->handle, sample);
        if (!rc) {
            pad->failures = 0;
            ++*inserted;
            return;
        }
        ++*failed;
        if (!pad->failures) record(log, "insert_error", rc);
        if (++pad->failures < 3) return;
        virtual_reset(log, pad, time + 1000000);
    }
    if (time < pad->retry_at) return;
    pad->retry_at = time + 5000000;
    int rc = virtual_start(log, pad, sleep_us);
    record(log, "virtual_recovery", rc);
}

struct CapacityRequest { u64 address; u32 restore, original; };
struct CapacityArgs { void *function; struct CapacityRequest *request; };
static int controller_capacity(void *thread, struct CapacityArgs *args) {
    (void)thread;
    u32 low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(0xc0000082));
    u64 base = (((u64)high << 32) | low) - 0x1c0;
    if ((base >> 48) != 0xffff || (base & 0x3fff) || !args->request) return 22;
    struct CapacityRequest *r = args->request;
    if (!r->address || (r->address >> 48) || r->restore > 1) return 22;
    if (*(u64 *)(base + 0x5b6d00) != 0x56415741e5894855UL) return 22;
    int (*lock)(void) = (void *)(base + 0x5a6b80);
    int (*unlock)(int) = (void *)(base + 0x5a6c00);
    int (*copyout)(const void *, void *, u64) = (void *)(base + 0x36c6a0);
    int rc = lock();
    if (rc) return rc;
    u8 *context = *(void **)(base + 0x2612550);
    rc = 2;
    if (context && ((u64)context >> 48) == 0xffff) {
        for (u32 offset = 0x42a8; offset < 0x185a0; offset += 0x1588) {
            u8 *link = context + offset;
            if (*(u64 *)(link + 0x30) != r->address) continue;
            u8 *device = *(void **)(link + 0x638);
            if (!device || ((u64)device >> 48) != 0xffff || *(u16 *)(device + 0x28) != 0x54c || *(u16 *)(device + 0x2a) != 0xce6) break;
            u32 *capacity = (void *)(link + 0x1574);
            if (*capacity != 22 && *capacity != 49 && *capacity != 78) { rc = 22; break; }
            if (r->restore) {
                if (r->original != 22 && r->original != 49 && r->original != 78) { rc = 22; break; }
                *capacity = r->original;
                rc = 0;
            } else {
                u32 previous = *capacity;
                rc = copyout(&previous, &r->original, sizeof(previous));
                if (!rc) *capacity = 78;
            }
            break;
        }
    }
    unlock(0);
    return rc;
}

static long send_output(long fd, u64 address, u8 sequence, u8 large, u8 small, const u8 color[3], int reset) {
    u8 output[78];
    dualsense_output_bluetooth(output, sequence, large, small, color, reset);
    struct { u64 address; void *buffer; u64 size; u64 report_id; } request = {address, output, 78, 0x31};
    return call3(54, fd, 0x80206232UL, (long)&request);
}

static float root_positive(float value) {
    if (value <= 0) return 0;
    float result = value > 1 ? value : 1;
    for (unsigned i = 0; i < 12; ++i) result = (result + value / result) * 0.5f;
    return result;
}

static void extended_sample(PadSample *sample, const DualSenseState *state, const DualSenseCalibration *calibration, float dt) {
    for (unsigned i = 0; i < 24; ++i) sample->touch[i] = 0;
    unsigned contacts = 0;
    for (unsigned i = 0; i < 2; ++i) {
        if (!state->touch_active[i]) continue;
        u16 x = state->touch_x[i] < 1920 ? state->touch_x[i] : 1919;
        u16 y = state->touch_y[i] < 1080 ? (u16)((u32)state->touch_y[i] * 942 / 1080) : 941;
        u8 *point = sample->touch + 8 + 8 * contacts++;
        point[0] = (u8)x; point[1] = (u8)(x >> 8);
        point[2] = (u8)y; point[3] = (u8)(y >> 8);
        point[4] = state->touch_id[i];
    }
    sample->touch[0] = (u8)contacts;
    float omega[3];
    for (unsigned i = 0; i < 3; ++i) {
        sample->angular_velocity[i] = state->gyro[i] * calibration->gyro_scale[i];
        sample->acceleration[i] = (state->accel[i] - calibration->accel_bias[i]) * calibration->accel_scale[i];
        omega[i] = sample->angular_velocity[i];
    }
    if (dt <= 0 || dt > 0.1f) return;
    float x = sample->orientation[0], y = sample->orientation[1], z = sample->orientation[2], w = sample->orientation[3];
    float magnitude = root_positive(sample->acceleration[0]*sample->acceleration[0] + sample->acceleration[1]*sample->acceleration[1] + sample->acceleration[2]*sample->acceleration[2]);
    if (magnitude > 0.8f && magnitude < 1.2f) {
        float ax = sample->acceleration[0] / magnitude;
        float ay = sample->acceleration[1] / magnitude;
        float az = sample->acceleration[2] / magnitude;
        float gx = 2 * (x*y + w*z), gy = 1 - 2 * (x*x + z*z), gz = 2 * (y*z - w*x);
        omega[0] += 2 * (ay*gz - az*gy);
        omega[1] += 2 * (az*gx - ax*gz);
        omega[2] += 2 * (ax*gy - ay*gx);
    }
    float half = dt * 0.5f;
    sample->orientation[0] += (w*omega[0] + y*omega[2] - z*omega[1]) * half;
    sample->orientation[1] += (w*omega[1] + z*omega[0] - x*omega[2]) * half;
    sample->orientation[2] += (w*omega[2] + x*omega[1] - y*omega[0]) * half;
    sample->orientation[3] += (-x*omega[0] - y*omega[1] - z*omega[2]) * half;
    float norm = 0;
    for (unsigned i = 0; i < 4; ++i) norm += sample->orientation[i] * sample->orientation[i];
    norm = root_positive(norm);
    if (norm > 0.0001f) for (unsigned i = 0; i < 4; ++i) sample->orientation[i] /= norm;
}

static int native_run(void) {
    long log = call3(5, (long)"/data/dualsense_native.log", 0x209, 0644);
    if (log < 0) return 1;
    int (*version)(void *) = 0;
    int (*sleep_us)(u32) = 0;
    u64 (*now)(void) = 0;
    struct { u64 size; char text[28]; u32 version; } info = { .size = 40 };
    long rc = call3(591, 0x2001, (long)"sceKernelGetSystemSwVersion", (long)&version);
    record(log, "resolve_version", rc);
    if (rc || !version) { call3(6, log, 0, 0); return 2; }
    rc = version(&info);
    record(log, "get_version", rc);
    record(log, "firmware", info.version);
    if (rc || (info.version >> 16) != 0x1250) {
        call3(6, log, 0, 0);
        return 3;
    }
    rc = call3(591, 0x2001, (long)"sceKernelUsleep", (long)&sleep_us);
    if (rc || !sleep_us) { call3(6, log, 0, 0); return 4; }
    rc = call3(591, 0x2001, (long)"sceKernelGetProcessTime", (long)&now);
    if (rc || !now) { call3(6, log, 0, 0); return 4; }
    long fd = call3(5, (long)"/dev/bt", 2, 0);
    record(log, "open_hid", fd);
    if (fd < 0) { call3(6, log, 0, 0); return 5; }
    long queue = call3(362, 0, 0, 0);
    record(log, "kqueue", queue);
    if (queue < 0) { call3(6, fd, 0, 0); call3(6, log, 0, 0); return 6; }
    struct { u64 ident; short filter; u16 flags; u32 fflags; long data; void *udata; } change = {
        (u64)fd, -1, 1, 0, 0, 0
    }, event;
    rc = call6(363, queue, (long)&change, 1, 0, 0, 0);
    record(log, "watch_read", rc);
    if (rc) { call3(6, queue, 0, 0); call3(6, fd, 0, 0); call3(6, log, 0, 0); return 6; }
    u64 mask = 0x1ff000000UL;
    rc = call3(4, fd, (long)&mask, sizeof(mask));
    record(log, "subscribe", rc);
    if (rc != 8) { call3(6, queue, 0, 0); call3(6, fd, 0, 0); call3(6, log, 0, 0); return 7; }
    struct PatchRequest patch_request = {0};
    rc = call3(11, (long)patch_allowlist, (long)&patch_request, 0);
    record(log, "apply_temporary_allowlist", rc);
    if (rc) { call3(6, queue, 0, 0); call3(6, fd, 0, 0); call3(6, log, 0, 0); return 8; }
    struct { u16 vendor; u16 product; } device = { 0x054c, 0x0ce6 };
    rc = call3(54, fd, 0x8004622bUL, (long)&device);
    record(log, "register_dualsense", rc);
    int registered = rc == 0;
    if (!registered) {
        patch_request.restore = 1;
        record(log, "restore_allowlist", call3(11, (long)patch_allowlist, (long)&patch_request, 0));
        call3(6, queue, 0, 0);
        call3(6, fd, 0, 0);
        call3(6, log, 0, 0);
        return 8;
    }
    struct VirtualPad virtual_pad = {.handle = -1};
    int virtual_result = virtual_start(log, &virtual_pad, sleep_us);
    record(log, "virtual_start", virtual_result);
    if (virtual_result) {
        if (registered) call3(54, fd, 0x8004622cUL, (long)&device);
        patch_request.restore = 1;
        record(log, "restore_allowlist", call3(11, (long)patch_allowlist, (long)&patch_request, 0));
        call3(6, queue, 0, 0);
        call3(6, fd, 0, 0);
        call3(6, log, 0, 0);
        return 9;
    }
    PadSample sample = {0};
    sample.lx = sample.ly = sample.rx = sample.ry = 128;
    sample.orientation[3] = 1.0f;
    sample.connected = 1;
    u64 decoded = 0, inserted = 0, insert_failures = 0;
    u32 buttons_seen = 0;
    u64 last_input = now(), last_stop_check = 0, last_telemetry = 0;
    long data = call3(5, (long)"/data/dualsense_native_events.bin", 0x601, 0644);
    record(log, "open_events", data);
    u64 physical_address = 0, last_output = 0, last_motion = 0, rumble_test = 0, last_calibration_attempt = 0;
    u64 extended_count = 0, output_ok = 0, output_errors = 0, touch_count = 0, motion_count = 0, rumble_sent = 0;
    u8 maximum_large = 0, maximum_small = 0;
    u32 original_capacity = 0;
    u8 output_sequence = 0, previous_feedback[5] = {255,255,255,255,255};
    int initialized_output = 0, calibration_requested = 0, calibration_valid = 0;
    int controller_connected = 0;
    DualSenseCalibration calibration;
    for (unsigned i = 0; i < 3; ++i) {
        calibration.gyro_scale[i] = 2000.0f / 32768.0f * 0.01745329252f;
        calibration.accel_scale[i] = 1.0f / 8192.0f;
        calibration.accel_bias[i] = 0;
    }
    u64 events = 0;
    u64 reports = 0;
    long last_read_error = 0;
    u64 last_iteration = now();
    long last_wall = wall_seconds();
    record(log, "wall_clock", last_wall);
    for (;;) {
        u64 current_time = now();
        long current_wall = wall_seconds();
        if (resume_gap(last_iteration, current_time, last_wall, current_wall)) {
            record(log, "resume_gap", current_time - last_iteration);
            record(log, "resume_wall_gap", current_wall - last_wall);
            break;
        }
        last_iteration = current_time;
        last_wall = current_wall;
        if (controller_connected && current_time - last_input > 3000000) {
            controller_connected = 0;
            notify("DualSense disconnected");
        }
        if (current_time - last_stop_check >= 500000) {
            last_stop_check = current_time;
            long stop = call3(5, (long)"/data/dualsense_native.stop", 0, 0);
            if (stop >= 0) { call3(6, stop, 0, 0); break; }
        }
        if (current_time - last_telemetry >= 10000000) {
            last_telemetry = current_time;
            record(log, "factory_calibrated", calibration_valid);
            record(log, "extended_reports", extended_count);
            record(log, "rumble_sent", rumble_sent);
            record(log, "maximum_large", maximum_large);
            record(log, "maximum_small", maximum_small);
            record(log, "output_ok", output_ok);
            record(log, "output_errors", output_errors);
            record(log, "touch_reports", touch_count);
            record(log, "motion_reports", motion_count);
            record(log, "live_decoded", decoded);
            record(log, "live_inserted", inserted);
            record(log, "live_insert_failures", insert_failures);
            record(log, "live_buttons_seen", buttons_seen);
        }
        if (physical_address && initialized_output && !calibration_requested && current_time - last_calibration_attempt > 1000000) {
            last_calibration_attempt = current_time;
            struct { u64 address; u8 report_id; u8 reserved[7]; } feature = {physical_address, 5, {0}};
            long rc = call3(54, fd, 0x8010622fUL, (long)&feature);
            record(log, "request_calibration", rc);
            if (!rc) calibration_requested = 1;
        }
        if (physical_address && current_time - last_output >= 20000) {
            u8 feedback[256] = {0};
            if (virtual_pad.handle >= 0 && virtual_pad.feedback) virtual_pad.feedback(virtual_pad.handle, feedback);
            u8 values[5] = {feedback[3], feedback[4], feedback[5], feedback[6], feedback[7]};
            if (current_time - last_input >= 500000) values[0] = values[1] = 0;
            if (values[0] > maximum_large) maximum_large = values[0];
            if (values[1] > maximum_small) maximum_small = values[1];
            long test = call3(5, (long)"/data/dualsense_native.rumble_test", 0, 0);
            if (test >= 0) {
                call3(6, test, 0, 0);
                call3(10, (long)"/data/dualsense_native.rumble_test", 0, 0);
                rumble_test = current_time;
            }
            if (rumble_test && current_time - rumble_test < 800000) {
                values[0] = current_time - rumble_test < 400000 ? 110 : 0;
                values[1] = current_time - rumble_test >= 400000 ? 110 : 0;
            }
            int changed = !initialized_output;
            for (unsigned i = 0; i < 5; ++i) if (values[i] != previous_feedback[i]) changed = 1;
            if (changed || current_time - last_output >= 1000000) {
                struct CapacityRequest capacity = {physical_address, 0, 0};
                long cap_rc = call3(11, (long)controller_capacity, (long)&capacity, 0);
                if (!cap_rc) {
                    if (capacity.original != 78 || !original_capacity) original_capacity = capacity.original;
                    u8 color[3];
                    for (unsigned i = 0; i < 3; ++i) color[i] = values[2+i] > 63 ? 255 : values[2+i] * 4;
                    long rc = send_output(fd, physical_address, output_sequence++, values[0], values[1], color, !initialized_output);
                    if (!rc) {
                        ++output_ok;
                        if (initialized_output && (values[0] || values[1])) ++rumble_sent;
                        if (initialized_output) for (unsigned i = 0; i < 5; ++i) previous_feedback[i] = values[i];
                        initialized_output = 1;
                    } else if ((u32)rc != 0x802f3707u && ++output_errors == 1) record(log, "first_output_error", rc);
                } else if (++output_errors == 1) record(log, "capacity_error", cap_rc);
                last_output = current_time;
            }
        }
        struct { long seconds; long nanoseconds; } timeout = {0, 0};
        long ready = call6(363, queue, 0, 0, (long)&event, 1, (long)&timeout);
        if (ready < 0) { record(log, "wait_error", ready); break; }
        if (current_time - last_input > 500000) {
            sample.buttons = 0;
            sample.lx = sample.ly = sample.rx = sample.ry = 128;
            sample.l2 = sample.r2 = 0;
            for (unsigned i = 0; i < 24; ++i) sample.touch[i] = 0;
            for (unsigned i = 0; i < 3; ++i) sample.angular_velocity[i] = 0;
        }
        sample.timestamp = current_time;
        ++sample.count;
        virtual_update(log, &virtual_pad, &sample, current_time, sleep_us, &inserted, &insert_failures);
        if (!ready) { sleep_us(10000); continue; }
        u8 buffer[256];
        long count = call3(3, fd, (long)buffer, sizeof(buffer));
        if (count > 0 && count <= (long)sizeof(buffer)) {
            if (data >= 0 && events < 4096) {
                u32 size = (u32)count;
                call3(4, data, (long)&size, sizeof(size));
                call3(4, data, (long)buffer, count);
            }
            events += (u64)count / 16;
            for (long pos = 0; pos + 16 <= count; pos += 16) {
                if (buffer[pos] == 0x18 || buffer[pos] == 0x19) { initialized_output = 0; calibration_requested = 0; }
                if (buffer[pos] < 0x18 || buffer[pos] > 0x20) continue;
                u64 address = 0;
                for (unsigned i = 0; i < 8; ++i) address |= (u64)buffer[pos + 8 + i] << (8 * i);
                u8 report[80];
                for (unsigned i = 0; i < sizeof(report); ++i) report[i] = 0;
                struct { u64 address; void *buffer; u64 capacity; u64 reserved; } request = {
                    address, report, sizeof(report), 0
                };
                long result = call3(54, fd, 0x80206233UL, (long)&request);
                if (result == 43 && report[0] == 41 && report[2] == 5) {
                    int rc = dualsense_calibration_bluetooth(report + 2, 41, &calibration);
                    record(log, "calibration_result", rc);
                    if (!rc) calibration_valid = 1;
                }
                if (result >= 2 && result <= 80 && report[0] + 2 == result && report[1] == 0x1f) {
                    DualSenseState state;
                    if (!dualsense_decode_bluetooth(report + 2, (unsigned long)result - 2, &state)) {
                        u64 input_time = now();
                        if (!controller_connected) {
                            controller_connected = 1;
                            notify("DualSense connected");
                        }
                        if (decoded && input_time - last_input > 3000000) {
                            record(log, "bluetooth_resume_gap", input_time - last_input);
                            virtual_reset(log, &virtual_pad, input_time);
                            initialized_output = 0;
                            calibration_requested = 0;
                            last_motion = 0;
                        }
                        physical_address = address;
                        if (state.extended) {
                            ++extended_count;
                            if (state.touch_active[0] || state.touch_active[1]) ++touch_count;
                            if (state.gyro[0] || state.gyro[1] || state.gyro[2]) ++motion_count;
                            u64 motion_time = now();
                            extended_sample(&sample, &state, &calibration, last_motion ? (motion_time - last_motion) / 1000000.0f : 0);
                            last_motion = motion_time;
                        }
                        sample.buttons = state.buttons;
                        sample.lx = state.left_x;
                        sample.ly = state.left_y;
                        sample.rx = state.right_x;
                        sample.ry = state.right_y;
                        sample.l2 = state.l2;
                        sample.r2 = state.r2;
                        buttons_seen |= state.buttons;
                        last_input = now();
                        ++decoded;
                    }
                }
                if (result > 0 && result <= 80 && reports < 1024 && data >= 0) {
                    u32 size = 0x80000000u | (u32)result;
                    call3(4, data, (long)&size, sizeof(size));
                    call3(4, data, (long)report, result);
                    ++reports;
                }
            }
        } else if (count < 0 && count != -35) {
            if (count != last_read_error) record(log, "read_error", count);
            last_read_error = count;
            break;
        }
        sleep_us(10000);
    }
    record(log, "decoded", decoded);
    record(log, "inserted", inserted);
    record(log, "insert_failures", insert_failures);
    record(log, "buttons_seen", buttons_seen);
    if (physical_address) {
        u8 black[3] = {0};
        record(log, "stop_motors", send_output(fd, physical_address, output_sequence++, 0, 0, black, 0));
        if (original_capacity) {
            struct CapacityRequest capacity = {physical_address, 1, original_capacity};
            record(log, "restore_capacity", call3(11, (long)controller_capacity, (long)&capacity, 0));
        }
    }
    if (virtual_pad.handle >= 0) record(log, "delete_virtual", virtual_pad.remove(virtual_pad.handle));
    record(log, "events", events);
    record(log, "reports_saved", reports);
    if (registered) record(log, "unregister_dualsense", call3(54, fd, 0x8004622cUL, (long)&device));
    patch_request.restore = 1;
    record(log, "restore_allowlist", call3(11, (long)patch_allowlist, (long)&patch_request, 0));
    if (data >= 0) call3(6, data, 0, 0);
    call3(6, queue, 0, 0);
    call3(6, fd, 0, 0);
    record(log, "complete", 1);
    call3(6, log, 0, 0);
    return 0;
}

__attribute__((used)) static void *native_worker(void *guard) {
    int (*sleep_us)(u32) = 0;
    call3(591, 0x2001, (long)"sceKernelUsleep", (long)&sleep_us);
    int rc;
    for (;;) {
        rc = native_run();
        long stop = call3(5, (long)"/data/dualsense_native.stop", 0, 0);
        if (stop >= 0) { call3(6, stop, 0, 0); break; }
        if (!sleep_us || rc == 2 || rc == 3 || rc == 4 || rc == 8) break;
        sleep_us(3000000);
    }
    call3(6, (long)guard, 0, 0);
    return (void *)(long)rc;
}

__attribute__((section(".text.entry"))) int _start(void) {
    long guard = call3(97, 2, 2, 0);
    if (guard < 0) return 1;
    struct { u8 length, family; u16 port; u32 address; u8 padding[8]; } address = {
        16, 2, (37947 >> 8) | ((37947 & 255) << 8), 0x0100007f, {0}
    };
    if (call3(104, guard, (long)&address, sizeof(address)) < 0) {
        call3(6, guard, 0, 0);
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
    call3(10, (long)"/data/dualsense_native.stop", 0, 0);
    void *thread = 0;
    void *(*worker)(void *) = (void *)(copy + (entry - source));
    int rc = create(&thread, 0, worker, (void *)guard, "DualSense native Bluetooth");
    if (rc) { unmap(copy, allocation); call3(6, guard, 0, 0); return rc; }
    detach(thread);
    return 0;
}
