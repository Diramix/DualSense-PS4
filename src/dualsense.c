#include "dualsense.h"

static uint32_t crc_byte(uint32_t crc, uint8_t value) {
    crc ^= value;
    for (unsigned i = 0; i < 8; ++i)
        crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    return crc;
}

int dualsense_decode_bluetooth(const uint8_t *report, size_t length, DualSenseState *state) {
    static const uint32_t directions[9] = {0x10, 0x30, 0x20, 0x60, 0x40, 0xc0, 0x80, 0x90, 0};
    if (!report || !state)
        return -1;
    uint8_t simple[10] = {0};
    const uint8_t *data;
    if (length == 10 && report[0] == 0x01) {
        for (unsigned i = 0; i < 4; ++i) simple[i] = report[i + 1];
        simple[4] = report[8];
        simple[5] = report[9];
        simple[7] = report[5];
        simple[8] = report[6];
        simple[9] = report[7] & 3;
        data = simple;
    } else if (length == 78 && report[0] == 0x31) {
        uint32_t crc = crc_byte(0xffffffffu, 0xa1);
        for (size_t i = 0; i < 74; ++i)
            crc = crc_byte(crc, report[i]);
        uint32_t expected = (uint32_t)report[74] | ((uint32_t)report[75] << 8) |
                            ((uint32_t)report[76] << 16) | ((uint32_t)report[77] << 24);
        if (~crc != expected)
            return -2;
        data = report + 2;
    } else {
        return -1;
    }
    unsigned direction = data[7] & 15;
    if (direction > 8)
        return -3;
    DualSenseState result = {0};
    result.left_x = data[0];
    result.left_y = data[1];
    result.right_x = data[2];
    result.right_y = data[3];
    result.l2 = data[4];
    result.r2 = data[5];
    result.buttons = directions[direction];
    if (data[7] & 0x10) result.buttons |= 0x8000;
    if (data[7] & 0x20) result.buttons |= 0x4000;
    if (data[7] & 0x40) result.buttons |= 0x2000;
    if (data[7] & 0x80) result.buttons |= 0x1000;
    if (data[8] & 0x01) result.buttons |= 0x0400;
    if (data[8] & 0x02) result.buttons |= 0x0800;
    if (data[8] & 0x04) result.buttons |= 0x0100;
    if (data[8] & 0x08) result.buttons |= 0x0200;
    if (data[8] & 0x10) result.buttons |= 0x0001;
    if (data[8] & 0x20) result.buttons |= 0x0008;
    if (data[8] & 0x40) result.buttons |= 0x0002;
    if (data[8] & 0x80) result.buttons |= 0x0004;
    if (data[9] & 0x01) result.buttons |= 0x10000;
    if (data[9] & 0x02) result.buttons |= 0x100000;
    result.mute = (data[9] >> 2) & 1;
    if (length == 78) {
        result.extended = 1;
        result.battery = data[52] & 15;
        for (unsigned i = 0; i < 3; ++i) {
            result.gyro[i] = (int16_t)((uint16_t)data[15 + i * 2] | ((uint16_t)data[16 + i * 2] << 8));
            result.accel[i] = (int16_t)((uint16_t)data[21 + i * 2] | ((uint16_t)data[22 + i * 2] << 8));
        }
        for (unsigned i = 0; i < 2; ++i) {
            const uint8_t *point = data + 32 + i * 4;
            result.touch_id[i] = point[0] & 127;
            result.touch_active[i] = !(point[0] & 128);
            result.touch_x[i] = (uint16_t)point[1] | ((uint16_t)(point[2] & 15) << 8);
            result.touch_y[i] = (uint16_t)(point[2] >> 4) | ((uint16_t)point[3] << 4);
        }
    }
    *state = result;
    return 0;
}

void dualsense_output_bluetooth(uint8_t report[78], uint8_t sequence, uint8_t large, uint8_t small, const uint8_t color[3], int reset_leds) {
    for (unsigned i = 0; i < 78; ++i) report[i] = 0;
    report[0] = 0x31;
    report[1] = (sequence & 15) << 4;
    report[2] = 0x10;
    if (reset_leds) {
        report[41] = 2;
        report[44] = 2;
    } else {
        report[3] = 3;
        report[4] = 0x14;
        report[5] = small;
        report[6] = large;
        report[46] = 4;
        for (unsigned i = 0; i < 3; ++i) report[47 + i] = color[i];
    }
    uint32_t crc = crc_byte(0xffffffffu, 0xa2);
    for (unsigned i = 0; i < 74; ++i) crc = crc_byte(crc, report[i]);
    crc = ~crc;
    for (unsigned i = 0; i < 4; ++i) report[74 + i] = (uint8_t)(crc >> (8 * i));
}

static int read_signed(const uint8_t *data) {
    return (int16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

int dualsense_calibration_bluetooth(const uint8_t *report, size_t length, DualSenseCalibration *calibration) {
    if (!report || !calibration || length != 41 || report[0] != 5) return -1;
    uint32_t crc = crc_byte(0xffffffffu, 0xa3);
    for (unsigned i = 0; i < 37; ++i) crc = crc_byte(crc, report[i]);
    uint32_t expected = 0;
    for (unsigned i = 0; i < 4; ++i) expected |= (uint32_t)report[37 + i] << (8 * i);
    if (~crc != expected) return -2;
    int speed = read_signed(report + 19) + read_signed(report + 21);
    if (speed <= 0 || speed > 10000) return -3;
    DualSenseCalibration result;
    for (unsigned i = 0; i < 3; ++i) {
        int bias = read_signed(report + 1 + i * 2);
        int plus = read_signed(report + 7 + i * 4) - bias;
        int minus = read_signed(report + 9 + i * 4) - bias;
        int denominator = (plus < 0 ? -plus : plus) + (minus < 0 ? -minus : minus);
        int accel_plus = read_signed(report + 23 + i * 4);
        int accel_minus = read_signed(report + 25 + i * 4);
        int range = accel_plus - accel_minus;
        if (!denominator || range <= 0) return -3;
        result.gyro_scale[i] = speed * 0.01745329252f / denominator;
        result.accel_scale[i] = 2.0f / range;
        result.accel_bias[i] = accel_plus - range / 2;
    }
    *calibration = result;
    return 0;
}
