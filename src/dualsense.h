#ifndef DUALSENSE_H
#define DUALSENSE_H
#include <stddef.h>
#include <stdint.h>
typedef struct {
    uint32_t buttons;
    uint8_t left_x;
    uint8_t left_y;
    uint8_t right_x;
    uint8_t right_y;
    uint8_t l2;
    uint8_t r2;
    uint8_t mute;
    uint8_t extended;
    uint8_t battery;
    int16_t gyro[3];
    int16_t accel[3];
    uint16_t touch_x[2];
    uint16_t touch_y[2];
    uint8_t touch_id[2];
    uint8_t touch_active[2];
} DualSenseState;
int dualsense_decode_bluetooth(const uint8_t *report, size_t length, DualSenseState *state);
typedef struct {
    float gyro_scale[3];
    float accel_scale[3];
    float accel_bias[3];
} DualSenseCalibration;
int dualsense_calibration_bluetooth(const uint8_t *report, size_t length, DualSenseCalibration *calibration);
void dualsense_output_bluetooth(uint8_t report[78], uint8_t sequence, uint8_t large, uint8_t small, const uint8_t color[3], int reset_leds);
#endif
