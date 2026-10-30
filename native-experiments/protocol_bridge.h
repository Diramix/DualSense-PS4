#ifndef PROTOCOL_BRIDGE_H
#define PROTOCOL_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
int bridge_input(const uint8_t *source, size_t size, uint8_t sequence, uint8_t destination[78]);
int bridge_calibration(const uint8_t source[41], uint8_t destination[41]);
typedef struct {
    uint8_t large, small, color[3], sequence;
} BridgeFeedback;
int bridge_output(const uint8_t source[78], BridgeFeedback *state, uint8_t destination[78]);
#endif
