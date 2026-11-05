#include "protocol_bridge.h"

static uint32_t checksum(uint8_t prefix, const uint8_t* data, size_t size) {
    uint32_t crc = 0xffffffffu;

    for (size_t pos = 0; pos <= size; ++pos) {
        crc ^= pos ? data[pos - 1] : prefix;
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }

    return ~crc;
}

static uint32_t little32(const uint8_t* data) {
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static void write32(uint8_t* data, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) data[i] = (uint8_t)(value >> (8 * i));
}

int bridge_input(const uint8_t* source, size_t size, uint8_t sequence, uint8_t destination[78]) {
    if (!source || !destination) return -1;
    int extended = size == 78 && source[0] == 0x31;

    if (!extended && !(size == 10 && source[0] == 1)) return -1;
    if (extended && checksum(0xa1, source, 74) != little32(source + 74)) return -2;
    const uint8_t* input = source + (extended ? 2 : 1);
    uint8_t result[78] = {0};

    result[0] = 0x11;
    result[1] = 0xc0;
    uint8_t* output = result + 3;

    for (unsigned i = 0; i < 4; ++i) output[i] = input[i];
    output[4] = input[extended ? 7 : 4];
    if ((output[4] & 15) > 8) return -3;
    output[5] = input[extended ? 8 : 5];
    output[6] = (input[extended ? 9 : 6] & 3) | ((sequence & 63) << 2);
    output[7] = input[extended ? 4 : 7];
    output[8] = input[extended ? 5 : 8];

    if (extended) {
        uint16_t timestamp = (uint16_t)(little32(input + 27) >> 4);

        output[9] = (uint8_t)timestamp;
        output[10] = (uint8_t)(timestamp >> 8);
        for (unsigned i = 0; i < 12; ++i) output[12 + i] = input[15 + i];
        output[29] = (input[52] & 15) > 10 ? 10 : input[52] & 15;
        if ((input[52] >> 4) == 1 || (input[52] >> 4) == 2) output[29] |= 0x10;
        output[32] = 1;
        output[33] = sequence;

        for (unsigned i = 0; i < 2; ++i) {
            const uint8_t* point = input + 32 + i * 4;
            uint8_t* target = output + 34 + i * 4;

            unsigned x = point[1] | ((unsigned)(point[2] & 15) << 8);
            unsigned y = (point[2] >> 4) | ((unsigned)point[3] << 4);
            if (x > 1919) x = 1919;
            y = y < 1080 ? y * 942 / 1080 : 941;
            target[0] = point[0];
            target[1] = (uint8_t)x;
            target[2] = (uint8_t)((x >> 8) | ((y & 15) << 4));
            target[3] = (uint8_t)(y >> 4);
        }
    }

    write32(result + 74, checksum(0xa1, result, 74));
    for (unsigned i = 0; i < 78; ++i) destination[i] = result[i];
    return 0;
}

int bridge_calibration(const uint8_t source[41], uint8_t destination[41]) {
    if (!source || !destination || source[0] != 5) return -1;
    if (checksum(0xa3, source, 37) != little32(source + 37)) return -2;
    uint8_t result[41];

    for (unsigned i = 0; i < 41; ++i) result[i] = source[i];
    const unsigned positions[6] = {7, 11, 15, 9, 13, 17};

    for (unsigned i = 0; i < 6; ++i) {
        result[7 + i * 2] = source[positions[i]];
        result[8 + i * 2] = source[positions[i] + 1];
    }

    write32(result + 37, checksum(0xa3, result, 37));
    for (unsigned i = 0; i < 41; ++i) destination[i] = result[i];
    return 0;
}

int bridge_output(const uint8_t source[78], BridgeFeedback* state, uint8_t destination[78]) {
    if (!source || !state || !destination || source[0] != 0x11) return -1;
    if (checksum(0xa2, source, 74) != little32(source + 74)) return -2;
    BridgeFeedback next = *state;

    if (source[3] & 1) {
        next.small = source[6];
        next.large = source[7];
    }

    if (source[3] & 2)
        for (unsigned i = 0; i < 3; ++i) next.color[i] = source[8 + i];
    uint8_t result[78] = {0};

    result[0] = 0x31;
    result[1] = (next.sequence++ & 15) << 4;
    result[2] = 0x10;
    result[3] = 3;
    result[4] = 4;
    result[5] = next.small;
    result[6] = next.large;
    for (unsigned i = 0; i < 3; ++i) result[47 + i] = next.color[i];
    write32(result + 74, checksum(0xa2, result, 74));
    for (unsigned i = 0; i < 78; ++i) destination[i] = result[i];
    *state = next;

    return 0;
}
