/* SPDX-License-Identifier: MIT */
#ifndef HYBRID_BINAPI_PAYLOAD_SHAPE_H
#define HYBRID_BINAPI_PAYLOAD_SHAPE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define HYBRID_BINAPI_PARAM_BYTES 992U
#define HYBRID_BINAPI_U32_SLOTS (HYBRID_BINAPI_PARAM_BYTES / sizeof(uint32_t))
#define HYBRID_BINAPI_U32_MASK_BYTES ((HYBRID_BINAPI_U32_SLOTS + 7U) / 8U)
#define HYBRID_BINAPI_CHANGED_MASK_BYTES ((HYBRID_BINAPI_PARAM_BYTES + 7U) / 8U)

_Static_assert(HYBRID_BINAPI_PARAM_BYTES == 992U, "observed BINAPI buffer bound");
_Static_assert(HYBRID_BINAPI_U32_SLOTS == 248U, "BINAPI 32-bit shape slots");
_Static_assert(HYBRID_BINAPI_U32_MASK_BYTES == 31U, "BINAPI shape mask bytes");
_Static_assert(HYBRID_BINAPI_CHANGED_MASK_BYTES == 124U, "BINAPI changed mask bytes");

struct hybrid_binapi_payload_shape {
    uint8_t nonzero_u32_mask[HYBRID_BINAPI_U32_MASK_BYTES];
    uint8_t changed_byte_mask[HYBRID_BINAPI_CHANGED_MASK_BYTES];
    uint16_t nonzero_u32_count;
    uint16_t changed_byte_count;
    int payload_valid;
    /* -1 means entry-only snapshot; 0/1 means exit comparison result. */
    int payload_equal;
};

static inline void hybrid_binapi_set_mask_bit(uint8_t *mask, size_t index) {
    mask[index / 8U] |= (uint8_t)(1U << (index % 8U));
}

static inline int hybrid_binapi_payload_entry_shape(
    const uint8_t payload[HYBRID_BINAPI_PARAM_BYTES],
    struct hybrid_binapi_payload_shape *shape)
{
    if (payload == NULL || shape == NULL)
        return -1;
    memset(shape, 0, sizeof(*shape));
    shape->payload_equal = -1;
    for (size_t slot = 0; slot < HYBRID_BINAPI_U32_SLOTS; ++slot) {
        uint32_t word;
        memcpy(&word, payload + slot * sizeof(word), sizeof(word));
        if (word != 0U) {
            hybrid_binapi_set_mask_bit(shape->nonzero_u32_mask, slot);
            ++shape->nonzero_u32_count;
        }
    }
    shape->payload_valid = 1;
    return 0;
}

static inline int hybrid_binapi_payload_exit_shape(
    const uint8_t payload[HYBRID_BINAPI_PARAM_BYTES],
    const uint8_t entry[HYBRID_BINAPI_PARAM_BYTES],
    struct hybrid_binapi_payload_shape *shape)
{
    if (payload == NULL || entry == NULL || shape == NULL)
        return -1;
    if (hybrid_binapi_payload_entry_shape(payload, shape) != 0)
        return -1;
    shape->payload_equal = memcmp(payload, entry, HYBRID_BINAPI_PARAM_BYTES) == 0;
    for (size_t byte = 0; byte < HYBRID_BINAPI_PARAM_BYTES; ++byte) {
        if (payload[byte] != entry[byte]) {
            hybrid_binapi_set_mask_bit(shape->changed_byte_mask, byte);
            ++shape->changed_byte_count;
        }
    }
    return 0;
}

#endif
