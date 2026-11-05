#include <assert.h>
#include <string.h>
#include "../../src/hybrid_binapi_payload_shape.h"

int main(void) {
    unsigned char entry[HYBRID_BINAPI_PARAM_BYTES] = {0};
    unsigned char exit_payload[HYBRID_BINAPI_PARAM_BYTES];
    struct hybrid_binapi_payload_shape shape;

    entry[0] = 1;
    entry[8] = 0x80;
    assert(hybrid_binapi_payload_entry_shape(entry, &shape) == 0);
    assert(shape.payload_valid);
    assert(shape.nonzero_u32_count == 2);
    assert((shape.nonzero_u32_mask[0] & 0x05) == 0x05);

    memcpy(exit_payload, entry, sizeof(entry));
    exit_payload[5] = 0x42;
    exit_payload[8] = 0x81;
    exit_payload[HYBRID_BINAPI_PARAM_BYTES - 1] = 1;
    assert(hybrid_binapi_payload_exit_shape(exit_payload, entry, &shape) == 0);
    assert(shape.payload_valid);
    assert(!shape.payload_equal);
    assert(shape.nonzero_u32_count == 4);
    assert(shape.changed_byte_count == 3);
    assert((shape.nonzero_u32_mask[0] & 0x07) == 0x07);
    assert((shape.changed_byte_mask[0] & (1u << 5)) != 0);
    assert((shape.changed_byte_mask[1] & 1u) != 0);
    assert((shape.changed_byte_mask[HYBRID_BINAPI_CHANGED_MASK_BYTES - 1] & 0x80) != 0);

    memset(entry, 0, sizeof(entry));
    assert(hybrid_binapi_payload_entry_shape(entry, &shape) == 0);
    assert(shape.nonzero_u32_count == 0);
    assert(hybrid_binapi_payload_exit_shape(entry, entry, &shape) == 0);
    assert(shape.payload_equal);
    assert(shape.changed_byte_count == 0);
    return 0;
}
