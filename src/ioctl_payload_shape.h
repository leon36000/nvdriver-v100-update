/* SPDX-License-Identifier: MIT */
#ifndef HYBRID_IOCTL_PAYLOAD_SHAPE_H
#define HYBRID_IOCTL_PAYLOAD_SHAPE_H

#include <stddef.h>
#include <stdint.h>

#define HYBRID_IOCTL_SHAPE_MAX_BYTES 56U

/*
 * Reduce two bounded snapshots to presence/change masks. The inputs must not
 * be emitted or retained by callers after this function returns.
 */
static inline int hybrid_ioctl_payload_shape(size_t size,
                                              const uint8_t *entry,
                                              const uint8_t *exit,
                                              uint8_t *entry_nonzero,
                                              uint8_t *exit_nonzero,
                                              uint8_t *changed)
{
    if (size == 0 || size > HYBRID_IOCTL_SHAPE_MAX_BYTES || entry == NULL ||
        exit == NULL || entry_nonzero == NULL || exit_nonzero == NULL ||
        changed == NULL)
        return -1;

    for (size_t i = 0; i < size; ++i) {
        entry_nonzero[i] = entry[i] != 0;
        exit_nonzero[i] = exit[i] != 0;
        changed[i] = entry[i] != exit[i];
    }
    return 0;
}

#endif
