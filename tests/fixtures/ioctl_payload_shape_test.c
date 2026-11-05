/* SPDX-License-Identifier: MIT */
#include "ioctl_payload_shape.h"

#include <stdint.h>
#include <string.h>

int main(void)
{
    const uint8_t entry[4] = {0xa7, 0, 0x91, 0};
    const uint8_t exit[4] = {0xa7, 0x34, 0, 0};
    uint8_t entry_nonzero[4] = {0};
    uint8_t exit_nonzero[4] = {0};
    uint8_t changed[4] = {0};

    if (hybrid_ioctl_payload_shape(4, entry, exit, entry_nonzero,
                                   exit_nonzero, changed) != 0)
        return 1;
    if (entry_nonzero[0] != 1 || entry_nonzero[1] != 0 ||
        entry_nonzero[2] != 1 || entry_nonzero[3] != 0)
        return 2;
    if (exit_nonzero[0] != 1 || exit_nonzero[1] != 1 ||
        exit_nonzero[2] != 0 || exit_nonzero[3] != 0)
        return 3;
    if (changed[0] != 0 || changed[1] != 1 || changed[2] != 1 ||
        changed[3] != 0)
        return 4;
    if (hybrid_ioctl_payload_shape(0, entry, exit, entry_nonzero,
                                   exit_nonzero, changed) == 0 ||
        hybrid_ioctl_payload_shape(57, entry, exit, entry_nonzero,
                                   exit_nonzero, changed) == 0 ||
        hybrid_ioctl_payload_shape(4, NULL, exit, entry_nonzero,
                                   exit_nonzero, changed) == 0 ||
        hybrid_ioctl_payload_shape(4, entry, exit, NULL,
                                   exit_nonzero, changed) == 0)
        return 5;
    if (memcmp(entry, (const uint8_t[]){0xa7, 0, 0x91, 0}, sizeof(entry)) != 0 ||
        memcmp(exit, (const uint8_t[]){0xa7, 0x34, 0, 0}, sizeof(exit)) != 0)
        return 6;
    return 0;
}
