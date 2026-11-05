/* SPDX-License-Identifier: MIT */
#ifndef HYBRID_TEST_NV_CHARDEV_NUMBERS_H
#define HYBRID_TEST_NV_CHARDEV_NUMBERS_H

/* Minimal host-test ABI fixture for the standard NVIDIA character nodes.
 * The production kernel build includes NVIDIA's header. These fixed values
 * let the CPU harness compile from a clean checkout without a local SDK tree.
 */
#define NV_MAJOR_DEVICE_NUMBER 195
#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247
#define NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE 254
#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255

#endif
