/* SPDX-License-Identifier: MIT */
#include "hybrid580-standard-node-devices.h"

#ifdef __KERNEL__
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <nv-chardev-numbers.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <nv-chardev-numbers.h>

struct cdev { int identity; void *owner; };
struct class;
struct device;
struct file_operations { int identity; void *owner; };
int register_chrdev_region(dev_t, unsigned int, const char *);
void unregister_chrdev_region(dev_t, unsigned int);
void cdev_init(struct cdev *, const struct file_operations *);
int cdev_add(struct cdev *, dev_t, unsigned int);
void cdev_del(struct cdev *);
struct class *class_create(const char *);
void class_destroy(struct class *);
struct device *device_create(struct class *, struct device *, dev_t,
                             void *, const char *, ...);
void device_destroy(struct class *, dev_t);
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#define PTR_ERR(pointer) ((int)(intptr_t)(pointer))
#define MKDEV(major, minor) makedev((major), (minor))
#define MAJOR(device) major(device)
#define MINOR(device) minor(device)
#endif

#define HYBRID580_NODE_NAME "hybrid580"

static struct cdev hybrid580_gpu_cdev;
static struct cdev hybrid580_control_cdev;
static struct class *hybrid580_node_class;
static struct device *hybrid580_gpu_devices[NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U];
static struct device *hybrid580_control_device;
static const struct hybrid580_gpu_catalog_v1 *hybrid580_node_catalog;
static bool hybrid580_gpu_region_registered;
static bool hybrid580_control_region_registered;
static bool hybrid580_gpu_cdev_added;
static bool hybrid580_control_cdev_added;
static bool hybrid580_nodes_ready;

static void hybrid580_standard_nodes_reset(void)
{
    hybrid580_u32 i;

    hybrid580_nodes_ready = false;
    if (hybrid580_node_class != NULL) {
        if (hybrid580_control_device != NULL) {
            device_destroy(hybrid580_node_class,
                MKDEV(NV_MAJOR_DEVICE_NUMBER,
                      NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE));
            hybrid580_control_device = NULL;
        }
        for (i = NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U; i != 0; --i) {
            hybrid580_u32 minor = i - 1U;
            if (hybrid580_gpu_devices[minor] != NULL) {
                device_destroy(hybrid580_node_class,
                               MKDEV(NV_MAJOR_DEVICE_NUMBER, minor));
                hybrid580_gpu_devices[minor] = NULL;
            }
        }
        class_destroy(hybrid580_node_class);
        hybrid580_node_class = NULL;
    }
    if (hybrid580_control_cdev_added) {
        cdev_del(&hybrid580_control_cdev);
        hybrid580_control_cdev_added = false;
    }
    if (hybrid580_gpu_cdev_added) {
        cdev_del(&hybrid580_gpu_cdev);
        hybrid580_gpu_cdev_added = false;
    }
    if (hybrid580_control_region_registered) {
        unregister_chrdev_region(
            MKDEV(NV_MAJOR_DEVICE_NUMBER,
                  NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1);
        hybrid580_control_region_registered = false;
    }
    if (hybrid580_gpu_region_registered) {
        unregister_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0),
            NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U);
        hybrid580_gpu_region_registered = false;
    }
    hybrid580_node_catalog = NULL;
}

int hybrid580_standard_nodes_register_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    const struct file_operations *fops)
{
    hybrid580_u32 i;
    int rc;

    if (catalog == NULL || fops == NULL ||
        catalog->count > NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U)
        return catalog != NULL &&
            catalog->count > NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U ?
            -E2BIG : -EINVAL;
    if (hybrid580_nodes_ready || hybrid580_gpu_region_registered ||
        hybrid580_control_region_registered ||
        hybrid580_gpu_cdev_added || hybrid580_control_cdev_added ||
        hybrid580_node_class != NULL)
        return -EBUSY;

    rc = register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0),
        NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, HYBRID580_NODE_NAME);
    if (rc != 0)
        return rc;
    hybrid580_gpu_region_registered = true;

    /* Minor 254 belongs to NVKMS; leave 248-254 unreserved. */
    rc = register_chrdev_region(
        MKDEV(NV_MAJOR_DEVICE_NUMBER,
              NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1,
        HYBRID580_NODE_NAME);
    if (rc != 0)
        goto fail;
    hybrid580_control_region_registered = true;
    hybrid580_node_catalog = catalog;

    cdev_init(&hybrid580_gpu_cdev, fops);
    /* cdev_init() stores ops but leaves cdev->owner NULL. Pin the module
     * before cdev_add() can publish this mapping to chrdev_open(). */
    hybrid580_gpu_cdev.owner = fops->owner;
    rc = cdev_add(&hybrid580_gpu_cdev,
        MKDEV(NV_MAJOR_DEVICE_NUMBER, 0),
        NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U);
    if (rc != 0)
        goto fail;
    hybrid580_gpu_cdev_added = true;

    cdev_init(&hybrid580_control_cdev, fops);
    hybrid580_control_cdev.owner = fops->owner;
    rc = cdev_add(&hybrid580_control_cdev,
        MKDEV(NV_MAJOR_DEVICE_NUMBER, NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1);
    if (rc != 0)
        goto fail;
    hybrid580_control_cdev_added = true;

    hybrid580_node_class = class_create(HYBRID580_NODE_NAME);
    if (IS_ERR(hybrid580_node_class)) {
        rc = PTR_ERR(hybrid580_node_class);
        hybrid580_node_class = NULL;
        goto fail;
    }
    for (i = 0; i < catalog->count; ++i) {
        hybrid580_gpu_devices[i] = device_create(
            hybrid580_node_class, NULL, MKDEV(NV_MAJOR_DEVICE_NUMBER, i),
            NULL, "nvidia%u", i);
        if (IS_ERR(hybrid580_gpu_devices[i])) {
            rc = PTR_ERR(hybrid580_gpu_devices[i]);
            hybrid580_gpu_devices[i] = NULL;
            goto fail;
        }
    }
    hybrid580_control_device = device_create(
        hybrid580_node_class, NULL,
        MKDEV(NV_MAJOR_DEVICE_NUMBER,
              NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE),
        NULL, "nvidiactl");
    if (IS_ERR(hybrid580_control_device)) {
        rc = PTR_ERR(hybrid580_control_device);
        hybrid580_control_device = NULL;
        goto fail;
    }

    /* Publish the catalog to open only after every node exists. */
    hybrid580_nodes_ready = true;
    return 0;

fail:
    hybrid580_standard_nodes_reset();
    return rc;
}

void hybrid580_standard_nodes_unregister_v1(void)
{
    hybrid580_standard_nodes_reset();
}

int hybrid580_standard_nodes_active_v1(void)
{
    return hybrid580_nodes_ready;
}

int hybrid580_standard_nodes_resolve_v1(
    hybrid580_u32 minor,
    struct hybrid580_standard_node_resolution_v1 *resolution)
{
    if (!hybrid580_nodes_ready)
        return -ENODEV;
    return hybrid580_standard_node_resolve_v1(
        hybrid580_node_catalog, minor, resolution);
}

int hybrid580_standard_nodes_catalog_matches_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog)
{
    hybrid580_u32 i;

    if (!hybrid580_nodes_ready || catalog == NULL ||
        catalog->count != hybrid580_node_catalog->count)
        return 0;
    for (i = 0; i < catalog->count; ++i) {
        const struct hybrid580_gpu_catalog_entry_v1 *left =
            &catalog->entries[i];
        const struct hybrid580_gpu_catalog_entry_v1 *right =
            &hybrid580_node_catalog->entries[i];
        if (memcmp(left->bdf, right->bdf, sizeof(left->bdf)) != 0 ||
            left->frontend_index != right->frontend_index ||
            left->frontend_gpu_id != right->frontend_gpu_id ||
            left->backend != right->backend ||
            left->backend_minor != right->backend_minor ||
            left->backend_gpu_id != right->backend_gpu_id ||
            left->domain != right->domain || left->bus != right->bus ||
            left->slot != right->slot || left->function != right->function ||
            left->vendor_id != right->vendor_id ||
            left->device_id != right->device_id || left->reserved != 0 ||
            right->reserved != 0)
            return 0;
    }
    return 1;
}
