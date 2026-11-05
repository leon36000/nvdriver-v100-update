/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysmacros.h>

#include "nv-chardev-numbers.h"
#include "hybrid580-standard-node-devices.h"

_Static_assert(NV_MAJOR_DEVICE_NUMBER == 195,
               "standard NVIDIA major number changed");
_Static_assert(NV_MINOR_DEVICE_NUMBER_REGULAR_MAX == 247,
               "standard NVIDIA GPU-minor range changed");
_Static_assert(NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE == 254,
               "NVIDIA modeset minor reservation changed");
_Static_assert(NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE == 255,
               "standard NVIDIA control minor changed");

#define MKDEV(major_number, minor_number) makedev((major_number), (minor_number))

struct cdev { int identity; void *owner; };
struct class { int identity; };
struct device { dev_t devt; char name[32]; };
struct file_operations { int identity; void *owner; };

static int reserve_result[2], fail_cdev_add, fail_class_create, fail_device_create;
static int modeset_region_busy;
static unsigned int cdev_init_calls, cdev_add_calls, cdev_del_calls, device_create_calls;
static int cdev_owner_mismatch;
static unsigned int device_destroy_calls, class_destroy_calls;
static unsigned int register_region_calls, unregister_region_calls;
static dev_t reserve_devt[2], released_devt[2], added_devt[2];
static dev_t created_devt[8], destroyed_devt[8];
static unsigned int reserve_count[2], released_count[2], added_count[2], created_count;
static int deleted_cdev_id[2];
static unsigned int deleted_cdev_count;
static char created_names[8][32];
static struct cdev cdevs[2];
static struct class class_object;
static struct device devices[8];
static const struct file_operations fops_object = {
    .identity = 1,
    .owner = (void *)(uintptr_t)1,
};

int register_chrdev_region(dev_t first, unsigned int count, const char *name)
{
    unsigned int index = register_region_calls++;
    assert(name != NULL && strcmp(name, "hybrid580") == 0);
    assert(index < 2);
    reserve_devt[index] = first;
    reserve_count[index] = count;
    if (reserve_result[index] != 0)
        return reserve_result[index];
    if (modeset_region_busy && major(first) == 195 && minor(first) <= 254 &&
        minor(first) + count > 254)
        return -EBUSY;
    return 0;
}

void unregister_chrdev_region(dev_t first, unsigned int count)
{
    unsigned int index = unregister_region_calls++;
    unsigned int i;
    int found = 0;
    assert(index < 2);
    for (i = 0; i < register_region_calls; ++i) {
        if (first == reserve_devt[i] && count == reserve_count[i]) {
            found = 1;
            break;
        }
    }
    assert(found);
    released_devt[index] = first;
    released_count[index] = count;
}

void cdev_init(struct cdev *cdev, const struct file_operations *fops)
{
    assert(fops == &fops_object);
    memset(cdev, 0, sizeof(*cdev));
    cdev->identity = (int)++cdev_init_calls;
}

int cdev_add(struct cdev *cdev, dev_t first, unsigned int count)
{
    unsigned int index = cdev_add_calls++;
    assert(index < 2);
    added_devt[index] = first;
    added_count[index] = count;
    assert(cdev->identity == (int)index + 1);
    if (cdev->owner != fops_object.owner)
        cdev_owner_mismatch = 1;
    return fail_cdev_add == (int)index + 1 ? -EIO : 0;
}

void cdev_del(struct cdev *cdev)
{
    assert(cdev != NULL);
    assert(deleted_cdev_count < 2);
    deleted_cdev_id[deleted_cdev_count++] = cdev->identity;
    ++cdev_del_calls;
}

struct class *class_create(const char *name)
{
    assert(strcmp(name, "hybrid580") == 0);
    if (fail_class_create)
        return (struct class *)(intptr_t)-ENOMEM;
    return &class_object;
}

void class_destroy(struct class *class)
{
    assert(class == &class_object);
    ++class_destroy_calls;
}

struct device *device_create(struct class *class, struct device *parent,
                             dev_t devt, void *data, const char *format, ...)
{
    va_list args;
    unsigned int index = device_create_calls++;
    assert(class == &class_object && parent == NULL && data == NULL);
    assert(index < 8);
    devices[index].devt = devt;
    va_start(args, format);
    if (strcmp(format, "nvidia%u") == 0) {
        unsigned int minor = va_arg(args, unsigned int);
        assert(snprintf(devices[index].name, sizeof(devices[index].name),
                        format, minor) > 0);
    } else {
        assert(strcmp(format, "nvidiactl") == 0);
        strcpy(devices[index].name, format);
    }
    va_end(args);
    if (fail_device_create == (int)index + 1)
        return (struct device *)(intptr_t)-ENOMEM;
    created_devt[index] = devt;
    strcpy(created_names[index], devices[index].name);
    ++created_count;
    return &devices[index];
}

void device_destroy(struct class *class, dev_t devt)
{
    assert(class == &class_object);
    assert(device_destroy_calls < 8);
    destroyed_devt[device_destroy_calls++] = devt;
}

static struct hybrid580_gpu_backend_record_v1 record(
    const char *bdf, unsigned int minor, unsigned int gpu_id,
    unsigned int bus, unsigned int device)
{
    struct hybrid580_gpu_backend_record_v1 item = {0};
    strcpy(item.bdf, bdf);
    item.backend_minor = minor;
    item.backend_gpu_id = gpu_id;
    item.domain = 0;
    item.bus = bus;
    item.vendor_id = 0x10de;
    item.device_id = device;
    return item;
}

static void reset_fakes(void)
{
    memset(reserve_result, 0, sizeof(reserve_result));
    modeset_region_busy = 0;
    fail_cdev_add = fail_class_create = fail_device_create = 0;
    cdev_init_calls = cdev_add_calls = cdev_del_calls = device_create_calls = 0;
    cdev_owner_mismatch = 0;
    device_destroy_calls = class_destroy_calls = 0;
    register_region_calls = unregister_region_calls = 0;
    created_count = deleted_cdev_count = 0;
    memset(reserve_devt, 0, sizeof(reserve_devt));
    memset(released_devt, 0, sizeof(released_devt));
    memset(reserve_count, 0, sizeof(reserve_count));
    memset(released_count, 0, sizeof(released_count));
    memset(added_devt, 0, sizeof(added_devt));
    memset(added_count, 0, sizeof(added_count));
    memset(created_devt, 0, sizeof(created_devt));
    memset(destroyed_devt, 0, sizeof(destroyed_devt));
    memset(deleted_cdev_id, 0, sizeof(deleted_cdev_id));
    memset(created_names, 0, sizeof(created_names));
    memset(cdevs, 0, sizeof(cdevs));
}

int main(void)
{
    struct hybrid580_gpu_catalog_v1 catalog = {0};
    struct hybrid580_gpu_backend_record_v1 legacy[1] = {
        record("0000:81:00.0", 0, 5, 0x81, 0x1db6),
    };
    struct hybrid580_gpu_backend_record_v1 open[1] = {
        record("0000:02:00.0", 0, 512, 2, 0x2c02),
    };
    struct hybrid580_standard_node_resolution_v1 resolved = {0};
    unsigned int scenarios = 0;

    assert(hybrid580_gpu_catalog_build_v1(legacy, 1, open, 1, &catalog) == 0);
    reset_fakes();
    modeset_region_busy = 1;
    assert(hybrid580_standard_nodes_register_v1(&catalog, &fops_object) == 0);
    if (cdev_owner_mismatch) {
        fprintf(stderr, "cdev module owner not pinned before cdev_add\n");
        return 2;
    }
    assert(hybrid580_standard_nodes_active_v1());
    assert(register_region_calls == 2);
    assert(reserve_devt[0] == MKDEV(195, 0) && reserve_count[0] == 248);
    assert(reserve_devt[1] == MKDEV(195, 255) && reserve_count[1] == 1);
    assert(added_devt[0] == MKDEV(195, 0) && added_count[0] == 248);
    assert(added_devt[1] == MKDEV(195, 255) && added_count[1] == 1);
    assert(created_count == 3 && device_create_calls == 3);
    assert(created_devt[0] == MKDEV(195, 0) && strcmp(created_names[0], "nvidia0") == 0);
    assert(created_devt[1] == MKDEV(195, 1) && strcmp(created_names[1], "nvidia1") == 0);
    assert(created_devt[2] == MKDEV(195, 255) && strcmp(created_names[2], "nvidiactl") == 0);
    assert(hybrid580_standard_nodes_resolve_v1(0, &resolved) == 0);
    assert(resolved.kind == HYBRID580_STANDARD_NODE_GPU &&
           resolved.backend == HYBRID580_BACKEND_OPEN);
    assert(hybrid580_standard_nodes_resolve_v1(1, &resolved) == 0);
    assert(resolved.backend == HYBRID580_BACKEND_LEGACY);
    assert(hybrid580_standard_nodes_resolve_v1(255, &resolved) == 0);
    assert(resolved.kind == HYBRID580_STANDARD_NODE_CONTROL);
    assert(hybrid580_standard_nodes_catalog_matches_v1(&catalog));
    struct hybrid580_gpu_catalog_v1 changed = catalog;
    changed.entries[0].device_id ^= 1;
    assert(!hybrid580_standard_nodes_catalog_matches_v1(&changed));
    assert(hybrid580_standard_nodes_register_v1(&catalog, &fops_object) == -EBUSY);
    hybrid580_standard_nodes_unregister_v1();
    assert(!hybrid580_standard_nodes_active_v1());
    assert(device_destroy_calls == 3 && class_destroy_calls == 1);
    assert(cdev_del_calls == 2 && unregister_region_calls == 2);
    assert(released_devt[0] == MKDEV(195, 255) && released_count[0] == 1);
    assert(released_devt[1] == MKDEV(195, 0) && released_count[1] == 248);
    assert(hybrid580_standard_nodes_resolve_v1(0, &resolved) == -ENODEV);
    ++scenarios;

    reset_fakes();
    reserve_result[0] = -EBUSY;
    assert(hybrid580_standard_nodes_register_v1(&catalog, &fops_object) == -EBUSY);
    assert(!hybrid580_standard_nodes_active_v1());
    assert(register_region_calls == 1 && cdev_add_calls == 0 &&
           cdev_del_calls == 0 && unregister_region_calls == 0);
    ++scenarios;

    reset_fakes();
    reserve_result[1] = -EBUSY;
    assert(hybrid580_standard_nodes_register_v1(&catalog, &fops_object) == -EBUSY);
    assert(!hybrid580_standard_nodes_active_v1());
    assert(register_region_calls == 2 && unregister_region_calls == 1);
    assert(released_devt[0] == MKDEV(195, 0) && released_count[0] == 248);
    assert(cdev_add_calls == 0);
    ++scenarios;

    reset_fakes();
    fail_cdev_add = 1;
    assert(hybrid580_standard_nodes_register_v1(&catalog, &fops_object) == -EIO);
    assert(!hybrid580_standard_nodes_active_v1());
    assert(cdev_init_calls == 1 && cdev_add_calls == 1 &&
           cdev_del_calls == 0 && deleted_cdev_count == 0);
    assert(device_destroy_calls == 0 && class_destroy_calls == 0 &&
           unregister_region_calls == 2);
    assert(released_devt[0] == MKDEV(195, 255) && released_count[0] == 1);
    assert(released_devt[1] == MKDEV(195, 0) && released_count[1] == 248);
    ++scenarios;

    reset_fakes();
    fail_cdev_add = 2;
    assert(hybrid580_standard_nodes_register_v1(&catalog, &fops_object) == -EIO);
    assert(!hybrid580_standard_nodes_active_v1());
    assert(cdev_init_calls == 2 && cdev_add_calls == 2 &&
           cdev_del_calls == 1 && deleted_cdev_count == 1);
    assert(deleted_cdev_id[0] == 1 && unregister_region_calls == 2);
    ++scenarios;

    reset_fakes();
    fail_class_create = 1;
    assert(hybrid580_standard_nodes_register_v1(&catalog, &fops_object) == -ENOMEM);
    assert(!hybrid580_standard_nodes_active_v1());
    assert(device_destroy_calls == 0 && cdev_del_calls == 2 &&
           unregister_region_calls == 2);
    assert(deleted_cdev_id[0] == 2 && deleted_cdev_id[1] == 1);
    ++scenarios;

    reset_fakes();
    fail_device_create = 1;
    assert(hybrid580_standard_nodes_register_v1(&catalog, &fops_object) == -ENOMEM);
    assert(!hybrid580_standard_nodes_active_v1());
    assert(device_create_calls == 1 && created_count == 0 &&
           device_destroy_calls == 0);
    assert(class_destroy_calls == 1 && cdev_del_calls == 2 &&
           unregister_region_calls == 2);
    assert(deleted_cdev_id[0] == 2 && deleted_cdev_id[1] == 1);
    ++scenarios;

    reset_fakes();
    fail_device_create = 2;
    assert(hybrid580_standard_nodes_register_v1(&catalog, &fops_object) == -ENOMEM);
    assert(!hybrid580_standard_nodes_active_v1());
    assert(device_destroy_calls == 1 && destroyed_devt[0] == MKDEV(195, 0));
    assert(class_destroy_calls == 1 && cdev_del_calls == 2 &&
           unregister_region_calls == 2);
    assert(deleted_cdev_id[0] == 2 && deleted_cdev_id[1] == 1);
    ++scenarios;

    reset_fakes();
    fail_device_create = 3;
    assert(hybrid580_standard_nodes_register_v1(&catalog, &fops_object) == -ENOMEM);
    assert(!hybrid580_standard_nodes_active_v1());
    assert(device_create_calls == 3 && created_count == 2);
    assert(device_destroy_calls == 2 &&
           destroyed_devt[0] == MKDEV(195, 1) &&
           destroyed_devt[1] == MKDEV(195, 0));
    assert(class_destroy_calls == 1 && cdev_del_calls == 2 &&
           unregister_region_calls == 2);
    assert(deleted_cdev_id[0] == 2 && deleted_cdev_id[1] == 1);
    ++scenarios;

    struct hybrid580_gpu_catalog_v1 too_many = {0};
    too_many.count = 249;
    reset_fakes();
    assert(hybrid580_standard_nodes_register_v1(&too_many, &fops_object) == -E2BIG);
    assert(cdev_add_calls == 0 && reserve_count[0] == 0);
    ++scenarios;

    printf("standard node device scenarios: %u\n", scenarios);
    return 0;
}
