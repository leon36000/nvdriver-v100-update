// SPDX-License-Identifier: GPL-2.0-only
/*
 * Compile-only MISC frontend skeleton. It is deliberately unrelated to the
 * NVIDIA PCI, character-device, RM, UVM, and CUDA interfaces.
 */
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>

static const char status_text[] =
    "frontend=hybrid-driver-lab\n"
    "status=stub-only\n"
    "binds_pci=false\n"
    "owns_nvidia_device_nodes=false\n"
    "forwards_cuda=false\n"
    "resource_manager=absent\n";

static ssize_t hybrid_lab_read(struct file *file, char __user *buffer,
                               size_t count, loff_t *position)
{
    return simple_read_from_buffer(buffer, count, position,
                                   status_text, sizeof(status_text) - 1);
}

static const struct file_operations hybrid_lab_fops = {
    .owner = THIS_MODULE,
    .read = hybrid_lab_read,
    .llseek = default_llseek,
};

static struct miscdevice hybrid_lab_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "hybrid-driver-lab",
    .fops = &hybrid_lab_fops,
    .mode = 0444,
};

static int __init hybrid_lab_init(void)
{
    return misc_register(&hybrid_lab_device);
}

static void __exit hybrid_lab_exit(void)
{
    misc_deregister(&hybrid_lab_device);
}

module_init(hybrid_lab_init);
module_exit(hybrid_lab_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Compile-only NVIDIA hybrid frontend stub without GPU or CUDA support");
