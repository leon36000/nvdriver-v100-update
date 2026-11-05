#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build an isolated, namespaced Open R595 module against its pinned core.

This is compile-only. It copies the official source snapshot and exact installed
R595 core into disposable experiment directories; it never installs or loads a
module and never accesses a GPU.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
          "open-gpu-kernel-modules-595.99.02")
CORE = Path("/usr/src/nvidia-595.99.02/nvidia/nv-kernel.o_binary")
SOURCE_TREE_SHA256 = "6d4ae86fb03f3afac63007c3c13422b114c93f5ab6a271ccb3dde5fb2440c066"
SOURCE_FILE_COUNT = 3810
CORE_SHA256 = "c19870e43606b4358d9274c4d3dec2adb1822d65ce1203520a8184cf043cafe8"
PRIVATE_PREFIX = "hybrid580_open_"
PRIVATE_MODULE = "hybrid580_open"
PROJECTION_PATCH = ROOT / "patches/r580.178.04/0008-private-open-file-projection.patch"
PROJECTION_EXPORTS = {
    "hybrid580_open_register_file_projection_v1": "EXPORT_SYMBOL",
    "hybrid580_open_unregister_file_projection_v1": "EXPORT_SYMBOL",
}
CONTROL_SESSION_PATCH = ROOT / "patches/r580.178.04/0009-private-open-control-session.patch"
CONTROL_SESSION_EXPORTS = {
    "hybrid580_open_control_session_create_v1": "EXPORT_SYMBOL",
    "hybrid580_open_control_session_get_v1": "EXPORT_SYMBOL",
    "hybrid580_open_control_session_put_v1": "EXPORT_SYMBOL",
    "hybrid580_open_control_session_file_v1": "EXPORT_SYMBOL",
}
DEVICE_MAPPING_UPDATE_PATCH = ROOT / "patches/r580.178.04/0041-private-open-update-device-mapping-info.patch"
DEVICE_MAPPING_UPDATE_EXPORTS = {
    "hybrid580_open_control_session_update_device_mapping_info_v1": "EXPORT_SYMBOL",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_tree_digest(path: Path) -> tuple[str, int]:
    """Hash each regular file and relative path in stable lexical order."""
    root = Path(path)
    digest = hashlib.sha256()
    count = 0
    for item in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        relative = item.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(sha256(item)))
        count += 1
    return digest.hexdigest(), count


def transform_kbuild(text: str) -> str:
    """Rename the R595 module and inject the private API namespace header."""
    block = ("obj-m += nvidia.o\n"
             "nvidia-y := $(NVIDIA_OBJECTS)\n\n"
             "NVIDIA_KO = nvidia/nvidia.ko")
    replacement = ("obj-m += hybrid580_open.o\n"
                   "hybrid580_open-y := $(NVIDIA_OBJECTS)\n\n"
                   "NVIDIA_KO = hybrid580_open.ko")
    if text.count(block) != 1:
        raise ValueError("R595 Kbuild module-name anchor is missing or ambiguous")
    text = text.replace(block, replacement)
    object_line = "nvidia-y += $(NVIDIA_BINARY_OBJECT_O)\n"
    if text.count(object_line) != 1:
        raise ValueError("R595 Kbuild core-object anchor is missing or ambiguous")
    text = text.replace(object_line,
                        "hybrid580_open-y += $(NVIDIA_BINARY_OBJECT_O)\n")
    cflags = "NVIDIA_CFLAGS += -I$(src)/nvidia\n"
    if text.count(cflags) != 1:
        raise ValueError("R595 Kbuild CFLAGS anchor is missing or ambiguous")
    text = text.replace(cflags, cflags +
                        "NVIDIA_CFLAGS += -include $(src)/nvidia/"
                        "hybrid580-open-exports.h\n")
    return text


def transform_module_name(text: str) -> str:
    """Keep Linux-visible resource labels in the private Open namespace."""
    anchor = '#define MODULE_NAME "nvidia"'
    if text.count(anchor) != 1:
        raise ValueError("R595 MODULE_NAME anchor is missing or ambiguous")
    return text.replace(anchor, '#define MODULE_NAME "hybrid580_open"')


def transform_nv_pci_selection(text: str) -> str:
    """Adapt the early, fail-closed PCI selector to the R595 source layout."""
    marker = "extern int NVreg_ExcludeAllGpus;\n"
    if text.count(marker) != 1:
        raise ValueError("R595 PCI selector declaration anchor is missing or ambiguous")
    selector = '''
/* Explicit, read-only selection; absence never claims a PCI GPU. */
static char *hybrid_gpu_pci;
module_param_named(hybrid_gpu_pci, hybrid_gpu_pci, charp, 0400);
MODULE_PARM_DESC(hybrid_gpu_pci,
    "Private Open backend: exact lowercase dddd:bb:ss.f PCI selector");

static int hybrid_pci_bdf_selected(const char *requested, const char *actual)
{
    unsigned int i;

    if (requested == NULL || actual == NULL || strlen(requested) != 12)
        return 0;

    for (i = 0; i < 12; ++i)
    {
        if (i == 4 || i == 7)
        {
            if (requested[i] != ':')
                return 0;
        }
        else if (i == 10)
        {
            if (requested[i] != '.')
                return 0;
        }
        else if (!((requested[i] >= '0' && requested[i] <= '9') ||
                   (requested[i] >= 'a' && requested[i] <= 'f')))
            return 0;
    }

    /* PCI slots are 0..31 and functions 0..7. */
    if (requested[8] > '1' || requested[11] > '7')
        return 0;

    return strcmp(requested, actual) == 0;
}
'''
    text = text.replace(marker, marker + selector, 1)

    old_probe = '''    NvU8 regs_bar_index = nv_bar_index_to_os_bar_index(pci_dev,
                                                       NV_GPU_BAR_INDEX_REGS);
    NvBool bar0_requested = NV_FALSE;

    nv_printf(NV_DBG_SETUP, "NVRM: probing 0x%x 0x%x, class 0x%x\\n",
'''
    new_probe = '''    NvU8 regs_bar_index;
    NvBool bar0_requested = NV_FALSE;

    /* Reject every non-selected GPU before BAR helpers, logging or RM work. */
    if (!hybrid_pci_bdf_selected(hybrid_gpu_pci, pci_name(pci_dev)))
        return -ENODEV;

    regs_bar_index = nv_bar_index_to_os_bar_index(pci_dev,
                                                 NV_GPU_BAR_INDEX_REGS);

    nv_printf(NV_DBG_SETUP, "NVRM: probing 0x%x 0x%x, class 0x%x\\n",
'''
    if text.count(old_probe) != 1:
        raise ValueError("R595 PCI probe early-guard anchor is missing or ambiguous")
    text = text.replace(old_probe, new_probe, 1)

    start = text.find("nv_pci_count_devices(void)")
    end = text.find("nv_pci_is_valid_topology_for_direct_pci(", start)
    if start < 0 or end < 0 or end <= start:
        raise ValueError("R595 PCI device-count function anchors are missing")
    count_body = text[start:end]
    supported = "if (rm_is_supported_pci_device("
    if count_body.count(supported) != 2:
        raise ValueError("R595 PCI device-count call anchors are missing or ambiguous")
    count_body = count_body.replace(
        supported,
        "if (hybrid_pci_bdf_selected(hybrid_gpu_pci, pci_name(pci_dev)) &&\n"
        "            rm_is_supported_pci_device(")
    text = text[:start] + count_body + text[end:]
    return text


def transform_private_chardev(text: str) -> str:
    """Replace R595 fixed-major registration with a private dynamic range."""
    alias = "MODULE_ALIAS_CHARDEV_MAJOR(NV_MAJOR_DEVICE_NUMBER);\n"
    if text.count(alias) != 1:
        raise ValueError("R595 public character-major alias anchor is missing or ambiguous")
    text = text.replace(alias, "", 1)

    helper_start = text.find("static int nv_register_chrdev(")
    helper_end = text.find("static int __init nvidia_init_module(void)", helper_start)
    if helper_start < 0 or helper_end < 0 or helper_end <= helper_start:
        raise ValueError("R595 character-device helper anchors are missing")
    if text[helper_start:helper_end].count("nv_unregister_chrdev") != 1:
        raise ValueError("R595 character-device helper block is not the pinned shape")
    helper = '''static dev_t hybrid_chrdev_base;

static int hybrid_register_chrdevs(void)
{
    int rc;

    rc = alloc_chrdev_region(&hybrid_chrdev_base, 0,
            NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE + 1, "hybrid580_open");
    if (rc < 0)
    {
        hybrid_chrdev_base = 0;
        return rc;
    }

    cdev_init(&nv_linux_devices_cdev, &nvidia_fops);
    rc = cdev_add(&nv_linux_devices_cdev, hybrid_chrdev_base,
            NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1);
    if (rc < 0)
        goto release_region;

    cdev_init(&nv_linux_control_device_cdev, &nvidia_fops);
    rc = cdev_add(&nv_linux_control_device_cdev,
            MKDEV(MAJOR(hybrid_chrdev_base), NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1);
    if (rc < 0)
    {
        cdev_del(&nv_linux_devices_cdev);
        goto release_region;
    }

    return 0;

release_region:
    unregister_chrdev_region(hybrid_chrdev_base,
            NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE + 1);
    hybrid_chrdev_base = 0;
    return rc;
}

static void hybrid_unregister_chrdevs(void)
{
    cdev_del(&nv_linux_control_device_cdev);
    cdev_del(&nv_linux_devices_cdev);
    unregister_chrdev_region(hybrid_chrdev_base,
            NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE + 1);
    hybrid_chrdev_base = 0;
}

'''
    text = text[:helper_start] + helper + text[helper_end:]

    init_start = text.find("static int __init nvidia_init_module(void)")
    registration_start = text.find(
        "    /*\n     * Register char devices for both the region of regular devices", init_start)
    drivers_label = text.find("\ndrivers_exit:\n", registration_start)
    if init_start < 0 or registration_start < 0 or drivers_label < 0:
        raise ValueError("R595 module-init character-device anchors are missing")
    old_registration = text[registration_start:drivers_label]
    if ("nv_register_chrdev(" not in old_registration or
            "partial_chrdev_exit:" not in old_registration or
            old_registration.count("nv_unregister_chrdev(") != 1):
        raise ValueError("R595 module-init character-device block is not the pinned shape")
    registration = '''    /* Register the private dynamic major after RM and GPU setup. */
    rc = hybrid_register_chrdevs();
    if (rc < 0)
    {
        goto drivers_exit;
    }

    __nv_init_sp = sp;

    return 0;
'''
    text = text[:registration_start] + registration + text[drivers_label:]

    exit_start = text.find("static void __exit nvidia_exit_module(void)")
    old_unregister = '''    nv_unregister_chrdev(NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE, 1,
        &nv_linux_control_device_cdev);
    nv_unregister_chrdev(0, NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1,
        &nv_linux_devices_cdev);
'''
    if exit_start < 0 or text.count(old_unregister) != 1:
        raise ValueError("R595 module-exit character-device anchors are missing or ambiguous")
    text = text.replace(old_unregister, "    hybrid_unregister_chrdevs();\n", 1)

    old_major_check = '''    if (MAJOR(rdev) != NV_MAJOR_DEVICE_NUMBER)
    {
        goto fail;
    }
'''
    new_major_check = '''    if (hybrid_chrdev_base == 0 ||
        filp->f_op != &nvidia_fops ||
        MAJOR(rdev) != MAJOR(hybrid_chrdev_base))
    {
        goto fail;
    }
'''
    if text.count(old_major_check) != 1:
        raise ValueError("R595 file-private fixed-major check is missing or ambiguous")
    text = text.replace(old_major_check, new_major_check, 1)
    if ("nv_register_chrdev(" in text or
            re.search(r"(?<!un)register_chrdev_region\(", text)):
        raise ValueError("R595 fixed-major character registration remains")
    return text


def transform_procfs_path(text: str) -> str:
    """Size the private procfs directory buffer for the longer module name."""
    old = "    char nv_dir_name[20];\n"
    new = '    char nv_dir_name[sizeof("driver/" MODULE_NAME)];\n'
    if text.count(old) != 1:
        raise ValueError("R595 procfs directory-buffer anchor is missing or ambiguous")
    return text.replace(old, new, 1)


def extract_projection_api_header(patch_text: str) -> str:
    """Extract the exact shared ABI header added by the R580 projection patch."""
    target = "+++ b/kernel-open/nvidia/hybrid580-file-projection.h\n"
    if patch_text.count(target) != 1:
        raise ValueError("R580 file-projection header patch anchor is missing or ambiguous")
    lines = patch_text.splitlines(keepends=True)
    try:
        index = lines.index(target)
    except ValueError as error:
        raise ValueError("R580 file-projection header line is not exact") from error
    if index + 1 >= len(lines) or not lines[index + 1].startswith("@@ -0,0 +1,"):
        raise ValueError("R580 file-projection header hunk is missing")
    content: list[str] = []
    for line in lines[index + 2:]:
        if line.startswith(("diff --git ", "--- ")):
            break
        if not line.startswith("+"):
            raise ValueError("R580 file-projection header contains a non-addition line")
        content.append(line[1:])
    header = "".join(content)
    if (not header.startswith("/* SPDX-License-Identifier: MIT */\n") or
            not header.endswith("#endif\n") or
            header.count("struct hybrid580_file_projection_ops_v1 {") != 1):
        raise ValueError("R580 file-projection header content is incomplete")
    return header


def _extract_added_projection_helpers(patch_text: str) -> str:
    start_marker = "+struct hybrid580_file_projection_provider {"
    end_marker = " nv_file_private_t* NV_API_CALL nv_get_file_private("
    if patch_text.count(start_marker) != 1 or patch_text.count(end_marker) != 1:
        raise ValueError("R580 file-projection helper hunk is missing or ambiguous")
    start = patch_text.index(start_marker)
    end = patch_text.index(end_marker, start)
    additions = patch_text[start:end].splitlines(keepends=True)
    if any(not line.startswith("+") for line in additions):
        raise ValueError("R580 file-projection helper hunk has unexpected context")
    helper = "".join(line[1:] for line in additions)

    old_control = ("((NV_STATE_PTR(nvl))->flags & (NV_FLAG_OPEN | NV_FLAG_CONTROL)) !=\n"
                   "                (NV_FLAG_OPEN | NV_FLAG_CONTROL)")
    if helper.count(old_control) != 1:
        raise ValueError("R580 control-file validation anchor is missing or ambiguous")
    helper = helper.replace(old_control, "(nv->flags & NV_FLAG_CONTROL) == 0", 1)
    old_state_declaration = "    nv_linux_state_t *nvl;\n    struct inode *inode;"
    if helper.count(old_state_declaration) != 1:
        raise ValueError("R580 projection state declaration anchor is missing or ambiguous")
    helper = helper.replace(old_state_declaration,
                            "    nv_linux_state_t *nvl;\n    nv_state_t *nv;\n    struct inode *inode;", 1)
    old_state_load = ("    if (nvlfp == NULL || (nvl = READ_ONCE(nvlfp->nvptr)) == NULL)\n"
                      "        return NULL;\n")
    if helper.count(old_state_load) != 1:
        raise ValueError("R580 projection state-load anchor is missing or ambiguous")
    helper = helper.replace(old_state_load,
                            old_state_load + "    nv = NV_STATE_PTR(nvl);\n", 1)
    old_identity = "READ_ONCE(nv_linux_minor_num_table[minor]) != nvl"
    if helper.count(old_identity) != 1:
        raise ValueError("R580 minor-to-device validation anchor is missing or ambiguous")
    helper = helper.replace(
        old_identity,
        "!test_bit(minor, nv_linux_minor_bitmap) ||\n"
        "             READ_ONCE(nvl->minor_num) != minor ||\n"
        "             READ_ONCE(nv->removed)", 1)
    old_private_guard = '''    if (filp == NULL || filp->f_op != &nvidia_fops ||
        hybrid_chrdev_base == 0 || (inode = NV_FILE_INODE(filp)) == NULL)'''
    new_private_guard = '''    if (filp == NULL || filp->f_op != &nvidia_fops ||
        filp->private_data == NULL || hybrid_chrdev_base == 0 ||
        (inode = NV_FILE_INODE(filp)) == NULL)'''
    if helper.count(old_private_guard) != 1:
        raise ValueError("R580 backend file-private guard anchor is missing or ambiguous")
    helper = helper.replace(old_private_guard, new_private_guard, 1)
    return helper


def transform_file_projection_r595(text: str, patch_text: str) -> str:
    """Port R580 file projection to R595's bitmap and device-removal model."""
    include_anchor = '#include "nv-chardev-numbers.h"\n'
    if text.count(include_anchor) != 1:
        raise ValueError("R595 file-projection include anchor is missing or ambiguous")
    added_includes = (
        '#include "hybrid580-file-projection.h"\n'
        "#include <linux/spinlock.h>\n"
        "#include <linux/slab.h>\n")
    required_patch_includes = "".join("+" + line for line in added_includes.splitlines(True))
    if patch_text.count(required_patch_includes) != 1:
        raise ValueError("R580 file-projection include block differs from the expected ABI")
    text = text.replace(include_anchor, include_anchor + added_includes, 1)

    helper = _extract_added_projection_helpers(patch_text)
    get_start = text.find("nv_file_private_t* NV_API_CALL nv_get_file_private(")
    get_end = text.find("\nvoid NV_API_CALL nv_put_file_private(", get_start)
    if get_start < 0 or get_end < 0 or get_end <= get_start:
        raise ValueError("R595 file-private lookup function anchors are missing")
    if text.count("nv_file_private_t* NV_API_CALL nv_get_file_private(") != 1:
        raise ValueError("R595 file-private lookup function is ambiguous")
    replacement = '''nv_file_private_t* NV_API_CALL nv_get_file_private(
    NvS32 fd,
    NvBool ctl,
    void **os_private
)
{
    struct file *filp;
    nv_linux_file_private_t *nvlfp;

    if (os_private == NULL)
        return NULL;
    *os_private = NULL;
    filp = fget(fd);
    if (filp != NULL && filp->f_op != &nvidia_fops)
    {
        struct file *back = hybrid580_open_project_file(filp, ctl);
        fput(filp);
        filp = back;
    }
    nvlfp = hybrid580_open_backend_file(filp, ctl != NV_FALSE);
    if (nvlfp == NULL)
    {
        if (filp != NULL)
            fput(filp);
        return NULL;
    }
    *os_private = filp;
    return &nvlfp->nvfp;
}
'''
    text = text[:get_start] + helper + "\n" + replacement.rstrip() + text[get_end:]

    match_start = text.find("static int nv_match_dev_state(")
    match_end = text.find("\nNvBool NV_API_CALL nv_match_gpu_os_info(", match_start)
    if match_start < 0 or match_end < 0 or match_end <= match_start:
        raise ValueError("R595 file-state matcher anchors are missing")
    if text.count("static int nv_match_dev_state(") != 1:
        raise ValueError("R595 file-state matcher is ambiguous")
    matcher = '''static int nv_match_dev_state(const void *data, struct file *filp, unsigned fd)
{
    nv_linux_file_private_t *nvlfp;
    struct file *back = NULL;
    int matches;

    if (filp != NULL && filp->f_op != &nvidia_fops)
    {
        back = hybrid580_open_project_file(filp, NV_FALSE);
        filp = back;
    }
    nvlfp = hybrid580_open_backend_file(filp, back != NULL ? 0 : -1);
    matches = (nvlfp != NULL && data == READ_ONCE(nvlfp->nvptr));
    if (back != NULL)
        fput(back);
    return matches;
}
'''
    return text[:match_start] + matcher.rstrip() + text[match_end:]


def extract_control_session_api_header(patch_text: str) -> str:
    """Extract the exact control-session header added by the R580 patch."""
    target = "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
    if patch_text.count(target) != 1:
        raise ValueError("R580 control-session header patch anchor is missing or ambiguous")
    lines = patch_text.splitlines(keepends=True)
    index = lines.index(target)
    if index + 1 >= len(lines) or not lines[index + 1].startswith("@@ -0,0 +1,"):
        raise ValueError("R580 control-session header hunk is missing")
    content: list[str] = []
    for line in lines[index + 2:]:
        if line.startswith(("diff --git ", "--- ")):
            break
        if not line.startswith("+"):
            raise ValueError("R580 control-session header contains a non-addition line")
        content.append(line[1:])
    header = "".join(content)
    if (not header.startswith("/* SPDX-License-Identifier: MIT */\n") or
            "hybrid580_open_control_session_create_v1" not in header or
            not header.endswith("#endif\n")):
        raise ValueError("R580 control-session header content is incomplete")
    return header


def extract_gpu_session_api_header(patch_text: str) -> str:
    """Extract the exact GPU-session header added by the R580 patch."""
    target = "+++ b/kernel-open/nvidia/hybrid580-gpu-session.h\n"
    if patch_text.count(target) != 1:
        raise ValueError("R580 GPU-session header patch anchor is missing or ambiguous")
    lines = patch_text.splitlines(keepends=True)
    index = lines.index(target)
    if index + 1 >= len(lines) or not lines[index + 1].startswith("@@ -0,0 +1,"):
        raise ValueError("R580 GPU-session header hunk is missing")
    content: list[str] = []
    for line in lines[index + 2:]:
        if line.startswith(("diff --git ", "--- ")):
            break
        if not line.startswith("+"):
            raise ValueError("R580 GPU-session header contains a non-addition line")
        content.append(line[1:])
    header = "".join(content)
    if (not header.startswith("/* SPDX-License-Identifier: MIT */\n") or
            "hybrid580_open_gpu_session_create_v1" not in header or
            "hybrid580_open_gpu_session_ioctl_v1" not in header or
            not header.endswith("#endif\n")):
        raise ValueError("R580 GPU-session header content is incomplete")
    return header


def transform_gpu_session_r595(nv: str, patch_text: str) -> str:
    """Insert the R580 GPU-session implementation at R595's exact function anchor."""
    include_anchor = '#include "hybrid580-control-session.h"\n'
    include = '#include "hybrid580-gpu-session.h"\n'
    patch_include = "+" + include
    if patch_text.count(patch_include) != 1:
        raise ValueError("R580 GPU-session include differs from the pinned patch")
    if nv.count(include_anchor) != 1 or include in nv:
        raise ValueError("R595 GPU-session include anchor is missing, ambiguous or already adapted")
    nv = nv.replace(include_anchor, include_anchor + include, 1)

    start_marker = "+/* A GPU session owns the actual file-private state created by nvidia_open."
    end_marker = " nv_file_private_t* NV_API_CALL nv_get_file_private("
    if patch_text.count(start_marker) != 1 or patch_text.count(end_marker) != 1:
        raise ValueError("R580 GPU-session implementation hunk is missing or ambiguous")
    start = patch_text.index(start_marker)
    end = patch_text.index(end_marker, start)
    additions = patch_text[start:end].splitlines(keepends=True)
    if any(not line.startswith("+") for line in additions):
        raise ValueError("R580 GPU-session implementation contains unexpected context")
    implementation = "".join(line[1:] for line in additions)
    function_anchor = "nv_file_private_t* NV_API_CALL nv_get_file_private("
    if nv.count(function_anchor) != 1:
        raise ValueError("R595 GPU-session insertion anchor is missing or ambiguous")
    return nv.replace(function_anchor, implementation + "\n" + function_anchor, 1)


def transform_gpu_session_bdf_lookup_r595(
        nv: str, header: str, patch_text: str) -> tuple[str, str]:
    """Add the exact BDF-to-minor lookup after the R595 GPU-session factory."""
    implementation_start = "+int hybrid580_open_gpu_session_create_by_bdf_v1(\n"
    implementation_end = " nv_file_private_t* NV_API_CALL nv_get_file_private("
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-gpu-session.h\n"
    if patch_text.count(header_marker) != 1:
        raise ValueError("R580 GPU-session BDF header file marker is missing or ambiguous")
    source_patch = patch_text[:patch_text.index(header_marker)]
    if (source_patch.count(implementation_start) != 1 or
            source_patch.count(implementation_end) != 1):
        raise ValueError("R580 GPU-session BDF implementation hunk is missing or ambiguous")
    start = source_patch.index(implementation_start)
    end = source_patch.index(implementation_end, start)
    additions = source_patch[start:end].splitlines(keepends=True)
    if any(not line.startswith("+") for line in additions):
        raise ValueError("R580 GPU-session BDF implementation contains unexpected context")
    implementation = "".join(line[1:] for line in additions)
    nv_anchor = "EXPORT_SYMBOL(hybrid580_open_gpu_session_create_v1);\n"
    if nv.count(nv_anchor) != 1 or "create_by_bdf_v1" in nv:
        raise ValueError("R595 GPU-session BDF insertion anchor is missing or already adapted")
    nv = nv.replace(nv_anchor, nv_anchor + "\n" + implementation.rstrip() + "\n", 1)

    declaration_start = "+int hybrid580_open_gpu_session_create_by_bdf_v1(\n"
    declaration_end = " void hybrid580_open_gpu_session_get_v1("
    header_patch = patch_text[patch_text.index(header_marker):]
    if (header_patch.count(declaration_start) != 1 or
            header_patch.count(declaration_end) != 1):
        raise ValueError("R580 GPU-session BDF declaration hunk is missing or ambiguous")
    start = header_patch.index(declaration_start)
    end = header_patch.index(declaration_end, start)
    declaration_lines = header_patch[start:end].splitlines(keepends=True)
    if any(not line.startswith("+") for line in declaration_lines):
        raise ValueError("R580 GPU-session BDF declaration contains unexpected context")
    declaration = "".join(line[1:] for line in declaration_lines)
    header_anchor = "void hybrid580_open_gpu_session_get_v1("
    if header.count(header_anchor) != 1 or "create_by_bdf_v1" in header:
        raise ValueError("R595 GPU-session BDF header anchor is missing or already adapted")
    header = header.replace(header_anchor, declaration + header_anchor, 1)
    return nv, header


def transform_gpu_register_control_r595(
        nv: str, header: str, patch_text: str) -> tuple[str, str]:
    """Port the pinned REGISTER_FD ownership bridge at exact R595 anchors."""
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-gpu-session.h\n"
    api_name = "hybrid580_open_gpu_session_register_control_v1"
    if patch_text.count(header_marker) != 1:
        raise ValueError("R580 REGISTER_FD header marker is missing or ambiguous")
    source_patch = patch_text[:patch_text.index(header_marker)]
    implementation_start = f"+int {api_name}(\n"
    if source_patch.count(implementation_start) != 1:
        raise ValueError("R580 REGISTER_FD implementation is missing or ambiguous")
    start = source_patch.index(implementation_start)
    additions: list[str] = []
    for line in source_patch[start:].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        additions.append(line)
    implementation = "".join(line[1:] for line in additions)
    export = f"EXPORT_SYMBOL({api_name});"
    if api_name in nv:
        raise ValueError("R595 REGISTER_FD implementation is already adapted")
    if (implementation.count(export) != 1 or
            "get_file(control->file)" not in implementation or
            "rm_acquire_api_lock(sp)" not in implementation or
            "cmpxchg(&gpu_nvlfp->nvfp.ctl_nvfp, NULL," not in implementation or
            "gpu_nvlfp->nvfp.ctl_nvfp_priv = control_file" not in implementation or
            "fput(control_file)" not in implementation):
        raise ValueError("R580 REGISTER_FD ownership or publication contract drifted")
    nv_anchor = "EXPORT_SYMBOL(hybrid580_open_gpu_session_ioctl_v1);\n"
    if nv.count(nv_anchor) != 1:
        raise ValueError("R595 REGISTER_FD source anchor is missing or ambiguous")
    nv = nv.replace(nv_anchor, nv_anchor + "\n" + implementation.rstrip() + "\n", 1)

    header_patch = patch_text[patch_text.index(header_marker):]
    forward = "+struct hybrid580_control_session;\n"
    declaration_start = f"+int {api_name}(\n"
    declaration_end = " int hybrid580_open_gpu_inventory_v1("
    if (header_patch.count(forward) != 1 or
            header_patch.count(declaration_start) != 1 or
            header_patch.count(declaration_end) != 1):
        raise ValueError("R580 REGISTER_FD header additions are missing or ambiguous")
    start = header_patch.index(declaration_start)
    end = header_patch.index(declaration_end, start)
    declaration_lines = header_patch[start:end].splitlines(keepends=True)
    if any(not line.startswith("+") for line in declaration_lines):
        raise ValueError("R580 REGISTER_FD declaration contains unexpected context")
    declaration = "".join(line[1:] for line in declaration_lines)

    forward_anchor = "struct hybrid580_gpu_session;\n"
    if (header.count(forward_anchor) != 1 or
            "struct hybrid580_control_session;" in header or api_name in header):
        raise ValueError("R595 REGISTER_FD header forward declaration is missing or present")
    header = header.replace(forward_anchor,
                            forward_anchor + "struct hybrid580_control_session;\n", 1)
    prototype_anchor = (
        "long hybrid580_open_gpu_session_ioctl_v1(\n"
        "    struct hybrid580_gpu_session *session, unsigned int command,\n"
        "    unsigned long argument);\n")
    if header.count(prototype_anchor) != 1:
        raise ValueError("R595 REGISTER_FD prototype anchor is missing or ambiguous")
    header = header.replace(prototype_anchor,
                            prototype_anchor + "\n" + declaration, 1)
    return nv, header


def transform_gpu_inventory_r595(
        nv: str, gpu_header: str, catalog_header: str,
        patch_text: str) -> tuple[str, str]:
    """Port the R580 inventory API while preserving the pinned shared record ABI."""
    source_file_marker = "+++ b/kernel-open/nvidia/nv.c\n"
    gpu_header_marker = "+++ b/kernel-open/nvidia/hybrid580-gpu-session.h\n"
    if (patch_text.count(source_file_marker) != 1 or
            patch_text.count(gpu_header_marker) != 1):
        raise ValueError("R580 GPU-inventory patch file markers are missing or ambiguous")
    source_patch = patch_text[patch_text.index(source_file_marker):
                              patch_text.index(gpu_header_marker)]
    start_marker = "+/* Snapshot the initialized PCI inventory while the backend minor table is"
    end_marker = " nv_file_private_t* NV_API_CALL nv_get_file_private("
    if source_patch.count(start_marker) != 1 or source_patch.count(end_marker) != 1:
        raise ValueError("R580 GPU-inventory implementation hunk is missing or ambiguous")
    start = source_patch.index(start_marker)
    end = source_patch.index(end_marker, start)
    additions = source_patch[start:end].splitlines(keepends=True)
    if any(not line.startswith("+") for line in additions):
        raise ValueError("R580 GPU-inventory implementation contains unexpected context")
    implementation = "".join(line[1:] for line in additions)
    nv_anchor = "EXPORT_SYMBOL(hybrid580_open_gpu_session_create_by_bdf_v1);\n"
    if nv.count(nv_anchor) != 1 or "hybrid580_open_gpu_inventory_v1" in nv:
        raise ValueError("R595 GPU-inventory insertion anchor is missing or already adapted")
    nv = nv.replace(nv_anchor, nv_anchor + "\n" + implementation.rstrip() + "\n", 1)

    required_catalog = (
        "#define HYBRID580_GPU_MAX_BACKEND_DEVICES 248U",
        "struct hybrid580_gpu_backend_record_v1 {",
        "char bdf[HYBRID580_GPU_BDF_SIZE];",
    )
    if any(token not in catalog_header for token in required_catalog):
        raise ValueError("shared GPU catalog ABI header is missing required R595 record fields")

    header_patch = patch_text[patch_text.index(gpu_header_marker):]
    include = '#include "hybrid580-gpu-catalog.h"\n'
    if header_patch.count("+" + include) != 1:
        raise ValueError("R580 GPU-inventory shared-header include is missing or ambiguous")
    include_anchor = "#include <nvtypes.h>\n"
    if gpu_header.count(include_anchor) != 1 or include in gpu_header:
        raise ValueError("R595 GPU-session catalog include anchor is missing or already adapted")
    gpu_header = gpu_header.replace(include_anchor, include_anchor + include, 1)

    declaration_start = "+int hybrid580_open_gpu_inventory_v1(\n"
    declaration_end = " \n #endif\n"
    if (header_patch.count(declaration_start) != 1 or
            header_patch.count(declaration_end) != 1):
        raise ValueError("R580 GPU-inventory API declaration hunk is missing or ambiguous")
    start = header_patch.index(declaration_start)
    end = header_patch.index(declaration_end, start)
    declaration_lines = header_patch[start:end].splitlines(keepends=True)
    if any(not line.startswith("+") for line in declaration_lines):
        raise ValueError("R580 GPU-inventory API declaration contains unexpected context")
    declaration = "".join(line[1:] for line in declaration_lines)
    header_anchor = "\n#endif\n"
    if gpu_header.count(header_anchor) != 1 or "hybrid580_open_gpu_inventory_v1" in gpu_header:
        raise ValueError("R595 GPU-inventory API insertion anchor is missing or already adapted")
    gpu_header = gpu_header.replace(header_anchor, "\n" + declaration + header_anchor, 1)
    return nv, gpu_header


def transform_gpu_card_info_r595(
        nv: str, gpu_header: str, patch_text: str) -> tuple[str, str]:
    """Port the card-info export after R595's inventory helper implementation."""
    source_marker = "+++ b/kernel-open/nvidia/nv.c\n"
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-gpu-session.h\n"
    if (patch_text.count(source_marker) != 1 or
            patch_text.count(header_marker) != 1):
        raise ValueError("R580 card-info patch file markers are missing or ambiguous")
    source_patch = patch_text[patch_text.index(source_marker):
                              patch_text.index(header_marker)]
    function_start = "+int hybrid580_open_gpu_card_info_v1(\n"
    if source_patch.count(function_start) != 1:
        raise ValueError("R580 card-info implementation hunk is missing or ambiguous")
    added_lines: list[str] = []
    for line in source_patch[source_patch.index(function_start):].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        added_lines.append(line)
    implementation = "".join(line[1:] for line in added_lines)
    if ("EXPORT_SYMBOL(hybrid580_open_gpu_card_info_v1);" not in implementation or
            "nvidia_read_card_info(typed_records, capacity)" not in implementation):
        raise ValueError("R580 card-info implementation is incomplete")
    if "hybrid580_open_gpu_card_info_v1" in nv:
        raise ValueError("R595 card-info implementation is already present")

    read_start = "static int nvidia_read_card_info(nv_ioctl_card_info_t *ci, size_t num_entries)"
    read_end = "\nstatic NV_STATUS nv_validate_ioctls(unsigned int cmd)"
    start = nv.find(read_start)
    end = nv.find(read_end, start + len(read_start)) if start >= 0 else -1
    if (start < 0 or end < 0 or nv.count(read_start) != 1 or
            nv.count(read_end) != 1 or end <= start):
        raise ValueError("R595 card-info reader insertion boundaries are missing or ambiguous")
    read_function = nv[start:end]
    expected_tail = "    UNLOCK_NV_LINUX_DEVICES();\n    return rc;\n}\n"
    if not read_function.endswith(expected_tail):
        raise ValueError("R595 card-info reader body differs from the pinned source")
    nv = nv[:end] + "\n" + implementation.rstrip() + "\n" + nv[end:]

    header_patch = patch_text[patch_text.index(header_marker):]
    forward_decl = "struct nv_ioctl_card_info;\n"
    patch_forward_decl = "+" + forward_decl
    forward_anchor = "struct hybrid580_gpu_session;\n"
    if (header_patch.count(patch_forward_decl) != 1 or
            gpu_header.count(forward_anchor) != 1 or
            "struct nv_ioctl_card_info;" in gpu_header):
        raise ValueError("R595 GPU-session card-info forward declaration anchor is missing or ambiguous")
    gpu_header = gpu_header.replace(forward_anchor,
                                    forward_anchor + forward_decl, 1)

    declaration_marker = "+int hybrid580_open_gpu_card_info_v1(\n"
    if header_patch.count(declaration_marker) != 1:
        raise ValueError("R580 GPU card-info API declaration is missing or ambiguous")
    header_additions: list[str] = []
    for line in header_patch[header_patch.index(declaration_marker):].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        header_additions.append(line)
    declaration = "".join(line[1:] for line in header_additions)
    if ("hybrid580_open_gpu_card_info_v1" in gpu_header or
            gpu_header.count("#endif\n") != 1):
        raise ValueError("R595 GPU-session card-info header anchor is missing or already adapted")
    gpu_header = gpu_header.replace("#endif\n", declaration + "#endif\n", 1)
    return nv, gpu_header


def transform_control_session_r595(nv: str, kbuild: str,
                                   patch_text: str) -> tuple[str, str]:
    """Adapt the R580 root-control session addition to exact R595 anchors."""
    added_includes = (
        '#include "hybrid580-control-session.h"\n'
        "#include <linux/kref.h>\n"
        "#include <linux/mutex.h>\n"
        "#include <linux/mount.h>\n"
        "#include <nvos.h>\n"
        "#include <nv_escape.h>\n")
    required_patch_includes = "".join("+" + line for line in added_includes.splitlines(True))
    if patch_text.count(required_patch_includes) != 1:
        raise ValueError("R580 control-session include block differs from pinned patch")
    include_anchor = '#include "hybrid580-file-projection.h"\n'
    if nv.count(include_anchor) != 1:
        raise ValueError("R595 control-session include anchor is missing or ambiguous")
    nv = nv.replace(include_anchor, include_anchor + added_includes, 1)

    null_anchor = '''    nv_linux_file_private_t *nvlfp = NV_GET_LINUX_FILE_PRIVATE(file);

    nv_printf(NV_DBG_INFO,
'''
    null_replacement = '''    nv_linux_file_private_t *nvlfp = NV_GET_LINUX_FILE_PRIVATE(file);

    /* Pseudo files are FMODE_OPENED before vendor open can fail. */
    if (nvlfp == NULL)
        return 0;

    nv_printf(NV_DBG_INFO,
'''
    if nv.count(null_anchor) != 1:
        raise ValueError("R595 nvidia_close private-data anchor is missing or ambiguous")
    nv = nv.replace(null_anchor, null_replacement, 1)

    start_marker = "+/* An unpublished control file has ordinary vendor private storage."
    end_marker = " nv_file_private_t* NV_API_CALL nv_get_file_private("
    if patch_text.count(start_marker) != 1 or patch_text.count(end_marker) != 1:
        raise ValueError("R580 control-session implementation hunk is missing or ambiguous")
    start = patch_text.index(start_marker)
    end = patch_text.index(end_marker, start)
    additions = patch_text[start:end].splitlines(keepends=True)
    if any(not line.startswith("+") for line in additions):
        raise ValueError("R580 control-session implementation has unexpected context")
    implementation = "".join(line[1:] for line in additions)
    function_anchor = "nv_file_private_t* NV_API_CALL nv_get_file_private("
    if nv.count(function_anchor) != 1:
        raise ValueError("R595 control-session insertion anchor is missing or ambiguous")
    nv = nv.replace(function_anchor, implementation + "\n" + function_anchor, 1)

    kbuild_additions = (
        "NVIDIA_CFLAGS += -I$(src)/../src/common/sdk/nvidia/inc\n"
        "NVIDIA_CFLAGS += -I$(src)/../src/common/inc\n"
        "NVIDIA_CFLAGS += -I$(src)/../src/common/inc/swref\n"
        "NVIDIA_CFLAGS += -I$(src)/../src/nvidia/arch/nvalloc/unix/include\n")
    if any(line in kbuild for line in kbuild_additions.splitlines(True)):
        raise ValueError("R595 control-session include directories already exist")
    kbuild_anchor = "NVIDIA_CFLAGS += -include $(src)/nvidia/hybrid580-open-exports.h\n"
    if kbuild.count(kbuild_anchor) != 1:
        raise ValueError("R595 private export-header Kbuild anchor is missing or ambiguous")
    for relative in ("../src/common/sdk/nvidia/inc/nvos.h",
                     "../src/common/inc", "../src/common/inc/swref",
                     "../src/nvidia/arch/nvalloc/unix/include/nv_escape.h"):
        if not (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02/kernel-open" / relative).exists():
            raise ValueError("R595 control-session include dependency is missing: " + relative)
    kbuild = kbuild.replace(kbuild_anchor, kbuild_anchor + kbuild_additions, 1)
    return nv, kbuild


def transform_control_attach_r595(
        nv: str, control_header: str, patch_text: str) -> tuple[str, str]:
    """Port the control-file GPU attach API to R595's reset-aware RM calls."""
    source_marker = "+++ b/kernel-open/nvidia/nv.c\n"
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
    if (patch_text.count(source_marker) != 1 or
            patch_text.count(header_marker) != 1):
        raise ValueError("R580 control-attach patch file markers are missing or ambiguous")
    source_patch = patch_text[patch_text.index(source_marker):
                              patch_text.index(header_marker)]

    declaration = (
        "static int hybrid580_attach_gpus_to_file("
        "nv_linux_file_private_t *, nvidia_stack_t *, const NvU32 *, size_t);\n")
    if source_patch.count("+" + declaration) != 1:
        raise ValueError("R580 control-attach forward declaration differs from the pinned patch")
    declaration_anchor = (
        "static long          nvidia_unlocked_ioctl "
        "(struct file *, unsigned int, unsigned long);\n")
    if nv.count(declaration_anchor) != 1 or declaration.rstrip() in nv:
        raise ValueError("R595 unlocked-ioctl declaration anchor is missing or already adapted")
    nv = nv.replace(declaration_anchor,
                    declaration_anchor + declaration, 1)

    case_start = "        case NV_ESC_ATTACH_GPUS_TO_FD:\n        {\n"
    case_end = "\n        case NV_ESC_CHECK_VERSION_STR:\n"
    start = nv.find(case_start)
    end = nv.find(case_end, start + len(case_start)) if start >= 0 else -1
    if (start < 0 or end < 0 or nv.count(case_start) != 1 or
            nv.count(case_end) != 1 or end <= start):
        raise ValueError("R595 attach-ioctl case boundaries are missing or ambiguous")
    attach_case = nv[start:end]
    required_ioctl_behavior = (
        "NV_CTL_DEVICE_ONLY(nv);",
        "nvidia_dev_get(nvlfp->attached_gpus[i], sp, NV_FALSE /* reset_aware */)",
        "nvidia_dev_put(nvlfp->attached_gpus[i], sp, NV_FALSE /* reset_aware */)",
        "nvlfp->num_attached_gpus = 0;")
    if any(attach_case.count(token) != 1 for token in required_ioctl_behavior):
        raise ValueError("R595 attach-ioctl behavior no longer matches the pinned reset-aware path")
    replacement_case = '''        case NV_ESC_ATTACH_GPUS_TO_FD:
        {
            NV_CTL_DEVICE_ONLY(nv);
            status = hybrid580_attach_gpus_to_file(nvlfp, sp, arg_copy, arg_size);
            break;
        }
'''
    nv = nv[:start] + replacement_case.rstrip("\n") + nv[end:]

    helper_start = "+/* Kernel-owned equivalent of the NV_ESC_ATTACH_GPUS_TO_FD wrapper path."
    helper_end = " struct hybrid580_control_session {"
    if (source_patch.count(helper_start) != 1 or
            source_patch.count(helper_end) != 1):
        raise ValueError("R580 kernel-owned attach helper hunk is missing or ambiguous")
    start = source_patch.index(helper_start)
    end = source_patch.index(helper_end, start)
    helper_lines = source_patch[start:end].splitlines(keepends=True)
    if any(not line.startswith("+") for line in helper_lines):
        raise ValueError("R580 kernel-owned attach helper contains unexpected patch context")
    helper = "".join(line[1:] for line in helper_lines)
    old_get = "nvidia_dev_get(nvlfp->attached_gpus[i], sp)"
    old_put = "nvidia_dev_put(nvlfp->attached_gpus[i], sp)"
    if helper.count(old_get) != 1 or helper.count(old_put) != 1:
        raise ValueError("R580 attach helper device-reference calls are missing or ambiguous")
    helper = helper.replace(
        old_get,
        "nvidia_dev_get(nvlfp->attached_gpus[i], sp, NV_FALSE /* reset_aware */)", 1)
    helper = helper.replace(
        old_put,
        "nvidia_dev_put(nvlfp->attached_gpus[i], sp, NV_FALSE /* reset_aware */)", 1)
    comment_anchor = (
        "/* An unpublished control file has ordinary vendor private storage."
        " The owner\n"
        " * holds a session reference throughout every call and mapping publication.\n"
        " * This mutex serializes calls only; it never covers a final fput(). */\n")
    if (nv.count(comment_anchor) != 1 or
            "static int hybrid580_attach_gpus_to_file(\n" in nv):
        raise ValueError("R595 control-session comment anchor is missing or helper already exists")
    nv = nv.replace(comment_anchor, helper + "\n" + comment_anchor, 1)

    attach_start = "+int hybrid580_open_control_session_attach_v1(\n"
    if source_patch.count(attach_start) != 1:
        raise ValueError("R580 control-session attach API hunk is missing or ambiguous")
    start = source_patch.index(attach_start)
    attach_lines: list[str] = []
    for line in source_patch[start:].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        attach_lines.append(line)
    attach_api = "".join(line[1:] for line in attach_lines)
    export_anchor = "EXPORT_SYMBOL(hybrid580_open_control_session_file_v1);\n"
    if nv.count(export_anchor) != 1 or "hybrid580_open_control_session_attach_v1" in nv:
        raise ValueError("R595 control-session file export anchor is missing or already adapted")
    nv = nv.replace(export_anchor, export_anchor + "\n" + attach_api.rstrip() + "\n", 1)

    header_addition = (
        "int hybrid580_open_control_session_attach_v1(\n"
        "    struct hybrid580_control_session *, const NvU32 *gpu_ids, NvU32 count);\n")
    patch_header_addition = (
        "+int hybrid580_open_control_session_attach_v1(\n"
        "+    struct hybrid580_control_session *, const NvU32 *gpu_ids, NvU32 count);\n")
    if (patch_text.count(patch_header_addition) != 1 or
            control_header.count("#endif\n") != 1 or
            "hybrid580_open_control_session_attach_v1" in control_header):
        raise ValueError("R580 control-session attach header declaration is missing or ambiguous")
    header_contract = (
        "/* Process-context call; the caller retains a session reference for the\n"
        " * duration. gpu_ids points to kernel-owned memory valid for this call.\n"
        " * Attach is serialized with control invokes by the session mutex. */\n")
    control_header = control_header.replace(
        "#endif\n", header_contract + header_addition + "#endif\n", 1)
    return nv, control_header


def transform_gpu_id_info_r595(
        nv: str, control_header: str, patch_text: str) -> tuple[str, str]:
    """Add the kernel-owned GPU-ID control bridge at exact R595 anchors."""
    source_marker = "+++ b/kernel-open/nvidia/nv.c\n"
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
    if (patch_text.count(source_marker) != 1 or
            patch_text.count(header_marker) != 1):
        raise ValueError("R580 GPU-ID-info patch file markers are missing or ambiguous")
    source_patch = patch_text[patch_text.index(source_marker):
                              patch_text.index(header_marker)]

    rmapi_include = "#include <nv-kernel-rmapi-ops.h>\n"
    patch_include = "+" + rmapi_include
    include_anchor = "#include <nv_escape.h>\n"
    if (source_patch.count(patch_include) != 1 or nv.count(include_anchor) != 1 or
            rmapi_include in nv):
        raise ValueError("R595 kernel RMAPI include anchor is missing or already adapted")
    nv = nv.replace(include_anchor, include_anchor + rmapi_include, 1)

    function_start = "+NV_STATUS hybrid580_open_control_session_gpu_id_info_v1(\n"
    if source_patch.count(function_start) != 1:
        raise ValueError("R580 GPU-ID-info implementation hunk is missing or ambiguous")
    additions: list[str] = []
    for line in source_patch[source_patch.index(function_start):].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        additions.append(line)
    implementation = "".join(line[1:] for line in additions)
    required = (
        "NV04_CONTROL",
        "rm_kernel_rmapi_op(sp, &ops);",
        "NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2",
        "EXPORT_SYMBOL(hybrid580_open_control_session_gpu_id_info_v1);")
    if any(token not in implementation for token in required):
        raise ValueError("R580 GPU-ID-info bridge implementation is incomplete")
    if "hybrid580_open_control_session_gpu_id_info_v1" in nv:
        raise ValueError("R595 GPU-ID-info bridge is already present")
    attach_export = "EXPORT_SYMBOL(hybrid580_open_control_session_attach_v1);\n"
    if nv.count(attach_export) != 1:
        raise ValueError("R595 control-session attach export anchor is missing or ambiguous")
    nv = nv.replace(attach_export, attach_export + "\n" + implementation.rstrip() + "\n", 1)

    old_fs_include = "#include <linux/fs.h>\n"
    ctrl_include = "#include <ctrl/ctrl0000/ctrl0000gpu.h>\n"
    if (control_header.count(old_fs_include) != 1 or ctrl_include in control_header or
            control_header.count("struct hybrid580_control_session;\n") != 1 or
            "struct file;\n" in control_header):
        raise ValueError("R595 control-session header include set is missing or already adapted")
    control_header = control_header.replace(old_fs_include, ctrl_include, 1)
    control_header = control_header.replace(
        "struct hybrid580_control_session;\n",
        "struct file;\nstruct hybrid580_control_session;\n", 1)

    header_start = "+/* One command-specific kernel-buffer bridge. The GPU ID is backend-local;\n"
    header_marker_text = "+NV_STATUS hybrid580_open_control_session_gpu_id_info_v1(\n"
    header_patch = patch_text[patch_text.index(header_marker):]
    if (header_patch.count(header_start) != 1 or
            header_patch.count(header_marker_text) != 1):
        raise ValueError("R580 GPU-ID-info header declaration hunk is missing or ambiguous")
    start = header_patch.index(header_start)
    header_additions: list[str] = []
    for line in header_patch[start:].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        header_additions.append(line)
    declaration = "".join(line[1:] for line in header_additions)
    if ("hybrid580_open_control_session_gpu_id_info_v1" in control_header or
            control_header.count("#endif\n") != 1):
        raise ValueError("R595 control-session GPU-ID-info API anchor is missing or already adapted")
    control_header = control_header.replace("#endif\n", declaration + "#endif\n", 1)
    return nv, control_header


def transform_control_query_r595(
        nv: str, control_header: str, patch_text: str) -> tuple[str, str, str]:
    """Port one fixed-size kernel-owned NV04_CONTROL query API by exact anchors."""
    source_marker = "+++ b/kernel-open/nvidia/nv.c\n"
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
    if (patch_text.count(source_marker) != 1 or
            patch_text.count(header_marker) != 1):
        raise ValueError("R580 control-query patch file markers are missing or ambiguous")
    source_patch = patch_text[patch_text.index(source_marker):
                              patch_text.index(header_marker)]
    api_pattern = re.compile(
        r"^\+NV_STATUS (hybrid580_open_control_session_[A-Za-z0-9_]+_v1)\(\n",
        flags=re.MULTILINE)
    matches = list(api_pattern.finditer(source_patch))
    if len(matches) != 1:
        raise ValueError("R580 control-query implementation API is missing or ambiguous")
    api_name = matches[0].group(1)
    source_additions: list[str] = []
    for line in source_patch[matches[0].start():].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        source_additions.append(line)
    implementation = "".join(line[1:] for line in source_additions)
    if (f"EXPORT_SYMBOL({api_name});" not in implementation or
            "NV04_CONTROL" not in implementation or
            "rm_kernel_rmapi_op(sp, &ops);" not in implementation):
        raise ValueError("R580 fixed-size control-query implementation is incomplete")
    if api_name in nv:
        raise ValueError("R595 control-query implementation is already present: " + api_name)
    create_anchor = "int hybrid580_open_control_session_create_v1("
    if nv.count(create_anchor) != 1:
        raise ValueError("R595 control-session implementation anchor is missing or ambiguous")
    nv = nv.replace(create_anchor, implementation.rstrip() + "\n\n" + create_anchor, 1)

    header_patch = patch_text[patch_text.index(header_marker):]
    declaration_marker = f"+NV_STATUS {api_name}(\n"
    if header_patch.count(declaration_marker) != 1:
        raise ValueError("R580 control-query header declaration is missing or ambiguous")
    header_start = header_patch.index(declaration_marker)
    if api_name.endswith("device_ids_v1"):
        comment_marker = "+/* Fixed output-only device-instance bitmask used to construct the frontend\n"
        if header_patch.count(comment_marker) != 1:
            raise ValueError("R580 device-ID API contract comment is missing or ambiguous")
        header_start = header_patch.index(comment_marker)
    header_additions: list[str] = []
    for line in header_patch[header_start:].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        header_additions.append(line)
    declaration = "".join(line[1:] for line in header_additions)
    if (api_name in control_header or control_header.count("#endif\n") != 1):
        raise ValueError("R595 control-session query header anchor is missing or already adapted")
    control_header = control_header.replace("#endif\n", declaration + "#endif\n", 1)
    return nv, control_header, api_name


def transform_device_object_r595(
        nv: str, control_header: str, patch_text: str) -> tuple[str, str]:
    """Add the typed NV01_DEVICE_0 allocate/free bridge at exact R595 anchors."""
    source_marker = "+++ b/kernel-open/nvidia/nv.c\n"
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
    if (patch_text.count(source_marker) != 1 or
            patch_text.count(header_marker) != 1):
        raise ValueError("R580 device-object patch file markers are missing or ambiguous")
    source_patch = patch_text[patch_text.index(source_marker):
                              patch_text.index(header_marker)]
    function_start = "+NV_STATUS hybrid580_open_control_session_device_alloc_v1(\n"
    if source_patch.count(function_start) != 1:
        raise ValueError("R580 device-object implementations are missing or ambiguous")
    additions: list[str] = []
    for line in source_patch[source_patch.index(function_start):].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        additions.append(line)
    implementation = "".join(line[1:] for line in additions)
    required = (
        "NV04_ALLOC",
        "NV01_DEVICE_0",
        "NV01_FREE",
        "NVOS64_PARAMETERS",
        "rm_kernel_rmapi_op(sp, &ops);",
        "EXPORT_SYMBOL(hybrid580_open_control_session_device_alloc_v1);",
        "EXPORT_SYMBOL(hybrid580_open_control_session_device_free_v1);")
    if any(token not in implementation for token in required):
        raise ValueError("R580 NV01_DEVICE_0 bridge implementation is incomplete")
    if "hybrid580_open_control_session_device_alloc_v1" in nv:
        raise ValueError("R595 NV01_DEVICE_0 allocation bridge is already present")
    create_anchor = "int hybrid580_open_control_session_create_v1("
    if nv.count(create_anchor) != 1:
        raise ValueError("R595 control-session implementation anchor is missing or ambiguous")
    nv = nv.replace(create_anchor, implementation.rstrip() + "\n\n" + create_anchor, 1)

    class_include = "#include <class/cl0080.h>\n"
    include_anchor = "#include <ctrl/ctrl0000/ctrl0000gpu.h>\n"
    if (control_header.count(include_anchor) != 1 or class_include in control_header):
        raise ValueError("R595 device-class header include anchor is missing or already adapted")
    control_header = control_header.replace(include_anchor,
                                            include_anchor + class_include, 1)

    header_patch = patch_text[patch_text.index(header_marker):]
    api_comment = "+/* Narrow NV01_DEVICE_0 lifecycle bridge. The object handle is supplied by\n"
    if header_patch.count(api_comment) != 1:
        raise ValueError("R580 NV01_DEVICE_0 API contract comment is missing or ambiguous")
    header_additions: list[str] = []
    for line in header_patch[header_patch.index(api_comment):].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        header_additions.append(line)
    declaration = "".join(line[1:] for line in header_additions)
    for api_name in ("hybrid580_open_control_session_device_alloc_v1",
                     "hybrid580_open_control_session_device_free_v1"):
        if api_name in control_header or declaration.count(api_name) != 1:
            raise ValueError("R595 NV01_DEVICE_0 API header is missing or already adapted")
    if control_header.count("#endif\n") != 1:
        raise ValueError("R595 control-session header terminator is missing or ambiguous")
    control_header = control_header.replace("#endif\n", declaration + "#endif\n", 1)
    return nv, control_header


def transform_control_session_additions_r595(
        nv: str, control_header: str, patch_text: str, *,
        dispatch_markers: tuple[str, ...] | None = None
        ) -> tuple[str, str, list[str]]:
    """Port additive control-session methods without accepting patch offsets."""
    source_marker = "+++ b/kernel-open/nvidia/nv.c\n"
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
    if (patch_text.count(source_marker) != 1 or
            patch_text.count(header_marker) != 1):
        raise ValueError("R580 control-session addition patch markers are missing or ambiguous")
    source_patch = patch_text[patch_text.index(source_marker):
                              patch_text.index(header_marker)]
    api_pattern = re.compile(
        r"^\+(?:NV_STATUS|int) "
        r"(hybrid580_open_control_session_[A-Za-z0-9_]+_v1)\(\n",
        flags=re.MULTILINE)
    matches = list(api_pattern.finditer(source_patch))
    if not matches:
        raise ValueError("R580 additive control-session implementations are missing")
    source_additions: list[str] = []
    for line in source_patch[matches[0].start():].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        source_additions.append(line)
    implementation = "".join(line[1:] for line in source_additions)
    api_exports = re.findall(
        r"EXPORT_SYMBOL\((hybrid580_open_control_session_[A-Za-z0-9_]+_v1)\);",
        implementation)
    if (not api_exports or len(api_exports) != len(set(api_exports)) or
            any(implementation.count(f"EXPORT_SYMBOL({name});") != 1
                for name in api_exports)):
        raise ValueError("R580 control-session additions have missing or duplicate exports")
    if any(name in nv for name in api_exports):
        raise ValueError("R595 control-session implementation is already present")
    if dispatch_markers is None:
        if "rm_kernel_rmapi_op(sp, &ops);" not in implementation:
            raise ValueError("R580 control-session additions do not use the pinned RMAPI helper")
    elif (not dispatch_markers or
          any(marker not in implementation for marker in dispatch_markers)):
        raise ValueError("R580 control-session additions omit a required dispatch path")
    create_anchor = "int hybrid580_open_control_session_create_v1("
    if nv.count(create_anchor) != 1:
        raise ValueError("R595 control-session source anchor is missing or ambiguous")
    nv = nv.replace(create_anchor, implementation.rstrip() + "\n\n" + create_anchor, 1)

    header_patch = patch_text[patch_text.index(header_marker):]
    added_lines = [line for line in header_patch.splitlines(keepends=True)
                   if line.startswith("+") and not line.startswith("+++")]
    if not added_lines:
        raise ValueError("R580 control-session header additions are missing")
    include_additions = [line[1:] for line in added_lines
                         if line.startswith("+#include ")]
    declaration_lines = [line[1:] for line in added_lines
                         if not line.startswith("+#include ")]
    missing_includes: list[str] = []
    for include in include_additions:
        if include not in control_header and include not in missing_includes:
            missing_includes.append(include)
    if missing_includes:
        forward_anchor = "struct hybrid580_control_session;\n"
        if control_header.count(forward_anchor) != 1:
            raise ValueError("R595 control-session type forward declaration is missing or ambiguous")
        control_header = control_header.replace(
            forward_anchor,
            "".join(missing_includes) + "\n" + forward_anchor, 1)

    declarations = "".join(declaration_lines)
    if any(name not in declarations for name in api_exports):
        raise ValueError("R580 control-session header omits an exported API declaration")
    if any(name in control_header for name in api_exports):
        raise ValueError("R595 control-session header API is already present")
    if control_header.count("#endif\n") != 1:
        raise ValueError("R595 control-session header terminator is missing or ambiguous")
    control_header = control_header.replace("#endif\n", declarations + "#endif\n", 1)
    return nv, control_header, api_exports


def transform_context_share_r595(
        nv: str, control_header: str, patch_text: str) -> tuple[str, str, list[str]]:
    """Adapt context-share validation to R595's documented RM contract.

    R595 uses a null VASpace handle for default/legacy context shares and treats
    ``subctxId`` as output unless the SUBCONTEXT_SPECIFIED mode is requested.
    Preserve the explicit-ID high-bit check, but do not reject those valid
    R595 input/output forms before the RM allocation call.
    """
    old_guard = (
        "+        h_context_share == h_group || params->hVASpace == 0 ||\n"
        "+        (params->flags & ~0x3U) != 0 ||\n"
        "+        (params->flags == NV_CTXSHARE_ALLOCATION_FLAGS_SUBCONTEXT_SPECIFIED ?\n"
        "+            (params->subctxId & 0x80000000U) != 0 : params->subctxId != 0))")
    new_guard = (
        "+        h_context_share == h_group ||\n"
        "+        (params->flags & ~0x3U) != 0 ||\n"
        "+        (params->flags == NV_CTXSHARE_ALLOCATION_FLAGS_SUBCONTEXT_SPECIFIED &&\n"
        "+         (params->subctxId & 0x80000000U) != 0))")
    if patch_text.count(old_guard) != 1:
        raise ValueError("R580 context-share validation anchor is missing or ambiguous")
    adapted = patch_text.replace(old_guard, new_guard, 1)
    return transform_control_session_additions_r595(nv, control_header, adapted)


def transform_channel_allocation_r595(
        nv: str, control_header: str, patch_text: str) -> tuple[str, str, list[str]]:
    """Whitelist the pinned R595 Volta and Blackwell GPFIFO channel classes."""
    old_class_guard = "if (class_id != BLACKWELL_CHANNEL_GPFIFO_A)"
    new_class_guard = (
        "if ((class_id != VOLTA_CHANNEL_GPFIFO_A) &&\n+"
        "        (class_id != BLACKWELL_CHANNEL_GPFIFO_A) &&\n+"
        "        (class_id != BLACKWELL_CHANNEL_GPFIFO_B))")
    if patch_text.count(old_class_guard) != 1:
        raise ValueError("R580 Blackwell-only channel-class guard is missing or ambiguous")
    if patch_text.count("VOLTA_CHANNEL_GPFIFO_A") != 0:
        raise ValueError("R580 channel patch already contains the R595 Volta adapter")
    blackwell_a_include = "+#include <class/clc96f.h>\n"
    blackwell_b_include = "+#include <class/clca6f.h>\n"
    if (patch_text.count(blackwell_a_include) != 1 or
            patch_text.count(blackwell_b_include) != 0):
        raise ValueError("R580 channel patch Blackwell class includes drifted")
    adapted = patch_text.replace(old_class_guard, new_class_guard, 1)
    adapted = adapted.replace(blackwell_a_include,
                              blackwell_a_include + blackwell_b_include, 1)
    return transform_control_session_additions_r595(nv, control_header, adapted)


def transform_map_memory_r595(
        nv: str, control_header: str, patch_text: str) -> tuple[str, str, list[str]]:
    """Port fixed NVOS33/NVOS34 memory-map calls through R595's RM ioctl path."""
    include = '#include "nv-unix-nvos-params-wrappers.h"\n'
    source_include = "+" + include
    include_anchor = '#include "hybrid580-control-session.h"\n'
    if patch_text.count(source_include) != 1:
        raise ValueError("R580 map-memory wrapper include is missing or ambiguous")
    if nv.count(include_anchor) != 1:
        raise ValueError("R595 map-memory source include anchor is missing or ambiguous")
    if include in nv:
        raise ValueError("R595 map-memory wrapper include is already present")
    adapted = nv.replace(include_anchor, include_anchor + include, 1)
    changed, changed_header, api_names = transform_control_session_additions_r595(
        adapted, control_header, patch_text,
        dispatch_markers=(
            "rm_ioctl(sp, nv, &nvlfp->nvfp, NV_ESC_RM_MAP_MEMORY,",
            "rm_ioctl(sp, nv, &nvlfp->nvfp, NV_ESC_RM_UNMAP_MEMORY,"))
    expected = [
        "hybrid580_open_control_session_map_memory_v1",
        "hybrid580_open_control_session_unmap_memory_v1",
    ]
    if api_names != expected:
        raise ValueError("R580 map-memory API set or order drifted")
    return changed, changed_header, api_names


def transform_update_device_mapping_info_r595(
        nv: str, control_header: str, patch_text: str) -> tuple[str, str, list[str]]:
    """Port the fixed NVOS56 route without changing caller-process semantics."""
    changed, header, api_names = transform_control_session_additions_r595(
        nv, control_header, patch_text,
        dispatch_markers=("NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO",
                          "sizeof(api)", "*params = api"))
    expected = ["hybrid580_open_control_session_update_device_mapping_info_v1"]
    if api_names != expected:
        raise ValueError("R580 NVOS56 mapping-update API set or order drifted")
    implementation = changed[changed.index(
        "NV_STATUS hybrid580_open_control_session_update_device_mapping_info_v1("):
        changed.index(
            "EXPORT_SYMBOL(hybrid580_open_control_session_update_device_mapping_info_v1);")]
    for required in ("NVOS56_PARAMETERS api", "mutex_lock_interruptible(&session->lock)",
                     "nv_down_read_interruptible(&nv_system_pm_lock)",
                     "rm_ioctl(sp, nv, &nvlfp->nvfp",
                     "api.status = 0xffffffffU", "*params = api"):
        if required not in implementation:
            raise ValueError("R580 NVOS56 mapping-update bridge is incomplete")
    if "workqueue" in implementation.lower() or "kthread" in implementation.lower():
        raise ValueError("R580 NVOS56 bridge must remain synchronous in the caller")
    return changed, header, api_names


def transform_rusd_allocation_r595(
        nv: str, control_header: str, patch_text: str) -> tuple[str, str, list[str]]:
    """Add the fixed RM_USER_SHARED_DATA bridge and its R595 type dependency."""
    source_marker = "+++ b/kernel-open/nvidia/nv.c\n"
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
    if patch_text.count(source_marker) != 1 or header_marker in patch_text:
        raise ValueError("R580 RUSD patch file layout is missing or ambiguous")
    if "NV00DE_ALLOC_PARAMETERS" in control_header:
        raise ValueError("R595 RUSD API is already present")
    additions = (
        "\n--- a/kernel-open/nvidia/hybrid580-control-session.h\n"
        "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
        "@@ -1,0 +1,8 @@\n"
        "+#include <class/cl00de.h>\n"
        "+/* Fixed eight-byte RM_USER_SHARED_DATA allocation bridge. */\n"
        "+NV_STATUS hybrid580_open_control_session_rusd_alloc_v1(\n"
        "+    struct hybrid580_control_session *, NvHandle h_root,\n"
        "+    NvHandle h_subdevice, NvHandle h_rusd,\n"
        "+    const NV00DE_ALLOC_PARAMETERS *params, NvHandle *returned_rusd,\n"
        "+    NvU32 *rm_status);\n")
    synthetic_patch = patch_text + additions
    changed, changed_header, api_names = transform_control_session_additions_r595(
        nv, control_header, synthetic_patch)
    expected = ["hybrid580_open_control_session_rusd_alloc_v1"]
    if api_names != expected:
        raise ValueError("R580 RUSD API signature or ordering drifted")
    return changed, changed_header, api_names


def transform_engine_allocation_r595(
        nv: str, control_header: str, patch_text: str) -> tuple[str, str, list[str]]:
    """Port the fixed, zero-payload Blackwell engine allocation bridge."""
    source_marker = "+++ b/kernel-open/nvidia/nv.c\n"
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
    if patch_text.count(source_marker) != 1 or header_marker in patch_text:
        raise ValueError("R580 engine-object patch file layout is missing or ambiguous")
    required_classes = ("BLACKWELL_DMA_COPY_B", "BLACKWELL_COMPUTE_B")
    if any(patch_text.count(class_id) != 1 for class_id in required_classes):
        raise ValueError("R580 Blackwell engine-class allowlist drifted")
    additions = (
        "\n--- a/kernel-open/nvidia/hybrid580-control-session.h\n"
        "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
        "@@ -1,0 +1,10 @@\n"
        "+#include <class/clcab5.h>\n"
        "+#include <class/clcec0.h>\n"
        "+/* Blackwell compute/DMA child objects have no allocation payload. */\n"
        "+NV_STATUS hybrid580_open_control_session_engine_alloc_v1(\n"
        "+    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_channel,\n"
        "+    NvHandle h_engine, NvU32 class_id, NvHandle *returned_engine,\n"
        "+    NvU32 *rm_status);\n")
    synthetic_patch = patch_text + additions
    changed, changed_header, api_names = transform_control_session_additions_r595(
        nv, control_header, synthetic_patch)
    expected = ["hybrid580_open_control_session_engine_alloc_v1"]
    if api_names != expected:
        raise ValueError("R580 engine-object API signature or ordering drifted")
    return changed, changed_header, api_names


def transform_sys_params_r595(
        nv: str, control_header: str, patch_text: str) -> tuple[str, str, list[str]]:
    """Share R595's set-once SYS_PARAMS update with the hybrid control bridge."""
    source_marker = "+++ b/kernel-open/nvidia/nv.c\n"
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
    if patch_text.count(source_marker) != 1 or header_marker in patch_text:
        raise ValueError("R580 SYS_PARAMS patch file layout is missing or ambiguous")
    if "hybrid580_sys_params_lock" in nv or "hybrid580_set_sys_params" in nv:
        raise ValueError("R595 SYS_PARAMS helper is already present")

    helper_marker = "+static DEFINE_MUTEX(hybrid580_sys_params_lock);\n"
    if patch_text.count(helper_marker) != 1:
        raise ValueError("R580 SYS_PARAMS helper implementation is missing or ambiguous")
    helper_lines: list[str] = []
    for line in patch_text[patch_text.index(helper_marker):].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        helper_lines.append(line)
    helper = "".join(line[1:] for line in helper_lines)
    if ("mutex_lock(&hybrid580_sys_params_lock);" not in helper or
            "mutex_unlock(&hybrid580_sys_params_lock);" not in helper or
            "nvl->numa_memblock_size != memblock_size" not in helper):
        raise ValueError("R580 SYS_PARAMS set-once locking semantics drifted")
    helper_anchor = "#include <linux/slab.h>\n\n"
    if nv.count(helper_anchor) != 1:
        raise ValueError("R595 SYS_PARAMS helper include anchor is missing or ambiguous")
    nv = nv.replace(helper_anchor, helper_anchor + helper + "\n", 1)

    old_update = (
        "            /* numa_memblock_size should only be set once */\n"
        "            if (nvl->numa_memblock_size == 0)\n"
        "            {\n"
        "                nvl->numa_memblock_size = api->memblock_size;\n"
        "            }\n"
        "            else\n"
        "            {\n"
        "                status = (nvl->numa_memblock_size == api->memblock_size) ?\n"
        "                    0 : -EBUSY;\n"
        "                goto done;\n"
        "            }\n")
    new_update = (
        "            status = hybrid580_set_sys_params(nvl, api->memblock_size);\n"
        "            if (status != 0)\n"
        "                goto done;\n")
    if nv.count(old_update) != 1:
        raise ValueError("R595 SYS_PARAMS set-once update block is missing or ambiguous")
    nv = nv.replace(old_update, new_update, 1)

    additions = (
        "\n--- a/kernel-open/nvidia/hybrid580-control-session.h\n"
        "+++ b/kernel-open/nvidia/hybrid580-control-session.h\n"
        "@@ -1,0 +1,3 @@\n"
        "+/* NVIDIA's OS-level SYS_PARAMS control-device state update. */\n"
        "+int hybrid580_open_control_session_sys_params_v1(\n"
        "+    struct hybrid580_control_session *, NvU64 memblock_size);\n")
    synthetic_patch = patch_text + additions
    changed, changed_header, api_names = transform_control_session_additions_r595(
        nv, control_header, synthetic_patch,
        dispatch_markers=("hybrid580_set_sys_params(nvl, memblock_size)",))
    expected = ["hybrid580_open_control_session_sys_params_v1"]
    if api_names != expected:
        raise ValueError("R580 SYS_PARAMS API signature or ordering drifted")
    return changed, changed_header, api_names


def transform_build_version_r595(
        nv: str, patch_text: str, build_version_header: str) -> str:
    """Port the pointer-free V2 build-version bridge after the SYS_PARAMS API."""
    source_marker = "+++ b/kernel-open/nvidia/nv.c\n"
    header_marker = "+++ b/kernel-open/nvidia/hybrid580-open-build-version.h\n"
    if patch_text.count(source_marker) != 1 or header_marker in patch_text:
        raise ValueError("R580 build-version patch file layout is missing or ambiguous")

    source_patch = patch_text[patch_text.index(source_marker):]
    include = '#include "hybrid580-open-build-version.h"\n'
    if source_patch.count("+" + include) != 1:
        raise ValueError("R580 build-version API include is missing or ambiguous")
    include_anchor = '#include "hybrid580-control-session.h"\n'
    if nv.count(include_anchor) != 1 or include in nv:
        raise ValueError("R595 build-version include anchor is missing or already adapted")

    function_start = "+NV_STATUS hybrid580_open_control_session_build_version_v1(\n"
    if source_patch.count(function_start) != 1:
        raise ValueError("R580 build-version implementation is missing or ambiguous")
    additions: list[str] = []
    for line in source_patch[source_patch.index(function_start):].splitlines(keepends=True):
        if not line.startswith("+"):
            break
        additions.append(line)
    implementation = "".join(line[1:] for line in additions)
    required = (
        "NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS",
        "NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION_V2",
        "NVOS54_PARAMETERS",
        "NV04_CONTROL",
        "NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS *result = NULL;",
        "result = kzalloc(sizeof(*result), GFP_KERNEL);",
        "KERNEL_POINTER_TO_NvP64(result)",
        "paramsSize = sizeof(*result)",
        "rm_kernel_rmapi_op(sp, &ops);",
        "control.status == 0xffffffffU",
        "*params = *result;",
        "kfree(result);",
        "EXPORT_SYMBOL(hybrid580_open_control_session_build_version_v1);")
    if any(token not in implementation for token in required):
        raise ValueError("R580 build-version bridge implementation is incomplete")
    if (re.search(r"\bcopy_(?:from|to)_user\s*\(", implementation) or
            "NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION," in implementation):
        raise ValueError("R580 build-version bridge must use only the pointer-free V2 RM packet")

    prototype = (
        "NV_STATUS hybrid580_open_control_session_build_version_v1(\n"
        "    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,\n"
        "    NvU32 flags, NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS *params,\n"
        "    NvU32 *control_status);")
    if build_version_header.count(prototype) != 1:
        raise ValueError("R595 build-version API header differs from the pinned project contract")
    if "#include <ctrl/ctrl0000/ctrl0000system.h>" not in build_version_header:
        raise ValueError("R595 build-version API header omits the fixed V2 RM type")

    export_anchor = "EXPORT_SYMBOL(hybrid580_open_control_session_sys_params_v1);\n"
    if nv.count(export_anchor) != 1 or "hybrid580_open_control_session_build_version_v1" in nv:
        raise ValueError("R595 SYS_PARAMS export anchor is missing or already adapted")
    nv = nv.replace(export_anchor,
                    export_anchor + "\n" + implementation.rstrip() + "\n", 1)
    return nv.replace(include_anchor, include_anchor + include, 1)


def transform_pm_channel_depth_enum_r595(header: str, patch_text: str) -> str:
    """Add the private channel PM depth at the exact R595 enum definition."""
    target_marker = "+++ b/kernel-open/common/inc/nv.h\n"
    if patch_text.count(target_marker) != 1 or patch_text.count("+++ b/") != 1:
        raise ValueError("R580 PM-depth enum patch file layout is missing or ambiguous")
    if (patch_text.count("-    NV_PM_ACTION_DEPTH_UVM\n") != 1 or
            patch_text.count("+    NV_PM_ACTION_DEPTH_UVM,\n") != 1 or
            patch_text.count("+    NV_PM_ACTION_DEPTH_CHANNELS\n") != 1):
        raise ValueError("R580 PM-depth enum patch values differ from the pinned contract")

    original = (
        "typedef enum\n"
        "{\n"
        "    NV_PM_ACTION_DEPTH_DEFAULT,\n"
        "    NV_PM_ACTION_DEPTH_MODESET,\n"
        "    NV_PM_ACTION_DEPTH_UVM\n"
        "} nv_pm_action_depth_t;\n")
    adapted = (
        "typedef enum\n"
        "{\n"
        "    NV_PM_ACTION_DEPTH_DEFAULT,\n"
        "    NV_PM_ACTION_DEPTH_MODESET,\n"
        "    NV_PM_ACTION_DEPTH_UVM,\n"
        "    NV_PM_ACTION_DEPTH_CHANNELS\n"
        "} nv_pm_action_depth_t;\n")
    if header.count(original) != 1 or "NV_PM_ACTION_DEPTH_CHANNELS" in header:
        raise ValueError("R595 PM-depth enum anchor is missing or already adapted")
    return header.replace(original, adapted, 1)


def transform_pm_channel_depth_r595(
        nv: str, procfs: str, patch_text: str) -> tuple[str, str]:
    """Adapt the R580 channel-only PM lifetime rules to R595's source layout."""
    if (patch_text.count("+++ b/kernel-open/nvidia/nv.c\n") != 1 or
            patch_text.count("+++ b/kernel-open/nvidia/nv-procfs.c\n") != 1 or
            patch_text.count("NV_PM_ACTION_DEPTH_CHANNELS") < 4 or
            patch_text.count('strcasecmp(kbuf, "channels")') != 1):
        raise ValueError("R580 channel-depth PM patch contract is missing or ambiguous")

    def replace_once(text: str, old: str, new: str, label: str) -> str:
        if text.count(old) != 1:
            raise ValueError("R595 PM-depth " + label + " anchor is missing or ambiguous")
        return text.replace(old, new, 1)

    old_close_proto = "static int           nvidia_ctl_close       (struct inode *, struct file *);\n"
    new_close_proto = (
        "static void          nvidia_ctl_close_callback(nv_linux_file_private_t *);\n"
        "static void          nvidia_ctl_close_deferred(void *);\n")
    nv = replace_once(nv, old_close_proto, new_close_proto, "control-close declaration")

    mmap_guard = (
        "static int nv_mmap_pm_guard(struct file *file, struct vm_area_struct *vma)\n"
        "{\n"
        "    int status;\n"
        "\n"
        "    if (!down_read_trylock(&nv_system_pm_lock))\n"
        "    {\n"
        "        return -EAGAIN;\n"
        "    }\n"
        "\n"
        "    status = nvidia_mmap(file, vma);\n"
        "    up_read(&nv_system_pm_lock);\n"
        "\n"
        "    return status;\n"
        "}\n\n")
    mmap_anchor = "/* character device entry points*/\n"
    nv = replace_once(nv, mmap_anchor, mmap_anchor + mmap_guard, "mmap guard insertion")
    nv = replace_once(nv, "    .mmap      = nvidia_mmap,\n",
                      "    .mmap      = nv_mmap_pm_guard,\n", "file mmap operation")

    old_open = (
        "    if (nv_is_control_device(inode))\n"
        "    {\n"
        "        rc = nvidia_ctl_open(inode, file);\n"
        "        if (rc != 0)\n"
        "            goto failed;\n"
        "        return rc;\n"
        "    }\n")
    new_open = (
        "    if (nv_is_control_device(inode))\n"
        "    {\n"
        "        rc = nv_down_read_interruptible(&nv_system_pm_lock);\n"
        "        if (rc < 0)\n"
        "        {\n"
        "            NV_SET_FILE_PRIVATE(file, NULL);\n"
        "            nv_free_file_private(nvlfp);\n"
        "            nv_kmem_cache_free_stack(sp);\n"
        "            return rc;\n"
        "        }\n"
        "\n"
        "        rc = nvidia_ctl_open(inode, file);\n"
        "        up_read(&nv_system_pm_lock);\n"
        "        if (rc != 0)\n"
        "        {\n"
        "            NV_SET_FILE_PRIVATE(file, NULL);\n"
        "            nv_free_file_private(nvlfp);\n"
        "            nv_kmem_cache_free_stack(sp);\n"
        "            return rc;\n"
        "        }\n"
        "        return 0;\n"
        "    }\n")
    nv = replace_once(nv, old_open, new_open, "control-open PM guard")

    old_close_route = (
        "    if (nv_is_control_device(inode))\n"
        "    {\n"
        "        return nvidia_ctl_close(inode, file);\n"
        "    }\n")
    new_close_route = (
        "    if (nv_is_control_device(inode))\n"
        "    {\n"
        "        NV_SET_FILE_PRIVATE(file, NULL);\n"
        "\n"
        "        rc = nv_down_read_interruptible(&nv_system_pm_lock);\n"
        "        if (rc == 0)\n"
        "        {\n"
        "            nvidia_ctl_close_callback(nvlfp);\n"
        "            up_read(&nv_system_pm_lock);\n"
        "        }\n"
        "        else\n"
        "        {\n"
        "            nv_kthread_q_item_init(&nvlfp->deferred_close_q_item,\n"
        "                                   nvidia_ctl_close_deferred,\n"
        "                                   nvlfp);\n"
        "            rc = nv_kthread_q_schedule_q_item(&nv_deferred_close_kthread_q,\n"
        "                                              &nvlfp->deferred_close_q_item);\n"
        "            WARN_ON(rc == 0);\n"
        "        }\n"
        "        return 0;\n"
        "    }\n")
    nv = replace_once(nv, old_close_route, new_close_route, "control-close PM guard")
    nv = replace_once(nv, "** nvidia_ctl_close\n", "** nvidia_ctl_close_callback\n",
                      "control-close callback comment")

    close_start = "static int\nnvidia_ctl_close(\n"
    close_end = "\n\n\nvoid NV_API_CALL\nnv_set_dma_address_size("
    if nv.count(close_start) != 1 or nv.count(close_end) != 1:
        raise ValueError("R595 control-close callback boundaries are missing or ambiguous")
    start = nv.index(close_start)
    end = nv.index(close_end, start)
    close = nv[start:end]
    close = replace_once(
        close,
        "static int\nnvidia_ctl_close(\n    struct inode *inode,\n    struct file *file\n)",
        "static void\nnvidia_ctl_close_callback(\n    nv_linux_file_private_t *nvlfp\n)",
        "control-close callback signature")
    close = replace_once(close,
                         "    nv_linux_state_t *nvl = NV_GET_NVL_FROM_FILEP(file);\n",
                         "    nv_linux_state_t *nvl = nvlfp->nvptr;\n",
                         "control-close state lookup")
    close = replace_once(close,
                         "    nv_linux_file_private_t *nvlfp = NV_GET_LINUX_FILE_PRIVATE(file);\n",
                         "", "control-close private lookup")
    close = replace_once(close, "    NV_SET_FILE_PRIVATE(file, NULL);\n", "",
                         "control-close file-private clearing")
    close = replace_once(close,
                         "    nv_kmem_cache_free_stack(sp);\n\n    return 0;\n}",
                         "    nv_kmem_cache_free_stack(sp);\n}",
                         "control-close return")
    deferred_close = (
        "\n\nstatic void nvidia_ctl_close_deferred(void *data)\n"
        "{\n"
        "    nv_linux_file_private_t *nvlfp = data;\n"
        "\n"
        "    down_read(&nv_system_pm_lock);\n"
        "    nvidia_ctl_close_callback(nvlfp);\n"
        "    up_read(&nv_system_pm_lock);\n"
        "}\n")
    nv = nv[:start] + close + deferred_close + nv[end:]

    resume_start = "static NV_STATUS\nnv_resume_devices(\n"
    suspend_start = "\n\nstatic NV_STATUS\nnv_suspend_devices(\n"
    power_state_start = "\n\nNV_STATUS\nnv_set_system_power_state(\n"
    if (nv.count(resume_start) != 1 or nv.count(suspend_start) != 1 or
            nv.count(power_state_start) != 1):
        raise ValueError("R595 PM-depth device callback boundaries are missing or ambiguous")
    resume_begin = nv.index(resume_start)
    suspend_begin = nv.index(suspend_start, resume_begin)
    power_state_begin = nv.index(power_state_start, suspend_begin)
    resume = nv[resume_begin:suspend_begin]
    suspend = nv[suspend_begin + 2:power_state_begin]

    resume = replace_once(
        resume,
        "    NvBool resume_devices = NV_TRUE;\n    NV_STATUS status;\n",
        "    NvBool resume_devices = NV_TRUE;\n"
        "    NvBool resume_uvm = NV_TRUE;\n"
        "    NV_STATUS status;\n", "resume UVM state")
    resume = replace_once(
        resume,
        "    if (pm_action_depth == NV_PM_ACTION_DEPTH_UVM)\n"
        "    {\n"
        "        resume_devices = NV_FALSE;\n"
        "    }\n",
        "    if (pm_action_depth == NV_PM_ACTION_DEPTH_UVM)\n"
        "    {\n"
        "        resume_devices = NV_FALSE;\n"
        "    }\n"
        "    else if (pm_action_depth == NV_PM_ACTION_DEPTH_CHANNELS)\n"
        "    {\n"
        "        resume_devices = NV_FALSE;\n"
        "        resume_uvm = NV_FALSE;\n"
        "    }\n", "channels-only resume policy")
    resume = replace_once(
        resume,
        "    status = nv_uvm_resume();\n"
        "    WARN_ON(status != NV_OK);\n",
        "    if (resume_uvm)\n"
        "    {\n"
        "        status = nv_uvm_resume();\n"
        "        WARN_ON(status != NV_OK);\n"
        "    }\n", "conditional UVM resume")

    suspend = replace_once(
        suspend,
        "    NvBool resume_devices = NV_FALSE;\n    NV_STATUS status = NV_OK;\n",
        "    NvBool resume_devices = NV_FALSE;\n"
        "    NvBool uvm_suspended = NV_FALSE;\n"
        "    NV_STATUS status = NV_OK;\n", "UVM rollback state")
    suspend = replace_once(
        suspend,
        "    if (status == NV_OK)\n"
        "    {\n"
        "        status = nv_uvm_suspend();\n"
        "        WARN_ON(status != NV_OK);\n"
        "    }\n",
        "    if (status == NV_OK && pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS)\n"
        "    {\n"
        "        status = nv_uvm_suspend();\n"
        "        WARN_ON(status != NV_OK);\n"
        "        uvm_suspended = (status == NV_OK);\n"
        "    }\n", "channels-only UVM suspend policy")
    suspend = replace_once(
        suspend,
        "    if (pm_action_depth == NV_PM_ACTION_DEPTH_UVM)\n"
        "    {\n"
        "        return NV_OK;\n"
        "    }\n",
        "    if (pm_action_depth == NV_PM_ACTION_DEPTH_UVM ||\n"
        "        pm_action_depth == NV_PM_ACTION_DEPTH_CHANNELS)\n"
        "    {\n"
        "        return NV_OK;\n"
        "    }\n", "channels-only suspend exit")
    suspend = replace_once(
        suspend,
        "    if (status != NV_OK)\n"
        "    {\n"
        "        LOCK_NV_LINUX_DEVICES();\n",
        "    if (status != NV_OK)\n"
        "    {\n"
        "        NV_STATUS cleanup_status;\n"
        "        NV_STATUS rollback_status = NV_OK;\n"
        "\n"
        "        LOCK_NV_LINUX_DEVICES();\n", "rollback status initialization")
    suspend = replace_once(
        suspend,
        "            if (resume_devices && nv_dev_needs_vidmem_preservation(nv))\n"
        "            {\n"
        "                nvidia_resume(nvl->dev, NV_PM_ACTION_RESUME);\n"
        "            }\n"
        "\n"
        "            nv_restore_user_channels(nv);\n",
        "            if (resume_devices && nv_dev_needs_vidmem_preservation(nv))\n"
        "            {\n"
        "                cleanup_status = nvidia_resume(nvl->dev, NV_PM_ACTION_RESUME);\n"
        "                WARN_ON(cleanup_status != NV_OK);\n"
        "                if (cleanup_status != NV_OK && rollback_status == NV_OK)\n"
        "                {\n"
        "                    rollback_status = cleanup_status;\n"
        "                }\n"
        "            }\n"
        "\n"
        "            cleanup_status = nv_restore_user_channels(nv);\n"
        "            WARN_ON(cleanup_status != NV_OK);\n"
        "            if (cleanup_status != NV_OK && rollback_status == NV_OK)\n"
        "            {\n"
        "                rollback_status = cleanup_status;\n"
        "            }\n", "device rollback status collection")
    suspend = replace_once(
        suspend,
        "        nv_uvm_resume();\n\n"
        "        nvidia_modeset_resume(0);\n",
        "        if (uvm_suspended)\n"
        "        {\n"
        "            cleanup_status = nv_uvm_resume();\n"
        "            WARN_ON(cleanup_status != NV_OK);\n"
        "            if (cleanup_status != NV_OK && rollback_status == NV_OK)\n"
        "            {\n"
        "                rollback_status = cleanup_status;\n"
        "            }\n"
        "        }\n\n"
        "        nvidia_modeset_resume(0);\n"
        "        if (rollback_status != NV_OK)\n"
        "        {\n"
        "            status = NV_ERR_GENERIC;\n"
        "        }\n", "UVM/device rollback completion")
    nv = nv[:resume_begin] + resume + "\n\n" + suspend + nv[power_state_begin:]

    procfs = replace_once(procfs, '    char kbuf[sizeof("modeset\\n")];\n',
                          '    char kbuf[sizeof("channels\\n")];\n',
                          "procfs input buffer")
    uvm_arm = (
        "    if (strcasecmp(kbuf, \"uvm\") == 0)\n"
        "    {\n"
        "        nv_procfs_pm_action_depth = NV_PM_ACTION_DEPTH_UVM;\n"
        "    }\n")
    channels_arm = (
        "    if (strcasecmp(kbuf, \"uvm\") == 0)\n"
        "    {\n"
        "        nv_procfs_pm_action_depth = NV_PM_ACTION_DEPTH_UVM;\n"
        "    }\n"
        "    else if (strcasecmp(kbuf, \"channels\") == 0)\n"
        "    {\n"
        "        nv_procfs_pm_action_depth = NV_PM_ACTION_DEPTH_CHANNELS;\n"
        "    }\n")
    procfs = replace_once(procfs, uvm_arm, channels_arm, "procfs channels input")
    procfs = replace_once(procfs, 'seq_printf(m, "default modeset uvm\\n");',
                          'seq_printf(m, "default modeset uvm channels\\n");',
                          "procfs supported-depth listing")
    return nv, procfs


def transform_pm_vma_access_r595(nv_mmap: str, patch_text: str) -> str:
    """Guard R595 VMA access with the provider-wide PM read lock."""
    if (patch_text.count("+++ b/kernel-open/nvidia/nv-mmap.c\n") != 1 or
            patch_text.count("-nvidia_vma_access(\n") != 1 or
            patch_text.count("+nvidia_vma_access_unlocked(\n") != 1 or
            patch_text.count("down_read_trylock(&nv_system_pm_lock)") != 1 or
            patch_text.count("return -EAGAIN;") != 1 or
            patch_text.count("up_read(&nv_system_pm_lock);") != 1 or
            patch_text.count("status = nvidia_vma_access_unlocked(vma, addr, buffer, length, write);") != 1):
        raise ValueError("R580 VMA-access patch contract is missing or ambiguous")
    old_signature = "static int\nnvidia_vma_access(\n"
    new_signature = "static int\nnvidia_vma_access_unlocked(\n"
    if nv_mmap.count(old_signature) != 1 or "nvidia_vma_access_unlocked(" in nv_mmap:
        raise ValueError("R595 VMA-access function anchor is missing or already adapted")
    nv_mmap = nv_mmap.replace(old_signature, new_signature, 1)

    wrapper = (
        "static int\n"
        "nvidia_vma_access(\n"
        "    struct vm_area_struct *vma,\n"
        "    unsigned long addr,\n"
        "    void *buffer,\n"
        "    int length,\n"
        "    int write\n"
        ")\n"
        "{\n"
        "    int status;\n"
        "\n"
        "    /* Do not access mapped GPU memory during a provider PM transition. */\n"
        "    if (!down_read_trylock(&nv_system_pm_lock))\n"
        "        return -EAGAIN;\n"
        "\n"
        "    status = nvidia_vma_access_unlocked(vma, addr, buffer, length, write);\n"
        "    up_read(&nv_system_pm_lock);\n"
        "\n"
        "    return status;\n"
        "}\n")
    function_anchor = "\nstatic vm_fault_t nvidia_fault(\n"
    if nv_mmap.count(function_anchor) != 1:
        raise ValueError("R595 VMA-access wrapper insertion anchor is missing or ambiguous")
    return nv_mmap.replace(function_anchor, "\n" + wrapper + function_anchor, 1)


def transform_pm_free_list_lock_r595(linux_header: str, patch_text: str) -> str:
    """Serialize R595 allocation refcount/free-list publication per file."""
    target_marker = "+++ b/kernel-open/common/inc/nv-linux.h\n"
    required_patch_tokens = (
        "+    unsigned long eflags;\n",
        "+    NV_SPIN_LOCK_IRQSAVE(&nvlfp->fp_lock, eflags);\n",
        "+        NV_SPIN_UNLOCK_IRQRESTORE(&nvlfp->fp_lock, eflags);\n",
        "+    NV_SPIN_UNLOCK_IRQRESTORE(&nvlfp->fp_lock, eflags);\n")
    if (patch_text.count(target_marker) != 1 or
            any(patch_text.count(token) != 1 for token in required_patch_tokens)):
        raise ValueError("R580 VMA free-list lock patch contract is missing or ambiguous")
    original = (
        "static inline NvBool nv_alloc_release(nv_linux_file_private_t *nvlfp, nv_alloc_t *at)\n"
        "{\n"
        "    NV_PRINT_AT(NV_DBG_MEMINFO, at);\n"
        "\n"
        "    if (atomic64_dec_and_test(&at->usage_count))\n"
        "    {\n"
        "        atomic64_inc(&at->usage_count);\n"
        "\n"
        "        at->next = nvlfp->free_list;\n"
        "        nvlfp->free_list = at;\n"
        "        return NV_TRUE;\n"
        "    }\n"
        "\n"
        "    return NV_FALSE;\n"
        "}\n")
    adapted = (
        "static inline NvBool nv_alloc_release(nv_linux_file_private_t *nvlfp, nv_alloc_t *at)\n"
        "{\n"
        "    unsigned long eflags;\n"
        "\n"
        "    NV_PRINT_AT(NV_DBG_MEMINFO, at);\n"
        "\n"
        "    NV_SPIN_LOCK_IRQSAVE(&nvlfp->fp_lock, eflags);\n"
        "    if (atomic64_dec_and_test(&at->usage_count))\n"
        "    {\n"
        "        atomic64_inc(&at->usage_count);\n"
        "\n"
        "        at->next = nvlfp->free_list;\n"
        "        nvlfp->free_list = at;\n"
        "        NV_SPIN_UNLOCK_IRQRESTORE(&nvlfp->fp_lock, eflags);\n"
        "        return NV_TRUE;\n"
        "    }\n"
        "\n"
        "    NV_SPIN_UNLOCK_IRQRESTORE(&nvlfp->fp_lock, eflags);\n"
        "    return NV_FALSE;\n"
        "}\n")
    if linux_header.count(original) != 1:
        raise ValueError("R595 nv_alloc_release function anchor is missing or ambiguous")
    return linux_header.replace(original, adapted, 1)


def transform_pm_recovery_provider_r595(
        nv: str, uvm_interface: str, patch_text: str) -> tuple[str, str]:
    """Port the PM recovery bridge using R595's registered-UVM event ABI."""
    if (patch_text.count("+++ b/kernel-open/nvidia/nv.c\n") != 1 or
            patch_text.count("+++ b/kernel-open/nvidia/nv_uvm_interface.c\n") != 1 or
            patch_text.count("+++ b/") != 2):
        raise ValueError("R580 PM-recovery patch file layout is missing or ambiguous")
    patch_contract = (
        '#include "hybrid580-pm-provider-kernel.h"',
        "HYBRID580_PM_PROVIDER_CALLBACK_RESUME",
        "HYBRID580_PM_PROVIDER_CALLBACK_RESTORE",
        "HYBRID580_PM_PROVIDER_CALLBACK_THAW",
        "hybrid580_open_nv_uvm_suspend_registered_v1(void)",
        "hybrid580_open_nv_uvm_resume_registered_v1(void)",
        "NV_ERR_NOT_SUPPORTED",
        "events->suspend()",
        "events->resume()",
        "down(&g_pNvUvmEventsLock);",
        "up(&g_pNvUvmEventsLock);")
    if any(token not in patch_text for token in patch_contract):
        raise ValueError("R580 PM-recovery patch contract is incomplete")
    if (patch_text.count("UvmOpsUvmEvents *events") != 2 or
            patch_text.count("NV_STATUS hybrid580_open_nv_uvm_suspend_registered_v1(void)") != 2 or
            patch_text.count("NV_STATUS hybrid580_open_nv_uvm_resume_registered_v1(void)") != 2):
        raise ValueError("R580 PM-recovery UVM API signatures are missing or ambiguous")

    include_block = (
        "#define HYBRID580_PM_PROVIDER_PREFIX hybrid580_open_\n"
        "#define HYBRID580_PM_PROVIDER_SHARED_UVM_OWNER 1\n"
        '#include "hybrid580-pm-provider-kernel.h"\n'
        "#undef HYBRID580_PM_PROVIDER_SHARED_UVM_OWNER\n"
        "#undef HYBRID580_PM_PROVIDER_PREFIX\n\n")
    include_anchor = "int nv_pmops_suspend(\n    struct device *dev\n)\n{\n"
    if nv.count(include_anchor) != 1 or "hybrid580-pm-provider-kernel.h" in nv:
        raise ValueError("R595 PM-recovery provider include anchor is missing or already adapted")
    nv = nv.replace(include_anchor, include_block + include_anchor, 1)

    def replace_once(text: str, old: str, new: str, label: str) -> str:
        if text.count(old) != 1:
            raise ValueError("R595 PM-recovery " + label + " anchor is missing or ambiguous")
        return text.replace(old, new, 1)

    resume_old = (
        "int nv_pmops_resume(\n"
        "    struct device *dev\n"
        ")\n"
        "{\n"
        "    NV_STATUS status;\n\n"
        "    status = nvidia_resume(dev, NV_PM_ACTION_RESUME);\n"
        "    return (status == NV_OK) ? 0 : -EIO;\n"
        "}\n")
    resume_new = (
        "int nv_pmops_resume(\n"
        "    struct device *dev\n"
        ")\n"
        "{\n"
        "    NV_STATUS status;\n"
        "    int rc;\n\n"
        "    status = nvidia_resume(dev, NV_PM_ACTION_RESUME);\n"
        "    rc = (status == NV_OK) ? 0 : -EIO;\n"
        "    if (hybrid580_pm_provider_record_dpm_callback(\n"
        "            dev, HYBRID580_PM_PROVIDER_CALLBACK_RESUME, rc) != 0 && rc == 0)\n"
        "        rc = -EIO;\n"
        "    return rc;\n"
        "}\n")
    nv = replace_once(nv, resume_old, resume_new, "resume callback")

    thaw_old = (
        "int nv_pmops_thaw(\n"
        "    struct device *dev\n"
        ")\n"
        "{\n"
        "    return 0;\n"
        "}\n")
    thaw_new = (
        "int nv_pmops_thaw(\n"
        "    struct device *dev\n"
        ")\n"
        "{\n"
        "    return hybrid580_pm_provider_record_dpm_callback(\n"
        "        dev, HYBRID580_PM_PROVIDER_CALLBACK_THAW, 0) == 0 ? 0 : -EIO;\n"
        "}\n")
    nv = replace_once(nv, thaw_old, thaw_new, "thaw callback")

    restore_old = (
        "int nv_pmops_restore(\n"
        "    struct device *dev\n"
        ")\n"
        "{\n"
        "    NV_STATUS status;\n\n"
        "    status = nvidia_resume(dev, NV_PM_ACTION_RESUME);\n"
        "    return (status == NV_OK) ? 0 : -EIO;\n"
        "}\n")
    restore_new = (
        "int nv_pmops_restore(\n"
        "    struct device *dev\n"
        ")\n"
        "{\n"
        "    NV_STATUS status;\n"
        "    int rc;\n\n"
        "    status = nvidia_resume(dev, NV_PM_ACTION_RESUME);\n"
        "    rc = (status == NV_OK) ? 0 : -EIO;\n"
        "    if (hybrid580_pm_provider_record_dpm_callback(\n"
        "            dev, HYBRID580_PM_PROVIDER_CALLBACK_RESTORE, rc) != 0 && rc == 0)\n"
        "        rc = -EIO;\n"
        "    return rc;\n"
        "}\n")
    nv = replace_once(nv, restore_old, restore_new, "restore callback")

    if ("hybrid580_open_nv_uvm_suspend_registered_v1" in uvm_interface or
            "hybrid580_open_nv_uvm_resume_registered_v1" in uvm_interface):
        raise ValueError("R595 PM-recovery UVM API is already adapted")
    native_suspend = (
        "NV_STATUS nv_uvm_suspend(void)\n"
        "{\n"
        "    NV_STATUS status = NV_OK;\n"
        "    struct UvmEventsLinux *events;\n\n"
        "    // Synchronize callbacks with unregistration\n"
        "    down(&g_pNvUvmEventsLock);\n\n"
        "    // It's not strictly necessary to use a cached local copy of the events\n"
        "    // pointer here since it can't change under the lock, but we'll do it for\n"
        "    // consistency.\n"
        "    events = getUvmEvents();\n"
        "    if (events && events->suspend)\n"
        "    {\n"
        "        status = events->suspend();\n"
        "    }\n\n"
        "    up(&g_pNvUvmEventsLock);\n\n"
        "    return status;\n"
        "}\n")
    native_resume = native_suspend.replace(
        "nv_uvm_suspend", "nv_uvm_resume").replace("events->suspend", "events->resume")
    if (uvm_interface.count(native_suspend) != 1 or
            uvm_interface.count(native_resume) != 1 or
            uvm_interface.count("static struct semaphore g_pNvUvmEventsLock;") != 1 or
            uvm_interface.count("static struct UvmEventsLinux *getUvmEvents(void)") != 1):
        raise ValueError("R595 UVM event structure or synchronization contract changed")

    uvm_prototypes = (
        "NV_STATUS hybrid580_open_nv_uvm_suspend_registered_v1(void);\n"
        "NV_STATUS hybrid580_open_nv_uvm_resume_registered_v1(void);\n\n")
    uvm_include_anchor = ('#include "nv-linux.h"\n\n'
                          "#if defined(NV_UVM_ENABLE)\n")
    if uvm_interface.count(uvm_include_anchor) != 1:
        raise ValueError("R595 UVM bridge prototype include anchor is missing or ambiguous")
    uvm_interface = uvm_interface.replace(
        uvm_include_anchor,
        '#include "nv-linux.h"\n\n' + uvm_prototypes + "#if defined(NV_UVM_ENABLE)\n", 1)

    enabled_apis = (
        "/* The hybrid owner must distinguish a registered callback from the "
        "native no-callback success. */\n"
        "NV_STATUS hybrid580_open_nv_uvm_suspend_registered_v1(void)\n"
        "{\n"
        "    NV_STATUS status = NV_ERR_NOT_SUPPORTED;\n"
        "    struct UvmEventsLinux *events;\n\n"
        "    down(&g_pNvUvmEventsLock);\n"
        "    events = getUvmEvents();\n"
        "    if (events != NULL && events->suspend != NULL)\n"
        "        status = events->suspend();\n"
        "    up(&g_pNvUvmEventsLock);\n\n"
        "    return status;\n"
        "}\n\n"
        "NV_STATUS hybrid580_open_nv_uvm_resume_registered_v1(void)\n"
        "{\n"
        "    NV_STATUS status = NV_ERR_NOT_SUPPORTED;\n"
        "    struct UvmEventsLinux *events;\n\n"
        "    down(&g_pNvUvmEventsLock);\n"
        "    events = getUvmEvents();\n"
        "    if (events != NULL && events->resume != NULL)\n"
        "        status = events->resume();\n"
        "    up(&g_pNvUvmEventsLock);\n\n"
        "    return status;\n"
        "}\n\n")
    enabled_anchor = "NV_STATUS nv_uvm_event_interrupt(const NvU8 *pUuid)\n{\n"
    uvm_interface = replace_once(uvm_interface, enabled_anchor,
                                 enabled_apis + enabled_anchor,
                                 "registered-UVM callback insertion")

    disabled_apis = (
        "NV_STATUS hybrid580_open_nv_uvm_suspend_registered_v1(void)\n"
        "{\n"
        "    return NV_ERR_NOT_SUPPORTED;\n"
        "}\n\n"
        "NV_STATUS hybrid580_open_nv_uvm_resume_registered_v1(void)\n"
        "{\n"
        "    return NV_ERR_NOT_SUPPORTED;\n"
        "}\n\n")
    disabled_anchor = "#endif // NV_UVM_ENABLE\n"
    uvm_interface = replace_once(uvm_interface, disabled_anchor,
                                 disabled_apis + disabled_anchor,
                                 "disabled-UVM stub insertion")
    return nv, uvm_interface


def transform_pm_channel_dpm_modeset_r595(nv: str, patch_text: str) -> str:
    """Avoid duplicating NVKMS transitions for per-device channels-only DPM."""
    if (patch_text.count("+++ b/kernel-open/nvidia/nv.c\n") != 1 or
            patch_text.count("+++ b/") != 1 or
            patch_text.count("NV_PM_ACTION_DEPTH_CHANNELS") != 3 or
            patch_text.count("nvidia_modeset_suspend(0);") != 2 or
            patch_text.count("nvidia_modeset_resume(0);") != 4 or
            patch_text.count("PCI DPM") != 2):
        raise ValueError("R580 channel-DPM modeset patch contract is missing or ambiguous")

    def replace_once(text: str, old: str, new: str, label: str) -> str:
        if text.count(old) != 1:
            raise ValueError("R595 channel-DPM " + label + " anchor is missing or ambiguous")
        return text.replace(old, new, 1)

    resume_start = "static NV_STATUS\nnv_resume_devices(\n"
    suspend_start = "static NV_STATUS\nnv_suspend_devices(\n"
    system_pm_start = "NV_STATUS\nnv_set_system_power_state(\n"
    if (nv.count(resume_start) != 1 or nv.count(suspend_start) != 1 or
            nv.count(system_pm_start) != 1 or "PCI DPM" in nv):
        raise ValueError("R595 channel-DPM function anchors are missing or already adapted")
    resume_offset = nv.index(resume_start)
    suspend_offset = nv.index(suspend_start)
    system_pm_offset = nv.index(system_pm_start)
    if not (resume_offset < suspend_offset < system_pm_offset):
        raise ValueError("R595 channel-DPM function ordering changed")

    resume = nv[resume_offset:suspend_offset]
    resume = replace_once(
        resume,
        "resume_modeset:\n    nvidia_modeset_resume(0);\n",
        "resume_modeset:\n"
        "    /* PCI DPM resumed NVKMS per GPU during the channels-only phase. */\n"
        "    if (pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS)\n"
        "    {\n"
        "        nvidia_modeset_resume(0);\n"
        "    }\n",
        "aggregate NVKMS resume")

    suspend = nv[suspend_offset:system_pm_offset]
    suspend = replace_once(
        suspend,
        "    nvidia_modeset_suspend(0);\n",
        "    /* PCI DPM owns NVKMS suspend while aggregate PM only preempts channels. */\n"
        "    if (pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS)\n"
        "    {\n"
        "        nvidia_modeset_suspend(0);\n"
        "    }\n",
        "aggregate NVKMS suspend")
    suspend = replace_once(
        suspend,
        "        nvidia_modeset_resume(0);\n",
        "        if (pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS)\n"
        "        {\n"
        "            nvidia_modeset_resume(0);\n"
        "        }\n",
        "rollback NVKMS resume")
    return nv[:resume_offset] + resume + suspend + nv[system_pm_offset:]


def transform_pm_provider_kernel_r595(kernel_header: str) -> str:
    """Use R595's device list to validate per-minor PM state ownership."""
    old = (
        "static struct hybrid580_pm_provider_recovery_status *\n"
        "hybrid580_pm_provider_status_for_nvl(nv_linux_state_t *nvl)\n"
        "{\n"
        "    NvU32 minor;\n\n"
        "    if (nvl == NULL)\n"
        "        return NULL;\n"
        "    minor = nvl->minor_num;\n"
        "    if (minor > NV_MINOR_DEVICE_NUMBER_REGULAR_MAX ||\n"
        "        nv_linux_minor_num_table[minor] != nvl)\n"
        "        return NULL;\n"
        "    return &hybrid580_pm_provider_status[minor];\n"
        "}\n")
    new = (
        "static struct hybrid580_pm_provider_recovery_status *\n"
        "hybrid580_pm_provider_status_for_nvl(nv_linux_state_t *nvl)\n"
        "{\n"
        "    NvU32 minor;\n"
        "    nv_linux_state_t *candidate;\n\n"
        "    if (nvl == NULL)\n"
        "        return NULL;\n"
        "    minor = nvl->minor_num;\n"
        "    if (minor > NV_MINOR_DEVICE_NUMBER_REGULAR_MAX)\n"
        "        return NULL;\n\n"
        "    /* R595 has a minor bitmap and device list, not the R580 pointer table.\n"
        "     * All callers hold nv_linux_devices_lock while validating ownership. */\n"
        "    for (candidate = nv_linux_devices; candidate != NULL;\n"
        "         candidate = candidate->next)\n"
        "    {\n"
        "        if (candidate == nvl)\n"
        "            return &hybrid580_pm_provider_status[minor];\n"
        "    }\n\n"
        "    return NULL;\n"
        "}\n")
    if kernel_header.count(old) != 1:
        raise ValueError("R595 PM provider minor-table anchor is missing or already adapted")
    if kernel_header.count("nv_linux_minor_num_table") != 1:
        raise ValueError("R595 PM provider minor-table reference is missing or ambiguous")
    return kernel_header.replace(old, new, 1)


def transform_sdk_rs_access_header_r595(sdk_header: str,
                                        kernel_header: str) -> str:
    """Make the private SDK include reuse R595's kernel-open RS_ACCESS types.

    R595 ships two otherwise-identical generated headers at these paths. When
    nvos.h includes the SDK copy and the kernel wrapper later includes the
    kernel-open copy, both ``#pragma once`` directives refer to different
    files and the public struct definitions collide. Preserve the SDK notice,
    but replace its duplicate definitions with an exact relative include of
    the canonical kernel-open header. Refuse any source drift beyond the
    known MSVC-only warning directive.
    """
    msvc_warning = (
        "#if defined(_MSC_VER)\n"
        "#pragma warning(disable:4324)\n"
        "#endif\n")
    if kernel_header.count(msvc_warning) != 1:
        raise ValueError("R595 kernel-open RS_ACCESS MSVC warning block is missing or ambiguous")
    if kernel_header.replace(msvc_warning, "", 1) != sdk_header:
        raise ValueError("R595 SDK and kernel-open RS_ACCESS headers differ beyond the pinned warning block")
    pragma = "#pragma once\n"
    if sdk_header.count(pragma) != 1:
        raise ValueError("R595 SDK RS_ACCESS pragma anchor is missing or ambiguous")
    prefix = sdk_header.split(pragma, 1)[0] + pragma
    return (prefix + "\n"
            "/* Private R595 build adapter: share the kernel-open RS_ACCESS\n"
            " * declarations with nvos.h instead of compiling duplicate types. */\n"
            '#include "../../../../../kernel-open/common/inc/rs_access.h"\n')


def transform_pci_only_lifecycle(nv: str, pci_table: str,
                                platform: str) -> tuple[str, str, str]:
    """Keep only the exact-BDF PCI path; suppress NVSwitch/platform claiming."""
    substitutions = (
        ('''static void
nvlink_drivers_exit(void)
{
#if NVCPU_IS_64_BITS
    nvswitch_exit();
#endif

    nvlink_core_exit();
}
''', '''static void
nvlink_drivers_exit(void)
{
    /* PCI-GPU-only private backend: no NVSwitch driver was registered. */
    nvlink_core_exit();
}
'''),
        ('''#if NVCPU_IS_64_BITS
    rc = nvswitch_init();
    if (rc < 0)
    {
        nv_printf(NV_DBG_INFO, "NVRM: NVSwitch init failed.\\n");
        nvlink_core_exit();
    }
#endif
''', '''    /* NVLink core is retained; NVSwitch probing is outside this backend. */
'''),
        ('''static void
nv_drivers_exit(void)
{
#if NV_SUPPORTS_PLATFORM_DEVICE
    nv_platform_unregister_driver();
#endif
    nv_pci_unregister_driver();
}
''', '''static void
nv_drivers_exit(void)
{
    nv_pci_unregister_driver();
}
'''),
        ('''#if NV_SUPPORTS_PLATFORM_DEVICE
    rc = nv_platform_register_driver();
    if (rc < 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: SOC driver registration failed!\\n");
        nv_pci_unregister_driver();
        rc = -ENODEV;
    }
#endif
''', '''    /* Only the BDF-filtered GPU PCI driver is registered by this backend. */
'''),
        ('const NvBool is_nvswitch_present = os_is_nvswitch_present();',
         'const NvBool is_nvswitch_present = NV_FALSE;'),
        ('    nplatform = nv_platform_count_devices();\n',
         '    /* Platform devices are not registered by this PCI-only backend. */\n'),
    )
    for old, new in substitutions:
        if nv.count(old) != 1:
            raise ValueError("R595 PCI-only lifecycle anchor is missing or ambiguous: " +
                             old.splitlines()[0].strip())
        nv = nv.replace(old, new, 1)

    pci_autoload = "MODULE_DEVICE_TABLE(pci, nv_module_device_table);"
    of_autoload = "MODULE_DEVICE_TABLE(of, nv_platform_device_table);"
    if pci_table.count(pci_autoload) != 1 or platform.count(of_autoload) != 1:
        raise ValueError("R595 hardware autoload table anchor is missing or ambiguous")
    pci_table = pci_table.replace(
        pci_autoload, "/* Private prototype is loaded explicitly; no public PCI alias. */", 1)
    platform = platform.replace(
        of_autoload, "/* Private prototype is loaded explicitly; no public OF alias. */", 1)
    return nv, pci_table, platform


def parse_symvers(text: str) -> dict[str, str]:
    exports: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 4 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", fields[1]):
            raise ValueError(f"invalid Module.symvers row at line {line_number}")
        name, flavor = fields[1], fields[3]
        if flavor not in {"EXPORT_SYMBOL", "EXPORT_SYMBOL_GPL"}:
            raise ValueError(f"unsupported export flavor at line {line_number}")
        if name in exports:
            raise ValueError(f"duplicate Module.symvers export: {name}")
        exports[name] = flavor
    if not exports:
        raise ValueError("Module.symvers has no exports")
    return exports


def private_export_header(exports: dict[str, str]) -> str:
    if any(name.startswith(PRIVATE_PREFIX) for name in exports):
        raise ValueError("baseline already contains a private-prefix export")
    header = ["/* SPDX-License-Identifier: MIT */",
              "/* Compile-only R595 Open backend export namespace. */",
              "#ifndef HYBRID580_OPEN_EXPORTS_H",
              "#define HYBRID580_OPEN_EXPORTS_H"]
    header.extend(f"#define {name} {PRIVATE_PREFIX}{name}" for name in sorted(exports))
    header.append("#endif")
    return "\n".join(header) + "\n"


def validate_private_exports(original: dict[str, str], actual: dict[str, str],
                             extra_exports: dict[str, str] | None = None) -> None:
    expected = {PRIVATE_PREFIX + name: flavor for name, flavor in original.items()}
    additions = {} if extra_exports is None else dict(extra_exports)
    if expected.keys() & additions.keys():
        raise ValueError("additional private export duplicates a wrapped baseline export")
    expected.update(additions)
    if actual != expected:
        raise ValueError("private export set/flavors differ from wrapped baseline and explicit APIs")


def parse_nm_symbols(path: Path) -> tuple[set[str], set[str]]:
    output = subprocess.check_output(["nm", "-g", str(path)], text=True,
                                     errors="replace")
    defined: set[str] = set()
    undefined: set[str] = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        if fields[-2] in {"U", "w", "v"}:
            undefined.add(fields[-1])
        else:
            defined.add(fields[-1])
    return defined, undefined


def run_logged(name: str, argv: list[str], cwd: Path, log: Path,
               steps: list[dict], timeout: int = 1800) -> str:
    log.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    with log.open("x", encoding="utf-8") as output:
        os.chmod(log, 0o600)
        output.write("$ " + " ".join(argv) + "\ncwd: " + str(cwd) + "\n")
        output.flush()
        try:
            code = subprocess.run(argv, cwd=cwd, stdout=output,
                                  stderr=subprocess.STDOUT, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            code = 124
    steps.append({"name": name, "argv": argv, "cwd": str(cwd),
                  "exit_code": code, "log": str(log.relative_to(ROOT)),
                  "log_sha256": sha256(log),
                  "duration_seconds": round(time.monotonic() - start, 3)})
    if code:
        raise RuntimeError(f"{name} failed; see {log.relative_to(ROOT)}")
    return log.read_text(errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--kernel-release", default="7.0.0-38-generic")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    report_path = args.report.resolve()
    if args.jobs < 1 or work.exists() or report_path.exists():
        parser.error("positive jobs and unused work/report paths are required")
    if not work.is_relative_to(ROOT / "build/experiments"):
        parser.error("work directory must remain under build/experiments")
    if not report_path.is_relative_to(ROOT / "evidence"):
        parser.error("report must remain under evidence")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report: dict = {
        "schema": "private-open595-wrapper-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "not-started",
        "loaded_or_installed": False,
        "hardware_validated": False,
        "gpu_accessed": False,
        "source_version": "595.99.02",
        "private_module_name": PRIVATE_MODULE,
        "private_export_prefix": PRIVATE_PREFIX,
        "kernel_release": args.kernel_release,
        "source": str(SOURCE),
        "core": str(CORE),
        "work_dir": str(work),
        "steps": [],
    }

    def step(name: str, argv: list[str], cwd: Path, timeout: int = 1800) -> str:
        log = ROOT / "evidence/logs" / f"r595-private-open-{name}-{stamp}.log"
        return run_logged(name, argv, cwd, log, report["steps"], timeout)

    source_before = None
    core_before = None
    try:
        if not SOURCE.is_dir() or not CORE.is_file():
            raise FileNotFoundError("pinned R595 source or core is unavailable")
        if "NVIDIA_VERSION = 595.99.02" not in (SOURCE / "version.mk").read_text():
            raise ValueError("R595 source version anchor does not match 595.99.02")
        source_before = source_tree_digest(SOURCE)
        core_before = sha256(CORE)
        report.update(source_tree_manifest_sha256=source_before[0],
                      source_file_count=source_before[1], core_sha256=core_before)
        if source_before != (SOURCE_TREE_SHA256, SOURCE_FILE_COUNT):
            raise ValueError("R595 source snapshot differs from pinned content manifest")
        if core_before != CORE_SHA256:
            raise ValueError("R595 core binary differs from pinned SHA-256")

        work.mkdir(parents=True)
        baseline = work / "baseline/source"
        private = work / "private/source"
        baseline.parent.mkdir(parents=True)
        private.parent.mkdir(parents=True)
        shutil.copytree(SOURCE, baseline, symlinks=True)
        shutil.copytree(SOURCE, private, symlinks=True)
        for tree in (baseline, private):
            shutil.copy2(CORE, tree / "kernel-open/nvidia/nv-kernel.o_binary")

        common = ["KERNEL_UNAME=" + args.kernel_release,
                  "NV_KERNEL_MODULES=nvidia", "-j" + str(args.jobs), "modules"]
        step("baseline-build", ["make", "-C", str(baseline / "kernel-open"), *common], ROOT)
        baseline_module = baseline / "kernel-open/nvidia.ko"
        baseline_symvers = baseline / "kernel-open/Module.symvers"
        if not baseline_module.is_file() or not baseline_symvers.is_file():
            raise RuntimeError("baseline build lacks nvidia.ko or Module.symvers")
        original = parse_symvers(baseline_symvers.read_text())
        core_defined, core_undefined = parse_nm_symbols(CORE)
        core_collisions = set(original) & (core_defined | core_undefined)
        if core_collisions:
            raise ValueError("R595 core directly references or defines wrapped exports: " +
                             ",".join(sorted(core_collisions)))
        report["baseline"] = {
            "module_sha256": sha256(baseline_module),
            "module_bytes": baseline_module.stat().st_size,
            "symvers_sha256": sha256(baseline_symvers),
            "export_count": len(original),
            "export_flavors": {flavor: sum(value == flavor for value in original.values())
                               for flavor in sorted(set(original.values()))},
            "core_export_symbol_collisions": 0,
        }

        sdk_rs_access = private / "src/common/sdk/nvidia/inc/rs_access.h"
        kernel_rs_access = private / "kernel-open/common/inc/rs_access.h"
        sdk_rs_access_original_sha256 = sha256(sdk_rs_access)
        sdk_rs_access.write_text(transform_sdk_rs_access_header_r595(
            sdk_rs_access.read_text(), kernel_rs_access.read_text()))
        report["compile_adaptations"] = [{
            "path": str(sdk_rs_access.relative_to(private)),
            "source_sha256": sdk_rs_access_original_sha256,
            "adapted_sha256": sha256(sdk_rs_access),
            "shared_header": str(kernel_rs_access.relative_to(private)),
            "reason": "nvos.h and kernel-open must share one R595 RS_ACCESS declaration set",
            "scope": "private compile copy only",
        }]

        kbuild = private / "kernel-open/nvidia/nvidia.Kbuild"
        linux_header = private / "kernel-open/common/inc/nv-linux.h"
        pci_source = private / "kernel-open/nvidia/nv-pci.c"
        nv_source = private / "kernel-open/nvidia/nv.c"
        procfs_source = private / "kernel-open/nvidia/nv-procfs.c"
        pci_table_source = private / "kernel-open/nvidia/nv-pci-table.c"
        platform_source = private / "kernel-open/nvidia/nv-platform.c"
        kbuild.write_text(transform_kbuild(kbuild.read_text()))
        linux_header.write_text(transform_module_name(linux_header.read_text()))
        pci_source.write_text(transform_nv_pci_selection(pci_source.read_text()))
        nv_source.write_text(transform_private_chardev(nv_source.read_text()))
        procfs_source.write_text(transform_procfs_path(procfs_source.read_text()))
        nv_text, pci_table_text, platform_text = transform_pci_only_lifecycle(
            nv_source.read_text(), pci_table_source.read_text(), platform_source.read_text())
        nv_source.write_text(nv_text)
        pci_table_source.write_text(pci_table_text)
        platform_source.write_text(platform_text)
        if not PROJECTION_PATCH.is_file():
            raise FileNotFoundError("pinned R580 file-projection patch is unavailable")
        projection_patch = PROJECTION_PATCH.read_text()
        nv_source.write_text(transform_file_projection_r595(nv_source.read_text(),
                                                             projection_patch))
        projection_header = private / "kernel-open/nvidia/hybrid580-file-projection.h"
        if projection_header.exists():
            raise ValueError("unexpected preexisting R595 projection ABI header")
        projection_header.write_text(extract_projection_api_header(projection_patch))
        if not CONTROL_SESSION_PATCH.is_file():
            raise FileNotFoundError("pinned R580 control-session patch is unavailable")
        control_patch = CONTROL_SESSION_PATCH.read_text()
        nv_text, kbuild_text = transform_control_session_r595(
            nv_source.read_text(), kbuild.read_text(), control_patch)
        nv_source.write_text(nv_text)
        kbuild.write_text(kbuild_text)
        control_header = private / "kernel-open/nvidia/hybrid580-control-session.h"
        if control_header.exists():
            raise ValueError("unexpected preexisting R595 control-session API header")
        control_header.write_text(extract_control_session_api_header(control_patch))
        if not DEVICE_MAPPING_UPDATE_PATCH.is_file():
            raise FileNotFoundError("pinned NVOS56 mapping-update patch is unavailable")
        nv_text, control_header_text, mapping_update_apis = (
            transform_update_device_mapping_info_r595(
                nv_source.read_text(), control_header.read_text(),
                DEVICE_MAPPING_UPDATE_PATCH.read_text()))
        if mapping_update_apis != list(DEVICE_MAPPING_UPDATE_EXPORTS):
            raise ValueError("R595 NVOS56 export contract differs from the pinned API")
        nv_source.write_text(nv_text)
        control_header.write_text(control_header_text)
        endpoint_header = private / "kernel-open/nvidia/rm_session_endpoint.h"
        endpoint_source = ROOT / "src/rm_session_endpoint.h"
        if endpoint_header.exists() or not endpoint_source.is_file():
            raise ValueError("shared RM endpoint header is missing or already present")
        shutil.copy2(endpoint_source, endpoint_header)
        export_header = private / "kernel-open/nvidia/hybrid580-open-exports.h"
        if export_header.exists():
            raise ValueError("unexpected preexisting private export header")
        export_header.write_text(private_export_header(original))
        report["private_source_adaptations"] = {
            str(path.relative_to(private)): sha256(path)
            for path in (kbuild, linux_header, pci_source, nv_source, procfs_source,
                         pci_table_source, platform_source, projection_header,
                         control_header, endpoint_header, export_header)
        }
        step("private-build", ["make", "-C", str(private / "kernel-open"), *common], ROOT)
        module = private / "kernel-open/hybrid580_open.ko"
        private_symvers = private / "kernel-open/Module.symvers"
        if not module.is_file() or not private_symvers.is_file():
            raise RuntimeError("private build lacks hybrid580_open.ko or Module.symvers")
        actual = parse_symvers(private_symvers.read_text())
        validate_private_exports(original, actual,
                                 PROJECTION_EXPORTS | CONTROL_SESSION_EXPORTS |
                                 DEVICE_MAPPING_UPDATE_EXPORTS)
        info = step("modinfo", ["modinfo", str(module)], ROOT)
        metadata: dict[str, list[str]] = {}
        for line in info.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                metadata.setdefault(key, []).append(value.strip())
        if metadata.get("name") != [PRIVATE_MODULE]:
            raise ValueError("private module name mismatch")
        if metadata.get("license") != ["Dual MIT/GPL"]:
            raise ValueError("private module license metadata mismatch")
        if not metadata.get("vermagic", [""])[0].startswith(args.kernel_release + " "):
            raise ValueError("private module kernel vermagic mismatch")
        defined, undefined = parse_nm_symbols(module)
        old_names = set(original) & defined
        if old_names:
            raise ValueError("unprefixed baseline exports retained in module: " +
                             ",".join(sorted(old_names)))
        expected_names = {PRIVATE_PREFIX + name for name in original}
        if not expected_names <= defined:
            raise ValueError("private module ELF lacks expected namespaced exports")
        if sha256(private / "kernel-open/nvidia/nv-kernel.o_binary") != CORE_SHA256:
            raise ValueError("R595 core binary changed in private build tree")
        report.update(
            qualification="compiled-private-r595-open-wrapper-only",
            private_module={"path": str(module), "sha256": sha256(module),
                            "bytes": module.stat().st_size,
                            "symvers_sha256": sha256(private_symvers),
                            "export_count": len(actual)},
            metadata=metadata,
            undefined_symbol_count=len(undefined),
            unprefixed_export_definitions=sorted(old_names),
            source_wrapper_changes=[
                {"path": str(kbuild), "sha256": sha256(kbuild)},
                {"path": str(linux_header), "sha256": sha256(linux_header)},
                {"path": str(pci_source), "sha256": sha256(pci_source)},
                {"path": str(nv_source), "sha256": sha256(nv_source)},
                {"path": str(procfs_source), "sha256": sha256(procfs_source)},
                {"path": str(pci_table_source), "sha256": sha256(pci_table_source)},
                {"path": str(platform_source), "sha256": sha256(platform_source)},
                {"path": str(control_header), "sha256": sha256(control_header)},
                {"path": str(export_header), "sha256": sha256(export_header)}],
            isolation_contract={
                "bdf_selector_default": "deny",
                "device_probe_gate_precedes_bar_and_rm": True,
                "public_char_major_alias_removed": True,
                "character_major": "dynamic",
                "registered_file_operations_checked": True,
                "runtime_validated": False,
            },
            source_tree_unchanged=True,
            core_unchanged=True,
            inputs_unchanged=True,
            warnings=[line.strip() for item in report["steps"]
                      if item["name"] == "private-build"
                      for line in (ROOT / item["log"]).read_text(errors="replace").splitlines()
                      if "warning:" in line.lower()],
        )
    except Exception as error:
        report.update(qualification="failed", error=f"{type(error).__name__}: {error}")
    try:
        source_after = source_tree_digest(SOURCE)
        core_after = sha256(CORE)
        report["source_tree_unchanged"] = source_before is None or source_after == source_before
        report["core_input_unchanged"] = core_before is None or core_after == core_before
        report["inputs_unchanged"] = report["source_tree_unchanged"] and report["core_input_unchanged"]
        if not report["inputs_unchanged"]:
            report["qualification"] = "failed"
            report.setdefault("error", "pinned source or core changed during build")
    except OSError as error:
        report.update(qualification="failed",
                      inputs_unchanged=False,
                      error=f"input verification failed: {type(error).__name__}: {error}")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    os.chmod(report_path, 0o600)
    print(json.dumps({"qualification": report["qualification"],
                      "report": str(report_path), "error": report.get("error"),
                      "private_module": report.get("private_module")}, sort_keys=True))
    return 0 if report["qualification"] == "compiled-private-r595-open-wrapper-only" else 1


if __name__ == "__main__":
    raise SystemExit(main())
