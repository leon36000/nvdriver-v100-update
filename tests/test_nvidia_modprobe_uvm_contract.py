# SPDX-License-Identifier: MIT
"""Exercise pinned NVIDIA UVM helper reads against isolated synthetic inputs."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/upstream/nvidia-modprobe-4ffadd6b"
UPSTREAM_HASHES = {
    "nvidia-modprobe-utils.c": "0d293dc50bbcd26c4829408a63dd0dbcdc892c4ffb900620f761dbd112813f4d",
    "nvidia-modprobe-utils.h": "c4d3501a09924ab3a2a7d73a7273598442af4995ae6e5263f6be938623a28541",
    "pci-enum.h": "ba186befe87b3568da15c74fd0054338f8375be967b07f48c9aeb4e2f1c217cb",
}
HARNESS = r'''#include <stdio.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "nvidia-modprobe-utils.h"
#include "pci-enum.h"

static int test_root;
static int spawn_count;
static char spawned_module[64];

uid_t geteuid(void) { return test_root ? 0 : 1000; }
int pci_enum_match_id(struct pci_id_match *match)
{
    match->num_matches = 1;
    return 0;
}
int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *actions,
                const posix_spawnattr_t *attributes,
                char *const argv[], char *const envp[])
{
    (void)path;
    (void)actions;
    (void)attributes;
    (void)envp;
    spawn_count++;
    if (argv != NULL && argv[1] != NULL) {
        snprintf(spawned_module, sizeof(spawned_module), "%s", argv[1]);
    }
    *pid = 1234;
    return 0;
}
pid_t waitpid(pid_t pid, int *status, int options)
{
    (void)status;
    (void)options;
    return pid;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    test_root = strcmp(argv[1], "root") == 0;
    if (strcmp(argv[2], "uvm-modprobe") == 0) {
        int result = nvidia_uvm_modprobe();
        printf("%d|%d|%s\n", result, spawn_count, spawned_module);
        return 0;
    }
    if (strcmp(argv[2], "nvidia-modprobe") == 0) {
        int result = nvidia_modprobe(0);
        printf("%d|%d|%s\n", result, spawn_count, spawned_module);
        return 0;
    }
    if (strcmp(argv[2], "uvm-major") == 0) {
        printf("%d\n", nvidia_get_chardev_major("nvidia-uvm"));
        return 0;
    }
    return 2;
}
'''


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NvidiaModprobeUvmContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc")
        if compiler is None:
            raise AssertionError("a C compiler is required for the pinned helper harness")
        for name, expected in UPSTREAM_HASHES.items():
            path = FIXTURE / name
            if not path.is_file() or sha256(path) != expected:
                raise AssertionError(f"pinned NVIDIA source fixture differs: {path}")

        cls.temporary = tempfile.TemporaryDirectory(prefix="nvidia-modprobe-uvm-contract-")
        cls.root = Path(cls.temporary.name)
        include = cls.root / "include"
        include.mkdir()
        for name in ("nvidia-modprobe-utils.h", "pci-enum.h"):
            shutil.copyfile(FIXTURE / name, include / name)

        source = (FIXTURE / "nvidia-modprobe-utils.c").read_text(encoding="utf-8")
        proc_devices = cls.root / "proc/devices"
        proc_devices.parent.mkdir()
        sys_module_prefix = str(cls.root / "sys/module") + "/"
        substitutions = (
            ('#define NV_PROC_DEVICES_PATH "/proc/devices"',
             "#define NV_PROC_DEVICES_PATH " + json.dumps(str(proc_devices))),
            ('#define NV_PROC_MODPROBE_PATH "/proc/sys/kernel/modprobe"',
             "#define NV_PROC_MODPROBE_PATH " +
             json.dumps(str(cls.root / "proc/sys/kernel/modprobe"))),
            ('"/sys/module/%s/initstate"',
             json.dumps(sys_module_prefix + "%s/initstate")),
            ('strlen("/sys/module/")',
             "strlen(" + json.dumps(sys_module_prefix) + ")"),
        )
        for original, replacement in substitutions:
            if source.count(original) != 1:
                raise AssertionError(f"upstream helper path anchor changed: {original}")
            source = source.replace(original, replacement, 1)

        source_path = cls.root / "nvidia-modprobe-utils.c"
        source_path.write_text(source, encoding="utf-8")
        harness_path = cls.root / "harness.c"
        harness_path.write_text(HARNESS, encoding="utf-8")
        cls.executable = cls.root / "helper-contract"
        compiled = subprocess.run(
            [compiler, "-DNV_LINUX", "-ffunction-sections", "-fdata-sections",
             "-Wl,--gc-sections", "-I", str(include), str(source_path),
             str(harness_path), "-o", str(cls.executable)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if compiled.returncode != 0:
            raise AssertionError("pinned NVIDIA helper fixture did not compile:\n" + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        (self.root / "proc/devices").write_text(
            "Character devices:\n\nBlock devices:\n", encoding="ascii")
        fake_modprobe = self.root / "sbin/modprobe"
        fake_modprobe.parent.mkdir(parents=True, exist_ok=True)
        fake_modprobe.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        fake_modprobe.chmod(0o700)
        modprobe_path = self.root / "proc/sys/kernel/modprobe"
        modprobe_path.parent.mkdir(parents=True, exist_ok=True)
        modprobe_path.write_text(str(fake_modprobe) + "\n", encoding="ascii")
        shutil.rmtree(self.root / "sys", ignore_errors=True)

    def run_helper(self, operation, identity="user"):
        result = subprocess.run(
            [str(self.executable), identity, operation], capture_output=True, text=True,
            timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return result.stdout.strip()

    def mark_loaded(self, module_name):
        initstate = self.root / "sys/module" / module_name / "initstate"
        initstate.parent.mkdir(parents=True, exist_ok=True)
        initstate.write_text("live\n", encoding="ascii")

    def test_standard_uvm_module_identity_short_circuits_helper_as_loaded(self):
        self.mark_loaded("nvidia_uvm")
        self.assertEqual(self.run_helper("uvm-modprobe"), "1|0|")

    def test_standard_frontend_module_identity_short_circuits_helper_as_loaded(self):
        self.mark_loaded("nvidia")
        self.assertEqual(self.run_helper("nvidia-modprobe"), "1|0|")

    def test_private_uvm_module_identity_does_not_satisfy_standard_name_check(self):
        self.mark_loaded("hybrid580_uvm")
        self.assertEqual(self.run_helper("uvm-modprobe"), "0|0|")

    def test_spawn_success_without_standard_module_sysfs_still_fails_postcheck(self):
        self.mark_loaded("hybrid580_uvm")
        self.assertEqual(self.run_helper("uvm-modprobe", identity="root"),
                         "0|1|nvidia-uvm")

    def test_private_frontend_alias_request_still_fails_standard_nvidia_postcheck(self):
        self.mark_loaded("hybrid580_frontend")
        self.assertEqual(self.run_helper("nvidia-modprobe", identity="root"),
                         "0|1|nvidia")

    def test_chardev_lookup_returns_first_exact_registration_label(self):
        (self.root / "proc/devices").write_text(
            "Character devices:\n"
            "  7 nvidia-uvm-tools\n"
            " 511 nvidia-uvm\n"
            " 520 nvidia-uvm\n"
            "\nBlock devices:\n"
            " 530 nvidia-uvm\n",
            encoding="ascii",
        )
        self.assertEqual(self.run_helper("uvm-major"), "511")

    def test_chardev_lookup_ignores_partial_names_and_block_devices(self):
        (self.root / "proc/devices").write_text(
            "Character devices:\n"
            "  7 nvidia-uvm-tools\n"
            "\nBlock devices:\n"
            " 530 nvidia-uvm\n",
            encoding="ascii",
        )
        self.assertEqual(self.run_helper("uvm-major"), "-1")


if __name__ == "__main__":
    unittest.main()
