# SPDX-License-Identifier: MIT
"""Pin the R580 channels-only system-PM phase contract for both backends."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
OPEN_SOURCE = ROOT / "build/experiments/r580-uvm-clean-v3-20261021/source"
OPEN_PROVIDER_SOURCE = ROOT / "build/experiments/private-open-pm-recovery-provider-v3-20261021/NVIDIA-kernel-module-source-580.178.04/kernel-open"
LEGACY_SOURCE = ROOT / ".cache/vendor-proprietary/r580.178.04-ubuntu/usr/src/nvidia-580.178.04"
ENUM_OPEN_PATCH = ROOT / "patches/r580.178.04/0001-private-open-pm-channel-depth-enum.patch"
ENUM_LEGACY_PATCH = ROOT / "patches/r580.178.04/proprietary/0001-private-legacy-pm-channel-depth-enum.patch"
OPEN_PATCH = ROOT / "patches/r580.178.04/0031-private-open-pm-channel-depth.patch"
LEGACY_PATCH = ROOT / "patches/r580.178.04/proprietary/0031-private-legacy-pm-channel-depth.patch"
LEGACY_PROCFS_PATCH = ROOT / "patches/r580.178.04/proprietary/0032-private-legacy-pm-procfs-channel-depth.patch"
OPEN_VMA_ACCESS_PATCH = ROOT / "patches/r580.178.04/0033-private-open-pm-vma-access-guard.patch"
LEGACY_VMA_ACCESS_PATCH = ROOT / "patches/r580.178.04/proprietary/0033-private-legacy-pm-vma-access-guard.patch"
OPEN_VMA_FREE_LIST_PATCH = ROOT / "patches/r580.178.04/0034-private-open-vma-free-list-lock.patch"
LEGACY_VMA_FREE_LIST_PATCH = ROOT / "patches/r580.178.04/proprietary/0034-private-legacy-vma-free-list-lock.patch"
OPEN_DPM_MODESET_PATCH = ROOT / "patches/r580.178.04/0036-private-open-pm-channel-dpm-modeset.patch"
LEGACY_DPM_MODESET_PATCH = ROOT / "patches/r580.178.04/proprietary/0036-private-legacy-pm-channel-dpm-modeset.patch"

sys.path.insert(0, str(ROOT / "tools"))
from audit_uvm_pm_lifecycle import function_body
import build_private_proprietary580 as legacy_builder


class HybridPmChannelDepthTests(unittest.TestCase):
    def _patched_source(self, source_root: Path, patch_files: tuple[Path, ...], prefix: str) -> Path:
        self.assertTrue(source_root.is_dir(), f"pinned baseline missing: {source_root}")
        for patch_file in patch_files:
            self.assertTrue(patch_file.is_file(), f"R580 PM-depth patch missing: {patch_file}")
        scratch = Path(tempfile.mkdtemp(prefix="hybrid-pm-depth-"))
        for relative in ("common/inc/nv.h", "common/inc/nv-linux.h", "nvidia/nv.c",
                         "nvidia/nv-procfs.c", "nvidia/nv-mmap.c"):
            source = source_root / prefix / relative if prefix else source_root / relative
            target = scratch / prefix / relative if prefix else scratch / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        for patch_file in patch_files:
            result = subprocess.run(
                ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch_file)],
                cwd=scratch, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return scratch

    def test_open_backend_builder_exposes_opt_in_phase(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/probe_private_backend_chardev.py"), "--help"],
            cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--hybrid-pm-depth", result.stdout)

    def _assert_channel_phase(self, scratch: Path, prefix: str) -> None:
        root = scratch / prefix if prefix else scratch
        header = (root / "common/inc/nv.h").read_text()
        procfs = (root / "nvidia/nv-procfs.c").read_text()
        driver = (root / "nvidia/nv.c").read_text()
        self.assertRegex(header, r"NV_PM_ACTION_DEPTH_UVM\s*,\s*NV_PM_ACTION_DEPTH_CHANNELS")
        self.assertIn('strcasecmp(kbuf, "channels")', procfs)
        self.assertIn('sizeof("channels\\n")', procfs)

        suspend, _ = function_body(driver, "nv_suspend_devices")
        self.assertLess(suspend.index("nv_preempt_user_channels"),
                        suspend.index("nv_uvm_suspend"))
        self.assertIn("pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS", suspend)
        self.assertIn("pm_action_depth == NV_PM_ACTION_DEPTH_CHANNELS", suspend)
        self.assertLess(suspend.index("pm_action_depth == NV_PM_ACTION_DEPTH_CHANNELS"),
                        suspend.index("nvidia_suspend(nvl->dev"))
        self.assertRegex(
            suspend,
            r"if \(pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS\)\s*\{\s*"
            r"nvidia_modeset_suspend\(0\);",
        )
        suspend_rollback = suspend[suspend.index("done:"):]
        self.assertRegex(
            suspend_rollback,
            r"if \(pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS\)\s*\{\s*"
            r"nvidia_modeset_resume\(0\);",
        )

        per_gpu_suspend, _ = function_body(driver, "nvidia_suspend")
        self.assertIn("nvidia_modeset_suspend(nv->gpu_id);", per_gpu_suspend)
        per_gpu_resume, _ = function_body(driver, "nvidia_resume")
        self.assertIn("nvidia_modeset_resume(nv->gpu_id);", per_gpu_resume)
        self.assertIn("if (uvm_suspended)\n        {\n            cleanup_status = nv_uvm_resume();", suspend)

        resume, _ = function_body(driver, "nv_resume_devices")
        self.assertIn("NV_PM_ACTION_DEPTH_CHANNELS", resume)
        self.assertIn("resume_uvm = NV_FALSE", resume)
        self.assertLess(resume.index("NvBool resume_uvm"),
                        resume.index("pm_action_depth == NV_PM_ACTION_DEPTH_MODESET"))
        self.assertLess(resume.index("if (resume_uvm)"), resume.index("nv_restore_user_channels"))
        self.assertRegex(
            resume,
            r"if \(pm_action_depth == NV_PM_ACTION_DEPTH_CHANNELS\)[\s\S]*?"
            r"resume_devices = NV_FALSE;[\s\S]*?resume_uvm = NV_FALSE;",
        )
        self.assertRegex(
            resume,
            r"if \(resume_uvm\)\s*\{\s*status = nv_uvm_resume\(\);",
        )
        self.assertRegex(
            resume,
            r"resume_modeset:\s*if \(pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS\)\s*\{\s*"
            r"nvidia_modeset_resume\(0\);",
        )

        self.assertTrue(".mmap      = nv_mmap_pm_guard" in driver,
                        "native file operations still bypass the PM-aware mmap gate")
        mmap_guard, _ = function_body(driver, "nv_mmap_pm_guard")
        self.assertIn("down_read_trylock(&nv_system_pm_lock)", mmap_guard)
        self.assertIn("return -EAGAIN;", mmap_guard)
        self.assertIn("status = nvidia_mmap(file, vma);", mmap_guard)
        self.assertIn("up_read(&nv_system_pm_lock);", mmap_guard)

        open_body, _ = function_body(driver, "nvidia_open")
        control_open = open_body[open_body.index("if (nv_is_control_device(inode))"):]
        self.assertLess(control_open.index("nv_down_read_interruptible(&nv_system_pm_lock)"),
                        control_open.index("nvidia_ctl_open(inode, file)"))
        self.assertLess(control_open.index("nvidia_ctl_open(inode, file)"),
                        control_open.index("up_read(&nv_system_pm_lock)"))
        self.assertIn("nv_kmem_cache_free_stack(sp);", control_open)

        close_body, _ = function_body(driver, "nvidia_close")
        control_close = close_body[close_body.index("if (nv_is_control_device(inode))"):]
        self.assertIn("NV_SET_FILE_PRIVATE(file, NULL);", control_close)
        self.assertIn("nv_down_read_interruptible(&nv_system_pm_lock)", control_close)
        self.assertIn("nvidia_ctl_close_callback(nvlfp);", control_close)
        self.assertIn("nvidia_ctl_close_deferred", control_close)

        ctl_close, _ = function_body(driver, "nvidia_ctl_close_callback")
        self.assertIn("rm_cleanup_file_private", ctl_close)
        self.assertIn("nv_free_file_private(nvlfp);", ctl_close)
        self.assertNotIn("struct file *", ctl_close)
        ctl_close_deferred, _ = function_body(driver, "nvidia_ctl_close_deferred")
        self.assertIn("down_read(&nv_system_pm_lock);", ctl_close_deferred)
        self.assertIn("nvidia_ctl_close_callback(nvlfp);", ctl_close_deferred)
        self.assertIn("up_read(&nv_system_pm_lock);", ctl_close_deferred)

        mmap_source = (root / "nvidia/nv-mmap.c").read_text()
        access, _ = function_body(mmap_source, "nvidia_vma_access")
        self.assertIn("down_read_trylock(&nv_system_pm_lock)", access)
        self.assertIn("return -EAGAIN;", access)
        self.assertIn("nvidia_vma_access_unlocked(vma, addr, buffer, length, write)", access)
        self.assertIn("up_read(&nv_system_pm_lock);", access)

        linux_header = (root / "common/inc/nv-linux.h").read_text()
        release, _ = function_body(linux_header, "nv_alloc_release")
        lock = release.index("NV_SPIN_LOCK_IRQSAVE(&nvlfp->fp_lock, eflags)")
        decrement = release.index("atomic64_dec_and_test(&at->usage_count)")
        insertion = release.index("nvlfp->free_list = at;")
        self.assertLess(lock, decrement)
        self.assertLess(decrement, insertion)
        self.assertEqual(release.count("NV_SPIN_UNLOCK_IRQRESTORE(&nvlfp->fp_lock, eflags)"), 2)
        self.assertLess(insertion,
                        release.rindex("NV_SPIN_UNLOCK_IRQRESTORE(&nvlfp->fp_lock, eflags)"))

    def test_open_backend_has_channels_only_phase(self):
        scratch = self._patched_source(OPEN_SOURCE,
                                       (ENUM_OPEN_PATCH, OPEN_PATCH,
                                        OPEN_VMA_ACCESS_PATCH,
                                        OPEN_VMA_FREE_LIST_PATCH,
                                        OPEN_DPM_MODESET_PATCH), "kernel-open")
        try:
            self._assert_channel_phase(scratch, "kernel-open")
        finally:
            shutil.rmtree(scratch)

    def test_open_provider_patch_has_zero_offset_on_composed_source(self):
        source = OPEN_PROVIDER_SOURCE / "nvidia/nv.c"
        self.assertTrue(source.is_file(), f"pinned Open provider source missing: {source}")
        with tempfile.TemporaryDirectory(prefix="open-pm-dpm-offset-") as temp:
            scratch = Path(temp)
            target = scratch / "kernel-open/nvidia/nv.c"
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            result = subprocess.run(
                ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(OPEN_DPM_MODESET_PATCH)],
                cwd=scratch, text=True, capture_output=True, check=False)
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            self.assertNotRegex(output, r"\b(?:offset|fuzz)\b")
            driver = target.read_text()
            suspend, _ = function_body(driver, "nv_suspend_devices")
            self.assertRegex(
                suspend[suspend.index("done:"):],
                r"if \(pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS\)\s*\{\s*"
                r"nvidia_modeset_resume\(0\);",
            )

    def test_proprietary_backend_has_channels_only_phase(self):
        scratch = self._patched_source(LEGACY_SOURCE,
                                       (ENUM_LEGACY_PATCH, LEGACY_PATCH,
                                        LEGACY_PROCFS_PATCH,
                                        LEGACY_VMA_ACCESS_PATCH,
                                        LEGACY_VMA_FREE_LIST_PATCH,
                                        LEGACY_DPM_MODESET_PATCH), "")
        try:
            self._assert_channel_phase(scratch, "")
        finally:
            shutil.rmtree(scratch)

    def test_proprietary_pm_patch_has_zero_offset_on_composed_source(self):
        relative = "nvidia/nv.c"
        previous = (legacy_builder.PREVIOUS_SOURCE / relative).read_text()
        if previous.startswith("/*\n * " + legacy_builder.NOTICE_ID + "\n"):
            _, separator, previous = previous.partition(" */\n")
            self.assertTrue(separator)
        extras = (
            ("nvidia/hybrid580-control-session.h", legacy_builder.PREVIOUS_CONTROL_HEADER),
            ("nvidia/nv-procfs.c", legacy_builder.PREVIOUS_SOURCE / "nvidia/nv-procfs.c"),
        )
        composed = legacy_builder.apply_patches_to_text(
            previous, legacy_builder.PM_CHANNEL_DEPTH_PREDECESSOR_PATCHES,
            relative, extra_files=extras)
        patched = legacy_builder.apply_patches_to_text(
            composed, (LEGACY_PATCH, legacy_builder.PM_RECOVERY_PROVIDER_PATCH),
            relative, extra_files=extras)
        patched = legacy_builder.apply_patches_to_text(
            patched, (LEGACY_DPM_MODESET_PATCH,), relative, extra_files=extras)
        resume, _ = function_body(patched, "nv_resume_devices")
        self.assertIn("NV_PM_ACTION_DEPTH_CHANNELS", resume)
        self.assertIn("resume_uvm = NV_FALSE", resume)
        self.assertRegex(
            resume,
            r"resume_modeset:\s*if \(pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS\)\s*\{\s*"
            r"nvidia_modeset_resume\(0\);",
        )
        suspend, _ = function_body(patched, "nv_suspend_devices")
        self.assertRegex(
            suspend,
            r"if \(pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS\)\s*\{\s*"
            r"nvidia_modeset_suspend\(0\);",
        )
        suspend_rollback = suspend[suspend.index("done:"):]
        self.assertRegex(
            suspend_rollback,
            r"if \(pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS\)\s*\{\s*"
            r"nvidia_modeset_resume\(0\);",
        )

        mmap_relative = "nvidia/nv-mmap.c"
        mmap_previous = (legacy_builder.PREVIOUS_SOURCE / mmap_relative).read_text()
        if mmap_previous.startswith("/*\n * " + legacy_builder.NOTICE_ID + "\n"):
            _, separator, mmap_previous = mmap_previous.partition(" */\n")
            self.assertTrue(separator)
        mmap_patched = legacy_builder.apply_patches_to_text(
            mmap_previous, (LEGACY_VMA_ACCESS_PATCH,), mmap_relative)
        access, _ = function_body(mmap_patched, "nvidia_vma_access")
        self.assertIn("nvidia_vma_access_unlocked(vma, addr, buffer, length, write)", access)

        header_relative = "common/inc/nv-linux.h"
        header_previous = (legacy_builder.PREVIOUS_SOURCE / header_relative).read_text()
        if header_previous.startswith("/*\n * " + legacy_builder.NOTICE_ID + "\n"):
            _, separator, header_previous = header_previous.partition(" */\n")
            self.assertTrue(separator)
        header_patched = legacy_builder.apply_patches_to_text(
            header_previous, (LEGACY_VMA_FREE_LIST_PATCH,), header_relative)
        release, _ = function_body(header_patched, "nv_alloc_release")
        self.assertIn("NV_SPIN_LOCK_IRQSAVE(&nvlfp->fp_lock, eflags)", release)

    def test_vma_free_list_release_is_serialized_for_shared_files(self):
        scratch = self._patched_source(
            OPEN_SOURCE,
            (ENUM_OPEN_PATCH, OPEN_PATCH, OPEN_VMA_ACCESS_PATCH,
             OPEN_VMA_FREE_LIST_PATCH, OPEN_DPM_MODESET_PATCH),
            "kernel-open")
        try:
            header = (scratch / "kernel-open/common/inc/nv-linux.h").read_text()
        finally:
            shutil.rmtree(scratch)
        release, _ = function_body(header, "nv_alloc_release")
        code = r'''#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#define NV_TRUE true
#define NV_FALSE false
#define NV_DBG_MEMINFO 0
#define NV_PRINT_AT(level, at) do { (void)(level); (void)(at); } while (0)
typedef bool NvBool;
typedef struct { pthread_mutex_t mutex; } nv_spinlock_t;
typedef struct nv_alloc { atomic_long usage_count; struct nv_alloc *next; } nv_alloc_t;
typedef struct { nv_spinlock_t fp_lock; nv_alloc_t *free_list; } nv_linux_file_private_t;
#define NV_SPIN_LOCK_IRQSAVE(lock, flags) do { \
    (flags) = 0; assert(pthread_mutex_lock(&(lock)->mutex) == 0); \
} while (0)
#define NV_SPIN_UNLOCK_IRQRESTORE(lock, flags) do { \
    (void)(flags); assert(pthread_mutex_unlock(&(lock)->mutex) == 0); \
} while (0)
static int atomic64_dec_and_test(atomic_long *value) {
    return atomic_fetch_sub(value, 1) == 1;
}
static void atomic64_inc(atomic_long *value) { atomic_fetch_add(value, 1); }
'''
        code += "static inline NvBool nv_alloc_release("
        code += "nv_linux_file_private_t *nvlfp, nv_alloc_t *at) {\n" + release + "\n}\n"
        code += r'''
struct work { nv_linux_file_private_t *file; nv_alloc_t *alloc; int released; };
static void *run_release(void *opaque) {
    struct work *work = opaque;
    work->released = nv_alloc_release(work->file, work->alloc);
    return NULL;
}
int main(void) {
    enum { COUNT = 48 };
    nv_linux_file_private_t file = { .fp_lock = { .mutex = PTHREAD_MUTEX_INITIALIZER } };
    nv_alloc_t allocations[COUNT] = {0};
    struct work work[COUNT];
    pthread_t threads[COUNT];
    bool seen[COUNT] = {0};
    for (int i = 0; i < COUNT; ++i) {
        atomic_init(&allocations[i].usage_count, 1);
        work[i] = (struct work){ .file = &file, .alloc = &allocations[i] };
        assert(pthread_create(&threads[i], NULL, run_release, &work[i]) == 0);
    }
    for (int i = 0; i < COUNT; ++i)
        assert(pthread_join(threads[i], NULL) == 0 && work[i].released);
    size_t listed = 0;
    for (nv_alloc_t *at = file.free_list; at != NULL; at = at->next) {
        ptrdiff_t index = at - allocations;
        assert(index >= 0 && index < COUNT && !seen[index]);
        seen[index] = true;
        ++listed;
    }
    assert(listed == COUNT);
    for (int i = 0; i < COUNT; ++i) assert(seen[i]);

    nv_alloc_t shared = {0};
    struct work pair[2];
    pthread_t pair_threads[2];
    atomic_init(&shared.usage_count, 2);
    pair[0] = (struct work){ .file = &file, .alloc = &shared };
    pair[1] = (struct work){ .file = &file, .alloc = &shared };
    assert(pthread_create(&pair_threads[0], NULL, run_release, &pair[0]) == 0);
    assert(pthread_create(&pair_threads[1], NULL, run_release, &pair[1]) == 0);
    assert(pthread_join(pair_threads[0], NULL) == 0);
    assert(pthread_join(pair_threads[1], NULL) == 0);
    assert(pair[0].released + pair[1].released == 1);
    assert(atomic_load(&shared.usage_count) == 1);
    size_t shared_count = 0;
    for (nv_alloc_t *at = file.free_list; at != NULL; at = at->next)
        if (at == &shared) ++shared_count;
    assert(shared_count == 1);
    puts("VMA release CPU concurrency: 48 distinct allocations and one shared allocation retained exactly once");
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix="hybrid-vma-free-list-") as temp:
            source, binary = Path(temp) / "release.c", Path(temp) / "release"
            source.write_text(code)
            result = subprocess.run(
                ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
                 "-fsanitize=undefined", "-fno-sanitize-recover=all", str(source), "-o", str(binary)],
                text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(binary)], text=True, capture_output=True,
                                    check=False, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("48 distinct allocations", result.stdout)

    def test_both_backends_report_failed_channel_rollback(self):
        sources = (
            (OPEN_SOURCE, (ENUM_OPEN_PATCH, OPEN_PATCH), "kernel-open"),
            (LEGACY_SOURCE,
             (ENUM_LEGACY_PATCH, LEGACY_PATCH, LEGACY_PROCFS_PATCH), ""),
        )
        for source_root, patch_files, prefix in sources:
            with self.subTest(prefix=prefix or "proprietary"):
                scratch = self._patched_source(source_root, patch_files, prefix)
                try:
                    root = scratch / prefix if prefix else scratch
                    driver = (root / "nvidia/nv.c").read_text()
                    suspend, _ = function_body(driver, "nv_suspend_devices")
                    rollback = suspend[suspend.index("done:"):]
                    self.assertIn("rollback_status", rollback)
                    self.assertIn("cleanup_status = nv_restore_user_channels", rollback)
                    self.assertIn("rollback_status = cleanup_status", rollback)
                    self.assertIn("if (rollback_status != NV_OK)", rollback)
                    self.assertIn("status = NV_ERR_GENERIC;", rollback)
                finally:
                    shutil.rmtree(scratch)


if __name__ == "__main__":
    unittest.main()
