# SPDX-License-Identifier: MIT
"""Execute the patched debugger provider bodies against a fake RM boundary.

This is a host-side contract test for the exact added C functions. It does not
model the kernel, NVIDIA RM internals, or device behavior.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = (
    (ROOT / "patches/r580.178.04/0050-private-open-debugger-bridge.patch",
     "hybrid580_open_control_session_debugger_exception_mask_v1"),
    (ROOT / "patches/r580.178.04/proprietary/0048-private-legacy-debugger-bridge.patch",
     "hybrid580_legacy_control_session_debugger_exception_mask_v1"),
)


def added_function(patch_path: Path, symbol: str) -> str:
    """Return the exact added function body from a pinned patch."""
    patch = patch_path.read_text(encoding="utf-8")
    start_marker = f"+NV_STATUS {symbol}("
    end_marker = f"+EXPORT_SYMBOL({symbol});"
    start = patch.find(start_marker)
    if start < 0:
        raise AssertionError(f"provider method is absent from {patch_path}")
    end = patch.find(end_marker, start)
    if end < 0:
        raise AssertionError(f"provider export is absent from {patch_path}")
    added_lines = patch[start:end].splitlines()
    if any(not line.startswith("+") for line in added_lines):
        raise AssertionError("provider method unexpectedly includes context lines")
    return "\n".join(line[1:] for line in added_lines) + "\n"


HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef unsigned int NvU32;
typedef unsigned int NvHandle;
typedef uintptr_t NvP64;
typedef int NV_STATUS;

enum {
    NV_OK = 0,
    NV_ERR_INVALID_ARGUMENT = 1,
    NV_ERR_OPERATING_SYSTEM = 2,
    NV_ERR_INVALID_STATE = 3,
    NV_ERR_NO_MEMORY = 4,
    NV_ERR_INVALID_OBJECT_HANDLE = 5,
    NV_ERR_GPU_NOT_POWERED = 6,
    NV04_CONTROL = 7,
    NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK = 0x83de0309,
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_FATAL = 0x01,
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_TRAP = 0x02,
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_SINGLE_STEP = 0x04,
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_INT = 0x08,
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_CILP = 0x10,
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PREEMPTION_STARTED = 0x20,
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_ALL = 0xffff,
    NVOS54_FLAGS_NONE = 0,
};

typedef struct {
    NvU32 exceptionMask;
} NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS;

typedef struct {
    NvHandle hClient;
    NvHandle hObject;
    NvU32 cmd;
    NvU32 flags;
    NvP64 params;
    NvU32 paramsSize;
    NvU32 status;
} NVOS54_PARAMETERS;

typedef struct {
    int op;
    union { NVOS54_PARAMETERS control; } params;
} nvidia_kernel_rmapi_ops_t;

typedef struct { int marker; } nv_state_t;
typedef struct { void *nvptr; } nv_linux_file_private_t;
typedef struct { int marker; } nvidia_stack_t;
struct hybrid580_control_session { void *file; int lock; };

#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "build-time contract")
#define NV_PTR_TO_NvP64(pointer) ((NvP64)(uintptr_t)(pointer))
#define KERNEL_POINTER_TO_NvP64(pointer) ((NvP64)(uintptr_t)(pointer))
#define NV_STATE_PTR(pointer) ((nv_state_t *)(pointer))

static int nv_system_pm_lock;
static int fail_mutex, fail_pm, fail_stack, backend_file_present = 1;
static int mutex_depth, pm_depth, stack_allocs, stack_frees, rm_calls;
static NV_STATUS gpu_status = NV_OK;
static int rm_mode;
static NvU32 rm_embedded_status = NV_OK;
static NvHandle observed_client, observed_object;
static NvU32 observed_command, observed_flags, observed_size, observed_mask;
static nv_state_t fake_gpu;
static nv_linux_file_private_t fake_file = { .nvptr = &fake_gpu };
static nvidia_stack_t fake_stack;
static int file_token;

static void reset_state(void)
{
    fail_mutex = fail_pm = fail_stack = 0;
    backend_file_present = 1;
    mutex_depth = pm_depth = stack_allocs = stack_frees = rm_calls = 0;
    gpu_status = NV_OK;
    rm_mode = 0;
    rm_embedded_status = NV_OK;
    observed_client = observed_object = 0;
    observed_command = observed_flags = observed_size = observed_mask = 0;
}

static int mutex_lock_interruptible(int *lock)
{
    (void)lock;
    if (fail_mutex) return -1;
    assert(mutex_depth == 0);
    ++mutex_depth;
    return 0;
}
static void mutex_unlock(int *lock)
{
    (void)lock;
    assert(mutex_depth == 1);
    --mutex_depth;
}
static int nv_down_read_interruptible(int *lock)
{
    (void)lock;
    assert(mutex_depth == 1 && pm_depth == 0);
    if (fail_pm) return -1;
    ++pm_depth;
    return 0;
}
static void up_read(int *lock)
{
    (void)lock;
    assert(pm_depth == 1);
    --pm_depth;
}
static nv_linux_file_private_t *hybrid580_open_backend_file(void *file, int gpu)
{
    assert(file == &file_token && gpu == 1 && mutex_depth == 1);
    return backend_file_present ? &fake_file : NULL;
}
static nv_linux_file_private_t *hybrid580_legacy_backend_file(void *file, int gpu)
{
    return hybrid580_open_backend_file(file, gpu);
}
static NV_STATUS nv_check_gpu_state(nv_state_t *nv)
{
    assert(nv == &fake_gpu && mutex_depth == 1 && pm_depth == 1);
    return gpu_status;
}
static int nv_kmem_cache_alloc_stack(nvidia_stack_t **stack)
{
    assert(mutex_depth == 1 && pm_depth == 1);
    if (fail_stack) return -1;
    ++stack_allocs;
    *stack = &fake_stack;
    return 0;
}
static void nv_kmem_cache_free_stack(nvidia_stack_t *stack)
{
    assert(stack == &fake_stack && mutex_depth == 1 && pm_depth == 1);
    ++stack_frees;
}
static void rm_kernel_rmapi_op(nvidia_stack_t *stack,
                               nvidia_kernel_rmapi_ops_t *ops)
{
    assert(stack == &fake_stack && ops != NULL && ops->op == NV04_CONTROL);
    assert(mutex_depth == 1 && pm_depth == 1);
    NVOS54_PARAMETERS *control = &ops->params.control;
    assert(control->params != 0);
    ++rm_calls;
    observed_client = control->hClient;
    observed_object = control->hObject;
    observed_command = control->cmd;
    observed_flags = control->flags;
    observed_size = control->paramsSize;
    assert(control->paramsSize == sizeof(NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS));
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS *payload =
        (void *)(uintptr_t)control->params;
    observed_mask = payload->exceptionMask;
    if (rm_mode != 3) control->status = rm_embedded_status;
}

typedef NV_STATUS (*bridge_fn)(struct hybrid580_control_session *, NvHandle,
    NvHandle, NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS *, NvU32 *);

static void assert_balanced(void)
{
    assert(mutex_depth == 0 && pm_depth == 0);
    assert(stack_allocs == stack_frees);
}

static void exercise_provider(bridge_fn bridge)
{
    struct hybrid580_control_session session = { .file = &file_token };
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS params = { .exceptionMask = 0x21 };
    NvU32 control_status;

    reset_state();
    control_status = 0xffffffffU;
    assert(bridge(&session, 0x11, 0x22, &params, &control_status) == NV_OK);
    assert(control_status == NV_OK && rm_calls == 1);
    assert(observed_client == 0x11 && observed_object == 0x22);
    assert(observed_command == NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK);
    assert(observed_flags == NVOS54_FLAGS_NONE && observed_size == 4 && observed_mask == 0x21);
    assert(stack_allocs == 1 && stack_frees == 1);
    assert_balanced();

    reset_state();
    params.exceptionMask = NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_ALL;
    control_status = 0xffffffffU;
    assert(bridge(&session, 0x11, 0x22, &params, &control_status) == NV_OK);
    assert(control_status == NV_OK && rm_calls == 1 &&
           observed_mask == NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_ALL);
    assert_balanced();

    reset_state();
    control_status = 0xffffffffU;
    assert(bridge(&session, 0, 0x22, &params, &control_status) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(control_status == 0xffffffffU && rm_calls == 0 && mutex_depth == 0);

    reset_state();
    assert(bridge(&session, 0x11, 0x22, NULL, &control_status) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(rm_calls == 0 && mutex_depth == 0);

    reset_state();
    params.exceptionMask = 0x40;
    control_status = 0xffffffffU;
    assert(bridge(&session, 0x11, 0x22, &params, &control_status) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(control_status == 0xffffffffU && rm_calls == 0 && mutex_depth == 0 &&
           pm_depth == 0 && stack_allocs == 0);

    reset_state();
    params.exceptionMask = 0x03;
    rm_embedded_status = NV_ERR_INVALID_OBJECT_HANDLE;
    control_status = 0xffffffffU;
    assert(bridge(&session, 0x11, 0x22, &params, &control_status) == NV_OK);
    assert(control_status == NV_ERR_INVALID_OBJECT_HANDLE && rm_calls == 1);
    assert(stack_allocs == 1 && stack_frees == 1);
    assert_balanced();

    reset_state();
    rm_mode = 3; /* fake RM leaves NVOS54.status at the provider's sentinel */
    control_status = 0xffffffffU;
    assert(bridge(&session, 0x11, 0x22, &params, &control_status) ==
           NV_ERR_INVALID_STATE);
    assert(control_status == 0xffffffffU && rm_calls == 1);
    assert(stack_allocs == 1 && stack_frees == 1);
    assert_balanced();

    reset_state();
    gpu_status = NV_ERR_GPU_NOT_POWERED;
    control_status = 0xffffffffU;
    assert(bridge(&session, 0x11, 0x22, &params, &control_status) ==
           NV_ERR_GPU_NOT_POWERED);
    assert(control_status == 0xffffffffU && rm_calls == 0 && stack_allocs == 0);
    assert_balanced();

    reset_state();
    fail_mutex = 1;
    assert(bridge(&session, 0x11, 0x22, &params, &control_status) ==
           NV_ERR_OPERATING_SYSTEM);
    assert(rm_calls == 0 && pm_depth == 0 && stack_allocs == 0 && mutex_depth == 0);

    reset_state();
    backend_file_present = 0;
    assert(bridge(&session, 0x11, 0x22, &params, &control_status) == NV_ERR_INVALID_STATE);
    assert(rm_calls == 0 && pm_depth == 0 && mutex_depth == 0);

    reset_state();
    fail_pm = 1;
    assert(bridge(&session, 0x11, 0x22, &params, &control_status) ==
           NV_ERR_OPERATING_SYSTEM);
    assert(rm_calls == 0 && pm_depth == 0 && mutex_depth == 0 && stack_allocs == 0);

    reset_state();
    fail_stack = 1;
    assert(bridge(&session, 0x11, 0x22, &params, &control_status) == NV_ERR_NO_MEMORY);
    assert(rm_calls == 0 && stack_allocs == 0 && pm_depth == 0 && mutex_depth == 0);
    assert_balanced();
}

__PROVIDER_FUNCTIONS__

int main(void)
{
    exercise_provider(hybrid580_open_control_session_debugger_exception_mask_v1);
    exercise_provider(hybrid580_legacy_control_session_debugger_exception_mask_v1);
    puts("R595 Open and R580 proprietary debugger provider contracts passed");
    return 0;
}
"""


class DebuggerProviderBridgeTests(unittest.TestCase):
    def test_exact_provider_methods_with_fake_rm(self):
        functions = "\n".join(added_function(path, symbol)
                                for path, symbol in PROVIDERS)
        source = HARNESS.replace("__PROVIDER_FUNCTIONS__", functions)
        with tempfile.TemporaryDirectory(prefix="debugger-provider-bridge-") as tmp:
            c_file = Path(tmp) / "provider_bridge.c"
            binary = Path(tmp) / "provider_bridge"
            c_file.write_text(source, encoding="utf-8")
            compile_result = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 str(c_file), "-o", str(binary)],
                text=True, capture_output=True, check=False)
            self.assertEqual(compile_result.returncode, 0,
                             compile_result.stdout + compile_result.stderr)
            run_result = subprocess.run([str(binary)], text=True,
                                        capture_output=True, check=False)
            self.assertEqual(run_result.returncode, 0,
                             run_result.stdout + run_result.stderr)
            self.assertEqual(
                run_result.stdout.strip(),
                "R595 Open and R580 proprietary debugger provider contracts passed")


if __name__ == "__main__":
    unittest.main()
