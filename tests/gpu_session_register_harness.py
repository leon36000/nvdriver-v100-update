# SPDX-License-Identifier: MIT
"""Compile the exact patched provider REGISTER_FD bridge with VFS/RM doubles."""
from pathlib import Path
import subprocess
import tempfile

import test_private_backend_file_projection as projection


PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint32_t NvU32;
typedef int NV_STATUS;
typedef struct nv_file_private_t nv_file_private_t;
struct nv_file_private_t {
    nv_file_private_t *ctl_nvfp;
    void *ctl_nvfp_priv;
    NvU32 register_or_refcount;
};
typedef struct { nv_file_private_t nvfp; } nv_linux_file_private_t;
struct file {
    unsigned refs;
    bool provider;
    bool is_control;
    nv_linux_file_private_t *private_data;
};
struct hybrid580_gpu_session { struct file *file; };
struct hybrid580_control_session { struct file *file; };
typedef struct nvidia_stack_t { unsigned marker; } nvidia_stack_t;

#define NV_OK 0
#define NVFP_TYPE_NONE 0
#define NVFP_TYPE_REFCOUNTED 1
#define NVFP_TYPE_REGISTERED 2

static int pm_error;
static int stack_error;
static NV_STATUS api_error;
static unsigned pm_depth;
static unsigned stack_allocations;
static unsigned stack_frees;
static unsigned api_acquires;
static unsigned api_releases;
static bool api_locked;
static bool inject_publish_race;
static nv_file_private_t *race_link;
static nv_file_private_t **race_target;

static struct file *get_file(struct file *file)
{
    assert(file != NULL && file->refs > 0);
    ++file->refs;
    return file;
}

static void fput(struct file *file)
{
    assert(file != NULL && file->refs > 1);
    --file->refs;
}

static NvU32 fake_cmpxchg_u32(NvU32 *ptr, NvU32 expected, NvU32 desired)
{
    NvU32 old = *ptr;
    if (old == expected)
        *ptr = desired;
    return old;
}

static nv_file_private_t *fake_cmpxchg_nvfp(
    nv_file_private_t **ptr, nv_file_private_t *expected,
    nv_file_private_t *desired)
{
    nv_file_private_t *old = *ptr;
    if (inject_publish_race && ptr == race_target) {
        *ptr = race_link;
        inject_publish_race = false;
        return race_link;
    }
    if (old == expected)
        *ptr = desired;
    return old;
}

#define cmpxchg(ptr, expected, desired) \
    _Generic(*(ptr), NvU32: fake_cmpxchg_u32, \
             nv_file_private_t *: fake_cmpxchg_nvfp)((ptr), (expected), (desired))

static int nv_down_read_interruptible(void *lock)
{
    assert(lock != NULL && pm_depth == 0);
    if (pm_error != 0)
        return pm_error;
    ++pm_depth;
    return 0;
}

static void up_read(void *lock)
{
    assert(lock != NULL && pm_depth == 1);
    --pm_depth;
}

static int nv_kmem_cache_alloc_stack(nvidia_stack_t **stack)
{
    assert(stack != NULL && *stack == NULL && pm_depth == 1);
    if (stack_error != 0)
        return stack_error;
    *stack = calloc(1, sizeof(**stack));
    assert(*stack != NULL);
    ++stack_allocations;
    return 0;
}

static void nv_kmem_cache_free_stack(nvidia_stack_t *stack)
{
    assert(stack != NULL);
    free(stack);
    ++stack_frees;
}

static NV_STATUS rm_acquire_api_lock(nvidia_stack_t *stack)
{
    assert(stack != NULL && pm_depth == 1 && !api_locked);
    ++api_acquires;
    if (api_error != NV_OK)
        return api_error;
    api_locked = true;
    return NV_OK;
}

static NV_STATUS rm_release_api_lock(nvidia_stack_t *stack)
{
    assert(stack != NULL && pm_depth == 1 && api_locked);
    api_locked = false;
    ++api_releases;
    return NV_OK;
}

static void *nv_system_pm_lock = (void *)1;

static nv_linux_file_private_t *BACKEND_FILE_HELPER(
    struct file *file, int require_control)
{
    if (file == NULL || !file->provider || file->is_control != !!require_control)
        return NULL;
    return file->private_data;
}

static struct file gpu_file;
static struct file control_file;
static struct file invalid_file;
static nv_linux_file_private_t gpu_data;
static nv_linux_file_private_t control_data;
static nv_linux_file_private_t foreign_data;
static struct hybrid580_gpu_session gpu_session;
static struct hybrid580_control_session control_session;

static void reset_case(void)
{
    gpu_file = (struct file){ .refs = 1, .provider = true,
        .is_control = false, .private_data = &gpu_data };
    control_file = (struct file){ .refs = 1, .provider = true,
        .is_control = true, .private_data = &control_data };
    invalid_file = (struct file){ .refs = 1, .provider = false,
        .is_control = true, .private_data = &control_data };
    gpu_data = (nv_linux_file_private_t){0};
    control_data = (nv_linux_file_private_t){0};
    foreign_data = (nv_linux_file_private_t){0};
    gpu_session.file = &gpu_file;
    control_session.file = &control_file;
    pm_error = 0;
    stack_error = 0;
    api_error = NV_OK;
    pm_depth = 0;
    stack_allocations = 0;
    stack_frees = 0;
    api_acquires = 0;
    api_releases = 0;
    api_locked = false;
    inject_publish_race = false;
    race_link = NULL;
    race_target = NULL;
}

static void assert_balanced(void)
{
    assert(gpu_file.refs == 1 && control_file.refs == 1);
    assert(pm_depth == 0 && !api_locked);
    assert(stack_allocations == stack_frees);
    assert(api_acquires == api_releases || api_acquires == api_releases + 1);
}
'''


SUFFIX_TEMPLATE = r'''
int main(void)
{
    unsigned scenarios = 0;
    int rc;

    reset_case();
    rc = FUNCTION_NAME(NULL, &control_session);
    assert(rc == -EINVAL && control_file.refs == 1 && api_acquires == 0);
    assert_balanced(); ++scenarios;

    reset_case();
    control_session.file = &invalid_file;
    rc = FUNCTION_NAME(&gpu_session, &control_session);
    assert(rc == -EINVAL && invalid_file.refs == 1);
    assert(gpu_file.refs == 1 && pm_depth == 0);
    ++scenarios;

    reset_case();
    gpu_file.provider = false;
    rc = FUNCTION_NAME(&gpu_session, &control_session);
    assert(rc == -EINVAL);
    assert_balanced(); ++scenarios;

    reset_case();
    control_file.private_data = &gpu_data;
    rc = FUNCTION_NAME(&gpu_session, &control_session);
    assert(rc == -EINVAL && gpu_data.nvfp.ctl_nvfp == NULL);
    assert_balanced(); ++scenarios;

    reset_case();
    pm_error = -EINTR;
    rc = FUNCTION_NAME(&gpu_session, &control_session);
    assert(rc == -EINTR && stack_allocations == 0 && api_acquires == 0);
    assert_balanced(); ++scenarios;

    reset_case();
    stack_error = -ENOMEM;
    rc = FUNCTION_NAME(&gpu_session, &control_session);
    assert(rc == -ENOMEM && pm_depth == 0 && api_acquires == 0);
    assert_balanced(); ++scenarios;

    reset_case();
    api_error = 7;
    rc = FUNCTION_NAME(&gpu_session, &control_session);
    assert(rc == -EINVAL && api_acquires == 1 && api_releases == 0);
    assert_balanced(); ++scenarios;

    reset_case();
    gpu_data.nvfp.ctl_nvfp = &foreign_data.nvfp;
    rc = FUNCTION_NAME(&gpu_session, &control_session);
    assert(rc == -EINVAL && gpu_data.nvfp.ctl_nvfp == &foreign_data.nvfp);
    assert(api_releases == 1);
    assert_balanced(); ++scenarios;

    reset_case();
    control_data.nvfp.ctl_nvfp = &foreign_data.nvfp;
    rc = FUNCTION_NAME(&gpu_session, &control_session);
    assert(rc == -EINVAL && control_data.nvfp.ctl_nvfp == &foreign_data.nvfp);
    assert(api_releases == 1);
    assert_balanced(); ++scenarios;

    reset_case();
    gpu_data.nvfp.register_or_refcount = NVFP_TYPE_REFCOUNTED;
    rc = FUNCTION_NAME(&gpu_session, &control_session);
    assert(rc == -EINVAL);
    assert(gpu_data.nvfp.register_or_refcount == NVFP_TYPE_REFCOUNTED);
    assert(gpu_data.nvfp.ctl_nvfp == NULL && control_file.refs == 1);
    assert_balanced(); ++scenarios;

    reset_case();
    inject_publish_race = true;
    race_target = &gpu_data.nvfp.ctl_nvfp;
    race_link = &foreign_data.nvfp;
    rc = FUNCTION_NAME(&gpu_session, &control_session);
    assert(rc == -EINVAL && gpu_data.nvfp.ctl_nvfp == &foreign_data.nvfp);
    assert(gpu_data.nvfp.register_or_refcount == NVFP_TYPE_NONE);
    assert(control_file.refs == 1 && api_releases == 1);
    gpu_data.nvfp.ctl_nvfp = NULL; /* Remove the independent racing writer's test link. */
    assert_balanced(); ++scenarios;

    reset_case();
    rc = FUNCTION_NAME(&gpu_session, &control_session);
    assert(rc == 0 && gpu_data.nvfp.register_or_refcount == NVFP_TYPE_REGISTERED);
    assert(gpu_data.nvfp.ctl_nvfp == &control_data.nvfp);
    assert(gpu_data.nvfp.ctl_nvfp_priv == &control_file && control_file.refs == 2);
    assert(api_releases == 1 && stack_allocations == stack_frees);
    /* Model the native GPU-file close dropping the retained provider ref. */
    gpu_data.nvfp.ctl_nvfp = NULL;
    gpu_data.nvfp.ctl_nvfp_priv = NULL;
    fput(&control_file);
    assert_balanced(); ++scenarios;

    printf("provider REGISTER_FD bridge CPU/UBSan scenarios: %u\n", scenarios);
    return 0;
}
'''


def run_register_control_contract(source: str, backend: str) -> str:
    """Compile and run the actual patched helper against deterministic doubles."""
    function_name = f'hybrid580_{backend}_gpu_session_register_control_v1'
    backend_file_helper = f'hybrid580_{backend}_backend_file'
    start = source.index(f'int {function_name}(')
    body = projection.braced_block(source, start)
    brace = source.index('{', start)
    function = source[start:brace] + body
    prefix = PREFIX.replace('BACKEND_FILE_HELPER', backend_file_helper)
    suffix = SUFFIX_TEMPLATE.replace('FUNCTION_NAME', function_name)
    with tempfile.TemporaryDirectory(prefix='hybrid-register-control-') as temporary:
        root = Path(temporary)
        c_file = root / 'register_control.c'
        binary = root / 'register_control'
        c_file.write_text(prefix + '\n' + function + '\n' + suffix)
        subprocess.run([
            'cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-fsanitize=undefined', '-fno-sanitize-recover=all',
            str(c_file), '-o', str(binary),
        ], check=True, capture_output=True, text=True)
        result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
        return result.stdout.strip()
