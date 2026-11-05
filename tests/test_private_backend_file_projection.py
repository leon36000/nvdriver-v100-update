# SPDX-License-Identifier: MIT
"""Execute patched source with CPU substitutes, not kernel/runtime validation.

The pthread rwlock model checks reference balance and reader/writer lifetime protocol only;
it cannot prove Linux spinlocks, module unloading, fd locking, or a real RM operation.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / '.cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz'
SHA = '060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8'
PATCHES = [next((ROOT / 'patches/r580.178.04').glob(f'{i:04d}-*.patch'))
           for i in range(2, 9)]


def function(source, name):
    start = source.index(name + '(')
    # Return the declaration including its return type.
    start = source.rfind('\n', 0, start) + 1
    if source[start:source.index(name + '(')].strip() == '':
        start = source.rfind('\n', 0, start - 1) + 1
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


def braced_block(source, start):
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[opening:end]


class PrivateFileProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with ARCHIVE.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != SHA:
                raise AssertionError('archive does not match pinned R580 source')
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.tree = Path(cls.tmp.name)
        targets = set()
        for patch in PATCHES:
            targets.update(re.findall(r'^--- a/([^\n]+)$', patch.read_text(), re.M))
        with tarfile.open(ARCHIVE) as archive:
            vendor_header = archive.extractfile(
                'NVIDIA-kernel-module-source-580.178.04/kernel-open/common/inc/nv-linux.h'
            ).read().decode()
            matches = re.findall(r'^#define NV_STATE_PTR\(nvl\)[^\n]+$', vendor_header, re.M)
            if len(matches) != 1:
                raise AssertionError('expected exactly one vendor NV_STATE_PTR definition')
            cls.vendor_macros = matches[0] + '\n'
            nv_header = archive.extractfile(
                'NVIDIA-kernel-module-source-580.178.04/kernel-open/common/inc/nv.h'
            ).read().decode()
            for name in ('NV_FLAG_OPEN', 'NV_FLAG_CONTROL'):
                definitions = re.findall(r'^#define ' + name + r'\s+[^\n]+$', nv_header, re.M)
                if len(definitions) != 1:
                    raise AssertionError('expected exactly one vendor ' + name + ' definition')
                cls.vendor_macros += definitions[0] + '\n'
            for name in targets:
                data = archive.extractfile('NVIDIA-kernel-module-source-580.178.04/' + name).read()
                target = cls.tree / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            cls.escape_source = archive.extractfile(
                'NVIDIA-kernel-module-source-580.178.04/src/nvidia/arch/nvalloc/unix/src/escape.c'
            ).read().decode()
            cls.osapi_source = archive.extractfile(
                'NVIDIA-kernel-module-source-580.178.04/src/nvidia/arch/nvalloc/unix/src/osapi.c'
            ).read().decode()
        for patch in PATCHES:
            result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                                    cwd=cls.tree, capture_output=True, text=True)
            if result.returncode or re.search(r'\b(?:fuzz|offset)\b', result.stdout + result.stderr):
                raise AssertionError(result.stdout + result.stderr)
        cls.source = (cls.tree / 'kernel-open/nvidia/nv.c').read_text()
        cls.header = (cls.tree / 'kernel-open/nvidia/hybrid580-file-projection.h').read_text()

    def test_projection_patch_scope_and_contract(self):
        targets = re.findall(r'^\+\+\+ b/([^\n]+)$', PATCHES[-1].read_text(), re.M)
        self.assertEqual(targets, ['kernel-open/nvidia/nv.c',
                                  'kernel-open/nvidia/hybrid580-file-projection.h'])
        self.assertIn('SPDX-License-Identifier: MIT', self.header)
        self.assertEqual(self.source.count('EXPORT_SYMBOL(hybrid580_open_register_file_projection_v1);'), 1)
        self.assertEqual(self.source.count('EXPORT_SYMBOL(hybrid580_open_unregister_file_projection_v1);'), 1)
        segment = self.source[self.source.index('struct hybrid580_file_projection_provider {'):
                              self.source.index('int NV_API_CALL nv_get_event(')]
        self.assertNotIn('rm_ioctl(', segment)
        self.assertNotIn('nv_kmem_cache_alloc_stack(', segment)
        for forbidden in ('rcu_', 'synchronize_rcu', 'mutex_'):
            self.assertNotIn(forbidden, segment)
        self.assertIn('MUST NOT sleep', self.header)

    def test_actual_projection_functions_reference_and_reader_contract(self):
        header = re.sub(r'^#include[^\n]*\n', '', self.header, flags=re.M)
        begin = self.source.index('struct hybrid580_file_projection_provider {')
        end = self.source.index('\nint NV_API_CALL nv_get_event(', begin)
        actual = self.source[begin:end]
        actual += function(self.source, 'nv_match_dev_state')
        code = STUBS + self.vendor_macros + header + actual + CASES
        source = self.tree / 'projection-contract.c'
        source.write_text(code)
        binary = self.tree / 'projection-contract'
        result = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra',
                                 '-Wno-unused-parameter', '-Werror', '-pthread',
                                 '-fsanitize=undefined', '-fno-sanitize-recover=all',
                                 str(source), '-o', str(binary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('projection CPU scenarios: 38; writer waited for reader', result.stdout)
        print(result.stdout.strip())

    def test_pinned_r580_register_fd_case_holds_projected_control_until_gpu_close(self):
        # Execute the unchanged vendor REGISTER_FD case and close cleanup against
        # the patched backend's real projection and nv_get_file_private code.
        # The only substitutes are Linux file-table/refcount and RM lock primitives.
        case_start = self.escape_source.index('case NV_ESC_REGISTER_FD:')
        register_case = 'case NV_ESC_REGISTER_FD: ' + braced_block(self.escape_source, case_start)
        done_start = self.osapi_source.index('if (nvfp->ctl_nvfp != NULL)',
                                             self.osapi_source.index('done:'))
        close_cleanup = braced_block(self.osapi_source, done_start)
        self.assertIn('nv_get_file_private(params->ctl_fd', register_case)
        self.assertIn('nv_put_file_private(priv)', register_case)
        self.assertIn('nv_put_file_private(nvfp->ctl_nvfp_priv)', close_cleanup)

        header = re.sub(r'^#include[^\n]*\n', '', self.header, flags=re.M)
        begin = self.source.index('struct hybrid580_file_projection_provider {')
        end = self.source.index('\nint NV_API_CALL nv_get_event(', begin)
        actual = self.source[begin:end]
        registration_stubs = STUBS.replace(
            'typedef struct { int marker; } nv_file_private_t;',
            'typedef struct nv_file_private_t { int marker; struct nv_file_private_t *ctl_nvfp; '
            'void *ctl_nvfp_priv; uint32_t register_or_refcount; } nv_file_private_t;').replace(
            'static nv_linux_state_t nv_ctl_device, gpu_state, other_gpu_state;',
            'static nv_linux_state_t nv_ctl_device, gpu_state;')
        code = registration_stubs + self.vendor_macros + header + actual
        code += REGISTER_FD_HARNESS_PREFIX + register_case + REGISTER_FD_HARNESS_SUFFIX
        code = code.replace('/* INSERT_CLOSE_CLEANUP */', close_cleanup)
        source = self.tree / 'register-fd-contract.c'
        source.write_text(code)
        binary = self.tree / 'register-fd-contract'
        result = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra',
                                 '-Wno-unused-parameter', '-Werror', '-pthread',
                                 '-fsanitize=undefined', '-fno-sanitize-recover=all',
                                 str(source), '-o', str(binary)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('R580 REGISTER_FD CPU scenarios: 11; held control reference released on GPU close',
                      result.stdout)
        print(result.stdout.strip())


STUBS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
typedef uint32_t u32;
typedef int NvS32;
typedef unsigned NvBool;
#define NV_FALSE 0
#define NV_TRUE 1
#define NV_API_CALL
#define GFP_KERNEL 0
#define EXPORT_SYMBOL(name)
#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255
#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247
struct module { atomic_int refs; atomic_bool going; };
struct file_operations { struct module *owner; };
struct inode { dev_t i_rdev; mode_t i_mode; };
typedef struct { int flags; } nv_state_t;
typedef struct { nv_state_t nv_state; } nv_linux_state_t;
typedef struct { int marker; } nv_file_private_t;
typedef struct { nv_file_private_t nvfp; nv_linux_state_t *nvptr; } nv_linux_file_private_t;
struct file { const struct file_operations *f_op; struct inode *inode;
              void *private_data; atomic_int refs; struct file *back; };
static const struct file_operations nvidia_fops;
static nv_linux_state_t nv_ctl_device, gpu_state, other_gpu_state;
static nv_linux_state_t *nv_linux_minor_num_table[248];
static dev_t hybrid_chrdev_base;
#define MAJOR(v) major(v)
#define MINOR(v) minor(v)
#define NV_FILE_INODE(f) ((f)->inode)
#define NV_GET_LINUX_FILE_PRIVATE(f) ((nv_linux_file_private_t *)(f)->private_data)
#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_ACQUIRE)
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
static int fail_alloc;
static void *kzalloc(size_t n, int flags) { return fail_alloc ? NULL : calloc(1,n); }
static void kfree(void *p) { free(p); }
static _Thread_local unsigned read_depth, write_depth;
#define DEFINE_RWLOCK(name) pthread_rwlock_t name = PTHREAD_RWLOCK_INITIALIZER
static atomic_int writer_wait_test, writer_entered, writer_completed;
static void cpu_read_lock(pthread_rwlock_t *lock) { pthread_rwlock_rdlock(lock); ++read_depth; }
static void cpu_read_unlock(pthread_rwlock_t *lock) { --read_depth; pthread_rwlock_unlock(lock); }
static void cpu_write_lock(pthread_rwlock_t *lock) {
    if (atomic_load(&writer_wait_test)) atomic_store(&writer_entered,1);
    pthread_rwlock_wrlock(lock); ++write_depth;
    if (atomic_load(&writer_wait_test)) atomic_store(&writer_completed,1);
}
static void cpu_write_unlock(pthread_rwlock_t *lock) { --write_depth; pthread_rwlock_unlock(lock); }
#define read_lock_irqsave(lock,flags) ((flags)=0,cpu_read_lock(lock))
#define read_unlock_irqrestore(lock,flags) ((void)(flags),cpu_read_unlock(lock))
#define write_lock_irqsave(lock,flags) ((flags)=0,cpu_write_lock(lock))
#define write_unlock_irqrestore(lock,flags) ((void)(flags),cpu_write_unlock(lock))
static bool try_module_get(struct module *m) {
    if (atomic_load(&m->going)) return false;
    atomic_fetch_add(&m->refs,1); return true;
}
static void module_put(struct module *m) { assert(!read_depth && !write_depth); assert(atomic_fetch_sub(&m->refs,1)>0); }
static struct file *fd_files[4];
static struct file *get_file(struct file *f) { assert(atomic_fetch_add(&f->refs,1)>0); return f; }
static struct file *fget(int fd) { return fd>=0 && fd<4 && fd_files[fd] ? get_file(fd_files[fd]) : NULL; }
static void fput(struct file *f) { assert(atomic_fetch_sub(&f->refs,1)>0); }
'''

REGISTER_FD_HARNESS_PREFIX = r'''
typedef uint32_t NvU32;
typedef int NV_STATUS;
#define NV_OK 0
#define NV_ERR_INVALID_ARGUMENT 1
#define NV_ERR_INVALID_STATE 2
#define NV_ERR_IN_USE 3
#define NVFP_TYPE_NONE 0
#define NVFP_TYPE_REFCOUNTED 1
#define NVFP_TYPE_REGISTERED 2
#define NV_ESC_REGISTER_FD 201
#define API_LOCK_FLAGS_NONE 0
#define RM_LOCK_MODULES_OSAPI 0
typedef struct nv_ioctl_register_fd { int ctl_fd; } nv_ioctl_register_fd_t;
static unsigned lock_attempts, lock_releases;
static NV_STATUS lock_error;
static bool api_locked;
static NV_STATUS rmapiLockAcquire(unsigned flags, unsigned module) {
    (void)flags; (void)module; ++lock_attempts;
    if (lock_error != NV_OK) return lock_error;
    assert(!api_locked); api_locked=true; return NV_OK;
}
static void rmapiLockRelease(void) {
    assert(api_locked); api_locked=false; ++lock_releases;
}
static bool portAtomicCompareAndSwapU32(NvU32 *ptr, NvU32 value, NvU32 old) {
    return __atomic_compare_exchange_n(ptr, &old, value, false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}
static void portAtomicSetSize(nv_file_private_t **ptr, nv_file_private_t *value) {
    __atomic_store_n(ptr, value, __ATOMIC_RELEASE);
}
static NV_STATUS run_register_fd_case(nv_file_private_t *current,
                                      NvU32 supplied_size, void *payload) {
    nv_file_private_t *nvfp=current;
    NvU32 dataSize=supplied_size;
    void *data=payload;
    NV_STATUS rmStatus=NV_OK;
    switch (NV_ESC_REGISTER_FD) {
'''

REGISTER_FD_HARNESS_SUFFIX = r'''
        default: assert(0); break;
    }
done:
    return rmStatus;
}
static void close_registered_fd(nv_file_private_t *nvfp) {
    /* INSERT_CLOSE_CLEANUP */
}
static struct module provider_module, other_module;
static const struct file_operations front_fops={&provider_module};
static const struct file_operations other_fops={&other_module};
static struct inode ctl_inode, gpu_inode;
static nv_linux_file_private_t ctl_data, gpu_data;
static struct file front, ctl, gpu, foreign;
static struct file *project_control(struct file *file, bool is_ctl) {
    assert(read_depth && !write_depth && is_ctl);
    if (file->f_op != &front_fops || file->back == NULL) return NULL;
    return get_file(file->back);
}
static struct hybrid580_file_projection_ops_v1 projection_ops={
    HYBRID580_FILE_PROJECTION_ABI_V1, sizeof(projection_ops),
    &provider_module, &front_fops, project_control
};
static void check_base_references(void) {
    assert(atomic_load(&front.refs)==1 && atomic_load(&ctl.refs)==1);
    assert(atomic_load(&gpu.refs)==1 && atomic_load(&foreign.refs)==1);
    assert(atomic_load(&provider_module.refs)==0 && !api_locked);
}
int main(void) {
    unsigned scenarios=0;
    hybrid_chrdev_base=makedev(240,0);
    ctl_inode=(struct inode){makedev(240,255),S_IFCHR};
    gpu_inode=(struct inode){makedev(240,0),S_IFCHR};
    ctl_data.nvptr=&nv_ctl_device; gpu_data.nvptr=&gpu_state;
    nv_ctl_device.nv_state.flags=NV_FLAG_OPEN|NV_FLAG_CONTROL;
    nv_linux_minor_num_table[0]=&gpu_state;
    ctl=(struct file){&nvidia_fops,&ctl_inode,&ctl_data,1,NULL};
    gpu=(struct file){&nvidia_fops,&gpu_inode,&gpu_data,1,NULL};
    foreign=(struct file){&other_fops,&ctl_inode,&ctl_data,1,NULL};
    front=(struct file){&front_fops,&ctl_inode,NULL,1,&ctl};
    fd_files[0]=&front;
    assert(hybrid580_open_register_file_projection_v1(&projection_ops)==0);
    nv_ioctl_register_fd_t payload={.ctl_fd=0};

    assert(run_register_fd_case(&gpu_data.nvfp,sizeof(payload),&payload)==NV_OK);
    assert(gpu_data.nvfp.ctl_nvfp==&ctl_data.nvfp);
    assert(gpu_data.nvfp.ctl_nvfp_priv==&ctl && atomic_load(&ctl.refs)==2);
    assert(lock_attempts==1 && lock_releases==1); ++scenarios;
    close_registered_fd(&gpu_data.nvfp);
    assert(gpu_data.nvfp.ctl_nvfp==NULL && gpu_data.nvfp.ctl_nvfp_priv==NULL);
    check_base_references(); ++scenarios;

    front.back=&foreign;
    assert(run_register_fd_case(&gpu_data.nvfp,sizeof(payload),&payload)==NV_ERR_INVALID_ARGUMENT);
    check_base_references(); front.back=&ctl; ++scenarios;
    fd_files[0]=NULL;
    assert(run_register_fd_case(&gpu_data.nvfp,sizeof(payload),&payload)==NV_ERR_INVALID_ARGUMENT);
    check_base_references(); fd_files[0]=&front; ++scenarios;
    fd_files[0]=&gpu;
    assert(run_register_fd_case(&gpu_data.nvfp,sizeof(payload),&payload)==NV_ERR_INVALID_ARGUMENT);
    check_base_references(); fd_files[0]=&front; ++scenarios;
    assert(run_register_fd_case(&gpu_data.nvfp,sizeof(payload)-1,&payload)==NV_ERR_INVALID_ARGUMENT);
    check_base_references(); ++scenarios;

    gpu_data.nvfp.ctl_nvfp=&ctl_data.nvfp;
    assert(run_register_fd_case(&gpu_data.nvfp,sizeof(payload),&payload)==NV_ERR_INVALID_STATE);
    check_base_references(); gpu_data.nvfp.ctl_nvfp=NULL; ++scenarios;

    ctl_data.nvfp.ctl_nvfp=&gpu_data.nvfp;
    assert(run_register_fd_case(&gpu_data.nvfp,sizeof(payload),&payload)==NV_ERR_INVALID_ARGUMENT);
    check_base_references(); ctl_data.nvfp.ctl_nvfp=NULL; ++scenarios;

    gpu_data.nvfp.register_or_refcount=NVFP_TYPE_REFCOUNTED;
    assert(run_register_fd_case(&gpu_data.nvfp,sizeof(payload),&payload)==NV_ERR_IN_USE);
    check_base_references(); gpu_data.nvfp.register_or_refcount=NVFP_TYPE_NONE; ++scenarios;

    lock_error=NV_ERR_INVALID_STATE;
    assert(run_register_fd_case(&gpu_data.nvfp,sizeof(payload),&payload)==NV_ERR_INVALID_STATE);
    check_base_references(); lock_error=NV_OK; ++scenarios;

    assert(run_register_fd_case(&ctl_data.nvfp,sizeof(payload),&payload)==NV_ERR_INVALID_ARGUMENT);
    check_base_references(); ++scenarios;

    assert(hybrid580_open_unregister_file_projection_v1(&projection_ops)==0);
    assert(scenarios==11);
    printf("R580 REGISTER_FD CPU scenarios: %u; held control reference released on GPU close\n",scenarios);
    return 0;
}
'''

CASES = r'''
static struct module provider_module, other_module;
static const struct file_operations front_fops = { &provider_module };
static const struct file_operations other_fops = { &other_module };
static struct inode ctl_inode, gpu_inode, wrong_inode;
static nv_linux_file_private_t ctl_data, gpu_data;
static struct file front, ctl, gpu, foreign;
static atomic_int calls, callback_entered, callback_release, callback_block;
static bool last_ctl;
static struct file *project(struct file *f, bool is_ctl) {
    assert(read_depth && !write_depth);
    atomic_fetch_add(&calls,1); last_ctl=is_ctl;
    /* Deliberately retain a CPU-model reader to test writer lifetime.
     * This spinning fixture violates the bounded O(1) production callback
     * contract and is never a suggested provider implementation. */
    if (atomic_load(&callback_block)) {
        atomic_store(&callback_entered,1);
        while (!atomic_load(&callback_release)) sched_yield();
    }
    if (f->back == (void *)(intptr_t)-EINVAL) return f->back;
    return f->back ? get_file(f->back) : NULL;
}
static struct hybrid580_file_projection_ops_v1 ops = {
    HYBRID580_FILE_PROJECTION_ABI_V1, sizeof(ops),
    &provider_module, &front_fops, project
};
static void check_balance(void) {
    assert(atomic_load(&front.refs)==1 && atomic_load(&ctl.refs)==1);
    assert(atomic_load(&gpu.refs)==1 && atomic_load(&foreign.refs)==1);
    assert(atomic_load(&provider_module.refs)==0);
}
static void no_lookup(void) {
    void *priv=(void *)1;
    assert(nv_get_file_private(0,NV_TRUE,&priv)==NULL && priv==NULL);
    check_balance();
}
static void *lookup_thread(void *unused) {
    void *priv=NULL;
    assert(nv_get_file_private(0,NV_TRUE,&priv)==&ctl_data.nvfp);
    nv_put_file_private(priv); return NULL;
}
static void *unregister_thread(void *unused) {
    assert(hybrid580_open_unregister_file_projection_v1(&ops)==0); return NULL;
}
int main(void) {
    unsigned cases=0;
    hybrid_chrdev_base=makedev(240,0);
    ctl_inode=(struct inode){makedev(240,255),S_IFCHR};
    gpu_inode=(struct inode){makedev(240,0),S_IFCHR};
    wrong_inode=(struct inode){makedev(195,255),S_IFCHR};
    ctl_data.nvptr=&nv_ctl_device; gpu_data.nvptr=&gpu_state;
    nv_ctl_device.nv_state.flags=NV_FLAG_OPEN|NV_FLAG_CONTROL;
    nv_linux_minor_num_table[0]=&gpu_state;
    ctl=(struct file){&nvidia_fops,&ctl_inode,&ctl_data,1,NULL};
    gpu=(struct file){&nvidia_fops,&gpu_inode,&gpu_data,1,NULL};
    foreign=(struct file){&other_fops,&ctl_inode,&ctl_data,1,NULL};
    front=(struct file){&front_fops,&ctl_inode,NULL,1,&ctl}; fd_files[0]=&front;
    no_lookup(); ++cases;
    assert(hybrid580_open_unregister_file_projection_v1(&ops)==-ENOENT); ++cases;
    assert(hybrid580_open_register_file_projection_v1(NULL)==-EINVAL); ++cases;
    struct hybrid580_file_projection_ops_v1 bad=ops;
    bad.abi_version++; assert(hybrid580_open_register_file_projection_v1(&bad)==-EINVAL); ++cases;
    bad=ops; bad.struct_size--; assert(hybrid580_open_register_file_projection_v1(&bad)==-EINVAL); ++cases;
    bad=ops; bad.owner=NULL; assert(hybrid580_open_register_file_projection_v1(&bad)==-EINVAL); ++cases;
    bad=ops; bad.frontend_fops=NULL; assert(hybrid580_open_register_file_projection_v1(&bad)==-EINVAL); ++cases;
    bad=ops; bad.frontend_fops=&nvidia_fops; assert(hybrid580_open_register_file_projection_v1(&bad)==-EINVAL); ++cases;
    bad=ops; bad.owner=&other_module; assert(hybrid580_open_register_file_projection_v1(&bad)==-EINVAL); ++cases;
    bad=ops; bad.get_backing_file=NULL; assert(hybrid580_open_register_file_projection_v1(&bad)==-EINVAL); ++cases;
    fail_alloc=1; assert(hybrid580_open_register_file_projection_v1(&ops)==-ENOMEM); fail_alloc=0; ++cases;
    assert(hybrid580_open_register_file_projection_v1(&ops)==0); ++cases;
    assert(hybrid580_open_register_file_projection_v1(&ops)==-EBUSY); ++cases;
    assert(hybrid580_open_unregister_file_projection_v1(&bad)==-ENOENT); ++cases;
    void *priv=NULL;
    assert(nv_get_file_private(0,NV_TRUE,&priv)==&ctl_data.nvfp && priv==&ctl && last_ctl);
    assert(atomic_load(&ctl.refs)==2); nv_put_file_private(priv); check_balance(); ++cases;
    ops.get_backing_file=NULL;
    assert(nv_get_file_private(0,NV_TRUE,&priv)==&ctl_data.nvfp); nv_put_file_private(priv);
    ops.get_backing_file=project; check_balance(); ++cases;
    atomic_store(&provider_module.going,true); int before=atomic_load(&calls);
    no_lookup(); assert(atomic_load(&calls)==before); atomic_store(&provider_module.going,false); ++cases;
    front.back=NULL; no_lookup(); front.back=&ctl; ++cases;
    front.back=&foreign; no_lookup(); front.back=&ctl; ++cases;
    front.back=&front; no_lookup(); front.back=&ctl; ++cases;
    front.back=(void *)(intptr_t)-EINVAL; no_lookup(); front.back=&ctl; ++cases;
    ctl.inode=&wrong_inode; no_lookup(); ctl.inode=&ctl_inode; ++cases;
    ctl_inode.i_rdev=makedev(240,248); no_lookup(); ctl_inode.i_rdev=makedev(240,255); ++cases;
    ctl_inode.i_mode=S_IFREG; no_lookup(); ctl_inode.i_mode=S_IFCHR; ++cases;
    ctl.inode=NULL; no_lookup(); ctl.inode=&ctl_inode; ++cases;
    ctl.private_data=NULL; no_lookup(); ctl.private_data=&ctl_data; ++cases;
    ctl_data.nvptr=NULL; no_lookup(); ctl_data.nvptr=&nv_ctl_device; ++cases;
    ctl_data.nvptr=&other_gpu_state; no_lookup(); ctl_data.nvptr=&nv_ctl_device; ++cases;
    nv_ctl_device.nv_state.flags=NV_FLAG_CONTROL; no_lookup();
    nv_ctl_device.nv_state.flags=NV_FLAG_OPEN|NV_FLAG_CONTROL; ++cases;
    assert(nv_get_file_private(0,NV_TRUE,NULL)==NULL); check_balance(); ++cases;
    fd_files[0]=&ctl; before=atomic_load(&calls);
    assert(nv_match_dev_state(&nv_ctl_device,&ctl,0));
    assert(!nv_match_dev_state(&gpu_state,&ctl,0));
    assert(nv_get_file_private(0,NV_TRUE,&priv)==&ctl_data.nvfp); nv_put_file_private(priv);
    assert(atomic_load(&calls)==before); check_balance(); ++cases;
    fd_files[0]=&gpu;
    assert(nv_get_file_private(0,NV_FALSE,&priv)==&gpu_data.nvfp); nv_put_file_private(priv);
    assert(nv_match_dev_state(&gpu_state,&gpu,0)); assert(!nv_match_dev_state(&other_gpu_state,&gpu,0));
    assert(atomic_load(&calls)==before); check_balance(); ++cases;
    fd_files[0]=&front; front.back=&gpu;
    assert(nv_get_file_private(0,NV_FALSE,&priv)==&gpu_data.nvfp && !last_ctl); nv_put_file_private(priv);
    assert(nv_match_dev_state(&gpu_state,&front,0) && !last_ctl);
    assert(!nv_match_dev_state(&other_gpu_state,&front,0)); check_balance(); ++cases;
    nv_linux_minor_num_table[0]=&other_gpu_state;
    assert(!nv_match_dev_state(&gpu_state,&front,0));
    nv_linux_minor_num_table[0]=&gpu_state; check_balance(); ++cases;
    front.f_op=&other_fops; no_lookup(); front.f_op=&front_fops; ++cases;
    front.back=&ctl;
    assert(!nv_match_dev_state(&nv_ctl_device,&front,0)); check_balance(); ++cases;
    atomic_store(&callback_block,1); atomic_store(&writer_wait_test,1); atomic_store(&writer_entered,0); atomic_store(&writer_completed,0);
    pthread_t reader,remover;
    assert(!pthread_create(&reader,NULL,lookup_thread,NULL));
    while (!atomic_load(&callback_entered)) sched_yield();
    assert(!pthread_create(&remover,NULL,unregister_thread,NULL));
    while (!atomic_load(&writer_entered)) sched_yield();
    assert(!atomic_load(&writer_completed));
    atomic_store(&callback_release,1);
    pthread_join(reader,NULL); pthread_join(remover,NULL);
    assert(atomic_load(&writer_completed)); check_balance(); ++cases;
    no_lookup(); assert(hybrid580_open_unregister_file_projection_v1(&ops)==-ENOENT); ++cases;
    printf("projection CPU scenarios: %u; writer waited for reader\n",cases);
    return 0;
}
'''
