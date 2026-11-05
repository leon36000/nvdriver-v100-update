# SPDX-License-Identifier: MIT
"""Actual frontend + broker code with CPU VFS/module/session doubles only."""
from pathlib import Path
import importlib.util
import re
import subprocess
import tempfile
import unittest

from test_rm_root_client import include_flags

ROOT = Path(__file__).resolve().parents[1]
OPEN = ROOT / 'build/experiments/private-open-gpu-inventory-v2/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia'

PREAMBLE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#define MAJOR(device) major(device)
#define MINOR(device) minor(device)
#include "nv-ioctl-numbers.h"
#include "nv-ioctl.h"
#include "nv-ioctl-numa.h"
#include "nv-chardev-numbers.h"
#include "nv-unix-nvos-params-wrappers.h"
#include <ctrl/ctrl0000/ctrl0000gpu.h>
#include <ctrl/ctrl0000/ctrl0000system.h>
#include <ctrl/ctrl0000/ctrl0000syncgpuboost.h>
#include <ctrl/ctrl2080/ctrl2080gr.h>
#include <class/cl0080.h>
#include <class/cl2080.h>
#include <class/clc361.h>
#include <class/clc661.h>
#include <class/cl003e.h>
#include <class/cl0040.h>
#include <class/cl50a0.h>
#include <class/cl9067.h>
#include <class/cl90e6.h>
#include <ctrl/ctrl90e6.h>
#include <ctrl/ctrl83de/ctrl83dedebug.h>
#include <class/clc36f.h>
#include <class/clc96f.h>
#include <class/clc3b5.h>
#include <class/clc3c0.h>
#include <class/clcab5.h>
#include <class/clcec0.h>
#include <class/cl83de.h>
#include <class/cl503c.h>
#include <class/cl00de.h>
#include <alloc/alloc_channel.h>
#include "rm_root_client.h"
#include "hybrid580-control-session.h"
#include "hybrid580_uvm_dup_memory_route.h"
/* Keep this harness independent of ctrl0000client.h: the R580 kernel-open
 * include tree also exposes a distinct rs_access.h with duplicate typedefs. */
#define NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY 0x00000d04U
typedef struct NV0000_CTRL_CLIENT_SET_INHERITED_SHARE_POLICY_PARAMS {
 RS_SHARE_POLICY sharePolicy;
} NV0000_CTRL_CLIENT_SET_INHERITED_SHARE_POLICY_PARAMS;
#define __user
#define __init
#define __exit
#define module_param(...)
#define MODULE_PARM_DESC(...)
#define MODULE_LICENSE(...)
#define MODULE_DESCRIPTION(...)
#define module_init(...)
#define module_exit(...)
#define CONFIG_COMPAT 1
#define HYBRID580_UVM_ABI_R580 1
#define GFP_KERNEL 0
#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "BUILD_BUG_ON")
#define MISC_DYNAMIC_MINOR 255
typedef unsigned int u32;
typedef uint32_t __u32;
typedef int32_t __s32;
struct module { int dummy; };
static struct module module;
#define THIS_MODULE (&module)
struct inode { dev_t i_rdev; };
struct file;
struct vm_area_struct;
typedef unsigned int __poll_t;
struct wait_queue_head { int identity; };
typedef struct wait_queue_head wait_queue_head_t;
static unsigned int association_wait_wakes;
static void init_waitqueue_head(wait_queue_head_t *queue) { queue->identity=1; }
static void wake_up_interruptible_poll(wait_queue_head_t *queue, unsigned int mask) {
 assert(queue && mask); ++association_wait_wakes;
}
struct poll_table_struct;
typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);
typedef struct poll_table_struct { poll_queue_proc _qproc; unsigned int _key; } poll_table;
#define POLLERR 0x008U
#define POLLIN 0x001U
#define POLLPRI 0x002U
#define EPOLLERR 0x008U
#define EPOLLIN 0x001U
#define EPOLLRDNORM 0x040U
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, next) ((value)=(next))
static void poll_wait(struct file *file, wait_queue_head_t *queue, poll_table *pt) {
 if(pt && pt->_qproc) pt->_qproc(file,queue,pt);
}
struct file_operations {
 struct module *owner;
 int (*open)(struct inode *, struct file *);
 int (*release)(struct inode *, struct file *);
 long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
 long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
 __poll_t (*poll)(struct file *, poll_table *);
 int (*mmap)(struct file *, struct vm_area_struct *);
 long (*llseek)(void);
};
struct file { const struct file_operations *f_op; void *private_data; atomic_int refs; bool heap_allocated; int f_flags; };
struct vm_area_struct { struct file *vm_file; unsigned long vm_pgoff; unsigned long vm_start, vm_end; };
struct miscdevice { int minor; const char *name; const struct file_operations *fops; unsigned mode; };
static long no_llseek(void) { return 0; }
struct mutex { pthread_mutex_t p; };
typedef struct { int counter; } atomic_t;
static int atomic_read(const atomic_t *value) { return value->counter; }
static void atomic_set(atomic_t *value, int next) { value->counter=next; }
static void atomic_inc(atomic_t *value) { ++value->counter; }
static int atomic_dec_if_positive(atomic_t *value) {
 if(value->counter<=0) return -1;
 return --value->counter;
}
struct list_head { struct list_head *next, *prev; };
static void model_list_init(struct list_head *head) { head->next=head; head->prev=head; }
static void model_list_add(struct list_head *node, struct list_head *head) {
 node->next=head->next; node->prev=head; head->next->prev=node; head->next=node;
}
#define LIST_HEAD(name) struct list_head name = { &(name), &(name) }
#define INIT_LIST_HEAD(head) model_list_init(head)
#define list_add(node, head) model_list_add((node),(head))
static _Thread_local int lock_depth;
#define DEFINE_MUTEX(name) struct mutex name = { .p = PTHREAD_MUTEX_INITIALIZER }
typedef pthread_mutex_t spinlock_t;
#define DEFINE_SPINLOCK(name) spinlock_t name = PTHREAD_MUTEX_INITIALIZER
#define DECLARE_WAIT_QUEUE_HEAD(name) wait_queue_head_t name = { .identity = -1 }
#define TASK_UNINTERRUPTIBLE 0x02
#define TASK_FREEZABLE 0x2000
#define __maybe_unused __attribute__((unused))
#define __used __attribute__((used))
static bool allow_warn_once;
static bool model_warn_on_once(bool condition) {
 if(condition) { assert(allow_warn_once); allow_warn_once=false; }
 return condition;
}
#define WARN_ON_ONCE(condition) model_warn_on_once(!!(condition))
static int model_wait_event_freezable(wait_queue_head_t *queue, bool condition) {
 (void)queue; assert(condition); return 0;
}
static void model_wait_event_state(wait_queue_head_t *queue, bool condition, int state) {
 (void)queue; (void)state; assert(condition);
}
static void model_wait_event(wait_queue_head_t *queue, bool condition) {
 (void)queue; assert(condition);
}
#define wait_event_freezable(queue, condition) model_wait_event_freezable(&(queue), (condition))
#define wait_event_state(queue, condition, state) model_wait_event_state(&(queue), (condition), (state))
#define wait_event(queue, condition) model_wait_event(&(queue), (condition))
static void wake_up_all(wait_queue_head_t *queue) { assert(queue); }
static void spin_lock_init(spinlock_t *lock) { assert(!pthread_mutex_init(lock,NULL)); }
static void model_spin_lock_irqsave(spinlock_t *lock,unsigned long *flags) { *flags=0; assert(!pthread_mutex_lock(lock)); }
static void model_spin_unlock_irqrestore(spinlock_t *lock,unsigned long flags) { (void)flags; assert(!pthread_mutex_unlock(lock)); }
#define spin_lock_irqsave(lock,flags) model_spin_lock_irqsave((lock),&(flags))
#define spin_unlock_irqrestore(lock,flags) model_spin_unlock_irqrestore((lock),(flags))
static int interrupt_lock, from_fault, from_fault_call, copy_from_user_calls, to_fault;
static int mutate_xfer_after_copy, mutate_register_fd_after_copy;
static int to_fault_call, copy_to_user_calls;
static int fail_alloc, fail_alloc_at, alloc_calls, live_model_allocs;
static int fail_create, fail_register, fail_misc;
static int fail_anon_file, fail_fd_alloc, next_fd = 40;
static unsigned int last_fd_flags, last_anon_flags;
static bool fd_reserved[128];
static struct file *installed_fds[128];
static struct file *register_gpu_front, *register_control_front;
static struct file *register_fd_reuse_front, *register_backend_control_front;
static int register_fd_calls, register_fd_matches;
static int register_fd_error;
static int created[2], session_puts[2], calls[2], frees[2], registrations[2], unregistrations[2], device_registers, device_unregisters;
static bool standard_nodes_ready;
static const struct hybrid580_gpu_catalog_v1 *standard_nodes_catalog;
static unsigned int standard_nodes_unregisters;
static int control_create_calls[2], fail_create_call[2];
static int alloc_error_backend = -1, free_error_backend = -1;
static NvHandle next_root = 987;
static bool zero_failure_handle, duplicate_handle;
static bool duplicate_second;
static bool active_calls_block, entered_call, allow_call;
static pthread_mutex_t block_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t block_cond = PTHREAD_COND_INITIALIZER;
static void (*mutex_lock_interruptible_hook)(struct mutex *);
static void mutex_init(struct mutex *m) { assert(!pthread_mutex_init(&m->p, NULL)); }
static void mutex_lock(struct mutex *m) { assert(!pthread_mutex_lock(&m->p)); ++lock_depth; }
static void mutex_unlock(struct mutex *m) { --lock_depth; assert(!pthread_mutex_unlock(&m->p)); }
static int mutex_trylock(struct mutex *m) {
 int rc=pthread_mutex_trylock(&m->p); if(!rc) ++lock_depth; return rc==0;
}
static void spin_lock(spinlock_t *lock) { assert(!pthread_mutex_lock(lock)); }
static void spin_unlock(spinlock_t *lock) { assert(!pthread_mutex_unlock(lock)); }
static int mutex_lock_interruptible(struct mutex *m) {
 if(interrupt_lock) return -EINTR;
 if(mutex_lock_interruptible_hook) mutex_lock_interruptible_hook(m);
 mutex_lock(m); return 0;
}
static void *model_alloc(size_t size) {
 ++alloc_calls;
 if(fail_alloc || alloc_calls==fail_alloc_at) return NULL;
 void *p=calloc(1,size); if(p) ++live_model_allocs; return p;
}
static void *kzalloc(size_t size, int flags) { (void)flags; return model_alloc(size); }
static void *kcalloc(size_t n, size_t size, int flags) {
 (void)flags; if(n && size>SIZE_MAX/n) return NULL; return model_alloc(n*size);
}
static void *kvzalloc(size_t size, int flags) { return kzalloc(size,flags); }
static void *kvcalloc(size_t n, size_t size, int flags) { return kcalloc(n,size,flags); }
static void kfree(void *p) { if(p) { assert(live_model_allocs>0); --live_model_allocs; } free(p); }
static void kvfree(void *p) { if(p) { assert(live_model_allocs>0); --live_model_allocs; } free(p); }
static int copy_from_user(void *d, const void *s, size_t n) {
 ++copy_from_user_calls;
 if(from_fault || (from_fault_call && copy_from_user_calls==from_fault_call)) return 1;
 memcpy(d,s,n);
 if(mutate_xfer_after_copy) {
  ((nv_ioctl_xfer_t *)(uintptr_t)s)->cmd=NV_ESC_REGISTER_FD;
  mutate_xfer_after_copy=0;
 }
 if(mutate_register_fd_after_copy && n==sizeof(nv_ioctl_register_fd_t)) {
  ((nv_ioctl_register_fd_t *)(uintptr_t)s)->ctl_fd=99;
  mutate_register_fd_after_copy=0;
 }
 return 0;
}
static int copy_to_user(void *d, const void *s, size_t n) {
 ++copy_to_user_calls;
 if(to_fault || (to_fault_call && copy_to_user_calls==to_fault_call)) return 1;
 memcpy(d,s,n); return 0;
}
static struct file *get_file(struct file *f) { ++f->refs; return f; }
static struct file *fget(unsigned int fd) {
 if(fd>=128 || !installed_fds[fd]) return NULL;
 return get_file(installed_fds[fd]);
}
static void fput(struct file *f) {
 if(atomic_fetch_sub(&f->refs,1)==1) {
  if(f->f_op && f->f_op->release) assert(!f->f_op->release(NULL,f));
  if(f->heap_allocated) free(f);
 }
}
static void vma_set_file(struct vm_area_struct *vma, struct file *file) {
 get_file(file); struct file *old=vma->vm_file; vma->vm_file=file; fput(old);
}
static struct file *anon_inode_getfile(const char *name, const struct file_operations *ops, void *data, int flags) {
 (void)name; last_anon_flags=(unsigned)flags; if(fail_anon_file) return (struct file *)(intptr_t)-ENOMEM;
 struct file *f=calloc(1,sizeof(*f)); if(!f) return (struct file *)(intptr_t)-ENOMEM;
 f->f_op=ops; f->private_data=data; f->refs=1; f->heap_allocated=true; f->f_flags=flags; return f;
}
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
static int get_unused_fd_flags(unsigned int flags) { last_fd_flags=flags; if(fail_fd_alloc) return -EMFILE; for(int i=next_fd;i<128;i++) if(!fd_reserved[i] && !installed_fds[i]) { fd_reserved[i]=true; return i; } return -EMFILE; }
static void put_unused_fd(unsigned int fd) { assert(fd<128 && fd_reserved[fd] && !installed_fds[fd]); fd_reserved[fd]=false; }
static void fd_install(unsigned int fd, struct file *f) { assert(fd<128 && fd_reserved[fd] && !installed_fds[fd]); fd_reserved[fd]=false; installed_fds[fd]=f; }
static void close_test_fd(int fd) { assert(fd>=0 && fd<128 && installed_fds[fd]); struct file *f=installed_fds[fd]; installed_fds[fd]=NULL; fput(f); }
'''

BACKENDS = r'''
static struct file *hybrid_front_project_legacy(struct file *, bool);
static struct file *hybrid_front_project_open(struct file *, bool);
struct hybrid580_control_session { int backend; struct file file; };
struct hybrid580_gpu_session { int backend; char bdf[16]; struct file *file; };
static struct hybrid580_control_session *register_expected_session;
static struct hybrid580_control_session *register_replacement_session;
static struct hybrid580_control_session *register_bound_session;
static NvU64 sys_params_value[2];
static int sys_params_set[2], sys_params_calls[2], sys_params_error[2];
static int fake_sys_params(struct hybrid580_control_session *session, NvU64 value) {
 assert(lock_depth==2 && session);
 int backend=session->backend;
 ++sys_params_calls[backend];
 if(sys_params_error[backend]) return sys_params_error[backend];
 if(!sys_params_set[backend]) {
  sys_params_set[backend]=1; sys_params_value[backend]=value; return 0;
 }
 return sys_params_value[backend]==value ? 0 : -EBUSY;
}
int hybrid580_legacy_control_session_sys_params_v1(
 struct hybrid580_control_session *session, NvU64 value) {
 return fake_sys_params(session,value);
}
int hybrid580_open_control_session_sys_params_v1(
    struct hybrid580_control_session *session, NvU64 value) {
 return fake_sys_params(session,value);
}
static int version_check_calls[2];
static NV_STATUS version_check_transport[2]={NV_OK,NV_OK};
static NvU32 version_check_reply[2]={NV_RM_API_VERSION_REPLY_RECOGNIZED,
                                     NV_RM_API_VERSION_REPLY_RECOGNIZED};
static NvU32 version_check_sizes[2];
static nv_ioctl_rm_api_version_t version_check_inputs[2];
static NV_STATUS fake_check_version(struct hybrid580_control_session *session,
                                    nv_ioctl_rm_api_version_t *params,
                                    NvU32 size) {
 assert(lock_depth==1 && session && params);
 int backend=session->backend;
 ++version_check_calls[backend];
 version_check_sizes[backend]=size;
 version_check_inputs[backend]=*params;
 params->reply=version_check_reply[backend];
 if(version_check_transport[backend]==NV_ERR_GENERIC)
  memcpy(params->versionString,"580.178.04",sizeof("580.178.04"));
 return version_check_transport[backend];
}
NV_STATUS hybrid580_legacy_control_session_check_version_v1(
 struct hybrid580_control_session *session,
 nv_ioctl_rm_api_version_t *params, NvU32 size) {
 return fake_check_version(session,params,size);
}
NV_STATUS hybrid580_open_control_session_check_version_v1(
 struct hybrid580_control_session *session,
 nv_ioctl_rm_api_version_t *params, NvU32 size) {
 return fake_check_version(session,params,size);
}
static int build_version_calls[2];
static NV_STATUS build_version_transport=NV_OK, build_version_embedded=NV_OK;
static bool build_version_malformed, build_version_no_status;
static NvHandle build_version_client, build_version_object;
static NvU32 build_version_flags, build_version_payload_size;
static NV_STATUS fake_build_version(struct hybrid580_control_session *session,
                                    NvHandle h_client, NvHandle h_object,
                                    NvU32 flags,
                                    NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS *params,
                                    NvU32 *control_status) {
 assert(lock_depth==1 && session && session->backend==HYBRID580_BACKEND_OPEN);
 assert(params && control_status && h_client==h_object && flags==NVOS54_FLAGS_NONE);
 ++build_version_calls[session->backend];
 build_version_client=h_client; build_version_object=h_object;
 build_version_flags=flags; build_version_payload_size=sizeof(*params);
 memset(params,0,sizeof(*params));
 if(build_version_malformed) {
  memset(params->driverVersionBuffer,'D',sizeof(params->driverVersionBuffer));
  memset(params->versionBuffer,'V',sizeof(params->versionBuffer));
  memset(params->titleBuffer,'T',sizeof(params->titleBuffer));
 } else {
  memcpy(params->driverVersionBuffer,"580.178.04",sizeof("580.178.04"));
  memcpy(params->versionBuffer,"R580.178",sizeof("R580.178"));
  memcpy(params->driverBranch,"580",sizeof("580"));
  memcpy(params->titleBuffer,"NVIDIA UNIX Open Kernel Module Driver",
         sizeof("NVIDIA UNIX Open Kernel Module Driver"));
 }
 params->changelistNumber=58017804U;
 params->officialChangelistNumber=58017800U;
 if(!build_version_no_status) *control_status=(NvU32)build_version_embedded;
 return build_version_transport;
}
NV_STATUS hybrid580_open_control_session_build_version_v1(
    struct hybrid580_control_session *session, NvHandle h_client,
    NvHandle h_object, NvU32 flags,
    NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS *params,
    NvU32 *control_status) {
 return fake_build_version(session,h_client,h_object,flags,params,control_status);
}
static int system_features_calls[2];
static NV_STATUS system_features_transport=NV_OK, system_features_embedded=NV_OK;
static bool system_features_no_status;
static NvHandle system_features_client, system_features_object;
static NvU32 system_features_flags, system_features_payload_size;
NV_STATUS hybrid580_open_control_session_system_features_v1(
 struct hybrid580_control_session *session, NvHandle h_client,
 NvHandle h_object, NvU32 flags,
 NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS *params, NvU32 *control_status) {
 assert(lock_depth==1 && session && session->backend==HYBRID580_BACKEND_OPEN);
 assert(params && control_status && h_client==h_object && flags==NVOS54_FLAGS_NONE);
 ++system_features_calls[session->backend];
 system_features_client=h_client; system_features_object=h_object;
 system_features_flags=flags; system_features_payload_size=sizeof(*params);
 params->featuresMask=0x00000015U;
 if(!system_features_no_status) *control_status=(NvU32)system_features_embedded;
 return system_features_transport;
}
static int fabric_status_calls[2];
static NV_STATUS fabric_status_transport=NV_OK, fabric_status_embedded=NV_OK;
static bool fabric_status_no_status;
static NvHandle fabric_status_client, fabric_status_object;
static NvU32 fabric_status_flags, fabric_status_payload_size;
NV_STATUS hybrid580_open_control_session_fabric_status_v1(
 struct hybrid580_control_session *session, NvHandle h_client,
 NvHandle h_object, NvU32 flags,
 NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS *params, NvU32 *control_status) {
 assert(lock_depth==1 && session && session->backend==HYBRID580_BACKEND_OPEN);
 assert(params && control_status && h_client==h_object && flags==NVOS54_FLAGS_NONE);
 ++fabric_status_calls[session->backend];
 fabric_status_client=h_client; fabric_status_object=h_object;
 fabric_status_flags=flags; fabric_status_payload_size=sizeof(*params);
 params->fabricStatus=NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_INITIALIZED;
 if(!fabric_status_no_status) *control_status=(NvU32)fabric_status_embedded;
 return fabric_status_transport;
}
static int sync_boost_calls[2];
static NV_STATUS sync_boost_transport[2]={NV_OK,NV_OK};
static NvU32 sync_boost_embedded[2]={NV_OK,NV_OK};
static NvU32 sync_boost_count[2]={0,0};
static bool sync_boost_no_status[2], sync_boost_no_count[2];
static NvHandle sync_boost_client[2], sync_boost_object[2];
static NvU32 sync_boost_flags[2], sync_boost_payload_size[2];
static NV_STATUS fake_sync_boost_groups(unsigned int backend,
 struct hybrid580_control_session *session, NvHandle h_client,
 NvHandle h_object, NvU32 flags, NvU32 *group_count,
 NvU32 *control_status) {
 assert(lock_depth==1 && session && (unsigned int)session->backend==backend);
 assert(group_count && control_status && h_client==h_object &&
        flags==NVOS54_FLAGS_NONE);
 ++sync_boost_calls[backend];
 sync_boost_client[backend]=h_client; sync_boost_object[backend]=h_object;
 sync_boost_flags[backend]=flags;
 sync_boost_payload_size[backend]=sizeof(NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS);
 *group_count=0xffffffffU;
 if(!sync_boost_no_status[backend])
  *control_status=sync_boost_embedded[backend];
 if(sync_boost_transport[backend]!=NV_OK ||
    sync_boost_embedded[backend]!=NV_OK || sync_boost_no_status[backend] ||
    sync_boost_no_count[backend]) return sync_boost_transport[backend];
 *group_count=sync_boost_count[backend];
 return NV_OK;
}
NV_STATUS hybrid580_legacy_control_session_sync_boost_groups_v1(
 struct hybrid580_control_session *session, NvHandle h_client,
 NvHandle h_object, NvU32 flags, NvU32 *group_count,
 NvU32 *control_status) {
 return fake_sync_boost_groups(HYBRID580_BACKEND_LEGACY,session,h_client,
     h_object,flags,group_count,control_status);
}
NV_STATUS hybrid580_open_control_session_sync_boost_groups_v1(
 struct hybrid580_control_session *session, NvHandle h_client,
 NvHandle h_object, NvU32 flags, NvU32 *group_count,
 NvU32 *control_status) {
 return fake_sync_boost_groups(HYBRID580_BACKEND_OPEN,session,h_client,
     h_object,flags,group_count,control_status);
}
static int share_policy_calls[2];
static NV_STATUS share_policy_transport[2]={NV_OK,NV_OK};
static NV_STATUS share_policy_embedded[2]={NV_OK,NV_OK};
static NvHandle share_policy_client[2], share_policy_object[2];
static NvU32 share_policy_flags[2];
static RS_SHARE_POLICY share_policy_params[2];
static NV_STATUS fake_client_share_policy(unsigned int backend,
    struct hybrid580_control_session *session, NvHandle h_client,
    NvHandle h_object, NvU32 flags,
    RS_SHARE_POLICY *params,
    NvU32 *control_status) {
 assert(lock_depth==1 && session && (unsigned int)session->backend==backend);
 assert(params && control_status && h_client==h_object &&
        flags==NVOS54_FLAGS_NONE);
 ++share_policy_calls[backend];
 share_policy_client[backend]=h_client;
 share_policy_object[backend]=h_object;
 share_policy_flags[backend]=flags;
 share_policy_params[backend]=*params;
 *control_status=(NvU32)share_policy_embedded[backend];
 return share_policy_transport[backend];
}
NV_STATUS hybrid580_legacy_control_session_client_share_policy_v1(
    struct hybrid580_control_session *session, NvHandle h_client,
    NvHandle h_object, NvU32 flags,
    RS_SHARE_POLICY *params,
    NvU32 *control_status) {
 return fake_client_share_policy(HYBRID580_BACKEND_LEGACY,session,
     h_client,h_object,flags,params,control_status);
}
NV_STATUS hybrid580_open_control_session_client_share_policy_v1(
    struct hybrid580_control_session *session, NvHandle h_client,
    NvHandle h_object, NvU32 flags,
    RS_SHARE_POLICY *params,
    NvU32 *control_status) {
 return fake_client_share_policy(HYBRID580_BACKEND_OPEN,session,
     h_client,h_object,flags,params,control_status);
}
static int gpu_mmap_calls[2], gpu_mmap_error[2];
static struct file *gpu_mmap_files[2];
static int gpu_poll_calls[2];
static __poll_t gpu_poll_masks[2];
static int gpu_poll_flags[2];
static struct file *gpu_poll_files[2];
static poll_table *gpu_poll_tables[2];
static wait_queue_head_t gpu_poll_waitqueues[2]={{.identity=0},{.identity=1}};
static struct file *poll_wait_files[8];
static wait_queue_head_t *poll_wait_queues[8];
static int poll_wait_calls, gate_poll_wait_calls;
static struct file *epoll_poll_file_seen;
static wait_queue_head_t *epoll_poll_queue_seen;
static int epoll_poll_qproc_calls;
static void fake_poll_qproc(struct file *file, wait_queue_head_t *queue, poll_table *pt) {
 if(queue->identity==-1) { ++gate_poll_wait_calls; return; }
 (void)pt; assert(poll_wait_calls<8); poll_wait_files[poll_wait_calls]=get_file(file);
 poll_wait_queues[poll_wait_calls]=queue; ++poll_wait_calls;
}
static void fake_epoll_qproc(struct file *file, wait_queue_head_t *queue, poll_table *pt) {
 (void)pt; ++epoll_poll_qproc_calls;
 if(queue->identity==-1) ++gate_poll_wait_calls;
 epoll_poll_file_seen=file; epoll_poll_queue_seen=queue;
}
static int gpu_map_calls[2], gpu_map_fd_expected;
static struct file *gpu_map_context_files[2];
static const struct file_operations fake_backend_fops;
static NvHandle map_test_root, map_test_device, map_test_memory;
static NvHandle map_test_backend_device, map_test_backend_memory;
static int control_map_calls[2], control_unmap_calls[2], control_mmap_calls[2];
static int control_map_transport[2], control_map_status[2], control_mmap_error[2];
static struct file *control_map_context_files[2], *control_mmap_files[2];
static NvHandle control_map_clients[2], control_map_devices[2], control_map_memories[2];
static int control_map_target_fds[2];
static NvU32 control_map_flags[2];
static int fake_backend_mmap(struct file *file, struct vm_area_struct *vma) {
 struct hybrid580_gpu_session *session=file->private_data;
 assert(session && vma && vma->vm_file==file);
 assert(gpu_map_context_files[session->backend]==file);
 ++gpu_mmap_calls[session->backend]; gpu_mmap_files[session->backend]=file;
 return gpu_mmap_error[session->backend];
}
static int fake_backend_control_mmap(struct file *file, struct vm_area_struct *vma) {
 struct hybrid580_control_session *session=file->private_data;
 assert(session && vma && vma->vm_file==file);
 assert(control_map_context_files[session->backend]==file);
 ++control_mmap_calls[session->backend]; control_mmap_files[session->backend]=file;
 return control_mmap_error[session->backend];
}
static long fake_backend_control_ioctl(struct file *file, unsigned int command,
                                       unsigned long argument) {
 struct hybrid580_control_session *session=file->private_data;
 int backend=session->backend;
 if(_IOC_TYPE(command)!=NV_IOCTL_MAGIC) return -ENOTTY;
 if(_IOC_NR(command)==NV_ESC_RM_MAP_MEMORY) {
  nv_ioctl_nvos33_parameters_with_fd *params=(void *)argument;
  struct file *target, *mapped=NULL;
  assert(_IOC_SIZE(command)==sizeof(*params));
  ++control_map_calls[backend];
  control_map_clients[backend]=params->params.hClient;
  control_map_devices[backend]=params->params.hDevice;
  control_map_memories[backend]=params->params.hMemory;
  control_map_flags[backend]=params->params.flags;
  control_map_target_fds[backend]=(int)params->fd;
  if(control_map_transport[backend]) return control_map_transport[backend];
  params->params.status=control_map_status[backend];
  if(params->params.status!=NV_OK) return 0;
  target=fget(params->fd); assert(target);
  if(backend==HYBRID580_BACKEND_LEGACY) {
   mapped=hybrid_front_project_legacy(target,true);
   if(!mapped) mapped=hybrid_front_project_legacy(target,false);
  } else {
   mapped=hybrid_front_project_open(target,true);
   if(!mapped) mapped=hybrid_front_project_open(target,false);
  }
  assert(mapped);
  if(target->private_data && mapped->private_data==session) {
   /* The exact projected file is retained as a borrowed identity below. */
  }
  if(mapped->f_op==&fake_backend_fops) {
   gpu_map_context_files[backend]=mapped;
   ++gpu_map_calls[backend];
  } else {
   control_map_context_files[backend]=mapped;
  }
  fput(mapped); fput(target);
  params->params.pLinearAddress=(NvP64)(uintptr_t)0x100000U;
  return 0;
 }
 if(_IOC_NR(command)==NV_ESC_RM_UNMAP_MEMORY) {
  NVOS34_PARAMETERS *params=(void *)argument;
  assert(_IOC_SIZE(command)==sizeof(*params));
  ++control_unmap_calls[backend];
  assert(params->hClient==control_map_clients[backend]);
  assert(params->hDevice==control_map_devices[backend]);
  assert(params->hMemory==control_map_memories[backend]);
  params->status=NV_OK;
  return 0;
 }
 return -ENOTTY;
}
static const struct file_operations fake_backend_control_fops={
 .unlocked_ioctl=fake_backend_control_ioctl,
 .mmap=fake_backend_control_mmap,
};
static __poll_t fake_backend_poll(struct file *file, poll_table *wait) {
 struct hybrid580_gpu_session *session=file->private_data;
 assert(session); ++gpu_poll_calls[session->backend]; gpu_poll_files[session->backend]=file;
 gpu_poll_tables[session->backend]=wait; gpu_poll_flags[session->backend]=file->f_flags;
 if(!(file->f_flags&O_NONBLOCK)) poll_wait(file,&gpu_poll_waitqueues[session->backend],wait);
 return gpu_poll_masks[session->backend];
}
static const struct file_operations fake_backend_fops={.poll=fake_backend_poll,.mmap=fake_backend_mmap};
static const struct file_operations fake_backend_no_poll_fops={.mmap=fake_backend_mmap};
struct fake_register_fd_payload { int ctl_fd; };
struct integrated_uvm_dup_probe {
 uintptr_t expected_device;
 uint32_t expected_client, expected_memory;
 uintptr_t output_handle, last_released;
 unsigned int duplicate_calls, release_calls;
};
static uint32_t integrated_uvm_duplicate(void *context, uintptr_t device,
    uint32_t client, uint32_t memory, uintptr_t *output, void *memory_info) {
 struct integrated_uvm_dup_probe *probe=context;
 (void)memory_info;
 assert(probe && output && device==probe->expected_device);
 assert(client==probe->expected_client && memory==probe->expected_memory);
 ++probe->duplicate_calls; *output=probe->output_handle; return 0;
}
static uint32_t integrated_uvm_release(void *context, uintptr_t device,
    uintptr_t memory) {
 struct integrated_uvm_dup_probe *probe=context;
 assert(probe && device==probe->expected_device);
 ++probe->release_calls; probe->last_released=memory; return 0;
}
static int backend_identity[2];
static struct hybrid580_gpu_backend_record_v1 inventory_records[2][HYBRID580_GPU_MAX_BACKEND_DEVICES];
static unsigned int inventory_count[2];
static int inventory_error[2], inventory_calls[2];
static nv_ioctl_card_info_t card_info_records[2][HYBRID580_GPU_MAX_BACKEND_DEVICES];
static unsigned int card_info_count[2], card_info_calls[2];
static int card_info_error[2];
static int gpu_id_info_calls[2];
static NvU32 gpu_id_info_input_ids[2], gpu_id_info_clients[2], gpu_id_info_objects[2];
static NvU32 gpu_id_info_device_instances[2] = {10, 11};
static NV_STATUS gpu_id_info_transport = NV_OK;
static NvU32 gpu_id_info_embedded = NV_OK;
static int gpu_id_info_fail_call[2];
static NV_STATUS gpu_id_info_failure_transport[2];
static NvU32 gpu_id_info_failure_embedded[2];
static int device_ids_calls[2];
static NvU32 device_ids_values[2], device_ids_clients[2], device_ids_objects[2];
static NV_STATUS device_ids_transport[2], device_ids_embedded[2];
static int device_alloc_calls[2], device_free_calls[2];
static NvHandle device_alloc_roots[2], device_alloc_handles[2];
static NvHandle device_free_roots[2], device_free_handles[2];
static NV0080_ALLOC_PARAMETERS device_alloc_params[2];
static NV_STATUS device_alloc_transport[2], device_alloc_embedded[2];
static NV_STATUS device_free_transport[2], device_free_embedded[2];
static NvHandle device_alloc_return_override[2];
static bool device_alloc_override_enabled[2];
static int subdevice_alloc_calls[2], gr_tpc_mask_calls[2];
static int master_alloc_calls[2], master_error_intr_calls[2];
static NvHandle master_alloc_roots[2], master_alloc_parents[2], master_alloc_handles[2];
static NvS32 master_alloc_param_values[2];
static NvHandle master_error_intr_roots[2], master_error_intr_objects[2];
static NV90E6_CTRL_MASTER_GET_ERROR_INTR_OFFSET_MASK_PARAMS master_error_intr_params[2];
static NV_STATUS master_alloc_transport[2], master_alloc_embedded[2];
static NV_STATUS master_error_intr_transport[2], master_error_intr_embedded[2];
static NvHandle subdevice_alloc_roots[2], subdevice_alloc_parents[2], subdevice_alloc_handles[2];
static NV2080_ALLOC_PARAMETERS subdevice_alloc_params[2];
static NV_STATUS subdevice_alloc_transport[2], subdevice_alloc_embedded[2];
static NvHandle subdevice_alloc_return_override[2];
static bool subdevice_alloc_override_enabled[2];
static int binapi_alloc_calls[2];
static NvHandle binapi_alloc_roots[2], binapi_alloc_parents[2], binapi_alloc_handles[2];
static NV2081_ALLOC_PARAMETERS binapi_alloc_params[2];
static NV_STATUS binapi_alloc_transport[2], binapi_alloc_embedded[2];
static NvHandle binapi_alloc_return_override[2];
static bool binapi_alloc_override_enabled[2];
static int rusd_alloc_calls[2];
static NvHandle rusd_alloc_roots[2], rusd_alloc_parents[2], rusd_alloc_handles[2];
static NV00DE_ALLOC_PARAMETERS rusd_alloc_params[2];
static NV_STATUS rusd_alloc_transport[2], rusd_alloc_embedded[2];
static NvHandle rusd_alloc_return_override[2];
static bool rusd_alloc_override_enabled[2];
static int p2p_alloc_calls;
static NvHandle p2p_alloc_root, p2p_alloc_parent, p2p_alloc_handle;
static NvU32 p2p_alloc_outer_size;
static NV503C_ALLOC_PARAMETERS p2p_alloc_params;
static NV_STATUS p2p_alloc_transport, p2p_alloc_embedded;
static NvHandle p2p_alloc_return_override;
static bool p2p_alloc_override_enabled;
enum { FAKE_P2P_REG_VA, FAKE_P2P_UNREG_VA,
       FAKE_P2P_REG_VIDMEM, FAKE_P2P_UNREG_VIDMEM, FAKE_P2P_CONTROL_COUNT };
static int p2p_control_calls[FAKE_P2P_CONTROL_COUNT];
static NvHandle p2p_control_roots[FAKE_P2P_CONTROL_COUNT];
static NvHandle p2p_control_objects[FAKE_P2P_CONTROL_COUNT];
static NV503C_CTRL_REGISTER_VA_SPACE_PARAMS p2p_register_va_params;
static NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS p2p_unregister_va_params;
static NV503C_CTRL_REGISTER_VIDMEM_PARAMS p2p_register_vidmem_params;
static NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS p2p_unregister_vidmem_params;
static NV_STATUS p2p_control_transport[FAKE_P2P_CONTROL_COUNT];
static NvU32 p2p_control_embedded[FAKE_P2P_CONTROL_COUNT];
static int usermode_alloc_calls[2];
static NvHandle usermode_alloc_roots[2], usermode_alloc_parents[2];
static NvHandle usermode_alloc_handles[2], usermode_alloc_return_override[2];
static NvU32 usermode_alloc_classes[2];
static NV_HOPPER_USERMODE_A_PARAMS usermode_alloc_params[2];
static bool usermode_alloc_has_params[2], usermode_alloc_override_enabled[2];
static NV_STATUS usermode_alloc_transport[2], usermode_alloc_embedded[2];
static NvHandle gr_tpc_mask_clients[2], gr_tpc_mask_objects[2];
static NV2080_CTRL_GR_GET_TPC_MASK_PARAMS gr_tpc_mask_params[2];
static NV_STATUS gr_tpc_mask_transport[2], gr_tpc_mask_embedded[2];
static int memory_alloc_calls[2], object_free_calls[2];
static NvHandle memory_alloc_roots[2], memory_alloc_parents[2], memory_alloc_handles[2];
static NvHandle object_free_roots[2], object_free_parents[2], object_free_handles[2];
static NvU32 memory_alloc_classes[2];
static NV_MEMORY_ALLOCATION_PARAMS memory_alloc_params[2];
static NV_STATUS memory_alloc_transport[2], memory_alloc_embedded[2];
static int mapping_update_calls[2];
static NVOS56_PARAMETERS mapping_update_packets[2];
static NV_STATUS mapping_update_transport[2], mapping_update_embedded[2];
static int vaspace_alloc_calls[2];
static NvHandle vaspace_alloc_roots[2], vaspace_alloc_parents[2], vaspace_alloc_handles[2];
static NV_VASPACE_ALLOCATION_PARAMETERS vaspace_alloc_params[2];
static NV_STATUS vaspace_alloc_transport[2], vaspace_alloc_embedded[2];
static NvHandle vaspace_backend_handles[2];
static int channel_group_alloc_calls[2];
static NvHandle channel_group_alloc_roots[2], channel_group_alloc_parents[2], channel_group_alloc_handles[2];
static NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS channel_group_alloc_params[2];
static NV_STATUS channel_group_alloc_transport[2], channel_group_alloc_embedded[2];
static int context_share_alloc_calls[2];
static NvHandle context_share_alloc_roots[2], context_share_alloc_parents[2], context_share_alloc_handles[2];
static NV_CTXSHARE_ALLOCATION_PARAMETERS context_share_alloc_params[2];
static NV_STATUS context_share_alloc_transport[2], context_share_alloc_embedded[2];
static int channel_alloc_calls[2];
static NvHandle channel_alloc_roots[2], channel_alloc_parents[2], channel_alloc_handles[2];
static NvU32 channel_alloc_classes[2];
static NV_CHANNEL_ALLOC_PARAMS channel_alloc_params[2];
static NV_STATUS channel_alloc_transport[2], channel_alloc_embedded[2];
static int engine_alloc_calls[2];
static NvHandle engine_alloc_roots[2], engine_alloc_parents[2], engine_alloc_handles[2];
static NvU32 engine_alloc_classes[2];
static NV_STATUS engine_alloc_transport[2], engine_alloc_embedded[2];
static int debugger_alloc_calls[2], debugger_exception_mask_calls[2];
static NvHandle debugger_alloc_roots[2], debugger_alloc_parents[2];
static NvHandle debugger_alloc_handles[2], debugger_alloc_returned[2];
static NV83DE_ALLOC_PARAMETERS debugger_alloc_params[2];
static NvHandle debugger_control_clients[2], debugger_control_objects[2];
static NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS debugger_control_params[2];
static NV_STATUS debugger_alloc_transport[2], debugger_alloc_embedded[2];
static NV_STATUS debugger_control_transport[2], debugger_control_embedded[2];
static NV_STATUS object_free_transport[2], object_free_embedded[2];
static int gpu_owner = HYBRID580_BACKEND_LEGACY;
static int gpu_create_error[2], gpu_create_attempts[2], gpu_puts[2], gpu_ioctl_calls[2];
static char gpu_create_bdf[2][32];
static unsigned int gpu_ioctl_command_seen[2];
static unsigned long gpu_ioctl_argument_seen[2];
static int attach_error_backend=-1, attach_attempts[2], attached_count[2];
static NvU32 attached_ids[2][HYBRID580_GPU_MAX_DEVICES];
static NV_STATUS NV_API_CALL fake_invoke(void *context, NvU32 command, void *payload, NvU32 size) {
 struct hybrid580_control_session *s = context;
 int i=s->backend;
 assert(lock_depth == 1);
 if(command == NV_ESC_RM_ALLOC) {
  ++calls[i];
  pthread_mutex_lock(&block_mutex);
  if(active_calls_block && i==0) { entered_call=true; pthread_cond_broadcast(&block_cond); while(!allow_call) pthread_cond_wait(&block_cond,&block_mutex); }
  pthread_mutex_unlock(&block_mutex);
  if(size == sizeof(NVOS21_PARAMETERS)) {
   NVOS21_PARAMETERS *p=payload; p->status = i == alloc_error_backend ? NV_ERR_INVALID_ARGUMENT : NV_OK; p->hObjectNew = duplicate_second && i==1 ? 987 : (i == alloc_error_backend && zero_failure_handle) ? 0 : (p->hRoot ? p->hRoot : (duplicate_handle ? 987 : next_root++));
  } else { NVOS64_PARAMETERS *p=payload; assert(size == sizeof(*p)); p->status = i == alloc_error_backend ? NV_ERR_INVALID_ARGUMENT : NV_OK; p->hObjectNew = duplicate_second && i==1 ? 987 : (i == alloc_error_backend && zero_failure_handle) ? 0 : (p->hRoot ? p->hRoot : (duplicate_handle ? 987 : next_root++)); }
 } else { NVOS00_PARAMETERS *p=payload; assert(command==NV_ESC_RM_FREE && size==sizeof(*p)); ++frees[i]; p->status = i == free_error_backend ? NV_ERR_INVALID_STATE : NV_OK; }
 return NV_OK;
}
static int fake_create(int i, struct file *anchor, struct hybrid580_control_session **out, struct hybrid_rm_session_endpoint_v1 *endpoint) {
 struct hybrid580_control_session *s;
 assert(anchor);
 *out=NULL; memset(endpoint,0,sizeof(*endpoint));
 ++control_create_calls[i];
 if(fail_create==i+1 || control_create_calls[i]==fail_create_call[i]) return -ENODEV;
 s=calloc(1,sizeof(*s)); assert(s); s->backend=i; s->file.refs=1; s->file.private_data=s;
 s->file.f_op=&fake_backend_control_fops;
 *out=s; *endpoint=(struct hybrid_rm_session_endpoint_v1){ HYBRID_RM_SESSION_ABI_V1, sizeof(*endpoint), fake_invoke,s,&backend_identity[i],&s->file };
 ++created[i]; return 0;
}
static void fake_put(struct hybrid580_control_session *s) { assert(lock_depth==0); assert(s && s->file.refs==1); ++session_puts[s->backend]; --s->file.refs; free(s); }
static NV_STATUS fake_map_memory(struct hybrid580_control_session *s,
                                 NVOS33_PARAMETERS *params, NvS32 fd) {
 assert(s && params && fd>=0);
 nv_ioctl_nvos33_parameters_with_fd wrapper={.params=*params,.fd=fd};
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_MAP_MEMORY,
                            nv_ioctl_nvos33_parameters_with_fd);
 long rc=fake_backend_control_ioctl(&s->file,command,(unsigned long)&wrapper);
 *params=wrapper.params;
 return rc==0 ? NV_OK : NV_ERR_OPERATING_SYSTEM;
}
static NV_STATUS fake_unmap_memory(struct hybrid580_control_session *s,
                                   NVOS34_PARAMETERS *params) {
 assert(s && params);
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_UNMAP_MEMORY,NVOS34_PARAMETERS);
 long rc=fake_backend_control_ioctl(&s->file,command,(unsigned long)params);
 return rc==0 ? NV_OK : NV_ERR_OPERATING_SYSTEM;
}
NV_STATUS hybrid580_open_control_session_map_memory_v1(
 struct hybrid580_control_session *s,NVOS33_PARAMETERS *p,NvS32 fd) {
 return fake_map_memory(s,p,fd);
}
NV_STATUS hybrid580_legacy_control_session_map_memory_v1(
 struct hybrid580_control_session *s,NVOS33_PARAMETERS *p,NvS32 fd) {
 return fake_map_memory(s,p,fd);
}
NV_STATUS hybrid580_open_control_session_unmap_memory_v1(
 struct hybrid580_control_session *s,NVOS34_PARAMETERS *p) {
 return fake_unmap_memory(s,p);
}
NV_STATUS hybrid580_legacy_control_session_unmap_memory_v1(
 struct hybrid580_control_session *s,NVOS34_PARAMETERS *p) {
 return fake_unmap_memory(s,p);
}
static NV_STATUS fake_update_device_mapping_info(
 struct hybrid580_control_session *s, NVOS56_PARAMETERS *params) {
 assert(lock_depth==1 && s && params);
 int backend=s->backend; ++mapping_update_calls[backend];
 mapping_update_packets[backend]=*params;
 if(mapping_update_transport[backend]==NV_OK)
  params->status=mapping_update_embedded[backend];
 return mapping_update_transport[backend];
}
NV_STATUS hybrid580_open_control_session_update_device_mapping_info_v1(
 struct hybrid580_control_session *s,NVOS56_PARAMETERS *p) {
 return fake_update_device_mapping_info(s,p);
}
NV_STATUS hybrid580_legacy_control_session_update_device_mapping_info_v1(
 struct hybrid580_control_session *s,NVOS56_PARAMETERS *p) {
 return fake_update_device_mapping_info(s,p);
}
int hybrid580_open_control_session_create_v1(struct file *a, struct hybrid580_control_session **o, struct hybrid_rm_session_endpoint_v1 *e) { return fake_create(1,a,o,e); }
int hybrid580_legacy_control_session_create_v1(struct file *a, struct hybrid580_control_session **o, struct hybrid_rm_session_endpoint_v1 *e) { return fake_create(0,a,o,e); }
void hybrid580_open_control_session_put_v1(struct hybrid580_control_session *s) { fake_put(s); }
void hybrid580_legacy_control_session_put_v1(struct hybrid580_control_session *s) { fake_put(s); }
struct file *hybrid580_open_control_session_file_v1(struct hybrid580_control_session *s) { return get_file(&s->file); }
struct file *hybrid580_legacy_control_session_file_v1(struct hybrid580_control_session *s) { return get_file(&s->file); }
static int fake_attach(struct hybrid580_control_session *s, const NvU32 *ids, NvU32 count) {
 assert(lock_depth==1 && s && ids && count && count<=HYBRID580_GPU_MAX_DEVICES);
 int backend=s->backend; ++attach_attempts[backend]; attached_count[backend]=count;
 memcpy(attached_ids[backend],ids,count*sizeof(*ids));
 return backend==attach_error_backend ? -EINVAL : 0;
}
int hybrid580_open_control_session_attach_v1(struct hybrid580_control_session *s,const NvU32 *ids,NvU32 n) { return fake_attach(s,ids,n); }
int hybrid580_legacy_control_session_attach_v1(struct hybrid580_control_session *s,const NvU32 *ids,NvU32 n) { return fake_attach(s,ids,n); }
static NV_STATUS fake_gpu_id_info(struct hybrid580_control_session *s, NvHandle h_client,
                                  NvHandle h_object, NvU32 flags,
                                  NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS *params,
                                  NvU32 *control_status) {
 assert(lock_depth==1 && s && params && control_status && flags==0);
 int backend=s->backend; ++gpu_id_info_calls[backend];
 gpu_id_info_clients[backend]=h_client; gpu_id_info_objects[backend]=h_object;
 gpu_id_info_input_ids[backend]=params->gpuId;
 params->gpuFlags=8+backend; params->deviceInstance=gpu_id_info_device_instances[backend];
 params->subDeviceInstance=20+backend; params->sliStatus=30+backend;
 params->boardId=40+backend; params->gpuInstance=50+backend;
 params->numaId=(NvS32)(60+backend);
 if(gpu_id_info_fail_call[backend]==gpu_id_info_calls[backend]) {
  *control_status=gpu_id_info_failure_embedded[backend];
  return gpu_id_info_failure_transport[backend];
 }
 *control_status=gpu_id_info_embedded;
 return gpu_id_info_transport;
}
NV_STATUS hybrid580_open_control_session_gpu_id_info_v1(struct hybrid580_control_session *s,
    NvHandle c,NvHandle o,NvU32 f,NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS *p,NvU32 *st) {
 return fake_gpu_id_info(s,c,o,f,p,st);
}
NV_STATUS hybrid580_legacy_control_session_gpu_id_info_v1(struct hybrid580_control_session *s,
    NvHandle c,NvHandle o,NvU32 f,NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS *p,NvU32 *st) {
 return fake_gpu_id_info(s,c,o,f,p,st);
}
static NV_STATUS fake_device_ids(struct hybrid580_control_session *s, NvHandle c,
                                 NvHandle o, NvU32 flags,
                                 NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS *params,
                                 NvU32 *status) {
 assert(lock_depth==1 && s && params && status && flags==0);
 int backend=s->backend; ++device_ids_calls[backend];
 device_ids_clients[backend]=c; device_ids_objects[backend]=o;
 params->deviceIds=device_ids_values[backend];
 *status=device_ids_embedded[backend];
 return device_ids_transport[backend];
}
NV_STATUS hybrid580_open_control_session_device_ids_v1(struct hybrid580_control_session *s,
    NvHandle c,NvHandle o,NvU32 f,NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS *p,NvU32 *st) {
 return fake_device_ids(s,c,o,f,p,st);
}
NV_STATUS hybrid580_legacy_control_session_device_ids_v1(struct hybrid580_control_session *s,
    NvHandle c,NvHandle o,NvU32 f,NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS *p,NvU32 *st) {
 return fake_device_ids(s,c,o,f,p,st);
}
static NV_STATUS fake_device_alloc(struct hybrid580_control_session *s, NvHandle root,
                                   NvHandle handle, const NV0080_ALLOC_PARAMETERS *params,
                                   NvHandle *returned, NvU32 *rm_status) {
 assert(lock_depth==1 && s && params && returned && rm_status);
 int backend=s->backend; ++device_alloc_calls[backend];
 device_alloc_roots[backend]=root; device_alloc_handles[backend]=handle;
 device_alloc_params[backend]=*params;
 *returned=device_alloc_override_enabled[backend] ?
     device_alloc_return_override[backend] : handle;
 *rm_status=device_alloc_embedded[backend];
 return device_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_device_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle handle,const NV0080_ALLOC_PARAMETERS *p,NvHandle *returned,NvU32 *st) {
 return fake_device_alloc(s,root,handle,p,returned,st);
}
NV_STATUS hybrid580_legacy_control_session_device_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle handle,const NV0080_ALLOC_PARAMETERS *p,NvHandle *returned,NvU32 *st) {
 return fake_device_alloc(s,root,handle,p,returned,st);
}
static NV_STATUS fake_subdevice_alloc(struct hybrid580_control_session *s, NvHandle root,
    NvHandle parent, NvHandle handle, const NV2080_ALLOC_PARAMETERS *params,
    NvHandle *returned, NvU32 *rm_status) {
 assert(lock_depth==1 && s && params && returned && rm_status);
 int backend=s->backend; ++subdevice_alloc_calls[backend];
 subdevice_alloc_roots[backend]=root; subdevice_alloc_parents[backend]=parent;
 subdevice_alloc_handles[backend]=handle; subdevice_alloc_params[backend]=*params;
 *returned=subdevice_alloc_override_enabled[backend] ? subdevice_alloc_return_override[backend] : handle;
 *rm_status=subdevice_alloc_embedded[backend];
 return subdevice_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_subdevice_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,const NV2080_ALLOC_PARAMETERS *p,
    NvHandle *returned,NvU32 *st) { return fake_subdevice_alloc(s,root,parent,handle,p,returned,st); }
NV_STATUS hybrid580_legacy_control_session_subdevice_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,const NV2080_ALLOC_PARAMETERS *p,
    NvHandle *returned,NvU32 *st) { return fake_subdevice_alloc(s,root,parent,handle,p,returned,st); }
static NV_STATUS fake_master_alloc(struct hybrid580_control_session *s, NvHandle root,
    NvHandle parent, NvHandle handle, const NvS32 *params,
    NvHandle *returned, NvU32 *rm_status) {
 assert(lock_depth==1 && s && params && returned && rm_status);
 int backend=s->backend; ++master_alloc_calls[backend];
 master_alloc_roots[backend]=root; master_alloc_parents[backend]=parent;
 master_alloc_handles[backend]=handle; master_alloc_param_values[backend]=*params;
 *returned=handle; *rm_status=master_alloc_embedded[backend];
 return master_alloc_transport[backend];
}
NV_STATUS hybrid580_legacy_control_session_master_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,const NvS32 *params,
    NvHandle *returned,NvU32 *st) {
 return fake_master_alloc(s,root,parent,handle,params,returned,st);
}
static NV_STATUS fake_master_error_intr(struct hybrid580_control_session *s,
    NvHandle root, NvHandle object, NvU32 flags,
    NV90E6_CTRL_MASTER_GET_ERROR_INTR_OFFSET_MASK_PARAMS *params,
    NvU32 *control_status) {
 assert(lock_depth==1 && s && params && control_status && flags==0);
 int backend=s->backend; ++master_error_intr_calls[backend];
 master_error_intr_roots[backend]=root; master_error_intr_objects[backend]=object;
 master_error_intr_params[backend]=*params;
 params->offset=0x1234U+(NvU32)backend; params->mask=0x10U+(NvU32)backend;
 params->eccMask=0x20U+(NvU32)backend; params->nvlinkMask=0x40U+(NvU32)backend;
 *control_status=master_error_intr_embedded[backend];
 return master_error_intr_transport[backend];
}
NV_STATUS hybrid580_legacy_control_session_master_error_intr_offset_mask_v1(
    struct hybrid580_control_session *s, NvHandle root, NvHandle object,
    NvU32 flags, NV90E6_CTRL_MASTER_GET_ERROR_INTR_OFFSET_MASK_PARAMS *p,
    NvU32 *st) { return fake_master_error_intr(s,root,object,flags,p,st); }
static NV_STATUS fake_binapi_alloc(struct hybrid580_control_session *s, NvHandle root,
    NvHandle parent, NvHandle handle, const NV2081_ALLOC_PARAMETERS *params,
    NvHandle *returned, NvU32 *rm_status) {
 assert(lock_depth==1 && s && params && returned && rm_status);
 int backend=s->backend; ++binapi_alloc_calls[backend];
 binapi_alloc_roots[backend]=root; binapi_alloc_parents[backend]=parent;
 binapi_alloc_handles[backend]=handle; binapi_alloc_params[backend]=*params;
 *returned=binapi_alloc_override_enabled[backend] ? binapi_alloc_return_override[backend] : handle;
 *rm_status=binapi_alloc_embedded[backend];
 return binapi_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_binapi_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,const NV2081_ALLOC_PARAMETERS *p,
    NvHandle *returned,NvU32 *st) { return fake_binapi_alloc(s,root,parent,handle,p,returned,st); }
NV_STATUS hybrid580_legacy_control_session_binapi_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,const NV2081_ALLOC_PARAMETERS *p,
    NvHandle *returned,NvU32 *st) { return fake_binapi_alloc(s,root,parent,handle,p,returned,st); }
static NV_STATUS fake_rusd_alloc(struct hybrid580_control_session *s, NvHandle root,
    NvHandle parent, NvHandle handle, const NV00DE_ALLOC_PARAMETERS *params,
    NvHandle *returned, NvU32 *rm_status) {
 assert(lock_depth==1 && s && params && returned && rm_status);
 int backend=s->backend; ++rusd_alloc_calls[backend];
 rusd_alloc_roots[backend]=root; rusd_alloc_parents[backend]=parent;
 rusd_alloc_handles[backend]=handle; rusd_alloc_params[backend]=*params;
 *returned=rusd_alloc_override_enabled[backend] ? rusd_alloc_return_override[backend] : handle;
 *rm_status=rusd_alloc_embedded[backend];
 return rusd_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_rusd_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,const NV00DE_ALLOC_PARAMETERS *p,
    NvHandle *returned,NvU32 *st) { return fake_rusd_alloc(s,root,parent,handle,p,returned,st); }
NV_STATUS hybrid580_legacy_control_session_rusd_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,const NV00DE_ALLOC_PARAMETERS *p,
    NvHandle *returned,NvU32 *st) { return fake_rusd_alloc(s,root,parent,handle,p,returned,st); }
NV_STATUS hybrid580_legacy_control_session_p2p_alloc_v1(
    struct hybrid580_control_session *s, NvHandle root, NvHandle parent,
    NvHandle handle, NvU32 params_size, const NV503C_ALLOC_PARAMETERS *params,
    NvHandle *returned, NvU32 *rm_status) {
 assert(lock_depth==1 && s && params && returned && rm_status &&
        s->backend==HYBRID580_BACKEND_LEGACY);
 ++p2p_alloc_calls; p2p_alloc_root=root; p2p_alloc_parent=parent;
 p2p_alloc_handle=handle; p2p_alloc_outer_size=params_size;
 p2p_alloc_params=*params;
 *returned=p2p_alloc_override_enabled ? p2p_alloc_return_override : handle;
 *rm_status=p2p_alloc_embedded; return p2p_alloc_transport;
}
NV_STATUS hybrid580_legacy_control_session_p2p_register_va_space_v1(
    struct hybrid580_control_session *s, NvHandle root, NvHandle p2p,
    NV503C_CTRL_REGISTER_VA_SPACE_PARAMS *params, NvU32 *status) {
 assert(lock_depth==1 && s && s->backend==HYBRID580_BACKEND_LEGACY && params && status);
 ++p2p_control_calls[FAKE_P2P_REG_VA];
 p2p_control_roots[FAKE_P2P_REG_VA]=root;
 p2p_control_objects[FAKE_P2P_REG_VA]=p2p;
 p2p_register_va_params=*params;
 params->vaSpaceToken=0x76543210ULL;
 *status=p2p_control_embedded[FAKE_P2P_REG_VA];
 return p2p_control_transport[FAKE_P2P_REG_VA];
}
NV_STATUS hybrid580_legacy_control_session_p2p_unregister_va_space_v1(
    struct hybrid580_control_session *s, NvHandle root, NvHandle p2p,
    NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS *params, NvU32 *status) {
 assert(lock_depth==1 && s && s->backend==HYBRID580_BACKEND_LEGACY && params && status);
 ++p2p_control_calls[FAKE_P2P_UNREG_VA];
 p2p_control_roots[FAKE_P2P_UNREG_VA]=root;
 p2p_control_objects[FAKE_P2P_UNREG_VA]=p2p;
 p2p_unregister_va_params=*params;
 *status=p2p_control_embedded[FAKE_P2P_UNREG_VA];
 return p2p_control_transport[FAKE_P2P_UNREG_VA];
}
NV_STATUS hybrid580_legacy_control_session_p2p_register_vidmem_v1(
    struct hybrid580_control_session *s, NvHandle root, NvHandle p2p,
    NV503C_CTRL_REGISTER_VIDMEM_PARAMS *params, NvU32 *status) {
 assert(lock_depth==1 && s && s->backend==HYBRID580_BACKEND_LEGACY && params && status);
 ++p2p_control_calls[FAKE_P2P_REG_VIDMEM];
 p2p_control_roots[FAKE_P2P_REG_VIDMEM]=root;
 p2p_control_objects[FAKE_P2P_REG_VIDMEM]=p2p;
 p2p_register_vidmem_params=*params;
 *status=p2p_control_embedded[FAKE_P2P_REG_VIDMEM];
 return p2p_control_transport[FAKE_P2P_REG_VIDMEM];
}
NV_STATUS hybrid580_legacy_control_session_p2p_unregister_vidmem_v1(
    struct hybrid580_control_session *s, NvHandle root, NvHandle p2p,
    NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS *params, NvU32 *status) {
 assert(lock_depth==1 && s && s->backend==HYBRID580_BACKEND_LEGACY && params && status);
 ++p2p_control_calls[FAKE_P2P_UNREG_VIDMEM];
 p2p_control_roots[FAKE_P2P_UNREG_VIDMEM]=root;
 p2p_control_objects[FAKE_P2P_UNREG_VIDMEM]=p2p;
 p2p_unregister_vidmem_params=*params;
 *status=p2p_control_embedded[FAKE_P2P_UNREG_VIDMEM];
 return p2p_control_transport[FAKE_P2P_UNREG_VIDMEM];
}
static NV_STATUS fake_usermode_alloc(struct hybrid580_control_session *s, NvHandle root,
    NvHandle parent, NvHandle handle, NvU32 class_id,
    const NV_HOPPER_USERMODE_A_PARAMS *params, NvHandle *returned,NvU32 *rm_status) {
 assert(lock_depth==1 && s && returned && rm_status);
 int backend=s->backend; ++usermode_alloc_calls[backend];
 usermode_alloc_roots[backend]=root; usermode_alloc_parents[backend]=parent;
 usermode_alloc_handles[backend]=handle; usermode_alloc_classes[backend]=class_id;
 usermode_alloc_has_params[backend]=params!=NULL;
 memset(&usermode_alloc_params[backend],0,sizeof(usermode_alloc_params[backend]));
 if(params) usermode_alloc_params[backend]=*params;
 *returned=usermode_alloc_override_enabled[backend] ? usermode_alloc_return_override[backend] : handle;
 *rm_status=usermode_alloc_embedded[backend];
 return usermode_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_usermode_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 class_id,
    const NV_HOPPER_USERMODE_A_PARAMS *p,NvHandle *returned,NvU32 *st) {
 return fake_usermode_alloc(s,root,parent,handle,class_id,p,returned,st);
}
NV_STATUS hybrid580_legacy_control_session_usermode_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 class_id,
    const NV_HOPPER_USERMODE_A_PARAMS *p,NvHandle *returned,NvU32 *st) {
 return fake_usermode_alloc(s,root,parent,handle,class_id,p,returned,st);
}
static NV_STATUS fake_gr_tpc_mask(struct hybrid580_control_session *s, NvHandle root,
    NvHandle subdevice, NvU32 flags, NV2080_CTRL_GR_GET_TPC_MASK_PARAMS *params,
    NvU32 *control_status) {
 assert(lock_depth==1 && s && params && control_status && flags==0);
 int backend=s->backend; ++gr_tpc_mask_calls[backend];
 gr_tpc_mask_clients[backend]=root; gr_tpc_mask_objects[backend]=subdevice;
 gr_tpc_mask_params[backend]=*params; params->tpcMask=0x100U+(NvU32)backend;
 *control_status=gr_tpc_mask_embedded[backend];
 return gr_tpc_mask_transport[backend];
}
NV_STATUS hybrid580_open_control_session_gr_tpc_mask_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle subdevice,NvU32 flags,NV2080_CTRL_GR_GET_TPC_MASK_PARAMS *p,NvU32 *st) {
 return fake_gr_tpc_mask(s,root,subdevice,flags,p,st);
}
NV_STATUS hybrid580_legacy_control_session_gr_tpc_mask_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle subdevice,NvU32 flags,NV2080_CTRL_GR_GET_TPC_MASK_PARAMS *p,NvU32 *st) {
 return fake_gr_tpc_mask(s,root,subdevice,flags,p,st);
}
static int gpu_name_string_calls[2];
static NvHandle gpu_name_string_roots[2], gpu_name_string_subdevices[2];
static NvU32 gpu_name_string_selectors[2], gpu_name_string_flags[2];
static NV_STATUS fake_gpu_name_string(struct hybrid580_control_session *s,
    NvHandle root,NvHandle subdevice,NvU32 flags,
    NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS *p,NvU32 *st) {
 assert(lock_depth==1 && s && p && st && flags==0);
 int backend=s->backend; ++gpu_name_string_calls[backend];
 gpu_name_string_roots[backend]=root;
 gpu_name_string_subdevices[backend]=subdevice;
 gpu_name_string_flags[backend]=flags;
 gpu_name_string_selectors[backend]=p->gpuNameStringFlags;
 memset(&p->gpuNameString,0,sizeof(p->gpuNameString));
 const char *name=backend ? "RTX 5080" : "Tesla V100";
 if(p->gpuNameStringFlags==NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_UNICODE) {
  for(size_t i=0;name[i];i++) p->gpuNameString.unicode[i]=(NvU16)(unsigned char)name[i];
 } else {
  memcpy(p->gpuNameString.ascii,name,strlen(name)+1);
 }
 *st=NV_OK;
 return NV_OK;
}
NV_STATUS hybrid580_open_control_session_gpu_name_string_v1(
    struct hybrid580_control_session *s,NvHandle root,NvHandle subdevice,
    NvU32 flags,NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS *p,NvU32 *st) {
 return fake_gpu_name_string(s,root,subdevice,flags,p,st);
}
NV_STATUS hybrid580_legacy_control_session_gpu_name_string_v1(
    struct hybrid580_control_session *s,NvHandle root,NvHandle subdevice,
    NvU32 flags,NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS *p,NvU32 *st) {
 return fake_gpu_name_string(s,root,subdevice,flags,p,st);
}
static NV_STATUS fake_device_free(struct hybrid580_control_session *s, NvHandle root,
                                  NvHandle handle, NvU32 *rm_status) {
 assert(lock_depth==1 && s && rm_status);
 int backend=s->backend; ++device_free_calls[backend];
 device_free_roots[backend]=root; device_free_handles[backend]=handle;
 *rm_status=device_free_embedded[backend];
 return device_free_transport[backend];
}
NV_STATUS hybrid580_open_control_session_device_free_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle handle,NvU32 *st) {
 return fake_device_free(s,root,handle,st);
}
NV_STATUS hybrid580_legacy_control_session_device_free_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle handle,NvU32 *st) {
 return fake_device_free(s,root,handle,st);
}
static NV_STATUS fake_memory_alloc(struct hybrid580_control_session *s, NvHandle root,
    NvHandle parent, NvHandle object, NvU32 class_id,
    NV_MEMORY_ALLOCATION_PARAMS *params, NvHandle *returned, NvU32 *rm_status) {
 assert(lock_depth==1 && s && params && returned && rm_status);
 assert(class_id==NV01_MEMORY_SYSTEM || class_id==NV01_MEMORY_LOCAL_USER ||
        class_id==NV50_MEMORY_VIRTUAL);
 int backend=s->backend; ++memory_alloc_calls[backend];
 memory_alloc_roots[backend]=root; memory_alloc_parents[backend]=parent;
 memory_alloc_handles[backend]=object; memory_alloc_classes[backend]=class_id;
 memory_alloc_params[backend]=*params;
 params->size=0x4000;
 params->address=(NvP64)(uintptr_t)0xabc000;
 *returned=object; *rm_status=memory_alloc_embedded[backend];
 return memory_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_memory_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 class_id,
    NV_MEMORY_ALLOCATION_PARAMS *params,NvHandle *returned,NvU32 *status) {
 return fake_memory_alloc(s,root,parent,handle,class_id,params,returned,status);
}
NV_STATUS hybrid580_legacy_control_session_memory_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 class_id,
    NV_MEMORY_ALLOCATION_PARAMS *params,NvHandle *returned,NvU32 *status) {
 return fake_memory_alloc(s,root,parent,handle,class_id,params,returned,status);
}
static NV_STATUS fake_vaspace_alloc(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,
    NV_VASPACE_ALLOCATION_PARAMETERS *params,NvHandle *returned,NvU32 *status) {
 assert(lock_depth==1 && s && params && returned && status);
 int backend=s->backend; ++vaspace_alloc_calls[backend];
 vaspace_alloc_roots[backend]=root; vaspace_alloc_parents[backend]=parent;
 vaspace_alloc_handles[backend]=handle; vaspace_alloc_params[backend]=*params;
 params->vaBase=0x10000; params->vaSize=0x100000000ULL;
 *returned=vaspace_backend_handles[backend] ? vaspace_backend_handles[backend] : handle;
 *status=vaspace_alloc_embedded[backend];
 return vaspace_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_vaspace_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,
    NV_VASPACE_ALLOCATION_PARAMETERS *params,NvHandle *returned,NvU32 *status) {
 return fake_vaspace_alloc(s,root,parent,handle,params,returned,status);
}
NV_STATUS hybrid580_legacy_control_session_vaspace_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,
    NV_VASPACE_ALLOCATION_PARAMETERS *params,NvHandle *returned,NvU32 *status) {
 return fake_vaspace_alloc(s,root,parent,handle,params,returned,status);
}
static NV_STATUS fake_channel_group_alloc(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,
    NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS *params,NvHandle *returned,NvU32 *status) {
 assert(lock_depth==1 && s && params && returned && status);
 int backend=s->backend; ++channel_group_alloc_calls[backend];
 channel_group_alloc_roots[backend]=root; channel_group_alloc_parents[backend]=parent;
 channel_group_alloc_handles[backend]=handle; channel_group_alloc_params[backend]=*params;
 params->engineType=0x55U+(NvU32)backend;
 *returned=handle; *status=channel_group_alloc_embedded[backend];
 return channel_group_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_channel_group_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,
    NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS *params,NvHandle *returned,NvU32 *status) {
 return fake_channel_group_alloc(s,root,parent,handle,params,returned,status);
}
NV_STATUS hybrid580_legacy_control_session_channel_group_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,
    NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS *params,NvHandle *returned,NvU32 *status) {
 return fake_channel_group_alloc(s,root,parent,handle,params,returned,status);
}
static NV_STATUS fake_context_share_alloc(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,
    NV_CTXSHARE_ALLOCATION_PARAMETERS *params,NvHandle *returned,NvU32 *status) {
 assert(lock_depth==1 && s && params && returned && status);
 int backend=s->backend; ++context_share_alloc_calls[backend];
 context_share_alloc_roots[backend]=root; context_share_alloc_parents[backend]=parent;
 context_share_alloc_handles[backend]=handle; context_share_alloc_params[backend]=*params;
 params->subctxId=0x15U+(NvU32)backend;
 *returned=handle; *status=context_share_alloc_embedded[backend];
 return context_share_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_context_share_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,
    NV_CTXSHARE_ALLOCATION_PARAMETERS *params,NvHandle *returned,NvU32 *status) {
 return fake_context_share_alloc(s,root,parent,handle,params,returned,status);
}
NV_STATUS hybrid580_legacy_control_session_context_share_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,
    NV_CTXSHARE_ALLOCATION_PARAMETERS *params,NvHandle *returned,NvU32 *status) {
 return fake_context_share_alloc(s,root,parent,handle,params,returned,status);
}
static NV_STATUS fake_channel_alloc(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 class_id,
    NV_CHANNEL_ALLOC_PARAMS *params,NvHandle *returned,NvU32 *status) {
 assert(lock_depth==1 && s && params && returned && status);
 int backend=s->backend; ++channel_alloc_calls[backend];
 channel_alloc_roots[backend]=root; channel_alloc_parents[backend]=parent;
 channel_alloc_handles[backend]=handle; channel_alloc_classes[backend]=class_id;
 channel_alloc_params[backend]=*params;
 params->cid=0xc001U+(NvU32)backend;
 *returned=handle; *status=channel_alloc_embedded[backend];
 return channel_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_channel_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 class_id,
    NV_CHANNEL_ALLOC_PARAMS *params,NvHandle *returned,NvU32 *status) {
 return fake_channel_alloc(s,root,parent,handle,class_id,params,returned,status);
}
NV_STATUS hybrid580_legacy_control_session_channel_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 class_id,
    NV_CHANNEL_ALLOC_PARAMS *params,NvHandle *returned,NvU32 *status) {
 return fake_channel_alloc(s,root,parent,handle,class_id,params,returned,status);
}
static NV_STATUS fake_engine_alloc(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 class_id,
    NvHandle *returned,NvU32 *status) {
 assert(lock_depth==1 && s && returned && status);
 int backend=s->backend; ++engine_alloc_calls[backend];
 engine_alloc_roots[backend]=root; engine_alloc_parents[backend]=parent;
 engine_alloc_handles[backend]=handle; engine_alloc_classes[backend]=class_id;
 *returned=handle; *status=engine_alloc_embedded[backend];
 return engine_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_engine_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 class_id,
    NvHandle *returned,NvU32 *status) {
 return fake_engine_alloc(s,root,parent,handle,class_id,returned,status);
}
NV_STATUS hybrid580_legacy_control_session_engine_alloc_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 class_id,
    NvHandle *returned,NvU32 *status) {
 return fake_engine_alloc(s,root,parent,handle,class_id,returned,status);
}
static NV_STATUS fake_debugger_alloc(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,
    const NV83DE_ALLOC_PARAMETERS *params,NvHandle *returned,NvU32 *status) {
 assert(lock_depth==1 && s && params && returned && status);
 int backend=s->backend; ++debugger_alloc_calls[backend];
 debugger_alloc_roots[backend]=root; debugger_alloc_parents[backend]=parent;
 debugger_alloc_handles[backend]=handle; debugger_alloc_params[backend]=*params;
 *returned=debugger_alloc_returned[backend] ? debugger_alloc_returned[backend] : handle;
 *status=debugger_alloc_embedded[backend];
 return debugger_alloc_transport[backend];
}
NV_STATUS hybrid580_open_control_session_debugger_alloc_v1(
    struct hybrid580_control_session *s,NvHandle root,NvHandle parent,
    NvHandle handle,const NV83DE_ALLOC_PARAMETERS *params,
    NvHandle *returned,NvU32 *status) {
 return fake_debugger_alloc(s,root,parent,handle,params,returned,status);
}
NV_STATUS hybrid580_legacy_control_session_debugger_alloc_v1(
    struct hybrid580_control_session *s,NvHandle root,NvHandle parent,
    NvHandle handle,const NV83DE_ALLOC_PARAMETERS *params,
    NvHandle *returned,NvU32 *status) {
 return fake_debugger_alloc(s,root,parent,handle,params,returned,status);
}
static NV_STATUS fake_debugger_exception_mask(
    struct hybrid580_control_session *s,NvHandle client,NvHandle debugger,
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS *params,NvU32 *status) {
 assert(lock_depth==1 && s && params && status);
 int backend=s->backend; ++debugger_exception_mask_calls[backend];
 debugger_control_clients[backend]=client;
 debugger_control_objects[backend]=debugger;
 debugger_control_params[backend]=*params;
 *status=debugger_control_embedded[backend];
 return debugger_control_transport[backend];
}
NV_STATUS hybrid580_open_control_session_debugger_exception_mask_v1(
    struct hybrid580_control_session *s,NvHandle client,NvHandle debugger,
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS *params,NvU32 *status) {
 return fake_debugger_exception_mask(s,client,debugger,params,status);
}
NV_STATUS hybrid580_legacy_control_session_debugger_exception_mask_v1(
    struct hybrid580_control_session *s,NvHandle client,NvHandle debugger,
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS *params,NvU32 *status) {
 return fake_debugger_exception_mask(s,client,debugger,params,status);
}
static NV_STATUS fake_object_free(struct hybrid580_control_session *s, NvHandle root,
    NvHandle parent,NvHandle object,NvU32 *rm_status) {
 assert(lock_depth==1 && s && rm_status);
 int backend=s->backend; ++object_free_calls[backend];
 object_free_roots[backend]=root; object_free_parents[backend]=parent;
 object_free_handles[backend]=object; *rm_status=object_free_embedded[backend];
 return object_free_transport[backend];
}
NV_STATUS hybrid580_open_control_session_object_free_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 *status) {
 return fake_object_free(s,root,parent,handle,status);
}
NV_STATUS hybrid580_legacy_control_session_object_free_v1(struct hybrid580_control_session *s,
    NvHandle root,NvHandle parent,NvHandle handle,NvU32 *status) {
 return fake_object_free(s,root,parent,handle,status);
}
static int attached_ids_calls[2];
static NvHandle attached_ids_clients[2], attached_ids_objects[2];
static NvU32 attached_ids_values[2][NV0000_CTRL_GPU_MAX_ATTACHED_GPUS];
static NvU32 attached_ids_counts[2];
static NV_STATUS attached_ids_transport[2], attached_ids_embedded[2];
static int probed_ids_calls[2];
static NvHandle probed_ids_clients[2], probed_ids_objects[2];
static NvU32 probed_ids_flags[2], probed_ids_commands[2], probed_ids_sizes[2];
static NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS probed_ids_reply[2];
static NV_STATUS probed_ids_transport[2], probed_ids_embedded[2];
static NV_STATUS fake_attached_ids(struct hybrid580_control_session *s, NvHandle c,
                                   NvHandle o, NvU32 flags,
                                   NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS *params,
                                   NvU32 *status) {
 assert(lock_depth==1 && s && params && status && flags==0);
 int backend=s->backend; ++attached_ids_calls[backend];
 attached_ids_clients[backend]=c; attached_ids_objects[backend]=o;
 for(unsigned int i=0;i<NV0000_CTRL_GPU_MAX_ATTACHED_GPUS;i++)
  params->gpuIds[i]=i<attached_ids_counts[backend]?attached_ids_values[backend][i]:NV0000_CTRL_GPU_INVALID_ID;
 *status=attached_ids_embedded[backend];
 return attached_ids_transport[backend];
}
NV_STATUS hybrid580_open_control_session_attached_ids_v1(struct hybrid580_control_session *s,
    NvHandle c,NvHandle o,NvU32 f,NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS *p,NvU32 *st) {
 return fake_attached_ids(s,c,o,f,p,st);
}
NV_STATUS hybrid580_legacy_control_session_attached_ids_v1(struct hybrid580_control_session *s,
    NvHandle c,NvHandle o,NvU32 f,NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS *p,NvU32 *st) {
 return fake_attached_ids(s,c,o,f,p,st);
}
static NV_STATUS fake_probed_ids(struct hybrid580_control_session *s, NvHandle c,
                                 NvHandle o, NvU32 flags,
                                 NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *params,
                                 NvU32 *status) {
 assert(lock_depth==1 && s && params && status && flags==0);
 int backend=s->backend; ++probed_ids_calls[backend];
 probed_ids_clients[backend]=c; probed_ids_objects[backend]=o;
 probed_ids_flags[backend]=flags;
 probed_ids_commands[backend]=NV0000_CTRL_CMD_GPU_GET_PROBED_IDS;
 probed_ids_sizes[backend]=sizeof(*params);
 *params=probed_ids_reply[backend];
 *status=probed_ids_embedded[backend];
 return probed_ids_transport[backend];
}
NV_STATUS hybrid580_open_control_session_probed_ids_v1(struct hybrid580_control_session *s,
    NvHandle c,NvHandle o,NvU32 f,NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *p,NvU32 *st) {
 return fake_probed_ids(s,c,o,f,p,st);
}
NV_STATUS hybrid580_legacy_control_session_probed_ids_v1(struct hybrid580_control_session *s,
    NvHandle c,NvHandle o,NvU32 f,NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *p,NvU32 *st) {
 return fake_probed_ids(s,c,o,f,p,st);
}
static int fake_inventory(int backend, struct hybrid580_gpu_backend_record_v1 *records,
                          NvU32 capacity, NvU32 *count) {
 ++inventory_calls[backend]; if(!count) return -EINVAL; *count=0;
 if(inventory_error[backend]) return inventory_error[backend];
 *count=inventory_count[backend]; if(capacity<inventory_count[backend]) return -ENOSPC;
 if(inventory_count[backend] && !records) return -EINVAL;
 memcpy(records,inventory_records[backend],inventory_count[backend]*sizeof(*records)); return 0;
}
int hybrid580_legacy_gpu_inventory_v1(struct hybrid580_gpu_backend_record_v1 *r,NvU32 c,NvU32 *n) { return fake_inventory(0,r,c,n); }
int hybrid580_open_gpu_inventory_v1(struct hybrid580_gpu_backend_record_v1 *r,NvU32 c,NvU32 *n) { return fake_inventory(1,r,c,n); }
static int fake_card_info(int backend, struct nv_ioctl_card_info *records,
                          NvU32 capacity, NvU32 *count) {
 ++card_info_calls[backend]; if(!count) return -EINVAL; *count=0;
 if(card_info_error[backend]) return card_info_error[backend];
 *count=card_info_count[backend]; if(capacity<card_info_count[backend]) return -ENOSPC;
 if(card_info_count[backend] && !records) return -EINVAL;
 memcpy(records,card_info_records[backend],card_info_count[backend]*sizeof(*records)); return 0;
}
int hybrid580_legacy_gpu_card_info_v1(struct nv_ioctl_card_info *r,NvU32 c,NvU32 *n) { return fake_card_info(0,r,c,n); }
int hybrid580_open_gpu_card_info_v1(struct nv_ioctl_card_info *r,NvU32 c,NvU32 *n) { return fake_card_info(1,r,c,n); }
static int fake_gpu_create(int i, struct file *anchor, const char *bdf, struct hybrid580_gpu_session **out) {
 ++gpu_create_attempts[i]; assert(anchor && bdf && out); *out=NULL;
 assert(strlen(bdf)<sizeof(gpu_create_bdf[i]));
 memcpy(gpu_create_bdf[i],bdf,strlen(bdf)+1U);
 if(gpu_create_error[i]) return gpu_create_error[i];
 if(gpu_owner!=i) return -EXDEV;
 struct hybrid580_gpu_session *s=calloc(1,sizeof(*s)); assert(s);
 s->file=calloc(1,sizeof(*s->file)); assert(s->file); s->file->refs=1; s->file->heap_allocated=true; s->file->private_data=s;
 s->file->f_op=&fake_backend_fops;
 s->backend=i; memcpy(s->bdf,bdf,sizeof(s->bdf)); *out=s; return 0;
}
static void fake_gpu_put(struct hybrid580_gpu_session *s) { assert(lock_depth==0 && s); ++gpu_puts[s->backend]; fput(s->file); free(s); }
static struct file *fake_gpu_file(struct hybrid580_gpu_session *s) { return s ? get_file(s->file) : NULL; }
static int fake_gpu_register_control(struct hybrid580_gpu_session *s,
                                     struct hybrid580_control_session *control) {
 assert(s && control); ++register_fd_calls; ++gpu_ioctl_calls[s->backend];
 register_bound_session=control;
 if(control==register_expected_session) register_backend_control_front=register_control_front;
 else if(control==register_replacement_session) register_backend_control_front=register_fd_reuse_front;
 if(s->backend!=control->backend) return -EXDEV;
 ++register_fd_matches;
 return register_fd_error;
}
int hybrid580_legacy_gpu_session_register_control_v1(
 struct hybrid580_gpu_session *s, struct hybrid580_control_session *c) {
 return fake_gpu_register_control(s,c);
}
int hybrid580_open_gpu_session_register_control_v1(
 struct hybrid580_gpu_session *s, struct hybrid580_control_session *c) {
 return fake_gpu_register_control(s,c);
}
static long fake_gpu_ioctl(struct hybrid580_gpu_session *s, unsigned int command, unsigned long argument) {
 assert(s && _IOC_TYPE(command)==NV_IOCTL_MAGIC); ++gpu_ioctl_calls[s->backend];
 gpu_ioctl_command_seen[s->backend]=command;
 gpu_ioctl_argument_seen[s->backend]=argument;
 if(_IOC_NR(command)==NV_ESC_REGISTER_FD) {
  struct fake_register_fd_payload *p=(void *)argument;
  /* Model the backend's second fget after descriptor 9 has been closed and
   * reused since the frontend pinned register_control_front. */
  struct file *gpu_back=NULL, *ctl_back=NULL;
  struct file *ctl_front=p->ctl_fd==9 ?
      (register_fd_reuse_front ? register_fd_reuse_front : register_control_front) : NULL;
  ++register_fd_calls;
  if(!register_gpu_front || !ctl_front) return -EINVAL;
  register_backend_control_front=ctl_front;
  if(s->backend==HYBRID580_BACKEND_LEGACY) {
   gpu_back=hybrid_front_project_legacy(register_gpu_front,false);
   ctl_back=hybrid_front_project_legacy(ctl_front,true);
   assert(!hybrid_front_project_open(register_gpu_front,false));
  } else {
   gpu_back=hybrid_front_project_open(register_gpu_front,false);
   ctl_back=hybrid_front_project_open(ctl_front,true);
   assert(!hybrid_front_project_legacy(register_gpu_front,false));
  }
  if(gpu_back && ctl_back && ((struct hybrid580_gpu_session *)gpu_back->private_data)->backend==s->backend &&
     ((struct hybrid580_control_session *)ctl_back->private_data)->backend==s->backend)
   ++register_fd_matches;
  if(gpu_back) fput(gpu_back);
  if(ctl_back) fput(ctl_back);
  if(register_fd_error) return register_fd_error;
  return register_fd_matches==register_fd_calls ? 0 : -EXDEV;
 }
 if(_IOC_NR(command)==NV_ESC_RM_MAP_MEMORY) {
  nv_ioctl_nvos33_parameters_with_fd *params=(void *)argument;
  assert(params && _IOC_SIZE(command)==sizeof(*params));
  assert(params->params.length==4096 && params->fd==gpu_map_fd_expected);
  params->params.status=NV_OK;
  ++gpu_map_calls[s->backend]; gpu_map_context_files[s->backend]=s->file;
  return 0;
 }
 (void)argument; return 100+s->backend;
}
int hybrid580_legacy_gpu_session_create_by_bdf_v1(struct file *a, const char *b, struct hybrid580_gpu_session **o) { return fake_gpu_create(0,a,b,o); }
int hybrid580_open_gpu_session_create_by_bdf_v1(struct file *a, const char *b, struct hybrid580_gpu_session **o) { return fake_gpu_create(1,a,b,o); }
void hybrid580_legacy_gpu_session_put_v1(struct hybrid580_gpu_session *s) { fake_gpu_put(s); }
void hybrid580_open_gpu_session_put_v1(struct hybrid580_gpu_session *s) { fake_gpu_put(s); }
struct file *hybrid580_legacy_gpu_session_file_v1(struct hybrid580_gpu_session *s) { return fake_gpu_file(s); }
struct file *hybrid580_open_gpu_session_file_v1(struct hybrid580_gpu_session *s) { return fake_gpu_file(s); }
long hybrid580_legacy_gpu_session_ioctl_v1(struct hybrid580_gpu_session *s, unsigned int c, unsigned long a) { return fake_gpu_ioctl(s,c,a); }
long hybrid580_open_gpu_session_ioctl_v1(struct hybrid580_gpu_session *s, unsigned int c, unsigned long a) { return fake_gpu_ioctl(s,c,a); }
static int fake_register(int i, const struct hybrid580_file_projection_ops_v1 *ops) { assert(ops->owner==THIS_MODULE && ops->get_backing_file); ++registrations[i]; return fail_register==i+1 ? -EBUSY : 0; }
int hybrid580_open_register_file_projection_v1(const struct hybrid580_file_projection_ops_v1 *o) { return fake_register(1,o); }
int hybrid580_legacy_register_file_projection_v1(const struct hybrid580_file_projection_ops_v1 *o) { return fake_register(0,o); }
int hybrid580_open_unregister_file_projection_v1(const struct hybrid580_file_projection_ops_v1 *o) { (void)o; ++unregistrations[1]; return 0; }
int hybrid580_legacy_unregister_file_projection_v1(const struct hybrid580_file_projection_ops_v1 *o) { (void)o; ++unregistrations[0]; return 0; }
static int misc_register(struct miscdevice *d) { assert(d->mode==0600 && !strcmp(d->name,"hybrid580ctl")); ++device_registers; return fail_misc ? -EBUSY : 0; }
static void misc_deregister(struct miscdevice *d) { (void)d; ++device_unregisters; }
int hybrid580_standard_nodes_register_v1(const struct hybrid580_gpu_catalog_v1 *catalog,
                                         const struct file_operations *fops) {
 if(!catalog || !fops || standard_nodes_ready) return -EBUSY;
 standard_nodes_catalog=catalog; standard_nodes_ready=true; return 0;
}
void hybrid580_standard_nodes_unregister_v1(void) {
 if(standard_nodes_ready) { standard_nodes_ready=false; standard_nodes_catalog=NULL; ++standard_nodes_unregisters; }
}
int hybrid580_standard_nodes_active_v1(void) { return standard_nodes_ready; }
int hybrid580_standard_nodes_resolve_v1(hybrid580_u32 minor,
                                        struct hybrid580_standard_node_resolution_v1 *resolution) {
 if(!standard_nodes_ready) return -ENODEV;
 return hybrid580_standard_node_resolve_v1(standard_nodes_catalog,minor,resolution);
}
int hybrid580_standard_nodes_catalog_matches_v1(const struct hybrid580_gpu_catalog_v1 *catalog) {
 if(!standard_nodes_ready || !catalog || catalog->count!=standard_nodes_catalog->count) return 0;
 for(unsigned int i=0;i<catalog->count;i++) {
  const struct hybrid580_gpu_catalog_entry_v1 *a=&catalog->entries[i], *b=&standard_nodes_catalog->entries[i];
  if(memcmp(a->bdf,b->bdf,sizeof(a->bdf)) || a->frontend_index!=b->frontend_index ||
     a->frontend_gpu_id!=b->frontend_gpu_id || a->backend!=b->backend ||
     a->backend_minor!=b->backend_minor || a->backend_gpu_id!=b->backend_gpu_id ||
     a->domain!=b->domain || a->bus!=b->bus || a->slot!=b->slot ||
     a->function!=b->function || a->vendor_id!=b->vendor_id || a->device_id!=b->device_id ||
     a->reserved || b->reserved) return 0;
 }
 return 1;
}
'''

MAIN = r'''
struct model_register_thread_args {
 struct file *gpu;
 unsigned int command;
 unsigned long argument;
 long result;
};
static struct mutex *model_register_wait_mutex;
static bool model_register_wait_entered;
static void model_register_wait_hook(struct mutex *m) {
 assert(m==model_register_wait_mutex);
 pthread_mutex_lock(&block_mutex);
 model_register_wait_entered=true;
 pthread_cond_broadcast(&block_cond);
 pthread_mutex_unlock(&block_mutex);
}
static void *model_register_thread(void *opaque) {
 struct model_register_thread_args *args=opaque;
 args->result=args->gpu->f_op->unlocked_ioctl(args->gpu,args->command,args->argument);
 return NULL;
}
_Static_assert(sizeof(NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) == 40,
               "R580 build-version V1 ABI size");
_Static_assert(offsetof(NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS,
                        pDriverVersionBuffer) == 8,
               "R580 build-version V1 first pointer offset");
_Static_assert(offsetof(NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS,
                        pVersionBuffer) == 16,
               "R580 build-version V1 second pointer offset");
_Static_assert(offsetof(NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS,
                        pTitleBuffer) == 24,
               "R580 build-version V1 third pointer offset");
_Static_assert(offsetof(NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS,
                        changelistNumber) == 32,
               "R580 build-version V1 first changelist offset");
_Static_assert(offsetof(NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS,
                        officialChangelistNumber) == 36,
               "R580 build-version V1 second changelist offset");
_Static_assert(sizeof(NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS) == 1032,
               "R580 build-version V2 fixed payload size");
_Static_assert(sizeof(nv_ioctl_rm_api_version_t) == 72,
               "R580 version-check fixed payload size");
_Static_assert(offsetof(nv_ioctl_rm_api_version_t, reply) == 4,
               "R580 version-check reply offset");
_Static_assert(offsetof(nv_ioctl_rm_api_version_t, versionString) == 8,
               "R580 version-check string offset");
static struct file front;
static struct inode inode;
static unsigned int alloc21_cmd = _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_ALLOC, NVOS21_PARAMETERS);
static unsigned int alloc64_cmd = _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_ALLOC, NVOS64_PARAMETERS);
static unsigned int free_cmd = _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_FREE, NVOS00_PARAMETERS);
static unsigned int rm_control_cmd = _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL, NVOS54_PARAMETERS);
static unsigned int version_check_cmd(size_t size) {
 return _IOC(_IOC_READ|_IOC_WRITE,NV_IOCTL_MAGIC,NV_ESC_CHECK_VERSION_STR,size);
}
static unsigned int card_info_cmd(size_t bytes) { return _IOC(_IOC_READ|_IOC_WRITE,NV_IOCTL_MAGIC,NV_ESC_CARD_INFO,bytes); }
static unsigned int gpu_test_cmd = _IO(NV_IOCTL_MAGIC, 0x7a);
static struct hybrid580_open_gpu_v1 last_gpu_request;
static NVOS21_PARAMETERS p21;
static NVOS64_PARAMETERS p64;
static NVOS64_PARAMETERS device_packet;
static void make_front(void) {
 front=(struct file){ .f_op=&hybrid_front_fops, .refs=1, .private_data=(void *)1 };
 assert(hybrid_front_open(&inode,&front)==0); assert(front.private_data);
}
static long alloc_root(bool wide) {
 p21=(NVOS21_PARAMETERS){.hClass=NV01_ROOT_CLIENT}; p64=(NVOS64_PARAMETERS){.hClass=NV01_ROOT_CLIENT};
 return hybrid_front_ioctl(&front,wide?alloc64_cmd:alloc21_cmd,(unsigned long)(wide?(void *)&p64:(void *)&p21));
}
static void front_put(void) { if(--front.refs==0) assert(hybrid_front_release(&inode,&front)==0); }
static void *ioctl_thread(void *arg) { (void)arg; NVOS21_PARAMETERS local={.hClass=NV01_ROOT_CLIENT};
 assert(hybrid_front_ioctl(&front,alloc21_cmd,(unsigned long)&local)==0 && local.status==NV_OK); front_put(); return NULL; }
static long open_gpu(const char *bdf) {
  struct hybrid580_open_gpu_v1 request={.struct_size=sizeof(request)};
  if(bdf) memcpy(request.bdf,bdf,strlen(bdf)+1);
  long rc=hybrid_front_ioctl(&front,HYBRID580_IOCTL_OPEN_GPU,(unsigned long)&request);
  if(!rc) last_gpu_request=request;
  return rc;
}
static void prepare_map_request(int fd, NvU32 class_id,
                                nv_ioctl_nvos33_parameters_with_fd *params) {
 struct hybrid_front_file *state=front.private_data;
 struct hybrid_front_root *root;
 struct hybrid_front_rm_object *device,*memory;
 NVOS21_PARAMETERS root_packet;
 assert(state && params);
 root_packet=(NVOS21_PARAMETERS){.hClass=NV01_ROOT_CLIENT};
 assert(hybrid_front_ioctl(&front,alloc21_cmd,(unsigned long)&root_packet)==0);
 assert(root_packet.status==NV_OK && root_packet.hObjectNew!=0);
 root=hybrid_front_find_root(state,root_packet.hObjectNew); assert(root);
 device=kzalloc(sizeof(*device),GFP_KERNEL); memory=kzalloc(sizeof(*memory),GFP_KERNEL);
 assert(device && memory);
 device->handle=0x100U+(NvHandle)gpu_owner; device->backend_handle=device->handle+0x1000U;
 device->parent_handle=root->root.id; device->backend_parent_handle=root->root.slot[gpu_owner].handle;
 device->class_id=NV01_DEVICE_0; device->backend=gpu_owner;
 memory->handle=0x200U+(NvHandle)gpu_owner; memory->backend_handle=memory->handle+0x2000U;
 memory->parent_handle=device->handle; memory->backend_parent_handle=device->backend_handle;
 memory->class_id=class_id; memory->backend=gpu_owner;
 memory->next=root->objects; device->next=memory; root->objects=device;
 root->object_count+=2; state->object_count+=2;
 map_test_root=root->root.id; map_test_device=device->handle; map_test_memory=memory->handle;
 map_test_backend_device=device->backend_handle; map_test_backend_memory=memory->backend_handle;
 params->params.hClient=root_packet.hObjectNew; params->params.hDevice=device->handle;
 params->params.hMemory=memory->handle; params->params.length=4096;
 params->fd=fd; gpu_map_fd_expected=fd;
}
static NvHandle prepare_uvm_owner_objects(struct file *control, unsigned int backend,
                                          NvHandle *device_out,
                                          NvHandle *memory_out) {
 struct hybrid_front_file *state=control->private_data;
 struct hybrid_front_root *root;
 struct hybrid_front_rm_object *device,*memory;
 NVOS21_PARAMETERS root_packet={.hClass=NV01_ROOT_CLIENT};
 assert(state && device_out && memory_out);
 assert(!hybrid_front_ioctl(control,alloc21_cmd,(unsigned long)&root_packet));
 assert(root_packet.status==NV_OK && root_packet.hObjectNew);
 root=hybrid_front_find_root(state,root_packet.hObjectNew); assert(root);
 device=kzalloc(sizeof(*device),GFP_KERNEL); memory=kzalloc(sizeof(*memory),GFP_KERNEL);
 assert(device && memory);
 device->handle=0x100U+(NvHandle)backend;
 device->backend_handle=device->handle+0x1000U;
 device->parent_handle=root->root.id;
 device->backend_parent_handle=root->root.slot[backend].handle;
 device->class_id=NV01_DEVICE_0; device->backend=backend;
 memory->handle=0x200U+(NvHandle)backend;
 memory->backend_handle=memory->handle+0x2000U;
 memory->parent_handle=device->handle;
 memory->backend_parent_handle=device->backend_handle;
 memory->class_id=NV01_MEMORY_SYSTEM; memory->backend=backend;
 device->next=root->objects; memory->next=device; root->objects=memory;
 root->object_count+=2; state->object_count+=2;
 *device_out=device->handle; *memory_out=memory->handle;
 return root->root.id;
}
static NvHandle prepare_uvm_address_space_owner_objects(
    struct file *control, unsigned int backend, NvHandle *device_out,
    NvHandle *vaspace_out) {
 struct hybrid_front_file *state=control->private_data;
 struct hybrid_front_root *root;
 struct hybrid_front_rm_object *device,*vaspace;
 NVOS21_PARAMETERS root_packet={.hClass=NV01_ROOT_CLIENT};
 assert(state && device_out && vaspace_out);
 assert(!hybrid_front_ioctl(control,alloc21_cmd,(unsigned long)&root_packet));
 assert(root_packet.status==NV_OK && root_packet.hObjectNew);
 root=hybrid_front_find_root(state,root_packet.hObjectNew); assert(root);
 device=kzalloc(sizeof(*device),GFP_KERNEL);
 vaspace=kzalloc(sizeof(*vaspace),GFP_KERNEL);
 assert(device && vaspace);
 device->handle=0x100U+(NvHandle)backend;
 device->backend_handle=0x1100U+(NvHandle)backend;
 device->parent_handle=root->root.id;
 device->backend_parent_handle=root->root.slot[backend].handle;
 device->class_id=NV01_DEVICE_0; device->backend=backend;
 vaspace->handle=0x300U+(NvHandle)backend;
 vaspace->backend_handle=0x3300U+(NvHandle)backend;
 vaspace->parent_handle=device->handle;
 vaspace->backend_parent_handle=device->backend_handle;
 vaspace->class_id=FERMI_VASPACE_A; vaspace->backend=backend;
 device->next=vaspace; root->objects=device;
 root->object_count+=2; state->object_count+=2;
 *device_out=device->handle; *vaspace_out=vaspace->handle;
 return root->root.id;
}
static void create_map_context(int fd, struct file *gpu_front, NvU32 class_id) {
 nv_ioctl_nvos33_parameters_with_fd params={0};
 prepare_map_request(fd,class_id,&params);
 assert(!gpu_front || gpu_front->private_data);
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_MAP_MEMORY,
                            nv_ioctl_nvos33_parameters_with_fd);
 if(gpu_front) assert(gpu_front->f_op->unlocked_ioctl);
 assert(hybrid_front_ioctl(&front,command,(unsigned long)&params)==0);
 assert(params.params.status==NV_OK);
}
static long attach_xfer(const NvU32 *ids, NvU32 count) {
  nv_ioctl_xfer_t xfer={.cmd=NV_ESC_ATTACH_GPUS_TO_FD,.size=count*sizeof(*ids),.ptr=(NvP64)ids};
  unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
  return hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
}
static long attach_direct(NvU32 id) {
  unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_ATTACH_GPUS_TO_FD,NvU32);
  return hybrid_front_ioctl(&front,command,(unsigned long)&id);
}
static long gpu_id_info_direct(NvU32 frontend_id, NvHandle root_id,
                               NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS *output,
                               NvU32 *status) {
 NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS info={.gpuId=frontend_id};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2,.params=&info,
   .paramsSize=sizeof(info),.status=0xffffffffU};
 long rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
 if(output) { *output=info; }
 if(status) { *status=control.status; }
 return rc;
}
static long gpu_id_info_xfer(NvU32 frontend_id, NvHandle root_id,
                             NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS *output,
                             NvU32 *status) {
 NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS info={.gpuId=frontend_id};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2,.params=&info,
   .paramsSize=sizeof(info),.status=0xffffffffU};
 nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),.ptr=(NvP64)&control};
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
 long rc=hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
 if(output) { *output=info; }
 if(status) { *status=control.status; }
 return rc;
}
static long build_version_direct(NvHandle root_id,
                                 NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS *params,
                                 NvU32 flags, NvU32 *status) {
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION,.flags=flags,
   .params=params,.paramsSize=sizeof(*params),.status=0xffffffffU};
 long rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
 if(status) *status=control.status;
 return rc;
}
static long build_version_xfer(NvHandle root_id,
                               NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS *params,
                               NvU32 flags, NvU32 *status) {
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION,.flags=flags,
   .params=params,.paramsSize=sizeof(*params),.status=0xffffffffU};
 nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),.ptr=(NvP64)&control};
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
 long rc=hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
 if(status) *status=control.status;
 return rc ? rc : (long)control.status;
}
static long system_features_direct(NvHandle root_id, NvU32 *features,
                                   NvU32 *status) {
 NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS params={.featuresMask=0xdeadbeefU};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_SYSTEM_GET_FEATURES,.flags=NVOS54_FLAGS_NONE,
   .params=&params,.paramsSize=sizeof(params),.status=0xffffffffU};
 long rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
 if(features) *features=params.featuresMask;
 if(status) *status=control.status;
 return rc;
}
static long system_features_xfer(NvHandle root_id, NvU32 *features,
                                 NvU32 *status) {
 NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS params={.featuresMask=0xdeadbeefU};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_SYSTEM_GET_FEATURES,.flags=NVOS54_FLAGS_NONE,
   .params=&params,.paramsSize=sizeof(params),.status=0xffffffffU};
 nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),.ptr=(NvP64)&control};
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
 long rc=hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
 if(features) *features=params.featuresMask;
 if(status) *status=control.status;
 return rc ? rc : (long)control.status;
}
static long sync_boost_direct(NvHandle root_id,
    NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS *output, NvU32 flags,
    NvU32 params_size, NvU32 *status) {
 NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
 memset(&params,0xa5,sizeof(params));
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO,.flags=flags,
   .params=&params,.paramsSize=params_size,.status=0xffffffffU};
 long rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
 if(output) *output=params;
 if(status) *status=control.status;
 return rc;
}
static long sync_boost_xfer(NvHandle root_id,
    NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS *output, NvU32 *status) {
 NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
 memset(&params,0xa5,sizeof(params));
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO,.flags=NVOS54_FLAGS_NONE,
   .params=&params,.paramsSize=sizeof(params),.status=0xffffffffU};
 nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),
                       .ptr=(NvP64)&control};
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
 long rc=hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
 if(output) *output=params;
 if(status) *status=control.status;
 return rc;
}
static long fabric_status_direct(NvHandle root_id, NvU32 *fabric,
                                 NvU32 *status) {
 NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS params={
   .fabricStatus=NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_SKIP};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS,.flags=NVOS54_FLAGS_NONE,
   .params=&params,.paramsSize=sizeof(params),.status=0xffffffffU};
 long rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
 if(fabric) *fabric=(NvU32)params.fabricStatus;
 if(status) *status=control.status;
 return rc;
}
static long fabric_status_xfer(NvHandle root_id, NvU32 *fabric,
                               NvU32 *status) {
 NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS params={
   .fabricStatus=NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_SKIP};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS,.flags=NVOS54_FLAGS_NONE,
   .params=&params,.paramsSize=sizeof(params),.status=0xffffffffU};
 nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),.ptr=(NvP64)&control};
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
 long rc=hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
 if(fabric) *fabric=(NvU32)params.fabricStatus;
 if(status) *status=control.status;
 return rc ? rc : (long)control.status;
}
static long device_ids_direct(NvHandle root_id, NvU32 *mask, NvU32 *status) {
 NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS ids={.deviceIds=0xdeadbeefU};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS,.params=&ids,
   .paramsSize=sizeof(ids),.status=0xffffffffU};
 long rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
 if(mask) *mask=ids.deviceIds;
 if(status) *status=control.status;
 return rc;
}
static long device_ids_xfer(NvHandle root_id, NvU32 *mask, NvU32 *status) {
 NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS ids={.deviceIds=0xdeadbeefU};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS,.params=&ids,
   .paramsSize=sizeof(ids),.status=0xffffffffU};
 nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),.ptr=(NvP64)&control};
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
 long rc=hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
 if(mask) *mask=ids.deviceIds;
 if(status) *status=control.status;
 return rc;
}
static long attached_ids_direct(NvHandle root_id,
                                NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS *output,
                                NvU32 *status) {
 NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS ids={0};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS,.params=&ids,
   .paramsSize=sizeof(ids),.status=0xffffffffU};
 long rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
 if(output) *output=ids;
 if(status) *status=control.status;
 return rc;
}
static long attached_ids_xfer(NvHandle root_id,
                              NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS *output,
                              NvU32 *status) {
 NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS ids={0};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS,.params=&ids,
   .paramsSize=sizeof(ids),.status=0xffffffffU};
 nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),.ptr=(NvP64)&control};
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
 long rc=hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
 if(output) *output=ids;
 if(status) *status=control.status;
 return rc;
}
static long probed_ids_direct(NvHandle root_id,
                              NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *output,
                              NvU32 *status) {
 NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS ids={0};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_GPU_GET_PROBED_IDS,.params=&ids,
   .paramsSize=sizeof(ids),.status=0xffffffffU};
 long rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
 if(output) *output=ids;
 if(status) *status=control.status;
 return rc;
}
static long probed_ids_xfer(NvHandle root_id,
                            NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *output,
                            NvU32 *status) {
 NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS ids={0};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
   .cmd=NV0000_CTRL_CMD_GPU_GET_PROBED_IDS,.params=&ids,
   .paramsSize=sizeof(ids),.status=0xffffffffU};
 nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),.ptr=(NvP64)&control};
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
 long rc=hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
 if(output) *output=ids;
 if(status) *status=control.status;
 return rc;
}
static void set_attached_backend_ids(int backend, NvU32 first, NvU32 second) {
 attached_ids_counts[backend]=second==NV0000_CTRL_GPU_INVALID_ID?1:2;
 attached_ids_values[backend][0]=first;
 if(attached_ids_counts[backend]>1) attached_ids_values[backend][1]=second;
 attached_ids_transport[backend]=NV_OK; attached_ids_embedded[backend]=NV_OK;
}
static void set_inventory_record(int backend, const char *bdf, unsigned int minor,
                                 unsigned int gpu_id, unsigned int bus) {
 struct hybrid580_gpu_backend_record_v1 *r=&inventory_records[backend][0];
 memset(r,0,sizeof(*r)); strcpy(r->bdf,bdf); r->backend_minor=minor;
 r->backend_gpu_id=gpu_id; r->domain=0; r->bus=bus; r->vendor_id=0x10de;
 r->device_id=0x2684; inventory_count[backend]=1;
}
static struct hybrid580_gpu_catalog_v1 standard_node_catalog;
static void prepare_standard_nodes(void) {
 assert(hybrid580_gpu_catalog_build_v1(inventory_records[0],inventory_count[0],
        inventory_records[1],inventory_count[1],&standard_node_catalog)==0);
 assert(hybrid580_standard_nodes_register_v1(&standard_node_catalog,&hybrid_front_fops)==0);
}
static void set_standard_node_inventory(void) {
 set_inventory_record(0,"0000:81:00.0",7,5,0x81);
 set_inventory_record(1,"0000:02:00.0",7,512,2);
}
static void prepare_device_object_test(void) {
 set_inventory_record(0,"0000:81:00.0",7,5,0x81);
 set_inventory_record(1,"0000:02:00.0",7,512,2);
 device_ids_values[0]=1U<<10; device_ids_values[1]=1U<<11;
 device_ids_transport[0]=device_ids_transport[1]=NV_OK;
 device_ids_embedded[0]=device_ids_embedded[1]=NV_OK;
 device_alloc_transport[0]=device_alloc_transport[1]=NV_OK;
 device_alloc_embedded[0]=device_alloc_embedded[1]=NV_OK;
 device_free_transport[0]=device_free_transport[1]=NV_OK;
 device_free_embedded[0]=device_free_embedded[1]=NV_OK;
 device_alloc_override_enabled[0]=device_alloc_override_enabled[1]=false;
}
static long request_device_alloc(NvHandle root, NvHandle handle, NvU32 instance,
                                 NvHandle share, NvU32 outer_size) {
 NV0080_ALLOC_PARAMETERS params={.deviceId=instance,.hClientShare=share,
   .vaSpaceSize=0x200000};
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=root,
   .hObjectNew=handle,.hClass=NV01_DEVICE_0,.pAllocParms=(NvP64)&params,
   .paramsSize=outer_size,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_subdevice_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                                    NvU32 subdevice_id, NvU32 outer_size) {
 NV2080_ALLOC_PARAMETERS params={.subDeviceId=subdevice_id};
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=NV20_SUBDEVICE_0,.pAllocParms=(NvP64)&params,
   .paramsSize=outer_size,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_binapi_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                                 NvU32 reserved, NvU32 outer_size) {
 NV2081_ALLOC_PARAMETERS params={.reserved=reserved};
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=NV2081_BINAPI,.pAllocParms=(NvP64)&params,
   .paramsSize=outer_size,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_rusd_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                               NvU64 polled_data_mask, NvU32 outer_size) {
 NV00DE_ALLOC_PARAMETERS params={.polledDataMask=polled_data_mask};
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=RM_USER_SHARED_DATA,.pAllocParms=(NvP64)&params,
   .paramsSize=outer_size,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_rusd_alloc_missing_payload(NvHandle root, NvHandle parent,
                                                NvHandle handle, NvU32 outer_size) {
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=RM_USER_SHARED_DATA,.pAllocParms=NvP64_NULL,
   .paramsSize=outer_size,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_binapi_alloc_omitted(NvHandle root, NvHandle parent,
                                         NvHandle handle) {
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=NV2081_BINAPI,.pAllocParms=NvP64_NULL,
   .paramsSize=0,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_binapi_alloc_missing_payload(NvHandle root, NvHandle parent,
                                                  NvHandle handle, NvU32 outer_size) {
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=NV2081_BINAPI,.pAllocParms=NvP64_NULL,
   .paramsSize=outer_size,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_p2p_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                              NvU32 flags, NvU32 outer_size) {
 NV503C_ALLOC_PARAMETERS params={.flags=flags};
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=NV50_THIRD_PARTY_P2P,
   .pAllocParms=(NvP64)&params,.paramsSize=outer_size,
   .flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long p2p_control_request(bool xfer, NvHandle root, NvHandle p2p,
                                NvU32 command_id, void *params, NvU32 size,
                                NvU32 *status) {
 NVOS54_PARAMETERS control={.hClient=root,.hObject=p2p,.cmd=command_id,
   .params=(NvP64)params,.paramsSize=size,.status=0xffffffffU};
 long rc;
 if(xfer) {
  nv_ioctl_xfer_t request={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),
                           .ptr=(NvP64)&control};
  unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
  rc=hybrid_front_ioctl(&front,command,(unsigned long)&request);
 } else {
  rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
 }
 if(status) *status=control.status;
 return rc;
}
static long request_memory_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                                 NvU32 class_id, NV_MEMORY_ALLOCATION_PARAMS *params);
static long request_vaspace_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                                  NV_VASPACE_ALLOCATION_PARAMETERS *params);
static NvHandle prepare_p2p_control_fixture(void) {
 prepare_device_object_test();
 subdevice_alloc_transport[0]=subdevice_alloc_transport[1]=NV_OK;
 subdevice_alloc_embedded[0]=subdevice_alloc_embedded[1]=NV_OK;
 memory_alloc_transport[0]=memory_alloc_transport[1]=NV_OK;
 memory_alloc_embedded[0]=memory_alloc_embedded[1]=NV_OK;
 vaspace_alloc_transport[0]=vaspace_alloc_transport[1]=NV_OK;
 vaspace_alloc_embedded[0]=vaspace_alloc_embedded[1]=NV_OK;
 object_free_transport[0]=object_free_transport[1]=NV_OK;
 object_free_embedded[0]=object_free_embedded[1]=NV_OK;
 p2p_alloc_transport=NV_OK; p2p_alloc_embedded=NV_OK;
 p2p_alloc_override_enabled=false;
 make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
 NvHandle root=p21.hObjectNew;
 assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
 assert(!request_subdevice_alloc(root,223,225,0,0) && device_packet.status==NV_OK);
 NV_VASPACE_ALLOCATION_PARAMETERS va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW,
   .vaSize=0x200000000ULL};
 assert(!request_vaspace_alloc(root,223,445,&va) && device_packet.status==NV_OK);
 NV_MEMORY_ALLOCATION_PARAMS memory={.size=0x40000,.alignment=0x10000,
   .hVASpace=445};
 assert(!request_memory_alloc(root,223,556,NV01_MEMORY_LOCAL_USER,&memory) &&
        device_packet.status==NV_OK);
 assert(!request_p2p_alloc(root,225,250,NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1,0) &&
        device_packet.status==NV_OK);
 return root;
}
static long request_usermode_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                                   NvU32 class_id,
                                   const NV_HOPPER_USERMODE_A_PARAMS *params,
                                   NvU32 outer_size) {
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=class_id,
   .pAllocParms=params?(NvP64)params:NvP64_NULL,
   .paramsSize=outer_size,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long gr_tpc_mask_direct(NvHandle root_id, NvHandle subdevice,
    NV2080_CTRL_GR_GET_TPC_MASK_PARAMS *output, NvU32 *status) {
 NV2080_CTRL_GR_GET_TPC_MASK_PARAMS params={.gpcId=1};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=subdevice,
   .cmd=NV2080_CTRL_CMD_GR_GET_TPC_MASK,.params=&params,
   .paramsSize=sizeof(params),.status=0xffffffffU};
 long rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
 if(output) *output=params;
 if(status) *status=control.status;
 return rc;
}
static long gr_tpc_mask_malformed(NvHandle root_id, NvHandle subdevice,
    NvU32 command_id, NvU32 flags, NvU32 params_size) {
 NV2080_CTRL_GR_GET_TPC_MASK_PARAMS params={0};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=subdevice,
   .cmd=command_id,.flags=flags,.params=&params,.paramsSize=params_size,
   .status=0xffffffffU};
 return hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
}
static long gr_tpc_mask_xfer(NvHandle root_id, NvHandle subdevice,
    NV2080_CTRL_GR_GET_TPC_MASK_PARAMS *output, NvU32 *status) {
 NV2080_CTRL_GR_GET_TPC_MASK_PARAMS params={.gpcId=2};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=subdevice,
   .cmd=NV2080_CTRL_CMD_GR_GET_TPC_MASK,.params=&params,
   .paramsSize=sizeof(params),.status=0xffffffffU};
 nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),.ptr=(NvP64)&control};
 unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
 long rc=hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
 if(output) *output=params;
 if(status) *status=control.status;
 return rc;
}
static long gpu_name_string_control(NvHandle root_id, NvHandle subdevice,
    NvU32 selector, NvU32 flags, NvU32 params_size, bool use_xfer,
    NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS *output, NvU32 *status) {
 NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS params={.gpuNameStringFlags=selector};
 NVOS54_PARAMETERS control={.hClient=root_id,.hObject=subdevice,
   .cmd=NV2080_CTRL_CMD_GPU_GET_NAME_STRING,.flags=flags,
   .params=&params,.paramsSize=params_size,.status=0xffffffffU};
 long rc;
 if(use_xfer) {
  nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),
    .ptr=(NvP64)&control};
  unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
  rc=hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
 } else {
  rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
 }
 if(output) *output=params;
 if(status) *status=control.status;
 return rc;
}
static long request_memory_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                                 NvU32 class_id, NV_MEMORY_ALLOCATION_PARAMS *params) {
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=class_id,.pAllocParms=(NvP64)params,
   .paramsSize=0,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_vaspace_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                                  NV_VASPACE_ALLOCATION_PARAMETERS *params) {
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=FERMI_VASPACE_A,.pAllocParms=(NvP64)params,
   .paramsSize=0,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_channel_group_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                                        NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS *params) {
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=KEPLER_CHANNEL_GROUP_A,.pAllocParms=(NvP64)params,
   .paramsSize=0,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_context_share_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                                        NV_CTXSHARE_ALLOCATION_PARAMETERS *params) {
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=FERMI_CONTEXT_SHARE_A,.pAllocParms=(NvP64)params,
   .paramsSize=0,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_channel_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                                  NvU32 class_id, NV_CHANNEL_ALLOC_PARAMS *params) {
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=class_id,.pAllocParms=(NvP64)params,
   .paramsSize=0,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static long request_engine_alloc(NvHandle root, NvHandle parent, NvHandle handle,
                                 NvU32 class_id, NvP64 alloc_params,
                                 NvU32 outer_size) {
 device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=parent,
   .hObjectNew=handle,.hClass=class_id,.pAllocParms=alloc_params,
   .paramsSize=outer_size,.flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
 return hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet);
}
static void append_inventory_record(int backend, unsigned int index, const char *bdf,
                                    unsigned int minor, unsigned int gpu_id,
                                    unsigned int bus) {
 struct hybrid580_gpu_backend_record_v1 *r=&inventory_records[backend][index];
 memset(r,0,sizeof(*r)); strcpy(r->bdf,bdf); r->backend_minor=minor;
 r->backend_gpu_id=gpu_id; r->domain=0; r->bus=bus; r->vendor_id=0x10de;
 r->device_id=0x2684; if(inventory_count[backend]<index+1) inventory_count[backend]=index+1;
}
static void set_probed_backend_ids(int backend, const NvU32 *gpu_ids,
                                  const NvU32 *gpu_flags, unsigned int gpu_count,
                                  const NvU32 *excluded_ids, unsigned int excluded_count) {
 NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *reply=&probed_ids_reply[backend];
 memset(reply,0xff,sizeof(*reply));
 for(unsigned int i=0;i<NV0000_CTRL_GPU_MAX_PROBED_GPUS;i++) reply->gpuFlags[i]=0;
 for(unsigned int i=0;i<gpu_count;i++) {
  reply->gpuIds[i]=gpu_ids[i]; reply->gpuFlags[i]=gpu_flags[i];
 }
 for(unsigned int i=0;i<excluded_count;i++) reply->excludedGpuIds[i]=excluded_ids[i];
 probed_ids_transport[backend]=NV_OK; probed_ids_embedded[backend]=NV_OK;
}
static void set_card_info(int backend, unsigned int index, unsigned int minor,
                          unsigned int gpu_id, unsigned int bus,
                          unsigned int device_id, unsigned long long reg,
                          unsigned long long fb) {
 nv_ioctl_card_info_t *r=&card_info_records[backend][index]; memset(r,0,sizeof(*r));
 r->valid=NV_TRUE; r->pci_info.domain=0; r->pci_info.bus=bus;
 r->pci_info.slot=0; r->pci_info.function=0; r->pci_info.vendor_id=0x10de;
 r->pci_info.device_id=device_id; r->gpu_id=gpu_id; r->minor_number=minor;
 r->interrupt_line=13; r->reg_address=reg; r->reg_size=0x10000;
 r->fb_address=fb; r->fb_size=0x100000000ULL; card_info_count[backend]=index+1;
}
static unsigned int pm_api_log[64];
static unsigned int pm_api_log_count;
static int pm_fail_legacy_begin;
static unsigned int pm_expected_callback=HYBRID580_PM_PROVIDER_CALLBACK_RESUME;
static unsigned long long pm_last_generation;
static void pm_record(unsigned int event, unsigned long long generation) {
 assert(pm_api_log_count < sizeof(pm_api_log)/sizeof(pm_api_log[0]));
 pm_api_log[pm_api_log_count++]=event; pm_last_generation=generation;
}
int hybrid580_open_pm_recovery_begin_v1(unsigned long long generation) {
 pm_record(11,generation); return 0;
}
int hybrid580_legacy_pm_recovery_begin_v1(unsigned long long generation) {
 pm_record(21,generation); return pm_fail_legacy_begin ? -EIO : 0;
}
int hybrid580_open_pm_recovery_recover_v1(unsigned long long generation, unsigned int callback) {
 assert(callback==pm_expected_callback); pm_record(12,generation); return 0;
}
int hybrid580_legacy_pm_recovery_recover_v1(unsigned long long generation, unsigned int callback) {
 assert(callback==pm_expected_callback); pm_record(22,generation); return 0;
}
int hybrid580_open_pm_recovery_end_v1(unsigned long long generation) {
 pm_record(13,generation); return 0;
}
int hybrid580_legacy_pm_recovery_end_v1(unsigned long long generation) {
 pm_record(23,generation); return 0;
}
int hybrid580_open_pm_channels_suspend_v1(unsigned long long generation) {
 pm_record(14,generation); return 0;
}
int hybrid580_legacy_pm_channels_suspend_v1(unsigned long long generation) {
 pm_record(24,generation); return 0;
}
int hybrid580_open_pm_channels_resume_v1(unsigned long long generation) {
 pm_record(15,generation); return 0;
}
int hybrid580_legacy_pm_channels_resume_v1(unsigned long long generation) {
 pm_record(25,generation); return 0;
}
int hybrid580_open_pm_shared_uvm_suspend_v1(void) { pm_record(16,0); return 0; }
int hybrid580_open_pm_shared_uvm_resume_v1(void) { pm_record(17,0); return 0; }
int main(int argc, char **argv) {
 const char *s; assert(argc==2); s=argv[1];
 if(!strcmp(s,"version-check-roundtrip")) {
  make_front();
  nv_ioctl_rm_api_version_t request={.cmd=NV_RM_API_VERSION_CMD_QUERY,
      .reply=0xaaaaaaaaU};
  memcpy(request.versionString,"580.178.04",sizeof("580.178.04"));
  assert(hybrid_front_ioctl(&front,version_check_cmd(sizeof(request)),
                            (unsigned long)&request)==0);
  assert(version_check_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         version_check_calls[HYBRID580_BACKEND_OPEN]==1);
  assert(version_check_sizes[HYBRID580_BACKEND_LEGACY]==sizeof(request) &&
         version_check_sizes[HYBRID580_BACKEND_OPEN]==sizeof(request));
  assert(version_check_inputs[HYBRID580_BACKEND_LEGACY].cmd==request.cmd &&
         version_check_inputs[HYBRID580_BACKEND_OPEN].cmd==request.cmd &&
         !memcmp(version_check_inputs[HYBRID580_BACKEND_LEGACY].versionString,
                 "580.178.04",sizeof("580.178.04")) &&
         !memcmp(version_check_inputs[HYBRID580_BACKEND_OPEN].versionString,
                 "580.178.04",sizeof("580.178.04")));
  assert(request.reply==NV_RM_API_VERSION_REPLY_RECOGNIZED);
  front_put(); return 0;
 }
 if(!strcmp(s,"version-check-disagreement")) {
  make_front();
  nv_ioctl_rm_api_version_t request={.cmd=NV_RM_API_VERSION_CMD_QUERY,
      .reply=0xaaaaaaaaU};
  memcpy(request.versionString,"580.178.04",sizeof("580.178.04"));
  version_check_reply[HYBRID580_BACKEND_OPEN]=NV_RM_API_VERSION_REPLY_UNRECOGNIZED;
  assert(hybrid_front_ioctl(&front,version_check_cmd(sizeof(request)),
                            (unsigned long)&request)==-EINVAL);
  assert(version_check_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         version_check_calls[HYBRID580_BACKEND_OPEN]==1 &&
         request.reply==0xaaaaaaaaU);
  front_put(); return 0;
 }
 if(!strcmp(s,"version-check-fail-closed")) {
  make_front();
  nv_ioctl_rm_api_version_t request={.cmd=NV_RM_API_VERSION_CMD_QUERY,
      .reply=0xbbbbbbbbU};
  memcpy(request.versionString,"580.178.04",sizeof("580.178.04"));
  version_check_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_INVALID_ARGUMENT;
  assert(hybrid_front_ioctl(&front,version_check_cmd(sizeof(request)),
                            (unsigned long)&request)==-EINVAL);
  assert(version_check_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         version_check_calls[HYBRID580_BACKEND_OPEN]==1 &&
         request.reply==0xbbbbbbbbU);
  front_put(); return 0;
 }
 if(!strcmp(s,"version-check-native-rejection-copyout")) {
  make_front();
  nv_ioctl_rm_api_version_t request={.cmd=NV_RM_API_VERSION_CMD_STRICT,
      .reply=0xeeeeeeeeU};
  memcpy(request.versionString,"579.99.99",sizeof("579.99.99"));
  version_check_transport[HYBRID580_BACKEND_LEGACY]=NV_ERR_GENERIC;
  version_check_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_GENERIC;
  assert(hybrid_front_ioctl(&front,version_check_cmd(sizeof(request)),
                            (unsigned long)&request)==-EINVAL);
  assert(version_check_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         version_check_calls[HYBRID580_BACKEND_OPEN]==1 &&
         request.reply==NV_RM_API_VERSION_REPLY_RECOGNIZED &&
         !memcmp(request.versionString,"580.178.04",sizeof("580.178.04")));
  front_put(); return 0;
 }
 if(!strcmp(s,"version-check-invalid-size")) {
  make_front();
  nv_ioctl_rm_api_version_t request={.cmd=NV_RM_API_VERSION_CMD_STRICT};
  assert(hybrid_front_ioctl(&front,version_check_cmd(sizeof(request)-1),
                            (unsigned long)&request)==-EINVAL);
  assert(version_check_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         version_check_calls[HYBRID580_BACKEND_OPEN]==0);
  nv_ioctl_xfer_t xfer={.cmd=NV_ESC_CHECK_VERSION_STR,
      .size=sizeof(request)-1,.ptr=NV_PTR_TO_NvP64(&request)};
  assert(hybrid_front_ioctl(&front,
      _IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),
      (unsigned long)&xfer)==-EINVAL);
  assert(version_check_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         version_check_calls[HYBRID580_BACKEND_OPEN]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"version-check-copy-faults")) {
  make_front();
  nv_ioctl_rm_api_version_t request={.cmd=NV_RM_API_VERSION_CMD_QUERY,
      .reply=0xccccccccU};
  memcpy(request.versionString,"580.178.04",sizeof("580.178.04"));
  from_fault=1;
  assert(hybrid_front_ioctl(&front,version_check_cmd(sizeof(request)),
                            (unsigned long)&request)==-EFAULT);
  assert(version_check_calls[0]==0 && version_check_calls[1]==0);
  from_fault=0; to_fault=1;
  assert(hybrid_front_ioctl(&front,version_check_cmd(sizeof(request)),
                            (unsigned long)&request)==-EFAULT);
  assert(version_check_calls[0]==1 && version_check_calls[1]==1);
  to_fault=0;
  front_put(); return 0;
 }
 if(!strcmp(s,"version-check-xfer")) {
  make_front();
  nv_ioctl_rm_api_version_t request={.cmd=NV_RM_API_VERSION_CMD_QUERY,
      .reply=0xddddddddU};
  memcpy(request.versionString,"580.178.04",sizeof("580.178.04"));
  nv_ioctl_xfer_t xfer={.cmd=NV_ESC_CHECK_VERSION_STR,
      .size=sizeof(request),.ptr=NV_PTR_TO_NvP64(&request)};
  assert(hybrid_front_ioctl(&front,
      _IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),
      (unsigned long)&xfer)==0);
  assert(version_check_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         version_check_calls[HYBRID580_BACKEND_OPEN]==1 &&
         request.reply==NV_RM_API_VERSION_REPLY_RECOGNIZED);
  front_put(); return 0;
 }
 if(!strcmp(s,"system-pm-provider-adapter-fail-closed")) {
  static const unsigned int expected[]={11,21,14,24,25,15,23,13};
  assert(!hybrid_front_system_pm_notify(HYBRID580_PM_NOTIFY_SUSPEND_PREPARE));
  assert(hybrid_front_admission_state.blocked);
  assert(hybrid_front_admission_try_enter()==-EAGAIN);
  assert(hybrid_front_system_pm_dpm(HYBRID580_PM_DPM_SUSPEND)==-EOPNOTSUPP);
  assert(hybrid_front_admission_state.blocked);
  assert(!hybrid_front_system_pm_notify(HYBRID580_PM_NOTIFY_POST_SUSPEND));
  assert(!hybrid_front_admission_state.blocked);
  assert(pm_api_log_count==sizeof(expected)/sizeof(expected[0]));
  assert(!memcmp(pm_api_log,expected,sizeof(expected)) && pm_last_generation==1);
  return 0;
 }
 if(!strcmp(s,"system-pm-provider-adapter-begin-failure")) {
  pm_fail_legacy_begin=1;
  assert(hybrid_front_system_pm_notify(HYBRID580_PM_NOTIFY_SUSPEND_PREPARE)==-EIO);
  assert(!hybrid_front_admission_state.blocked);
  assert(pm_api_log_count==3 && pm_api_log[0]==11 && pm_api_log[1]==21 &&
         pm_api_log[2]==13);
  return 0;
 }
 if(!strcmp(s,"system-pm-provider-adapter-fail-closed-event-matrix")) {
  for(unsigned int i=0;i<4;i++) {
   enum hybrid580_pm_notifier_event prepare = i==0 ? HYBRID580_PM_NOTIFY_SUSPEND_PREPARE :
       i==1 ? HYBRID580_PM_NOTIFY_RESTORE_PREPARE : HYBRID580_PM_NOTIFY_HIBERNATION_PREPARE;
   enum hybrid580_pm_notifier_event complete = i==0 ? HYBRID580_PM_NOTIFY_POST_SUSPEND :
       i==1 ? HYBRID580_PM_NOTIFY_POST_RESTORE : HYBRID580_PM_NOTIFY_POST_HIBERNATION;
   enum hybrid580_pm_dpm_event quiesce = i==0 ? HYBRID580_PM_DPM_SUSPEND :
       i==1 ? HYBRID580_PM_DPM_POWEROFF :
       i==2 ? HYBRID580_PM_DPM_FREEZE : HYBRID580_PM_DPM_QUIESCE;
   assert(!hybrid_front_system_pm_notify(prepare));
   assert(hybrid_front_system_pm_dpm(quiesce)==-EOPNOTSUPP);
   assert(!hybrid_front_system_pm_notify(complete));
   assert(!hybrid_front_admission_state.blocked);
   assert(pm_api_log_count==8U*(i+1) && pm_last_generation==i+1);
  }
  return 0;
 }
 if(!strcmp(s,"build-version-null-sizing")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  const char *driver="580.178.04", *version="R580.178";
  const char *title="NVIDIA UNIX Open Kernel Module Driver";
  NvU32 expected=(NvU32)(sizeof("NVIDIA UNIX Open Kernel Module Driver"));
  assert(expected>sizeof("580.178.04") && expected>sizeof("R580.178"));
  for(NvU32 null_mask=1;null_mask<8;null_mask++) {
   char d[64],v[64],t[96]; memset(d,0x5a,sizeof(d)); memset(v,0x5a,sizeof(v)); memset(t,0x5a,sizeof(t));
   NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS params={
    .sizeOfStrings=0xffffffffU,
    .pDriverVersionBuffer=(null_mask&1)?0:(NvP64)d,
    .pVersionBuffer=(null_mask&2)?0:(NvP64)v,
    .pTitleBuffer=(null_mask&4)?0:(NvP64)t,
    .changelistNumber=0xaaaaaaaaU,.officialChangelistNumber=0xbbbbbbbbU};
   int before_copyouts=copy_to_user_calls;
   NvU32 status=0xffffffffU;
   assert(build_version_direct(root,&params,0,&status)==0 && status==NV_OK);
   assert(params.sizeOfStrings==expected && params.changelistNumber==0xaaaaaaaaU &&
          params.officialChangelistNumber==0xbbbbbbbbU);
   assert(copy_to_user_calls==before_copyouts+2);
   for(size_t i=0;i<sizeof(d);i++) assert((unsigned char)d[i]==0x5a);
   for(size_t i=0;i<sizeof(v);i++) assert((unsigned char)v[i]==0x5a);
   for(size_t i=0;i<sizeof(t);i++) assert((unsigned char)t[i]==0x5a);
   (void)driver; (void)version; (void)title;
  }
  assert(build_version_calls[HYBRID580_BACKEND_OPEN]==7 &&
         build_version_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         build_version_payload_size==1032U && build_version_client==root &&
         build_version_object==root && build_version_flags==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"build-version-capacity")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK); NvHandle root=p21.hObjectNew;
  const NvU32 max=(NvU32)sizeof("NVIDIA UNIX Open Kernel Module Driver");
  const NvU32 caps[]={max-1,max,max+1,0xffffffffU};
  for(unsigned int n=0;n<sizeof(caps)/sizeof(caps[0]);n++) {
   char d[64],v[64],t[96]; memset(d,0x5a,sizeof(d)); memset(v,0x5a,sizeof(v)); memset(t,0x5a,sizeof(t));
   NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS params={.sizeOfStrings=caps[n],
    .pDriverVersionBuffer=(NvP64)d,.pVersionBuffer=(NvP64)v,.pTitleBuffer=(NvP64)t,
    .changelistNumber=0xaaaaaaaaU,.officialChangelistNumber=0xbbbbbbbbU};
   int before_copyouts=copy_to_user_calls;
   NvU32 status=0xffffffffU;
   long rc=build_version_direct(root,&params,0,&status);
   if(n==0) {
    assert(rc==0 && status==NV_ERR_INVALID_PARAM_STRUCT && params.sizeOfStrings==caps[n]);
    assert(params.changelistNumber==0xaaaaaaaaU && params.officialChangelistNumber==0xbbbbbbbbU);
    assert(copy_to_user_calls==before_copyouts+2);
    for(size_t i=0;i<sizeof(d);i++) assert((unsigned char)d[i]==0x5a);
    for(size_t i=0;i<sizeof(v);i++) assert((unsigned char)v[i]==0x5a);
    for(size_t i=0;i<sizeof(t);i++) assert((unsigned char)t[i]==0x5a);
   } else {
    assert(rc==0 && status==NV_OK && params.sizeOfStrings==caps[n]);
    assert(!strcmp(d,"580.178.04") && !strcmp(v,"R580.178") &&
           !strcmp(t,"NVIDIA UNIX Open Kernel Module Driver"));
    assert((unsigned char)d[sizeof("580.178.04")] == 0x5a &&
           (unsigned char)v[sizeof("R580.178")] == 0x5a &&
           (unsigned char)t[sizeof("NVIDIA UNIX Open Kernel Module Driver")] == 0x5a);
    assert(params.changelistNumber==58017804U && params.officialChangelistNumber==58017800U);
    assert(copy_to_user_calls==before_copyouts+5);
   }
  }
  assert(build_version_calls[HYBRID580_BACKEND_OPEN]==4);
  front_put(); return 0;
 }
 if(!strcmp(s,"build-version-xfer")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK); NvHandle root=p21.hObjectNew;
  char d[64]={0},v[64]={0},t[96]={0};
  NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS params={.sizeOfStrings=40,
   .pDriverVersionBuffer=(NvP64)d,.pVersionBuffer=(NvP64)v,.pTitleBuffer=(NvP64)t};
  NvU32 status=0xffffffffU;
  assert(build_version_xfer(root,&params,0,&status)==NV_OK && status==NV_OK);
  assert(!strcmp(d,"580.178.04") && !strcmp(v,"R580.178") &&
         !strcmp(t,"NVIDIA UNIX Open Kernel Module Driver"));
  assert(params.changelistNumber==58017804U && params.officialChangelistNumber==58017800U);
  assert(build_version_calls[HYBRID580_BACKEND_OPEN]==1);
  front_put(); return 0;
 }
 if(!strcmp(s,"build-version-copy-faults")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK); NvHandle root=p21.hObjectNew;
  for(int fail_at=1;fail_at<=3;fail_at++) {
   char d[64],v[64],t[96]; memset(d,0x5a,sizeof(d)); memset(v,0x5a,sizeof(v)); memset(t,0x5a,sizeof(t));
   NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS params={.sizeOfStrings=64,
    .pDriverVersionBuffer=(NvP64)d,.pVersionBuffer=(NvP64)v,.pTitleBuffer=(NvP64)t,
    .changelistNumber=0xaaaaaaaaU,.officialChangelistNumber=0xbbbbbbbbU};
   NvU32 before=copy_to_user_calls, status=0xffffffffU; to_fault_call=(int)before+fail_at;
   assert(build_version_direct(root,&params,0,&status)==0 && status==NV_ERR_INVALID_PARAM_STRUCT);
   to_fault_call=0;
   assert(params.changelistNumber==0xaaaaaaaaU && params.officialChangelistNumber==0xbbbbbbbbU);
   assert(!strcmp(d,"580.178.04") == (fail_at>1));
   assert(!strcmp(v,"R580.178") == (fail_at>2));
   assert(!strcmp(t,"NVIDIA UNIX Open Kernel Module Driver") == false);
   assert(build_version_calls[HYBRID580_BACKEND_OPEN]==fail_at);
  }
  front_put(); return 0;
 }
 if(!strcmp(s,"build-version-fail-closed")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK); NvHandle root=p21.hObjectNew;
  char d[64],v[64],t[96]; memset(d,0x5a,sizeof(d)); memset(v,0x5a,sizeof(v)); memset(t,0x5a,sizeof(t));
  NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS params={.sizeOfStrings=64,
   .pDriverVersionBuffer=(NvP64)d,.pVersionBuffer=(NvP64)v,.pTitleBuffer=(NvP64)t};
  NvU32 status=0xffffffffU;
  build_version_malformed=true;
  assert(build_version_direct(root,&params,0,&status)==0 && status==NV_ERR_INVALID_PARAM_STRUCT);
  assert(build_version_calls[HYBRID580_BACKEND_OPEN]==1);
  assert((unsigned char)d[0]==0x5a && (unsigned char)v[0]==0x5a && (unsigned char)t[0]==0x5a);
  build_version_malformed=false; build_version_calls[HYBRID580_BACKEND_OPEN]=0;
  build_version_no_status=true;
  assert(build_version_direct(root,&params,0,&status)==0 && status==NV_ERR_INVALID_STATE);
  assert(build_version_calls[HYBRID580_BACKEND_OPEN]==1);
  build_version_no_status=false; build_version_calls[HYBRID580_BACKEND_OPEN]=0;
  build_version_transport=NV_ERR_OPERATING_SYSTEM;
  assert(build_version_direct(root,&params,0,&status)==-EINVAL && status==NV_ERR_OPERATING_SYSTEM);
  assert(build_version_calls[HYBRID580_BACKEND_OPEN]==1);
  assert((unsigned char)d[0]==0x5a && (unsigned char)v[0]==0x5a && (unsigned char)t[0]==0x5a);
  build_version_transport=NV_OK; build_version_calls[HYBRID580_BACKEND_OPEN]=0;
  build_version_embedded=NV_ERR_INVALID_STATE;
  assert(build_version_direct(root,&params,0,&status)==0 && status==NV_ERR_INVALID_STATE);
  assert(build_version_calls[HYBRID580_BACKEND_OPEN]==1);
  assert((unsigned char)d[0]==0x5a && (unsigned char)v[0]==0x5a && (unsigned char)t[0]==0x5a);
  front_put(); return 0;
 }
 if(!strcmp(s,"build-version-allocation-failure")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK); NvHandle root=p21.hObjectNew;
  char d[64],v[64],t[96]; memset(d,0x5a,sizeof(d)); memset(v,0x5a,sizeof(v)); memset(t,0x5a,sizeof(t));
  NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS params={.sizeOfStrings=64,
   .pDriverVersionBuffer=(NvP64)d,.pVersionBuffer=(NvP64)v,.pTitleBuffer=(NvP64)t,
   .changelistNumber=0xaaaaaaaaU,.officialChangelistNumber=0xbbbbbbbbU};
  int before_allocs=live_model_allocs;
  fail_alloc=true;
  NvU32 status=0xffffffffU;
  assert(build_version_direct(root,&params,0,&status)==0 && status==NV_ERR_NO_MEMORY);
  fail_alloc=false;
  assert(build_version_calls[HYBRID580_BACKEND_OPEN]==0 &&
         build_version_calls[HYBRID580_BACKEND_LEGACY]==0);
  assert(live_model_allocs==before_allocs);
  assert(params.sizeOfStrings==64 && params.changelistNumber==0xaaaaaaaaU &&
         params.officialChangelistNumber==0xbbbbbbbbU);
  for(size_t i=0;i<sizeof(d);i++) assert((unsigned char)d[i]==0x5a);
  for(size_t i=0;i<sizeof(v);i++) assert((unsigned char)v[i]==0x5a);
  for(size_t i=0;i<sizeof(t);i++) assert((unsigned char)t[i]==0x5a);
  front_put(); return 0;
 }
 if(!strcmp(s,"build-version-invalid-input")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK); NvHandle root=p21.hObjectNew;
  char d[64]={0},v[64]={0},t[96]={0};
  NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS params={.sizeOfStrings=64,
   .pDriverVersionBuffer=(NvP64)d,.pVersionBuffer=(NvP64)v,.pTitleBuffer=(NvP64)t};
  NvU32 status=0xffffffffU;
  assert(build_version_direct(root,&params,1,&status)==-EINVAL);
  assert(build_version_direct(root+77,&params,0,&status)==-EINVAL);
  assert(build_version_calls[HYBRID580_BACKEND_OPEN]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"system-features-direct")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew; NvU32 features=0xdeadbeefU, status=0xffffffffU;
  assert(system_features_direct(root,&features,&status)==0 && status==NV_OK);
  assert(features==0x00000015U);
  assert(system_features_calls[HYBRID580_BACKEND_OPEN]==1 &&
         system_features_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         system_features_client==root && system_features_object==root &&
         system_features_flags==0 && system_features_payload_size==sizeof(NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS));
  front_put(); return 0;
 }
 if(!strcmp(s,"system-features-xfer")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew; NvU32 features=0xdeadbeefU, status=0xffffffffU;
  assert(system_features_xfer(root,&features,&status)==NV_OK && status==NV_OK);
  assert(features==0x00000015U && system_features_calls[HYBRID580_BACKEND_OPEN]==1 &&
         system_features_calls[HYBRID580_BACKEND_LEGACY]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"system-features-invalid")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS params={.featuresMask=0xaaaaaaaaU};
  NVOS54_PARAMETERS control={.hClient=root,.hObject=root,
   .cmd=NV0000_CTRL_CMD_SYSTEM_GET_FEATURES,.params=&params,
   .paramsSize=sizeof(params),.status=0xffffffffU};
  control.flags=1;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  control.flags=0; control.paramsSize=sizeof(params)-1;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  control.paramsSize=sizeof(params); control.hClient=root+77; control.hObject=root+77;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  assert(system_features_calls[HYBRID580_BACKEND_OPEN]==0 &&
         system_features_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         params.featuresMask==0xaaaaaaaaU);
  front_put(); return 0;
 }
 if(!strcmp(s,"system-features-fail-closed")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew; NvU32 features=0xdeadbeefU, status=0xffffffffU;
  system_features_transport=NV_ERR_OPERATING_SYSTEM;
  assert(system_features_direct(root,&features,&status)==-EINVAL &&
         status==NV_ERR_OPERATING_SYSTEM && features==0xdeadbeefU);
  system_features_transport=NV_OK; system_features_calls[HYBRID580_BACKEND_OPEN]=0;
  system_features_embedded=NV_ERR_INVALID_STATE;
  assert(system_features_direct(root,&features,&status)==0 &&
         status==NV_ERR_INVALID_STATE && features==0xdeadbeefU);
  system_features_embedded=NV_OK; system_features_calls[HYBRID580_BACKEND_OPEN]=0;
  system_features_no_status=true;
  assert(system_features_direct(root,&features,&status)==0 &&
         status==NV_ERR_INVALID_STATE && features==0xdeadbeefU);
  system_features_no_status=false;
  assert(system_features_calls[HYBRID580_BACKEND_OPEN]==1 &&
         system_features_calls[HYBRID580_BACKEND_LEGACY]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-policy")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==0 && status==NV_OK);
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0);
  assert(sync_boost_xfer(root,&params,&status)==0 && status==NV_OK);
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0);
  assert(sync_boost_calls[HYBRID580_BACKEND_LEGACY]==2 &&
         sync_boost_calls[HYBRID580_BACKEND_OPEN]==2 &&
         sync_boost_client[HYBRID580_BACKEND_LEGACY]==root &&
         sync_boost_client[HYBRID580_BACKEND_OPEN]==root &&
         sync_boost_object[HYBRID580_BACKEND_LEGACY]==root &&
         sync_boost_object[HYBRID580_BACKEND_OPEN]==root &&
         sync_boost_flags[HYBRID580_BACKEND_LEGACY]==NVOS54_FLAGS_NONE &&
         sync_boost_flags[HYBRID580_BACKEND_OPEN]==NVOS54_FLAGS_NONE &&
         sync_boost_payload_size[HYBRID580_BACKEND_LEGACY]==2244 &&
         sync_boost_payload_size[HYBRID580_BACKEND_OPEN]==2244);
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-nonzero")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  for(int owner=0;owner<2;owner++) {
   sync_boost_count[owner]=1;
   assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
       sizeof(params),&status)==0 && status==NV_ERR_NOT_SUPPORTED);
   for(size_t i=0;i<sizeof(params);i++)
    assert(((const unsigned char *)&params)[i]==0xa5);
   sync_boost_count[owner]=0;
  }
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==0 && status==NV_OK);
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0);
  assert(sync_boost_calls[0]==3 && sync_boost_calls[1]==3);
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-transport-error")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  for(int owner=0;owner<2;owner++) {
   sync_boost_transport[owner]=NV_ERR_OPERATING_SYSTEM;
   assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
       sizeof(params),&status)==-EINVAL && status==NV_ERR_OPERATING_SYSTEM);
   for(size_t i=0;i<sizeof(params);i++)
    assert(((const unsigned char *)&params)[i]==0xa5);
   sync_boost_transport[owner]=NV_OK;
  }
  assert(sync_boost_calls[0]==2 && sync_boost_calls[1]==2);
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-rm-error")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  for(int owner=0;owner<2;owner++) {
   sync_boost_embedded[owner]=NV_ERR_NOT_SUPPORTED;
   assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
       sizeof(params),&status)==0 && status==NV_ERR_NOT_SUPPORTED);
   for(size_t i=0;i<sizeof(params);i++)
    assert(((const unsigned char *)&params)[i]==0xa5);
   sync_boost_embedded[owner]=NV_OK;
  }
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-xfer-transport-error")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  for(int owner=0;owner<2;owner++) {
   sync_boost_transport[owner]=NV_ERR_OPERATING_SYSTEM;
   assert(sync_boost_xfer(root,&params,&status)==-EINVAL &&
          status==NV_ERR_OPERATING_SYSTEM);
   for(size_t i=0;i<sizeof(params);i++)
    assert(((const unsigned char *)&params)[i]==0xa5);
   sync_boost_transport[owner]=NV_OK;
  }
  assert(sync_boost_calls[0]==2 && sync_boost_calls[1]==2);
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-xfer-rm-error")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  for(int owner=0;owner<2;owner++) {
   sync_boost_embedded[owner]=NV_ERR_NOT_SUPPORTED;
   assert(sync_boost_xfer(root,&params,&status)==0 &&
          status==NV_ERR_NOT_SUPPORTED);
   for(size_t i=0;i<sizeof(params);i++)
    assert(((const unsigned char *)&params)[i]==0xa5);
   sync_boost_embedded[owner]=NV_OK;
  }
  assert(sync_boost_calls[0]==2 && sync_boost_calls[1]==2);
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-cross-provider-error-precedence")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  sync_boost_embedded[HYBRID580_BACKEND_LEGACY]=NV_ERR_NOT_SUPPORTED;
  sync_boost_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_OPERATING_SYSTEM;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==-EINVAL && status==NV_ERR_OPERATING_SYSTEM);
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0xa5);
  status=0xffffffffU;
  assert(sync_boost_xfer(root,&params,&status)==-EINVAL &&
         status==NV_ERR_OPERATING_SYSTEM);
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0xa5);

  sync_boost_embedded[HYBRID580_BACKEND_LEGACY]=NV_OK;
  sync_boost_transport[HYBRID580_BACKEND_LEGACY]=NV_ERR_OPERATING_SYSTEM;
  sync_boost_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  sync_boost_embedded[HYBRID580_BACKEND_OPEN]=NV_ERR_NOT_SUPPORTED;
  status=0xffffffffU;
  assert(sync_boost_xfer(root,&params,&status)==-EINVAL &&
         status==NV_ERR_OPERATING_SYSTEM);
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0xa5);
  status=0xffffffffU;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==-EINVAL && status==NV_ERR_OPERATING_SYSTEM);
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0xa5);
  assert(sync_boost_calls[HYBRID580_BACKEND_LEGACY]==4 &&
         sync_boost_calls[HYBRID580_BACKEND_OPEN]==4);
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-malformed-provider")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  sync_boost_no_status[0]=true;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==-EINVAL && status==NV_ERR_INVALID_STATE);
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0xa5);
  sync_boost_no_status[0]=false;
  sync_boost_no_count[1]=true;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==-EINVAL && status==NV_ERR_INVALID_STATE);
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0xa5);
  sync_boost_no_count[1]=false;
  sync_boost_count[0]=NV0000_SYNC_GPU_BOOST_MAX_GROUPS+1;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==-EINVAL && status==NV_ERR_INVALID_STATE);
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0xa5);
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-invalid")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params={0};
  NVOS54_PARAMETERS control={.hClient=root,.hObject=root,
   .cmd=NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO,.params=&params,
   .paramsSize=sizeof(params),.status=0xffffffffU};
  control.flags=1;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  control.flags=0; control.paramsSize=sizeof(params)-1;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  control.paramsSize=sizeof(params); control.hObject=root+7;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  control.hObject=root; control.hClient=0;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  control.hClient=root; control.params=0;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  assert(sync_boost_calls[0]==0 && sync_boost_calls[1]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-root-split")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  struct hybrid_front_root *tracked=hybrid_front_find_root(front.private_data,root);
  assert(tracked);
  tracked->root.slot[HYBRID580_BACKEND_OPEN].handle=root+1;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==-EINVAL && status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(sync_boost_calls[0]==0 && sync_boost_calls[1]==0);
  tracked->root.slot[HYBRID580_BACKEND_OPEN].handle=root;
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-missing-session")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  struct hybrid_front_file *state=front.private_data;
  struct hybrid580_control_session *saved=state->sessions[HYBRID580_BACKEND_OPEN];
  state->sessions[HYBRID580_BACKEND_OPEN]=NULL;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==-EINVAL && status==NV_ERR_INVALID_STATE);
  assert(sync_boost_calls[0]==0 && sync_boost_calls[1]==0);
  state->sessions[HYBRID580_BACKEND_OPEN]=saved;
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-allocation-failure")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  fail_alloc=1;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==-ENOMEM && status==NV_ERR_NO_MEMORY);
  fail_alloc=0;
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0xa5);
  assert(sync_boost_calls[0]==0 && sync_boost_calls[1]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-interrupted")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  interrupt_lock=1;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==-EINTR && status==NV_ERR_OPERATING_SYSTEM);
  interrupt_lock=0;
  assert(sync_boost_calls[0]==0 && sync_boost_calls[1]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"sync-boost-groups-copy-faults")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
  NvU32 status=0xffffffffU;
  int before=copy_to_user_calls;
  to_fault_call=before+1;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==-EFAULT && status==NV_ERR_INVALID_PARAM_STRUCT);
  to_fault_call=0;
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0xa5);
  before=copy_to_user_calls;
  to_fault_call=before+2;
  assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
      sizeof(params),&status)==-EFAULT && status==0xffffffffU);
  to_fault_call=0;
  for(size_t i=0;i<sizeof(params);i++)
   assert(((const unsigned char *)&params)[i]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"system-features-copy-faults")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS params={.featuresMask=0xaaaaaaaaU};
  NVOS54_PARAMETERS control={.hClient=root,.hObject=root,
   .cmd=NV0000_CTRL_CMD_SYSTEM_GET_FEATURES,.params=&params,
   .paramsSize=sizeof(params),.status=0xffffffffU};
  int before=copy_to_user_calls;
  to_fault_call=before+1;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EFAULT);
  to_fault_call=0;
  assert(params.featuresMask==0xaaaaaaaaU && control.status==NV_ERR_INVALID_PARAM_STRUCT);
  before=copy_to_user_calls; to_fault_call=before+2;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EFAULT);
  to_fault_call=0;
  assert(params.featuresMask==0x00000015U && system_features_calls[HYBRID580_BACKEND_OPEN]==2);
  front_put(); return 0;
 }
 if(!strcmp(s,"fabric-status-direct")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew; NvU32 fabric=0, status=0xffffffffU;
  assert(fabric_status_direct(root,&fabric,&status)==0 && status==NV_OK);
  assert(fabric==NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_INITIALIZED);
  assert(fabric_status_calls[HYBRID580_BACKEND_OPEN]==1 &&
         fabric_status_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         fabric_status_client==root && fabric_status_object==root &&
         fabric_status_flags==0 && fabric_status_payload_size==sizeof(NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS));
  front_put(); return 0;
 }
 if(!strcmp(s,"fabric-status-xfer")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew; NvU32 fabric=0, status=0xffffffffU;
  assert(fabric_status_xfer(root,&fabric,&status)==NV_OK && status==NV_OK);
  assert(fabric==NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_INITIALIZED &&
         fabric_status_calls[HYBRID580_BACKEND_OPEN]==1 &&
         fabric_status_calls[HYBRID580_BACKEND_LEGACY]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"fabric-status-invalid")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS params={
   .fabricStatus=NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_SKIP};
  NVOS54_PARAMETERS control={.hClient=root,.hObject=root,
   .cmd=NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS,.params=&params,
   .paramsSize=sizeof(params),.status=0xffffffffU};
  control.flags=1;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  control.flags=0; control.paramsSize=sizeof(params)-1;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  control.paramsSize=sizeof(params); control.hClient=root+77; control.hObject=root+77;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  assert(fabric_status_calls[HYBRID580_BACKEND_OPEN]==0 &&
         fabric_status_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         params.fabricStatus==NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_SKIP);
  front_put(); return 0;
 }
 if(!strcmp(s,"fabric-status-fail-closed")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew; NvU32 fabric=0, status=0xffffffffU;
  fabric_status_transport=NV_ERR_OPERATING_SYSTEM;
  assert(fabric_status_direct(root,&fabric,&status)==-EINVAL &&
         status==NV_ERR_OPERATING_SYSTEM &&
         fabric==NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_SKIP);
  fabric_status_transport=NV_OK; fabric_status_calls[HYBRID580_BACKEND_OPEN]=0;
  fabric_status_embedded=NV_ERR_INVALID_STATE;
  assert(fabric_status_direct(root,&fabric,&status)==0 &&
         status==NV_ERR_INVALID_STATE &&
         fabric==NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_SKIP);
  fabric_status_embedded=NV_OK; fabric_status_calls[HYBRID580_BACKEND_OPEN]=0;
  fabric_status_no_status=true;
  assert(fabric_status_direct(root,&fabric,&status)==0 &&
         status==NV_ERR_INVALID_STATE &&
         fabric==NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_SKIP);
  fabric_status_no_status=false;
  assert(fabric_status_calls[HYBRID580_BACKEND_OPEN]==1 &&
         fabric_status_calls[HYBRID580_BACKEND_LEGACY]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"fabric-status-copy-fault")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS params={
   .fabricStatus=NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_SKIP};
  NVOS54_PARAMETERS control={.hClient=root,.hObject=root,
   .cmd=NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS,.params=&params,
   .paramsSize=sizeof(params),.status=0xffffffffU};
  int before=copy_to_user_calls; to_fault_call=before+1;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EFAULT);
  to_fault_call=0;
  assert(params.fabricStatus==NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_SKIP &&
         control.status==NV_ERR_INVALID_PARAM_STRUCT);
  front_put(); return 0;
 }
 if(!strcmp(s,"sys-params-route")) {
  unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_SYS_PARAMS,nv_ioctl_sys_params_t);
  nv_ioctl_sys_params_t params={.memblock_size=0x200000ULL};
  make_front();
  assert(hybrid_front_ioctl(&front,command,(unsigned long)&params)==0);
  assert(sys_params_calls[0]==1 && sys_params_calls[1]==1);
  assert(sys_params_set[0] && sys_params_set[1] &&
         sys_params_value[0]==params.memblock_size &&
         sys_params_value[1]==params.memblock_size);
  assert(hybrid_front_ioctl(&front,command,(unsigned long)&params)==0);
  assert(sys_params_calls[0]==2 && sys_params_calls[1]==2);
  params.memblock_size++;
  assert(hybrid_front_ioctl(&front,command,(unsigned long)&params)==-EBUSY);
  assert(sys_params_calls[0]==3 && sys_params_calls[1]==2);
  assert(sys_params_value[0]==0x200000ULL && sys_params_value[1]==0x200000ULL);
  front_put(); return 0;
 }
 if(!strncmp(s,"sys-params-",11) && strcmp(s,"sys-params-route")) {
  unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_SYS_PARAMS,nv_ioctl_sys_params_t);
  nv_ioctl_sys_params_t params={.memblock_size=0x400000ULL};
  make_front();
  if(!strcmp(s,"sys-params-copyin")) {
   from_fault=1;
   assert(hybrid_front_ioctl(&front,command,(unsigned long)&params)==-EFAULT);
   assert(!sys_params_calls[0] && !sys_params_calls[1]);
  } else if(!strcmp(s,"sys-params-copyout")) {
   to_fault=1;
   assert(hybrid_front_ioctl(&front,command,(unsigned long)&params)==-EFAULT);
   assert(sys_params_calls[0]==1 && sys_params_calls[1]==1);
   to_fault=0;
   assert(hybrid_front_ioctl(&front,command,(unsigned long)&params)==0);
   assert(sys_params_calls[0]==2 && sys_params_calls[1]==2);
  } else if(!strcmp(s,"sys-params-first-failure")) {
   sys_params_error[0]=-EBUSY;
   assert(hybrid_front_ioctl(&front,command,(unsigned long)&params)==-EBUSY);
   assert(sys_params_calls[0]==1 && sys_params_calls[1]==0);
   assert(!hybrid_front_sys_params_poisoned);
  } else if(!strcmp(s,"sys-params-second-failure")) {
   sys_params_error[1]=-EIO;
   assert(hybrid_front_ioctl(&front,command,(unsigned long)&params)==-EIO);
   assert(sys_params_calls[0]==1 && sys_params_calls[1]==1);
   assert(hybrid_front_sys_params_poisoned &&
          ((struct hybrid_front_file *)front.private_data)->quarantined);
   assert(hybrid_front_ioctl(&front,command,(unsigned long)&params)==-EIO);
   assert(sys_params_calls[0]==1 && sys_params_calls[1]==1);
  } else if(!strcmp(s,"sys-params-format")) {
   unsigned int bad[]={_IOWR(NV_IOCTL_MAGIC,NV_ESC_SYS_PARAMS,NvU32),
       _IOR(NV_IOCTL_MAGIC,NV_ESC_SYS_PARAMS,nv_ioctl_sys_params_t)};
   for(unsigned int i=0;i<sizeof(bad)/sizeof(bad[0]);i++)
    assert(hybrid_front_ioctl(&front,bad[i],(unsigned long)&params)==-EINVAL);
   assert(!sys_params_calls[0] && !sys_params_calls[1]);
  } else { assert(!"unknown sys-params scenario"); }
  front_put(); return 0;
 }
 if(!strncmp(s,"gpu-",4)) {
  if(!strcmp(s,"gpu-open-route") || !strcmp(s,"gpu-poll-open-lifetime") ||
     !strcmp(s,"gpu-poll-missing-backend-callback") ||
     !strcmp(s,"gpu-poll-gated") ||
     !strcmp(s,"gpu-mmap-open-lifetime") || !strcmp(s,"gpu-mmap-backend-error") ||
     !strcmp(s,"gpu-mmap-gated")) {
   set_inventory_record(0,"0000:65:00.0",7,5,0x65);
   set_inventory_record(1,"0000:81:00.0",7,512,0x81);
  } else {
   set_inventory_record(0,"0000:81:00.0",7,5,0x81);
   set_inventory_record(1,"0000:02:00.0",7,512,2);
  }
 }
 if(!strcmp(s,"attach-after-gpu-open-failure"))
  set_inventory_record(0,"0000:65:00.0",3,45,0x65);
 if(!strcmp(s,"init-disabled")) { assert(!enable_control); assert(!hybrid_front_init()); assert(!device_registers && !registrations[0] && !created[0]); hybrid_front_exit(); assert(!device_unregisters); return 0; }
 if(!strncmp(s,"init-",5)) {
  enable_control=true;
  if(!strcmp(s,"init-legacy-fail")) fail_register=1;
  if(!strcmp(s,"init-open-fail")) fail_register=2;
  if(!strcmp(s,"init-device-fail")) fail_misc=1;
  int r=hybrid_front_init();
  if(!strcmp(s,"init-success")) { assert(!r && hybrid_front_registered); assert(standard_nodes_ready); hybrid_front_exit(); assert(device_unregisters==1 && standard_nodes_unregisters==1 && unregistrations[0]==1 && unregistrations[1]==1); }
  else { assert(r==-EBUSY && !hybrid_front_registered); assert(unregistrations[0]==(fail_register!=1)); assert(unregistrations[1]==!!fail_misc); assert(standard_nodes_unregisters==!!fail_misc); }
  assert(!created[0] && !created[1]); return 0;
 }
 if(!strncmp(s,"open-",5)) {
  if(!strcmp(s,"open-memory-fail")) fail_alloc=1;
  if(!strcmp(s,"open-legacy-fail")) fail_create=1;
  if(!strcmp(s,"open-modern-fail")) fail_create=2;
  front=(struct file){.f_op=&hybrid_front_fops,.private_data=(void *)1,.refs=1};
  assert(hybrid_front_open(&inode,&front)<0 && front.private_data==NULL);
  assert(session_puts[0]==(fail_create==2)); assert(!session_puts[1]); assert(!hybrid_front_release(&inode,&front)); return 0;
 }
 if(!strcmp(s,"catalog-query")) {
  set_inventory_record(0,"0000:65:00.0",3,44,0x65);
  set_inventory_record(1,"0000:01:00.0",3,44,1);
 }
 if(!strncmp(s,"gpu-id-info-",12) || !strncmp(s,"attached-ids-",13) ||
    !strncmp(s,"probed-ids-",11)) {
  /* Installed R580/R595 observations use distinct raw RM GPU IDs: V100=5,
   * RTX5080=512. The frontend must translate by the BDF-sorted catalog. */
  set_inventory_record(0,"0000:81:00.0",7,5,0x81);
  set_inventory_record(1,"0000:02:00.0",7,512,2);
 }
 if(!strncmp(s,"probed-ids-",11)) {
  NvU32 v100_ids[]={5}, v100_flags[]={8}, v100_excluded[]={7};
  NvU32 rtx_ids[]={512}, rtx_flags[]={1}, rtx_excluded[]={513};
  append_inventory_record(0,1,"0000:03:00.0",8,7,3);
  append_inventory_record(1,1,"0000:90:00.0",8,513,0x90);
  set_probed_backend_ids(0,v100_ids,v100_flags,1,v100_excluded,1);
  set_probed_backend_ids(1,rtx_ids,rtx_flags,1,rtx_excluded,1);
 }
 if(!strcmp(s,"card-info-merge") || !strcmp(s,"card-info-small") ||
    !strcmp(s,"card-info-xfer") || !strcmp(s,"card-info-stale") ||
    !strcmp(s,"card-info-backend-error") || !strcmp(s,"card-info-copyin-failure") ||
    !strcmp(s,"card-info-copyout-failure") || !strncmp(s,"card-info-allocation-fail-",26)) {
  set_inventory_record(0,"0000:81:00.0",7,44,0x81);
  set_inventory_record(1,"0000:02:00.0",7,44,2);
  inventory_records[0][0].device_id=0x1db6;
  inventory_records[1][0].device_id=0x2c02;
  set_card_info(0,0,7,44,0x81,0x1db6,0x81000000ULL,0x900000000ULL);
  set_card_info(1,0,7,44,2,0x2c02,0x20000000ULL,0xa00000000ULL);
  if(!strcmp(s,"card-info-stale")) card_info_records[1][0].pci_info.device_id=0xdead;
  if(!strcmp(s,"card-info-backend-error")) card_info_error[1]=-EIO;
 }
 if(!strcmp(s,"hybrid-dual-gpu-contract") ||
    !strcmp(s,"hybrid-dual-gpu-contract-legacy-first")) {
  bool legacy_first=!strcmp(s,"hybrid-dual-gpu-contract-legacy-first");
  const char *legacy_bdf=legacy_first ? "0000:02:00.0" : "0000:81:00.0";
  const char *open_bdf=legacy_first ? "0000:81:00.0" : "0000:02:00.0";
  unsigned int legacy_bus=legacy_first ? 2U : 0x81U;
  unsigned int open_bus=legacy_first ? 0x81U : 2U;
  unsigned int first_backend=legacy_first ? HYBRID580_BACKEND_LEGACY :
                                            HYBRID580_BACKEND_OPEN;
  unsigned int second_backend=legacy_first ? HYBRID580_BACKEND_OPEN :
                                             HYBRID580_BACKEND_LEGACY;
  /* Compose the independent frontend contracts in one process-scoped fixture:
   * BDF catalog/card metadata, frontend device-instance IDs, standard device
   * nodes, REGISTER_FD ownership, and typed NV01_DEVICE_0 allocation. Run with
   * either provider first in PCI order so routing cannot depend on generation. */
  set_inventory_record(HYBRID580_BACKEND_LEGACY,legacy_bdf,7,5,legacy_bus);
  set_inventory_record(HYBRID580_BACKEND_OPEN,open_bdf,3,512,open_bus);
  inventory_records[HYBRID580_BACKEND_LEGACY][0].device_id=0x1db6;
  inventory_records[HYBRID580_BACKEND_OPEN][0].device_id=0x2c02;
  set_card_info(HYBRID580_BACKEND_LEGACY,0,7,5,legacy_bus,0x1db6,
                0x81000000ULL,0x900000000ULL);
  set_card_info(HYBRID580_BACKEND_OPEN,0,3,512,open_bus,0x2c02,
                0x20000000ULL,0xa00000000ULL);
  device_ids_values[HYBRID580_BACKEND_LEGACY]=1U;
  device_ids_values[HYBRID580_BACKEND_OPEN]=1U;
  device_ids_transport[HYBRID580_BACKEND_LEGACY]=NV_OK;
  device_ids_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  device_ids_embedded[HYBRID580_BACKEND_LEGACY]=NV_OK;
  device_ids_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  gpu_id_info_device_instances[HYBRID580_BACKEND_LEGACY]=0;
  gpu_id_info_device_instances[HYBRID580_BACKEND_OPEN]=0;
  device_alloc_transport[HYBRID580_BACKEND_LEGACY]=NV_OK;
  device_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  device_alloc_embedded[HYBRID580_BACKEND_LEGACY]=NV_OK;
  device_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;

  make_front();
  nv_ioctl_card_info_t cards[2]={{0}};
  assert(!hybrid_front_ioctl(&front,card_info_cmd(sizeof(cards)),
                             (unsigned long)cards));
  assert(cards[0].valid && cards[0].pci_info.bus==2U &&
         cards[0].gpu_id==1 &&
         cards[0].pci_info.device_id==(legacy_first?0x1db6:0x2c02) &&
         cards[0].minor_number==0);
  assert(cards[1].valid && cards[1].pci_info.bus==0x81U &&
         cards[1].gpu_id==2 &&
         cards[1].pci_info.device_id==(legacy_first?0x2c02:0x1db6) &&
         cards[1].minor_number==1);
  assert(card_info_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         card_info_calls[HYBRID580_BACKEND_OPEN]==1);

  assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NvU32 device_mask=0,status=0xffffffffU;
  assert(!device_ids_direct(root,&device_mask,&status) && status==NV_OK &&
         device_mask==3U);
  NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS info={0};
  assert(!gpu_id_info_direct(1,root,&info,&status) && status==NV_OK &&
         info.gpuId==1 && info.gpuFlags==8U+first_backend &&
         info.deviceInstance==0);
  NvU32 first_device_instance=info.deviceInstance;
  assert(!gpu_id_info_direct(2,root,&info,&status) && status==NV_OK &&
         info.gpuId==2 && info.gpuFlags==8U+second_backend &&
         info.deviceInstance==1);
  NvU32 second_device_instance=info.deviceInstance;
  assert(!request_device_alloc(root,222,first_device_instance,root,0) &&
         device_packet.status==NV_OK);
  assert(device_alloc_calls[first_backend]==1 && device_alloc_calls[second_backend]==0 &&
         device_alloc_params[first_backend].deviceId==0);
  assert(!request_device_alloc(root,223,second_device_instance,root,0) &&
         device_packet.status==NV_OK);
  assert(device_alloc_calls[first_backend]==1 && device_alloc_calls[second_backend]==1 &&
         device_alloc_params[second_backend].deviceId==0);
  assert(device_ids_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         device_ids_calls[HYBRID580_BACKEND_OPEN]==1 &&
         gpu_id_info_calls[HYBRID580_BACKEND_LEGACY]==2 &&
         gpu_id_info_calls[HYBRID580_BACKEND_OPEN]==2);

  prepare_standard_nodes();
  for(unsigned int minor=0;minor<2;minor++) {
   unsigned int expected_backend=minor==0 ? first_backend : second_backend;
   const char *expected_bdf=expected_backend==HYBRID580_BACKEND_LEGACY ?
       legacy_bdf : open_bdf;
   gpu_owner=expected_backend;
   struct inode gpu_inode={.i_rdev=makedev(NV_MAJOR_DEVICE_NUMBER,minor)};
   struct file gpu_front={.f_op=&hybrid_front_fops,.refs=1};
   assert(!hybrid_front_open(&gpu_inode,&gpu_front) && gpu_front.private_data);
   struct hybrid_front_gpu_file *gpu_state=gpu_front.private_data;
   assert(gpu_state->backend==expected_backend &&
          !strcmp(gpu_state->bdf,expected_bdf));
   assert(!strcmp(gpu_create_bdf[expected_backend],expected_bdf));
   installed_fds[9]=get_file(&front);
   struct fake_register_fd_payload register_payload={.ctl_fd=9};
   unsigned int register_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_REGISTER_FD,
                                   struct fake_register_fd_payload);
   register_gpu_front=&gpu_front; register_control_front=&front;
   register_expected_session=((struct hybrid_front_file *)front.private_data)->sessions[expected_backend];
   register_bound_session=NULL; register_backend_control_front=NULL;
   int prior_register_calls=register_fd_calls;
   int prior_register_matches=register_fd_matches;
   assert(!gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,
                                          (unsigned long)&register_payload));
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_REGISTERED &&
          register_fd_calls==prior_register_calls+1 &&
          register_fd_matches==prior_register_matches+1 &&
          register_bound_session==register_expected_session);
   register_gpu_front=NULL; register_control_front=NULL;
   register_expected_session=NULL; register_backend_control_front=NULL;
   close_test_fd(9);
   fput(&gpu_front);
   assert(!gpu_front.private_data);
  }
  assert(gpu_ioctl_calls[HYBRID580_BACKEND_OPEN]==1 &&
         gpu_ioctl_calls[HYBRID580_BACKEND_LEGACY]==1);
  assert(gpu_create_attempts[HYBRID580_BACKEND_OPEN]==1 &&
         gpu_create_attempts[HYBRID580_BACKEND_LEGACY]==1 &&
         gpu_puts[HYBRID580_BACKEND_OPEN]==1 &&
         gpu_puts[HYBRID580_BACKEND_LEGACY]==1);
  front_put();
  assert(!front.private_data);
  assert(session_puts[HYBRID580_BACKEND_LEGACY]==created[HYBRID580_BACKEND_LEGACY] &&
         session_puts[HYBRID580_BACKEND_OPEN]==created[HYBRID580_BACKEND_OPEN]);
  hybrid580_standard_nodes_unregister_v1();
  assert(!standard_nodes_ready && standard_nodes_unregisters==1);
  return 0;
 }
 if(!strncmp(s,"attach-",7) && strcmp(s,"attach-copy-in-failure") &&
    strcmp(s,"attach-malformed")) {
  set_inventory_record(0,"0000:65:00.0",3,45,0x65);
  set_inventory_record(1,"0000:01:00.0",3,46,1);
 }
 if(!strcmp(s,"gpu-id-info-route")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  /* Both isolated RMs may number their sole GPU instance 0. The public
   * frontend IDs are BDF ordered, so Blackwell gets 0 and Volta gets 1. */
  set_inventory_record(0,"0000:81:00.0",7,5,0x81);
  set_inventory_record(1,"0000:02:00.0",7,512,2);
  gpu_id_info_device_instances[0]=gpu_id_info_device_instances[1]=0;
  device_ids_values[0]=device_ids_values[1]=1U;
  device_ids_transport[0]=device_ids_transport[1]=NV_OK;
  device_ids_embedded[0]=device_ids_embedded[1]=NV_OK;
  device_alloc_transport[0]=device_alloc_transport[1]=NV_OK;
  device_alloc_embedded[0]=device_alloc_embedded[1]=NV_OK;
  NvHandle root=p21.hObjectNew; assert(root!=0);
  NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS returned={0}; NvU32 returned_status=0xffffffffU;
  assert(!gpu_id_info_direct(1,root,&returned,&returned_status));
  assert(returned.gpuId==1 && returned.gpuFlags==9 && returned.deviceInstance==0 &&
         returned.boardId==41 && returned.numaId==61 && returned_status==NV_OK);
  assert(gpu_id_info_input_ids[1]==512 && gpu_id_info_clients[1]==root && gpu_id_info_objects[1]==root);
  assert(!gpu_id_info_xfer(2,root,&returned,&returned_status));
  assert(returned.gpuId==2 && returned.gpuFlags==8 && returned.deviceInstance==1 &&
         returned.boardId==40 && returned.numaId==60 && returned_status==NV_OK);
  assert(gpu_id_info_calls[0]==2 && gpu_id_info_calls[1]==2);
  assert(!request_device_alloc(root,222,returned.deviceInstance,root,0) &&
         device_packet.status==NV_OK);
  assert(device_alloc_calls[0]==1 && device_alloc_calls[1]==0 &&
         device_alloc_params[0].deviceId==0);
  assert(!gpu_id_info_direct(1,root,&returned,&returned_status));
  assert(returned.deviceInstance==0 && returned_status==NV_OK);
  assert(!request_device_alloc(root,223,returned.deviceInstance,root,0) &&
         device_packet.status==NV_OK);
  assert(device_alloc_calls[1]==1 && device_alloc_params[1].deviceId==0);
  gpu_id_info_embedded=NV_ERR_INVALID_ARGUMENT;
  gpu_id_info_device_instances[HYBRID580_BACKEND_OPEN]=11;
  assert(!gpu_id_info_direct(1,root,&returned,&returned_status));
  assert(returned.gpuId==1 && returned.deviceInstance==0 &&
         returned_status==NV_ERR_INVALID_ARGUMENT);
  assert(gpu_id_info_calls[0]==2 && gpu_id_info_calls[1]==4);
  gpu_id_info_embedded=NV_OK;
  assert(gpu_id_info_input_ids[0]==5 && gpu_id_info_clients[0]==root && gpu_id_info_objects[0]==root);
  front_put(); return 0;
 }
 if(!strcmp(s,"gpu-id-info-map-transport-error") ||
    !strcmp(s,"gpu-id-info-map-embedded-error") ||
    !strcmp(s,"gpu-id-info-map-device-ids-error")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  device_ids_values[HYBRID580_BACKEND_LEGACY]=1U<<10;
  device_ids_values[HYBRID580_BACKEND_OPEN]=1U<<11;
  device_ids_transport[0]=device_ids_transport[1]=NV_OK;
  device_ids_embedded[0]=device_ids_embedded[1]=NV_OK;
  if(!strcmp(s,"gpu-id-info-map-transport-error")) {
   gpu_id_info_fail_call[HYBRID580_BACKEND_OPEN]=2;
   gpu_id_info_failure_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_OPERATING_SYSTEM;
   gpu_id_info_failure_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  } else if(!strcmp(s,"gpu-id-info-map-embedded-error")) {
   gpu_id_info_fail_call[HYBRID580_BACKEND_OPEN]=2;
   gpu_id_info_failure_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
   gpu_id_info_failure_embedded[HYBRID580_BACKEND_OPEN]=NV_ERR_INVALID_STATE;
  } else {
   device_ids_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_OPERATING_SYSTEM;
  }
  NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS returned={0}; NvU32 returned_status=0xffffffffU;
  assert(gpu_id_info_direct(1,root,&returned,&returned_status)==-EINVAL);
  assert(returned.gpuId==1 && returned.deviceInstance==0);
  NvU32 expected_status=!strcmp(s,"gpu-id-info-map-embedded-error") ?
      NV_ERR_INVALID_STATE : NV_ERR_OPERATING_SYSTEM;
  assert(returned_status==expected_status);
  struct hybrid_front_root *tracked=hybrid_front_find_root(front.private_data,root);
  assert(tracked && !tracked->device_map_valid);
  device_ids_transport[0]=device_ids_transport[1]=NV_OK;
  gpu_id_info_fail_call[HYBRID580_BACKEND_OPEN]=0;
  assert(!gpu_id_info_direct(1,root,&returned,&returned_status));
  assert(returned.gpuId==1 && returned.deviceInstance==0 && returned_status==NV_OK);
  assert(tracked->device_map_valid);
  front_put(); return 0;
 }
 if(!strcmp(s,"gpu-id-info-unknown-local-instance")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  device_ids_values[HYBRID580_BACKEND_LEGACY]=1U<<10;
  device_ids_values[HYBRID580_BACKEND_OPEN]=1U<<11;
  device_ids_transport[0]=device_ids_transport[1]=NV_OK;
  device_ids_embedded[0]=device_ids_embedded[1]=NV_OK;
  NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS returned={0}; NvU32 returned_status=0xffffffffU;
  assert(!gpu_id_info_direct(1,root,&returned,&returned_status));
  assert(returned.deviceInstance==0 && returned_status==NV_OK);
  gpu_id_info_device_instances[HYBRID580_BACKEND_OPEN]=12;
  assert(gpu_id_info_direct(1,root,&returned,&returned_status)==-EINVAL);
  assert(returned.gpuId==1 && returned.deviceInstance==0 &&
         returned_status==NV_ERR_INVALID_STATE);
  front_put(); return 0;
 }
 if(!strcmp(s,"gpu-name-string-control")) {
  prepare_device_object_test();
  subdevice_alloc_transport[0]=subdevice_alloc_transport[1]=NV_OK;
  subdevice_alloc_embedded[0]=subdevice_alloc_embedded[1]=NV_OK;
  memset(gpu_name_string_calls,0,sizeof(gpu_name_string_calls));
  memset(gpu_name_string_roots,0,sizeof(gpu_name_string_roots));
  memset(gpu_name_string_subdevices,0,sizeof(gpu_name_string_subdevices));
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,222,224,0,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,223,225,0,0) && device_packet.status==NV_OK);

  NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS output={0}; NvU32 status=0xffffffffU;
  assert(!gpu_name_string_control(root,224,
      NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII,0,
      sizeof(output),false,&output,&status));
  assert(status==NV_OK && !strcmp((const char *)output.gpuNameString.ascii,"RTX 5080"));
  assert(gpu_name_string_calls[HYBRID580_BACKEND_OPEN]==1 &&
         gpu_name_string_calls[HYBRID580_BACKEND_LEGACY]==0);
  assert(gpu_name_string_roots[HYBRID580_BACKEND_OPEN]==root &&
         gpu_name_string_subdevices[HYBRID580_BACKEND_OPEN]==224 &&
         gpu_name_string_flags[HYBRID580_BACKEND_OPEN]==0 &&
         gpu_name_string_selectors[HYBRID580_BACKEND_OPEN]==
           NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII);

  memset(&output,0,sizeof(output)); status=0xffffffffU;
  assert(!gpu_name_string_control(root,225,
      NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_UNICODE,0,
      sizeof(output),true,&output,&status));
  assert(status==NV_OK && output.gpuNameString.unicode[0]=='T' &&
         output.gpuNameString.unicode[5]==' ' && output.gpuNameString.unicode[6]=='V');
  assert(gpu_name_string_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         gpu_name_string_roots[HYBRID580_BACKEND_LEGACY]==root &&
         gpu_name_string_subdevices[HYBRID580_BACKEND_LEGACY]==225 &&
         gpu_name_string_selectors[HYBRID580_BACKEND_LEGACY]==
           NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_UNICODE);

  int before_open=gpu_name_string_calls[HYBRID580_BACKEND_OPEN];
  int before_legacy=gpu_name_string_calls[HYBRID580_BACKEND_LEGACY];
  assert(gpu_name_string_control(root,225,2,0,sizeof(output),false,
                                 &output,&status)==-EINVAL &&
         status==NV_ERR_INVALID_ARGUMENT);
  assert(gpu_name_string_control(root,225,
      NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII,1,
      sizeof(output),false,&output,&status)==-ENOTTY);
  assert(gpu_name_string_control(root,225,
      NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII,0,
      sizeof(output)-1,false,&output,&status)==-ENOTTY);
  assert(gpu_name_string_calls[HYBRID580_BACKEND_OPEN]==before_open &&
         gpu_name_string_calls[HYBRID580_BACKEND_LEGACY]==before_legacy);

  from_fault_call=copy_from_user_calls+2;
  assert(gpu_name_string_control(root,224,
      NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII,0,
      sizeof(output),false,&output,&status)==-EFAULT);
  from_fault_call=0;
  assert(gpu_name_string_calls[HYBRID580_BACKEND_OPEN]==before_open &&
         gpu_name_string_calls[HYBRID580_BACKEND_LEGACY]==before_legacy);

  to_fault_call=copy_to_user_calls+1;
  assert(gpu_name_string_control(root,224,
      NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII,0,
      sizeof(output),false,&output,&status)==-EFAULT);
  to_fault_call=0;
  assert(gpu_name_string_calls[HYBRID580_BACKEND_OPEN]==before_open+1 &&
         gpu_name_string_calls[HYBRID580_BACKEND_LEGACY]==before_legacy);
  front_put(); return 0;
 }
 if(!strcmp(s,"subdevice-object-lifecycle")) {
  prepare_device_object_test();
  subdevice_alloc_transport[0]=subdevice_alloc_transport[1]=NV_OK;
  subdevice_alloc_embedded[0]=subdevice_alloc_embedded[1]=NV_OK;
  gr_tpc_mask_transport[0]=gr_tpc_mask_transport[1]=NV_OK;
  gr_tpc_mask_embedded[0]=gr_tpc_mask_embedded[1]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  object_free_embedded[0]=object_free_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,222,226,1,sizeof(NV2080_ALLOC_PARAMETERS)) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_subdevice_alloc(root,222,227,0,3) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_subdevice_alloc(root,999,228,0,0) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(subdevice_alloc_calls[HYBRID580_BACKEND_OPEN]==0 &&
         subdevice_alloc_calls[HYBRID580_BACKEND_LEGACY]==0);
  assert(!request_subdevice_alloc(root,222,224,0,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,223,225,0,sizeof(NV2080_ALLOC_PARAMETERS)) &&
         device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,222,224,0,0) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(subdevice_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         subdevice_alloc_calls[HYBRID580_BACKEND_LEGACY]==1);
  assert(subdevice_alloc_roots[HYBRID580_BACKEND_OPEN]==root &&
         subdevice_alloc_parents[HYBRID580_BACKEND_OPEN]==222 &&
         subdevice_alloc_handles[HYBRID580_BACKEND_OPEN]==224 &&
         subdevice_alloc_params[HYBRID580_BACKEND_OPEN].subDeviceId==0);
  assert(subdevice_alloc_roots[HYBRID580_BACKEND_LEGACY]==root &&
         subdevice_alloc_parents[HYBRID580_BACKEND_LEGACY]==223 &&
         subdevice_alloc_handles[HYBRID580_BACKEND_LEGACY]==225 &&
         subdevice_alloc_params[HYBRID580_BACKEND_LEGACY].subDeviceId==0);
  NV2080_CTRL_GR_GET_TPC_MASK_PARAMS params={0}; NvU32 status=0xffffffffU;
  assert(!gr_tpc_mask_direct(root,224,&params,&status) && status==NV_OK && params.tpcMask==0x101U);
  assert(gr_tpc_mask_calls[HYBRID580_BACKEND_OPEN]==1 &&
         gr_tpc_mask_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         gr_tpc_mask_clients[HYBRID580_BACKEND_OPEN]==root &&
         gr_tpc_mask_objects[HYBRID580_BACKEND_OPEN]==224 &&
         gr_tpc_mask_params[HYBRID580_BACKEND_OPEN].gpcId==1);
  assert(gr_tpc_mask_direct(root,0xdead,&params,&status)==-EINVAL &&
         status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(gr_tpc_mask_direct(root+1,224,&params,&status)==-EINVAL &&
         status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(gr_tpc_mask_malformed(root,224,NV2080_CTRL_CMD_GR_GET_TPC_MASK,1,
         sizeof(params))==-ENOTTY);
  assert(gr_tpc_mask_malformed(root,224,0xdeadbeefU,0,sizeof(params))==-ENOTTY);
  assert(gr_tpc_mask_calls[HYBRID580_BACKEND_OPEN]==1 &&
         gr_tpc_mask_calls[HYBRID580_BACKEND_LEGACY]==0);
  assert(!gr_tpc_mask_xfer(root,225,&params,&status) && status==NV_OK && params.tpcMask==0x100U);
  assert(gr_tpc_mask_calls[HYBRID580_BACKEND_OPEN]==1 &&
         gr_tpc_mask_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         gr_tpc_mask_clients[HYBRID580_BACKEND_LEGACY]==root &&
         gr_tpc_mask_objects[HYBRID580_BACKEND_LEGACY]==225 &&
         gr_tpc_mask_params[HYBRID580_BACKEND_LEGACY].gpcId==2);
  NVOS00_PARAMETERS packet={.hRoot=root,.hObjectParent=root,.hObjectOld=222};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
         packet.status==NV_ERR_INVALID_OBJECT_HANDLE && device_free_calls[1]==0);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=222,.hObjectOld=224};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
         packet.status==NV_OK && object_free_calls[1]==1 && object_free_parents[1]==222);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=223,.hObjectOld=225};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
         packet.status==NV_OK && object_free_calls[0]==1 && object_free_parents[0]==223);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=223};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=222};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
         packet.status==NV_OK && !state->root_count && !state->object_count);
  front_put(); return 0;
 }
 if(!strcmp(s,"master-object-lifecycle")) {
  prepare_device_object_test();
  subdevice_alloc_transport[0]=subdevice_alloc_transport[1]=NV_OK;
  subdevice_alloc_embedded[0]=subdevice_alloc_embedded[1]=NV_OK;
  master_alloc_transport[0]=master_alloc_transport[1]=NV_OK;
  master_alloc_embedded[0]=master_alloc_embedded[1]=NV_OK;
  master_error_intr_transport[0]=master_error_intr_transport[1]=NV_OK;
  master_error_intr_embedded[0]=master_error_intr_embedded[1]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  object_free_embedded[0]=object_free_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,222,224,0,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,223,225,0,0) && device_packet.status==NV_OK);

  NvS32 master_alloc_payload=0;
  device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=224,
    .hObjectNew=230,.hClass=GF100_SUBDEVICE_MASTER,
    .pAllocParms=(NvP64)&master_alloc_payload,.paramsSize=sizeof(master_alloc_payload),
    .flags=NVOS64_FLAGS_NONE,.status=0xffffffffU};
  assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
         device_packet.status==NV_ERR_NOT_SUPPORTED &&
         master_alloc_calls[HYBRID580_BACKEND_OPEN]==0 &&
         master_alloc_calls[HYBRID580_BACKEND_LEGACY]==0);
  device_packet.hObjectParent=999;
  device_packet.hObjectNew=231;
  assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         master_alloc_calls[HYBRID580_BACKEND_OPEN]==0 &&
         master_alloc_calls[HYBRID580_BACKEND_LEGACY]==0);
  device_packet.hObjectParent=225;
  device_packet.hObjectNew=232;
  assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
         device_packet.status==NV_OK &&
         master_alloc_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         master_alloc_calls[HYBRID580_BACKEND_OPEN]==0 &&
         master_alloc_roots[HYBRID580_BACKEND_LEGACY]==root &&
         master_alloc_parents[HYBRID580_BACKEND_LEGACY]==225 &&
         master_alloc_handles[HYBRID580_BACKEND_LEGACY]==232 &&
         master_alloc_param_values[HYBRID580_BACKEND_LEGACY]==0);

  int master_calls_before=master_alloc_calls[HYBRID580_BACKEND_LEGACY];
  device_packet.hObjectNew=233;
  assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
         device_packet.status==NV_ERR_INVALID_STATE &&
         master_alloc_calls[HYBRID580_BACKEND_LEGACY]==master_calls_before);
  device_packet.hObjectNew=234; device_packet.paramsSize=sizeof(master_alloc_payload)-1;
  assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT &&
         master_alloc_calls[HYBRID580_BACKEND_LEGACY]==master_calls_before);
  device_packet.hObjectNew=235; device_packet.paramsSize=sizeof(master_alloc_payload);
  device_packet.pAllocParms=NvP64_NULL;
  assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT &&
         master_alloc_calls[HYBRID580_BACKEND_LEGACY]==master_calls_before);
  device_packet.hObjectNew=236; device_packet.pAllocParms=(NvP64)&master_alloc_payload;
  from_fault_call=copy_from_user_calls+2;
  assert(hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet)==-EFAULT &&
         master_alloc_calls[HYBRID580_BACKEND_LEGACY]==master_calls_before);
  from_fault_call=0;

  NV90E6_CTRL_MASTER_GET_ERROR_INTR_OFFSET_MASK_PARAMS params={
    .offset=0xaaaaaaaaU,.mask=0xbbbbbbbbU,
    .eccMask=0xccccccccU,.nvlinkMask=0xddddddddU};
  NVOS54_PARAMETERS control={.hClient=root,.hObject=232,
    .cmd=NV90E6_CTRL_CMD_MASTER_GET_ERROR_INTR_OFFSET_MASK,
    .params=(NvP64)&params,.paramsSize=sizeof(params),.status=0xffffffffU};
  assert(!hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control) &&
         control.status==NV_OK && params.offset==0x1234U &&
         params.mask==0x10U && params.eccMask==0x20U &&
         params.nvlinkMask==0x40U &&
         master_error_intr_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         master_error_intr_calls[HYBRID580_BACKEND_OPEN]==0 &&
         master_error_intr_roots[HYBRID580_BACKEND_LEGACY]==root &&
         master_error_intr_objects[HYBRID580_BACKEND_LEGACY]==232 &&
         master_error_intr_params[HYBRID580_BACKEND_LEGACY].offset==0xaaaaaaaaU &&
         master_error_intr_params[HYBRID580_BACKEND_LEGACY].nvlinkMask==0xddddddddU);

  control.hObject=225; control.status=0xffffffffU;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL &&
         control.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         master_error_intr_calls[HYBRID580_BACKEND_LEGACY]==1);
  control.hObject=232; control.flags=1; control.status=0xffffffffU;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-ENOTTY &&
         master_error_intr_calls[HYBRID580_BACKEND_LEGACY]==1);
  control.flags=0; control.paramsSize=sizeof(params)-sizeof(NvU32);
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-ENOTTY &&
         master_error_intr_calls[HYBRID580_BACKEND_LEGACY]==1);

  NVOS00_PARAMETERS free_packet={.hRoot=root,.hObjectParent=225,.hObjectOld=232};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         object_free_parents[HYBRID580_BACKEND_LEGACY]==225 &&
         object_free_handles[HYBRID580_BACKEND_LEGACY]==232);
  front_put(); return 0;
 }
 if(!strcmp(s,"master-map-parent-binding")) {
  prepare_device_object_test();
  subdevice_alloc_transport[0]=subdevice_alloc_transport[1]=NV_OK;
  subdevice_alloc_embedded[0]=subdevice_alloc_embedded[1]=NV_OK;
  master_alloc_transport[0]=master_alloc_transport[1]=NV_OK;
  master_alloc_embedded[0]=master_alloc_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,223,225,0,0) && device_packet.status==NV_OK);
  NvS32 master_alloc_payload=0;
  device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=225,
    .hObjectNew=232,.hClass=GF100_SUBDEVICE_MASTER,
    .pAllocParms=(NvP64)&master_alloc_payload,
    .paramsSize=sizeof(master_alloc_payload),.flags=NVOS64_FLAGS_NONE,
    .status=0xffffffffU};
  assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
         device_packet.status==NV_OK);

  int fd=50; installed_fds[fd]=get_file(&front);
  unsigned int map_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_MAP_MEMORY,
                             nv_ioctl_nvos33_parameters_with_fd);
  nv_ioctl_nvos33_parameters_with_fd map={0};
  map.params.hClient=root; map.params.hDevice=223; map.params.hMemory=232;
  map.params.length=4096; map.params.flags=NVOS33_FLAGS_ACCESS_READ_ONLY;
  map.fd=fd;
  assert(!hybrid_front_ioctl(&front,map_cmd,(unsigned long)&map) &&
         map.params.status==NV_ERR_INVALID_ARGUMENT &&
         control_map_calls[HYBRID580_BACKEND_LEGACY]==0);

  map.params.hDevice=225; map.params.status=0xffffffffU;
  struct hybrid_front_root *root_state=
    hybrid_front_find_root(front.private_data,root);
  struct hybrid_front_rm_object *master_object=
    hybrid_front_find_object(root_state,232);
  struct hybrid_front_rm_object *subdevice_object=
    hybrid_front_find_object(root_state,225);
  NvHandle expected_subdevice_backend_parent;
  assert(root_state && master_object && subdevice_object &&
         master_object->parent_handle==225 &&
         master_object->backend_parent_handle==subdevice_object->backend_handle);
  expected_subdevice_backend_parent=subdevice_object->backend_parent_handle;
  master_object->parent_handle=223;
  assert(!hybrid_front_ioctl(&front,map_cmd,(unsigned long)&map) &&
         map.params.status==NV_ERR_INVALID_ARGUMENT &&
         control_map_calls[HYBRID580_BACKEND_LEGACY]==0);
  master_object->parent_handle=225;
  master_object->backend_parent_handle=0xdeadbeefU;
  assert(!hybrid_front_ioctl(&front,map_cmd,(unsigned long)&map) &&
         map.params.status==NV_ERR_INVALID_ARGUMENT &&
         control_map_calls[HYBRID580_BACKEND_LEGACY]==0);
  master_object->backend_parent_handle=subdevice_object->backend_handle;
  subdevice_object->backend_parent_handle=0xdeadbeefU;
  assert(!hybrid_front_ioctl(&front,map_cmd,(unsigned long)&map) &&
         map.params.status==NV_ERR_INVALID_ARGUMENT &&
         control_map_calls[HYBRID580_BACKEND_LEGACY]==0);
  subdevice_object->backend_parent_handle=expected_subdevice_backend_parent;
  assert(!hybrid_front_ioctl(&front,map_cmd,(unsigned long)&map) &&
         map.params.status==NV_OK &&
         control_map_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         control_map_clients[HYBRID580_BACKEND_LEGACY]==root &&
         control_map_devices[HYBRID580_BACKEND_LEGACY]==225 &&
         control_map_flags[HYBRID580_BACKEND_LEGACY]==
           NVOS33_FLAGS_ACCESS_READ_ONLY &&
         control_map_memories[HYBRID580_BACKEND_LEGACY]==
           master_alloc_handles[HYBRID580_BACKEND_LEGACY]);
  NVOS34_PARAMETERS unmap={.hClient=root,.hDevice=223,.hMemory=232};
  unsigned int unmap_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_UNMAP_MEMORY,
                               NVOS34_PARAMETERS);
  assert(!hybrid_front_ioctl(&front,unmap_cmd,(unsigned long)&unmap) &&
         unmap.status==NV_ERR_INVALID_ARGUMENT &&
         control_unmap_calls[HYBRID580_BACKEND_LEGACY]==0);
  unmap.hDevice=225;
  master_object->parent_handle=223;
  assert(!hybrid_front_ioctl(&front,unmap_cmd,(unsigned long)&unmap) &&
         unmap.status==NV_ERR_INVALID_ARGUMENT &&
         control_unmap_calls[HYBRID580_BACKEND_LEGACY]==0);
  master_object->parent_handle=225;
  assert(!hybrid_front_ioctl(&front,unmap_cmd,(unsigned long)&unmap) &&
         unmap.status==NV_OK &&
         control_unmap_calls[HYBRID580_BACKEND_LEGACY]==1);
  close_test_fd(fd); front_put(); assert(!front.private_data); return 0;
 }
 if(!strcmp(s,"p2p-object-lifecycle")) {
  prepare_device_object_test();
  subdevice_alloc_transport[0]=subdevice_alloc_transport[1]=NV_OK;
  subdevice_alloc_embedded[0]=subdevice_alloc_embedded[1]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  object_free_embedded[0]=object_free_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,222,224,0,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,223,225,0,0) && device_packet.status==NV_OK);
  assert(!request_p2p_alloc(root,225,250,NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1,0) &&
         device_packet.status==NV_OK);
  assert(p2p_alloc_calls==1 && p2p_alloc_parent==225 && p2p_alloc_root==root &&
         p2p_alloc_handle==250 && p2p_alloc_outer_size==0 &&
         p2p_alloc_params.flags==NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1);
  assert(!request_p2p_alloc(root,224,251,NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1,0) &&
         device_packet.status==NV_ERR_NOT_SUPPORTED && p2p_alloc_calls==1);
  assert(!request_p2p_alloc(root,225,252,0,0) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT && p2p_alloc_calls==1);
  assert(!request_p2p_alloc(root,225,253,NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1,3) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT && p2p_alloc_calls==1);
  from_fault_call=copy_from_user_calls+2;
  assert(request_p2p_alloc(root,225,254,NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1,0)==-EFAULT);
  from_fault_call=0;
  assert(p2p_alloc_calls==1);
  NVOS00_PARAMETERS free_packet={.hRoot=root,.hObjectParent=224,.hObjectOld=250};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_ERR_INVALID_OBJECT_HANDLE && object_free_calls[0]==0);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=225,.hObjectOld=250};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[0]==1 &&
         object_free_parents[0]==225 && object_free_handles[0]==250);
  front_put(); return 0;
 }
 if(!strncmp(s,"p2p-object-failure-",19)) {
  prepare_device_object_test();
  subdevice_alloc_transport[HYBRID580_BACKEND_LEGACY]=NV_OK;
  subdevice_alloc_embedded[HYBRID580_BACKEND_LEGACY]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,223,225,0,0) && device_packet.status==NV_OK);
  p2p_alloc_transport=NV_OK; p2p_alloc_embedded=NV_OK;
  p2p_alloc_override_enabled=false;
  if(!strcmp(s,"p2p-object-failure-transport"))
   p2p_alloc_transport=NV_ERR_OPERATING_SYSTEM;
  else if(!strcmp(s,"p2p-object-failure-status"))
   p2p_alloc_embedded=NV_ERR_INVALID_ARGUMENT;
  else if(!strcmp(s,"p2p-object-failure-return")) {
   p2p_alloc_override_enabled=true; p2p_alloc_return_override=0xabcdef;
  } else assert(0);
  assert(!request_p2p_alloc(root,225,250,NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1,0));
  assert(state->quarantined && state->roots->root.state==HYBRID_ROOT_QUARANTINED &&
         device_packet.status!=NV_OK && state->object_count==2 &&
         state->roots->object_count==2 && p2p_alloc_calls==1);
  p2p_alloc_transport=NV_OK; p2p_alloc_embedded=NV_OK;
  p2p_alloc_override_enabled=false;
  assert(!request_p2p_alloc(root,225,251,NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1,0) &&
         device_packet.status==NV_ERR_INVALID_STATE && p2p_alloc_calls==1);
  front_put(); return 0;
 }
 if(!strcmp(s,"p2p-control-lifecycle")) {
  NvHandle root=prepare_p2p_control_fixture();
  struct hybrid_front_file *state=front.private_data;
  NV503C_CTRL_REGISTER_VA_SPACE_PARAMS register_va={.hVASpace=445};
  NvU32 status=0xffffffffU;
  assert(!p2p_control_request(false,root,250,NV503C_CTRL_CMD_REGISTER_VA_SPACE,
      &register_va,sizeof(register_va),&status) && status==NV_OK);
  assert(register_va.hVASpace==445 && register_va.vaSpaceToken==0x76543210ULL);
  assert(p2p_control_calls[FAKE_P2P_REG_VA]==1 &&
      p2p_control_roots[FAKE_P2P_REG_VA]==root &&
      p2p_control_objects[FAKE_P2P_REG_VA]==250 &&
      p2p_register_va_params.hVASpace==445);
  struct hybrid_front_rm_object *p2p=hybrid_front_find_object(state->roots,250);
  struct hybrid_front_rm_object *va=hybrid_front_find_object(state->roots,445);
  assert(p2p && va && p2p->p2p_registration_refs==1 && va->p2p_registration_refs==1);
  NVOS00_PARAMETERS free_packet={.hRoot=root,.hObjectParent=225,.hObjectOld=250};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
      free_packet.status==NV_ERR_INVALID_OBJECT_HANDLE && !object_free_calls[0]);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=223,.hObjectOld=445};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
      free_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);

  NV503C_CTRL_REGISTER_VIDMEM_PARAMS register_memory={.hMemory=556,
      .address=0x20000,.size=0x10000,.offset=0x10000};
  assert(!p2p_control_request(true,root,250,NV503C_CTRL_CMD_REGISTER_VIDMEM,
      &register_memory,sizeof(register_memory),&status) && status==NV_OK);
  assert(register_memory.hMemory==556 && p2p_control_calls[FAKE_P2P_REG_VIDMEM]==1 &&
      p2p_control_roots[FAKE_P2P_REG_VIDMEM]==root &&
      p2p_control_objects[FAKE_P2P_REG_VIDMEM]==250 &&
      p2p_register_vidmem_params.hMemory==556 &&
      p2p_register_vidmem_params.address==0x20000 &&
      p2p_register_vidmem_params.size==0x10000 &&
      p2p_register_vidmem_params.offset==0x10000 &&
      p2p->p2p_registration_refs==2);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=223,.hObjectOld=556};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
      free_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);

  NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS unregister_va={.hVASpace=445};
  assert(!p2p_control_request(true,root,250,NV503C_CTRL_CMD_UNREGISTER_VA_SPACE,
      &unregister_va,sizeof(unregister_va),&status) && status==NV_OK);
  assert(p2p_control_calls[FAKE_P2P_UNREG_VA]==1 &&
      p2p_control_roots[FAKE_P2P_UNREG_VA]==root &&
      p2p_control_objects[FAKE_P2P_UNREG_VA]==250 &&
      p2p_unregister_va_params.hVASpace==445 &&
      p2p->p2p_registration_refs==1 && va->p2p_registration_refs==0);
  NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS unregister_memory={.hMemory=556};
  assert(!p2p_control_request(false,root,250,NV503C_CTRL_CMD_UNREGISTER_VIDMEM,
      &unregister_memory,sizeof(unregister_memory),&status) && status==NV_OK);
  assert(p2p_control_calls[FAKE_P2P_UNREG_VIDMEM]==1 &&
      p2p_control_roots[FAKE_P2P_UNREG_VIDMEM]==root &&
      p2p_control_objects[FAKE_P2P_UNREG_VIDMEM]==250 &&
      p2p_unregister_vidmem_params.hMemory==556 &&
      p2p->p2p_registration_refs==0 && va->p2p_registration_refs==0);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=225,.hObjectOld=250};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
      free_packet.status==NV_OK && object_free_calls[0]==1);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=223,.hObjectOld=556};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
      free_packet.status==NV_OK);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=223,.hObjectOld=445};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
      free_packet.status==NV_OK);
  front_put(); return 0;
 }
 if(!strcmp(s,"p2p-control-transport-failure")) {
  NvHandle root=prepare_p2p_control_fixture();
  struct hybrid_front_file *state=front.private_data;
  p2p_control_transport[FAKE_P2P_REG_VA]=NV_ERR_OPERATING_SYSTEM;
  NV503C_CTRL_REGISTER_VA_SPACE_PARAMS params={.hVASpace=445}; NvU32 status=0;
  assert(p2p_control_request(false,root,250,NV503C_CTRL_CMD_REGISTER_VA_SPACE,
      &params,sizeof(params),&status)==-EINVAL && status==NV_ERR_OPERATING_SYSTEM);
  assert(state->quarantined && state->roots->root.state==HYBRID_ROOT_ACTIVE &&
      p2p_control_calls[FAKE_P2P_REG_VA]==1);
  p2p_control_transport[FAKE_P2P_REG_VA]=NV_OK;
  assert(p2p_control_request(false,root,250,NV503C_CTRL_CMD_REGISTER_VA_SPACE,
      &params,sizeof(params),&status)==-EINVAL && status==NV_ERR_INVALID_OBJECT_HANDLE &&
      p2p_control_calls[FAKE_P2P_REG_VA]==1);
  front_put(); return 0;
 }
 if(!strcmp(s,"p2p-control-status-retry")) {
  NvHandle root=prepare_p2p_control_fixture();
  struct hybrid_front_file *state=front.private_data;
  struct hybrid_front_rm_object *p2p=hybrid_front_find_object(state->roots,250);
  struct hybrid_front_rm_object *memory=hybrid_front_find_object(state->roots,556);
  NV503C_CTRL_REGISTER_VIDMEM_PARAMS params={.hMemory=556,.address=0x20000,
      .size=0x10000,.offset=0}; NvU32 status=0;
  p2p_control_embedded[FAKE_P2P_REG_VIDMEM]=NV_ERR_INVALID_ARGUMENT;
  assert(!p2p_control_request(false,root,250,NV503C_CTRL_CMD_REGISTER_VIDMEM,
      &params,sizeof(params),&status) && status==NV_ERR_INVALID_ARGUMENT);
  assert(!state->quarantined && p2p->p2p_registration_refs==0 &&
      memory->p2p_registration_refs==0 && p2p_control_calls[FAKE_P2P_REG_VIDMEM]==1);
  p2p_control_embedded[FAKE_P2P_REG_VIDMEM]=NV_OK;
  assert(!p2p_control_request(false,root,250,NV503C_CTRL_CMD_REGISTER_VIDMEM,
      &params,sizeof(params),&status) && status==NV_OK);
  assert(p2p->p2p_registration_refs==1 && memory->p2p_registration_refs==1 &&
      p2p_control_calls[FAKE_P2P_REG_VIDMEM]==2);
  NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS unregister={.hMemory=556};
  assert(!p2p_control_request(false,root,250,NV503C_CTRL_CMD_UNREGISTER_VIDMEM,
      &unregister,sizeof(unregister),&status) && status==NV_OK &&
      p2p->p2p_registration_refs==0 && memory->p2p_registration_refs==0);
  int calls=p2p_control_calls[FAKE_P2P_REG_VIDMEM];
  params.size=0;
  assert(p2p_control_request(false,root,250,NV503C_CTRL_CMD_REGISTER_VIDMEM,
      &params,sizeof(params),&status)==-EINVAL &&
      status==NV_ERR_INVALID_ARGUMENT && p2p_control_calls[FAKE_P2P_REG_VIDMEM]==calls);
  assert(p2p_control_request(false,root,250,NV503C_CTRL_CMD_REGISTER_PID,
      &params,sizeof(params),&status)==-ENOTTY &&
      p2p_control_calls[FAKE_P2P_REG_VIDMEM]==calls);
  front_put(); return 0;
 }
 if(!strcmp(s,"p2p-control-copyout-failure")) {
  NvHandle root=prepare_p2p_control_fixture();
  struct hybrid_front_file *state=front.private_data;
  struct hybrid_front_rm_object *p2p=hybrid_front_find_object(state->roots,250);
  NV503C_CTRL_REGISTER_VA_SPACE_PARAMS params={.hVASpace=445}; NvU32 status=0;
  to_fault=1;
  assert(p2p_control_request(false,root,250,NV503C_CTRL_CMD_REGISTER_VA_SPACE,
      &params,sizeof(params),&status)==-EFAULT);
  to_fault=0;
  assert(state->quarantined && p2p->p2p_registration_refs==1 &&
      p2p_control_calls[FAKE_P2P_REG_VA]==1);
  NVOS00_PARAMETERS free_packet={.hRoot=root,.hObjectParent=225,.hObjectOld=250};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
      free_packet.status==NV_ERR_INVALID_OBJECT_HANDLE && !object_free_calls[0]);
  front_put(); return 0;
 }
 if(!strcmp(s,"binapi-control-denied")) {
  NvHandle root=prepare_p2p_control_fixture();
  binapi_alloc_transport[0]=binapi_alloc_transport[1]=NV_OK;
  binapi_alloc_embedded[0]=binapi_alloc_embedded[1]=NV_OK;
  assert(!request_binapi_alloc(root,225,260,0,sizeof(NV2081_ALLOC_PARAMETERS)) &&
         device_packet.status==NV_OK);
  unsigned char opaque_payload[992]={0};
  NVOS54_PARAMETERS control={.hClient=root,.hObject=260,.cmd=0x20810108U,
      .params=(NvP64)opaque_payload,.paramsSize=sizeof(opaque_payload),
      .status=0xffffffffU};
  int copyins=copy_from_user_calls;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-ENOTTY);
  assert(copy_from_user_calls==copyins+1 && control.status==0xffffffffU);
  nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),
      .ptr=(NvP64)&control};
  unsigned int xfer_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
  copyins=copy_from_user_calls;
  assert(hybrid_front_ioctl(&front,xfer_cmd,(unsigned long)&xfer)==-ENOTTY);
  assert(copy_from_user_calls==copyins+3 && control.status==0xffffffffU);
  for(int i=0;i<2;i++) assert(gr_tpc_mask_calls[i]==0);
  assert(p2p_control_calls[FAKE_P2P_REG_VA]==0 &&
      p2p_control_calls[FAKE_P2P_UNREG_VA]==0 &&
      p2p_control_calls[FAKE_P2P_REG_VIDMEM]==0 &&
      p2p_control_calls[FAKE_P2P_UNREG_VIDMEM]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"binapi-object-lifecycle")) {
  prepare_device_object_test();
  subdevice_alloc_transport[0]=subdevice_alloc_transport[1]=NV_OK;
  subdevice_alloc_embedded[0]=subdevice_alloc_embedded[1]=NV_OK;
  binapi_alloc_transport[0]=binapi_alloc_transport[1]=NV_OK;
  binapi_alloc_embedded[0]=binapi_alloc_embedded[1]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  object_free_embedded[0]=object_free_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,222,224,0,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,223,225,0,0) && device_packet.status==NV_OK);
  /* Stock R580/R595 traces use outer paramsSize=0 with a present optional
   * four-byte class payload. The frontend must read by class layout and stop
   * safely if that fixed-size user copy faults before backend dispatch. */
  int binapi_copy_start=copy_from_user_calls;
  from_fault_call=binapi_copy_start+2;
  long binapi_nested_copy_rc=request_binapi_alloc(root,224,237,0,0);
  from_fault_call=0;
  assert(binapi_nested_copy_rc==-EFAULT &&
         copy_from_user_calls==binapi_copy_start+2 &&
         binapi_alloc_calls[HYBRID580_BACKEND_OPEN]==0);
  assert(!request_binapi_alloc_omitted(root,224,232) && device_packet.status==NV_OK);
  assert(binapi_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         binapi_alloc_params[HYBRID580_BACKEND_OPEN].reserved==0);
  assert(!request_binapi_alloc_omitted(root,222,232) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(!request_binapi_alloc_omitted(root,999,233) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(!request_binapi_alloc(root,224,234,1,sizeof(NV2081_ALLOC_PARAMETERS)) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_binapi_alloc_missing_payload(root,224,236,
         sizeof(NV2081_ALLOC_PARAMETERS)) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_binapi_alloc(root,224,235,0,3) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_binapi_alloc(root,224,230,0,0) && device_packet.status==NV_OK);
  assert(!request_binapi_alloc(root,225,231,0,0) && device_packet.status==NV_OK);
  assert(!request_binapi_alloc(root,224,238,0,sizeof(NV2081_ALLOC_PARAMETERS)) &&
         device_packet.status==NV_OK);
  assert(!request_binapi_alloc_omitted(root,224,230) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(binapi_alloc_calls[HYBRID580_BACKEND_OPEN]==3 &&
         binapi_alloc_calls[HYBRID580_BACKEND_LEGACY]==1);
  assert(binapi_alloc_roots[HYBRID580_BACKEND_OPEN]==root &&
         binapi_alloc_parents[HYBRID580_BACKEND_OPEN]==224 &&
         binapi_alloc_handles[HYBRID580_BACKEND_OPEN]==238 &&
         binapi_alloc_params[HYBRID580_BACKEND_OPEN].reserved==0);
  assert(binapi_alloc_roots[HYBRID580_BACKEND_LEGACY]==root &&
         binapi_alloc_parents[HYBRID580_BACKEND_LEGACY]==225 &&
         binapi_alloc_handles[HYBRID580_BACKEND_LEGACY]==231 &&
         binapi_alloc_params[HYBRID580_BACKEND_LEGACY].reserved==0);
  NVOS00_PARAMETERS free_packet={.hRoot=root,.hObjectParent=224,.hObjectOld=224};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=224,.hObjectOld=232};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[HYBRID580_BACKEND_OPEN]==1 &&
         object_free_parents[HYBRID580_BACKEND_OPEN]==224 &&
         object_free_handles[HYBRID580_BACKEND_OPEN]==232);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=224,.hObjectOld=230};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[HYBRID580_BACKEND_OPEN]==2 &&
         object_free_parents[HYBRID580_BACKEND_OPEN]==224 &&
         object_free_handles[HYBRID580_BACKEND_OPEN]==230);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=224,.hObjectOld=238};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[HYBRID580_BACKEND_OPEN]==3 &&
         object_free_parents[HYBRID580_BACKEND_OPEN]==224 &&
         object_free_handles[HYBRID580_BACKEND_OPEN]==238);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=225,.hObjectOld=231};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         object_free_parents[HYBRID580_BACKEND_LEGACY]==225 &&
         object_free_handles[HYBRID580_BACKEND_LEGACY]==231);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=222,.hObjectOld=224};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) && free_packet.status==NV_OK);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=223,.hObjectOld=225};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) && free_packet.status==NV_OK);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=223};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) && free_packet.status==NV_OK);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=222};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) && free_packet.status==NV_OK);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && !((struct hybrid_front_file *)front.private_data)->object_count);
 front_put(); return 0;
 }
 if(!strcmp(s,"rusd-object-lifecycle")) {
  const NvU64 open_mask=UINT64_C(0xfedcba9876543210);
  const NvU64 legacy_mask=UINT64_C(0x8000000000000042);
  prepare_device_object_test();
  subdevice_alloc_transport[0]=subdevice_alloc_transport[1]=NV_OK;
  subdevice_alloc_embedded[0]=subdevice_alloc_embedded[1]=NV_OK;
  rusd_alloc_transport[0]=rusd_alloc_transport[1]=NV_OK;
  rusd_alloc_embedded[0]=rusd_alloc_embedded[1]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  object_free_embedded[0]=object_free_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,222,224,0,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,223,225,0,0) && device_packet.status==NV_OK);
  assert(!request_rusd_alloc_missing_payload(root,224,260,0) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_rusd_alloc_missing_payload(root,224,261,
         sizeof(NV00DE_ALLOC_PARAMETERS)) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_rusd_alloc(root,224,262,open_mask,3) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_rusd_alloc(root,222,263,open_mask,0) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(!request_rusd_alloc(root,0xdead,264,open_mask,0) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(rusd_alloc_calls[HYBRID580_BACKEND_OPEN]==0 &&
         rusd_alloc_calls[HYBRID580_BACKEND_LEGACY]==0);
  int copy_start=copy_from_user_calls;
  from_fault_call=copy_start+2;
  long copy_rc=request_rusd_alloc(root,224,265,open_mask,0);
  from_fault_call=0;
  assert(copy_rc==-EFAULT && copy_from_user_calls==copy_start+2 &&
         rusd_alloc_calls[HYBRID580_BACKEND_OPEN]==0);
  assert(!request_rusd_alloc(root,224,266,open_mask,0) &&
         device_packet.status==NV_OK);
  assert(!request_rusd_alloc(root,225,267,legacy_mask,
         sizeof(NV00DE_ALLOC_PARAMETERS)) && device_packet.status==NV_OK);
  assert(rusd_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         rusd_alloc_roots[HYBRID580_BACKEND_OPEN]==root &&
         rusd_alloc_parents[HYBRID580_BACKEND_OPEN]==224 &&
         rusd_alloc_handles[HYBRID580_BACKEND_OPEN]==266 &&
         rusd_alloc_params[HYBRID580_BACKEND_OPEN].polledDataMask==open_mask);
  assert(rusd_alloc_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         rusd_alloc_roots[HYBRID580_BACKEND_LEGACY]==root &&
         rusd_alloc_parents[HYBRID580_BACKEND_LEGACY]==225 &&
         rusd_alloc_handles[HYBRID580_BACKEND_LEGACY]==267 &&
         rusd_alloc_params[HYBRID580_BACKEND_LEGACY].polledDataMask==legacy_mask);
  struct hybrid_front_file *state=front.private_data;
  struct hybrid_front_rm_object *subdevice=hybrid_front_find_object(state->roots,224);
  struct hybrid_front_rm_object *rusd=hybrid_front_find_object(state->roots,266);
  assert(subdevice && rusd && subdevice->backend==HYBRID580_BACKEND_OPEN &&
         rusd->class_id==RM_USER_SHARED_DATA && rusd->backend==HYBRID580_BACKEND_OPEN);
  map_test_root=root; map_test_device=subdevice->handle; map_test_memory=rusd->handle;
  map_test_backend_device=subdevice->backend_handle;
  map_test_backend_memory=rusd->backend_handle;
  const int map_fd=50;
  installed_fds[map_fd]=get_file(&front);
  nv_ioctl_nvos33_parameters_with_fd map_packet={
      .params={.hClient=root,.hDevice=subdevice->handle,.hMemory=rusd->handle,
               .length=4096,.status=0xffffffffU},.fd=map_fd};
  unsigned int map_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_MAP_MEMORY,
                              nv_ioctl_nvos33_parameters_with_fd);
  assert(!hybrid_front_ioctl(&front,map_cmd,(unsigned long)&map_packet) &&
         map_packet.params.status==NV_OK && control_map_calls[HYBRID580_BACKEND_OPEN]==1 &&
         control_map_devices[HYBRID580_BACKEND_OPEN]==subdevice->backend_handle &&
         control_map_memories[HYBRID580_BACKEND_OPEN]==rusd->backend_handle &&
         control_map_target_fds[HYBRID580_BACKEND_OPEN]==map_fd);
  assert(state->pending_map_state==HYBRID_FRONT_MAP_READY &&
         control_map_context_files[HYBRID580_BACKEND_OPEN]);
  struct vm_area_struct rusd_vma={.vm_file=get_file(&front),.vm_pgoff=0,
                                  .vm_start=0x10000000,.vm_end=0x10001000};
  assert(!front.f_op->mmap(&front,&rusd_vma) &&
         rusd_vma.vm_file==control_map_context_files[HYBRID580_BACKEND_OPEN] &&
         state->pending_map_state==HYBRID_FRONT_MAP_CONSUMED);
  fput(rusd_vma.vm_file);
  NVOS34_PARAMETERS rusd_unmap={.hClient=root,.hDevice=subdevice->handle,
                                 .hMemory=rusd->handle};
  unsigned int unmap_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_UNMAP_MEMORY,
                                NVOS34_PARAMETERS);
  assert(!hybrid_front_ioctl(&front,unmap_cmd,(unsigned long)&rusd_unmap) &&
         rusd_unmap.status==NV_OK &&
         control_unmap_calls[HYBRID580_BACKEND_OPEN]==1);
  close_test_fd(map_fd);
  NVOS00_PARAMETERS free_packet={.hRoot=root,.hObjectParent=224,.hObjectOld=266};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[HYBRID580_BACKEND_OPEN]==1 &&
         object_free_parents[HYBRID580_BACKEND_OPEN]==224 &&
         object_free_handles[HYBRID580_BACKEND_OPEN]==266);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=225,.hObjectOld=267};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         object_free_parents[HYBRID580_BACKEND_LEGACY]==225 &&
         object_free_handles[HYBRID580_BACKEND_LEGACY]==267);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=222,.hObjectOld=224};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=223,.hObjectOld=225};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK &&
         !((struct hybrid_front_file *)front.private_data)->object_count);
  front_put(); return 0;
 }
 if(!strcmp(s,"usermode-object-lifecycle")) {
  prepare_device_object_test();
  subdevice_alloc_transport[0]=subdevice_alloc_transport[1]=NV_OK;
  subdevice_alloc_embedded[0]=subdevice_alloc_embedded[1]=NV_OK;
  usermode_alloc_transport[0]=usermode_alloc_transport[1]=NV_OK;
  usermode_alloc_embedded[0]=usermode_alloc_embedded[1]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  object_free_embedded[0]=object_free_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,222,224,0,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,223,225,0,0) && device_packet.status==NV_OK);
  NV_HOPPER_USERMODE_A_PARAMS hopper={.bBar1Mapping=1,.bPriv=0};
  NV_HOPPER_USERMODE_A_PARAMS invalid={.bBar1Mapping=2,.bPriv=0};
  NV_HOPPER_USERMODE_A_PARAMS privileged={.bBar1Mapping=1,.bPriv=1};
  assert(!request_usermode_alloc(root,225,240,HOPPER_USERMODE_A,&hopper,0) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(!request_usermode_alloc(root,224,241,VOLTA_USERMODE_A,&hopper,0) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(!request_usermode_alloc(root,224,242,HOPPER_USERMODE_A,&invalid,0) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_usermode_alloc(root,224,243,HOPPER_USERMODE_A,&privileged,0) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_usermode_alloc(root,224,244,HOPPER_USERMODE_A,&hopper,3) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_usermode_alloc(root,224,245,HOPPER_USERMODE_A,NULL,
         sizeof(hopper)) && device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(!request_usermode_alloc(root,225,245,VOLTA_USERMODE_A,NULL,
         sizeof(hopper)) && device_packet.status==NV_ERR_INVALID_ARGUMENT);
  assert(usermode_alloc_calls[HYBRID580_BACKEND_OPEN]==0 &&
         usermode_alloc_calls[HYBRID580_BACKEND_LEGACY]==0);
  from_fault_call=copy_from_user_calls+2;
  assert(request_usermode_alloc(root,224,245,HOPPER_USERMODE_A,&hopper,
         sizeof(hopper))==-EFAULT);
  from_fault_call=0;
  assert(usermode_alloc_calls[HYBRID580_BACKEND_OPEN]==0);
  assert(!request_usermode_alloc(root,224,246,HOPPER_USERMODE_A,&hopper,
         sizeof(hopper)) && device_packet.status==NV_OK);
  assert(usermode_alloc_has_params[HYBRID580_BACKEND_OPEN] &&
         usermode_alloc_params[HYBRID580_BACKEND_OPEN].bBar1Mapping==1 &&
         usermode_alloc_params[HYBRID580_BACKEND_OPEN].bPriv==0);
  assert(!request_usermode_alloc(root,224,247,HOPPER_USERMODE_A,NULL,0) &&
         device_packet.status==NV_OK);
  assert(!request_usermode_alloc(root,225,248,VOLTA_USERMODE_A,NULL,0) &&
         device_packet.status==NV_OK);
  assert(!request_usermode_alloc(root,225,249,VOLTA_USERMODE_A,&hopper,0) &&
         device_packet.status==NV_OK);
  assert(usermode_alloc_calls[HYBRID580_BACKEND_OPEN]==2 &&
         usermode_alloc_calls[HYBRID580_BACKEND_LEGACY]==2);
  assert(usermode_alloc_roots[HYBRID580_BACKEND_OPEN]==root &&
         usermode_alloc_parents[HYBRID580_BACKEND_OPEN]==224 &&
         usermode_alloc_handles[HYBRID580_BACKEND_OPEN]==247 &&
         usermode_alloc_classes[HYBRID580_BACKEND_OPEN]==HOPPER_USERMODE_A &&
         !usermode_alloc_has_params[HYBRID580_BACKEND_OPEN]);
  assert(usermode_alloc_parents[HYBRID580_BACKEND_LEGACY]==225 &&
         usermode_alloc_handles[HYBRID580_BACKEND_LEGACY]==249 &&
         usermode_alloc_classes[HYBRID580_BACKEND_LEGACY]==VOLTA_USERMODE_A &&
         !usermode_alloc_has_params[HYBRID580_BACKEND_LEGACY]);
  NVOS00_PARAMETERS free_packet={.hRoot=root,.hObjectParent=224,.hObjectOld=224};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=224,.hObjectOld=246};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[HYBRID580_BACKEND_OPEN]==1);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=224,.hObjectOld=247};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[HYBRID580_BACKEND_OPEN]==2);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=225,.hObjectOld=248};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[HYBRID580_BACKEND_LEGACY]==1);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=225,.hObjectOld=249};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && object_free_calls[HYBRID580_BACKEND_LEGACY]==2);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=222,.hObjectOld=224};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) && free_packet.status==NV_OK);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=223,.hObjectOld=225};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) && free_packet.status==NV_OK);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=223};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) && free_packet.status==NV_OK);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=222};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) && free_packet.status==NV_OK);
  free_packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_packet) &&
         free_packet.status==NV_OK && !((struct hybrid_front_file *)front.private_data)->object_count);
  front_put(); return 0;
 }
 if(!strncmp(s,"usermode-object-failure-",24)) {
  prepare_device_object_test();
  subdevice_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  subdevice_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  usermode_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  usermode_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,222,224,0,0) && device_packet.status==NV_OK);
  NV_HOPPER_USERMODE_A_PARAMS params={.bBar1Mapping=1,.bPriv=0};
  if(!strcmp(s,"usermode-object-failure-transport"))
   usermode_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_OPERATING_SYSTEM;
  else if(!strcmp(s,"usermode-object-failure-status"))
   usermode_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_ERR_INVALID_ARGUMENT;
  else if(!strcmp(s,"usermode-object-failure-return")) {
   usermode_alloc_override_enabled[HYBRID580_BACKEND_OPEN]=true;
   usermode_alloc_return_override[HYBRID580_BACKEND_OPEN]=0xabcdef;
  } else assert(0);
  assert(!request_usermode_alloc(root,224,230,HOPPER_USERMODE_A,&params,0));
  assert(state->quarantined && state->roots->root.state==HYBRID_ROOT_QUARANTINED &&
         device_packet.status!=NV_OK && state->object_count==2 &&
         state->roots->object_count==2 &&
         usermode_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  usermode_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  usermode_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  usermode_alloc_override_enabled[HYBRID580_BACKEND_OPEN]=false;
  assert(!request_usermode_alloc(root,224,230,HOPPER_USERMODE_A,&params,0) &&
         device_packet.status==NV_ERR_INVALID_STATE &&
         usermode_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  front_put(); return 0;
 }
 if(!strncmp(s,"binapi-object-failure-",22)) {
  prepare_device_object_test();
  subdevice_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  subdevice_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  binapi_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  binapi_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_subdevice_alloc(root,222,224,0,0) && device_packet.status==NV_OK);
  if(!strcmp(s,"binapi-object-failure-transport"))
   binapi_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_OPERATING_SYSTEM;
  else if(!strcmp(s,"binapi-object-failure-status"))
   binapi_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_ERR_INVALID_ARGUMENT;
  else if(!strcmp(s,"binapi-object-failure-return")) {
   binapi_alloc_override_enabled[HYBRID580_BACKEND_OPEN]=true;
   binapi_alloc_return_override[HYBRID580_BACKEND_OPEN]=0xabcdef;
  } else assert(0);
  assert(!request_binapi_alloc(root,224,230,0,sizeof(NV2081_ALLOC_PARAMETERS)));
  assert(state->quarantined && state->roots->root.state==HYBRID_ROOT_QUARANTINED &&
         device_packet.status!=NV_OK && state->object_count==2 &&
         state->roots->object_count==2 && binapi_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  binapi_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  binapi_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  binapi_alloc_override_enabled[HYBRID580_BACKEND_OPEN]=false;
  assert(!request_binapi_alloc(root,224,230,0,sizeof(NV2081_ALLOC_PARAMETERS)) &&
         device_packet.status==NV_ERR_INVALID_STATE &&
         binapi_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  front_put(); return 0;
 }
 if(!strncmp(s,"subdevice-object-failure-",25)) {
  prepare_device_object_test();
  subdevice_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  subdevice_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  if(!strcmp(s,"subdevice-object-failure-transport"))
   subdevice_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_OPERATING_SYSTEM;
  else if(!strcmp(s,"subdevice-object-failure-status"))
   subdevice_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_ERR_INVALID_ARGUMENT;
  else if(!strcmp(s,"subdevice-object-failure-return")) {
   subdevice_alloc_override_enabled[HYBRID580_BACKEND_OPEN]=true;
   subdevice_alloc_return_override[HYBRID580_BACKEND_OPEN]=0xabcdef;
  } else assert(0);
  assert(!request_subdevice_alloc(root,222,224,0,0));
  assert(state->quarantined && state->roots->root.state==HYBRID_ROOT_QUARANTINED &&
         device_packet.status!=NV_OK && state->object_count==1 &&
         state->roots->object_count==1 && subdevice_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  subdevice_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  subdevice_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  subdevice_alloc_override_enabled[HYBRID580_BACKEND_OPEN]=false;
  assert(!request_subdevice_alloc(root,222,224,0,0) &&
         device_packet.status==NV_ERR_INVALID_STATE &&
         subdevice_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  front_put(); return 0;
 }
 if(!strncmp(s,"device-object-",14)) {
  prepare_device_object_test();
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  struct hybrid_front_file *state=front.private_data;
  if(!strcmp(s,"device-object-map-mask-mismatch") ||
     !strcmp(s,"device-object-map-device-ids-error") ||
     !strcmp(s,"device-object-map-id-info-error")) {
   if(!strcmp(s,"device-object-map-mask-mismatch"))
    device_ids_values[HYBRID580_BACKEND_OPEN]=1U<<9;
   else if(!strcmp(s,"device-object-map-device-ids-error"))
    device_ids_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_OPERATING_SYSTEM;
   else {
    gpu_id_info_fail_call[HYBRID580_BACKEND_OPEN]=1;
    gpu_id_info_failure_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
    gpu_id_info_failure_embedded[HYBRID580_BACKEND_OPEN]=NV_ERR_INVALID_STATE;
   }
   assert(!request_device_alloc(root,318,0,root,0));
   NvU32 expected=!strcmp(s,"device-object-map-device-ids-error") ?
       NV_ERR_OPERATING_SYSTEM : NV_ERR_INVALID_STATE;
   assert(device_packet.status==expected && !state->roots->device_map_valid &&
          state->roots->root.state==HYBRID_ROOT_ACTIVE && !state->quarantined &&
          !state->object_count && !device_alloc_calls[HYBRID580_BACKEND_LEGACY] &&
          !device_alloc_calls[HYBRID580_BACKEND_OPEN]);
   device_ids_values[HYBRID580_BACKEND_OPEN]=1U<<11;
   device_ids_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
   gpu_id_info_fail_call[HYBRID580_BACKEND_OPEN]=0;
   gpu_id_info_failure_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
   assert(!request_device_alloc(root,318,0,root,0) && device_packet.status==NV_OK);
   assert(state->roots->device_map_valid && state->object_count==1 &&
          device_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
          !device_alloc_calls[HYBRID580_BACKEND_LEGACY] &&
          device_alloc_params[HYBRID580_BACKEND_OPEN].deviceId==11);
   front_put(); return 0;
  }
  if(!strcmp(s,"device-object-open-lifecycle")) {
   assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
   assert(device_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
          device_alloc_calls[HYBRID580_BACKEND_LEGACY]==0);
   assert(device_alloc_roots[HYBRID580_BACKEND_OPEN]==root &&
          device_alloc_handles[HYBRID580_BACKEND_OPEN]==222 &&
          device_alloc_params[HYBRID580_BACKEND_OPEN].deviceId==11 &&
          device_alloc_params[HYBRID580_BACKEND_OPEN].hClientShare==root &&
          device_alloc_params[HYBRID580_BACKEND_OPEN].vaSpaceSize==0x200000);
   assert(state->object_count==1 && state->roots->object_count==1 &&
          state->roots->device_map_valid);
   NVOS00_PARAMETERS packet={.hRoot=root,.hObjectParent=root,.hObjectOld=222};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
          packet.status==NV_OK);
   assert(device_free_calls[HYBRID580_BACKEND_OPEN]==1 &&
          device_free_handles[HYBRID580_BACKEND_OPEN]==222 &&
          !state->object_count && !state->roots->object_count);
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
          packet.status==NV_ERR_INVALID_OBJECT_HANDLE &&
          device_free_calls[HYBRID580_BACKEND_OPEN]==1);
   packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
          packet.status==NV_OK && state->root_count==0);
   assert(frees[0]==1 && frees[1]==1);
   front_put(); return 0;
  }
  if(!strcmp(s,"device-object-legacy-lifecycle")) {
   assert(!request_device_alloc(root,223,1,0,sizeof(NV0080_ALLOC_PARAMETERS)) &&
          device_packet.status==NV_OK);
   assert(device_alloc_calls[HYBRID580_BACKEND_LEGACY]==1 &&
          device_alloc_calls[HYBRID580_BACKEND_OPEN]==0 &&
          device_alloc_roots[HYBRID580_BACKEND_LEGACY]==root &&
          device_alloc_handles[HYBRID580_BACKEND_LEGACY]==223 &&
          device_alloc_params[HYBRID580_BACKEND_LEGACY].deviceId==10 &&
          device_alloc_params[HYBRID580_BACKEND_LEGACY].hClientShare==0);
   NVOS00_PARAMETERS packet={.hRoot=root,.hObjectParent=root,.hObjectOld=223};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
          packet.status==NV_OK && device_free_calls[HYBRID580_BACKEND_LEGACY]==1);
   packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
   front_put(); return 0;
  }
  if(!strcmp(s,"device-object-invalid")) {
   assert(!request_device_alloc(root,300,9,root,0) &&
          device_packet.status==NV_ERR_INVALID_ARGUMENT);
   assert(!request_device_alloc(root,301,0,root+1,0) &&
          device_packet.status==NV_ERR_INVALID_ARGUMENT);
   NV0080_ALLOC_PARAMETERS nested={.deviceId=0,.hTargetDevice=1};
   device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=root,
     .hObjectNew=302,.hClass=NV01_DEVICE_0,.pAllocParms=(NvP64)&nested,
     .flags=NVOS64_FLAGS_NONE};
   assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
          device_packet.status==NV_ERR_INVALID_ARGUMENT);
   assert(!request_device_alloc(root,303,0,root,57) &&
          device_packet.status==NV_ERR_INVALID_ARGUMENT);
   NVOS21_PARAMETERS narrow={.hRoot=root,.hObjectParent=root,.hObjectNew=304,
     .hClass=NV01_DEVICE_0};
   assert(!hybrid_front_ioctl(&front,alloc21_cmd,(unsigned long)&narrow) &&
          narrow.status==NV_ERR_INVALID_CLASS);
   device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=root,
     .hObjectNew=305,.hClass=NV01_DEVICE_0,.flags=NVOS64_FLAGS_NONE};
   assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
          device_packet.status==NV_ERR_INVALID_ARGUMENT);
   nested=(NV0080_ALLOC_PARAMETERS){.deviceId=0};
   device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=root,
     .hObjectNew=314,.hClass=NV01_DEVICE_0,.pAllocParms=(NvP64)&nested,
     .flags=1};
   assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
          device_packet.status==NV_ERR_INVALID_ARGUMENT);
   device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=root,
     .hObjectNew=315,.hClass=NV01_DEVICE_0,.pAllocParms=(NvP64)&nested,
     .pRightsRequested=(NvP64)1,.flags=NVOS64_FLAGS_NONE};
   assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
          device_packet.status==NV_ERR_INVALID_ARGUMENT);
   device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=root+1,
     .hObjectNew=316,.hClass=NV01_DEVICE_0,.pAllocParms=(NvP64)&nested,
     .flags=NVOS64_FLAGS_NONE};
   assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
          device_packet.status==NV_ERR_INVALID_ARGUMENT);
   device_packet=(NVOS64_PARAMETERS){.hRoot=root+1,.hObjectParent=root+1,
     .hObjectNew=317,.hClass=NV01_DEVICE_0,.pAllocParms=(NvP64)&nested,
     .flags=NVOS64_FLAGS_NONE};
   assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
          device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
   assert(!device_alloc_calls[0] && !device_alloc_calls[1] &&
          state->object_count==0);
   NVOS00_PARAMETERS packet={.hRoot=root,.hObjectOld=root};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
   front_put(); return 0;
  }
  if(!strcmp(s,"device-object-copyin-failure")) {
   copy_from_user_calls=0; from_fault_call=2;
   assert(request_device_alloc(root,306,0,root,0)==-EFAULT);
   from_fault_call=0;
   assert(!device_ids_calls[0] && !device_ids_calls[1] &&
          !device_alloc_calls[0] && !device_alloc_calls[1] &&
          state->stateful_started);
   NVOS00_PARAMETERS packet={.hRoot=root,.hObjectOld=root};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
   front_put(); return 0;
  }
  if(!strcmp(s,"device-object-copyout-failure")) {
   to_fault=1;
   assert(request_device_alloc(root,307,0,root,0)==-EFAULT);
   to_fault=0;
   assert(device_alloc_calls[1]==1 && state->object_count==1 &&
          state->roots->object_count==1);
   front_put(); assert(frees[0]==1 && frees[1]==1); return 0;
  }
  if(!strcmp(s,"device-object-root-free")) {
   assert(!request_device_alloc(root,308,0,root,0) && device_packet.status==NV_OK);
   NVOS00_PARAMETERS packet={.hRoot=root,.hObjectParent=root,.hObjectOld=root};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
          packet.status==NV_OK && state->root_count==0 &&
          state->object_count==0 && !device_free_calls[0] &&
          !device_free_calls[1]);
   assert(frees[0]==1 && frees[1]==1);
   front_put(); return 0;
  }
  if(!strcmp(s,"device-object-free-copyout-failure")) {
   assert(!request_device_alloc(root,309,0,root,0) && device_packet.status==NV_OK);
   NVOS00_PARAMETERS packet={.hRoot=root,.hObjectParent=root,.hObjectOld=309};
   to_fault=1;
   assert(hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet)==-EFAULT);
   to_fault=0;
   assert(state->object_count==0 && device_free_calls[1]==1);
   packet.status=0xffffffffU;
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
          packet.status==NV_ERR_INVALID_OBJECT_HANDLE && device_free_calls[1]==1);
   packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
   front_put(); return 0;
  }
  if(!strcmp(s,"device-object-duplicate-handle")) {
   assert(!request_device_alloc(root,310,0,root,0) && device_packet.status==NV_OK);
   assert(!request_device_alloc(root,310,1,root,0) &&
          device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE &&
          device_alloc_calls[1]==1 && device_alloc_calls[0]==0 &&
          !state->quarantined);
   NVOS00_PARAMETERS packet={.hRoot=root,.hObjectParent=root,.hObjectOld=310};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
   packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
   front_put(); return 0;
  }
  if(!strcmp(s,"device-object-capacity")) {
   for(unsigned int i=0;i<HYBRID_FRONT_MAX_DEVICE_OBJECTS;i++) {
    long alloc_rc=request_device_alloc(root,1000+i,0,root,0);
    assert(!alloc_rc && device_packet.status==NV_OK);
   }
   assert(!request_device_alloc(root,2000,0,root,0) &&
          device_packet.status==NV_ERR_INSUFFICIENT_RESOURCES &&
          device_alloc_calls[1]==HYBRID_FRONT_MAX_DEVICE_OBJECTS &&
          state->object_count==HYBRID_FRONT_MAX_DEVICE_OBJECTS);
   NVOS00_PARAMETERS packet={.hRoot=root,.hObjectOld=root};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
          packet.status==NV_OK && !state->object_count);
   front_put(); return 0;
  }
  if(!strcmp(s,"device-object-backend-transport-failure") ||
     !strcmp(s,"device-object-backend-status-failure") ||
     !strcmp(s,"device-object-return-mismatch")) {
   if(!strcmp(s,"device-object-backend-transport-failure"))
    device_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_OPERATING_SYSTEM;
   if(!strcmp(s,"device-object-backend-status-failure"))
    device_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_ERR_INVALID_STATE;
   if(!strcmp(s,"device-object-return-mismatch")) {
    device_alloc_override_enabled[HYBRID580_BACKEND_OPEN]=true;
    device_alloc_return_override[HYBRID580_BACKEND_OPEN]=999;
   }
   assert(!request_device_alloc(root,311,0,root,0));
   assert(device_packet.status!=NV_OK && state->quarantined &&
          state->roots->root.state==HYBRID_ROOT_QUARANTINED &&
          state->object_count==0 && !device_free_calls[0] &&
          !device_free_calls[1]);
   front_put(); assert(!frees[0] && !frees[1]); return 0;
  }
  if(!strcmp(s,"device-object-free-transport-failure") ||
     !strcmp(s,"device-object-free-status-failure")) {
   assert(!request_device_alloc(root,312,0,root,0) && device_packet.status==NV_OK);
   if(!strcmp(s,"device-object-free-transport-failure"))
    device_free_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_OPERATING_SYSTEM;
   else
    device_free_embedded[HYBRID580_BACKEND_OPEN]=NV_ERR_INVALID_STATE;
   NVOS00_PARAMETERS packet={.hRoot=root,.hObjectParent=root,.hObjectOld=312};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
          packet.status!=NV_OK && state->quarantined &&
          state->roots->root.state==HYBRID_ROOT_QUARANTINED &&
          state->object_count==1 && device_free_calls[1]==1);
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
          packet.status==NV_ERR_INVALID_STATE && device_free_calls[1]==1);
   front_put(); assert(!frees[0] && !frees[1]); return 0;
  }
  if(!strcmp(s,"device-object-root-handle-collision")) {
   assert(!request_device_alloc(root,313,0,root,0) && device_packet.status==NV_OK);
   next_root=313;
   long root_rc=alloc_root(false);
   assert(!root_rc && p21.status!=NV_OK && state->quarantined &&
          state->object_count==1 && calls[0]==2 && calls[1]==1);
   front_put(); return 0;
  }
  assert(!"unknown device-object scenario");
 }
 if(!strcmp(s,"vaspace-object-lifecycle")) {
  prepare_device_object_test();
  memory_alloc_transport[0]=memory_alloc_transport[1]=NV_OK;
  memory_alloc_embedded[0]=memory_alloc_embedded[1]=NV_OK;
  vaspace_alloc_transport[0]=vaspace_alloc_transport[1]=NV_OK;
  vaspace_alloc_embedded[0]=vaspace_alloc_embedded[1]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  object_free_embedded[0]=object_free_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, open_device=222, legacy_device=223;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,open_device,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,legacy_device,1,root,0) && device_packet.status==NV_OK);
  NV_VASPACE_ALLOCATION_PARAMETERS open_va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW,
    .flags=NV_VASPACE_ALLOCATION_FLAGS_ENABLE_PAGE_FAULTING,
    .bigPageSize=NV_VASPACE_BIG_PAGE_SIZE_64K,.vaSize=0x400000000ULL};
  NV_VASPACE_ALLOCATION_PARAMETERS legacy_va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW,
    .vaSize=0x200000000ULL};
  assert(!request_vaspace_alloc(root,open_device,444,&open_va) &&
         device_packet.status==NV_OK && open_va.vaBase==0x10000 &&
         open_va.vaSize==0x100000000ULL);
  assert(!request_vaspace_alloc(root,legacy_device,445,&legacy_va) &&
         device_packet.status==NV_OK && legacy_va.vaBase==0x10000);
  assert(vaspace_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         vaspace_alloc_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         vaspace_alloc_roots[HYBRID580_BACKEND_OPEN]==root &&
         vaspace_alloc_parents[HYBRID580_BACKEND_OPEN]==open_device &&
         vaspace_alloc_handles[HYBRID580_BACKEND_OPEN]==444 &&
         vaspace_alloc_params[HYBRID580_BACKEND_OPEN].index==NV_VASPACE_ALLOCATION_INDEX_GPU_NEW &&
         vaspace_alloc_params[HYBRID580_BACKEND_OPEN].flags==NV_VASPACE_ALLOCATION_FLAGS_ENABLE_PAGE_FAULTING);
  NV_MEMORY_ALLOCATION_PARAMS open_mem={.size=0x2000,.alignment=0x1000,.hVASpace=444};
  NV_MEMORY_ALLOCATION_PARAMS legacy_mem={.size=0x3000,.alignment=0x1000,.hVASpace=445};
  assert(!request_memory_alloc(root,open_device,555,NV01_MEMORY_SYSTEM,&open_mem) &&
         device_packet.status==NV_OK && memory_alloc_params[HYBRID580_BACKEND_OPEN].hVASpace==444);
  assert(!request_memory_alloc(root,legacy_device,556,NV01_MEMORY_LOCAL_USER,&legacy_mem) &&
         device_packet.status==NV_OK && memory_alloc_params[HYBRID580_BACKEND_LEGACY].hVASpace==445);
  assert(state->object_count==6 && state->roots->object_count==6);
  NVOS00_PARAMETERS packet={.hRoot=root,.hObjectParent=open_device,.hObjectOld=444};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
         packet.status==NV_ERR_INVALID_OBJECT_HANDLE && object_free_calls[1]==0);
  NV_MEMORY_ALLOCATION_PARAMS mismatch={.hVASpace=444};
  assert(!request_memory_alloc(root,legacy_device,557,NV01_MEMORY_SYSTEM,&mismatch) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         memory_alloc_calls[HYBRID580_BACKEND_LEGACY]==1);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=open_device,.hObjectOld=555};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=open_device,.hObjectOld=444};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=legacy_device,.hObjectOld=556};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=legacy_device,.hObjectOld=445};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  assert(object_free_calls[HYBRID580_BACKEND_OPEN]==2 &&
         object_free_calls[HYBRID580_BACKEND_LEGACY]==2 &&
         state->object_count==2);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=open_device};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=legacy_device};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  front_put(); return 0;
 }
 if(!strcmp(s,"vaspace-object-invalid-and-copy")) {
  prepare_device_object_test();
  vaspace_alloc_transport[0]=vaspace_alloc_transport[1]=NV_OK;
  vaspace_alloc_embedded[0]=vaspace_alloc_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, device=222;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,device,0,root,0) && device_packet.status==NV_OK);
  NV_VASPACE_ALLOCATION_PARAMETERS params={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW};
  copy_from_user_calls=0; from_fault_call=2;
  assert(request_vaspace_alloc(root,device,444,&params)==-EFAULT &&
         vaspace_alloc_calls[HYBRID580_BACKEND_OPEN]==0);
  from_fault_call=0;
  params=(NV_VASPACE_ALLOCATION_PARAMETERS){.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW,
    .flags=NV_VASPACE_ALLOCATION_FLAGS_SHARED_MANAGEMENT};
  assert(!request_vaspace_alloc(root,device,444,&params) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT &&
         vaspace_alloc_calls[HYBRID580_BACKEND_OPEN]==0);
  params=(NV_VASPACE_ALLOCATION_PARAMETERS){.index=NV_VASPACE_ALLOCATION_INDEX_GPU_MAX};
  assert(!request_vaspace_alloc(root,device,444,&params) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT &&
         vaspace_alloc_calls[HYBRID580_BACKEND_OPEN]==0);
  params=(NV_VASPACE_ALLOCATION_PARAMETERS){.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW};
  to_fault=1;
  assert(request_vaspace_alloc(root,device,444,&params)==-EFAULT &&
         vaspace_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         state->object_count==2 && state->roots->object_count==2);
  to_fault=0;
  assert(frees[0]==0 && frees[1]==0);
  front_put(); assert(frees[0]==1 && frees[1]==1); return 0;
 }
 if(!strcmp(s,"channel-group-vaspace-notifier-lifetime")) {
  prepare_device_object_test();
  memory_alloc_transport[0]=memory_alloc_transport[1]=NV_OK;
  memory_alloc_embedded[0]=memory_alloc_embedded[1]=NV_OK;
  vaspace_alloc_transport[0]=vaspace_alloc_transport[1]=NV_OK;
  vaspace_alloc_embedded[0]=vaspace_alloc_embedded[1]=NV_OK;
  channel_group_alloc_transport[0]=channel_group_alloc_transport[1]=NV_OK;
  channel_group_alloc_embedded[0]=channel_group_alloc_embedded[1]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  object_free_embedded[0]=object_free_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, open_device=222, legacy_device=223;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,open_device,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,legacy_device,1,root,0) && device_packet.status==NV_OK);
  NV_VASPACE_ALLOCATION_PARAMETERS open_va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW};
  NV_VASPACE_ALLOCATION_PARAMETERS legacy_va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW};
  assert(!request_vaspace_alloc(root,open_device,444,&open_va) && device_packet.status==NV_OK);
  assert(!request_vaspace_alloc(root,legacy_device,445,&legacy_va) && device_packet.status==NV_OK);
  NV_MEMORY_ALLOCATION_PARAMS open_error={.size=64,.hVASpace=444};
  NV_MEMORY_ALLOCATION_PARAMS legacy_error={.size=64,.hVASpace=445};
  assert(!request_memory_alloc(root,open_device,555,NV01_MEMORY_SYSTEM,&open_error) &&
         device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,legacy_device,556,NV01_MEMORY_LOCAL_USER,&legacy_error) &&
         device_packet.status==NV_OK);
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS open_group={.hObjectError=555,.hVASpace=444,
      .engineType=1,.bIsCallingContextVgpuPlugin=NV_FALSE};
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS legacy_group={.hObjectEccError=556,.hVASpace=445,
      .engineType=2,.bIsCallingContextVgpuPlugin=NV_FALSE};
  assert(!request_channel_group_alloc(root,open_device,666,&open_group) && device_packet.status==NV_OK);
  assert(!request_channel_group_alloc(root,legacy_device,667,&legacy_group) && device_packet.status==NV_OK);
  NV_CTXSHARE_ALLOCATION_PARAMETERS open_share={.hVASpace=444,
      .flags=NV_CTXSHARE_ALLOCATION_FLAGS_SUBCONTEXT_ASYNC};
  NV_CTXSHARE_ALLOCATION_PARAMETERS legacy_share={.hVASpace=445,
      .flags=NV_CTXSHARE_ALLOCATION_FLAGS_SUBCONTEXT_SPECIFIED,.subctxId=7};
  assert(!request_context_share_alloc(root,666,668,&open_share) && device_packet.status==NV_OK);
  assert(!request_context_share_alloc(root,667,669,&legacy_share) && device_packet.status==NV_OK);
  assert(open_group.hVASpace==444 && open_group.hObjectError==555 && open_group.engineType==0x56);
  assert(legacy_group.hVASpace==445 && legacy_group.hObjectEccError==556 && legacy_group.engineType==0x55);
  assert(open_share.hVASpace==444 && open_share.flags==NV_CTXSHARE_ALLOCATION_FLAGS_SUBCONTEXT_ASYNC &&
         open_share.subctxId==0x16 && legacy_share.hVASpace==445 && legacy_share.subctxId==0x15);
  assert(context_share_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         context_share_alloc_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         context_share_alloc_roots[HYBRID580_BACKEND_OPEN]==root &&
         context_share_alloc_parents[HYBRID580_BACKEND_OPEN]==666 &&
         context_share_alloc_handles[HYBRID580_BACKEND_OPEN]==668 &&
         context_share_alloc_params[HYBRID580_BACKEND_OPEN].hVASpace==444 &&
         context_share_alloc_params[HYBRID580_BACKEND_OPEN].flags==NV_CTXSHARE_ALLOCATION_FLAGS_SUBCONTEXT_ASYNC &&
         context_share_alloc_parents[HYBRID580_BACKEND_LEGACY]==667 &&
         context_share_alloc_params[HYBRID580_BACKEND_LEGACY].hVASpace==445 &&
         context_share_alloc_params[HYBRID580_BACKEND_LEGACY].subctxId==7);
  assert(channel_group_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         channel_group_alloc_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         channel_group_alloc_roots[HYBRID580_BACKEND_OPEN]==root &&
         channel_group_alloc_parents[HYBRID580_BACKEND_OPEN]==open_device &&
         channel_group_alloc_handles[HYBRID580_BACKEND_OPEN]==666 &&
         channel_group_alloc_params[HYBRID580_BACKEND_OPEN].hVASpace==444 &&
         channel_group_alloc_params[HYBRID580_BACKEND_OPEN].hObjectError==555 &&
         channel_group_alloc_params[HYBRID580_BACKEND_LEGACY].hVASpace==445 &&
         channel_group_alloc_params[HYBRID580_BACKEND_LEGACY].hObjectEccError==556);
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS wrong_va={.hVASpace=444,.engineType=1};
  assert(!request_channel_group_alloc(root,legacy_device,668,&wrong_va) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         channel_group_alloc_calls[HYBRID580_BACKEND_LEGACY]==1);
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS wrong_notifier={.hVASpace=445,.hObjectError=555,.engineType=1};
  assert(!request_channel_group_alloc(root,legacy_device,669,&wrong_notifier) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         channel_group_alloc_calls[HYBRID580_BACKEND_LEGACY]==1);
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS vgpu_plugin={.hVASpace=444,.engineType=1,
      .bIsCallingContextVgpuPlugin=NV_TRUE};
  assert(!request_channel_group_alloc(root,open_device,670,&vgpu_plugin) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT &&
         channel_group_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  NV_CTXSHARE_ALLOCATION_PARAMETERS wrong_context_va={.hVASpace=445};
  assert(!request_context_share_alloc(root,666,671,&wrong_context_va) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         context_share_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  NV_CTXSHARE_ALLOCATION_PARAMETERS invalid_context_flags={.hVASpace=444,.flags=4};
  assert(!request_context_share_alloc(root,666,672,&invalid_context_flags) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT &&
         context_share_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  NV_CTXSHARE_ALLOCATION_PARAMETERS invalid_context_id={.hVASpace=444,.subctxId=1};
  assert(!request_context_share_alloc(root,666,673,&invalid_context_id) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT &&
         context_share_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  NVOS00_PARAMETERS free={.hRoot=root,.hObjectParent=open_device,.hObjectOld=444};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_ERR_INVALID_OBJECT_HANDLE && object_free_calls[HYBRID580_BACKEND_OPEN]==0);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=open_device,.hObjectOld=555};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_ERR_INVALID_OBJECT_HANDLE && object_free_calls[HYBRID580_BACKEND_OPEN]==0);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=open_device,.hObjectOld=666};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_ERR_INVALID_OBJECT_HANDLE && object_free_calls[HYBRID580_BACKEND_OPEN]==0);
  /* Two devices, VASpaces, memory objects, channel groups, and context shares. */
  assert(state->object_count==10 && state->roots->object_count==10);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=666,.hObjectOld=668};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) && free.status==NV_OK);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=667,.hObjectOld=669};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) && free.status==NV_OK);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=open_device,.hObjectOld=666};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) && free.status==NV_OK);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=legacy_device,.hObjectOld=667};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) && free.status==NV_OK);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=open_device,.hObjectOld=555};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) && free.status==NV_OK);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=open_device,.hObjectOld=444};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) && free.status==NV_OK);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=legacy_device,.hObjectOld=556};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) && free.status==NV_OK);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=legacy_device,.hObjectOld=445};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) && free.status==NV_OK);
  assert(object_free_calls[HYBRID580_BACKEND_OPEN]==4 &&
         object_free_calls[HYBRID580_BACKEND_LEGACY]==4 && state->object_count==2);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=open_device};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) && free.status==NV_OK);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=legacy_device};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) && free.status==NV_OK);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) && free.status==NV_OK);
  front_put(); return 0;
 }
 if(!strcmp(s,"channel-object-reference-routing")) {
  prepare_device_object_test();
  for(int backend=0;backend<2;backend++) {
   memory_alloc_transport[backend]=NV_OK;
   memory_alloc_embedded[backend]=NV_OK;
   vaspace_alloc_transport[backend]=NV_OK;
   vaspace_alloc_embedded[backend]=NV_OK;
   channel_group_alloc_transport[backend]=NV_OK;
   channel_group_alloc_embedded[backend]=NV_OK;
   context_share_alloc_transport[backend]=NV_OK;
   context_share_alloc_embedded[backend]=NV_OK;
   channel_alloc_transport[backend]=NV_OK;
   channel_alloc_embedded[backend]=NV_OK;
   object_free_transport[backend]=NV_OK;
   object_free_embedded[backend]=NV_OK;
  }
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, open_device=222, legacy_device=223;
  assert(!request_device_alloc(root,open_device,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,legacy_device,1,root,0) && device_packet.status==NV_OK);
  NV_VASPACE_ALLOCATION_PARAMETERS open_va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW};
  NV_VASPACE_ALLOCATION_PARAMETERS legacy_va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW};
  assert(!request_vaspace_alloc(root,open_device,444,&open_va) && device_packet.status==NV_OK);
  assert(!request_vaspace_alloc(root,legacy_device,445,&legacy_va) && device_packet.status==NV_OK);
  NV_MEMORY_ALLOCATION_PARAMS open_error={.size=64,.hVASpace=444};
  NV_MEMORY_ALLOCATION_PARAMS open_buffer={.size=4096,.hVASpace=444};
  NV_MEMORY_ALLOCATION_PARAMS open_userd={.size=4096,.hVASpace=444};
  NV_MEMORY_ALLOCATION_PARAMS legacy_error={.size=64,.hVASpace=445};
  NV_MEMORY_ALLOCATION_PARAMS legacy_buffer={.size=4096,.hVASpace=445};
  NV_MEMORY_ALLOCATION_PARAMS legacy_userd={.size=4096,.hVASpace=445};
  assert(!request_memory_alloc(root,open_device,555,NV01_MEMORY_SYSTEM,&open_error) && device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,open_device,556,NV01_MEMORY_LOCAL_USER,&open_buffer) && device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,open_device,557,NV01_MEMORY_LOCAL_USER,&open_userd) && device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,legacy_device,558,NV01_MEMORY_SYSTEM,&legacy_error) && device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,legacy_device,559,NV01_MEMORY_LOCAL_USER,&legacy_buffer) && device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,legacy_device,560,NV01_MEMORY_LOCAL_USER,&legacy_userd) && device_packet.status==NV_OK);
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS open_group={.hObjectError=555,.hVASpace=444,.engineType=1};
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS legacy_group={.hObjectEccError=558,.hVASpace=445,.engineType=1};
  assert(!request_channel_group_alloc(root,open_device,666,&open_group) && device_packet.status==NV_OK);
  assert(!request_channel_group_alloc(root,legacy_device,667,&legacy_group) && device_packet.status==NV_OK);
  NV_CTXSHARE_ALLOCATION_PARAMETERS open_share={.hVASpace=444};
  assert(!request_context_share_alloc(root,666,668,&open_share) && device_packet.status==NV_OK);
  NV_CHANNEL_ALLOC_PARAMS open_channel={.hObjectError=555,.hObjectBuffer=556,
    .gpFifoOffset=0x1000,.gpFifoEntries=256,.hContextShare=668,
    .hUserdMemory={557},.userdOffset={0x80},.engineType=1,.subDeviceId=1};
  NV_CHANNEL_ALLOC_PARAMS legacy_channel={.hObjectError=558,.hObjectBuffer=559,
    .gpFifoOffset=0x2000,.gpFifoEntries=512,.hUserdMemory={560},
    .userdOffset={0x100},.engineType=2,.subDeviceId=1};
  NV_CHANNEL_ALLOC_PARAMS unsupported_channel=open_channel;
  unsupported_channel.flags=1U<<3; /* SKIP_MAP_REFCOUNTING is not yet routed. */
  assert(!request_channel_alloc(root,666,697,BLACKWELL_CHANNEL_GPFIFO_A,
                                &unsupported_channel) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT &&
         channel_alloc_calls[HYBRID580_BACKEND_OPEN]==0);
  open_channel.flags=1U<<4; /* observed GROUP_CHANNEL_RUNQUEUE=ONE */
  assert(!request_channel_alloc(root,666,698,VOLTA_CHANNEL_GPFIFO_A,&open_channel) &&
         device_packet.status==NV_ERR_INVALID_CLASS &&
         channel_alloc_calls[HYBRID580_BACKEND_OPEN]==0);
  assert(!request_channel_alloc(root,667,699,BLACKWELL_CHANNEL_GPFIFO_A,&legacy_channel) &&
         device_packet.status==NV_ERR_INVALID_CLASS &&
         channel_alloc_calls[HYBRID580_BACKEND_LEGACY]==0);
  assert(!request_channel_alloc(root,666,700,BLACKWELL_CHANNEL_GPFIFO_A,&open_channel) &&
         device_packet.status==NV_OK);
  assert(!request_channel_alloc(root,667,701,VOLTA_CHANNEL_GPFIFO_A,&legacy_channel) &&
         device_packet.status==NV_OK);
  assert(channel_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         channel_alloc_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         channel_alloc_roots[HYBRID580_BACKEND_OPEN]==root &&
         channel_alloc_parents[HYBRID580_BACKEND_OPEN]==666 &&
         channel_alloc_classes[HYBRID580_BACKEND_OPEN]==BLACKWELL_CHANNEL_GPFIFO_A &&
         channel_alloc_parents[HYBRID580_BACKEND_LEGACY]==667 &&
         channel_alloc_classes[HYBRID580_BACKEND_LEGACY]==VOLTA_CHANNEL_GPFIFO_A);
  assert(channel_alloc_params[HYBRID580_BACKEND_OPEN].hObjectError==555 &&
         channel_alloc_params[HYBRID580_BACKEND_OPEN].hObjectBuffer==556 &&
         channel_alloc_params[HYBRID580_BACKEND_OPEN].hContextShare==668 &&
         channel_alloc_params[HYBRID580_BACKEND_OPEN].hUserdMemory[0]==557 &&
         channel_alloc_params[HYBRID580_BACKEND_OPEN].hVASpace==0 &&
         channel_alloc_params[HYBRID580_BACKEND_OPEN].gpFifoOffset==0x1000 &&
         channel_alloc_params[HYBRID580_BACKEND_OPEN].flags==(1U<<4) &&
         channel_alloc_params[HYBRID580_BACKEND_OPEN].userdOffset[0]==0x80 &&
         channel_alloc_params[HYBRID580_BACKEND_LEGACY].hObjectError==558 &&
         channel_alloc_params[HYBRID580_BACKEND_LEGACY].hObjectBuffer==559 &&
         channel_alloc_params[HYBRID580_BACKEND_LEGACY].hUserdMemory[0]==560 &&
         channel_alloc_params[HYBRID580_BACKEND_LEGACY].gpFifoOffset==0x2000);
  assert(open_channel.cid==0xc002 && legacy_channel.cid==0xc001 &&
         open_channel.hObjectError==555 && open_channel.hObjectBuffer==556 &&
         open_channel.hContextShare==668 && open_channel.hUserdMemory[0]==557 &&
         legacy_channel.hObjectError==558 && legacy_channel.hObjectBuffer==559 &&
         legacy_channel.hUserdMemory[0]==560);
  unsigned int mapping_command=_IOWR(NV_IOCTL_MAGIC,
      NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO,NVOS56_PARAMETERS);
  NVOS56_PARAMETERS open_mapping={.hClient=root,.hDevice=open_device,
      .hMemory=700,.pOldCpuAddress=(NvP64)(uintptr_t)0x70001000,
      .pNewCpuAddress=(NvP64)(uintptr_t)0x70002000,.status=0xffffffffU};
  assert(!hybrid_front_ioctl(&front,mapping_command,
                             (unsigned long)&open_mapping) &&
         open_mapping.status==NV_OK &&
         mapping_update_calls[HYBRID580_BACKEND_OPEN]==1 &&
         mapping_update_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         mapping_update_packets[HYBRID580_BACKEND_OPEN].hMemory==700);
  NVOS56_PARAMETERS legacy_mapping={.hClient=root,.hDevice=legacy_device,
      .hMemory=701,.pOldCpuAddress=(NvP64)(uintptr_t)0x70101000,
      .pNewCpuAddress=(NvP64)(uintptr_t)0x70102000,.status=0xffffffffU};
  assert(!hybrid_front_ioctl(&front,mapping_command,
                             (unsigned long)&legacy_mapping) &&
         legacy_mapping.status==NV_OK &&
         mapping_update_calls[HYBRID580_BACKEND_OPEN]==1 &&
         mapping_update_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         mapping_update_packets[HYBRID580_BACKEND_LEGACY].hMemory==701);
  NVOS00_PARAMETERS packet={.hRoot=root,.hObjectParent=222,.hObjectOld=666};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
         packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=666,.hObjectOld=668};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
         packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=222,.hObjectOld=555};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
         packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=222,.hObjectOld=556};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
         packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=222,.hObjectOld=557};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
         packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  front_put(); assert(frees[0]==1 && frees[1]==1); return 0;
 }
 if(!strcmp(s,"channel-group-copyout-failure")) {
  prepare_device_object_test();
  vaspace_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  channel_group_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, device=222;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,device,0,root,0) && device_packet.status==NV_OK);
  NV_VASPACE_ALLOCATION_PARAMETERS va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW};
  assert(!request_vaspace_alloc(root,device,444,&va) && device_packet.status==NV_OK);
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS group={.hVASpace=444,.engineType=1};
  to_fault=1;
  assert(request_channel_group_alloc(root,device,666,&group)==-EFAULT &&
         channel_group_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         state->object_count==3 && state->roots->object_count==3);
  to_fault=0; front_put(); assert(frees[0]==1 && frees[1]==1); return 0;
 }
 if(!strcmp(s,"channel-object-copyout-failure")) {
  prepare_device_object_test();
  vaspace_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  channel_group_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  channel_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  int allocation_baseline=live_model_allocs;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, device=222;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,device,0,root,0) && device_packet.status==NV_OK);
  NV_VASPACE_ALLOCATION_PARAMETERS va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW};
  assert(!request_vaspace_alloc(root,device,444,&va) && device_packet.status==NV_OK);
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS group={.hVASpace=444,.engineType=1};
  assert(!request_channel_group_alloc(root,device,666,&group) && device_packet.status==NV_OK);
  NV_CHANNEL_ALLOC_PARAMS channel={.flags=NVOS04_FLAGS_CHANNEL_TYPE_PHYSICAL,
      .gpFifoOffset=0x4000};
  int before_channel_alloc=live_model_allocs;
  fail_alloc_at=alloc_calls+1;
  assert(request_channel_alloc(root,666,700,BLACKWELL_CHANNEL_GPFIFO_A,&channel)==-ENOMEM &&
         channel_alloc_calls[HYBRID580_BACKEND_OPEN]==0 &&
         state->object_count==3 && live_model_allocs==before_channel_alloc);
  fail_alloc_at=0; to_fault=1;
  assert(request_channel_alloc(root,666,700,BLACKWELL_CHANNEL_GPFIFO_A,&channel)==-EFAULT &&
         channel_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         state->object_count==4 && state->roots->object_count==4 &&
         live_model_allocs==before_channel_alloc+1);
  to_fault=0; front_put();
  assert(frees[0]==1 && frees[1]==1 && live_model_allocs==allocation_baseline);
  return 0;
 }
 if(!strcmp(s,"engine-object-allocation-routing")) {
  prepare_device_object_test();
  for(int backend=0;backend<2;backend++) {
   vaspace_alloc_transport[backend]=NV_OK;
   channel_group_alloc_transport[backend]=NV_OK;
   channel_alloc_transport[backend]=NV_OK;
   object_free_transport[backend]=NV_OK;
   engine_alloc_transport[backend]=NV_OK;
   engine_alloc_embedded[backend]=NV_OK;
  }
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, open_device=222, legacy_device=223;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,open_device,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,legacy_device,1,root,0) && device_packet.status==NV_OK);
  NV_VASPACE_ALLOCATION_PARAMETERS open_va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW};
  NV_VASPACE_ALLOCATION_PARAMETERS legacy_va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW};
  assert(!request_vaspace_alloc(root,open_device,444,&open_va) && device_packet.status==NV_OK);
  assert(!request_vaspace_alloc(root,legacy_device,445,&legacy_va) && device_packet.status==NV_OK);
  NV_MEMORY_ALLOCATION_PARAMS open_error={.size=64,.hVASpace=444};
  NV_MEMORY_ALLOCATION_PARAMS open_buffer={.size=4096,.hVASpace=444};
  NV_MEMORY_ALLOCATION_PARAMS open_userd={.size=4096,.hVASpace=444};
  NV_MEMORY_ALLOCATION_PARAMS legacy_error={.size=64,.hVASpace=445};
  NV_MEMORY_ALLOCATION_PARAMS legacy_buffer={.size=4096,.hVASpace=445};
  NV_MEMORY_ALLOCATION_PARAMS legacy_userd={.size=4096,.hVASpace=445};
  assert(!request_memory_alloc(root,open_device,555,NV01_MEMORY_SYSTEM,&open_error) && device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,open_device,556,NV01_MEMORY_LOCAL_USER,&open_buffer) && device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,open_device,557,NV01_MEMORY_LOCAL_USER,&open_userd) && device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,legacy_device,558,NV01_MEMORY_SYSTEM,&legacy_error) && device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,legacy_device,559,NV01_MEMORY_LOCAL_USER,&legacy_buffer) && device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,legacy_device,560,NV01_MEMORY_LOCAL_USER,&legacy_userd) && device_packet.status==NV_OK);
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS open_group={.hObjectError=555,.hVASpace=444,.engineType=1};
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS legacy_group={.hObjectEccError=558,.hVASpace=445,.engineType=1};
  assert(!request_channel_group_alloc(root,open_device,666,&open_group) && device_packet.status==NV_OK);
  assert(!request_channel_group_alloc(root,legacy_device,667,&legacy_group) && device_packet.status==NV_OK);
  NV_CTXSHARE_ALLOCATION_PARAMETERS open_share={.hVASpace=444};
  assert(!request_context_share_alloc(root,666,668,&open_share) && device_packet.status==NV_OK);
  NV_CHANNEL_ALLOC_PARAMS open_channel={.hObjectError=555,.hObjectBuffer=556,
      .gpFifoOffset=0x1000,.gpFifoEntries=256,.hContextShare=668,
      .hUserdMemory={557},.userdOffset={0x80},.engineType=1,.subDeviceId=1};
  NV_CHANNEL_ALLOC_PARAMS legacy_channel={.hObjectError=558,.hObjectBuffer=559,
      .gpFifoOffset=0x2000,.gpFifoEntries=512,.hUserdMemory={560},
      .userdOffset={0x100},.engineType=2,.subDeviceId=1};
  open_channel.flags=1U<<4;
  assert(!request_channel_alloc(root,666,700,BLACKWELL_CHANNEL_GPFIFO_A,&open_channel) &&
         device_packet.status==NV_OK);
  assert(!request_channel_alloc(root,667,701,VOLTA_CHANNEL_GPFIFO_A,&legacy_channel) &&
         device_packet.status==NV_OK);
  /* The installed trace has paramsSize=0 and a non-null payload pointer. Do
   * not dereference that pointer when routing these optional-parameter classes. */
  NvP64 ignored=(NvP64)(uintptr_t)1;
  assert(!request_engine_alloc(root,700,710,BLACKWELL_COMPUTE_B,ignored,0) &&
         device_packet.status==NV_OK);
  assert(!request_engine_alloc(root,700,711,BLACKWELL_DMA_COPY_B,ignored,0) &&
         device_packet.status==NV_OK);
  assert(!request_engine_alloc(root,701,712,VOLTA_COMPUTE_A,ignored,0) &&
         device_packet.status==NV_OK);
  assert(!request_engine_alloc(root,701,713,VOLTA_DMA_COPY_A,ignored,0) &&
         device_packet.status==NV_OK);
  assert(engine_alloc_calls[HYBRID580_BACKEND_OPEN]==2 &&
         engine_alloc_calls[HYBRID580_BACKEND_LEGACY]==2 &&
         engine_alloc_roots[HYBRID580_BACKEND_OPEN]==root &&
         engine_alloc_parents[HYBRID580_BACKEND_OPEN]==700 &&
         engine_alloc_classes[HYBRID580_BACKEND_OPEN]==BLACKWELL_DMA_COPY_B &&
         engine_alloc_parents[HYBRID580_BACKEND_LEGACY]==701 &&
         engine_alloc_classes[HYBRID580_BACKEND_LEGACY]==VOLTA_DMA_COPY_A);
  NV83DE_ALLOC_PARAMETERS debugger_params={.hDebuggerClient_Obsolete=0,
      .hAppClient=root,.hClass3dObject=710};
  NvU32 objects_before_debugger=state->object_count;
  device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=open_device,
      .hObjectNew=718,.hClass=GT200_DEBUGGER,
      .pAllocParms=(NvP64)&debugger_params,.paramsSize=sizeof(debugger_params),
      .flags=NVOS64_FLAGS_NONE};
  assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
         device_packet.status==NV_ERR_NOT_SUPPORTED &&
         state->object_count==objects_before_debugger &&
         debugger_alloc_calls[HYBRID580_BACKEND_OPEN]==0 && !state->quarantined &&
         engine_alloc_calls[HYBRID580_BACKEND_OPEN]==2 &&
         engine_alloc_calls[HYBRID580_BACKEND_LEGACY]==2 &&
         debugger_params.hDebuggerClient_Obsolete==0 &&
         debugger_params.hAppClient==root &&
         debugger_params.hClass3dObject==710);
  debugger_params.hClass3dObject=712;
  device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=legacy_device,
      .hObjectNew=720,.hClass=GT200_DEBUGGER,
      .pAllocParms=(NvP64)&debugger_params,.paramsSize=sizeof(debugger_params),
      .flags=NVOS64_FLAGS_NONE};
  assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
         device_packet.status==NV_OK &&
         debugger_alloc_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         debugger_alloc_roots[HYBRID580_BACKEND_LEGACY]==root &&
         debugger_alloc_parents[HYBRID580_BACKEND_LEGACY]==legacy_device &&
         debugger_alloc_handles[HYBRID580_BACKEND_LEGACY]==720 &&
         debugger_alloc_params[HYBRID580_BACKEND_LEGACY].hClass3dObject==712 &&
         state->object_count==objects_before_debugger+1);
  debugger_params.hClass3dObject=710;
  /* Bad user memory is rejected before any backend call or ownership change. */
  device_packet.hObjectNew=719;
  device_packet.pAllocParms=(NvP64)(uintptr_t)1;
  from_fault=1;
  assert(hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet)==-EFAULT &&
         debugger_alloc_calls[HYBRID580_BACKEND_OPEN]==0 &&
         state->object_count==objects_before_debugger+1);
  from_fault=0;
  device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=legacy_device,
      .hObjectNew=719,.hClass=GT200_DEBUGGER,
      .pAllocParms=(NvP64)&debugger_params,.paramsSize=sizeof(debugger_params),
      .flags=NVOS64_FLAGS_NONE};
  long cross_debugger_rc=hybrid_front_ioctl(&front,alloc64_cmd,
      (unsigned long)&device_packet);
  assert(!cross_debugger_rc);
  assert(device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(debugger_alloc_calls[HYBRID580_BACKEND_LEGACY]==1);
  assert(state->object_count==objects_before_debugger+1);
  NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS mask_params={
      .exceptionMask=NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_TRAP |
                     NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PREEMPTION_STARTED};
  NVOS54_PARAMETERS debugger_control={.hClient=root,.hObject=718,
      .cmd=NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK,
      .params=(NvP64)&mask_params,.paramsSize=sizeof(mask_params),
      .flags=NVOS54_FLAGS_NONE,.status=0xffffffffU};
  assert(hybrid_front_ioctl(&front,rm_control_cmd,
             (unsigned long)&debugger_control)==-EINVAL &&
         debugger_control.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_OPEN]==0);
  debugger_control.hObject=720;
  assert(!hybrid_front_ioctl(&front,rm_control_cmd,
             (unsigned long)&debugger_control) &&
         debugger_control.status==NV_OK &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         debugger_control_clients[HYBRID580_BACKEND_LEGACY]==root &&
         debugger_control_objects[HYBRID580_BACKEND_LEGACY]==720 &&
         debugger_control_params[HYBRID580_BACKEND_LEGACY].exceptionMask==
             mask_params.exceptionMask);
  /* A backend RM rejection is an ioctl-success/RM-status-failure. Preserve
   * that status for CUDA's caller without quarantining an otherwise healthy
   * root; the source-predicted null internal-handle failure must remain
   * diagnosable instead of being rewritten as frontend transport failure. */
  debugger_control_embedded[HYBRID580_BACKEND_LEGACY]=NV_ERR_OBJECT_NOT_FOUND;
  assert(!hybrid_front_ioctl(&front,rm_control_cmd,
             (unsigned long)&debugger_control) &&
         debugger_control.status==NV_ERR_OBJECT_NOT_FOUND &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_LEGACY]==2 &&
         !state->quarantined &&
         state->roots->root.state==HYBRID_ROOT_ACTIVE);
  debugger_control_embedded[HYBRID580_BACKEND_LEGACY]=NV_OK;
  debugger_control.hObject=710;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,
             (unsigned long)&debugger_control)==-EINVAL &&
         debugger_control.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_OPEN]==0);
  debugger_control.hObject=718;
  mask_params.exceptionMask=1U<<31;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,
             (unsigned long)&debugger_control)==-EINVAL &&
         debugger_control.status==NV_ERR_INVALID_ARGUMENT &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_OPEN]==0);
  NVOS54_PARAMETERS unsupported_debugger_control={.hClient=root,.hObject=718,
      .cmd=NV83DE_CTRL_CMD_SM_DEBUG_MODE_ENABLE,
      .params=(NvP64)(uintptr_t)1,.paramsSize=sizeof(NvU32)};
  assert(hybrid_front_ioctl(&front,rm_control_cmd,
             (unsigned long)&unsupported_debugger_control)==-ENOTTY &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_OPEN]==0);
  NVOS00_PARAMETERS free={.hRoot=root,.hObjectParent=666,.hObjectOld=700};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_ERR_INVALID_OBJECT_HANDLE && !object_free_calls[HYBRID580_BACKEND_OPEN]);
  assert(!request_engine_alloc(root,700,714,VOLTA_COMPUTE_A,ignored,0) &&
         device_packet.status==NV_ERR_INVALID_CLASS &&
         engine_alloc_calls[HYBRID580_BACKEND_OPEN]==2);
  assert(!request_engine_alloc(root,701,715,BLACKWELL_COMPUTE_B,ignored,0) &&
         device_packet.status==NV_ERR_INVALID_CLASS &&
         engine_alloc_calls[HYBRID580_BACKEND_LEGACY]==2);
  assert(!request_engine_alloc(root,222,716,BLACKWELL_COMPUTE_B,ignored,0) &&
         device_packet.status==NV_ERR_INVALID_CLASS &&
         engine_alloc_calls[HYBRID580_BACKEND_OPEN]==2);
  assert(!request_engine_alloc(root,700,717,BLACKWELL_COMPUTE_B,ignored,1) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT &&
         engine_alloc_calls[HYBRID580_BACKEND_OPEN]==2);
  assert(state->object_count==20 && state->roots->object_count==20);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=701,.hObjectOld=713};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_OK && object_free_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         object_free_roots[HYBRID580_BACKEND_LEGACY]==root &&
         object_free_parents[HYBRID580_BACKEND_LEGACY]==701 &&
         object_free_handles[HYBRID580_BACKEND_LEGACY]==713);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=701,.hObjectOld=712};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         object_free_calls[HYBRID580_BACKEND_LEGACY]==1);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=legacy_device,.hObjectOld=720};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_OK && object_free_calls[HYBRID580_BACKEND_LEGACY]==2 &&
         object_free_parents[HYBRID580_BACKEND_LEGACY]==legacy_device &&
         object_free_handles[HYBRID580_BACKEND_LEGACY]==720);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=701,.hObjectOld=712};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_OK && object_free_calls[HYBRID580_BACKEND_LEGACY]==3 &&
         object_free_parents[HYBRID580_BACKEND_LEGACY]==701 &&
         object_free_handles[HYBRID580_BACKEND_LEGACY]==712);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=700,.hObjectOld=711};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_OK && object_free_calls[HYBRID580_BACKEND_OPEN]==1 &&
         object_free_roots[HYBRID580_BACKEND_OPEN]==root &&
         object_free_parents[HYBRID580_BACKEND_OPEN]==700 &&
         object_free_handles[HYBRID580_BACKEND_OPEN]==711);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=700,.hObjectOld=710};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_OK && object_free_calls[HYBRID580_BACKEND_OPEN]==2 &&
         object_free_parents[HYBRID580_BACKEND_OPEN]==700 &&
         object_free_handles[HYBRID580_BACKEND_OPEN]==710);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=open_device,.hObjectOld=718};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         object_free_calls[HYBRID580_BACKEND_OPEN]==2);
  assert(state->object_count==15 && state->roots->object_count==15);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=667,.hObjectOld=701};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_OK && object_free_calls[HYBRID580_BACKEND_LEGACY]==4 &&
         object_free_parents[HYBRID580_BACKEND_LEGACY]==667 &&
         object_free_handles[HYBRID580_BACKEND_LEGACY]==701);
  free=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=666,.hObjectOld=700};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free) &&
         free.status==NV_OK && object_free_calls[HYBRID580_BACKEND_OPEN]==3 &&
         object_free_parents[HYBRID580_BACKEND_OPEN]==666 &&
         object_free_handles[HYBRID580_BACKEND_OPEN]==700);
  assert(state->object_count==13 && state->roots->object_count==13);
  front_put(); assert(frees[0]==1 && frees[1]==1); return 0;
 }
 if(!strcmp(s,"context-share-copyout-failure")) {
  prepare_device_object_test();
  vaspace_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  channel_group_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  context_share_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, device=222;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,device,0,root,0) && device_packet.status==NV_OK);
  NV_VASPACE_ALLOCATION_PARAMETERS va={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW};
  assert(!request_vaspace_alloc(root,device,444,&va) && device_packet.status==NV_OK);
  NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS group={.hVASpace=444,.engineType=1};
  assert(!request_channel_group_alloc(root,device,666,&group) && device_packet.status==NV_OK);
  NV_CTXSHARE_ALLOCATION_PARAMETERS context_share={.hVASpace=444};
  to_fault=1;
  assert(request_context_share_alloc(root,666,668,&context_share)==-EFAULT &&
         context_share_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         state->object_count==4 && state->roots->object_count==4);
  to_fault=0; front_put(); assert(frees[0]==1 && frees[1]==1); return 0;
 }
 if(!strcmp(s,"memory-object-open-lifecycle")) {
  prepare_device_object_test();
  memory_alloc_transport[0]=memory_alloc_transport[1]=NV_OK;
  memory_alloc_embedded[0]=memory_alloc_embedded[1]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  object_free_embedded[0]=object_free_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, device=222, memory=333;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,device,0,root,0) && device_packet.status==NV_OK);
  NV_MEMORY_ALLOCATION_PARAMS params={.owner=7,.type=9,.size=0x2000,
    .alignment=0x1000,.hVASpace=0};
  assert(!request_memory_alloc(root,device,memory,NV01_MEMORY_SYSTEM,&params) &&
         device_packet.status==NV_OK);
  assert(memory_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         memory_alloc_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         memory_alloc_roots[HYBRID580_BACKEND_OPEN]==root &&
         memory_alloc_parents[HYBRID580_BACKEND_OPEN]==device &&
         memory_alloc_handles[HYBRID580_BACKEND_OPEN]==memory &&
         memory_alloc_classes[HYBRID580_BACKEND_OPEN]==NV01_MEMORY_SYSTEM &&
         memory_alloc_params[HYBRID580_BACKEND_OPEN].size==0x2000 &&
         memory_alloc_params[HYBRID580_BACKEND_OPEN].alignment==0x1000);
  assert(params.size==0x4000 &&
         (uintptr_t)params.address==(uintptr_t)0xabc000 &&
         state->object_count==2 && state->roots->object_count==2);
  NV_MEMORY_ALLOCATION_PARAMS local={.owner=8,.type=4,.size=0x8000,
    .alignment=0x2000,.hVASpace=0};
  assert(!request_memory_alloc(root,device,334,NV01_MEMORY_LOCAL_USER,&local) &&
         device_packet.status==NV_OK && local.size==0x4000);
  assert(memory_alloc_calls[HYBRID580_BACKEND_OPEN]==2 &&
         memory_alloc_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         memory_alloc_classes[HYBRID580_BACKEND_OPEN]==NV01_MEMORY_LOCAL_USER &&
         memory_alloc_parents[HYBRID580_BACKEND_OPEN]==device);
  NVOS00_PARAMETERS parent_free={.hRoot=root,.hObjectParent=root,.hObjectOld=device};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&parent_free) &&
         parent_free.status==NV_ERR_INVALID_OBJECT_HANDLE && device_free_calls[0]==0 &&
         device_free_calls[1]==0 && state->object_count==3 && state->roots->object_count==3);
  NV_MEMORY_ALLOCATION_PARAMS wrong_parent={.hVASpace=0};
  assert(!request_memory_alloc(root,memory,338,NV01_MEMORY_SYSTEM,&wrong_parent) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         memory_alloc_calls[HYBRID580_BACKEND_OPEN]==2);
  NV_MEMORY_ALLOCATION_PARAMS unsupported={.hVASpace=123};
  assert(!request_memory_alloc(root,device,335,NV01_MEMORY_SYSTEM,&unsupported) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         memory_alloc_calls[HYBRID580_BACKEND_OPEN]==2);
  NV_MEMORY_ALLOCATION_PARAMS default_va={.hVASpace=0};
  assert(!request_memory_alloc(root,root,336,NV01_MEMORY_SYSTEM,&default_va) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         memory_alloc_calls[HYBRID580_BACKEND_OPEN]==2);
  copy_from_user_calls=0; from_fault_call=2;
  assert(request_memory_alloc(root,device,337,NV01_MEMORY_SYSTEM,&unsupported)==-EFAULT &&
         memory_alloc_calls[HYBRID580_BACKEND_OPEN]==2);
  from_fault_call=0;
  NVOS00_PARAMETERS packet={.hRoot=root,.hObjectParent=root,.hObjectOld=memory};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) &&
         packet.status==NV_ERR_INVALID_OBJECT_HANDLE && !object_free_calls[0] &&
         !object_free_calls[1]);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=device,.hObjectOld=memory};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  assert(object_free_calls[HYBRID580_BACKEND_OPEN]==1 &&
         object_free_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         object_free_roots[HYBRID580_BACKEND_OPEN]==root &&
         object_free_parents[HYBRID580_BACKEND_OPEN]==device &&
         object_free_handles[HYBRID580_BACKEND_OPEN]==memory &&
         state->object_count==2 && state->roots->object_count==2);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=device,.hObjectOld=334};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  assert(object_free_calls[HYBRID580_BACKEND_OPEN]==2 &&
         state->object_count==1 && state->roots->object_count==1);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=device};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  packet=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&packet) && packet.status==NV_OK);
  assert(frees[0]==1 && frees[1]==1);
  front_put(); return 0;
 }
 if(!strcmp(s,"memory-virtual-object-backend-affinity")) {
  prepare_device_object_test();
  memory_alloc_transport[0]=memory_alloc_transport[1]=NV_OK;
  memory_alloc_embedded[0]=memory_alloc_embedded[1]=NV_OK;
  vaspace_alloc_transport[0]=vaspace_alloc_transport[1]=NV_OK;
  vaspace_alloc_embedded[0]=vaspace_alloc_embedded[1]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  object_free_embedded[0]=object_free_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
  NV_VASPACE_ALLOCATION_PARAMETERS va0={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW,
    .vaSize=0x200000000ULL};
  NV_VASPACE_ALLOCATION_PARAMETERS va1={.index=NV_VASPACE_ALLOCATION_INDEX_GPU_NEW,
    .vaSize=0x200000000ULL};
  assert(!request_vaspace_alloc(root,222,444,&va0) && device_packet.status==NV_OK);
  assert(!request_vaspace_alloc(root,223,445,&va1) && device_packet.status==NV_OK);
  struct hybrid_front_file *state=front.private_data;
  struct hybrid_front_root *tracked_root=hybrid_front_find_root(state,root);
  struct hybrid_front_rm_object *open_device=hybrid_front_find_object(tracked_root,222);
  struct hybrid_front_rm_object *legacy_device=hybrid_front_find_object(tracked_root,223);
  assert(open_device && legacy_device &&
         open_device->backend==HYBRID580_BACKEND_OPEN &&
         legacy_device->backend==HYBRID580_BACKEND_LEGACY);
  struct hybrid_front_rm_object *open_vaspace=hybrid_front_find_object(tracked_root,444);
  struct hybrid_front_rm_object *legacy_vaspace=hybrid_front_find_object(tracked_root,445);
  assert(open_vaspace && legacy_vaspace &&
         open_vaspace->backend==HYBRID580_BACKEND_OPEN &&
         legacy_vaspace->backend==HYBRID580_BACKEND_LEGACY);
  open_vaspace->backend_handle=0xb0000445U;
  legacy_vaspace->backend_handle=0xa0000444U;

  NV_MEMORY_ALLOCATION_PARAMS open_params={.owner=7,.type=9,
    .flags=NVOS32_ALLOC_FLAGS_VIRTUAL,.size=0x8000,.alignment=0x1000,
    .hVASpace=444};
  NV_MEMORY_ALLOCATION_PARAMS legacy_params={.owner=8,.type=9,
    .flags=NVOS32_ALLOC_FLAGS_VIRTUAL,.size=0x10000,.alignment=0x2000,
    .hVASpace=445};
  assert(!request_memory_alloc(root,222,555,NV50_MEMORY_VIRTUAL,&open_params) &&
         device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,223,556,NV50_MEMORY_VIRTUAL,&legacy_params) &&
         device_packet.status==NV_OK);
  assert(memory_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         memory_alloc_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         memory_alloc_classes[HYBRID580_BACKEND_OPEN]==NV50_MEMORY_VIRTUAL &&
         memory_alloc_classes[HYBRID580_BACKEND_LEGACY]==NV50_MEMORY_VIRTUAL &&
         memory_alloc_parents[HYBRID580_BACKEND_OPEN]==open_device->backend_handle &&
         memory_alloc_parents[HYBRID580_BACKEND_LEGACY]==legacy_device->backend_handle &&
         memory_alloc_params[HYBRID580_BACKEND_OPEN].hVASpace==open_vaspace->backend_handle &&
         memory_alloc_params[HYBRID580_BACKEND_LEGACY].hVASpace==legacy_vaspace->backend_handle &&
         open_params.hVASpace==444 && legacy_params.hVASpace==445 &&
         open_params.size==0x4000 && legacy_params.size==0x4000);

  NV_MEMORY_ALLOCATION_PARAMS cross_backend={.flags=NVOS32_ALLOC_FLAGS_VIRTUAL,
    .size=0x1000,.alignment=0x1000,.hVASpace=445};
  assert(!request_memory_alloc(root,222,557,NV50_MEMORY_VIRTUAL,&cross_backend) &&
         device_packet.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         memory_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  NV_MEMORY_ALLOCATION_PARAMS no_vaspace={.flags=NVOS32_ALLOC_FLAGS_VIRTUAL,
    .size=0x1000,.alignment=0x1000};
  assert(!request_memory_alloc(root,222,558,NV50_MEMORY_VIRTUAL,&no_vaspace) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT &&
         memory_alloc_calls[HYBRID580_BACKEND_OPEN]==1);
  NV_MEMORY_ALLOCATION_PARAMS nonvirtual={.size=0x1000,.alignment=0x1000,
    .hVASpace=444};
  assert(!request_memory_alloc(root,222,559,NV50_MEMORY_VIRTUAL,&nonvirtual) &&
         device_packet.status==NV_ERR_INVALID_ARGUMENT &&
         memory_alloc_calls[HYBRID580_BACKEND_OPEN]==1);

  NVOS00_PARAMETERS free_open_va={.hRoot=root,.hObjectParent=222,.hObjectOld=444};
  NVOS00_PARAMETERS free_legacy_device={.hRoot=root,.hObjectParent=root,.hObjectOld=223};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_open_va) &&
         free_open_va.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_legacy_device) &&
         free_legacy_device.status==NV_ERR_INVALID_OBJECT_HANDLE);
  NVOS00_PARAMETERS free_object={.hRoot=root,.hObjectParent=222,.hObjectOld=555};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_object) &&
         free_object.status==NV_OK);
  free_object=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=223,.hObjectOld=556};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_object) &&
         free_object.status==NV_OK);
  free_object=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=222,.hObjectOld=444};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_object) &&
         free_object.status==NV_OK);
  free_object=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=223,.hObjectOld=445};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_object) &&
         free_object.status==NV_OK);
  free_object=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=222};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_object) &&
         free_object.status==NV_OK);
  free_object=(NVOS00_PARAMETERS){.hRoot=root,.hObjectParent=root,.hObjectOld=223};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_object) &&
         free_object.status==NV_OK);
  free_object=(NVOS00_PARAMETERS){.hRoot=root,.hObjectOld=root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_object) &&
         free_object.status==NV_OK && !state->object_count);
  front_put(); return 0;
 }
 if(!strcmp(s,"memory-object-copyout-failure")) {
  prepare_device_object_test();
  memory_alloc_transport[0]=memory_alloc_transport[1]=NV_OK;
  memory_alloc_embedded[0]=memory_alloc_embedded[1]=NV_OK;
  object_free_transport[0]=object_free_transport[1]=NV_OK;
  object_free_embedded[0]=object_free_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, device=222;
  struct hybrid_front_file *state=front.private_data;
  assert(!request_device_alloc(root,device,0,root,0) && device_packet.status==NV_OK);
  NV_MEMORY_ALLOCATION_PARAMS params={.size=0x2000,.alignment=0x1000};
  to_fault=1;
  assert(request_memory_alloc(root,device,333,NV01_MEMORY_SYSTEM,&params)==-EFAULT);
  to_fault=0;
  assert(memory_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         state->object_count==2 && state->roots->object_count==2 &&
         object_free_calls[0]==0 && object_free_calls[1]==0);
  front_put();
  assert(frees[0]==1 && frees[1]==1 &&
         object_free_calls[0]==0 && object_free_calls[1]==0);
  return 0;
 }
 if(!strcmp(s,"debugger-exception-mask-provider-owner-route")) {
  prepare_device_object_test();
  for(int backend=0;backend<2;backend++) {
   device_alloc_transport[backend]=NV_OK;
   device_alloc_embedded[backend]=NV_OK;
   engine_alloc_transport[backend]=NV_OK;
   engine_alloc_embedded[backend]=NV_OK;
   debugger_alloc_transport[backend]=NV_OK;
   debugger_alloc_embedded[backend]=NV_OK;
   debugger_control_transport[backend]=NV_OK;
  }
  /* Both provider roots intentionally share the public client handle. The
   * tracked debugger owner must select the backend for this ambiguous ID. */
  debugger_control_embedded[HYBRID580_BACKEND_LEGACY]=NV_ERR_OBJECT_NOT_FOUND;
  debugger_control_embedded[HYBRID580_BACKEND_OPEN]=NV_ERR_NOT_SUPPORTED;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  struct hybrid_front_file *state=front.private_data;
  struct hybrid_front_root *front_root=hybrid_front_find_root(state,root);
  assert(front_root &&
         front_root->root.slot[HYBRID580_BACKEND_OPEN].handle==root &&
         front_root->root.slot[HYBRID580_BACKEND_LEGACY].handle==root);
  assert(!request_device_alloc(root,222,0,root,0) && device_packet.status==NV_OK);
  assert(!request_device_alloc(root,223,1,root,0) && device_packet.status==NV_OK);
  struct hybrid_front_rm_object *open_device=
      hybrid_front_find_object(front_root,222);
  struct hybrid_front_rm_object *legacy_device=
      hybrid_front_find_object(front_root,223);
  assert(open_device && legacy_device &&
         open_device->backend==HYBRID580_BACKEND_OPEN &&
         legacy_device->backend==HYBRID580_BACKEND_LEGACY);
  struct hybrid_front_rm_object *open_debuggee=kzalloc(sizeof(*open_debuggee),GFP_KERNEL);
  struct hybrid_front_rm_object *legacy_debuggee=kzalloc(sizeof(*legacy_debuggee),GFP_KERNEL);
  assert(open_debuggee && legacy_debuggee);
  *open_debuggee=(struct hybrid_front_rm_object){
      .handle=710,.parent_handle=222,.backend_handle=1710,
      .backend_parent_handle=open_device->backend_handle,
      .class_id=BLACKWELL_COMPUTE_B,.backend=HYBRID580_BACKEND_OPEN};
  *legacy_debuggee=(struct hybrid_front_rm_object){
      .handle=712,.parent_handle=223,.backend_handle=1712,
      .backend_parent_handle=legacy_device->backend_handle,
      .class_id=VOLTA_COMPUTE_A,.backend=HYBRID580_BACKEND_LEGACY};
  open_debuggee->next=front_root->objects; front_root->objects=open_debuggee;
  legacy_debuggee->next=front_root->objects; front_root->objects=legacy_debuggee;
  ++front_root->object_count; ++front_root->object_count;
  ++state->object_count; ++state->object_count;
  NV83DE_ALLOC_PARAMETERS debugger_params={.hAppClient=root,.hClass3dObject=710};
  device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=222,
      .hObjectNew=718,.hClass=GT200_DEBUGGER,
      .pAllocParms=(NvP64)&debugger_params,.paramsSize=sizeof(debugger_params),
      .flags=NVOS64_FLAGS_NONE};
  assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
         device_packet.status==NV_OK &&
         debugger_alloc_calls[HYBRID580_BACKEND_OPEN]==1 &&
         debugger_alloc_handles[HYBRID580_BACKEND_OPEN]==718 &&
         hybrid_front_find_object(front_root,718)->backend_handle==718);
  debugger_params.hClass3dObject=712;
  device_packet=(NVOS64_PARAMETERS){.hRoot=root,.hObjectParent=223,
      .hObjectNew=720,.hClass=GT200_DEBUGGER,
      .pAllocParms=(NvP64)&debugger_params,.paramsSize=sizeof(debugger_params),
      .flags=NVOS64_FLAGS_NONE};
  assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&device_packet) &&
         device_packet.status==NV_OK &&
         debugger_alloc_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         debugger_alloc_handles[HYBRID580_BACKEND_LEGACY]==720 &&
         hybrid_front_find_object(front_root,720)->backend_handle==720);

  NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS mask_params={
      .exceptionMask=NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_TRAP};
  NVOS54_PARAMETERS control={.hClient=root,.hObject=718,
      .cmd=NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK,
      .params=(NvP64)&mask_params,.paramsSize=sizeof(mask_params),
      .flags=NVOS54_FLAGS_NONE,.status=0xffffffffU};
  assert(!hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control) &&
         control.status==NV_ERR_NOT_SUPPORTED &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_OPEN]==1 &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         debugger_control_clients[HYBRID580_BACKEND_OPEN]==
             state->roots->root.slot[HYBRID580_BACKEND_OPEN].handle &&
         debugger_control_objects[HYBRID580_BACKEND_OPEN]==718);
  control.hObject=720;
  assert(!hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control) &&
         control.status==NV_ERR_OBJECT_NOT_FOUND &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_OPEN]==1 &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         debugger_control_clients[HYBRID580_BACKEND_LEGACY]==
             state->roots->root.slot[HYBRID580_BACKEND_LEGACY].handle &&
         debugger_control_objects[HYBRID580_BACKEND_LEGACY]==720);

  struct hybrid_front_rm_object *legacy_debugger=
      hybrid_front_find_object(front_root,720);
  assert(legacy_debugger && legacy_debuggee &&
         legacy_debugger->backend==HYBRID580_BACKEND_LEGACY &&
         legacy_debuggee->backend==HYBRID580_BACKEND_LEGACY);
  legacy_debuggee->backend=HYBRID580_BACKEND_OPEN;
  int open_calls=debugger_exception_mask_calls[HYBRID580_BACKEND_OPEN];
  int legacy_calls=debugger_exception_mask_calls[HYBRID580_BACKEND_LEGACY];
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL &&
         control.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_OPEN]==open_calls &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_LEGACY]==legacy_calls);
  legacy_debuggee->backend=HYBRID580_BACKEND_LEGACY;
  control.hClient=root+1;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL &&
         control.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_OPEN]==open_calls &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_LEGACY]==legacy_calls);
  control.hClient=root; control.hObject=0xf00d;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL &&
         control.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_OPEN]==open_calls &&
         debugger_exception_mask_calls[HYBRID580_BACKEND_LEGACY]==legacy_calls);
  front_put();
  return 0;
 }
 if(!strncmp(s,"device-ids-",11)) {
  set_inventory_record(0,"0000:81:00.0",7,5,0x81);
  set_inventory_record(1,"0000:02:00.0",7,512,2);
  device_ids_values[0]=1U<<10; device_ids_values[1]=1U<<11;
  device_ids_transport[0]=device_ids_transport[1]=NV_OK;
  device_ids_embedded[0]=device_ids_embedded[1]=NV_OK;
  if(!strcmp(s,"device-ids-backend-error"))
   device_ids_embedded[1]=NV_ERR_INVALID_STATE;
  if(!strcmp(s,"device-ids-backend-transport-error"))
   device_ids_transport[1]=NV_ERR_OPERATING_SYSTEM;
  if(!strcmp(s,"device-ids-mask-mismatch")) device_ids_values[1]=1U<<9;
  if(!strcmp(s,"device-ids-gpu-id-error")) gpu_id_info_embedded=NV_ERR_INVALID_STATE;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew; NvU32 mask=0xffffffffU,status=0xffffffffU; long rc;
  if(!strcmp(s,"device-ids-invalid-root")) root++;
  if(!strcmp(s,"device-ids-copyin-failure")) from_fault=1;
  if(!strcmp(s,"device-ids-copyout-failure")) to_fault=1;
  if(!strcmp(s,"device-ids-xfer")) rc=device_ids_xfer(root,&mask,&status);
  else rc=device_ids_direct(root,&mask,&status);
  from_fault=0; to_fault=0;
  if(!strcmp(s,"device-ids-merge") || !strcmp(s,"device-ids-xfer")) {
   assert(!rc && status==NV_OK && mask==3);
   assert(device_ids_calls[0]==1 && device_ids_calls[1]==1);
   assert(device_ids_clients[0]==root && device_ids_objects[0]==root &&
          device_ids_clients[1]==root && device_ids_objects[1]==root);
   assert(attached_ids_calls[0]==0 && attached_ids_calls[1]==0);
   assert(gpu_id_info_calls[0]==1 && gpu_id_info_calls[1]==1);
   assert(!device_ids_direct(root,&mask,&status) && status==NV_OK && mask==3);
   assert(device_ids_calls[0]==1 && device_ids_calls[1]==1);
  } else if(!strcmp(s,"device-ids-copyin-failure")) {
   assert(rc==-EFAULT && device_ids_calls[0]==0 && device_ids_calls[1]==0);
  } else if(!strcmp(s,"device-ids-copyout-failure")) {
   assert(rc==-EFAULT && device_ids_calls[0]==1 && device_ids_calls[1]==1);
  } else if(!strcmp(s,"device-ids-invalid-root")) {
   assert(rc==-EINVAL && status==NV_ERR_INVALID_OBJECT_HANDLE);
   assert(device_ids_calls[0]==0 && device_ids_calls[1]==0);
  } else {
   assert(rc==-EINVAL && status!=NV_OK && mask==0);
  }
  front_put(); return 0;
 }
 if(!strcmp(s,"attached-ids-merge") || !strcmp(s,"attached-ids-xfer") ||
    !strcmp(s,"attached-ids-backend-error") || !strcmp(s,"attached-ids-transport-error") ||
    !strcmp(s,"attached-ids-stale") || !strcmp(s,"attached-ids-duplicate") ||
    !strcmp(s,"attached-ids-noncontiguous") || !strcmp(s,"attached-ids-overflow") ||
    !strcmp(s,"attached-ids-copyin-failure") || !strcmp(s,"attached-ids-copyout-failure")) {
  NvHandle root;
  set_attached_backend_ids(0,5,NV0000_CTRL_GPU_INVALID_ID);
  set_attached_backend_ids(1,512,NV0000_CTRL_GPU_INVALID_ID);
  if(!strcmp(s,"attached-ids-backend-error")) attached_ids_embedded[1]=NV_ERR_INVALID_STATE;
  if(!strcmp(s,"attached-ids-transport-error")) attached_ids_transport[1]=NV_ERR_OPERATING_SYSTEM;
  if(!strcmp(s,"attached-ids-stale")) attached_ids_values[1][0]=999;
  if(!strcmp(s,"attached-ids-duplicate")) {
   set_inventory_record(1,"0000:02:00.0",7,55,2);
   attached_ids_counts[1]=2; attached_ids_values[1][1]=55;
  }
  if(!strcmp(s,"attached-ids-noncontiguous")) {
   attached_ids_counts[1]=3; attached_ids_values[1][0]=55;
   attached_ids_values[1][1]=NV0000_CTRL_GPU_INVALID_ID;
   attached_ids_values[1][2]=55;
  }
  if(!strcmp(s,"attached-ids-overflow")) {
   inventory_count[0]=16; inventory_count[1]=17;
   for(unsigned int b=0;b<2;b++) for(unsigned int i=0;i<inventory_count[b];i++) {
    struct hybrid580_gpu_backend_record_v1 *r=&inventory_records[b][i]; memset(r,0,sizeof(*r));
    snprintf(r->bdf,sizeof(r->bdf),"0000:%02x:00.0",b?i:0x40+i);
    r->backend_minor=i; r->backend_gpu_id=100+b*100+i; r->domain=0;
    r->bus=b?i:0x40+i; r->vendor_id=0x10de; r->device_id=0x2684;
   }
   attached_ids_counts[0]=16; attached_ids_counts[1]=17;
   for(unsigned int i=0;i<16;i++) attached_ids_values[0][i]=100+i;
   for(unsigned int i=0;i<17;i++) attached_ids_values[1][i]=200+i;
  }
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK); root=p21.hObjectNew;
  NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS out; NvU32 status=0xffffffffU;
  long rc;
  if(!strcmp(s,"attached-ids-copyin-failure")) from_fault=1;
  if(!strcmp(s,"attached-ids-copyout-failure")) to_fault=1;
  if(!strcmp(s,"attached-ids-xfer")) rc=attached_ids_xfer(root,&out,&status);
  else rc=attached_ids_direct(root,&out,&status);
  from_fault=0; to_fault=0;
  if(!strcmp(s,"attached-ids-merge") || !strcmp(s,"attached-ids-xfer")) {
   assert(!rc && status==NV_OK && out.gpuIds[0]==1 && out.gpuIds[1]==2);
   for(unsigned int i=2;i<NV0000_CTRL_GPU_MAX_ATTACHED_GPUS;i++)
    assert(out.gpuIds[i]==NV0000_CTRL_GPU_INVALID_ID);
   assert(attached_ids_calls[0]==1 && attached_ids_calls[1]==1);
   assert(attached_ids_clients[0]==root && attached_ids_objects[0]==root &&
          attached_ids_clients[1]==root && attached_ids_objects[1]==root);
  } else if(!strcmp(s,"attached-ids-overflow")) {
   assert(rc==-EINVAL && status==NV_ERR_INSUFFICIENT_RESOURCES);
   for(unsigned int i=0;i<NV0000_CTRL_GPU_MAX_ATTACHED_GPUS;i++)
    assert(out.gpuIds[i]==NV0000_CTRL_GPU_INVALID_ID);
  } else if(!strcmp(s,"attached-ids-copyin-failure")) {
   assert(rc==-EFAULT && attached_ids_calls[0]==0 && attached_ids_calls[1]==0);
  } else if(!strcmp(s,"attached-ids-copyout-failure")) {
   assert(rc==-EFAULT && attached_ids_calls[0]==1 && attached_ids_calls[1]==1);
  } else {
   assert(rc==-EINVAL && status!=NV_OK);
   for(unsigned int i=0;i<NV0000_CTRL_GPU_MAX_ATTACHED_GPUS;i++)
    assert(out.gpuIds[i]==NV0000_CTRL_GPU_INVALID_ID);
  }
  front_put(); return 0;
 }
 if(!strncmp(s,"probed-ids-",11)) {
  if(!strcmp(s,"probed-ids-embedded-error"))
   probed_ids_embedded[1]=NV_ERR_INVALID_STATE;
  if(!strcmp(s,"probed-ids-transport-error"))
   probed_ids_transport[1]=NV_ERR_OPERATING_SYSTEM;
  if(!strcmp(s,"probed-ids-unknown")) probed_ids_reply[1].gpuIds[0]=999;
  if(!strcmp(s,"probed-ids-duplicate")) {
   probed_ids_reply[1].gpuIds[1]=512;
  }
  if(!strcmp(s,"probed-ids-noncontiguous")) {
   probed_ids_reply[1].gpuIds[1]=NV0000_CTRL_GPU_INVALID_ID;
   probed_ids_reply[1].gpuIds[2]=512;
  }
  if(!strcmp(s,"probed-ids-excluded-unknown"))
   probed_ids_reply[1].excludedGpuIds[0]=999;
  if(!strcmp(s,"probed-ids-excluded-overlap"))
   probed_ids_reply[0].excludedGpuIds[0]=5;
  if(!strcmp(s,"probed-ids-overflow")) {
   NvU32 legacy_ids[16], legacy_flags[16], open_ids[17], open_flags[17];
   char bdf[16];
   for(unsigned int i=0;i<16;i++) {
    legacy_ids[i]=100+i; legacy_flags[i]=i;
    snprintf(bdf,sizeof(bdf),"0000:%02x:00.0",0x40+i);
    append_inventory_record(0,i,bdf,i,legacy_ids[i],0x40+i);
   }
   for(unsigned int i=0;i<17;i++) {
    open_ids[i]=200+i; open_flags[i]=i+1;
    snprintf(bdf,sizeof(bdf),"0000:%02x:00.0",i);
    append_inventory_record(1,i,bdf,i,open_ids[i],i);
   }
   set_probed_backend_ids(0,legacy_ids,legacy_flags,16,NULL,0);
   set_probed_backend_ids(1,open_ids,open_flags,17,NULL,0);
  }
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS out; NvU32 status=0xffffffffU;
  long rc;
  if(!strcmp(s,"probed-ids-allocation-failure")) fail_alloc=1;
  if(!strcmp(s,"probed-ids-copyin-failure")) from_fault=1;
  if(!strcmp(s,"probed-ids-copyout-failure")) to_fault=1;
  if(!strcmp(s,"probed-ids-invalid-root")) root++;
  if(!strcmp(s,"probed-ids-xfer")) rc=probed_ids_xfer(root,&out,&status);
  else rc=probed_ids_direct(root,&out,&status);
  from_fault=0; to_fault=0; fail_alloc=0;
  if(!strcmp(s,"probed-ids-merge") || !strcmp(s,"probed-ids-xfer")) {
   assert(!rc && status==NV_OK);
   assert(out.gpuIds[0]==1 && out.gpuFlags[0]==1);
   assert(out.gpuIds[1]==3 && out.gpuFlags[1]==8);
   assert(out.excludedGpuIds[0]==2 && out.excludedGpuIds[1]==4);
   for(unsigned int i=2;i<NV0000_CTRL_GPU_MAX_PROBED_GPUS;i++) {
    assert(out.gpuIds[i]==NV0000_CTRL_GPU_INVALID_ID && out.gpuFlags[i]==0);
   }
   for(unsigned int i=2;i<NV0000_CTRL_GPU_MAX_PROBED_GPUS;i++)
    assert(out.excludedGpuIds[i]==NV0000_CTRL_GPU_INVALID_ID);
   assert(probed_ids_calls[0]==1 && probed_ids_calls[1]==1);
   for(unsigned int b=0;b<2;b++) {
    assert(probed_ids_clients[b]==root && probed_ids_objects[b]==root);
    assert(probed_ids_flags[b]==0 && probed_ids_commands[b]==NV0000_CTRL_CMD_GPU_GET_PROBED_IDS);
    assert(probed_ids_sizes[b]==sizeof(NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS));
   }
  } else if(!strcmp(s,"probed-ids-overflow")) {
   assert(rc==-EINVAL && status==NV_ERR_INSUFFICIENT_RESOURCES);
  } else if(!strcmp(s,"probed-ids-unknown") || !strcmp(s,"probed-ids-duplicate") ||
            !strcmp(s,"probed-ids-excluded-unknown") ||
            !strcmp(s,"probed-ids-excluded-overlap")) {
   assert(rc==-EINVAL && status==NV_ERR_INVALID_STATE);
  } else if(!strcmp(s,"probed-ids-noncontiguous")) {
   assert(rc==-EINVAL && status==NV_ERR_INVALID_ARGUMENT);
  } else if(!strcmp(s,"probed-ids-embedded-error")) {
   assert(rc==-EINVAL && status==NV_ERR_INVALID_STATE);
  } else if(!strcmp(s,"probed-ids-transport-error")) {
   assert(rc==-EINVAL && status==NV_ERR_OPERATING_SYSTEM);
  } else if(!strcmp(s,"probed-ids-allocation-failure")) {
   assert(rc==-ENOMEM && status==NV_ERR_NO_MEMORY);
   assert(probed_ids_calls[0]==0 && probed_ids_calls[1]==0);
  } else if(!strcmp(s,"probed-ids-invalid-root")) {
   assert(rc==-EINVAL && status==NV_ERR_INVALID_OBJECT_HANDLE);
   assert(probed_ids_calls[0]==0 && probed_ids_calls[1]==0);
  } else if(!strcmp(s,"probed-ids-copyin-failure")) {
   assert(rc==-EFAULT && probed_ids_calls[0]==0 && probed_ids_calls[1]==0);
  } else if(!strcmp(s,"probed-ids-copyout-failure")) {
   assert(rc==-EFAULT && probed_ids_calls[0]==1 && probed_ids_calls[1]==1);
  }
  if(rc==-EINVAL && strcmp(s,"probed-ids-copyout-failure")) {
   for(unsigned int i=0;i<NV0000_CTRL_GPU_MAX_PROBED_GPUS;i++) {
    assert(out.gpuIds[i]==NV0000_CTRL_GPU_INVALID_ID);
    assert(out.excludedGpuIds[i]==NV0000_CTRL_GPU_INVALID_ID);
    assert(out.gpuFlags[i]==0);
   }
  }
  front_put(); return 0;
 }
 if(!strcmp(s,"gpu-id-info-reject")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  assert(gpu_id_info_direct(999,root,NULL,NULL)==-EINVAL);
  assert(gpu_id_info_calls[0]==0 && gpu_id_info_calls[1]==0);
  assert(gpu_id_info_direct(1,root+1,NULL,NULL)==-EINVAL);
  assert(gpu_id_info_direct(1,0,NULL,NULL)==-EINVAL);
  assert(gpu_id_info_calls[0]==0 && gpu_id_info_calls[1]==0);
  NVOS54_PARAMETERS unrelated={.hClient=root,.hObject=root,.cmd=0x204,
    .params=(NvP64)1,.paramsSize=1};
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&unrelated)==-ENOTTY);
  assert(gpu_id_info_calls[0]==0 && gpu_id_info_calls[1]==0);
  front_put(); return 0;
 }
 if(!strcmp(s,"attach-direct-success")) inventory_count[1]=0;
 if(!strcmp(s,"catalog-duplicate")) {
  set_inventory_record(0,"0000:65:00.0",3,44,0x65);
  set_inventory_record(1,"0000:65:00.0",3,44,0x65);
 }
 if(!strcmp(s,"catalog-inventory-error")) inventory_error[1]=-EIO;
 if(!strcmp(s,"catalog-duplicate") || !strcmp(s,"catalog-inventory-error")) {
  front=(struct file){.f_op=&hybrid_front_fops,.private_data=(void *)1,.refs=1};
  assert(hybrid_front_open(&inode,&front)<0 && front.private_data==NULL);
  assert(session_puts[0]==1 && session_puts[1]==1 && !device_registers);
  return 0;
 }
 if(!strncmp(s,"catalog-allocation-fail-",23)) {
  fail_alloc_at=!strcmp(s,"catalog-allocation-fail-catalog")?2:
                !strcmp(s,"catalog-allocation-fail-legacy-buffer")?3:4;
  front=(struct file){.f_op=&hybrid_front_fops,.private_data=(void *)1,.refs=1};
  assert(hybrid_front_open(&inode,&front)==-ENOMEM && front.private_data==NULL);
  assert(alloc_calls==4 && session_puts[0]==1 && session_puts[1]==1);
  assert(inventory_calls[0]==0 && inventory_calls[1]==0);
  assert(!hybrid_front_release(&inode,&front)); return 0;
 }
 make_front();
 if(!strcmp(s,"catalog-query")) {
  struct hybrid580_gpu_count_v1 count={.struct_size=sizeof(count)};
  assert(!hybrid_front_ioctl(&front,HYBRID580_IOCTL_GET_GPU_COUNT,(unsigned long)&count));
  assert(count.count==2 && count.reserved[0]==0 && count.reserved[1]==0);
  struct hybrid580_gpu_info_v1 info={.struct_size=sizeof(info),.index=0};
  assert(!hybrid_front_ioctl(&front,HYBRID580_IOCTL_GET_GPU_INFO,(unsigned long)&info));
  assert(info.entry.frontend_index==0 && info.entry.frontend_gpu_id==1 && !strcmp(info.entry.bdf,"0000:01:00.0"));
  assert(info.entry.backend==HYBRID580_BACKEND_OPEN && info.entry.backend_minor==3 && info.entry.backend_gpu_id==44);
  info=(struct hybrid580_gpu_info_v1){.struct_size=sizeof(info),.index=1};
  assert(!hybrid_front_ioctl(&front,HYBRID580_IOCTL_GET_GPU_INFO,(unsigned long)&info));
  assert(info.entry.frontend_index==1 && info.entry.frontend_gpu_id==2 && !strcmp(info.entry.bdf,"0000:65:00.0"));
  assert(info.entry.backend==HYBRID580_BACKEND_LEGACY && info.entry.backend_minor==3 && info.entry.backend_gpu_id==44);
  info=(struct hybrid580_gpu_info_v1){.struct_size=sizeof(info),.index=2};
  assert(hybrid_front_ioctl(&front,HYBRID580_IOCTL_GET_GPU_INFO,(unsigned long)&info)==-EINVAL);
  count=(struct hybrid580_gpu_count_v1){.struct_size=sizeof(count),.count=1};
  assert(hybrid_front_ioctl(&front,HYBRID580_IOCTL_GET_GPU_COUNT,(unsigned long)&count)==-EINVAL);
  count=(struct hybrid580_gpu_count_v1){.struct_size=sizeof(count)}; from_fault=1;
  assert(hybrid_front_ioctl(&front,HYBRID580_IOCTL_GET_GPU_COUNT,(unsigned long)&count)==-EFAULT); from_fault=0;
  info=(struct hybrid580_gpu_info_v1){.struct_size=sizeof(info),.index=0}; to_fault=1;
  assert(hybrid_front_ioctl(&front,HYBRID580_IOCTL_GET_GPU_INFO,(unsigned long)&info)==-EFAULT); to_fault=0;
  assert(inventory_calls[0]==1 && inventory_calls[1]==1);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1);
  return 0;
 } else if(!strcmp(s,"catalog-empty")) {
  struct hybrid580_gpu_count_v1 count={.struct_size=sizeof(count)};
  assert(!hybrid_front_ioctl(&front,HYBRID580_IOCTL_GET_GPU_COUNT,(unsigned long)&count) && count.count==0);
  struct hybrid580_gpu_info_v1 info={.struct_size=sizeof(info)};
  assert(hybrid_front_ioctl(&front,HYBRID580_IOCTL_GET_GPU_INFO,(unsigned long)&info)==-EINVAL);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1);
  return 0;
 } else if(!strcmp(s,"card-info-merge")) {
  nv_ioctl_card_info_t records[2]={{0}};
  assert(hybrid_front_ioctl(&front,card_info_cmd(sizeof(records)),(unsigned long)records)==0);
  assert(records[0].valid && records[0].pci_info.bus==2 && records[0].gpu_id==1 && records[0].minor_number==0);
  assert(records[0].pci_info.device_id==0x2c02 && records[0].reg_address==0x20000000ULL && records[0].fb_address==0xa00000000ULL);
  assert(records[1].valid && records[1].pci_info.bus==0x81 && records[1].gpu_id==2 && records[1].minor_number==1);
  assert(records[1].pci_info.device_id==0x1db6 && records[1].reg_address==0x81000000ULL && records[1].fb_address==0x900000000ULL);
  assert(card_info_calls[0]==1 && card_info_calls[1]==1);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1); return 0;
 } else if(!strcmp(s,"card-info-small")) {
  nv_ioctl_card_info_t record={.valid=NV_TRUE,.gpu_id=99,.minor_number=99};
  assert(hybrid_front_ioctl(&front,card_info_cmd(sizeof(record)),(unsigned long)&record)==-EINVAL);
  assert(!record.valid && !record.gpu_id && !record.minor_number);
  assert(!card_info_calls[0] && !card_info_calls[1]);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1); return 0;
 } else if(!strcmp(s,"card-info-xfer")) {
  nv_ioctl_card_info_t records[2]={{0}};
  nv_ioctl_xfer_t xfer={.cmd=NV_ESC_CARD_INFO,.size=sizeof(records),.ptr=(NvP64)records};
  unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
  assert(hybrid_front_ioctl(&front,command,(unsigned long)&xfer)==0);
  assert(records[0].valid && records[0].pci_info.bus==2 && records[0].gpu_id==1 && records[0].minor_number==0);
  assert(records[1].valid && records[1].pci_info.bus==0x81 && records[1].gpu_id==2 && records[1].minor_number==1);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1); return 0;
 } else if(!strcmp(s,"card-info-stale")) {
  nv_ioctl_card_info_t records[2]={{.valid=NV_TRUE},{.valid=NV_TRUE}};
  assert(hybrid_front_ioctl(&front,card_info_cmd(sizeof(records)),(unsigned long)records)==-EAGAIN);
  assert(!records[0].valid && !records[1].valid);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1); return 0;
 } else if(!strcmp(s,"card-info-backend-error")) {
  nv_ioctl_card_info_t records[2]={{.valid=NV_TRUE},{.valid=NV_TRUE}};
  assert(hybrid_front_ioctl(&front,card_info_cmd(sizeof(records)),(unsigned long)records)==-EIO);
  assert(!records[0].valid && !records[1].valid && card_info_calls[0]==1 && card_info_calls[1]==1);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1); return 0;
 } else if(!strcmp(s,"card-info-copyin-failure")) {
  nv_ioctl_card_info_t records[2]={{0}}; from_fault=1;
  assert(hybrid_front_ioctl(&front,card_info_cmd(sizeof(records)),(unsigned long)records)==-EFAULT);
  from_fault=0; assert(!card_info_calls[0] && !card_info_calls[1]);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1); return 0;
 } else if(!strcmp(s,"card-info-copyout-failure")) {
  nv_ioctl_card_info_t records[2]={{0}}; to_fault=1;
  assert(hybrid_front_ioctl(&front,card_info_cmd(sizeof(records)),(unsigned long)records)==-EFAULT);
  to_fault=0; assert(card_info_calls[0]==1 && card_info_calls[1]==1);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1); return 0;
 } else if(!strncmp(s,"card-info-allocation-fail-",26)) {
  nv_ioctl_card_info_t records[2]={{.valid=NV_TRUE},{.valid=NV_TRUE}};
  fail_alloc_at=alloc_calls+(!strcmp(s,"card-info-allocation-fail-user")?1:
                           !strcmp(s,"card-info-allocation-fail-legacy")?2:3);
  assert(hybrid_front_ioctl(&front,card_info_cmd(sizeof(records)),(unsigned long)records)==-ENOMEM);
  fail_alloc_at=0;
  if(!strcmp(s,"card-info-allocation-fail-user"))
   assert(records[0].valid && records[1].valid);
  else assert(!records[0].valid && !records[1].valid);
  assert(!card_info_calls[0] && !card_info_calls[1]);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1); return 0;
 } else if(!strcmp(s,"card-info-xfer-reject")) {
  nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(nv_ioctl_card_info_t)*2,
                        .ptr=(NvP64)(uintptr_t)card_info_records[0]};
  unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
  assert(hybrid_front_ioctl(&front,command,(unsigned long)&xfer)==-EINVAL);
  assert(!card_info_calls[0] && !card_info_calls[1]);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1); return 0;
 } else if(!strcmp(s,"attach-publish-success")) {
  struct hybrid_front_file *state=front.private_data;
  struct hybrid580_control_session *old[2]={state->sessions[0],state->sessions[1]};
  NvU32 requested[]={2,1};
  assert(attach_xfer(requested,2)==0);
  assert(state->sessions[0]!=old[0] && state->sessions[1]!=old[1]);
  assert(attach_attempts[0]==1 && attach_attempts[1]==1);
  assert(attached_count[0]==1 && attached_ids[0][0]==45);
  assert(attached_count[1]==1 && attached_ids[1][0]==46);
  assert(session_puts[0]==1 && session_puts[1]==1);
  assert(alloc_root(false)==0 && p21.status==NV_OK && calls[0]==1 && calls[1]==1);
  front_put(); assert(!front.private_data && session_puts[0]==2 && session_puts[1]==2);
  return 0;
 } else if(!strcmp(s,"attach-direct-success")) {
  set_inventory_record(0,"0000:65:00.0",3,45,0x65);
  inventory_count[1]=0;
  assert(attach_direct(1)==0 && attach_attempts[0]==1 && !attach_attempts[1]);
  assert(attached_count[0]==1 && attached_ids[0][0]==45 && session_puts[0]==1 && session_puts[1]==1);
 } else if(!strcmp(s,"attach-second-backend-failure")) {
  struct hybrid_front_file *state=front.private_data;
  struct hybrid580_control_session *old[2]={state->sessions[0],state->sessions[1]};
  attach_error_backend=HYBRID580_BACKEND_OPEN; NvU32 requested[]={2,1};
  assert(attach_xfer(requested,2)==-EINVAL);
  assert(state->sessions[0]==old[0] && state->sessions[1]==old[1]);
  assert(state->attach_attempted && state->quarantined && !state->attach_committed);
  assert(attach_attempts[0]==1 && attach_attempts[1]==1 && session_puts[0]==1 && session_puts[1]==1);
  assert(alloc_root(false)==0 && p21.status==NV_ERR_INVALID_STATE && !calls[0] && !calls[1]);
 } else if(!strcmp(s,"attach-candidate-create-retry")) {
  struct hybrid_front_file *state=front.private_data;
  struct hybrid580_control_session *old[2]={state->sessions[0],state->sessions[1]};
  fail_create_call[1]=2; NvU32 requested[]={2,1};
  assert(attach_xfer(requested,2)==-ENODEV);
  assert(state->sessions[0]==old[0] && state->sessions[1]==old[1]);
  assert(!state->attach_attempted && !state->quarantined && session_puts[0]==1 && !session_puts[1]);
  fail_create_call[1]=0;
  assert(attach_xfer(requested,2)==0 && state->attach_committed);
  assert(attach_attempts[0]==1 && attach_attempts[1]==1);
 } else if(!strcmp(s,"attach-after-stateful-rejected")) {
  assert(alloc_root(false)==0 && p21.status==NV_OK);
  NvU32 requested[]={1}; assert(attach_xfer(requested,1)==-EBUSY);
  assert(!attach_attempts[0] && !attach_attempts[1] && !((struct hybrid_front_file *)front.private_data)->attach_attempted);
 } else if(!strcmp(s,"attach-copy-in-failure")) {
  NvU32 requested[]={1}; from_fault=1;
  assert(attach_xfer(requested,1)==-EFAULT); from_fault=0;
  assert(control_create_calls[0]==1 && control_create_calls[1]==1 && !attach_attempts[0] && !attach_attempts[1]);
 } else if(!strcmp(s,"attach-malformed")) {
  nv_ioctl_xfer_t xfer={.cmd=NV_ESC_ATTACH_GPUS_TO_FD,.size=3,.ptr=(NvP64)(uintptr_t)&inventory_count[0]};
  unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
  assert(hybrid_front_ioctl(&front,command,(unsigned long)&xfer)==-EINVAL);
  assert(!attach_attempts[0] && !attach_attempts[1]);
 } else if(!strcmp(s,"attach-repeat-rejected")) {
  NvU32 requested[]={2,1}; assert(attach_xfer(requested,2)==0);
  int before0=control_create_calls[0],before1=control_create_calls[1];
  assert(attach_xfer(requested,2)==-EBUSY);
  assert(control_create_calls[0]==before0 && control_create_calls[1]==before1);
  assert(attach_attempts[0]==1 && attach_attempts[1]==1);
 } else if(!strcmp(s,"attach-zero-placeholder")) {
  struct hybrid_front_file *state=front.private_data;
  struct hybrid580_control_session *old[2]={state->sessions[0],state->sessions[1]};
  NvU32 zero[]={0};
  assert(attach_xfer(zero,1)==0 && state->attach_committed);
  assert(state->sessions[0]!=old[0] && state->sessions[1]!=old[1]);
  assert(!attach_attempts[0] && !attach_attempts[1]);
  assert(session_puts[0]==1 && session_puts[1]==1);
 } else if(!strcmp(s,"attach-after-gpu-open-failure")) {
  gpu_create_error[0]=-ENOMEM;
  assert(open_gpu("0000:65:00.0")==-ENOMEM);
  struct hybrid_front_file *state=front.private_data;
  assert(state->operation_inflight==0 && !state->stateful_started);
  gpu_create_error[0]=0; NvU32 requested[]={2,1};
  assert(attach_xfer(requested,2)==0 && state->attach_committed);
 }
 if(!strncmp(s,"attach-",7)) {
  front_put(); assert(!front.private_data && session_puts[0]==created[0] && session_puts[1]==created[1]);
  return 0;
 }
 if(!strcmp(s,"gpu-legacy-route") || !strcmp(s,"gpu-open-route")) {
  gpu_owner=!strcmp(s,"gpu-open-route")?HYBRID580_BACKEND_OPEN:HYBRID580_BACKEND_LEGACY;
  assert(!open_gpu("0000:81:00.0")); int fd=40;
  assert(installed_fds[fd] && installed_fds[fd]->f_op==&hybrid_front_fops);
  assert(last_gpu_request.gpu_fd==fd && last_gpu_request.backend==(unsigned)gpu_owner);
  assert((last_fd_flags&O_CLOEXEC)!=0 && (last_anon_flags&O_CLOEXEC)!=0);
  assert(((struct hybrid_front_gpu_file *)installed_fds[fd]->private_data)->backend==(unsigned)gpu_owner);
  assert(gpu_create_attempts[0]==(gpu_owner==HYBRID580_BACKEND_LEGACY) &&
         gpu_create_attempts[1]==(gpu_owner==HYBRID580_BACKEND_OPEN));
  assert(installed_fds[fd]->f_op->unlocked_ioctl(installed_fds[fd],gpu_test_cmd,0)==100+gpu_owner);
  assert(gpu_ioctl_calls[gpu_owner]==1);
  struct fake_register_fd_payload payload={.ctl_fd=9};
  unsigned int register_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_REGISTER_FD,struct fake_register_fd_payload);
  register_gpu_front=installed_fds[fd]; register_control_front=&front;
  assert(installed_fds[fd]->f_op->unlocked_ioctl(installed_fds[fd],register_cmd,(unsigned long)&payload)==0);
  assert(register_fd_calls==1 && register_fd_matches==1);
  register_gpu_front=NULL; register_control_front=NULL;
  struct file *back=gpu_owner==HYBRID580_BACKEND_LEGACY ?
      hybrid_front_project_legacy(installed_fds[fd],false) : hybrid_front_project_open(installed_fds[fd],false);
  assert(back && atomic_load(&back->refs)==2); fput(back);
  assert((gpu_owner==HYBRID580_BACKEND_LEGACY ? hybrid_front_project_open(installed_fds[fd],false) :
          hybrid_front_project_legacy(installed_fds[fd],false))==NULL);
  front_put(); assert(front.private_data && !session_puts[0] && !session_puts[1]);
  close_test_fd(fd);
  assert(!front.private_data && gpu_puts[gpu_owner]==1 && session_puts[0]==1 && session_puts[1]==1);
  return 0;
 } else if(!strcmp(s,"standard-gpu-blackwell-register") || !strcmp(s,"standard-gpu-volta-register") ||
           !strcmp(s,"standard-gpu-observed-node-ioctls-blackwell") ||
           !strcmp(s,"standard-gpu-observed-node-ioctls-volta") ||
           !strcmp(s,"standard-gpu-register-fd-xfer-blackwell") ||
           !strcmp(s,"standard-gpu-register-fd-xfer-volta") ||
           !strcmp(s,"standard-gpu-register-fd-reuse-blackwell") ||
           !strcmp(s,"standard-gpu-register-fd-reuse-volta") ||
           !strcmp(s,"standard-gpu-register-fd-xfer-reuse-blackwell") ||
           !strcmp(s,"standard-gpu-register-fd-xfer-reuse-volta") ||
           !strcmp(s,"standard-gpu-register-fd-xfer-bad-size") ||
           !strcmp(s,"standard-gpu-register-fd-xfer-copyin-failure") ||
           !strcmp(s,"standard-gpu-register-fd-xfer-inner-copyin-failure") ||
           !strcmp(s,"standard-gpu-register-fd-xfer-header-race") ||
           !strcmp(s,"standard-gpu-register-fd-xfer-payload-race-blackwell") ||
           !strcmp(s,"standard-gpu-register-fd-quarantine-race") ||
           !strcmp(s,"standard-gpu-pending-quarantine-blocked") ||
           !strcmp(s,"standard-gpu-bad-control") || !strcmp(s,"standard-gpu-bad-fd") ||
           !strcmp(s,"standard-gpu-copyin-failure") || !strcmp(s,"standard-gpu-backend-failure")) {
  set_standard_node_inventory(); prepare_standard_nodes();
  bool blackwell=strstr(s,"blackwell")!=NULL;
  bool reuse_fd=strstr(s,"reuse")!=NULL;
  bool xfer_register=strstr(s,"-xfer")!=NULL;
  unsigned int gpu_minor=blackwell?0:1;
  int expected_backend=blackwell?HYBRID580_BACKEND_OPEN:HYBRID580_BACKEND_LEGACY;
  gpu_owner=expected_backend;
  struct inode gpu_inode={.i_rdev=makedev(NV_MAJOR_DEVICE_NUMBER,gpu_minor)};
  struct file gpu_front={.f_op=&hybrid_front_fops,.refs=1};
  assert(hybrid_front_open(&gpu_inode,&gpu_front)==0 && gpu_front.private_data);
  struct hybrid_front_gpu_file *gpu_state=gpu_front.private_data;
  assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_UNREGISTERED);
  assert(gpu_state->backend==(unsigned int)expected_backend);
  assert(!strcmp(gpu_state->bdf,blackwell?"0000:02:00.0":"0000:81:00.0"));
  assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,gpu_test_cmd,0)==-ENOTCONN);
  assert(gpu_ioctl_calls[0]==0 && gpu_ioctl_calls[1]==0);
  poll_table before_register_wait={0};
  assert(gpu_front.f_op->poll(&gpu_front,&before_register_wait)==0);
  assert(gpu_poll_calls[0]==0 && gpu_poll_calls[1]==0);
  struct inode ctl_inode={.i_rdev=makedev(NV_MAJOR_DEVICE_NUMBER,NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE)};
  struct file ctl_front={.f_op=&hybrid_front_fops,.refs=1};
  assert(hybrid_front_open(&ctl_inode,&ctl_front)==0 && ctl_front.private_data);
  struct file replacement_control_front={.f_op=&hybrid_front_fops,.refs=1};
  if(reuse_fd)
   assert(hybrid_front_open(&ctl_inode,&replacement_control_front)==0 &&
          replacement_control_front.private_data);
  installed_fds[9]=&ctl_front;
  nv_ioctl_register_fd_t request={.ctl_fd=9};
  nv_ioctl_xfer_t xfer={.cmd=NV_ESC_REGISTER_FD,.size=sizeof(request),.ptr=(NvP64)&request};
  if(!strcmp(s,"standard-gpu-register-fd-xfer-header-race"))
   xfer.cmd=NV_ESC_RM_CONTROL;
  unsigned int register_cmd=xfer_register ?
      _IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t) :
      _IOWR(NV_IOCTL_MAGIC,NV_ESC_REGISTER_FD,nv_ioctl_register_fd_t);
  unsigned long register_argument=xfer_register ? (unsigned long)&xfer : (unsigned long)&request;
  register_gpu_front=&gpu_front; register_control_front=&ctl_front;
  register_fd_reuse_front=reuse_fd ? &replacement_control_front : NULL;
  register_backend_control_front=NULL; register_bound_session=NULL;
  register_expected_session=((struct hybrid_front_file *)ctl_front.private_data)->sessions[expected_backend];
  register_replacement_session=reuse_fd ?
      ((struct hybrid_front_file *)replacement_control_front.private_data)->sessions[expected_backend] : NULL;
  if(!strcmp(s,"standard-gpu-register-fd-quarantine-race")) {
   struct hybrid_front_file *ctl_state=ctl_front.private_data;
   struct model_register_thread_args args={
    .gpu=&gpu_front,.command=register_cmd,.argument=register_argument,.result=0
   };
   pthread_t thread;
   mutex_lock(&ctl_state->transaction_lock);
   model_register_wait_mutex=&ctl_state->transaction_lock;
   model_register_wait_entered=false;
   mutex_lock_interruptible_hook=model_register_wait_hook;
   assert(!pthread_create(&thread,NULL,model_register_thread,&args));
   pthread_mutex_lock(&block_mutex);
   while(!model_register_wait_entered) pthread_cond_wait(&block_cond,&block_mutex);
   pthread_mutex_unlock(&block_mutex);
   ctl_state->quarantined=true;
   mutex_unlock(&ctl_state->transaction_lock);
   assert(!pthread_join(thread,NULL));
   mutex_lock_interruptible_hook=NULL;
   assert(args.result==-EXDEV);
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_UNREGISTERED);
   assert(!gpu_ioctl_calls[expected_backend] && !register_fd_calls);
   mutex_lock(&ctl_state->transaction_lock);
   ctl_state->quarantined=false;
   mutex_unlock(&ctl_state->transaction_lock);
   args.result=gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,register_argument);
   assert(args.result==0);
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_REGISTERED);
   assert(gpu_ioctl_calls[expected_backend]==1 && register_fd_calls==1 &&
          register_fd_matches==1);
  } else if(!strcmp(s,"standard-gpu-pending-quarantine-blocked")) {
   struct hybrid_front_file *ctl_state=ctl_front.private_data;
   assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,
                                         register_argument)==0);
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_REGISTERED);
   atomic_set(&ctl_state->quarantine_pending,1);
   int ioctls_before=gpu_ioctl_calls[expected_backend];
   assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,gpu_test_cmd,0)==-EIO);
   assert(gpu_ioctl_calls[expected_backend]==ioctls_before && register_fd_calls==1);
  } else if(!strcmp(s,"standard-gpu-bad-control")) {
   struct hybrid_front_file *ctl_state=ctl_front.private_data;
   ctl_state->catalog->entries[gpu_minor].bdf[5]='3';
   assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,(unsigned long)&request)==-EXDEV);
   ctl_state->catalog->entries[gpu_minor].bdf[5]=blackwell?'0':'8';
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_UNREGISTERED);
   assert(!gpu_ioctl_calls[expected_backend] && !register_fd_calls);
  } else if(!strcmp(s,"standard-gpu-bad-fd")) {
   request.ctl_fd=99;
   assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,(unsigned long)&request)==-EBADF);
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_UNREGISTERED);
   assert(!gpu_ioctl_calls[expected_backend] && !register_fd_calls);
  } else if(!strcmp(s,"standard-gpu-copyin-failure")) {
   from_fault=1;
   assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,(unsigned long)&request)==-EFAULT);
   from_fault=0;
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_UNREGISTERED);
   assert(!gpu_ioctl_calls[expected_backend] && !register_fd_calls);
  } else if(!strcmp(s,"standard-gpu-register-fd-xfer-bad-size")) {
   xfer.size=sizeof(request)-1;
   assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,register_argument)==-EINVAL);
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_UNREGISTERED);
   assert(!gpu_ioctl_calls[expected_backend] && !register_fd_calls);
  } else if(!strcmp(s,"standard-gpu-register-fd-xfer-copyin-failure")) {
   from_fault=1;
   assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,register_argument)==-EFAULT);
   from_fault=0;
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_UNREGISTERED);
   assert(!gpu_ioctl_calls[expected_backend] && !register_fd_calls);
  } else if(!strcmp(s,"standard-gpu-register-fd-xfer-inner-copyin-failure")) {
   from_fault_call=copy_from_user_calls+2;
   assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,register_argument)==-EFAULT);
   from_fault_call=0;
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_UNREGISTERED);
   assert(!gpu_ioctl_calls[expected_backend] && !register_fd_calls);
  } else if(!strcmp(s,"standard-gpu-register-fd-xfer-header-race")) {
   mutate_xfer_after_copy=1;
   assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,register_argument)==-ENOTCONN);
   assert(!mutate_xfer_after_copy && xfer.cmd==NV_ESC_REGISTER_FD);
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_UNREGISTERED);
   assert(!gpu_ioctl_calls[expected_backend] && !register_fd_calls);
  } else {
   if(!strcmp(s,"standard-gpu-register-fd-xfer-payload-race-blackwell"))
    mutate_register_fd_after_copy=1;
   register_fd_error=!strcmp(s,"standard-gpu-backend-failure")?-EIO:0;
   assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,register_argument)==
          register_fd_error);
   assert(gpu_ioctl_calls[expected_backend]==1 && register_fd_calls==1 && register_fd_matches==1);
   if(!strcmp(s,"standard-gpu-register-fd-xfer-payload-race-blackwell"))
    assert(!mutate_register_fd_after_copy && request.ctl_fd==99 &&
           register_bound_session==register_expected_session);
   if(reuse_fd) {
    assert(register_backend_control_front==&ctl_front);
    assert(gpu_state->control_front==&ctl_front);
   }
   if(register_fd_error) {
   assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_FAILED);
   assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,gpu_test_cmd,0)==-EIO);
    poll_table failed_wait={0};
    assert(gpu_front.f_op->poll(&gpu_front,&failed_wait)==EPOLLERR);
    assert(gpu_ioctl_calls[expected_backend]==1 && gpu_poll_calls[expected_backend]==0 &&
           association_wait_wakes==1);
   } else {
    assert(gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_REGISTERED);
    assert(association_wait_wakes==1);
    gpu_poll_masks[expected_backend]=POLLIN;
    poll_table after_register_wait={0};
    assert(gpu_front.f_op->poll(&gpu_front,&after_register_wait)==POLLIN);
    assert(gpu_poll_calls[expected_backend]==1);
    assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,register_cmd,register_argument)==
           (!strcmp(s,"standard-gpu-register-fd-xfer-payload-race-blackwell") ? -EBADF : -EINVAL));
    assert(register_fd_calls==1);
    if(strstr(s,"observed-node-ioctls")) {
     nv_ioctl_alloc_os_event_t event={.hClient=0x1234,.hDevice=0x5678,.fd=9};
     nv_ioctl_free_os_event_t free_event={.hClient=0x1234,.hDevice=0x5678,.fd=9};
     nv_ioctl_numa_info_t numa={0};
     unsigned int event_command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_ALLOC_OS_EVENT,
                                      nv_ioctl_alloc_os_event_t);
     unsigned int free_event_command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_FREE_OS_EVENT,
                                           nv_ioctl_free_os_event_t);
     unsigned int numa_command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_NUMA_INFO,
                                     nv_ioctl_numa_info_t);
     assert(event_command==0xc01046ceU && free_event_command==0xc01046cfU &&
            numa_command==0xc23046d7U);
     assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,event_command,
                                           (unsigned long)&event)==100+expected_backend);
     assert(gpu_ioctl_calls[expected_backend]==2 &&
            gpu_ioctl_command_seen[expected_backend]==event_command &&
            gpu_ioctl_argument_seen[expected_backend]==(unsigned long)&event);
     assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,free_event_command,
                                           (unsigned long)&free_event)==100+expected_backend);
     assert(gpu_ioctl_calls[expected_backend]==3 &&
            gpu_ioctl_command_seen[expected_backend]==free_event_command &&
            gpu_ioctl_argument_seen[expected_backend]==(unsigned long)&free_event);
     assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,numa_command,
                                           (unsigned long)&numa)==100+expected_backend);
     assert(gpu_ioctl_calls[expected_backend]==4 &&
            gpu_ioctl_command_seen[expected_backend]==numa_command &&
            gpu_ioctl_argument_seen[expected_backend]==(unsigned long)&numa);
     assert(gpu_ioctl_calls[1-expected_backend]==0 && calls[0]==0 && calls[1]==0);
     assert(ctl_front.f_op->unlocked_ioctl(&ctl_front,event_command,
                                           (unsigned long)&event)==-EINVAL);
     assert(ctl_front.f_op->unlocked_ioctl(&ctl_front,free_event_command,
                                           (unsigned long)&free_event)==-EINVAL);
     assert(ctl_front.f_op->unlocked_ioctl(&ctl_front,numa_command,
                                           (unsigned long)&numa)==-EINVAL);
     assert(gpu_ioctl_calls[expected_backend]==4 && gpu_ioctl_calls[1-expected_backend]==0 &&
            calls[0]==0 && calls[1]==0);
    } else {
     assert(gpu_front.f_op->unlocked_ioctl(&gpu_front,gpu_test_cmd,0)==100+expected_backend);
     assert(gpu_ioctl_calls[expected_backend]==2);
    }
   }
  }
  bool control_pinned=gpu_state->association_state==HYBRID_FRONT_GPU_STANDARD_REGISTERED;
  register_gpu_front=NULL; register_control_front=NULL; register_fd_reuse_front=NULL;
  register_expected_session=NULL; register_replacement_session=NULL;
  close_test_fd(9);
  assert((ctl_front.private_data!=NULL)==control_pinned);
  fput(&gpu_front);
  assert(gpu_front.private_data==NULL && ctl_front.private_data==NULL);
  if(reuse_fd) {
   assert(replacement_control_front.private_data!=NULL);
   fput(&replacement_control_front);
   assert(replacement_control_front.private_data==NULL);
  }
  hybrid580_standard_nodes_unregister_v1();
  assert(!standard_nodes_ready && standard_nodes_unregisters==1);
  return 0;
 } else if(!strcmp(s,"standard-control-open")) {
  set_standard_node_inventory(); prepare_standard_nodes();
  struct inode ctl_inode={.i_rdev=makedev(NV_MAJOR_DEVICE_NUMBER,NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE)};
  struct file ctl_front={.f_op=&hybrid_front_fops,.refs=1};
  assert(hybrid_front_open(&ctl_inode,&ctl_front)==0 && ctl_front.private_data);
  assert(hybrid580_standard_nodes_catalog_matches_v1(((struct hybrid_front_file *)ctl_front.private_data)->catalog));
  fput(&ctl_front); hybrid580_standard_nodes_unregister_v1();
  assert(!ctl_front.private_data && !standard_nodes_ready);
  return 0;
 } else if(!strcmp(s,"gpu-poll-legacy-lifetime") || !strcmp(s,"gpu-poll-open-lifetime")) {
  gpu_owner=!strcmp(s,"gpu-poll-open-lifetime")?HYBRID580_BACKEND_OPEN:HYBRID580_BACKEND_LEGACY;
  gpu_poll_masks[gpu_owner]=POLLIN|POLLPRI;
  assert(!open_gpu("0000:81:00.0")); int fd=last_gpu_request.gpu_fd;
  struct file *gpu_front=installed_fds[fd]; struct hybrid_front_gpu_file *gpu_state=gpu_front->private_data;
  struct file *backend_file=gpu_state->session->file;
  poll_table wait={._qproc=fake_poll_qproc};
  assert(gpu_front->f_op->poll);
  assert(gpu_front->f_op->poll(gpu_front,&wait)==(POLLIN|POLLPRI));
  assert(gpu_poll_calls[gpu_owner]==1 && gpu_poll_files[gpu_owner]==backend_file);
  assert(gpu_poll_tables[gpu_owner]==&wait && gate_poll_wait_calls==1 && poll_wait_calls==1);
  assert(poll_wait_files[0]==backend_file && poll_wait_queues[0]==&gpu_poll_waitqueues[gpu_owner]);
  assert(backend_file->refs==2); /* session + wait-table reference after callback */
  gpu_front->f_flags|=O_NONBLOCK;
  assert(gpu_front->f_op->poll(gpu_front,&wait)==(POLLIN|POLLPRI));
  assert(gpu_poll_calls[gpu_owner]==2 && gpu_poll_flags[gpu_owner]&O_NONBLOCK);
  assert(gate_poll_wait_calls==2 && poll_wait_calls==1); /* Gate stays watched; R580 skips backend registration for nonblocking files. */
  gpu_front->f_flags&=~O_NONBLOCK;
  assert(gpu_front->f_op->poll(gpu_front,&wait)==(POLLIN|POLLPRI));
  assert(gpu_poll_calls[gpu_owner]==3 && !(gpu_poll_flags[gpu_owner]&O_NONBLOCK));
  assert(gate_poll_wait_calls==3 && poll_wait_calls==2 && poll_wait_files[1]==backend_file);
  close_test_fd(fd);
  assert(gpu_puts[gpu_owner]==1 && backend_file->refs==2);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1);
  fput(poll_wait_files[0]); fput(poll_wait_files[1]);
  poll_wait_files[0]=poll_wait_files[1]=NULL;
  return 0;
 } else if(!strcmp(s,"gpu-poll-missing-backend-callback")) {
  gpu_owner=HYBRID580_BACKEND_OPEN; assert(!open_gpu("0000:81:00.0"));
  int fd=last_gpu_request.gpu_fd; struct file *gpu_front=installed_fds[fd];
  struct hybrid_front_gpu_file *gpu_state=gpu_front->private_data;
  struct file *backend_file=gpu_state->session->file;
  backend_file->f_op=&fake_backend_no_poll_fops;
  poll_table wait={._qproc=fake_poll_qproc};
  assert(gpu_front->f_op->poll);
  assert(gpu_front->f_op->poll(gpu_front,&wait)==POLLERR);
  assert(backend_file->refs==1 && !gpu_poll_calls[0] && !gpu_poll_calls[1] &&
         !poll_wait_calls && gate_poll_wait_calls==1);
  close_test_fd(fd); front_put(); assert(!front.private_data); return 0;
 } else if(!strcmp(s,"gpu-poll-epoll-lifetime")) {
  gpu_owner=HYBRID580_BACKEND_LEGACY; gpu_poll_masks[gpu_owner]=POLLIN;
  assert(!open_gpu("0000:81:00.0")); int fd=last_gpu_request.gpu_fd;
  struct file *gpu_front=installed_fds[fd]; struct hybrid_front_gpu_file *gpu_state=gpu_front->private_data;
  struct file *backend_file=gpu_state->session->file;
  get_file(gpu_front); /* epoll epitem holds the frontend open-file description. */
  poll_table wait={._qproc=fake_epoll_qproc};
  assert(gpu_front->f_op->poll(gpu_front,&wait)==POLLIN);
  assert(epoll_poll_qproc_calls==2 && gate_poll_wait_calls==1 &&
         epoll_poll_file_seen==backend_file);
  assert(epoll_poll_queue_seen==&gpu_poll_waitqueues[gpu_owner] && backend_file->refs==1);
  close_test_fd(fd);
  assert(gpu_puts[gpu_owner]==0 && backend_file->refs==1 && gpu_front->private_data==gpu_state);
  fput(gpu_front); /* EPOLL_CTL_DEL/epoll teardown drops its frontend reference. */
  assert(gpu_puts[gpu_owner]==1);
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1);
  return 0;
 } else if(!strcmp(s,"gpu-poll-control-reject")) {
  poll_table wait={._qproc=fake_poll_qproc};
  assert(front.f_op->poll && front.f_op->poll(&front,&wait)==0);
  assert(!poll_wait_calls && gate_poll_wait_calls==1 &&
         !gpu_poll_calls[0] && !gpu_poll_calls[1]);
 } else if(!strcmp(s,"gpu-poll-gated")) {
  gpu_owner=HYBRID580_BACKEND_OPEN; gpu_poll_masks[gpu_owner]=POLLIN;
  assert(!open_gpu("0000:81:00.0")); int fd=last_gpu_request.gpu_fd;
  struct file *gpu_front=installed_fds[fd];
  poll_table wait={._qproc=fake_poll_qproc};
  assert(!hybrid_front_admission_block());
  assert(gpu_front->f_op->poll(gpu_front,&wait)==0);
  assert(!gpu_poll_calls[0] && !gpu_poll_calls[1] && gate_poll_wait_calls==1);
  assert(!hybrid_front_admission_unblock());
  assert(gpu_front->f_op->poll(gpu_front,&wait)==POLLIN);
  assert(gpu_poll_calls[gpu_owner]==1 && gate_poll_wait_calls==2 && poll_wait_calls==1);
  close_test_fd(fd); front_put();
  fput(poll_wait_files[0]); poll_wait_files[0]=NULL;
  return 0;
 } else if(!strcmp(s,"gpu-mmap-legacy-lifetime") || !strcmp(s,"gpu-mmap-open-lifetime")) {
  gpu_owner=!strcmp(s,"gpu-mmap-open-lifetime")?HYBRID580_BACKEND_OPEN:HYBRID580_BACKEND_LEGACY;
  assert(!open_gpu("0000:81:00.0")); int fd=last_gpu_request.gpu_fd;
  struct file *gpu_front=installed_fds[fd]; assert(gpu_front && gpu_front->f_op->mmap);
  struct hybrid_front_gpu_file *gpu_state=gpu_front->private_data;
  struct file *backend_file=gpu_state->session->file;
  create_map_context(fd,gpu_front,NV01_MEMORY_LOCAL_USER);
  assert(gpu_map_calls[gpu_owner]==1 && gpu_map_context_files[gpu_owner]==backend_file);
  struct vm_area_struct vma={.vm_file=get_file(gpu_front),.vm_pgoff=0};
  assert(!gpu_front->f_op->mmap(gpu_front,&vma));
  assert(vma.vm_file==backend_file && gpu_mmap_calls[gpu_owner]==1);
  assert(gpu_mmap_files[gpu_owner]==backend_file && backend_file->refs==2);
  assert(((struct hybrid_front_file *)front.private_data)->stateful_started);
  close_test_fd(fd);
  assert(gpu_puts[gpu_owner]==1 && backend_file->refs==1);
  fput(vma.vm_file); /* VMA-held backend-file reference survives fd close. */
  front_put(); assert(!front.private_data && session_puts[0]==1 && session_puts[1]==1);
  return 0;
 } else if(!strcmp(s,"gpu-mmap-gated")) {
  gpu_owner=HYBRID580_BACKEND_OPEN;
  assert(!open_gpu("0000:81:00.0")); int fd=last_gpu_request.gpu_fd;
  struct file *gpu_front=installed_fds[fd];
  struct hybrid_front_gpu_file *gpu_state=gpu_front->private_data;
  struct file *backend_file=gpu_state->session->file;
  create_map_context(fd,gpu_front,NV01_MEMORY_LOCAL_USER);
  struct vm_area_struct vma={.vm_file=get_file(gpu_front),.vm_pgoff=0};
  assert(!hybrid_front_admission_block());
  assert(gpu_front->f_op->mmap(gpu_front,&vma)==-EAGAIN);
  assert(vma.vm_file==gpu_front && gpu_mmap_calls[gpu_owner]==0);
  assert(!hybrid_front_admission_unblock());
  assert(!gpu_front->f_op->mmap(gpu_front,&vma));
  assert(vma.vm_file==backend_file && gpu_mmap_calls[gpu_owner]==1);
  close_test_fd(fd); fput(vma.vm_file); front_put();
  return 0;
 } else if(!strcmp(s,"gpu-mmap-backend-error")) {
  gpu_owner=HYBRID580_BACKEND_OPEN; gpu_mmap_error[gpu_owner]=-EIO;
  assert(!open_gpu("0000:81:00.0")); int fd=last_gpu_request.gpu_fd;
  struct file *gpu_front=installed_fds[fd]; struct hybrid_front_gpu_file *gpu_state=gpu_front->private_data;
  struct file *backend_file=gpu_state->session->file;
  create_map_context(fd,gpu_front,NV01_MEMORY_LOCAL_USER);
  assert(gpu_map_calls[gpu_owner]==1 && gpu_map_context_files[gpu_owner]==backend_file);
  struct vm_area_struct vma={.vm_file=get_file(gpu_front),.vm_pgoff=0};
  assert(gpu_front->f_op->mmap(gpu_front,&vma)==-EIO);
  assert(vma.vm_file==backend_file && gpu_mmap_calls[gpu_owner]==1);
  fput(vma.vm_file); /* mmap core unwinds the switched VMA file on error. */
  assert(backend_file->refs==1);
  close_test_fd(fd); assert(gpu_puts[gpu_owner]==1);
  front_put(); assert(!front.private_data); return 0;
 } else if(!strcmp(s,"control-mmap-same-file") ||
           !strcmp(s,"control-mmap-separate-file")) {
  gpu_owner=HYBRID580_BACKEND_OPEN;
  struct file target;
  int fd=50;
  if(!strcmp(s,"control-mmap-same-file")) {
   installed_fds[fd]=get_file(&front);
  } else {
   target=(struct file){.f_op=&hybrid_front_fops,.refs=1,.private_data=(void *)1};
   assert(!hybrid_front_open(&inode,&target));
   installed_fds[fd]=&target;
  }
  create_map_context(fd,NULL,NV01_MEMORY_SYSTEM);
  assert(control_map_calls[gpu_owner]==1 && control_map_context_files[gpu_owner]);
  assert(control_map_clients[gpu_owner]==map_test_root &&
         control_map_devices[gpu_owner]==map_test_backend_device &&
         control_map_memories[gpu_owner]==map_test_backend_memory &&
         control_map_target_fds[gpu_owner]==fd);
  struct file *target_front=installed_fds[fd];
  struct hybrid_front_file *target_state=target_front->private_data;
  assert(target_state && target_state->pending_map_state==HYBRID_FRONT_MAP_READY &&
         target_state->pending_map_backend==HYBRID580_BACKEND_OPEN);
  struct vm_area_struct vma={.vm_file=get_file(target_front),.vm_pgoff=0,
                             .vm_start=0x10000000,.vm_end=0x10001000};
  assert(!target_front->f_op->mmap(target_front,&vma));
  assert(vma.vm_file==control_map_context_files[gpu_owner] &&
         control_mmap_calls[gpu_owner]==1 &&
         control_mmap_files[gpu_owner]==vma.vm_file &&
         target_state->pending_map_state==HYBRID_FRONT_MAP_CONSUMED);
  fput(vma.vm_file);
  NVOS34_PARAMETERS unmap={.hClient=map_test_root,.hDevice=map_test_device,
                           .hMemory=map_test_memory};
  unsigned int unmap_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_UNMAP_MEMORY,NVOS34_PARAMETERS);
  assert(!hybrid_front_ioctl(&front,unmap_cmd,(unsigned long)&unmap));
  assert(unmap.status==NV_OK && control_unmap_calls[gpu_owner]==1);
  nv_ioctl_nvos33_parameters_with_fd second={0};
  second.params.hClient=map_test_root; second.params.hDevice=map_test_device;
  second.params.hMemory=map_test_memory; second.params.length=4096; second.fd=fd;
  unsigned int map_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_MAP_MEMORY,
                             nv_ioctl_nvos33_parameters_with_fd);
  assert(hybrid_front_ioctl(&front,map_cmd,(unsigned long)&second)==-EBUSY);
  assert(control_map_calls[gpu_owner]==1);
  close_test_fd(fd);
  front_put(); assert(!front.private_data); return 0;
 } else if(!strcmp(s,"map-embedded-error-retry")) {
  gpu_owner=HYBRID580_BACKEND_OPEN;
  int fd=50; installed_fds[fd]=get_file(&front);
  nv_ioctl_nvos33_parameters_with_fd params={0};
  prepare_map_request(fd,NV01_MEMORY_SYSTEM,&params);
  unsigned int map_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_MAP_MEMORY,
                             nv_ioctl_nvos33_parameters_with_fd);
  control_map_status[gpu_owner]=NV_ERR_INVALID_STATE;
  assert(!hybrid_front_ioctl(&front,map_cmd,(unsigned long)&params));
  assert(params.params.status==NV_ERR_INVALID_STATE && control_map_calls[gpu_owner]==1);
  struct hybrid_front_file *state=front.private_data;
  assert(!state->quarantined && state->pending_map_state==HYBRID_FRONT_MAP_EMPTY);
  control_map_status[gpu_owner]=NV_OK;
  assert(!hybrid_front_ioctl(&front,map_cmd,(unsigned long)&params));
  assert(params.params.status==NV_OK && control_map_calls[gpu_owner]==2);
  assert(state->pending_map_state==HYBRID_FRONT_MAP_READY);
  struct vm_area_struct vma={.vm_file=get_file(&front),.vm_start=0x10000000,
                             .vm_end=0x10001000};
  assert(!front.f_op->mmap(&front,&vma));
  assert(vma.vm_file==control_map_context_files[gpu_owner] &&
         state->pending_map_state==HYBRID_FRONT_MAP_CONSUMED);
  fput(vma.vm_file); close_test_fd(fd); front_put();
  assert(!front.private_data); return 0;
 } else if(!strcmp(s,"map-transport-failure-poisons")) {
  gpu_owner=HYBRID580_BACKEND_OPEN;
  int fd=50; installed_fds[fd]=get_file(&front);
  nv_ioctl_nvos33_parameters_with_fd params={0};
  prepare_map_request(fd,NV01_MEMORY_SYSTEM,&params);
  unsigned int map_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_MAP_MEMORY,
                             nv_ioctl_nvos33_parameters_with_fd);
  control_map_transport[gpu_owner]=-EIO;
  assert(hybrid_front_ioctl(&front,map_cmd,(unsigned long)&params)==-EINVAL);
  struct hybrid_front_file *state=front.private_data;
  assert(params.params.status==0xffffffffU && control_map_calls[gpu_owner]==1 &&
         state->quarantined && state->pending_map_state==HYBRID_FRONT_MAP_POISONED);
  control_map_transport[gpu_owner]=0;
  assert(!hybrid_front_ioctl(&front,map_cmd,(unsigned long)&params));
  assert(params.params.status==NV_ERR_INVALID_STATE && control_map_calls[gpu_owner]==1);
  close_test_fd(fd); front_put(); assert(!front.private_data); return 0;
 } else if(!strcmp(s,"map-copyout-failure-poisons")) {
  gpu_owner=HYBRID580_BACKEND_OPEN;
  int fd=50; installed_fds[fd]=get_file(&front);
  nv_ioctl_nvos33_parameters_with_fd params={0};
  prepare_map_request(fd,NV01_MEMORY_SYSTEM,&params);
  unsigned int map_cmd=_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_MAP_MEMORY,
                             nv_ioctl_nvos33_parameters_with_fd);
  to_fault=1;
  assert(hybrid_front_ioctl(&front,map_cmd,(unsigned long)&params)==-EFAULT);
  to_fault=0;
  struct hybrid_front_file *state=front.private_data;
  assert(control_map_calls[gpu_owner]==1 && control_map_context_files[gpu_owner] &&
         state->quarantined && state->pending_map_state==HYBRID_FRONT_MAP_POISONED);
  close_test_fd(fd); front_put(); assert(!front.private_data); return 0;
 } else if(!strcmp(s,"device-mapping-update-route")) {
  prepare_device_object_test();
  subdevice_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  subdevice_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  memory_alloc_transport[0]=memory_alloc_transport[1]=NV_OK;
  memory_alloc_embedded[0]=memory_alloc_embedded[1]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, open_device=222, legacy_device=223;
  NvHandle open_memory=555, legacy_memory=556;
  struct hybrid_front_file *state=front.private_data;
  struct hybrid_front_root *root_state;
  assert(!request_device_alloc(root,open_device,0,root,0) &&
         device_packet.status==NV_OK);
  assert(!request_device_alloc(root,legacy_device,1,root,0) &&
         device_packet.status==NV_OK);
  NvHandle open_subdevice=559;
  assert(!request_subdevice_alloc(root,open_device,open_subdevice,0,0) &&
         device_packet.status==NV_OK);
  NV_MEMORY_ALLOCATION_PARAMS open_params={.size=0x2000,.alignment=0x1000};
  NV_MEMORY_ALLOCATION_PARAMS legacy_params={.size=0x3000,.alignment=0x1000};
  assert(!request_memory_alloc(root,open_device,open_memory,
                               NV01_MEMORY_SYSTEM,&open_params) &&
         device_packet.status==NV_OK);
  assert(!request_memory_alloc(root,legacy_device,legacy_memory,
                               NV01_MEMORY_LOCAL_USER,&legacy_params) &&
         device_packet.status==NV_OK);
  root_state=hybrid_front_find_root(state,root);
  assert(root_state);
  unsigned int command=_IOWR(NV_IOCTL_MAGIC,
      NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO,NVOS56_PARAMETERS);
  unsigned int malformed_command=_IOC(_IOC_READ|_IOC_WRITE,NV_IOCTL_MAGIC,
      NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO,sizeof(NVOS56_PARAMETERS)-sizeof(NvU32));
  NVOS56_PARAMETERS request={.hClient=root,.hDevice=open_device,
      .hMemory=legacy_memory,.pOldCpuAddress=(NvP64)(uintptr_t)0x00007fff12345678ULL,
      .pNewCpuAddress=(NvP64)(uintptr_t)0x00007fff23456789ULL,
      .status=0xffffffffU};
  assert(hybrid_front_ioctl(&front,malformed_command,(unsigned long)&request)==-EINVAL &&
         !mapping_update_calls[0] && !mapping_update_calls[1]);
  assert(!hybrid_front_ioctl(&front,command,(unsigned long)&request));
  assert(request.status==NV_ERR_INVALID_ARGUMENT &&
         !mapping_update_calls[0] && !mapping_update_calls[1]);

  /* A same-backend pair can still name different physical GPUs. Construct a
   * second tracked device and memory object to prove the ancestry check rejects
   * that alias before the provider sees NVOS56. */
  struct hybrid_front_rm_object *other_gpu=kzalloc(sizeof(*other_gpu),GFP_KERNEL);
  struct hybrid_front_rm_object *other_memory=kzalloc(sizeof(*other_memory),GFP_KERNEL);
  assert(other_gpu && other_memory);
  *other_gpu=(struct hybrid_front_rm_object){.handle=557,.backend_handle=0xb0000557,
      .parent_handle=root,.backend_parent_handle=root_state->root.slot[HYBRID580_BACKEND_OPEN].handle,
      .class_id=NV01_DEVICE_0,.backend=HYBRID580_BACKEND_OPEN,
      .backend_device_instance=99,.next=root_state->objects};
  root_state->objects=other_gpu; ++root_state->object_count; ++state->object_count;
  *other_memory=(struct hybrid_front_rm_object){.handle=558,.backend_handle=0xc0000558,
      .parent_handle=other_gpu->handle,.backend_parent_handle=other_gpu->backend_handle,
      .class_id=NV01_MEMORY_SYSTEM,.backend=HYBRID580_BACKEND_OPEN,
      .next=root_state->objects};
  root_state->objects=other_memory; ++root_state->object_count; ++state->object_count;
  request=(NVOS56_PARAMETERS){.hClient=root,.hDevice=open_device,
      .hMemory=other_memory->handle,.pOldCpuAddress=(NvP64)(uintptr_t)0x123456789abcdef0ULL,
      .pNewCpuAddress=(NvP64)(uintptr_t)0xfedcba9876543210ULL,
      .status=0xffffffffU};
  assert(!hybrid_front_ioctl(&front,command,(unsigned long)&request) &&
         request.status==NV_ERR_INVALID_ARGUMENT &&
         !mapping_update_calls[0] && !mapping_update_calls[1]);

  struct hybrid_front_rm_object *tracked_memory=
      hybrid_front_find_object(root_state,open_memory);
  struct hybrid_front_rm_object *tracked_open_device=
      hybrid_front_find_object(root_state,open_device);
  struct hybrid_front_rm_object *tracked_open_subdevice=
      hybrid_front_find_object(root_state,open_subdevice);
  struct hybrid_front_rm_object *tracked_legacy_device=
      hybrid_front_find_object(root_state,legacy_device);
  struct hybrid_front_rm_object *tracked_legacy_memory=
      hybrid_front_find_object(root_state,legacy_memory);
  assert(tracked_memory && tracked_open_device && tracked_open_subdevice &&
         tracked_legacy_device && tracked_legacy_memory);
  NvU32 original_class=tracked_memory->class_id;
  tracked_memory->class_id=NV01_ROOT_CLIENT;
  request=(NVOS56_PARAMETERS){.hClient=root,.hDevice=open_device,
      .hMemory=open_memory,.pOldCpuAddress=(NvP64)(uintptr_t)0x00007fff12345678ULL,
      .pNewCpuAddress=(NvP64)(uintptr_t)0x00007fff23456789ULL,
      .status=0xffffffffU};
  assert(!hybrid_front_ioctl(&front,command,(unsigned long)&request));
  assert(request.status==NV_ERR_INVALID_ARGUMENT &&
         !mapping_update_calls[0] && !mapping_update_calls[1]);
  tracked_memory->class_id=original_class;

  /* Give frontend handles deliberately different backend-local values. The
   * provider packet must contain the translated handles and unchanged scalar
   * CPU mapping keys. */
  root_state->root.slot[HYBRID580_BACKEND_OPEN].handle=0xa0000011;
  tracked_open_device->backend_handle=0xb0000022;
  tracked_open_device->backend_parent_handle=0xa0000011;
  tracked_open_subdevice->backend_handle=0xb0000077;
  tracked_open_subdevice->backend_parent_handle=0xb0000022;
  tracked_memory->backend_handle=0xc0000055;
  tracked_memory->backend_parent_handle=0xb0000022;
  root_state->root.slot[HYBRID580_BACKEND_LEGACY].handle=0xa0000033;
  tracked_legacy_device->backend_handle=0xb0000044;
  tracked_legacy_device->backend_parent_handle=0xa0000033;
  tracked_legacy_memory->backend_handle=0xc0000066;
  tracked_legacy_memory->backend_parent_handle=0xb0000044;

  mapping_update_embedded[HYBRID580_BACKEND_OPEN]=NV_ERR_INVALID_STATE;
  request=(NVOS56_PARAMETERS){.hClient=root,.hDevice=open_device,
      .hMemory=open_memory,.pOldCpuAddress=(NvP64)(uintptr_t)0x00007fff12345678ULL,
      .pNewCpuAddress=(NvP64)(uintptr_t)0x00007fff23456789ULL,
      .status=0xffffffffU};
  assert(!hybrid_front_ioctl(&front,command,(unsigned long)&request));
  assert(request.status==NV_ERR_INVALID_STATE &&
         mapping_update_calls[HYBRID580_BACKEND_OPEN]==1 &&
         mapping_update_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         !((struct hybrid_front_file *)front.private_data)->quarantined);
  mapping_update_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  request.status=0xffffffffU;
  assert(!hybrid_front_ioctl(&front,command,(unsigned long)&request));
  assert(request.status==NV_OK &&
         mapping_update_calls[HYBRID580_BACKEND_OPEN]==2 &&
         mapping_update_calls[HYBRID580_BACKEND_LEGACY]==0);
  assert(mapping_update_packets[HYBRID580_BACKEND_OPEN].hClient==0xa0000011 &&
         mapping_update_packets[HYBRID580_BACKEND_OPEN].hDevice==
         0xb0000022 &&
         mapping_update_packets[HYBRID580_BACKEND_OPEN].hMemory==
         0xc0000055 &&
         mapping_update_packets[HYBRID580_BACKEND_OPEN].pOldCpuAddress==
         (NvP64)(uintptr_t)0x00007fff12345678ULL &&
         mapping_update_packets[HYBRID580_BACKEND_OPEN].pNewCpuAddress==
         (NvP64)(uintptr_t)0x00007fff23456789ULL);

  request=(NVOS56_PARAMETERS){.hClient=root,.hDevice=open_subdevice,
      .hMemory=open_memory,.pOldCpuAddress=(NvP64)(uintptr_t)0x00007fff3456789aULL,
      .pNewCpuAddress=(NvP64)(uintptr_t)0x00007fff456789abULL,
      .status=0xffffffffU};
  assert(!hybrid_front_ioctl(&front,command,(unsigned long)&request) &&
         request.status==NV_OK &&
         mapping_update_calls[HYBRID580_BACKEND_OPEN]==3 &&
         mapping_update_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         mapping_update_packets[HYBRID580_BACKEND_OPEN].hDevice==0xb0000077 &&
         mapping_update_packets[HYBRID580_BACKEND_OPEN].hMemory==0xc0000055);

  request=(NVOS56_PARAMETERS){.hClient=root,.hDevice=legacy_device,
      .hMemory=legacy_memory,.pOldCpuAddress=(NvP64)(uintptr_t)0x123456789ULL,
      .pNewCpuAddress=(NvP64)(uintptr_t)0x23456789aULL,
      .status=0xffffffffU};
  assert(!hybrid_front_ioctl(&front,command,(unsigned long)&request));
  assert(request.status==NV_OK &&
         mapping_update_calls[HYBRID580_BACKEND_OPEN]==3 &&
         mapping_update_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         mapping_update_packets[HYBRID580_BACKEND_LEGACY].hClient==0xa0000033 &&
         mapping_update_packets[HYBRID580_BACKEND_LEGACY].hDevice==
             0xb0000044 &&
         mapping_update_packets[HYBRID580_BACKEND_LEGACY].hMemory==
             0xc0000066 &&
         mapping_update_packets[HYBRID580_BACKEND_LEGACY].pOldCpuAddress==
             (NvP64)(uintptr_t)0x123456789ULL &&
         mapping_update_packets[HYBRID580_BACKEND_LEGACY].pNewCpuAddress==
             (NvP64)(uintptr_t)0x23456789aULL);

  mapping_update_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_OPERATING_SYSTEM;
  request=(NVOS56_PARAMETERS){.hClient=root,.hDevice=open_device,
      .hMemory=open_memory,.pOldCpuAddress=(NvP64)(uintptr_t)0x1000,
      .pNewCpuAddress=(NvP64)(uintptr_t)0x2000,.status=0xffffffffU};
  assert(hybrid_front_ioctl(&front,command,(unsigned long)&request)==-EINVAL);
  assert(request.status==0xffffffffU &&
         mapping_update_calls[HYBRID580_BACKEND_OPEN]==4 &&
         ((struct hybrid_front_file *)front.private_data)->quarantined);
  front_put(); assert(!front.private_data); return 0;
 } else if(!strcmp(s,"device-mapping-update-copyout-poison")) {
  prepare_device_object_test();
  memory_alloc_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  memory_alloc_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  mapping_update_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  mapping_update_embedded[HYBRID580_BACKEND_OPEN]=NV_OK;
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew, gpu=222, memory=555;
  assert(!request_device_alloc(root,gpu,0,root,0) &&
         device_packet.status==NV_OK);
  NV_MEMORY_ALLOCATION_PARAMS memory_params={.size=0x2000,.alignment=0x1000};
  assert(!request_memory_alloc(root,gpu,memory,NV01_MEMORY_SYSTEM,
                               &memory_params) && device_packet.status==NV_OK);
  unsigned int command=_IOWR(NV_IOCTL_MAGIC,
      NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO,NVOS56_PARAMETERS);
  NVOS56_PARAMETERS request={.hClient=root,.hDevice=gpu,.hMemory=memory,
      .pOldCpuAddress=(NvP64)(uintptr_t)0x70001000,
      .pNewCpuAddress=(NvP64)(uintptr_t)0x70002000,.status=0x12345678U};
  to_fault=1;
  assert(hybrid_front_ioctl(&front,command,(unsigned long)&request)==-EFAULT);
  to_fault=0;
  struct hybrid_front_file *state=front.private_data;
  assert(request.status==0x12345678U &&
         mapping_update_calls[HYBRID580_BACKEND_OPEN]==1 && state &&
         state->quarantined);
  request.status=0xffffffffU;
  assert(!hybrid_front_ioctl(&front,command,(unsigned long)&request) &&
         request.status==NV_ERR_INVALID_STATE &&
         mapping_update_calls[HYBRID580_BACKEND_OPEN]==1 &&
         state->quarantined);
  front_put(); assert(!front.private_data); return 0;
 } else if(!strcmp(s,"control-mmap-error-retry")) {
  gpu_owner=HYBRID580_BACKEND_OPEN;
  int fd=50; installed_fds[fd]=get_file(&front);
  create_map_context(fd,NULL,NV01_MEMORY_SYSTEM);
  struct hybrid_front_file *state=front.private_data;
  control_mmap_error[gpu_owner]=-EIO;
  struct vm_area_struct vma={.vm_file=get_file(&front),.vm_start=0x10000000,
                             .vm_end=0x10001000};
  assert(front.f_op->mmap(&front,&vma)==-EIO);
  assert(vma.vm_file==control_map_context_files[gpu_owner] &&
         state->pending_map_state==HYBRID_FRONT_MAP_READY);
  fput(vma.vm_file);
  control_mmap_error[gpu_owner]=0;
  vma=(struct vm_area_struct){.vm_file=get_file(&front),.vm_start=0x10000000,
                              .vm_end=0x10001000};
  assert(!front.f_op->mmap(&front,&vma));
  assert(vma.vm_file==control_map_context_files[gpu_owner] &&
         state->pending_map_state==HYBRID_FRONT_MAP_CONSUMED);
  fput(vma.vm_file); close_test_fd(fd); front_put();
  assert(!front.private_data); return 0;
 } else if(!strcmp(s,"gpu-mmap-control-reject")) {
  struct vm_area_struct vma={.vm_file=get_file(&front)};
  assert(front.f_op->mmap && front.f_op->mmap(&front,&vma)==-EINVAL);
  assert(vma.vm_file==&front && !gpu_mmap_calls[0] && !gpu_mmap_calls[1]);
  fput(vma.vm_file);
 } else if(!strcmp(s,"gpu-mmap-interrupted")) {
  gpu_owner=HYBRID580_BACKEND_LEGACY; assert(!open_gpu("0000:81:00.0")); int fd=last_gpu_request.gpu_fd;
  struct file *gpu_front=installed_fds[fd]; struct vm_area_struct vma={.vm_file=get_file(gpu_front)};
  interrupt_lock=1;
  assert(gpu_front->f_op->mmap(gpu_front,&vma)==-EINTR);
  interrupt_lock=0;
  assert(vma.vm_file==gpu_front && !gpu_mmap_calls[0] && !gpu_mmap_calls[1]);
  fput(vma.vm_file); close_test_fd(fd); assert(gpu_puts[gpu_owner]==1);
 } else if(!strcmp(s,"gpu-no-owner")) {
  gpu_owner=-1; assert(open_gpu("0000:81:00.0")==-ENODEV);
  assert(gpu_create_attempts[0]==1 && gpu_create_attempts[1]==0 && !gpu_puts[0] && !gpu_puts[1]);
 } else if(!strcmp(s,"gpu-invalid-bdf")) {
  assert(open_gpu("../../bad")==-EINVAL && !gpu_create_attempts[0] && !gpu_create_attempts[1]);
 } else if(!strcmp(s,"gpu-malformed-request")) {
  struct hybrid580_open_gpu_v1 bad={.struct_size=sizeof(bad),.bdf="0000:81:00.0"};
  bad.flags=1; assert(hybrid_front_ioctl(&front,HYBRID580_IOCTL_OPEN_GPU,(unsigned long)&bad)==-EINVAL);
  bad=(struct hybrid580_open_gpu_v1){.struct_size=sizeof(bad)-1,.bdf="0000:81:00.0"};
  assert(hybrid_front_ioctl(&front,HYBRID580_IOCTL_OPEN_GPU,(unsigned long)&bad)==-EINVAL);
  bad=(struct hybrid580_open_gpu_v1){.struct_size=sizeof(bad),.bdf="0000:81:00.8"};
  assert(hybrid_front_ioctl(&front,HYBRID580_IOCTL_OPEN_GPU,(unsigned long)&bad)==-EINVAL);
  bad=(struct hybrid580_open_gpu_v1){.struct_size=sizeof(bad),.bdf="0000:81:00.0",.reserved={1,0}};
  assert(hybrid_front_ioctl(&front,HYBRID580_IOCTL_OPEN_GPU,(unsigned long)&bad)==-EINVAL);
  assert(!gpu_create_attempts[0] && !gpu_create_attempts[1]);
 } else if(!strcmp(s,"gpu-create-failure")) {
  gpu_create_error[0]=-ENOMEM; assert(open_gpu("0000:81:00.0")==-ENOMEM);
  assert(gpu_create_attempts[0]==1 && !gpu_create_attempts[1] && !gpu_puts[0]);
 } else if(!strcmp(s,"gpu-copyout-failure")) {
  to_fault=1; assert(open_gpu("0000:81:00.0")==-EFAULT); to_fault=0;
  assert(!installed_fds[40] && !fd_reserved[40] && gpu_puts[0]==1 && front.refs==1);
 } else if(!strcmp(s,"gpu-copyin-failure")) {
  from_fault=1; assert(open_gpu("0000:81:00.0")==-EFAULT); from_fault=0;
  assert(!gpu_create_attempts[0] && !gpu_create_attempts[1] && !installed_fds[40]);
 } else if(!strcmp(s,"gpu-anon-file-failure")) {
  fail_anon_file=1; assert(open_gpu("0000:81:00.0")==-ENOMEM);
  assert(gpu_puts[0]==1 && !installed_fds[40] && front.refs==1);
 } else if(!strcmp(s,"gpu-fd-allocation-failure")) {
  fail_fd_alloc=1; assert(open_gpu("0000:81:00.0")==-EMFILE);
  assert(!installed_fds[40] && gpu_puts[0]==1 && front.refs==1);
 } else if(!strcmp(s,"gpu-open-ioctl-reject")) {
  assert(hybrid_front_ioctl(&front,_IOWR(HYBRID580_IOCTL_MAGIC,2,struct hybrid580_open_gpu_v1),0)==-ENOTTY);
 } else if(!strcmp(s,"projection")) {
  struct file *a=hybrid_front_project_legacy(&front,true), *b=hybrid_front_project_open(&front,true);
  assert(a && b && a!=b && a->refs==2 && b->refs==2); --a->refs; --b->refs;
  assert(!hybrid_front_project_legacy(&front,false) && !hybrid_front_project_open(&front,false));
  assert(!hybrid_front_project_open(NULL,true)); struct file bad={0}; assert(!hybrid_front_project_legacy(&bad,true));
 } else if(!strcmp(s,"format-reject")) {
  unsigned int bad[]={_IOWR('X',NV_ESC_RM_ALLOC,NVOS21_PARAMETERS),_IOR(NV_IOCTL_MAGIC,NV_ESC_RM_ALLOC,NVOS21_PARAMETERS),_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_ALLOC,NvU32),_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_FREE,NVOS21_PARAMETERS),_IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_CONTROL,NVOS54_PARAMETERS)};
  for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++)
   assert(hybrid_front_ioctl(&front,bad[i],(unsigned long)&p21)==(i==4?-ENOTTY:-EINVAL));
  assert(!calls[0] && !calls[1]);
 } else if(!strcmp(s,"copy-in-fail")) { from_fault=1; assert(alloc_root(false)==-EFAULT); assert(!calls[0] && !calls[1]); }
 else if(!strcmp(s,"interrupted")) { interrupt_lock=1; assert(alloc_root(false)==-EINTR); assert(!calls[0]); interrupt_lock=0; }
 else if(!strcmp(s,"copy-out-fail")) { to_fault=1; assert(alloc_root(false)==-EFAULT); assert(((struct hybrid_front_file *)front.private_data )->roots->root.state==HYBRID_ROOT_ACTIVE); assert(!frees[0]); }
 else if(!strcmp(s,"nested-reject")) { p64=(NVOS64_PARAMETERS){.hClass=NV01_ROOT_CLIENT,.pAllocParms=(NvP64)1}; assert(!hybrid_front_ioctl(&front,alloc64_cmd,(unsigned long)&p64)); assert(p64.status==NV_ERR_INVALID_ARGUMENT && !calls[0]); }
 else if(!strcmp(s,"alloc-quarantine")) { alloc_error_backend=1; assert(!alloc_root(false)); assert(p21.status!=NV_OK); assert(((struct hybrid_front_file *)front.private_data )->roots->root.state==HYBRID_ROOT_QUARANTINED); assert(frees[0]==1 && !frees[1]); }
 else if(!strcmp(s,"free-quarantine")) {
  assert(!alloc_root(true) && p64.status==NV_OK); free_error_backend=1;
  NVOS00_PARAMETERS p={.hRoot=p64.hObjectNew,.hObjectOld=p64.hObjectNew}; assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&p));
  assert(p.status!=NV_OK && frees[0]==1 && frees[1]==1);
 } else if(!strcmp(s,"free-reject")) {
  NVOS00_PARAMETERS p={.hRoot=987,.hObjectOld=987}; assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&p)); assert(p.status==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(!alloc_root(false)); p.hRoot=1; assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&p)); assert(p.status==NV_ERR_INVALID_OBJECT_HANDLE && !frees[0]);
 } else if(!strcmp(s,"uvm-owner-dup-memory-provider-route")) {
  struct file other={.f_op=&hybrid_front_fops,.private_data=(void *)1,.refs=1};
  NvHandle device1,memory1,generated_device2,generated_memory2;
  NvHandle root1=prepare_uvm_owner_objects(
      &front,HYBRID580_BACKEND_LEGACY,&device1,&memory1);
  struct hybrid_front_file *state1=front.private_data;
  struct hybrid_front_root *record1=hybrid_front_find_root(state1,root1);
  struct hybrid_front_rm_object *object1=hybrid_front_find_object(record1,memory1);
  assert(record1 && object1);
  next_root=root1; assert(!hybrid_front_open(&inode,&other));
  NvHandle root2=prepare_uvm_owner_objects(
      &other,HYBRID580_BACKEND_OPEN,&generated_device2,&generated_memory2);
  struct hybrid_front_file *state2=other.private_data;
  struct hybrid_front_root *record2=hybrid_front_find_root(state2,root2);
  struct hybrid_front_rm_object *device_object2=
      hybrid_front_find_object(record2,generated_device2);
  struct hybrid_front_rm_object *object2=
      hybrid_front_find_object(record2,generated_memory2);
  assert(record2 && device_object2 && object2 && root2==root1);
  device_object2->handle=device1;
  object2->handle=memory1;
  object2->parent_handle=device1;
  object2->backend_handle=0xdecafbadU;
  assert(hybrid_front_find_object(record2,memory1)==object2 &&
         hybrid_front_find_object(record2,device1)==device_object2);
  installed_fds[50]=get_file(&front);
  installed_fds[51]=get_file(&other);

  struct hybrid580_frontend_memory_owner legacy_owner={0},open_owner={0};
  assert(hybrid580_frontend_uvm_memory_owner_pin_v1(
      50,root1,memory1,&legacy_owner)==NV_OK);
  assert(hybrid580_frontend_uvm_memory_owner_pin_v1(
      51,root1,memory1,&open_owner)==NV_OK);
  assert(legacy_owner.backend==HYBRID580_BACKEND_LEGACY &&
         open_owner.backend==HYBRID580_BACKEND_OPEN);
  assert(legacy_owner.backend_root==root1 &&
         legacy_owner.backend_memory==object1->backend_handle);
  assert(open_owner.backend_root==root2 &&
         open_owner.backend_memory==0xdecafbadU);
  assert(atomic_read(&object1->uvm_memory_pins)==1 &&
         atomic_read(&object2->uvm_memory_pins)==1);

  struct hybrid580_uvm_device_registry devices={0};
  struct hybrid580_uvm_typed_child_registry children={0};
  struct hybrid580_uvm_typed_child_entry legacy_child={0},open_child={0};
  unsigned char open_uuid[HYBRID580_UVM_GPU_UUID_BYTES]={0x41};
  unsigned char legacy_uuid[HYBRID580_UVM_GPU_UUID_BYTES]={0x52};
  assert(hybrid580_uvm_device_registry_record(
      &devices,0x3000,HYBRID580_UVM_PROVIDER_OPEN,open_uuid)==
      HYBRID580_UVM_DEVICE_REGISTRY_OK);
  assert(hybrid580_uvm_device_registry_record(
      &devices,0x4000,HYBRID580_UVM_PROVIDER_LEGACY,legacy_uuid)==
      HYBRID580_UVM_DEVICE_REGISTRY_OK);
  struct integrated_uvm_dup_probe open_probe={
      .expected_device=0x3000,
      .expected_client=(uint32_t)open_owner.backend_root,
      .expected_memory=(uint32_t)open_owner.backend_memory,
      .output_handle=0xa001U};
  struct integrated_uvm_dup_probe legacy_probe={
      .expected_device=0x4000,
      .expected_client=(uint32_t)legacy_owner.backend_root,
      .expected_memory=(uint32_t)legacy_owner.backend_memory,
      .output_handle=0xa002U};
  struct hybrid580_uvm_dup_memory_backend_ops open_ops={
      .context=&open_probe,.provider=HYBRID580_UVM_PROVIDER_OPEN,
      .duplicate=integrated_uvm_duplicate,.release=integrated_uvm_release};
  struct hybrid580_uvm_dup_memory_backend_ops legacy_ops={
      .context=&legacy_probe,.provider=HYBRID580_UVM_PROVIDER_LEGACY,
      .duplicate=integrated_uvm_duplicate,.release=integrated_uvm_release};
  enum hybrid580_uvm_provider legacy_provider=HYBRID580_UVM_PROVIDER_LEGACY;
  enum hybrid580_uvm_provider open_provider=HYBRID580_UVM_PROVIDER_OPEN;
  uintptr_t duplicate=UINTPTR_MAX;
  int quarantine=1;
  assert(hybrid580_uvm_dup_memory_route_duplicate(
      &devices,&children,&legacy_child,0x3000,legacy_provider,
      (uint32_t)legacy_owner.backend_root,
      (uint32_t)legacy_owner.backend_memory,NULL,open_ops,legacy_ops,
      0xe0012201U,0xe0012202U,0xe0012204U,&duplicate,&quarantine)==
      0xe0012204U);
  assert(duplicate==0 && !quarantine && !open_probe.duplicate_calls &&
         !legacy_probe.duplicate_calls);
  assert(hybrid580_uvm_dup_memory_route_duplicate(
      &devices,&children,&legacy_child,0x4000,legacy_provider,
      (uint32_t)legacy_owner.backend_root,
      (uint32_t)legacy_owner.backend_memory,NULL,open_ops,legacy_ops,
      0xe0012201U,0xe0012202U,0xe0012204U,&duplicate,&quarantine)==0);
  assert(duplicate==0xa002U && !quarantine && !open_probe.duplicate_calls &&
         legacy_probe.duplicate_calls==1);
  assert(hybrid580_uvm_dup_memory_route_duplicate(
      &devices,&children,&open_child,0x3000,open_provider,
      (uint32_t)open_owner.backend_root,
      (uint32_t)open_owner.backend_memory,NULL,open_ops,legacy_ops,
      0xe0012201U,0xe0012202U,0xe0012204U,&duplicate,&quarantine)==0);
  assert(duplicate==0xa001U && !quarantine && open_probe.duplicate_calls==1 &&
         legacy_probe.duplicate_calls==1);
  uint32_t backend_status=UINT32_MAX;
  struct hybrid580_uvm_typed_child_entry *removed=NULL;
  assert(hybrid580_uvm_dup_memory_route_release(
      &devices,&children,0x4000,0xa002U,open_ops,legacy_ops,
      &backend_status,&removed)==HYBRID580_UVM_TYPED_CHILD_OK);
  assert(backend_status==0 && removed==&legacy_child &&
         legacy_probe.release_calls==1 && legacy_probe.last_released==0xa002U);
  assert(hybrid580_uvm_dup_memory_route_release(
      &devices,&children,0x3000,0xa001U,open_ops,legacy_ops,
      &backend_status,&removed)==HYBRID580_UVM_TYPED_CHILD_OK);
  assert(backend_status==0 && removed==&open_child &&
         open_probe.release_calls==1 && open_probe.last_released==0xa001U);
  assert(hybrid580_uvm_typed_child_registry_count(&children)==0);

  hybrid580_frontend_uvm_memory_owner_unpin_v1(&legacy_owner);
  hybrid580_frontend_uvm_memory_owner_unpin_v1(&open_owner);
  assert(!legacy_owner.pin && !open_owner.pin &&
         !atomic_read(&object1->uvm_memory_pins) &&
         !atomic_read(&object2->uvm_memory_pins));
  close_test_fd(50); close_test_fd(51); front_put(); fput(&other);
  assert(!front.private_data && !other.private_data &&
         session_puts[0]==2 && session_puts[1]==2);
  return 0;
 } else if(!strcmp(s,"uvm-owner-control-fd-lifetime")) {
  struct file other={.f_op=&hybrid_front_fops,.private_data=(void *)1,.refs=1};
  const unsigned int backend=HYBRID580_BACKEND_LEGACY;
  NvHandle device1,memory1,device2,memory2;
  NvHandle root1=prepare_uvm_owner_objects(&front,backend,&device1,&memory1);
  struct hybrid_front_file *state1=front.private_data;
  struct hybrid_front_root *record1=hybrid_front_find_root(state1,root1);
  struct hybrid_front_rm_object *object1=hybrid_front_find_object(record1,memory1);
  assert(record1 && object1);
  NvHandle backend_memory1=object1->backend_handle;
  next_root=root1; assert(!hybrid_front_open(&inode,&other));
  NvHandle root2=prepare_uvm_owner_objects(&other,backend,&device2,&memory2);
  struct hybrid_front_file *state2=other.private_data;
  struct hybrid_front_root *record2=hybrid_front_find_root(state2,root2);
  struct hybrid_front_rm_object *object2=hybrid_front_find_object(record2,memory2);
  assert(record2 && object2 && root2==root1 && memory2==memory1 && device2==device1);
  object2->backend_handle=0xdecafbadU;
  installed_fds[50]=get_file(&front); installed_fds[51]=get_file(&other);
  struct hybrid580_frontend_memory_owner rejected={.backend=99,.pin=(void *)1};
  assert(hybrid580_frontend_uvm_memory_owner_pin_v1(127,root1,memory1,&rejected)==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(!rejected.pin && rejected.backend==0);
  rejected=(struct hybrid580_frontend_memory_owner){.backend=99,.pin=(void *)1};
  assert(hybrid580_frontend_uvm_memory_owner_pin_v1(50,root1+1,memory1,&rejected)==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(!rejected.pin && rejected.backend==0 && !atomic_read(&object1->uvm_memory_pins));
  mutex_lock(&state1->transaction_lock);
  assert(hybrid580_frontend_uvm_memory_owner_pin_v1(50,root1,memory1,&rejected)==NV_ERR_NOT_READY);
  mutex_unlock(&state1->transaction_lock);
  assert(!rejected.pin && !atomic_read(&object1->uvm_memory_pins));
  struct hybrid580_frontend_memory_owner owner1={0},owner2={0};
  assert(hybrid580_frontend_uvm_memory_owner_pin_v1(50,root1,memory1,&owner1)==NV_OK);
  assert(hybrid580_frontend_uvm_memory_owner_pin_v1(51,root1,memory1,&owner2)==NV_OK);
  assert(owner1.backend==backend && owner1.backend_root==root1 &&
         owner1.backend_memory==backend_memory1);
  assert(owner2.backend==backend && owner2.backend_root==root2 &&
         owner2.backend_memory==0xdecafbadU);
  int original_file_refs=front.refs;
  int replacement_file_refs=other.refs;
  close_test_fd(50);
  assert(front.refs+1==original_file_refs && front.private_data);
  installed_fds[50]=get_file(&other); /* Reuse the closed number for another control file. */
  assert(other.refs==replacement_file_refs+1);
  struct hybrid580_frontend_memory_owner reused_fd_owner={0};
  assert(hybrid580_frontend_uvm_memory_owner_pin_v1(
      50,root1,memory1,&reused_fd_owner)==NV_OK);
  assert(reused_fd_owner.backend==backend && reused_fd_owner.backend_root==root2 &&
         reused_fd_owner.backend_memory==0xdecafbadU);
  int replacement_refs_after_reuse_pin=other.refs;
  assert(atomic_read(&object1->uvm_memory_pins)==1 &&
         atomic_read(&object2->uvm_memory_pins)==2);
  NVOS00_PARAMETERS free_memory={.hRoot=root1,.hObjectOld=memory1,
                                  .hObjectParent=device1};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_memory));
  assert(free_memory.status==NV_ERR_INVALID_OBJECT_HANDLE && !object_free_calls[backend]);
  free_memory=(NVOS00_PARAMETERS){.hRoot=root2,.hObjectOld=memory2,
                                  .hObjectParent=device2};
  assert(!hybrid_front_ioctl(&other,free_cmd,(unsigned long)&free_memory));
  assert(free_memory.status==NV_ERR_INVALID_OBJECT_HANDLE && !object_free_calls[backend]);
  NVOS00_PARAMETERS free_root={.hRoot=root1,.hObjectOld=root1};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_root));
  assert(free_root.status==NV_ERR_INVALID_STATE && !frees[0] && !frees[1]);
  hybrid580_frontend_uvm_memory_owner_unpin_v1(&owner1);
  assert(front.refs+2==original_file_refs && front.private_data &&
         other.refs==replacement_refs_after_reuse_pin);
  hybrid580_frontend_uvm_memory_owner_unpin_v1(&owner2);
  hybrid580_frontend_uvm_memory_owner_unpin_v1(&reused_fd_owner);
  assert(other.refs+2==replacement_refs_after_reuse_pin &&
         !owner1.pin && !owner2.pin && !reused_fd_owner.pin &&
         !atomic_read(&object1->uvm_memory_pins) &&
         !atomic_read(&object2->uvm_memory_pins));
  free_memory=(NVOS00_PARAMETERS){.hRoot=root1,.hObjectOld=memory1,
                                  .hObjectParent=device1};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_memory));
  assert(free_memory.status==NV_OK && object_free_calls[backend]==1 &&
         object_free_handles[backend]==backend_memory1);
  free_memory=(NVOS00_PARAMETERS){.hRoot=root2,.hObjectOld=memory2,
                                  .hObjectParent=device2};
  assert(!hybrid_front_ioctl(&other,free_cmd,(unsigned long)&free_memory));
  assert(free_memory.status==NV_OK && object_free_calls[backend]==2 &&
         object_free_handles[backend]==0xdecafbadU);
  NVOS00_PARAMETERS free_device={.hRoot=root1,.hObjectOld=device1,
                                  .hObjectParent=root1};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_device) &&
         free_device.status==NV_OK);
  free_device=(NVOS00_PARAMETERS){.hRoot=root2,.hObjectOld=device2,
                                  .hObjectParent=root2};
  assert(!hybrid_front_ioctl(&other,free_cmd,(unsigned long)&free_device) &&
         free_device.status==NV_OK);
  free_root=(NVOS00_PARAMETERS){.hRoot=root1,.hObjectOld=root1};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_root) &&
         free_root.status==NV_OK);
  free_root=(NVOS00_PARAMETERS){.hRoot=root2,.hObjectOld=root2};
  assert(!hybrid_front_ioctl(&other,free_cmd,(unsigned long)&free_root) &&
         free_root.status==NV_OK);
  close_test_fd(50); close_test_fd(51); front_put(); fput(&other);
  assert(!front.private_data && !other.private_data &&
         session_puts[0]==2 && session_puts[1]==2);
  return 0;
 } else if(!strcmp(s,"uvm-memory-quarantine-contention")) {
  NvHandle device,memory;
  NvHandle root=prepare_uvm_owner_objects(
      &front,HYBRID580_BACKEND_LEGACY,&device,&memory);
  struct hybrid_front_file *state=front.private_data;
  assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle unrelated_root=p21.hObjectNew;
  int calls_before=calls[0]+calls[1];
  int frees_before=frees[0]+frees[1];
  installed_fds[50]=get_file(&front);
  struct hybrid580_frontend_memory_owner owner={0};
  assert(hybrid580_frontend_uvm_memory_owner_pin_v1(
      50,root,memory,&owner)==NV_OK);
  mutex_lock(&state->transaction_lock);
  hybrid580_frontend_uvm_memory_owner_quarantine_v1(&owner);
  mutex_unlock(&state->transaction_lock);
  close_test_fd(50);
  assert(!owner.pin && !alloc_root(false));
  assert(p21.status==NV_ERR_INVALID_STATE && calls[0]+calls[1]==calls_before);
  NVOS00_PARAMETERS free_unrelated={.hRoot=unrelated_root,
                                     .hObjectOld=unrelated_root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_unrelated));
  assert(free_unrelated.status==NV_ERR_INVALID_STATE &&
         frees[0]+frees[1]==frees_before);
 } else if(!strcmp(s,"uvm-memory-quarantine-underflow")) {
  NvHandle device,memory;
  NvHandle root=prepare_uvm_owner_objects(
      &front,HYBRID580_BACKEND_LEGACY,&device,&memory);
  struct hybrid_front_file *state=front.private_data;
  assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle unrelated_root=p21.hObjectNew;
  struct hybrid_front_root *record=hybrid_front_find_root(state,root);
  struct hybrid_front_rm_object *object=hybrid_front_find_object(record,memory);
  installed_fds[50]=get_file(&front);
  struct hybrid580_frontend_memory_owner owner={0};
  assert(object && hybrid580_frontend_uvm_memory_owner_pin_v1(
      50,root,memory,&owner)==NV_OK);
  close_test_fd(50);
  atomic_dec_if_positive(&object->uvm_memory_pins);
  allow_warn_once=true;
  hybrid580_frontend_uvm_memory_owner_unpin_v1(&owner);
  assert(!owner.pin && !alloc_root(false));
  assert(p21.status==NV_ERR_INVALID_STATE);
  NVOS00_PARAMETERS free_unrelated={.hRoot=unrelated_root,
                                     .hObjectOld=unrelated_root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_unrelated));
  assert(free_unrelated.status==NV_OK && frees[0]+frees[1]==2);
 } else if(!strcmp(s,"uvm-address-space-quarantine-contention")) {
  NvHandle device,vaspace;
  NvHandle root=prepare_uvm_address_space_owner_objects(
      &front,HYBRID580_BACKEND_LEGACY,&device,&vaspace);
  struct hybrid_front_file *state=front.private_data;
  assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle unrelated_root=p21.hObjectNew;
  int calls_before=calls[0]+calls[1];
  int frees_before=frees[0]+frees[1];
  struct file *control_file=get_file(&front);
  struct hybrid580_frontend_address_space_owner owner={0};
  assert(hybrid580_frontend_uvm_address_space_owner_pin_v1(
      control_file,root,vaspace,&owner)==NV_OK);
  fput(control_file);
  mutex_lock(&state->transaction_lock);
  hybrid580_frontend_uvm_address_space_owner_quarantine_v1(&owner);
  mutex_unlock(&state->transaction_lock);
  assert(!owner.pin);
  assert(!alloc_root(false));
  assert(p21.status==NV_ERR_INVALID_STATE && calls[0]+calls[1]==calls_before);
  NVOS00_PARAMETERS free_unrelated={.hRoot=unrelated_root,
                                     .hObjectOld=unrelated_root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_unrelated));
  assert(free_unrelated.status==NV_ERR_INVALID_STATE &&
         frees[0]+frees[1]==frees_before);
 } else if(!strcmp(s,"uvm-address-space-quarantine-underflow")) {
  NvHandle device,vaspace;
  NvHandle root=prepare_uvm_address_space_owner_objects(
      &front,HYBRID580_BACKEND_LEGACY,&device,&vaspace);
  struct hybrid_front_file *state=front.private_data;
  assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle unrelated_root=p21.hObjectNew;
  int frees_before=frees[0]+frees[1];
  struct hybrid_front_root *record=hybrid_front_find_root(state,root);
  struct hybrid_front_rm_object *object=hybrid_front_find_object(record,vaspace);
  struct file *control_file=get_file(&front);
  struct hybrid580_frontend_address_space_owner owner={0};
  assert(object && hybrid580_frontend_uvm_address_space_owner_pin_v1(
      control_file,root,vaspace,&owner)==NV_OK);
  fput(control_file);
  atomic_dec_if_positive(&object->uvm_address_space_pins);
  allow_warn_once=true;
  hybrid580_frontend_uvm_address_space_owner_unpin_v1(&owner);
  assert(!owner.pin);
  assert(!alloc_root(false));
  assert(p21.status==NV_ERR_INVALID_STATE);
  NVOS00_PARAMETERS free_unrelated={.hRoot=unrelated_root,
                                     .hObjectOld=unrelated_root};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_unrelated));
  assert(free_unrelated.status==NV_OK && frees[0]+frees[1]==frees_before+2);
 } else if(!strcmp(s,"uvm-address-space-owner-control-fd-lifetime")) {
  struct file other={.f_op=&hybrid_front_fops,.private_data=(void *)1,.refs=1};
  const unsigned int backend=HYBRID580_BACKEND_LEGACY;
  NvHandle device1,vaspace1,device2,vaspace2;
  NvHandle root1=prepare_uvm_address_space_owner_objects(
      &front,backend,&device1,&vaspace1);
  struct hybrid_front_file *state1=front.private_data;
  struct hybrid_front_root *record1=hybrid_front_find_root(state1,root1);
  struct hybrid_front_rm_object *object1=
      hybrid_front_find_object(record1,vaspace1);
  struct hybrid_front_rm_object *device_object1=
      hybrid_front_find_object(record1,device1);
  assert(record1 && object1 && device_object1);
  object1->backend_handle=0xa1a1U;
  NvHandle backend_vaspace1=object1->backend_handle;
  next_root=root1; assert(!hybrid_front_open(&inode,&other));
  NvHandle root2=prepare_uvm_address_space_owner_objects(
      &other,backend,&device2,&vaspace2);
  struct hybrid_front_file *state2=other.private_data;
  struct hybrid_front_root *record2=hybrid_front_find_root(state2,root2);
  struct hybrid_front_rm_object *object2=
      hybrid_front_find_object(record2,vaspace2);
  struct hybrid_front_rm_object *device_object2=
      hybrid_front_find_object(record2,device2);
  assert(record2 && object2 && device_object2 && root2==root1 &&
         vaspace2==vaspace1 && device2==device1);
  object2->backend_handle=0xb2b2U;
  NvHandle backend_vaspace2=object2->backend_handle;
  installed_fds[50]=get_file(&front); installed_fds[51]=get_file(&other);

  struct hybrid580_frontend_address_space_owner rejected={
      .backend=99,.backend_root=99,.backend_vaspace=99,.pin=(void *)1};
  struct file invalid_control={.f_op=NULL,.private_data=NULL,.refs=1};
  assert(hybrid580_frontend_uvm_address_space_owner_pin_v1(
      &invalid_control,root1,vaspace1,&rejected)==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(!rejected.pin && rejected.backend==0 &&
         !atomic_read(&object1->uvm_address_space_pins));
  rejected=(struct hybrid580_frontend_address_space_owner){
      .backend=99,.backend_root=99,.backend_vaspace=99,.pin=(void *)1};
  assert(hybrid580_frontend_uvm_address_space_owner_pin_v1(
      &front,root1+1,vaspace1,&rejected)==NV_ERR_INVALID_OBJECT_HANDLE);
  assert(!rejected.pin && rejected.backend==0 &&
         !atomic_read(&object1->uvm_address_space_pins));
  mutex_lock(&state1->transaction_lock);
  assert(hybrid580_frontend_uvm_address_space_owner_pin_v1(
      &front,root1,vaspace1,&rejected)==NV_ERR_NOT_READY);
  mutex_unlock(&state1->transaction_lock);
  assert(!rejected.pin && !atomic_read(&object1->uvm_address_space_pins));

  int front_refs_before_pins=front.refs, other_refs_before_pins=other.refs;
  struct file *control_file1=get_file(&front); /* UVM's ioctl-scope fget */
  struct file *control_file2=get_file(&other);
  struct hybrid580_frontend_address_space_owner owner1={0},owner2={0};
  assert(hybrid580_frontend_uvm_address_space_owner_pin_v1(
      control_file1,root1,vaspace1,&owner1)==NV_OK);
  assert(hybrid580_frontend_uvm_address_space_owner_pin_v1(
      control_file2,root2,vaspace2,&owner2)==NV_OK);
  assert(front.refs==front_refs_before_pins+2 &&
         other.refs==other_refs_before_pins+2);
  fput(control_file1); fput(control_file2); /* ioctl releases its references */
  assert(front.refs==front_refs_before_pins+1 &&
         other.refs==other_refs_before_pins+1);
  assert(owner1.backend==backend && owner2.backend==backend &&
         owner1.backend_root==record1->root.slot[backend].handle &&
         owner2.backend_root==record2->root.slot[backend].handle &&
         owner1.backend_vaspace==backend_vaspace1 &&
         owner2.backend_vaspace==backend_vaspace2 &&
         owner1.backend_vaspace!=owner2.backend_vaspace);
  assert(atomic_read(&object1->uvm_address_space_pins)==1 &&
         atomic_read(&object2->uvm_address_space_pins)==1);
  NVOS00_PARAMETERS free_vaspace={.hRoot=root1,.hObjectOld=vaspace1,
                                   .hObjectParent=device1};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_vaspace));
  assert(free_vaspace.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         !object_free_calls[backend]);
  NVOS00_PARAMETERS free_root={.hRoot=root1,.hObjectOld=root1};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_root));
  assert(free_root.status==NV_ERR_INVALID_STATE && !frees[0] && !frees[1]);

  hybrid580_frontend_uvm_address_space_owner_unpin_v1(&owner1);
  hybrid580_frontend_uvm_address_space_owner_unpin_v1(&owner2);
  assert(!owner1.pin && !owner2.pin &&
         front.refs==front_refs_before_pins &&
         other.refs==other_refs_before_pins &&
         !atomic_read(&object1->uvm_address_space_pins) &&
         !atomic_read(&object2->uvm_address_space_pins));
  free_vaspace=(NVOS00_PARAMETERS){.hRoot=root1,.hObjectOld=vaspace1,
                                   .hObjectParent=device1};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_vaspace) &&
         free_vaspace.status==NV_OK);
  free_vaspace=(NVOS00_PARAMETERS){.hRoot=root2,.hObjectOld=vaspace2,
                                   .hObjectParent=device2};
  assert(!hybrid_front_ioctl(&other,free_cmd,(unsigned long)&free_vaspace) &&
         free_vaspace.status==NV_OK);
  NVOS00_PARAMETERS free_device={.hRoot=root1,.hObjectOld=device1,
                                  .hObjectParent=root1};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_device) &&
         free_device.status==NV_OK);
  free_device=(NVOS00_PARAMETERS){.hRoot=root2,.hObjectOld=device2,
                                  .hObjectParent=root2};
  assert(!hybrid_front_ioctl(&other,free_cmd,(unsigned long)&free_device) &&
         free_device.status==NV_OK);
  free_root=(NVOS00_PARAMETERS){.hRoot=root1,.hObjectOld=root1};
  assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&free_root) &&
         free_root.status==NV_OK);
  free_root=(NVOS00_PARAMETERS){.hRoot=root2,.hObjectOld=root2};
  assert(!hybrid_front_ioctl(&other,free_cmd,(unsigned long)&free_root) &&
         free_root.status==NV_OK);
  close_test_fd(50); close_test_fd(51); front_put(); fput(&other);
  assert(!front.private_data && !other.private_data &&
         session_puts[0]==2 && session_puts[1]==2);
  return 0;
 } else if(!strcmp(s,"client-share-policy-route")) {
  assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_CTRL_CLIENT_SET_INHERITED_SHARE_POLICY_PARAMS policy={0};
  policy.sharePolicy.target=0x10203040U;
  policy.sharePolicy.accessMask.limbs[0]=0x87654321U;
  policy.sharePolicy.type=3;
  policy.sharePolicy.action=2;
  _Static_assert(sizeof(policy)==12,"R580 client share-policy ABI size");
  _Static_assert(sizeof(RS_SHARE_POLICY)==12,"R580 share-policy ABI size");
  NVOS54_PARAMETERS control={.hClient=root,.hObject=root,
      .cmd=NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY,
      .flags=NVOS54_FLAGS_NONE,.params=&policy,.paramsSize=sizeof(policy),
      .status=0xffffffffU};
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==0);
  assert(control.status==NV_OK);
  assert(share_policy_calls[0]==1 && share_policy_calls[1]==1);
  assert(share_policy_client[0]==root && share_policy_client[1]==root &&
         share_policy_object[0]==root && share_policy_object[1]==root &&
         share_policy_flags[0]==0 && share_policy_flags[1]==0);
  assert(!memcmp(&share_policy_params[0],&policy.sharePolicy,sizeof(policy.sharePolicy)) &&
         !memcmp(&share_policy_params[1],&policy.sharePolicy,sizeof(policy.sharePolicy)));
  policy.sharePolicy.target=0x55667788U;
  control=(NVOS54_PARAMETERS){.hClient=root,.hObject=root,
      .cmd=NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY,
      .flags=NVOS54_FLAGS_NONE,.params=&policy,.paramsSize=sizeof(policy),
      .status=0xffffffffU};
  nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),
                        .ptr=(NvP64)&control};
  unsigned int xfer_command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,
                                  nv_ioctl_xfer_t);
  assert(hybrid_front_ioctl(&front,xfer_command,(unsigned long)&xfer)==0);
  assert(control.status==NV_OK && share_policy_calls[0]==2 &&
         share_policy_calls[1]==2);
  assert(!memcmp(&share_policy_params[0],&policy.sharePolicy,sizeof(policy.sharePolicy)) &&
         !memcmp(&share_policy_params[1],&policy.sharePolicy,sizeof(policy.sharePolicy)));
 } else if(!strcmp(s,"client-share-policy-failure-quarantine")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_CTRL_CLIENT_SET_INHERITED_SHARE_POLICY_PARAMS policy={0};
  policy.sharePolicy.target=0x10203040U;
  policy.sharePolicy.accessMask.limbs[0]=0x87654321U;
  policy.sharePolicy.type=3; policy.sharePolicy.action=2;
  share_policy_transport[HYBRID580_BACKEND_OPEN]=NV_ERR_OPERATING_SYSTEM;
  NVOS54_PARAMETERS control={.hClient=root,.hObject=root,
      .cmd=NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY,
      .flags=NVOS54_FLAGS_NONE,.params=&policy,.paramsSize=sizeof(policy),
      .status=0xffffffffU};
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  assert(control.status==NV_ERR_OPERATING_SYSTEM &&
         share_policy_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         share_policy_calls[HYBRID580_BACKEND_OPEN]==1);
  struct hybrid_front_file *state=front.private_data;
  assert(state->quarantined && state->roots->root.state==HYBRID_ROOT_QUARANTINED);
  share_policy_transport[HYBRID580_BACKEND_OPEN]=NV_OK;
  control.status=0xffffffffU;
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  assert(control.status==NV_ERR_INVALID_OBJECT_HANDLE &&
         share_policy_calls[HYBRID580_BACKEND_LEGACY]==1 &&
         share_policy_calls[HYBRID580_BACKEND_OPEN]==1);
  front_put(); return 0;
 } else if(!strcmp(s,"client-share-policy-invalid")) {
  make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
  NvHandle root=p21.hObjectNew;
  NV0000_CTRL_CLIENT_SET_INHERITED_SHARE_POLICY_PARAMS policy={0};
  NVOS54_PARAMETERS control={.hClient=root,.hObject=root,
      .cmd=NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY,
      .flags=NVOS54_FLAGS_NONE,.params=&policy,.paramsSize=sizeof(policy)-1,
      .status=0xffffffffU};
  assert(hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control)==-EINVAL);
  assert(share_policy_calls[HYBRID580_BACKEND_LEGACY]==0 &&
         share_policy_calls[HYBRID580_BACKEND_OPEN]==0 &&
         !((struct hybrid_front_file *)front.private_data)->quarantined);
  front_put(); return 0;
 } else if(!strcmp(s,"success21") || !strcmp(s,"success64")) {
  bool w=!strcmp(s,"success64"); assert(!alloc_root(w)); assert((w?p64.status:p21.status)==NV_OK); assert(calls[0]==1 && calls[1]==1);
  NVOS00_PARAMETERS p={.hRoot=987,.hObjectOld=987}; assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&p)); assert(p.status==NV_OK && frees[0]==1 && frees[1]==1);
 } else if(!strcmp(s,"multi-root") || !strcmp(s,"multi-close")) {
  assert(!alloc_root(false) && p21.hObjectNew==987); assert(!alloc_root(true) && p64.hObjectNew==988);
  struct hybrid_front_file *st=front.private_data; assert(st->root_count==2);
  if(!strcmp(s,"multi-root")) { NVOS00_PARAMETERS p={.hRoot=987,.hObjectOld=987,.hObjectParent=987};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&p) && p.status==NV_OK && st->root_count==1);
   p=(NVOS00_PARAMETERS){.hRoot=988,.hObjectOld=988}; assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&p) && p.status==NV_OK && !st->root_count);
  }
 } else if(!strcmp(s,"multi-quarantine") || !strcmp(s,"quarantine-noid")) {
  if(!strcmp(s,"multi-quarantine")) assert(!alloc_root(false) && p21.status==NV_OK);
  alloc_error_backend=0; zero_failure_handle=true;
  assert(!alloc_root(false) && p21.status!=NV_OK); struct hybrid_front_file *st=front.private_data;
  assert(st->quarantined && st->roots->root.id==0 && st->roots->root.state==HYBRID_ROOT_QUARANTINED);
  int before=calls[0]; assert(!alloc_root(false) && p21.status==NV_ERR_INVALID_STATE && calls[0]==before);
  if(!strcmp(s,"multi-quarantine")) { NVOS00_PARAMETERS p={.hRoot=987,.hObjectOld=987};
   assert(!hybrid_front_ioctl(&front,free_cmd,(unsigned long)&p) && p.status==NV_OK && st->root_count==1); }
 } else if(!strcmp(s,"capacity")) {
  for(unsigned i=0;i<HYBRID_FRONT_MAX_ROOTS;i++) assert(!alloc_root(false) && p21.status==NV_OK);
  assert(!alloc_root(false) && p21.status==NV_ERR_INSUFFICIENT_RESOURCES && calls[0]==HYBRID_FRONT_MAX_ROOTS);
 } else if(!strcmp(s,"record-memory-fail")) { fail_alloc=1; assert(!alloc_root(false) && p21.status==NV_ERR_NO_MEMORY && !calls[0]); fail_alloc=0; }
 else if(!strcmp(s,"duplicate-id")) {
  duplicate_handle=true; assert(!alloc_root(false) && p21.status==NV_OK); assert(!alloc_root(false) && p21.status==NV_ERR_INVALID_STATE);
  struct hybrid_front_file *st=front.private_data; assert(st->root_count==2 && st->quarantined && !frees[0] && !frees[1]);
  assert(st->roots->root.state==HYBRID_ROOT_QUARANTINED && st->roots->next->root.state==HYBRID_ROOT_QUARANTINED);
 } else if(!strcmp(s,"duplicate-first-second-failure")) {
  assert(!alloc_root(false)); duplicate_handle=true; alloc_error_backend=1;
  assert(!alloc_root(false) && p21.status==NV_ERR_INVALID_STATE && calls[1]==1 && !frees[0] && !frees[1]);
  assert(((struct hybrid_front_file *)front.private_data)->quarantined);
 } else if(!strcmp(s,"duplicate-second-mismatch")) {
  assert(!alloc_root(false)); duplicate_second=true;
  assert(!alloc_root(false) && p21.status==NV_ERR_INVALID_STATE && frees[0]==1 && !frees[1]);
  struct hybrid_front_file *st=front.private_data; assert(st->quarantined && st->roots->root.slot[1].handle==0 && st->roots->root.slot[1].observed==987);
 } else if(!strcmp(s,"free-copy-out-fail")) {
  assert(!alloc_root(false)); NVOS00_PARAMETERS p={.hRoot=987,.hObjectOld=987}; to_fault=1;
  assert(hybrid_front_ioctl(&front,free_cmd,(unsigned long)&p)==-EFAULT && !((struct hybrid_front_file *)front.private_data)->root_count);
 } else if(!strcmp(s,"concurrent-allocs")) {
  pthread_t a,b; active_calls_block=true; get_file(&front); get_file(&front);
  assert(!pthread_create(&a,NULL,ioctl_thread,NULL));
  pthread_mutex_lock(&block_mutex); while(!entered_call) pthread_cond_wait(&block_cond,&block_mutex); pthread_mutex_unlock(&block_mutex);
  assert(!pthread_create(&b,NULL,ioctl_thread,NULL));
  pthread_mutex_lock(&block_mutex); allow_call=true; pthread_cond_broadcast(&block_cond); pthread_mutex_unlock(&block_mutex);
  assert(!pthread_join(a,NULL) && !pthread_join(b,NULL));
  assert(((struct hybrid_front_file *)front.private_data)->root_count==2 && calls[0]==2 && calls[1]==2);
 } else if(!strcmp(s,"close-active")) { assert(!alloc_root(false)); }
 else if(!strcmp(s,"concurrent-close")) {
  pthread_t thread; active_calls_block=true; get_file(&front); assert(!pthread_create(&thread,NULL,ioctl_thread,NULL));
  pthread_mutex_lock(&block_mutex); while(!entered_call) pthread_cond_wait(&block_cond,&block_mutex); pthread_mutex_unlock(&block_mutex);
  front_put(); assert(front.refs==1 && !session_puts[0] && !session_puts[1]);
  pthread_mutex_lock(&block_mutex); allow_call=true; pthread_cond_broadcast(&block_cond); pthread_mutex_unlock(&block_mutex);
  assert(!pthread_join(thread,NULL)); assert(front.refs==0 && !front.private_data && session_puts[0]==1 && session_puts[1]==1 && frees[0]==1 && frees[1]==1); return 0;
 } else { assert(!"unknown scenario"); }
 int before0=frees[0], before1=frees[1]; bool quarantined=hybrid_front_file_is_quarantined(front.private_data);
 front_put();
 if(!strcmp(s,"uvm-memory-quarantine-contention") ||
    !strcmp(s,"uvm-memory-quarantine-underflow") ||
    !strcmp(s,"uvm-address-space-quarantine-contention") ||
    !strcmp(s,"uvm-address-space-quarantine-underflow")) {
  assert(quarantined && front.refs==1 && front.private_data &&
         session_puts[0]==0 && session_puts[1]==0);
  return 0;
 }
 assert(!front.private_data && session_puts[0]==created[0] && session_puts[1]==created[1]);
 if(quarantined) assert(frees[0]==before0 && frees[1]==before1);
 if(!strcmp(s,"close-active") || !strcmp(s,"copy-out-fail")) assert(frees[0]==1 && frees[1]==1);
 if(!strcmp(s,"multi-close") || !strcmp(s,"concurrent-allocs")) assert(frees[0]==2 && frees[1]==2);
 if(!strcmp(s,"capacity")) assert(frees[0]==HYBRID_FRONT_MAX_ROOTS && frees[1]==HYBRID_FRONT_MAX_ROOTS);
 return 0;
}
'''


class HybridFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        work = Path(cls.tmp.name)
        source = (ROOT / 'src/hybrid_frontend.c').read_text()
        source = re.sub(r'^#include[^\n]*\n', '', source, flags=re.M)
        headers = re.sub(r'^#include[^\n]*\n', '',
                         (ROOT / 'src/hybrid580-control-session.h').read_text(), flags=re.M)
        headers += re.sub(r'^#include[^\n]*\n', '',
                          (ROOT / 'src/hybrid580-open-build-version.h').read_text(), flags=re.M)
        headers += re.sub(r'^#include[^\n]*\n', '',
                          (OPEN / 'hybrid580-file-projection.h').read_text(), flags=re.M)
        headers += re.sub(r'^#include[^\n]*\n', '',
                          (ROOT / 'src/hybrid580-gpu-session.h').read_text(), flags=re.M)
        headers += re.sub(r'^#include[^\n]*\n', '',
                          (ROOT / 'src/hybrid580-device-instance-map.h').read_text(), flags=re.M)
        headers += re.sub(r'^#include[^\n]*\n', '',
                          (ROOT / 'src/hybrid580-standard-node-map.h').read_text(), flags=re.M)
        headers += re.sub(r'^#include[^\n]*\n', '',
                          (ROOT / 'src/hybrid580-standard-node-devices.h').read_text(), flags=re.M)
        headers += re.sub(r'^#include[^\n]*\n', '',
                          (ROOT / 'src/hybrid580_frontend_admission.h').read_text(), flags=re.M)
        headers += re.sub(r'^#include[^\n]*\n', '',
                          (ROOT / 'src/hybrid580_pm_provider_recovery.h').read_text(), flags=re.M)
        headers += re.sub(r'^#include[^\n]*\n', '',
                          (ROOT / 'src/hybrid580_system_pm_coordinator.h').read_text(), flags=re.M)
        headers += re.sub(r'^#include[^\n]*\n', '',
                          (ROOT / 'src/hybrid580_frontend_uvm_memory_owner.h').read_text(), flags=re.M)
        headers += re.sub(r'^#include[^\n]*\n', '',
                          (ROOT / 'src/hybrid580_frontend_uvm_address_space_owner.h').read_text(), flags=re.M)
        catalog_header = (ROOT / 'src/hybrid580-gpu-catalog.h').read_text()
        uapi = re.sub(r'^#include[^\n]*\n', '', (ROOT / 'src/hybrid580_ioctl.h').read_text(), flags=re.M)
        def build_executable(preamble, name):
            fixture = work / f'{name}.c'
            fixture.write_text(preamble + catalog_header + headers + uapi +
                               BACKENDS + source + MAIN)
            executable = work / name
            result = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                     '-Wno-unused-parameter', '-Wno-unused-function', '-pthread',
                                     '-fsanitize=undefined', '-fno-sanitize-recover=all',
                                     *include_flags(), str(ROOT / 'src/rm_root_client.c'),
                                     str(fixture), str(ROOT / 'src/hybrid580-gpu-catalog.c'),
                                     str(ROOT / 'src/hybrid580-device-instance-map.c'),
                                     str(ROOT / 'src/hybrid580-standard-node-map.c'),
                                     '-o', str(executable)], capture_output=True, text=True,
                                    timeout=60)
            if result.returncode:
                cls.tmp.cleanup()
                raise AssertionError(result.stderr)
            return executable

        cls.exe = build_executable(PREAMBLE, 'frontend-r580')
        r595_preamble, replacements = PREAMBLE.replace(
            '#define HYBRID580_UVM_ABI_R580 1\n', '', 1), PREAMBLE.count(
                '#define HYBRID580_UVM_ABI_R580 1\n')
        if replacements != 1:
            cls.tmp.cleanup()
            raise AssertionError('R580 ABI test define was not unique')
        cls.r595_exe = build_executable(r595_preamble, 'frontend-r595')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_build_version_provider_is_open_only(self):
        spec = importlib.util.spec_from_file_location(
            'hybrid_frontend_builder', ROOT / 'tools/build_hybrid_frontend.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        expected = builder.expected_backend_imports()
        self.assertIn('hybrid580_open_control_session_build_version_v1', expected)
        self.assertNotIn('hybrid580_legacy_control_session_build_version_v1', expected)

    def test_system_features_provider_is_open_only(self):
        spec = importlib.util.spec_from_file_location(
            'hybrid_frontend_builder', ROOT / 'tools/build_hybrid_frontend.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        provider = 'hybrid580_open_control_session_system_features_v1'
        legacy_provider = 'hybrid580_legacy_control_session_system_features_v1'
        for expected in (builder.expected_backend_imports(),
                         builder.expected_backend_imports(
                             uvm_abi='r580',
                             standard_uvm_symbols=('nvUvmInterfaceProbe',))):
            self.assertIn(provider, expected)
            self.assertNotIn(legacy_provider, expected)

    def test_fabric_status_provider_is_open_only(self):
        spec = importlib.util.spec_from_file_location(
            'hybrid_frontend_builder', ROOT / 'tools/build_hybrid_frontend.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        provider = 'hybrid580_open_control_session_fabric_status_v1'
        legacy_provider = 'hybrid580_legacy_control_session_fabric_status_v1'
        for expected in (builder.expected_backend_imports(),
                         builder.expected_backend_imports(
                             uvm_abi='r580',
                             standard_uvm_symbols=('nvUvmInterfaceProbe',))):
            self.assertIn(provider, expected)
            self.assertNotIn(legacy_provider, expected)

    def test_v100_master_class_and_control_route(self):
        spec = importlib.util.spec_from_file_location(
            'hybrid_frontend_builder', ROOT / 'tools/build_hybrid_frontend.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        imports = builder.expected_backend_imports()
        self.assertIn('hybrid580_legacy_control_session_master_alloc_v1', imports)
        self.assertIn('hybrid580_legacy_control_session_master_error_intr_offset_mask_v1',
                      imports)
        self.assertNotIn('hybrid580_open_control_session_master_alloc_v1', imports)
        self.assertNotIn('hybrid580_open_control_session_master_error_intr_offset_mask_v1',
                         imports)
        result = subprocess.run([str(self.exe), 'master-object-lifecycle'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_actual_frontend_lifecycle_and_broker_cpu_contract(self):
        scenarios = ('version-check-roundtrip', 'version-check-disagreement',
                     'version-check-fail-closed', 'version-check-native-rejection-copyout',
                     'version-check-invalid-size',
                     'version-check-copy-faults', 'version-check-xfer',
                     'system-pm-provider-adapter-fail-closed',
                     'system-pm-provider-adapter-begin-failure',
                     'system-pm-provider-adapter-fail-closed-event-matrix',
                     'build-version-null-sizing', 'build-version-capacity',
                     'build-version-xfer', 'build-version-copy-faults',
                     'build-version-fail-closed', 'build-version-allocation-failure',
                     'build-version-invalid-input', 'system-features-direct',
                     'system-features-xfer', 'system-features-invalid',
                     'system-features-fail-closed', 'system-features-copy-faults',
                     'sync-boost-groups-policy', 'sync-boost-groups-nonzero',
                     'sync-boost-groups-transport-error', 'sync-boost-groups-rm-error',
                     'sync-boost-groups-xfer-transport-error',
                     'sync-boost-groups-xfer-rm-error',
                     'sync-boost-groups-cross-provider-error-precedence',
                     'sync-boost-groups-malformed-provider', 'sync-boost-groups-invalid',
                     'sync-boost-groups-root-split', 'sync-boost-groups-missing-session',
                     'sync-boost-groups-allocation-failure', 'sync-boost-groups-interrupted',
                     'sync-boost-groups-copy-faults',
                     'fabric-status-direct', 'fabric-status-xfer',
                     'fabric-status-invalid', 'fabric-status-fail-closed',
                     'fabric-status-copy-fault',
                     'client-share-policy-route',
                     'client-share-policy-failure-quarantine',
                     'client-share-policy-invalid',
                     'sys-params-route',
                     'sys-params-copyin', 'sys-params-copyout',
                     'sys-params-first-failure', 'sys-params-second-failure',
                     'sys-params-format',
                     'init-disabled', 'init-success', 'init-legacy-fail', 'init-open-fail',
                     'init-device-fail', 'open-memory-fail', 'open-legacy-fail', 'open-modern-fail',
                     'projection', 'format-reject', 'copy-in-fail', 'copy-out-fail', 'interrupted',
                     'nested-reject', 'alloc-quarantine', 'free-quarantine', 'free-reject',
                     'uvm-owner-control-fd-lifetime',
                     'uvm-memory-quarantine-contention',
                     'uvm-memory-quarantine-underflow',
                     'uvm-address-space-quarantine-contention',
                     'uvm-address-space-quarantine-underflow',
                     'uvm-address-space-owner-control-fd-lifetime',
                     'success21', 'success64', 'close-active', 'concurrent-close', 'multi-root', 'multi-close',
                     'multi-quarantine', 'quarantine-noid', 'capacity', 'record-memory-fail',
                     'duplicate-id', 'duplicate-first-second-failure', 'duplicate-second-mismatch',
                     'free-copy-out-fail', 'concurrent-allocs', 'gpu-legacy-route', 'gpu-open-route',
                     'catalog-query', 'catalog-empty', 'catalog-duplicate', 'catalog-inventory-error',
                     'catalog-allocation-fail-catalog', 'catalog-allocation-fail-legacy-buffer',
                     'catalog-allocation-fail-open-buffer',
                     'gpu-no-owner', 'gpu-invalid-bdf', 'gpu-create-failure', 'gpu-copyout-failure',
                     'gpu-malformed-request', 'gpu-copyin-failure', 'gpu-anon-file-failure', 'gpu-fd-allocation-failure',
                     'gpu-poll-legacy-lifetime', 'gpu-poll-open-lifetime', 'gpu-poll-missing-backend-callback',
                     'gpu-poll-epoll-lifetime', 'gpu-poll-control-reject', 'gpu-poll-gated',
                     'gpu-mmap-legacy-lifetime', 'gpu-mmap-open-lifetime', 'gpu-mmap-backend-error',
                     'gpu-mmap-gated',
                     'control-mmap-same-file', 'control-mmap-separate-file',
                     'master-map-parent-binding',
                     'map-embedded-error-retry', 'map-transport-failure-poisons',
                     'map-copyout-failure-poisons', 'control-mmap-error-retry',
                     'device-mapping-update-route',
                     'device-mapping-update-copyout-poison',
                     'gpu-mmap-control-reject', 'gpu-mmap-interrupted',
                     'standard-control-open','standard-gpu-blackwell-register','standard-gpu-volta-register',
                     'standard-gpu-observed-node-ioctls-blackwell',
                     'standard-gpu-observed-node-ioctls-volta',
                     'standard-gpu-observed-node-ioctls-blackwell',
                     'standard-gpu-observed-node-ioctls-volta',
                     'standard-gpu-register-fd-xfer-blackwell','standard-gpu-register-fd-xfer-volta',
                     'standard-gpu-register-fd-reuse-blackwell',
                     'standard-gpu-register-fd-reuse-volta',
                     'standard-gpu-register-fd-xfer-reuse-blackwell',
                     'standard-gpu-register-fd-xfer-reuse-volta',
                     'standard-gpu-register-fd-xfer-bad-size',
                     'standard-gpu-register-fd-xfer-copyin-failure',
                     'standard-gpu-register-fd-xfer-inner-copyin-failure',
                     'standard-gpu-register-fd-xfer-header-race',
                     'standard-gpu-register-fd-xfer-payload-race-blackwell',
                     'standard-gpu-pending-quarantine-blocked',
                     'standard-gpu-register-fd-quarantine-race',
                     'standard-gpu-bad-control','standard-gpu-bad-fd','standard-gpu-copyin-failure',
                     'standard-gpu-backend-failure',
                     'gpu-open-ioctl-reject', 'attach-publish-success', 'attach-direct-success',
                     'attach-second-backend-failure', 'attach-candidate-create-retry',
                     'attach-after-stateful-rejected', 'attach-copy-in-failure', 'attach-malformed',
                     'attach-repeat-rejected', 'attach-zero-placeholder',
                     'attach-after-gpu-open-failure', 'card-info-merge', 'card-info-small',
                     'card-info-xfer', 'card-info-stale', 'card-info-backend-error',
                     'card-info-copyin-failure', 'card-info-copyout-failure',
                     'card-info-allocation-fail-user', 'card-info-allocation-fail-legacy',
                     'card-info-allocation-fail-open', 'card-info-xfer-reject',
                     'gpu-id-info-route', 'gpu-id-info-map-transport-error',
                     'gpu-id-info-map-embedded-error', 'gpu-id-info-map-device-ids-error',
                     'gpu-id-info-unknown-local-instance', 'gpu-id-info-reject',
                     'subdevice-object-lifecycle',
                     'p2p-object-lifecycle',
                     'p2p-object-failure-transport', 'p2p-object-failure-status',
                     'p2p-object-failure-return',
                     'p2p-control-lifecycle', 'p2p-control-transport-failure',
                     'p2p-control-status-retry', 'p2p-control-copyout-failure',
                     'binapi-control-denied',
                     'subdevice-object-failure-transport', 'subdevice-object-failure-status',
                     'subdevice-object-failure-return',
                     'binapi-object-lifecycle',
                     'rusd-object-lifecycle',
                     'usermode-object-lifecycle',
                     'usermode-object-failure-transport', 'usermode-object-failure-status',
                     'usermode-object-failure-return',
                     'binapi-object-failure-transport', 'binapi-object-failure-status',
                     'binapi-object-failure-return',
                     'device-object-open-lifecycle', 'device-object-legacy-lifecycle',
                     'device-object-map-mask-mismatch',
                     'device-object-map-device-ids-error',
                     'device-object-map-id-info-error',
                     'device-object-invalid', 'device-object-copyin-failure',
                     'device-object-copyout-failure', 'device-object-root-free',
                     'device-object-free-copyout-failure', 'device-object-duplicate-handle',
                     'device-object-capacity', 'device-object-backend-transport-failure',
                     'device-object-backend-status-failure', 'device-object-return-mismatch',
                     'device-object-free-transport-failure', 'device-object-free-status-failure',
                     'device-object-root-handle-collision',
                     'vaspace-object-lifecycle', 'vaspace-object-invalid-and-copy',
                     'channel-object-reference-routing', 'channel-object-copyout-failure',
                     'engine-object-allocation-routing',
                     'context-share-copyout-failure',
                     'device-ids-merge', 'device-ids-xfer', 'device-ids-invalid-root',
                     'device-ids-backend-error', 'device-ids-backend-transport-error',
                     'device-ids-mask-mismatch',
                     'device-ids-gpu-id-error', 'device-ids-copyin-failure',
                     'device-ids-copyout-failure',
                     'attached-ids-merge', 'attached-ids-xfer', 'attached-ids-backend-error',
                     'attached-ids-transport-error', 'attached-ids-stale', 'attached-ids-duplicate',
                     'attached-ids-noncontiguous', 'attached-ids-overflow',
                     'attached-ids-copyin-failure', 'attached-ids-copyout-failure',
                     'probed-ids-merge', 'probed-ids-xfer', 'probed-ids-embedded-error',
                     'probed-ids-transport-error', 'probed-ids-unknown',
                     'probed-ids-duplicate', 'probed-ids-noncontiguous',
                     'probed-ids-excluded-unknown', 'probed-ids-excluded-overlap',
                     'probed-ids-overflow', 'probed-ids-invalid-root',
                     'probed-ids-allocation-failure',
                     'probed-ids-copyin-failure', 'probed-ids-copyout-failure')
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                result = subprocess.run([str(self.exe), scenario], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_composed_dual_gpu_frontend_contract(self):
        for executable in (self.exe, self.r595_exe):
            for scenario in ('hybrid-dual-gpu-contract',
                             'hybrid-dual-gpu-contract-legacy-first'):
                with self.subTest(executable=executable.name, scenario=scenario):
                    result = subprocess.run([str(executable), scenario],
                                             capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_uvm_map_owner_fd_selects_backend_before_duplicate_route(self):
        result = subprocess.run(
            [str(self.exe), 'uvm-owner-dup-memory-provider-route'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_vaspace_and_memory_children_preserve_backend_and_lifetime(self):
        result = subprocess.run([str(self.exe), 'vaspace-object-lifecycle'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_v100_bar1_p2p_child_is_confined_to_legacy_backend_and_tracked(self):
        result = subprocess.run([str(self.exe), 'p2p-object-lifecycle'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_vaspace_rejects_unowned_modes_and_retains_copyout_ownership(self):
        result = subprocess.run([str(self.exe), 'vaspace-object-invalid-and-copy'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_channel_group_tracks_vaspace_notifiers_and_backend_lifetimes(self):
        result = subprocess.run([str(self.exe), 'channel-group-vaspace-notifier-lifetime'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_channel_group_copyout_failure_keeps_rm_ownership_for_root_teardown(self):
        result = subprocess.run([str(self.exe), 'channel-group-copyout-failure'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_channel_alloc_resolves_owned_handles_and_blocks_early_free(self):
        result = subprocess.run([str(self.exe), 'channel-object-reference-routing'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_channel_alloc_handles_payload_allocation_and_copyout_failure(self):
        result = subprocess.run([str(self.exe), 'channel-object-copyout-failure'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_engine_objects_route_by_owned_generation_channel(self):
        result = subprocess.run([str(self.exe), 'engine-object-allocation-routing'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_r595_debugger_control_routes_by_owner_when_root_id_is_shared(self):
        result = subprocess.run(
            [str(self.r595_exe), 'debugger-exception-mask-provider-owner-route'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_context_share_copyout_failure_keeps_child_ownership_for_root_teardown(self):
        result = subprocess.run([str(self.exe), 'context-share-copyout-failure'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_memory_child_allocation_uses_device_parent_backend_and_copies_outputs(self):
        result = subprocess.run([str(self.exe), 'memory-object-open-lifecycle'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_memory_child_output_fault_retains_ownership_for_root_teardown(self):
        result = subprocess.run([str(self.exe), 'memory-object-copyout-failure'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_virtual_memory_child_routes_to_owned_gpu_and_translates_vaspace(self):
        result = subprocess.run(
            [str(self.exe), 'memory-virtual-object-backend-affinity'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_usermode_doorbell_classes_are_backend_affine_and_typed(self):
        for scenario in ('usermode-object-lifecycle',
                         'usermode-object-failure-transport',
                         'usermode-object-failure-status',
                         'usermode-object-failure-return'):
            with self.subTest(scenario=scenario):
                result = subprocess.run([str(self.exe), scenario],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_v100_p2p_controls_translate_handles_and_hold_resource_lifetimes(self):
        for scenario in ('p2p-control-lifecycle',
                         'p2p-control-transport-failure',
                         'p2p-control-status-retry',
                         'p2p-control-copyout-failure'):
            with self.subTest(scenario=scenario):
                result = subprocess.run([str(self.exe), scenario],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_opaque_nv2081_binapi_control_is_denied_without_nested_read_or_backend_call(self):
        result = subprocess.run([str(self.exe), 'binapi-control-denied'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_gpu_name_string_control_marshals_direct_and_xfer_requests(self):
        result = subprocess.run([str(self.exe), 'gpu-name-string-control'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
