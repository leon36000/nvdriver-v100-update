/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hybrid580_uvm_device_route.h"
#include "hybrid580_uvm_p2p_object_route.h"

typedef uint32_t NvU32;
typedef uint64_t NvU64;
typedef uint32_t NvBool;
typedef uint32_t NvHandle;
typedef uint32_t NV_STATUS;
typedef void *uvmGpuDeviceHandle;
typedef void *uvmGpuSessionHandle;

#define NV_OK UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0xe0010001)
#define NV_ERR_NOT_SUPPORTED UINT32_C(0xe0010002)
#define NV_ERR_NO_MEMORY UINT32_C(0xe0010003)
#define NV_ERR_GENERIC UINT32_C(0xe0010004)

/* Exact R595 UVM_LINK_TYPE values relevant to the static-peer predicate. */
#define UVM_LINK_TYPE_NONE UINT32_C(0)
#define UVM_LINK_TYPE_PCIE UINT32_C(1)
#define UVM_LINK_TYPE_PCIE_BAR1 UINT32_C(2)
#define UVM_LINK_TYPE_NVLINK_1 UINT32_C(3)

typedef struct {
    NvU32 peerIds[2];
    NvU32 egmPeerIds[2];
    NvU32 p2pLink;
    NvU32 optimalNvlinkWriteCEs[2];
    NvU32 totalLinkLineRateMBps;
    NvU64 bar1DmaAddress[2];
    NvU64 bar1DmaSize[2];
    NvBool bar1PcieAtomics[2];
} UvmGpuP2PCapsParams;

_Static_assert(sizeof(UvmGpuP2PCapsParams) == 72,
               "fixture must match pinned R595 P2P-caps payload size");
_Static_assert(offsetof(UvmGpuP2PCapsParams, bar1PcieAtomics) == 64,
               "fixture must match pinned R595 BAR1 atomics offset");

static struct hybrid580_uvm_device_registry hybrid580_uvm_devices;
static struct hybrid580_uvm_p2p_object_registry hybrid580_uvm_p2p_objects;
static int hybrid580_uvm_callback_lock;
static int hybrid580_uvm_sessions;
static unsigned test_open_caps_calls;
static unsigned test_legacy_caps_calls;
static unsigned test_open_object_calls;
static unsigned test_legacy_object_calls;
static unsigned test_quarantine_calls;
static unsigned test_peer_setup_calls;
static unsigned test_peer_cleanup_calls;
static unsigned test_rm_locked_calls;

static struct {
    int global_lock;
} g_uvm_global;

#define mutex_lock(lock) ((void)(lock))
#define mutex_unlock(lock) ((void)(lock))
#define pr_emerg(...) ((void)0)
#define uvm_rm_locked_call(expression) test_rm_locked_call((expression))
#define UVM_ASSERT(expression) assert(expression)
#define UVM_ERR_PRINT(...) ((void)0)
#define uvm_parent_id_value(id) (id)
#define uvm_assert_mutex_locked(lock) ((void)(lock))

static NV_STATUS test_rm_locked_call(NV_STATUS status)
{
    ++test_rm_locked_calls;
    return status;
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++test_quarantine_calls;
}

static uint32_t test_open_caps(void *context, uintptr_t device1,
                               uintptr_t device2, void *params)
{
    (void)context;
    (void)device1;
    (void)device2;
    (void)params;
    ++test_open_caps_calls;
    return NV_ERR_GENERIC;
}

static uint32_t test_legacy_caps(void *context, uintptr_t device1,
                                uintptr_t device2, void *params)
{
    (void)context;
    (void)device1;
    (void)device2;
    (void)params;
    ++test_legacy_caps_calls;
    return NV_ERR_GENERIC;
}

static const struct hybrid580_uvm_device_pair_backend_ops
hybrid580_open_p2p_caps_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = test_open_caps,
};

static const struct hybrid580_uvm_device_pair_backend_ops
hybrid580_legacy_p2p_caps_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = test_legacy_caps,
};

static uint32_t test_open_object_create(void *context, uintptr_t device1,
                                        uintptr_t device2,
                                        uint32_t *native_handle)
{
    (void)context;
    (void)device1;
    (void)device2;
    ++test_open_object_calls;
    *native_handle = UINT32_C(0x51);
    return NV_OK;
}

static uint32_t test_legacy_object_create(void *context, uintptr_t device1,
                                          uintptr_t device2,
                                          uint32_t *native_handle)
{
    (void)context;
    (void)device1;
    (void)device2;
    ++test_legacy_object_calls;
    *native_handle = UINT32_C(0x52);
    return NV_OK;
}

static void test_object_destroy(void *context, uintptr_t session,
                                uint32_t native_handle)
{
    (void)context;
    (void)session;
    (void)native_handle;
}

static struct hybrid580_uvm_p2p_object_backend_ops
hybrid580_open_p2p_object_ops(void)
{
    return (struct hybrid580_uvm_p2p_object_backend_ops) {
        .provider = HYBRID580_UVM_PROVIDER_OPEN,
        .native_session = UINT32_C(0x5001),
        .create = test_open_object_create,
        .destroy = test_object_destroy,
    };
}

static struct hybrid580_uvm_p2p_object_backend_ops
hybrid580_legacy_p2p_object_ops(void)
{
    return (struct hybrid580_uvm_p2p_object_backend_ops) {
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .native_session = UINT32_C(0x5002),
        .create = test_legacy_object_create,
        .destroy = test_object_destroy,
    };
}

typedef struct {
    uint32_t id;
    uvmGpuDeviceHandle rm_device;
} uvm_parent_gpu_t;

typedef struct {
    uint32_t ref_count;
} uvm_parent_gpu_peer_t;

static uvm_parent_gpu_t *test_parent_gpus[2];
static size_t test_parent_gpu_count;
static size_t test_parent_gpu_iteration;
static uvm_parent_gpu_peer_t test_peer_caps;

#define for_each_parent_gpu(gpu) \
    for (test_parent_gpu_iteration = 0; \
         test_parent_gpu_iteration < test_parent_gpu_count && \
         (((gpu) = test_parent_gpus[test_parent_gpu_iteration]), 1); \
         ++test_parent_gpu_iteration)

static uvm_parent_gpu_peer_t *parent_gpu_peer_caps(
    uvm_parent_gpu_t *gpu1, uvm_parent_gpu_t *gpu2)
{
    (void)gpu1;
    (void)gpu2;
    return &test_peer_caps;
}

static NV_STATUS parent_peers_init(uvm_parent_gpu_t *gpu1,
                                   uvm_parent_gpu_t *gpu2,
                                   uvm_parent_gpu_peer_t *caps)
{
    (void)gpu1;
    (void)gpu2;
    (void)caps;
    ++test_peer_setup_calls;
    return NV_OK;
}

static void parent_peers_destroy_static_link(uvm_parent_gpu_t *gpu)
{
    (void)gpu;
    ++test_peer_cleanup_calls;
}

/* INSERT_EXTRACTED_PRODUCTION_FUNCTIONS */

static int p2p_caps_are_exactly_no_link(const UvmGpuP2PCapsParams *caps)
{
    return caps->peerIds[0] == 0 && caps->peerIds[1] == 0 &&
           caps->egmPeerIds[0] == 0 && caps->egmPeerIds[1] == 0 &&
           caps->p2pLink == UVM_LINK_TYPE_NONE &&
           caps->optimalNvlinkWriteCEs[0] == 0 &&
           caps->optimalNvlinkWriteCEs[1] == 0 &&
           caps->totalLinkLineRateMBps == 0 &&
           caps->bar1DmaAddress[0] == 0 && caps->bar1DmaAddress[1] == 0 &&
           caps->bar1DmaSize[0] == 0 && caps->bar1DmaSize[1] == 0 &&
           caps->bar1PcieAtomics[0] == 0 && caps->bar1PcieAtomics[1] == 0;
}

int main(void)
{
    static int open_native_gpu;
    static int legacy_native_gpu;
    static unsigned char open_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x11};
    static unsigned char legacy_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x22};
    uvm_parent_gpu_t open_parent = {1, &open_native_gpu};
    uvm_parent_gpu_t legacy_parent = {2, &legacy_native_gpu};
    UvmGpuP2PCapsParams caps;
    NvHandle public_object = UINT32_C(0xdeadbeef);

    assert(hybrid580_uvm_device_registry_record(
               &hybrid580_uvm_devices, (uintptr_t)&open_native_gpu,
               HYBRID580_UVM_PROVIDER_OPEN, open_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
               &hybrid580_uvm_devices, (uintptr_t)&legacy_native_gpu,
               HYBRID580_UVM_PROVIDER_LEGACY, legacy_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);

    memset(&caps, 0xa5, sizeof(caps));
    assert(nvUvmInterfaceGetP2PCaps(&open_native_gpu, &legacy_native_gpu,
                                    &caps) == NV_OK);
    assert(p2p_caps_are_exactly_no_link(&caps));
    assert(test_open_caps_calls == 0 && test_legacy_caps_calls == 0);

    memset(&caps, 0xa5, sizeof(caps));
    assert(nvUvmInterfaceGetP2PCaps(&legacy_native_gpu, &open_native_gpu,
                                    &caps) == NV_OK);
    assert(p2p_caps_are_exactly_no_link(&caps));
    assert(test_open_caps_calls == 0 && test_legacy_caps_calls == 0);

    test_parent_gpus[0] = &open_parent;
    test_parent_gpus[1] = &legacy_parent;
    test_parent_gpu_count = 2;
    assert(parent_peers_discover_static_link(&open_parent) == NV_OK);
    assert(parent_peers_discover_static_link(&legacy_parent) == NV_OK);
    assert(test_rm_locked_calls == 2);
    assert(test_peer_setup_calls == 0 && test_peer_cleanup_calls == 0);
    assert(test_open_caps_calls == 0 && test_legacy_caps_calls == 0);

    assert(nvUvmInterfaceP2pObjectCreate(&open_native_gpu,
                                         &legacy_native_gpu,
                                         &public_object) ==
           NV_ERR_NOT_SUPPORTED);
    assert(public_object == 0);
    assert(test_open_object_calls == 0 && test_legacy_object_calls == 0);
    assert(hybrid580_uvm_p2p_objects.count == 0);
    assert(test_rm_locked_calls == 2);
    assert(test_quarantine_calls == 0);

    public_object = UINT32_C(0xdeadbeef);
    assert(nvUvmInterfaceP2pObjectCreate(&legacy_native_gpu,
                                         &open_native_gpu,
                                         &public_object) ==
           NV_ERR_NOT_SUPPORTED);
    assert(public_object == 0);
    assert(test_open_object_calls == 0 && test_legacy_object_calls == 0);
    assert(hybrid580_uvm_p2p_objects.count == 0);
    assert(test_rm_locked_calls == 2);
    assert(test_quarantine_calls == 0);

    puts("production bridge and R595 discovery contract passed");
    return 0;
}
