/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nvmisc.h"
#include "nv_uvm_types.h"
#include "hybrid580_uvm_abi_compat.h"
#include "hybrid580_uvm_gpu_route.h"

struct pci_dev;
typedef struct {
    struct pci_dev *pci_dev;
    NvU64 dma_addressable_start;
    NvU64 dma_addressable_limit;
} UvmGpuPlatformInfo;

#define ROUTE_STATUS_UUID_NOT_FOUND UINT32_C(0xe0010001)
#define ROUTE_STATUS_NO_MEMORY      UINT32_C(0xe0010002)
#define ROUTE_STATUS_GENERIC        UINT32_C(0xe0010003)

#ifndef HYBRID580_TEST_GPU_ARCH
#error "the test must pass architecture and class IDs compiled from R580 headers"
#endif
#ifndef HYBRID580_TEST_HOST_CLASS
#error "the test must pass architecture and class IDs compiled from R580 headers"
#endif
#ifndef HYBRID580_TEST_CE_CLASS
#error "the test must pass architecture and class IDs compiled from R580 headers"
#endif
#ifndef HYBRID580_TEST_COMPUTE_CLASS
#error "the test must pass architecture and class IDs compiled from R580 headers"
#endif

static NvU32 fake_r580_sysmem_link;
static NvU32 fake_r580_access_counter_buffers;
static NV_STATUS fake_r580_status;
static unsigned fake_r580_info_calls;
static NvU32 fake_r595_access_counter_buffers;
static NV_STATUS fake_r595_status;
static unsigned fake_r595_info_calls;
static int hybrid580_uvm_callback_lock;
static unsigned hybrid580_test_lock_depth;
static unsigned hybrid580_test_lock_calls;
static unsigned hybrid580_test_unlock_calls;
static struct hybrid580_uvm_gpu_registry hybrid580_uvm_gpu_registry;
static struct hybrid580_uvm_gpu_backend_ops hybrid580_open_gpu_ops;
static struct hybrid580_uvm_gpu_backend_ops hybrid580_legacy_gpu_ops;
static struct hybrid580_uvm_gpu_info_backend_ops hybrid580_open_gpu_info_ops;
static struct hybrid580_uvm_gpu_info_backend_ops hybrid580_legacy_gpu_info_ops;

static void hybrid580_test_mutex_lock(int *lock)
{
    assert(lock == &hybrid580_uvm_callback_lock);
    assert(hybrid580_test_lock_depth == 0);
    ++hybrid580_test_lock_depth;
    ++hybrid580_test_lock_calls;
}

static void hybrid580_test_mutex_unlock(int *lock)
{
    assert(lock == &hybrid580_uvm_callback_lock);
    assert(hybrid580_test_lock_depth == 1);
    --hybrid580_test_lock_depth;
    ++hybrid580_test_unlock_calls;
}

#define mutex_lock(lock) hybrid580_test_mutex_lock(lock)
#define mutex_unlock(lock) hybrid580_test_mutex_unlock(lock)
#define EXPORT_SYMBOL(symbol)

static NV_STATUS hybrid580_open_nvUvmInterfaceGetGpuInfo(
    const NvProcessorUuid *uuid,
    const UvmGpuClientInfo *client_info,
    UvmGpuInfo *gpu_info)
{
    assert(uuid != NULL && client_info != NULL && gpu_info != NULL);
    ++fake_r595_info_calls;
    gpu_info->sysmemLink = UVM_LINK_TYPE_PCIE;
    gpu_info->accessCntrBufferCount = fake_r595_access_counter_buffers;
    return fake_r595_status;
}

static NV_STATUS hybrid580_legacy_nvUvmInterfaceGetGpuInfo(
    const NvProcessorUuid *uuid,
    const UvmGpuClientInfo *client_info,
    UvmGpuInfo *gpu_info)
{
    assert(uuid != NULL && client_info != NULL && gpu_info != NULL);
    ++fake_r580_info_calls;
    gpu_info->sysmemLink = fake_r580_sysmem_link;
    gpu_info->accessCntrBufferCount = fake_r580_access_counter_buffers;
    /* R580 header-derived values exercise the adapter, not a hardware capture. */
    gpu_info->gpuArch = HYBRID580_TEST_GPU_ARCH;
    gpu_info->gpuImplementation = 0;
    gpu_info->hostClass = HYBRID580_TEST_HOST_CLASS;
    gpu_info->ceClass = HYBRID580_TEST_CE_CLASS;
    gpu_info->computeClass = HYBRID580_TEST_COMPUTE_CLASS;
    gpu_info->virtMode = 0;
    return fake_r580_status;
}

/* INSERT_EXACT_OPEN_GPU_INFO_CALLBACK */
/* INSERT_EXACT_LEGACY_GPU_INFO_CALLBACK */

struct fake_registration_provider {
    uint32_t status;
    uint32_t platform_marker;
    unsigned register_calls;
    unsigned unregister_calls;
};

static uint32_t fake_register_gpu(void *context,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    void *platform_info, size_t platform_info_size)
{
    struct fake_registration_provider *provider = context;

    assert(uuid != NULL && platform_info != NULL);
    ++provider->register_calls;
    if (provider->status == 0) {
        assert(platform_info_size >= sizeof(provider->platform_marker));
        memset(platform_info, 0, platform_info_size);
        memcpy(platform_info, &provider->platform_marker,
               sizeof(provider->platform_marker));
    }
    return provider->status;
}

static void fake_unregister_gpu(void *context,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES])
{
    struct fake_registration_provider *provider = context;

    assert(uuid != NULL);
    ++provider->unregister_calls;
}

static struct hybrid580_uvm_gpu_backend_ops make_registration_ops(
    struct fake_registration_provider *provider,
    enum hybrid580_uvm_provider owner)
{
    return (struct hybrid580_uvm_gpu_backend_ops) {
        .context = provider,
        .provider = owner,
        .register_gpu = fake_register_gpu,
        .unregister_gpu = fake_unregister_gpu,
    };
}

static struct hybrid580_uvm_gpu_info_backend_ops make_gpu_info_ops(
    enum hybrid580_uvm_provider owner,
    uint32_t (*get_info)(void *, const unsigned char *, const void *, void *))
{
    return (struct hybrid580_uvm_gpu_info_backend_ops) {
        .context = NULL,
        .provider = owner,
        .get_gpu_info = get_info,
    };
}

/* INSERT_EXACT_PUBLIC_GPU_API_WRAPPERS */

static void test_exported_gpu_info_wrappers(void)
{
    struct fake_registration_provider open_registration = {
        .status = NV_ERR_GPU_UUID_NOT_FOUND,
        .platform_marker = 0x11111111,
    };
    struct fake_registration_provider legacy_registration = {
        .status = NV_OK,
        .platform_marker = 0x22222222,
    };
    NvProcessorUuid processor_uuid = {0};
    NvProcessorUuid unknown_uuid = {0};
    NvProcessorUuid ambiguous_uuid = {0};
    NvProcessorUuid unowned_uuid = {0};
    UvmGpuClientInfo client = {0};
    UvmGpuPlatformInfo platform_info;
    UvmGpuInfo info;
    NvU32 marker = 0;
    enum hybrid580_uvm_provider provider = 0;
    unsigned open_info_calls_before;
    unsigned legacy_info_calls_before;

    memset(&hybrid580_uvm_gpu_registry, 0, sizeof(hybrid580_uvm_gpu_registry));
    hybrid580_test_lock_depth = 0;
    hybrid580_test_lock_calls = 0;
    hybrid580_test_unlock_calls = 0;
    hybrid580_open_gpu_ops = make_registration_ops(
        &open_registration, HYBRID580_UVM_PROVIDER_OPEN);
    hybrid580_legacy_gpu_ops = make_registration_ops(
        &legacy_registration, HYBRID580_UVM_PROVIDER_LEGACY);
    hybrid580_open_gpu_info_ops = make_gpu_info_ops(
        HYBRID580_UVM_PROVIDER_OPEN, hybrid580_open_gpu_get_info);
    hybrid580_legacy_gpu_info_ops = make_gpu_info_ops(
        HYBRID580_UVM_PROVIDER_LEGACY, hybrid580_legacy_gpu_get_info);
    processor_uuid.uuid[0] = 0x91;
    unknown_uuid.uuid[0] = 0x92;
    ambiguous_uuid.uuid[0] = 0x93;
    unowned_uuid.uuid[0] = 0x94;

    /* Invalid public arguments must not acquire the callback lock. */
    memset(&platform_info, 0xa5, sizeof(platform_info));
    assert(nvUvmInterfaceRegisterGpu(NULL, &platform_info) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(platform_info.pci_dev == NULL &&
           platform_info.dma_addressable_start == 0 &&
           platform_info.dma_addressable_limit == 0);
    assert(nvUvmInterfaceRegisterGpu(&processor_uuid, NULL) ==
           NV_ERR_INVALID_ARGUMENT);
    memset(&info, 0xa5, sizeof(info));
    assert(nvUvmInterfaceGetGpuInfo(NULL, &client, &info) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(info.gpuArch == 0 && info.hostClass == 0 && info.ceClass == 0);
    memset(&info, 0xa5, sizeof(info));
    assert(nvUvmInterfaceGetGpuInfo(&processor_uuid, NULL, &info) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(info.gpuArch == 0 && info.hostClass == 0 && info.ceClass == 0);
    assert(nvUvmInterfaceGetGpuInfo(&processor_uuid, &client, NULL) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(hybrid580_test_lock_calls == 0 &&
           hybrid580_test_unlock_calls == 0);

    memset(&platform_info, 0xa5, sizeof(platform_info));
    assert(nvUvmInterfaceRegisterGpu(&processor_uuid, &platform_info) == NV_OK);
    memcpy(&marker, &platform_info, sizeof(marker));
    assert(marker == legacy_registration.platform_marker);
    assert(open_registration.register_calls == 1);
    assert(legacy_registration.register_calls == 1);
    assert(hybrid580_uvm_gpu_registry_lookup(
               &hybrid580_uvm_gpu_registry, processor_uuid.uuid,
               &provider, NULL) == HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(provider == HYBRID580_UVM_PROVIDER_LEGACY);

    /* Re-registering the UUID must preserve its owner and use only that RM. */
    memset(&platform_info, 0xa5, sizeof(platform_info));
    assert(nvUvmInterfaceRegisterGpu(&processor_uuid, &platform_info) == NV_OK);
    memcpy(&marker, &platform_info, sizeof(marker));
    assert(marker == legacy_registration.platform_marker);
    assert(open_registration.register_calls == 1);
    assert(legacy_registration.register_calls == 2);

    /* Neither backend claiming an UUID leaves no owner and no stale output. */
    open_registration.status = NV_ERR_GENERIC;
    legacy_registration.status = NV_ERR_GENERIC;
    memset(&platform_info, 0xa5, sizeof(platform_info));
    assert(nvUvmInterfaceRegisterGpu(&unowned_uuid, &platform_info) ==
           NV_ERR_GENERIC);
    assert(platform_info.pci_dev == NULL &&
           platform_info.dma_addressable_start == 0 &&
           platform_info.dma_addressable_limit == 0);
    assert(hybrid580_uvm_gpu_registry_lookup(
               &hybrid580_uvm_gpu_registry, unowned_uuid.uuid,
               &provider, NULL) == HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND);

    /* If both RMs claim a UUID, both registrations roll back. */
    open_registration.status = NV_OK;
    legacy_registration.status = NV_OK;
    memset(&platform_info, 0xa5, sizeof(platform_info));
    assert(nvUvmInterfaceRegisterGpu(&ambiguous_uuid, &platform_info) ==
           NV_ERR_GENERIC);
    assert(platform_info.pci_dev == NULL &&
           platform_info.dma_addressable_start == 0 &&
           platform_info.dma_addressable_limit == 0);
    assert(open_registration.unregister_calls == 1);
    assert(legacy_registration.unregister_calls == 1);
    assert(hybrid580_uvm_gpu_registry_lookup(
               &hybrid580_uvm_gpu_registry, ambiguous_uuid.uuid,
               &provider, NULL) == HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND);

    fake_r580_sysmem_link = HYBRID580_R580_LINK_TYPE_NVLINK_3;
    fake_r580_access_counter_buffers = 2;
    fake_r580_status = NV_OK;
    fake_r580_info_calls = 0;
    fake_r595_info_calls = 0;
    memset(&info, 0xa5, sizeof(info));
    assert(nvUvmInterfaceGetGpuInfo(&processor_uuid, &client, &info) == NV_OK);
    assert(info.gpuArch == HYBRID580_TEST_GPU_ARCH);
    assert(info.hostClass == HYBRID580_TEST_HOST_CLASS);
    assert(info.ceClass == HYBRID580_TEST_CE_CLASS);
    assert(info.computeClass == HYBRID580_TEST_COMPUTE_CLASS);
    assert(info.sysmemLink == UVM_LINK_TYPE_NVLINK_3);
    assert(info.accessCntrBufferCount == 1);
    assert(fake_r580_info_calls == 1 && fake_r595_info_calls == 0);

    /* SMC handles are rejected before either provider is called. */
    client.hSmcPartRef = 1;
    memset(&info, 0xa5, sizeof(info));
    open_info_calls_before = fake_r595_info_calls;
    legacy_info_calls_before = fake_r580_info_calls;
    assert(nvUvmInterfaceGetGpuInfo(&processor_uuid, &client, &info) ==
           NV_ERR_NOT_SUPPORTED);
    assert(info.gpuArch == 0 && info.hostClass == 0 && info.ceClass == 0);
    assert(fake_r595_info_calls == open_info_calls_before);
    assert(fake_r580_info_calls == legacy_info_calls_before);
    client.hSmcPartRef = 0;

    /* Owner errors clear output and never fall through to the other RM. */
    fake_r580_status = NV_ERR_NOT_SUPPORTED;
    memset(&info, 0xa5, sizeof(info));
    assert(nvUvmInterfaceGetGpuInfo(&processor_uuid, &client, &info) ==
           NV_ERR_NOT_SUPPORTED);
    assert(info.gpuArch == 0 && info.hostClass == 0 && info.ceClass == 0);
    assert(fake_r580_info_calls == legacy_info_calls_before + 1);
    assert(fake_r595_info_calls == open_info_calls_before);

    /* Unknown UUIDs report the public not-found status with cleared output. */
    memset(&info, 0xa5, sizeof(info));
    assert(nvUvmInterfaceGetGpuInfo(&unknown_uuid, &client, &info) ==
           NV_ERR_GPU_UUID_NOT_FOUND);
    assert(info.gpuArch == 0 && info.hostClass == 0 && info.ceClass == 0);
    assert(fake_r580_info_calls == legacy_info_calls_before + 1);
    assert(fake_r595_info_calls == open_info_calls_before);

    assert(hybrid580_test_lock_depth == 0);
    assert(hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void test_composed_legacy_gpu_info_route(void)
{
    struct hybrid580_uvm_gpu_registry registry = {0};
    struct fake_registration_provider open_registration = {
        .status = ROUTE_STATUS_UUID_NOT_FOUND,
        .platform_marker = 0x11111111,
    };
    struct fake_registration_provider legacy_registration = {
        .status = 0,
        .platform_marker = 0x22222222,
    };
    unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x83};
    unsigned char unknown_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x84};
    NvProcessorUuid processor_uuid = {0};
    UvmGpuClientInfo client = {0};
    UvmGpuInfo info;
    NvU32 platform_info = 0;
    NvU32 open_platform_info = 0;
    NvU32 legacy_platform_info = 0;
    enum hybrid580_uvm_provider owner = 0;

    memcpy(processor_uuid.uuid, uuid, sizeof(processor_uuid.uuid));
    assert(hybrid580_uvm_gpu_route_register(
               &registry, uuid, &platform_info, sizeof(platform_info),
               &open_platform_info, &legacy_platform_info,
               make_registration_ops(&open_registration,
                                     HYBRID580_UVM_PROVIDER_OPEN),
               make_registration_ops(&legacy_registration,
                                     HYBRID580_UVM_PROVIDER_LEGACY),
               ROUTE_STATUS_UUID_NOT_FOUND, ROUTE_STATUS_NO_MEMORY,
               ROUTE_STATUS_GENERIC) == 0);
    assert(platform_info == legacy_registration.platform_marker);
    assert(open_registration.register_calls == 1 &&
           legacy_registration.register_calls == 1);
    assert(hybrid580_uvm_gpu_registry_lookup(&registry, uuid, &owner, NULL) ==
           HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(owner == HYBRID580_UVM_PROVIDER_LEGACY);

    fake_r580_sysmem_link = HYBRID580_R580_LINK_TYPE_NVLINK_3;
    fake_r580_access_counter_buffers = 2;
    fake_r580_status = NV_OK;
    fake_r580_info_calls = 0;
    fake_r595_info_calls = 0;
    memset(&info, 0, sizeof(info));
    assert(hybrid580_uvm_gpu_route_get_info(
               &registry, processor_uuid.uuid, &client, &info, sizeof(info),
               make_gpu_info_ops(HYBRID580_UVM_PROVIDER_OPEN,
                                 hybrid580_open_gpu_get_info),
               make_gpu_info_ops(HYBRID580_UVM_PROVIDER_LEGACY,
                                 hybrid580_legacy_gpu_get_info),
               ROUTE_STATUS_UUID_NOT_FOUND, ROUTE_STATUS_GENERIC) == NV_OK);
    assert(info.gpuArch == HYBRID580_TEST_GPU_ARCH &&
           info.hostClass == HYBRID580_TEST_HOST_CLASS &&
           info.ceClass == HYBRID580_TEST_CE_CLASS);
    assert(info.sysmemLink == UVM_LINK_TYPE_NVLINK_3);
    assert(info.accessCntrBufferCount == 1);
    assert(fake_r580_info_calls == 1 && fake_r595_info_calls == 0);

    /* An owner failure clears the result and never falls through to the open RM. */
    fake_r580_status = NV_ERR_NOT_SUPPORTED;
    memset(&info, 0xa5, sizeof(info));
    assert(hybrid580_uvm_gpu_route_get_info(
               &registry, processor_uuid.uuid, &client, &info, sizeof(info),
               make_gpu_info_ops(HYBRID580_UVM_PROVIDER_OPEN,
                                 hybrid580_open_gpu_get_info),
               make_gpu_info_ops(HYBRID580_UVM_PROVIDER_LEGACY,
                                 hybrid580_legacy_gpu_get_info),
               ROUTE_STATUS_UUID_NOT_FOUND, ROUTE_STATUS_GENERIC) ==
           NV_ERR_NOT_SUPPORTED);
    assert(info.gpuArch == 0 && info.hostClass == 0 && info.ceClass == 0);
    assert(fake_r580_info_calls == 2 && fake_r595_info_calls == 0);

    /* An untranslatable R580 link is also rejected with a cleared result. */
    fake_r580_status = NV_OK;
    fake_r580_sysmem_link = UINT32_MAX;
    memset(&info, 0xa5, sizeof(info));
    assert(hybrid580_uvm_gpu_route_get_info(
               &registry, processor_uuid.uuid, &client, &info, sizeof(info),
               make_gpu_info_ops(HYBRID580_UVM_PROVIDER_OPEN,
                                 hybrid580_open_gpu_get_info),
               make_gpu_info_ops(HYBRID580_UVM_PROVIDER_LEGACY,
                                 hybrid580_legacy_gpu_get_info),
               ROUTE_STATUS_UUID_NOT_FOUND, ROUTE_STATUS_GENERIC) ==
           NV_ERR_NOT_SUPPORTED);
    assert(info.gpuArch == 0 && info.hostClass == 0 && info.ceClass == 0);
    assert(fake_r580_info_calls == 3 && fake_r595_info_calls == 0);

    assert(hybrid580_uvm_gpu_route_get_info(
               &registry, unknown_uuid, &client, &info, sizeof(info),
               make_gpu_info_ops(HYBRID580_UVM_PROVIDER_OPEN,
                                 hybrid580_open_gpu_get_info),
               make_gpu_info_ops(HYBRID580_UVM_PROVIDER_LEGACY,
                                 hybrid580_legacy_gpu_get_info),
               ROUTE_STATUS_UUID_NOT_FOUND, ROUTE_STATUS_GENERIC) ==
           ROUTE_STATUS_UUID_NOT_FOUND);
    assert(fake_r580_info_calls == 3 && fake_r595_info_calls == 0);
}

int main(void)
{
    static const NvU32 old_values[] = {
        HYBRID580_R580_LINK_TYPE_NONE,
        HYBRID580_R580_LINK_TYPE_PCIE,
        HYBRID580_R580_LINK_TYPE_NVLINK_1,
        HYBRID580_R580_LINK_TYPE_NVLINK_2,
        HYBRID580_R580_LINK_TYPE_NVLINK_3,
        HYBRID580_R580_LINK_TYPE_NVLINK_4,
        HYBRID580_R580_LINK_TYPE_NVLINK_5,
        HYBRID580_R580_LINK_TYPE_C2C,
    };
    static const NvU32 new_values[] = {
        UVM_LINK_TYPE_NONE,
        UVM_LINK_TYPE_PCIE,
        UVM_LINK_TYPE_NVLINK_1,
        UVM_LINK_TYPE_NVLINK_2,
        UVM_LINK_TYPE_NVLINK_3,
        UVM_LINK_TYPE_NVLINK_4,
        UVM_LINK_TYPE_NVLINK_5,
        UVM_LINK_TYPE_C2C,
    };
    static const NvU32 access_counter_inputs[] = {0, 1, 2, UINT32_MAX};
    static const NvU32 access_counter_outputs[] = {0, 1, 1, 1};
    static const NvU32 open_access_counter_inputs[] = {0, 1, 2, UINT32_MAX};
    NvProcessorUuid uuid = {0};
    UvmGpuClientInfo client = {0};
    UvmGpuInfo info;
    size_t i;
    size_t j;
    size_t k;

    for (k = 0; k < sizeof(open_access_counter_inputs) /
                    sizeof(open_access_counter_inputs[0]); ++k) {
        memset(&info, 0, sizeof(info));
        fake_r595_access_counter_buffers = open_access_counter_inputs[k];
        fake_r595_status = NV_OK;
        assert(hybrid580_open_gpu_get_info(NULL, uuid.uuid, &client, &info) == NV_OK);
        assert(info.sysmemLink == UVM_LINK_TYPE_PCIE);
        assert(info.accessCntrBufferCount == open_access_counter_inputs[k]);
    }

    for (i = 0; i < sizeof(old_values) / sizeof(old_values[0]); ++i) {
        memset(&info, 0, sizeof(info));
        fake_r580_sysmem_link = old_values[i];
        fake_r580_access_counter_buffers = 1;
        fake_r580_status = NV_OK;
        assert(hybrid580_legacy_gpu_get_info(NULL, uuid.uuid, &client, &info) == NV_OK);
        assert(info.sysmemLink == new_values[i]);
        assert(info.accessCntrBufferCount == 1);
        assert(info.gpuArch == HYBRID580_TEST_GPU_ARCH);
        assert(info.gpuImplementation == 0);
        assert(info.hostClass == HYBRID580_TEST_HOST_CLASS);
        assert(info.ceClass == HYBRID580_TEST_CE_CLASS);
        assert(info.computeClass == HYBRID580_TEST_COMPUTE_CLASS);
        assert(info.virtMode == 0);
    }

    for (j = 0; j < sizeof(access_counter_inputs) / sizeof(access_counter_inputs[0]); ++j) {
        memset(&info, 0, sizeof(info));
        fake_r580_sysmem_link = HYBRID580_R580_LINK_TYPE_PCIE;
        fake_r580_access_counter_buffers = access_counter_inputs[j];
        fake_r580_status = NV_OK;
        assert(hybrid580_legacy_gpu_get_info(NULL, uuid.uuid, &client, &info) == NV_OK);
        assert(info.accessCntrBufferCount == access_counter_outputs[j]);
    }

    test_composed_legacy_gpu_info_route();
    test_exported_gpu_info_wrappers();

    memset(&info, 0, sizeof(info));
    fake_r595_access_counter_buffers = UINT32_MAX;
    fake_r595_status = NV_ERR_NOT_SUPPORTED;
    assert(hybrid580_open_gpu_get_info(NULL, uuid.uuid, &client, &info) ==
           NV_ERR_NOT_SUPPORTED);
    assert(info.accessCntrBufferCount == UINT32_MAX);

    memset(&info, 0, sizeof(info));
    fake_r580_sysmem_link = UINT32_MAX;
    fake_r580_access_counter_buffers = UINT32_MAX;
    fake_r580_status = NV_OK;
    assert(hybrid580_legacy_gpu_get_info(NULL, uuid.uuid, &client, &info) ==
           NV_ERR_NOT_SUPPORTED);
    assert(info.sysmemLink == 0);
    assert(info.accessCntrBufferCount == 0);
    assert(info.gpuArch == 0);
    assert(info.gpuImplementation == 0);
    assert(info.hostClass == 0);
    assert(info.ceClass == 0);
    assert(info.computeClass == 0);
    assert(info.virtMode == 0);

    memset(&info, 0, sizeof(info));
    fake_r580_sysmem_link = HYBRID580_R580_LINK_TYPE_PCIE;
    fake_r580_access_counter_buffers = UINT32_MAX;
    fake_r580_status = NV_ERR_NOT_SUPPORTED;
    assert(hybrid580_legacy_gpu_get_info(NULL, uuid.uuid, &client, &info) ==
           NV_ERR_NOT_SUPPORTED);
    assert(info.sysmemLink == 0);
    assert(info.accessCntrBufferCount == 0);
    assert(info.gpuArch == 0);
    assert(info.gpuImplementation == 0);
    assert(info.hostClass == 0);
    assert(info.ceClass == 0);
    assert(info.computeClass == 0);
    assert(info.virtMode == 0);

    puts("legacy GPU-info adapter, UUID-owner route, and exported wrappers passed");
    return 0;
}
