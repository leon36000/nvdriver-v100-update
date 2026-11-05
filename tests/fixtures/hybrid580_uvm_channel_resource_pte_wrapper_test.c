/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t NV_STATUS;
typedef uint32_t NvBool;
typedef uint32_t NvU32;
typedef uint64_t NvU64;
typedef uintptr_t NvP64;
typedef void *uvmGpuAddressSpaceHandle;
typedef struct {
    uint64_t fields[4];
} UvmGpuExternalMappingInfo;

#define NV_OK                    UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0xe0013801)
#define NV_ERR_GENERIC          UINT32_C(0xe0013802)
#define TEST_PROVIDER_ERROR     UINT32_C(0xe0013803)
#define NV_FALSE                UINT32_C(0)
#define NV_TRUE                 UINT32_C(1)
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

#include "src/hybrid580_uvm_address_space_route.h"

struct fake_backend {
    uintptr_t expected_space;
    NvP64 expected_descriptor;
    NvU64 expected_offset;
    NvU64 expected_size;
    UvmGpuExternalMappingInfo expected_info;
    UvmGpuExternalMappingInfo result_info;
    NV_STATUS status;
    NvU64 expected_phys_address;
    unsigned expected_num_entries;
    NvBool expected_video_aperture;
    NvU32 expected_pasid;
    NvU64 dma_result;
    NV_STATUS set_page_directory_status;
    NV_STATUS unset_page_directory_status;
    unsigned calls;
    unsigned set_page_directory_calls;
    unsigned unset_page_directory_calls;
    uintptr_t last_unset_space;
};

static struct hybrid580_uvm_address_space_registry hybrid580_uvm_address_spaces;
static struct hybrid580_uvm_address_space_entry hybrid580_test_open_space;
static struct hybrid580_uvm_address_space_entry hybrid580_test_legacy_space;
static int hybrid580_uvm_callback_lock;
static struct fake_backend hybrid580_test_open;
static struct fake_backend hybrid580_test_legacy;
static unsigned hybrid580_test_lock_depth;
static unsigned hybrid580_test_lock_calls;
static unsigned hybrid580_test_unlock_calls;
static unsigned hybrid580_test_quarantine_pins;

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

static NV_STATUS hybrid580_test_get_channel_resource_ptes(
    struct fake_backend *backend, uvmGpuAddressSpaceHandle va_space,
    NvP64 resource_descriptor, NvU64 offset, NvU64 size,
    UvmGpuExternalMappingInfo *external_mapping_info)
{
    assert((uintptr_t)va_space == backend->expected_space);
    assert(resource_descriptor == backend->expected_descriptor);
    assert(offset == backend->expected_offset);
    assert(size == backend->expected_size);
    assert(external_mapping_info != NULL);
    assert(memcmp(external_mapping_info, &backend->expected_info,
                  sizeof(*external_mapping_info)) == 0);
    ++backend->calls;
    *external_mapping_info = backend->result_info;
    return backend->status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceGetChannelResourcePtes(
    uvmGpuAddressSpaceHandle va_space, NvP64 resource_descriptor,
    NvU64 offset, NvU64 size,
    UvmGpuExternalMappingInfo *external_mapping_info)
{
    return hybrid580_test_get_channel_resource_ptes(&hybrid580_test_open,
        va_space, resource_descriptor, offset, size, external_mapping_info);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceGetChannelResourcePtes(
    uvmGpuAddressSpaceHandle va_space, NvP64 resource_descriptor,
    NvU64 offset, NvU64 size,
    UvmGpuExternalMappingInfo *external_mapping_info)
{
    return hybrid580_test_get_channel_resource_ptes(&hybrid580_test_legacy,
        va_space, resource_descriptor, offset, size, external_mapping_info);
}

static NV_STATUS hybrid580_test_set_page_directory(
    struct fake_backend *backend, uvmGpuAddressSpaceHandle va_space,
    NvU64 phys_address, unsigned num_entries, NvBool video_aperture,
    NvU32 pasid, NvU64 *dma_address)
{
    assert((uintptr_t)va_space == backend->expected_space);
    assert(phys_address == backend->expected_phys_address);
    assert(num_entries == backend->expected_num_entries);
    assert(video_aperture == backend->expected_video_aperture);
    assert(pasid == backend->expected_pasid);
    assert(dma_address != NULL);
    ++backend->set_page_directory_calls;
    *dma_address = backend->dma_result;
    return backend->set_page_directory_status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceSetPageDirectory(
    uvmGpuAddressSpaceHandle va_space, NvU64 phys_address,
    unsigned num_entries, NvBool video_aperture, NvU32 pasid,
    NvU64 *dma_address)
{
    return hybrid580_test_set_page_directory(&hybrid580_test_open, va_space,
        phys_address, num_entries, video_aperture, pasid, dma_address);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceSetPageDirectory(
    uvmGpuAddressSpaceHandle va_space, NvU64 phys_address,
    unsigned num_entries, NvBool video_aperture, NvU32 pasid,
    NvU64 *dma_address)
{
    return hybrid580_test_set_page_directory(&hybrid580_test_legacy, va_space,
        phys_address, num_entries, video_aperture, pasid, dma_address);
}

static NV_STATUS hybrid580_test_unset_page_directory(
    struct fake_backend *backend, uvmGpuAddressSpaceHandle va_space)
{
    assert((uintptr_t)va_space == backend->expected_space);
    ++backend->unset_page_directory_calls;
    backend->last_unset_space = (uintptr_t)va_space;
    return backend->unset_page_directory_status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceUnsetPageDirectory(
    uvmGpuAddressSpaceHandle va_space)
{
    return hybrid580_test_unset_page_directory(&hybrid580_test_open, va_space);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceUnsetPageDirectory(
    uvmGpuAddressSpaceHandle va_space)
{
    return hybrid580_test_unset_page_directory(&hybrid580_test_legacy,
                                                va_space);
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++hybrid580_test_quarantine_pins;
}

/* INSERT_EXACT_RESOURCE_PTE_TYPES */
/* INSERT_EXACT_RESOURCE_PTE_ADAPTERS */
/* INSERT_EXACT_RESOURCE_PTE_OPS */
/* INSERT_EXACT_PAGE_DIRECTORY_TYPES */
/* INSERT_EXACT_PAGE_DIRECTORY_ADAPTERS */
/* INSERT_EXACT_PAGE_DIRECTORY_OPS */
/* INSERT_EXACT_ADDRESS_SPACE_CALL_HELPER */
/* INSERT_EXACT_RESOURCE_PTE_PUBLIC_WRAPPER */
/* INSERT_EXACT_PAGE_DIRECTORY_PUBLIC_WRAPPERS */

static void hybrid580_test_reset(void)
{
    memset(&hybrid580_uvm_address_spaces, 0,
           sizeof(hybrid580_uvm_address_spaces));
    memset(&hybrid580_test_open_space, 0, sizeof(hybrid580_test_open_space));
    memset(&hybrid580_test_legacy_space, 0,
           sizeof(hybrid580_test_legacy_space));
    memset(&hybrid580_test_open, 0, sizeof(hybrid580_test_open));
    memset(&hybrid580_test_legacy, 0, sizeof(hybrid580_test_legacy));
    hybrid580_test_lock_depth = 0;
    hybrid580_test_lock_calls = 0;
    hybrid580_test_unlock_calls = 0;
    hybrid580_test_quarantine_pins = 0;
    hybrid580_test_open.expected_space = 0x1000;
    hybrid580_test_open.expected_descriptor = 0xa1;
    hybrid580_test_open.expected_offset = 0x1000;
    hybrid580_test_open.expected_size = 0x2000;
    hybrid580_test_open.expected_info.fields[0] = 0xa001;
    hybrid580_test_open.expected_info.fields[1] = 0xa002;
    hybrid580_test_open.expected_info.fields[2] = 0xa003;
    hybrid580_test_open.expected_info.fields[3] = 0xa004;
    hybrid580_test_open.result_info.fields[0] = 0xa101;
    hybrid580_test_open.result_info.fields[1] = 0xa102;
    hybrid580_test_open.status = NV_OK;
    hybrid580_test_open.expected_phys_address = 0x100000;
    hybrid580_test_open.expected_num_entries = 64;
    hybrid580_test_open.expected_video_aperture = NV_TRUE;
    hybrid580_test_open.expected_pasid = 0x123;
    hybrid580_test_open.dma_result = 0xaabbccdd;
    hybrid580_test_open.set_page_directory_status = NV_OK;
    hybrid580_test_open.unset_page_directory_status = NV_OK;
    hybrid580_test_legacy.expected_space = 0x2000;
    hybrid580_test_legacy.expected_descriptor = 0xb1;
    hybrid580_test_legacy.expected_offset = 0x3000;
    hybrid580_test_legacy.expected_size = 0x4000;
    hybrid580_test_legacy.expected_info.fields[0] = 0xb001;
    hybrid580_test_legacy.expected_info.fields[1] = 0xb002;
    hybrid580_test_legacy.expected_info.fields[2] = 0xb003;
    hybrid580_test_legacy.expected_info.fields[3] = 0xb004;
    hybrid580_test_legacy.result_info.fields[0] = 0xb101;
    hybrid580_test_legacy.result_info.fields[1] = 0xb102;
    hybrid580_test_legacy.status = TEST_PROVIDER_ERROR;
    hybrid580_test_legacy.expected_phys_address = 0x200000;
    hybrid580_test_legacy.expected_num_entries = 128;
    hybrid580_test_legacy.expected_video_aperture = NV_FALSE;
    hybrid580_test_legacy.expected_pasid = 0x456;
    hybrid580_test_legacy.dma_result = 0x11223344;
    hybrid580_test_legacy.set_page_directory_status = NV_OK;
    hybrid580_test_legacy.unset_page_directory_status = TEST_PROVIDER_ERROR;
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_open_space,
               0x1000, 0x0100, HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_legacy_space,
               0x2000, 0x0200, HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
}

static void hybrid580_test_assert_locks_balanced(void)
{
    assert(hybrid580_test_lock_depth == 0);
    assert(hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_provider_routing_copies_backend_payload(void)
{
    UvmGpuExternalMappingInfo open_info = {
        .fields = {0xa001, 0xa002, 0xa003, 0xa004},
    };
    UvmGpuExternalMappingInfo legacy_info = {
        .fields = {0xb001, 0xb002, 0xb003, 0xb004},
    };
    UvmGpuExternalMappingInfo invalid_info = {
        .fields = {0xc001, 0xc002, 0xc003, 0xc004},
    };

    hybrid580_test_reset();
    assert(nvUvmInterfaceGetChannelResourcePtes(
               (uvmGpuAddressSpaceHandle)0x1000, 0xa1, 0x1000, 0x2000,
               &open_info) == NV_OK);
    assert(open_info.fields[0] == 0xa101 &&
           open_info.fields[1] == 0xa102 &&
           hybrid580_test_open.calls == 1 &&
           hybrid580_test_legacy.calls == 0);

    assert(nvUvmInterfaceGetChannelResourcePtes(
               (uvmGpuAddressSpaceHandle)0x2000, 0xb1, 0x3000, 0x4000,
               &legacy_info) == TEST_PROVIDER_ERROR);
    assert(legacy_info.fields[0] == 0xb101 &&
           legacy_info.fields[1] == 0xb102 &&
           hybrid580_test_legacy.calls == 1 &&
           hybrid580_test_open.calls == 1);

    assert(nvUvmInterfaceGetChannelResourcePtes(
               (uvmGpuAddressSpaceHandle)0x9999, 0xa1, 0x1000, 0x2000,
               &invalid_info) == NV_ERR_INVALID_ARGUMENT);
    assert(invalid_info.fields[0] == 0xc001 &&
           invalid_info.fields[1] == 0xc002 &&
           hybrid580_test_quarantine_pins == 1 &&
           hybrid580_test_open.calls == 1 &&
           hybrid580_test_legacy.calls == 1);
    assert(nvUvmInterfaceGetChannelResourcePtes(
               (uvmGpuAddressSpaceHandle)0x1000, 0, 0, 0, NULL) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceGetChannelResourcePtes(
               NULL, 0, 0, 0, &invalid_info) == NV_ERR_INVALID_ARGUMENT);
    hybrid580_test_assert_locks_balanced();
}

static void hybrid580_test_page_directory_dma_and_provider_contracts(void)
{
    NvU64 dma_address = UINT64_MAX;

    hybrid580_test_reset();
    assert(nvUvmInterfaceSetPageDirectory(
               (uvmGpuAddressSpaceHandle)0x1000, 0x100000, 64, NV_TRUE,
               0x123, &dma_address) == NV_OK);
    assert(dma_address == 0xaabbccdd &&
           hybrid580_test_open.set_page_directory_calls == 1 &&
           hybrid580_test_legacy.set_page_directory_calls == 0);

    hybrid580_test_open.set_page_directory_status = TEST_PROVIDER_ERROR;
    hybrid580_test_open.dma_result = 0xdeadbeef;
    dma_address = UINT64_MAX;
    assert(nvUvmInterfaceSetPageDirectory(
               (uvmGpuAddressSpaceHandle)0x1000, 0x100000, 64, NV_TRUE,
               0x123, &dma_address) == TEST_PROVIDER_ERROR);
    assert(dma_address == 0 &&
           hybrid580_test_open.set_page_directory_calls == 2);

    dma_address = 0;
    assert(nvUvmInterfaceSetPageDirectory(
               (uvmGpuAddressSpaceHandle)0x2000, 0x200000, 128, NV_FALSE,
               0x456, &dma_address) == NV_OK);
    assert(dma_address == 0x11223344 &&
           hybrid580_test_legacy.set_page_directory_calls == 1);
    assert(nvUvmInterfaceUnsetPageDirectory(
               (uvmGpuAddressSpaceHandle)0x1000) == NV_OK);
    assert(nvUvmInterfaceUnsetPageDirectory(
               (uvmGpuAddressSpaceHandle)0x2000) == TEST_PROVIDER_ERROR);
    assert(hybrid580_test_open.unset_page_directory_calls == 1 &&
           hybrid580_test_open.last_unset_space == 0x1000 &&
           hybrid580_test_legacy.unset_page_directory_calls == 1 &&
           hybrid580_test_legacy.last_unset_space == 0x2000);

    dma_address = UINT64_MAX;
    assert(nvUvmInterfaceSetPageDirectory(
               (uvmGpuAddressSpaceHandle)0x9999, 0x100000, 64, NV_TRUE,
               0x123, &dma_address) == NV_ERR_INVALID_ARGUMENT);
    assert(dma_address == 0 &&
           nvUvmInterfaceUnsetPageDirectory(
               (uvmGpuAddressSpaceHandle)0x9999) == NV_ERR_INVALID_ARGUMENT &&
           hybrid580_test_quarantine_pins == 2 &&
           hybrid580_test_open.set_page_directory_calls == 2 &&
           hybrid580_test_legacy.set_page_directory_calls == 1 &&
           hybrid580_test_open.unset_page_directory_calls == 1 &&
           hybrid580_test_legacy.unset_page_directory_calls == 1);
    assert(nvUvmInterfaceSetPageDirectory(
               (uvmGpuAddressSpaceHandle)0x1000, 0x100000, 64, NV_TRUE,
               0x123, NULL) == NV_ERR_INVALID_ARGUMENT);
    assert(hybrid580_test_lock_calls == 7);
    hybrid580_test_assert_locks_balanced();
}

int main(void)
{
    hybrid580_test_provider_routing_copies_backend_payload();
    hybrid580_test_page_directory_dma_and_provider_contracts();
    puts("exact channel resource-PTE wrapper preserves provider and payload routing");
    return 0;
}
