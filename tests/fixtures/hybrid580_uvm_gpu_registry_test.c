/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../../src/hybrid580_uvm_gpu_registry.h"

int main(void)
{
    struct hybrid580_uvm_gpu_registry registry = {0};
    unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0};
    unsigned char other[HYBRID580_UVM_GPU_UUID_BYTES] = {0};
    enum hybrid580_uvm_provider provider = 0;
    uint32_t references = 0;
    uint32_t i;

    uuid[0] = 0x10;
    uuid[15] = 0xfe;
    assert(hybrid580_uvm_gpu_registry_record_success(
               &registry, uuid, HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(hybrid580_uvm_gpu_registry_lookup(
               &registry, uuid, &provider, &references) ==
           HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(provider == HYBRID580_UVM_PROVIDER_OPEN && references == 1);

    assert(hybrid580_uvm_gpu_registry_record_success(
               &registry, uuid, HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(hybrid580_uvm_gpu_registry_lookup(
               &registry, uuid, &provider, &references) ==
           HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(references == 2);
    assert(hybrid580_uvm_gpu_registry_record_success(
               &registry, uuid, HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_GPU_REGISTRY_PROVIDER_CONFLICT);

    assert(hybrid580_uvm_gpu_registry_release(
               &registry, uuid, &provider, &references) ==
           HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(provider == HYBRID580_UVM_PROVIDER_OPEN && references == 1);
    assert(hybrid580_uvm_gpu_registry_release(
               &registry, uuid, &provider, &references) ==
           HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(references == 0 && registry.count == 0);
    assert(hybrid580_uvm_gpu_registry_release(
               &registry, uuid, &provider, &references) ==
           HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND);

    for (i = 0; i < HYBRID580_UVM_GPU_REGISTRY_CAPACITY; ++i) {
        memset(other, 0, sizeof(other));
        other[0] = (unsigned char)(i >> 8);
        other[1] = (unsigned char)i;
        other[15] = (unsigned char)(i ^ 0xa5U);
        assert(hybrid580_uvm_gpu_registry_record_success(
                   &registry, other, (i & 1U) ? HYBRID580_UVM_PROVIDER_OPEN :
                                               HYBRID580_UVM_PROVIDER_LEGACY) ==
               HYBRID580_UVM_GPU_REGISTRY_OK);
    }
    memset(other, 0xff, sizeof(other));
    assert(hybrid580_uvm_gpu_registry_record_success(
               &registry, other, HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_GPU_REGISTRY_FULL);
    puts("UVM GPU UUID ownership/refcount/conflict/capacity scenarios passed");
    return 0;
}
