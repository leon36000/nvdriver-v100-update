/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../src/hybrid580_uvm_gpu_registry.h"

static int check(int condition, const char *message)
{
    if (condition)
        return 0;
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

int main(void)
{
    struct hybrid580_uvm_gpu_registry registry = {0};
    const unsigned char volta[HYBRID580_UVM_GPU_UUID_BYTES] = {1};
    const unsigned char blackwell[HYBRID580_UVM_GPU_UUID_BYTES] = {2};
    const unsigned char another_volta[HYBRID580_UVM_GPU_UUID_BYTES] = {3};
    const unsigned char missing[HYBRID580_UVM_GPU_UUID_BYTES] = {4};
    int same = 9;
    int failures = 0;

    failures += check(hybrid580_uvm_gpu_registry_record_success(
                          &registry, volta, HYBRID580_UVM_PROVIDER_LEGACY) ==
                          HYBRID580_UVM_GPU_REGISTRY_OK,
                      "register Volta provider");
    failures += check(hybrid580_uvm_gpu_registry_record_success(
                          &registry, blackwell, HYBRID580_UVM_PROVIDER_OPEN) ==
                          HYBRID580_UVM_GPU_REGISTRY_OK,
                      "register Blackwell provider");
    failures += check(hybrid580_uvm_gpu_registry_record_success(
                          &registry, another_volta, HYBRID580_UVM_PROVIDER_LEGACY) ==
                          HYBRID580_UVM_GPU_REGISTRY_OK,
                      "register second GPU on Volta provider");

    failures += check(hybrid580_uvm_gpu_registry_same_provider(
                          &registry, volta, another_volta, &same) ==
                          HYBRID580_UVM_GPU_REGISTRY_OK && same == 1,
                      "same-provider query recognizes two Volta GPUs");
    same = 9;
    failures += check(hybrid580_uvm_gpu_registry_same_provider(
                          &registry, volta, blackwell, &same) ==
                          HYBRID580_UVM_GPU_REGISTRY_OK && same == 0,
                      "cross-provider query reports incompatibility");
    same = 9;
    failures += check(hybrid580_uvm_gpu_registry_same_provider(
                          &registry, volta, missing, &same) ==
                          HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND && same == 0,
                      "unknown GPU fails closed and clears result");
    failures += check(hybrid580_uvm_gpu_registry_same_provider(
                          &registry, volta, blackwell, NULL) ==
                          HYBRID580_UVM_GPU_REGISTRY_INVALID,
                      "null result is rejected");

    if (failures != 0)
        return 1;
    puts("hybrid580 UVM GPU provider comparison passed");
    return 0;
}
