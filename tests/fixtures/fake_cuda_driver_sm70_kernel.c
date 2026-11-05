/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int cuInit(unsigned int flags) { (void)flags; return 0; }
int cuDriverGetVersion(int *version) { *version = 13000; return 0; }
int cuDeviceGetCount(int *count) { *count = 1; return 0; }
int cuDeviceGet(int *device, int ordinal) { *device = ordinal; return 0; }
int cuDeviceGetName(char *name, int length, int device) {
    (void)device; snprintf(name, (size_t)length, "Tesla V100-SXM2-16GB"); return 0;
}
int cuDeviceGetPCIBusId(char *pci, int length, int device) {
    (void)device; snprintf(pci, (size_t)length, "0000:00:05.0"); return 0;
}
int cuDeviceComputeCapability(int *major, int *minor, int device) {
    (void)device; *major = 7; *minor = 0; return 0;
}
int cuGetErrorName(int code, const char **name) {
    (void)code; *name = "CUDA_ERROR_FAKE"; return 0;
}
int cuGetErrorString(int code, const char **description) {
    (void)code; *description = "synthetic CUDA test failure"; return 0;
}
int cuCtxCreate_v2(void **context, unsigned int flags, int device) {
    (void)flags; (void)device; *context = (void *)(uintptr_t)1; return 0;
}
int cuCtxSetCurrent(void *context) { return context ? 0 : 1; }
int cuCtxGetDevice(int *device) { *device = 0; return 0; }
int cuCtxSynchronize(void) { return 0; }
int cuCtxDestroy_v2(void *context) { return context ? 0 : 1; }
int cuModuleLoadData(void **module, const void *image) {
    if (!image) return 1;
    *module = (void *)(uintptr_t)2; return 0;
}
int cuModuleGetFunction(void **function, void *module, const char *name) {
    if (!module || strcmp(name, "hybrid_arch") != 0) return 1;
    *function = (void *)(uintptr_t)3; return 0;
}
int cuModuleUnload(void *module) { return module ? 0 : 1; }
int cuMemAlloc_v2(uint64_t *pointer, size_t bytes) {
    void *memory = calloc(1, bytes);
    if (!memory) return 1;
    *pointer = (uint64_t)(uintptr_t)memory; return 0;
}
int cuMemFree_v2(uint64_t pointer) { free((void *)(uintptr_t)pointer); return 0; }
int cuLaunchKernel(void *function, unsigned int gx, unsigned int gy, unsigned int gz,
                   unsigned int bx, unsigned int by, unsigned int bz,
                   unsigned int shared, void *stream, void **parameters, void **extra) {
    (void)gx; (void)gy; (void)gz; (void)bx; (void)by; (void)bz;
    (void)shared; (void)stream; (void)extra;
    if (getenv("FAKE_CUDA_FAIL_KERNEL")) return 123;
    if (!function || !parameters || !parameters[0]) return 1;
    uint64_t pointer = *(uint64_t *)parameters[0];
    *(int *)(uintptr_t)pointer = 700; return 0;
}
int cuMemcpyDtoH_v2(void *destination, uint64_t source, size_t bytes) {
    memcpy(destination, (void *)(uintptr_t)source, bytes); return 0;
}
