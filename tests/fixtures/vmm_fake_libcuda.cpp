// SPDX-License-Identifier: MIT
// CPU-only fake CUDA driver for exercising the VMM probe control flow.
#include <cuda.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>

namespace {
struct FakeContext { int ordinal; };
struct FakeAllocation { std::vector<unsigned char> bytes; };
struct FakeModule {};

thread_local FakeContext *currentContext = nullptr;
std::map<CUmemGenericAllocationHandle, FakeAllocation *> allocations;
std::map<int, unsigned long long> accessByDevice;
CUmemGenericAllocationHandle nextAllocation = 1;
bool unmapFailed = false;

bool mode(const char *value) {
  const char *configured = std::getenv("FAKE_CUDA_MODE");
  return configured && std::strcmp(configured, value) == 0;
}

void *pointer(CUdeviceptr value) {
  return reinterpret_cast<void *>(static_cast<std::uintptr_t>(value));
}
}  // namespace

extern "C" {
CUresult CUDAAPI cuInit(unsigned int) { return CUDA_SUCCESS; }
CUresult CUDAAPI cuDriverGetVersion(int *version) {
  *version = 13010;
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuDeviceGetCount(int *count) {
  *count = 2;
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuDeviceGet(CUdevice *device, int ordinal) {
  if (ordinal < 0 || ordinal > 1) return CUDA_ERROR_INVALID_DEVICE;
  *device = ordinal;
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuDeviceGetName(char *name, int length, CUdevice device) {
  const char *value = device == 0 ? "NVIDIA Tesla V100" : "NVIDIA RTX 5080";
  if (device < 0 || device > 1 || length <= 0) return CUDA_ERROR_INVALID_VALUE;
  std::snprintf(name, static_cast<std::size_t>(length), "%s", value);
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuDeviceGetPCIBusId(char *pci, int length, CUdevice device) {
  if (device < 0 || device > 1 || length < 1) return CUDA_ERROR_INVALID_VALUE;
  std::snprintf(pci, static_cast<std::size_t>(length), "%s",
                device == 0 ? "0000:01:00.0" : "0000:02:00.0");
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuDeviceGetAttribute(int *value, CUdevice_attribute attribute,
                                      CUdevice device) {
  if (device < 0 || device > 1) return CUDA_ERROR_INVALID_DEVICE;
  switch (attribute) {
    case CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR:
      *value = device == 0 ? 7 : 12;
      break;
    case CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR:
      *value = 0;
      break;
    case CU_DEVICE_ATTRIBUTE_VIRTUAL_MEMORY_MANAGEMENT_SUPPORTED:
      *value = 1;
      break;
    default:
      *value = 0;
      break;
  }
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuDeviceCanAccessPeer(int *canAccess, CUdevice, CUdevice) {
  *canAccess = 0;
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuCtxCreate_v2(CUcontext *context, unsigned int, CUdevice device) {
  if (device < 0 || device > 1) return CUDA_ERROR_INVALID_DEVICE;
  *context = reinterpret_cast<CUcontext>(new FakeContext{device});
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuCtxDestroy_v2(CUcontext context) {
  auto *fake = reinterpret_cast<FakeContext *>(context);
  if (!fake) return CUDA_ERROR_INVALID_CONTEXT;
  if (currentContext == fake) currentContext = nullptr;
  delete fake;
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuCtxSetCurrent(CUcontext context) {
  currentContext = reinterpret_cast<FakeContext *>(context);
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuCtxSynchronize() { return CUDA_SUCCESS; }
CUresult CUDAAPI cuModuleLoad(CUmodule *module, const char *) {
  *module = reinterpret_cast<CUmodule>(new FakeModule{});
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuModuleUnload(CUmodule module) {
  delete reinterpret_cast<FakeModule *>(module);
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuModuleGetFunction(CUfunction *function, CUmodule, const char *) {
  *function = reinterpret_cast<CUfunction>(static_cast<std::uintptr_t>(1));
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemAlloc_v2(CUdeviceptr *devicePointer, size_t size) {
  void *value = std::malloc(size);
  if (!value) return CUDA_ERROR_OUT_OF_MEMORY;
  *devicePointer = reinterpret_cast<CUdeviceptr>(value);
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemFree_v2(CUdeviceptr devicePointer) {
  std::free(pointer(devicePointer));
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemcpyHtoD_v2(CUdeviceptr destination, const void *source, size_t size) {
  std::memcpy(pointer(destination), source, size);
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemcpyDtoH_v2(void *destination, CUdeviceptr source, size_t size) {
  std::memcpy(destination, pointer(source), size);
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuLaunchKernel(CUfunction, unsigned int, unsigned int, unsigned int,
                                unsigned int, unsigned int, unsigned int, unsigned int,
                                CUstream, void **parameters, void **) {
  if (mode("launch_fail")) return CUDA_ERROR_LAUNCH_FAILED;
  const auto source = *static_cast<CUdeviceptr *>(parameters[0]);
  const auto destination = *static_cast<CUdeviceptr *>(parameters[1]);
  const auto count = *static_cast<unsigned int *>(parameters[2]);
  std::memcpy(pointer(destination), pointer(source),
              static_cast<std::size_t>(count) * sizeof(std::uint32_t));
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemGetAllocationGranularity(size_t *granularity,
                                               const CUmemAllocationProp *,
                                               CUmemAllocationGranularity_flags) {
  *granularity = 65536;
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemCreate(CUmemGenericAllocationHandle *handle, size_t size,
                             const CUmemAllocationProp *, unsigned long long) {
  auto *allocation = new FakeAllocation{};
  allocation->bytes.resize(size);
  *handle = nextAllocation++;
  allocations[*handle] = allocation;
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemAddressReserve(CUdeviceptr *address, size_t size, size_t,
                                     CUdeviceptr, unsigned long long) {
  void *value = std::malloc(size);
  if (!value) return CUDA_ERROR_OUT_OF_MEMORY;
  *address = reinterpret_cast<CUdeviceptr>(value);
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemMap(CUdeviceptr address, size_t size, size_t,
                          CUmemGenericAllocationHandle handle, unsigned long long) {
  return allocations.count(handle) && allocations[handle]->bytes.size() >= size && address
             ? CUDA_SUCCESS : CUDA_ERROR_INVALID_VALUE;
}
CUresult CUDAAPI cuMemSetAccess(CUdeviceptr address, size_t,
                                const CUmemAccessDesc *descriptors, size_t count) {
  if (!address || !descriptors || count == 0) return CUDA_ERROR_INVALID_VALUE;
  accessByDevice.clear();
  for (size_t i = 0; i < count; ++i)
    accessByDevice[descriptors[i].location.id] = descriptors[i].flags;
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemGetAccess(unsigned long long *flags, const CUmemLocation *location,
                                CUdeviceptr address) {
  if (!address || !location) return CUDA_ERROR_INVALID_VALUE;
  auto found = accessByDevice.find(location->id);
  if (found == accessByDevice.end()) return CUDA_ERROR_INVALID_VALUE;
  *flags = found->second;
  if (mode("one_way") && currentContext && currentContext->ordinal == 0 && location->id == 1)
    *flags = CU_MEM_ACCESS_FLAGS_PROT_NONE;
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemUnmap(CUdeviceptr, size_t) {
  if (mode("unmap_fail")) {
    unmapFailed = true;
    return CUDA_ERROR_INVALID_VALUE;
  }
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemRelease(CUmemGenericAllocationHandle handle) {
  if (unmapFailed) return CUDA_ERROR_INVALID_VALUE;
  auto found = allocations.find(handle);
  if (found == allocations.end()) return CUDA_ERROR_INVALID_VALUE;
  delete found->second;
  allocations.erase(found);
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuMemAddressFree(CUdeviceptr address, size_t) {
  if (unmapFailed) return CUDA_ERROR_INVALID_VALUE;
  std::free(pointer(address));
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuGetErrorName(CUresult error, const char **name) {
  *name = error == CUDA_SUCCESS ? "CUDA_SUCCESS" : "CUDA_ERROR_FAKE";
  return CUDA_SUCCESS;
}
CUresult CUDAAPI cuGetErrorString(CUresult error, const char **description) {
  *description = error == CUDA_SUCCESS ? "success" : "fake CUDA API failure";
  return CUDA_SUCCESS;
}
}  // extern "C"
