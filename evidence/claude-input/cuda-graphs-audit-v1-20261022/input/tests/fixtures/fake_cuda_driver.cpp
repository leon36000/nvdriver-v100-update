// SPDX-License-Identifier: MIT
// CPU-only CUDA Driver API double for probe control-flow tests. This does not
// implement CUDA, access a GPU, or validate any physical NVIDIA device.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

// Minimal public CUDA Driver API ABI declarations. Values/signatures mirror
// cuda.h; the fake deliberately links no CUDA library.
using CUresult = int;
using CUdevice = int;
using CUdeviceptr = unsigned long long;
struct CUctx_st;
struct CUmod_st;
struct CUfunc_st;
struct CUstream_st;
struct CUgraph_st;
struct CUgraphNode_st;
struct CUgraphExec_st;
using CUcontext = CUctx_st *;
using CUmodule = CUmod_st *;
using CUfunction = CUfunc_st *;
using CUstream = CUstream_st *;
using CUkernel = CUfunc_st *;
using CUgraph = CUgraph_st *;
using CUgraphNode = CUgraphNode_st *;
using CUgraphExec = CUgraphExec_st *;

struct CUDA_KERNEL_NODE_PARAMS {
  CUfunction func{};
  unsigned int gridDimX{};
  unsigned int gridDimY{};
  unsigned int gridDimZ{};
  unsigned int blockDimX{};
  unsigned int blockDimY{};
  unsigned int blockDimZ{};
  unsigned int sharedMemBytes{};
  void **kernelParams{};
  void **extra{};
  CUkernel kern{};
  CUcontext ctx{};
};

struct CUmemLocation {
  int type{};
  int id{};
};

constexpr CUresult CUDA_SUCCESS = 0;
constexpr CUresult CUDA_ERROR_INVALID_VALUE = 1;
constexpr CUresult CUDA_ERROR_INVALID_CONTEXT = 201;
constexpr CUresult CUDA_ERROR_UNKNOWN = 999;
constexpr CUdevice CU_DEVICE_CPU = -1;
#ifndef FAKE_CUDA_NO_PREFETCH_V2
constexpr int CU_MEM_LOCATION_TYPE_DEVICE = 1;
constexpr int CU_MEM_LOCATION_TYPE_HOST = 2;
#endif
constexpr int CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR = 75;
constexpr int CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR = 76;

struct CUctx_st {
  std::uint64_t id{};
  CUdevice device{};
  bool invalidated = false;
  std::string last_kernel;
  unsigned int last_add_count = 0;
};

struct CUmod_st {
  CUcontext owner{};
  std::vector<CUfunction> functions;
};

struct CUfunc_st {
  CUmodule module{};
  std::string name;
};

struct CUstream_st {
  std::uint64_t id{};
  CUcontext owner{};
};

struct CUgraph_st {
  CUcontext owner{};
  CUfunction function{};
  CUdeviceptr parameters[3]{};
  unsigned int count{};
  unsigned int gridX{};
  unsigned int blockX{};
  CUgraphNode node{};
};

struct CUgraphNode_st {
  CUgraph graph{};
};

struct CUgraphExec_st {
  CUgraph graph{};
};

namespace {

struct DeviceAllocation {
  void *address{};
  std::size_t bytes{};
  CUcontext owner{};
  bool managed{};
};

std::unordered_map<CUcontext, bool> contexts;
std::vector<CUcontext> created_contexts;
std::unordered_map<CUmodule, bool> modules;
std::unordered_map<CUdeviceptr, DeviceAllocation> device_allocations;
std::unordered_map<void *, std::size_t> host_allocations;
std::unordered_map<CUstream, bool> streams;
std::unordered_map<CUgraph, bool> graphs;
std::unordered_map<CUgraphExec, bool> graph_execs;
std::unordered_map<CUfunction, bool> functions;
thread_local CUcontext current_context = nullptr;
std::uint64_t next_context_id = 1;
std::uint64_t next_stream_id = 1;
bool memfree_failure_injected = false;
bool context_destroy_failure_injected = false;
bool managed_prefetch_failure_injected = false;
#ifndef FAKE_CUDA_NO_GRAPHS
bool graph_launch_failure_injected = false;
bool graph_launch_corruption_injected = false;
#endif

const char *tracePath() {
  const char *path = std::getenv("FAKE_CUDA_TRACE_PATH");
  return path && *path ? path : nullptr;
}

void trace(const std::string &line, bool truncate = false) {
  const char *path = tracePath();
  if (!path) return;
  std::ofstream output(path, truncate ? std::ios::trunc : std::ios::app);
  if (output) output << line << '\n';
}

bool enabled(const char *name) {
  const char *value = std::getenv(name);
  return value && *value && std::strcmp(value, "0") != 0;
}

bool syncFailureRequested(unsigned int count) {
  const char *value = std::getenv("FAKE_CUDA_FAIL_SYNC_SIZE");
  if (!value || !*value) return false;
  char *end = nullptr;
  const unsigned long requested = std::strtoul(value, &end, 10);
  return end != value && *end == '\0' && requested == count;
}

bool validContext(CUcontext context) {
  const auto found = contexts.find(context);
  return context && found != contexts.end() && !context->invalidated;
}

bool validCurrentContext() {
  return validContext(current_context);
}

const char *errorName(CUresult result) {
  switch (result) {
    case CUDA_SUCCESS: return "CUDA_SUCCESS";
    case CUDA_ERROR_INVALID_VALUE: return "CUDA_ERROR_INVALID_VALUE";
    case CUDA_ERROR_INVALID_CONTEXT: return "CUDA_ERROR_INVALID_CONTEXT";
    default: return "CUDA_ERROR_UNKNOWN";
  }
}

const char *errorDescription(CUresult result) {
  switch (result) {
    case CUDA_SUCCESS: return "no error";
    case CUDA_ERROR_INVALID_VALUE: return "invalid value in fake CPU driver";
    case CUDA_ERROR_INVALID_CONTEXT: return "context is invalid or not current in fake CPU driver";
    default: return "injected or unsupported fake CPU driver error";
  }
}

CUresult findAllocation(CUdeviceptr address, std::size_t bytes,
                        DeviceAllocation **allocation, std::size_t *offset) {
  for (auto &entry : device_allocations) {
    const CUdeviceptr base = entry.first;
    const DeviceAllocation &candidate = entry.second;
    if (address < base) continue;
    const CUdeviceptr difference = address - base;
    if (difference > candidate.bytes || bytes > candidate.bytes - difference) continue;
    if (candidate.owner != current_context || !validCurrentContext())
      return CUDA_ERROR_INVALID_CONTEXT;
    *allocation = &entry.second;
    *offset = static_cast<std::size_t>(difference);
    return CUDA_SUCCESS;
  }
  return CUDA_ERROR_INVALID_VALUE;
}

void resourceSnapshot() {
  char line[256];
  std::snprintf(line, sizeof(line),
                "resource_snapshot contexts=%zu modules=%zu functions=%zu "
                "device_allocations=%zu host_allocations=%zu streams=%zu "
                "graphs=%zu graph_execs=%zu",
                contexts.size(), modules.size(), functions.size(),
                device_allocations.size(), host_allocations.size(), streams.size(),
                graphs.size(), graph_execs.size());
  trace(line);
}

}  // namespace

extern "C" {

CUresult cuInit(unsigned int flags) {
  (void)flags;
  trace("fake_cpu_driver_initialized", true);
  trace(std::getenv("FAKE_CUDA_ONLY_SM120") ? "device_inventory count=1 sm=120" :
                                          "device_inventory count=2 sm=70,120");
  return CUDA_SUCCESS;
}

CUresult cuDriverGetVersion(int *version) {
  if (!version) return CUDA_ERROR_INVALID_VALUE;
  *version = 13010;
  return CUDA_SUCCESS;
}

CUresult cuDeviceGetCount(int *count) {
  if (!count) return CUDA_ERROR_INVALID_VALUE;
  *count = std::getenv("FAKE_CUDA_ONLY_SM120") ? 1 : 2;
  return CUDA_SUCCESS;
}

CUresult cuDeviceGet(CUdevice *device, int ordinal) {
  const bool onlyBlackwell = std::getenv("FAKE_CUDA_ONLY_SM120") != nullptr;
  if (!device || ordinal < 0 || ordinal >= (onlyBlackwell ? 1 : 2)) return CUDA_ERROR_INVALID_VALUE;
  *device = onlyBlackwell ? 1 : ordinal;
  return CUDA_SUCCESS;
}

CUresult cuDeviceGetName(char *name, int length, CUdevice device) {
  if (!name || length <= 0 || device < 0 || device >= 2)
    return CUDA_ERROR_INVALID_VALUE;
  const char *value = device == 0
      ? "FAKE CPU Volta-shaped device (SM70; not a GPU)"
      : "FAKE CPU Blackwell-shaped device (SM120; not a GPU)";
  std::snprintf(name, static_cast<std::size_t>(length), "%s", value);
  return CUDA_SUCCESS;
}

CUresult cuDeviceGetPCIBusId(char *pci, int length, CUdevice device) {
  if (!pci || length <= 0 || device < 0 || device >= 2)
    return CUDA_ERROR_INVALID_VALUE;
  std::snprintf(pci, static_cast<std::size_t>(length),
                device == 0 ? "0000:01:00.0" : "0000:02:00.0");
  return CUDA_SUCCESS;
}

CUresult cuDeviceGetAttribute(int *value, int attribute, CUdevice device) {
  if (!value || device < 0 || device >= 2) return CUDA_ERROR_INVALID_VALUE;
  if (attribute == CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR)
    *value = device == 0 ? 7 : 12;
  else if (attribute == CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR)
    *value = 0;
  else
    return CUDA_ERROR_INVALID_VALUE;
  return CUDA_SUCCESS;
}

CUresult cuCtxCreate_v2(CUcontext *context, unsigned int flags, CUdevice device) {
  (void)flags;
  if (!context || device < 0 || device >= 2) return CUDA_ERROR_INVALID_VALUE;
  auto *created = new CUctx_st;
  created->id = next_context_id++;
  created->device = device;
  contexts.emplace(created, true);
  created_contexts.push_back(created);
  current_context = created;
  *context = created;
  char line[192];
  std::snprintf(line, sizeof(line),
                "ctx_create id=%llu ordinal=%d live_contexts=%zu",
                static_cast<unsigned long long>(created->id), device, contexts.size());
  trace(line);

  if (enabled("FAKE_CUDA_INVALIDATE_FIRST_ON_SECOND_CONTEXT") &&
      created_contexts.size() == 2) {
    CUcontext first = created_contexts.front();
    first->invalidated = true;
    std::snprintf(line, sizeof(line),
                  "ctx_invalidate first=id:%llu on_second_create=1",
                  static_cast<unsigned long long>(first->id));
    trace(line);
  }
  return CUDA_SUCCESS;
}

CUresult cuCtxDestroy_v2(CUcontext context) {
  if (!contexts.count(context)) return CUDA_ERROR_INVALID_CONTEXT;
  if (enabled("FAKE_CUDA_FAIL_CTXDESTROY_ONCE") &&
      !context_destroy_failure_injected) {
    context_destroy_failure_injected = true;
    trace("ctx_destroy_injected_error");
    return CUDA_ERROR_UNKNOWN;
  }
  const std::uint64_t id = context->id;
  const int ordinal = context->device;
  if (current_context == context) current_context = nullptr;
  contexts.erase(context);
  delete context;
  char line[160];
  std::snprintf(line, sizeof(line), "ctx_destroy id=%llu ordinal=%d live_contexts=%zu",
                static_cast<unsigned long long>(id), ordinal, contexts.size());
  trace(line);
  resourceSnapshot();
  return CUDA_SUCCESS;
}

CUresult cuCtxSetCurrent(CUcontext context) {
  if (context && !validContext(context)) {
    trace("ctx_set_current_invalid");
    return CUDA_ERROR_INVALID_CONTEXT;
  }
  current_context = context;
  trace(context ? "ctx_set_current_valid" : "ctx_set_current_null");
  return CUDA_SUCCESS;
}

CUresult cuCtxGetDevice(CUdevice *device) {
  if (!device) return CUDA_ERROR_INVALID_VALUE;
  if (!validCurrentContext()) return CUDA_ERROR_INVALID_CONTEXT;
  *device = current_context->device;
  char line[128];
  std::snprintf(line, sizeof(line), "ctx_get_device id=%llu ordinal=%d",
                static_cast<unsigned long long>(current_context->id), *device);
  trace(line);
  return CUDA_SUCCESS;
}

CUresult cuCtxSynchronize() {
  if (!validCurrentContext()) return CUDA_ERROR_INVALID_CONTEXT;
  if (current_context->last_kernel == "hybrid_add" &&
      syncFailureRequested(current_context->last_add_count)) {
    trace("ctx_synchronize_injected_error size=31");
    return CUDA_ERROR_UNKNOWN;
  }
  trace("ctx_synchronize");
  return CUDA_SUCCESS;
}

CUresult cuModuleLoad(CUmodule *module, const char *path) {
  if (!module || !path) return CUDA_ERROR_INVALID_VALUE;
  if (!validCurrentContext()) return CUDA_ERROR_INVALID_CONTEXT;
  auto *created = new CUmod_st;
  created->owner = current_context;
  modules.emplace(created, true);
  *module = created;
  trace("module_load");
  return CUDA_SUCCESS;
}

CUresult cuModuleUnload(CUmodule module) {
  if (!modules.count(module)) return CUDA_ERROR_INVALID_VALUE;
  for (CUfunction function : module->functions) {
    functions.erase(function);
    delete function;
  }
  modules.erase(module);
  delete module;
  trace("module_unload");
  return CUDA_SUCCESS;
}

CUresult cuModuleGetFunction(CUfunction *function, CUmodule module,
                             const char *name) {
  if (!function || !module || !name || !modules.count(module))
    return CUDA_ERROR_INVALID_VALUE;
  if (!validCurrentContext() || module->owner != current_context)
    return CUDA_ERROR_INVALID_CONTEXT;
  auto *created = new CUfunc_st;
  created->module = module;
  created->name = name;
  functions.emplace(created, true);
  module->functions.push_back(created);
  *function = created;
  return CUDA_SUCCESS;
}

CUresult cuMemAlloc_v2(CUdeviceptr *pointer, std::size_t bytes) {
  if (!pointer || bytes == 0) return CUDA_ERROR_INVALID_VALUE;
  if (!validCurrentContext()) return CUDA_ERROR_INVALID_CONTEXT;
  void *memory = std::malloc(bytes);
  if (!memory) return CUDA_ERROR_UNKNOWN;
  const auto address = static_cast<CUdeviceptr>(reinterpret_cast<std::uintptr_t>(memory));
  device_allocations.emplace(address, DeviceAllocation{memory, bytes, current_context, false});
  *pointer = address;
  trace("device_alloc");
  return CUDA_SUCCESS;
}

CUresult cuMemAllocManaged(CUdeviceptr *pointer, std::size_t bytes,
                           unsigned int flags) {
  if (!pointer || bytes == 0 || flags != 1) return CUDA_ERROR_INVALID_VALUE;
  if (!validCurrentContext()) return CUDA_ERROR_INVALID_CONTEXT;
  if (enabled("FAKE_CUDA_MANAGED_MEMORY_UNSUPPORTED")) return CUDA_ERROR_UNKNOWN;
  void *memory = std::malloc(bytes);
  if (!memory) return CUDA_ERROR_UNKNOWN;
  const auto address = static_cast<CUdeviceptr>(reinterpret_cast<std::uintptr_t>(memory));
  device_allocations.emplace(address, DeviceAllocation{memory, bytes, current_context, true});
  *pointer = address;
  trace("managed_alloc flags=1");
  return CUDA_SUCCESS;
}

CUresult cuMemPrefetchAsync(CUdeviceptr pointer, std::size_t bytes,
                            CUdevice destination, CUstream stream) {
  const auto found = device_allocations.find(pointer);
  if (found == device_allocations.end() || !found->second.managed ||
      bytes == 0 || bytes > found->second.bytes)
    return CUDA_ERROR_INVALID_VALUE;
  if (!validCurrentContext() || found->second.owner != current_context)
    return CUDA_ERROR_INVALID_CONTEXT;
  if (destination != CU_DEVICE_CPU && destination != current_context->device)
    return CUDA_ERROR_INVALID_VALUE;
  if (stream && (!streams.count(stream) || stream->owner != current_context))
    return CUDA_ERROR_INVALID_CONTEXT;
  if (enabled("FAKE_CUDA_MANAGED_PREFETCH_FAIL_ONCE") && !managed_prefetch_failure_injected) {
    managed_prefetch_failure_injected = true;
    trace("managed_prefetch_injected_error");
    return CUDA_ERROR_UNKNOWN;
  }
  trace("managed_prefetch destination=" + std::to_string(destination) +
        " bytes=" + std::to_string(bytes) +
        " stream=" + (stream ? "nondefault" : "default"));
  return CUDA_SUCCESS;
}

#ifndef FAKE_CUDA_NO_PREFETCH_V2
CUresult cuMemPrefetchAsync_v2(CUdeviceptr pointer, std::size_t bytes,
                               CUmemLocation location, unsigned int flags,
                               CUstream stream) {
  if (flags != 0) return CUDA_ERROR_INVALID_VALUE;
  if (location.type == CU_MEM_LOCATION_TYPE_HOST)
    return cuMemPrefetchAsync(pointer, bytes, CU_DEVICE_CPU, stream);
  if (location.type == CU_MEM_LOCATION_TYPE_DEVICE)
    return cuMemPrefetchAsync(pointer, bytes, location.id, stream);
  return CUDA_ERROR_INVALID_VALUE;
}
#endif

CUresult cuMemFree_v2(CUdeviceptr pointer) {
  const auto found = device_allocations.find(pointer);
  if (found == device_allocations.end()) return CUDA_ERROR_INVALID_VALUE;
  if (found->second.owner != current_context || !validCurrentContext())
    return CUDA_ERROR_INVALID_CONTEXT;
  if (enabled("FAKE_CUDA_FAIL_MEMFREE_ONCE") && !memfree_failure_injected) {
    memfree_failure_injected = true;
    trace("device_free_injected_error");
    return CUDA_ERROR_UNKNOWN;
  }
  const bool managed = found->second.managed;
  std::free(found->second.address);
  device_allocations.erase(found);
  trace(managed ? "managed_free" : "device_free");
  return CUDA_SUCCESS;
}

CUresult cuMemHostAlloc(void **pointer, std::size_t bytes, unsigned int flags) {
  (void)flags;
  if (!pointer || bytes == 0) return CUDA_ERROR_INVALID_VALUE;
  if (!validCurrentContext()) return CUDA_ERROR_INVALID_CONTEXT;
  void *memory = std::malloc(bytes);
  if (!memory) return CUDA_ERROR_UNKNOWN;
  host_allocations.emplace(memory, bytes);
  *pointer = memory;
  trace("host_alloc");
  return CUDA_SUCCESS;
}

CUresult cuMemFreeHost(void *pointer) {
  const auto found = host_allocations.find(pointer);
  if (found == host_allocations.end()) return CUDA_ERROR_INVALID_VALUE;
  std::free(pointer);
  host_allocations.erase(found);
  trace("host_free");
  return CUDA_SUCCESS;
}

CUresult cuMemcpyHtoD_v2(CUdeviceptr destination, const void *source,
                         std::size_t bytes) {
  if ((!source && bytes) || !validCurrentContext())
    return !source && bytes ? CUDA_ERROR_INVALID_VALUE : CUDA_ERROR_INVALID_CONTEXT;
  DeviceAllocation *allocation = nullptr;
  std::size_t offset = 0;
  const CUresult status = findAllocation(destination, bytes, &allocation, &offset);
  if (status != CUDA_SUCCESS) return status;
  std::memcpy(static_cast<char *>(allocation->address) + offset, source, bytes);
  trace("copy_htod");
  return CUDA_SUCCESS;
}

CUresult cuMemcpyDtoH_v2(void *destination, CUdeviceptr source,
                         std::size_t bytes) {
  if ((!destination && bytes) || !validCurrentContext())
    return !destination && bytes ? CUDA_ERROR_INVALID_VALUE : CUDA_ERROR_INVALID_CONTEXT;
  DeviceAllocation *allocation = nullptr;
  std::size_t offset = 0;
  const CUresult status = findAllocation(source, bytes, &allocation, &offset);
  if (status != CUDA_SUCCESS) return status;
  std::memcpy(destination, static_cast<char *>(allocation->address) + offset, bytes);
  trace("copy_dtoh");
  return CUDA_SUCCESS;
}

CUresult cuMemcpyHtoDAsync_v2(CUdeviceptr destination, const void *source,
                              std::size_t bytes, CUstream stream) {
  if (stream && !streams.count(stream)) return CUDA_ERROR_INVALID_VALUE;
  return cuMemcpyHtoD_v2(destination, source, bytes);
}

CUresult cuMemcpyDtoHAsync_v2(void *destination, CUdeviceptr source,
                              std::size_t bytes, CUstream stream) {
  if (stream && !streams.count(stream)) return CUDA_ERROR_INVALID_VALUE;
  return cuMemcpyDtoH_v2(destination, source, bytes);
}

CUresult cuStreamCreate(CUstream *stream, unsigned int flags) {
  (void)flags;
  if (!stream || !validCurrentContext()) return CUDA_ERROR_INVALID_CONTEXT;
  auto *created = new CUstream_st;
  created->id = next_stream_id++;
  created->owner = current_context;
  streams.emplace(created, true);
  *stream = created;
  trace("stream_create");
  return CUDA_SUCCESS;
}

CUresult cuStreamDestroy_v2(CUstream stream) {
  if (!streams.count(stream)) return CUDA_ERROR_INVALID_VALUE;
  streams.erase(stream);
  delete stream;
  trace("stream_destroy");
  return CUDA_SUCCESS;
}

CUresult cuStreamSynchronize(CUstream stream) {
  if (!streams.count(stream) || !validCurrentContext())
    return CUDA_ERROR_INVALID_CONTEXT;
  trace("stream_synchronize");
  return CUDA_SUCCESS;
}

CUresult cuLaunchKernel(CUfunction function,
                        unsigned int grid_x, unsigned int grid_y,
                        unsigned int grid_z, unsigned int block_x,
                        unsigned int block_y, unsigned int block_z,
                        unsigned int shared_bytes, CUstream stream,
                        void **kernel_parameters, void **extra) {
  (void)grid_y;
  (void)grid_z;
  (void)block_y;
  (void)block_z;
  (void)shared_bytes;
  (void)extra;
  if (!function || !functions.count(function) || !kernel_parameters ||
      (stream && !streams.count(stream)))
    return CUDA_ERROR_INVALID_VALUE;
  if (!validCurrentContext() || function->module->owner != current_context)
    return CUDA_ERROR_INVALID_CONTEXT;

  CUresult status = CUDA_SUCCESS;
  if (function->name == "hybrid_arch") {
    const CUdeviceptr output = *static_cast<CUdeviceptr *>(kernel_parameters[0]);
    DeviceAllocation *allocation = nullptr;
    std::size_t offset = 0;
    status = findAllocation(output, sizeof(int), &allocation, &offset);
    if (status == CUDA_SUCCESS) {
      const int major = current_context->device == 0 ? 7 : 12;
      const int architecture = major * 100;
      std::memcpy(static_cast<char *>(allocation->address) + offset,
                  &architecture, sizeof(architecture));
      current_context->last_kernel = "hybrid_arch";
      current_context->last_add_count = 0;
    }
  } else if (function->name == "hybrid_add") {
    const CUdeviceptr a_address = *static_cast<CUdeviceptr *>(kernel_parameters[0]);
    const CUdeviceptr b_address = *static_cast<CUdeviceptr *>(kernel_parameters[1]);
    const CUdeviceptr output_address = *static_cast<CUdeviceptr *>(kernel_parameters[2]);
    const unsigned int count = *static_cast<unsigned int *>(kernel_parameters[3]);
    DeviceAllocation *a = nullptr;
    DeviceAllocation *b = nullptr;
    DeviceAllocation *output = nullptr;
    std::size_t a_offset = 0;
    std::size_t b_offset = 0;
    std::size_t output_offset = 0;
    const std::size_t bytes = static_cast<std::size_t>(count) * sizeof(int);
    status = findAllocation(a_address, bytes, &a, &a_offset);
    if (status == CUDA_SUCCESS)
      status = findAllocation(b_address, bytes, &b, &b_offset);
    if (status == CUDA_SUCCESS)
      status = findAllocation(output_address, bytes, &output, &output_offset);
    if (status == CUDA_SUCCESS) {
      const auto *a_values = reinterpret_cast<const int *>(
          static_cast<const char *>(a->address) + a_offset);
      const auto *b_values = reinterpret_cast<const int *>(
          static_cast<const char *>(b->address) + b_offset);
      auto *out_values = reinterpret_cast<int *>(
          static_cast<char *>(output->address) + output_offset);
      const std::uint64_t launched_threads =
          static_cast<std::uint64_t>(grid_x) * block_x;
      for (unsigned int i = 0; i < count && i < launched_threads; ++i)
        out_values[i] = a_values[i] + b_values[i];
      current_context->last_kernel = "hybrid_add";
      current_context->last_add_count = count;
    }
  } else {
    status = CUDA_ERROR_INVALID_VALUE;
  }

  char line[192];
  std::snprintf(line, sizeof(line),
                "launch kind=%s ordinal=%d count=%u live_contexts=%zu",
                function->name.c_str() == std::string("hybrid_arch") ? "arch" : "add",
                current_context->device, current_context->last_add_count,
                contexts.size());
  trace(line);
  return status;
}

#ifndef FAKE_CUDA_NO_GRAPHS
CUresult cuGraphCreate(CUgraph *graph, unsigned int flags) {
  (void)flags;
  if (!graph || !validCurrentContext()) return CUDA_ERROR_INVALID_CONTEXT;
  auto *created = new CUgraph_st;
  created->owner = current_context;
  graphs.emplace(created, true);
  *graph = created;
  char line[128];
  std::snprintf(line, sizeof(line), "graph_create ordinal=%d live_graphs=%zu",
                current_context->device, graphs.size());
  trace(line);
  return CUDA_SUCCESS;
}

CUresult cuGraphAddKernelNode_v2(CUgraphNode *node, CUgraph graph,
                                 const CUgraphNode *dependencies,
                                 std::size_t dependency_count,
                                 const CUDA_KERNEL_NODE_PARAMS *parameters) {
  (void)dependencies;
  if (!node || !graph || !graphs.count(graph) || !parameters ||
      dependency_count != 0 || !parameters->func ||
      parameters->func->name != "hybrid_add" || !parameters->kernelParams ||
      !validCurrentContext() || graph->owner != current_context)
    return CUDA_ERROR_INVALID_VALUE;
  auto *created = new CUgraphNode_st;
  created->graph = graph;
  graph->node = created;
  graph->function = parameters->func;
  graph->parameters[0] = *static_cast<CUdeviceptr *>(parameters->kernelParams[0]);
  graph->parameters[1] = *static_cast<CUdeviceptr *>(parameters->kernelParams[1]);
  graph->parameters[2] = *static_cast<CUdeviceptr *>(parameters->kernelParams[2]);
  graph->count = *static_cast<unsigned int *>(parameters->kernelParams[3]);
  graph->gridX = parameters->gridDimX;
  graph->blockX = parameters->blockDimX;
  *node = created;
  char line[128];
  std::snprintf(line, sizeof(line), "graph_add_kernel_node ordinal=%d count=%u",
                current_context->device, graph->count);
  trace(line);
  return CUDA_SUCCESS;
}

CUresult cuGraphInstantiateWithFlags(CUgraphExec *executable, CUgraph graph,
                                     unsigned long long flags) {
  if (!executable || !graph || !graphs.count(graph) || !graph->node || flags != 0 ||
      !validCurrentContext() || graph->owner != current_context)
    return CUDA_ERROR_INVALID_VALUE;
  auto *created = new CUgraphExec_st;
  created->graph = graph;
  graph_execs.emplace(created, true);
  *executable = created;
  char line[128];
  std::snprintf(line, sizeof(line), "graph_instantiate ordinal=%d live_graph_execs=%zu",
                current_context->device, graph_execs.size());
  trace(line);
  return CUDA_SUCCESS;
}

CUresult cuGraphLaunch(CUgraphExec executable, CUstream stream) {
  if (!executable || !graph_execs.count(executable) || !stream ||
      !streams.count(stream) || !validCurrentContext() ||
      executable->graph->owner != current_context || stream->owner != current_context)
    return CUDA_ERROR_INVALID_CONTEXT;
  if (enabled("FAKE_CUDA_GRAPH_LAUNCH_FAIL_ONCE") && !graph_launch_failure_injected) {
    graph_launch_failure_injected = true;
    trace("graph_launch_injected_error");
    return CUDA_ERROR_UNKNOWN;
  }
  CUgraph graph = executable->graph;
  CUdeviceptr a = graph->parameters[0];
  CUdeviceptr b = graph->parameters[1];
  CUdeviceptr output = graph->parameters[2];
  unsigned int count = graph->count;
  void *parameters[] = {&a, &b, &output, &count};
  const CUresult status = cuLaunchKernel(graph->function,
      graph->gridX, 1, 1, graph->blockX, 1, 1, 0, stream, parameters, nullptr);
  if (status == CUDA_SUCCESS &&
      enabled("FAKE_CUDA_GRAPH_CORRUPT_FIRST_ONCE") &&
      !graph_launch_corruption_injected) {
    graph_launch_corruption_injected = true;
    auto *output_values = reinterpret_cast<int *>(output);
    output_values[0] ^= 1;
    trace("graph_launch_injected_numeric_corruption");
  }
  char line[128];
  std::snprintf(line, sizeof(line), "graph_launch ordinal=%d count=%u",
                current_context->device, graph->count);
  trace(line);
  return status;
}

#ifndef FAKE_CUDA_NO_GRAPH_EXEC_DESTROY
CUresult cuGraphExecDestroy(CUgraphExec executable) {
  if (!executable || !graph_execs.count(executable)) return CUDA_ERROR_INVALID_VALUE;
  graph_execs.erase(executable);
  delete executable;
  char line[128];
  std::snprintf(line, sizeof(line), "graph_exec_destroy live_graph_execs=%zu",
                graph_execs.size());
  trace(line);
  return CUDA_SUCCESS;
}
#endif

CUresult cuGraphDestroy(CUgraph graph) {
  if (!graph || !graphs.count(graph)) return CUDA_ERROR_INVALID_VALUE;
  if (graph->node) delete graph->node;
  graphs.erase(graph);
  delete graph;
  char line[128];
  std::snprintf(line, sizeof(line), "graph_destroy live_graphs=%zu", graphs.size());
  trace(line);
  return CUDA_SUCCESS;
}
#endif

CUresult cuGetErrorName(CUresult error, const char **name) {
  if (!name) return CUDA_ERROR_INVALID_VALUE;
  *name = errorName(error);
  return CUDA_SUCCESS;
}

CUresult cuGetErrorString(CUresult error, const char **description) {
  if (!description) return CUDA_ERROR_INVALID_VALUE;
  *description = errorDescription(error);
  return CUDA_SUCCESS;
}

}  // extern "C"
