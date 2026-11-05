// SPDX-License-Identifier: MIT
// CPU-only CUDA Driver API double for probe control-flow tests. This does not
// implement CUDA, access a GPU, or validate any physical NVIDIA device.

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <set>
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
struct CUevent_st;
struct CUgraph_st;
struct CUgraphNode_st;
struct CUgraphExec_st;
using CUcontext = CUctx_st *;
using CUmodule = CUmod_st *;
using CUfunction = CUfunc_st *;
using CUstream = CUstream_st *;
using CUevent = CUevent_st *;
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
constexpr int CU_MEM_LOCATION_TYPE_DEVICE = 1;
#ifndef FAKE_CUDA_NO_PREFETCH_V2
constexpr int CU_MEM_LOCATION_TYPE_HOST = 2;
#endif
constexpr int CU_MEM_ADVISE_SET_ACCESSED_BY = 5;
constexpr int CU_MEM_ADVISE_UNSET_ACCESSED_BY = 6;
constexpr int CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR = 75;
constexpr int CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR = 76;
constexpr int CU_DEVICE_ATTRIBUTE_CONCURRENT_MANAGED_ACCESS = 89;
constexpr int CU_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS = 88;
constexpr int CU_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS_USES_HOST_PAGE_TABLES = 100;
constexpr int CU_DEVICE_ATTRIBUTE_UNIFIED_ADDRESSING = 41;

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

struct CUevent_st {
  CUcontext owner{};
  double timestampMicroseconds{};
  bool recorded = false;
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
std::set<std::pair<CUcontext, CUcontext>> peer_accesses;
std::vector<CUcontext> created_contexts;
std::unordered_map<CUmodule, bool> modules;
std::unordered_map<CUdeviceptr, DeviceAllocation> device_allocations;
std::unordered_map<CUdeviceptr, bool> accessed_by_advice;
std::unordered_map<void *, std::size_t> host_allocations;
std::unordered_map<CUstream, bool> streams;
std::unordered_map<CUevent, bool> events;
std::unordered_map<CUgraph, bool> graphs;
std::unordered_map<CUgraphExec, bool> graph_execs;
std::unordered_map<CUfunction, bool> functions;
thread_local CUcontext current_context = nullptr;
std::recursive_mutex fake_driver_mutex;
std::uint64_t next_context_id = 1;
std::uint64_t next_stream_id = 1;
double simulated_device_clock_microseconds = 0.0;
bool event_record_failure_injected = false;
bool event_sync_failure_injected = false;
bool event_elapsed_failure_injected = false;
bool memfree_failure_injected = false;
bool context_destroy_failure_injected = false;
bool managed_prefetch_failure_injected = false;
bool managed_advice_set_failure_injected = false;
bool managed_advice_unset_failure_injected = false;
#ifndef FAKE_CUDA_NO_GRAPHS
bool graph_launch_failure_injected = false;
bool graph_launch_corruption_injected = false;
#endif
std::mutex concurrent_launch_gate_mutex;
std::condition_variable concurrent_launch_gate_changed;
unsigned int concurrent_launch_gate_arrivals = 0;
bool concurrent_launch_gate_cancelled = false;

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

std::uint32_t fakeConcurrentValue(std::uint32_t seed, unsigned int rounds) {
  std::uint32_t accumulated_multiplier = 1U;
  std::uint32_t accumulated_increment = 0U;
  std::uint32_t multiplier = 1664525U;
  std::uint32_t increment = 1013904223U;
  while (rounds != 0) {
    if (rounds & 1U) {
      accumulated_increment = multiplier * accumulated_increment + increment;
      accumulated_multiplier = multiplier * accumulated_multiplier;
    }
    increment = multiplier * increment + increment;
    multiplier *= multiplier;
    rounds >>= 1U;
  }
  return accumulated_multiplier * seed + accumulated_increment;
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

#ifndef FAKE_CUDA_NO_PEER_API
CUresult findPeerAllocation(CUdeviceptr address, std::size_t bytes,
                            CUcontext owner, DeviceAllocation **allocation,
                            std::size_t *offset) {
  for (auto &entry : device_allocations) {
    const CUdeviceptr base = entry.first;
    DeviceAllocation &candidate = entry.second;
    if (address < base) continue;
    const CUdeviceptr difference = address - base;
    if (difference > candidate.bytes || bytes > candidate.bytes - difference) continue;
    if (candidate.owner != owner || !validContext(owner))
      return CUDA_ERROR_INVALID_CONTEXT;
    *allocation = &candidate;
    *offset = static_cast<std::size_t>(difference);
    return CUDA_SUCCESS;
  }
  return CUDA_ERROR_INVALID_VALUE;
}

CUresult performPeerCopy(CUdeviceptr destination, CUcontext destinationContext,
                         CUdeviceptr source, CUcontext sourceContext,
                         std::size_t bytes) {
  if (bytes == 0 || !validContext(destinationContext) ||
      !validContext(sourceContext) || destinationContext == sourceContext)
    return CUDA_ERROR_INVALID_CONTEXT;
  DeviceAllocation *sourceAllocation = nullptr;
  DeviceAllocation *destinationAllocation = nullptr;
  std::size_t sourceOffset = 0;
  std::size_t destinationOffset = 0;
  CUresult status = findPeerAllocation(source, bytes, sourceContext,
                                       &sourceAllocation, &sourceOffset);
  if (status != CUDA_SUCCESS) return status;
  status = findPeerAllocation(destination, bytes, destinationContext,
                              &destinationAllocation, &destinationOffset);
  if (status != CUDA_SUCCESS) return status;
  std::memcpy(static_cast<char *>(destinationAllocation->address) + destinationOffset,
              static_cast<char *>(sourceAllocation->address) + sourceOffset, bytes);
  return CUDA_SUCCESS;
}
#endif

void resourceSnapshot() {
  char line[256];
  std::snprintf(line, sizeof(line),
                "resource_snapshot contexts=%zu modules=%zu functions=%zu "
                "device_allocations=%zu host_allocations=%zu streams=%zu "
                "graphs=%zu graph_execs=%zu events=%zu",
                contexts.size(), modules.size(), functions.size(),
                device_allocations.size(), host_allocations.size(), streams.size(),
                graphs.size(), graph_execs.size(), events.size());
  std::string summary(line);
  summary += " peer_accesses=" + std::to_string(peer_accesses.size());
  trace(summary);
}

}  // namespace

#define FAKE_DRIVER_LOCK std::lock_guard<std::recursive_mutex> driverLock(fake_driver_mutex)

bool isConcurrentWorkFunction(CUfunction function) {
  FAKE_DRIVER_LOCK;
  return function && functions.count(function) &&
         function->name == "hybrid_concurrent_work";
}

bool waitForConcurrentWorkPeer() {
  std::unique_lock<std::mutex> lock(concurrent_launch_gate_mutex);
  ++concurrent_launch_gate_arrivals;
  if (concurrent_launch_gate_arrivals == 2) {
    concurrent_launch_gate_changed.notify_all();
    return true;
  }
  if (!concurrent_launch_gate_changed.wait_for(
          lock, std::chrono::seconds(5), [] {
            return concurrent_launch_gate_arrivals == 2 ||
                   concurrent_launch_gate_cancelled;
          })) {
    concurrent_launch_gate_cancelled = true;
    concurrent_launch_gate_changed.notify_all();
    return false;
  }
  return !concurrent_launch_gate_cancelled;
}

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
  else if (attribute == CU_DEVICE_ATTRIBUTE_CONCURRENT_MANAGED_ACCESS)
    *value = 1;
  else if (attribute == CU_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS)
    *value = device == 0 || std::getenv("FAKE_CUDA_PAGEABLE_MEMORY_UNSUPPORTED")
        ? 0 : 1;
  else if (attribute == CU_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS_USES_HOST_PAGE_TABLES)
    *value = 0;
  else if (attribute == CU_DEVICE_ATTRIBUTE_UNIFIED_ADDRESSING)
    *value = 1;
  else
    return CUDA_ERROR_INVALID_VALUE;
  return CUDA_SUCCESS;
}

#ifndef FAKE_CUDA_NO_PEER_API
CUresult cuDeviceCanAccessPeer(int *canAccessPeer, CUdevice device,
                               CUdevice peerDevice) {
  if (!canAccessPeer || device < 0 || device >= 2 || peerDevice < 0 ||
      peerDevice >= 2 || device == peerDevice)
    return CUDA_ERROR_INVALID_VALUE;
  int value = enabled("FAKE_CUDA_PEER_UNSUPPORTED") ? 0 : 1;
  if (enabled("FAKE_CUDA_PEER_ONE_WAY") && device == 1 && peerDevice == 0)
    value = 0;
  *canAccessPeer = value;
  trace("peer_capability from=" + std::to_string(device) +
        " to=" + std::to_string(peerDevice) +
        " supported=" + std::to_string(value));
  return CUDA_SUCCESS;
}
#endif

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
  FAKE_DRIVER_LOCK;
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

#ifndef FAKE_CUDA_NO_PEER_API
CUresult cuCtxEnablePeerAccess(CUcontext peerContext, unsigned int flags) {
  FAKE_DRIVER_LOCK;
  if (!validCurrentContext() || !validContext(peerContext) ||
      current_context == peerContext || flags != 0)
    return CUDA_ERROR_INVALID_CONTEXT;
  if (enabled("FAKE_CUDA_PEER_ENABLE_FAIL")) {
    trace("peer_enable_injected_error");
    return CUDA_ERROR_UNKNOWN;
  }
  if (!peer_accesses.emplace(current_context, peerContext).second)
    return CUDA_ERROR_UNKNOWN;
  trace("peer_enable from=" + std::to_string(current_context->device) +
        " to=" + std::to_string(peerContext->device));
  return CUDA_SUCCESS;
}

CUresult cuCtxDisablePeerAccess(CUcontext peerContext) {
  FAKE_DRIVER_LOCK;
  if (!validCurrentContext() || !validContext(peerContext))
    return CUDA_ERROR_INVALID_CONTEXT;
  if (enabled("FAKE_CUDA_PEER_DISABLE_FAIL")) {
    trace("peer_disable_injected_error");
    return CUDA_ERROR_UNKNOWN;
  }
  if (peer_accesses.erase({current_context, peerContext}) != 1)
    return CUDA_ERROR_INVALID_VALUE;
  trace("peer_disable from=" + std::to_string(current_context->device) +
        " to=" + std::to_string(peerContext->device));
  return CUDA_SUCCESS;
}
#endif

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
  FAKE_DRIVER_LOCK;
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
  FAKE_DRIVER_LOCK;
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
  FAKE_DRIVER_LOCK;
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
  FAKE_DRIVER_LOCK;
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

CUresult cuMemAdvise_v2(CUdeviceptr pointer, std::size_t bytes, int advice,
                        CUmemLocation location) {
  const auto allocation = device_allocations.find(pointer);
  if (allocation == device_allocations.end() || !allocation->second.managed ||
      bytes == 0 || bytes > allocation->second.bytes)
    return CUDA_ERROR_INVALID_VALUE;
  if (!validCurrentContext() || allocation->second.owner != current_context)
    return CUDA_ERROR_INVALID_CONTEXT;
  if (location.type != CU_MEM_LOCATION_TYPE_DEVICE ||
      location.id != current_context->device)
    return CUDA_ERROR_INVALID_VALUE;

  if (advice == CU_MEM_ADVISE_SET_ACCESSED_BY) {
    if (accessed_by_advice.count(pointer)) return CUDA_ERROR_INVALID_VALUE;
    if (enabled("FAKE_CUDA_MEM_ADVISE_FAIL_SET_ONCE") &&
        !managed_advice_set_failure_injected) {
      managed_advice_set_failure_injected = true;
      trace("mem_advise_injected_error advice=5");
      return CUDA_ERROR_UNKNOWN;
    }
    accessed_by_advice.emplace(pointer, true);
  } else if (advice == CU_MEM_ADVISE_UNSET_ACCESSED_BY) {
    if (!accessed_by_advice.count(pointer)) return CUDA_ERROR_INVALID_VALUE;
    if (enabled("FAKE_CUDA_MEM_ADVISE_FAIL_UNSET_ONCE") &&
        !managed_advice_unset_failure_injected) {
      managed_advice_unset_failure_injected = true;
      trace("mem_advise_injected_error advice=6");
      return CUDA_ERROR_UNKNOWN;
    }
    accessed_by_advice.erase(pointer);
  } else {
    return CUDA_ERROR_INVALID_VALUE;
  }

  trace("mem_advise advice=" + std::to_string(advice) +
        " type=" + std::to_string(location.type) +
        " id=" + std::to_string(location.id) +
        " bytes=" + std::to_string(bytes));
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
  FAKE_DRIVER_LOCK;
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
  accessed_by_advice.erase(pointer);
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
  std::uint32_t firstWord = 0;
  if (bytes >= sizeof(firstWord)) std::memcpy(&firstWord, source, sizeof(firstWord));
  if (enabled("FAKE_CUDA_HOST_STAGE_CORRUPT") && bytes == 4096 &&
      (firstWord == 0x53544731U || firstWord == 0x53544732U)) {
    static_cast<char *>(allocation->address)[offset + bytes - 1] ^= 0x1;
    trace("host_stage_corrupt");
  }
  trace("copy_htod");
  return CUDA_SUCCESS;
}

CUresult cuMemcpyDtoH_v2(void *destination, CUdeviceptr source,
                         std::size_t bytes) {
  FAKE_DRIVER_LOCK;
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

#ifndef FAKE_CUDA_NO_PEER_API
CUresult cuMemcpyPeer(CUdeviceptr destination, CUcontext destinationContext,
                      CUdeviceptr source, CUcontext sourceContext,
                      std::size_t bytes) {
  FAKE_DRIVER_LOCK;
  if (enabled("FAKE_CUDA_PEER_COPY_FAIL")) {
    trace("peer_copy_injected_error");
    return CUDA_ERROR_UNKNOWN;
  }
  const CUresult status = performPeerCopy(destination, destinationContext,
                                          source, sourceContext, bytes);
  if (status != CUDA_SUCCESS) return status;
  trace("peer_copy_sync from=" + std::to_string(sourceContext->device) +
        " to=" + std::to_string(destinationContext->device) +
        " bytes=" + std::to_string(bytes));
  return CUDA_SUCCESS;
}

CUresult cuMemcpyPeerAsync(CUdeviceptr destination,
                           CUcontext destinationContext, CUdeviceptr source,
                           CUcontext sourceContext, std::size_t bytes,
                           CUstream stream) {
  if (!stream || !streams.count(stream) || stream->owner != destinationContext ||
      current_context != destinationContext)
    return CUDA_ERROR_INVALID_CONTEXT;
  if (enabled("FAKE_CUDA_PEER_COPY_FAIL")) {
    trace("peer_copy_injected_error");
    return CUDA_ERROR_UNKNOWN;
  }
  const CUresult status = performPeerCopy(destination, destinationContext,
                                          source, sourceContext, bytes);
  if (status == CUDA_SUCCESS) {
    simulated_device_clock_microseconds += 4.0 + bytes / (1024.0 * 100.0);
    trace("peer_copy_async from=" + std::to_string(sourceContext->device) +
          " to=" + std::to_string(destinationContext->device));
  }
  return status;
}
#endif

CUresult cuMemcpyHtoDAsync_v2(CUdeviceptr destination, const void *source,
                              std::size_t bytes, CUstream stream) {
  if (stream && !streams.count(stream)) return CUDA_ERROR_INVALID_VALUE;
  const CUresult status = cuMemcpyHtoD_v2(destination, source, bytes);
  if (status == CUDA_SUCCESS)
    simulated_device_clock_microseconds += 4.0 + bytes / (1024.0 * 100.0);
  return status;
}

CUresult cuMemcpyDtoHAsync_v2(void *destination, CUdeviceptr source,
                              std::size_t bytes, CUstream stream) {
  if (stream && !streams.count(stream)) return CUDA_ERROR_INVALID_VALUE;
  const CUresult status = cuMemcpyDtoH_v2(destination, source, bytes);
  if (status == CUDA_SUCCESS)
    simulated_device_clock_microseconds += 4.0 + bytes / (1024.0 * 100.0);
  return status;
}

CUresult cuStreamCreate(CUstream *stream, unsigned int flags) {
  FAKE_DRIVER_LOCK;
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
  FAKE_DRIVER_LOCK;
  if (!streams.count(stream)) return CUDA_ERROR_INVALID_VALUE;
  streams.erase(stream);
  delete stream;
  trace("stream_destroy");
  return CUDA_SUCCESS;
}

CUresult cuStreamSynchronize(CUstream stream) {
  FAKE_DRIVER_LOCK;
  if (!streams.count(stream) || !validCurrentContext())
    return CUDA_ERROR_INVALID_CONTEXT;
  trace("stream_synchronize");
  return CUDA_SUCCESS;
}

CUresult cuEventCreate(CUevent *event, unsigned int flags) {
  if (!event || flags != 0 || !validCurrentContext())
    return CUDA_ERROR_INVALID_CONTEXT;
  auto *created = new CUevent_st;
  created->owner = current_context;
  events.emplace(created, true);
  *event = created;
  trace("event_create");
  return CUDA_SUCCESS;
}

CUresult cuEventDestroy_v2(CUevent event) {
  if (!event || !events.count(event)) return CUDA_ERROR_INVALID_VALUE;
  events.erase(event);
  delete event;
  trace("event_destroy");
  return CUDA_SUCCESS;
}

CUresult cuEventRecord(CUevent event, CUstream stream) {
  if (!event || !events.count(event) || !validCurrentContext() ||
      event->owner != current_context || (stream && !streams.count(stream)))
    return CUDA_ERROR_INVALID_CONTEXT;
  if (enabled("FAKE_CUDA_EVENT_RECORD_FAIL_ONCE") &&
      !event_record_failure_injected) {
    event_record_failure_injected = true;
    trace("event_record_injected_error");
    return CUDA_ERROR_UNKNOWN;
  }
  event->timestampMicroseconds = simulated_device_clock_microseconds;
  event->recorded = true;
  return CUDA_SUCCESS;
}

CUresult cuEventSynchronize(CUevent event) {
  if (!event || !events.count(event) || !event->recorded ||
      !validCurrentContext() || event->owner != current_context)
    return CUDA_ERROR_INVALID_CONTEXT;
  if (enabled("FAKE_CUDA_EVENT_SYNC_FAIL_ONCE") &&
      !event_sync_failure_injected) {
    event_sync_failure_injected = true;
    trace("event_sync_injected_error");
    return CUDA_ERROR_UNKNOWN;
  }
  return CUDA_SUCCESS;
}

CUresult cuEventElapsedTime(float *milliseconds, CUevent start, CUevent stop) {
  if (!milliseconds || !start || !stop || !events.count(start) ||
      !events.count(stop) || !start->recorded || !stop->recorded ||
      start->owner != stop->owner || !validCurrentContext() ||
      start->owner != current_context || stop->owner != current_context ||
      stop->timestampMicroseconds <= start->timestampMicroseconds)
    return CUDA_ERROR_INVALID_VALUE;
  if (enabled("FAKE_CUDA_EVENT_ELAPSED_FAIL_ONCE") &&
      !event_elapsed_failure_injected) {
    event_elapsed_failure_injected = true;
    trace("event_elapsed_injected_error");
    return CUDA_ERROR_UNKNOWN;
  }
  *milliseconds = static_cast<float>(stop->timestampMicroseconds -
                                     start->timestampMicroseconds) / 1000.0F;
  return CUDA_SUCCESS;
}

CUresult cuLaunchKernel(CUfunction function,
                        unsigned int grid_x, unsigned int grid_y,
                        unsigned int grid_z, unsigned int block_x,
                        unsigned int block_y, unsigned int block_z,
                        unsigned int shared_bytes, CUstream stream,
                        void **kernel_parameters, void **extra) {
  if (isConcurrentWorkFunction(function) && !waitForConcurrentWorkPeer())
    return CUDA_ERROR_UNKNOWN;
  FAKE_DRIVER_LOCK;
  (void)grid_y;
  (void)grid_z;
  (void)block_y;
  (void)block_z;
  (void)shared_bytes;
  (void)extra;
  if (!function || !functions.count(function) ||
      (function->name != "hybrid_empty" && !kernel_parameters) ||
      (stream && !streams.count(stream)))
    return CUDA_ERROR_INVALID_VALUE;
  if (!validCurrentContext() || function->module->owner != current_context)
    return CUDA_ERROR_INVALID_CONTEXT;

  CUresult status = CUDA_SUCCESS;
  if (function->name == "hybrid_empty") {
    current_context->last_kernel = "hybrid_empty";
    current_context->last_add_count = 0;
  } else if (function->name == "hybrid_arch") {
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
    const bool system_pageable =
        std::getenv("FAKE_CUDA_SYSTEM_PAGEABLE_MEMORY") != nullptr &&
        status == CUDA_ERROR_INVALID_VALUE;
    if (system_pageable)
      status = CUDA_SUCCESS;
    if (status == CUDA_SUCCESS) {
      const auto *a_values = system_pageable
          ? reinterpret_cast<const int *>(static_cast<std::uintptr_t>(a_address))
          : reinterpret_cast<const int *>(static_cast<const char *>(a->address) + a_offset);
      const auto *b_values = system_pageable
          ? reinterpret_cast<const int *>(static_cast<std::uintptr_t>(b_address))
          : reinterpret_cast<const int *>(static_cast<const char *>(b->address) + b_offset);
      auto *out_values = system_pageable
          ? reinterpret_cast<int *>(static_cast<std::uintptr_t>(output_address))
          : reinterpret_cast<int *>(static_cast<char *>(output->address) + output_offset);
      const std::uint64_t launched_threads =
          static_cast<std::uint64_t>(grid_x) * block_x;
      for (unsigned int i = 0; i < count && i < launched_threads; ++i)
        out_values[i] = a_values[i] + b_values[i];
      current_context->last_kernel = "hybrid_add";
      current_context->last_add_count = count;
      if (system_pageable)
        trace("pageable_pointer_launch count=" + std::to_string(count));
    }
  } else if (function->name == "hybrid_concurrent_work") {
    const CUdeviceptr output_address =
        *static_cast<CUdeviceptr *>(kernel_parameters[0]);
    const unsigned int count =
        *static_cast<unsigned int *>(kernel_parameters[1]);
    const unsigned int rounds =
        *static_cast<unsigned int *>(kernel_parameters[2]);
    DeviceAllocation *output = nullptr;
    std::size_t output_offset = 0;
    status = findAllocation(output_address,
                            static_cast<std::size_t>(count) * sizeof(std::uint32_t),
                            &output, &output_offset);
    if (enabled("FAKE_CUDA_FAIL_CONCURRENT_SM70") &&
        current_context->device == 0)
      status = CUDA_ERROR_UNKNOWN;
    if (status == CUDA_SUCCESS) {
      auto *values = reinterpret_cast<std::uint32_t *>(
          static_cast<char *>(output->address) + output_offset);
      const std::uint64_t launched_threads =
          static_cast<std::uint64_t>(grid_x) * block_x;
      for (unsigned int i = 0; i < count && i < launched_threads; ++i)
        values[i] = fakeConcurrentValue(i + 1U, rounds);
      current_context->last_kernel = "hybrid_concurrent_work";
      current_context->last_add_count = count;
    }
  } else if (function->name == "hybrid_peer_read") {
#ifndef FAKE_CUDA_NO_PEER_API
    if (enabled("FAKE_CUDA_PEER_KERNEL_FAIL")) {
      trace("peer_kernel_injected_error");
      status = CUDA_ERROR_UNKNOWN;
    } else {
      const CUdeviceptr source_address =
          *static_cast<CUdeviceptr *>(kernel_parameters[0]);
      const CUdeviceptr output_address =
          *static_cast<CUdeviceptr *>(kernel_parameters[1]);
      const unsigned int count =
          *static_cast<unsigned int *>(kernel_parameters[2]);
      const std::size_t bytes = static_cast<std::size_t>(count) * sizeof(std::uint32_t);
      CUcontext source_owner = nullptr;
      for (const auto &entry : device_allocations) {
        const CUdeviceptr base = entry.first;
        const DeviceAllocation &candidate = entry.second;
        if (source_address >= base &&
            source_address - base <= candidate.bytes &&
            bytes <= candidate.bytes - static_cast<std::size_t>(source_address - base)) {
          source_owner = candidate.owner;
          break;
        }
      }
      if (!source_owner || !peer_accesses.count({current_context, source_owner})) {
        status = CUDA_ERROR_INVALID_CONTEXT;
      } else {
        DeviceAllocation *source = nullptr;
        DeviceAllocation *output = nullptr;
        std::size_t source_offset = 0;
        std::size_t output_offset = 0;
        status = findPeerAllocation(source_address, bytes, source_owner,
                                   &source, &source_offset);
        if (status == CUDA_SUCCESS)
          status = findAllocation(output_address, bytes, &output, &output_offset);
        if (status == CUDA_SUCCESS &&
            static_cast<std::uint64_t>(grid_x) * block_x < count)
          status = CUDA_ERROR_INVALID_VALUE;
        if (status == CUDA_SUCCESS) {
          std::memcpy(static_cast<char *>(output->address) + output_offset,
                      static_cast<char *>(source->address) + source_offset, bytes);
          current_context->last_kernel = "hybrid_peer_read";
          current_context->last_add_count = count;
          trace("peer_kernel_read from=" +
                std::to_string(source_owner->device) + " to=" +
                std::to_string(current_context->device) + " count=" +
                std::to_string(count));
        }
      }
    }
#else
    status = CUDA_ERROR_INVALID_VALUE;
#endif
  } else {
    status = CUDA_ERROR_INVALID_VALUE;
  }

  char line[192];
  if (function->name == "hybrid_concurrent_work") {
    std::snprintf(line, sizeof(line),
                  "concurrent_launch ordinal=%d count=%u live_contexts=%zu",
                  current_context->device, current_context->last_add_count,
                  contexts.size());
  } else {
    std::snprintf(line, sizeof(line),
                  "launch kind=%s ordinal=%d count=%u live_contexts=%zu",
                  function->name == "hybrid_arch" ? "arch" :
                      (function->name == "hybrid_empty" ? "empty" : "add"),
                  current_context->device, current_context->last_add_count,
                  contexts.size());
  }
  trace(line);
  if (status == CUDA_SUCCESS) simulated_device_clock_microseconds += 0.5;
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
      (parameters->func->name != "hybrid_add" &&
       parameters->func->name != "hybrid_empty") ||
      (parameters->func->name == "hybrid_add" && !parameters->kernelParams) ||
      !validCurrentContext() || graph->owner != current_context)
    return CUDA_ERROR_INVALID_VALUE;
  auto *created = new CUgraphNode_st;
  created->graph = graph;
  graph->node = created;
  graph->function = parameters->func;
  if (parameters->func->name == "hybrid_add") {
    graph->parameters[0] = *static_cast<CUdeviceptr *>(parameters->kernelParams[0]);
    graph->parameters[1] = *static_cast<CUdeviceptr *>(parameters->kernelParams[1]);
    graph->parameters[2] = *static_cast<CUdeviceptr *>(parameters->kernelParams[2]);
    graph->count = *static_cast<unsigned int *>(parameters->kernelParams[3]);
  }
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
      graph->gridX, 1, 1, graph->blockX, 1, 1, 0, stream,
      graph->function->name == "hybrid_empty" ? nullptr : parameters, nullptr);
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
