// SPDX-License-Identifier: MIT
#include <cuda.h>

#include <dlfcn.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <vector>

namespace {

struct UsageError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

struct CudaError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

using CtxCreateV2 = CUresult(CUDAAPI *)(CUcontext *, unsigned int, CUdevice);
using MemPrefetchAsyncLegacy = CUresult(CUDAAPI *)(CUdeviceptr, std::size_t, CUdevice, CUstream);
using MemPrefetchAsyncV2 = CUresult(CUDAAPI *)(CUdeviceptr, std::size_t, CUmemLocation,
                                               unsigned int, CUstream);

struct Api {
  void *library = nullptr;
  std::string libraryPath;
  decltype(&cuInit) init = nullptr;
  decltype(&cuDriverGetVersion) driverGetVersion = nullptr;
  decltype(&cuDeviceGetCount) deviceGetCount = nullptr;
  decltype(&cuDeviceGet) deviceGet = nullptr;
  decltype(&cuDeviceGetName) deviceGetName = nullptr;
  decltype(&cuDeviceGetPCIBusId) deviceGetPciBusId = nullptr;
  decltype(&cuDeviceGetAttribute) deviceGetAttribute = nullptr;
  CtxCreateV2 contextCreate = nullptr;
  decltype(&cuCtxDestroy_v2) contextDestroy = nullptr;
  decltype(&cuCtxSetCurrent) contextSetCurrent = nullptr;
  decltype(&cuCtxGetDevice) contextGetDevice = nullptr;
  decltype(&cuCtxSynchronize) contextSynchronize = nullptr;
  decltype(&cuModuleLoad) moduleLoad = nullptr;
  decltype(&cuModuleUnload) moduleUnload = nullptr;
  decltype(&cuModuleGetFunction) moduleGetFunction = nullptr;
  decltype(&cuMemAlloc_v2) memoryAlloc = nullptr;
  decltype(&cuMemAllocManaged) managedMemoryAlloc = nullptr;
  MemPrefetchAsyncLegacy managedMemoryPrefetchLegacy = nullptr;
  MemPrefetchAsyncV2 managedMemoryPrefetchV2 = nullptr;
  std::string managedMemoryPrefetchApi = "not-requested";
  std::string cudaGraphsApi = "not-requested";
  decltype(&cuMemFree_v2) memoryFree = nullptr;
  decltype(&cuMemHostAlloc) hostAlloc = nullptr;
  decltype(&cuMemFreeHost) hostFree = nullptr;
  decltype(&cuMemcpyHtoD_v2) copyHostToDevice = nullptr;
  decltype(&cuMemcpyDtoH_v2) copyDeviceToHost = nullptr;
  decltype(&cuMemcpyHtoDAsync_v2) copyHostToDeviceAsync = nullptr;
  decltype(&cuMemcpyDtoHAsync_v2) copyDeviceToHostAsync = nullptr;
  decltype(&cuStreamCreate) streamCreate = nullptr;
  decltype(&cuStreamDestroy_v2) streamDestroy = nullptr;
  decltype(&cuStreamSynchronize) streamSynchronize = nullptr;
  decltype(&cuLaunchKernel) launchKernel = nullptr;
  decltype(&cuGraphCreate) graphCreate = nullptr;
  decltype(&cuGraphDestroy) graphDestroy = nullptr;
  decltype(&cuGraphAddKernelNode) graphAddKernelNode = nullptr;
  decltype(&cuGraphInstantiate) graphInstantiate = nullptr;
  decltype(&cuGraphLaunch) graphLaunch = nullptr;
  decltype(&cuGraphExecDestroy) graphExecDestroy = nullptr;
  decltype(&cuGetErrorName) getErrorName = nullptr;
  decltype(&cuGetErrorString) getErrorString = nullptr;

  template <typename T>
  T symbol(const char *name) {
    dlerror();
    void *address = dlsym(library, name);
    const char *error = dlerror();
    if (error || !address) {
      throw CudaError(std::string("libcuda.so.1 is missing ") + name +
                      (error ? std::string(": ") + error : ""));
    }
    return reinterpret_cast<T>(address);
  }

  void enableManagedMemory() {
    if (!managedMemoryAlloc)
      managedMemoryAlloc = symbol<decltype(managedMemoryAlloc)>("cuMemAllocManaged");
  }

  void enableManagedPrefetch() {
    if (managedMemoryPrefetchLegacy || managedMemoryPrefetchV2) return;
    managedMemoryPrefetchApi = "unavailable";
    dlerror();
    if (void *address = dlsym(library, "cuMemPrefetchAsync_v2")) {
      managedMemoryPrefetchV2 = reinterpret_cast<MemPrefetchAsyncV2>(address);
      managedMemoryPrefetchApi = "cuMemPrefetchAsync_v2";
      return;
    }
    const char *v2ErrorPointer = dlerror();
    const std::string v2Error = v2ErrorPointer ? v2ErrorPointer : "";
    dlerror();
    if (void *address = dlsym(library, "cuMemPrefetchAsync")) {
      managedMemoryPrefetchLegacy = reinterpret_cast<MemPrefetchAsyncLegacy>(address);
      managedMemoryPrefetchApi = "cuMemPrefetchAsync";
      return;
    }
    const char *legacyError = dlerror();
    throw CudaError(std::string("libcuda.so.1 is missing cuMemPrefetchAsync_v2 and cuMemPrefetchAsync") +
                    (legacyError ? std::string(": ") + legacyError :
                     (!v2Error.empty() ? std::string(": ") + v2Error : "")));
  }

  void enableCudaGraphs() {
    if (graphCreate) return;
    try {
      const auto create = symbol<decltype(graphCreate)>("cuGraphCreate");
      const auto destroy = symbol<decltype(graphDestroy)>("cuGraphDestroy");
      const auto addKernelNode =
          symbol<decltype(graphAddKernelNode)>("cuGraphAddKernelNode_v2");
      const auto instantiate =
          symbol<decltype(graphInstantiate)>("cuGraphInstantiateWithFlags");
      const auto launch = symbol<decltype(graphLaunch)>("cuGraphLaunch");
      const auto destroyExecutable =
          symbol<decltype(graphExecDestroy)>("cuGraphExecDestroy");
      graphCreate = create;
      graphDestroy = destroy;
      graphAddKernelNode = addKernelNode;
      graphInstantiate = instantiate;
      graphLaunch = launch;
      graphExecDestroy = destroyExecutable;
      cudaGraphsApi = "cuGraphInstantiateWithFlags";
    } catch (...) {
      cudaGraphsApi = "unavailable";
      throw;
    }
  }

  Api() {
    library = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library) {
      const char *error = dlerror();
      throw CudaError(std::string("cannot load the installed libcuda.so.1: ") +
                      (error ? error : "unknown loader error"));
    }
    try {
#define LOAD(member, name) member = symbol<decltype(member)>(name)
    LOAD(init, "cuInit");
    LOAD(driverGetVersion, "cuDriverGetVersion");
    LOAD(deviceGetCount, "cuDeviceGetCount");
    LOAD(deviceGet, "cuDeviceGet");
    LOAD(deviceGetName, "cuDeviceGetName");
    LOAD(deviceGetPciBusId, "cuDeviceGetPCIBusId");
    LOAD(deviceGetAttribute, "cuDeviceGetAttribute");
    LOAD(contextCreate, "cuCtxCreate_v2");
    LOAD(contextDestroy, "cuCtxDestroy_v2");
    LOAD(contextSetCurrent, "cuCtxSetCurrent");
    LOAD(contextGetDevice, "cuCtxGetDevice");
    LOAD(contextSynchronize, "cuCtxSynchronize");
    LOAD(moduleLoad, "cuModuleLoad");
    LOAD(moduleUnload, "cuModuleUnload");
    LOAD(moduleGetFunction, "cuModuleGetFunction");
    LOAD(memoryAlloc, "cuMemAlloc_v2");
    LOAD(memoryFree, "cuMemFree_v2");
    LOAD(hostAlloc, "cuMemHostAlloc");
    LOAD(hostFree, "cuMemFreeHost");
    LOAD(copyHostToDevice, "cuMemcpyHtoD_v2");
    LOAD(copyDeviceToHost, "cuMemcpyDtoH_v2");
    LOAD(copyHostToDeviceAsync, "cuMemcpyHtoDAsync_v2");
    LOAD(copyDeviceToHostAsync, "cuMemcpyDtoHAsync_v2");
    LOAD(streamCreate, "cuStreamCreate");
    LOAD(streamDestroy, "cuStreamDestroy_v2");
    LOAD(streamSynchronize, "cuStreamSynchronize");
    LOAD(launchKernel, "cuLaunchKernel");
    LOAD(getErrorName, "cuGetErrorName");
    LOAD(getErrorString, "cuGetErrorString");
#undef LOAD
      Dl_info info{};
      if (!dladdr(reinterpret_cast<void *>(init), &info) || !info.dli_fname)
        throw CudaError("cannot identify the loaded CUDA driver library");
      char *resolved = realpath(info.dli_fname, nullptr);
      if (!resolved) throw CudaError("cannot resolve the loaded CUDA driver library");
      libraryPath = resolved;
      std::free(resolved);
    } catch (...) {
      dlclose(library);
      library = nullptr;
      throw;
    }
  }

  ~Api() {
    if (library) dlclose(library);
  }

  void check(CUresult result, const std::string &operation) const {
    if (result == CUDA_SUCCESS) return;
    const char *name = nullptr;
    const char *description = nullptr;
    getErrorName(result, &name);
    getErrorString(result, &description);
    std::ostringstream message;
    message << operation << " failed with CUresult=" << static_cast<int>(result)
            << " (" << (name ? name : "unknown") << "): "
            << (description ? description : "no description");
    throw CudaError(message.str());
  }
};

struct DeviceInfo {
  CUdevice handle{};
  int ordinal = -1;
  int major = 0;
  int minor = 0;
  int sm = 0;
  bool concurrentManagedAccess = false;
  bool pageableMemoryAccess = false;
  bool pageableMemoryAccessUsesHostPageTables = false;
  std::string name;
  std::string pci;
};

struct DeviceResult {
  DeviceInfo device;
  bool targeted = false;
  bool tested = false;
  bool archPassed = false;
  bool syncPassed = false;
  bool asyncPassed = false;
  bool managedMemoryPassed = false;
  bool managedPrefetchPassed = false;
  bool cudaGraphsPassed = false;
  unsigned int cudaGraphLaunches = 0;
  std::vector<unsigned int> syncSizes;
  std::vector<unsigned int> asyncSizes;
  bool cleanupPassed = true;
  std::vector<std::string> cleanupErrors;
  std::string error;
};

struct Options {
  bool contractOnly = false;
  bool listOnly = false;
  bool managedMemory = false;
  bool managedPrefetch = false;
  bool cudaGraphs = false;
  std::string phase;
  std::string modulePath;
  std::set<int> requiredSm{70, 120};
  std::string expectedPci;
};

std::string jsonEscape(const std::string &input) {
  std::ostringstream output;
  for (unsigned char ch : input) {
    switch (ch) {
      case '"': output << "\\\""; break;
      case '\\': output << "\\\\"; break;
      case '\b': output << "\\b"; break;
      case '\f': output << "\\f"; break;
      case '\n': output << "\\n"; break;
      case '\r': output << "\\r"; break;
      case '\t': output << "\\t"; break;
      default:
        if (ch < 0x20) {
          char escaped[7];
          std::snprintf(escaped, sizeof(escaped), "\\u%04x", ch);
          output << escaped;
        } else {
          output << static_cast<char>(ch);
        }
    }
  }
  return output.str();
}

void printUsage(std::ostream &stream, const char *program) {
  stream << "Usage:\n"
         << "  " << program << " --contract\n"
         << "  " << program << " --list\n"
         << "  " << program
         << " --module FILE [--require-sm 70,120] [--managed-memory [--managed-prefetch]]\n"
         << "  " << program << " --phase initialize|enumerate|context|allocation|module|kernel|system-pageable-memory "
         << "--expected-pci BDF [--module FILE]\n\n"
         << "--list inventories devices through the installed libcuda.so.1.\n"
         << "--module loads one fatbin into a distinct Driver API context per matching GPU.\n"
         << "--require-sm takes comma-separated compute-capability numbers (7.0 => 70, 12.0 => 120).\n"
         << "--expected-pci BDF requires exactly one visible GPU with that PCI ID before any context is created.\n"
         << "--managed-memory uses cuMemAllocManaged and CPU access after CUDA synchronization instead of explicit copies.\n"
         << "--managed-prefetch requires --managed-memory; it requests cuMemPrefetchAsync to each GPU and back to the CPU before host reads.\n"
         << "--cuda-graphs adds two opt-in CUDA Graph replays of the numeric kernel per targeted device.\n"
         << "--phase runs one bounded Driver API lifecycle phase in a fresh process; it never claims hybrid validation.\n"
         << "Phases: initialize (cuInit only), enumerate, context, allocation, module, one-result architecture kernel, and system-pageable-memory.\n"
         << "A missing required architecture returns 77 and keeps hybrid_validated false.\n";
}

void printProbeContract() {
  std::cout
      << R"({"schema":"nvidia-hybrid-probe-contract-v1","contract_version":4,"probe_report_schema":"nvidia-hybrid-probe-v2","probe_report_fields":["memory_mode","managed_prefetch_requested","managed_prefetch_api","devices","cuda_graphs_requested","cuda_graph_api"],"device_report_fields":["concurrent_managed_access","pageable_memory_access","pageable_memory_access_uses_host_page_tables","managed_memory_passed","managed_prefetch_passed","cuda_graphs_passed","cuda_graph_launches"]})"
      << '\n';
}

std::string canonicalPci(std::string text) {
  if (text.size() != 12 && text.size() != 16) return {};
  const std::size_t domain = text.size() - 8;
  if (text[domain] != ':' || text[domain + 3] != ':' || text[domain + 6] != '.' ||
      text.back() < '0' || text.back() > '7') return {};
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (i == domain || i == domain + 3 || i == domain + 6) continue;
    if (text[i] >= 'A' && text[i] <= 'F') text[i] += 'a' - 'A';
    if (!(text[i] >= '0' && text[i] <= '9') && !(text[i] >= 'a' && text[i] <= 'f')) return {};
  }
  if (std::strtoul(text.substr(domain + 4, 2).c_str(), nullptr, 16) > 31) return {};
  return std::string(8 - domain, '0') + text;
}

int parseSmList(const std::string &text, std::set<int> &result) {
  result.clear();
  if (text.empty() || text.back() == ',') return -1;
  std::istringstream input(text);
  std::string token;
  while (std::getline(input, token, ',')) {
    if (token.empty() || token.size() > 3 ||
        !std::all_of(token.begin(), token.end(),
                     [](unsigned char ch) { return ch >= '0' && ch <= '9'; })) {
      return -1;
    }
    errno = 0;
    char *end = nullptr;
    const long value = std::strtol(token.c_str(), &end, 10);
    if (errno || end == token.c_str() || *end || value < 10 || value > 999) {
      return -1;
    }
    result.insert(static_cast<int>(value));
  }
  return result.empty() ? -1 : 0;
}

Options parseOptions(int argc, char **argv) {
  Options options;
  bool gotRequiredSm = false;
  bool gotManagedMemory = false;
  bool gotManagedPrefetch = false;
  bool gotPhase = false;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      printUsage(std::cout, argv[0]);
      std::exit(0);
    } else if (arg == "--contract") {
      if (argc != 2 || i != 1)
        throw UsageError("--contract must be used alone");
      options.contractOnly = true;
    } else if (arg == "--list") {
      options.listOnly = true;
    } else if (arg == "--managed-memory") {
      if (gotManagedMemory) throw UsageError("--managed-memory may be supplied only once");
      options.managedMemory = true;
      gotManagedMemory = true;
    } else if (arg == "--managed-prefetch") {
      if (gotManagedPrefetch) throw UsageError("--managed-prefetch may be supplied only once");
      options.managedPrefetch = true;
      gotManagedPrefetch = true;
    } else if (arg == "--cuda-graphs") {
      if (options.cudaGraphs) throw UsageError("--cuda-graphs may be supplied only once");
      options.cudaGraphs = true;
    } else if (arg == "--phase" && i + 1 < argc) {
      if (gotPhase) throw UsageError("--phase may be supplied only once");
      options.phase = argv[++i];
      gotPhase = true;
    } else if (arg == "--module" && i + 1 < argc) {
      options.modulePath = argv[++i];
    } else if (arg == "--require-sm" && i + 1 < argc) {
      if (parseSmList(argv[++i], options.requiredSm) != 0)
        throw UsageError("--require-sm must be a non-empty comma-separated list of numeric SM values");
      gotRequiredSm = true;
    } else if (arg == "--expected-pci" && i + 1 < argc) {
      if (!options.expectedPci.empty()) throw UsageError("--expected-pci may be supplied only once");
      options.expectedPci = canonicalPci(argv[++i]);
      if (options.expectedPci.empty()) throw UsageError("invalid expected PCI ID; use DDDD:BB:DD.F or DDDDDDDD:BB:DD.F");
    } else {
      throw UsageError("unknown or incomplete argument: " + arg);
    }
  }
  if (options.listOnly && !options.modulePath.empty())
    throw UsageError("--list cannot be combined with --module");
  if (options.listOnly && gotRequiredSm)
    throw UsageError("--list cannot be combined with --require-sm");
  if (options.listOnly && gotPhase)
    throw UsageError("--list cannot be combined with --phase");
  if (options.listOnly && options.managedMemory)
    throw UsageError("--list cannot be combined with --managed-memory");
  if (options.managedPrefetch && !options.managedMemory)
    throw UsageError("--managed-prefetch requires --managed-memory");
  if (options.listOnly && options.managedPrefetch)
    throw UsageError("--list cannot be combined with --managed-prefetch");
  if (options.listOnly && options.cudaGraphs)
    throw UsageError("--list cannot be combined with --cuda-graphs");
  if (!options.phase.empty() && options.phase != "initialize" &&
      options.phase != "enumerate" && options.phase != "context" &&
      options.phase != "allocation" && options.phase != "module" &&
      options.phase != "kernel" && options.phase != "system-pageable-memory")
    throw UsageError("unsupported phase: " + options.phase);
  if (gotPhase && options.expectedPci.empty())
    throw UsageError("--phase requires --expected-pci for exact device selection");
  if (gotPhase && (options.managedMemory || options.managedPrefetch))
    throw UsageError("--phase cannot be combined with managed-memory modes");
  if (gotPhase && options.cudaGraphs)
    throw UsageError("--phase cannot be combined with --cuda-graphs");
  if (!options.contractOnly && !options.listOnly && options.phase.empty() &&
      options.modulePath.empty())
    throw UsageError("--module FILE is required unless --list is used");
  if ((!options.phase.empty() &&
       (options.phase == "module" || options.phase == "kernel" ||
        options.phase == "system-pageable-memory") && options.modulePath.empty()))
    throw UsageError("--phase module/kernel/system-pageable-memory requires --module FILE");
  if (!options.listOnly && !options.modulePath.empty()) {
    std::ifstream file(options.modulePath, std::ios::binary);
    if (!file.good()) throw UsageError("module file is not readable: " + options.modulePath);
  }
  return options;
}

std::vector<DeviceInfo> enumerateDevices(Api &api, int &driverVersion,
                                         std::vector<std::string> *operations = nullptr) {
  api.check(api.init(0), "cuInit");
  if (operations) operations->emplace_back("cuInit");
  api.check(api.driverGetVersion(&driverVersion), "cuDriverGetVersion");
  if (operations) operations->emplace_back("cuDriverGetVersion");
  int count = 0;
  api.check(api.deviceGetCount(&count), "cuDeviceGetCount");
  if (operations) operations->emplace_back("cuDeviceGetCount");
  std::vector<DeviceInfo> devices;
  for (int ordinal = 0; ordinal < count; ++ordinal) {
    DeviceInfo device;
    device.ordinal = ordinal;
    api.check(api.deviceGet(&device.handle, ordinal), "cuDeviceGet");
    if (operations) operations->emplace_back("cuDeviceGet");
    char name[256]{};
    char pci[32]{};
    api.check(api.deviceGetName(name, sizeof(name), device.handle), "cuDeviceGetName");
    if (operations) operations->emplace_back("cuDeviceGetName");
    api.check(api.deviceGetPciBusId(pci, sizeof(pci), device.handle), "cuDeviceGetPCIBusId");
    if (operations) operations->emplace_back("cuDeviceGetPCIBusId");
    api.check(api.deviceGetAttribute(&device.major,
                                     CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
                                     device.handle),
              "compute capability major");
    if (operations) operations->emplace_back("cuDeviceGetAttribute.major");
    api.check(api.deviceGetAttribute(&device.minor,
                                     CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
                                     device.handle),
              "compute capability minor");
    if (operations) operations->emplace_back("cuDeviceGetAttribute.minor");
    int concurrentManagedAccess = -1;
    api.check(api.deviceGetAttribute(&concurrentManagedAccess,
                                     CU_DEVICE_ATTRIBUTE_CONCURRENT_MANAGED_ACCESS,
                                     device.handle),
              "concurrent managed access");
    if (operations)
      operations->emplace_back("cuDeviceGetAttribute.concurrent_managed_access");
    if (concurrentManagedAccess != 0 && concurrentManagedAccess != 1)
      throw CudaError("concurrent managed access attribute is not boolean");
    int pageableMemoryAccess = -1;
    api.check(api.deviceGetAttribute(&pageableMemoryAccess,
                                     CU_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS,
                                     device.handle),
              "pageable memory access");
    if (operations)
      operations->emplace_back("cuDeviceGetAttribute.pageable_memory_access");
    if (pageableMemoryAccess != 0 && pageableMemoryAccess != 1)
      throw CudaError("pageable memory access attribute is not boolean");
    int pageableMemoryAccessUsesHostPageTables = -1;
    api.check(api.deviceGetAttribute(&pageableMemoryAccessUsesHostPageTables,
                                     CU_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS_USES_HOST_PAGE_TABLES,
                                     device.handle),
              "pageable memory access host page tables");
    if (operations)
      operations->emplace_back(
          "cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables");
    if (pageableMemoryAccessUsesHostPageTables != 0 &&
        pageableMemoryAccessUsesHostPageTables != 1)
      throw CudaError("pageable memory access host page tables attribute is not boolean");
    device.sm = device.major * 10 + device.minor;
    device.concurrentManagedAccess = concurrentManagedAccess == 1;
    device.pageableMemoryAccess = pageableMemoryAccess == 1;
    device.pageableMemoryAccessUsesHostPageTables =
        pageableMemoryAccessUsesHostPageTables == 1;
    device.name = name;
    device.pci = pci;
    devices.push_back(device);
  }
  return devices;
}

void recordCleanup(Api &api, CUresult status, const char *operation,
                   DeviceResult &result) noexcept {
  if (status == CUDA_SUCCESS) return;
  result.cleanupPassed = false;
  try {
    api.check(status, operation);
  } catch (const std::exception &error) {
    try { result.cleanupErrors.push_back(error.what()); } catch (...) {}
  } catch (...) {}
}

struct ContextGuard {
  Api &api;
  DeviceResult &result;
  CUcontext context{};
  ContextGuard(Api &apiIn, CUdevice device, DeviceResult &resultIn)
      : api(apiIn), result(resultIn) {
    api.check(api.contextCreate(&context, CU_CTX_SCHED_AUTO, device), "cuCtxCreate_v2");
  }
  ~ContextGuard() {
    if (context) {
      recordCleanup(api, api.contextSetCurrent(context), "cuCtxSetCurrent(cleanup)", result);
      recordCleanup(api, api.contextDestroy(context), "cuCtxDestroy_v2", result);
    }
  }
};

struct ModuleGuard {
  Api &api;
  DeviceResult &result;
  CUmodule module{};
  ModuleGuard(Api &apiIn, const std::string &path, DeviceResult &resultIn)
      : api(apiIn), result(resultIn) {
    api.check(api.moduleLoad(&module, path.c_str()), "cuModuleLoad(fatbin)");
  }
  ~ModuleGuard() {
    if (module) recordCleanup(api, api.moduleUnload(module), "cuModuleUnload", result);
  }
};

struct BufferGuard {
  Api &api;
  DeviceResult &result;
  CUdeviceptr pointer{};
  BufferGuard(Api &apiIn, std::size_t bytes, DeviceResult &resultIn,
              bool managedMemory)
      : api(apiIn), result(resultIn) {
    if (managedMemory) {
      api.enableManagedMemory();
      api.check(api.managedMemoryAlloc(&pointer, bytes, CU_MEM_ATTACH_GLOBAL),
                "cuMemAllocManaged");
    } else {
      api.check(api.memoryAlloc(&pointer, bytes), "cuMemAlloc_v2");
    }
  }
  ~BufferGuard() {
    if (pointer) recordCleanup(api, api.memoryFree(pointer), "cuMemFree_v2", result);
  }
};

struct HostGuard {
  Api &api;
  DeviceResult &result;
  void *pointer = nullptr;
  HostGuard(Api &apiIn, std::size_t bytes, DeviceResult &resultIn)
      : api(apiIn), result(resultIn) {
    api.check(api.hostAlloc(&pointer, bytes, CU_MEMHOSTALLOC_PORTABLE), "cuMemHostAlloc");
  }
  ~HostGuard() {
    if (pointer) recordCleanup(api, api.hostFree(pointer), "cuMemFreeHost", result);
  }
};

struct StreamGuard {
  Api &api;
  DeviceResult &result;
  CUstream stream{};
  StreamGuard(Api &apiIn, DeviceResult &resultIn) : api(apiIn), result(resultIn) {
    api.check(api.streamCreate(&stream, CU_STREAM_DEFAULT), "cuStreamCreate");
  }
  ~StreamGuard() {
    if (stream) {
      recordCleanup(api, api.streamSynchronize(stream), "cuStreamSynchronize(cleanup)", result);
      recordCleanup(api, api.streamDestroy(stream), "cuStreamDestroy_v2", result);
    }
  }
};

struct GraphGuard {
  Api &api;
  DeviceResult &result;
  CUstream stream{};
  CUgraph graph{};
  CUgraphExec executable{};
  GraphGuard(Api &apiIn, DeviceResult &resultIn, CUstream streamIn)
      : api(apiIn), result(resultIn), stream(streamIn) {
    api.check(api.graphCreate(&graph, 0), "cuGraphCreate");
  }
  ~GraphGuard() {
    if (executable) {
      recordCleanup(api, api.streamSynchronize(stream),
                    "cuStreamSynchronize(cuda graph cleanup)", result);
      recordCleanup(api, api.graphExecDestroy(executable),
                    "cuGraphExecDestroy", result);
    }
    if (graph)
      recordCleanup(api, api.graphDestroy(graph), "cuGraphDestroy", result);
  }
};

void launchArchKernel(Api &api, CUfunction function, CUdeviceptr output) {
  void *arguments[] = {&output};
  api.check(api.launchKernel(function, 1, 1, 1, 1, 1, 1, 0, nullptr,
                             arguments, nullptr),
            "cuLaunchKernel(hybrid_arch)");
}

void launchAddKernel(Api &api, CUfunction function, CUdeviceptr a,
                     CUdeviceptr b, CUdeviceptr output, unsigned int count,
                     CUstream stream) {
  void *arguments[] = {&a, &b, &output, &count};
  const unsigned int blocks = (count + 255U) / 256U;
  api.check(api.launchKernel(function, blocks, 1, 1, 256, 1, 1, 0, stream,
                             arguments, nullptr),
            "cuLaunchKernel(hybrid_add)");
}

void prefetchManaged(Api &api, CUdeviceptr pointer, std::size_t bytes,
                     CUmemLocation destination, CUdevice legacyDestination,
                     CUstream stream,
                     const std::string &operation) {
  const CUresult status = api.managedMemoryPrefetchV2
      ? api.managedMemoryPrefetchV2(pointer, bytes, destination, 0, stream)
      : api.managedMemoryPrefetchLegacy(pointer, bytes, legacyDestination, stream);
  api.check(status, operation);
}

bool verifyResult(const int *a, const int *b, const int *output,
                  unsigned int count);
bool verifyExpectedResult(const int *expected, const int *output,
                          unsigned int count);

void runCudaGraphs(Api &api, CUfunction function, CUdeviceptr deviceA,
                   CUdeviceptr deviceB, CUdeviceptr deviceOutput,
                   int *hostA, int *hostB, int *hostOutput,
                   unsigned int count, std::size_t bytes,
                   const DeviceInfo &device, bool managedMemory,
                   bool managedPrefetch, CUstream stream,
                   DeviceResult &result) {
  api.enableCudaGraphs();
  std::vector<int> expected(count);
  for (unsigned int i = 0; i < count; ++i)
    expected[i] = hostA[i] + hostB[i];

  if (managedMemory) {
    if (managedPrefetch) {
      const CUmemLocation gpu{CU_MEM_LOCATION_TYPE_DEVICE, device.handle};
      prefetchManaged(api, deviceA, bytes, gpu, device.handle, stream,
                      "cuMemPrefetchAsync(graph input A to GPU)");
      prefetchManaged(api, deviceB, bytes, gpu, device.handle, stream,
                      "cuMemPrefetchAsync(graph input B to GPU)");
    }
  } else {
    api.check(api.copyHostToDevice(deviceA, hostA, bytes),
              "cuMemcpyHtoD_v2(graph input A)");
    api.check(api.copyHostToDevice(deviceB, hostB, bytes),
              "cuMemcpyHtoD_v2(graph input B)");
  }

  GraphGuard graph(api, result, stream);
  CUdeviceptr parameterA = deviceA;
  CUdeviceptr parameterB = deviceB;
  CUdeviceptr parameterOutput = deviceOutput;
  unsigned int parameterCount = count;
  void *kernelParameters[] = {
      &parameterA, &parameterB, &parameterOutput, &parameterCount};
  CUDA_KERNEL_NODE_PARAMS nodeParameters{};
  nodeParameters.func = function;
  nodeParameters.gridDimX = (count + 255U) / 256U;
  nodeParameters.gridDimY = 1;
  nodeParameters.gridDimZ = 1;
  nodeParameters.blockDimX = 256;
  nodeParameters.blockDimY = 1;
  nodeParameters.blockDimZ = 1;
  nodeParameters.kernelParams = kernelParameters;
  CUgraphNode node{};
  api.check(api.graphAddKernelNode(&node, graph.graph, nullptr, 0,
                                   &nodeParameters),
            "cuGraphAddKernelNode");
  api.check(api.graphInstantiate(&graph.executable, graph.graph, 0),
            "cuGraphInstantiateWithFlags");
  for (unsigned int replay = 0; replay < 2; ++replay) {
    if (managedPrefetch) {
      prefetchManaged(api, deviceOutput, bytes,
                      CUmemLocation{CU_MEM_LOCATION_TYPE_DEVICE, device.handle},
                      device.handle, stream,
                      "cuMemPrefetchAsync(graph output to GPU)");
    }
    api.check(api.graphLaunch(graph.executable, stream), "cuGraphLaunch");
    ++result.cudaGraphLaunches;
    api.check(api.streamSynchronize(stream),
              "cuStreamSynchronize(cuda graph replay)");
    if (managedPrefetch) {
      prefetchManaged(api, deviceOutput, bytes,
                      CUmemLocation{CU_MEM_LOCATION_TYPE_HOST, 0}, CU_DEVICE_CPU,
                      stream, "cuMemPrefetchAsync(graph output to CPU)");
      api.check(api.streamSynchronize(stream),
                "cuStreamSynchronize(cuda graph CPU prefetch)");
    } else if (!managedMemory) {
      api.check(api.copyDeviceToHost(hostOutput, deviceOutput, bytes),
                "cuMemcpyDtoH_v2(cuda graph output)");
    }
    if (!verifyExpectedResult(expected.data(), hostOutput, count))
      throw CudaError("CUDA Graph numeric result mismatch at replay " +
                      std::to_string(replay + 1) + " of 2, count " +
                      std::to_string(count));
  }
  result.cudaGraphsPassed = true;
}

bool verifyResult(const int *a, const int *b, const int *output,
                  unsigned int count) {
  for (unsigned int i = 0; i < count; ++i) {
    if (output[i] != a[i] + b[i]) return false;
  }
  return true;
}

bool verifyExpectedResult(const int *expected, const int *output,
                          unsigned int count) {
  for (unsigned int i = 0; i < count; ++i) {
    if (output[i] != expected[i]) return false;
  }
  return true;
}

void runDevice(Api &api, ContextGuard &context, const DeviceInfo &device,
               const std::string &modulePath, bool managedMemory,
               bool managedPrefetch, bool cudaGraphs,
               DeviceResult &result) {
  result.device = device;
  result.targeted = true;
  result.tested = true;
  api.check(api.contextSetCurrent(context.context), "cuCtxSetCurrent(execution)");
  ModuleGuard module(api, modulePath, result);
  CUfunction archFunction{};
  CUfunction addFunction{};
  api.check(api.moduleGetFunction(&archFunction, module.module, "hybrid_arch"),
            "cuModuleGetFunction(hybrid_arch)");
  api.check(api.moduleGetFunction(&addFunction, module.module, "hybrid_add"),
            "cuModuleGetFunction(hybrid_add)");
  if (managedPrefetch) api.enableManagedPrefetch();

  constexpr unsigned int maximumCount = 65537;
  constexpr unsigned int sizes[] = {1, 31, 256, 4096, 65537};
  const std::size_t bytes = maximumCount * sizeof(int);
  BufferGuard deviceA(api, bytes, result, managedMemory);
  BufferGuard deviceB(api, bytes, result, managedMemory);
  BufferGuard deviceOutput(api, bytes, result, managedMemory);
  std::unique_ptr<HostGuard> hostMemory;
  if (!managedMemory)
    hostMemory = std::make_unique<HostGuard>(api, bytes * 3, result);
  StreamGuard stream(api, result);
  int *hostA = managedMemory
                   ? reinterpret_cast<int *>(static_cast<std::uintptr_t>(deviceA.pointer))
                   : static_cast<int *>(hostMemory->pointer);
  int *hostB = managedMemory
                   ? reinterpret_cast<int *>(static_cast<std::uintptr_t>(deviceB.pointer))
                   : hostA + maximumCount;
  int *hostOutput = managedMemory
                        ? reinterpret_cast<int *>(static_cast<std::uintptr_t>(deviceOutput.pointer))
                        : hostB + maximumCount;

  int returnedArch = -1;
  if (managedPrefetch)
    prefetchManaged(api, deviceOutput.pointer, bytes,
                    CUmemLocation{CU_MEM_LOCATION_TYPE_DEVICE, device.handle},
                    device.handle, nullptr,
                    "cuMemPrefetchAsync(architecture to GPU)");
  launchArchKernel(api, archFunction, deviceOutput.pointer);
  api.check(api.contextSynchronize(), "cuCtxSynchronize(architecture kernel)");
  if (managedPrefetch) {
    prefetchManaged(api, deviceOutput.pointer, bytes,
                    CUmemLocation{CU_MEM_LOCATION_TYPE_HOST, 0}, CU_DEVICE_CPU, nullptr,
                    "cuMemPrefetchAsync(architecture to CPU)");
    api.check(api.contextSynchronize(), "cuCtxSynchronize(architecture CPU prefetch)");
  }
  if (managedMemory)
    returnedArch = *hostOutput;
  else
    api.check(api.copyDeviceToHost(&returnedArch, deviceOutput.pointer, sizeof(returnedArch)),
              "cuMemcpyDtoH_v2(architecture)");
  const int expectedArch = device.major * 100 + device.minor * 10;
  if (returnedArch != expectedArch) {
    std::ostringstream message;
    message << "hybrid_arch returned " << returnedArch << ", expected " << expectedArch;
    throw CudaError(message.str());
  }
  result.archPassed = true;

  for (unsigned int i = 0; i < maximumCount; ++i) {
    hostA[i] = static_cast<int>((i * 7U) % 1009U) - 500;
    hostB[i] = static_cast<int>((i * 13U) % 1013U) - 506;
  }

  for (unsigned int count : sizes) {
    if (!managedMemory) {
      api.check(api.copyHostToDevice(deviceA.pointer, hostA, count * sizeof(int)),
                "cuMemcpyHtoD_v2(input A)");
      api.check(api.copyHostToDevice(deviceB.pointer, hostB, count * sizeof(int)),
                "cuMemcpyHtoD_v2(input B)");
    } else if (managedPrefetch) {
      const std::size_t rangeBytes = count * sizeof(int);
      prefetchManaged(api, deviceA.pointer, rangeBytes,
                      CUmemLocation{CU_MEM_LOCATION_TYPE_DEVICE, device.handle},
                      device.handle, nullptr,
                      "cuMemPrefetchAsync(sync input A to GPU)");
      prefetchManaged(api, deviceB.pointer, rangeBytes,
                      CUmemLocation{CU_MEM_LOCATION_TYPE_DEVICE, device.handle},
                      device.handle, nullptr,
                      "cuMemPrefetchAsync(sync input B to GPU)");
      prefetchManaged(api, deviceOutput.pointer, rangeBytes,
                      CUmemLocation{CU_MEM_LOCATION_TYPE_DEVICE, device.handle},
                      device.handle, nullptr,
                      "cuMemPrefetchAsync(sync output to GPU)");
    }
    launchAddKernel(api, addFunction, deviceA.pointer, deviceB.pointer,
                    deviceOutput.pointer, count, nullptr);
    api.check(api.contextSynchronize(), "cuCtxSynchronize(synchronous kernel)");
    if (managedPrefetch) {
      prefetchManaged(api, deviceOutput.pointer, count * sizeof(int),
                      CUmemLocation{CU_MEM_LOCATION_TYPE_HOST, 0}, CU_DEVICE_CPU,
                      nullptr, "cuMemPrefetchAsync(sync output to CPU)");
      api.check(api.contextSynchronize(), "cuCtxSynchronize(sync CPU prefetch)");
    }
    if (!managedMemory)
      api.check(api.copyDeviceToHost(hostOutput, deviceOutput.pointer,
                                     count * sizeof(int)),
                "cuMemcpyDtoH_v2(output)");
    if (!verifyResult(hostA, hostB, hostOutput, count)) {
      throw CudaError("synchronous numeric result mismatch at count " +
                      std::to_string(count));
    }
    result.syncSizes.push_back(count);
  }
  result.syncPassed = true;

  for (unsigned int count : sizes) {
    if (!managedMemory) {
      api.check(api.copyHostToDeviceAsync(deviceA.pointer, hostA,
                                          count * sizeof(int), stream.stream),
                "cuMemcpyHtoDAsync_v2(input A)");
      api.check(api.copyHostToDeviceAsync(deviceB.pointer, hostB,
                                          count * sizeof(int), stream.stream),
                "cuMemcpyHtoDAsync_v2(input B)");
    } else if (managedPrefetch) {
      const std::size_t rangeBytes = count * sizeof(int);
      prefetchManaged(api, deviceA.pointer, rangeBytes,
                      CUmemLocation{CU_MEM_LOCATION_TYPE_DEVICE, device.handle},
                      device.handle, stream.stream,
                      "cuMemPrefetchAsync(async input A to GPU)");
      prefetchManaged(api, deviceB.pointer, rangeBytes,
                      CUmemLocation{CU_MEM_LOCATION_TYPE_DEVICE, device.handle},
                      device.handle, stream.stream,
                      "cuMemPrefetchAsync(async input B to GPU)");
      prefetchManaged(api, deviceOutput.pointer, rangeBytes,
                      CUmemLocation{CU_MEM_LOCATION_TYPE_DEVICE, device.handle},
                      device.handle, stream.stream,
                      "cuMemPrefetchAsync(async output to GPU)");
    }
    launchAddKernel(api, addFunction, deviceA.pointer, deviceB.pointer,
                    deviceOutput.pointer, count, stream.stream);
    if (!managedMemory)
      api.check(api.copyDeviceToHostAsync(hostOutput, deviceOutput.pointer,
                                          count * sizeof(int), stream.stream),
                "cuMemcpyDtoHAsync_v2(output)");
    api.check(api.streamSynchronize(stream.stream),
              "cuStreamSynchronize(asynchronous test)");
    if (managedPrefetch) {
      prefetchManaged(api, deviceOutput.pointer, count * sizeof(int),
                      CUmemLocation{CU_MEM_LOCATION_TYPE_HOST, 0}, CU_DEVICE_CPU,
                      stream.stream, "cuMemPrefetchAsync(async output to CPU)");
      api.check(api.streamSynchronize(stream.stream),
                "cuStreamSynchronize(async CPU prefetch)");
    }
    if (!verifyResult(hostA, hostB, hostOutput, count)) {
      throw CudaError("asynchronous numeric result mismatch at count " +
                      std::to_string(count));
    }
    result.asyncSizes.push_back(count);
  }
  result.asyncPassed = true;
  if (cudaGraphs) {
    constexpr unsigned int graphCount = 256;
    runCudaGraphs(api, addFunction, deviceA.pointer, deviceB.pointer,
                  deviceOutput.pointer, hostA, hostB, hostOutput,
                  graphCount, graphCount * sizeof(int), device,
                  managedMemory, managedPrefetch, stream.stream, result);
  }
  result.managedMemoryPassed = managedMemory;
  result.managedPrefetchPassed = managedPrefetch;
}

struct PhaseOutcome {
  std::vector<std::string> operations;
  DeviceInfo device;
  bool deviceValidated = false;
  DeviceResult cleanup;
  int driverVersion = 0;
  int resultValue = 0;
  int expectedValue = 0;
  bool numericResultPassed = false;
  std::string error;
};

void printPhaseReport(const Api &api, const Options &options,
                      const PhaseOutcome &outcome, const char *status) {
  std::cout << "{\"schema\":\"nvidia-cuda-driver-phase-v1\",\"status\":\""
            << status << "\",\"phase\":\"" << jsonEscape(options.phase)
            << "\",\"expected_pci\":\"" << jsonEscape(options.expectedPci)
            << "\",\"driver_library_path\":\"" << jsonEscape(api.libraryPath)
            << "\",\"driver_api\":";
  if (outcome.driverVersion > 0) std::cout << outcome.driverVersion;
  else std::cout << "null";
  std::cout << ",\"selected_device\":";
  if (!outcome.deviceValidated) {
    std::cout << "null";
  } else {
    std::cout << "{\"name\":\"" << jsonEscape(outcome.device.name)
              << "\",\"pci_bus_id\":\"" << jsonEscape(outcome.device.pci)
              << "\",\"sm\":" << outcome.device.sm
              << ",\"compute_capability\":\"" << outcome.device.major << '.'
              << outcome.device.minor << "\",\"concurrent_managed_access\":"
              << (outcome.device.concurrentManagedAccess ? "true" : "false")
              << ",\"pageable_memory_access\":"
              << (outcome.device.pageableMemoryAccess ? "true" : "false")
              << ",\"pageable_memory_access_uses_host_page_tables\":"
              << (outcome.device.pageableMemoryAccessUsesHostPageTables ? "true" : "false")
              << "}";
  }
  std::cout << ",\"completed_operations\":[";
  for (std::size_t i = 0; i < outcome.operations.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << '"' << jsonEscape(outcome.operations[i]) << '"';
  }
  std::cout << "],\"numeric_result_passed\":"
            << (outcome.numericResultPassed ? "true" : "false")
            << ",\"result_value\":";
  if (outcome.numericResultPassed) std::cout << outcome.resultValue;
  else std::cout << "null";
  std::cout << ",\"expected_result\":";
  if (outcome.numericResultPassed) std::cout << outcome.expectedValue;
  else std::cout << "null";
  std::cout << ",\"cleanup_passed\":"
            << (outcome.cleanup.cleanupPassed ? "true" : "false")
            << ",\"cleanup_errors\":[";
  for (std::size_t i = 0; i < outcome.cleanup.cleanupErrors.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << '"' << jsonEscape(outcome.cleanup.cleanupErrors[i]) << '"';
  }
  std::cout << "],\"error\":\"" << jsonEscape(outcome.error) << "\"}\n";
}

struct SystemAllocatorResult {
  bool tested = false;
  bool passed = false;
  std::string executionMode;
  std::vector<unsigned int> sizes;
};

struct SystemPageableOutcome {
  DeviceInfo device;
  bool deviceValidated = false;
  bool unifiedAddressing = false;
  DeviceResult cleanup;
  int driverVersion = 0;
  SystemAllocatorResult malloc;
  SystemAllocatorResult mmap;
  std::string error;
};

struct SystemPageableBuffer {
  void *base = nullptr;
  std::size_t bytes = 0;
  bool mapped = false;
  DeviceResult &cleanup;

  SystemPageableBuffer(std::size_t length, bool useMmap, DeviceResult &result)
      : bytes(length), mapped(useMmap), cleanup(result) {
    if (mapped) {
      base = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (base == MAP_FAILED) {
        base = nullptr;
        throw CudaError(std::string("mmap(system pageable) failed: ") +
                        std::strerror(errno));
      }
    } else {
      base = std::malloc(bytes);
      if (!base) throw CudaError("malloc(system pageable) failed");
    }
  }

  ~SystemPageableBuffer() {
    if (!base) return;
    if (!mapped) {
      std::free(base);
      return;
    }
    if (::munmap(base, bytes) != 0) {
      cleanup.cleanupPassed = false;
      try {
        cleanup.cleanupErrors.emplace_back(
            std::string("munmap(system pageable): ") + std::strerror(errno));
      } catch (...) {}
    }
  }

  SystemPageableBuffer(const SystemPageableBuffer &) = delete;
  SystemPageableBuffer &operator=(const SystemPageableBuffer &) = delete;
};

void printSizes(const std::vector<unsigned int> &sizes);

CUdeviceptr pageableDevicePointer(const int *pointer) {
  return static_cast<CUdeviceptr>(reinterpret_cast<std::uintptr_t>(pointer));
}

void runSystemPageableAllocator(Api &api, CUfunction function,
                                CUstream stream, bool contextSync,
                                SystemPageableBuffer &memory,
                                SystemAllocatorResult &result) {
  constexpr unsigned int maximumCount = 65537;
  constexpr unsigned int sizes[] = {1, 31, 256, 4096, 65537};
  constexpr std::size_t bytes = maximumCount * sizeof(int);
  auto *hostA = static_cast<int *>(memory.base);
  auto *hostB = hostA + maximumCount;
  auto *hostOutput = hostB + maximumCount;
  for (unsigned int i = 0; i < maximumCount; ++i) {
    hostA[i] = static_cast<int>((i * 7U) % 1009U) - 500;
    hostB[i] = static_cast<int>((i * 13U) % 1013U) - 506;
    hostOutput[i] = 0;
  }

  result.tested = true;
  result.executionMode = contextSync ? "context-synchronized" : "stream-synchronized";
  for (unsigned int count : sizes) {
    launchAddKernel(api, function, pageableDevicePointer(hostA),
                    pageableDevicePointer(hostB),
                    pageableDevicePointer(hostOutput), count, stream);
    if (contextSync)
      api.check(api.contextSynchronize(), "cuCtxSynchronize(system pageable kernel)");
    else
      api.check(api.streamSynchronize(stream),
                "cuStreamSynchronize(system pageable kernel)");
    if (!verifyResult(hostA, hostB, hostOutput, count))
      throw CudaError("system-pageable numerical result mismatch at count " +
                      std::to_string(count));
    result.sizes.push_back(count);
  }
  result.passed = true;
}

void printSystemPageableReport(const Api &api, const Options &options,
                              const SystemPageableOutcome &outcome,
                              const char *status) {
  std::cout << "{\"schema\":\"nvidia-cuda-system-pageable-memory-v1\",\"status\":\""
            << status << "\",\"phase\":\"system-pageable-memory\",\"expected_pci\":\""
            << jsonEscape(options.expectedPci) << "\",\"driver_library_path\":\""
            << jsonEscape(api.libraryPath) << "\",\"driver_api\":"
            << outcome.driverVersion << ",\"selected_device\":";
  if (!outcome.deviceValidated) {
    std::cout << "null";
  } else {
    const DeviceInfo &device = outcome.device;
    std::cout << "{\"name\":\"" << jsonEscape(device.name)
              << "\",\"pci_bus_id\":\"" << jsonEscape(device.pci)
              << "\",\"sm\":" << device.sm
              << ",\"compute_capability\":\"" << device.major << '.' << device.minor
              << "\",\"concurrent_managed_access\":"
              << (device.concurrentManagedAccess ? "true" : "false")
              << ",\"pageable_memory_access\":"
              << (device.pageableMemoryAccess ? "true" : "false")
              << ",\"pageable_memory_access_uses_host_page_tables\":"
              << (device.pageableMemoryAccessUsesHostPageTables ? "true" : "false")
              << ",\"unified_addressing\":"
              << (outcome.unifiedAddressing ? "true" : "false") << "}";
  }
  auto printAllocator = [](const SystemAllocatorResult &result) {
    std::cout << "{\"tested\":" << (result.tested ? "true" : "false")
              << ",\"passed\":" << (result.passed ? "true" : "false")
              << ",\"execution_mode\":\"" << jsonEscape(result.executionMode)
              << "\",\"sizes\":";
    printSizes(result.sizes);
    std::cout << "}";
  };
  std::cout << ",\"allocators\":{\"malloc\":";
  if (std::string(status) == "unsupported") std::cout << "null";
  else printAllocator(outcome.malloc);
  std::cout << ",\"mmap\":";
  if (std::string(status) == "unsupported") std::cout << "null";
  else printAllocator(outcome.mmap);
  std::cout << "},\"cleanup_passed\":"
            << (outcome.cleanup.cleanupPassed ? "true" : "false")
            << ",\"cleanup_errors\":[";
  for (std::size_t i = 0; i < outcome.cleanup.cleanupErrors.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << '"' << jsonEscape(outcome.cleanup.cleanupErrors[i]) << '"';
  }
  std::cout << "],\"error\":\"" << jsonEscape(outcome.error) << "\"}\n";
}

int runSystemPageableMemoryPhase(Api &api, const Options &options) {
  SystemPageableOutcome outcome;
  const char *status = "failed";
  int exitCode = 2;
  try {
    api.check(api.init(0), "cuInit");
    int driverVersion = 0;
    std::vector<DeviceInfo> devices = enumerateDevices(api, driverVersion);
    outcome.driverVersion = driverVersion;
    if (devices.size() != 1 ||
        canonicalPci(devices.front().pci) != options.expectedPci)
      throw CudaError("pageable-memory selected-GPU guard: expected exactly one device at " +
                      options.expectedPci);
    outcome.device = devices.front();
    outcome.deviceValidated = true;
    int unifiedAddressing = -1;
    api.check(api.deviceGetAttribute(&unifiedAddressing,
                                     CU_DEVICE_ATTRIBUTE_UNIFIED_ADDRESSING,
                                     outcome.device.handle),
              "cuDeviceGetAttribute(unified_addressing)");
    if (unifiedAddressing != 0 && unifiedAddressing != 1)
      throw CudaError("unified addressing attribute is not boolean");
    outcome.unifiedAddressing = unifiedAddressing == 1;
    if (!outcome.device.pageableMemoryAccess || !outcome.unifiedAddressing) {
      outcome.error = !outcome.device.pageableMemoryAccess
          ? "device does not report pageable memory access"
          : "device does not report unified addressing";
      status = "unsupported";
      exitCode = 77;
    } else {
      {
        ContextGuard context(api, outcome.device.handle, outcome.cleanup);
        api.check(api.contextSetCurrent(context.context), "cuCtxSetCurrent(pageable-memory)");
        CUdevice current{};
        api.check(api.contextGetDevice(&current), "cuCtxGetDevice(pageable-memory)");
        if (current != outcome.device.handle)
          throw CudaError("pageable-memory context belongs to a different CUDA device");
        ModuleGuard module(api, options.modulePath, outcome.cleanup);
        CUfunction function{};
        api.check(api.moduleGetFunction(&function, module.module, "hybrid_add"),
                  "cuModuleGetFunction(hybrid_add)");
        constexpr std::size_t allocationBytes = 3U * 65537U * sizeof(int);
        SystemPageableBuffer mallocMemory(allocationBytes, false, outcome.cleanup);
        SystemPageableBuffer mappedMemory(allocationBytes, true, outcome.cleanup);
        StreamGuard stream(api, outcome.cleanup);
        runSystemPageableAllocator(api, function, stream.stream, true,
                                   mallocMemory, outcome.malloc);
        runSystemPageableAllocator(api, function, stream.stream, false,
                                   mappedMemory, outcome.mmap);
      }
      if (!outcome.cleanup.cleanupPassed)
        throw CudaError("pageable-memory phase cleanup failed");
      status = "validated";
      exitCode = 0;
    }
  } catch (const std::exception &error) {
    outcome.error = error.what();
    status = "failed";
    exitCode = 2;
  }
  printSystemPageableReport(api, options, outcome, status);
  return exitCode;
}

int runPhase(Api &api, const Options &options) {
  if (options.phase == "system-pageable-memory")
    return runSystemPageableMemoryPhase(api, options);
  PhaseOutcome outcome;
  const char *status = "phase-passed";
  int exitCode = 0;
  try {
    if (options.phase == "initialize") {
      api.check(api.init(0), "cuInit");
      outcome.operations.emplace_back("cuInit");
    } else {
      int driverVersion = 0;
      std::vector<DeviceInfo> devices = enumerateDevices(api, driverVersion,
                                                         &outcome.operations);
      outcome.driverVersion = driverVersion;
      if (devices.size() != 1 ||
          canonicalPci(devices.front().pci) != options.expectedPci) {
        throw CudaError("phase selected-GPU guard: expected exactly one device at " +
                        options.expectedPci);
      }
      outcome.device = devices.front();
      outcome.deviceValidated = true;
      if (options.phase != "enumerate") {
        {
          ContextGuard context(api, outcome.device.handle, outcome.cleanup);
          outcome.operations.emplace_back("cuCtxCreate_v2");
          api.check(api.contextSetCurrent(context.context), "cuCtxSetCurrent(phase)");
          outcome.operations.emplace_back("cuCtxSetCurrent");
          CUdevice current{};
          api.check(api.contextGetDevice(&current), "cuCtxGetDevice(phase)");
          outcome.operations.emplace_back("cuCtxGetDevice");
          if (current != outcome.device.handle)
            throw CudaError("phase context belongs to a different CUDA device");

          if (options.phase == "allocation") {
            {
              BufferGuard buffer(api, 4096, outcome.cleanup, false);
              outcome.operations.emplace_back("cuMemAlloc_v2");
            }
          } else if (options.phase == "module" || options.phase == "kernel") {
            {
              ModuleGuard module(api, options.modulePath, outcome.cleanup);
              outcome.operations.emplace_back("cuModuleLoad");
              CUfunction function{};
              api.check(api.moduleGetFunction(&function, module.module, "hybrid_arch"),
                        "cuModuleGetFunction(hybrid_arch)");
              outcome.operations.emplace_back("cuModuleGetFunction(hybrid_arch)");
              if (options.phase == "kernel") {
                {
                  BufferGuard output(api, sizeof(int), outcome.cleanup, false);
                  outcome.operations.emplace_back("cuMemAlloc_v2");
                  launchArchKernel(api, function, output.pointer);
                  outcome.operations.emplace_back("cuLaunchKernel(hybrid_arch)");
                  api.check(api.contextSynchronize(), "cuCtxSynchronize(phase kernel)");
                  outcome.operations.emplace_back("cuCtxSynchronize");
                  api.check(api.copyDeviceToHost(&outcome.resultValue, output.pointer,
                                                 sizeof(outcome.resultValue)),
                            "cuMemcpyDtoH_v2(phase result)");
                  outcome.operations.emplace_back("cuMemcpyDtoH_v2");
                  outcome.expectedValue = outcome.device.major * 100 + outcome.device.minor * 10;
                  outcome.numericResultPassed = outcome.resultValue == outcome.expectedValue;
                  if (!outcome.numericResultPassed)
                    throw CudaError("architecture kernel returned an unexpected value");
                }
              }
            }
          }
        }
      }
      if (!outcome.cleanup.cleanupPassed)
        throw CudaError("phase cleanup failed");
    }
  } catch (const std::exception &error) {
    status = "phase-failed";
    outcome.error = error.what();
    exitCode = 2;
  }
  printPhaseReport(api, options, outcome, status);
  return exitCode;
}

void printSizes(const std::vector<unsigned int> &sizes) {
  std::cout << '[';
  for (std::size_t i = 0; i < sizes.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << sizes[i];
  }
  std::cout << ']';
}

void printReport(const std::string &status, bool requiredSetPassed,
                 bool hybridValidated, bool contextCoexistence,
                 bool managedMemory,
                 bool managedPrefetch,
                 const std::string &managedPrefetchApi,
                 bool cudaGraphs, const std::string &cudaGraphsApi,
                 const std::string &driverLibrary,
                 int driverVersion, const std::set<int> &required,
                 const std::vector<int> &missing,
                 const std::vector<DeviceResult> &devices) {
  std::cout << "{\"schema\":\"nvidia-hybrid-probe-v2\",\"status\":\""
            << jsonEscape(status) << "\",\"hybrid_validated\":"
            << (hybridValidated ? "true" : "false")
            << ",\"required_set_passed\":"
            << (requiredSetPassed ? "true" : "false")
            << ",\"context_coexistence_passed\":" << (contextCoexistence ? "true" : "false")
            << ",\"memory_mode\":\"" << (managedMemory ? "managed" : "device") << '"'
            << ",\"managed_prefetch_requested\":"
            << (managedPrefetch ? "true" : "false")
            << ",\"managed_prefetch_api\":\""
            << jsonEscape(managedPrefetchApi) << '\"'
            << ",\"cuda_graphs_requested\":" << (cudaGraphs ? "true" : "false")
            << ",\"cuda_graph_api\":\"" << jsonEscape(cudaGraphsApi) << '\"'
            << ",\"execution_mode\":\"resident-contexts-sequential-kernels\""
            << ",\"concurrent_kernel_execution_validated\":false"
            << ",\"driver_library_path\":\"" << jsonEscape(driverLibrary) << '"'
            << ",\"driver_api\":" << driverVersion << ",\"required_sm\":[";
  bool first = true;
  for (int sm : required) {
    if (!first) std::cout << ',';
    first = false;
    std::cout << sm;
  }
  std::cout << "],\"missing_sm\":[";
  for (std::size_t i = 0; i < missing.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << missing[i];
  }
  std::cout << "],\"devices\":[";
  for (std::size_t i = 0; i < devices.size(); ++i) {
    if (i) std::cout << ',';
    const DeviceResult &result = devices[i];
    const DeviceInfo &device = result.device;
    std::cout << "{\"ordinal\":" << device.ordinal
              << ",\"name\":\"" << jsonEscape(device.name)
              << "\",\"pci_bus_id\":\"" << jsonEscape(device.pci)
              << "\",\"compute_capability\":\"" << device.major << '.'
              << device.minor << "\",\"sm\":" << device.sm
              << ",\"concurrent_managed_access\":"
              << (device.concurrentManagedAccess ? "true" : "false")
              << ",\"pageable_memory_access\":"
              << (device.pageableMemoryAccess ? "true" : "false")
              << ",\"pageable_memory_access_uses_host_page_tables\":"
              << (device.pageableMemoryAccessUsesHostPageTables ? "true" : "false")
              << ",\"targeted\":" << (result.targeted ? "true" : "false")
              << ",\"tested\":" << (result.tested ? "true" : "false")
              << ",\"architecture_kernel_passed\":"
              << (result.archPassed ? "true" : "false")
              << ",\"synchronous_passed\":"
              << (result.syncPassed ? "true" : "false")
              << ",\"synchronous_sizes\":";
    printSizes(result.syncSizes);
    std::cout << ",\"asynchronous_passed\":"
              << (result.asyncPassed ? "true" : "false")
              << ",\"managed_memory_passed\":"
              << (result.managedMemoryPassed ? "true" : "false")
              << ",\"managed_prefetch_passed\":"
              << (result.managedPrefetchPassed ? "true" : "false")
              << ",\"cuda_graphs_passed\":"
              << (result.cudaGraphsPassed ? "true" : "false")
              << ",\"cuda_graph_launches\":" << result.cudaGraphLaunches
              << ",\"asynchronous_sizes\":";
    printSizes(result.asyncSizes);
    std::cout << ",\"cleanup_passed\":" << (result.cleanupPassed ? "true" : "false")
              << ",\"cleanup_errors\":[";
    for (std::size_t j = 0; j < result.cleanupErrors.size(); ++j) {
      if (j) std::cout << ',';
      std::cout << '"' << jsonEscape(result.cleanupErrors[j]) << '"';
    }
    std::cout << "],\"error\":\"" << jsonEscape(result.error) << "\"}";
  }
  std::cout << "]}\n";
}

}  // namespace

int main(int argc, char **argv) {
  Options options;
  try {
    options = parseOptions(argc, argv);
  } catch (const UsageError &error) {
    printUsage(std::cerr, argv[0]);
    std::cerr << "error: " << error.what() << '\n';
    return 64;
  }

  if (options.contractOnly) {
    printProbeContract();
    return 0;
  }

  try {
    Api api;
    if (!options.phase.empty()) return runPhase(api, options);
    int driverVersion = 0;
    const std::vector<DeviceInfo> inventory = enumerateDevices(api, driverVersion);
    if (!options.expectedPci.empty() &&
        (inventory.size() != 1 || canonicalPci(inventory.front().pci) != options.expectedPci)) {
      throw CudaError("selected GPU guard: expected exactly one visible GPU at " + options.expectedPci);
    }
    std::vector<DeviceResult> results(inventory.size());
    std::vector<std::unique_ptr<ContextGuard>> contexts(inventory.size());
    bool anyFailure = false;
    bool contextCoexistence = false;
    std::set<int> presentSm;
    std::set<int> foundSm;
    std::set<CUcontext> distinctContexts;
    for (std::size_t i = 0; i < inventory.size(); ++i) {
      const DeviceInfo &device = inventory[i];
      presentSm.insert(device.sm);
      DeviceResult &result = results[i];
      result.device = device;
      result.targeted = !options.listOnly && options.requiredSm.count(device.sm) > 0;
      if (result.targeted) {
        result.tested = true;
        try {
          contexts[i] = std::make_unique<ContextGuard>(api, device.handle, result);
          if (!distinctContexts.insert(contexts[i]->context).second) {
            contexts[i]->context = nullptr; // Do not destroy another owner's context twice.
            throw CudaError("cuCtxCreate_v2 returned a duplicate context handle");
          }
        } catch (const std::exception &error) {
          result.error = error.what();
          anyFailure = true;
        }
      }
    }

    // All targeted contexts remain alive while every device is exercised.
    // Round trips detect a backend that invalidates an older context when a
    // second architecture is initialized. Kernel submissions are sequential.
    std::set<int> residentSm;
    for (std::size_t i = 0; i < contexts.size(); ++i) {
      if (!contexts[i] || !results[i].error.empty()) continue;
      try {
        api.check(api.contextSetCurrent(contexts[i]->context), "cuCtxSetCurrent(residency)");
        CUdevice current{};
        api.check(api.contextGetDevice(&current), "cuCtxGetDevice(residency)");
        if (current != inventory[i].handle)
          throw CudaError("current context does not own the expected CUDA device");
        residentSm.insert(inventory[i].sm);
      } catch (const std::exception &error) {
        results[i].error = error.what();
        anyFailure = true;
      }
    }
    contextCoexistence = !anyFailure && residentSm.count(70) && residentSm.count(120);
    for (std::size_t i = 0; i < contexts.size(); ++i) {
      if (!contexts[i] || !results[i].error.empty()) continue;
      try {
        runDevice(api, *contexts[i], inventory[i], options.modulePath,
                  options.managedMemory, options.managedPrefetch,
                  options.cudaGraphs, results[i]);
      } catch (const std::exception &error) {
        results[i].error = error.what();
      }
    }
    // Close explicitly before serializing, so destructor errors affect the gate.
    for (auto &context : contexts) context.reset();
    for (const DeviceResult &result : results) {
      if (!result.targeted) continue;
      if (!result.error.empty() || !result.cleanupPassed || !result.archPassed ||
          !result.syncPassed || !result.asyncPassed ||
          (options.cudaGraphs && !result.cudaGraphsPassed)) anyFailure = true;
      else foundSm.insert(result.device.sm);
    }

    std::vector<int> missing;
    if (!options.listOnly) {
      for (int sm : options.requiredSm) {
        if (!presentSm.count(sm)) missing.push_back(sm);
      }
    }

    if (options.listOnly) {
      printReport("inventory", false, false, false, options.managedMemory, options.managedPrefetch,
                  api.managedMemoryPrefetchApi,
                  options.cudaGraphs, api.cudaGraphsApi,
                  api.libraryPath, driverVersion, options.requiredSm,
                  {}, results);
      return 0;
    }
    if (anyFailure) {
      printReport("failed", false, false, contextCoexistence, options.managedMemory, options.managedPrefetch,
                  api.managedMemoryPrefetchApi,
                  options.cudaGraphs, api.cudaGraphsApi,
                  api.libraryPath, driverVersion, options.requiredSm,
                  missing, results);
      return 2;
    }
    if (!missing.empty()) {
      printReport("incomplete", false, false, contextCoexistence, options.managedMemory, options.managedPrefetch,
                  api.managedMemoryPrefetchApi,
                  options.cudaGraphs, api.cudaGraphsApi,
                  api.libraryPath, driverVersion, options.requiredSm,
                  missing, results);
      return 77;
    }
    const bool requiredSetPassed = std::all_of(
        options.requiredSm.begin(), options.requiredSm.end(),
        [&foundSm](int sm) { return foundSm.count(sm) > 0; });
    const bool hybridValidated = requiredSetPassed &&
                                 options.requiredSm.count(70) > 0 &&
                                 options.requiredSm.count(120) > 0 && contextCoexistence;
    printReport(hybridValidated ? "hybrid-validated" : "control-passed",
                requiredSetPassed, hybridValidated, contextCoexistence, options.managedMemory, options.managedPrefetch,
                api.managedMemoryPrefetchApi,
                options.cudaGraphs, api.cudaGraphsApi,
                api.libraryPath, driverVersion,
                options.requiredSm, {}, results);
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "fatal: " << error.what() << '\n';
    return 2;
  }
}
