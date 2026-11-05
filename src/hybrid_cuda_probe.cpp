// SPDX-License-Identifier: MIT
#include <cuda.h>

#include <dlfcn.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace {

struct UsageError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

struct CudaError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

using CtxCreateV2 = CUresult(CUDAAPI *)(CUcontext *, unsigned int, CUdevice);
using MemAdviseV2 = decltype(&cuMemAdvise_v2);
using MemPrefetchAsyncLegacy = CUresult(CUDAAPI *)(CUdeviceptr, std::size_t, CUdevice, CUstream);
using MemPrefetchAsyncV2 = CUresult(CUDAAPI *)(CUdeviceptr, std::size_t, CUmemLocation,
                                               unsigned int, CUstream);
using EventCreate = CUresult(CUDAAPI *)(CUevent *, unsigned int);
using EventDestroy = CUresult(CUDAAPI *)(CUevent);
using EventRecord = CUresult(CUDAAPI *)(CUevent, CUstream);
using EventSynchronize = CUresult(CUDAAPI *)(CUevent);
using EventElapsedTime = CUresult(CUDAAPI *)(float *, CUevent, CUevent);

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
  MemAdviseV2 managedMemoryAdvise = nullptr;
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
  decltype(&cuDeviceCanAccessPeer) deviceCanAccessPeer = nullptr;
  decltype(&cuCtxEnablePeerAccess) contextEnablePeerAccess = nullptr;
  decltype(&cuCtxDisablePeerAccess) contextDisablePeerAccess = nullptr;
  decltype(&cuMemcpyPeer) copyPeer = nullptr;
  decltype(&cuMemcpyPeerAsync) copyPeerAsync = nullptr;
  bool peerTransferApiAvailable = false;
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
  EventCreate eventCreate = nullptr;
  EventDestroy eventDestroy = nullptr;
  EventRecord eventRecord = nullptr;
  EventSynchronize eventSynchronize = nullptr;
  EventElapsedTime eventElapsedTime = nullptr;
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

  void enableManagedMemoryAdvice() {
    if (!managedMemoryAdvise)
      managedMemoryAdvise = symbol<MemAdviseV2>("cuMemAdvise_v2");
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

  void enablePerformanceTiming() {
    if (eventCreate) return;
    eventCreate = symbol<EventCreate>("cuEventCreate");
    eventDestroy = symbol<EventDestroy>("cuEventDestroy_v2");
    eventRecord = symbol<EventRecord>("cuEventRecord");
    eventSynchronize = symbol<EventSynchronize>("cuEventSynchronize");
    eventElapsedTime = symbol<EventElapsedTime>("cuEventElapsedTime");
  }

  void enablePeerTransfer() noexcept {
    if (peerTransferApiAvailable) return;
    try {
      deviceCanAccessPeer = symbol<decltype(deviceCanAccessPeer)>("cuDeviceCanAccessPeer");
      contextEnablePeerAccess = symbol<decltype(contextEnablePeerAccess)>("cuCtxEnablePeerAccess");
      contextDisablePeerAccess = symbol<decltype(contextDisablePeerAccess)>("cuCtxDisablePeerAccess");
      copyPeer = symbol<decltype(copyPeer)>("cuMemcpyPeer");
      copyPeerAsync = symbol<decltype(copyPeerAsync)>("cuMemcpyPeerAsync");
      peerTransferApiAvailable = true;
    } catch (...) {
      deviceCanAccessPeer = nullptr;
      contextEnablePeerAccess = nullptr;
      contextDisablePeerAccess = nullptr;
      copyPeer = nullptr;
      copyPeerAsync = nullptr;
    }
  }

  explicit Api(const std::string &libraryOverride) {
    const char *libraryName = libraryOverride.empty() ? "libcuda.so.1" : libraryOverride.c_str();
    library = dlopen(libraryName, RTLD_NOW | RTLD_LOCAL);
    if (!library) {
      const char *error = dlerror();
      throw CudaError(std::string("cannot load CUDA driver library ") + libraryName + ": " +
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

struct TimingMetrics {
  std::vector<double> hostApiMicroseconds;
  std::vector<double> deviceElapsedMicroseconds;
};

struct TransferDirectionMetrics {
  std::vector<double> hostApiMicrosecondsPerCopy;
  std::vector<double> deviceElapsedMicrosecondsPerCopy;
  std::vector<double> deviceGigabytesPerSecond;
  bool dataIntegrityPassed = false;
};

struct TransferMetrics {
  std::size_t bytes = 0;
  unsigned int iterationsPerSample = 0;
  TransferDirectionMetrics hToD;
  TransferDirectionMetrics dToH;
  bool dataIntegrityPassed = false;
};

struct PerformanceBenchmark {
  bool passed = false;
  unsigned int samples = 9;
  unsigned int transferSamples = 7;
  unsigned int warmupLaunches = 64;
  unsigned int launchesPerSample = 256;
  TimingMetrics directLaunch;
  TimingMetrics graphLaunch;
  std::vector<TransferMetrics> transfers;
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
  bool performanceBenchmarkPassed = false;
  PerformanceBenchmark performanceBenchmark;
  unsigned int cudaGraphLaunches = 0;
  std::vector<unsigned int> syncSizes;
  std::vector<unsigned int> asyncSizes;
  bool cleanupPassed = true;
  std::vector<std::string> cleanupErrors;
  std::string error;
};

struct ConcurrentDispatchDevice {
  int sm = 0;
  std::string pci;
  std::uint64_t hostWindowStartNs = 0;
  std::uint64_t hostWindowEndNs = 0;
  bool numericResultPassed = false;
  bool launched = false;
};

struct ConcurrentDispatchResult {
  bool passed = false;
  unsigned int rounds = 0;
  std::vector<ConcurrentDispatchDevice> devices;
};

struct PeerTransferDirection {
  int sourceSm = 0;
  int destinationSm = 0;
  bool directAccessEnabled = false;
  bool directKernelAttempted = false;
  bool directKernelPassed = false;
  bool syncCopyPassed = false;
  bool asyncCopyPassed = false;
  bool dataIntegrityPassed = false;
  bool hostStagedSyncCopyPassed = false;
  bool hostStagedAsyncCopyPassed = false;
  bool hostStagedDataIntegrityPassed = false;
};

struct PeerTransferResult {
  bool requested = false;
  bool passed = false;
  bool directPeerAccessEnabled = false;
  bool directDmaAttested = false;
  bool cleanupPassed = true;
  bool hostStagedFallbackPassed = false;
  std::string hostStagedFallbackStatus = "not-attempted";
  std::string status = "not-requested";
  std::string error;
  int sm70CanAccessSm120 = -1;
  int sm120CanAccessSm70 = -1;
  std::string sm70Pci;
  std::string sm120Pci;
  std::size_t bytesPerDirection = 4096;
  std::vector<PeerTransferDirection> directions;
};

struct Options {
  bool contractOnly = false;
  bool listOnly = false;
  bool managedMemory = false;
  bool managedPrefetch = false;
  bool cudaGraphs = false;
  bool performanceBenchmark = false;
  unsigned int benchmarkSamples = 9;
  unsigned int benchmarkTransferSamples = 7;
  bool concurrentKernels = false;
  bool peerTransfer = false;
  bool closeFdsOnExit = false;
  std::string phase;
  std::string modulePath;
  std::string libcudaPath;
  std::set<int> requiredSm{70, 120};
  std::string expectedPci;
  std::map<int, std::string> expectedDevicePciBySm;
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
         << " --module FILE [--require-sm 70,120] [--expected-device SM=PCI ...] [--managed-memory [--managed-prefetch]]\n"
         << "  " << program << " --phase initialize|enumerate|context|allocation|module|kernel|managed-accessed-by|system-pageable-memory "
         << "--expected-pci BDF [--module FILE]\n\n"
         << "  " << program << " --phase kernel --close-fds-on-exit --expected-pci BDF --module FILE\n\n"
         << "  " << program << " --module FILE --benchmark --expected-pci BDF\n\n"
         << "  " << program << " --module FILE --concurrent-kernels --expected-device 70=PCI --expected-device 120=PCI\n\n"
         << "  " << program << " --module FILE --peer-transfer --expected-device 70=PCI --expected-device 120=PCI\n\n"
         << "--list inventories devices through the installed libcuda.so.1.\n"
         << "--module loads one fatbin into a distinct Driver API context per matching GPU.\n"
         << "--libcuda loads one exact CUDA Driver API shared library path instead of the loader default.\n"
         << "--require-sm takes comma-separated compute-capability numbers (7.0 => 70, 12.0 => 120).\n"
         << "--expected-device pins a required SM to one exact PCI ID; supply every required SM for hybrid certification.\n"
         << "--expected-pci BDF requires exactly one visible GPU with that PCI ID before any context is created.\n"
         << "--managed-memory uses cuMemAllocManaged and CPU access after CUDA synchronization instead of explicit copies.\n"
         << "--managed-prefetch requires --managed-memory; it requests cuMemPrefetchAsync to each GPU and back to the CPU before host reads.\n"
         << "--cuda-graphs adds two opt-in CUDA Graph replays of the numeric kernel per targeted device.\n"
         << "--benchmark adds bounded host-launch, CUDA Graph, and pinned-copy timing for one PCI-selected GPU.\n"
         << "--benchmark-samples N selects 9..1001 launch and transfer samples; defaults are 9 launches and 7 transfers.\n"
         << "--concurrent-kernels dispatches bounded work from two host threads; this does not prove GPU timeline overlap.\n"
         << "--peer-transfer checks numeric synchronous/asynchronous peer copies and, when enabled, destination-GPU reads from peer memory; it also verifies explicit pinned-host staging, without attesting physical DMA routing.\n"
         << "--phase runs one bounded Driver API lifecycle phase in a fresh process; it never claims hybrid validation.\n"
         << "--close-fds-on-exit closes descriptors >=3 after the CUDA API object is destroyed; for isolated lifecycle experiments only.\n"
         << "Phases: initialize (cuInit only), enumerate, context, allocation, module, one-result architecture kernel, managed-accessed-by advice lifecycle, and system-pageable-memory.\n"
         << "A missing required architecture returns 77 and keeps hybrid_validated false.\n";
}

void printProbeContract() {
  std::cout
      << R"({"schema":"nvidia-hybrid-probe-contract-v1","contract_version":10,"probe_report_schema":"nvidia-hybrid-probe-v2","probe_report_fields":["expected_device_pci_by_sm","memory_mode","managed_prefetch_requested","managed_prefetch_api","devices","cuda_graphs_requested","cuda_graph_api","performance_benchmark_requested","concurrent_kernel_test_requested","concurrent_kernel_dispatch_passed","concurrent_kernel_dispatch","peer_transfer_requested","peer_transfer"],"peer_transfer_report_schema":"nvidia-hybrid-peer-transfer-v3","peer_transfer_fields":["host_staged_fallback_passed","host_staged_fallback_status"],"peer_transfer_direction_fields":["host_staged_sync_copy_passed","host_staged_async_copy_passed","host_staged_data_integrity_passed"],"device_report_fields":["concurrent_managed_access","pageable_memory_access","pageable_memory_access_uses_host_page_tables","managed_memory_passed","managed_prefetch_passed","cuda_graphs_passed","cuda_graph_launches","performance_benchmark_passed","performance_benchmark"]})"
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
  bool gotBenchmark = false;
  bool gotBenchmarkSamples = false;
  bool gotConcurrentKernels = false;
  bool gotCloseFdsOnExit = false;
  bool gotLibcudaPath = false;
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
    } else if (arg == "--benchmark") {
      if (gotBenchmark) throw UsageError("--benchmark may be supplied only once");
      options.performanceBenchmark = true;
      gotBenchmark = true;
    } else if (arg == "--benchmark-samples" && i + 1 < argc) {
      if (gotBenchmarkSamples)
        throw UsageError("--benchmark-samples may be supplied only once");
      const char *text = argv[++i];
      char *end = nullptr;
      errno = 0;
      const unsigned long value = std::strtoul(text, &end, 10);
      if (text[0] < '0' || text[0] > '9' || errno != 0 || end == text ||
          *end != '\0' || value < 9 || value > 1001)
        throw UsageError("--benchmark-samples must be an integer from 9 through 1001");
      options.benchmarkSamples = static_cast<unsigned int>(value);
      options.benchmarkTransferSamples = static_cast<unsigned int>(value);
      gotBenchmarkSamples = true;
    } else if (arg == "--concurrent-kernels") {
      if (gotConcurrentKernels)
        throw UsageError("--concurrent-kernels may be supplied only once");
      options.concurrentKernels = true;
      gotConcurrentKernels = true;
    } else if (arg == "--peer-transfer") {
      if (options.peerTransfer) throw UsageError("--peer-transfer may be supplied only once");
      options.peerTransfer = true;
    } else if (arg == "--close-fds-on-exit") {
      if (gotCloseFdsOnExit)
        throw UsageError("--close-fds-on-exit may be supplied only once");
      options.closeFdsOnExit = true;
      gotCloseFdsOnExit = true;
    } else if (arg == "--phase" && i + 1 < argc) {
      if (gotPhase) throw UsageError("--phase may be supplied only once");
      options.phase = argv[++i];
      gotPhase = true;
    } else if (arg == "--module" && i + 1 < argc) {
      options.modulePath = argv[++i];
    } else if (arg == "--libcuda" && i + 1 < argc) {
      if (gotLibcudaPath) throw UsageError("--libcuda may be supplied only once");
      options.libcudaPath = argv[++i];
      gotLibcudaPath = true;
    } else if (arg == "--require-sm" && i + 1 < argc) {
      if (parseSmList(argv[++i], options.requiredSm) != 0)
        throw UsageError("--require-sm must be a non-empty comma-separated list of numeric SM values");
      gotRequiredSm = true;
    } else if (arg == "--expected-pci" && i + 1 < argc) {
      if (!options.expectedPci.empty()) throw UsageError("--expected-pci may be supplied only once");
      options.expectedPci = canonicalPci(argv[++i]);
      if (options.expectedPci.empty()) throw UsageError("invalid expected PCI ID; use DDDD:BB:DD.F or DDDDDDDD:BB:DD.F");
    } else if (arg == "--expected-device" && i + 1 < argc) {
      const std::string mapping = argv[++i];
      const std::size_t equals = mapping.find('=');
      if (equals == std::string::npos)
        throw UsageError("--expected-device must use SM=PCI, for example 70=0000:03:00.0");
      std::set<int> smValues;
      if (parseSmList(mapping.substr(0, equals), smValues) != 0 || smValues.size() != 1)
        throw UsageError("--expected-device SM must be one numeric compute-capability value");
      const int sm = *smValues.begin();
      const std::string pci = canonicalPci(mapping.substr(equals + 1));
      if (pci.empty())
        throw UsageError("--expected-device contains an invalid PCI ID");
      if (!options.expectedDevicePciBySm.emplace(sm, pci).second)
        throw UsageError("--expected-device may pin each SM only once");
      for (const auto &entry : options.expectedDevicePciBySm) {
        if (entry.first != sm && entry.second == pci)
          throw UsageError("--expected-device may not reuse a PCI ID");
      }
    } else {
      throw UsageError("unknown or incomplete argument: " + arg);
    }
  }
  if (options.listOnly && !options.modulePath.empty())
    throw UsageError("--list cannot be combined with --module");
  if (options.listOnly && gotRequiredSm)
    throw UsageError("--list cannot be combined with --require-sm");
  if (options.listOnly && !options.expectedDevicePciBySm.empty())
    throw UsageError("--list cannot be combined with --expected-device");
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
      options.phase != "kernel" && options.phase != "managed-accessed-by" &&
      options.phase != "system-pageable-memory")
    throw UsageError("unsupported phase: " + options.phase);
  if (gotPhase && options.expectedPci.empty())
    throw UsageError("--phase requires --expected-pci for exact device selection");
  if (gotPhase && !options.expectedDevicePciBySm.empty())
    throw UsageError("--phase cannot be combined with --expected-device");
  if (options.closeFdsOnExit && options.phase != "kernel")
    throw UsageError("--close-fds-on-exit requires --phase kernel");
  if (gotPhase && (options.managedMemory || options.managedPrefetch))
    throw UsageError("--phase cannot be combined with managed-memory modes");
  if (gotPhase && options.cudaGraphs)
    throw UsageError("--phase cannot be combined with --cuda-graphs");
  if (options.performanceBenchmark && options.expectedPci.empty())
    throw UsageError("--benchmark requires --expected-pci for exact device selection");
  if (gotBenchmarkSamples && !options.performanceBenchmark)
    throw UsageError("--benchmark-samples requires --benchmark");
  if (!options.expectedPci.empty() && !options.expectedDevicePciBySm.empty())
    throw UsageError("--expected-pci cannot be combined with --expected-device");
  if (options.peerTransfer &&
      (options.requiredSm != std::set<int>{70, 120} ||
       options.expectedDevicePciBySm.size() != 2 || !options.expectedPci.empty() ||
       options.listOnly || gotPhase || options.performanceBenchmark))
    throw UsageError("--peer-transfer requires only the exact pinned SM70 and SM120 device pair");
  if (!options.expectedDevicePciBySm.empty()) {
    if (options.expectedDevicePciBySm.size() != options.requiredSm.size())
      throw UsageError("--expected-device must pin every required SM exactly once");
    for (int sm : options.requiredSm) {
      if (!options.expectedDevicePciBySm.count(sm))
        throw UsageError("--expected-device must pin every required SM exactly once");
    }
  }
  if (options.concurrentKernels &&
      (options.requiredSm != std::set<int>{70, 120} ||
       options.expectedDevicePciBySm.size() != 2 || !options.expectedPci.empty() ||
       options.listOnly || gotPhase || options.managedMemory || options.managedPrefetch ||
       options.cudaGraphs || options.performanceBenchmark))
    throw UsageError("--concurrent-kernels requires only the exact pinned SM70 and SM120 device pair");
  if (options.performanceBenchmark &&
      (options.listOnly || gotPhase || options.managedMemory || options.managedPrefetch ||
       options.cudaGraphs))
    throw UsageError("--benchmark is an isolated device-memory reference mode");
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
  if (gotLibcudaPath) {
    char *resolved = realpath(options.libcudaPath.c_str(), nullptr);
    if (!resolved)
      throw UsageError("--libcuda path cannot be resolved: " + options.libcudaPath);
    options.libcudaPath = resolved;
    std::free(resolved);
    struct stat libraryStatus {};
    if (stat(options.libcudaPath.c_str(), &libraryStatus) != 0 ||
        !S_ISREG(libraryStatus.st_mode) || access(options.libcudaPath.c_str(), R_OK) != 0)
      throw UsageError("--libcuda path must be a readable regular file: " + options.libcudaPath);
  }
  return options;
}

struct CloseFdsAtExit {
  bool enabled;
  ~CloseFdsAtExit() noexcept {
    if (enabled && syscall(SYS_close_range, 3U, ~0U, 0U) != 0) {
      constexpr char message[] = "close_range lifecycle experiment failed\n";
      const ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1);
      if (written < 0) _exit(126);
      _exit(126);
    }
  }
};

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

constexpr std::size_t kPeerTransferBytes = 4096;

struct PeerBufferGuard {
  Api &api;
  CUcontext owner;
  DeviceResult &result;
  CUdeviceptr pointer{};
  PeerBufferGuard(Api &apiIn, CUcontext ownerIn, DeviceResult &resultIn)
      : api(apiIn), owner(ownerIn), result(resultIn) {
    api.check(api.memoryAlloc(&pointer, kPeerTransferBytes),
              "cuMemAlloc_v2(peer-transfer)");
  }
  ~PeerBufferGuard() {
    if (pointer) {
      recordCleanup(api, api.contextSetCurrent(owner),
                    "cuCtxSetCurrent(peer-buffer cleanup)", result);
      recordCleanup(api, api.memoryFree(pointer),
                    "cuMemFree_v2(peer-transfer)", result);
    }
  }
};

struct PeerStreamGuard {
  Api &api;
  CUcontext owner;
  DeviceResult &result;
  CUstream stream{};
  PeerStreamGuard(Api &apiIn, CUcontext ownerIn, DeviceResult &resultIn)
      : api(apiIn), owner(ownerIn), result(resultIn) {
    api.check(api.streamCreate(&stream, CU_STREAM_DEFAULT),
              "cuStreamCreate(peer-transfer)");
  }
  ~PeerStreamGuard() {
    if (stream) {
      recordCleanup(api, api.contextSetCurrent(owner),
                    "cuCtxSetCurrent(peer-stream cleanup)", result);
      recordCleanup(api, api.streamSynchronize(stream),
                    "cuStreamSynchronize(peer-transfer cleanup)", result);
      recordCleanup(api, api.streamDestroy(stream),
                    "cuStreamDestroy_v2(peer-transfer)", result);
    }
  }
};

void appendPeerError(PeerTransferResult &result, const std::string &message) {
  if (!result.error.empty()) result.error += "; ";
  result.error += message;
}

bool checkPeerValues(const std::vector<std::uint32_t> &expected,
                     const std::vector<std::uint32_t> &actual) {
  return expected.size() == actual.size() && expected == actual;
}


PeerTransferDirection runHostStagedTransferDirection(
    Api &api, CUcontext sourceContext, CUcontext destinationContext,
    int sourceSm, int destinationSm, DeviceResult &sourceResult,
    DeviceResult &destinationResult, PeerTransferResult &peerReport) {
  PeerTransferDirection direction;
  direction.sourceSm = sourceSm;
  direction.destinationSm = destinationSm;
  constexpr std::size_t elementCount = kPeerTransferBytes / sizeof(std::uint32_t);

  api.check(api.contextSetCurrent(sourceContext),
            "cuCtxSetCurrent(host-staged source allocation)");
  PeerBufferGuard source(api, sourceContext, sourceResult);
  api.check(api.contextSetCurrent(destinationContext),
            "cuCtxSetCurrent(host-staged destination allocation)");
  PeerBufferGuard destination(api, destinationContext, destinationResult);

  HostGuard staging(api, kPeerTransferBytes, sourceResult);
  HostGuard verification(api, kPeerTransferBytes, sourceResult);
  auto *stagingWords = static_cast<std::uint32_t *>(staging.pointer);
  auto *verificationWords = static_cast<std::uint32_t *>(verification.pointer);

  api.check(api.contextSetCurrent(sourceContext),
            "cuCtxSetCurrent(host-staged source stream)");
  PeerStreamGuard sourceStream(api, sourceContext, sourceResult);
  api.check(api.contextSetCurrent(destinationContext),
            "cuCtxSetCurrent(host-staged destination stream)");
  PeerStreamGuard destinationStream(api, destinationContext, destinationResult);

  std::vector<std::uint32_t> input(elementCount);
  const auto fillInput = [&](std::uint32_t marker, std::uint32_t salt) {
    for (std::size_t i = 0; i < elementCount; ++i) {
      input[i] = 0xa511e9b3U * static_cast<std::uint32_t>(i + 1) ^
                 salt ^ static_cast<std::uint32_t>(sourceSm * 257 + destinationSm);
    }
    input[0] = marker;
  };

  fillInput(0x53544731U, 0x13579bdfU);
  try {
    api.check(api.contextSetCurrent(sourceContext),
              "cuCtxSetCurrent(host-staged synchronous source)");
    api.check(api.copyHostToDevice(source.pointer, input.data(), kPeerTransferBytes),
              "cuMemcpyHtoD_v2(host-staged synchronous source)");
    api.check(api.copyDeviceToHost(stagingWords, source.pointer, kPeerTransferBytes),
              "cuMemcpyDtoH_v2(host-staged synchronous source)");
    const bool sourceRoundTrip = checkPeerValues(
        input, std::vector<std::uint32_t>(stagingWords, stagingWords + elementCount));
    api.check(api.contextSetCurrent(destinationContext),
              "cuCtxSetCurrent(host-staged synchronous destination)");
    api.check(api.copyHostToDevice(destination.pointer, stagingWords, kPeerTransferBytes),
              "cuMemcpyHtoD_v2(host-staged synchronous destination)");
    api.check(api.copyDeviceToHost(verificationWords, destination.pointer,
                                   kPeerTransferBytes),
              "cuMemcpyDtoH_v2(host-staged synchronous verification)");
    direction.hostStagedSyncCopyPassed = sourceRoundTrip && checkPeerValues(
        input, std::vector<std::uint32_t>(verificationWords,
                                          verificationWords + elementCount));
    if (!direction.hostStagedSyncCopyPassed)
      appendPeerError(peerReport,
                      "explicit synchronous host-staged transfer data mismatch");
  } catch (const std::exception &error) {
    appendPeerError(peerReport, error.what());
  }

  fillInput(0x53544732U, 0x2468ace0U);
  try {
    api.check(api.contextSetCurrent(sourceContext),
              "cuCtxSetCurrent(host-staged asynchronous source)");
    api.check(api.copyHostToDeviceAsync(source.pointer, input.data(),
                                        kPeerTransferBytes, sourceStream.stream),
              "cuMemcpyHtoDAsync_v2(host-staged source seed)");
    api.check(api.copyDeviceToHostAsync(stagingWords, source.pointer,
                                        kPeerTransferBytes, sourceStream.stream),
              "cuMemcpyDtoHAsync_v2(host-staged source)");
    api.check(api.streamSynchronize(sourceStream.stream),
              "cuStreamSynchronize(host-staged source)");
    const bool sourceRoundTrip = checkPeerValues(
        input, std::vector<std::uint32_t>(stagingWords, stagingWords + elementCount));
    api.check(api.contextSetCurrent(destinationContext),
              "cuCtxSetCurrent(host-staged asynchronous destination)");
    api.check(api.copyHostToDeviceAsync(destination.pointer, stagingWords,
                                        kPeerTransferBytes,
                                        destinationStream.stream),
              "cuMemcpyHtoDAsync_v2(host-staged destination)");
    api.check(api.copyDeviceToHostAsync(verificationWords, destination.pointer,
                                        kPeerTransferBytes,
                                        destinationStream.stream),
              "cuMemcpyDtoHAsync_v2(host-staged verification)");
    api.check(api.streamSynchronize(destinationStream.stream),
              "cuStreamSynchronize(host-staged destination)");
    direction.hostStagedAsyncCopyPassed = sourceRoundTrip && checkPeerValues(
        input, std::vector<std::uint32_t>(verificationWords,
                                          verificationWords + elementCount));
    if (!direction.hostStagedAsyncCopyPassed)
      appendPeerError(peerReport,
                      "explicit asynchronous host-staged transfer data mismatch");
  } catch (const std::exception &error) {
    appendPeerError(peerReport, error.what());
  }
  direction.hostStagedDataIntegrityPassed =
      direction.hostStagedSyncCopyPassed && direction.hostStagedAsyncCopyPassed;
  return direction;
}

  PeerTransferDirection runPeerTransferDirection(
    PeerTransferDirection direction, Api &api,
    CUcontext sourceContext, CUcontext destinationContext,
    int sourceSm, int destinationSm, DeviceResult &sourceResult,
    DeviceResult &destinationResult, bool directAccessEnabled,
    const std::string &modulePath, PeerTransferResult &peerReport) {
  direction.directAccessEnabled = directAccessEnabled;
  api.check(api.contextSetCurrent(sourceContext),
            "cuCtxSetCurrent(peer source allocation)");
  PeerBufferGuard source(api, sourceContext, sourceResult);
  api.check(api.contextSetCurrent(destinationContext),
            "cuCtxSetCurrent(peer destination allocation)");
  PeerBufferGuard destination(api, destinationContext, destinationResult);
  constexpr std::size_t elementCount = kPeerTransferBytes / sizeof(std::uint32_t);
  std::vector<std::uint32_t> input(elementCount);
  std::vector<std::uint32_t> output(elementCount);
  std::vector<std::uint32_t> sentinel(elementCount, 0xdeadbeefU);

  for (std::size_t i = 0; i < elementCount; ++i)
    input[i] = 0x9e3779b9U * static_cast<std::uint32_t>(i + 1) ^
               static_cast<std::uint32_t>(sourceSm * 257 + destinationSm);
  try {
    api.check(api.contextSetCurrent(sourceContext),
              "cuCtxSetCurrent(peer-transfer source)");
    api.check(api.copyHostToDevice(source.pointer, input.data(), kPeerTransferBytes),
              "cuMemcpyHtoD_v2(peer-transfer source)");
    api.check(api.contextSetCurrent(destinationContext),
              "cuCtxSetCurrent(peer-transfer destination)");
    api.check(api.copyHostToDevice(destination.pointer, sentinel.data(),
                                   kPeerTransferBytes),
              "cuMemcpyHtoD_v2(peer-transfer destination sentinel)");
    api.check(api.copyPeer(destination.pointer, destinationContext,
                           source.pointer, sourceContext, kPeerTransferBytes),
              "cuMemcpyPeer");
    api.check(api.copyDeviceToHost(output.data(), destination.pointer,
                                   kPeerTransferBytes),
              "cuMemcpyDtoH_v2(peer-transfer sync verification)");
    direction.syncCopyPassed = checkPeerValues(input, output);
  } catch (const std::exception &error) {
    appendPeerError(peerReport, error.what());
  }

  for (std::size_t i = 0; i < elementCount; ++i)
    input[i] = 0x85ebca6bU * static_cast<std::uint32_t>(i + 3) ^
               static_cast<std::uint32_t>(destinationSm * 521 + sourceSm);
  try {
    api.check(api.contextSetCurrent(sourceContext),
              "cuCtxSetCurrent(peer-transfer async source)");
    api.check(api.copyHostToDevice(source.pointer, input.data(), kPeerTransferBytes),
              "cuMemcpyHtoD_v2(peer-transfer async source)");
    api.check(api.contextSetCurrent(destinationContext),
              "cuCtxSetCurrent(peer-transfer async destination)");
    api.check(api.copyHostToDevice(destination.pointer, sentinel.data(),
                                   kPeerTransferBytes),
              "cuMemcpyHtoD_v2(peer-transfer async destination sentinel)");
    PeerStreamGuard stream(api, destinationContext, destinationResult);
    api.check(api.copyPeerAsync(destination.pointer, destinationContext,
                                source.pointer, sourceContext, kPeerTransferBytes,
                                stream.stream),
              "cuMemcpyPeerAsync");
    api.check(api.streamSynchronize(stream.stream),
              "cuStreamSynchronize(peer-transfer)");
    api.check(api.copyDeviceToHost(output.data(), destination.pointer,
                                   kPeerTransferBytes),
              "cuMemcpyDtoH_v2(peer-transfer async verification)");
    direction.asyncCopyPassed = checkPeerValues(input, output);
  } catch (const std::exception &error) {
    appendPeerError(peerReport, error.what());
  }
  direction.dataIntegrityPassed = direction.syncCopyPassed &&
                                  direction.asyncCopyPassed;

  if (directAccessEnabled) {
    direction.directKernelAttempted = true;
    try {
      std::vector<std::uint32_t> kernelInput(elementCount);
      for (std::size_t i = 0; i < elementCount; ++i)
        kernelInput[i] = 0xc2b2ae35U * static_cast<std::uint32_t>(i + 5) ^
                         static_cast<std::uint32_t>(sourceSm * 911 + destinationSm);
      api.check(api.contextSetCurrent(sourceContext),
                "cuCtxSetCurrent(peer-kernel source)");
      api.check(api.copyHostToDevice(source.pointer, kernelInput.data(),
                                     kPeerTransferBytes),
                "cuMemcpyHtoD_v2(peer-kernel source)");
      api.check(api.contextSetCurrent(destinationContext),
                "cuCtxSetCurrent(peer-kernel destination)");
      PeerBufferGuard kernelOutput(api, destinationContext, destinationResult);
      ModuleGuard peerModule(api, modulePath, destinationResult);
      CUfunction peerRead{};
      api.check(api.moduleGetFunction(&peerRead, peerModule.module,
                                      "hybrid_peer_read"),
                "cuModuleGetFunction(hybrid_peer_read)");
      CUdeviceptr remotePointer = source.pointer;
      CUdeviceptr localPointer = kernelOutput.pointer;
      unsigned int count = static_cast<unsigned int>(elementCount);
      void *kernelParameters[] = {&remotePointer, &localPointer, &count};
      constexpr unsigned int threadsPerBlock = 256;
      const unsigned int blocks =
          (count + threadsPerBlock - 1) / threadsPerBlock;
      api.check(api.launchKernel(peerRead, blocks, 1, 1, threadsPerBlock,
                                 1, 1, 0, nullptr, kernelParameters, nullptr),
                "cuLaunchKernel(hybrid_peer_read)");
      api.check(api.contextSynchronize(),
                "cuCtxSynchronize(peer-kernel)");
      api.check(api.copyDeviceToHost(output.data(), kernelOutput.pointer,
                                     kPeerTransferBytes),
                "cuMemcpyDtoH_v2(peer-kernel verification)");
      direction.directKernelPassed = checkPeerValues(kernelInput, output);
      if (!direction.directKernelPassed)
        appendPeerError(peerReport,
                        "hybrid_peer_read returned incorrect peer-memory data");
    } catch (const std::exception &error) {
      appendPeerError(peerReport, error.what());
    }
  }
  return direction;
}

PeerTransferResult runPeerTransfer(
    Api &api, const std::vector<DeviceInfo> &inventory,
    const std::vector<std::unique_ptr<ContextGuard>> &contexts,
    std::vector<DeviceResult> &deviceResults, const std::string &modulePath) {
  PeerTransferResult report;
  report.requested = true;
  std::map<int, std::size_t> indexBySm;
  for (std::size_t i = 0; i < inventory.size(); ++i) {
    if (deviceResults[i].targeted &&
        (inventory[i].sm == 70 || inventory[i].sm == 120)) {
      indexBySm.emplace(inventory[i].sm, i);
      if (inventory[i].sm == 70) report.sm70Pci = inventory[i].pci;
      if (inventory[i].sm == 120) report.sm120Pci = inventory[i].pci;
    }
  }
  if (indexBySm.size() != 2) {
    report.status = "pair-unavailable";
    report.hostStagedFallbackStatus = "pair-unavailable";
    return report;
  }
  const std::size_t sm70Index = indexBySm.at(70);
  const std::size_t sm120Index = indexBySm.at(120);
  if (!contexts[sm70Index] || !contexts[sm120Index] ||
      !deviceResults[sm70Index].error.empty() ||
      !deviceResults[sm120Index].error.empty()) {
    report.status = "contexts-unavailable";
    report.hostStagedFallbackStatus = "contexts-unavailable";
    return report;
  }

  PeerTransferDirection sm70ToSm120;
  sm70ToSm120.sourceSm = 70;
  sm70ToSm120.destinationSm = 120;
  try {
    sm70ToSm120 = runHostStagedTransferDirection(
        api, contexts[sm70Index]->context, contexts[sm120Index]->context,
        70, 120, deviceResults[sm70Index], deviceResults[sm120Index], report);
  } catch (const std::exception &error) {
    appendPeerError(report, error.what());
  }
  PeerTransferDirection sm120ToSm70;
  sm120ToSm70.sourceSm = 120;
  sm120ToSm70.destinationSm = 70;
  try {
    sm120ToSm70 = runHostStagedTransferDirection(
        api, contexts[sm120Index]->context, contexts[sm70Index]->context,
        120, 70, deviceResults[sm120Index], deviceResults[sm70Index], report);
  } catch (const std::exception &error) {
    appendPeerError(report, error.what());
  }
  report.directions = {sm70ToSm120, sm120ToSm70};
  report.cleanupPassed = deviceResults[sm70Index].cleanupPassed &&
                         deviceResults[sm120Index].cleanupPassed;
  const auto hostStagedDirectionsPassed = [&]() {
    return report.directions.size() == 2 &&
        std::all_of(report.directions.begin(), report.directions.end(),
                    [](const PeerTransferDirection &direction) {
                      return direction.hostStagedDataIntegrityPassed;
                    });
  };
  report.hostStagedFallbackPassed =
      report.cleanupPassed && hostStagedDirectionsPassed();
  report.hostStagedFallbackStatus = !report.cleanupPassed
      ? "cleanup-failed"
      : (report.hostStagedFallbackPassed ? "host-staged-verified" : "copy-failed");
  if (!report.cleanupPassed) {
    report.status = "cleanup-failed";
    return report;
  }

  api.enablePeerTransfer();
  if (!api.peerTransferApiAvailable) {
    report.status = "api-unavailable";
    return report;
  }

  const CUdevice sm70Device = inventory[sm70Index].handle;
  const CUdevice sm120Device = inventory[sm120Index].handle;
  try {
    api.check(api.deviceCanAccessPeer(&report.sm70CanAccessSm120,
                                      sm70Device, sm120Device),
              "cuDeviceCanAccessPeer(SM70->SM120)");
    api.check(api.deviceCanAccessPeer(&report.sm120CanAccessSm70,
                                      sm120Device, sm70Device),
              "cuDeviceCanAccessPeer(SM120->SM70)");
    if ((report.sm70CanAccessSm120 != 0 && report.sm70CanAccessSm120 != 1) ||
        (report.sm120CanAccessSm70 != 0 && report.sm120CanAccessSm70 != 1))
      throw CudaError("cuDeviceCanAccessPeer returned a non-boolean result");
  } catch (const std::exception &error) {
    report.status = "query-failed";
    appendPeerError(report, error.what());
    return report;
  }

  bool sm70AccessEnabled = false;
  bool sm120AccessEnabled = false;
  const auto enablePeer = [&](std::size_t ownerIndex, std::size_t peerIndex,
                              bool capability, bool &enabled) {
    if (!capability) return;
    try {
      api.check(api.contextSetCurrent(contexts[ownerIndex]->context),
                "cuCtxSetCurrent(peer-access enable)");
      api.check(api.contextEnablePeerAccess(contexts[peerIndex]->context, 0),
                ownerIndex == sm70Index ? "cuCtxEnablePeerAccess(SM70->SM120)"
                                        : "cuCtxEnablePeerAccess(SM120->SM70)");
      enabled = true;
    } catch (const std::exception &error) {
      appendPeerError(report, error.what());
    }
  };
  enablePeer(sm70Index, sm120Index, report.sm70CanAccessSm120 == 1,
             sm70AccessEnabled);
  enablePeer(sm120Index, sm70Index, report.sm120CanAccessSm70 == 1,
             sm120AccessEnabled);
  report.directPeerAccessEnabled = sm70AccessEnabled && sm120AccessEnabled;

  try {
    report.directions[0] = runPeerTransferDirection(
        report.directions[0], api,
        contexts[sm70Index]->context, contexts[sm120Index]->context,
        70, 120, deviceResults[sm70Index], deviceResults[sm120Index],
        sm120AccessEnabled, modulePath, report);
  } catch (const std::exception &error) {
    appendPeerError(report, error.what());
    report.directions[0].directAccessEnabled = sm120AccessEnabled;
  }
  try {
    report.directions[1] = runPeerTransferDirection(
        report.directions[1], api,
        contexts[sm120Index]->context, contexts[sm70Index]->context,
        120, 70, deviceResults[sm120Index], deviceResults[sm70Index],
        sm70AccessEnabled, modulePath, report);
  } catch (const std::exception &error) {
    appendPeerError(report, error.what());
    report.directions[1].directAccessEnabled = sm70AccessEnabled;
  }

  const auto disablePeer = [&](std::size_t ownerIndex, std::size_t peerIndex,
                               bool enabled) {
    if (!enabled) return;
    DeviceResult &ownerResult = deviceResults[ownerIndex];
    recordCleanup(api, api.contextSetCurrent(contexts[ownerIndex]->context),
                  "cuCtxSetCurrent(peer-access cleanup)", ownerResult);
    recordCleanup(api, api.contextDisablePeerAccess(contexts[peerIndex]->context),
                  ownerIndex == sm70Index ? "cuCtxDisablePeerAccess(SM70->SM120)"
                                          : "cuCtxDisablePeerAccess(SM120->SM70)",
                  ownerResult);
    if (!ownerResult.cleanupPassed) report.cleanupPassed = false;
  };
  disablePeer(sm120Index, sm70Index, sm120AccessEnabled);
  disablePeer(sm70Index, sm120Index, sm70AccessEnabled);

  if (!deviceResults[sm70Index].cleanupPassed ||
      !deviceResults[sm120Index].cleanupPassed)
    report.cleanupPassed = false;
  report.passed = report.cleanupPassed && report.directions.size() == 2 &&
      std::all_of(report.directions.begin(), report.directions.end(),
                  [](const PeerTransferDirection &direction) {
                    return direction.dataIntegrityPassed &&
                           (!direction.directKernelAttempted ||
                            direction.directKernelPassed);
                  });
  if (!report.cleanupPassed) {
    report.hostStagedFallbackPassed = false;
    report.hostStagedFallbackStatus = "cleanup-failed";
    report.status = "cleanup-failed";
  } else if (report.directions.size() == 2 &&
           std::any_of(report.directions.begin(), report.directions.end(),
                       [](const PeerTransferDirection &direction) {
                         return direction.directKernelAttempted &&
                                !direction.directKernelPassed;
                       }))
    report.status = "peer-kernel-failed";
  else if (!report.passed)
    report.status = "copy-failed";
  else if (report.directPeerAccessEnabled)
    report.status = "peer-memory-verified";
  else if (sm70AccessEnabled || sm120AccessEnabled)
    report.status = "one-way-peer-memory-verified";
  else
    report.status = "copy-only-verified";
  return report;
}

struct EventGuard {
  Api &api;
  DeviceResult &result;
  CUevent event{};
  EventGuard(Api &apiIn, DeviceResult &resultIn) : api(apiIn), result(resultIn) {
    api.check(api.eventCreate(&event, CU_EVENT_DEFAULT), "cuEventCreate(performance)");
  }
  ~EventGuard() {
    if (event) recordCleanup(api, api.eventDestroy(event),
                             "cuEventDestroy_v2(performance)", result);
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

void launchEmptyKernel(Api &api, CUfunction function, CUstream stream) {
  api.check(api.launchKernel(function, 1, 1, 1, 1, 1, 1, 0, stream,
                             nullptr, nullptr),
            "cuLaunchKernel(hybrid_empty)");
}

template <typename Submit>
std::pair<double, double> measureBatch(Api &api, CUevent start, CUevent stop,
                                       CUstream stream, unsigned int operations,
                                       const std::string &label, Submit &&submit) {
  if (operations == 0) throw CudaError(label + " has no operations to time");
  api.check(api.eventRecord(start, stream), label + " cuEventRecord(start)");
  const auto begin = std::chrono::steady_clock::now();
  for (unsigned int i = 0; i < operations; ++i) submit();
  const auto end = std::chrono::steady_clock::now();
  api.check(api.eventRecord(stop, stream), label + " cuEventRecord(stop)");
  api.check(api.eventSynchronize(stop), label + " cuEventSynchronize");
  float elapsedMilliseconds = 0.0F;
  api.check(api.eventElapsedTime(&elapsedMilliseconds, start, stop),
            label + " cuEventElapsedTime");
  const double hostMicroseconds =
      std::chrono::duration<double, std::micro>(end - begin).count() / operations;
  const double deviceMicroseconds =
      static_cast<double>(elapsedMilliseconds) * 1000.0 / operations;
  if (!std::isfinite(hostMicroseconds) || hostMicroseconds <= 0.0 ||
      !std::isfinite(deviceMicroseconds) || deviceMicroseconds <= 0.0)
    throw CudaError(label + " returned a non-positive or non-finite duration");
  return {hostMicroseconds, deviceMicroseconds};
}

double median(const std::vector<double> &samples) {
  if (samples.empty()) throw CudaError("cannot summarize an empty timing sample set");
  std::vector<double> sorted = samples;
  std::sort(sorted.begin(), sorted.end());
  const std::size_t middle = sorted.size() / 2;
  if (sorted.size() % 2) return sorted[middle];
  return (sorted[middle - 1] + sorted[middle]) / 2.0;
}

double percentile95(const std::vector<double> &samples) {
  if (samples.empty()) throw CudaError("cannot summarize an empty timing sample set");
  std::vector<double> sorted = samples;
  std::sort(sorted.begin(), sorted.end());
  const std::size_t rank =
      static_cast<std::size_t>(std::ceil(0.95 * sorted.size()));
  return sorted[std::max<std::size_t>(1, rank) - 1];
}

template <typename Submit>
void runLaunchSamples(Api &api, CUstream stream, CUevent start, CUevent stop,
                      TimingMetrics &metrics, unsigned int warmupLaunches,
                      unsigned int launchesPerSample, unsigned int samples,
                      const std::string &label, Submit &&submit) {
  for (unsigned int i = 0; i < warmupLaunches; ++i) submit();
  api.check(api.streamSynchronize(stream), label + " warmup synchronization");
  for (unsigned int sample = 0; sample < samples; ++sample) {
    const auto measurement = measureBatch(api, start, stop, stream,
        launchesPerSample, label, submit);
    metrics.hostApiMicroseconds.push_back(measurement.first);
    metrics.deviceElapsedMicroseconds.push_back(measurement.second);
  }
}

template <typename DirectionMetrics>
void runTransferSamples(Api &api, CUdeviceptr device, const void *hostSource,
                        void *hostDestination, std::size_t bytes,
                        unsigned int iterations, unsigned int samples, CUstream stream,
                        CUevent start, CUevent stop, bool hostToDevice,
                        DirectionMetrics &metrics) {
  for (unsigned int i = 0; i < 2; ++i) {
    if (hostToDevice)
      api.check(api.copyHostToDeviceAsync(device, hostSource, bytes, stream),
                "cuMemcpyHtoDAsync_v2(performance warmup)");
    else
      api.check(api.copyDeviceToHostAsync(hostDestination, device, bytes, stream),
                "cuMemcpyDtoHAsync_v2(performance warmup)");
  }
  api.check(api.streamSynchronize(stream), "cuStreamSynchronize(transfer warmup)");
  for (unsigned int sample = 0; sample < samples; ++sample) {
    const auto measurement = measureBatch(api, start, stop, stream, iterations,
        hostToDevice ? "HtoD performance" : "DtoH performance", [&]() {
          if (hostToDevice)
            api.check(api.copyHostToDeviceAsync(device, hostSource, bytes, stream),
                      "cuMemcpyHtoDAsync_v2(performance)");
          else
            api.check(api.copyDeviceToHostAsync(hostDestination, device, bytes, stream),
                      "cuMemcpyDtoHAsync_v2(performance)");
        });
    // measureBatch already normalizes event time by operation count, so both
    // the elapsed time and reported bandwidth must describe one copy.
    const double bandwidth = static_cast<double>(bytes) /
        (measurement.second * 1.0e-6) / 1.0e9;
    if (!std::isfinite(bandwidth) || bandwidth <= 0.0)
      throw CudaError("transfer benchmark returned an invalid bandwidth sample");
    metrics.hostApiMicrosecondsPerCopy.push_back(measurement.first);
    metrics.deviceElapsedMicrosecondsPerCopy.push_back(measurement.second);
    metrics.deviceGigabytesPerSecond.push_back(bandwidth);
  }
  if (hostToDevice) {
    api.check(api.copyDeviceToHostAsync(hostDestination, device, bytes, stream),
              "cuMemcpyDtoHAsync_v2(HtoD integrity check)");
    api.check(api.streamSynchronize(stream), "cuStreamSynchronize(HtoD integrity check)");
    metrics.dataIntegrityPassed =
        std::memcmp(hostSource, hostDestination, bytes) == 0;
  } else {
    metrics.dataIntegrityPassed = std::memcmp(hostSource, hostDestination, bytes) == 0;
  }
  if (!metrics.dataIntegrityPassed)
    throw CudaError(hostToDevice ? "HtoD transfer integrity check failed"
                                 : "DtoH transfer integrity check failed");
}

void runPerformanceBenchmark(Api &api, CUfunction emptyFunction,
                             CUstream stream, unsigned int samples,
                             unsigned int transferSamples,
                             DeviceResult &result) {
  api.enablePerformanceTiming();
  api.enableCudaGraphs();
  EventGuard start(api, result);
  EventGuard stop(api, result);
  PerformanceBenchmark &benchmark = result.performanceBenchmark;
  constexpr unsigned int warmupLaunches = 64;
  constexpr unsigned int launchesPerSample = 256;
  if (samples < 9 || samples > 1001 || transferSamples < 7 ||
      transferSamples > 1001)
    throw CudaError("benchmark sample count is outside the supported range");
  benchmark.warmupLaunches = warmupLaunches;
  benchmark.launchesPerSample = launchesPerSample;
  benchmark.samples = samples;
  benchmark.transferSamples = transferSamples;

  const auto directSubmit = [&]() { launchEmptyKernel(api, emptyFunction, stream); };
  runLaunchSamples(api, stream, start.event, stop.event,
                   benchmark.directLaunch, warmupLaunches, launchesPerSample,
                   samples, "direct kernel launch", directSubmit);

  GraphGuard graph(api, result, stream);
  CUDA_KERNEL_NODE_PARAMS nodeParameters{};
  nodeParameters.func = emptyFunction;
  nodeParameters.gridDimX = 1;
  nodeParameters.gridDimY = 1;
  nodeParameters.gridDimZ = 1;
  nodeParameters.blockDimX = 1;
  nodeParameters.blockDimY = 1;
  nodeParameters.blockDimZ = 1;
  CUgraphNode node{};
  api.check(api.graphAddKernelNode(&node, graph.graph, nullptr, 0,
                                   &nodeParameters),
            "cuGraphAddKernelNode(performance)");
  api.check(api.graphInstantiate(&graph.executable, graph.graph, 0),
            "cuGraphInstantiateWithFlags(performance)");
  const auto graphSubmit = [&]() {
    api.check(api.graphLaunch(graph.executable, stream),
              "cuGraphLaunch(performance)");
  };
  for (unsigned int i = 0; i < warmupLaunches; ++i) graphSubmit();
  api.check(api.streamSynchronize(stream), "cuStreamSynchronize(graph warmup)");
  for (unsigned int sample = 0; sample < samples; ++sample) {
    const auto measurement = measureBatch(api, start.event, stop.event, stream,
        launchesPerSample, "CUDA Graph launch", graphSubmit);
    benchmark.graphLaunch.hostApiMicroseconds.push_back(measurement.first);
    benchmark.graphLaunch.deviceElapsedMicroseconds.push_back(measurement.second);
  }

  constexpr std::size_t maximumBytes = 64U * 1024U * 1024U;
  constexpr std::size_t targetBytesPerSample = 8U * 1024U * 1024U;
  constexpr std::size_t transferSizes[] = {
      4096U, 65536U, 1048576U, 16777216U, 67108864U};
  BufferGuard deviceBuffer(api, maximumBytes, result, false);
  HostGuard hostInput(api, maximumBytes, result);
  HostGuard hostOutput(api, maximumBytes, result);
  auto *input = static_cast<unsigned char *>(hostInput.pointer);
  auto *output = static_cast<unsigned char *>(hostOutput.pointer);
  for (std::size_t i = 0; i < maximumBytes; ++i)
    input[i] = static_cast<unsigned char>((i * 131U + 17U) & 0xffU);

  for (const std::size_t bytes : transferSizes) {
    TransferMetrics transfer;
    transfer.bytes = bytes;
    transfer.iterationsPerSample = static_cast<unsigned int>(
        std::max<std::size_t>(1, targetBytesPerSample / bytes));
    runTransferSamples(api, deviceBuffer.pointer, input, output, bytes,
                       transfer.iterationsPerSample, transferSamples, stream, start.event,
                       stop.event, true, transfer.hToD);
    api.check(api.copyHostToDeviceAsync(deviceBuffer.pointer, input, bytes, stream),
              "cuMemcpyHtoDAsync_v2(DtoH benchmark seed)");
    api.check(api.streamSynchronize(stream), "cuStreamSynchronize(DtoH benchmark seed)");
    runTransferSamples(api, deviceBuffer.pointer, input, output, bytes,
                       transfer.iterationsPerSample, transferSamples, stream, start.event,
                       stop.event, false, transfer.dToH);
    transfer.dataIntegrityPassed = transfer.hToD.dataIntegrityPassed &&
                                   transfer.dToH.dataIntegrityPassed;
    benchmark.transfers.push_back(std::move(transfer));
  }
  benchmark.passed = true;
  result.performanceBenchmarkPassed = true;
}

void runDevice(Api &api, ContextGuard &context, const DeviceInfo &device,
               const std::string &modulePath, bool managedMemory,
               bool managedPrefetch, bool cudaGraphs,
               bool performanceBenchmark,
               unsigned int benchmarkSamples,
               unsigned int benchmarkTransferSamples,
               DeviceResult &result) {
  result.device = device;
  result.targeted = true;
  result.tested = true;
  api.check(api.contextSetCurrent(context.context), "cuCtxSetCurrent(execution)");
  ModuleGuard module(api, modulePath, result);
  CUfunction archFunction{};
  CUfunction addFunction{};
  CUfunction emptyFunction{};
  api.check(api.moduleGetFunction(&archFunction, module.module, "hybrid_arch"),
            "cuModuleGetFunction(hybrid_arch)");
  api.check(api.moduleGetFunction(&addFunction, module.module, "hybrid_add"),
            "cuModuleGetFunction(hybrid_add)");
  if (performanceBenchmark)
    api.check(api.moduleGetFunction(&emptyFunction, module.module, "hybrid_empty"),
              "cuModuleGetFunction(hybrid_empty)");
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
  if (performanceBenchmark)
    runPerformanceBenchmark(api, emptyFunction, stream.stream,
                            benchmarkSamples, benchmarkTransferSamples, result);
}

constexpr unsigned int kConcurrentElementCount = 65536;
constexpr unsigned int kConcurrentRounds = 65536;

std::uint32_t expectedConcurrentValue(std::uint32_t seed, unsigned int rounds) {
  std::uint32_t accumulatedMultiplier = 1U;
  std::uint32_t accumulatedIncrement = 0U;
  std::uint32_t multiplier = 1664525U;
  std::uint32_t increment = 1013904223U;
  while (rounds != 0) {
    if (rounds & 1U) {
      accumulatedIncrement = multiplier * accumulatedIncrement + increment;
      accumulatedMultiplier = multiplier * accumulatedMultiplier;
    }
    increment = multiplier * increment + increment;
    multiplier *= multiplier;
    rounds >>= 1U;
  }
  return accumulatedMultiplier * seed + accumulatedIncrement;
}

struct ConcurrentStartGate {
  std::mutex mutex;
  std::condition_variable changed;
  unsigned int ready = 0;
  bool released = false;
  bool cancelled = false;

  bool arriveAndWait() {
    std::unique_lock<std::mutex> lock(mutex);
    ++ready;
    changed.notify_all();
    changed.wait(lock, [this] { return released || cancelled; });
    return released && !cancelled;
  }

  void cancel() {
    {
      std::lock_guard<std::mutex> lock(mutex);
      cancelled = true;
    }
    changed.notify_all();
  }

  void releaseAfterBothReady() {
    {
      std::unique_lock<std::mutex> lock(mutex);
      changed.wait(lock, [this] { return ready == 2 || cancelled; });
      if (!cancelled && ready == 2)
        released = true;
      else
        cancelled = true;
    }
    changed.notify_all();
  }
};

std::uint64_t steadyClockNanoseconds() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
}

ConcurrentDispatchResult runConcurrentDispatch(
    Api &api, const std::vector<DeviceInfo> &inventory,
    std::vector<std::unique_ptr<ContextGuard>> &contexts,
    std::vector<DeviceResult> &deviceResults, const std::string &modulePath) {
  ConcurrentDispatchResult report;
  report.rounds = kConcurrentRounds;
  std::map<int, std::size_t> indexBySm;
  for (std::size_t i = 0; i < inventory.size(); ++i) {
    if (deviceResults[i].targeted &&
        (inventory[i].sm == 70 || inventory[i].sm == 120) && contexts[i] &&
        deviceResults[i].error.empty())
      indexBySm.emplace(inventory[i].sm, i);
  }
  if (indexBySm.size() != 2) return report;

  const std::size_t indices[] = {indexBySm.at(70), indexBySm.at(120)};
  report.devices.resize(2);
  for (std::size_t slot = 0; slot < 2; ++slot) {
    report.devices[slot].sm = inventory[indices[slot]].sm;
    report.devices[slot].pci = inventory[indices[slot]].pci;
  }

  // Contexts are resident but must be detached from the coordinator thread
  // before workers attach one context each.
  api.check(api.contextSetCurrent(nullptr),
            "cuCtxSetCurrent(detach before concurrent dispatch)");
  ConcurrentStartGate setupGate;
  ConcurrentStartGate dispatchGate;
  std::vector<std::thread> workers;
  workers.reserve(2);
  auto worker = [&](std::size_t slot) {
    const std::size_t index = indices[slot];
    DeviceResult &cleanup = deviceResults[index];
    ConcurrentDispatchDevice &deviceReport = report.devices[slot];
    bool contextAttached = false;
    std::string failure;
    try {
      api.check(api.contextSetCurrent(contexts[index]->context),
                "cuCtxSetCurrent(concurrent dispatch)");
      contextAttached = true;
      {
        ModuleGuard module(api, modulePath, cleanup);
        BufferGuard output(api, kConcurrentElementCount * sizeof(std::uint32_t),
                           cleanup, false);
        StreamGuard stream(api, cleanup);
        CUfunction function{};
        api.check(api.moduleGetFunction(&function, module.module,
                                        "hybrid_concurrent_work"),
                  "cuModuleGetFunction(hybrid_concurrent_work)");
        if (!setupGate.arriveAndWait())
          throw CudaError("concurrent dispatch cancelled before launch setup");

        CUdeviceptr outputPointer = output.pointer;
        unsigned int count = kConcurrentElementCount;
        unsigned int rounds = kConcurrentRounds;
        void *arguments[] = {&outputPointer, &count, &rounds};
        if (!dispatchGate.arriveAndWait())
          throw CudaError("concurrent dispatch cancelled before launch");
        deviceReport.hostWindowStartNs = steadyClockNanoseconds();
        deviceReport.launched = true;
        api.check(api.launchKernel(function, 256, 1, 1, 256, 1, 1, 0,
                                  stream.stream, arguments, nullptr),
                  "cuLaunchKernel(hybrid_concurrent_work)");
        api.check(api.streamSynchronize(stream.stream),
                  "cuStreamSynchronize(concurrent dispatch)");
        deviceReport.hostWindowEndNs = steadyClockNanoseconds();

        std::vector<std::uint32_t> host(kConcurrentElementCount);
        api.check(api.copyDeviceToHost(host.data(), output.pointer,
                                      host.size() * sizeof(host.front())),
                  "cuMemcpyDtoH_v2(concurrent numeric result)");
        for (unsigned int i = 0; i < kConcurrentElementCount; ++i) {
          if (host[i] != expectedConcurrentValue(i + 1U, kConcurrentRounds))
            throw CudaError("concurrent workload numeric result mismatch at element " +
                            std::to_string(i));
        }
        deviceReport.numericResultPassed = true;
      }
      if (!cleanup.cleanupPassed)
        throw CudaError("concurrent dispatch resource cleanup failed");
    } catch (const std::exception &error) {
      failure = error.what();
      setupGate.cancel();
      dispatchGate.cancel();
    } catch (...) {
      failure = "unknown concurrent dispatch failure";
      setupGate.cancel();
      dispatchGate.cancel();
    }
    if (contextAttached) {
      const CUresult detachStatus = api.contextSetCurrent(nullptr);
      recordCleanup(api, detachStatus, "cuCtxSetCurrent(detach concurrent worker)", cleanup);
      if (detachStatus != CUDA_SUCCESS && failure.empty())
        failure = "failed to detach concurrent worker context";
    }
    if (!failure.empty()) cleanup.error = failure;
  };

  try {
    workers.emplace_back(worker, 0);
    workers.emplace_back(worker, 1);
  } catch (const std::exception &error) {
    setupGate.cancel();
    dispatchGate.cancel();
    for (std::thread &thread : workers)
      if (thread.joinable()) thread.join();
    for (std::size_t index : indices)
      if (deviceResults[index].error.empty()) deviceResults[index].error = error.what();
    return report;
  }
  setupGate.releaseAfterBothReady();
  dispatchGate.releaseAfterBothReady();
  for (std::thread &thread : workers) thread.join();
  const bool hostWindowsOverlap =
      report.devices.size() == 2 &&
      std::max(report.devices[0].hostWindowStartNs,
               report.devices[1].hostWindowStartNs) <
          std::min(report.devices[0].hostWindowEndNs,
                   report.devices[1].hostWindowEndNs);
  report.passed = hostWindowsOverlap &&
      std::all_of(report.devices.begin(), report.devices.end(),
          [](const ConcurrentDispatchDevice &device) {
            return device.launched && device.numericResultPassed &&
                   device.hostWindowStartNs < device.hostWindowEndNs;
          }) && std::all_of(indices, indices + 2, [&](std::size_t index) {
            return deviceResults[index].error.empty() &&
                   deviceResults[index].cleanupPassed;
          });
  return report;
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

void printDoubleSamples(const std::vector<double> &samples) {
  std::cout << '[';
  for (std::size_t i = 0; i < samples.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << std::setprecision(12) << samples[i];
  }
  std::cout << ']';
}

void printTimingValues(const std::vector<double> &samples) {
  std::cout << "{\"samples\":" << samples.size() << ",\"values\":";
  printDoubleSamples(samples);
  std::cout << ",\"median\":" << std::setprecision(12) << median(samples)
            << ",\"p95\":" << std::setprecision(12) << percentile95(samples) << '}';
}

void printTimingMetrics(const TimingMetrics &metrics) {
  std::cout << "{\"host_api_us\":";
  printTimingValues(metrics.hostApiMicroseconds);
  std::cout << ",\"device_elapsed_us\":";
  printTimingValues(metrics.deviceElapsedMicroseconds);
  std::cout << '}';
}

void printTransferDirection(const TransferDirectionMetrics &metrics) {
  std::cout << "{\"host_api_us_per_copy_samples\":";
  printDoubleSamples(metrics.hostApiMicrosecondsPerCopy);
  std::cout << ",\"host_api_us_per_copy_median\":" << std::setprecision(12)
            << median(metrics.hostApiMicrosecondsPerCopy)
            << ",\"host_api_us_per_copy_p95\":" << std::setprecision(12)
            << percentile95(metrics.hostApiMicrosecondsPerCopy)
            << ",\"device_elapsed_us_per_copy_samples\":";
  printDoubleSamples(metrics.deviceElapsedMicrosecondsPerCopy);
  std::cout << ",\"device_elapsed_us_per_copy_median\":"
            << std::setprecision(12)
            << median(metrics.deviceElapsedMicrosecondsPerCopy)
            << ",\"device_elapsed_us_per_copy_p95\":"
            << std::setprecision(12)
            << percentile95(metrics.deviceElapsedMicrosecondsPerCopy)
            << ",\"gb_per_second_samples\":";
  printDoubleSamples(metrics.deviceGigabytesPerSecond);
  std::cout << ",\"gb_per_second_median\":" << std::setprecision(12)
            << median(metrics.deviceGigabytesPerSecond)
            << ",\"gb_per_second_p95\":" << std::setprecision(12)
            << percentile95(metrics.deviceGigabytesPerSecond)
            << ",\"data_integrity_passed\":"
            << (metrics.dataIntegrityPassed ? "true" : "false") << '}';
}

void printPerformanceBenchmark(const PerformanceBenchmark &benchmark) {
  std::cout << "{\"schema\":\"nvidia-cuda-performance-benchmark-v2\""
            << ",\"status\":\"completed\",\"timing_sources\":{"
            << "\"host\":\"std::chrono::steady_clock\","
            << "\"device\":\"CUDA events (cuEventElapsedTime)\"}"
            << ",\"samples\":" << benchmark.samples
            << ",\"transfer_samples\":" << benchmark.transferSamples
            << ",\"warmup_launches\":" << benchmark.warmupLaunches
            << ",\"launches_per_sample\":" << benchmark.launchesPerSample
            << ",\"kernel_launch\":{\"kernel\":\"hybrid_empty\","
            << "\"samples\":" << benchmark.directLaunch.hostApiMicroseconds.size()
            << ",\"host_api_us_samples\":";
  printDoubleSamples(benchmark.directLaunch.hostApiMicroseconds);
  std::cout << ",\"host_api_us_median\":" << std::setprecision(12)
            << median(benchmark.directLaunch.hostApiMicroseconds)
            << ",\"host_api_us_p95\":" << std::setprecision(12)
            << percentile95(benchmark.directLaunch.hostApiMicroseconds)
            << ",\"device_elapsed_us_samples\":";
  printDoubleSamples(benchmark.directLaunch.deviceElapsedMicroseconds);
  std::cout << ",\"device_elapsed_us_median\":" << std::setprecision(12)
            << median(benchmark.directLaunch.deviceElapsedMicroseconds)
            << ",\"device_elapsed_us_p95\":" << std::setprecision(12)
            << percentile95(benchmark.directLaunch.deviceElapsedMicroseconds)
            << "},\"cuda_graph_launch\":";
  printTimingMetrics(benchmark.graphLaunch);
  std::cout << ",\"transfers\":[";
  for (std::size_t i = 0; i < benchmark.transfers.size(); ++i) {
    if (i) std::cout << ',';
    const TransferMetrics &transfer = benchmark.transfers[i];
    std::cout << "{\"bytes\":" << transfer.bytes
              << ",\"iterations_per_sample\":" << transfer.iterationsPerSample
              << ",\"samples\":" << transfer.hToD.deviceGigabytesPerSecond.size()
              << ",\"h_to_d\":";
    printTransferDirection(transfer.hToD);
    std::cout << ",\"d_to_h\":";
    printTransferDirection(transfer.dToH);
    std::cout << ",\"data_integrity_passed\":"
              << (transfer.dataIntegrityPassed ? "true" : "false") << '}';
  }
  std::cout << "]}";
}

CUdeviceptr pageableDevicePointer(const int *pointer) {
  return static_cast<CUdeviceptr>(reinterpret_cast<std::uintptr_t>(pointer));
}

void runSystemPageableAllocator(Api &api, CUfunction function,
                                CUstream stream, bool contextSync,
                                SystemPageableBuffer &memory,
                                SystemAllocatorResult &result) {
  constexpr unsigned int maximumCount = 65537;
  constexpr unsigned int sizes[] = {1, 31, 256, 4096, 65537};
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
          } else if (options.phase == "managed-accessed-by") {
            api.enableManagedMemory();
            api.enableManagedMemoryAdvice();
            {
              BufferGuard buffer(api, 4096, outcome.cleanup, true);
              outcome.operations.emplace_back("cuMemAllocManaged");
              const CUmemLocation location{CU_MEM_LOCATION_TYPE_DEVICE,
                                           outcome.device.handle};
              api.check(api.managedMemoryAdvise(buffer.pointer, 4096,
                                                CU_MEM_ADVISE_SET_ACCESSED_BY,
                                                location),
                        "cuMemAdvise(SET_ACCESSED_BY)");
              outcome.operations.emplace_back("cuMemAdvise(SET_ACCESSED_BY)");
              api.check(api.managedMemoryAdvise(buffer.pointer, 4096,
                                                CU_MEM_ADVISE_UNSET_ACCESSED_BY,
                                                location),
                        "cuMemAdvise(UNSET_ACCESSED_BY)");
              outcome.operations.emplace_back("cuMemAdvise(UNSET_ACCESSED_BY)");
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

void printPeerTransfer(const PeerTransferResult &peer) {
  std::cout << "{\"schema\":\"nvidia-hybrid-peer-transfer-v3\",\"status\":\""
            << jsonEscape(peer.status) << "\",\"requested\":true,\"passed\":"
            << (peer.passed ? "true" : "false")
            << ",\"sm70_can_access_sm120\":";
  if (peer.sm70CanAccessSm120 < 0) std::cout << "null";
  else std::cout << (peer.sm70CanAccessSm120 == 1 ? "true" : "false");
  std::cout << ",\"sm120_can_access_sm70\":";
  if (peer.sm120CanAccessSm70 < 0) std::cout << "null";
  else std::cout << (peer.sm120CanAccessSm70 == 1 ? "true" : "false");
  std::cout << ",\"direct_peer_access_enabled\":"
            << (peer.directPeerAccessEnabled ? "true" : "false")
            << ",\"direct_dma_attested\":false,\"host_staged_fallback_passed\":"
            << (peer.hostStagedFallbackPassed ? "true" : "false")
            << ",\"host_staged_fallback_status\":\""
            << jsonEscape(peer.hostStagedFallbackStatus)
            << "\",\"sm70_pci_bus_id\":\"" << jsonEscape(peer.sm70Pci)
            << "\",\"sm120_pci_bus_id\":\"" << jsonEscape(peer.sm120Pci)
            << "\",\"bytes_per_direction\":" << peer.bytesPerDirection
            << ",\"directions\":[";
  for (std::size_t i = 0; i < peer.directions.size(); ++i) {
    if (i) std::cout << ',';
    const PeerTransferDirection &direction = peer.directions[i];
    std::cout << "{\"source_sm\":" << direction.sourceSm
              << ",\"destination_sm\":" << direction.destinationSm
              << ",\"direct_access_enabled\":"
              << (direction.directAccessEnabled ? "true" : "false")
              << ",\"direct_kernel_attempted\":"
              << (direction.directKernelAttempted ? "true" : "false")
              << ",\"direct_kernel_passed\":"
              << (direction.directKernelPassed ? "true" : "false")
              << ",\"sync_copy_passed\":"
              << (direction.syncCopyPassed ? "true" : "false")
              << ",\"async_copy_passed\":"
              << (direction.asyncCopyPassed ? "true" : "false")
              << ",\"data_integrity_passed\":"
              << (direction.dataIntegrityPassed ? "true" : "false")
              << ",\"host_staged_sync_copy_passed\":"
              << (direction.hostStagedSyncCopyPassed ? "true" : "false")
              << ",\"host_staged_async_copy_passed\":"
              << (direction.hostStagedAsyncCopyPassed ? "true" : "false")
              << ",\"host_staged_data_integrity_passed\":"
              << (direction.hostStagedDataIntegrityPassed ? "true" : "false") << '}';
  }
  std::cout << "],\"cleanup_passed\":"
            << (peer.cleanupPassed ? "true" : "false")
            << ",\"error\":\"" << jsonEscape(peer.error) << "\"}";
}

void printReport(const std::string &status, bool requiredSetPassed,
                 bool hybridValidated, bool contextCoexistence,
                 bool managedMemory,
                 bool managedPrefetch,
                 const std::string &managedPrefetchApi,
                 bool cudaGraphs, const std::string &cudaGraphsApi,
                 bool performanceBenchmark,
                 const std::string &driverLibrary,
                 int driverVersion, const std::set<int> &required,
                 const std::vector<int> &missing,
                 const std::vector<DeviceResult> &devices,
                 const std::map<int, std::string> &expectedDevicePciBySm,
                 bool concurrentKernelTestRequested = false,
                 const ConcurrentDispatchResult *concurrentDispatch = nullptr,
                 bool peerTransferRequested = false,
                 const PeerTransferResult *peerTransfer = nullptr) {
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
            << ",\"performance_benchmark_requested\":"
            << (performanceBenchmark ? "true" : "false")
            << ",\"execution_mode\":\"resident-contexts-sequential-kernels\""
            << ",\"concurrent_kernel_execution_validated\":false"
            << ",\"concurrent_kernel_test_requested\":"
            << (concurrentKernelTestRequested ? "true" : "false")
            << ",\"concurrent_kernel_dispatch_passed\":"
            << (concurrentDispatch && concurrentDispatch->passed ? "true" : "false")
            << ",\"concurrent_kernel_dispatch\":";
  if (concurrentDispatch && concurrentDispatch->passed) {
    std::cout << "{\"schema\":\"nvidia-hybrid-concurrent-dispatch-v1\","
              << "\"qualification\":\"host-dispatch-window-overlap-profiler-timeline-required\","
              << "\"requested\":true,\"passed\":true,"
              << "\"gpu_timeline_overlap_validated\":false,\"rounds\":"
              << concurrentDispatch->rounds << ",\"devices\":[";
    for (std::size_t i = 0; i < concurrentDispatch->devices.size(); ++i) {
      if (i) std::cout << ',';
      const ConcurrentDispatchDevice &device = concurrentDispatch->devices[i];
      std::cout << "{\"sm\":" << device.sm
                << ",\"pci_bus_id\":\"" << jsonEscape(device.pci)
                << "\",\"kernel_name\":\"hybrid_concurrent_work\",\"rounds\":"
                << concurrentDispatch->rounds
                << ",\"numeric_result_passed\":true,\"host_window_start_ns\":"
                << device.hostWindowStartNs
                << ",\"host_window_end_ns\":" << device.hostWindowEndNs << '}';
    }
    std::cout << "]}";
  } else {
    std::cout << "null";
  }
  std::cout << ",\"peer_transfer_requested\":"
            << (peerTransferRequested ? "true" : "false")
            << ",\"peer_transfer\":";
  if (peerTransferRequested && peerTransfer)
    printPeerTransfer(*peerTransfer);
  else
    std::cout << "null";
  std::cout << ",\"driver_library_path\":\"" << jsonEscape(driverLibrary) << '"'
            << ",\"driver_api\":" << driverVersion
            << ",\"expected_device_pci_by_sm\":{";
  bool firstMapping = true;
  for (const auto &entry : expectedDevicePciBySm) {
    if (!firstMapping) std::cout << ',';
    firstMapping = false;
    std::cout << '"' << entry.first << "\":\"" << jsonEscape(entry.second) << '"';
  }
  std::cout << "},\"required_sm\":[";
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
              << ",\"performance_benchmark_passed\":"
              << (result.performanceBenchmarkPassed ? "true" : "false")
              << ",\"performance_benchmark\":";
    if (performanceBenchmark && result.performanceBenchmarkPassed)
      printPerformanceBenchmark(result.performanceBenchmark);
    else
      std::cout << "null";
    std::cout
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

  CloseFdsAtExit closeFdsAtExit{options.closeFdsOnExit};
  try {
    Api api(options.libcudaPath);
    if (!options.phase.empty()) return runPhase(api, options);
    int driverVersion = 0;
    const std::vector<DeviceInfo> inventory = enumerateDevices(api, driverVersion);
    if (!options.expectedPci.empty() &&
        (inventory.size() != 1 || canonicalPci(inventory.front().pci) != options.expectedPci)) {
      throw CudaError("selected GPU guard: expected exactly one visible GPU at " + options.expectedPci);
    }
    for (const auto &expected : options.expectedDevicePciBySm) {
      for (const DeviceInfo &device : inventory) {
        if (canonicalPci(device.pci) == expected.second && device.sm != expected.first) {
          throw CudaError("pinned PCI device reports an unexpected compute capability");
        }
      }
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
      DeviceResult &result = results[i];
      result.device = device;
      const auto expectedDevice = options.expectedDevicePciBySm.find(device.sm);
      const bool exactDeviceMatch = expectedDevice != options.expectedDevicePciBySm.end() &&
                                    canonicalPci(device.pci) == expectedDevice->second;
      result.targeted = !options.listOnly && options.requiredSm.count(device.sm) > 0 &&
                        (options.expectedDevicePciBySm.empty() || exactDeviceMatch);
      if (result.targeted) presentSm.insert(device.sm);
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
                  options.cudaGraphs, options.performanceBenchmark,
                  options.benchmarkSamples, options.benchmarkTransferSamples,
                  results[i]);
      } catch (const std::exception &error) {
        results[i].error = error.what();
      }
    }
    PeerTransferResult peerTransfer;
    bool peerTransferAttempted = false;
    if (options.peerTransfer) {
      peerTransferAttempted = true;
      try {
        peerTransfer = runPeerTransfer(api, inventory, contexts, results,
                                       options.modulePath);
      } catch (const std::exception &error) {
        peerTransfer.requested = true;
        peerTransfer.status = "query-failed";
        appendPeerError(peerTransfer, error.what());
      }
      if (peerTransfer.status == "query-failed" ||
          peerTransfer.status == "peer-kernel-failed" ||
          peerTransfer.status == "cleanup-failed" ||
          peerTransfer.status == "copy-failed" ||
          peerTransfer.hostStagedFallbackStatus == "copy-failed" ||
          peerTransfer.hostStagedFallbackStatus == "cleanup-failed")
        anyFailure = true;
    }
    ConcurrentDispatchResult concurrentDispatch;
    bool concurrentDispatchAttempted = false;
    if (options.concurrentKernels && presentSm.count(70) && presentSm.count(120)) {
      const bool coreReady = std::all_of(results.begin(), results.end(),
          [](const DeviceResult &result) {
            return !result.targeted ||
                   (result.error.empty() && result.cleanupPassed && result.archPassed &&
                    result.syncPassed && result.asyncPassed);
          });
      if (coreReady) {
        concurrentDispatchAttempted = true;
        try {
          concurrentDispatch = runConcurrentDispatch(
              api, inventory, contexts, results, options.modulePath);
          if (!concurrentDispatch.passed) anyFailure = true;
        } catch (const std::exception &error) {
          anyFailure = true;
          for (DeviceResult &result : results)
            if (result.targeted && result.error.empty()) result.error = error.what();
        }
      }
    }
    // Close explicitly before serializing, so destructor errors affect the gate.
    for (auto &context : contexts) context.reset();
    for (const DeviceResult &result : results) {
      if (!result.targeted) continue;
      if (!result.error.empty() || !result.cleanupPassed || !result.archPassed ||
          !result.syncPassed || !result.asyncPassed ||
          (options.cudaGraphs && !result.cudaGraphsPassed) ||
          (options.performanceBenchmark && !result.performanceBenchmarkPassed))
        anyFailure = true;
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
                  options.performanceBenchmark,
                  api.libraryPath, driverVersion, options.requiredSm,
                  {}, results, options.expectedDevicePciBySm,
                  options.concurrentKernels, nullptr, options.peerTransfer,
                  peerTransferAttempted ? &peerTransfer : nullptr);
      return 0;
    }
    if (anyFailure) {
      printReport("failed", false, false, contextCoexistence, options.managedMemory, options.managedPrefetch,
                  api.managedMemoryPrefetchApi,
                  options.cudaGraphs, api.cudaGraphsApi,
                  options.performanceBenchmark,
                  api.libraryPath, driverVersion, options.requiredSm,
                  missing, results, options.expectedDevicePciBySm,
                  options.concurrentKernels,
                  concurrentDispatchAttempted && concurrentDispatch.passed
                      ? &concurrentDispatch : nullptr,
                  options.peerTransfer,
                  peerTransferAttempted ? &peerTransfer : nullptr);
      return 2;
    }
    if (!missing.empty()) {
      printReport("incomplete", false, false, contextCoexistence, options.managedMemory, options.managedPrefetch,
                  api.managedMemoryPrefetchApi,
                  options.cudaGraphs, api.cudaGraphsApi,
                  options.performanceBenchmark,
                  api.libraryPath, driverVersion, options.requiredSm,
                  missing, results, options.expectedDevicePciBySm,
                  options.concurrentKernels, nullptr, options.peerTransfer,
                  peerTransferAttempted ? &peerTransfer : nullptr);
      return 77;
    }
    const bool requiredSetPassed = std::all_of(
        options.requiredSm.begin(), options.requiredSm.end(),
        [&foundSm](int sm) { return foundSm.count(sm) > 0; });
    const bool hybridValidated = requiredSetPassed &&
                                 options.requiredSm.count(70) > 0 &&
                                 options.requiredSm.count(120) > 0 && contextCoexistence &&
                                 options.expectedDevicePciBySm.size() == options.requiredSm.size() &&
                                 (!options.concurrentKernels ||
                                  (concurrentDispatchAttempted && concurrentDispatch.passed));
    printReport(hybridValidated ? "hybrid-validated" : "control-passed",
                requiredSetPassed, hybridValidated, contextCoexistence, options.managedMemory, options.managedPrefetch,
                api.managedMemoryPrefetchApi,
                options.cudaGraphs, api.cudaGraphsApi,
                options.performanceBenchmark,
                api.libraryPath, driverVersion,
                options.requiredSm, {}, results, options.expectedDevicePciBySm,
                options.concurrentKernels,
                concurrentDispatchAttempted && concurrentDispatch.passed
                    ? &concurrentDispatch : nullptr,
                options.peerTransfer,
                peerTransferAttempted ? &peerTransfer : nullptr);
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "fatal: " << error.what() << '\n';
    return 2;
  }
}
