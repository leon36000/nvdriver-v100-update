#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
// SPDX-License-Identifier: MIT
// Test-only VMM peer-memory read probe. This does not enable production P2P.
#include <cuda.h>

#include <dlfcn.h>
#include <link.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using CtxCreateV2 = CUresult(CUDAAPI *)(CUcontext *, unsigned int, CUdevice);

struct Failure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

std::string jsonEscape(const std::string &value) {
  std::string out;
  for (unsigned char c : value) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          const char hex[] = "0123456789abcdef";
          out += "\\u00";
          out += hex[c >> 4];
          out += hex[c & 0xf];
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out;
}

struct Api {
  void *library{};
  std::string libraryPath;
  decltype(&cuInit) init{};
  decltype(&cuDriverGetVersion) driverGetVersion{};
  decltype(&cuDeviceGetCount) deviceGetCount{};
  decltype(&cuDeviceGet) deviceGet{};
  decltype(&cuDeviceGetName) deviceGetName{};
  decltype(&cuDeviceGetPCIBusId) deviceGetPciBusId{};
  decltype(&cuDeviceGetAttribute) deviceGetAttribute{};
  decltype(&cuDeviceCanAccessPeer) deviceCanAccessPeer{};
  CtxCreateV2 contextCreate{};
  decltype(&cuCtxDestroy_v2) contextDestroy{};
  decltype(&cuCtxSetCurrent) contextSetCurrent{};
  decltype(&cuCtxSynchronize) contextSynchronize{};
  decltype(&cuModuleLoad) moduleLoad{};
  decltype(&cuModuleUnload) moduleUnload{};
  decltype(&cuModuleGetFunction) moduleGetFunction{};
  decltype(&cuMemAlloc_v2) memoryAlloc{};
  decltype(&cuMemFree_v2) memoryFree{};
  decltype(&cuMemcpyHtoD_v2) copyHostToDevice{};
  decltype(&cuMemcpyDtoH_v2) copyDeviceToHost{};
  decltype(&cuLaunchKernel) launchKernel{};
  decltype(&cuMemGetAllocationGranularity) getGranularity{};
  decltype(&cuMemCreate) memoryCreate{};
  decltype(&cuMemAddressReserve) addressReserve{};
  decltype(&cuMemMap) memoryMap{};
  decltype(&cuMemSetAccess) memorySetAccess{};
  decltype(&cuMemGetAccess) memoryGetAccess{};
  decltype(&cuMemUnmap) memoryUnmap{};
  decltype(&cuMemRelease) memoryRelease{};
  decltype(&cuMemAddressFree) addressFree{};
  decltype(&cuGetErrorName) getErrorName{};
  decltype(&cuGetErrorString) getErrorString{};

  template <typename T>
  T symbol(const char *name) {
    dlerror();
    void *address = dlsym(library, name);
    const char *error = dlerror();
    if (error || !address) {
      std::string message("libcuda.so.1 is missing ");
      message.append(name);
      if (error) {
        message.append(": ");
        message.append(error);
      }
      throw Failure(std::move(message));
    }
    return reinterpret_cast<T>(address);
  }

  void load() {
    library = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library) {
      std::string message("dlopen(libcuda.so.1): ");
      message.append(dlerror());
      throw Failure(std::move(message));
    }
    link_map *mapping = nullptr;
    if (dlinfo(library, RTLD_DI_LINKMAP, &mapping) == 0 && mapping && mapping->l_name)
      libraryPath = mapping->l_name;
    if (libraryPath.empty()) throw Failure("could not identify the loaded libcuda path");
#define LOAD(member, name) member = symbol<decltype(member)>(name)
    LOAD(init, "cuInit");
    LOAD(driverGetVersion, "cuDriverGetVersion");
    LOAD(deviceGetCount, "cuDeviceGetCount");
    LOAD(deviceGet, "cuDeviceGet");
    LOAD(deviceGetName, "cuDeviceGetName");
    LOAD(deviceGetPciBusId, "cuDeviceGetPCIBusId");
    LOAD(deviceGetAttribute, "cuDeviceGetAttribute");
    LOAD(deviceCanAccessPeer, "cuDeviceCanAccessPeer");
    LOAD(contextCreate, "cuCtxCreate_v2");
    LOAD(contextDestroy, "cuCtxDestroy_v2");
    LOAD(contextSetCurrent, "cuCtxSetCurrent");
    LOAD(contextSynchronize, "cuCtxSynchronize");
    LOAD(moduleLoad, "cuModuleLoad");
    LOAD(moduleUnload, "cuModuleUnload");
    LOAD(moduleGetFunction, "cuModuleGetFunction");
    LOAD(memoryAlloc, "cuMemAlloc_v2");
    LOAD(memoryFree, "cuMemFree_v2");
    LOAD(copyHostToDevice, "cuMemcpyHtoD_v2");
    LOAD(copyDeviceToHost, "cuMemcpyDtoH_v2");
    LOAD(launchKernel, "cuLaunchKernel");
    LOAD(getGranularity, "cuMemGetAllocationGranularity");
    LOAD(memoryCreate, "cuMemCreate");
    LOAD(addressReserve, "cuMemAddressReserve");
    LOAD(memoryMap, "cuMemMap");
    LOAD(memorySetAccess, "cuMemSetAccess");
    LOAD(memoryGetAccess, "cuMemGetAccess");
    LOAD(memoryUnmap, "cuMemUnmap");
    LOAD(memoryRelease, "cuMemRelease");
    LOAD(addressFree, "cuMemAddressFree");
    LOAD(getErrorName, "cuGetErrorName");
    LOAD(getErrorString, "cuGetErrorString");
#undef LOAD
  }

  std::string describe(CUresult result) const {
    const char *name = nullptr;
    const char *message = nullptr;
    getErrorName(result, &name);
    getErrorString(result, &message);
    std::string description(name ? name : "CUDA_ERROR_UNKNOWN");
    description.append(" (");
    description.append(std::to_string(result));
    description.push_back(')');
    if (message) {
      description.append(": ");
      description.append(message);
    }
    return description;
  }

  void check(CUresult result, const std::string &operation) const {
    if (result != CUDA_SUCCESS) {
      std::string message(operation);
      message.append(": ");
      message.append(describe(result));
      throw Failure(std::move(message));
    }
  }
};

struct Device {
  int ordinal{};
  CUdevice handle{};
  int sm{};
  int vmmSupported{};
  std::string pci;
  std::string name;
};

struct Direction {
  Device *source{};
  Device *destination{};
  bool peerCapability{};
  std::size_t granularity{};
  std::size_t allocationBytes{};
  bool allocationCreated{};
  bool mappingCreated{};
  bool accessConfigured{};
  bool sourceAccessVerified{};
  bool destinationAccessVerified{};
  bool kernelAttempted{};
  bool kernelPassed{};
  bool cleanupPassed{true};
  std::string error;
  std::vector<std::string> cleanupErrors;
};

void append(std::string &to, const std::string &text) {
  if (!to.empty()) to += "; ";
  to += text;
}

void cleanupCall(Api &api, CUresult result, const std::string &operation,
                 Direction &direction) {
  if (result == CUDA_SUCCESS) return;
  direction.cleanupPassed = false;
  std::string message(operation);
  message.append(": ");
  message.append(api.describe(result));
  direction.cleanupErrors.push_back(std::move(message));
}

std::uint32_t pattern(std::uint32_t index) {
  return index * 2654435761U + 0x9e3779b9U;
}

Direction runDirection(Api &api, Device &source, Device &destination,
                       CUcontext sourceContext, CUcontext destinationContext,
                       CUmodule destinationModule, unsigned int count) {
  Direction result;
  result.source = &source;
  result.destination = &destination;
  CUmemGenericAllocationHandle allocation{};
  CUdeviceptr address{};
  CUdeviceptr output{};
  bool allocationCreated = false;
  bool addressReserved = false;
  bool mappingCreated = false;
  bool outputCreated = false;

  try {
    int canAccess = 0;
    api.check(api.deviceCanAccessPeer(&canAccess, destination.handle, source.handle),
              "cuDeviceCanAccessPeer(destination, source)");
    result.peerCapability = canAccess != 0;
    api.check(api.contextSetCurrent(sourceContext), "cuCtxSetCurrent(source)");

    CUmemAllocationProp prop{};
    prop.type = CU_MEM_ALLOCATION_TYPE_PINNED;
    prop.requestedHandleTypes = CU_MEM_HANDLE_TYPE_NONE;
    prop.location.type = CU_MEM_LOCATION_TYPE_DEVICE;
    prop.location.id = source.ordinal;
    api.check(api.getGranularity(&result.granularity, &prop,
                                 CU_MEM_ALLOC_GRANULARITY_MINIMUM),
              "cuMemGetAllocationGranularity");
    if (!result.granularity)
      throw Failure("cuMemGetAllocationGranularity returned zero");
    const std::size_t dataBytes = static_cast<std::size_t>(count) * sizeof(std::uint32_t);
    result.allocationBytes = std::max(result.granularity, dataBytes);
    const std::size_t remainder = result.allocationBytes % result.granularity;
    if (remainder) {
      const std::size_t increment = result.granularity - remainder;
      if (result.allocationBytes > std::numeric_limits<std::size_t>::max() - increment)
        throw Failure("VMM allocation size overflow while aligning to granularity");
      result.allocationBytes += increment;
    }

    api.check(api.memoryCreate(&allocation, result.allocationBytes, &prop, 0),
              "cuMemCreate(source-device VMM allocation)");
    allocationCreated = true;
    result.allocationCreated = true;
    api.check(api.addressReserve(&address, result.allocationBytes, 0, 0, 0),
              "cuMemAddressReserve");
    addressReserved = true;
    api.check(api.memoryMap(address, result.allocationBytes, 0, allocation, 0),
              "cuMemMap");
    mappingCreated = true;
    result.mappingCreated = true;

    CUmemAccessDesc access[2]{};
    access[0].location.type = CU_MEM_LOCATION_TYPE_DEVICE;
    access[0].location.id = source.ordinal;
    access[0].flags = CU_MEM_ACCESS_FLAGS_PROT_READWRITE;
    access[1].location.type = CU_MEM_LOCATION_TYPE_DEVICE;
    access[1].location.id = destination.ordinal;
    access[1].flags = CU_MEM_ACCESS_FLAGS_PROT_READ;
    api.check(api.memorySetAccess(address, result.allocationBytes, access, 2),
              "cuMemSetAccess(source read-write, destination read)");
    result.accessConfigured = true;

    unsigned long long sourceFlags = 0;
    CUmemLocation sourceLocation{CU_MEM_LOCATION_TYPE_DEVICE, source.ordinal};
    api.check(api.memoryGetAccess(&sourceFlags, &sourceLocation, address),
              "cuMemGetAccess(source)");
    result.sourceAccessVerified =
        (sourceFlags & CU_MEM_ACCESS_FLAGS_PROT_READWRITE) ==
        CU_MEM_ACCESS_FLAGS_PROT_READWRITE;
    unsigned long long destinationFlags = 0;
    CUmemLocation destinationLocation{CU_MEM_LOCATION_TYPE_DEVICE, destination.ordinal};
    api.check(api.memoryGetAccess(&destinationFlags, &destinationLocation, address),
              "cuMemGetAccess(destination)");
    result.destinationAccessVerified =
        (destinationFlags & CU_MEM_ACCESS_FLAGS_PROT_READ) == CU_MEM_ACCESS_FLAGS_PROT_READ &&
        (destinationFlags & CU_MEM_ACCESS_FLAGS_PROT_READWRITE) !=
            CU_MEM_ACCESS_FLAGS_PROT_READWRITE;
    if (!result.sourceAccessVerified || !result.destinationAccessVerified)
      throw Failure("cuMemGetAccess returned permissions different from the requested policy");

    std::vector<std::uint32_t> expected(count);
    std::vector<std::uint32_t> actual(count, 0U);
    for (unsigned int i = 0; i < count; ++i) expected[i] = pattern(i);
    api.check(api.copyHostToDevice(address, expected.data(),
                                   static_cast<std::size_t>(count) * sizeof(std::uint32_t)),
              "cuMemcpyHtoD_v2(source VMM initialize)");

    api.check(api.contextSetCurrent(destinationContext), "cuCtxSetCurrent(destination)");
    api.check(api.memoryAlloc(&output,
                              static_cast<std::size_t>(count) * sizeof(std::uint32_t)),
              "cuMemAlloc_v2(destination output)");
    outputCreated = true;
    CUfunction function{};
    api.check(api.moduleGetFunction(&function, destinationModule, "hybrid_peer_read"),
              "cuModuleGetFunction(hybrid_peer_read)");
    CUdeviceptr remote = address;
    void *arguments[] = {&remote, &output, &count};
    result.kernelAttempted = true;
    api.check(api.launchKernel(function, (count + 255U) / 256U, 1, 1,
                               256, 1, 1, 0, nullptr, arguments, nullptr),
              "cuLaunchKernel(hybrid_peer_read VMM peer)");
    api.check(api.contextSynchronize(), "cuCtxSynchronize(destination VMM peer)");
    api.check(api.copyDeviceToHost(actual.data(), output,
                                   static_cast<std::size_t>(count) * sizeof(std::uint32_t)),
              "cuMemcpyDtoH_v2(VMM peer result)");
    result.kernelPassed = actual == expected;
    if (!result.kernelPassed) throw Failure("VMM peer kernel result mismatch");
  } catch (const std::exception &error) {
    result.error = error.what();
  }

  if (outputCreated) {
    const CUresult current = api.contextSetCurrent(destinationContext);
    cleanupCall(api, current, "cuCtxSetCurrent(destination cleanup)", result);
    if (current == CUDA_SUCCESS)
      cleanupCall(api, api.memoryFree(output), "cuMemFree_v2(destination output)", result);
    else
      result.cleanupErrors.emplace_back("cuMemFree_v2(destination output) skipped: destination context not current");
  }
  const CUresult sourceCurrent = api.contextSetCurrent(sourceContext);
  cleanupCall(api, sourceCurrent, "cuCtxSetCurrent(source cleanup)", result);
  if (sourceCurrent == CUDA_SUCCESS) {
    bool unmapSucceeded = true;
    if (mappingCreated) {
      const CUresult unmapped = api.memoryUnmap(address, result.allocationBytes);
      cleanupCall(api, unmapped, "cuMemUnmap", result);
      unmapSucceeded = unmapped == CUDA_SUCCESS;
    }
    if (allocationCreated) {
      if (unmapSucceeded) {
        cleanupCall(api, api.memoryRelease(allocation), "cuMemRelease", result);
      } else {
        result.cleanupPassed = false;
        result.cleanupErrors.emplace_back("cuMemRelease skipped: cuMemUnmap failed");
      }
    }
    if (addressReserved) {
      if (unmapSucceeded) {
        cleanupCall(api, api.addressFree(address, result.allocationBytes), "cuMemAddressFree", result);
      } else {
        result.cleanupPassed = false;
        result.cleanupErrors.emplace_back("cuMemAddressFree skipped: cuMemUnmap failed");
      }
    }
  } else {
    if (mappingCreated) result.cleanupErrors.emplace_back("cuMemUnmap skipped: source context not current");
    if (allocationCreated) result.cleanupErrors.emplace_back("cuMemRelease skipped: source context not current");
    if (addressReserved) result.cleanupErrors.emplace_back("cuMemAddressFree skipped: source context not current");
  }
  for (const auto &error : result.cleanupErrors) append(result.error, error);
  return result;
}

void printDirection(const Direction &direction) {
  std::cout << "{\"source_sm\":" << direction.source->sm
            << ",\"destination_sm\":" << direction.destination->sm
            << ",\"source_pci_bus_id\":\"" << jsonEscape(direction.source->pci)
            << "\",\"destination_pci_bus_id\":\""
            << jsonEscape(direction.destination->pci)
            << "\",\"peer_capability\":"
            << (direction.peerCapability ? "true" : "false")
            << ",\"allocation_granularity_bytes\":" << direction.granularity
            << ",\"allocation_bytes\":" << direction.allocationBytes
            << ",\"allocation_created\":" << (direction.allocationCreated ? "true" : "false")
            << ",\"mapping_created\":" << (direction.mappingCreated ? "true" : "false")
            << ",\"access_configured\":" << (direction.accessConfigured ? "true" : "false")
            << ",\"source_access_verified\":" << (direction.sourceAccessVerified ? "true" : "false")
            << ",\"destination_readonly_access_verified\":"
            << (direction.destinationAccessVerified ? "true" : "false")
            << ",\"kernel_attempted\":" << (direction.kernelAttempted ? "true" : "false")
            << ",\"kernel_passed\":" << (direction.kernelPassed ? "true" : "false")
            << ",\"cleanup_passed\":" << (direction.cleanupPassed ? "true" : "false")
            << ",\"cleanup_errors\":[";
  for (std::size_t i = 0; i < direction.cleanupErrors.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << '"' << jsonEscape(direction.cleanupErrors[i]) << '"';
  }
  std::cout << "],\"error\":\"" << jsonEscape(direction.error) << "\"}";
}

std::string normalizePci(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (value.size() == 7) value.insert(0, "0000:");
  return value;
}

int mainImpl(int argc, char **argv) {
  std::string modulePath;
  std::map<int, std::string> expectedPci;
  unsigned int count = 1024;
  for (int i = 1; i < argc; ++i) {
    const std::string arg(argv[i]);
    if (arg == "--module" && i + 1 < argc) {
      modulePath = argv[++i];
    } else if (arg == "--expected-device" && i + 1 < argc) {
      const std::string spec(argv[++i]);
      const auto equal = spec.find('=');
      if (equal == std::string::npos) throw Failure("expected device format is SM=PCI");
      const std::string smText = spec.substr(0, equal);
      std::size_t parsedCharacters = 0;
      const int sm = std::stoi(smText, &parsedCharacters, 10);
      if (parsedCharacters != smText.size())
        throw Failure("compute capability must be a decimal integer");
      if ((sm != 70 && sm != 120) || expectedPci.count(sm))
        throw Failure("exactly one expected device per SM70 and SM120 is required");
      expectedPci[sm] = normalizePci(spec.substr(equal + 1));
    } else if (arg == "--count" && i + 1 < argc) {
      const std::string countText(argv[++i]);
      std::size_t parsedCharacters = 0;
      const unsigned long parsed = std::stoul(countText, &parsedCharacters, 10);
      if (parsedCharacters != countText.size())
        throw Failure("count must be a decimal integer");
      if (parsed == 0 || parsed > (1U << 20)) throw Failure("count must be in 1..1048576");
      count = static_cast<unsigned int>(parsed);
    } else if (arg == "--help") {
      std::cout << "Usage: " << argv[0]
                << " --module FILE --expected-device 70=PCI --expected-device 120=PCI [--count N]\n";
      return 0;
    } else {
      std::string message("unknown or incomplete argument: ");
      message.append(arg);
      throw Failure(std::move(message));
    }
  }
  if (modulePath.empty() || expectedPci.size() != 2 || !expectedPci.count(70) ||
      !expectedPci.count(120))
    throw Failure("module and exact SM70/SM120 PCI identities are required");

  Api api;
  api.load();
  api.check(api.init(0), "cuInit");
  int driverVersion = 0;
  api.check(api.driverGetVersion(&driverVersion), "cuDriverGetVersion");
  int deviceCount = 0;
  api.check(api.deviceGetCount(&deviceCount), "cuDeviceGetCount");
  std::vector<Device> devices;
  for (int ordinal = 0; ordinal < deviceCount; ++ordinal) {
    Device device;
    device.ordinal = ordinal;
    api.check(api.deviceGet(&device.handle, ordinal), "cuDeviceGet");
    char pci[64]{};
    char name[256]{};
    int major = 0, minor = 0;
    api.check(api.deviceGetPciBusId(pci, sizeof(pci), device.handle), "cuDeviceGetPCIBusId");
    api.check(api.deviceGetName(name, sizeof(name), device.handle), "cuDeviceGetName");
    api.check(api.deviceGetAttribute(&major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
                                     device.handle), "cuDeviceGetAttribute(SM major)");
    api.check(api.deviceGetAttribute(&minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
                                     device.handle), "cuDeviceGetAttribute(SM minor)");
    api.check(api.deviceGetAttribute(&device.vmmSupported,
                                     CU_DEVICE_ATTRIBUTE_VIRTUAL_MEMORY_MANAGEMENT_SUPPORTED,
                                     device.handle), "cuDeviceGetAttribute(VMM support)");
    device.sm = major * 10 + minor;
    device.pci = normalizePci(pci);
    device.name = name;
    devices.push_back(device);
  }

  Device *sm70 = nullptr;
  Device *sm120 = nullptr;
  for (auto &device : devices) {
    if (device.sm == 70 && device.pci == expectedPci.at(70)) sm70 = &device;
    if (device.sm == 120 && device.pci == expectedPci.at(120)) sm120 = &device;
  }
  if (!sm70 || !sm120)
    throw Failure("exact expected SM70 and SM120 PCI devices were not enumerated");
  if (!sm70->vmmSupported || !sm120->vmmSupported)
    throw Failure("one or both exact devices report VMM unsupported");

  CUcontext context70{}, context120{};
  CUmodule module70{}, module120{};
  bool context70Created = false, context120Created = false;
  bool module70Loaded = false, module120Loaded = false;
  std::vector<Direction> directions;
  std::string setupError;
  try {
    api.check(api.contextCreate(&context70, CU_CTX_SCHED_AUTO, sm70->handle),
              "cuCtxCreate_v2(SM70)");
    context70Created = true;
    api.check(api.contextCreate(&context120, CU_CTX_SCHED_AUTO, sm120->handle),
              "cuCtxCreate_v2(SM120)");
    context120Created = true;
    api.check(api.contextSetCurrent(context70), "cuCtxSetCurrent(SM70 module)");
    api.check(api.moduleLoad(&module70, modulePath.c_str()), "cuModuleLoad(SM70)");
    module70Loaded = true;
    api.check(api.contextSetCurrent(context120), "cuCtxSetCurrent(SM120 module)");
    api.check(api.moduleLoad(&module120, modulePath.c_str()), "cuModuleLoad(SM120)");
    module120Loaded = true;
    directions.push_back(runDirection(api, *sm70, *sm120, context70, context120,
                                      module120, count));
    if (directions.back().cleanupPassed) {
      directions.push_back(runDirection(api, *sm120, *sm70, context120, context70,
                                        module70, count));
    } else {
      append(setupError, "reverse VMM direction skipped after prior direction cleanup failure");
    }
  } catch (const std::exception &error) {
    setupError = error.what();
  }

  bool cleanupPassed = true;
  auto cleanup = [&](CUcontext context, bool &loaded, CUmodule module,
                     bool &created, const char *label) {
    if (!created) return;
    if (loaded) {
      CUresult current = api.contextSetCurrent(context);
      if (current != CUDA_SUCCESS) {
        cleanupPassed = false;
        std::string message("cuCtxSetCurrent(");
        message.append(label);
        message.append(" unload): ");
        message.append(api.describe(current));
        append(setupError, message);
      } else {
        CUresult unloaded = api.moduleUnload(module);
        if (unloaded != CUDA_SUCCESS) {
          cleanupPassed = false;
          std::string message("cuModuleUnload(");
          message.append(label);
          message.append("): ");
          message.append(api.describe(unloaded));
          append(setupError, message);
        }
      }
    }
    CUresult destroyed = api.contextDestroy(context);
    if (destroyed != CUDA_SUCCESS) {
      cleanupPassed = false;
      std::string message("cuCtxDestroy_v2(");
      message.append(label);
      message.append("): ");
      message.append(api.describe(destroyed));
      append(setupError, message);
    }
    created = false;
  };
  cleanup(context120, module120Loaded, module120, context120Created, "SM120");
  cleanup(context70, module70Loaded, module70, context70Created, "SM70");

  const std::size_t passedDirections = static_cast<std::size_t>(std::count_if(
      directions.begin(), directions.end(), [](const Direction &d) {
        return d.kernelPassed && d.cleanupPassed;
      }));
  cleanupPassed = cleanupPassed && std::all_of(
      directions.begin(), directions.end(), [](const Direction &d) { return d.cleanupPassed; });
  const bool passed = directions.size() == 2 && passedDirections == 2 && cleanupPassed;
  const std::string status = passed ? "vmm-peer-memory-verified" :
      (passedDirections == 1 ? "one-way-vmm-peer-memory-verified" :
       (directions.empty() ? "setup-failed" : "vmm-peer-memory-failed"));
  std::cout << "{\"schema\":\"nvidia-hybrid-vmm-peer-probe-v1\",\"status\":\""
            << status << "\",\"passed\":" << (passed ? "true" : "false")
            << ",\"driver_version\":" << driverVersion
            << ",\"libcuda_path\":\"" << jsonEscape(api.libraryPath)
            << "\",\"module_path\":\"" << jsonEscape(modulePath)
            << "\",\"cuda_vmm_mode\":\"explicit-vmm-access-no-cuCtxEnablePeerAccess\""
            << ",\"direct_dma_attested\":false,\"requested_count\":" << count
            << ",\"sm70_pci_bus_id\":\"" << jsonEscape(sm70->pci)
            << "\",\"sm120_pci_bus_id\":\"" << jsonEscape(sm120->pci)
            << "\",\"sm70_name\":\"" << jsonEscape(sm70->name)
            << "\",\"sm120_name\":\"" << jsonEscape(sm120->name)
            << "\",\"cleanup_passed\":" << (cleanupPassed ? "true" : "false")
            << ",\"directions\":[";
  for (std::size_t i = 0; i < directions.size(); ++i) {
    if (i) std::cout << ',';
    printDirection(directions[i]);
  }
  std::cout << "],\"error\":\"" << jsonEscape(setupError) << "\"}\n";
  return passed ? 0 : 2;
}

}  // namespace

int main(int argc, char **argv) {
  try {
    return mainImpl(argc, argv);
  } catch (const std::exception &error) {
    std::cout << "{\"schema\":\"nvidia-hybrid-vmm-peer-probe-v1\","
              << "\"status\":\"preflight-failed\",\"passed\":false,"
              << "\"direct_dma_attested\":false,\"directions\":[],\"error\":\""
              << jsonEscape(error.what()) << "\"}\n";
    return 2;
  }
}
