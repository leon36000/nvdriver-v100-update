/* SPDX-License-Identifier: MIT */
#include <linux/module.h>
#include <linux/stddef.h>

#include "nv_uvm_interface.h"
#include "nv_uvm_user_types.h"

#if defined(HYBRID_PROBE_R580)
_Static_assert(sizeof(struct UvmOpsUvmEvents) == 56,
               "R580 Linux UVM event table must be seven pointers");
_Static_assert(offsetof(struct UvmOpsUvmEvents, suspend) == 0,
               "R580 suspend slot moved");
_Static_assert(offsetof(struct UvmOpsUvmEvents, resume) == 8,
               "R580 resume slot moved");
_Static_assert(offsetof(struct UvmOpsUvmEvents, startDevice) == 16,
               "R580 startDevice slot moved");
_Static_assert(offsetof(struct UvmOpsUvmEvents, stopDevice) == 24,
               "R580 stopDevice slot moved");
_Static_assert(offsetof(struct UvmOpsUvmEvents, isrTopHalf) == 32,
               "R580 ISR slot moved");
_Static_assert(offsetof(struct UvmOpsUvmEvents, drainP2P) == 40,
               "R580 drainP2P slot moved");
_Static_assert(offsetof(struct UvmOpsUvmEvents, resumeP2P) == 48,
               "R580 resumeP2P slot moved");

static typeof(&nvUvmInterfaceRegisterUvmCallbacks) register_api
    __maybe_unused = nvUvmInterfaceRegisterUvmCallbacks;
static typeof(&nvUvmInterfaceDeRegisterUvmOps) deregister_api
    __maybe_unused = nvUvmInterfaceDeRegisterUvmOps;
#else
_Static_assert(sizeof(struct UvmEventsLinux) == 40,
               "R595 Linux UVM event table must be five pointers");
_Static_assert(offsetof(struct UvmEventsLinux, isrTopHalf) == 0,
               "R595 ISR slot moved");
_Static_assert(offsetof(struct UvmEventsLinux, suspend) == 8,
               "R595 suspend slot moved");
_Static_assert(offsetof(struct UvmEventsLinux, resume) == 16,
               "R595 resume slot moved");
_Static_assert(offsetof(struct UvmEventsLinux, drainP2P) == 24,
               "R595 drainP2P slot moved");
_Static_assert(offsetof(struct UvmEventsLinux, resumeP2P) == 32,
               "R595 resumeP2P slot moved");
_Static_assert(sizeof(UvmGpuAccessBitsBufferAlloc) == 1040,
               "R595 AccessBits payload size changed");
_Static_assert(offsetof(UvmGpuAccessBitsBufferAlloc, enabledMask) == 16,
               "R595 AccessBits enabledMask offset changed");
_Static_assert(offsetof(UvmGpuAccessBitsBufferAlloc, currentBits) == 528,
               "R595 AccessBits currentBits offset changed");

static typeof(&nvUvmInterfaceRegisterUvmEvents) register_api
    __maybe_unused = nvUvmInterfaceRegisterUvmEvents;
static typeof(&nvUvmInterfaceDeRegisterUvmEvents) deregister_api
    __maybe_unused = nvUvmInterfaceDeRegisterUvmEvents;
static typeof(&nvUvmInterfaceAccessBitsBufAlloc) access_bits_alloc_api
    __maybe_unused = nvUvmInterfaceAccessBitsBufAlloc;
static typeof(&nvUvmInterfaceAccessBitsBufFree) access_bits_free_api
    __maybe_unused = nvUvmInterfaceAccessBitsBufFree;
static typeof(&nvUvmInterfaceAccessBitsDump) access_bits_dump_api
    __maybe_unused = nvUvmInterfaceAccessBitsDump;
#endif

static int __maybe_unused hybrid_uvm_event_header_probe(void)
{
#if defined(HYBRID_PROBE_R580)
    return register_api == NULL || deregister_api == NULL;
#else
    return register_api == NULL || deregister_api == NULL ||
           access_bits_alloc_api == NULL || access_bits_free_api == NULL ||
           access_bits_dump_api == NULL;
#endif
}
