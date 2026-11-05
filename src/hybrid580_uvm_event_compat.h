/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_EVENT_COMPAT_H
#define HYBRID580_UVM_EVENT_COMPAT_H

/*
 * R595's Linux UVM ABI uses struct UvmEventsLinux (five callbacks). The
 * R580 private RM provider still imports struct UvmOpsUvmEvents (seven
 * callbacks). This declaration intentionally reproduces the R580 Linux
 * layout from common/inc/nv_uvm_types.h; keep the tag and field order exact
 * so CONFIG_MODVERSIONS can verify the legacy provider import.
 *
 * The event callback typedefs are shared by both source releases. R595 no
 * longer supplies the legacy startDevice/stopDevice callbacks, so those
 * slots are NULL. Callers must keep this adapted table alive until the R580
 * provider has completed nvUvmInterfaceDeRegisterUvmOps().
 */
struct UvmOpsUvmEvents {
    uvmEventSuspend_t suspend;
    uvmEventResume_t resume;
    uvmEventStartDevice_t startDevice;
    uvmEventStopDevice_t stopDevice;
    uvmEventIsrTopHalf_t isrTopHalf;
    uvmEventDrainP2P_t drainP2P;
    uvmEventResumeP2P_t resumeP2P;
};

static inline struct UvmOpsUvmEvents
hybrid580_uvm_event_compat_from_linux(const struct UvmEventsLinux *events)
{
    return (struct UvmOpsUvmEvents) {
        .suspend = events->suspend,
        .resume = events->resume,
        .startDevice = NULL,
        .stopDevice = NULL,
        .isrTopHalf = events->isrTopHalf,
        .drainP2P = events->drainP2P,
        .resumeP2P = events->resumeP2P,
    };
}

#endif /* HYBRID580_UVM_EVENT_COMPAT_H */
