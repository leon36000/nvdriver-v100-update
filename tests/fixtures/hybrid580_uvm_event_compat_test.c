/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>

#include "nv_uvm_types.h"
#include "nv_uvm_user_types.h"

#include "../../src/hybrid580_uvm_event_compat.h"

static NV_STATUS suspend_cb(void) { return 1; }
static NV_STATUS resume_cb(void) { return 2; }
static NV_STATUS isr_cb(const NvProcessorUuid *uuid) { (void)uuid; return 3; }
static NV_STATUS drain_cb(const NvProcessorUuid *uuid) { (void)uuid; return 4; }
static NV_STATUS resume_p2p_cb(const NvProcessorUuid *uuid) { (void)uuid; return 5; }

#define SLOT(type, field, index) \
    _Static_assert(offsetof(type, field) == (index) * sizeof(void *), \
                   #type "." #field " ABI offset changed")
SLOT(struct UvmOpsUvmEvents, suspend, 0);
SLOT(struct UvmOpsUvmEvents, resume, 1);
SLOT(struct UvmOpsUvmEvents, startDevice, 2);
SLOT(struct UvmOpsUvmEvents, stopDevice, 3);
SLOT(struct UvmOpsUvmEvents, isrTopHalf, 4);
SLOT(struct UvmOpsUvmEvents, drainP2P, 5);
SLOT(struct UvmOpsUvmEvents, resumeP2P, 6);
_Static_assert(sizeof(struct UvmOpsUvmEvents) == 7 * sizeof(void *),
               "R580 event adapter must match the 7-slot Linux ABI");
_Static_assert(sizeof(struct UvmEventsLinux) == 5 * sizeof(void *),
               "R595 Linux event table must remain 5 slots");
_Static_assert(offsetof(struct UvmEventsLinux, isrTopHalf) == 0,
               "R595 Linux ISR callback offset changed");
_Static_assert(offsetof(struct UvmEventsLinux, suspend) == sizeof(void *),
               "R595 Linux suspend callback offset changed");

int main(void)
{
    struct UvmEventsLinux modern = {
        .isrTopHalf = isr_cb,
        .suspend = suspend_cb,
        .resume = resume_cb,
        .drainP2P = drain_cb,
        .resumeP2P = resume_p2p_cb,
    };
    struct UvmOpsUvmEvents legacy =
        hybrid580_uvm_event_compat_from_linux(&modern);

    assert(legacy.suspend == suspend_cb);
    assert(legacy.resume == resume_cb);
    assert(legacy.startDevice == NULL);
    assert(legacy.stopDevice == NULL);
    assert(legacy.isrTopHalf == isr_cb);
    assert(legacy.drainP2P == drain_cb);
    assert(legacy.resumeP2P == resume_p2p_cb);
    puts("R595 Linux UVM event table maps to the R580 Linux ABI and passed");
    return 0;
}
