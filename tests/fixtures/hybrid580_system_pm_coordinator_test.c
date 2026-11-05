/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../src/hybrid580_pm_recovery_status.h"
#include "../../src/hybrid580_system_pm_coordinator.h"

enum event {
    EVENT_BLOCK = 1,
    EVENT_FREEZER_COMPLETE,
    EVENT_DRAIN,
    EVENT_SUSPEND_OPEN,
    EVENT_SUSPEND_LEGACY,
    EVENT_DRAIN_IRQS_OPEN,
    EVENT_DRAIN_IRQS_LEGACY,
    EVENT_SUSPEND_UVM,
    EVENT_VERIFY_OPEN,
    EVENT_VERIFY_LEGACY,
    EVENT_RESUME_UVM,
    EVENT_RESTORE_LEGACY,
    EVENT_RESTORE_OPEN,
    EVENT_SUPPLIERS_RESUMED,
    EVENT_POST_NOTIFIER,
    EVENT_UNBLOCK,
};

struct fake_pm {
    enum event events[32];
    size_t event_count;
    enum event fail_event;
    enum event second_fail_event;
    struct hybrid580_pm_recovery_status recovery[2];
    bool gpu_suspended[2];
    int fallback_resume_error[2];
    unsigned long long armed_generation;
    enum hybrid580_pm_dpm_event last_recovery_event;
    unsigned int thaw_recovery_calls;
    int fail_arm_backend_plus_one;
    unsigned int recovery_end_calls[2];
    int fail_end_backend_plus_one;
    bool channels_attempted[2];
};

static int record(struct fake_pm *pm, enum event event)
{
    assert(pm->event_count < sizeof(pm->events) / sizeof(pm->events[0]));
    pm->events[pm->event_count++] = event;
    return pm->fail_event == event || pm->second_fail_event == event ? -EIO : 0;
}

static int block(void *context) { return record(context, EVENT_BLOCK); }
static int drain(void *context) { return record(context, EVENT_DRAIN); }
static int begin_recovery_cycle(void *context, unsigned int backend,
                                unsigned long long generation)
{
    struct fake_pm *pm = context;
    int error;

    if (backend > HYBRID580_PM_BACKEND_LEGACY)
        return -EINVAL;
    if (pm->fail_arm_backend_plus_one == (int)backend + 1)
        return -EIO;
    error = hybrid580_pm_recovery_begin(&pm->recovery[backend], generation);
    if (error == 0)
        pm->armed_generation = generation;
    return error;
}

static int end_recovery_cycle(void *context, unsigned int backend,
                              unsigned long long generation)
{
    struct fake_pm *pm = context;

    if (backend > HYBRID580_PM_BACKEND_LEGACY)
        return -EINVAL;
    pm->recovery_end_calls[backend]++;
    if (pm->fail_end_backend_plus_one == (int)backend + 1)
        return -EIO;
    return hybrid580_pm_recovery_end(&pm->recovery[backend], generation);
}

static int suspend_channels(void *context, unsigned int backend)
{
    struct fake_pm *pm = context;
    int error;

    if (backend > HYBRID580_PM_BACKEND_LEGACY)
        return -EINVAL;
    pm->channels_attempted[backend] = true;
    error = record(pm, backend == HYBRID580_PM_BACKEND_OPEN ?
                   EVENT_SUSPEND_OPEN : EVENT_SUSPEND_LEGACY);
    return error;
}
static int drain_irqs(void *context, unsigned int backend)
{
    struct fake_pm *pm = context;

    if (backend > HYBRID580_PM_BACKEND_LEGACY)
        return -EINVAL;
    return record(pm, backend == HYBRID580_PM_BACKEND_OPEN ?
                  EVENT_DRAIN_IRQS_OPEN : EVENT_DRAIN_IRQS_LEGACY);
}
static int suspend_uvm(void *context) { return record(context, EVENT_SUSPEND_UVM); }
static int recover_and_verify_devices(void *context, unsigned int backend,
                                      unsigned long long generation,
                                      enum hybrid580_pm_dpm_event event)
{
    struct fake_pm *pm = context;
    int error;

    if (backend > HYBRID580_PM_BACKEND_LEGACY)
        return -EINVAL;
    error = record(pm, backend == HYBRID580_PM_BACKEND_OPEN ?
                   EVENT_VERIFY_OPEN : EVENT_VERIFY_LEGACY);
    if (error != 0)
        return error;
    pm->last_recovery_event = event;
    if ((event == HYBRID580_PM_DPM_THAW || event == HYBRID580_PM_DPM_RECOVER) &&
        pm->gpu_suspended[backend]) {
        pm->thaw_recovery_calls++;
        if (pm->fallback_resume_error[backend] != 0) {
            hybrid580_pm_recovery_record(&pm->recovery[backend], generation,
                                         pm->fallback_resume_error[backend]);
        } else {
            pm->gpu_suspended[backend] = false;
            hybrid580_pm_recovery_record(&pm->recovery[backend], generation, 0);
        }
    }
    error = hybrid580_pm_recovery_check(&pm->recovery[backend], generation);
    if (error != 0)
        return error;
    return pm->gpu_suspended[backend] ? -EIO : 0;
}
static int resume_uvm(void *context) { return record(context, EVENT_RESUME_UVM); }
static int restore_channels(void *context, unsigned int backend)
{
    struct fake_pm *pm = context;
    int error;

    if (backend > HYBRID580_PM_BACKEND_LEGACY)
        return -EINVAL;
    error = record(pm, backend == HYBRID580_PM_BACKEND_OPEN ?
                   EVENT_RESTORE_OPEN : EVENT_RESTORE_LEGACY);
    if (error == 0)
        pm->channels_attempted[backend] = false;
    return error;
}
static int unblock(void *context) { return record(context, EVENT_UNBLOCK); }

static struct hybrid580_system_pm_ops ops_for(struct fake_pm *pm)
{
    return (struct hybrid580_system_pm_ops){
        .context = pm,
        .block_frontend = block,
        .drain_frontend = drain,
        .begin_recovery_cycle = begin_recovery_cycle,
        .end_recovery_cycle = end_recovery_cycle,
        .suspend_channels = suspend_channels,
        .drain_irqs = drain_irqs,
        .suspend_uvm = suspend_uvm,
        .recover_and_verify_devices = recover_and_verify_devices,
        .resume_uvm = resume_uvm,
        .restore_channels = restore_channels,
        .unblock_frontend = unblock,
    };
}

static void record_supplier_results_for_event(struct fake_pm *pm,
                                             unsigned long long generation,
                                             enum hybrid580_pm_dpm_event event,
                                             int open_error, int legacy_error)
{
    record(pm, EVENT_SUPPLIERS_RESUMED);
    assert(hybrid580_pm_recovery_record(&pm->recovery[HYBRID580_PM_BACKEND_OPEN],
                                        generation, open_error) == 0);
    assert(hybrid580_pm_recovery_record(&pm->recovery[HYBRID580_PM_BACKEND_LEGACY],
                                        generation, legacy_error) == 0);
    pm->gpu_suspended[HYBRID580_PM_BACKEND_OPEN] =
        (event == HYBRID580_PM_DPM_THAW ||
         event == HYBRID580_PM_DPM_RECOVER || open_error != 0);
    pm->gpu_suspended[HYBRID580_PM_BACKEND_LEGACY] =
        (event == HYBRID580_PM_DPM_THAW ||
         event == HYBRID580_PM_DPM_RECOVER || legacy_error != 0);
}

static void record_supplier_results(struct fake_pm *pm,
                                    unsigned long long generation,
                                    int open_error, int legacy_error)
{
    record_supplier_results_for_event(pm, generation,
                                      HYBRID580_PM_DPM_RESUME,
                                      open_error, legacy_error);
}

static void expect_events(const struct fake_pm *pm, const enum event *events,
                          size_t count)
{
    assert(pm->event_count == count);
    assert(memcmp(pm->events, events, count * sizeof(events[0])) == 0);
}

static int begin_and_suspend(struct fake_pm *pm,
                             struct hybrid580_system_pm *state,
                             const struct hybrid580_system_pm_ops *ops)
{
    assert(hybrid580_system_pm_begin(state, ops) == HYBRID580_PM_OK);
    assert(pm->event_count == 1 && pm->events[0] == EVENT_BLOCK);
    record(pm, EVENT_FREEZER_COMPLETE);
    return hybrid580_system_pm_suspend_after_freezer(state, ops);
}

static void test_suspend_resume_order_and_single_uvm_pair(void)
{
    struct fake_pm pm = {0};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);
    const enum event expected[] = {
        EVENT_BLOCK, EVENT_FREEZER_COMPLETE, EVENT_DRAIN,
        EVENT_SUSPEND_OPEN, EVENT_SUSPEND_LEGACY,
        EVENT_DRAIN_IRQS_OPEN, EVENT_DRAIN_IRQS_LEGACY,
        EVENT_SUSPEND_UVM, EVENT_SUPPLIERS_RESUMED,
        EVENT_VERIFY_OPEN, EVENT_VERIFY_LEGACY,
        EVENT_RESUME_UVM, EVENT_RESTORE_LEGACY, EVENT_RESTORE_OPEN,
        EVENT_POST_NOTIFIER, EVENT_UNBLOCK,
    };

    assert(hybrid580_system_pm_begin(&state, &ops) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_ADMISSION_CLOSED);
    assert(pm.event_count == 1 && pm.events[0] == EVENT_BLOCK);
    record(&pm, EVENT_FREEZER_COMPLETE);
    assert(hybrid580_system_pm_suspend_after_freezer(&state, &ops) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_SUSPENDED);
    assert(state.channels_suspended == HYBRID580_PM_ALL_BACKENDS);
    assert(state.frontend_blocked && state.uvm_suspended);
    assert(hybrid580_system_pm_begin(&state, &ops) == HYBRID580_PM_BUSY);
    record_supplier_results(&pm, state.generation, 0, 0);
    assert(hybrid580_system_pm_resume_after_suppliers(&state, &ops) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_DPM_RESUMED && state.frontend_blocked);
    record(&pm, EVENT_POST_NOTIFIER);
    assert(hybrid580_system_pm_complete(&state, &ops) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_RUNNING);
    assert(!state.frontend_blocked && !state.uvm_suspended);
    assert(state.channels_suspended == 0);
    assert(hybrid580_system_pm_resume_after_suppliers(&state, &ops) ==
           HYBRID580_PM_INVALID);
    expect_events(&pm, expected, sizeof(expected) / sizeof(expected[0]));
}

static void test_partial_channel_suspend_rolls_back_in_reverse(void)
{
    struct fake_pm pm = {.fail_event = EVENT_SUSPEND_LEGACY};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);
    const enum event expected[] = {
        EVENT_BLOCK, EVENT_FREEZER_COMPLETE, EVENT_DRAIN,
        EVENT_SUSPEND_OPEN, EVENT_SUSPEND_LEGACY,
        EVENT_RESTORE_LEGACY, EVENT_RESTORE_OPEN,
        EVENT_UNBLOCK,
    };

    assert(begin_and_suspend(&pm, &state, &ops) == -EIO);
    assert(state.phase == HYBRID580_PM_ADMISSION_CLOSED);
    assert(state.channels_suspended == 0 && state.frontend_blocked);
    assert(!pm.channels_attempted[HYBRID580_PM_BACKEND_OPEN]);
    assert(!pm.channels_attempted[HYBRID580_PM_BACKEND_LEGACY]);
    assert(!state.uvm_suspended);
    assert(hybrid580_system_pm_complete(&state, &ops) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_RUNNING && !state.frontend_blocked);
    expect_events(&pm, expected, sizeof(expected) / sizeof(expected[0]));
}

static void test_partial_suspend_cleanup_failure_keeps_frontend_quarantined(void)
{
    struct fake_pm pm = {
        .fail_event = EVENT_SUSPEND_LEGACY,
        .second_fail_event = EVENT_RESTORE_LEGACY,
    };
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);
    const enum event expected[] = {
        EVENT_BLOCK, EVENT_FREEZER_COMPLETE, EVENT_DRAIN,
        EVENT_SUSPEND_OPEN, EVENT_SUSPEND_LEGACY,
        EVENT_RESTORE_LEGACY, EVENT_RESTORE_OPEN,
    };

    assert(begin_and_suspend(&pm, &state, &ops) ==
           HYBRID580_PM_ROLLBACK_FAILED);
    assert(state.phase == HYBRID580_PM_FAILED);
    assert(state.frontend_blocked);
    assert(state.channels_suspended == HYBRID580_PM_LEGACY_MASK);
    assert(pm.channels_attempted[HYBRID580_PM_BACKEND_LEGACY]);
    assert(!pm.channels_attempted[HYBRID580_PM_BACKEND_OPEN]);
    assert(hybrid580_system_pm_complete(&state, &ops) ==
           HYBRID580_PM_RESUME_FAILED);
    expect_events(&pm, expected, sizeof(expected) / sizeof(expected[0]));
}

static void test_frontend_drain_failure_unblocks_without_touching_providers(void)
{
    struct fake_pm pm = {.fail_event = EVENT_DRAIN};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);
    const enum event expected[] = {
        EVENT_BLOCK, EVENT_FREEZER_COMPLETE, EVENT_DRAIN, EVENT_UNBLOCK,
    };

    assert(begin_and_suspend(&pm, &state, &ops) == -EIO);
    assert(state.phase == HYBRID580_PM_ADMISSION_CLOSED);
    assert(state.frontend_blocked && !state.uvm_suspended);
    assert(state.channels_suspended == 0);
    assert(state.original_error == -EIO && state.cleanup_error == 0);
    assert(hybrid580_system_pm_complete(&state, &ops) == HYBRID580_PM_OK);
    expect_events(&pm, expected, sizeof(expected) / sizeof(expected[0]));
}

static void test_irq_drain_failure_rolls_back_after_both_provider_suspend_calls(void)
{
    struct fake_pm pm = {.fail_event = EVENT_DRAIN_IRQS_LEGACY};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);
    const enum event expected[] = {
        EVENT_BLOCK, EVENT_FREEZER_COMPLETE, EVENT_DRAIN,
        EVENT_SUSPEND_OPEN, EVENT_SUSPEND_LEGACY,
        EVENT_DRAIN_IRQS_OPEN, EVENT_DRAIN_IRQS_LEGACY,
        EVENT_RESTORE_LEGACY, EVENT_RESTORE_OPEN, EVENT_UNBLOCK,
    };

    assert(begin_and_suspend(&pm, &state, &ops) == -EIO);
    assert(state.phase == HYBRID580_PM_ADMISSION_CLOSED);
    assert(state.channels_suspended == 0 && state.frontend_blocked);
    assert(!state.uvm_suspended);
    assert(pm.channels_attempted[HYBRID580_PM_BACKEND_OPEN] == false);
    assert(pm.channels_attempted[HYBRID580_PM_BACKEND_LEGACY] == false);
    assert(hybrid580_system_pm_complete(&state, &ops) == HYBRID580_PM_OK);
    expect_events(&pm, expected, sizeof(expected) / sizeof(expected[0]));
}

static void test_failed_uvm_suspend_restores_channels_without_fake_uvm_resume(void)
{
    struct fake_pm pm = {.fail_event = EVENT_SUSPEND_UVM};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);
    const enum event expected[] = {
        EVENT_BLOCK, EVENT_FREEZER_COMPLETE, EVENT_DRAIN,
        EVENT_SUSPEND_OPEN, EVENT_SUSPEND_LEGACY,
        EVENT_DRAIN_IRQS_OPEN, EVENT_DRAIN_IRQS_LEGACY, EVENT_SUSPEND_UVM,
        EVENT_RESTORE_LEGACY, EVENT_RESTORE_OPEN, EVENT_UNBLOCK,
    };

    assert(begin_and_suspend(&pm, &state, &ops) == -EIO);
    assert(state.phase == HYBRID580_PM_ADMISSION_CLOSED);
    assert(state.frontend_blocked && !state.uvm_suspended);
    assert(state.channels_suspended == 0);
    assert(hybrid580_system_pm_complete(&state, &ops) == HYBRID580_PM_OK);
    expect_events(&pm, expected, sizeof(expected) / sizeof(expected[0]));
}

static void test_rollback_failure_keeps_frontend_blocked_and_state_quarantined(void)
{
    struct fake_pm pm = {.fail_event = EVENT_RESTORE_OPEN};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);
    const enum event expected[] = {
        EVENT_BLOCK, EVENT_FREEZER_COMPLETE, EVENT_DRAIN,
        EVENT_SUSPEND_OPEN, EVENT_SUSPEND_LEGACY,
        EVENT_DRAIN_IRQS_OPEN, EVENT_DRAIN_IRQS_LEGACY,
        EVENT_SUSPEND_UVM, EVENT_RESTORE_LEGACY, EVENT_RESTORE_OPEN,
    };

    pm.fail_event = EVENT_SUSPEND_UVM;
    pm.second_fail_event = EVENT_RESTORE_OPEN;
    assert(begin_and_suspend(&pm, &state, &ops) ==
           HYBRID580_PM_ROLLBACK_FAILED);
    assert(state.phase == HYBRID580_PM_FAILED);
    assert(state.frontend_blocked && !state.uvm_suspended);
    assert(state.channels_suspended == HYBRID580_PM_OPEN_MASK);
    assert(state.original_error == -EIO && state.cleanup_error == -EIO);
    expect_events(&pm, expected, sizeof(expected) / sizeof(expected[0]));
}

static void test_dpm_recovery_error_keeps_uvm_and_channels_quiesced(void)
{
    struct fake_pm pm = {0};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);

    assert(begin_and_suspend(&pm, &state, &ops) == HYBRID580_PM_OK);
    pm.event_count = 0;
    pm.fail_event = EVENT_VERIFY_LEGACY;
    record_supplier_results(&pm, state.generation, 0, 0);
    assert(hybrid580_system_pm_resume_after_suppliers(&state, &ops) ==
           HYBRID580_PM_RESUME_FAILED);
    assert(state.phase == HYBRID580_PM_FAILED);
    assert(state.frontend_blocked && state.uvm_suspended);
    assert(state.channels_suspended == HYBRID580_PM_ALL_BACKENDS);
    assert(pm.events[0] == EVENT_SUPPLIERS_RESUMED &&
           pm.events[1] == EVENT_VERIFY_OPEN && pm.events[2] == EVENT_VERIFY_LEGACY);
    assert(pm.event_count == 3);
}

static void test_sticky_gpu_resume_error_is_checked_before_uvm(void)
{
    struct fake_pm pm = {0};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);

    assert(begin_and_suspend(&pm, &state, &ops) == HYBRID580_PM_OK);
    pm.event_count = 0;
    pm.fallback_resume_error[HYBRID580_PM_BACKEND_LEGACY] = -EIO;
    record_supplier_results_for_event(&pm, state.generation,
                                      HYBRID580_PM_DPM_THAW, 0, 0);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_THAW) == HYBRID580_PM_RESUME_FAILED);
    assert(state.phase == HYBRID580_PM_FAILED);
    assert(state.frontend_blocked && state.uvm_suspended);
    assert(state.channels_suspended == HYBRID580_PM_ALL_BACKENDS);
    assert(pm.last_recovery_event == HYBRID580_PM_DPM_THAW);
    assert(pm.events[0] == EVENT_SUPPLIERS_RESUMED &&
           pm.events[1] == EVENT_VERIFY_OPEN &&
           pm.events[2] == EVENT_VERIFY_LEGACY);
    assert(pm.event_count == 3);
}

static void test_unobserved_gpu_resume_is_not_treated_as_success(void)
{
    struct fake_pm pm = {0};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);

    assert(begin_and_suspend(&pm, &state, &ops) == HYBRID580_PM_OK);
    pm.event_count = 0;
    record(&pm, EVENT_SUPPLIERS_RESUMED);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_RESUME) == HYBRID580_PM_RESUME_FAILED);
    assert(state.phase == HYBRID580_PM_FAILED);
    assert(state.frontend_blocked && state.uvm_suspended);
    assert(pm.events[0] == EVENT_SUPPLIERS_RESUMED &&
           pm.events[1] == EVENT_VERIFY_OPEN &&
           pm.events[2] == EVENT_VERIFY_LEGACY);
    assert(pm.event_count == 3);
}

static void test_recovery_latches_arm_before_dpm_and_reopen_on_arm_failure(void)
{
    struct fake_pm pm = {.fail_arm_backend_plus_one =
                         HYBRID580_PM_BACKEND_LEGACY + 1};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);

    assert(hybrid580_system_pm_begin(&state, &ops) == -EIO);
    assert(state.phase == HYBRID580_PM_RUNNING);
    assert(!state.frontend_blocked && state.cycle == HYBRID580_PM_CYCLE_NONE);
    assert(state.generation == 1);
    assert(pm.recovery[HYBRID580_PM_BACKEND_OPEN].generation == 1);
    assert(pm.recovery[HYBRID580_PM_BACKEND_LEGACY].generation == 0);
    assert(pm.event_count == 2 && pm.events[0] == EVENT_BLOCK &&
           pm.events[1] == EVENT_UNBLOCK);

    pm.fail_arm_backend_plus_one = 0;
    pm.event_count = 0;
    assert(hybrid580_system_pm_begin(&state, &ops) == HYBRID580_PM_OK);
    assert(state.generation == 2);
    assert(pm.recovery[HYBRID580_PM_BACKEND_OPEN].generation == 2);
    assert(pm.recovery[HYBRID580_PM_BACKEND_LEGACY].generation == 2);
    assert(hybrid580_system_pm_complete(&state, &ops) == HYBRID580_PM_OK);
    assert(!pm.recovery[HYBRID580_PM_BACKEND_OPEN].armed &&
           !pm.recovery[HYBRID580_PM_BACKEND_LEGACY].armed);
    assert(pm.recovery_end_calls[HYBRID580_PM_BACKEND_OPEN] == 2 &&
           pm.recovery_end_calls[HYBRID580_PM_BACKEND_LEGACY] == 1);
}

static void test_recovery_cycle_is_ended_before_uvm_and_frontend_reopen(void)
{
    struct fake_pm pm = {0};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);

    assert(begin_and_suspend(&pm, &state, &ops) == HYBRID580_PM_OK);
    record_supplier_results(&pm, state.generation, 0, 0);
    assert(hybrid580_system_pm_resume_after_suppliers(&state, &ops) ==
           HYBRID580_PM_OK);
    assert(!pm.recovery[HYBRID580_PM_BACKEND_OPEN].armed &&
           !pm.recovery[HYBRID580_PM_BACKEND_LEGACY].armed);
    assert(pm.recovery_end_calls[HYBRID580_PM_BACKEND_OPEN] == 1 &&
           pm.recovery_end_calls[HYBRID580_PM_BACKEND_LEGACY] == 1);
    assert(hybrid580_system_pm_complete(&state, &ops) == HYBRID580_PM_OK);
    assert(pm.recovery_end_calls[HYBRID580_PM_BACKEND_OPEN] == 1 &&
           pm.recovery_end_calls[HYBRID580_PM_BACKEND_LEGACY] == 1);
}

static void test_recovery_cleanup_failure_keeps_frontend_quarantined(void)
{
    struct fake_pm pm = {.fail_end_backend_plus_one =
                         HYBRID580_PM_BACKEND_OPEN + 1};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);

    assert(hybrid580_system_pm_begin(&state, &ops) == HYBRID580_PM_OK);
    assert(hybrid580_system_pm_complete(&state, &ops) ==
           HYBRID580_PM_RESUME_FAILED);
    assert(state.phase == HYBRID580_PM_FAILED && state.frontend_blocked);
    assert(state.recovery_armed == HYBRID580_PM_OPEN_MASK);
    assert(pm.recovery[HYBRID580_PM_BACKEND_OPEN].armed &&
           !pm.recovery[HYBRID580_PM_BACKEND_LEGACY].armed);
    assert(pm.recovery_end_calls[HYBRID580_PM_BACKEND_OPEN] == 1 &&
           pm.recovery_end_calls[HYBRID580_PM_BACKEND_LEGACY] == 1);
}

static void test_channel_restore_error_after_uvm_resume_stays_closed(void)
{
    struct fake_pm pm = {0};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);

    assert(begin_and_suspend(&pm, &state, &ops) == HYBRID580_PM_OK);
    pm.event_count = 0;
    pm.fail_event = EVENT_RESTORE_OPEN;
    record_supplier_results(&pm, state.generation, 0, 0);
    assert(hybrid580_system_pm_resume_after_suppliers(&state, &ops) ==
           HYBRID580_PM_RESUME_FAILED);
    assert(state.phase == HYBRID580_PM_FAILED);
    assert(state.frontend_blocked && !state.uvm_suspended);
    assert(state.channels_suspended == HYBRID580_PM_OPEN_MASK);
    assert(pm.events[0] == EVENT_SUPPLIERS_RESUMED &&
           pm.events[1] == EVENT_VERIFY_OPEN &&
           pm.events[2] == EVENT_VERIFY_LEGACY &&
           pm.events[3] == EVENT_RESUME_UVM &&
           pm.events[4] == EVENT_RESTORE_LEGACY &&
           pm.events[5] == EVENT_RESTORE_OPEN);
    assert(pm.event_count == 6);
}

static void test_uvm_resume_failure_keeps_channels_and_gate_quiesced(void)
{
    struct fake_pm pm = {0};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);
    const enum event expected[] = {
        EVENT_SUPPLIERS_RESUMED,
        EVENT_VERIFY_OPEN, EVENT_VERIFY_LEGACY, EVENT_RESUME_UVM,
    };

    assert(begin_and_suspend(&pm, &state, &ops) == HYBRID580_PM_OK);
    pm.event_count = 0;
    pm.fail_event = EVENT_RESUME_UVM;
    record_supplier_results(&pm, state.generation, 0, 0);
    assert(hybrid580_system_pm_resume_after_suppliers(&state, &ops) ==
           HYBRID580_PM_RESUME_FAILED);
    assert(state.phase == HYBRID580_PM_FAILED);
    assert(state.frontend_blocked && state.uvm_suspended);
    assert(state.channels_suspended == HYBRID580_PM_ALL_BACKENDS);
    assert(state.original_error == -EIO);
    expect_events(&pm, expected, sizeof(expected) / sizeof(expected[0]));
}

static void test_frontend_unblock_failure_quarantines_fully_restored_providers(void)
{
    struct fake_pm pm = {0};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);
    const enum event expected[] = {
        EVENT_SUPPLIERS_RESUMED,
        EVENT_VERIFY_OPEN, EVENT_VERIFY_LEGACY, EVENT_RESUME_UVM,
        EVENT_RESTORE_LEGACY, EVENT_RESTORE_OPEN, EVENT_POST_NOTIFIER,
        EVENT_UNBLOCK,
    };

    assert(begin_and_suspend(&pm, &state, &ops) == HYBRID580_PM_OK);
    pm.event_count = 0;
    pm.fail_event = EVENT_UNBLOCK;
    record_supplier_results(&pm, state.generation, 0, 0);
    assert(hybrid580_system_pm_resume_after_suppliers(&state, &ops) ==
           HYBRID580_PM_OK);
    record(&pm, EVENT_POST_NOTIFIER);
    assert(hybrid580_system_pm_complete(&state, &ops) ==
           HYBRID580_PM_RESUME_FAILED);
    assert(state.phase == HYBRID580_PM_FAILED);
    assert(state.frontend_blocked && !state.uvm_suspended);
    assert(state.channels_suspended == 0);
    assert(state.original_error == -EIO);
    expect_events(&pm, expected, sizeof(expected) / sizeof(expected[0]));
}

static void test_event_matrix_routes_hibernation_freeze_restore_and_notifiers(void)
{
    struct fake_pm pm = {0};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);

    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_HIBERNATION_PREPARE) == HYBRID580_PM_OK);
    record(&pm, EVENT_FREEZER_COMPLETE);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_FREEZE) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_SUSPENDED);

    /* A restored image captured during hibernation resumes under PMSG_RESTORE,
     * but its matching notifier is POST_HIBERNATION in the restored kernel. */
    record_supplier_results_for_event(&pm, state.generation,
                                      HYBRID580_PM_DPM_RESTORE, 0, 0);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_RESTORE) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_DPM_RESUMED);
    assert(pm.last_recovery_event == HYBRID580_PM_DPM_RESTORE);
    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_POST_HIBERNATION) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_RUNNING);
    assert(pm.events[0] == EVENT_BLOCK &&
           pm.events[1] == EVENT_FREEZER_COMPLETE &&
           pm.events[2] == EVENT_DRAIN &&
           pm.events[3] == EVENT_SUSPEND_OPEN &&
           pm.events[4] == EVENT_SUSPEND_LEGACY &&
           pm.events[5] == EVENT_DRAIN_IRQS_OPEN &&
           pm.events[6] == EVENT_DRAIN_IRQS_LEGACY &&
           pm.events[7] == EVENT_SUSPEND_UVM &&
           pm.events[8] == EVENT_SUPPLIERS_RESUMED &&
           pm.events[9] == EVENT_VERIFY_OPEN &&
           pm.events[10] == EVENT_VERIFY_LEGACY &&
           pm.events[11] == EVENT_RESUME_UVM &&
           pm.events[12] == EVENT_RESTORE_LEGACY &&
           pm.events[13] == EVENT_RESTORE_OPEN &&
           pm.events[14] == EVENT_UNBLOCK);
    assert(pm.event_count == 15);

    memset(&pm, 0, sizeof(pm));
    state = (struct hybrid580_system_pm){0};
    ops = ops_for(&pm);
    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_RESTORE_PREPARE) == HYBRID580_PM_OK);
    record(&pm, EVENT_FREEZER_COMPLETE);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_QUIESCE) == HYBRID580_PM_OK);
    record_supplier_results_for_event(&pm, state.generation,
                                      HYBRID580_PM_DPM_RECOVER, 0, 0);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_RECOVER) == HYBRID580_PM_OK);
    assert(pm.last_recovery_event == HYBRID580_PM_DPM_RECOVER);
    assert(pm.thaw_recovery_calls == 2);
    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_POST_RESTORE) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_RUNNING);
}

static void test_event_matrix_failed_freeze_rolls_back_once_before_recover(void)
{
    struct fake_pm pm = {.fail_event = EVENT_SUSPEND_LEGACY};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);

    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_HIBERNATION_PREPARE) == HYBRID580_PM_OK);
    record(&pm, EVENT_FREEZER_COMPLETE);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_FREEZE) == -EIO);
    record_supplier_results(&pm, state.generation, 0, 0);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_RECOVER) == HYBRID580_PM_OK);
    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_POST_HIBERNATION) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_RUNNING);
    assert(state.channels_suspended == 0 && !state.uvm_suspended);
    assert(pm.events[4] == EVENT_SUSPEND_LEGACY &&
           pm.events[5] == EVENT_RESTORE_LEGACY &&
           pm.events[6] == EVENT_RESTORE_OPEN &&
           pm.events[7] == EVENT_SUPPLIERS_RESUMED &&
           pm.events[8] == EVENT_UNBLOCK);
    assert(pm.event_count == 9);
}

static void test_notifier_pair_must_match_and_unknown_event_is_ignored(void)
{
    struct fake_pm pm = {0};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);

    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_UNRELATED) == HYBRID580_PM_IGNORED);
    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_HIBERNATION_PREPARE) == HYBRID580_PM_OK);
    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_POST_RESTORE) == HYBRID580_PM_INVALID);
    assert(state.frontend_blocked && state.phase == HYBRID580_PM_ADMISSION_CLOSED);
    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_POST_HIBERNATION) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_RUNNING && !state.frontend_blocked);
}

static void test_linux_v7_dpm_event_matrix_routes_every_callback_family(void)
{
    const enum hybrid580_pm_dpm_event quiesce_events[] = {
        HYBRID580_PM_DPM_SUSPEND,
        HYBRID580_PM_DPM_FREEZE,
        HYBRID580_PM_DPM_QUIESCE,
        HYBRID580_PM_DPM_POWEROFF,
        HYBRID580_PM_DPM_HIBERNATE,
    };
    const enum hybrid580_pm_dpm_event restore_events[] = {
        HYBRID580_PM_DPM_RESUME,
        HYBRID580_PM_DPM_THAW,
        HYBRID580_PM_DPM_RECOVER,
        HYBRID580_PM_DPM_RESTORE,
    };
    size_t i;

    for (i = 0; i < sizeof(quiesce_events) / sizeof(quiesce_events[0]); ++i)
        assert(hybrid580_pm_dpm_action_for_event(quiesce_events[i]) ==
               HYBRID580_PM_DPM_ACTION_QUIESCE);
    for (i = 0; i < sizeof(restore_events) / sizeof(restore_events[0]); ++i)
        assert(hybrid580_pm_dpm_action_for_event(restore_events[i]) ==
               HYBRID580_PM_DPM_ACTION_RESTORE);
    assert(hybrid580_pm_dpm_action_for_event(HYBRID580_PM_DPM_UNRELATED) ==
           HYBRID580_PM_DPM_ACTION_IGNORE);
}

static void test_event_dispatch_runs_suspend_resume_and_hibernation_thaw_cycles(void)
{
    struct fake_pm pm = {0};
    struct hybrid580_system_pm state = {0};
    struct hybrid580_system_pm_ops ops = ops_for(&pm);

    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_SUSPEND_PREPARE) == HYBRID580_PM_OK);
    record(&pm, EVENT_FREEZER_COMPLETE);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_SUSPEND) == HYBRID580_PM_OK);
    record_supplier_results_for_event(&pm, state.generation,
                                      HYBRID580_PM_DPM_RESUME, 0, 0);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_RESUME) == HYBRID580_PM_OK);
    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_POST_SUSPEND) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_RUNNING);

    memset(&pm, 0, sizeof(pm));
    state = (struct hybrid580_system_pm){0};
    ops = ops_for(&pm);
    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_HIBERNATION_PREPARE) == HYBRID580_PM_OK);
    record(&pm, EVENT_FREEZER_COMPLETE);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_FREEZE) == HYBRID580_PM_OK);
    record_supplier_results_for_event(&pm, state.generation,
                                      HYBRID580_PM_DPM_THAW, 0, 0);
    assert(hybrid580_system_pm_dpm(&state, &ops,
           HYBRID580_PM_DPM_THAW) == HYBRID580_PM_OK);
    assert(pm.last_recovery_event == HYBRID580_PM_DPM_THAW);
    assert(pm.thaw_recovery_calls == 2);
    assert(hybrid580_system_pm_notify(&state, &ops,
           HYBRID580_PM_NOTIFY_POST_HIBERNATION) == HYBRID580_PM_OK);
    assert(state.phase == HYBRID580_PM_RUNNING);
}

int main(void)
{
    test_suspend_resume_order_and_single_uvm_pair();
    test_partial_channel_suspend_rolls_back_in_reverse();
    test_partial_suspend_cleanup_failure_keeps_frontend_quarantined();
    test_frontend_drain_failure_unblocks_without_touching_providers();
    test_irq_drain_failure_rolls_back_after_both_provider_suspend_calls();
    test_failed_uvm_suspend_restores_channels_without_fake_uvm_resume();
    test_rollback_failure_keeps_frontend_blocked_and_state_quarantined();
    test_dpm_recovery_error_keeps_uvm_and_channels_quiesced();
    test_sticky_gpu_resume_error_is_checked_before_uvm();
    test_unobserved_gpu_resume_is_not_treated_as_success();
    test_recovery_latches_arm_before_dpm_and_reopen_on_arm_failure();
    test_recovery_cycle_is_ended_before_uvm_and_frontend_reopen();
    test_recovery_cleanup_failure_keeps_frontend_quarantined();
    test_channel_restore_error_after_uvm_resume_stays_closed();
    test_uvm_resume_failure_keeps_channels_and_gate_quiesced();
    test_frontend_unblock_failure_quarantines_fully_restored_providers();
    test_event_matrix_routes_hibernation_freeze_restore_and_notifiers();
    test_event_matrix_failed_freeze_rolls_back_once_before_recover();
    test_notifier_pair_must_match_and_unknown_event_is_ignored();
    test_linux_v7_dpm_event_matrix_routes_every_callback_family();
    test_event_dispatch_runs_suspend_resume_and_hibernation_thaw_cycles();
    puts("hybrid580 system PM coordinator passed");
    return 0;
}
