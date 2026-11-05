/* SPDX-License-Identifier: MIT */
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>

#include "../../src/hybrid580_irq_lifecycle_contract.h"

static void release_all(struct hybrid580_irq_lifecycle *state);

struct owner_race {
    struct hybrid580_irq_lifecycle *state;
    pthread_mutex_t *lifecycle_lock;
    pthread_barrier_t *start;
    enum hybrid580_irq_owner owner;
    int result;
};

static void *try_lifecycle_owner(void *argument)
{
    struct owner_race *race = argument;
    int barrier_result = pthread_barrier_wait(race->start);

    assert(barrier_result == 0 || barrier_result == PTHREAD_BARRIER_SERIAL_THREAD);
    assert(pthread_mutex_lock(race->lifecycle_lock) == 0);
    race->result = hybrid580_irq_lifecycle_begin_quiesce(race->state, race->owner);
    assert(pthread_mutex_unlock(race->lifecycle_lock) == 0);
    return NULL;
}

static void register_live(struct hybrid580_irq_lifecycle *state,
                          enum hybrid580_irq_mode mode,
                          unsigned int vectors)
{
    unsigned int i;

    assert(hybrid580_irq_lifecycle_init(state, mode, vectors) == 0);
    assert(hybrid580_irq_lifecycle_mark_device_sources_masked(state) == 0);
    for (i = 0; i < vectors; ++i)
        assert(hybrid580_irq_lifecycle_register_vector(state, i) == 0);
    assert(hybrid580_irq_lifecycle_activate(state) == 0);
    assert(hybrid580_irq_lifecycle_unmask_device_sources(state) == 0);
}

static void synchronize_registered(struct hybrid580_irq_lifecycle *state)
{
    unsigned int i;

    for (i = 0; i < state->expected_vectors; ++i) {
        if ((state->registered_mask & (1ULL << i)) != 0)
            assert(hybrid580_irq_lifecycle_synchronize_vector(state, i) == 0);
    }
}

static void flush_queue(struct hybrid580_irq_lifecycle *state)
{
    assert(hybrid580_irq_lifecycle_flush_queue_begin(state) == 0);
    while (state->deferred_pending != 0) {
        assert(hybrid580_irq_lifecycle_deferred_begin(state) == 0);
        assert(hybrid580_irq_lifecycle_deferred_complete(state) == 0);
    }
    assert(hybrid580_irq_lifecycle_flush_queue_complete(state) == 0);
}

static void quiesce(struct hybrid580_irq_lifecycle *state,
                    enum hybrid580_irq_owner owner)
{
    assert(hybrid580_irq_lifecycle_begin_quiesce(state, owner) == 0);
    assert(hybrid580_irq_lifecycle_mark_device_sources_masked(state) == 0);
    synchronize_registered(state);
    flush_queue(state);
    assert(hybrid580_irq_lifecycle_quiesce_complete(state) == 0);
}

static void quiesce_after_owner(struct hybrid580_irq_lifecycle *state)
{
    assert(hybrid580_irq_lifecycle_mark_device_sources_masked(state) == 0);
    synchronize_registered(state);
    flush_queue(state);
    assert(hybrid580_irq_lifecycle_quiesce_complete(state) == 0);
    release_all(state);
}

static void release_all(struct hybrid580_irq_lifecycle *state)
{
    unsigned int i;

    for (i = 0; i < state->expected_vectors; ++i) {
        if ((state->registered_mask & (1ULL << i)) != 0)
            assert(hybrid580_irq_lifecycle_release_vector(state, i) == 0);
    }
    assert(hybrid580_irq_lifecycle_shutdown_complete(state) == 0);
}

static void test_inflight_handler_and_queue_flush_order(void)
{
    struct hybrid580_irq_lifecycle state;

    register_live(&state, HYBRID580_IRQ_MODE_MSIX, 2);
    assert(hybrid580_irq_lifecycle_handler_enter(&state, 0) == 0);
    assert(hybrid580_irq_lifecycle_queue_from_handler(&state, 0) == 0);
    assert(hybrid580_irq_lifecycle_begin_quiesce(
               &state, HYBRID580_IRQ_OWNER_PM) == 0);

    /* A handler admitted before PM may finish and queue its final work item. */
    assert(hybrid580_irq_lifecycle_queue_from_handler(&state, 0) == 0);
    assert(hybrid580_irq_lifecycle_handler_enter(&state, 1) == -ESHUTDOWN);
    assert(hybrid580_irq_lifecycle_mark_device_sources_masked(&state) == 0);
    /* A queued worker may already be running while IRQ synchronization waits. */
    assert(hybrid580_irq_lifecycle_deferred_begin(&state) == 0);
    assert(hybrid580_irq_lifecycle_synchronize_vector(&state, 0) == -EBUSY);
    assert(hybrid580_irq_lifecycle_flush_queue_begin(&state) == -EAGAIN);
    assert(hybrid580_irq_lifecycle_handler_exit(&state, 0) == 0);
    synchronize_registered(&state);

    assert(hybrid580_irq_lifecycle_flush_queue_begin(&state) == 0);
    assert(hybrid580_irq_lifecycle_flush_queue_complete(&state) == -EAGAIN);
    assert(hybrid580_irq_lifecycle_deferred_complete(&state) == 0);
    assert(hybrid580_irq_lifecycle_deferred_begin(&state) == 0);
    assert(hybrid580_irq_lifecycle_deferred_complete(&state) == 0);
    assert(hybrid580_irq_lifecycle_flush_queue_complete(&state) == 0);
    assert(hybrid580_irq_lifecycle_queue_from_handler(&state, 0) == -ESHUTDOWN);
    assert(hybrid580_irq_lifecycle_quiesce_complete(&state) == 0);

    assert(hybrid580_irq_lifecycle_resume_begin(&state) == 0);
    assert(hybrid580_irq_lifecycle_unmask_device_sources(&state) == -EINVAL);
    assert(hybrid580_irq_lifecycle_resume_open_gate(&state) == 0);
    assert(hybrid580_irq_lifecycle_unmask_device_sources(&state) == 0);
}

static void test_pm_and_last_close_have_one_owner(void)
{
    struct hybrid580_irq_lifecycle state;

    register_live(&state, HYBRID580_IRQ_MODE_SHARED_LEGACY, 1);
    assert(hybrid580_irq_lifecycle_begin_quiesce(
               &state, HYBRID580_IRQ_OWNER_PM) == 0);
    assert(hybrid580_irq_lifecycle_begin_quiesce(
               &state, HYBRID580_IRQ_OWNER_LAST_CLOSE) == -EBUSY);
    assert(hybrid580_irq_lifecycle_mark_device_sources_masked(&state) == 0);
    synchronize_registered(&state);
    flush_queue(&state);
    assert(hybrid580_irq_lifecycle_quiesce_complete(&state) == 0);
    assert(hybrid580_irq_lifecycle_resume_begin(&state) == 0);
    assert(hybrid580_irq_lifecycle_resume_open_gate(&state) == 0);
    assert(hybrid580_irq_lifecycle_unmask_device_sources(&state) == 0);

    quiesce(&state, HYBRID580_IRQ_OWNER_LAST_CLOSE);
    release_all(&state);

    register_live(&state, HYBRID580_IRQ_MODE_SHARED_LEGACY, 1);
    assert(hybrid580_irq_lifecycle_begin_quiesce(
               &state, HYBRID580_IRQ_OWNER_LAST_CLOSE) == 0);
    assert(hybrid580_irq_lifecycle_begin_quiesce(
               &state, HYBRID580_IRQ_OWNER_REMOVE) == -EBUSY);
    quiesce_after_owner(&state);
}

static void test_partial_msix_registration_failure_releases_only_acquired_vectors(void)
{
    struct hybrid580_irq_lifecycle state;

    assert(hybrid580_irq_lifecycle_init(
               &state, HYBRID580_IRQ_MODE_MSIX, 8) == 0);
    assert(hybrid580_irq_lifecycle_mark_device_sources_masked(&state) == 0);
    assert(hybrid580_irq_lifecycle_register_vector(&state, 0) == 0);
    assert(hybrid580_irq_lifecycle_register_vector(&state, 1) == 0);
    assert(hybrid580_irq_lifecycle_register_vector(&state, 2) == 0);
    assert(hybrid580_irq_lifecycle_abort_registration(&state) == 0);
    assert(hybrid580_irq_lifecycle_synchronize_vector(&state, 3) == -EINVAL);
    assert(hybrid580_irq_lifecycle_handler_enter(&state, 0) == -ESHUTDOWN);
    synchronize_registered(&state);
    flush_queue(&state);
    assert(hybrid580_irq_lifecycle_quiesce_complete(&state) == 0);
    assert(hybrid580_irq_lifecycle_release_vector(&state, 0) == 0);
    assert(hybrid580_irq_lifecycle_release_vector(&state, 1) == 0);
    assert(hybrid580_irq_lifecycle_release_vector(&state, 2) == 0);
    assert(hybrid580_irq_lifecycle_shutdown_complete(&state) == 0);
    assert(state.phase == HYBRID580_IRQ_PHASE_DEAD);
}

static void test_concurrent_pm_and_remove_choose_one_serialized_owner(void)
{
    unsigned int iteration;

    for (iteration = 0; iteration < 128; ++iteration) {
        struct hybrid580_irq_lifecycle state;
        pthread_mutex_t lifecycle_lock = PTHREAD_MUTEX_INITIALIZER;
        pthread_barrier_t start;
        struct owner_race pm_race = {
            .state = &state,
            .lifecycle_lock = &lifecycle_lock,
            .start = &start,
            .owner = HYBRID580_IRQ_OWNER_PM,
            .result = -999,
        };
        struct owner_race remove_race = {
            .state = &state,
            .lifecycle_lock = &lifecycle_lock,
            .start = &start,
            .owner = HYBRID580_IRQ_OWNER_REMOVE,
            .result = -999,
        };
        pthread_t pm_thread;
        pthread_t remove_thread;

        register_live(&state, HYBRID580_IRQ_MODE_MSIX, 2);
        assert(pthread_barrier_init(&start, NULL, 2) == 0);
        assert(pthread_create(&pm_thread, NULL, try_lifecycle_owner, &pm_race) == 0);
        assert(pthread_create(&remove_thread, NULL, try_lifecycle_owner, &remove_race) == 0);
        assert(pthread_join(pm_thread, NULL) == 0);
        assert(pthread_join(remove_thread, NULL) == 0);
        assert(pthread_barrier_destroy(&start) == 0);
        assert((pm_race.result == 0 && remove_race.result == -EBUSY) ||
               (remove_race.result == 0 && pm_race.result == -EBUSY));
        assert(pthread_mutex_destroy(&lifecycle_lock) == 0);
    }
}

static void test_removal_owner_and_unmasked_setup_failure_stay_closed(void)
{
    struct hybrid580_irq_lifecycle state;

    assert(hybrid580_irq_lifecycle_init(
               &state, HYBRID580_IRQ_MODE_SHARED_LEGACY, 2) == -EINVAL);
    assert(hybrid580_irq_lifecycle_init(
               &state, HYBRID580_IRQ_MODE_MSIX, 2) == 0);
    assert(hybrid580_irq_lifecycle_register_vector(&state, 0) == -ESHUTDOWN);
    assert(hybrid580_irq_lifecycle_abort_registration(&state) == -EINVAL);

    register_live(&state, HYBRID580_IRQ_MODE_SHARED_LEGACY, 1);
    assert(hybrid580_irq_lifecycle_begin_quiesce(
               &state, HYBRID580_IRQ_OWNER_REMOVE) == 0);
    assert(hybrid580_irq_lifecycle_begin_quiesce(
               &state, HYBRID580_IRQ_OWNER_LAST_CLOSE) == -EBUSY);
    quiesce_after_owner(&state);
    assert(state.phase == HYBRID580_IRQ_PHASE_DEAD);
}

int main(void)
{
    test_inflight_handler_and_queue_flush_order();
    test_pm_and_last_close_have_one_owner();
    test_partial_msix_registration_failure_releases_only_acquired_vectors();
    test_concurrent_pm_and_remove_choose_one_serialized_owner();
    test_removal_owner_and_unmasked_setup_failure_stay_closed();
    puts("hybrid580 IRQ lifecycle contract passed: in-flight work, owner arbitration, partial MSI-X");
    return 0;
}
