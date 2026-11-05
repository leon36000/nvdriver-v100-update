/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "../../src/hybrid580_frontend_admission.h"

static struct hybrid580_frontend_admission_state gate;
static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_changed = PTHREAD_COND_INITIALIZER;
static int waiter_entered;

static int enter_gate(void)
{
    int rc;
    pthread_mutex_lock(&gate_lock);
    rc = hybrid580_frontend_admission_try_enter_locked(&gate);
    pthread_mutex_unlock(&gate_lock);
    return rc;
}

static void leave_gate(void)
{
    pthread_mutex_lock(&gate_lock);
    assert(hybrid580_frontend_admission_leave_locked(&gate) == 0);
    pthread_cond_broadcast(&gate_changed);
    pthread_mutex_unlock(&gate_lock);
}

static void *waiter(void *unused)
{
    (void)unused;
    pthread_mutex_lock(&gate_lock);
    while (hybrid580_frontend_admission_is_blocked_locked(&gate))
        pthread_cond_wait(&gate_changed, &gate_lock);
    assert(hybrid580_frontend_admission_try_enter_locked(&gate) == 0);
    waiter_entered = 1;
    pthread_mutex_unlock(&gate_lock);
    return NULL;
}

static void test_block_drains_and_reopens(void)
{
    pthread_t thread;
    pthread_mutex_lock(&gate_lock);
    hybrid580_frontend_admission_init(&gate);
    pthread_mutex_unlock(&gate_lock);

    assert(enter_gate() == 0);
    pthread_mutex_lock(&gate_lock);
    assert(hybrid580_frontend_admission_block_locked(&gate) == 0);
    assert(!hybrid580_frontend_admission_is_drained_locked(&gate));
    assert(hybrid580_frontend_admission_try_enter_locked(&gate) == -EAGAIN);
    assert(hybrid580_frontend_admission_block_locked(&gate) == -EBUSY);
    pthread_mutex_unlock(&gate_lock);

    assert(pthread_create(&thread, NULL, waiter, NULL) == 0);
    pthread_mutex_lock(&gate_lock);
    while (!hybrid580_frontend_admission_is_blocked_locked(&gate))
        pthread_cond_wait(&gate_changed, &gate_lock);
    pthread_mutex_unlock(&gate_lock);

    leave_gate();
    pthread_mutex_lock(&gate_lock);
    assert(hybrid580_frontend_admission_is_drained_locked(&gate));
    assert(!waiter_entered);
    assert(hybrid580_frontend_admission_unblock_locked(&gate) == 0);
    pthread_cond_broadcast(&gate_changed);
    pthread_mutex_unlock(&gate_lock);

    assert(pthread_join(thread, NULL) == 0);
    pthread_mutex_lock(&gate_lock);
    assert(waiter_entered);
    assert(gate.active == 1);
    pthread_mutex_unlock(&gate_lock);
    leave_gate();
    pthread_mutex_lock(&gate_lock);
    assert(hybrid580_frontend_admission_is_drained_locked(&gate));
    assert(hybrid580_frontend_admission_unblock_locked(&gate) == -EINVAL);
    pthread_mutex_unlock(&gate_lock);
}

static void test_leave_underflow_is_rejected(void)
{
    struct hybrid580_frontend_admission_state local = { 0 };
    assert(hybrid580_frontend_admission_leave_locked(&local) == -EINVAL);
    assert(local.active == 0);
}

int main(void)
{
    test_block_drains_and_reopens();
    test_leave_underflow_is_rejected();
    puts("frontend admission contract passed");
    return 0;
}
