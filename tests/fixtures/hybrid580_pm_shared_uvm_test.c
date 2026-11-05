/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stdio.h>

#include "hybrid580_pm_shared_uvm.h"

struct callback_fixture {
    int result;
    unsigned int calls;
};

static int transition(void *data)
{
    struct callback_fixture *fixture = data;

    fixture->calls++;
    return fixture->result;
}

int main(void)
{
    struct hybrid580_pm_shared_uvm_state state = { 0 };
    struct callback_fixture callback = { .result = -EIO, .calls = 0 };

    if (hybrid580_pm_shared_uvm_suspend(NULL, transition, &callback) != -EINVAL)
        return 1;
    if (hybrid580_pm_shared_uvm_suspend(&state, NULL, &callback) != -EINVAL)
        return 2;
    if (hybrid580_pm_shared_uvm_suspend(&state, transition, &callback) != -EIO ||
        state.phase != HYBRID580_PM_SHARED_UVM_RUNNING || callback.calls != 1)
        return 3;

    callback.result = 1;
    if (hybrid580_pm_shared_uvm_suspend(&state, transition, &callback) != -EPROTO ||
        state.phase != HYBRID580_PM_SHARED_UVM_RUNNING || callback.calls != 2)
        return 4;

    callback.result = 0;
    if (hybrid580_pm_shared_uvm_suspend(&state, transition, &callback) != 0 ||
        state.phase != HYBRID580_PM_SHARED_UVM_SUSPENDED || callback.calls != 3)
        return 5;
    if (hybrid580_pm_shared_uvm_suspend(&state, transition, &callback) != -EBUSY ||
        callback.calls != 3)
        return 6;

    callback.result = -EIO;
    if (hybrid580_pm_shared_uvm_resume(&state, transition, &callback) != -EIO ||
        state.phase != HYBRID580_PM_SHARED_UVM_SUSPENDED || callback.calls != 4)
        return 7;

    callback.result = 0;
    if (hybrid580_pm_shared_uvm_resume(&state, transition, &callback) != 0 ||
        state.phase != HYBRID580_PM_SHARED_UVM_RUNNING || callback.calls != 5)
        return 8;
    if (hybrid580_pm_shared_uvm_resume(&state, transition, &callback) != -EINVAL ||
        callback.calls != 5)
        return 9;

    state.phase = 99;
    if (hybrid580_pm_shared_uvm_suspend(&state, transition, &callback) != -EINVAL ||
        hybrid580_pm_shared_uvm_resume(&state, transition, &callback) != -EINVAL ||
        callback.calls != 5)
        return 10;

    puts("shared UVM PM state contract passed");
    return 0;
}
