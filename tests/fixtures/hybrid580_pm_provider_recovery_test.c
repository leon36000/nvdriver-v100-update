/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include "../../src/hybrid580_pm_provider_recovery.h"

static void test_noop_thaw_requires_fallback_and_keeps_failure_sticky(void)
{
    struct hybrid580_pm_provider_recovery_status gpu = {0};

    assert(hybrid580_pm_provider_recovery_begin(&gpu, 10) == 0);
    assert(hybrid580_pm_provider_recovery_check(
               &gpu, 10, HYBRID580_PM_PROVIDER_CALLBACK_THAW, false) == -EAGAIN);
    assert(hybrid580_pm_provider_recovery_record_callback(
               &gpu, 10, HYBRID580_PM_PROVIDER_CALLBACK_THAW, 0) == 0);
    assert(hybrid580_pm_provider_recovery_check(
               &gpu, 10, HYBRID580_PM_PROVIDER_CALLBACK_THAW, false) == 0);
    assert(hybrid580_pm_provider_recovery_check(
               &gpu, 10, HYBRID580_PM_PROVIDER_CALLBACK_THAW, true) == -EAGAIN);
    assert(hybrid580_pm_provider_recovery_record_fallback(&gpu, 10, -EIO) == 0);
    assert(hybrid580_pm_provider_recovery_check(
               &gpu, 10, HYBRID580_PM_PROVIDER_CALLBACK_THAW, true) == -EIO);
    assert(hybrid580_pm_provider_recovery_record_fallback(&gpu, 10, 0) == 0);
    assert(hybrid580_pm_provider_recovery_check(
               &gpu, 10, HYBRID580_PM_PROVIDER_CALLBACK_THAW, true) == -EIO);
}

static void test_callback_kind_and_generation_are_checked(void)
{
    struct hybrid580_pm_provider_recovery_status gpu = {0};

    assert(hybrid580_pm_provider_recovery_begin(&gpu, 1) == 0);
    assert(hybrid580_pm_provider_recovery_record_callback(
               &gpu, 1, HYBRID580_PM_PROVIDER_CALLBACK_RESTORE, 0) == 0);
    assert(hybrid580_pm_provider_recovery_check(
               &gpu, 1, HYBRID580_PM_PROVIDER_CALLBACK_RESUME, false) == -EPROTO);
    assert(hybrid580_pm_provider_recovery_check(
               &gpu, 1, HYBRID580_PM_PROVIDER_CALLBACK_RESTORE, false) == 0);
    assert(hybrid580_pm_provider_recovery_record_callback(
               &gpu, 2, HYBRID580_PM_PROVIDER_CALLBACK_RESTORE, 0) == -ESTALE);
    assert(hybrid580_pm_provider_recovery_end(&gpu, 1) == 0);
    assert(hybrid580_pm_provider_recovery_check(
               &gpu, 1, HYBRID580_PM_PROVIDER_CALLBACK_RESTORE, false) == -ESTALE);
    assert(hybrid580_pm_provider_recovery_begin(&gpu, 1) == -ESTALE);
}

static void test_per_gpu_results_remain_independent(void)
{
    struct hybrid580_pm_provider_recovery_status v100 = {0};
    struct hybrid580_pm_provider_recovery_status blackwell = {0};

    assert(hybrid580_pm_provider_recovery_begin(&v100, 3) == 0);
    assert(hybrid580_pm_provider_recovery_begin(&blackwell, 3) == 0);
    assert(hybrid580_pm_provider_recovery_record_callback(
               &v100, 3, HYBRID580_PM_PROVIDER_CALLBACK_RESUME, -EIO) == 0);
    assert(hybrid580_pm_provider_recovery_record_callback(
               &blackwell, 3, HYBRID580_PM_PROVIDER_CALLBACK_RESUME, 0) == 0);
    assert(hybrid580_pm_provider_recovery_check(
               &v100, 3, HYBRID580_PM_PROVIDER_CALLBACK_RESUME, false) == -EIO);
    assert(hybrid580_pm_provider_recovery_check(
               &blackwell, 3, HYBRID580_PM_PROVIDER_CALLBACK_RESUME, false) == 0);
}

static void test_channel_state_survives_failed_restore_until_retried(void)
{
    struct hybrid580_pm_provider_recovery_status gpu = {0};

    assert(hybrid580_pm_provider_recovery_begin(&gpu, 11) == 0);
    assert(hybrid580_pm_provider_channels_suspend_attempt(&gpu, 11) == 0);
    assert(gpu.channels_suspended == 1);
    assert(hybrid580_pm_provider_channels_suspend_attempt(&gpu, 11) == -EALREADY);
    assert(hybrid580_pm_provider_recovery_end(&gpu, 11) == 0);
    assert(hybrid580_pm_provider_recovery_begin(&gpu, 12) == -EBUSY);
    assert(hybrid580_pm_provider_channels_restore_result(&gpu, 11, -EIO) == -EIO);
    assert(gpu.channels_suspended == 1);
    assert(hybrid580_pm_provider_channels_restore_result(&gpu, 11, 0) == 0);
    assert(gpu.channels_suspended == 0);
    assert(hybrid580_pm_provider_recovery_begin(&gpu, 12) == 0);
}

int main(void)
{
    test_noop_thaw_requires_fallback_and_keeps_failure_sticky();
    test_callback_kind_and_generation_are_checked();
    test_per_gpu_results_remain_independent();
    test_channel_state_survives_failed_restore_until_retried();
    puts("hybrid580 provider PM recovery contract passed");
    return 0;
}
