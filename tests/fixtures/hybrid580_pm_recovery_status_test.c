/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include "../../src/hybrid580_pm_recovery_status.h"

static void test_generation_and_sticky_error(void)
{
    struct hybrid580_pm_recovery_status gpu = {0};

    assert(hybrid580_pm_recovery_check(&gpu, 1) == -ESTALE);
    assert(hybrid580_pm_recovery_begin(&gpu, 1) == 0);
    assert(hybrid580_pm_recovery_check(&gpu, 1) == -EAGAIN);
    assert(hybrid580_pm_recovery_record(&gpu, 1, 0) == 0);
    assert(hybrid580_pm_recovery_check(&gpu, 1) == 0);
    assert(hybrid580_pm_recovery_record(&gpu, 1, -EIO) == 0);
    assert(hybrid580_pm_recovery_check(&gpu, 1) == -EIO);
    assert(hybrid580_pm_recovery_record(&gpu, 1, -ENODEV) == 0);
    assert(hybrid580_pm_recovery_check(&gpu, 1) == -EIO);
    assert(hybrid580_pm_recovery_record(&gpu, 1, 0) == 0);
    assert(hybrid580_pm_recovery_check(&gpu, 1) == -EIO);
    assert(hybrid580_pm_recovery_begin(&gpu, 1) == -ESTALE);
    assert(hybrid580_pm_recovery_begin(&gpu, 2) == 0);
    assert(hybrid580_pm_recovery_check(&gpu, 2) == -EAGAIN);
    assert(hybrid580_pm_recovery_check(&gpu, 1) == -ESTALE);
    assert(hybrid580_pm_recovery_record(&gpu, 1, -EIO) == -ESTALE);
    assert(hybrid580_pm_recovery_record(&gpu, 2, 1) == -EINVAL);
    assert(hybrid580_pm_recovery_record(&gpu, 2, 0) == 0);
    assert(hybrid580_pm_recovery_check(&gpu, 2) == 0);
}

static void test_each_gpu_has_an_independent_latch(void)
{
    struct hybrid580_pm_recovery_status v100 = {0};
    struct hybrid580_pm_recovery_status blackwell = {0};

    assert(hybrid580_pm_recovery_begin(&v100, 9) == 0);
    assert(hybrid580_pm_recovery_begin(&blackwell, 9) == 0);
    assert(hybrid580_pm_recovery_record(&v100, 9, -EIO) == 0);
    assert(hybrid580_pm_recovery_record(&blackwell, 9, 0) == 0);
    assert(hybrid580_pm_recovery_check(&v100, 9) == -EIO);
    assert(hybrid580_pm_recovery_check(&blackwell, 9) == 0);
}

int main(void)
{
    test_generation_and_sticky_error();
    test_each_gpu_has_an_independent_latch();
    puts("hybrid580 PM recovery status model passed");
    return 0;
}
