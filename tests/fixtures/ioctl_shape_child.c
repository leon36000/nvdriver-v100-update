/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

static int expect_enotty(int fd, unsigned long request, void *argument)
{
    errno = 0;
    return ioctl(fd, request, argument) == -1 && errno == ENOTTY;
}

static void *close_range_through_max(void *argument)
{
    int fd = *(int *)argument;
    return (void *)(intptr_t)syscall(SYS_close_range, (unsigned)fd,
                                     ~0U, 0U);
}

int main(int argc, char **argv)
{
    int close_range_probe = argc == 2 && strcmp(argv[1], "close-range") == 0;
    if (argc > 2 || (argc == 2 && !close_range_probe))
        return 14;
    uint8_t card_info[56] = {0};
    uint8_t control_5e[40] = {0};
    uint8_t gpu_control[16] = {0};
    uint8_t gpu_free_event[16] = {0};
    uint8_t root_free[16] = {0};
    uint8_t nonroot_free[16] = {0};
    uint8_t unrelated[8] = {0};
    int control_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    int gpu_fd = open("/dev/zero", O_RDWR | O_CLOEXEC);
    int gpu_duplicate_fd = -1;
    int result = 0;

    if (control_fd < 0 || gpu_fd < 0) {
        result = 10;
        goto out;
    }
    if (close_range_probe) {
        gpu_duplicate_fd = dup(gpu_fd);
        if (gpu_duplicate_fd < 0) {
            result = 17;
            goto out;
        }
    }
    card_info[0] = 0xa7;
    card_info[4] = 0x91;
    card_info[16] = 0x34;
    control_5e[3] = 0xb2;
    gpu_control[8] = 0x83;
    gpu_free_event[8] = 0x83;
    /* NVOS00_PARAMETERS: hRoot at byte 0, hObjectOld at byte 8. */
    root_free[0] = 0x44;
    root_free[1] = 0x33;
    root_free[2] = 0x22;
    root_free[3] = 0x11;
    root_free[8] = 0x44;
    root_free[9] = 0x33;
    root_free[10] = 0x22;
    root_free[11] = 0x11;
    nonroot_free[0] = 0x44;
    nonroot_free[1] = 0x33;
    nonroot_free[2] = 0x22;
    nonroot_free[3] = 0x11;
    nonroot_free[8] = 0x45;
    nonroot_free[9] = 0x33;
    nonroot_free[10] = 0x22;
    nonroot_free[11] = 0x11;
    if (!expect_enotty(control_fd, 0xc038464eUL, card_info) ||
        !expect_enotty(control_fd, 0xc028465eUL, control_5e) ||
        !expect_enotty(gpu_fd, 0xc01046ceUL, gpu_control) ||
        !expect_enotty(gpu_fd, 0xc01046cfUL, gpu_free_event) ||
        !expect_enotty(control_fd, 0xc0104629UL, root_free) ||
        !expect_enotty(control_fd, 0xc0104629UL, nonroot_free) ||
        !expect_enotty(control_fd, 0xc00846d6UL, unrelated) ||
        !expect_enotty(control_fd, 0xc001464eUL, unrelated))
        result = 11;

out:
    if (close_range_probe && gpu_fd >= 0) {
        pthread_t closer;
        void *thread_result = (void *)(intptr_t)-1;
        int range_first_fd = control_fd;
        if (close(control_fd) != 0)
            result = 12;
        else
            control_fd = -1;
        if (pthread_create(&closer, NULL, close_range_through_max,
                           &range_first_fd) != 0)
            result = 15;
        else if (pthread_join(closer, &thread_result) != 0 ||
                 (intptr_t)thread_result != 0)
            result = 16;
        else {
            control_fd = -1;
            gpu_fd = -1;
            gpu_duplicate_fd = -1;
        }
    }
    if (control_fd >= 0 && close(control_fd) != 0)
        result = 12;
    if (gpu_fd >= 0 && close(gpu_fd) != 0)
        result = 13;
    if (gpu_duplicate_fd >= 0 && close(gpu_duplicate_fd) != 0)
        result = 18;
    return result;
}
