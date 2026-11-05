/* SPDX-License-Identifier: MIT
 * Synthetic UVM ioctl request to /dev/null; never contacts a GPU or RM. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "uvm_ioctl.h"

static void *exercise_shared_fd_table(void *unused)
{
    (void)unused;
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd >= 0)
        close(fd);
    return (void *)(long)(fd < 0);
}

int main(int argc, char **argv)
{
    int control_fd;
    int uvm_fd;
    pthread_t thread;
    void *thread_result = NULL;
    UVM_REGISTER_GPU_VASPACE_PARAMS params = {0};
    UVM_MAP_EXTERNAL_ALLOCATION_PARAMS map_params = {0};

    if (argc != 2)
        return 90;
    control_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    uvm_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (control_fd < 0 || uvm_fd < 0)
        return 91;
    if (strstr(argv[1], "threaded")) {
        if (pthread_create(&thread, NULL, exercise_shared_fd_table, NULL) != 0 ||
            pthread_join(thread, &thread_result) != 0 || thread_result != NULL)
            return 92;
    }
    if (strstr(argv[1], "reopen")) {
        close(control_fd);
        control_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (control_fd < 0)
            return 93;
    }
    if (strstr(argv[1], "unshare"))
        (void)unshare(CLONE_FILES);
    params.rmCtrlFd = strcmp(argv[1], "negative-control") ? control_fd : -1;
    (void)ioctl(uvm_fd, UVM_REGISTER_GPU_VASPACE, &params);
    map_params.rmCtrlFd = params.rmCtrlFd;
    (void)ioctl(uvm_fd, UVM_MAP_EXTERNAL_ALLOCATION, &map_params);
    close(uvm_fd);
    close(control_fd);
    return 0;
}
