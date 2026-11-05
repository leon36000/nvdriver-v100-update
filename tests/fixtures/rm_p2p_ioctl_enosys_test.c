/* SPDX-License-Identifier: MIT */
/* Verifies the cold forwarding path fails closed when RTLD_NEXT lacks ioctl. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void)
{
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int result;

    assert(fd >= 0);
    errno = 0;
    result = ioctl(fd, FIOCLEX);
    assert(result == -1);
    assert(errno == ENOSYS);
    assert(close(fd) == 0);
    puts("unresolved next ioctl failed closed with ENOSYS");
    return 0;
}
