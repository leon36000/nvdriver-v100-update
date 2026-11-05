/* SPDX-License-Identifier: MIT */
/* Test-only dlsym interposer that forces the shim's RTLD_NEXT ioctl lookup to fail. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <string.h>

void *dlsym(void *handle, const char *symbol)
{
    static void *(*real_dlsym)(void *, const char *);

    if (handle == RTLD_NEXT && strcmp(symbol, "ioctl") == 0) {
        errno = ENOENT;
        return NULL;
    }
    if (real_dlsym == NULL) {
        void *resolved = dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
        memcpy(&real_dlsym, &resolved, sizeof(real_dlsym));
    }
    return real_dlsym == NULL ? NULL : real_dlsym(handle, symbol);
}
