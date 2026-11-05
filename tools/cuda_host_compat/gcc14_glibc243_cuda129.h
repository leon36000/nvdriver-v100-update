/* SPDX-License-Identifier: MIT */
/*
 * Narrow host-header workaround for CUDA 12.9.86 + GCC 14 on glibc 2.43.
 *
 * CUDA 12.9's math declarations conflict with glibc's GNU math declarations,
 * so CUDA translation units are compiled with _GNU_SOURCE undefined and
 * _POSIX_C_SOURCE=200809L. Ubuntu's GCC 14 libstdc++ headers were configured
 * with optional GNU timed-lock APIs enabled; those declarations are hidden
 * when _GNU_SOURCE is undefined. Disable only those optional libstdc++ paths
 * for CUDA translation units. Native C/C++ translation units are unaffected.
 * Revalidate before using this with another libc, libstdc++, NVCC, or host
 * compiler version.
 */
#pragma once

#ifndef __CUDACC__
#error "This compatibility header is only for NVCC translation units"
#endif

#include <bits/c++config.h>

#undef _GLIBCXX_USE_PTHREAD_COND_CLOCKWAIT
#undef _GLIBCXX_USE_PTHREAD_MUTEX_CLOCKLOCK
#define _GLIBCXX_USE_PTHREAD_MUTEX_CLOCKLOCK 0
#undef _GLIBCXX_USE_PTHREAD_RWLOCK_CLOCKLOCK
