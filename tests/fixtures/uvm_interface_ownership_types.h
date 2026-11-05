/* SPDX-License-Identifier: MIT */
typedef struct UvmCslContext_tag {
    struct ccslContext_t *ctx;
    void *nvidia_stack;
} UvmCslContext;
typedef struct UvmGpuFaultInfo_tag {
    struct { void *bufferAddress; } replayable;
    struct Device *pDevice;
} UvmGpuFaultInfo;
typedef struct UvmGpuPagingChannel_tag {
    struct gpuDevice *device;
    void *errorNotifier;
} UvmGpuPagingChannel;
