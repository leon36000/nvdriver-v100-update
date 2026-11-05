// SPDX-License-Identifier: MIT
extern "C" __global__ void hybrid_arch(int *out) {
  if (blockIdx.x == 0 && threadIdx.x == 0) *out = __CUDA_ARCH__;
}

extern "C" __global__ void hybrid_add(const int *a, const int *b, int *out,
                                       unsigned int count) {
  const unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i < count) out[i] = a[i] + b[i];
}
