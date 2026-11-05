// SPDX-License-Identifier: MIT
extern "C" __global__ void hybrid_arch(int *out) {
  if (blockIdx.x == 0 && threadIdx.x == 0) *out = __CUDA_ARCH__;
}

extern "C" __global__ void hybrid_empty() {}

extern "C" __global__ void hybrid_add(const int *a, const int *b, int *out,
                                       unsigned int count) {
  const unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i < count) out[i] = a[i] + b[i];
}

extern "C" __global__ void hybrid_concurrent_work(unsigned int *out,
                                                    unsigned int count,
                                                    unsigned int rounds) {
  const unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= count) return;
  unsigned int value = i + 1U;
  for (unsigned int round = 0; round < rounds; ++round)
    value = value * 1664525U + 1013904223U;
  out[i] = value;
}
