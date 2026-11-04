# Separate stock-driver CUDA performance references

Generated 2026-10-29T10:50:41.370530+00:00. These are separate stock-environment baselines, not a hybrid-driver comparison.

Direct launch metrics are batch averages over 256 empty-kernel launches; graph metrics are batch averages over 256 one-node graph replays. The schema-v2 `host_api_us` values are host-side wall time per submitted operation, measured around the full submission lambda, including the Driver API wrapper and status check; they are not isolated call-only latency. CUDA-event elapsed values describe stream time around the empty-kernel operation, not useful kernel instruction time, and may include GPU idle bubbles while the host submits work. Pinned-copy bandwidth uses per-copy CUDA-event time, and the validator checks every sample against bytes divided by that elapsed time. Each capture has nine launch batches or seven transfer batches; its nearest-rank p95 is therefore its maximum observed batch. The pooled median and nearest-rank p95 summarize the batch observations across 3 RTX processes and 4 V100 processes; with these sample counts, p95 is descriptive and not a stable tail-latency estimate.

## RTX 5080 — PC3 host

NVIDIA GeForce RTX 5080 at 0000:02:00.0 (SM120); driver 595.99.02, Driver API 13020, kernel 7.0.0-38-generic on pc3. The 3 runs use probe SHA-256 df4ab2558a7315680eb55d91cfacd807926d0adf15d9835424e256a5eb43b71d and fatbin SHA-256 74cd97aabd47ab1abe720493bf54012a494472d9047b249d049300cda57e1741.

| Measurement | Median (p95) | Unit |
|---|---:|---|
| Direct empty-kernel host submission wall time (wrapper + status check) | 1.272 (1.292) | µs/launch |
| Direct empty-kernel CUDA-event stream elapsed | 1.275 (1.294) | µs/launch |
| One-node graph host submission wall time (wrapper + status check) | 1.292 (1.316) | µs/replay |
| One-node graph CUDA-event stream elapsed | 2.011 (2.048) | µs/replay |

| Pinned transfer size | H→D GB/s median (p95) | D→H GB/s median (p95) |
|---:|---:|---:|
| 4,096 bytes | 3.114 (3.128) | 3.875 (3.899) |
| 65,536 bytes | 26.474 (26.654) | 35.778 (36.113) |
| 1,048,576 bytes | 47.182 (47.438) | 24.628 (25.102) |
| 16,777,216 bytes | 50.490 (51.573) | 23.986 (24.478) |
| 67,108,864 bytes | 51.318 (51.523) | 23.461 (24.176) |

Evidence files:
- evidence/pc3-rtx5080-stock-benchmark-v7-run1-20261028T2120Z.json — SHA-256 9a9365b34bdfce11ccf0b570d9ede1ebd78e10d1510d94c4dd293dcf4bfa0eeb; observed 2026-10-28T21:18:23+00:00.
- evidence/pc3-rtx5080-stock-benchmark-v7-run2-20261028T2120Z.json — SHA-256 67ad38195bc21b20f814e765f90accd4c2990f9568c1753554e3b442b8fb6b60; observed 2026-10-28T21:18:28+00:00.
- evidence/pc3-rtx5080-stock-benchmark-v7-run3-20261028T2120Z.json — SHA-256 8ac8fd1a14cae41e73443b55073496c9bee633d3a82be606bf3e781602f94acc; observed 2026-10-28T21:18:31+00:00.

The host exposes SM120 only. The probe exits 77 because SM70 is absent and leaves hybrid_validated=false; this is an RTX-only stock reference.

## Tesla V100 — PC3 guest VM

Tesla V100-SXM2-16GB at 0000:00:05.0 (SM70); driver 580.178.04, Driver API 13000, kernel 6.8.0-147-generic on pc3-v100. The 4 runs use probe SHA-256 df4ab2558a7315680eb55d91cfacd807926d0adf15d9835424e256a5eb43b71d and fatbin SHA-256 74cd97aabd47ab1abe720493bf54012a494472d9047b249d049300cda57e1741.

| Measurement | Median (p95) | Unit |
|---|---:|---|
| Direct empty-kernel host submission wall time (wrapper + status check) | 1.552 (1.576) | µs/launch |
| Direct empty-kernel CUDA-event stream elapsed | 2.112 (2.136) | µs/launch |
| One-node graph host submission wall time (wrapper + status check) | 1.123 (1.166) | µs/replay |
| One-node graph CUDA-event stream elapsed | 2.240 (2.256) | µs/replay |

| Pinned transfer size | H→D GB/s median (p95) | D→H GB/s median (p95) |
|---:|---:|---:|
| 4,096 bytes | 0.913 (0.936) | 1.405 (1.407) |
| 65,536 bytes | 2.863 (2.876) | 3.038 (3.039) |
| 1,048,576 bytes | 3.281 (3.283) | 3.269 (3.270) |
| 16,777,216 bytes | 3.319 (3.319) | 3.291 (3.291) |
| 67,108,864 bytes | 3.315 (3.318) | 3.294 (3.294) |

Evidence files:
- evidence/pc3-v100-stock-benchmark-v7-run1-20261028T2120Z.json — SHA-256 9dafc91530bd91305cf579dcd0218c6497b15e9582bf381052cdf0ceed872d1f; observed 2026-10-28T21:17:45+00:00.
- evidence/pc3-v100-stock-benchmark-v7-run2-20261028T2120Z.json — SHA-256 ce0e990ac719d2b4147ae345daf4bae7842647da65742a1d93b5d004c1d4cce4; observed 2026-10-28T21:18:01+00:00.
- evidence/pc3-v100-stock-benchmark-v7-run3-20261028T2120Z.json — SHA-256 43c34bdda3caf37e5c481014496cbc9111f8d060b0f58a3d07f0a9407f4014c0; observed 2026-10-28T21:18:09+00:00.
- evidence/pc3-v100-stock-benchmark-v1-20261029T1051Z.json — SHA-256 714f01b645dbe7209c8e7e7f6f3be876107a8d3f40e2d7dd1e431b905af52083; observed 2026-10-29T10:49:55+00:00.

This capture uses the existing R580 V100 guest. It validates one SM70 device only and leaves hybrid_validated=false.

## Limits

The V100 guest and RTX 5080 host differ in GPU, Linux kernel, NVIDIA driver branch, VM boundary, and hardware path. Their values are reported separately and are not a speedup comparison. The empty kernel measures launch overhead, not useful model work; inference throughput and token latency were not measured. These isolated pinned-host copies do not measure UVM migration, P2P/NVLink, concurrent devices, or the proposed hybrid driver. No clock locking was used, so the results describe the observed stock environments and runtime state.

## Excluded diagnostic captures

4 diagnostic captures are excluded from the qualified summary and remain preserved:
- `evidence/pc3-rtx5080-performance-reference-v1-20261023T2345Z.json` — remote staging failed before CUDA because the required contract helper was omitted.
- `evidence/pc3-rtx5080-performance-reference-v2-20261023T2347Z.json` — uses the superseded benchmark-v1 bandwidth normalization; remote qualification also rejected the graph API claim.
- `evidence/pc3-rtx5080-performance-reference-v3-20261023T2350Z.json` — CUDA work completed under the old benchmark-v1 bandwidth formula, so per-copy small and medium transfer results are invalid.
- `evidence/pc3-v100-performance-reference-v2-20261023T2356Z.json` — CUDA work completed, but the old graph API acceptance policy rejected the performance-only graph API claim.

## Reproduction

Build the SM70/SM120 probe bundle and run each stock GPU separately:

    python3 tools/build_probe.py --output-dir build/probe-performance-v2-20261023

    python3 tools/run_remote_selected_gpu.py --target pc3@pc3 --host-key-alias pc3 --gpu-uuid GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77 --pci 0000:02:00.0 --probe build/probe-performance-v2-20261023/hybrid_cuda_probe --module build/probe-performance-v2-20261023/hybrid_probe.sm70-sm120.fatbin --evidence evidence/rtx-reference.json --benchmark

    python3 tools/run_pc3_v100_guest_reference.py --probe build/probe-performance-v2-20261023/hybrid_cuda_probe --module build/probe-performance-v2-20261023/hybrid_probe.sm70-sm120.fatbin --evidence evidence/v100-reference.json --benchmark

Supply three unique evidence paths for each GPU using the repeated --rtx-report and --v100-report options of tools/aggregate_cuda_performance_references.py. It revalidates stock-reference qualification, PCI identity, common binary hashes, every raw benchmark sample, and every bandwidth/time pair before producing the JSON and Markdown outputs.
