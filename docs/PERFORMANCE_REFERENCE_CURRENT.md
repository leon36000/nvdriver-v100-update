# Current CUDA performance reference

## Short stock RTX 5080 repeat — 2026-11-03 17:17 UTC, 9 launch samples

A report-contract-checked repeat used stock R595.99.02 and the pinned SM120 device on PC3. It executed 256 empty-kernel launches per sample after 64 warmups. CUDA-event launch timing was **1.2681 µs median / 1.2856 µs p95**; host API timing was **1.2669 / 1.2714 µs**. A one-node CUDA Graph replay measured **1.9390 / 2.0477 µs** by CUDA events and **1.2736 / 1.3200 µs** by host API timing.

| Pinned transfer size | H→D median / p95 | D→H median / p95 |
| ---: | ---: | ---: |
| 4 KiB | 3.0769 / 3.0809 GB/s | 3.8882 / 3.8937 GB/s |
| 64 KiB | 27.0642 / 27.2357 GB/s | 35.5449 / 35.6707 GB/s |
| 1 MiB | 47.4383 / 47.5415 GB/s | 24.2524 / 24.6121 GB/s |
| 16 MiB | 50.3832 / 50.5240 GB/s | 24.1774 / 24.7026 GB/s |
| 64 MiB | 51.1326 / 51.3140 GB/s | 23.3294 / 23.5985 GB/s |

The benchmark's copy-integrity checks passed for all sizes. The outer hybrid acceptance still returned 77 because SM70 was absent, and independent CUDA hardware attestation remains false. These nine-sample results are a short report-backed repeat; the 1,001-sample capture below remains the stronger reference. The path-free [receipt](../evidence/pc3-rtx5080-stock-benchmark-sanitized-v3-20261103.json) has SHA-256 `a323723b96acc28e4d8369038a73cb92a6a38bc4d71aa8a775aec2d5255eb151`.

## PC3 RTX 5080 stock-driver reference — 2026-11-03, 1,001 samples

The exact pinned CUDA 12.9.2 v3 probe/fatbin ran on PC3's RTX 5080 (SM120, BDF `0000:02:00.0`) with stock R595.99.02 and CUDA Driver API 13020. Synchronous and asynchronous numerical checks passed for **1, 31, 256, 4096, and 65537** elements, cleanup passed, and the report records transfer integrity as true for every direction and size. The probe returned **77** because SM70 was absent from the host.

The `hybrid_empty` kernel measured **1.1856 µs median / 1.2053 µs p95** by CUDA events and **1.1839 µs / 1.2039 µs** by host API timing. The separate strict-host-key `nvidia-smi pmon` stream observed the single `probe` process during 12 of 20 samples, with nonzero SM utilization in all 12 process rows (peak **99%** SM, **7%** memory).

| Transfer size | H→D median / p95 | D→H median / p95 |
| ---: | ---: | ---: |
| 4 KiB | 3.1095 / 3.1434 GB/s | 3.8869 / 3.9050 GB/s |
| 64 KiB | 26.7357 / 26.8508 GB/s | 35.1918 / 35.4057 GB/s |
| 1 MiB | 47.3013 / 47.6106 GB/s | 24.2793 / 24.6817 GB/s |
| 16 MiB | 50.4172 / 50.6803 GB/s | 23.8389 / 24.4230 GB/s |
| 64 MiB | 50.4135 / 50.8894 GB/s | 23.2629 / 23.7600 GB/s |

These are **probe-reported single-run stock values**, not a qualified performance result or a driver gain. The receipt explicitly keeps `performance_benchmark_validated=false` and `independent_hardware_attestation=false`; it does mark RTX execution observed by the separate NVML monitor. No hybrid module, V100, UVM/P2P path, inference model, or matched application workload was tested.

The path-free [receipt v3](../evidence/pc3-rtx5080-pmon-summary-v3-20261103.json), SHA-256 `2a11022b8f049901197a8130188a61b3535c90cfd5d1a0a8a694dd330b06a91a`, contains the reduced aggregates. The raw report is mode `0600` at `evidence/logs/pc3-rtx5080-pmon-runtime-v2-20261103.json` (SHA-256 `416e4f66f17b3abfb9e16f9cc9fdd6a132de4fcb6df83934bc88daee5d90770a`); the separate Pmon witness is mode `0600` at `evidence/logs/pc3-rtx5080-pmon-witness-v2-20261103.json` (SHA-256 `5a6da0f1d4fcf4ee89f402fdf76169c355248250aaee267ea115558297cb7a4d`).

## PC3 RTX 5080 stock-driver capture — 2026-11-02

Three back-to-back captures on the stock RTX 5080 produced report-contract-valid, hybrid-incomplete results. Each used PC3 BDF `0000:02:00.0` (SM120), Linux `7.0.0-38-generic`, NVIDIA R595.99.02, the same pinned SM70/SM120 probe (SHA-256 `85fdf6a3d3f7c98bad83d8e5dcd7f88fdbcf19fbf25866e0c7fc3e8d4e37bb98`), fatbin (SHA-256 `8dc12fa61f5ed270c3122f5516c2afce43d9c39f5fa9a16f9a7e313fe34f6f70`), and system `libcuda` (SHA-256 `192d4eedb1b39f0568f2b5423d35227d13b32b9025599e1968a9081982da207d`). Each recorded 101 kernel-launch samples and 101 transfer samples at each size. Numeric checks, cleanup, and transfer data-integrity checks passed for SM120. The runner returned 77 because SM70 was absent from the host.

| Capture | Observed UTC | SHA-256 |
| --- | --- | --- |
| [v2](../evidence/pc3-rtx5080-stock-benchmark-v2-20261102T1533Z.json) | 15:32:06 | `f47161ad0db8a76b177bda10e9ab98bfac4d2652a78a7ce9327b109299121ab9` |
| [v3](../evidence/pc3-rtx5080-stock-benchmark-v3-20261102T1534Z.json) | 15:33:32 | `7a802adbf2905f426852f7f5fdebf100b78a63b620e6dac9d9a3b1a5f52a31ea` |
| [v4](../evidence/pc3-rtx5080-stock-benchmark-v4-20261102T1535Z.json) | 15:33:50 | `3bbf593bcbc8b322290300b3225e6618ad880460cdd00e5488e69acd60a57246` |

The latest individual run (v4) measured the following medians. Transfers were verified byte-for-byte in both directions.

| Transfer size | Host-to-device | Device-to-host |
| ---: | ---: | ---: |
| 4 KiB | 3.1219 GB/s | 3.8780 GB/s |
| 64 KiB | 26.7439 GB/s | 35.4872 GB/s |
| 1 MiB | 48.0557 GB/s | 24.3041 GB/s |
| 16 MiB | 50.9463 GB/s | 23.8313 GB/s |
| 64 MiB | 51.1813 GB/s | 23.2536 GB/s |

For the empty `hybrid_empty` kernel, v4 measured host API latency of **1.1893 µs median / 1.2684 µs p95** and CUDA-event elapsed time of **1.1911 µs median / 1.2699 µs p95**. These are single-run diagnostic values; they do not represent inference or application performance.

The local aggregation helper refuses to pool these captures because independent execution attestation and its trusted key are not configured. The report contract and numeric checks are evidence about the stock RTX path only; the wrapper intentionally keeps `cuda_execution_validated=false`. No V100 result, same-process Volta/Blackwell test, hybrid-driver result, or speedup is established. No candidate module was installed or loaded. The separately attempted V100 guest reference stopped at non-interactive sudo authentication before guest execution; see [the checkpoint](STATE.md).

## Reproduction

Use the pinned selected-GPU runner with the same probe/fatbin and the target's current PCI BDF and UUID. For a fresh full benchmark capture, use `--performance-benchmark` and a new evidence path; the runner refuses mismatched artifact pins. Do not compare values across different drivers, GPU clocks, thermal states, host memory modes, or probe builds without recording those variables.
