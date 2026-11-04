# NVIDIA hybrid-driver experiments

Experimental work in the canonical `cuda13-volta-compat-20260927` project. Parent CUDA13-Volta and VoltaFabric assets remain authoritative.

## Current status — 2026-11-02

The project is **incomplete**. The selected experiment is a R595.99.02 shared frontend/Open Blackwell provider plus a separately namespaced R580.196.07 Volta provider and one R595 UVM consumer. The four-module bundle compiled and passed static import/CRC closure; the hash-pinned isolated `depmod`/`modprobe --show-depends` check was freshly rerun for Linux `7.0.0-38-generic` ([receipt](evidence/hybrid-module-bundle-depmod-r595580-v6-20261102T0600Z.json), SHA-256 `61f56a24f3e0ef34497fc937077cef734beabc11ec93af05a2a9e0a0ba79d89f`). This verifies a private dependency map only; no candidate module has been installed or loaded.

The latest pinned CPU/software suite passes **2,563/2,563** in **173.99 s**, exit 0 ([receipt](evidence/software-verification-openrm-hal-matrix-v1-20261102T153807Z.json), SHA-256 `72a9fac0957e063c6eafe48cb3791cac3662a6bed252d2d8976481a18718572f`). It found zero source changes during the run across 371 test and 90 implementation inputs. This remains software-only evidence; no candidate module was loaded. A fresh PC3 inventory at 15:52Z confirms the RTX 5080/R595.99.02 is idle (0 compute processes; 2 MiB reported in use) and host-visible; the V100 remains assigned to the active VM on `vfio-pci`, in a separate IOMMU group and PCI domain. ACS remains unknown because unprivileged capability reads are denied. A PC3-only SSH tunnel reached the guest endpoint and matched its pinned host-key fingerprint, but the available user key was denied; no guest command or kernel ran, and the tunnel was closed. The V100 runner still needs root on PC3 to read its guest SSH identity; no other PC or credential route was used. The stock RTX kernel phase passed with numeric result `1200/1200`; three separate 101-sample benchmark captures passed their report and data-integrity contracts, but the host lacks SM70 and independent execution attestation is not configured. Their per-run metrics and limits are in [the current performance record](docs/PERFORMANCE_REFERENCE_CURRENT.md). Direct V100 guest execution stopped at the PC3 noninteractive-sudo boundary before a guest command. No same-process V100+RTX CUDA or hybrid-driver operation has been validated, and no performance gain is claimed.

The [dual-architecture inference matrix](docs/AI_RUNTIME_COMPATIBILITY.md) selects llama.cpp as the first workload after same-process kernels pass. A separate llama.cpp 0.8.0-dev build (commit `1c5ed702c9e540ac14cc8c78100ea3984bc0e227`) contains 146 SM70 PTX images and 146 SM120a cubins, verified with the project-local CUDA 12.9.2/CMake 4.4.5 toolchain and pinned `cuobjdump` ([receipt v6](evidence/llama-cpp-cuda129-artifact-audit-v6-20261102.json), SHA-256 `62965ad241f7c96a891c16c24eb495b6cfa2d587019c59dace1b6eb2461dab18`). The same configuration builds upstream `test-backend-ops`; the [guarded PC3 runner](tools/run_llama_backend_ops.py) now rejects upstream's missing-backend false success and expired-receipt aggregate pass, verifies mapped-library identity on every poll and after process exit, enforces the authorized host, maps PCI identities to tested CUDA ordinals, and binds runtime-library hashes to mapped file inodes. Its success, timeout, expiry, in-flight mutation, post-exit, and cache-mutation paths pass 35 focused CPU tests; no GPU process was launched. Neither application binary has run on a GPU; no model or inference ran. The separate pinned v0.8.0/CUDA 12.8 acceptance profile remains unbuilt.

A repeatable compiler-only check now builds an SM120a CUDA Runtime translation unit on this host with `-U_GNU_SOURCE`; the helper requires successful version queries for NVCC, GCC, and `cuobjdump`, which then confirms the cubin image. The executable is not run. This does not validate runtime behavior or replace the CUDA 12.8 shared-toolchain plan ([tool and evidence](tools/verify_nvcc_cuda_smoke.py), [receipt](evidence/cuda-toolchain-sm120-header-smoke-v3-20261102T0604Z.json)).

The current Driver API acceptance probe was rebuilt locally with separate Volta13 SM70 and Clang 23 + CUDA 13.1/`ptxas` SM120 images. The combined fatbin contains both cubins, the host executable passes the compile warnings and does not link `libcuda`, and its contract version 9 is readable in `--contract` mode. The [receipt](evidence/hybrid-probe-sm70-sm120-build-v1-20261102T0602Z.json) explicitly says the CUDA API was not initialized, no GPU or kernel was accessed, and runtime validation remains false.

R595.112.07 is the newest inspected R595 source base and has a separate historical compile/static-closure result for Linux `7.0.0-38-generic`. Its source delta against R595.99.02 is 93 changed files out of 2,172 C/H files, with all 213 UVM C/H files identical. Four narrowly scoped Linux-backend fixes are adapted into R595.99.02: oversized page-table allocation, scatter/gather DMA unmap count, read-only VMA protection ordering, and null per-CPU RSS backing. They do not enable cross-provider P2P or add Blackwell instructions to Volta; no gain is measured. See [the architecture record](docs/ARCHITECTURE.md), [checkpoint](docs/STATE.md), and [validation record](docs/VALIDATION.md).

REA 6.8.0 and Ghidra 12.1.4 are installed locally. Targeted analysis of the GPL Nouveau module and a project-built open R595.112.07 UVM module are recorded in sanitized receipts; proprietary NVIDIA module binaries remain excluded from REA because the installer license restricts reverse engineering. The user has authorized PC3 testing and transfer to the requested PC4 GitLab project. The local staged snapshot is prepared, but HTTPS `git ls-remote` cannot authenticate, the available PC3 SSH key is rejected, and local Git author identity is unset; therefore no commit or push has been made, and remote refs remain unknown. `.gitignore` excludes build/cache output, raw logs, compressed traces, raw host inventory, and raw REA/Ghidra output. See [the reverse-engineering boundary](docs/REVERSE_ENGINEERING.md), [checkpoint](docs/STATE.md), and [transfer procedure/status](docs/GITLAB_TRANSFER.md).

The older sections below preserve dated experiments and reproduction notes. Their historical “current” or “next” wording does not supersede the checkpoint or architecture record.

## Probe and software checks

The pinned CUDA probes contain SM70 and SM120 images. Their default numerical phases execute kernels sequentially. The optional `--concurrent-kernels` mode dispatches bounded, numerically checked work from two host threads and reports host dispatch/synchronization-window overlap; that does **not** validate concurrent GPU execution. To establish GPU timeline overlap, capture an Nsight Systems trace and run the SQLite export through [`tools/audit_nsys_concurrent_overlap.py`](tools/audit_nsys_concurrent_overlap.py). A hybrid pass requires both exact PCI BDFs to be present in the same Linux system and both devices to pass numerical checks. Separate host/VM results do not satisfy this gate.

The latest pinned CPU/software suite is recorded in the current status above; this older v12 probe receipt from November 1 passes **2,427/2,427** tests. It confirms unchanged test and implementation inputs and pins both probe environment variables to v12 (SHA-256 `ad1d63b81f8ec2dbeba37c156bf230c9059f7d9d54e5a48e9097303408966898`). See the [dated suite receipt](evidence/software-verification-openrm-hal-matrix-v1-20261101T103741Z.json), SHA-256 `79c4ab078c3426d316279ff3f3e39b5cb73d2b9699ba878073406863ce52722a`, and private log (local-only artifact; excluded from GitLab transfer; source: `evidence/logs/software-verification-openrm-hal-matrix-v1-20261101T103741Z.log`), SHA-256 `37432b9a4f92fa824503c0ee05fb320a43762e27f05b6166211cd1c66f368c38`. The exact 32-instance mask test has seven scenarios; the VMM fake-driver and runner-contract tests pass 33/33 in their log (local-only artifact; excluded from GitLab transfer; source: `evidence/logs/vmm-peer-fake-driver-focused-v3-20261031.log`). Run the repository helper below to pin the current probe automatically:

```sh
python3 -B tools/run_software_test_suite.py
```

This verifies source/CPU contracts only. `tests/fixtures/fake_cuda_driver.cpp` and `tests/fixtures/vmm_fake_libcuda.cpp` inject responses into host executables using CPU memory; neither simulates functioning CUDA hardware. A successful build, module closure report, or software suite cannot qualify GPU initialization or execution.

### Opt-in peer-transfer diagnostic

The current research probe is `build/probe-peer-transfer-v3-20261031/build-manifest.json` (local-only; excluded from GitLab transfer). Its SM70/SM120 fatbin contains the `hybrid_peer_read` entry point in both images, and its host binary SHA-256 is `d7cdbd528cbf4665a1ffe2ca0d5792e8e70de98cb88fd368f4a1e496abdcac13`. `--peer-transfer` checks capability and context access in both directions, deterministic 4 KiB synchronous/asynchronous `cuMemcpyPeer` copies, and (for each enabled direction) a kernel launched on the destination GPU that dereferences and verifies a source-context allocation. `peer-memory-verified` therefore means the test kernel read the peer allocation in that run; it still does not identify the physical DMA, NVLink, or PCIe route. Every report keeps `direct_dma_attested=false`, and this diagnostic does not enable production cross-provider P2P. CUDA peer access is directional, while peer-copy APIs are distinct; the Driver API's blanket immediate-access statement is conditioned on UVA and matching major compute capability, so this SM70/SM120 test must be validated on hardware ([CUDA Driver API peer access](https://docs.nvidia.com/cuda/cuda-driver-api/cuda_driver_api/group__CUDA__PEER__ACCESS.html), [memory management](https://docs.nvidia.com/cuda/cuda-driver-api/cuda_driver_api/group__CUDA__MEM.html)).

When both cards are visible to the same Linux kernel, run this on that host with its actual PCI BDFs. The acceptance runner pins the CUDA 12.9.2 v3 host-staged probe and fatbin below. Use these exact paths: the separate CUDA 13 output from `tools/build_probe.py` is not interchangeable with this reviewed acceptance pair.

```sh
set -euo pipefail
: "${V100_PCI:?set the V100 PCI BDF visible on this Linux host}"
: "${BLACKWELL_PCI:?set the Blackwell PCI BDF visible on this Linux host}"
: "${EVIDENCE_DIR:?set a fresh writable evidence directory on this host}"
python3 tests/run_hybrid_acceptance.py \
  --probe build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_cuda_probe \
  --module build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_probe.sm70-ptx_sm120a-cubin.fatbin \
  --expected-device "70=${V100_PCI}" \
  --expected-device "120=${BLACKWELL_PCI}" \
  --peer-transfer \
  --evidence-dir "$EVIDENCE_DIR"
```

This is a stock-driver diagnostic; it does not install or load the hybrid candidate. The same-process gate is not met by separate V100 VM and Blackwell host results.

### Opt-in CUDA VMM peer-memory diagnostic

The classic peer-context probe above uses `cuCtxEnablePeerAccess`. CUDA 13.1 documents the blanket immediate-access guarantee for that API when devices have the same major compute capability. Its VMM guide separately documents explicit per-device access permissions for a mapped allocation, but does not promise that this SM70/SM120 pairing is supported on every topology. The isolated VMM probe tests that exact question: allocate pinned physical memory on one GPU, map it in the process, grant read-write access to the source and read-only access to the peer with `cuMemSetAccess`, verify both permissions, and run `hybrid_peer_read` from the other GPU. It repeats in both directions and checks every output value. It never calls `cuCtxEnablePeerAccess`, changes production UVM/P2P routing, or claims a physical DMA route. If `cuMemUnmap` fails, it skips the dependent release/free calls and the reverse direction, and reports failure. See the [CUDA 13.1 VMM guide](https://docs.nvidia.com/cuda/archive/13.1.0/cuda-programming-guide/04-special-topics/virtual-memory-management.html) and [CUDA 13.1 peer-context reference](https://docs.nvidia.com/cuda/archive/13.1.0/cuda-driver-api/group__CUDA__PEER__ACCESS.html).

Build the separate probe (the pinned default output is `build/vmm-peer-probe-v3-20261031`), then run it only on the Linux host that sees the exact V100 and Blackwell PCI devices. Its build manifest is deterministic for the pinned inputs. The hardware runner independently pins the executable SHA-256 (`3ebe23609679621035c14f2eec895e4df5df0cbe9bd8e00cddde23e8b9cd92e0`), manifest SHA-256 (`52daa929819bc3b82407a6f3fa16824dc9083a45ac8cd81510ded7b87f8e2e5d`), and SM70/SM120 fatbin (`9b6c772590c0e7ce6a95e36fb637b769eceef69856979761d739028d8b45675f`); an adjacent edited manifest cannot authorize a replacement executable. It also refuses target GPUs with an active compute process, removes loader override variables, records the resolved `libcuda` path and hash, and creates a fresh mode-0600 evidence file without overwriting. A changed source, compiler, or build output requires a reviewed new hash pin before the runner will accept it. Pick a new evidence filename for every run:

```sh
set -euo pipefail
python3 -B tools/build_vmm_peer_probe.py
: "${V100_PCI:?set the V100 PCI BDF visible on this Linux host}"
: "${BLACKWELL_PCI:?set the Blackwell PCI BDF visible on this Linux host}"
: "${EVIDENCE_FILE:?set a fresh evidence JSON path on this host}"
python3 -B tools/run_vmm_peer_probe.py \
  --expected-device "70=${V100_PCI}" \
  --expected-device "120=${BLACKWELL_PCI}" \
  --evidence "$EVIDENCE_FILE"
```

The probe is a separate process from `--peer-transfer` so both classic context access and explicit VMM mapping can be compared without conflating their APIs. A successful VMM kernel read is runtime evidence for that exact host, driver, GPU pair, and direction; it still does not prove direct DMA/NVLink routing, production cross-provider P2P, UVM migration, or performance. No hardware VMM run has been made yet.

Run acceptance from this project checkout on the Linux host that physically owns both GPUs. Stage the pinned v12 bundle there, then set `PROBE_DIR` to that host's bundle directory and `EVIDENCE_DIR` to a writable evidence directory on that host. The hash gate prevents accidentally running a stale local probe:

```sh
set -euo pipefail
: "${PROBE_DIR:?set to the staged, pinned v12 probe bundle on this GPU host}"
: "${EVIDENCE_DIR:?set to a writable evidence directory on this GPU host}"
: "${V100_PCI:?set the V100 PCI BDF from the same Linux host}"
: "${BLACKWELL_PCI:?set the Blackwell PCI BDF from the same Linux host}"
PROBE="$PROBE_DIR/hybrid_cuda_probe"
MODULE="$PROBE_DIR/hybrid_probe.sm70-sm120.fatbin"
printf '%s  %s\n' \
  d7cdbd528cbf4665a1ffe2ca0d5792e8e70de98cb88fd368f4a1e496abdcac13 "$PROBE" \
  9b6c772590c0e7ce6a95e36fb637b769eceef69856979761d739028d8b45675f "$MODULE" \
  | sha256sum --check
python3 tests/run_hybrid_acceptance.py \
  --probe "$PROBE" \
  --module "$MODULE" \
  --evidence-dir "$EVIDENCE_DIR" \
  --expected-device "70=${V100_PCI}" \
  --expected-device "120=${BLACKWELL_PCI}" \
  --concurrent-kernels
```

Acceptance records probe, fatbin and resolved `libcuda` identities. `--concurrent-kernels` adds bounded numeric launches from two host threads and checks their host dispatch/synchronization windows; this does not establish GPU timeline overlap. For that separate measurement, choose a fresh `TRACE_DIR` on the same host and capture/export the exact run:

```sh
set -euo pipefail
: "${V100_PCI:?set the V100 PCI BDF from this host}"
: "${BLACKWELL_PCI:?set the Blackwell PCI BDF from this host}"
: "${PROBE_DIR:?set to the staged, pinned v12 probe bundle on this GPU host}"
: "${TRACE_DIR:?set a new, writable directory for this capture}"
PROBE="$PROBE_DIR/hybrid_cuda_probe"
MODULE="$PROBE_DIR/hybrid_probe.sm70-sm120.fatbin"
printf '%s  %s\n' \
  d7cdbd528cbf4665a1ffe2ca0d5792e8e70de98cb88fd368f4a1e496abdcac13 "$PROBE" \
  9b6c772590c0e7ce6a95e36fb637b769eceef69856979761d739028d8b45675f "$MODULE" \
  | sha256sum --check
if [[ -e "$TRACE_DIR" || -L "$TRACE_DIR" ]]; then
  printf 'TRACE_DIR already exists; choose a new evidence path: %s\n' "$TRACE_DIR" >&2
  exit 2
fi
mkdir -p "$TRACE_DIR"
nsys profile --trace=cuda --output="$TRACE_DIR/hybrid-concurrent" \
  "$PROBE" --module "$MODULE" --require-sm 70,120 \
  --expected-device "70=${V100_PCI}" \
  --expected-device "120=${BLACKWELL_PCI}" \
  --concurrent-kernels
nsys export --type=sqlite \
  --output="$TRACE_DIR/hybrid-concurrent.sqlite" \
  "$TRACE_DIR/hybrid-concurrent.nsys-rep"
python3 tools/audit_nsys_concurrent_overlap.py \
  --trace-sqlite "$TRACE_DIR/hybrid-concurrent.sqlite" \
  --expected-device "70=${V100_PCI}" \
  --expected-device "120=${BLACKWELL_PCI}" \
  > "$TRACE_DIR/overlap-audit.json"
cat "$TRACE_DIR/overlap-audit.json"
```

The auditor requires the named kernel to have overlapping GPU activity intervals on the pinned SM70 and SM120 devices. Pair that audit with the numerical acceptance result; profiler overlap alone does not prove correctness. Acceptance exit `0` means the requested report contract passed for the exact pair, `77` means hardware is missing, `2` means failure or an inconsistent report, and `124` means timeout. Neither the report nor the Nsight audit independently attests the driver. `--allow-incomplete` preserves incomplete qualification even if it permits exit zero. Do not replace the stock driver or load experimental modules without a separately verified canary and rollback procedure.

## R595.104.02 OpenRM policy experiment (historical)

Official tag `595.104.02`, commit `ac24e02fc090c3e05c1fc03384b317ac2cc301b5`. Obtain the [exact NVIDIA commit archive](https://codeload.github.com/NVIDIA/open-gpu-kernel-modules/tar.gz/ac24e02fc090c3e05c1fc03384b317ac2cc301b5). Local cache: `.cache/upstream/open-gpu-kernel-modules-ac24e02fc090c3e05c1fc03384b317ac2cc301b5.tar.gz`. Required SHA-256:

```text
da4e454d493818027998fc9d7ef95fd5dd291d3d37119f1f81d12db85fc33190
```

Use a new work directory for each experiment:

```sh
python3 tools/build_openrm_gv100_probe.py \
  --source-archive .cache/upstream/open-gpu-kernel-modules-ac24e02fc090c3e05c1fc03384b317ac2cc301b5.tar.gz \
  --work-dir build/experiments/openrm-gv100-firmware-v2 --jobs 4
```

The tool verifies archive digest/root, runs the policy contract, applies [the opt-in patch](patches/r595.104.02/0001-gv100-monolithic-firmware-policy.patch) with zero fuzz, then builds full RM/modules and archives logs/hashes/modinfo. `NV_HYBRID_EXPERIMENTAL_GV100` changes only exact GV100 policy. This build contains stock modern UVM, separate from the legacy overlay. The firmware patch is not the earliest change required: `RmInitPrivateState` already uses generated GpuArch selection before the firmware request.

## Early R580.178.04 two-backend object-link experiment

This early experiment proposed a **same-version R580.178.04 pair**: proprietary physical RM for Volta and Open RM for Blackwell. It has since been superseded as the leading prototype by the R595.99.02 frontend/UVM plus private R580.196.07 Volta provider documented in `docs/STATE.md`. The R580.178.04 work remains source and fallback evidence; its shared headers do not prove full ABI compatibility or user-space routing.

`tools/probe_rm_namespace_link.py` resolves colliding strong definitions in a copy of the Open object only. It refuses implicit cross-backend references, weak/absolute external definitions, destination-name collisions and existing work trees. Neither original input is modified. The real R580 pair links as an ET_REL object after213 renames, with411 unclassified undefined names. It is **not a Linux module or CUDA driver**. The cross-version R580/R595 control also links after210 renames, with416 undefined names. Reports: `evidence/same-branch-rm-link-v2-20261018.json` and `evidence/cross-branch-rm-link-v2-20261018.json`.

The R580 Open baseline source/object paths and exact archive/build command are recorded in `evidence/openrm580-source-baseline-v1-20261018.json`. To repeat the namespace experiment using those existing verified inputs:

```sh
python3 tools/probe_rm_namespace_link.py \
  --legacy-object .cache/vendor-proprietary/r580.178.04-ubuntu/usr/src/nvidia-580.178.04/nvidia/nv-kernel.o_binary \
  --open-object build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04/src/nvidia/_out/Linux_x86_64/nv-kernel.o \
  --work-dir build/experiments/same-branch-rm-link-v3 --prefix hybrid580_
```

The proprietary reference was downloaded/extracted only, with its package hash verified; no package scripts ran. No redistribution rights for a combined artifact are asserted. The fixture tests execute only tiny project-owned C functions to verify symbol binding; they never execute NVIDIA RM code. Shared external dependencies, per-backend client handles, global ioctl routing, UVM ownership, module flavor and licensing remain integration gates.

## Root-client bridge

`src/rm_root_client.c` is the first C bridge slice against the real R580 `rm_ioctl`, `NVOS21`/`NVOS64` and `NVOS00` declarations. It allocates a root in the legacy backend, requests the same client ID through `hRoot` in the Open backend, and publishes the ID only after both status channels succeed. It keeps backend file-private state separate, rolls back confirmed allocations in reverse order, and quarantines every backend allocation failure or failed free. No handle from an error response is freed blindly. The caller must provide isolated initialized RM instances and serialize file lifetime operations.

The broker now also accepts versioned opaque session endpoints from `src/rm_session_endpoint.h`. It snapshots callback/context/ownership tokens, retains no raw stack/control/nvfp on that route, and preserves publication, rollback and quarantine behavior. Callers still own references and serialize complete transactions. Per-call stack/PM resources belong to the backend callback. The original typed raw-RM API remains a compile/link experiment.

[Fresh bridge evidence](evidence/r580-root-client-bridge-v6-20261019.json) records the unchanged411 dependencies; [Kbuild objects](evidence/r580-root-client-kbuild-v5-20261019.json) compile with Linux7.0.0-38 headers. Eighty-six CPU scenarios cover raw/session endpoints and both packet forms. **No real RM function executes in these tests.** Scope remains automatic ROOT allocation/free, NULL class parameters/rights and flags NONE. Child resources, generic controls, enumeration and UVM remain unimplemented.

```sh
python3 tools/build_rm_root_client_bridge.py \
  --work build/experiments/root-client-bridge-next \
  --report evidence/root-client-bridge-next.json
python3 tools/build_rm_root_client_kbuild.py \
  --work build/experiments/root-client-kbuild-next \
  --report evidence/root-client-kbuild-next.json
```

The [ABI report](evidence/r580-abi-layout-20261018.json) measures matching host C declarations, not the proprietary binary or kernel-build ABI. The [dependency inventory](evidence/r580-external-dependencies-20261018.json) distinguishes source candidates from compiled providers. Neither report certifies runtime compatibility.

The separate [official Open580 wrapper baseline](evidence/open580-wrapper-baseline-20261018.json) builds `nvidia.ko` and supplies398 dependencies in compiled objects; the remaining13 are kernel-exported thunks. This module contains only the official Open RM. It retains its original license metadata; its104 GPL-only imports are a constraint on a future module design, not permission to label a merged proprietary core GPL. Its build also emitted objtool return-mitigation warnings, retained in the logs; no loading or hardware qualification follows from this result.

**PC3 scope:** the user authorizes installed-driver reference tests on both GPUs. RTX5080 host tests use its verified UUID in `CUDA_VISIBLE_DEVICES` plus `--expected-pci 0000:02:00.0` before context creation. The V100 at host BDF `0000:81:00.0` remains assigned to its active VM; guest `pc3-v100` reports BDF `0000:00:05.0`, kernel `6.8.0-147-generic`, driver `580.178.04`. The V100-only SM70 reference and full R580 acceptance passed in that guest. Same-Linux coexistence remains untested; do not stop/rebind the VM or replace its driver as part of an installed-driver reference test.

## Selected RTX5080 reference and private backend

The fresh [PC3 run](evidence/pc3-rtx5080-postcanary-reference-v1-20261020.json) passes RTX5080 SM120 architecture, five synchronous/asynchronous sizes and cleanup on the installed595.99.02 driver; the typed ROOT observations are summarized in [this report](evidence/pc3-rtx5080-postcanary-root-summary-v1-20261020.json). Its only visible GPU is RTX5080 SM120. The hybrid result remains incomplete, exit77, missing70. This is an official-driver reference, not execution of an experimental backend. The versioned reference probe is in `build/probe-selected-v1/`; for new guarded runs, rebuild the contract-reporting probe first so stale binaries are rejected locally before SSH.

```sh
python3 tools/build_probe.py --output-dir build/probe-contract-v2-20261022
HYBRID_PROBE="$PWD/build/probe-contract-v2-20261022/hybrid_cuda_probe" \
HYBRID_CUDA_PROBE="$PWD/build/probe-contract-v2-20261022/hybrid_cuda_probe" \
python3 -B -m unittest discover -v -s tests
python3 tools/run_remote_selected_gpu.py \
  --target pc3@pc3 --host-key-alias pc3 \
  --gpu-uuid GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77 --pci 0000:02:00.0 \
  --probe build/probe-contract-v2-20261022/hybrid_cuda_probe \
  --module build/probe-contract-v2-20261022/hybrid_probe.sm70-sm120.fatbin \
  --evidence evidence/pc3-rtx5080-selected-cuda-repeat.json
```

The local tool first verifies the executable's SHA-256 and the no-CUDA `--contract` response against the report schema required by the acceptance runner; an old probe is rejected before SSH. The remote tool checks selected `/proc` identity/binding, targets NVML by UUID, cleans the child's injection environment, checks a unique PCI/SM120 device in inventory and again before contexts, then records hashes before/after and strict missing-hardware qualification. It issues no VM-management or experimental driver-change command. It does not attest absence of internal NVIDIA enumeration or official module autoload.

## V100 guest numerical reference

The guarded [PC3 V100 guest runner](tools/run_pc3_v100_guest_reference.py) passes the prebuilt probe and fatbin through PC3's existing guest route, verifies the sole pinned host key for the exact forwarded endpoint using root-owned known-hosts material, checks exact GPU identity, runs only the SM70 requirement, and removes hash-verified temporary files. A real-key negative test rejects an unrelated-host fingerprint. The runner reads the authorized PC3 sudo value from the PC6 mode-0600 credential file into memory; neither the value nor the authentication stdin is stored in evidence. No module, driver, VM, or PCI binding is changed. The fresh [hardware report](evidence/pc3-v100-sm70-reference-v4-20261020.json) validates five sync/async sizes and cleanup under guest driver580.178.04, Driver API13000. Its status is V100 reference only (`hybrid_validated=false`).

```sh
python3 -B tools/run_pc3_v100_guest_reference.py \
  --evidence evidence/pc3-v100-sm70-reference-v5-20261020.json
```

The separate parent V100/R580 acceptance bundle (local-only artifact; excluded from GitLab transfer; source: `../hardware/v100-r580/README.md`) is the authority for its CUDA-X, RDC/device-link and library smoke matrix. It passed all21 gates on the installed R580 guest after physical cooling confirmation; see the [acceptance report](evidence/pc3-v100-r580-acceptance-final-20261020.json) and [validation record](docs/VALIDATION.md). This remains a V100-only guest result and does not qualify the hybrid driver.

Selected-process [IOCTL trace](evidence/pc3-rtx5080-ioctl-summary-20261019.json):599 calls, including100 RM_ALLOC requests of48 bytes. This drove the NVOS64 broker addition. Payload classes, pointers, rights, flags and embedded statuses were not observed; packet size alone does not prove the broker covers the real root-allocation contents. UVM calls in that trace do not validate managed-memory migration.

The private Open R580 patches0002–0009 now compile with99 private exports. The latest slice projects a frontend FD onto a referenced, genuine backend file in both RM fd lookup and device-state matching. It preserves the embedded event container, validates backend ownership and uses an atomic reader/writer protocol for provider removal. The direct backend path bypasses projection; minor lookup uses direct indexing rather than scanning248 entries. This algorithmic change has no measured latency gain yet. No common frontend/provider or CUDA routing is running.

The Open RM is also rebuilt with the existing `EXTRA_CFLAGS=-mfunction-return=thunk-extern` hook. [Source/compiler evidence](evidence/r580-open-return-thunk-20261019.json) and the [integrated module](evidence/private-open-control-session-v2-20261019.json) show the witness return transformed and the10857 naked-return warnings removed, with objtool still enabled. The latest module has zero objtool warnings and30 other recorded warnings. This concerns the Open backend only; the proprietary reference remains unchanged and full kernel mitigation behavior is unqualified.

```sh
python3 -B tools/probe_private_backend_chardev.py --resource-isolation --file-projection \
  --core build/experiments/openrm580-return-thunk-v1/NVIDIA-kernel-module-source-580.178.04/src/nvidia/_out/Linux_x86_64/nv-kernel.o \
  --core-sha256 c5f7a58442286f02f9caebf3279320dd8a846883d7514c183981efa754d11248 \
  --work-dir build/experiments/private-open-file-projection-next \
  --report evidence/private-open-file-projection-next.json
```

The builder refuses existing destinations and never loads or installs a module. With --control-session it checks all99 exact export names/flavors and classifies every kernel import. The new reader/writer and VFS imports are ordinary exports; the existing104 GPL-only Open imports remain. Resource names and private major are not automatically discoverable by vendor utilities. Exclusive backend-owned control creation/invocation is implemented and compiled in patch0009; the initial ROOT-only frontend is superseded by the BDF GPU-file frontend below. Runtime dual-backend validation, general ioctl/handle/UVM routing and teardown validation are still required. PCI-only registration does not imply inert global initialization or ARM64 subordinate-device isolation.

## Private control sessions

Patch0009 creates an unpublished control file using real VFS allocation and the original NVIDIA open/private-data path. Four private exports provide create/get/put/backing-file operations. Opaque invocation serializes the session, acquires PM read protection and a fresh temporary stack per call, validates ROOT32/64/FREE, then releases resources. The persistent open/close stack is preserved. Final fput can defer RM cleanup; returning from put does not certify completed teardown.

```sh
python3 -B tools/probe_private_backend_chardev.py --resource-isolation --file-projection --control-session --gpu-session \
  --core build/experiments/openrm580-return-thunk-v1/NVIDIA-kernel-module-source-580.178.04/src/nvidia/_out/Linux_x86_64/nv-kernel.o \
  --core-sha256 c5f7a58442286f02f9caebf3279320dd8a846883d7514c183981efa754d11248 \
  --work-dir build/experiments/private-open-control-attach-next \
  --report evidence/private-open-control-attach-next.json
```

The current attach build produces107 private exports. The source-extracted control-session suite executes67 CPU scenarios for construction failures, references, request/status boundaries, attach pin/rollback and invocation serialization. These models do not validate Linux VFS/LSM, real RM execution or hardware. No session, frontend or experimental module has run in the kernel.

## R580 UVM module-pair compile

The upstream R580.178.04 Open RM and UVM modules were extracted into a fresh tree and built together against Linux7.0.0-38, using the same-version Open RM core compiled with return-thunk mitigation. The exact [audit report](evidence/r580-uvm-clean-thunk-pair-v1-20261021.json) records both module hashes, `vermagic`, unchanged Dual MIT/GPL metadata, the build log, and all76 matching UVM interface imports/exports. This is compile/link and static symbol-closure evidence only: neither module was installed or loaded, and UVM has not run on hardware.

The command below independently audits a previously built pair and refuses mismatched archive/core hashes, incomplete interface closure, malformed metadata, or an existing report:

```sh
python3 -B tools/audit_r580_uvm_module_pair.py \
  --build-tree build/experiments/r580-uvm-clean-v3-20261021/source/kernel-open \
  --source-archive .cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz \
  --rm-core-object build/experiments/openrm580-return-thunk-v1/NVIDIA-kernel-module-source-580.178.04/src/nvidia/_out/Linux_x86_64/nv-kernel.o \
  --expected-rm-core-sha256 c5f7a58442286f02f9caebf3279320dd8a846883d7514c183981efa754d11248 \
  --build-log evidence/logs/r580-uvm-clean-thunk-build-v1-20261021.log \
  --kernel-release 7.0.0-38-generic \
  --report evidence/r580-uvm-clean-thunk-pair-next.json
```

The source ownership audit [`uvm-interface-ownership-r580-v3`](evidence/uvm-interface-ownership-r580-v3-20261021.json) matches all76 R580 declarations to exports and observes a UVM C callsite for each. The bridge must create one logical session backed by two child sessions; route GPUs by UUID; track typed handles; map provider-owned PMA, CPU-map and retained-channel pointers; associate fault/CSL structures with their RM owner; and validate multi-handle calls against one provider. Reproduce the inventory with:

```sh
python3 -B tools/audit_uvm_interface_ownership.py \
  --source-root build/experiments/r580-uvm-clean-v3-20261021/source/kernel-open \
  --source-version 580.178.04 \
  --output evidence/uvm-interface-ownership-r580-next.json
```

This is a bridge contract, not an implemented UVM bridge. Stock-driver references now validate managed allocation, CUDA kernels, GPU/CPU prefetch and cleanup separately on the V100/R580 guest and RTX5080/R595 host: [V100](evidence/pc3-v100-managed-prefetch-reference-v1-20261021.json), [RTX5080](evidence/pc3-rtx5080-managed-prefetch-reference-v2-20261021.json). The devices remain on separate kernels, and no experimental module was loaded.

One `nvidia-uvm.ko` holds a single global callback registration and RM session. The interface inventory is complete, and CPU-side session-pair and typed owner-map primitives model dual child sessions, handle ownership, safe retirement, rollback, and quarantine. They are not wired into the kernel bridge. PM entry-point auditing now separates R580's global procfs suspend protocol from its device-local PCI PMOps. Each private backend gets a distinct procfs name, while PC1's installed NVIDIA sleep script targets only `/proc/driver/nvidia/suspend`; a safe coordinator still needs an all-provider quiesce/restore barrier and exactly-once UVM suspend/resume. See the [source audit](docs/REVERSE_ENGINEERING.md#uvm-callbacks-and-power-management-entry-points-2026-10-21) and [checkpoint](docs/STATE.md). The same-Linux dual-GPU CUDA objective remains unvalidated.

## R580-to-R595 UVM overlay diagnostic build

```sh
python3 tools/probe_volta_uvm_port.py \
  --r580-archive .cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz \
  --scratch build/experiments/r580-uvm-r595-hardened-v2 \
  --compile-probe-adapter --jobs 4
```

Archive digest/root are pinned. Default target: installed source `/usr/src/nvidia-595.99.02`. The diagnostic adapter imports the Pascal MMU base, removes eleven obsolete Volta assignments and adapts two callbacks. Fresh linkage requires a build trace, newly written ELF module and all imported objects compiled this run. Exit `3` means make succeeded without sufficient fresh-link evidence. **Do not load this module:** dispatch, PTE semantics, PLC and scoped atomics remain unresolved. The RM and UVM experiments have not been combined into a runtime driver.

See [checkpoint](docs/STATE.md), [architecture](docs/ARCHITECTURE.md), [source evidence](docs/REVERSE_ENGINEERING.md), [validation/performance status](docs/VALIDATION.md) and [installation/rollback boundary](docs/INSTALL_ROLLBACK.md). Historical `kernel-stub/` is an unrelated MISC device and is not a hybrid-driver milestone.

Project host tools are MIT licensed; imported NVIDIA files retain their notices. The historical Linux stub is GPL-2.0-only. A license-text check is not a legal redistribution determination.

## Typed ROOT observations on the selected RTX5080

The optional own-child observer records top-level allocation/free payload fields and both syscall/payload status channels. It never reads nested pointers or attaches to an existing process. Build against the pinned R580 SDK with the compiler command recorded in `evidence/rm-ioctl-observer-build-v2-20261019.json`; output is `build/experiments/rm-ioctl-observer-v2/rm_ioctl_observer`.

```sh
python3 -B tools/run_remote_selected_gpu.py \
  --target pc3@pc3 --host-key-alias pc3 \
  --gpu-uuid GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77 --pci 0000:02:00.0 \
  --probe build/probe-contract-v2-20261022/hybrid_cuda_probe \
  --module build/probe-contract-v2-20261022/hybrid_probe.sm70-sm120.fatbin \
  --ioctl-observer build/experiments/rm-ioctl-observer-v2/rm_ioctl_observer \
  --evidence evidence/pc3-root-payload-next.json
python3 -B tools/summarize_rm_payloads.py evidence/pc3-root-payload-next.json \
  --report evidence/pc3-root-summary-next.json
```

The fresh V100 and RTX5080 captures have a reproducible [cross-branch comparison](evidence/pc3-volta-blackwell-root-protocol-comparison-v3-20261020.json): both installed drivers accepted two ordinary NVOS64 ROOT requests with `hRoot=0`, and each trace confirms one root FREE with parent==root. The RTX5080 SM120 kernels passed, while its combined acceptance exits77 because no SM70 device is visible. Those packet traces alone did not exercise the broker's mirror request.

## Bounded root-ID mirror probe

`src/rm_root_id_probe.c` issues one NVOS64 ROOT or ROOT_CLIENT allocation on `/dev/nvidiactl`, then frees only a confirmed nonzero allocation. It does not open a CUDA context, select a GPU, or launch a kernel. CPU syscall-double tests cover malformed IDs, both allocation status channels, mismatched IDs, one-shot cleanup and close errors.

Both one-shot numeric-ID directions passed across the installed V100/R580 guest and RTX5080/R595 host. Two live tests also passed: V100 ROOT `3251650399` stayed open through the RTX mirror allocation/FREE, and RTX ROOT `3251634269` stayed open through the V100 mirror allocation/FREE. The source was freed only after the other server completed its mirror request. Identities, status channels, closes and temporary cleanup passed. This is an RM lifecycle result across separate Linux kernels, not same-process CUDA or the experimental R580/Open pair. No module or driver state changed. The [live forward report](evidence/pc3-live-v100-root-on-rtx5080-v3-20261020.json), [live reverse report](evidence/pc3-live-rtx5080-root-on-v100-v1-20261020.json), [one-shot forward](evidence/pc3-rm-root-id-v100-to-rtx5080-v3-20261020.json), [one-shot reverse](evidence/pc3-rm-root-id-rtx5080-to-v100-v2-20261020.json), [hold-probe build manifest](evidence/rm-root-id-probe-hold-v1-20261020.json) and [checkpoint](docs/STATE.md) contain the evidence and limits.

For a fresh build, use new, unused paths because the builder refuses to replace artifacts:

```sh
python3 tools/build_rm_root_id_probe.py \
  --output build/experiments/rm-root-id-probe-next/rm_root_id_probe \
  --report evidence/rm-root-id-probe-next.json
python3 tools/run_pc3_rm_root_id_probe.py \
  --probe build/experiments/rm-root-id-probe-next/rm_root_id_probe \
  --output evidence/pc3-rm-root-id-next.json
python3 tools/run_pc3_v100_rm_root_id_probe.py \
  --probe build/experiments/rm-root-id-probe-next/rm_root_id_probe \
  --output evidence/pc3-rm-root-id-reverse-next.json
```

The next runtime check keeps the source root alive while the other server requests the same ID, then frees both clients. After that, repeat on two isolated same-version R580 backends. Neither result substitutes for a same-Linux CUDA process.

## Separate proprietary backend

```sh
python3 -B tools/build_private_proprietary580.py \
  --work-dir build/experiments/private-proprietary-next \
  --report evidence/private-proprietary-next.json
```

The [latest build](evidence/private-proprietary-notices-v3-20261019.json) preserves the NVIDIA license and core hash. It has100 private exports,303 resolved imports and zero GPL-only imports. It provides the same bounded projection/control-session APIs as the Open backend, with backend-specific names. Original proprietary return/frame-pointer warnings remain; runtime coexistence and CUDA routing are not validated. The builder never installs/loads a module.

## BDF-selected GPU-file frontend prototype

```sh
python3 -B tools/build_hybrid_frontend.py \
  --work build/experiments/frontend-control-attach-next \
  --report evidence/frontend-control-attach-next.json \
  --open-backend build/experiments/private-open-control-attach-next/NVIDIA-kernel-module-source-580.178.04 \
  --legacy-backend build/experiments/private-proprietary-control-attach-next/nvidia-580.178.04
```

The latest [frontend card-info build](evidence/frontend-card-info-v2-20261021.json) imports24 exact APIs across the matched private backends. A per-open catalog uses nonzero synthetic IDs and resolves them to backend-local IDs. The versioned BDF request selects a backend-specific GPU descriptor. The attach route handles direct size-encoded and `NV_ESC_IOCTL_XFER_CMD` requests; zero placeholders remain in the caller-order view but are omitted from backend partitions. It creates two disposable control sessions, attaches their nonempty partitions and publishes the pair only after all operations succeed. The card-info route handles the standard packet directly or inside XFER, checks each backend record against the catalog and rewrites the frontend minor/GPU ID while retaining resource fields. The [Open build](evidence/private-open-card-info-v1-20261021.json) has108 exports; the [proprietary build](evidence/private-proprietary-card-info-v2-20261021.json) has109 exports,303 imports and zero GPL-only imports while preserving the NVIDIA license/core. The frontend and both backends remain unloaded.

The frontend C harness covers catalog selection, standard-node resolution, attach transactions, metadata and child objects, map-context-to-mmap routing and VMA lifetime, and native poll delegation. Poll scenarios verify both selected backends, event masks, blocking waitqueue registration, `O_NONBLOCK` toggles, select-style file references, and epoll-style retention of the frontend file. Software verification v71 (local-only artifact; excluded from GitLab transfer; source: `evidence/logs/software-verification-v71-poll-doc-sync-v1-20261021.log`) passed **358 tests, zero skipped**, with both probe paths pinned; SHA-256 is in `docs/STATE.md`. The [frontend build](evidence/frontend-gpu-poll-v3-20261021.json) resolves all imports and has objtool active with no objtool/naked-return warnings; the pahole-version warning is retained. Stock-driver map-to-mmap observations remain separate from these source/CPU tests. The standard nodes and typed ID-info route are now implemented in source, but no test executes them through the Linux VFS or an experimental RM, and hybrid CUDA is not operational. `NV_ESC_CARD_INFO` is implemented only on the private control descriptor; broad RM controls, CUDA library integration, RM event-object management, the dual-backend UVM bridge, and P2P remain unqualified. Per-open inventory snapshots can become stale after hotplug and are not atomic across backends. Loading dependencies still initializes backend resources; these builds are not permission or readiness to install.

The pinned Open R580 source shows that `NV_ESC_CARD_INFO` is control-file-only and returns backend-local minor and GPU IDs. The private frontend serves BDF-ordered standard `nvidiactl`/`nvidiaN` nodes, a card-info merge on `/dev/hybrid580ctl`, and typed `GPU_GET_ID_INFO_V2` and `GPU_GET_ATTACHED_IDS` translations. These are custom source paths, not yet proven to satisfy `libcuda` through the Linux VFS and real RMs. Attached-ID results are capped at32 and merged from both private RM sessions; ID-info queries go only to the backend owning the requested synthetic ID, and the `deviceInstance` now maps back into the frontend namespace. These paths compile and pass CPU models but have not run through Linux VFS or a real RM. A narrow backend-owned `.mmap` delegation now preserves the selected R580 file as `vma->vm_file`; its CPU contract passes, but the kernel VFS, fault path, unmap ioctl and deferred release remain untested. The next routing seam is the actual CUDA open/control sequence and its complete call surface. Matching-branch control sessions remain a source-level ownership model only; Linux VFS close timing and deferred RM cleanup remain untested. Single-GPU captures on each installed driver contain no `NV_ESC_ATTACH_GPUS_TO_FD` request, so actual multi-GPU library sequencing remains unknown. Preserve the rollback/quarantine boundary until real dual-backend session and deferred-close behavior are validated.

## ROOT-only userspace canary (prepared, not run)

```sh
python3 -B tools/build_frontend_canary.py \
  --work build/experiments/frontend-canary-next \
  --report evidence/frontend-canary-next.json
```

[Canary build v3](evidence/frontend-canary-v3-20261019.json) produces `build/experiments/frontend-canary-v3/hybrid_frontend_canary`. The builder executes only a separately compiled syscall-double fixture; it never runs the production executable, including preflight. Six tests exercise51 CPU scenarios. They do not establish real RM operation.

The user has authorized nondisruptive reference testing on both PC3 GPUs. Strict pinned guest access is now available and the installed-driver V100 numerical reference passed, but the active VM is still separate from the RTX5080 host. A same-Linux canary still requires a verified co-located topology and an approved installation/recovery plan. The standalone tool accepts two verified host BDFs and a fresh report path. It defaults to preflight only and never loads a module. It checks kernel, private module parameters, driver/module bindings, frontend enable flag and misc-device identity. `--execute` explicitly opens only `/dev/hybrid580ctl`, verifies two distinct ROOT clients in both packet forms, frees in reverse order, aborts on ambiguous failure and closes once. No automatic retries, official NVIDIA device opens or CUDA/GPU kernel submissions are implemented. Successful ROOT transactions would still not validate CUDA, UVM or synchronous backend teardown. See [installation boundaries](docs/INSTALL_ROLLBACK.md).


## Local private canary archive

The canary packager validates module names/licenses/dependencies, all recorded import CRCs against the exact kernel/backend tables, pinned original GSP firmware and fresh software/build evidence. It writes a deterministic archive atomically without overwriting an existing output. It never installs or loads modules, extracts the archive, or runs its canary. A package is compile-only preparation; mixed-generation CUDA is unvalidated.

```sh
python3 -B tools/package_hybrid_canary.py \
  --verification-report evidence/software-verification-v12-20261019.json \
  --output build/packages/hybrid580-local-next.tar.gz \
  --report evidence/canary-package-next.json
python3 -I tools/verify_canary_bundle.py build/packages/hybrid580-local-next.tar.gz \
  --sha256 "${EXPECTED_SHA256_FROM_SEPARATELY_TRUSTED_RECORD:?expected digest required}" \
  --kernel-release 7.0.0-38-generic
```

Use fresh archive/report names. The standalone verifier executes no payload and extracts no files. Without a trusted expected digest its result is only self-consistency. Original license texts and individual vendor notice prefixes are included for local traceability; redistribution has not been assessed. See [quarantine and rollback](docs/INSTALL_ROLLBACK.md).

## Full CUDA ioctl references on PC3

Installed-driver traces accompany the RTX5080/R595 SM120 and V100/R580 guest SM70 numerical references: [RTX report](evidence/pc3-rtx5080-full-ioctl-trace-v2-20261020.json), [V100 report](evidence/pc3-v100-guest-full-ioctl-trace-v2-20261020.json), and [metadata-only comparison](evidence/pc3-volta-blackwell-full-ioctl-comparison-v1-20261020.json). They include GPU-file `NV_ESC_REGISTER_FD` and 48-byte `NV_ESC_RM_ALLOC` requests. The private frontend has source/CPU contracts for BDF-selected GPU files, REGISTER_FD projection, and typed GPU metadata. A BDF-ordered backend-local device-instance map now passes CPU/UBSan and Kbuild, but is not called by the frontend. Next wire the private `GPU_GET_DEVICE_IDS` query and per-backend `NV01_DEVICE_0` allocation/child-handle routing; nested payload bytes remain unread. The V100 ran in its guest, so no same-Linux hybrid CUDA or UVM migration is established. See [the source-level analysis and limits](docs/REVERSE_ENGINEERING.md), [architecture](docs/ARCHITECTURE.md), and [validation record](docs/VALIDATION.md).

## RM_CONTROL, allocation-header and SDK-layout evidence reproduction

The tools below emit create-only mode-0600 evidence reports. Use new output paths; existing reports are never replaced.

```sh
python3 -B tools/compare_rm_control_headers.py \
  --rtx-report evidence/pc3-rtx5080-rm-control-v1-20261021.json \
  --v100-report evidence/pc3-v100-rm-control-v1-20261021.json \
  --report evidence/pc3-volta-blackwell-rm-control-header-comparison-next.json
python3 -B tools/summarize_rm_alloc_headers.py \
  --rtx-report evidence/pc3-rtx5080-rm-control-v1-20261021.json \
  --v100-report evidence/pc3-v100-rm-control-v1-20261021.json \
  --report evidence/pc3-volta-blackwell-rm-alloc-header-summary-next.json
python3 -B tools/probe_rm_ctrl_layouts.py \
  --r580-source build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04 \
  --r595-source build/research/open-gpu-kernel-modules-595.99.02/source/open-gpu-kernel-modules-595.99.02 \
  --r580-archive .cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz \
  --r595-archive build/research/open-gpu-kernel-modules-595.99.02/source.tar.gz \
  --report evidence/rm-control-layout-r580-r595-next.json
```

The observer reports contain fixed packet headers only. The RM_ALLOC summarizer suppresses handle and pointer values and never reads class payloads. The SDK probe compiles layout declarations; it does not execute hardware or validate cross-backend translation. Current findings and limits are in [the reverse-engineering record](docs/REVERSE_ENGINEERING.md), [architecture](docs/ARCHITECTURE.md), [validation](docs/VALIDATION.md), and [checkpoint](docs/STATE.md).
