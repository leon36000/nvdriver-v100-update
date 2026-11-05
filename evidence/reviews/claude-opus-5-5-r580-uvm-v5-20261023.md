# REPORT — PC6 independent static review: R580.178.04 isolated UVM GPU execution (patch 0002)

Review id `pc6-r580-uvm-isolated-execution-review-v1-20261023T2135Z`, 2026-10-23. Static source review only:
**hardware_validated = false, runtime_validated = false.** No module was built, installed or loaded. No GPU, VM or kernel
state was touched. Inputs are unmodified (re-verified at the end). Persistent outputs exist only inside this task root.
Disclosure: three transient lead scratch files (an archive listing and two drafts) were written to the session scratchpad
under /tmp, which is outside the task root. They were removed before completion. Agent transcripts there are managed by the
harness. Structured findings: `FINDINGS.json`. Progress log: `ITERATION_LOG.md`.
Independent reviews: `SONNET_REVIEW_CALLSITES.md`, `SONNET_REVIEW_ORDERING.md`, `SONNET_REVIEW_SCOPE.md`.

Paths: `S/` = `source/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm/` (pristine), `P/` = `patched/kernel-open/nvidia-uvm/`
(pristine + patch). Files other than the four patched ones are byte-identical in both trees.

## 1. Verdict: **conditionally sound for named scope**

**Named scope.** This covers `nvidia-uvm` from the pinned archive plus patch 0002, with Confidential Computing (CC) off and
`uvm_hybrid_isolated_gpu_execution=1`, in production (non-test) code. Within that scope, static evidence supports four
properties:
1. No non-secure UVM semaphore-pool page is RM-mapped into a GPU other than its owner (R-02).
2. No UVM kernel push GPU-acquires a semaphore owned by another GPU (R-01).
3. Every cross-GPU tracker dependency is met by a CPU wait before the dependent push begins, with ordering at least as strong as
   the removed GPU acquire (R-01, R-03).
4. The patch's eight hunks (four files) add no lifetime, leak or error-path defect (R-02, R-03).

**Conditions.** The verdict holds only while all of these hold:
- **C1.** The acquire census is complete. Four independent censuses agree, but this is not machine-proved.
- **C2.** A caller keeps exclusive access to a tracker between the CPU wait and the acquire. This is the upstream invariant that CC
  already relies on, and it is an inference.
- **C3.** The newly active CPU waits create no GPU→CPU dependency cycle. This is **unknown** (R-05).
- **C4.** A CPU-observed membar-sys release orders the producer's writes for the consumer GPU. This is an inference; the hardware
  was not tested.
- **C5.** The tested `.ko` really contains the hunks, and `UVM_MIGRATE_VMA_SUPPORTED` is defined. This is **unknown** (R-09).
- **C6.** The release build has **no runtime guard** for the invariant, so a missed path fails open (R-04, medium).

**Not supported by any evidence here.** At most the evidence shows the code compiles; none of the following is shown:
- memory or data-plane isolation, P2P disablement, or fault isolation (R-07);
- admission of a GPU from a second provider (R-06, high, depends on the bridge);
- CC combined with this mode (R-08);
- same-process CUDA behaviour, performance or liveness;
- any hardware or runtime behaviour.

There is no **blocker**. The hunks are internally consistent and do what their comments say for UVM-internal semaphores.
The open risks are a missing runtime backstop, unproven liveness of the newly active CPU waits, and claims broader than the mechanism.

## 2. Inputs and provenance (independently verified)

- `python3 -I VERIFY_REMOTE_INPUTS.py` reports `verified_inputs 13` (exit 0), and an independent `sha256sum` matches all 13
  `inputs/INPUTS.json` entries.
- Archive `NVIDIA-kernel-module-source-580.178.04.tar.xz`:
  - 22267204 B, SHA-256 `060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8`.
  - Single root `NVIDIA-kernel-module-source-580.178.04/`, 3797 regular files, no links, no absolute or `..` paths.
  - `version.mk` reads `NVIDIA_VERSION = 580.178.04`. Extracted to `source/`.
- Patch `0002-hybrid-isolated-gpu-execution.patch`:
  - 4344 B, SHA-256 `23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0`, 8 hunks across 4 files.
  - Applied with the probe's own flags (`patch --batch --fuzz=0 --forward -p1`) to a copy (`patched/`): exit 0, no rejects.
- Post-patch SHA-256 values:

  | File | SHA-256 |
  |---|---|
  | `uvm_gpu.c` | `23bb5a514a99b1c747e683ddd3612511647cc3e95745ccdc1b1e22db3d584197` |
  | `uvm_gpu_semaphore.c` | `4224b4f808c9f86279cb97bfa9645e6b592ace4b2f4213e81848d1ebba4258a3` |
  | `uvm_push.c` | `53b1cdd7abc6f5dcea062a314b5580b05329868ad36a61f6a3f0d567f3326227` |
  | `uvm_migrate_pageable.c` | `0aea84a9260f3ae70847e366ef83eae5d7119e0a4865ff631491200e004306bb` |

  The pristine hashes are in `FINDINGS.json`.

## 3. What the patch changes

| Hunk (patched lines) | Change |
|---|---|
| `P/uvm_push.c:44-49` | `static bool uvm_hybrid_isolated_gpu_execution = false; module_param(..., bool, 0444)` |
| `P/uvm_push.c:65-70` | `uvm_push_allow_dependencies_across_gpus()` returns `!cc && !param` (was `!cc`) |
| `P/uvm_gpu.c:1143-1147` | `init_semaphore_pools` returns before mapping other GPUs' pools when dependencies are disallowed |
| `P/uvm_gpu.c:1163-1169` | `deinit_semaphore_pools` unmaps only if `cc \|\| allow` |
| `P/uvm_gpu_semaphore.c:180-188` | a non-secure page uses `uvm_rm_mem_alloc_and_map_cpu` (owner + CPU) when `!cc && !allow`; otherwise it uses `alloc_and_map_all` |
| `P/uvm_migrate_pageable.c:809-817` | `uvm_tracker_wait_for_other_gpus(&zero_tracker, copying_gpu)` before `migrate_vma_copy_begin_push` |
| includes `P/uvm_gpu.c:27`, `P/uvm_gpu_semaphore.c:29` | `#include "uvm_push.h"` |

Truth table (`allow = !cc && !p`):

| Branch | cc0 p0 | cc0 p1 | cc1 p0 | cc1 p1 |
|---|---|---|---|---|
| map other pools into a new GPU | yes | **no** | no (CC early return) | no |
| deinit unmap loop | yes | **no** (nothing mapped) | yes | yes |
| non-secure page mapping | all GPUs | **owner+CPU** | all GPUs | all GPUs |
| push-begin CPU wait (pre-existing, `P/uvm_push.c:210-219`) | no | yes | yes | yes |
| pageable-migration CPU wait | no | yes | **yes (new under CC)** | **yes (new under CC)** |

The three pool gates agree in every combination, so the parameter never yields owner-only pages with `allow=true`.
With the parameter at its default, behaviour is identical to pristine (R-16).

## 4. Evidence

**A. The patch reuses upstream CC machinery (R-01).**
- The only production emitter of a GPU semaphore acquire is `push_acquire_tracker_entry` (`P/uvm_push.c:74-124`, HAL call `:102`).
  The only acquire HAL op is `semaphore_acquire` (`S/uvm_hal.h:290-293`).
- That function is reached only through `uvm_push_acquire_tracker` (`P:126-142`), which has two production callers:
  - `push_begin_acquire_with_info` (`P:242`). Both tracker-taking entry points CPU-wait first, via
    `wait_for_other_gpus_if_needed` (`P:210-219`, called at `P:267` and `P:299`, before channel reservation).
  - `uvm_migrate_pageable.c:825`, which the patch now precedes with the wait (`P:809-816`).
- This satisfies the documented contract at `S/uvm_push.h:328-337`: with cross-GPU dependencies disallowed, the caller must pre-wait.
- Every `uvm_push_begin*` macro resolves to these entry points (`S/uvm_push.h:233-284`).
- Tracker-less begins never acquire later: `S/uvm_ats_faults.c:722`, `S/uvm_gpu_access_counters.c:238,280`, and channel/mmu internals.
- The full call-site enumeration for TASK item 2 is in `SONNET_REVIEW_CALLSITES.md` §3: 25 textual `uvm_push_begin_acquire*`
  sites, 14 page-tree macro uses, the direct pageable acquire, the existing CPU-wait sites, tracker-less pushes and test-only
  sites. It covers:
  - pageable migration;
  - semaphore release (`S/uvm_migrate.c:763`);
  - channel scheduling (reserved-channel pushes take a NULL tracker);
  - eviction (`uvm_va_block_evict_chunks` → block copy → begin-wait);
  - peer GPU_TO_GPU copies (`S/uvm_va_block.c:3406`);
  - context destruction (`S/uvm_va_block.c:9336` local tracker; `deinit_gpu` CPU waits).

  Every production row is either same-GPU by construction or CPU-waited. The lead re-checked the tracker-bearing sites cited
  above in source.

**B. Mapping removal and lifetime (R-02).**
- In production, only two sites reach `nvUvmInterfaceDupAllocation` across GPUs, and both are gated:
  - `P/uvm_gpu_semaphore.c:187` (pristine `S:180`);
  - `P:445` (pristine `S:437`).
- `S/uvm_pushbuffer.c:148` is CC-only and maps into its own GPU.
- Channel tracking semaphores come from the owner's pool (`S/uvm_channel.c:2428-2442`).
- Unmap is idempotent (`S/uvm_rm_mem.c:347-372`). Free unmaps every GPU in `mapped_on`, owner last (`:374-407`).
- Teardown destroys channels before pools (`P/uvm_gpu.c:1792-1802`).
- CC is fixed at init (`S/uvm_global.c:123`), and the parameter is `0444`.

**C. Wait semantics, ordering, locks and errors (R-03, R-05).**
- `uvm_tracker_wait_for_other_gpus` (`S/uvm_tracker.c:360-386`):
  - It spins on every entry whose GPU differs, then calls `remove_completed`. Completion is monotonic, so waited entries are removed.
  - On error it clears the tracker and returns the global fatal status.
- The spin loop (`S/uvm_common.c:249-282`) calls `schedule()`, never checks signals (TODO `:274`) and has no time bound.
  Its stuck warning is `UVM_DBG_PRINT`, which is off in release (`S/uvm_common.h:288-298`, `S/uvm_common.c:28-40`).
- In the migration hunk:
  - `zero_tracker` is stack-local (`P/uvm_migrate_pageable.c:729`).
  - Its only foreign entry is the destination-GPU zero push, which is created only for GPU→GPU copies over NVLink ≥5 or an
    injected NVLink error (`:762-784`).
  - The copy and zero begins take no tracker (`:114-191`). After the wait, the acquire at `:825` emits nothing.
- Lock context: the new wait sits between `migrate_vma_setup` and `migrate_vma_pages` (`:1147-1180`).
  - mmap_lock and the va_space lock are held for read (`:1274-1275`, `:1347-1348`), and pages are locked (`:752`).
  - Upstream already waits unconditionally in the same context (`:1022`) on work that transitively includes the zero push.
    No new lock edge is added.
- The error path matches the existing returns (`:804-807`, `:818-822`) and the shared cleanup (`:1058-1062`).
  `pmm_gpu_alloc` uses the same pattern unconditionally (`S/uvm_pmm_gpu.c:575-582`).
- Push-end releases always use membar sys (`S/uvm_channel.c:1053-1063`).
- Driver-wide, the predicate change turns on CPU waits at about 25 begin sites. These include fault bottom halves (replay and
  cancel trackers inherit VA-block entries, `S/uvm_gpu_replayable_faults.c:352-416,503-544,1636`) and the async `UVM_MIGRATE`
  semaphore release, which runs under the va_space read lock (`S/uvm_migrate.c:919-1083`, `:763`).
- Pristine bottom halves already CPU-wait on such multi-GPU trackers (`S/uvm_gpu_replayable_faults.c:630,2081,2782,2858,2972,3004`;
  `S/uvm_gpu_non_replayable_faults.c:321`). This is therefore more exposure to a hazard class the driver documents
  (`S/uvm_lock.h:136-181`), not a new class. Liveness is still unproven (R-05).

**D. Release builds fail open (R-04).**
- The guard is `UVM_ASSERT` (`P/uvm_push.c:98-99`), which compiles to nothing unless `DEBUG` is defined
  (`S/uvm_common.h:163-171`). `S/nvidia-uvm.Kbuild:5` sets `UVM_BUILD_TYPE = release`, and the build command does not override it.
- A missed path would read `vas[gpu]=0` (`S/uvm_rm_mem.c:91-96`) and acquire at `0 + index*4`
  (`P/uvm_gpu_semaphore.c:481-486`). Because completed entries are removed first, such a failure would depend on timing.

**E. What "isolated" means (R-06, R-07, R-08).** The mode removes GPU-side cross-GPU semaphore dependencies and
semaphore-pool cross-mappings for every GPU pair, not only cross-provider pairs. It leaves these untouched:
- per-GPU PTEs on shared sysmem (`S/uvm_va_block.c:1345-1365`);
- user semaphore-pool ranges mapped on every GPU (`S/uvm_va_range.c:833-847,1117-1123`);
- tools staging memory (`S/uvm_tools.c:2505-2527`);
- external allocations (`S/uvm_map_external.c:628-675,906-913`);
- peer enablement (`S/uvm_va_space.c:96-116,1195-1275,2037-2068`; `P/uvm_gpu.c:2271,3025`);
- the module-wide fatal error (`S/uvm_global.c:420-438`).

Registration still calls `nvUvmInterfaceGetP2PCaps` for every pair of parent GPUs (`P/uvm_gpu.c:2241`, `:2596-2625`) and aborts
`add_gpu` on any error (`:2875-2899`). The open RM rejects devices from different sessions
(`source/.../src/nvidia/src/kernel/rmapi/nv_gpu_ops.c:3154-3155`).

Under CC, the parameter has no effect on mapping, and the only CC-visible change is the pageable wait.

**One provider vs mixed providers (TASK item 4).**
- **Single GPU.** The mode is a no-op apart from the early return in `init_semaphore_pools`.
- **Several GPUs under one RM provider.** Pristine code already works. The mode unlocks nothing: it replaces GPU-side ordering of
  every cross-GPU dependency (including same-provider and SMC partition pairs, R-15) with CPU waits. That is a pure latency and
  CPU cost plus the liveness exposure of R-05.
- **Mixed providers.** The mode statically removes both directions of semaphore-pool `DupAllocation`:
  - new GPU into old, via `alloc_and_map_cpu` (`P/uvm_gpu_semaphore.c:183-185`);
  - old GPU into new, via the skipped map loop (`P/uvm_gpu.c:1145-1146`).

  This is the `cross_provider_dup_allocation` blocker named by the v2 static audit (`inputs/r580-uvm-cross-provider-static-v2-…json`,
  `result.blocker`). Admission still depends on the out-of-tree bridge's answer to `GetP2PCaps` (R-06), and data-plane sharing is
  untouched (R-07). Admission is therefore **unknown**, not established.

## 5. Affected invariants

| Invariant | Pristine mechanism | Patched (cc0 p1) | Status |
|---|---|---|---|
| INV-1: an acquire targets a semaphore mapped on the acquiring GPU | all pool pages mapped on all GPUs | owner-only pages, and no foreign pending entry reaches the acquire | holds statically (R-01); no runtime guard (R-04) |
| INV-2: dependent work starts after the producer completes | GPU acquire | CPU wait before begin; membar-sys release | holds statically (R-01, R-03); hardware equivalence inferred (C4) |
| INV-3: pool mappings are symmetric and never outlive a GPU address space | init-map / deinit-unmap / free | no foreign mappings exist | holds (R-02) |
| INV-4: pool regime is constant for the module lifetime | n/a | `0444` parameter, CC fixed at init | holds in normal operation; not latched (R-12) |
| INV-5: direct `uvm_push_acquire_tracker` callers pre-wait (`S/uvm_push.h:328-337`) | n/a (dependencies allowed) | sole production caller now waits | holds in production; violated by a built-in test (R-11) |
| INV-6: no new lock edge or liveness hazard | — | no new lock; more CPU waits under ISR, va_space and block locks | no cycle found; **unknown** (R-05) |

## 6. Counterexample search (TASK item 5)

| Attempted counterexample | Result |
|---|---|
| Cross-provider GPU VA access to owner-only semaphore pages | Refuted: no foreign mapping exists, and the only production consumer of a foreign semaphore VA is the acquire (R-01, R-02) |
| Shared managed-memory mappings | Present by design and untouched (R-07) |
| P2P | Not gated; GetP2PCaps is issued at registration (R-06, R-07) |
| Another direct GPU acquire that bypasses the wait | None in production. One test-only case: `S/uvm_tracker_test.c:59-148` (R-11, ORD-12) |
| Tracker entries not cleared by a successful wait | Refuted: `remove_completed` runs after the wait and completion is monotonic (`S/uvm_tracker.c:377-379,417-434`); `zero_tracker` is stack-local; the begin-path window relies on C2 |
| Teardown or unload | Safe: channels are destroyed before pools, unmap is idempotent, free walks `mapped_on` (R-02) |
| Concurrent migration | No counterexample: per-call state, stack tracker, lock-protected block trackers |
| Interruption or context loss | The wait is uninterruptible, unbounded and silent in release. On a channel or global error it returns and cleanup runs, but un-awaited entries are dropped (R-13, pre-existing). A GPU hang with no error notifier means an infinite wait (unknown, and depends on the bridge) |

## 7. Build report and tests vs code (TASK item 6)

- **Build report (R-09).** It qualifies the build as "compiled", not validated, and that self-description is accurate.
  - Its `source_files` hashes are the **pristine** ones because the probe hashes before patching
    (`inputs/probe_r580_uvm_isolated_execution.py:233` vs `:235-246`). No post-patch hash, `modinfo` or log is supplied.
  - That the hunks are in the `.ko` is a high-confidence inference from the probe's control flow, not recorded evidence.
  - Hunk 4 compiles only if conftest defines `UVM_MIGRATE_VMA_SUPPORTED` (`S/uvm_migrate_pageable.c:44`,
    `S/uvm_migrate_pageable.h:63-69`), and that is not recorded either.
- **Tests (R-10).** The patch test only checks substrings and text order.
  - Its `uvm_channel_test.c` assertion (`inputs/test_r580_uvm_isolated_execution_patch.py:91-96`) checks an **upstream** guard
    (`S/uvm_channel_test.c:792`), not a hunk.
  - The "gates only" property in the test name is never tested.
  - The imported audit module is not supplied, so the tests cannot be re-run.
  - The 1214-test run (`…log:2043-2045`, `OK`) is software-only.
- **Built-in UVM tests (R-11).** They are not aware of isolated mode.
  - `test_tracker_completion` acquires one GPU's semaphore on every GPU at an unmapped VA. Its loop at `:133-137` can spin forever.
  - `test_alloc` fails its non-zero-VA check (`S/uvm_gpu_semaphore_test.c:179-190`).

## 8. Findings summary (details in `FINDINGS.json`)

| ID | Sev | Class | Conf | Finding |
|---|---|---|---|---|
| R-06 | high (conditional) | source-observation / outcome unknown | medium | Mixed-provider admission is not established: `GetP2PCaps` is still issued for every pair at registration |
| R-04 | medium | source-observation | high | The invariant is guarded only by `UVM_ASSERT`; release builds fail open (acquire at VA < 4 KiB) |
| R-05 | medium | inference | medium | CPU waits now run in fault bottom halves and under locks; no cycle found; liveness unknown |
| R-07 | medium | source-observation | high | "Isolated" means semaphore/tracker isolation only, not memory, P2P, fault or provider isolation |
| R-10 | medium | test | high | Tests are textual, partly target upstream code, and cannot be re-run |
| R-08 | low | source-observation | high | Under CC the parameter does not change mapping; only the pageable wait changes CC; comments are inexact |
| R-09 | low | build-report | high | Build report has pre-patch hashes only; hunk 4's compile gate is not recorded |
| R-11 | low (validation impact medium) | source-observation | high | Built-in tests are incompatible; one test does a raw cross-GPU acquire and can hang |
| R-12 | low | inference | low | Mode constancy relies on `0444`; not latched or announced |
| R-13 | low | source-observation | high | A failed wait drops un-awaited entries before pages are freed (pre-existing) |
| R-01/02/03 | info | source-observation | high | Census complete; mappings removed; migration hunk correct |
| R-14/15/16 | info | source-observation | high/med | Hunk 4 is narrow; SMC partitions count as separate GPUs; default-off matches pristine |

## 9. Reconciliation of the independent reviews

The ORDERING and SCOPE reviewers state that they did not read the other reviewers' files. The CALLSITES reviewer made no
statement either way.

Independence caveat: the ORDERING reviewer's first draft (53721 B) cited the lead's interim `ITERATION_LOG.md` (its N17,
"ITERATION_LOG note confirmed"). The log was readable in the shared task root, so that reviewer was only partly independent of the
lead's interim notes. Its findings nonetheless carry its own source citations, and the lead re-verified every point it relied on.
The final reviewer files contain no references to lead artefacts.

| Topic | Lead | CALLSITES | ORDERING | SCOPE | Resolution |
|---|---|---|---|---|---|
| Overall | conditionally sound | no production bypass; coverage complete | conditionally sound (named static scope) | static compile only for the evidence and claims; conditionally sound for the code | No factual disagreement. Adopted "conditionally sound for named scope" for the code; every broader claim is listed as unsupported (§1) |
| Release fail-open | low | medium (F5) | medium (ORD-01) | medium (F-04) | **medium**; lead raised its rating: this is the single point of failure for the core invariant |
| CPU waits in bottom halves and under locks | "no new class" (hunk 4 only) | medium (F6) | medium/unknown (ORD-02) | low cross-ref (F-15) | **medium/unknown**. Lead verified pristine bottom halves already CPU-wait on multi-GPU trackers, so exposure grows but the class is not new |
| "Isolated" overreach | medium | — | info (ORD-07) | high (F-01) | **medium**. `MODULE_PARM_DESC` is precise; the overreach is in names and docstrings, and §1 bounds the guarantee. SCOPE's "high" is recorded as dissent |
| `GetP2PCaps` at registration | ungated (noted) | out of census | bridge liveness (ORD-11) | high conditional (F-02) | **high, conditional**. Lead verified the open-RM session check and the `add_gpu` failure path |
| CC behaviour | low | info (F3/F9) | info (ORD-07) | medium (F-03) | **low**. Pristine CC behaviour is preserved, and CC with a legacy provider is implausible |
| Test evidence | low | info (F12) | low (ORD-03) | medium (F-08) | **medium**. The mislabelled assertion concerns the very property under review |
| Running `TRACKER_SANITY` on 2 GPUs | exclude | run (expect failure) | U1: run as probe | — | **Exclude from pass/fail.** The debug assert does not stop the acquire, and the loop can hang without interruption. Use only as a deliberate probe on a disposable host |
| Hunk count | 8 | "six" (slip) | per-file table | "nine" (slip) | **8** (`grep -c '^@@'`); clerical only |

Provenance note on the census reviewer:
- It first returned its report inline, saying its harness discouraged writing `.md` files.
- After being pointed to `agents.json:3` and `TASK.md:24`, it wrote `SONNET_REVIEW_CALLSITES.md` itself: 25435 B,
  sha256 `ab515d8df6f8dbb674be878b85ab878f5b11e75c48a4cb79da97edcc9006a2b9`.
- It self-reported two clerical slips: "six patch hunks", and `test_tracker_completion` ending at `:142` instead of `:148`.
  Neither changes a finding. The lead did not edit any reviewer file.

Every auditor-sourced line I relied on was re-read in source (`ITERATION_LOG.md`, "Auditor intake").

## 10. Unknowns

- U-01: how the hybrid bridge answers `GetP2PCaps`, `P2pObjectCreate` and `DupMemory` for a cross-provider pair (decides R-06).
- U-02: the hardware effect of an acquire at an unmapped low VA (R-04).
- U-03: whether CE progress can depend on fault servicing that the waiting thread holds up (R-05).
- U-04: the contents of the compiled `.ko` and the `UVM_MIGRATE_VMA_SUPPORTED` outcome. U-05: the build log and conftest output.
- U-06: coherence and DMA/IOMMU validity of sysmem shared by two providers.
- U-07: suspend, reset or surprise removal during a CPU wait.
- U-08: how the CUDA user-mode driver uses UVM for same-process multi-device work.
- U-09: the CC flag reported through the bridge.
- U-10: the unsupplied audit module and its tests.
- U-11: SR-IOV heavy proxy VAs, which are also 0 when unmapped.

## 11. Next discriminating experiment

1. **Static prerequisites, no hardware.**
   - On the existing artefact, without installing or loading it: `modinfo -p nvidia-uvm.ko` should list
     `uvm_hybrid_isolated_gpu_execution`.
   - Record post-patch source hashes in the build report.
   - `objdump -dr uvm_migrate_pageable.o` should show the call to `uvm_tracker_wait_for_other_gpus` (resolves C5).
   - Review the bridge's `GetP2PCaps` route for a cross-provider pair. It must return `NV_OK` with `UVM_LINK_TYPE_NONE` for
     registration to proceed (resolves R-06).
2. **Discriminating run (owner-operated, one provider, two GPUs).**
   - Build the patched module with `UVM_BUILD_TYPE=debug` and load it with
     `uvm_hybrid_isolated_gpu_execution=1 uvm_debug_prints=1 uvm_debug_enable_push_acquire_info=1`.
   - Drive managed-memory A↔B migration (peer access off, then on), eviction under oversubscription, concurrent faults on both
     GPUs, and async `UvmMigrate` with a semaphore.
   - Pass criteria:
     - no `Assert failed` for `uvm_push_allow_dependencies_across_gpus()` (`P/uvm_push.c:99`) or for `uvm_rm_mem_mapped_on_gpu`
       (`S/uvm_rm_mem.c:93`);
     - no MMU fault at VA < 0x1000 on UVM-internal channels;
     - no "stuck waiting" print;
     - correct data.
   - Any assert or low-VA fault falsifies C1 and R-01. A stuck-wait print tests C3 and R-05.
   - Keep `UVM_TEST_TRACKER_SANITY` and `UVM_TEST_GPU_SEMAPHORE_SANITY` out of this run when 2 or more GPUs are registered (R-11).
