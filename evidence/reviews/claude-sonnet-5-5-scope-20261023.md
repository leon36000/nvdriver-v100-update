# SONNET_REVIEW_SCOPE - mode parameter, CC, semaphore-pool semantics, provider ownership, claim limits

Reviewer: independent static reviewer (Sonnet 5.5), 2026-10-23. Static analysis only: no build, no module load, no GPU or
device access, no network, no execution of code from `source/` or `inputs/`. The only file written is this one.
`hardware_validated = false`, `runtime_validated = false` for everything stated below.

Subject: `inputs/0002-hybrid-isolated-gpu-execution.patch` (opt-in `uvm_hybrid_isolated_gpu_execution`) applied to the
NVIDIA R580.178.04 open kernel-module UVM sources.

Evidence classes used: `source-observation`, `test`, `build-report`, `inference`, `unknown`. Confidence: high/medium/low.
Severity: blocker/high/medium/low/info.

---------------------------------------------------------------------------------------------------------------------

## 0. Conventions, verified inputs, hashes

Review root: `/home/pc6/claude-driver-hybrid-uvm-v5-20261023`.

Citation notation (all paths relative to the review root unless stated):

* `S:<file>:<lines>` = `source/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm/<file>` (pristine).
* `P:<file>:<lines>` = `patched/kernel-open/nvidia-uvm/<file>` (pristine + patch).
* `S=P:<file>:<lines>` = file not touched by the patch; the two trees are byte-identical, line numbers coincide.
  (Never used for the four patched files; for those I give `S:` and/or `P:` numbers explicitly.)
* `patch:Lnn` = line `nn` of `inputs/0002-hybrid-isolated-gpu-execution.patch`.
* `in:<name>` = file in `inputs/`.
* Paths starting `src/` or `kernel-open/nvidia/` are relative to `source/NVIDIA-kernel-module-source-580.178.04/`.

Own verification (sha256sum / patch --dry-run / diff, all read-only):

* Archive `in:NVIDIA-kernel-module-source-580.178.04.tar.xz` = `060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8`; single archive root
  `NVIDIA-kernel-module-source-580.178.04`; `version.mk` (sha256 `cbc6488ed2c35ea814120bc80749dd2d11f486c3e98046b3be240d462ee86e7c`) has `NVIDIA_VERSION = 580.178.04`.
* Patch = `23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0`, 4344 bytes, 4 files, 9 hunks (listed below).
* `patch --dry-run --batch --fuzz=0 --forward -p1` against `source/...` exits 0.
* `diff -rq source/.../kernel-open/nvidia-uvm patched/kernel-open/nvidia-uvm` lists exactly `uvm_gpu.c`, `uvm_gpu_semaphore.c`,
  `uvm_migrate_pageable.c`, `uvm_push.c`; `diff -u` of those four equals the patch hunks (no extra edits in `patched/`).
* All 13 `inputs/INPUTS.json` hashes re-checked and match (build report `85778e16...`, probe `ccd0bb61...`, patch test
  `38121cc8...`, probe test `f55698ef...`, static v2 `a02b4d8b...`, architecture `c5578ce5...`, focused log `c044e1f0...`,
  software-verification json `a0600f1d...`, log `74636c50...`, TASK.md `c6e58a08...`, agents.json `e526e6c4...`, archive, patch).

SHA-256 of the four patched files (S -> P):

| file | S (pristine) | P (patched) |
|---|---|---|
| `uvm_gpu.c` | `b43bb94bbc465bbb4fb243e6f722cb450d6402f3071971843d61f1f7678bf700` | `23bb5a514a99b1c747e683ddd3612511647cc3e95745ccdc1b1e22db3d584197` |
| `uvm_gpu_semaphore.c` | `1472d3bdcd91b35095fb7ae6aa1f66a075ea495c08d106ed7da497176a3d629f` | `4224b4f808c9f86279cb97bfa9645e6b592ace4b2f4213e81848d1ebba4258a3` |
| `uvm_push.c` | `9628ada0b4007eff5af16525d0d71788045832e5ca268699e2ae82a5dc14b85e` | `53b1cdd7abc6f5dcea062a314b5580b05329868ad36a61f6a3f0d567f3326227` |
| `uvm_migrate_pageable.c` | `e7178513d684596aadbe24c1f699eb9e7b13b7f39c19805fe213bbef090898da` | `0aea84a9260f3ae70847e366ef83eae5d7119e0a4865ff631491200e004306bb` |

SHA-256 of other cited files (S = P, identical in both trees):

| file (`kernel-open/nvidia-uvm/` unless noted) | sha256 |
|---|---|
| `uvm_rm_mem.c` | `fdf517f711ce9ae3421e4af2e7fe128f0db4182000eeed32504eacc82d1a43d7` |
| `uvm_rm_mem.h` | `ced992530152a8fc0e0c9b099cad16a857bcf09b0a1bc4407c0598c53d239c7e` |
| `uvm_gpu_semaphore.h` | `e19a72f018add7239e024b3907f6408abab0ef1626a6d1c814fe447574b055e3` |
| `uvm_push.h` | `5c2152b36c194ab14d3d79ec514aec59d2c204a0d50122f440d102d8b59072ce` |
| `uvm_tracker.c` | `756ce284db092691c5e346c9180299c98e050d4391242c53c19d14fcdff13e41` |
| `uvm_va_space.c` | `cff2ab99e9b45143865413cd15d78381ead57b370f4b3bc32ac7584ca9e91693` |
| `uvm_va_range.c` | `10c80433314c9b38cc84f82ac156f2df9d0f5c9d3c73a9e64179047eb2148878` |
| `uvm_va_range_device_p2p.c` | `64090e24a6cd722769bf2023d3299485ce516eb03334adfbc459ebc0738c19b5` |
| `uvm_mem.c` | `e98ce17dd9902f5a8b6cf8fb3919b3e85a4f82814029011af64c6e287a1d84d2` |
| `uvm_tools.c` | `42557042482532ac9ec39918663bfb0ea8c78ac0cd977a2725168c632e37ba1e` |
| `uvm_va_block.c` | `dd2821620e83cfaeb03fd765d64dcb75d82da83a38107afa4b0c2882570a7b03` |
| `uvm_pmm_gpu.c` | `35248129b757c9a405bed7adf7022ea108ebbd9bbb0b091a008935f1247dea9b` |
| `uvm_pmm_sysmem.c` | `83d371c8395a5e1e36a18c8efcb0d9dabd93e4a6e29e7a0651aad4c4ba9e5932` |
| `uvm_conf_computing.c` | `a6f00c57334ce6bb397cb69b129cb72ba938460e10dd2fc8fddb680edfe273c0` |
| `uvm_global.c` | `aeee2f257a289853f36d9c7b196f1e02d19b84695db44cdd2e00f28b0f1a4489` |
| `uvm_global.h` | `32c99fb632fa831da1fbae7c4e541e4fc35afd1d3bf94fe5f7ba57f97dc2e33c` |
| `uvm_hmm.c` | `6e0476ded5b3adc6f5996bcd83e18012f7c38b6ccb662c9d9befd8b2e885cfc9` |
| `uvm_common.c` | `4703e2717dc3eb71bdbaa08f2759887e26ddf129a93918a4014ed19d7089bfa2` |
| `uvm_common.h` | `0666a8f60e034f8461b06b208b1ebe8b8425ff91149fa956533c0a6bda3914d6` |
| `uvm_channel.c` | `64fcdb55ecba388c8ed6c656ca72b60f2b6f4b8bc0ebaffd794ed1e78068a248` |
| `uvm_channel.h` | `c03569619e1295d2b646087228454f4f4c8a77cb911cfa308559daabfd497c0f` |
| `uvm_pushbuffer.c` | `7031f10fc2215d792d58675b503623be5792e13fa4304d14f9b60b811a0a812c` |
| `uvm_mmu.c` | `61dcbb1826e6104452d82d319b5b8c810e328e6a606f619e0efaa273d162bdea` |
| `uvm_map_external.c` | `4115e9f2de1fc9ad460a61168e78e68ede19c57ac6216740dc57475b29d07511` |
| `uvm_migrate.c` | `e8fb855d0fc4150107118752b6a5e897b2c5f7d770243278f631a49ca4b36e36` |
| `uvm_ats.c` | `e637830fc7735d68638e34d3001455de80a08d6505b9760705739da6d95244ca` |
| `uvm_gpu.h` | `11f5a41820746ffb1bc2d70729eaca257eeea3ca71ecbf4fc31fa4a1f3bc5a01` |
| `uvm_gpu_replayable_faults.c` | `c7991f9a9e029ae1e9dc4aba579ecb37c64408d9600117abdeec82fbc1b245b3` |
| `uvm_channel_test.c` | `f846b5e2925258bb1643e389bee4016743a73a6f396571e0621aac109bb94e87` |
| `uvm_gpu_semaphore_test.c` | `2c9339e77c04cb94bf361ee881260ef7e5dc100dfa6bb2dccf41f6bd81c70155` |
| `uvm_rm_mem_test.c` | `eb4a886963fc226830e58268797a25f0d5b3f8af2aaba645ccfb16106aafb2f4` |
| `uvm_push_test.c` | `33d6978c9cd7e2feafddeda76245543e44d999d13826c78adfabf96c86efd3ab` |
| `uvm_host_test.c` | `ad1ab9157ec9113575f351b15e3a8ea5543b74a9a99af60154cda56d6ff8025a` |
| `uvm_tracker_test.c` | `517fe4ab345c0d90fc53a53dbf715bea1fea945dafc171142f74c5ae7240a0b9` |
| `nvidia-uvm.Kbuild` | `0e8d3d96e00d6ca8b6b564e4668dd70447d8b6bca9200845180ce7c66902328b` |
| `kernel-open/Kbuild` | `de6fce64926a8b74e64eea9baeba659f85f71cf8e6c5d6fd7f949153c2a0b5ae` |
| `kernel-open/nvidia/nv_uvm_interface.c` | `b41c704d29363dd52dd0ea669ee253a37185f5826c7db56a07dec21c3d24eddc` |
| `src/nvidia/src/kernel/rmapi/nv_gpu_ops.c` | `1aaf4f11896388812bf1a372718746e4e5753598bb4c0a43c42d10010e7e0f58` |

Line-number offsets S -> P (useful when reading S-numbered text from other reviewers):

* `uvm_gpu.c`: +1 from line 27 on (include), +6 from line 1142 on (init hunk adds 5), +8 from line 1166 on (deinit hunk adds 2).
* `uvm_gpu_semaphore.c`: +1 from line 29 on (include), +8 from line 181 on (alloc hunk adds 7).
* `uvm_push.c`: +6 from line 44 on (parameter block).
* `uvm_migrate_pageable.c`: +9 from line 809 on (wait block).

Patch hunks (patch line numbers):

| hunk | file | patch lines | content |
|---|---|---|---|
| H1 | `uvm_gpu.c` | L3-10 | `#include "uvm_push.h"` |
| H2 | `uvm_gpu.c` | L11-22 | `init_semaphore_pools`: `if (!uvm_push_allow_dependencies_across_gpus()) return NV_OK;` before the cross-map loop |
| H3 | `uvm_gpu.c` | L23-39 | `deinit_semaphore_pools`: unmap loop guarded by `conf_computing_enabled \|\| uvm_push_allow_dependencies_across_gpus()` |
| H4 | `uvm_gpu_semaphore.c` | L42-49 | include |
| H5 | `uvm_gpu_semaphore.c` | L50-66 | `pool_page_alloc_buffers`: non-secure page -> `alloc_and_map_cpu` iff `!CC && !allow` |
| H6 | `uvm_push.c` | L69-81 | `static bool uvm_hybrid_isolated_gpu_execution = false;` + `module_param(..., bool, 0444)` + `MODULE_PARM_DESC` |
| H7 | `uvm_push.c` | L82-89 | predicate returns `!CC && !uvm_hybrid_isolated_gpu_execution` |
| H8 | `uvm_migrate_pageable.c` | L93-105 | `if (!allow) uvm_tracker_wait_for_other_gpus(&zero_tracker, copying_gpu)` before the copy push |

Out of reach for this review (everything marked `unknown` below depends on one of these):

* The hybrid callback bridge / frontend (`hybrid580_uvm_callback_bridge.c`, `hybrid580_uvm_address_space_route.h`) named in
  `in:r580-uvm-cross-provider-static-v2-...json` and `in:uvm-owner-isolation-architecture-v1-...json`. Not in the source tree, not in `inputs/`.
* The out-of-tree audit module `tools.audit_uvm_owner_isolation_architecture` imported by the probe and the patch test.
* The build log (only its sha256 `37a4fe1d...` appears in the build report).
* The closed legacy RM and the CUDA user-mode driver.

---------------------------------------------------------------------------------------------------------------------

## 1. Verdict summary

Primary verdict for the slice I reviewed: **supports static compile only** at the evidence level; at the code level the nine hunks are
**conditionally sound for one narrow, named scope**. No blocker found.

The narrow scope the hunks implement correctly (by source inspection, no hunk-level defect found in my area):
{non-CC, `uvm_hybrid_isolated_gpu_execution=1`, kernel-internal tracking-semaphore pool mapping, and the GPU-side acquisition of
cross-GPU tracker entries}. Inside that scope: no semaphore-pool page is mapped into a non-owner GPU, no UVM-initiated
RM `DupAllocation` remains in production code, and every cross-GPU tracker entry is waited for on the CPU before a dependent push
is begun (the three pool gates and the predicate agree in all four CC x param combinations, section 2.3).

What the evidence does not support (the reasons the verdict is not stronger):

1. The word "isolated" (patch name, comment text, test names, class docstring) is far wider than the code. The patch changes
   one mechanism (kernel semaphore pool + tracker acquires). Cross-GPU system-memory sharing through UVM-owned PTEs, user
   semaphore-pool ranges, tools staging memory, external allocations, peer/NVLink enablement, global fatal-error state and the CC
   SYS pool are untouched (sections 4, 5; F-01, F-05, F-06).
2. The mixed-provider purpose is not shown to be reachable: `add_gpu` still issues a cross-GPU RM call
   (`nvUvmInterfaceGetP2PCaps`) for every pair of parent GPUs, and the open RM implementation rejects devices of different
   sessions. Whether the out-of-tree bridge answers it is unknown (F-02).
3. Under Confidential Computing the parameter is inert for mapping (SYS pool pages stay mapped on all GPUs) and the only
   CC-visible change is the pageable-migration wait (F-03).
4. The only runtime guards of the "no direct cross-GPU acquire" invariant are `UVM_ASSERT`s that the recorded release build compiles
   out; a missed acquire would become a silent acquire on an unmapped (zero-based) VA, a failure mode that does not exist in pristine
   non-CC mode (F-04).
5. The tests are textual; one assertion exercises upstream code, not a hunk; the build report is compile-only and records only
   pre-patch hashes (F-08, F-10).
6. No runtime, hardware, same-process CUDA, P2P, or managed-memory evidence exists. All bridge-dependent behaviour is `unknown`.

Highest-severity items: F-01 (claim scope, high), F-02 (unpatched cross-provider RM call in registration, high but
bridge-dependent), F-03/F-04/F-05/F-06/F-08 (medium).

---------------------------------------------------------------------------------------------------------------------

## 2. Parameter semantics and truth table

### 2.1 Facts about the parameter [source-observation, high unless tagged]

* Declaration: `P:uvm_push.c:44-48` (patch:L73-77):
  `static bool uvm_hybrid_isolated_gpu_execution = false;` (line 45), `module_param(uvm_hybrid_isolated_gpu_execution, bool, 0444);`
  (line 46), `MODULE_PARM_DESC(... "Disable cross-GPU semaphore dependencies and use host waits")` (lines 47-48), comment line 44
  "Opt-in constrained mode for mixed-provider CUDA bring-up."
* Only definition and only reader: `grep -rn "hybrid_isolated\|uvm_hybrid" patched/ source/` returns only `P:uvm_push.c:45,46,47,69`.
  No `module_param_named`, no alias, no `extern`, no reference from `nvidia.ko` sources, Kbuild, or any other UVM file.
* Single reader: `uvm_push_allow_dependencies_across_gpus()` at `P:uvm_push.c:65-70` (value used at line 69:
  `return !g_uvm_global.conf_computing_enabled && !uvm_hybrid_isolated_gpu_execution;`; prototype `S=P:uvm_push.h:494-496`).
* Consumers of that predicate (complete list from grep over `patched/`):
  `P:uvm_gpu.c:1145` (init gate), `P:uvm_gpu.c:1163` (deinit gate), `P:uvm_gpu_semaphore.c:184` (page alloc gate),
  `P:uvm_migrate_pageable.c:810` (zero-tracker wait), `P:uvm_push.c:99` (assert; no-op in release, see F-04),
  `P:uvm_push.c:215` (`wait_for_other_gpus_if_needed`), `S=P:uvm_channel_test.c:792` (built-in test).
* Type/permission/default: `bool`, `0444`, default `false`. Precedent in the same module: `S=P:uvm_hmm.c:49`
  (`module_param(uvm_disable_hmm, bool, 0444)`). `0444` leaves no write bit on the sysfs attribute, and module arguments are applied before
  `init_module` runs [inference: kernel behaviour outside the tree].
* Lifetime: the other input to every gate, `g_uvm_global.conf_computing_enabled`, is assigned once in `uvm_global_init`
  (`S=P:uvm_global.c:115-123`, from the session-create platform info; the open RM fills it from `os_cc_enabled`,
  `kernel-open/nvidia/nv_uvm_interface.c:211`). `add_gpu`, `init_gpu`, pool code and push code all run after `uvm_global_init`.
  So for any reader the pair (CC, param) is constant for the module lifetime, with one caveat below.
* Not latched: plain load of a `static bool`, no `READ_ONCE`, no snapshot at global init, no log line when the mode is active,
  no procfs/ioctl exposure, no UVM capability bit. User space cannot discover the mode through UVM.
* Caveat [inference, low; kernel behaviour outside the tree]: `0444` is a file-mode, not a freeze. If a privileged actor made the sysfs
  attribute writable (chmod) the bool could change at runtime; there is no code in the tree that would prevent it. A mid-life flip
  would desynchronise state from gates: 1 -> 0 leaves owner-only pages while the predicate again allows GPU-side cross acquires;
  0 -> 1 leaves cross-mapped pages that deinit would no longer unmap, after which `uvm_rm_mem_free` iterates `mapped_on` and
  calls `uvm_gpu_get(gpu_id)` on a possibly removed GPU (`S=P:uvm_rm_mem.c:389-399`). Constancy is therefore a real
  correctness precondition, not a convenience.

### 2.2 Truth table (every changed branch x {CC, param})

Notation: CC = `g_uvm_global.conf_computing_enabled`, P = module parameter, allow = `uvm_push_allow_dependencies_across_gpus()` = `!CC && !P`.

| # | site (patched lines) | CC=0,P=0 | CC=0,P=1 | CC=1,P=0 | CC=1,P=1 |
|---|---|---|---|---|---|
| D | predicate `P:uvm_push.c:65-70` | true | **false** | false (pristine) | false (pristine) |
| A | `init_semaphore_pools` cross-map loop `P:uvm_gpu.c:1148-1154`, preceded by gate `1145-1146` | loop runs (pristine) | gate returns `NV_OK`, loop skipped | not reached: CC early return `1140-1141` (pristine) | not reached |
| B | `deinit_semaphore_pools` unmap loop `P:uvm_gpu.c:1163-1169` | runs (pristine) | **skipped** | runs (pristine) | runs (param ignored) |
| C | `pool_page_alloc_buffers` non-secure branch `P:uvm_gpu_semaphore.c:180-188` | `alloc_and_map_all` (CPU + every GPU retained at that time) | **`alloc_and_map_cpu` (CPU + owner)** | SYS pool: `alloc_and_map_all`; VID pool takes the secure branch (pristine) | same as CC=1,P=0 |
| E | host wait in push begin `P:uvm_push.c:210-219`, called at `267` and `299` | not used | used | used (pristine) | used |
| F | pageable-migration wait `P:uvm_migrate_pageable.c:809-816` | skipped | executes | **executes (new vs pristine)** | executes |
| G | cross-GPU acquire assert `P:uvm_push.c:96-99` | passes | would fire (debug builds only) | would fire (debug only) | same |
| - | resulting pool regime | cross-mapped | **owner-only** | cross-mapped (SYS) / local-vidmem (VID) | same as CC=1,P=0 |

### 2.3 Asymmetries and contradictions checked

1. **Pool gates A, B, C agree.** "Owner-only regime" holds exactly when `!CC && P` at all three sites: A skips iff (reached, so CC=0) `!allow` = P;
   B skips iff `!(CC || allow)` = `!CC && P`; C owner-only iff `!CC && !allow` = `!CC && P`. [source-observation, high]
2. **Predicate vs pools.** P=1 implies allow=false, therefore no combination has owner-only pages with allow=true (the one fatal pairing). [source-observation, high]
3. **`!CC &&` in C and `CC ||` in B are both required for CC to stay pristine**: `!allow` is true under CC, so dropping the first would silently switch the CC SYS pool
   to owner-only, and dropping the second (while C stays pristine) would stop unmapping CC cross-mappings. The author preserved pristine CC behaviour deliberately (inference).
4. **CC row is not self-consistent in spirit**: under CC, allow=false (no GPU-side cross acquire) yet SYS-pool pages stay cross-mapped, and F
   executes with the comment `P:uvm_migrate_pageable.c:809` "No cross-GPU semaphore mapping exists in isolated mode" although the
   mapping does exist in CC. Benign functionally, inaccurate as a comment (F-03, F-13).
5. **CC=1,P=1 is identical to CC=1,P=0** for D, A, B, C, E: the parameter is inert under CC (F-03).
6. **Pristine asymmetry kept:** under CC, A never maps pre-existing pages into the new GPU, but B still runs the unmap loop. Harmless because
   unmap is idempotent and tolerant of never-mapped GPUs (`S=P:uvm_rm_mem.c:347-372`, early return at 351-352 and 368-369).
7. **No branch introduced is unreachable.** A's `!allow` can only be true when `!CC && P`; every other conjunct is live in some row.
8. **Default (P=0):** non-CC control flow is identical to pristine at every site (rows D, A, B, C, E, F). Under CC the only change versus pristine is F.
9. **Not introduced:** a state where B or C would run in a regime different from the one the pages were created in, as long as (CC, P) are constant (2.1).
10. **H3 is not needed for correctness.** In the owner-only regime the unmap loop would call `uvm_rm_mem_unmap_gpu` on pages that are not mapped on the departing GPU and return at
    `S=P:uvm_rm_mem.c:351-352`; H3 only avoids taking the other GPUs' pool mutexes and walking their pages. H2 and H5, by contrast, are load-bearing (without them
    `uvm_gpu_semaphore_pool_map_gpu` / `alloc_and_map_all` issue the Dup). [source-observation, high]

---------------------------------------------------------------------------------------------------------------------

## 3. Confidential Computing analysis

### 3.1 How pristine R580 handles CC for this area [source-observation, high]

* One global flag, set once from the RM session platform info (`S=P:uvm_global.c:115-123`). Per-GPU consistency is checked only by
  `UVM_ASSERT(parent->rm_info.gpuConfComputeCaps.bConfComputingEnabled == g_uvm_global.conf_computing_enabled)`
  (`S=P:uvm_conf_computing.c:68-75`, called from `S:uvm_gpu.c:1426` = `P:uvm_gpu.c:1434`), a debug-only assert.
* Cross-GPU dependencies are forbidden in CC: `S:uvm_push.c:59-64` returns `!CC` with the comment "In Confidential Computing a GPU
  semaphore release cannot be waited on (acquired by) any other GPU, due to a mix of HW and SW constraints." The enforcement is host-side: `wait_for_other_gpus_if_needed`
  (`S:uvm_push.c:204-213`) invoked from `__uvm_push_begin_acquire_with_info` (`S:uvm_push.c:261`) and `__uvm_push_begin_acquire_on_channel_with_info`
  (`S:uvm_push.c:293`); assertion at `S:uvm_push.c:90-93`.
* Two semaphore pools per GPU in CC (`S:uvm_gpu.c:1128-1141`, `S:uvm_gpu_semaphore.c:367-399`): `gpu->semaphore_pool` (SYS aperture) and
  `gpu->secure_semaphore_pool` (VID aperture, created only under CC). CE channels use the secure pool, everything else (SEC2) the SYS pool
  (`S=P:uvm_channel.c:2428,2439-2442`; `uvm_channel_is_ce` is `!sec2`, `S=P:uvm_channel.h:558-571`).
* Secure pages (`S:uvm_gpu_semaphore.c:182-207`): vidmem `uvm_rm_mem_alloc` with no CPU and no cross-GPU mapping, plus a CPU-mapped sysmem
  encrypted-payload buffer. `uvm_rm_mem_map_gpu` asserts SYS memory only ("Peer mappings are not supported yet", `S=P:uvm_rm_mem.c:320-321`).
* CC init returns before the cross-map loop (`S:uvm_gpu.c:1139-1140`); the header documents the exception (`S=P:uvm_gpu_semaphore.h:112-115`:
  semaphores are mapped on all GPUs "The only exception (in Confidential Computing) are semaphores allocated from a secure pool").
* Non-secure pages in CC still use `uvm_rm_mem_alloc_and_map_all` (`S:uvm_gpu_semaphore.c:180`), i.e. SEC2 channel semaphore pages are mapped on
  every retained GPU in pristine CC.
* Neighbouring CC constraints not touched by the patch: HMM is disabled (`S=P:uvm_hmm.c:151-156`), GPUs cannot access sysmem
  (`S=P:uvm_va_space.c:833-842,894-897`), CPU-to-GPU transfers use encrypted DMA buffers (`S=P:uvm_va_block.c:3417-3445`).
* No CC-specific check exists on the peer-enable path (`S=P:uvm_va_space.c` mentions CC only at 421 and 833); whatever restricts P2P under CC must come from
  RM capability reporting [inference, medium].

### 3.2 What the patch changes under CC [source-observation, high]

* D, A, B, C: no behavioural change by construction (section 2.2, rows CC=1).
* F (`P:uvm_migrate_pageable.c:809-816`): the only CC-visible change; the wait now executes in CC. Practically unreachable in CC: HMM is off in CC
  (`S=P:uvm_hmm.c:151-156`) and the `zero_tracker` it waits on is only populated for GPU-to-GPU NVLink >= 5 copies or injected NVLink errors
  (`P:uvm_migrate_pageable.c:762-784`). In pristine CC the unguarded `uvm_push_acquire_tracker` at `S:uvm_migrate_pageable.c:816` would have tripped the debug assert if that
  branch were ever reached, so F arguably fixes a latent CC issue (inference, low).

### 3.3 What the patch does not do under CC

* It does not isolate CC mappings. In CC with a second provider, SEC2 channel semaphore pages still go through `uvm_rm_mem_alloc_and_map_all`
  -> `uvm_rm_mem_map_gpu` -> `nvUvmInterfaceDupAllocation` (`P:uvm_gpu_semaphore.c:183-187`; `S=P:uvm_rm_mem.c:326-330`). The `!g_uvm_global.conf_computing_enabled &&` conjunct
  at `P:uvm_gpu_semaphore.c:183` is deliberate. `MODULE_PARM_DESC` and the comments do not say the mode is a no-op for mapping under CC. [source-observation, high]
* CC and the mode are therefore not combinable for mixed-provider purposes. Whether CC + mixed providers is a real configuration is `unknown`
  (CC-capable hardware with a legacy provider is unlikely but not excluded by the code).
* The mode is "CC's host-wait discipline reused without CC's other constraints": CC also removes GPU access to sysmem, HMM, and uses
  encrypted staging. None of that applies in the non-CC isolated mode.

---------------------------------------------------------------------------------------------------------------------

## 4. What "isolated" guarantees in code, and what it does not

### 4.1 Guarantees, scope {non-CC, P=1} [source-observation, high unless noted]

G1. No semaphore-pool page is mapped on a GPU other than its owner, neither at page allocation (`P:uvm_gpu_semaphore.c:183-185`) nor when a GPU is
    registered (`P:uvm_gpu.c:1145-1146`).
G2. The kernel semaphore pool is used in production only for per-channel tracking semaphores (`S=P:uvm_channel.c:2442`); every other
    `uvm_gpu_semaphore_alloc`/`uvm_gpu_tracking_semaphore_alloc` caller is a built-in test (grep: `uvm_push_test.c`, `uvm_channel_test.c`,
    `uvm_tracker_test.c`, `uvm_gpu_semaphore_test.c`). So after G1 no GPU holds a VA for another GPU's channel semaphore.
G3. The only production callers of `uvm_rm_mem_map_gpu`/`uvm_rm_mem_map_all_gpus`/`uvm_rm_mem_alloc_and_map_all` are the semaphore pool
    (`P:uvm_gpu_semaphore.c:187,445`) and a self-map of the owner in CC (`S=P:uvm_pushbuffer.c:148`, a no-op because the memory is already mapped on the owner);
    `nvUvmInterfaceDupAllocation` is reachable only from `uvm_rm_mem_map_gpu` (`S=P:uvm_rm_mem.c:326`). So in this scope UVM issues no RM
    `DupAllocation` in production code. (Test-only users remain, see F-09.)
G4. Every GPU-side semaphore acquire from a tracker entry originates in `push_acquire_tracker_entry` (`P:uvm_push.c:102`, the only production
    `semaphore_acquire` HAL call; other call sites are `uvm_push_test.c`, `uvm_host_test.c`, `uvm_tracker_test.c`, `uvm_channel_test.c`).
G5. That function is reached through `uvm_push_acquire_tracker` (`P:uvm_push.c:126-142`) from exactly two production call sites:
    `push_begin_acquire_with_info` (`P:uvm_push.c:242`), which is reached by two entry points that call `wait_for_other_gpus_if_needed` first
    (`P:uvm_push.c:267`, `299`) and by one entry point that passes `NULL` (`P:uvm_push.c:329`); and `P:uvm_migrate_pageable.c:825`, now preceded by the new wait.
    `uvm_tracker_wait_for_other_gpus` waits for each entry whose GPU differs, then `uvm_tracker_remove_completed` (clears on error)
    (`S=P:uvm_tracker.c:360-386`), so a following `uvm_push_acquire_tracker` sees only same-GPU entries.
G6. The waits occur before the push is begun/channel reserved (`P:uvm_push.c:267-271`, `299-303`; `P:uvm_migrate_pageable.c:809-818`), so no concurrent-push
    semaphore is held while waiting.
G7. Completion polling uses the owner's CPU mapping (`S:uvm_gpu_semaphore.c:480-489`, `551-554`; same code at `P:uvm_gpu_semaphore.c:488-497`, `559-562`), unaffected by the removal of other GPUs' mappings.
G8. Per-GPU VAs: `rm_mem->vas[]` is indexed per GPU (`S=P:uvm_rm_mem.c:55-59,91-96`); nothing assumes a common VA across GPUs, so removing non-owner VAs breaks no cross-GPU VA invariant.
G9. Teardown: skipping the unmap loop is safe because nothing was mapped; `uvm_rm_mem_free` unmaps whatever `mapped_on` holds, owner last
    (`S=P:uvm_rm_mem.c:374-407`).
G10. Default-off leaves non-CC behaviour identical to pristine (section 2.3 item 8).

### 4.2 Non-guarantees (each backed in sections 5 and 8)

* NG1 Data-plane isolation: no change to who may map or touch which pages (sysmem shared through UVM-owned PTEs, user semaphore pools, tools staging, external allocations).
* NG2 P2P: peer enablement and NVLink auto-peers are not gated and may still create peer-aperture mappings and RM P2P objects.
* NG3 Provider awareness: nothing in UVM identifies a provider; the mode is per-GPU-pair and global.
* NG4 CC: inert for mapping.
* NG5 Runtime enforcement: invariants hold by construction; their asserts are compiled out in the recorded release build.
* NG6 Fault isolation: one `uvm_global_set_fatal_error` (`S=P:uvm_global.c:420-438`, `g_uvm_global.fatal_error` module-wide) affects all GPUs and every host wait
  (`wait_for_entry_with_spin` reads `uvm_global_get_status()`, `S=P:uvm_tracker.c:301-313`).
* NG7 Liveness: the added waits are CPU spin waits that do not check `fatal_signal_pending` (`S=P:uvm_common.c:249-282`, TODO at 274) and are taken in call chains that hold
  VA-block locks (for example `block_copy_begin_push`, `S=P:uvm_va_block.c:3352-3470`). Not evaluated here; cross-reference to the ordering review.
* NG8 "Same-process CUDA", "mixed-provider CUDA bring-up": no code, test or log in the inputs exercises or defines these.

---------------------------------------------------------------------------------------------------------------------

## 5. Remaining cross-GPU mappings and dependencies in this mode

Question for each row: in {non-CC, P=1}, would UVM still create a GPU-VA mapping or a cross-GPU/cross-provider dependency?

| # | mechanism | citation | still cross-GPU in this mode? | provider involvement | class/conf |
|---|---|---|---|---|---|
| 1 | kernel tracking-semaphore pool pages | `P:uvm_gpu_semaphore.c:183-185`, `P:uvm_gpu.c:1145-1146` | **No** (CPU + owner) | none | source, high |
| 2 | same pool pages under CC (SEC2 channel only) | `P:uvm_gpu_semaphore.c:183,187`, `S=P:uvm_channel.c:2439-2442` | **Yes** (all retained GPUs, via RM Dup) | RM `DupAllocation` | source, high; outcome with 2 providers `unknown` |
| 3 | secure (VID) pool, CC | `S:uvm_gpu_semaphore.c:182-207` | No | none | source, high |
| 4 | GPU-side cross-GPU tracker acquires | `P:uvm_push.c:210-219,242`, `P:uvm_migrate_pageable.c:809-825` | **No** (host waits) | none | source, high |
| 5 | PMM / eviction / CC DMA-buffer trackers | `S=P:uvm_pmm_gpu.c:575-582`, `S=P:uvm_conf_computing.c:300` | No (pre-existing unconditional host waits) | none | source, high |
| 6 | channel resources: TSG, GPFIFO, GPPUT, control, pushbuffer, fault/access-counter buffers | `S=P:uvm_channel.c:2366-2411`, `S=P:uvm_pushbuffer.c:114-120`, `S=P:uvm_gpu_replayable_faults.c:254` | No (per-GPU RM objects) | each GPU's own provider | source, high; provider routing `unknown` |
| 7 | CC WLC/LCIC pool buffers | `S=P:uvm_channel.c:2788-2833` | No (`alloc_and_map_cpu`/`alloc`, owner) | none | source, high |
| 8 | managed-memory sysmem pages mapped by several GPUs | `S=P:uvm_va_block.c:1345-1365`, `S=P:uvm_pmm_sysmem.c:322-336`, `S=P:uvm_va_space.c:894-897` | **Yes**: same CPU chunk gets a DMA address + UVM-written PTE per GPU; `parent_gpu->pci_dev` comes from RM (`P:uvm_gpu.c:1436`) | RM supplies `pci_dev`; UVM writes PTEs | source, high; coherence between providers `unknown` |
| 9 | managed-memory vidmem mapped remotely | `S=P:uvm_va_block.c:11660-11764`, `S=P:uvm_va_space.c:1226-1239` | Only after peer enable (`can_access`/`accessible_from`) | RM P2P | source, high |
| 10 | GPU->GPU migration without peers | `S=P:uvm_va_block.c:3068-3121`, `S=P:uvm_va_space.c:899-901` | Staged through CPU: dependency between the two pushes exists but is host-waited (row 4) | none | source, high |
| 11 | peer access: NVLink auto-peers at registration, PCIe peers via `UvmEnablePeerAccess` | `P:uvm_gpu.c:2596-2631,2876-2883`, `S=P:uvm_va_space.c:96-116,1195-1275,2037-2068`, `S=P:uvm_mmu.c:2384-2421` | **Yes if enabled; not gated by the mode** | RM `GetP2PCaps`, `P2pObjectCreate` | source, high; result with 2 providers `unknown` |
| 12 | `GetP2PCaps` during `add_gpu` | `P:uvm_gpu.c:2224-2251,2610,2876` | **Yes: an RM call spanning two GPUs on every registration** | RM; open RM requires same session (`src/nvidia/src/kernel/rmapi/nv_gpu_ops.c:3154-3155`) | source, high; bridge `unknown` |
| 13 | user semaphore-pool ranges (`UVM_ALLOC_SEMAPHORE_POOL`) | `S=P:uvm_va_range.c:419-424,833-847,1117-1123,2139-2150`, `S=P:uvm_va_space.c:933-937`, `S=P:uvm_mem.c:1037-1094,1120-1203` | **Yes**: one sysmem `uvm_mem` mapped on every VA-space GPU (kernel VA + user VA) | UVM PTEs only | source, high |
| 14 | tools process-memory staging | `S=P:uvm_tools.c:2505-2528` | **Yes** (non-CC): one staging page mapped on every registered GPU | UVM PTEs only | source, high |
| 15 | external allocations | `S=P:uvm_map_external.c:628-675,906-913` | sysmem: any GPU may map without peer; vidmem needs peer; `nvUvmInterfaceDupMemory` on the mapping GPU's device with a user client/object | RM Dup of user handle | source, high; cross-provider `unknown` |
| 16 | HMM / ATS pageable memory | `S=P:uvm_ats.c:35-76`, `S=P:uvm_hmm.c:141-159`, `P:uvm_migrate_pageable.c:707-850` | All GPUs access the same CPU pages (inherent); hunk H8 only covers the NVLink5 `zero_tracker` | per-GPU SVA bind / device-private pages | source, high |
| 17 | built-in tests (default off, `uvm_enable_builtin_tests=0`) | `S=P:uvm_common.c:46-49`; `S=P:uvm_channel_test.c:69,690-706`, `uvm_rm_mem_test.c:127-168`, `uvm_gpu_semaphore_test.c:171-196` | **Yes if enabled**: cross-GPU `rm_mem` mapping and per-GPU VA != 0 assertions | RM Dup | source, high |
| 18 | SR-IOV proxy mappings | `S=P:uvm_rm_mem.c:130-190` | n/a here | n/a | source, high |

Reading of rows 8, 13, 14: these mappings are written by UVM itself into each GPU's own page tables using per-GPU DMA addresses, so unlike row 2 they
need no RM-level cross-provider handshake. They are exactly the kind of data-plane sharing "isolated" might be assumed to forbid; it does not.

### Appendix A - RM interface calls that span more than one GPU (from a grep of all `nvUvmInterface*` calls in non-test UVM sources)

| call | UVM site | spans | state in {non-CC, P=1} |
|---|---|---|---|
| `nvUvmInterfaceDupAllocation` | `S=P:uvm_rm_mem.c:326` | two GPUs' RM address spaces | no production caller left (G3) |
| `nvUvmInterfaceGetP2PCaps` | `P:uvm_gpu.c:2241` (callers `2395`, `2610`) | two devices | **still called on every `add_gpu` of a new parent GPU (F-02)** |
| `nvUvmInterfaceP2pObjectCreate` / `Destroy` | `P:uvm_gpu.c:2271` (caller `2391`), `2433`, `2459` | two devices / session + handle | only when peers are initialised (NVLink discovery or `UvmEnablePeerAccess`) |
| `nvUvmInterfaceDupMemory` | `S=P:uvm_map_external.c:909`; `S=P:uvm_va_range_device_p2p.c:307,405,470` (not analysed) | mapping GPU's device + a user client/object | not gated |
| `nvUvmInterfaceDupAddressSpace` | `S=P:uvm_va_space.c:1531` | one GPU's device + user handles (per-GPU VA-space registration) | per GPU |
| `nvUvmInterfacePagingChannelsMap` / `Unmap` | `S=P:uvm_rm_mem.c:156,185` | SR-IOV heavy only | n/a |
| `SessionCreate/Destroy`, `RegisterUvmCallbacks`, `ReportFatalError` | `S=P:uvm_global.c:115,248,62,437` | module-global | bridge-defined, `unknown` |
| all other calls (`RegisterGpu`, `GetGpuInfo`, `DeviceCreate`, `AddressSpaceCreate`, `MemoryAllocSys/FB`, `MemoryCpuMap`, PMA, Channel/TSG, fault and access-counter, CSL) | various | one GPU | untouched |

---------------------------------------------------------------------------------------------------------------------

## 6. One provider versus mixed providers

### 6.1 All GPUs under one RM provider

* P=0: pristine.
* P=1, non-CC: removes the per-pair RM `DupAllocation` of semaphore pool pages (both directions: the new GPU's pages into earlier GPUs via `alloc_and_map_all` during
  `uvm_channel_manager_create`, and earlier GPUs' pages into the new GPU via `init_semaphore_pools`; note `for_each_gpu` iterates `retained_gpus`, which `add_gpu` sets only
  after `init_gpu`, `S=P:uvm_global.h:372-377`, `P:uvm_gpu.c:2837`). Every cross-GPU tracker dependency becomes a CPU wait. Ordering is stronger (producer complete before the
  consumer push is submitted), CPU stalls are longer. No capability is unlocked: pristine already worked in this configuration. The mode is cost without functional benefit.
* P=1, CC: no change except H8 (section 3.2).
* One GPU only: no cross-GPU dependency and no other GPU to map; the mode is a no-op except for the gate returning early.

### 6.2 Mixed providers

Prior static finding [in:r580-uvm-cross-provider-static-v2-...json, result.blocker `cross_provider_dup_allocation`, `cross_provider_admission: blocked`]:
the second provider's GPU cannot complete UVM initialisation in non-CC mode because semaphore-pool pages must be `DupAllocation`-mapped across providers. That finding was
computed on the pristine hashes (`uvm_gpu.c b43bb94b...`, `uvm_gpu_semaphore.c 1472d3bd...`); no report in `inputs/` re-examines the patched source.

What the patch removes (non-CC, P=1) [source-observation, high]: both semaphore-pool Dup directions (rows 1, 4 above). Together with G3 this removes every UVM-initiated RM
`DupAllocation` in production code.

What `add_gpu` still does for a new parent GPU (patched numbering) [source-observation, high; outcome `unknown`]:

1. `alloc_parent_gpu`, `init_parent_gpu` (`P:uvm_gpu.c:1414-1534`): per-GPU `nvUvmInterfaceDeviceCreate(session, ...)` etc. Not cross-GPU. Provider routing `unknown`.
2. `init_gpu` (`P:uvm_gpu.c:1536-1666`): per-GPU address space, PMM, channels. `init_semaphore_pools` now skips cross-mapping. Not cross-GPU.
3. After the GPU is entered into the table (`P:uvm_gpu.c:2837-2883`; pristine `S:uvm_gpu.c:2829-2875`), `parent_peers_discover_nvlink` (`P:uvm_gpu.c:2876`, body `2596-2631`)
   calls `get_parent_p2p_caps(parent_gpu, other_parent_gpu, ...)` (`2610`) for every other parent GPU, i.e. `nvUvmInterfaceGetP2PCaps(rm_device0, rm_device1, ...)`
   (`P:uvm_gpu.c:2241`). Any non-OK status goes to `cleanup` and `add_gpu` fails with "Failed to discover NVLINK peers" (`P:uvm_gpu.c:2889-2899`).
   The open RM implementation returns `NV_ERR_INVALID_ARGUMENT` when the two devices belong to different sessions
   (`src/nvidia/src/kernel/rmapi/nv_gpu_ops.c:3154-3155`) and works on RM-private `struct gpuDevice *`. Whether the bridge answers a cross-provider pair with OK + `UVM_LINK_TYPE_NONE`
   (`nv_gpu_ops.c:3181`, which UVM treats as "skip", `P:uvm_gpu.c:2615-2616`) is `unknown`. The v2 report's `function_sha256` set includes `add_gpu` (so the call site was in view) but not
   `get_parent_p2p_caps`, `parent_peers_discover_nvlink` or `peers_discover_nvlink`, and it states no conclusion about this answer; its `p2p_none_cannot_bypass_gpu_admission: true` says a
   "no P2P" answer would not by itself avoid the semaphore blocker, which is a different statement.
4. `peers_discover_nvlink(gpu)` (`P:uvm_gpu.c:2881`): only for pairs whose parent peer caps already say NVLink.

Admitted vs still blocked, using this source tree alone:

| step for a second-provider GPU (non-CC, P=1) | status | basis |
|---|---|---|
| semaphore-pool Dup, new -> old GPU (`alloc_and_map_all`) | removed | `P:uvm_gpu_semaphore.c:183-185` |
| semaphore-pool Dup, old -> new GPU (`init_semaphore_pools`) | removed | `P:uvm_gpu.c:1145-1146` |
| `GetP2PCaps` for the pair | **not removed; admission depends on the bridge** | `P:uvm_gpu.c:2610,2241`; `nv_gpu_ops.c:3154-3155` |
| per-GPU RM calls (device, address space, PMA, channels, ISR setup) | untouched; bridge routing | `unknown` |
| `UvmEnablePeerAccess` / NVLink peers | not gated; outcome | `unknown` |
| `UvmMapExternalAllocation` with a handle of the other provider | not gated | `unknown` |
| shared sysmem PTEs, user semaphore pools, tools staging | not gated; no RM handshake | rows 8, 13, 14 |

Nothing in the source proves the second GPU is admitted; nothing in the source (other than the removed Dup) proves it is blocked. All provider questions are bridge-dependent and therefore `unknown`.

### 6.3 Provider ownership in the code

* UVM has no provider concept. The identities it carries are opaque RM handles: one global session `g_uvm_global.rm_session_handle` (`S=P:uvm_global.c:115`),
  per-parent `rm_device`, per-GPU `rm_address_space`, per-`rm_mem` `gpu_owner`. The architecture report describes one logical session paired across two RMs in the bridge [in:uvm-owner-isolation-architecture-v1-...json, `bridge_registration`]; that is bridge behaviour, `unknown` here.
* In the patched regime each semaphore page is allocated, CPU-mapped and GPU-mapped solely through its owning GPU's `rm_address_space`
  (`P:uvm_gpu_semaphore.c:185`, `S=P:uvm_rm_mem.c:193-259,261-292,409-433`), consistent with "memory owned by the channel's provider". [source-observation, high]
* The patch comments say "other providers" (`P:uvm_gpu.c:1143-1144`, `P:uvm_push.c:44`), but the gates test only the module parameter; same-provider GPU pairs lose the GPU-side fast path as well (F-07).

---------------------------------------------------------------------------------------------------------------------

## 7. Claims versus evidence

### 7.1 Claims in the patch and what the code supports

| claim (location) | supported? | note |
|---|---|---|
| "Disable cross-GPU semaphore dependencies and use host waits" (`P:uvm_push.c:47-48`) | yes for non-CC; trivially true under CC | G4-G6; enforcement only by construction (F-04) |
| "Opt-in constrained mode for mixed-provider CUDA bring-up" (`P:uvm_push.c:44`) | opt-in yes; "constrained" no (adds no restriction beyond dependencies); "mixed-provider" not modelled; "CUDA bring-up" unverifiable | F-01, F-07 |
| "...semaphore pages need not be mapped into other providers" (`P:uvm_gpu.c:1143-1144`) | true as stated for pool pages, but it means "any other GPU", and says nothing about CC | F-03, F-07 |
| "Keep the page CPU-mapped and mapped to its owner GPU only" (`P:uvm_gpu_semaphore.c:181-182`) | true for non-CC isolated; comment omits that the code branch excludes CC | F-03 |
| "No cross-GPU semaphore mapping exists in isolated mode. Wait on the CPU." (`P:uvm_migrate_pageable.c:809`) | true for non-CC; the branch also runs under CC where the mapping exists | F-13 |
| header contract "semaphore will be mapped on all GPUs currently registered ... and on all new GPUs" (`S=P:uvm_gpu_semaphore.h:112-115`) | now false in isolated mode; not updated | F-09 |
| comment above predicate still says only CC (`P:uvm_push.c:67-68`) | stale | F-11 |

### 7.2 The tests in `inputs/` versus the hunks

`in:test_r580_uvm_isolated_execution_patch.py` (single test `test_patch_applies_exactly_and_gates_only_cross_gpu_semaphore_paths`; [test]):

| assertion (lines) | what it exercises | assessment |
|---|---|---|
| copy 5 source files, hash-check, `patch --fuzz=0 --forward -p1` returns 0 (29-47) | patch applicability to 5 pristine files | real, but patch-application only |
| `uvm_push.c` contains decl, `module_param(..., bool, 0444)`, predicate string (49-55) | H6, H7 | substring presence; says nothing about behaviour or the `0444` effect |
| `uvm_gpu.c` contains the init gate and the deinit condition strings (57-65) | H2, H3 | substring presence |
| `uvm_gpu_semaphore.c` contains the `alloc_and_map_cpu` branch string and `alloc_and_map_all` (67-72) | H5 | substring presence; does not check the `!CC` conjunct beyond the exact string |
| `uvm_migrate_pageable.c`: textual order wait < `migrate_vma_copy_begin_push` < `uvm_push_acquire_tracker`, plus block string (74-89) | H8 | offsets within one file; correct for the single occurrences present, still textual |
| `uvm_channel_test.c` contains the guarded acquire (91-96) | **not a hunk**: the guard is upstream (`S=P:uvm_channel_test.c:792-793`), file hash unchanged | exercises upstream code, not the patch (F-08) |

Absent: any check that the diff is limited to the four files ("gates only" is asserted by name, never by test), a CC x P truth-table test, a default-off equivalence test,
a check that the compiled `.ko` carries the parameter, or any behavioural/harness test. The imports `tools.audit_uvm_owner_isolation_architecture`
(`SOURCE_ROOT`, `EXPECTED_SOURCE_SHA256`, `sha256_file`) are not provided, so I could not re-run the tests; I rely on `in:focused-...log` (7 tests ok) and
the 1214-test log (`qualification: software-suite-only`, `gpu_runtime_validated: false`).

`in:test_probe_r580_uvm_isolated_execution.py`: tests archive path confinement, duplicate/link rejection, extraction, digest mismatch, source-hash derivation and the
`NV_KERNEL_MODULES=nvidia nvidia-uvm` build selector. None exercises a patch hunk.

Harness drift: both the probe (`in:probe_r580_uvm_isolated_execution.py:37-43`, `SOURCE_LABELS`) and the test (`in:test_r580_uvm_isolated_execution_patch.py:13-19`, `SOURCE_FILES`) still list
`uvm_channel_test.c` as a file the patch is checked against, while the patch does not modify it. This suggests the harness was written for an earlier patch revision (inference, medium).

### 7.3 The build report versus the compiled modules [build-report]

Proves (from `in:r580-uvm-isolated-gpu-execution-build-v5-20261023T2130Z.json` and the probe's control flow):

* fresh extraction of the hashed archive, five pristine source hashes verified, patch applied with `--fuzz=0` exit 0, then `make ... KERNEL_UNAME=7.0.0-38-generic NV_KERNEL_MODULES="nvidia nvidia-uvm" modules -j 8` exit 0
  in 28.079 s, producing `nvidia.ko` (36578392 B, `8282f23a...`), `nvidia-uvm.ko` (62562120 B, `d8d96ff9...`), `Module.symvers` (5932 B).
* `qualification.level = compiled`, `runtime_or_hardware_validated = false`, `module_loaded_or_installed = false`. These self-descriptions are accurate.

Does not prove:

* That the `.ko` contains the hunks. `inputs.source_files` holds the **pristine** hashes (`uvm_gpu.c b43bb94b...` etc.) because the probe hashes before patching
  (`in:probe...py:233` hash check, `235-246` patch, `248-266` build). That the build used patched sources is inferred from control flow (high confidence), not recorded.
  No post-patch hash, no `modinfo`, no `strings`/`nm` evidence of `uvm_hybrid_isolated_gpu_execution` is in the report.
* Anything in the build log: only its sha256 is given; the log is not in `inputs/`.
* Debug-assert coverage: the build is a release build (`S=P:nvidia-uvm.Kbuild:5` `UVM_BUILD_TYPE = release`, `kernel-open/Kbuild:19` `NV_BUILD_TYPE ?= release`, no `-DDEBUG`),
  so every `UVM_ASSERT` guarding this patch's invariant is compiled out (F-04).
* The hybrid arrangement: the report built the stock open `nvidia.ko`, not a bridge/frontend; which provider module the built `nvidia-uvm.ko` is bound to at run time is not recorded.
* Target kernel: the artefacts are for `7.0.0-38-generic` only. Nothing links this to the intended runtime kernel (`unknown`).
* Any runtime behaviour, same-process CUDA, P2P, managed memory, CC, or the bridge.

### 7.4 Other claim-shaped statements

* Names and docstrings ("isolated GPU execution", "isolated same-process GPU execution mode" in `in:test_r580_uvm_isolated_execution_patch.py:2`, "opt-in R580 UVM prototype" in the probe docstring)
  go beyond the code (F-01). I found no explicit production-readiness claim in the inputs; the qualification fields are conservative.
* `in:r580-uvm-cross-provider-static-v2-...json` is a statement about the pristine source and the then-current bridge, "analyzed-statically", not validated; its `interpretation` text
  itself says it "does not establish a runtime failure".

---------------------------------------------------------------------------------------------------------------------

## 8. Findings

### F-01 Scope of the word "isolated" exceeds the code
* Severity: high. Evidence class: source-observation (+ inference about intent). Confidence: high.
* Where: names and text in `patch:L15-16,56-57,73,97`; test names/docstring (`in:test_r580_uvm_isolated_execution_patch.py:2,23`); versus rows 8, 11-16 of section 5.
* The patch changes exactly one mechanism: the kernel tracking-semaphore pool mapping plus GPU-side acquisition of cross-GPU tracker entries.
  It does not isolate memory (sysmem PTE sharing, `UVM_ALLOC_SEMAPHORE_POOL`, tools staging, external sysmem), peers (F-05), faults (global fatal error, NG6), providers (F-07), or CC (F-03).
* Why it matters: a reader of "isolated mode" can reasonably assume GPU A cannot reach GPU B's pages or that failures are contained; neither holds. The supported guarantee is "no GPU-side cross-GPU semaphore dependency".
* Suggested handling (documentation only, no patch broadening): state the guarantee as G1-G7, list NG1-NG8 as unsupported/unverified.

### F-02 Registration still performs a cross-GPU RM call the patch does not touch
* Severity: high (conditional on the bridge). Evidence class: source-observation for the call path; unknown for the bridge. Confidence: high for the path, medium for the impact.
* Where: `P:uvm_gpu.c:2876` (`add_gpu`) -> `2596-2631` (`parent_peers_discover_nvlink`, call at `2610`) -> `2224-2251` (`get_parent_p2p_caps`, RM call `2241`); failure path `2889-2899`.
  Open RM: `src/nvidia/src/kernel/rmapi/nv_gpu_ops.c:3154-3155` (different sessions -> `NV_ERR_INVALID_ARGUMENT`).
* The patch removes the semaphore-pool Dup blocker but leaves this call for every parent GPU pair. If the bridge forwards it unmodified for a cross-provider pair, `add_gpu` fails and the purpose of the patch is not met.
  Nothing in `inputs/` shows the answer for a cross-provider pair (section 6.2 item 3).
* Resolution needs: bridge source or a trace showing the answer for a cross-provider pair (one plausible answer is "OK with `UVM_LINK_TYPE_NONE`", which UVM accepts).

### F-03 The parameter is inert for mapping under CC; the mode and CC are not composable for mixed providers
* Severity: medium. Evidence class: source-observation. Confidence: high.
* Where: `P:uvm_gpu_semaphore.c:183-187` (the `!conf_computing_enabled &&` conjunct), `P:uvm_gpu.c:1163`, `P:uvm_gpu.c:1140-1141`; SEC2-only consumer `S=P:uvm_channel.c:2439-2442`.
* Under CC, SEC2 channel semaphore pages keep going through `alloc_and_map_all` -> `uvm_rm_mem_map_gpu` -> `nvUvmInterfaceDupAllocation` to every retained GPU. P=1 changes nothing there. `MODULE_PARM_DESC` and comments do not say so.
* Impact bound: CC with a legacy provider is an unlikely configuration, but the code does not exclude it and does not fail closed (for example, no refusal to start with `CC && P`).

### F-04 The invariant is enforced only by construction; the recorded build removes the guards
* Severity: medium. Evidence class: source-observation + build-report. Confidence: high (the debug/release macro mechanics), medium (that a missed path exists: not shown).
* Where: `P:uvm_push.c:96-99` (`UVM_ASSERT(uvm_push_allow_dependencies_across_gpus())`), `S=P:uvm_rm_mem.c:93` (`UVM_ASSERT_MSG(uvm_rm_mem_mapped_on_gpu(...))`);
  `S=P:uvm_common.h:165-171` (UVM_ASSERT is a no-op unless `DEBUG`/Coverity); `S=P:nvidia-uvm.Kbuild:5` (`UVM_BUILD_TYPE = release`); build command in the report has no `NV_BUILD_TYPE`.
* In pristine non-CC every GPU had every semaphore mapped, so a missed cross-GPU acquire was harmless. In the isolated regime a missed acquire computes `semaphore_va` from `rm_mem->vas[gpu]`,
  which is 0 for an unmapped GPU (`uvm_rm_mem_alloc` zero-allocates, `S=P:uvm_rm_mem.c:208`; `rm_mem_clear_gpu_va` zeroes, `77-78`), and pushes `semaphore_acquire` against `0 + index*4`: an unmapped GPU VA, with no diagnostic in the module.
* My census of acquire sites (G4, G5) found none missed, so this is a robustness gap rather than a demonstrated defect. Callsite completeness is the callsite reviewer's remit.
* Possible hardening for the reconciler to weigh (not requested, TASK forbids broadening): `UVM_ASSERT_RELEASE`/error return in `push_acquire_tracker_entry` when `!allow` and the entry GPU differs.

### F-05 Peer access is not gated or described
* Severity: medium. Evidence class: source-observation; outcome with two providers unknown. Confidence: high.
* Where: `S=P:uvm_va_space.c:2037-2068` (`uvm_api_enable_peer_access`), `1195-1275` (`enable_peers`), `96-116` (auto-enable NVLink/SMC peers), `P:uvm_gpu.c:3025-3048,2474-2518,2380-2436`, `S=P:uvm_mmu.c:2384-2421`.
  None of them reads `uvm_push_allow_dependencies_across_gpus()` or the parameter.
* A user in isolated mode can still enable P2P, causing RM P2P object creation (`P:uvm_gpu.c:2271`), peer identity mappings, remote vidmem mappings for managed ranges and GPU_TO_GPU copies. The mode neither forbids nor documents this.
  UVM has no CC check on this path either (3.1), so under CC the restriction presumably comes from RM capability reporting (inference). Whether the bridge permits it for two providers is `unknown`.

### F-06 Shared system-memory mappings through UVM-owned PTEs remain (managed, user semaphore pool, tools, external)
* Severity: medium. Evidence class: source-observation. Confidence: high.
* Where: section 5 rows 8, 13, 14, 15.
* These are cross-GPU GPU-VA mappings of the same pages that do not need an RM cross-provider handshake, so they will work or fail independently of the patch. They are also the main route by which a "cross-provider" GPU can still touch data
  produced by another GPU. Coherence/ordering semantics of one sysmem page mapped by two GPUs under two providers are `unknown`.

### F-07 Granularity mismatch: the mode is per GPU pair and global, the justification is per provider
* Severity: low-medium. Evidence class: source-observation. Confidence: high.
* Where: `P:uvm_gpu.c:1143-1146` and `P:uvm_push.c:69` (no provider test anywhere); comment text "other providers".
* With one provider the mode only adds CPU waits (section 6.1). With mixed providers, same-provider GPU pairs also lose GPU-side dependencies. There is no way to scope the mode to mixed-provider pairs and no signal in UVM that the configuration is mixed.

### F-08 Test evidence is textual and partly unrelated to the hunks
* Severity: medium. Evidence class: test. Confidence: high.
* Where: section 7.2; `in:test_r580_uvm_isolated_execution_patch.py:91-96` versus `S=P:uvm_channel_test.c:792-793`.
* The "gates only cross-GPU semaphore paths" claim is never tested. One assertion checks upstream text. The `tools.audit_uvm_owner_isolation_architecture` dependency is not provided, so independent re-execution is not possible.
  The 1214-test run is `software-suite-only` and `gpu_runtime_validated=false`.

### F-09 Header contract, built-in tests and their assumptions were not updated
* Severity: low-medium. Evidence class: source-observation. Confidence: high.
* Where: header `S=P:uvm_gpu_semaphore.h:35-41,112-115`; `S=P:uvm_gpu_semaphore_test.c:171-196` (asserts a non-zero semaphore VA on every VA-space GPU for semaphores from every GPU's pool);
  `S=P:uvm_rm_mem_test.c:127-168` (`map_other_gpus`); `S=P:uvm_channel_test.c:69,690-706` (`uvm_rm_mem_alloc_and_map_all`).
* With `uvm_enable_builtin_tests=1`, two or more GPUs and P=1, `uvm_test_gpu_semaphore_sanity` fails: for a non-owner GPU the VA is `0 + index*4`, so the `gpu_va != 0` check (`uvm_gpu_semaphore_test.c:184`) fails
  at least for the first semaphore of every newly allocated page (index 0), and the test allocates 4096 per GPU. Other tests attempt cross-GPU RM Dup. Default is off (`S=P:uvm_common.c:46-49`), but any
  validation plan that uses UVM's built-in tests would produce false negatives or cross-provider Dup attempts.

### F-10 Build report limits
* Severity: low (info for most). Evidence class: build-report. Confidence: high.
* Where: section 7.3. Pre-patch hashes only; log not provided; release build; stock `nvidia.ko`; single target kernel; no `modinfo`. The report's own qualification is accurate; the risk is over-reading it.

### F-11 Parameter has no latch, no announcement, and a stale neighbouring comment
* Severity: low. Evidence class: source-observation (+ inference for sysfs behaviour). Confidence: high / low.
* Where: `P:uvm_push.c:45-48,65-70`; comment `P:uvm_push.c:67-68` still describes only CC; section 2.1 caveat.
* Constancy is a correctness precondition (2.1) but is guaranteed only by file permissions. No load-time log line records that the mode is active. An unknown parameter name at module load is, to my knowledge, rejected by the kernel
  (outside the tree; inference), which would fail closed.

### F-12 Global fatal-error coupling
* Severity: low. Evidence class: source-observation. Confidence: high.
* Where: `S=P:uvm_global.c:420-438`, `S=P:uvm_global.h:73,277-279`, `S=P:uvm_tracker.c:301-313`.
* One GPU's UVM fatal error is module-wide, and host waits poll it. The mode increases the number of host waits, hence the number of places a stuck or errored GPU surfaces on another GPU's thread. This is not isolation of failures.

### F-13 Hunk H8 is effectively a no-op on non-NVLink5 hardware and its comment is inexact
* Severity: low. Evidence class: source-observation. Confidence: high.
* Where: `P:uvm_migrate_pageable.c:762-784` (zero tracker populated only if `UVM_GPU_LINK_NVLINK_5` pair or injected NVLink error), `809-816`.
* For PCIe or older-NVLink pairs `zero_tracker` is empty, so the wait does nothing and no test or log exercises it. Under CC it executes with a comment that does not hold (F-03). The CC-visible behaviour change is unreachable in practice (3.2).

### F-14 One CC flag, trusted from the session
* Severity: low. Evidence class: source-observation; hybrid value unknown. Confidence: medium.
* Where: `S=P:uvm_global.c:115-123`, `S=P:uvm_conf_computing.c:68-75`, `P:uvm_gpu.c:1434`.
* All patch conditions depend on a single global CC flag whose per-GPU consistency check is debug-only. In the hybrid arrangement the value depends on the bridge's session-create answer.

### F-15 Added host waits are uninterruptible and taken under VA-block locks (cross-reference)
* Severity: low here (belongs to the ordering review). Evidence class: source-observation. Confidence: medium.
* Where: `S=P:uvm_common.c:249-282` (no `fatal_signal_pending` check), `S=P:uvm_tracker.c:301-322`, `S=P:uvm_va_block.c:3352-3470`.
* Not assessed for deadlock; recorded so the reconciler can connect it to the ordering and lifetime review.

---------------------------------------------------------------------------------------------------------------------

## 9. Negative results (checked, found consistent)

N-01 One declaration, one reader, no alias; type `bool`, perm `0444`, default `false` (2.1).
N-02 Default-off non-CC behaviour is identical to pristine at every patched site (2.3 item 8).
N-03 The three pool gates (A, B, C) agree in all four (CC, P) combinations; P=1 implies allow=false, so owner-only pages never coexist with allow=true (2.3 items 1-2).
N-04 CC behaviour is unchanged at D, A, B, C; the sole CC-visible change is H8, practically unreachable (3.2).
N-05 The patch applies with `--fuzz=0` to pristine; `patched/` equals pristine + patch exactly (section 0).
N-06 All production sources of GPU-side tracker acquires are accounted for (G4, G5); the only direct `uvm_push_acquire_tracker` outside push-begin is `P:uvm_migrate_pageable.c:825`, now preceded by the wait.
N-07 All production cross-GPU `uvm_rm_mem` mappings come from the semaphore pool; `S=P:uvm_pushbuffer.c:148` maps the owner onto itself (G3). Production callers of the kernel semaphore pool are channel tracking semaphores only (G2).
N-08 Pool teardown is safe in a constant regime: unmap is idempotent and tolerant of never-mapped GPUs (`S=P:uvm_rm_mem.c:347-372`), `uvm_rm_mem_free` unmaps `mapped_on` GPUs and the owner last (`374-407`); consequently H3 is an optimisation, not a requirement (2.3 item 10).
N-09 Allocation error paths: `uvm_rm_mem_alloc_and_map_cpu` frees on failure (`S=P:uvm_rm_mem.c:409-433`); `pool_alloc_page` error handling is unchanged (`P:uvm_gpu_semaphore.c:221-261`); no leak introduced.
N-10 `init_semaphore_pools` early return leaves `gpu->semaphore_pool` created and `secure_semaphore_pool` NULL, as in pristine non-CC (`P:uvm_gpu.c:1134-1146`); `uvm_gpu_semaphore_pool_destroy(NULL)` returns (`S:uvm_gpu_semaphore.c:406-407`, `P:uvm_gpu_semaphore.c:414-415`).
N-11 PMM and CC DMA-buffer allocation already host-wait other GPUs' entries unconditionally (`S=P:uvm_pmm_gpu.c:575-582`, `S=P:uvm_conf_computing.c:300`), so those trackers carry no cross-GPU entries into later acquires.
N-12 Wait placement: before channel reservation and push begin in both tracker-taking entry points and before the migrate copy push (G6). `uvm_tracker_wait_for_other_gpus` clears completed entries on success and the whole tracker on error (`S=P:uvm_tracker.c:360-386`).
N-13 Per-GPU semaphore VAs are not assumed equal across GPUs (G8).
N-14 Peer copies and GPU_TO_GPU channels use the source GPU's own tracking semaphore; no peer path acquires another GPU's semaphore (G4).
N-15 `S=P:uvm_hmm.c:151-156` disables HMM under CC; CC GPUs cannot access sysmem (`S=P:uvm_va_space.c:833-842`), consistent with H8 being unreachable in CC.
N-16 Coherent/non-coherent and ATS-support mismatches are rejected at VA-space GPU registration (`S=P:uvm_va_space.c:799-814`), unrelated to the patch.
N-17 The build report's self-description (`compiled`, not validated) is accurate; the probe fails closed on archive hash, source hash, patch application and build exit.
N-18 The patched `deinit_semaphore_pools` braces/flow are well-formed and the pool destroy calls remain outside the guard (`P:uvm_gpu.c:1159-1173`).

---------------------------------------------------------------------------------------------------------------------

## 10. Unknowns and what would discriminate them

| id | unknown | why it matters | cheapest discriminating step (not performed; static or later runtime) |
|---|---|---|---|
| U-01 | Bridge behaviour for `nvUvmInterfaceGetP2PCaps` on a cross-provider pair | F-02: may block registration | Read the bridge route for `GetP2PCaps`; or extend the v2 static audit to the patched tree and add `parent_peers_discover_nvlink` and `get_parent_p2p_caps` |
| U-02 | Bridge handling of `P2pObjectCreate`, `DupMemory`, `DupAddressSpace`, `RegisterGpu`, `DeviceCreate` for the second provider | rows 11, 15; whole admission chain | Same audit, using Appendix A as the checklist |
| U-03 | Whether the built `nvidia-uvm.ko` binds to the stock `nvidia.ko` or the hybrid frontend at run time | what the build proves | Module pair audit (the 1214-suite names `test_r580_uvm_module_pair_audit`); record vermagic and `modinfo` |
| U-04 | That the compiled `.ko` contains H1-H8 | build report is pre-patch-hash only | `modinfo`/`strings` for the parameter name and a post-patch hash of the four sources in the report schema |
| U-05 | Build log content and conftest results | warnings could hide issues | Provide the log with sha256 `37a4fe1d...` |
| U-06 | Behaviour of a missed cross-GPU acquire in release (silent fault vs hang) | F-04 | Needs hardware; not requested. Static alternative: complete the callsite census (other reviewer) |
| U-07 | Coherence/ordering of one sysmem page mapped by two GPUs under two providers | F-06 | Hardware experiment, out of scope |
| U-08 | Whether the CUDA user-mode driver uses `UVM_ALLOC_SEMAPHORE_POOL`, peers or external dups for cross-device features | what "same-process CUDA" would exercise | Trace UVM ioctls from a CUDA process; closed source, `unknown` |
| U-09 | sysfs mode handling of the parameter on the target kernel | 2.1 caveat | Kernel behaviour, out of tree |
| U-10 | What `test_isolated_gpu_execution_requires_both_semaphore_mapping_gates_and_cpu_waits` and `test_pinned_non_cc_registration_path_exposes_the_cross_provider_blocker` (named in `in:software-verification-...log` lines 80 and 51) actually assert | possible overlap with this review | Provide `tools/audit_uvm_owner_isolation_architecture.py` and the tests |
| U-11 | Intended runtime kernel/machine for the artefacts | build target is `7.0.0-38-generic` only | Record in the build report |
| U-12 | CC value reported by the bridge's session create in the hybrid case | F-14 | Bridge source |

Reconciler notes (points where other reviewers may reasonably differ):

* Severity of F-02: I rate it high because it sits on the same registration path the patch targets and is untouched; a reviewer who has read the bridge may downgrade it.
* Severity of F-04: depends on whether the callsite census is complete; I found no missed site.
* F-03: only matters if CC with a second provider is a real configuration.
* I did not find a hunk-level defect (compile, logic, lifetime, error path). Disagreement with a "conditionally sound for named scope" reading should therefore be about scope and claims, not about the nine hunks.

Limitations of this review: static reading only; the bridge, the closed RM, the CUDA driver, the build log and the out-of-tree audit module were not available; I did not run the probe or the tests; kernel
behaviour outside the tree (sysfs mode handling, module argument parsing) is stated as inference.
