# SONNET_REVIEW_ORDERING - tracker wait ordering, locking, error paths, semaphore page lifetime

Reviewer: delegated read-only agent `r580-ordering-lifetime` (Sonnet 5.5, model id `claude-sonnet-5-5`).
Date: 2026-10-23. Method: static source reading only. No build, no module load, no GPU, `/dev/nvidia*`, `/sys`, `/proc`, VM or kernel access.
`hardware_validated = false`. `runtime_validated = false`. This is the only file written; nothing else in or outside the review root was modified.

## 0. Conventions, inputs, and how the trees were verified

- `S/` = `source/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm/` (pristine, extracted from the verified archive).
- `P/` = `patched/kernel-open/nvidia-uvm/` (pristine copy + `inputs/0002-hybrid-isolated-gpu-execution.patch`).
- In tables, a bare `uvm_*.c:NNN` means `S/` (the file is byte-identical in `P/` unless it is one of the four patched files, in which case the prefix is always written). Files outside `nvidia-uvm/` are cited with their full path from the review root.
- `diff -rq S/ P/` reports exactly four differing files (`uvm_gpu.c`, `uvm_gpu_semaphore.c`, `uvm_migrate_pageable.c`, `uvm_push.c`). `diff -u` of those four reproduces exactly the hunks in the patch file. Every other file is byte-identical in both trees.
- Line numbers are 1-based. A function in a patched file is cited in `P/`; pre-patch behaviour is cited from `S/` (line numbers differ after the hunks).
- Evidence classes: `source-observation` (read in code), `inference` (reasoned from code), `test` (in `inputs/` test script), `build-report`, `unknown` (not provable from the supplied material). Confidence applies to the stated class.
- Verified at review time (independent `sha256sum`): archive `060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8`; patch `23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0`; `source/NVIDIA-kernel-module-source-580.178.04/version.mk` -> `NVIDIA_VERSION = 580.178.04`. SHA-256 of every cited file is in Appendix B.

Patch hunk map (patched-tree line numbers):

| # | File (P/) | Lines | What changed |
|---|---|---|---|
| 1 | `uvm_push.c` | 44-48 (param), 65-70 (predicate, return at 69) | read-only bool module param `uvm_hybrid_isolated_gpu_execution` (default false, `0444`); `uvm_push_allow_dependencies_across_gpus()` now `!conf_computing_enabled && !param` |
| 2 | `uvm_gpu.c` | 27 (include), 1143-1146 (init), 1163-1169 (deinit) | `init_semaphore_pools()` returns before mapping other GPUs' pool pages when `!allow`; `deinit_semaphore_pools()` skips the unmap loop unless `CC or allow` |
| 3 | `uvm_gpu_semaphore.c` | 29 (include), 180-188 | non-secure pool pages use `uvm_rm_mem_alloc_and_map_cpu()` when `!CC and !allow`, else `uvm_rm_mem_alloc_and_map_all()` |
| 4 | `uvm_migrate_pageable.c` | 809-816 | `uvm_tracker_wait_for_other_gpus(&zero_tracker, copying_gpu)` before `migrate_vma_copy_begin_push()` when `!allow` |

Mode matrix derived from the four hunks (`allow` = `uvm_push_allow_dependencies_across_gpus()`):

| Mode | `allow` | `init_semaphore_pools` cross-map | `pool_page_alloc_buffers` (non-secure pool) | `deinit` unmap loop | begin-time CPU wait (`wait_for_other_gpus_if_needed`) | hunk 4 wait |
|---|---|---|---|---|---|---|
| non-CC, param 0 (default) | true | runs (as pristine) | `alloc_and_map_all` (as pristine) | runs | skipped | skipped |
| non-CC, param 1 (isolated) | false | skipped | `alloc_and_map_cpu` (owner + CPU only) | skipped | runs | runs |
| CC, param 0 | false | CC path returns first (as pristine) | `alloc_and_map_all` (as pristine) | runs | runs (as pristine) | **runs (new)** |
| CC, param 1 | false | CC path returns first | `alloc_and_map_all` (param has no effect) | runs | runs | runs |

(Sources: P/uvm_push.c:65-70, 210-219; P/uvm_gpu.c:1139-1146, 1163; P/uvm_gpu_semaphore.c:180-188; P/uvm_migrate_pageable.c:810.)

## 1. Verdict summary

**Verdict for the ordering / locking / error-path / semaphore-lifetime scope: conditionally sound for the named static scope. No blocker and no high-severity defect found. Not validated on hardware or at runtime; compile-only evidence does not upgrade this.**

What I could prove from source:
- Hunk 4 is ordering-correct at its single call site: the wait precedes `migrate_vma_copy_begin_push()`, the only entries that can be in `zero_tracker` are from `dst_gpu` (never `copying_gpu`), the wait removes all of them on success, so the later `uvm_push_acquire_tracker(&push, &zero_tracker)` is a no-op and no cross-GPU semaphore acquire is emitted (section 3).
- Every return in `uvm_migrate_vma_copy_pages_from()` after the tracker is initialised either waits for and deinitialises it, or (P:775, P:783) returns while it provably owns no storage; the new return does not skip `migrate_vma_finalize()`; no leak, double free or use-after-free is introduced (section 5).
- The new CPU wait takes no new lock, holds no push/channel/PMM/va_block lock, and makes no RM call on its normal path; pristine code already performs equivalent CPU waits on GPU work in the same lock context (section 4).
- Semaphore pool init/alloc/unmap/free are mutually consistent in isolated mode; unmapping a never-mapped GPU is a no-op; the parameter is immutable after module load so a mid-life mode flip is impossible (section 6).

The verdict is conditional on premises this review could **not** prove:
- C1 Caller completeness: the only production GPU-side cross-GPU acquire paths are (a) `push_begin_acquire_with_info` (covered by flipping the predicate) and (b) the migrate site (hunk 4). I found no other production caller of `uvm_push_acquire_tracker` or `host_hal->semaphore_acquire` (section 3.7). One hand-written cross-GPU acquire exists in a built-in test (ORD-12). The exhaustive caller census belongs to the callsite reviewer.
- C2 Because `UVM_ASSERT` is compiled out in release builds, a violation of C1 is **fail-open** (ORD-01).
- C3 The awaited GPU work does not depend on CPU-side progress held by the waiter (page faults, preemption, RM interrupts). Unknown (ORD-02, U2).
- C4 Wait failure implies a global fatal error (true by construction, section 2) and UVM's existing fatal-error cleanup semantics are acceptable (ORD-05).
- C5 Hunk 4 was compiled into the tested module and is reachable on the target platform. Unknown (ORD-03).

Short answers to the six assigned items:

| # | Assigned item | Answer | Section |
|---|---|---|---|
| 1 | `uvm_tracker_wait_for_other_gpus` semantics and callers | waits every entry not on `gpu`; success -> removes all completed entries; failure -> clears the whole tracker; global-fatal-error only; not interruptible; no time bound; 3 pristine callers all propagate failure and deinit | 2 |
| 2 | `zero_tracker` lifecycle and acquire | stack-local; only `dst_gpu` entries; empty after the wait; copy push acquires nothing else | 3 |
| 3 | lock context of the wait | mmap_lock(r) + va_space(r) + page locks (+ ISR service lock in the BH); no new edge versus pristine waits; GPU->CPU dependency class unprovable | 4 |
| 4 | error / cleanup | all returns clean; `migrate_vma_finalize` still runs; no leak | 5 |
| 5 | semaphore page lifetime | owner+CPU only; init/deinit/alloc/free symmetric; teardown order safe; CC unchanged; docs/tests drift | 6 |
| 6 | concurrency, interruption, context loss | wait is uninterruptible and silent in release; va_space write lock excludes teardown; no bad page/tracker state on failure | 5, 7 |

Top findings (details in section 8):
1. ORD-01 (medium): the "caller must pre-wait other-GPU dependencies" contract is enforced only by `UVM_ASSERT`; in a release build a missed site emits a Host semaphore acquire at a near-zero VA instead of failing closed.
2. ORD-02 (medium, unknown consequence): the mechanism that actually orders the whole driver is the predicate flip in `uvm_push.c`, which turns on CC-only `wait_for_other_gpus_if_needed()` for about 25 `uvm_push_begin_acquire*` sites, including the fault bottom halves. No deadlock cycle found; none excludable statically.
3. ORD-03 (low): hunk 4 is narrow (ATS-only, NVLink5 or injected-error only), compiled only if `UVM_MIGRATE_VMA_SUPPORTED`, and neither the build report nor the text-order unit test shows it was compiled or reached.

## 2. Wait semantics: `uvm_tracker_wait_for_other_gpus`

Definition: `S/uvm_tracker.c:360-386` (identical in `P/`). Contract: `S/uvm_tracker.h:154-162`.

```
for_each_tracker_entry(entry, tracker) {                 /* :368 */
    if (uvm_tracker_entry_gpu(entry) == gpu) continue;   /* :369-370 */
    status = wait_for_entry_with_spin(entry, &spin);     /* :372 */
    if (status != NV_OK) break;                          /* :373-374 */
}
if (status == NV_OK) uvm_tracker_remove_completed(tracker);                          /* :377-379 */
else { UVM_ASSERT(status == uvm_global_get_status()); uvm_tracker_clear(tracker); }   /* :380-383 */
```

| Property | Behaviour | Evidence (S/) |
|---|---|---|
| Entries waited for | every entry whose `uvm_channel_get_gpu(entry->channel)` differs from `gpu` | uvm_tracker.c:369, 443-446; uvm_channel.h:732-735 |
| Same-GPU entries | neither waited for nor error-checked | uvm_tracker.c:369-370 |
| Completed-entry removal on success | `uvm_tracker_remove_completed()` removes **all** completed entries (every other-GPU entry, plus same-GPU entries that happen to be complete). Incomplete same-GPU entries remain | uvm_tracker.c:377-379, 417-434 |
| On failure | `uvm_tracker_clear()` (size = 0): **every** entry dropped, including un-awaited same-GPU ones. The failing entry is first set to `channel = NULL, value = 0` | uvm_tracker.c:315-319, 380-383 |
| Error sources | `uvm_channel_check_errors(entry->channel)` for the *awaited* channel only, then `uvm_global_get_status()` | uvm_tracker.c:309-312 |
| RC / ECC | channel error notifier non-zero -> `NV_ERR_RC_ERROR`, or `NV_ERR_ECC_ERROR` if the GPU ECC notifier is set; `uvm_channel_check_errors()` calls `uvm_global_set_fatal_error()` before returning | uvm_channel.c:2058-2082, 2091-2125; uvm_global.h:268-273; uvm_global.c:420-438 |
| Pre-existing global error | ends the wait only if the entry is still incomplete; an already-complete entry returns `NV_OK` even with a global error set | uvm_tracker.c:305-313 |
| So failure implies | a global fatal error is set (header: "can only fail if a fatal error is hit that uvm_tracker_check_errors() would return") | uvm_tracker.h:154-162 |
| Interruptible | **No.** No `fatal_signal_pending()` check; explicit TODO | uvm_common.c:274 |
| Time limit | **None.** Every 30 s `uvm_spin_loop()` returns `NV_ERR_TIMEOUT_RETRY`; the loop prints pending pushes and keeps waiting | uvm_common.c:26, 276-279; uvm_tracker.c:306-307 |
| CPU behaviour | `cpu_relax()` busy loop; after 10 us each iteration calls `schedule()` when `NV_MAY_SLEEP()` | uvm_common.c:25, 267-272; `source/NVIDIA-kernel-module-source-580.178.04/kernel-open/common/inc/nv-linux.h:541` |
| Stuck diagnostics | `UVM_DBG_PRINT`, suppressed unless `uvm_debug_prints` is nonzero (default `UVM_IS_DEBUG() or UVM_IS_DEVELOP()` = 0 in release) | uvm_common.h:101-102, 288-298; uvm_common.c:30-39 |
| Locks taken by the wait itself | none at tracker level; completion check uses the tracking semaphore's leaf lock only on the slow path | P/uvm_gpu_semaphore.c:830-874 |
| RM calls | none on the normal path; `nvUvmInterfaceReportFatalError()` only inside `uvm_global_set_fatal_error_impl()` | uvm_global.c:437 |
| NULL-channel entries | `uvm_tracker_entry_gpu()` dereferences `entry->channel` unguarded although the header says NULL means "completed" | uvm_tracker.h:35-38; uvm_tracker.c:443-446 |

No production path persists NULL-channel entries: the only store of `channel = NULL` is uvm_tracker.c:317, applied to a stack copy (`uvm_push_wait`, uvm_push.c:351-358; `uvm_tracker_add_entry_safe`, uvm_tracker.c:252-260) or to an entry of a tracker that is then cleared (uvm_tracker.c:380-383). The unguarded dereference is unreachable at the new call site (ORD-08, info).

### 2.1 All callers in the pristine tree, and the new one

| Caller | Location | Tracker | Return-value handling | Lock context |
|---|---|---|---|---|
| `wait_for_other_gpus_if_needed()` <- `__uvm_push_begin_acquire_with_info` / `..._on_channel_with_info` | S/uvm_push.c:204-213 (called at :261, :293) | caller's tracker | returns the status before any channel is reserved (:262-263, :294-295) | caller's; only when `!allow` (CC in pristine) |
| `pmm_gpu_alloc()` | S/uvm_pmm_gpu.c:575-582 | local `local_tracker` | `goto error`: `uvm_tracker_deinit`, free chunks, `memset` chunk array, return status (:593-601) | **unconditional (all modes)**; under `block->lock` from `block_alloc_gpu_chunk()` (S/uvm_va_block.c:1998) |
| `uvm_conf_computing_dma_buffer_alloc()` | S/uvm_conf_computing.c:300-302, 317-320 | `dma_buffer->tracker` | `goto error`: `uvm_tracker_deinit`, free buffer, return status | CC only |
| **new:** `uvm_migrate_vma_copy_pages_from()` | P/uvm_migrate_pageable.c:810-816 | local `zero_tracker` | `uvm_tracker_wait_deinit(&zero_tracker)` then `return status` | mmap_lock (read) + va_space lock (read) + page locks (section 4) |

All four treat failure as terminal and do not retry. The new caller differs only cosmetically: it calls `uvm_tracker_wait_deinit` on a tracker the failing wait already cleared (a no-op wait), where the others call `uvm_tracker_deinit`. Source-observation, high confidence.

## 3. Ordering analysis

### 3.1 Pristine ordering at the site (S/uvm_migrate_pageable.c)

The zero push on `dst_gpu` is ended (S:779) and tracked in `zero_tracker` (S:781); the copy push is begun on `copying_gpu` (S:809); `uvm_push_acquire_tracker(&push, &zero_tracker)` (S:816) makes `push_acquire_tracker_entry()` emit a Host `semaphore_acquire` on `dst_gpu`'s channel tracking semaphore **through `copying_gpu`'s mapping of that semaphore page** (S/uvm_push.c:95-96: `uvm_channel_tracking_semaphore_get_gpu_va_in_channel`, `host_hal->semaphore_acquire`). Removing that cross-GPU mapping is exactly what isolated mode does.

### 3.2 Patched ordering (P/uvm_migrate_pageable.c)

`:781` add zero push -> `:794-807` DMA mapping -> `:810-816` CPU wait -> `:818` `migrate_vma_copy_begin_push()` -> `:825` `uvm_push_acquire_tracker()` -> `:826` `uvm_tracker_deinit()` -> `:828` tools record -> copy methods -> `:847` `uvm_push_end` -> `:849` add to `state->tracker`. This matches the string-order assertions in `inputs/test_r580_uvm_isolated_execution_patch.py:75-79` (test class: text position only, see ORD-03).

### 3.3 `zero_tracker` can contain only `dst_gpu` entries (hence only "other GPU" entries)

- The only writer of `zero_tracker` is P:781, after a push begun by `migrate_vma_zero_begin_push(va_space, dst_id, dst_gpu, ...)` (P:773; function P:114-139: `uvm_push_begin(gpu->channel_manager, ...)` with `gpu = dst_gpu`).
- The block is entered only if `UVM_ID_IS_GPU(src_id) and UVM_ID_IS_GPU(dst_id)` and (the copying GPU has NVLink enabled with a >= NVLINK_5 peer link to `dst_gpu`, or a test-injected unresolved NVLink error) (P:762-766; enum `UVM_GPU_LINK_NVLINK_5` at S/uvm_gpu.h:622; injection needs `uvm_enable_builtin_tests`, default 0: S/uvm_common.c:46, S/uvm_gpu.c:2166-2178).
- `copying_gpu` for GPU->GPU is `uvm_gpu_get(src_id)` (P:682-705, else branch :695-699) and the block asserts `copying_gpu->id == src_id` (P:771). `src_id != dst_id`: pages already at the destination are filtered out (P:261-265) and `migrate_vma_copy_begin_push()` asserts it (P:151-153).
- Therefore `uvm_tracker_entry_gpu(entry) == dst_gpu != copying_gpu` for every entry. After `uvm_tracker_wait_for_other_gpus(&zero_tracker, copying_gpu)` succeeds every entry was awaited and `uvm_tracker_remove_completed()` removes it: `zero_tracker` is empty, and `uvm_push_acquire_tracker()` (which itself first calls `uvm_tracker_remove_completed`, P/uvm_push.c:136) emits nothing. Source-observation + inference, high confidence.
- In every other case the tracker is empty and the wait is a no-op loop over zero entries.

### 3.4 Thread-locality, and nothing added between wait and acquire

`zero_tracker` is an automatic variable (`UVM_TRACKER_INIT()` at P:729). No other thread can reach it. Between P:811 (wait) and P:825 (acquire) nothing touches it: `migrate_vma_copy_begin_push()` (P:142-191) does not take it, and `uvm_push_begin*` is called with `tracker = NULL` (S/uvm_push.h:233-235, 254-256), for which `wait_for_other_gpus_if_needed()` returns `NV_OK` (S/uvm_push.c:206-207) and `uvm_push_acquire_tracker(push, NULL)` returns immediately (S/uvm_push.c:127-128).

### 3.5 Are other trackers acquired by the same copy push?

No. In `uvm_migrate_pageable.c` the only call of `uvm_push_acquire_tracker` is P:825 (grep). The pushes in this file are begun with `uvm_push_begin` / `uvm_push_begin_gpu_to_gpu` (no tracker): P:131, P:173, P:183. `state->tracker` receives entries only *after* `uvm_push_end` (P:524, P:849) and is only waited for (P:1022). No va_space, va_block or page-tree tracker is referenced anywhere in the file. Because no production code outside `uvm_push.c` and this file emits an acquire (section 3.7), no callback invoked from the copy loop (`uvm_tools_record_migration_begin`, S/uvm_tools.c:1385-1450, which only uses `uvm_push_timestamp()` and `push_info->on_complete`; `uvm_perf_event_notify_migration_ats`, S/uvm_perf_events.h:368-400, which only dispatches events) can add one.

### 3.6 Memory-ordering equivalence of "CPU observed completion" versus "GPU acquired the semaphore"

The zero push's completion is the tracking-semaphore release emitted by `uvm_channel_end_push()` (S/uvm_channel.c:1512-1513) through `uvm_channel_tracking_semaphore_release()`, which strips any NONE/GPU membar flag and always uses a **membar sys** ("To be safe, just always uses a membar sys", S/uvm_channel.c:1053-1063). `uvm_gpu_tracking_semaphore_is_value_completed()` is documented to guarantee that operations ordered before the release are visible to the caller (S/uvm_gpu_semaphore.h:186-199) and implements the barriers (P/uvm_gpu_semaphore.c:852-874). The CPU submits the copy only after that observation. Net: the CPU wait gives a happens-before from the zero writes to the copy that is at least as strong as the removed GPU acquire (source-observation + inference, medium-high confidence; the hardware effect of the membar cannot be tested here).

### 3.7 Census of GPU-side acquires

`grep` over `S/*.c`/`*.h`: `uvm_push_acquire_tracker` is called in production at S/uvm_push.c:236 (`push_begin_acquire_with_info`, always preceded by `wait_for_other_gpus_if_needed`, S/uvm_push.c:261, :293) and at S/uvm_migrate_pageable.c:816 (covered by hunk 4). Test: S/uvm_channel_test.c:793, guarded upstream by `random_stream->push.gpu == gpu or allow` (S/uvm_channel_test.c:792; not part of the patch). `host_hal->semaphore_acquire` is called in production only at S/uvm_push.c:96. Test-only callers: uvm_push_test.c:546-547, 697-698 (semaphore from the same GPU's pool), uvm_host_test.c:183 and uvm_channel_test.c:1495 (test memory on the same GPU) are same-GPU; **S/uvm_tracker_test.c:109-112 is a cross-GPU acquire that bypasses the wait (ORD-12)**. The only other GPU-side use of a tracking-semaphore VA is the push-end release on the channel's own semaphore (S/uvm_channel.c:1512). Source-observation, high confidence for these greps; whether anything outside these functions builds an equivalent acquire by hand is the callsite reviewer's census.

### 3.8 The ordering mechanism that actually governs the whole driver

Hunk 1 changes the global predicate. `wait_for_other_gpus_if_needed()` (P/uvm_push.c:210-219) is called before channel reservation in both begin paths (P:267, P:299). In isolated mode every `uvm_push_begin_acquire*` call with a non-NULL tracker therefore CPU-waits for all other-GPU entries first and then acquires only same-GPU entries (GPU semaphore through the owner mapping). I count about 25 textual production call sites in 8 files (uvm_va_block.c x13; uvm_gpu_replayable_faults.c x4 at :370, :379, :461, :515; uvm_mmu.c x2, macro lines :62, :64; uvm_conf_computing.c x2; uvm_migrate.c:763; uvm_hmm.c:207; uvm_gpu_non_replayable_faults.c:274; uvm_map_external.c:230). This is pre-existing CC code, newly live outside CC (ORD-02).

TOCTOU inside the begin path: the wait (before `push_reserve_channel`, which may block) and the acquire (inside `push_begin_acquire_with_info`) are separated in time. Safety relies on the caller owning the tracker exclusively (va_block lock, tree lock, local tracker), which `uvm_push_acquire_tracker` already requires because it mutates the tracker in place (S/uvm_push.c:130). Same assumption as CC. Source-observation + inference, medium confidence (I did not audit each of the 25 callers' locking).

### 3.9 Counterexample search for lost ordering

| # | Attempted counterexample | Result | Basis |
|---|---|---|---|
| A | cross-GPU entry added to `zero_tracker` after the wait | not possible (stack-local, no writer between P:811 and P:825) | 3.4 |
| B | copy push acquires a second tracker with foreign entries | not possible in this file | 3.5 |
| C | same-GPU entry left in `zero_tracker` that needs an unmapped page | none exist; and the owner mapping exists anyway (`rm_mem_set_gpu_va(owner)`, S/uvm_rm_mem.c:247) | 3.3, 6.1 |
| D | wait returns OK with an incomplete other-GPU entry | impossible (loop exits only on completion or error) | S/uvm_tracker.c:305-313 |
| E | wait skipped while the page is unmapped | the same predicate gates init, alloc, deinit, begin-time wait and hunk 4; the parameter is `0444`; CC is false-`allow` in all of them | mode matrix; P/uvm_push.c:45-46 |
| F | semaphore pages still cross-mapped in isolated mode | **yes in CC** (non-secure SYS pool keeps `alloc_and_map_all`); harmless to ordering because CC forbids cross-GPU dependencies, but contradicts the "owner GPU only" comment (ORD-07) | P/uvm_gpu_semaphore.c:180-188 |
| G | param changes between page alloc and use | impossible at runtime (read-only, fixed at module load) | P/uvm_push.c:46 |
| H | GPU hot-added after pages exist | init skip + `alloc_and_map_cpu` are consistent; nothing expects the new GPU to see old pages | 6.3 |
| I | GPU_TO_GPU channel push uses `dst_gpu`'s semaphore | no: the release is always on the pushing channel's own semaphore | S/uvm_channel.c:1512 |
| J | zero push on the copying GPU itself | cannot happen (dst != src); if it did, the acquire would be same-GPU and mapped | 3.3 |
| K | tools / perf callbacks add acquires | none | 3.5, 3.7 |
| L | hand-written cross-GPU acquire outside the mechanism | **one exists, test-only** (`test_tracker_completion`) | ORD-12 |

## 4. Lock / deadlock analysis

### 4.1 Locks and state held at the new wait

| Item | `UVM_MIGRATE` ioctl on an ATS range | ATS fault bottom half (replayable / non-replayable) |
|---|---|---|
| Entry | `uvm_api_migrate` -> `uvm_migrate_pageable` at S/uvm_migrate.c:1002, 1029 (reached only if `uvm_api_range_type_check()` returns ATS: S/uvm_policy.c:74-85, needs `g_uvm_global.ats.enabled`, S/uvm_ats.c:39-42) | `service_fault_batch_ats_sub_vma` S/uvm_gpu_replayable_faults.c:1695-1718 -> `service_ats_requests` S/uvm_ats_faults.c:111; non-replayable S/uvm_gpu_non_replayable_faults.c:613 |
| mmap_lock | read (S/uvm_migrate.c:918; S/uvm_va_space_mm.h:155-171) | read (S/uvm_gpu_replayable_faults.c:2286; non-replayable :683) |
| va_space->lock | read (S/uvm_migrate.c:919) | read (S/uvm_gpu_replayable_faults.c:2289; non-replayable :686) |
| GPU ISR service lock | n/a | held for the BH (S/uvm_lock.h:83-111) |
| Page state | dst pages `lock_page`'d (P:752); src pages isolated and locked by `migrate_vma_setup` (Linux behaviour, not in the supplied source) | same |
| Not held | va_block lock, PMM chunk / root-chunk locks, channel lock, push semaphore (the zero push is ended at P:779, the copy push is not yet begun), RM API / GPUs locks | same |
| Eviction | not involved: destination pages come from `alloc_pages_node()` (P:306-335), not from PMM | same |

### 4.2 Comparison with pristine waits in the same context

- S/uvm_migrate_pageable.c:402 (inside `uvm_dma_map_sg`, S:384-411, called from `dma_map_non_failed_pages_in_mask`, S:447) calls `uvm_mmu_tlb_invalidate_phys()`, which does `uvm_push_begin(MEMOPS)` + `uvm_push_end_and_wait()` (S/uvm_mmu.c:2956-2975) unless `ats.dma_map_invalidation` is NONE (S/uvm_mmu.c:2958-2963): a CPU wait on GPU work with the same locks and page locks held, immediately before the new wait.
- S/uvm_migrate_pageable.c:1013 (P:1022) `uvm_tracker_wait_deinit(&state->tracker)` waits for the copy push, which in the pristine GPU-acquire design transitively waits for the zero push. The patch moves the wait for the same zero push earlier; it adds nothing new to wait for.
- Under `block->lock`, `pmm_gpu_alloc()` already CPU-waits for other-GPU tracker entries in every mode (S/uvm_pmm_gpu.c:575-582 via S/uvm_va_block.c:1998).

### 4.3 What the awaited work needs

The zero push is a CE `memset_8` on physical (`uvm_gpu_address_copy` / `uvm_gpu_phys_address`) or peer-copy addresses (P:79-85 `uvm_migrate_vma_dma_page_copy_address`; P:89-111 `uvm_migrate_vma_page_copy_address`; P:337-382): no GPU virtual-address faults and no dependency on any CPU lock. It needs only the CE channel to run and to release the tracking semaphore. Whether the CE channel's scheduling can be blocked by pending replayable faults of a user context on the same GPU, which the faulting BH (holding that GPU's service lock) cannot service while it spins, is **not decidable from source** (U2). The hazard class is documented by the driver itself (S/uvm_common.c:253-265; S/uvm_lock.h:136-181) and is shared with the pristine end-of-migration wait, so I classify it as "no new edge", not "proved absent".

### 4.4 Lock-order and RM-call constraints

- The wait acquires no UVM lock beyond leaf locks inside the tracking semaphore (P/uvm_gpu_semaphore.c:830-850). On the error path only, `uvm_channel_get_fatal_entry()` -> `uvm_channel_get_first_pending_entry()` runs `channel_update_progress_all()` and takes the channel pool lock (S/uvm_channel.c:2084-2089, 1906-1922); that is pre-existing in every tracker wait.
- mmap_lock is held, and S/uvm_lock.h:136-140 forbids RM calls while mmap_lock is held (GPU faults can block threads holding the RM GPUs lock). The normal wait path makes no RM call; the error path calls `nvUvmInterfaceReportFatalError` (S/uvm_global.c:437), as every other tracker wait does.
- VA-space writer-fairness scenario (S/uvm_lock.h:150-181): holding the va_space read lock longer is the same exposure as the pristine final wait. No new edge.

### 4.5 Conclusion

No lock cycle was found, and the new wait does not extend the *set* of things waited for (section 4.2). Residual risk is the GPU->CPU dependency class (U2) and the consequences of the predicate flip (ORD-02: CPU waits now exist inside fault bottom halves and under va_block locks for about 25 begin sites; I did not enumerate each site's lock context and saw no caller holding a spinlock, which is not exhaustively verified, U8).

## 5. Error and cleanup analysis (`uvm_migrate_vma_copy_pages_from`, P:707-850)

| Return (P line) | Condition | `zero_tracker` state | Handling |
|---|---|---|---|
| 775 | `migrate_vma_zero_begin_push` failed | empty | return; static storage only, nothing to free |
| 783 | `uvm_tracker_add_push_safe` failed | no entry added | return (pre-existing) |
| 787 | all pages failed allocation | may hold the zero push | `return uvm_tracker_wait_deinit` |
| 805-806 | DMA map failed | may hold the zero push | `uvm_tracker_wait_deinit`, return |
| **813-814 (new)** | `uvm_tracker_wait_for_other_gpus` failed | **cleared by the failing wait** | `uvm_tracker_wait_deinit` (no-op wait + deinit), return status |
| 820-821 | copy push begin failed | in isolated/CC mode already empty; in default mode may still hold the zero push (`wait_deinit` waits for it) | `uvm_tracker_wait_deinit`, return |
| 825-826, 849 | success | acquired (no-op) + deinit | `return uvm_tracker_add_push_safe(&state->tracker, &push)` |

- `UVM_TRACKER_INIT()` uses the one-entry static array (S/uvm_tracker.h:66-78), and `zero_tracker` holds at most one entry (one zero push per call), so no dynamic allocation can leak on any path.
- Caller chain on failure: `uvm_migrate_vma_copy_pages()` returns the first error (P:852-878) -> `uvm_migrate_vma_alloc_and_copy()` still waits `state->tracker` (P:1022), then, because `state->status != NV_OK`, frees and unlocks all destination pages (`uvm_migrate_vma_cleanup_pages`, P:880-894, called at P:1062) and tears down the scatter tables (`uvm_migrate_vma_state_deinit_sgt`, P:978-996, called at P:1063) -> `nv_migrate_vma()` skips `migrate_vma_pages`/`finalize_and_map` and **always** calls `migrate_vma_finalize()` (P:1171-1177). The new early return therefore bypasses no finalize step (N5).
- DMA mappings created at P:794-802 before the new wait are released by `uvm_migrate_vma_state_deinit_sgt` on the failure path, not by this function; unchanged from pristine for the other early returns.
- Residual (pre-existing, unchanged in kind): after a wait failure the tracker is cleared, so in-flight zero/copy pushes on healthy GPUs are not awaited before destination pages are freed. Failure implies a global fatal error (section 2), and `uvm_tracker_wait`/`uvm_tracker_check_errors` already behave this way (S/uvm_tracker.c:331-358, 388-403). ORD-05.
- The ATS fault BH expects ATS servicing to return only global errors (S/uvm_gpu_replayable_faults.c:1731-1742), consistent with the new failure mode.
- State left behind on failure: pages restored by `migrate_vma_finalize` (dst entries zeroed by `uvm_migrate_vma_cleanup_pages`), trackers cleared or deinitialised, scatter tables freed. No bad state beyond ORD-05.

## 6. Semaphore page lifetime

### 6.1 Allocation

`uvm_gpu_semaphore_alloc()` (P/uvm_gpu_semaphore.c:291-342) holds `pool->mutex` (lock order `UVM_LOCK_ORDER_GPU_SEMAPHORE_POOL`, S/uvm_lock.h:254-258, set at P/uvm_gpu_semaphore.c:383) and, when no free slot exists, calls `pool_alloc_page()` (:221-261) -> `pool_page_alloc_buffers()` (:172-219). In isolated non-CC mode the non-secure branch returns `uvm_rm_mem_alloc_and_map_cpu()` (:183-185), i.e. `uvm_rm_mem_alloc()` (RM sysmem allocation in the *owner's* RM address space, owner VA recorded, proxy VA only in SR-IOV heavy: S/uvm_rm_mem.c:193-259, 130-171) followed by `uvm_rm_mem_map_cpu()` (S/uvm_rm_mem.c:261-292, 409-433). `mapped_on` then contains the owner and the CPU only; `vas[other] == 0` (S/uvm_rm_mem.h:47-49).
Failure: `uvm_rm_mem_alloc_and_map_cpu()` frees the rm_mem itself on error (S/uvm_rm_mem.c:430-432) and `pool_alloc_page()` frees the page struct (P:258-260); `page->memory` stays NULL. No leak (N10).

### 6.2 Pristine invariants that the patch removes

- I1: at `init_semaphore_pools(new)` all existing pages of the other GPUs' pools are mapped into `new` (S/uvm_gpu.c:1142-1148).
- I2: every page allocated later is mapped on all retained GPUs: `uvm_rm_mem_alloc_and_map_all()` -> `uvm_rm_mem_map_all_gpus()` -> `for_each_gpu` (S/uvm_rm_mem.c:435-475), which asserts that the global lock is held (S/uvm_global.h:372-376).
- Isolated mode removes both: each page lives on its owner and the CPU.

### 6.3 GPU add / remove ordering

- `add_gpu()`: `init_gpu()` is called at P/uvm_gpu.c:2828; inside it `init_semaphore_pools()` (:1615) runs **before** `uvm_channel_manager_create()` (:1623), so the new pool is empty at init; the new GPU enters `g_uvm_global.retained_gpus` only after `init_gpu()` succeeds (:2836-2837), so during its own channel creation `for_each_gpu` does not include it. This is why pristine maps new-GPU pages onto existing GPUs at allocation and existing pages onto the new GPU at init (symmetric, all under the global lock). In isolated mode neither direction exists, so there is no window.
- `remove_gpu()` clears `retained_gpus` first (P:2757), then calls `deinit_gpu()` (:2767), which flushes other GPUs' trackers of references to this GPU (`remove_gpus_from_gpu`, :1710-1721, called from :1773-1777), destroys the channel manager (:1794, so every tracking semaphore is freed first), then runs `deinit_semaphore_pools()` (:1802).
- `deinit_semaphore_pools()`: the unmap loop (:1163-1169) exists to remove *this GPU's* mapping from the other GPUs' pages. It is skipped iff `!CC and !allow`, exactly when `init` returned early (:1139-1146). Equivalent conditions. Also `uvm_rm_mem_unmap_gpu()` is a no-op for a GPU that is not mapped (S/uvm_rm_mem.c:347-352, 362-372), so even a residual mismatch would be benign.

### 6.4 Unmap / free and in-flight work

- `uvm_gpu_semaphore_free()` only returns the slot (P/uvm_gpu_semaphore.c:344-373). Pages are freed only at pool destroy (`pool_free_page`, :263-289) -> `uvm_rm_mem_free()` (S/uvm_rm_mem.c:374-407): unmap CPU, unmap non-owner GPUs listed in `mapped_on` (none in isolated mode), free the owner mapping last, assert `mapped_on` empty.
- In isolated mode no other GPU holds a mapping, so "freeing a page still referenced by in-flight work on another GPU" cannot occur through a GPU-side acquire, **provided C1 holds**. The CPU side reads a channel's tracking semaphore through the owner's CPU mapping (`uvm_gpu_semaphore_get_cpu_va`, P/uvm_gpu_semaphore.c:488-497), which lives until pool destroy; trackers holding foreign channels are flushed by `deinit_gpu` before the channel and pool are destroyed (P/uvm_gpu.c:1773-1794).
- Pristine hazard that disappears: B's acquire spinning on A's page through B's mapping while A is destroyed.

### 6.5 Confidential Computing

CC creates a secure (VID) pool in addition to the SYS pool (P/uvm_gpu.c:1139-1141; P/uvm_gpu_semaphore.c:101-104). Secure-pool pages (P/uvm_gpu_semaphore.c:190-219) and the encrypted-payload sysmem are untouched by the patch and are owner-only already. The SYS pool in CC keeps `alloc_and_map_all` (P:183-187), and `init_semaphore_pools()` returns on the CC check before the new early return (P/uvm_gpu.c:1139-1146), so in CC the parameter changes neither pool mapping nor teardown; only hunk 4 runs (ORD-07). Tracking-semaphore pool choice: S/uvm_channel.c:2428, 2439-2442.

### 6.6 Contract and test drift

- S/uvm_gpu_semaphore.h:110-116 still states that a semaphore "will be mapped on all GPUs currently registered ... and on all new GPUs", and :101-108 / :122-128 say the global lock is needed "for unmapping from all GPUs" / "for mapping on all GPUs". Not true in isolated mode (ORD-06).
- Built-in test `UVM_TEST_GPU_SEMAPHORE_SANITY` (S/uvm_test.c:258) asserts `gpu_va != 0` for every (semaphore, va_space GPU) pair (S/uvm_gpu_semaphore_test.c:179-196), and `UVM_TEST_TRACKER_SANITY` acquires one GPU's semaphore from all GPUs (ORD-12). Neither can pass with two or more GPUs in isolated mode (built-in tests are off by default, S/uvm_common.c:46).

## 7. Concurrency, interruption, context loss

- **Concurrent migrations**: per-call `migrate_vma_state_t` and stack `zero_tracker`; the only shared objects are GPU channels and the pushbuffer, whose usage rules the patch does not touch. The CPU wait is performed *outside* any open push (no push semaphore or channel lock held), so a waiting thread cannot starve other threads of push slots.
- **Signals**: the wait ignores signals completely (uvm_common.c:274), so SIGKILL cannot interrupt it. A thread stuck there is runnable (it calls `schedule()` every iteration), so hung-task detection (D-state) would not fire (inference; Linux behaviour not in the supplied source), and the stuck warning is debug-print gated (section 2). The migrating thread holds mmap_lock (read), the va_space lock (read) and page locks for the duration. Process exit also waits for the BH's mm retainer (`uvm_va_space_mm_shutdown`, S/uvm_va_space_mm.c:329, 426). Same as the pristine waits, but a larger share of the migration is now a wait.
- **Channel / RC / ECC / global errors during the wait**: only the awaited channel's notifier is polled (plus global status). A detected error sets the global fatal error and the wait returns it; the tracker is cleared; the migration unwinds as in section 5. A GPU hang with no error notifier raised is an infinite wait (liveness depends on RM, or on the hybrid bridge, delivering notifiers: U6).
- **VA space teardown / GPU unregister**: `uvm_va_space_destroy` and `unregister_gpu` need the va_space lock in write mode (S/uvm_va_space.c:494, 330), which excludes the in-flight reader; BH users are locked out the same way (S/uvm_va_space.c:490-494 comment). `uvm_gpu_release` -> `remove_gpu` needs the GPU's retained count at zero (P/uvm_gpu.c:2717-2720), which the registered VA space holds. So `copying_gpu` and `dst_gpu` stay valid across the wait.
- **System suspend/resume, GPU reset / surprise removal during the wait**: not analysed (U7).

## 8. Findings

Severity scale: blocker / high / medium / low / info. No blocker, no high.

**ORD-01 - Contract enforced only by debug assertions; release build fails open.** Severity medium. Evidence: source-observation (code facts) + inference (build is release) + unknown (hardware consequence). Confidence: high for code facts, medium for "build is release", low for the runtime consequence.
- `push_acquire_tracker_entry()` checks the cross-GPU condition with `UVM_ASSERT(uvm_push_allow_dependencies_across_gpus())` (P/uvm_push.c:98-99), then unconditionally computes the semaphore VA and emits the acquire (:101-102). Documented contract: the caller must pre-wait (S/uvm_push.h:333-336).
- `uvm_push_acquire_tracker()` first removes completed entries (P/uvm_push.c:136), so only a still-pending foreign entry reaches the check: a missed call site fails only when the producer is slow (timing-dependent; invisible to compile-only and text-order tests).
- For an unmapped GPU, `uvm_rm_mem_get_gpu_uvm_va()` has `UVM_ASSERT_MSG(mapped)` (S/uvm_rm_mem.c:93) and otherwise returns `vas[gpu]`, which is zero (S/uvm_rm_mem.h:47-49; rm_mem zero-allocated, S/uvm_rm_mem.c:208); `uvm_gpu_semaphore_get_gpu_va()` then returns `0 + index*4` (P/uvm_gpu_semaphore.c:481-486).
- `UVM_ASSERT`/`UVM_ASSERT_MSG` are compiled out unless `DEBUG` or Coverity (S/uvm_common.h:163-171); `UVM_BUILD_TYPE = release` (S/nvidia-uvm.Kbuild:5) adds `-DDEBUG` only for debug/develop (:25-33); the build command in `inputs/r580-uvm-isolated-gpu-execution-build-v5-20261023T2130Z.json` passes no override. `UVM_ASSERT_RELEASE`-class macros exist (S/uvm_common.h:173-200) but are not used here.
- Impact: the central invariant "no cross-GPU semaphore acquire is ever emitted in isolated mode" has no run-time guard in the shipped configuration. What the GPU does on an acquire at a near-zero VA of its UVM-internal address space is unknown (MMU fault -> channel error, hang, or accidental match).
- Not a bug at the present call-site coverage (N2), but a single point of failure. Optional hardening outside this patch's scope: fail closed in release (for example a `UVM_ASSERT_RELEASE` plus error return, or a mapped-on-GPU check) before emitting the acquire.

**ORD-02 - The predicate flip activates CC-only CPU-wait code for the whole driver; deadlock/stall freedom is unproven.** Severity medium. Evidence: source-observation (what runs) + unknown (consequences). Confidence: high / low.
- P/uvm_push.c:65-70 changes the predicate that `wait_for_other_gpus_if_needed()` (P:210-219) uses on every `uvm_push_begin_acquire*` with a tracker (P:267, P:299): about 25 sites (section 3.8), including the replayable-fault replay/cancel pushes whose trackers inherit entries from VA-block work on peer GPUs (`push_replay_on_gpu`, S/uvm_gpu_replayable_faults.c:503-544; `push_cancel_on_gpu` :352-416; the comment at P/uvm_gpu.c:1674-1675 (S:1666-1667) says the replay tracker "inherits dependencies from the VA block trackers").
- Consequence: fault bottom halves and va_block-locked code now block on peer-GPU work they previously ordered on the GPU, extending hold times of the ISR service lock / va_block mutex and coupling one GPU's hang to another GPU's fault service. A pre-existing CPU wait on foreign entries under `block->lock` exists (`pmm_gpu_alloc`, S/uvm_pmm_gpu.c:580) but is narrower.
- I found no lock cycle: the awaited work consists of already-submitted UVM CE pushes that use physical addressing and (in isolated mode) have no GPU-side cross-GPU dependencies, so it terminates unless the hardware stalls. Whether a CE channel can be starved by faulted user contexts that this same BH must service is a hardware/RM question (U2). I have no evidence that the CC-only code has been exercised with real cross-GPU entries (single-GPU CC never produces them) (U9).

**ORD-03 - Hunk 4 is narrow and its compilation / reachability is not evidenced.** Severity low. Evidence: source-observation + build-report + test. Confidence: high for the facts; whether it was compiled is unknown.
- Reachable only through ATS: `uvm_api_range_type_check()` returns ATS only if `g_uvm_global.ats.enabled` (platform `atsSupported`, `uvm_ats_mode`, `UVM_ATS_SUPPORTED()`, mm-based VA space: S/uvm_ats.c:35-43; S/uvm_policy.c:74-85); the fault-BH path needs `uvm_ats_can_service_faults` (S/uvm_ats_faults.c:104). `zero_tracker` is non-empty only for NVLink >= 5 or test-injected errors (P:762-766). On a PCIe-only non-ATS system the hunk is dead code.
- The whole body of `uvm_migrate_pageable.c` is under `#ifdef UVM_MIGRATE_VMA_SUPPORTED` (P:44, :1542), defined only if `CONFIG_MIGRATE_VMA_HELPER` or `NV_IS_EXPORT_SYMBOL_PRESENT_migrate_vma_setup` (S/uvm_migrate_pageable.h:63-69), which conftest derives from the build kernel's `Module.symvers` and which "may be a false negative if Module.symvers is absent or incomplete" (`source/NVIDIA-kernel-module-source-580.178.04/kernel-open/conftest.sh:378-391`; S/nvidia-uvm.Kbuild:75). The build report records neither that conftest result nor compiler flags, and its `source_files` hashes are the pristine ones (probe hashes before patching: `inputs/probe_r580_uvm_isolated_execution.py:233` then patch at :235-246), so "compiled" does not demonstrate that hunk 4 is in the `.ko`.
- `inputs/test_r580_uvm_isolated_execution_patch.py:75-79` proves ordering by `str.index()` of three strings (text position), not control flow.

**ORD-04 - New CPU waits are non-interruptible, unbounded and silent in release.** Severity low. Evidence: source-observation (+ inference for Linux detector behaviour). Confidence: high / medium.
- uvm_common.c:274 (TODO), :276-279; the stuck message is `UVM_DBG_PRINT` (uvm_common.h:288-298), gated by `uvm_debug_prints` (uvm_common.c:30-39). A hung peer GPU (or a provider that fails to raise an error notifier) becomes a runnable-but-stuck thread holding mmap_lock/va_space/page locks (migrate ioctl and ATS BH) or the ISR service lock (BH), with no log line, no signal escape, and probably no kernel watchdog report.
- Same property as the pristine waits at S/uvm_migrate_pageable.c:402 and :1013; the patch adds more of them (ORD-02) and one more on the pageable path.

**ORD-05 - Wait failure drops all tracking before pages are freed.** Severity low. Evidence: source-observation. Confidence: high (code); hardware consequence unknown.
- uvm_tracker.c:380-383 clears the whole tracker (including un-awaited entries); the caller then frees destination pages (P:880-894, :1062). A healthy GPU's still-running zero push could in principle write a freed page. This is the same exposure as the pristine `uvm_tracker_wait` failure behaviour (S/uvm_tracker.c:344-355) and the pristine final wait (S/uvm_migrate_pageable.c:1013); failure implies a global fatal error. No new class; recorded so the reconciler does not credit hunk 4 with improving it.

**ORD-06 - Documentation and built-in-test drift.** Severity low (info for production). Evidence: source-observation. Confidence: high.
- S/uvm_gpu_semaphore.h:101-116 and :122-128 describe all-GPU mapping and global-lock requirements that no longer hold in isolated mode; `UVM_TEST_GPU_SEMAPHORE_SANITY` (S/uvm_gpu_semaphore_test.c:179-196) fails with two or more GPUs. The patch updates neither.

**ORD-07 - Hunk 4 also runs under CC with the parameter off; CC + isolated does not isolate semaphore pages.** Severity info. Evidence: source-observation. Confidence: high.
- P:810 uses `!uvm_push_allow_dependencies_across_gpus()`, which is true for CC (P/uvm_push.c:69), so CC deployments gain the wait without opting in (no effect when `zero_tracker` is empty; otherwise it replaces an acquire that CC forbids and that pristine would have emitted against an unmapped VA). Conversely the patch comment at P/uvm_gpu_semaphore.c:181-182 ("Keep the page CPU-mapped and mapped to its owner GPU only") is not true in CC, because the branch is gated by `!conf_computing_enabled`. Belongs to the scope reviewer; listed for completeness.

**ORD-08 - `uvm_tracker_wait_for_other_gpus` dereferences `entry->channel` without a NULL check.** Severity info. Evidence: source-observation. Confidence: high.
- uvm_tracker.c:369, 443-446 versus uvm_tracker.h:35-38. No production path stores NULL-channel entries (grep of `channel = NULL`: only uvm_tracker.c:317), so it is unreachable at the new call site.

**ORD-09 - Debug-only assertion can misfire on error.** Severity info. Evidence: source-observation. Confidence: medium.
- `UVM_ASSERT(status == uvm_global_get_status())` (uvm_tracker.c:316, 381) can fail if `uvm_channel_check_errors()` returns an error different from an earlier global error, because `uvm_global_set_fatal_error_impl()` keeps the first (uvm_global.c:426-436). Pre-existing, debug builds only.

**ORD-10 - Serialisation and CPU burn.** Severity info. Evidence: source-observation. Confidence: high.
- With hunk 4 each source iteration with a zero push serialises zero -> copy and spins a CPU; throughput only, NVLink5 / test-injection paths only.

**ORD-11 - Liveness of the CPU wait depends on per-provider error-notifier delivery.** Severity low. Evidence: unknown (bridge not supplied). Confidence: low.
- The wait ends only on semaphore completion, the awaited channel's error notifier, the GPU ECC notifier, or a global error (S/uvm_channel.c:2058-2082). In a mixed-provider setup the notifier memory and the CPU mapping of the semaphore page come from the owning provider's RM via the callback bridge, which is not in the supplied source tree.

**ORD-12 - An in-tree hand-written cross-GPU acquire (test-only) bypasses the wait and is incompatible with isolated mode.** Severity low (info for production). Evidence: source-observation (code), inference (runtime effect). Confidence: high / low.
- `test_tracker_completion()` (S/uvm_tracker_test.c:59-148, run by `UVM_TEST_TRACKER_SANITY`, S/uvm_test.c:264, S/uvm_tracker_test.c:437-448) allocates one semaphore from the *first* VA-space GPU's pool (:77-80), then loops over every VA-space GPU reusing the same `gpu` variable (:88) and emits `host_hal->semaphore_acquire` on every channel of every GPU against that single semaphore (:109-112). With two or more GPUs this is a GPU-side cross-GPU acquire that does not go through `push_acquire_tracker_entry` or `wait_for_other_gpus_if_needed`. It skips only in CC (:74-75), not in isolated mode.
- In isolated mode the second GPU has no mapping: debug build -> `UVM_ASSERT_MSG` (S/uvm_rm_mem.c:93); release build -> acquire against `0 + index*4`, after which the CPU loop at :133-137 spins on `uvm_tracker_remove_completed()` with no error check and may never exit (inference).
- Active only with `uvm_enable_builtin_tests=1` (default 0, S/uvm_common.c:46) and an explicit test ioctl; not a production path. It is a concrete instance of "another direct GPU acquire bypassing the wait" and of ORD-01's fail-open behaviour. The patch neither guards nor skips it.

## 9. Negative results (checked, found safe)

- N1 Hunk 4 ordering and emptiness: sections 3.2-3.4.
- N2 No production caller of `uvm_push_acquire_tracker` or `host_hal->semaphore_acquire` other than S/uvm_push.c:236 (preceded by the wait) and S/uvm_migrate_pageable.c:816 (hunk 4); test callers are same-GPU, guarded (S/uvm_channel_test.c:792), or listed as ORD-12.
- N3 `zero_tracker` is stack-local; no concurrent modification.
- N4 The copy push acquires no other tracker; `state->tracker` is wait-only.
- N5 All returns clean up; `migrate_vma_finalize()` is always reached (P:1177); no leak, double free or UAF introduced (section 5).
- N6 No new lock, no lock-order change, no push/channel/PMM/va_block lock held across the wait (section 4).
- N7 No RM call on the wait's normal path (S/uvm_lock.h:136-140 not violated).
- N8 `init`/`deinit` semaphore pool conditions are mutually consistent (P/uvm_gpu.c:1139-1146 versus :1163); unmapping an unmapped GPU is a no-op (S/uvm_rm_mem.c:347-372).
- N9 Owner-GPU mapping and CPU mapping always exist for owner-only pages (S/uvm_rm_mem.c:247, 261-292), so same-GPU acquires, push-end releases (S/uvm_channel.c:1512) and CPU polling still work.
- N10 Page-allocation failure paths do not leak (P/uvm_gpu_semaphore.c:228-261; S/uvm_rm_mem.c:430-433).
- N11 Teardown order (channels, then pool) leaves no cross-GPU mapping lifetime coupling (P/uvm_gpu.c:1794, 1802).
- N12 Default mode (param 0, non-CC) is behaviourally identical to pristine in all four files (mode matrix, section 0).
- N13 Failure of the wait is a global fatal error, which the ATS BH is written to expect (S/uvm_gpu_replayable_faults.c:1731-1742).
- N14 The end-of-push release always uses membar sys (S/uvm_channel.c:1053-1063): CPU-observed completion is at least as strong as the removed GPU acquire.
- N15 The pristine `uvm_tracker_wait_for_other_gpus` caller set is three (push begin, PMM alloc, CC DMA buffer); all propagate failure and deinit their tracker.
- N16 The `UVM_MIGRATE` ioctl cannot race `uvm_va_space_destroy` / GPU unregister: both need the va_space write lock (S/uvm_va_space.c:330, 490-494).
- N17 The upstream guard in `uvm_channel_test.c` is unchanged by the patch (S/uvm_channel_test.c:792).
- N18 Tools / perf hooks used in the copy push issue no acquires (S/uvm_tools.c:1385-1450; S/uvm_perf_events.h:368-400).

## 10. Unknowns and proposed discriminating experiments

None of these was performed; no hardware or runtime access was used.

| ID | Unknown | Why it matters | Cheapest discriminator |
|---|---|---|---|
| U1 | Hardware behaviour of a Host semaphore acquire at an unmapped near-zero VA | defines ORD-01 / ORD-12 severity | owner-run, debug UVM build with `uvm_enable_builtin_tests=1`, isolated param, 2 GPUs: run `UVM_TEST_TRACKER_SANITY` and note whether the unmapped-VA assertion trips (expected) |
| U2 | Can CE scheduling for the awaited zero/copy push be starved by pending faults that the waiting BH must service? | deadlock class (ORD-02) | owner-run two-GPU stress, isolated param, debug build, `uvm_debug_prints=1`: `UVM_TEST_CHANNEL_STRESS`, `UVM_TEST_PUSH_SANITY` (S/uvm_test.c:265, 267) while faulting workloads run; expect `TRACKER_SANITY` and `GPU_SEMAPHORE_SANITY` to fail by design (ORD-06, ORD-12) |
| U3 | Is ATS enabled and are NVLink >= 5 links present on the target? | whether hunk 4 can execute | read `uvm_ats_mode` and platform ATS support on the target (owner action) |
| U4 | Was `UVM_MIGRATE_VMA_SUPPORTED` defined in the tested build? | whether hunk 4 is in the `.ko` | static: inspect the original build tree's conftest output for `NV_IS_EXPORT_SYMBOL_PRESENT_migrate_vma_setup`, and `nm` / `objdump -dr` on `uvm_migrate_pageable.o` for a call to `uvm_tracker_wait_for_other_gpus`; the recorded module hash is `d8d96ff95285da7640073944774241dec84e662e60255f7f37c4e2790506db38` (file not supplied) |
| U5 | Actual `UVM_BUILD_TYPE` of the tested artefact | release versus debug assert state | inferred release from S/nvidia-uvm.Kbuild:5 and the build command; confirm from the original build log (not supplied) |
| U6 | Hybrid bridge: error-notifier delivery, CPU map of owner-provider sysmem, completion visibility | liveness of CPU waits (ORD-11) | review the bridge source (not in this tree) |
| U7 | Suspend/resume, GPU reset, surprise removal during a CPU wait | context-loss behaviour | not analysed; needs a `uvm_suspend` / PM path review |
| U8 | Lock context of each of the ~25 `uvm_push_begin_acquire*` callers (spinlock or atomic context?) | completeness of 4.5 | per-caller audit |
| U9 | Whether CC multi-GPU cross-wait code has real-world exercise | confidence in reusing it | external to this tree |

## Appendix A. Read-only commands used

`sha256sum` (archive, patch, all cited files), `diff -rq` and `diff -u` between `S/` and `P/`, `grep`/ripgrep over `S/`, `P/`, `inputs/`, `sed -n`, `awk` for line-numbered excerpts, `cat` and file reads of source and inputs. No scripts from `source/` or `inputs/` were executed; no build, load, GPU, VM or kernel interaction. Two in-place text replacements on this output file itself were made with `python3 -I` (a hash line and one sentence); nothing else was modified.

## Appendix B. SHA-256 of cited files

Files outside the first group are byte-identical in `S/` and `P/`.

Patched-tree variants (`P/` = `patched/kernel-open/nvidia-uvm/`):

```
23bb5a514a99b1c747e683ddd3612511647cc3e95745ccdc1b1e22db3d584197  P/uvm_gpu.c
4224b4f808c9f86279cb97bfa9645e6b592ace4b2f4213e81848d1ebba4258a3  P/uvm_gpu_semaphore.c
53b1cdd7abc6f5dcea062a314b5580b05329868ad36a61f6a3f0d567f3326227  P/uvm_push.c
0aea84a9260f3ae70847e366ef83eae5d7119e0a4865ff631491200e004306bb  P/uvm_migrate_pageable.c
```

Pristine tree (`S/` = `source/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm/`):

```
b43bb94bbc465bbb4fb243e6f722cb450d6402f3071971843d61f1f7678bf700  S/uvm_gpu.c
1472d3bdcd91b35095fb7ae6aa1f66a075ea495c08d106ed7da497176a3d629f  S/uvm_gpu_semaphore.c
9628ada0b4007eff5af16525d0d71788045832e5ca268699e2ae82a5dc14b85e  S/uvm_push.c
e7178513d684596aadbe24c1f699eb9e7b13b7f39c19805fe213bbef090898da  S/uvm_migrate_pageable.c
756ce284db092691c5e346c9180299c98e050d4391242c53c19d14fcdff13e41  S/uvm_tracker.c
17db41fd3fbbaa9aec3047f7c226514085ae0d5479c572f99aa3dd36e9403058  S/uvm_tracker.h
5c2152b36c194ab14d3d79ec514aec59d2c204a0d50122f440d102d8b59072ce  S/uvm_push.h
795b78731ee73c36ea1200402277b73146d4772c6e220bff8c205133a4bb152c  S/uvm_migrate_pageable.h
e8fb855d0fc4150107118752b6a5e897b2c5f7d770243278f631a49ca4b36e36  S/uvm_migrate.c
4ad27640aa15efd4ec7e87fa649aa67049441b63208285cd6cfed5bc87fb41cc  S/uvm_ats_faults.c
e637830fc7735d68638e34d3001455de80a08d6505b9760705739da6d95244ca  S/uvm_ats.c
0aa0dfa810e67b1b78c3de96581089b37cc4421ed20f5adedecb4df638ac95db  S/uvm_policy.c
35248129b757c9a405bed7adf7022ea108ebbd9bbb0b091a008935f1247dea9b  S/uvm_pmm_gpu.c
a6f00c57334ce6bb397cb69b129cb72ba938460e10dd2fc8fddb680edfe273c0  S/uvm_conf_computing.c
e19a72f018add7239e024b3907f6408abab0ef1626a6d1c814fe447574b055e3  S/uvm_gpu_semaphore.h
fdf517f711ce9ae3421e4af2e7fe128f0db4182000eeed32504eacc82d1a43d7  S/uvm_rm_mem.c
ced992530152a8fc0e0c9b099cad16a857bcf09b0a1bc4407c0598c53d239c7e  S/uvm_rm_mem.h
64fcdb55ecba388c8ed6c656ca72b60f2b6f4b8bc0ebaffd794ed1e78068a248  S/uvm_channel.c
c03569619e1295d2b646087228454f4f4c8a77cb911cfa308559daabfd497c0f  S/uvm_channel.h
4703e2717dc3eb71bdbaa08f2759887e26ddf129a93918a4014ed19d7089bfa2  S/uvm_common.c
0666a8f60e034f8461b06b208b1ebe8b8425ff91149fa956533c0a6bda3914d6  S/uvm_common.h
aeee2f257a289853f36d9c7b196f1e02d19b84695db44cdd2e00f28b0f1a4489  S/uvm_global.c
32c99fb632fa831da1fbae7c4e541e4fc35afd1d3bf94fe5f7ba57f97dc2e33c  S/uvm_global.h
dbdf1e68a13c6bb3bf351d6516cf8884c06b016268d4a286dcdb7e68e6963f53  S/uvm_lock.h
dd2821620e83cfaeb03fd765d64dcb75d82da83a38107afa4b0c2882570a7b03  S/uvm_va_block.c
cff2ab99e9b45143865413cd15d78381ead57b370f4b3bc32ac7584ca9e91693  S/uvm_va_space.c
f9a8e86af533a538834fc55b04896703da16d76bb57d4f481532a85d287e905c  S/uvm_va_space_mm.c
9ae60b0954c659d0f43d90cdfa0f778805046c56c6eafd7edb09f45467f20512  S/uvm_va_space_mm.h
61dcbb1826e6104452d82d319b5b8c810e328e6a606f619e0efaa273d162bdea  S/uvm_mmu.c
42557042482532ac9ec39918663bfb0ea8c78ac0cd977a2725168c632e37ba1e  S/uvm_tools.c
2c9339e77c04cb94bf361ee881260ef7e5dc100dfa6bb2dccf41f6bd81c70155  S/uvm_gpu_semaphore_test.c
f846b5e2925258bb1643e389bee4016743a73a6f396571e0621aac109bb94e87  S/uvm_channel_test.c
c7991f9a9e029ae1e9dc4aba579ecb37c64408d9600117abdeec82fbc1b245b3  S/uvm_gpu_replayable_faults.c
588e72e5e3163f2e9a3c1b0d78a5450c97a4393b5b0c8e024915c41460d0250b  S/uvm_gpu_non_replayable_faults.c
6e0476ded5b3adc6f5996bcd83e18012f7c38b6ccb662c9d9befd8b2e885cfc9  S/uvm_hmm.c
4115e9f2de1fc9ad460a61168e78e68ede19c57ac6216740dc57475b29d07511  S/uvm_map_external.c
11f5a41820746ffb1bc2d70729eaca257eeea3ca71ecbf4fc31fa4a1f3bc5a01  S/uvm_gpu.h
28114c2b6616aaac935c1995a280c55099117444f491325918f64e61a6e51ba4  S/uvm_test.c
517fe4ab345c0d90fc53a53dbf715bea1fea945dafc171142f74c5ae7240a0b9  S/uvm_tracker_test.c
33d6978c9cd7e2feafddeda76245543e44d999d13826c78adfabf96c86efd3ab  S/uvm_push_test.c
ad1ab9157ec9113575f351b15e3a8ea5543b74a9a99af60154cda56d6ff8025a  S/uvm_host_test.c
0e8d3d96e00d6ca8b6b564e4668dd70447d8b6bca9200845180ce7c66902328b  S/nvidia-uvm.Kbuild
3e826d4f67ecabb304e2ff79e3d72d7559693dece308af3b61dd73398e4279d1  S/uvm_perf_events.h
```

Other files under `source/NVIDIA-kernel-module-source-580.178.04/`:

```
1fef0f05becc1901172fa331b8797e291d6dbc16d43975a65f8629846bc69bbf  kernel-open/conftest.sh
f42689de8a2608926ec792325d8f383b9e87c567be0e640860156b68456fd253  kernel-open/common/inc/nv-linux.h
cbc6488ed2c35ea814120bc80749dd2d11f486c3e98046b3be240d462ee86e7c  version.mk
```

Inputs cited:

```
060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8  inputs/NVIDIA-kernel-module-source-580.178.04.tar.xz
23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0  inputs/0002-hybrid-isolated-gpu-execution.patch
85778e162d6a39549e1126073d7a1f71ac110c90526f6151c1aa72d277564fe1  inputs/r580-uvm-isolated-gpu-execution-build-v5-20261023T2130Z.json
38121cc8cf79bd8b34818dcedde9bdcc95453cdf896b7da5d3f701eea5e1298a  inputs/test_r580_uvm_isolated_execution_patch.py
ccd0bb61687975af1daae386dcb5cee1dfcbb911aabee1a589576877089075a8  inputs/probe_r580_uvm_isolated_execution.py
a02b4d8b9e1498ba1aab379121ebb1f38c206bf5942d035ab96af98aaf63feb9  inputs/r580-uvm-cross-provider-static-v2-20261023T204103Z.json
```
