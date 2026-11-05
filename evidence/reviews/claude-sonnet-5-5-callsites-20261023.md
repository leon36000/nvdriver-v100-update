# SONNET_REVIEW_CALLSITES — R580.178.04 UVM isolated-execution patch, acquire-path census

Static analysis only. `hardware_validated=false`, `runtime_validated=false`. Nothing was built, loaded or run.

## 0. Provenance and hashes

- `S/` is `/home/pc6/claude-driver-hybrid-uvm-v5-20261023/source/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm/` (pristine).
- `Q/` is `/home/pc6/claude-driver-hybrid-uvm-v5-20261023/patched/kernel-open/nvidia-uvm/` (patched).
- Archive SHA-256 `060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8`, re-hashed. `version.mk` reads 580.178.04.
- Patch SHA-256 `23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0`, re-hashed.
- `diff -u S/ Q/` matches the six patch hunks exactly. `diff -rq` lists only 4 differing files, so all other files are byte-identical and their line numbers hold in both trees.
- For the 4 changed files, lines are cited as `pristine[patched]`.

Changed files, pristine to patched:
```
uvm_push.c             9628ada0b4007eff5af16525d0d71788045832e5ca268699e2ae82a5dc14b85e -> 53b1cdd7abc6f5dcea062a314b5580b05329868ad36a61f6a3f0d567f3326227
uvm_gpu.c              b43bb94bbc465bbb4fb243e6f722cb450d6402f3071971843d61f1f7678bf700 -> 23bb5a514a99b1c747e683ddd3612511647cc3e95745ccdc1b1e22db3d584197
uvm_gpu_semaphore.c    1472d3bdcd91b35095fb7ae6aa1f66a075ea495c08d106ed7da497176a3d629f -> 4224b4f808c9f86279cb97bfa9645e6b592ace4b2f4213e81848d1ebba4258a3
uvm_migrate_pageable.c e7178513d684596aadbe24c1f699eb9e7b13b7f39c19805fe213bbef090898da -> 0aea84a9260f3ae70847e366ef83eae5d7119e0a4865ff631491200e004306bb
```
Other cited files, identical in both trees:
```
uvm_push.h 5c2152b36c194ab14d3d79ec514aec59d2c204a0d50122f440d102d8b59072ce
uvm_tracker.c 756ce284db092691c5e346c9180299c98e050d4391242c53c19d14fcdff13e41
uvm_tracker.h 17db41fd3fbbaa9aec3047f7c226514085ae0d5479c572f99aa3dd36e9403058
uvm_channel.c 64fcdb55ecba388c8ed6c656ca72b60f2b6f4b8bc0ebaffd794ed1e78068a248
uvm_rm_mem.c fdf517f711ce9ae3421e4af2e7fe128f0db4182000eeed32504eacc82d1a43d7
uvm_gpu_semaphore.h e19a72f018add7239e024b3907f6408abab0ef1626a6d1c814fe447574b055e3
uvm_hal.c 9e1c8c1e0e70d26328809713fc7af7f79e49a57a545ea474b36d70a07d56325d
uvm_maxwell_host.c 184c79ac70133209a320b64dfa4896525066a3894423ad95848ba75d6c45ca76
uvm_turing_host.c 2542e3dd1ce48c9b8c1edaecd4e2bbe09f9fa0e6adbd0a9e1974ff6ba7116147
uvm_hopper_host.c 63afaf72e0993a75fc8e5630a6c609742d47a8da2fca97805dff7160860e2ea5
uvm_maxwell_ce.c 917111014f1400fc97046fe3e4812e60fa98955e7945c67c10d9ee5b95760890
uvm_va_block.c dd2821620e83cfaeb03fd765d64dcb75d82da83a38107afa4b0c2882570a7b03
uvm_pmm_gpu.c 35248129b757c9a405bed7adf7022ea108ebbd9bbb0b091a008935f1247dea9b
uvm_migrate.c e8fb855d0fc4150107118752b6a5e897b2c5f7d770243278f631a49ca4b36e36
uvm_gpu_replayable_faults.c c7991f9a9e029ae1e9dc4aba579ecb37c64408d9600117abdeec82fbc1b245b3
uvm_gpu_non_replayable_faults.c 588e72e5e3163f2e9a3c1b0d78a5450c97a4393b5b0c8e024915c41460d0250b
uvm_gpu_access_counters.c cda1dfa8ca763d78a4db2b30aa559b75334e5fe0f0262b32de7be22d7f73357d
uvm_gpu_isr.c 456ee47bb83564cc1ada830538781256bb246bf82888601d3c3f2b3a2bc777f5
uvm_ats_faults.c 4ad27640aa15efd4ec7e87fa649aa67049441b63208285cd6cfed5bc87fb41cc
uvm_hmm.c 6e0476ded5b3adc6f5996bcd83e18012f7c38b6ccb662c9d9befd8b2e885cfc9
uvm_map_external.c 4115e9f2de1fc9ad460a61168e78e68ede19c57ac6216740dc57475b29d07511
uvm_mmu.c 61dcbb1826e6104452d82d319b5b8c810e328e6a606f619e0efaa273d162bdea
uvm_conf_computing.c a6f00c57334ce6bb397cb69b129cb72ba938460e10dd2fc8fddb680edfe273c0
uvm_va_range.c 10c80433314c9b38cc84f82ac156f2df9d0f5c9d3c73a9e64179047eb2148878
uvm_pushbuffer.c 7031f10fc2215d792d58675b503623be5792e13fa4304d14f9b60b811a0a812c
uvm_common.h 0666a8f60e034f8461b06b208b1ebe8b8425ff91149fa956533c0a6bda3914d6
uvm_common.c 4703e2717dc3eb71bdbaa08f2759887e26ddf129a93918a4014ed19d7089bfa2
uvm_global.c aeee2f257a289853f36d9c7b196f1e02d19b84695db44cdd2e00f28b0f1a4489
uvm_test.c 28114c2b6616aaac935c1995a280c55099117444f491325918f64e61a6e51ba4
nvidia-uvm.Kbuild 0e8d3d96e00d6ca8b6b564e4668dd70447d8b6bca9200845180ce7c66902328b
uvm_tracker_test.c 517fe4ab345c0d90fc53a53dbf715bea1fea945dafc171142f74c5ae7240a0b9
uvm_gpu_semaphore_test.c 2c9339e77c04cb94bf361ee881260ef7e5dc100dfa6bb2dccf41f6bd81c70155
uvm_channel_test.c f846b5e2925258bb1643e389bee4016743a73a6f396571e0621aac109bb94e87
uvm_push_test.c 33d6978c9cd7e2feafddeda76245543e44d999d13826c78adfabf96c86efd3ab
uvm_host_test.c ad1ab9157ec9113575f351b15e3a8ea5543b74a9a99af60154cda56d6ff8025a
```

## 1. Verdict summary

**Q5: with the parameter set and CC off, I found no production path where a GPU push acquires or accesses a semaphore owned by a different `uvm_gpu_t`.** Evidence class is source-observation and confidence is high. The basis is:

1. **Single acquire sink.** The only code that emits a GPU semaphore acquire is `push_acquire_tracker_entry`, S:uvm_push.c:68-118 [Q:74-124]. It calls `host_hal->semaphore_acquire` at S:96 [Q:102]. No raw `ACQ_GEQ`, `ACQ_CIRC_GEQ`, `SEMAPHORED` or `SEM_EXECUTE` acquire exists outside the three HAL implementations.
2. **Two entry points.** In production the sink is reached through exactly two routes:
   - `push_begin_acquire_with_info`, always preceded by `wait_for_other_gpus_if_needed`. This is pre-existing upstream CC infrastructure. The patch only widens its predicate, `uvm_push_allow_dependencies_across_gpus()`, at Q:65-70.
   - One direct `uvm_push_acquire_tracker(&push, &zero_tracker)` at S:uvm_migrate_pageable.c:816 [Q:825]. The patch guards it with a CPU wait at Q:809-816.
3. **Only cross-GPU semaphore-VA consumer.** The only production code that computes another channel's tracking-semaphore GPU VA is that acquire, via `uvm_channel_tracking_semaphore_get_gpu_va_in_channel` (S:uvm_channel.c:2509-2516).
4. **No cross-GPU mapping in isolated mode.** Semaphore pool pages are mapped only on CPU and owner. No production caller of `nvUvmInterfaceDupAllocation` remains reachable.

**Patch coverage.** It is complete for production: one direct acquire exists and it is patched. The begin-acquire sites are protected by pre-existing code, not by the patch.

**Caveats that matter:**
- F4: two built-in test routines (`UVM_TEST_TRACKER_SANITY`, `UVM_TEST_GPU_SEMAPHORE_SANITY`) do raw cross-GPU semaphore acquire or lookups that no guard covers.
- F5: the shipped build configuration compiles every `UVM_ASSERT` out, so no runtime backstop would catch a missed path.
- F6: many pushes now block the calling thread on other GPUs' work.
- Everything is unvalidated on hardware.

## 2. Acquire primitives and their isolated-mode behavior

| Primitive (S line [Q line]) | Production callers | Isolated-mode behavior |
|---|---|---|
| `host_hal->semaphore_acquire`: `uvm_hal_maxwell_host_semaphore_acquire` (uvm_maxwell_host.c:207-223, ACQ_GEQ), `..._turing_...` (uvm_turing_host.c:53-71, ACQ_CIRC_GEQ), `..._hopper_...` (uvm_hopper_host.c:55-73, ACQ_CIRC_GEQ). Table entries uvm_hal.c:201/267/299. Ampere inherits Turing and Blackwell inherits Hopper through `parent_id`. | Only `push_acquire_tracker_entry` (S:96 [Q:102]). | No skip and no runtime check. `semaphore_target_is_valid` is wrapped in `UVM_ASSERT_MSG`, and it only rejects peer addresses (uvm_maxwell_ce.c:53-61). |
| `push_acquire_tracker_entry` S:68-118 [Q:74-124] | `uvm_push_acquire_tracker` S:120-136 [Q:126-142] | Returns early for a NULL channel or the same channel. An other-GPU entry only hits `UVM_ASSERT(uvm_push_allow_dependencies_across_gpus())` (S:92-93 [Q:98-99]). It does not skip or error. See F5. |
| `uvm_push_acquire_tracker` | S:uvm_push.c:236 [Q:242] (inside begin, after the wait); S:uvm_migrate_pageable.c:816 [Q:825] (direct, patched); test uvm_channel_test.c:793 (guarded at :792 upstream, not by this patch) | The pageable route is guarded by the CPU wait. |
| `wait_for_other_gpus_if_needed` S:204-213 [Q:210-219] | Called from `__uvm_push_begin_acquire_with_info` (S:261 [Q:267]) and `__uvm_push_begin_acquire_on_channel_with_info` (S:293 [Q:299]) | Returns OK if the tracker is NULL or `allow()` is true. Otherwise it calls `uvm_tracker_wait_for_other_gpus(tracker, push_gpu)`. |
| `uvm_tracker_wait_for_other_gpus` S:uvm_tracker.c:360-386 | Also uvm_pmm_gpu.c:580, uvm_conf_computing.c:300, Q:uvm_migrate_pageable.c:811 | CPU-spin waits on every entry whose `uvm_gpu_t` differs, then `remove_completed`. On error it clears the whole tracker. |
| `__uvm_push_begin_on_reserved_channel_with_info` S:312-327 | channel init and ctrl-GPFIFO pushes | Passes NULL tracker, so no acquire. |
| `__uvm_push_begin_acquire_on_channel_with_info` and the `uvm_push_begin_acquire_on_channel` macro | No production callers; tests only | Guarded the same way. |
| `uvm_channel_tracking_semaphore_get_gpu_va_in_channel` S:uvm_channel.c:2509-2516, then `uvm_gpu_semaphore_get_gpu_va` (S:uvm_gpu_semaphore.c:473-478 [Q:481-486]), then `uvm_rm_mem_get_gpu_va` (S:uvm_rm_mem.c:105-121) | Only the acquire; self-GPU uses at uvm_channel.c:1512, :4124 and uvm_tracker.c:287 | If the page is not mapped on that GPU, the assert is the only check (uvm_rm_mem.c:93). Without it the zero-initialised `vas[]` entry (0) is returned, so VA becomes `index*4`. |
| `uvm_gpu_semaphore_pool_map_gpu` / `unmap_gpu` S:uvm_gpu_semaphore.c:426-446 / 448-461 | Only S:uvm_gpu.c:1145 / :1160 (init and deinit) | Both skipped in isolated mode (Q:uvm_gpu.c:1143-1146 and :1163). |

## 3. Callsite table

"W1" means the CPU wait inside the begin-acquire chokepoint (S:uvm_push.c:261 [Q:267]). In isolated mode it fires on any other-GPU entry. No row bypasses the patch with the parameter set and CC off.

### 3a. Production `uvm_push_begin_acquire*` sites (25 textual sites plus 14 macro uses)

Files are in `S/`. All except Q:uvm_migrate_pageable.c are unchanged by the patch.

| # | Site | Function | Tracker passed, and can it hold other-GPU entries? | Coverage |
|---|---|---|---|---|
| 1 | uvm_va_block.c:2851 | `block_zero_new_gpu_chunk` | `&retry->tracker` (callers :2930, :2953). PMM-origin entries are same-GPU (uvm_pmm_gpu.c:575-582), but one retry object can span GPUs. Possible. | W1 |
| 2 | :3406 | `block_copy_begin_push`, GPU_TO_GPU | `&va_block->tracker`. Yes, the block tracker aggregates all GPUs (:2890, :4021). | W1 |
| 3 | :3447 | `block_copy_begin_push`, CPU/GPU | `&va_block->tracker`. Yes. The CC-only local copy is at :3417-3445. | W1 |
| 4 | :3992 | `zero_destination_mem_if_needed` | `&block->tracker` on dst GPU. Yes (src-GPU entries). | W1 |
| 5 | :8039 | `block_unmap_gpu` | `&block->tracker`. Yes. | W1 |
| 6 | :8504 | `block_map_gpu_to` | `&va_block->tracker`. Yes. | W1 |
| 7 | :8959 | `block_revoke_prot_gpu_to` | `&va_block->tracker`. Yes. | W1 |
| 8 | :9336 | `uvm_va_block_remove_gpu_va_space` | `&local_tracker`, filled only by `uvm_va_block_unmap` on the same GPU. No. | W1 |
| 9 | :9904, :9934 | `block_split_presplit_ptes_gpu` | `&existing->tracker`. Yes. | W1 |
| 10 | :13050 | `va_block_write_cpu_to_gpu` | `&va_block->tracker`. Yes. The CC branch (:13037-13048) is CC-only. | W1 |
| 11 | :13159 | `va_block_read_gpu_to_cpu` | `&va_block->tracker`. Yes. | W1 |
| 12 | :13547 | `block_gpu_force_4k_ptes` | `&block->tracker`. Yes. | W1 |
| 13 | uvm_gpu_replayable_faults.c:370, :379 | `push_cancel_on_gpu` | Caller tracker is `&batch_context->tracker` (:1077, :1080, :2532, :2684), merged with `replay_tracker` at :365. The batch tracker receives `va_block->tracker` at :1636. Yes. | W1 |
| 14 | :461 | `cancel_fault_precise_va` | `&replay_tracker` (per-parent). No, except SMC partitions (F8). | W1 |
| 15 | :515 | `push_replay_on_gpu` | `&batch_context->tracker` or NULL. Yes. | W1 |
| 16 | uvm_gpu_non_replayable_faults.c:274 | `clear_faulted_method_on_gpu` | Service tracker; `fault_service_tracker` gets `va_block->tracker` at :470-471. Yes. | W1 |
| 17 | uvm_migrate.c:763 | `semaphore_release_from_gpu` | Ioctl `release_after_tracker` (call at :1061-1065), which collects every GPU touched by the migrate. Yes. | W1 |
| 18 | uvm_map_external.c:230 | `copy_ptes` | Per-mapping `ext_gpu_map->tracker` or local (:393-407). No. | W1 |
| 19 | uvm_hmm.c:207 | `hmm_copy_devmem_page` | Fresh empty local tracker. No. | n/a |
| 20 | uvm_mmu.c:55-70 macro `page_tree_begin_acquire`. 14 uses: :715, :752, :992, :1167, :1204, :1270, :1492, :1668, :1967, :2006, :2123, :2176, :2583, :2643. | page tree | `&tree->tracker`, local, or NULL. No (tree is per GPU). | W1 |
| 21 | uvm_conf_computing.c:875, :920 | `uvm_conf_computing_util_memcopy_*` | CC-only. | Unreachable with CC off |

### 3b. Direct acquire outside the begin chokepoint

| # | Site | Function | Tracker | Coverage |
|---|---|---|---|---|
| 22 | S:uvm_migrate_pageable.c:816 [Q:825] | `uvm_migrate_vma_copy_pages_from` | `&zero_tracker`. The zero push runs on `dst_gpu` (:773-781) while the copy runs on `copying_gpu` = src GPU (:771 asserts this), so it is other-GPU by construction. Taken only when src and dst are both GPUs and (NVLink >= 5 or injected NVLink error), at :762-767. | Patched. Q:809-816 does the CPU wait before `migrate_vma_copy_begin_push` (Q:818). After success the tracker is empty, so Q:825 emits nothing. On error the tracker is cleared and the function returns at Q:812-815. |

### 3c. Existing CPU waits that carry cross-GPU dependencies (cannot create an acquire)

- uvm_pmm_gpu.c:575-582: `pmm_gpu_alloc` sanitises output trackers to PMM-GPU entries.
- uvm_pmm_gpu.c:523, :1188 and :2041, plus eviction: `uvm_va_block_evict_chunks` puts the whole `va_block->tracker` into the output at S:uvm_va_block.c:13486. It lands in `root_chunk->tracker` (uvm_pmm_gpu.c:704, :1188), and every consumer of that tracker is a CPU wait.
- uvm_mmu.c:2733-2734: `uvm_mmu_chunk_unmap` waits.
- uvm_va_block.c:9274, :9632, :9721: block destroy, GPU unregister, block kill.
- uvm_gpu.c:1660-1713 and :1761-1809: GPU teardown syncs trackers by CPU.
- uvm_migrate.c:1071, uvm_migrate_pageable.c:1022: ioctl and pageable state tracker.

### 3d. Pushes with no tracker input (no acquire possible)

- uvm_ats_faults.c:722
- uvm_gpu_access_counters.c:238, :280
- uvm_migrate_pageable.c:131, :173, :183
- uvm_mmu.c:2965, :2982, :3035 (:3035 is a test ioctl)
- uvm_channel.c:1793 and :2546 (non-CC)
- uvm_channel.c:1190, :1385, :1652, :3521, :3558, :3663, :3705, :3952 (CC-only)

### 3e. Non-acquire consumers of another GPU's semaphore pool (Q4)

- **Map existing pages on GPU add.** S:uvm_gpu.c:1144-1148 [Q:1148-1154], skipped by Q:1143-1146.
- **Unmap on GPU removal.** S:1157-1161 [Q:1163-1169], skipped by the guard at Q:1163.
- **Allocation-time map to all GPUs.** S:uvm_gpu_semaphore.c:180 [Q:180-188] now uses `uvm_rm_mem_alloc_and_map_cpu`.
- **CE or Host release or write to another GPU's semaphore.**
  - None found. `uvm_channel_end_push` releases only its own channel's semaphore (uvm_channel.c:1512-1513).
  - The user semaphore pool is host sysmem mapped per GPU through `uvm_mem` (uvm_va_range.c:1118-1123). It is not a tracking semaphore and is not touched by the patch.
- **RM dup path.**
  - `nvUvmInterfaceDupAllocation` is called only from `uvm_rm_mem_map_gpu` (uvm_rm_mem.c:326).
  - Production callers of that function: the pool map (skipped) and `uvm_rm_mem_map_all_gpus` (reached only through `uvm_rm_mem_alloc_and_map_all`, whose only production caller is the semaphore pool).
  - `uvm_pushbuffer.c:148` is CC-only, and its owner==gpu case returns early (uvm_rm_mem.c:317-318).

### 3f. Test-only

- **`uvm_tracker_test.c`:** `test_tracker_completion` (:59-142) allocates `sema` from the first GPU's pool (:80). It then loops over all VA-space GPUs (:88), takes the VA with `uvm_gpu_semaphore_get_gpu_va(&sema, gpu, …)` (:109) and issues a raw `semaphore_acquire` (:112). **Cross-GPU and unguarded** (F4). Reached via `UVM_TEST_TRACKER_SANITY` (uvm_test.c:264, tracker_test.c:437-448).
- **`uvm_gpu_semaphore_test.c`:** `test_alloc` (:179-196) asserts every semaphore has a nonzero VA on every VA-space GPU (:183-184). It fails with 2 or more GPUs in isolated mode (F4). Reached via `UVM_TEST_GPU_SEMAPHORE_SANITY` (uvm_test.c:258).
- **`uvm_channel_test.c`:**
  - The stress test (:792-793) is guarded upstream, and the guard's GPU comparison is correct.
  - `stress_test_all_gpus_in_va` and `test_ordering` use `uvm_rm_mem_alloc_and_map_all` (:69, :690, :697, :706), a separate cross-GPU RM dup.
- **`uvm_push_test.c`** (:546, :697), **`uvm_host_test.c`** (:183), **`uvm_channel_test.c`** (:1495): same-GPU acquires, which are fine.
- **Gate:** all test ioctls are gated by `uvm_enable_builtin_tests` (default 0, uvm_common.c:46-48; checked at uvm_test.c:245).

## 4. Findings

**F1. Complete census; the patch covers every production acquire.** Severity info; source-observation; high confidence.
- One sink. Two entry points. One direct caller. See sections 1 and 3.
- Grep over both trees finds no other production `semaphore_acquire` or `uvm_push_acquire_tracker` use.
- Production `_on_channel` begin-acquire callers: none.

**F2. The pageable fix is correctly placed, and the begin chokepoint is a load-time constant.** Severity info; source-observation; high confidence.
- The CPU wait precedes channel reservation, so it does not hold a reserved channel.
- Predicate stability: `module_param(…, bool, 0444)` at Q:45-46 and CC flag set once at uvm_global.c:123 make `allow()` constant after load.
- Tracker stability: all trackers passed to begin are caller-locked (block mutex, ISR service lock, tree lock, local), so nothing mutates them between W1 and the acquire at push.c:242.

**F3. With the parameter at its default (false) and with CC on, behavior is unchanged.** Severity info; inference by code equivalence; high confidence. The one exception is the new pageable wait, which also fires under CC.

**F4. Test-only cross-GPU semaphore users are uncovered.** Severity low for production, medium for any validation plan; source-observation; high confidence. The consequence is inference at medium confidence.
- `test_tracker_completion` acquires gpu1's semaphore on gpu2's channels. In isolated mode the VA is `index*4`, unmapped on gpu2. Expect an RC error or hang.
- `test_alloc` returns `NV_ERR_INVALID_STATE` with 2 or more GPUs. It allocates 4096 semaphores per GPU against 1024 per page, so some page has an index-0 semaphore whose unmapped VA is exactly 0. For non-zero indices the `!= 0` oracle cannot detect missing mappings at all.
- Both pass with one GPU. A multi-GPU run of the built-in UVM tests under the parameter will give misleading failures.

**F5. No runtime backstop in the shipped build configuration.** Severity medium; source-observation for the configuration; inference for the build and for hardware outcome; medium confidence.
- `UVM_ASSERT` and `UVM_ASSERT_MSG` are live only if `UVM_IS_DEBUG()` (uvm_common.h:165-171).
- `nvidia-uvm.Kbuild:5` sets `UVM_BUILD_TYPE = release`. `-DDEBUG` is added only for debug or develop (Kbuild:25-33).
- The build report's make command passes no override, so the compiled `.ko` most likely has the assertions removed. The build log was not supplied, so this is inference.
- Inert consequently: the push.c:98-99 assertion, the uvm_rm_mem.c:93 assertion, and the `semaphore_target_is_valid` assertions.
- A missed cross-GPU entry would emit an acquire at VA `index*4` in the pushing GPU's address space. HW behavior is unknown.
- Optional hardening, outside the patch's scope: a release assert (`uvm_release_asserts` defaults to 1, uvm_common.c:52) or an error return.

**F6. Behavioral change: many pushes now block on other GPUs' work.** Severity medium for latency and liveness; inference; medium confidence. No deadlock was found.
- **Replayable fault bottom half.**
  - It holds the per-parent `service_lock` (uvm_gpu_isr.c:598-632).
  - `push_replay_on_gpu` (uvm_gpu_replayable_faults.c:2856, :515) acquires the batch tracker, which holds `va_block->tracker` entries (:1636).
  - So it spin-waits for other GPUs' copies.
- **Async `UVM_MIGRATE` with a semaphore.**
  - `uvm_api_migrate` holds the VA-space read lock from :919 to :1083.
  - Its `semaphore_release` (:1061, then :763) now CPU-waits across GPUs, so the "async" ioctl blocks.
- **Eviction.** `uvm_va_block_evict_chunks` (S:13331) runs `make_resident` (:13440-13447) with the VA block lock held.
- **Error path.** Clearing the whole tracker on error (uvm_tracker.c:380-383) discards same-GPU ordering. It is only reached after a global fatal error.

**F7. The patched pageable branch is rarely reachable and unexercised.** Severity low; source-observation; high confidence. The zero branch needs GPU to GPU pageable migration with NVLink >= 5 or an injected NVLink error (:762-767). On PCIe or pre-Blackwell hardware `zero_tracker` is always empty, so the new wait is a no-op there.

**F8. SMC partitions count as "other GPUs".** Severity info; source-observation; medium confidence. `replay_tracker` is per parent (uvm_gpu_replayable_faults.c:361) but pushes can run on any partition (:546-554). In isolated mode that causes CPU waits on the same physical device, which costs time but is not incorrect.

**F9. The pristine pageable path has a latent CC defect that the patch fixes incidentally.** Severity info; inference; medium confidence. With CC on, S:816 would assert (debug) or acquire cross-GPU (release) whenever the zero branch runs. HMM and CC are mutually exclusive (uvm_hmm.c ~150-158), so this is hard to reach.

**F10. Stale comments.** Severity info; the comment at Q:uvm_push.c:66-68 still describes only CC.

**F11. Cross-check with the prior static report (`cross_provider_dup_allocation` blocker).** Severity info; source-observation; high confidence. In isolated mode, `init_semaphore_pools` no longer reaches `uvm_gpu_semaphore_pool_map_gpu`, which led to `uvm_rm_mem_map_gpu` and `nvUvmInterfaceDupAllocation`. Pool allocation no longer calls `map_all`. The out-of-tree `hybrid580_*` bridge is not in the supplied tree, so I cannot say how the bridge behaves.

**F12. The shipped Python tests are narrow.** Severity info; test evidence, static only. `test_r580_uvm_isolated_execution_patch.py` checks strings, patch application, and wait < begin < acquire ordering in `uvm_migrate_pageable.c`. It cannot detect a missed acquire elsewhere. The build report is compile-only.

## 5. Negative results

- **N1.** No raw semaphore-acquire method emission outside the three HAL host implementations (grep for `SEMAPHORED|SEM_EXECUTE|ACQ_GEQ|ACQ_CIRC_GEQ`).
- **N2.** No production caller of `uvm_push_begin_on_channel` or `uvm_push_begin_acquire_on_channel`.
- **N3.** `uvm_tools.c` has no `uvm_tracker_t`; its "trackers" are event trackers. `uvm_mem.c`, `uvm_pmm_sysmem.c`, `uvm_va_range_device_p2p.c`, `uvm_user_channel.c` and `uvm_va_space.c` create no pushes.
- **N4.** `uvm_channel.c` has no `uvm_tracker` usage. `uvm_ce_utils` does not exist in this tree.
- **N5.** Only 13 production files start pushes: ats_faults, channel, conf_computing, access_counters, non_replayable, replayable, hmm, map_external, migrate, migrate_pageable, mmu, push, va_block. All are in the table.
- **N6.** The PMM allocation tracker is sanitised to same-GPU entries (uvm_pmm_gpu.c:575-582). `uvm_pmm_test.c:139` asserts that property.
- **N7.** Page-tree trackers are per GPU, NULL or local. Access-counter clear and ATS TLB-invalidate pushes take no tracker.
- **N8.** There is no peer-address fallback for semaphores. `semaphore_target_is_valid` rejects peer addresses (uvm_maxwell_ce.c:53-61), though only inside an assert.
- **N9.** No production source of NULL-channel tracker entries was found (the only write is the error path at uvm_tracker.c:317, followed by a tracker clear). `uvm_tracker_entry_gpu` would crash on one.
- **N10.** Teardown does not rely on cross-mapped semaphores. `deinit_gpu` and block unregister only CPU-wait trackers. Pool free unmaps owner and CPU only in isolated mode (uvm_rm_mem.c:374-407).
- **N11.** CC-only paths are unreachable with CC off. Their sites: `uvm_conf_computing.c`, the CC branches in `uvm_va_block.c` :3417-3445, :13037-13048 and :13143-13153, and `uvm_channel.c` WLC/LCIC/SEC2.

## 6. Unknowns

- Hardware behavior of a Host semaphore acquire on an unmapped VA, and the RC or hang path (F4, F5). Unknown.
- Whether the build used release flags. Inferred from the Kbuild defaults; the build log was not supplied.
- Behavior of the hybrid bridge for sysmem allocation and CPU mapping on the second provider. Unknown.
- SR-IOV heavy (proxy VAs, which are also zero when unmapped), SMC liveness, and multi-GPU CC. Not analyzed in depth.
- Liveness and fault-latency cost of the new CPU waits under load (F6). Unknown.
- Data-plane cross-provider mappings such as peer or remote PTEs, external allocations (`uvm_map_external.c:909`, `uvm_va_range_device_p2p.c`) and shared managed memory. They are outside this census and left to the scope reviewer.

## 7. Next discriminating experiment (optional)

Run a debug-build (`UVM_BUILD_TYPE=debug`) patched module on 2 GPUs with the parameter set. Use a GPU A to CPU to GPU B migrate/map/unmap/evict workload and expect zero assertion failures at uvm_push.c:98 or uvm_rm_mem.c:93. Optionally load with `uvm_debug_enable_push_acquire_info=1` and check that recorded acquire `gpu_id`s (Q:uvm_push.c:111) always match the pushing GPU. Separately, run the two built-in tests with 1 GPU (expect pass) and 2 GPUs (expect F4 failure).
