# R580.178.04 IRQ source-mask and lifetime audit (static only)

Static Read/Grep/Glob audit of immutable `input/`. No build, load, hardware, PM, shell or network action.
`SRC/` = `input/build/experiments/private-open-hybrid-pm-v2-20261021/NVIDIA-kernel-module-source-580.178.04/`.
Evidence tags: **SP** source-proven (path:line), **RO** report-only (Ghidra/JSON summary, unverified here),
**INF** inference (incl. standard Linux kernel semantics not present in input), **UNK** opaque/unknown.

## 1. Decision summary
- **No device-specific GPU interrupt-source mask is visible before Linux IRQ registration, RM init, or deferred-queue init** on the PCI path (SP, by absence in `SRC/kernel-open/nvidia/nv.c:1321-1468`). Whether RM/hardware leaves sources disabled until `rm_init_adapter` is UNK.
- Registration (nv.c:1416/1423) precedes the `bottom_half_q` item/queue init (1447-1448), `isr_bh_unlocked_mutex` (1444) and `rm_init_adapter` (1468) (SP). This is an ordering window, **not a demonstrated race**: whether `nvidia_isr` can reach the 2918 producer in that window depends on opaque `rm_gpu_handle_mmu_faults`/RM state (UNK).
- The only source-visible device-source masks are **UVM-scoped HAL calls** (replayable faults, access counters); they are not whole-GPU masks and run only after UVM ISR init (SP/UNK HAL bodies).
- The CPU contract's central transition `mark_device_sources_masked` has **no provider operation** anywhere in input (SP by absence). The contract cannot currently be bound to R580; `drain_irqs` must stay fail-closed (it is absent from input; its current `-EOPNOTSUPP` behaviour is RO only).
- Strongest source-visible hazard is PM, not open: the handler stays registered while `bottom_half_q` is stopped (nv.c:6560) and later re-`memset` on resume (6569-6572) (SP ordering). Whether it fires there is UNK. No runtime race or safety is claimed.

## 2. Exact registration ordering — `nv_open_device` (nv.c:1599) → `nv_start_device` (nv.c:1654, only if `!NV_FLAG_OPEN` 1642)
| nv.c line | Step | Note |
|---|---|---|
| 1332, 1353/1362 | rsync, `rm_ref_dynamic_power` | RM power ref, body UNK; not a mask |
| 1372 | `nv_dev_alloc_stacks` | ISR stacks (`sp[NV_DEV_STACK_ISR]`) exist before registration |
| 1382-1392 | registry read, `rm_is_msix_allowed`, `nv_init_msix` / `nv_init_msi` | PCI MSI(-X) capability enable, not a source mask |
| 1398-1405 | fail if no interrupt type available | |
| 1412 / 1416-1418 / 1423 | SoC `nv_soc_register_irqs`; legacy/MSI `request_threaded_irq(nvidia_isr, nvidia_isr_kthread_bh)`; MSI-X `nv_request_msix_irq` | **Linux handler live from here** |
| 1444 | `os_alloc_mutex(isr_bh_unlocked_mutex)` | after registration |
| 1447 / 1448 | `nv_kthread_q_item_init(bottom_half_q_item)` / `nv_kthread_q_init(bottom_half_q)` | after registration |
| 1453-1456, 1460 | `nv_queue` init, `nv->queue` set; optional NUMA queue | after registration |
| 1468 | `rm_init_adapter` | first RM adapter init (UNK body) |
| 1483, 1493, 1504 | UVM start notify, `NV_FLAG_OPEN`, FINE unref | |
All steps 1408-1466 are skipped under `NV_FLAG_PERSISTENT_SW_STATE` (IRQ/queues persist across close) (SP 1408, 1442).
Legacy IRQ is `IRQF_SHARED`; MSI/MSI-X flags are 0; no `IRQF_ONESHOT` on PCI paths (SP `SRC/kernel-open/common/inc/nv-linux.h:1698-1711`).

Unwind (SP): `failed_release_irq` (1508-1526; from 1446/1450/1455/1463/1474) frees legacy IRQ (1514) / SoC (1518) / MSI-X (1523), then `failed` (1528-1592) disables MSI/MSI-X and frees arrays (1530-1543), frees `msix_bh_mutex` (1545), stops `nv_queue` (1555), `bottom_half_q` (1559), NUMA q (1564), frees mutex (1567), FLR (1573), stacks (1583). On `rm_init_adapter` failure IRQs are freed **without** `rm_disable_adapter`/`rm_shutdown_adapter` (SP by absence 1508-1593); RM partial-init state at free time is UNK.

## 3. Mask / line-control inventory (complete-input grep: mask, unmask, disable_irq, enable_irq, synchronize_irq, free_irq, intr)
| Site | Operation | Class |
|---|---|---|
| nv.c:1416, 1514, 1967; `SRC/kernel-open/nvidia/nv-msi.c:152,159` | request/free_irq | Linux IRQ line (registration) |
| nv.c:1533/1970, 1540/1983; nv-msi.c:33,113 | MSI/MSI-X enable/disable | PCI delivery config, not a GPU source mask |
| nv.c:7765-7798 `nv_control_soc_irqs` | enable_irq / disable_irq_nosync | SoC/platform Linux line control |
| `SRC/kernel-open/nvidia/nv-platform.c:113,135,68,172` | disable/enable_irq in SoC ISR/BH/request | SoC/platform Linux line control |
| `SRC/kernel-open/nvidia/nv-gpio.c:256` | disable_irq_nosync after GPIO request | GPIO Linux line control |
| `SRC/kernel-open/nvidia-uvm/uvm_gpu_isr.c:880-898` | `fault_buffer_hal->disable/enable_replayable_faults` | **UVM device-source mask** (HAL body UNK) |
| uvm_gpu_isr.c:900-935 | `access_counter_buffer_hal->disable/enable_access_counter_notifications` | **UVM device-source mask** (HAL body UNK) |
| uvm_gpu_isr.c:125-155 | non-replayable: no HW disable, schedule only | UVM software (no mask) |
| `rm_isr`, `rm_init_adapter`, `rm_disable_adapter`, `rm_power_management` | possible internal masking | UNK (binary RM) |
| — | `synchronize_irq` | **zero source hits** in input (SP); appears only in JSON prose |
| — | PCI main-GPU source mask in wrapper | **none found** (SP by absence) |
| — | RM software shadow | none visible (UNK) |
`disable_irq*`/`free_irq`/`synchronize_irq` are treated as line controls only, never GPU source masking.
SoC detail (SP): `nv_request_soc_irq` registers then calls `disable_irq_nosync` (nv-platform.c:164-172), leaving a short window where the line is enabled; GPIO path calls `disable_irq_nosync` a second time (nv-gpio.c:256) while `ref_count` is set to 0 once (nv-platform.c:186). INF (kernel disable-depth semantics): one `enable_irq` from `nv_control_soc_irqs` may not re-enable a GPIO line disabled twice. SoC/GPIO is out of the PCI-GPU scope.

## 4. ISR / thread / bottom-half graph (SP unless tagged)
```
legacy/MSI line --> nvidia_isr (nv.c:2809)
MSI-X vector i  --> nvidia_isr_msix (2780, msix_isr_lock 2795) --> nvidia_isr
SoC line        --> nvidia_soc_isr (nv-platform.c:77, soc_isr_lock, disables lines 113) --> nvidia_isr (117)
nvidia_isr:
  rm_gpu_handle_mmu_faults(sp[ISR])           2824  (RO: indirect HAL dispatch)
  nv_uvm_event_interrupt -> uvm_isr_top_half  2841  (uvm_gpu_isr.c:218; NULL uuid -> NO_INTR 236-240)
       -> UVM bottom_half_q producers: uvm_gpu_isr.c:115, 145, 188 (+kill_channel_q)
  rm_isr(sp[ISR])                              2845  (RO: state check + 2 internal routines)
  need_bh  -> IRQ_WAKE_THREAD                 2908 -> nvidia_isr_kthread_bh (2925) | nvidia_isr_msix_kthread_bh
              (2934, msix_bh_mutex 2948) -> nvidia_isr_common_bh (2960) -> rm_isr_bh(sp[ISR_BH]) 2976
  else if mmu faults -> nv_kthread_q_schedule_q_item(bottom_half_q) 2918
              -> nvidia_isr_bh_unlocked (2983, isr_bh_unlocked_mutex 2996) -> rm_isr_bh_unlocked 3014
```
Other nv.c queue producers are process-context only: `open_q` (1915), `nv_deferred_close_kthread_q` (2239). nv.c:2918 is the only hard-IRQ producer into an nv.c queue.
Queue semantics (`SRC/kernel-open/nvidia/nv-kthread-q.c`): `schedule` rejects with WARN if `main_loop_should_exit` (282-289) but the check is not under `q_lock` (252-270); `stop` returns early if `q_kthread==NULL` (122), flushes, then sets exit (125-141); `flush` after stop WARNs and returns (318-321); `init` `memset`s the queue (217). INF: a producer racing `stop` past the 285 check can enqueue onto a stopping queue (also flagged RO in `r580-pm-entrypoint-lifetime-v5` `source_exposes_post_flush_enqueue_window`).
API contract (SP `SRC/kernel-open/common/inc/nv-kthread-q.h`): queue "must not be used before" init (90); "Do not add any more items ... after calling nv_kthread_q_stop" (137); schedule "returns false if ... not yet started up" (197), but the code only checks `main_loop_should_exit` (nv-kthread-q.c:285), so a zeroed queue is not detected. nv.c's ordering leaves 2918 able to violate 90/137 if reached (reachability UNK).
Pre-init producer (INF): before 1447 the zeroed q_item makes `_raw_q_schedule` no-op (list_empty false) only if `nvl` is zero-allocated (allocation not in input, UNK); between 1447 and 1448 an enqueue would touch an uninitialised list head.

## 5. Shutdown, PM and recovery ordering (SP)
- Last close: `nv_close_device` (2091) → `nv_stop_device` (2020): UVM stop notify (2039); persistent → `rm_disable_adapter` only (2048, IRQ stays registered); else `nv_shutdown_adapter` (2053).
- `nv_shutdown_adapter` (1943-2014): `rm_disable_adapter` 1947 → stop `bottom_half_q` 1950 → stop `nv_queue` 1955 → free `isr_bh_unlocked_mutex` 1958-1962 → `free_irq`/MSI disable 1967-1973 | SoC 1977 | `nv_free_msix_irq`+`pci_disable_msix` 1982-1986 → free `msix_bh_mutex` 1990 → `rm_shutdown_adapter` 1996. Also called from platform remove nv-platform.c:1259.
- Window: handler still registered after `bottom_half_q` stop and mutex free; a late 2918 call hits the WARN/return-0 path (nv-kthread-q.c:285) rather than a freed queue (SP); whether RM still reports faults after `rm_disable_adapter` is UNK.
- PM suspend (nv.c:6543-6563): flush `open_q` → `rm_power_management` → stop `bottom_half_q`; no IRQ free/synchronize. Resume (6565-6577): item re-init + queue `memset`/init **while the IRQ is registered**, then `rm_power_management` (INF: safe only if RM keeps sources quiet across that interval; UNK).
- UVM: `uvm_parent_gpu_disable_isr` (uvm_gpu_isr.c:463-498) masks replayable faults, clears `handling` under `interrupts_lock`, then stops UVM queues; called at `SRC/kernel-open/nvidia-uvm/uvm_gpu.c:2755`, flush at 2757; init at uvm_gpu.c:1517. Suspend gate `isr.is_suspended` (`uvm_global.c:267`) makes top-half scheduling return 0 (uvm_gpu_isr.c:90,125,169). `uvm_suspend` source comment states "GPU interrupts are enabled" on entry and new bottom halves may be scheduled (uvm_global.c:278-286), so UVM relies on its software gate + flush (330-335), not a GPU-wide mask (SP text; behaviour INF).

## 6. MSI-X partial setup and rollback (SP, `nv-msi.c`)
- `nv_init_msix` (67-139) failure label frees `msix_entries`, `irq_count`, `msix_bh_mutex` and clears the flag (120-138) but does not NULL the two array pointers (`NV_KFREE` is plain `kfree`, nv-linux.h:483-486). INF: stale pointers are not dereferenced on later paths because use is gated by `NV_FLAG_USES_MSI(X)`; `nv_init_msi` overwrites `irq_count` when it runs.
- `nv_pci_enable_msix`, `nv_get_max_irq`, `nv_free_msix_irq` bodies are not in input (UNK); `num_intr` is set only there (INF).
- `nv_request_msix_irq` (141-166): on failure of vector *i*, frees vectors 0..i-1 (157-160) and returns rc; caller jumps to `failed` (nv.c:1439), which disables MSI-X and frees arrays (1537-1543). No queue/thread exists yet. Rollback is source-complete for acquired vectors (SP); `free_irq` waiting for in-flight handlers is kernel semantics (INF).
- `nv_init_msi` (28-65): if `irq_count` alloc fails, flag is cleared but MSI is **not** disabled and `interrupt_line` already holds the MSI vector (36-47); registration then uses legacy `IRQF_SHARED` flags on an MSI vector (SP oddity, consequence INF).

## 7. Current CPU-contract mapping (`input/src/hybrid580_irq_lifecycle_contract.h`)
| Contract transition (line) | R580 provider operation | Status |
|---|---|---|
| `init` (85) | — | model only |
| `mark_device_sources_masked` (117) | none in nv.c/provider; R580 never masks before 1416 | **UNSUPPORTED** |
| `register_vector` (131), `activate` (151) | request_threaded_irq nv.c:1416 / nv-msi.c:152 | operation exists, but its precondition (masked) is unmet |
| `unmask_device_sources` (163) | none (maybe inside `rm_init_adapter`, UNK) | **UNPROVEN** |
| `handler_enter/exit` (184/219) | Linux invokes handler unconditionally; no admission gate in nvidia_isr | model gate has no provider counterpart |
| `queue_from_handler` (201) | nv.c:2918 (+UVM 115/145/188, IRQ thread 2908) | partial: one counter models ≥3 distinct deferred paths |
| `begin_quiesce` (230) owner arbitration | `nv_linux_devices_lock`/`ldata_lock` in provider (`input/src/hybrid580_pm_provider_kernel.h:60,84`) | **UNPROVEN** as single owner gate (RO: PCI remove bypasses `nv_system_pm_lock`) |
| `synchronize_vector` (259) | no `synchronize_irq` in input | **UNSUPPORTED** |
| `flush_queue_begin/complete` (294/337) | `nv_kthread_q_flush/stop` exist (nv-kthread-q.c:119,316) but provider never calls them | **UNSUPPORTED** in provider |
| `abort_registration` (246) | nv-msi.c:157-160 / nv.c:1508 free IRQs **without** a mask step | model precondition unmet |
| `resume_begin/open_gate` (365/377) | `nvidia_resume` called by provider (provider.h:229) → nv.c:6565 | partial; source mask state UNK |
| `release_vector`, `shutdown_complete` (388/411) | free_irq nv.c:1967 / `nv_free_msix_irq` 1982 | exists in driver, not in provider |
| `drain_irqs` | not present in input; RO `r580-pm-irq-lifetime-audit-v1` says frontend returns `-EOPNOTSUPP` (`src/hybrid_frontend.c`, not supplied) | **fail-closed (RO)**; keep |
The provider header exposes only recovery records, `nv_preempt_user_channels`/`nv_restore_user_channels` (provider.h:388,444), `nvidia_resume` and UVM suspend/resume (476-521); no IRQ op (SP by absence). Both 0035 patches only hook PM callbacks and UVM registered suspend/resume (SP). The contract test (`input/tests/...`) was not executed here.

## 8. Adversarial review and resolution
**A. "Current R580 ordering is a real race" — challenged.** Source ordering alone (1416 before 1448/1468) proves a *window*, not a race. Countervailing (UNK) possibilities: RM/hardware may keep all GPU interrupt enables cleared until `rm_init_adapter`; `rm_isr` "checks RM state" (RO) and may return not-handled; UVM top half returns early on NULL uuid (uvm_gpu_isr.c:236-240, SP). The 2918 producer also requires `rm_serviceable_fault_cnt != 0` (2824-2825), which is opaque. Pre-1447 a zeroed item no-ops in `_raw_q_schedule` (INF, needs zeroed `nvl`). **Resolution:** classify as *unproven ordering hazard*, not a defect.
**B. "It is safe because the registered handler appears quiescent" — challenged.** (i) Legacy line is `IRQF_SHARED` (nv-linux.h:1707-1708): any co-tenant device interrupt runs `nvidia_isr` → RM calls with no wrapper-level readiness gate (SP 2809-2846). (ii) No wrapper check of `NV_FLAG_OPEN`/queue readiness before 2918 (SP). (iii) Stop-before-free in shutdown (1950 vs 1967) and PM (6560, IRQ never freed) leaves the handler live after the queue API forbids new items (nv-kthread-q.h:137). (iv) `schedule` exit check is lock-free relative to `stop` (nv-kthread-q.c:285 vs 135; RO v5 agrees). (v) Resume re-`memset`s `bottom_half_q` while the IRQ is registered (6572). (vi) `free_irq` waiting for in-flight handlers is Linux semantics, not in input (INF). **Resolution:** safety is *unproven*; quiescence depends entirely on opaque RM masking.
**C. Distinctions enforced:** GPU interrupt source (RM/HAL register state, UNK) ≠ Linux IRQ line (request/free/disable_irq, SP) ≠ threaded handler (IRQ_WAKE_THREAD 2908 → `rm_isr_bh`) ≠ nv.c `bottom_half_q` (2918 → `rm_isr_bh_unlocked`) ≠ UVM IRQ path (`nv_uvm_event_interrupt` → UVM `bottom_half_q`/`kill_channel_q`, own `interrupts_lock`, own HAL masks). The contract's single `deferred_pending` counter collapses at least four of these (§7).
**D. Contract-model gaps (SP from header text):** handler admission (`handler_enter` 189-191) is a model gate the real handler cannot enforce; `abort_registration` (249-251) requires a masked state R580 never produces; `begin_quiesce` requires `!device_sources_masked` (237) so masking must be an external provider action that does not exist; the fixture (`tests/fixtures/...:96-130`) exercises the model only and was not run here.
**E. Red-team counterexamples adopted (re-checked by main agent with Read):**
- *Persistent mode* (SP): last close with `NV_FLAG_PERSISTENT_SW_STATE` runs only `rm_disable_adapter` (nv.c:2046-2049); next open skips registration (1408) and runs `rm_init_adapter` (1468) **with the IRQ already live**. This weakens the "race" claim for that flow (INF: the driver appears to rely on RM tolerating a live handler during init) and shows the contract's LAST_CLOSE→DEAD path does not exist in that mode. RO `r580-pm-irq-lifetime-audit-v1` "close-teardown-owns-irq-lifetime" omits this (overstated).
- *Static lock cycle* (SP code order, occurrence UNK): `nvidia_suspend` holds `ldata_lock` (nv.c:6718) across `nv_power_management` (6750) → `nv_kthread_q_flush(open_q)` (6556); queued `nvidia_open_deferred` does `down(ldata_lock)` (1743). An item queued when `down_trylock` fails on an OPEN device (1776, 1790-1793; needs `NVreg_EnableNonblockingOpen`) could block the flush. Any future drain must not flush queues under `ldata_lock`.
- *Deferred open escapes the flush* (SP): `nvidia_suspend` returns early for non-OPEN, non-persistent devices (6720-6724) before the 6556 flush, so a pending deferred open can still run `nv_start_device` (IRQ registration + RM init) during PM; RO v5 `native_suspend_flushes_deferred_opens_before_rm: true` is overstated.
- *Second UVM entry* (SP definition; caller context INF): `nv_schedule_uvm_isr` (nv.c:1292-1298, `NV_API_CALL`, i.e. RM-callable) also invokes `nv_uvm_event_interrupt`, a second entry into the UVM top half besides nv.c:2841. Its RM callers are not in input.
- *UVM gaps* (SP): non-replayable faults have no UVM source mask (uvm_gpu_isr.c:121-155); the replayable source is re-enabled from the bottom half whenever `handling` is true (782-800), independent of `is_suspended`; `uvm_global.c:320` TODO (non-replayable flush) is an admitted gap.
- *SoC* (SP): `nv_soc_register_irqs` returns early when `nv->request_firmware` ("OpenRM", nv-platform.c:264-266); a dpaux failure at index > 0 frees display/hdacodec/tcpc2disp but not earlier dpaux IRQs (313-323); `nv_control_soc_irqs` reads `current_soc_irq` before taking `soc_isr_lock` and silently returns (nv.c:7771 vs 7774).
- *Contract coverage* (SP): no MSI mode (single non-shared vector; `init` 93-95 allows only SHARED_LEGACY or MSIX); the threaded phase after `IRQ_WAKE_THREAD` is not in `active_handlers`; the queue stop-and-recreate at PM (6560/6569-6572) is not modelled; the fixture's pthread test (183-219) proves arbitration only under the caller-owned mutex the header requires (contract.h:9).
- *Downgraded/not adopted:* red-team's "possible `kill_channel_q` flush hang" (uvm_gpu_isr.c:460 vs uvm_global.c:334) stays INF; "provider unref without ref" around channel preempt/restore (nv.c:6606/6646) is PM-channel scope, so it is noted but not IRQ evidence; the proprietary patch's unused statics and the header filename mismatch (hyphen vs underscore) are build-hygiene notes, INF.
- **Joint resolution:** both agents and the main agent agree. Neither "unsafe" nor "safe" is established. The missing provider-level source mask plus in-flight/threaded completion is the blocker, and the PM path (handler live across queue stop/re-init) is a stronger hazard than the open-time window.

## 9. Static wrapper facts vs. the two bounded Ghidra reports (RO = decompilation summary, not source)
- `rea-private-r580-isr-order-v1`: `rm_isr` "checks RM state" and calls internal routines; `rm_gpu_handle_mmu_faults` dispatches via unresolved indirect HAL entries; the observed bookkeeping spinlock does not span the HAL callback; `rm_isr_bh` → `_nv000801rm` with IRQ-type-dependent indirect callbacks (RO). Consistent with SP wrapper order at nv.c:2824-2846, 2976. It does **not** show whether `rm_isr` returns not-handled before `rm_init_adapter` (UNK).
- `rea-private-r580-rm-disable-quiescence-v1`: `rm_disable_adapter` flushes RM work queue twice, has no recovered direct Linux IRQ sync, and does not establish masking of every PCI source or joining an in-flight ISR (RO). Consistent with SP order nv.c:1947 (disable) before 1967 (free_irq). Its `os-interface.c` citation is not in input (unverifiable here).
- Both reports target `nv-kernel.o_binary` sha256 `5269a23f…6f4b` (not supplied); their logs are not supplied. Neither claims a runtime result; neither is used here as proof of masking or of safety.
- `r580-pm-irq-lifetime-audit-v1` and `r580-pm-entrypoint-lifetime-v5` are source-audit summaries; claims about `nv-pci.c`, `nv-procfs.c`, `os-interface.c`, `src/hybrid_frontend.c` and test logs cite files absent from input → RO only. Their nv.c/nv-msi.c/nv-kthread-q.c line claims that I re-checked (2906-2921, 1943-1987, 1377-1494, 252/282/119) match source (SP).

## 10. Specific unknowns (blockers)
1. RM interrupt-enable state between `nv_init_msi(x)`/`request_threaded_irq` (nv.c:1387-1423) and `rm_init_adapter` return (1468): indirect RM callbacks, runtime HAL selection (Volta vs other), device register reset defaults.
2. Whether `rm_gpu_handle_mmu_faults` can return `rm_serviceable_fault_cnt != 0` before RM init, i.e. whether nv.c:2918 is reachable before 1448 (and between 1950 and 1967).
3. Whether `rm_disable_adapter` / `rm_power_management(STANDBY)` disables GPU interrupt sources in hardware, and whether either waits for an in-flight `nvidia_isr` / IRQ thread (Linux `free_irq`/`synchronize_irq` semantics are INF, not in input).
4. Bodies of `nv_pci_enable_msix`, `nv_free_msix_irq`, `nv_get_max_irq`, `nv_uvm_event_interrupt`, PCI probe/remove (`nv-pci.c`), `nvl` allocation (zeroing), UVM HAL `disable_replayable_faults` etc. — not in input.
5. Shared legacy line: any other device's interrupt invokes `nvidia_isr` → RM calls while uninitialised; RM tolerance is UNK.

## 11. Next discriminating test (smallest safe; described only, not performed)
**Static first (no hardware):** in the pinned `nv-kernel.o_binary` (same SHA as RO reports), resolve the indirect HAL targets reachable from `rm_isr` and `rm_gpu_handle_mmu_faults` when the RM "initialized" state check fails, and the GPU-interrupt-enable writes reachable from `rm_init_adapter`, `rm_disable_adapter`, `rm_power_management`. Discriminates H1 "RM keeps all GPU sources disabled / ISR returns early outside init window" vs H2 "sources may be live and 2918 reachable pre-1448". Falsifier for H1: an enable write ordered before the RM-ready state flag, or a fault-count path not gated by state. Prerequisite: lawful local binary access; risk: decompiler error, HAL selection unresolved statically.
**Dynamic only if static is inconclusive:** on a disposable, isolated test host with a single non-production GPU, read-only tracing (ftrace/kprobe counters, no writes to device) of `nvidia_isr` entry, `nv_kthread_q_schedule_q_item` return value and `rm_init_adapter`/`nv_shutdown_adapter` boundaries over repeated open/close. Prediction H2: `nvidia_isr` hits before `rm_init_adapter` returns or a schedule WARN at nv-kthread-q.c:286. Absence does **not** prove H1 (no interrupt may have been pending). Prerequisites: explicit owner authorization, out-of-band console, rollback plan; risks: hang/oops of the test host, kernel taint. Not authorized by this task.

## 12. Inputs (SHA-256 and bytes from `input/MANIFEST.txt:8-27`; content of each checked with Read)
| SHA-256 | Bytes | Path (`input/` + MANIFEST relative path) |
|---|---|---|
| 3fddec7956bd263ac1d238a82861894c93cd9ca904067b770cca5a7beec2631a | 229287 | SRC/kernel-open/nvidia/nv.c |
| 444917fc7855970c64c6d3f81e2ba71a7a2f062add6e24f27e6e24ca97b3a913 | 4982 | SRC/kernel-open/nvidia/nv-msi.c |
| 13222c7db5bd1e57c5d36d0125d4cca4da1d288e5e52ac679f005668bc2e6274 | 11520 | SRC/kernel-open/nvidia/nv-kthread-q.c |
| db869854b2628d477833a56b3fc91f10750a546d40ca4ce3281734e684398979 | 46699 | SRC/kernel-open/nvidia/nv-platform.c |
| fcd3c55fc28d4d44a6f4cd6495f56a8e7589319454bddc09adfb0f75a1aff4bf | 6782 | SRC/kernel-open/nvidia/nv-gpio.c |
| b2f28c6acac451b1673bb1dc3b9712d888a51c80b4ffbd03109871cd54965019 | 61386 | SRC/kernel-open/common/inc/nv-linux.h |
| 24b46d1c3b2c1e02a524de058ba0a2d4b999bb41b8396014faf23bff03a2d364 | 8960 | SRC/kernel-open/common/inc/nv-kthread-q.h |
| 456ee47bb83564cc1ada830538781256bb246bf82888601d3c3f2b3a2bc777f5 | 40263 | SRC/kernel-open/nvidia-uvm/uvm_gpu_isr.c |
| b43bb94bbc465bbb4fb243e6f722cb450d6402f3071971843d61f1f7678bf700 | 151186 | SRC/kernel-open/nvidia-uvm/uvm_gpu.c |
| aeee2f257a289853f36d9c7b196f1e02d19b84695db44cdd2e00f28b0f1a4489 | 18035 | SRC/kernel-open/nvidia-uvm/uvm_global.c |
| 709c02b1c08271999140fbc9f44dcfe51d24008a0a6447883b1b8468db293c66 | 13684 | src/hybrid580_irq_lifecycle_contract.h |
| e31d07cd40e96304eee1a8b65475b85f7c216d61ead7b708355364a9852e7bcd | 10374 | tests/fixtures/hybrid580_irq_lifecycle_contract_test.c |
| 78e079d768a0db1881ce4e1cbbc5fba2ad71c309a0fcedc5766f6a944f4816a0 | 1227 | tests/test_hybrid580_irq_lifecycle_contract.py |
| 5fa0d8ecde9a48852b24b137003d14b91a1afed0bdcffe7d151a3af664e99d90 | 15130 | src/hybrid580_pm_provider_kernel.h |
| 060f6ff65802ff691ec59d9ea39b88b5a65b28498b825efd57fa46d09835091f | 2763 | patches/r580.178.04/0035-private-open-pm-recovery-provider.patch |
| 7ac552341f5d9ab4287c638abe6ea8a12696100657bcbbad0a8c179d632d63e0 | 2036 | patches/r580.178.04/proprietary/0035-private-legacy-pm-recovery-provider.patch |
| b6f70ea20c5d2bc7f4f7b86b0e94f3b52c4ec164b01bd87cf5fd7481a56059d7 | 5899 | evidence/rea-private-r580-isr-order-v1-20261022.json |
| d64a35bdcfcc74995bb5d31ae076d6abdc45fe76cc91df2e503f1a1eec623d74 | 4166 | evidence/rea-private-r580-rm-disable-quiescence-v1-20261022.json |
| f919e93566f2387c5849253053cd60f5722ad38b6a4f08157ad14ca38a7946c6 | 8405 | evidence/r580-pm-irq-lifetime-audit-v1-20261022.json |
| fe11a76d316e9a615543014d6056b7bf91ba6169cc203810c35351721d0bb49c | 11248 | evidence/r580-pm-entrypoint-lifetime-v5-20261022.json |
Hashes are quoted from the manifest, not recomputed (no shell per TASK.md); uvm_gpu.c and uvm_global.c were read in the cited ranges only.

## 13. Subagents (spawned in parallel, Read/Grep/Glob only)
| Name | Model | Completed | Reconciliation |
|---|---|---|---|
| `irq-startup-mapper` | sonnet | yes | Agrees on all ordering/unwind lines (§2, §5, §6); its extra SP findings adopted: `nv_init_msi` leaves MSI enabled on counter-alloc failure (nv-msi.c:41-47), `rm_init_adapter` failure path frees IRQs without RM shutdown (nv.c:1474→1508), `nv_shutdown_adapter` also reached from nv-platform.c:1259, `synchronize_irq` has zero source hits, `nv_pci_enable_msix`/`nv_free_msix_irq` bodies absent. Its "ISR can run before queue exists" is downgraded here to reachability-UNK (§8A). Its dynamic test was narrowed to read-only tracing (§11). |
| `irq-lifetime-red-team` | sonnet | yes (finished after the 8th loop iteration) | Agrees with §1, §7 (every contract transition UNSUPPORTED/UNPROVEN; `drain_irqs` absent from input, fail-closed only RO). Counterexamples verified and adopted in §8E; flagged report overstatements recorded in §8E/§9. Its CPU-only harness test (real `nv-kthread-q.c` vs concurrent init/stop) is a valid hardware-free complement to §11, but it needs compilation, which is outside this task. |
Both reports were reconciled against source by the main agent. Where the agents conflicted, or where a claim had no supporting line, the weaker tag is used.
