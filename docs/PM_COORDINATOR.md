# Dual-provider system power management

Updated: 2026-10-21. Scope: design and source audit for coordinating the private
R580 Open and proprietary providers through one frontend. This document does
not certify a loaded module or a hardware suspend cycle.

## Current provider-result, channel and shared-UVM primitives (2026-10-21)

Both compiled R580 providers now contain a generation-scoped, per-GPU DPM
result table protected by `nv_linux_devices_lock`. The private Open provider
exports `hybrid580_open_pm_recovery_begin_v1`,
`hybrid580_open_pm_recovery_recover_v1`, and
`hybrid580_open_pm_recovery_end_v1`; the proprietary provider exports the same
operations under the `hybrid580_legacy_` prefix. DPM wrappers record whether
Linux called resume, restore, or thaw, and retain the first callback failure.
The R580 thaw callback remains a no-op; the explicit recovery query performs
the provider's `nvidia_resume()` fallback only when the GPU suspend count is
zero, then verifies `NV_FLAG_SUSPENDED` and `suspend_count` are clear. Missing
device state and fallback failure are reported as errors. This primitive is
compiled and source-tested; no frontend invokes it yet.

The CPU coordinator tracks which providers were armed and calls their end
operation in reverse order. It retires both records after checking both
providers, before resuming shared UVM; a matching post notifier also retires
records if DPM aborts before the aggregate recovery callback. Any end failure
keeps frontend admission quarantined. When one provider's recovery check fails,
the model still checks the other and then fails closed. These changes are
covered by the C/UBSan model and source contracts. They do not register Linux
notifiers or the aggregate DPM consumer, and do not prove device-link order at
runtime.

The Open provider also exposes one shared-UVM suspend/resume pair. Its checked
entrypoints take the existing callback-registration semaphore and return
`NV_ERR_NOT_SUPPORTED` when UVM has not registered the requested callback;
this is necessary because stock `nv_uvm_suspend()` and `nv_uvm_resume()` report
`NV_OK` when no callback is present. The wrapper state prevents duplicate
suspend, permits retry after callback failure, and retains suspended state
until a successful resume. Only Open exports these entrypoints, so the frontend
has one route to the shared callback table even though the bridge registers
that table in both RMs. Neither the frontend nor Linux PM invokes this API yet.
The C/UBSan test exercises the state contract; a source contract checks the
registration test and single-owner patch.

Both private providers now also export generation-scoped
`pm_channels_suspend_v1()` and `pm_channels_resume_v1()` APIs. These call only
the existing channel preempt/restart helpers; GPU power and NVKMS remain with
the per-device PCI DPM callbacks. A per-GPU latch is set before preemption,
retained if restart fails, and cleared only after that GPU restarts
successfully. DPM recovery results can be retired before UVM resumes while
the separate channel generation stays active until channel restore finishes;
a new recovery cycle is rejected while old channel state remains. The CPU coordinator records a backend as
attempted before invoking suspend and calls restore for that backend even when
its suspend callback returns an error. This lets rollback recover a partially
quiesced provider without restarting GPUs already restored successfully.

Current corrected channel-API builds: [Open report](../evidence/private-open-pm-channel-api-v2-20261021.json)
has 134 exports and 435 resolved imports; [proprietary report](../evidence/private-proprietary-pm-channel-api-v2-20261021.json)
has 138 exports, 303 imports and zero GPL-only imports. Both remain
`loaded_or_installed=false` and `hardware_validated=false`; full module hashes
are recorded in `docs/STATE.md` and `docs/VALIDATION.md`. The v1 modules are
superseded: their first lifecycle model coupled channel state to DPM recovery
retirement and did not preserve the valid DPM-recovery, UVM-resume, then
channel-restore order.

## Frontend admission primitive (2026-10-21; not PM-wired)

`src/hybrid580_frontend_admission.h` now provides a serialized blocked/active
state used by `hybrid580_frontend.ko`. Open, ioctl, and final release hold an
active reference for their full frontend operation; sleepable entries wait
freezably while the gate is closed. Release uses an uninterruptible but
freezable wait because VFS ignores a release error and abandoning final cleanup
would leak frontend/backend ownership. `.mmap` uses try-enter and fails with
`-EAGAIN` while blocked, avoiding a sleep in a callback made under mmap
locking. `.poll` registers the gate waitqueue and returns no readiness while
blocked so unblock can trigger a fresh readiness check. The block, drain and
unblock helpers are currently `__maybe_unused`; no PM path calls them. The
frontend also has static callback adapters for both provider recovery/channel
APIs and the single Open shared-UVM owner. Those callbacks are retained with
`__used` so the compiled module resolves their private imports, but none is
registered with a Linux notifier or DPM device. Provider routing, recovery
event mapping, single-owner UVM dispatch, callback order, and rollback are
covered by CPU contract tests. Build
[`frontend-system-pm-adapter-v3`](../evidence/frontend-system-pm-adapter-v3-20261021.json)
contains 283 imports including all 221 expected provider imports, with no
unresolved or duplicate symbols. The full suite passed 624 tests; hashes are
recorded in [`STATE.md`](STATE.md) and [`VALIDATION.md`](VALIDATION.md).

The C/UBSan contract and frontend source model cover operation draining,
sleeping entrants across block/unblock, mmap rejection, poll wake registration,
and file-operation wiring. Build [`frontend-pm-admission-v3`](../evidence/frontend-pm-admission-v3-20261021.json)
resolves all 271 imports (209 private backend imports), has no unresolved or
duplicate symbols, and reports active objtool with no objtool/naked-return
warnings. Full verification passed 620 tests; hashes and limitations are in
[`docs/STATE.md`](STATE.md) and [`docs/VALIDATION.md`](VALIDATION.md).

This gate does not yet cover the frontend's exported UVM entrypoints or prove
that native provider faults, VMA callbacks, or workers are drained at system
PM time. The provider API imports and static adapters exist, but remain
unreachable because no Linux consumer is registered. Before PM wiring, classify
every externally callable frontend/UVM entry by whether it may sleep, whether
it can run in fault/interrupt context, and which provider/UVM locks it holds.
Add sleepable or nonblocking admission only where the established callback
contract permits it. Then connect the block/drain, recovery, shared-UVM,
channel, and rollback paths through a lifetime-safe aggregate DPM consumer and
prove its device links and notifier phases against the pinned Linux source.
No notifier, synthetic DPM device or device link is currently registered.

Historical UVM-only build evidence: Open R580 report
[`private-open-pm-recovery-provider-v3`](../evidence/private-open-pm-recovery-provider-v3-20261021.json)
and proprietary R580 report
[`private-proprietary-pm-recovery-provider-v5`](../evidence/private-proprietary-pm-recovery-provider-v5-20261021.json).
The Open module has 132 exports; the proprietary module has 136 exports,
303 kernel imports, and zero GPL-only imports. Both reports say
`loaded_or_installed=false` and `hardware_validated=false`. The proprietary
report confirms that the original NVIDIA core object and its license remain
unchanged. The full software-test result is recorded in `docs/STATE.md`.

The earlier full pinned software suite passed **616 tests, zero failures or
skips in 33.132 s**; see the historical [log
`software-verification-shared-uvm-v1`](../evidence/logs/software-verification-shared-uvm-v1-20261021.log),
SHA-256 `f687ff43802b6e2b4443a85b382597d49c62c1cab04dde6e1572125b0ad66fd5`,
mode 0600. The current 620-test result is recorded in `docs/STATE.md` and
`docs/VALIDATION.md`.

Four earlier private-proprietary build attempts are retained as negative
evidence. They exposed, in sequence, an incomplete source-composition test,
patch line numbers that preceded the channels-only PM delta, a header-name
mismatch, and an exact-export-count assertion that had not allowed the three
new PM symbols. The successful v5 build follows fixes for each failure.

## Pinned source observations

- Linux v7.0 `kernel/power/suspend.c` is retained at
  `build/reference-sources/linux-v7.0/suspend.c`, SHA-256
  `71c4a16ad3db8cac349b7d8b52cdfddae26a8918216f18ec54a68c1761077576`.
  `suspend_prepare()` sends `PM_SUSPEND_PREPARE` before freezing processes. A
  freeze failure sends `PM_POST_SUSPEND`. Normal resume runs
  `dpm_resume_end(PMSG_RESUME)` before `suspend_finish()`; that function thaws
  processes and then sends `PM_POST_SUSPEND`.
- Linux v7.0 `kernel/power/hibernate.c` sends `PM_HIBERNATION_PREPARE` before
  freezing processes and `PM_POST_HIBERNATION` after its device/restore work
  and thaw. The source also has a separate `PM_RESTORE_PREPARE` /
  `PM_POST_RESTORE` path. The nested snapshot/restore lifecycle has not yet
  been integrated into the coordinator.
- The pinned R580 `nv_set_system_power_state()` takes the provider's
  `nv_system_pm_lock` for write and retains it across the private transition.
  The experimental `CHANNELS` depth preempts that provider's user channels,
  skips its UVM suspend/resume and skips its GPU power transition. Its resume
  restores the channels while also skipping device resume and UVM resume. The
  Linux PCI DPM callbacks remain responsible for per-device power transitions.
- R580 UVM `uvm_suspend()` documents that RM has already preempted every user
  channel. It acquires the global UVM PM lock for write, flushes queues and
  interrupt work, and holds PM and VA-space write locks until `uvm_resume()`.
  UVM's ordinary ioctl entry uses `uvm_down_read_trylock()` and returns
  `-EAGAIN` when the native UVM PM lock is unavailable.
- In the pinned R580 `uvm_global.c`, `uvm_suspend()` returns `NV_OK` after
  acquiring the PM/VA-space locks, flushing work and suspending interrupt
  handling. The provider rollback now invokes `nv_uvm_resume()` only if that
  suspend callback completed. Channel/device restoration errors are checked;
  a failed rollback is reported as `NV_ERR_GENERIC` rather than silently
  returning the original status.
- The source-pinned entrypoint audit
  `evidence/nvidia-pm-entrypoints-v1-20261021.json` found no NVIDIA-owned
  kernel PM notifier in either selected R580 provider. The Open R580 and
  proprietary R580 global path is procfs; the PCI PM methods remain device
  local. The audited R595 Open tree has a separate notifier path, which is not
  part of this same-version R580 design. Report SHA-256:
  `ab1d647a22fe845240a7458a56221eadec47e8a48d4dbb8729c37ef388ad0e42`.

## Consequences for an integrated coordinator

`src/hybrid580_system_pm_coordinator.h` models the four transition phases and
the event matrix below, but still registers no Linux callback or device link:

1. `hybrid580_system_pm_begin()` is the pre-freezer notifier phase. It closes
   frontend admission and returns; it does not drain, preempt channels, or
   call UVM.
2. After the process freezer completes, an aggregate DPM consumer callback
   drains remaining frontend work, preempts channels on both providers, then
   calls the one shared UVM suspend callback.
3. On resume, after every GPU supplier DPM callback has completed, the
   aggregate callback checks both sticky device-recovery results, resumes UVM
   once, and restores channels in reverse order.
4. The frontend gate remains closed until the matching post notifier after
   thaw. The post phase also reopens the gate when prepare/freezing aborts
   before the aggregate DPM callback runs. Any uncertain rollback leaves the
   gate quarantined.

### Event-specific CPU model

The model keeps a cycle identity so only its matching post notifier can reopen
the frontend. Its notifier routes are:

| Linux notifier | Model operation | Cycle identity |
|---|---|---|
| `PM_SUSPEND_PREPARE` | Close frontend admission | Suspend |
| `PM_POST_SUSPEND` | Reopen only after safe rollback or DPM resume | Suspend |
| `PM_HIBERNATION_PREPARE` | Close frontend admission | Hibernation |
| `PM_POST_HIBERNATION` | Reopen only after safe rollback or DPM resume | Hibernation |
| `PM_RESTORE_PREPARE` | Close frontend admission | Restore attempt |
| `PM_POST_RESTORE` | Reopen only after a returned restore attempt is safe | Restore attempt |

The abstract Linux DPM events map to the coordinator actions as follows. The
cross-audit reads the exact pinned Linux `pm_op()` and compares it with the
coordinator switch; it does not implement or register the aggregate device's
`dev_pm_ops` callbacks.

| Linux DPM event | Linux `dev_pm_ops` callback | Coordinator action |
|---|---|---|
| `SUSPEND` | `.suspend` | Quiesce channels, then shared UVM |
| `FREEZE`, `QUIESCE` | `.freeze` | Quiesce channels, then shared UVM |
| `POWEROFF`, `HIBERNATE` | `.poweroff` | Quiesce channels, then shared UVM |
| `RESUME` | `.resume` | Verify suppliers, resume shared UVM, restore channels |
| `THAW`, `RECOVER` | `.thaw` | Verify suppliers, resume shared UVM, restore channels |
| `RESTORE` | `.restore` | Verify suppliers, resume shared UVM, restore channels |

There are two materially different hibernation outcomes in pinned Linux v7.0.
For an image that is successfully restored, `load_image_and_restore()` does
not return to the restore kernel: execution continues in the saved
`hibernation_snapshot()` frame, where the DPM event is `PMSG_RESTORE`; the
restored system then finishes its saved hibernation cycle with
`PM_POST_HIBERNATION`. If a restore attempt fails and returns, the restore
kernel resumes devices with `PMSG_RECOVER` and completes its own
`PM_RESTORE_PREPARE` / `PM_POST_RESTORE` pair. The CPU test models both paths.
If a failed suspend/freeze callback already rolled all channel and UVM work
back, its later matching `THAW`/`RECOVER` is deliberately idempotent and does
not restore channels twice. A failed rollback remains quarantined.

The event routes match the pinned upstream Linux v7.0 source and both selected
private R580 provider trees in [audit v3](../evidence/nvidia-hibernate-dpm-contract-v3-20261021.json),
SHA-256 `365859f44f108c5779e8e2cdd1e675bef7edf678cca3f2e9a4848d66da54fe66`.
The C/UBSan coordinator tests exercise normal suspend/resume, hibernation
freeze/thaw, failed freeze/recover, restore-attempt quiesce/recover, restored
image restore, matching notifier pairs, and failure quarantine. These remain
CPU/source checks; no Linux callback, device link, freezer, PM cycle, or
hardware recovery has run.

The R580 source leaves a PM-critical ordering question around non-replayable
faults. The Volta and Blackwell HALs both enable this support. The fault worker
fetches and services cached batches until empty; the ISR top half checks for
pending faults and schedules the worker, while `uvm_suspend()` flushes the
bottom-half and kill-channel queues. However, `uvm_suspend()` retains an
explicit TODO to flush the non-replayable buffer and does not rescan or enqueue
pending faults itself before marking the ISR suspended. The source-pinned
[callback/PM lifecycle audit v10](../evidence/uvm-callback-pm-lifecycle-v10-20261021.json),
SHA-256 `5e4243f84bc67117d7a3493b973c5118c8570289c2b9e939a0a179aa9388994b`,
confirms this in the Open baseline, private Open backend, and proprietary
backend. It remains to prove that R580 channel preemption always causes the
top half to queue every pending fault before UVM crosses this barrier. This is
a conditional static-source risk, not an observed fault loss; no hybrid PM
cycle has run.

The UVM VMA audit explains why UVM must not be called from the early notifier.
In both exact R580 source trees, managed VMA `.open` and `.close` use per-VA
space locks but do not acquire the global UVM PM lock. They cannot return an
error to the VM. Process-teardown `.close` may also take the VA-space RM read
lock to stop user channels. Managed CPU faults instead acquire the global PM
lock with a nonblocking trylock before the VA-space read lock. UVM's
`UVM_ENTRY_WRAP` supplies thread-context setup; it is not a PM guard. The
semaphore-pool and device-P2P VMA callbacks likewise use VA-space locks or are
empty, rather than taking the global PM lock.

R580 `uvm_suspend()` takes the global PM write lock, flushes global and per-GPU
work, then takes the global VA-space list lock and every VA-space write lock.
It retains those locks until `uvm_resume()`, specifically to synchronize VMA
open/release callbacks that cannot exit early. UVM mmap has its own PM read
trylock; on contention it disables the VMA and returns success to preserve
`MAP_FIXED` semantics. This source contract makes a post-freezer DPM callback
the candidate place for the shared UVM transition. Calling UVM from
`PM_SUSPEND_PREPARE` is unproven and intentionally excluded from the phase
model.

`nv_vma_start_write()` is a compatibility fallback used by the NVIDIA VMA
flag helpers when the kernel's VMA writer API cannot be called. Its helper
maintains the kernel VMA writer sequence; it does not acquire either NVIDIA's
provider PM lock or UVM's global PM lock. The pinned R580 UVM code has three
`nv_vm_flags_set()` sites. The source audit and exact hashes are in
[`uvm-vma-pm-lock-audit-v2`](../evidence/uvm-vma-pm-lock-audit-v2-20261021.json)
(SHA-256 `49329fc9722a030a44b77872985766c694fff102ed9c5b3e58facf00e7cc7321`).
The audit script is [`audit_r580_uvm_vma_pm.py`](../tools/audit_r580_uvm_vma_pm.py);
four regression tests compare independent Open and proprietary source trees
and reject removal of the critical locks.

Linux v7.0 device-link documentation says supplier/consumer links impose
system suspend/resume ordering. A candidate wiring is a synthetic aggregate
DPM device as consumer and every NVIDIA GPU PCI device as a supplier. That
would place the aggregate callback before its suppliers during suspend and
after them during resume. The pinned `main.c` makes the ordering concrete:
`device_suspend()` waits for children and active device-link consumers before
its callback; `dpm_wait_for_consumers()` waits for non-dormant links other than
sync-state-only links. Resume uses `dpm_wait_for_superior()`, which waits for
the parent and active suppliers before invoking the consumer callback. Async
DPM represents those waits with each device's completion. This confirms the
ordering primitive, not the proposed aggregate device itself. Every active GPU
supplier must be linked; links must be created and removed outside a PM
transition, and device removal, probe order, hibernation and recovery still
need explicit coverage. Pinned source hash for `main.c`:
`73003d1eff8e9da39baf524b92f1cb9654c0dcdb3817146205261feda18140e5`.
See the [Linux v7.0 device-link contract](https://github.com/torvalds/linux/blob/v7.0/Documentation/driver-api/device_link.rst) and
[DPM ordering implementation](https://github.com/torvalds/linux/blob/v7.0/drivers/base/power/main.c).

The gate coverage boundary remains open. Frontend GPU-file `.open`, ioctl,
`.poll`, `.mmap`, and final `.release` now enter the admission primitive with
different sleep rules. GPU-file `.open`, ioctl and `.poll` also have distinct
provider-lock behavior; GPU and control-file release hold a provider PM read
lock, while deferred close callbacks retain only the kernel-owned file-private
object. Native `.mmap`, `nvidia_fault()` and VMA `.access` use nonblocking
provider PM admission. VMA `.open/.close` instead serialize their per-file
bookkeeping, and UVM's own VMA paths use the VA-space and global PM contracts
above. These static audits do not prove that every frontend operation or
kernel worker is drained at the proposed DPM point. The admission primitive is
present in the frontend, but no PM notifier, synthetic DPM device or device
link invokes it.

Linux PM notifier callbacks do not provide the hybrid coordinator with a
reliable aggregate of per-device resume errors. The per-GPU result primitive
above now supplies this channel in both providers; the frontend still needs to
call `begin`, `recover`, and `end` at the matching lifecycle points. If either
provider reports an error, it must leave UVM, channels, and the operation gate
quarantined rather than expose partially restored devices.

The same-version providers now expose flavor-specific PM entrypoints, so their
export names do not collide. A single UVM suspend/resume callback may be invoked
through exactly one selected R580 backend; its registration/lifetime model
across both provider sessions still needs source-level proof.

The earlier [`r580-modeset-pm-audit-v1`](../evidence/r580-modeset-pm-audit-v1-20261021.json)
found that both private `CHANNELS` paths dispatched global `nvidia_modeset_suspend(0)`
and `nvidia_modeset_resume(0)`. That was unsafe for the selected order: Linux PCI
DPM later calls per-GPU `nvidia_suspend()`/`nvidia_resume()`, and NVKMS's GPU-zero
callback holds one global write semaphore until its matching resume.

Patch [`0036 Open`](../patches/r580.178.04/0036-private-open-pm-channel-dpm-modeset.patch)
and [`0036 proprietary`](../patches/r580.178.04/proprietary/0036-private-legacy-pm-channel-dpm-modeset.patch)
now make aggregate `CHANNELS` suspend, resume, and failed-suspend rollback skip
those global NVKMS calls. Per-GPU DPM callbacks continue to pass `nv->gpu_id`,
so GPU power transitions own their matching modeset calls. The refreshed
[source audit v2](../evidence/r580-channel-dpm-modeset-audit-v2-20261021.json),
SHA-256 `eeb9d5f3fce062a9311aa4d7ca5e21967493625bf245828738d19c34eb774d56`,
checks all three guards and both per-GPU call paths in the built Open and
proprietary sources. This is a static source contract; it does not demonstrate
runtime callback order or lock pairing.

The modeset dispatch still has one callback slot per provider core and returns
`void`; NVKMS's GPU-zero callback still pairs the global `down_write()` and
`up_write()` semaphore. NVKMS reserves fixed character device `195:254`. The
private core exports rename `nvidia_get_rm_ops`, so the stock modeset module
cannot bind by the standard symbol. A compute-focused candidate remains one
namespaced R580 NVKMS module against the Open R580 provider, with proprietary
Volta compute-only; this is a compile-time design hypothesis, not runtime proof.

The compiled private cores rename the `nvidia_get_rm_ops` export to
`hybrid580_open_nvidia_get_rm_ops` and
`hybrid580_legacy_nvidia_get_rm_ops` respectively (their exact module hashes
and export maps are in the two channel-PM build reports). Thus a stock
R580/R595 modeset module does not register callbacks with either private core
through the standard symbol. A compute-focused candidate is to build one
namespaced R580 NVKMS module against the Open R580 Blackwell provider and keep
the proprietary R580 Volta provider compute-only. The Volta provider's local
callback slot would then remain empty, while the single Open-side NVKMS owns
195:254. This is a source/ELF-based design hypothesis: the private NVKMS module
has not been built, neither callback binding was executed, and display support
for the V100 is outside that candidate.

Linux v7.0's `pm_op()` maps SUSPEND/RESUME to `.suspend/.resume`,
FREEZE/QUIESCE to `.freeze`, POWEROFF/HIBERNATE to `.poweroff`, THAW/RECOVER
to `.thaw`, and RESTORE to `.restore`. The CPU coordinator models and tests
this event matrix; no Linux callback has yet been wired. Normal suspend success
is not a hibernation/restore proof. Do not wire notifier/DPM fan-in until sole
modeset ownership, complete frontend/backend admission, rollback behavior,
every event path, and provider-result cleanup have been qualified.

The normal system-suspend notifier runs before the user-process freezer, while
the post notifier runs after DPM resume and process thaw. Therefore the front
gate's blocked entrants must sleep in a freezer-aware wait and must be woken by
the post notifier; a plain semaphore/rwsem wait behind a writer is not an
acceptable implementation. The gate must cover every entry that can mutate RM
channels or launch UVM work, while deferred close paths must remain safe.

## Prototype contract and stopping rule

The CPU model tests that no provider or UVM callback runs before the modeled
freezer boundary, success ordering, duplicate calls, partial channel
preemption, failure returned by a partial suspend attempt, cleanup failure and
quarantine, UVM suspend failure, DPM recovery failure, UVM resume failure,
channel restore failure, and post-notifier gate-open failure.
It does not exercise a Linux notifier, device link, freezer, UVM lock, RM
callback, VFS operation, module symbol dependency, or physical device.

The provider-result and channel-API evidence is recorded in `docs/STATE.md`
under “per-GPU channels-only PM control”. Both provider modules compile
separately, but the frontend has not imported these APIs; neither module has
been installed or loaded, and no suspend/hibernate operation was run.

Do not register a notifier, install a module, or test suspend on a live system
until the operation-gate coverage and lock order are established in source and
the frontend resolves both provider APIs. A hardware canary must then verify
aborted prepare, freeze failure, successful suspend/resume,
hibernation/restore, and rollback before the coordinator is enabled by default.

## Primary source links

- [Linux v7.0 suspend.c](https://github.com/torvalds/linux/blob/v7.0/kernel/power/suspend.c)
- [Linux v7.0 hibernate.c](https://github.com/torvalds/linux/blob/v7.0/kernel/power/hibernate.c)
- [Linux v7.0 vm_operations_struct](https://github.com/torvalds/linux/blob/v7.0/include/linux/mm.h)
- [Linux v7.0 device-link contract](https://github.com/torvalds/linux/blob/v7.0/Documentation/driver-api/device_link.rst)
- [Linux v7.0 DPM ordering implementation](https://github.com/torvalds/linux/blob/v7.0/drivers/base/power/main.c)
- Pinned NVIDIA R580.178.04 sources and exact patch stack are recorded in
  `docs/STATE.md` and `patches/r580.178.04/`.
