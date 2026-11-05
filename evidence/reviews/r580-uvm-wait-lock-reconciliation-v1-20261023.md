# R580 UVM CPU-wait lock review

Status: **analyzed statically; no deadlock demonstrated; canary liveness test still required.**

Inputs: NVIDIA R580.178.04 source archive SHA-256 `060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8`; isolated-execution patch `0002` SHA-256 `23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0`; patched `uvm_push.c` SHA-256 `53b1cdd7abc6f5dcea062a314b5580b05329868ad36a61f6a3f0d567f3326227`; unchanged `uvm_va_block.c` SHA-256 `dd2821620e83cfaeb03fd765d64dcb75d82da83a38107afa4b0c2882570a7b03`; unchanged `uvm_hmm.c` SHA-256 `6e0476ded5b3adc6f5996bcd83e18012f7c38b6ccb662c9d9befd8b2e885cfc9`.

In stock R580, `wait_for_other_gpus_if_needed()` already existed in `uvm_push.c:204-213` and was called before channel reservation at `261-272`. Patch `0002` changes the dependency predicate so the same helper uses a CPU wait in opt-in isolated mode. `block_unmap_gpu()` passes `&block->tracker` into that push at `uvm_va_block.c:8039-8045`; `uvm_va_block_unmap()` asserts the block mutex at `8103-8113`.

This lock pattern is not wholly new: stock `hmm_invalidate()` holds `va_block->lock`, unmaps into `va_block->tracker`, calls `uvm_tracker_wait()` and only then unlocks (`uvm_hmm.c:468, 500-518, 523-524`). Stock CPU page insertion also waits on that tracker with the block mutex held (`uvm_va_block.c:8268, 8331-8338`). That evidence invalidates the broad claim that any CPU tracker wait under this mutex is a new defect. It does not prove that the opt-in cross-GPU wait is safe in every context.

UVM tracker entries refer to UVM channel pushes, not directly to user CUDA kernels (`uvm_tracker.c:128-155`). The reviewed call sites do not establish that a tracked push needs a replayable fault on the same block. However, tracker progress checks channel/global errors while polling and has no terminal timeout (`uvm_tracker.c:301-321, 360-385`); R580 also documents that RM interrupt handling and UVM fault service can be needed for progress (`uvm_common.c:253-281`). An indirect wait-for cycle remains possible but is not proven.

The patch adds a second CPU wait in `uvm_migrate_pageable.c:809-826`, waiting on the local `zero_tracker` before starting the page-copy push. That tracker receives the optional destination zeroing push only (`uvm_migrate_pageable.c:771-782`). The pageable VMA path rejects NVIDIA UVM-owned VMAs (`migrate_pageable_vma()`), so this is distinct from the demonstrated block-lock call chain. Other progress-critical lock interactions and runtime behavior remain unvalidated.

The decisive canary test is to record the GPU/channel/tracker value and VA range at entry and completion of the generic wait, create a real cross-GPU entry in `block->tracker`, delay its completion, and concurrently trigger a replayable fault in the same block during unmap. Use a watchdog and fault/interrupt traces to determine whether that push completes while the fault handler is blocked on the mutex. Do not load patch `0002` until the canary and a verified rollback path exist.

The expanded static auditor is [`audit_r580_uvm_wait_lock_context.py`](../../tools/audit_r580_uvm_wait_lock_context.py); its mode-0600 machine report is [`r580-uvm-wait-lock-context-v2-20261023T2331Z.json`](../r580-uvm-wait-lock-context-v2-20261023T2331Z.json). The audit covers both wait sites and has mutation tests; it is source evidence only.
