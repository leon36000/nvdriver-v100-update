# Independent R580 UVM cross-GPU wait / VA-block lock review

## Goal

Produce a source-grounded, adversarial design review of the R580.178.04 isolated-UVM patch's CPU tracker waits. The concrete decision is whether the current patch is safe enough to advance to a kernel canary, and if not, what smallest source-backed implementation can remove the blocker.

This is an independent review. Verify every material statement in the pinned archive and exact patch; do not rely on a lead's summary. The earlier lead hypothesis to falsify is: the patched host wait can be reached while `uvm_va_block_unmap()` requires `va_block->lock`, via a push acquiring `block->tracker`. A wait may stop forward progress if a pending GPU completion requires fault service on that same VA block. Treat that as a hypothesis until an exact source path supports it.

## Inputs and immutable scope

- NVIDIA open source archive: `inputs/NVIDIA-kernel-module-source-580.178.04.tar.xz`, SHA-256 `060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8`.
- Patch under review: `inputs/0002-hybrid-isolated-gpu-execution.patch`, SHA-256 `23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0`.
- Read-only upstream source: `inputs/source/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm/`.
- Read-only patch replay: `analysis/patched-source/kernel-open/nvidia-uvm/`; patch 0002 was dry-run checked and applied to a separate copy. Use this tree to inspect behavior after the patch and compare with the upstream source.
- The project is not checked out on this host. Do not infer the newer Kbuild patch affects runtime behavior.
- Do not change any input/source files. Write only `REPORT.md` and `ITERATION_LOG.md` in the workspace root. The report must include exact source paths/function names and line locations, input hashes, agent findings/reconciliation, and explicit evidence level.

## Required investigation

1. Independently verify both newly introduced CPU-wait sites (general push begin and already-selected-channel push begin) and trace every code path that invokes them with a non-NULL tracker. Search for additional waits or hidden preconditions.
2. Trace the lock path from the caller to the wait. Establish what is locked, which tracker entries can be present, when entries are removed, and whether waiting occurs before/after channel reservation or push begin. Quote code locations, not assumptions.
3. Inspect the tracker wait loop, channel completion/error behavior, GPU fault servicing, and relevant block-lock/retry protocols. Either construct a concrete possible wait-for cycle involving the same VA block, or explain precisely what dependency is missing so the concern is downgraded. Distinguish a possible progress hazard from a reproduced deadlock.
4. Trace error/status propagation for any proposed non-blocking or fail-closed behavior, especially `NV_ERR_MORE_PROCESSING_REQUIRED`, through every caller of `block_unmap_gpu`/the push API. Identify callers that assert, retry, return to userspace, or convert errors to a global failure.
5. Compare at least these designs: keep GPU semaphore dependencies where provider-compatible and reject cross-provider dependencies; nonblocking check with an established retry status; move waits outside the block-lock critical section using an established split-phase protocol; disable only mixed-provider UVM while allowing independent CUDA contexts. Do not recommend lock drop/reacquire without proving state/lifetime serialization.
6. Recommend the smallest safe next patch or state that no source-safe patch can be selected yet. Give a specific CPU/static regression and a later hardware stress scenario. Never claim runtime/hardware validation.

## Reviewer team

Spawn and use all three supplied Sonnet 5.5 agents: `wait-callgraph`, `wait-liveness`, and `retry-design`. Keep them read-only and give them disjoint questions. Require concrete file/function/line evidence and counterevidence. Resolve disagreements yourself and record which conclusions remain inference.

## Safety and completion

This is source-only analysis. Do not build, install, load, unload, or interact with GPU devices; do not change firmware, kernel, modules, or production services. Do not fetch new proprietary material. You may inspect only the staged open-source archive/patch and your reports.

Use the installed Ralph loop with `--max-iterations 8` and completion promise `R580_WAIT_LOCK_REVIEW_COMPLETE`. Continue until the report closes every numbered investigation item or clearly labels an unresolved blocker and the exact missing evidence. Output `<promise>R580_WAIT_LOCK_REVIEW_COMPLETE</promise>` only after the report and iteration log meet those requirements, all three agent reports have been reconciled, and source paths/hashes have been checked.
