# PC6 independent static review: R580 isolated UVM GPU execution

## Objective
Review the exact opt-in R580.178.04 patch and its clean build as a hostile independent reviewer. Decide whether the current patch correctly removes cross-GPU semaphore mappings/dependencies while preserving UVM correctness for the supported isolated-execution scope. Identify any missed direct GPU acquire path, ordering or deadlock hazard, lifetime/error issue, or claim that exceeds the evidence.

## Exact inputs and provenance
- Source archive: NVIDIA-kernel-module-source-580.178.04.tar.xz, SHA-256 `060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8`.
- Patch: `0002-hybrid-isolated-gpu-execution.patch`, SHA-256 `23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0`.
- Fresh pinned build report: `r580-uvm-isolated-gpu-execution-build-v5-20261023T2130Z.json`; compile qualification only. This review must independently verify source and patch, not trust the report's conclusion.
- Local scope: R580 UVM semaphore ownership and tracker ordering only. No driver install/load, device access, GPU/VM change, reboot, external communication, or editing the canonical project.

## Required analysis
1. Verify copied input hashes and the archive root/tag. Inspect the exact unmodified R580 source, all patch hunks, surrounding function callers and definitions.
2. Enumerate every production call site that can queue a tracker acquire against a GPU different from the producer/owner, including pageable migration, semaphore tracking, channel scheduling, eviction, peer paths, and context destruction. Distinguish tests and same-GPU-only paths.
3. Trace `uvm_tracker_wait_for_other_gpus`, tracker destruction/error paths, migration push ordering, semaphore allocate/map/unmap/free semantics, and lock/VA-block constraints. Look for deadlocks, lost ordering, stale use-after-free, hangs and failure cleanup.
4. Analyze module parameter defaults, read-only load-time semantics, interaction with Confidential Computing, and behavior with one provider versus mixed providers. Confirm what “isolated” concretely guarantees and what it does not.
5. Adversarially search for counterexamples: cross-provider GPU VA access to owner-only pages, shared managed-memory mappings, P2P, another direct GPU acquire bypassing the wait, tracker entries that are not cleared by a successful wait, teardown/unload, concurrent migration, interruption/context loss.
6. Compare patch to the build report and test source. Treat successful compilation and CPU/static tests as such; hardware/runtime, same-process CUDA and P2P remain unverified.

## Deliverables
Write only inside this review directory:
- `REPORT.md`: concise verdict (`supports static compile only`, `blocker`, or `conditionally sound for named scope`), specific evidence with source paths/line numbers, affected invariants, counterexamples, unknowns, and the next discriminating experiment.
- `FINDINGS.json`: structured findings with severity, source path, line/function, evidence class (`source-observation`, `test`, `build-report`, `inference`, `unknown`), and confidence; include verified input hashes and explicit `hardware_validated=false`.
- `SONNET_REVIEW_*.md`: independent findings from delegated read-only agents. Resolve disagreements explicitly in REPORT.md.

Do not modify inputs. Do not claim original proprietary implementation from pseudocode. Do not broaden the patch or create production-ready claims. If a premise cannot be proved, mark it unknown. Stop only when the report is complete and the completion promise is justified.
