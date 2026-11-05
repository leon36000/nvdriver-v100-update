I did the audit using only Read, Grep and Glob. Nothing was run or written, and I did not print the completion marker. One conflict: plan mode asked me to write a plan file, but you said not to write files, so I put the whole report in this message.

```
CANDIDATE REPORT — Volta UVM capability map v2 (R580.178.04 → R615.71.10)
Opus iteration 1 of 3. Static source review only. No runtime or hardware claims.
Paths below are relative to the bundle root: capability-map-review/

========================================================================
1. VERDICT
========================================================================
Mostly correct, with gaps. Not ready to sign off yet.

- All 11 rows are accurate at the line level. Every R580 assignment, every
  cited R580 consumer and every R615 anchor is at the stated file and line
  with the stated text.
- The 11 fields are exactly the ones R580's uvm_volta.c sets that no longer
  exist in R615. Every other field uvm_volta.c sets is still declared in
  R615 uvm_gpu.h.
- The map never claims Volta works: every row and the top level say
  runtime_or_hardware_validated=false.
- What it gets wrong or leaves out:
  (a) It does not say that stock R615 UVM has no GV100 or Volta entries in
      its HAL tables. A GV100 is refused when its GPU support is set up,
      before any of the 11 code paths can run.
  (b) R615's public header uvm.h still promises that PLC and sparse requests
      are rejected on GPUs that don't support them, but the code no longer
      checks. The map misses this.
  (c) PLC is the one row where Volta's behavior actually changes. R615
      unmaps existing overlapping mappings before the request ever reaches
      RM, so a rejection now has a side effect R580 didn't have.
  (d) Four rows use an R615 anchor that is unchanged R580 code.
  (e) The C scanner works for LF and CRLF line splicing but has untested
      weak spots.
  (f) The tests only exercise the in-memory function, not the file and
      archive pipeline that produced the report.

========================================================================
2. FINDINGS BY SEVERITY
========================================================================

MEDIUM-1: The map leaves out that R615 has no GV100 HAL entries at all.
  Source facts:
  - R615 uvm_hal.c:60 — the copy-engine table starts at TURING_DMA_COPY_A.
  - R615 uvm_hal.c:146 — the host table starts at TURING_CHANNEL_GPFIFO_A.
  - R615 uvm_hal.c:239 — the architecture table starts at
    ARCHITECTURE_TU100.
  - No GV100 or Volta entry exists anywhere in the R615 tree. A
    case-insensitive search for volta|GV100 only finds two comments,
    uvm_hal.h:181 and :833.
  - R615 uvm_hal.c:642-668 — if the copy-engine class, host class or
    architecture isn't found, setup returns NV_ERR_INVALID_CLASS.
  - Neither the clc3b5.h nor the clc36f.h class header is in the R615 tree.
  - R580 uvm_volta.c:75 — R580 asserts the GPU is GV100.
  Inference (class numbers are from my own knowledge, not the bundle): GV100
  reports Volta copy-engine and host classes (0xC3B5 / 0xC36F), so stock
  R615 rejects it at setup.
  Impact: labels like "no-GV100-proof" understate the gap. Every R615 anchor
  depends on a host, MMU, architecture or fault-buffer HAL table that has no
  GV100 entry, so none of these paths can run on GV100.
  Fix: add a top-level prerequisite to the map saying a GV100 HAL entry must
  be restored first, citing uvm_hal.c:642-668.

MEDIUM-2: The PLC row misses a documented promise and a side effect.
  Source facts:
  - R615 uvm.h:1799-1800 still documents that UvmMapExternalAllocation
    returns NV_ERR_INVALID_DEVICE when "UvmGpuCompressionTypeEnabledNoPlc
    compression type was used on one or more GPUs that don't support PLC".
  - R615 has no such check anywhere. Its only validation is the enum range
    check at uvm_map_external.c:549.
  - R580 rejected the request at uvm_map_external.c:861-862, before taking
    the lock (868) and before unmapping anything (870).
  - R615's uvm_map_external_allocation_on_gpu calls
    uvm_unmap_external_in_range at line 879 and nvUvmInterfaceDupMemory at
    918, both before the compression type reaches RM via
    nvUvmInterfaceGetExternalAllocPtes (187).
  Inference: on Volta (R580 uvm_volta.c:105 sets plc_supported=false), an
  EnabledNoPlc request that RM rejects in R615 would already have destroyed
  any existing mappings overlapping the target range. The error code would
  also be whatever RM returns, not the documented NV_ERR_INVALID_DEVICE.
  This is the only one of the 11 fields where Volta's behavior flips; the
  other gates passed Volta through.
  Fix: cite uvm.h:1799-1800 and the unmap-before-RM ordering (879 before
  187). Raise this row's priority for restoring a UVM-side check.

MEDIUM-3: The tests don't cover the pipeline that produced the report (see
  section 4).

LOW-1: Four rows use an R615 anchor that is unchanged from R580, so the
  "reworked-*" labels overstate the change.
  - va_invalidate_supported: R615 uvm_tlb_batch.c:70 is the same as R580
    uvm_tlb_batch.c:70. The real change is that R580's gate at lines 91-92
    was deleted; R615 lines 89-95 have no such check.
  - sparse_mappings_supported: R615 uvm_map_external.c:1103 is the same as
    R580 :1094. The real change is the deleted gate at R580 :1196-1199;
    R615 lines 1180-1208 have none.
  - fault_cancel_va_supported: R615 uvm_gpu_replayable_faults.c:472 is the
    same call as R580 :485. The real changes are R615 :2701, which now
    always calls cancel_faults_all, and :2871, which always calls
    service_fault_batch_for_cancel.
  - non_replayable_faults_supported: R615 uvm_gpu_replayable_faults.c:272
    matches R580 :274. The real change is the gate removed at R580 :273.
    The map cites uvm_gpu_isr.c from R580 instead of this direct
    counterpart, even though it is in the supplied excerpt.
  Fix: for each field, add the "R580 gate → R615 ungated" line pair as the
  main evidence.

LOW-2: The R580 consumer lists are partial, and the JSON doesn't say so.
  - Only the script docstring (audit_volta_uvm_capability_map.py:276) calls
    them "representative". The JSON field r580_consumer_evidence has no
    such qualifier.
  - Consumers that are in the supplied excerpt but not cited:
    - fault_cancel_va_supported: R580 uvm_gpu_replayable_faults.c:857, the
      in_pascal_cancel_path flag that controlled fault filtering. R615 :837
      is now just may_filter = uvm_perf_fault_coalesce. Also R580 :2871.
    - prefetch_fault_supported: R580 :235, :2880, :3033 and :3044.
    - non_replayable_faults_supported: R580 :273, :302 and uvm_gpu_isr.c:643.
    - gpfifo_in_vidmem_supported: R580 uvm_channel.c:3341-3352 also forced
      the GPPUT location back to default. The map only mentions GPFIFO, and
      R615 uvm_channel.c:3387 now picks the GPPUT location using
      max_host_va == 1<<40, the value Volta sets at R580 uvm_volta.c:65.
  - Consumers in R580 files not in the excerpt can't be checked. See open
    questions.

LOW-3: The scanner has weak spots that don't affect the current results.
  (a) A quote that is never closed stays open across lines. In
      _mask_c_comments_and_literals (script lines 203-233) the string and
      character states only end at a matching quote. A lone apostrophe
      outside a comment, for example in "#warning don't", would hide every
      later line up to the next apostrophe. That would make
      absent_from_code=true wrongly.
      I found no such case in R615: no #error or #warning line contains an
      apostrophe, and there are no #if 0 blocks.
  (b) Line numbers come from counting LF only (lines 238-260), but the
      reported text uses Python's str.splitlines() (lines 269 and 307),
      which also splits on characters like form feed, vertical tab and
      U+2028. If a file contained one of those, the reported line numbers
      and text would drift apart.
      The supplied sources contain none of them, and no stray CR either.
  (c) _line_hits (lines 263-271) matches anchors as plain substrings without
      masking comments, and doesn't require them to be unique. A
      commented-out call would still count as an anchor.
  (d) GCC also splices a backslash followed by spaces then a newline (with a
      warning); the scanner doesn't. No such lines exist in R615 (searched
      for a backslash followed by trailing spaces).
  (e) Identifiers built by token pasting (##) wouldn't be found. None
      target these fields: no "##" near "_supported".

LOW-4: The report can't be reproduced from the bundle, or tied to the script
  version.
  - The evidence's source_root
    (/run/media/pc1/.../extracted-r615-71-10-package/kernel-open/nvidia-uvm)
    is from a different machine than the script default (script :23).
  - The report doesn't record a hash of the audit script.
  - The R580 excerpt has no manifest of its own; only the R580 archive hash
    is recorded.
  - I could not check any hash in SOURCES.json or MANIFEST.sha256 without
    running code.

INFO-1: Old fallback code is still in R615 but nothing calls it.
  - cancel_fault_batch_tlb (uvm_gpu_replayable_faults.c:2663) and
    cancel_faults_precise_tlb (:2729) are defined but have no callers.
  - So "without the historical capability fallback" is true about the call
    graph, not about the source text. Useful if this is restored.

INFO-2: The sparse row's statement that "the Turing implementation is not a
  Volta implementation" is an inference.
  - R615 uvm_turing_mmu.c:329-333 builds the sparse entry with _MMU_VER2
    fields. Whether Volta's page-table format matches is not shown by the
    bundle.

INFO-3: scoped_atomics_supported can be stated more strongly.
  - The whole system-wide-atomics feature is gone from R615: no matches for
    "wide_atomic" anywhere. That covers system_wide_atomics_set and the
    system_wide_atomics_enabled_processors processor set.
  - On Volta, R580 uvm_policy.c:977-979 returned NV_ERR_NOT_SUPPORTED, so
    this removal is not a regression for Volta.

INFO-4: Sparse has the same documentation problem as PLC.
  - R615 uvm.h:1886 still documents NV_ERR_INVALID_DEVICE when "Sparse
    mappings are not supported on the specified GPU", but the code has no
    check.
  - Volta had sparse_mappings_supported=true (R580 uvm_volta.c:99), so
    Volta's behavior is unchanged here.

========================================================================
3. EVIDENCE / CLAIM MATRIX
========================================================================
Confirmed = verified in the supplied source. Inference = my reasoning, not
shown directly by source.

Row 1 — va_invalidate_supported
  R580: set at uvm_volta.c:31; checked at uvm_tlb_batch.c:91. Confirmed.
  R615: uvm_tlb_batch.c:70 confirmed, but the same line exists in R580
        (LOW-1). Gate removed: R615 :89-95.
  Map's interpretation: partly overstated ("reworked callback").

Row 2 — va_range_invalidate_supported
  R580: set at uvm_volta.c:33; checked at :97 and :124. Confirmed.
  R615: :94 and :118 confirmed. The max_pages path is gone.
  Map's interpretation: accurate.

Row 3 — can_map_sysmem_with_large_pages
  R580: set at :68; checked at uvm_mem.c:332, with a 4K fallback at
        :338-339. Confirmed.
  R615: uvm_mem.c:332 confirmed; there is no 4K fallback.
  Map's interpretation: accurate.

Row 4 — prefetch_fault_supported
  R580: set at :71; checked at uvm_gpu_replayable_faults.c:216 (other
        consumers in LOW-2). Confirmed.
  R615: :216 and :3028 confirmed. The HAL calls at :236, :2739 and :3027
        are unconditional.
  Map's interpretation: accurate.

Row 5 — gpfifo_in_vidmem_supported
  R580: set at :79; checked at uvm_channel.c:3341. Confirmed.
  R615: :3393 and :2355 confirmed. The coherent-platform branch (:3379) and
        override (:3398) are not cited; GPPUT is left out (LOW-2).
  Map's interpretation: accurate but incomplete.

Row 6 — replayable_faults_supported
  R580: set at :81; checked at uvm_gpu_isr.c:359. Confirmed.
  R615: uvm_gpu_isr.c:359 confirmed; the call is now unconditional.
  Map's interpretation: accurate.

Row 7 — non_replayable_faults_supported
  R580: set at :83; checked at uvm_gpu_isr.c:394 and :552. Confirmed.
  R615: :272 confirmed, but it matches R580 :274 (LOW-1). The only R615
        mention is a comment at uvm_user_channel.h:115, which the scanner
        correctly treats as non-code.
  Map's interpretation: accurate.

Row 8 — fault_cancel_va_supported
  R580: set at :89; checked at :2696 (also :857 and :2871, not cited).
        Confirmed.
  R615: :472 confirmed, but it matches R580 :485 (LOW-1). The dead
        fallbacks are INFO-1.
  Map's interpretation: mostly accurate.

Row 9 — scoped_atomics_supported
  R580: set at :91; checked at uvm_policy.c:977. Confirmed.
  R615: no anchor, consistent with the feature being removed entirely
        (INFO-3).
  Map's interpretation: accurate, could be stronger.

Row 10 — sparse_mappings_supported
  R580: set at :99; checked at uvm_map_external.c:1196. Confirmed.
  R615: :1103 confirmed, but it matches R580 :1094 (LOW-1). uvm.h:1886
        still documents the check.
  Map's interpretation: accurate; the Turing statement is an inference.

Row 11 — plc_supported
  R580: set at :105 (=false); checked at uvm_map_external.c:861. Confirmed.
  R615: :549, :1044, :110 and :187 confirmed (path below). uvm.h:1799 still
        documents the check; the unmap happens before the RM call
        (MEDIUM-2).
  Map's interpretation: accurate but incomplete.

PLC path, checked step by step in R615 (all confirmed):
  1. uvm_api_map_external_allocation (uvm_map_external.c:1095)
  2. uvm_map_external_allocation (:983): validates the request at :1021-1028,
     which includes the enum range check at :549
  3. map_rm_params.compression_type is set (:1044)
  4. uvm_map_external_allocation_on_gpu (:1045 → :852): unmaps overlapping
     mappings (:879), duplicates the memory handle (:918)
  5. uvm_va_range_map_rm_allocation (:964 → :379)
  6. uvm_pte_buffer_init (:441 → :91): sets mapping_info.compressionType
     (:110)
  7. map_rm_pt_range (:476) → uvm_pte_buffer_get (:321 → :133)
  8. nvUvmInterfaceGetExternalAllocPtes(..., &pte_buffer->mapping_info)
     (:187)
  Also confirmed:
  - The struct uvm_map_rm_params_t has exactly six fields
    (uvm_map_external.h:33-41), and all six are set at :1039-1044.
  - The channel path hard-codes compression_type = Default
    (uvm_user_channel.c:503) and calls nvUvmInterfaceGetChannelResourcePtes
    (uvm_map_external.c:180).
  - No UVM-side PLC check exists anywhere. Confirmed.
  Unknown: what RM does with compressionType on GV100.

Scanner checks:
  - Splicing for LF and CRLF (lines 245-252) handles both and maps lines
    correctly. Confirmed by reading the code.
  - Masking of line comments after a splice. Confirmed.
  - Weak spots: LOW-3.

Completeness of the 11 fields:
  - Every other field R580 uvm_volta.c sets is still declared in R615
    uvm_gpu.h: lines 411, 1053, 1057, 1063, 1065, 1076, 1083, 1087, 1100,
    1105, 1108, 1132, 1142-1153, 1212, 1260 and 1321. smc.supported is used
    in uvm_turing.c:75 and others.
  - So the set of 11 is complete. Confirmed.

========================================================================
4. TESTS AND LIMITATIONS
========================================================================
There are 8 tests, all calling audit_capability_sources() on made-up input.
None of them runs against the real pinned sources.

What they cover:
  - all 11 fields appear in the output
  - failure when an R580 assignment or an R615 anchor is missing
  - the manifest hash depends on paths but not on input order
  - comment-only occurrences are ignored, code occurrences are counted
  - line splicing for LF and CRLF, both comment continuation and an
    identifier split across lines (line 1 only)

What's missing:
  - Nothing tests build_report, _read_r615_tree (wrong file count, manifest
    mismatch, symlink refusal), _read_r580_archive, the archive hash checks,
    or strict UTF-8 decoding.
  - No test for a missing R580 consumer, or for a duplicate assignment
    (more than one match).
  - No tests for block comments, string or character literals containing the
    field name, escaped quotes, a block comment continued by a splice, or an
    unclosed quote (LOW-3a).
  - No test checks line numbers after a splice when the match is on a later
    line.
  - No test of the splitlines drift (LOW-3b), or of an anchor that only
    appears inside a comment (LOW-3c).
  - No golden test that regenerating the report reproduces the evidence
    JSON.
  - The assertion all(item["r580_assignment"]) in test 1 can never fail.
  - I did not run any tests. Whether they pass is unverified.

Limitations of this review:
  - Static reading only; nothing was executed or hashed.
  - The 222-file count and the manifest hash in SOURCES.json are unverified
    (the Glob listing is consistent with 222 files).
  - Only 8 R580 files were supplied.
  - Neither the RM source (open or proprietary flavor) nor the
    nv_uvm_types.h header is in the bundle.

========================================================================
5. OPEN QUESTIONS
========================================================================
  1. Does R615's RM (whichever flavor the hybrid targets) still support
     GV100, and does it reject EnabledNoPlc for GV100 inside
     nvUvmInterfaceGetExternalAllocPtes, and with what error code?
  2. Which other R580 files used these fields, for example uvm_gpu.c,
     uvm_va_block.c, uvm_gpu_non_replayable_faults.c, uvm_user_channel.c?
     They are not in the excerpt.
  3. Did R580's Volta MMU code define its own sparse page-table entry, and
     does it match Turing's _MMU_VER2 entry (uvm_turing_mmu.c:329-333)?
  4. Are the R615 uvm.h:1799 and :1886 notes stale documentation, or
     enforced somewhere outside nvidia-uvm?
  5. Does the supplied R615 tree hash to 994da262…2fbf? This needs a run
     outside this review.

========================================================================
6. NEXT REVIEW ACTION
========================================================================
For iteration 2:
  (a) Ask the author to fix MEDIUM-1 and MEDIUM-2 and LOW-1/LOW-2 in the
      map: GV100 HAL prerequisite, the uvm.h promises, the unmap-before-RM
      ordering, and gate-deletion line pairs for every row.
  (b) Ask for scanner tests covering LOW-3 (a)-(c), plus tests of the
      file-tree and archive readers using made-up files.
  (c) Re-check the revised map against the anchors in section 3.
  (d) If an RM source excerpt becomes available, check the PLC behavior
      inside RM (open question 1).
The completion marker is held until those are done.
```