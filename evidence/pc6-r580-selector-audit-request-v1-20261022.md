# PC6 independent R580 selector ABI audit

Read the immutable snapshot in `input/`. The SHA-256 manifest is
`input/INPUT_MANIFEST.json`. Work only in this new run directory. Do not
inspect or alter any PC1/PC3 path, load a kernel module, touch a GPU, install a
driver, or use tools outside the provided snapshot. Write only
`output/AUDIT.md`; leave all input files unchanged.

Use the configured read-only `sonnet-selector-auditor` subagent once to
independently challenge the argument flow and propose a counterexample or
failure mode. Then reconcile its findings yourself. The parent Opus session
owns the final report; the subagent must not write files.

Answer this narrow question: what does the current static and hardware evidence
actually establish about the selector argument passed into
`_nv031399rm`, and what is the smallest safe experiment that would capture its
runtime value on the PC3 V100 guest?

The audit must:

1. Verify the supplied manifest hashes for the files you inspect.
2. Trace each link from `_nv000790rm` through the record field to
   `_nv031364rm` and `_nv031399rm`, citing exact JSON/log file and object
   offsets/instructions. Distinguish disassembly observations from recovered
   source code.
3. State the x86-64 function-entry argument registers and assess whether the
   already compiled observer can read the second argument via its existing
   `regs_get_kernel_argument(registers, 1)` pattern. Check the 6.8 ABI and
   access safety against the supplied module source; do not assume a direct
   `regs->si` access is portable.
4. Challenge the conclusion: inspect callsites and control-flow gates, explain
   what the live count-only v3 report proves, and what it does not prove about
   causality, selector equality, descriptor-cache hit/miss, or CUDA.
5. Recommend a minimal bounded scalar-only capture design, including races,
   atomicity, counter/delta semantics, invalid/unavailable reporting, cleanup,
   and a hardware acceptance criterion. Do not modify or write any code.
6. Separate direct hardware observation, reproducible test, static finding,
   inference, hypothesis, and unknown. End with a clear implement/defer
   decision and its decisive evidence.

Do not claim the full Volta/Blackwell hybrid objective is achieved. Do not emit
`<promise>R580 SELECTOR ABI AUDIT COMPLETE</promise>` until `output/AUDIT.md`
exists and contains all six required sections plus the subagent's critique.
