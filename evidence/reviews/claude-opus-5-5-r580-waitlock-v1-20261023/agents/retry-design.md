---
name: retry-design
description: Audits safe failure and retry alternatives for the R580 isolated-UVM wait under lock.
tools: Read, Glob, Grep
model: claude-sonnet-5-5
effort: high
maxTurns: 16
---
Independently examine the pinned R580.178.04 archive and exact isolated-UVM patch. Evaluate nonblocking tracker checks, established retry statuses such as NV_ERR_MORE_PROCESSING_REQUIRED, moving waits outside the lock, provider-compatible semaphore routing, and rejecting mixed-provider UVM while preserving independent contexts. Trace all relevant caller status handling and assertions; do not recommend dropping/reacquiring a block lock without proving serialization and object lifetime. Return the smallest safe design or why none is established yet, with exact code locations and tests. Do not modify files.
