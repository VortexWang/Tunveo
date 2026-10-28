# Go 1.26.10 / 1.27.3 RSS toolchain pilot

This diagnostic branches from PR35 head ea4874c4eedd51e89dec08e60c8bfb602dbcc552. Production sources, dependencies, go.mod, resource gates and the existing pair runner are unchanged.

A single Ubuntu runner builds ordinary/race binaries with each exact toolchain, then runs toolchains in old/new/new/old order. Each batch reuses scripts/soak_build_pair.py with ordinary/race/race/ordinary fresh processes, yielding four samples per version/build. Load, warmup, sampling and recovery remain the runner's existing 180s/12s/5s/120s profile. GOMAXPROCS=2 and empty GODEBUG/GORACE/GOEXPERIMENT apply equally. Toolchain auto-switching and setup-go cache are disabled.

Every batch runs even if an earlier batch fails its original 64MiB RSS increment gate. Failed originals and exit codes remain in artifacts, and any batch failure fails the workflow. The binary bytes, source hashes, host information, report/events/logs, per-point violations and summary are uploaded even on failure. This is a fresh-process short pilot, not the PR35 repeated-process/THP-controlled profile, and never grants 24h acceptance.

Compare matched build samples across toolchains using raw baseline/peak/delta, RSS violations and recovery data; require consistent results across both batches. A passing short pilot supports a subsequent unchanged three-cycle validation; it does not establish resolution of PR35's cumulative RSS growth. No threshold relaxation or historical failure deletion is permitted.

Local validation: existing 120 Python tests pass; workflow YAML and embedded Python parse. Go builds and RSS measurements require CI; no new results are claimed here.
