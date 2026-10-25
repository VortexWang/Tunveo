# TNV-004 evidence

Runtime source: `665e751c2f4442c8f412429711d830000d16fc2a`. See [design and limits](../../run-lifecycle.md).

- before-native / after-native: identical canonical template and runner, 30 controlled native TCP race observations each; old reports expected defects, new expects rejection/cancellation.
- reconnect-final: eight cases, persistent client process, one orderly server replacement; all process logs and per-case results.
- matrix-*: complete 48-cell run, 47 passed and one legacy-server initial HTTPS EOF, retained unchanged.
- handshake-investigation: independent ten-repeat targeted run on final source, no application retries within a case; not a replacement of the failed matrix cell.
- handshake-baseline: same targeted case with previous Tunveo binary and original/original controls. Full outcomes, including unrelated legacy verification failures, retained. This is observational comparison, not proof of an EOF root cause.
- reconnect-pilot / reconnect-confirm-deadline: two intermediate implementation failures, not baseline source. Logs/hashes retained; dirty pilot binaries are not final artifacts.
- security / reload-interval: final normal-binary process regressions.
- metadata: final binary hashes/build info, result counts, scope and provenance.

Paths in JSON are portable relative to each report; binary paths use BUILD/. Logs and outcome values were not rewritten. SHA256SUMS covers every evidence file except itself. No production credentials or state were used.
