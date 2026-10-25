# TNV-005 evidence

See [design and limits](../../h2-stream-deadlines.md).

- before-native / after-native: same final fixture and driver, 40 observations each, real TLS/H2 pools, two streams on one physical connection. Old expected defects vs new isolation/timeout/reset behavior.
- matrix-*: complete 48 cells, 47 passed. One old-server initial HTTPS EOF in type=2, before pool creation, retained. All 12 HTTP/2 cells passed.
- reconnect-final: eight cases, one server replacement each, persistent client; all process logs/results retained.
- security-final / reload-final: final normal binary 20/24 process cases.
- full-race-final2 / repeated-race-final2 / vet-offline: successful full race, ten-repeat HTTP2 race and vet command output. Dependencies resolved from existing local module cache.
- pilots: intermediate failed baseline/adapter/fixture observations, not the final comparison; see metadata limitations. No failures overwritten as successes.
- metadata: binary SHA/build information, code/fixture source distinction and scope.

Paths in JSON are relative to each report, binary prefixes BUILD/. Log bytes/outcomes unchanged. SHA256SUMS covers each evidence file except itself. Synthetic credentials; no production state.
