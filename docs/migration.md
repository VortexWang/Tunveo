# Tunveo baseline migration

## Identity and layout

- Repository and module: `github.com/VortexWang/Tunveo` (case-sensitive module spelling).
- Command: `tunveo`; source entry point: `cmd/tunveo`.
- Pool packages: `internal/tunnelpool/{tcp,quic,websocket,http2}`.
- Existing `common.TransportPool` interface and the pool type numbers 0/1/2/3 are retained.
- One root Go module; no submodules, vendor edits or local replace directives.

## Intentional compatibility boundaries

Protocol fields, URL schemes, API routes and transport implementation behavior are retained in this migration. New/old binary interoperability still requires end-to-end verification; source similarity alone does not establish it.

The inherited `NP_*` environment variables remain supported and are deliberately unchanged in this baseline. They are compatibility settings, not the product name. A future `TUNVEO_*` alias scheme should be implemented and tested separately rather than silently changing environment behavior during the move.

Master state now uses `gob/tunveo.gob` beside the executable; exported instance configuration uses `tunveo.json`. No automatic migration from `nodepass.gob` or `nodepass.json` is performed. Before attempting a migration, stop the old process, preserve a backup, and use an isolated directory. Cross-module GOB state and instance import compatibility must be validated before production migration. Do not run both binaries against the same state directory.

## Validation gates

1. Verify upstream commits and original source/license hashes.
2. For the original migration comparison, use the recorded Go 1.26.5 baseline. Current maintained Tunveo requires Go 1.26.10 or newer; security-upgrade reports compare exact recorded toolchains and modules rather than assuming identical builds.
3. Confirm no module dependency remains on the four upstream wrapper modules.
4. Run module verification, vet, unit tests and race-enabled tests.
5. Exercise TCP/UDP business forwarding through all supported transport/TLS combinations.
6. Exercise reconnect, pool exhaustion, Flush/Close and repeated start/stop.
7. Test old-client/new-server and new-client/old-server interoperability.
8. Compare goroutines, file descriptors and memory under repeated reconnect and sustained load.

Compilation and static checks do not complete gates 5–8. Existing upstream defects must be tracked separately from migration regressions and assessed before release.

## Follow-up audit candidates

No fix is implied by importing the code. Verify concurrent map/channel replacement in Flush; ID publication before connection storage; TCP concrete type assertions; and HTTP/2 stream deadlines affecting shared connections. Dependency upgrades and security fixes should be separate changes with targeted regression evidence.

## Reproduce forwarding diagnostics

```sh
python3 scripts/verify_forwarding.py --binary bin/tunveo
# Add the original v1.17.0 binary to test all four server/client pairings:
python3 scripts/verify_forwarding.py --binary bin/tunveo --upstream /path/to/nodepass --output results.json
```

Each pairing covers four pool transports, two flow modes and both TCP and UDP echo traffic, using TLS mode 1 and a small pool (min=2, max=8). These are smoke/edge diagnostics, not full protocol, load, security or TLS-mode coverage. Intermittent failures remain visible and fail the forwarding CI job; the compile/static check job is separate. Fixes must not be disguised as a relocation-only change.


## TLS and log safety changes

- Invalid `tls=2` files now stop startup with exit code 1; deployments that depended on an automatic self-signed fallback must fix certificate paths/pairs. `tls=1` generation failure also aborts, and unknown TLS mode values are rejected.
- Reload errors retain the last successful certificate pair. Certificate validity/trust are still checked by TLS clients; loading a pair does not prove a trusted or unexpired chain.
- URL userinfo, complete URL queries and fragments are masked in logs. APIs/state/config exports still contain operational credentials and require their existing access controls; this patch does not sanitize all management data.
- API key values are removed from startup/load/rotation logs. Read an existing key with `tunveo api-key --state /path/to/gob/tunveo.gob`, or consume the authenticated rotation response. The explicit local command prints the key and must not be captured in routine logs.

See [security fix record](tls-log-safety.md) for validation and remaining risks.

Current build requirements and dependency changes: [Go/HTTP2 security update](security-dependencies.md). Rebuild binaries to obtain standard-library fixes; changing only external module versions does not update an existing executable.


## Reload interval validation

`NP_RELOAD_INTERVAL` must be a strictly positive Go duration. Unset preserves the one-hour default. Explicit zero, negative, empty, malformed or overflowing values now stop server/client/master startup with exit code 1, before opening service listeners or creating master state. Earlier invalid values could silently use the default, while zero could crash the master after state creation. Remove the environment variable to use the default, or set a value such as `1h` and restart. Empty is not equivalent to unset.

Other zero-valued timeouts retain their existing meanings. Help, version and explicit local API-key retrieval remain usable with an invalid reload setting. See [TNV-013](reload-interval.md) for scope and regression evidence.


## Idle pool ownership

[TNV-003](pool-publication.md) changes private idle bookkeeping for all four backends. Wire IDs/control frames and pool method signatures are unchanged; no configuration or state migration is required. Getting a specific ID now preserves other FIFO entries, and cancellation/deadline errors wrap their context cause. Treat errors as errors rather than parsing exact strings. This does not add full restart-generation fencing or change HTTP/2 physical-connection deadline behavior.


## Run and pool lifetime

[TNV-004](run-lifecycle.md) makes Client/Server.Start and pool managers single-use. Construct a fresh endpoint/pool after Stop/Close. Run/RunWithContext retain automatic retry by creating a fresh runtime for each attempt. Client/Server now embed *common.Common; internal callers using struct literals must supply a pointer. Runtime channels, cache, address snapshots and resources reset per attempt; cumulative statistics and thread-safe buffers remain shared. Flush fences pending setup and old waiters, while Close also terminates leased resources. No wire, state, configuration or dependency migration is required. Public HTTP/2 deadline forwarding remains TNV-005.


## HTTP/2 stream deadlines

[TNV-005](h2-stream-deadlines.md) supersedes the H2 deadline limitation noted above: deadlines now affect only the logical stream, can be reset after expiry, and do not set the physical TLS connection deadline. Timeouts expose os.ErrDeadlineExceeded through errors.Is. A timed-out Write can accept partial data; continue after clearing the deadline using its returned byte count. Close cancels pending work for that stream. No configuration, wire or state migration is needed. Shared HTTP/2 connection flow control still causes ordinary backpressure. Extra bounded buffering/workers require later performance validation.


## Management request and SSE boundaries

[TNV-009A](management-boundaries.md) fails closed with 503 if the API-key entry is missing/empty; invalid or duplicate key headers get 401. Restore valid persisted credentials rather than relying on an unauthenticated mode. Public docs/preflight remain available. Protected request bodies are limited to 1 MiB (413), must contain one JSON value, and have a read budget. Ordinary requests and SSE each allow 32 concurrent operations per master (429); clients should back off.

SSE accepts bodyless GET, excludes the master API-key entry and disconnects on rotation. Reconnect with the new key; do not require a final shutdown data frame. Heartbeats run every 15s, each write has a 5s budget cleared after successful Flush. Existing authenticated REST credential responses and local api-key retrieval remain available. State/wire/dependencies are unchanged; local import files, instance totals and background process workloads are not capped by the HTTP body/handler limits. Full Instance concurrency and shutdown auditing remain TNV-009B.
