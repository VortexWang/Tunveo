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
2. Build upstream and Tunveo using Go 1.26.5; compare selected external dependency versions.
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
