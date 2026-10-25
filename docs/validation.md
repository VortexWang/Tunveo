# Bootstrap validation — 2026-10-25

Environment: Linux amd64, Go 1.26.5. This is an initial source migration, not a stable release or completed audit.

## Completed checks

- Original NodePass v1.17.0 builds successfully.
- Tunveo builds successfully; `version` and `help` show the new identity.
- `go mod verify`, `go mod tidy -diff` and `go vet ./...` pass.
- `go test ./...` and `go test -race ./...` complete, but all packages have no Go test files. These commands do not demonstrate exercised race-free behavior.
- All selected external module versions match upstream. Only the four internalized wrapper modules are removed from the external module graph.
- The root LICENSE and four library licenses match the original bytes. Library implementation hashes match after reversing only the documented package-declaration changes.
- `git diff --check` passes.

## Forwarding diagnostics

The loopback matrix uses both server flow modes, four transports, TLS mode 1, min=2/max=8, a 32 KiB TCP echo and a 512-byte UDP echo. It tests Tunveo/Tunveo, upstream/upstream and both mixed-version pairings.

Initial runs expose intermittent `OutgoingVerify` timeouts, including in the unchanged upstream v1.17.0 binary. Individual successful runs must not be interpreted as a reliable pass for a transport. Root cause and retry/lifecycle behavior require follow-up analysis; no fix is included here. The complete matrix results will be recorded with the diagnostic commit.

The forwarding CI job intentionally returns a failure when its diagnostic fails; compilation/static checks are a separate job. No failures are suppressed or declared expected passes.

## Not yet verified

TLS modes 0 and 2 across all supported combinations; internet/NAT conditions; long-running load; reconnection/Flush/Close races; native cross-platform execution; state/import migration across module names; Docker image execution; GoReleaser execution; dependency vulnerability scanning and source security audit.
