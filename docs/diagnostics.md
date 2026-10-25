# Forwarding diagnostics

The runner uses loopback echo services and controlled fixture credentials, TLS mode 1 and standard-library Python only. It observes engine log milestones before attempting **one** TCP exchange and **one** UDP exchange. It does not retry application exchanges or silently recover from a restart. Its certificate milestone is a log observation, not a security proof.

## Targeted execution

```sh
go build -trimpath -o bin/tunveo ./cmd/tunveo
python3 scripts/verify_forwarding.py --binary bin/tunveo \
  --case 2:1 --case 1:2 --pool 2:8 --pool 64:1024 --repeat 3 \
  --artifacts artifacts/targeted
```

`--case` is `transport:server-mode`; transport 0=TCP, 1=QUIC, 2=WebSocket, 3=HTTP/2. Mode 1 exposes the front listener on the server; mode 2 exposes it on the client. `--pool` is `min:max`. Repeat either option to select more cells. With no case/pool options, the original eight-cell selection and min=2/max=8 remain the default.

For an unchanged upstream v1.17.0 binary:

```sh
python3 scripts/verify_forwarding.py --binary bin/tunveo --upstream /path/to/nodepass \
  --pair tunveo/tunveo --pair upstream/upstream \
  --case 2:1 --case 1:2 --pool 2:8 --pool 64:1024 --repeat 3 \
  --artifacts artifacts/comparison
```

`--pair` can also select either mixed direction. Without a pairing filter, providing `--upstream` retains all four pairings. Each runner is sequential. Different runner processes may run independently; record that execution mode when comparing evidence.

## Reports and lifecycle

Each invocation creates a new evidence directory, with `report.json` and numbered server/client logs. Existing artifact directories are rejected. `--output` can select a separate report path. The schema is now **version 2**, a report object containing metadata and `results`; it differs from the historical array in `docs/forwarding-results.json`.

The runner atomically saves the report at each phase transition, after process launch and after each completed row. SIGINT and SIGTERM preserve the interrupted row and reap the child processes. Phase statuses are `not_run`, `running`, `passed`, `failed` or `interrupted`. A failure preserves earlier successful stages; later stages remain `not_run`. The stages are:

1. Server startup: pending-handshake log milestone.
2. Tunnel handshake: both sending and receiving the configuration are observed.
3. Pool readiness: both control-connection readiness log milestones are observed.
4. Certificate verification: both completion logs are observed; fatal errors and restarts fail the stage.
5. TCP echo: exact 32 KiB payload equality.
6. UDP echo: exact 512-byte equality in a single datagram.
7. Cleanup: bounded simultaneous termination and reaping; forced kills are reported as cleanup failures.

Reports record binary SHA-256, binary version and Go build provenance when Go is available (`--go` selects its path), platform, selected parameters, first failure stage, application attempt counts, log paths and verification IDs. Engine output and command URLs are stripped of ANSI escapes and URL credentials before final persistence. Actual test credentials are synthetic; do not extend this runner to real secrets without a separate redaction review.

TCP/UDP ports are reserved for both protocols until the process that owns that listener is launched. There remains an unavoidable handoff race between releasing a reservation and an external executable binding its port; bind errors are preserved rather than silently retried.

Default time budgets: startup 5 seconds, each log milestone 15 seconds, each application exchange 3 seconds, cleanup 5 seconds shared across children. I/O uses a total deadline, so a dribbling peer cannot indefinitely reset it. Arguments can set explicit positive finite limits, which are recorded in the report.

Exit codes: 0=all selected cases passed; 1=at least one case failed; 2=invalid arguments/runner error; 130=interrupted. A successful diagnostic is not production-readiness or security certification. CI uploads failed-run evidence without suppressing the job's failure.

## Driver self-tests

```sh
python3 -m unittest discover -s scripts/tests -v
```

Controlled child executables and real sockets cover selection, payload checks, TCP-success/UDP-failure preservation, credential masking, SIGINT/SIGTERM persistence and reaping, whole-exchange timeout and truncated UDP handling. These tests validate the driver, not the tunnel engine.

## Deterministic TLS verification regression

```sh
go run ./scripts/repro_tls_verify
```

The executable uses real TLS/TCP pools with two connections: control plus one idle verification connection. It calls both real verification initiators before delivering either queued control signal, modelling bounded control-message delay. It checks that verification completes without cancelling either endpoint. The pool-get timeout is reduced to 100 ms **inside this fixture only**, with an independent 10-second watchdog. Current engine code exits 1; that failure is deliberate evidence of an unresolved defect, not an expected successful test. CI runs it in its own failing job.

For comparison, place the same command inside an upstream v1.17.0 checkout and change only the imports from `github.com/VortexWang/Tunveo/internal/common` to `github.com/NodePassProject/nodepass/internal/common`, and the TCP pool import to `github.com/NodePassProject/pool`. No upstream runtime implementation changes are required.

See [M1 findings](m1-findings.md), [defect ledger](defects.md) and the [evidence manifest](evidence/m1/manifest.json).
