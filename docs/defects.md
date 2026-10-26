# Tunveo defect ledger

Updated 2026-10-26. Status describes evidence, not a vulnerability severity certification. M1 baseline records are immutable; subsequent scoped fixes are recorded separately.

| ID | Status | Evidence / impact | Next action |
| --- | --- | --- | --- |
| TNV-001 | Diagnostic change verified | Nine runner/exchange tests pass; staged results, targeted selection, durable reports, cleanup and redaction implemented | Review PR; retain schema and lifecycle tests |
| TNV-002 | Implemented and scoped validation passed; pending integration | Negotiated single initiation with correlated acknowledgement; legacy peer-first sequencing. Forty real-pool flow cases and final 48-cell matrix passed | Review stacked fix PR and retain regression; full release/long-run gates remain |
| TNV-003 | Implemented; native TCP mechanism/compatibility regression passed, pending integration | Unified idle FIFO/ID ownership across four transports; prior native TCP tests reproduce publication loss and mismatched notification 20/20, fixed 20/20; forwarding 48/48 | Review pool publication PR; retain scheduling/ID tests; full lifecycle remains TNV-004 |
| TNV-004 | Implemented for reproduced scope; pending integration | Fresh runtime per retry, permanent pool lifetime, Flush generation fence, bound physical metadata; native before 30/30 reproduced / after 30/30 passed; race reconnect 8/8; forwarding 47/48 with legacy-server initial EOF retained | Review lifecycle PR; retain cancellation tests; legacy EOF and long-run/release gates remain |
| TNV-005 | Implemented for reproduced scope; pending integration | Per-stream resettable deadlines, bounded lazy I/O pumps, joined Close and request cancellation; native same-connection before 40/40 reproduced / after 40/40 passed; H2 compatibility 12/12, reconnect 8/8 | Review H2 deadline PR; retain multi-stream tests; shared flow control and performance/long-run gates remain |
| TNV-006 | Implemented; scoped validation passed, pending integration | Missing/unreadable/malformed/mismatched strict pairs abort startup; 15 process cases across server/client/master include invalid mode values | Review security fix PR; complete transport-specific trust/expiry matrix separately |
| TNV-007 | Startup downgrade and reload publication patched; broader audit open | Injected generator failure returns error; immutable certificate pointers and mutex protect reload; concurrent test and real HTTPS rotation/failed reload pass | Retain race test; audit remaining TLS lifecycle and trust boundaries |
| TNV-008 | Known URL/API-key log paths patched; scoped validation passed, pending integration | Engine log sink masks URL userinfo/query/fragment; startup omits tunnel key; API-key lifecycle logs omit values; explicit local read command added | Review compatibility note; authenticated API/state/export contents and arbitrary text secrets remain separate audit scope |
| TNV-009 | Parts A/B implemented for reproduced scope; pending integration; broader audit open | A entry/SSE boundaries retained; B serializes mutable state and detached snapshots, bounds import/process workloads and owns child generations/Wait/shutdown; native baseline DATA RACE reproduced, fixed regression passed | Review stacked A/B PRs; proceed to offline migration/rollback; retain public-network, duration/performance and broader policy/fault gates |
| TNV-010 | Offline tooling and scoped compatibility implemented; pending integration | GOB byte-preserving migrate/restore, no-clobber synced copies, strict inspection/loading; 22 cross-version checks include actual v1.17.0 master and periodic backup restore | Review migration PR; retain operator preflight/backup; production-size, filesystem and power-loss recovery remain release gates |
| TNV-011 | Security upgrades implemented; scoped rescan passed, pending integration | Go 1.26.10 / x/net v0.60.0 reduce static called IDs 15 → 5 → 0; one module-only OpenPGP advisory remains, with no affected package imported | Review dependency PR; preserve scan gate and assess new database findings; not a blanket security clearance |
| TNV-012 | New-server early-close path fixed; scoped validation passed | Full response is written and flushed before listener transition; capability tests exercise 30 real HTTPS handshakes | Old servers remain unchanged; controlled completion barrier now reproduces old EOF 10/10 and current complete replies 10/10; historical random failures still require separate attribution |
| TNV-013 | Startup validation implemented; scoped regression passed, pending integration | Zero/negative/empty/malformed/overflowing reload values reject service startup before state/listeners; 24 process cases pass and prior panic remains recorded | Review fix PR and migration note; other interval parameters/full maintenance lifecycle remain separate audit scope |
| TNV-014 | Implemented; scoped CI passed, pending integration | HTTP/2 tls=0 returned a nil pool and started a nil manager; promote to TLS 1 and reject invalid pool setup | Retain real process and nil-config regressions; see [TLS matrix](tls-support-matrix.md) |
| TNV-015 | Implemented; scoped CI passed, pending integration | Preserve DNS/IP identity, strip default IPv6 route zone, honor explicit WebSocket SNI without rewriting URL/HTTP Host; real before/after reproduces 6+2 failures and fixes them | Review [identity and expiry evidence](tls-identity.md); retain strict validation and full compatibility gates |
| TNV-016 | Implemented; controlled proof and corrected full measurement passed for maintained peers, pending integration | Unbound loopback TCP/UDP probes can self-echo without a listener; bind a distinct source, record successful echo endpoints, never count setup errors as TLS rejection; original20/20 reproduced, fixed20/20 rejected | Preserve first uninstrumented anomaly; corrected 4160-cell coverage complete, 41 old-server failures remain; see [TLS acceptance](tls-identity.md) |

Evidence, exact baseline commits and scope limitations are in [M1 findings](m1-findings.md) and [TNV-002 fix](tnv-002-fix.md). Unfixed security observations must not be presented as resolved by redacting the diagnostic artifact or by adding a test.

TLS/log changes and process evidence: [security fix record](tls-log-safety.md).

Dependency changes and staged scan evidence: [TNV-011](security-dependencies.md).

Reload-period validation and before/after evidence: [TNV-013](reload-interval.md).

Idle publication/ID claim changes and scoped evidence: [TNV-003](pool-publication.md).

Run/pool ownership, intermediate failures and compatibility limits: [TNV-004](run-lifecycle.md).

HTTP/2 per-stream deadline and cancellation evidence: [TNV-005](h2-stream-deadlines.md).

Management entry/SSE scope and remaining TNV-009B: [TNV-009A](management-boundaries.md).

State/child ownership and bounded import follow-up: [TNV-009B](master-state-lifecycle.md).

Offline identity-preserving transfer and rollback: [TNV-010](state-migration.md).

Cumulative integration, packaging evidence and remaining release blockers: [integration readiness](integration-readiness.md). No defect is closed merely by adding a release gate.
