# Tunveo defect ledger

Updated 2026-10-25. Status describes evidence, not a vulnerability severity certification. M1 baseline records are immutable; subsequent scoped fixes are recorded separately.

| ID | Status | Evidence / impact | Next action |
| --- | --- | --- | --- |
| TNV-001 | Diagnostic change verified | Six runner tests pass; staged results, targeted selection, durable reports, cleanup and redaction implemented | Review PR; retain schema and lifecycle tests |
| TNV-002 | Implemented and scoped validation passed; pending integration | Negotiated single initiation with correlated acknowledgement; legacy peer-first sequencing. Forty real-pool flow cases and final 48-cell matrix passed | Review stacked fix PR and retain regression; full release/long-run gates remain |
| TNV-003 | Source risk awaiting isolation | Some ID notifications precede connection storage | Controlled publication-order test; do not equate this with TNV-002 |
| TNV-004 | Source risk awaiting isolation | Flush/Close replace shared state while workers may still run | Lifecycle/race tests and explicit ownership model |
| TNV-005 | Source risk awaiting isolation | HTTP/2 deadlines are forwarded to a shared physical connection | Multi-stream deadline/cancellation regression |
| TNV-006 | Implemented and locally verified; pending integration | Invalid initial tls=2 material now aborts before runtime construction with exit 1. Fifteen executable startup cases and valid TLS 1.3 certificate handshake passed | Review stacked fix; see [TNV-006 record](tnv-006-fix.md). Hot reload remains TNV-007 |
| TNV-007 | Partially inspected, not reproduced | TLS generation failure fallback and hot-reload shared state remain separate concerns | Fault injection and concurrent certificate reload tests |
| TNV-008 | Synthetic credential logging confirmed; unfixed in engine | Engine emits test URL credentials in startup logs; runner now masks its saved evidence only | Fix engine log construction and test all secret-bearing outputs |
| TNV-009 | Audit pending | API/MCP/SSE authentication, limits and process management | Threat-oriented request and resource tests |
| TNV-010 | Migration not verified | State/export names changed; GOB and import compatibility remain unverified | Offline sample, backup, import and rollback tests |
| TNV-011 | Static scan findings recorded; unfixed | 15 unique advisories have symbol-level call traces; 20 module/advisory pairs across stdlib and x/net. This does not establish exploitability | Fast-track assessed Go and HTTP/2 security updates as separate changes, then rescan |
| TNV-012 | New-server early-close path fixed; scoped validation passed | Full response is written and flushed before listener transition; capability tests exercise 30 real HTTPS handshakes | Old servers remain unchanged; other EOF causes must still be diagnosed separately |

Evidence, exact baseline commits and scope limitations are in [M1 findings](m1-findings.md) and [TNV-002 fix](tnv-002-fix.md). Unfixed security observations must not be presented as resolved by redacting the diagnostic artifact or by adding a test.
