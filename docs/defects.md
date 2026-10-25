# Tunveo defect ledger

Updated 2026-10-25. Status describes evidence, not a vulnerability severity certification. No engine fix is included in the M1 diagnostic change.

| ID | Status | Evidence / impact | Next action |
| --- | --- | --- | --- |
| TNV-001 | Diagnostic change verified | Six runner tests pass; staged results, targeted selection, durable reports, cleanup and redaction implemented | Review PR; retain schema and lifecycle tests |
| TNV-002 | Root cause reproduced; unfixed | Both peers can consume the same TLS verification connection before either peer processes its signal. Real TCP fixture reproduces on both versions 10/10; targeted WS/QUIC logs show matching IDs and subsequent timeouts | Define verification connection ownership/direction, fix with minimal protocol impact, make regression pass and repeat affected matrix |
| TNV-003 | Source risk awaiting isolation | Some ID notifications precede connection storage | Controlled publication-order test; do not equate this with TNV-002 |
| TNV-004 | Source risk awaiting isolation | Flush/Close replace shared state while workers may still run | Lifecycle/race tests and explicit ownership model |
| TNV-005 | Source risk awaiting isolation | HTTP/2 deadlines are forwarded to a shared physical connection | Multi-stream deadline/cancellation regression |
| TNV-006 | Downgrade behavior confirmed; unfixed | Invalid strict-mode certificate paths log failure, fall back to TLS mode 1 and leave server running | Fail clearly on invalid initial strict configuration; document compatibility change |
| TNV-007 | Partially inspected, not reproduced | TLS generation failure fallback and hot-reload shared state remain separate concerns | Fault injection and concurrent certificate reload tests |
| TNV-008 | Synthetic credential logging confirmed; unfixed in engine | Engine emits test URL credentials in startup logs; runner now masks its saved evidence only | Fix engine log construction and test all secret-bearing outputs |
| TNV-009 | Audit pending | API/MCP/SSE authentication, limits and process management | Threat-oriented request and resource tests |
| TNV-010 | Migration not verified | State/export names changed; GOB and import compatibility remain unverified | Offline sample, backup, import and rollback tests |
| TNV-011 | Static scan findings recorded; unfixed | 15 unique advisories have symbol-level call traces; 20 module/advisory pairs across stdlib and x/net. This does not establish exploitability | Fast-track assessed Go and HTTP/2 security updates as separate changes, then rescan |
| TNV-012 | One EOF observed; cause unassigned | One WS mode-1/default-pool run logs server sending config while client receives HTTPS EOF | Isolate response-write/server-close timing; preserve as separate failure |

Evidence, exact baseline commits and scope limitations are in [M1 findings](m1-findings.md). Unfixed security observations must not be presented as resolved by redacting the diagnostic artifact or by adding a test.
