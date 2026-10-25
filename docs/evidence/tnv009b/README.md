# TNV-009B evidence

See [design, scope and limits](../../master-state-lifecycle.md).

before-state / after-state exercise real production log mutation, REST and JSON/GOB/event encoding using the same final native fixture. Baseline must report DATA RACE and a mutable queued snapshot; fixed must exit successfully without race. Test cleanup differs only in available helper support, recorded in metadata.

process-final is the clean race master/managed-child runner (8 scenarios), with its complete captured log. It records all observed startup and unique-Wait reap PIDs. It does not use /proc or send tunnel traffic. management-final/security-final/reload-final retain 22/20/24 compatibility cases. Full race, ten-repeat master race and vet command outputs are included.

pilots retains failed intermediate implementation/fixture results and available logs, plus the initial CI cleanup failure excerpt. These are dirty intermediate binary hashes, not final runtime provenance or frozen source reproductions. The earliest pilot did not save stdout. Final outcomes were not substituted into failed reports.

metadata records clean build SHA/source, fixture revision and limitations. Build binary prefixes use BUILD/; report/log bytes remain unchanged. Synthetic keys, isolated state; no production files. SHA256SUMS covers all files except itself.
