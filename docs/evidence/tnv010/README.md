# TNV-010 evidence

See [offline migration and rollback runbook](../../state-migration.md).

migration-final covers 22 checks using original v1.17.0 declarations/save code and an actual clean original binary. Fixture provenance and old binary build info are in the report. Runtime oracle rows have Restart=false; credentials/config JSON are compared only in memory. Byte-preserving transfer, no-overwrite/refusal paths, current save, periodic backup and actual old-runtime rollback are checked.

lifecycle-final (and log), management-final, security-final and reload-final are current clean-binary compatibility regressions. full-race, repeated-race and vet retain successful command output. Native tests also cover concurrency/permissions/no-clobber and an injected target failure after backup; they do not simulate real power failure.

metadata records both current clean binaries, source, scope and compile-only Windows status. No GOB files or credentials are published. SHA256SUMS covers every evidence file except itself.
