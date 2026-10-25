# Upstream provenance

The initial Tunveo commit ancestry retains NodePass v1.17.0 at `114345043d9608e1e24e783a270cde75193e4f42`. The local tag `upstream/nodepass-v1.17.0` identifies that baseline; it is not a Tunveo release.

The four bundled v1.1.1 libraries were initially imported byte-for-byte with their full licenses. `sources.json` records their resolved commit identities, original SHA-256 hashes, original import paths and current locations. Only package declarations change when the TCP, WebSocket and HTTP/2 directories become functional internal package names. The QUIC implementation remains byte-for-byte unchanged in this migration.

The root LICENSE is retained unchanged from upstream. NOTICE connects each library to its license and provenance. Redistribution archives and the container include these notices.

Direct upstream module dependencies are replaced by internal packages. Third-party dependencies remain external modules, managed at the root. Internalization does not remove responsibility to track upstream advisories and inherited code defects.

Subsequent maintained changes: [TNV-003](../pool-publication.md) replaces the four libraries' private idle map/channel bookkeeping with a shared atomic FIFO/ID registry. The original import hashes in `sources.json` remain historical provenance; they are not claimed as hashes of the subsequently patched files. Licenses and original notices remain intact.
