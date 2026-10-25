# Tunveo bootstrap import record

The development baseline is published at https://github.com/VortexWang/Tunveo.

The repository preserves the complete NodePass ancestry at base commit `114345043d9608e1e24e783a270cde75193e4f42` and these exact Tunveo commits:

- `8d8629957bed35aacc1bd90c4ccc56636e3d1011`: original four-library import, licenses and provenance.
- `8eabcdc455a5b1c9a02ab92f552bf71b5a86570c`: Tunveo identity and internal package integration.
- `62bb7c84d4d5d3e739bd7819cb59f140360de7a3`: diagnostic script, CI and recorded baseline failures.

History reconstruction verifies the SHA-256 import manifest, every source tree and every commit object ID. The resulting history is attached to the repository initialization with a merge commit; no existing branch history is overwritten. Temporary import helpers are not included in the current source tree.

To continue development:

```sh
git clone https://github.com/VortexWang/Tunveo.git
cd Tunveo
go build -trimpath -o bin/tunveo ./cmd/tunveo
```

Use Go 1.26.5. See `docs/validation.md` and `docs/forwarding-results.json` before deployment. The baseline has known forwarding diagnostic failures, including failures reproduced on unchanged upstream. Security fixes and dependency upgrades are separate follow-up work; this import does not certify a stable release.

The previously supplied Git bundle remains an offline copy of the three exact initialization commits and their original ancestry. No Tunveo release tag or container image is published by this import.
