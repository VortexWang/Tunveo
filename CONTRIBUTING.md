# Contributing to Tunveo

Use Go 1.26.5 and the module path `github.com/VortexWang/Tunveo`.

Build with `go build -o bin/tunveo ./cmd/tunveo`. Before submitting changes, run `go mod verify`, `go vet ./...`, `go test ./...` and `go test -race ./...`. Add targeted regression cases for behavioral fixes; successful compilation is not a tunnel compatibility test.

Keep migrations, bug fixes, dependency upgrades and protocol changes in separate commits. Preserve upstream notices and update `docs/upstream/sources.json` when imported implementations change. Internal packages are maintained as part of the root module and do not have separate go.mod files.

Use a feature branch and open a pull request at https://github.com/VortexWang/Tunveo. Include the problem, resulting behavior, compatibility impact and verification evidence. Security disclosures follow SECURITY.md.

The real forwarding smoke test is `python3 scripts/verify_forwarding.py --binary bin/tunveo`. See `docs/validation.md` for known baseline failures.
