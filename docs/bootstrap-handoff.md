# Bootstrap handoff

The source repository is https://github.com/VortexWang/Tunveo.git. The initial implementation is prepared locally, but this environment has no authenticated Git write access to that repository. The GitHub connector reports read access only, and a Git push dry-run failed because no credentials were available. No remote commit, tag, release or container publication was made.

The handoff Git bundle contains the complete NodePass ancestry, the upstream baseline tag and the Tunveo initialization commits. To import the bundle on a machine with authorized write access:

```sh
git clone -b main Tunveo-bootstrap.bundle Tunveo
cd Tunveo
git remote set-url origin https://github.com/VortexWang/Tunveo.git
git push -u origin main
# Optional provenance tag; this namespace does not trigger the v* release workflow.
git push origin refs/tags/upstream/nodepass-v1.17.0
```

If the remote gains commits before import, fetch and review them first. Do not force-push over someone else's work. Do not push the original upstream `v1.17.0` tag as a Tunveo release.

Read `docs/validation.md` before deployment. The forwarding diagnostic exposes inherited timeouts and is intentionally allowed to fail visibly in CI. Security fixes and dependency upgrades have not yet been made in the bootstrap commits.
