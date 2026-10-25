# Tunveo · 隧维

Tunveo is an independently maintained TCP/UDP tunnel forwarding tool derived from NodePass v1.17.0. It retains server, client and master modes and brings the TCP, QUIC, WebSocket and HTTP/2 pool implementations into one repository.

本项目基于 NodePass v1.17.0 独立维护，首轮工作为品牌更名、四库内置和验证基线建立。当前为开发基线，不代表已完成安全审计或漏洞修复，也尚未发布正式版本。

## Build

Use Go 1.26.10 or newer; the maintained security baseline is pinned in `go.mod`:

```sh
git clone https://github.com/VortexWang/Tunveo.git
cd Tunveo
go build -trimpath -o bin/tunveo ./cmd/tunveo
./bin/tunveo version
./bin/tunveo help
```

## Quick start

Example: forward a local TCP service through a tunnel. Run a service on port 3000 at the server, then start:

```sh
# Server: require a certificate for authenticated production deployments.
./bin/tunveo server --tunnel-port 10101 --target-addr 127.0.0.1 --target-port 3000
# Client: connects to the server and exposes the forwarded service locally.
./bin/tunveo client --tunnel-addr server.example.com --tunnel-port 10101 --target-addr 127.0.0.1 --target-port 3000
```

The example uses the inherited default plaintext mode. TLS mode 1 encrypts traffic without validating the peer certificate; use mode 2 with an appropriate certificate for certificate validation. See the configuration documentation for the behavior of each transport.

## Validation status

Local builds, module verification and vet pass. Initial loopback TCP/UDP checks also expose intermittent TLS-mode-1 verification timeouts; a timeout was reproduced with the unchanged upstream binary. The diagnostic matrix reports failures with a nonzero exit status. This baseline is not ready for a stable release. See [validation notes](docs/validation.md).

## Development

```sh
go mod verify
go vet ./...
go test ./...
go test -race ./...
```

- [开发与维护计划](docs/development-plan.md)
- [诊断工具](docs/diagnostics.md)、[M1 定位结果](docs/m1-findings.md)、[缺陷台账](docs/defects.md)
- [TNV-002 修复记录](docs/tnv-002-fix.md)、[校验协议](docs/tls-verification.md)
- [Installation](docs/installation.md)
- [CLI](docs/cli.md), [configuration](docs/configuration.md), [API](docs/api.md), [MCP](docs/mcp.md)
- [Migration and compatibility](docs/migration.md)
- [Upstream provenance](docs/upstream/README.md) and [source records](docs/upstream/sources.json)
- [Security policy](SECURITY.md)

The detailed usage documents were inherited from upstream and renamed. Their examples and claims are not a substitute for the compatibility checks tracked in the migration document.

## Origin and license

Based on [NodePass v1.17.0](https://github.com/NodePassProject/nodepass/tree/v1.17.0), with the `pool`, `quic`, `npws`, and `nph2` libraries at v1.1.1 incorporated as internal packages. Original copyright notices and BSD-3-Clause licenses are retained. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Tunveo is independently maintained and is not an official NodePass release. Upstream names are used for attribution and compatibility documentation. No upstream logos, sponsorships, donations, community channels or distribution scripts are adopted as Tunveo branding.

TLS startup failures and credential-safe logs: [security fix and migration notes](docs/tls-log-safety.md).

Go/HTTP2 dependency security baseline and scan scope: [TNV-011](docs/security-dependencies.md).

Reload interval startup validation and migration: [TNV-013](docs/reload-interval.md).
