# TNV-006 初始严格 TLS 配置修复

2026-10-25。以 PR #2 的 `03d62ede55b26183414971225a1a13c263fa8646` 为基线。
核对时 PR #1 仍为草稿、PR #2 为 open 且未合并；PR #2 最新提交的
[CI 40170022515](https://github.com/VortexWang/Tunveo/actions/runs/40170022515) 成功。
本变更叠加于 PR #2，尚不表示已经集成到 main 或可以发布稳定版本。

## 行为

`tls=2` 初始证书/私钥缺失、不存在、无法读取、PEM 损坏或不匹配时，返回配置错误；
错误经 createCore/start 传播，由 CLI 以状态 1 退出。错误发生在构造运行实例前，
不再进入服务监听、握手、自动重启，也不会回退到 RAM 证书模式。
该公共入口用于 server、master 和 client 的本地 TLS 配置，URL 与子命令输入均覆盖。

RAM 证书只在 `tls=1` 时生成；生成错误也向上传播，不再从此入口降级为明文。
此附带错误传播路径经过代码检查，未对随机源故障进行注入验证。
`tls=0`、有效的 mode-1/mode-2 配置继续工作；有效 mode-2 证书的热重载实现保持原样。

这是兼容性变化：以前依赖无效证书自动降级的部署需修正文件或明确改用 `tls=1`。
加载密钥对不等于验证证书有效期、域名、信任链或撤销状态。
热重载并发、轮换失败策略以及握手期间临时证书生成仍属 TNV-007，不能视为已解决。

## 本地验证

环境为 macOS arm64、Go 1.26.6；没有修改 go.mod、go.sum 或依赖版本。

- 九类无效输入 × 三种角色 × 四种池，共 108 个子用例：必须返回错误、空模式、nil 配置且不创建实例。
- 有效文件证书经真实 TLS 1.3 握手，逐字节核对客户端收到的证书；默认明文和 mode-1 配置检查通过。
- URL/子命令的 start 错误传播；子进程 run/exit 测试检查三种角色实际退出码 1。
- 修复前可执行文件在缺失证书时输出 mode-1 与 Server started，并持续运行直到测试终止。
- 修复后可执行文件：三角色 × 四池 URL，加三角色子命令，共 15/15 立即退出 1，无降级和 started 日志。
- `go test -race ./...`、`go vet ./...`、`go mod verify`、`go mod tidy -diff` 通过。
- 真实 TLS/TCP 池的两个流向校验回归通过；四传输 × 两流向的小池 tls=1 转发 8/8，通过 TCP/UDP 回显与进程清理。
- Python 3.12.14 诊断驱动测试 6/6 通过。首次系统 Python 3.9.6 为 5/6：已有慢速 TCP 测试仅捕获 TimeoutError，
  而该版本可能抛出独立的 socket.timeout，产生一次 ERROR。未改写该次失败，也未将其归为 TLS 修复通过项。

[启动对照](evidence/tnv006/startup.json)、[转发记录](evidence/tnv006/forwarding/report.json)
与 [SHA-256 清单](evidence/tnv006/manifest.json) 保留本次二进制结果。证据中的临时路径、凭据做了替换；
baseline 是原提交的 tls.go/run.go 通过 Go overlay 构建，生产源码与基线一致。
不声称完成严格 TLS 四传输端到端矩阵、公网、每格十轮或 24 小时验收。
