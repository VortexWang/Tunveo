# TNV-011：Go / HTTP/2 安全更新

2026-10-25。本补丁叠加 TLS/日志安全分支，按 Go 工具链与外部模块两步升级，不修改生产 Go 源码，不表示已合并或发布。

## 锁定版本

| 项目 | 升级前 | 本次锁定 |
| --- | --- | --- |
| Go 最低构建版本 | 1.26.5 | 1.26.10 |
| golang.org/x/net | v0.56.0 | v0.60.0 |
| golang.org/x/crypto（间接） | v0.53.0 | v0.57.0 |
| golang.org/x/sys（间接） | v0.46.0 | v0.48.0 |
| golang.org/x/text（间接） | v0.39.0 | v0.42.0 |
| quic-go / coder/websocket | v0.60.0 / v1.8.15 | 保持当前锁定版本 |

`x/crypto`、`x/sys`、`x/text` 随 `x/net v0.60.0` 的模块约束更新；没有批量执行 `go get -u`。选择修复已有公告所需版本，不将其称为所有依赖的最新版本。`go.mod` 最低版本改为 1.26.10；较旧工具链在 `GOTOOLCHAIN=local` 时会拒绝构建，默认自动工具链模式可能下载新工具链。

Docker 构建镜像更新为官方 `golang:1.26.10-alpine` 并固定已读取的多架构 manifest digest。Release 与 CI 都从 `go.mod` 读取 Go 版本，避免单独保留旧版本。官方 Linux amd64 Go 归档在解压前对照发布元数据校验 SHA-256。镜像 manifest 已验证，当前环境无 Docker，未执行容器构建或镜像运行。

两个提交：`978ba2ea2db2b79ec47f1b97aea416458d798614` 更新 Go/Docker/Release；`290c3f871fb7d72f43577bf6688d9b4a4cc47ccd` 更新模块与 CI 扫描。运行回归使用第二个干净提交构建的二进制，Go 1.26.10。

## 同库分阶段扫描

扫描器固定 `govulncheck v1.9.0`，漏洞库为 `https://vuln.go.dev`，三次报告的库时间均为 `2026-10-21T00:27:29Z`；目标 Linux amd64，源码 symbol 分析。

| 阶段 | 工具链 / x/net | 模块级公告 ID | 已导入包公告 ID | 可达符号公告 ID | 可达模块/公告对 |
| --- | --- | ---: | ---: | ---: | ---: |
| 升级前（TLS/日志修复后的 e5aecef） | 1.26.5 / v0.56.0 | 27 | 18 | 15 | 20 |
| 只升级 Go | 1.26.10 / v0.56.0 | 10 | 5 | 5 | 5 |
| 升级模块后 | 1.26.10 / v0.60.0 | 1 | 0 | 0 | 0 |

标准库原有 15 个可达公告被新工具链覆盖；剩余五项 HTTP/2 模块公告由 `x/net` 更新覆盖。此处可达是静态符号调用关系，不是已经证明可利用，也不等于代码经过完整安全审计。

剩余模块级 `GO-2026-5932` 涉及未维护的 `golang.org/x/crypto/openpgp` 及其子包，公告没有修复版本。本项目的实际依赖包列表不包含这些包；使用 `x/crypto` 的 ChaCha20/Poly1305 相关包。保留该公告和包依赖清单，不添加扫描忽略项，不宣称“零漏洞”。以后引入新代码或依赖时仍需重新评估。

最终源码文本扫描及实际二进制扫描均退出 0，报告可达结果为 0；文本报告仍保留上述模块级提示。`-json` 即使有发现也可能返回 0，因此不能仅凭 JSON 退出码判断安全状态。

CI 新增 `vulnerability-scan`：安装固定扫描器，使用当前 `go.mod` 工具链并设置 `GOTOOLCHAIN=local`，执行普通文本扫描；`pipefail` 保留扫描器失败状态，同时保存输出。没有 `continue-on-error` 或公告豁免。

## 验证范围

- Go-only 阶段 `go test ./...` 通过；最终模块组合 `go mod verify`、`go mod tidy -diff`、`go vet ./...`、`go test -race ./...` 通过。
- 实际进程安全回归 20/20；新/新、新/旧、旧/新 × 四种传输 × 两种流向 × 两档容量，完整转发矩阵 48/48，各格仅一次。TCP/UDP 回显完整、进程均正常回收、无强杀；最终日志包含阶段已观察字节，未观察到双方发起相同校验 ID。
- 发布配置的 Darwin/FreeBSD/Linux/Windows × amd64/arm64 八组合编译 8/8；只验证编译，不代表平台运行验收。
- 源码 CI 五任务（含真实连接池回归与漏洞扫描）均成功：[40172117542](https://github.com/VortexWang/Tunveo/actions/runs/40172117542)。
- 继续使用受控回环、合成凭据，不使用公网服务或生产状态。不完成公网、长期运行、性能或严格证书全传输验收。
- TNV-003/004/005、TNV-009 和零重载周期崩溃 TNV-013 等源码问题不会因升级依赖自动解决。

[证据目录](evidence/tnv011) 保存三阶段紧凑扫描报告、可达调用示例、完整原始扫描流的 SHA-256、最终文本报告、构建信息、模块清单和运行报告。紧凑报告省略无关 OSV 事件正文；原始扫描事件流保留在本地工作产物，可使用记录的命令、目标与工具重跑，未来数据库变化可能改变结果。历史 M1/TNV-002/TLS 日志证据未改写。

## 上游依据

- [Go 发布记录](https://go.dev/doc/devel/release)：1.26.9 包含 HTTP/TLS 等修复，1.26.10 包含 x509 修复。
- [Go 1.26.10 官方下载元数据](https://go.dev/dl/?mode=json&include=all)。
- [x/net v0.60.0](https://pkg.go.dev/golang.org/x/net@v0.60.0) 与 [模块约束](https://proxy.golang.org/golang.org/x/net/@v/v0.60.0.mod)。
- [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)、[GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603)、[GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617)。
- [剩余 OpenPGP 模块公告 GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)。

后续状态：依赖升级不改变的 TNV-013 已由后续 [重载周期启动校验](reload-interval.md) 单独处理，本页扫描与运行证据保持原样。
