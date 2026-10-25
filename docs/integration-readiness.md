# 集成验收与发布门槛

截至 2026-10-25，本分支是在 PR #12 的累计修复上增加发布前检查，尚不能宣布可发布。早期文档各节是当时的结果，不能累计推导成完整验收通过。

## 集成顺序

依次评审 PR #1、#2、#4、#5、#6、#7、#8、#9、#10、#11、#12，再评审本项。#3 的严格 TLS 方案被 #4 覆盖，应跳过 #3。所有这些变更仍需完成集成评审；本轮没有合并、创建版本标签或发布。合并或变基后的最终提交必须重新验证。

## 本项改动

- 固定 GoReleaser v2.19.0，移除发布过程中的 latest；快照版本写入二进制。
- 生成四个系统（Linux、FreeBSD、macOS、Windows）× 两个架构（amd64、arm64）的八份归档；Windows 使用 zip，其余使用 tar.gz。
- 校验每份归档的 SHA-256、二进制平台头、六份许可证/声明及迁移手册，并执行 Linux amd64 的 version/help。其他目标仅验证交叉构建，不能作为原生运行支持证据。
- Docker 本地构建后验证只读根目录、私有状态卷、管理鉴权、离线状态检查、六份许可证及退出；不推送镜像。
- 标签发布先运行完整 CI，再检查 docs/release-gates.json；未完成的门槛或输入指纹不匹配将阻断发布。普通 CI 仅输出 readiness 报告，未完成长期验收不会导致单项回归的误报。

## 证据与边界

源码 d89896681d1b92eeb596a582d93ba893efc2d16b 的 [累计 CI](https://github.com/VortexWang/Tunveo/actions/runs/40209486144) 13/13 通过，含全仓 vet/test/race、各项缺陷回归、互通、迁移、漏洞扫描、实际八目标归档与真实容器。Python 验证器单元测试 11/11、归档 8/8、容器 7/7。容器由 CI 实际构建/运行，本地没有 Docker。

精确证据：[CI](evidence/integration/ci.json)、[归档与 SHA-256](evidence/integration/release-archives.json)、[容器](evidence/integration/container.json)、[祖先链](evidence/integration/ancestry.json)。扫描为零可达漏洞，仍有一项依赖模块级发现，不能称所有依赖无漏洞。

本地试跑曾受继承标签中的斜杠影响，已固定独立快照版本模板；还出现过一次校验和不匹配，该轮不计通过，失败记录保留。独立重新构建后本地八份归档通过；最终打包证据以 CI 干净目录重建和校验结果为准。

本轮补充 [TLS 1 互通诊断](evidence/integration/matrix-tls1-local.json) 48/48：四传输、两种服务流向、两种池容量、三种新旧配对，每格一轮。此处流向 mode=1/2 不是 TLS 模式。该本地二进制构建标记为 4f3c2aa+dirty，差异仅快照配置；只作为诊断，不替代 d898966 源码 CI 或发布构建认证。历史矩阵曾为 47/48，旧服务端初始化 HTTPS EOF 尚未解释，单轮重跑全绿不能关闭该问题。单项 Linux 回环成功不等于全平台、公网、全 TLS 模式或长期稳定性验收。

## 未完成的发布条件

| 门槛 | 必须补充的证据 |
| --- | --- |
| supported_matrix_10x | 所有声明支持的传输、TLS 0/1/2 与负例、容量、三种版本配对；每个单元至少十轮，零未解释失败 |
| lifecycle_100 | 每传输百次连接/重连/endpoint 周期及 FD、goroutine、内存回落 |
| soak_24h | 明确负载、错误预算与资源预算下的每传输 24 小时运行 |
| native_platforms | 声明支持平台的原生运行证据；否则正式缩小支持范围 |
| integration_review | 按依赖顺序完成评审和集成，在最终提交重新验收 |

只有七项门槛全部有通过证据，才可记录 verified_input_sha256。指纹覆盖已跟踪源码、依赖、工作流、配置和普通文档；仅排除门槛 JSON、本报告和 docs/evidence/integration/ 证据目录，避免记录结果导致自引用。任何其他输入改变都必须重新验收。门槛文件需要人工评审，脚本不认证证据真实性。

## 复现

```sh
python3 -m unittest discover -s scripts/tests -v
goreleaser check
goreleaser release --snapshot --clean --skip=publish
python3 scripts/verify_release_archives.py --dist dist --output artifacts/release-archives.json
docker build --build-arg VERSION=integration-local -t tunveo-integration .
python3 scripts/verify_container.py --image tunveo-integration --output artifacts/container.json
python3 scripts/check_release_readiness.py --report
# 以下命令在尚未完成全部门槛时应退出 1：
python3 scripts/check_release_readiness.py
```

工具来源：[GoReleaser v2.19.0](https://github.com/goreleaser/goreleaser/releases/tag/v2.19.0)。本地 Linux x86_64 安装包 SHA-256：ebc3194ad1d1b1787614405285a0039665cd4c5bd3305215a1b201600f90630b（与官方 checksums.txt 核对）。

2026-10-26 后续 TLS 0/2 扩展、TNV-014 修复和十轮矩阵结果以 [TLS 验收](tls-support-matrix.md) 为准；本页前述 13 项 CI 是当时提交的历史结果。
