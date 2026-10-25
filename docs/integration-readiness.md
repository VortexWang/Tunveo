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

本地 Python 验证器单元测试 11/11 通过。源码 CI、实际归档与容器验证的最终结果在本轮完成后补录。本地没有 Docker，容器证据必须来自 CI 的真实构建/运行，不能以脚本静态检查替代。

历史累计混合互通矩阵曾为 47/48；旧服务端初始化 HTTPS EOF 未解释。单项 Linux 回环成功不等于全平台、公网、全 TLS 模式或长期稳定性验收。

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
