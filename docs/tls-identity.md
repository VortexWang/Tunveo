# TNV-015：TLS 身份名称与过期证书检查

日期：2026-10-26。基于 PR #14；名称策略修复已实施，仍待集成。此前 TLS 十轮结果保留在 [前一轮报告](tls-support-matrix.md)，不能用本轮成功覆盖历史失败。

## 问题与行为

Common.GetServerName 曾把 IP 地址改成字面值 none，TCP/QUIC/HTTP2 的严格 TLS 随后验证 DNS 名称 none，无法使用有效的 IP SAN 证书。WebSocket 则从拨号 URL 推导名称，未消费通用显式 sni；IP 拨号配合 DNS 证书时同样失败。

本轮统一默认和显式身份选择。下表的证书匹配要求针对严格模式 TLS 2；模式 1 仍使用原有 RAM 指纹协议：

| 输入 | 验证身份 | TLS ClientHello 的 SNI |
| --- | --- | --- |
| DNS 地址，未设置 sni | 原始拨号 DNS 名称 | DNS 名称 |
| IPv4/IPv6 地址，未设置 sni | 原始 IP，对照 IP SAN | 不发送 |
| 带 zone 的 IPv6 地址，未设置 sni | 去掉路由 zone 的 IP | 不发送 |
| 显式 sni | 显式给定的 DNS/IP | DNS 发送，IP 不发送 |
| 显式 sni=none | 字面名称 none，证书必须匹配 | 字面名称 none |

这里使用 Go 标准 TLS/X.509 验证，没有将严格模式改成 InsecureSkipVerify，也没有新增跳过名称验证的特殊值。旧注释将 none 描述成关闭 SNI，与实际 Go 行为不符；本轮保留显式字面取值，修正默认 IP 和文档。没有可用拨号主机时的遗留 fallback 仍是 none，严格连接应提供完整主机或显式身份。

WebSocket 保留原 NewClientPool 接口，另增 NewClientPoolWithServerName 供引擎传入通用身份。TLS 名称与拨号 URL/HTTP Host 分开：显式 sni 不会把连接重定向到那个 DNS 名称，也不会重写 WebSocket HTTP Host。其他池的接口和线上配置协议不变。

## 迁移注意

有效 IP SAN 证书现在可以直接用于 IP 地址，不再需要 sni=IP 的补丁配置。如果旧证书只包含 DNS SAN，应显式指定该 DNS 名称；不能依赖 none 的旧默认值。WebSocket 的显式 sni 现在生效，原本被忽略的错误名称也会正确导致拒绝，需检查现有 URL。

IPv6 zone 只从默认身份中去除，实际拨号地址保留 zone。显式身份应使用证书里的 DNS/IP 名称，不含接口标记。初始 HTTPS 配置交换仍继承原协议的证书信任边界，本轮修复的是数据池身份选择，不声称已经认证初始控制握手。

## 过期证书夹具

新增 expired 负例使用有效 CA 签发、SAN 与目标身份匹配、具有 serverAuth 用途的过期叶证书，时间区间在测试时钟的前两天至前一天。OpenSSL 正常验证必须得到过期错误；只在夹具自检中关闭时间检查后，完整签名链、用途和名称必须通过。引擎实际连接从不关闭时间检查。

负例先要求初始配置交换成功，再观察两秒不能建立数据池，并各尝试一次 TCP/UDP；它们是有界行为回归，结合相同身份的有效证书正例使用。新矩阵的负例 I/O 预算为 0.5 秒，使观察与探测结束在常规握手自动重试前；正例仍为 3 秒。前一轮 3 秒负例 I/O 的结果独立保留，不据失败数量变化推断旧端生命周期问题已修复。

本轮没有修改服务端加载/热重载对证书有效期的策略；过期文件仍可能被加载，严格数据客户端必须拒绝。TNV-007 的更广泛轮换/故障策略审计继续开放。

## TNV-016：消除诊断自回显

首次完整 4160 格在源码 d555c8b 上执行，40 格旧服务端 HTTP/2 模式 0 失败，另有一格新版双端的过期证书负例报告了回显。该格没有任何池就绪日志，也没有记录探针端点，因此保留为未能从原记录确证归因的异常，不把它直接描述为过期证书已穿透 TLS。

受控实验确认 Linux TCP/UDP 都允许源端点等于目的端点的本机自连接：原 exchange 在内核为未绑定套接字选择空闲目的端口时，可以不经过任何监听服务回送自己的载荷。用真实套接字强制这个合法的分配顺序，原版本两协议各十次复现；修正版本两协议各十次均正确识别无监听服务。该证明建立了验证器的具体缺陷，仍不补造原异常格缺失的四元组。

修正后在 connect/send 之前显式分配本地端口，若与目标端口相同则只重新分配本地套接字；尚未发出网络连接或应用请求，应用重试次数仍是零。连接后再次检查两端不同，成功探针以及负例意外回显的错误都记录本地/对端地址与 TCP/UDP 类型。源套接字准备失败单列 ProbeSetupError，不能被当成“证书拒绝”通过。

新增测试还验证：没有池就绪日志、但实际存在回显服务时，负例必须失败；不会通过忽略回显来让结果变绿。验证器单元测试现为 18 项。原始首次矩阵、异常格日志和受控前后证明均保留，修正探针后重新执行完整矩阵。TNV-016 不改变生产 Go/TLS 实现。

## 回归证据

固定前态为 6cff6b1cb61005ea8227d1b5c4bb9ed252ab6263 的未修改归档。同一新版验证器、临时信任库及 Go 1.26.10 编译器比较四传输、两流向：

| 场景 | 修复前 | 修复后 |
| --- | --- | --- |
| 默认 IP | 2/8 通过，TCP/QUIC/H2 六格失败 | 8/8 通过 |
| IP 拨号、显式 DNS 身份 | 6/8 通过，WebSocket 两格失败 | 8/8 通过 |
| 默认 IP、过期叶证书拒绝 | 未用来证明名称缺陷 | 8/8 通过 |
| 显式 DNS、过期叶证书拒绝 | 未用来证明名称缺陷 | 8/8 通过 |

原生测试使用真实 TLS ClientHello、可信证书和主机名错误类型，覆盖 IPv4、IPv6、zone、DNS、显式 DNS、字面 none 与错误名称，七个场景各十轮通过。IPv6 身份通过 IPv4 回环 TLS 承载验证，不代表原生 IPv6 数据转发或全平台认证。

名称补丁的首轮源码 d555c8b 的 [常规 CI](https://github.com/VortexWang/Tunveo/actions/runs/40244162038) 15/15 通过。随后修正诊断探针，规范源码 adccb517c38a36714d76aa56eec70988f0642f92 的 [常规 CI](https://github.com/VortexWang/Tunveo/actions/runs/40246652146) 同样 15/15 通过，包含全仓 vet/test/race、前后进程对照、原生握手及自回显对照。生产 Go 源码和依赖在两次提交间没有变化。修正探针后的 [十轮验收](https://github.com/VortexWang/Tunveo/actions/runs/40246652123) 已完整执行 4160 格，无缺格、无重复：

| 服务端 / 客户端 | 身份场景 | 正例通过 / 总数 | 负例通过 / 总数 |
| --- | --- | ---: | ---: |
| Tunveo / Tunveo | 显式 IP，TLS 0/1/2 | 480/480 | 480/480 |
| Tunveo / Tunveo | 默认 IP，TLS 2 | 160/160 | 480/480 |
| Tunveo / Tunveo | 显式 DNS，TLS 2 | 160/160 | 480/480 |
| Tunveo / 原版 | 显式 IP，TLS 0/1/2 | 480/480 | 480/480 |
| 原版 / Tunveo | 显式 IP，TLS 0/1/2 | 440/480 | 479/480 |
| 合计 | | 1720/1760 | 2399/2400 |

新版双端共2240/2240、新版服务端配旧客户端共960/960。41格失败均位于旧服务端：40格HTTP/2请求TLS 0崩溃/模式不匹配，一格HTTP/2模式1、TLS 2未知CA负例在初始HTTPS GET出现EOF（小池、第3轮），尚未进入数据证书校验。8320个转发子进程均已回收，未强制结束；旧端panic退出仍为失败，不将“已退出”称作正常应用退出。

原异常对应场景另从固定adccb517的未修改源码归档构建，在WebSocket模式2、小池、显式IP、过期证书负例下独立复测10/10通过。该补充不替代完整矩阵，也不改写首次异常格的failed状态。前一轮旧端EOF/强制结束与首次异常均独立保留，不能以新结果宣称已修复原版端点。

证据：[完整覆盖与失败表](evidence/tls-identity/coverage.json)、[CI作业与artifact原始摘要](evidence/tls-identity/ci.json)、[矩阵作业与artifact摘要](evidence/tls-identity/acceptance-ci.json)、[兼容矩阵完整报告/日志](evidence/tls-identity/compatibility-evidence.zip)、[默认IP/显式DNS完整报告/日志](evidence/tls-identity/identity-evidence.zip)、[回归/自回显证明/定向复测](evidence/tls-identity/regression-evidence.zip)、[首次4160格报告与失败日志](evidence/tls-identity/prior-attempt-evidence.zip)、[首次覆盖表](evidence/tls-identity/initial-coverage.json)、[ZIP SHA-256](evidence/tls-identity/archives.json)。所有下载均先核对GitHub artifact digest，证据ZIP在源码仓库长期保留，未保存临时证书私钥。

发布门槛 supported_matrix_10x 继续为 failed；百次生命周期资源回落、24小时负载、原生平台与最终集成评审仍未完成。

十轮计划保留原三配对 × 三 TLS 请求模式 × 四传输 × 两流向 × 两容量，并在 TLS 2 增加过期负例；另对新版双端运行默认 IP 与显式 DNS 的正例及三类负例。总计 1760 正例、2400 负例，共 4160 格，十一分片不提前取消、不改旧端失败为通过。旧端兼容、百次资源生命周期、24 小时负载、原生平台和集成评审仍是独立门槛。

## 复现

```sh
go test -race -count=10 -run '^TestTLSIdentityAndClientHello$' ./internal/common
go build -race -trimpath -o bin/tunveo-race ./cmd/tunveo
python3 scripts/verify_tls_identity.py --binary bin/tunveo-race --go go --artifacts artifacts/identity
python3 scripts/verify_forwarding.py --binary bin/tunveo-race --tls 2 --identity default-ip --artifacts artifacts/default-ip --go go
python3 scripts/verify_forwarding.py --binary bin/tunveo-race --tls 2 --identity explicit-dns --reject-tls expired --io-timeout .5 --artifacts artifacts/expired --go go
```
