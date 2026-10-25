# TLS 互通矩阵与 HTTP/2 模式 0 修复

日期：2026-10-26。基于 PR #13，本轮包含一个新增可用性缺陷修复和验收扩展，尚未集成或发布。

## TNV-014：HTTP/2 tls=0 导致进程崩溃

此前 server 的 tls=0 配置不提供 TLSConfig，HTTP/2 的 NewServerPool 返回 nil，InitTunnelPool 仍启动 ServerManager，导致 nil pointer panic。首轮真实进程证据保留；这是新扩展测试发现的原有缺陷，不能归因于新增测试。

HTTP/2 后端只实现基于 TLS 的 h2，没有 h2c。现在与 QUIC 一样将请求 tls=0 提升为模式 1，在初始配置响应中向客户端发送实际 TLS 模式。InitTunnelPool 对空 HTTP/2 池直接返回错误，避免异步启动空 manager。TCP/WebSocket 的模式 0 仍按原有明文后端运行。

| 传输 | 请求 TLS 0 | 请求 TLS 1 | 请求 TLS 2 |
| --- | --- | --- | --- |
| TCP | 明文池 | RAM 证书与指纹协议 | 文件证书与信任链/名称校验 |
| QUIC | 提升为模式 1 | RAM 证书与指纹协议 | 文件证书与信任链/名称校验 |
| WebSocket | ws（本矩阵为非 443 回环端口） | wss 与指纹协议 | wss 与信任链/名称校验 |
| HTTP/2 | 提升为模式 1 | TLS h2 与指纹协议 | TLS h2 与信任链/名称校验 |

原版 v1.17.0 服务端没有本轮修复；其 HTTP/2 模式 0 崩溃会作为验收失败保留。使用旧客户端连接新版服务端时，以服务端协商配置为准。这里没有声明对原版问题实现了远端修复。

## 验证器与信任边界

verify_forwarding.py 记录请求 tls 与预期归一化 effective_tls，并检查双方实际加载的配置日志；旧端不匹配即失败，不能把预期字段当作失败端实际值。模式 0/2 不再误等 RAM 指纹日志。TLS 2 使用临时自签名证书、独立 SSL_CERT_FILE/SSL_CERT_DIR 和显式 sni=127.0.0.1。IP URL 在 TCP/QUIC/HTTP2 的缺省校验名称是 none，WebSocket 则直接使用 TunnelAddr 主机名，未接收 Common 的显式 SNI 配置；首轮测试因此出现有效 IP SAN 证书的握手超时。显式 SNI 正例不能覆盖这个默认输入问题，已另记 TNV-015，尚未修复。临时证书与私钥位于进程外的临时目录，结束后移除，不上传到证据包。

负例分别使用不受信任 CA、受信任但 SAN 不匹配的证书：先要求初始配置交换成功，持续观察数据池不能就绪，再确认 TCP/UDP 都不能转发。它们是有界的进程行为检查，结合相同配置下的有效证书正例使用；初始 HTTPS 握手仍继承跳过证书验证的协议，不能以本轮负例声称初始控制握手获得 PKI 身份认证。证书过期、吊销及公网攻击场景仍属于后续审计。

## 旧端初始 HTTPS EOF

repro_handshake_eof.py 在隔离 git archive 中仅添加测试专用屏障：在 close(done) 后暂停 handler，允许外层 server.Close 和重新绑定监听完成。原版在 handler 返回前尚未 flush JSON，真实 HTTPS 客户端会收到 EOF；当前实现先写入并 Flush，再发布 done。原版十次复现，当前十次交付完整 JSON。该受控顺序证明了一个具体成因，不能把历史随机失败全部归到同一原因，也不是线上故障率估计。夹具为原版值类型 Common 和当前指针类型作适配，生产算法没有为测试改写。

## 十轮验收范围与结果

独立 TLS acceptance 工作流运行三种版本配对 × 三个请求 TLS 模式 × 四传输 × 两种服务流向 × 两档池容量 × 十轮，共 1440 个正例；TLS 2 另运行两类负例，共 960 个。mode=1/2 表示流向，不表示 TLS 模式。测试每格只交换一次 TCP/UDP 载荷，没有失败重试，不将旧端失败白名单化。九个分片 fail-fast=false，各自保留失败和部分报告。

源码 f236559410de2df1539318e2b593cbe68ef37af5（测试合并树 e6a65f0d36719d5b2f6e0e4d9d8826184382ddac）的 [常规 CI](https://github.com/VortexWang/Tunveo/actions/runs/40238595212) **14/14 通过**；独立 [TLS acceptance](https://github.com/VortexWang/Tunveo/actions/runs/40238595162) **6 个分片通过、3 个旧服务端分片失败**，不标记为完整兼容通过。

| 服务端 / 客户端 | 正例通过 / 总数 | 证书负例通过 / 总数 |
| --- | ---: | ---: |
| Tunveo / Tunveo | 480 / 480 | 320 / 320 |
| Tunveo / 原版 | 480 / 480 | 320 / 320 |
| 原版 / Tunveo | 439 / 480 | 317 / 320 |
| 总计 | 1399 / 1440 | 957 / 960 |

全部 2400 格已执行，按配对、TLS、传输、流向、池容量、轮次与负例类型核对，无缺格、无重复。44 格失败全部位于旧服务端：40 格为 HTTP/2 请求模式 0 的崩溃/模式不匹配；2 格初始 HTTPS EOF（TLS 1 正例、TLS 2 错误主机名负例各一）；2 格为 WebSocket TLS 2 负例的服务端退出超时，需要 SIGKILL。4800 个子进程最终均被回收，4798 个自然退出或已结束，2 个强制结束。强制结束照常计失败，不能当作正常生命周期通过。

EOF 的服务端日志已进入 Sending config/Getting pool ready，而客户端尚未 Loading config 即收到 Get EOF；随后服务端的 context canceled 是测试清理动作，不能倒因为初始原因。受控屏障证明旧端提前关闭路径确实存在，原样矩阵日志则没有内部时序插桩，历史及本轮个例仍保留归因边界。

证据：[完整逐格汇总](evidence/tls-matrix/coverage.json)、[验收作业与原始 artifact SHA-256](evidence/tls-matrix/acceptance-ci.json)、[全部原始报告/日志及旧端构建来源 ZIP](evidence/tls-matrix/acceptance-evidence.zip)、[常规 CI 及试跑证据 ZIP](evidence/tls-matrix/regression-evidence.zip)、[ZIP 校验和](evidence/tls-matrix/archives.json)。原始 artifact 下载均核对 GitHub digest；源码仓库中的 ZIP 保留证据，避免只依赖 14 天的 Actions artifact。

本地首轮夹具还存在 SNI 默认名称输入限制以及原版 Common 值类型适配编译失败；均未计作引擎修复通过，原失败保留。有效配置试跑 16/16、证书拒绝 16/16、验证器单元 14/14；最终结论以干净源码 CI 的实际报告为准。常规 CI 另运行新版 race 二进制的 TLS 0/2 正例、两类负例及原版/新版 EOF 对照，避免把旧端不兼容隐藏在常规回归结果中。

源码运行环境为 Linux amd64；原版从固定提交 114345043d9608e1e24e783a270cde75193e4f42 的未修改归档构建，保持原 go.mod/go.sum，由同一 Go 工具链编译以控制编译器变量。历史旧版 Go 1.26.5 二进制的结果单独保留，不能混称同一构建。所有二进制均记录哈希和构建信息。

完整兼容验收门槛现记录为 failed，TNV-015 默认/显式身份名称策略和过期证书仍待独立修复/验证。百次生命周期资源回落、24 小时负载、原生平台和最终集成评审继续开放，本轮不修改为可发布。

## 复现

```sh
go build -trimpath -o bin/tunveo ./cmd/tunveo
python3 scripts/build_matrix_oracle.py --go go --output bin/nodepass-original
python3 scripts/verify_forwarding.py --binary bin/tunveo --upstream bin/nodepass-original --pair tunveo/tunveo --tls 0 --tls 1 --tls 2 --pool 2:8 --pool 64:1024 --repeat 10 --artifacts artifacts/current --go go
python3 scripts/verify_forwarding.py --binary bin/tunveo --tls 2 --reject-tls untrusted-ca --repeat 10 --artifacts artifacts/reject-ca --go go
python3 scripts/repro_handshake_eof.py --ref 114345043d9608e1e24e783a270cde75193e4f42 --mode original --go go --output artifacts/eof-original.json
python3 scripts/repro_handshake_eof.py --ref HEAD --mode fixed --go go --output artifacts/eof-fixed.json
```
