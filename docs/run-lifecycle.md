# TNV-004 运行实例与连接池生命周期

2026-10-25。PR #8 叠加在 TNV-003 分支上，尚未合并或发布。源码及测试提交为 `665e751c2f4442c8f412429711d830000d16fc2a`；证据提交只补充文档和运行结果。

## 问题与新行为

旧实现允许 Flush 前启动的建连任务在 Flush 后发布；Close 后再次启动 manager 可以替换已取消的上下文；Close 不能立即打断正在读取连接 ID 的已建立套接字。原生 TCP 三种受控时序各重复十次，在父提交 `11232377ec3f537647a34ceb95ece633b1a7527f` 共复现 30/30，新实现通过 30/30。使用相同测试模板及驱动，旧版本只切换测试的预期结果，不插入生产源码调度钩子。测试通过表示分别观察到预期缺陷或预期修复，不是现场故障率。

四个内置池共同使用永久的 `lifetime.Group`：上下文在构造时创建，manager 只能启动一次，Close 永久终止该池。监听器、待握手连接及已交给业务的连接仍归根资源所有者管理；正常释放注销资源，Close 在锁外关闭快照中的资源，迟到资源直接关闭，不能复活池。WebSocket 终止使用 CloseNow；QUIC 跟踪物理连接，旧连接出错只清除仍指向自己的指针。

`idle.Queue.Begin` 捕获当前代际。Flush 在锁内推进代际并清空空闲登记，在锁外取消旧代际、关闭其空闲资源。建连任务只有在代际和上下文仍有效时才能 Commit；旧等待者也检查代际，不能领取 Flush 后的新资源。提交同时解除建立阶段的中断监听，避免成功移交后被建立超时误关。Flush 不关闭已经领取的业务流；Pool.Close 会终止根资源下的连接。

QUIC/HTTP2 流在创建时绑定真实物理连接的地址、TLS 信息，之后不会改读池中的最新连接。HTTP/2 客户端将物理连接与 http2.ClientConn 作为同一 session 发布，避免配错代际。请求建立阶段可被取消，成功流保留自己的请求上下文。

## 每轮运行隔离

Client/Server 使用单次 Start 的运行对象，Run/RunWithContext 的自动重试每次创建新的 Common。上下文、控制通道、校验状态、UDP 会话、DNS/负载缓存、监听器和限速器均归该轮；TLS 配置克隆，地址切片复制。旧协程继续引用被取消的旧对象，无法改写下一轮字段。累计原子统计和线程安全缓冲池有意跨轮共享。

Stop 先取消，再等待 Start 或重试控制器完成自身清理；Common 清理幂等。业务 accept/dial 连接绑定该轮根资源，发送控制通知能响应取消，关闭通道后的 drain 正常结束，健康时间点使用原子快照。

这是内部 Go API 的行为变化：不要对同一 endpoint 重复 Start/Run，也不要在 Close 后重启 pool manager。需要新一轮时构造新对象；常规 CLI 自动重连仍保留。线上协议、环境变量、状态格式和依赖版本未变化。

## 复测中发现的 HTTP/2 时序

首轮 race 重连试跑发现 handler 返回时业务 ResponseWriter.Flush 尚未结束的真实 DATA RACE。当前流 Close 使用 once/done，handler 返回前等待写操作退出；内部逻辑关闭通过 ResponseController 的单流写期限打断阻塞写，再取得写锁完成关闭。另补阻塞写关闭回归。

第二轮试跑暴露对端流关闭可能早于控制消息到达：立即删除空闲 ID 会让后续指纹校验找不到它。现在结束处理器并关闭流，但保留空闲 ID 的绑定元信息，直到领取或 Flush；新增单元测试覆盖。两轮失败报告、进程日志和中间二进制 SHA 均保留，未改写结果。它们属于本次开发中间态，不是父提交缺陷复现。

公开 HTTP/2 StreamConn.SetReadDeadline/SetWriteDeadline 仍转发物理连接，影响兄弟流的风险属于 **TNV-005，未关闭**。本次用于关闭写入的单流机制不代表公开 deadline API 已完成隔离。

## 验证与证据

- 原生 TCP：三种可控时序，各十轮，修复前 30/30 复现、修复后 30/30 通过；均启用 race。
- 新端 race 二进制：四传输 × 两流向共 8 组，每组替换服务端一次，客户端 PID 保持；前后各做一次 TCP 32 KiB / UDP 512 B 回显，全部通过，24 个进程正常回收、无强杀、未观察到 DATA RACE/panic。
- 最终转发矩阵：三种配对 × 四传输 × 两流向 × 两档容量（2:8、64:1024），**47/48 通过**。新/新 16/16、新服务端/旧客户端 16/16、旧服务端/新客户端 15/16；失败为 TCP mode=2 小池的初始 HTTPS EOF，未进入 pool-ready。完整失败保留。定向独立复测当前版/上一版 Tunveo 与旧服务端各 10/10；原版双端 5/10，另五次为既有校验超时。EOF 未再次复现，与 TNV-012 旧端提前关闭风险一致，但日志不足以确证此次 EOF 根因；不能据通过的复测覆盖该失败。
- 安全进程 20/20、重载周期进程 24/24；完整 go test、race、vet、模块一致性检查和六项 Python 驱动测试通过。
- 源码 CI [40176011532](https://github.com/VortexWang/Tunveo/actions/runs/40176011532) 七个 job 全部成功，新增 lifecycle-regression 持续运行原生时序与八组 race 重连。

详见 [evidence/tnv004](evidence/tnv004)，包含成功和失败报告、全部对应日志、构建信息、路径规范化说明及 SHA-256 清单。普通和 race 二进制均由上述干净源码提交构建，Go 1.26.10；race 标志由构建信息确认。

重跑示例：

```sh
python3 scripts/repro_pool_lifecycle.py --ref HEAD --mode fixed --go go --output artifacts/lifecycle.json
go build -race -trimpath -o bin/tunveo-race ./cmd/tunveo
python3 scripts/verify_reconnect.py --binary bin/tunveo-race --artifacts artifacts/reconnect
```

## 验收边界

这些是本地回环、tls=1、受控时序与一次正常服务端替换，不能证明所有网络故障、长时间运行、性能或生产稳定性。Close 不承诺任意外部回调或所有 goroutine 均已 join：旧式 `func() (net.Conn, error)` dialer 不接受 context，返回前无法强制中断；迟到返回资源会被关闭并拒绝发布。自定义阻塞 Close、外部 DNS/回调仍需调用方遵守自身期限。

TNV-004 的已复现范围已实施修复，待集成；旧服务端提前关闭响应、TNV-005、管理面审计、状态迁移和发布前长期验收仍独立跟进。


后续 [TNV-005](h2-stream-deadlines.md) 已将公开 HTTP/2 deadline 移至单流适配层，取代本文记录的 TNV-004 版本限制；本文证据和历史范围不变。
