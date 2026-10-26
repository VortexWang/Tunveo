# 百次生命周期及资源回落验收

本项叠加在 PR #15，尚未合并或发布。源码验证完成后在此记录精确提交、结果和原始失败；不能将试跑计作完整百次门槛。

## 场景与边界

`scripts/lifecycle100` 在一个 Linux 进程中调用真实 Client/Server API，不插入生产调度钩子。四种传输各自独立进程；TLS=1、池 min=2/max=8、两种流向。每个流向执行以下两组：

- fresh-pair：先完整预热五次，再连续创建、建立、回显、停止两个实例100次。
- replace-server：保留同一个客户端 RunWithContext 控制器，服务端停止并在原地址替换100次，每次完成重新协商和业务回显。初始连接不计入100次。

每轮各一次随机载荷 TCP 32768B、UDP 512B 回显，记录实际端点，源/目的相同则在发送前拒绝。应用数据不重试。实例关闭期限5秒、握手验证15秒、资源回落5秒、外层进程20分钟。`NP_REPORT_INTERVAL=100ms`、`NP_SERVICE_COOLDOWN=100ms` 加速受控测试，其他配置保持默认。自动重试属于引擎行为，重启次数和完整日志保留。

每组五次预热后记录基线；每十轮和最终停止后记录 Go goroutine、Linux `/proc/self/fd`、GC 后 HeapAlloc、HeapInuse、Sys、RSS。固定回落预算为 goroutine 基线+4、FD 基线+2、HeapAlloc 基线+8MiB；预算不随轮数增加。fresh-pair 每十轮也要求回落；replace-server 中间记录活跃客户端和未超时 UDP 会话，不冒充静止资源。所有实例停止后必须在五秒内回到上述预算。

内存回落结论指 GC 后存活 Go 堆；RSS/Sys/HeapInuse 全量记录，但不承诺分配器或 race 检测器立即把驻留页交还系统。不能据此宣称零泄漏、24小时稳定性、生产性能、全TLS/容量覆盖、原生Windows/macOS/arm64支持。

## TNV-017：QUIC Close 返回后 UDP 地址仍被占用

初始试跑的 QUIC 服务端替换失败，保留客户端反复连接被拒绝的日志。增加 Start 返回值记录后，明确观察到新服务端 `listen udp ... bind: address already in use`。该诊断增强没有修改生产代码。

独立原生用例通过真实 QUIC 客户端连接并 Accept，再调用 Pool.Close，随后立即绑定同一 UDP 地址。父提交上的十轮均失败；修复后定向一百轮均通过，归档对照证据待规范源码运行后补入。

便利 ListenAddr 隐藏了 Transport；关闭 listener 及物理连接后，closed connection ID 的 drain 仍可能让 UDP 套接字继续存活。现在显式创建 UDP PacketConn 和 quic.Transport，将 listener、Transport.Close、PacketConn.Close 作为同一生命周期资源关闭。迟到创建资源也由 lifetime.Track 的拒绝路径关闭。Pool.Close 不等待网络 drain 才释放地址；未改动线协议、TLS 校验、依赖或公开构造函数签名。

Python 验收器拒绝缺失场景/轮次/样本/资源指标、超时、自回显、应用重试和超预算结果；Go 的成功退出本身不足以通过验收。CI 对四种传输分别运行 race 百次测试，失败照常阻断。

## 运行

```sh
go build -race -trimpath -o bin/lifecycle100-race ./scripts/lifecycle100
python3 scripts/verify_lifecycle100.py --binary bin/lifecycle100-race --transport 1 --artifacts artifacts/lifecycle-100-quic
python3 scripts/repro_quic_close.py --ref 89292ba58eeb8ffd356a2b37edb689666d1ab237 --mode original --go go --repeat 10 --output artifacts/quic-before.json
python3 scripts/repro_quic_close.py --ref HEAD --mode fixed --go go --repeat 100 --output artifacts/quic-fixed.json
```

正式结果仍待完成；lifecycle_100 门槛目前保持 pending，历史旧端矩阵失败与其他发布阻断不变。
