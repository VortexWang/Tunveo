# 百次生命周期及资源回落验收

本项为叠加在 PR #15 上的 PR #16，尚未合并或发布。规范源码 e611f0e0 的百次验收及19项CI已通过，原始试跑和失败仍保留；范围与资源预算见下文。

## 场景与边界

`scripts/lifecycle100` 在一个 Linux 进程中调用真实 Client/Server API，不插入生产调度钩子。四种传输各自独立进程；TLS=1、池 min=2/max=8、两种流向。每个流向执行以下两组：

- fresh-pair：先完整预热五次，再连续创建、建立、回显、停止两个实例100次。
- replace-server：保留同一个客户端 RunWithContext 控制器，服务端停止并在原地址替换100次，每次完成重新协商和业务回显。初始连接不计入100次。

每轮各一次随机载荷 TCP 32768B、UDP 512B 回显，记录实际端点，源/目的相同则在发送前拒绝。应用数据不重试。实例关闭期限5秒、握手验证15秒、资源回落5秒、外层进程20分钟。`NP_REPORT_INTERVAL=100ms`、`NP_SERVICE_COOLDOWN=100ms` 加速受控测试，其他配置保持默认。自动重试属于引擎行为，重启次数和完整日志保留。

每组五次预热后记录基线；每十轮和最终停止后记录 Go goroutine、Linux `/proc/self/fd`、GC 后 HeapAlloc、HeapInuse、Sys、RSS。固定回落预算为 goroutine 基线+4、FD 基线+2、HeapAlloc 基线+8MiB；预算不随轮数增加。fresh-pair 每十轮也要求回落；replace-server 中间记录活跃客户端和未超时 UDP 会话，不冒充静止资源。所有实例停止后必须在五秒内回到上述预算。

内存回落结论指 GC 后存活 Go 堆；RSS/Sys/HeapInuse 全量记录，但不承诺分配器或 race 检测器立即把驻留页交还系统。不能据此宣称零泄漏、24小时稳定性、生产性能、全TLS/容量覆盖、原生Windows/macOS/arm64支持。

## TNV-017：QUIC Close 返回后 UDP 地址仍被占用

初始试跑的 QUIC 服务端替换失败，保留客户端反复连接被拒绝的日志。增加 Start 返回值记录后，明确观察到新服务端 `listen udp ... bind: address already in use`。该诊断增强没有修改生产代码。

独立原生用例通过真实 QUIC 客户端连接并 Accept，再调用 Pool.Close，随后立即绑定同一 UDP 地址。父提交上的十轮均失败；修复后定向一百轮均通过，规范CI也用相同模板完成不可变源码归档对照。

便利 ListenAddr 隐藏了 Transport；关闭 listener 及物理连接后，closed connection ID 的 drain 仍可能让 UDP 套接字继续存活。现在显式创建 UDP PacketConn 和 quic.Transport，将 listener、Transport.Close、PacketConn.Close 作为同一生命周期资源关闭。迟到创建资源也由 lifetime.Track 的拒绝路径关闭。Pool.Close 不等待网络 drain 才释放地址；未改动线协议、TLS 校验、依赖或公开构造函数签名。

Python 验收器拒绝缺失场景/轮次/样本/资源指标、超时、自回显、应用重试和超预算结果；Go 的成功退出本身不足以通过验收。CI 对四种传输分别运行 race 百次测试，失败照常阻断。

## 运行

```sh
go build -race -trimpath -o bin/lifecycle100-race ./scripts/lifecycle100
python3 scripts/verify_lifecycle100.py --binary bin/lifecycle100-race --transport 1 --artifacts artifacts/lifecycle-100-quic
python3 scripts/repro_quic_close.py --ref 89292ba58eeb8ffd356a2b37edb689666d1ab237 --mode original --go go --repeat 10 --output artifacts/quic-before.json
python3 scripts/repro_quic_close.py --ref HEAD --mode fixed --go go --repeat 100 --output artifacts/quic-fixed.json
```

以下记录实施顺序和失败，正式百次结果见文末；历史旧端矩阵失败与其他发布阻断不变。

首轮 CI（59995a65）的 TCP 第72轮发现验收驱动分配端口冲突：两次分别打开/关闭 TCP :0 可能分到同一端口，被引擎配置校验正确拒绝。该失败保留；驱动改为同时持有前端/隧道的 TCP+UDP 四个套接字，全部分配成功后才交接，不对失败业务重试。原生回归100次验证持有期间不能重复绑定，释放后地址可用。后续以修正驱动的完整新一轮为规范结果，不改写旧报告。

## 已完成的普通构建补充证据

使用规范源码 `e611f0e018dbb1733e1a8316f3e9b55097ebce5a` 的不可变 git archive 构建，未修改生产源码；源码归档 SHA-256 为 `30aa018ecaaeb6b3a7a1f0315246ca376fe0f9278390f916325259ca003fc990`，二进制 SHA-256 为 `11c6a32834738d9be353081494ea1db0047cf982d09e6373bd91220afc541daa`。四种传输各400轮，合计1600轮、3200次单次尝试回显全部通过。每种传输的四组最终 goroutine 均4（基线4）、FD均12（基线14），GC后HeapAlloc均低于各自预热基线。实测最长Stop约10.9ms；该数字只描述本轮环境，不是性能承诺。

16组活跃/清理采样保存在 `evidence/lifecycle-100/native-coverage.json`；原始报告、全部引擎日志、进程退出状态及构建信息在 `native-evidence.zip`。活跃采样最大 goroutine38、FD28、HeapAlloc23736072B、RSS69144576B，不将活跃状态与停止后回落混为同一个样本。

前态 `89292ba5` 的相同原生 QUIC 测试模板由 git archive 执行，10/10在 Close 返回后的立即 UDP rebind 失败；修复源码 `59995a65` 的 archive执行100/100通过。生产 Go/依赖在 `59995a65` 与 `e611f0e0` 间无差异，后一个提交只修改验收端口预留、对应测试和文档。CI 的规范源码以 synthetic merge checkout `bde88b04854551e88bcbf8edd35f2debb79f05c2` 运行，其树 `835a788ccbce4e057a34d125c9ce0b5709f0fa80` 与 head完全一致。

首次CI [40266123277](https://github.com/VortexWang/Tunveo/actions/runs/40266123277) 为18/19通过，唯一失败是上述驱动端口冲突；其余三个百次race分片各400轮通过。开发中的QUIC端口占用试跑、短试跑空数组编码被验证器拒绝，以及全部首次生命周期CI原始结果均保留在 `intermediate-evidence.zip`。它们不能被修正后的通过结果覆盖。

## 规范 CI 百次 race 结果

源码 `e611f0e0` 的 [CI 40266322087](https://github.com/VortexWang/Tunveo/actions/runs/40266322087) **19/19成功**，包括完整Go test/race/vet、22项Python验证器测试、四个百次race分片、归档8项及Linux amd64容器7项。扫描为0个可达发现、1个模块级发现，不是零漏洞保证。QUIC archive对照在同一CI中前10/10复现、后100/100通过。

四个分片使用同一race二进制摘要，构建信息证明 Go1.26.10、`-race=true`、匹配的checkout及`vcs.modified=false`。每传输两种流向×两场景×100轮，**1600/1600轮、3200/3200次单次尝试回显通过**；16组资源回落全部在预定预算内，未观察到DATA RACE/panic。最长Stop约1.10ms，仍仅描述本轮环境。

| 传输 | race轮次 | 最终goroutine相对基线最大增量 | 最终FD相对基线最大增量 | GC后HeapAlloc相对基线最大增量 |
| --- | ---: | ---: | ---: | ---: |
| TCP | 400/400 | 0 | -2 | -79280B |
| QUIC | 400/400 | 0 | 0 | -18488B |
| WebSocket | 400/400 | 0 | 0 | -49872B |
| HTTP/2 | 400/400 | 0 | -2 | +6215008B（约5.93MiB） |

HTTP/2最后一组race堆样本高于预热基线，仍低于**运行前规定**的+8MiB预算；没有放宽预算或重跑替换该样本，也没有将其宣称为完全回到基线。该增量单独留给24小时验证继续观察；本轮数据不足以确定其具体持有原因。普通构建16组最终堆均低于基线，两类构建分别保留，不相互覆盖。

规范报告及全部进程日志见 [race覆盖](evidence/lifecycle-100/race-coverage.json)、[普通构建覆盖](evidence/lifecycle-100/native-coverage.json)、[CI元数据](evidence/lifecycle-100/ci.json) 和对应ZIP。完整TLS兼容矩阵结果见下节；lifecycle_100单项已达到上述范围，其他发布阻断保持。

首次相同行为的完整TLS矩阵（源码59995a65，[40266123141](https://github.com/VortexWang/Tunveo/actions/runs/40266123141)）已完整测得4160格：正例1717/1760、负例2400/2400，总计4117通过；43个失败全部在旧服务端，包含40格H2请求TLS0的空池panic和3次初始HTTPS EOF。8320个子进程均回收，无强杀。这是首次实测，不被后一次通过或不同的失败分布覆盖；全部26份报告、11份汇总及11份原版构建来源、86份失败进程日志保存在 `prior-matrix-evidence.zip`，首次通过格的完整日志另在原始GitHub工件保留14天。


## 最终完整 TLS 兼容矩阵

规范源码e611f0e0对应 [TLS acceptance 40266322078](https://github.com/VortexWang/Tunveo/actions/runs/40266322078) 十一个分片全部结束：**4118/4160通过**，正例1720/1760、负例2398/2400；预期语义键全部齐全，无重复或遗漏。

| 服务端/客户端 | 正例 | 证书负例 |
| --- | ---: | ---: |
| 新版/新版（含三种身份路径） | 800/800 | 1440/1440 |
| 新版/旧版 | 480/480 | 480/480 |
| 旧版/新版 | 440/480 | 478/480 |

新版服务端3200格全部通过。42格失败全部涉及旧服务端：40格为HTTP/2请求TLS0时的旧端空池panic；另2格发生在H2模式1的初始HTTPS GET阶段，分别为 untrusted-ca、64:1024、第10轮，以及 wrong-hostname、2:8、第2轮的EOF。这两格未进入数据证书判定阶段，不能标成证书拒绝通过，也不能据此宣称证书校验被绕过。TNV-012已有受控提前关闭复现，但这些具体EOF的根因不作未经证明的统一归因。

全部8320个转发子进程均回收、无强杀；其中旧端panic的进程是已经退出，不称为正常应用退出。所有成功正例的3440次TCP/UDP业务回显均为单次尝试，长度32768/512B，实际源/目的端点不同且对端为本轮前端端口。

完整26份报告、11份汇总、11份原版构建来源及8320份进程日志保存在 `compatibility-evidence.zip` 和 `identity-evidence.zip`。见 [覆盖与42项失败](evidence/lifecycle-100/matrix-coverage.json)、[CI元数据](evidence/lifecycle-100/acceptance-ci.json) 和 [ZIP校验和](evidence/lifecycle-100/archives.json)。第一次的43项失败仍独立保留，不以第二次的42项替换。

百次生命周期单项通过；完整兼容矩阵仍为failed，24小时持续负载、其他原生平台、最终集成审查和精确发布指纹仍未完成。PR保持草稿，未合并、未创建标签、未发布。下一项准备24小时持续负载验收，持续观察H2堆样本及资源趋势。
