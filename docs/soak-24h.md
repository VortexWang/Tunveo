# 24小时持续负载验收工具

本项接在PR16的百次生命周期验收之后。生产代码、依赖和既有转发验证器未变；新增工具尚不能证明已经运行24小时。`soak_24h`门槛保持pending，旧服务端兼容等阻断继续保留。

## 固定候选场景

新版/新版，Linux回环、TLS1、IPv4、pool min16/max64；四传输×两流向共8个独立profile。每个profile保持同一对Client/Server Start实例，2个工作线程，合计10次请求/秒，确定性75%TCP/25%UDP；每次TCP 32768B、UDP512B。UDP每worker复用一个源套接字，持续使用业务会话；TCP每次建立新业务连接。请求只尝试一次，不重试失败业务。

预热60秒后开始**连续86400秒**计时；实际测量使用Go单调时钟，预热、启动及停止不计入24小时。发生端点退出、重启、业务失败、负载调度丢弃或遗漏时钟tick，立即失败。压测结束后有界清理并回收进程；SIGINT/SIGTERM/外层超时均转发终止信号，等待、必要时强杀并保留失败；中断数据不能拼接成连续24小时。

完整压缩引擎日志和逐请求JSONL审计保存到本地。审计记录序号、worker、阶段、调度时间、协议、实际源/目的、实际读写字节、单次尝试、请求/回复SHA256及耗时。验证器流式重读，检查每worker连续序号、调度节拍、随机请求/回复摘要一致、源目的不同、长度和阶段计数一致；负载实际完成数至少为目标的90%，且应用失败/显式丢弃必须为0。没有恢复或自动覆盖旧证据目录。

报告记录Go版本/构建信息、二进制及脚本SHA256、PID、CPU型号/可见核数/GOMAXPROCS、总内存、可读时的cgroupCPU和内存限制、OS版本。不会收集主机序列号。8组复核要求相同二进制、源码、验证脚本和工作负载配置，缺组或重复组失败。

## 资源判定（运行前固定）

预热时每min(稳态采样间隔,2秒)采样，正式负载默认每30秒采样；每次先GC后记录goroutine、FD、HeapAlloc、HeapInuse、Sys和RSS。预热后半段至少3个样本的逐指标上界构成活跃基线，避免单一低点将池补充连接的周期波动误判为增长。

| 指标 | 稳态各样本上限（相对预热上界） | 后四分之一与前四分之一中位数增量上限 |
| --- | ---: | ---: |
| goroutine | +32 | +4 |
| FD | +16 | +2 |
| GC后HeapAlloc | +32MiB | +8MiB |
| RSS | +64MiB | +32MiB |

正式24小时要求完整首尾覆盖、至少120个稳态样本，无超过两倍采样周期+5秒的采样缺口。结束后5秒内，goroutine/FD/GC后HeapAlloc必须回到启动前闲置基线+4/+2/+8MiB；RSS结束值另行记录。短时pilot不判定长时趋势，也没有24小时资格。自动规则仅输出`candidate_passed`，仍需审查资源曲线、负载和机器条件；不自动改写发布门槛，不作零泄漏或生产性能承诺。

## 独立运行

先在干净的固定提交上构建普通版本；正式执行前`--describe`预检必须证明非race、可识别的40位源码提交和`vcs.modified=false`，否则在负载开始前拒绝，避免浪费24小时。以下命令每次只运行一个profile：

```sh
go build -trimpath -o bin/soak24h ./scripts/soak24h
./bin/soak24h --describe
python3 scripts/verify_soak.py --binary bin/soak24h --transport 0 --mode 1 --artifacts artifacts/soak-full/0-1
```

`transport=0/1/2/3`对应TCP/QUIC/WebSocket/HTTP2，mode为1或2。8个profile均要各自连续24小时；可在容量明确的机器上并行，或分配独立机器。并行运行时应记录同机总profile数和合计负载；不能把8个24小时串行任务称为一天内完成，也不能把多个短任务拼成一个24小时实例。

完成8组后，在同一版本工具下复核完整目录：

```sh
python3 scripts/summarize_soak.py --artifacts artifacts/soak-full --output artifacts/soak-full/suite-summary.json
```

长期运行应在可持续运行、留存证据的专用Linux环境执行。GitHub托管runner单任务上限6小时；自托管虽有更长job上限，GITHUB_TOKEN最长24小时会影响事后上传，因此本项的24小时命令不依赖GitHub任务或上传令牌。官方依据：[Actions limits](https://docs.github.com/en/actions/reference/limits)、[workflow timeout/token说明](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idtimeout-minutes)。正式运行没有在本轮启动。

## 短时CI与开发失败

`Soak smoke`工作流运行四传输×两流向的race pilot：预热12秒、实际负载60秒；独立验证器和原生错误回显测试先执行。所有结果明确`pilot=true, qualifies_24h=false`，即使延长pilot时长也不自动变成正式验收。

开发首轮2:8小池、10QPS、2worker未达到声明负载，预热期出现调度丢弃，保留两个原始失败；它们是独立容量场景，不作为16:64候选结果。随后20秒8组试跑业务均成功（各150TCP/50UDP），但以首个稳态样本为基线时，TCP/WS四组FD检查失败：采样可见连接池补充期间的周期变化。改用上述多点预热上界，原增量预算不变，且要求足够预热样本；四组失败不重新涂绿，使用新策略和足够预热重新运行。

已完成的本地开发试跑8/8通过，每组20秒、200次业务交换；该阶段为工作区开发构建，规范源码CI结果及原始证据在完成后另行记录。所有中间失败保留，生产源码未因此作修改，后续真实24小时仍需检查H2堆与RSS趋势。
