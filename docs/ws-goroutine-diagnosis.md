# WebSocket mode 2 goroutine 峰值诊断

2026-10-26，接 PR #17；仅增加验收诊断工具，生产引擎、依赖及资源预算不变。

## 已知问题和证据边界

PR #17 的规范源码 `ee3b813d83564629e3a4b3ccc0eba21eee6d16f4` 在 [Soak smoke 40291159968](https://github.com/VortexWang/Tunveo/actions/runs/40291159968) 的 WS mode 2 采样出现 goroutine 64，超过后半段预热上界29+32；随后回到29。该次失败保持失败，尚无当时调用栈，不能断言泄漏或认定环境原因。PR #17 的未上传本地归档没有在本项中冒充已恢复；原始 CI artifacts 仍是对应运行的证据来源。

## 新增诊断

`verify_soak.py --goroutine-diagnostics --pilot` 启用同步本地栈采样，未启用时不执行栈采样；无监听端口或额外采样协程。后半段预热上界与原验证器窗口一致，每次测量后记录新高点或超过上界+32的点。最多8份预热新高、8份稳态新高、8份超预算和1份停止后调用栈，gzip压缩、权限0600，写入失败传播为失败。所有输出由现有逐文件SHA256清单覆盖。

资源计数与随后调用栈不是原子快照，短命协程可能在两次观测之间退出。同步剖析有CPU/分配开销，可能影响调度；因此带诊断开关的运行只用于定位，Python入口在启动前拒绝正式验收搭配此开关。不能以诊断轮通过关闭原失败或提升24小时门槛。未放宽预算或排除任何资源类别。

```sh
go build -race -trimpath -o bin/soak24h-diag ./scripts/soak24h
python3 scripts/verify_soak.py --binary bin/soak24h-diag --transport 2 --mode 2 --pilot --duration-seconds 60 --warmup-seconds 12 --sample-seconds 5 --pool-min 16 --pool-max 64 --workers 2 --qps 10 --goroutine-diagnostics --artifacts artifacts/ws-diagnostic-01
```

新工作流 `WebSocket resource diagnosis` 在两个独立runner分别测试不可变原版与诊断版，各连续执行3个独立60秒窗口；每轮重新建立端点，保持负载、池容量、预热与预算相同。不重试失败窗口，不用后续成功覆盖；任一窗口失败使相应任务失败，始终上传全部证据。原版源码固定为上述40位提交，诊断版使用本PR源码；两种二进制都保留构建元数据及SHA256。

## 本地开发验证（非规范源码验收）

Linux amd64 / Go1.26.10，race。两轮顺序执行，固定同一负载与预算；运行期间共享工作环境有编译/检查活动，资源条件见原始报告，未证明调度失败根因。

| 运行 | 结果 | 事实 |
| --- | --- | --- |
| 原版不可变源码，60秒目标 | failed | 实测约31秒后漏1个调度tick；正式交换234 TCP/76 UDP，无业务失败，正常回收、无强杀；不视为完整60秒 |
| 新诊断版工作区构建 | pilot_passed | 完整60秒，450 TCP/150 UDP，719条含预热事件逐条校验；goroutine后半段预热上界29、稳态峰值37、停止后5（闲置4）；未复现64峰值 |

诊断轮生成4份调用栈：1份预热、2份稳态新高及1份停止后；未发生超预算，不能根据这些栈归因原64峰值。保持根因未确认，正式24小时未启动，`soak_24h`仍pending，旧端兼容和其他发布阻断不变。

本地完整 `go test -race ./...`、`go vet ./...` 及Python验证器结果见证据目录。新增真实阻塞协程栈/采样窗口/预算边界/峰值次数/权限/输出错误传播测试，以及正式诊断模式启动前拒绝测试。干净源码CI与3轮对照完成后另行补录。

完整本地失败与成功报告、审计、引擎日志、栈和构建来源保存在 [evidence/ws-goroutine](evidence/ws-goroutine)。诊断二进制为 `ee3b813+dirty`；提交后的源码文件哈希用于核对，不将工作区运行标作干净提交验收。
