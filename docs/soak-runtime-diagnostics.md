# 负载调度与HTTP/2 RSS受控诊断

2026-10-26，接PR19。新增验收工具观测字段和受控实验，不修改生产Go引擎、依赖、负载目标或资源预算。历史TCP mode2漏tick与H2 mode1 RSS超限仍是失败，不用后续通过覆盖；正式24小时仍未开始。

## 新增观测

每个采样点增加measure/checkpoint/snapshot耗时；报告增加最大ticker迟到、最大同步采样/写报告耗时，以及首次漏tick的时间、期望槽、实际槽和漏槽数。仍使用原调度与失败规则，既不补发追赶，也不降低QPS或容忍丢弃。checkpoint耗时在该次写入返回后才已知，因此中间文件最后一个点可能尚未记录完成耗时，最终完整报告会补齐。

资源样本增加HeapSys、HeapIdle、HeapReleased、StackInuse、OtherSys、TotalAlloc、Mallocs/Frees、NumGC、累计GC暂停和runtime.GC调用耗时。GC调用耗时不是STW暂停时长；Go内存统计不等于操作系统RSS，虚拟堆预留也不是已驻留内存，不能简单相减就归因为race影子内存或泄漏。新增统计与序列化存在观测开销；观测为相邻读取，不是原子快照；覆盖的是引擎与同进程夹具/驱动整体。

## 调度控制

同一真实回环TCP/UDP回显夹具，在首次checkpoint注入250ms延迟，10QPS的调度器必须继续按原规则报告漏tick失败。模板通过不代表负载成功，只表示受控失败被正确识别。使用同一模板SHA256，在父提交8c45fe5和当前源码归档分别执行十轮；当前版本还要求相应耗时和漏槽信息出现。

```sh
python3 scripts/repro_soak_checkpoint.py --ref 8c45fe55738a302d0b6e3274ee7ef8ed9e0c3221 --go go --repeat 10 --output artifacts/checkpoint-parent.json
python3 scripts/repro_soak_checkpoint.py --ref HEAD --go go --repeat 10 --require-timing --output artifacts/checkpoint-current.json
```

该控制用于证明同步checkpoint足以影响负载计时，不证明缺少这些字段的历史CI一定由此引起。本项没有移动采样线程、绕过GC或修改调度器来消除原失败。

## RSS对照协议

普通构建与race构建来自同一干净源码，各做三个独立H2 mode1短时窗口；每组预热12秒、正式60秒、采样5秒、TLS1、pool16:64、2worker、10QPS、75%TCP/25%UDP，单次业务尝试，无调用栈剖析。比较每轮RSS、Go堆、已释放堆、分配累计和GC数据。每轮独立归档，任一失败使相应CI任务失败，不重跑覆盖。普通/race是构建差异对照，不构成对历史一次RSS峰值的确定归因。

```sh
go build -trimpath -o bin/ordinary ./scripts/soak24h
go build -race -trimpath -o bin/race ./scripts/soak24h
python3 scripts/verify_soak.py --binary bin/race --transport 3 --mode 1 --pilot --duration-seconds 60 --warmup-seconds 12 --sample-seconds 5 --artifacts artifacts/h2-race-1
```

新工作流`Soak timing and RSS diagnosis`执行两组对照及原生调度控制。所有短时运行明确pilot/qualifies_24h=false，不增加RSS豁免，不改变原有+64MiB上限或其他资源预算；后续实际结果另行补录。

## 上一源码CI状态

PR19规范源码19653e6：常规CI40314437009的19项任务全部成功，Soak smoke40314437227的9项任务全部成功（pilot8/8），WebSocket专项40314436881成功；TLS acceptance40314437033失败，失败任务位于旧服务端/新客户端配对的TLS0与TLS2分片。精确失败单元格仍以原始矩阵报告为准；不把新一轮通过写回PR18那轮race6/8。任务状态保存在本目录后续证据中，正式24小时、原生平台与集成等门槛继续开放。

## 规范源码实测结果

源码`fe4e9b2f1383f1ac6038b256111d1d1d9833186b`，普通与race两个本地二进制均vcs.modified=false、Go1.26.10、同机两组并行20QPS，各三个独立60秒窗口。本地期间还进行了artifact下载及只读复核，不是空闲专用性能测试机。两种构建的CI则运行在独立VM，机器条件保留在原始报告，不能把CI行当作严格同机差分。

| 位置 | 构建 | 三轮RSS相对各自预热上界的增量，MiB |
| --- | --- | --- |
| 本地同机 | ordinary | 14.1328 / 16.1445 / 15.7109 |
| 本地同机 | race | 56.6562 / 66.2305（failed） / 61.0078 |
| 专项CI独立VM | ordinary | 8.3047 / 6.3125 / 6.3672 |
| 专项CI独立VM | race | 57.4609 / 59.7812 / 60.4375 |

本地普通3/3、race2/3通过；race第二轮RSS从110342144B增加到179789824B，增量66.23046875MiB，超过原64MiB上限。相同两个采样点HeapAlloc从26408872B至27306120B，仅增加约0.8557MiB；Go Sys从52320520B至69359880B。记录说明RSS增长没有对应同幅的存活Go堆增加，不能据此确定余量属于race影子内存、非Go分配、页驻留或泄漏。该轮保留failed，不加豁免，不调预算。

12轮（本地6+CI6）业务均完成600次交换，各719条含预热审计，合计7200交换/8628事件；无业务重试/失败/丢弃，正常回收、无强杀。12轮均未出现实际漏tick；其中一轮仍因RSS资源验证失败。因此没有证明问题已修复，也没有以新通过覆盖历史失败。

## 调度控制与观测结果

父/当前源码使用同一模板SHA256 `9df33d008abdbbb7a81285699d8f45adecb7486fbd6881bcc0c777833791273e`，本地分别10/10识别注入延迟导致的失败；当前报告记录checkpoint至少0.2501秒、ticker迟到至少0.1568秒以及漏槽信息。专项CI另外各十轮同样通过，当前checkpoint至少0.2500秒、ticker迟到至少0.1506秒。控制通过只代表预期失败和观测记录正确，不是成功负载数据。

实际六个本地H2窗口的最大tick迟到均低于0.012秒，最大measure（GC/资源读取，不含checkpoint）低于0.011秒；失败的race第二轮也未漏tick。这次补充数据没有解释历史TCP预热漏tick的具体原因，后续若再次发生可依据新增字段区分采样/写入耗时与其他调度延迟。

## CI、来源和证据

新[专项CI40322786732](https://github.com/VortexWang/Tunveo/actions/runs/40322786732)3/3任务成功；[常规CI40322786607](https://github.com/VortexWang/Tunveo/actions/runs/40322786607)19/19、[Soak smoke40322786680](https://github.com/VortexWang/Tunveo/actions/runs/40322786680)9/9成功。CI检出`a94c2261809983870d2ef9499b0ace053224e298`与规范源码fe4e9b2的树相同，实际git对象核对记录在补录中。所有专项artifact的发布digest、ZIP CRC、逐文件清单、原始资源、事件与引擎日志均已独立复核。

另独立下载PR19的八份race pilot artifact，逐份核对digest/CRC/清单并重读全部5752条事件及原始日志，8/8通过；CI检出61cac987的树与19653e6相同。该轮新通过不覆盖PR18 race6/8。PR19失败TLS任务的原始汇总有44条failed记录：40条旧服务端H2请求TLS0的握手阶段进程退出，4条旧服务端配对中证书负例在初始HTTPS握手收到EOF（3条expired、1条wrong-hostname），没有当作有效证书拒绝通过；本项未重做其余单元格的完整覆盖证明。

完整本地与专项CI原始数据、构建指纹、调度控制、上一轮CI资料和SHA256清单见 [evidence/soak-runtime-diagnostics](evidence/soak-runtime-diagnostics)。生产引擎Go、依赖、阈值不变，TLS/原生平台/集成及发布指纹等门槛仍开放。下一项需在固定环境细分OS驻留内存来源，并等待/捕获带耗时记录的自然漏tick；正式24小时保持pending，未启动、未合并、未发布。

补录：该源码TLS acceptance40322786525最终失败，11任务10成功，失败为旧服务端TLS0分片正例；不作完整覆盖成功声明。下一轮OS分项见 [soak-os-memory.md](soak-os-memory.md)。
