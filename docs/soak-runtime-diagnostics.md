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
