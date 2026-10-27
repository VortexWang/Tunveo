# 同进程映射台账的停载驻留诊断

日期：2026-10-27。接 PR29 的180秒RSS超限实证，本轮新增独立诊断，不改生产探针、引擎、依赖或64MiB预算，不启动24h。PR29及全部历史失败保留。

## 问题与实验

PR29已复算：RSS预算增量69.3359375MiB超过64MiB；峰值→末点总RSS下降11.7265625MiB，但已观测race运行库家族驻留增加2.9765625MiB。原外部映射只覆盖warmup/measured，不能用末点代替停载或释放证据。本轮继续在同一PID/地址空间中记录原完整内存台账，观察以下阶段：

| 阶段 | 设置 | 判定边界 |
| --- | --- | --- |
| 真实C控制 | 原held/hole/reused/moved/released五阶段 | 控制/身份/清理/读取守卫失败即阻断Go阶段 |
| 原负载 | H2 mode1/TLS1，pool16:64，2worker10QPS，12秒预热、180秒measured，5秒采样 | 完全沿用原64MiB预算，不用后续低值替代峰值 |
| 停载GC采样 | 探针已有的120秒post_stop_observation，每5秒强制GC采样 | 独立停载时钟；属于重复GC干预，不是自然闲置 |
| 显式Go回收 | 原生debug.FreeOSMemory，单列poststop_go_scavenge | 必须先完成最后GC点的原始smaps及回执，不能事后补造回收前证据 |

最后停载点之后仍沿用原生5秒暴露窗口。观察者上限450秒用于原负载、120秒观察及收尾，不延长measured负载；专项作业仍限30分钟。bpftrace固定v0.21.2源码、BFD开启、unsafe关闭，不用uretprobe/栈展开，也不修改宿主策略或GORACE/GODEBUG。

## 实现与证据

新入口`scripts/soak_mapping_retention.py`组合原控制/负载Collector与新停载Collector。原`scripts/soak_mapping_ledger.py`及正式验证器保持原样；Go探针已有的`--post-stop-observe 120s --diagnostic-go-scavenge --post-stop-observer-ack`直接复用。

原warmup/measured采样仍写`pilot/snapshots.json`；停载单列`pilot/retention-snapshots.json`和`pilot/retention-mappings/*.smaps.gz`。每点保留原point、SHA、原始smaps gzip/SHA、PID/启动时间、实际二进制身份及CLOCK_MONOTONIC读取前后时间；读取耗时和距checkpoint均不得超过100ms。停载point采用完整精确比较，不使用负载两个晚填计时字段的例外。

首个停载点冻结`points/counts/warmup_counts/idle_baseline/after_stop/measured_seconds/scheduler_timing/stop_seconds`的整体SHA；每点读取前后及最终报告都须一致。120秒末GC点只有在全部已发布停载点按序完整采集、最后点时效合格、原始文件和台账索引写出后才原子发布回执。回执绑定point、原始smaps、记录和冻结负载SHA；最终独立核对。缺点、重复、乱序、PID复用、exec变化、旧/错回执、读取超时或原负载被改写均failed。

终态用同一份完整捕获台账重放负载和停载映射，维持原完整VMA覆盖、代次、失败撤销、并发/在途变更规则。精细路径与更宽运行库家族分开，空上下文不改标已知，不按地址长度分摊RSS。输出负载峰值→首个停载GC、首个→末个GC、末个GC→显式Go回收三段比较，列出分类驻留变化、相同边界/代次/来源的RSS变化、边界或代次改变的整VMA及区间内mmap/munmap/mremap/brk计数。

边界改变不等于对象分配/释放；同址不同代次不得当作同一分配。家族是映射申请路径下界，不证明TracePart缓存用途、对象存活或泄漏。负载峰值到首个停载GC之间还包含stop、fixture关闭及GC，不能仅凭两个端点隔离其中单一因果。

本轮仍不保证drained/after_stop瞬时点的外部smaps覆盖；原after_stop数值只做冻结保护。能覆盖的是明确发布并持有的poststop_gc及poststop_go_scavenge。正式24h验证器仍拒绝这些诊断选项。

## 成功与失败

`experiment.json`始终标记`pilot_only=true`、`qualifies_24h=false`。控制、原负载映射、停载映射分别记录完成阶段；全部已审计映射及业务证据在原资源验证之前保存。如果资源超限，最终仍为failed、命令非零，`acceptance`不产生。若所有原守卫通过，状态仅为`diagnostic_passed`，不得解释为24h通过或历史失败消失。

8项新增回归覆盖完整同进程归属、缺失/乱序/哈希/时钟/身份守卫、原负载及after_stop冻结、错误回执、完整及时的回执前缀、地址新代次、实际/proc/self采集及资源失败仍保留双阶段证据；全套Python结果以本轮日志为准。真实CI结果待运行；不预设会释放、不释放或长期有界。

```sh
python3 scripts/soak_mapping_retention.py --binary bin/probe \
  --control bin/ledger-control --tracer /path/to/pinned/bpftrace \
  --artifacts artifacts/mapping-retention
```

专项工作流`.github/workflows/soak-ledger-retention.yml`会构建原race探针及C控制，运行Python回归，再执行上述有界诊断；失败也上传全部artifacts，保留30天。只有读到实际CI原件并独立重放后，才补写真实数值和结论。
