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

8项新增回归覆盖完整同进程归属、缺失/乱序/哈希/时钟/身份守卫、原负载及after_stop冻结、错误回执、完整及时的回执前缀、地址新代次、实际/proc/self采集及资源失败仍保留双阶段证据；全套Python结果以本轮日志为准。初始提交时真实CI尚未运行；本轮实测和独立复核见下文。

```sh
python3 scripts/soak_mapping_retention.py --binary bin/probe \
  --control bin/ledger-control --tracer /path/to/pinned/bpftrace \
  --artifacts artifacts/mapping-retention
```

专项工作流`.github/workflows/soak-ledger-retention.yml`会构建原race探针及C控制，运行Python回归，再执行上述有界诊断；失败也上传全部artifacts，保留30天。运行前不预设结果；以下已读取真实CI原件并独立重放，原失败状态保持。


## 本轮真实CI与独立重放

规范执行源码 `99a0ec17e7eea87d7cfee7c9856fffd970dec90b`，实际CI检出 `5c70c5d433d0b533a1b039239e92c0eec56ff24c`，完整Git树均为 `60ba41478f84e88662a08d8d8ea66a38d238675d`。探针构建信息为干净的实际CI检出、Go1.26.10 linux/amd64及race构建；规范/CI Git对象与七份审计依赖源码blob均已核对。后续文档证据提交不算新的负载运行。

[专项CI40490226221](https://github.com/VortexWang/Tunveo/actions/runs/40490226221) **failed**，原错误为 `ValueError: active resource bound: rss`。本地和专项CI均86项Python通过。真实C控制、42个warmup/measured点与26个停载点（25个GC点+1个显式Go回收点）审计全部通过；完整负载180.000919539秒，1350TCP+450UDP无失败/丢弃，含预热1919业务事件均独立验证。完整捕获1284056事件，Go内存台账mmap1083、munmap50、brk3对；无Go mremap。本轮控制和目标/观察者实际身份及进程组均验证，未超时、未强制清理，原始资源/业务证据完整。

[原始ZIP12727627992](https://github.com/VortexWang/Tunveo/actions/runs/40490226221/artifacts/12727627992) SHA256为 `6016e43d58134119343a0aca4b93d6e676cf554b5289863cfd2c43eefe08ee52`，与发布digest一致、CRC通过。原始逐线程记录已重新解析，上下文/真实syscall及包装配对、exec隔离、实际进程关系、所有原始smaps/hash/point/rollup、冻结load/after_stop与回执均复核，重放出的所有负载及停载结果与CI保存结果一致。停载读取最大耗时3.429477ms，最大距checkpoint24.549193ms，均满足100ms；另独立核对26点单调时钟相对原点存在共同合法区间，防止晚写报告伪装成新发布点。

### 预算仍失败

后半预热基线：负载时钟10.005479646秒、123805696B（118.0703125MiB）。measured峰值：187.008529215秒、203214848B（193.80078125MiB）。增量79409152B（**75.73046875MiB**），超64MiB **11.73046875MiB**。原验证器离线再运行得到相同资源失败，未出现acceptance，不用停载低值替代此峰值。

### 同进程停载结果

| 选点 | 所属时钟秒 | 总statm RSS MiB | 已观测运行库家族 MiB | 未归属匿名 MiB | race shadow MiB | Go命名堆 MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 原负载峰值 | 负载187.0085 | 193.80078125 | 61.80078125 | 16.27734375 | 50.234375 | 46 |
| 首个停载GC | 停载0.0038 | 158.4453125 | 62.6015625 | 16.27734375 | 53.60546875 | 9.7265625 |
| 末个停载GC | 停载120.0070 | 161.08984375 | 62.71484375 | 16.27734375 | 54.1484375 | 7.50390625 |
| 显式Go回收后 | 停载120.0599 | 159.99609375 | 62.71484375 | 16.27734375 | 54.30078125 | 7.65625 |

上表来自同一PID和唯一目标exec后的同一份台账；负载/停载时钟分开，排序与区间内调用使用原始CLOCK_MONOTONIC。smaps与statm相邻读取非原子、表未列全部分类，不能强制加总。

| 区间 | 总RSS变化MiB | 家族变化MiB | 未知变化MiB | 已捕获内存调用 |
| --- | ---: | ---: | ---: | --- |
| 负载峰值→首个GC | -35.35546875 | +0.80078125 | 0 | mmap21、munmap1 |
| 首个→末个GC | +2.64453125 | +0.11328125 | 0 | mmap132，无munmap |
| 末个GC→Go回收 | -1.09375 | 0 | 0 | mmap6，无munmap |

负载峰值→首个GC的Go命名堆驻留下降36.2734375MiB；该区间还包含原负载收尾、端点/fixture关闭与GC，不能把变化全部归给单一动作。120秒GC首末家族62.6015625→62.71484375MiB，显式Go回收前后家族保持62.71484375MiB；后两段的整匿名VMA端点比较未发现边界/代次/来源变更，家族/未知仍沿用完整整VMA来源证据。Go回收时HeapReleased增加1.109375MiB，但这不能作为上述家族RSS已释放的证明。

这里只记录mmap/munmap/mremap/brk生命周期与已观测上下文；没有munmap不能证明不存在madvise等其他页回收行为。整VMA来源不是对象或缓存类型证明，120秒窗口内的保留也不能单独定性为泄漏、永久保留或长期有界。

### 可关闭与继续阻断

已关闭“同进程停载映射未覆盖”“回收前原始证据/回执未实测”的待验证项。没有关闭RSS资源失败、未知匿名来源、对象/缓存用途及长期行为；PR29和全部历史失败保持原样。常规CI40490226176为19/19成功；TLS40490226139的旧服务端请求TLS0分片failed，其余分片在本轮状态快照时仍有进行中项，不宣称完整兼容通过。

下一步应核验家族映射的具体申请/复用/页回收路径及预期释放条件，必要时把madvise范围与现有代次、smaps驻留绑定，并核对固定Go race运行库源码。不得仅凭Go堆回落或短期家族稳定提高64MiB门槛。生产探针/引擎/依赖未改；保持草稿、未合并/发布，正式普通构建资格及24h仍pending、未启动。

### 可复算证据

见[固定源码审计脚本](evidence/soak-mapping-retention/audit-ci.py)、[精简结果](evidence/soak-mapping-retention/audit-summary.json)、[CI/树快照](evidence/soak-mapping-retention/ci-snapshot.json)与[SHA清单](evidence/soak-mapping-retention/sha256.json)。完整原始ZIP、七份固定源码、独立重放全量结果及日志另随 `Tunveo-PR30-Mapping-Retention-Evidence-2026-10-27.zip` 交付，摘要不替代原件；Actions原件在2026-11-26到期。

```sh
python3 docs/evidence/soak-mapping-retention/audit-ci.py \\
  --archive pr30-mapping-retention.zip \\
  --sha256 6016e43d58134119343a0aca4b93d6e676cf554b5289863cfd2c43eefe08ee52 \\
  --scripts-dir scripts --output /tmp/pr30-full.json --summary /tmp/pr30-summary.json
```

离线脚本成功表示独立重现原始判定，输出仍是original_status=failed、qualifies_24h=false；不修改原件、不启动探针，也不回写原CI状态。
