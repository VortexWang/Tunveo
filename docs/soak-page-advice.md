# 同进程页回收请求与驻留证据

日期：2026-10-27。接PR30，本轮核对固定race运行库源码，并将madvise纳入同一个逐线程完整序号流。保持原180秒H2负载、120秒重复GC停载观察、显式Go回收以及64MiB资源门槛；不改生产Go探针、引擎、依赖、GORACE/GODEBUG或宿主策略，不启动24h。PR29/30及全部历史失败保留。

## 固定源码能说明什么

Go1.26.10标签解析到提交`4e8c85f5319d999bfd7617fdc191631e5634e3c5`；该版本[race README](https://github.com/golang/go/blob/4e8c85f5319d999bfd7617fdc191631e5634e3c5/src/runtime/race/README)声明linux/amd64v1 syso使用LLVM `51bfeff0e4b0757ff773da6882f4d538996c9b04`及对应[race_linux.patch](https://github.com/golang/go/blob/4e8c85f5319d999bfd7617fdc191631e5634e3c5/src/runtime/race/internal/amd64v1/race_linux.patch)。该补丁初始化Trace.local_head，不是页回收策略修改。以下是该固定源码层面的机制，不是对PR30全部62.7MiB家族驻留的对象用途证明。

| 固定源码位置 | 机制 | 本轮边界 |
| --- | --- | --- |
| [tsan_rtl.cpp](https://github.com/llvm/llvm-project/blob/51bfeff0e4b0757ff773da6882f4d538996c9b04/compiler-rt/lib/tsan/rtl/tsan_rtl.cpp)的TracePartAlloc/Free、TraceSwitchPartImpl | 无可复用part时才MmapOrDie；Free放入回收队列；切换时按local_parts安排回收 | 源码存在复用机制，不证明当前某个VMA内对象正空闲或未来有界 |
| [tsan_rtl_thread.cpp](https://github.com/llvm/llvm-project/blob/51bfeff0e4b0757ff773da6882f4d538996c9b04/compiler-rt/lib/tsan/rtl/tsan_rtl_thread.cpp)的OnFinished | finished trace parts排入全局回收队列并更新额度 | 结束并不自动等于每个part即时munmap |
| tsan_rtl.cpp的TraceResetForTesting | 显式遍历回收队列并UnmapOrDie | 测试接口不在本轮调用，也不靠改runtime排除原失败 |
| [内部分配器定义](https://github.com/llvm/llvm-project/blob/51bfeff0e4b0757ff773da6882f4d538996c9b04/compiler-rt/lib/sanitizer_common/sanitizer_allocator_internal.h)、[primary32](https://github.com/llvm/llvm-project/blob/51bfeff0e4b0757ff773da6882f4d538996c9b04/compiler-rt/lib/sanitizer_common/sanitizer_allocator_primary32.h)、[allocator.cpp](https://github.com/llvm/llvm-project/blob/51bfeff0e4b0757ff773da6882f4d538996c9b04/compiler-rt/lib/sanitizer_common/sanitizer_allocator.cpp) | InternalAllocator采用Primary32与large allocator组合；该primary的ReleaseToOS间隔为never，ForceReleaseToOS为空实现 | 不能将primary策略套给整个combined allocator或混合家族，也不能从映射入口反推全部对象类别 |
| [页归还函数](https://github.com/llvm/llvm-project/blob/51bfeff0e4b0757ff773da6882f4d538996c9b04/compiler-rt/lib/sanitizer_common/sanitizer_posix_libcdep.cpp) | ReleaseMemoryPagesToOS按整页调用internal_madvise；tsan的DontNeedShadowFor调用该函数 | 没有munmap不等于没有页回收请求；请求范围不等于实际归还RSS |
| tsan_rtl.cpp的BackgroundThread相关条件编译 | 内存profile及周期flush后台代码位于非SANITIZER_GO分支 | 不能照搬其他TSan构建的后台flush设置作为Go修复结论 |
| [Go mem_linux.go](https://github.com/golang/go/blob/4e8c85f5319d999bfd7617fdc191631e5634e3c5/src/runtime/mem_linux.go) | sysUnusedOS包含MADV_FREE、MADV_DONTNEED及固定映射回退；另有THP等advice | 本轮不改GODEBUG来挑选分支，实际类型和结果以trace为准 |

源码、来源及SHA另列source-manifest.json；原文与许可证随证据包保留。源码审查只是验证方法的依据，不能关闭资源失败或将整批家族认定为TracePart缓存。

## 新观察方法

`scripts/soak_page_advice.py`在同一序号流中新增sys_enter/exit_madvise，沿用原PID/UID、exec唯一性、完整逐TID序号、上下文嵌套和包装/内核mmap配对验证。共享ledger仅增加可选call_args和控制验证回调；原默认参数与四类内存syscall保持不变，默认追踪程序已与原版本逐字节比较一致。

Linux6.17上游的[系统调用定义](https://github.com/torvalds/linux/blob/v6.17/mm/madvise.c)为start/len_in/behavior。专项还会读取并归档实际CI内核的tracepoint布局，检查实际字段，不把上游版本当作Azure内核补丁的完整证明。

每次madvise保留请求地址/长度、behavior原值及有符号解码、返回值/errno、完整时间和上下文；成功/失败分开，失败不能当作无副作用。成功不是实际释放RSS，MADV_FREE不当作即时回收。零长度、未知advice、地址溢出、异常返回均有明确处理。

在调用开始/结束的原始台账中重放映射，按完整请求区间关联来源和代次；并发/在途映射变更或代次不同保持未知。同址复用必须使用新代次，不借用晚一点的地址标签。shadow地址带仅是已验证版本的地址分类，不等于对象类型或该次调用实际驻留。

负载和停载全部smaps统一按CLOCK_MONOTONIC排序，madvise事件引用前后邻近的真实采样及重叠读取点。整VMA边界/代次一致、没有区间内映射变更时才列整VMA前后RSS差；保留同区间其他重叠advice，不把5秒邻点差当单次调用的因果释放量。绝不按请求长度比例分摊整VMA RSS，也不把累计虚拟请求字节当释放字节。未采集process_madvise/mprotect等接口，缺失其他页行为的边界继续保留。

## 真实控制先行

新C控制在保护页之间固定4MiB匿名映射：触碰→MADV_DONTNEED→故意未对齐失败→重触碰→解除后异上下文同址复用→再次MADV_DONTNEED→解除。每阶段原始marker与外部smaps要求完整、及时；实际预期RSS为4/0/0/4/4/0/0MiB。

必须核验三次advice的真实入口/退出、参数及0/-EINVAL/0返回，成功discard不删除映射代次，复用后必须为新代次与新来源。控制、身份、清理或完整台账不合格即阻断Go窗口。本地C运行退出0且七阶段marker完整，但本地未作BPF/RSS资格声明，完整控制结论以真实CI原件为准。

## 负载、失败与验证状态

Go窗口继续H2 mode1/TLS1、pool16:64、2worker10QPS、12秒预热+180秒measured，再120秒重复GC及单列Go回收。原负载/after_stop冻结哈希、100ms读守卫、450秒观察者上限和回收前完整回执不变。已审计映射、停载、advice及业务证据在原资源验证前保存；64MiB超限仍failed/非零，qualifies_24h始终false。

初版本地101项Python通过（新增15项）；字段修正版本地/实际CI103项通过，分析缓存版本地104项通过（新增18项），覆盖扩展序号/配对、默认拒绝未声明syscall、成功discard保留映射、失败及FREE不伪造RSS释放、地址复用/并发变更、整VMA不分摊、共存advice披露、真实控制契约和资源超限证据保留。C控制编译及七阶段本地运行完成；初始状态为CI待运行；下面单列已完成的真实窗口和后续分析优化版的状态，不混用来源。

```sh
python3 scripts/soak_page_advice.py --binary bin/probe \
  --control bin/advice-control --tracer /path/to/pinned/bpftrace \
  --artifacts artifacts/page-advice
```

新专项`.github/workflows/soak-page-advice.yml`会保留实际内核字段布局与失败产物。共享ledger的旧15秒、180秒和停载专项也作为回归运行。保持草稿、未合并/发布，正式普通构建资格及24h仍pending。以下已完成窗口已读取原始ZIP并独立重放；后续版本仍按各自CI状态单列。


## 初版字段校验失败与修正

初版源码 `5a5e2c0c615915d4377abfa4665654df95118269`、CI检出 `40d09b54360bc6fc0eedabe7c5420d888628dee7`，完整树 `13e092cce24ef77020861b260e37b246946f85d7`。[CI40495389062](https://github.com/VortexWang/Tunveo/actions/runs/40495389062) failed保留：固定追踪器的实际字段名/类型正确，但它的-lv输出不带分号，初版错误地把分号作为必要格式。C控制及Go步骤均未运行，不能计入任何负载覆盖。

[原始ZIP12729708955](https://github.com/VortexWang/Tunveo/actions/runs/40495389062/artifacts/12729708955) SHA256为 `806588cb811124dcd47c579e7e13872ee7a963acd1249a612d5e3cc0f6df06d2`，digest/CRC已核验。冻结原检查对同一原件仍失败；修正版只兼容显示分号，字段名称/类型、重复及未知字段检查仍严格拒绝，新增两项回归，已用该原件直接验证。没有改内核、权限或资源预算。

## 已完成的真实页回收窗口

实测源码为 **`5a0dfea2ee25127a2a2c979d5534715cc415b916`**，实际CI检出 **`aa0619065e6eac26fb560f9c046013f1c30acde6`**，完整Git树均为 `886f47535d7725d3b5a1a9c86c87f2e1b77e1d5a`。探针为干净的实际CI检出、Go1.26.10 linux/amd64 race构建。

[专项CI40495990351](https://github.com/VortexWang/Tunveo/actions/runs/40495990351)最终 **failed**，原错误 `ValueError: active resource bound: rss`。七阶段真实C控制、42个原负载smaps点、26个停载点、完整回执、advice与业务审计均通过；180秒measured的1350TCP+450UDP无失败/丢弃，含预热1919事件独立验证。完整捕获1288312条记录，mmap1141、munmap46、brk3、madvise5994对，全部逐TID序号、上下文、真实syscall、包装返回与exec隔离重新解析并与CI原结果一致。

[原始ZIP12731876763](https://github.com/VortexWang/Tunveo/actions/runs/40495990351/artifacts/12731876763) SHA256为 `4fa01310afe9b28188761c9633c3c043a789d0a8ca539bfdf575a043dfe6e8a1`，与发布digest一致、CRC通过。实际tracepoint字段布局、固定BFD/unsafe关闭工具、原始smaps/point/core哈希、rollup、冻结load/after_stop、回收前回执、实际PID/启动时间/二进制及父子/进程组清理均复核；无超时或强制清理，所有原验证守卫保持。C控制的两次成功discard与中间-EINVAL已按记录时间绑定到对应marker前、上一阶段外部读取后。

### 资源仍失败

原口径后半预热RSS基线为10.004583844秒的128745472B（122.78125MiB）；measured峰值为167.007254348秒的198918144B（189.703125MiB）。增量70172672B，即 **66.921875MiB**，超64MiB **2.921875MiB**。原验证器离线重跑仍得到相同失败；没有acceptance。不能用停载低值、成功advice或后续偶然通过覆盖此失败。

| 选点 | 总RSS MiB | 已观测运行库家族 MiB | 未归属匿名 MiB | race shadow MiB | Go命名堆 MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| 负载峰值 | 189.703125 | 57.39453125 | 19.40234375 | 52.2890625 | 40.2578125 |
| 首个停载GC | 161.7265625 | 58.7890625 | 19.40234375 | 49.10546875 | 7.42578125 |
| 120秒末GC | 154.24609375 | 59.16015625 | 19.40234375 | 49.6484375 | 6.7109375 |
| 显式Go回收后 | 153.43359375 | 59.16015625 | 19.40234375 | 49.5078125 | 6.14453125 |

同进程、同台账、原始单调时钟排序。负载/停载自己的at_seconds仍分开，不把0秒停载点排到负载开始；smaps/statm为非原子邻近读取，表未列全部分类，不强制精确加总，也不把不同实验地址或数值移植过来。

### madvise实测

| 行为 | 实际返回 | 完整请求区间来源视图 | 地址带 | 次数 |
| --- | --- | --- | --- | ---: |
| DONTNEED | 成功0 | 未归属 | 其他地址 | 5288 |
| NOHUGEPAGE | 成功0 | 已观测运行库映射来源 | race shadow | 702 |
| NOHUGEPAGE | 成功0 | 已观测运行库映射来源 | race metadata | 2 |
| NOHUGEPAGE | 成功0 | 未归属 | 其他地址 | 2 |

Go窗口5994次均保留原始参数/返回值；真实控制里的失败请求另列，不混入此表。没有捕获到MADV_FREE。本轮未对单次advice估算释放RSS，也没有累计请求字节后称作驻留。

5,288次DONTNEED每次均有通过边界/代次与区间变更守卫的邻近Go命名堆VMA对照；这表示存在相应交集，不冒充Go调用栈或把整VMA变化全归给一条请求。独立补充审计还检查了请求在调用开始/结束的所有稳定映射子区间，而非只看完整请求的单一标签，避免把混合请求错误地当作完全无关。

该补充视图中，有已观测运行库映射来源的稳定虚拟交集共704次，全部为上表的NOHUGEPAGE/shadow或metadata；DONTNEED没有满足该守卫的已知来源交集。这里的“运行库映射来源”包含shadow/metadata，**不是表内57–59MiB未命名匿名RSS家族**，不得相加或直接转换成被释放字节。未知或不稳定区间、未捕获接口及内核自发回收仍不在这种正向关联证明内。

结合首末停载及Go回收前后，能够关闭本轮“madvise未捕获、请求与代次/邻点未核验”的缺口。仍不能证明59.16015625MiB全为TracePart缓存、已经无泄漏、永久保留或长期有界。源码中的复用/保留机制与本窗口保留现象相容只是推断，不是对全部对象用途的实测定性。

## 结果分析优化版与回归边界

后续源码 `5bb40c6852ef4b82a9c1a8baa96176e68c01e185` 仅对采样后的重复区间重放做精确完成状态缓存，并复用邻近窗口的advice候选集；没有时间分桶、删记录或改采样/预算。新增回归逐时刻比较缓存与原重放，含在途、相同地址复用及反向查询，本地104项通过。450秒原观察者上限不变，另给分析命令20分钟外层上限，给30分钟作业保留产物上传时间。

[该优化版专项40498176545](https://github.com/VortexWang/Tunveo/actions/runs/40498176545)在本次快照仍运行中，尚无可复核的原件，**不能借前一个实测窗口宣称新源码已完成专项CI**。本节与前述103项实测源码严格分开。原实测版本的所有派生证据已独立重算一致，补充区间交集优化前后输出逐项完全一致；原失败未回写。

共享ledger回归方面，实测源码的旧15秒专项40495990466成功；旧180秒40495990355、旧停载40495990430均failed。已核验后两份原ZIP发布digest/CRC和原native验证器，分别确认为原RSS资源超限，完整台账阶段为CI保存结论，此处未把它们算作新增完整台账独立重放。该源码常规CI40495990381成功。优化版的旧15秒40498176548及停载40498176539成功、旧180秒40498176522失败、常规CI40498176554成功；这组只复核CI状态，不能消除已完成窗口的失败。TLS仍未有完整通过结论，详见状态快照。

保持草稿、未合并/发布，正式普通构建资格及24h pending、未启动。下一步先取得优化版专项的终态及原件，再核验剩余匿名家族的具体对象/复用条件；不通过提高64MiB门槛、改GORACE或重置测试运行库来改写失败。

## 独立复算与原件

见[固定实测源码审计器](evidence/soak-page-advice/audit-ci.py)、[精简实测结果](evidence/soak-page-advice/audit-summary.json)、[原有资源回归摘要](evidence/soak-page-advice/regression-resources.json)、[按版本分开的CI快照](evidence/soak-page-advice/ci-snapshot.json)与[SHA清单](evidence/soak-page-advice/sha256.json)。完整初版/实测ZIP、八份固定实测Python源码、全量审计输出、17份primary-source输入及许可证随 `Tunveo-PR31-Page-Advice-Evidence-2026-10-27.zip` 交付；仓库摘要不替代原件。原件在2026-11-26到期。

下列scripts-dir必须指向实测源码5a0dfea的scripts，或证据包的pinned-scripts；当前优化版源码会被固定blob守卫拒绝，不得为了复算移除来源校验。

```sh
python3 docs/evidence/soak-page-advice/audit-ci.py \\
  --archive pr31-pre-optimization.zip \\
  --sha256 4fa01310afe9b28188761c9633c3c043a789d0a8ca539bfdf575a043dfe6e8a1 \\
  --initial-archive pr31-initial-layout-failure.zip \\
  --scripts-dir /path/to/pinned-scripts \\
  --output /tmp/pr31-full.json --summary /tmp/pr31-summary.json
```

离线成功表示原件独立重放一致，original_status仍failed、qualifies_24h=false；不会启动新负载或改写原CI。
