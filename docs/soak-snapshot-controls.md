# 完整smaps采集开销对照与静态入口清单

接PR34：进程级THP已清除全部大页，race第三轮仍相对最初基线增长164.328125/162.23828125MiB；剩余增量主要位于已知shadow/metadata带外的未命名匿名映射。对象调用者未知，本轮先核验静态候选入口并检查额外完整smaps采集链路是否放大驻留，不能把静态符号或地址反推为对象归属。

## 两项独立证据

1. 每个构建归档精确目标ELF和C启动包装器及SHA256，另存nm完整定义符号、readelf段/节表、候选分配/回收入口的反混淆名称、地址、大小与反汇编。优先TracePartAlloc/Free、TraceSwitchPart、InternalAlloc/Free、MmapOrDie/UnmapOrDie、ReleaseMemoryPagesToOS等，反汇编最多128个候选，完整nm保留。缺失符号可能内联/被消除；存在符号/RET不证明可安全挂载或实际执行。尚不挂BPF、不证明对象或映射代次。
2. ordinary/race各一台独立job，同机同一二进制执行full→metadata_only→metadata_only→full。每进程内三轮原180秒负载、12秒预热、120秒停载GC/Go回收，各自冻结第一轮基线，RSS仍64MiB。所有样本均使用已有进程级THP控制，目标THP_enabled=0、GODEBUG为空、每份资源rollup的AnonHugePages=0。不同host/job之间不直接相减。

## 采集策略与校验

full保持完整smaps读取、压缩、哈希及VMA索引；metadata_only显式省略这整条额外链路，仅写同样阶段的PID/轮次/计数/单调时钟/目标THP状态/GODEBUG元数据，不伪造原文文件或哈希。默认策略仍full，新原生开关仅允许diagnostic-cycles=3；Python元数据模式仅允许已验证process控制。

metadata_only仍保留原measure()的资源smaps_rollup、MemStats、report JSON序列化、业务/引擎日志、强制GC和Go回收，因此比较只能解释额外完整smaps read/compress/hash/write链路的作用，不能宣布排除了全部探针开销，也不能区分其中哪一个子操作。两侧原验证器、固定初始基线、业务与日志审计及失败退出保持。后续局部预热升高不替换固定基线。

实际报告必须带diagnostic_mapping_policy，索引策略匹配；metadata_only索引不得有file或sha256_raw、目录不得出现mapping-*.smaps.gz。THP控制由包装器回读/PID、目标状态和原资源rollup核验；元数据模式的full-VMA大页字段显式为null，不能把缺失映射数据当作观测到0。保留内核/宿主THP策略前后值，同job源码和记录的二进制哈希必须一致。归档ELF可供后续按字节复核及反汇编。

每次资源/证据失败仍继续ABBA剩余样本，最终任一失败使job失败，矩阵不fail-fast。缺轮、无效控制、采集策略不匹配及业务失败不能当作RSS改善。元数据模式不存在原完整映射证据，不能因此获得默认验收资格，qualifies_24h始终false。

## 判读与后续

逐样本同时看第一轮基线、各轮绝对峰值/固定增量、停载低水位/Go回收后RSS、HeapAlloc/Inuse/Released、业务和时序。若省略完整采集后仍累积，继续追踪剩余分配/回收入口；若明显改善，只能认为该额外诊断链路可能贡献，需进一步拆分读/压缩/序列化控制，不删除历史原采集失败。full两次和metadata_only两次均保留，不能挑最低样本。静态候选清单只是后续真实调用控制的前置，不等于调用者归属台账已完成。

本地12项相关Python/C测试通过：保留4项固定基线/PID/缺轮/缺回收、5项THP及真实C exec状态/PID回归，新增3项静态候选边界与未验证process时拒绝元数据模式。新增Go回归检查元数据模式不生成完整映射文件或哈希且保留目标状态；本地无Go工具链；现已核对实际CI：每组120项Python测试与Go soak24h测试通过。真实ABBA与ELF证据已独立重放，见下方实际结果。

每job12个周期纯窗口至少62分24秒，预计一小时以上；job110分钟，测试/编译8、ELF/符号清单3、ABBA90、上传3分钟，预留6分钟。宿主sysfs不写，目标THP控制仅在独立诊断子进程。原验证器/64MiB预算、生产引擎与依赖不改。草稿、未合并/发布，24小时验收未启动，所有历史失败保留。

## 实际结果（2026-10-28）

[实际CI、独立重放与失败判定](soak-snapshot-results.md)：专项CI40628377687已完成，普通版通过，race因RSS失败。24轮、46056条事件、852份完整smaps及852条元数据记录已复核，归档ELF字节/符号/反汇编一致。race仅元数据第三轮固定增量170.09765625/178.04296875MiB，完整采集153.86328125/159.84765625MiB，均超64MiB。不能用不同初始基线的增量直接相减估计采集开销；只能确认完整采集不是失败的唯一解释。静态候选不证明实际调用或对象归属；24h资格仍为false，历史失败保留。
