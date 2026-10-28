# 混合VMA的按页状态控制

PR38已实际重放映射代次与85份smaps，但180秒RSS仍增72.640625MiB。已验证CALL的37.625MiB虚拟区间不能直接当RSS；Go回收后只有2.25MiB整VMA RSS可保守关联，其余混合来源VMA不能按地址比例分摊。本轮新增页状态观测，不改变原预算和历史失败。

## 观测和保存范围

外部只读读取`/proc/<pid>/pagemap`，仅保存每页bits55..63的9个高位，uint16小端压缩。PFN和swap偏移低55位在内存中丢弃，不写文件；不读取kpageflags/kpagecount，不写clear_refs、不使用页保护ioctl、不触碰目标数据页。bit63 present、bit62 swapped，其他状态位原样保存作审计；present字节数不是RSS、PSS或独占物理页量，exclusive位也不能直接解释THP物理独占（[内核文档](https://www.kernel.org/doc/html/latest/admin-guide/mm/pagemap.html)）。

选择源完整smaps中可读、未命名、完全位于已知shadow/metadata带外的匿名VMA，包括RSS为0的未触页区域；不可读保留区、具名映射、文件、地址带内/跨带VMA明确不扫描，不将未扫描项写成0。每点选择总虚拟范围超过1GiB直接失败，不截断。此范围覆盖本次已验证CALL所在地址族，不能代表全进程所有页。

每个VMA连续读两次高位状态，归档原文状态向量、长度/哈希、各次单调时间和前后完整smaps；后读新出现的VMA明确列为未观测。每个页观测侧捕获最多250ms，独立于原smaps的100ms读取和100ms点年龄要求，原约束不改。前后拓扑/代次不一致、页范围内有重叠映射或advice操作则归属未知；页fault没有系统调用，双读相同也不构成原子快照。

后处理先验证原始事件完整序号、exec/PID/UID/可执行inode、原始smaps及点/observer ACK，与PR38同样重放映射代次。页只有在读取前后同一已验证代次完整覆盖且无重叠操作时才标记CALL路径；present/swapped两次计数分别保存，状态变化保留。累计present*4096只是观测指标，不能替代原生statm RSS门槛或分摊smaps RSS；同一映射内的对象/缓存复用仍未知。

## 真实控制

同一C fixture分别在进程THP disabled/enabled两种独立进程运行10阶段：未触页→只读零页→写入→DONTNEED→失败的非对齐DONTNEED→重新写入→部分unmap→同址固定复用→固定移动/扩展→释放。每阶段原子marker停留400ms，用于及时读取，非生产时序。

- 未触页/DONTNEED/失败advice后应0个present；只读零页后1024个present但原始smaps RSS仍为0；写入/重新触页1024个present且4MiB RSS。读零页控制专门防止present误当RSS。
- disabled通过PR_SET/GET_THP_DISABLE回读确认且控制VMA无AnonHugePages；enabled显式HUGEPAGE与MADV_COLLAPSE必须成功，held原始smaps至少2MiB AnonHugePages，缺正曝光则失败，不以平台不支持算通过。源区4MiB、2MiB对齐并有不可读guards。
- 初始代次在advice前后不变；部分unmap后512个已知代次页保留，复用后总present1024但旧代次只占512页；移动到新地址的复用部分不能继承旧CALL，释放后实际VMA消失。源/后smaps和页向量都必须满足控制。

本地真实THP-disabled子进程已验证页状态/零页RSS、页后无PFN保存、真实C运行；enabled正THP曝光和BPF联动仍待CI。测试在少数本地/proc外层PID命名空间只解析自己直接子进程并核验ELF；生产采集仍使用原BPF PID/启动标识，不做身份降级。

## ACK和真实负载

给既有retention Collector增加可选acknowledger回调；默认行为完全保留。新页Collector显式延迟ACK，原始smaps与全部该阶段页文件/索引写完后才放行原生Go回收；另存放行时间、索引哈希与历史前缀。页捕获失败不ACK。后Go回收页读取必须在放行之后，原生ACK字段及固定目标字节不改。

两种C控制通过，才执行冻结PR35 ELF的15秒控制和180秒+120秒停载/Go回收，原12秒预热/5秒采样、transport3/mode1/TLS1、workers2/qps10/pool16..64保持。真实目标不新增THP干预，两段独立进程；每进程原固定预热基线，原验证器/64MiB逐点门槛不变。资源失败保留，最终任一失败则job失败；控制或证据失败停止后续阶段。

这一轮没有新增三轮或带/不带页观察对照；不能外推24h、对象生命周期或无泄漏。页读取的调度/观测影响还需单独对照。所有PR38及更早RSS/TLS失败保持，草稿/未合并/未发布，qualifies_24h=false，24小时验收未启动。

## 验证状态

本地21项相关检查通过（新增12项、既有停载/ACK回归9项）：真实C disabled的10阶段页状态与RSS、PFN/swap偏移剥离、短读/坏向量、代次改变/部分页/拓扑与重叠操作拒绝、ACK默认兼容/延迟放行/失败不放行。完整既有套件、BPF和enabled THP控制、真实15/180秒及停载页证据待CI。工作流保留原生/控制/tracer ELF、原始页高位向量和系统调用布局，工具仍固定源码、bfd边界检查、unsafe关闭；job65分钟。
