# 已验证 CALL 的映射代次与驻留核验

PR36已经真实核对冻结ELF中TraceSwitchPartImpl→MmapOrDie的CALL、参数/返回与mmap配对。本轮只为这个路径增加生命周期台账，不把其他匿名映射自动归给TracePart，不修改原验证器、生产引擎或依赖。

## 字节、身份与事件

继续下载PR35 artifact12793001666并校验ZIP SHA256 `3722365efe2bf1f7f7378e2bae89fe5c3ad00ddb065449440e01208d746d63ce` 和ELF `2b332b9b27afeecca123e2d3fb5819c31bd787406d1393b1335e649a78eec391`。目标仍为构建b362c900b25935f39b3b8b271fc8664c4bde9a3c，不重编译替换。CALL/完成指令和文件偏移、精确目标exec/PID/UID、原始线程序号/SP、子进程关系、退出/清理和tracer丢事件守卫均保留。此次另归档实际tracer ELF和哈希，补足PR36只记录tracer哈希的证据缺口。

同一原始序号流捕获mmap进入/退出（addr/len/prot/flags，不声称已记录fd/off）、munmap、mremap、madvise、brk。所有额外系统调用先在原始流按TID配对并校验完整序号；只有明确标出的CALL验证投影重新编号以复用PR36验证器，随后把验证成功的mmap恢复到原始TID:seq ID。投影不替代原始序号审计。只有已验证CALL的mmap获得validated_tracepart_call标签，其余请求保留unresolved。

本轮只覆盖上述系统调用；exec加载和其他未观测映射机制不会因此取得来源证明，内核生成VMA或覆盖不完整的范围保留未知。

统一使用CLOCK_MONOTONIC。归档每个系统调用tracepoint布局、内核、tracer固定源码93c593f6dab2e930d6198cfaa52b29d19a8c0647及构建配置/日志，bfd边界检查保持，不使用uretprobe/unsafe。

## 新台账的保守规则

- 每个成功mmap使用原始TID:seq作为新代次。部分成功munmap拆分区间，幸存部分保留原代次；MAP_FIXED替换只在新返回范围建立新代次。同地址复用不继承旧归属。
- 成功mremap移除旧范围并建立新代次，记录源代次；只有原大小内可完整证明的范围继承请求路径，扩展部分保留未归属。成功的old_len=0克隆或MREMAP_DONTUNMAP等不支持变体直接阻断，不能按普通移动处理。
- 失败的非fixed mmap不删除原区间；其他失败变更请求对可能受影响的已知区间只取消归属，不宣告已释放。无法证明的范围保留unknown。旧台账重放函数不会参与本轮归属计算。
- madvise仅记录请求/返回，不改变映射代次，不把成功请求字节当作RSS归还。brk只保留观察到的边界变化，堆来源默认未知。
- 时间重叠且地址可能相交的操作标记歧义，归属降为unresolved；不靠完成顺序猜测真实内核先后。未支持变体、不可能的非fixed覆盖、丢失/重复/未配对操作、身份/时钟失败必须阻断。

复用旧模块的采样、点哈希和observer ACK实现；映射重放/归属使用新模块。VMA仅在采样前后整段由同一稳定请求路径完整覆盖、代次一致且读取期间无重叠操作时计入该路径；不按地址覆盖比例分摊RSS。内核加载、未观测源、混合或缺失覆盖都保留未归属。已知地址带只作为分类，不能替代请求/对象证据。

## 真实控制和负载顺序

1. 先运行新的C控制：guard隔离的4MiB固定CALL分配并触页→DONTNEED→失败的非对齐DONTNEED→重新触页→中间2MiB部分unmap→同址MAP_FIXED复用→固定移动/扩展mremap→释放。8个原子marker与同期完整smaps必须齐全，代次、幸存范围、已知RSS变化和释放空洞逐项匹配；400ms控制停留只为观察采样，不代表生产时序。
2. C控制通过，才运行冻结目标15秒真实控制，随后180秒真实负载。每个阶段独立进程，原12秒预热、5秒采样、transport3/mode1/TLS1、workers2/qps10、pool16..64保留；180秒阶段另有原120秒GC观察、显式Go回收及observer ACK。每个进程内部预算基线不重置，不以15秒结果替代180秒。
3. 全部负载点/停载点须有同期完整smaps，读取时间不超过100ms、checkpoint年龄不超过100ms，PID启动标识/可执行inode、原始文件与点哈希核验。原load/after_stop证据在驻留阶段不得变化。
4. 15秒或180秒资源超限继续保存其失败，最终job失败；不能用后一个结果替换前一个。证据/控制无效则停止后续阶段。原RSS增量64MiB逐点预算与原验证器不改。

这轮是一轮180秒+120秒诊断，不是三轮、不是THP干预对照，不是24小时验收；缺少带/不带新追踪器对照，不能宣称已排除观察开销。最终只能提供请求路径/映射代次与整VMA驻留关联，不能把InternalFree、映射释放和RSS回落互相替代，更不能凭累计虚拟字节证明无泄漏。

## 本地与CI状态

本地14项回归通过：真实C生命周期运行/指令核验，部分unmap、固定复用、失败变更、madvise、mremap扩展/不支持变体、并发歧义、完整序号投影和缺退出/错误UID等。实际BPF控制、同期采样、真实负载与CI完整套件尚待运行。控制失败、采样缺失或预算超限都不降低门槛。

job65分钟：回归5、下载3、工具构建35、布局/工具归档2、控制+负载15、上传2分钟上限，另留调度/清理余量。所有历史RSS与TLS失败保留，草稿/未合并/发布，qualifies_24h=false，24h未启动。

参考：[Linux mmap/munmap](https://man7.org/linux/man-pages/man2/mmap.2.html)、[mremap](https://man7.org/linux/man-pages/man2/mremap.2.html)、[madvise](https://man7.org/linux/man-pages/man2/madvise.2.html)。实际支持范围以上述控制和失败守卫为准。
