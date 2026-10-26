# 未命名匿名映射分配来源（2026-10-26）

接PR22。上轮race的shadow约20–21MiB、Go堆驻留约10–12MiB之外，仍有约19–22MiB未命名匿名增长。本轮新增系统调用栈证据与三分钟观察，不修改Go引擎、负载探针、依赖、verify_soak资源预算或业务策略。历史超限不关闭，正式24小时未启动。

## 依据与方法

已核对官方Go1.26.10所用LLVM51bfeff0的tsan_rtl.cpp：MemoryProfiler/InitializeMemoryProfiler以及启动后台线程均受`!SANITIZER_GO`限制，不能靠设置GORACE profile_memory为该Go二进制取得后台分配统计。没有打开flush_memory_ms、降低history_size或改变race内存策略。

在允许ptrace的CI上，用strace -f -k -ttt -T记录mmap/munmap/mremap和进程/线程创建。外围Python的系统调用同样被记录，审计通过控制程序显式PID或probe原native_pid确定根进程，展开clone/fork子树后只使用目标调用，不混入观察者Python分配。保留原文、调用栈、时间和原始映射。

对每个完整VMA，在smaps读取起止时间分别重放成功mmap、munmap和mremap；只有整个地址范围均被仍存活的同类分配区间覆盖，且前后类别相同，才将该VMA的RSS归为该类。mremap、部分覆盖、缺栈或混合未知来源继续未归属。不按虚拟区间长度分摊RSS。多个race已知类别合并时只标race_runtime_mixed，不虚构细项。TracePartAlloc/TraceSwitchPart调用栈标race_trace；其他sanitizer/tsan栈仅作较宽的运行库类别，不直接等同具体trace缓冲区。

## 受控验证与时序限制

先在原32MiB触碰分配控制上采集调用栈与smaps，核对源码、PID、哈希、原文和分配区间。随后两种构建各执行一次原60秒H2 mode1窗口，加系统调用跟踪以取得来源证据；跟踪有观察者开销，若造成漏tick或资源失败，原样保留失败，不称有效性能验收。

另各执行一次无strace的180秒H2 mode1窗口，仍TLS1、pool16:64、2worker10QPS、12秒预热、5秒采样、单次业务尝试、原64MiB预算。与60秒数据分开，观察早晚变化，不通过调阈值或只挑通过窗口证明有界。180秒也不能证明24小时无泄漏。外部smaps与原statm仍是相邻而非原子读取。

本地已有两次外部smaps控制受权限限制，仍保留，不重试提升权限；本轮真实外部证据由CI采集。解析测试覆盖线程归属、未完成调用拼接、失败/取消区间、部分覆盖、混合归属和未知调用栈，未改原验收规则。

规范源码、实际控制、跟踪与三分钟结果后续补录。
