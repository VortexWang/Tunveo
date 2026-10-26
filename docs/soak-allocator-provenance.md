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

规范源码、首次解析失败与实际结果如下。


## 首次解析失败与修复

首次源码`adc042d50bfa5d9acdc6f5846a554b2c29bcb9df`，CI40338030239两个任务均failed。race真实32MiB控制本身完成，但strace的未完成/恢复调用拼接产生合法的`munmap(..., 46137344 )`空白，解析器过于严格而失败，后续race负载步骤未运行；ordinary控制完成，两窗口资源/业务通过，但同一解析问题使作业失败。保留两个原始ZIP和失败状态，不把离线复读写回绿色。

修正源码`73e8a40315f8bd61a58dfa8837e9390678907a2a`仅允许系统调用参数周围合法空白，并加入实际输出样式回归。冻结原版解析同一不可变race控制trace仍报unparsed munmap，修正解析通过；未改PID归属、完整VMA覆盖、资源预算或负载要求。Python由40项增至41项通过。新源码CI40338501723是含修正代码的新运行，不是覆盖原失败。

## 规范源码与原文复核

新CI检出`fbbfe95e37258c9c22156494e14f3ce0f18e9111`与73e8a40的树均为`3cfda4ae883d877819a45f4a9b9183c71eab1ea8`；旧CI检出6e421a55与adc042d的树均为d61ee2bc52c0a3e0d3eb6e8a296b50c06ed54c91，经实际git对象核对。生产/探针/控制Go、依赖及verify_soak.py与PR22相同。两个版本全部四份ZIP发布digest、CRC、逐文件哈希、控制/映射原文、原始业务事件及日志均下载后独立复核；初版缺少的调用栈审计只离线另存，不修改原ZIP。

新[分配来源CI40338501723](https://github.com/VortexWang/Tunveo/actions/runs/40338501723)普通任务success、race任务failed，后者由无跟踪180秒RSS超限触发；两种构建的控制、跟踪窗口和调用栈审计均完成。两构建分别在CI VM执行，不是严格同机差分。

| 构建 | 窗口 | 原statm RSS增量MiB | 资源结果 | 早/晚30秒RSS中位数差MiB |
| --- | --- | --- | --- | --- |
| ordinary | strace 60s | 6.3516 | passed | +0.0879 |
| ordinary | 无strace 180s | 8.6289 | passed | +2.3906 |
| race | strace 60s | 59.4180 | passed | +19.9766 |
| race | 无strace 180s | **80.0625** | **failed** | **+26.6875** |

四窗口合计4800正式业务交换/5276含预热事件；两种180秒窗口各1800交换（1350TCP/450UDP）。全部业务成功、无丢弃/重试、正常回收，没有用业务成功掩盖资源失败。加上初版ordinary两窗口为7200交换/7914事件，初版race未运行负载，不计数。

## 已确认的来源范围

新race带跟踪窗口的外部smaps增量58.734375MiB：shadow+23.37890625MiB、race metadata+0.97265625MiB、Go标注堆驻留+13.60546875MiB，另有**20.3828125MiB未命名匿名增长**位于已核对的sanitizer mmap分配区间。其他Go标注元数据补足余项，完整互斥求和见fixed-ci-audit.json。原statm增量59.41796875MiB是另一读取，不强行比例对账。

目标native线程子树的607次成功mmap中533次有可识别sanitizer调用栈，74次未归属；每份原文前后按时间重放，整块VMA均被仍存活的runtime分配区间覆盖才计入。真实栈通常只解析到`__sanitizer::internal_mmap`，更高层调用者未展开，因此结论是**运行库映射分配路径**，尚不能细分为trace缓冲、clock、depot或其他内部结构，未把整个运行库泛称引擎泄漏。部分基线匿名映射仍未归属，只是本窗口未归属RSS增量为0，不能称所有匿名内存都已查清。

该来源结论只限带跟踪窗口；没有把不同进程地址范围转移到无跟踪180秒窗口，也不追溯认定历史几次超限都同因。strace影响时序和分配，两个窗口分别报告。

## 增长边界仍开放

无strace race180秒仍按原64MiB预算失败，RSS最大增量80.0625MiB；预算所选同两点HeapAlloc只增约1.4288MiB。测量开头/末尾30秒RSS中位数181413888B→209397760B，增加26.6875MiB；对应HeapAlloc中位数约+0.8095MiB，HeapSys中位数-16384B。RSS有起伏，不能描述为单调增长，也没有足够证据证明已进入稳定平台；三分钟不是无限增长或24小时有界性的证明。

规范源码常规CI及TLS在本轮状态快照仍未全部完成；独立映射回归任务成功，但这里没有重新下载其另六个窗口作新覆盖声明。历史RSS、自然漏tick、旧端兼容与正式24小时门槛继续开放。下一步需取得运行库更高层分配来源及更长时间的回收/稳定性证据，而不是增加预算或用通过重写失败。

全部原始ZIP、失败/修复对照、独立审计脚本与结果、来源/构建指纹和SHA256清单见 [evidence/soak-allocator-provenance](evidence/soak-allocator-provenance)。未合并、未打标签、未发布，24小时未启动。
