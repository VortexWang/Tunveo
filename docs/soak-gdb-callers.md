# Sanitizer mmap上层调用者诊断

PR25确认两轮Go堆大页全程禁用的race仍超原64MiB RSS增长预算，约80MiB未命名匿名驻留仍未细分。PR23的strace原栈通常只展开到internal_mmap。本实验换用GDB独立观察相同Go1.26.10 Linux/amd64 race二进制的上层栈，生产实现、负载探针和原预算不改。

只支持ET_EXEC固定地址ELF，nm唯一定位实际`_ZN11__sanitizer13internal_mmapEPvmiiiy`入口，断在精确入口地址，按Linux amd64 C ABI保留寄存器参数、进程/线程、GDB原始bt32和时间；FinishBreakpoint另记返回rax、对应ID及线程。unsigned -errno区间不当成功；没有返回的调用不计成功字节，失败/未知帧及越作用域保留，不按名称推测缺失帧。此方法没有完整munmap/mremap/其他mmap台账，累计虚拟请求字节不是当前映射量或RSS，也不能把本轮调用者搬到先前80MiB VMA上。

先以独立C ABI的1MiB匿名分配做控制：精确匹配返回指针、大小、256个触碰页和校验值1792，并必须展开control_mmap/control_parent/main。C控制使用调试信息、关闭帧指针和尾调用优化，非PIE；不链接进引擎。控制通过后才做一次GDB跟踪60秒H2 mode1（12秒预热、5秒采样、TLS1、pool16:64、2workers、10QPS），原资源/调度/事件/引擎日志仍独立检查，跟踪影响时序也如实保留失败，不当性能基线。

无论调用者诊断是否成功，另执行一次原始无GDB 180秒pilot，原验收/事件/映射审核不变且失败不重试。两个窗口是独立进程，不比较成精确开销或证明24h有界。不改变GORACE history/刷新策略、GODEBUG、宿主ptrace/THP策略，也不添加Engine调试API。

依据：[GDB Python breakpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints-In-Python.html)、[GDB Python frames](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Frames-In-Python.html)。GDB可以提供不同于strace的栈展开路径，是否能取得本二进制更高层帧必须由实测确认，不预先承诺。Python50项通过，C触碰控制本地通过；实测结果及停止自动实验的依据如下。正式24h仍pending，保持草稿。


## 源码与两次实际失败

初版源码`0db125563760d41f9b7146e6c8be3c19d0bdbfdc`，CI检出`92366d00a7039d11086f7f25974988df7d6b953e`，完整Git树均为`cc35e6d4c5a5f8a5dbfdb9669e44a02cfe7e3958`。参数修正版源码`1074d2a5f296f75f3946a8e53b54a6e5deb48a7b`，CI检出`0c119b0c4158a50ec920315be2740e4ae2c86190`，树均为`fe4b48f00517d74657d70c3a97318573665ecd6f`；均以实际git对象核对，探针构建干净、版本Go1.26.10 Linux/amd64。Go race syso SHA为`5bdd6b292a1d7bb4a21c3134bafec7545f23133e2e640fed265a7f8c5b67a638`。

[初版CI40422732629](https://github.com/VortexWang/Tunveo/actions/runs/40422732629)failed：1MiB C控制完整通过，但GDB的run带重定向时覆盖了--args原探针参数，native因invalid soak settings退出2。只有24对启动期入口/返回，无native业务报告，不计60秒负载。修订将完整参数显式写入run命令，增加回归检查；不是覆盖旧失败，也没有修改原资源预算。

[修正版CI40423431181](https://github.com/VortexWang/Tunveo/actions/runs/40423431181)仍failed：C控制再次通过，探针参数原文已匹配，但GDB在360秒上限超时。原文4325条入口、36条返回，最后与最初记录相隔约359.49秒；没有gdb-result.json。native仅保留running启动报告，预热/正式计数均0、points为空、measured_seconds=0，不能把这个尝试当作完成60秒窗口或任何业务覆盖，也不能把未匹配入口当成功映射。

超时的根因尚未确定，不能只凭展开信息缺失认定全部原因。GDB的返回断点依赖展开结果，真实Go二进制不能用C控制通过代替有效性证明。本方法尚未取得更高层分配者、RSS所有权或任何泄漏定论。

## 已确认的栈展开限制及守卫

两份CI实际ELF的readelf解码均含11285条FDE，但internal_mmap、MmapNamed、TraceSwitchPartImpl这三个选定入口地址均没有FDE覆盖。原始GDB实际栈通常为internal_mmap→MmapNamed→未知，后续还有无法解析的地址；未知地址不是已经验证的函数帧，不据此补全TracePart/allocator类别。存在.debug_frame段不等于目标C++函数具备可用展开信息；仅凭这些数据也不证明GDB具体使用了哪种展开器。

最终守卫源码`72c46ad030601f2d28d11ab539cb12df18ff79da`（树`f4698a5dea4b2dd204cfc4632700c7c5dd860e96`）在启动GDB前检查精确入口是否被readelf解码FDE覆盖；缺失即拒绝。两份不可变CI ELF回放均被拒绝，本地C控制入口有覆盖，52项Python测试通过。此必要条件不是充分正确性证明，也不声称根因已修复。没有重复执行已失败的GDB实测；该工作流移除PR自动触发，仅保留workflow_dispatch，当前Go race路径被守卫阻断，等待改用不依赖猜测展开的函数入口/退出上下文观察。

## 无跟踪原资源结果

每个版本另有一个原始无GDB 180秒H2 mode1窗口。原样审核事件/引擎日志、smaps哈希/范围、原预算、native退出与自身子进程回收，两轮均因RSS增量超64MiB而failed；业务成功不能覆盖该失败。

| 来源 | 完整业务交换 | 审计事件含预热 | 原statm RSS增长MiB | 原资源结果 |
|---|---:|---:|---:|---|
| 初版后无跟踪180s | 1800 | 1919 | 72.31640625 | failed: rss |
| 参数修正版后无跟踪180s | 1800 | 1919 | 66.36328125 | failed: rss |

这两个完整负载窗口合计3600业务（2700TCP/900UDP）与3838审计事件，无业务失败/丢弃/重试，自身子进程正常回收。两次GDB启动/超时尝试均不混入这个窗口计数。

**隔离限制：**修正版超时后没有保存GDB inferior已回收或宿主没有残留观察者进程的证明。后续180秒窗口自身的事件/退出/预算仍能重算，但不能当成已证明干净隔离的性能对照，不能把两轮RSS差归为修订效果。没有用该轮低值宣称泄漏减少，也没有补写不存在的清理证明。

## 来源、审计与后续范围

Go1.26.10官方race README将amd64v1 Linux syso关联至LLVM `51bfeff0e4b0757ff773da6882f4d538996c9b04`加Go随附补丁；补丁为trace local_head初始化，本轮没有修改它。该LLVM源码存在TracePartAlloc新建及复用路径，但本轮没有实际栈证据把约80MiB未命名匿名页认定为trace分片，更没有调用测试重置/刷新或降低history来掩盖增长。固定来源URL/blob/SHA见source-profile.json。

两份原始CI ZIP发布digest及CRC、C控制指针/触碰/调用链、部分入口/返回ID/线程/时序、原始错误/超时、两份native启动状态、无跟踪完整窗口事件/日志/映射均独立复核。失败执行仍保持失败；部分原文的完整性复核不等于完整业务或性能验收。参数修正版常规CI40423431012最终19/19成功；最终守卫另有52本地测试及实际帧原文回放，新的CI状态另存，不把旧CI当最终守卫CI。

全部原始ZIP、版本元数据、展开范围/守卫回放、独立审计代码/结果、50/51/52项测试日志及SHA清单在`docs/evidence/soak-gdb-callers`。生产internal/cmd、Go探针和依赖保持不变，原64MiB预算与24小时pending不变，未合并、打标签或发布。下一步改用精确函数入口/退出上下文关联请求，先校验观察者不扰乱探针，再谈当前映射及RSS归属。
