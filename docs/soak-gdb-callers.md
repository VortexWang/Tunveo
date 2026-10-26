# Sanitizer mmap上层调用者诊断

PR25确认两轮Go堆大页全程禁用的race仍超原64MiB RSS增长预算，约80MiB未命名匿名驻留仍未细分。PR23的strace原栈通常只展开到internal_mmap。本实验换用GDB独立观察相同Go1.26.10 Linux/amd64 race二进制的上层栈，生产实现、负载探针和原预算不改。

只支持ET_EXEC固定地址ELF，nm唯一定位实际`_ZN11__sanitizer13internal_mmapEPvmiiiy`入口，断在精确入口地址，按Linux amd64 C ABI保留寄存器参数、进程/线程、GDB原始bt32和时间；FinishBreakpoint另记返回rax、对应ID及线程。unsigned -errno区间不当成功；没有返回的调用不计成功字节，失败/未知帧及越作用域保留，不按名称推测缺失帧。此方法没有完整munmap/mremap/其他mmap台账，累计虚拟请求字节不是当前映射量或RSS，也不能把本轮调用者搬到先前80MiB VMA上。

先以独立C ABI的1MiB匿名分配做控制：精确匹配返回指针、大小、256个触碰页和校验值1792，并必须展开control_mmap/control_parent/main。C控制使用调试信息、关闭帧指针和尾调用优化，非PIE；不链接进引擎。控制通过后才做一次GDB跟踪60秒H2 mode1（12秒预热、5秒采样、TLS1、pool16:64、2workers、10QPS），原资源/调度/事件/引擎日志仍独立检查，跟踪影响时序也如实保留失败，不当性能基线。

无论调用者诊断是否成功，另执行一次原始无GDB 180秒pilot，原验收/事件/映射审核不变且失败不重试。两个窗口是独立进程，不比较成精确开销或证明24h有界。不改变GORACE history/刷新策略、GODEBUG、宿主ptrace/THP策略，也不添加Engine调试API。

依据：[GDB Python breakpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints-In-Python.html)、[GDB Python frames](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Frames-In-Python.html)。GDB可以提供不同于strace的栈展开路径，是否能取得本二进制更高层帧必须由实测确认，不预先承诺。Python50项通过，C触碰控制本地通过；GDB实测结果待本轮CI。正式24h仍pending，保持草稿。
