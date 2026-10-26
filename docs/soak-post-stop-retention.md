# 停载保留内存与Go堆回收对照（2026-10-27）

接PR23。前轮无strace180秒race RSS+80.0625MiB超过64MiB预算；带跟踪窗口有20.3828MiB匿名增长关联到sanitizer mmap路径，但调用栈止于internal_mmap，尚不能细分内部用途。本轮优先区分停载后保留与Go堆可回收的内存，不修改生产引擎或依赖，不打开TSan flush_memory、不降低history，不增加64MiB预算。

## 追加诊断阶段

保留原H2 mode1/TLS1、pool16:64、2worker10QPS、12秒预热+180秒测量、5秒采样、单次业务尝试。原Stop、after_stop回落判定、业务日志/事件关闭与夹具清理完成后，追加独立120秒观察。沿用measure()的runtime.GC采样，每5秒记录，**不是不受干预的自然空闲观察**。随后可选一次debug.FreeOSMemory，单独标poststop_go_scavenge并记录耗时；最后留5秒让外部读取器完成。

[Go1.26.10源码](https://github.com/golang/go/blob/go1.26.10/src/runtime/debug/garbage.go)说明FreeOSMemory先GC，再尝试向OS返还内存。它不是保证清空所有RSS的接口；未修改全局GC比例、内存上限或race策略。显式Go回收发生于停载观察之后，不能解释为生产引擎修复或正式验收的一部分。

新post_stop_observation数组使用“清理完成后首个采样开始”的独立时钟。原Points、Counts、Measured、Idle、after_stop及调度计时不改；外部采集每个停载快照时冻结这些原字段的哈希，独立审计要求最终相同，防止回收阶段重写原负载失败。原RSS验证仍只用原预热/测量窗口，原after_stop仍来自原回落逻辑，不用后面的更低值替换。

正式模式的命令和原始报告验证均拒绝停载实验；native探针也拒绝24小时及更长负载携带此诊断。所有结果pilot/qualifies_24h=false。执行超时只按明确追加的观察时长延长，业务/资源预算不变。一次资源失败仍使CI失败，即使后面的RSS下降也不改绿。

## 控制与复核

新增真实32MiB Go分配、逐页触碰并持有，记录held、释放后的GC、显式Go回收后三个样本；已知对象不再存活后HeapAlloc应下降至少24MiB，最终HeapReleased应比持有时增加至少16MiB。记录每阶段原文，不预设GC后与显式回收之间一定释放多少RSS，也不假设race shadow按同样幅度释放。

Go协议测试核对追加记录不改原Points/after_stop/计数，并验证checkpoint失败时不会继续进入显式回收。最初1ms单位测试误要求至少3个点，而一次测量即可耗尽1ms；已修正为检查实际两阶段，初版测试日志保留，未改观察窗口或资源控制阈值。普通控制与race完整包测试通过，Python43项通过，包括拒绝正式验收携带诊断以及阶段顺序/完整性。

外部smaps仍有观察者开销与异步误差。独立审计重读原始映射、rollup、文件清单、事件和日志；单独比较停载初始、120秒末、显式Go回收后的命名Go堆、shadow、metadata和未命名匿名驻留。后者不因所在进程是race就直接标为某种trace缓冲。各读取不可精确加总到另一时刻的statm。

前轮规范源码73e8a40常规CI最终19/19成功，独立映射回归成功；TLS最终8/11分片成功，3个失败均为旧服务端配对（TLS0/1/2），未在此重做整矩阵失败格数或兼容性覆盖声明。PR23的RSS资源失败、初版解析失败及历史失败均保留。

规范源码、CI实际回收曲线与原始证据后续补录。正式24小时未启动，未合并、未发布。
