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

本地101项Python通过（新增15项），覆盖扩展序号/配对、默认拒绝未声明syscall、成功discard保留映射、失败及FREE不伪造RSS释放、地址复用/并发变更、整VMA不分摊、共存advice披露、真实控制契约和资源超限证据保留。C控制编译及七阶段本地运行完成；真实CI待运行，不预设会观察到或不会观察到家族页回收。

```sh
python3 scripts/soak_page_advice.py --binary bin/probe \
  --control bin/advice-control --tracer /path/to/pinned/bpftrace \
  --artifacts artifacts/page-advice
```

新专项`.github/workflows/soak-page-advice.yml`会保留实际内核字段布局与失败产物。共享ledger的旧15秒、180秒和停载专项也作为回归运行。保持草稿、未合并/发布，正式普通构建资格及24h仍pending。只有读取并独立复核本轮实际ZIP后，才补写数值与结论。
