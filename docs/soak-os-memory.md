# OS驻留内存证据（2026-10-26）

接PR20。历史H2 mode1 race的64.9023MiB和66.2305MiB增长均超过64MiB预算，仍是资源失败。新观测用于区分匿名页、文件页、共享页与私有脏页，不认定race影子内存、Go堆泄漏或其他分配者。生产引擎、依赖、调度、QPS、预热、验收预算不变；正式24小时未启动。

## 采集与独立复核

每个资源点新增`os_memory`：读取`/proc/self/smaps_rollup`，保留完整原文、每项kB转字节的结果、读取耗时。Rss/Pss/Anonymous/Private_Clean/Private_Dirty/Shared_Clean/Shared_Dirty/Swap为必要诊断字段；Pss_Anon/Pss_File/Pss_Shmem等按实际内核输出保留，缺失不补零。读取或解析失败明确记录error，不改原`statm` RSS预算或用零值冒充有效观测。该附加诊断不可用时原验收语义仍不变，但专项证据审计失败。

依据[Linux内核proc文档](https://cdn.kernel.org/doc/html/latest/filesystems/proc.html)：rollup是映射统计之和；PSS是按共享比例分摊的页，不能把Pss_File当作文件RSS；文件映射也可能含写时复制匿名页。这些字段有重叠，不能把Anonymous与Private_Dirty相加。不同读取与Go MemStats不是同一原子时刻；statm和rollup可能有时序及统计差异。读取及原文写入增加观测开销，已纳入现有measure/checkpoint/snapshot计时。

独立Python脚本重新解析每点原文，要求与字节字段逐项一致，再输出原验收所用后半预热statm最大值与测量statm峰值所对应两点的OS分项差值。固定两个采样点而非各分项另选最值，正负差均保留；不以rollup替代statm做验收。

```sh
python3 scripts/audit_soak_os_memory.py artifacts/trial-*/native/report.json --output artifacts/os-memory-audit.json
```

新增Linux控制：真实匿名mmap16MiB并逐页触碰，保持映射直到前后读取完成，要求RSS/Anonymous/Private_Dirty观测到至少12MiB增量（允许其他运行时页并发回收），随后解除映射。它只验证匿名页观测，不作为业务负载或历史归因证据。解析测试覆盖错误单位、溢出、负数、缺项、重复项和错误header。

## 同源码对照

继续现有工作流普通/race各三轮独立H2 mode1窗口：TLS1、pool16:64、2worker、10QPS、预热12秒、正式60秒、采样5秒，每轮一次执行。任何资源失败保留且使对应任务失败；独立OS审计始终执行。所有短测pilot，不把历史失败重写为通过，不升64MiB预算。

上一源码fe4e9b2的TLS acceptance40322786525最终failure：11分片中10成功，失败在`matrix (0, upstream-tunveo, explicit-ip)`正例步骤。这里仅核对任务状态，不推断失败格数或完整矩阵覆盖。常规CI19/19、Soak9/9、诊断3/3及历史RSS失败继续分别保留。

本轮规范源码和原始运行结果后续补录；即使普通/race短测均通过，也不关闭旧端兼容、自然漏tick、历史RSS超限与24小时门槛。
