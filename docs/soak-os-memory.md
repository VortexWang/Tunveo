# OS驻留内存证据（2026-10-26）

接PR20。历史H2 mode1 race的64.9023MiB和66.2305MiB增长均超过64MiB预算，仍是资源失败。新观测用于区分匿名页、文件页、共享页与私有脏页，不认定race影子内存、Go堆泄漏或其他分配者。生产引擎、依赖、调度、QPS、预热、验收预算不变；正式24小时未启动。

## 采集与独立复核

每个资源点新增`os_memory`：读取`/proc/self/smaps_rollup`，保留完整原文、每项kB转字节的结果、读取及解析耗时。Rss/Pss/Anonymous/Private_Clean/Private_Dirty/Shared_Clean/Shared_Dirty/Swap为必要诊断字段；Pss_Anon/Pss_File/Pss_Shmem等按实际内核输出保留，缺失不补零。读取或解析失败明确记录error，不改原`statm` RSS预算或用零值冒充有效观测。该附加诊断不可用时原验收语义仍不变，但专项证据审计失败。

依据[Linux内核proc文档](https://cdn.kernel.org/doc/html/latest/filesystems/proc.html)：rollup是映射统计之和；PSS是按共享比例分摊的页，不能把Pss_File当作文件RSS；文件映射也可能含写时复制匿名页。这些字段有重叠，不能把Anonymous与Private_Dirty相加。不同读取与Go MemStats不是同一原子时刻；statm和rollup可能有时序及统计差异。读取及原文写入增加观测开销，已纳入现有measure/checkpoint/snapshot计时。

独立Python脚本重新解析每点原文，要求与字节字段逐项一致，再输出原验收所用后半预热statm最大值与测量statm峰值所对应两点的OS分项差值。固定两个采样点而非各分项另选最值，正负差均保留；不以rollup替代statm做验收。

```sh
python3 scripts/audit_soak_os_memory.py artifacts/trial-*/native/report.json --output artifacts/os-memory-audit.json
```

新增Linux控制：真实匿名mmap16MiB并逐页触碰，保持映射直到前后读取完成，要求RSS/Anonymous/Private_Dirty观测到至少12MiB增量（允许其他运行时页并发回收），随后解除映射。它只验证匿名页观测，不作为业务负载或历史归因证据。解析测试覆盖错误单位、溢出、负数、缺项、重复项和错误header。

## 同源码对照

继续现有工作流普通/race各三轮独立H2 mode1窗口：TLS1、pool16:64、2worker、10QPS、预热12秒、正式60秒、采样5秒，每轮一次执行。任何资源失败保留且使对应任务失败；独立OS审计始终执行。所有短测pilot，不把历史失败重写为通过，不升64MiB预算。

上一源码fe4e9b2的TLS acceptance40322786525最终failure：11分片中10成功，失败在`matrix (0, upstream-tunveo, explicit-ip)`正例步骤。这里仅核对任务状态，不推断失败格数或完整矩阵覆盖。常规CI19/19、Soak9/9、诊断3/3及历史RSS失败继续分别保留。

本轮规范源码和原始结果如下；短测不关闭旧端兼容、自然漏tick、历史RSS超限与24小时门槛。


## 规范源码结果

源码`54295c8f98177cebc18b61c4b1476526f6740474`，源码树`884508a0b8eb501cbcb2fceb8eabd3dc06564825`；CI检出`b64fb3d2dc1773ed341b6d7ca3439856b96f1032`的git树经实际对象核对相同。本地两构建Go1.26.10、vcs.modified=false，隔离干净checkout，cgroup8CPU配额/8GiB，普通/race每轮并行总20QPS。执行期间有只读复核、元数据/artifact下载；不是空闲专用性能机。CI两种构建在独立VM，不能作为严格同机差分。

| 位置 | 构建 | 三轮statm RSS增量，MiB | 同两点Anonymous增量，MiB |
| --- | --- | --- | --- |
| 本地 | ordinary | 17.1836 / 14.9570 / 15.1211 | 17.1211 / 14.9570 / 15.0625 |
| 本地 | race | 40.9180 / **64.0781（failed）** / 60.9922 | 40.9219 / 64.0156 / 60.9883 |
| CI | ordinary | 10.3750 / 6.3359 / 8.2930 | 10.3125 / 6.2773 / 8.2969 |
| CI | race | 50.4492 / 60.0352 / 60.3984 | 50.4492 / 60.0352 / 60.3359 |

本地race第二轮仍为资源failed：后半预热statm上界116367360B（10.0043秒）到峰值183558144B（67.0076秒），增长64.078125MiB超过64MiB。对应两点Anonymous增长64.015625MiB、Private_Dirty增长58.85546875MiB、Pss_File仅增长0.0634765625MiB；HeapAlloc从28145896B至28160968B，只增15072B（0.0143738MiB）。本轮增长主要对应匿名驻留页，没有同幅存活Go堆增长；统计覆盖引擎、夹具、驱动与运行时整个进程，仍不能确定分配者。statm与rollup相邻读取的差额不作分配归因。原始失败保留，未重试覆盖。

本地ordinary3/3、race2/3；专项CI普通/race各3/3。12轮共7200业务交换/8628事件，逐条核对原始事件、日志、逐文件哈希及正常进程回收；业务无失败/丢弃/重试，其中一轮资源失败。全部资源点的rollup原文重新解析，与报告字节字段完全一致；本地最大读取加解析9.407ms，CI3.568ms，12轮均未自然漏tick。这不是测量零开销的证明，也不解释旧轮漏tick。

真实匿名mmap控制在本地race测试中16MiB逐页触碰后，Rss/Anonymous/Private_Dirty均增加约16.04MiB；Go测试通过，Python35项通过。专项CI父/当前源码各十轮checkpoint延迟控制同样通过，只证明正确保留预期漏tick失败。

[诊断CI40330759181](https://github.com/VortexWang/Tunveo/actions/runs/40330759181)3/3、[常规CI40330759290](https://github.com/VortexWang/Tunveo/actions/runs/40330759290)19/19和WebSocket专项成功。下载三个专项原始ZIP，发布digest、ZIP CRC、逐文件哈希、事件/日志/资源与OS原文均独立复核；没有仅依赖CI的绿色状态。当前源码Soak smoke与TLS任务在本轮状态快照时仍运行中，未宣称完成全回归。

全部本地原始六轮、CI原始ZIP、独立审计、构建指纹、前轮TLS状态、测试输出与SHA256清单见 [evidence/soak-os-memory](evidence/soak-os-memory)。下一步需要映射/分配所有权层面的受控证据；匿名页增长不等于已经查明race影子内存，不能据此关闭缺陷或增加预算。正式24小时仍pending，未开始、未合并、未发布。
