# PR33透明大页驻留定位与控制方案

日期2026-10-28。读取原ZIP12781915632，固定SHA256 7320d208f1f2e42a95e252dc72733f15aa947370b27b3c5b511876264df2337a。只读分析，不运行新负载，不改变GODEBUG、GORACE、THP或宿主设置。原64MiB门槛与全部失败保留。

## 选点与核验

每轮选择第一条retention_points=26且status=running的mapping checkpoint，紧邻该轮poststop_go_scavenge采样，避免使用5秒后最终checkpoint替代。验证原ZIP digest/CRC、PID/轮次、smaps原文哈希与实际读取时钟。六个选点smaps的AnonHugePages加总均与相邻report的rollup一致，但读取仍非原子，不能因此宣称时刻完全相同。原始地址只在本进程内分析，不移植不同实验的地址。

| 构建/轮次 | Go命名堆 THP MiB | 未命名匿名 THP MiB | 已知race shadow/metadata地址带 THP MiB | 总THP MiB |
| --- | ---: | ---: | ---: | ---: |
| ordinary 1 | 0 | 2 | 不适用 | 2 |
| ordinary 2 | 18 | 2 | 不适用 | 20 |
| ordinary 3 | 30 | 2 | 不适用 | 32 |
| race 1 | 2 | 50 | 0 | 52 |
| race 2 | 0 | 146 | 0 | 146 |
| race 3 | 0 | 158 | 0 | 158 |

Go命名堆按原smaps名称[anon: Go: heap]识别。race地址带仅采用固定版本既有分类：shadow为[0x200000000000,0x21c000000000)，metadata为[0x300000000000,0x400000000000)；仅对完全落在带内的未命名映射应用，不覆盖Go命名堆、不按交集比例分摊。地址带不等于对象用途，未命名映射不能冒称TSan/InternalAllocator/TracePart来源。

ordinary第二/三轮的大页集中在同一个已观测Go堆VMA边界[0x33c875000000,0x33c878000000)，其THP为18→30MiB，VMA RSS为24.0703125→34.55078125MiB。相同边界没有映射代次证据，不能证明对象复用。另有2MiB低地址未命名映射驻留稳定；未经ELF段核验不认定其为BSS。

race第二/三轮主要大页来自高地址未命名匿名VMA，例如[0x7efed4000000,0x7efed8021000)在两轮均含64MiB THP；该观察不能推出它的调用者或分配器。定位结果不支持把本轮THP增量归给已知shadow地址带，但并不排除shadow自身RSS增长或其他运行库开销。

## 能关闭与不能关闭

可以关闭本窗口“大页只知道总量、不知道所在VMA类别”的缺口：ordinary新增大页集中于Go命名堆，race新增大页集中于未命名匿名映射。不能关闭THP是否导致RSS累积、未命名映射对象用途、诊断快照开销及长期有界性。AnonHugePages已包含在匿名RSS中，绝不相加或视为可全部回收的字节。

原ordinary三轮固定预算内但回收后RSS22.75390625→39.375→50.02734375MiB上升；race固定基线增长66.80078125→140.91015625→168.21484375MiB仍失败。该分类不改变上述判定，不删除失败，不据减少大页后的一次通过关闭历史失败。

## 下一项独立控制的具体设计

以PR33同一执行源码/构建、相同三轮负载、GC/Go回收和smaps采集为基础，分别保留以下配置，全部仍用第一轮固定基线与64MiB门槛，结果标签明确标为诊断：

1. 默认策略作为同期基准，启动时记录实际THP策略、环境与二进制/源码哈希。
2. 仅Go堆THP控制：独立子进程设置GODEBUG=disablethp=1，其他环境不动。该控制主要针对普通构建的Go命名堆，不能据此假定race未命名映射也受影响。必须用真实smaps核验控制有效性。
3. 进程级THP控制：专门的Linux启动包装器在exec目标前设置PR_SET_THP_DISABLE并读取PR_GET_THP_DISABLE确认；目标仍用同一二进制和相同负载。验证控制对实际目标生效，不能只看包装器返回0。该控制应覆盖更广匿名映射，仍需用smaps验证，避免把未生效控制当负结果。

两个干预应分别与同期默认配置比较，每类保留重复/反向顺序，记录全部样本；不能拿旧runner数据直接相减。每个进程仍保持自己的第一轮基线，额外比较绝对峰值、停载低水位、每VMA的RSS/AnonHugePages、Go heap指标、业务/日志、时序及性能变化。相同地址不作为跨进程配对键，不用THP减少量直接计算“已修复RSS”。

优先级：ordinary先检查Go堆控制是否抑制已定位的18/30MiB大页与低水位上升；race同时需要进程级控制及未命名VMA来源追踪。若THP下降而RSS仍逐轮上升，应继续查剩余驻留与生命周期，不能归为纯THP问题。若RSS改善，结论也限于该诊断条件，不自动采用生产策略或重写原验收结果。

本次只完成定位和控制规范，尚未实现/运行以上干预。宿主sysfs不改；普通/race原诊断与原失败保留，PR33草稿、未合并，24h未启动。

## 来源与复算

[Go GC指南](https://go.dev/doc/gc-guide#Linux_transparent_huge_pages)区分Go堆disablethp与进程级THP控制；[Linux内核THP文档](https://docs.kernel.org/admin-guide/mm/transhuge.html)说明进程控制及逐VMA AnonHugePages观察。固定Go1.26.10 mem_linux.go已在此前证据包保留；本文不将一般文档当作当前内核控制已生效的证明。

脚本[evidence/soak-cycles/localize-thp.py](evidence/soak-cycles/localize-thp.py)与[结果](evidence/soak-cycles/thp-localization.json)保留全部选点、读取索引及含THP的VMA。复算：python3 localize-thp.py --archive original/pr33-cycles.zip --output /tmp/thp-localization.json。固定原件、脚本及结果随Tunveo-PR33-THP-Localization-2026-10-28.zip交付。
