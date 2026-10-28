# 独立THP诊断对照

接PR33逐VMA定位：普通构建Go命名堆AnonHugePages为0/18/30MiB，race未命名匿名为50/146/158MiB，已知shadow/metadata地址带均0。地址类别不是对象或分配器归属。本轮独立干预用于检查THP与驻留变化的关系，不修改生产策略，不关闭历史失败。

## 配置与顺序

四个独立CI job：ordinary/race × go_heap/process。每个job在同一主机、同一干净源码及同一已编译二进制上运行baseline→control→control→baseline；每个进程内保留PR33相同三轮180秒负载、12秒预热、120秒GC/Go回收及完整smaps。跨轮固定各进程第一轮预热基线，所有原门槛含RSS64MiB保持。不同主机job之间不直接相减，也不把不同进程的地址当作配对键。

- baseline：不改变运行时环境，启动包装器要求原PR_GET_THP_DISABLE=0且保留0。
- go_heap：独立目标子进程环境仅增加GODEBUG=disablethp=1，原GODEBUG/GORACE非空时拒绝，避免覆盖或混合未声明策略。包装器仍要求进程THP禁用标记为0。每份目标快照必须记录预期环境及THP_enabled=1，并核验Go命名堆AnonHugePages=0；其他匿名区域可仍有THP。
- process：Linux C包装器在exec目标之前执行PR_SET_THP_DISABLE=1，并用PR_GET_THP_DISABLE回读1。exec保留PID，包装器证据PID必须等于实际启动子进程及原生报告PID。每份目标快照要求THP_enabled=0、GODEBUG为空、总AnonHugePages=0。只看包装器成功不算控制有效。

所有设置只在实验子进程中生效，目标退出后结束；不写宿主sysfs。记录内核、宿主THP策略（含可见多尺寸策略）、每配置前后状态，宿主策略变化使比较失败。保存包装器before/after、实际目标环境/状态、原文哈希、单调时钟、所有report、事件、日志及数据文件哈希。无BPF代次台账，同址仍不能认定对象复用。

## 结果规则

各进程原局部验证与跨轮固定验证继续执行。某个默认/干预窗口资源失败仍保存并继续其他ABBA样本，最终任一资源或证据失败使job失败。矩阵fail-fast=false，不能以一个job失败取消其余控制。业务失败导致的缺轮或无效控制不能当作RSS改善。

必须逐次比较：第一轮基线、绝对峰值、各轮固定增量、停载低水位/Go回收后值、每VMA RSS/AnonHugePages、HeapAlloc/Inuse/Released、业务完整性与时序。不把AnonHugePages与RSS相加，不按大页下降量计算已修复内存。如果默认样本没有对应大页暴露，则该job不能建立相应THP差异结论。若控制有效但RSS仍累积，继续查剩余驻留与生命周期；若RSS下降，也只限于该实验条件，不证明无泄漏或长期有界。

## 检查与状态

本地117项Python测试通过（新增5项），包括环境隔离/拒绝继承配置、目标状态验证、Go堆与其他匿名区分、残留大页拒绝，以及真实Linux C编译→prctl→exec后状态/PID回归。C以-Wall -Wextra -Werror编译通过。Go编译、原生命周期及新增目标状态字段回归待真实CI核验。

默认soak_cycles入口不传THP控制时保留此前路径；原verify_soak.py、固定基线函数、64MiB预算与生产引擎/依赖不修改。诊断快照新增实际THP状态和GODEBUG字段，可能有少量开销，所有ABBA配置一致采集。

每job12个负载/停载周期纯窗口合计至少62分24秒，加上清理与采集约一小时以上。job上限105分钟，测试/编译8、ABBA90、上传3分钟，预留4分钟。四个job各自独立主机，实际并行受CI容量影响。

实际干预CI尚待完成，不能用本地回归或PR33旧窗口代替控制结果。保留草稿、未合并/发布，原失败全部保持，24h未启动。

## 完整CI与独立复算（2026-10-28）

[CI40618124776](https://github.com/VortexWang/Tunveo/actions/runs/40618124776)四组均完整结束并上传产物：ordinary两组diagnostic_passed，race两组failed。每组117项Python测试、Go测试及两份干净构建均通过；未用取消/超时解释资源失败。

规范源码8a50a5e5b7d1f0bd33bed98615f859ea7e9ff82b，实际干净检出30b69a5b28f17937569dacb56148b651b180b042，完整树同为13eb808655683060dc697c170346f1e77e7fa8c4。四份原ZIP发布digest/CRC、四份执行Python源码blob、全部comparison/cycles产物哈希、同job源码/记录的二进制哈希一致性、目标PID/包装器回读、目标THP和GODEBUG、宿主THP策略前后不变、参数、原验证器、业务与日志均独立复核。共48轮、92112事件、3409份smaps；快照按每份报告实际点数验证完整阶段序列，不假定每轮点数恒定。所有重算与CI保存对象一致。

原生/包装器二进制未随产物归档，因此这里只能验证记录的二进制哈希在同job各配置间一致，不能重算二进制字节；源码/构建元数据与实际目标控制状态另行核对。没有系统调用代次或对象调用者证据。

### 各样本原结果

下表“增长”为相对每个进程第一轮后半预热固定基线，单位MiB；每项仍保留原64MiB门槛。Go回收后的值是独立停载阶段，不能抵消负载峰值。

| 构建/控制组 | ABBA次序/模式 | 三轮固定RSS增长 MiB | 三轮Go回收后RSS MiB | 原结果 |
| --- | --- | --- | --- | --- |
| race/process | 1 baseline | 74.59375 / 133.75 / 180.67578125 | 160.16796875 / 235.5 / 261.59375 | failed |
| race/process | 2 process | 73.21484375 / 150.0390625 / 164.328125 | 147.765625 / 225.58984375 / 240.12109375 | failed |
| race/process | 3 process | 72.6640625 / 150.40625 / 162.23828125 | 146.6015625 / 221.0859375 / 234.90625 | failed |
| race/process | 4 baseline | 72.53515625 / 157.078125 / 172.171875 | 157.8828125 / 240.109375 / 255.37890625 | failed |
| ordinary/process | 1 baseline | 12.64453125 / 12.9375 / 15.12890625 | 21.28515625 / 22.5546875 / 44.1015625 | diagnostic_passed |
| ordinary/process | 2 process | 14.4375 / 20.50390625 / 20.78125 | 16.6875 / 17.1328125 / 17.296875 | diagnostic_passed |
| ordinary/process | 3 process | 18.26171875 / 23.02734375 / 22.56640625 | 17.046875 / 16.92578125 / 17.33984375 | diagnostic_passed |
| ordinary/process | 4 baseline | 8.6015625 / 9.046875 / 9.203125 | 47.55078125 / 22.35546875 / 22.0390625 | diagnostic_passed |
| ordinary/go_heap | 1 baseline | 8.67578125 / 11.078125 / 9.19921875 | 21.5546875 / 23.7421875 / 54.09765625 | diagnostic_passed |
| ordinary/go_heap | 2 go_heap | 17.15625 / 21.140625 / 21.24609375 | 18.49609375 / 18.66796875 / 18.90234375 | diagnostic_passed |
| ordinary/go_heap | 3 go_heap | 15.58203125 / 19.73828125 / 20.82421875 | 18.50390625 / 18.7890625 / 19.03125 | diagnostic_passed |
| ordinary/go_heap | 4 baseline | 12.62890625 / 14.9296875 / 15.09375 | 19.96875 / 22.359375 / 42.08203125 | diagnostic_passed |
| race/go_heap | 1 baseline | 62.078125 / 150.125 / 177.0078125 | 156.9375 / 244.46875 / 267.73046875 | failed |
| race/go_heap | 2 go_heap | 64.6171875 / 166.33984375 / 174.3359375 | 153.14453125 / 243.84765625 / 261.7109375 | failed |
| race/go_heap | 3 go_heap | 72.30078125 / 144.3515625 / 174.55859375 | 157.89453125 / 229.8203125 / 260.83984375 | failed |
| race/go_heap | 4 baseline | 68.4453125 / 156.0859375 / 169.13671875 | 156.96875 / 256.4140625 / 266.26171875 | failed |

### 控制效果与结论

两次baseline均具有相应大页暴露，因此不是没有THP可比较的空对照。go_heap干预全部目标快照GODEBUG=disablethp=1、THP_enabled=1，Go命名堆AnonHugePages为0；其他匿名大页允许存在。process干预全部目标THP_enabled=0、GODEBUG为空，所有smaps总AnonHugePages为0，包装器PR_GET回读及PID与原生报告一致。每个job宿主THP策略前后保持。

ordinary全部8个进程通过原局部与跨轮固定资源门槛。Go堆控制的三轮Go回收后RSS约18.50–19.03MiB，进程级控制约16.69–17.34MiB；同期默认样本约19.97–54.10MiB且并非每次单调上涨。这支持THP干预与较低/较平稳停载驻留相关，但不能说默认普通构建每次都会泄漏，不能把RSS差额当作纯THP效应。控制进程的固定增量并不一定更小，需同时看基线和绝对峰值，禁止只挑一个指标。

race全部8个进程失败，两项控制均不能令其通过64MiB门槛。Go堆控制第三轮固定增长174.3359375/174.55859375MiB，仍有其他匿名大页驻留；进程级控制已经清除所有大页，第三轮仍增长164.328125/162.23828125MiB，Go回收后仍240.12109375/234.90625MiB且逐轮上升。因此“THP是race超限唯一原因”可在本诊断条件下否定；THP对部分驻留的影响、具体对象和长期行为仍未闭合。

进程级race控制样本2、3的相邻Go回收后smaps进一步显示：已知shadow/metadata地址带之外的未命名匿名RSS，从第一轮约70.70/70.41MiB升到第三轮162.26/162.94MiB，增量约91.56/92.54MiB；同期shadow地址带RSS反而下降。这使剩余高地址未命名映射成为下一步追踪重点，但“带外未命名”不等于运行库/TracePart/InternalAllocator归属。资源采样与smaps非原子，同址也无代次证明。

所有样本的其他固定ACTIVE及局部RETURN检查通过，48轮业务事件及日志审计通过。原RETURN不含RSS；pilot趋势没有被当作正式长期验收。两个race job保持failure，即使某个后续局部预热口径通过，也不能重置最初基线掩盖累积。ordinary控制成功不能替代默认配置验收或关闭race历史失败。

### 下一步与未决事项

优先在保留THP已禁用标签的独立诊断中，对上述带外未命名映射建立分配/解除/回收调用者和映射代次台账；先验证固定二进制中候选入口的符号可观测性及实际调用控制，再关联RSS，不从地址反推对象。另需分离smaps/报告采集自身开销与业务生命周期，防止把诊断工具的驻留混作生产泄漏。当前不自动采用生产THP策略，不改64MiB门槛，不关闭未知归属或长期有界性；草稿、未合并、未发布、24h未启动。

见[固定审计器](evidence/soak-thp-controls/audit-thp-controls.py)、[独立结果](evidence/soak-thp-controls/independent-controls.json)和[按执行版本保存的CI快照](evidence/soak-thp-controls/ci-snapshot.json)。完整四份原ZIP、固定Python源码、结果及校验清单随Tunveo-PR34-THP-Controls-Evidence-2026-10-28.zip保留。原产物2026-11-27到期。
