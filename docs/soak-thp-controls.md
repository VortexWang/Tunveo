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
