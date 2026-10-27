# 映射生命周期与同进程整VMA驻留对齐

接PR27合格的入口/RET/白名单尾出口上下文，在同一逐线程序号流中增加mmap、munmap、mremap、brk的系统调用入口/退出，并记录exec边界。只取唯一目标二进制exec之后的台账；再次exec或缺失配对拒绝，不把启动shell/setpriv/env的旧地址空间转移到目标进程。

CPP mmap包装入口长度和返回值必须与其内嵌真实mmap syscall一一匹配。上下文仍要求PID/UID、完整逐线程序号、时间及RSP嵌套闭合；BPF与Python smaps读取都显式使用CLOCK_MONOTONIC。外部读取同时校验PID启动时间和实际exe inode，保存原始gzip、SHA、完整原point与读取前后时间；原native样本、资源预算和业务检查不改。读取在checkpoint100ms内且耗时不超过100ms，目标point前后必须相同。

每个成功mmap产生独立代次，页长按实际支持的4096页向上取整；部分munmap分裂/删除区间，MAP_FIXED替换产生新代次，地址复用不继承旧标签。mremap新旧区间均不继承已知来源（含DONTUNMAP）；brk变化只撤销潜在旧归属，初始exec/heap等非mmap来源保持未知。失败固定映射或失败删除/重映射也保守撤销潜在影响范围，不凭失败假造成功分配。

并发且范围重叠、无法确定真实生效顺序的变更保留未知。只有整个未命名匿名VMA被完整覆盖，读取前后来源与代次集合相同、且读取期间没有触及范围的在途变更，才将该整VMA的Rss关联至来源路径。多来源混合单列，不按地址长度分摊RSS。Go标注、shadow、metadata和文件等原分类分开保留。驻留关联是映射申请路径证据，不是对象存活、缓存用途、可回收或泄漏证明。

先用真实C控制验证：隔离保护页内4MiB触碰映射→解除中间2MiB→不同上下文MAP_FIXED复用→完整合并VMA混合来源→mremap移到8MiB并触碰→解除。每阶段保存原始marker/monotonic时钟及smaps；新地址和旧地址不跨阶段猜测。所有控制、台账、清理和读取守卫通过后，才运行原H2 mode1的15秒资格窗口（12秒预热、5秒采样、TLS1、pool16:64、2worker10QPS）。这不是180秒或24小时验收。

继续固定BFD-enabled bpftrace0.21.2源码，unsafe关闭；不使用uretprobe或栈展开，不修改生产Go探针/internal/cmd/依赖、GORACE/GODEBUG或内核BPF/ptrace/THP策略。进程组及实际父子身份验证沿用PR27，任何超时/强制清理/缺失证据失败并阻断后续。75项Python通过，真实C控制本地编译通过；实测结果待本次CI，原64MiB增长预算、历史失败及24h pending不变。

依据：[bpftrace0.21时钟与tracepoint说明](https://bpftrace.org/docs/0.21)、[Linux mmap/munmap](https://www.man7.org/linux/man-pages/man2/mmap.2.html)、[Linux mremap](https://www.man7.org/linux/man-pages/man2/mremap.2.html)。smaps不是原子全进程快照，不能强制与另一次statm读取精确加总一致；未覆盖或不稳定部分不作正向归属。
