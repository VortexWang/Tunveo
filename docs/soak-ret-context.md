# 精确入口/RET指令上下文资格测试

接PR26：GDB返回断点没有取得有效Go负载，原失败保留并继续阻断。新方法以nm唯一带长度符号和objdump完整逐字节指令范围定位C ABI函数入口及所有plain RET（c3）位置，只用普通uprobe在这些实际指令点记录。没有uretprobe、修改栈返回地址、GDB FinishBreakpoint或ustack展开；RET处读ax寄存器，入口读映射长度arg1。

先验证独立C控制的parent→1MiB mmap→RET→parent RET，匹配返回指针、256触碰页和checksum1792。通过且观察者/目标进程组消失后，才运行同一Go1.26.10 Linux amd64 race探针的15秒资格窗口（12秒预热、5秒采样、H2 mode1/TLS1、pool16:64、2workers/10QPS），不直接进入更长实验。

拟记录TraceSwitchPartImpl、InternalAlloc、internal_mmap三类入口/RET，以PID/UID、OS TID、逐线程连续序号、单调时间和严格嵌套RSP匹配。同线程上下文必须全部关闭才能关联嵌套mmap请求。BPF输出末尾的逐线程序号map作为完整性台账，丢行、重复、漏整线程、SP/指令点/身份不符或未关闭上下文均拒绝，不猜丢失记录。成功请求的累计虚拟量不是当前映射量、RSS或泄漏证据。

追踪器在隔离CI以所需权限启动；目标由setpriv降至原runner UID/GID，env-i清理环境，原始命令/UID均保留。每次跟踪均在自己的新会话/进程组，完成/超时后验证整个组消失；无法证明、需要TERM/KILL、超时或tracer报告丢失/错误则失败并阻断下一阶段。C控制45秒、Go资格120秒上限，不改任何内核BPF/ptrace/THP策略；能力不足不绕过。

原verify_soak资源/计时/业务/事件/引擎日志标准照常审计15秒窗口，64MiB预算不变；资格通过也不代表180秒或24小时有界，不替代无观察者实验或正式资源门槛。生产Go探针、internal/cmd和依赖不改。完整指令计划、BPF源码、原始输出、进程组清理、上下文配对及原报告均存档。

依据：[bpftrace语言说明](https://bpftrace.org/docs/0.22)支持按符号+指令偏移附着；[官方关于uretprobe的限制](https://bpftrace.org/docs/release_025/language)说明返回地址替换对Go运行时的风险。本实验选择RET位置普通uprobe，实际支持性和观察者影响仍须由控制及资格测试验证，不能仅据方法名称认定安全或完整。

本地Go1.26.10旧race二进制的三个符号完整指令范围已验证，RET偏移分别0x800/0x3f/0x24。59项Python通过；首次测试暴露指令冒号后的合法空白解析问题，原失败日志保留，已修正空白兼容，未放宽完整指令、配对或资源要求。实测待本次CI，不提前宣称BPF能力可用或方法合格。保持草稿，原失败、24小时pending及预算不变。
