# 精确入口、RET与已知尾出口上下文资格测试

接PR26。旧GDB失败继续保留并阻断。本实验不用栈展开、FinishBreakpoint或uretprobe；对实际ELF的C ABI函数入口、所有plain RET（c3）以及经过白名单校验的直接尾出口，分别放置普通uprobe。它不以返回地址替换实现退出观察，实际支持性和观察者影响仍需资格验证。

nm唯一带长度符号与objdump完整指令范围确定位置，每个返回点都落在实际c3指令边界。Go1.26.10 Linux/amd64 race的三个观测对象为TraceSwitchPartImpl、InternalAlloc、internal_mmap；入口分别读sp，mmap额外读arg1长度，RET处读ax。只有内核PID/UID、OS TID、逐线程连续序号、单调时间、严格嵌套RSP、计划指令位置和完整退出均匹配才关联请求。末尾逐线程序号map用于核对丢行、重复和漏整线程；未知间接/外部跳转不接受。

## 四个版本的实际结果

| 版本 | 规范源码 / CI检出 | 专项CI | 实际状态 |
|---|---|---|---|
| 初版 | 110279ee / d1720213 | [40430780499](https://github.com/VortexWang/Tunveo/actions/runs/40430780499) | failed：-c不接受shell内建exec，目标未执行 |
| 显式shell启动 | 2f3d114d / 64afe6d4 | [40431040331](https://github.com/VortexWang/Tunveo/actions/runs/40431040331) | failed：发行版bpftrace无偏移校验能力，附着被拒绝 |
| 固定源码工具及进程关系证明 | b03b453d / b2e2a4f2 | [40431855579](https://github.com/VortexWang/Tunveo/actions/runs/40431855579) | failed：C控制通过，Go业务完成，但上下文缺少尾出口而不闭合 |
| 显式白名单尾出口 | 47c822aa / e5d81c6c | [40432734438](https://github.com/VortexWang/Tunveo/actions/runs/40432734438) | success：C控制、Go15s原守卫、完整上下文及清理资格均通过 |

四个CI检出与对应源码完整Git树分别相同，已通过实际git对象验证，完整40位ID、树及ZIP发布digest见证据。后两轮Go构建均vcs.modified=false，CPP/Go探针二进制SHA与各自计划一致。没有把前三个失败状态回写为通过，也不把未执行的负载计入覆盖。

## 启动与工具能力修正

bpftrace 0.20.2的-c直接执行程序，不能将exec当可执行文件。改为显式/bin/sh及受控启动文件，文件内保留完整探针参数、降权和重定向。随后Ubuntu自带构建报告bfd:no，无法核验symbol+offset位置，拒绝控制程序的RET探针；未使用--unsafe绕过。

改用官方bpftrace提交`93c593f6dab2e930d6198cfaa52b29d19a8c0647`（v0.21.2，支持LLVM18）及libbfd/libopcodes构建，明确ALLOW_UNSAFE_PROBE=OFF。实际--info为LLVM18.1.3、bfd:yes、unsafe probe:no。源码commit、CMakeCache、构建日志、二进制SHA、完整构建包版本与内核原文都在原始ZIP中；源码构建位于RUNNER_TEMP，未污染Go仓库。固定源码与源码blob/SHA见tracer-source-profile.json。

追踪器使用CI所需权限，目标经setpriv降至原runner UID/GID1001并清理附加组，以env-i和PATH显式环境执行。启动文件先保存目标和追踪器实际/proc stat及追踪器exe，核对父子关系、会话和允许的进程组。每阶段在自己的新会话执行，结束或超时后核验已证明属于本实验的实际进程组消失；权限查询失败不当进程消失。任何超时、TERM/KILL、身份/清理不明、丢失或工具错误都失败并阻断后续。C控制45秒、Go资格120秒上限；没有改BPF、ptrace或THP内核策略。

## 尾出口不是缺失RET的猜测补全

只观察RET的版本留下182639条完整序号记录：InternalAlloc87621对、mmap401对，而TraceSwitchPartImpl6583次入口仅12个RET。新审计器复读这份不可变旧记录仍拒绝non-nested C ABI stack，没有插入假出口。

实际函数还有一处恢复RSP及保存寄存器后，直接jmp至唯一已核对的`__tsan::SlotUnlock(ThreadState*)`符号入口。最终计划为TraceSwitchPartImpl增加该偏移0x959的tail_exit，原RET偏移0x800保持；InternalAlloc和internal_mmap的RET偏移为0x3f/0x24。该事件关闭的是本函数已观测词法区间，不冒充函数RET或SlotUnlock的返回值，也不把跳转后的潜在请求归入已经关闭的区间。退出RSP必须与对应入口相同，未知目标/间接/条件外跳仍拒绝。源码改为实际记录此出口，不放宽原数据的闭合要求。

## 已通过的资格与请求上下文

两轮固定源码工具的C控制均验证parent→1MiB mmap→RET→parent RET，返回指针、256触碰页及checksum1792一致。只有控制及清理通过才启动Go。

最终Go15秒资格：12秒预热、5秒采样、H2 mode1/TLS1、pool16:64、2workers、10QPS、单次业务尝试；150正式交换（114TCP/36UDP）、269条含预热审计事件，均业务成功，无丢弃/重试。原资源/返回/调度/事件/引擎日志守卫通过，statm RSS增量26120192B（24.91015625MiB）在原64MiB预算内。所有事件UID为原runner1001，PID匹配native报告；控制和Go阶段均无超时、无TERM/KILL，实际目标/追踪器身份关系与组消失记录完整。

原始上下文190534条，组成95267对完整入口/出口：InternalAlloc88192对，internal_mmap411对，TraceSwitchPartImpl6664对（17个RET及6647个已验证尾出口）。逐线程末台账、序号、指令位置、时间和RSP全部核对，全部已观测区间关闭。

| 已观测上下文 | 成功internal_mmap请求 | 累计成功虚拟申请MiB |
|---|---:|---:|
| TraceSwitchPartImpl词法区间内 | 272 | 34.0000 |
| InternalAlloc词法区间内 | 17 | 30.0078 |
| 两个区间之外，未进一步归属 | 122 | 402.9180 |

这把272次请求关联到trace切换路径，较仅见internal_mmap的栈证据更细；**34MiB是累计虚拟申请，不是34MiB RSS，更不代表此前约80MiB匿名驻留已归属。**本实验没有完整mmap/munmap/mremap台账，也没有把请求区间与同一进程smaps整VMA驻留相绑定。没有观察到新映射也不能仅按次数差推断复用率。

前一轮b03b453的Go15秒原业务/资源守卫也能独立复核（150交换/269事件、RSS增量43249664B），但上下文资格仍failed。两个完整Go窗口共300交换/538事件；不把两轮RSS差解释为尾出口修正降低内存，也不称零观察者开销或干净性能差分。

## 审计、限制与下一步

四份原始发布ZIP的digest/CRC、计划反汇编与出口、实际身份关系、完整序号台账、C触碰控制、Go原报告/事件/日志和请求配对均离线独立复算。旧C控制与新审计器仅规范化新增空尾出口字段/说明文字，原始输出保持字节不变；旧Go失败仍被拒绝。

64项Python通过；首次测试发现指令冒号后合法空白解析问题，失败日志保留并修正，未放宽指令完整性。59/60/62/64项各版本日志及全部证据在`docs/evidence/soak-ret-context`。常规CI和TLS快照另存，当前仍排队，不宣称所有回归已绿。该15秒资格不是180秒或24小时验收，仍可能存在未被短窗口触发的观察者影响。

生产internal/cmd、Go探针和依赖不变，原64MiB预算、历史失败及24小时pending不变；未启动24h，未合并/打标签/发布。下一步将合格的上下文记录与完整映射生命周期、同进程smaps整VMA及明确读取时钟关联，才讨论驻留归属和保留/复用边界。

依据：[bpftrace语言与偏移探针](https://bpftrace.org/docs/0.22)、[官方uretprobe对Go的限制](https://bpftrace.org/docs/release_025/language)。当前方法使用普通uprobe，不替换栈返回地址；实际资格由以上控制与完整性数据建立，不由方法名称保证。
