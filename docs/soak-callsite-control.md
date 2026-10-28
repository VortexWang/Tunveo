# 冻结 ELF 的真实 CALL 控制

PR35 独立证据复核后，仍不能把未命名匿名 RSS 全部归给 TracePart 或 InternalAlloc。本轮只验证一个实际调用路径，为后续映射代次台账提供前置证据。不是180秒复现、不是24小时验收，不修改原64MiB门槛或历史失败。

## 字节与指令绑定

只接受 PR35 CI40628377687 的 snapshot-race artifact12793001666：原ZIP SHA256 `3722365efe2bf1f7f7378e2bae89fe5c3ad00ddb065449440e01208d746d63ce`；目标ELF SHA256 `2b332b9b27afeecca123e2d3fb5819c31bd787406d1393b1335e649a78eec391`。实际构建checkout为 `b362c900b25935f39b3b8b271fc8664c4bde9a3c`。下载后先核ZIP摘要/CRC及ELF摘要，任一不一致停止。下载凭证只需actions读取权限。归档过期/无法下载也停止，不能用重编译替代冻结字节。

按x86_64 ET_EXEC程序段从虚拟地址独立计算可执行文件偏移，核对objdump指令边界、原始字节和E8相对目标。唯一静态路径为TraceSwitchPartImpl的`0x41d8fc → 0x40df10 MmapOrDie`，完成点是下一指令`0x41d901`。PR35冻结调用点给出的size=131072、tag指针=0xd29cef（TracePart字符串）、bool=0须与实际寄存器一致。

仅普通uprobe置于CALL前与下一条指令，不使用uretprobe或修改目标返回地址；调用方与完成点按TID、完整序号和相同SP配对。这样得到的是该静态调用点的一次已完成调用，不等于TraceSwitchPart函数的所有入口/出口，也不等于所有TracePart分配路径。

## 真实控制顺序

1. 沿用已有固定源码bpftrace `93c593f6dab2e930d6198cfaa52b29d19a8c0647`，开启bfd指令边界检查、编译关闭unsafe；不以unsafe绕过失败。保留源码版本、构建配置/日志、工具哈希、内核和包版本。
2. 新C控制4线程各8次，32个唯一size（4096到131072），每次已知直接CALL只触发一个mmap。原生程序输出TID/size/返回指针，触页后munmap。观测结果必须与32条原生输出逐项一致；静态扫描/本地C运行不算BPF控制已通过。
3. C控制通过后，才运行冻结原生race探针，15秒负载、12秒预热，其余transport3/mode1/TLS1/workers2/qps10/pool16..64沿用既有短时调用控制。无新THP干预，无三轮/120秒驻留实验，不和PR35 THP控制样本直接做RSS差值。
4. 同时捕获目标进程mmap进入/退出，按TID配对并定位到调用窗口；每次已完成候选CALL必须包含且仅包含一个mmap，size和返回地址一致。多余、缺失、错误返回、SP不一致、空路径、丢序号/整线程、进程身份不一致、超时/清理异常、tracer丢事件/报错都判控制失败；不得输出完整归属结论。

复用已经检查进程关系、目标UID、单调时钟、按线程序号和资源退出的soak_ret_context.launch。原生业务事件/引擎日志与原资源验证器仍运行，64MiB原门槛不变；资源失败可与已保存的调用控制证据并存，整个实验仍失败。即使15秒资源通过，也不能关闭原180秒/三轮失败，不能进入24h。

## 结果范围与下一阶段门槛

成功仅证明：该冻结ELF、该次负载中，一个候选CALL的参数及返回值能与同线程实际mmap系统调用配对。计数/size之和是虚拟请求量，不能当作匿名RSS或存活对象量；mmap成功也不等于页面已驻留。C控制中的munmap是已知fixture行为，本轮没有建立全进程munmap/mremap/madvise台账。

只有C和真实调用控制均有效，才继续地址重用代次、映射拆分/合并/释放及madvise的统一台账，再与同进程驻留快照关联。InternalFree、映射释放和RSS回落分别记录，不互相替代。追踪器额外开销仍需后续带/不带观测对照。

本地8项回归通过：含真实C多线程运行与ELF偏移核验，以及丢失/重复、未完成返回、SP/size/指针/PID/地址错误和冻结摘要守卫。实际BPF挂载、原生15秒负载及CI完整回归尚待运行。新job60分钟（各步骤上限合计50分钟，保留调度/清理余量），工具构建35分钟上限，实际调用步骤5分钟上限；失败不能跳过控制后继续长窗。

参考官方说明：[bpftrace uprobe/uretprobe](https://bpftrace.org/docs/pre-release/language)、[固定tracer源码](https://github.com/bpftrace/bpftrace/tree/93c593f6dab2e930d6198cfaa52b29d19a8c0647)、[Linux uprobe文件偏移](https://www.kernel.org/doc/html/v6.12/trace/uprobetracer.html)。本轮草稿、未合并/发布，24小时验收未启动。
