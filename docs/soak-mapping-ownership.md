# RSS映射所有权诊断（2026-10-26）

接PR21。本轮只新增进程外观测、分配控制和验证工具，不修改生产引擎、原负载探针或验收器。历史三次RSS超限仍保留失败，64MiB预算不变，正式24小时未启动。

## 来源限定

范围只适用已核对的Go1.26.10 linux/amd64普通或race干净构建。官方工具链runtime/race/README指出amd64v1 Linux运行库基于LLVM `51bfeff0e4b0757ff773da6882f4d538996c9b04`；对应race_linux.syso SHA256为`5bdd6b292a1d7bb4a21c3134bafec7545f23133e2e640fed265a7f8c5b67a638`。附带补丁只初始化Trace.local_head，不修改映射。

核对该提交[tsan_platform.h](https://github.com/llvm/llvm-project/blob/51bfeff0e4b0757ff773da6882f4d538996c9b04/compiler-rt/lib/tsan/rtl/tsan_platform.h)中MappingGo48及SelectMapping：shadow为`[0x200000000000,0x21c000000000)`，metainfo为`[0x300000000000,0x400000000000)`。[tsan_defs.h](https://github.com/llvm/llvm-project/blob/51bfeff0e4b0757ff773da6882f4d538996c9b04/compiler-rt/lib/tsan/rtl/tsan_defs.h)定义每8B应用内存对应四个4B shadow项，因此shadow地址为对齐后应用地址×2+0x200000000000。本地实际race二进制MapShadow反汇编亦符合该运算。不是按虚拟区间大小估算RSS。

32MiB真实Go缓冲区逐8字节写入且保持存活，外部读取器通过stdin握手确保前后阶段不切换；普通版shadow应为0，race版应在指定shadow范围观测至少48MiB驻留增长，并确认预测的缓冲区shadow地址落入有驻留页的实际VMA。只验证范围与分配控制，不把控制数据当业务验收或证明泄漏。

## 外部采样

`soak_mappings.py capture`启动原verify_soak.py，读取其显式native_pid，并核对进程启动时钟及可执行文件哈希。每次原子checkpoint更新后，读取一次/proc/PID/smaps，在独立目录保存压缩原文、SHA256、采集时钟、checkpoint年龄与解析分组。不向目标进程写入额外字段；轮询、读取页表仍有观察者开销。

每个VMA整块归到shadow、metainfo、其他匿名、内核命名或文件映射；跨边界映射拒绝作归因，不按虚拟长度分摊RSS。各组互斥，只累加同一smaps读取中的Rss等同名字段；Anonymous和Private_Dirty相互重叠，不相加。文件映射可能包含匿名写时复制页。

独立audit重新解压解析每份原文，核对哈希和分组；要求每个warmup/measured checkpoint均有一份映射。比较原statm后半预热最大点与测量峰值对应的外部快照；这两个采集需在checkpoint更新后100ms以内开始且读取少于100ms，否则归因证据不合格。原资源失败保留，并继续核对全部业务事件、原始日志、文件哈希和回收。外部smaps与原statm/rollup是相邻异步读取，不将几MiB差额强行对账成分配所有权。

```sh
python3 scripts/soak_mappings.py control --binary bin/control --artifacts artifacts/control
python3 scripts/soak_mappings.py capture --binary bin/probe --artifacts artifacts/trial-1
python3 scripts/soak_mappings.py audit artifacts/trial-1
```

保持H2 mode1/TLS1、pool16:64、2worker10QPS、12秒预热+60秒测量、5秒采样、单次业务尝试。普通/race各三轮，任一资源失败令任务失败，保留所有原文，不重跑覆盖。所有窗口仍为pilot，不能关闭24小时门槛。范围之外的匿名映射继续标为未归属，不直接称为TSan trace、malloc或引擎泄漏。

PR21源码54295c8的Soak smoke40330759446已成功；TLS40330759296在本轮初次核对时仍运行中。上一轮常规19/19、映射前诊断3/3继续有效；不宣称完整兼容通过。

规范源码、分配控制和六个新窗口结果后续补录。
