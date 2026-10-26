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

规范源码、控制和六窗口结果如下。


## 规范源码实测与局限

规范源码`149709df8cf90aba1bbc18524adbdc184bde2b6f`。CI检出`3691792698a47939a6a01e63b80a3e61c2c993eb`经实际git对象核对，树均为`8819f0f6d0a126881e2a144a965f0e315f184421`。生产引擎、原Go负载探针和verify_soak.py均与PR21相同，只有外部工具、独立控制、工作流及文档新增。

本地普通和race两次控制在首次读取子进程smaps时均PermissionError，未完成控制、未启动本地负载。两次失败与空stderr原样归档，无权限提升、无改procfs权限，不能称本地分配控制通过。真实Python self/smaps格式检查解析55个VMA，只支持解析器验证。两个负载和控制二进制来自同一干净源码，指纹已保留。

[映射专项CI40333753710](https://github.com/VortexWang/Tunveo/actions/runs/40333753710)普通/race两个任务均成功。该环境中普通32MiB持有分配的shadow增量0，race增量正好64MiB；预测shadow地址确实处于有驻留页的VMA。两个原始ZIP发布digest、CRC、逐文件哈希、实际运行库syso指纹、控制原文/预测地址以及六份pilot全部事件/日志/资源和映射原文，均下载后独立复核。

六轮普通/race各3/3原预算通过，各600业务交换/719条含预热事件，合计3600/4314，无业务失败/丢弃/重试，正常回收。新增映射证据没有再现一次超限，不覆盖历史三次资源失败。普通/race在独立CI VM，不能按同机性能差分解释。

| 构建/轮次 | 原statm RSS增长MiB | 外部smaps RSS增长MiB | shadow增长MiB | race metadata增长MiB | Go标注堆映射驻留增长MiB | 未命名匿名增长MiB |
| --- | --- | --- | --- | --- | --- | --- |
| ordinary 1 | 8.2969 | 8.2969 | 0 | 0 | 8.0000 | 0 |
| ordinary 2 | 6.3008 | 6.3008 | 0 | 0 | 6.0000 | 0 |
| ordinary 3 | 6.2969 | 6.3125 | 0 | 0 | 6.0000 | 0 |
| race 1 | 55.6094 | 55.1953 | 19.9297 | 1.1367 | 11.5273 | 22.1563 |
| race 2 | 56.7852 | 51.0859 | 20.4688 | 0.9609 | 10.2266 | 19.0664 |
| race 3 | 54.1367 | 53.5742 | 21.4023 | 0.9844 | 10.5391 | 20.1719 |

表内省略Go其他已命名运行时映射及少量文件页，完整分项和求和核对在named-mapping-audit.json。Go1.26.10 runtime/set_vma_name_linux.go使用“ Go: ”前缀，mheap.go为堆映射传递heap名称；真实原文有`[anon: Go: heap]`，据此单独统计驻留堆映射，**不是存活对象HeapAlloc**，也不能认定引擎泄漏。原宽分组other_anonymous含Go已命名匿名页，已在第二阶段原文复核中按名称继续拆开，没有把30–34MiB宽分组全部称为未归属。

两点外部采集在checkpoint更新后约2.2–10.8ms启动，所有smaps读取最长约2.378ms。即使时间接近，race第二轮smaps与statm增量仍相差约5.70MiB；它们不是同一读取，不能用shadow/metadata/Go堆的外部数字对原statm做精确比例归因，更不能追溯断言历史超限全部同因。结论只限本轮：约20–21MiB位于race shadow，约1MiB位于race metadata，另有约19–22MiB未命名匿名驻留增长，后者分配所有权尚未查明。

[常规CI40333753586](https://github.com/VortexWang/Tunveo/actions/runs/40333753586)19/19成功，Python37项通过；当前TLS仍运行中，未宣称全兼容通过。本轮仅新增映射工作流，没有重新执行当前源码八场景Soak矩阵；PR21原Soak smoke9/9已核对任务状态，不作为本轮新矩阵证据。

原始CI ZIP、本地不可用控制、来源/二进制指纹、反汇编、全部复核脚本/结果与SHA256清单见 [evidence/soak-mapping-ownership](evidence/soak-mapping-ownership)。下一步需区分未命名匿名映射的分配者及增长是否有界，保持原64MiB预算；正式24小时仍pending，未启动、未合并、未发布。
