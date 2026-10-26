# Go堆透明大页顺序对照

PR24发现race停载观察中Go堆AnonHugePages增加，但没有宿主策略快照，不能认定因果。本实验只改变新建试跑进程的`GODEBUG`：默认组移除该变量，对照组精确设置`disablethp=1`。其他继承的GOGC/GOMEMLIMIT/GOMAXPROCS保留并记录。生产代码和宿主sysfs不改。

每台CI VM同一干净二进制依次运行两组，各180秒H2 mode1/TLS1原负载、12秒预热、120秒停载重复GC观察和一次握手后的FreeOSMemory。ordinary/race各有默认优先、禁用优先两台独立VM，共8个窗口；每组只跑一次，失败不重试，先前失败不覆盖。反向顺序帮助检查顺序影响，不能消除独立VM宿主差异。

采集每组前后完整可读THP sysfs、内核和cgroup限制，读取失败原样记录；跨进程读取实际GODEBUG/GOGC/GOMEMLIMIT/GOMAXPROCS并与声明逐项比较，不存储其他环境变量。保留每个原始smaps及哈希，Go堆整VMA的Rss、AnonHugePages、THPeligible、VmFlags逐点解析；缺字段不补零。禁用组必须每个Go堆映射都有`nh`且AnonHugePages为0，否则诊断失败，不能把未生效处理当对照。所有THP映射读取须在原100ms质量界限内。

现有验收器独立复核180秒负载资源预算、事件和引擎日志、停载冻结哈希、回收前握手。64MiB RSS增长预算不变；停载或禁用组低值不覆盖默认组或历史失败。数据只支持Go堆干预的试验范围，不是race/sanitizer所有映射的大页干预，也不是泄漏定论、生产配置建议或24小时验收。

依据：[Go runtime环境说明](https://pkg.go.dev/runtime#hdr-Environment_Variables)、[Go GC guide](https://go.dev/doc/gc-guide#Linux_transparent_huge_pages)。固定工具链Go1.26.10的runtime源码原文及SHA随CI存档，以确认该版本设置语义。当前尚无本实验实测结果。
