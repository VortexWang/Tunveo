# 普通构建30分钟与提前退出复核

固定[审计CI40843102690](https://github.com/VortexWang/Tunveo/actions/runs/40843102690)核对两个原始artifact SHA256及summary所列各文件哈希，重新运行原验证器、业务事件和engine日志检查。未将不同运行拼接为同一测试。

## 30分钟连续短验

CI40813794494，原artifact12872717761 SHA256 9d0508642ea4b0f8d23c1f020d27b73ab42bc1b670d5bb9755220f5035e710ff。普通Go1.26.10构建，transport3/mode1，12秒预热、1800秒负载、5秒采样，workers2/qps10/pool16..64。

固定基线29548544字节（28.1796875MiB），峰值54210560字节（51.69921875MiB），增量24662016字节（23.51953125MiB），0/360超限。18000次measured业务交换，0失败/丢失，含预热18119条事件经验证；原验证器pilot通过，qualifies_24h=false。前后四分位数中位RSS差7550976字节（约7.201MiB），该诊断pilot的趋势值未作为正式趋势门槛进行验收。30分钟不能外推为24小时或证明无泄漏。

## 180秒提前退出

CI40813639682，原artifact12870604610 SHA256 29324b63f141223d4d6b42c91dae53689853443cf2fc4171a82cb20a1d739101。普通构建只完成37.923110258秒measured，probe报scheduler missed declared offered-load ticks，28次dropped，退出码1；原先摘要的nonzero并非RSS失败。报告证据显示，在elapsed47.00427971秒的measured检查点，measure为2.722154ms，checkpoint耗时2.918793548秒，snapshot总耗时2.921516554秒；在49.923079758秒报告expected slot471、observed499、丢28，最大tick lag2.823071931秒。runLoad的snapshot及同步checkpoint位于接收tick的同一个select循环。该时间关系直接支持同步checkpoint阻塞负载调度；尚不能区分底层文件写入、文件系统阻塞或runner调度等原因。此次未完成，0/8 RSS超限不是通过结果。

## 下一步

隔离checkpoint持久化与负载调度，保留不可变快照、固定基线、采样顺序及可验证的落盘/错误反馈；队列满或写入失败必须明确失败，不丢点、不把补发称作按时负载，退出前确认完成写入。用可控2.9秒写入停顿验证调度按原qps继续、事件完整及写入错误不被掩盖；检查race、外部映射观察/ACK、退出/超时清理，然后同配置重跑。不得仅放宽missed-slot规则。实际生产进程的RSS问题仍不可凭此宣布解决，PR保持草稿，24小时未启动。
