# 普通构建与 race 资源短窗分开验证

## 已有正式规则

`scripts/verify_soak.py::validate_build` 已要求正式验收为未修改且可识别来源的普通构建，并拒绝 `-race=true`。本PR没有改变正式验收定义或原ACTIVE RSS增量64MiB。短窗 `--pilot` 不能获得24小时资格。

## 真实执行及证据

源码 b1651830a9928e706bac6d055d70b62e454ceece，GitHub PR合并检出 a4074770b6482d795e343ff34b23f196c065971f；[实际CI](https://github.com/VortexWang/Tunveo/actions/runs/40812445806)。两个独立Ubuntu 24.04 runner，Go1.26.10，同一检出源码及transport3/mode1，warmup12秒、180秒负载、5秒采样、workers2/qps10/pool16..64。每个作业回归177项通过；各自原固定预热基线，业务事件1919条。

| 构建 | 固定基线 MiB | 峰值 MiB | 增量 MiB | 超限点/测量点 | 判定 |
|---|---:|---:|---:|---:|---|
| 普通 | 26.80859375 | 42.23046875 | 15.421875 | 0/36 | pilot通过 |
| race | 102.2890625 | 177.3203125 | 75.03125 | 18/36 | RSS失败 |

数值由[固定产物审计](https://github.com/VortexWang/Tunveo/actions/runs/40813023515)读取原始报告、校验archive和summary文件哈希，并复算原验证器、业务事件和engine日志。普通artifact12871435612 SHA256 12426263ad657ef09838e52fd792260562d1de03d20102cd90a6d9b213462c3f；race artifact12871420661 SHA256 31e6f286c9195b0a8681d554a9e46f1596835de1d55899627ad9062931470ab9。普通ELF SHA256 fb4f95061a10b3e05ccff4b16c48e97109c48fc3a478870d6f982bcbb45d8073；race ELF 5be9833c509a35a3ab0b9a33705ac9ab87ce5591c18cf1954f95fea5967dcf66。

两个runner不是同一主机，不能据此独立证明因果。普通短窗通过不消除race历史失败、不证明长期稳定或无泄漏；race诊断的失败也不能改写普通pilot结果。两个短窗均qualifies_24h=false；24小时未启动。其他正在运行的专项工作流各自独立判定。

## 采样时序诊断修复与边界

PR41重跑因 `post-stop mapping timing failure` 拒绝原始证据；旧实现没有保存被拒绝记录中的读起止时间和检查点年龄，不能判断到底是哪项超过100ms。新实现先原样保存 `rejected-timing.json`，再抛出原错误；未把记录写入有效快照、未发ACK，100ms边界不变。拒绝及无ACK回归已通过。此修复解决的是失败证据缺失，尚未证明已消除采样超时的根因，也不修改生产引擎或试图调整系统时钟。

下一步检查实际新触发的拒绝记录，以区分调度延迟、读取耗时和检查点年龄；修复导致无效证据的机制后重新核验。普通构建需进行更多同配置、重复及长期验证；race预算若拟另设，须基于完整多轮数据并明确变更，而不改写历史失败。
