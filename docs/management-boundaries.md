# TNV-009A 管理入口与 SSE 边界

2026-10-25。PR #10 叠加在 PR #9 上，尚未合并或发布。实现和最终原生测试的干净提交为 `998b778470a9db56ee18c9d813419854a6b7f079`，普通/race 二进制均由该提交、Go 1.26.10 构建。

本轮完成 TNV-009 的入口与流生命周期部分，不关闭整个管理面审计。

## 确认的问题与变化

旧入口只有在凭据条目存在且 URL 非空时才校验密钥；条目缺失或为空时直接进入处理器。现在受保护路由统一使用 Handler 构建，缺失、空或不可用凭据返回 503；缺失、错误或重复 X-API-Key 返回 401。密钥使用常量时间比较。OPTIONS 仍为不执行操作的公开预检，文档与 OpenAPI 仍公开。

密钥轮换使用锁及新的不可变凭据对象替换登记项，不再原地改写被认证请求或持久化快照引用的 URL。已有普通请求不会被追溯撤销；SSE 在注册时重新校验密钥，轮换与断开旧订阅使用同一认证锁，防止旧凭据在轮换后补注册。

旧 SSE 初始快照遍历全部登记项，会发送 API Key 特殊条目；现在初始、排队、广播入口均排除该条目。轮换后的新密钥不会经 SSE 广播，显式认证的轮换响应、本地读取命令及其他已有认证管理响应仍可提供凭据。普通隧道配置仍含运行凭据，SSE 不是全面脱敏后的公开数据流。

旧 SSE 广播可能与退订关闭通道并发。现在数据队列始终不关闭，独立 done 信号表示退订；登记、计数和移除受锁保护。密钥轮换与关闭断开连接，客户端不应依赖一定收到最后一条 shutdown 数据帧。事件通知入口与总通道关闭也受锁保护，迟到通知直接丢弃。

## 固定资源边界

| 范围 | 本轮行为 |
| --- | --- |
| 受保护的非 SSE 请求体 | 最多 1 MiB；已知长度预先拒绝，未知长度/分块也完整限量读取；超限 413 |
| 请求体读取 | 每次设置 10s 预算；超时 408，读取失败 400；操作前完成读取 |
| REST / MCP JSON | 只接受一个 JSON 值；拒绝尾随第二值，避免先执行合法前缀；REST 400，MCP 保持 JSON-RPC parse error 形式 |
| 普通受保护请求并发 | 每 master 32 个，满时立即 429 / Retry-After: 1；不是速率限制 |
| SSE | 每 master 最多 32 个、每个 10 条事件队列；满时 429；仅接受无请求体 GET，拒绝在订阅前读取不受并发门闩限制的 SSE 请求体 |
| SSE 写入 | 每帧 5s，刷新成功后清除期限；写入/Flush 出错退订；15s 心跳；慢接收端仍可能最多等待该帧预算 |
| 普通管理响应 | 写入预算 5s；不会强制终止任意阻塞业务回调 |
| HTTP server | ReadHeaderTimeout 5s、ReadTimeout 15s、IdleTimeout 60s、MaxHeaderBytes 32 KiB；不设置会截断长期 SSE 的全局 WriteTimeout |
| TCPing | 仍最多 10 个；REST/MCP 传入请求 context，取消等待及实际 DialContext；旧内部 PerformTCPing API 保留后台 context 包装 |

Body 上限适用于 HTTP 入站，不代表本地 import_instances 文件、导出结果、实例总数或所有后台任务已有配额。HTTP 读写预算和 handler 并发上限也不等于连接总数、来源速率或公网 DoS 防护。

## 回归与来源

原生前后对照使用同一测试模板/驱动。旧版本没有共享 Handler 工厂，因此测试适配器从父提交 Run 中逐字截取真实路由和中间件注册块，封装为可调用处理器；不修改生产源码。新版本适配器直接调用实际 Handler。两者各自适配器哈希、模板哈希、源码提交和完整输出保留。测试在内存 HTTP 边界及取消的回环 TCPing 上运行，不创建实际隧道子进程。

| 验证 | 结果 |
| --- | --- |
| 原生认证缺失/空、已知/未知长度超限、尾随 JSON、SSE 密钥、取消等待 | 旧版 70/70 复现，新版 70/70 通过；五类路径十轮 |
| 管理包 race 十轮 | 通过；全路由认证、并发满额、32订阅广播/退订、轮换、不关闭队列、写错误、帧期限清除、SSE拒绝请求体 |
| 真实 race master 进程 | 22/22；MCP、认证、超限、32订阅、轮换断流、新旧密钥；正常退出，无强杀，原始日志未发现密钥、panic 或 DATA RACE |
| 既有安全 / 重载周期进程回归 | 20/20、24/24 |
| 完整 go test -race / go vet | 通过 |
| 源码 CI | [40196076169](https://github.com/VortexWang/Tunveo/actions/runs/40196076169)，9/9 成功；新增 management-boundary-regression |

完整报告、输出、构建信息和 SHA-256 清单位于 [evidence/tnv009](evidence/tnv009)。没有将旧版预期复现报告当作新版失败，也没有用日志脱敏代替原始输出中的泄露断言。真实进程测试只使用临时状态和内存中的合成密钥，不保存密钥值。

```sh
python3 scripts/repro_management_boundaries.py --ref HEAD --mode fixed --go go --output artifacts/management-native.json
go test -race -count=10 ./internal/master
go build -race -trimpath -o bin/tunveo-race ./cmd/tunveo
python3 scripts/verify_management.py --binary bin/tunveo-race --output artifacts/management-process.json
```

## 仍开放的 TNV-009B

普通 Instance 是共享可变对象。日志指标写入、REST/MCP 修改、序列化与持久化之间的字段并发尚未整体隔离；本轮没有声称运行真实子进程时这些路径全部 race-free。优先补日志更新与管理修改并发的真实复现，再确定快照/锁与所有权边界。

批量导入本地文件大小、实例总数、创建/重启速率、后台任务与子进程配额、重复关停及超时后资源回收仍需处理。这里的 32 个 handler 限制不会限制已异步启动的总工作量。

CORS 仍允许已有跨域管理方式，鉴权仍为单一完整管理员密钥；没有新增角色权限、Origin/Host 允许名单、来源速率限制或网络目标访问策略。TCPing/隧道访问网络是已认证管理员功能，本轮没有把允许探测内网的功能改为公共安全边界。

测试是本地受控 HTTP/SSE 与状态轮换，不能代替真实网络慢读压力、长时间运行、公网部署、管理面完整审计或发布验收。下一项继续 TNV-009B，再进入 TNV-010 迁移验证。
