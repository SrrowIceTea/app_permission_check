# 移动审计证据交付与复核

仅用于授权测试。入口为 `frontend/app.html` 对接的移动一键审计服务 `8771`。

## 证据 ZIP 与离线复算

完成任务的结果卡显示「下载可重放证据 ZIP」。关联阶段封存参与计算的原始记录、移动规则库、权限与静态类表、实际选用的本地政策。下载时再次校验原始 APK、规则库及同一会话标识，附上原始关联结果，以及已有的 JSON 证据包、PDF 和人工复核记录。原始 APK 以摘要绑定。ZIP 可能含原始请求和读取数据，应在授权审计范围内流转。

历史任务若缺原件或存在无法核对的记录，不提供可重放 ZIP。封存失败保留审计结果及阶段日志。离线核验拒绝错误 APK 摘要、混入其他会话、清单外文件及摘要变化。同一清单内的哈希用于一致性核验，证据来源仍以原采集任务及独立回执为准。

```powershell
$apk = (Get-FileHash 'owned.apk' -Algorithm SHA256).Hash.ToLowerInvariant()
.\tools\python313.ps1 -m mobile.pipeline.evidence_archive replay --archive evidence.zip --apk-sha256 $apk --out output/mobile-offline-replay
```

Android ID 四组基准另可用 `export-benchmark --source <四组采集目录> --out <ZIP>` 生成可携带文件。同一重放命令根据清单类型运行既有移动关联器或四组五档基准。关联重放逐条比较结论及证据引用，任务成功的依据是输出目录中的 `verification.json`。

## 失败日志、重试与人工复核

- 失败或仅完成静态的任务可以展开失败阶段和任务日志。显示末尾 64 KiB 时带截断提示。日志接口使用任务内固定名称。
- 重试要求用户确认授权，核对原始 APK 摘要并沿用已保存的设置。每次重试新建任务，原失败任务及其日志可回看。没有完整设置或 APK 的历史任务需重新上传。
- 动态审计页为当前任务的 `MOB-*` 发现提供确认、驳回与待补证。复核人和依据必填。服务记录时间，并在任务目录原子写入独立复核文件。原始关联结果及结论等级保留原值。

| 路由 | 操作 |
| --- | --- |
| `GET /api/pipeline/{id}/evidence.zip` | 下载绑定当前任务的 ZIP |
| `GET /api/pipeline/{id}/logs[?name=…]` | 查询失败阶段、可用日志或指定日志末尾 |
| `POST /api/pipeline/{id}/retry` | 使用 `{"authorized":true}` 提交独立重试 |
| `GET /api/pipeline/{id}/reviews` | 获取本任务发现与人工复核 |
| `POST /api/pipeline/{id}/reviews` | 提交发现 ID、状态、人工复核人和依据 |
