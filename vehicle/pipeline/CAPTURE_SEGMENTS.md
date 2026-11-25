# A4 车载分段采集与进程退出恢复

仅用于授权测试。提供自有 AAOS 35 设备、明确授权的包名及 Activity、设备用户和本地自有 APK。每段开始前核对装机 APK 的 SHA-256。分段入口关闭 TLS 校验绕过。

```powershell
.\vehicle.ps1 capture-segmented --serial emulator-5554 --user 10 `
  --package com.vscanner.targetapp --activity com.vscanner.targetapp/.MainActivity `
  --apk vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk `
  --segments 2 --seconds 30 --out output/vehicle-segmented-example
```

`--segments` 指计划完成的健康段数（2–10）。`--seconds` 是每段观测时长（1–30 秒），设备检查、重新附加与收尾时间另计。传入 `--preserve-system-proxy` 可保留设备代理设置，未经过本机采集代理的请求正文可能不可观测。

## 恢复与证据

- 初始段启动指定 Activity，后续健康段直接附加。恢复要求同一 PID 在 Hook 就绪时可见、收尾时消失，并确认授权 APK、采集器与网络状态的收尾检查通过。恢复最多启动指定 Activity 一次，并用新会话补足当前段。
- 每次尝试占用独立 `attempt-NN/`，保留日志、原始事件、采集健康和会话清单。运行索引 `segmented-capture.json` 记录段号、会话、验证结果和清单 SHA-256。恢复前核对失败段的原始读数、流量及健康结果摘要。
- `completed_with_gaps` 表示计划健康段已补足，失败段仍保留。重新附加和切段期间存在观测空窗。可对每个通过健康检查的段分别运行 `vehicle.ps1 audit`。失败段供诊断，禁止跨会话拼接读数和请求。
- ADB 状态未知、清理失败、证据校验失败或第二次退出时，索引记录 `failed`，命令退出 1。用户取消返回 130。可查看该段的 `verification.json` 和 `reads.log`。
