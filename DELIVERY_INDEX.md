# 交付索引（2026-09-25）

已完成本轮开发与验证。APK 静态反编译见 [vehicle/workbench/](vehicle/workbench/)（独立工作台，2026-09-28 加入）。适用范围见 [COMPLETION.md](COMPLETION.md)。

## 前端更新（2026-09-25）

- [审计复核工作台](output/frontend-review/dashboard.html)：组合检索、代码位置、规则依据、离线深浅主题。复用下方真实交付会话。
- [前端浏览器验证](output/frontend-review/verification.json) 与 [精确手机视口验证](output/frontend-review/viewport-verification.json)。

## 最终产物

- [PDF报告](output/pdf/vscanner-audit-report.pdf)：12页、8张真实载荷图、16条结论。
- [自包含看板](output/delivery-20260924-193039/dashboard.html)：6 candidate、5 observed、5 correlated。
- [机器可读结论](output/delivery-20260924-193039/findings.jsonl) 与 [汇总](output/delivery-20260924-193039/summary.json)。
- [装机APK核对](output/delivery-20260924-193039/dex-verification.json)：38 VERIFIED、2 INCOMPLETE。
- [数据来源及摘要](output/delivery-20260924-193039/provenance.json)。
- [接收端归属](output/delivery-20260924-193039/ownership.json)：本次为私网地址，如实标non_public。
- [主夹具Debug APK](vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk)。
- [第二夹具Debug APK](vehicle/targets/target-app2/app/build/outputs/apk/debug/app-debug.apk)。
- [主夹具Gadget APK](vehicle/targets/target-app/app/build/outputs/apk/gadget/app-gadget.apk)。
- [规则库](vehicle/rules/rules_library/rules.db)：每版22条风险规则全部启用，8条外发规则窗口30000ms。

## 实测证据

| 验收 | 结果 | 证据 |
| --- | --- | --- |
| 离线回归 | 88项全通过，另schema parity PASS | [回归日志索引](output/regression-20260924-193043/verification.json) |
| Room预置库 | state=OK，14/15分别39/179行，每版22条启用 | [设备结果](output/completion/room-verification.json) |
| 单应用Wi-Fi链路 | 订阅回调、OkHttp Pinner、HTTPS明文、完整载荷、200响应均通过 | [设备结果](output/device-20260924-133521/verification.json) |
| Gadget启动等待 | 注入后恢复，23条真实VHAL读取 | [设备结果](output/gadget-20260924-174538/verification.json) |
| 双App与Phase5 | 错峰两条MATCH，近同时两条AMBIGUOUS，无串包，歧义流不关联 | [设备结果](output/multi-20260924-183952/verification.json) |
| PDF/看板展示 | 深浅主题、筛选、事件徽章、定位缺口、纹理、PDF页码和载荷图通过；逐页视觉检查完成 | [展示结果](output/delivery-20260924-193039/presentation-qa/verification.json) |
| RDAP | example.com真实查询及可校验缓存 | [独立查询示例](output/completion/rdap-smoke.json) |
| IP地理估计 | 8.8.4.4真实HTTPS查询及缓存 | [独立查询示例](output/completion/geo-smoke.json) |

双App轮次使用ADB回环转发；600ms错峰和50ms近同时触发。之前SLIRP轮次的连接超时保留在output中，
不得将回环成功写成SLIRP完全同时外发已通过。公网归属查询示例不是本次私网接收端的身份。
可选MMDB接口尚未用真实数据库做端到端验收；当前可用路径为HTTPS查询及离线缓存。

核对备份库发现CURRENT_GEAR已有R004，8个属性均已有规则，旧“3/8”描述已纠正。
2条INCOMPLETE均来自订阅回调的Native Method栈；保持调用链及缺口，不从dex表编选行号。

## 复现

先按 [COMPLETION.md](COMPLETION.md) 初始化 environment.ps1。常用入口：

```powershell
& $VScanPython tools/run_regressions.py
& $VScanPython tools/device_acceptance.py
& $VScanPython tools/gadget_acceptance.py
& $VScanPython tools/multi_acceptance.py
& $VScanPython tools/build_delivery.py
& $VScanPython tools/verify_presentation.py
```

设备验收要求本项目自建AAOS模拟器与Frida服务已启动；仅用于授权测试。
每轮产生独立目录；latest-*.txt指向最近一次尝试，是否成功必须检查verification.json。
没有执行第三方APK重打包、签名或任意无授权App注入。静态分析见 vehicle/workbench，只读 APK、只分析已获授权的样本。

