# 原核心链路的 Root 采集入口

只负责真实采集，不替代 `correlate_mobile.py → evidence_bundle.py → ai_review.py → report_mobile.py`。
Web 总编排应调用 `capture()`，不能把基准摘要或 AI 解说当作这条链路已经执行。

```powershell
python -m mobile.lab.core_capture --apk APP.apk --package com.example.app `
  --out output/core-capture-NEW --serial emulator-5562 --scenario launch --authorize
python -m unittest mobile.lab.test_core_capture -v
node mobile/hooks/test_privacy_implementation.mjs
```

调用接口：`capture(apk, package, out, serial="emulator-5562", scenario="launch", seconds=20, adb=None)`。
`out` 必须是新目录。场景 `fixture` 是自有阳性对照，`libchecker` 是明确的原包 UI 场景。
所有设备操作均指定同一模拟器；拒绝 USB 真机、非 root 环境、已有同名包及不匹配的 APK 包名。
安装后核对原 APK 摘要，结束只卸载本次自己安装的包，恢复代理设置。失败也保留现场。

## 原始输出

- `session/reads.jsonl`：规则库生成的 68 个敏感 API，保留 canonical API 身份。
- `session/consent.jsonl`：权限请求、权限结果、政策页面线索；不代表直接政策接受。
- `session/egress.jsonl`：应用进程内真实出网连接和 URL 观测。
- `session/flows.jsonl`：复用原 mitmproxy collector 的响应流、时间归因与脱敏令牌。
- `session/audit.jsonl`：真实存储、JCE 调用观察；流写入不等于磁盘明文证明。
- `session/traffic.pcap`、`pcap-summary.json`：`any` 接口不设协议过滤的全模拟器包；不是应用 UID 归因，也不代表全协议可解密。
- `verification.json`、ADB 日志、UI XML、应用/崩溃日志、编译脚本：本次检查和失败证据。

HTTPS 不安装测试 CA、不绕过固定证书；因此此入口不声称可读取所有 TLS/QUIC 载荷。
有限 UI 没有流量或某类事件不能判“无风险”。`state=done` 只指声明的采集判据满足，不指合规或完整业务路径覆盖。

## 本轮复现与修复

1. 原敏感钩子独立加载在 API 36 自有正控上可以捕到事件，并非全量 68 个 API 必然崩溃。
2. 多个独立 Java bridge 在冷启动阶段产生 `Application.attach` 递归：改为单 bundle、共享一个 Java bridge；失败现场保留在 run1。
3. `PackageManager` 是抽象类，挂声明但实际子类覆盖会出现“ARMED 但安装列表零事件”。运行时映射到 `ApplicationPackageManager`，仍引用 android.jar 生成的 canonical API，并额外记录 `hook_class`。
4. 夹具 run3 真实捕获 12 条读取、4 条权限事件、1 条 HTTP 200 流；Android ID 读取与发送令牌哈希相同。安装列表成功返回 249 项。
5. LibChecker 原包 run1 真实捕获 2 条安装列表读取、57 次文件打开、88 次文件写入、6 次偏好写入；该窗口 0 条应用 HTTP 流。数据库初始化数据不是已证明的隐私泄露。

原始现场：`output/core-e2e-fixture-20261018-run3/`、`output/core-e2e-libchecker-20261018-run1/`。
13 项离线采集契约回归、具体实现类回归及原 40 项 dispatch 回归通过；不把离线模拟数据计入上述实测数量。


## 冷启动与兼容晚附加

默认 `--startup-mode spawn` 在应用启动前安装钩子。部分原包与模拟器组合启动异常时，
可显式使用 `--startup-mode attach`：先完成声明的初始界面动作，再对白名单包的确切进程附加。
多 PID 时按 cmdline 及前台应用身份缩窄，无法唯一确认就失败，不猜 PID。
晚附加之前的启动/同意/网络行为没有被钩子观测，gap 与 `pre-attach-ui-actions.json` 保留，不能声称覆盖首次启动。
原包及安装后摘要不变，每次独立新目录，清理已安装测试包并恢复原代理。
若进程已结束，不向失效 Frida session 同步卸载以免阻塞 PCAP 导出；坏 JSONL 仍保存失败验收，不能视为零事件。
