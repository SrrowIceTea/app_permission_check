# 交付索引（2026-10-19 更新）

> **2026-10-19 `output/` 清理**：历史跑批产物共 208 项（`mobile-regression-*`、`thirdparty-*`、
> `device-*`、`delivery-*`、`regression-*`、`mobile-device-*` 等）已删除，`latest-*.txt` 指针一并移除。
> 原因：项目尚未进入集中跑测试集阶段，这些是历次调试／验收的中间产物，不是最终交付物。
>
> **清理不改变任何结论**——已有结论仍以 `COMPLETION.md`、各目录 `DECISIONS.md`（D1xx–D7xx、M0xx）、
> `mobile/DEV_FIX_REPORT.md` 的文字记录为准；但**逐次运行的原始 `verification.json` 已不可复核**，
> 需要证据请按下方「复现」重跑，不要引用已删除的目录路径。

## 现存交付物

### 车载（AAOS）

- [审计报告 PDF](output/pdf/vscanner-audit-report.pdf)：12 页、含真实载荷截图与结论。
- [审计复核工作台](output/frontend-review/dashboard.html)：单文件，双击可离线打开（需启用 JavaScript）。
- [前端验证结果](output/frontend-review/verification.json) 与
  [手机视口验证](output/frontend-review/viewport-verification.json)。
- [验收原始材料](output/completion/)：`findings.jsonl`、`summary.json`、`room-verification.json`、
  `rdap-smoke.json`、`geo-smoke.json`、`payload-images/`、PDF 逐页截图。
- 夹具 APK：
  - [主夹具 Debug](vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk)
  - [第二夹具 Debug](vehicle/targets/target-app2/app/build/outputs/apk/debug/app-debug.apk)
  - [主夹具 Gadget](vehicle/targets/target-app/app/build/outputs/apk/gadget/app-gadget.apk)
- [规则库](vehicle/rules/rules_library/rules.db)：双版本 44 条风险规则全部启用，
  外发规则每版 8 条、窗口 30000ms、revision=2（依据见 `vehicle/rules/EGRESS_CALIBRATION.md`）。

### 移动端

前端日常查看报告走 `frontend/pdfs/`（四份）：

- [车载报告](frontend/pdfs/car-audit-report.pdf)
- [设备实机](frontend/pdfs/mobile-device-latest.pdf)
- [回归](frontend/pdfs/mobile-regression-latest.pdf)
- [第三方批次](frontend/pdfs/thirdparty-latest.pdf)

生成与模型说明：`mobile/README.md`（流程）、`mobile/RISK_SCORE_MODEL.md`（风险评分 v1.3）。

移动端文档入口（合并 ch / junzhe 后按这个顺序读）：

- 总览与两条运行入口：根 [README.md](README.md)（`pipeline` 默认 8771、`workbench` 默认 8772）
- 一键审计流水线：[mobile/pipeline/README.md](mobile/pipeline/README.md)（16 阶段 + SSE 契约）
- 静态/动态工作台：[mobile/workbench/README.md](mobile/workbench/README.md)、
  完整检测 API：[README.audit.md](mobile/workbench/README.audit.md)
- 政策库（含《用户协议》分册）：[mobile/policy/README.local.md](mobile/policy/README.local.md)
- 非 root / root / 真机实验：[mobile/lab/README.core.md](mobile/lab/README.core.md)、
  [README.nonroot.md](mobile/lab/README.nonroot.md)、[README.root.md](mobile/lab/README.root.md)
- 决策与踩坑：[mobile/DECISIONS.md](mobile/DECISIONS.md)（M001–M040）

### 2026-10-19 新产物（保留）

- [测试集质量分析](output/dataset-quality-20261019/质量分析-20261019.md)
  + `batch-quality.csv` / `batch-quality.json` / `policy-inventory.json`
- [前端界面截图](output/frontend-shots/)

## 复现

先按 [COMPLETION.md](COMPLETION.md) 初始化 `environment.ps1`，再按需运行：

```powershell
& $VScanPython tools/run_regressions.py          # 根回归 13 组
& $VScanPython mobile/tools/run_mobile_checks.py # 移动侧 24 组
& $VScanPython tools/check_mobile_branch.py      # 移动分支 22 组（含 workbench/policy/AI/前端契约）
& $VScanPython tools/device_acceptance.py
& $VScanPython tools/gadget_acceptance.py
& $VScanPython tools/multi_acceptance.py
& $VScanPython tools/build_delivery.py
& $VScanPython tools/verify_presentation.py
```

每轮在 `output/<类型>-<时间戳>/` 下产生独立目录。

> **`latest-*.txt` 已删除的副作用**：`tools/verify_presentation.py` 会读取
> `output/latest-delivery.txt`。在全新 `output/` 上直接跑它会 `FileNotFoundError`；
> 正确顺序是**先跑 `build_delivery.py`**（会重建指针与交付目录），再跑 `verify_presentation.py`。
> 其余工具用 `mkdir(parents=True)` 自建目录，清空 `output/` 不影响。

设备验收要求本项目自建 AAOS 模拟器与 Frida 服务已启动；**仅用于授权测试**。
没有执行第三方 APK 重打包、签名或任意无授权 App 注入。静态分析见 `vehicle/workbench`，
只读 APK、只分析已获授权的样本。

## 保留的判定边界（不因清理而放宽）

- 双 App 轮次使用 ADB 回环转发；600ms 错峰与 50ms 近同时触发。
  **不得**把回环成功写成 SLIRP 完全同时外发已通过。
- 公网归属查询示例**不是**本次私网接收端的身份；可选 MMDB 接口尚未用真实数据库做端到端验收。
- 2 条 INCOMPLETE 来自订阅回调的 Native Method 栈；保持调用链与缺口，不从 dex 表编选行号。
- 失败运行保留、不覆盖：重跑请用新时间戳目录，不要复用旧目录名。
