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

- [审计报告 PDF](frontend/pdfs/car-audit-report.pdf)：6 页、含真实载荷截图与结论。
- 审计复核工作台：`vehicle/dashboard/` 的**生成物**，按轮次写入 `output/<轮次>/`（不在库里）；
  仓库内保留的静态示例见 [evidence/dashboard-refactor.html](vehicle/dashboard/evidence/dashboard-refactor.html)。
- 前端验证结果（`verification.json` / `viewport-verification.json`）与验收原始材料（`output/completion/`）：
  原目录已随 `output/` 重建清理，**按需重跑**下方「复现」里的 `tools/build_delivery.py`、
  `tools/verify_presentation.py`；不要引用已不存在的目录路径。
- 夹具 APK：`app/build/outputs/` 的构建产物不入库，需在 `vehicle/targets/target-app/`、
  `vehicle/targets/target-app2/` 本地构建（Debug 与 Gadget 变体）。
- [规则库](vehicle/rules/rules_library/rules.db)：四版本共 116 条风险规则、启用 96 条
  （13/14/15/16 = 19/29/29/19）；外发规则每版 10 条，14/15 全启用（窗口 30000ms，
  revision 2 的 8 条 + revision 1 的 2 条），13/16 登记未启用
  （依据见 `vehicle/rules/EGRESS_CALIBRATION.md`）。

### 移动端

前端日常查看报告走 `frontend/pdfs/`（四份）：

- [车载报告](frontend/pdfs/car-audit-report.pdf)
- [设备实机](frontend/pdfs/mobile-device-latest.pdf)
- [回归](frontend/pdfs/mobile-regression-latest.pdf)
- [第三方批次](frontend/pdfs/thirdparty-latest.pdf)

生成与模型说明：`mobile/README.md`（流程）、`mobile/RISK_SCORE_MODEL.md`（风险评分 v1.3）。

移动端文档入口（合并 ch / junzhe 后按这个顺序读）：

- 总览与两条运行入口：根 [README.md](README.md)（`pipeline` 默认 8771、`workbench` 默认 8772）
- 一键审计流水线：[mobile/pipeline/README.md](mobile/pipeline/README.md)（17 阶段 + SSE 契约）
- 静态/动态工作台：[mobile/workbench/README.md](mobile/workbench/README.md)、
  完整检测 API：[README.audit.md](mobile/workbench/README.audit.md)
- 政策库（含《用户协议》分册）：[mobile/policy/README.local.md](mobile/policy/README.local.md)
- 非 root / root / 真机实验：[mobile/lab/README.core.md](mobile/lab/README.core.md)、
  [README.nonroot.md](mobile/lab/README.nonroot.md)、[README.root.md](mobile/lab/README.root.md)
- 决策与踩坑：[mobile/DECISIONS.md](mobile/DECISIONS.md)（M001–M058）

### 2026-10-19 后的产物

2026-10-19 之后 `output/` 按轮次重新积累（当前为 11-02 ~ 11-10 的多轮跑批），旧目录不可再引用；
需要质量分析或前端截图时按需重跑（质量分析走 `mobile/tools/batch_thirdparty.py`，
前端截图按 [frontend/README.md](frontend/README.md) 的说明）。

### 2026-11-10 新增可交付物

> 只加条目，不改上文结构。上面第 23 行已按实测改写为四版本口径（116 条规则、启用 96 条），
> 与本节第 1 条一致；本节只补充证据链接。

- [规则库四版本](vehicle/rules/rules_library/rules.db)：13/14/15/16 同库（权限 10/10/150/10、风险规则 29×4，
  启用 19/29/29/19；13/16 的 `data_egress` 登记未启用）——回答「同一套规则怎么覆盖四个 AAOS 版本」。
- [规则库与 App 资产一致性](vehicle/rules/android/app/src/main/assets/rules.db)：与 `rules_library/rules.db`
  同为 `DDF57F6F…3026F29`——回答「装进 App 的规则库和仓库里的是不是同一份」。
- [车载工作台后端字段契约](vehicle/webapp/FIELD_CONTRACT.md)：四档计数、阶段耗时、`apk_sha256`、
  `rule_title` 的五级来源、`finding_uid`、复核写接口防护与残余风险——回答「前端能拿到哪些字段、缺字段怎么显示」。
- 车载前端三档改动：B 档组件层 `vehicle/frontend/components.js` / `components.css`（结论汇总条、证据链两级折叠、
  空态/未完成/失败三态）、B 档上传校验 `vehicle/frontend/upload.js`、C 档任务头耗时（`app.js:17` 起）——
  回答「结论、证据、进度和失败原因分别怎么呈现」；验收截图在 `output/vehicle-frontend-{a,b,c}-tier-2026110*/`（不入库）。
- [移动端可达性边界](docs/MOBILE_REACHABILITY_BOUNDARIES_20261110.md)：9 个 F-Droid 样本、110 条可达候选、
  7 个样本触发「本方法对该样本失效」声明——回答「静态可达性到哪一步就不能再下判断」。
- [证书固定样本与设备验证方案](output/memhook-pinning-samples-20261110/REPORT.md)：Proton Mail 3.0.17（首选）与
  Wire 4.36.0（备选）的静态 pinning 证据、判据与排除项；`DEVICE-VALIDATION-PLAN.md` 是尚未执行的上机步骤——
  回答「第三层证书固定场景要用什么样本、怎么验」。
- [内存 Hook 设备证据](output/memhook-evidence-20261109/)：JCE 与 native SSL 正控各一份、不挂 hook 的负控一份——
  回答「Hook 能不能真拿到明文、不挂 hook 时是不是干净的」。
- [跑批手册 §10](docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md#L388)：AAOS 模拟器单样本动态采集的 5 个已知坑
  （多显示器、UXR 吞触摸、EGL 周期失败、verity 装不进系统 CA、TLS 绕过反噬）——回答「在车载模拟器上跑动态采集会卡在哪」。
- [项目真实状态（2026-11-10）](docs/PROJECT_STATUS_20261110.md)：已闭环/进行中/已知缺口/口径易错点——
  回答「现在到底完成了什么、哪些结论还不能说」。

## 复现

先按 [COMPLETION.md](COMPLETION.md) 初始化 `environment.ps1`，再按需运行：

```powershell
& $VScanPython tools/run_regressions.py          # 根回归 18 组（带 --mobile 为 19 组）
& $VScanPython mobile/tools/run_mobile_checks.py # 移动侧 63 项（2026-11-10 并入 test_privacy_implementation.mjs 等 6 个僵尸测试模块 + mobile/lab 的 24 个 + 1 个测试清单守卫 + 并发线同日加入的 observed_surface）
& $VScanPython tools/check_mobile_branch.py      # 移动分支 24 组（含 workbench/policy/AI/前端契约）
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
