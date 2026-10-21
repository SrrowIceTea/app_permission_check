# archive/ — 归档清单（MANIFEST）

车载 / 移动端拆分过程中归档的死内容与历史快照。逐条记录来源路径、归档理由、原引用方，
以及"如果反悔"如何找回。

## 条目

### 1. `research/RELATED_WORK.md`

- **原路径**：`vehicle/rules/research/RELATED_WORK.md`（更早是 `phase1/research/RELATED_WORK.md`）
- **归档理由**：全仓仅 1 处文档引用（`vehicle/rules/CLAUDE.md` 的目录表），零代码依赖。
  属于研究阶段的工作记录，不在当前运行链上。
- **原引用方**：`vehicle/rules/CLAUDE.md:17`（已改为指向 `archive/research/RELATED_WORK.md`）。
- **找回方式**：需要时 `git mv archive/research/RELATED_WORK.md vehicle/rules/research/`。

### 2. ~~`mobile-device-latest.pdf` / `mobile-regression-latest.pdf` / `thirdparty-latest.pdf`~~（**已撤回**）

- **状态**：**2026-10-13 撤回归档，三份已移回 `frontend/pdfs/`**，`frontend/app.html`
  的 PDF 下拉同步加回三个选项。当初按「前端只服务车载」移出，但前端才是日常查看报告的
  入口，只列车载不够用，故恢复。
- **原路径**：`frontend/pdfs/`（车载工作台前端，2026-10-11 手工拷贝，无脚本引用）。
- **当初的归档理由**：`frontend/` 是车载专用前端，不该混入移动端报告。三个 PDF 是某次
  运行结果的**手工快照**，正规产物在 `output/` 下、可随时重新生成。
- **正规产物位置**（仍是更新快照的正规来源，`pdfs/` 下的是快照、要手工替换）：
  - 设备审计 → `output/mobile-device-*/out/mobile-report.pdf`（指针 `output/latest-mobile-device.txt`）
  - 回归 → `output/mobile-regression-*/e2e/report.pdf`（指针 `output/latest-mobile.txt`）
  - 第三方 → `output/thirdparty-*/<包名>/out/mobile-report.pdf`（指针 `output/latest-thirdparty-batch.txt`）
- **找回方式**：从上面指针目录直接取最新一份，或重跑 `mobile/tools/device_run.py` / `run_mobile_checks.py` / `batch_thirdparty.py`；
  本次撤回是用 `git checkout 4122025^ -- frontend/pdfs/<名字>.pdf` 从历史恢复的。

### 3. 文档治理批量归档（2026-10-21，一次性/过期的进度与复核文档）

这批是**已过期或一次性**的进度记录/复核报告，内容均已落入
`mobile/DECISIONS.md`（M001–M056）与 `AGENTS.md` 的当前状态，不再需要以活跃文档存在。
集中归档前逐个核对：无代码 import；引用方已同步改为 `archive/...` 路径。

| 文件 | 原路径 | 归档理由 |
|---|---|---|
| `VERIFY_M031_M032_20261016.md` | 仓库根 | A1 修复的**一次性独立复核报告**，结论已并入 `mobile/DECISIONS.md` M031/M032 与 `mobile/DEV_FIX_REPORT.md` |
| `TWO_DEV_PLAN.md` | 仓库根 | 双通道开发计划 v3，其 A1/SLIRP 修复、工程-6/工程-7 均已完成，剩余项已并入 `mobile/PLAN_OPTIMIZATION_20261020.md`（本批同归档）与 `HANDOFF.md` |
| `EXPERIMENTS.md` | 仓库根 | 早期量化实验结论（归因/相关性 228/228、precision/recall 1.0），为固定时序下的**构造实验**，非当前产品状态；结论被 `COMPLETION.md` 等引用处已改为 `archive/` 路径 |
| `docs/DS60_VERIFY_20261020.md` `docs/DS60_FIX_20261020.md` | `docs/` | keylog 链路单样本深挖（DS60）的一次性验证与修复记录，结论已并入 `HANDOFF.md` 3.4 与 M056 |
| `docs/FIX_VERIFICATION_20261019.md` | `docs/` | 前端修复的一次性验证报告 |
| `docs/MERGE_NONROOT_AUDIT_20261018.md` | `docs/` | 合并 ch/junzhe 分支的一次性审计记录 |
| `docs/FUNCTIONAL_FRONTEND_20261019.md` | `docs/` | 2026-10-19 前端功能验收的一次性记录，验收表格已在根 `README.md` |
| `mobile/SAMPLE_RUN_5APPS.md` | `mobile/` | 2026-10-13 五个第三方样本的一次性实机实测报告，结论已并入 `mobile/DECISIONS.md` M026–M028 |
| `mobile/PLAN_OPTIMIZATION_20261020.md` | `mobile/` | P2 优化计划/优先级裁决；P0-A/P0-B 任务已全部收口（见本批 p1–p7 完成），裁决结论与拆分记录已在 `mobile/DECISIONS.md` M055 |

- **找回方式**：`git checkout <commit>^ -- <原路径>`；或直接读 `archive/<文件名>`（保留在这里，
  链接已从活跃文档改为本目录）。

## 尚未归档（留待确认）

以下内容也在 `.gitignore` 之外、或涉及运行链，暂不归档，等确认后再动：

- `apk/` 样本按平台分目录（车载 `com.ximalaya.ting.android.car.*` vs 移动端样本）。
  边界需你判断：ximalaya 是"车载版 APK"却一直被 `mobile/tools/batch_thirdparty.py` 当第三方样本跑。
- `output/` 历史产物（101+ 目录）。`latest-*.txt` 指针被运行脚本持续写、`DELIVERY_INDEX.md`
  引用交付目录，物理移动会断证据链，需先规划旧→新路径映射。
- `mobile.zip`（55MB）、各级 `logs/`/`evidence/`/`.cache/`/`gadget-cache/`：均在 `.gitignore`
  内、属于可再生运行产物，无需归档。
