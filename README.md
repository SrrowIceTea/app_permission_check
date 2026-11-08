# V-Scanner（项目根）

移动端 / 车载 App 隐私数据与合规审计平台（杭州师范大学星光计划，2026；移动端对应
第九届浙江省大学生网络与信息安全竞赛企业命题）。**仅用于授权测试（自有设备与自有 APK）。**

学术立场（全局硬约束，#2）：工具**不输出违规成立结论**——静态/动态/关联结论以规则封顶
（候选/已观测/已关联），AI 章节只给「涉嫌」+ 置信度 + 需人工复核；每一处
`policy_violation` 只能以提示/优先级/人工复核标记存在。

## 两条产品线 + 平台无关内核

```
vscanner/
├── core/           # 平台无关内核（唯一一份）：事件库/流量采集/代码行号/规则契约/Frida驱动/静态内核
├── vehicle/        # 普通第三方车载审计：独立入口/覆盖链/场景/政策/样本评估 + 原车载工具
├── mobile/         # 移动端产品线：规则库/钩子/政策/AI/报告/工具 + 一键审计流水线
├── frontend/       # 移动端零构建前端：落地页 + 一键审计（8771）；车载独立入口 vehicle/frontend（8773）
├── tools/          # 验收 / 回归脚本（run_regressions.py / check_mobile_branch.py）
├── docs/           # 操作手册（AGENT_TEST_SUITE_RUNBOOK 等）
└── archive/        # 已归档的过期/一次性文档（含 MANIFEST.md 找回说明）
```

> 权威 agent 操作手册见 [AGENTS.md](AGENTS.md)；复现与证据说明见 [COMPLETION.md](COMPLETION.md)；
> 交付索引与当前状态见 [DELIVERY_INDEX.md](DELIVERY_INDEX.md)。

## 普通第三方车载开发（2026-11-02）

统一入口：`./vehicle.ps1 prepare --install-deps`、`coverage`、`profiles`、`capture`、`audit`、`samples`、`benchmark`。
当前以 AAOS 35 为动态基线，版本/车型范围见 [vehicle/COMPATIBILITY.md](vehicle/COMPATIBILITY.md)，
运行步骤见 [vehicle/README.md](vehicle/README.md)，[覆盖链](vehicle/coverage/generated/COVERAGE.md)、
[车载场景](vehicle/scenarios/CATALOG.md)、[独立样本评估](vehicle/bench/README.md) 分别保留验收范围。
移动端前端仍对接 mobile/pipeline；车载入口独立，不能把移动端任务当成车载测试。

## 移动端能力（详见 [mobile/CLAUDE.md](mobile/CLAUDE.md)）

把一次检测拆成五段，每段留下可复核的原始证据：

```
规则库(法规驱动) → 采集(钩子+代理) → 隐私政策 → 关联判定 → AI 研判 → PDF 报告
```

| 赛题要求 | 本工具对应实现 |
| --- | --- |
| 静态分析：识别敏感数据的收集 | APK 清单权限 + dex 代码引用（复用 core/static 事实抽取） |
| 动态分析：识别存储与传输行为 | Frida 钩子观测敏感 API 签名读取 + 同意时序 |
| 通信流量：明文/未加密传输 | mitmproxy 抓流 + 设备端 tcpdump + keylog + tshark 重组完整 HTTP 报文 + 形态打标 + 值哈希/派生值匹配 |
| 风险量化 | 四维乘积评分 v1.3（重复衰减 + 正交置信度），见 mobile/RISK_SCORE_MODEL.md |
| 基于大模型，结合隐私政策与行为研判 | 三阶段提示词 + 证据包 + 输出校验 |

### 关键目录

| 目录 | 内容 | 详情 |
| --- | --- | --- |
| `mobile/rules/` | 移动规则库 `rules_mobile.db`（`MOB-*` 前缀，扩展表 sensitive_data_types/app_categories/policy_requirements） | 构建：`extract_android_apis.py` + `build_mobile_rules.py` |
| `mobile/hooks/` | Frida 钩子（privacy/consent/egress/tls + native），`dist/hook_all.bundle.js` | `gen_targets.py` + `build.mjs` |
| `mobile/hooks/dist/` | 合并 bundle，装载运行时 `core/frida_host/run.py` | 单 agent 合并架构，见 M026 |
| `mobile/policy/` | 隐私政策抽取/分库/登录 | `policy_fetch.py` / `policy_discover.py` / `policy_library.py` |
| `mobile/analyze/` | 关联引擎 `correlate_mobile.py`、风险评分 `risk_score.py`、覆盖缺口 `coverage_gap.py` | |
| `mobile/ai/` | 三阶段提示词 + 证据包 + 输出校验 | `evidence_bundle.py` / `ai_review.py` |
| `mobile/report/` | 十章节 PDF 报告 | |
| `mobile/tools/` | 设备端脚本 `device_run.py`/`device_run_thirdparty.py`（+ split 子模块）、`batch_thirdparty.py`、`pcap_capture.py`/`pcap_http.py`、`conn_probe.py`、`run_mobile_checks.py`、`validate_keylog.py` 等 | 入口集合 |
| `mobile/pipeline/` | 一键审计流水线：`stages.py`(16 阶段)/`runner.py`/`server.py`，SSE 事件流，默认端口 **8771** | |
| `mobile/workbench/` | 静态工作台 `server.py`，默认端口 **8772**，与新流水线互不抢端口 | |
| `mobile/lab/` | 实验室交付入口：`core`/`nonroot`/`root`（README.nonroot.md / README.root.md 等） | |
| `frontend/` | 零构建前端：`index.html` 落地页 + `app.html` 工作台 | 不新增 package.json、不引框架，`python -m http.server` 直接开 |

### 端口分工（重要）

| 服务 | 端口 | 入口 |
| --- | --- | --- |
| 一键审计流水线 | **8771** | `python -B mobile/pipeline/server.py --port 8771 --workdir output/pipe ...` |
| 静态工作台（旧） | **8772** | `python -B mobile/workbench/server.py` |
| 车载审计工作台 | **8773** | `./vehicle.ps1 web`，详见 [车载前端](vehicle/frontend/README.md) |
| 前端静态服务器 | **8090** | `python -m http.server 8090 --bind 127.0.0.1 --directory frontend` |

> 旧文档「都为 8771」已过时。Root / 非 root 由启动配置的正控决定，不能混用证明。

## 车载产品线（已交付，保持稳定）

`vehicle/*`（rules/targets/hooks/traffic/analyze/dashboard/workbench）是独立交付物，
移动端不在车内复制实现，而是以 import 复用 `core/` 的代理归因、代码行号、dex 解析、报告字体方案。
命名对照：Phase 1–7 → `vehicle/{rules,targets,hooks,traffic,analyze,dashboard,workbench}`，
子目录 `DECISIONS.md` 仍按旧 Phase N / D1xx–D7xx 记录历史决策。

## 环境事实（当前主机；入口 environment.ps1）

| 项 | 值 |
| --- | --- |
| Python | `%LOCALAPPDATA%\Programs\Python\Python313\python.exe`（**只有它**装了 frida/mitmproxy/reportlab；`environment.ps1` 用 `$env:LOCALAPPDATA` 派生，换机不硬编码用户名） |
| SDK | `D:\Android\SDK`；`JAVA_HOME=D:\Android\JDK`（JDK 21，**不要用 JBR 25**） |
| 设备 | AAOS 模拟器 `emulator-5554`，Android 15 / API 35 / userdebug；**应用跑在 user 10** |
| frida-server | 设备 `/data/local/tmp/frida-server -l 127.0.0.1:27043`（**27043 不是 27042**）；spawn 超时，用 attach |
| 网络 | 设备只走 wifi 且会掉线；宿主机 `dl.google.com` 不通 → maven 用阿里云镜像 |
| 编译 | Gradle 8.13 / AGP 8.11.1 / Kotlin 2.2.0 / KSP 2.2.0-2.0.2 / Room 2.8.5，compileSdk 36 |

> `.agents/README.md` 记录了当前主机与本文环境表的实测漂移（Python 依赖全缺 → 离线回归会假红；
> SDK/`android-36` 缺失 → 编译会失败；`D:\Anroid` 实为 `D:\Android` 拼写）——跑不通用例前先读它。

## 快速开始

```powershell
# 依赖解释器只有那个（装了 reportlab/Pillow/mitmproxy/cryptography/frida/pypdf）
$py = "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe"

# 1) 仓库级离线回归（不需要设备/网络/API key）
& $py tools/run_regressions.py                 # 16 组：completion/rules-contract/event-store/codeloc/correlate/...

# 2) 移动侧离线回归 + 端点干跑（29 项；看 output/mobile-regression-*/verification.json）
& $py mobile/tools/run_mobile_checks.py

# 3) 移动分支回归（含 workbench / policy / AI / 前端契约）
& $py tools/check_mobile_branch.py

# 4) 一键审计前端（选 APK 触发全流程；仅上传已授权样本）
& $py mobile/pipeline/server.py --port 8771 --workdir output/pipe
python -m http.server 8090 --bind 127.0.0.1 --directory frontend   # 浏览器开 127.0.0.1:8090
```

> **先确认解释器再判红**：若该解释器缺少 `reportlab`/`mitmproxy`/`cryptography`/`frida`/`pypdf`
> 会冒出 6 处 `ModuleNotFoundError` 假红。先跑 `& $py -c "import reportlab, PIL, mitmproxy, cryptography"`。

## 运行一轮设备审计（可选，需设备）

```bash
"$PY" mobile/tools/device_run.py --user 10            # 全流程（有 key 时会跑 AI）
"$PY" mobile/tools/device_run.py --user 10 --skip-ai  # 只到工具结论与报告
```

产物在 `output/mobile-device-<时间戳>/`：`session/` 原始采集 · `out/findings.jsonl + summary.json`
工具规则结论 · `out/bundle.json` 证据包 · `out/ai/` AI 三阶段输出 · `out/mobile-report.pdf` ·
`verification.json` 本轮判据（**看这个判断成败，不要只看目录存在**）。

样本批处理与回归：`mobile/tools/batch_thirdparty.py`（静态 `--static-only` → 动态 `--static-reuse`），
数据集在 `D:/数据集/数据集/F-Droid-60`（60 个 F-Droid 样本），完整步骤/判据/故障处置见
[docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md](docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md)。

## Agent 读项目入口（按顺序）

1. **[AGENTS.md](AGENTS.md)** — agent 操作手册：全局约束、环境事实、跑测试集、规则库、产品地图、
   拆分进度与已完成/未做清单。改任何模块前必读。
2. **[mobile/CLAUDE.md](mobile/CLAUDE.md)** — 移动端模块级说明（结构 + 关键链路 + 坑位）。
3. **[mobile/DECISIONS.md](mobile/DECISIONS.md)** — 移动端决策记录 M001–M058（几乎每个坑都是静默失败）。
4. **[DELIVERY_INDEX.md](DELIVERY_INDEX.md)** — 交付物现状、文档入口清单与复现命令。
5. **[core/collector/DECISIONS.md](core/collector/DECISIONS.md)** 与 `vehicle/*/CLAUDE.md` — 平台内核与车载模块细节。

**改任何模块前先读对应目录的 DECISIONS**——大多数历史坑都是**静默失败**。

## 能力边界（不得逾越）

- 工具不产出「违规成立」；候选/已观测/已关联封顶，违规需人工复核。
- 「未采集到」≠「未发生」；缺失写进缺口清单，AI 提示词强制要求「证据不足」输出。
- 形态 ≠ 事实：报文出现 15 位数字 ≠ IMEI（IMEI/IMSI 同为 15 位），只有值哈希匹配才算「确实传输」。
- 单文件 ≤300 行（超了按职责拆分，拆后回归验证）；观察不改写；判定可追溯（规则 ID + 依据）。
- keylog 不做 100% 解密承诺：部分解密 + 未解密帧数如实呈现。
