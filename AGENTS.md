# V-Scanner 项目根

面向 AAOS 的第三方车载 App 与移动端 App 数据安全合规审计平台（杭州师范大学星光计划，2026）。
**仅用于授权测试（自有设备与自有 APK）。**

本仓库正在把「车载审计」与「移动端审计」两条产品线**分开**，共享平台无关内核：

```
vscanner/
├── core/           # 平台无关内核（唯一一份）：事件库/流量采集/代码行号/规则契约/Frida驱动/静态内核
├── vehicle/        # 车载 AAOS 产品线：rules→targets→hooks→traffic→analyze→dashboard→workbench
├── mobile/         # 移动端产品线：规则库/钩子/政策/AI/报告/工具 + 一键审计流水线（详见 mobile/CLAUDE.md）
├── frontend/       # 零构建前端：落地页 + 「一键审计」工作台（对接 mobile/pipeline:8771）
└── tools/          # 验收 / 回归脚本
```

## 用户定的全局约束（两条产品线都适用，不得违反）

1. **仅授权测试**：涉及抓包/Hook 的代码必须写明"仅用于授权测试"，默认只监控白名单包名。
2. **绝不编造签名**：`android.car` 的类名/方法/protectionLevel/propertyId 不确定就生成
   TODO + 占位常量表 + 探测脚本让用户跑。例外：CAR_SPEED / CAR_ENERGY 已实测存在。
3. **观察不改写**：观察阶段只记录，不拦截不篡改（`ssl_pinning_bypass.js` 是唯一例外，
   且仅对白名单进程、仅为审计流量捕获）。
4. **可运行优先于完整**：每阶段交付物必须能在用户环境跑通，再谈完整。
5. **判定可追溯**：每条违规结论带规则 ID + 依据来源。
6. **失败可诊断**：Hook 脚本 try/catch + 日志落盘，区分"没读到数据"和"脚本崩了"。
7. **禁止再让用户做环境探测**（Phase 0 已完成）。
8. **单文件 ≤300 行**；超了按职责拆分（hooks/traffic/dashboard 都有拆分的先例），拆后必须回归验证。
9. **每次开发都写开发日志**：开始前在 [docs/DEVELOPMENT_LOG.md](docs/DEVELOPMENT_LOG.md) 登记范围；结束前补齐实际改动、验证命令与结果、证据路径、失败或待办。代码、规则、配置和验收工具改动都适用。日志到 300 行时转存分卷，主文件保留索引及最新记录。
10. **只推功能分支，`main` 走 PR 由管理员合并**：改动先提交到 `feature/*` 分支并推送，再提 PR 等管理员审核合并。
    **禁止 `git push` 到 `main`**（2026-11-23 误推过一次，靠 force push 回退）；回退 `main`、改写共享历史属破坏性操作，
    必须先拿到用户当次的显式授权。细则见下节。

## 分支与提交流程（2026-11-24）

远程 `origin` = Gitee `mao-yuqi-12/mobile-app-permission-check`。`main` 是唯一目标分支，
协作者只往 `feature/*` 推。

- **"需要管理员审核"的前提是仓库设置**：只有管理员在「管理 → 分支设置」把 `main` 设为保护分支
  （禁止直接推送 + 需审核通过才可合并）后，这条才真正生效。设置之前，任何协作者都能直接推 `main`——
  不要因为"推成功了"就认为不需要审核。
- 标准流程：

  ```powershell
  git switch -c feature/<主题>        # 或复用已有的 feature 分支
  git add <逐个列出的文件>            # 不用 git add -A
  git commit -m "feat(vehicle): ..."
  git push -u origin feature/<主题>   # 只推功能分支
  ```

  然后在 Gitee 提 PR：`origin/feature/<主题>` → `origin/main`，等管理员审核合并。
  PR 链接格式：`https://gitee.com/mao-yuqi-12/mobile-app-permission-check/pull/new/mao-yuqi-12:feature/<主题>...mao-yuqi-12:main`

- **禁止项**：
  - 不执行 `git push origin <分支>:main`。本地分支跟踪 `origin/main` 只是跟踪关系，**不代表可以推送**。
  - 不对 `main` 用 `--force` / `--force-with-lease`，除非用户当次明确要求；确需回退时先 `git fetch`，
    再用 `--force-with-lease=<ref>:<旧提交>` 锁定，避免覆盖他人提交。
  - 不用 `git add -A`：临时验证脚本（`_*.py`）和 `output/` 产物不该进提交。
- **推送后自检**：`git rev-parse origin/main` 应仍是你预期的提交；本次改动只能出现在功能分支上。

## 环境事实（当前主机；入口 environment.ps1）

| 项 | 值 |
| --- | --- |
| Python | **本机（HW）实测**：项目 `.venv` 是 3.14.10（`D:\软件\python.exe` 建的；frida 17.18.0 / mitmproxy / cryptography / reportlab / pypdf / jsonschema 齐全），统一入口 `.\tools\python313.ps1` 会**优先选 `.venv`**。**原开发机**记录为 `%LOCALAPPDATA%\Programs\Python\Python313\python.exe`（3.13.9），当时默认 `python` 是 WindowsApps 3.15 缺库。**依赖是否齐全一律看 `core/env_guard.py` 的退出码**（0 可用 / 3 缺库）；不同时点写下的"缺 jsonschema""依赖已齐"都只是当时那个解释器的状态，别当常量 |
| SDK / JDK | **本机（HW）主 SDK = `D:\app project\AndroidSdk`**（`VSCAN_SDK` 与 `ANDROID_SDK_ROOT` 都已指向它）：含 `platform-tools`、`emulator`、`system-images\android-35-ext15\android-automotive\x86_64`（AAOS 35 镜像）、`build-tools\34.0.0/35.0.0/36.0.0`、`platforms\android-36`（含 `optional/android.car.jar`）、`jdk-21`、`avd`。`%LOCALAPPDATA%\Android\Sdk` 是 2026-11-24 补装的**副本**（只有 cmdline-tools、platform-tools、build-tools 35+36、platforms 36、emulator、镜像）——**探测环境先看 `VSCAN_SDK`，只看 LOCALAPPDATA 会误判成"什么都没装"**。JDK：`JAVA_HOME=D:\Android\JDK`（Temurin 21.0.13.1），SDK 内另有同版本 `AndroidSdk\jdk-21`。JADX 在 `D:\app project\Jadx\jadx-gui-1.5.3-with-jre-win`。**原开发机**记录为 `D:\Anroid\SDK` / `D:\Anroid\JDK`（目录名就是这种拼写）；换机用 `VSCAN_SDK` / `VSCAN_JDK` 覆盖，别把文档改回旧路径。**不要用 JBR 25** |
| 设备 | AAOS 模拟器 `emulator-5554`：Android 15 / API 35 / userdebug / `ro.build.characteristics=automotive`；**应用跑在 user 10**。AVD 实体在 `D:\app project\AndroidSdk\avd\VScanner_AAOS_35_P1.avd`（1408×792、data 6G），项目里的 `output/vehicle-device-setup/avd/VScanner_AAOS_35_P1.ini` 只是 `path=` 指针；镜像在 SDK 的 `system-images\android-35-ext15\android-automotive\x86_64\`，**不在** `output/vehicle-device-setup/image/`（那是原开发机布局）。启动可用 WMI `Win32_Process.Create`；`Start-Process` 起的子进程可能随执行会话被回收 |
| frida-server | 设备 `/data/local/tmp/frida-server -l 127.0.0.1:27043`（**27043 不是 27042**）；spawn 超时，用 attach。宿主侧文件在 `output/vehicle-device-setup/frida-server`，**版本必须等于 `.venv` 的 frida（本机 17.18.0）**；官方只发 `.xz`，Windows 没自带 xz，用 Python `lzma` 解压即可 |
| 网络 | 设备只走 wifi 且会掉线。**本机（HW）`dl.google.com`、`nodejs.org`、`mirrors.aliyun.com`、清华 Adoptium 实测都通**；原开发机 `dl.google.com` 不通、故 maven 用阿里云镜像（这条继续保留）。Gradle wrapper 的 `networkTimeout=10000` 太短，走阿里云下 130 MB 会 SSL decode 中断，需手工放缓存：目录名是 distributionUrl 的 MD5 转 **base36**（不是 hex）。Git Bash 的 `$PWD` 是 POSIX 形式，写进 Windows 环境变量要用 `$(pwd -W)` |
| 编译 | Gradle 8.13 / AGP 8.11.1 / Kotlin 2.2.0 / KSP 2.2.0-2.0.2 / Room 2.8.5，compileSdk 36（工程钉 36，需 `optional/android.car.jar`）。**AGP 8.11.1 实际还会要 build-tools 35.0.0**：只装 36 时 `:app:assembleDebug` 报 `Install Build-Tools 35 v.35.0.0 failed`。Node 24 在 `D:\tools\node`（已进用户 PATH，`vehicle.ps1 prepare` 依赖 `npm`，缺了报 `npm_missing`）。工程路径含非 ASCII **或空格**需 `android.overridePathCheck=true`；`start-all.ps1` 已对含空格路径的参数补引号 |

## 跑移动端测试集（agent 操作手册）

测试集在 `D:/数据集/数据集/F-Droid-60`（60 个 F-Droid 样本），**不是** `D:/测试集`。
**本机（2026-11-11）该目录不存在**：跑批入口会明确报「目录不存在」，别把路径错当成
「0 个样本」或「数据集为空」；换机先确认数据集是否已挂载。
跑批入口 `mobile/tools/batch_thirdparty.py`（静态 `--static-only` → 动态 `--static-reuse`）。
完整步骤、判据、故障处置见 [docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md](docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md)，
改环境或换机后先读它，别从零试错（Wi-Fi 不自动连、System UI ANR 挡夹具、托管 Python 缺 frida 三个坑必踩）。

## 产品地图

| 目录 | 内容 | 详情 |
| --- | --- | --- |
| `core/` | 平台无关内核（车载/移动共用） | `event_store.py` 时序事件库；`collector/` 流量采集；`evidence/` 代码行号+dex 核对；`rules_contract.py` 规则库契约 |
| `core/privacy/` | 通用隐私来源的规则与设备观测冻结（车载/移动共用） | [core/privacy/DECISIONS.md](core/privacy/DECISIONS.md) |
| `vehicle/rules/` | 车载规则库（VSC-*，四版本 rules.db：13/14/15/16）+ Room 工程 | [vehicle/rules/CLAUDE.md](vehicle/rules/CLAUDE.md) |
| `vehicle/targets/` | 靶子 App×2（被测对象）+ trigger.py | [vehicle/targets/CLAUDE.md](vehicle/targets/CLAUDE.md) |
| `vehicle/hooks/` | Frida 钩子（VHAL 读取/出站/TLS 绕过/内存明文/侦察） | [vehicle/hooks/CLAUDE.md](vehicle/hooks/CLAUDE.md) |
| `vehicle/traffic/` | Mitmproxy 反向代理 + 按包名归因 + 敏感打标（VHAL 指纹表） | [vehicle/traffic/CLAUDE.md](vehicle/traffic/CLAUDE.md) |
| `vehicle/analyze/` | 关联引擎 + PDF 报告（代码行号已抽到 core/evidence） | [vehicle/analyze/CLAUDE.md](vehicle/analyze/CLAUDE.md) |
| `vehicle/dashboard/` | Web 可视化预警看板（交付物 B，静态单文件） | [vehicle/dashboard/CLAUDE.md](vehicle/dashboard/CLAUDE.md) |
| `vehicle/workbench/` | APK 静态反编译工作台（server + static_rules + crosscheck） | [vehicle/workbench/CLAUDE.md](vehicle/workbench/CLAUDE.md) |
| `vehicle/pipeline/` | 车载审计流水线：preflight→capture→audit→acceptance（`vehicle.ps1` 的实现层） | `vehicle/pipeline/audit.py` |
| `vehicle/scenarios/` | 夹具场景目录与触发套件 | [vehicle/scenarios/CATALOG.md](vehicle/scenarios/CATALOG.md) |
| `vehicle/coverage/` | 规则覆盖链生成与设备观测导出 | `vehicle/coverage/export.py`、[generated/COVERAGE.md](vehicle/coverage/generated/COVERAGE.md) |
| `vehicle/policy/` | 隐私政策条款匹配与复核结论评估 | [vehicle/policy/REVIEW_POLICY.md](vehicle/policy/REVIEW_POLICY.md) |
| `vehicle/privacy/` | 通用隐私来源（定位/麦克风/联系人/Android ID/AAID）规则与设备验收 | [vehicle/privacy/README.md](vehicle/privacy/README.md) |
| `vehicle/bench/` | 基准/盲测套件与窗口标定（B1–B3 指标） | [vehicle/bench/README.md](vehicle/bench/README.md) |
| `vehicle/lab/` | 一次性实验与第三方设备验收记录（root/non-root、HA、API 34 等） | `vehicle/lab/P1_P2_RESULTS.md` |
| `mobile/` | 移动端产品线（MOB-* 规则库/钩子/政策/AI/报告/工具）+ `pipeline/` 一键审计（17 阶段 + SSE）+ `workbench/` 静态工作台 | [mobile/CLAUDE.md](mobile/CLAUDE.md) |
| `frontend/` | 零构建前端：`index.html` 落地页 + `app.html`「一键审计」工作台 | [frontend/README.md](frontend/README.md) |

各目录的实测教训记录在各自 `DECISIONS.md`（D101–D7xx 编号），
改任何模块前先读对应目录的 DECISIONS——几乎每个坑都是**静默失败**。

**命名对照**（目录已从 `phase1–7` 改名，子目录 `DECISIONS.md` 仍按旧 Phase N / D1xx–D7xx 记录历史决策）：
Phase 1=`vehicle/rules/`，Phase 2=`vehicle/targets/`，Phase 3=`vehicle/hooks/`，Phase 4=`vehicle/traffic/`，
Phase 5=`vehicle/analyze/`，Phase 6=`vehicle/dashboard/`，Phase 7=`vehicle/workbench/`。

## 规则库（已分开，2026-10-12）

两套 `.db` 物理独立、schema 大同小异，通过 `core/rules_contract.py` 以 **rule_id 前缀**
（`VSC-` 车载 / `MOB-` 移动）作权威判别符、按平台加载扩展表：

| 库 | 路径 | 前缀 | 扩展表 |
| --- | --- | --- | --- |
| 车载 | `vehicle/rules/rules_library/rules.db` | `VSC-` | `vhal_properties` |
| 移动 | `mobile/rules/rules_mobile.db` | `MOB-` | `sensitive_data_types` / `app_categories` / `policy_requirements` |

移动库不再伪造空 `vhal_properties` 表去适配车载加载器（该 hack 已删除）。

## 前端改动与外部 Skills（2026-10-19）

`frontend/` 是**零构建**的纯 HTML/CSS/JS：不新增 `package.json`、不引 React/Vue/Tailwind/CDN 组件库，
`python -m http.server` 必须直接能打开。改版的工作流、契约与视觉规范见
[frontend/README.md](frontend/README.md) 的「Skills / MCP 使用」与
`.workbuddy/skills/vscanner-frontend-redesign/SKILL.md`（项目级技能，**随仓库分发**）。

上游 25 个 skill/MCP 仓库副本共 **1.5 GB / 34,262 文件，已全部不入库**（见 `.gitignore`）；
clone 后 `skills/` 下只有两个索引文件。需要时按 [skills/SKILLS.md](skills/SKILLS.md) 的地址
**只拉最小集**（`anthropics-skills` + `lucide`，约 67 MB），其余按表里的判定决定是否要；
浏览器自动化用 `npx @playwright/mcp@latest`，不必克隆仓库。**不要**全量克隆——会把 1.5 GB 拖进工作区。

## DeepSeek Harness（DSH）技能与插件（2026-10-21）

`.agents/skills/` 是 **DSH 自动发现**的项目级技能根（rank 200；只扫一层，嵌套 `**/SKILL.md` 不生效），
已放入 5 个技能 + 1 个指向 `.workbuddy/skills/` 的符号链接，共 37 文件 / 573 KB，**随仓库分发**。
选型判定、加/删技能步骤、本次装的 3 个 DSH 插件（需重启生效）、以及**没做的 MCP 配置**，
全部见 [.agents/README.md](.agents/README.md)。那里还记录了**当前主机与本文环境表的实测漂移**
（截至 2026-11-10：Python 3.13 依赖已齐、`android-36` 已装；`D:\Anroid` 是原开发机路径，不是本机拼写错误）——
换机或跑不通用例前先读它。

## 离线回归（改完代码先跑，不需要设备）

```bash
# 统一入口：固定解析到项目 Python 3.13（VSCAN_PYTHON > .venv > Python313 安装目录）
.\tools\python313.ps1 tools/run_regressions.py        # 22 组（--mobile 23、--prepare --mobile 24）：
                                                      #  completion / rules-contract / event-store / log-rotation /
                                                      #  codeloc / correlate / vehicle-evidence / vehicle-pipeline /
                                                      #  collector / vehicle-method / vehicle-optimizations /
                                                      #  tagging-vehicle / dashboard / vehicle-webapp /
                                                      #  vehicle-expanded-review / vehicle-ledger-ui / runtime /
                                                      #  privacy-runtime / parity / workbench / hook-bundles /
                                                      #  frida-bundle-config

.\tools\python313.ps1 mobile/tools/run_mobile_checks.py   # 移动侧 63 项（另一条入口，改 mobile 后必须跑）
.\tools\python313.ps1 tools/check_mobile_branch.py        # 移动分支 26 组（含 batch_plan / pipeline 前端契约 /
                                                          #  workbench / policy / AI / 7 个 UI 契约）
```

> **组数以代码为准**（`tools/run_regressions.py:CHECKS`、`tools/check_mobile_branch.py:CHECKS`）：
> 上面这组数字是 2026-11-11 实测核对值。历史上本节写过 18 组、`docs/REGRESSION_CI.md` 写过
> 历史 18/19 组口径都是手工维护漏更新——**改清单时同步本文**，或者只看 `verification.json`。
> 当前状态与本周工单唯一入口见 [docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md)。

> **先确认解释器再判红**：本机默认 `python` 是 WindowsApps 的 **3.15**，缺 `frida`/`mitmproxy`/
> `cryptography`/`jsonschema`/`pypdf`；用它跑会冒出成片 `ModuleNotFoundError` 的**假红**（实测：
> 根回归 3 组、分支回归 5 组），把真正的回归失败盖住。改用 `.\tools\python313.ps1` 启动即可
> （选择顺序 `VSCAN_PYTHON` > `.venv` > `%LOCALAPPDATA%\Programs\Python\Python313`）。
> 三个回归入口已内置 `core/env_guard.py` 前置检查：缺库时打印缺哪些包、该用哪个解释器，
> 并以**退出码 3** 结束（`1` 才是测试失败），不会让每组测试各自报错。
> 细节见 [docs/REGRESSION_CI.md](docs/REGRESSION_CI.md)「解释器与缺库」。

## 当前交付与拆分进度（2026-10-19）

完整复现入口与证据说明见 [COMPLETION.md](COMPLETION.md)。
APK 静态反编译作为**独立工作台**（vehicle/workbench，2026-09-28，用户解除原排除）；违规代码行号仍**只**
取自运行时栈（D507 不变），静态证据不写进 code_locs。

已补齐：RDAP 归属与 IP 位置估计/离线缓存、PDF 载荷截图、SQLite 单机时序事件库、
自有源码 Gadget 模式、OkHttp 固定证书夹具、订阅回调、规则覆盖缺口展示、/collect 200 接收端。
外发规则每版 10 条（revision 2 的 8 条 + revision 1 的 2 条），窗口 30000ms，仅 14/15 全启用、
13/16 登记未启用；四版本 116 条风险规则启用 96 条（13/14/15/16 = 19/29/29/19）。
启用依据与范围见 vehicle/rules/EGRESS_CALIBRATION.md，不再依赖分析时窗口覆盖。

**移动端进展（M034–M040，2026-10-16 → 10-19；详见 `mobile/DECISIONS.md`）**：

- **C1 派生值匹配**：`core/collector/derive.py`（md5/sha*/base64/urlencode/hex/gzip+b64 候选）
  — 值为派生形态时不再只认原值哈希。
- **C2 静态/动态覆盖差集**：`mobile/analyze/coverage_gap.py` — 只出缺口，不下结论。
- **明文链路补全**：M036 定位 Frida 17 API 已删 + 库懒加载 + `RTLD_LOCAL`（这才是旧的
  "明文读不到"真根因）、native/QUIC 接线；M037 扩到应用层加密（EVP/AES）与 TLS 元数据
  （SNI/keylog）+ 轮询兜底；M038 设备端 `tcpdump` + keylog + `tshark` 重组完整 HTTP 报文；
  M039 Flutter / 静态剥符号 BoringSSL 按代码形状定位（不靠符号）。入口见 `mobile/tools/pcap_http.py`。
- **风险量化**：`mobile/analyze/risk_score.py`（四维乘积 + 重复衰减 + 正交置信度，v1.3）
  + `calibrate_risk_bands.py`（阈值标定），模型说明见 `mobile/RISK_SCORE_MODEL.md`。
- **工程小项闭环**：M034 修 `conn_probe` 并发防撞、加 `run_regressions --mobile` 开关
  （归档文档 TWO_DEV_PLAN 的工程-6/工程-7 已完成）。
- **隐私工作台**：`mobile/workbench/`（工作流 / 运行时导入 / 合并布局，独立测试齐备）。
- **一键审计流水线**：`mobile/pipeline/`（17 阶段 + SSE 事件流，`stages.py`/`runner.py`/`server.py`；
  第 4 阶段 `surface` 是 L2 只读覆盖统计，见 `docs/MOBILE_OBSERVED_SURFACE_20261110.md`），
  前端是根 `frontend/app.html`。**端口分工**：`mobile/pipeline/server.py` 默认 **8771**、
  `mobile/workbench/server.py` 默认 **8772**，两套可同时起；旧文档里"都为 8771"已过时，
  见根 `README.md`「运行入口」。
- **《用户协议》接入（M040）**：`policy_discover.classify()` 按隐私词/协议词分流，
  `policy_fetch --from-apk` 落盘带 `document_kind`；`policy_library.load_app_agreements()`
  以 `AGR-*` 挂到 `app_agreements`，**不进主政策路径**（`--allow-legacy-policy` 下同样拦截）；
  AI 端 `policy_source()` 可解析 `AGR-`，协议不得把条款判 `met`。只有协议时主政策是
  `not_found` 而不是 `invalid`（新增 `NotAPolicy` 异常区分）。
- **跑批提速（M041）**：批处理按阶段切分——`batch_plan.py`（判定/续跑/复用）→
  `batch_static.py`（jadx **N 路并行**，默认 3，`--static-workers` 可退串行）→
  `batch_dynamic.py`（动态**必须单设备串行**：8888 单端口 / 全局 http_proxy / 单前台 /
  固定 pcap 路径，并发会串归因，见 M020 / D413）→ `batch_thirdparty.py`（CLI/汇总）。
  `--resume` 额外复用本批次 `_static/` 已完成产物（判据是 `static-manifest.json`）。
  实测 3 样本并行 7m42s、同批 `--resume` 3.1s。

B1 自有 AAOS 夹具补采已完成两名独立 subagent 复核与第三名仲裁，五档重放见
[vehicle/bench/WINDOW_CALIBRATION.md](vehicle/bench/WINDOW_CALIBRATION.md)。跨应用阈值仍待独立样本验证。
B2 VScanBench 最小版已复验两个自有 APK 的五档重放和一条独立应用补传业务，完整场景矩阵待补。
入口见 [车载基准](vehicle/bench/README.md#b2-vscanbench-最小基准)。

A5-1 protectionLevel 标定已覆盖车载规则库全部 180 条权限。Android 13/14/15/16 分别有 10/10/150/10 条，
各自保留定义包和构建指纹。Android 16 的证据来自 AAOS 36.1 r01 预览镜像。 [设备标定](vehicle/rules/device_calibration/README.md)

仍待完成的事项包括 F1 类加载归因（无 `hook_classload.js`）、G1 UI 探索覆盖率度量和 A4 分段自愈。

**拆分进度**（已提交、每步回归全绿）：
- ✅ 建 git 仓库 + 快照（ce1859d）
- ✅ `core/event_store.py`（audit_store 迁移）
- ✅ `core/collector/`（vehicle/traffic 流量采集内核 + `VSCAN_TAGGING` 平台打标表注入）
- ✅ `core/evidence/`（vehicle/analyze 代码行号/事件定位/dex 核对）
- ✅ `core/rules_contract.py` + 两份 `rules.manifest.json`（规则库分开的契约层）
- ✅ `core/frida_host/`（Frida 驱动 + 共享 bundle，斩断 mobile 对 vehicle/hooks 的引用）
- ✅ `core/static/`（静态分析内核，斩断 mobile 对 vehicle/workbench 的引用）
- ✅ `phase1–7` → `vehicle/*` 语义化改名（rules/targets/hooks/traffic/analyze/dashboard/workbench）
- ✅ `frontend/` 的 `--android-version` 从 manifest 读（不再写死 14/15）
  - 注：同时做过的「清除移动端 PDF 污染」（把三份移动端报告移出 `frontend/pdfs/`）
    **已于 2026-10-13 撤回**——前端才是日常查看报告的入口，只列车载不够用；
    三份已移回，见 `archive/MANIFEST.md` 第 2 条
- ✅ 修 `core/static/` 的 Windows MAX_PATH（拆分把 `phase7/` 改名为 `vehicle/workbench/`
  后，jadx 源码树最深路径由 ~253 涨到 262，越过 260 → 拖入 APK 直接分析失败）：
  新增 `core/static/winpath.py`（`\\?\` 扩展长度路径，覆盖 stat/read/rmtree 四个边界）
  + 离线回归 `test_jobs.LongPathTest`
- ✅ `apk/` 按平台分目录：`apk/mobile/`（手机样本）与 `apk/vehicle/`（车载样本），
  移动端取样本的默认目录跟着改；见 `apk/README.md`
- ✅ 修 `tools/device_acceptance.py` 的钩子路径（拆分漏改）：`hook_egress`/`ssl_pinning_bypass`
  已移到 `core/frida_host/dist/`，原路径导致 run.py `no such script` + **空等 40 秒**等 ARMED；
  `session-manifest` 的 `hook_bundles` 同时补上 core 目录（原先静默漏记这两个的哈希）。
  新增离线守卫 `tools/test_hook_bundles.py`（已并入 `run_regressions.py`）

**待办**：拆分主体已完成。
- ✅ `output/` 历史产物清理（2026-10-19，**历史事件**）——当时删除 208 项历史跑批目录与
  `latest-*.txt` 指针，`output/` 随后按轮次重新积累新产物。
  `output/` 在 `.gitignore` 中、git 不跟踪，且所有工具用 `mkdir(parents=True)` 自建目录；
  历史结论的引用改为"按需重跑"，见 `DELIVERY_INDEX.md`。**不要按本条去删 `output/` 里的现存内容。**

边界仍须保留：native TLS/未解析协议无明文能力；Gadget 需要自有源码与安装授权，
不支持无条件注入任意第三方 APK；统计归因遇歧义不关联；代码行号不证明违规语义。
工具不输出 policy_violation。缺失注册组织/位置不得编造，IP 位置只能标估计。

所有采集器显式使用同一 session，避免混合会话；失败运行保留，不能只凭文件存在宣称通过。
