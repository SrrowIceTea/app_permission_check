# Mobile — 移动 App 隐私数据泄露的智能化检测与合规评估

**仅用于授权测试（已获授权的样本与设备）。**
面向第九届浙江省大学生网络与信息安全竞赛企业命题（浙江省质量科学研究院）。

车载 phase1–7 是已交付成果，本目录**不改动它**；通用部件以 import 复用（见下表）。
决策见 `DECISIONS.md`（M001– ），全局约束沿用根 `CLAUDE.md`。

## 目录

| 路径 | 作用 |
| --- | --- |
| `rules/` | **规则库**：schema v2 + 法规依据 + android.jar 签名抽取 + 构建器 |
| `rules/regulations/` | 法规原文（认定方法 / 必要信息规定 / 个保法 / GB-T 35273），带条款号与 URL |
| `hooks/` | Frida 钩子：敏感 API 读取 + 同意时序。监视表由规则库生成，不手抄 |
| `traffic/` | mitmproxy 移动适配：打标表 + 注入壳（复用 phase4/addon.py） |
| `policy/` | 隐私政策获取 / 正文抽取 / 规则化检查 |
| `analyze/` | 关联引擎与八种移动谓词（复用 core/evidence/codeloc.py 的行号链） |
| `ai/` | **证据打包 + 三阶段提示词 + LLM 客户端 + 输出校验** |
| `report/` | PDF 报告（工具结论 + AI 研判 + 校验问题清单） |
| `tools/` | 离线回归总入口、合成演示会话生成器 |
| `fixture-app/` | 自有靶子 App（隐私演示），用于端到端验证 |

## 怎么跑（离线优先，不需要设备）

```bash
PY="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"

# 1) 规则库（从本机 android.jar 抽签名，这是 source_verified 的唯一来源）
cd mobile/rules
"$PY" extract_android_apis.py                      # → build/api_facts.jsonl
"$PY" extract_android_apis.py --seed seed/consent_targets.json --out-prefix consent_
"$PY" build_mobile_rules.py                        # → rules_mobile.db
cd ../hooks && "$PY" gen_targets.py && node build.mjs   # 生成监视表 + 打包钩子

# 2) 离线回归（全部）
"$PY" mobile/tools/run_mobile_checks.py            # → output/mobile-regression-*/

# 3) 端到端干跑（合成会话，验证字段契约）
"$PY" mobile/tools/make_demo_session.py --out /tmp/demo
"$PY" mobile/analyze/correlate_mobile.py --session /tmp/demo --package com.vscanner.privacydemo \
      --permissions /tmp/demo/requested-permissions.txt --app-category map_navigation \
      --out /tmp/demo/findings.jsonl --summary /tmp/demo/summary.json
"$PY" mobile/ai/evidence_bundle.py --session /tmp/demo --findings /tmp/demo/findings.jsonl \
      --package com.vscanner.privacydemo --app-category map_navigation --out /tmp/demo/bundle.json

# 4) AI 研判（先 dry-run 审阅，再填 key 真跑）
"$PY" mobile/ai/ai_review.py --bundle /tmp/demo/bundle.json --out-dir /tmp/demo/ai --dry-run
cp mobile/ai/config.example.json mobile/ai/config.local.json   # ← 在这里填 api_key
"$PY" mobile/ai/ai_review.py --bundle /tmp/demo/bundle.json --out-dir /tmp/demo/ai

# 5) 报告
"$PY" mobile/report/report_mobile.py --bundle /tmp/demo/bundle.json \
      --ai-out-dir /tmp/demo/ai --out /tmp/demo/report.pdf
```

## 复用关系（不复制、不漂移）

| 复用对象 | 方式 |
| --- | --- |
| `phase4/addon.py`、`attribution.py`、`flow_entry.py`、`payloads.py` | 直接 import；`traffic/addon_mobile.py` 只把 `sys.modules["tagging"]` 换成移动版 |
| `phase3/hook_egress.js`、`phase3/run.py`、`bundle_config.py` | 原样使用（Socket.connect 与车载无关；run.py 的注入器也替换 `__VSCAN_SESSION_PACKAGES__`） |
| `core/evidence/codeloc.py` | 直接 import，`evidence_kind` 沿用同名种类（`read_event` / `read_then_egress`） |
| reportlab 中文字体方案 | 照抄 `phase5/report.py` 的候选链（SimHei → DengXian → 雅黑 → STSong） |
| 输出约定 | `output/mobile-regression-*/verification.json` + `latest-mobile.txt`，与车载一致 |

## 本目录的坑（全部实测）

- **签名绝不手写**：所有 API 签名由 `javap -s` 从本机 `android.jar` 抽取。
  抽不到的落 `build/api_missing.json` 作为探测 TODO，**不编造**。
  （照抄 phase7 的 `(class_name, method_name, jvm_descriptor)` 三元组口径。）
- **npm 装依赖必须跳过原生编译**：`frida-compile` 依赖 `frida` 包的原生绑定，
  本机没有 make，`npm install` 会失败。绕过办法是**直接复用 phase3 已装好的
  `node_modules`**（同一套依赖，绑定已构建）。
- **`/tmp` 在 Git Bash 与 Python 眼里不是同一个目录**：Bash 会把**实参**里的
  POSIX 路径转成 Windows 路径，但脚本正文里的字符串不转——`python -c` 里的
  `/tmp/x` 会落到 `C:\tmp\x`。写脚本一律用真实路径。
- **形态标签不能定性**：15 位数字分不出 IMEI 与 IMSI，`digit15_shape` 的
  data_type 是 `None`（故意的）。只凭形态**不得**产出任何数据类别结论；
  要定性必须有值哈希匹配。这条是设计，不是缺陷。
- **同意时序缺失时「同意前收集」不可判定**：`consent.jsonl` 为空时该谓词
  不产出结论（进 gaps），不把"没采到"当成"没同意"。
- **部分授权必须逐条用**：`PERM_RESULT` 里 granted/denied 是逐权限的；
  被拒的权限不算同意，否则判定会反过来。
- **值哈希口径两侧必须一致**：钩子（Java MessageDigest）与打标（Python hashlib）
  都是 `UTF-8 + sha256 前 16 位十六进制`。变了要同步改两边，否则值级匹配静默失效。
- **构建失败不得留下半成品 DB**：`build_mobile_rules.py` 任何异常都清理输出——
  半成品与成功产物在文件系统上长得一模一样。

## 状态（2026-10-03）

规则库（126 条规则 / 8 种类型 / 33 个 android.jar 实证 API / 39 类必要信息 /
16 条政策条款）、移动钩子（敏感读取 + 同意时序）、流量打标（含值哈希令牌）、
隐私政策三件套（获取 / 抽取 / 检查）、关联引擎（八种谓词）、AI 三阶段研判
（含编造校验）、PDF 报告（十章 + 三附录）、自有靶子 App 与设备端端到端
均已实现。离线回归 16 项全过（`tools/run_mobile_checks.py`）。

**设备端实测（2026-10-03，AAOS 模拟器 emulator-5554 / user 10）**：
一轮完整检测得到 26 条结论、0 缺口、七种规则全部命中——
7 条「同意前读取」、1 条值级匹配的 `data_egress`（correlated，3 对）、
3 条「政策未声明即收集」、6 条超范围收集、7 条敏感读取、1 条明文传输、1 条第三方外发。
采集侧观察到 8 类数据（其中 IMEI 因权限未授予被拒，如实记为 denied 而非收集）。
详见 `output/mobile-device-20261003-041553/`。

**未完成**：
- 时间窗 30000ms 是**声明值，尚未由移动夹具校准**（`WINDOW_CALIBRATION.md` 待建）。
  E2E 已能量出真实的"读取→外发"间隔分布，下一步据此校准。
- AI 阶段未用真实 key 跑过（提示词渲染与校验逻辑已测；真实调用的效果待用户填 key 后验证）。

**能力边界**：native 层 / 加固壳 / QUIC / 自定义加密不在覆盖内；
剪贴板等无需运行时权限的 API，"无同意事件"需要结合 API 判断；
政策关键词预扫是正则代理指标，未命中不等于未声明；
静态扫描看不到被 D8 折叠掉的版本分支（M013）。
