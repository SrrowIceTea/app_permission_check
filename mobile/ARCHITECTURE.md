# V-Scanner 移动端（Mobile）整体架构

> 仅用于授权测试（已获授权的样本与设备）。
> 面向第九届浙江省大学生网络与信息安全竞赛企业命题（浙江省质量科学研究院）。
> 本文档基于 `mobile/CLAUDE.md`、`mobile/README.md`、`mobile/RISK_SCORE_MODEL.md` 与目录实际结构整理，状态截至 2026-10-24（含风险量化 RL 优化模块）。

---

## 1. 项目定位与边界

移动端 `mobile/` 是 V-Scanner 平台的**两条产品线之一**（另一条是车载 `vehicle/`）。二者共用同一份平台无关内核 `core/`，移动端**不改动**车载代码，只通过 import 复用。

| 维度 | 说明 |
| --- | --- |
| 目标 | 移动 App 隐私数据泄露的智能化检测与合规评估 |
| 入口 | 前端 `frontend/index.html` → 工作台 `frontend/app.html` → `mobile/pipeline/server.py`（端口 **8771**） |
| 兼容旧端 | `mobile/workbench/server.py`（端口 **8772**，旧隐私工作台，可并行） |
| 运行模式 | Root 模拟器（frida-server 直挂）/ 非 root Gadget 重签衍生包（两轮正控均已通过） |
| 离线优先 | 绝大多数能力无需设备即可回归（`run_mobile_checks.py` 31 项、`check_mobile_branch.py` 24 组） |

---

## 2. 分层架构总览

数据流自上而下：**样本 APK → 采集（静态+动态）→ 内核时序事件 → 关联 → 风险量化 → AI 研判 → PDF 报告**，由流水线编排串联，前端可视化呈现。

```
┌──────────────────────────────────────────────────────────────────────┐
│                         前端 / 可视化 (frontend/)                       │
│   index.html 落地页  |  app.html 一键审计工作台（6 工作区）              │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │ HTTP + SSE 事件流（唯一契约）
┌───────────────────────────────┴──────────────────────────────────────┐
│                    编排层  mobile/pipeline/  (端口 8771)                │
│   stages.py 16 阶段  ·  runner.py 执行器  ·  server.py SSE 服务         │
└───────┬───────────────┬───────────────┬───────────────┬──────────────┘
        │               │               │               │
┌───────▼──────┐ ┌──────▼───────┐ ┌─────▼──────┐ ┌──────▼───────┐
│ 规则层       │ │ 采集层        │ │ 分析层     │ │ 研判 / 报告  │
│ rules/       │ │ 静态 + 动态   │ │ analyze/   │ │ ai/ report/  │
│ rules_mobile │ │ hooks/traffic │ │ correlate  │ │ bundle→LLM→  │
│ .db          │ │ /tools(pcap)  │ │ risk_score │ │ validate→PDF │
└───────┬──────┘ └──────┬───────┘ └─────┬──────┘ └──────┬───────┘
        │               │               │               │
┌───────┴───────────────┴───────┬───────┴───────────────┘
│            内核层  core/  (平台无关，唯一一份)            │
│  event_store.py 时序事件库 · collector/ 流量采集 ·        │
│  evidence/codeloc.py 代码行号 · rules_contract.py 契约    │
└──────────────────────────────────────────────────────────┘
        │               │
┌───────▼───────────────▼──────────────────────────────────┐
│  被检对象：自有靶子 App（fixture-app/）+ 第三方开源样本     │
│  AAOS 模拟器 / Android 模拟器（userdebug，仅白名单包名）    │
└──────────────────────────────────────────────────────────┘
```

---

## 3. 七大模块职责

### 3.1 规则层 `rules/`
- **规则库**：`rules_mobile.db`（schema v2），当前 **223 条规则 / 8 种类型 / 58 个 android.jar 实证 API / 28 类数据 / 39 类 App 必要信息 / 16 条政策条款**。
- **签名抽取**：`extract_android_apis.py` 用 `javap -s` 从本机 `android.jar` 抽取 `(类名, 方法, JVM 描述符)` 三元组，抽不到的落 `build/api_missing.json` 作 TODO——**绝不手写签名**。
- **构建器**：`build_mobile_rules.py`（异常即清理半成品 DB）、`rule_gen.py`、`mobile_rules_*.py`。
- **法规原文**：`regulations/`（认定方法 / 必要信息规定 / 个保法 / GB-T 35273，带条款号与 URL）。
- **rule_id 前缀 `MOB-`** 作为权威判别符，与车载 `VSC-` 物理隔离、通过 `rules_contract.py` 按平台加载扩展表。

### 3.2 采集层
**静态剖析（无需设备）**
- `tools/batch_static.py`：`jadx` **N 路并行**（默认 3，`--static-workers` 可退串行），产出反编译 Java 与 manifest。
- 政策抽取：`policy/policy_discover.py` 按「隐私词 / 协议词」分流《用户协议》进 `app_agreements`（M040），不冒充主政策。

**动态插桩（Frida，随 `hook_all` 单 agent 挂载）** `hooks/`
- Java 层：敏感 API 读取 `hook_privacy.js`、同意时序 `hook_consent.js`、出站 `hook_egress_tp.js`、TLS 校验收宽 `ssl_pinning_tp.js` + `tls_bypasses_tp.js`。
- Native 层（对证书 pinning 免疫）：`hook_native_ssl.js`（SSL_read/SSL_write 明文）、`hook_native_crypto.js`（EVP/AES 应用层加密明文）、`hook_tls_meta.js`（SNI + keylog）、`hook_flutter_ssl.js`（剥符号 BoringSSL 按代码形状绕过校验）。
- 构建：`gen_targets.py` 生成监视表 + `node build.mjs` 打包（直接复用 vehicle/hooks 已装好的 `node_modules`，绕过本机无 make 的原生编译）。

**流量镜像** `traffic/` + `tools/`
- `addon_mobile.py` 复用 `core/collector/addon.py`，注入 `VSCAN_TAGGING` 移动打标表（含值哈希令牌，UTF-8 + sha256 前 16 位，与钩子侧口径一致）。
- 透明代理 `transparent.py`（算启动参数 + 装系统 CA）；强制代理实测需 `-http-proxy 127.0.0.1` 且先于模拟器存在。
- **完整报文链路（M038）**：`pcap_capture.py`（设备端 `tcpdump`，仅 `su 0`）+ `pcap_http.py`（keylog 喂 `tshark` 解密重组，TCP/TLS/gzip 全由 tshark 完成）。
- **QUIC 压制（M041）**：`am start` 前 `iptables -I OUTPUT -p udp --dport 443 -j DROP` 逼回退 TCP。

### 3.3 内核层 `core/`（平台无关，与车载共用）
- `event_store.py`：SQLite 单机时序事件库（audit_store 迁移而来）。
- `collector/`：流量采集内核 + `VSCAN_TAGGING` 平台打标表注入。
- `evidence/codeloc.py`：代码行号链（`read_event` / `read_then_egress` 同名种类沿用）。
- `rules_contract.py`：规则库契约，按 `MOB-`/`VSC-` 前缀分平台加载。

### 3.4 分析层 `analyze/`
- **关联引擎** `correlate_mobile.py`：八种移动谓词，复用 `core/evidence/codeloc.py` 行号链，每条结论带 `rule_id` + 依据来源（可追溯）。
- **风险量化** `risk_score.py`（v1.3，38 项回归）：五维乘积 `数据敏感度 × 危害路径 × 证据强度 × 必要性 × 值级加成` + 重复衰减 `1/k` + 正交置信度（**不与分数相乘**）。模型对齐 Peng'12 单调性 / Zhu'21 异常度 / PrivacyGrade / CNKI'26 自适应阈值；`calibrate_risk_bands.py` 一键标定。权重表拆在 `risk_weights.py`，阈值/置信度标定在 `risk_calibrate.py`。
- **风险量化 RL 优化**（旁路优化器，不改动核心评分）：`risk_rl.py` 用**进化策略（ES）**以「人工风险排序 vs 模型分数排序」的 Spearman 秩相关为奖励信号，联合微调权重与档位阈值；输出严格落在 `hint` / `review_priority` / `needs_human_review` 三槽（M046），**绝不**改写 `conclusion_level` / `severity`。配套 `gen_rl_demo.py`（合成演示标注）、`build_real_scenarios.py`（静态样本 → RL 场景，60 App / 1004 finding）、`prelabel_expert.py`（专家规则候选预标注，供人工校正为 gold 标准）。方法论文档见 `RISK_SCORE_RL.md`，真实样本落地见 `RISK_SCORE_RL_REAL.md`。
- **覆盖差集** `coverage_gap.py`：只出缺口不下结论。
- 派生值匹配 `core/collector/derive.py`（md5/sha*/base64/urlencode/hex/gzip+b64），值为派生形态时不再只认原值哈希。

### 3.5 研判层 `ai/`
- **证据封装** `evidence_bundle.py`：打包观测 + 顺带做 APK 加固特征探测，命中即写进 gaps（结论受限）。
- **三阶段提示词 + LLM 客户端** `llm_client.py` + `prompts/`。
- **输出校验** `review_gates.py` / `validate.py`：编造校验、契约校验、引用校验（AI 不把协议条款判 `met`）。
- 同源决策见 `DECISIONS.md` M040、模型说明见 `RISK_SCORE_MODEL.md`。

### 3.6 报告层 `report/`
- `report_mobile.py`：PDF（十章 + 三附录），含工具结论 + AI 研判 + 校验问题清单；中文字体链路照抄车载（SimHei → DengXian → 雅黑 → STSong）。

### 3.7 编排层 `pipeline/`（一键审计）
- `stages.py`：16 阶段定义（前端时间线唯一契约 `{"ts","stage","status","message"}`）。
- `runner.py` 执行器、`server.py` HTTP+SSE（端口 8771）、`history.py` 历史任务、`formal_runner.py` 真实 AI 硬门控。
- 前端对应 `frontend/app.html`；旧 `workbench/server.py` 端口 8772 保留兼容。

**16 阶段顺序**：`prepare 环境准备 → boot 模拟器就绪 → static 静态剖析 → frida_server → network → install 安装样本 → launch 启动应用 → conn_probe 连接采样 → mitm 流量镜像 → hooks 插桩 → explore 交互驱动 → death_probe 存活取证 → correlate 关联分析 → bundle 证据封装 → ai_review AI 研判 → report 报告生成`。

---

## 4. 复用关系（不复制、不漂移）

| 复用对象 | 方式 |
| --- | --- |
| `core/collector/addon.py`、`attribution.py`、`flow_entry.py`、`payloads.py` | 直接 import，`addon_mobile.py` 注入移动打标表 |
| `core/frida_host/run.py`、`bundle_config.py` + `dist/`（hook_egress / ssl_pinning_bypass） | 原样使用，注入器替换 `__VSCAN_SESSION_PACKAGES__` |
| `core/evidence/codeloc.py` | 直接 import，evidence_kind 同名种类 |
| reportlab 中文字体方案 | 照抄 `vehicle/analyze/report.py` |
| 输出约定 | `output/mobile-regression-*/verification.json` + `latest-mobile.txt` |

---

## 5. 能力边界与已知局限（如实呈现）

- **加固壳**：`apk_packer_probe.py` 仅标注「结论受限」，不脱壳。
- **明文来源六条**：mitmproxy 解密 / Java TLS 校验收宽 / native TLS / native 应用层加密 / TLS 元数据(SNI+keylog) / pcap+tshark。覆盖导出符号的模块；符号被剥/内联的静态 BoringSSL、Flutter 仅到「绕过校验」为止；自研算法（XOR 等）仍在覆盖外。
- **尚未校准/未完成**：时间窗 30000ms 仍为声明值（`WINDOW_CALIBRATION.md` 待建）；权限 `protectionLevel` 40 条未断言；AI 幻觉率无量化数据；写入类 API 与覆写型服务（无障碍/通知监听）未覆盖。
- **样本死在窗口内** 如实记录（`app-death.json`，`alive_at_end` 三态），不掩盖。

---

## 6. 关键设计原则（源自全局约束）

1. **仅授权测试**：抓包/Hook 只监控白名单包名。
2. **绝不编造签名**：不确定的 android.car / API 签名 → TODO + 占位常量 + 探测脚本。
3. **观察不改写**：观察阶段只记录不拦截（`ssl_pinning_bypass.js` 是唯一例外，且仅白名单、仅为审计流量）。
4. **可运行优先于完整**：每阶段交付物先跑通再谈完整。
5. **判定可追溯**：每条违规带 `rule_id` + 依据来源。
6. **失败可诊断**：Hook 脚本 try/catch + 日志落盘，区分「没读到数据」与「脚本崩了」。
7. **单文件 ≤300 行**，超了按职责拆分并回归验证。

---

## 7. 怎么跑（最小验证路径）

```bash
PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"   # 原开发机是 C:/Users/毛宇淇/...

# 1) 规则库（android.jar 抽签名，source_verified 唯一来源）
cd mobile/rules && "$PY" extract_android_apis.py && "$PY" build_mobile_rules.py
cd ../hooks && "$PY" gen_targets.py && node build.mjs

# 2) 离线回归（全部）
"$PY" mobile/tools/run_mobile_checks.py

# 3) 端到端干跑（合成会话）
"$PY" mobile/tools/make_demo_session.py --out /tmp/demo
"$PY" mobile/analyze/correlate_mobile.py --session /tmp/demo --package com.vscanner.privacydemo \
      --permissions /tmp/demo/requested-permissions.txt --app-category map_navigation \
      --out /tmp/demo/findings.jsonl --summary /tmp/demo/summary.json
"$PY" mobile/ai/evidence_bundle.py --session /tmp/demo --findings /tmp/demo/findings.jsonl \
      --package com.vscanner.privacydemo --app-category map_navigation --out /tmp/demo/bundle.json

# 4) AI 研判（先 dry-run 审阅，再填 key 真跑）
"$PY" mobile/ai/ai_review.py --bundle /tmp/demo/bundle.json --out-dir /tmp/demo/ai --dry-run

# 5) 报告
"$PY" mobile/report/report_mobile.py --bundle /tmp/demo/bundle.json \
      --ai-out-dir /tmp/demo/ai --out /tmp/demo/report.pdf
```

> 启动完整检测见 `mobile/README.md`（准备 SDK/JDK/JADX/Frida/mitmproxy/reportlab，再起 `pipeline/server.py --port 8771` 与 `frontend` 静态服务）。
