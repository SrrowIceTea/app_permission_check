# V-Scanner Mobile — 移动 App 隐私数据泄露的智能化检测与合规评估

> **仅用于授权测试（已获授权的样本与设备）。**
> 对应第九届浙江省大学生网络与信息安全竞赛企业命题（浙江省质量科学研究院）。

## 它做什么

把一次检测拆成五段，每段都留下可复核的原始证据：

```
规则库(法规驱动) → 采集(钩子+代理) → 隐私政策 → 关联判定 → AI 研判 → PDF 报告
```

| 赛题要求 | 本工具对应实现 |
| --- | --- |
| 静态分析：识别敏感数据的收集 | APK 清单权限 + dex 代码引用（复用 vehicle/workbench 事实抽取） |
| 动态分析：识别存储与传输行为 | Frida 钩子观测 58 条敏感 API 签名（覆盖 28 类数据）读取 + 同意时序 |
| 通信流量：明文/未加密传输 | mitmproxy 抓流 + 设备端 `tcpdump` + keylog + `tshark` 重组完整 HTTP 报文 + 形态打标 + 值哈希/派生值匹配 |
| 风险量化 | 四维乘积评分 v1.3（重复衰减 + 正交置信度），见 `RISK_SCORE_MODEL.md` |
| 基于大模型，结合隐私政策与行为研判 | 三阶段提示词 + 证据包 + 输出校验 |

> **2026-10-16 → 10-19 的新增能力**（细节见 `DECISIONS.md` M034–M040）：
>
> - **完整 HTTP 报文**：hook 只能拿到 `SSL_read/SSL_write` 的**分片**，自己拼要重写
>   HPACK/chunked/gzip。改为 `tools/pcap_capture.py`（设备端 tcpdump）+ `tools/pcap_http.py`
>   （抽 keylog → `tshark -o tls.keylog_file:` → JSONL），抓包须在 `am start` 之前起。
> - **明文范围扩围**：`hook_native_crypto.js`（EVP/AES 应用层加密）+ `hook_tls_meta.js`
>   （SNI + 主动挂 keylog 回调）+ `hook_flutter_ssl.js`（Flutter 剥符号 BoringSSL 按代码形状定位）。
> - **值证据**：派生值候选（md5/sha*/base64/urlencode/hex/gzip+b64，`core/collector/derive.py`）
>   与静态/动态覆盖差集（`analyze/coverage_gap.py`）。
> - **风险量化**：`analyze/risk_score.py` + `calibrate_risk_bands.py`，模型与阈值见
>   `RISK_SCORE_MODEL.md`；报告与答辩的量化口径以它为准。
> - **政策分册（M040）**：`policy/policy_discover.py` 按隐私词/协议词把文档分成
>   `privacy` / `agreement`；《用户协议》入库后挂在 `app_agreements`（ID `AGR-*`），
>   **不参与主政策披露比对**，只有协议时主政策记 `not_found`。见 `policy/README.local.md`。
> - **一键审计**：`pipeline/`（16 阶段 + SSE），前端在根 `frontend/`，与
>   `workbench/` 是两套入口且默认端口相同（8771），起法见根 `README.md`。
> - **工程**：`run_regressions.py --mobile`（移动侧失败计入根回归失败）、`conn_probe` 并发防撞。

## 快速开始（不需要设备、不需要网络、不需要 API key）

```bash
PY="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"

# 1) 构建规则库（从本机 android.jar 抽签名）
cd mobile/rules
"$PY" extract_android_apis.py
"$PY" extract_android_apis.py --seed seed/consent_targets.json --out-prefix consent_
"$PY" build_mobile_rules.py
cd ../hooks && "$PY" gen_targets.py && node build.mjs && cd ..

# 2) 全部离线回归 + 端到端干跑
"$PY" mobile/tools/run_mobile_checks.py     # 看 output/mobile-regression-*/verification.json
```

## 形态与行为分离

- **形态提示**：报文里出现设备标识符、位置坐标、敏感字段名等，只作为线索，不构成判定。
- **行为判定**：以读取事件、同意事件、传输事实为基础，形成可回溯的结论。
- **规则库**：只收录已核对来源的 API 签名与法规条款，未核对项标注为待确认。

## 填写 AI API key（这一步由你来做）

```bash
cp mobile/ai/config.example.json mobile/ai/config.local.json
# 编辑 config.local.json：base_url / api_key / model
```

已内置多家供应商的 base_url 预设（DeepSeek / 通义千问 / 智谱 / Kimi / OpenAI）。
`config.local.json` 不要提交到仓库。

**没有 key 也能用**：`--dry-run` 只渲染提示词不联网，可以先审阅「到底要发什么出去」。

## 在设备上跑一轮（自有夹具）

```bash
# 前提：模拟器/真机已连接，首次需确认 frida-server 在位（脚本会自动以 root 拉起）
"$PY" mobile/tools/device_run.py --user 10            # 全流程（有 key 时会跑 AI）
"$PY" mobile/tools/device_run.py --user 10 --skip-ai  # 只到工具结论与报告
```

产物在 `output/mobile-device-<时间戳>/`：

```
session/          原始采集（reads / consent / flows / egress / tls.jsonl）
out/findings.jsonl  + summary.json     工具规则结论
out/bundle.json    证据包（送 AI 的就是它，已脱敏）
out/ai/            AI 三阶段输出 + 提示词全文 + 调用记录 + 校验结果
out/mobile-report.pdf                  最终报告
verification.json  本轮判据（**看这个判断成败，不要只看目录存在**）
```

## 报告结构（十章）

检测概览 · 判定依据 · 证据摘要 · **工具规则结论** · **AI 合规研判** ·
政策—行为一致性对照 · 整改建议 · **AI 输出校验结果** · 方法与局限 · 附录（证据索引/缺口/提示词）

## 三条必须知道的能力边界

1. **工具不产出「违规成立」**。结论等级由规则封顶（候选/已观测/已关联），
   是否违规需人工复核。AI 章节同样只给「涉嫌」+ 置信度 + 需人工复核。
2. **「未采集到」不等于「未发生」**。报告里每一处缺失都写在缺口清单里，
   AI 提示词强制要求在这种情况下输出「证据不足」而不是猜测。
3. **形态不等于事实**。报文里出现 15 位数字不等于就是 IMEI（IMEI 与 IMSI 都是 15 位）；
   只有值哈希匹配才构成「确实传输了该值」。

## 与车载版的关系

车载 vehicle/ 是独立交付物，本目录不改动它；
代理归因、代码行号、dex 解析、报告字体方案以 import 复用，不复制。
详见 [CLAUDE.md](CLAUDE.md) 的复用关系表，踩坑记录见 [DECISIONS.md](DECISIONS.md)。
