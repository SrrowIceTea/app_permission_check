# V-Scanner 优化评估与实施路线（2026-10-20）

> 本文基于两个来源：① `ds60-sup-1019` 60 样本跑批的前 19 个样本实测数据；
> ② 对 `mobile/RESEARCH_EXTERNAL_WORK_20261019.md`（外部调研）的核验与可行性裁决。
> 硬约束不变：静态封顶 `candidate`、不产 `policy_violation`、观察不改写、单文件 ≤300 行、仅授权测试。

---

## 一、现状体检：主链在真实样本上几乎不产出

`ds60-sup-1019`（60 样本，已完成 19）中间态体检结果：

| 指标 | 实测 | 判读 |
|---|---|---|
| 过检（verification.passed） | 19/19 | 判据偏松，不代表有证据 |
| 运行时敏感读取 >0 | 4/19 | 触发覆盖不足 |
| `conns.jsonl` >0（连接归因） | 1/19 | 归因链路基本不工作 |
| `flows` >0 | 1/19 | 同上 |
| 时间归因（`app_process_hook`） | **0/19** | 主归因路径从未命中 |
| 值哈希链路命中（核心差异化） | **0/19** | 一次都没触发 |
| `keys.log` 非空（TLS keylog） | **0/19** | keylog 旁路未产出任何密钥 |
| 未解密 TLS 帧 >0 | 19/19 | 解密旁路等于没启用 |
| `policy.available` | 0/19（`store_missing`） | 合规维度不可判定 |
| `consent_state` | 19/19 `unknown` | 同意类规则不适用≠通过 |
| 单样本事件总量 | 21–28 条 / 100s | 窗口内 App 基本没被触发 |
| 插桩崩溃 | 0/19 | A1 分段续采缓解有效（根因未除） |

**结论**：项目最核心的卖点「读取值哈希 → 网络流令牌 → 值级证据链」在测试集上 **0 次命中**。
不是报告写得好不好的问题，是**上游没有数据**。

---

## 二、优化优先级（重排后）

调研文档的 P0 全是报告/提示词层，默认「主链是好的」。实测证明主链是空的。
在观测为 0 的前提下先把报告做规范，只会得到一份更规范的空报告。故重排如下：

### P0-1（最高）：恢复动态观测有效性 —— 调研文档完全没覆盖的盲区

| 子项 | 现象 | 动作 | 落点 |
|---|---|---|---|
| ① UI 触发覆盖 | 100s 窗口只有 21–28 条事件；04-Pulse 曾因找不到候选点击点耗满 36 分钟 | 敏感引用聚类 → Activity/控件触发优先级排序 | `tools/thirdparty_ui_flow.py`（已有，需增强，≤300 行；不足则拆 `ui_target_rank.py`） |
| ② 连接归因为 0 | `conns.jsonl` 18/19 为空 | 排查 `hook_egress_tp.js` 的 `BlockGuardOs.connect` 在 API35 上是否命中；补 `libjavacrypto.so` 之外的 native connect | `hooks/hook_egress_tp.js`、`analyze/evaluation_mobile.py` |
| ③ keylog = 0 | 钩子已 ARMED（`SSL_CTX_new@libjavacrypto.so+keylog`）但 `keys.log` 0 字节 | 查 `KEYLOG_INSTALLED` / `KEYLOG_UNAVAILABLE` 事件是否落盘；确认 `maxKeylog` 配置与写入路径 | `hooks/hook_tls_meta.js`、`runtime.js` 的写入分支 |
| ④ 时间归因 0 | 唯一 1 条是 `single_package_fallback` | 归因窗口与 egress 事件时间戳对齐校验（egress 事件 0 条是根因，先修 ②） | `analyze/evaluation_mobile.py` |

> ② 是 ③④ 的前置：**egress 事件 0/19 是整条链的第一断点**，必须先修。

### P0-2：政策库重建（合规维度当前不可判定）

政策正文库 `output/local-policy-library-20261018` 已清理且从未入 git，`mobile/policy/` 只有来源清单。
结果：60 样本全批 `store_missing`，产品名里「合规」的一半是空的。

- 按 `mobile/policy/README.local.md` 重建正文库，并**纳入版本管理或固化到 output 外目录**；
- `policy_library` 增加「库缺失」硬告警（当前只是静默降级）；
- 验收：至少一个样本 `policy.available=true` 且一致性章有实质结论。

### P0-3：调研文档中确实低风险可并行做的（纯离线，不动设备）

即 B1 / B2 / B3 / B4 / B8 / B9-前半。详见 §三。

### P1：依赖 P0-1 产出后才能见效

B5（TPL 矩阵）、B6（已提到 P0-1①）、B7（denied 后仍外发）、B10（复测对比）、B11（误报复核清单）。

### P2：工程债与文档治理（不影响结论正确性，但影响交付与维护）

见 §四。

---

## 三、对调研文档（`RESEARCH_EXTERNAL_WORK_20261019.md`）的裁决

### 3.1 可信度：高，可放心引用

抽检了整份文档最关键的两条锚点，**逐字对上**：

- **GNChecker**（ASE 2024）：DOI `10.1145/3691620.3695528`、作者 8 人、页码 1595–1606、
  「1,134 个真实 App 中 379 个检出 1,410 条」——与 ACM 官方记录、IEEE Xplore、Mendeley 三处一致。
- **PIChecker**（FORGE 2026）：DOI `10.1145/3691620.3695528`→`10.1145/3793655.3793721`、页码 160–171、
  「147 个 App / 17 个无政策 / 130 中 ~11% 未提、>64% 描述不准 / accuracy 55%→90% /
  静态 P 94.12% / 文本 P 96.96%」——与 ACM 全文摘要逐条一致。

加分项：文档自带四档核实状态标注与 §11.3「未核实清单」，并主动指出
AndroByte「摘要 89% Fβ vs 正文 91.70%（β=0.5）」的口径漂移——这是诚实性很强的信号，
与本项目「缺失写 gap、不硬判」的工程文化一致。

### 3.2 可行性：全部可落地，但优先级需重排

| 项 | 调研定级 | 裁决 | 理由 |
|---|---|---|---|
| B1 五分类 OD/VD | P0 | **同意 P0**，但需改设计（见 3.3） | 纯提示词+枚举，无风险 |
| B2 卡片五要素断言 | P0 | 同意 | 渲染+断言 |
| B3 ML 位置约束 | P0 | 同意 | 文档级，防未来误用 |
| B4 GDPR-Bench 引用 | P0 | 同意 | 17.38% 是「不产 policy_violation」的强背书 |
| B8 版本清单+哈希附录 | P0 | 同意 | 复现性 |
| B9-前半 SARIF | P0/P1 | 同意 | 纯离线 |
| **B6 隐私定向 UI 探索** | P1 | **上提到 P0-1** | 它就是 4/19 读取率的直接解，是主链瓶颈 |
| B5 TPL 矩阵 | P1 | **降级，排在归因修复之后** | 归因现在 0 命中，矩阵会全 `unknown` |
| B7 denied 后外发 | P1 | 同意，但依赖先观测到 denied 事件 | 已确认 `evaluation_mobile.py` 中确无 `denied` 语义，缺口真实 |
| B10/B11 | P1 | 同意 | 需两轮产物 / 真跑 |
| B12–B15 | P2 | 同意 | 研究级 |

### 3.3 一个必须提醒的设计风险（B1）

现有 `stage2_consistency.md` 的 `assessment` 是**单枚举**，把两个正交维度混排：
披露状态轴（`undisclosed_collection` / `consistent`）+ 行为风险轴（`over_collection` / `plaintext_transmission`），
靠「从上到下取第一条命中」+ `also_applicable` 兜底。

GNChecker 的 OD/VD 属于**披露状态轴**。若直接把 `vague` / `omitted` / `incorrect` 塞进同一个枚举，
优先级语义会更混乱（「模糊声明」和「明文传输」谁排前面？）。

**建议改双字段**：

```json
"disclosure_status": "clear | vague | omitted | incorrect | ambiguous | not_applicable",
"behavior_risk": ["over_collection", "plaintext_transmission", "read_before_consent_unknown"]
```

`validate.py` 分别枚举校验；报告章按两列渲染。这比继续堆单枚举干净，也更容易与
PIChecker 的「TPL 行为—政策声明矩阵」对接（矩阵的行=数据类别，列=披露状态×收集方）。

---

## 四、工程债（P2，不影响结论正确性但影响交付）

| 项 | 现状 | 建议 |
|---|---|---|
| 违反「单文件 ≤300 行」 | 14 个 py 超限：`thirdparty_env.py` 1196、`device_run_thirdparty.py` 1018、`risk_score.py` 618、`pcap_http.py` 540、`device_run.py` 478、`test_risk_score.py` 472、`conn_probe.py` 406、`report_sections.py` 384、`policy_fetch.py` 371、`test_app_death.py` 337、`correlate_mobile.py` 336、`pipeline/runner.py` 305、`test_hooks_parity.py` 303、`fixture_selftest.py` 301 | 按职责拆分（项目已有先例），拆后跑 `run_mobile_checks.py` 回归 |
| 双入口冗余 | `mobile/workbench`（旧，8772）+ `mobile/pipeline`（新，8771）并存 | README 已说明；建议在跑批稳定后把 workbench 标为 deprecated |
| 工作区脏 | 24 个已改 + 6 个未跟踪未提交（`coverage_window.py`、`test_consent_observation.py` 等新能力在脏区） | 尽快提交，否则换机即丢 |
| 大文件滞留 | `mobile/tools.zip` 58.7MB（未跟踪） | 移出工作区或加入 `.gitignore` |
| 文档膨胀 | `DECISIONS.md` 84KB、`DEV_FIX_REPORT.md` 74KB、`RESEARCH_*.md` 77KB+79KB | 考虑按主题拆分子文档 |
| `DEVICE_WRITE_DENIED` | `runtime.js:42` 显示所有钩子事件**设备侧落盘全部失败**（靠 host 接收兜住） | 确认设备写入路径权限；若长期不可用应在 `verification` 中显式标注，避免误以为证据已双份留存 |

---

## 五、建议执行顺序

1. **先修 `conns.jsonl` = 0（egress 钩子不命中）** —— 这是整条链的第一断点，修完 ③④ 可能自愈。
2. **keylog 旁路修复** —— 解「未解密 TLS 帧 19/19」。
3. **UI 触发目标排序（B6 上提）** —— 解「4/19 读取率」。
4. **政策库重建** —— 解「合规维度不可判定」。
5. **并行做 B1/B2/B3/B4/B8/B9-前半**（纯离线，不依赖设备，不影响上面四条）。
6. **归因稳定后再做 B5 TPL 矩阵**。
7. 最后清工程债（拆文件、提交工作区）。

> 每步都按项目惯例配离线单测并记入 `DECISIONS.md`（新 M0xx）；
> 结论口径必须带降级注记（「无网络流证据≠没有外发」「未命中≠未声明」）。
