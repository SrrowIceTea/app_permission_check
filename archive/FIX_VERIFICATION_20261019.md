# 修复复核记录（2026-10-19 晚）

> 仅用于授权测试。本文是对"三项修复是否真的完成"的独立复核结论，
> 由 4 个独立 subagent（政策 / 流量 / 同意 / 端到端复跑）交叉验证后汇总。
> 结论分两栏：**代码层**与**交付物层**——两者不能互相替代。

## 一、总判定

| 主题 | 代码层 | 交付物层 | 一句话 |
|---|---|---|---|
| 本地政策库 | ⚠️ 部分 | ⚠️ 不可判 | 回退链路已通、状态可区分；但库正文不存在，APK 内政策的绑定分支只在代码上补齐、未上设备验证 |
| 同意时刻 | ✅ 通过 | ✅ 通过 | 四态区分正确（observed / requested_only / not_observed / no_consent_channel），6 条回归用例钉住 |
| 流量归因 | ✅ 通过 | ✅ 重新生成并通过断言 | CA 修复真实有效；14 条流为**单包排除法**归因，已封顶 candidate 并在报告中如实披露 |

## 二、每项的实证

### 1. 政策

- **前提被证伪**：`mobile/policy/*.json` 是**来源清单**（`sample_id`+URL+notes），不是政策正文；
  `output/local-policy-library-20261018` 不存在，`git log --all -- <path>` 为空，`.gitignore:24` 忽略 `output/`。
  所以"库已写好但没人用"不成立——正文库从未入库，10-19 清理后本地也没有。
- **修复 1（回退）**：`device_run_thirdparty.py` 原来无条件传 `--policy-store <out>/policy`，
  而 `correlate_mobile.py` 收到该参数就不再回退 `DEFAULT_STORE`。现改为三分支：
  APK 可用 → 用它；显式库可用 → 用它；否则**不传**（交给默认库）。`out/policy-source.json` 记录判定依据。
- **修复 2（可用性判据）**：不再看"目录里有没有文件"，改为真调
  `load_policy(package, version_code, apk_sha256)` 判 `available`。
- **修复 3（绑定）**：`policy_fetch` 落盘的 meta 没有包名/版本/摘要，导致 APK 分支永远 `invalid`。
  现在抽到 `document_kind=app_policy` 的正文后，用 `register_policy()` 重新入库绑定被测包
  （`apk_policies_bound` 记入 `policy-source.json`）。**这条只在代码上成立，未上设备验证**——
  手上 3 个样本都是 `neither`，需要拿 `dataset-quality` 里那 4 个 in-APK 样本才能验。
- **修复 4（状态可读）**：`policy_library` 新增 `store_missing`，与"库在但没这个包"（`not_found`）区分；
  gap 直接写出路径与重建命令。
- **未闭环**：`correlate` 与 `evidence_bundle` 现在都传 `--version-code`+`--apk-sha256`，口径已一致，
  但"同一 run 两份产物 status 必须相等"还没有断言测试；默认库为空，回退只能证明"会走到默认库"。

### 2. 同意

- **审计抓到的真漏洞**：`CONSENT_SIGNALS` 把 `PERM_REQ`/`PERM_CHECK` 也算作同意信号，
  于是"弹窗发起了但没结果"会被标成 `observed`，并配上"有权限回调"的错误文案。
- **已修**：`correlate_mobile.py` 拆成四态——
  `observed`（PERM_RESULT/POLICY_VIEW）、`requested_only`（只有 PERM_REQ/PERM_CHECK）、
  `not_observed`（只有 START/ARMED）、`no_consent_channel`（文件缺失/空）。
  文案按信号种类分叉，明确"请求了 ≠ 同意了""没观测到 ≠ 未同意"。
- **回归**：新增 `mobile/analyze/test_consent_observation.py`，7 条用例覆盖上述分支（含"文件缺失"与"空文件"分开钉住），
  已接入两个聚合入口：`mobile/tools/run_mobile_checks.py` 的 analyze 组、
  `tools/check_mobile_branch.py` 的 read_semantics 组——不是只写在文档里。
  同时把 policy 组补上 `test_policy_library`（原来只跑 `test_policy`，31 项里有 15 项从不进回归）。
- **仍存**：`consent_observation` 还没有被 bundle/AI 直接读取；目前靠 `device_run` 把口径类 gap
  以 `【同意口径】` 注记带入报告，属于"报告层已贯通、数据结构未贯通"。

### 3. 流量

- **根因确认**：`mitm-early.log` 的 `client does not trust the proxy's certificate`；
  mitmproxy 拿不到完整 flow，`flows.jsonl` 必空，pcap 只剩未解密 TLS。
- **修复**：`device_run_thirdparty.py` 在采集前调用 `mobile/traffic/transparent.install_system_ca()`
  （`/system` + conscrypt APEX + 每个 zygote 的 namespace），结果记 `verification.system_ca`
  与 `ca-install.json`；新增 `--no-system-ca`（跳过时记非 0，避免看起来"通过"）。
- **正证**：openmensa 一轮 `flows.jsonl` **14 条**，全部 `openmensa.org`、
  `intercepted_tls=true`、HTTP 200、gzip 明文可读；修复前同目录无 `flows.jsonl`、`flows.sqlite` events=0。
- **归因诚实性**：14 条均为 `single_package_fallback`（排除法，`delta_ms=null`）。
  已做三件事：
  1. `is_loose()` 对 fallback 返回 True → 相关结论封顶 `candidate`；
  2. 封顶理由按 `attribution_mode` 分支，不再对 fallback 说"距离 ≥1500ms"；
  3. `correlate` 在"全部流都是 fallback"时写入 gap，报告 §9 同步改为"优先时间归因，退化时用单包排除法"。
- **交付物**：重跑 `correlate → evidence_bundle → report`，生成
  `D:/vscanner-tp/regen-openmensa-1019/out/mobile-report-v2.pdf`（14 页），文本断言 6/6 通过：
  含"单包排除法""不是时间对齐""封顶 candidate""全部为单包排除法归因""没有可观测的同意时刻"，
  且旧句"网络流按同会话、同包名的时间归因"已消失。
- **注意**：`D:/vscanner-tp/ds3-ca-test/.../mobile-report.pdf`（19:40）与
  `ds3-verify-vd/...`（19:54）都是**修复前**产物，不可作为修复证据引用；
  之前误当作重生成的 `ds3-regen-1019` 实际是整目录复制（sha256 与 19:40 相同）。

## 三、仍然开放（按优先级）

1. **政策库正文**：需要联网抓官方页面 + 对应 APK 清单；F-Droid 60 个样本里只有 4 个有包内政策、
   6 个有资源表 URL，其余 50 个 `neither`。这 3 个受测样本都属于 `neither`，
   所以它们 `policy.available=false` 是**数据事实**，不是代码缺陷。
2. **APK 绑定分支上设备验证**：用 `com.waist.line` 等 in-APK 样本跑一轮，确认
   `policy-source.json.used == "apk"` 且 `available=true`。
3. **cross-product 一致性断言**：`summary.policy.status` 与 `bundle.policy.status` 必须相等，
   建议进单测；同理 `consent_observation` 应写进 bundle 结构而不是只靠 note。
   （三个域同源：判定端加了字段、消费端/聚合入口没跟——所以新字段必须有消费方或显式声明"仅审计用"。）
4. **排除法前提**：`SYSTEM_PROBE_PATHS` 只有 4 条 host+path，`gmscompliance-pa.googleapis.com`
   这类系统进程流量不在内；多应用设备上有被误归属的风险。现已封顶 candidate，但报告要声明该前提。
5. **A1 插桩崩溃**仍未解决：videodiary 窗口内 SIGSEGV，`covered=false`，阴性结论只能限定在
   `observed_s` 内。

## 四、复验命令（不需要设备）

```bash
cd mobile/analyze
PYTHONPATH=".;../..;../../core" python -m unittest \
  test_analyze test_analyze_egress test_coverage_gap test_consent_observation
# 报告文案断言
python - <<'EOF'
from pypdf import PdfReader
t = "\n".join(p.extract_text() or "" for p in PdfReader(
  r"D:/vscanner-tp/regen-openmensa-1019/out/mobile-report-v2.pdf").pages)
assert "单包排除法" in t and "不是时间对齐" in t
assert "网络流按同会话、同包名的时间归因；" not in t
print("report wording ok")
EOF
```
