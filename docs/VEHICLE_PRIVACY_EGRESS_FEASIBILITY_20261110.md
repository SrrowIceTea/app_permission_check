# 定位 / 麦克风的「读取 → 外发」关联可行性评估

日期：2026-11-10
范围：**只做可行性分析**。本文不改 `rules.db`、不改 `dangerous_apis`、不改任何 hook 或前端，不提交不推送。
所有数字来自只读勘察脚本（`output/_vehicle-coverage/ge_probe*.py`，不入库）。

---

## 0. 结论先说

| 数据类型 | 能不能做 `VSC-GE-*` | 建议 |
| --- | --- | --- |
| 麦克风 | **不能**（值级证据根本不存在） | **不做**。任何"读了音频又发了包"的结论只能靠时间接近，这正是 `POLICY.md` 明令禁止的 |
| 定位 | **当前不能；换机制后可能** | **不做"加规则行"路线**。要做就必须先补采集侧（`value_len` + 可配比的规范形态）+ 求值侧（数值量化匹配器 + 误配封顶）+ 新窗口标定，属于**机制扩展**，不是规则库改动 |

一句话：现有两条 `VSC-GE-*` 能成立，靠的是"**值原样出现在出站 JSON 里**"。定位的值是会被重采样/降精度/换坐标系的浮点对，麦克风的值**根本没被保留**——两者都不满足这个前提。

---

## 1. 现有两条 `VSC-GE-*` 是怎么定义的

### 1.1 规则行长什么样

`vehicle/rules/rules_library/rules.db` → `risk_rules`，四版本各一条 `VSC-GE-android_id` 与 `VSC-GE-contacts`：

```
rule_type        = data_egress
conclusion_level = correlated
window_ms        = 30000
enabled          = 14/15 为 1；13/16 为 0（未做外发窗口标定）
property_key     = NULL          ← 与 VHAL 的 VSC-E00x 靠 property_key 区分
api_key          = NULL
condition_json   = {
  "data_type": "android_id" | "contacts",
  "data_type_name": "...",
  "api_targets": ["...Settings$Secure.getString(...)", ...],   ← 描述用，求值不读
  "predicate": "same_value_in_outgoing_json",
  "value_basis": "complete_request_json_string_value_hash",
  "identity_scope": "same_package_user_uid_session",
  "requires_read_state": "obtained",
  "scope": "partial_api_surface",
  "permission_op": "none" | "capability_dependent",
  "required_permissions": [...],
  "window_ms": 30000
}
basis_refs_json  = [{"kind":"project_policy","path":"vehicle/privacy/POLICY.md","sha256":"b7147dac…"}]
```

关键点：**`condition_json` 里没有 host、没有 data_type 标记字段、也没有 `property_id`**。
配对完全靠"值 + 身份 + 时间窗"三件套，`api_targets` 只是给人看的描述。

### 1.2 求值在哪段代码

**不在** `vehicle/analyze/correlate.py`（那是 VHAL 的 `VSC-E00x`），而在
`vehicle/privacy/evaluation.py`。四步：

1. **建"可用流"集合**：`request_hashes(flow)`（[evaluation.py:47-69](file:///d:/AAA/mobile-app-permission-check/vehicle/privacy/evaluation.py#L47-L69)）
   - 只认 `request_payload.text` 是**完整**请求体：`raw_truncated` / `text_truncated` / `decode_error` 任一为真 → 直接返回空集
   - 正文 > 2MB → 空集；`json.loads` 失败 → 空集
   - 遍历到 10000 个节点为止，收集**每个长度 ≥ 8 的字符串叶子**的 `sha256[:16]`
   - 只扫**请求**，不扫响应；数字叶子不参与（`isinstance(node, str)`）
2. **读出侧门槛**（[evaluation.py:162-166](file:///d:/AAA/mobile-app-permission-check/vehicle/privacy/evaluation.py#L162-L166)）：
   - `value_hash` 必须 `[0-9a-f]{16}`；`host_received_ts` 必须存在；**`value_len >= 8`**
3. **配对判据**（[evaluation.py:167-178](file:///d:/AAA/mobile-app-permission-check/vehicle/privacy/evaluation.py#L167-L178)）：
   `compatible(read, flow)`（同包/同 user/同 uid/同 session）∧ `0 <= flow.ts - read.host_received_ts <= 30000` ∧ `value_hash ∈ request_hashes`
4. **封顶**：归因偏松（`is_loose`）时结论降为 `candidate`；`conclusion_level` 只在规则库里声明，引擎不抬高

### 1.3 两个硬编码闸门（这是本轮问题的根）

- [evaluation.py:153](file:///d:/AAA/mobile-app-permission-check/vehicle/privacy/evaluation.py#L153)：
  `if dtype in ('android_id', 'contacts')` —— **不在这个元组里，连 `VSC-GE-*` 都不会去查**
- [privacy_rows.py:44](file:///d:/AAA/mobile-app-permission-check/vehicle/rules/python/privacy_rows.py#L44)：
  `EGRESS_TYPES = ("android_id", "contacts")` —— 建库时只生成这两条 GE 行

即：**只加规则行不够**，这两处不同时改，规则行永远不会被读到。

---

## 2. 定位 / 麦克风要能关联，缺什么证据

### 2.1 采集侧现在有什么

**读事件 `PRIVACY_READ`**（`vehicle/hooks/hook_privacy.js` + `core/privacy/values.js`）：

| 字段 | 说明 |
| --- | --- |
| `evt_id` / `ev` / `ts` / `host_received_ts` | 事件标识与两端时钟 |
| `pkg` / `uid` / `user_id` / `session_id` / `src` | 身份（`compatible()` 的输入） |
| `api` / `data_types[]` | 命中的签名与数据类型标签 |
| `outcome` / `collection_state` / `non_empty` | 取值状态（`read_state()` 据此分级） |
| `value_hash` / `value_len` / `count` | **值证据**——每个 capture 模式给的不一样 |
| `value_capture_gap` | 明确写"这一型不提供什么" |

按 capture 模式的实际产出（[hook_privacy.js:38-52](file:///d:/AAA/mobile-app-permission-check/vehicle/hooks/hook_privacy.js#L38-L52)）：

| capture | `value_hash` | `value_len` | `count` | 自报缺口 |
| --- | --- | --- | --- | --- |
| `string`（android_id） | `sha256[:16](原字符串)` | ✅ 有 | — | — |
| `cursor`（contacts） | 逐条 `Cursor.getString` 的哈希 | ✅ 有 | ✅ 条数 | — |
| **`location`** | `sha256[:16](JSON.stringify([lat, lon]))` | ❌ **没有** | — | `location pair hash only; location egress matching not implemented` |
| **`audio_count`**（麦克风） | ❌ **没有** | ❌ **没有** | ✅ 字节数 | `audio samples intentionally not retained; no audio egress value matching` |

**外发事件（flow）**：`evt_id` / `ts` / `package` / `session_id` / `src` / `host` / `method` / `path` /
`request_payload{text, raw_truncated, text_truncated, decode_error}` / `intercepted_tls` / 归因三元组。

### 2.2 「读取 → 外发」要成立，还缺什么

**定位，还缺三样**：

1. **`value_len`**。求值器第 165 行要求 `value_len >= 8`，location 分支压根没写这个字段 → 默认 `0` → **即使把 `dtype` 放进白名单也会被全部丢弃**。这是可验证的死结，不是猜测。
2. **可配比的规范形态**。现在的哈希对象是 `JSON.stringify([lat, lon])`（双精度浮点原样）。而实际出站报文体里出现的是：
   - 分段字段 `{"lat": 30.2741, "lon": 120.1551}`
   - 降低精度后的字符串 `"30.2741,120.1551"`
   - 投影/加密坐标系（GCJ-02、BD-09）或 WGS84 之外的单位
   - 一串轨迹（多个点、时间戳），而不是单点
   
   这几类**没有一类**等于 `JSON.stringify([lat, lon])`，所以现在的哈希几乎必然不命中。
3. **数值匹配器**。`request_hashes()` 只收**字符串叶子**，数字叶子完全跳过。定位的外发值通常是 JSON number，需要一个新的、能按路径约束匹配数字的分支。

**麦克风，还缺"值"本身**——这是补不上的：`POLICY.md` 明确不保留音频样本，`hook_privacy.js` 只给 `count`（`AudioRecord.read` 返回的字节数）。没有内容就没有值哈希，**不存在任何值级配对**。

### 2.3 与 android_id / contacts 的本质差别

| 维度 | android_id / contacts | 定位 | 麦克风 |
| --- | --- | --- | --- |
| 值的形态 | **稳定标量字符串**，≥8 字符 | 浮点**对**，有精度 | **字节流** |
| 序列化后是否原样存活 | **是**（JSON 里出现同一字符串） | 否（重采样/降精度/换坐标系/拆字段） | 否（编码、压缩、分片） |
| 同一性 | 值唯一标识设备/记录 | 坐标随时间变化，重复值只在原地震荡时出现 | 每次读取内容都不同 |
| 可保留性 | 可（哈希即可） | 可（哈希一对坐标） | **不可**（隐私红线，已定为不保留） |
| 结论 | 值相等 = 强证据 | 值相等只在**量化后**才可能 | 无值证据，只能时间接近 |

一句话：前两者的值**天然是 JSON 里能原样找到的字符串**；定位的值是会被下游改写的数值，麦克风的值根本不在手里。

---

## 3. 配对判据的候选方案

### 方案 A：弱配对（时间窗 + 同 host + data_type 标记）

**做法**：读侧不变；外发侧扫请求正文，找 key 名含 `lat`/`lon`/`location` 的字段，或整体形如 `[x, y]` 的二元数组；同包同会话、30s 内即判"关联"。

**能成立的前提**：几乎没有——只要报文里有任何坐标形状的字段就打标。

**误配风险：不可接受。**
- 任何发送地图视野中心、城市中心坐标、`lat=0,lng=0` 占位、甚至远端下发配置的应用，都会在"刚读过定位"后的 30s 内命中一次
- 车机场景更糟：`PERF_VEHICLE_SPEED`/罗盘/导航类数值大量是一两位小数的浮点，与坐标区间重叠
- 结论会变成"凡是用定位的 App 都外发定位"，误配率接近 100%，且**不可复核**

**判定**：只能作为 `candidate` 并显式标注 `correlation_scope=time_proximity_only`，但那等于把已知的弱判据包装成结论。**不建议做**（若一定要有，必须由规则显式声明 `conclusion_level=candidate` 且报告里写"仅时间接近"）。

### 方案 B：量化坐标匹配（推荐，但需要新匹配器）

**做法**：
1. 读侧把定位规范化为 `(lat6, lon6)` 两个定点字符串（或一个 `"lat,lon"`），并补 `value_len`
2. 外发侧新增**数值叶子**分支：遍历请求 JSON，对每个 number 叶子按同一量化规则取整
3. 判据：**同一 JSON 对象节点内**同时出现 `|lat_leaf - lat_read| <= 1e-4` 与 `|lon_leaf - lon_read| <= 1e-4`（约 11m），且该节点深度 ≤ 8、同包同会话、时间窗内

**为什么比 A 强**：要求**两个数同时命中**，随机命中的概率从"必然"降到 `(1e-4/取值域)^2` 量级。

**误配风险（仍然存在）**：
- **整数/整数化坐标**：`lat=30`、`lon=120` 这类粗值会命中大量配置
- **低精度上报**：只发 2 位小数时，量化阈值内的候选会成片出现（一个 0.01° 网格 ≈ 1km，同城多点同格）
- **首点即设备当前点**：很多 SDK 会把"上一次已知位置"当默认值发出去，与本次读取无关
- **坐标系不一致**：GCJ-02 与 WGS84 差 300–500m，直接比会全不命中（漏），换算错了会全命中（误）

**缓解措施（缺一不可）**：排除有效数字 < 5 的值；要求同一对象下成对出现；`attribution_loose` 时封顶 `candidate`；对"0,0"与常见城市中心做 denylist；窗口不得大于 30s。

**判定**：**技术上可行，但要新增匹配器 + 标定**，不是加一行规则。

### 方案 C：派生形态匹配（复用 `derive.py` / `transformations()`）

**做法**：把规范化后的 `"lat,lon"` 字符串按 base64 / hex / urlencode / md5 / sha1 / sha256 派生，再去报文里找（`vehicle/analyze/value_match.py:53-59` 已有这套变换）。

**能成立的前提**：应用把坐标当作**不透明字符串**整体编码上报，且序列化格式与我们的规范化一致（顺序、分隔符、小数位）。

**误配风险：极低**；**漏配风险：极高**。格式组合（`lat,lon` / `lon,lat` / `[lat,lon]` / 6 位 vs 7 位小数 × 坐标系）本身就把命中率压到接近 0，且必须"先猜对格式"才谈匹配。

**判定**：可以做成**加分项**（命中即升级为强证据），但不能作为主判据。

### 方案 D：字节级污点追踪（"最强"，但做不到）

把 socket 写出的 buffer 与 `AudioRecord.read` / `Location` 返回值做真实数据流关联。需要 native 层 taint tracking（Frida Stalker + 内存标记），与项目"只观察、不介入"的定位冲突，也不在现有采集链路里。

**判定**：**不做**。这是另一个产品的能力，不是本仓库的规则扩展。

### 麦克风：没有候选方案

- `count`（字节数）匹配报文里的 `length`/`size` 字段：误配率极高（任意上报都带长度）
- 音频编码容器头（ADTS/Opus 头）特征：只能证明"发了音频"，**不能证明发的是这次读到的音频**
- 能量/RMS 指纹：需要保留音频派生量，与"不保留样本"的策略边界冲突

**判定**：**明确做不到**。`VSC-GR-microphone` 停在 `observed` 是正确的上限，不应包装成 `correlated`。

---

## 4. 代价（逐项，不含"应该不影响"）

假设只在 **14/15** 启用（与现有 GE 一致），且 `--out` 指向同一个 `rules.db`。

### 4.1 必须改的文件

| # | 文件 | 改什么 | 不改的后果 |
| --- | --- | --- | --- |
| 1 | `vehicle/privacy/evaluation.py:153` | dtype 白名单元组 | 规则行永不被读取 |
| 2 | `vehicle/privacy/evaluation.py:165` | `value_len >= 8` 对 location 放宽（或改判据） | 所有 location 读被静默丢弃 |
| 3 | `vehicle/hooks/hook_privacy.js:45-51` | location 分支补 `value_len` + 规范形态 | 同上（且这是 **hook 改动**，本轮边界内禁止） |
| 4 | `vehicle/rules/python/privacy_rows.py:44` | `EGRESS_TYPES` 加 `location` | 建库不生成 GE 行 |
| 5 | `vehicle/privacy/coverage.py:15` | 追加 `VSC-GE-location` 到 `rule_ids` | 覆盖链与规则库不一致 |
| 6 | `vehicle/privacy/POLICY.md:14` | 现文写的是"当前不做定位/音频值级外发归因"，要改 | 规则依据与政策自相矛盾；且**该文件的 sha256（`b7147dac…`）被写进每条 `VSC-GE-*` 的 `basis_refs_json`**，一改文本，8 条 GE 行的依据摘要全部变化，diff 会扩散到 android_id/contacts 两条已有规则 |
| 7 | `vehicle/privacy/test_evaluation.py:102/107` | 断言的是**精确集合** `{VSC-GE-android_id, VSC-GE-contacts}` | 回归必红 |
| 8 | `vehicle/rules/rules_library/rules.db` | **必须重建** | — |
| 9 | `vehicle/rules/rules_library/rules.db.summary.json` | `counts.*.risk_rules` 29→31、`enabled_rules` 96→100、`privacy_rules` 7→9、`enablement.after.data_egress` 40→48 / 20→24、`database_sha256` | 摘要与库不一致 |
| 10 | `vehicle/rules/android/.../BaselineExpectation.kt:32,41,50,61,69` | `SHA256` + 四版本 `riskRules/enabledRules` | `RulesVerifier` **fail closed**，App 拒绝加载规则库 |
| 11 | `vehicle/coverage/generated/{coverage.json,COVERAGE.md}` | 重生成（`rules_sha256` 会变） | 覆盖链里的摘要过期 |
| 12 | `COMPLETION.md` / `docs/PROJECT_STATUS_20261110.md` | 116 条 / 96 启用 / `19/29/29/19` 等文字与数字 | 文档与库不一致（无测试断言，但属交付物） |

重建四版本库的命令（`vehicle/rules/CLAUDE.md` 记录的口径，参数顺序照抄）：

```powershell
.\tools\python313.ps1 vehicle\rules\python\build_multiversion_rules.py `
  --base baseline_android14/rules.db `
  --source-seed baseline_android13 --source-seed baseline_android16 `
  --calibration device_calibration/permissions-car-android15.jsonl `
  --general-permissions device_calibration/permissions-general-android15.jsonl `
  --property-ids device_calibration/vhal-property-ids-device35.json `
  --cpm-signatures device_calibration/cpm-signatures-device35.json `
  --device-facts device_calibration/device-facts.json `
  --enable-types over_permission,sensitive_read,data_egress `
  --egress-window-ms 30000 --egress-versions 14,15 `
  --out rules_library/rules.db --summary rules_library/rules.db.summary.json
```

两个坑（[build_multiversion_rules.py:131-132](file:///d:/AAA/mobile-app-permission-check/vehicle/rules/python/build_multiversion_rules.py#L131-L132)）：
`--out` 目标已存在时脚本**拒绝覆盖**（先写新路径再替换，不能就地重建）；
`--egress-versions 14,15` 就是第 4.2 节"仅 14/15 启用"的来源，改这个值等于改启用范围，需要新标定依据。

> 注意 `build_rules.py` 是**单版本**构造器（要 `--manifest/--properties/--android-version/--source-revision`），
> 四版本必须走 `build_multiversion_rules.py`，别拿单版本脚本当重建入口。

### 4.2 计数影响（算清楚）

| 指标 | 现在 | 加 2 条 GE（仅 14/15 启用） | 加 2 条 GE（四版本都启用） |
| --- | --- | --- | --- |
| `risk_rules` 每版本 | 29 | **31** | **31** |
| 四版本总行数 | 116 | **124** | **124** |
| `enabled_rules` | 96 | **100** | **104** |
| 每版本启用（13/14/15/16） | 19/29/29/19 | **19/31/31/19** | 31/31/31/31 |

> 13/16 若要启用，会打破 `EGRESS_CALIBRATION.md` 的"未标定不启用"约束，需要新的标定依据。
> 只加 `location` 一条时把上表的 +2 换成 +1：31→30、96→98（或 100）。

### 4.3 SHA256 与已封存产物

- **`rules.db` 的摘要一定变**（新增行）。`rules.db.summary.json` 里的 `database_sha256`
  与 `BaselineExpectation.SHA256`（`ddf57f6f…`）都要同步，否则 Android 侧 `RulesVerifier` 直接失败。
- **契约结构校验不会失败**：表结构、前缀 `VSC-`、`rules.manifest.json`（它只声明
  `platform/prefix/tables`，不含摘要与计数）都不变。
- **绑定校验会失败**，且这是设计如此：
  - `vehicle/analyze/correlate.py:148`：`manifest['rules_sha256'] != digest(--rules)` → 拒绝重分析
  - `vehicle/pipeline/audit.py:85`：结论文档写死采集时的 `rules_sha256`
  - `vehicle/analyze/report.py:279`：摘要与 `meta.sha256` 不一致 → 报告拒绝
  - `vehicle/bench/ablation_integrity.py:31-42,71`：重放要求"与采集清单 `rules_sha256` 匹配的规则库快照"，找不到就报错
- 结论：**旧采集产物不能再用新库重放**，只能保留当时的 `rules.db` 快照，或重跑采集。
  若这条不能接受，就不要改库——这也是"加规则行"路线最贵的部分，不是代码量。
- `vehicle/coverage/generated/coverage.json` 内嵌 `rules_sha256`，必须重生成；已归档的
  coverage 文件本身仍然自洽（它记的是它当时那版的摘要）。

---

## 5. 明确做不到的部分

1. **麦克风的"读取 → 外发"关联：做不到。** 不保留音频内容 ⇒ 没有可比对的值；
   任何结论都只能建立在时间接近上，而 `vehicle/privacy/POLICY.md:12` 明写
   "不使用响应、预览、形态标签或时间相近推断外发"。给一个能跑的版本只会产出高误配结论。**不做。**
2. **定位的"原样值匹配"：做不到。** 现有 `value_hash` 的输入是
   `JSON.stringify([lat, lon])`，出站报文体里几乎不会出现同一字符串；
   加上 location 分支**不产出 `value_len`**，求值器第 165 行会把它们全部过滤掉。
   即使放开闸门，命中数也会是 0。
3. **二进制 / 压缩 / 未解析协议的定位外发：做不到。** `request_hashes()` 遇到
   `raw_truncated` / `text_truncated` / `decode_error` / 非 JSON 一律返回空集。
   汽车场景大量上报走 protobuf 或 gzip，这类一律不可配。
4. **"读了哪个点"与"发了哪个点"的一一对应：做不到。** 一次读取 = 一个 fix，
   一次上报常含多点的轨迹；没有稳定 ID 把两者绑定，只能做"某点 ∈ 某批"。
5. **高精度可信**：即使方案 B，也只是"量化后相等"，`POLICY.md:13` 的
   "相同值相关不证明唯一因果"仍然成立——这决定了上限只能是 `correlated`，不能到 `policy_violation`。

---

## 6. 建议

**建议做（不碰规则库、不碰 hook）**：把"为什么没有 GE-location / GE-microphone"写成显式缺口，
而不是留在 `value_capture_gap` 里当附带信息。具体是两处文案对齐：

- `vehicle/privacy/coverage.py` 的 `uncovered_reasons` 里，对 location / microphone 明写
  "不做值级外发归因（`POLICY.md` 第 14 行）"，避免读者把它当成漏做；
- 报告侧同样对这两类只出 `observed`，并展示原因。

**建议不做**：给麦克风加 `VSC-GE-microphone`（第 5.1 条）。
**暂不做、需单独立项**：给定位加 `VSC-GE-location`——它要一次"采集侧 + 求值侧 + 标定"
的机制扩展（第 3 节方案 B），并且会改变 `rules.db` 摘要、打断已封存产物的重放（第 4.3 节）。
如果立项，顺序应是：先补 `hook_privacy.js` 的 location 规范形态与 `value_len` →
再写数值量化匹配器与离线误配率评估 → 最后才谈规则行与计数。

**不建议**先加规则行再补采集：那会造出一条永远 0 命中的规则，比没有更糟——
它会让覆盖链显示"已覆盖"，而实际上是静默空转。

---

## 附：勘察脚本（只读，不入库）

| 脚本 | 产出 |
| --- | --- |
| `output/_vehicle-coverage/ge_probe.py` | 表结构、VSC-GE 行、每版本 rule_type 计数 |
| `output/_vehicle-coverage/ge_probe2.py` | VSC-GR/GE 全量清单与启用状态 |
| `output/_vehicle-coverage/ge_probe3.py` | `condition_json` / `basis_refs_json` 全文 |
