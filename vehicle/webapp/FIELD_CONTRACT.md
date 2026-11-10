# 车载工作台后端字段契约（2026-11-10 修订）

仅用于授权测试（自有设备与自有 APK）。本文只描述**新增字段**；原有字段一个都没改。
所有派生值只补字段、不参与判定：`candidate` 不会被升成 `observed`，工具依旧不产出
`policy_violation`。认不出的值一律 `null` + 原因，**没有默认值、没有平均值**。

实现：`vehicle/webapp/presentation.py`（计数/耗时/身份）、`vehicle/webapp/rule_titles.py`
+ `rule_titles.zh.json`（规则标题）、`vehicle/webapp/finding_reviews.py`（复核）、
`vehicle/webapp/artifacts.py`（`/summary`、`/findings` 组装）。
本文所有取值都以真实任务（`v-4505…` done / `v-c723…` failed / `v-ca66…` 纯静态）的
实际响应为准，不是按代码推测。

## 1. `GET /api/pipeline`（数组）与 `GET /api/pipeline/<id>`

`GET /api/pipeline/<id>`、列表接口的每一项、以及 SSE 结束时推送的 `end.data`，都是同一份快照。
原有六键（`id` / `name` / `state` / `created` / `options` / `result`）逐字保留，另加下列 12 键。

| 字段 | 类型 | 缺失时 | 数据来源 / 计算方式 |
| --- | --- | --- | --- |
| `package` | `string \| null` | `null` + `field_gaps.package` | 依次取 `result.package` → `audit/summary.json:package` → `static/static.json:apk.package`。都是产物原值，不做推断 |
| `apk_sha256` | `string`（64 位小写 hex）`\| null` | `null` + `field_gaps.apk_sha256` | 优先 `audit/summary.json:static_analysis.apk_sha256`（preflight 已与装机 APK 核对）；没有时现场对 `uploaded.apk` 算 SHA-256 |
| `apk_sha256_source` | `string \| null` | `null`（只随 `apk_sha256` 一起缺） | 只有两种取值，见下 |
| `apk_size` | `integer`（字节）`\| null` | `null` + `field_gaps.apk_size` | `uploaded.apk` 的 `st_size`；任务目录没有该文件时为 `null` |
| `findings_total` | `integer \| null` | `null`（**没有单独的字段级原因**，见下） | `audit/summary.json:findings_total`，缺失时退回 `result.findings_total`。未跑完审计的任务是 `null`，不是 `0` |
| `findings_by_conclusion_level` | `object`，四档键恒定存在 | 每档为 `null` | 见 1.1 |
| `findings_by_conclusion_level_raw` | `object \| null` | `null` | `audit/summary.json` 里的原始分档字典，逐字复制（真实任务目前只有 `observed`/`candidate` 两键） |
| `findings_by_conclusion_level_note` | `string` | 恒有 | 口径说明，可直接展示，见 1.1 末尾原文 |
| `stage_timings` | `array`，固定 5 项 | 恒有 | 顺序＝静态→反编译→采集→审计→看板，见 1.2 |
| `stage_timings_elapsed_ms` | `integer \| null` | `null` | `events.jsonl` 全部事件 `ts` 的 **max − min**（不是"最后一条减第一条"）；数值型时间戳不足两个时为 `null`，无单独原因字段 |
| `stage_timings_note` | `string` | 恒有 | 说明按主机墙钟算、跨阶段间隙不计入任何阶段 |
| `field_gaps` | `object`：字段名 → 中文原因 | 无缺口时 `{}` | 见 1.3 |

`apk_sha256_source` 的两种取值（前端可据此标注证据强度）：

1. `audit/summary.json:static_analysis.apk_sha256（preflight 已与装机 APK 核对）`
2. `uploaded.apk 的 SHA-256（服务端现场计算）`

### 1.1 `findings_by_conclusion_level` 四档

| 键 | 含义 | 来源 |
| --- | --- | --- |
| `correlated` | 有跨源关联证据的结论条数 | 原始字典该键的值；**没有该键记 `0`**（不是 `null`）；有键但不是整数 → `null` |
| `observed` | 设备侧直接观测到的结论条数 | 同上 |
| `candidate` | 仅静态候选、未经运行时确认的条数 | 同上 |
| `unjudged` | **没有**这三档结论等级的条目数 | `findings_total` − 原始字典里所有数值型计数之和（含三档之外的键）＋原始 `unjudged`（若有） |

- 任务没有 `audit/summary.json`（未完成 / 失败 / 纯静态）时：四档**全部为 `null`**，
  且 `field_gaps.findings_by_conclusion_level` 给出原因（实际文案：
  `本轮没有 audit/summary.json 的分档计数（任务未完成或摘要缺失）。`）。
- 有摘要但缺 `findings_total`：`unjudged` 取原始 `unjudged`，仍取不到则 `null` +
  `field_gaps['findings_by_conclusion_level.unjudged']`（`缺少 findings_total，无法推算未判定条数。`）。
- 摘要不自洽（`findings_total` 小于各档之和）：`unjudged` 为 `null` +
  `field_gaps['findings_by_conclusion_level.unjudged']`（`findings_total 小于分档计数之和，摘要内部不自洽，不推算。`），**不做 `max(0, …)` 修正**。
- 三档之外的键（如历史 `policy_violation`）原样附加在四档之后，不并入 `unjudged`，避免改口径。
- `findings_by_conclusion_level_note` 固定原文：
  `correlated/observed/candidate 取自 findings.jsonl 的 conclusion_level 计数；unjudged 指没有上述三档结论等级的条目（缺失或其他取值），由 findings_total 减去各档之和得出；本工具不产出 policy_violation，计数只描述证据强度，不代表安全或合规结论。`

真实值举例：`v-4505…` → `{"correlated":0,"observed":5,"candidate":6,"unjudged":0}`（`findings_total=11`）。

### 1.2 `stage_timings[]` 单项

```json
{"stage": "capture", "label": "AAOS 设备采集", "status": "done",
 "started_at": 1793947053.6419706, "ended_at": 1793947079.283618,
 "duration_ms": 25642, "unavailable_reason": null}
```

- `stage` / `label` 恒有；顺序与数量固定 5 项（`static` / `decompile` / `capture` / `audit` / `dashboard`）。
- `status`：`events.jsonl` 里该阶段**最后一条**事件的 `status` 原值（`done` / `failed` /
  `running` / `skipped` …）；该阶段一条事件都没有时为 `pending`。
- `started_at` / `ended_at`：该阶段第一条与最后一条事件的 `ts`（Unix 秒，主机墙钟）。
  **只有 `duration_ms` 能算出来时才填**，其余情况两者都是 `null`。
- `duration_ms`：`round((ended_at − started_at) × 1000)`，只在阶段真的执行过且已终止时给出。
- `unavailable_reason` 非空即表示 `duration_ms` 为 `null`，按下列顺序判定（只会命中一条）：
  1. `events.jsonl 没有该阶段的事件，无法计算区间。`（`status=pending`）
  2. `阶段被跳过，没有执行区间。`（`status=skipped`，如纯静态任务没有采集阶段）
  3. `阶段未结束（最后一条事件状态为 running），没有结束边界。`（任务仍在跑）
  4. `起止事件不足两条或缺少数值型时间戳，无法计算区间。`
  5. `结束事件早于开始事件，时间戳不自洽。`
- 既不用平均值，也不用"总时长按阶段均摊"之类的估算。真实失败任务 `v-c723…` 的采集阶段是
  `status=failed`、`duration_ms=4643`（有真实起止事件），审计/看板阶段是 `pending` + 原因 1。

### 1.3 `field_gaps` 的键只有这几种

| 键 | 触发条件 |
| --- | --- |
| `package` | 三处来源都没有包名 |
| `apk_sha256` | 摘要无摘要值且 `uploaded.apk` 不存在或读不了 |
| `apk_size` | 任务目录没有 `uploaded.apk` |
| `findings_by_conclusion_level` | 没有 `audit/summary.json` 的分档计数（未完成/失败/纯静态） |
| `findings_by_conclusion_level.<档>` | 该档有键但不是整数 |
| `findings_by_conclusion_level.unjudged` | 缺 `findings_total` 或摘要不自洽 |

**`findings_total` 为 `null` 时不会出现在 `field_gaps` 里**：原因由
`findings_by_conclusion_level` 这条覆盖说明（两者同时为 `null`）。前端不要把
`field_gaps.findings_total` 当成一定会有的键。

## 2. `GET /api/pipeline/<id>/summary`

只在该任务 `state == done` 时可用；其余状态返回 `404 audit_not_completed`（真实失败任务
`v-c723…` 的 `/summary`、`/findings`、`/report` 都是这个结果，即使磁盘上已有部分摘要）。

除新增四键外，其余字段逐字保留（`findings_total`、`findings_by_class`、`coverage`、
`static_analysis`、`review_order` 等全部不动，`/summary` 里没有 `findings[]` 这个键）。

| 字段 | 类型 | 缺失时 | 说明 |
| --- | --- | --- | --- |
| `findings_by_conclusion_level` | `object`，四档 | 值为 `null` | 同 1.1，覆盖原产物里只有两键的字典 |
| `findings_by_conclusion_level_raw` | `object \| null` | `null` | 产物原文，供核对 |
| `findings_by_conclusion_level_note` | `string` | 恒有 | 口径说明 |
| `findings_by_conclusion_level_gaps` | `object` | **键不存在**（不是 `null`） | 仅在有缺口时出现，内容与 1.3 里 `findings_by_conclusion_level*` 那几条一致 |

磁盘上的 `audit/summary.json` **没有被改写**，投影只发生在响应里。
`review_order[]` 里的 `finding_id`（形如 `finding-6`）原样保留，投影层不覆盖也不改写。

## 3. `GET /api/pipeline/<id>/findings`

同样只在 `state == done` 时可用，否则 `404 audit_not_completed`。
`audit/findings.jsonl` 的**每一行原字段逐字保留**，另加下列 9 键：

| 字段 | 类型 | 缺失时 | 说明 |
| --- | --- | --- | --- |
| `rule_title` | `string \| null` | `null` | 规则标题，解析顺序见 3.1 |
| `rule_title_locale` | `"zh" \| "en" \| null` | `null`（与 `rule_title` 同时为 `null`） | 标题**实际所用**语言：中文映射为 `zh`；库内原值按是否含汉字判 `zh`（库内已有 7 条中文标题）/`en` |
| `rule_title_source` | `string` | 恒有 | 标题出处或取不到的具体原因，见 3.1 |
| `finding_uid` | `string` | 恒有 | 稳定结论标识，见 3.2 |
| `review_status` | `"confirmed" \| "rejected" \| "needs_more_evidence" \| null` | `null` + `review_status_reason` | **没有记录就是 `null`，不默认 `pending`** |
| `reviewer` | `string \| null` | `null` | 人填写的复核人 |
| `reviewed_at` | `string \| null` | `null` | 带时区的 ISO 8601 原文 |
| `review_note` | `string \| null` | `null` | 复核说明；**与行内原有 `note`（规则说明）不是同一个字段** |
| `review_status_reason` | `string \| null` | 有记录时 `null` | 无记录时为 `该结论行没有复核记录，不能当作已复核。`；复核文件损坏时为 `复核文件不可用：<错误>` |

原字段 `note` 保持规则说明语义，不会被复核覆盖；`conclusion_level` 也不会因为复核而改变。

### 3.1 `rule_title` 的解析顺序（`rule_title_source` 的全部取值）

按 `rule_id` 查，优先级从高到低：

1. **展示层中文映射** `vehicle/webapp/rule_titles.zh.json` 命中（22 条）→
   `rule_title` 为映射值、`rule_title_locale=zh`、
   `rule_title_source = rule_titles.zh.json 人工映射`。
   真实值：`VSC-P001` → `声明车辆识别代号（VIN）相关权限`、`VSC-R002` → `读取车辆速度`。
2. **规则库原值**（只读 join `vehicle/rules/rules_library/rules.db` 的 `risk_rules.title`，
   按本轮 `android_version` 取值）→ `rule_title_locale` 按标题是否含汉字判 `zh`/`en`、
   `rule_title_source = rules.db risk_rules（只读，按 android_version=15 取值）`
   （版本号随任务变，如 `android_version=16`）。
   库内已有 7 条中文标题（`VSC-GE-android_id`、`VSC-GE-contacts`、`VSC-GR-advertising_id`、
   `VSC-GR-android_id`、`VSC-GR-contacts`、`VSC-GR-location`、`VSC-GR-microphone`）走这一条，
   不进映射文件。
3. **跨版本唯一标题**：本轮版本没有该 `rule_id` 的行，但四个版本（13/14/15/16）标题完全一致 →
   取这个唯一标题。这是**追加后缀**而不是独立来源：谁提供标题，就在谁的文案后面追加
   `；规则库没有 android_version=15 行；各版本标题一致，取其唯一标题。`
   （所以完整值可能是 `rule_titles.zh.json 人工映射；规则库没有 …`）。
4. 取不到 → `rule_title=null`、`rule_title_locale=null`，`rule_title_source` 写给具体原因：
   - `规则库 risk_rules 没有该 rule_id。`（实验室样本行，见下）
   - `结论行没有 rule_id。`
   - `规则库没有 android_version=15 行，且各版本标题不一致，无法确定。`
   - `规则库里该 rule_id 的标题为空，无法展示。`

要点：

- **中文标题优先于库内英文原值**，但中文映射**不能**救第 4 条的第三种情况：本轮版本行缺失
  且各版本标题不一致时直接 `null`，不拿映射去"覆盖"库内的不确定性。
- 本轮 `android_version` 取 `summary.android_version` → `job.options.version` → 缺省 `15`。
- 结论行是 `VSC-LAB-OWNTRACKS-*` 这类实验室 id（由 `vehicle/privacy/owntracks_evidence.py`
  产出），`risk_rules` 里没有对应行，因此 `rule_title` 必定 `null`、`rule_title_source`
  为 `规则库 risk_rules 没有该 rule_id。`。这是真实缺口，不硬编。
- 已知文案瑕疵（保留未改，仅登记）：规则库文件不存在或不可读时，每行仍会得到
  `规则库 risk_rules 没有该 rule_id。`，真正原因（`规则库不存在，无法 join 标题。` /
  `规则库不可读（...），无法 join 标题。`）目前没有字段暴露。

### 3.2 `finding_uid`（稳定标识）

```
finding_uid = sha256(rule_id | conclusion_level | 排序后的 event_ids | 排序后的 code_locs)[:16]
```

- 只投影，不写回产物：`audit/findings.jsonl` 与 `review_order[].finding_id`（`finding-<下标>`）
  **都原样保留**，AI 复核校验与 PDF 排序继续用原 id；`/findings` 的行里**没有** `finding_id`。
- 字段缺失时以空串参与指纹，不影响其余行。
- 同一输入重跑，`finding_uid` 完全一致；`event_ids` 与 `code_locs` 的顺序不影响取值。
- 两行内容完全相同时，按出现顺序加 `-1` / `-2` 后缀（`string`，不是 16 位定长）。
- **改内容就换 id**：重跑后证据一变，旧 `finding_uid` 失配，已有复核记录留在文件里但不再挂行
  （不会丢，也不会错套到新行）。

## 4. 复核结果与写接口

| 项 | 值 |
| --- | --- |
| 存储 | `output/vehicle-web/<任务>/review/finding-review.json`（每任务一文件，`findings` 的键为 `finding_uid`） |
| 读 | `GET /api/pipeline/<id>/finding-reviews` |
| 写 | `POST /api/pipeline/<id>/finding-reviews`，成功 `201`，响应 `{"finding_uid": ..., "review": {...}}` |
| 请求体 | `{"finding_uid","status","reviewer_kind","reviewer","reviewed_at","note"}`，≤8 KiB，多一个字段都拒 |

读接口：

- 没有文件时返回 `{"schema_version": 1, "findings": {}}`（`200`），**不是 404**。
- 文件损坏 / 结构非法时返回 `400`（`review_unreadable` / `review_invalid`），不返回半截数据。
- 读不受 `state == done` 限制（失败任务此前写过的记录仍可读）；`/findings` 才要求 `done`。

写接口的字段规则：

- `status` ∈ `confirmed` / `rejected` / `needs_more_evidence`；**不接受 `pending`**
  （未复核的行本就不写记录）。
- `reviewer_kind` 必须是 `human`；`ai` / `auto` / 空 / 缺省一律 `403 reviewer_kind_rejected`
  （与 `labels.py` 拒绝 AI 标注计分同一立场）。
- `reviewer` 1–100 字、非纯空白、不含控制字符（首尾空白会被裁掉后保存）。
- `reviewed_at` 必须是带时区的 ISO 8601（如 `2026-11-10T12:00:00+08:00`）。
- `note` 可省略或 `null`，≤500 字。
- `finding_uid` 必须是本轮 `/findings` 里存在的 id，否则 `400 unknown_finding_uid`。
- 写复核**只写这个文件**，不改 `audit/*`、不改 `conclusion_level`、不新增 `policy_violation`。
- 同一 `finding_uid` 再次提交会覆盖上一条记录（无历史版本），需按"以最新为准"使用。

状态码一览：`201` 成功；`400`（`invalid_job_id` / `unknown_finding_uid` / `review_invalid*` /
`review_unknown_field` / `invalid_body` / `incomplete_body` / `invalid_json`）；
`403`（`origin_required` / `local_only` / `reviewer_kind_rejected`）；
`404`（`not_found` / `audit_not_completed`）；`413`（`body_too_large`）。

## 5. 复核写接口的防护与残余风险

已做：`Host` 必须是本机回环；写接口**强制要求 `Origin`** 且必须匹配本机来源（缺 Origin 记
`origin_required`、非本机 Origin 在入口就被 `local_only` 拦掉，都是 403）；任务编号必须匹配
`v-[0-9a-f]{32}`（`..`、绝对路径、百分号编码穿越都过不了正则）；请求体必须带
`Content-Length`、不接受 `Transfer-Encoding`、上限 8 KiB（超限 413 且不读体）；JSON 结构、
字段白名单、取值、时间时区逐项校验；读-改-写在进程内锁内完成，临时文件 + `os.replace`
原子替换，失败只清理临时文件、正式文件保持旧内容；未复核的行显式 `null` + 原因；
错误响应带 `Connection: close`，且在拒绝请求前把 ≤8 KiB 的未读请求体读掉
（Windows 上带未读数据直接关 socket 会发 RST，把刚写出的 4xx 冲掉，客户端只看到
`WinError 10053`）。

残余风险：

1. 锁只在单进程内生效（依赖 `.service.lock` 保证单实例，绕过它手工改文件仍可能丢一次写）。
2. 无身份认证，本机任何页面都能提交；`reviewer` 是自填文本，不可作为签名证据。
3. 同一 `finding_uid` 覆写无历史版本。
4. `os.replace` 的原子性依赖同一卷（放网络盘不保证）。
5. 无速率限制。
6. 超过 8 KiB 的请求体被拒时**不读体**，此时客户端可能仍会看到 `10053` 而不是 `413`
   ——为了不吞下任意大的请求体，这是有意接受的取舍。
