# 下一轮三项工作的操作说明

2026-11-05。仅用于授权测试，限自有设备、获授权 APK 和自有接收端。
本文是实施与人工操作指南；不表示下面的待办已经完成。

## 先安排顺序和人员

1. 开发侧先补规则库升级中断恢复，再扩大真实业务覆盖。
2. 用户最新指定默认由 subagent 签核，可同时进行，不需要等待开发结束或启动模拟器。
3. 组织者启动两个全新上下文 subagent A/B 独立作答，再启动第三个 subagent C 复核与签核。
4. 记录真实 agent 身份、独立评审会话和来源摘要，指标明确标为 subagent 参考范围。
5. 真人评审作为显式可选方式保留；签核指具名、带时间和理由的 JSON 确认。

## 一、规则库升级中断恢复：开发与验收步骤

当前已验证正常升级、损坏资产保留旧库和升级后的 AAOS 35 整机重启。
当前切换仍先删除旧库；切换中杀进程、写入异常及并发安装尚未验收。
入口是 `vehicle/rules/android/app/src/main/java/com/vscanner/rules/RulesDbInstaller.kt`。

1. **冻结旧、新两份库。** 两者 schema 相同，选一条 notes 写不同测试标记。
   分别保存安装资产摘要、四表内容摘要、schema、条数和标记。
2. **补可恢复的切换流程。** 新库完整写入、刷盘、校验后再提交；保存与数据库对应的元数据及恢复状态。
   启动时先恢复上次未完成的切换，按实际内容核验决定使用哪个完整版本。
   对同一库的安装串行化，处理跨进程竞争，并确认切换时没有仍使用旧文件的 Room 连接。
3. **加入只用于测试的故障点。** 至少覆盖暂存写入、保留旧库、切换文件、提交元数据等阶段。
   区分抛出可捕获异常与直接终止进程；终止后的恢复必须在新进程内验证。
4. **执行故障矩阵。** 每个关键阶段测试写入失败、进程终止；关键切换阶段补设备重启。
   另测两次安装竞争、坏资产、首次安装失败，以及当前库和备份都不可用的明确报错。
5. **核对恢复结果。** 应读到完整旧库或完整新库，且生效摘要、内容摘要、元数据和实际标记一致。
   不得把丢库后 Room 自动创建的空库当作恢复成功。没有可信副本时停止审计并给出诊断。
6. **留证并回归。** 在独立测试库或测试用户中运行，保留失败现场和恢复后报告。
   设备重启记录前后 boot ID；测试后恢复原 APK、用户和设备设置。
   运行对应 Android 测试及仓库回归，更新 D014/D015 的后续验收记录。新增/修改代码文件不得超过 300 行。

交付物应包含故障点、触发方法、故障前后文件摘要、恢复结果、设备指纹和总验收 JSON。
模拟器重启及进程终止的结果按实际名称报告，不扩大成物理断电可靠性结论。
目前没有已验收的“一键中断恢复测试”命令，不能用现有正常升级测试代替本项。

## 二、扩大真实业务覆盖：一次只增加一个可验收问题

当前已经通过：MG4 固定 APK 的单次完整明文 POST 逐流归因及同端点负控；
OwnTracks 的前台、后台、真实断网重连、HTTP 503 四项。
这些是固定样本与自有 HTTP 场景，仍为 `workflow_only`。

1. **先选下一条问题。** 建议先补 OwnTracks“撤销定位权限 → 恢复权限”，再做持续后台观察。
   分片发送、HTTPS、其他 APK 版本和其他 AAOS 版本分别立项，不混为一次验收。
2. **固定样本与环境。** 登记 APK 来源、签名和摘要、设备指纹、用户、规则及 Hook 摘要。
   使用合成坐标、自有接收端和显式包名白名单；同一台设备的动态任务串行执行。
3. **写出预期再操作。** 正控至少使用两次不同测试值，必须有新鲜读取、正确应用身份、请求正文和独立回执。
   负控根据该样本真实能力设计；权限拒绝需保存实际授权状态及读取结果。
4. **执行并区分旧、新值。** 撤权后的缓存值或待发队列不能当作新的定位读取。
   恢复权限后应重新取得新值并完成业务；前台、后台、拒绝和恢复阶段分别留时间与状态证据。
5. **分别验收每层。** 业务是否触发、采集是否健康、读取是否取得、请求是否归属、正文是否匹配、
   接收端是否收到、应用是否获成功响应，各自报告。
   HTTP 503 可能已经把正文送到服务器，只能证明业务响应失败，不能证明没有外发。
6. **纳入回归与覆盖表。** 保存通过及失败会话，补可复跑入口，再跑车载/共享内核相关回归。
   没有 Hook、没触发、权限拒绝、正文不可解析和无法归因分别登记；无法证明的项保留缺口。
7. **另起评审轮次。** 新业务证据经规则适用性与参考范围检查后再决定是否计分。
   重新冻结新包，不修改下面已经分发的历史盲评包，也不把业务通过直接换成准确率。

背景与现有复跑入口见 `docs/VEHICLE_MAIN_CLOSEOUT_20261105.md`。
“后台通过”只支持当轮时长；长期后台、休眠、真车和其他系统版本分别需要实际证据。

## 三、签核默认使用 subagent

现行步骤、命令和来源字段见 [subagent 签核说明](VEHICLE_SUBAGENT_SIGNOFF_20261105.md)。
由 Codex 实际启动三个独立上下文：A/B 各自只看冻结包并独立作答，C 收卷后复核证据、负控和分歧。
代码核对身份、会话及摘要，再生成 subagent 标签和分层指标；不用找真人代签。
证据不足仍保留待补，不以多个 agent 意见一致代替缺失事实。

以下是真人轮次的可选操作，仅在明确选择 `--review-mode human` 时使用。

### 第 1 步：分配三位真人

- A、B：分别阅读相同证据，各自独立作答，不提前交流结论。
- C：两份答卷交回后，处理配对题分歧、确认负控并签核，可由导师或另一位独立复核者承担。
- 你可以做组织者。只有两位真人时，先完成两份答卷和分歧登记，正式指标继续待签。

### 第 2 步：只分发各自的 ZIP

- A：`output/aaos35-team-blind-20261104-r2/reviewer-A.zip`
- B：`output/aaos35-team-blind-20261104-r2/reviewer-B.zip`

不要把整个父目录发给评审，里面另有 AI 初评、组织者材料和旧签核文件。
不要把旧 AI 答卷改名或把 `reviewer_kind` 改成人类来代替真人作答。

本次只读核查：两包均含 README.md、evidence.md、evidence.json、空白 review.json；
各有 P01–P06 六道配对题及 W01–W06 六道业务题。冻结材料的 36 个源文件引用均存在且摘要一致。
本轮包绑定的是历史证据；其中旧 MG4 的缺口不能拿后来补测的结果替换。

### 第 3 步：评审独立填写 review.json

先读 README.md，再读 evidence.md，最后编辑自己包中的 review.json。

只填写以下内容，保留其余原值：

- `reviewer`：实际复核者姓名或可追溯身份。
- `reviewer_kind`：`"human"`。
- `reviewed_at`：真实提交时间，包含时区，例如 `"2026-11-05T20:00:00+08:00"`，示例时间需替换。
- 每道题的 `decision` 和 `reason`，12 道题均需填写。

| decision | 怎么判断 |
| --- | --- |
| `present` | 本题命题得到包内证据支持 |
| `absent` | 包内证据足以否定本题命题 |
| `insufficient` | 证据缺失、歧义或无法判断，说明缺什么 |

`reason` 写引用的来源、事件编号及关键字段，并解释为什么支持、否定或不足。
不能只写“同意系统”。看不到证据用 insufficient，不能直接写 absent。
不改题号、slot、schema_version、evidence_sha256、plan_sha256。
保存为 UTF-8 无 BOM 的 JSON，避免注释、末尾多余逗号和中文引号。
两人分别交回各自的 review.json，组织者另存为 review-A.json、review-B.json。

### 第 4 步：组织者收卷并比较

在项目根目录的 PowerShell 中运行一次初始化：

```powershell
Set-Location 'D:\AAA\mobile-app-permission-check'
. ./environment.ps1
$reviewRun = Join-Path (Get-Location) ('output/human-review-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $reviewRun | Out-Null
$reviewRun
```

把收到的两份原始答卷放到刚显示的目录，分别叫 review-A.json、review-B.json。
原始答卷保留不改。继续在同一终端运行：

```powershell
& $VScanPython -m vehicle.bench.blind_round compare `
  --organizer output/aaos35-team-blind-20261104-r2/organizer-only `
  --review-a "$reviewRun/review-A.json" --review-b "$reviewRun/review-B.json" `
  --out "$reviewRun/compare"
```

| 输出状态 | 下一步 |
| --- | --- |
| `awaiting_human_reviews` | 答卷没有声明两位真人，核对来源与填写情况，不能擅改身份 |
| `awaiting_pair_evidence` | 配对题有人选证据不足，先补证；新证据需重新冻结并重新评审 |
| `awaiting_human_adjudication` | 可以请第三位真人复核签核 |

哈希、题号、时间或 JSON 错误按诊断核对，不能删除保护字段绕过。
修改答卷须由原作者确认并保留版本；重新比较使用新输出目录，不能覆盖旧结果。

### 第 5 步：第三位真人填写签核表

仅在生成 signoff-request.json 后执行：

```powershell
Copy-Item -LiteralPath "$reviewRun/compare/signoff-request.json" -Destination "$reviewRun/signoff-human.json"
```

把副本、冻结证据、两份答卷和 adjudication.json 交给 C。
C 填写 reviewer、reviewer_kind="human"、reviewed_at，完成以下项目后再设 confirmed=true：

1. `controls` 的六个配对逐项填写布尔值 `negative_control` 和非空 `reason`。
   true 表示有依据确认该项是检验误关联的负控，不等于“没看见流量”。
2. `disagreements` 中每个配对分歧填写布尔值 `present` 和非空 `reason`。
   没有配对分歧时保留空数组，也仍需确认全部负控。
3. 保留题号、pair、题目/证据/答卷摘要，不得修改哈希使文件勉强通过。
4. 六道业务题的分歧保存在 workflow-reviews.json，另行记录复核结果；它们不进入这批配对分数。

这里 true/false 是 JSON 布尔值，不带引号。
配对争议仍无法根据材料解决时，保留待签，先补证。
两份答卷在签核请求生成后若发生变化，须重新比较并由 C 对新请求重新确认。

### 第 6 步：生成正式标签和指标

C 交回填写完成的 signoff-human.json 后，运行：

```powershell
& $VScanPython -m vehicle.bench.blind_signoff `
  --organizer output/aaos35-team-blind-20261104-r2/organizer-only `
  --review-a "$reviewRun/review-A.json" --review-b "$reviewRun/review-B.json" `
  --signoff "$reviewRun/signoff-human.json" --out "$reviewRun/signed"
```

上一条成功后才运行评估，使用采集当时的历史规则库：

```powershell
./vehicle.ps1 benchmark --suite vehicle/bench/aaos35-suite.json `
  --rules output/o6-device-acceptance-20261104/rules-before-o6.db `
  --labels "$reviewRun/signed/labels-signed.json" --out "$reviewRun/scored"
```

核对 scored/evaluation.json 的 completion、逐案状态及 independently_signed_cases，
再看 benchmark-metrics.json 和 ha-battery/metrics.json；不能只看命令退出码。
指标包含配对的 TP/FP/FN、精确率/召回率、区间及一致性等，空分母继续保留空值。
本轮正式配对指标只适用于这批 HA 电量参考范围。其余业务题及后来补测的 MG4/OwnTracks 单列，
不能称为“整个车载平台的准确率”，也不能把 12 道题当作 12 个独立 App 样本。

### 今天可以先做的事

默认流程由助手启动 A/B/C subagent，实际运行比较、签核校验和指标生成，并保留执行记录。
如显式选择真人轮次，再按上面的可选步骤分发 ZIP；该轮判断和签核由真人完成。
