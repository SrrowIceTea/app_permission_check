# 双人一周计划：B侧开发与验收交付

> **历史快照（2026-11-11 归档，不作当前清单）**：现在什么状态、本周做什么见 [CURRENT_STATUS.md](CURRENT_STATUS.md)。

2026-11-11。仅用于授权测试（自有设备与已获授权APK）。
依据桌面已完成下载的 `TWO_PERSON_ONE_WEEK_PLAN_CURRENT_20261110.md`，不是旧五人计划的B。
该输入文件SHA256：`602beeeb7c0c1e5a29e65ae7145f6ecaa7b77a7ac22f356e92a580f18fd597b0`。
实现起点为 `7fb35c0`，独立分支 `codex/duo-b-week1`。

## 1. 达成与未达成

| 工作日 | B侧工作 | 实际交付 | 状态 |
|---|---|---|---|
| D1 | 重放现有定位六类用例、检查计分/报告、正负控清单 | 六类全部符合预期；新建交接检查表与输入格式 | 完成 |
| D2 | collector wire/text、压缩/脱敏、PID反例，报告尾项 | 复用并重跑已有真实collector构造测试；业务证据与unscored投影修复、新增反例 | 完成 |
| D3 | 只读新交接包重放、分层计数和独立实验报告 | 新增冻结复制、原preflight健康校验、动作/回执绑定、分层报告入口 | 代码完成；A本轮新输入待交接 |
| D4 | 歧义/缺字段/正文/PID边界与互审 | 既有修复回归；新增“各自可用但身份/窗口不相容”的负控验收反例；A侧身份/收尾接口检查 | 离线完成；A本轮变更与设备结果待复核 |
| D5 | 集成、回归、完成/未完成表 | 根19组、移动分支24组（含63项）及测试清单守卫；本表与固定输出目录 | B分支完成；A分支合并与设备最终复跑待交接 |

没有把A的采集任务重分配给B，没有改A的Hook、驱动或App坐标格式。
周末无新增任务。没有创建远端PR或自动上传；本交付为可审阅的本地B分支。
现有前端保持原状，本周不开发新前端。

## 2. 代码改进

1. `tools/real_sample_result.py`：业务证据只读business_evidence_scoped，缺字段显示未知。
   规则命中保留整轮口径并标明；定位实验通过独立参数/章节呈现，三类计数不相加。
2. `claim_scope.py` / `claim_verdicts.py`：不可计分原因区分裁决缺失、不一致、非二元、
   无审计产物与审计结构损坏。结构损坏不再导致无解释崩溃或伪健康零命中。
   既有有效记录的七态及三个比率公式不变；没有总体准确率。
3. `location_handoff.py`：复制原输入和归档bundle，验证复制前后摘要与APK/规则身份，
   复用原preflight及定位重放；记录动作声明、进程、TLS与收尾状态，正例附接收正文摘要。
4. `location_acceptance.py`：五类场景独立session；缺输入/缺健康/缺回执明确失败。
   合成结果固定synthetic_only；第三方缺格式/读取时只记尝试，不升级为能力通过。
5. `location_match.py`：增加compatible_comparisons计数，不改变支持格式或候选规则。
   验收负控必须有同身份/窗口可比组合，跨UID或超窗不再凭0候选取得“通过”。

接口和逐项输入要求见[交接说明](DUO_LOCATION_HANDOFF.md)。新增两份测试模块由B登记根回归。
旧定位四项修复已经在基线中，本次复用验证，没有把它们重新宣称为新开发。

## 3. 可核对的实验结果

固定目录：`output/duo-b-week1-20261111/`（不入库，保留私有输入和失败记录）。

| 输入 | 候选 | 歧义流 | 结论 |
|---|---:|---:|---|
| 合成同值整对 | 1 | 0 | 仅内容候选 |
| 合成异值 | 0 | 0 | 符合预期 |
| 合成单坐标/分离坐标 | 0 | 0 | 符合预期，不扩大格式 |
| 合成重复来源 | 2 | 1 | 保留歧义 |
| 合成异会话/身份 | 0 | 0 | 符合预期 |
| 合成空值/不完整正文 | 0 | 0 | 符合预期 |
| 历史OwnTracks s1 | 0 | 0 | 通用定位读取0，流量0，真实正例未验证 |
| 历史OwnTracks s2 | 0 | 0 | 同上 |
| 历史OwnTracks scenarios-004 | 0 | 0 | 通用定位读取0，流量5，不能以专用事件代替 |

历史轮只读重放、核对原摘要；没有改原输入、移植旧签核或视为本周新第三方尝试。
`synthetic-acceptance/`是经过真实collector构造与原preflight的完整合成接口演练，
虽然四类控制条件满足，device_controls_verified仍为false。
`awaiting-a/`输入为明确的空交接模板：incomplete、缺五类场景，两个设备/第三方验收标记均为false。

`projection-result.md`是全部合成统计的报告反例：其他命题业务证据总数9，本题列为0；
裁决缺失、不一致和无审计产物分别显示原因；定位交接缺失单独展示。
反例不是盲评签核或真实样本指标。原冻结盲评目录在本机未找到，未补造“历史七态重放无变化”。

## 4. 测试、配置与复现

定向6模块共79项通过，新增19个测试方法；覆盖快照不改原文件、摘要/归档bundle破坏、
健康缺失、动作/回执串会话、用户冲突、重复session、空输入、PID上下文与报告投影。
原gzip/脱敏/wire-text、PID同号、JSON结构和正文缺失反例均重跑。
根回归19/19，移动分支24/24（其中移动检查63/63），测试清单守卫PASS：unregistered=0、stale=0。
本轮所有修改和新增文件均不超过300行，git diff --check通过。

移动分支首次在工作区中文路径失败：observed_surface夹具出现6个错误/1个失败。
原失败保留在 `branch/`，没有删除、关闭或跳过测试。
使用本进程 `JDK_JAVAC_OPTIONS=-encoding UTF-8`，并把整个分支输出放入ASCII临时路径后通过；
该入口会将TEMP/TMP指向输出下的tmp目录。不是默认宿主中文路径已经修复。
ASCII通过产物复制到 `branch-ascii/`；最终提交复验另存 `release-root/` 与 `release-branch/`。
Python通过项目入口解析至本仓库 `.venv/Scripts/python.exe`；未使用WindowsApps的默认Python。

```powershell
.\tools\python313.ps1 -m unittest vehicle.privacy.test_location_acceptance vehicle.bench.test_duo_projection vehicle.privacy.test_location_match vehicle.privacy.test_location_review_fixes vehicle.bench.test_claim_scope vehicle.bench.test_claim_verdicts
.\tools\python313.ps1 -m vehicle.privacy.location_experiment --synthetic --out output/duo-b-new-synthetic
.\tools\python313.ps1 tools/run_regressions.py --out output/duo-b-new-root
.\tools\python313.ps1 tools/test_inventory_guard.py
$env:JDK_JAVAC_OPTIONS = '-encoding UTF-8'
# 使用尚不存在的ASCII绝对路径；验收后复制日志回私有output目录
.\tools\python313.ps1 tools/check_mobile_branch.py --out C:/Users/OneKyubey/AppData/Local/Temp/vscan-duo-b-new
```

## 5. 仍需交接的材料

- A的本轮设备四类正负控、授权第三方自然工作流及实际业务日志/接收回执。
- 新采集的commit/APK/规则/bundle/设备/user/PID/TLS来源记录及健康收尾状态。
- A的变更提交，供B最终合并复核；两位开发者互审不当作独立专家金标准。

没有这些材料时，B的离线代码通过不等于设备定位闭环完成。
当前原preflight与禁用TLS绕过的就绪事件存在接口风险，详见交接说明；本次未改A代码或降门禁。
实验仍只支持五种完整JSON字符串坐标对，时间窗未标定；不启用VSC-GE-location，
不输出policy_violation，不承诺真实APK检出率或P/R提升。
