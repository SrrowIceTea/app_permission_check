# 陶俊哲一周任务交付：有限定位外发匹配

日期：2026-11-10。依据[一周方案](ONE_WEEK_DEVELOPMENT_PLAN_20261110.md)中陶俊哲职责实施。
仅用于授权测试（自有设备与自有 APK）。本交付是离线内容关联实验，不生成违规或定位外发规则结论。

## 1. 完成范围

| 原任务 | 本次结果 |
|---|---|
| 核对 location_forms、通用求值器与规则 | 已核对真实 Hook 形态；四版本仅登记 VSC-GR-location，均无 VSC-GE-location |
| 有限 JSON 字符串坐标对匹配 | 已实现 5 种形态；复用原值摘要，不要求新增 Hook 或明文坐标 |
| 六类离线验收 | 同值、不同值、单坐标、重复来源、异会话/身份、空值/正文不可用全部符合预期 |
| 可用真实定位样本验证 | 对 3 组封存 OwnTracks 输入执行摘要校验和离线重放；均缺通用定位读取摘要，真实正例未验证 |
| 独立交付和自测 | 独立分支 codex/tao-location-week1；代码、测试、命令及实验产物齐备 |
| 稳定性门禁与是否默认接入 | 无定位外发规则，按方案不接默认路径；原规则求值器、Hook、catalog 和前端不变 |

这表示完成本周允许的“独立实验模块＋明确真实验证限制”交付，不表示真实 App 定位检出能力已经通过验收。

## 2. 文件及接口

| 文件 | 职责 |
|---|---|
| vehicle/privacy/location_match.py | 纯函数 evaluate(reads, flows, package, session, window_ms=30000)，输入不变，输出实验候选及诊断 |
| vehicle/privacy/location_experiment.py | 合成用例/封存会话 CLI；验证会话包名及输入摘要，只写独立新目录 |
| vehicle/privacy/location_fixtures.py | 明确标记为合成的六类验收输入，不充当设备采集/人工金标准 |
| vehicle/privacy/test_location_match.py | 匹配、门禁、异常、原 Hook 交叉验证、默认规则不变、CLI 故障保留等测试 |
| tools/run_regressions.py | 仅为 vehicle-pipeline 组登记新测试模块；不改其他人的功能代码 |

输入使用已有字段：PRIVACY_READ/location、obtained、value_kind=location_pair、location_form、value_hash/value_len、location_forms、包名/UID/user/session、事件引用及主机收件毫秒时间。
主形态与形态表不一致、旧式无形态哈希、零值/越界标记、身份/时钟缺失、同引用冲突均拒绝匹配并给诊断。
如果明确记录了主形态但省略形态数组，可仅按主形态匹配；不能把旧版无形态 value_hash 猜成新编码。
允许 pair_d6、pair_d6_lonlat、pair_raw、pair_raw_lonlat、geo_d6，均要求完整单个字符串含整对坐标。
忽略 single_lat_d6/single_lon_d6，即使两者都出现在不同字段也不配对。JSON 数字、其他精度、表单、Protobuf 不在范围内。
正文必须是完整请求 JSON；不读响应、预览或键名。截断、解码失败、重复 JSON 键、非法常量、摘要/长度不符或遍历超限不给部分命中。
仅接受已知归因类型及明确 UID/user；同设备身份冲突、不同会话/包、失败/歧义/单包兜底归因不关联。
所有候选均为 content_match_candidate，origin_proven=false；宽松归因另留 attribution_loose。相同内容不证明因果、服务端收到、唯一来源或违规。
时间窗默认 30000ms，是显式未标定实验参数；保留先读后发及边界，不宣称适用于所有定位 App。

## 3. 可重放命令

在仓库根执行。示例输出目录必须尚不存在；重跑另换目录，不覆盖失败/成功证据。

```powershell
.\tools\python313.ps1 -m unittest vehicle.privacy.test_evaluation vehicle.privacy.test_location_match
.\tools\python313.ps1 -m vehicle.privacy.location_experiment --synthetic --out output/location-new-synthetic
.\tools\python313.ps1 -m vehicle.privacy.location_experiment --capture output/companion-followup/owntracks-scenarios-004/capture --package org.owntracks.android --out output/location-new-owntracks
```

捕获重放必须提供清单白名单中的包名，session 从清单读取；reads/flows 的字节摘要须与清单一致，分析结束再次核验输入及清单未变化。
输出不能位于原 capture 内。成功写 result.json；异常写 failure.json、返回 2；合成预期不符返回 1。返回 0 仅表示实验执行成功，不是设备验收或合规通过。
实验报告保留输入/实现摘要、Git HEAD、形态/事件引用及缺口；不另写坐标原文、不生成 findings.jsonl、不改原采集或复核记录。
输入摘要一致不等于全部采集健康已核验；本工具明确不替代 vehicle/pipeline/preflight。

## 4. 本轮结果

| 六类合成输入 | 候选配对数 | 歧义流数 | 结果 |
|---|---:|---:|---|
| 同值坐标对 | 1 | 0 | 符合预期，只有内容候选 |
| 不同值 | 0 | 0 | 符合预期 |
| 分开的单坐标字段 | 0 | 0 | 符合预期，不升级 |
| 相同坐标的两次来源读取 | 2 | 1 | 全部保留，不强行选唯一来源 |
| 异会话/异身份 | 0 | 0 | 符合预期 |
| 空值或不可用正文 | 0 | 0 | 符合预期，不当阴性 |

所有五种成对形态均用真实 privacy_location.js 的输出做交叉测试；同一读/请求命中多个形态仍只有一个候选配对。
重复落盘的同一事件不重复计数，同引用不同内容则拒绝；重复请求与不同来源的候选保留。六组数据都是合成测试，不能算真实 P/R。

| 历史会话 | 通用定位读取 | 流量 | 可支持的真实结论 |
|---|---:|---:|---|
| output/v8-20261109/dynamic/owntracks-s1/capture | 0 | 0 | 未验证；没有本模块需要的读取/请求输入 |
| output/v8-20261109/dynamic/owntracks-s2/capture | 0 | 0 | 同上 |
| output/companion-followup/owntracks-scenarios-004/capture | 0 | 5 | 专用 owntracks_location 事件不冒充通用 PRIVACY_READ；不能证明通用链成功 |

本轮最终实验结果在 output/tao-location-week1-20261110/experiments-release/ 下，synthetic 与三组真实重放分别存放。
真实重放的 real_validation 为 not_validated_on_supported_real_content；零候选不表示“没有定位外发”。未修改历史记录、从数值正文反造读取或调用专用求值器冒充通用链。

## 5. 回归、限制及交接

匹配相关新旧单测共 31 个通过（含 13 个新增测试方法）；根回归见 output/tao-location-week1-20261110/regression-release/verification.json。
移动分支首次检查暴露两个问题：新测试尚未登记回归清单（已通过最小登记修复）；observed_surface 的 javac 默认 GBK 编码无法读取既有 UTF-8 Java 夹具。
后者独立复现，原移动源码不变；仅本次进程设置 JDK_JAVAC_OPTIONS=-encoding UTF-8 后该 20 个测试通过。进一步确认分支入口把 TEMP 放在含中文的工程路径下，dexdump 随后报 ReadFileToString failed。使用 ASCII 临时输出目录后，移动分支 24 组全部通过，内含移动检查 63 项全过。
最终移动兼容日志已复制至 output/tao-location-week1-20261110/mobile-branch-utf8-ascii/，原始临时目录与全部失败轮次也保留。此处是测试环境规避，不是已修复移动侧编码/路径问题，后续仍需其负责人修复。

```powershell
$env:JDK_JAVAC_OPTIONS = (($env:JDK_JAVAC_OPTIONS + ' -encoding UTF-8').Trim())
$locationCheckOut = Join-Path ([System.IO.Path]::GetTempPath()) ('vscanner-location-' + [guid]::NewGuid().ToString('N'))
.\tools\python313.ps1 tools/check_mobile_branch.py --out $locationCheckOut
```

默认规则、通用 evaluation、catalog/政策、Hook、数据库、前端、其他两人的判定/采集模块均未修改。
唯一共用文件变更是回归清单登记，避免新测试成为清单守卫中的未登记测试。所有新文件保持 ≤300 行。
后续默认接线必须另行完成定位外发规则依据/登记、窗口标定和合适真实样本验证；这超出本周隔离范围。未来若增加规则，也不能仅因候选唯一就写来源因果或违规。
给采集负责人只保留一个输入请求：下轮若自然采到带通用 location_forms 的 PRIVACY_READ 且同会话存在整对字符串坐标正文，即可原样重放；不要求为本实验更改 Hook 或改写 App 返回值。
