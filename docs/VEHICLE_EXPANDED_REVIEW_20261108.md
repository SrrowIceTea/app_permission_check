# MG4 / OwnTracks 新证据资格复核

仅用于授权测试（自有设备与获授权固定 APK）。本轮只读历史设备证据，不新增设备实测。

## 本轮结论

新冻结轮次 `output/expanded-review-20261108-001/`，包含三个案例、两个应用家族、五个独立采集会话。
13 道题由两个 `fork_turns=none` 的独立 subagent 审阅，第三个全新上下文逐项核对后签核。
两份初审无决策分歧；P03 保留 `insufficient`，C 未将其改为通过。

| 新材料 | 已获支持的业务范围 | 现行计分资格 |
| --- | --- | --- |
| MG4 native-004 | 目标进程完整 POST 写入、逐流身份、完整正文摘要与服务端 200；同端点 shell actor 排除 | workflow_only：没有敏感 API 读取事件，发送不能当作读取 |
| OwnTracks scenarios-008 | 前台、后台、真实断网恢复、503 与之后重试的有限业务证据 | workflow_only：专用位置契约不在正式 ha_battery 配对计分分支 |
| OwnTracks permissions-007 | 授权与恢复新值闭环；撤权约 15 秒窗口无本轮新读/流/回执 | workflow_only：不存在的读取与流不能编为负配对；不能泛化永久无外发或实际 API 拒绝异常 |

**本轮新增正式可计分 App=0，新增参考正例对=0，precision/recall 不计算。**
业务复核扩大了材料范围，没有改变现行正式评分契约、独立 App 去重方式或 10 App / 100 正例配对门槛。
历史 HA 的已签 2 条正例与 4 条负控仍单列，不混入本轮分母。
旧 MG4 W03 的不足记录和旧答卷保持原样，本轮只描述后来补齐的新会话。

## 新冻结包与签核

- `organizer-only/plan.json`：题目、范围与原始来源 SHA-256。
- `organizer-only/evidence.json`：身份、原始事件、正文哈希、独立回执及权限快照的中性投影。
- `reviewer-A/`、`reviewer-B/`：各自材料、口径与答卷，不含旧预测/旧答案。
- `reviewer-C/`：同一冻结材料、A/B 答卷和 C 签核；不继承父对话。
- `comparison.json`、`signoff-subagent.json`、`run.json`：比较、实际身份、独立 UUID、摘要与签核。
- `public-review.json`：用于本机前端的公开摘要；只发布 ID/哈希和复核内容，不暴露原始日志。
- `reference-metrics.json`：明确 not_measured，不生成虚假的配对标签文件。

实际任务身份为 `/root/expanded_blind_a`、`/root/expanded_blind_b`、`/root/expanded_signoff_c`。
来源固定 `subagent_review`，真人签核为 `not_applicable`；共享目录隔离为执行约束，相同模型可能共享错误。
独立资格调查另存 `output/expanded-evidence-20261108-investigation/`，调查结果未提供给 A/B 当作答案。
调查绑定 161 个来源摘要，核对了采集输入、Hook、装机 APK 与审计副本；未将签名来源不足补成已验证。

可复跑入口：

```powershell
. ./environment.ps1
& $VScanPython -m vehicle.bench.expanded_round prepare --out output/全新轮次
# 实际启动两个独立新上下文，并各自填写答卷后：
& $VScanPython -m vehicle.bench.expanded_round compare --out output/该轮次
# 第三个独立新上下文提交该轮 signoff-subagent.json 后：
& $VScanPython -m vehicle.bench.expanded_round finalize --out output/该轮次
```

## 前端

新增第七页“证据复核”，与当前 APK 任务选择分开。
使用 `vehicle.ps1 web --review-round output/expanded-review-20261108-001` 启动，访问 `http://127.0.0.1:8773/#review`。
页面逐例展示工作流、资格、会话、签核与边界，明确 workflow_only 不计分，也不等于失败或安全。
`/api/review-round` 只读显式目录的固定 schema 摘要；缺失不回退，不提供任意文件浏览。

当前已完成：

- 全量车载及移动侧回归 19/19 组，其中新冻结包门控初轮 8 项、HTTP/workflow 20 项、移动侧 29 项。
- 最终追加口径、路径与重复案例反例后，新包 11 项与发布门控 4 项合计 15/15 通过。
- 原页面布局与字体 47 项通过；真实复核页 44/44 项通过，包含 desktop/mobile、三案例、实际 session、签核哈希、历史切换与零计分展示。
- 最终真实页面证据：`output/vehicle-review-browser/review-1794150663805/verification.json`。
- 普通授权签核、源文件篡改、重复 agent、错误答卷绑定、强行 eligible 等反例均被阻止。
- 未修改移动端前端和现行评分契约，所有新源码不超过 300 行。

## 扩样登记

已按既有授权清单重试 Audiowagon 官方 Release 获取，输出 `output/expanded-samples-20261108-001/`。
三次解析均未取得合法 release tag，保留 `upstream_unavailable`；取得 APK=0、动态运行=0、参考配对=0。
没有改用不明镜像、重打包或将下载失败计作通过。此尝试不影响已完成的三案例新复核。

后续先处理官方 APK 来源和媒体所需 USB 条件，再逐例建立实际读取、归属请求、独立回执及可标注正负范围。
如需增加位置配对计分层，应另立规则/求值范围和独立标注轮次，不在本次回溯放宽。
