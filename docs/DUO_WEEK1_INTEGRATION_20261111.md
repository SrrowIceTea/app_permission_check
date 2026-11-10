# 双人一周分支集成记录

2026-11-11。仅用于授权测试。依据用户“将Gitee三个分支全部拉下合并”的请求执行。

## 合并范围

| 来源分支 | 固定提交 | 内容 |
|---|---|---|
| origin/codex/b-report-projection-20261110 | 1994e97ca2e8a0c1cb449185185a0d80be67195a | 命题证据列、不可计分原因、报告反例 |
| origin/codex/b-location-replay-20261110 | 789816f54e3a39e510127a60bbc0bab657d5f012 | 分层统计、历史只读重放、周验收工具 |
| origin/codex/b-week1-20261110 | ed11cecde6c50533d32eabe756699fe7962d6316 | 交付文档及前两项完整提交历史 |
| 本地codex/duo-b-week1 | 12213999dc03c6e7025bcdd34a40d09a6637b51e | 封存交接验收、设备/合成区分、报告与反例 |

远端三个新分支是线性依赖，合并ed11cec即包含1994e97、789816f；保留真实父提交，不重复cherry-pick。
集成先在codex/duo-week1-integration执行，验证后本地main快进到该合并结果。
origin/ch是2026-10-21至23日的另一条移动开发线，不属于本次三个新分支，未混入。
origin/main在拉取时仍为7fb35c0。当前请求只拉取并本地合并，不自动推送。
原有未跟踪的测试文档、启动/停止脚本及service_bootstrap.py未加入提交或覆盖。

## 冲突与接口整合

三个冲突文件：tools/real_sample_result.py、tools/run_regressions.py、vehicle/bench/claim_scope.py。

- 使用远端evidence_cell作为业务证据列唯一入口，保留本地五类unscored原因、结构校验和独立定位报告参数。
- 统一两侧不可计分文案，兼容已有调用；不恢复整轮业务证据兜底，不把未观测的漏检称为正确。
- 根回归同时登记两侧所有测试；分层统计保留为实验投影，兼容本地身份/窗口可比组合计数。
- 远端历史重放编排与本地新设备交接验收并存，前者不替代后者的健康/回执门禁。

## 集成时确认并修复的问题

1. 历史重放layer_view把all(not origin_proven)写进origin_proven，会把正确的false候选投影成true。
   现在始终保留实验来源未证明，并单独计异常来源声明，防止层级升级。
2. 记录缺失时all(empty)使部分B04/B05/B06通过；只有一套回归存在时B10也可能通过。
   现要求非空、全部成功、逐项元数据、三套回归齐备；缺失保留not_run或fail。
3. 空合成集合不能证明六类用例；单版本规则不能证明四版本范围。现在验证完整集合。
4. 缺冻结统计时comparison不能硬编码“比率未变”；缺重放/合成输入时检查表不再自动写verified。
5. 重放缺源文件、CLI失败、验收缺项现在返回非零，保留索引/诊断；staging和输出禁止放在源capture内。

新增tools/test_week_b_integration.py共8项反例，与两侧原测试一起登记执行。
集成定向7模块74项通过；最终根/移动兼容结果以以下固定目录的verification为准。
所有本轮源文件均不超过300行；安全守卫没有关闭。

## 复验与证据

固定目录：output/duo-week1-integration-20261111/，原失败/历史产物不覆盖。
targeted.log记录74项；root/记录根回归；branch/复制ASCII路径运行的完整移动分支回归（含移动63项）。
integration-verification.json记录实际提交、三个源提交可达性、代码摘要、文件行数及回归结果。
移动兼容沿用本机已验证配置：JDK_JAVAC_OPTIONS=-encoding UTF-8，输出和TEMP/TMP使用ASCII临时路径；
没有关闭项目安全守卫，不宣称默认中文临时路径问题已修复。

```powershell
.\tools\python313.ps1 -m unittest tools.test_week_b_integration tools.test_report_projection vehicle.privacy.test_location_layers vehicle.privacy.test_location_acceptance vehicle.bench.test_duo_projection vehicle.bench.test_claim_scope vehicle.bench.test_claim_verdicts
.\tools\python313.ps1 tools/run_regressions.py --out output/duo-integration-new-root
$env:JDK_JAVAC_OPTIONS = '-encoding UTF-8'
.\tools\python313.ps1 tools/check_mobile_branch.py --out C:/Users/OneKyubey/AppData/Local/Temp/duo-integration-new-branch
.\tools\python313.ps1 tools/test_inventory_guard.py
```

## 设备验收边界

这三个分支的提交说明和docs/ONE_WEEK_B_20261110.md均标识为B侧；后者明确说明本周无新设备采集、
无新会话、无新标签。output被git忽略，三个提交没有附带原始采集包。
因此这次完成代码合并，不能据此声明A的设备正负控/第三方工作流已交接或验收通过。
远端交付文档中的历史主机测试结果仍是其原轮次记录，不能冒充本机本轮测试。
新设备包接入使用docs/DUO_LOCATION_HANDOFF.md及vehicle.privacy.location_acceptance。
默认不启用VSC-GE-location、不输出policy_violation，不承诺P/R提高。
