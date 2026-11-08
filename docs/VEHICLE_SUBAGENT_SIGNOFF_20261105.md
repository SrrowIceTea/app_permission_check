# Subagent 独立复核与签核

2026-11-05。用户指定的默认流程。仅用于授权测试。
本说明取代“本项目必须三位真人签核”的默认安排；真人流程作为显式可选方式保留。

## 流程

1. 冻结题目、证据、来源文件和摘要，准备 A/B 两份空白审阅包。
2. 启动两个 `fork_turns=none` 的 subagent，分别只读自己的包，不能看历史答案、组织者材料、
   工具预测或对方答卷。父 agent 不向它们提供期望答案。
3. A/B 各自回答全部题目，逐题给出证据引用和理由；不足写 insufficient。
4. 收卷后运行 compare，核对来源和摘要、列出分歧。配对题不足时暂停，先补证。
5. 启动第三个全新上下文 subagent C，只读本轮冻结证据、A/B 答卷及签核请求，
   复核全部负控并处理配对分歧。不能确认的项保留未签，不能用多数票补证据。
6. C 提交签核表后运行 blind_signoff，再用采集时的历史规则快照评估。
7. 单列 subagent 指标、业务缺口及基准验收状态，保留原始答卷和实际启动记录。

当前实现负责准备、比较、签核校验和指标；启动 subagent 由 Codex 的协作工具执行，
不是在 Python 命令里伪造三份答卷。以后可直接要求“按默认流程运行一轮 subagent 盲审”。

## 身份与签核格式

每份答卷及 C 的签核表均需真实填写：

- reviewer：可追溯的 agent 身份；reviewer_kind="subagent"。
- agent_id：实际启动任务的 canonical name；A、B、C 各不相同。
- context_mode="fresh"：新上下文，不继承包含工具预测的父对话。
- review_session_id：本次评审的独立 UUID；三个会话各不相同。
- reviewed_at：实际带时区 ISO 8601 时间。
- 保留题号、pair、schema 和计划/证据/答卷摘要；逐项提供理由。

C 的 controls 全量确认 negative_control；disagreements 全量确认 present，均用 JSON 布尔值。
实际核对完成后才设置 confirmed=true。业务题另存复核结果，不混入 HA 电量配对评分。

输出来源固定为：

```json
{
  "review_mode": "subagent",
  "origin": "subagent_review",
  "signoff_status": "signed",
  "subagent_signoff": "signed",
  "human_signoff": "not_applicable"
}
```

普通旧 AI 初评不能仅改 reviewer_kind 就变成这类签核；缺来源信息、重复 agent/会话、
继承上下文、摘要不匹配、证据不足或混用人/agent 答卷均不能生成已签标签。

## 命令

项目根目录中加载环境后，新 prepare 默认 subagent；输出目录须为新目录：

```powershell
. ./environment.ps1
& $VScanPython -m vehicle.bench.blind_round prepare --out output/my-subagent-round
```

确需真人轮次时，prepare 显式加 `--review-mode human`，新轮次不能混用两类身份。
历史未记录 review_mode 的冻结计划可以由两份完整 subagent 来源记录确定模式，
无需修改原始包或来源文件。

实际启动 A/B 并收齐答卷后：

```powershell
& $VScanPython -m vehicle.bench.blind_round compare `
  --organizer output/my-subagent-round/organizer-only `
  --review-a <本轮A答卷> --review-b <本轮B答卷> --out output/my-subagent-compare
```

`awaiting_subagent_adjudication` 表示可以启动 C；`awaiting_pair_evidence` 表示配对题缺证据，
须先补证、重新冻结和复核。不能跳过比较或让 C 猜测缺失事实。

C 提交签核表后：

```powershell
& $VScanPython -m vehicle.bench.blind_signoff `
  --organizer output/my-subagent-round/organizer-only `
  --review-a <本轮A答卷> --review-b <本轮B答卷> `
  --signoff <C提交的签核表> --out output/my-subagent-signed
./vehicle.ps1 benchmark --suite vehicle/bench/aaos35-suite.json `
  --rules output/o6-device-acceptance-20261104/rules-before-o6.db `
  --labels output/my-subagent-signed/labels-signed.json --out output/my-subagent-scored
```

上述历史规则参数适用于当前 aaos35-suite；新采集必须使用各自匹配的规则快照。
核对 evaluation.json 的 completion、逐案结果和 subagent_signed_cases，不能只看退出码。
benchmark-metrics.json 分别输出 human_reference_metrics、subagent_reference_metrics、
各自的样本量和 benchmark_acceptance_by_review_mode。

## 证据边界

子 agent 使用共享工具与工作目录，“只读各自材料”是本轮执行约束，不是文件系统权限隔离。
来源字段和摘要校验也不是不可伪造的执行证明，需同时保留实际启动身份与运行记录。
同模型可能产生相同误判，不能因两者一致就声称比真人准确。

本轮 HA 电量配对可对 subagent 参考范围计量；其他六道业务题单独复核。
新 MG4/OwnTracks 设备补测不改写历史盲审包，不直接扩成本轮计分样本。
即使本轮配对结果全部一致，仍不代表达到整个车载平台的准确率或样本规模验收门槛。

本轮目录：output/subagent-signoff-20261105-224116/。
实际结果以其中的签核表、signed/labels-signed.json、scored/ 与 verification.json 为准。
