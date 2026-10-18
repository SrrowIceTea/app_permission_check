# 每个 APK 的证据风险分与 AI 研判

仅用于授权测试。工作台 `/app.html#benchmarks` 将**执行结果、风险分、AI 解释**分开呈现。
安装成功不等于安全；论文修复版标签不作为评分输入；未知维度不按零分展示。

## VSCAN-RISK-1

实现：`mobile/analyze/risk_rating.py`。这是项目自定义的、尚需专家标定的研究指标，
借鉴 OWASP 的风险分级思路和移动安全领域划分，不是官方 OWASP、CVSS 或法定合规分数。

- 单项风险信号分 = `4 × 可能性(1..5) × 影响(1..5)`，范围 4–100。
- APK 分 = 所有已识别单项的最高分，不按权限或 API 数量累加，不以平均数稀释高风险。
- 高：60–100；中：25–59；低：1–24；0：仅已测范围未检出可评分项；无证据：`null/unknown`。
- 分数不是事故概率。证据强度另列为 `observed`（行为证实）、`candidate`（待验证线索）、
  `contextual`（需结合数据和系统环境解释），不能把低分线索说成已发生泄露。

当前规则与固定取值：

| 信号 | 可能性 × 影响 | 分数 | 证据要求 |
| --- | --- | --- | --- |
| 明确 ECB 调用 | 3 × 3 | 36 | 运行时记录明确模式 |
| 默认模式未解析且同输入同输出 | 2 × 2 | 16 | 两项行为同时出现；不直接断言 ECB |
| CBC IV 复用 | 3 × 3 | 36 | 本会话重复 IV 指纹；不推断密钥相同 |
| 资源位于外部存储 | 1 × 2 | 8 | 资源哈希与实际目录对照；不推断其他 App 可读 |
| 示例文件经 TCP 明文取回 | 3 × 2 | 24 | 接收端内容及逐包/重组流独立对照 |
| 接受不受信任的自签名 TLS | 4 × 4 | 64 | 接受行为、应用层响应、服务端请求三方佐证 |
| 清单显式启用调试 | 3 × 3 | 36 | 原包 Manifest 的 application 属性；配置候选 |
| 清单显式允许明文 | 2 × 2 | 16 | 原包 Manifest；不代表实际发过敏感明文 |
| 清单显式允许备份 | 1 × 2 | 8 | 原包 Manifest；须结合 Android 版本和实际数据 |

覆盖度是五个领域（收集、存储、通信、加密、政策一致性）中具备至少一项观测或配置证据的比例。
例如 20% 只代表一个领域有证据，不表示该领域全部规则已测试。没有实际政策和同意时序时，
政策一致性保持未测。评分中所有条目都带 JSON Pointer，可回到样本证据复核。

## 真实 AI 的作用

`mobile/ai/benchmark_review.py` 一次请求可解释一批样本。输入去除作者标签、应用名与路径，
只发送匿名化技术证据；真实调用必须显式指定 `--live`。

输出必须逐样本给出摘要、待确认点、修复/补测建议、缺口和本样本证据引用。
程序校验结构、样本完整性、引用归属和不受支持的法规断言；失败结果保留但不作为有效 AI 结论显示。
引用校验不是对自然语言推理正确率的证明，重要结论仍可由审查人复核。
AI 不能修改确定性风险分，没有政策证据时不能给出合规定性。

本机密钥保存在桌面的项目外配置中，不进入源码、Git 或前端。
使用自己的配置文件和新输出目录复跑：

```powershell
python -m mobile.lab.enrich_risk --source output/root-benchmark-20261018-verified `
  --out output/root-benchmark-risk-new
python mobile/ai/benchmark_review.py --batch output/root-benchmark-risk-new/batch.json `
  --config C:\path\to\provider.local.json --out output/ai-review-new --live --attach
```

AI 产物保留请求摘要、模型、实际请求次数、用量及校验报告。派生评分不改历史采集结果；
`created_at/completed_at` 保留实验时间，`assessed_at/ai_reviewed_at` 标记后续分析时间。

`--attach` 仅在输出校验及输入一致性检查通过后附加 AI，原文件先保存在该 AI 输出目录的 attachment-backup 子目录。

## 两类测试集分别解释

- **Ghera 配对基准**：十个原始 APK 已在专用 root 模拟器真实运行，可用行为、落盘和网络对照验证。
  本轮分布为高 1、中 1、低 3、已测范围零分 5。高分来自接受自签名 TLS，不是“全部没有风险”。
- **国内真实应用观察集**：官方分发原包，保存来源、版本、摘要和签名验证。Manifest 与全 DEX 静态
  扫描能提供配置和潜在调用线索；没有实际执行时，运行阶段保持 `not_run`，不得套用论文漏洞标签。
  权限数量与静态 API 候选只提供上下文，不直接算作个人信息泄露。

后续扩大风险指标需要带真实标签的评审样本，测量误报/漏报与规则校准；不能从上述观察集直接计算准确率。

参考：[OWASP MASVS](https://mas.owasp.org/MASVS/)、
[OWASP Risk Rating Methodology](https://community.owasp.org/OWASP_Risk_Rating_Methodology)。

国内原包目录、来源和获取方式见 [domestic/README.md](domestic/README.md)。
静态接入入口：`python -m mobile.lab.domestic_static --manifest output/domestic-apk-corpus-20261018/manifest.json --out output/root-benchmark-domestic-new`。
每个样本保留清单属性和静态扫描状态；超时不会被改成扫描成功。


## 2026-10-18 本机实测结果

- DeepSeek `deepseek-flash` 实际请求 **2 次**，分别研判 10 个运行基准和 20 个国内静态样本；
  两批 HTTP 200，30 个结果均通过结构与本样本引用校验，原风险分未变。
- 国内原包 20 款：14 款完成全 DEX 静态扫描；微信、哔哩哔哩、百度地图、今日头条、天猫、QQ音乐
  在 120 秒预算内未完成，保留 failed 与已有 Manifest 证据，不计为全量扫描成功。
- 国内 16 款有低分配置线索，4 款证据不足；这不是“16 款低整体风险、4 款安全”。
  该批没有安装、登录或执行实际业务，动态阶段均未运行。
- 派生批次：`output/root-benchmark-risk-ai-20261018/`、`output/root-benchmark-domestic-20261018/`。
- 真实 AI 留档：`output/ai-benchmark-deepseek-20261018-live/`、
  `output/ai-domestic-deepseek-20261018-live/`。这些目录和 APK 都不进入 Git。
- 风险、AI、国内扫描、API 等新增定向回归 56 项通过；原移动回归 23 项通过。
  HTTP 验证 30 个样本证据接口与评分索引一致，AI JSON Pointer 均可解析。
