# AAOS 35 双人交接与首轮盲评

2026-11-04。仅用于授权测试。主线为普通第三方 AAOS App，自有夹具与侧载对照单列。

## 交付状态

| 案例 | 当前证据 | O3 计分资格 |
| --- | --- | --- |
| HA 电量 | 固定 APK 的电量读取、请求字段、独立服务端状态。两次变值离线复验对齐 | `VSC-LAB-HA-BATTERY-HTTP-001` 的 6 个候选组合进入首轮盲评，签核待完成 |
| HA 控制、MG4、YAABSA | 6 个业务复核题。HA 控制含成功及 503。MG4 应用内请求与自有表单回执对齐，代理逐流归因缺失。YAABSA 的播放和 native 发送证据按各自路径登记 | 业务验收题单列 |
| OwnTracks | 固定 APK 的两组定位回调、归属到该 App 的代理 POST 和独立回执。以侧载对照计 | `workflow_only`。现有通用定位规则 `VSC-GR-location` 未消费专用回调，通用外发求值器未覆盖数值坐标正文 |
| AAOS 35 自有夹具 | AAID 四态已验收。8 项 VHAL 同步读取含 5 项成功、3 项拒绝，另有挡位实际订阅回调 | 夹具验收独立于第三方指标 |

覆盖链以现行规则库生成，包含 16 行和固定样本的限定条件。单独的设备矩阵同时保留属性权限定义、应用声明、实际授予快照与事件结果。历史 VHAL 会话绑定了权限声明和读取事件的摘要，未绑定同目录 `dumpsys-package.txt` 的摘要，权限实授在导出中注明这一限制。详见 [覆盖链](../vehicle/coverage/generated/COVERAGE.md)、[设备矩阵](../output/aaos35-team-coverage-20261104/COVERAGE.md)和 [OwnTracks 样本复核](../vehicle/lab/SAMPLE_RUNTIME_REVIEW.md)。

报告用 `observed` 表示直接取得的运行时证据，`candidate` 表示需复核的关联，`static` 表示清单或静态事实。单列权限拒绝、业务未触发、已触发但 Hook 未覆盖、正文未解析、无法归因和采集失败。常规第三方关联仍为 30 秒。批次令牌配对留在协作夹具评估中。

## 人工盲评交接

分别交付 [新版审阅包 A](../output/aaos35-team-blind-20261104-r2/reviewer-A.zip)和[新版审阅包 B](../output/aaos35-team-blind-20261104-r2/reviewer-B.zip)。两个包都包含同一份证据、6 道 HA 电量配对题、6 道独立业务题及各自的空白 `review.json`。答卷提交前只看自己的包，暂缓查阅业务交接包和审计预测。`organizer-only` 由组织者保管。

旧答卷属于 AI 初评。新版证据卡补充了代理见到 POST、服务端标记匹配及逐流归因数量。新版答卷须绑定新证据摘要，旧答卷保留原绑定。组织者复核材料见 [修正版说明](../output/aaos35-team-adjudication-r2/REVIEW.md)。

收到两份真人答卷后运行以下命令，两位均填写 `reviewer_kind=human`。证据不足项留待补证。配对证据齐全时生成 `signoff-request.json`，由第三位真人在副本中填写身份、带时区时间、每个负控标记、每项配对分歧的决定与理由，并设置 `confirmed=true`。第三位复核者也填写 `reviewer_kind=human`。签核前保持 `pending` 和 `not_measured`。

```powershell
. ./environment.ps1
& $VScanPython -m vehicle.bench.blind_round compare `
  --organizer output/aaos35-team-blind-20261104-r2/organizer-only `
  --review-a <答卷A.json> --review-b <答卷B.json> --out output/aaos35-team-human-adjudication
```

收齐真人签核表后生成正式标签。程序重新核验冻结材料、两份答卷、负控和仲裁结果。原始签核文件和标签都应保留。

```powershell
& $VScanPython -m vehicle.bench.blind_signoff `
  --organizer output/aaos35-team-blind-20261104-r2/organizer-only `
  --review-a <答卷A.json> --review-b <答卷B.json> --signoff <已填写的签核表.json> `
  --out output/aaos35-team-human-signed
./vehicle.ps1 benchmark --suite vehicle/bench/aaos35-suite.json `
  --rules output/o6-device-acceptance-20261104/rules-before-o6.db `
  --labels output/aaos35-team-human-signed/labels-signed.json --out output/aaos35-team-scored
```

使用相同规则快照、不传 `--labels` 已重放 7 个封存业务案例。该检查确认历史规则和证据可重放，准确率仍为 `not_measured`。签核后的指标只适用于该批参考配对。

如需重新生成审阅包，使用 `vehicle.bench.blind_round prepare --out <新目录>`。新版保持原始案例、题号和源文件绑定，修订后的证据摘要与旧轮次分开。ZIP 本身包含打包时间，以实际生成的 ZIP 摘要校验分发副本。

## 脱敏离线重放

解压 [业务证据交接包](../output/aaos35-team-handoff-20261104.zip)，从自己的项目目录运行以下命令。若需只读检查 Python 依赖，先加载 `. ./environment.ps1`，再运行 `& $VScanPython -c "import PIL"`。环境准备和设备采集继续使用 `vehicle.ps1 prepare` 与 `vehicle.ps1 capture`。

```powershell
./vehicle.ps1 handoff replay --package <解压目录>
```

交接包有统一索引和两个最小证据文件。索引登记 APK、装机身份、会话、规则库和 Hook 摘要、历史目录快照、证据文件及复核状态。重放复用 HA 电量求值与 OwnTracks 的读流回执配对检查，验证每个投影文件的摘要。包内仅有演示所需电量、合成坐标、测试事件、状态和摘要。原始报文、令牌、完整请求地址、运行日志和 APK 留在授权设备环境。

此入口支持脱敏业务证据重放。完整设备采集与审计仍以原始会话、实际 APK、历史规则和 Hook 为依据。归档规则的区别很重要，HA 采集绑定 O6 前规则库，OwnTracks 绑定 O6 后规则库。导出时对源文件逐项校验，也将历史目录快照与采集摘要及当前支持的 Hook 契约逐项比对。

```powershell
./vehicle.ps1 handoff export --out <新目录> `
  --ha-rules output/o6-device-acceptance-20261104/rules-before-o6.db

./vehicle.ps1 coverage --out <新目录> `
  --vhal-capture output/o6-device-acceptance-20261104/vhal/capture `
  --capture-catalog output/o6-device-acceptance-20261104/aaid-audit/privacy-catalog.json
```

复现检查使用一份独立 Python 源码副本，未复制原始采集目录或规则库。HA 和 OwnTracks 各对齐 2 组证据，篡改和缺失文件均被拒绝。详见 [交接包验证](../output/aaos35-team-handoff-20261104.verification.json)。
