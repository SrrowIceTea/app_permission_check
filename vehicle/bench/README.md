# 独立公开样本评估

仅用于授权测试（自有设备与用户明确授权下载的公开第三方 APK）。

## 入口

```powershell
./vehicle.ps1 samples --out output/my-vehicle-samples
./vehicle.ps1 benchmark --manifest output/my-vehicle-samples/manifest.json --out output/my-benchmark
./vehicle.ps1 overhead --pairs 6 --actions 4
```

`overhead` 是自有 AAOS 夹具上的 Hook 开销量：有/无 Hook 两臂交替执行同一
`plain` 工作负载（读取 8 个 VHAL 属性并 POST 到 `/collect`），按配对比较应用进程
CPU（`/proc/<pid>/stat` 的 utime+stime）与主机墙钟。产物写在
`output/vehicle-hook-overhead-<ts>/`：`runs.jsonl`（逐轮原始数据，失败的臂也保留）、
`overhead.json`（机器可读汇总）、`report.md`（可读报告）。每轮使用唯一动作 ID，
目录同时封存实际执行的 bundle，报告包含装机 APK 和 bundle 的 SHA-256。

```powershell
./vehicle.ps1 overhead --pairs 4 --actions 12   # 放大工作负载，信号高于模拟器噪声
```

历史实测（2026-11-02）：
- `--pairs 6 --actions 4`：中位 CPU 增量 0 ms（出现负增量），夹具噪声大于 Hook 开销；
- `--pairs 4 --actions 12`：中位 CPU 增量 845 ms（相对无 Hook 基线 77.5%），
  Hook 每轮记录 276 条 `VHAL_READ`、12 条外发事件。
两份都只能说明该夹具该工作负载的稳态执行成本，不能外推到第三方 App。
**检测准确率未测量**：没有独立人工标注，CPU/墙钟开销不能冒充 precision/recall。

O4 同负载复测使用同一 AAOS 35 指纹和同一装机 APK：

| 4 配对 × 12 动作 | CPU 增量中位 | P95 | 每臂读取记录 / 合并记录 |
| --- | ---: | ---: | ---: |
| [当前基线](../../output/o4-heavy-before-20261103-224542/overhead.json) | 1000 ms | 1340 ms | 276 / 0 |
| [批传输与嵌套合并](../../output/o4-heavy-after-20261103-224953/overhead.json) | 420 ms | 970 ms | 156 / 120 |
| [最终版](../../output/o4-heavy-verified-20261104-134058/overhead.json) | **205 ms** | **260 ms** | 156 / 120 |

最终版减少重复取值和栈处理，重载达到中位 ≤400 ms 的目标，较本轮基线下降 79.5%。
每个有 Hook 的测试臂均保留 96 次主读取和 12 次外发。四组读取的属性、结果、API、区域和取值形状一致；
每臂 190 条事件均获宿主刷盘确认。P95 按最近秩计算，四对时等于最大值。
恢复模拟器后的诊断轮有两组因新单条回传兼容问题无效，原始失败保留，修复后完整重跑四组。
[最终版轻载](../../output/o4-light-verified-20261104-134218/overhead.json) 六组全部通过，CPU 增量
中位 35 ms、P95 110 ms。每臂 32 次主读取与 4 次外发，70 条事件均获刷盘确认。
[最终版 O2 新采集](../../output/o4-o2-live-retry-20261104-134344/primary-window-calibration.json)
覆盖断网入队、恢复网络与延迟发送。自有夹具的 10 条主读取参考配对全部对齐，其中 5 条跨过 30 秒，
无额外配对或漏配，保留人工签核项。首次挂载失败单独留档，夹具就绪后的重试完成。

只从上游正式 Release 获取 APK，不使用账号规避、破解分发或重打包。清单记录仓库、
确定的 release tag/下载地址、SHA-256、实际清单权限/minSdk/targetSdk、许可来源和失败重试。
不同构建变体按同一 family 计数，不包装成多个独立 App。发布方签名没有核实的状态单独保留。

下载成功不等于安装成功；静态候选不证明动态读取；未标注结果不计算 precision/recall。
读取总数合计 VHAL 与通用隐私事件，并分列两类计数；通用成功只计 obtained。
开销统计排除 passed=false 的测试臂及其配对，失败记录仍保留在原始数据与 failed_runs 中。
需要后台服务器、账号或 USB 媒体的 App，未满足条件时必须标注业务探索范围不足。
手机投屏与未适配侧载对照不能混入原生 AAOS 的分母。

## 动态绑定

### 重放已有的三家样本

`./vehicle.ps1 benchmark --suite vehicle/bench/aaos35-suite.json`
读取本地封存证据和 APK。输入路径相对于项目根，摘要不匹配时对应案例失败。需先有清单指定的本地文件，尤其是未随 Git 分发的 `output/` 证据。
APK 的签名验证与发布方证书独立核验分列。HA 与 MG4 重跑常规审计，YAABSA 核对脱敏请求、服务端会话和暂停记录。
`completion=complete` 表示各案例已按各自证据口径复核，MG4 仍可登记正文归因缺口。
摘要分列业务、采集健康、身份归因、正文匹配和人工签核。

输出的 `review-packet.json` 收录全部案例。HA 电量提供读取与请求配对复核入口，
HA 控制、MG4 与 YAABSA 的业务回执按各自证据口径登记。使用下面的命令把 O2 自有夹具
作为独立一组加入复核包：

```powershell
./vehicle.ps1 benchmark --suite vehicle/bench/aaos35-suite.json `
  --fixture-capture output/vehicle-offline-window-20261103-002/capture `
  --fixture-labels output/o2-batch-pairing-20261103/primary-labels.json
```

先在自有 AAOS 35 上以普通第三方身份安装/运行样本；不授予特权、不替换签名、不重打包。
用 `vehicle.ps1 capture --package 实际包名 --user 10 --seconds 60 --out output/my-capture` 采集。
可显式指定 `--activity 包名/.Activity`；没有 launcher Activity 的媒体应用需从车机媒体入口启动。
采集期间按实际功能操作，测试设备一次只运行一个审计任务。

`--captures captures.json` 接受如下结构，路径使用明确的本机路径：

```json
{"samples":[{"id":"清单中已有的样本ID","capture":"本轮采集目录","scenarios":"本轮场景清单，可省略","policy":"政策快照清单，可省略"}]}
```

绑定会再次核对 APK/包名/普通安装身份/会话/规则/Hook/采集健康。错误不能变为正常零发现。
默认严格归因不会把设备中所有流量兜底给唯一白名单包；无法归因只保留计数、不保留其他包正文。
忽略系统代理、WebView 子进程、native/二进制协议与连接复用仍可能造成覆盖缺口。

## 独立标注

首轮试标从封存记录生成两个审阅包和一份组织者材料。组织者只分发 `reviewer-A.zip`
与 `reviewer-B.zip`，保留 `organizer-only/`。审阅包只含必要的原始观测字段和独立回执，
HA 电量配对与其他业务问题分开。候选由同会话电量读取与请求的笛卡尔积得到，
包括时间顺序或数值不符合的交叉组合。这些组合由人工判定，并在仲裁时确认负控标记。

```powershell
. ./environment.ps1
& $VScanPython -m vehicle.bench.blind_round prepare --out output/o3-blind-pilot
& $VScanPython -m vehicle.bench.blind_round compare --organizer output/o3-blind-pilot/organizer-only --review-a review-A.json --review-b review-B.json --out output/o3-adjudication
```

两份答卷须由不同审阅者完成，且绑定同一份证据和配对表。比较命令生成分歧清单及单独的业务答卷。
配对题存在证据不足时保留补证项并暂停生成计分草稿。草稿始终待签，第三位审阅者填写分歧决定和
全部负控标记后再人工签核。历史 HA 电量会话绑定当时的规则库，后续重放须使用匹配的历史规则快照。

从复核包中选取支持配对评分的样本，使用其 APK、会话、来源、参考文件及 SHA-256。
评审人根据独立业务回执和采集事件构建 `universe`，包含未被工具命中的正例和明确负控。
每项形如 `{"pair":[rule_id, read_src, read_event_id, flow_src, flow_event_id],"negative_control":false}`。
`reviews` 包含两名独立标注人的 `reviewer/reviewed_at/decisions`。每项决策包含 `pair` 和布尔值
`present`。两人各自标注全部范围。第三位仲裁人用同结构在 `adjudication` 中处理全部分歧。
时间使用带时区的 ISO 8601。完成后设置 `human_signoff=signed`，把配对案例放入
`{"samples":[...]}` 并通过 `--labels` 提交。

每案输出 `metrics.json`，汇总写入 `benchmark-metrics.json`。各层按读取来源、传输路径、
样本来源、标注来源及证据指纹区分。输出 Wilson 95% 区间、Cohen's κ 和显式负控误报率。
空分母、未审阅预测及待签层保留空值和原因。旧三元组继续供历史窗口重放使用。
O2 的 agent 初评单列，人工签核和独立样本规模决定对外验收状态。

统计包含观测量、歧义/无法归因、正文不可用和已关联间隔分位数。后者存在选择偏差，
不能据此宣称窗口覆盖率；Hook 开销用上面的 `overhead` 配对实验测，旧文档里
「当前不编造」的缺口已由该入口补上；准确率仍须独立标注才能计算。
夹具初评见 [窗口校准记录](WINDOW_CALIBRATION.md)。独立应用的延迟分布与人工签核仍待积累。
命令正常退出表示该轮评估流程执行完成；是否完成动态评估应读 `completion`、样本状态和标注状态，不能只看退出码。

## 政策快照

`--policy` 接受 JSON 元数据：`package/apk_sha256/document_kind/file/sha256/source/content_type`，
可加 `business_context: {app_category,purpose}` 与 `applicability`。
文件放在元数据同目录内；用户协议须为 `app_agreement`，不冒充主政策。
输出规范化正文、字符位置与来源摘要，关键词仅用于定位片段，必要性由人工复核。
公共网站的当前快照使用 `current_official_snapshot`，不假称对应历史发布版本。
