# 车载场景与验收口径

仅用于授权测试。测试 Actor 可以构造正反例，观察 Hook 始终只记录、不改写。

| 场景 | 执行入口 | 必须观察到的证据 | 范围/未覆盖 |
|---|---|---|---|
| 只读不发、正常上传、同名异值、摘要上传、延迟上传 | `tools/vehicle_scenario_acceptance.py` | 有成功读取的正控，按内容/窗口得到预期配对 | 自有夹具；延迟不是全市场分布 |
| 后台与 Android 权限拒绝 | 同上 | 实际前台状态；拒绝事件不作为成功采集 | 权限拒绝不能替代同意撤回 |
| 同意后读取，UI 撤回后停止 | `tools/vehicle_context_acceptance.py` | 真实自有同意 UI XML、点击后状态、夹具回执、撤回后无新读取/上传 | 独立 App UI 需要逐应用操作记录 |
| UI 撤回后仍读取的反例 | 同上 | 真实撤回状态、后续读取、人工复核提示 | 不自动判政策违规 |
| 缓存两批，撤回后上传 | 同上 | 读取在前、持久缓存回执、撤回 UI、之后外发 | 不是断网重连测试；当前 30 秒窗口仍有限 |
| 显式清理缓存再尝试上传 | 同上 | 有读取正控、清理后 cache_empty 回执、无流量 | 只验证自有缓存实现 |
| 换用户后新用户读不到旧缓存，切回后原缓存仍在 | `tools/vehicle_user_acceptance.py` | 两用户均有读取/外发正控、不同 UID、新用户空缓存、原用户恢复缓存 | Android 用户切换，不推断实际驾驶员身份 |
| 模拟停车→行驶→停车 | `tools/vehicle_context_acceptance.py` | 当前镜像 help 中的 emulate-driving-state 命令、实际 CarDrivingStateService 变化、每阶段读取/外发 | 已有模拟器验收；不代表真实车辆或道路状态 |
| 模拟器断网→重连后队列上传 | 同上 | Wi-Fi 关闭、wlan0 链路 down、实际连接失败/持久缓存、恢复后的成功上传 | 必须直连宿主回环并使用 NO_PROXY；不代表蜂窝或公网故障 |
| 休眠→唤醒、点火周期 | 场景导入契约已支持 | 实际设备电源状态记录、时间、同会话身份、来源与摘要 | 未完成设备驱动；不猜测车型/厂商控制命令 |

## 执行记录

`scenarios.json` 是数组，每项必须有 `id/package/session_id/start_ms/end_ms/context`。
已知 consent/vehicle_state/network 必须附 `context_evidence`：相对文件路径、SHA-256 和来源类型
（`ui_observation`、`adb_state`、`owned_fixture_receipt`、`synthetic_control`）。
输入缺失保持 unknown。时间不能倒置；不能跨会话/包名套用；`user_id` 限定该场景统计的用户。
合成输入只能证明分析语义，不能算设备通过。原始 UI/回执保留在同轮目录。

驾驶状态属于观察上下文。当前自有模拟器的状态控制是独立测试 Actor，有该镜像命令帮助与服务状态依据，
不能放进观察 Hook，也不能套用到真实车辆。结束返回安全的模拟停车状态，Wi-Fi 恢复实际连接。

## 本轮真机执行记录（2026-11-02）

场景证据：`output/vehicle-context-20261102-140807-70d2d7/verification.json`（6/6 通过）。
用户切换证据：`output/vehicle-users-20261102-205712/verification.json`（5 个用例、12/12 项 checks）。

| 场景 | 预期 | 实际证据 |
|---|---|---|
| `consent-stop` 同意后读取、UI 撤回后停止 | 同意状态可读、有上传；撤回后同一动作不再读取/上传 | 真实同意 UI XML 与点击后状态；grant 后 `consent_respected` 读取 8 次、HTTP 200；revoke 后同一动作 `suppressed_by_fixture_consent=true`；23 读取 / 1 流量 / 14 值级配对，14 项 checks 全 true |
| `consent-ignored` 撤回后仍读取 | 撤回状态已确认，后续读取仍被观测到，只提示人工复核 | UI XML 确认 revoked；`consent_ignored` 读取 8 次、HTTP 200；`read_after_revoke_observed=true`，不自动判政策违规 |
| `cache-after-revoke` 缓存两批、撤回后上传 | 读取在前、两批持久缓存、撤回后仍能上传 | 两次 `cache_collect` 各 8 次读取、`cached_batches=1/2`；撤回后 `cache_flush` HTTP 200；46 读取 / 28 配对，13 项 checks 全 true |
| `cache-cleared` 显式清理缓存 | 清理后回执为空、无外发 | `cache_empty=true`、`flows=0`；23 读取仅来自清理前的 `cache_collect`；不把“未观测到上传”当安全结论 |
| `offline-reconnect` 断网→重连队列上传 | Wi-Fi 关闭时真实失败并缓存，恢复后成功上传 | `wlan0` DOWN、`network_enqueue` 报 `java.net.ConnectException` 且缓存；恢复后 `cache_flush` HTTP 200；1 条 `/collect` 归属夹具（Host=10.0.2.2、上游 127.0.0.1） |
| `vehicle-transition` 停车→行驶→停车 | CarDrivingState 实际变化，每阶段读取/外发 | `observed_state_code` 0→2→0；46 读取 / 14 配对；14 项 checks 全 true |
| 用户切换缓存残留 | 新用户读不到旧缓存，切回后旧缓存仍在 | 原用户种子缓存成功；新用户 `cache_empty=true`、`flows=0`；切回后 `cache_flush` HTTP 200；两用户 UID 不同、12 项 checks 全 true |

`--denied` 的后台/Android 权限拒绝只证明权限缺失下的行为，**不是**同意撤回的证据，两者不得互换。
以上均为自有夹具与当前 AAOS 35 镜像，不外推到第三方 App 或真实车辆。

## 判据

- 正反例都要有采集器就绪、非空正控、正常退出及原 PID 存活证据。
- 缓存外发提示不依赖撤回窗口内出现新的读取，但只提示检查报文与撤回范围。
- 不同用户的读/流量不关联；缓存残留实验与归因隔离实验分别判定。
- 首次安装之前、attach 之前和未探索界面的行为不在当前观察范围内。
