# 同伴采集交接（2026-11-04）

> 用户补齐 APK 与镜像后的新结果见 [同伴续验](COMPANION_FOLLOWUP_20261104.md)。下文保留首轮状态。

仅用于授权测试。范围为当前主机的自有 AAOS 35 模拟器、普通第三方安装的固定 MG4 APK 和合成表单。
本轮完成 B1 的限时实验与缺口交付，B2 尚未完成，B3 完成浏览器前后台场景部分。
不得把脚本开发、历史文档中的通过记录或单元测试当作新的设备验收。

## B1：完成实验，保留逐流归因缺口

最终轮次 `output/companion-20261104/mg4-run-007/`。
session 为 `capture-07ace67e846a49c6a0795f5ab7a93843`。

- MG4 官方 1.0.2 原版 APK，SHA-256 为
  `376b931673869c0ac6a23fb719a4b642252eae6cab0fd1fc436d182ded4cf396`。
  来源：<https://github.com/Tommasov/MG4_WebBrowser/releases/tag/1.0.2>。
- GET 导航、链接、返回、刷新均有 UI 与接收端记录。`business.json` 单列 GET 回执和 GET 归因数量。
- 目标 POST 有 `mg4_webview` 事件、宿主 UID、随机标记和独立完整正文摘要。
  代理看见 POST，但 `post_flow_attributed=0`。不声称找到了 WebView 网络进程到代理连接的稳定映射。
- 同一设备、同一轮、同一 POST URL，另外两个 shell 进程分别发 GET/POST；
  `control_process.requests` 保存各自实际 PID、UID、起止时刻、响应状态及正文摘要。
  对照是 UID 0 的 shell 发送者，不是第二个普通 App，也不是 WebView 隔离进程。
  对照 POST 与独立回执相符，没有被归给 MG4；代理身份保持未知/丢弃。
- 完整采集健康通过，包括原 PID 存活、APK 不变、代理与 reverse 恢复、worker 清理及 callback 健康。
- 结论仍为 `webview_receipt_linked`，依据是替代证据；无法归因的代理正文继续丢弃。
  两人计划允许限时找不到稳定映射时交付此缺口并切换后续任务。

失败轮保留：`mg4-run-002` 的 Hook 契约摘要不匹配导致主采集未就绪；
`-004/-005` 的设备对照管道失败。`-003` 只验证了宿主进程对照，不能替代同设备对照；
`-006` 已验证同设备对照，`-007` 进一步补齐 Activity 场景记录。
没有 `-001` 证据目录；其启动命令阻塞，已取消，不能算一次完成的采集。

复现：

```powershell
$env:VSCAN_SDK = 'E:\Android\android-sdk'
$env:PYTHONUTF8 = '1'
& .venv/Scripts/python.exe -m vehicle.privacy.catalog
& .venv/Scripts/python.exe -m core.frida_host.build --platform vehicle --only hook_vehicle_mg4.js
& .venv/Scripts/python.exe -m vehicle.lab.browser_run --serial emulator-5554 --webview-probe --control --out output/companion-new-mg4
```

要求设备 API 35、前台 user 10、已运行的普通 MG4 进程和本地 27043 观察服务。
目标 APK 必须匹配契约；不能仅用另一版本替代。HTTP 接收端由脚本在宿主实际网卡地址的 18124 端口启动。
主采集器控制 8888 代理和 reverse；独立进程只通过本轮代理发送合成请求。
输出目录须为全新路径。失败看 `business.json`、`capture.log` 和 `capture/verification.json`。

## B2：尚未完成设备外发路径与负控

本轮启动时 user 10 只有自有 targetapp、targetapp2、rules；此后只安装了固定 MG4。
当前检出 `apk/` 不含路线图的固定第三方 APK，11 月 3–4 日引用的历史会话也不在此检出。
恢复旧 AVD 后的实际指纹与历史文档不一致，不能套用旧的设备验收。

| 筛选对象 | 当前可核查条件 | 结论 |
| --- | --- | --- |
| HA Automotive | 已有原生业务采集入口；固定 APK、隔离 HA 运行配置与旧回执本地缺失 | 待恢复基线；未跑新正控/负控 |
| YAABSA | 已有原生媒体业务采集入口；固定 APK、隔离 ABS 配置及样本本地缺失 | 待恢复基线；未跑新正控/负控 |
| OwnTracks | 已有两测试值的采集器；固定 APK、已导入的 HTTP 配置及接收地址本地缺失 | 侧载对照，尚未复跑；不能充当新增原生 AAOS 路径 |
| GPSLogger | 历史记录只有注册调用；固定 APK 与异步回调验收本地缺失 | 侧载诊断待做；不能把注册成功当获得定位 |
| MG4 | 本轮已实际通过自有 HTTP 表单与前后台恢复 | 不是新增敏感读取外发路径 |

新增 `owntracks_run --scenarios`：第一个新坐标在前台、第二个在后台，第三个新坐标由独立接收端实际返回 HTTP 503。
正例要求读取、代理、回执一致；503 也要求三侧一致并且不能计为成功外发。
明确 `permission_result=not_tested`，不把 HTTP 拒绝说成权限拒绝。
核对完整正文真实 SHA-256、UID 所属用户、同会话与 30 秒窗口。
此入口只有离线验证，**未取得本轮 OwnTracks 设备验收**。

```powershell
& .venv/Scripts/python.exe -m core.frida_host.build --platform vehicle --only hook_vehicle_owntracks.js
& .venv/Scripts/python.exe -m vehicle.lab.owntracks_run --config <已配置的本轮JSON> --apk <固定原版APK> --scenarios --out output/companion-new-owntracks
```

OwnTracks 配置与 SHA 限制沿用 `SAMPLE_RUNTIME_REVIEW.md` 和 `vehicle/privacy/owntracks_contract.py`。
不能从工具预测反推参考答案。后台触发不到、重复回执或采集不健康均保留失败。

## B3：前后台部分通过，读取诊断和重连待做

MG4 最终轮的 `scenario-observations.json` 记录 10 次 Activity 观测，
每次引用独立文本及摘要；`09-background` 为后台，`10-resume` 恢复前台。
同名 `ui/` XML、PNG 及摘要支持业务复核。这些是离散观测，不宣称连续后台运行或后台外发。

OwnTracks 新入口也采集前后台边界；它不在后台点击前台的“上报”菜单来伪装后台触发。
没有新点回执则失败。HTTP 503 不等同于断网重连。
Fossify 启动查询、GPSLogger 异步返回、断网/恢复链路与独立回执仍未完成。
OpenTracks 未复核业务触发，因此没有据零调用新增 Hook 缺口结论。

## 验证与交接

- 相关 16 项离线测试通过，含真实本地 HTTP 503 接收端、错误摘要、跨用户身份、重复/过期回执、前后台状态缺失。
- 完整 `tools/run_regressions.py --mobile`：17 组中 16 组通过，含移动端组
  （当时口径；现行为 18 组根回归、带 `--mobile` 19 组）。
  `vehicle-pipeline` 组有一个失败及一个错误，涉及冻结 `device-observation.json` 的 catalog 摘要。
  这些输入与 catalog 逻辑本轮未改，不通过重写历史观测来消除失败。
  详细日志见 `output/companion-20261104/evidence-index.json` 引用的回归目录。
- `privacy_targets.generated.js` 重新生成，使新 Hook 与当前检出实际 catalog 一致；
  未覆盖历史采集中的 Hook 副本。冻结观测与当前 catalog 的不匹配仍需单独复核。
- 清单 `output/companion-20261104/evidence-index.json` 保存新证据、APK 来源、设备身份及文件摘要。
  人工签核仍为 pending，不计算 precision/recall。
- 未改共享采集内核，未提交或修改 A1–A3 的参考集和评分层。

剩余依赖是固定 APK、隔离服务配置和原始会话的位置。取得基线后须实际完成 B2、B3 后续设备轮次，不能把本记录标为全部验收完成。
