# 同伴续验：新镜像与固定 APK（2026-11-04）

仅用于授权测试。用户补充四个固定 APK 与 `x86_64/` 后执行本轮。
B1 结论延用[首轮交接](COMPANION_HANDOFF_20261104.md)：限时实验已交付，MG4 代理逐流映射仍未解决。
本轮完成 OwnTracks 前后台 HTTP 路径及拒绝对照、GPSLogger 异步读取诊断。
二者均归入 **AAOS 上的侧载对照层**；不声称新增原生 AAOS 外发样本。

## 设备与样本

- 使用用户提供的 AAOS 35 镜像 revision 4，新建 `Companion_AAOS35`，前台 user 10。
  实际指纹为 `google/sdk_gcar_x86_64/emulator_car64_x86_64:15/AAI5.260516.001.A6/16618942:userdebug/test-keys`。
- 原始中文镜像路径导致模拟器无法打开 `VerifiedBootParams.textproto`，内核报 vbmeta digest 与 system 挂载失败。
  使用 ASCII 目录联接后正常启动；没有修改镜像或关闭 AVB。首次失败和重试内核日志均保留。
- 四个用户提供的 APK 摘要分别匹配 MG4、HA、YAABSA 和 OwnTracks 的固定契约。
  本轮 OwnTracks 2.5.9 是普通第三方 UID `1010250`。
- GPSLogger 138 从 F-Droid 固定地址恢复，SHA-256 为
  `1d92fd8639dfc0ec210b013a81cc7dc85fc8c73ef521f71b2a08ffa165d4e265`，
  与历史清单前缀一致，apksigner 验证通过；普通第三方 UID `1010251`。
  来源：<https://f-droid.org/repo/com.mendhak.gpslogger_138.apk>。

## B2：可复核侧载路径通过，原生扩展仍待完成

最终轮：`output/companion-followup/owntracks-scenarios-004/verification.json`。
会话：`capture-f30efd1bad014bcbb1849f1c08b862e9`。

1. 第一个不同测试点在前台触发；第二个测试点在后台触发。
   每个点均有实际定位回调、身份已归属的代理 POST、独立接收端回执。
   读取摘要、定位时间、完整正文 SHA-256 和 HTTP 状态逐项一致。
2. 第三个新点在后台触发，独立接收端实际返回 HTTP 503。
   读值、代理和回执仍对齐；成功配对为空，拒绝配对成立。
   该负控是 HTTP 业务拒绝，权限拒绝明确为 `not_tested`。
3. 捕获健康全部通过，包含原 PID 存活、APK 不变、worker 正常退出和代理/reverse 恢复。
   关联上限仍为 30 秒，没有扩大时间窗或使用单包回退归因。
4. 同坐标的不同新定位时间可形成多组合法配对；每个 flow 仍必须有唯一完整回执。
   重复同一回执、错 UID、陈旧时间、伪造正文摘要继续拒绝。

固定样本的 Hook 已收窄为定位回调与实际 HTTP 请求构造观察，去掉该专用 bundle 的通用地图/socket 栈观察。
构造事件仍只是候选，必须有代理正文与独立回执才能通过。
接收端支持原 `198.18.0.1` 或本机 `10/8` 网卡，端口、路径、令牌和 APK 仍固定约束；
脚本须实际绑定该地址启动接收端，不能用远端回执代替。

原生筛选结果：HA 与 YAABSA 的固定 APK 已恢复，但新 AVD 无 `/data/local/tmp/vscanner-ha/root`，
隔离 HA/ABS 运行基线和历史服务配置未恢复。因此本轮未触发其新业务，也没有新原生负控。
不能把 APK 到位、静态车载入口或侧载层成功说成“新增原生 AAOS 外发路径通过”。
此优先项仍是 B2 剩余工作。

## B3：后台来源与异步读取诊断通过

OwnTracks 的前后台边界、回调与 HTTP 拒绝在上述同会话封存。
Activity 文本、采集事件和 UI XML/PNG 都有摘要；状态是离散观测，不声称覆盖所有后台时段。

GPSLogger 最终轮：`output/companion-followup/gpslogger-007/verification.json`。
会话：`gpslogger-cf4cdb93e8414dd195ce6ccbb4d5220a`。

- 先从固定 APK 反编译确认 `GeneralLocationListener.onLocationChanged(android.location.Location)`，
  再做只读观察；没有把注册调用算成获得数据，没有改写参数、返回值或应用逻辑。
- 前台与后台各捕获一个不同新定位值。只保存坐标摘要、定位时间、provider、PID/UID 和事件引用。
- 驱动退出码为 0，原 PID 存活，事件无 Hook 错误。它是读取诊断，不是 GPSLogger 外发验收或评分依据。
- GPSLogger 自身负控为 `not_tested`。OwnTracks 503 是另一独立案例，不能借给 GPSLogger 作为负控。
- 设置页将 GPSLogger 日志间隔由 60 秒改为 1 秒；仅在专用模拟器临时满足其忽略电池优化要求，
  普通 App 身份不变。收尾记录登记恢复情况。
- 首轮使用的小数测试值存在模拟器 NMEA 量化差异，随后改为可精确编码的值。
  若没有预期值，必须登记量化/触发缺口，不能按时间相近强配。

本轮选择后台场景，未验证断网重连。权限拒绝与返回空值不混为一谈，未测试状态保留为空。
OpenTracks 业务未触发，因此不新增其 Hook 缺口结论。

## 复现与失败记录

OwnTracks 完成正常引导、前后台定位授权后，按[官方配置入口](https://owntracks.org/booklet/features/remoteconfig/)
导入本地 `output/companion-followup/owntracks-setup.otrc`；配置仅含合成测试参数。
每轮冷启动到地图页，并在采集前注入不同起始点，避免沿用上一轮运行时或读值。

```powershell
& .venv/Scripts/python.exe -m core.frida_host.build --platform vehicle --only hook_vehicle_owntracks.js
& .venv/Scripts/python.exe -m vehicle.lab.owntracks_run --config output/companion-followup/owntracks-config.json --apk 'apk/sample(1).apk' --scenarios --out output/owntracks-new
& .venv/Scripts/python.exe -m vehicle.lab.gpslogger_probe --apk output/companion-followup/gpslogger-138.apk --out output/gpslogger-new
```

GPSLogger 需完成正常定位/通知引导并打开主界面；入口会在同一 App 内确认并停止上次记录，再开始新诊断。
Hook 在本轮目录构建封存；普通审计不自动加载该诊断 Hook。

失败轮全部保留：OwnTracks `baseline-001` 的 worker 退出超时；`scenarios-002` 的状态页没有上报菜单；
`-003` 被旧的“恰好一组”条件拒绝，原结果未改。GPSLogger `-001..-006` 保留采样、恢复界面、
进程与设备命令失败；不能据其中只有回调的部分把整轮健康改成通过。

最终测试、APK/镜像身份、失败轮、配置与证据摘要见 `output/companion-followup/evidence-index.json`。
完整离线回归的冻结观测契约失败继续单列；不修改旧观测摘要以求全绿。
人工签核 pending，precision/recall 仍不计算。共享采集内核及 A1–A3 参考集未修改。
