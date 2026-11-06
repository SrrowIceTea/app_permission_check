# 样本运行记录纠偏

复核读取 [11 份 APK 清单](../../output/sample-acquisition-20261103/manifest.json)
和每轮原始 JSONL，按实际事件核算调用、空值、拒绝和取得数据。结果见
[机器可读复核清单](../../output/owntracks-vehicle-retest-20261104/historical-runtime-review.json)。
前六个样本在报告中登记为 AAOS 35 试跑，事件使用移动端 Hook。后五个样本的报告
记录的是 Android 17 手机镜像，事件也使用移动端 Hook。两批证据均保留其原有范围。

| 样本 | 可复核证据 | 待处理 |
| --- | --- | --- |
| Trail Sense | 5 条 `getLastKnownLocation` 返回值。拒绝轮仅有传感器注册 | 定位 API 没有 `denied` 事件，旧截图损坏 |
| OwnTracks | 14 条定位注册、11 条 Wi-Fi 字段返回，拒绝后零次定位调用 | 历史轮没有上传对照，旧截图损坏 |
| GPSLogger | 5 条定位注册，app-op 对照仍能注册 | 定位回调未捕获，旧截图损坏 |
| Audio Recorder | 2 条启动录音调用，截图显示 27 秒、445 kB | 音频值无 Hook 证据，拒绝轮未调用录音 API |
| Fossify Contacts | 多次附加后均未捕获联系人查询，业务报告称显示测试联系人 | 需独立验证启动阶段与实际 API 路径 |
| OpenTracks | 记录动作未启动，保留界面和零调用记录 | 触发缺口 |

前六个 APK 中有 4 个未声明 `INTERNET`。GPSLogger 与 OwnTracks 声明了该权限，
历史轮没有可供值级匹配的请求正文。授权弹窗拒绝和 API 调用拒绝分别登记。
返回 `void` 的注册事件在复核清单中归为 `call_only`。原始 JSONL、截图与动作日志保留，
Audio Recorder 的摘要已修为有效 JSON，原文另存为 `result.json.original`。

旧定位截图包含文本输出污染，无法作为 PNG 复核。新截图走二进制 `exec-out` 并校验 PNG；
新采集不会覆盖历史文件。后续运行中只有 APK、设备、会话和实际 Hook 均匹配的证据
才可用于车载验收。

复核入口

```powershell
. ./environment.ps1
& $VScanPython -m vehicle.bench.runtime_review --out output/owntracks-vehicle-retest-20261104/historical-runtime-review.json
```

## OwnTracks AAOS 35 复验（2026-11-04）

[验收结果](../../output/owntracks-vehicle-retest-20261104/run-003/verification.json)与
[采集健康检查](../../output/owntracks-vehicle-retest-20261104/run-003/capture/verification.json)均通过。
两次注入新测试点各得到一组定位回调、代理 POST 正文、隔离接收端回执。三侧定位摘要和定位时间一致，
代理与接收端正文 SHA-256 一致。两条代理流均归属 user 10 的 OwnTracks UID 1010258，HTTP 200。
5 条回执中仅 2 条满足新测试点条件。新截图已验证为有效 PNG。

默认 OkHttp Hook 未覆盖该固定 APK 的混淆方法。实验入口观察实际定位回调和应用内 HTTP 请求构造，
后者仅作为归因候选，须同时有代理实收正文和独立回执才通过。该入口仅允许固定 SHA 的原版 APK、
AAOS 35 普通 App 模式和本地 HTTP 路径，不装载 TLS 绕过。读取与外发关联上限仍为 30 秒。
归因分别相差 19 ms 和 12 ms，属于请求候选与代理流的间隔。

保留失败轮供排查。[首轮](../../output/owntracks-vehicle-retest-20261104/run-001/verification.json)
捕获了定位回调，但代理未归属收到的旧队列请求。
[第二轮](../../output/owntracks-vehicle-retest-20261104/run-002/verification.json)有两条新点回执，
OwnTracks 下载线程发生原生崩溃，采集健康检查失败。冷启动并缩小 Hook 范围后复验通过，
第二轮崩溃的具体根因尚未确定。验收仅覆盖隔离 HTTP 业务路径，保留 TLS、其他 APK 版本、
其他样本的 AAOS 复验和人工签核。

复现前在自有模拟器的 user 10 安装对应 APK，完成引导并授予测试定位权限。在应用中选用 HTTP 模式和移动监控，
将地址指向 `http://198.18.0.1:18145/owntracks/<16 位小写十六进制随机值>`，关闭扩展数据和认证。
配置文件填写同一 `url` 和实际 `serial`。宿主机需有 `198.18.0.1` 这个测试网段地址，受控接收端由脚本启动。
应用导入配置的格式见 [OwnTracks 配置文档](https://owntracks.org/booklet/features/remoteconfig/)。

```powershell
. ./environment.ps1
& $VScanPython -m core.frida_host.build --platform vehicle --only hook_vehicle_owntracks.js
& $VScanPython -m vehicle.lab.owntracks_run --out <新输出目录> --config <本轮配置文件> --apk <原版APK路径>
```

## 常规审计重放（2026-11-05）

已通过前置校验的 OwnTracks 专用采集可由 `vehicle.ps1 audit` 处理。
`VSC-LAB-OWNTRACKS-LOCATION-001` 记录定位回调，`VSC-LAB-OWNTRACKS-HTTP-001` 记录完整 HTTP 正文的同值候选。
候选要求同 UID、用户和会话，定位时间及坐标摘要一致，并满足 30 秒窗口。
PDF 和结论文件仅展示事件引用和关联结果。三侧核对（回调、代理、独立回执）仍由本页的业务验收入口执行。
此路径属于侧载对照，计分资格为 `workflow_only`。

历史采集使用 `--capture-catalog` 提供当时的目录快照，配套政策和签名文件保留在快照同目录。

```powershell
./vehicle.ps1 audit `
  --capture output/owntracks-vehicle-retest-20261104/run-003/capture `
  --capture-catalog output/o6-device-acceptance-20261104/aaid-audit/privacy-catalog.json `
  --package org.owntracks.android `
  --apk output/sample-acquisition-20261103/org.owntracks.android/sample.apk `
  --out <新输出目录>
```

## 第三方业务补测（2026-11-05）

新一轮 AAOS 35 采集已补 MG4 实际写入与代理逐流正文身份，并用独立设备进程做同端点负控。
OwnTracks 的前台、后台、真实断网重连和 HTTP 503 四项通过；503 后正常恢复的上传单列。
详见 [主线集成与第三方车机补测](../../docs/VEHICLE_MAIN_CLOSEOUT_20261105.md)。
历史 MG4 替代关系与 OwnTracks 原接收地址证据保持原范围，不因新轮次通过而升级。

本地 GPSLogger 与 OwnTracks 侧载补测另见 [同伴续验](COMPANION_FOLLOWUP_20261104.md)。旧轮次的范围与失败状态保持原样。
