# 同伴任务续验与交接（2026-11-06）

仅用于授权测试。按用户选定的 B1–B3 范围执行；路线图中的 A1–A3 和独立人工标注不由本轮代签。
本轮补齐原生 AAOS 媒体读取、实际发送、独立回执和暂停负控，并复验 MG4 逐流归因。
所有业务证据仍为 `workflow_only`，人工签核 `pending`，不计算 precision/recall。

## 本轮结果

| 任务 | 验收与范围 |
| --- | --- |
| B1 | 固定 MG4 的一次完整明文表单 POST，进程实际写入、代理逐流正文、独立 HTTP 200 回执一致；同端点另一进程正文未归给 MG4 |
| B2 | 固定 YAABSA 的原生车载媒体入口，两次不同进度有实际 API 返回、native 成功写入和独立服务端记录；暂停负控通过 |
| B3 | YAABSA 前台、后台各有真实同步与当时的服务端回执；GPSLogger 的异步读取诊断沿用 11 月 4 日封存证据，本轮未重新采集 |

### B1：MG4

结果：`output/companion-20261106/mg4-001/business.json`。
会话：`capture-5616245233584fd4aeade96ad3a30e88`。
APK SHA-256：`376b931673869c0ac6a23fb719a4b642252eae6cab0fd1fc436d182ded4cf396`。

- 普通 App UID `1010253`，主进程 PID `14777`；`libwebviewchromium.so → sendto` 成功写入后，
  以正文摘要、随机路径、目标、连接和时间核对唯一代理流。1 条 POST 归因通过，服务端正文一致。
- 同轮 shell curl PID `15256`、UID `0` 访问相同端点、相同路径，服务端收到另一正文；
  未归给 MG4，未将其正文保留在目标流中。
- GET 的 `/`、`/second` 导航、回退与重载有 UI 和服务端记录；本轮逐流正文归因结论仅覆盖 POST。
  GET 未获得相同的逐流身份依据，不把导航成功算作身份已核验。
- 原 WebView 回调继续作为元数据/替代证据单列。分片写入、TLS、其他 APK 或 Chromium 版本未验收。

### B2：YAABSA 原生媒体路径

结果：`output/companion-20261106/yaabsa-006/verification.json`。
会话：`capture-ce374540a3d04d6db52559c360bceb71`。
APK SHA-256：`3860d29741dd6f67fc79f03bb34132143da11e99c048ae4206863879505f68e1`。
普通第三方 UID `1010252`、user 10；AAOS 35 / Android 15，专用 `Companion_AAOS35`。
指纹为 `google/sdk_gcar_x86_64/emulator_car64_x86_64:15/AAI5.260516.001.A6/16618942:userdebug/test-keys`。

1. 从固定 APK 的 DEX/反编译实现核对 `yc.d.S()J` 是 just_audio 当前播放位置（毫秒）。
   Hook 调用原方法后记录实际返回值，不修改调用、参数或返回值，仅对白名单进程加载。
2. 通过正常车载媒体 UI 播放自生成的 180 秒 PCM 音频。两个暂停点分别读到 `48673 ms`、`122476 ms`，
   同会话实际发送的 `currentTime` 为 `48.673 s`、`122.476 s`。
3. `libcronet.147.0.7727.49.so → sendto` 的完整成功写入，与回环 HTTP 的正文摘要、源端口、设备时间一对一匹配。
   独立的官方 Audiobookshelf 服务查询确认进度和 listening session；6 条发送均能归属应用。
4. 实际 API 返回直接对齐其中 2 条请求；另外 4 条周期/累计同步保留 `read_write_gap`。
   Flutter 周期进度可能按时间推算，未把推算值、界面显示或调用注册当成 API 实际返回。
5. 在第一个暂停点等待 6 秒，独立服务端进度保持 `48.673 s`；这是实际暂停负控，权限拒绝为 `not_tested`。
6. 独立 listening session 累计增量 `29.900454 s`，与封存请求的 `timeListened` 总量一致。
   采集器、原 PID、APK、Hook 健康和正常退出检查全部通过。

### B3：后台时段与读取诊断

- 前台为 `com.android.car.media`；后台为 user 10 的 `com.android.car.carlauncher`。
  保存两个阶段的 Activity、PLAYING/PAUSED 状态和动作边界；边界统一用**设备毫秒时钟**。
- 在仍处于前台播放、后台播放时分别查询独立服务端，当前进度为 `36.831066 s`、`108.826698 s`，
  各自与本时段的一条实际 native 请求相等。
- 返回播放器后触发的暂停同步单独登记。两个暂停点的读取证据不冒充后台期间的读取。
- GPSLogger 的 `GeneralLocationListener.onLocationChanged(Location)` 前后台真实回调，沿用
  `output/companion-followup/gpslogger-007/`，会话 `gpslogger-cf4cdb93e8414dd195ce6ccbb4d5220a`。
  此项是侧载读取诊断，没有 GPSLogger 外发或负控结论；权限拒绝、空值和未测试继续分开。
- OwnTracks 的前后台与 HTTP 503 历史证据见[上轮续验](COMPANION_FOLLOWUP_20261104.md)。
  后续主线的真实断网重连见[11 月 5 日记录](../../docs/VEHICLE_MAIN_CLOSEOUT_20261105.md)，本轮未重复宣称新采集。

## 环境与复现

使用官方 ABS 2.37.2 的固定 amd64 manifest：
`sha256:37c2057e150694970442579815c646fe6bdc01c95b9d1547c4c9068be8844ef3`。
逐层校验原始下载摘要；为兼容 Android tar，将容器绝对符号链接改为等价相对链接，
移除覆盖链接的 PAX `linkpath`，原始层、转换层和摘要都保留，普通文件内容不变。
服务绑定 `127.0.0.1:18125`，以专用 UID `62001` 运行；使用私有 mount namespace 和 chroot，
**不声称 PID 或网络 namespace 隔离，也不声称 Docker 的完整安全边界**。
测试账号凭据只存在忽略目录的 `.private.json`，不进入共享证据包。

以下初始化命令用于尚未部署此后端的新专用 AVD。复跑保留的 AVD 时，复用
`output/companion-20261106/abs-runtime` 及其原凭据，跳过镜像、后端和账号初始化，
重新启动后端、联网和转发后直接运行采集；同一已初始化服务不能换用另一套新生成的凭据。

```powershell
# 专用自有 AAOS 35 x86_64 模拟器；正常安装固定 APK。
& .venv/Scripts/python.exe -m vehicle.lab.abs_image --folder output/abs-new
adb -s emulator-5554 root
& .venv/Scripts/python.exe -m vehicle.lab.abs_backend --folder output/abs-new
# 另启后台进程运行 owned-namespace.sh，服务启动后设置仅本机 ADB 转发。
adb -s emulator-5554 forward tcp:18125 tcp:18125
& .venv/Scripts/python.exe -m vehicle.lab.abs_api --folder output/abs-new
# 用正常 UI 登录本地服务，选择 OwnedAuditTone，并在播放器暂停。
& .venv/Scripts/python.exe -m vehicle.privacy.catalog
& .venv/Scripts/python.exe -m core.frida_host.build --platform vehicle --only hook_vehicle_abs_send.js
& .venv/Scripts/python.exe -m vehicle.lab.abs_progress_run --folder output/abs-new --apk apk/yaabsa.apk --out output/yaabsa-new
& .venv/Scripts/python.exe -m core.frida_host.build --platform vehicle --only hook_vehicle_mg4.js
& .venv/Scripts/python.exe -m vehicle.lab.browser_run --webview-probe --native-control --out output/mg4-new
```

后端启动命令：`adb -s emulator-5554 shell unshare -m sh /data/local/tmp/vscanner-abs-20261106-v2/owned-namespace.sh`。
Windows 后台启动使用 `Start-Process -WindowStyle Hidden`，将标准输出和错误分别保存到本轮目录。
需要运行 Frida 17.18.0 server，监听 `127.0.0.1:27043`；所有设备任务串行。
测试联网需要正常连接模拟器的 `AndroidWifi`，不依赖篡改目标调用。

## 失败记录、回归与交接

- `yaabsa-001/002`：媒体按键未可靠暂停，UI 无法空闲；改用正常播放器控件并核验实际状态。
- `yaabsa-003`：合并后的生成 Hook 摘要与来源契约不一致，标准就绪检查拒绝；重新生成后复跑。
- `yaabsa-004`：最初校验为通过，但发现混用主机/设备时间，后台边界不够严格；保留原结果，**以 006 替代**。
- `yaabsa-005`：进度条操作后立即点击播放未生效，场景检查拒绝；增加状态确认后 006 通过。
- 完整回归 `output/companion-20261106/regression-003/verification.json`：17/17 组通过，包含移动端。
  新增身份、会话、数值、时间窗和跨后台边界反例；修复 Windows 长/短临时目录别名导致的交接测试错误。
- MG4 与 YAABSA 均经常规审计重放，各 18 项证据包文件校验通过；findings 为 0 不表示“应用无风险”。
  原生媒体读取属于实验业务证据，没有伪造隐私来源、扩大发送覆盖或新增违规判定。
- 新证据包：`output/companion-20261106/shareable-evidence.zip`。解压后在本仓库运行
  `python -m vehicle.lab.companion_verify <解压目录>`，校验清单、两份审计包和媒体读取/发送引用。
  历史 GPSLogger 只附原始诊断记录；它不是本轮采集。
- 本轮停止自有后端、Frida 和两个 App，恢复 Wi-Fi 开启但未连接；代理为 `null`，forward/reverse 为空，
  adbd 恢复 shell UID `2000`，关闭本轮启动的专用模拟器。保留测试账号、书库和 AVD 用于复现。

TLS、分片、其他应用/库版本、真车长期后台、休眠/唤醒、其他 API 版本与独立人工签核仍不在本轮通过范围内。
