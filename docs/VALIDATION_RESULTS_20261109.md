# 乙线：8 个 App 的首轮实测

实测汇总时间：2026-11-09 22:52:49（Asia/Shanghai）；2026-11-10 整理入库。
仅用于授权测试（自有模拟器与获授权的公开原版 APK）。

静态扫描、安装、启动均完成 **8/8**；乙1真实上传验收为 **1/8 App、2/16 成功会话**。
四个有效采集会话健康检查通过。真人标注尚未完成，precision/recall 与置信区间保持未测。

## 样本与范围

设备：AAOS 35 / Android 15、user 10、普通第三方安装身份。
HA 与 YAABSA 使用上游 AAOS 变体，其余六个是 AAOS 侧载对照，不计入原生 AAOS App 分母。
手机样本的静态规则库版本为 36，车载样本为 Android 15；静态规则版本与实际设备 API 分列。

| App | 固定发布版本 | 静态线索数 | 安装/启动 | 上传验收 |
| --- | --- | ---: | --- | --- |
| Immich | v3.3.6，x86_64 | 18 | 通过 | 后台/账号未配置 |
| DAVx⁵ | v4.5.21-ose，上游签名 | 10 | 通过 | 后台/账号未配置 |
| GPSLogger | v138 | 12 | 通过 | 两轮无回执，网络约束阻塞 |
| Nextcloud | stable-35.0.2 | 18 | 通过 | 后台/账号未配置 |
| Element X | v26.10.1，x86_64 | 16 | 通过 | 后台/账号未配置 |
| OwnTracks | v2.5.9，OSS | 12 | 通过 | 两个独立会话成功 |
| YAABSA | v1.17.0，AAOS x86_64 | 0 | 通过 | 后台/账号未配置 |
| Home Assistant | 2026.11.1，automotive-minimal | 2 | 通过 | 后台/账号未配置 |

每个 APK 的 SHA-256、平台范围及状态见 [机器汇总](validation-20261109/summary.json)。
来源筛选与服务端要求见 [样本池方案](VALIDATION_SAMPLE_POOL_20261109.md)。
DAVx⁵ 实际从上游 GitHub Release 下载，未使用 F-Droid 重签包；发布方证书尚未独立核验。

## 运行时观测

OwnTracks 使用本机独立 HTTP 接收端及随机测试账号，通过 ADB reverse 访问回环服务。
两个会话分别使用独立采集 session、接收路径与不同合成坐标，通过正常 Report Location 操作触发上传。
接收端记录认证成功、HTTP 200、新测试坐标与定位时间，并保存请求正文 SHA-256。
旧坐标、非 location 报文及窗口外回执没有计入成功数量。

| 会话及最小证据 | 采集健康 | 隐私读取事件 | 出站事件 | 新坐标认证回执 |
| --- | --- | ---: | ---: | ---: |
| [OwnTracks S1](validation-20261109/owntracks-s1.json) | 通过 | 0 | 11 | 2 |
| [OwnTracks S2](validation-20261109/owntracks-s2.json) | 通过 | 0 | 5 | 1 |
| [GPSLogger S1 重试](validation-20261109/gpslogger-s1-retry.json) | 通过 | 120 | 0 | 0 |
| [GPSLogger S2 重试](validation-20261109/gpslogger-s2-retry.json) | 通过 | 12 | 0 | 0 |

读取事件、出站事件、接收回执是三个计数单位。S1 的两条回执仍只算一个会话。
出站事件由 URL/连接观测构成，不能直接当作完整 HTTP 请求数或读流配对数。

OwnTracks 两轮未捕获定位返回的 PRIVACY_READ 证据。因此只通过受控 HTTP **业务上传**验收，
定位回调与值级配对仍有缺口，不能从回执倒造读取事件或计算定位 recall。
本轮未放宽旧专用 Hook 的固定 APK SHA 限制，没有继承旧版本验收资格。
会话采用 `attach_preserve_proxy`，代理正文不可见的范围保留在证据缺口中。

GPSLogger 显示本轮新定位点；通用 Hook 捕获到的 120/12 条读取均为 Android ID，状态为 obtained，
不能将它们写成定位回调。脱敏应用日志记录 `isConnected=true、isValidated=false`，
并反复出现 WorkManager `Constraints not met`。这两轮没有独立上传回执，不能解释为工具正确识别“无外发”。

## 候选与静态线索

八包静态分析使用 DEX/权限事实。表中数字是静态规则线索，不是实际读取、实际外发或违规数量。
没有独立签核的读流配对结论，当前不报告候选 TP/FP/FN。
GPSLogger 额外 JADX 反编译仅用于诊断权限和配置流程，存在 31 个反编译错误，不能当作完整源码或运行时行号证据。

## 失败与待完成项

- YAABSA 首次解析普通 launcher 失败；从实际清单定位 MainActivity 后显式启动成功。首次失败未覆盖。
- GPSLogger 在 AAOS 电池优化授权流程循环；临时添加该 App 的系统电池白名单后进入业务。配置使用原版支持的外部 preset，未修改 APK 或内部偏好。
- GPSLogger 首次 preset 复制被 ADB 的 user 0 存储挂载拒绝，后通过核对的 user 10 外部存储底层路径重试。失败记录保留。
- GPSLogger 原 S2 已自动恢复日志，首次触发未找到 START LOGGING；另开 S2 重试后完成有效采集，不修改原失败结果。
- 其余六个 App 尚需 HA、Audiobookshelf、Nextcloud、Immich、Matrix 后台及对应账号。登录页可打开不代表已执行上传。
- 乙2仍需两位不同真人独立初评及第三位不同真人仲裁签核；当前参考配对标注数为 0，不能报准确率 1.0。
- 乙3的数据源 × 传输路径 TP/FP/FN 仍待适用规则、独立参考和真人签核；本轮只有来源/状态观测计数。
- 乙4睡眠→点火→唤醒、蜂窝重连、多 Android 用户并发本轮未测。

## 证据保存与收尾

本目录的 JSON 是字段白名单导出的脱敏结果与合成坐标最小证据，附 APK、规则、Hook、原始输入和来源文件指纹。
它们是描述性证据投影，不是完整离线重放包或人工标签；独立复算需要同一冻结原始材料。
机器汇总保留原生成时间及来源 SHA-256；`observed` 事实、待复核配对和 `static` 线索不合并计数。

原始材料位于本机 `output/v8-20261109/`；APK 位于 `apk/mobile/validation-20261109/`
及 `apk/vehicle/validation-20261109/`。这些目录依仓库约定不入库。
测试账号、带凭据的配置/导入截图、原始完整日志未导出。

[收尾核验](validation-20261109/cleanup.json)记录临时显示、电池白名单、定位/动画设置的恢复，
以及接收器、Frida 与本轮转发的停止/清理；失败操作为 0。模拟器保留运行，八个原版 App 保留安装。
