# AAOS 35 三应用业务验收与 agent 初评

2026-11-03。仅用于授权测试。设备为专用 AAOS 35 模拟器，普通第三方 APK 安装于 user 10。三个应用的签名验证有效，装机 APK SHA-256 与审计输入一致。发布证书独立核验留作后续。

| 应用家族 | 业务与独立参考 | 健康采集范围 | 主要缺口 |
| --- | --- | --- | --- |
| Home Assistant Automotive minimal 2026.10.1 | 独立服务账号登录，原生车机实体切换 `off → on → off`，后台恢复。服务端保存模拟器电量、充电状态、充电类型 | `vehicle-ha-20261103-005` 业务轮；`ha-socket-20261103-r4` 控制与订阅同轮采集，7 项 capture checks 全真 | 引导期间采集退出。成功轮保留系统代理，业务 HTTP/WebSocket 正文不可见。三个传感器值已登记，尚未执行设备端变值对照。控制侧为 HTTP webhook，无消息 ID；失败控制尚未端到端注入 |
| YAABSA AAOS x86_64 1.16.0 | 独立 Audiobookshelf 登录，车机书库浏览，自有音频播放、暂停、恢复和后台播放。服务端有正时长听音会话；本轮确认 `POST /api/session/{id}/sync` 携带 `currentTime/timeListened/duration`，服务端 `timeListening` 增量与请求总和一致 | `vehicle-yaabsa-20261103-001` 登录、`-003` 播放两个健康会话；`-006` 设备回环 tcpdump 播放进度对齐 | 末次暂停在 Hook 时限后，由系统状态确认。常规代理仍无 Flutter 正文和可归因 flow，`-006` 属实验证据 |
| MG4 WebBrowser 1.0.2 | 自有页面打开、跳转、返回、刷新、收藏操作和后台恢复。服务端确认 GET `/`、`/second` 与随机标记 POST `/submit` | `vehicle-browser-20261103-002` 业务轮；`-004` 加随机标记 POST，健康采集和新鲜 UI XML、主屏 PNG | 代理层已看到 POST，但 10 条 flow 全部未归因（`outside_allowlist_or_unresolved`），按正文归因缺口登记，不判通过 |

HA 2026.10.4 和 Audiobookshelf 2.37.2 均为真实后端，分别绑定 `127.0.0.1:18123` 和 `127.0.0.1:18125`。使用专用根目录、私有挂载与低权限 UID，网络与模拟器共享。镜像内核不支持 PID 命名空间。HA 使用正式 HTTP 配置确认流程，语音导入依赖按固定源码版本编译。Camera 的可选加速库和 FFmpeg 功能未纳入 HA 控制验收。ABS 的媒体由本地生成，为 45 秒 PCM 测试音频。

本地初评文件为 `output/vehicle-p1p2-agent-20261103/agent-review.json`。三家业务路径均按独立参考证据复核，证据带 SHA-256，`human_signoff=pending`。三个健康审计均为 0 条发现。由于缺少覆盖范围内且具有来源真值的第三方读取与外发参考配对，第三方样本的 precision 和 recall 均为空。夹具的配对初评单独见 [窗口校准](../bench/WINDOW_CALIBRATION.md)；三条路径的正例、负例、漏采与归因不确定逐条登记在 [第三方验收登记](THIRD_PARTY_ACCEPTANCE.md)。

| 数据类型 | 所需权限 | 读取 API | Hook 覆盖 | 判断规则 | 验收样例 | 未覆盖原因 |
| --- | --- | --- | --- | --- | --- | --- |
| 车机 Android 电源状态 | 按 App 实际源路径补核 | 待定位 APK 中的电源数据来源 | 未接入 | 独立服务端状态证明上报结果，读取路径另行核对 | HA 的 3 个模拟器电源传感器状态 | 本轮四类通用源和 VHAL 表未包含这一 Android 电源来源 |

采集恢复修复同时校验 Android 旧代理键及生效主机、端口。已有 PAC 或排除列表时使用 `capture --preserve-system-proxy`，报告显示相应的正文覆盖缺口。现场出现过 AAOS 掉线、界面 XML 复用旧文件、HA 引导期间目标进程退出和遗留代理引起的 WebSocket 拒绝。失败轮次均保留。API 33、34、36 动态验收、量产车休眠和真实点火仍待单独测试。

上游来源：[Home Assistant Android](https://github.com/home-assistant/android/releases/tag/2026.10.1)、[Audiobookshelf 镜像](https://github.com/advplyr/audiobookshelf/pkgs/container/audiobookshelf)、[YAABSA](https://github.com/Vito0912/yaabsa/releases/tag/v1.16.0)、[MG4 WebBrowser](https://github.com/Tommasov/MG4_WebBrowser)。

后续复验见 [HA 电源状态变值](POWER_VALIDATION.md)、[HA 电量 HTTP 正文](HA_WEBHOOK_VALIDATION.md)、[HA WebSocket 订阅与控制](HA_SOCKET_VALIDATION.md) 和 [断网恢复窗口对照](../bench/WINDOW_CALIBRATION.md)。HA 控制侧按 HTTP webhook 单独取证，与订阅状态分离；YAABSA 的 Flutter 出站和 MG4 的 WebView 出站仍分别保留正文/归因缺口，验收登记见 [第三方验收登记](THIRD_PARTY_ACCEPTANCE.md)。
