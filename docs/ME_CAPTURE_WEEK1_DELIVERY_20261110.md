# 么贵行一周任务交付：采集侧修复与当前基线

日期：2026-11-10。仅用于授权测试（自有设备与自有 APK）。对应[一周开发方案](ONE_WEEK_DEVELOPMENT_PLAN_20261110.md)的采集主线。
开发及离线验证已完成；当前真实采集受设备资源阻塞，不能标为全部实测完成。

## 1. 修复的一个主要采集缺陷

`core/frida_host/device_target.py::resolve_pids()` 原实现仍只调用 `pidof package`。
该命令按精确进程名查找，不枚举 `package:remote` 等后缀进程，因此“多进程开启”可能仍只附加主进程。
本轮以模拟真实命令返回的离线反例复现：pidof 返回主 PID 900，而 ps 同时包含 PID 700/600 两个同 UID 子进程；原实现返回 [900]，修复后返回 [900,600,700]。
这是离线可复现的实现缺陷；本轮没有运行设备正控，不宣称已完成 AAOS 多进程实测。

修复策略：保留 resolve_pid 的严格单进程行为；resolve_pids 读取 `ps -A -o PID,NAME` 快照，
只选精确 `package:` 前缀，逐 PID 读取 /proc 状态并要求 UID 与所选用户的主进程一致。
相似包名、不同 UID、不同用户以及不符合范围的孤立进程不自动附加；主进程排序优先，然后应用进程数上限并返回 skipped。
未知进程表格式、重复 PID、UID 无法核验或查询失败会显式失败，不静默回退成“没有子进程”。

仍未解决：晚启动子进程轮询、自定义非包名前缀进程、孤立 WebView 进程的身份核验，以及下游只用 src/evt_id 引用时的多 PID 冲突。
本次只修一个已复现的发现缺口，没有同时重构采集调度或篡改下游判定。

## 2. 当前 bundle 构建与身份

通过现有 Python Frida Compiler 17.18.0 重建以下四份 bundle，构建日志在 output/me-capture-week1-20261110/build.log。
源码未修改，所有构建的 dirty_at_build=false；基线工具复核其新鲜度。构建成功/源码一致不等于设备就绪或取得明文。

| Bundle | SHA-256 |
|---|---|
| hook_vehicle_all.bundle.js | b1127b2e8f1d33ff6c454e2febdc3aa47a65f282ed87c65718bb72159401c110 |
| hook_vehicle_ha.bundle.js | 8d33efea922891f2eb9cd3e84826afc582d6a5d7910cb2bc90886670115133e2 |
| hook_vehicle_mg4.bundle.js | eda03dd5673a80b8c736c4e0ae947dcffac907c7f5fdceb48f2623030c56e0f1 |
| hook_vehicle_abs_send.bundle.js | f5a77a50bbee024fa1c5d56a48a99b9bf2acda48302bb5d0a42ae8fea2b81be4 |

专用 HA/MG4/YAABSA bundle 与普通 all bundle 并非同一采集面；不能因 all 聚合了 TLS/Cipher 就宣称专用路径也已观测到这些数据。

## 3. 三条代表工作流与旧 7 case 状态

本机实际解释器为项目 .venv 的 Python，Frida 17.18.0，ADB 位于 E:/Android/android-sdk/platform-tools/adb.exe。
显式使用本机用户 .android 目录后，ADB devices 查询成功但返回空设备列表。
SDK 中有 android-35-ext15 automotive 镜像，但现有 AVD 清单仅 Pixel_7_API_30、Pixel_7_API_34、VScan_Phone；没有配置好的 AAOS AVD。
原先记录的 output/vehicle-device-setup 不在本机；本轮没有新建模拟器、下载样本、安装应用或让手机 AVD 冒充 AAOS。

| Case | 本轮状态 | 说明 |
|---|---|---|
| ha-battery | blocked / target_device_unavailable | 代表工作流已执行采集入口前置尝试；没有设备，未启动 Hook/业务动作 |
| mg4-post | blocked / target_device_unavailable | 同上；没有逐流身份、正文或回执的新证据 |
| yaabsa-send | blocked / target_device_unavailable | 同上；没有 native 发送的新证据 |
| ha-control | not_attempted | 次要工作流，设备恢复后用现有 HA socket 业务验收 |
| ha-control-failure | not_attempted | 503 负控需同轮业务配置，不能用设备缺失充当负控 |
| mg4-webview-post | not_attempted | 不能复制 mg4-post 的状态冒充独立触发 |
| yaabsa-playback | not_attempted | 播放和 send 分开，没有伪造 capture 清单 |

结构化基线在 output/me-capture-week1-20261110/baseline-final/baseline.json。
每条代表工作流记录授权包、固定 APK 预期摘要、bundle、新鲜度、设备状态和阻塞原因；没有实际装机摘要/session 就不补造。
根级 rules 摘要及工具/驱动源码摘要也随基线保存。所有失败/未执行状态保留，不能据此计算真实检测率。

## 4. 新增可重跑入口

`tools/capture_week1_baseline.py` 默认只查已有目标设备/固定样本身份和 bundle；显式 --capture 才尝试实际 capture_app。
仅白名单三个固定样本，user 默认 10，AAOS 35，attach，不安装/提权/启动 Activity，明确关闭 TLS 绕过。
同设备按顺序执行；已有采集的端口、代理及收尾约束继续由 capture_app 管理。实际 capture 完成也只称 capture_health_only，业务触发与独立回执仍须现有样本验收工具核验。

```powershell
# 先重建需要的 bundle；不会连接设备
.\tools\python313.ps1 core/frida_host/build.py --platform vehicle --only hook_vehicle_all.js --only hook_vehicle_ha.js --only hook_vehicle_mg4.js --only hook_vehicle_abs_send.js

# 新目录；设备不可用会保存 blocked，不生成假的采集成功产物
.\tools\python313.ps1 tools/capture_week1_baseline.py --capture --serial emulator-5554 --user 10 --seconds 30 --out output/capture-week1-new
```

输出目录必须新建；不覆盖旧轮次。初始化失败也保留 baseline_failed 和全部 7 case 状态，既不吞成零数据，也不写成功摘要。
若 ADB 因宿主用户目录解析失败，可仅在当前测试进程设 ANDROID_USER_HOME 为真实用户的 .android；不要创建盘根 .android 或改全局 HOME。
设备恢复后，应先确认三个固定版本 APK 在 user 10 已运行，按既有样本手册配置自有 HA/MG4/ABS 后端和触发动作；工具不会自动把“挂上 Hook”当业务已发生。

## 5. 验证与隔离

定向单测共 25 个通过：原设备解析/多进程测试、新增命名子进程及 UID/user/异常进程表负控、基线阻塞与失败保留测试。
根回归 19 组通过；移动分支 24 组通过，含上游移动 63 项。移动检查沿用已确认的 UTF-8 javac 参数与 ASCII 临时输出目录规避宿主编码/路径问题，未修改移动模块。
最终日志在 output/me-capture-week1-20261110/ 下；新测试已登记根回归并通过 test_inventory_guard。

修改范围：core/frida_host/device_target.py、其现有测试和决策记录；新增采集基线工具及测试；回归清单仅加测试登记。
未改陶俊哲的匹配实验、毛宇淇的计分/摘要、Hook 业务源码、规则库、前端或 TLS 开关默认策略。
两个 subagent 对上一提交的审查结果另见 [定位实验 Review](LOCATION_WEEK1_REVIEW_20261110.md)，本次不混入定位分析修复。

结论：采集侧发现缺陷已修复且离线检查通过；真实重采与设备验收仍是未完成项，待有可运行的授权 AAOS 设备及业务前提后执行。
