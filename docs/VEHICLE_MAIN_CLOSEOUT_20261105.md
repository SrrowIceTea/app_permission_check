# 主线集成与第三方车机补测

2026-11-05。仅用于授权测试。对应本轮第 1、3 项。

## 主线与 Jenkins

60 个协作文件已收拢为 `a4a8b77`，包括规则库升级、历史目录封存、盲评交接、可搬迁证据包及 CI 隔离。
随后以 `3431ee4` 合并 `codex/jenkins-integration`，保留双方提交历史并推送 Gitee `main`。
冲突保留主线中更完整的历史快照校验、证据包与交接测试，同时保留 CI 的来源冻结修复。

Jenkins [vscanner-gitee](http://127.0.0.1:8080/job/vscanner-gitee/) 已切换到 `main`。
第 3 次手动基线构建为 SUCCESS；后续真实提交须以
[机器记录](../output/main-closeout-20261105/automatic-verification.json)核对自动 SCM 触发、实际哈希和全部结果。
部署与恢复见 [CI 说明](REGRESSION_CI.md)。

规则库正常升级、损坏资产和升级后的整机重启已有验收。本次集成纠正文档的过度承诺：
当前文件替换不是原子切换，升级中断、磁盘异常和并发安装仍未验收，不能据正常重启通过推断这些能力。

## 本轮真实设备

AAOS 35、Android 15、user 10；指纹为
`google/sdk_gcar_x86_64/emulator_car64_x86_64:15/AAI5.260516.001.A6/16618942:userdebug/test-keys`。
当前镜像位于 `output/vehicle-device-setup/image/x86_64/`，AVD 位于
`output/vehicle-device-setup/avd/`，不在默认 SDK system-images 列表。
本轮是新采集，非历史 session 副本。

## MG4 逐流身份

[业务结果](../output/vehicle-thirdparty-20261105-173730/mg4-native-004/business.json)和
[采集健康](../output/vehicle-thirdparty-20261105-173730/mg4-native-004/capture/verification.json)通过。
固定 APK SHA-256 为 `376b931673869c0ac6a23fb719a4b642252eae6cab0fd1fc436d182ded4cf396`。

| 项 | 本轮结果 |
| --- | --- |
| 应用实际写入 | 主进程 PID 4028、UID 1010252，libwebviewchromium.so → sendto 成功写入完整表单 |
| 代理逐流正文 | 1 条 POST，正文摘要、目标、随机路径与实际写入一对一匹配 |
| 独立服务端 | 完整同值正文，HTTP 200 |
| 同端点负控 | 设备 shell curl PID 7301、UID 0，服务端收到另一正文；未归给 MG4、正文未保留在 flows |
| 审计重放 | [摘要](../output/vehicle-thirdparty-20261105-173730/mg4-audit-final/summary.json)复核写入引用，证据包 18 项校验通过 |

原 WebView 回调只证明请求元数据，旧轮次仍保留替代证据的边界。
新增路径覆盖本固定 APK、自有明文表单与完整单次写入；分片、TLS、其他版本未验证。
重复请求/重复写入会弃权，不以同端点或单包白名单兜底。
未触发敏感 API，审计 findings 为 0 只表示没有该类证据，不能推断应用没有风险。

```powershell
. ./environment.ps1
& $VScanPython -m core.frida_host.build --platform vehicle --only hook_vehicle_mg4.js
& $VScanPython -m vehicle.lab.browser_run --webview-probe --native-control --out <新目录>
```

## OwnTracks 真实网络场景

[业务验收](../output/vehicle-thirdparty-20261105-173730/owntracks-scenarios-008/verification.json)四项通过，
[采集健康](../output/vehicle-thirdparty-20261105-173730/owntracks-scenarios-008/capture/verification.json)通过。
固定 APK SHA-256 为 `b12ca46508b8f33e6ddc03433be5600f7fec6b2c30adb8056368aa2e17129d0f`，UID 1010258。
本轮自有接收地址是宿主机 `10.18.80.25:18145`，只接收合成位置。原应用导入配置后采用移动监控与 2 秒采样。

| 场景 | 真实证据 |
| --- | --- |
| 前台 | 新定位回调、归属应用的代理流、独立 HTTP 200 回执同值 |
| 后台 | 主界面退后台，无手动上报；回调、归属应用的代理流、独立回执同值 |
| 断网重连 | Wi-Fi 关闭且本轮 ADB 8888 隧道移除；离线取得新定位、服务端无回执；恢复后由应用自动上传 |
| HTTP 503 | 应用实际 POST 获得 503，归属应用的代理流与独立回执一致；该阶段成功配对为 0 |

503 后恢复 HTTP 200，让应用自动重试清空合成队列；这条恢复流与 503 阶段分开。
全轮 4 条定位事件、5 条代理流，成功正文候选包含上述 3 条正控和恢复后的 1 条。
Wi-Fi、代理和 ADB 转发已恢复。未放宽 30 秒读取外发关联窗口。
[常规审计摘要](../output/vehicle-thirdparty-20261105-173730/owntracks-audit-final/summary.json)与证据包校验通过。

首次在当前 user 10 安装样本时，需通过应用首次引导，并授予自有测试所需定位和通知权限。
使用 `vehicle.lab.owntracks_config --initialize --url <自有HTTP地址> --out <新目录>` 通过应用导入 UI 配置。
地址必须是自有私网 IPv4、18145 端口和 `/owntracks/<16位小写十六进制>`；配置 JSON 包含 `url` 和实际 `serial`。

```powershell
& $VScanPython -m core.frida_host.build --platform vehicle --only hook_vehicle_owntracks.js
& $VScanPython -m vehicle.lab.owntracks_scenarios --out <新目录> --config <配置JSON> --apk <固定APK>
```

旧清单不含 `owntracks_endpoint_host` 时，审计仍按原 `198.18.0.1` 求值。
新地址单独封存，不修改旧契约或把旧 session 改写为新测试。

本轮 [设备汇总复核](../output/main-closeout-20261105/device-verification.json)包含 14 项检查、两个会话 ID、
独立回执和清单摘要。两个自包含审计包分别核对 18 项文件，结果均通过。

## 失败记录与计分边界

同批目录保留 MG4 native-001～003（负控发送未完成）、OwnTracks scenarios-001～006
（地址不存在、未安装/引导未完成、尚未离线读到值、坐标量化导致摘要不符）的原始失败。
第 007 轮业务链通过，但 Wi-Fi 的早期快照仍是 disabling；第 008 轮等待服务完全 disabled 后重新验收。
未覆盖失败产物，也未将采集健康与业务通过混为一谈。

两例均计为 `workflow_only`，未产生真人标签或新的准确率结论。AAOS 其他版本、真车、
长期后台、休眠、真实用户同意及规则库升级中断安全仍需独立验证。
