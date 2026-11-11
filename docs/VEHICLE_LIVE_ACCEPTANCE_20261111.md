# 车载端新设备验收与修复记录（2026-11-11）

仅用于授权测试：本轮新建的自有 AAOS 模拟器、自有 debug APK，以及此前授权获取的原版车载 APK。
范围为车载端；未修改 mobile 或根前端功能。原始成功、失败与构建记录均保存在
`output/vehicle-live-acceptance-20261111/`，该目录不入 Git。

## 结果

已完成代码基线封存、实际设备正反对照、MG4 自然业务复测，以及 B 侧五会话交接验收。
HA 与新版 YAABSA 的完整业务检测仍未完成，不能据此发布商用 APK 总体检测率。

| 验收项 | 实际结果 | 原始证据（相对本轮 output 根） |
|---|---|---|
| 根离线回归 | 最终 20/20 组通过 | `root-sealed/verification.json` |
| 移动兼容回归 | 24/24 组通过，含 upstream_mobile；只做兼容检查 | `mobile-compatibility/verification.json` |
| 测试入口登记 | scanned 239 / referenced 232 / allowlisted 7 / 未登记 0 | `tools/test_inventory_guard.py` |
| 通用隐私自有夹具 | 13 项检查全通过，正控含 Android ID/定位/联系人/麦克风 | `privacy-device-002/verification.json` |
| 整对坐标正控 | 1 次可比组合，1 个候选；完整请求与独立接收正文摘要相符 | `location-device-001/pair/verification.json` |
| 异值整对负控 | 1 次可比组合，0 候选 | `location-device-001/mismatch/verification.json` |
| 单坐标负控 | 1 次可比组合，0 候选 | `location-device-001/single/verification.json` |
| 重复来源对照 | 2 次实际读取、1 次上传，2 候选、1 歧义流 | `location-repeat-001/repeat/verification.json` |
| MG4 实际业务 | GET/链接/后退/刷新/POST/收藏/后台恢复完成；异 UID 请求负控通过 | `mg4-device-002/business.json` |
| MG4 正文归因 | 1 个完整 POST，1 个严格归因流；未使用归因替代 | 同上及 `capture/flows.jsonl` |
| MG4 会话绑定 | 10 条 UI 观察 + 1 条接收回执，共 11 条可重新核验 | `mg4-device-002/capture/session-binding.json` |
| 报告搬移完整性 | 35 项通过，导出包内绑定仍为 binding_consistent / 11 回执 | `mg4-sealed-audit/`、`mg4-sealed-audit.log` |
| B 侧正式交接 | completed；四组设备控制通过；第三方自然尝试已记录；缺类 0 | `handoff-acceptance/acceptance.json`、`REPORT.md` |

这些计数属于不同证据层，不能相加计算检测率。四组定位控制均关闭 TLS 校验收宽，
都有实际 SDK 返回、独立 session、完整请求和接收回执；负控不是依靠无输入通过。
坐标来自模拟 GPS，返回值存在实际精度差异，Actor 上传的字符串取自实际 Location 返回值。
观察 Hook 不修改 API 返回值；只有自有 debug Actor 构造不同值和单坐标负控载荷。

## 真正修复的阻断

1. **归档 Hook 丢失构建证明**：首轮驱动因 `freshness=no_manifest` 拒绝加载，采集为零。
   `archive_hook_bundle` 现在同时复制脚本与 `.sha256.json`，重过新鲜度闸，并核对首次预检摘要。
   没有删除或绕过门禁；失败目录 `privacy-device-001/` 保留。
2. **业务完成但新会话绑定仍为空**：MG4 原脚本在采集后才写业务汇总。
   现在在请求结束前封存本轮 UI 和完整正文接收回执，capture 收尾时重新核验实际文件。
3. **报告导出/交接丢绑定且可降级为旧会话**：新增统一依赖收集器，携带 binding、动作、
   回执、归档 Hook 和构建证明。manifest 已声明绑定但文件缺失时明确失败。
   增加删绑定、改回执、改构建证明、导出搬移后重新核验等反例。

新增设备入口 `tools/vehicle_location_device_acceptance.py`，默认执行四种控制，
也可用 `--case repeat` 单独执行某类。debug Actor 是 `AuditLocationReceiver`，不进入 release。
修改后的主要文件均不超过 300 行；最终检查涉及文件最高 294 行。

## 仍需开发与验证的部分

### HA：真实后端前提尚未具备

本轮 `ha-device-001/verification.json` 保留实际连接失败：本机回环 18123 没有 HA 服务。
原方案所需 Ubuntu/Python/HA 运行包在本机缓存中不齐，未用伪接口替代 HA。
因此没有 HA 电量 webhook 或订阅/控制的新验收结论。

下一项是重建可复现的官方 HA 后端运行包，核对当前原版 APK 与专用契约版本，再完成
App 正常登录、两次电量变化、服务端独立状态回执和订阅/控制验收。

### YAABSA：新版 APK 与旧版专用 Hook 不同

本轮已在自有模拟器部署真实官方 Audiobookshelf 2.37.2，逐层核对原版镜像摘要，
使用新建本地账户和自生成 180 秒音频；旧账户与旧验收没有迁移。
实际账户登录被服务端记录，Flutter 首页随后出现无法连接提示。

| 项 | SHA-256 |
|---|---|
| 当前仓库 APK | `5a00d0962d61f3aae2669e8802d23bf5ce819b7aa55f10204dad300d04f58873` |
| 旧专用 Hook 契约 APK | `3860d29741dd6f67fc79f03bb34132143da11e99c048ae4206863879505f68e1` |

专用 `abs_send` 只适配旧摘要，不能直接修改摘要白名单来冒充新版方法已验证。
本轮新版使用通用模式另建健康采集，实际为 0 条通用隐私取得、0 个可见流，
审计状态 `no_target_general_reads`，业务绑定仍 incomplete。
这是一轮明确的能力/业务缺口，不能作为安全阴性或完整播放进度检测通过。
证据在 `yaabsa-device-001/`、`yaabsa-device-002/`、`yaabsa-general-audit/` 与私有设置截图。

下一项是核对新版 DEX/实际运行栈、播放器方法和 native 请求调用者，解决本地业务连接，
再扩展版本契约并验证播放/暂停、前后台、两次进度和服务端增量回执。

### 检测率和产品边界

- MG4 这条浏览业务没有要求定位调用，B 侧第三方定位支持匹配数为 0，原因保留为
  `missing_general_location_reads`；其浏览/POST 业务通过不等于定位外发能力通过。
- 定位整对字符串匹配继续是实验能力，没有启用 VSC-GE-location 外发规则。
  分离数值坐标、GeoJSON、protobuf、其他精度等格式仍未覆盖。
- B 验收的 `workflow_verified=false` 与人工复核检查表保持待复核；宿主文件和摘要一致
  不构成独立专家金标准，也不证明唯一因果或违规。
- 晚启动进程、PID 生命周期复用、native TLS/未知协议等原有限制仍保留。
- 尚未完成有金标准的 3–5 个授权商用车载 APK 批次，不能发布总体 Precision/Recall。

## 实际环境与复现

| 项 | 本轮实测 |
|---|---|
| AVD | `VScanner_AAOS35_acceptance_20261111_v2`；本轮单独新建 |
| 镜像 | 本机 SDK `android-35-ext15/android-automotive/x86_64`，revision 3 |
| 指纹 | `google/sdk_gcar_x86_64/emulator_car64_x86_64:15/AAI5.260516.001.A1/15446886:userdebug/test-keys` |
| 设备/用户 | `emulator-5554` / user 10；普通第三方安装 |
| SDK | `E:/Android/android-sdk` |
| Python | 统一脚本实际选择项目 `.venv`，版本 **3.12.14**；本轮所需依赖检查通过 |
| Frida | 客户端/服务端 17.18.0；设备仅绑定 `127.0.0.1:27043` |
| 构建 | Gradle 8.13 / JDK 17.0.12；Java/Kotlin target 17；当前 debug APK 实际构建成功 |

Python 实际值与旧环境表的 3.13 不同，本轮记录实际解释器，没有借助默认 WindowsApps python。
初始 Gradle 镜像下载和旧 JDK AF_UNIX 回环失败均保留日志；从官方发布获取 Gradle，按
[官方校验表](https://gradle.org/release-checksums/) 核对 SHA-256 后使用。
根据本机 JDK 源码提供的 bind 失败回退路径，仅在该构建进程设置
`JAVA_TOOL_OPTIONS=-Djdk.net.unixdomain.tmpdir=C:/Users/OneKyubey/AppData/Local/Temp/vscanner-afunix-unused/unavailable`，
使其使用 TCP 回环；不修改系统 Java 默认配置。
Frida 服务端按[官方发布资源](https://github.com/frida/frida/releases/expanded_assets/17.18.0)的摘要校验。
下载 URL、摘要、失败尝试、构建日志均在 `device/`。

设备控制复现（自有夹具安装在 user 10，设备为 AAOS35 时）：

```powershell
$env:ANDROID_USER_HOME='C:/Users/OneKyubey/.android'
$env:VSCAN_SDK='E:/Android/android-sdk'
$env:VSCAN_SERIAL='emulator-5554'
.\tools\python313.ps1 tools/vehicle_location_device_acceptance.py --out output/location-new
.\tools\python313.ps1 -m vehicle.lab.browser_run --out output/mg4-new --webview-probe --native-control
```

每次必须使用新目录；设备权限、定位开关、代理和 reverse 映射由验收入口按初始状态恢复。
原始私有 UI/后端账户文件留在 ignored output，不提交远程。

## 本地代码基线

分支 `codex/vehicle-live-acceptance`：

- `4c2a088`：封存已有 PID 引用、就绪契约、生命周期与诊断账本基线。
- `394a748`：修复构建证明归档，封存实际业务回执，加入定位设备控制。
- `9dbf3b0`：补齐报告/交接依赖，阻止缺绑定降级，加入重复来源设备控制。

MG4 的采集发生在 4c2a088 上的本轮宿主修复尚未提交时，随后封存为 394a748；
handoff 动作明确记录这一点，Hook 的源码/构建证明另外独立绑定。
前三个定位会话来自 394a748 的 APK，重复来源会话来自 9dbf3b0 的 APK，
两份实际 APK 已分别归档并与各会话装机摘要核对。本文记录设备验收基线；
上传时另合并远程 main 的队友更新，远程同步状态以仓库提交历史为准。
