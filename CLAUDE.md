# V-Scanner 项目根

面向 AAOS 的第三方车载 App 数据安全合规审计平台（杭州师范大学星光计划，2026）。
链路：规则库(1) → 靶子 App(2) → Frida 动态插桩(3) → Mitmproxy 流量层(4) →
关联分析与报告(5) → Web 预警看板(6)。**仅用于授权测试（自有设备与自有 APK）。**

## 用户定的全局约束（任何 phase 都适用，不得违反）

1. **仅授权测试**：涉及抓包/Hook 的代码必须写明"仅用于授权测试"，默认只监控白名单包名。
2. **绝不编造签名**：`android.car` 的类名/方法/protectionLevel/propertyId 不确定就生成
   TODO + 占位常量表 + 探测脚本让用户跑。例外：CAR_SPEED / CAR_ENERGY 已实测存在。
3. **观察不改写**：观察阶段只记录，不拦截不篡改（`ssl_pinning_bypass.js` 是唯一例外，
   且仅对白名单进程、仅为审计流量捕获）。
4. **可运行优先于完整**：每阶段交付物必须能在用户环境跑通，再谈完整。
5. **判定可追溯**：每条违规结论带规则 ID + 依据来源。
6. **失败可诊断**：Hook 脚本 try/catch + 日志落盘，区分"没读到数据"和"脚本崩了"。
7. **禁止再让用户做环境探测**（Phase 0 已完成）。
8. **单文件 ≤300 行**；超了按职责拆分（hooks/traffic/dashboard 都有拆分的先例），拆后必须回归验证。

## 环境事实（旧设备记录与当前主机路径；入口 environment.ps1）

| 项 | 值 |
| --- | --- |
| Python | `C:/Users/OneKyubey/AppData/Local/Programs/Python/Python313/python.exe`（**只有它**装了 frida/mitmproxy/reportlab，默认 `python` 没有） |
| SDK | `E:\Android\android-sdk`（2026-09-24 用户更新）；`JAVA_HOME=本项目 .tools/jdk21/jdk-21.0.12.1+1`（JDK 21，**不要用 JBR 25**） |
| 设备 | AAOS 模拟器 `emulator-5554`，Android 15 / API 35 / userdebug；**应用跑在 user 10** |
| frida-server | 设备 `/data/local/tmp/frida-server -l 127.0.0.1:27043`（**27043 不是 27042**）；spawn 超时，用 attach |
| 网络 | 设备只走 wifi 且会掉线；宿主机 `dl.google.com` 不通 → maven 用阿里云镜像；Git Bash 的 `$PWD` 是 POSIX 形式，写进 Windows 环境变量要用 `$(pwd -W)` |
| 编译 | Gradle 8.13 / AGP 8.11.1 / Kotlin 2.2.0 / KSP 2.2.0-2.0.2 / Room 2.8.5，compileSdk 36（唯一带 android.car.jar 的平台）；工程路径含非 ASCII 需 `android.overridePathCheck=true` |

## Phase 地图

| 目录 | 内容 | 详情 |
| --- | --- | --- |
| `vehicle/rules/` | 规则库（双版本 rules.db）+ Android Room 工程 | [vehicle/rules/CLAUDE.md](vehicle/rules/CLAUDE.md) |
| `vehicle/targets/` | 靶子 App×2（被测对象）+ trigger.py | [vehicle/targets/CLAUDE.md](vehicle/targets/CLAUDE.md) |
| `vehicle/hooks/` | Frida 钩子（VHAL 读取/出站/TLS 绕过/侦察） | [vehicle/hooks/CLAUDE.md](vehicle/hooks/CLAUDE.md) |
| `vehicle/traffic/` | Mitmproxy 反向代理 + 按包名归因 + 敏感打标 | [vehicle/traffic/CLAUDE.md](vehicle/traffic/CLAUDE.md) |
| `vehicle/analyze/` | 关联引擎 + PDF 报告 + 违规代码行号（dex 核对） | [vehicle/analyze/CLAUDE.md](vehicle/analyze/CLAUDE.md) |
| `vehicle/dashboard/` | Web 可视化预警看板（交付物 B，静态单文件） | [vehicle/dashboard/CLAUDE.md](vehicle/dashboard/CLAUDE.md) |
| `vehicle/workbench/` | APK 静态分析工作台（拖入看源码 + 规则匹配 + 静动四象限） | [vehicle/workbench/CLAUDE.md](vehicle/workbench/CLAUDE.md) |

各目录的实测教训记录在各自 `DECISIONS.md`（D101–D606 编号），
改任何模块前先读对应目录的 DECISIONS——几乎每个坑都是**静默失败**。

## 离线回归（改完代码先跑，不需要设备）

```bash
PY="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"
"$PY" tools/run_regressions.py        # 10 组：completion/rules-contract/codeloc/correlate/
                                      #       collector/tagging-vehicle/dashboard/runtime/parity/workbench
```

## 当前交付（2026-09-24）

完整复现入口与证据说明见 [COMPLETION.md](COMPLETION.md)。
APK 静态反编译作为**独立工作台**加入（vehicle/workbench，2026-09-28，用户解除原排除）；违规代码行号仍**只**取自运行时栈（D507 不变），静态证据不写进 code_locs。

已补齐：RDAP归属与IP位置估计/离线缓存、PDF载荷截图、SQLite单机时序事件库、
自有源码Gadget模式、OkHttp固定证书夹具、订阅回调、规则覆盖缺口展示、/collect 200接收端。
外发规则每版8条已正式启用，窗口30000ms，revision=2；双版本44条风险规则全部启用。
启用依据与范围见 vehicle/rules/EGRESS_CALIBRATION.md，不再依赖分析时窗口覆盖。

边界仍须保留：native TLS/未解析协议无明文能力；Gadget需要自有源码与安装授权，
不支持无条件注入任意第三方APK；统计归因遇歧义不关联；代码行号不证明违规语义。
工具不输出policy_violation。缺失注册组织/位置不得编造，IP位置只能标估计。

新增离线回归入口：`python tools/run_regressions.py`；结果写入独立output/regression-*。
所有采集器显式使用同一session，避免混合会话；失败运行保留，不能只凭文件存在宣称通过。
