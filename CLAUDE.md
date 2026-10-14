# V-Scanner 项目根

面向 AAOS 的第三方车载 App 与移动端 App 数据安全合规审计平台（杭州师范大学星光计划，2026）。
**仅用于授权测试（自有设备与自有 APK）。**

本仓库已把「车载审计」与「移动端审计」两条产品线**分开**，共享平台无关内核：

```
vscanner/
├── core/           # 平台无关内核（唯一一份）：事件库/流量采集/代码行号/规则契约/Frida驱动/静态内核
├── vehicle/        # 车载 AAOS 产品线：rules→targets→hooks→traffic→analyze→dashboard→workbench
├── mobile/         # 移动端产品线：规则库/钩子/政策/AI/报告/工具（详见 mobile/CLAUDE.md）
├── frontend/       # 前端壳（车载工作台专用；移动端报告在 output/mobile-*/ 下）
└── tools/          # 验收 / 回归脚本
```

> 权威入口与拆分进度见 [AGENTS.md](AGENTS.md)；复现与证据说明见 [COMPLETION.md](COMPLETION.md)。

## 用户定的全局约束（两条产品线都适用，不得违反）

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

## 环境事实（当前主机；入口 environment.ps1）

| 项 | 值 |
| --- | --- |
| Python | `C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe`（**只有它**装了 frida/mitmproxy/reportlab，默认 `python` 没有；`environment.ps1` 用 `$env:LOCALAPPDATA` 派生，换机不硬编码用户名） |
| SDK | `D:\Anroid\SDK`；`JAVA_HOME=D:\Anroid\JDK`（JDK 21，**不要用 JBR 25**） |
| 设备 | AAOS 模拟器 `emulator-5554`，Android 15 / API 35 / userdebug；**应用跑在 user 10** |
| frida-server | 设备 `/data/local/tmp/frida-server -l 127.0.0.1:27043`（**27043 不是 27042**）；spawn 超时，用 attach |
| 网络 | 设备只走 wifi 且会掉线；宿主机 `dl.google.com` 不通 → maven 用阿里云镜像；Git Bash 的 `$PWD` 是 POSIX 形式，写进 Windows 环境变量要用 `$(pwd -W)` |
| 编译 | Gradle 8.13 / AGP 8.11.1 / Kotlin 2.2.0 / KSP 2.2.0-2.0.2 / Room 2.8.5，compileSdk 36（唯一带 android.car.jar 的平台）；工程路径含非 ASCII 需 `android.overridePathCheck=true` |

## 命名对照（Phase N → vehicle/*）

目录已从 `phase1–7` 语义化改名；各子目录 `DECISIONS.md` 仍按旧 Phase N 与 `D1xx–D7xx` 编号
记录历史决策（保留为历史证据），阅读时用此表对照：

| 旧名 | 新目录 | 内容 |
| --- | --- | --- |
| Phase 1 | `vehicle/rules/` | 车载规则库（VSC-*，双版本 rules.db）+ Room 工程 |
| Phase 2 | `vehicle/targets/` | 靶子 App×2（被测对象）+ trigger.py |
| Phase 3 | `vehicle/hooks/` | Frida 钩子（VHAL 读取/出站/TLS 绕过/内存明文/侦察） |
| Phase 4 | `vehicle/traffic/` | Mitmproxy 反向代理 + 按包名归因 + 敏感打标 |
| Phase 5 | `vehicle/analyze/` | 关联引擎 + PDF 报告（代码行号已抽到 core/evidence） |
| Phase 6 | `vehicle/dashboard/` | Web 可视化预警看板（交付物 B，静态单文件） |
| Phase 7 | `vehicle/workbench/` | APK 静态反编译工作台（server + static_rules + crosscheck） |

## 产品地图

| 目录 | 内容 | 详情 |
| --- | --- | --- |
| `core/` | 平台无关内核（车载/移动共用） | `event_store.py` 时序事件库；`collector/` 流量采集；`evidence/` 代码行号+dex 核对；`rules_contract.py` 规则库契约；`frida_host/` Frida 驱动；`static/` 静态内核 |
| `vehicle/rules/` | 车载规则库（VSC-*，双版本 rules.db）+ Room 工程 | [vehicle/rules/CLAUDE.md](vehicle/rules/CLAUDE.md) |
| `vehicle/targets/` | 靶子 App×2（被测对象）+ trigger.py | [vehicle/targets/CLAUDE.md](vehicle/targets/CLAUDE.md) |
| `vehicle/hooks/` | Frida 钩子（VHAL 读取/出站/TLS 绕过/内存明文/侦察） | [vehicle/hooks/CLAUDE.md](vehicle/hooks/CLAUDE.md) |
| `vehicle/traffic/` | Mitmproxy 反向代理 + 按包名归因 + 敏感打标（VHAL 指纹表） | [vehicle/traffic/CLAUDE.md](vehicle/traffic/CLAUDE.md) |
| `vehicle/analyze/` | 关联引擎 + PDF 报告（代码行号已抽到 core/evidence） | [vehicle/analyze/CLAUDE.md](vehicle/analyze/CLAUDE.md) |
| `vehicle/dashboard/` | Web 可视化预警看板（交付物 B，静态单文件） | [vehicle/dashboard/CLAUDE.md](vehicle/dashboard/CLAUDE.md) |
| `vehicle/workbench/` | APK 静态反编译工作台（server + static_rules + crosscheck） | [vehicle/workbench/CLAUDE.md](vehicle/workbench/CLAUDE.md) |
| `mobile/` | 移动端产品线（MOB-* 规则库/钩子/政策/AI/报告/工具） | [mobile/CLAUDE.md](mobile/CLAUDE.md) |
| `frontend/` | 车载工作台前端壳 | [frontend/README.md](frontend/README.md) |

各目录的实测教训记录在各自 `DECISIONS.md`（D101–D7xx 编号），
改任何模块前先读对应目录的 DECISIONS——几乎每个坑都是**静默失败**。

## 规则库（已分开）

两套 `.db` 物理独立、schema 大同小异，通过 `core/rules_contract.py` 以 **rule_id 前缀**
（`VSC-` 车载 / `MOB-` 移动）作权威判别符、按平台加载扩展表：

| 库 | 路径 | 前缀 | 扩展表 |
| --- | --- | --- | --- |
| 车载 | `vehicle/rules/rules_library/rules.db` | `VSC-` | `vhal_properties` |
| 移动 | `mobile/rules/rules_mobile.db` | `MOB-` | `sensitive_data_types` / `app_categories` / `policy_requirements` |

移动库不再伪造空 `vhal_properties` 表去适配车载加载器（该 hack 已删除）。

## 新增能力（2026-10）

- **内存 Hook（车载 `vehicle/hooks/`）**：`hook_cipher.js`（hook JCE `Cipher.update/doFinal`，
  截获自绘加密**加密前明文**）+ `hook_native_ssl.js`（`Interceptor.attach` BoringSSL
  `SSL_write/SSL_read`，截获 native TLS 明文）+ 共享 `stack_capture.js`，补齐申报书
  「内存 Hook 截获明文 Buffer」缺口。夹具新增 `CipherSender`（AES/GCM）+ 按钮「4. 自绘加密外泄」。
  离线编译已过，**设备端实测待跑**。
- **透明代理（移动 `mobile/traffic/transparent.py`）**：模拟器级强制代理
  （`emulator -http-proxy`）+ 系统级 CA，让第三方 App 流量**无法绕过**抓包（不依赖 App 是否
  读取系统代理设置）。带 `test_transparent.py` 离线自检。

## 离线回归（改完代码先跑，不需要设备）

```bash
PY="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"
"$PY" tools/run_regressions.py            # 车载/内核 12 组：completion/rules-contract/codeloc/
                                          #   correlate/collector/tagging-vehicle/dashboard/runtime/parity/
                                          #   workbench/hook-bundles/frida-bundle-config
"$PY" mobile/tools/run_mobile_checks.py   # 移动端 22 项
```

## 边界（必须保留）

native TLS/未解析协议无明文能力；Gadget 需要自有源码与安装授权，
不支持无条件注入任意第三方 APK；统计归因遇歧义不关联；代码行号不证明违规语义。
工具不输出 policy_violation。缺失注册组织/位置不得编造，IP 位置只能标估计。
内存 Hook 不覆盖静态链接自有 BoringSSL 且符号不导出的栈（Cronet 常见）、不经 JCE 的手工加密。

所有采集器显式使用同一 session，避免混合会话；失败运行保留，不能只凭文件存在宣称通过。
