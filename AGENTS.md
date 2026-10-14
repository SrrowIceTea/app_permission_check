# V-Scanner 项目根

面向 AAOS 的第三方车载 App 与移动端 App 数据安全合规审计平台（杭州师范大学星光计划，2026）。
**仅用于授权测试（自有设备与自有 APK）。**

本仓库正在把「车载审计」与「移动端审计」两条产品线**分开**，共享平台无关内核：

```
vscanner/
├── core/           # 平台无关内核（唯一一份）：事件库/流量采集/代码行号/规则契约/Frida驱动/静态内核
├── vehicle/        # 车载 AAOS 产品线：rules→targets→hooks→traffic→analyze→dashboard→workbench
├── mobile/         # 移动端产品线：规则库/钩子/政策/AI/报告/工具（详见 mobile/CLAUDE.md）
├── frontend/       # 前端壳（车载工作台专用；移动端报告在 output/mobile-*/ 下）
└── tools/          # 验收 / 回归脚本
```

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

## 产品地图

| 目录 | 内容 | 详情 |
| --- | --- | --- |
| `core/` | 平台无关内核（车载/移动共用） | `event_store.py` 时序事件库；`collector/` 流量采集；`evidence/` 代码行号+dex 核对；`rules_contract.py` 规则库契约 |
| `vehicle/rules/` | 车载规则库（VSC-*，双版本 rules.db）+ Room 工程 | [vehicle/rules/CLAUDE.md](vehicle/rules/CLAUDE.md) |
| `vehicle/targets/` | 靶子 App×2（被测对象）+ trigger.py | [vehicle/targets/CLAUDE.md](vehicle/targets/CLAUDE.md) |
| `vehicle/hooks/` | Frida 钩子（VHAL 读取/出站/TLS 绕过/内存明文/侦察） | [vehicle/hooks/CLAUDE.md](vehicle/hooks/CLAUDE.md) |
| `vehicle/traffic/` | Mitmproxy 反向代理 + 按包名归因 + 敏感打标（VHAL 指纹表） | [vehicle/traffic/CLAUDE.md](vehicle/traffic/CLAUDE.md) |
| `vehicle/analyze/` | 关联引擎 + PDF 报告（代码行号已抽到 core/evidence） | [vehicle/analyze/CLAUDE.md](vehicle/analyze/CLAUDE.md) |
| `vehicle/dashboard/` | Web 可视化预警看板（交付物 B，静态单文件） | [vehicle/dashboard/CLAUDE.md](vehicle/dashboard/CLAUDE.md) |
| `vehicle/workbench/` | APK 静态反编译工作台（server + static_rules + crosscheck） | [vehicle/workbench/CLAUDE.md](vehicle/workbench/CLAUDE.md) |
| `mobile/` | 移动端产品线（MOB-* 规则库/钩子/政策/AI/报告/工具） | [mobile/CLAUDE.md](mobile/CLAUDE.md) |

各目录的实测教训记录在各自 `DECISIONS.md`（D101–D7xx 编号），
改任何模块前先读对应目录的 DECISIONS——几乎每个坑都是**静默失败**。

**命名对照**（目录已从 `phase1–7` 改名，子目录 `DECISIONS.md` 仍按旧 Phase N / D1xx–D7xx 记录历史决策）：
Phase 1=`vehicle/rules/`，Phase 2=`vehicle/targets/`，Phase 3=`vehicle/hooks/`，Phase 4=`vehicle/traffic/`，
Phase 5=`vehicle/analyze/`，Phase 6=`vehicle/dashboard/`，Phase 7=`vehicle/workbench/`。

## 规则库（已分开，2026-10-12）

两套 `.db` 物理独立、schema 大同小异，通过 `core/rules_contract.py` 以 **rule_id 前缀**
（`VSC-` 车载 / `MOB-` 移动）作权威判别符、按平台加载扩展表：

| 库 | 路径 | 前缀 | 扩展表 |
| --- | --- | --- | --- |
| 车载 | `vehicle/rules/rules_library/rules.db` | `VSC-` | `vhal_properties` |
| 移动 | `mobile/rules/rules_mobile.db` | `MOB-` | `sensitive_data_types` / `app_categories` / `policy_requirements` |

移动库不再伪造空 `vhal_properties` 表去适配车载加载器（该 hack 已删除）。

## 离线回归（改完代码先跑，不需要设备）

```bash
PY="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"
"$PY" tools/run_regressions.py        # 12 组：completion/rules-contract/codeloc/correlate/
                                      #       collector/tagging-vehicle/dashboard/runtime/parity/
                                      #       workbench/hook-bundles/frida-bundle-config

"$PY" mobile/tools/run_mobile_checks.py   # 移动侧 22 项（另一条入口，改 mobile 后必须跑）
```

> **先确认解释器再判红**：这两条都依赖 `requirements.txt`（`reportlab`/`Pillow`/`mitmproxy`/
> `cryptography`/`frida`/`pypdf`）。若解释器没装，会冒出 6 处 `ModuleNotFoundError` 的**假红**，
> 把真正的回归失败盖住。看到红先跑一次 `"$PY" -c "import reportlab, PIL, mitmproxy, cryptography"`。

## 当前交付与拆分进度（2026-10-12）

完整复现入口与证据说明见 [COMPLETION.md](COMPLETION.md)。
APK 静态反编译作为**独立工作台**（vehicle/workbench，2026-09-28，用户解除原排除）；违规代码行号仍**只**
取自运行时栈（D507 不变），静态证据不写进 code_locs。

已补齐：RDAP 归属与 IP 位置估计/离线缓存、PDF 载荷截图、SQLite 单机时序事件库、
自有源码 Gadget 模式、OkHttp 固定证书夹具、订阅回调、规则覆盖缺口展示、/collect 200 接收端。
外发规则每版 8 条已正式启用，窗口 30000ms，revision=2；双版本 44 条风险规则全部启用。
启用依据与范围见 vehicle/rules/EGRESS_CALIBRATION.md，不再依赖分析时窗口覆盖。

**拆分进度**（已提交、每步回归全绿）：
- ✅ 建 git 仓库 + 快照（ce1859d）
- ✅ `core/event_store.py`（audit_store 迁移）
- ✅ `core/collector/`（vehicle/traffic 流量采集内核 + `VSCAN_TAGGING` 平台打标表注入）
- ✅ `core/evidence/`（vehicle/analyze 代码行号/事件定位/dex 核对）
- ✅ `core/rules_contract.py` + 两份 `rules.manifest.json`（规则库分开的契约层）
- ✅ `core/frida_host/`（Frida 驱动 + 共享 bundle，斩断 mobile 对 vehicle/hooks 的引用）
- ✅ `core/static/`（静态分析内核，斩断 mobile 对 vehicle/workbench 的引用）
- ✅ `phase1–7` → `vehicle/*` 语义化改名（rules/targets/hooks/traffic/analyze/dashboard/workbench）
- ✅ `frontend/` 的 `--android-version` 从 manifest 读（不再写死 14/15）
  - 注：同时做过的「清除移动端 PDF 污染」（把三份移动端报告移出 `frontend/pdfs/`）
    **已于 2026-10-13 撤回**——前端才是日常查看报告的入口，只列车载不够用；
    三份已移回，见 `archive/MANIFEST.md` 第 2 条
- ✅ 修 `core/static/` 的 Windows MAX_PATH（拆分把 `phase7/` 改名为 `vehicle/workbench/`
  后，jadx 源码树最深路径由 ~253 涨到 262，越过 260 → 拖入 APK 直接分析失败）：
  新增 `core/static/winpath.py`（`\\?\` 扩展长度路径，覆盖 stat/read/rmtree 四个边界）
  + 离线回归 `test_jobs.LongPathTest`
- ✅ `apk/` 按平台分目录：`apk/mobile/`（手机样本）与 `apk/vehicle/`（车载样本），
  移动端取样本的默认目录跟着改；见 `apk/README.md`
- ✅ 修 `tools/device_acceptance.py` 的钩子路径（拆分漏改）：`hook_egress`/`ssl_pinning_bypass`
  已移到 `core/frida_host/dist/`，原路径导致 run.py `no such script` + **空等 40 秒**等 ARMED；
  `session-manifest` 的 `hook_bundles` 同时补上 core 目录（原先静默漏记这两个的哈希）。
  新增离线守卫 `tools/test_hook_bundles.py`（已并入 `run_regressions.py`）

**待办**：拆分主体已完成。剩余可选整理（见 archive/README.md）：
- `output/` 历史产物归档——涉及 `latest-*.txt` 指针与 DELIVERY_INDEX 引用链，需确认后再动

边界仍须保留：native TLS/未解析协议无明文能力；Gadget 需要自有源码与安装授权，
不支持无条件注入任意第三方 APK；统计归因遇歧义不关联；代码行号不证明违规语义。
工具不输出 policy_violation。缺失注册组织/位置不得编造，IP 位置只能标估计。

所有采集器显式使用同一 session，避免混合会话；失败运行保留，不能只凭文件存在宣称通过。
