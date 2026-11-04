# 普通第三方车载 App：P0 / P1 本轮交付

日期：2026-11-02。仅用于授权测试（自有设备与用户授权的公开 APK）。

## 范围

目标为普通第三方安装的车载 App。采集设备具备授权调试条件，不代表任意锁定量产车机均可注入。
AAOS 35 是 Android 15 / API 35。API 34 与 35 已通过通用来源夹具设备验收（API 34
`general_dynamic_verified=true`、全量车载 `dynamic_verified=false`）；API 33、36 只做了规则登记与
能力声明（14 为 source_reference，13/16 为 planned），二者 `general_dynamic_verified=false`、
`general_validation_scope=no_device_acceptance`；离线流水线通过不等于设备验收。
车型与版本依据见 [COMPATIBILITY.md](COMPATIBILITY.md)。前端仍属移动线，车载用独立 CLI。

## 已实现

| 优先级 | 交付 | 判据 |
|---|---|---|
| P0 | `vehicle.ps1` / `python -m vehicle` 统一入口 | prepare / profiles / coverage / capture / audit / samples / benchmark / scenarios |
| P0 | 可复现 Hook 构建、解释器选择 | 现有 .venv 非必要；按锁文件安装、跳过原生安装脚本；失败留构建日志 |
| P0 | 采集健康与证据前置检查 | APK/会话/白名单/API/规则/Hook/新版输入摘要核验；失败不提交正常 summary |
| P0 | 严格归因与回调健康 | 禁止唯一白名单包兜底；未知正文不持久化；回调异常有结构化 failed 状态 |
| P0 | 诊断失败不覆盖原始失败 | ADB/logcat/manifest/清理失败分别记录，仍写最终验收状态 |
| P0 | 数据到验收覆盖链 | [自动生成表](coverage/generated/COVERAGE.md) 与同目录 JSON；8 属性、5 类未接入数据；空映射明确列出 |
| P1 | 自有车载场景 | [场景目录](scenarios/CATALOG.md)：同意 UI/撤回、缓存批传/清理、跨用户缓存、模拟行驶、真实链路断开/恢复 |
| P1 | 政策与业务必要性复核 | core/policy 共享正文解析；APK 绑定、协议分离、正文字符引用、用途与必要性人工复核 |
| P1 | 独立样本与评估工具 | 官方 APK 下载/来源/摘要/签名记录；静态与运行时分开，独立标注可计算配对 TP/FP/FN |

## 本轮设备与证据

新建独立 AAOS 35-ext15 x86_64 r04 userdebug AVD，位于 `output/vehicle-device-setup/`，不修改既有手机 AVD。
官方镜像 1,402,295,681 字节，SHA-1 与官方索引一致：`0ddb2dd3cf225407000c32e5d73a3f3529c6e94c`。
Frida 17.18.0 与宿主一致，回环 27043；被测普通 App 位于 user 10。

- 基础设备读取/订阅/HTTP/HTTPS 验收通过。
- 最新严格目标归因独立实测通过：23 条读取事件、1 条成功流量、14 个值级配对，进程正常退出且 PID 存活。
- 既有 7 个场景通过；新增 6 个同意/缓存/网络/车辆状态场景本轮 6/6 通过
  （`output/vehicle-context-20261102-140807-70d2d7/verification.json`）。
  reverse 模式改用 Host 头做目标锚定（D417），离线重连寻址 `10.0.2.2` 正常归因；
  系统连通性探测被目标校验挡下，只计入 `scope-discarded.json` 的丢弃计数，不再误归夹具。
- 用户切换、不同 UID、跨用户拒绝配对、新用户空缓存、原用户缓存恢复曾在完整轮次通过。
  2026-11-02 复验第三次通过（`output/vehicle-users-20261102-205712/verification.json`，
  12/12 项 checks、5 个用例）；
  复跑脚本已加就绪门、`pm grant` 有界重试与 detach 等待，早期 ADB 超时失败轮次保留为证据。
- Hook 开销配对测量已落地：`./vehicle.ps1 overhead`，本轮两份产物
  `output/vehicle-hook-overhead-20261102-213242`（6 配对 × 4 动作）与
  `output/vehicle-hook-overhead-20261102-213504`（4 配对 × 12 动作，中位 CPU 增量 845 ms、
  276 条 VHAL_READ/轮）。检测准确率仍为未测量。
- 本轮完整回归收口：`run_regressions.py --mobile` 17 组全 0（`output/regression-20261102-221059`）、
  `run_mobile_checks.py` 28/28（`output/mobile-regression-20261102-221335`）、
  `check_mobile_branch.py` 24/24（`output/mobile-branch-20261102-221336`）；
  汇总见 `output/vehicle-p0p1-verification-final-20261102.json`。
  17:44 的 `output/vehicle-p0p1-verification.json` 是多用户复验前的旧快照，保留不覆盖。
- 真实夹具证据经 APK 核对、关联、场景、静态与 PDF 全流程；报告已渲染检查。

所有轮次包括失败轮次均保留在本机 `output/`；产物不随 Git 分发。失败诊断与最终通过证据分开，
不能只凭目录或 PDF 存在认定通过。JSON 汇总保存准确路径、状态和限制。

## 公开独立样本

已从 Home Assistant 官方 Release 下载 `2026.10.1` Automotive minimal APK，普通安装并完成 AAOS 35 健康采集。
APK SHA-256：`0a6ecb8634c9995aa7cbad9e81b6497eaab2234e0996590b77860fa619b94847`。
签名密码学验证有效，未将证书 DN 当成独立发布方身份背书。
静态发现 2 条候选；45 秒未登录观察中无覆盖范围内的车辆读取/代理流，不代表无隐私行为。
APK 全量声明 47 条权限，API 35 PM 有效请求为 44 条；差异来自 BLUETOOTH/ADMIN 的 maxSdk 30
以及 WRITE_EXTERNAL_STORAGE 的 maxSdk 28，不是漏解析。
从 APK classes7.dex 的实际 URL 字符串找到官方隐私政策，保存当前公开快照、来源和摘要并运行政策复核。
当前政策快照不冒充该 APK 发布时的确切版本；必要性与同意范围需人工确认。
AudioWagon 官方最新发布入口未能解析出可下载 APK，下载失败保留，未替换为来历不明镜像。

**登录后业务明确未覆盖**：唯一可用的第三方公开演示站 `app.testhomeassistant.fr` 是共享账号、
每晚重置，既不能保证测试隔离，也不是可复现的验收服务端；本轮未自建隔离 HA 实例，
因此登录后的传感器/车辆实体业务没有执行记录。演示站观察数据不作为正式验收证据。

## 尚未完成，不能算通过

- Home Assistant 登录后传感器/车辆业务：缺少可隔离的自有服务端，当前只覆盖安装、启动与未登录范围。
- 独立专家配对标注与长时间真实样本分布：precision/recall 与 30 秒窗口覆盖率保持 null 或未确立；
  Hook 开销已有配对测量，但没有独立人工标注，不能写成检测准确率。
- 多个独立应用家族的完整业务验证、其他 AAOS API 的动态校准、量产 OEM 真车、休眠/点火、蜂窝重连。
- AAID **读取已覆盖**（见 [AAID_POLICY.md](privacy/AAID_POLICY.md) 与规则 `VSC-GR-advertising_id`），
  **外发关联未覆盖**；厂商私有车辆属性仍未接入（覆盖表已列为未覆盖，不冒充已覆盖）。
- 未提供真实 AI 服务配置时为 skipped，不用模板冒充大模型调用。

因此：P0 工程能力已落地；P1 工具、夹具场景及首个独立样本基线已落地。
P1 全量验收尚未完成，仍需独立样本完整业务、统计标定与 API 33/36 设备验收。

## 复跑

```powershell
./vehicle.ps1 prepare --install-deps
./vehicle.ps1 coverage
./vehicle.ps1 scenarios --suite all
./vehicle.ps1 samples --out output/new-samples
./vehicle.ps1 benchmark --manifest output/new-samples/manifest.json --out output/new-benchmark
. ./environment.ps1
& $VScanPython tools/run_regressions.py --mobile
& $VScanPython tools/check_mobile_branch.py
```

夹具须先用 JDK 21 / Gradle `:app:assembleDebug` 构建；正式动态审计前需启动自有 AAOS 与匹配 Frida。
构建网络故障时，临时镜像/缓存修复不改用户全局 Gradle 配置。本轮临时 Maven 修复文件保存在 output。

## Review 修复复验（2026-11-02）

普通/反向代理按实际模式选择目标，延迟归因复用首次目标；通用规则来源改用独立采集快照，
只更新 6 条 Android15 通用规则的来源字段，VHAL 数据与其余字段逐项核对未变。
失败开销臂及其配对排除统计；基准读取合计 VHAL/通用来源，并仅将 obtained 计入通用成功。
验证：17 组离线回归、6 个真实设备上下文场景、Android 规则工程构建均通过；APK 内规则摘要与
DEX 校验常量一致。另修复已有 KDoc 中通配符导致注释提前结束的编译错误。
记录：`output/review-fixes-20261102/verification.json`；历史失败与修复前库备份均保留。
