# V-Scanner 两人协作开发规划（2026-10-19 · 移动端聚焦版 v4 —— M034–M039 同步）

> **仅用于授权测试（自有设备与自有 APK）。**
> **v4 修订说明（2026-10-19）**：按 v3 定的规矩「改完当场重标」，对 10-16 之后落地的
> M034–M039 做一次状态同步。**四条从"待做"翻为"已完成"**：
> ① **C1 派生值匹配**（`core/collector/derive.py`，M035）；
> ② **C2 静态/动态覆盖差集**（`mobile/analyze/coverage_gap.py`，M035）；
> ③ **工程-6** `conn_probe` 并发防撞（M034）；
> ④ **工程-7** `run_regressions --mobile` 开关（M034）。
> **v3 未覆盖的新增主线**（§2.5 补录）：M036 明文缺口真根因（Frida 17 API 已删 + 库懒加载 +
> `RTLD_LOCAL`）、M037 应用层加密与 TLS 元数据、M038 完整 HTTP 报文（tcpdump+keylog+tshark）、
> M039 Flutter/剥符号 BoringSSL；以及**风险量化模型 v1.0→v1.3**（`mobile/analyze/risk_score.py`）。
> **工程-2 的口径也变了**：>300 行文件由「6 个」涨到 **11 个**（见 §1 该行），拆分不能再按旧清单做。
> 依据：`mobile/DECISIONS.md` M034–M039；实查 `find + wc -l`、文件存在性与 DB 计数（2026-10-19）。
> v3 保留说明：A1 / SLIRP 已于 2026-10-16 修复并独立复验（`VERIFY_M031_M032_20261016.md`）。
> **v3 修订说明（2026-10-16 晚）**：把 v2 中标"待设备定位"的 **A1（插桩打死应用，唯一 P0 硬阻塞）**
> 与当晚新发现的 **SLIRP 强制代理失效（P0）** 两项**重标为「已修」**；"关 JIT"假修复路线已双向证伪并
> 清退（M032）。§3 排期、§6 行动项随修复顺延重排。
> 依据：`mobile/DECISIONS.md` M031/M032、`mobile/DEV_FIX_REPORT.md` §5.8/§5.9、独立复验报告
> `VERIFY_M031_M032_20261016.md`（代码清退核查 + 原始证据核对 + 回归重跑）。
> v2 保留内容：对全部移动端问题的逐条核查（§1 四档结论）与"文档状态列不可信、以代码为准"的方法论。

---

## 0. 一页纸结论

- **A1 已修（2026-10-16）**：三层根因定位——① ~~JIT×ArtMethod 替换竞态~~【假层，已证伪清退】、
  ② **JNI transition frame reference**（Android 14+ CheckJNI 拒绝 Frida trampoline 帧，上游
  frida#3700/#3745 未修）→ **bridge 补丁**（`patches/02-class-factory-transition-ref.patch`）、
  ③ **多脚本替换不被 bridge 支持**（x64 + API 37 恰在未覆盖区）→ **单 agent 合并**（`hook_all` bundle，
  事件由 `split_events.py` 分流回独立文件，下游零改动）。
  验证：夹具 `hook_all` ×5 全绿（`all-49-r*`）；JIT 开启下 49 档 **2/2 干净复跑**（`jiton-49-r2/r3`）；
  **真实样本** voicerecorder 端到端 `passed`（`e2e-1`，21 项检查零失败、`runtime_events_captured ✓`）。
- **第二个 P0 同日修复：SLIRP 强制代理此前一直失效**——修复前只有"读设备侧 `http_proxy` 的组件"
  能被抓到，**不读系统代理的直连流量一直全漏**（与"SLIRP 层强制走代理：应用绕不过去"的既有承诺不符）。
  修复两件套（缺一不可）：`-http-proxy` 地址改宿主侧回环 `127.0.0.1` + **冷启动前置 mitmproxy**。
  铁证：guest `nc` 直连 example.com 拿到经代理的真实 200；直连 dummy IP 收到 `Server: mitmproxy` 报错页。
  **连带影响：修复前批次（含 `tp-10151137`）的"零出网"结论不可信**（与 A1 时期"零读取"同性质），
  重跑批次时一并复验。
- **下一步不再是"接设备定位"，而是"端到端验收 + 铺开"**：① 去掉 `--skip-fixture-selftest` 重跑
  第三方批次；② keepass 等高死亡样本复跑；③ 设备侧全线解锁（B1 校准、A5-1 标定、F1、G1、B2 可开工）。
- **两人天然分工照旧**：人 A 守运行时轨（验收与设备铺开）；人 B 做离线增强与工程轨（不依赖设备，
  可立即并行）。
- 本轮核查的价值再次应验——**每次修复后要当场重标文档**，防止"人 A/人 B 照旧表开工重复劳动"。

---

## 1. 核查方法与总览表

**方法**：对每条问题直接查代码 / 查数据库 / 查证据目录，不信任文档状态列（沿用 `DEV_FIX_REPORT §6.11` 的教训）；
结论四档：**✅存在**（真待办）· **✅已修**（附证据）· **⚠️部分** · **📌已更新**（描述需修正）。
**2026-10-16 重标**：A1 与 SLIRP 由"存在"改判"已修"，依据见各行"核查方式"列。

| ID | 问题 | 核查方式 | 结论 |
| --- | --- | --- | --- |
| **A1** | 插桩打死应用（崩前事件发不出） | 修复后重核：`all-49-r*` 夹具 5/5、`jiton-49-r2/r3` JIT 开启 2/2、`e2e-1` 真实样本 passed、`_ensure_jit_off`/`-prop` 零残留；旧现场：01-keepass reads 2 行 + SIGSEGV vs 06-contacts 361 行 | **✅已修（2026-10-16，M031/M032）**——bridge 补丁 + 单 agent；**端到端批次复跑待做** |
| **SLIRP** | 强制代理此前一直失效（直连流量全漏） | `emulator.log` 修复前固定 "Proxy will be ignored!"；guest `nc` 直连实测（修复前 mitmproxy 零记录；修复后 200 + 报错页铁证） | **✅已修（2026-10-16，M032）**——127.0.0.1 + 冷启动前置代理；修复前批次出网数据需重采 |
| A2 | 判据盲区（armed ≠ 能捕到） | `device_run_thirdparty.py:350,355` 强制判据已接线；**真实样本 e2e-1 `runtime_events_captured ✓`（已设备验证）** | ✅已修·已设备验证 |
| A3 | 夹具阳性对照内建 | `fixture_selftest.py` + `batch_thirdparty.py` 前置门已接线；自检轮询修复已设备验证（jiton 2/2 均经自检）；批次 10151137 用了 `--skip`（result.json 留痕） | ✅已落地——**批次级"去 skip 复跑"待做** |
| A4 | 崩溃自愈 + 分段采集 | 全工具链 grep 无分段采集实现 | **✅存在（未做）**——A1 已修：从"必要缓解"降级为"鲁棒性增强"，可顺延 |
| B1 | 时间窗未校准 | `WINDOW_CALIBRATION.md` 不存在；`mobile_rules_inputs.py:29` 注释"声明值；未校准前不是通用阈值" | **✅存在（未做）**——A1 已修，设备侧可开工 |
| B2 | 无 ground truth / VScanBench | 全仓 grep 无 VScanBench；实验仅构造时序（15 场景 precision/recall=1.0 非真实误判率） | **✅存在（未做）**——A1 已解锁设备侧 |
| B3 | AI 幻觉率/一致性零量化 | `mobile/ai/` 无评测集目录；只有 `test_ai.py` 20 个校验单测（性质不同） | **✅存在（未做）** |
| C1 | 值证据只支持原值/同哈希 | ~~无 `derive.py`~~ → 已落地 `core/collector/derive.py` + `test_derive.py`（M035） | **✅已修（2026-10-16，M035）** |
| C2 | 静态引用 vs 动态观测差集 | ~~无 `coverage_gap.py`~~ → 已落地 `mobile/analyze/coverage_gap.py` + `test_coverage_gap.py`（M035） | **✅已修（2026-10-16，M035）** |
| E1 | 政策声明五分类 | `stage1_policy_extract.md` 现为三态 `met/not_met/unclear`（五分类未做） | **✅存在（未做）** |
| A5-1 | protectionLevel 40 条未标定 | **查数据库实锤**：`rules_mobile.db` 权限表 40 条、`protection_level_raw` 非空 **0 条** | **✅存在（未做）**——A1 已修，设备侧可开工 |
| A5-2 | API→权限映射新谓词 | 谓词集无新项（仍八谓词） | **✅存在（未做）** |
| F1 | 第三方 SDK 归因 | 无 classload 钩子（mobile/hooks 无相关文件） | **✅存在（未做）**——A1 已解锁 |
| G1 | UI 探索覆盖率不可度量 | `thirdparty_ui_flow.py` 仅 119 行浅探索（首屏），无覆盖率度量输出 | **✅存在（未做）**——A1 已解锁 |
| E2 | 数据类别本体表 | 无 subclass 关系实现 | **✅存在（未做）** |
| C3/DT | 差分原型 / 有限污点 | 全仓无实现（研究级） | ✅存在（未做，P2） |
| 工程-1 | CI 在 Gitee 不生效 | `.github/workflows/ci.yml` 存在且**文件自述**"Gitee 不执行 .github/workflows/"；`.git/hooks/` 为空 → pre-commit 未安装；全仓 **293 条** ruff 存量问题 | **✅存在（未生效）** |
| 工程-2 | >300 行文件（v4 重测为 **11 个**，不再是 6 个） | 2026-10-19 实测：`thirdparty_env.py` 647 / `device_run_thirdparty.py` 618 / `risk_score.py` 618 / `pcap_http.py` 540 / `device_run.py` 478 / `test_risk_score.py` 472 / `addon.py` 355 / `batch_thirdparty.py` 339 / `runner.py` 318 / `test_hooks_parity.py` 303 / `frida_host/run.py` 302 | **✅存在（且比 v3 恶化：`thirdparty_env` 459→647、`device_run_thirdparty` 472→618）**——拆分清单必须重列 |
| 工程-3 | hooks 共享化（中期） | `core/hooks_shared/` 不存在；短期守卫（`test_hooks_parity.py` 7 对 13 规则）已绿 | ⚠️部分（短期已完成） |
| 工程-4 | output/ 归档未做 | ~~400+ 子目录（4 万+文件）~~ → **已于 2026-10-19 清理**：删除 208 项历史跑批与 `latest-*.txt`，仅留今日产物+交付物 | **✅已完成（2026-10-19）** |
| 工程-5 | sqlite 只读 URI 编码 | M034 顺带核查已**更正**：全仓只读连接（correlate_mobile / evidence_bundle / policy_lint / gen_targets / rule_coverage_report / static_scan_thirdparty 等）均已带 `?mode=ro`，其余不带 URI 的是写库/测试/内存库 | **✅无需动作（M034 已核实，v3 的"⚠️部分"是滞后）** |
| 工程-6 | `conn_probe.py:57` 固定路径 | ~~仍为固定 `/data/local/tmp/vscan_conn_*`~~ → M034 已加 pid 后缀防并发冲突 | **✅已修（2026-10-16，M034）** |
| 工程-7 | `run_regressions --mobile` 开关 | ~~未加~~ → M034 已落地（语义：移动侧失败计入根回归失败） | **✅已修（2026-10-16，M034）** |
| 工程-8 | JIT-off 假修复残留风险 | 全库 grep `_ensure_jit_off` 代码 **0 残留**（只剩文档留痕）；启动参数无 `-prop`（均为清退后实测） | **✅已清退（2026-10-16）** |
| 人工-1 | **AI key 轮换** | `config.local.json` 真实 key 待本人吊销轮换 + 历史提交核查（`git log --all -- mobile/ai/config.local.json`） | **✅存在（用户本人执行）** |
| 人工-2 | H4：Frida 上游 issue 核对 | 根因已落到 frida-java-bridge 上游限制（"多脚本替换不支持"；x64/API37 未覆盖区），以单 agent 规避；对应 frida#3700/#3745 | 📌已更新——无需再查 release note；换 Frida 版本时复核这两个 issue |

---

## 2. 移动端优化清单（核查后，按优先级）

### 2.1 P0 —— 两项均已解除（2026-10-16）

**A1 · `hook_privacy` 插桩打死应用 —— ✅ 已修（bridge 补丁 + 单 agent）**

- 根因（两层实因 + 一层假因）：
  1. ~~JIT×ArtMethod 替换竞态~~ —— **假因（M032 双向证伪）**：`setprop dalvik.vm.usejit false` +
     框架重启**关不掉** JIT（夹具进程仍有 `Jit thread pool` 与 `dalvik-jit-code-cache`），`-prop` 被
     emulator 37.1.11 拒绝（只收 `qemu.*`）。此前"关 JIT 后能跑"实为巧合——**修复全程是 JIT 开着完成的**。
  2. **JNI transition frame reference**（Android 14+）：CheckJNI 因 Frida trampoline 帧拒绝校验型
     JNI 调用 → **bridge 补丁** `patches/02-class-factory-transition-ref.patch`（`build.mjs` 构建前
     幂等重放，`npm install` 后不丢）。
  3. **多脚本替换不被 bridge 支持**：双脚本 ~50% 崩 vs 单脚本 5/5 → **单 agent 合并**（`hook_all`：
     privacy+consent+egress_tp+ssl_pinning_tp 同一 JS 上下文；挂载清单 5→1；`split_events.py` 分流）。
- 验收证据：夹具 `hook_all` ×5 全绿；JIT 开启下 49 档 2/2（`jiton-49-r2/r3`：各 2 条 PRIVACY_READ、
  `alive=true`、fatal 空）；真实样本 voicerecorder `e2e-1` `passed=true`、21 项零失败。
- **剩余动作（是"验收"，不是"修复"）**：见 §6 行动项 1（去 skip 重跑批次 + 高死亡样本复跑 +
  修复前批次出网数据重采）。
- 器材保留：`a1_tier_scan.py`（三态统计）改为**回归排查工具**留存，不再阻塞主线。

**SLIRP 强制代理失效 —— ✅ 已修（本晚新发现，同日修复）**

- 现象：启动日志固定出现 `Could not connect to proxy at 10.0.2.2:8888: timed out` +
  `Proxy will be ignored!` → 整条 SLIRP 重定向被关闭。
- 根因：emulator 37.x 从**宿主进程**对 `-http-proxy` 地址做一次性可达性探测；guest 别名
  `10.0.2.2` 在宿主上不可路由 → 必超时。实测（`nc` 裸 socket，绕开应用层代理）：**不读系统代理的
  直连流量此前一直全漏**。
- 修复两件套：① `-http-proxy` 改宿主侧回环 `127.0.0.1`（`transparent.PROXY_ARG_HOST`；设备侧
  `settings put global http_proxy` 仍为 `10.0.2.2`，两个地址空间语义不变）；② **冷启动前置
  mitmproxy**（`runner._start_early_mitm` + `device_run_thirdparty --reuse-mitm`）。
- 铁证：`nc` 直连 example.com 拿到经代理真实 200；直连 dummy IP 收到 `Server: mitmproxy` 报错页。
- 复现/回退检查：换 emulator 版本后先看启动日志有无 "Proxy will be ignored!"。

### 2.2 P1 —— 可信度与核心功能

| ID | 做什么 | 验收判据 | 依赖 |
| --- | --- | --- | --- |
| A2/A3 批次验收 | **去掉 `--skip-fixture-selftest` 重跑一批**（批次 10151137 是跳过态）；改坏钩子验证批前门拒绝出批 | 自检真出 PRIVACY_READ；门拒绝路径实测 | ✅已解锁（A1 已修） |
| B1 窗口校准 | 移动夹具采集"读取→外发"间隔分布 → `WINDOW_CALIBRATION.md`；据此决定 `DEFAULT_WINDOW_MS` | 分布有分位数与样本量；报告去掉"未校准"标注 | ✅已解锁 |
| A5-1 protectionLevel | 40 条权限设备标定（链路已通，步骤在 `rules/calibration/README.md`） | 库中 `protection_level_raw` 非空 = 40/40（现为 **0**） | ✅已解锁 |
| A5-2 API→权限谓词 | 新增"读到 X 但保护权限未申请/未授予"谓词（侧信道最简形式） | 反例不产出；正例（夹具）稳定产出 | A5-1 数据 |
| B2 VScanBench | ground truth 矩阵（延迟外发/批处理/只读不发/编码/加密/并发/重启/断网），出正确率/歧义率/无法归因率 | 每 case 有 ground truth、自动出数、并入实验文档 | ✅已解锁 |
| B3 AI 评测集 | fixture ×6（含"故意缺证据/故意错法条"），量化幻觉率与跨 3 次一致性 | 离线可跑、不过则失败；算法参考 SelfCheckGPT/语义熵 | 无（纯离线） |
| F1 类加载归因 | `hook_classload.js` + `origin` 字段 + 静态类差集 | 已知 SDK 的自有 APK 稳定复现 `third_party` 前缀；未知一律 `unknown` | ✅已解锁 |
| G1 UI 探索器 | `flow.explore` 轻量增强（~200 行）：触达 Activity 集合 / 未触发敏感 API 清单 | 输出三项度量，可进报告 | ✅已解锁 |
| A4 崩溃自愈（可顺延） | 窗口切 N 段（30s/段）重启重挂、数据跨段累加、死亡记 `app-death.json`（含段号） | keepass 上崩 1–2 次仍保留崩前真实事件 | A1 已修 → **降级为鲁棒性增强**，视排期做 |

### 2.3 P2–P3 —— 完善度与工程

- **E2 本体表**（"IMEI ⊂ 设备标识符"可复核）、**C3 差分原型**（仅限自有夹具）、**DT 有限污点**（研究级）——纯离线。
- **工程-1 CI**：两条路选一——① 加 GitHub 远端推一份（Actions 直接可用）；② 搬进 Gitee Go。
  pre-commit 建议**先摘掉 `ruff-format` 只留 `ruff check`**（293 条存量问题，防止开钩子即大 diff）。
- **工程-2 拆分**：~~5 个~~ → **11 个 >300 行文件**（清单见 §1 该行，风险评分与 pcap 链路是新增的大头），
  建议按"先拆 `pcap_http.py` / `risk_score.py` 这两个新增大文件、再拆 `thirdparty_env.py`"的顺序。
- ~~**工程-5 sqlite URI**~~ ✅ M034 已核实无需动作；~~**工程-6**~~ ✅ M034 已修；
  ~~**工程-7** `--mobile`~~ ✅ M034 已加。
- ~~**工程-4 归档**~~ ✅ 2026-10-19 已完成（`output/` 清空，208 项历史跑批删除）。
- **E1 政策五分类** 仍是"P0 价值最高的离线项"（C1/C2 已于 M035 完成，不必再排）。

### 2.4 本轮核查确认「已修复」的清单（不要再动，防止重复劳动）

> 出处：`mobile/DEV_FIX_REPORT.md` 批次 1–5 + §5.8/§5.9（2026-10-16）+ 独立复验 `VERIFY_M031_M032_20261016.md`。
> 带"待设备"的表示离线已完成、设备侧未验证。

- **A1 修复本体** ✅：bridge 补丁（`02-class-factory-transition-ref.patch` + `build.mjs` 幂等）；
  单 agent（`hook_all` + `split_events.py` 6 例）；hooks 导出化 + parity 白名单 +3 条
- **JIT-off 清退** ✅：`runner._ensure_jit_off` 整体删除（含 stop/start + CA 重装）、`-prop` 移除
- **SLIRP 强制代理修复**（两件套）+ 四项配套加固 ✅：`start_mitm` 端口预检/监听校验、
  `emulator.log` 落盘、`app_death_reason` 抗 adb 超时、`fixture_selftest` 轮询 armed+collecting
- **A2 判据** ✅ 已设备验证（e2e-1）；**A3 自检门** ✅ 已落地（批次级复跑待做）
- **A6 死钩子**（`libcore.io.Posix`）✅ 已删；**A7 插件/钩子顺序** ✅ 已修（addon 源缺失诊断 + 轮询容忍）
- **夹具 dialog**（`isShowing` 判断）✅ 已修（`MainActivity.kt:146`）
- **钩子一致性守卫**（`test_hooks_parity.py` 7 对 13 规则）✅ 已绿并入围回归
- **winpath `extended_rglob`** ✅；**sdk_paths**（19 处 → 一处）✅；**6 份 `load_jsonl` 统一** ✅
- **关联引擎 O(n²)** ✅；**字体表** ✅；**uid_sampler** ✅（12 例离线用例）；**CORS/`digest` 校验/prompt 注入围栏** ✅
- **拆分 11 → 6** ✅（拆掉 5 个低风险文件，测试数守恒）
- **回归基线（修复后重跑）**：`run_mobile_checks.py` **23 项全绿**（2026-10-16 15:07）；
  根回归 **13 组全绿**（2026-10-16 14:21）——均晚于全部修复文件 mtime，覆盖到位

### 2.5 v3 未覆盖的新主线（M036–M039 + 风险量化，2026-10-18）

> 这五项不在 v2/v3 的核查表里，是 10-16 之后新增的。列出来是为了让排期**别再按 v3 老清单**开。

**M036 ·「明文读不到」的真根因**（原以为要换方案，其实是钩子从没跑通）：三层实测——
① Frida 17 删掉 `Module.findExportByName`，旧代码包在 try/catch 里 → 永久静默 `SYMBOL_ABSENT`；
② Android linker 默认 `RTLD_LOCAL`，`getGlobalExportByName` 查不到 dlopen 进来的库；
③ 库懒加载，attach 时 `libssl.so` 往往还没加载，只扫一次就**永久**漏。
顺带**证伪**「模拟器内核不支持 iptables、QUIC 只能真机」（实测 `-I OUTPUT -p udp --dport 443 -j DROP` 可用）。
边界：仓库内无 Flutter 样本，NVISO 思路未实测。

**M037 · 明文范围扩围**：新增 `hook_native_crypto.js`（EVP/AES 加密入参、解密出参）与
`hook_tls_meta.js`（SNI + 主动挂 `SSL_CTX_set_keylog_callback`）。关键坑：EVP 必须过滤 TLS
记录层（BoringSSL `tls_seal_record` 内部也走 EVP），否则每条 TLS 流量多记一条密文事件。

**M038 · 完整 HTTP 报文**：hook 只能拿到 `SSL_read/SSL_write` **分片**，自己拼要重写
HPACK/chunked/gzip。改为设备端 `tcpdump` + keylog + `tshark` 重组（`pcap_capture.py` /
`pcap_http.py`，抓包须在 `am start` **之前**起）。两个已踩的坑：tcpdump 只能 `su 0` 用
（shell 域探测会得到假阴性）、`-G N -W 1` 会把文件截成 0 字节。

**M039 · Flutter / 剥符号 BoringSSL**：不是「看不了明文」，是「没有符号可 hook」
（`libflutter.so` 静态链接并剥表，连 `SSL_read` 字符串都不存在）。改用解剖学常量锚点
（`*out_alert = 0x50` → `c6 02 50`）回扫序言，不依赖版本相关的整段签名。

**风险量化 v1.0→v1.3**（`mobile/analyze/risk_score.py` + `calibrate_risk_bands.py`）：
四维乘积 + 重复衰减 + 正交置信度，含 necessity 维度与单调性保证；模型说明见
`mobile/RISK_SCORE_MODEL.md`。**v3 完全没有这一项**——论文/答辩的「量化」章节以它为准，
不要再用旧文档「仅有计数」的描述。

**对排期的影响**：人 B 的 W1–W2（C1+C2）已空出，建议前移到 E1 五分类与 B3 AI 评测集；
人 A 的 B1/B2/A5-1 仍未动，且 M036–M039 改的都是采集核心，需补回归覆盖。

---

## 3. 两人分工方案（移动端 only，建议节奏 8 周）

### 3.1 原则

1. **A1 已于 2026-10-16 解除**（修复 + 验收达成：夹具 5/5、真实样本 passed）；当前硬前置变为
   "**A1 端到端批次验收**"（去 skip 重跑，W1 完成），之后设备侧全线解锁。
2. **人 B 的全部任务不依赖设备、不依赖 A1**（纯离线），两人即刻并行、零等待。
3. **`core/` 是唯一耦合点**（C1 会动 `core/collector/`）：接口先行 + 合并后**两条回归都跑**。
4. 验收判据永远是 `verification.json` / `app-death.json`，不是"代码看起来对"。

### 3.2 人 A · 运行时轨（移动 AVD 专用）

| 周 | 任务 | 验收判据 |
| --- | --- | --- |
| W1–2 | **A1 端到端验收**：去掉 `--skip-fixture-selftest` 重跑第三方批次（含 keepass 等高死亡样本复跑）；SLIRP 修复前批次的出网结论加覆盖边界标注或重采 | 批次自检真出 PRIVACY_READ；样本"真实事件 / 如实 app-death"二选一有记录；出网数据经代理路径 |
| W2–3 | **A2/A3 批次级验收**：改坏钩子验证批前门拒绝出批 | 门拒绝路径实测 |
| W3–5 | **B1 窗口校准** + **A5-1 protectionLevel 标定**（40 条；A1 已解锁，可提前启动） | `WINDOW_CALIBRATION.md` 成文；DB 标定 40/40 |
| W5–6 | **F1 类加载归因** + **A4**（可顺延：降为鲁棒性增强） | `third_party` 前缀稳定复现 |
| W6–8 | **G1 UI 探索器** + **B2 设备侧 matrix** | 三项度量输出；矩阵出数字 |

### 3.3 人 B · 离线增强 + 工程轨（纯离线，可立即开工）

> **v4 注**：下表 W1–W2 的 **C1/C2 已于 2026-10-16 完成（M035）**，W4–W5 的工程小项中
> 工程-5/6/7 也已闭环（M034），故实际进度已前移约两周——请按 §6 第 2 条（E1 → B3）接续，
> 不要照表从 W1 重做。下表保留为原始排期与验收判据来源。

| 周 | 任务 | 验收判据 |
| --- | --- | --- |
| W1–2 | **C1 派生值匹配**（最高价值）：`core/collector/derive.py`（md5/sha1/sha256/base64/urlencode/hex/gzip+b64 候选）+ `tagging_mobile.py` + `value_matches` 扩展 | 构造"读到 IMEI→发 sha1/base64"命中；**反例**（别的 15 位数字）不产出 |
| W1–2 | **C2 覆盖缺口**：静态引用 vs 动态观测差集 → bundle gaps + 报告渲染（只做 gap 不做结论） | 夹具 APK 差集非空且稳定；回归覆盖 |
| W2–3 | **E1 政策五分类**（clear/vague/omitted/incorrect/ambiguous 替换三态）+ `validate.py` 校验 + 报告章节 | 5 类各有路径；越界枚举被拦 |
| W3–4 | **B3 AI 评测集**（6 fixture）量化幻觉率与一致性；算法参考 SelfCheckGPT / 语义熵（Nature 2024） | 离线可跑、不过则失败，并入回归 |
| W3–4 | **E2 本体表** + **A5-2 谓词**（离线部分先行，数据由人 A W3–5 补） | 本体关系可复核；谓词正反例 |
| W4–5 | **工程整改**：CI 落地（二选一）+ pre-commit（先摘 ruff-format）+ sqlite 4 处 + conn_probe + `--mobile` 语义 | CI 每次 push 两条回归全跑；小项各自回归 |
| W5–6 | **I1 VScanBench 离线框架**（矩阵用例与 ground truth 声明；设备侧交人 A） | 框架可跑、每 case 声明输出 |
| W6–8 | **工程-4 归档**（路径映射后动）+ 协助 B2 + 材料整理（论文/答辩） | 指针链更新；文档同步 |

### 3.4 里程碑

```
W1─W2  人A: A1 端到端验收（去 skip 复跑批次 + keepass）┃ 人B: C1 + C2
W3─W4  人A: A2/A3 批次验收 + B1 校准（提前）        ┃ 人B: E1 + B3 评测集 + E2/A5-2
W5─W6  人A: A5-1 标定 + F1（A4 可顺延）              ┃ 人B: 工程整改(CI/小项) + VScanBench 框架
W7─W8  人A: G1 + B2 设备侧                          ┃ 人B: 归档 + 协助 B2 + 材料
```

每 W 结束：两人各跑 `run_mobile_checks.py`（涉及 `core/` 改动时加跑 `run_regressions.py`），
在 `mobile/DECISIONS.md` 接续 **M033+** 编号记录。

### 3.5 协作规约

1. 改动前读对应 `DECISIONS.md`；改动后跑回归 + DECISIONS 追加编号（只增不改）。
2. `core/` 改动**接口先行**（先提交签名 + 用例，另一方确认后实现）；合并后两条回归都跑。
3. 验收铁律（`§8.6`）：不许为让判据变绿弱化判据；"已修"必须有设备证据（先例：A1 的达成 =
   夹具 5/5 + 真实样本 e2e-1 + 回归全绿）；不许引入外部项目代码/数据；真实 key 不进新文件；失败运行保留。
4. **文档状态列不可信**（`§6.11` 教训）：一切以代码与 `verification.json` 为准；**改完当场重标相关文档**
   （本次 v3 重标就是执行这条）。

---

## 4. 可借鉴论文与开源项目（移动端）

> 完整调研（8 簇约 30 篇）见 `mobile/RESEARCH_OUTLOOK.md` §3；下表为精选 + 2026-10-15 新增，挂到具体任务。

| 工作 | 一句话 | 借鉴点 | 用于 | 谁 |
| --- | --- | --- | --- | --- |
| **Purifire**（arXiv:2509.16340, 2025） | eBPF 反检测：2,340 个"Frida 下崩溃"应用救回 662 个 | ① "Frida 致崩"是被正式研究的问题→A1 报告叙述的学术支撑；② 若未来遇 native 层反插桩，eBPF 干预思路 | A1（已修，转论文叙述支撑） | A |
| **SelfCheckGPT** / **语义熵（Nature 2024）** | 多次独立采样测一致性 / 语义层不确定性 | 幻觉率与跨运行一致性的具体算法（n-gram/BERTScore/NLI 三档） | B3 | B |
| **GDPR-Bench-Android**（arXiv:2511.00619, 2025） | 合规检测 benchmark：11 种方法横评，"无单一范式全优" | 评测集设计（多粒度、Accuracy@k）；防止对 AI 过度声称 | B3/B2 | A+B |
| **PoliCheck**（USENIX'20） | policy↔flow 一致性 5 分类 Clear/Vague/Omitted/Incorrect/Ambiguous | **E1 的直接出处**；"不考虑实体会 38.4% 误判"支撑第三方归因必要性 | E1 | B |
| **PolicyLint**（USENIX'19） / **Polisis**（USENIX'18） | 收集陈述三元组+本体 / 政策 NLP 分类 | E2 本体表出处；政策结构化抽取基线 | E2 | B |
| **Agrigento**（NDSS'17） / **Reardon et al.**（USENIX'19） / **LeakScope**（S&P'19） | 黑盒差分 / 原文+MD5/SHA 候选+解 gzip/base64 / 后向切片 | **C1 派生值匹配的直接出处**；C3 差分原型的方法源头 | C1/C3 | B |
| **"Your Signal, Their Data"**（PoPETS'25） | 类名二级域名 ≠ 宿主 ⇒ 跨库调用 + `FindClass` 插桩 | **F1 类加载归因的直接出处** | F1 | A |
| **PScout**（CCS'12） / **Axplorer**（NDSS'16） | API→权限映射 / 过度权限 | ① "实测抽取不编造"立场（=A5-1 标定）；② A5-2 谓词判据 | A5-1/A5-2 | A+B |
| **DroidBot** / **Fastbot** / **Themis**（FSE'21） | 偏置随机探索 / 工业级 / 真实 bug 基准 | G1"覆盖率必须可测"的共识；先做 ~200 行轻量版 | G1 | A |
| **TSE 2021** / **Reprodroid** / **DroidBench** | 静态工具真实 App 失效 / 统一基准 | "不自研通用污点引擎"依据；VScanBench 的 ground truth 方法学 | B2 | A+B |
| **中文**：HPDROID（西安交大）/ 软件学报 2024 政策合规检测 / 《安卓应用隐私合规检测方法研究》/ SELMAnalyzer（信工所+信通院） | 三类违规分类 / 31 类标签 94% 精度 / BiLSTM-CRF+Frida / 执行逻辑模型 | 答辩与国内法规语境近；政策标签体系可对照 `policy_requirements` | E1/报告定位 | B |

> 引用注意：以上信息来自 2026-10-15 网络检索，**入论文前必须逐篇核对原文**；无把握不作引用。

---

## 5. 暂缓区：车载线（本轮不投入）

以下为车载线已识别的优化点，**本轮不开发**；恢复车载开发时从此清单接续（详细出处见 v1 及
`vehicle/*/DECISIONS.md`、`EXPERIMENTS.md`）：

| # | 项 | 一句话状态 |
| --- | --- | --- |
| V-1 | 归因歧义保护 ±500ms 窄带 | `wrong` 风险区已用实验定位，未修 |
| V-2/V-5 | 真实迟到/间隔分布、30s 窗口通用性 | 需长时间真机采集，未做 |
| V-4 | 内存 Hook（JCE/native TLS）设备端实测 | 代码 + 夹具按钮已备，待跑 |
| V-8 | 看板事件级时间轴 / 真车浏览器验证 | 未做 |
| V-9 | `frontend/` 零测试零 lint | 未做（属车载工作台前端） |
| 车载论文 | PriDrive（AAOS 隐私分析）、Automatic Transmission（IMC'26） | 已调研归档，恢复车载线时启用 |

---

## 6. 立即行动项（2026-10-19 起）

> v3 的本节是 10-16 那周的清单，其中第 2 条（C1+C2）已完成，其余按现状重排。
> **`output/` 已于 2026-10-19 清空**：本节不再给出 `output/...` 证据路径，需要证据一律重跑。

1. **人 A · A1 端到端验收仍未闭环**：去掉 `--skip-fixture-selftest` 重跑第三方批次
   （含 keepass 等高死亡样本）；对 SLIRP 修复前批次（如 `D:/vscanner-tp/tp-10151137`）的
   "零出网"结论加覆盖边界标注或重采。判据：批次自检真出 PRIVACY_READ。
2. **人 B · 前置已清空 → 前移到 E1 政策五分类**（clear/vague/omitted/incorrect/ambiguous），
   再做 B3 AI 评测集（6 fixture，量化幻觉率与跨 3 次一致性）。
3. **用户本人 · 安全项（v3 遗留，仍未确认完成）**：吊销轮换 `mobile/ai/config.local.json`
   里的真实 key，并核查历史提交（`git log --all -- mobile/ai/config.local.json`）。
4. **两人 · 拆分**：11 个 >300 行文件，优先 `pcap_http.py`(540)、`risk_score.py`(618)、
   `thirdparty_env.py`(647) 三个新增/恶化的大文件（清单见 §1 工程-2 行）。
5. **两人 · 集中跑测试集前的闸门**：先跑 `run_regressions.py --mobile`（13 组 + 移动 23 项）
   全绿再开跑；本轮 `output/` 已空，首轮会产生新时间戳目录，`latest-*.txt` 随之重建。
6. 两人：定 CI 路线（GitHub 远端 or Gitee Go）与 pre-commit 是否摘 `ruff-format`（建议摘）。

---

## 7. 出处索引

- **A1 修复证据**：`mobile/DECISIONS.md` M031/M032；`mobile/DEV_FIX_REPORT.md` §5.8/§5.9；
  `D:/vscanner-tp/a1-scan/`（`all-49-r1..r5` 夹具 5/5、`jiton-49-r2/r3` JIT 开启 2/2、`e2e-1` 真实样本）
- **SLIRP 修复证据**：`D:/vscanner-tp/proxy-probe/mitm.log`（nc 实测 200 / 报错页）；
  `D:/vscanner-tp/pipeline/dc89d5a6f6b4/`（`emulator-start.log` 命令行、`emulator.log` 无警告、
  `kill-early-mitm.log` 回收）
- **独立复验**：`VERIFY_M031_M032_20261016.md`（代码清退核查 + 原始证据核对 + 回归重跑）
- **回归**：~~`output/mobile-regression-20261016-150714/`、`output/regression-20261016-142103/`~~
  —— 已于 2026-10-19 随 `output/` 清理删除，**需重跑**：
  `run_regressions.py --mobile`（13 组 + 移动 23 项）
- **旧核查证据**：`output/tp-10151137/`（符号链接 → `D:/vscanner-tp/tp-10151137`，**未删**；
  含 01-keepass `app-death.json` + reads 2 行、06-contacts reads 361 行、
  `_fixture-selftest/result.json` 跳过留痕）；`rules_mobile.db`（40 条权限 / 0 条标定）
- **M034–M039 证据**：`mobile/DECISIONS.md` 对应各节（路径、实测数字与边界均在其中）
- 状态权威源：`mobile/DEV_FIX_REPORT.md`、`mobile/DECISIONS.md`（M029–M039）
- 缺口与建议：`mobile/RESEARCH_OUTLOOK.md`（§2/§4/§8）、`mobile/EVAL_CROSSCHECK.md`
- 外部调研时间：2026-10-15；**状态重标：2026-10-16（v3）→ 2026-10-19（v4）**

---

*本文件为规划文档，不改代码；执行中与各模块 DECISIONS.md 冲突时，以 DECISIONS 的实测记录为准。*
