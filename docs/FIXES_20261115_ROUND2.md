# 第二轮缺陷修复：N3 / N5 / N6（2026-11-15）

承接 [AUTOMOTIVE_APK_PILOT_20261115.md](AUTOMOTIVE_APK_PILOT_20261115.md) §4 里未修的三项。
本文只写改了什么、怎么验证的、还剩什么，不复述试点过程。

---

## 0. 结论

| ID | 原问题 | 处置 | 验证 |
| --- | --- | --- | --- |
| N5 | pcap 报文没有应用归因，系统/OwnTracks 流量被算成被测应用 | **已修**：先修 uid（多用户偏移），再用 conn_probe 的 socket 表按端口归属；判据只认归属到被测包的报文 | Blue 7 条 → **0 条归属**（判红并写明原因）；Proton 28 条 → **4 条归属**（`target_ports=7`） |
| N6 | 回调式定位只记录"订阅"，不记录"取值"，MOB-R006 不触发 | **已修**：规则库新增 4 个 `Location` 取值 API，重建 targets 与 bundle | Blue 读取 4 → **52** 条；`getSpeed/getLatitude/getLongitude/getAccuracy` 全 `obtained`；结论出现 **MOB-R006 observed** |
| N3 | `--spawn-hook` 在本环境 frida spawn 超时，启动期读取无覆盖 | **未修（环境限制）**：回退链与原因记录已完整；新增 `startup_calls_covered` 让每次 attach 跑显式提示 | 判据按预期判 1，note 指明"需 `--spawn-hook` 复跑" |

---

## 1. N5：报文归属

### 1.1 根因不是 pcap，而是 uid

pcap 在链路层抓包，本来就没有 uid；原设计指望 `conn_probe` 提供"哪个端口属于哪个 uid"。
但 `conn_probe` 的落盘一直是 **0 行**——Proton 有 37 条连接、`conns.summary.json` 仍写
`endpoints: 0`。

对照 `/proc/<pid>/status` 发现：

```
Uid:  1010276  1010276  1010276  1010276     # user 10 的内核 uid
pm list packages --user 10 -U → uid:10276    # appId，不含用户维度
```

`app_uid()` 原来固定用 `--user 0` / `/data/user/0/...`，拿到的是 appId（10276），
而去和 socket 表里的 1010276 比——永远不相等。多用户设备上内核 uid 是
`UserHandle.getUid(user, appId) = user*100000 + appId`。

**改动**（`mobile/tools/thirdparty_env_hook.py`）：

- 新增 `current_user_id()`（`am get-current-user`）；
- `app_uid()` 按当前用户查 `pm list packages --user <user> -U`、`stat /data/user/<user>/<pkg>`；
- 新增 `_kernel_uid()`：`user > 0 and uid < 100000` 时补 `user*100000`；已是内核 uid 的原样返回；
- `thirdparty_env.py` 导出 `current_user_id`。

**验证**：

- `env.app_uid('com.nic.roam')` → `1010276`，与 `/proc/<pid>/status` 一致；
- 6 秒试采 OwnTracks：`conn-test.jsonl` **15 行**，含 `uid=1010214`（OwnTracks 的内核 uid）；
- Proton 窗口：`conns.jsonl` **7 行**、`endpoints 8`，全部 `uid=1010280`。

### 1.2 归属规则

新增 `mobile/analyze/http_attribution.py`：

- 目标 uid 的 `local_port` 集合来自 `conns.jsonl`；
- 请求看 `src` 端口、响应看 `dst` 端口（本地侧）；
- 命中 → `attributed=true, attribution="conn_probe_uid"`；否则 `unattributed`；
- conns 为空 → `basis=None`，调用方不得据此写"没有外发"。

`device_run_thirdparty_run4.py` 在解码后调用它，把结果写回 `http_messages.jsonl`，
并写进 `http-stats.json` 的 `http_attribution`：

```json
{"total": 28, "attributed": 4, "target_ports": 7, "basis": "conn_probe_uid"}   // Proton
{"total": 7,  "attributed": 0, "target_ports": 0, "basis": null}              // Blue
```

判据 `http_messages_extracted` 从"解出几条"改为"**归属被测包几条**"：

- 有归属 → 通过，note 写 `归属被测包 M/N 条`；
- 解出报文但 0 条归属 → 判红，note 追加 `⚠ 全部未归属：这些报文来自系统/其他应用，不得写成被测应用的外发`；
- 没有 conns → note 写"未做归属"，不假装已归属。

### 1.3 实测

| 样本 | 报文 | 归属 | target_ports | 判据 |
| --- | ---: | ---: | ---: | --- |
| Blue Square（无网络） | 7 | **0** | 0 | optional 失败，note 写明全部未归属 |
| Proton Mail（走代理） | 28 | **4** | 7 | 通过，note `归属被测包 4/28 条` |

Proton 的 4 条可归属报文来自它自己到 mitmproxy 的 CONNECT/请求；其余 24 条是系统
`connectivitycheck`、Google 等。**这正是修复前会被误算的部分。**

---

## 2. N6：定位取值点

### 2.1 为什么“订阅”不够

`requestLocationUpdates` 只是注册监听，值由系统回调投递。原规则库只有
`getLastKnownLocation`（read）与 `requestLocationUpdates`（observe），所以 Blue 的
4 条读取全是 `observe/empty`，MOB-R006（`successful_sensitive_api_read`）永远不触发。

### 2.2 改动链

1. `mobile/rules/seed/api_targets.json` 新增 4 条（`api_role=read`、
   `data_type_key=precise_location`、`observation.kind=direct`）：
   `Location.getLatitude()`、`getLongitude()`、`getSpeed()`、`getAccuracy()`。
2. `python mobile/rules/extract_android_apis.py` → `api_facts.jsonl` 62 条（原 58）。
3. `python mobile/rules/build_mobile_rules.py` → 新库。与旧库逐行对比：
   - `dangerous_apis` 58 → 62（新增 4 条 Location getter）；
   - 其余表条数不变；`risk_rules` 的行为**只有 `source_refs_json` 里的 jar 路径变化**
     （旧库记的是笔误路径 `D:\Anroid\...`，新库是真实 SDK 路径，`jar_sha256` 相同）。
   - 旧库备份为 `mobile/rules/rules_mobile.db.bak-20261115`。
4. `python mobile/hooks/gen_targets.py` → `targets.generated.js` 62 条 API。
5. bundle 重建：`node build.mjs hook_all` **失败**——`frida-compile` 依赖的
   `frida_binding.node` 本机没有预编译产物（`Could not locate the bindings file`）。
   改用 `mobile/hooks/patch_bundle_targets.py`：只替换 bundle 里 `var WATCH` 数组，
   并**重算 `📦` 包头里每个模块的 UTF-8 字节数**（不重算会在运行期报
   `Frida bundle 长度校验失败`，本轮踩过一次）。脚本写完会调用
   `bundle_config.configure()` 自检，过不了就不写盘。

### 2.3 实测（Blue Square，75 s 窗口）

| 指标 | 修复前 | 修复后 |
| --- | ---: | ---: |
| `PRIVACY_READ` | 4（全 observe/empty） | **52**（含 4 类 getter，`obtained=true`） |
| `runtime_events_captured` | 4 条观测 | **124 条观测** |
| 结论 | 2 条（全 candidate） | **4 条**：`MOB-R006 sensitive_read observed`、`MOB-O006 over_collection candidate`、`MOB-P003/P004 candidate` |

取值事件样例：

```
android.location.Location.getSpeed()F     obtained True ['precise_location']
android.location.Location.getLatitude()D   obtained True ['precise_location']
android.location.Location.getAccuracy()F   obtained True ['precise_location']
```

### 2.4 代价

事件量上去了（Blue 从 25 行到 124 行观测），因为界面每帧读速度都会打点。
目前没有做聚合/去重；长窗口（>10 分钟）或高频传感器应用需要再评估落盘体积。

---

## 3. N3：交接时的 spawn 超时

后续复验已定位到 Android 用户选择。Frida 17.18.0 显式使用用户 10 后可返回 Roam 的目标 PID，
工具装载脚本后成功恢复进程。Roam 全量脚本在恢复后的 RenderThread 崩溃仍可复现，回退 attach 会保留
首段证据并标记启动期覆盖未通过。复验记录见 [开发日志](DEVELOPMENT_LOG.md) 顶部。

`--spawn-hook` 仍然是：

```
frida.TimedOutError: unexpectedly timed out while waiting for app to launch
```

回退链本身是完整的：停 spawn 钩子 → `am start` 冷启动 → attach 重挂，
并把原因写进 `app_started` 的 note。本轮补的是**可见性**：
新增 optional 判据 `startup_calls_covered`，attach 模式必判 1 并写明
"启动期调用可能早于挂钩；需 `--spawn-hook` 复跑"。这样报告读者不会把
"0 条读取"读成"应用没读"。

可行的下一步（未做）：换 frida 版本/注入方式（gadget、zygote），
或确认 `device.spawn` 的超时是否可配。**代码层没有更稳的替代**，
所以本轮不把它伪装成已修。

---

## 4. 修复过程中新暴露的问题

| 问题 | 现象 | 处置 |
| --- | --- | --- |
| bundle 长度头 | 手改 WATCH 后运行期 `ValueError: Frida bundle 长度校验失败` | 补丁脚本重算每模块 UTF-8 字节数，并调用 `bundle_config.configure()` 自检 |
| `helpers.py` 缺 `import sys` | `load_action_log` 遇到坏行时 `NameError` | 已补；`test_device_tools` 覆盖 |
| `pcap_tshark.py` 缺 `import json` | 有 TLS 事件的窗口在解码阶段整轮退出 | 解码阶段已加异常兜底（降级 `stats.ok=false`）；文件本身已含导入 |
| bundle 注入后长度头过期 | 手改 WATCH 且把 CRLF 归一成 LF，运行期 `ValueError: Frida bundle 长度校验失败` | 补丁脚本重算每个模块 UTF-8 字节数，并调用 `bundle_config.configure()` 自检 |
| `MOB-E006` 断言过时 | 库新增 direct 定位 getter，`apis_in_library` 0 → 4 | 更新断言并加 `apis_referenced == 0`；判据本意不变 |
| 新测试未登记 | 测试清单守卫判 `unregistered=1` | 加进 analyze 组执行 |

---

## 5. 回归

| 项 | 结果 |
| --- | --- |
| `mobile/rules/test_rules.py` | 13/13 |
| `mobile/hooks/test_dispatch.mjs` | 40/40 |
| `mobile/hooks/test_privacy_implementation.mjs` | 全过（含 bounded rescan） |
| `mobile/analyze/test_http_attribution.py` | 5/5 |
| `mobile/tools/test_device_tools.py` | 14/14 |
| 全量移动回归 | 见 §5.1 |

### 5.1 全量移动回归

**63/63 通过**：`output/mobile-regression-20261115-181722-zun98fli/`
（日志 `output/auto-apks-20261115/mobile-regression-fixes2.log`）。

第一次跑失败 2 项，都不是功能回归，但都值得记：

| 失败项 | 原因 | 处置 |
| --- | --- | --- |
| `test_inventory` | 新增的 `mobile/analyze/test_http_attribution.py` 没被任何清单引用 | 加进 `run_mobile_checks.py` 的 analyze 组（不是塞白名单），实际执行 |
| `static_supplement` | 断言 `MOB-E006.apis_in_library == 0` 在库新增 4 个 direct 定位 getter 后过时 | 改了那条断言：`> 0`，并加 `apis_referenced == 0`（合成 facts 没引用 getter 时仍不得产出外发结论）。**判据本意（spec 映射不得当外发证据）没动** |

---

## 6. 改动文件

| 文件 | 类型 | 说明 |
| --- | --- | --- |
| `mobile/tools/thirdparty_env_hook.py` | 改 | `current_user_id()` / `_kernel_uid()`；`app_uid` 按当前用户解析 |
| `mobile/tools/thirdparty_env.py` | 改 | 导出 `current_user_id` |
| `mobile/analyze/http_attribution.py` | 新 | 按 uid 端口归属 pcap 报文 |
| `mobile/analyze/test_http_attribution.py` | 新 | 5 例单测 |
| `mobile/tools/device_run_thirdparty_run4.py` | 改 | 解码后归属；判据只认"归属被测包"的报文 |
| `mobile/rules/seed/api_targets.json` | 改 | 新增 4 个 Location 取值 API |
| `mobile/rules/rules_mobile.db` | 改 | 重建（58 → 62 API）；旧库备份 `.bak-20261115` |
| `mobile/hooks/targets.generated.js` | 改 | 重新生成（62 API） |
| `mobile/hooks/dist/hook_all.bundle.js` | 改 | WATCH 58 → 62，长度头重算 |
| `mobile/hooks/patch_bundle_targets.py` | 新 | 构建链不可用时的可复现注入 + 自检 |

---

## 7. 交接时仍未解决的事项

后续 R1–R6 的修复与实测见 [开发日志](DEVELOPMENT_LOG.md)。Roam 两轮均完成 spawn 窗口，
连接归属已覆盖标准 QUIC Initial 元数据，Blue 的重复定位取值已聚合。表内保留交接时的状态。

| # | 项 | 事实 | 影响 |
| --- | --- | --- | --- |
| R1 | `--spawn-hook` 超时 | 本环境 frida spawn 不可用 | 启动期读取仍无覆盖；只能靠 `startup_calls_covered` 提示 |
| R2 | 归属只覆盖 TCP | conn_probe 只读 `tcp/tcp6`；QUIC/UDP 不在内 | HTTP/3 流量既抓不到报文，也无法归属 |
| R3 | 端口采样有间隙 | conn_probe 约 0.5 s 轮询，极短连接可能错过 | 归属会偏少（宁少不多，不会错归） |
| R4 | 端口复用 | 同一端口在窗口内被别的进程复用时会错归 | 概率低；未做时间窗二次校验 |
| R5 | bundle 靠补丁维持 | `frida-compile` 的 Node 绑定缺失 | 规则库再变时要重跑补丁脚本；长期应修构建链 |
| R6 | 取值事件量 | Blue 观测 25 → 124 行 | 长窗口/高频传感器需聚合策略 |
