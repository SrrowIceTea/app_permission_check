# 工程缺陷修复记录（2026-10-14）

> 任务书：[`mobile/RESEARCH_OUTLOOK.md` §八](RESEARCH_OUTLOOK.md)「工程缺陷与修复清单」。
> 执行方式：按 §8.5 的分批计划 1 → 2 → 3 → 4；**每批改完跑两条离线回归**；批次 4 **只写方案，未动一行代码**。
> 遵守 §8.6 六条红线；`core` 未出现任何 `import vehicle` / `import mobile`。

---

## 1. 概述

| 项 | 结果 |
|---|---|
| 改动文件 | **46 个**（其中新建 6 个：`core/io_utils.py`、`core/sdk_paths.py`、`.github/workflows/ci.yml`、`ruff.toml`、`.pre-commit-config.yaml`、`mobile/ai/config.example.json`）+ 本报告 |
| 分批 | 批次 1（配置与文档）→ 批次 2（小范围代码）→ 批次 3（语义级）→ 批次 4（**只写方案**） |
| 移动侧回归 | `mobile/tools/run_mobile_checks.py` → **21/21 passed，failed=[]**（终态） |
| 根回归 | `tools/run_regressions.py` → **11 组全 0 失败**（终态） |
| 回归次数 | 基线 1 次 + 批次 1/2/3 各 1 次 + 批次 3 收尾 2 次，**中间出现过一次回归失败并已修**（见 §3.4） |
| 未执行条目 | 6 条（A1、A3、A4、A5、B-2 钩子共享化/超 300 行拆分、B-3 `extended_rglob`），全部属于批次 4，见 §5 |

两条回归命令（纯离线、不需要设备）：

```bash
PYTHONIOENCODING=utf-8 "C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe" mobile/tools/run_mobile_checks.py
PYTHONIOENCODING=utf-8 "C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe" tools/run_regressions.py
```

---

## 2. 逐条记录

> 「状态」：`已修` = 本轮落地且回归覆盖；`未执行` = 批次 4 或与环境矛盾，原因已写明。

### 批次 1 · 零风险配置与文档

| # | 条目 | 改前 → 改后 | 文件:行 | 为什么改 | 怎么验证 | 状态 |
|---|---|---|---|---|---|---|
| B-5/速修2 | **无 CI** | 无 → 新建 workflow，push/PR 串行跑两条离线回归 | `.github/workflows/ci.yml:1`（新建） | 两条入口都纯离线却全靠手动跑，改完忘记跑 = 静默劣化；这是性价比最高的一项 | 只**建文件**，未推送、未创建远端仓库（本仓库私有、无 CI 服务器）；runner 选 `windows-latest`，因为 winpath 的长路径用例只在 Windows 成立 | 已修（**未在真实 CI 上跑过**——本机没有 CI，yaml 语法未被执行验证） |
| B-6/速修6 | **无 lint/format** | 无 → `ruff.toml`（默认规则集 E+F）+ `.pre-commit-config.yaml`（ruff + **300 行守卫**） | `ruff.toml:1`、`.pre-commit-config.yaml:1`（新建） | 代码里有 `# noqa: BLE001` 说明曾按某套规则整理过而配置丢失；AGENTS.md 第 8 条铁律没有机器检查 | 未装 pre-commit，**未实际执行**；ruff 规则集故意开得窄（不开 BLE/B），避免为过 lint 动无关代码 | 已修（配置就绪，**未执行验证**） |
| B-5/B-6/速修5 | **依赖不可复现** | `Pillow>=11,<13` → `Pillow==12.1.0`；新增 `cryptography==48.0.0`；附 `pip freeze` 快照注释 | `requirements.txt:6,10,13-19` | `tools/test_proxy_cert.py` 直接 `from cryptography import x509` 却未声明 → 按文件装依赖必然 ImportError | 版本取自本机实测 `pip freeze`；快照里如实记录了 `reportlab` 声明 5.0.1 / 实测 5.0.0 的**既有漂移**（本轮未改这一项） | 已修 |
| B-6 | **`config.example.json` 断链** | 文件不存在（文档与 `llm_client.py:55` 都指向它）→ 新建纯占位符模板 | `mobile/ai/config.example.json:1`（新建） | 新环境按文档 `cp` 即失败 | `api_key` 用 `PUT-YOUR-KEY-HERE`（在 `llm_client.PLACEHOLDER_KEYS` 里，会被明确拒绝）；**未写入任何真实 key** | 已修 |
| B-4 | **`config.local.json` 明文真实 key** | 只做确认，不改动内容 | `.gitignore:3-4` | 用户会自己去控制台吊销轮换 | `git check-ignore -v mobile/ai/config.local.json` → 命中 `.gitignore:4:**/config.local.json`，**已被覆盖** | 已确认（**key 本身仍需用户去 DeepSeek 控制台吊销轮换**） |
| B-6 | **文档漂移** | `AGENTS.md`「10 组回归」→「11 组」+ 补移动侧入口；`mobile/CLAUDE.md`「AI 未用真实 key 跑过」→ 已跑过（keepass/camera 两次真实调用） | `AGENTS.md:76-83`、`mobile/CLAUDE.md:182-184` | 与现状矛盾 | 目视核对；`mobile/CLAUDE.md` 的「回归 21 项」**实测已经是 21**，无需改 | 已修 |

### 批次 2 · 单行/小范围代码修复

| # | 条目 | 改前 → 改后 | 文件:行 | 为什么改 | 怎么验证 | 状态 |
|---|---|---|---|---|---|---|
| B-1/速修3 | **共享 bundle 路径拼错** | `HERE.parent.parent / "frida_host" / "dist"`（拼出**仓库根**）→ `.../ "core" / "frida_host" / "dist"` | `vehicle/hooks/build.py:109-113` | `HERE.parent.parent` 是仓库根不是 `core/`；产物会写到无人读取的目录，与 `.gitignore:72`、run.py、模块头注释三处不一致 | 静态核对路径；`core/frida_host/dist/` 实物存在（`hook_egress.bundle.js` 等） | 已修 |
| B-4/速修4 | **workbench digest 无校验** | `CACHE.dir_for(digest)` 直接拼 → 先 `[0-9a-f]{64}` 校验，不符返回 400 | `vehicle/workbench/server.py:42-45,194-196` | `/api/apk/../tree` 可让缓存根解析到父目录 | 用 `re.fullmatch` 实测：`'a'*64` 通过、`'..'` 与大写 64 位被拒 | 已修 |
| B-4/速修8 | **CORS `*`** | `Access-Control-Allow-Origin: *` → 只回显**白名单内**的 Origin（127.0.0.1 / localhost / [::1]）；不带 Origin 时退校验 Host；加 `Vary: Origin` | `vehicle/workbench/server.py:91-107` | 本机任意网页可跨域上传 APK 触发反编译（localhost CSRF） | 正则实测：`http://127.0.0.1:8000`、`http://localhost:5500` 通过，`http://evil.com` 被拒；同源请求（不带 Origin）不受影响 | 已修 |
| B-3/速修7 | **关联引擎 O(n²)** | `rules × reads × flows` 三重嵌套 → 新增 `usable_flow_index()` 按 `(package, session_id)` 预建**可用流**索引，内层降为 O(该包该会话流数)；`condition_json` 预解析 | `vehicle/analyze/evaluation.py:54-74,91` | 长时间采集后是引擎热点 | 过滤条件（未歧义、归因不是 unresolved/ambiguous）只取决于流自身，与规则无关，提出循环外**语义等价**；回归全绿 | 已修 |
| B-3/B-2 低 | **字体表重复 + 每流重新加载字体 + O(n²) 切片** | 两处候选表 → 唯一一份放 `report_extras.py` 并被 `report.py` import（另加 `VSCAN_CJK_FONT` env 覆盖）；`ImageFont.truetype` → 模块级缓存 `raster_font()`；`story[group_start:] = [KeepTogether(...)]` 逐结论重建 → 先记下标、最后一次性重建 | `vehicle/analyze/report_extras.py:15-32,65-66`、`vehicle/analyze/report.py:32,40-44,132-195` | 换机改一处漏一处；PDF 生成随流数变慢 | 本机三个字体文件均存在；回归里的报告渲染用例全过 | 已修（**注意**：`mobile/report/report_common.py:19` 还有**第三份**候选表，属移动侧自有副本，本轮未动，见 §6） |
| B-4 | **`_is_dir_raw` 无条件吞 OSError** | 吞所有 `OSError` → 只吞 `FileNotFoundError`，其余向上传播；`rmtree` 遍历处显式接住并按 `ignore_errors` 决定 | `core/static/winpath.py:85-95,110-131` | `rmtree(ignore_errors=False)` 对无权限路径**静默成功**（"删完了"其实是"没查到"），违反失败可诊断 | 现网两个调用点（`core/static/jobs.py:99`、`test_jobs.py:171`）都用 `ignore_errors=True`，语义保持不变；`test_jobs` 的 `LongPathTest` 通过 | 已修 |
| B-4 | **sqlite URI 路径未编码** | `f"file:{p}?mode=ro"` → `f"file:{quote(p, safe=':/')}?mode=ro"` | `core/rules_contract.py:22,48` | 路径含 `?`/`#` 会被截断 | 实测：目录名含 `#` 时裸拼 URI 报 `no such table`，两种 quote 写法都正常；`safe=':/'` 保留盘符与分隔符便于日志阅读 | 已修 |
| B-3 | **`uid_sampler.adb()` 吞失败** | 失败返回空串 → 返回 `(ok, text)`（退出码非 0 也算失败，挡住"多设备裸 adb 报错"）；新增 `AdbError`；`measure_clock_offset_ms()` 一次都没成功时**抛错**而非静默返回 0；`package_for()` 失败抛错且不写缓存 | `core/collector/uid_sampler.py:39-97,118-131` | 包名静默记成 `null`、时钟偏移静默取 0 → 污染归因时间窗 | 该模块无离线用例（独立脚本、无人 import），改动以编译 + 阅读核对为准；**需设备回归**（见 §6） | 已修（**行为变化，见 §4**） |
| B-4 | **设备端日志固定路径** | `/data/local/tmp/vscan_conn.log|.sh` → 带 pid 后缀（`device_log_path()` / `device_script_path()`） | `core/collector/uid_sampler.py:43-54,164,168-172` | 两实例并发互相 `rm -f` 对方正在写的文件 | 脚本文件同样会互相覆写，一并加 pid | 已修 |
| B-4 | **`adb shell cat >` 拼命令行** | `[ADB,"shell", f"cat > {DEVICE_SCRIPT}"]` → `[ADB,"shell","cat",">",DEVICE_SCRIPT]` | `mobile/tools/conn_probe.py:171-175` | 拼字符串的写法一旦让路径带上外部输入就有整条 shell 注入面；内容仍走 `input=` | adb shell 会把后续参数按空格拼给 sh，拆分后等价 | 已修 |
| B-4/速修9 | **19 处 `D:/Anroid` 硬编码** | 19 处散落硬编码 → 全部改走新建的 `core/sdk_paths.py`（`VSCAN_SDK`/`VSCAN_JDK` → `ANDROID_SDK_ROOT`/`ANDROID_HOME`/`JAVA_HOME` → `shutil.which` → 历史候选表）；`D:/Anroid` 只剩 `sdk_paths.py` 一个文件 | 新建 `core/sdk_paths.py`；改动 `core/evidence/dexlines.py:43`、`core/static/toolchain.py:20-32`、`mobile/rules/extract_android_apis.py:36-42`、`mobile/traffic/transparent.py`、`mobile/tools/{conn_probe,device_run,thirdparty_env,trigger,ui_trigger,fetch_apk,start_emulator,batch_thirdparty,device_run_thirdparty}.py`、`tools/{build_delivery,create_test_avd,device_acceptance}.py` | 换机依赖文档救场，绕过 `environment.ps1` 已有的覆盖机制 | 实测解析结果：`sdk_root=D:\Anroid\SDK`、`adb/emulator/aapt2/javap/android.jar` 全部解析正确；`toolchain.android_build_tool('aapt2')` 正常；全仓代码文件 `grep D:/Anroid` **只剩 `core/sdk_paths.py`** | 已修（**19 处的计数与规格一致**；`mobile/rules/build/*.jsonl` 里的 `D:/Anroid` 是 javap 实证签名的**出处路径**，属证据，**故意未改**） |

### 批次 3 · 语义级修复

| # | 条目 | 改前 → 改后 | 文件:行 | 为什么改 | 怎么验证 | 状态 |
|---|---|---|---|---|---|---|
| B-1 | **内核默认包名白名单** | `VSCAN_PACKAGES` 未设 → 默认 `{"com.vscanner.targetapp","com.vscanner.targetapp2"}` → **空集合 + 响亮 `SystemExit`**（照 `core/evidence/event_lookup.py:24-30` 的写法） | `core/collector/addon.py:88-96` | 移动端漏设时**静默零流量**，日志一切如常 | 调用方全部补齐：`core/collector/test_unanswered.py:127-129`（setdefault）、`tools/device_acceptance.py:139-141`、`tools/multi_acceptance.py:33-35`、`tools/smoke_proxy.py:39-41`；`mobile/tools/{device_run,thirdparty_env}.py` 本来就在设。回归全绿 | 已修（**行为变化，见 §4**） |
| B-1 | **run.py / dexlines.py 同类默认值** | `run.py`：`--allow-package` 默认两个夹具 → 空 + `parser.error`；`dexlines.py`：`--package` 默认 `com.vscanner.targetapp` → `None` + `parser.error` | `core/frida_host/run.py:97-102`、`core/evidence/dexlines.py:201-208` | 同上，平台无关内核不该假定车载包名 | 调用方补齐：`tools/device_acceptance.py:190-193`、`tools/multi_acceptance.py:66-68` 显式传 `--allow-package` | 已修（**行为变化，见 §4**） |
| B-1 | **`crosscheck.py` 裸 import** | `from static_rules import LEVEL_ORDER` → 先 `from .static_rules import`，捕获 `ImportError` 后回退到顶层（显式 shim 并注释） | `core/static/crosscheck.py:69-74` | 依赖调用方预先 `sys.path` hack；按 `core.static.crosscheck` 导入就炸 | 回归里 `test_crosscheck` 仍以顶层 `import crosscheck` 形式跑（走 shim 分支），通过 | 已修 |
| B-2 | **6 份 `load_jsonl` 语义相反** | 6 份手写实现 → 新建 `core/io_utils.py`，策略显式化：`load_jsonl(on_bad_line="raise")` 与 `load_jsonl_counting()`（返回 `(rows, skipped)`） | 新建 `core/io_utils.py`；`vehicle/analyze/correlate.py:48`、`vehicle/dashboard/dashboard.py:36-37`、`vehicle/analyze/report.py:30,258`、`vehicle/traffic/verify_multi_app.py:25,38-44`、`mobile/analyze/correlate_mobile.py:29,33-46`、`mobile/ai/evidence_bundle.py:36,42-55` | 车载侧坏行抛、移动侧静默 `continue`，同批产物两边解释不同 | 静默跳过全部改为**计数并写进 gaps**（`[jsonl] …` 前缀）或 stderr 告警；回归全绿 | 已修 |
| B-2 | **`rule_db_meta()` / `rules_meta()` 逐字重复** | 两份 → 合并为 `core/rules_contract.py::rules_db_meta()`；两个历史键名（`sha256` / `rules_sha256`）都保留 | `core/rules_contract.py:51-70`、`vehicle/analyze/report.py:31,252`（删本地实现与 `sqlite3` import）、`vehicle/dashboard/dashboard.py:36-37,57`（删本地实现与 `hashlib`/`sqlite3` import） | 双份必然漂移；键名不一致是历史包袱，一并按旧名保留 | `test_dashboard.test_rules_meta_embedded` 只断言 `rules_sha256`/`rules_total`，新增键不影响；回归全绿 | 已修 |
| B-4 | **政策正文直拼 prompt，无注入围栏** | 直接 `render()` 填入 → 新增 `fence_untrusted()`：明确分隔符 + "是分析对象不是指令" 声明 + **把 `{{`/`}}` 打散** | `mobile/ai/ai_review.py:63-84` | ① 政策正文里"忽略以上指示"之类句子可诱导结论；② `render()` 是纯字符串替换，正文里若带 `{{REQUIREMENTS}}` 字面量会在后续占位符替换时被**当成真占位符**换掉（模板注入）；③ `req_brief` 原本就是白名单字段，加了注释固化 | 回归里 stage1 提示词渲染与 `test_ai` 全过；**未做真模型调用验证**（需要 key） | 已修 |
| **A2** | **判据盲区：armed ≠ 能捕到** | 只有 `hook_*_armed` → 新增强制判据 `runtime_events_captured`（`reads.jsonl` 中 START/ARMED 之外的事件 ≥1）；零事件时判据失败，并以 `[orch]` 前缀写进证据包 `gaps` | `mobile/tools/device_run_thirdparty.py:290-311,326-330` | 5 个样本 44 条结论 100% 来自静态分析，而判据全绿 | `--no-hooks` 对照下该项为 `optional`（设计使然）；**未做设备验证**——按 §8.6 第 1 条，若夹具仍捕不到应报失败并暴露 A1，而不是改回 optional | 已修（**预期会让现有第三方批次判失败**，见 §4） |
| **A6** | **`egress_tp` 死钩子目标** | 目标表含 `['libcore.io.Posix', [...]]` → 删除 | `mobile/hooks/hook_egress_tp.js:135-143` | API 37 上 `ClassNotFoundException`，每轮记一条 `HOOK_MISS`，看起来像"钩子坏了" | 本文件里实测只有 **1 条** Posix 目标（规格文字写"4 个"，与实际不符，已按代码实际删除）；`BlockGuardOs`/`Linux` 四个保留。回归里 `hooks_dispatch` 通过 | 已修（**与规格描述的数量不一致，已按实际代码处理**） |
| **A12** | **块缓冲导致 `taskkill /F` 丢日志** | — | — | 规格 §8.1 已标【已修】（三个 `start_*` 埋 `PYTHONUNBUFFERED=1`），本轮复核确认在位 | 读代码确认 | 无需改动 |

---

## 3. 回归结果

两条命令都是纯离线、不需要设备。

### 3.1 批次 1 之后

```
$ python mobile/tools/run_mobile_checks.py
{ "status": "passed", "checks": 21, "failed": [] }        # output/mobile-regression-20261014-021958

$ python tools/run_regressions.py
completion 0 / rules-contract 0 / codeloc 0 / correlate 0 / collector 0 /
tagging-vehicle 0 / dashboard 0 / runtime 0 / parity 0 / workbench 0 / hook-bundles 0
```

### 3.2 批次 2 之后

```
$ python mobile/tools/run_mobile_checks.py
{ "status": "passed", "checks": 21, "failed": [] }        # output/mobile-regression-20261014-023621

$ python tools/run_regressions.py
11 组全 0
```

### 3.3 批次 3 之后（终态）

```
$ python mobile/tools/run_mobile_checks.py
{
  "status": "passed",
  "out": "...\\output\\mobile-regression-20261014-025727",
  "checks": 21,
  "failed": []
}

$ python tools/run_regressions.py
completion 0
rules-contract 0
codeloc 0
correlate 0
collector 0
tagging-vehicle 0
dashboard 0
runtime 0
parity 0
workbench 0
hook-bundles 0
（退出码 0）
```

### 3.4 一次真实失败（如实记录）

批次 3 收尾时我顺手删掉了 `mobile/analyze/correlate_mobile.py` 的 `import json`（以为统一 `load_jsonl` 后不再用到），回归立刻变红：

```
{ "status": "failed", "checks": 21, "failed": ["e2e_correlate", "findings_nonempty"] }
...
File ".../mobile/analyze/correlate_mobile.py", line 67, in load_rules
    "condition": json.loads(r["condition_json"] or "{}"),
NameError: name 'json' is not defined.
```

已恢复该 import，重跑转绿。**记录在这里是因为它正好说明两条回归确实在盯字段契约**——也提醒后来者：`grep -n json | head -5` 会漏看，删 import 前要全文件确认。

---

## 4. 行为变化清单（需要用户知晓）

1. **`VSCAN_PACKAGES` 漏设 = 响亮失败，不再是静默零流量**。
   `core/collector/addon.py` 在白名单为空时直接 `SystemExit`。任何直接起 `mitmdump -s core/collector/addon.py` 的手工流程必须先导出 `VSCAN_PACKAGES=<包名>`。`tools/{device_acceptance,multi_acceptance,smoke_proxy}.py` 已改为显式设置；若你还有别的手工命令，需要同步补上。
2. **`core/frida_host/run.py` 的 `--allow-package` 不再有默认值**。
   不传会 `parser.error` 退出。`tools/device_acceptance.py`、`tools/multi_acceptance.py` 已补齐；其余调用点（含你自己的手工命令）都要补。
3. **`core/evidence/dexlines.py` 的 `--package` 变为必填**。
   以前默认 `com.vscanner.targetapp`，不传会拿到"看起来对、其实是错包名"的核对结果。
4. **第三方批次会开始判失败**（A2 的直接后果，也是它的目的）。
   `runtime_events_captured` 是**强制**判据：只要 `reads.jsonl` 只有 START/ARMED，`verification.json` 就 `passed=false`，且证据包 `gaps` 会多一条 `[orch] 本轮 … 零运行时事件 …`。**这是期望行为**——按 §8.6 第 1 条，不许为了判据变绿而把它改回 optional；读数为零应当先归因到 A1。
5. **`uid_sampler` 的失败不再静默**。
   - 时钟标定一次都没成功 → 抛 `AdbError`，进程退出码 2（原来是"偏移 0"，会把归因时间窗整体污染）。
   - 包名查询失败 → 控制台 `[uid_sampler] !! …` 报错，且该条记录多一个 `package_lookup_error` 字段（成功时**没有**这个键）。下游用 `.get("package")` 不受影响。
   - 设备端日志/脚本路径变成 `vscan_conn.<pid>.log` / `vscan_rec.<pid>.sh`；如果某些清理脚本写死了旧路径，需要跟着改。
6. **JSONL 坏行不再被静默吞掉**。
   移动侧（`correlate_mobile.py` / `evidence_bundle.py`）从"静默 `continue`"变成"跳过 + 写进 `gaps`（`[jsonl] …` 前缀）"；`verify_multi_app.py` 变成"跳过 + stderr `[warn]`"。因此**证据包与报告的 gaps 可能比过去多条目**——那是过去被吞掉的部分，不是新问题。
7. **`vehicle/workbench` 的跨域只对本机放行**。
   如果你用非 127.0.0.1/localhost 的来源（例如局域网另一台机器）访问工作台前端，会被浏览器拒绝——这是有意的收紧。
8. **字体候选表合并后顺序是 SimHei → DengXian → 雅黑**（原来是两处各取一半）。换机可用 `VSCAN_CJK_FONT=<ttf 路径>` 覆盖而不改代码。
9. **`sdk_paths` 会读 `VSCAN_SDK`/`VSCAN_JDK`**。换机时设这两个环境变量即可，不必再改 19 处代码。
10. **pre-commit 的 300 行守卫会拦下现有 7 个超限文件**（`vehicle/workbench/server.py` 316、`mobile/tools/device_run.py` 457、`mobile/tools/thirdparty_env.py` 459、`mobile/tools/device_run_thirdparty.py` 411、`mobile/tools/fetch_apk.py` 382、`core/collector/addon.py` 355、`mobile/ai/evidence_bundle.py` 355）。这几个**改动前就已超限**，本轮未做拆分（属批次 4）；它们只在被提交时才会触发守卫，日常工作不受影响。

---

## 5. 批次 4 方案（**未动一行代码**）

### 5.1 A1 · 插桩把应用打死（P0，最高优先级）

**现状事实**（M029/M030 已取证，本轮未变）：挂全套钩子时应用非确定地死（SIGABRT/SIGSEGV），同 UI 序列一死一活；不挂钩子对照全程存活；崩点是"某个静态方法的 ArtMethod 入口失效导致主线程取指到未映射页"，发生在**第一次被监视 API 被调用附近**，崩前的事件一条也发不出来。

#### 待验证假设（离线读代码得出，**未经设备验证，不作为结论**）

| 编号 | 假设 | 依据（离线可见） | 验证步骤（需设备） |
|---|---|---|---|
| **H1（最强）** | **钩子体内（事件期）的 `Java.use()` 是触发点**。每次命中都会走 `buildExtra()` → `stackStr()` → `Java.use('java.lang.Thread').currentThread().getStackTrace()`、`threadName()`；标量返回值还要走 `values.js::sha256hex16()` → `Java.use('java.security.MessageDigest').getInstance('SHA-256')` 并 `new java.lang.String(...)` | `mobile/hooks/hook_privacy.js:97`（`vlog('PRIVACY_READ', buildExtra(...))`）、`runtime.js:70,79`、`values.js:20-21`。这些调用都发生在**被替换的 ArtMethod 正在执行、栈还压在 Frida trampoline 里**的时刻，而 M029 的崩点正是 `art_quick_invoke_static_stub` 跳入未映射页 | ① 在 ARMED 阶段把 `Thread` / `MessageDigest` 的 `Java.use` 结果缓存到模块级变量，事件期不再 `Java.use`；② 加 `VSCAN_NO_STACK=1` 关掉 `stackStr()`/`threadName()`；③ 夹具各跑 3 次，对比崩溃率与是否出现真实事件 |
| **H2** | **一次性替换 58 个 ArtMethod 入口**本身是规模问题 | `hook_privacy.js:123` `for (var i = 0; i < WATCH.length; i++) armOne(WATCH[i]);`，全部在 `Java.perform` 里同步完成 | 分档二分：只挂 1~3 → 8 → 16 → 32 → 58，每档夹具跑 3 次，找阈值 |
| **H3** | **attach 模式换成 spawn 模式**可规避 | 当前是 attach（`AGENTS.md` 记"spawn 超时，用 attach"）。spawn 能让钩子在应用代码执行前装好，避免替换"正在被执行/编译"的 ArtMethod——而 M029 观察到崩时进程几乎全在解释器里（新装 APK 的 `verify` 过滤器） | 用 `run.py` 的 spawn 路径 + 更长超时（如 120s）重跑夹具；对比 attach 的崩溃率 |
| **H4** | **Frida 版本 / API 37 + 16KB 页的已知问题** | 本机 frida 17.18.0，设备 Android 16 / API 37 / 16KB 页 | 需联网核对上游 release note 与 issue（本轮未做）；若确有修复，升级后重跑夹具 |
| **H5（次要）** | 事件期构造 Java 对象（`new java.lang.String`）与 Digest 调用开销放大竞态窗口 | `values.js:21` | 先用 `args_only` 模式跑一档（不做值哈希），看崩溃是否消失，以隔离"是哈希导致还是替换本身导致" |

#### 落地步骤建议（顺序）

1. **先把 A2 的强制判据用起来**（本轮已做）：任何一轮跑完先看 `verification.json` 的 `runtime_events_captured`，它现在是 A1 的探针。
2. **分档脚本**：给 `hook_privacy.js` 加一个 `VSCAN_WATCH_LIMIT=<n>`（或 `--watch-limit` 由 `gen_targets.py` 生成子集），按 H2 的档位跑；每档把 `app-death.json` 与 `reads.jsonl` 落盘归档，形成可对照的表格。
3. **H1 的缓存化改造**：把 `runtime.js` 的 `Java.use` 收敛成 `tryUse` 的模块级缓存；`stackStr()` 做成可关开关。**这两处是纯离线可写、但必须设备验证的改动**——按 §8.6 第 6 条，未验证前不得声称 A1 已修。
4. 每档/每次都要记：`alive_at_end`（三态）、`/data/tombstones/` 文本、crash 缓冲行数、`reads.jsonl` 真实事件数。
5. **验收判据**（照 §8.1 A1）：夹具跑一次，`reads.jsonl` 出现 ≥1 条非 START/ARMED 的真实事件，且进程在窗口内存活。

#### 风险预估

- H1/H2/H3 都是"改钩子加载方式"，**不改 API 观测面**（58 条签名与 ARMED 语义不变），因此不触及规则库与回归；风险主要在于"改了仍崩"→ 需要按 A4 做工程韧性兜底。
- H3（spawn）受本机"spawn 超时"限制，可能需要先解决 spawn 本身，成本高于收益，建议放最后。
- H4 需要网络与升级，可能引入其他回归（frida 版本与 mitmproxy/Python 绑定耦合），建议单独一轮。

### 5.2 A3 · 夹具阳性对照内建进 `batch_thirdparty.py`

- 批次开始前先跑一次**夹具最小自检**：装 `com.vscanner.privacydemo` → 挂钩 → 点 1 个按钮（如 `btnDeviceId`）→ 断言 `reads.jsonl` 有 ≥1 条真实事件。
- 自检失败 → **拒绝出批**，给出明确原因并指向 A1 的分档脚本。
- 建议实现形态：新增 `mobile/tools/fixture_selftest.py`（≤300 行）返回结构化结果；`batch_thirdparty.py` 在遍历样本前调用一次，结果写进批次级 `verification.json`。
- 验收：故意 `--no-hooks` 或把钩子脚本改坏，批次必须在自检阶段失败退出。
- 依赖：A1 未修时自检**必然失败**，这会让批次永远出不了——所以**先做 A1 的分档定位**，或把自检做成"可跳过但必须显式 `--skip-fixture-selftest` 并在报告里留痕"。

### 5.3 A4 · 崩溃自愈 + 分段采集

- 采集窗口切 N 段（默认 30s/段）：每段「`am force-stop` → `am start` → 等 pid → 重挂钩子 → 采集 → 收尾落盘」。
- 数据**跨段累加**（`reads.jsonl` 等按段追加，`evt_id` 需跨段唯一——注意 `event_lookup.py` 里"撞号"那条坑）。
- 每次死亡记入 `app-death.json`（含段号、段内已采到的事件数）；最终报告写明"N 段中 K 段进程死亡"。
- 风险：重启应用会丢"跨段的应用内状态"（如已登录态），深层功能触达率可能下降 —— 与 A5 的意图化探索要结合设计；`session_id` 是否跨段保持一致需要与 `VSCAN_SESSION` 语义对齐（归因要求同会话）。

### 5.4 B-2 · 钩子 JS 共享化 或 一致性守卫

- **短期（推荐先做）**：新增 `mobile/tools/test_hooks_parity.py`——把 `mobile/hooks/{hook_cipher,hook_native_ssl,stack_capture,ssl_pinning_tp,tls_bypasses_tp}.js` 与 `vehicle/hooks/` 同名文件**去注释后 diff**，差异非空即失败（允许一份"已知差异白名单"，每条带理由与日期）。并入 `run_mobile_checks.py`。
  - 纯离线、不需要设备、收益立即可见：车载侧修的 bug（如 D312 的 doFinal 重载语义）不会再静默漏到移动侧。
- **中期**：JS 共享源码放 `core/hooks_shared/`，两侧 `frida-compile` 时按平台注入不同 runtime import 与日志路径（`addon_mobile.py` 的 `VSCAN_TAGGING` 模式已是同一思路的成功先例）。
  - 风险：产物 bundle 路径与 `.gitignore:72`（`**/dist/*.bundle.js` 不入库）耦合；共享化后必须同步更新 `tools/test_hook_bundles.py` 的清单，否则"离线全绿、真跑才炸"。
  - `core` 不得引用任何平台特有概念——共享的是**机制**（日志、栈、值哈希口径），不是包名。

### 5.5 B-2 · 超 300 行文件拆分

- 当前 7 个：`mobile/tools/device_run.py`(457)、`mobile/tools/thirdparty_env.py`(459)、`mobile/tools/device_run_thirdparty.py`(411)、`mobile/tools/fetch_apk.py`(382)、`core/collector/addon.py`(355)、`mobile/ai/evidence_bundle.py`(355)、`vehicle/workbench/server.py`(316)。（`mobile/rules/build_mobile_rules.py`、`mobile/analyze/test_analyze.py` 也在规格名单里，本轮未复核行数。）
- 切法建议：`addon.py` 按"流生命周期 / 归因调度 / HTTP 端点"三拆；`device_run.py` 按"adb 封装 / 进程编排 / 对话框处理"拆；`thirdparty_env.py` 把"环境变量与常量"单独抽一份给两个入口共用。
- 前置：先上好 §5.4 的一致性守卫与现在的 300 行 pre-commit 钩子，拆完才不会再长回去；每拆一步跑两条回归。

### 5.6 B-3 · `winpath.extended_rglob()`

- 问题：`core/static/jadx.py:82,97`、`core/static/jobs.py:79,91,98` 用 `rglob`/`scandir` 不走 `\\?\` 前缀，目录自身路径超 260 时 glob **静默吞掉整棵子树**（`source_tree` 少列、LRU 淘汰失准）且无报错——`winpath` 现在只兜住文件级 `stat`。
- 实现思路：新增 `winpath.extended_rglob(root, pattern)`——用 `os.scandir(extended(root))` **逐级自己遍历**（与 `rmtree` 同一套手工反斜杠拼接，见模块头第 2 条坑：`os.path.join` 会拼出正斜杠 → WinError 123），对每一级返回的 `entry.name` 做 `fnmatch`，命中即产出 `Path`（**对外仍是普通路径，不让 `\\?\` 渗进业务代码与 JSON**）。非 Windows 直接退化成 `Path.rglob`。
- 风险预估：
  1. 符号链接/联接的循环风险 —— 需要深度上限与"已访问 realpath"集合；
  2. 与 `rmtree` 共用拼接逻辑，写错会同时打坏两处 → 建议先抽一个 `winpath._join_ext(parent, name)` 私有助手；
  3. 返回值顺序与 `Path.rglob` 不完全一致（后者按目录序遍历），下游若有排序依赖需要显式 `sorted()`；
  4. 必须有离线用例：`test_jobs.LongPathTest` 的现有深路径基础上再补一条"目录自身 > 260"的用例（当前用例可能只覆盖文件级）。

### 5.7 B-4 · `vscan_conn.log` 并发路径

- **已在批次 2 一并做了**（`core/collector/uid_sampler.py` 带 pid 后缀，见 §2）。
- 剩余：`mobile/tools/conn_probe.py` 的 `DEVICE_LOG = "/data/local/tmp/vscan_conn_all.log"`（第 57 行）仍是固定路径，同一个并发问题。建议同样加 pid 后缀（`conn_probe` 与 `uid_sampler` 会在同一轮里同时跑，两者**互相不构成冲突**因为文件名不同，但两个 conn_probe 实例会冲突）。本轮**未改**（规格只点名 `vscan_conn.log`）。

---

## 6. 遗留问题与建议下一步

1. **A1 未修，是全部运行时结论为空的根因**。建议下一步就按 §5.1 的 H1 → H2 顺序做分档实验，把"崩溃率 × 钩子档位"做成一张表——这张表本身就是论文里"方法可靠性"一节可用的材料。
2. **`config.local.json` 里的真实 key 仍需你本人去吊销轮换**（DeepSeek 控制台）。该文件已被 `.gitignore` 覆盖，但**历史提交里是否曾入库未核查**（需要 `git log --all -- mobile/ai/config.local.json` 与必要时 scrub 历史）。
3. **CI / pre-commit 未在本机实际执行过**。yaml 与 pre-commit 配置只做了人工核对；要真正生效需要：① 有远端仓库与 Actions 权限；② 本机 `pip install pre-commit && pre-commit install`。本轮按你的要求**没有推送、没有创建远端仓库**。
4. **新增的 300 行守卫会拦下 7 个既有超限文件**（见 §4.10）。要不要在下一轮按 §5.5 拆，取决于你是否接受这批文件的改动量。
5. **`mobile/report/report_common.py:19` 还有第三份字体候选表**（规格只列了两处）。移动侧不 import 车载侧（项目约定），所以要么复制合并后的顺序过去，要么把候选表下沉到 `core`（更彻底，但会让 `core` 承担"报告字体"这种表现层职责，需要你定夺）。
6. **`sqlite` 只读连接的 URI 编码只改了 `core/rules_contract.py` 一处**。`vehicle/dashboard/dashboard.py`、`vehicle/workbench/static_rules.py`、`mobile/analyze/correlate_mobile.py:56`、`mobile/ai/evidence_bundle.py` 里还有同类 `f"file:{p}?mode=ro"` 写法，属同一风险。本轮按"小而准"只改了规格点名的那处（顺带 `rules_db_meta` 合并让 `report.py` 间接受益）。
7. **`uid_sampler.py` 的改动没有离线用例覆盖**（该模块是独立脚本、无人 import，两条回归都不碰它）。改动后只在编译层面验证，建议补一组"adb 返回非 0 → `ok=False`"的纯函数用例，或直接依赖设备回归。
8. **文档漂移还有一处未改**：根 `CLAUDE.md:103` 也写着"10 组回归"（与 `AGENTS.md` 同一个漂移）。规格只点名 `AGENTS.md`，本轮未动。
9. **仓库卫生**：450 个跟踪文件混入产物/证据、46 个文件改动未提交（规格 B-5 低优先级，属批次外的独立整理），建议单独一轮处理，不要和代码修复混在一起提交。
