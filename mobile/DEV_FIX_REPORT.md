# 工程缺陷修复记录（2026-10-14）

> 任务书：[`mobile/RESEARCH_OUTLOOK.md` §八](RESEARCH_OUTLOOK.md)「工程缺陷与修复清单」。
> 执行方式：按 §8.5 的分批计划 1 → 2 → 3 → 4；**每批改完跑两条离线回归**。
> 批次 4 的第一轮**只写方案、未动一行代码**；第二轮（2026-10-14 晚）落地了其中**纯离线可写**的三项
> （A1 的分档/缓存预备、A3 的夹具阳性对照、B-2 的钩子一致性守卫）——当时 A1 本体未修，
> **已于 2026-10-16 修复**（执行记录见 §5.1 / §5.8 / §5.9）。
> 遵守 §8.6 六条红线；`core` 未出现任何 `import vehicle` / `import mobile`。

---

## 1. 概述

| 项 | 结果 |
|---|---|
| 改动文件 | **46 个**（其中新建 6 个：`core/io_utils.py`、`core/sdk_paths.py`、`.github/workflows/ci.yml`、`ruff.toml`、`.pre-commit-config.yaml`、`mobile/ai/config.example.json`）+ 批次 5 的 13 个新建/拆分文件 + 本报告 |
| 分批 | 批次 1（配置与文档）→ 批次 2（小范围代码）→ 批次 3（语义级）→ 批次 4-A（**只写方案**）→ 批次 4-B（**离线可写部分落地**，2026-10-14 晚）→ 批次 5（**全量复核 + 清剩余债**，2026-10-14 第二轮/第三轮） |
| 移动侧回归 | `mobile/tools/run_mobile_checks.py` → **23/23 passed，failed=[]**（批次 5 终态） |
| 根回归 | `tools/run_regressions.py` → **13 组全 0 失败**（批次 5 终态） |
| 回归次数 | 基线 1 次 + 批次 1/2/3 各 1 次 + 批次 3 收尾 2 次 + 批次 4-B 2 次 + 批次 5 至少 4 次，**中间出现过一次回归失败并已修**（见 §3.4） |
| 未执行条目 | ~~A1 本体（需设备）~~ **2026-10-16 已修复**（见 §5.1/§5.8/§5.9）、A4、A5、B-2 的中期共享化、剩余 6 个超 300 行文件的拆分、`run_regressions.py --mobile` 开关，见 §6 |

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

### 3.5 批次 4（离线部分）之后

**结论：两条回归都全绿；但换一个解释器就会冒出 6 处假红，必须先看解释器再看红。**

```
# 用「裸 python」（本机落到 WorkBuddy 托管解释器，没装 requirements.txt）——6 处红
$ python mobile/tools/run_mobile_checks.py
{ "status": "failed", "checks": 22, "failed": ["report", "e2e_report", "report_nonempty"] }
      # → No module named 'reportlab'（mobile/report/report_mobile.py:33）

$ python tools/run_regressions.py
completion 1        # → No module named 'PIL'（vehicle/analyze/report_extras.py）
collector 1         # → No module named 'mitmproxy'（core/collector/addon.py）
hook-bundles 1      # → No module named 'cryptography'（tools/test_proxy_cert.py）
（其余 9 组 0）

# 按 requirements.txt 装完依赖后重跑——两条全绿
$ <venv>/python mobile/tools/run_mobile_checks.py
{ "status": "passed", "checks": 22, "failed": [] }

$ <venv>/python tools/run_regressions.py
completion 0   rules-contract 0   codeloc 0   correlate 0   collector 0
tagging-vehicle 0   dashboard 0   runtime 0   parity 0   workbench 0
hook-bundles 0   frida-bundle-config 0
```

四个要点：

1. **那 6 处红是解释器问题，不是代码问题，也不是"批次 3 的记录是假的"**。实测四个解释器：
   | 解释器 | reportlab / PIL / mitmproxy / cryptography | maxminddb |
   |---|---|---|
   | `C:\Users\毛宇淇\AppData\Local\Programs\Python\Python313`（用户自己的） | 全有 | **缺** |
   | `D:\MSYS2\mingw64\bin\python.exe` | 全缺 | 缺 |
   | WorkBuddy 托管 `…\versions\3.13.12\python.exe` | 全缺 | 缺 |
   | 隔离 venv `…\envs\default\`（本轮装的） | 全有 | **有** |
   §3.3 那张全 0 的表是用**用户自己的 Python 3.13** 跑的，所以是真的；本轮第一次跑落到托管解释器上，才出现那 6 处红。
2. **`requirements.txt` 里"reportlab 声明 5.0.1 而本机 5.0.0"的漂移已经不存在**：本轮 `pip install -r requirements.txt` 装到的是 **5.0.1**，与声明一致，那条注解可以删。
3. **`maxminddb` 只有 venv 装了**——说明 `requirements.txt` 声明了它，但现有的回归/检查一条都不 import 它。这既是"声明了没验证"，也是换机时最容易漏的一个。
4. **新增/改动的离线套件**：`run_regressions.py` 从 11 组到 **12 组**（新增 `frida-bundle-config` = `core/frida_host/test_bundle_config.py`，6 例）；`run_mobile_checks.py` 从 21 项到 **22 项**（新增 `hooks_parity` = `mobile/tools/test_hooks_parity.py`）。

> ⚠️ **踩坑记录**：跑这两条回归**先确认解释器**。本轮用隔离 venv（已按 `requirements.txt` 装齐）跑通；
> 直接敲裸 `python` 会落到托管解释器上，然后看到 6 处红——**那 6 处红会掩盖真正的回归失败**。
> 另外注意 bash 里不要用 `~` 指代用户目录（本机 `HOME=/d/HZNU/GitHome`），要用绝对路径。
> 这条正是 §8.2 B-5「全项目无 CI」的实际代价：同一个仓库、同一个命令，换台机器/换个解释器结果就不一样。

### 3.6 批次 5 之后（本轮，2026-10-14 第二与第三轮）

> 批次 5 = 「还有什么要修的一起都修了」这一轮的复核 + 落地。先**逐条对代码复核**了 §8.2 全部 29 条，
> 结论：**其中 24 条与 A6/A7/A8 在批次 1–3 里其实已经落地了**，只是 `RESEARCH_OUTLOOK.md` 的状态列没跟着改
> （该文件的这一列已按复核结果刷新，并加了「不要相信这一列，要相信代码」的警告）。
> 真正剩下的三笔债——超 300 行拆分、`winpath.extended_rglob()`、`run_regressions.py --mobile`——本轮清掉前两笔。

```
$ <venv>/python mobile/tools/run_mobile_checks.py
{ "status": "passed",
  "out": "...\\output\\mobile-regression-20261014-182327",
  "checks": 23,        # 22 → 23（新增 a1_tier_scan）
  "failed": [] }

$ <venv>/python tools/run_regressions.py
completion 0    rules-contract 0    event-store 0    codeloc 0    correlate 0
collector 0     tagging-vehicle 0   dashboard 0      runtime 0    parity 0
workbench 0     hook-bundles 0      frida-bundle-config 0
# 12 组 → 13 组（新增 event-store = core/test_event_store.py，4 例）；退出码 0
```

四个要点：

1. **`event-store` 是拆出来的**：`StorageTests` 原先挤在仓库根的 `test_completion.py` 里（318 行），
   移到 `core/test_event_store.py`（75 行）既治了"测试放错层"（内核的存储不该由 completion 套件代管），
   也让 `test_completion.py` 降到 281 行。**测试数守恒：4 例搬到哪儿都还是 4 例**（不是删测试换绿）。
2. **`a1_tier_scan` 是新增的检查项**，不是新功能：A1 的分档实验需要一个机器可读的"崩溃率 × 档位"表，
   以前只有纯手工跑。它把 §5.1 的 H1/H2/H5 假设变成一条命令（`--tiers 1,3,8,16,32,58 --repeats N`），
   并强制三态统计（`valid` / `env_failed` / `crashed`）——**环境没跑起来的格子会被排除出分母**，
   因为把"没测到"记成"没崩"正是 A1 一直在制造的假安心（§8.6 第 1 条）。**11 例**纯函数用例覆盖
   汇总/判词/参数解析/渲染——其中 2 例正是无设备冒烟抓出工具自身 bug 后补的（见 §3.6 末注）。
3. **`fetch_apk.py --help` / import 链回归**：把 `fetch_apk.py`(382→242) 拆成 + `fetch_apk_io.py`(162) 之后，
   专门验了 `import fetch_apk, fetch_apk_io, apk_meta` 与 `apk_meta.fetch_apk.apk_identity` 这条**跨文件引用**
   仍然可用（`fetch_apk.py` 头部显式再导出三个原名），`--help` 正常打印 usage。
4. **`test_analyze.py` 拆分后测试数守恒 31 = 22 + 9**：`EgressTest`(9 例) 移到 `test_analyze_egress.py`，
   新文件从 `test_analyze` 里 import 现成的 `ctx`/`read`/`rule` 夹具——**重复一份夹具比多一个文件更糟**，
   所以这个文件自愿放弃了"完全自包含"。

> ⚠️ **无设备冒烟反而抓出了 `a1_tier_scan` 自己的一个真 bug——照实记。**
> 跑 `--out output/_a1_scan_smoke --repeats 1`（6 档 ×1，每档等设备超时约 5 分钟，共约半小时），
> 得到 6 格**全 `env_failed`**（`alive=None reads=None`，`reason=设备未在超时内启动完成`）——
> 三态统计本身是对的（`crash_rate`/`capture_rate` 都渲染成 `—` 而不是 `0%`）。
> **但判词输出了「所有档位都没崩——再跑一轮」，退出码还是 0。**
> 那就是本工具存在的全部意义所在的那件事——**把"没测到"写成"没崩"**——只不过这次发生在
> 工具自己身上：`_verdict()` 只看了 `crashed == 0`，没先问"到底有没有格子被测到"。
>
> 修法（两处，共用一条不变量）：
> 1. 抽出 `any_valid(tiers)`——零有效格是**整轮级别的失败**，不是"结果全好"；
> 2. `_verdict()` 把它当**前置判断**（放在 `crashing` 之前），零有效格时只输出
>    「本轮根本没测到，不能读成没崩」+「先修环境再重跑」，不出现任何"没崩"式的字眼；
> 3. `main()` 在表落盘后仍**返回 2**——现场要留，但脚本层面不能是成功，否则批量脚本里
>    "退出码 0"会被读成"跑过了"。
>
> 新增 2 条用例（`test_a1_tier_scan.py` 9 → **11**）：一条把"全 env_failed 不得出现
> 「都没崩」/「再跑一轮」"钉死，另一条是反向用例（只要有一格有效就必须走正常判词，
> 防止上一条被"一律拒绝"糊弄过去）。并用**真实冒烟数据回放**验证修复后的判词与退出码。
>
> 纯函数部分（汇总/判词/参数解析/渲染）现有 11 例离线用例；真机路径（`run_cell`）仍需设备。

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
10. **pre-commit 的 300 行守卫曾会拦下 7 个文件**——批次 5 按"只拆低风险那批"的口径拆掉了 5 个
    （`fetch_apk.py` 382→242、`build_mobile_rules.py` 406→209、`test_analyze.py` 324→220、
    `test_completion.py` 318→281、`evaluation_mobile.py` 309→241），**剩 6 个故意不拆**：
    `mobile/tools/device_run.py`(457)、`mobile/tools/thirdparty_env.py`(459)、`mobile/tools/device_run_thirdparty.py`(411)、
    `core/collector/addon.py`(355)、`mobile/ai/evidence_bundle.py`(355)、`vehicle/workbench/server.py`(316)。
    这 6 个是设备验证主链路（第三方的采集/编排/报告），**A1 修好前动它们风险不对等**——只在被提交时触发守卫，
    日常工作不受影响（见 §6.4）。
11. **`core/frida_host/run.py` 多三个分档开关（A1 定位用，默认不启用）**。
    `--watch-limit <n>`（同 `VSCAN_WATCH_LIMIT`）：只挂前 n 条监视项，`0` = 全不挂（attach 对照组），不给 = 全量 58。
    `--no-stack`（同 `VSCAN_NO_STACK=1`）：事件里不带 `thread_name`/`stack` 字段值。
    `--args-only`（同 `VSCAN_ARGS_ONLY=1`）：**整轮完全不碰返回值**——连 `count_only` 也退化成只记参数字段（批次 5 新增，针对假设 H5：事件期构造 Java 对象/做值哈希触发 VM 内部崩溃）。
    **不给这三个参数时行为与以前完全一致**（占位符原样保留在 bundle 里，`configure()` 只替换显式传入的）；一旦启用，`START`/`ARMED` 事件会多出 `watch_limit`/`watch_limit_raw`/`runtime_cache`/`value_cache`/`args_only` 字段，档位可事后从证据里复核。
12. **第三方批次多了一道前置门（A3）**：跑批前自动跑一次夹具阳性对照，**失败就拒绝出批**。
    - 直接后果：**没接设备 / 设备没起来时，以前会产出一批"零运行时事件"的样本结论，现在批次会直接失败退出**（退出码 1，stdout 给 `status: fixture_selftest_failed` + `reason` + `hint`）。这是期望行为，不是回归。
    - A1 未修期间确实会挡住正常工作，所以留了显式逃生口 `--skip-fixture-selftest`；**跳过时批次摘要里会留痕**（`selftest.passed = null` + 跳过原因 + "结论可信度下降"提示），事后可查——不许把它当成透明的开关用。
    - 批次产物多一个 `_fixture-selftest/` 目录（求值现场 + `result.json`）与一份 `fixture-selftest.log`；`batch-summary.json` 多一个 `selftest` 字段。
13. **新增钩子一致性守卫（B-2）：改 `mobile/hooks/*.js` 或 `vehicle/hooks/*.js` 后被它拦下是正常的**。
    `mobile/tools/test_hooks_parity.py` 会比对 7 对共享钩子脚本；两侧不一致就失败。若差异是**有意**的，必须往 `mobile/tools/hooks_parity_whitelist.json` 加一条带 `id`/`reason`/`date` 的规则，否则守卫会一直红。**反过来，白名单里的规则一旦不再命中也会报错**——两侧代码演进后要记得清理。
14. **`measure_clock_offset_ms()` 现在会抛错而不是返回 0**（批次 2 的行为变化，批次 5 补上了离线用例）。
    该函数以前"一次都没成功"时静默返回 0，会把归因时间窗整体污染成"看起来对齐"。现在抛 `AdbError`，
    调用方要接住。同理 `PackageMap.package_for()` 失败**不写缓存**（避免把一次失败固化成永久 `null`）。
15. **新增 A1 分档扫描器 `mobile/tools/a1_tier_scan.py`（236 行，纯函数部分离线可验）**：
    `--tiers 1,3,8,16,32,58 --repeats N` 逐档跑夹具自检并出"崩溃率 × 档位"表 + `tier-scan.md`。
    它**不会**把环境没跑起来的格子算成"没崩"——那些格子归 `env_failed`、**排除出分母**、
    且**零有效格时退出码为 2**（表照样落盘，但脚本层面不能算成功）。
    - ⚠️ **别把它当"无设备冒烟测试"跑**：`device_guard()` 只拦"多设备且未指定 ANDROID_SERIAL"，
      **不拦"没有设备"**——无设备时每一档都会老老实实等设备超时（约 5 分钟/档），
      6 档 ×1 复次就要半小时。想验离线部分直接跑 `test_a1_tier_scan`。

---

## 5. 批次 4 与批次 5：方案与执行（**A1 已于 2026-10-16 修复**，见 §5.8/§5.9）

> 批次 4-B（2026-10-14 第二批）只做**纯离线可写**的三件事：A1 的分档/缓存预备（§5.1）、
> A3 的夹具阳性对照（§5.2）、B-2 的钩子一致性守卫（§5.4）。**当时 A1 本体没修**——
> 按 §8.6 第 6 条与 §5.1 的验收判据，A1 必须设备上跑夹具出真实事件才算修好。
>
> 批次 5（本轮的复核轮）在那一轮之上：补 H5 的 `--args-only` 开关与分档扫描器、
> 落地 §5.6 的 `extended_rglob`、按"只拆低风险那批"拆掉 5 个超 300 行文件、给 `uid_sampler`
> 与字体表补兜底。**当时 A1 本体依然没修**——所有运行时结论为空；
> **该状态已于 2026-10-16 终结**（bridge 补丁 + 单 agent，执行记录 §5.8，复证与抓包链路修复 §5.9）。

### 5.0 执行摘要

| 条目 | 状态 | 落地物 | 离线证据 | 缺什么才能算完 |
|---|---|---|---|---|
| **5.1 A1 分档定位** | **离线预备已落地，A1 本体未修** | `--watch-limit`/`VSCAN_WATCH_LIMIT`（H2）、`--no-stack`/`VSCAN_NO_STACK`（H1）、**`--args-only`/`VSCAN_ARGS_ONLY`（H5，批次 5）**、事件期缓存化 `armRuntimeCache()`/`armValueCache()`、扫描器 `mobile/tools/a1_tier_scan.py` | `core/frida_host/test_bundle_config.py` 6 例全过；真实 bundle 上 **4 个**占位符各存活 1 次（`hook_consent` 只有 2 个，正常），替换后长度头自洽、模块拼接过 `node --check`；`test_a1_tier_scan.py` 11 例 | 设备上按档位跑夹具，`reads.jsonl` 出现 ≥1 条非 START/ARMED 事件且进程存活 |
| **5.2 A3 夹具自检** | **已落地，待设备验收** | `mobile/tools/fixture_selftest.py`；`batch_thirdparty.py` 前置门 + `--skip-fixture-selftest`；结果写进 `batch-summary.json` 的 `selftest` | 无设备跑 → `passed:false` + `reason`/`hint`；`--skip` → `passed:null` 且跳过事实落进批次摘要；门判 `False` 时批次拒绝出批。**批次 5 修掉一处会记错的字段**：`alive_at_end`/`app_death` 只在真的取到存活状态时才写 | 设备上跑批，夹具自检真出 PRIVACY_READ |
| **5.4 B-2 一致性守卫** | **已落地并验证** | `mobile/tools/test_hooks_parity.py` + `hooks_parity_whitelist.json`（**7 对**、13 条规则） | 通过 exit 0；注入 4 种真实漂移均 exit 1 并给出行级 A/B 差异；白名单陈旧也 exit 1 | —（纯离线，已完） |
| **5.5 超 300 行拆分** | **部分落地（11 → 6）** | 拆 5 个：`fetch_apk`(382→242)、`build_mobile_rules`(406→209)、`test_analyze`(324→220)、`test_completion`(318→281)、`evaluation_mobile`(309→241) | 每个都验了"测试数守恒"与受影响套件全绿（§5.5） | 剩 6 个主链路文件**等 A1 修好再拆**（用户决定） |
| **5.6 `extended_rglob`** | **已落地并复现原缺陷** | `core/static/winpath.py::extended_rglob()`；5 个调用点改完 | 目录自身 310 字符时 `rglob` → `[]`、`extended_rglob` → `['Deep.java']`；`test_jobs.ExtendedRglobTest` 3 例 | —（纯离线，已完） |
| **5.3 / 5.7** | 未做（仍为方案） | — | — | 见各自小节 |

### 5.1 A1 · 插桩把应用打死（P0，最高优先级）—— **已修复（2026-10-16），执行记录见 §5.8**

> **修复摘要（2026-10-16）**：A1 由**三层独立缺陷**叠加而成（"原分析"段只描述了其中
> 第 3 层的表象），全部定位并修复。验收判据（§8.1：`reads.jsonl` 出现 ≥1 条非
> START/ARMED 真实事件 **且进程存活**）达成：夹具 `hook_all` 单 agent **5/5 通过**、
> 真实样本（voicerecorder）端到端通过。
>
> | 层 | 根因 | 关键证据 | 修复 |
> |---|---|---|---|
> | 1 | **JIT 编译线程 × ArtMethod 替换竞态**（Jit thread pool SIGSEGV） | 分档实验：46 档（不含触发 API）不崩 / 49 档（含 getImei）崩；崩溃线程 = Jit thread pool | **关闭 JIT**（`setprop dalvik.vm.usejit false` + `stop/start`） |
> | 2 | **JNI transition frame reference**：Android 14+ ART 把 `this`/对象参数以 transition ref 传给 native；CheckJNI（userdebug 强制开启）穿不过 Frida trampoline 帧做栈遍历 → "jobject is an invalid JNI transition frame reference" | 上游已知 bug（frida#3700/#3745，**未修**）+ 本机 tombstone 逐帧一致 | **bridge 补丁**：`mobile/hooks/patches/02-class-factory-transition-ref.patch`（transition ref 解码 + `AddGlobalRef` 提升为真全局引用；参考 MaYiFei1995/Camille_Android16；`build.mjs` 构建前幂等重放，`npm install` 后不丢） |
> | 3 | **多脚本（多 agent）各自替换不被 bridge 支持**：被 hook 方法调用时触发 `ArtMethod::GetOatQuickMethodHeader` 的 debug FATAL（主线程 SIGABRT；tombstone 显示 `#17 GetOatQuickMethodHeader ← #18 <anonymous>`——调用者正是 Frida） | **bridge 源码注释原文** "we don't support replacing methods from multiple scripts"；对照实验：双脚本 ~50% 崩 vs 单脚本 **5/5** | **单 agent 合并**：新 `hook_all` bundle（privacy+consent+egress_tp+ssl_pinning_tp 在同一个 JS 上下文装配），挂载清单 5→1 |
>
> 同批附带修复（详见 §5.8）：**拆钩噪声隔离**（哨兵优雅停止 `stop_hook`；窗口证据
> 【reads 读取 / alive / 死亡取证】全部前移到拆钩之前）；**死亡取证对齐被挂钩 pid**
> （`/proc/<pid>` 判活，防"崩溃后自动重启"把死亡伪装成存活）；**event 分流器**
> `split_events.py`（单文件产物 → consent/egress/tls 独立文件，下游零改动）；
> vehicle 版 egress/pinning 从 mobile 链路退役（含已实证会炸 ART 的 HttpsURLConnection
> 手法）。deopt 路线已证伪（deopt=1 引出 JNI 副作用新崩溃、deopt=2 无效——均为实测）。
>
> **修正（2026-10-16 晚，复证 + 诚实性补丁）**：上表第 1 行"**关闭 JIT**"**并未真正生效，
> 也不再是修复的必要环节**。复证证据：① `setprop dalvik.vm.usejit false` + `stop/start`
> 后，夹具进程**仍有** `Jit thread pool` 线程与 `dalvik-jit-code-cache` 映射（与 M029 旧结论
> 一致，双向实测：usejit=true 与 false 的进程形态相同）；② `-prop dalvik.vm.usejit=false`
> 被 emulator 37.1.11 直接拒绝（启动日志：only 'qemu.*' properties are supported）。
> 因此此前全部"修复后验证"（fix ×3 / single ×5 / hook_all ×5 / e2e）实际都在 **JIT 开启**
> 状态下完成——修复的实质是**第 2 层（bridge 补丁）+ 第 3 层（单 agent）**；JIT-SEGV
> 是同一根因的另一种随机落点形态，不构成独立的"层"。JIT 开启下 hook_all 49 档复跑
> **2/2 干净通过**（`jiton-49-r2/r3`；r1 为自检工具的点击时序假阴性，已修 harness，
> 见 §5.9）。`_ensure_jit_off` 机制与 `-prop` 参数已**整体清退**。

**原分析（M029/M030 取证，保留留痕）**：挂全套钩子时应用非确定地死（SIGABRT/SIGSEGV），同 UI 序列一死一活；不挂钩子对照全程存活；崩点是"某个静态方法的 ArtMethod 入口失效导致主线程取指到未映射页"，发生在**第一次被监视 API 被调用附近**，崩前的事件一条也发不出来。

#### 待验证假设（离线读代码得出，**未经设备验证，不作为结论**）

| 编号 | 假设 | 依据（离线可见） | 验证步骤（需设备） |
|---|---|---|---|
| **H1（最强）** | **钩子体内（事件期）的 `Java.use()` 是触发点**。每次命中都会走 `buildExtra()` → `stackStr()` → `Java.use('java.lang.Thread').currentThread().getStackTrace()`、`threadName()`；标量返回值还要走 `values.js::sha256hex16()` → `Java.use('java.security.MessageDigest').getInstance('SHA-256')` 并 `new java.lang.String(...)` | `mobile/hooks/hook_privacy.js:97`（`vlog('PRIVACY_READ', buildExtra(...))`）、`runtime.js:70,79`、`values.js:20-21`。这些调用都发生在**被替换的 ArtMethod 正在执行、栈还压在 Frida trampoline 里**的时刻，而 M029 的崩点正是 `art_quick_invoke_static_stub` 跳入未映射页 | ① 在 ARMED 阶段把 `Thread` / `MessageDigest` 的 `Java.use` 结果缓存到模块级变量，事件期不再 `Java.use`；② 加 `VSCAN_NO_STACK=1` 关掉 `stackStr()`/`threadName()`；③ 夹具各跑 3 次，对比崩溃率与是否出现真实事件 |
| **H2** | **一次性替换 58 个 ArtMethod 入口**本身是规模问题 | `hook_privacy.js:123` `for (var i = 0; i < WATCH.length; i++) armOne(WATCH[i]);`，全部在 `Java.perform` 里同步完成 | 分档二分：只挂 1~3 → 8 → 16 → 32 → 58，每档夹具跑 3 次，找阈值 |
| **H3** | **attach 模式换成 spawn 模式**可规避 | 当前是 attach（`AGENTS.md` 记"spawn 超时，用 attach"）。spawn 能让钩子在应用代码执行前装好，避免替换"正在被执行/编译"的 ArtMethod——而 M029 观察到崩时进程几乎全在解释器里（新装 APK 的 `verify` 过滤器） | 用 `run.py` 的 spawn 路径 + 更长超时（如 120s）重跑夹具；对比 attach 的崩溃率 |
| **H4** | **Frida 版本 / API 37 + 16KB 页的已知问题** | 本机 frida 17.18.0，设备 Android 16 / API 37 / 16KB 页 | 需联网核对上游 release note 与 issue（本轮未做）；若确有修复，升级后重跑夹具 |
| **H5** | 事件期构造 Java 对象（`new java.lang.String`）与 Digest 调用开销放大竞态窗口 | `values.js:21` | **开关已落地**（批次 5 的 `--args-only` / `VSCAN_ARGS_ONLY=1`，整轮连 `count_only` 都退化成只记参数）：58 档 + `args_only` 跑 3 次，若活下来而关掉就崩 → 崩点在事件期，而不在"挂 58 个方法" |

#### 落地步骤建议（顺序）

1. **先把 A2 的强制判据用起来**（本轮已做）：任何一轮跑完先看 `verification.json` 的 `runtime_events_captured`，它现在是 A1 的探针。
2. **分档脚本**（**本轮已落地**）：`core/frida_host/run.py` 新增 `--watch-limit <n>`，`hook_privacy.js` 里 `for (var i = 0; i < limit; i++) armOne(WATCH[i])`；`0` 是合法档位（等价全不挂，当 attach 对照组），未给 = 全量 58。同名的 `VSCAN_WATCH_LIMIT` 环境变量可兜底。`START`/`ARMED` 事件里都带 `watch_limit`/`watch_limit_raw`，档位可事后从证据里复核。按 H2 的档位跑；每档把 `app-death.json` 与 `reads.jsonl` 落盘归档，形成可对照的表格。
3. **H1 的缓存化改造**（**本轮已落地**）：`runtime.js` 新增 `armRuntimeCache()` 把 `Java.use('java.lang.Thread')` 提到 ARMED 阶段缓存（`threadName()`/`stackStr()` 事件期不再 `Java.use`）；`values.js` 新增 `armValueCache()` 缓存 `MessageDigest`。`stackStr()` 另有总开关 `VSCAN_NO_STACK=1` / `--no-stack`，打开后事件不带线程/栈字段。`START` 里记 `runtime_cache`/`value_cache` 两个布尔，能立刻看出缓存是否生效。**这些仍是纯离线可写、必须设备验证的改动**——按 §8.6 第 6 条，未验证前不得声称 A1 已修。
   - 坑（已踩并记录）：`frida-compile` 的压缩器会把**直接的字面量比较**（`"__VSCAN_NO_STACK__" === "1"`）常量折叠成 `false`，占位符必须走 `parseInt("__VSCAN_NO_STACK__", 10)` 消费。判断方式是构建后 `grep` bundle，确认占位符字符串还在。
   - **批次 5 追加**：同一条路子又加了第四个占位符 `__VSCAN_ARGS_ONLY__`（H5 开关）。验证方式与 H1 一致——
     构建后 `grep` 确认 4 个占位符在 `hook_privacy.bundle.js` 里各存活 **1 次**（`hook_consent.bundle.js` 只用到 2 个，
     不是漏替换），替换后逐模块 UTF-8 字节长度头自洽、拼接结果过 `node --check`、且**替换后不留占位符残渣**。
4. 每档/每次都要记：`alive_at_end`（三态）、`/data/tombstones/` 文本、crash 缓冲行数、`reads.jsonl` 真实事件数。
5. **验收判据**（照 §8.1 A1）：夹具跑一次，`reads.jsonl` 出现 ≥1 条非 START/ARMED 的真实事件，且进程在窗口内存活。
6. **把分档跑成一条命令**（**批次 5 已落地**）：`mobile/tools/a1_tier_scan.py --tiers 1,3,8,16,32,58 --repeats 3`
   逐档跑 `fixture_selftest` 并渲染"崩溃率 × 捕获率 × 档位"表（外加一份 `tier-scan.md`）。
   档位/开关通过**环境变量**下传（`thirdparty_env.start_hook` 会把 `dict(os.environ)` 原样交给 `run.py`），
   所以同一份代码既能整体跑也能单档复现。**三态统计是硬约束**：环境没跑起来的格子记 `env_failed`
   并**排除出分母**——不许把"没测到"记成"没崩"（§8.6 第 1 条）。
   判词会直接给结论：首个崩档、完好上界、一轮没崩时说"再跑一轮"、最小档就崩时指向 H3/H4。

#### 风险预估

- H1/H2/H3 都是"改钩子加载方式"，**不改 API 观测面**（58 条签名与 ARMED 语义不变），因此不触及规则库与回归；风险主要在于"改了仍崩"→ 需要按 A4 做工程韧性兜底。
- H3（spawn）受本机"spawn 超时"限制，可能需要先解决 spawn 本身，成本高于收益，建议放最后。
- H4 需要网络与升级，可能引入其他回归（frida 版本与 mitmproxy/Python 绑定耦合），建议单独一轮。

### 5.2 A3 · 夹具阳性对照内建进 `batch_thirdparty.py`

**状态：已实现（离线可验部分全过，设备侧待验收）。**

- 批次开始前自动跑一次**夹具最小自检**：装 `com.vscanner.privacydemo` → 挂钩 → 点 1 个按钮（`btnDeviceId`）→ 断言 `reads.jsonl` 有 ≥1 条真实事件。
- 落地物：新增 `mobile/tools/fixture_selftest.py`（209 行，独立入口，可单独跑）；`batch_thirdparty.py` 在**遍历样本前**调用一次，拿到 `passed is False` 就写 `status="fixture_selftest_failed"`、`samples=0` 的批次摘要并 `return 1`。
- **结果落在哪**：不是 `verification.json`——那是**单样本**级产物，批次本来就没有；改为写进**批次级** `batch-summary.json` 的 `selftest` 字段，自检自己的 `result.json` 另存 `<批次>/_fixture-selftest/`。
- 自检失败 → **拒绝出批**，`reason`/`hint` 直接回显 stdout；`hint` 指向 A1 的分档脚本。
- **依赖（原判断成立）**：A1 未修时自检必然失败，会让批次永远出不了。所以做成"**可跳过但必须显式 `--skip-fixture-selftest`**"：跳过时写 `passed: null` + `skipped` 原因 + 一句"本轮无法区分『采不到』与『没收集』、结论可信度下降"，跳过事实留在批次摘要里，事后可查。
- 附带说明：`batch_thirdparty.py` **没有** `--no-hooks`（那是单样本 runner 的对照开关），所以批次侧的自检**永远用真实钩子链跑**——这正是阳性对照要的语义。

**验收（对应 §8.1 A3 判据）**

| 分支 | 手段 | 结果 |
|---|---|---|
| 自检不过 → 拒绝出批 | 无设备离线跑 | ✅ `{"status":"fixture_selftest_failed","reason":"设备未在超时内启动完成",...}`，退出码 1；`batch-summary.json` 里 `samples=0`、`selftest.passed=false`（证据：`output/_batch_gate_refuse/`） |
| `--skip` → 留痕但放行 | 显式跳过 | ✅ `selftest: {"passed": null, "skipped": "explicit --skip-fixture-selftest", "hint": ...}` 写进批次摘要（证据：`output/_batch_gate_test/`） |
| 自检脚本崩掉 → 不产出 `result.json` | 代码分支 | ⚠️ 只做了代码走查：缺文件一律判 `passed=false` 并把原因指向 `fixture-selftest.log`，未做实际注入 |
| **把钩子脚本改坏** → 自检因零 PRIVACY_READ 失败 | 需设备 | ⏳ 未验。它走的是同一条 `passed is False` 拒绝路径，但现场尚未跑过 |

### 5.3 A4 · 崩溃自愈 + 分段采集

- 采集窗口切 N 段（默认 30s/段）：每段「`am force-stop` → `am start` → 等 pid → 重挂钩子 → 采集 → 收尾落盘」。
- 数据**跨段累加**（`reads.jsonl` 等按段追加，`evt_id` 需跨段唯一——注意 `event_lookup.py` 里"撞号"那条坑）。
- 每次死亡记入 `app-death.json`（含段号、段内已采到的事件数）；最终报告写明"N 段中 K 段进程死亡"。
- 风险：重启应用会丢"跨段的应用内状态"（如已登录态），深层功能触达率可能下降 —— 与 A5 的意图化探索要结合设计；`session_id` 是否跨段保持一致需要与 `VSCAN_SESSION` 语义对齐（归因要求同会话）。

### 5.4 B-2 · 钩子 JS 共享化 或 一致性守卫

- **短期：已落地并验证**。新增 `mobile/tools/test_hooks_parity.py`，已并入 `mobile/tools/run_mobile_checks.py`。
  - ⚠️ **规格漏了 2 对**：原文只列 5 对（3 同名 + 2 改名）。把 `mobile/hooks/*.js` 与 `vehicle/hooks/*.js` 两两做相似度矩阵后，实际是 **7 对**——多出 `scope.js`↔`scope.js`（0.857）与 `runtime.js`↔`vehicle/hooks/vscan_runtime.js`（0.769，改名）。其余组合相似度 ≤0.33，据此排除"还有漏配"。
  - 白名单 `mobile/tools/hooks_parity_whitelist.json`：13 条规则、4 类动作——`sub`（两侧同点替换，用于标识符改名）、`block`（整块豁免）、`exempt_functions`（只豁免函数体，签名仍比对）、`drop`（两侧同删）。每条强制带 `id`/`reason`/`date`，并限定生效的 `pair` 与 `side`。
  - **陈旧白名单必须报错**（规则零命中即 exit 1）：否则两侧代码演进后白名单会悄悄失效、退化成"永久豁免"，守卫就没价值了。这条是它有没有长期意义的成败点。
  - 已验证：通过路径 exit 0（7 对全绿）；4 种真实漂移全部 exit 1 并给出行级 A/B 差异——`hook_cipher` 的 `maxPlainBytes`、`hook_native_ssl` 的 `maxPlainBytes`、`scope.js` 的 `JSON.parse`、`runtime.js` 的 `rec.tid`→`rec.rid`；另单独验过"白名单里留一条陈旧规则"会报出来（且只报这一条，不做级联噪音）。
  - 纯离线、不需要设备、收益立即可见：车载侧修的 bug（如 D312 的 doFinal 重载语义）不会再静默漏到移动侧。
- **中期**：JS 共享源码放 `core/hooks_shared/`，两侧 `frida-compile` 时按平台注入不同 runtime import 与日志路径（`addon_mobile.py` 的 `VSCAN_TAGGING` 模式已是同一思路的成功先例）。
  - 风险：产物 bundle 路径与 `.gitignore:72`（`**/dist/*.bundle.js` 不入库）耦合；共享化后必须同步更新 `tools/test_hook_bundles.py` 的清单，否则"离线全绿、真跑才炸"。
  - `core` 不得引用任何平台特有概念——共享的是**机制**（日志、栈、值哈希口径），不是包名。

### 5.5 B-2 · 超 300 行文件拆分

> **批次 5 执行状态：11 → 6，用户明确选择「只拆低风险的那批」。**
> 拆掉的 5 个（都不在设备验证主链路上）：
>
> | 文件 | 改前 → 改后 | 拆出 |
> |---|---|---|
> | `mobile/tools/fetch_apk.py` | 382 → 242 | `fetch_apk_io.py`(162)：HTTP 原语 / 下载 / 身份摘要 |
> | `mobile/rules/build_mobile_rules.py` | 406 → 209 | `mobile_rules_inputs.py`(93) + `mobile_rules_insert.py`(155) |
> | `mobile/analyze/test_analyze.py` | 324 → 220 | `test_analyze_egress.py`(142)，9 例 |
> | `test_completion.py`（仓库根） | 318 → 281 | `core/test_event_store.py`(75)，4 例 |
> | `mobile/analyze/evaluation_mobile.py` | 309 → 241 | `evaluation_mobile_parts.py`(110)，纯函数助手 |
>
> 每个都验了"测试数守恒"（31 = 22 + 9；存储 4 例原样搬）与受影响套件全绿，没有靠删测试换绿。
>
> **剩余 6 个故意不拆**（设备验证主链路，A1 修好前不动）：`mobile/tools/device_run.py`(457)、
> `mobile/tools/thirdparty_env.py`(459)、`mobile/tools/device_run_thirdparty.py`(411)、
> `core/collector/addon.py`(355)、`mobile/ai/evidence_bundle.py`(355)、`vehicle/workbench/server.py`(316)。

- 切法建议（对剩余 6 个仍然适用）：`addon.py` 按"流生命周期 / 归因调度 / HTTP 端点"三拆；
  `device_run.py` 按"adb 封装 / 进程编排 / 对话框处理"拆；`thirdparty_env.py` 把"环境变量与常量"单独抽一份给两个入口共用。
- 前置：先上好 §5.4 的一致性守卫与现在的 300 行 pre-commit 钩子，拆完才不会再长回去；每拆一步跑两条回归。
- **拆分踩过的坑（给下次拆的人）**：① 被拆出的模块如果两边互相引用，会撞**循环 import**——`mobile_rules_inputs.py`
  与 `mobile_rules_insert.py` 之间就差点撞上，最后把共用的 `_protection_level_value` 固定在 inputs 一侧才解开；
  ② 原文件里的名字是**别人 import 的入口**（`apk_meta.fetch_apk.apk_identity`、`test_rules.bmr._protection_level_value`），
  拆完必须在原文件头部显式再导出，否则"离线全绿、真跑才炸"；
  ③ 按行号做文本手术会失手（行号会漂），要**按内容定位边界**。

### 5.6 B-3 · `winpath.extended_rglob()`

> **批次 5 执行状态：已落地。** `core/static/winpath.py` 新增 `extended_rglob(root, pattern="*")`，
> 5 个调用点全部改过来（`core/static/jadx.py` 2 处、`core/static/jobs.py` 3 处）。
> **原始缺陷已复现为证**：同一目录下，把目录自身路径撑到 310 字符后，
> 原生 `sources.rglob("*.java")` 返回 **`[]`**（静默吞掉整棵子树），而 `extended_rglob` 返回 `['Deep.java']`；
> 同一路径上裸 `os.scandir` 则直接抛 `FileNotFoundError`——这就是"为什么不自己走一遍就兜不住"。
> 新增 3 条离线用例（找到子树且不漏 `\\?\` / 普通树上与 `rglob` 结果一致 / 边界：缺失根、多段模式报 `ValueError`），
> 全部在 `core/static/test_jobs.py::ExtendedRglobTest`。
>
> **实现与原始设计的偏差（照实记）**：
> 1. **没做符号链接环防护**。用的是 `entry.is_dir(follow_symlinks=False)`，与 Python 3.13 `rglob` 的默认一致——
>    也就是说"不跟随链接"本身就是环的天然上界，再加深度上限反而与 `rglob` 语义不一致（会产生假绿）。
> 2. **没抽 `_join_ext` 公共助手**，而是给模块级 `_SEP` 常量：`os.name == "nt"` 但 `os.sep == "/"` 的解释器
>    （本机 MSYS2 那个）存在，`os.path.join` 会拼出正斜杠，而 `\\?\` 只认反斜杠（见模块头第 2 条坑）。
> 3. **返回值是普通 `Path`**，不外泄 `\\?\`；下游若依赖顺序要显式 `sorted()`（`jadx.py` 那处已经加了）。
> 4. 非 Windows 上 `\\?\` 前缀本就是无操作，函数退化成"自己走一遍的 rglob"，行为一致。
>
> 原方案里的三条风险（符号链接环 / `_join_ext` 助手 / 顺序不一致）结局见上；第 4 条"必须有离线用例"
> 已兑现，且比原要求更严——**新用例专门构造了"目录自身 > 260"的那种形态**，
> 因为旧 `LongPathTest` 只覆盖了文件级长路径（文件级 `rglob` 仍然列得出条目，只有 `stat`/`open` 才炸，
> 与目录级"整棵子树消失"是两种症状，见 §6.8）。

### 5.7 B-4 · `vscan_conn.log` 并发路径

- **已在批次 2 一并做了**（`core/collector/uid_sampler.py` 带 pid 后缀，见 §2）。
- 剩余：`mobile/tools/conn_probe.py` 的 `DEVICE_LOG = "/data/local/tmp/vscan_conn_all.log"`（第 57 行）仍是固定路径，同一个并发问题。建议同样加 pid 后缀（`conn_probe` 与 `uid_sampler` 会在同一轮里同时跑，两者**互相不构成冲突**因为文件名不同，但两个 conn_probe 实例会冲突）。本轮**未改**（规格只点名 `vscan_conn.log`）。

### 5.8 A1 修复执行记录（2026-10-16）

**设备/环境**：VScan_Phone（API 37、userdebug【CheckJNI 强制开】、16KB 页）；
frida-server 17.18.0；frida-java-bridge 7.0.13；模拟器 `-http-proxy` 强制抓包。

**定位实验矩阵**（全部实机，产物 `D:/vscanner-tp/a1-scan/`）：

| 实验 | 配置 | 结果 | 结论 |
|---|---|---|---|
| 基线 | 58 档全量 | 崩（Jit thread pool SIGSEGV） | 复现 A1（修复前近 100% 崩） |
| 分档 | 1 / 46 档（不含 getImei） | 存活、零事件 | **非规模问题**；崩点在"被 hook 方法被调用" |
| 分档 | 49 / 58 档（含 getImei） | 崩 | 触发即崩、崩前零事件（与 M029 一致） |
| deopt=1 | 49 档 | 崩溃形态改变：主线程 `JNI invalid jobject` | 全文去优化引出 JNI 副作用；**证伪** |
| deopt=2 | 49 档 ×3 | 与基线同型 | boot image 去优化无效；**证伪** |
| JIT-off | 49 档 | JIT 线程崩溃消失，暴露 `GetOatQuickMethodHeader` FATAL | 第 1 层被消除；第 3 层暴露 |
| bridge 补丁 | 49/58 档 | 事件首次捕获成功（2 条 PRIVACY_READ + 完整调用栈）但 ~50% 仍崩 | 第 2 层修复；第 3 层残留 |
| 样本对照 | 单脚本 ×5 vs 双脚本 ~19 轮 | **5/5 vs ~50%** | **第 3 层 = 多 agent**（命中 bridge 注释的限制） |
| 合并验证 | `hook_all` ×5 | **5/5 通过（零 fatal）** | 修复达成（判据：≥1 真实事件 + 进程存活） |

**关键取证**（`/data/tombstones/tombstone_39`）：一级 FATAL 栈——
`#17 ArtMethod::GetOatQuickMethodHeader ← #18 <anonymous>`（Frida 代码），
dump 的方法为 getImei（`pc=0, entrypoint= 71524030, ...`）；ART 在 debug 构建下对
"无法解析的 pc"直接 FATAL，而 bridge 的防护（`ensureArtKnowsHowToHandleReplacementMethods`
里"替换该函数"的路线）因 **libart.so 被 strip** 装不上——实测 `findSymbolByName`
返回 null、`enumerateSymbols()` 的 12872 个 `.gnu_debugdata` 符号里也查无此符号，
且 x64 分支被 bridge 作者标注"Not needed on x86 and x64"（内联副本拦截直接跳过）。
即 **x64 + API 37 恰好命中 bridge 的未覆盖区**——这是第 3 层的放大条件，
"单 agent"把触发路径（多脚本各自替换的清理/交互）整体移除，从而绕开。

**改动清单**（本批）：
- `mobile/hooks/patches/02-class-factory-transition-ref.patch` + `build.mjs`（补丁幂等重放 + BUNDLES 薄入口体系 + `hook_all`）
- `mobile/hooks/runtime.js`（`deoptimizeBeforeArm` + `VSCAN_DEOPTIMIZE` 开关——**默认关**，保留 A/B 对照能力）+ `hook_privacy.js`（START 事件留痕 `deoptimize`）
- `mobile/hooks/{hook_privacy,hook_consent,hook_egress_tp,ssl_pinning_tp}.js`（导出 `main`，摘除顶层自执行）
- `core/frida_host/bundle_config.py`（第五占位符 `__VSCAN_DEOPTIMIZE__`）+ `run.py`（`--deoptimize`、`--stop-file` 优雅停止）
- `mobile/tools/thirdparty_env.py`（`start_hook` 哨兵路径 + `stop_hook`）
- `mobile/tools/{fixture_selftest,device_run_thirdparty,device_run}.py`（单 agent 切换 + 证据时序前移 + 被挂钩 pid 对齐）
- `mobile/tools/split_events.py` + `test_split_events.py`（事件分流器，6 例）
- `mobile/tools/hooks_parity_whitelist.json`（+3 条：导出化 sub/drop、deoptimize 豁免，均带 reason/date）

**验证**：夹具 `hook_all` ×5 全绿（`D:/vscanner-tp/a1-scan/all-49-r*`）；真实样本端到端
（`D:/vscanner-tp/a1-scan/e2e-1/`）；`test_hooks_parity` 7 对全过；`test_bundle_config` 6 例；
`test_split_events` 6 例；`run_regressions` / `run_mobile_checks`（回归结果见 §3）。

**遗留边界（如实）**：a) `-prop dalvik.vm.usejit=false` 启动参数方式待验证（当前用
setprop + stop/start）；b) 双脚本拆钩仍会产生一次工具侧 abort（已隔离出取证窗口，
不影响结论）；c) 若未来必须多脚本，需等 frida-java-bridge 上游修复（#3700/#3745）；
d) x64 `GetOatQuickMethodHeader` 符号定位（版本偏移表/指纹）属 bridge 上游问题，
本仓库以"单 agent 规避"绕开，未改 bridge 本体。

### 5.9 A1 复证 + 抓包链路修复（2026-10-16 晚）

**① JIT-off 复证（修正 §5.1/§5.8 的"第 1 层"）**：

- 线程级裁决实验：`setprop dalvik.vm.usejit false` + `stop/start` 之后，夹具进程
  （`com.vscanner.privacydemo`）`/proc/<pid>/task/*/comm` 里**仍有 `Jit thread pool`**，
  `/proc/<pid>/maps` 里仍有 `dalvik-jit-code-cache` / `dalvik-zygote-jit-code-cache`
  映射——**JIT 没有被关掉**（与 M029 的旧结论互相印证）。`-prop` 路径同时被
  emulator 37.1.11 拒绝（"only 'qemu.*' properties are supported"）。
- 结论：修复实质 = bridge 补丁 + 单 agent；JIT 开启下复跑 hook_all 49 档 **2/2 干净
  通过**（`D:/vscanner-tp/a1-scan/jiton-49-r2/r3`：各 2 条 PRIVACY_READ、alive=true、
  fatal 空）。r1 的"点击成功但零事件"经取证（无 tombstone、trigger 结果正常、日志
  顺序）判为**自检工具点击时序假阴性**（钩子未挂妥就点击），已修：`fixture_selftest`
  改为**轮询 hook 日志的 armed+collecting 标记**（≤90s，等不到即失败退出），替换
  原来的固定 `sleep(8)`。
- **清退**：`pipeline/runner.py` 的 `_ensure_jit_off`（含 stop/start + CA 重装的整套
  动作）整体删除；`transparent.emulator_capture_args` 移除 `-prop` 参数。

**② 抓包链路修复（本晚最重要的发现，SLIRP 强制代理此前一直是失效的）**：

- **现象**：模拟器启动日志固定出现
  `WARNING | Could not connect to proxy at 10.0.2.2:8888: timed out !` +
  `WARNING | Proxy will be ignored !`。
- **取证链**（guest 原始 socket 实测，用 `nc` 直连做判别，绕开所有应用层代理设置）：
  - 代理在线/离线两种启动次序下，guest 直连任意 IP 均**超时**、mitmproxy 侧
    **零连接记录** → SLIRP 重定向**关闭**；
  - 此前 e2e 里"系统连通性检查"能进 mitmproxy，是**设备侧 http_proxy 设置**的功劳
    （NetworkMonitor 显式连 10.0.2.2:8888），**不是** SLIRP 重定向——即：**不读系统
    代理的直连流量一直在漏**，与"SLIRP 层强制"的文档承诺不符。
- **根因**：emulator 37.x 启动时从**宿主进程**对 `-http-proxy` 地址做一次性可达性
  探测；传 guest 侧别名 `10.0.2.2` 在宿主上不可路由 → 必超时 → 重定向整条被关。
- **修复**（两件套，缺一不可）：
  1. `transparent.emulator_capture_args` 的 `-http-proxy` 地址改为**宿主侧回环**
     `127.0.0.1`（新增 `PROXY_ARG_HOST` 常量；设备侧 `settings put global http_proxy`
     仍是 guest 侧 `10.0.2.2`，两个地址空间各自的语义不变）；
  2. `pipeline/runner.py` 新增 `_start_early_mitm`：**冷启动模拟器之前**先把
     mitmproxy 拉起来（该探测只在模拟器启动那一刻做、失败不重试）；device_run 以
     `--reuse-mitm` 复用（端口探活、死了自动回退自起）；生命周期到 `finalize` 统一收。
- **验证（铁证）**：同一模拟器（修复后配置）上
  - `nc` 直连 `example.com:80` 拿到**经代理的真实 200**（cloudflare）；
  - `nc` 直连任意 dummy IP 收到 **`Server: mitmproxy 12.2.3` 的 400 报错页**——
    连 raw socket 都被重定向，证明不依赖应用配合；
  - mitmproxy 日志完整记录以上连接（`server connect example.com:80` / `200 OK`）。
- **配套加固**：`start_mitm` 增加"端口被占预检 + 启动后监听校验"（原先 mitmdump
  抢不到端口会静默退出、采集带着"没有代理"跑完——把静默错变成响亮报错）；
  `app_death_reason` 抗 adb 超时（pidof/logcat 超时 → `alive_at_end=None` 如实降级，
  不再掀翻整轮）；模拟器 stdout/stderr 落 `emulator.log`（"Proxy will be ignored"
  这类只出现在启动日志里的关键警告不再随 DEVNULL 消失）。
- **复现/回退**：若换 emulator 版本，先核对启动日志里有**无**"Proxy will be ignored"；
  出现即意味着重定向失效、只剩设备侧代理路径。
- **现场复验（2026-10-16 下午，M033）**：M032 修复另做了**独立于端到端**的现场复验，
  已固化成可重复工具 `mobile/tools/verify_force_proxy.py`：前置 mitmdump → 冷启动
  （启动参数与流水线同源 `tp.emulator_capture_args`）→ 等 boot → **等多目标 TCP
  探测通过**（对齐 `ensure_wifi`）→ `settings put global http_proxy :0` 把系统代理
  **彻底禁用** → raw socket 三测。工具化复跑（2026-10-16 15:45，全绿，七项判据
  `D:/vscanner-tp/verify-force-proxy/20261016-154525/verdict.json`）：
  - 前置：模拟器日志无 "Proxy will be ignored"、`settings get` 实测 `':0'`；
  - **A**：raw socket 直连 `example.com:80` 被捕获（mitm.log 有
    `GET http://example.com/ HTTP/1.0` 的 flow）；
  - **B（铁证）**：raw socket 直连 TEST-NET-3 不可达 IP `203.0.113.7:80`，guest
    收到 `HTTP/1.1 400 Bad Request` + `Server: mitmproxy 12.2.3` +
    "HTTP request has no host header, destination unknown."——不可达地址不可能有
    真实服务，此响应只能来自本机代理 = 直连被强制劫持；
  - **C**：UDP 到宿主 listener **直出**（`-http-proxy` 只重定向 TCP）——QUIC/HTTP3
    属已声明边界，报告如实引用（不解码）。
- **复验固化出的两个排障点**：① **boot 完成 ≠ 网络就绪**——冷启动后 eth0 的 DHCP
  还要等（两轮实测 36s / 106s），过早测试全是 "Network is unreachable"（假阴性，
  会误判成"代理没抓"；工具内置网络等待）；② mitmproxy 对**无 Host 的畸形请求**
  （如直连 IP 不带 Host）直接回 400，但**不产生 flow 日志行、也不进 flows.jsonl**
  （本地隔离实验复现：日志为空）——判断该类直连是否被劫持要看连接增量或客户端
  实际收到的响应，不能查 flow 日志，否则漏判。

---

## 6. 遗留问题与建议下一步

1. ~~**A1 未修，是全部运行时结论为空的根因——但工具已就位，下一步就是接设备跑。**~~
   **→ A1 已修（2026-10-16，见 §5.8）**：三层根因全部定位并修复，验收判据达成
   （夹具 hook_all 5/5、真实样本端到端通过）。以下原文与分档判据保留——对未来的
   同类回归排查仍有价值：
   三个开关（`--watch-limit` / `--no-stack` / `--args-only`，§5.1 第 2、3 步 + 批次 5 补的 H5 开关）
   已经能用，夹具阳性对照（§5.2）会自动告诉你哪一档活着，分档扫描器 `mobile/tools/a1_tier_scan.py`
   直接把结果出成表。建议按 §5.1 的 H1 → H2 → H5 顺序做分档实验——这张"崩溃率 × 钩子档位"表本身
   就是论文里"方法可靠性"一节可用的材料。
   - **H5 的判据**：若 `--args-only=1` 能让 58 档活下来而 `--args-only=0` 崩，则崩点在**事件期的
     返回值处理/Java 对象构造/值哈希**，而不是"挂 58 个方法"本身；接下来的优化方向是让采集
     在事件期"只读参数、不构造对象"。
2. **`config.local.json` 里的真实 key 仍需你本人去吊销轮换**（DeepSeek 控制台）。该文件已被 `.gitignore` 覆盖，但**历史提交里是否曾入库未核查**（需要 `git log --all -- mobile/ai/config.local.json` 与必要时 scrub 历史）。
3. **CI / pre-commit 仍未在本机实际执行过**。仓库已推到 Gitee（`git@gitee.com:mao-yuqi-12/mobile-app-permission-check.git`，main），`.github/workflows/ci.yml` 已入库；要真正生效还需要两步：① Gitee 侧开 Actions（或改推 GitHub）并配 runner；② 本机 `pip install pre-commit && pre-commit install`。
   - ⚠️ **本机直接开 pre-commit 会炸**：`.pre-commit-config.yaml` 里挂了 `ruff-format`，而全仓有 **293 条** `ruff check` 存量问题、且代码风格（单引号等）与 `ruff-format` 的默认不一致。一旦 `pre-commit install`，git 钩子会把改动文件重新格式化，产生与存量风格断层的大 diff。**要开之前先决定**：要么先做一轮"冻结 + 全仓 format"再启用，要么把 `ruff-format` 从钩子里摘掉只留 `ruff`（本轮采取的是后者：只保证改动文件过 `ruff check`，不动格式）。
4. **300 行守卫现在只会拦下 6 个文件**（批次 5 已拆 5 个，见 §5.5 与 §4.10）。
   剩下这 6 个是设备验证主链路，**用户已明确选择等 A1 修好再拆**——A1 没修之前动采集/编排/报告主链路，
   风险不对等（拆错了会同时失去"能定位 A1"的能力）。
5. ~~**`mobile/report/report_common.py:19` 还有第三份字体候选表**~~ —— **批次 5 已处理**：
   不把候选表下沉到 `core`（那会让内核承担表现层职责），而是**保持两份副本 + 加 `VSCAN_CJK_FONT` env 覆盖口**
   （`os.environ["VSCAN_CJK_FONT"]` 会被插到候选表最前面，实测 `首候选: ('CustomCJK', 'X:/custom.ttf')`）。
   这样两份表即使顺序漂了，换机也能不改代码救场；**顺序本身仍靠人工保持"同序同项"**，
   `report_common.py` 里已加注释指回 `vehicle/analyze/report_extras.py`。
6. **`sqlite` 只读连接的 URI 编码只改了 `core/rules_contract.py` 一处**。`vehicle/dashboard/dashboard.py`、`vehicle/workbench/static_rules.py`、`mobile/analyze/correlate_mobile.py:56`、`mobile/ai/evidence_bundle.py` 里还有同类 `f"file:{p}?mode=ro"` 写法，属同一风险。本轮按"小而准"只改了规格点名的那处（顺带 `rules_db_meta` 合并让 `report.py` 间接受益）。
7. ~~**`uid_sampler.py` 的改动没有离线用例覆盖**~~ —— **批次 5 已补**：新建
   `core/collector/test_uid_sampler.py`（12 例），已挂进 `run_regressions.py` 的 `collector` 组。
   覆盖：adb 非 0 退出算失败、超时/`OSError` 保留非空 reason、`measure_clock_offset_ms()` 抛 `AdbError`
   而不是返回 0、设备时间不可解析算失败、中位数取样与毫秒单位、`package_for()` 失败**不写缓存**、
   `package:` 行首命中优先且命中后不再调 adb（`fake.call_count == 1`）、无包名行是 `None` 而非失败、
   `/proc/net/tcp` 行解析、非 TCP 行忽略。
8. ~~**文档漂移还有一处未改**：根 `CLAUDE.md:103` 也写着"10 组回归"~~ —— **批次 4-B 已一并修正**：`CLAUDE.md` 的"10 组 / 16 项"、`AGENTS.md` 的"11 组 / 21 项"、`mobile/CLAUDE.md` 的"21 项（路径写成 `tools/`）"全部改成当前实际的 **12 组 / 22 项**，并在 `AGENTS.md` 补了一句"看到红先确认解释器依赖"。
   - **批次 5 又改了一轮**：`12 组 / 22 项` → **`13 组 / 23 项`**（`AGENTS.md`、根 `CLAUDE.md`、`mobile/CLAUDE.md`、
     `.github/workflows/ci.yml` 的 step 名四处同步，并把 `event-store` 补进套件枚举）。
9. **仓库卫生**：450 个跟踪文件混入产物/证据（规格 B-5 低优先级，属批次外的独立整理），建议单独一轮处理，不要和代码修复混在一起提交。
10. **`run_regressions.py --mobile` 开关仍未加**（§8.2 B-6 的一项）：根入口与移动侧入口现在是两条独立命令，
    没有"一条命令跑全部"的方式；CI 里也是两个 step。加一个 `--mobile` 让根入口顺带跑移动侧是个小改动，
    但会让"根回归全绿"这句话的含义变模糊（移动侧失败算不算根回归失败？），所以需要你定一下语义再动。
11. **一条方法论教训（本轮的真正收获）**：`RESEARCH_OUTLOOK.md` 的状态列**曾经严重滞后**——
    本轮逐条对代码复核 29 项，**24 项 + A6/A7/A8 其实早在批次 1–3 就落地了**，只是没改状态文字。
    这正是"信任文档陈述"的代价：如果照状态列去"修"，会重复劳动甚至把已修的东西改坏。
    该文件顶部已加警告（「**不要相信这一列，要相信代码**」），状态列也已按复核结果刷新为
    `【已修】`/`【已修·部分】`/`【已修·待设备验收】` 三档，并保留 `【规划】` 给真正未动的条目。
