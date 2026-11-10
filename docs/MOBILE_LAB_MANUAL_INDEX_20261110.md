# `mobile/lab/` 单跑手册与判定口径（2026-11-10）

配套盘点：[ZOMBIE_TESTS_20261110.md](ZOMBIE_TESTS_20261110.md)（现行口径 **209 个测试文件 / 202 个被三个 runner 之一引用 / 7 个白名单登记**；
盘点第一版的「207 个 / 172 有调用方 / 35 无」是**错的**，漏了 runner 内的 `unittest discover` 规则与 f-string 模板，勘误见该文档开头）。

> **2026-11-10 第二、三轮更新：这 24 个已全部并入 `run_mobile_checks.py`（37 → 61 项），
> 再追加 1 项测试清单守卫（61 → 62 项，`tools/test_inventory_guard.py`）；同日并发线又并入
> `observed_surface` 一组，现行 **63 项**（两次连跑 63/63），
> 不再是「无调用方」。本文保留逐文件单跑命令，用于**排查单个失败**（跑全套 33 s，单跑 0.1–0.7 s）。

## ⚠️ 先读：两个会让"绿变红"的假阴性

**1) 不要给命令加 `2>&1`。** `tools/python313.ps1` 顶部是 `$ErrorActionPreference = 'Stop'`，
把原生命令的 stderr 合并进管道会被 PowerShell 当成终止错误；而 `unittest` 的进度点、
`Ran N tests`、`OK` **全部写在 stderr**。结果：测试明明通过，PowerShell 也以退出码 1 结束
（`NativeCommandError`）。**直接跑、不重定向**。实测对照：

```powershell
.\tools\python313.ps1 -m unittest mobile.lab.test_compat_control            # Ran 6 tests ... OK
.\tools\python313.ps1 -m unittest mobile.lab.test_compat_control 2>&1 | ...  # 同样 OK，但 EXIT=1
```

**2) runner 内部不存在这个问题（已核对）。** `run_mobile_checks.py` 的 `run()` 用的是
`subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, ...)`——stdout 与 stderr **分开捕获**，
判据只有 `proc.returncode`；既没有 `stderr=subprocess.STDOUT`，也没有 `shell=True`，
**不经过 PowerShell**。因此 PowerShell 的 `$ErrorActionPreference` / 管道语义**污染不到**它判定的
`exit_code`。唯一的污染入口是人在命令行上自己加的 `2>&1`（会把整个 runner 的退出码变成 1，
而 `verification.json` 里其实是 `"passed": true`）。判绿只看 `verification.json` 的
`passed` / `failed`，不看命令行退出码是否被这一步带偏。

## 0. 判定口径

**「放进目录」不等于「会被执行」。** 本仓库的自动执行路径只有三条，全部是显式清单：

1. `tools/run_regressions.py`（18 组；`--mobile` 为 19 组）
2. `mobile/tools/run_mobile_checks.py`（**63 项**）
3. `tools/check_mobile_branch.py`（24 组）

仓库**没有** `pytest.ini` / `pyproject.toml [tool.pytest]` / `tox.ini` / `conftest.py`，
CI 里也没有自动发现（`unittest discover` 只出现在 `check_mobile_branch.py` 内部的显式目录规则里）；
`.github/workflows/ci.yml` 只调
`run_regressions.py --prepare --mobile`，`Jenkinsfile` 无测试步骤，`.pre-commit-config.yaml`
只跑 ruff 与行数守卫。因此：

> **一个 `test_*.py` 只要没被上面三个清单里的模块名引用，就没有任何自动执行路径**——
> 它在 PR、CI、提交钩子里都不会跑。是否「有价值」与是否「被执行」是两件事。

这正是本目录 24 个文件的病史：它们长期被当作「设备/真机实验，设计上就是手动跑」，
实测却 **24/24 纯离线**（mock adb/APK/网络，227 用例 7.9 秒），于是"目录身份"顶替了
"执行路径"——没人收集，就永远没人发现它们其实跑得动。

### 0.1 测试清单守卫：让这件事再也漏不过去（第 62 项）

并入 24 个文件只治了这一批，不防下一批。所以 2026-11-10 第三轮把判定做成
`tools/test_inventory_guard.py`，作为第 62 项并进 `run_mobile_checks.py`：

| 环节 | 规则 |
| --- | --- |
| 扫描 | 全仓 `test_*.py` / `test_*.mjs` / `test_*.js`，剪掉 `archive/`、`output/`、`.venv`、`node_modules/`、`.git` 的子树 |
| 引用判定 | 只认三个 runner 的 **AST**：① 字符串常量里的 `test_*` token；② f-string 模板（`f"test_{name}_model.mjs"` → `test_*_model.mjs`）；③ `-m unittest discover -s <dir> -p <pattern>`。**注释与 docstring 不算引用** |
| 豁免 | 未引用但已确认不接入的，必须在 `tools/test_inventory_allowlist.json` 逐条登记 `path` / `category` / `reason`，`reason` 少于 12 字或写「暂未接入」会被判红 |
| 判红 | 未引用且未登记（逐条打印路径，回答"这次新增了哪个"）、白名单条目已过期（文件已被引用/已不存在）、category 非法 |

单次 0.43 s（`os.walk` 剪枝，不用 `rglob`——后者会走完 `output/`，实测 27 s）。
**负向验证已做**：把 `hooks_privacy_impl` 从 runner 删掉 → 守卫立刻指名
`mobile/hooks/test_privacy_implementation.mjs` 并退出码 1；恢复 → `unregistered=0` 通过。
它上线后的第一次实战就抓到了并发新建的 `mobile/tools/test_observed_surface.py`（13:13 落盘）：
先按 `pending_evaluation` 登记，14 分钟后该文件被并入 runner，**白名单条目随即被判过期**
（`stale=1`，退出码 1），删掉即恢复绿——正向漏检与反向过期两条路都实测响过一次。

## 1. 并入方式与隔离（对应"会不会互相污染"）

**每项一个独立子进程**，不是同进程导入：

```python
for name in lab_root:      # 20 个：仓库根 + dotted module
    unit.append((f"lab_{name[5:]}", ROOT, [PY, "-m", "unittest", f"mobile.lab.{name}"]))
for name in lab_local:     # 4 个：cwd=mobile/lab + 裸模块名
    unit.append((f"lab_{name[5:]}", MOBILE / "lab", [PY, "-m", "unittest", name]))
```

因此**不存在**跨文件的模块级全局 / `os.environ` / `sys.path` / 临时目录污染：每个文件都在
全新的解释器里 import、执行、退出，进程结束即回收。这也解释了为什么两次连跑的结果完全一致
（见 §2）——没有可残留的状态，也不存在顺序依赖。

cwd 分两种是历史原因，不是设计：这 4 个文件用 `from pcap_sidecar import ...` 这类**裸兄弟
import**，cwd 必须是 `mobile/lab`；其余用 `from mobile.lab import x`，cwd 为仓库根。

## 2. 两次连跑的原始末行

```
# 第 1 遍（12:48:29）
{ "status": "passed", "out": "...\\mobile-regression-20261110-124829-3oulhbuf",
  "checks": 61, "failed": [] }
EXIT=0    SECONDS=27.7

# 第 2 遍（12:49:00）
{ "status": "passed", "out": "...\\mobile-regression-20261110-124900-zw5zplnk",
  "checks": 61, "failed": [] }
EXIT=0    SECONDS=26.9
```

两遍均 61/61、`failed: []`，**没有顺序相关或残留状态导致的偶发失败**，也没有需要上报的失败
（24 项第一次进套件就全通过，没有改任何断言）。

## 3. 耗时（哪几项超过 1 秒）

全套 63 项 **≈33 s**（加守卫后两次连跑 32.8 s / 33.7 s；其中约 28 s 花在各 `python -m unittest`
与 node 子进程上，4 项是纯断言、不启进程；`test_inventory` 守卫自身 0.43 s）。
单项超过 1 秒的只有 5 个，**全部是原有检查，没有一项来自这 24 个**：

| 检查 | 耗时 | 来源 |
| --- | --- | --- |
| `workbench_http` | 4.18 s | 2026-11-10 第一轮并入（本机 HTTP 集成，随机端口 + 线程） |
| `workbench_adapters` | 2.92 s | 2026-11-10 第一轮并入（适配器 mock + 临时目录） |
| `report` | 2.41 s | 原有（PDF 渲染） |
| `policy` | 1.51 s | 原有 |
| `analyze` | 1.23 s | 原有 |

24 个 lab 项里最慢的是 `lab_domestic_summary` **0.65 s**，其余 0.54 s 以下，合计 **7.9 s**。

## 4. 通用前置与单跑命令

```powershell
# 在仓库根 d:\AAA\mobile-app-permission-check 下执行；不要用默认 python（3.15 缺依赖）
.\tools\python313.ps1 --version
```

- **R 口径**（仓库根，dotted module）：`.\tools\python313.ps1 -m unittest mobile.lab.<文件名>`
- **L 口径**（`mobile\lab` 目录，裸模块名）：
  `Set-Location mobile\lab; ..\..\tools\python313.ps1 -m unittest <文件名>; Set-Location ..\..`

**统一成功判据**：退出码 `0`，且 stderr 末尾两行是

```
Ran N tests in X.XXXs
OK
```

`N` 必须等于下表「用例」列的数字；若出现 `OK (skipped=…)`、`FAILED (…)` 或 `N` 变小，
都算**没通过**（skip 说明环境变了，不是通过）。「耗时」是本机实测墙钟（含解释器启动）。

失败排查顺序：① 是否用了 `.\tools\python313.ps1`；② cwd 是否与表中口径一致（口径错了是
`ModuleNotFoundError`，不是断言失败）；③ `-v` 看具体用例名。

## 5. 逐文件索引

### 5.1 采集/流水线编排

| 文件 | 干什么用的 | 依赖 | 口径 | 命令 | 用例 | 耗时 |
| --- | --- | --- | --- | --- | --- | --- |
| `test_core_pipeline.py` | fail-closed 编排 seam：SDK 必须匹配正式规则版本；只有 `ARMED` 的 selftest 不算可用采集；部分静态不算完整成功；可用部分来源保留 gap；静态终态必须真实；重审静态输入不复用上次 capture/network gap | 无（纯函数 + 合成 JSON） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_core_pipeline` | 6 | 0.33s |
| `test_core_compile_entry.py` | 真实 session 入口编译：导出的钩子必须在**同一个** bridge session 内被调用（防止每个模块各起一个 bridge） | 无 | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_core_compile_entry` | 1 | 0.25s |
| `test_core_task_binding.py` | 同一上传任务的续跑与有界取消：同 upload 继续；路径/字节/dex 不一致拒绝；无 jadx 与 stop 标记 fail closed；`static_snapshot` 必须证明每个原始 dex 且拒绝不完整事实 | 无（临时目录 + zip） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_core_task_binding` | 5 | 0.55s |
| `test_core_observer_start.py` | 启动窗口契约：late attach 不重启/不 resume 他人进程；目标死亡时跳过陈旧 RPC 但仍关闭证据文件；spawn 只 resume 自己拥有的 pid | 无（Mock） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_core_observer_start` | 3 | 0.24s |
| `test_compat_control.py` | 兼容性对照控制：进程存活与原始身份都必须有；`launch-only` 跳过 UI dump 但保留进程检查；ABI 选项只记录不重打包；已有安装不卸；改包或死进程不能判过 | 无（adb 全 mock） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_compat_control` | 6 | 0.27s |
| `test_enrich_risk.py` | 风险富化必须保留原始实验与原始证据文件，运行日期不被改写 | 无（临时目录） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_enrich_risk` | 1 | 0.27s |

### 5.2 root / 非 root 采集与评估

| 文件 | 干什么用的 | 依赖 | 口径 | 命令 | 用例 | 耗时 |
| --- | --- | --- | --- | --- | --- | --- |
| `test_root_runner.py` | root 一体化 runner 的边界：设备/数据集访问前必须有授权；USB serial 在任何设备命令前拒绝；非 root 环境拒绝 profile；已有包不替换不卸载；静态失败不安装；已装身份不符失败且只清自己装的；spawn/observer 失败仍卸载自有包；trigger/probe/脚本错误都不能算 `observed` | 无（adb/APK/进程全 mock） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_root_runner` | 18 | 0.45s |
| `test_root_assessment.py` | root 加密外泄评估的边界：裸 AES 不解（重复 token 也不算）；ECB 需显式事实；解密失败/截断不算加密；跨包 session 不计数；CBC 重复指纹不升级成「永久常量」；socket 需同声明 payload 端点 + pcap；被拒 stream 是拒绝控制不是暴露 | 无 | L | `Set-Location mobile\lab; ..\..\tools\python313.ps1 -m unittest test_root_assessment; Set-Location ..\..` | 19 | 0.12s |
| `test_root_tcp.py` | 有界 TCP 重组：按字节重组；乱序/重传/相同重叠可接受；gap、冲突重叠、序号回绕、header 截断、尾巴截断一律 `unsupported` 且不拼接；新 SYN / RST 分隔连接代；UDP 不产出 TCP stream | 无（合成包） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_root_tcp` | 17 | 0.31s |
| `test_nonroot_capture.py` | 非 root 采集契约：原始静态与插桩运行时身份必须分开；已有应用不替换；真实应用不许运行时权限预授（只有自有 fixture 可以）；VPN 正向控制要目标传输包而不是 pcap 元数据；清理/钩子缺失 fail closed；卸载失败不能发布 done | 无（假 adb） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_nonroot_capture` | 13 | 0.49s |
| `test_nonroot_traffic.py` | 非 root VPN 状态/导出契约：未请求的抓包不能报成「全部流量」；未确认 start 保留 gap 且不编造导出；stop 要等真实 `stopped` 才导出；Gadget 连接不能在应用启动前打开 | 无 | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_nonroot_traffic` | 5 | 0.32s |
| `test_nonroot_vpn_identity.py` | VPN 进程身份解析：精确包名（非子串、非重复包）；uid 当前匹配 vs 陈旧 mismatch；network capabilities 的 inline owner uid 不污染目标范围；uid 范围不得推断成包身份；其他用户/其他 VPN/新语法保持 `unknown` | 无（合成文本） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_nonroot_vpn_identity` | 5 | 0.11s |
| `test_pcap_sidecar.py` | 设备侧抓包 sidecar 的 adb 命令/结果契约：授权包名就是精确 capture filter；`am` 成功不代表 capture 在跑；service+VPN 才算 running；零字节文件永不过 pull；其他应用的陈旧 tunnel 不算证据；stop 只走 control action 并观察 `stopped` | 无（adb 全 mock） | L | `Set-Location mobile\lab; ..\..\tools\python313.ps1 -m unittest test_pcap_sidecar; Set-Location ..\..` | 24 | 0.15s |

### 5.3 UI 触发 / 设备传输面

| 文件 | 干什么用的 | 依赖 | 口径 | 命令 | 用例 | 耗时 |
| --- | --- | --- | --- | --- | --- | --- |
| `test_core_capture_ui.py` | 权限弹窗处理：AOSP 与 Google 两套控件变体；`launch-only` 不连 uiautomator；legacy review 只认已观测前台 + display；第三方同名资源不算系统权限；API<31 用 endpoint 替换文本 | 无（合成 XML） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_core_capture_ui` | 6 | 0.18s |
| `test_nonroot_capture_ui.py` | 非 root UI 触发编排：ECB 原始/备用 resource id；缺按钮在触发前失败；disabled 不点；外部控件不算命中；Ghera 包名不符在 UI 操作前拒绝；存档证明是「动作」而非宣称加密成功 | 无 | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_nonroot_capture_ui` | 9 | 0.25s |
| `test_readyou_ui.py` | 观测 RSS 控制与本地目标：collectors 同 session 但不同尝试 id 不同；local origin 拒绝意外 host/port/凭据；控件必须属于原始 ReadYou；订阅只用公开本地 feed 与 UI | 无 | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_readyou_ui` | 4 | 0.24s |
| `test_probe_transport.py` | 自有 fixture 的传输面控制：默认端点兼容；LAN 必须显式 host 且只绑该 IP；无 UDP 的 USB 是显式 partial；拒绝 wildcard/multicast/broadcast；LAN SAN 与 asset 绑同一证书；startup 重试有 deadline 且不吞无关错误 | 无（网络全 mock） | L | `Set-Location mobile\lab; ..\..\tools\python313.ps1 -m unittest test_probe_transport; Set-Location ..\..` | 24 | 0.55s |
| `test_validate_network.py` | 端点控制汇总：只有服务端回执没抓包、只有抓包没回执、错 marker、意外 https 明文、缺 UDP 都算失败；物理 VPN 上下文移除已覆盖 gap；未知上下文拒绝 | 无 | L | `Set-Location mobile\lab; ..\..\tools\python313.ps1 -m unittest test_validate_network; Set-Location ..\..` | 11 | 0.22s |
| `test_sdk_hook_scope.py` | SDK 钩子作用域：精确「类 + 方法 + 描述符」交集；错误 SDK API 在提取签名前拒绝；未知提取失败不算「不支持」豁免；原始规则版本与 SDK unsupported 分别记录 | 无（合成签名） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_sdk_hook_scope` | 4 | 0.26s |

### 5.4 PCAP / JSONL 解析

| 文件 | 干什么用的 | 依赖 | 口径 | 命令 | 用例 | 耗时 |
| --- | --- | --- | --- | --- | --- | --- |
| `test_pcap_cooked.py` | Linux SLL（cooked header）PCAP：IPv4 TCP marker 与两种字节序；IPv6 UDP 与接口元数据；截断 cooked header 仍保留记录并计数；不支持的 ethertype 保留接口但不假造载荷 | 无（合成字节流） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_pcap_cooked` | 6 | 0.14s |
| `test_jsonl_unicode.py` | 只按物理 LF 分行的 JSONL 读取与采集收尾：U+2028/U+0085 留在 JSON 字符串内（LF/CRLF 两种）；坏记录按物理行号计数；坏 flows/reads/pcap-summary 各自保留 failed verification 与 unknown 计数 | 无 | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_jsonl_unicode` | 7 | 0.40s |

### 5.5 国内正式评审（离线来源选择与汇总）

| 文件 | 干什么用的 | 依赖 | 口径 | 命令 | 用例 | 耗时 |
| --- | --- | --- | --- | --- | --- | --- |
| `test_domestic_formal.py` | 正式评审的来源选择与批量上限：0 读取的通过采集只算「可选取」不算安全结论；失败/空 checks 阻断；哈希或设备不符不接受；后续失败不掩盖先前完整采集；plan 阶段不加载配置、不起模型 worker | 无（不发模型请求） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_domestic_formal` | 10 | 0.52s |
| `test_domestic_static.py` | 静态标志解析与下载账本：显式 flag 不误认子元素；未设置/资源引用算 `unknown` 而非安全；缺失或重复 `application` 仍 `unknown`；别的命名空间不定义 android flag；超时保留 manifest 标志且不宣称已扫描 | 无（不装 APK、不执行） | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_domestic_static` | 13 | 0.31s |
| `test_domestic_summary.py` | 汇总索引选择：哈希不符不借同包别的记录；更新的失败不掩盖完整采集；最新失败只带自己的读取数；空 checks/缺原始文件不算成功；未知风险不变 0、无正式结果算 `unknown`；伪改标签过不了三段校验 | 无 | R | `.\tools\python313.ps1 -m unittest mobile.lab.test_domestic_summary` | 10 | 0.65s |

## 6. 变化对照

| 文件 | 盘点时 | 第一轮后 | 现在（第二轮后） |
| --- | --- | --- | --- |
| `mobile/workbench/test_adapters.py` | 无调用方（只被 import） | ✅ 有调用方 | ✅ `workbench_adapters` |
| `mobile/workbench/test_http.py` | 无调用方（只被 import） | ✅ 有调用方 | ✅ `workbench_http` |
| `mobile/audit/test_cipher_storage.py` | 无调用方（只被 import） | ✅ 有调用方 | ✅ `audit_cipher_storage` |
| `mobile/lab/test_pcap_inventory.py` | 无调用方（只被 import） | ✅ 有调用方 | ✅ `lab_pcap_inventory` |
| `mobile/lab/test_core_capture.py` | 无调用方（只被 import） | ✅ 有调用方 | ✅ `lab_core_capture` |
| `mobile/hooks/test_privacy_implementation.mjs` | 无调用方 | ✅ 有调用方 | ✅ `hooks_privacy_impl` |
| 本文 §5 的 24 个 | 无调用方 | ❌ 仍无调用方 | ✅ 全部并入（`lab_*` 前缀，20 个 R 口径 + 4 个 L 口径） |

`mobile/lab/` 现有 **27 个测试文件全部有调用方**（`domestic/test_fetch.py` 由
`check_mobile_branch.py` 收集，其余 26 个由 `run_mobile_checks.py` 收集）。

## 7. 维护约定

1. 往 `mobile/lab/` 新增测试时，**必须**同步本文档并在 `run_mobile_checks.py` 的
   `lab_root` / `lab_local` 里登记，否则它默认不会被执行。
2. 新增项如果是裸兄弟 import（`from x import ...`），cwd 必须是 `mobile/lab`，
   加进 `lab_local`；否则加进 `lab_root`（dotted module）。
3. 判据只认 `Ran N tests` + `OK` 两行，不接受「跑完没报错」「输出看起来正常」。
