# Mobile — 移动 App 隐私数据泄露的智能化检测与合规评估

**仅用于授权测试（已获授权的样本与设备）。**
面向第九届浙江省大学生网络与信息安全竞赛企业命题（浙江省质量科学研究院）。

车载 vehicle/ 是已交付成果，本目录**不改动它**；通用部件以 import 复用（见下表）。
决策见 `DECISIONS.md`（M001– ），全局约束沿用根 `CLAUDE.md`。

## 目录

| 路径 | 作用 |
| --- | --- |
| `rules/` | **规则库**：schema v2 + 法规依据 + android.jar 签名抽取 + 构建器 |
| `rules/regulations/` | 法规原文（认定方法 / 必要信息规定 / 个保法 / GB-T 35273），带条款号与 URL |
| `hooks/` | Frida 钩子：敏感 API 读取 + 同意时序 + TLS 校验收宽（Java 层 pinning 绕过）+ **内存 Hook（native TLS / JCE / native 应用层加密明文 + SNI/keylog）**，全部随 `hook_all` 单 agent 挂载。native 覆盖到哪、到哪为止，见「能力边界」段 |
| `traffic/` | mitmproxy 移动适配：打标表 + 注入壳（复用 core/collector/addon.py）+ 透明代理（transparent.py） |
| `policy/` | 隐私政策获取 / 正文抽取 / 规则化检查；`policy_discover.py` 按「隐私词 / 协议词」分流（`doc_kind`），《用户协议》进 `app_agreements` 而不冒充主政策（M040） |
| `analyze/` | 关联引擎与八种移动谓词（复用 core/evidence/codeloc.py 的行号链）；**风险量化** `risk_score.py`（四维乘积 + 重复衰减 + 正交置信度，v1.3，模型见 `RISK_SCORE_MODEL.md`、阈值标定 `calibrate_risk_bands.py`）；静态/动态覆盖差集 `coverage_gap.py` |
| `ai/` | **证据打包 + 三阶段提示词 + LLM 客户端 + 输出校验**；打包时顺带做 APK 加固特征探测，命中即写入 gaps（结论受限） |
| `report/` | PDF 报告（工具结论 + AI 研判 + 校验问题清单） |
| `tools/` | 离线回归总入口、合成演示会话生成器、设备跑批；**完整报文链路** `pcap_capture.py`（设备端 tcpdump，只能 `su 0` 用）、`pcap_http.py`（keylog + `tshark` 重组）、`flutter_probe.py`（剥符号 BoringSSL 静态探测） |
| `workbench/` | 隐私审计工作台（工作流 / 运行时导入 / 合并布局 / 一键审计，带独立测试）；自带前端 `workbench/frontend/` |
| `pipeline/` | **一键审计流水线**：16 阶段定义 `stages.py`、执行器 `runner.py`、HTTP+SSE `server.py`；前端在根 `frontend/`。默认 **8771**（`workbench/server.py` 默认 **8772**，两套可同时起），见根 `README.md` |
| `fixture-app/` | 自有靶子 App（隐私演示），用于端到端验证 |

## 怎么跑（离线优先，不需要设备）

```bash
PY="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"

# 1) 规则库（从本机 android.jar 抽签名，这是 source_verified 的唯一来源）
cd mobile/rules
"$PY" extract_android_apis.py                      # → build/api_facts.jsonl
"$PY" extract_android_apis.py --seed seed/consent_targets.json --out-prefix consent_
"$PY" build_mobile_rules.py                        # → rules_mobile.db
cd ../hooks && "$PY" gen_targets.py && node build.mjs   # 生成监视表 + 打包钩子

# 2) 离线回归（全部）
"$PY" mobile/tools/run_mobile_checks.py            # → output/mobile-regression-*/

# 3) 端到端干跑（合成会话，验证字段契约）
"$PY" mobile/tools/make_demo_session.py --out /tmp/demo
"$PY" mobile/analyze/correlate_mobile.py --session /tmp/demo --package com.vscanner.privacydemo \
      --permissions /tmp/demo/requested-permissions.txt --app-category map_navigation \
      --out /tmp/demo/findings.jsonl --summary /tmp/demo/summary.json
"$PY" mobile/ai/evidence_bundle.py --session /tmp/demo --findings /tmp/demo/findings.jsonl \
      --package com.vscanner.privacydemo --app-category map_navigation --out /tmp/demo/bundle.json

# 4) AI 研判（先 dry-run 审阅，再填 key 真跑）
"$PY" mobile/ai/ai_review.py --bundle /tmp/demo/bundle.json --out-dir /tmp/demo/ai --dry-run
cp mobile/ai/config.example.json mobile/ai/config.local.json   # ← 在这里填 api_key
"$PY" mobile/ai/ai_review.py --bundle /tmp/demo/bundle.json --out-dir /tmp/demo/ai

# 5) 报告
"$PY" mobile/report/report_mobile.py --bundle /tmp/demo/bundle.json \
      --ai-out-dir /tmp/demo/ai --out /tmp/demo/report.pdf
```

## 复用关系（不复制、不漂移）

| 复用对象 | 方式 |
| --- | --- |
| `core/collector/addon.py`、`attribution.py`、`flow_entry.py`、`payloads.py` | 直接 import；`traffic/addon_mobile.py` 通过 `VSCAN_TAGGING` 注入移动打标表 |
| `core/frida_host/run.py`、`bundle_config.py` + `dist/` 共享 bundle（hook_egress / ssl_pinning_bypass） | 原样使用（Socket.connect 与车载无关；run.py 的注入器替换 `__VSCAN_SESSION_PACKAGES__`） |
| `core/evidence/codeloc.py` | 直接 import，`evidence_kind` 沿用同名种类（`read_event` / `read_then_egress`） |
| reportlab 中文字体方案 | 照抄 `vehicle/analyze/report.py` 的候选链（SimHei → DengXian → 雅黑 → STSong） |
| 输出约定 | `output/mobile-regression-*/verification.json` + `latest-mobile.txt`，与车载一致 |

## 本目录的坑（全部实测）

- **签名绝不手写**：所有 API 签名由 `javap -s` 从本机 `android.jar` 抽取。
  抽不到的落 `build/api_missing.json` 作为探测 TODO，**不编造**。
  （照抄 core/static 的 `(class_name, method_name, jvm_descriptor)` 三元组口径。）
- **npm 装依赖必须跳过原生编译**：`frida-compile` 依赖 `frida` 包的原生绑定，
  本机没有 make，`npm install` 会失败。绕过办法是**直接复用 vehicle/hooks 已装好的
  `node_modules`**（同一套依赖，绑定已构建）。
- **`/tmp` 在 Git Bash 与 Python 眼里不是同一个目录**：Bash 会把**实参**里的
  POSIX 路径转成 Windows 路径，但脚本正文里的字符串不转——`python -c` 里的
  `/tmp/x` 会落到 `C:\tmp\x`。写脚本一律用真实路径。
- **形态标签不能定性**：15 位数字分不出 IMEI 与 IMSI，`digit15_shape` 的
  data_type 是 `None`（故意的）。只凭形态**不得**产出任何数据类别结论；
  要定性必须有值哈希匹配。这条是设计，不是缺陷。
- **同意时序缺失时「同意前收集」不可判定**：`consent.jsonl` 为空时该谓词
  不产出结论（进 gaps），不把"没采到"当成"没同意"。
- **部分授权必须逐条用**：`PERM_RESULT` 里 granted/denied 是逐权限的；
  被拒的权限不算同意，否则判定会反过来。
- **值哈希口径两侧必须一致**：钩子（Java MessageDigest）与打标（Python hashlib）
  都是 `UTF-8 + sha256 前 16 位十六进制`。变了要同步改两边，否则值级匹配静默失效。
- **构建失败不得留下半成品 DB**：`build_mobile_rules.py` 任何异常都清理输出——
  半成品与成功产物在文件系统上长得一模一样。
- **第三方 App 抓不到流量先查透明代理**：不少 App（如 loopj/AsyncHttpClient）无视系统代理设置，
  `emulator -http-proxy`（SLIRP 层强制代理）才对它们有效。`traffic/transparent.py` 只负责
  算出启动参数 + 装系统 CA，不在设备上跑 `iptables REDIRECT`——代理跑在宿主机时
  `SO_ORIGINAL_DST` 查不到原目标，那条路不通（见 transparent.py 顶部说明）。
  （补充实测：强制抓包与设备全局代理**可并存**，SLIRP 会把"连到 10.0.2.2:8888"的连接
  照送到宿主 127.0.0.1:8888，不是自环，见 M030。）
- **设备端一切 adb 调用都要显式 `ANDROID_SERIAL`**：宿主机上常年有第二台模拟器
  （Android Studio 的 Medium_Phone）。裸 `adb` 在多设备下**静默返回空串**，于是
  "查不到进程"被当成"进程已死"、"读不到日志"被当成"没有崩溃"。`device_guard()`
  在批次/单样本入口做启动前拦截（M027）。
- **模拟器要压掉 UWB HAL 崩溃循环**：ranchu 镜像的 `vendor.uwb_hal` 找不到 `/dev/uwb0`，
  每 5~10 秒 abort 一次，几十秒就把 crash 缓冲刷一轮、把样本自己的 tombstone 挤掉。
  `start_emulator.py` 里已加 `stop vendor.uwb_hal`（幂等，按"进程是否消失"验证）。
  注意：**框架重启（`stop`/`start`）后要复查它是否复活**。
- **子进程必须 `PYTHONUNBUFFERED=1`**：采集类子进程（mitmproxy / frida / conn_probe）
  结束时用 `taskkill /F` 收树，**未落盘的 stdout 缓冲会整块丢掉**——表现为日志 0 字节，
  看起来像"压根没启动"。三个 start_* 都已埋此变量。
- **启动 Activity 以设备侧为准，不信 aapt2 badging**：F-Droid 的 manifest 有两个
  LAUNCHER，aapt2 取到的是伪装的 `org.fdroid.fdroid.panic.CalculatorActivity`，
  而该类已被 R8 裁掉 → `am start` 报 "Activity class does not exist"（结果码 -92）。
  统一用 `cmd package resolve-activity --brief -c android.intent.category.LAUNCHER`，
  badging 仅作回退，并把两个来源都写进 `main-activity.log`。
- **插桩打死应用（A1）已修：bridge 补丁 + 单 agent**（2026-10-16，两层根因：
  JNI transition ref 上游 bug + 多脚本各自替换不被 bridge 支持；见 M031/M032 与
  DEV_FIX_REPORT §5.1）。**"关 JIT"这条路已被双向证伪、不要再走**：
  `setprop dalvik.vm.usejit false` + 框架重启**无效**（zygote 与 app 进程的
  `/proc/<pid>/task/*/comm` 里仍有 `Jit thread pool`），`-prop` 也被 37.x 拒绝
  （只接受 `qemu.*`）。诊断时优先拉 `/data/tombstones/`（需 `adb root`）——文本
  tombstone 比 logcat 的 crash 缓冲完整得多。
- **模拟器抓包两个硬前提**（2026-10-16 实测，M032）：① `-http-proxy` 必须传
  **宿主侧地址 `127.0.0.1`**——emulator 37.x 从宿主进程探测代理，传 guest 别名
  `10.0.2.2` 宿主不可路由 → 探测必超时 → 打印 "Proxy will be ignored!" 并把
  SLIRP 强制重定向整条关掉（表现为：只有读设备侧 http_proxy 的组件能抓到，
  直连流量全漏）；② **代理必须先于模拟器进程存在**（探测只在启动那一刻做、
  失败不重试），冷启动路径由 pipeline 的 `_start_early_mitm` 保证。排障第一步：
  看 `emulator.log` 里有没有那句 "Proxy will be ignored!"。
- **抓包强制性的现场复验（2026-10-16 下午，M033）**：`mobile/tools/verify_force_proxy.py`
  ——前置 mitm → 冷启动 → **等网络就绪** → `settings put global http_proxy :0`
  彻底禁系统代理 → raw socket 三测。已实测（系统代理全禁的极端条件）：A `nc -4`
  直连域名被捕获；B 直连 TEST-NET-3 不可达 IP 收到 **mitmproxy 自己的 400 页**
  （"no host header"，铁证）；C UDP 到宿主 **直出、不经代理**——这是 `-http-proxy`
  的边界（它只重定向 TCP），**不是** UDP 不能被拦：常规采集链路已改为在设备侧
  `iptables -I OUTPUT -p udp --dport 443 -j DROP` 逼 QUIC 回退 TCP（见 §能力边界）。**boot 完成 ≠ 网络就绪**（eth0
  DHCP 实测还要等 36s / 106s 两轮），过早测试全是 "Network is unreachable" 假阴性——
  本工具内置网络等待，同源探测勿在别处绕过。

## 阳性对照：夹具 App（**读数为零时的第一件事**）

`mobile/fixture-app/`（`com.vscanner.privacydemo`）有 10 个按钮，覆盖设备标识 / 位置 /
通讯录 / 应用列表 / 剪贴板 / 短信 / 明文外发 / HTTPS 外发 / 权限 / 政策。

```
python mobile/tools/device_run.py --seconds 120           # 全链路（装夹具→钩子+代理→触发→关联→证据包→报告）
python mobile/tools/trigger.py --package com.vscanner.privacydemo --button btnDeviceId
```

**实测结论（2026-10-13 现场；2026-10-16 已修复——保留作判据设计依据）**：夹具 12 个按钮**全部命中**且带真实结果
（`line1=+15551234567`、`installed_apps=270`、三个权限 GRANTED），但 `reads.jsonl`
**一条事件都没有**——钩子日志停在 `armed 58/58 apis; failed=0`。最小化实验复现：
钩子 attach 到 pid X → 按 `btnDeviceId` → **X 当场消失**（SIGABRT，`abort message`
是一条内存映射行，2 帧栈）；**同夹具同按钮不挂钩子则全程健康**（pid 稳定 +30s、
crash 缓冲 0 行）。

→ **`armed` ≠ 能捕到**——这条判据设计依据至今成立。**A1（58 钩子打死应用）已于
2026-10-16 修复**（根因 = JNI transition ref 上游 bug + 多脚本替换不被 bridge 支持；
修复 = bridge 补丁 + 单 agent，见 M031/M032）。此结论的两个保留用途：

- 读数为零**不得**先归因成"该应用没有收集"；先跑夹具自检，再按 M030 的三类拆
  （采集缺陷 / 能力边界 / 样本行为）。
- 这条与 M016「钩子必须自证挂载成功」是两层：挂上 ≠ 生效。修复史与分档实验归档
  见 `DECISIONS.md` M031/M032、`DEV_FIX_REPORT.md` §5.8/§5.9 与 `D:/vscanner-tp/a1-scan/`。

## 状态（2026-10-03，计数更新于 2026-10-13）

规则库（223 条规则 / 8 种类型 / 58 个 android.jar 实证 API / 28 类数据 /
39 类 App 必要信息 / 16 条政策条款）、移动钩子（敏感读取 + 同意时序）、流量打标
（含值哈希令牌）、隐私政策三件套（获取 / 抽取 / 检查）、关联引擎（八种谓词）、
AI 三阶段研判（含编造校验）、PDF 报告（十章 + 三附录）、自有靶子 App 与设备端端到端
均已实现。离线回归 **24 组**全过（`mobile/tools/run_mobile_checks.py`）；
分支全量（含 workbench/policy/AI/前端契约）**22 组**见 `tools/check_mobile_branch.py`。

**2026-10-13（外部评估核对后的落地，见 [EVAL_CROSSCHECK.md](EVAL_CROSSCHECK.md)、DECISIONS M021–M025）**：
- 覆盖守护：每个数据类别要么有 API 抓手、要么显式声明 `uncovered_by_design`（构建期断言）。
- 补 `ip_address` 抓手 + 新增 `camera_capture` / `microphone_capture` / `screen_capture` /
  `biometric_data` 四类高敏数据类别（47 → 58 条签名，`api_missing` 仍为 0）。
- 规则覆盖矩阵报告 `tools/rule_coverage_report.py`（空格 + 空转规则可视化，并入回归）。
- APK 加固特征探测 `tools/apk_packer_probe.py` → 命中即写进证据包 gaps（结论受限）。
- 修通权限 `protectionLevel` 标定链路（原先 INSERT 根本没写这两列，是条死路）。

**第三方 App 实测（2026-10-13，5 个开源样本；平台修正见 DECISIONS M026–M028）**：
- 跑批前**必须** `export ANDROID_SERIAL=<serial>`（或保证单设备）：多设备时裸 adb
  命令全部报错，且失败形态是**静默空结果**（假"已死亡"、假"已恢复"）。
  `thirdparty_env.device_guard()` 会在启动前拦截并给出可操作的报错。
- 子进程读输出一律显式 `encoding="utf-8", errors="replace"`：本机 `PYTHONUTF8=1`
  使管道默认按 UTF-8 解码，Windows 工具（cmd.exe / mklink 等）的 GBK 输出会打死
  Reader 线程且该流变 None。
- 样本死在窗口内是**要如实记录**的结论：证据在 `app-death.json`（读 crash 缓冲、
  按时间戳分块解析，`alive_at_end` 为三态）。已知风险：本 AVD（API 37 / 16KB 页）
  上样本有概率死于 native 崩溃（疑似插桩去优化与 ART 的竞态，对照实验未做，
  不得下结论）——报告以 gaps / 判据如实呈现，不掩盖。

**设备端实测（2026-10-03，AAOS 模拟器 emulator-5554 / user 10）**：
一轮完整检测得到 26 条结论、0 缺口、七种规则全部命中——
7 条「同意前读取」、1 条值级匹配的 `data_egress`（correlated，3 对）、
3 条「政策未声明即收集」、6 条超范围收集、7 条敏感读取、1 条明文传输、1 条第三方外发。
采集侧观察到 8 类数据（其中 IMEI 因权限未授予被拒，如实记为 denied 而非收集）。
详见 `output/mobile-device-20261003-041553/`。

**未完成**：
- 时间窗 30000ms 是**声明值，尚未由移动夹具校准**（`WINDOW_CALIBRATION.md` 待建）。
  E2E 已能量出真实的"读取→外发"间隔分布，下一步据此校准。
- 权限 `protectionLevel` 40 条全部未断言（链路已修通，产出步骤见
  `rules/calibration/README.md`；无实测数据前不得编造级别）。
- AI 阶段**已用真实 key 跑过**（keepass / camera 两次真实调用，见 §8.1 A13）：提示词渲染、
  校验逻辑与真实调用均已跑通；跨多次运行的一致性与幻觉率仍无量化数据（§2 B3 缺口未补）。
- 写入类 API（`ContentResolver.insert` 等）与覆写型服务（无障碍/通知监听）未覆盖，
  理由与前置条件见 `EVAL_CROSSCHECK.md` 第四节。

**能力边界**：加固壳不在覆盖内——`apk_packer_probe.py` 只在报告里如实标注"结论受限"，
仍**不具备**脱壳能力。**明文来源现有五条**：mitmproxy 解密（系统 CA + `-http-proxy`）、
Java 层 TLS 校验收宽（`tls_bypasses_tp.js` 三手法）、**native TLS 明文**
（`hook_native_ssl.js` 拦 `SSL_write/SSL_read`）、**native 应用层加密明文**
（`hook_native_crypto.js` 拦 `EVP_EncryptUpdate/DecryptUpdate` 与低层 `AES_*`）、
**TLS 元数据**（`hook_tls_meta.js` 取 SNI 与 keylog）。前三条 2026-10-18 接线进
`hook_all`，后两条同批加入，同一 agent 装配。native 路径是在**应用自己的 SSL / 加密栈里
读明文**，不依赖代理与证书，因此**对证书 pinning 免疫**——pinning 挡住的是"我们伪造
证书"这条路，不是明文本身。

`hook_native_crypto.js` 解决的是"TLS 之前就已加密"：SSL_write 看到的是密文，明文只在
`EVP_*Update` 的入参（加密）/ 出参（解密）。**必须过滤 TLS 记录层自己的 EVP 调用**
（BoringSSL 的 `tls_seal_record` 内部也走 EVP），否则每条 TLS 流量都会多记一条密文事件；
实现用回溯符号名 + HTTP 报文启发式双保险，实测 TLS 握手全程 **EVP 事件为 0**。
低层 AES 按 120ms/类节流、全局 800 条上限，超限记 `NATIVE_CRYPTO_DROPPED`。

`hook_tls_meta.js` 是"符号被剥"场景的旁路：`SSL_set_tlsext_host_name` 记 SNI（明文拿不到
时仍能证明"发给了谁"）；hook `SSL_CTX_new` **与 `SSL_new`** 的返回值后主动调
`SSL_CTX_set_keylog_callback`，拿标准 NSS keylog 行（`CLIENT_RANDOM` 等）。只挂
`SSL_CTX_new` 是不够的：attach 模式下 App 的上下文通常在我们挂钩之前就建好了
（实测 F-Droid 一轮有 5 条 `SSL_WRITE_PLAINTEXT` 但 keylog 为 0），所以补了
`SSL_new` + `SSL_get_SSL_CTX` 反查上下文补装，事件标 `arms:"…+ssl_new"`。
App 若在之后覆盖回调，后续连接会失效，以 `KEYLOG_INSTALLED` 是否出现为准。

**明文来源第六条：pcap + tshark（2026-10-18，M038）**。hook 拿到的是 `SSL_read/SSL_write`
的**分片**——没有连接标识、没有方向、没有边界，gzip 的是压缩字节。完整报文改由
`pcap_capture.py` 抓设备端 pcap、`pcap_http.py` 把 keylog 喂给 `tshark` 解：
TCP 重组、TLS 解密、chunked 分帧、gzip 解压**全是 tshark 做的**，我们一行重组代码没写。
产物是 `out/http_messages.jsonl` + `out/bodies/`。实测一轮解出 31 条报文
（h1=29 / h2=2），其中 h2 那条拿到 37KB 的 gzip 明文 JSON；`test_pcap_pipeline.py`
（16 条断言）把 `gzip → 明文`、h2 伪头还原、缺 pcap/未启动必须报错这几条钉死。
**必须跑两趟**：h1 用 `http.request or http.response`，h2 用 `http2.header.*`——
ALPN 协商成 h2 时前者**一条都匹配不到**，只跑一趟会误判成"没抓到东西"。
body 带 `*_truncated` 的只拿到前半截（抓包在流中途结束），报告里不能当全文用。
**keylog 覆盖率实测只有一半**（4 轮 2 成）：应用若在 agent 装载前就建好 TLS 连接，
`SSL_CTX_new`/`SSL_new` 都已过去，后装回调补不回来；本机 AVD 的 spawn 不可用
（pid 5s 消失），所以别指望 spawn 兜底。缺 keylog 时 `stats.tls_undecrypted_app_data`
会给出未解密帧数（实测 ~2000），非 0 就说明报文只是零头——这时 `http_messages_extracted`
判失败，不是通过。
`/system/bin/tcpdump` 在测试 AVD 上是预装的（4.99.6），但 SELinux 只允许 `su 0` 执行——
能力探测也必须以 root 身份做，否则会得到"设备上没有 tcpdump"的假阴性。

**Flutter / 静态剥符号 BoringSSL：已从覆盖外移入（M039）**。`hook_flutter_ssl.js` 不靠
符号，靠**代码形状**：`ssl_crypto_x509_session_verify_cert_chain` 的第一条语句是
`*out_alert = SSL_AD_INTERNAL_ERROR`（0x50），x64 上是 `c6 02 50` + `48 8b af`；
从这个锚点回扫 10~14 字节拿到序言，`Interceptor.attach` 后 `retval.replace(1)`。
静态侧 `flutter_probe.py` 给出同一偏移，两路互相印证（LocalSend 1.18.2 x64：
`va=0x8113ee`，运行时日志一致）。**但这只绕过证书校验**：Dart 的 `HttpClient` 不读
Android 系统代理，"装系统 CA + 设 http_proxy"对 Flutter 无效，拿明文还需要把 443
用 iptables 引到 mitmproxy 透明模式——本仓库尚未实现，所以 Flutter **仍无明文样本**。
另外 `Memory.scanSync` 不能整模块扫（跨度里有未映射空洞，一次 access violation 就让
整次扫描归零、伪装成 `FLUTTER_SCAN_MISS`），必须按 `Process.enumerateRanges('r-x')` 逐段扫。

覆盖边界：只覆盖**导出了**相应符号的模块。实测 conscrypt（`libjavacrypto.so`，同时导出
SSL 与 EVP/AES 两套）与 `libssl.so`/`libcrypto.so` 可截（F-Droid 索引刷新一轮记到 1003
条明文）；**符号被剥/内联的静态 BoringSSL（部分 Cronet 构建）与 Flutter（`libflutter.so`
自带 BoringSSL）由 `hook_flutter_ssl.js` 按代码形状处理（见上，只到"绕过校验"为止）**；
RN 走 OkHttp/Java 栈、WebView 走系统网络栈，由既有 Java 钩子 + mitmproxy 覆盖。
不经 JCE 也不走 EVP/AES 的自研算法（XOR、字节置换）仍在覆盖外。**库晚加载**：attach 时
SSL 库常尚未 dlopen，仅靠 `dlopen` 重扫实测不可靠（`dlopen` 在各模块解析到同一地址，
无法区分 linker 实现与 PLT 转发），已加 2s 低频轮询兜底（`RESCAN_HOOKED` 带
`how:"poll"`），实测懒加载场景 2s 内补挂成功；**空闲阈值已从 3 轮（6s）放宽到 12 轮（24s）**
——采集窗口比库加载窗口长时，早期放弃等于整轮失明（F-Droid 实测踩到）。
**QUIC 已从"覆盖外"改为设备侧压制**：`device_run_thirdparty.py` 在 `am start` **之前**
`iptables -I OUTPUT -p udp --dport 443 -j DROP`，逼 HTTP/3 回退 TCP（2026-10-18 实测：
规则 pkts 计数随发包增长、撤销后无残留）；无 root / 内核缺 netfilter 时 `quic_blocked`
记缺口，报告回落为"QUIC 不在覆盖内"。
剪贴板等无需运行时权限的 API，"无同意事件"需要结合 API 判断；
政策关键词预扫是正则代理指标，未命中不等于未声明；
静态扫描看不到被 D8 折叠掉的版本分支（M013）。
