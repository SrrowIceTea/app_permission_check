# Mobile 决策记录（M001– ）

改任何模块前先读这里。与车载侧一样，**几乎每个坑都是静默失败**：
不报错、只是结论少了一条，或者把"没采到"读成"没发生"。

## M001 独立目录树，通用部件靠 import 复用

移动产品自成一套（`mobile/`），车载 vehicle/ 一个字节不动。理由是车载那套有
108 项回归与已交付的证据链，就地改造会让"哪一版是交付物"无法回答。
通用部件（vehicle/traffic 代理层、vehicle/analyze 行号链、reportlab 字体方案）以 import 复用，
不复制——复制会立刻产生两份会漂移的实现。

## M002 规则库 schema v2：只加列加表，不改名

下游（vehicle/workbench 静态匹配、vehicle/dashboard 看板）按 v1 的四张表名与列名读。v2 因此只做：
新增 `sensitive_data_types` / `app_categories` / `policy_requirements` 三张表，
`dangerous_apis` 加 `data_type_key` 与 `observation_spec_json`，
`risk_rules` 的 `rule_type` CHECK 枚举从 3 种扩到 8 种。
`window_ms` 与 `data_egress` 的绑定**保持不变**——时间窗是校准参数，
不该扩散到不需要它的规则类型。

## M003 签名来源只有一处：本机 android.jar

`extract_android_apis.py` 用 `javap -s` 抽描述符，抽到的标 `source_verified`。
抽不到的落 `build/api_missing.json`，**不手写、不推断**。
这与车载侧"android-15 源码镜像不可达时给设备观测安源码出处就是伪造来源"同源。
权限的 protectionLevel 同理：未做设备实测前保持 NULL + pending。

## M004 一个 API 可能对应多个数据类别

`ContentResolver.query` 按 URI 分派、`LocationManager.getLastKnownLocation`
按 provider 分派、`Settings.Secure.getString` 按 key 分派。
因此 `dangerous_apis.data_type_key` 只填 1:1 的情形，多对多写进
`observation_spec_json`（kind = content_uri / provider_arg / string_key_arg），
**运行时按实参分派**。未映射的实参记 `UNMAPPED_ARG` 留痕——
否则"没有 contacts 读取"与"URI 变了我们没认出来"在日志里完全一样。

## M005 钩子只记值哈希与前 6 字符预览，不记原文

审计工具不该成为个人信息的又一份副本，尤其这些证据后面要送进 LLM。
记长度 + `sha256(值)[:16]` + 前 6 字符：足以证明"确实拿到了一个具体的值"，
且前 6 字符能看出"这是不是一串 15 位数字"。副产品是**值级匹配**——
报文里出现同样的哈希，就把"时间上相近"升级成"确实发了这个值"，
比车载侧的关键字匹配强一档（车载侧当时明确说那条是弱证据）。

**哈希口径**：UTF-8 编码 + sha256 前 16 位十六进制。钩子（Java MessageDigest）
与打标（Python hashlib）必须一致，改了要同步两边。

## M006 形态不能定性，只有值能定性

15 位数字可能是 IMEI 也可能是 IMSI；19–20 位更像 ICCID（本库未收录）。
所以 `digit15_shape` 这类标签的 data_type 是 `None`（故意的），
**不产出任何数据类别结论**。要定性必须有值哈希匹配，或读取事件的 data_type。
代价：只凭报文形态识别不出 IMEI。这个代价是值得的——
按形态断言"这是 IMEI"就是过度声称。

## M007 同意时序是「同意前收集」的唯一前提

「征得用户同意前就开始收集」只能由时序证明。因此：
- `consent.jsonl` 缺失 → 该谓词**不产出结论**（进 gaps），不是判为违规；
- 时序存在但没有相关授权 → 才是"窗口内未授权"的证据；
- `PERM_RESULT` 的 granted/denied 必须**逐权限**使用——把"三项里同意两项"
  整体当作已同意，会让判定反过来；
- `POLICY_VIEW`（打开疑似政策页）与 `PERM_RESULT` 都是**代理信号**，
  这不是"用户同意了隐私政策"的直接证明，报告的边界章节必须写明。

## M008 流量层不复制 addon，只换打标模块

`vehicle/traffic/addon.py` 是纯 HTTP 逻辑（反向代理、挂起重试式归因、宽限期、
失败流单列落盘、白名单门），与车载无关。移动侧只在 `addon_mobile.py` 里
`sys.modules["tagging"] = tagging_mobile`，再显式再导出钩子函数
（mitmproxy 在脚本模块的命名空间里找钩子；不导出会"加载成功但一个钩子都没注册"）。

## M009 报告把「没做的部分」写进正文，而不是省略

没配 API key 时报告照出，只是第五至八章明确写"本轮未生成 AI 研判"。
理由：只做到工具规则结论的报告仍然有用；而"因为没配 key 就不出报告"
会让整条链在没网/没 key 时不可用。但缺的部分**必须显式声明**——
省略会让人以为是"没有发现"。

## M010 AI 的三条硬约束与校验器

提示词规定：只用证据包里的事实、每条结论带 evidence_refs、法规只引用允许清单、
不做法律定性、证据不足必须说不足。这些**不能靠模型自觉**，所以有 `validate.py`：
引用不存在的证据 ID、法规条款越界、政策 quote 在正文里找不到、
值级匹配的 token 不在该流里——逐条判为 problems 并把问题清单印进报告第八章。
**校验未通过的内容不会被当作结论。**

## M011 值级匹配的三重校验

`value_level_transfer` 必须同时满足：token 在该流的 `request_tokens` 里、
读取事件存在、token 尾部哈希与该读取事件的 `value_hash` 一致。
只"看起来都是 15 位数字"不算——那正是 M006 要防的事。

## M012 工具不产出 policy_violation（沿用 D501）

结论等级由规则自身封顶，引擎不抬高。AI 章节给"涉嫌不符合《X》第 Y 条"+
置信度 + needs_human_review=true，同样不做定性。

## M013 静态扫描看不到被 D8 折叠掉的版本分支（实测）

夹具里写了 `if (Build.VERSION.SDK_INT >= O) tm.imei else tm.deviceId`，
但**反汇编夹具 APK 后，字节码里只有 `getImei()`，`getDeviceId` 整个消失**
（三个 dex 全扫，`getDeviceId` 字符串 0 次出现）。

原因是 D8 的 **API 级别建模**：`minSdk = 29 ≥ 26` ⇒ else 分支恒不可达 ⇒ 直接被删。
不是解析器漏了，也不是多 dex 没扫——是引用**真的不在** dex 里。

影响与对策：
- 静态结论封顶 `candidate` 的做法继续成立，这条更说明它必要；
- 报告与提示词里说"代码引用了 X"时，准确含义是"**在受支持的 API 级别上会执行的路径里**引用了 X"；
- 因此**动态观测不能省**：只有钩子能证明某条路径真的跑了。
- 排查此类"静态没扫到"时，先反汇编看字节码，不要先怀疑扫描器。

## M014 设备端四个"报错不指向原因"的坑（全部实测）

跑通 `mobile/tools/device_run.py` 的过程中依次踩到，全部已自动化处理：

1. **frida-server 必须以 root 身份在跑。** 以 shell 身份启动时，钩子报的是
   `frida.PermissionDeniedError: unable to access process with pid N`
   （Android 10+ 禁止跨 uid 访问应用进程）；压根没启动时，报的是
   `frida.TransportError: connection closed`。两句都不提"frida-server 的状态"。
   → `ensure_frida_server()` 先 `adb root` 再拉起来，并校验 `ps` 里的 USER 是 root。
2. **AAOS 模拟器只走 wifi，且会周期性掉线。** wlan0 DOWN 时设备侧一切照常，
   只有"网络不可达"——外发失败会被读成"应用没有外发"。
   → `ensure_wifi()` 每轮检查并按需 `cmd wifi connect-network AndroidWifi open`。
3. **`pidof` 与 `am start` 之间存在冷启动竞争。** 顺序反了（先挂钩子后启动应用）
   会得到 `CalledProcessError: pidof 退出码 1`，与"应用没装上"无法区分。
   → `wait_for_app()`：先 `am start`、等到 pid 出现、再挂钩子。
4. **系统权限弹窗是异步弹出的**，可能晚一两秒才出现，于是挡住的是**后面几个**按钮，
   症状是"前一个按钮过了、后三个全找不到控件"，看起来像控件 id 写错或滚动问题。
   → 每次触发前 `clear_system_dialogs()`；找不到"允许"就按 BACK（= 拒绝，
   同样产生合法的 PERM_RESULT）。

另外两条同类的：

5. **上游端口用固定 8080 会与上一轮残留进程冲突**，子进程 bind 失败 →
   主控只看到"上游返回 404"，像应用发错了路径。→ 每轮挑空闲端口。
6. **标记命中不等于动作成功**：外发按钮在主线程抛 `NetworkOnMainThreadException` 时，
   标记照打、一个字节都没发出去。→ 触发器同时检查紧随其后的「结果：」行，
   但**只认自己写的失败前缀**——`imei=DENIED(SecurityException)` 是合法结果
   （权限被拒正是要观测的事实），扫 "Exception" 字样会把它误报成故障。

## M015 数组参数必须用 Frida 认的 JVM 形态（实测）

描述符→Frida overload 类型时，`String[]` 必须转成 `[Ljava.lang.String;`。
拼成 `[java.lang.String` 时，`ContentResolver.query` 三个重载**全部挂不上**，
报 `specified argument types do not match any of`；而钩子其它 API 照常工作，
症状是"通讯录/短信从来没被观测到"，不报错、不影响其他检测项。
→ `jvmdesc.param_types` 保留数组的 JVM 文本形态，并有回归测试钉住。

## M016 钩子必须自证挂载成功

实测：钩子在 `main()` 里抛 `TypeError`（`Process.myUid` 不存在——它是
`android.os.Process` 的方法）时，采集文件里只有一条 `SCRIPT_ERROR`，
而所有按钮触发都"成功"、报告照常生成，**整个运行看起来正常**。
→ `device_run.py` 增加 `hook_*_armed` 断言：没有 `ARMED` 事件即判失败。

## M017 出口判据必须实测 TCP，不能查路由表（实测）

Android 走**策略路由**：default 路由放在 per-network 表里（`default via 10.0.2.2
dev eth0 table eth0`），而 `ip route` 只显示 **main 表**——正常联网时 main 表里
**就没有** default。用 `"default" in ip route` 判"有没有外网出口"会在网络完好时
**误判断网**，而"断网"与"应用没外发"在交付物上长得一模一样（本项目最忌讳的失真）。
同理不能写死网卡名：本机 16k 模拟器走 `eth0`（10.0.2.15）、`wlan0` 是 `DOWN`，
但 `cmd wifi status` 仍报 "Wifi is enabled"。
→ `ensure_wifi` 改为**从设备侧实测 TCP**（`toybox nc -z`，3 个目标任一可连即通过；
多目标是因为单点会被网络环境挡住，实测 8.8.8.8:53 不通而其余三个通）。

## M018 报告的 AI 章节有两处「看起来有 AI、其实没有」（实测）

未配 key 时走 `ai_review.py --dry-run`：只渲染提示词到 `<out-dir>/prompts/`，
**没有任何模型输出**。实测暴露三处静默不一致：
- 报告第八章**硬编码** `ai-out/prompts/`，与实际交付布局 `out/ai/` 不符——报告是
  交付物，指向不存在的目录会让人以为文件丢了。→ 路径改由 `--ai-out-dir` 算出。
- 第五章开场白写"本章由大语言模型……生成"，紧跟其后才是"本轮未生成 AI 研判"，
  自相矛盾，会让人以为报告是 AI 写的。→ 改为"配置 API 并运行 AI 阶段后……"。
- 编排层旧条件只在 `stage3.json` 存在时才把 AI 目录交给报告，使 dry-run 渲染的
  提示词变成**孤儿文件**（躺在交付目录里、报告却不指向它）。→ 目录存在即传入。

## M019 内存 Hook 从 vehicle/hooks 移植（复制而非 import 共享）

`hook_cipher.js`（JCE 加密前明文）、`hook_native_ssl.js`（BoringSSL SSL_write/SSL_read
明文）挂的全是**通用 Android API**，不含任何 `android.car` / VHAL / system_server 依赖，
移动端同样需要「外发前明文」这类证据，故移植。
- **复制而非共享**：frida-compile 按入口文件所在目录解析相对 import，跨项目根
  import vehicle/hooks 的模块会静默失败（与 `tls_bypasses_tp.js` 同一个原因）。
- **适配面只有三处**：① runtime `vscan_runtime.js` → `runtime.js`（接口 `makeLogger`/
  `procName` 一致）；② 日志路径 `vscan.log` → `vscan-mobile.log`；③ `stack_capture.js`
  逐字复用（纯函数）。`scope.js` 同名同接口，直接用。
- **定位是独立落盘**：事件 `CIPHER_PLAINTEXT` / `SSL_*_PLAINTEXT` 只作证据写进日志，
  **不接入** `correlate_mobile.py` 的判定（不改规则库、不产出违规结论）。
- **能力边界保留**：静态链接自有 BoringSSL（Cronet，符号不导出）、不经 JCE 的
  手工加密 / XOR，仍拿不到明文——这是 Hook 方案的固有边界，非移动端独有。
- **现状注记（2026-10-16 核实）**：这两个钩子**从未被任何运行时入口挂载**——
  `device_run.py` / `device_run_thirdparty.py` / `fixture_selftest.py` 全部只挂
  `hook_all`（privacy+consent+egress_tp+ssl_pinning_tp）；对二者的引用只剩
  `build.mjs`（遗留入口构建）与 `test_hooks_parity.py`（一致性守卫）。若要接线
  （合并进 hook_all）：① 先处理授权范围差异（此二者头部标注"自有设备与自有 APK"，
  比 tp 版的"已授权的公开第三方样本"窄）；② 挂钩面变大后必须重跑 A1 稳定性夹具。

## M020 常规代理模式开目标校验 + 流类谓词跳过 unresolved（2026-10-13）

第三方样本走常规代理模式（SLIRP 强制全机流量进代理），时间归因会把"别的 App 的流"
静默认领给被审计包（详见 `core/collector/DECISIONS.md` D413 的移动端形态）。
两处配套改动：

1. `thirdparty_env.py` 的 `start_mitm` 置 `VSCAN_ATTRIB_TARGET_CHECK=1`，让归因按
   目标 host/IP/peername 校验，不匹配 → unresolved。**只在常规代理模式开**；reverse
   模式（`device_run.py`，自有夹具）不设该变量，保持默认关。
2. `evaluation_mobile.py` 的三个流类谓词（read_then_egress / plaintext /
   third_party_domain）统一经 `_flow_unusable()`：同时排除 `attribution_ambiguous`
   与 `attribution="unresolved"` 的流。原先只排除 ambiguous，未解析的流（package=None）
   仍可能凭值哈希被升级成 value_hash_in_payload——误告被审计 App。

归因置信信息（delta / runner_up / candidates）已接进配对，`delta ≥ ATTRIB_LOOSE_MS`
 时结论封顶 candidate。见 core/collector/DECISIONS.md D414。

保守弃权开关（`VSCAN_ATTRIB_CONSERVATIVE`，D415）对移动端**同样可用但默认关**——移动端
常规代理模式已靠 D413 的目标校验在前端拦掉"误认领"，无需再叠保守弃权；除非要"零静默
误报"的极端保证，否则不开（开了会把并发正确匹配也退化成 ambiguous）。

## M021 覆盖守护：把「有规则、无抓手」从人工核对变成构建期断言（2026-10-13）

外部评估指出 `sensitive_data_types` 里 3 个类别没有任何 API 抓手，却各自挂着 6 条规则
（`advertising_id` / `ip_address` / `notification_content`）——规则在运行期**永不触发**，
而这一点过去只靠人眼看种子表。实测确认：旧的 `validate()` 只查了单向
（有 API 无规则 → orphan），**没查反向**。

补法（不是逐条人工修，而是让构建器自己拦）：
- `seed/sensitive_data_types.json` 每个类别新增 `coverage` 声明：
  `api`（默认，声称有抓手）或 `uncovered_by_design`（必须带 `coverage_reason`）。
- `build_mobile_rules.py::validate()` 新增三向断言：声明 `api` 却无抓手 → 失败；
  声明缺口却写了理由不全 → 失败；声明缺口却**查到了**抓手（声明过期）→ 失败。
- 顺带修一个既有静默 bug：`provider_arg` 的 `map` 是 dict（`{"gps": "precise_location"}`），
  原抽取逻辑只认 list，导致 `precise_location` / `coarse_location` 在"可观测类别"集合里
  **一直缺席**——所以旧 orphan 检查也从未覆盖它们。抽出 `spec_data_types()` 统一处理两种形态。
- `test_rules.py` 新增 `test_every_data_type_has_api_or_declared_gap`（反向守护），
  并修好 `test_no_orphan_observable_data_types` 使用同一抽取值。

## M022 补 2 类既有缺口的抓手 + 新增 4 类高敏数据类别（2026-10-13）

**补的**（全部 `javap -s` 实证，`api_missing.json` 仍为 0）：
- `ip_address`：`NetworkInterface.getInetAddresses()` —— 原先只有 `getHardwareAddress`（给 mac），
  IP 类别本身无抓手。
- 新增 4 类：`camera_capture`（CameraManager.openCamera / Camera.open）、
  `microphone_capture`（AudioRecord.startRecording）、`screen_capture`
  （MediaProjectionManager.getMediaProjection）、`biometric_data`
  （BiometricPrompt.authenticate / FingerprintManager.authenticate）。
  新增 3 条相应权限（USE_BIOMETRIC / USE_FINGERPRINT / FOREGROUND_SERVICE_MEDIA_PROJECTION）。

**有意不加的**（写进种子的 `matrix_rationale` / `coverage_reason`，宁缺勿错）：
- `MediaRecorder.start()`：一个 API 同时覆盖录音与录像，`start()` 时无法判定音/视频源，
  强行归到 microphone 会做错归因（本工程最忌的静默错判）。
- `AccessibilityService` / `NotificationListenerService`：都是 App **继承并覆写**的服务类，
  SDK 侧没有调用点；钩基类不会被覆写实现命中（症状是 ARMED 但永不触发）。正确处理需
  运行期枚举子类挂钩，属独立钩子策略 → `notification_content` 因此显式声明为设计缺口。
- `advertising_id`：`AdvertisingIdClient` 属 Google Play 服务，不在 android.jar，抽不到签名；
  国产 OAID 各厂商 SDK 亦然 → 显式声明为设计缺口。
- **写入类**（`ContentResolver.insert/update/delete`、`MediaStore.insert`、
  `SmsManager.sendTextMessage`、`Environment.getExternalStorageDirectory`）：
  语义是"数据改动/发送"而非"采集"，塞进现有 8 种谓词会把写操作误判成"读取收集"。
  要覆盖须新增 write/send 类谓词与 `api_role` 枚举值，属规则语义层改动，本轮不做。

改后计数：规则 193→**223**、数据类别 24→**28**、权限 37→**40**、实证签名 47→**58**。
既有规则 ID（MOB-P001… / R… / E…）**全部不变**——新类别追加在种子表末尾，
新权限追加在权限表末尾，序号只增不改（沿用"新规则一律追加，不改变既有 ID 含义"的约定）。

## M023 规则覆盖矩阵报告（数据类别 × 规则类型）（2026-10-13）

223 条规则由矩阵自动生成，但"哪些格是空的、为什么空"没有产物。新增
`tools/rule_coverage_report.py`：
- 渲染 `rules_coverage.md`（人读矩阵）+ `rules_coverage.json`（机读）；
- 每行带「API 抓手数」（0 = 运行期无从观测）与 `matrix_rationale`（空白格理由）；
- 单独列出**空转规则**；退出码 1 = 存在**未声明**的空转类别，已并入
  `run_mobile_checks.py`（离线回归 16→18 项）。
- 种子表为 `sensor_data` / `ip_address` / `calendar` / `accounts` / `bluetooth_info` /
  `usage_stats` / `biometric_data` / `sms` / `media_images` / `clipboard` 等补了
  `matrix_rationale`，把"为什么不启用那一类规则"从口头说明变成可复核文字。

## M024 APK 加固特征探测 → 证据包 gaps（诚实性增强，2026-10-13）

能力边界里一直写着「加固壳不在覆盖内」，但**报告不会因此提示读者**：加壳样本的自解密
dex、运行时动态加载会让静态结论与 Hook 观察同时失真，而报告看起来和干净样本一样。

做法（不引 APKiD / apktool，纯标准库 zipfile，只读不解压不执行）：
- `tools/apk_packer_probe.py`：在 zip 条目名里匹配公开的加固厂商特征（libjiagu / libshella /
  libDexHelper / libmobisec / libijiami / libchaosvmp …）。
- `evidence_bundle.py` 新增 `--apk`：命中即在 `gaps` 写入带 [orch 同级的] 说明，
  并由 `packer_probe` 字段带出原始探测结果；报告第一/第十章会渲染 gaps。
- `device_run.py` / `device_run_thirdparty.py` 的 bundle 调用补传 `--apk`（编排层本来就知道 APK 路径）。

**定位是提示而非定性**：输出 `packer_suspected`，措辞固定为「疑似/受限」，并明确
「未命中 ≠ 未加壳」（自研壳、字符串混淆的壳测不到）。低置信特征（如通用 `libexec.so`）
照收但标为「低置信」，误报代价由"疑似"承担。探测失败也不静默：写 [probe] 缺口。

## M025 修通权限 protectionLevel 标定链路（原先是一条死路，2026-10-13）

核对外部评估「37 条 seed 权限保护级别未断言」时发现：问题比"未断言"更严重——
`build_mobile_rules.py` 的 permissions INSERT **列清单里根本没有 protection_level_raw /
protection_level_value**，所以哪怕设备实测文件放进 `calibration/`，值也永远落不进库。
`device_calibration_json` 只是把原始观测塞进一个 JSON blob，没有任何下游读它。

修法：
- `load_calibration()` 改为返回结构化条目，抽出 `protection_level_raw` 并按 AOSP 位值表
  算 `protection_level_value`（认不出的级别词留 NULL，不编造）；兼容车载标定产物字段名。
- INSERT 补上这两列；`definition_status` 仍恒为 `pending`（schema 规定设备观测不得标
  source_verified，只有 javap 才是）。
- 摘要新增 `permissions_protection_level.asserted = N/40`，让"还没标定"每次都可见，
  而不是像以前那样只有一句注释。
- 支持 `VSCAN_MOBILE_CALIB` 环境变量覆盖标定目录（便于 CI 与离线回归注入）。
- 新增 `calibration/README.md` 写清产出步骤，并纠正一个流传的说法：可复用的是
  `extract_device_calibration.py`（抽取保护级别），**不是** `calibrate_permissions.py`
  （只比对权限名，原文写着 "No protection levels inferred"）。

## M026 子进程管道必须显式 utf-8 + errors="replace"（环境级坑，实测崩过，2026-10-13）

跑 Fossify Camera 批次时看到 `Exception in thread Thread-1 (_readerthread) ...
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xd3`。定位到根因是**环境组合**：

- 本机（WorkBuddy 环境）全局设了 `PYTHONUTF8=1` → Python 处于 UTF-8 模式；
- UTF-8 模式下 `subprocess(text=True)` 未显式指定编码时，管道**默认按 UTF-8 解码**
  （非 UTF-8 模式的默认是本地代码页 GBK）；
- 而 `cmd.exe`（mklink）、部分 Windows 工具的输出是 GBK 字节 → Reader 线程
  在 `fh.read()` 处抛异常、**该流的结果直接变成 None**（实测复现：mklink 在联接已存在
  时输出 GBK 报错，`result.stderr` 为 None，下游 `[:60]` 立刻 TypeError）。

崩点是 `batch_thirdparty.py` 的 mklink（这条恰好只创建目录联接、不读输出，所以在
本轮之前从未暴露）。全仓扫描同类隐患（`text=True` 且有管道但缺 encoding/errors）
共 5 处，全部加显式 `encoding="utf-8", errors="replace"`，行为从此不依赖运行环境：
mklink、device_run_thirdparty 的 serial 取证、`thirdparty_env.adb/run`、
`uid_sampler` 三处 adb 调用、`vehicle/hooks/build.py` 的 frida-compile。
修复后复查：同类隐患 0 处。

**教训**：Windows 工具链上"默认编码"永远不能依赖进程环境推断——显式写死。

## M027 多设备是静默失真源：启动前守护 + serial 证据修正（实测，2026-10-13）

Fossify Camera 一轮跑完后发现 `app-death.json` 写"原因未记录"，但设备 crash 缓冲里
明明有完整的 SIGABRT tombstone。回查时间线：运行收尾阶段（14:36+）宿主机上出现了
**第二台模拟器**（Android Studio 启的 Medium_Phone），而工具链所有 adb 调用都是
**裸命令**（不带 `-s`）——两台设备同挂时一律报 `error: more than one device/emulator`，
失败形态全是**静默空结果**：

- `pidof` 报错 → 空串 → 旧代码把它当 `alive=False`（"查不到"写成"死了"）；
- `logcat -d` 报错 → 空串 → fatal_lines=[]（"原因未记录"）；
- `settings get http_proxy` 报错 → 空串 → 看起来"已恢复"。

三处修正：
1. `thirdparty_env.device_guard()`：多设备且未指定 `ANDROID_SERIAL` → **启动前退出**
   （批次与单样本入口都调用）。宁可响亮失败，不安静写错。
2. verification 的 `device.serial` 改用 `get-serialno`（旧代码用 `get-state`，
   只会返回字面量 "device"，多设备时还会直接报错）。
3. `app_death_reason` 区分"adb 报错"与"应用死亡"：报错时 `alive_at_end=null`（三态）。

不变式：设备端工具链假定"ANDROID_SERIAL 或单设备"，此假定现在由守护显式检查。

## M028 app 死亡取证：crash 缓冲 + 按时间戳分块 + 真实 tombstone 回归（2026-10-13）

旧实现两个问题（均由 Fossify Camera 的 SIGABRT 实证）：

1. **丢缓冲**：`logcat -d` 读默认缓冲，native 崩溃的 tombstone（`F DEBUG` 行）只在
   `-b crash` 里；而 crash 缓冲会被其它进程的崩溃快速挤占（本模拟器上 UWB HAL 在
   崩溃循环，几十秒就刷掉一轮）——所以取证要在窗口结束**立刻**做，且显式带上
   `-b main -b system -b crash`。
2. **丢上下文**：旧解析"先按包名过滤行、再看相邻 5 行找 Exception"。tombstone 里
   只有 `Cmdline: <package>` 一行带包名，`Abort message:` 不带——过滤一步就把原因
   丢光。改为 `parse_app_death()`：**按时间戳前缀分块**（同一条崩溃记录共享
   `MM-DD HH:MM:SS.mmm`），块内出现包名/进程名才算候选，块内取崩溃标记
   （Fatal signal / FATAL EXCEPTION）与原因（Abort message 优先，Java 异常次之）。

回归：`test_app_death.py` 用**这次真实 tombstone 原文**（逐字抄自设备 crash 缓冲）
+ 干扰进程崩溃 + Java 崩溃等 6 个用例，已并入 `run_mobile_checks.py`。

记录一次**未尽的调查**（重要，别让后来者重新踩）：本次实测 5 个第三方样本，2 个在
150s 窗口内死亡，且死法同型——

- Fossify Camera：SIGABRT，abort message 是一条 `[anon:dalvik-main space]` 映射行，
  backtrace 仅 2 帧（libc abort → 匿名代码），崩前主线程有 17 秒卡顿帧
  （`Davey! duration=16967ms`）。
- KeePassDX：SIGSEGV（SEGV_MAPERR，页对齐的未映射地址），39 帧栈显示**主线程在
  `Looper.loop → MessageQueue.nextLegacy` 里，解释器 `DoCall → art_quick_invoke_static_stub`
  调用某个方法时，方法入口指针指向已解除映射的代码页**（故障地址与符号化里的
  `framework.jar (offset 0x4000)` 页对齐）。
- 回查 2026-10-11 旧批次：opentracks 当天也是**同型 SIGSEGV**（未映射地址、进程主线程）。
- 项目内部已有前例：`tls_bypasses_tp.js` 头部记录过某 Hook "aborted ART on the Glide
  source thread"，因此该 Hook 对第三方样本被**移除**（reduced 字段）。

判断（暂定，未证实）：与"应用自身 bug"不符，更像**插桩去优化（deopt）与 ART 的竞态**
在 API 37 / 16KB 页模拟器上的表现，不是今天新增 API 导致的回归（旧批次同型）。
**控制实验待做**：不挂钩跑同一 App 观察是否存活；以及"精简监视表（reduced profile）"
是否降低死亡率。在此之前，文档与答辩都不得断言"是/不是平台引起"。

## M029 插桩是样本死亡的原因，且是非确定竞态（三段控制实验 + tombstone 取证，2026-10-13）

M028 尾部留了一条"控制实验待做"，本轮补齐。三个运行**同包名、同窗口（150s）、同设备
（`ANDROID_SERIAL=emulator-5554`）**，只改一个变量：

| 轮次 | 变量 | 结果 |
|---|---|---|
| A `control-kp-nohooks` | 不挂钩子（`--no-hooks`） | **存活**（`alive_at_end: true`），10 次 UI 动作全部落地 |
| B `repro-kp-hooks` | 挂全套钩子 | **SIGSEGV 死亡**，`Process uptime: 101s` |
| C `exp-kp-nojit` | 挂全套钩子 + `setprop dalvik.vm.usejit false` | **存活** |

C 看起来支持"关 JIT 有效"，但**不能这样读**——查 `dalvik.vm.usejit` 是否真被采纳：

- `setprop dalvik.vm.usejit false` **之后再** `stop`/`start` 重启框架，新 zygote（pid 21557）
  的 `/proc/<pid>/task/*/comm` 里**仍有 `Jit thread pool`**；随后启动的 keepass 进程
  （pid 23340）同样有。→ 该属性在本镜像（Android 16 / API 37，16KB 页）**未被采纳**，
  很可能 `-Xusejit` 在 init 的服务定义里就已固化，运行时 setprop 改不到 zygote 的命令行。
- 因此 A/B/C 的正确读法是：**A（不插桩）存活；B、C（都插桩）一死一活** → 死因是插桩，
  且**发生是概率性的**。
- 旁证：B 与 C 的 `ui-actions.json` **10 步逐条相同**（Settings → Create new vault → back
  → Open existing vault → back → About → 点中 Chrome → back → no_candidate），
  同一序列一死一活，排除"某个 UI 动作触发"，坐实竞态。

**tombstone 级取证**（`/data/tombstones/tombstone_49`，614 KB，来自 B；UWB 那些只有 62 KB，
不会把它挤掉）：

- `err 0x14` = 用户态**取指**访问不存在的页（不是读数据、不是写）。
- `--->Fault address falls at 00007978'a6004000 between mapped regions`，紧邻
  `[anon:libwebview reservation]`（1 GB `PROT_NONE`）尾端。
- 故障地址**不在** `[anon_shmem:dalvik-jit-code-cache]`（0x54164000–0x56163fff）区间内
  → "JIT 代码页被回收"这一最省事的假说**不成立**。
- 主线程（tid == pid == 8747）栈：
  `ActivityThread.main`(AOT) → `Looper.loop`(AOT) → `artQuickToInterpreterBridge` → 解释器
  → `MessageQueue.nextLegacy` → `DoCall` → `ArtMethod::Invoke` → `art_quick_invoke_static_stub`
  → **跳入未映射页**。即**某个静态方法的 ArtMethod 入口指针失效**。
- 整条主线程栈几乎全在解释器里，与"新装 APK 默认走 `verify` 编译过滤器（解释器 + JIT）"一致。
- 同进程 `Jit thread pool`（tid 8750）当时停在 `ConditionVariable::WaitHoldingLocks`（空闲）
  → 崩的不是"JIT 正在编译"那一刻。

**结论**：这是 ArtMethod 入口失效导致的主线程取指崩溃，只在插桩下出现、非确定。
**API 观测面不改**（58 个敏感读取 + 4 + 8 个出网钩子全部 `ARMED` 成功，钩子不是嫌疑）。
**缓解方向不是调 ART 参数**（已证 `dalvik.vm.usejit` 无效），而是工程韧性——见 M030。

## M030 五个样本暴露的链路问题：先分清"采集缺陷"与"行为事实"（2026-10-13）

本轮 5 个 F-Droid 生态样本（Fossify Camera / Fossify Voice Recorder / KeePassDX /
Breezy Weather / F-Droid）跑完后，运行时数据几乎为零。把它当成"钩子坏了"是错的——
按证据拆成三类，因为**改法完全不同**：

1. **真缺陷 · 代理插件拿不到打标源**。`addon_mobile.py` 启动时检查
   `session/egress.jsonl` / `egress_tp.jsonl`，不存在就警告，并明确说
   "本轮所有流都会是 unresolved"。而钩子是**在 mitmproxy 之后**才起的 → 这两个文件
   在插件启动那一刻必然不存在。**顺序错**，不是配置错。
2. **能力边界 · 只做 Java 层出网归因**。TLS 绕过后 mitmproxy 能看到明文，但
   `flows.jsonl` 要回答的是"**哪个 App 的哪次读取**对应这条流"，这需要 Java 层
   `connect()` 观测（egress/egress_tp 钩子）。纯 native 出网（NDK socket、cronet）
   没有抓手 → 应写进 `gaps`，而不是让 flows 静默为空。
3. **样本行为**（原以为的主因，**已被阳性对照推翻**）。最初推断：5 个样本都是
   F-Droid 生态的隐私友好应用，keepass 首屏（数据库选择页）不触碰被监视 API，
   所以 `reads.jsonl` 只有 START/ARMED 是自洽的。**这个推断站不住**——见下。

### 阳性对照推翻了上面的第 3 条（本轮最重要的结论）

夹具是"必然触发"的：12 个按钮全部命中 logcat 标记，且带真实结果
（`line1=+15551234567`、`gps=39.908998,116.397`、`installed_apps=270`、三个运行时权限 GRANTED）。
这些动作**必然**调用被监视 API。但：

```
hook-privacy.log:  armed 58/58 apis; failed=0
                   attached pid 28892; collecting for 120s -> .../session/reads.jsonl
                   !! pid 28892 在第 17s 消失——钩子已随之失效，此后的事件一条也收不到。
reads.jsonl:       2 行（START + ARMED），零事件
```

最小化实验（只挂钩子，不启 mitmproxy、不走编排）复现：

| 步骤 | 结果 |
|---|---|
| 起夹具 | pid = 32755 |
| 挂 `hook_privacy` | `armed 58/58 apis; failed=0` |
| 按 `btnDeviceId`（按前 pid=32755） | **按后 pid 为空 → 进程消失**，读数仍 2 行 |
| 按 `btnApps` | 命中标记，但 pid 已是 780（`trigger.py` 内部的 `am start` 拉起的新进程）→ 钩子是孤儿 |
| 收尾查 crash 缓冲 | 0 行（进程级 tombstone 已被系统收走） |

从 dropbox 取回的那次现场（`data_app_native_crash@…`，设备时间 16:02:30）：

```
Process: com.vscanner.privacydemo   PID: 28892   ← 正是被钩子 attach 的那个
signal 6 (SIGABRT), code -1 (SI_QUEUE)
Abort message: '02000000-0e000000 rw-p 00000000 00:00 0   [anon:dalvik-main space]'   ← 垃圾内容
2 total frames:  #00 abort+189 (libc)   #01 <anonymous:7bde68aa4000>
Process uptime: 37s
```

**不挂钩子的对照（同夹具、同 4 个按钮、同设备）**：pid 1599 全程稳定，
每个按钮后都存活，再等 30s 仍存活，crash 缓冲 0 行。

→ **插桩是唯一变量。`hook_privacy` 的 58 个钩子在第一次被监视 API 被调用附近
把应用打死（SIGABRT），且崩前的事件一条也发不出来。** 夹具（我们自己最简单的
app）与 Fossify Camera 的崩法**同型**（SIGABRT + abort message 是一条内存映射行
+ 2 帧栈），说明这是**平台级插桩缺陷，不是第三方样本的问题**。

**这条缺陷重新解释了很多现象**：判据 `hook_privacy_armed` 只看"58/58 挂上"，
而 **armed ≠ 能捕到**。整条移动端链路在"应用真的有读取"的场景下必然产出零数据，
且报告看起来一切正常——这正是 M016「钩子必须自证挂载成功」没覆盖到的下一层。

**设计层面的补救（必须做，见待办）**：把夹具阳性对照**内建进链路**，作为跑批前置自检。
读数为零时先看自检结论：自检不过 → 判"采集链路故障"，**不得**写成"该应用未收集"。

**另外两个实证发现**：

- `hook_egress_tp.js` 的 `libcore.io.Posix.connect` 两个重载在 API 37 上
  `ClassNotFoundException`（记了 `HOOK_MISS`，非致命）。同类 8 个钩子里
  `libcore.io.BlockGuardOs` ×2 / `libcore.io.Linux` ×2 / `java.net.Socket.connect` ×2 /
  `java.net.URI|URL.$init` 都挂上了 → **个别死目标要清理，不是链路问题**。
  值得保留的做法：挂不上就写 `HOOK_MISS` 带完整异常串，而不是静默跳过。
- 强制抓包（SLIRP `-http-proxy http://10.0.2.2:8888`）与设备全局代理
  （`settings put global http_proxy 10.0.2.2:8888`）**可以并存**：SLIRP 把"连到
  10.0.2.2:8888"的连接照样改送到宿主 127.0.0.1:8888，mitmproxy 收到的仍是
  `CONNECT <真实域名>:443`，不构成自环。`start_emulator.py` 里"留着可能双重代理"
  的提醒偏保守；实测无碍（GMS 那批 502 是宿主到 Google 域名不通，环境所致）。

不变式：**"没有数据"必须先归因到上面三类之一，才允许写进报告**。

## M031 A1 根因（三层）与修复：单 agent 收敛（2026-10-16）

A1（"插桩把应用打死"）不是单一缺陷，是**三层独立问题叠加**——此前只有第 3 层的表象
（"主线程取指到未映射页 / abort message 是一条内存映射行"）。全部实机定位，逐层修复：

1. **JIT × ArtMethod 替换竞态**：分档实验（46 档不崩 / 49 档崩）排除"规模问题"，
   把崩点锁在"被 hook 方法被调用"；崩溃线程是 `Jit thread pool`（SEGV_ACCERR）。
   **【2026-10-16 晚修正：本项的"关 JIT"修复不成立，见 M032 追记】**——setprop +
   框架重启**关不掉** JIT（复证：usejit=false 后夹具进程仍有 `Jit thread pool` 与
   `dalvik-jit-code-cache`），`-prop` 被 emulator 37.1.11 拒绝；修复的实质是
   第 2/3 层，且全部验证都在 JIT 开启状态下完成。
2. **JNI transition frame reference**（Android 14+ 起）：ART 把 `this`/对象参数以
   transition ref 传给 native；CheckJNI（userdebug 强制开启）对任何校验型 JNI 调用
   都会因"Frida trampoline 帧让栈遍历失败"而拒绝 → 上游 frida#3700/#3745（未修）→
   **bridge 补丁**（`patches/02-class-factory-transition-ref.patch`：解码 + AddGlobalRef；
   `build.mjs` 构建前幂等重放，`npm install` 后不丢）。
3. **多脚本不被 bridge 支持**：bridge 源码注释原文 "we don't support replacing methods
   from multiple scripts"；tombstone 一级 FATAL 栈 `ArtMethod::GetOatQuickMethodHeader
   ← Frida 匿名段`，且 **x64 + API 37 恰落在 bridge 防护的"未覆盖区"**（libart 被 strip、
   符号三路皆查无；x64 分支被作者标注 "Not needed on x86 and x64"）。对照实验：
   **双脚本 ~50% 崩 vs 单脚本 5/5** → **单 agent 合并**（`hook_all` bundle：
   privacy+consent+egress_tp+ssl_pinning_tp 同一个 JS 上下文；挂载清单 5→1；
   事件由 `split_events.py` 分流回独立文件，下游零改动）。

**证伪留痕**：`deoptimizeEverything`（引出 JNI 副作用新崩溃）、`deoptimizeBootImage`
（无效）、"重启 frida-server / 换新模拟器 / 重置应用编译状态"（均非变量）。
**退役**：vehicle 版 egress / ssl_pinning_bypass 从 mobile 链路移除（观测面被 tp 版覆盖；
vehicle 版 TLS 含**已实证会炸 ART** 的 HttpsURLConnection 手法）。

**配套工程**（同批）：哨兵优雅停止（`run.py --stop-file` + `thirdparty_env.stop_hook`）；
窗口证据前移（reads/alive/死亡取证全部在拆钩**之前**——拆钩噪声隔离）；
死亡取证对齐 `/proc/<挂钩 pid>`（防"崩溃重启"骗过存活检查）。

**验证**：夹具 `hook_all` ×5 全绿；真实样本（voicerecorder）端到端 `passed`（21 项
检查零失败）。执行记录与实验矩阵见 DEV_FIX_REPORT §5.8。

## M032 JIT-off 不成立（复证）+ SLIRP 强制代理失效根因与修复（2026-10-16 晚）

**JIT-off 复证**（修正 M031 第 1 项，详见 DEV_FIX_REPORT §5.9①）：两条铁证——
① `setprop dalvik.vm.usejit false` + `stop/start` 后，夹具进程**仍有** `Jit thread pool`
线程与 `dalvik-jit-code-cache` 映射（与 M029 旧结论互相印证）；② emulator 37.1.11
只接受 `qemu.*` 前缀的 `-prop`。修复的实质 = bridge 补丁 + 单 agent；JIT 开启下
hook_all 49 档 2/2 复跑通过。已清退 `runner._ensure_jit_off`（连同 stop/start + CA
重装的整套动作）与 `-prop` 参数。

**SLIRP 强制代理失效（P0 级，已修）**：emulator 37.x 启动时从**宿主进程**对
`-http-proxy` 地址做一次性可达性探测——传 guest 侧别名 `10.0.2.2` 在宿主上不可
路由 → 必超时（启动日志固定出现 "Could not connect to proxy at 10.0.2.2:8888:
timed out" + "Proxy will be ignored!"）→ **整条 SLIRP 重定向被关闭**。guest raw
socket 实测（`nc`，绕开一切应用层代理设置）证明：此前只有"读设备侧 global
http_proxy 的组件"能被抓到，**不读系统代理的直连流量一直全漏**——与"SLIRP 层强制
走代理：应用绕不过去"的既有承诺不符。修复两件套（缺一不可）：
① `-http-proxy` 地址改**宿主侧回环** `127.0.0.1`（`transparent.PROXY_ARG_HOST`；
设备侧 `settings put global http_proxy` 仍为 guest 侧 `10.0.2.2`，两个地址空间各自
语义不变）；② **冷启动前置 mitmproxy**（`runner._start_early_mitm` +
`device_run_thirdparty --reuse-mitm`）——探测只在模拟器启动那一刻做、失败不重试，
代理必须先于模拟器进程存在。

**验证（铁证）**：同一模拟器上 `nc` 直连 example.com:80 拿到经代理的真实 200；
直连任意 dummy IP 收到 `Server: mitmproxy` 的报错页（raw socket 都被重定向）；
代理日志有完整连接记录。配套加固：`start_mitm` 端口占用预检 + 启动后监听校验
（把"抢不到端口静默跑完"变成响亮报错）；`app_death_reason` 抗 adb 超时；
模拟器 stdout 落 `emulator.log`（启动期关键警告不再随 DEVNULL 消失）。

## M033 现场复验：系统代理全禁下 TCP 仍被强制劫持（铁证）+ UDP 不经代理的边界确认（2026-10-16 下午）

**动机**：M032 的修复（宿主侧地址 + 前置代理）需要一个**独立于端到端**的现场复验——
端到端里设备侧 `settings http_proxy` 一直存在（会被部分组件尊重），"系统代理完全
不存在时还能不能抓"没有被单独证明过；UDP 行为（QUIC 的承载层）此前也从未测过。

**方法**（新工具 `mobile/tools/verify_force_proxy.py`，可重复跑）：前置 mitmdump →
冷启动模拟器（启动参数与流水线同源 `tp.emulator_capture_args`）→ 等 boot →
**等多目标 TCP 探测通过**（对齐 `ensure_wifi`，就绪才开测）→
`settings put global http_proxy :0` 彻底禁用系统代理 → 三测：
A：`nc -4` 直连 example.com:80｜B：`nc -4` 直连 203.0.113.7:80（TEST-NET-3，不带
Host）｜C：`nc -4 -u` 到宿主 UDP listener（10.0.2.2:9999）。

**结果**（工具化复跑 2026-10-16 15:45–15:49 全绿，证据
`D:/vscanner-tp/verify-force-proxy/20261016-154525/verdict.json`（同目录含
mitm.log / emulator.log / emulator-start.log / session/）；早期手稿轮证据在
`D:/vscanner-tp/manual/proxy-verify/`）：
- 前置条件全绿：模拟器日志无 'Proxy will be ignored'；`settings get` 实测 `':0'`。
- **A 被捕获**：代理侧 client connect 增量（手稿轮 +4 / 工具化复跑 +3，含设备自身
  连接的噪声）；mitm.log 记录到 guest 的 `GET http://example.com/ HTTP/1.0` flow。
- **B 是铁证**：203.0.113.7 是保留给文档的不可达地址，guest 却收到了
  `HTTP/1.1 400 Bad Request` + `Server: mitmproxy 12.2.3` +
  "HTTP request has no host header, destination unknown."——响应只能由本机
  mitmproxy 产生，证明 raw socket 直连（系统代理已禁用）被 SLIRP 强制劫持
  （手稿轮 +9 / 工具化复跑 captured(+2)，报错页逐字复现）。
- **C 确认边界**：宿主 UDP listener 收到 `b'VSCAN_UDP_PROBE'`（两轮均复现；源地址为
  SLIRP 宿主回环 + 临时端口，如 127.0.0.1:62221 / :53517）→ **UDP 直出、不经代理**。
  `-http-proxy` 只重定向 TCP，QUIC/HTTP3 走 UDP 443 因此不在包内——与 CLAUDE.md
  "能力边界：QUIC 不在覆盖内"一致，报告应如实引用（不解码 QUIC）。
- **固化的教训（v1 假阴性）**：boot 完成 ≠ 网络就绪——冷启动后 eth0 的 DHCP 还要等
  （两轮实测 36s / 106s），过早测试全是 "Network is unreachable"（那是"网络没醒"，
  不是"代理没抓"）。`verify_force_proxy.py` 内置网络等待，就绪才开测。
- **排障注记**：mitmproxy 对**无 Host 的畸形请求**（如 raw socket 直连 IP 不带 Host）
  直接回 400，但**不产生 flow 日志行、也不进 flows.jsonl**（本地隔离实验复现）——
  判断这类直连是否被劫持不能查 flow 日志，要看连接增量或客户端实际收到的响应。
  手稿轮 mitm.log 里"找不到测试 B 的 400"正是此因，非采集缺陷。

**结论**：M032 修复在"系统代理完全禁用"的极端条件下依然成立；UDP/QUIC 属已知且
已声明的边界。

## M034 工程小项整改：conn_probe 并发防撞 + `run_regressions --mobile` 开关（2026-10-16）

**动机**：对 `TWO_DEV_PLAN.md`（v3）逐条独立核查后，确认"存在"档中两项可离线修复的小项：

1. **工程-6**：`mobile/tools/conn_probe.py` 设备侧脚本/日志路径固定为
   `vscan_conn_all.*`。两个实例并发时，后启动者的开头 `rm -f` 会删掉前者的脚本，
   正在跑的那个下一轮 `sh <script>` 找不到文件而**静默失明**——症状与"应用没外发"
   难分（本项目最忌讳的失真形态）。
2. **工程-7**：`tools/run_regressions.py` 没有 `--mobile` 开关，移动侧 23 项检查
   不在根回归入口内（待办原注"需先定义语义"）。

**修复**：

- conn_probe：设备路径改为 `vscan_conn_<pid>_<epoch>.sh/.log`（唯一后缀），启动时
  顺带清一次旧固定名残留，收尾 `finally` 里 `rm -f` 本轮脚本（唯一后缀保证不误删
  并发实例的文件）。同时确认 `DEVICE_LOG` 是遗留名（本工具从不写入，走 stdout 流），
  仅保留为清理目标。
- run_regressions：新增 `--mobile`。**语义定为：移动侧失败 = 根回归失败（非零退出）**，
  理由是"根回归绿了但移动端已烂"的静默状态正是"文档状态列不可信"教训的来源；
  不想受影响时不带该开关即可。移动组超时单独放宽到 600s（整批依赖 requirements.txt，
  缺包会假红——AGENTS.md「先确认解释器再判红」）。

**验证**：两文件 `py_compile` 通过；`run_regressions.py --mobile` 全量跑通
（13 组根回归 + mobile-checks 组）。

**顺带核查更正**：TWO_DEV_PLAN.md 把"工程-5 sqlite 只读 URI"标为 ⚠️部分（4 处未改）
已**滞后**——现全仓所有只读连接（correlate_mobile / evidence_bundle / policy_lint /
gen_targets / rule_coverage_report / static_scan_thirdparty 等）均已带 `?mode=ro` URI，
不带 URI 的剩余连接全是写库/测试/内存库，属正常。该项无需动作。

## M035 C1 派生值匹配 + C2 静态/动态覆盖差集（2026-10-16）

**动机**：TWO_DEV_PLAN §3.3 的 C1/C2 是"存在（未做）"档里仅有的两项可纯离线完成、
且修的是**静默失真**的功能项（其余 C/E 项需要真机或排期给两人）。

**C1 · 派生值匹配**（`core/collector/derive.py` 平台无关内核 + 三处接线）：
真实应用常把读到的值**变换后再外发**（base64/url/hex/gzip+b64 编码、md5/sha1/sha256
摘要）。原值级匹配只认「原值 hash16」一种形态，这些场景全部**静默降级**成
"仅形态相似"——证据强度凭空掉档且无任何标注。做法：
  * 可逆编码：报文侧 `reversible_decodings()` 解回原文 → 重新过形态扫描 →
    令牌仍是**解码后原值**的 hash16 → 读取侧（value_hash）**零改动**即命中；
  * 单向摘要：只能从原值方向算——读取侧 `hash16_candidates()` 对完整原值
    （value_preview 未截断时）算各摘要形态的 hash16，与报文侧
    `md5/sha1/sha256_hex_shape` 形态令牌比对。截断预览（以 … 结尾）的摘要候选
    整体不参与——只可能漏配，不可能错配；
  * 诚实边界：解码产物只贡献**值级令牌**与 `derived_*` 标记，不贡献形态级标签
    （乱码/巧合解码可能凑出假形状）；「报文里有个 md5」本身不构成任何匹配；
  * 配对记录新增 `value_match_form`（raw/md5/sha1/sha256），配对可溯源到具体形态。
  * **阈值教训**：首跑 test_derive 即失败——15 位 IMEI 的 base64 只有 20 字符、
    hex 只有 30 字符，最初 24/32 字符的门槛把最典型场景挡在门外。阈值按真实目标
    反推（b64≥16、hex≥10 字节），误报由「charset+对齐+可打印 UTF-8+敏感形态重扫」
    四层兜底。另：tagging 的 urlencoded 用例初版把手机号里塞了 `%2D`（连字符），
    数字串被截断不可能匹配——改用 URL 编码 JSON 体的真实场景。

**C2 · 覆盖差集**（`mobile/analyze/coverage_gap.py` + evidence_bundle 接线）：
静态 dex 引用与动态观测是两条独立证据链，各有盲区且盲区**长得一样**（都是
"该类别没出现在结论里"）。不摆差集，"静态有引用但动态没触发"（多半是本轮
场景没走到）会被误读成"运行时没这个行为"；反过来会被误读成"静态漏报可修"。
做法：纯函数 `compute_gaps()`（精确 key 匹配、不做同义词归并），差集三区
`static_only` / `dynamic_only` / `both`，四条诚实边界写死在输出的 caveats；
`evidence_bundle.py` 新增 `--static-supplement`，提供了 static_scan_thirdparty
产物才算（没跑静态扫描时硬算只会产出误导性的全 dynamic_only）；产物不可解析/
不存在时写 `[coverage]` gap，绝不静默。

**验收**：test_derive 12 例 + test_tagging_mobile 24 例（含 8 个派生值用例，含
反例：别的 15 位数字不得产出本 IMEI 的值级命中）+ test_coverage_gap 11 例全绿；
evidence_bundle `py_compile` 通过；全量 `run_regressions.py --mobile` 复跑。
C1/C2 均不改变既有结论的判定路径——C1 只把原本静默降级的匹配升回来，
C2 是纯增量字段。

## 待办（已想清楚要做什么，尚未做）

- ~~**P0 · 修`hook_privacy` 打死应用**（M030 的结论）~~ **→ 已修（2026-10-16，见 M031
  / DEV_FIX_REPORT §5.8）**：三层根因全部定位修复，夹具 hook_all 5/5、真实样本端到端
  passed。以下原文保留（对同类排查仍有参考价值）：夹具（自己最简单的 app）在
  `armed 58/58` 之后第一次被监视 API 调用附近就 SIGABRT，读数一条没有；同夹具不挂钩子
  则完全健康。缩小钩子面分档实验是第一步：先只挂 1~3 个 API（如
  `Settings$Secure.getString` / `TelephonyManager.getLine1Number`）确认机制本身可用，
  再按 8 / 16 / 32 递增定位崩点。候选方向：改用 `Interceptor.attach` 在 native 层
  拦 `libc` 而非逐个 `Java.use` 替换；或先 `Java.deoptimizeBootImage()` 再挂；
  或对 `java.net.*` / `android.provider.*` 这类高流量类改采样。**在此之前，
  所有"零读取"结论都不可信**。
- **P0 · 夹具阳性对照内建进链路**：`device_run.py` 已有夹具链路，但它是独立入口。
  要把它作为 `batch_thirdparty.py` 的**前置自检**（跑批前自动跑一次夹具，读数为零即
  拒绝出批），并把结论写进批次摘要。读数为零时先看自检：不过 → "采集链路故障"。
- **P1 · 崩溃自愈 + 分段采集**（M029 的直接后果）：崩溃是非确定的，不能靠
  调 ART 参数规避。做法是把采集窗口切成 N 段（如 30s/段）：每段（重）启动应用 →
  （重）挂钩子 → 采集 → 收尾；进程死了就由下一段重新拉起，数据**跨段累加**。
  验证判据：在 keepass 这种高死亡率样本上，即使中途崩 1~2 次，`reads.jsonl` /
  `egress.jsonl` 仍应有本段之前的真实事件，且 `app-death.json` 记录每次死亡。
- **P1 · 夹具 `showPolicy` 的 dialog 生命周期**：编排按 BACK 提前关掉政策弹窗后，
  夹具 8 秒定时器再到时会 `Dialog.dismiss()` 一个已 detach 的 view →
  `IllegalArgumentException: View=...DecorView... not attached to window manager`
  （dropbox `data_app_crash@…16:05`）。夹具侧应先判 `isShowing` 再 dismiss。
- **P2 · `addon_mobile.py` 与钩子的启动顺序**：插件启动时 `egress.jsonl` /
  `egress_tp.jsonl` 必然还不存在（钩子在其后才起），于是"本轮所有流都是 unresolved"。
  要么把插件推迟到钩子 ARMED 之后再起，要么让插件容忍源文件后到（tail -F 语义）。
- **P2 · 清理死钩子目标**：`hook_egress_tp.js` 里 `libcore.io.Posix.connect` 两个重载
  在 API 37 上 `ClassNotFoundException`（已记 `HOOK_MISS`，非致命）。留作已知死目标
  或删除，避免每次跑都产生噪声。
- **时间窗校准**：30000ms 是从车载侧沿用的**声明值**，未由移动夹具实测校准。
  要做的是跑夹具采集"读取→外发"间隔分布，写 `WINDOW_CALIBRATION.md`，
  再决定是否调整 `rule_gen.DEFAULT_WINDOW_MS`。在此之前报告里如实标注未校准。
- **自有靶子 App**：`fixture-app/` 在建；设备端端到端依赖它。
- **App 类目归属**：目前靠 `--app-category` 手工声明。自动从应用商店信息推断
  会引入不可靠来源，宁可手工声明并标注 `source: declared`。
