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

**动机**：对 `archive/TWO_DEV_PLAN.md`（v3）逐条独立核查后，确认"存在"档中两项可离线修复的小项：

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

**顺带核查更正**：`archive/TWO_DEV_PLAN.md` 把"工程-5 sqlite 只读 URI"标为 ⚠️部分（4 处未改）
已**滞后**——现全仓所有只读连接（correlate_mobile / evidence_bundle / policy_lint /
gen_targets / rule_coverage_report / static_scan_thirdparty 等）均已带 `?mode=ro` URI，
不带 URI 的剩余连接全是写库/测试/内存库，属正常。该项无需动作。

## M035 C1 派生值匹配 + C2 静态/动态覆盖差集（2026-10-16）

**动机**：`archive/TWO_DEV_PLAN.md` §3.3 的 C1/C2 是"存在（未做）"档里仅有的两项可纯离线完成、
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

## M036 明文缺口的真根因：Frida 17 API 已删 + 库懒加载 + RTLD_LOCAL；native/QUIC 接线（2026-10-18）

**动机**：面板把 `HTTPS·native pinning` / `Flutter·RN·WebView` / `QUIC` 三行标成
"拿不到 / 漏掉"，外部又给了一份修复建议（r0capture 兜底、iptables 在模拟器不可行、
Flutter 用 NVISO 脚本、RN 需 Hook Hermes）。逐条在本机 AVD 上核实，能落地的直接接线。

**核实结论（含被证伪的）**：
- **"模拟器内核不支持 iptables，QUIC 只能真机"——证伪。** 实测 Android 37 x86_64 AVD：
  `iptables -I OUTPUT -p udp --dport 443 -j DROP` 返回 0，`-L OUTPUT -v` 首条规则
  pkts 随发包增长；`-D` 撤销后无残留。M033 的"C：UDP 直出"只证明 `-http-proxy`
  这个参数不管 UDP，**不等于内核层丢不掉**——当时把"参数的能力边界"写成了"内核的能力边界"。
- **"r0capture 可作兜底"——方向对，但真根因不在方案选择上：现有 native 钩子在
  Frida 17 上从没真正跑通过。** 三层，逐层实测：
  1. **API 已删**：Frida 17 移除 `Module.findExportByName`，只留
     `Module.getGlobalExportByName`。旧代码把它包在 try/catch 里 → 永远静默
     `SYMBOL_ABSENT`，看上去像"设备/方案不支持"。
  2. **全局查找查不到**：`getGlobalExportByName` 对 dlopen 进来的库返回 not found——
     Android 的 linker 默认 `RTLD_LOCAL`，符号不进全局作用域。必须逐模块
     `module.findExportByName(sym)`。
  3. **懒加载**：attach 那一刻库里往往还没有 `libssl.so`（BreezyWeather 冷启动 2s 时
     为 0，产生流量后才加载）。只在 arm 时扫一次会**永久**漏掉。
- **"Flutter 用 NVISO 脚本"——可信，但仓库没有 Flutter 样本**，无法实测；按
  "无实测不出结论"不接，边界如实标注。
- **"RN 需 Hook Hermes"——不需要**：RN 的网络最终走 OkHttp/Java 栈，既有 Java 钩子覆盖；
  仓库里唯一的 RN 样本（车载喜马拉雅）只有 arm ABI，本 x86_64 模拟器跑不起来。

**改动**：
- `mobile/hooks/hook_native_ssl.js`（车载同源副本同步）：逐模块扫描 + 按地址去重挂载；
  Hook `dlopen`/`android_dlopen_ext`，库加载后重扫（SSL/加解密相关库立即重扫，其余
  150ms 节流）；`SYMBOL_ABSENT` 附带"相关库在不在"的清单，作为边界判据而不是猜测。
  另修一个真 bug：`SSL_write_ex` 的长度取的是 `args[3]`（`written` 出参，onEnter 还没写），
  恒为 0 → 新 API 调用永远记不到明文；应为 `args[2]`。
- **接线**：两个文件改为只导出 `main()`，由 `hook_all` 在同一 `Java.perform` 里调用
  （`build.mjs` / 车载 `build.py` 各自加单模块入口）。**不能用 side-effect import**：
  ESM 的 import 会被提升到入口 `globalThis.Java = Java` 之前，实测直接
  `ReferenceError: 'Java' is not defined`。
- `runtime.js` / `vscan_runtime.js`：新增共用的 `decodeUtf8()`，供两个明文钩子把
  byte[] 解成真 UTF-8（原实现给出的是 Latin-1）。
- **QUIC**：`thirdparty_env.block_quic / unblock_quic`；`device_run_thirdparty.py` 在
  `am start` **之前**压制（外发就发生在启动那一刻），窗口结束或 `app_started` 早退时撤销。
  失败不阻断采集，记 `quic_blocked` 缺口——"没拦住"与"没流量"在报告里必须可区分。

**实测**（Android 37.1 x86_64 AVD，frida 17.18.0）：
- 合并包 `hook_all` 在 F-Droid（`pm clear` 后首启，逼出索引下载）：5 个 ARMED，native 侧
  `SSL_write@libjavacrypto.so` + `SSL_read@libjavacrypto.so`，cipher 12 个重载，
  与 privacy/consent/egress/tls 同处一个 agent（A1 单脚本约束不变）；
  同一轮记到 **27 条 `SSL_READ_PLAINTEXT` + 7 条 `SSL_WRITE_PLAINTEXT`**
  （HTTP/1.1 响应头、F-Droid 索引 JSON），另有 9 条 EGRESS_CONNECT / 16 条 EGRESS_URL。
- native 单独挂载 F-Droid 冷启动：**1003 条 `SSL_READ_PLAINTEXT`**（每条 16KB，
  内容是 F-Droid 索引 JSON 原文），模块 `libjavacrypto.so`。
- **关键性质**：所有轮次设备 `http_proxy` 都是 `:0`（没有代理），明文是在**应用自己的
  SSL 栈里**读到的——证书 pinning 挡的是"我们伪造证书"这条路，挡不住这条路。
- 顺带修 `utf8` 预览字段：原先逐字节 `String.fromCharCode` 得到的是 Latin-1，
  中文变成乱码（`hex` 对、人读不了）。改为共用 `runtime.decodeUtf8()`（含截断处理），
  实测 10 条明文事件里中文可读；Node 单测覆盖中文/emoji/截断三例。
- QUIC 开关：`block_quic=True`、规则首条 `DROP udp dpt:443`、`unblock` 后 `still_present=False`。

**遗留边界**：符号被剥/内联的静态 BoringSSL（部分 Cronet 构建）、Flutter
（`libflutter.so` 自带 BoringSSL，需模式扫描）、不经 JCE 的手工加密/XOR；
Java 层 pinning 三手法仍缺阳性对照样本（与本次改动无关，缺口不变）。

## M037 明文范围扩围：应用层加密（EVP/AES）+ TLS 元数据（SNI/keylog）+ 轮询兜底（2026-10-18）

**动机**：M036 之后 TLS 记录层已能读明文，但"TLS 之前就已加密"的路径仍是盲区；
且符号被剥的构建没有旁路。本轮按"加密转换点"思路补两条，并把实测暴露的懒加载缺陷修掉。

**新增两个钩子**（均为纯 native attach，不替换 Java 方法，随 `hook_all` 装配）：

- `hook_native_crypto.js`：拦 `EVP_EncryptUpdate` / `EVP_DecryptUpdate` 与低层
  `AES_encrypt` / `AES_cbc_encrypt` / `AES_ctr128_encrypt`，取加密的**入参**、
  解密的**出参**（`outl` 在 onLeave 才写，onEnter 读是上一轮残留——这类钩子最常见的错）。
- `hook_tls_meta.js`：`SSL_set_tlsext_host_name` 记 SNI；hook `SSL_CTX_new` 的返回值后
  **主动**调 `SSL_CTX_set_keylog_callback`。为什么不是 hook setter 本身：那是 App 的调用
  入口，App 不调就什么都拿不到。

**关键设计：EVP 必须过滤 TLS 记录层。** BoringSSL 的 `tls_seal_record` 内部也走
`EVP_EncryptUpdate`，不过滤的话每条 TLS 流量都会多记一条**密文**事件，既污染日志又误导
"拿到了明文"的结论。两道过滤：① 回溯前 6 帧符号名命中 `^(ssl_|tls_|dtls_|SSL_|DTLS_)`；
② 兜底看入参是否以 HTTP 方法/状态行开头（符号被剥时仍有效）。低层 AES 按
`symbol|direction|module` 做 120ms 节流 + 全局 800 条上限。

**实测证据（Android 37.1 x86_64 AVD / Frida 17.18.0）**：

- **EVP 阳性对照**（`NativeFunction` 直接调 `EVP_EncryptInit_ex` + `EVP_EncryptUpdate`）：
  命中 `EVP_ENCRYPT_PLAINTEXT`，`byte_len=39`，`utf8="VSCAN-EVP-SELFTEST-PLAINTEXT-0123456789"`。
- **端到端对照**（自写 `NetProbe` 走 `HttpsURLConnection` → conscrypt）：
  `TLS_SNI host=www.baidu.com`；`TLS_KEYLOG label=CLIENT_RANDOM`（64 字节 master secret）；
  `SSL_WRITE_PLAINTEXT 114B = "GET / HTTP/1.1\r\nUser-Agent: ...Host: www.baidu.com"`；
  `SSL_READ_PLAINTEXT` 6 条（200 OK 头 + gzip body 分段）。
- **TLS 过滤生效**：同一轮里 EVP 事件 **0 条**——握手/收发全程走了大量 EVP，全部被正确
  跳过。这是"过滤对不对"的阴性对照，和上面的阳性对照缺一不可。
- **懒加载补挂**：`lazy` 模式（attach 时库未加载、6s 后才 `SSLContext.init`）初始
  `native_ssl=0 / tls_meta=0` 钩子；2s 后 `RESCAN_HOOKED {how:"poll", added:2}`，
  随后 SNI/keylog/明文全部命中，`RESCAN_STOPPED rounds=6`。

**修掉的缺陷：`dlopen` 重扫不可靠。** 第一轮 lazy 对照里库加载后**没有**触发重扫
（钩子仍为 0、无 `RESCAN_HOOKED`）。诊断：`dlopen` 在 app_process64 / libdl.so /
libc.so 等所有模块里解析到**同一地址**，无法区分 linker 真实实现与 PLT 转发。
不深究 linker 细节，改为 2s 低频轮询兜底（连续 3 次无新增或满 30 轮停止），三个 native
钩子都加。真实 App 里 attach 通常晚于库加载，轮询只是保险；探针场景是它的主战场。

**仍存在的边界（不要写成已覆盖）**：

- ~~**gzip body 不可读**~~ → **已解（M038）**：改由 pcap + tshark 重组，`http.file_data`
  给出的是解压后的明文，`test_pcap_pipeline.py` 里有一条 `gzip → 明文` 的实测用例。
- ~~**keylog 需要 pcap 才兑现**~~ → **已解（M038）**：`device_run_thirdparty.py` 现在
  先抓 pcap，收尾时把 keylog 事件写成 `keys.log` 喂给 tshark。
- ~~Flutter / 剥符号的静态 BoringSSL 在覆盖外~~ → **部分解（M039）**：`hook_flutter_ssl.js`
  按代码形状（不是符号）定位并 patch 证书校验函数，静态/运行时两路对同一偏移互相印证。
  不经 JCE 也不走 EVP 的自研算法仍在覆盖外（同 M036）。

## M038 完整 HTTP 报文：设备端 tcpdump + keylog + tshark，重组外包（2026-10-18）

**动机**：M037 收尾时留下的最大缺口是「hook 拿到的是 `SSL_read/SSL_write` 的**分片**」——
一次调用可能只有半个 body，且没有连接标识、没有方向。要自己拼就得上
`Content-Length`/chunked 状态机、gzip 解压、HTTP/2 帧与 HPACK，等于重写一个 Wireshark。
而这条路**本来就有成熟实现**，缺的只是"把 pcap 抓下来"。

**做法（三层，各管一件事）**：

| 文件 | 职责 |
|---|---|
| `mobile/tools/pcap_capture.py` | 设备端 `tcpdump` 起停 + 拉回本地。只抓不解 |
| `mobile/tools/pcap_http.py` | 从事件抽 NSS keylog → 调 `tshark -o tls.keylog_file:` → JSONL（body 落 `bodies/`）|
| `device_run_thirdparty.py` | 在 `am start` **之前**起抓包（外发就在启动那一刻），UI 探索结束后停 |

**实测（本机 AVD / Android 17）**：

- `/system/bin/tcpdump` **4.99.6（libpcap 1.10.6）是系统预装的**，不用 push 二进制。
- 但它的 SELinux 类型是 `tcpdump_exec`：**shell 域既读不到也 exec 不了**（`ls` 直接
  Permission denied），只有 `su 0` 看得见。所以能力探测必须**以 root 身份**做——
  先用 shell 探测会得到"设备上没有 tcpdump"的假阴性（本轮踩过一次）。
- `-i eth0` → EN10MB；`-i any` → **linktype 276（Linux SLL2）**；tshark 两种都认。
- `-G N -W 1` 退出时会把文件**截断成 0 字节**（踩了两次），必须用 `timeout N tcpdump`
  或发 SIGINT 让它走正常收尾。
- 端到端跑通：一轮 F-Droid（走设备代理）解出 **31 条报文**（h1=29 / h2=2，见下方
  「HTTP/2」一节），`http_messages.jsonl` 里 method/host/uri/status/body 齐全；
  其中 h2 的 `index-v2.json` 拿到了 37KB gzip 明文。
- `test_pcap_pipeline.py`（16 条断言，不依赖设备与外网）覆盖：keylog 去重、
  请求+响应齐全、**gzip → 明文**、**h2c 伪头还原 + 跨段 gzip DATA**、
  缺 pcap/未启动时必须报错而不是返回空。

**修掉的缺陷（都是测试逼出来的）**：

- `keylog_from_events` 第一版用正则枚举标签，写错一个字符就**静默返回 0 行**；
  改成按结构校验（3 段、后两段 hex），TLS 1.3 的 `CLIENT_HANDSHAKE_TRAFFIC_SECRET` 一并收。
- `PcapRecorder.stop()` 在没 `start()` 时会把**设备上残留的同名文件**当成"本轮抓到的"
  拉回来——最坏的一种假证据。现在未启动直接返回 None。

**已知边界（不要写成已覆盖）**：

- **抓包截止会截断 body**：应用被杀/抓包停止时，正在传输的 body 只拿到前一半。
  这类报文带 `gaps: ["gzip_truncated"]`，`http-stats.json` 里有 `bodies_truncated` 计数。
  实测那条 F-Droid 索引 body 解出 37016 字节明文，`json.loads` 在 28501 字符处报
  `Unterminated string`——**是截断，不是解码错误**。报告里必须写明"部分正文"，不能当全文用。
- 抓的是**全设备**流量，要靠 tshark 侧按五元组/端口筛；QUIC 的 keylog 是另一套 API，
  仍靠 `block_quic` 压制。
- 轮询兜底原先「连续 3 轮空闲（6s）就停」，实测采集窗口比库加载窗口长时整轮失明；
  已放宽到 12 轮（24s）/ 90 轮。
- `hook_tls_meta.js` 原先只 hook `SSL_CTX_new`，而 attach 模式下 App 的上下文往往在
  挂钩之前就建好了（实测 F-Droid 一轮 5 条 `SSL_WRITE_PLAINTEXT`、keylog 为 0）。
  已补 `SSL_new` + `SSL_get_SSL_CTX` 反查上下文补装（`KEYLOG_INSTALLED … +ssl_new`）。

**HTTP/2：不解这一趟等于白抓（2026-10-18 补）**

第一版只跑 `-Y "http.request or http.response"`，结果 keylog 明明生效、tshark 明明白白
解开了 TLS（`tls.app_data` 上千帧），`http_messages.jsonl` 里却只有 CONNECT 那几条——
因为 **ALPN 协商成了 `h2`**，而 h2 的头在 `http2.header.*` 里，`http.request.*` 一个都不匹配。
所以加了第二趟 `decode_h2()`。三个坑：

| 坑 | 现象 | 解法 |
|---|---|---|
| 分组键少一维 | 请求和响应共用 (连接, streamid)，只按这两维分组 → `:method` 顶掉 `:status`，**有请求没响应** | 键加**方向**：(tcp.stream, streamid, 源 ip:port) |
| `-e` 是包级提取 | 一个 TCP 段塞 SETTINGS+HEADERS+DATA 三帧，`http2.streamid` 给成 `["0","1","1"]` | 用 `http2.type` 与 `http2.streamid` **逐帧同序成数组**做下标对齐，头个数由 `http2.header.count` 给 |
| h2 没有 `decompress_body` | `-o http.decompress_body` 管不到 h2 | 取 `http2.body.reassembled.data` 原始字节自己解；`http2.data.data` 是 Wireshark 解好的，只作兜底 |

**实测（同一份 `capture.pcap` 重解，2026-10-18）**：29 → **31 条**报文（h1=29 / h2=2），
h2 那条是 `GET https://ftp.lysator.liu.se/pub/fdroid/repo/index-v2.json` →
`200 application/json`，body 37016 字节，明文是 `{"repo": {"name": {"ar": "F-Droid"…`
——**gzip 的完整 HTTP 报文拿到了**，这是 M037 留下的那个缺口的正解。

注意 h2 的 body 在这份真包里，Wireshark **没有**替我们解压（`http2.data.data` 以 `1f 8b`
开头），是我自己的 gunzip 兜住的；离线合成用例里 Wireshark 又确实解压了。两条路径都得留着，
所以加了 gzip 魔数校验：**留魔数=没解压，就地解；没有魔数=已解压，不能再解一次**。

`test_pcap_pipeline.py` 现在 **16 条断言**（不依赖设备与外网），新增的 h2 用例造的是
h2c 明文 + 跨 TCP 段的 gzip DATA——正是因为两个方向用同一个 `ip.src` 会让 Wireshark
把它们当成两条会话（`tcp.stream` 0/1），h2 反向就解不出来。这个坑是测试逼出来的。

**还没做**：请求与响应只按 streamid 分到同一个流，没有配对成"一问一答"的事务对象；
`http_messages.jsonl` 目前是**报文级**而不是事务级。要用事务视角得再拼一层。

**keylog 覆盖率：4 轮实测 2/4，且"通过"曾经在骗人（2026-10-18 补）**

| 轮次 | 装配顺序 | keylog 行 | 报文 | 备注 |
|---|---|---|---|---|
| 1 | tls_meta 第 7 位 | 10 | 29 | 拿到 |
| 2 | 同上 | **0** | 2 | 只有明文 CONNECT |
| 3 | tls_meta 提到第 1 位 | 20 | 19 | 拿到 |
| 4 | 同上 | **0** | 22 | 只有明文 CONNECT |

**顺序不是根因**：改序前后各 2 轮、都是 1 成 1 败，没有可测量的提升。失败轮的现象是
`tls_meta ARMED` 了但 `SSL_new` 一次都没触发——应用的 TLS 连接在 agent 装载**之前**
就建好了，之后只是在旧连接上 `SSL_read`，`SSL_CTX_new` / `SSL_new` 早就过去了，
任何"后装回调"都无从补。（改序仍然保留：它更正确，且 privacyMain 抛异常时 keylog 已就位。）

**spawn 在本机 AVD 上不可用**（`exp_spawn_keylog.py` 可复现）：钩子全部 ARMED 之后
`pid 在第 5s 消失`并被重启为新 pid，新进程没有任何钩子，抓到的 TLS 应用数据为 0。
这与 `core/frida_host/run.py` 里早就写着的 "Frida spawn is unreliable on this emulator"
一致，也与之前 LocalSend（Flutter）3s 消失的现象一致——**两个不同技术栈的样本都这样**，
所以不是某个 App 的问题，是这台模拟器的问题。要在真机上才有资格谈 spawn。

**修掉的"假通过"（这条比覆盖率更重要）**：没有 keylog 时，`messages=2` 和 `messages=0`
在报告里长得几乎一样，检查项曾经照常 `passed`——把"解不开"读成"没流量"。
现在 `pcap_http.decode()` 在缺 keylog 时会额外数一遍 `tls.app_data` 帧，写进
`stats.tls_undecrypted_app_data`；`device_run_thirdparty.py` 见到
`keylog=0 且未解密帧>0` 就把 `http_messages_extracted` 判**失败**（optional，不中断整轮），
并在 note 里写明"上面这些不是全部外发内容"。实测该值为 1999 / 2009 帧。

## M039 Flutter / 静态剥符号 BoringSSL：按代码形状定位，不靠符号（2026-10-18）

**结论先说**：不是「看不了明文」，是「没有符号可 hook」。`libflutter.so` 把 BoringSSL
静态链接进去并剥表，实测样本（LocalSend 1.18.2 x86_64）的 `.dynsym` 里**连 `SSL_read`
这个字符串都不存在**——`hook_native_ssl.js` / `hook_tls_meta.js` 对它零挂载且静默。

**做法**：定位 `ssl_crypto_x509_session_verify_cert_chain`，把返回值改成 true。

- 不用社区现有的**整段函数序言签名**（NVISO 2019/2022、reFlutter）：版本一变栈帧就变。
  实测本地样本序言是 `48 83 ec 38` + `[rdi+0xa0]`，而 NVISO 2019 x64 那份是
  `[rdi+0xa8]`——**旧签名直接不命中**（本地验证：`find()` 返回 -1）。
- 改成**锚在解剖学常量上再回扫序言**：函数第一条语句是 `*out_alert = SSL_AD_INTERNAL_ERROR`
  （0x50），编译成 `c6 02 50`（x64）/ `08 0a 80 52 48 00 00 39`（arm64），
  紧跟一次 ssl 解引用。这个"先写 0x50 再解引用"的形状不随栈帧/结构体偏移变化。
- 静态：`mobile/tools/flutter_probe.py` 从 APK 里取 `lib/*/libflutter.so`，报
  stripped 状态并给出 `va` / `file_offset` / 命中的锚点。
- 运行时：`mobile/hooks/hook_flutter_ssl.js` 扫**可执行区间**、回扫序言、`Interceptor.attach`
  后 `retval.replace(1)`。已并入 `hook_all`。

**实测**：

- 静态：LocalSend 1.18.2 x64 → `stripped=true`、`how=anatomy+prologue`、
  `va=0x8113ee`、`anchor_va=0x8113fc`、`gap=4`。
- 运行时：同一 APK 装进 AVD，attach 后日志
  `FLUTTER_VERIFY_PATCHED {offset:"0x8113ee", anchor_offset:"0x8113fc", gap:4}`
  ——**静态与运行时对同一个偏移互相印证**，这是本条最硬的一份证据。

**两个坑**：

- `Memory.scanSync(mod.base, mod.size, …)` 会崩：模块跨度里夹着未映射空洞
  （实测 0x7639a640c000），一次 access violation 就让**整次扫描归零**，表现成
  `FLUTTER_SCAN_MISS`——看起来像"没有这个函数"。必须按 `Process.enumerateRanges('r-x')`
  逐段扫。
- **spawn 注入**（本轮给 `run.py` 加的 `--spawn`）在 LocalSend 上 pid 第 3 秒消失；
  attach 模式正常。原因未查明，**Flutter 样本一律用 attach**，不要默认 spawn。

**仍是边界的部分（重要）**：

- **补丁 ≠ 明文。** 绕过的是证书校验；Dart 的 `HttpClient` **不读 Android 系统代理**，
  所以"装系统 CA + `settings put global http_proxy`"那套对 Flutter 无效。要拿明文还需
  iptables `REDIRECT`/`DNAT` 把 443 引到 mitmproxy 透明模式——**本仓库尚未实现**。
- 因此本轮只证明到"定位准确 + 补丁生效"，**没有** Flutter 明文样本。
- 加固/改名 `libflutter.so` 时扫不到（会记 `FLUTTER_SCAN_MISS`，带模块列表）。

## M040 《用户协议》收进资料库：可引用、独立 scope、绝不替代隐私政策（2026-10-19）

**背景**：合并 ch 时按对方契约把「用户协议」从嗅探词里剔除了（`AGREEMENT_WORDS` 为空），
结果「数据条款只写在用户协议里」的样本什么都拿不到。用户明确要求收「用户协议」，
但**不能**让它冒充隐私政策，否则披露比对会被服务协议稀释成"好像提到了"。

**做法：两段式归类，而不是加回词表**：

1. **发现**（`policy_discover.classify()`）：隐私词优先 → `privacy`；否则协议词 →
   `agreement`；都没有 → 丢弃。一份文档同时写"隐私政策"和"用户协议"时算 **privacy**
   （合并版文档本来就是政策）。`find_in_apk` 两类都返回，带 `doc_kind`，
   排序固定 privacy 在前（`score` 加权 20），`extract_from_apk` 再按
   `(doc_kind, -chars)` 排一次——**协议再长也抢不到主政策前面**。
2. **落盘/入库**：`policy_fetch.save()` 的 meta 增加 `document_kind`
   （`app_policy` / `app_agreement`）；`--from-apk` 只有协议时报 `agreement_only`
   （退出码仍 0：文本可用，但状态不许写成 ok）。
3. **取用**：`policy_library` 新增 `load_app_agreements()`，记录带
   `document_id=AGR-<text_sha256[:16]>`、`supplementary_scope=independent_agreement`；
   `load_policy()` 把它挂到 `app_agreements`，并写一条 gap 说明"不参与披露比对"。
4. **AI/引用**：`stage1_user.md` 增加 `policy.app_agreements` 段；`policy_sources.policy_source()`
   能在 `supporting_documents` 和 `app_agreements` 两处解析 `document_id`；
   `quote_problems` 的 scope 校验改成**按文档自带的 scope**要求（补充告知 =
   `document_scope_only`，协议 = `independent_agreement`），旧文档没声明时仍退回
   `document_scope_only`，不放宽既有约束。

**关键防线（三条都不能松）**：

- `_read_record(expect_kind="app_policy")` 遇到 `app_agreement` 抛 `NotAPolicy`——
  **`--allow-legacy-policy` 下也一样**，否则 legacy 模式会把协议当政策。
- 只有协议时主政策状态是 `not_found`（不是 `invalid`）：`NotAPolicy` 单独收集成 gap，
  不污染"库损坏"判定。
- 主政策 `available=False` 时，协议引文**不能**把条款判成 `met`（复用原有
  "缺少可用主政策不能仅凭附录判 met" 的规则，协议同样适用）。

**代价/已知限制**：`policy_fetch --from-apk` 的 store 没有 package/version 绑定，
入库后 `association_verified=False`（legacy 语义）；要严格绑定仍需走
`prepare_local_policies.py`，其 sources 配置新增可选 `document_kind` 字段。

**测试**：`mobile/policy` 46 项（新增协议入库/只有协议/不触发 ambiguous 三条）、
`mobile/ai/test_policy_sources.py` 10 项（新增协议可引用、scope 不匹配拒绝、
协议不能单独判 met 三条）。

## M041 批量跑批提速：静态并行、动态仍单设备串行（2026-10-19）

**背景**：60 样本批次串行跑约 5 小时，其中 jadx 静态阶段每包 1–2 分钟纯等待。
用户问"能不能多个 APK 一起跑"。核对后结论是：**能不能并行取决于阶段**，
而"同一台设备跑两个包"不是慢的问题，是**归因必然失真**的问题。

**为什么动态阶段不能并行（写下来防止后人再试）**：同一台设备上的可变状态全是全局的——
宿主 `MITM_PORT=8888` 单端口（`reclaim_port()` 会把上一单的 mitmdump 当残留杀掉）、
`settings put global http_proxy`、QUIC 的 iptables 规则、`am start` 只有一个前台、
`pcap_capture.REMOTE_DEFAULT` 固定路径。归因侧的前提是"一个代理 ↔ 一个会话 ↔ 一个包名"
（`VSCAN_PACKAGES` 白名单 + 时间窗就近匹配 + `ATTRIB_TARGET_CHECK`），两个包并发时
两边事件落进同一份代理流量 → `ambiguous` / `unresolved`，甚至静默串包（M020 / D413）。

**做法**：按阶段切分，而不是按样本并发。

1. `batch_plan.py`：先做完**整批判定**（aapt2 解包名、`--resume` 完成判据、
   `--static-reuse` 命中），产出计划表。判定不碰设备，串行几十秒。
2. `batch_static.py`：`ThreadPoolExecutor` 跑静态，默认 3 路。并发安全的依据是三条
   实际核对过的性质：① 产物全在各自 `--out`；② `analysis.scan_static` 用
   `tempfile.TemporaryDirectory()`；③ `toolchain.jadx_jar()` 只解析路径不写缓存。
   jadx 线程数按 `ceil(核数/worker)` 下调并封顶 4——**向上取整**是刻意的：
   `8//3=2` 会让 3 个 worker 只占 6 核，ceil 给 3（合计 9）更好。
3. `batch_dynamic.py`：原动态段整体搬出，行为不变（按样本前置代理 + `--reuse-mitm`
   + `finally` 收树）。
4. `batch_thirdparty.py`：只剩 CLI / 静态并行 / 动态串行 / 汇总。

**顺带修好的断点续跑**：`--resume` 现在也复用**本批次** `_static/<序号>-<短包名>/`
里 `static-manifest.json` 已存在的产物。模拟器约 20 分钟崩一次是常态，
崩后接着跑不该把已解完的 jadx 重解一遍。判据仍是 manifest（完成标记），
不是目录存在——半成品目录长得和成功产物一模一样。

**实测**（本机 15.8 GB / 8 核）：
- 3 个样本（keepass / breezyweather / fdroid）3 路并行 **7m42s** 全部完成，
  三个产物目录同一秒创建、分别结束（真并发）；类数 8177 / 9459 / 9885，
  结论 6 / 12 / 14 条。
- 同批次 `--resume` 复跑 **3.1s**（0 次 jadx），`static_reused_from` 如实记录。
- 根回归 13 组全绿；`run_mobile_checks` 新增 `batch_static` 组（12 项）。

**边界（不要当成已完成）**：并行只提升静态段；动态段仍是 wall-clock 主成本
（每样本 `--seconds 150` + 装包/报告）。要进一步压缩只能上**多设备槽位**
（每槽独立 serial/端口/pcap 路径），那需要把 `MITM_PORT`/`FRIDA_PORT` 参数化，
并修 `core/frida_host/run.py::ensure_forward()` 的跨设备串台（它按
`adb forward --list` 做全局字符串匹配，第二台设备会跳过建转发 → attach 到错的设备）。
本条目不含这些改动。

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

## M042 A1 复核：崩在 JIT 编译线程（不是执行替换入口），后果已兜住 4 类中的 3 类（2026-10-19）

**背景**：文档曾把 A1 标"已修（bridge 补丁 + 单 agent）"。10-19 现场夹具与真实样本仍被打死
（`SIGSEGV @ Jit thread pool`），且旧判据把死亡记成 `alive_at_end=true`（pidof 拿到自动重启的新进程）。

**根因（新证据，完整墓碑）**：崩的是 **JIT 编译线程**在编译某个方法时越界读——
`JitCompileTask::Run → Jit::CompileMethodInternal → JitCompiler::CompileMethod →
OptimizingCompiler::JitCompile → TryCompile → HGraphBuilder::BuildGraph →
HBasicBlockBuilder::Build`，`SEGV_ACCERR` + 页对齐 `fault addr` +
`Cause: possible buffer underflow accessing before secondary allocation`。
即 Frida 克隆/改写 `ArtMethod`（`cloneArtMethod` + `patchArtMethod`）与 ART 把该方法排进
JIT 编译队列并发，编译期拿到的 dex/code item 与 ArtMethod 不再自洽。M029 观察到的
"主线程取指到未映射页"是同一竞态的另一落点。

**已排除**：`VSCAN_NO_STACK=1`（2/2 仍死，说明事件路径的 getStackTrace 不是触发点）；
AOT 预编译（2 死 1 活，有迹象但不构成修复，未采纳）；deopt/JIT-off（旧记录已证伪）。
**放大因素**：模拟器 UWB HAL 每 5s abort，把 `-b crash` 与 `/data/tombstones` 挤掉
（我们的墓碑约 4 分钟后消失），死因因此丢失/被误归属——`cause` 曾被写成 UWB 的
`failed to open the serial device`。

**决策**：不再声称"消除崩溃"（属 bridge × ART 上游缺陷，x64 + API 37 未覆盖区），
改为"**后果逐条兜住 + 概率不恶化**"（不写"全部"：见下方的三处未兜住项）：
1. 分段采集（A4 落地）：死亡即取证 → 重启 → 重新挂钩 → 用剩余时间续采；
   `coverage_window.py` 把窗口换算成 `observed_s/truncated`，写进 `verification.json`。
2. 死因归属：墓碑按记录切块、只认 `Cmdline` 是本包名的记录；logcat 无完整墓碑时从
   `/data/tombstones` 兜底；结构化抽 `signal/thread/uptime_s`。
3. 判据三态：`fixture_selftest` 死亡但有事件 = `degraded`（不再 `passed=true`）；
   批次默认放行但整批标注，`--strict-selftest` 可拒绝。
4. 报告口径：`bundle.gaps` 增加 `[orch]【采集窗口被截断】…`；`orchestrator_notes`
   的样本级说明按包名收敛（原先把 domivega 的四条结论无条件写进所有样本）。

**边界**：上游修复依赖 frida-java-bridge #3700/#3745，或改用 JVMTI MethodEntry /
arm64 设备。详见 `mobile/A1_RESIDUAL_20261019.md`。

**审计核销（2026-10-19 晚，三路独立只读审计）**：初版结论用了"后果全部兜住"，
审计证明这个说法超出证据，已就地改正。审计挖出并已修掉的：
- 终局取证顺序颠倒：先判活后取证，拿不到 death 的段被按墙钟记满 → `truncated=true`
  同时 `coverage_ratio=1.0`。已改为先取证再判活，`observed_s` 取 `min(elapsed, uptime)`。
- `Fatal signal` 行不受 `since_ms` 约束（只有墓碑块受约束）→ 上一轮的 signal 行可被
  算进本段。已加 logcat 行时间过滤。
- `test_values.mjs` 被纯 JS 哈希改动静默打红（`hook_values` 门禁组变红）。已重写用例，
  现绿。
- `values.js` 注释里"args-only 两轮里活下来"是错数据（实际 1 活 1 死），已改。
- 设备端兜底会无条件置 `tombstone_seen=true` 的口径歧义、`tombstone_complete` 只表示
  "有头"、`orchestrator_notes` 只读末段（多段时把"signal 未知"写进报告而 seg0 明明有证据）。

**仍未兜住（照实记，不要当已修）**：
1. **有效观测 ≈ 进程存活，不等于钩子在采**。钩子的 `seconds` 从 attach 起算，而窗口起点
   在 attach 之后 9s（spawn 模式更多），窗口尾部那段没有钩子却记成"已知存活"。
2. **Java 崩溃路径（`FATAL EXCEPTION`）不过滤 pid/since**，且用子串匹配包名
   （`com.foobar` 会命中 `com.foo`）。多段重启下上一段的 Java 崩溃会被算到本段。
3. **钩子中途死掉但应用存活**时，selftest 与 coverage 都看不见（漏报成 `passed`）。

**关于"把 Java 调用移出钩子体"**：根因在 JIT 编译线程，与 trampoline 内是否调 Java
无因果关系；实测纯 JS 版仍 1/2 死于同型 SIGSEGV，与改前无差别（每组 n=2，统计上
说明不了任何事）。它只降低 trampoline 内额外分配/Java 调用的风险，**不是解药，不要
写成"净收益"**。

**新增证据（改写结论的一段）**：`D:/vscanner-tp/ds3-verify-vd/01-lukeneedham-videod/`
是**自然崩溃**（`SIGSEGV @ binder:9433_1`，uptime 49s）后自动重启续采跑通的真实样本：
`segments=2 / deaths=1 / observed_s=79.6/100`，seg1 的 `hook-all-seg1.log` 里确有
`PRIVACY_READ`。所以"自然崩溃 → 重启 → 重新挂钩 → 继续采到数据"这条链已验证；
而 `a4-smoke5` 那组 48.7/60 **同样是自然 JIT SIGSEGV**（其 `app-death-seg0.json` 有
`Fatal signal 11 ... Jit thread pool`，全目录无 `force-stop` 痕迹），此前写成
"`am force-stop` 注入验证"是归因错误，已在 `A1_RESIDUAL_20261019.md` 改正。


## M043 UI 探索状态跨分段存活 + 钩子尾窗补全 + JSONL 只按 LF 分行（2026-10-20）

**触发**：`ds60-sup-1019` 跑到 40/60（进程被杀），体检显示"应用在窗口内几乎不联网"，
但归因、UI、政策三条链路各自的缺陷混在一起，无法判断哪一条是主因。

### D1 探索状态跨分段存活（P1，根因级）

`device_run_thirdparty` 按 `--segment-chunk`（默认 10 秒）**分多次**调 `explore()`——分段
是为了每 10 秒判一次应用是否还活着，不是重开探索。而 `tapped`/`stale`/`scrolls` 全在
`explore()` 的局部变量里，每次调用清零。

实测（40 个已完成样本）：**326 次点击 / 平均 3.0 个不同目标**。
- `40-timer-other`：`Next→Add`（2 轮）→`START STEP→More timer settings`（2 轮）× 5 段
- `35-kerballone-spamblo`：`Settings→Screening`（2 轮）× 5 段
- 每段只有 2 轮，因为 `--segment-chunk=10s` ÷ 每轮约 4.5s（2 次 dump + 点击等待）

改为 `explore(..., state)`：调用方持有一份 `new_state()`，跨段传入；轮次号改全局
（`ui-{r:03d}-*`），顺带修掉**证据被覆盖**——`40-timer-other` 12 次点击，`ui/` 下
只剩 `ui-00`/`ui-01` 两对（每段都从 0 写起）。另加：候选穷尽时 BACK 回退（`MAX_BACKS=6`，
BACK 后前台不是目标包就把预算打满，避免"退出→拉回→再退出"）。

**复核后补的关键一条**：`stale`（点了没反应）与 `no_candidate`（没得点）必须走**同一条
恢复链**。真机上更常见的失败形态是"有按钮、点了界面不变"，它落到 `stale` 分支；原实现
在 `stale` 里只试一次滚动就 `break`，BACK/填输入根本进不去——修复只覆盖了"看得见没得点"
的那一半。现在两级共用 `_recover()`（滚动→填输入→滑回顶部→BACK），且滚动加了
"屏幕真的变了才算恢复成功"，滚不动就换下一种方式。

**这条缺陷不会让任何检查项变红**：taps 照样统计、`ui_taps_made` 照样通过、报告照样印
"交互了 N 次"，只是应用永远走不到联网界面。所以 `test_ui_flow_state.py` 用"两次分段调用
必须点出 4 个不同目标"把它钉住；把状态改回"每次新建"时该用例立刻红（变异验证：
`['Next','Add','Next','Add']`）。

### D2 钩子尾窗（P0 残余，M042「仍未兜住 #1」的另一半）

上一轮只给**主路径**的 `start_hook` 加了余量（spawn 55s / attach 15s）。
**回退 attach** 那处仍传 `args.seconds`，而它之后还有 `sleep(9)` + 一次
`wait_for_app(≤20s)` 才开观测窗口 → 末尾至少 9 秒没有钩子，正好落在项目自己认定的
"延迟读取/延迟外连在后半段"。已改为 `args.seconds + HOOK_MARGIN_ATTACH_S`。

**死亡重启那处不用加**（复核纠正了我第一版的误判）：`remaining` 在死亡时刻算，
钩子还要排在 `am start + wait_for_app` 之后启动（Δ 秒），deadline 天然 = 窗口结束 + Δ。
加 15 秒只是让钩子白活 15 秒，已撤回。

### D3 spawn 失败的两条路合并

`device.spawn` **超时/报错**时应用根本没被启动，而原代码只在"spawn 起来的 pid 又消失"
时回退 attach；前者会直接判 `app_started` 失败并早退（40s 等待白扔）。
`core/frida_host/run.py:resolve_pid` 的注释明确记着本模拟器上 spawn 会超时——所以这不是
理论风险。现在 `not spawn_pid` 与 `spawn_died` 走同一个回退分支，`verification.json` 的
`app_started.note` 会写明回退原因。

### D4 工具侧 JSONL 读取：只认 LF

`core/io_utils` 早已改成 `split("\n")`，但工具侧还有 4 处自己写的 `splitlines()`。
`36-ign-geoportail/session/flows.jsonl` 一条 6.7KB 记录含 **59 个 U+0085(NEL)**
（`response_payload.text` 是 latin-1 解码出的正文），`splitlines()` 把 34 条记录读成
**93 段碎片**。边界要说清：只有**含分隔符的那一条**会被切碎，不影响后面的记录；但本项目
大量判据是"有没有 ≥1 条"，少数几条的下限就足以翻转结论。
新增 `core/io_utils.split_jsonl_lines()` 作为唯一出口。

### D5 政策库接线（P2，只修接线，不伪造覆盖）

`batch_thirdparty.py` / `batch_dynamic.py` 早就支持 `--policy-store`，但守护进程
`supervise_batch.py` 不转发 → **批次永远用不到已准备好的本地库**。已补参数与透传；
启动器只在 `catalog.json` 存在时才传（空目录会多一条误导性的 `explicit_store` 记录）。

**本样本集的政策一致性维度仍然不可判定**：`output/local-policy-library-fdroid` 目前
4 个样本全 `not_found`（这些 F-Droid 小工具仓库里确实没有 PRIVACY.md）。
这不是 bug，报告必须写"未取得匹配政策"，不能写"无政策"或"合规"。

### D6 体检脚本的消费侧误读

`output/_ds60_probe.py` 的 "pids" 读的是 `conns.summary.pids`（= **留下了连接**的进程），
于是体检表把"应用没联网"写成"进程不可定位"。而实际上：有 `pids_seen` 字段的 **12 个
样本全部非空**（都读到了目标进程命名空间）；另外 29 个是该字段出现之前的旧格式，只能用
`rows>0` 推断，无法把"读到了但没连接"与"根本没读到"分开。已改为 `pids_seen`，并另列
"留下连接的进程"一列——两个问题不能互相顶替。顺带修了脚本自己的两处错读：`deaths`
在 `app-death.json` 的 `coverage` 里（原来读顶层，恒为 None）、`?`（解析失败行）不再
计入 `egress_real`。

### D7 conn_probe 的并发：锁要覆盖两个容器

心跳线程每 2 秒 `sorted(pids_seen)` + `len(seen)` + 遍历 `seen.values()`，主线程同时在
`add()` / `seen[key] = rec`。第一次只锁了 `pids_seen`；`seen` 被并发遍历时抛出的
`RuntimeError` 会**把心跳线程整条打死**，此后 sidecar 停在早期快照，而进程常被编排层
kill_tree 强杀（收尾那次写不执行）——落盘的 covered/rows 就是陈旧值。现在两个容器共用
`_state_lock`，心跳线程外另加 try/except，收尾先 `join` 再写最后一次（避免两次
`write_text` 互相截断）。`rows/pid_miss` 等 int 计数不加锁：CPython 下读写原子。

### D8 轮次预算多算了"幽灵轮"

`explore()` 到时间上限时追加的 `stop` 动作带的是**下一个**（没跑过的）轮次号，
`device_run` 原口径把它也算一整轮 —— 实测 `40-timer-other` 每次调用"2 次点击 + 1 条
stop"记 3 轮，`--max-rounds 32` 实际只有 ~22 轮可用。已改为只数 `action != "stop"`。

### 单样本验证（2026-10-20 11:22–11:36，真机 3/3 通过）

报告 `output/VERIFY_20261020.md`，读数脚本 `output/_verify_check.py`。

1. **spawn 在本模拟器上不可用（3/3）**：`openmensa`/`geoportail`/`timer-other` 三个样本
   spawn 起的 pid 都在 6 秒观察窗内消失，全部回退 attach 后才跑起来。与
   `exp_spawn_keylog.py` 的旧结论一致——是 AVD 的问题。代价是可量化的：每样本多花
   `wait_for_app(≤40s)+6s`，且 `openmensa` 因此多一次死亡、`covered=false`（阴性结论只能
   限定在 85.1s）。**启动器已改默认不开 `--spawn-hook`（`SPAWN=1` 显式打开）**。
2. **UI 状态持久化生效**：不同目标/点击数 = 9/10、7/8、9/9（上一批 40 个样本 ≈ 10%）；
   `round` 跨段递增 0..11 / 0..13；`ui/` XML 组数 ≈ 点击数（不再 12 次点击只剩 2 组）。
3. **恢复链在真机上真会触发**：geoportail 出现 `stale→fill_input→swipe_top×2→back`，
   退出去之后继续点到了 `Enregistrés`/`Comparer`/`Filtrer les points d'intérêt`。
   改之前 `stale` 只滚一次就 break，那 70 秒是死的。
4. **钩子盖住了尾窗**：START 之后 +95s 仍有事件（`reads` 17 条、`egress` 5 条）。

**同时被证实的未修项**：keylog 仍 0 行（`tls_encrypted_without_body=411`、明文 body 0）、
`egress` 事件数仍少于 flow 数（keep-alive 复用连接不产生 connect 事件）、夹具自检仍
degraded（A1 JIT SIGSEGV）。**下一个该修的是 keylog**，不是归因。

### 仍未验证

1. **归因的另一半根因**：hook 没盖住非常规网络栈（NDK/重打包 HttpClient/QUIC）也会
   egress=0。"有 pcap 流量而 hook 零事件"的样本还没被逐个对照过。
2. **整批效果**：本轮 3 个样本只能证明机制通了，覆盖率提升要等 60 样本的新批次。

**回归**：`python mobile/tools/run_mobile_checks.py` 28 项全绿（新增
`ui_flow_state` 5 例、`jsonl_tool_readers` 6 例）。

**单文件行数**：`thirdparty_ui_flow.py` 一度被本轮推到 374 行（破 AGENTS.md:28 的 300 行
硬线），已把**界面理解层**（候选打分 / 继承文案 / 三个护栏常量）拆到 `ui_flow_text.py`
（176 行），本体 237 行。`test_ui_flow_label.py` 一行未改——`thirdparty_ui_flow` 原样
再导出那几个名字。

## M044 代码行号三处断链 + keylog 的真边界（2026-10-20）

冒烟批次 5 个样本里 `findings_with_code_loc = 0/55`、`keylog_lines = 0/5`。用户要求先补这两处
再跑全量，查下来一个是**三处断链叠加**，另一个**不是接链问题**。

### 一、代码行号：0/55 → 2/10、2/14（同数据回放）

三处断链，每一处单独都足以让"有栈但无位置"：

1. **栈帧分隔符不认 `" <- "`**。移动端钩子把 `getStackTrace()` 压成一行用 `" <- "` 连接，
   `frames_of()` 只按 `\n` 切 → 整串当一帧 → `FRAME_RE` 要求行尾是 `)`，匹配失败，
   应用帧凭空消失。修：单行且含 `" <- "` 时按它切。
2. **`evt_id` 跨 src 撞号**。`privacy` / `native_ssl` 各写各的 JSONL、编号都从 1 开始，
   分流进同一文件后 13/15/25/27 各对应两条，codeloc 只能如实报"编号歧义"。
   修：finding 增加 `event_refs: [{src, evt_id}]`，`event_lookup.resolve_ref()` 精确解析；
   无 refs 时回落编号（车载旧数据零改动）。**src 对不上仍报缺口**，不借用别人的栈。
3. **R8 混淆后包名没了**。F-Droid 样本大量 R8，栈帧是 `v81.g(...:26)`，`package + '.'`
   前缀认不出来。修：新增 `core/evidence/app_classes.py`，从 `static/dexfacts.json` 的
   `classes`（APK 内全部类名）建类表，命中即应用代码；`android./java./com.android.*` 等
   系统前缀一票否决；类表缺失时回退前缀（只解析首个 dex 时兜底）。

同数据回放（旧 correlate vs 新 correlate，输入完全相同）：

| 样本 | 旧 | 新 | 说明 |
| --- | --- | --- | --- |
| 02 openmensa | 0/10 | **2/10** | sensitive_read 与 over_collection 各一条拿到行号 |
| 01 trail_sense | 0/14 | **2/14** | 同上 |
| 04 towercollector | 0/11 | 0/11 | 11 条全是 `over_permission`，本质无代码位置（非缺陷） |

**报告可见性**：`evidence_bundle` 原来把 `code_locs` 裁掉，PDF 里看不到——已补
`code_locs`/`code_loc_note`；`report_sections` 增"代码位置"一行，渲染放
`mobile/report/code_loc_text.py`（R8 合成文件名压成 `r8-map-id…`，**行号照实显示**）。

### 二、keylog：不是"差接链"，是 attach 模式的结构性边界

三次单样本实测（openmensa×2、towercollector×1）拿到同一组指纹：
`SSL_CTX_new` 有、`SSL_new` 有、`KEYLOG_INSTALLED` 有，但 `TLS_SNI` 0、
`SSL_do_handshake`/`SSL_connect` 0、`SSL_write/read` 0 或"有 write 无 new"。

三种成因用 `mobile/tools/tls_profile.py` 分开（这是本轮真正落地的修复）：

| verdict | 证据 | 含义 |
| --- | --- | --- |
| `reused_session` | 有 SSL 明文、无 `SSL_new` | 会话在钩子装上前建好，窗口内全复用，回调无处可挂（02：27 条明文、0 次 new） |
| `other_tls_stack` | pcap 有加密帧、钩子零 SSL_* | WebView/Chromium 静态 BoringSSL，两条旁路都够不着（03：409 帧） |
| `no_tls_in_window` | 两者皆无 | 应用没被驱动到联网界面（01/05） |
| `callback_not_fired` | 有握手无 keylog | 真 bug，查 `KEYLOG_SETTER_CALLED` 是否被设 NULL |

所以**没有去改 keylog 的采集代码**（改了也拿不到），改为：

1. `hook_tls_meta.js` 新增 `SSL_do_handshake`/`SSL_connect` 观察 + 握手前最后一刻补装
   （`TLS_HANDSHAKE` 事件直接回答"到底有没有握手"）；
2. 新增 `SSL_CTX_set_keylog_callback` 观察钩（只记录谁设的、cb 是否为 NULL）；
3. `http-stats.error` 从笼统的"keylog 未装上"改成 `tls_profile` 的三分法结论——
   原文案把 attach 的已知边界误报成采集链故障，会误导排查方向。

**边界（写进报告口径）**：要覆盖"钩子装上之前就建好的会话"，只有 spawn 注入；本机 AVD
spawn 不可用（M043 实测 3/3 失败）。这一条不是代码能绕过的，只能在报告里如实标注。

### 三、两侧同步与回归

- `hook_tls_meta.js` 的改动已同步到 `vehicle/hooks/hook_tls_meta.js`（parity 守卫会拦）；
  车载 bundle 用 `vehicle/hooks/build.py` 重建（注意：`build.mjs` 只构 4 个脚本，不含
  `hook_tls_meta`，别用错）。
- `run_regressions.py` 13 组全 0；`run_mobile_checks.py` 28 项全绿（codeloc 组新增 6 例，
  并做了两次变异验证：去掉类表分支 → `test_dexfacts_classes_locate_obfuscated_frame` 变红；
  去掉 `resolve_ref` → `test_src_ref_resolves_the_collision` 变红）。
- `check_mobile_branch.py` 的 `mobile_workbench` 5 个 `FileNotFoundError` **与本次无关**：
  workbench 不引用任何被改模块、`git status` 无 workbench 改动、单独重跑同样失败（既存竞态）。

## M045 归因窗口：连接建立到首个请求是 16–29 秒，不是 2 秒（2026-10-20）

### 一、实测：2 秒容差只覆盖 11%

60 个样本里只有 4 个同时有 `egress` 事件与 `flows`。逐条测量"流到最近 connect 事件的距离"：

| 样本 | egress | flows | 2s 内 | 中位 Δ | 最小 Δ |
| --- | --- | --- | --- | --- | --- |
| 34 openmensa | 1 | 14 | 0 | 27.0 s | 23.7 s |
| 36 geoportail | 10 | 34 | 6 | 16.4 s | 0.16 s |
| 38 dsub2000 | 4 | 24 | 0 | 29.3 s | 15.0 s |
| 60 trailence | 12 | 50 | 7 | 708 s | 0.03 s |

合计 122 条 flow，**只有 13 条落在 2 秒内**。归因全量退化为 `single_package_fallback`。

### 二、语义错误：判据本来就不该是双向的

原写法 `abs(event_ts - flow_ts) <= MATCH_TOLERANCE_MS` 默认"事件与流几乎同时"。
但 **TCP 连接一定早于跑在它上面的请求**——中间隔 TLS 握手、应用组包、连接池排队，
十几秒是常态，七百秒也不稀奇（应用挂后台再回来）。

改成有符号判据：

```
-MATCH_TOLERANCE_MS <= (flow_ts - event_ts) <= CONNECT_AGE_MS   # 120 秒
```

即"事件不晚于流（允许 2 秒时钟抖动）+ 年龄不超过 2 分钟"。

### 三、只在 `target_check` 开启时生效

放大窗口必须配目标锚定，否则会把别人 20 秒前连到别处的连接算到这条流头上：
- **移动端第三方跑批**：`thirdparty_env.py` 设 `VSCAN_ATTRIB_TARGET_CHECK=1`，候选必须
  host/ip 对得上 → 放开到 120 秒；
- **车载反向代理**：所有 App 都寻址同一个代理端口，没有目标锚定 → 保持 2 秒。

`CONNECT_AGE_MS` 与窗口开关都写在 `core/collector/attribution.py` 里，一处定义。

### 四、离线重算的收益与边界

对 88 条 flow 用新窗口重算（`output/_attr_after.py`）：**7 → 39 条能归因**，
34 号 0/14 → 14/14、38 号 0/24 → 15/24、60 号 7/50 → 10/50。

**但结论数没有增加**（34/38/60 三次重跑 correlate，findings 数不变）。原因不在归因：
`read_before_egress_within_window` 还要求读取值/形态与报文内容匹配，而这些样本读的是定位、
发的是食堂 API 查询，两者本来就不沾。**归因是必要条件，不是充分条件**——这条要在报告里
如实写，不能把"归因率提升"说成"检出了新问题"。

### 五、历史数据可以回填

`attribution` 是采集期写进 `flows.jsonl` 的，改代码不会自动修正历史产物。
`output/_reattrib.py` 用新引擎重算并输出到独立目录（不覆盖原 session）：
125 条 flow 里 32 条归因发生变化。下次跑批则直接生效。

### 六、副作用与测试

长窗口命中的 `delta_ms` 远大于 `ATTRIB_LOOSE_MS`（1500ms），`is_loose()` 会把它标 loose，
相关结论仍封顶 `candidate`——这是对的：只能写"该连接窗口内的唯一候选"，**不能**写成
"按时间精确对齐"。

- `nearest_egress()` 同步加 `window_ms`（默认不变），`codeloc.attach()` 加
  `connect_window_ms`，`correlate_mobile` 传 `CONNECT_AGE_MS`——车载路径零影响。
- 新增 `ConnectAgeWindowTest` 4 例（20 秒前可归因 / 超 120 秒不归因 / 事件晚于流超抖动不归因 /
  无目标校验时仍按 2 秒）；变异验证：窗口改回 2 秒 → 用例变红。

## M046 ML/LLM 辅助输出的输入边界：只挂 hint/review_priority/needs_human_review（2026-10-21）

**触发**：外部调研 B3 项「ML/LLM 位置约束」。GDPR-Bench-Android（arXiv:2511.00619）
文件级 Acc@1 仅 17.38%，端到端语义判定不可靠，不能当谓词输入。

**决定**：
1. 模型输出只进三个槽：`hint` / `review_priority` / `needs_human_review`；
2. 八谓词（conclusion_level）、severity、risk 分数、档位切分只吃证据链派生事实；
3. 违反进 `validation.warnings`，原样写进报告附录。

**落点**：`RISK_SCORE_MODEL.md` §六之二；报告方法章 9.2 已引 GDPR-Bench 数据作背书；与既有
「不产 policy_violation」一致。无代码行为变化（是输入边界声明）。

## M047 阶段二一致性判定改双字段：disclosure_status × behavior_risk（2026-10-21）

**触发**：B1。旧 `assessment` 把披露轴与行为风险轴混排成单枚举，vague/明文传输的优先级
无法定论；GNChecker 的 OD/VD 定性需要一个干净的披露轴。

**决定**：`per_data_type` 每个条目改两个正交字段——
- `disclosure_status`：clear | vague | ambiguous | omitted | incorrect | not_applicable
  （vague 口径 = 政策写宽泛上位词覆盖具体数据类型；政策层是误报主源，不得凭此升级结论）；
- `behavior_risk`（数组）：over_collection | plaintext_transmission | read_before_consent_unknown。
  
废弃 `assessment` / `also_applicable`。**禁止**不带 `_unknown` 后缀的 `read_before_consent`
（无直接政策接受信号只能标 unknown）。`policy_consent_state` 仍只能 unknown。

**落点**：`stage2_consistency.md` / `stage2_user.md` 判定口径与 schema、`validate.py` 双枚举
校验、`review_contract.py` stage2 分支、`report_ai_sections.py` 一致性章两列渲染。
测试：六个 disclosure 值各一示例 + 越界/非数组/肯定式 read_before_consent 被拦 + 声称收集
必须有取得非空数据的读取证据（64→78 项 AI 测试全绿）。

## M048 PP-TPL 条款组：第三方披露清单只从政策原文出发（2026-10-21）

**触发**：B5-前半。"SDK 清单从政策引用出发，不假设集成"——防编造的第三方面名单。

**决定**：PP 第三个条款组 PP-TPL（在阶段一提示词内生效，PP-TPL-01 逐项列名/目的/数据类别、
PP-TPL-02 禁止宽泛上位词代替结对信息）。`third_parties` 升级：每条带 `tpl_ref`（TPL-xx）、
必须有逐字 quote，无 quote 即假（校验拦截）；政策未提第三方则输出空数组。阶段二新增
`tpl_matrix`（数据类别 × 收集方 TPL-xx × disclosure_status），collector_ref 必须存在于阶段一。
**不新增 DB 条款行**——避免主链政策条款清单级联改动，PP-TPL 在提示词组生效，
`validate_stage(stage, output, bundle, stage1=...)` 增加可选 stage1 参数做跨阶段引用校验。

## M049 报告契约：finding 五要素 + 判定依据矩阵 + 版本/哈希附录（2026-10-21）

**触发**：B2/B4/B8。每条 finding 卡片的信息完整性、判定依据的可统计性、复现性。

**决定**：
1. `finding_missing_elements()` 五要素断言（现象/证据/法规/严重度/整改），缺整改建议渲染
   ⚠ gap 文案并在卡片下印"五要素缺口"；显式 `remediation` 字段可豁免；
2. `section_basis` 2.4 新增规则分布矩阵（规则 ID × 结论等级 × 命中数 × 依据法规条款）；
3. 概览 1.1 工具与模型版本表；附录 C 证据文件逐文件 sha256（`evidence_hashes`，
   排除输出 PDF 与无关后缀）；方法章 9.2 引 GDPR-Bench-Android 17.38% 作「不产
   policy_violation」背书。report 测试 16 项全绿。

## M050 SARIF 2.1.0 导出：静态与 AI 校验两 run 严格分桶（2026-10-21）

**触发**：B9-前半。"消费端不能把 dex 引用候选和 AI 校验问题混成同一类结论"。

**决定**：新建 `report/export_sarif.py`（≤300 行），导出 `static_mobile_supplement.json` +
AI 校验 `validation.json` 为 SARIF 2.1.0：
- run[0] 静态桶：results 全部 properties.evidence_kind=static_reference，location 指向
  类/方法（logicalLocations），等级由 severity 映射 error/warning/note，且源侧已压 candidate；
- run[1] AI 校验桶：problems→warning、warnings→note、全过→ok/none；
- 两桶绝不混排；partialFingerprints 用哈希保证同一条不重复计数。
**schema 校验是硬门**：官方 sarif-schema-2.1.0.json 纳入 `report/testdata/` 作离线测试资产
（SchemaStore 镜像，draft-07），`test_export_sarif.py` 5 例过官方 schema 才放行；
jsonschema 加入运行依赖。

## M051 本轮 P0-3 离线批收口：报告契约全部落地（2026-10-21）

B1/B2/B3/B4/B5-前半/B8/B9-前半 全部完成并各自配离线单测；`run_mobile_checks.py` 全绿。
详见 M046–M050。keylog、UI 探索、hooks native 迁移由并行通道执行，本批未触碰其文件。

## M052 本批 P2 工程债 + P0-2 收口（2026-10-21）

报告与评分的两处超 300 行硬线拆除：
- `report_sections.py` 427 → 290 行：第四章 finding 卡片（`section_findings`/
  `_finding_block`/五要素断言/映射表）拆入新文件 `finding_cards.py`（151 行）。
  卡片渲染的所有私有辅助与 `LEVEL_ZH`/`TYPE_ZH` 一并迁走，`report_sections.py`
  顶部 re-export 保持 `from report_sections import LEVEL_ZH, TYPE_ZH` 等既有引用不变。
- `analyze/risk_score.py` 530 → 299 行：权重常量表与单维权重函数拆入
  `risk_weights.py`（89 行）；档位/置信度/自适应标定拆入 `risk_calibrate.py`（110 行）。
  拆出时不改任何数值与公式，`import risk_score as rs` 的全部符号通过 re-export
  保持可用，`calibrate_risk_bands --self-check` 与 test_client_tls 均过。
- P0-2 收口：`policy_library` 的 `store_missing`（库目录不存在）此前只有实现没有测试；
  `test_policy_library.py` 新增守卫——store 缺失必须返回 `store_missing` 且 gap 含
  `prepare_local_policies.py` 重建指令，禁止被读成 `not_found`（「该应用没有政策」）。

回归：analyze 89 + report 32 + policy 48 自测全绿；`run_mobile_checks.py` 28 项中唯一
failed 为 `hooks_parity`——`stack_capture.js`/`runtime.js` 系并行通道正在修改的
hooks 区文件（vehicle 侧未同步），属并行 agent 收口范围，非本批引入。

## M053 本批 P2 工程债续：policy_fetch / correlate_mobile / test_risk_score 拆分（2026-10-21）

三处超 300 行硬线的零行为改动拆分（纯移动代码，全走"子模块 + re-export"惯例）：
- `policy/policy_fetch.py` 330 → 239 行：网络层（`UA`/`MAX_BYTES`/`TIMEOUT_S`/
  `POLICY_HINTS`/`sha256`/`raw_code_url`/`fetch_url`/`score_link`/`discover_policy_links`）
  拆入 `policy_fetch_net.py`（105 行）。`prepare_fdroid_policies.py` 等外部引用的
  `from policy_fetch import fetch_url, UA` 全部不变。
- `analyze/correlate_mobile.py` 318 → 287 行：同意链四态观测
  （observed / requested_only / not_observed / no_consent_channel）与 gap 文案
  抽为纯函数 `observe_consent`，拆入 `correlate_consent.py`（48 行），
  main() 一行调用替换原内联块。四态语义已被 `test_consent_observation.py` 钉死。
- `analyze/test_risk_score.py` 408 → 267 行：`finding`/`summary`/`SENS` 三个构造
  helper 抽到 `_risk_test_fixtures.py`（31 行，非 test_ 前缀不参与 discover）；
  阈值标定/版本回归/标定工具四类（CalibrationTest/V12/V13/CalibrationTool）拆入
  `test_risk_band.py`（208 行）。两个文件各 `from _risk_test_fixtures import
  finding, summary, SENS`，38 项测试按主题分家后计数与语义均不变。

配套：`run_mobile_checks.py` 的 analyze 组显式补 `test_risk_score test_risk_band`，
拆分前这两个文件只在手动 discover 时跑到，现在进入自动化回归。

回归：policy 32 + `mobile.policy.test_policy_bytes` 1 + analyze 89 + analyze 全
discover 133 全绿；`_risk_test_fixtures.py` 31 行。`hooks_parity` 仍为并行通道
已知失败，未触碰 hooks 区与 UI/keylog 链路文件。



## M054 i2 迁移验证收口 + 栈开关决策（2026-10-21）

### i2 落地状态（validate_native_migration.py，_i2val6 全绿 passed）
- 3 迁移点（sensor_registerListener / camera_open / audiorecord_start）
  NATIVE_MIGRATED × SKIPPED_JAVA 成对证据齐；native 事件实测：camera 1、sensor 1
  （data_types 与 Java 层同构），audio 迁移武装已证但镜像 AudioRecord
  native_setup 不初始化（无麦克风）→ 事件断言降级 warn。
- **linux_connect 不可迁移（定论）**：libcore.io.Linux.connect 为 @CriticalNative，
  entry_point_from_jni_ 为空，槽位守卫拒绝（NATIVE_RESOLVE_MISS 预期输出）。
  egress 的 native 观测由既有 libc connect 层承担（via=native.connect，
  _i2val6 实测 3 条含回环）；Java 层 Linux.connect/BlockGuardOs 原样兜底，不丢覆盖。
- 崩点归属判据：fault_addr/pc 与 3 个迁移入口 ±0x1000 比对；
  _i2val4/5 的 JIT 崩 fault_addr=0x7fe94c400000 距迁移入口 17MB+，非迁移引入。

### A/B 实测与默认决策（用户已确认）
- 无钩基线 95s 存活；开栈 selftest 2 轮 1 活；关栈（NO_STACK=1）2 轮 0 活；
  validator 轮次 4 活 3（7~45s 不等，全为 SIGSEGV@Jit thread pool）。
  WalkStack/GetOatQuickMethodHeader 确定崩（tombstone_05）迁移后不再出现；
  残余 JIT 崩与栈开关无关、频度约 50-75%。
- **决策 D-054a：批量默认开栈保归因**（栈捕获保留，NO_STACK 仅深挖/特殊轮显式启用）。
- **决策 D-054b：残余 JIT 崩接受**，重启+窗口自动分段消化
  （coverage_window 按死亡分段、observed_s 如实呈现、status=degraded 非静默零事件）。

### 注入harness 实测教训（inject_triggers.py / fixture_trigger.js）
- frida-python 下 script console.log 直进子进程 stdout、不走 'message' 信号 →
  判据读 inject-run.log stdout 的 START/DONE。
- Java wrapper 实例属性跨线程失效（线程本地 wrapper）→ 回调载荷改 hashCode
  索引的 PENDING 表；合成类只注册一个共享 Runnable（多次各注册新类会放大
  HBasicBlockBuilder JIT 崩，实测 5 类必现、2 类仍偶发）。

## M055 本批 P2 工程债收口：6 处超 300 行硬线拆分（2026-10-21）

全走「子模块 + 原文件 re-export 薄壳」惯例，外部 `import` 引用面零改动，纯搬移零行为改动。

| 文件 | 原行数 | 拆分产物 | 验收 |
|---|---|---|---|
| `tools/test_app_death.py` | 337 | fixture 模块抽出 | py_compile/import 绿 |
| `tools/pipeline/runner.py` | 305 | 设备启动块出子模块 | 同上 |
| `tools/conn_probe.py` | 482 | 设备侧脚本/日志路径子模块 | 同上 |
| `tools/device_run.py` | 478 | 阶段函数子模块 | 同上 |
| `tools/thirdparty_env.py` | 1196 | 5 子模块（adb/device/pcap/proxy/etc）+ 壳层 | 同上 |
| `tools/device_run_thirdparty.py` | 1110 | helpers + run1~run6 + 薄壳(191 行) | 同上 |

`device_run_thirdparty.py` 拆分要点：
- 6 个阶段模块（head/launch/explore/teardown+decode/armed+finalize/verify）串成 main()，
  `RunCtx`（`__slots__`）在阶段间传值，取代原 main() 巨大局部作用域。
- 循环导入规避：各 run 模块本地定义 `MOBILE/PY/HOOK_MARGIN_*`，不反向 import 壳层；
  壳层将 `MOBILE/PY` 定义提前到 import 子模块之前。
- 行为保真复核点：`app_started` note 的「（回退值：设备解析为空）」需按 head 段解析出的
  `resolved_activity` 是否为空条件追加（原 line 401），`resolved_activity` 经 RunCtx 贯通
  run1→run2，未再写死。
- 复验：8 文件 py_compile + import + `--help` 正常退出（argparse SystemExit 预期）；
  行数均 ≤300（max：run5=295）。全量回归 `run_mobile_checks.py` 27/28 绿，
  唯一 failed `hooks_parity` 属并行通道 hooks/* 工作区，非本批拆分引入。

## M056 keylog 采集链验证收口：链路已证通 + hook_all 残余崩边界（2026-10-21）

- 实证双短板修复：dialog 自动清除（uiautomator dump + BACK 兜底，进程内触发已不依赖
  UI）+ 触发提前（"[tls_meta] ARMED" + 宿主驱动 "collecting" 即注入，不等 58 个 Java API）。
- **链路证明**：tls_meta 单挂对照轮第 1 轮活到握手 → keys.log 5 行完整 TLS 1.3 密钥
  （CLIENT/SERVER_HANDSHAKE_TRAFFIC_SECRET、EXPORTER_SECRET、两向 TRAFFIC_SECRET_0）；
  openmensa 真实样本轮抓到应用自身握手 1 次 + 明文事件 8 + keylog 5 行，之后死于
  SIGABRT@Thread-9（13s，D-054b 家族）。
- **边界记录**：hook_all（全栈 Java 替换 + native attach）下，冷进程任何 TLS 活动在
  connect 窗口 12/12 死亡（SIGSEGV@Jit thread pool @0x7fe94c400000 与 SIGABRT 交替，
  fix4/fix5/fix6 三轮），与触发方式无关（OkHttp / 裸 SSLSocket 同死）；单挂原生钩子
  （零 Java 替换）100% 存活。归因 D-054b 残余 JIT 崩，降 JIT 面方向见 HANDOFF.md。
- 触发实现细节：conscrypt SSLSocketFactory 桥只枚举到 2 个抽象 createSocket 重载
  （createSocket(Socket,String,int,boolean) 可用，createSocket(InetAddress,int) 报
  argument types do not match）→ 触发路径 = 裸 Socket.connect + 工厂包层 + startHandshake。
- 验收口径：keylog 不做 100% 解密承诺，部分解密 + 未解密帧数如实呈现。

## M057 文档治理：失效文档集中归档 + 根 README 重写（2026-10-21）

- **动机**：大量 md 文档过期或不再需要（一次性复核/验证报告、已完成的计划、过时的
  回归计数），且根 README 未覆盖两条产品线与 agent 入口，接手者无从下手。
- **归档**：`TWO_DEV_PLAN.md`、`VERIFY_M031_M032_20261016.md`、`EXPERIMENTS.md`、
  `PLAN_OPTIMIZATION_20261020.md`、`SAMPLE_RUN_5APPS.md`、`docs/DS60_VERIFY_20261020.md`、
  `docs/DS60_FIX_20261020.md`、`docs/FIX_VERIFICATION_20261019.md`、
  `docs/MERGE_NONROOT_AUDIT_20261018.md`、`docs/FUNCTIONAL_FRONTEND_20261019.md`
  共 10 份移入 `archive/`，理由见 `archive/MANIFEST.md` 第 3 条。遵循「保留证据链」
  惯例，不硬删；活跃文档的链接已改为 `archive/...` 相对路径。
- **根 README 重写**：改为「两条产品线 + 平台无关内核」结构，新增产品地图/端口分工/
  快速开始/Agent 读项目入口/能力边界五节，指向 `AGENTS.md`/`mobile/CLAUDE.md`/
  `HANDOFF.md`/`mobile/DECISIONS.md`。
- **计数校正**：`run_mobile_checks.py` 现为 **28 项**（非 24 组），同步修正
  `AGENTS.md`、`mobile/CLAUDE.md`、`mobile/ARCHITECTURE.md`、`mobile/workbench/README.development.md`。
- **复验**：`run_mobile_checks.py` 27/28 绿，唯一失败 `hooks_parity` 为既有已知失败
  （并行通道 hooks 工作区引入，非本次文档改动）；引用扫描确认无悬空链接。
