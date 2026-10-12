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

## 待办（已想清楚要做什么，尚未做）

- **时间窗校准**：30000ms 是从车载侧沿用的**声明值**，未由移动夹具实测校准。
  要做的是跑夹具采集"读取→外发"间隔分布，写 `WINDOW_CALIBRATION.md`，
  再决定是否调整 `rule_gen.DEFAULT_WINDOW_MS`。在此之前报告里如实标注未校准。
- **自有靶子 App**：`fixture-app/` 在建；设备端端到端依赖它。
- **App 类目归属**：目前靠 `--app-category` 手工声明。自动从应用商店信息推断
  会引入不可靠来源，宁可手工声明并标注 `source: declared`。
