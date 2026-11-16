# 车载 APK 第四轮试点：AndrOBD × 假 ELM327（诊断仪）

生成时间：2026-11-15 21:40（GMT+8）
设备：`emulator-5554`，AAOS **API 35**（automotive）、**user 10**、`x86_64`
样本：`com.fr3ts0n.ecu.gui.androbd` **V2.7.10**（`versionCode=20710`，`targetSdk=36`，SHA-256 前缀 `71d3cecd69b644da`）
新增工具：`mobile/lab/elm327_tcp_sink.py`（宿主侧 ELM327 应答端，本轮新增）

> 一句话：这轮第一次让**车载诊断类**应用真的跑通业务——不是看界面，是让它连上一个我们控制的
> ELM327，回执端逐条记账。同一份 pcap，修前解码 **0 行**、修后 **4419 行**，外发从"看不见"
> 变成 `pcap_line_from_app=2210`。缺陷在**行分隔符**上：ELM327 整条会话只有 CR，没有 LF。

---

## 0. 一页速览

| # | 事 | 修前 | 修后 |
|---|---|---|---|
| A | AndrOBD → TCP 35000 → 假 ELM327 | 连上、`ECU detected`、窗口内 2370 条请求 | 连上、窗口内 2503 条请求（含 `0113/0115/011C` 真 PID） |
| B | 行协议解码 | **0 行**（`line-messages.jsonl` 空） | **4419 行**（`obd` 4418），归属 100% |
| C | 外发 | `pcap_line_from_app = null` + 缺口文案 | `pcap_line_from_app = 2210`，`from_app/to_app = 2210/2209` |
| D | 逐轮判定 | `status=failed`（`report` 红） | `status=passed`，`failed=[]` |

窗口：120s / 120s，未截断，0 次应用死亡，`business_action_made` 记录 2 条人工动作。

---

## 1. 样本与夹具

### 1.1 为什么挑它

前三轮已经把"定位类"（Blue Square / Stateful / gpsdRelay）走完了，缺的是**另一条车域协议**。
AndrOBD 是 F-Droid 上最常用的开源 OBD-II 诊断前端，业务链路是"连适配器 → 读 ECU → 显示测量值"，
协议是 ELM327 的 AT 命令 + 十六进制 PID，正好补上前三轮没碰过的**命令-应答型**业务。

### 1.2 预置配置（可复现，不靠点坐标）

设备上的配置是 root 直写 `shared_prefs`，键值固定：

```xml
<string name="comm_medium">4</string>          <!-- 4 = NETWORK -->
<string name="device_address">10.0.2.2</string> <!-- 模拟器到宿主的别名 -->
<string name="device_port">35000</string>
<string name="protocol">0</string>              <!-- AUTO -->
<int name="LAST_ECU_ADDRESS" value="2024" />    <!-- 0x7E8 -->
```

夹具：`output/round4-elm-fixed/androbd-prefs.xml`（**user 10** 的路径是
`/data/user/10/com.fr3ts0n.ecu.gui.androbd/shared_prefs/`，写成 `/data/data/…` 会看到"没有这个目录"）。

> 适配器类型列表一次只渲染一行，要**滑动**才能看到 `NETWORK`（5 项：DEMO / BLUETOOTH / BLE / USB / NETWORK）。
> 这一条坑了半小时：`uiautomator dump` 只给可见项，看起来像"只有 DEMO 可选"。

### 1.3 回执端

`mobile/lab/elm327_tcp_sink.py`：监听 35000，按 ELM327 语义回
`ATZ/ATE0/ATL0/ATS0/ATAT0/ATSP0/ATH0|1`、`01xx`（22 个 PID，值写死在表里便于对账）、`0902`（VIN，ISO-TP 多帧）、`03/04`。
每条请求/应答写 `receipts.jsonl`，退出时汇总 `receipt.json`。

---

## 2. 业务路径与回执

```
AndrOBD（Network 适配器）──TCP──▶ 10.0.2.2:35000 ──▶ elm327_tcp_sink.py
        ▲                                              │
        └──────── 41 0C 1A F8（1726 rpm）/ 41 0D 58（88 km/h） ┘
```

| 项 | 修前窗口 | 修后窗口 |
|---|---:|---:|
| TCP 连接数（回执端 accept） | 2 | 1 |
| 请求条数 | 2370 | 2503 |
| 主要命令 | `0100` ×2354（ECU 探测一直没成功） | `ATSP0` ×609、`0113/0115/011C` 各 ×152 |
| 应用状态 | `ECU detected` → 反复重发 `0100` | 同上，但已进入 PID 轮询 |

两轮都拿到了**内容级回执**：回执端收到的每个字节都在 pcap 里，pcap 里的每行都能追到回执端的账本。
这一轮的回执强度不如第三轮 gpsdRelay（那是应用**发**数据给我们），但方向相反——
这次是**我们发数据给应用**，验证的是"入站应答能不能被工具看见"。

---

## 3. 缺陷 D6（高 · 已修）：只认 LF 的行切分，让 CR-only 协议整体消失

### 3.1 现象

修前窗口：回执端 2370 条请求、pcap 里 4051 个载荷包，`line-messages.jsonl` **0 字节**，
判据 `line_payload_attributed` 红，`egress_channels.pcap_line_from_app = null`，缺口写
"未找到可确认边界的 UTF-8 TCP 文本行"。

pcap 里明明有：

```
$ tshark -r capture.pcap -Y "tcp.port==35000 && tcp.len>0" -T fields -e tcp.payload | head -2
41545a0d                                  → "ATZ\r"
454c4d3332372076312e350d0d3e              → "ELM327 v1.5\r\r>"
```

### 3.2 根因

`tcp_line_reassembly._lines()` 只按 `\n` 切。ELM327（以及大量 AT 命令口）**整条会话一个 LF 都没有**，
于是缓冲里永远找不到行尾：全部计入 `partial_lines`，一条完整行都不产出。
D1（第三轮）修的是"只认 HTTP"，这一层更深：认了行协议，但只认 LF 结尾的行协议。

### 3.3 修法

`_separator(data)`：有 LF 按 LF（CRLF 归它），一个 LF 都没有才退到 CR。

```python
if b"\n" in data: return b"\n"
if b"\r" in data: return b"\r"
return b"\n"
```

配套在 `pcap_lines.classify()` 里加 ELM/OBD 识别，并剥掉 `>` 提示符（它会粘到下一句前面变成 `>ATZ`）：

| `obd_kind` | 判据 | 本轮行数 |
|---|---|---:|
| `at` | `AT…` / `ST…` | 543 |
| `status` | `OK` / `?` / `NO DATA` / `SEARCHING...` 等 | 1077 |
| `hex` | `41 0C 1A F8` 这类空格分隔大写十六进制 | 1131 |
| `pid` | `0100` / `011C` / `0902` 这类请求 | 1667 |

### 3.4 实机结果（`output/round4-elm-fixed/run`）

```
line_payload_attributed = 0（通过）
  确认应用发出 2210/4419 行，监听端口候选 0 行
egress_channels = {proxy_flows: 0, hook_egress: 2, pcap_http_attributed: 0,
                   pcap_line_from_app: 2210, pcap_line_basis:
                   {socket_inode_bracket: 4389, tcp_stream_socket_inode: 30},
                   pcap_line_proto: {obd: 2210}}
```

方向分布 `from_app 2210 / to_app 2209`——**双向都归到了被测包**，不再是"只能看入站"。
同一份修前 pcap 离线重解也复现了：0 → 4051 行（`output/round4-elm-baseline/redecode-lines.jsonl`）。

新增回归：`mobile/tools/test_pcap_lines.py` 4 条（CR-only 切分 / LF 优先 / AT 与 hex 分类 / 提示符剥离），
连同 `test_egress_channels`、`test_http_attribution` 共 **33 条全绿**。

---

## 4. 缺陷 D7（中 · 已修）：报告阶段缺 `reportlab`，整轮被判失败

修前 `verification.json`：`failed: ["report"]`，`report.log` 里是
`ModuleNotFoundError: No module named 'reportlab'`。

这不是代码缺陷，是**环境依赖**：采集、关联、判据全过，最后一步出 PDF 时整轮翻红，
看起来像"这轮白跑了"。已用项目解释器装好（`reportlab 5.1.0`），修后同命令 `status=passed`。

> 处置建议：`device_run_thirdparty` 在开跑前检查报告依赖，缺失时**降级为"不出 PDF 但不判失败"**，
> 而不是跑完 3 分钟再红。本轮先按"装依赖"处理，不改判据语义。

---

## 5. 缺陷 D8（中 · 已修）：Windows 上 `SO_REUSEADDR` 让两个回执端同时监听

排查"连不上"时发现：`netstat` 里 35000 有**两个** LISTENING（旧回执端没退干净、新回执端又绑成功），
连接落到哪个不确定——表现是"新回执端在跑，但一条命令都没收到"，日志全进了旧进程的账本。

修法：Windows 用 `SO_EXCLUSIVEADDRUSE`，类 Unix 才用 `SO_REUSEADDR`。
这条不是被测应用的问题，是**搭夹具时最容易得出错误结论**的一类坑（"应用没连"其实连了）。

---

## 6. 未解决 / 未验证

| # | 项 | 现状 | 影响 |
|---|---|---|---|
| D9 | `uiautomator dump` 在这类持续重绘的界面上恒返回 `ERROR: could not get idle state` | **未修**；本轮改用坐标点击 + 截图核对 + `log_action` 登记 | `ui_script` 的 `wait_text/tap_text` 在该样本上不可用；换设备分辨率后不可复现 |
| D10 | 回执端**按 ELM327 真实语义**回 ISO-TP 头（`7E8 06 41 00 …`）时，AndrOBD 探测完 ECU 后 6s 主动断链 | **未解释**；本轮对照窗口用 `--header-mode off`（复现"劣质适配器"） | 业务回执只能到"命令-应答"级，没拿到界面上的数值 |
| — | 数值级回执（界面上出现 1726 rpm / 88 km/h） | **未取到** | 应用的数据页始终空列表，PID 轮询发生在后台，界面不显示数值 |
| — | `http_messages_extracted` 仍红 | 既有结论（别人的 HTTP 报文 0 归属） | 与本轮无关，不冒充通过 |
| — | split APK / OEM 特权包 / 多 App 同窗口归因 / 准确率 / 长稳 | 仍未触碰 | 见第三轮 §8 |

---

## 7. 证据索引

```
output/round4-elm-baseline/            # 修前（同一份代码、同一夹具）
├── sink/receipts.jsonl                # 2370 条请求，0100 ×2354
├── run/capture.pcap                   # 4051 个 35000 端口载荷包
├── run/line-messages.jsonl            # 0 字节 ← 缺陷现场
└── redecode-lines.jsonl               # 修后离线重解：4051 行
output/round4-elm-fixed/               # 修后
├── sink/receipts.jsonl                # 2503 条请求（ATSP0/0113/0115/011C）
├── androbd-prefs.xml                  # 配置夹具（comm_medium=4 / 10.0.2.2:35000）
├── actions.jsonl                      # 2 条人工动作
└── run/{verification.json,line-messages.jsonl,capture.pcap,out/}
    line-messages.jsonl = 4419 行（obd 4418），归属 4419/4419
```

代码改动：
`mobile/tools/tcp_line_reassembly.py`（`_separator`）、`mobile/tools/pcap_lines.py`（`obd` 分类 + 提示符剥离）、
`mobile/tools/test_pcap_lines.py`（+4 条）、新增 `mobile/lab/elm327_tcp_sink.py`。

---

## 8. 下一轮建议

1. **D9**：给 `ui_script` 加"非 idle"降级（`dumpsys window` + accessibility 事件，或 dump 失败即改用坐标 + 截图），
   否则任何动画/轮询界面都只能靠人肉坐标；
2. **D10**：查 AndrOBD 断链原因（抓 logcat `CommService`），把"真实语义应答"跑通，才能拿到数值级回执；
3. 把本轮做成回归项：`elm327_tcp_sink --header-mode off` + `--skip-install` + 固定 prefs，一条命令复跑；
4. 仍未触碰：split APK、OEM 特权包、多 App 同窗口归因、准确率、长稳与驾驶态。
