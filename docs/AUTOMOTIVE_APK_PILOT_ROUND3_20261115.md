# 车载 APK 第三轮试点：gpsdRelay / Stateful Speedometer / TpmsMonitor

生成时间：2026-11-15 20:30（GMT+8）
设备：`emulator-5554`，AAOS **API 35**（`ro.build.characteristics=automotive`），**user 10**，`x86_64`
工具：`mobile/tools/device_run_thirdparty.py`（窗口 + 钩子 + pcap），`mobile/lab/nmea_tcp_sink.py`（本轮新增）
样本来源：F-Droid 清华镜像 `index-v1.json`；四个 APK 的 SHA-256 **与索引逐字一致**

> 一句话：这轮找到第一个**内容级、可数值对账**的车载业务回执——gpsdRelay 把 333 行 NMEA 发给我们自己连上去的
> TCP 端点，注入的速度与经纬度可以在报文里逐项核对。同时暴露三个工具侧缺口，其中两个是"证据在，报告看不见"。

---

## 0. 一页速览

| # | 样本 | 业务路径 | 独立回执 | 工具侧结论 | 判定 |
|---|---|---|---|---|---|
| A | gpsdRelay 2.2 | 加 TCP 监听 18960 → 启动服务 → 宿主连上去读 | **333 行 NMEA**（RMC 219 / GGA 114），速度 15→22 节两段 | 读取 53 条（getter 全 obtained）、`MOB-R006 observed`、**0 条外发结论** | 业务闭环成立；**外发不可见** |
| B | Stateful Speedometer 0.2.0 | 选 gps provider → 注入速度 | 界面文本 **Speed=33 km/h**（注入 18 节） | 4 条结论（`MOB-R006 observed` + `MOB-O006 candidate` + 2 权限） | 闭环成立；与 Blue Square 同型 |
| C | TpmsMonitor 0.0.1a | 点 `SEE ALL SENSORS READING` | **无**（无 BLE 传感器） | 2 条 `over_permission`、观测事件 1 条 | 可装可起；BLE 扫描不在监视表 |
| D | EDL Dashboard 1.7 | — | — | — | **仅安装**，本轮未跑窗口 |

三个窗口均 `passed=true`、`failed=[]`、未截断、0 次应用死亡。

---

## 1. 样本准入

| 包名 | 版本 | 大小 | min→target | 权限数 | 原生库 | `android.hardware.type.automotive` |
|---|---|---|---|---|---|---|
| `io.github.project_kaat.gpsdrelay` | 2.2 (7) | 1.42 MB | 24→35 | 9 | 无 | **未声明** |
| `com.github.timboode.statefulspeedometer` | 0.2.0 (2) | 1.01 MB | 15→35 | 3 | 无 | **未声明** |
| `nodomain.freeyourgadget.tpmsmonitor` | 0.0.1 alpha (1) | 2.46 MB | 26→28 | 6 | 无 | **未声明** |
| `net.xtlive.EDL.Dashboard` | 1.7 (8) | 3.71 MB | 16→30 | 8 | 无 | **未声明** |

SHA-256（与 `index-v1.json` 一致）：

```
b1c97c1e42a1a191ab5567ca64f099be9a2130362ca1b1c3b288ebbf0267439a  io.github.project_kaat.gpsdrelay_7.apk
6af8e56bf4ef635b8aeff7bd61398ea46e1f728911a5f5c7b6344039f0ba90af  com.github.timboode.statefulspeedometer_2.apk
4813d021e54f02b5e51dae48f525b28ae8f118ec9c5a91cc0a0df955ed162aae  nodomain.freeyourgadget.tpmsmonitor_1.apk
a1fa203acb7ebb578ac829583289eb9c9cadcb9ce4a5e435e29e94b673031307  net.xtlive.EDL.Dashboard_8.apk
```

**筛选口径**：索引 4987 个应用里，按"车域"关键词（obd/can/dashcam/parking/fuel/tpms/odometer/head unit…）得 70 个候选，
其中 44 个带 arm64 原生库（这台模拟器是 x86_64，跑不了），剩下 26 个纯 Java。本轮取其中**业务路径可验证**的 3 个。

**共性结论（第 2 轮已出现，本轮再确认）**：开源生态里被标成"车载"的应用基本都是**驾驶场景的手机应用**，
四个样本全部未声明 `android.hardware.type.automotive`，也都没有 `CarAppService`。任何"车载原生"的结论都不能从这批样本外推。

---

## 2. 场景 A：gpsdRelay —— 第一个内容级回执

### 2.1 业务路径（可重复）

`gpsdRelay` 的语义是**它自己监听**，gpsd 连上来取 NMEA（表单默认 `0.0.0.0` 就是提示）。所以验收链路是：

```
应用：表单填 IPv4=0.0.0.0 / Port=18960（relaying + generation 默认都开）→ 工具栏启动
宿主：adb forward tcp:18961 tcp:18960 → nmea_tcp_sink.py --peer 127.0.0.1:18961 连上去读
```

这比上一轮的"WebView 打开固定 URL"强在两点：**载荷是结构化的**（经纬度/速度/高度），**数值可算**（注入什么就该出现什么）。

### 2.2 回执：333 行，两条流并存

| 来源 | 句式 | 条数 | 校验和 |
|---|---|---:|---|
| Android 框架 GNSS | `$GPRMC,HHMMSS.ss,…`（带 mode 指示 `A,V`） | 105 RMC | **105/105 正确** |
| 应用自产 | `$GPRMC,HHMMSS,…` / `$GPGGA,HHMMSS,…` | 114 RMC + 114 GGA | **11/228 正确**（全部是固定 `*47`） |

同一个窗口里同时有两条流，靠"秒是否带两位小数"就能稳定区分：

```
$GPRMC,122106.00,A,3954.539900,N,11623.820000,E,0.0,0.0,151126,,,A,V*22   ← 框架
$GPRMC,122107,A,3954.5399,N,11623.8200,E,0.00,0.00,151126,0.0,W*47       ← 应用
```

### 2.3 数值对账（本轮最硬的一段）

`adb emu geo fix <lon> <lat> <alt> <sats> <velocity>` 的第 5 个参数是**节（knots）**。三处自洽：
注入 15 → 内核 `vel=7.71666 m/s` → NMEA 里 `15.00`（7.71666 × 1.943844 = 15.000）。

| 注入 | 报文里的取值 | 条数 |
|---|---|---:|
| 未注入 | `0.0` / `0.00` | 2 |
| `velocity=15` | `15.00`（应用）/ `14.999988`（框架） | 110 |
| `velocity=22` | `22.00`（应用）/ `21.99998`（框架） | 107 |

高度也对得上：注入 `alt=50` → GGA 第 9 字段 `50.0`。时间戳比设备时间早 8 小时（UTC），与 `HHMMSS` 一致。

### 2.4 样本自身的缺陷：校验和是常量

228 条自产句子里，`*` 后面**全部是 `47`**。按 NMEA 0183 重算：

```
$GPGGA,122107,...,0.0,M,0.,M,,,*47   实际应为 *71  → 错
$GPRMC,122115,...,15.00,...,W*47     实际应为 *54  → 错
```

固定校验和意味着**内容一变就错**，只有 11 条碰巧等于 `0x47`。任何做校验的解析器（gpsd、大多数车载导航栈）
会把其中 95% 的句子直接丢弃。这条不是我们工具的缺陷，是样本行为，但它解释了"为什么用 gpsd 接这个 App 会没数据"。

顺带：GGA 的 geoid 字段写成 `0.,M`（缺小数位），严格解析器会报格式错。

### 2.5 工具侧看到了什么

| 通道 | 结果 |
|---|---|
| 钩子读取 | 188 条事件 / 53 条 `PRIVACY_READ`：4 条订阅（`observe/empty`）+ `getLatitude/getLongitude/getSpeed` 全部 `obtained` |
| 结论 | `MOB-R006 sensitive_read observed`（precise_location）、`MOB-O006 over_collection candidate`、8 条 `over_permission` |
| pcap | **629 个包**在 18960 端口，载荷可还原 NMEA（`244750524d43…` = `$GPRMC…`） |
| flows（mitm） | **0**（裸 TCP，不走 HTTP 代理） |
| egress（钩子外发） | **0**（应用是监听方，没有出站 connect） |
| `http_messages_extracted` | 27 条报文、**归属被测包 0/27**（都是别的应用的 HTTP） |

**因此：一个持续把精确位置发给外部客户端的应用，在现有判定里没有任何 `data_egress` 结论。** 这是本轮最需要记住的一条。

---

## 3. 场景 B：Stateful Speedometer —— 与 Blue Square 同型的对照

- 路径：启动 → `Select location provider` 选 `gps` → 注入 `velocity=18`；
- 回执：界面文本 `Speed=33 km/h`（9.26 m/s × 3.6 = 33.3，截断成 33），另有 `Distance since last gas refill 0.0000 km`；
- 结论：4 条——`MOB-R006 observed` + `MOB-O006 candidate` + `MOB-P003/P004`；
- 与第 2 轮的 Blue Square（3 权限、仅定位、4 条结论、`Speed=27`）**完全同型**。两个独立实现给出同一剖面，
  说明这组结论不是某个 App 的特例。

窗口 85.1s / 85s，未截断，0 死亡；`http_messages_extracted` 同样因"17 条报文 0 归属"判红（别人的流量）。

---

## 4. 场景 C：TpmsMonitor —— 能起，但没有业务数据

- `aapt2` 与 dex 检查：`BluetoothLeScanner.startScan` + `ScanCallback`（BLE 扫描），权限只有 `BLUETOOTH`/`BLUETOOTH_ADMIN`/`ACCESS_COARSE_LOCATION`；
- 界面只有一个按钮 `SEE ALL SENSORS READING`，点进去是**空列表**；
- `dumpsys bluetooth_manager` → `Number of Ble app registered: 0`（扫描未注册/已停止）；
- 工具侧：22 条读取事件里**只有 1 条观测事件**，0 条 `PRIVACY_READ`；结论 2 条（`MOB-P004` COARSE、`MOB-P021` BLUETOOTH）。

**覆盖缺口**：规则库的蓝牙条目只有 3 个"身份读取"接口——`BluetoothAdapter.getAddress / getBondedDevices / getName`，
**没有 `BluetoothLeScanner.startScan` / `stopScan` / `BluetoothAdapter.startDiscovery`**。也就是说，胎压/车载配件这类
"靠 BLE 找设备"的场景，即使应用真的扫了，我们也一条都记不到。

---

## 5. 本轮暴露的工具缺陷

### D1（高 · **已修**）pcap 解码只认 HTTP，裸 TCP 的业务载荷等于不存在

`pcap_http.decode()` 只提 HTTP/1.1 与 h2。NMEA 是行协议，于是：

- pcap 里**有**：`tshark -Y "tcp.port==18960 && tcp.len>0" -T fields -e tcp.payload` → `244750524d43…`；
- 报告里**没有**：`http_messages.jsonl` 0 条 NMEA，判据只能写"27 条报文 0 归属"。

复现：

```bash
output/_tools/wireshark/tshark.exe -r output/auto-apks-20261115/run-gpsd2/capture.pcap \
  -Y "tcp.port==18960 && tcp.len>0" -T fields -e tcp.payload | head -1
# 244750524d432c3132323130362e30302c412c…  → $GPRMC,122106.00,A,…
```

影响：MQTT / gpsd / LwM2M / 自定义 TCP 上报这几类**车载最常见的上报方式**都读不到正文。修法不复杂：
按端口把可打印的行切出来、`$G`/`$GNTXT` 之类做类型标注，再走同一套 `http_attribution` 归属。

### D2（高 · **已修·证据层**）外发判定不覆盖"应用是监听方"的模式

现有两条外发证据都假设应用**主动发起**连接：

- `flows.sqlite`（mitm）只看得见走系统代理的 HTTP；
- `egress.jsonl`（钩子）挂的是 `connect()`。

gpsdRelay 是监听方，数据从入站连接流出，两边都空。报告里因此只有 `over_permission` 和 `over_collection candidate`，
**没有一个字说"它把定位持续发出去了"**——而这件事我们有 333 行报文作证。

修法方向：pcap 侧按「被测 uid 的本地端口」双向归属（D1 做完就顺带解决一半）；`conns.jsonl` 里已有
`LISTEN` 记录和 uid 1010290，信息是够的。

### D3（中 · **扫描调用已验证，传感器结果待验**）规则库缺 BLE 扫描 API

见 §4。补 3 条 seed（`BluetoothLeScanner.startScan/stopScan`、`BluetoothAdapter.startDiscovery`，角色 `observe`，
数据类型 `bluetooth_info`）即可，走的是上一轮验证过的 `seed → extract → build → patch_bundle` 链路。

### D4（已修）受控窗口默认 `uninstall` 会毁掉"业务前提就是既有配置"的夹具

gpsdRelay 必须先有一条服务器配置；TpmsMonitor 要先配对传感器。默认流程 `uninstall + install -r` 把 DataStore 一起清掉，
窗口内再手配既耗预算又引入"配置是否生效"的不确定性。

修法：新增 `--skip-install`。判据写成 `pre-installed：沿用设备上的既有安装与配置…本条不证明样本来自本次 APK 安装`，
不冒充干净安装。

### D5（已修，回执端）`adb forward` 的空连接会被误判成"读到 0 行"

宿主侧 `connect` 总是成功（adbd 先接受），设备侧端口没开时 adbd 立刻关闭 → 表现为"连上 0.01 秒、读到 0 行"。
第一版回执端就此退出，看起来像"应用没发数据"。

修法：`nmea_tcp_sink.py` 把空连接记为 `PORT_NOT_READY` 并重试；本轮实际发生 2 次，第 3 次连上后读到 333 行。

### 附带：应用内配置没有声明式记录

本轮在应用里加服务器、开开关、选 provider，全是坐标点击（`input tap 1345 633` 这类）。报告能写清"点了哪里"，
但换一台分辨率不同的设备就不可复现。缓解办法已落地一半：把配置库导出成夹具
（`output/auto-apks-20261115/gpsd-clean.db`，Room 表 `Server(type=1, ipv4=0.0.0.0, port=18960, relaying=1, generation=1)`），
下轮 `adb push` 回去即可跳过界面配置。

---

> **处置结果（2026-11-15 20:50）**：D1/D2/D3 与“声明式 UI”已在 [FIXES_20261115_ROUND3.md](FIXES_20261115_ROUND3.md) 处置。
> D1 真机验过（101 行 NMEA 归属被测包）；D2 的 `egress_channels` 已进 summary；
> D3 规则与 bundle 就位，但没有实机阳性样本（原因见该文 §4.3）。

> 后续复验在 AAOS 上取得 132 条窗口内独立回执，与 pcap 逐条一致。已确认应用 UID 的 NMEA 定位载荷可进入 `MOB-E006` 形态与时序关联。自有 BLE 夹具已验证扫描调用。见 [开发日志](DEVELOPMENT_LOG.md)。

## 6. 与上一轮的能力对照

| 能力 | 第 2 轮 | 本轮 |
|---|---|---|
| UI 文本回执（速度/高度） | ✅ Blue 27 / Roam 36、53 | ✅ Stateful 33 |
| **内容级回执（报文正文可对账）** | ❌ | ✅ **333 行 NMEA** |
| 裸 TCP 上报可见 | ❌ | ⚠️ pcap 可见、报告不可见（D1） |
| 应用作为监听方的外发 | — | ❌ 无结论（D2） |
| BLE 扫描 | — | ❌ 不在监视表（D3） |
| 需要预置配置的样本 | ❌ 会被卸载清空 | ✅ `--skip-install` |
| 夹具可复现 | — | ⚠️ 有 DB 夹具，无声明式 UI 脚本 |

---

## 7. 证据索引

```
output/auto-apks-20261115/
├── io.github.project_kaat.gpsdrelay_7.apk          # 样本（sha256 见 §1）
├── com.github.timboode.statefulspeedometer_2.apk
├── nodomain.freeyourgadget.tpmsmonitor_1.apk
├── net.xtlive.EDL.Dashboard_8.apk                  # 仅安装
├── gpsd-clean.db                                   # 配置夹具（Room: Server/Settings）
├── sink-gpsd/receipts.jsonl                        # ★ 333 行 NMEA 回执（含校验和判定）
├── run-gpsd2/                                      # 场景 A
│   ├── verification.json  coverage.json  http-stats.json
│   ├── capture.pcap                                # 629 包 @18960，含 NMEA 载荷
│   ├── out/summary.json  out/findings.jsonl
│   └── session/reads.jsonl  session/conns.jsonl
├── run-speed/                                      # 场景 B
├── run-tpms/                                       # 场景 C
└── mobile-regression-round3.log                    # 63/63
```

---

## 8. 下一轮建议顺序

1. **D1**（pcap 行协议提取 + 双向归属）——一次改动同时解掉 D1/D2 的一半，收益最大；
2. **D3**（补 BLE 扫描 API）——走已验证的 seed→bundle 链路，1 小时内可完成；
3. **D2 的剩余部分**：在 `summary` 里对"监听型外发"给一条显式缺口，而不是静默 0；
4. 用 `gpsd-clean.db` 夹具 + `nmea_tcp_sink.py --peer` 把场景 A 做成**可一键复跑**的回归项；
5. 仍未触碰：split APK、OEM 特权包、多 App 同窗口归因、准确率、长稳与驾驶态。
