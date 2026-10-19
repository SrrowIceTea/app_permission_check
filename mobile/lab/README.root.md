# Root 模拟器真实 APK 基准实验

仅用于授权测试。该模块是综合审计工作台中的独立实验模块，不是流程向导，也不接入 USB 真机。

## 运行范围

使用官方 Ghera 固定提交 `ea1dbe234e4d3433161a3b85e96648913a36e83c` 的原始 APK，
不嵌入 Gadget、不重新签名、不替换成自有夹具，不运行 Malicious 攻击程序。
每次安装后读取安装包并验证摘要与原始工件相同；不同案例复用同一包名，逐个安装、测试、卸载。
发现已有同名应用会停止该样本，不替换或卸载已有应用。

| 原始案例 | APK 数 | 本轮目标证据 |
| --- | ---: | --- |
| BlockCipher-ECB-InformationExposure-Lean | 2 | 实际算法名称、相同输入两次加密结果；裸 AES 模式未解析时不强报 ECB |
| BlockCipher-NonRandomIV-InformationExposure-Lean | 2 | CBC IV 指纹复用、加密结果经 Base64 后与落盘内容精确对照 |
| ExternalStorage-InformationLeak-Lean | 2 | 内外部存储路径、文件与作者随包图片资源摘要相同 |
| OpenSocket-InformationLeak-Lean | 2 | 原始文件内容经 TCP 输出，或明确的 Rejected 拒绝对照 |
| InvalidCertificateAuthority-MITM-Lean | 2 | 自签名本地 TLS 端点被接受，或明确的握手拒绝对照 |

Benign 是作者命名的含漏洞目标，不是安全阴性。Secure 是作者修复版；运行器不按该标签生成发现。
论文基准用于验证检测与取证方法，不代替应用商店真实产品的后续审计。

## 本机已准备的执行环境

- 独立 AVD：`VScanner_Root_API36`，serial `emulator-5562`，Android 16/API 36、x86_64、userdebug。
- root 权限由实际 `id` 的 UID 0 校验；运行器拒绝 USB serial、未 root 环境和重复输出目录。
- Frida Server/宿主版本 17.9.11；原始下载及官方 release digest 见
  `output/root-runtime-20261017/frida-provenance.json`。
- 主机转发 `127.0.0.1:27043` 到该模拟器的 Frida Server；不修改其他设备。
- 全量 DEX 静态扫描复用 `core.static.analysis.scan_static` 与移动端 223 条规则；
  反编译使用现有官方 JADX 1.5.6 Maven 库，不修改共享内核。
- Web 本机端口 8771（当次运行记录；2026-10-19 起 `workbench/server.py` 默认改为 8772），
  基准页为 `/app.html#benchmarks`。

本次启动资料与日志在 `output/root-runtime-20261017/`。没有安装系统 CA、关闭证书验证或修改原应用返回值。

## 复跑入口

先确保上述专用模拟器、同版本 Frida Server 及端口转发已准备；运行器会主动验证，不自动改真实手机。
在仓库根目录、装有项目依赖的 Python 环境中执行：

```powershell
python mobile/audit/compile_probe.py
python -m mobile.lab.root_benchmark --serial emulator-5562 --authorize-benchmarks `
  --jadx-classpath "D:\AAA-Codex\shengsai_app\mobile-app-permission-check-main\.cache\tools\jadx-maven-1.5.6\lib\*"
```

`--java` 可指定 JDK 的 java.exe，默认使用 JAVA_HOME。语料目录默认
`output/benchmark-corpus-20261017/ghera`；可用 `--corpus` 更换保存位置，但提交与 APK 摘要必须一致。
`--kinds ecb cbc` 可限定配对，默认五组十个 APK。每次生成新的 `output/root-benchmark-*/`。
`--out` 若指定，必须是仓库 output 中尚不存在的 root-benchmark-* 目录。

## 产物与工作台

```text
output/root-benchmark-*/
  batch.json                         紧凑索引、真实阶段状态、环境与样本身份
  samples/<sample_id>/
    result.json / assessment.json    实际观察、技术发现、失败原因
    static/                          全量 DEX 静态结果、JADX 源码与日志
    events.jsonl                     原始 Frida 事件及 session/PID/事件引用
    oracle.json                      落盘、端点、UI 等独立对照
    screenshot.png / *-ui.xml        实际设备截图与触发现场
    traffic.pcap / packets.jsonl     网络案例原始抓包与逐包元数据
    tcp-streams.json                 有界 TCP 序列重组、原始包引用
    adb-*.json / observer-errors.json 安装、运行、清理及采集错误
```

工作台通过只读 `GET /api/benchmarks` 枚举批次，并提供登记样本的证据 JSON 接口。
前端展示阶段完成图、实际结果分布、样本筛选和证据链接，不用示例数据补图，不计算虚构准确率。
历史失败批次保留；新的修复后运行生成新目录，不改历史结果。

该页面与现有 APK 上传静态分析并列。现有通用动态按钮仍为自有夹具入口；
不能把“这十个基准已接通”说成“任意上传 APK 都能自动动态审计”。

## 风险评分和真实 AI 研判

风险指标、分值表、复跑方式及证据解释见 [README.risk.md](README.risk.md)。
评分由版本化规则计算，AI 只解释证据，不修改分数；执行成功、风险与合规结论分别展示。

## 网络验证的方法

- 抓包在选定模拟器内通过 root tcpdump 的 any 接口进行，包含 lo/eth0/wlan0，
  本基准过滤到本地测试 TCP 5000；不声称完成所有应用流量归因。
- HTTPS 只连接本机 `10.0.2.2:5000/test/` 的临时自签名端点，不连接真实业务服务、不安装 CA。
- TCP 示例逐字节 write(int)，只逐包搜索会漏掉 `Enter SSN`。因此另外执行有界的按方向/连接代次/
  TCP sequence 重组，保留重传去重、乱序处理、原始 packet refs；不跨缺口拼接。
- 文件上限 8 MiB、每方向流上限 64 KiB；冲突、缺口、序号回绕和截断记 unsupported。
- 原始逐包匹配统计不被重组结果覆盖。TLS 加密包不会因为找不到明文就被判为安全。

## 结论口径

observed 表示预定行为或拒绝控制被真实观察到，不等于已发现违规。
BENCH-* 为本实验的技术观察 ID，不冒充移动规则库中的法规结论。
外部目录可由 root 读取，不证明现代 Android 上其他 App 也可读取；作者随包图片/固定演示文本不是真实个人信息。
IV 复用不等于已泄露明文，安全对照通过不等于整个应用安全。
本基准没有可供研判的真实隐私政策，因此不制造 AI 合规结论。

## 2026年10月18日实际验收

最终目录：`output/root-benchmark-20261018-verified/`，独立摘要 `verification.json`。
十个原始 APK 均完成全量 DEX 静态扫描、全量源码反编译、安装、启动、目标行为观察和卸载清理。
保留 60 条原始采集事件和 4 项技术观察：IV 复用、外部存储放置、TCP 明文示例文件输出、自签名 TLS 接受。
这不是四项个人信息泄露或法规违规定性；修复版的明确拒绝也算目标控制已观察。

前一批 `output/root-benchmark-20261017-full/` 为 9/10，其 TCP 逐包匹配漏报仍保留。
TCP 重组修复后新跑最终十个样本，不覆盖或改写原批次。移动端原有 23 项回归全部通过，
另有 root runner、判定、TCP 重组、SLL/SLL2、批次 HTTP API 与前端模型的定向测试。
真实 APK 通过 Web 上传的静态链也已实测，证据在
`output/root-runtime-20261017/workbench-upload-verification.json`。
