# 非 root Gadget 隐私审计实验

## 2026-10-18：原始 APK 制备与非 root 正式检测入口

现在支持把已获授权的完整 APK 制备为 Gadget 测试衍生包，并接入既有读取/同意/网络/存储采集、关联、三阶段 AI 和 PDF 管线：

- 制备：`python -B -m mobile.repack.prepare --apk ORIGINAL.apk --out output/NEW_REPACK --abi x86_64 --authorize`。
- 采集与正式检测命令见 [README.nonroot.md](README.nonroot.md)，工件及签名变化见 [../repack/README.md](../repack/README.md)。
- 当前专用模拟器使用普通 shell UID 2000，不运行 Frida Server，不使用 root、run-as、系统 CA 或系统代理。
- 原 APK 用于静态/权限/政策身份，动态对象是保留差异记录的重签衍生包；不宣称任意加固 APK 可无条件插桩或全部协议可解密。
- 以下 10 月 17 日章节是初始自有夹具实验记录；其中 run-as 磁盘核对不是当前非 root 正式检测的依赖。

## Root 模拟器真实基准入口

Root 路径运行官方原始 APK，独立展示批次结果；与非 root 衍生包路径分开验收。
运行方式、证据与边界见 [README.root.md](README.root.md)；非 root 真机实验作为另一条独立能力保留。


**真机功能可用入口与操作步骤见 [README.phone.md](README.phone.md)。**
本机 Android 14 user/nondebuggable 真机已完成 Gadget＋VPN 侧车对照；下文保留首轮模拟器实验记录。

以下初始实验只测试自有 `com.vscanner.privacydemo`、合成标记及本机接收端。
研究重点是 **非 root 双通道观测 + 加密/存储值级关联 + 抓包覆盖自检**。
初始实验尚未接入工作台默认采集；新的 APK 制备/正式核心入口见上方。
（**2026-10-19 更新**：工作台现在支持对任意已授权 APK 走 `nonroot-gadget` 一键审计——
原包记录身份 → Gadget 重打包 → 采集 → 关联/AI/报告，见 `workbench/README.audit.md`；
但"支持上传"不等于"任意加固包都能插桩解密"，能力边界仍见下文。）
论文测试集及分层指标见 [README.benchmarks.md](README.benchmarks.md)。

## 2026-10-17 实测

- 复用本机 Android 16/API 36、x86_64 AVD；Emulator 37.1.11、netsimd 0.3.114、Frida/Gadget 17.9.11。
- shell UID=2000，Gadget 在应用 UID 下执行；没有 adb root、su、frida-server、系统 CA 或系统代理改动。
- 镜像是 `userdebug`、`ro.debuggable=1`：属于受限非 root 路径模拟，不是量产 `user` 真机验收。
- 新存储/加密探针收到 17 条真实事件；文件明文和已提交 SharedPreferences 另用自有 Debug 的 run-as 读取核对。
- 捕获 Cipher 的实际 init 方向；解密输入保留为密文，不把任意 byte[] 都标成明文。
- AES-ECB 的完整密文与后续文件写入精确相同；AES-GCM 保留为强算法对照，没有报成弱配置。
- 仅表示应用私有目录内的明文/弱加密存储，不表示已证明其他 App 可读或已经向外泄露。

网络实测（本地服务均收到精确合成标记；计数来自 netsim Wi-Fi PCAP）：

| 对照 | 目标端口 | 包数 | 原始包中的明文标记 | 结果 |
| --- | ---: | ---: | --- | --- |
| HTTP | 18890 | 9 | 1 包命中 | 通过 |
| HTTPS | 18891 | 16 | 0 包命中 | 捕获成功、保持 TLS 密文 |
| 非 HTTP 直连 TCP | 18889 | 10 | 2 包命中 | 通过 |
| UDP | 18888 | 2 | 2 包命中 | 通过 |

Wi-Fi 原始记录 1194 条，1103 条解析到传输层，91 条保留 gap；没有截断记录。
91 条不是“丢包”：包括管理/控制帧、IPv6 扩展及当前未解析协议。原始包仍完整保留。
未测得真实丢包率；未完成 QUIC、IPv6 端到端载荷、多进程、网络切换及量产非 root 真机测试。
PCAP 不自带独立应用 UID 归因，以上由专用端口与本地接收记录验证自有夹具。

### 抓包改进来自一个真实漏抓

第一次只用 `-tcpdump`：服务端收到四组数据，但 PCAP 四个端口全部为零。
尝试给 `virtio-wifi` 增加 QEMU filter-dump 后仍为零，失败证据保留，不能称双抓成功。
本机默认 `-tcpdump` 绑定 `mynet`，新 Wi-Fi 实际经过 netsim。
最终 **radio 的 -tcpdump + netsim --pcap** 才使四组端口全部通过。
Wi-Fi 文件是 Radiotap/802.11、linktype 127，不能用仅 Ethernet 的解析器静默略过。

来源：[AOSP emulator 网络后端](https://android.googlesource.com/platform/external/qemu/+/emu-master-dev/android-qemu2-glue/main.cpp)、
[Android netsim 捕获](https://developer.android.com/studio/run/emulator-networking-advanced#capture-network-packets)。
不同版本必须重新用阳性端点验证，不能仅凭启动参数存在宣称覆盖。

## 两条观测通道

1. **包级通道**：不以是否 HTTP、可解密、命中敏感词作为是否保存包的条件。
   模拟器同时保留 radio 与 netsim Wi-Fi 原始捕获；未知协议也保留。
   真机下一阶段接 VpnService 侧车，优先复用 PCAPdroid，不自研 TCP/UDP 转发栈。
2. **Gadget 进程内通道**：观察敏感读取、存储 API、Cipher 输入输出与算法参数。
   当前新探针范围见 [../audit/README.md](../audit/README.md)，只观察成功返回，不改业务结果。
3. **证据关联**：同包、session、PID、时序窗口内匹配完整值；密文落盘用 `value_exact`。
   这不是完整动态污点传播证明；有界截取、分段写入等未覆盖情况明确列出。
4. **研判**：区分存储明文、弱配置、弱加密写入、网络明文和实际越界泄露。
   大模型后续可用于证据归纳，不能凭抓包缺失生成“未泄露”的结论。

## 复现（仓库根，使用装有 Frida/cryptography 的 Python）

先在新实验目录生成临时本地 TLS 证书，再构建 APK；证书只用于夹具自己的 HTTPS 对照。
已有证书时不要覆盖历史记录，沿用对应已构建 APK 的同一证书和私钥。

```powershell
python mobile/lab/run_probe.py --prepare-cert-only --out output/my-audit
python mobile/fixture-app/gadget_prepare.py --abi x86_64 --version <与宿主相同的Frida版本>
# Gradle 8.13 使用支持的 JDK，本机本轮为 JDK 17；不能用 JBR 25。
mobile/fixture-app/gradlew.bat -p mobile/fixture-app :app:assembleGadget --console=plain
python mobile/audit/compile_probe.py

./mobile/lab/start_emulator.ps1 -Avd VScanner_Mobile_API36_NoRoot `
  -SystemImage D:/Android/system-images/android-36/google_apis/x86_64 `
  -Out <本仓库output/my-audit的绝对路径> -Port 5560
python mobile/lab/run_probe.py --out output/my-audit --serial emulator-5560 `
  --canary VSCAN_TEST_MY_AUDIT --authorize-owned-fixture
```

记录设备配置、shell UID、APK 字节绑定、探针事件、本地接收证据及失败状态。
停止本轮自己启动的实例：`adb -s emulator-5560 emu kill`。
**下次启动 netsim 前，先复制其完整 artifacts ZIP**。本机实际位置在
`%TEMP%/netsimd/netsim_artifacts_*.zip`；以本机实际日志/目录为准，不写死其他用户名。
退出后 netsim 可能把 `pcaps/` 自动归档并清空。解出 WIFI.pcap，保留 ZIP 原件。

```powershell
python mobile/lab/validate_network.py --pcap output/my-audit/radio.pcap `
  --pcap <保存的WIFI.pcap> --receipts output/my-audit/sink-receipts.jsonl `
  --canary VSCAN_TEST_MY_AUDIT --out output/my-audit/network-validation.json
```

包清单 CLI：`python mobile/lab/pcap_inventory.py INPUT.pcap --jsonl PACKETS.jsonl --summary SUMMARY.json`。
支持 classic PCAP Ethernet/raw IP/Radiotap、基础 IPv4/IPv6/TCP/UDP/ICMP；不解密、不重组。
UDP443 仅记 `quic_candidate`，不是已经识别或解密 QUIC。

## 真机侧车与后续验收

拟使用 [PCAPdroid 的 VpnService 模式和控制 API](https://github.com/emanuele-f/PCAPdroid/blob/master/docs/app_api.md)：
`root_capture=false`，目标包过滤，`ip_mode=both`，全载荷保存，关闭主动 Private DNS/QUIC 阻断。
2026-10-17 已补真机侧车部署与四协议对照，见 README.phone.md；VPN 冲突/撤销、双栈和断流仍需扩展验证。
证书固定、native TLS、自绘加密不保证都能解密；加密连接必须仍然进入包级证据。
Gadget 单个进程不等于整个包多进程覆盖；当前 resume 模式不覆盖 attach 前的启动行为。

## 验证记录

- 新增 Python：`mobile/audit` 37 项、`mobile/lab` 19 项通过；Node Hook 语义测试通过。
- 原移动回归 23/23 通过；首次因 GBK 控制台输出失败，设置 UTF-8 后重跑通过，没有改上游测试。
- 原 UI 全链路 180 秒尝试超时，保留失败；上述独立新探针成功不替代该入口的完整验收。
- 输出在 `output/nonroot-lab-20261017*`；最终网络验收在 `nonroot-lab-20261017-netsim/network-control-validation.json`，
  最终存储探针在其 `probe-retry/`，仅此次独立实验通过，不表示整个平台完成验收。
- 本轮仅本地功能分支 `feature/nonroot-gadget-audit`，未提交或推送 Gitee/GitHub。
