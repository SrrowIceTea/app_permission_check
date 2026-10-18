# 真机非 root：功能可用阶段

入口是 `mobile/lab/run_phone.py`，不是模拟器脚本，也不需要 frida-server。
仅安装、运行自有合成夹具 `com.vscanner.privacydemo`；PCAPdroid 作为独立 VPN 侧车。
不读取用户其他应用数据，不安装系统 CA，不修改设备全局代理。

## 阶段范围

- ARM64 Frida Gadget 与宿主版本一致，装入自有源码的 Gadget 构建变体。
- 文件明文、SharedPreferences 字符串、Cipher 实际加解密方向与 ECB 弱配置观测。
- 同会话/同 PID 的完整密文与后续文件写入精确匹配；GCM 不误报为弱配置。
- PCAPdroid VpnService 按自有夹具过滤、IPv4/IPv6 配置、完整载荷、无主动 QUIC/Private DNS 阻断。
- 实际捕获 HTTP、HTTPS、非 HTTP 直连 TCP、UDP；HTTPS 仍保留密文，不冒称解密。
- 采集前后检查 VPN 存活；结束后正常停止、导出 PCAP、检查包与本地接收端双向证据。
- 无数据、未授权、断流、脚本错误、只有 TCP 没有 UDP 均不能报告完整通过。

此阶段不等于任意第三方 APK 无条件插桩；Gadget 需要合法装入对应进程。
SQLite/native 存储、QUIC 内容解析、多进程及 attach 前启动行为仍不在本阶段验收范围。
当前规则与完整值关联是确定性判定，不把在线大模型存在与否作为这些检查的前提。

## 已准备环境下，一条命令运行

在仓库根目录执行，选用安装了本项目依赖的 Python。本机实例：

```powershell
.\..\mobile-app-permission-check-main\.venv\Scripts\python.exe mobile/lab/run_phone.py `
  --serial ddec7e66 --host 192.168.31.43 `
  --cert-dir output/phone-functional-20261017 `
  --out output/phone-my-next-run `
  --canary VSCAN_TEST_PHONE_MY_NEXT_RUN --authorize-owned-fixture
```

- `--serial` 是明确选择的真机，`--host` 是手机可访问的本机 LAN IPv4。
- `--out` 每轮新建，不能覆盖之前的运行目录；canary 只允许合成 `VSCAN_TEST_*` 标记。
- PCAPdroid 首次安装后，以及通过 adb 再次请求时，设备可能弹出控制授权；需在设备确认。
  脚本等待最多 180 秒，不通过密钥/系统设置绕过授权。
- 服务器只绑定给定本机 IP，不绑定所有网卡；本机防火墙需允许实验端口 18888–18891。
  UDP 走 LAN，不用仅支持 TCP 的 adb reverse 假装 UDP 抓包通过。
- HTTP/HTTPS/TCP/UDP 全部只向该本机实验接收端发送合成标记。
- 设备须保持解锁，允许通过 USB 安装自有夹具；安装受设备策略阻止时按真实失败输出。

## 换设备、IP 或证书后的准备

```powershell
python mobile/fixture-app/gadget_prepare.py --version <宿主实际Frida版本> --abi arm64-v8a
python mobile/lab/run_probe.py --prepare-cert-only --transport lan `
  --host <本机LAN-IP> --out output/phone-cert-new --replace-test-certificate
mobile/fixture-app/gradlew.bat -p mobile/fixture-app :app:assembleGadget --console=plain
python mobile/audit/compile_probe.py
```

证书只由自有夹具的该次测试连接信任，不安装进系统信任库。替换证书后必须重建 APK；
证书在 APK 内和本地服务端一致才允许运行。临时证书有效期 7 天，过期应重新准备并构建。
本机 Gradle 使用 JDK 17；不要使用 Gradle 8.13 不支持的 JBR 25。
PCAPdroid 安装源为官方 [v2.0.2 release](https://github.com/emanuele-f/PCAPdroid/releases/tag/v2.0.2)，
本机下载校验记录在实验输出中；APK、动态库、证书和私钥不入源码提交。

## 单独操作网络侧车

```powershell
python mobile/lab/pcap_sidecar.py start --serial SERIAL --name UNIQUE.pcap
python mobile/lab/pcap_sidecar.py status --serial SERIAL --name UNIQUE.pcap
python mobile/lab/pcap_sidecar.py stop --serial SERIAL --name UNIQUE.pcap
python mobile/lab/pcap_sidecar.py pull --serial SERIAL --name UNIQUE.pcap --out output/RUN/network.pcap
```

`am start` 返回成功不证明 VPN 已启动；状态结合实际 CaptureService、同用户 VPN 或文件增长。
未知/等待授权退出码为 2；完整一键流程退出码 0 才代表本阶段的所有门控通过。
停止仅调用 PCAPdroid 正常控制接口，不终止用户其他 VPN，也不覆盖已有捕获文件。

## 看哪些结果

| 文件 | 意义 |
| --- | --- |
| `phone-verification.json` | 本阶段总验收；`passed=true` 才是完整通过 |
| `capture-running.json` / `capture-stop.json` | 真实 VPN 运行与停止状态 |
| `probe-verification.json` | 系统 user/nondebuggable、UID、Gadget ABI、存储与本地接收检查 |
| `probe-events.jsonl` / `probe-assessment.json` | 逐条 Gadget 证据及精确值关联 |
| `sink-receipts.jsonl` | 本地接收端实际收到的合成数据 |
| `network.pcap` / `network-verification.json` | 原始包及四组协议阳性对照 |

PCAP 的普通 RAW-IP 格式本身不带 UID；包过滤配置和 VPN 用户/UID 范围是另一层证据。
配置 dual-stack 不等于实测过 IPv6；全载荷保存不等于所有协议都可解析、解密。
明文保存在应用私有目录也不等于已证明其他应用可读取，弱配置不等于已验证向外泄露。

## 本轮设备与操作

2026-10-17，Android 14/API 34、ARM64，系统 `user`、`ro.debuggable=0`，shell UID=2000。
首轮真机独立探针与四组网络对照通过，PCAP 43 包，无截断；TLS 未误标明文。
最终一键流程的独立结果以 `output/phone-functional-ready-20261017/phone-verification.json` 为准。
本轮修改仅在本地 `feature/nonroot-gadget-audit`，未提交、推送或合并 main。

最终一键入口已于本轮真机通过：`phone-functional-ready-20261017` 下总验收、探针与网络验收均 `passed=true`，抓包正常停止。
