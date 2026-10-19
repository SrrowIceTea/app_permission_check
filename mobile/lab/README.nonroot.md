# 非 root Gadget 采集与正式核心管线

仅用于授权测试，显式指定一个 APK 包名和专用模拟器。无设备操作的单元测试不能替代真实采集验收。

## 输入与身份

- `original.apk`：原始签名 APK，供静态规则、版本、权限和本地政策匹配。
- `instrumented.apk`：已嵌入 Gadget、使用实验签名的衍生包，供动态执行。
- `manifest.json`：`mobile.repack.prepare` 输出；记录两包 SHA256、签名、包名、Gadget 版本/ABI/listen-wait 配置及代码转换。
- `resigned-baseline.apk`：只重签、不植入 Gadget 的对照，可帮助区分签名变化和插桩的影响。

两包身份必须分别保留，不能把衍生包的动态结果描述成“原始字节 APK 直接运行”。不绕过签名自检，不改业务 API 返回值。

## 真实采集

```powershell
python -B -m mobile.lab.nonroot_capture `
  --original-apk output/REPACK/original.apk `
  --instrumented-apk output/REPACK/instrumented.apk `
  --instrumentation output/REPACK/manifest.json `
  --package com.example.authorized `
  --serial emulator-5560 --scenario launch --seconds 20 `
  --pcap-sidecar --consent-timeout 120 `
  --out output/NEW_CAPTURE --authorize
```

设备端保留 PCAPdroid 控制请求与系统 VPN 确认；须在设备上实际确认。采集脚本要求普通 shell UID 2000，拒绝可见 Frida Server，不调用 `adb root`、`su`、`run-as`，不安装系统 CA，不改变系统代理。可调试镜像上的普通 shell 会明确标记，不等同锁定生产设备。

Gadget 在应用进程内监听环回地址，主机通过专属 ADB forward 连接。加载与 root 路径相同的共享四模块 bundle 后恢复启动，生成原有 `session/reads.jsonl`、`consent.jsonl`、`egress.jsonl`、`audit.jsonl` 和 `flows.jsonl` 契约，测试后卸载本次安装并移除自有 forward。

## 正式关联 → 三阶段 AI → PDF

先以 `--scenario fixture` 对自有正对照运行一次，必须实际取得隐私读取及带 HTTP 200 的归因流。再把真实采集目录交给既有核心管线：

```powershell
python -B -m mobile.lab.core_pipeline `
  --apk output/REPACK/original.apk `
  --capture-source output/NEW_CAPTURE `
  --selftest output/NONROOT_FIXTURE/verification.json `
  --config C:/PATH/TO/model.local.json `
  --serial emulator-5560 --out output/NEW_FORMAL_RUN --authorize
```

可通过 `--static-source` 复用同一原 APK 已保留的完整 DEX 事实；不会声称执行了未运行的 JADX。原有法规/政策、证据引用、存储分析、真实模型请求和报告发布门控全部保留。不同模式自测不互相替代。

## 结果口径

- `verification.json`：原包与衍生包身份、设备 UID、钩子健康、真实事件数、清理及覆盖范围。
- `session/traffic-scope.json`：VPN 是否启动、是否导出命名 PCAP、目标包过滤与失败原因；侧车失败不冒充完整网络覆盖。
- VPN 配置目标 UID 过滤，但 PCAP 不自带独立逐包 UID 归因，可能包含系统 DNS/侧车探测；853 端口握手不能当作应用业务流。VPN 绕行路径不在覆盖内，TLS/QUIC 载荷仍可能不可读。
- 自有夹具的本地 HTTP sink 是真实网络正对照，不是第三方应用流量，也不改变系统代理。
- 有限 UI 路径、Gadget 加载点之前、二级/隔离进程、签名绑定及后端完整性检查均需分别验收。

离线接口回归：`python -B -m unittest mobile.lab.test_nonroot_capture mobile.lab.test_core_pipeline mobile.lab.test_core_capture mobile.workbench.test_core_publish`。

## 2026-10-18 真实验收

4 个 Ghera 密码学正反对照与 LibChecker，共 5 个 APK，均完成实际 Gadget 采集、三阶段 AI、PDF 与工作台发布。15 次真实模型请求通过正式门控；原验收入口 `output/nonroot-delivery-20261018/README.md`（**该目录已于 2026-10-19 清理，路径不可达**，结论保留、证据需重跑，见 `DELIVERY_INDEX.md`）。

随后已接通上传原始 APK 的完整审计 API 与工作台“运行完整检测（含AI）”功能按钮，操作与授权说明见 [完整审计入口](../workbench/README.audit.md)。Read You 上传任务 `b2f4402f5d91` 已完成实际非 root 采集、AI 与报告；最新重判保留在 `output/platform-completion-20261018/readyou-reassessment/`，观察到 179 个包、1 条有应用归因的 F1 流量证据，生成 14 页 PDF。完整记录见 `output/platform-completion-20261018/README.md`（**该目录已于 2026-10-19 清理，路径不可达**，结论保留、证据需重跑）。LibChecker 工作台第二轮操作 `fa1beedd59a3` 随后通过真实完整检测：2 次实际读取、3 次模型请求、13 页 PDF；仍在原上传任务 `4c2053ccb80f` 展示，失败的第一轮另外保留。

当前支持范围是已经验证的 APK 与相应场景；入口接通不等于任意 APK 都能重打包运行，也不代表所有协议可解密。原包/重签衍生包区别、有限交互覆盖和未知风险仍按上文分别保留。
