# Permission Lab / V-Scanner Mobile

移动 App 隐私数据泄露检测与合规评估工作台。仅用于已获授权的 APK 和测试设备。

## 当前能力

同一个上传任务贯通：**原始 APK → 全 DEX 静态分析/JADX → 本地政策 → 实际运行采集 → 证据关联与风险指标 → 三阶段 AI → PDF**。

- 非 root：为授权单 APK 制备 Gadget 重签衍生包，记录原/衍生包身份；普通权限采集，可选 PCAPdroid VPN。
- Root 模拟器：安装原包，复用关联、政策、AI 和报告链；与非 root 分开正控。
- 读取、同意、网络、存储/密码学观察保留源索引；静态候选不冒充已执行行为。
- 模型原始响应及引用硬校验；失败不发布成功报告。未知维度保持未知，不以零观测证明安全。
- 工作台支持实际完整检测、独立 attempt、取消清理、结果恢复、报告重建保留已校验 AI。

## 目录与合并

| 目录 | 职责 |
|---|---|
| `mobile/workbench/` | 本地服务、前端、任务与完整审计入口 |
| `mobile/repack/`、`mobile/lab/` | Gadget 制备、真实采集、场景及正式管线 |
| `mobile/policy/`、`mobile/ai/` | 本地政策与三阶段 AI/证据门控 |
| `mobile/analyze/`、`mobile/report/` | 关联、风险评估、PDF |
| `mobile/audit/`、`mobile/hooks/` | 存储/加密探针、观察脚本 |
| `core/` | 两条产品线共用内核 |
| `vehicle/` | 已有车载产品线，移动分支不覆盖其成果 |

**组员合并前先读 [合并说明](docs/MERGE_NONROOT_AUDIT_20261018.md)。队友主线优先，不用整目录覆盖 main。**

## 运行入口

本仓库不是携带 SDK、依赖、APK 或模型密钥的开箱安装包。先按下列文档准备工具、规则库、本地政策和真实正控：

1. [完整检测服务与 API](mobile/workbench/README.audit.md)
2. [非 root 采集与正控](mobile/lab/README.nonroot.md)
3. [授权 APK Gadget 制备](mobile/repack/README.md)
4. [本地政策资料](mobile/policy/README.local.md)
5. [Root 模拟器实验](mobile/lab/README.root.md)

```powershell
python mobile/workbench/server.py --port 8771 `
  --sdk <本机SDK目录> --jadx <本机JADX目录> --java-home <本机JDK目录> `
  --audit-config <源码外私有模型配置.json> `
  --audit-selftest <同设备同模式真实正控目录/verification.json>
```

浏览器访问本机端口 8771 的 `/app.html`。模型配置参考
`mobile/ai/config.example.json`，不要提交真实 Key。

注意版本：根 `requirements.txt` 保留历史 Frida 17.18.0 环境声明；本轮非 root 制备默认 Gadget 为 **17.9.11**。
宿主 Frida 与 Gadget 必须对齐；不能混装后复用旧正控。详见合并说明的环境准备章节。

## 已验证范围（2026-10-18）

| 真实 APK | 本轮结果 |
|---|---|
| LibChecker 2.5.4 | 前端完整检测通过；2 次实际敏感读取、3 次真实模型响应、13 页 PDF |
| Read You 0.16.2 | 179 个包、1 条实际 HTTP200；最新重判 4 次真实模型响应、14 页 PDF |

本机 21 组离线回归通过；最后修复后工作台 125 项通过。实际采集、原响应和完整验收留在本机 `output/`，不随源码上传。
JADX 部分可用与全 DEX 引用事实扫描分开标识；有限场景不代表全部业务已覆盖。

不是任意加固 APK 无条件插桩，也不是所有协议明文解密；签名绑定、隔离/二级进程、登录后业务、TLS/QUIC 等缺口需独立验证。

## 离线回归

准备对应依赖与规则资源后，在仓库根运行：

```powershell
python tools/check_mobile_branch.py
```

测试不需要设备或真实模型 Key；真实检测仍需重新完成同设备正控。
