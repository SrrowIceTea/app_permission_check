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
| `mobile/pipeline/` + `frontend/` | **一键审计**：拖入 APK → 16 阶段（静态→采集→关联→AI→报告），SSE 实时进度 |
| `mobile/workbench/` | 静态/动态工作台：上传 APK、导入证据、静态发现、政策与研判、报告中心 |
| `mobile/repack/`、`mobile/lab/` | Gadget 制备、真实采集、场景及正式管线 |
| `mobile/policy/`、`mobile/ai/` | 本地政策（含《用户协议》分册）与三阶段 AI/证据门控 |
| `mobile/analyze/`、`mobile/report/` | 关联、风险评估、PDF |
| `mobile/audit/`、`mobile/hooks/` | 存储/加密探针、观察脚本 |
| `core/` | 两条产品线共用内核 |
| `vehicle/` | 已有车载产品线，移动分支不覆盖其成果 |

**组员合并前先读 [合并说明](docs/MERGE_NONROOT_AUDIT_20261018.md)。队友主线优先，不用整目录覆盖 main。**

## 运行入口（两套，默认端口已错开）

一键审计占 **8771**、工作台占 **8772**，两套可以同时起。前端也不同：一键审计用根 `frontend/`
（静态 8090），工作台用自带的 `mobile/workbench/frontend/`（同源）。

**A. 一键审计（`mobile/pipeline` + 根 `frontend/`）**

```powershell
# 后端：只提供 /api/stages、/api/pipeline/*（SSE），不托管静态文件
python mobile/pipeline/server.py --port 8771 --workdir <产物目录>
# 前端：另开一个终端
python -m http.server 8090 --directory frontend
# 打开 http://127.0.0.1:8090/app.html（侧边栏第一项「一键审计」，即默认页）
```

**B. 静态/动态工作台（`mobile/workbench`，自带前端）**

```powershell
# 默认 8772（pipeline 占 8771），两个服务可同时运行
python mobile/workbench/server.py `
  --sdk <本机SDK目录> --jadx <本机JADX目录> --java-home <本机JDK目录> `
  --audit-config <源码外私有模型配置.json> `
  --audit-selftest <同设备同模式真实正控目录/verification.json>
# 打开 http://127.0.0.1:8772/app.html
```

模型配置参考 `mobile/ai/config.example.json`，不要提交真实 Key。

准备工具、规则库、本地政策和真实正控，按以下顺序读：

1. [一键审计流水线](mobile/pipeline/README.md)（阶段定义、SSE 契约、设备自愈）
2. [完整检测服务与 API](mobile/workbench/README.audit.md)
3. [非 root 采集与正控](mobile/lab/README.nonroot.md)
4. [授权 APK Gadget 制备](mobile/repack/README.md)
5. [本地政策资料](mobile/policy/README.local.md)
6. [Root 模拟器实验](mobile/lab/README.root.md)

> 根 `frontend/` 现在对接的是 `mobile/pipeline`（8771），**不再是** `vehicle/workbench`（8770）。
> `frontend/README.md` 的文件结构表与 `frontend/CONTRACT_AUDIT.md` 仍留着 8770 时期的描述，
> 以 [`.workbuddy/skills/vscanner-frontend-redesign/references/contract.md`](.workbuddy/skills/vscanner-frontend-redesign/references/contract.md)
> 和 `frontend/app.js` 为准。

注意版本：根 `requirements.txt` 保留历史 Frida 17.18.0 环境声明；本轮非 root 制备默认 Gadget 为 **17.9.11**。
宿主 Frida 与 Gadget 必须对齐；不能混装后复用旧正控。详见合并说明的环境准备章节。

## 已验证范围

**2026-10-18（真实 APK）**

| 真实 APK | 本轮结果 |
|---|---|
| LibChecker 2.5.4 | 前端完整检测通过；2 次实际敏感读取、3 次真实模型响应、13 页 PDF |
| Read You 0.16.2 | 179 个包、1 条实际 HTTP200；最新重判 4 次真实模型响应、14 页 PDF |

**2026-10-19（合并 ch / junzhe 后的回归基线）**

| 入口 | 结果 |
|---|---|
| `mobile/tools/run_mobile_checks.py` | **24 组**全绿 |
| `tools/check_mobile_branch.py` | **22 组**（含 workbench、policy 46 项、AI、7 个前端契约）。本机沙箱下 19 组通过；`mobile_workbench`/`ai_gates`/`mobile_lab` 三组是环境侧 bulk-delete 保护在清理临时目录时 `SystemExit(1)`，不是断言失败，正常终端里应重跑确认 |
| `mobile/analyze/test_risk_score.py` | 38 项（v1.3） |
| `mobile/workbench/test_*.py` | 125 项 |

实际采集、原响应和完整验收留在本机 `output/`，不随源码上传。
JADX 部分可用与全 DEX 引用事实扫描分开标识；有限场景不代表全部业务已覆盖。

不是任意加固 APK 无条件插桩，也不是所有协议明文解密；签名绑定、隔离/二级进程、登录后业务、TLS/QUIC 等缺口需独立验证。

## 离线回归

准备对应依赖与规则资源后，在仓库根运行（不需要设备或真实模型 Key）：

```powershell
python tools/check_mobile_branch.py            # 移动分支 22 组
python mobile/tools/run_mobile_checks.py       # 组员原入口 24 组
python tools/check_mobile_branch.py --include-upstream-core   # 再带上车载/内核 13 组
```

真实检测仍需重新完成同设备正控。
