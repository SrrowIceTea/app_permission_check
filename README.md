# V-Scanner Mobile

移动应用隐私数据与合规评估平台。仅用于已获授权的 APK 和专用测试模拟器。

## 当前正确入口

- **首页：`frontend/index.html`；工作台：`frontend/app.html`。**
- 新前端对应 **`mobile/pipeline/server.py`**，不是 `mobile/workbench/server.py` 的旧页面。
- 主线保留原有 16 阶段 HTTP/SSE 契约。配置真实模型与正控后，使用共享的静态、采集、政策、三阶段 AI 校验和 PDF 发布核心，不重复实现检测算法。

## 启动新版完整检测

先准备 Android SDK/JDK、JADX、Frida Python、mitmproxy、reportlab/pypdf 和移动钩子的 Node 依赖。

```powershell
$env:ANDROID_SDK_ROOT = '<本机 Android SDK>'
$env:ANDROID_HOME = $env:ANDROID_SDK_ROOT
$env:JAVA_HOME = '<本机 JDK>'
$env:VSCAN_JADX = '<本机 JADX 目录>'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
python -B mobile/pipeline/server.py --port 8771 --workdir output/pipe `
  --audit-config '<源码外模型配置.json>' `
  --audit-selftest '<同模式同设备真实正控/verification.json>'
```

另一个终端在仓库根运行：

```powershell
python -m http.server 8090 --bind 127.0.0.1 --directory frontend
```

浏览器打开本机 8090 端口的 `/index.html`，点击“进入工作台”。选择 APK 会启动实际检测并调用已配置模型；只上传已获授权的样本。

**Root / 非 root 由启动配置的正控决定，不能混用证明。**

- Root 模拟器：安装原始 APK，要求专用模拟器及匹配的 frida-server。
- 非 root：制备并安装独立 Gadget 重签衍生包；保留原包用于静态与政策身份，不冒充原包字节未变。
- 本轮 Frida/Gadget 实测版本为 **17.9.11**。根 `requirements.txt` 保留队友 17.18.0 声明，勿混装后复用正控。
- 正控入口：[非 root](mobile/lab/README.nonroot.md)、[root](mobile/lab/README.root.md)。
- 第三方政策使用已匹配的本地资料；准备方法见 [本地政策库](mobile/policy/README.local.md)。资料与 APK 不随源码包分发。

不传 `--audit-config/--audit-selftest` 时保留队友的旧运行器以兼容已有实验；它不属于本轮“真实 AI 硬门控”验收口径。旧隐私工作台作为兼容工具保留，若需要同时运行请另用 8772 等端口，不能与新流水线抢占 8771。

## 工作台

首页 + 一键审计、源码查看、静态审计、动态审计、AI 报告、PDF 报告六个工作区。

- 新建审计、历史任务切换、服务重启后读取已完成结果。
- 动态页展示实际读取、归因网络流、同意事件和存储/加密观察。
- AI 页展示本轮已校验三阶段原始结论与引用；规则风险信号分和 AI 研判分别呈现。
- PDF 库区分本轮正式报告与历史示例；未通过完整门控不显示为本轮成功。

## 本轮验收（2026-10-19）

| 样本 | 模式 | 正式链路 | 真实 AI 请求 | PDF |
|---|---|---|---:|---:|
| LibChecker 2.5.4 | 非 root Gadget | 通过 | 5（含校验修复） | 13 页 |
| Read You 0.16.2 | 非 root Gadget | 通过；1 条实际本地公开 RSS 流 | 4 | 14 页 |
| LibChecker 2.5.4 原始 APK | Root | 通过 | 3 | 13 页 |
| LibChecker，经新版页面选择 APK 发起 | 非 root Gadget | 页面端到端通过 | 4 | 13 页 |

两种模式真实正控也通过。24 组离线回归通过；前端 21 项契约通过。验收详情见 [改动与测试记录](docs/FUNCTIONAL_FRONTEND_20261019.md)。

有界场景不代表全部业务覆盖。JADX 部分类反编译失败保持 `partial`，未观测到敏感读取/网络流不代表安全；本轮非 root 检测未启用 VPN，不宣称所有包或所有协议明文已覆盖。签名绑定、加固、多进程及不兼容 APK 仍可能阻断。

## 离线回归

```powershell
python -B tools/check_mobile_branch.py
python .workbuddy/skills/vscanner-frontend-redesign/scripts/check_contract.py
```

`core/`、`vehicle/`、规则库与队友现有成果保持；模型密钥只放源码外，不提交。
