# 移动端功能分支：开发内容与合并说明

## 1. 这份分支做了什么

本分支以组员 2026-10-15 提供的 ZIP 为基线，归档标注提交为
`bda21c705b18c3ce37be90a7cc67233fa965bbb6`。目标是补充移动端交付能力，
不是用我方旧版本替换组员主项目。合并时应对照 Gitee 当前 main 的最新改动。

| 我新增或完善的内容 | 具体效果 | 主要文件 |
| --- | --- | --- |
| 独立移动端工作台 | APK 上传、持久化任务、静态候选、源码查看、动态证据、政策与研判、报告中心；桌面/手机布局 | `mobile/workbench/`、`mobile/workbench/frontend/` |
| 工作台执行闭环 | 显式设备选择与安装授权，自有夹具采集、同任务证据保存、PDF 生成；后台查询、取消、失败留证 | `mobile/workbench/workflow.py`、`operation_jobs.py`、`report_generation.py` |
| 自有夹具非 root 入口 | 新增 Gadget 构建变体、版本/ABI/摘要检查、单会话挂钩、权限触发和资源清理 | `mobile/fixture-app/`、`mobile/tools/device_fixture_run.py`、`device_fixture_trigger.py`、其余新增 `device_*.py` |
| 读取与同意语义 | 区分取得数据、空返回、权限拒绝、错误、仅调用和未知；打开政策页不当作接受政策 | `mobile/analyze/read_semantics.py`、`consent_semantics.py`、`mobile/hooks/values.js`、`dispatch.js` |
| 流量证据修正 | 区分客户端 TLS 与代理上游 HTTP；只有明确未使用 TLS 才支持明文结论 | `mobile/analyze/evaluation_mobile*.py`、`mobile/ai/bundle_observations.py` |
| AI 结果校验 | 阶段失败停止、连续阶段约束、证据包与输出绑定、报告加载时重验；兼容组员新增的不可信政策围栏 | `mobile/ai/ai_review.py`、`review_gates.py`、`validate.py`、`mobile/report/report_mobile.py` |
| 报告可复核与格式 | 报告关联当前任务和 APK；保留缺口、读取状态、TLS；修正中文页脚、粗体、Hook 数组/缺失计数 | `mobile/report/` |
| Python Hook 编译入口 | 复用现有 Java bridge，避开 Node native binding 构建问题，不连接设备 | 新增 `core/frida_host/build.py`、`test_build.py` |

上表的“新增”指本人的开发工作，其中读取/AI门控、移动工作台的基础部分已在我方历史版本中完成，
此次整理为相对组员新基线的功能增量；不是声称这些基础工具或上游能力均由我开发。

## 2. 为方便合并主动让出的部分

- **不替换根 `frontend/`**。移动 UI 放到 `mobile/workbench/frontend/`，默认端口改为 **8771**，不占用原车载入口。
- **不替换上游 `device_run.py`、`trigger.py`**。我方入口改名为 `device_fixture_run.py`、`device_fixture_trigger.py`。
- **不改 `vehicle/`、`core/static/`、`mobile/rules/`**。保留组员的 223 条规则、58 个 API、归因诊断及长路径修复。
- **不改依赖清单、环境脚本、现有 CI 与回归入口**。不携带我方 Maven JADX 安装器/发现逻辑及全局环境重构；JADX 沿用上游支持的发行版。
- 不纳入我方可选窗口评估脚本、旧验收报告、运行缓存、APK、动态库、密钥、node_modules。
- 需要共同修改的主要是移动 Hook、关联、AI 与报告代码：保留上游缓存/诊断开关、坏行统计、加固探测、弱归因降级，再加入我方证据语义与校验。

未实现在线 AI 工作台入口，不把配置文件存在等同于已完成真实模型测试。

## 3. 启动与构建

使用组员项目已有 Python 环境；无需替换 `requirements.txt` 或 `environment.ps1`。

```powershell
# 仓库根目录；SDK/JADX/JDK 可以沿用原环境或通过参数明确提供
python mobile/workbench/server.py --port 8771
# 页面：http://127.0.0.1:8771/app.html
```

没有 JADX 时仍可静态扫描，但源码阶段明确显示不可用；没有已构建的 Gadget APK 时仍可上传/导入证据，设备采集不会假装可用。
历史 PDF 继续读取原 `frontend/pdfs/`，不重复复制四份报告。

非 root 采集只支持获授权的自有源码夹具 `com.vscanner.privacydemo`：

1. 安装已有 Node 项目依赖，在仓库根执行 `python core/frida_host/build.py --platform mobile`。
2. 按 `mobile/fixture-app/README.md` 准备 Gadget 并构建 Debug/Gadget APK；Gadget 版本必须与实际宿主 Frida 一致。
3. 连接获授权设备，工作台中主动选择设备、确认安装运行授权，再启动采集。

上游 requirements 声明 Frida 17.18.0，我方此前实测环境为 17.9.11；本分支不升级任何依赖。
不要混用旧 Gadget 与新宿主；在组员环境重新准备匹配版本。生产非 root 真机仍需复验。

## 4. 本次兼容验证结果

- 组员原移动总入口：**23/23 项通过**，包含规则、诊断、Hooks parity、流量、政策、关联、AI、报告和合成端到端。
- 新工作台 **44**、夹具设备管线 **34**、Gadget 准备 **14**、Python Compiler **13**、读取/TLS **16**、AI 门控 **12**、报告门控/健康计数 **10** 项离线测试通过。
- 前端模型 **59 条断言通过**；移动 Hook **6 个入口编译通过**，保留上游 58 个目标及诊断占位符。
- HTTP 测试验证新默认页面与 JS/CSS 来自独立移动目录。此兼容目录没有重做真实设备/在线 AI 实测，不移用旧目录的设备验收结论。

完整车载/共享总回归本机为 **11/13 组通过**，不是全绿：

1. `core/static/test_jobs.py` 的长路径用例在本机 Python 3.11 原生 `Path.rglob` 抛 WinError 3；**未改动的 ZIP 基线也已单独重现**。
2. 车载 Hook bundle 路径检查缺少未随源码交付的生成 `dist` 文件。

为避免扩大分支，没有修改这两处上游测试或伪造生成文件。组员应在其既定 Python 3.13/构建环境复核。
首次完整检查失败日志保留于本地 `output/mobile-branch-20261015-230103/`，原移动检查在 `output/mobile-regression-20261015-230109/`；运行产物不提交。

```powershell
# 移动分支检查：保留原移动检查，再加我方必要回归
python tools/check_mobile_branch.py
# 如需同时运行原车载/共享总回归（需先构建相应 bundles）
python tools/check_mobile_branch.py --include-upstream-core
```

默认命令仅代表移动分支范围通过，不代表整仓、真机或 AI 效果全部验收。

## 5. 在 Gitee 审查与合并

本次功能提交的目标分支是 `ch`，主分支 `main` 不在本次提交范围。
建议组员创建 `ch → main` 的 Pull Request，先审查移动 Hook、AI、关联与报告的共同修改，再合并。
源码分支不包含新增 ZIP、补丁包、运行日志、PDF、PNG 预览、APK、Gadget 动态库或密钥。

本提交中的三个 `mobile/ai/prompts/*.md` 是程序运行时加载的提示词模板，属于源码依赖。
构建配置与测试源码一同提交；历史 PDF 若已存在仍由原项目提供，不新增二进制报告。
