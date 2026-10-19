# 移动 App 隐私审计分支：组员合并说明

> 交付日期：2026-10-18。本文描述本机实际源码与验收，不代表已同步远端 main。
> 合并原则：**队友主线优先；增量接入本分支能力，不用整个目录覆盖主线。**
>
> **合并结果（2026-10-19 补记）**：本分支已以 `e629b6b` 合入 main 并推到 `origin/main`，
> 文本冲突 2 处（`tools/check_mobile_branch.py`、`mobile/ai/evidence_bundle.py`），按并集解决。
> 本文只覆盖「非 root Gadget 审计」这条线的增量；同时合入的 `mobile/pipeline/`（16 阶段
> 一键审计 + SSE）与根 `frontend/` 改版**不在本文范围内**，见 `mobile/pipeline/README.md`
> 与根 `README.md`。

## 1. 这份交付是什么

本分支新增了真实 APK 的非 root Gadget 审计、证据化风险评估、三阶段 AI 与工作台完整执行入口。目标是让同一个上传任务贯通：

**原始 APK 上传 → 全 DEX 静态/JADX → 本地政策匹配 → 原包或 Gadget 衍生包实际运行 → 行为/网络/存储关联 → 风险指标 → 真实三阶段 AI → PDF → 原任务查看。**

- 本机源码根：`D:/AAA-Codex/shengsai_app/mobile-app-permission-check-ch`。
- Git 基线 HEAD：`9f5c9766d275bfb9019d8b4c14066d6b66c7f570`。
- 桌面打包时本机分支：`feature/nonroot-gadget-audit`。
- **桌面打包快照形成时包含当时尚未提交的 tracked 修改和新增 untracked 源码**；只 checkout 此 HEAD 不会得到本轮功能。
- 基线 SHA 只是本地差异的起点，不表示队友当前 main 也停在该提交；本次未查询、拉取或判断远端 main。
- 本次经用户授权将源码与本说明提交到 Gitee 的 ch 分支；不修改 main、不强制推送、不创建 PR。接收方决定最终主线合并方式。

桌面交付文件为 `mobile-app-permission-check-合并交付-20261018.zip`，内含：

- `mobile-app-permission-check/`：完整源码快照，含需要保留的 shared/core/vehicle 源码；这不表示可整目录覆盖队友仓库。
- `相对基线合并.patch`：相对上述本地 HEAD 的、符合源码交付范围的当前未提交新增与修改；**不包含基线之前已经提交的开发历史**。
- `合并说明.md`：本文；桌面另有独立 Markdown 便于阅读。
- `文件清单.txt`：核对实际入包文件；资源排除以清单及交付打包规则为准。

如果队友主线连该本地基线已有的功能也没有，单独应用该 patch 不能补齐全部历史，需配合源码快照逐项比较。完整包是代码交付，不是携带 Android/SDK/模型凭据的可直接运行虚拟机快照。本文后面的环境与正控步骤仍需完成。

## 2. 我方新增的主要能力

| 能力 | 实际新增内容 | 合并时保留的约束 |
|---|---|---|
| 当前 APK 完整审计 | 工作台功能按钮及 `/api/tasks/{id}/audit`；复用原上传任务、独立 attempt、真实状态与 PDF | 不把第三方 APK 换成自有夹具；失败不发布成功报告 |
| 非 root Gadget | 备份原包、只重签对照、插桩衍生包；应用早期加载、单会话四模块观察 | 原/衍生包摘要与签名分开；不冒充原包字节直接运行 |
| 采集与网络证据 | 进程内读取/同意/出站/存储观察；可选目标 UID 配置的 PCAPdroid VPN；实际本地 RSS/HTTP 对照归因 | 包级抓取不等于逐包 UID 证明；握手不等于业务请求；不假装全协议解密 |
| 存储与弱加密 | JCE、写调用、密文与写入关联等进入正式证据和 AI/PDF | 默认 AES 模式未知不直接写 ECB；写 API 发生不等于个人隐私已落盘 |
| 本地政策资料链 | 主政策与补充告知单独归档、来源/日期/正文摘要及原 APK/版本匹配 | 不临时联网搜索充数；缺失、未来生效和版本不确定分别标记 |
| AI 三阶段门控 | 政策抽取、行为一致性、综合研判；原始响应→文本→解析→引用绑定；有限纠错 | 模型输出不替代证据；失败保留；不手工改 JSON 伪造通过 |
| 风险及补充证据 | 版本化确定性风险、覆盖与证据强度；ST 静态/N 网络/SC 存储源索引 | 固定分数与 AI 意见分开；未知保持 null，而不是零风险 |
| 生命周期与重建 | 取消清理、重启存活进程识别、报告重建保留 AI；partial 覆盖状态不被提升 | 操作 done 与任务 partial 可以同时成立；旧产物不冒充本轮结果 |
| 回归与基准展示 | 真实/失败结果独立；基准与风险数据展示；新增核心/接口/前端模型测试 | 不把离线测试当设备验收，不以论文漏洞标签代替本次观察 |

## 3. 目录职责与阅读入口

| 目录/文件 | 职责与优先阅读 |
|---|---|
| `mobile/repack/` | 授权单 APK 的工具来源核验、解包/插桩/重签与转换证明；读 `README.md` |
| `mobile/lab/` | 根/非 root 真实采集、场景、核心管线、国内样本批次与汇总；读 `README.nonroot.md`、`README.core.md`、`README.compat.md` |
| `mobile/audit/` | 存储/密码学探针及技术观察，不是另一套 HTTP 服务；读 `README.md` |
| `mobile/workbench/` | 上传任务、静态适配、完整 audit 操作、恢复、证据发布、报告；入口 `README.audit.md` |
| `mobile/workbench/frontend/` | 现有工作台增量功能：完整检测入口、真实任务状态、基准与风险展示 |
| `mobile/policy/` | 本地政策和补充材料获取、解析与严格绑定；读 `README.local.md` |
| `mobile/ai/` | 正式证据包、三阶段提示词、传输、来源/引用/存储补充门控；读 `README.storage.md` |
| `mobile/analyze/`、`mobile/report/` | 原关联引擎的增量、风险与补充证据、AI PDF |
| `mobile/hooks/`、`mobile/fixture-app/` | 共享观察钩子与自有正控；不是用夹具结果替换真实 APK |
| `tools/check_mobile_branch.py` | 一键移动分支回归：**当前 22 组**（10-18 时为 21 组，10-19 合并后并入 `risk_score` 与 ch 的扩展组）；不要替换队友已有的其他回归入口 |
| `core/io_utils.py` | 少量平台共享修改，影响不止移动侧；必须逐行审查 |

`vehicle/` 是既有车载产品线，不要为合并移动功能覆盖或改造车载成果。复用共享内核，避免复制两份同名规则或证据协议。

## 4. 高冲突文件：优先人工合并

以下是本机差异中的高耦合点，不是对远端是否有冲突的预判。

| 高冲突位置 | 重点检查 |
|---|---|
| `mobile/workbench/runtime.py`、`routes.py`、`server.py` | 现有 API/启动参数优先；增量接入 audit 配置与路由；保留 localhost/路径/上传长度限制 |
| `mobile/workbench/workflow.py`、`operation_jobs.py` | 同任务独立 attempt、取消/恢复、资源互斥；报告成功保持 partial，失败/取消优先 |
| `mobile/workbench/report_generation.py`、`evidence_adapter.py` | 原包/证据绑定、AI 重验及 PDF 摘要；不要退回“重建 PDF 丢 AI” |
| `mobile/workbench/frontend/js/app.js`、`tasks.js`、`workflow.js`、`workflow-model.js` | 队友布局和交互优先；仅移入必要事件、按钮、模式标签与模型函数 |
| `mobile/workbench/frontend/app.css` | 展示样式最容易牺牲；主线审美/布局优先，不整文件替换 |
| `mobile/ai/evidence_bundle.py`、`ai_review.py`、`llm_client.py`、`review_gates.py`、`validate.py` 及 prompts | 输入、输出 schema、ST/N/SC 引用和原响应绑定一起合并，不单独摘提示词绕过门控 |
| `mobile/analyze/correlate_mobile.py`、`mobile/report/report_mobile.py` | 维持既有规则语义，补充模块不得把静态线索当成运行事实 |
| `mobile/hooks/hook_privacy.js`、`core/io_utils.py` | 单 bridge/单会话与结果状态语义；共享读取行为不能破坏原车载链路 |
| `tools/check_mobile_branch.py`、原有测试文件 | 合并测试清单和新增用例；不能用删测试/放宽断言换“全绿” |

### 推荐合并顺序

1. 先确定队友主线的 API、task/bundle schema 与命名；保留其业务结构。
2. 接入相对独立的新目录与纯模型：`repack`、`audit`、`lab`、政策库、风险与 AI 补充模块。
3. 合并原关联/证据/AI/PDF 的接口及门控，先跑这些模块的离线测试。
4. 接入工作台 audit 生命周期及同一上传任务发布，确认旧上传/夹具/导入入口不退化。
5. 最后接前端事件、按钮和数据展示；有冲突先舍弃我方样式，不先舍弃身份校验与测试。
6. 在新环境重建规则/依赖，重新跑同设备正控与一个真实 APK 全链，最后才考虑提交合并。

## 5. 在队友仓库的新分支应用

以下仅供接收方在自己的主线合并时执行；桌面打包时没有执行这些 Git 操作。先保证队友工作区干净，或由本人备份现有改动。

```powershell
# 在队友真实仓库中，基于队友认可的当前主线创建新分支；不要直接覆盖 main。
git status --short
git switch main
git switch -c merge/nonroot-gadget-audit
```

分支名只是建议。如果主线不是 main，换成队友实际使用的分支；本说明不要求更新/重置其主线。

### 优先应用交付的 `相对基线合并.patch`

该补丁用于 eligible 未提交源码差异，覆盖符合交付范围的新增 untracked 源码；不要另用只含 tracked 修改的 `git diff` 替代。运行资源排除与源码快照一致。

```powershell
# 在新分支内，将下面路径换成解压后补丁的实际位置。
git apply --stat "<交付目录>/相对基线合并.patch"
git apply --check "<交付目录>/相对基线合并.patch"
```

- 检查无冲突再应用；检查失败先查看高冲突文件。共同基线对象存在时可在该新分支尝试 `git apply --3way --index "<交付目录>/相对基线合并.patch"`，它可能留下真实冲突，**不保证自动兼容**。
- 逐处合并双方逻辑，不对整棵目录一键使用 ours/theirs；以队友现有主线设计优先。
- 本地基线 SHA 不存在或仓库历史不相同时，不能把 `--3way` 当成万能办法；按职责人工迁移增量。

### 源码快照用于人工对照，不用于覆盖

在临时目录解压，用对比工具与本地基线/队友主线逐文件比较；优先导入新增模块，再按第 4 节处理原文件差异。**不要把源码压缩包直接解压覆盖队友仓库。**

完成后检查 `git diff --check`、`git status --short`，确认只包含预期源码/文档，没有 APK、凭据、运行目录或队友无关改动。测试通过后由提交者自行审查、提交与推送。

## 6. 源码包不包含的资源与重建前置

**不包含 APK/DEX 样本、模型密钥与本机私有配置、测试签名私钥、依赖目录、SDK/JDK/Android 镜像、node_modules、venv、Gradle 缓存、output 历史会话、PDF/PCAP/运行日志、JAR、生成的 Gadget provenance/动态库，以及预生成规则数据库等运行资源。** 不把这些内容“补进 Git”解决换机问题。

`mobile/rules/build/` 内的 API/consent 事实文件是可读的签名证据，予以保留，不等同预生成规则 DB；可读的 `libgadget.config.so` 是 JSON 配置，也予以保留，不等同原生 Gadget 库。

| 需要另行准备 | 正确做法 |
|---|---|
| Python/Node/Java 工具链 | 新建独立环境，不复制本机 venv；本轮核心实际在 Python 3.11 环境、JDK17、SDK36 工具及 Node 下测试 |
| 依赖版本一致性 | 审查 `requirements.txt`；它的历史 Frida 钉值为 17.18.0，而本轮通用重打包默认 Gadget 为 17.9.11。二者不能混装后宣称复现；使用本轮版本时宿主 Frida/Gadget 均应为 17.9.11，工具链版本变更需重新正控 |
| Android SDK/JADX | 配置本机路径；需 aapt2、dexdump、zipalign、apksigner、API36 android.jar、JADX 与 Java；不要复制本机绝对路径 |
| 规则库 | 从本机匹配 API 的 android.jar 抽实际签名，再构建 `mobile/rules/rules_mobile.db`；不手写/猜 API 描述符，不拿 API36 规则冒充 API30 |
| JS bridge/bundle | 按 `mobile/hooks/package-lock.json` 重建依赖；脚本说明要求 npm 跳过原生安装脚本。运行时核心以同一个 bridge 编译四模块；裸 hook 文件不能替代已编译 bundle |
| Gadget/Apktool | 按 `mobile/repack/README.md` 用官方版本及来源摘要核验重新取得；Gadget 宿主版本必须精确匹配；每轮测试证书重新生成 |
| 自有正控 APK | 按 `mobile/fixture-app/README.md` 重新准备 Gadget 并用 Gradle 构建；源码包中的 provenance 不能证明缺失的动态库存在 |
| 第三方样本 | 由有权测试者重新准备原始完整单 APK，记录来源/版本/签名/摘要；不能借旧 APK SHA 匹配不同版本 |
| 本地政策库 | 原文/正文位于被排除的 output 运行资源中；按 `mobile/policy/README.local.md` 事先采集和绑定，不把演示政策移给真实 App |
| PCAPdroid | 需要 VPN 包级采集时另行安装官方应用，并正常确认控制/VPN 请求；不要移植临时自动确认脚本 |

规则生成的基本顺序（先配置本机 SDK/JDK，详情以脚本参数为准）：

```powershell
Push-Location mobile/rules
python extract_android_apis.py
python extract_android_apis.py --seed seed/consent_targets.json --out-prefix consent_
python build_mobile_rules.py
Pop-Location
python mobile/hooks/gen_targets.py
```

若输出已存在，先保留再按脚本的显式重建参数处理，不随手删掉已有证据。完整依赖/资源重新构建的“干净机器一键安装”本轮没有单独验收；源码包不应被标为开箱即用安装包。

## 7. 非 root、AI 与正控接入

1. 准备一台专用、已授权模拟器；当前真实验收是 API36 x86_64、普通 shell UID2000 的 userdebug AVD，不是锁定量产真机。
2. 先按 `mobile/lab/README.nonroot.md` 对重新构建的自有夹具执行非 root 正控：必须有实际敏感读取、可归因成功 HTTP、Hook 健康和清理通过。启用 VPN 时还须有对应网络阳性证明。
3. 换设备、API、模式或工具版本要重新正控；不能把本机旧 verification 当成新环境证明。
4. 参考 `mobile/ai/config.example.json` 在源码目录之外创建本机私有配置，填写自己的模型配置；不要通过 HTTP、前端或补丁传密钥。
5. 预先准备与原始 APK 匹配的政策库。缺少主政策时技术分析可继续，但政策判断必须保留未知。
6. 使用同模式/同设备真实正控启动服务，详细参数见 `mobile/workbench/README.audit.md`。

```powershell
python mobile/workbench/server.py `
  --sdk <本机SDK目录> --jadx <本机JADX目录> --java-home <本机JDK目录> `
  --audit-config <源码外私有模型配置.json> `
  --audit-selftest <本机新正控目录/verification.json>
```

工作台操作：上传原始 APK，等待静态与可用源码输出，点击“检测连接设备”，只选择服务真实正控允许的模拟器，选择实际支持的场景，明确确认安装/插桩及向已配置模型发送脱敏证据，再点“运行完整检测（含AI）”。

默认健康检查/上传不会自行调用外部模型；显式完整检测会调用。模型费用、网络可达性及订阅由部署方准备。普通夹具“设备采集”是另一个保留入口，不等于用户上传任意 APK 已完成检测。

## 8. 合并后的回归与最低验收

先完成上一节资源重建，再从仓库根执行：

```powershell
python tools/check_mobile_branch.py
python -B -m unittest discover -s mobile/workbench -p 'test_*.py'
node mobile/workbench/frontend/test_audit_model.mjs
node mobile/workbench/frontend/test_workflow_model.mjs
```

回归失败先区分资源/环境缺失与真实代码失败，不能删门控、补造响应或把未运行阶段改成 done。

最低真实验收：同设备正控通过后，至少重新跑一个已授权真实 APK（建议首先 LibChecker），从上传按钮执行本轮重打包/实际安装/观察/关联/真实 AI/PDF。检查原/衍生身份、同一 task、各阶段原始产物、AI 引用、报告下载、取消清理；再重建报告验证保留 AI 且不把 partial 升成 done。不能只看“prepared”或 HTTP202。

## 9. 已有真实验证结果：不是新环境保证

以下来源为本机上一轮 `output/platform-completion-20261018/README.md` 和 `verification.json`。源码包不携带整套 output；若另附验收摘要，它是记录，不可借作新机正控。

| 样本 | 本机实际结果 |
|---|---|
| LibChecker 2.5.4 | 原上传任务 `4c2053ccb80f`；前端操作 `fa1beedd59a3` 完成；原包 1 DEX、8 个 ST 候选、政策 4985 字；2 次安装列表读取；仅 2 个无载荷 853 握手包、F0；3 次真实模型响应与三阶段门控通过；PDF 13 页 |
| Read You 0.16.2 | 原上传任务 `b2f4402f5d91`；真实界面访问本地公开合成 RSS，179 个包、76 个 N 分组、1 条实际 HTTP200；敏感读取 0；最新重判 4 次真实模型响应（含 1 次有限修复），PDF 14 页 |
| 先前非 root 对照 | 4 个 Ghera 密码学正反对照 + LibChecker 共 5 个 APK 完成采集、AI、PDF；这些与本轮工作台验收不能当成 5 个新商业 App 加总 |

- Read You 最新 `readyou-reassessment` **复用原真实采集做重新关联/AI**，不是再次运行模拟器；旧失败记录保留。
- Read You 固定风险 8/100 是合成 RSS 明文传输信号，不是用户隐私泄露证明；LibChecker 12/100 是待复核政策差异候选，网络未知。
- 两个样本均为 JADX 部分可用，但原始所有 DEX 引用事实已扫描；任务 `partial` 是覆盖缺口，不是执行未结束或“全部安全”。
- 报告重建保留 AI，未新增模型请求；服务完成后重启，任务与报告摘要持久化核验通过。
- 本机一键总回归 21 组通过；最后报告/HTTP 修复后工作台 125 项另通过。验收说明统计直接 Python 测试 736 项，嵌套数量另见原日志；这不是检测准确率。

## 10. 已知边界与可以牺牲的部分

- 不是任意 APK 无条件插桩：完整单 APK、ABI、Application 加载点、加固壳、签名绑定、后端完整性均可能阻挡；People+/Xunlei 原包环境问题仍有记录。
- 非 root 当前证明的是专用 userdebug AVD 普通权限路径；不是量产锁定真机/全部 Android 版本验收。多设备、USB 用户真机批量检测不是本次已交付范围。
- VPN 配置过滤没有独立逐包 UID 标签，DNS/侧车包可能出现；TLS/QUIC、自定义加密、隔离/二级进程和登录后业务不保证明文或完整覆盖。
- 本地政策不是所有历史版本/所有补充材料的完备集合；风险指标待更大规模专家标签校准，不宣称法定分或准确率。
- 存储 API/密文写调用不等于已证实敏感数据落盘；无读取/无流量/低分都不能等同安全。
- **可牺牲我方前端样式、重复导航与展示实现，按队友综合平台重新接线。** 可牺牲重复的命令入口，前提是保留实际采集与门控测试。不要为少冲突删掉 APK 身份、模式/规则版本、真实请求来源、未知状态和失败/取消保护。

合并完成的判据是：队友现有项目不退化，至少一个真实 APK 能在其环境完成全部核心流程，原始证据与 AI/PDF 可追溯；不是“文件复制完”或“界面有按钮”。
