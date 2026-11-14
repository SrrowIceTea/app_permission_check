# 车载前后端对接（2026-11-15）

仅用于授权测试。范围由用户明确为车载前后端；移动端保持兼容，不新增移动功能。
本次沿用七页零构建工作台、车载审计内核与独立规则库，没有重新实现判定引擎。

## 功能与实际链路

| 工作台功能 | 服务端/内核 | 本轮接入与验证 |
|---|---|---|
| APK 上传/静态分析 | POST `/api/pipeline` → core.static | 上传单飞；不同 Android 版本使用对应 VSC 规则；无授权不上传 |
| 源码查看 | `/tree`、`/source`、`/decompile` | 异步任务隔离；实际反编译元数据与覆盖缺口可展开 |
| 新 AAOS 采集 | options → Device → capture_app | 规则版本、all/general、TLS、同包多进程实际透传；TLS 默认关闭；仍核对装机 APK |
| 采集重放 | Catalog ID → run_audit | 不接收浏览器磁盘路径；静态规则与采集版本必须一致；完整身份/健康门禁保留 |
| 政策/场景 | `/api/attachments` → 任务 inputs → run_audit | 有界文件上传、独立任务副本；不替换 APK/会话/正文摘要，不自动生成同意或场景事实 |
| 动态结果/账本 | `/summary`、`/findings` | 缺字段显示缺口；实验候选、已观测、已关联保留原始等级 |
| 逐规则覆盖链 | `/coverage` → coverage.json | 动态页可展开完整覆盖链；缺文件显示 unavailable |
| 辅助复核 | per-job ai_review → 已配置服务 → `/ai` | 启动配置仍由服务管理，不在浏览器输入密钥；未配置禁用开关；读取已校验结果 |
| 单条人工复核 | `/finding-reviews` | 正常页面提交后回读，独立保存；不改结论或计数；不冒充独立签核 |
| PDF/看板 | `/report`、`/dashboard` | 仅完整任务发布；切换任务清空旧 PDF；静态成功不变成动态成功 |
| 证据包 | `/evidence.zip` → verify_bundle | 导出前验证审计引用，按摘要命名的引用集合打包，不递归发布整个任务目录 |
| 失败日志 | `/logs` | 按当前任务固定白名单读取尾部；拒绝任意路径读取；单文件最大 32 KiB |
| 失败重试 | POST `/retry?authorized=true` | 页面重新勾选授权；保留原任务/APK/日志，复制原输入后建立新任务；不自动重跑设备 |
| 历史/进度 | Registry + SSE | 刷新恢复、任务隔离、断线去重及 HTTP 状态恢复；恢复失败仍显示失败 |
| 独立证据复核页 | `/api/review-round` | 沿用 `--review-round` 发布的只读摘要；未配置明确提示，不借当前任务冒充独立复核 |

规则库维护、窗口校准、样本盲评组织等管理型 CLI 仍为独立研发入口，不是工作台的业务任务。
本轮修复的是现有审计页面到服务的功能链路，不改变 native TLS、未知格式或 OEM 的检测边界。

## 使用

```powershell
.\vehicle.ps1 web
# 正常入口 http://127.0.0.1:8773
# 深层冻结采集用启动参数登记，不在浏览器输入任意路径：
.\vehicle.ps1 web --capture output/本轮/已授权样本/capture
```

1. 选择静态、重放或新采集；确认对应 Android 规则版本。
2. 新采集选择 all/general 范围；TLS 例外只在明确需要时勾选，继续只对白名单应用生效。
3. 如有政策/场景，选择入口 JSON 与它引用的正文/回执文件，并选择对应入口。
   同目录材料可多选文件；有嵌套相对路径时选择证据文件夹保留目录关系，
   不改摘要或给另一 APK 套政策。最多 64 文件、合计 4 MiB。
4. 只有服务已通过 `--ai-config` 配置模型时才可选择本轮辅助复核。
5. 失败页可打开日志或重新授权重试；静态模式不执行政策判定、动态采集或在线 AI。

附件不是自动签核：JSON 不合法、政策 APK 摘要不同、场景不属于本 session、回执不匹配，
继续由既有 validator 拒绝。只有静态模式时附件原样保留，不宣称已完成政策/场景审计。
新采集的 session 由采集器产生，不能预填虚构的 session 或执行记录来凑场景通过。

## 工程边界

- `vehicle/frontend` 拆出身份/耗时、连接、复核表单与操作模块，所有改动文件 ≤300 行。
- 沿用原 APK 二进制上传协议；附件单独有界暂存，不把路径、密钥塞到 APK 请求中。
- 日志、重试、附件仍限本机；新的写入口要求本机 Origin，原审计产物不被修改为成功。
- 证据 ZIP 仅包含现有摘要引用及 PDF/看板派生产物；不包含上传 APK、AI 配置或私有账户目录。
- SSE 使用 `id`/`Last-Event-ID` 重连，符合 [WHATWG 事件流规范](https://html.spec.whatwg.org/multipage/server-sent-events.html#the-last-event-id-header)。
  不依赖自动重试业务操作来恢复进度，避免重复设备采集。
- 日常入口还存在环境断点：旧默认 SDK/JDK 在本机不存在，页面能启动但实际任务会找不到工具。
  `environment.ps1` 现在优先显式覆盖，再选择本机确实存在的 SDK 和支持的 JDK17/21，
  避免 JBR25；保留其他 Java 选项，并将本机失效的 Unix socket 路径改为 JDK 自身的 TCP 回退。

## 验证与产物

所有本机轮次保留在 `output/frontend-integration-20261115/`，失败的 browser-001 同样保留。
回放输入来自 11-11 已冻结、摘要绑定的自有夹具与授权 MG4；这不是新设备测试。

- 根回归 21 组、移动兼容 24 组通过；新增 HTTP 反例与 SSE 离线测试登记到统一入口。
- Chrome/Playwright 实际工作台流程：上传、静态、源码、动态账本、复核写入回读、PDF、ZIP、
  政策绑定失败、日志、新建重试、保留旧失败、任务切换、刷新历史、重复上传与 390px 窄屏。
- 正常政策/空场景附件到真实审计内核的传递另由合成 HTTP 契约测试验证，
  不把合成政策当作应用真实披露；空场景也不作为实际场景覆盖。
- 在线 AI 和新 AAOS 采集开关以接口/透传测试验证；本轮未新增设备采集或付费模型调用。
- `browser-release/verification.json` 的 31 项实际浏览器检查通过；日常 `vehicle.ps1 web`
  另在独立工作目录执行了真实 APK 静态任务，见 `entry-verification.json`。

浏览器验收工具（开发机需 `pip install playwright`，使用本机隔离的 headless Chrome）：

```powershell
.\tools\python313.ps1 tools/vehicle_frontend_integration.py --help
.\tools\python313.ps1 tools/vehicle_frontend_integration.py --base http://127.0.0.1:8773 `
  --apk <已授权APK> --capture-label <已登记采集标签片段> --out output/vehicle-ui-new
```

截图和 verification.json 只证明相应输入/服务/浏览器轮次；不证明总体检出率、合规成立或人工金标准。
工作区原有未提交的文档和 YAABSA 诊断工具没有被替换、删除或当成本次代码提交。
