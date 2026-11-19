# 车载审计工作台

仅用于授权测试（自有设备与自有 APK）。

从移动端 `frontend/app.html` 移植侧栏、上传舞台、源码、结果及报告页；
共享 `frontend/app.css`、`workspace.css`、`highlight.js`；车载背景单独位于 `assets/vehicle-studio.png`。
车载页面与逻辑位于本目录，独立服务位于 `vehicle/webapp/`。
移动端页面、8771/8772 服务及 MOB 规则没有改动。

## 启动

在项目根目录执行：

```powershell
./vehicle.ps1 web
# 浏览器访问 http://127.0.0.1:8773
```

也可以 `. ./environment.ps1` 后执行 `& $VScanPython -m vehicle web`。
默认任务目录为 `output/vehicle-web`，每次上传生成独立 UUID 目录，失败也保留。
停止服务时等待当前任务完成；强制结束进程后，下次启动将未结束任务标为失败，绝不假定已回滚设备状态。
同一工作目录只能由一个服务进程持有。

## 三种方式

| 方式 | 行为 | 前提与输出 |
| --- | --- | --- |
| 仅静态分析 | 上传 → VSC 静态匹配 → jadx 源码 | 不连接设备、不调用 AI；不生成动态审计报告 |
| 重放已有采集 | 上传 → 静态/源码 → 现有车载审计 → 看板/PDF | 校验 APK、包名、会话、规则、Hook、隐私目录和采集健康；不是新设备实测 |
| 新建 AAOS 采集 | 上传 → 静态/源码 → 装机身份核对 → 采集 → 审计 → 看板/PDF | AAOS API 35、已启动 Frida、已在正确用户下安装并打开的同版 APK；采集期间操作目标 App |

上传前确认测试授权。界面不会自动安装 APK、提权、授予权限或启动模拟器。
静态候选不代表实际读取或外发；健康但无观测不代表安全。
只监听 `127.0.0.1`，不接受远程 Origin/Host，不向公网开放源码与审计证据。

默认列出 `output/<轮次>/[capture/]` 和 `output/<轮次>/run-*/capture/` 的健康采集。
更深目录或其他位置通过启动参数显式登记，可重复传入：

```powershell
./vehicle.ps1 web --capture output/本轮/授权样本/capture
```

下拉列表只说明该会话曾通过采集自检，不保证与当前规则、Hook 或上传 APK 一致；
不一致会拒绝审计。历史会话与当前隐私目录不匹配时保留失败原因，不自动改写历史证据。
当前页面按 Android 15 车载规则分析；其他系统版本不在本次工作台验收范围。

服务默认不调用 AI。只有显式指定 `--ai-config vehicle/ai/config.local.json` 才启用现有车载辅助复核。
模型输出不能改变工具结论；辅助复核与工程交付的 subagent 签核是不同产物。

服务内动态任务串行，跨服务进程对同一设备使用文件锁。
已有 CLI/其他采集工具不参与此锁，不得与页面同时争用设备、代理或 8888 端口。

## 结果与恢复

- 六个页面：车载审计、源码、静态、动态、辅助复核、PDF 报告。
- SSE 阶段对应车载实际工作，不套用移动端 16 阶段或移动端结果字段。
- 任务历史来自服务端，刷新可恢复；切换历史不关闭运行任务的订阅。
- 新建任务清空旧结果，源码读取按最新点击显示；不混用不同任务的证据。
- 动态流程未完整完成时，摘要、PDF、看板不作为成功产物发布；静态结果可单独查看。
- `job.json`、`events.jsonl`、`failure.log`、`static/`、`capture/`、`audit/` 保留对应轮次。
- 默认未提供政策与场景记录时，沿用车载流水线的缺失说明，不虚构政策披露或场景覆盖。
- `审计摘要` 下载的是 JSON，完整的可迁移证据仍保存在任务的 `audit/bundle/`。

零构建：不新增 npm 工程、框架或 CDN 组件。也可在项目根启动普通静态服务，
访问 `/vehicle/frontend/app.html`；API 使用本机 8773，需要同时启动上述车载服务。

## 检查

```powershell
. ./environment.ps1
& $VScanPython -m unittest vehicle.webapp.test_server vehicle.webapp.test_workflow
& $VScanPython tools/run_regressions.py --mobile
node --check vehicle/frontend/app.js
node --check vehicle/frontend/results.js
node --check vehicle/frontend/source.js
# 实际 APK 与已登记采集目录片段，隔离 Chrome profile：
node vehicle/webapp/browser_acceptance.mjs 授权.apk 已登记会话目录片段
```

浏览器验收使用本机 Chrome/CDP，不读取个人浏览数据；Python Playwright 在当前解释器中未安装，
因此复用仓库已有的原生 CDP 验证方式。结果与截图保存在 `output/vehicle-frontend-acceptance/`。

布局检查：`node vehicle/webapp/layout_acceptance.mjs`，覆盖 1440、1920、390px 的完成、失败、新建和运行态。
完成/失败读取本机真实历史，运行态只做明确标注的合成布局检查，不代表新设备采集。
结果与截图写入 `output/vehicle-ui-redesign/`；图片生成方式及提示词见 [assets/README.md](assets/README.md)。

字体与艺术排版由 `fonts.css`、`typography.css` 独立维护，字体文件本地加载。
中文标题使用 Noto Serif SC，普通界面为 Manrope/Noto Sans SC；顶部历史控件保留原生 select 的键盘与读屏支持。
来源、子集及许可证见 [字体说明](assets/fonts/README.md)。

## 证据复核（第七页）

启动服务时附加 `--review-round <本轮目录>`，仅只读发布其中的 `public-review.json`，
通过 `GET /api/review-round` 返回固定 schema；其他文件、目录、查询路径和 POST 均不开放。
未配置、文件缺失或格式错误会显示明确提示，不自动回退历史轮次。

复核轮次与当前 APK/历史任务独立。工作流状态、配对计分资格、subagent 复核状态分别展示；
subagent 签核不代表人工签核，workflow_only 不并入计分样本数，静态成功不代表动态通过。
门槛由摘要提供，不由页面推断。bindings 只允许扁平 ID/摘要字符串；findings、limits、
eligibility_reasons 是公开说明字符串数组，不放磁盘路径或原始日志。

针对性检查：`python -m unittest vehicle.webapp.test_review_round`；
`node --check vehicle/frontend/review.js`。合成测试数据不代表真实签核。

只读浏览器复核：`node vehicle/webapp/review_acceptance.mjs http://127.0.0.1:8773`，
验证第七页、逐例状态、轮次隔离、subagent 标签、本地资源和 1440/390px 横向边界。
明确使用模拟文件时加 `--synthetic`，验收结果会标记为模拟而非签核证据。

## 11-15 车载前后端接通

失败页现在可读取当前任务日志并重新授权后创建独立重试任务。采集设置传递版本、范围、
TLS 与多进程参数；可上传政策/场景材料；源码页展示反编译元数据，动态页展示覆盖链，
报告页可下载经校验的完整证据 ZIP。AI 仅在服务已有模型配置时按本轮选择执行。
详见[功能矩阵、接口与验收说明](../../docs/VEHICLE_FRONTEND_INTEGRATION_20261115.md)。
本轮浏览器验证为冻结采集的回放，不代替新设备或在线模型验收；保持零构建和原结论边界。
