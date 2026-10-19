# 移动隐私审计工作台

仅用于授权测试。独立移动端入口，复用 `core/static` 与移动 API 补充扫描；不修改车载工作台。

## 启动

在仓库根目录运行：

```powershell
& .venv/Scripts/python.exe mobile/workbench/server.py --port 8771
# SDK / jadx / Java 位置可由参数或既有环境变量提供
& .venv/Scripts/python.exe mobile/workbench/server.py --port 8771 `
  --sdk SDK目录 --jadx JADX目录
```

> **端口冲突（2026-10-19 合并后）**：`mobile/pipeline/server.py`（一键审计）默认也是 **8771**。
> 两者同时起会抢端口；要并行就显式给本服务换一个：
> `--port 8772`。根 `README.md`「运行入口」写了推荐起法。

浏览器访问 `http://127.0.0.1:8771/app.html`。页面源码在 `mobile/workbench/frontend/`；
根 `frontend/` 现在对接的是 `mobile/pipeline`（一键审计），**不再是车载工作台**，
车载看板仍在 `output/frontend-review/dashboard.html`。同一服务托管移动前端与 API，不需要另开静态服务。
只监听回环地址；客户端传文件内容，不传本机任意文件路径。

持久化目录默认 `output/mobile-workbench/`，可用 `--storage` 改为其他本机目录。
静态缓存键包含 APK 摘要、移动平台、规则版本、规则库摘要，以及 aapt2/dexdump/jadx/java 的实际选择路径（缺失为 null）。安装或配置 jadx/Java 后会产生新缓存身份，不再复用缺工具的 partial 缓存。排队期间工具选择变化会明确失败，需重新提交；服务重启后未结束任务标为中断，不能声称成功。

## 本轮能力与边界

- 上传 APK：后台执行移动静态扫描；`static.json` 与 `static_mobile_supplement.json` 保留各自来源。
- 静态发现附规则库中真实的法规/来源引用，结论统一封顶 `candidate`。
- 缺 `aapt2/dexdump`：任务明确 `blocked`，不是零发现成功。缺 jadx：静态结果可看，反编译标缺口。
- `rules_evaluated` 是适配器实际支持的规则数；`rules_loaded` 是所选库的启用规则数，两者不可混淆。
- 动态证据支持导入已有 `bundle_version=1` 包，或显式授权后运行服务端固定自有 Gadget 夹具；不自动启动模拟器、不执行 Root、不装系统 CA、不修改上传 APK。
- AI 只导入已有阶段 JSON，再用现有校验器重新校验。拒绝伪造的引用；导入方声称的 validation 不当成校验结果。
- 原始 AI 导入内容独立保存为 `ai-import-raw.json`，包括被拒阶段，供审计留存；接口只返回已通过阶段与校验问题，不把原始内容当作结论。
- 没导入 AI 时显示 `not_run`。通过校验的导入产物为 `imported_validated`，不声称本服务调用过模型。
- 报告中心区分历史快照和本任务报告。可从当前任务证据包生成新 PDF；没有证据不能生成完整审计报告，生成失败不会发布旧 PDF。本工作台不调用在线 AI。

## API

| 请求 | 结果 |
|---|---|
| `GET /api/health` | 工具就绪、移动规则信息、真实能力；设备 `not_probed`、AI `not_run` |
| `GET /api/devices` | 显式只读 ADB 枚举，返回 `{devices,observed_at,reason}`，不由 health 调用 |
| `POST /api/tasks/{id}/capture` | `{serial,authorized:true,permission_response:"allow"或"deny",generate_report:true}` → `202 {task_id,job_id}` |
| `POST /api/tasks/{id}/report` | `{}` → `202 {task_id,job_id}`；只使用当前任务证据，不接受路径或命令 |
| `POST /api/tasks/{id}/audit` | 一键审计：`{serial, authorized:true, mode, scenario, generate_report}` → `202`；需先通过 `workflow.can_audit` 与正控自检，详见 [README.audit.md](README.audit.md) |
| `GET /api/tasks` | `{tasks:[], count}` |
| `POST /api/apk?name=…` | 原始 APK 字节 → `202 {task_id,job_id,job,digest,cached}`；上限 512 MiB |
| `GET /api/jobs/{id}` | 状态、阶段、真实进度（未知时 `percent:null`）、错误和 task_id |
| `POST /api/jobs/{id}/cancel` | 取消请求；当前不可停止步骤结束后生效 |
| `GET /api/tasks/{id}` | 任务身份、阶段、计数、缺口、产物接口，及 `workflow/capture/operation/report_metadata` |
| `GET /api/tasks/{id}/static` | `available/status/findings/core_findings/supplement_findings/coverage/gaps` |
| `GET /api/tasks/{id}/tree` | `{available,files:[{path,size}],reason}` |
| `GET /api/tasks/{id}/source?path=…` | 受限源码 `{path,size,truncated,text}` |
| `POST /api/evidence/import` | `application/json` → `201 {task_id,task}`；上限 16 MiB |
| `GET /api/tasks/{id}/evidence` | `{available,origin,bundle,counts_observed,ai,gaps}` |
| `GET /api/reports` | `{reports:[{id,title,kind,task_id,available,url}],count}` |
| `GET /api/reports/{id}/file` | 受控 PDF 文件；不存在返回 JSON 404 |
| `GET /api/benchmarks` | 基准批次目录（`{batches:[…],count}`）；无批次时为空，不伪造 |
| `GET /api/benchmarks/{suite}/{sample}/evidence` | 单样本证据 JSON；不存在 404 `benchmark_evidence_not_found` |

证据导入支持原证据包本身，或包装格式：

```json
{"bundle": {"bundle_version": "1", "app": {}, "rules": {}, "dynamic": {},
            "traffic": {}, "policy": {}, "findings": []},
 "ai": {"stage1": {}, "stage2": {}, "stage3": {}}}
```

上面仅说明字段位置，空对象不是有效证据包。AI 阶段可省略；如提供，后序阶段必须有通过校验的前序阶段。
`counts_observed` 按实际导入条目计算，导入包自报计数不覆盖它。不同任务的证据不会自动合并。

## 离线/本机回归

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
& .venv/Scripts/python.exe -B -m unittest discover -s mobile/workbench -p 'test_*.py'
```

测试将所有任务/缓存放临时目录，分析外部工具用 mock；HTTP 集成只使用本机随机端口。
不需要设备、网络、AI key 或可安装 APK。mock 结果用于验证适配契约，不是设备实测证据。

## 执行与证据绑定

仅支持上传内容摘要匹配服务端固定 `app-debug.apk` 或 `app-gadget.apk`、包名匹配 `com.vscanner.privacydemo` 的任务；名字或包名相同不足以通过。Debug 变体通过时采集固定 Gadget，分别记录 `source_apk_sha256` / `capture_apk_sha256`、`same_apk_bytes=false` 和构建关系声明，不能将 Gadget 行为说成上传 Debug APK 的直接实测。

每次操作独占任务与设备采集资源，生成 task-owned `attempts/<job_id>/`，不通过 latest 指针查产物。运行/取消/失败及原始日志均保留；报告当前指针只指向成功、摘要绑定的任务报告。重采集开始即撤销旧 bundle 和 AI 当前状态，旧文件保留在新尝试目录。重报告开始撤销旧报告的当前指针，不沿用旧报告冒充成功。

设备取消通过 `cancel-requested` 文件合作停止，在安装、启动、UI 动作、policy/correlate/bundle/report 阶段之间检查；不会立即中断当前阻塞命令。完成后清理本轮 Hook、代理及本轮创建的 ADB forward。正常服务关闭请求取消并有界等待清理；异常强杀不能保证清理，后续冲突失败，不杀未知占用者。服务恢复将未结束的任务标为中断。

报告默认不附带导入 AI 章节（缺少本轮调用绑定），metadata 如实 `ai_state=not_run`；不会伪造 LLM 调用日志。

## 与上游并存

默认页面来自 `mobile/workbench/frontend/`，默认端口 8771（与 `mobile/pipeline` 撞，见「启动」段的提示）。
根 `frontend/` 后来被改成了「一键审计」前端（对接 `mobile/pipeline`），**不再是车载工作台**；
车载看板在 `output/frontend-review/dashboard.html`。两套前端互不引用。
自有 Gadget 入口是 `mobile/tools/device_fixture_run.py`；上游 `mobile/tools/device_run.py` 不替换。

开发增量、兼容取舍与合并说明见 [README.development.md](README.development.md)。
