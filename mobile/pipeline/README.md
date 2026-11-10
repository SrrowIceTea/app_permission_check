# 一键审计流水线（Auto Audit Pipeline）

**仅用于授权测试（自有设备 / 已授权的公开第三方样本）。**

拖入 APK → 全自动跑「静态剖析 → 模拟器动态采集 → 关联分析 → AI 研判 → 报告」，
前端**实时**展示每个阶段的进行状态（模拟器就绪 / Frida 插桩 / 流量镜像 / AI 研判…）。

## 架构

```
mobile/pipeline/
├── stages.py    # 阶段定义（16 个）+ 事件读写（emit_events / read_events）
├── runner.py    # 流水线执行器：静态 → 设备自愈 → 动态 → AI → 报告（后台线程）
└── server.py    # HTTP + SSE 服务（上传 / 阶段流 / 产物下载）

frontend/
├── app.html / app.js / app.css   # 「一键审计」已集成进工作台（侧边栏第一项，默认页）
```

编排层**不重写检测能力**，只复用已跑通的脚本：
- 静态：`mobile/tools/static_scan_thirdparty.py`（移动规则库 + jadx 反编译）
- 动态+AI+报告：`mobile/tools/device_run_thirdparty.py`（内部 16 子阶段，经 `--events` 上报）

阶段事件是三方契约（runner / server SSE / 前端时间线），schema 单一：
`{"ts": float, "stage": str, "status": "running|done|failed|skipped", "message": str}`。

## 16 个阶段（前端时间线顺序）

`prepare` 环境准备 · `boot` 模拟器就绪 · `static` 静态剖析 · `frida_server` Frida 服务 ·
`network` 网络连通 · `install` 安装样本 · `launch` 启动应用 · `conn_probe` 连接采样 ·
`mitm` 流量镜像 · `hooks` Frida 插桩 · `explore` 交互驱动 · `death_probe` 存活取证 ·
`correlate` 关联分析 · `bundle` 证据封装 · `ai_review` AI 研判 · `report` 报告生成。

## 启动方式

```bash
PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"   # 原开发机是 C:/Users/毛宇淇/...

# 后端（只绑 127.0.0.1）
"$PY" mobile/pipeline/server.py --port 8771 --workdir D:/vscanner-tp/pipeline

# 前端（另开终端）
cd frontend && "$PY" -m http.server 8090   # 8080 被本机 httpd.exe 占用，避开
# 访问 http://localhost:8090/app.html —— 侧边栏第一项「一键审计」（默认页），
# 也可用 app.html#pipeline 直达；首页「一键审计」按钮同样跳这里。
```

端口分工：本服务默认 **8771**，`mobile/workbench/server.py` 默认 **8772**，两套可同时起。
不要再给工作台显式传 `--port 8771`，那是旧文档的写法。

## API

| 端点 | 方法 | 说明 |
| --- | --- | --- |
| `/api/stages` | GET | 阶段列表（id + 中文名） |
| `/api/pipeline?name=..&seconds=..&category=..` | POST | 上传 APK（原始字节），返回 `{id}` |
| `/api/pipeline/<id>/events` | GET | SSE 流式阶段事件；结束时发 `event: end`（`{state, result}`） |
| `/api/pipeline/<id>` | GET | 任务状态 + result（静态摘要 / report / bundle / verification） |
| `/api/pipeline/<id>/report` | GET | 动态审计报告（PDF） |
| `/api/pipeline/<id>/bundle` | GET | 证据包（JSON） |

## 设备自愈策略

- 已有模拟器在线 → 直接复用，绝不重启打断别的采集（注意：它**启动时刻**的代理探测
  结果无法追溯——若当时无代理在听，SLIRP 强制重定向就是关的）；
- 无 → **先前置启动 mitmproxy** → 冷启动 `VScan_Phone` → 装系统 CA → 抑制 UWB HAL
  崩溃循环。两件事都有硬原因（2026-10-16 实测，DEV_FIX_REPORT §5.9）：
  ① 代理必须先于模拟器进程存在——emulator 启动时探测代理可达性，失败会把 SLIRP
  强制重定向整条关掉且**不重试**；
  ② `-http-proxy` 必须传**宿主侧**地址 `127.0.0.1`——传 guest 别名 `10.0.2.2` 在宿主
  不可路由，探测必超时（也就是历史上一直出现的 "Proxy will be ignored!"）。
  设备侧 `global http_proxy` 设置仍为 guest 侧 `10.0.2.2`，两套地址空间各自语义不变。
- 冷启动失败（AVD 缺失 / 进程立即退出）→ **5 秒内快速失败**，动态各阶段如实降级为
  `skipped`，静态结论照常出，终态 `static_only`（前端明示「设备不可用」）。
- **抓包链路排障第一步**：查任务目录 `emulator.log` 里有没有 "Proxy will be ignored!"。
  出现即代表 SLIRP 重定向失效（只剩"读系统代理的组件"能被抓到）。

## 终态语义

- `done`：报告已生成（即便个别采集判据失败，如零运行时事件 A1 / AI 真实调用失败，
  报告已如实记录缺口，前端据 `verification` 展示「未通过项」）；
- `static_only`：静态完成、动态跳过（设备不可用）；
- `failed`：静态失败、或设备检测中断且未产出报告。

## 已端到端验证（2026-10-15，样本 org.fossify.voicerecorder）

冷启动模拟器 → 静态 5 条命中 + 补充扫描 8 条 + 4844 类反编译 → 设备动态采集 →
关联 → 证据包 → AI 真实调用 → 产出 `mobile-report.pdf`，16 阶段 SSE 全程推送。

**2026-10-16 复验**（JIT-off 复证 + SLIRP 代理修复后）：冷启动命令带
`-http-proxy http://127.0.0.1:8888`；`emulator.log` **零次** "Proxy will be ignored"；
前置 mitmproxy 先于模拟器就绪；guest raw socket（nc）实测被重定向进代理
（直连 example.com 拿到经代理 200、直连任意 IP 收到 mitmproxy 报错页）。
详见 DEV_FIX_REPORT §5.9。

## 已知限制（如实说明，不掩盖）

- **A1 已修**（2026-10-16：bridge 补丁 + 单 agent；JIT-off 路线已双向证伪并清退，
  见 M031/M032）。残余风险：个别样本仍可能出现零运行时事件（样本自身行为 /
  UI 驱动未触达等情况），`runtime_events_captured` 会如实红，报告以缺口呈现——
  不把「没捕到」写成「没收集」；
- **AI**：真实调用依赖 DeepSeek key（`VSCAN_LLM_API_KEY` / `config.local.json`）；
  未配 key 走 dry-run；调用失败不影响报告生成（报告标注「未生成 AI 研判」）；
- **设备**：动态采集依赖模拟器在线；离线时只出静态结论；
- 静态结论等级封顶 `candidate`；不产出 `policy_violation`。
