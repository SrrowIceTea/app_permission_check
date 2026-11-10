# `.agents/` — DeepSeek Harness（DSH）在本项目里的技能与插件配置

> 仅用于授权开发与测试。**只改本目录，不要改 DSH 的安装目录。**
> DSH 会自动发现 `<仓库根>/.agents/skills/<name>/SKILL.md`，加完**下一个模型步就生效，不用重启**。

## 1. DSH 从哪里找技能

DSH 的 `@deepseek-ai/dsh-skill-filesystem` 按优先级扫描这些根（rank 越小越优先，同名技能高优先级覆盖低的）：

| rank | 来源 | 路径 | 本项目是否用 |
| --- | --- | --- | --- |
| 100 | project-dsh | `<仓库根>/.dsh/skills` | 否 |
| 200 | **project-agents** | **`<仓库根>/.agents/skills`** ← 本目录 | **是** |
| 300 | custom | 配置文件里的 `customSkillDirs` | 由 `programming` 预设占了（superpowers） |
| 400 | user-dsh | `~/.dsh/skills` | 不存在 |
| 500 | user-agents | `~/.agents/skills` | 只有 `hindsight-coding-agent` |

两条硬规则（踩过就查不到，别怀疑自己）：

- **仓库根 = 最近的带 `.git` 的祖先目录**。本仓库有 `.git`，所以命中 `mobile-app-permission-check/`。
- **只扫根目录的**一层：`<root>/<name>/SKILL.md` 或 `<root>/<name>.md`。
  **嵌套的 `**/SKILL.md` 不会被发现**——所以 `.workbuddy/skills/` 里的技能 DSH 看不见。
- 技能必须用 `/` 或 `.` 之外的**合法 kebab-case** 目录名，且 frontmatter 有 `name` + `description`，
  否则整条被跳过并打警告（静默失效）。

**实测确认**（2026-10-21，本机 `m1866` / DSH `0.2.1-rc.2`）：往 `.agents/skills/` 放技能后，
下一次模型步的技能目录里就出现了它；**符号链接目录也能正常解析**。

## 2. 本次装进来的技能

| 技能 | 来源 | 授权 | 文件 | 什么时候会用到 |
| --- | --- | --- | --- | --- |
| `frontend-design` | [anthropics/skills](https://github.com/anthropics/skills) | Apache-2.0 | 2 | 改 `frontend/` 定调、截图后自评"AI 味" |
| `webapp-testing` | 同上 | Apache-2.0 | 6 | 前端验收：起服务 + Playwright 点页面/抓 console |
| `skill-creator` | 同上 | Apache-2.0 | 18 | 把某个模块的踩坑经验固化成可复用技能 |
| `mcp-builder` | 同上 | Apache-2.0 | 10 | 真要写 MCP server（如把 V-Scanner 能力暴露成工具）时 |
| `dsh-error-handling` | [deepseek-harness/.agents/skills](https://github.com/deepseek-ai/deepseek-harness/tree/master/.agents/skills) | MIT | 1 | 设计/审查失败路径、重试、后台任务、错误上报 |
| `vscanner-frontend-redesign` | **本仓库已有** `.workbuddy/skills/`（符号链接指过来） | 自有 | — | 前端改版的工作流 + 四条红线 |

授权核对：`anthropics/skills` 每个技能目录自带 `LICENSE.txt`（Apache-2.0，共 4 份，**别删**）；
`deepseek-harness` 仓库根 `LICENSE` 是 MIT。两者都允许随仓库分发副本。

体积：`.agents/skills/` 共 **37 个文件 / 573 KB**（`skill-creator` 268 KB 最重，`mcp-builder` 153 KB），
**随仓库提交**（`.gitignore` 的 `skills/*` 只匹配根下 `skills/`，命不到这里，已用 `git check-ignore` 验证）。
无残留嵌套 `.git`（sparse clone 的 `.staging` 已删）。

### 关于官方 `.agents/skills` 的判定（20 个里只拿了 1 个）

用户点名要官方技能，但**绝大多数是 DSH monorepo 专用的**，直接搬过来只会指向一堆不存在的路径。逐个读过后的结论：

| 官方技能 | 判定 | 原因 |
| --- | --- | --- |
| `dsh-error-handling` | ✅ **拿走** | 30 行纯原则（契约/不变量、catch-recover-or-stop、报告必须可见），零仓库引用 |
| `dsh-code-review`、`dsh-pre-push-checks`、`dsh-ci-test-reliability`、`dsh-prose-standard`、`dsh-trim-cot-leakage`、`dsh-find-simplifications` | ❌ 不拿 | 正文里挂 `../../../docs/testing.md`、`packages/*/src`、`pnpm run doc-sync`、`gh stack`、Agent Notes——本仓库**一个都没有**（本仓库是 Python + Gradle，跑 `tools/run_regressions.py`） |
| `dsh-doc`、`dsh-client-ui-ux`、`dsh-responsive-ui`、`dsh-speed-up-perf`、`cordis-styling-nitpicking`、`dsh-official-plugin-artwork`、`dsh-translate-docs`、`dsh-create-upgrade-guide`、`dsh-merging-stacked-prs`、`dsh-archive-agent-notes`、`record-browser-gif`、`agent-experience` | ❌ 不拿 | 面向 DSH 产品自身（Cordis 插件生命周期、双语文档树、插件图标、`pnpm` 栈）。本仓库不需要。注：`agent-experience` 已在 DSH 的 `programming` 预设里，本会话可直接用 |

**要用的话怎么办**：别复制 DSH 的技能，把它的**原则**写成本仓库技能——`skill-creator` 就是干这个的。
本仓库已有的先例：`.workbuddy/skills/vscanner-frontend-redesign/`（自己的技能，自己的契约文件）。

## 3. 加/删技能

```bash
# 加一个上游技能（只拉要的那一个，别整仓克隆——见 skills/SKILLS.md §6：全量 1.5 GB）
git clone --depth 1 --filter=blob:none --sparse https://github.com/anthropics/skills.git /tmp/as
git -C /tmp/as sparse-checkout set skills/<name>
cp -r /tmp/as/skills/<name> .agents/skills/ && rm -rf /tmp/as

# 让本仓库已有的 .workbuddy 技能被 DSH 看到（新克隆后这条要重做一次）
ln -s ../../.workbuddy/skills/vscanner-frontend-redesign .agents/skills/

# 临时禁用某技能而不删文件
# 在其 SKILL.md frontmatter 加：disable-model-invocation: true
```

`.agents/skills/vscanner-frontend-redesign` 这个符号链接**已进 `.gitignore`**（本机便捷项）：
Windows 上 `git clone` 默认不还原符号链接，会变成内容为路径的文本文件 → 技能静默不加载。
所以每台机器克隆后自己 `ln -s` 一次，或者干脆改成 `cp -r`（代价：两处副本会漂移）。

## 4. 本次装的 DSH 插件（官方包，必须钉死 rc.2）

装在 `C:\Users\m1866\.dsh\profiles\desktop\`，是**机器级**配置，影响该 profile 全部会话。

| 包 | 提供 | 状态（2026-10-21 重启后核验） |
| --- | --- | --- |
| `@deepseek-ai/dsh-experimental-terminal-bundle` @ **0.2.1-rc.2** | 跨工具调用**保活 shell**（跑批/等模拟器时状态不重建） | 已装、bundle 已注册，重启 DSH 后插件行激活 |
| `@deepseek-ai/dsh-experimental-tool-worktree` @ **0.2.1-rc.2** | `git worktree` 建模成工具（两产品线隔离工作区） | 同上 |
| ~~`dsh-experimental-session-search`~~ | ~~检索历史会话~~ | **已卸载，别再装**，见下 |

**踩过的坑（重要，别再犯）**：experimental 包不带版本号会解析到 `0.2.1-alpha.2`，与本运行时
`0.2.1-rc.2` 不兼容。装 `session-search` 时它把 hoisted 的 `dsh-session-query-sqlite@alpha` 残留在
profile `node_modules` 里，宿主启动判定不兼容后**禁用了核心行 `session-query-sqlite` →
`sessionController` 注入失败 → 所有新建会话报错**，且**禁用 bundle 清不掉残留**（要移依赖 +
`pnpm install` + 重启才算修复）。所以：① 安装一律写全 `包名@0.2.1-rc.2`；② 出会话级故障先
`grep alpha pnpm-lock.yaml` + 查 `node_modules/@deepseek-ai/*` 的 version；③ 不要用 `allow-version`
豁免硬顶——那是拿崩溃和数据丢失换便利。bundle 从 profile 消失后需回补 `package.json`
的 `dsh.profile.bundles` 数组（本轮 terminal/worktree 两行被修复流程清掉后就是这样恢复的）。

已存在的 `superpowers`（TDD/调试/计划/评审/验证）与 `univer`/`office`/`hindsight`/`modlens`
本来就在目录里，无需再装。

### Hindsight 记忆：本地 daemon，数据不出机器（2026-10-21 配通）

- **后端**：`hindsight-embed` daemon，profile `coding-agent`，端口 **8899**。
  不用默认的 8888——那个口是本项目 mitmproxy 抓包端口，实测撞车（daemon 被挡在门外），别再改回去。
- **LLM**：走本机 `dsh-our-free-model` 的 OpenAI 兼容网关 `http://127.0.0.1:8326/v1`，
  模型 `deepseek-official/deepseek-flash`，key 在 `~/.dsh/openai-gateway/api-key`（provider 填 `openai`，
  `openai_compatible` 这个名字服务端枚举里没有，会被拒）。零云端、零额外账号。
- **配置文件两份**：
  - `~/.hindsight/coding-agent.json`：`{"serverMode":"daemon","daemonProfile":"coding-agent","apiPort":8899,"autoUpdate":false}`
    （autoUpdate 关掉，防止自动更新的 daemon 又要求新 wheel）；
  - `~/.hindsight/profiles/coding-agent.env`：LLM 三件套 + **`UV_PYTHON=3.13`**（必需——
    onnxruntime 没有 cp315 wheel，3.15 下 daemon 直接起不来）。
- **数据落盘**：`C:\Users\m1866\.pg0\instances\hindsight-embed-coding-agent`（嵌入式 PG）。
- 冒烟验证过完整链路：retain → 事实提取 → recall 命中 → 删 bank 全 200。
- **依赖顺序**：8326 网关是 DSH 插件进程 → 机器重启后要**先起 DSH 再起 daemon**，否则提取静默失败
  （daemon 本身会由插件按需拉起，正常不用手动管）。

## 5. 没做的事（避免你以为已经配好了）

- **没配 MCP server**。DSH 的 MCP 要在 `C:\Users\m1866\.dsh\profiles\desktop\cordis.patch.yml` 里加
  `@deepseek-ai/dsh-mcp-client` 条目（每服务器一条；当前该文件里**没有任何 mcp 行**），且 `frontend-design`
  那套验收依赖 Playwright——**本机现在既没装浏览器缓存（无 `%LOCALAPPDATA%\ms-playwright`），
  Python 3.13 也没有 `playwright` 模块**，所以现在接上必然连不通。要接的话先装依赖，我可以按 `skills/SKILLS.md` §4 给补丁。
- **没动 `skills/SKILLS.md`**（前端专用的上游仓库索引）和 `.workbuddy/`（WorkBuddy 专用）。
  两套体系分开：WorkBuddy 看 `.workbuddy/skills/`，DSH 看 `.agents/skills/`，内容同源不重复。
- **没装任何第三方社区 DSH 插件**（npm 上有一批 `dsh-plugin-*`）。社区包会执行安装脚本并改全局 profile，
  需要你自己点头；要我先出一份候选清单和风险再决定，说一声。

## 6. 顺带发现的环境漂移（会导致"假红"，建议尽快核对）

本仓库 `AGENTS.md`/`CLAUDE.md` 记的环境事实与**当前这台机器**不符：

| 文档写的 | 本机实测（2026-11-10 复核） | 后果 / 处理 |
| --- | --- | --- |
| Python `C:/Users/毛宇淇/.../Python313` | 用户名是 `m1866`；`environment.ps1` 用 `$env:LOCALAPPDATA` 派生 → `.../m1866/.../Python313`（**存在**，3.13.9） | 走 `environment.ps1` 或 `.\tools\python313.ps1` 就没事；**硬编码旧用户名的脚本/文档会失效** |
| 该 Python 装了 frida/mitmproxy/reportlab | **已装齐**（含 `frida-tools`）：`core/env_guard.py` 要求的 import（`frida`/`mitmproxy`/`cryptography`，移动侧再加 `jsonschema`/`PIL`/`pypdf`/`reportlab`）全在。裸 `python`（WindowsApps 3.15）仍缺 6 个 | 裸 `python` 跑回归会成片 `ModuleNotFoundError` 假红；三个入口已加 `env_guard`，缺库**退出码 3**。`maxminddb` 在 `requirements.txt` 里声明但全仓无 import，检查故意不要求 |
| SDK `D:\Anroid\SDK`、`JAVA_HOME=D:\Anroid\JDK` | `D:\Anroid\*` 与 `D:\Android\SDK` **都不存在**；SDK 在 `%LOCALAPPDATA%\Android\Sdk`，`platforms/` 有 `android-36`、`android-37.0`（都有 `optional/android.car.jar`），**没有** `android-35`；JDK 在 `D:\Android\JDK`（Temurin 21.0.12.1） | 照抄旧路径会找不到工具；`core/sdk_paths.py` 按 `VSCAN_SDK`/`ANDROID_HOME`/PATH 解析，`D:\Anroid` 只是最后兜底。原开发机目录名确实是 `Anroid`，不是本机笔误 |
| 设备/frida-server/模拟器 | `emulator-5554` 在线：API 35 / Android 15 / userdebug / automotive / `emulator_car64_x86_64`。AAOS 镜像与 AVD 在仓库 `output/vehicle-device-setup/`（`ANDROID_AVD_HOME=D:\AVD` 下只有手机 AVD），**不在** SDK `system-images/`；`output/_frida/` 本机不存在 | 别去 SDK Manager 找"AAOS 35 镜像"——它从官网单独下载，存放位置见 `vehicle/COMPATIBILITY.md`。换机先读 `docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md`，但注意其中 `D:/Anroid/*` 已按本机改注 |

> 2026-11-10 已按本机实测改写 `AGENTS.md`/`CLAUDE.md`/`README.md` 的环境表（SDK 路径、平台列表、
> 镜像位置、Python 解释器）。本表保留为"原开发机记录 → 本机实测"的漂移索引，别再照抄左列。
