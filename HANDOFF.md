# 交接文档（HANDOFF）

> 写给接手本项目的开发者。本文只列「现在有什么问题要修」和「未来可以做什么」，
> 已完成的实现与决策细节见 `mobile/DECISIONS.md`（M001–M056）与仓库历史。
> 最后更新：2026-10-21。

## 1. 项目十秒速览

移动端隐私合规检测工具链（`mobile/` 独立目录树，车载侧 `vehicle/` 不动，见 M001）。
Frida 插桩手机 App → hooks 采集隐私行为证据 → analyze 归因/风险 → report 出
SARIF 2.1.0 报告。核心入口：

| 模块 | 位置 | 说明 |
|---|---|---|
| hooks（Frida 插桩） | `mobile/hooks/` | `node build.mjs` 打包 bundle；`hook_all` 是单 agent 全栈装配 |
| 设备侧驱动 | `mobile/tools/` | `device_run_thirdparty.py`（跑批主驱动）、`validate_keylog.py`、`validate_native_migration.py` |
| 分析/归因 | `mobile/analyze/` | 风险模型、证据链 |
| 报告 | `mobile/report/` | `export_sarif.py`（官方 SARIF 2.1.0 schema） |
| 回归 | `tools/run_regressions.py` | 全量离线回归（修改收口前必须全绿） |

## 2. 硬约束（接手第一件事：读并遵守）

1. **单文件代码量 ≤ 300 行**，超了拆子模块 + re-export 薄壳（M055 惯例）。
2. **不得直接生成 policy_violation 结论**——只输出提示、优先级或人工复核标记。
3. **静态候选结果必须封顶**，避免无限制探索。
4. **所有决策写入 `mobile/DECISIONS.md`**（`## M<NNN> 标题（日期）`），与实现一一对应。
5. **任何修改过 `tools/run_regressions.py` 全量回归，无失败项才收口**。
6. 仅用于授权测试（自有设备与 APK）；LLM 输出只用于高风险隐私页定向深挖，控 token。

## 3. 待办（按建议顺序）

### 3.1【P0】i4 UI 覆盖收口（原计划下一步，纯离线，最快半天落地）
- **状态指纹**：对 UI 树（uiautomator dump XML）算结构哈希，新哈希 = 新页面状态，
  落进 coverage（状态集 + 计数），替代只看按钮点击。
- **Activity 计数**：按 Activity 类名计数，量化 G1 探索深度。
- 目标：给 UI 探索一个可复现的「覆盖率」口径（当前只有定性结论）。
- 参考：`mobile/tools/device_run_thirdparty*.py` 的 explore/analyze 阶段；
  指纹与计数需进 correlates/reads.jsonl 以便 report 呈现。

### 3.2【P1】Fastbot2 模拟器冒烟，可行则接入
- 提升 UI 探索深度（随机+模型化点击流）；先跑通模拟器冒烟再谈接入，
  接入点应是 explore 阶段的可替换引擎。

### 3.3【P1】ACVTool 量化真覆盖率
- 独立于「状态指纹」的真覆盖率工具；选一个样本 App 评估，
  产出与自研指纹的对照结论。

### 3.4【P1】keylog hook_all 下的 JIT 残余崩（D-054b，已定位未解决）
- **现象**：hook_all（全套 Java 替换 + native attach）装配后，冷进程任何 TLS 活动
  在 connect 窗口 12/12 死亡（SIGSEGV@Jit thread pool @0x7fe94c400000 /
  SIGABRT 交替）；单挂原生钩子（零 Java 替换）100% 存活。
- **已证**：keylog 链路本身是通的——tls_meta 单挂与 openmensa 样本均产出
  5 行完整 TLS 1.3 密钥（`output/_keylog-tlsmeta/`、`output/_keylog-sample/`）。
- **可试方向**（按性价比）：① 触发前进程预热（先跑一轮空负载再武装）；② 缩小
  Java 替换面（低频方法回退/合并在单一 Java.perform 内）；③ Frida 版本/ART
  兼容性排障（镜像 API 37/Android 16）；④ tombstone 深挖 SIGABRT@Thread-9
  的具体 abort message（logcat 有完整 tombstone）。

### 3.5【P2】上游观测为空（最高优先级的历史缺陷）
- 主链瓶颈不在报告层，而在**上游数据采集为空**：先查 hooks 是否真的被触发
  （hook-all.log 的 ARMED/事件计数），再查 driver 侧窗口与归因，最后才是报告。

### 3.6【P2】回归中 `hooks_parity` 失败项
- 并行通道 hooks/* 工作区引入，非 M055 拆分引入；接手后先修这项恢复全绿。

### 3.7【P2】已知小瑕疵（可顺手修）
- `inject_triggers.py` 的 DONE 判据失效：frida python 下 `console.log` 直进子进程
  stdout、不走 `message` 信号 → rc 恒 1。`validate_keylog.py` 已改为解析
  inject-run.log 绕开；建议把 inject_triggers 的判据也改成读 stdout。
- native 侧拿不到 `Cipher.getAlgorithm()` 算法名（i2 迁移边界）；需要时可单独挂
  `dist/hook_cipher.bundle.js` 排障。
- keylog 不做 100% 解密承诺：验收口径 = 部分解密 + 未解密帧数如实呈现。

## 4. 未来可提升（不阻塞，方向性）

### 4.1 LLM 定向 UI 测试（用户点名方向）
- 定位：LLM **只用于高风险隐私页的定向深挖**（识别页面语义、决策下一步点击），
  不替代探索引擎——通用探索交给 Fastbot2/指纹，LLM 控 token 只吃关键页面。
- 建议形态：探索产出可疑页面快照 → 批式（非逐帧）交给 LLM 出导航建议 →
  反馈给驱动。链路可复用 `mobile/ai/` 的现有契约/闸门模式。

### 4.2 spawn 支持（M038 边界）
- 本机 AVD 上 frida spawn 不可用（pid 第 5s 消失并重启）；spawn 能解决
  「应用在装载 agent 前建好连接、旧连接 SSL_read 无从补」的时序问题。
  如环境升级（新 AVD/真机 root），优先把 keylog 采集切到 spawn。

### 4.3 其他
- capture 离线分析回放（现有 session jsonl 的可视化/查询体验）。
- hooks 采集的字段级隐私标记（当前偏 API 级，字段级可提升报告精度）。

## 5. 常用验证/复现命令

```powershell
# 打包全部 hooks bundle（必须在 hooks 目录下跑）
cd mobile/hooks; node build.mjs

# keylog 夹具验证（4 轮分段；--hooks 可换单挂 bundle 做对照）
python mobile/tools/validate_keylog.py --target fixture --out output/_keylog-fix --attempts 4
python mobile/tools/validate_keylog.py --target sample  --out output/_keylog-sample --attempts 4
# 对照轮（证明 keylog 链路，已跑通）
python mobile/tools/validate_keylog.py --target fixture --out output/_keylog-tlsmeta --attempts 4 --hooks mobile/hooks/dist/hook_tls_meta.bundle.js

# 全量离线回归（收口门槛）
python tools/run_regressions.py
```

## 6. 设备环境备注

- 模拟器 AVD（API 37，userdebug）`emulator-5554`，**未**用 `-http-proxy` 启动；
  app 内访问宿主机 = `10.0.2.2`。
- frida-server 由 `thirdparty_env.ensure_frida_server` 自动管理
  （本地 `output/_frida/frida-server`）。
- 夹具 App：`com.vscanner.privacydemo`（label「隐私演示」，`mobile/fixture-app/`）；
  真实样本：`de.uni_potsdam.hpi.openmensa`。