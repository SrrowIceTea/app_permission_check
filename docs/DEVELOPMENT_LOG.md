# V-Scanner 开发日志

从 2026-11-15 起记录每次开发。按日期追加，同日多轮写明任务。开始时登记范围，收尾时记录改动、验证、证据和待办。达到 300 行时将旧记录转入按日期命名的分卷，并在这里保留索引。验收记录只引用可复核、无测试凭据的产物。

- [2026-11-15 至 2026-11-18 分卷](DEVELOPMENT_LOG_20261115_20261118.md)
- [2026-11-19 至 2026-11-22 分卷](DEVELOPMENT_LOG_20261119_20261122.md)
- [2026-11-24 车载环境搭建分卷](DEVELOPMENT_LOG_20261124_SETUP.md)

- [开发日志分卷 A](DEVELOPMENT_LOG_20261123_20261126_A.md)
- [开发日志分卷 B](DEVELOPMENT_LOG_20261123_20261127_B.md)

## 2026-11-27 · 自有夹具 HTTPS 采集复验

- 范围：核对移动自有 Gadget 夹具到本地接收端的 HTTPS 采集；修复设备验收发现的 TLS 审计开关传递问题。仅用于授权测试，TLS 校验收宽仅用于白名单进程的流量捕获。
- 首轮 `output/mobile-device-gadget-20261127-140301-430200/verification.json` 失败，Gadget 驱动未传递 `VSCAN_TLS_BYPASS`，TLS 钩子报告关闭，就绪门控在触发外发前停止。
- 修复 Gadget 驱动向 bundle 传递显式开关，默认关闭，包名固定为自有夹具。关闭时就绪检查立即给出诊断；增加默认关闭、显式开启、白名单及关闭诊断回归。
- 在自有 API 36 userdebug 模拟器中显式启用审计开关复跑，47 项检查通过，HTTP 和客户端 HTTPS 各捕获一条归因流和 200 响应，响应内字节数与请求正文 SHA-256 均匹配。收集端位于本机 HTTP 反向代理上游，响应经代理记录；未保存独立服务端回执文件。证据见 `output/mobile-device-gadget-20261127-140622-473900/verification.json` 和 `https-capture-verification.json`。
- 验证：夹具定向回归 26/26；根回归含移动检查 24/24（`output/mobile-https-final-20261127/root/verification.json`）；移动分支回归 26/26（`output/mobile-https-final-20261127/branch/verification.json`）；工程守卫通过。隔离模拟器已关闭，ADB 转发已释放。
- 待办：PCAP 报文重组、独立服务端回执及正式一键审计新任务的证据 ZIP 离线复算需另行完成。当前环境未配置 tshark。

## 2026-11-27 · 移动权限保护级别设备标定

- 范围：核对 API 36 手机模拟器的 40 条权限保护级别，保留设备指纹和原始证据，验证构建器及规则库的来源与数值。仅用于授权测试。
- 设备指纹、`pm list permissions -f -g` 原文及 40 条解析记录随库保存于 `mobile/rules/calibration/`。设备为 API 36 userdebug 模拟器，定义包均为 `android`。40 条原文和整数已进入发布库，`definition_status` 保持 `pending`，每条设备观测保存指纹及原文 SHA-256。
- 修复保护级别转换：`privileged` 从错误的 4 改为 SDK 36 声明的 `0x10`，补 `retailDemo`，任何未知标志导致整数留空。带设备版本的观测只用于对应版本，解析器的来源信息会写入设备观测。位值逐条与 SDK 36 `attrs_manifest.xml` 对照，源文件 SHA-256 为 `8164b282928162d32dbe775c7fb956adbd724076d8fbe5217a4e3584f5d7f441`。
- 候选库逐项比较 40 条权限及其他表，其他表内容一致。旧摘要写 API 58 条，与原库实际 68 条不一致，重建摘要后与数据库一致。核验记录在 `output/mobile-calibration-candidate-20261127/publication/verification.json`。
- 验证：`-m unittest mobile.rules.test_rules` 14/14；`tools/engineering_guards.py` 通过；`tools/run_regressions.py --mobile --out output/mobile-permission-final-20261127/root` 24/24；`tools/check_mobile_branch.py --out output/mobile-permission-final-20261127/branch` 26/26。来源追溯回归在全量回归启动后新增，已单独复跑通过。
- 待办：其他系统版本需使用各自设备观测。HTTPS 本地链路与两端独立应用验收仍待继续。

## 2026-11-27 · 两端后续工作与工程守卫复验

- 范围：复验移动后台断网对照，排查回归守卫，核对手机权限标定证据。仅用于授权测试。
- 移动 API 36 自有模拟器重跑后台只读、后台发送和断网补传，五档离线复算通过，断网后网络恢复。证据见 `output/all-tasks-offline-control-20261127/` 和 `output/all-tasks-offline-control-replay-20261127/verification.json`。读取观测来自自有夹具原生日志，独立应用案例为 0。
- 保存 API 36 设备权限原始输出、构建指纹及解析结果至 `output/all-tasks-phone-permissions-20261127/`，规则库 40 个权限均有同名设备声明。结果尚未入库，需将指纹和原始证据绑定标定记录并校验数值。
- 工程守卫修复：拆分超 300 行的可达性测试并加入移动回归；补两个异常诊断；同步根回归清单为 23 组。开发日志分卷并更新状态页链接。
- 验证：工程守卫通过，定向测试 25/25；根回归含移动检查 24/24（`output/all-tasks-regression-final-20261127/verification.json`）；移动分支回归 26/26（`output/all-tasks-branch-final-20261127/verification.json`）。正常本机权限下移动检查 63/63（`output/all-tasks-mobile-unsandboxed-20261127/verification.json`）。
- 待办：车载 F1、独立样本窗口与其他两端任务仍需逐项验收；移动权限标定尚未入库。本机未发现 AAOS AVD。首次受沙箱限制的回归出现套接字及临时文件权限错误，相关检查已在本机权限下复跑。

## 2026-11-27 · 后台/断网对照修复与真断网复验（完成）

- 范围：修复上一节审查发现的 2 条阻塞项与 6 项重要问题，重新做设备采集与五档重放；只改 `feature/mobile-window-benchmark` worktree，证据落 `output/mobile-offline-20261126/`（不入库）。
- 断网机制（实测选定）：`cmd wifi set-wifi-enabled disabled` 无效（wlan0 关后 eth0 接管，10.0.2.2 仍可达）；改用 `cmd connectivity airplane-mode enable`，实测 eth0/wlan0 同时 DOWN、`10.0.2.2` 返回 `Network is unreachable`，而 adb 与 `adb reverse` 不受影响（走调试通道）。判据要求"无 UP 且非回环的 IPv4 地址"，只看设置项会被 eth0 兜底骗过。
- 步骤重排：`bg-read-a → bg-probe-before → net_off → bg-probe-offline → bg-offline-send-a → net_on → bg-probe-after → bg-flush-a`。探针只建 TCP 连接即关闭、不产生回执；断网必须发生在发送之前。
- 接收端与代理换位：mitmproxy 固定监听宿主 18960，接收端绑随机端口。`10.0.2.2:18960`（真实网络路径）与 `127.0.0.1:18960`（reverse 调试通道）都经代理，两条路径都可归因；接收端全程在监听，因此"断网区间零回执"才有意义。
- 契约修复：`send-a` 恢复旧三字段 body（实测 93 字节，`run/source_batch/android_id`）；后台路径才带 `origin/thread`，补传另带 `source_batch_tokens/created_ms`。`cached` 改 `ConcurrentHashMap`；`bg-queue-clear` 改全清；`enqueue`/`offline_failed` 用当前 run 计数；`flush` 逐行确认后删除；`onCreate` 补齐 step 处理；`record` 增 `ts`。
- 判据补强：`truth_offline` 增加 START/ARMED/pid/whitelist/hook 健康校验、探针三段证据、断网窗口落在 `net_off`/`bg-probe-after` 步骤窗内、`body.bin` 改为唯一封存对象（不再读未封存的 `body-0.bin`）、`case_inputs()` 作为采集与重放共用的封存集合。
- 五档断言：`replay_offline` 逐档 `check`——`bg_read_only` 全 0、`bg_send` 全 1、`offline_resend` 5 秒必须 0 且 30 秒以上必须 1、所有档 `outside_reference == 0`、`tp+fn == |positive|`。关联器完全失灵会直接失败。
- 测试：`test_offline_control.py` 重写为 14 例（字段负例、探针负例、区间端点、多回执、只读外发、pid 不符、五档期望），连同旧四组 3 例共 17/17。
- 设备验收（`output/mobile-offline-20261126/full-v2/`，API36）：三组 manifest 全 passed，`cleanup_ok=true`。`offline_resend` 实测事件序为 read → probe(before,可达) → probe(offline,不可达/ConnectException) → enqueue(cached=1) → offline_failed(cached=1) → probe(after,可达) → flush_send → flush_done；回执 `received_ms` 在 `online_confirmed_ms` 之后，断网窗口内 0 回执。
- 五档重放（`output/mobile-offline-20261126/replay-v2/verification.json`）：`bg_read_only` 全 0；`bg_send` 全 TP=1；`offline_resend` 5 秒 FN=1、10/30/60/120 秒 TP=1；所有档 `outside_reference=0`。
- 旧四组回归（`legacy-four-v2` + `legacy-four-replay-v2`）：read_only 全 0、immediate 全 1、delayed/cross_batch 30 秒内漏配、60 秒起命中；`send-a` body 逐字段核对为三字段。
- 验证：`unittest mobile.lab.test_window_benchmark mobile.lab.test_offline_control` 17/17；`run_mobile_checks.py` 63/63；`git diff --check` 干净。
- 过程修正（如实记录）：① 可达性判断最初只看地址不看链路状态，飞行模式下 `eth0 DOWN` 仍挂 10.0.2.15 会误判"断网未生效"；② 设备日志 `ts` 与宿主步骤时间来自两套时钟（偏差约 250ms），跨时钟比大小会假失败，改为用步骤顺序 + 探针结果做顺序证据；③ `offline_control_capture.py` 超 300 行，接收端按职责拆到 `resend_receiver.py`。

## 2026-11-27 · 移动采集脚本公共层抽取（完成，新三组设备端重跑待补）

- 范围：把 `window_benchmark_capture.py` 与 `offline_control_capture.py` 中重复的 adb 包装、子进程生命周期、动作读取、采集环境注入抽到 `mobile/lab/capture_common.py`；两份脚本只保留各自的接收端语义与步骤编排。公共层 148 行，两份脚本 194/197 行（均 ≤300），重复实现约 150 行降为一份。
- 顺带修复审查项：新采集脚本改用 `adb.environment()`（此前 `os.environ.copy()` 会丢 `VSCAN_ADB`/`ANDROID_SERIAL`）；`sys.path` 注入集中到公共层一处（此前两处重复插入）；`am start` 统一检查输出中的 `Error`（此前只有旧脚本查）。
- 设备回归（API36，`output/mobile-refactor-20261127/legacy-four*`）：旧四组采集 + 重放全过，五档结果与重构前逐档一致（read_only 全 0、immediate 全 1、delayed/cross_batch 30 秒内漏配、60 秒起命中）。
- 未完成：新三组（后台/断网）在重构后的设备端重跑被环境打断。共享仓库有并行会话在反复重启 adb server、清理模拟器，采集在 `bg_read_only`/`bg_send` 完成后掉线（`device 'emulator-5566' not found`），未拿到完整 suite。离线 `unittest mobile.lab.test_window_benchmark mobile.lab.test_offline_control` 17/17；新路径与旧路径共用同一套 helper，差异仅在接收端与步骤表。待设备空出后补一次 `-m mobile.lab.offline_control_capture` + `-m mobile.lab.offline_control` 重放。
- 既有失败（非本次引入）：`run_mobile_checks.py` 62/63，`hooks_parity` 报 `stack_capture.js` 两侧不一致（车辆侧新增 `headLimit`，移动侧副本未同步），属并行会话的改动范围，本次未处理。

## 2026-11-27 · F-Droid 真实样本端到端测试：暴露并修复 6 项（完成）

- 范围：从 F-Droid 官方源下载 5 个真实样本跑静态 + 一键审计流水线，暴露问题即修。**未改规则库、未改结论等级、未放宽任何判据**；只修"流程本身跑不对"的缺陷。
- 样本：`D:/vscanner-tp/fdroid-samples-1127/`（voicerecorder 22 / newpipe 1017 / opentracks 6766 / calendar 25 / keepass.libre 45800）。宿主直连 f-droid.org 不通，走本机 7897 代理取官方 API + APK。
- 产物：静态 `D:/vscanner-tp/run-1127/<pkg>/static/`；流水线任务 `D:/vscanner-tp/run-1127/pipeline{,2,4,6}/<job>/`（含 events.jsonl / session / 报告）。

### 1. `system_ca` 永远装不上（`import transparent` 路径按输出目录推算）
- 现象：每次 `system_ca` 阶段 `failed: ModuleNotFoundError: No module named 'transparent'`，HTTPS 全解不开。runbook §10.5 记过同一句原文，当时归因"本轮 sys.path 指错"，未修。
- 根因：`device_run_thirdparty_run1.py` 用 `ctx.out.parent.parent/"traffic"` 反推代码目录；pipeline 下 out 在 `D:/vscanner-tp/...`，该路径不存在。其余 6 处调用点都用源码位置（`Path(__file__).parents[...]`），只有这处按输出推算。
- 修：改为 `Path(__file__).resolve().parents[1]/"traffic"`，与 device_boot / start_emulator / coverage_gap 同口径。
- 验证：同一台设备同一任务，阶段从 `failed(ModuleNotFoundError)` 变为 `done(CA 已进入系统库与 APEX 的 zygote 命名空间)`；`ca-install.json` 四步 rc 全 0。

### 2. 任务状态长期停在 `queued`（状态机缺 running）
- 现象：任务已跑完静态、正在动态采集，`GET /api/pipeline/<id>` 仍回 `state=queued`；前端刷新只能看到"排队中"。
- 根因：`job.state` 只在 `finalize()` 赋值，整条流水线（实测 5–15 分钟）没有 running 态。
- 修：`run_pipeline()` 入口置 `state="running"` 并 `remember()` 落盘。`history.lookup` 本就对 queued/running 校验 owner_token（进程没了收敛为 failed+interrupted），持久化安全。
- 验证：`test_runner_branches` 新增 2 例（进入 finalize 时已是 running、pipeline.json 落盘 running）；实跑 `state=running`。

### 3. 补充扫描计数自相矛盾（总数 6、分类合计 11）
- 现象：真实样本 `static_mobile_supplement.json` 里 `counts.findings_total=5`，`findings_by_rule_type={"sensitive_read":11}`。
- 根因：`reach_report.apply()` 把 `supp["findings"]` 收窄成 app_reachable 子集并重算 `findings_total`，但没重算 `findings_by_rule_type`（仍是过滤前口径）。
- 修：`apply()` 内按新 findings 重算分布；过滤前分布仍可从 `reachability_buckets` 与各分桶复算，信息不丢。
- 验证：`test_reachability` 新增 `ApplyCountsTest` 2 例；真实样本重跑后 5 = 5。

### 4. 多设备时全链路静默失效（裸 adb 报 more than one device）
- 现象：宿主机两台模拟器在线时，`adb root/remount/push/install` 全部失败，但错误被 `install_system_ca` 误报成"系统不可写，请用 -writable-system 重启"。
- 根因：工具链所有 adb 调用都不带 `-s`；`device_guard()` 的原意是挡这种失真，做法却是让整单失败。
- 修：`ensure_device()` 主动选一台并写 `ANDROID_SERIAL`（显式指定 > 当前在用 > 列表第一台），复用与冷启动两条路径都绑定。`device_guard` 保留原语义（用户显式跑批仍受保护）。
- 验证：`test_device_boot` 3 例（多设备自动绑定、显式 serial 优先、残留 serial 改绑）；实跑事件变为"已有一台模拟器在线：emulator-5554（共 2 台在线，已绑定…）"。

### 5. `_has_emulator_process()` 名不副实 → 误冷启动第二台
- 现象：`adb devices` 恰好为空（adb server 重启的那几秒）时，明明有 qemu 在跑却被判"无在线模拟器"，冷启动第二台 → 直接触发第 4 条自锁。
- 根因：函数名为 process，实现只查 `adb devices`。
- 修：先查 adb 列表，再查宿主进程（Windows `tasklist /FI IMAGENAME eq qemu-system-x86_64.exe|emulator.exe`，其他平台 `pgrep -f`）。
- 验证：`test_device_boot` 覆盖冷启动分支；真实环境 `_has_emulator_process()` 返回 True（adb 列表为空时）。

### 6. CA 装不上被当成"设备不可用"，整条动态跳过
- 现象：`adb remount` 被 dm-verity 拒后 `ensure_device` 返回 False → 13 个动态阶段全部 `skipped`，终态 `static_only`，运行时证据一条不留。
- 判断依据：CA 只决定 HTTPS 能否解密，不决定设备能否跑动态（frida 钩子/安装/交互/死亡取证都不依赖它）；且"复用在线设备"那条路径本来就不检查 CA，两条路径口径不一致。runbook §10.5 的处置也是"改用 Java/native 明文 hook"，不是放弃动态。
- 修：CA 失败只发 `boot running`（写明"HTTPS 无法解密，动态其余部分照常执行"），不阻断。
- 验证：`test_device_boot` 1 例（CA 失败仍 ok，缺口留痕，UWB 抑制仍执行）。

### 7. 补一条"流量未建立"缺口（CA 成功但上游全不可达）
- 现象：NewPipe 实跑 mitm.log 有明文 `GET https://www.youtube.com/...`（TLS 已解密），但 flows 0 条、连接错误 38 条全 `upstream_timeout`（宿主到 google/youtube 无通路）。此时报告只显示 `http_messages` 失败，没有"flows 为空 ≠ 应用没有外发"的说明。
- 修：新增 `traffic_gap_notes()`（纯函数），区分三种空：CA 未装 / CA 成功但上游不可达 / 真有流量。前两种写进 `bundle.gaps`。
- 验证：`test_device_tools` 新增 4 例；实跑 bundle.gaps 出现「流量未建立…代理记录了 30 条连接失败…不能写成「应用没有外发」」。

### 8. 既有失败闭环：`hooks_parity` stack_capture 漂移
- 上一条 11-27 记录里挂着的 `run_mobile_checks 62/63`（车辆侧新增 `headLimit`、移动侧未同步）本次一并修掉：`mobile/hooks/stack_capture.js` 回流可选参数 `headLimit`（不传时 `head=null`，输出与旧版逐字一致），保留移动端特有的 `NO_STACK` 早退；`node build.mjs` 重建 bundle（dist 已 gitignore）。
- 验证：parity 11/11 passed；`run_mobile_checks.py` **63/63 passed**（此前 62/63）。

### 环境事实（不是平台缺陷，如实记录）
- 宿主直连 `www.google.com` / `play.googleapis.com` / `f-droid.org` 均不通（`curl --noproxy` 超时），只有 `mirrors.tuna.tsinghua.edu.cn` 通。因此真实样本的 HTTPS 上游全部 timeout，flows 为空是网络事实，平台按第 7 条如实标注。
- 未装 tshark：`http_messages` 阶段报 `未找到 tshark`，pcap 报文重组不可用（verification 里 already 列在 optional_failed）。
- 设备抖动有一半来自并行会话：同一份日志前一条已记「共享仓库有并行会话在反复重启 adb server、清理模拟器」，本次复现同款（`emulator-5566 not found`）。第 4/5 条修复正是为这种环境准备的。

### 待办
- `docs/DEVELOPMENT_LOG.md` 已 480+ 行，超过 300 行上限：下次改动前把 11-26 及更早记录转分卷，主文件只留索引与最新两轮。
- 若要把 flows 链路在无外网环境也验证一遍，需要本地可解析的上游（fixture 靶子 + tls_probe_server），本次未做。
