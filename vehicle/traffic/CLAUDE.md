# Mitmproxy 流量层（vehicle/traffic，原 Phase 4）

**仅用于授权测试（自有设备与自有 APK）。** 只抓取、只标注、不改写任何报文。**已完成。**
决策见 `DECISIONS.md`（D401–D410），全局约束见根 `CLAUDE.md`。

## 目录

| 路径 | 作用 |
| --- | --- |
| `addon.py` | Mitmproxy addon：流的生命周期、落盘、**挂起重试式**归因 |
| `attribution.py` | 时间归因与歧义判据（**可离线测试**，不依赖 mitmproxy） |
| `tagging.py` | 敏感载荷指纹与打标（**可离线测试**，不依赖 mitmproxy） |
| `test_attribution.py` / `test_tagging.py` | 各 10 个用例，不需要设备 |
| `verify_multi_app.py` | 双应用并发归因的验收脚本（拿载荷自报包名当基准） |
| `uid_sampler.py` | 设备侧 UID 采样器——**兜底，当前抓不到应用连接**（D402） |
| `logs/` `evidence/` | 流与事件、双应用验收的原始证据 |

## 怎么跑

```bash
cd vehicle/traffic
W="$(pwd -W)"                        # 不是 $PWD，见第 5 个坑
export VSCAN_FLOW_LOG="$W/logs/flows-round-N.jsonl"   # 不设会混进既有证据，见下
export VSCAN_ATTRIB_SOURCES="$W/../hooks/logs/egress_events.jsonl"
export VSCAN_PACKAGES="com.vscanner.targetapp,com.vscanner.targetapp2"
mitmdump -s addon.py --mode reverse:http://127.0.0.1:8080 \
         --listen-host 0.0.0.0 --listen-port 8888

# 另一终端：应用进程内观测出站（归因主来源）+ SSL 绕过（HTTPS 明文需要）
PY313="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"
"$PY313" ../core/frida_host/run.py --package com.vscanner.targetapp \
    --script ../core/frida_host/dist/hook_egress.bundle.js --seconds 60 \
    --out logs/egress_events.jsonl &

# 再一终端：先读后发（顺序不能反，D404）
"$PY313" ../targets/trigger.py --package com.vscanner.targetapp --button btnRead
"$PY313" ../targets/trigger.py --package com.vscanner.targetapp --button btnEgressHttp

python -m unittest test_attribution test_tagging      # 离线回归，20 用例
python verify_multi_app.py --flows evidence/flows-multi-app.jsonl \
    --egress evidence/egress-multi-A.jsonl --egress evidence/egress-multi-B.jsonl
```

**必须 Ctrl-C 正常退出**（`done()` 排空挂起队列）；强杀最多丢宽限期内最后几条。

## 本目录的坑

- **`$PWD` 不能写进 Windows 环境变量**：Git Bash 的 `$PWD` 是 `/c/Users/...`，被转成
  `\c\Users\...`——一个不存在的路径。而 `_refresh()` 的 `if not path.exists(): continue`
  是**静默跳过**的，于是"源配错了"和"今天没有出站流量"结果完全一样：每条流
  `package=null`，一条异常都没有。用 `$(pwd -W)`。启动日志会打每个源的绝对路径与存在性。
- **白名单默认给两个包名**，不是零个也不是一个：单包名白名单有个比归因失败更难发现的
  失败模式——归因**成功**到第二个 App 时，"已归因且不在白名单"会让这条流被**静默丢弃**。
- **包名比较必须精确相等**：`targetapp` 是 `targetapp2` 的前缀，子串包含会把 A 判成 B
  （曾误报 `*** CROSSED ***`）。
- **egress 事件结构上必然晚于对应的流**（`Socket.connect` 返回后才记录）。当场定成
  `unresolved` 会把可恢复的时序问题永久化——必须挂起重试（D408，3000ms 宽限期 +
  0.5s daemon 冲刷）。
- **`intercepted_tls` 取客户端连接是否握手，不是 `req.scheme`**：反向模式下 `req.scheme`
  是上游协议，用它会把"客户端走 TLS、上游明文"误报成没拦截——把成功看成失败。
- **AAOS 模拟器网络只走 wifi**：`Can't find service: ethernet`，`eth0` 永远 down。
  `cmd wifi connect-network AndroidWifi open`；wifi 会周期性掉线，掉线后所有设备侧操作
  静默失败，排查任何异常前先看 `ip -brief addr show wlan0`。
- **系统全局代理不会传播到 wifi 网络**：`settings put global http_proxy` 设了也白设
  （`dumpsys wifi` 恒为 `Proxy settings: NONE`）。所以用反向模式，由被测应用直接寻址（D401）。
- **`adb shell` 从脚本里跑时单个 `-t` 不分配 pty**：设备上的 `grep`/`sed` 会块缓冲，
  实测 `-t` 收到 0 行、`-t -t` 收到 232 行/5s。
- **`VSCAN_FLOW_LOG` 不设就混证据**：flows 是追加写的，新一轮会混进既有审计凭据，分不开。
- **归因是统计性的，不是确定性的**：容差 2000ms 对"两个 App 2 秒内先后外发"本身不敏感，
  能分开靠"最近匹配 + 亚军距离判据"。分不清标 `attribution_ambiguous` 而不是猜
  ——**错误归因比没有归因更糟**，它会把无辜的 App 写进报告。

## 状态（2026-09-24）

包名归因、敏感打标、HTTP/HTTPS明文、原始载荷摘要与SQLite双写已实现。
所有候选统一等3000ms宽限期再定案，避免后到采集事件缺席；歧义流保留标记。
失败连接和启动日志不作为归因候选；JSONL仍是原始证据，明确session隔离。
collector_server.py提供/collect的200响应与载荷摘要，替代旧httpd的404。
uid_sampler仍保留但不要继续投入；native TLS、MQTT/QUIC、未解析gRPC不在明文覆盖内。
第三方包必须显式授权且已配置钩子与代理，不能宣称自动捕获整机任意App。
