# 存储与弱加密最小观测探针

仅用于授权测试（已获授权的设备与样本）；默认白名单仅
`com.vscanner.privacydemo`。宿主可显式配置精确包名数组，用于论文公开基准等授权样本。
既支持 root 模拟器上的外部 Frida Server，也支持应用已嵌入的 Frida Gadget；
不要求改包。本模块不负责安装或重打包，不改变业务返回值/异常，不写设备日志。
所有内容由 `send` 发到宿主，宿主保存 JSONL；请勿输入真实个人信息。

## 宿主使用

从仓库根执行，Python 需安装 Frida 17 的 `Compiler`：

```powershell
python mobile/audit/compile_probe.py
python -B -m unittest discover -s mobile/audit -p test_assess_probe.py -v
node mobile/audit/test_storage_crypto.mjs
```

编译默认在 `mobile/audit/storage_crypto.bundle.js` 输出自包含脚本。
CH checkout 缺 Node 依赖时，只读复用同级 `mobile-app-permission-check-main`
的 `vehicle/hooks/node_modules/frida-java-bridge/index.js`，也可显式传
`--bridge C:/absolute/path/frida-java-bridge/index.js`。
不下载依赖、不运行原生 Node 编译、不修改 `core` 或其他目录。
`Compiler` 先生成 IIFE，再 JSON 编码包装为全局 `eval`：保留 bridge 中的多行
C 模板字符串内容，同时生成文件只有两行（项目单文件 300 行约束）。
已有 bundle/assessment 改写前备份，输出写临时文件后原子替换。

Gadget 已配置、端口已由调用方显式转发、夹具处于可连接状态后：

```powershell
python core/frida_host/run.py --gadget --port 27044 `
  --package com.vscanner.privacydemo --allow-package com.vscanner.privacydemo `
  --script mobile/audit/storage_crypto.bundle.js --seconds 60 `
  --out output/YOUR-SESSION/storage_crypto.jsonl
```

以上命令会连接设备；**本模块的编译与离线测试不会连接设备**。
Gadget 早启动时应用对象尚未就绪会重试至多约 10 秒；只有收到
`ev=ARMED, src=storage_crypto, pkg=本次授权包名` 后才触发样本动作。
`ARMED` 只证明装钩，不能证明捕获、进程存活或磁盘落盘。
宿主应记录 detach/异常、设备标识与会话，不要混入上一轮数据。

root 宿主加载自定义授权样本前，必须在同一脚本上下文设置：

```javascript
globalThis.__VSCAN_AUDIT_PACKAGES__ = ['edu.ksu.cs.benign'];
// 随后加载 storage_crypto.bundle.js；配置不是替换真实运行事件中的包名。
```

没有该配置时仍只允许默认夹具；显式空数组、非数组、非法包名会产生
`PROBE_ERROR` 并拒绝装钩。不接受通配符。合法数组之外的运行包名产生 `SKIP`。
root Frida Server 会枚举多个进程，宿主必须按明确包名/PID附加，不能套用
Gadget专用“只有一个进程”逻辑。attach前调用不在观察范围，应在ARMED后触发测试。

root冷启动可由宿主spawn→attach→load→resume。探针用`Java.performNow`预装
`Application.attach`的观察钩子：原方法成功返回后安装探针一次，覆盖后续onCreate/
onResume；既有应用对象则仍由boot立即安装，不重复装钩。SDK36的android.jar是裁剪
stub、未含隐藏attach，故签名来自运行时overloads枚举，不标为SDK源码验证。
仅选择VM实际存在的唯一`android.content.Context`参数、void返回重载；
`BOOTSTRAP_ARMED`记录实际类型，失败写`HOOK_MISS`并保留boot回退。
这仍不承诺覆盖Application.attach内部、attach前ContentProvider/native动作。

评估必须显式提供**合成**标记（与样本测试输入一致）：

```powershell
python mobile/audit/assess_probe.py --events output/YOUR-SESSION/storage_crypto.jsonl `
  --canary SYNTHETIC_PROBE_ONLY_42 --evidence-origin device `
  --out output/YOUR-SESSION/storage_crypto-assessment.json
```

`--package` 默认 `com.vscanner.privacydemo`；授权基准使用例如
`--package edu.ksu.cs.benign`，仅评估精确匹配包名的事件，不改写事件身份。
Python函数 `assess(..., package=...)` 同样可选，未传仍兼容原夹具调用。

`--evidence-origin` 默认 `unverified`；`device` 只是调用方声明，不是自动认证。
离线测试使用 `synthetic`，不能把它描述成真机验证。
CLI 退出码 0 表示解析/评估完成，不代表“安全”，发现项由结果字段表示；
输入错误退出 2，编译错误退出 1。

## 事件契约

每条事件固定含 `{ev, ts, pkg, src, pid, tid, evt_id}`：`ts` 为设备进程
`Date.now()` 毫秒，不能直接和宿主时钟比较。`src` 恒为 `storage_crypto`。
wire payload 为 `{...event, line: JSON.stringify(event)}`，兼容现有宿主。

| ev | 成功后观测字段 / 精确范围 |
| --- | --- |
| `BOOTSTRAP_ARMED` | 早期Application.attach观察钩子的VM实际参数/返回类型；不等于业务探针ARMED |
| `START` | 白名单及 `device_logging=false` |
| `ARMED` | 实际装钩 `hooks`、失败 `missing`、`coverage_gaps`、捕获界限 |
| `PREF_PUT_STRING` | EditorImpl 的精确 `putString(String,String)`；key/value为有界文本；仅代表编辑器暂存 |
| `CIPHER_INIT` | 运行时枚举的 `init` 重载；`cipher_id`、真实第一个参数 `opmode`、`getAlgorithm()`、IV长度及 SHA256前16hex；不读取/输出密钥 |
| `CIPHER_FINAL` | 仅精确 `doFinal(byte[]) -> byte[]`；`input/output`各自有界bytes，方向依据该对象成功的init |
| `FILE_OPEN` | 四个String/File（可带append）构造成功；仅canonical路径在应用dataDir内；`stream_id/path/append` |
| `FILE_WRITE` | 仅已跟踪流成功的 `write(byte[])`、`write(byte[],int,int)`；`bytes/array_offset/path/stream_id`，offset仅是输入数组偏移，不是磁盘偏移 |
| `HOOK_MISS` / `OBSERVATION_ERROR` / `PROBE_ERROR` | 失败定位及有界错误信息，不能当零行为 |
| `SKIP` / `NOT_READY` | 不在白名单或应用对象未就绪，不继续装钩 |

文本形态：`{text, chars, truncated}`，key最多128 UTF-16字符，value256；
路径最多1024字符。bytes形态：`{hex,len,captured,truncated}`，最多256字节；
`len`为该调用真实范围长度，不是数组全长（offset重载按有效切片截取）。
只在原调用成功返回后观察；原调用抛出的异常原样传播，不发成功事件。
每线程重入保护避免Java重载委托/观测自身产生重复事件；相应嵌套调用不单列。

加密方向：opmode=1 → input plaintext / output ciphertext；opmode=2反之。
未见init、wrap/unwrap或其他值 → 两边均unknown，不把密文当明文。
`cipher_id`标识一次成功init（再次init会换ID）；弱配置来自init，不是数据泄露证据。

## 评估语义与边界

- `storage_plaintext_observed=true`：合成canary出现在成功存储API边界；SharedPrefs
  仅`editor_staged`，FOS为`successful_stream_write`。均不是磁盘取证/外泄证明。
- `weak_crypto_configuration=true`：成功init显式使用ECB、DES/3DES、RC4别名等；
  单独的`AES`不猜测默认模式，记coverage gap。
- 强GCM不命中已知弱项，**不等于安全**；弱配置**不等于泄露**。
- `disk_plaintext_proven/ plaintext_leak_proven/ crypto_safety_assessed`均固定false。
  若需证明落盘，必须另取授权样本文件/SharedPrefs XML证据，不能由putString推断。
- 不覆盖：SharedPrefs commit/apply落盘、其他字段类型、native/SQLite、FD构造、
  write(int)、外部/设备保护目录、Cipher.update及其他doFinal重载、手工加密。
- 有界前缀、attach前调用、并发修改、脚本/进程失活都可能漏数据；未观测不可判无行为。
- 明文预览仅为**授权样本的合成输入测试**的窄范围例外，不应复用到真实数据采集或LLM证据包。

## 精确密文写入关联（新增，不增加Hook面）

`cipher_storage.py`对同pkg、非空`session_id`、相同正整数`pid`的事件做窄关联：
成功的encrypt `CIPHER_FINAL`输入必须**完整、精确等于合成canary**，输入/输出均
未截断且`len/captured/hex`长度自洽；后续事件行的成功`FILE_WRITE`完整bytes必须
与密文输出**完全相同**，或与完整密文的**Android Base64.DEFAULT精确编码**相同，
设备时间差在`0..5000ms`。缺失身份/时间、解密、片段、截断、拼接、其他编码、
跨会话/进程均不关联。

Base64.DEFAULT严格按标准字母表和padding编码、每76字符LF换行、非空输出末尾LF。
使用重新编码全字节比较，不宽松解码、不删除空白；任意插入的空格/制表/换行、
CRLF、缺padding、非规范尾比特、前后垃圾都会拒绝。无换行的NO_WRAP不冒充DEFAULT。

输出`encrypted_storage_evidence`包含原始字节`relation=value_exact`、
`value_transform=identity`，或编码关系`relation=value_transform_exact`、
`value_transform=android_base64_default`；并含`written_bytes`、双方事件行/ID、
算法、配置分类、路径及时间差；`weak_ciphertext_storage_observed`仅在至少一组
精确写入关联的算法命中弱配置时为true。分类：`weak_configuration`、
`strong_algorithm_observed`（仅显式AES/GCM/NoPadding）、`unclassified_configuration`。
强算法分类不证明nonce/key/tag使用安全，未知配置不自动归强。

这是**API边界的精确值关系+先后顺序**，不是完整taint因果、整个文件的加密覆盖、
磁盘持久化或外泄证明；这些证明字段保持false。多个候选相同值可能同时关联，
不据此声称唯一来源。由现有`assess_probe.py`入口自动合并，无需更改真实事件。

```powershell
python -B -m unittest discover -s mobile/audit -p 'test_*.py' -v
```