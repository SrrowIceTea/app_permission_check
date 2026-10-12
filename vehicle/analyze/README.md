> 2026-09-24 当前增补与复现见 [根 COMPLETION.md](../COMPLETION.md)。以下旧实测条数、时间与未实现描述属于历史轮次，以当前交付说明和对应 verification.json 为准。

# 关联分析与报告（vehicle/analyze，原 Phase 5）

**仅用于授权测试（自有设备与自有 APK）。**

把前四阶段的产物串成证据链：**谁读了什么 → 谁发了什么 → 两者是否对得上**。

## 状态：两项交付物均已完成并实测

| 交付物 | 状态 |
| --- | --- |
| E. 关联分析（时间窗匹配 + 规则匹配） | ✅ 实测产出 5 条结论，含 1 条 correlated |
| F. PDF 报告生成器 | ✅ 3 页 PDF，中文字体已嵌入，内容经 pypdf 回读校验 |
| G. 违规代码行号 | ✅ 实测 6 处位置，全部经装机 APK 的 dex 行号表核对通过 |

## 跑起来

```bash
cd vehicle/analyze
# 1) 关联分析（内含违规代码行号的提取，见下）
python correlate.py \
    --rules ../rules/rules_library/rules.db \
    --reads ../hooks/logs/cap_vhal.jsonl \
    --egress logs/egress.jsonl \
    --flows logs/flows.jsonl \
    --permissions logs/requested-permissions.txt \
    --window-override-ms 30000 \
    --out logs/findings.jsonl --summary logs/findings.summary.json

# 2) 拿装机 APK 的 dex 行号表核对上一步报出的行号（独立一步，不核不算数）
python dexlines.py --apk ../targets/target-app/app/build/outputs/apk/debug/app-debug.apk \
    --verify logs/findings.jsonl --package com.vscanner.targetapp \
    --out logs/codeloc-verify.json --cache logs/dexlines-cache.json

# 3) 生成报告
python report.py --findings logs/findings.jsonl --summary logs/findings.summary.json \
    --rules ../rules/rules_library/rules.db --out logs/audit-report.pdf
```

`--window-override-ms` 见下面「时间窗校准」——**不加它会漏掉全部外发结论**。
第 2 步的退出码即核对结果：全通过为 0，有任一条不通过为 1。

## 三类规则与各自的结论上限

上限是**规则自己定的**（`risk_rules.conclusion_level`），引擎不抬高：

| 规则类型 | 谓词 | 结论上限 | 需要的输入 |
| --- | --- | --- | --- |
| `over_permission` | `manifest_permission_requires_necessity_review` | `candidate` | 清单权限 |
| `sensitive_read` | `successful_property_value_read` | `observed` | 读取事件（`outcome=ok`） |
| `data_egress` | `read_before_egress_within_window` | `correlated` | 读取 + 外发 + 内容匹配 |

**本工具不产出 `policy_violation`。** 是否构成违规是政策判定，要人来下。
报告里专门有一节写这件事，不是为了免责，是因为工具越界下判决才是真问题。

## 实测结果（2026-09-21，靶子 App `com.vscanner.targetapp`）

```
VSC-P001 [candidate/high]   over_permission  CAR_IDENTIFICATION
VSC-P002 [candidate/medium] over_permission  CAR_SPEED
VSC-P003 [candidate/medium] over_permission  CAR_POWERTRAIN
VSC-R003 [observed/medium]  sensitive_read   GEAR_SELECTION（1 次成功读取）
VSC-E003 [correlated/medium] data_egress     GEAR_SELECTION
      read#5 → flow#1  gap=10634ms  tls=False  content=True
      read#5 → flow#2  gap=20292ms  tls=True   content=True
```

最后一条是完整证据链：**读到了 GEAR_SELECTION，11~20 秒后两次把它发出去（含一次 HTTPS），
而且外发报文里确实出现了这个属性名。**

## 时间窗校准：3000ms 小了整整一个数量级

规则的 `window_ms = 3000`。基线文档早就标注它"是项目实验参数【需实测校准】，不是法规阈值"。
**实测下来这个值偏小一个数量级**：

| 路径 | 读取→外发间隔 |
| --- | --- |
| 靶子 App（HTTP） | **10634 ms** |
| 靶子 App（HTTPS） | **20292 ms** |

原因很清楚：应用**先读、缓存，等用户另行触发外发**，不是即读即发。
研究文档在 Phase 5 之前就预告了这一点——"应用普遍缓冲后批量上报，时间窗要放宽"。
现在有了实测数字。

实测对比：

| 窗口 | 结论数 | 结论分布 |
| --- | --- | --- |
| 3000ms（规则声明值） | 4 | candidate×3, observed×1 —— **外发结论全漏** |
| 30000ms（实测校准值） | 5 | candidate×3, observed×1, **correlated×1** |

**没有擅自改规则库里的值**：那是政策参数，该由人来定。引擎提供 `--window-override-ms`
作为校准旋钮，结论里同时记录 `window_ms` 与 `window_declared_ms` 并标 `window_overridden`，
报告里也明写"用了实测校准值覆盖"——读者能看出这个结论依赖一个被调过的参数。

## 内容匹配必须扫完整报文，不能扫 preview

第一版拿 `request_preview` 做匹配，结果 `content_match=False`——**把最强的那条证据丢了**。
原因是 preview 截断到 400 字符，而载荷 2463 字节，`GEAR_SELECTION` 在第 3 条读取里、
落在截断点之后。

改为：addon 在扫描**完整报文**时记下命中的字面量（`request_tokens`），Phase 5 查这个列表。
现在 `content_match=True`。

规则里写着 `content_match: required_to_upgrade_beyond_temporal_correlation`——
**它就是"时间相近"与"确实发了这个数据"之间的分界线**，不能因为一个截断就丢掉。

## 违规代码行号：运行时给，dex 核对

每条结论带 `code_locs`——**读取处**和**外发处**各自的 `文件:行号`。
行号不是从反编译推的，是 Android 运行时自己报的
（应用进程里 `Thread.currentThread().getStackTrace()`，每帧自带 `File.kt:128`）。

实测（真机一轮，证据在 `evidence/codeloc/`）：

```
VSC-E003 [correlated] GEAR_SELECTION
   读取处  VhalReader.kt:128   VhalReader.readOne
           ↳ VhalReader.readAll(VhalReader.kt:105)
           ↳ MainActivity.doRead$lambda$9(MainActivity.kt:118)
   外发处  EgressSender.kt:46  EgressSender.doSend
           ↳ EgressSender.send$lambda$0(EgressSender.kt:27)
```

**关键是"怎么从几十帧里挑出该负责的那一帧"**，有三件事都不能省：

- 栈顶永远不是答案（栈顶是钩子自己）。要按**归属**筛：类名以被测包名开头。
- **合成帧必须排除**。R8/D8 生成的 `$r8$lambda$…`、`$$ExternalSyntheticLambda…`、
  `D8$$SyntheticClass:0` 长得和真帧一模一样，行号是 0。把 0 当行号，
  报告里就会出现「MainActivity.kt:0」这种看着具体、实则没有的定位。
- 给整条应用调用链，不拿单帧当唯一证据：R8 会内联，最内层那帧未必是开发者写的那行。

**行号必须独立核对，不能自称可信。** 栈里的 `VhalReader.kt:128` 看起来可信，
但在核对之前没有任何东西证明它在**装机那个 APK** 里成立。APK 一旦重新构建，
栈里的行号就陈了——**而陈行号不会报错**，它只会指到一个不相干的位置，
让结论看起来有据可查。所以 `dexlines.py` 拿 dex 的 LineNumberTable 逐条核对：

| 状态 | 含义 |
| --- | --- |
| `VERIFIED` | 类、方法、行号、源文件名都对得上 |
| `LINE_NOT_IN_METHOD` | 类与方法在，方法里没这一行（APK 过期，或 R8 内联改了归属） |
| `METHOD_NOT_FOUND` | 类在，方法名不在 |
| `CLASS_NOT_FOUND` | 类都没有（代码被改名，或 dex 取错了） |
| `DEX_UNAVAILABLE` | **没给 APK = 没核对，不等于通过** |

实测 6/6 VERIFIED。另外**语义另行复核**过：`VhalReader.kt:128` 正是
`cpm.getProperty<Any?>(...)` 那行，`EgressSender.kt:46` 正是把载荷写进 socket 那行。

**核对证明的边界要写清楚**：它证明"该行号存在于该方法的行号表中"，
**不证明**该行号就是违规语义所在——所以报告里这句话是留着的，不是免责话术。

`code_locs` 为空时一定带 `code_loc_note` 说明为什么空（清单权限**本质**没有位置，
不写清楚就和"工具没找到"分不开）；只定位到一半时带 `code_loc_gaps`，
摘要里单列 `findings_with_partial_loc`——列表非空最容易让人以为两侧都定位到了。

## 文件

| 文件 | 作用 |
| --- | --- |
| `correlate.py` | 关联引擎：三类谓词 + 时间窗 + 内容匹配 |
| `codeloc.py` | 违规代码行号：从运行时栈筛出应用自己的帧 |
| `dexlines.py` | 用装机 APK 的 dex 行号表核对报出的行号 |
| `test_codeloc.py` | 行号提取与 dex 解析的离线回归，**不需要设备** |
| `report.py` | PDF 报告生成器（reportlab + 嵌入中文字体） |
| `logs/findings.jsonl` | 结论，每条带规则 ID/版本/证据事件 ID/代码位置 |
| `logs/codeloc-verify.json` | 行号核对结果（逐条状态） |
| `logs/audit-report.pdf` | 审计报告 |
| `logs/requested-permissions.txt` | 靶子 App 的清单权限（`dumpsys package` 抽取） |
| `evidence/codeloc/` | 行号那条链的原始证据：读取/出站事件、代理流、核对结果、PDF |

## 边界

- **同时刻多应用外发时归因可能配错**：按时间就近配对，容差 2000ms。
  Phase 4 已用双应用实测过（`vehicle/traffic/verify_multi_app.py`），Phase 5 这里未再验证。
- 非 HTTP 协议（MQTT/gRPC/QUIC）解不了内容，只能弱匹配；native TLS 同理。
- `CURRENT_GEAR` 实测可读但规则库里没有对应规则——**覆盖缺口**，不是判定失败。
- 被拒绝的读取（SecurityException）不计入 `sensitive_read`；那是"试图获取拿不到的权限"，
  是另一个信号，留给后续规则。
- **行号只在 Java/Kotlin 层有效**：native（BoringSSL/Cronet/gRPC）路径拿不到 Java 栈帧，
  这类外发定位不到源码行。
- **代码位置 ≠ 违规判定**：核对证明行号属于该方法，不证明该行就是违规语义所在；
  混淆与内联会改变行号归属。这是给人复核用的线索，不是自动判决。
