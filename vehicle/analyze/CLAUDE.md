# 关联分析与报告（vehicle/analyze，原 Phase 5）

**仅用于授权测试（自有设备与自有 APK）。** 把前四阶段的产物串成证据链：
**谁读了什么 → 谁发了什么 → 两者是否对得上**。**已完成。**
决策见 `DECISIONS.md`（D501–D509），全局约束见根 `CLAUDE.md`。

## 目录

| 路径 | 作用 |
| --- | --- |
| `correlate.py` | 关联引擎：三类谓词 + 时间窗 + 内容匹配（内含代码行号提取） |
| `codeloc.py` | 违规代码行号：从运行时栈筛出应用自己的帧 |
| `dexlines.py` | 用**装机 APK** 的 dex 行号表核对报出的行号 |
| `test_codeloc.py` | 行号提取与 dex 解析的离线回归，**25 用例，不需要设备** |
| `report.py` | PDF 报告生成器（reportlab + 嵌入中文字体） |
| `logs/` | findings.jsonl / findings.summary.json / codeloc-verify.json / audit-report.pdf |
| `evidence/codeloc/` | 行号那条链的原始证据：读取/出站事件、代理流、核对结果、PDF |

## 怎么跑

```bash
cd vehicle/analyze
PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"   # 只有它装了 reportlab（原开发机是 C:/Users/毛宇淇/...）

# 1) 关联分析。--window-override-ms 不加会漏掉全部外发结论（见下）
"$PY" correlate.py --rules ../rules/rules_library/rules.db \
    --reads ../hooks/logs/cap_vhal.jsonl --egress logs/egress.jsonl --flows logs/flows.jsonl \
    --permissions logs/requested-permissions.txt \
    --window-override-ms 30000 \
    --out logs/findings.jsonl --summary logs/findings.summary.json

# 2) 拿装机 APK 的 dex 行号表核对（独立一步，不核不算数）；退出码 0=全通过 1=有不过
"$PY" dexlines.py --apk ../targets/target-app/app/build/outputs/apk/debug/app-debug.apk \
    --verify logs/findings.jsonl --package com.vscanner.targetapp \
    --out logs/codeloc-verify.json --cache logs/dexlines-cache.json

# 3) 生成报告
"$PY" report.py --findings logs/findings.jsonl --summary logs/findings.summary.json \
    --rules ../rules/rules_library/rules.db --out logs/audit-report.pdf

"$PY" -m unittest test_codeloc      # 离线回归，25 用例
```

## 三类规则与结论上限

上限由**规则自己定**（`risk_rules.conclusion_level`），引擎不抬高（D501）：

| 类型 | 谓词 | 上限 | 输入 |
| --- | --- | --- | --- |
| `over_permission` | `manifest_permission_requires_necessity_review` | `candidate` | 清单权限 |
| `sensitive_read` | `successful_property_value_read` | `observed` | 读取事件（`outcome=ok`） |
| `data_egress` | `read_before_egress_within_window` | `correlated` | 读取 + 外发 + 内容匹配 |

**本工具不产出 `policy_violation`**——是否构成违规是政策判定，要人来下。报告里专门有一节写这件事。

## 本目录的坑

- **`window_ms = 3000` 小了整整一个数量级**（D502）：实测读取→外发间隔
  **10634ms（HTTP）/ 20292ms（HTTPS）**。应用先读、缓存、等用户另行触发外发。
  3000ms 下结论 4 条（candidate×3 + observed×1，**外发结论全漏**）；30000ms 下 5 条
  （多出 **correlated×1**）。**没有擅自改规则库里的值**——那是政策参数；
  引擎给 `--window-override-ms`，结论里同时记 `window_ms` 与 `window_declared_ms`
  并标 `window_overridden`，报告明写"用了实测校准值覆盖"。
- **内容匹配必须扫完整报文，不能扫 preview**（D503）：preview 截断 400 字符而载荷
  2463 字节，`GEAR_SELECTION` 落在截断点之后 → 第一版 `content_match=False`，
  把最强的那条证据丢了。改为 addon 扫完整报文时记 `request_tokens`，Phase 5 查这个列表。
  规则写着 `content_match: required_to_upgrade_beyond_temporal_correlation`——
  它就是"时间相近"与"确实发了这个数据"之间的分界线。
- **栈顶永远不是答案**（栈顶是钩子自己）：要按归属筛——类名以被测包名开头。
- **合成帧必须排除**：R8/D8 的 `$r8$lambda$…`、`$$ExternalSyntheticLambda…`、
  `D8$$SyntheticClass:0` 长得和真帧一样，行号是 0。把 0 当行号，报告里就会出现
  「MainActivity.kt:0」这种看着具体、实则没有的定位。
- **给整条应用调用链，不拿单帧当唯一证据**：R8 会内联，最内层那帧未必是开发者写的那行。
- **行号必须独立核对，不能自称可信**（D508）：栈里的 `VhalReader.kt:128` 在核对前
  没有任何东西证明它在**装机那个 APK** 里成立。APK 一旦重新构建行号就陈了——
  **而陈行号不会报错**，它只会指到一个不相干的位置，让结论看起来有据可查。
  `dexlines.py` 的五态：`VERIFIED` / `LINE_NOT_IN_METHOD` / `METHOD_NOT_FOUND` /
  `CLASS_NOT_FOUND` / **`DEX_UNAVAILABLE`（没给 APK = 没核对，不等于通过）**。
- **被拒绝的读取不计入 `sensitive_read`**（D505）：那是"试图获取拿不到的权限"，
  是另一个信号，留给后续规则。
- **归因来源路径必须可配**（D504），不能硬编码——理由同 vehicle/traffic 第 5 个坑。

## 状态（2026-09-24）

关联引擎、PDF、运行时栈与dex核对已实现；新版默认使用主机时间、同包同会话隔离。
正式启用的外发规则使用30000ms，不再依赖override；禁用规则不产生结论。
ownership.py支持RDAP缓存/HTTPS在线查询与可选MMDB；组织/地理信息未知时如实标示。
PDF包含捕获载荷渲染截图与覆盖缺口；旧preview与截断不得伪称完整报文。
当前8属性已有规则，CURRENT_GEAR=R004；动态计算并展示真正缺口，不编造权限映射。
dex缓存绑定APK SHA256；重建后须针对装机APK重验，不能复用旧的6/6徽章。
代码位置不证明违规语义；无定位仍需code_loc_note或code_loc_gaps。
