# Phase 7 — APK 静态分析工作台

**仅用于授权测试（自有设备与自有 APK）。** 拖入 APK → 现场看反编译源码 + 静态规则匹配
+ 与运行时观测的四象限对照。决策见 `DECISIONS.md`（D701–D710）。

**这个工作台只读 APK**：不重打包、不签名、不注入、不修改。反编译由 jadx 完成。

## 目录

| 路径 | 作用 |
| --- | --- |
| `toolchain.py` | 定位 jadx / aapt2 / dexdump（环境变量 → 常见位置 → 响亮失败） |
| `apkmeta.py` | aapt2 取权限与包信息（与动态路径的 `requested-permissions.txt` 同源） |
| `dexfacts.py` | **全量** dex → `dexdump` → 代码引用事实（字符串 / 方法引用 / 字段 / 整型常量） |
| `static_rules.py` | 拿 `rules.db` 匹配事实 → 静态结论（等级封顶 `candidate`） |
| `crosscheck.py` | 静动四象限（both / static_only / dynamic_only / none） |
| `jadx.py` | 驱动 jadx 全量反编译、解析进度与部分失败、源码树与按路径读取 |
| `analysis.py` | 把上面几步串成一次分析（静态先出，反编译后出） |
| `jobs.py` | 后台任务 + 按 sha256 的磁盘缓存 + LRU 容量上限 |
| `server.py` | 本地服务（**只绑 127.0.0.1**），上传/进度/树/源码/结论/对照 |
| `web/` | 前端：拖放、进度、文件树、源码查看、结论表、四象限 |
| `test_*.py` | 离线回归 36 项，**不需要 jadx、不需要设备、不需要 APK** |

## 怎么跑

```bash
PY="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"

# 起服务（--session 给清单证明"同一个 APK"，--findings 给动态结论）
"$PY" phase7/server.py --port 8770 \
    --session output/device-20260928-015125 \
    --findings output/delivery-20260928-015231/findings.jsonl
# 浏览器打开 http://127.0.0.1:8770

"$PY" -m unittest discover -s phase7 -p "test_*.py" -t phase7   # 离线回归 36 项
"$PY" tools/workbench_acceptance.py --session <会话目录> --findings <findings.jsonl>   # 端到端，约 35s
```

## 本目录的坑（全部实测）

- **多 dex 必须全扫**：夹具的属性名只在 `classes3.dex` 里，只扫第一个**静默 0 命中**（D702）。
- **`dexdump` 用 `.` 连接类与方法**：`Lcom/x/Y;.m:(I)V`，不是 `->`。按 `->` 写正则全 dex 命中 0（D703）。
- **`CLASS_RE` 要逐字抄 `core/evidence/dexlines.py:45`**：手打多一个分号就命中 0（D703）。
- **危险 API 按三元组匹配**：`api_key` 不含类名，会误配同名方法（D704）。
- **属性"命中"要带区分度**：8 个属性 ID 同时出现时报 8 条强证据是误导（D705）。
- **逐类反编译太慢**（14s/类），必须全量一次（D706）。
- **部分反编译失败要当缺口**：jadx 报 5 个类失败，静默就当"类不存在"了（D707）。
- **动态侧为空不能当"什么都没发生"**：`findings.jsonl` 在**交付目录**里，
  指着会话目录读不到，象限表会自信地算成"全部 static_only"（D709）。

## 与现有阶段的关系

- **不替代 phase6 看板**：D601 要求看板是静态单文件（`file://`、无 fetch、无 CDN），
  而上传 + 反编译必须要有服务端。两者并存，`dashboard.html` 一个字节没动。
- **不碰 phase5 的行号链**：D507 的"违规行号只来自运行时栈"继续成立。
  静态证据用独立的 `evidence_kind`（`static_dex_reference`），**不写进 `code_locs`**。
- **不接进 `tools/build_delivery.py`**：工作台是交互式的，不是报告流水线的一环。
- **前端不引 CDN**（沿用 D601 约束一）：语法高亮是 `web/highlight.js` 自己写的单遍扫描器，
  不引 highlight.js——既因为拉不到，也因为那会破坏 phase6 那套"零外部引用"的验收。

## 状态（2026-09-28）

后端链路、静态规则匹配、四象限、前端均已完成并实测。
端到端验收 8 项全过：权限 8 条与动态路径一致、3 个 dex 全扫、
`GEAR_SELECTION` 在 `classes3.dex` 找到、静态等级封顶 candidate、
四象限 16 both / 6 static_only、身份证明为同一个 APK、
反编译出 930 个类、5 个部分失败被记成缺口。

**当前能力边界**：不做数据流分析（"调用了 CPM 读取方法"与"实参是哪个属性 ID"是两件事）；
不解析资源（`--no-res`）；不做反混淆（jadx 支持 `--deobf` / `--mappings-path`，未接）。
