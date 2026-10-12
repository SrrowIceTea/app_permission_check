# Phase 7 决策记录（D701 起）

仅用于授权测试（自有设备与自有 APK）。全局约束见根 `CLAUDE.md`。

## D701 静态证据的等级上限是 candidate

`rules.db` 的 `conclusion_level` 里，`observed` 在本项目的定义是**运行时观测到**
（见 phase5 的三类规则上限表）。静态分析只能得出"代码里**引用**了 X"，
得不出"运行时读了 X"——中间隔着条件分支、反射、以及"这份代码根本没被执行到"。

所以 `static_rules.cap_level()` 把任何声明等级压到 `candidate`，并把原等级
保留在 `declared_conclusion_level` 里供对照。工具**不产出 `policy_violation`**（沿用全局约束）。

同理，静态证据**不写进 `code_locs`、不参与 dex 核对**：D507 已经确定违规行号只来自
运行时栈。把反编译行号混进去会让读者以为两者对齐，而 R8 内联与反编译漂移会让它们
根本对不上——那正是 D507 当初要避开的坑。

## D702 多 dex 必须全扫，否则静默零命中

实测：夹具的 `GEAR_SELECTION` / `289408000` **只在 `classes3.dex` 里**。
只扫 `classes.dex` 得到 0 命中，而且**不报任何错**——看上去像"这个 App 没读 VHAL"。

`dexfacts.extract_dex()` 用 `^classes\d*\.dex$` 取全部并按**数字序**排
（`sorted()` 是字典序，`classes10` 会排在 `classes2` 前面）。验收脚本专门断言
`_per_dex` 里至少两个 dex，就是为了钉这条。

## D703 `dexdump` 用 `.` 连接类与方法，不是 `->`

形态是 `Landroid/car/hardware/property/CarPropertyManager;.getProperty:(II)Landroid/car/hardware/CarPropertyValue;`，
**不是** JVM 标准的 `L...;->getProperty(...)`。第一版按 `->` 写正则，**全 dex 命中 0**。

而且类名与方法/描述符要**分开取再拼**：整段拿去比对 `dangerous_apis` 对不上。
拼出来的三段正好是 `class_name` / `method_name` / `jvm_descriptor`。

另外 `CLASS_RE` 必须与 `core/evidence/dexlines.py:45` **逐字一致**——我手打时把结尾写成
`;)';`（多一个分号），于是类名命中 0，而其它计数都正常。

## D704 危险 API 按三元组匹配，不按 `api_key`

`dangerous_apis.api_key` 只由 `method_name + jvm_descriptor` 组成（`extract_seed.py:134`），
**不含类名**。跟着它匹配会把 `com.example.Evil.getProperty(II)L...;` 也算成 CPM 调用。
用 `(class_name, method_name, jvm_descriptor)` 三元组——那也是 schema 里 UNIQUE 索引的列组合。

## D705 属性信号必须带"区分度"，不能只报"命中"

实测夹具：`VhalProps` 一次性声明全部 8 个属性 ID，于是**8 个 ID 和 8 个属性名全都**
出现在 dex 里。第一版把"CpmApi 被调用"也算进每个属性的信号，结果 **8 条规则一起显示
`strong`**——看起来证据很硬，其实毫无区分力，读者会得出"这个 App 读了全部 8 个属性"。

现在三条信号分开记（`property_field_ref` / `property_id_constant` / `property_name_string`），
并显式算 `non_discriminating`：同一份 dex 里还有别的已知属性 ID 时，只靠 ID/名字出现
**不能**定位到某一个属性，强度降为 `weak`，理由写进结论的 `note`。

**当前不做数据流分析**，所以"代码调用了 CPM 读取方法"与"CpmApi 的实参是 285408000"
是两件事，后者本阶段给不出来。

## D706 全量反编译而非逐类按需

实测 `--single-class` 单次 **14.1 秒**（每次都要重新装载 APK 并建索引），点一下等 14 秒
在交互上不可用。改成拖入时全量一次（3.6MB 夹具 **28–33 秒**、930 个类、11MB），
之后浏览走磁盘现成文件，毫秒级。

代价是首次等待长，所以：静态扫描（秒级）**先于**反编译执行并立即出结果，
用户在等反编译时已经能看权限与规则匹配。

## D707 部分反编译失败是缺口，不是"类不存在"

jadx 对夹具报 `finished with errors, count: 5`，且返回码非 0。这属于正常的部分失败，
但**必须显式展示**：否则用户会把"没解出来"读成"这个类不存在"。
`decompile()` 把它包成 `gap`，验收脚本断言"有错误就必须有 gap"。

同理，缓存只在**成功且无未完成标记**时打 `.complete`；失败或取消留下的半个产物
不会被下次拖入当成完整结果复用。

## D708 上传不走 multipart，且必须分块落盘

项目里没有 multipart 解析器，而 `phase4/collector_server.py` 已确立
"有界 Content-Length + 原始字节"。浏览器 `fetch(url, {method:'POST', body: file})`
天然支持，于是 `POST /api/apk?name=x.apk`，body 就是 APK 字节。

**分块落盘并边写边算 sha256**：第三方 APK 可到几百 MB，读进内存会把进程撑死。
写完用 `shutil.move` 入缓存，不再读一遍。

路径一律 `urlsplit(self.path).path`——absolute-form 的坑 2026-09-28 踩过（见 D411）。

## D709 空动态结果**不能**当成"运行时什么都没发生"

`findings.jsonl` 在**交付目录**里，不在设备会话目录里（会话目录只有
reads/egress/flows/verification）。指着会话目录时如果读不到就当空，
象限表会算成"22 条 static_only"——而真相是"动态侧压根没载入"。
两者在界面上长得一模一样，而且都像是结论。

所以：`resolve_findings()` 说清是从哪个路径找到的；`compare()` 在动态侧为空时
**拒绝出象限表**并给出原因。`--session`（清单，证明是同一个 APK）与
`--findings`（动态结论）是**两个**输入，分开传。

## D710 未知身份的静默放行与否决

APK 身份三态：`same_apk` 为 `True` / `False` / `None`（没有清单，**无法证明一致**）。

- `False` → 拒绝对照（拿两个不同 APK 比，每一格都是错的）
- `None` → **允许**对照，但把"无法证明一致"写进结果，由读者判断

这里没有取巧：既不能默认放行（把前提当结论），也不该一律否决（那是把"没证据"
当成"反证"）。两种都会让象限表变得不可信，只是方向相反。

## D711 工作台不做"授权勾选"这种界面闸门

原设计在拖放区放了"我确认对这份 APK 有分析授权"的勾选，不勾就拒绝上传。
2026-09-28 按用户要求移除。

理由与保留的东西：

- **界面闸门拦不住也不证明任何事**。真正决定"能不能分析某份 APK"的是使用者有没有授权，
  而这是使用者的责任，不是工具能验证的。一个自证的勾选只会增加操作摩擦，
  却给不出任何可追溯的证据——它既不记录、也不上链、也不影响工具行为。
- **授权声明改为陈述而非交互**：页头保留"仅用于授权测试（自有设备与自有 APK）"
  与"只读取与反编译，不重打包、不签名、不注入、不修改 APK"。声明仍然在，
  只是不再假装它是一道闸门。
- **能力边界没有变化**：工作台仍然只读 APK；不重打包、不签名、不注入。
  全项目的"仅授权测试"约束（根 CLAUDE.md 第 1 条）不变。

如果将来要做真正的授权留痕，正确的做法是**记录**（谁、何时、分析了哪份 APK 的
sha256），而不是在界面上加一个点了就过的勾。
