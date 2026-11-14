# 车载工作台接入决策

仅用于授权测试（自有设备与自有 APK）。2026-11-06。

1. 用户要求移植移动端前端。复用视觉资源和交互布局，新增独立车载入口及 API，
   不将移动端页面改接车载，也不复用 MOB 规则、mobile.pipeline runner 或移动端 AI 输出。
   旧前端美化技能中的“只做移动端/后端零改动”是其限定工作流；本轮用户明确要求车载功能移植，
   视觉和 DOM 资料仅供复用参考，功能接入由本模块负责。
2. 默认仅静态；新采集需明确授权及设备参数，严格核对装机 APK 摘要后才操作设备。
   既有 capture_app 负责白名单、代理与进程收尾；run_audit 负责所有证据绑定与判定。
3. 服务固定回环监听，Host/Origin 限本机，上传有长度/容器检查；源码读取使用 core.static.jadx 的边界。
   浏览器只提交已登记采集的 ID，不接受任意文件路径；AI 配置也只由启动参数提供。
4. 每任务独立 UUID 目录；服务目录和动态设备分别使用内核文件锁。
   同设备的 CLI 采集不共享本锁，需要串行。锁文件残留不代表锁仍被占用。
5. 正常停止等当前任务收尾；异常退出的历史任务标 service_interrupted。
   保留失败证据，不自动重试、不声称设备已恢复。报告发布只认完整结束的 web 任务。
6. SSE 是任务进度，静态独立审计看板继续保持单文件事后视图；不改 D601。
   断线不改任务结果；运行任务保持独立订阅，新建任务清空旧页面，异步源码响应按请求序号门控。
7. jadx 非零退出且无源码是失败；部分输出保留覆盖缺口。AI 未配置显示 skipped，不冒充 subagent 签核。
8. 车载布局不使用移动端完成态的负 margin 覆盖过渡。标题、结果、进度使用正常文档流；
   运行和完成后隐藏设置，新建恢复。汽车图片使用独立本地资源与固定白名单路径，移动前端不变。
9. 字体与排版单独维护：本地 Noto Serif SC 标题，Manrope/Noto Sans SC 界面；等宽字体仅用于代码证据。
   顶部文件名与历史选择分开显示，透明原生 select 覆盖可见的历史控件并保留键盘/读屏语义。
   字体只通过三个固定路径提供，不开放整个字体目录或任意磁盘路径。
10. 证据复核是第七个独立页面，不绑定当前任务或 AI 辅助报告。只有启动参数 `--review-round`
    显式指定的目录可发布固定 `public-review.json`，`GET /api/review-round` 按闭合 schema 校验后返回；
    不提供目录、任意文件、路径查询、原始日志或写入端点。缺文件返回 404，格式无效返回 400，
    不回退组织者材料或历史轮次。bindings 仅平面 ID/摘要字符串。subagent 标签与人工签核区分；
    workflow_only 不并入配对计分，静态成功不代表动态通过。测试合成摘要明确标记，不作为签核证据。
11. 补齐前端所需字段放在**响应投影层**（`presentation.py`、`rule_titles.py`），不写回
    `output/vehicle-web/<任务>/` 的任何产物，也不改 `correlate.py` 的判定与计数。
    四档计数里 `correlated`/`observed`/`candidate` 取自摘要原值（缺键记 0），`unjudged` 由
    `findings_total` 反推；三档之外的键原样附加，不并入 `unjudged`，避免改口径。
    阶段耗时只认 `events.jsonl` 的起止事件，被跳过、仍在跑、事件不足两条的一律 `duration_ms: null`
    加 `unavailable_reason`，不做均摊或估算。APK 身份优先取 preflight 已核对的摘要值，
    没有时才现场对 `uploaded.apk` 计算；未跑完审计的任务 `findings_total` 是 `null` 而不是 `0`。
    规则标题只读 join `risk_rules`，按本轮 `android_version` 取值；库内没有中文标题，
    `VSC-LAB-*` 这类实验室结论行在库内无对应 id，统一 `null` + 原因，不翻译不兜底。
    详见 `FIELD_CONTRACT.md`。
12. 稳定的结论标识走**投影层内容指纹**（方案 A），不入 pipeline：`finding_uid` =
    `sha256(rule_id|conclusion_level|排序后 event_ids|排序后 code_locs)[:16]`，同内容按出现顺序加
    `-1/-2` 后缀。`review_order[].finding_id`（`finding-<下标>`）原样保留，AI 复核校验与 PDF
    排序继续用它；投影层绝不覆盖。副作用要记住：**证据一变 uid 就变**，旧复核记录会变成孤儿
    （保留在文件里、不再挂行），不会错配到新行。
13. 复核结果是本服务第一个业务写入口：每任务一文件 `review/finding-review.json`，键为 `finding_uid`。
    写端点强制本机 `Origin`（缺省也拒）、任务编号正则 `v-[0-9a-f]{32}`、`Content-Length` 必填且
    ≤8 KiB、不接分块传输、字段白名单；`reviewer_kind` 非 `human` 一律 403（与 `labels.py`
    拒绝 AI 标注计分同一立场）；未复核的行读取时是 `null` + 原因，不默认 `pending`。
    写只落到复核文件，绝不回写 `audit/*` 与 `conclusion_level`。读-改-写在进程内锁内完成，
    临时文件 + `os.replace` 原子替换；锁不跨进程，靠 `.service.lock` 保证单实例。
    中文标题另用展示层映射 `rule_titles.zh.json`（不改规则库），未映射回退英文原值并标 `locale=en`。
14. 契约以**真实响应**为准回头修订（2026-11-10）：`FIELD_CONTRACT.md` 原先漏记 `rule_title_locale`、
    还把"规则库没有中文标题"当成现状（那是加映射之前的结论）。本次按 `v-4505…`/`v-c723…`/`v-ca66…`
    的实际返回逐字段重写：`/findings` 新增 9 键（`rule_title`/`rule_title_locale`/`rule_title_source`/
    `finding_uid`/`review_status`/`reviewer`/`reviewed_at`/`review_note`/`review_status_reason`）；
    `field_gaps` 里不存在 `findings_total` 键（原因由 `findings_by_conclusion_level` 覆盖说明）；
    `/summary` 的 `findings_by_conclusion_level_gaps` 无缺口时**键不存在**而不是 `null`；
    `stage_timings_elapsed_ms` 是全部事件 `ts` 的 max−min，不是首尾两条之差。
15. `WinError 10053` 的根因在服务端不在测试：写接口在 `same_origin()`/任务编号/状态校验处提前拒绝时
    **没读请求体**，Windows 下关闭仍带未读接收数据的 socket 会发 RST，把刚写出的 4xx 冲掉。
    修法：POST 记 `body_pending`，`payload()`/`upload()` 读完即清；错误出口（`local_only`、
    `AuditError`、`500`）先把 ≤8 KiB 的未读体读掉再回响应，并给错误响应补 `Connection: close`。
    超 8 KiB 的请求体仍然不读（防 DoS），此时客户端可能看到 RST 而不是 `413`，这是有意取舍。
    负控测试 `test_rejection_still_delivers_status_with_unread_body` 连发 40 次拒绝请求做守卫。

16. 2026-11-15 用户要求打通车载前后端，明确排除移动端新功能。补齐失败任务显式授权重试、
    白名单日志尾部、版本/通用来源/TLS/多进程参数、政策与场景附件、AI 输出、完整证据 ZIP、
    反编译状态与逐规则覆盖读取。重试复制为新任务，不移动旧 APK 或覆盖旧失败；附件不改身份/
    session/摘要；ZIP 先校验命名引用，不递归发布任务目录。SSE 游标重连与前端去重不触发
    业务重跑。浏览器单飞上传，任务切换保持数据隔离。完整矩阵与实际验收范围见
    [前后端对接](../../docs/VEHICLE_FRONTEND_INTEGRATION_20261115.md)。
