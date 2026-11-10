# 双人一周方案：B侧定位输入与验收接口

仅用于授权测试（自有设备与已获授权APK）。B只读取A封存的输入，不启动设备、不修改Hook或App格式。
对应桌面 `TWO_PERSON_ONE_WEEK_PLAN_CURRENT_20261110.md` 的D1–D5。

## 1. 分工与交接

A提供真实新会话；B执行健康校验、只读副本重放、实验表和报告。
历史OwnTracks结果、合成夹具和ARMED均不能代替本轮通用定位读取。
新会话不得继承旧签核；输入来源 `device` 是交接方声明，不能由这个字段证明设备真实性。
动作记录验证不等于独立人工金标准，输出中的 `workflow_verified` 保持false。

每类场景单独一个session：

| kind | B核验条件 |
|---|---|
| controlled_positive | 通用定位读取、同身份/窗口完整请求、实验候选、同轮接收正文摘要相符 |
| different_value | 有身份/窗口可比组合，异值整对字符串0候选 |
| single_coordinate | 有身份/窗口可比组合，分离或单坐标0候选 |
| repeated_origin | 多来源仍有歧义流，不强行唯一归因 |
| third_party | 新自然工作流动作记录与健康输入；独立展示读取/正文/匹配缺口 |

负控不能因无输入、异UID或超出窗口而通过。上述场景属性来自A的动作声明，B的自动检查不能独立证明
真实执行了该操作；人工交接须核对触发日志、业务步骤和接收记录。跨UID/user/session、PID同号、
截断/正文缺失、压缩/脱敏等方法边界另由定向反例验证。

## 2. handoff.json

从 `vehicle/privacy/location-handoff.example.json` 复制到本轮私有目录。
空cases是“待交接”模板，运行必须返回incomplete/退出码2，不能当作通过。
本周限定AAOS API35/Android15；路径相对handoff.json解析，也可用绝对路径。
`input_kind` 必须为device或synthetic；后者即使所有场景满足条件，也只能为synthetic_only。

cases中每项的格式：

```json
{
  "id": "owned-positive-new",
  "kind": "controlled_positive",
  "package": "your.authorized.package",
  "capture": "positive/capture",
  "apk": "owned.apk",
  "rules": "rules.db",
  "actions": "positive/actions.json",
  "actions_sha256": "填写actions文件完整SHA256",
  "receipts": "positive/receipts.json",
  "receipts_sha256": "填写receipts文件完整SHA256"
}
```

id限字母开头的字母/数字/下划线/短横线，最多64字符，不重复。
正例必须提供receipts；其他场景不需要receipts。
历史catalog需可选 `catalog_snapshot`，其摘要必须匹配原manifest；不修改原契约。

capture必须包含：

- session-manifest.json：目标白名单、唯一session、user_id、Android版本、API、APK/规则摘要、实际bundle摘要。
- reads.jsonl、flows.jsonl、verification.json、collector-health.json：均在input_sha256中绑定。
- input_sha256中列出的其他原始文件；hook-bundles/下本轮used_hook_bundles的原始字节。
- verification的passed与checks全部为true；collector-health为completed且session_id一致。

必须保留既有采集器的收尾检查：workers_stopped_cleanly、worker_cleanup_healthy、
device_settings_restored、device_reverse_restored、apk_unchanged、original_process_alive、
no_hook_errors、collector_callbacks_healthy、proxy_log_redaction_healthy。
这些字段缺失或失败时保存blocked，禁止补造为true。
验收仍调用原vehicle.pipeline.preflight，不放宽白名单、APK、规则、bundle或钩子就绪要求。

## 3. 动作与回执

actions.json至少包含下列字段。示例仅定义结构，其中内容须由本轮真实记录填写。

```json
{
  "session_id": "本轮session",
  "capture_manifest_sha256": "本轮session-manifest.json完整摘要",
  "kind": "controlled_positive",
  "completed": true,
  "capture_commit": "实际采集代码提交哈希",
  "device_serial": "实际设备序列号",
  "tls_bypass": true,
  "processes": [{"pid": 123, "uid": 1012345, "user_id": 10}],
  "steps": ["按真实顺序记录定位种子/权限条件、触发与发送动作及日志位置"]
}
```

tls_bypass必须与verification中的本轮开关一致。processes必须来自本轮实际附加进程，
UID须对应清单用户；目标PRIVACY_READ中的PID/UID须在清单中。不要拿旧进程号补齐。
`capture_commit`与步骤属于声明性来源记录；还需人工核对A的构建指纹、命令和触发日志。
真实第三方不得改返回值、改序列化或用夹具替代，数字坐标/其他格式如实登记不支持。

正例receipts.json至少包含：

```json
{
  "session_id": "本轮session",
  "capture_manifest_sha256": "本轮session-manifest.json完整摘要",
  "request_body_sha256": ["接收端本轮实际收到的完整请求正文SHA256"]
}
```

摘要必须能与候选流的request_payload.raw_sha256对应；回执摘要不能证明唯一来源或因果。
接收端原日志、定位种子、命令及失败材料保留在私有交接目录，不贴入PR。

## 4. 运行与输出

在仓库根使用新目录：

```powershell
.\tools\python313.ps1 -m vehicle.privacy.location_acceptance --handoff <本轮handoff.json> --out output/duo-new-acceptance
.\tools\python313.ps1 tools/real_sample_result.py --verdicts <本轮verdicts.json> --location-acceptance output/duo-new-acceptance/acceptance.json --out output/duo-new-result.md
```

输出固定副本、逐案location-result.json/acceptance.json及总acceptance.json/REPORT.md。
快照复制前后检查摘要，核对归档bundle；输出不可放在源capture中，不覆盖已有目录。
失败副本和诊断保留；修复后另建采集/验收目录，不改失败记录。
顶层结构错误写failure.json，单案错误写blocked并继续其他独立场景。
CLI退出0表示交接条件满足或合成契约通过；后者不能算设备验收。缺类、缺健康、缺回执等返回2。

分层计数为本包/会话读取和流量、可用读取和正文、身份/窗口可比组合、实验候选、歧义流。
候选保持experimental_only，不进规则findings、不加到业务证据、不报告总体P/R。
第三方没有支持输入时只能完成“尝试记录”，不能宣称通用定位外发能力通过。
总报告明确分开设备正负控与第三方；人工检查项保持待复核，不自动签核。

## 5. A侧接口复核发现

既有capture_app记录TLS开关、实际bundle，finally中检查worker停止、代理/reverse恢复、
APK身份与原进程存活；B复用原preflight检查封存身份，不修改A的Hook/驱动。
当前默认通用preflight要求tls/PINNING_ARMED，而capture_app在关闭TLS绕过时发出
TLS_BYPASS_DISABLED。若新输入遇到hook_not_armed，应保留阻塞并由A确认采集契约；
B没有放宽门禁或擅自开启TLS绕过。本项是代码接口风险，尚未用A本轮设备输入复现。
