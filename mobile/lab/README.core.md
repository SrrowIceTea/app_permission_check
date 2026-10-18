# 完整移动审计核心入口

仅用于授权测试。这是原始业务主链，不是 `benchmark_review` 的批次摘要或前端演示。
前端无需修改；上传、政策、采集、AI 和报告最终归入同一个已上传 APK 任务。

## 先准备本地资料

应用政策库使用 `mobile/policy/policy_library.py`，具体准备方式见
`mobile/policy/README.local.md`。保存原文、正文、来源、时间、包名、版本和被测原包摘要。
检测只读本地资料，不临时抓政策；错包或提取失败不能替代为其他 App 的政策。
`mobile/rules/regulations/` 是独立的法规/规范摘录，不能替代应用政策，也不声称全法规覆盖。

首次安装设备采集前，应运行自有夹具的真实阳性自检，确认有成功读取和可归因网络流。
只出现 ARMED 不算通过。入口见 [README.core-capture.md](README.core-capture.md)。

## 一个入口跑主链

启动既有移动后端，配置本机 SDK、JDK、JADX，并准备专用 root 模拟器、匹配版本 Frida Server。
在仓库根目录执行，`--out` 必须是全新目录，`--selftest` 是同设备真实夹具自检结果：

```powershell
python -m mobile.lab.core_pipeline `
  --apk output/domestic-apk-corpus-20261018/cn-libchecker/original.apk `
  --out output/mobile-core-libchecker-new `
  --selftest output/core-e2e-fixture-20261018-run3/verification.json `
  --config C:\path\to\provider.local.json `
  --scenario libchecker --serial emulator-5562 --authorize
```

`--policy-store` 可选择另一份本地政策库，默认使用当前已准备的库。
`--storage` 必须与本地工作台的存储配置一致。示例自检路径来自本机实测，换机必须先重新自检。
密钥只从配置文件读取，不进入前端或 Git。

顺序：

1. 原工作台 `/api/apk` 实际上传，完成原全 DEX 扫描、移动补充规则和 JADX。
2. 按相同 APK 身份选择预先保存的政策；静态上传任务也会自动绑定本地政策。
3. 在专用 root 模拟器安装未修改原包，采集真实原 hooks 与 UI 场景，保留原始会话和 PCAP。
4. 原 `correlate_mobile.py` 关联读取、授权代理信号、流与政策；再由原 `evidence_bundle.py` 打包。
5. 原 `ai_review.py` 真正执行政策抽取、行为一致性、综合研判三个阶段，每阶段通过才继续。
6. 原报告生成器输出 PDF；重新验证任务与 APK 身份后发布到原上传任务。

静态事实未完成、采集失败、AI JSON/引用失败或报告失败会使本轮失败，不发布成功报告。
无可用主政策会保留 `available=false` 和缺口，但不阻止技术证据分析；政策一致性和整体政策条款
不得在缺证据时作肯定判断。有限场景没有敏感读取也可出证据不足的报告，不等于判定应用安全。
JADX 已产生可用源码但部分类失败时允许继续行为审计，**保留 partial、错误数量与报告缺口**，
不能把它说成全量源码成功。历史失败目录不覆写。

## 本机真实验收，2026-10-18

- 夹具：`output/core-e2e-fixture-20261018-run3/`，12 条真实读取、4 条权限事件、1 条已归因 HTTP 200。
- 用该原始会话运行原关联引擎：`output/core-e2e-fixture-correlation-20261018/`，8 类规则均有命中，
  包含 1 条值级 `data_egress` 和 1 条明文传输；没有合成或补造读/流事件。
- 真实 LibChecker：`output/mobile-core-libchecker-20261018-run3/verification.json`，任务 `55c3f558cf19`。
  政策来自对应官方 `2.5.4` 标签，共 4985 字符；原包摘要与安装包一致；2 条安装列表读取、6 条工具结论；
  三阶段共 3 次真实 DeepSeek 请求与门控通过；最终报告 9 页。
- 同一 APK 的 JADX 有 83 个类错误、4053 个输出源码文件，任务保持 `partial`；没有隐藏错误。
- run1 静态 gate 与 run2 非法模型 JSON 的失败现场保留；JSON 输出模式修复后的 run3 新跑完整采集和 AI。
- 移动分支一键离线检查 `python tools/check_mobile_branch.py` 已纳入新增核心模块，19 组通过，
  记录 `output/mobile-branch-20261018-014900/verification.json`。它不替代上述真实设备与模型验收。

## 批次复用与交付索引

已有完整全 DEX 结果时，可传 `--static-source <该样本结果目录>` 绑定原始事实及当前移动补充规则，
而不是重新反编译所有源码；任务明确保留 `decompile=not_requested`。已有同一原包、同一设备、
所有检查通过的实际会话时，可用 `--capture-source <采集目录>`，不重新安装或重造行为。
动态与正式批次分别由 `domestic_dynamic`、`domestic_formal` 运行；失败现场保留，不覆盖历史目录。

`domestic_summary` 只读取既有结果，输出单一 `verification.json` 和逐应用 `README.md`。
可重复提供 `--capture-root`、`--formal-root` 和 `--static-root`；各阶段优先同一 APK 的完整成功，
没有成功才选最近失败。不同来源的阶段、读取数、AI 风险和报告不会拼接成一次“成功”。

```powershell
python -m mobile.lab.domestic_summary `
  --capture-root output/domestic-dynamic-20261018-all `
  --capture-root output/domestic-dynamic-20261018-completion `
  --formal-root output/domestic-formal-20261018-current `
  --out output/domestic-delivery-new
```

默认静态源为原静态批次和大包重跑批次。只生成索引不代表所有 APK 检测成功；
实际完成数量、失败阶段和风险未知情况以本次生成结果为准，不在本说明中写死动态完成数。

## 资料、扩展证据与边界

- 国内 20 款的本地应用政策为 15 份可用、1 份头条正文尚未生效、4 个未找到。
  27 份已归档补充正文中，25 份当前可由严格 APK 绑定解析器进入正式 AI，2 份关联头条未来主政策暂排除。
  主政策与附录各自保留来源、摘要和范围；不是全部功能、全部历史版本政策的完整集合。
- 6 个大包原 120 秒扫描超时现场仍保留；`output/root-benchmark-domestic-retry-20261018/`
  已完成这 6 个同一原包的全 DEX 重跑。交付索引逐包选择完整源，不把旧超时解释为无风险。
- `audit.jsonl` 的存储/加密事实已由正式适配器接入 `dynamic.storage_crypto`，进入阶段二/三及 PDF。
  成功写调用、偏好编辑暂存、算法配置及密文写入关系分别处理；不把 SQLite 资源、普通字符串
  或 API 调用直接定性为磁盘个人信息泄露。未覆盖的磁盘读回、native IO 等保留缺口。
- 无测试 CA 的 HTTPS 只保留不透明连接/包级证据；整机 PCAP 不冒充全部属于目标 App，有限 UI 不等于全功能覆盖。
- 风险分来自绑定证据的版本化指标；静态候选数、存储技术观察和 AI 综合研判不得混成一个无来源分数。
  没有正式成功者综合风险保持 unknown，未知不能当作零分；模型结构/引用通过也不等于判断准确。
