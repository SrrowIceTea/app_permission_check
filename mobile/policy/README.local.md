# 离线应用政策库

应用隐私政策和法规是两类材料，不能互相替代。

- `mobile/rules/regulations/` 原有 4 份法规/规范**摘录**，有来源和条款号，但不是完整法规全文。
- 原有 `fixtures/demo-policy.html` 是自有演示应用政策，不适用于第三方应用。
- 本轮实际政策正文在 `output/local-policy-library-20261018/`，不修改/复用其他应用的政策。

## 先准备资料，再离线检测

`official_policy_sources.json` 是已核对的官方来源清单，不是按名称猜测的链接。
在资料准备阶段运行 `prepare_local_policies.py --manifest <APK清单> --store <本地政策库>`。
首次准备可联网；已匹配的缓存直接复用。检测阶段 `load_policy` **不联网**。

库保存每个文档的原始字节、抽取正文、原文与正文摘要、来源、取得日期、
包名、versionCode、被测原包 SHA-256 和版本适用范围。

解析接口：

```python
from mobile.policy.policy_library import load_policy
policy = load_policy(package=package, version_code=version_code, apk_sha256=apk_sha256)
```

未配置路径时只读 `policy_library.DEFAULT_STORE`。可显式传入另一本地政策库目录。
结果 `available/status/text/gaps` 区分可用、未取得、损坏、歧义；不再按文件名字母序取最后一份。
错包、错版本、原包摘要不符、提取失败、正文缺失/摘要校验失败均不能冒充可用政策。

## 已准备与未准备

截至 2026-10-18，本地 `coverage.json` 对 20 个国内样本记录：**15 份可用，
1 份已归档但尚未生效，4 个未找到可用正文**。

| 状态 | 应用 |
| --- | --- |
| 可用（15） | 高德地图、百度地图、哔哩哔哩、GKD、IT之家、LibChecker、人民网+、QQ音乐、铁路12306、Read You、搜狗输入法、天猫、微信、迅雷、要知 |
| 尚未生效（1） | 今日头条：归档正文生效日为 `2026-10-21`，当前返回 `not_effective`，不参与现行政策判断 |
| 未找到（4） | 魔珠 Poplines、TextSearcher、TtsDictEditor、TTSServer；返回 `not_found`，不把未找到等同于从未发布 |

- LibChecker 来自与 APK 对应的官方 `2.5.4` 发布标签；迅雷来自该原包内 `privacy.txt`。
- 其余 13 份可用正文是官方现行页面快照，**尚未证明与该 APK 发布时的政策版本严格对应**，解析结果保留此缺口。
- 哔哩哔哩已从官方动态文档载荷抽取产品政策；QQ音乐已取得产品隐私保护指引，不再以集团通用政策替代。
- 铁路12306 已取得官方完整政策，不以包内弹窗摘要替代；要知和天猫也已取得官方产品政策。
- 高德和天猫主文档有基本功能范围限定；其他高级功能及第三方服务不能自动视为已覆盖。
- Read You 和 GKD 使用官方 wiki/官网原文，不把英文政策自动判为不存在。

## 补充告知材料的实际接入状态

`official_policy_supplements.json` 列出 10 个应用主政策的一层官方链接；本地
`supplements.json` 记录 37 份补充材料，**27 份正文抽取成功，10 份因正文过短未通过**。
27 份成功材料的 `document.raw`、`document.txt` 和 `document.meta.json` 均已保存，
本地复核原文/正文摘要及字符数一致。内容包括权限说明、SDK/共享清单和功能专项告知。

`load_policy()` 将补充告知以独立 `policy.supporting_documents` 返回：逐份严格匹配
包名、versionCode、原 APK SHA-256，并复核原始字节、正文摘要、字符数、关联主政策修订。
每份保留 `SUP-…` 来源 ID、官方来源和功能/平台范围；主政策 `text`、`text_sha256`
以及 `available` 的含义不变，不会拼成一份通用政策。

截至 2026-10-18，27 份归档正文中 **25 份通过匹配并可供正式 AI 阶段一读取**；
另外 2 份关联尚未生效的今日头条主政策，暂不作为现行证据输入。10 份抽取未通过的材料
保留缺口，不给空正文冒充可用材料。仅有附录时主政策仍 `available=false`，不得仅凭
附录把整体政策条款判为 `met`。

阶段一引用补充正文须带 `policy_document_ref: "SUP-…"` 以及
`supplementary_scope: "document_scope_only"`，正式门控逐份核对原文，阶段二沿用来源 ID。
这些资料只证明文档中的声明，**不证明 SDK 已实际使用、实际收集、权限已授予或用户同意**。
范围和历史版本对应关系仍需复核，不能声称资料全面，不能仅凭主文档未命中就断言
补充清单也未声明。既有 AI 产物不自动更新，新建证据包和重新分析才使用该接入。

具体映射与缺口见本地库 `catalog.json`、`coverage.json` 及每份 `policy-local.meta.json`。
不存在本地完整政策时，关联和 AI 必须标记缺证据，不能将空文本解释成“政策未声明”。

## 应用协议（用户协议/服务协议）的接入状态

2026-10-19 起《用户协议》《服务协议》不再被丢弃——很多 App 把数据条款写在协议里，
审计需要它；但它**不替代隐私政策**（见 `DECISIONS.md` M040）。

- **发现**：`policy_discover.classify()` 按正文归类，隐私词优先，其次协议词。
  `find_in_apk()` 返回的每条都带 `doc_kind`（`privacy` / `agreement`），主政策固定排前。
- **落盘**：`policy_fetch --from-apk` 的 meta 带 `document_kind`；
  APK 里只有协议时状态是 `agreement_only`，**不许写成 `ok`**。
- **库**：`load_policy()` 把协议挂在 `policy.app_agreements`，每份带
  `document_id: "AGR-…"`、`supplementary_scope: "independent_agreement"`，
  并在 `gaps` 里注明"不参与披露比对与过度收集判定"。主政策 `text`/`available` 不受影响；
  只有协议时主政策仍是 `not_found`，不是 `invalid`。
- **AI**：阶段一可引用协议正文，`policy_document_ref` 写 `AGR-…`、
  `supplementary_scope` 写 `independent_agreement`；主政策不可用时**不得**仅凭协议判 `met`。
- **限制**：`policy_fetch` 的 store 没有包名/版本绑定，入库后 `association_verified=false`；
  需要严格绑定时走 `prepare_local_policies.py`，sources 配置里的 `document_kind`
  可选 `app_agreement`。

## 正式关联入口

`correlate_mobile.py` 支持 `--version-code`、`--apk-sha256` 和可选 `--policy-store`，
与证据打包统一调用同一个解析器。
仅旧版自有夹具 + 显式 policy-store 保留无包名元数据兼容，且会写明关联未经校验。

离线回归：`python -m unittest discover -s mobile/policy -p 'test_policy*.py'`。
测试包含断网解析、错包错版本、损坏摘要、目录逃逸、歧义版本以及排除设置/词库 JSON。
