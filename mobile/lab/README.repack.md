# 非 root Gadget：重打包与签名兼容

仅用于授权测试。更新日期：2026-10-18。

## 当前实现（2026-10-18）

新增 `mobile/repack/prepare.py`：对授权完整 APK 实施解包、Application.attachBaseContext
加载、官方 Gadget、重建、zipalign、测试证书签名与签名验证；同时生成只重签名 baseline，
保留原包、原/新证书、原始解包文件与逐项转换记录。入口和边界见
[重打包模块说明](../repack/README.md)。

6 款工件已静态制备：Ghera ECB 与 CBC 各两个变体、LibChecker、自有原始 debug APK。
工件：`output/nonroot-repack-20261018-v2/`。`prepared` 不代表设备功能验收，设备采集结果另记。
不宣称 split、所有加固或任意签名自检无条件兼容。

## 原有源码夹具路径（2026-10-17）

现有 `mobile/fixture-app/gadget_prepare.py` 向自有源码的 gadget variant 放置库与配置，
`AuditApplication` 加载 Gadget；该旧入口本身不负责 APK 解包或重建；新通用入口如上，自校验仍需按实际样本适配。
自有夹具的真机通过不能替代第三方 APK 重打包成功率。

用户提出的 MT 类签名校验兼容应作为重打包流程的一部分，不应省略。
[MT 官方手册](https://mt.cc/guide/reverse/signature.html)明确区分：改包后重新签名、
异签名无法覆盖安装、应用自身的额外校验；其去除签名校验功能针对第三类，不能恢复原签名身份。

## 四种不同问题

| 层次 | 工程处理 | 成功判据 |
| --- | --- | --- |
| Android APK 安装签名 | 使用独立测试证书重新签名并验证；不覆盖或删除用户现有应用 | 新测试包正常安装，证书与变换记录可追溯 |
| 应用 Java/native 本地自检 | 找到实际阻断点与执行顺序，再做逐样本定向适配 | 自检阻断消失且原测试功能仍可执行 |
| 签名权限、shared UID、第三方 SDK 绑定 | 记录签名变化造成的权限/功能差异，不伪装已保持原身份 | 对应功能、ICC 信任关系逐项对照 |
| 服务端完整性/证书绑定 | 单列服务端拒绝结果，不当成本地 Hook 故障 | 需服务端授权测试策略，不能由本地自检兼容推定成功 |

依据：[Android App Signing](https://developer.android.com/studio/publish/app-signing)、
[Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts)。
后者可检查包名、版本和签名证书，无法用“本地启动成功”替代服务端验证。

## 每个样本按四阶段对照

1. **原始 APK**：安装、启动、触发目标功能，建立原始行为与独立 oracle。
2. **只重签名**：DEX/资源/Manifest 不变，隔离证书改变本身的影响。
3. **Gadget 重打包**：固定 ABI/库版本/加载点，对照行为、崩溃与真实 Hook 事件。
4. **本地自检适配**：仅当第 3 步实际被自检阻断时进行，记录检查位置、修改与行为差异。

每步保留输入/输出 APK 摘要、证书摘要、安装/启动/触发结果、异常、变换记录与清理结果。
未发现自检的样本记“不需要适配”，不能用它来计算“签名绕过成功”。
本阶段不涉及付费、许可证、账户或服务端风控的绕过。

Gadget 的加载时序也要测试：当前 `on_load=resume` 允许宿主连接前继续运行，
因此连接前的自检或隐私操作可能丢失。需比较早期加载并等待脚本就绪的方式，
不能把后接入 Hook 当成启动全过程覆盖。参考 [Frida Gadget](https://frida.re/docs/gadget/)。

## 2026-10-17 已完成的论文 APK 签名对照（历史记录）

Ghera 固定提交 `ea1dbe234e4d3433161a3b85e96648913a36e83c`，
案例 `BlockCipher-ECB-InformationExposure-Lean` 的两个目标变体：

| 变体 | 原包 | 只重签名 | Gadget 重打包 | 本地自检适配 |
| --- | --- | --- | --- | --- |
| Benign（作者含漏洞版） | 通过 | 通过 | 未实施 | 未实施，尚无阻断证据 |
| Secure（作者修复版） | 通过 | 通过 | 未实施 | 未实施，尚无阻断证据 |

“通过”仅指本机 Android 14 非 root 安装、启动、合成输入触发 Get Token、
非空 token 日志、触发后进程存活以及测试包卸载均通过。
未修改密码、不发送邮件；只替换签名时非 META-INF 的 ZIP 内容一致，证书摘要确已改变。
两样本复用包名，逐个测试，不并列安装，不替换用户原应用。

结果：`output/benchmark-corpus-20261017/signing-baseline/verification.json`（4/4 次）。
这不是本项目弱加密检测结果，也不是通用自检兼容的验收。

## 设备运行验收范围

先将此配对接到“APK 重打包 → Gadget 早期就绪 → 合成路径触发 → 加密事件核对”，
再扩到 Ghera 固定 IV/随机 IV 的存储配对及网络配对。
固定 IV 用例的密文经 Base64 再落盘，应显式识别该变换，不能用原始密文与文件字节不等来判安全。
样本未触发、平台不支持、插桩失败与检测阴性分开统计。
