# 中国国内 APP 观察性样本集

此集与论文基准分开：论文基准用于有答案的对照，国内 APP 用于真实分发版本的观察性评估。
**国内 APP 没有预设风险真值，下载、安装或启动成功不表示没有风险。**

## 来源与获取

`catalog.json` 为 22 款不同应用的官方来源目录。
2026-10-18 已取得 20 款可用原包：14 款厂商正式分发、6 款国产开源；
夸克、UC 官方 CDN 下载超过五分钟预算，不计入成功数。
厂商原包取自官网或官网 JavaScript 直接提供的分发地址；不使用破解版或随机 APK 镜像。
国产开源项目的归属依据为作者/发布组织公开的中国位置资料，不按中文界面推断国籍。

示例官方入口：
- [微信](https://weixin.qq.com/)、[哔哩哔哩](https://app.bilibili.com/)、[高德地图](https://mobile.amap.com/cn/)
- [铁路12306](https://kyfw.12306.cn/otn/appDownload/init)、[人民网+](https://www.people.cn/app/download.html)
- [软媒官方软件页](https://m.ruanmei.com/)、[QQ音乐](https://y.qq.com/download/)、[UC](https://www.uc.cn/)
- [LibChecker](https://github.com/LibChecker/LibChecker)、[Read You](https://github.com/ReadYouApp/ReadYou)
- [GKD](https://github.com/gkd-kit/gkd)、[TTS Server](https://github.com/jing332/tts-server-android)
- [TextSearcher](https://github.com/jing332/TextSearcher)、[TTS 词典编辑器](https://github.com/jing332/TtsDictEditor)

公开提供下载不等于开源或允许再分发。商业安装包只保留在本地忽略目录，
用于本机测试与分析，不上传仓库、不提供镜像、不使用真实账号或个人数据。
开源项目也应按各自许可证使用；本目录不重新授予 APK 权利。

## 复现

在项目根目录，使用已配置的 Python 3.11 和 Android SDK 36/JDK 17：

```text
python mobile/lab/domestic/fetch.py --out output/domestic-apk-corpus-20261018
```

可用 `--ids cn-libchecker cn-readyou` 只取指定样本；`--aapt2`、`--java`、`--apksigner`
可覆盖工具路径。两路并发，每包上限 350 MiB、样本目录上限 3 GiB。
原包不改名内部文件、不重签名、不安装到设备；`original.apk` 只是本地保存文件名。

输出逐款增量写入：
- `manifest.json`：名称、实际包名/版本/ABI/min/target SDK、SHA-256、来源与下载状态。
- `<sample_id>/original.apk`：原始安装包，仅成功完整下载后命名。
- `<sample_id>/metadata.json`、`badging.txt`、`signature.txt`：身份与签名核验结果。
- 输出目录中的网页/发布 API 快照：下载地址与归属依据的可追溯资料。

只有 `download_status=downloaded` 且 `artifact_checks` 全部通过才计入可用原包。
HTML/LFS 指针不算 APK；官网重定向到应用商店安装器时，已知包名不匹配会拒绝计入。
GitHub 提供 SHA-256 digest 时核对；否则不虚构发布者哈希。

## 版本与结论口径

- `retrieved_at` 是获取时间，不是 APP 发布时间；实际版本取自二进制 Manifest。
- 部分作者长期未更新，魔珠和部分语音工具为历史官方样本；不得称 20 款都是最新流行 APP。
- 签名有效只说明该 APK 的内部签名完整性；不能单凭它宣称厂商授权或隐私合规。
- 非随机抽样、应用类别不均衡，不以该小样本推算国内 APP 总体风险比例。
- 静态候选、动态已观察风险、证据不足、执行失败分别记录，不能把未触发当作阴性。

## 本次实际可用原包（2026-10-18）

| APP | 实际版本 | min/target SDK | 类型 |
|---|---|---|---|
| 高德地图 | 17.01.0.2012 | 21/35 | 厂商正式分发 |
| 百度地图 | 22.0.40 | 24/33 | 厂商正式分发 |
| 哔哩哔哩 | 9.15.0 | 24/35 | 厂商正式分发 |
| GKD | 1.12.1 | 26/37 | 国产开源 |
| IT之家 | 9.38 | 21/35 | 厂商正式分发 |
| LibChecker | 2.5.4.5696014 | 24/37 | 国产开源 |
| 人民网+ | 5.1.1 | 21/30 | 厂商正式分发 |
| 魔珠 | 1.0.8.1 | 14/未声明（未知） | 厂商正式分发（历史发行） |
| QQ音乐 | 20.9.0.8 | 23/30 | 厂商正式分发 |
| 铁路12306 | 5.9.4.5 | 23/34 | 厂商正式分发 |
| Read You | 0.16.2 | 26/34 | 国产开源 |
| 搜狗输入法 | 20.17.0 | 21/30 | 厂商正式分发 |
| TextSearcher | 1.23.072210 | 23/33 | 国产开源（历史发行） |
| 天猫 | 15.71.0 | 23/33 | 厂商正式分发 |
| 今日头条 | 18.7.0 | 21/33 | 厂商正式分发 |
| TTS词典编辑器 | 1.23.112611 | 21/33 | 国产开源（历史发行） |
| TTS Server | 0.9_202307261647 | 21/33 | 国产开源（历史发行） |
| 微信 | 8.0.79 | 24/34 | 厂商正式分发 |
| 迅雷 | 25.2.60.245 | 24/30 | 厂商正式分发 |
| 要知 | 1.02 | 21/33 | 厂商正式分发 |

合计 20 个不同包名、原包约 2.00 GiB，20/20 签名验证通过；完整哈希与来源见本地 `manifest.json`。
夸克与 UC 两个失败条目保留在清单，不将部分下载计为成功，也不以失败判断应用风险。

min SDK 兼容 aapt2 的 `sdkVersion` / `minSdkVersion` 两种字段；上述值取自已保存的原包 badging。
魔珠未显式声明 target SDK，保留未知，不用 min SDK 或系统默认值补造。
