# 本地字体

三个 WOFF2 字体共 124,652 字节，运行时只从本机服务加载。

| 字体 | 用途 | 官方来源与许可证 |
| --- | --- | --- |
| Noto Serif SC | 中文艺术标题、结果标题 | [Google Fonts 源码](https://github.com/google/fonts/tree/main/ofl/notoserifsc)，`noto-serif-sc-OFL.txt` |
| Noto Sans SC | 中文导航、按钮与常用界面文字 | [Google Fonts 源码](https://github.com/google/fonts/tree/main/ofl/notosanssc)，`noto-sans-sc-OFL.txt` |
| Manrope | 英文品牌、APK 文件名、数字与拉丁字符 | [Google Fonts 源码](https://github.com/google/fonts/tree/main/ofl/manrope)，`manrope-OFL.txt` |

这些字体以 SIL Open Font License 1.1 分发，对应完整许可证随字体保存。
字体文件由 Google Fonts 官方 CSS API 按公共界面词汇提供子集，未安装到系统，也未发送 APK、日志、包名或业务证据。
下载地址、字集、长度及 SHA-256 记录在 `manifest.json`；`fonts.css` 只引用本地固定路径。

中文子集覆盖静态界面常用词汇；动态证据中的其他汉字按系统中文无衬线字体回退，不删改任何业务文字。
源码和原始 JSON 使用单独的等宽字体栈，普通界面不再套用等宽字体。
