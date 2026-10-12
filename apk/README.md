# apk/ — 第三方样本存放区（按平台分）

仅用于授权测试（自有设备 / 已获授权的公开第三方样本）。
样本是**输入**，不进版本库（体积大、且来源随时可重取）——
`.gitignore` 排除 `apk/*`，只放行本说明文档。

```
apk/
├── mobile/     移动端样本（手机 AVD 上跑）
└── vehicle/    车载样本（车机 AVD 上跑）
```

## 为什么要分

实测教训：`com.ximalaya.ting.android.car`（喜马拉雅**车机版**）被放在同一层、
被移动端批处理当成手机 App 跑了整轮——症状是设备检测卡在 `app_started`
（车机 App 在手机 AVD 上起不来），而当时的排查方向是"冷启动竞争或启动崩溃"，
**没意识到是平台归属问题**。

平台搞错时不会报"这是车机包"，只会表现为一个看起来像时序问题的失败。

## 每个样本的文件约定

| 文件 | 说明 |
| --- | --- |
| `<包名>.apk` | 样本本体。文件名**必须**是包名——批处理按文件名建目录并核对 |
| `<包名>.provenance.json` | 溯源记录（来源 URL、sha256/md5、aapt2 解出的真实包名、抓取时间） |
| `<包名>.download.log` | 下载日志（走 urllib 还是 curl 兜底） |

溯源记录由 `mobile/tools/fetch_apk.py` 生成；**下错应用会被拦下**——
实测拦过两次：官网给的"喜马拉雅"其实是车机版、OpenTracks 的真实包名带 `.playstore` 后缀。

## 怎么用

```bash
PY="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"

# 移动端批处理（默认读 apk/mobile/）
"$PY" mobile/tools/batch_thirdparty.py

# 下载新样本（默认落在 apk/mobile/）
"$PY" mobile/tools/fetch_apk.py --probe com.moji.mjweather      # 只看元数据
"$PY" mobile/tools/fetch_apk.py --direct "包名=直链"             # 从直链下

# 车载样本目前没有批处理入口，按 vehicle 侧的单样本流程跑
```

**注意**：应用宝的 CDN 有 JS 机器人挑战页，脚本下不下来（返回的是需要浏览器执行的
混淆 JS）。实测可行的是**官网直链**与 **GitHub Release**；
应用宝详情页只用来探测元数据（`--probe`）。
