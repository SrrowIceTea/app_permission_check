# 自有移动隐私夹具：普通 Debug 与非 root Gadget

仅用于授权测试的自有源码夹具 `com.vscanner.privacydemo`。本工程不重打包第三方 APK。

## 两种构建

- `:app:assembleDebug` → `app/build/outputs/apk/debug/app-debug.apk`。
  不含 Gadget Application、动态库或配置，沿用普通夹具。
- `:app:assembleGadget` → `app/build/outputs/apk/gadget/app-gadget.apk`。
  仅 `src/gadget` 注册早期 Application 并 `System.loadLibrary("gadget")`。
  不启动 frida-server，不需要 root，不安装系统 CA。

在仓库根目录、已安装与宿主一致版本 Frida 的 Python 下准备，例如：

```powershell
python mobile/fixture-app/gadget_prepare.py --version (python -c "import frida; print(frida.__version__)") --abi x86_64
# 真机 arm64 或双 ABI：附加 --abi arm64-v8a
cd mobile/fixture-app
.\gradlew.bat :app:assembleDebug :app:assembleGadget --console=plain
```

准备脚本从官方 `frida/frida` 指定版本获取 release 资产，先核对 GitHub release-asset
提供的 SHA256，再解压检查 ELF 架构。没有官方摘要时明确失败，不把自己算出的摘要当来源认证。
`--version` 必须与执行脚本的 Python 中 `frida.__version__` 一致。
离线可信本地动态库需同时给出 `--library PATH --expected-sha256 SHA256`，只支持一个 ABI。

下载缓存 `gadget-cache/` 与 `libgadget.so` 不入库。两处生成的 provenance（源码根和 APK
`assets/gadget-provenance.json`）绑定版本、包名、每 ABI 库/配置摘要与官方下载出处。
Gadget 构建检查 provenance 与实际文件摘要；普通 Debug 不依赖准备脚本。
替换生成文件时原件保存在本工程 `.cache/gadget-backups/`，目的文件使用原子替换。

## 采集约束

配置固定监听设备 `127.0.0.1:27044`（可由准备脚本 `--port` 明确指定），端口冲突即失败。
`on_load=resume` 允许夹具启动后由**一个 Gadget 会话** attach 一次、挂多个独立脚本，
不对每个脚本重复 spawn/resume；必须等四路非零 `ARMED` 与白名单 App 的非 root UID 后才按按钮。
启动到挂钩完成之间的行为**不在观测窗口**，不能据此声称覆盖任意 App 的冷启动行为。
普通 Debug 与 Gadget 使用同一包名及签名，不应并行安装或并行运行。

夹具的 HTTPS 流量验收需要显式设置 `VSCAN_TLS_BYPASS=1`，只对自有白名单进程生效；
不开启时脚本在就绪检查中说明原因。采集入口为仓库中的
`mobile/tools/device_fixture_run.py --mode gadget --serial SERIAL --skip-ai`，
也可先执行 `--preflight-only`。它记录 `shell id`、`ro.debuggable`、`ro.build.type`、
固件指纹与初始权限，不执行 `adb root`、`su`、frida-server 或系统 CA 安装。
若镜像仍是 `userdebug` / `ro.debuggable=1`，仅可称**受限非 root 路径模拟**，
不能称锁定量产 `user` 设备实测；shell/app UID 非 0 也不证明设备绝无提权工具。
安装不使用 `-g` 预授予权限；重复运行不会清除已有权限/用户数据，须依据快照解释初始状态。
这是自有源码夹具运行能力，**不是**普通非 root 设备任意第三方 APK 的无条件注入能力。

外发按钮必须获得明确成功响应，采集还需同一 session、白名单归因的 HTTP 与 HTTPS 流；
只出现按钮标记、连接尝试或空 JSONL 不算完整验收。IMEI 权限拒绝、空通讯录、
位置 null 则是合法观测，不要求虚构非空个人数据。

流量不经系统 CA 扩权。现有 HTTPS 捕获只使用**白名单进程内**的审计 TLS 校验绕过，
不修改系统信任库或全局代理；这不代表 App 在未插桩生产环境中的 TLS 安全性。
HTTP 外发可在本地接收端观测；HTTPS 信任错误必须保留为失败，
不能把它解释为“没有外发”。Gadget 能力仅在本进程，不提供跨 UID 或系统进程注入。

`on_load=resume` 与 Android `libgadget.config.so` 命名遵循
[Frida Gadget 官方文档](https://frida.re/docs/gadget/)。官方下载摘要字段依据
[GitHub release assets API](https://docs.github.com/en/rest/releases/assets)。

## 回滚与离线自检

停止采集后移除对应 `adb forward`，卸载 Gadget 变体或重新安装普通 Debug 即移除 Gadget。
安装授权与设备选择由采集入口显式给出，不在准备脚本内操作设备。

```powershell
.venv\Scripts\python.exe -m unittest discover -s mobile/fixture-app -p test_gadget_prepare.py -v
```

这些测试使用明确的 synthetic ELF header 和下载替身，只验证配置/摘要/隔离契约；
不等于 APK 构建通过，更不等于非 root 设备实测通过。设备结果由独立 verification 记录。
