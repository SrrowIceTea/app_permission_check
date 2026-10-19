# 非 root 授权 APK 重打包

仅用于已获授权的 APK 和测试设备。入口只制备工件，**不操作设备、不替换现有应用**。

```powershell
& $PY -m mobile.repack.prepare --apk <原始.apk> --out <新的输出目录> --abi x86_64 --authorize
& $PY -m unittest mobile.repack.test_repack -v
```

工具：官方 Apktool 3.0.3 固定 release SHA256；官方 Frida Gadget 17.9.11
（与 Python Frida 精确匹配、核验官方 release asset SHA256 和 ELF ABI）；Android
SDK 36.0.0 的 zipalign / apksigner。支持 `x86_64`、`arm64-v8a`，不下载第三方签名绕过器。

## 制备流程

1. 校验原签名和包名/版本，原包复制到独立输出，不覆盖用户文件。
2. 生成独立测试证书，产出**只重签名 baseline**，验证所有非 META-INF ZIP payload 完全一致。
3. Apktool 完整解包，保留原 Manifest 与待改 Application smali 的备份。
4. 无自定义 Application 时新增子类；已有自定义类时**修改原类而非继承它**，兼容 final 类。
   `attachBaseContext` 的 super 调用之后插入独立无参数 loader；保持原寄存器数和业务指令。
5. `System.loadLibrary("gadget")`，库和配置置于指定 ABI；`extractNativeLibs=true`。
   原 APK 没有 INTERNET 时显式增加该权限用于 loopback 控制连接，在转换记录里单列。
6. Gadget 仅监听 `127.0.0.1:27042`、`on_load=wait`，主机经 ADB forward 连接后安装观察脚本再 resume。
7. 重建、16 KiB page alignment、测试证书签名，验证签名、包名和版本保持、证书确实改变。

## 证据

`manifest.json` 包含 original/instrumented/resigned APK 路径和摘要、原/新证书摘要、
工具与 Gadget 来源、加载点/Manifest 转换、payload 差异、baseline payload 一致性。
`original-decoded-files/` 保存改前文本；`logs/` 保存命令输出，失败也保留 manifest 和异常。
`prepared` 只表示制备通过；设备安装、进程存活、Hook 命中与报告由非 root 采集验收单独确认。

## 可诊断边界

- 仅接受完整单 APK。split / shared UID / 已有 Gadget、原生 ABI 不匹配、已知壳 loader、
  native/abstract 或无法识别 super 的 attachBaseContext 会明确拒绝，而非静默改包。
- 添加 loader 不恢复原签名，不绕过本地自检、SDK 证书绑定或服务端完整性。
  应按“原包 → 只重签名 → Gadget”隔离失败原因，再对实证阻断点定向适配。
- 原 Application 的 constructor / static initializer，以及 super 调用之前的代码，可能先于加载点执行。
  多进程、isolated process 和纯 native 流量不能用主进程就绪推定覆盖。
- 原始权限集必须从 **original.apk** 取；不得把新增的控制连接 INTERNET 当成原 App 风险。
- 测试证书仅供实验，密码固定 android，不是产品签名密钥；每次输出独立，便于销毁和审计。

当前真实制备工件：`output/nonroot-repack-20261018-v2/`，设备验收结论不在此文预写。
