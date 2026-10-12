"""平台无关的 Frida 宿主运行时：驱动 hook bundle 并从设备/模拟器采集 JSONL。

这里只放车载与移动端共用的东西，判据同 core/__init__.py：

- ``run.py``           —— Frida attach 驱动（pidof 找进程、转发、EventStore 落盘）
- ``bundle_config.py`` —— 替换 bundle 内 ``__VSCAN_SESSION_PACKAGES__`` 白名单占位符
- ``dist/``           —— 自包含成品 bundle（Socket.connect 出站 + 证书固定绕过），
                        与车载概念无关，移动端设备脚本直接复用

hook **源码**（hook_egress.js / ssl_pinning_bypass.js / scope.js / vscan_runtime.js 等）
以及 frida-compile 构建链仍留在车载侧（vehicle/hooks/ → vehicle/hooks/），因为：
frida-compile 按入口所在目录解析相对 import，把 scope.js / vscan_runtime.js 抽到 core
会让车载 hook 的 import 断裂；而成品 bundle 是自包含的，运行时不需要源码。
重建共享 bundle 时，在 vehicle/hooks 下跑 ``python build.py``，并把 dist/<name>.bundle.js
拷回这里（见 vehicle/hooks/build.py 顶部注释）。
"""
