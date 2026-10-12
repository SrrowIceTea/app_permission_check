"""静态分析内核：APK 反编译、dex 事实抽取、清单解析、规则评估与任务调度。

平台无关——这套能力面向"任意 APK 的静态分析"，不包含 android.car / VHAL / 车载专有概念：

- ``analysis.py``    —— 门面：清单 → dex 事实 → 规则评估，一次调用完成静态扫描
- ``static_rules.py`` —— 规则加载与评估（委托 ``core.rules_contract`` 按平台分派）
- ``apkmeta.py``     —— aapt2 解析 APK 清单（权限/组件）
- ``dexfacts.py``    —— dexdump 抽取 dex 方法引用
- ``jadx.py``        —— jadx 反编译
- ``toolchain.py``   —— Android 构建工具链（aapt2/dexdump/jadx/java）定位
- ``crosscheck.py``  —— 交叉校验
- ``jobs.py``        —— 反编译任务调度
- ``winpath.py``     —— Windows 长路径（MAX_PATH 260）兼容层

车载 workbench 的交互式 HTTP 服务（``vehicle/workbench/server.py`` → ``vehicle/workbench/server.py``）
仍在车载侧，它 import 这里的内核。
"""
