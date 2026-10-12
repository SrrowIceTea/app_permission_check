"""证据层：从运行时栈提取违规代码行号，并用 APK 的 dex 核对。

平台无关——Java/Kotlin 栈帧解析与 dex LineNumberTable 核对不涉及 android.car / VHAL。
"""
