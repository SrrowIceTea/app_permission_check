# 通用隐私观察内核

## G001 从移动端抽取纯函数（2026-11-02）

dispatch.js、values.js、semantics.py 的唯一实现在此；移动端旧路径仅兼容导出。
车载使用自己的目标清单、运行时、规则与报告编排，不反向依赖 mobile/rules 或 MOB 规则。
SHA-256 前 16 位继续按 UTF-8 编码，不在事件期创建 Java MessageDigest。
观察失败不得改变原调用返回值或异常；Node 执行测试验证原调用恰好一次、原异常对象原样抛出。
Python 旧路径支持从 mobile/analyze 独立启动；纯 JS 数据 URI 测试直接读取共享实现，另验兼容入口。
