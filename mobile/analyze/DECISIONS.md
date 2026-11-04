# 移动分析局部决策

## M061 返回值语义共享（2026-11-02）

read_semantics.py 兼容导出 core/privacy/semantics.py，维持 obtained/empty/call_only/unknown/denied/error。
从本目录单独运行测试时，兼容层先加入仓库根，避免顶层 core 导入失败。
test_values.mjs 的数据 URI 诊断构造读取共享源码，另通过旧入口验证返回值一致。
