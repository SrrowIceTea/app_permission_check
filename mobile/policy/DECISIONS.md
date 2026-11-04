# 移动政策模块决策

## M059 政策正文解码提升为共享内核（2026-11-02）

policy_extract/policy_formats 的唯一实现迁入 core/policy，移动旧模块保留兼容导出，车载不反向依赖 mobile。
政策库、补充文档、应用协议分离和移动规则不改语义；全量移动检查与分支回归验证兼容。
本记录单独存放，避免继续扩充已超长的历史 mobile/DECISIONS.md。
