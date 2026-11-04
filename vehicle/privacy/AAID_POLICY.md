# Google 广告标识读取

仅用于授权测试。VSC-GR-advertising_id 依据 `AdvertisingIdClient.Info.getId()` 实际返回的非零标识记录读取事实。事件只保留非空状态和长度。获取 Info 本身只记调用。

目标 SDK 至少为 33 的应用缺少 `AD_ID` 且返回全零时，记录权限门槛拒绝。权限已授予时，全零或空值记录为 empty。Google SDK 报告服务缺失或需要恢复时记录 unavailable。其他连接和调用异常按 error 记录。各状态均保留独立证据。
