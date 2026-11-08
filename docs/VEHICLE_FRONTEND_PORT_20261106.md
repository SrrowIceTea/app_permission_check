# 车载前端移植

仅用于授权测试（自有设备与自有 APK）。

## 计划与实现

1. 复用移动端现有暗色界面、侧栏、上传舞台与六个页面；车载 HTML/JS 单独存放。
2. 新增 `vehicle.ps1 web`，回环端口 8773，复用车载静态、采集、审计、看板与 PDF 实现。
3. 支持静态、新采集及历史重放；保持 APK、会话、规则、Hook 与隐私目录的原有严格校验。
4. 添加上传/路径/互斥/重启恢复/失败门控回归，实际浏览器上传授权 APK、验证源码、动态证据与报告。
5. 独立 subagent 工程复核，修复后再检查；所有失败与测试脚本自身失败均保留。

视觉延续原移动端的近黑底、冷白字和淡青运行色；侧栏左对齐，上传舞台居中，证据页保留表格和展开原文。
没有另造主题，没有引入前端框架、构建工具或外部图像/字体请求。

运行与边界见 [车载工作台说明](../vehicle/frontend/README.md)。
本轮证据目录：`output/vehicle-frontend-acceptance/`，独立复核：`output/vehicle-frontend-review/`。

## 验收记录

| 检查 | 实际结果 | 证据 |
| --- | --- | --- |
| 全量回归 | 18/18 组，含新增工作台 16 项与移动侧 29 项 | `output/vehicle-frontend-regressions-002/verification.json` |
| 移动分支及前端契约 | 24/24 组 | `output/vehicle-frontend-mobile-checks-001/verification.json` |
| 真实 Chrome 上传与历史重放 | 15/15 项；源码、动态证据、PDF、刷新恢复、新建清空、390px 无横向溢出、无 JS 异常 | `output/vehicle-frontend-acceptance/browser-1793946710703/verification.json` |
| 新 AAOS 35 采集 | 6/6 项；自有夹具、实际 VHAL 事件、完整审计和 PDF | `output/vehicle-frontend-acceptance/live-verification.json` |
| 新采集内部健康/收尾 | 10/10 项，原进程存活、APK 不变、代理和 reverse 恢复、无 Hook 错误 | `output/vehicle-web/v-4505db85ec814a4ebb1263d0c2fa1167/capture/verification.json` |
| 独立 subagent 工程复核 | revision 2 approved，无未解决发现；当前 16 项及 6 条诊断注入检查通过 | `output/vehicle-frontend-review/review.json` |

新采集为 AAOS 35、user 10，指纹 `google/sdk_gcar_x86_64/emulator_car64_x86_64:15/AAI5.260516.001.A6/16618942:userdebug/test-keys`。
任务 `v-4505db85ec814a4ebb1263d0c2fa1167`，会话 `capture-44ac98b0618c44bc9648cc63d0eda314`，观察约 20 秒，生成 11 条原始分级结论。
浏览器重放任务 `v-b1996f8e68de40f497983a73a52ed9f9` 使用此前封存的 OwnTracks 授权采集；
历史重放没有记为新 AAOS 采集，单元测试合成输入没有记为设备证据。

独立复核修复了四条问题：历史切换丢失运行状态、新建残留旧结果、源码响应乱序、jadx 致命失败误报完成。
旧快照连续 10×15 项的证据单独保存在 `review-initial.json`，没有将其称作当前 16 项的十轮结果。
revision 2 签核 SHA-256：`6e1926509f5d907e2e11312a8f40a24486aaea3ca08bac815076dd7bef9528aa`。

首轮新采集因未打开目标 App 失败，完整保留在 `output/vehicle-web/v-c72390af1672478c97b7f60d8e38373f/`。
该轮未伪装为无观测，设备设置与 reverse 均恢复。工作台已增加启动采集前的进程检查，
无法确认目标运行时保留底层 cause，并提示核对连接和正确用户。
两个浏览器验收脚本自身等待条件失败保存在前两份 `browser-*` 目录；修复后第三份 15 项全过。
本机沙箱禁止回环连接的 WinError 10013 与拒绝未读 body 后的 Windows TCP reset 已分别诊断；
HTTP 拒绝测试用空 body 验证 header 阶段门控，没有声称所有拒绝客户端都必然收到 JSON 403。

AI 本轮未配置，页面显示 skipped；未验证外部模型调用。
新采集仅实测自有 AAOS 35 模拟器与自有夹具，未宣称真实车辆或任意第三方 App 通用通过。
本轮未新增 APK 安装、权限自动授予、自动探索、政策上传或交付 subagent 签核的 Web 管理入口。
