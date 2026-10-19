# 上传 APK 的完整审计接口

仅用于已获授权的 APK 与专用测试模拟器。此接口不再把上传 APK 替换成固定夹具。

## 服务配置

```powershell
python mobile/workbench/server.py `
  --audit-config <本机模型配置.json> `
  --audit-selftest <同设备同模式夹具正控目录/verification.json>
```

默认端口 **8772**（8771 留给 `mobile/pipeline`）；需要换端口再显式加 `--port`。

已有 `--jadx`、`--java-home`、`--sdk`、`--storage` 参数保持不变。
完整审计要求 storage 位于项目 `output` 下；模型配置只由服务启动读取，不从 HTTP 接收密钥或路径。
正控必须真实采到敏感读取及网络响应，且所有检查通过。其设备、采集模式、Android API
决定本服务允许的 audit 目标；切换 root / non-root 模式时要换相应正控配置，不能共用证明。

## 操作顺序

1. `POST /api/apk?name=sample.apk` 上传原始 APK。
2. 轮询上传 `job_id`，等待当前任务静态扫描、源码反编译结束。
3. `GET /api/tasks/{task_id}` 查看 `workflow.can_audit`、`audit_reason`、
   `audit_modes`、`audit_serial` 与 `audit_scenarios`。读取能力不会连接设备。
4. `POST /api/tasks/{task_id}/audit`：

```json
{
  "authorized": true,
  "mode": "nonroot-gadget",
  "serial": "emulator-5560",
  "scenario": "launch",
  "seconds": 20,
  "pcap_sidecar": true,
  "consent_timeout": 180
}
```

5. 返回 HTTP 202 与同一个 `task_id`、新的 `job_id`。轮询 `/api/jobs/{job_id}`。
6. 成功后仍在原上传任务查看 `/api/tasks/{task_id}/evidence` 与
   `/api/reports/task-{task_id}/file`；任务 `partial` 可表示实际流程完成但存在明确覆盖缺口。

### 实际执行

- `nonroot-gadget`：本轮原包备份及签名/身份记录 → 本轮 Gadget 重打包 → 普通权限实际安装、
  加载、场景触发与采集 → 原关联引擎、本地政策 → 真实三阶段 AI 与引用校验 → PDF。
  原包用于静态及政策身份，重签名副本的动态证据单独保留身份，不冒充原包字节未变。
- `root-emulator`：当前原包实际安装与采集，再进入同一正式管线；不重打包。
- VPN 抓包启用时，需在模拟器确认 PCAPdroid 控制与 Android VPN 正常可见授权弹窗。
  加密 PCAP 不等于已经取得全部协议明文。未启用 VPN 时仍记录实际进程 Hook 观察，
  不宣称 VPN 包级覆盖。
- 只接受 `emulator-数字`；不替换已安装同包名应用，不自动处理用户应用数据。
- 不接受任意命令、主机文件路径、密钥或保留会话路径，不能用旧会话假装本轮采集。

## 取消、失败与重启

`POST /api/jobs/{job_id}/cancel` 只请求取消。当前有界阶段及采集清理完成后才终止；
不会强杀正在清理的采集器。管线在发布前检查取消标记，取消或校验失败不发布本轮 PDF。

每次操作拥有独立 `tasks/{task_id}/attempts/{job_id}`，保留请求、插桩、采集及模型日志，
原报告会在新操作开始时撤下，而不是继续显示为本轮成功。
服务重启不等于旧采集已停止：仍存活的子进程以 PID 与进程创建时刻核对，
其退出前禁止新采集/报告操作，避免资源冲突或 PID 重用误判。
