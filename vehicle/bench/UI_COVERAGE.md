# G1 车载 UI 探索覆盖率

仅用于授权测试。这个最小基准冻结两份自有 debug APK。基准的页面与动作由夹具源码和布局人工标注，清单固定了包名及 APK 摘要。 [标注清单](ui-coverage-reference.json)

每个 APK 使用两个独立采集会话，从同一主 Activity 启动，各观察 36 秒。手动参考用 ADB 复现预先标注的操作顺序。自动模式运行工作台使用的现有探索器。两个模式都关闭 TLS 校验绕过，只操作读取和订阅控件。

- **页面覆盖率**按已观察到前台的标注 Activity 数除以标注页面数。每个夹具标注一页，启动页也计到达。页面分母取自 [第一夹具](../targets/target-app/app/src/main/AndroidManifest.xml) 与 [第二夹具](../targets/target-app2/app/src/main/AndroidManifest.xml) 的主流程。
- **动作覆盖率**按有同会话证据的标注动作数除以两个动作。读取须匹配界面操作和夹具 `VhalReader.readAll` 调用栈。订阅须记录接口接受注册及随后的 `SubscriptionReader` 回调读取。事件须在操作后 8 秒内且早于下一次记录操作。
- 新版自动探索记录已匹配的控件资源 ID。早期封存会话的读取记录按原有标签重放，沿用同一份标注清单。
- 评分核对包、用户、APK、会话、采集健康及输入摘要。每项输出命中、缺口和原始事件编号。手动参考必须实际覆盖标注清单，报表才会生成。

```powershell
# 在就绪的专用自有 AAOS 35 上建立四个新会话
.\tools\python313.ps1 -m vehicle.lab.ui_coverage_trial --serial emulator-5564 --out output/g1-new

# 从四轮已封存证据重算
.\tools\python313.ps1 -m vehicle.bench.ui_coverage --root output/g1-new --out output/g1-new/coverage.json
```

真实采集的 `ui-observations.json` 只保留 Activity、操作标识和时间。采集目录保存同会话 Hook 原始事件与探索器停止原因。这个基准的百分比适用于两份固定夹具及所标注的主流程。

## 2026-11-25 对照结果

| 自有夹具 | 手动页面 | 自动页面 | 手动动作 | 自动动作 | 自动停止原因 |
| --- | --- | --- | --- | --- | --- |
| `target-app` | 1/1 | 1/1 | 2/2 | 1/2 | `fixture_read_requested` |
| `target-app2` | 1/1 | 1/1 | 2/2 | 0/2 | `no_candidates` |

第一个夹具的自动探索触发直接读取，随后按现有策略结束。第二个夹具经过浏览后停止。两个自动会话均缺少订阅动作覆盖。四轮证据用同一入口重算两次，报告 SHA-256 一致。 [覆盖率报告](../../output/vehicle-g1-20261125/coverage.json)

## 2026-11-25 双夹具自动动作复验

| 自有夹具 | 手动页面 | 自动页面 | 手动动作 | 自动动作 |
| --- | --- | --- | --- | --- |
| `target-app` | 1/1 | 1/1 | 2/2 | 2/2 |
| `target-app2` | 1/1 | 1/1 | 2/2 | 2/2 |

四个新会话复用原 APK、标注清单和 36 秒窗口。复跑在同一 AAOS 35 构建的只读实例上关闭设备 Wi-Fi 和移动数据，并保留原代理设置。两个自动会话依次发送读取和订阅，评分均匹配到直接读取、成功注册及随后回调。旧报告重算字节一致。 [新报告](../../output/vehicle-g1-actions-20261125/coverage.json) · [改进复核](../../output/vehicle-g1-actions-20261125/improvement-verification.json) · [网络条件](../../output/vehicle-g1-actions-20261125/network-baseline.json)
