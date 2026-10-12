# archive/

车载 / 移动端拆分过程中归档的死内容与历史快照。每个条目的完整来源、归档理由与原引用方
统一记录在 `MANIFEST.md`（Step 6 完成）。

## 当前内容

移动端报告快照（原混在车载前端 `frontend/pdfs/` 下，2026-10-11 手工拷贝、无脚本引用，
2026-10-12 拆分时移出，让车载前端只服务车载）：

- `mobile-device-latest.pdf` — 移动端设备审计报告快照。正规产物：
  `output/mobile-device-*/out/mobile-report.pdf`（指针 `output/latest-mobile-device.txt`）。
- `mobile-regression-latest.pdf` — 移动端回归报告快照。正规产物：
  `output/mobile-regression-*/e2e/report.pdf`（指针 `output/latest-mobile.txt`）。
- `thirdparty-latest.pdf` — 第三方 APK 审计报告快照。正规产物：
  `output/thirdparty-*/<包名>/out/mobile-report.pdf`（指针 `output/latest-thirdparty-batch.txt`）。
