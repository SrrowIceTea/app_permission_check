# V-Scanner 前端界面

面向 AAOS 的车载 App 数据安全合规审计平台前端界面。
**仅用于授权测试（自有设备与自有 APK）。**

## 文件结构

```
frontend/
├── index.html      # 首页（Landing Page）
├── landing.css     # 首页样式
├── landing.js      # 首页动画与交互
├── app.html        # 工作台主界面
├── app.css         # 工作台样式
├── app.js          # 工作台逻辑（对接 vehicle/workbench 后端）
├── highlight.js    # 零依赖 Java/Kotlin 词法高亮器（自写，不引 CDN）
└── pdfs/           # 审计报告 PDF 快照：车载 + 移动端（设备/回归/第三方）各一份
```

## 功能页面

### 首页 (index.html)
- 高端大气的 Landing Page，进入工作台按钮跳转 `app.html`
- GSAP 滚动动画（CDN 不通时自动降级，不影响使用）

### 工作台 (app.html)
左侧导航包含五个功能页面：

1. **源码查看** - 反编译源码树（嵌套目录 + 路径过滤），点文件看代码
2. **静态审计** - 静态规则命中表（规则/类型/强度/等级/信号/依据）
3. **动态审计** - 静动交叉核对四象限（both / static_only / dynamic_only / none）
4. **AI 报告** - 综合审计报告（概览/权限/风险分布/缺口/建议）
5. **PDF 报告** - 审计报告 PDF 查看（车载 + 移动端快照，iframe 原生查看器）

## 使用方式

### 1. 启动后端服务（vehicle/workbench）

```bash
cd vehicle/workbench
python server.py --port 8770
# 可选：带采集会话做静动对照
python server.py --port 8770 \
    --session ../output/device-xxx \
    --findings ../output/delivery-xxx/findings.jsonl
```

### 2. 打开前端页面

```bash
cd frontend
python -m http.server 8080
# 访问 http://localhost:8080/app.html
```

> 前端通过 `127.0.0.1:8770` 调用后端 API，`server.py` 已加 CORS 头，
> 跨端口/跨域访问无需额外配置。

### 3. 上传 APK

- 拖拽 APK 到顶部上传区，或点击选择文件
- 后端后台分析（静态扫描秒级出结论，反编译分钟级），前端轮询进度
- 完成后自动跳转到静态审计页

## API 接口（vehicle/workbench/server.py）

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/apk?name=..` | POST | 上传 APK（原始字节，非 multipart），返回 `{digest, job, cached}` |
| `/api/jobs/{id}` | GET | 查询任务状态（`state`: queued/running/done/failed/cancelled） |
| `/api/jobs/{id}/cancel` | POST | 取消任务 |
| `/api/apk/{digest}/tree` | GET | 文件树（扁平 `{files:[{path,size}]}`） |
| `/api/apk/{digest}/source?path=..` | GET | 源码（`{path,size,truncated,text}`） |
| `/api/apk/{digest}/static` | GET | 静态结论（`findings` 等） |
| `/api/apk/{digest}/summary` | GET | 分析摘要（`apk/findings/decompile` 等） |
| `/api/apk/{digest}/crosscheck` | GET | 静动四象限对照（或 `comparable:false`） |
| `/api/tools` | GET | 工具链就绪情况（jadx/aapt2/dexdump） |

## 关键约定

- **PDF 页列的是手工快照，不是实时产物**：`pdfs/` 下四份 PDF 都没有脚本引用，
  要更新得重新拷。移动端报告的**正规产物**在 `output/mobile-*/`、`output/thirdparty-*/` 下
  （指针 `output/latest-mobile-device.txt` / `latest-mobile.txt` / `latest-thirdparty-batch.txt`），
  按需替换这里的快照。
  > 历史：2026-10-12 拆分时曾把移动端三份移出 `archive/`，以让前端「只服务车载」；
  > 2026-10-13 按用户要求恢复回下拉（前端是日常查看报告的入口，只列车载不够用）。
- **静态结论等级封顶 `candidate`**：代码里出现引用不证明运行时行为，违规仍需人工判定。
- **动态侧数据来自 `/crosscheck`**：需要后端启动时带 `--session`/`--findings`；
  缺失时前端如实显示"无法对照"，不硬凑数据。
- **源码渲染零 innerHTML**：反编译产物可能含任意字符串，统一走 `textContent`。

## 授权声明

**仅用于授权测试（自有设备与自有 APK）。**
所有抓包、Hook 操作均在白名单包名范围内进行，观察不改写，判定可追溯。
