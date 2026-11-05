# Windows 离线回归与 Gitee 接入

仅用于授权测试。回归执行使用 Python 3.13、Node.js 24 与 npm。它需要本机回环 HTTP，首次安装依赖需要访问 PyPI 和 npm。

## 统一回归入口

```powershell
python -m pip install -r requirements.txt
python tools/run_regressions.py --prepare --mobile --out output/ci-local
```

`--prepare` 调用现有的车载准备入口，安装锁文件对应的 Hook 依赖并构建车载与共享 bundle。
准备失败时停止本轮测试，保存 `prepare.log`、准备阶段的独立日志和 `verification.json`。
准备成功后运行 16 组根回归及 1 组移动侧检查。每次运行使用新目录。GitHub Actions 和 Jenkins 共用此入口。

隐私目录中按字节计算摘要的来源文件由 `.gitattributes` 固定换行格式。
第一版目录使用封存的 `POLICY_20261102.md`，审计导出采用同一份政策，便于干净检出时复核旧观测摘要。

## 并行与产物隔离

三个回归入口的默认目录均在时间戳后增加由文件系统独占创建的随机后缀。
`--out` 显式目录必须不存在，复用时立即失败。根回归的移动侧检查写入本轮 `mobile/`，
分支回归的上游检查分别写入本轮 `mobile/` 和可选的 `core/`，因此 CI 归档可包含子任务的端到端证据。
`latest-*.txt` 原子替换，Windows 短暂占用时有界重试；每轮通过与否仍以各自 `verification.json` 为准。

Jenkins 的 Push 和 PR 任务使用各自的工作区；`disableConcurrentBuilds()` 只约束同一个任务。
输出目录隔离支持共享源码目录上的并行离线回归。依赖安装、Hook 构建和设备采集仍各有可变状态，
构建任务应使用独立检出目录，单设备动态采集继续串行。

## Gitee 与 Jenkins

Gitee Go 官方云端 Python 插件文档列出 Linux 镜像和最高 Python 3.9。仓库的完整回归基线包含 Windows 路径测试，因此此处采用 Gitee Webhook 触发 Jenkins 的 Windows 执行节点。 [Gitee Go 构建插件](https://help.gitee.com/gitee-go/plugin/ci-build) · [Gitee Jenkins 插件](https://plugins.jenkins.io/gitee/)

1. 准备专用 Jenkins Windows 节点，标签设为 `windows`。在节点执行账号的 PATH 配置 Python 3.13、Node.js 24、npm 和 Git。使用专用检出目录，并在 Git 配置启用 **Clean before checkout**，使每轮从源码和锁文件准备依赖。
2. 安装 Gitee 插件。分别创建 **Push** 与 **PR** 两个 Pipeline 任务，Definition 选择 **Pipeline script from SCM**，指向同一 Gitee 仓库的 `Jenkinsfile`。Git 读取凭据与 Webhook 密码在各自的服务配置中填写。
3. Push 任务拉取 `+refs/heads/*:refs/remotes/origin/*`，分支填写 `origin/${giteeSourceBranch}`。PR 任务拉取 `+refs/pull/*/MERGE:refs/pull/*/MERGE`，分支填写 `pull/${giteePullRequestIid}/MERGE`。分别启用 Push 与 PR 新建、源分支更新事件。对两个任务分别在 Gitee 填写 Jenkins 提供的回调地址和密码。 [插件触发及检出配置](https://plugins.jenkins.io/gitee/)
4. 用一次测试分支推送和一次测试 PR 检查触发与检出。验收时将构建日志中的提交与 Gitee 对应分支或 PR 合并引用核对，并检查 `verification.json`。通过需包含准备步骤与 17 组回归全部退出为 0，失败构建仍可下载已写出的日志。

仓库中的配置负责执行和归档。Gitee 与 Jenkins 的首次远端触发需要在有权限的部署环境验证。

## 本机部署验收（2026-11-05）

本机 Jenkins 2.580.2 位于 `output/jenkins/`，使用 JDK 21，入口为
[本机 Jenkins](http://127.0.0.1:8080/)。账号为 `vscanner-admin`，密码保存在
`output/jenkins/home/LOGIN.txt`，文件访问限于本机部署账号。
Windows 节点 `windows-local` 有两个执行器，控制节点不执行构建。

任务 [vscanner-local #1](http://127.0.0.1:8080/job/vscanner-local/1/) 在独立工作区完成验收，
结果为 `SUCCESS`。准备步骤与 17 组回归全部通过，嵌套移动检查 29 项通过。
67 项产物已归档，包括本次 1181 个源码文件的快照摘要。
验收汇总见 [verification.json](../output/jenkins/acceptance/verification.json)。

部署以后台进程运行，Windows 重启后执行 `output/jenkins/start-all.ps1`。
配置、凭据与构建历史保存在 `output/jenkins/`，需随部署保留。
此任务验收本地工作区快照。Gitee 分支构建由下述独立任务执行。

## Gitee 主动轮询验收（2026-11-05）

[vscanner-gitee](http://127.0.0.1:8080/job/vscanner-gitee/) 直接检出
`codex/jenkins-integration`，Jenkinsfile 每五分钟轮询一次该分支。
任务使用独立 Windows 工作区与干净检出，构建产物按构建号归档。
首次手动构建检出 `57de015` 并通过准备步骤及 17 组回归。

随后在同一分支推送空验证提交 `6553011`，Jenkins 于 16:46 的轮询发现远端变化，
自动启动 [第 2 次构建](http://127.0.0.1:8080/job/vscanner-gitee/2/)。
该构建原因为 `hudson.triggers.SCMTrigger$SCMTriggerCause`，
实际检出 `6553011c47d1a0b15be7577d473488c44ae06577`，最终为 `SUCCESS`，
准备步骤和 17 组回归全部通过。
自动触发判据见 [automatic-verification.json](../output/jenkins/gitee-acceptance/automatic-verification.json)，
原始轮询日志与构建日志保存在同目录。
