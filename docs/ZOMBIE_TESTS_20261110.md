# 僵尸测试盘点（2026-11-10）

> 只读盘点：**没有修改任何测试文件**。执行环境为本机 Python 3.13（`tools/python313.ps1`）与 Node 24，未接设备。

## 方法

1. 枚举仓库全部 `test_*.py` / `test_*.mjs` / `test_*.js` / `*_test.py`（排除 `node_modules/`、`output/`、`skills/`、`archive/`、`.workbuddy/`、`.agents/`）。
2. 调用方只认三个 runner：`tools/run_regressions.py`、`mobile/tools/run_mobile_checks.py`、`tools/check_mobile_branch.py`（按其中的 `test_*` 模块名匹配）。
3. 仓库**没有** pytest 配置、没有 `conftest.py`，CI 里也**没有**自动发现（`python -m unittest discover` 只在 `check_mobile_branch.py` 内按目录显式调用）；`.github/workflows/ci.yml` 只调 `run_regressions.py --prepare --mobile`，`Jenkinsfile` 无测试步骤，`.pre-commit-config.yaml` 只跑 ruff 与行数守卫。因此「无 runner 引用」= 没有任何自动执行路径（**注意**：第一版把「没有 discover」当成全局事实，恰恰漏了 runner 内部那 6 条 discover 规则，见下方勘误）。
4. 对无调用方的文件逐个实跑：先按根目录 + dotted module（同 runner 口径），失败再按文件目录 + 裸模块名（兄弟模块裸 import 的目录），`rc=5` 再按脚本方式直跑；每次 120s 超时。

> **⚠️ 勘误（2026-11-10 13:14，由 `tools/test_inventory_guard.py` 复核）**：下面这句第一版口径**是错的**，
> 保留原文只为留病史，**不要据此判断**。当时只匹配「runner 文件里出现的字面 `test_*` 模块名」，
> 漏了两类引用：① `check_mobile_branch.py` 里的 `unittest discover -s <dir> -p <pattern>`
> （覆盖 `mobile/workbench` 12 个、`mobile/policy` 3 个、`mobile/pipeline` 2 个、`mobile/repack` 2 个、
> `mobile/audit` 的 `test_*.py`、`mobile/lab` 27 个）；② `f"test_{name}_model.mjs"` 这个 f-string 模板
> （覆盖 `mobile/workbench/frontend/` 的 7 个前端模型测试）。这 28 个文件**一直在跑**，被第一版误判成
> 「无调用方」——这也是后来「35 个」与「7 个」差异的全部来源。
>
> **现行口径（守卫实测，扫 `test_*.py` / `test_*.mjs` / `test_*.js`，排除 `archive/`、`output/`、`.venv`、`node_modules/`）**：
> **209 个文件 / 202 个被三个 runner 之一引用 / 7 个在 `tools/test_inventory_allowlist.json` 逐条登记 / 0 个未登记**。
> 判定规则（AST：字符串常量、f-string 模板、discover 规则；注释与 docstring 不算引用）见守卫脚本 docstring。
>
> 原文：~~总计 207 个文件：172 个有调用方，35 个无调用方。~~

| 判定 | 数量（第一版口径，见上方勘误） |
| --- | --- |
| 无调用方 · NOT_A_TEST | 2 |
| 无调用方 · PASS | 32 |
| 无调用方 · PASS(script) | 1 |
| 有调用方 | 172 |

## 结论先说

**真正的「无调用方且跑不通」= 0 个。** 64 个无调用方文件里，机械执行只有 1 个非零退出（`vehicle/pipeline/test_support.py`），人工核对后确认它**根本不是测试**——是被 4 个测试导入的辅助模块；同理 `tools/test_proxy_cert.py` 是自签证书库。去掉这 2 个误中 `test_*` 命名的库文件后，其余 62 个实跑全部通过（其中 `mobile/tools/test_pcap_pipeline.py` 是自带 FAILS 列表的脚本式测试，只能按脚本跑）。

> **2026-11-10 跟进（三轮，均已实跑）**：
> 
> 1. 第一轮把 5 个「被 import 但从不收集」的离线模块并入 `run_mobile_checks.py`（`workbench_adapters` / `workbench_http` / `audit_cipher_storage` / `lab_pcap_inventory` / `lab_core_capture`），套件 32 → **37 项**；连同先前的 `test_privacy_implementation.mjs` 共 6 个。
> 2. 第二轮把 `mobile/lab/` 剩余 24 个（20 个 dotted module + 4 个裸兄弟 import）并入同一套件，37 → **61 项**。两次连跑均 61/61 通过、`failed: []`，耗时 27.7 s / 26.9 s；24 项里最慢 0.65 s，无一项超过 1 s。隔离方式为**每项独立子进程**（`python -m unittest`），不共享解释器状态。单跑手册见 `docs/MOBILE_LAB_MANUAL_INDEX_20261110.md`。
> 3. 第三轮把这轮抓到的病做成**会响的警报**：新增 `tools/test_inventory_guard.py`（并入同一套件，61 → **62 项**）。它扫全仓 `test_*` 文件，判定是否被三个 runner 引用（AST 证据：字符串常量 / f-string 模板 / `unittest discover` 规则），未引用且未在 `tools/test_inventory_allowlist.json` 登记的**直接判红并打印路径**。两次连跑均 62/62 通过（32.8 s / 33.7 s）；负向验证（删掉 `hooks_privacy_impl` → 红并指名 `mobile/hooks/test_privacy_implementation.mjs`，恢复 → 绿）已闭环。同日并发线随后又并入 `observed_surface` 一组，现行为 **63 项**（63/63 通过）。
> 
> ~~因此表 B 现为 172 个文件，表 A 只剩 35 个~~（**这条是错的**，见上方勘误：现行 209 个文件 / 202 个被引用 / 7 个白名单登记）。
> 
> **另记**：12:44 起 `reachability` 组曾失败，原因是 `mobile/tools/{reachability,reach_report,test_reachability}.py` 正被另一条线并发修改（mtime 12:44–12:45，两次运行失败点不同：先 4 个 `KeyError: 'out_of_dex'`，后 2 个 wrapper 断言）。与本批并入无关；12:48 / 12:49 的两次 61 项连跑该组均为 `exit_code=0`。

但「能跑通」不等于「在被执行」。盘点暴露了三类问题，严重程度从高到低：

1. **测试方法从不执行、只当库被导入**（盘点时 5 个，已全部并入 runner）：`mobile/workbench/test_adapters.py`（15 用例）、`mobile/audit/test_cipher_storage.py`（25）、`mobile/lab/test_core_capture.py`（23）、`mobile/lab/test_pcap_inventory.py`（13）、`mobile/workbench/test_http.py`（7）。它们被同目录其它测试 `import` 当辅助模块，模块级代码确实跑了，**但 TestCase 方法在任何套件里都不会被收集**——正是「看着有守卫、其实没跑」的形态。
2. **纯脚本式测试**：`mobile/tools/test_pcap_pipeline.py`（无 TestCase，自带 FAILS 列表），只能人肉 `python 文件`，`-m unittest` 得 rc=5。
3. **`mobile/lab/` 几乎整目录无调用方**：27 个测试文件里，盘点时 0 个无调用方（`test_root_*` / `test_nonroot_*` / `test_domestic_*` 等，唯一例外是 `domestic/test_fetch.py`）。它们长期被当作「设备/真机实验，设计上就是手动跑」，实测却全部纯离线（227 用例 / 8 秒内 / 无设备依赖）——正是「目录身份代替执行路径」的病。已于 2026-11-10 第二轮全部并入 runner。

## 表 A：第一版判定的「无调用方」（正文 59 行，标题写 35 是生成脚本的遗留错误）

排序：非测试（误中命名）→ 脚本式 → 通过（按文件名）。

| 文件 | 实跑结果 | 用例数 | 说明 |
| --- | --- | --- | --- |
| `tools\test_proxy_cert.py` | NOT_A_TEST | — | **不是测试**：自签证书生成库，被 `tools/device_acceptance.py` 导入。误中 test_* 命名。 |
| `vehicle\pipeline\test_support.py` | NOT_A_TEST | 1 | **不是测试**：合成 capture 构造器，被 test_audit / test_bundle / test_preflight / test_window_calibration 导入（模块级代码确实执行，但无 TestCase）。 |
| `mobile\tools\test_pcap_pipeline.py` | PASS(script) | — | 脚本式测试（自带 FAILS 列表 + `python 文件` 跑法），无 unittest TestCase，`-m unittest` 得 rc=5；按脚本跑通过。 |
| `core\collector\test_derive.py` | PASS | 12 | `unittest-local` 口径跑通 |
| `mobile\audit\test_assess_probe.py` | PASS | 14 | `unittest-local` 口径跑通 |
| `mobile\audit\test_cipher_storage.py` | PASS | 25 | 被 test_package_base64 以辅助模块方式导入。 |
| `mobile\audit\test_package_base64.py` | PASS | 9 | `unittest-local` 口径跑通 |
| `mobile\audit\test_storage_crypto.mjs` | PASS | — | `node` 口径跑通 |
| `mobile\lab\test_compat_control.py` | PASS | 6 | `unittest-root` 口径跑通 |
| `mobile\lab\test_core_capture.py` | PASS | 23 | 被 test_jsonl_unicode 以辅助模块方式导入。 |
| `mobile\lab\test_core_capture_ui.py` | PASS | 6 | `unittest-root` 口径跑通 |
| `mobile\lab\test_core_compile_entry.py` | PASS | 1 | `unittest-root` 口径跑通 |
| `mobile\lab\test_core_observer_start.py` | PASS | 3 | `unittest-root` 口径跑通 |
| `mobile\lab\test_core_pipeline.py` | PASS | 6 | `unittest-root` 口径跑通 |
| `mobile\lab\test_core_task_binding.py` | PASS | 5 | `unittest-root` 口径跑通 |
| `mobile\lab\test_domestic_formal.py` | PASS | 10 | `unittest-root` 口径跑通 |
| `mobile\lab\test_domestic_static.py` | PASS | 13 | `unittest-root` 口径跑通 |
| `mobile\lab\test_domestic_summary.py` | PASS | 10 | `unittest-root` 口径跑通 |
| `mobile\lab\test_enrich_risk.py` | PASS | 1 | `unittest-root` 口径跑通 |
| `mobile\lab\test_jsonl_unicode.py` | PASS | 7 | `unittest-root` 口径跑通 |
| `mobile\lab\test_nonroot_capture.py` | PASS | 13 | `unittest-root` 口径跑通 |
| `mobile\lab\test_nonroot_capture_ui.py` | PASS | 9 | `unittest-root` 口径跑通 |
| `mobile\lab\test_nonroot_traffic.py` | PASS | 5 | `unittest-root` 口径跑通 |
| `mobile\lab\test_nonroot_vpn_identity.py` | PASS | 5 | `unittest-root` 口径跑通 |
| `mobile\lab\test_pcap_cooked.py` | PASS | 6 | `unittest-root` 口径跑通 |
| `mobile\lab\test_pcap_inventory.py` | PASS | 13 | 被 test_pcap_cooked / test_root_tcp 以辅助模块方式导入。 |
| `mobile\lab\test_pcap_sidecar.py` | PASS | 24 | `unittest-local` 口径跑通 |
| `mobile\lab\test_probe_transport.py` | PASS | 24 | `unittest-local` 口径跑通 |
| `mobile\lab\test_readyou_ui.py` | PASS | 4 | `unittest-root` 口径跑通 |
| `mobile\lab\test_root_assessment.py` | PASS | 19 | `unittest-local` 口径跑通 |
| `mobile\lab\test_root_runner.py` | PASS | 18 | `unittest-root` 口径跑通 |
| `mobile\lab\test_root_tcp.py` | PASS | 17 | `unittest-root` 口径跑通 |
| `mobile\lab\test_sdk_hook_scope.py` | PASS | 4 | `unittest-root` 口径跑通 |
| `mobile\lab\test_validate_network.py` | PASS | 11 | `unittest-local` 口径跑通 |
| `mobile\pipeline\test_formal_runner.py` | PASS | 3 | `unittest-root` 口径跑通 |
| `mobile\pipeline\test_history.py` | PASS | 2 | `unittest-root` 口径跑通 |
| `mobile\policy\test_policy_bytes.py` | PASS | 1 | `unittest-root` 口径跑通 |
| `mobile\policy\test_policy_formats.py` | PASS | 4 | `unittest-root` 口径跑通 |
| `mobile\policy\test_policy_supplements.py` | PASS | 10 | `unittest-root` 口径跑通 |
| `mobile\repack\test_certificate.py` | PASS | 2 | `unittest-root` 口径跑通 |
| `mobile\repack\test_repack.py` | PASS | 13 | `unittest-root` 口径跑通 |
| `mobile\tools\test_split_events.py` | PASS | 6 | `unittest-root` 口径跑通 |
| `mobile\workbench\frontend\test_audit_model.mjs` | PASS | — | `node` 口径跑通 |
| `mobile\workbench\frontend\test_benchmark_model.mjs` | PASS | — | `node` 口径跑通 |
| `mobile\workbench\frontend\test_evidence_model.mjs` | PASS | — | `node` 口径跑通 |
| `mobile\workbench\frontend\test_job_model.mjs` | PASS | — | `node` 口径跑通 |
| `mobile\workbench\frontend\test_risk_model.mjs` | PASS | — | `node` 口径跑通 |
| `mobile\workbench\frontend\test_runtime_model.mjs` | PASS | — | `node` 口径跑通 |
| `mobile\workbench\frontend\test_workflow_model.mjs` | PASS | — | `node` 口径跑通 |
| `mobile\workbench\test_adapters.py` | PASS | 15 | 有 15 个 TestCase 但无 runner；同时被 test_http / test_audit_api / test_core_publish / test_operations_http / mobile/ai/test_supplemental_observations 当**辅助模块**导入——模块级代码跑了，测试方法一次没跑。 |
| `mobile\workbench\test_audit_api.py` | PASS | 6 | `unittest-root` 口径跑通 |
| `mobile\workbench\test_audit_recovery.py` | PASS | 5 | `unittest-root` 口径跑通 |
| `mobile\workbench\test_audit_worker.py` | PASS | 7 | `unittest-root` 口径跑通 |
| `mobile\workbench\test_benchmarks.py` | PASS | 11 | `unittest-root` 口径跑通 |
| `mobile\workbench\test_capture_cancel.py` | PASS | 5 | `unittest-root` 口径跑通 |
| `mobile\workbench\test_core_publish.py` | PASS | 23 | `unittest-root` 口径跑通 |
| `mobile\workbench\test_core_static_task.py` | PASS | 8 | `unittest-root` 口径跑通 |
| `mobile\workbench\test_http.py` | PASS | 7 | 被 test_operations_http 以辅助模块方式导入。 |
| `mobile\workbench\test_local_policy.py` | PASS | 2 | `unittest-root` 口径跑通 |
| `mobile\workbench\test_merge_layout.py` | PASS | 1 | `unittest-root` 口径跑通 |
| `mobile\workbench\test_operations_http.py` | PASS | 3 | `unittest-root` 口径跑通 |
| `mobile\workbench\test_report_ai.py` | PASS | 16 | `unittest-root` 口径跑通 |
| `mobile\workbench\test_runtime_import.py` | PASS | 2 | `unittest-root` 口径跑通 |
| `vehicle\hooks\test_mg4_form.mjs` | PASS | — | `node` 口径跑通 |

## 表 B：有调用方（172 个）

| 文件 | 调用方 |
| --- | --- |
| `core\collector\test_attribution.py` | `run_regressions.py` |
| `core\collector\test_binary_probe.py` | `run_regressions.py` |
| `core\collector\test_body.py` | `run_regressions.py` |
| `core\collector\test_experiment.py` | `run_regressions.py` |
| `core\collector\test_health.py` | `run_regressions.py` |
| `core\collector\test_montecarlo.py` | `run_regressions.py` |
| `core\collector\test_native_write.py` | `run_regressions.py` |
| `core\collector\test_origin.py` | `run_regressions.py` |
| `core\collector\test_parse.py` | `run_regressions.py` |
| `core\collector\test_redaction.py` | `run_regressions.py` |
| `core\collector\test_response_capture.py` | `run_regressions.py` |
| `core\collector\test_response_observation.py` | `run_regressions.py` |
| `core\collector\test_scope.py` | `run_regressions.py` |
| `core\collector\test_system_probe.py` | `run_regressions.py` |
| `core\collector\test_targets.py` | `run_regressions.py` |
| `core\collector\test_uid_sampler.py` | `run_regressions.py` |
| `core\collector\test_unanswered.py` | `run_regressions.py` |
| `core\collector\test_vehicle_lifecycle.py` | `run_regressions.py` |
| `core\collector\test_websocket_frames.py` | `run_regressions.py` |
| `core\evidence\test_ambiguity.py` | `run_regressions.py` |
| `core\evidence\test_codeloc.py` | `run_regressions.py` |
| `core\evidence\test_decidability.py` | `run_regressions.py` |
| `core\evidence\test_event_lookup.py` | `run_regressions.py` |
| `core\frida_host\test_build.py` | `check_mobile_branch.py` |
| `core\frida_host\test_bundle_config.py` | `run_regressions.py` |
| `core\frida_host\test_message_stream.py` | `run_regressions.py` |
| `core\frida_host\test_shutdown.py` | `run_regressions.py` |
| `core\static\test_analysis.py` | `run_regressions.py` |
| `core\static\test_crosscheck.py` | `run_regressions.py` |
| `core\static\test_jobs.py` | `run_regressions.py` |
| `core\static\test_static_rules.py` | `run_regressions.py` |
| `core\test_event_store.py` | `run_regressions.py` |
| `core\test_regression_output.py` | `run_regressions.py` |
| `core\test_rules_contract.py` | `run_regressions.py` |
| `frontend\test_audit_results.mjs` | `check_mobile_branch.py` |
| `mobile\ai\test_ai.py` | `run_mobile_checks.py` |
| `mobile\ai\test_ai_gates.py` | `run_mobile_checks.py` + `check_mobile_branch.py` |
| `mobile\ai\test_benchmark_review.py` | `check_mobile_branch.py` |
| `mobile\ai\test_benchmark_review_attach.py` | `check_mobile_branch.py` |
| `mobile\ai\test_formal_contract.py` | `run_mobile_checks.py` + `check_mobile_branch.py` |
| `mobile\ai\test_llm_transport.py` | `check_mobile_branch.py` |
| `mobile\ai\test_policy_sources.py` | `run_mobile_checks.py` + `check_mobile_branch.py` |
| `mobile\ai\test_storage_context.py` | `check_mobile_branch.py` |
| `mobile\ai\test_storage_observations.py` | `check_mobile_branch.py` |
| `mobile\ai\test_storage_prompt_contract.py` | `check_mobile_branch.py` |
| `mobile\ai\test_supplemental_observations.py` | `check_mobile_branch.py` |
| `mobile\ai\test_validation_repair.py` | `check_mobile_branch.py` |
| `mobile\analyze\test_analyze.py` | `run_mobile_checks.py` |
| `mobile\analyze\test_analyze_egress.py` | `run_mobile_checks.py` |
| `mobile\analyze\test_bundle_risk.py` | `check_mobile_branch.py` |
| `mobile\analyze\test_client_tls.py` | `check_mobile_branch.py` |
| `mobile\analyze\test_consent_observation.py` | `run_mobile_checks.py` + `check_mobile_branch.py` |
| `mobile\analyze\test_coverage_gap.py` | `run_mobile_checks.py` |
| `mobile\analyze\test_observation_semantics.py` | `check_mobile_branch.py` |
| `mobile\analyze\test_risk_band.py` | `run_mobile_checks.py` |
| `mobile\analyze\test_risk_rating.py` | `check_mobile_branch.py` |
| `mobile\analyze\test_risk_score.py` | `run_mobile_checks.py` + `check_mobile_branch.py` |
| `mobile\analyze\test_values.mjs` | `check_mobile_branch.py` |
| `mobile\audit\test_cipher_storage.py` | `run_mobile_checks.py` |
| `mobile\fixture-app\test_gadget_prepare.py` | `check_mobile_branch.py` |
| `mobile\hooks\test_dispatch.mjs` | `run_mobile_checks.py` |
| `mobile\hooks\test_privacy_implementation.mjs` | `run_mobile_checks.py` |
| `mobile\lab\domestic\test_fetch.py` | `check_mobile_branch.py` |
| `mobile\lab\test_compat_control.py` | `run_mobile_checks.py` |
| `mobile\lab\test_core_capture.py` | `run_mobile_checks.py` |
| `mobile\lab\test_core_capture_ui.py` | `run_mobile_checks.py` |
| `mobile\lab\test_core_compile_entry.py` | `run_mobile_checks.py` |
| `mobile\lab\test_core_observer_start.py` | `run_mobile_checks.py` |
| `mobile\lab\test_core_pipeline.py` | `run_mobile_checks.py` |
| `mobile\lab\test_core_task_binding.py` | `run_mobile_checks.py` |
| `mobile\lab\test_domestic_formal.py` | `run_mobile_checks.py` |
| `mobile\lab\test_domestic_static.py` | `run_mobile_checks.py` |
| `mobile\lab\test_domestic_summary.py` | `run_mobile_checks.py` |
| `mobile\lab\test_enrich_risk.py` | `run_mobile_checks.py` |
| `mobile\lab\test_jsonl_unicode.py` | `run_mobile_checks.py` |
| `mobile\lab\test_nonroot_capture.py` | `run_mobile_checks.py` |
| `mobile\lab\test_nonroot_capture_ui.py` | `run_mobile_checks.py` |
| `mobile\lab\test_nonroot_traffic.py` | `run_mobile_checks.py` |
| `mobile\lab\test_nonroot_vpn_identity.py` | `run_mobile_checks.py` |
| `mobile\lab\test_pcap_cooked.py` | `run_mobile_checks.py` |
| `mobile\lab\test_pcap_inventory.py` | `run_mobile_checks.py` |
| `mobile\lab\test_pcap_sidecar.py` | `run_mobile_checks.py` |
| `mobile\lab\test_probe_transport.py` | `run_mobile_checks.py` |
| `mobile\lab\test_readyou_ui.py` | `run_mobile_checks.py` |
| `mobile\lab\test_root_assessment.py` | `run_mobile_checks.py` |
| `mobile\lab\test_root_runner.py` | `run_mobile_checks.py` |
| `mobile\lab\test_root_tcp.py` | `run_mobile_checks.py` |
| `mobile\lab\test_sdk_hook_scope.py` | `run_mobile_checks.py` |
| `mobile\lab\test_validate_network.py` | `run_mobile_checks.py` |
| `mobile\policy\test_policy.py` | `run_mobile_checks.py` + `check_mobile_branch.py` |
| `mobile\policy\test_policy_library.py` | `run_mobile_checks.py` |
| `mobile\report\test_export_sarif.py` | `run_mobile_checks.py` |
| `mobile\report\test_report.py` | `run_mobile_checks.py` |
| `mobile\report\test_report_gates.py` | `run_mobile_checks.py` + `check_mobile_branch.py` |
| `mobile\report\test_report_health.py` | `check_mobile_branch.py` |
| `mobile\rules\test_rules.py` | `run_mobile_checks.py` |
| `mobile\tools\test_a1_tier_scan.py` | `run_mobile_checks.py` |
| `mobile\tools\test_apk_packer.py` | `run_mobile_checks.py` |
| `mobile\tools\test_app_death.py` | `run_mobile_checks.py` |
| `mobile\tools\test_batch_static.py` | `run_mobile_checks.py` |
| `mobile\tools\test_coverage_window.py` | `run_mobile_checks.py` |
| `mobile\tools\test_device_cleanup.py` | `check_mobile_branch.py` |
| `mobile\tools\test_device_permissions.py` | `check_mobile_branch.py` |
| `mobile\tools\test_device_pipeline.py` | `check_mobile_branch.py` |
| `mobile\tools\test_device_runtime.py` | `check_mobile_branch.py` |
| `mobile\tools\test_device_trigger.py` | `check_mobile_branch.py` |
| `mobile\tools\test_hooks_parity.py` | `run_mobile_checks.py` |
| `mobile\tools\test_jsonl_tool_readers.py` | `run_mobile_checks.py` |
| `mobile\tools\test_launcher_activity.py` | `run_mobile_checks.py` |
| `mobile\tools\test_reachability.py` | `run_mobile_checks.py` |
| `mobile\tools\test_reachability_wrapper.py` | `run_mobile_checks.py` |
| `mobile\tools\test_sample_runtime.py` | `run_mobile_checks.py` |
| `mobile\tools\test_static_supplement.py` | `run_mobile_checks.py` |
| `mobile\tools\test_ui_flow_label.py` | `run_mobile_checks.py` |
| `mobile\tools\test_ui_flow_state.py` | `run_mobile_checks.py` |
| `mobile\traffic\test_apex_ca.py` | `run_mobile_checks.py` |
| `mobile\traffic\test_tagging_mobile.py` | `run_mobile_checks.py` |
| `mobile\traffic\test_transparent.py` | `run_mobile_checks.py` |
| `mobile\workbench\test_adapters.py` | `run_mobile_checks.py` |
| `mobile\workbench\test_http.py` | `run_mobile_checks.py` |
| `mobile\workbench\test_workflow.py` | `run_regressions.py` |
| `test_completion.py` | `run_regressions.py` |
| `tools\test_hook_bundles.py` | `run_regressions.py` |
| `vehicle\ai\test_evidence_capability.py` | `run_regressions.py` |
| `vehicle\analyze\test_context.py` | `run_regressions.py` |
| `vehicle\analyze\test_experiment.py` | `run_regressions.py` |
| `vehicle\analyze\test_method_evidence.py` | `run_regressions.py` |
| `vehicle\analyze\test_vehicle_evidence.py` | `run_regressions.py` |
| `vehicle\bench\test_ablation.py` | `run_regressions.py` |
| `vehicle\bench\test_blind_round.py` | `run_regressions.py` |
| `vehicle\bench\test_expanded_round.py` | `run_regressions.py` |
| `vehicle\bench\test_handoff.py` | `run_regressions.py` |
| `vehicle\bench\test_metrics.py` | `run_regressions.py` |
| `vehicle\bench\test_overhead.py` | `run_regressions.py` |
| `vehicle\bench\test_subagent_signoff.py` | `run_regressions.py` |
| `vehicle\bench\test_suite.py` | `run_regressions.py` |
| `vehicle\bench\test_window_calibration.py` | `run_regressions.py` |
| `vehicle\coverage\test_coverage.py` | `run_regressions.py` |
| `vehicle\dashboard\test_dashboard.py` | `run_regressions.py` |
| `vehicle\hooks\test_privacy.mjs` | `run_regressions.py` |
| `vehicle\hooks\test_runtime.mjs` | `run_regressions.py` |
| `vehicle\lab\test_abs_progress.py` | `run_regressions.py` |
| `vehicle\lab\test_companion.py` | `run_regressions.py` |
| `vehicle\lab\test_evidence_repairs.py` | `run_regressions.py` |
| `vehicle\lab\test_gpslogger_probe.py` | `run_regressions.py` |
| `vehicle\lab\test_mg4_write.py` | `run_regressions.py` |
| `vehicle\lab\test_owntracks_multiple.py` | `run_regressions.py` |
| `vehicle\lab\test_owntracks_permissions.py` | `run_regressions.py` |
| `vehicle\lab\test_owntracks_run.py` | `run_regressions.py` |
| `vehicle\pipeline\test_acceptance.py` | `run_regressions.py` |
| `vehicle\pipeline\test_audit.py` | `run_regressions.py` |
| `vehicle\pipeline\test_bundle.py` | `run_regressions.py` |
| `vehicle\pipeline\test_capture_lifecycle.py` | `run_regressions.py` |
| `vehicle\pipeline\test_capture_proxy.py` | `run_regressions.py` |
| `vehicle\pipeline\test_diagnostics.py` | `run_regressions.py` |
| `vehicle\pipeline\test_environment.py` | `run_regressions.py` |
| `vehicle\pipeline\test_preflight.py` | `run_regressions.py` |
| `vehicle\pipeline\test_scenarios.py` | `run_regressions.py` |
| `vehicle\policy\test_assessment.py` | `run_regressions.py` |
| `vehicle\privacy\test_evaluation.py` | `run_regressions.py` |
| `vehicle\privacy\test_ha_evaluation.py` | `run_regressions.py` |
| `vehicle\privacy\test_ha_socket_evidence.py` | `run_regressions.py` |
| `vehicle\privacy\test_observation.py` | `run_regressions.py` |
| `vehicle\privacy\test_versions.py` | `run_regressions.py` |
| `vehicle\rules\android\tools\test_crossprocess_checks.py` | `run_regressions.py` |
| `vehicle\rules\android\tools\test_recovery_acceptance.py` | `run_regressions.py` |
| `vehicle\traffic\test_tagging.py` | `run_regressions.py` |
| `vehicle\webapp\test_finding_reviews.py` | `run_regressions.py` |
| `vehicle\webapp\test_presentation.py` | `run_regressions.py` |
| `vehicle\webapp\test_review_round.py` | `run_regressions.py` |
| `vehicle\webapp\test_server.py` | `run_regressions.py` |
| `vehicle\webapp\test_workflow.py` | `run_regressions.py` |

## 盘点当时的边界（哪些后续已做）

- 盘点本身只读：没有合并、没有改测试。**后续三轮**已把 6 + 24 个模块并入 `run_mobile_checks.py`（32 → 61 项），并加 1 项测试清单守卫（61 → 62 项）；本条记录的是当时的边界。
- 没有改任何断言：并入的 30 项首跑即通过，无一项需要迁就。
- ~~其余 35 个无调用方文件保持原状~~（**计数已勘误**：真正无引用的是 7 个（`core/collector/test_derive.py`、`mobile/audit/test_storage_crypto.mjs`、`mobile/tools/test_pcap_pipeline.py`、`mobile/tools/test_split_events.py`、`tools/test_proxy_cert.py`、`vehicle/hooks/test_mg4_form.mjs`、`vehicle/pipeline/test_support.py`），全部在 `tools/test_inventory_allowlist.json` 逐条登记；其余曾被误判的文件一直在 discover / f-string 模板覆盖下执行）。
- 本次未接设备，所有结论只覆盖「本机离线可跑性」，不代表接设备后的结论。
