"""Real-browser vehicle HTTP acceptance; no device operations. 仅用于授权测试。

Uses an authorized APK and a frozen healthy capture, then intentional negative
inputs. Synthetic policy metadata is a binding-negative control, never a policy.
"""
import argparse
import io
import json
import sys
import time
import zipfile
from pathlib import Path

from playwright.sync_api import sync_playwright


def run(base, apk, capture_label, out):
    out.mkdir(parents=True, exist_ok=False)
    checks, errors, tasks = {}, [], []
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path='C:/Program Files/Google/Chrome/Application/chrome.exe', headless=True)
        page = browser.new_page(viewport={'width': 1440, 'height': 1000})
        page.on('pageerror', lambda error: errors.append(str(error)))
        try:
            page.goto(base, wait_until='networkidle')
            page.wait_for_function("document.querySelector('#service-state').textContent.includes('已连接')")
            checks['all_seven_pages'] = page.locator('.nav-item').count() == 7
            checks['tls_explicit_default_off'] = not page.locator('#tls-bypass').is_checked()
            checks['authorization_default_off'] = not page.locator('#authorized').is_checked()
            config = page.request.get(base + '/api/config').json()
            capture = next(c for c in config['captures'] if capture_label in c['label'])
            def click(name):
                page.locator('[data-page="' + name + '"]').click()
            def new():
                page.locator('#new-audit').click()
                page.locator('#authorized').check()
            def upload(mode, version='15'):
                page.select_option('#audit-mode', mode)
                page.select_option('#audit-version', version)
                if mode == 'replay':
                    page.select_option('#capture-choice', capture['id'])
                previous = page.evaluate('window.VehicleUI.current')
                page.locator('#pipeline-apk-input').set_input_files(str(apk.resolve()))
                page.wait_for_function('(old) => window.VehicleUI.current && window.VehicleUI.current !== old', arg=previous, timeout=60000)
                identity = page.evaluate('window.VehicleUI.current'); tasks.append(identity)
                page.wait_for_function("document.querySelector('#audit-stage').dataset.state === 'done'", timeout=180000)
                return page.request.get(base + '/api/pipeline/' + identity).json()
            new(); first = upload('replay')
            checks['real_replay_completed'] = first['state'] == 'done'
            if first['state'] != 'done':
                raise AssertionError(first['result'])
            page.screenshot(path=str(out/'replay.png'), full_page=True)
            click('static'); page.wait_for_selector('#static-results .results-table')
            checks['static_results_from_api'] = True
            click('source'); page.locator('#file-tree button').first.click()
            page.wait_for_selector('#code-view .code-content')
            checks['source_file_from_api'] = bool(page.locator('#code-view .code-content').inner_text())
            checks['decompile_diagnostics_connected'] = page.get_by_text('反编译状态与覆盖缺口', exact=True).count() == 1
            click('dynamic'); page.wait_for_selector('#dynamic-results .ledger-panel')
            cards = page.locator('#dynamic-results .evidence-card')
            if cards.count():
                card = cards.first
                card.evaluate('(n) => n.open=true')
                card.locator('.review-block__form').evaluate('(n) => n.open=true')
                card.locator('.review-block__form select').select_option('needs_more_evidence')
                card.locator('.review-block__form input').fill('Integration UI')
                card.locator('.review-block__form textarea').fill('仅授权界面集成测试，不代表独立人工签核。')
                card.get_by_role('button', name='提交复核').click()
                page.wait_for_function("document.querySelector('.review-block__msg').textContent.includes('已回读')")
                checks['finding_review_write_and_readback'] = '需补充证据' in card.locator('.review-block__state').inner_text()
                checks['conclusion_badges_are_complete_words'] = page.locator('#dynamic-results .result-badge').first.inner_text() in ('已关联','已观测','候选','未判定')
            checks['ledger_and_bound_identity'] = first['id'] in page.request.get(base+'/api/pipeline/'+first['id']).text()
            checks['current_summary_bound'] = page.request.get(base+'/api/pipeline/'+first['id']+'/summary').json()['capture_validation']['session_id'] == capture['session']
            checks['full_coverage_connected'] = page.request.get(base+'/api/pipeline/'+first['id']+'/coverage').ok
            click('ai-report'); page.wait_for_function("document.querySelector('#ai-report').textContent.includes('未执行 AI')")
            checks['ai_skip_and_policy_gap'] = True
            click('pdf-report'); page.get_by_role('button', name='查看 PDF').first.click()
            checks['pdf_current_task'] = first['id'] in page.locator('#pdf-viewer-container iframe').get_attribute('src')
            response = page.request.get(base+'/api/pipeline/'+first['id']+'/report')
            checks['real_pdf'] = response.ok and response.body().startswith(b'%PDF-')
            response = page.request.get(base+'/api/pipeline/'+first['id']+'/evidence.zip')
            with zipfile.ZipFile(io.BytesIO(response.body())) as archive:
                checks['verified_zip'] = 'summary.json' in archive.namelist() and 'vehicle-audit.pdf' in archive.namelist()
            checks['zip_ui_link'] = page.get_by_role('link', name='下载完整证据包 ZIP').count() > 0
            new(); second = upload('static', '14')
            checks['selected_static_version'] = second['state'] == 'static_only' and second['options']['version'] == '14'
            click('dynamic'); page.wait_for_function("document.querySelector('#dynamic-results').textContent.includes('仅静态分析')")
            checks['static_is_not_dynamic_success'] = True
            # Wrong policy binding is deliberately rejected by the existing audit.
            policy = out/'policy.json'; policy.write_text(json.dumps({'package':'wrong.app','apk_sha256':'0'*64}), encoding='utf-8')
            new(); page.locator('#audit-options details').evaluate('(n) => n.open=true')
            page.locator('#evidence-files').set_input_files(str(policy.resolve()))
            page.select_option('#policy-file', 'policy.json')
            failed = upload('replay')
            checks['policy_reaches_audit_binding_gate'] = failed['state'] == 'failed' and failed['result']['error']['code'] == 'policy_app_mismatch'
            page.get_by_role('button', name='打开日志').click()
            page.wait_for_function("document.querySelector('#pipeline-result').textContent.includes('policy_app_mismatch') || document.querySelector('#pipeline-result').textContent.includes('policy_app')")
            checks['logs_connected'] = 'policy_app' in page.locator('#pipeline-result').inner_text()
            old_log = page.request.get(base+'/api/pipeline/'+failed['id']+'/logs').json()
            page.get_by_role('button', name='重试', exact=True).click()
            dialog = page.locator('#retry-dialog')
            checks['retry_requires_new_authorization'] = dialog.get_by_role('button', name='新建重试任务').is_disabled()
            dialog.locator('input[type=checkbox]').check()
            dialog.get_by_role('button', name='新建重试任务').click()
            page.wait_for_function('(old) => window.VehicleUI.current !== old', arg=failed['id'])
            retry_id = page.evaluate('window.VehicleUI.current'); tasks.append(retry_id)
            page.wait_for_function("document.querySelector('#audit-stage').dataset.state === 'done'", timeout=180000)
            retried = page.request.get(base+'/api/pipeline/'+retry_id).json()
            checks['retry_independent_and_inputs_retained'] = retried['state'] == 'failed' and retried['retry_of'] == failed['id'] and retried['result']['error']['code'] == 'policy_app_mismatch'
            checks['old_failure_retained'] = old_log == page.request.get(base+'/api/pipeline/'+failed['id']+'/logs').json()
            page.select_option('#apk-switch', first['id']); click('pdf-report')
            checks['old_pdf_cleared_on_switch'] = page.locator('#pdf-viewer-container iframe').count() == 0
            click('review'); page.wait_for_function("!document.querySelector('#review-round').textContent.includes('正在读取')")
            checks['unconfigured_review_is_explicit'] = bool(page.locator('#review-round').inner_text())
            page.reload(wait_until='networkidle')
            page.wait_for_function('!!window.VehicleUI.current')
            checks['history_survives_reload'] = page.locator('#apk-switch option').count() >= len(tasks)
            page.set_viewport_size({'width':390,'height':844}); click('pipeline')
            page.locator('#new-audit').click()
            page.locator('#audit-options details').evaluate('(n) => n.open=true')
            checks['narrow_settings_no_horizontal_overflow'] = page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.set_viewport_size({'width':1440,'height':1000})
            page.locator('#authorized').check()
            page.select_option('#audit-mode', 'static')
            before = len(page.request.get(base+'/api/pipeline').json())
            page.locator('#pipeline-apk-input').set_input_files(str(apk.resolve()))
            page.locator('#pipeline-apk-input').set_input_files(str(apk.resolve()))
            page.wait_for_function('!!window.VehicleUI.current', timeout=60000)
            page.wait_for_function("document.querySelector('#audit-stage').dataset.state === 'done'", timeout=180000)
            checks['duplicate_upload_is_single_flight'] = len(page.request.get(base+'/api/pipeline').json()) == before + 1
            page.set_viewport_size({'width':390,'height':844})
            page.screenshot(path=str(out/'mobile-width.png'), full_page=True)
            checks['narrow_view_no_horizontal_overflow'] = page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            checks['no_page_errors'] = not errors
        except Exception as error:
            errors.append(type(error).__name__ + ': ' + str(error))
            page.screenshot(path=str(out/'failure.png'), full_page=True)
        finally:
            browser.close()
    result = {'scope':'real HTTP/browser; frozen capture replay; no new device or AI run',
        'passed':bool(checks) and all(checks.values()) and not errors, 'checks':checks,'errors':errors,'tasks':tasks}
    (out/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))
    return result['passed']


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',default='http://127.0.0.1:8773')
    parser.add_argument('--apk',type=Path,required=True)
    parser.add_argument('--capture-label',required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    sys.exit(0 if run(args.base,args.apk,args.capture_label,args.out) else 1)
