"""Publish one completed CLI run onto its original uploaded task. No new evidence."""
from __future__ import annotations
import hashlib
import json
import shutil
from pathlib import Path
from mobile.ai.review_gates import digest, load_checked_stages, validate_stage
from mobile.ai.validate import parse_json_output
from mobile.workbench import evidence_adapter
from mobile.workbench.store import Store, read_json, write_json


def check_response(ai_dir: Path, call: dict, output) -> None:
    """Bind every accepted response to the retained transport body, not a log label."""
    raw = read_json(ai_dir / ("llm-response-" + call['tag'] + ".raw.json"), {})
    choices = raw.get('choices') if isinstance(raw, dict) else None
    choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
    message = choice.get('message')
    raw_text = message.get('content') if isinstance(message, dict) else None
    if (call.get('http_status') != 200 or call.get('error')
            or call.get('response_complete') is not True or call.get('finish_reason') != 'stop'
            or choice.get('finish_reason') != 'stop'
            or not isinstance(call.get('model'), str) or not call['model'].strip()
            or not isinstance(raw.get('model'), str) or not raw['model'].strip()
            or not isinstance(call.get('text'), str) or not call['text'].strip()
            or raw_text != call['text'] or parse_json_output(call['text'])[0] != output):
        raise ValueError('live AI response provenance is incomplete or inconsistent for ' + call['tag'])


def check_live_calls(ai_dir: Path, stages: dict, bundle: dict) -> list[dict]:
    """Three ordered initial calls, each optionally followed by one gate-only repair."""
    calls = [json.loads(line) for line in (ai_dir / 'llm-calls.jsonl').read_text(encoding='utf-8').split("\n") if line.strip()]
    expected = []
    for num in (1, 2, 3):
        stage = f'stage{num}'
        initial = [c for c in calls if c.get('tag') == stage]
        repair = [c for c in calls if c.get('tag') == stage + '-repair1']
        if len(initial) != 1 or len(repair) > 1:
            raise ValueError('missing or duplicate live AI request provenance for ' + stage)
        expected.append(stage)
        if repair:
            expected.append(stage + '-repair1')
            first, final = initial[0], repair[0]
            original_path = ai_dir / (stage + '.initial.json')
            failed_output = read_json(original_path)
            failed_validation = read_json(ai_dir / (stage + '.initial.validation.json'), {})
            parsed_initial, parse_errors = parse_json_output(first.get('text') or '')
            parse_failure_retained = (failed_output is None and parsed_initial is None and bool(parse_errors)
                and all(error in failed_validation.get('problems', []) for error in parse_errors))
            if (not original_path.is_file() or not (isinstance(failed_output, dict) or parse_failure_retained)
                    or failed_validation.get('ok') is not False
                    or not failed_validation.get('problems')
                    or failed_validation.get('output_sha256') != digest(failed_output)
                    or failed_validation.get('bundle_sha256') != digest(bundle)
                    or validate_stage(stage, failed_output, bundle)['ok']):
                raise ValueError('repair provenance lacks the bound original gate failure for ' + stage)
            check_response(ai_dir, first, failed_output)
            repair_validation = read_json(ai_dir / (stage + '-repair1.validation.json'), {})
            if (repair_validation.get('ok') is not True or
                    repair_validation.get('output_sha256') != digest(stages[stage]) or
                    repair_validation.get('bundle_sha256') != digest(bundle)):
                raise ValueError('repaired output is not bound to its successful gate for ' + stage)
        check_response(ai_dir, repair[0] if repair else initial[0], stages[stage])
    if ([c.get('tag') for c in calls] != expected or not 3 <= len(calls) <= 6 or
            any(c.get('http_status') != 200 or c.get('error') for c in calls)):
        raise ValueError('missing complete ordered live AI request provenance')
    return calls


def publish(storage: Path, task_id: str, run: Path):
    store = Store(storage)
    task = store.get(task_id)
    if not task:
        raise ValueError('original upload task is missing')
    verification = read_json(run / 'verification.json', {})
    if (verification.get('passed') is not True or
            any(verification.get('stages', {}).get(s, {}).get('state') != 'done'
                for s in ('static', 'policy', 'capture', 'correlate', 'bundle', 'ai', 'report'))):
        raise ValueError('cannot publish an incomplete core run')
    bundle = evidence_adapter.check_bundle(read_json(run / 'out/bundle.json'))
    app = bundle['app']
    if app.get('package') != task['apk'].get('package') or app.get('apk_sha256') != task['apk'].get('sha256'):
        raise ValueError('core result belongs to a different uploaded APK')
    stages, validation = load_checked_stages(run / 'out/ai', bundle)
    if set(stages) != {'stage1', 'stage2', 'stage3'} or not all(v['ok'] for v in validation.values()):
        rejected = {name: item['problems'] for name, item in validation.items() if not item['ok']}
        raise ValueError('core AI stages failed bound formal revalidation: ' +
                         json.dumps(rejected, ensure_ascii=False))
    checked = {'state': 'imported_validated', 'stages': stages, 'validation': validation,
               'rejected_stages': []}
    calls = check_live_calls(run / 'out/ai', stages, bundle)
    checked.update(origin='core_cli_live', calls_verified=True, request_count=len(calls),
                   validation_repairs=sum(c['tag'].endswith('-repair1') for c in calls),
                   reason='本机完整核心管线实际调用三阶段模型，已再次核验阶段与证据引用。')
    report = run / 'out/mobile-report.pdf'
    if report.read_bytes()[:5] != b'%PDF-':
        raise ValueError('completed core run has no valid PDF')
    directory = store.task_dir(task_id)
    attempt = directory / 'attempts' / run.name
    attempt.mkdir(parents=True, exist_ok=False)
    for name in ('bundle.json', 'ai-import.json'):
        if (directory / name).exists():
            shutil.copy2(directory / name, attempt / ('previous-' + name))
    target = attempt / 'report.pdf'
    shutil.copy2(report, target)
    shutil.copy2(run / 'out/bundle.json', directory / 'bundle.json')
    write_json(directory / 'ai-import.json', checked)
    counts = {'reads': len(bundle['dynamic']['reads']), 'flows': len(bundle['traffic']['flows']),
              'consent_events': len(bundle['dynamic']['consent_timeline']), 'findings': len(bundle['findings'])}
    relative = target.relative_to(directory).as_posix()
    capture_meta = verification.get('capture') or {'mode': 'root-emulator', 'capture_apk_sha256': app['apk_sha256']}
    capture_meta = {**capture_meta, 'state': 'done', 'source_run': str(run)}
    store.patch(task_id, mode='core_audit', state='partial' if verification.get('quality_gaps') else 'done', core_run={'state': 'done', 'source_run': str(run)}, counts=counts, policy_available=bundle['policy']['available'],
                capture=capture_meta, ai_state='live_validated', gaps=bundle.get('gaps', []),
                risk_assessment=bundle.get('risk_assessment'),
                bundle_sha256=hashlib.sha256((run / 'out/bundle.json').read_bytes()).hexdigest(),
                report_metadata={'state': 'done', 'path_rel': relative, 'ai_state': 'live_validated',
                    'note': '同一原始 APK 绑定的本地政策、静态、' + capture_meta['mode'] + ' 动态、三阶段 AI 的本轮报告',
                    'bundle_file_sha256': hashlib.sha256((directory / 'bundle.json').read_bytes()).hexdigest(),
                    'report_file_sha256': hashlib.sha256(target.read_bytes()).hexdigest()})
    for stage in ('dynamic', 'ai', 'report'):
        store.stage(task_id, stage, 'done', '完整核心管线真实运行，见 source_run 与验收记录')
    result = {'task_id': task_id, 'report_url': f'/api/reports/task-{task_id}/file',
              'evidence_url': f'/api/tasks/{task_id}/evidence', 'source_run': str(run)}
    write_json(attempt / 'core-run.json', result)
    return result
