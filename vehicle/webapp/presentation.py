"""API 投影层：只补字段，不改任何结论语义。

授权测试专用。派生值一律注明来源；算不出来就 None + 原因，不用默认值、平均值或前端推算。
本模块只读产物，不写回 output/vehicle-web/<任务>/。
"""
import hashlib
import json
from pathlib import Path

CONCLUDED = ('correlated', 'observed', 'candidate')
UNJUDGED = 'unjudged'
TERMINAL_STATUS = ('done', 'failed', 'skipped')
COUNT_NOTE = ('correlated/observed/candidate 取自 findings.jsonl 的 conclusion_level 计数；'
              'unjudged 指没有上述三档结论等级的条目（缺失或其他取值），由 findings_total 减去各档之和得出；'
              '本工具不产出 policy_violation，计数只描述证据强度，不代表安全或合规结论。')
TIMING_NOTE = '由 events.jsonl 的 ts（主机墙钟）两两相减得出；跨阶段间隙不计入任何阶段。'
_CACHE = {}


def _stamp(path):
    try:
        stat = path.stat()
        return stat.st_mtime_ns, stat.st_size
    except OSError:
        return None


def _json(path):
    stamp = _stamp(path)
    if stamp is None:
        return None
    key = ('json', str(path), stamp)
    if key not in _CACHE:
        try:
            _CACHE[key] = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            _CACHE[key] = None
    return _CACHE[key]


def _rows(path):
    stamp = _stamp(path)
    if stamp is None:
        return []
    key = ('rows', str(path), stamp)
    if key not in _CACHE:
        rows = []
        try:
            for line in path.read_text(encoding='utf-8').splitlines():
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        continue
        except OSError:
            rows = []
        _CACHE[key] = rows
    return _CACHE[key]


def _digest(path):
    stamp = _stamp(path)
    if stamp is None:
        raise OSError('unreadable')
    key = ('sha256', str(path), stamp)
    if key not in _CACHE:
        hasher = hashlib.sha256()
        with path.open('rb') as handle:
            while block := handle.read(1 << 20):
                hasher.update(block)
        _CACHE[key] = hasher.hexdigest()
    return _CACHE[key]


def _int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def count_bands(summary):
    """返回 (四档计数, 原始计数, 缺口说明)。四档键恒定存在，缺数据时为 None。"""
    data = summary if isinstance(summary, dict) else {}
    raw = data.get('findings_by_conclusion_level')
    present = isinstance(raw, dict)
    raw = dict(raw) if present else None
    gaps = {}
    if not present:
        gaps['findings_by_conclusion_level'] = '本轮没有 audit/summary.json 的分档计数（任务未完成或摘要缺失）。'
    bands = {}
    for level in CONCLUDED:
        value = _int(raw.get(level, 0)) if present else None
        if present and value is None:
            gaps['findings_by_conclusion_level.' + level] = '该档计数字段不是整数。'
        bands[level] = value
    total = _int(data.get('findings_total'))
    if present and total is not None:
        derived = total - sum(v for v in raw.values() if _int(v) is not None) + (_int(raw.get(UNJUDGED)) or 0)
        if derived < 0:
            bands[UNJUDGED] = None
            gaps['findings_by_conclusion_level.unjudged'] = (
                'findings_total 小于分档计数之和，摘要内部不自洽，不推算。')
        else:
            bands[UNJUDGED] = derived
    elif present:
        bands[UNJUDGED] = _int(raw.get(UNJUDGED))
        if bands[UNJUDGED] is None:
            gaps['findings_by_conclusion_level.unjudged'] = '缺少 findings_total，无法推算未判定条数。'
    else:
        bands[UNJUDGED] = None
    for key, value in (raw or {}).items():
        if key not in CONCLUDED and key != UNJUDGED:
            bands[key] = value
    return bands, raw, gaps


def stage_timings(rows, stages):
    """按 events.jsonl 的时间戳算每阶段区间；无法成立的区间留空并写原因。"""
    grouped = {}
    for row in rows:
        if isinstance(row, dict) and row.get('stage'):
            grouped.setdefault(row['stage'], []).append(row)
    timings = []
    for stage in stages:
        entries = grouped.get(stage.get('id')) or []
        item = {'stage': stage.get('id'), 'label': stage.get('label'), 'status': None,
                'started_at': None, 'ended_at': None, 'duration_ms': None,
                'unavailable_reason': None}
        if not entries:
            item['status'] = 'pending'
            item['unavailable_reason'] = 'events.jsonl 没有该阶段的事件，无法计算区间。'
        else:
            item['status'] = entries[-1].get('status')
            start, end = entries[0].get('ts'), entries[-1].get('ts')
            if item['status'] == 'skipped':
                item['unavailable_reason'] = '阶段被跳过，没有执行区间。'
            elif item['status'] not in TERMINAL_STATUS:
                item['unavailable_reason'] = ('阶段未结束（最后一条事件状态为 %s），没有结束边界。'
                                              % item['status'])
            elif len(entries) < 2 or not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
                item['unavailable_reason'] = '起止事件不足两条或缺少数值型时间戳，无法计算区间。'
            elif end < start:
                item['unavailable_reason'] = '结束事件早于开始事件，时间戳不自洽。'
            else:
                item['started_at'], item['ended_at'] = start, end
                item['duration_ms'] = int(round((end - start) * 1000))
        timings.append(item)
    return timings


def elapsed_ms(rows):
    stamps = [row.get('ts') for row in rows if isinstance(row, dict)]
    stamps = [ts for ts in stamps if isinstance(ts, (int, float))]
    if len(stamps) < 2 or max(stamps) < min(stamps):
        return None
    return int(round((max(stamps) - min(stamps)) * 1000))


def apk_identity(out, summary, result):
    """被测对象身份：package / apk_sha256 / apk_size，缺失写进 gaps。"""
    out = Path(out)
    gaps, apk = {}, out / 'uploaded.apk'
    try:
        size = apk.stat().st_size
    except OSError:
        size = None
        gaps['apk_size'] = '任务目录里没有 uploaded.apk，无法取得文件大小。'
    static = summary.get('static_analysis') if isinstance(summary, dict) else None
    sha, source = None, None
    if isinstance(static, dict) and isinstance(static.get('apk_sha256'), str) and static['apk_sha256']:
        sha = static['apk_sha256']
        source = 'audit/summary.json:static_analysis.apk_sha256（preflight 已与装机 APK 核对）'
    elif apk.is_file():
        try:
            sha, source = _digest(apk), 'uploaded.apk 的 SHA-256（服务端现场计算）'
        except OSError:
            gaps['apk_sha256'] = 'uploaded.apk 读取失败，无法计算 SHA-256。'
    else:
        gaps['apk_sha256'] = '既没有 audit/summary.json 的 APK 摘要，也没有 uploaded.apk 可计算。'
    package = result.get('package') if isinstance(result, dict) else None
    if not package and isinstance(summary, dict):
        package = summary.get('package')
    if not package:
        static_doc = _json(out / 'static/static.json')
        if isinstance(static_doc, dict) and isinstance(static_doc.get('apk'), dict):
            package = static_doc['apk'].get('package')
    if not package:
        gaps['package'] = '本任务没有 result.package、summary.package，也没有可读的 static.json apk.package。'
    return {'package': package, 'apk_sha256': sha, 'apk_size': size,
            'apk_sha256_source': source, 'gaps': gaps}


def decorate(snapshot, out, stages):
    """给任务快照补身份、结论计数与阶段耗时；原字段一个不动。"""
    out = Path(out)
    summary = _json(out / 'audit/summary.json')
    result = snapshot.get('result') if isinstance(snapshot.get('result'), dict) else {}
    identity = apk_identity(out, summary, result)
    bands, raw, gaps = count_bands(summary)
    total = _int(summary.get('findings_total')) if isinstance(summary, dict) else None
    if total is None:
        total = _int(result.get('findings_total'))
    events = _rows(out / 'events.jsonl')
    data = dict(snapshot)
    data.update({
        'package': identity['package'],
        'apk_sha256': identity['apk_sha256'],
        'apk_size': identity['apk_size'],
        'apk_sha256_source': identity['apk_sha256_source'],
        'findings_total': total,
        'findings_by_conclusion_level': bands,
        'findings_by_conclusion_level_raw': raw,
        'findings_by_conclusion_level_note': COUNT_NOTE,
        'stage_timings': stage_timings(events, stages),
        'stage_timings_elapsed_ms': elapsed_ms(events),
        'stage_timings_note': TIMING_NOTE,
        'field_gaps': {**identity['gaps'], **gaps},
    })
    return data


def project_summary(summary):
    """/summary 的对外投影：四档键恒定，其余字段逐字保留。"""
    if not isinstance(summary, dict):
        return summary
    bands, raw, gaps = count_bands(summary)
    data = dict(summary)
    data['findings_by_conclusion_level'] = bands
    data['findings_by_conclusion_level_raw'] = raw
    data['findings_by_conclusion_level_note'] = COUNT_NOTE
    if gaps:
        data['findings_by_conclusion_level_gaps'] = gaps
    return data


def _uid_basis(row):
    """内容指纹：只取稳定字段，任一字段缺失都以空值参与，不影响其余行。"""
    events = row.get('event_ids') if isinstance(row.get('event_ids'), list) else []
    locs = row.get('code_locs') if isinstance(row.get('code_locs'), list) else []
    ordered = sorted(json.dumps(item, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
                     for item in locs)
    return '|'.join((
        str(row.get('rule_id') or ''),
        str(row.get('conclusion_level') or ''),
        ','.join(sorted(str(item) for item in events)),
        ';'.join(ordered),
    ))


def finding_uids(rows):
    """稳定 finding 标识：同输入重跑不变；内容完全相同的行按出现顺序加序号，仍然稳定。"""
    bases = [hashlib.sha256(_uid_basis(row).encode('utf-8')).hexdigest()[:16] for row in rows]
    total = {}
    for base in bases:
        total[base] = total.get(base, 0) + 1
    seen, uids = {}, []
    for base in bases:
        if total[base] > 1:
            seen[base] = seen.get(base, 0) + 1
            uids.append('%s-%d' % (base, seen[base]))
        else:
            uids.append(base)
    return uids
