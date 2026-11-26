"""APK-bound local policy evidence and business-necessity review. 授权测试专用。

No network, legal verdict or keyword-derived compliance verdict. Agreements are
kept separate. Exact character offsets refer to the exported normalized text.
"""
import re
from pathlib import Path
from core.policy.policy_extract import extract
from vehicle.pipeline.contracts import AuditError, digest, read_json, write_json

TERMS = {
    'INFO_VIN': ['车架号', '车辆识别', 'VIN', 'vehicle identification'],
    'PERF_VEHICLE_SPEED': ['车速', '行驶速度', 'vehicle speed'],
    'GEAR_SELECTION': ['挡位', '档位', 'gear'],
    'CURRENT_GEAR': ['挡位', '档位', 'gear'],
    'PERF_ODOMETER': ['里程', 'mileage', 'odometer'],
    'ENGINE_RPM': ['转速', 'engine speed', 'rpm'],
    'FUEL_LEVEL': ['油量', '燃油', 'fuel'],
    'EV_BATTERY_LEVEL': ['电量', '电池', 'battery'],
    'location': ['位置', '定位', 'location', 'coordinates'],
    'microphone': ['麦克风', '录音', 'microphone', 'audio recording'],
    'contacts': ['联系人', '通讯录', 'contacts'],
    'android_id': ['设备标识', 'Android ID', 'android_id', 'device identifier'],
}
RULE = 'VSC-REVIEW-DISCLOSURE'
SCHEMA_VERSION = 1
CLAUSE_BOUNDARY = re.compile(r'[^。！？!?\n；;]+')
NEGATION_SIGNALS = ('不收集', '不共享', '不向', '不会', '未经', '未收集', '拒绝')
BASIS_KEYS = ('function', 'precision', 'frequency', 'foreground_background',
              'recipients', 'retention', 'consent_scope')


def locate_clauses(text, available):
    """Sentence-level clause locations with verbatim char spans (location aid only).

    No subject/recipient/purpose verdict is inferred: every quote is an exact
    slice of the exported policy.txt and every clause stays human-review-only.
    """
    if not available:
        return [], []
    terms = sorted({t for group in TERMS.values() for t in group}, key=len, reverse=True)
    clauses, refs = [], []
    for match in CLAUSE_BOUNDARY.finditer(text):
        segment = match.group()
        stripped = segment.strip()
        if not stripped:
            continue
        lead = segment.find(stripped)
        start, end = match.start() + lead, match.start() + lead + len(stripped)
        hits = [t for t in terms if re.search(re.escape(t), stripped, re.IGNORECASE)]
        if not hits:
            continue
        clause_id = f'c{len(clauses) + 1}'
        quote = text[start:end]
        clauses.append({'clause_id': clause_id, 'start': start, 'end': end,
            'quote': quote, 'matched_terms': hits,
            'negation_signal': any(s in stripped for s in NEGATION_SIGNALS),
            'subject': None, 'recipients': [], 'purpose': None,
            'retention': None, 'consent_scope': None,
            'basis': 'keyword_sentence_span', 'needs_human_review': True})
        refs.append({'clause_id': clause_id, 'start': start, 'end': end, 'text': quote})
    return clauses, refs


def review_basis(business):
    """Seven review slots from manifest metadata; missing stays explicit None."""
    basis = {key: business.get(key) for key in BASIS_KEYS}
    basis['basis'] = 'manifest_business_context' if business else 'not_provided_in_manifest'
    basis['needs_human_review'] = True
    return basis


def assess_policy(path, package, apk_sha256, findings, output):
    if path is None:
        return {'status': 'not_supplied', 'schema_version': SCHEMA_VERSION,
                'reviews': [], 'clauses': [], 'clause_refs': [],
                'gaps': ['未提供与受测 APK 绑定的隐私政策；不能判断披露或必要性。']}
    path, output = Path(path).resolve(), Path(output)
    meta = read_json(path)
    if meta.get('package') != package or meta.get('apk_sha256') != apk_sha256:
        raise AuditError('policy_app_mismatch', '政策未绑定到本轮 APK/包名。',
                         '提供匹配版本的本地政策清单；不要套用另一应用或版本。')
    if meta.get('document_kind') not in ('app_policy', 'app_agreement'):
        raise AuditError('policy_kind_required', '必须明确区分隐私政策与用户协议。',
                         '在政策清单中指定 document_kind。')
    document = (path.parent / meta.get('file', '')).resolve()
    try:
        document.relative_to(path.parent)
    except ValueError as error:
        raise AuditError('policy_path_outside', '政策文件超出清单目录。', '将快照放在清单目录内。') from error
    if not document.is_file() or digest(document) != meta.get('sha256') or not meta.get('source'):
        raise AuditError('policy_snapshot_invalid', '政策快照缺失、摘要不符或来源为空。',
                         '核对快照文件、来源和 SHA-256。')
    extracted = extract(document.read_bytes(), content_type=meta.get('content_type', 'text/plain'),
                        source=meta['source'])
    output.mkdir(parents=True, exist_ok=False)
    (output / 'policy.txt').write_text(extracted['text'], encoding='utf-8')
    agreement = meta['document_kind'] == 'app_agreement'
    available = extracted['status'] == 'ok' and not agreement
    text, reviews = extracted['text'], []
    business = meta.get('business_context', {})
    clauses, clause_refs = locate_clauses(text, available)
    for index, finding in enumerate(findings):
        prop, snippets = finding.get('property'), []
        for term in TERMS.get(prop, []):
            hit = re.search(re.escape(term), text, re.IGNORECASE) if available else None
            if hit:
                start, end = max(0, hit.start() - 60), min(len(text), hit.end() + 80)
                snippets.append({'start': start, 'end': end, 'text': text[start:end], 'term': term})
        reviews.append({'finding_id': f'finding-{index}', 'rule_id': RULE,
            'property': prop, 'disclosure_signal': ('keyword_reference' if snippets else
                'no_keyword_reference' if available else 'not_evaluable'),
            'policy_refs': snippets, 'business_purpose': business.get('purpose'),
            'app_category': business.get('app_category', 'unknown'),
            'necessity': 'human_review_required', 'needs_human_review': True,
            'review_basis': review_basis(business),
            'basis_refs': [{'kind': 'project_policy', 'path': 'vehicle/policy/REVIEW_POLICY.md', 'clause': 'P1'}]})
    result = {'status': 'available' if available else 'agreement_only' if agreement else 'extraction_failed',
        'schema_version': SCHEMA_VERSION, 'clauses': clauses, 'clause_refs': clause_refs,
        'package': package, 'apk_sha256': apk_sha256, 'document_kind': meta['document_kind'],
        'source': meta['source'], 'source_sha256': digest(document),
        'text_sha256': digest(output / 'policy.txt'), 'extraction_status': extracted['status'],
        'applicability': meta.get('applicability', 'version_correspondence_unverified'),
        'reviews': reviews, 'gaps': ['关键词命中不证明披露充分；未命中不证明政策未写。',
            '业务描述由清单提供；必要性与同意范围需人工复核。']}
    write_json(output / 'assessment.json', result)
    return result
