"""Explicit, bounded publication of a review summary; never a filesystem browser."""
import json
import re
from pathlib import Path

from vehicle.pipeline.contracts import AuditError

TOP = {'schema_version', 'round_id', 'review_mode', 'signoff_status', 'cases',
       'counts', 'limits', 'bindings'}
CASE = {'id', 'family', 'package', 'session_ids', 'workflow_status', 'eligibility',
        'eligibility_reasons', 'reference_pairs', 'review_status', 'findings'}
COUNTS = {'scope', 'workflow_apps', 'independent_apps', 'required_independent_apps',
          'reference_pairs', 'required_reference_pairs'}
ID = re.compile(r'[A-Za-z0-9_.:@+\-]{1,200}')


def validate(data):
    """A closed public schema: bindings contain IDs/digests, never paths or logs."""
    def require(ok):
        if not ok:
            raise ValueError('public schema mismatch')

    def strings(rows):
        return isinstance(rows, list) and len(rows) <= 500 and all(
            isinstance(s, str) and len(s) <= 4000 for s in rows)

    require(isinstance(data, dict) and set(data) == TOP)
    require(type(data['schema_version']) is int and data['schema_version'] == 1 and isinstance(data['round_id'], str)
            and ID.fullmatch(data['round_id']))
    require(data['review_mode'] == 'subagent' and data['signoff_status'] in ('signed', 'pending'))
    counts = data['counts']
    require(isinstance(counts, dict) and set(counts) <= COUNTS)
    require(counts.get('scope') == 'this_new_round')
    for key, value in counts.items():
        require(key == 'scope' or type(value) is int and value >= 0)
    require(strings(data['limits']))
    bindings = data['bindings']
    require(isinstance(bindings, dict) and len(bindings) <= 100)
    for key, value in bindings.items():
        require(ID.fullmatch(key) and isinstance(value, str) and ID.fullmatch(value))
    require(isinstance(data['cases'], list) and len(data['cases']) <= 100)
    for case in data['cases']:
        require(isinstance(case, dict) and set(case) == CASE)
        for key in ('id', 'family', 'package', 'workflow_status', 'review_status'):
            require(isinstance(case[key], str) and len(case[key]) <= 300)
        require(strings(case['session_ids']) and all(ID.fullmatch(s) for s in case['session_ids']))
        require(case['eligibility'] in ('workflow_only', 'eligible', 'insufficient'))
        require(case['reference_pairs'] is None or type(case['reference_pairs']) is int
                and case['reference_pairs'] >= 0)
        require(strings(case['eligibility_reasons']) and strings(case['findings']))
    return data


def load_public_review(directory):
    if directory is None:
        raise AuditError('review_round_unavailable', '尚未发布本轮证据复核。',
                         '服务启动时用 --review-round 指定本轮公开摘要目录。')
    try:
        directory = Path(directory).resolve()
        target = directory / 'public-review.json'
        if target.resolve().parent != directory or target.stat().st_size > 1024 * 1024:
            raise ValueError('invalid publication')
        return validate(json.loads(target.read_text(encoding='utf-8')))
    except FileNotFoundError:
        raise AuditError('review_round_unavailable', '本轮公开复核摘要尚未发布。',
                         '等待本轮 public-review.json 生成；不会读取组织者材料或历史轮次。') from None
    except (OSError, ValueError, TypeError, KeyError):
        raise AuditError('review_round_invalid', '本轮公开复核摘要缺失或格式无效。',
                         '检查显式目录中的 public-review.json；不会回退到历史轮次。') from None
