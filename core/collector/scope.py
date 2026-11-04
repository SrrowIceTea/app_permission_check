"""Optional strict package retention for ordinary-app audit. 授权测试专用。

The legacy fixture/mobile policy stays unchanged. Strict mode never retains
unattributed bodies or upgrades a single allowlisted package into an identity.
"""
import json
import os
from collections import Counter

DISCARDED = Counter()


def persist(entry, whitelist, flow_log, session):
    if os.environ.get('VSCAN_STRICT_PACKAGE_SCOPE') != '1':
        return True
    reason = None
    if entry.get('attribution') == 'single_package_fallback':
        reason = 'single_package_fallback_forbidden'
    elif entry.get('attribution_ambiguous'):
        reason = 'ambiguous_identity'
    elif entry.get('package') not in whitelist:
        reason = 'outside_allowlist_or_unresolved'
    elif type(entry.get('uid')) is not int or entry['uid'] < 0:
        reason = 'uid_missing'
    if reason is None:
        return True
    DISCARDED[reason] += 1
    path = flow_log.with_name('scope-discarded.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    # Counts only: no other app's URL, body, identifiers or stack is retained.
    path.write_text(json.dumps({'session_id': session, 'counts': dict(DISCARDED),
        'scope': 'unattributed_discard_counts_only'}), encoding='utf-8')
    return False
