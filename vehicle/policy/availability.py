"""When a policy snapshot counts as *usable text*. 仅用于授权测试。

``vehicle.policy.assessment.assess_policy`` distinguishes four outcomes:
``available``, ``agreement_only`` (user agreement, NOT a privacy policy),
``extraction_failed`` and ``not_supplied``. Only ``available`` with a verified
privacy-policy document and a successful extraction may support a disclosure
claim. Both the AI capability gate and the observation-condition model use this
one contract, so they cannot disagree about what "policy text available" means.

AGENTS.md M040: user agreements are deliberately kept out of the main policy
path and must never allow a clause to be judged ``met``.
"""
from __future__ import annotations

USABLE_STATUS = 'available'
PRIVACY_POLICY_KIND = 'app_policy'
EXTRACTION_OK = 'ok'


def policy_text_usable(policy):
    """Fail closed; a partially populated dict is never treated as usable."""
    if not isinstance(policy, dict):
        return False
    return (policy.get('status') == USABLE_STATUS
            and policy.get('document_kind') == PRIVACY_POLICY_KIND
            and policy.get('extraction_status') == EXTRACTION_OK
            and bool(policy.get('apk_sha256'))
            and bool(policy.get('source_sha256'))
            and policy.get('binding_verified') is not False)
