"""Prompt/gate alignment tests, no model requests and no synthetic device claims."""
import copy
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ai_review
from review_gates import validate_stage
from test_ai import BUNDLE
from test_ai_gates import STAGE2


class StoragePromptContractTests(unittest.TestCase):
    def bundle(self):
        result = copy.deepcopy(BUNDLE)
        result['dynamic']['storage_crypto'] = {'available': True,
            'observations': [{'evidence_id': 'SC1', 'event': 'CIPHER_INIT'}],
            'findings': [{'evidence_id': 'SCF1', 'kind': 'provider_default_mode_unresolved', 'evidence_refs': ['SC1']}]}
        return result

    def test_stage3_prompt_covers_nonlegal_technical_item_and_no_empty_legal_items(self):
        prompt = ai_review.build_stage3_user(self.bundle(), STAGE2)
        self.assertIn('"category":"technical_storage_crypto"', prompt)
        self.assertIn('"regulation_refs":[]', prompt)
        self.assertIn('"basis_refs":[]', prompt)
        self.assertIn('不要为凑类别创建空证据 item', prompt)
        self.assertIn('不要将 SC/SCF 引用添加到 C3.1 等法规 item', prompt)

    def test_actual_storage_only_item_satisfies_existing_unchanged_gate(self):
        output = {'stage': 'assessment', 'overall_risk': 'insufficient_evidence',
            'overall_risk_reason': 'Only technical API observation A1; personal-data relationship unknown.',
            'items': [{'assessment_id': 'A1', 'category': 'technical_storage_crypto',
                'category_title': 'Technical observation', 'conclusion': 'observed_but_inconclusive',
                'summary': 'Observed API configuration only, not a proof of persistence or personal-data leakage.',
                'evidence_refs': ['SCF1', 'SC1'], 'regulation_refs': [], 'basis_refs': [],
                'severity': 'low', 'confidence': 'medium', 'needs_human_review': True}],
            'recommendations': [], 'uncertainties': [], 'coverage_note': 'Finite technical observation.'}
        checked = validate_stage('stage3', output, self.bundle())
        self.assertTrue(checked['ok'], checked['problems'])
        output['items'][0]['category'] = 'C3.1'
        self.assertFalse(validate_stage('stage3', output, self.bundle())['ok'])


if __name__ == '__main__':
    unittest.main()
