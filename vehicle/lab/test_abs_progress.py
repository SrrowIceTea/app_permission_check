"""Reject cross-session, wrong-owner and out-of-window media read candidates."""
import unittest
import json
import re
import tempfile
from pathlib import Path
from unittest.mock import patch
from vehicle.lab.abs_progress_run import link_positions, within_period
from vehicle.privacy.abs_contract import PACKAGE
from vehicle.privacy.catalog import catalog_hash
from vehicle.pipeline.contracts import ROOT
from vehicle.lab.abs_backend import stage
from vehicle.lab.abs_image import MANIFEST_SHA256
from vehicle.lab.companion_verify import verify_handoff


class PositionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.request={'body':{'currentTime':12.5}}
        self.write={'src':'abs_native_send','evt_id':4,'pid':321,'device_start_ms':50000}
        self.read={'src':'abs_progress','ev':'ABS_POSITION','session_id':'one','pkg':PACKAGE,
            'uid':1010252,'user_id':10,'pid':321,'api':'yc.d.S()J',
            'position_ms':12500,'ts':49000,'evt_id':3,'device_serial':'emulator-5554'}
        for key in ('session_id','pkg','uid','user_id','device_serial'):
            self.write[key]=self.read[key]
        self.link={'status':'uid_verified','write_refs':[{'evt_id':4}]}

    def candidate(self, read=None, link=None):
        return link_positions([self.request],[self.write, read or self.read],
                              [link or self.link],'one',1010252)[0]

    def test_observed_value_requires_verified_native_write(self):
        self.assertEqual(self.candidate()['status'],'read_write_candidate')
        bad={'status':'ownership_unresolved','write_refs':[]}
        self.assertEqual(self.candidate(link=bad)['status'],'read_write_gap')

    def test_wrong_identity_or_source_cannot_supply_value(self):
        for key,value in [('session_id','other'),('pkg','control.app'),('uid',1010253),
                          ('user_id',0),('pid',322),('api','madeUp()J'),('src','privacy'),
                          ('device_serial','other-device')]:
            with self.subTest(key=key):
                read={**self.read,key:value}
                self.assertEqual(self.candidate(read)['position_refs'],[])

    def test_value_and_time_bounds_are_not_relaxed(self):
        for patch in [{'ts':50001},{'ts':19999},{'position_ms':14501},
                      {'position_ms':True},{'position_ms':12500.0},{'position_ms':-1}]:
            with self.subTest(patch=patch):
                self.assertEqual(self.candidate({**self.read,**patch})['status'],'read_write_gap')

    def test_multiple_requests_are_not_silently_truncated(self):
        with self.assertRaises(ValueError):
            link_positions([self.request],[],[],'one',1010252)

    def test_post_background_pause_is_outside_device_period(self):
        step={'start_device_ms':1000,'end_device_ms':10000,'post_pause_device_ms':12000,
              'host_end_ms':11000}
        self.assertTrue(within_period({'device_ts_ms':9999},step))
        self.assertFalse(within_period({'device_ts_ms':10001},step))

    def test_generated_hook_uses_current_catalog(self):
        text=(ROOT/'vehicle/hooks/privacy_targets.generated.js').read_text(encoding='utf-8')
        meta=json.loads(re.search(r'export const META = (.*);',text)[1])
        self.assertEqual(meta['sha256'],catalog_hash())


class HandoffGuards(unittest.TestCase):
    def test_untrusted_backend_manifest_stops_before_staging(self):
        with tempfile.TemporaryDirectory() as tmp, patch('vehicle.lab.abs_backend.Device') as mocked:
            folder=Path(tmp)
            (folder/'abs-image.json').write_text(json.dumps({
                'image':'ghcr.io/advplyr/audiobookshelf:2.37.2',
                'manifest_sha256':MANIFEST_SHA256,'manifest':{}}),encoding='utf-8')
            (folder/'abs-manifest.json').write_text('{}',encoding='utf-8')
            mocked.return_value.call.side_effect=['1','35','0']
            with self.assertRaisesRegex(ValueError,'unreviewed backend'):
                stage(folder,'owned-test')
            self.assertEqual(mocked.return_value.call.call_count,3)

    def test_handoff_rejects_traversal_and_missing_files(self):
        for name in ('../outside','C:/outside','missing-file'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                folder=Path(tmp)
                (folder/'evidence-index.json').write_text(json.dumps({
                    'files':[{'path':name,'sha256':'0'*64}]}),encoding='utf-8')
                with self.assertRaises(ValueError): verify_handoff(folder)


if __name__=='__main__': unittest.main()
