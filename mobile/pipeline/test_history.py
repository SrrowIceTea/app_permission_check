"""Persisted-job recovery contracts, without device access."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase,main
from unittest.mock import patch
from mobile.pipeline.history import lookup,remember,catalog

class HistoryTests(TestCase):
    def test_finished_job_recovers_and_unsafe_id_is_rejected(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp);out=root/'123456abcdef';out.mkdir()
            job=SimpleNamespace(id=out.name,name='unit.apk',state='done',error=None,apk=out/'uploaded.apk',result={},out=out)
            registry=SimpleNamespace(workdir=root,runtime=None,_jobs={})
            remember(job)
            self.assertEqual(lookup(registry,job.id).state,'done')
            self.assertEqual(len(catalog(registry)),1)
            self.assertIsNone(lookup(registry,'../outside'))
    def test_live_other_process_is_not_mislabelled_as_restart_failure(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp);out=root/'123456abcdef';out.mkdir()
            job=SimpleNamespace(id=out.name,name='unit.apk',state='running',error=None,apk=out/'uploaded.apk',result={},out=out)
            registry=SimpleNamespace(workdir=root,runtime=None,_jobs={})
            remember(job)
            self.assertEqual(lookup(registry,job.id).state,'running')
            with patch('mobile.pipeline.history.creation_token',side_effect=OSError('gone')):
                self.assertEqual(lookup(registry,job.id).state,'failed')
            self.assertEqual(lookup(registry,job.id).state,'running')

if __name__=='__main__':main()
