"""Formal pipeline adapter contracts; mocked artifacts are not runtime evidence."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase,main
from unittest.mock import Mock,patch
from mobile.pipeline.formal_runner import run,wait_job
from mobile.workbench.store import write_json

class FormalTests(TestCase):
    def test_failed_worker_is_not_treated_as_complete(self):
        runtime=Mock();runtime.job.return_value={'state':'failed','error':'real AI gate rejected'}
        with self.assertRaisesRegex(RuntimeError,'AI gate rejected'):
            wait_job(runtime,'abc',lambda _:None)

    def execute(self,passed):
        with TemporaryDirectory() as tmp:
            root=Path(tmp);cache=root/'cache';cache.mkdir()
            task={'apk':{'package':'com.absinthe.libchecker'},'stages':{'decompile':{'state':'partial'}},'risk_assessment':{}}
            runtime=Mock();runtime.upload.return_value={'task_id':'abc','job_id':'static'}
            runtime.operate.return_value={'job_id':'audit'}
            runtime.store.get.return_value=task;runtime.store.cache_dir.return_value=cache
            runtime.store.task_dir.return_value=root/'task'
            write_json(cache/'workbench-static.json',{'available':True,'findings':[]})
            core=root/'task/attempts/audit/core-audit';target=core/'out';target.mkdir(parents=True)
            write_json(core/'verification.json',{'passed':passed,'task_id':'abc','stages':{'ai':{'request_count':3}}})
            write_json(target/'bundle.json',{'counts':{}});(target/'mobile-report.pdf').write_bytes(b'%PDF-unit-only')
            out=root/'pipeline';out.mkdir()
            job=SimpleNamespace(id='123456abcdef',state='queued',error=None,apk=root/'input.apk',
                name='test.apk',result={},events=out/'events.jsonl',out=out,seconds=5)
            finish=Mock()
            with patch('mobile.pipeline.formal_runner.audit_inputs.configuration',return_value={'mode':'nonroot-gadget','serial':'emulator-5560'}),patch('mobile.pipeline.formal_runner.wait_job'),patch('mobile.ai.review_gates.load_checked_stages',return_value=({f'stage{n}':{} for n in (1,2,3)},{})):
                run(job,runtime,finish)
            state=finish.call_args.args[1]
            published=(out/'out/mobile-report.pdf').exists()
            return state,published,job.result

    def test_existing_pdf_does_not_override_failed_formal_gates(self):
        state,published,_=self.execute(False)
        self.assertEqual(state,'failed');self.assertFalse(published)

    def test_checked_core_exports_original_task_result(self):
        state,published,result=self.execute(True)
        self.assertEqual(state,'done');self.assertTrue(published)
        self.assertEqual(result['task_id'],'abc')

if __name__=='__main__':main()
