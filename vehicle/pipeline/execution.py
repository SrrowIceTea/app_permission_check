"""One owner for stage reporting and safe final commit. 仅用于授权测试。"""
import json
import subprocess
import sys
import time
from vehicle.pipeline.contracts import AuditError, ROOT, write_json


class Execution:
    def __init__(self, output):
        self.output = output
        self.stage = 'initializing'
        write_json(output / 'run-status.json', {'status': 'running'})

    def run(self, name, action):
        self.stage = name
        self.emit('running')
        result = action()
        self.emit('done')
        return result

    def emit(self, status, **extra):
        with (self.output / 'events.jsonl').open('a', encoding='utf-8') as handle:
            handle.write(json.dumps({'ts': time.time(), 'stage': self.stage,
                                     'status': status, **extra}, ensure_ascii=False) + '\n')

    def command(self, args):
        path = self.output / (args[0].stem + '.log')
        with path.open('w', encoding='utf-8') as log:
            try:
                result = subprocess.run([sys.executable, *map(str, args)], cwd=ROOT,
                    stdout=log, stderr=log, encoding='utf-8', timeout=180)
            except subprocess.TimeoutExpired as error:
                raise AuditError('stage_timeout', f'{args[0].stem} 阶段超时。',
                                 f'查看 {path.name}；保留本轮后重试。') from error
        if result.returncode:
            raise AuditError('stage_failed', f'{args[0].stem} 阶段失败。',
                             f'查看 {path.name}。', exit_code=result.returncode)

    def failed(self, error, input_snapshot=None):
        detail = (error.record() if isinstance(error, AuditError) else
                  {'code': 'unexpected_error', 'message': str(error),
                   'next_action': '查看阶段日志；保留失败轮次，修复后创建新会话。'})
        self.emit('failed', error=detail)
        result = {'status': 'failed', 'stage': self.stage, 'error': detail, 'partial_artifacts': True}
        if input_snapshot is not None:
            result['input_completeness'] = {**input_snapshot, 'complete': False,
                'missing': [*input_snapshot['missing'], {'input': self.stage, 'reason': detail['code']}]}
        write_json(self.output / 'run-status.json', result)
