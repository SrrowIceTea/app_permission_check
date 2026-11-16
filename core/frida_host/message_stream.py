"""Persist legacy single messages and acknowledged vehicle batches. 授权测试专用。"""
import json
import sys
import threading
import time
from collections import Counter

TRANSPORT = 'vehicle_buffered_v1'
MAX_BATCH = 20


class MessageStream:
    def __init__(self, output, session, store, *, label='', serial=None):
        self.output, self.session, self.store = output, session, store
        self.collector = str(output.resolve())
        self.label, self.serial = label, serial
        self.ready = threading.Condition()
        self.failed = []
        self.counts = Counter()
        self.delivered = 0

    def _append(self, records):
        with self.output.open('a', encoding='utf-8') as handle:
            handle.writelines(json.dumps(row, ensure_ascii=False) + '\n' for row in records)

    def _failure(self, event, detail):
        row = {'ev': event, 'src': 'driver', 'session_id': self.session,
               'host_received_ts': int(time.time() * 1000), **detail}
        self.failed.append(event)
        try:
            self._append([row])
        except OSError as exc:  # noqa: BLE001  落盘失败不能盖掉脚本错误事件本身
            # 单独打一行：row 的 JSON 会被 [:600] 截断，长错误事件里挂在末尾的字段看不见。
            print(f'[frida_host] 失败事件落盘失败：{type(exc).__name__}: {exc}',
                  file=sys.stderr, flush=True)
        print(json.dumps(row, ensure_ascii=False)[:600], file=sys.stderr, flush=True)

    def _persist(self, message, received):
        kind = message.get('type')
        if kind == 'error':
            self._failure('SCRIPT_ERROR', {'message': message})
        if kind != 'send':
            return
        payload = message.get('payload')
        if not isinstance(payload, dict):
            return
        batched = payload.get('transport') == TRANSPORT
        if batched and 'lines' in payload:
            lines = payload['lines']
            if ('line' in payload or not isinstance(lines, list)
                    or not 1 <= len(lines) <= MAX_BATCH or not all(isinstance(line, str) for line in lines)):
                raise ValueError('invalid buffered transport packet')
        elif payload.get('line') and (not batched or isinstance(payload['line'], str)):
            lines = [payload['line']]
        elif batched:
            raise ValueError('missing buffered transport record')
        else:
            return
        records = [json.loads(line) for line in lines]
        for row in records:
            row.update(host_received_ts=received, session_id=self.session)
            if self.label:
                row['run_label'] = self.label
            if self.serial:
                row['device_serial'] = self.serial
        self._append(records)
        for row in records:
            self.store.append(self.session, self.collector, row)
        self.counts.update(row.get('ev', '?') for row in records)
        if batched:
            self.delivered += len(records)

    def on_message(self, message, _data):
        # Arrival time belongs to the callback boundary, before I/O or a lock wait.
        received = int(time.time() * 1000)
        with self.ready:
            try:
                self._persist(message, received)
            except Exception as error:
                self._failure('CAPTURE_ERROR', {'reason': 'message_persist_failed',
                                               'exception_type': type(error).__name__})
            finally:
                self.ready.notify_all()

    def acknowledge(self, stats, timeout=5):
        """The sender is closed. Wait for all accepted messages to reach disk."""
        with self.ready:
            sent = stats.get('delivered')
            if (type(sent) is not int or sent < 0 or stats.get('failed') != 0
                    or not self.ready.wait_for(lambda: self.delivered >= sent or self.failed, timeout)
                    or self.delivered != sent or self.failed):
                self._failure('CAPTURE_ERROR', {'reason': 'buffered_delivery_incomplete',
                                               'sent': sent, 'persisted': self.delivered})
                return False
        return True

    def flush_failed(self, error):
        with self.ready:
            self._failure('CAPTURE_ERROR', {'reason': 'buffered_flush_rpc_failed',
                                           'exception_type': type(error).__name__})
