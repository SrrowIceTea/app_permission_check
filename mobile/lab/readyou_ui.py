"""Actual observed Read You subscription controls, only a local public test RSS. 仅用于授权测试。"""
import re
import time
from mobile.lab.root_runtime import save


def tap(android, view, *, label=None, cls=None):
    nodes = [n for n in view.iter('node') if n.get('package') == 'me.ash.reader'
             and n.get('enabled') == 'true' and
             ((label is not None and label in (n.get('text'), n.get('content-desc')))
              or (cls is not None and n.get('class') == cls))]
    if len(nodes) != 1:
        raise RuntimeError('expected one observed Read You control: ' + str(label or cls))
    x1, y1, x2, y2 = map(int, re.findall(r'\d+', nodes[0].get('bounds', '')))
    android.shell('input', 'tap', (x1 + x2) // 2, (y1 + y2) // 2)


def subscribe(android, package, traffic, out):
    if package != 'me.ash.reader' or not getattr(traffic, 'feed', False):
        raise ValueError('local RSS scenario must use the original Read You package and active local endpoint')
    url = f'http://10.0.2.2:{traffic.port}/vscanner-public-feed.xml'
    tap(android, android.screen('rss-before-subscribe'), label='Subscribe')
    time.sleep(.5)
    view = android.screen('rss-url-form')
    tap(android, view, cls='android.widget.EditText')
    android.shell('input', 'text', url)
    android.shell('input', 'keyevent', '4')
    tap(android, android.screen('rss-url-entered'), label='Search')
    time.sleep(2)
    view = android.screen('rss-search-result')
    # Actual v0.16.2 UI; inspect and preserve if a newer build differs instead of guessing.
    labels = {n.get('text') or n.get('content-desc') for n in view.iter('node')}
    if 'Follow' in labels:
        tap(android, view, label='Follow')
    elif 'Subscribe' in labels:
        tap(android, view, label='Subscribe')
    time.sleep(2)
    android.screen('rss-subscription-end')
    proof = {'scenario': 'readyou', 'url': url, 'scope': 'actual visible UI subscription to public synthetic local RSS; server receipts and packet/egress evidence verified separately',
             'root_or_private_file_read': False}
    save(out / 'rss-trigger-verification.json', proof)
    return [proof]
