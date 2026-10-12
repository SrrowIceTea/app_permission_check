"""最终PDF与静态看板的展示验收；只读取真实交付数据，不连接外网。"""
import html
import json
import re
import subprocess
from pathlib import Path

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
CHROME = Path('C:/Program Files/Google/Chrome/Application/chrome.exe')

PROBE = r'''
<script>
(() => {
  const rows = () => document.querySelectorAll('#findings-table tr').length - 1;
  const initial = rows();
  const badges = [...document.querySelectorAll('.loc-line .badge')];
  const gaps = document.querySelectorAll('.gap-line').length;
  const root = document.documentElement;
  root.dataset.theme = 'light';
  const light = getComputedStyle(document.body).backgroundColor;
  document.querySelector('#theme-toggle').click();
  const dark = getComputedStyle(document.body).backgroundColor;
  const texture = getComputedStyle(document.querySelector('.badge.s-warning')).backgroundImage;
  document.querySelector('#filter-row button').click();
  const filtered = rows();
  document.querySelector('#filter-row button').click();
  const results = {
    row_count: initial === window.VSCAN_DATA.findings.length,
    event_badges: badges.length === 38 && badges.every(n => n.textContent.includes('dex 已核对')),
    native_gaps_visible: gaps >= 2,
    theme_changes: light !== dark,
    filter_works: filtered === initial - 5 && rows() === initial,
    coverage_visible: document.body.textContent.includes('已启用读取规则覆盖属性数：8'),
    texture_visible: texture !== 'none'
  };
  if (location.hash === '#light') document.querySelector('#theme-toggle').click();
  const out = document.createElement('pre');
  out.id = 'vscan-qa-result'; out.textContent = JSON.stringify(results);
  out.style.display = 'none'; document.body.appendChild(out);
})();
</script>
'''


def main():
    out = Path((ROOT / 'output/latest-delivery.txt').read_text(encoding='utf-8'))
    qa = out / 'presentation-qa'; qa.mkdir(exist_ok=True)
    reader = PdfReader(out / 'audit-report.pdf')
    text = '\n'.join(page.extract_text() for page in reader.pages)
    pdf = {'pages': len(reader.pages), 'images': sum(len(page.images) for page in reader.pages),
           'has_payload_section': '敏感载荷明文证据截图' in text,
           'has_location_gap': '定位缺口' in text,
           'page_numbers': all('Page ' + str(i) in page.extract_text() for i, page in enumerate(reader.pages, 1)),
           'no_replacement_character': '\ufffd' not in text}
    assert all(pdf[k] for k in ('has_payload_section', 'has_location_gap', 'page_numbers', 'no_replacement_character'))
    assert pdf['images'] >= 4
    probe = qa / 'probe.html'
    probe.write_text((out / 'dashboard.html').read_text(encoding='utf-8').replace('</body>', PROBE + '</body>'), encoding='utf-8')
    runs = {}
    for theme in ('light', 'dark'):
        process = subprocess.run([str(CHROME), '--headless=new', '--disable-gpu', '--no-first-run',
            '--no-default-browser-check', '--disable-background-networking', '--disable-extensions',
            '--user-data-dir=' + str(qa / ('profile-' + theme)), '--window-size=1440,1100',
            '--screenshot=' + str(qa / (theme + '.png')), '--dump-dom', '--virtual-time-budget=1500',
            probe.as_uri() + '#' + theme], capture_output=True, encoding='utf-8', errors='replace', timeout=45)
        (qa / (theme + '.stderr.log')).write_text(process.stderr, encoding='utf-8')
        match = re.search(r'<pre id="vscan-qa-result"[^>]*>(.*?)</pre>', process.stdout, re.S)
        if not match:
            raise RuntimeError('看板脚本未完成，检查Chrome日志')
        runs[theme] = json.loads(html.unescape(match[1]))
    report = dict(pdf=pdf, dashboard=runs, passed=all(all(v.values()) for v in runs.values()))
    (qa / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report), flush=True)
    assert report['passed']


if __name__ == '__main__':
    main()
