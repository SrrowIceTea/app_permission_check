"""离线前端浏览器回归：真实证据、组合筛选、展开、安全与响应式。"""
import html
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/frontend-review'
CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe'
PROBE = r'''
<script>
(() => {
 const U = window.VSCAN_UI, data = window.VSCAN_DATA;
 const rows = () => document.querySelectorAll('table.findings tr').length - 1;
 const search = document.getElementById('finding-search');
 const type = document.getElementById('finding-type');
 const reset = () => document.getElementById('reset-filters').click();
 const query = (v) => { search.value = v; search.dispatchEvent(new Event('input')); };
 const baseline = JSON.stringify(data);
 const checks = {};
 checks.real_rows = rows() === data.findings.length;
 checks.event_badges = document.querySelectorAll('.loc-line .badge').length === 38;
 checks.native_gaps = document.querySelectorAll('.gap-line').length === 2;
 checks.rule_sources = document.querySelectorAll('.evidence-details').length === data.findings.length;
 const metric = document.getElementById('kpi-row').textContent;
 query('vsc-e003'); checks.rule_search = rows() === 1;
 query('OkHttpSender.kt'); checks.code_search = rows() > 0 && rows() < data.findings.length;
 type.value = 'over_permission'; type.dispatchEvent(new Event('change'));
 checks.combined_empty = !!document.querySelector('#findings-table .empty-note');
 reset(); type.value = 'data_egress'; type.dispatchEvent(new Event('change'));
 checks.type_search = rows() === 5;
 document.querySelector('[data-level=correlated]').click();
 checks.level_filter = !!document.querySelector('#findings-table .empty-note') && document.activeElement.dataset.level === 'correlated';
 checks.stats_stable = document.getElementById('kpi-row').textContent === metric;
 reset(); checks.reset = rows() === 16 && search.value === '' && type.value === '';
 document.querySelectorAll('#filter-row button').forEach(b => b.click());
 checks.all_disabled = !!document.querySelector('#findings-table .empty-note') && document.querySelectorAll('.dist-seg.ghost').length === 3;
 reset();
 const details = document.querySelector('.location-details'); details.open = true;
 checks.disclosure = details.querySelector('.loc-line').getBoundingClientRect().height > 0; details.open = false;
 const light = getComputedStyle(document.body).backgroundColor;
 document.getElementById('theme-toggle').click();
 checks.theme = light !== getComputedStyle(document.body).backgroundColor;
 checks.texture = getComputedStyle(document.querySelector('.dist-seg.s-critical')).backgroundImage !== 'none';
 window.dispatchEvent(new Event('beforeprint'));
 checks.print_expands = !document.querySelector('details:not([open])');
 window.dispatchEvent(new Event('afterprint'));
 checks.print_restores = !document.querySelector('.location-details').open && document.documentElement.dataset.theme === 'dark';
 const old = data.findings[0].note;
 data.findings[0].note = '<img src=x onerror=alert(1)>';
 U.renderAll(); checks.safe_text = !document.querySelector('#findings-table img') && document.getElementById('findings-table').textContent.includes('<img src=x');
 data.findings[0].note = old; U.renderAll();
 const saved = data.findings; data.findings = []; U.renderAll();
 checks.empty_dataset = document.getElementById('findings-table').textContent.includes('本轮没有结论');
 data.findings = saved; U.renderAll();
 checks.immutable_evidence = JSON.stringify(data) === baseline;
 checks.no_page_overflow = document.documentElement.scrollWidth <= innerWidth;
 checks.nav_targets = [...document.querySelectorAll('nav a')].every(a => document.querySelector(a.getAttribute('href')));
 document.documentElement.dataset.theme = location.hash === '#dark' ? 'dark' : 'light';
 document.getElementById('theme-toggle').textContent = location.hash === '#dark' ? '浅色' : '深色';
 document.activeElement.blur(); scrollTo(0, 0);
 const out = document.createElement('pre'); out.id = 'frontend-qa'; out.hidden = true;
 out.textContent = JSON.stringify(checks); document.body.appendChild(out);
})();
</script>
'''


def main():
    page = (OUT / 'dashboard.html').read_text(encoding='utf-8')
    probe = OUT / 'probe.html'
    probe.write_text(page.replace('</body>', PROBE + '</body>'), encoding='utf-8')
    report = {}
    for mode, size in [('light', '1440,1080'), ('dark', '1440,1080'), ('mobile', '390,844')]:
        result = subprocess.run([CHROME, '--headless=new', '--disable-gpu', '--no-first-run',
            '--no-default-browser-check', '--disable-background-networking', '--disable-extensions',
            '--user-data-dir=' + str(OUT / ('chrome-' + mode)), '--window-size=' + size,
            '--force-device-scale-factor=1', '--hide-scrollbars', '--dump-dom',
            '--screenshot=' + str(OUT / (mode + '.png')), '--virtual-time-budget=1800',
            probe.as_uri() + '#' + mode], capture_output=True, encoding='utf-8', errors='replace', timeout=45)
        (OUT / (mode + '.stderr.log')).write_text(result.stderr, encoding='utf-8')
        match = re.search(r'<pre id="frontend-qa"[^>]*>(.*?)</pre>', result.stdout, re.S)
        if not match:
            raise RuntimeError('Browser probe did not finish: ' + mode)
        report[mode] = json.loads(html.unescape(match[1]))
    report['passed'] = all(all(values.values()) for values in report.values())
    (OUT / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report), flush=True)
    assert report['passed']


if __name__ == '__main__':
    main()
