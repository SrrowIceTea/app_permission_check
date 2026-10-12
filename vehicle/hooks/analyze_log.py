#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
# V-Scanner Phase 3 — JSONL 分析器。纯分析/报告，不含任何钩子逻辑。
# 输入是 run.py 在主机侧落下的 JSONL（见 README：hook 应用进程时，SELinux 禁止
# untrusted_app 写 /data/local/tmp，所以日志由主机持有，不再 adb pull）。
# 用法:
#   python analyze_log.py logs/hook_vhal.jsonl [--src recon|vhal|tls]
import collections
import json
import sys

PATH = 'vscan.log'
SRC_FILTER = None
i = 1
while i < len(sys.argv):
    a = sys.argv[i]
    if a == '--src':
        SRC_FILTER = sys.argv[i + 1]
        i += 2
    else:
        PATH = a
        i += 1

bad = 0
rows = []
with open(PATH, encoding='utf-8', errors='replace') as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            bad += 1

print('lines=%d bad=%d' % (len(rows), bad))
by_src = collections.Counter(r.get('src') for r in rows)
print('per src:', dict(by_src))

for src in sorted(by_src):
    if SRC_FILTER and src != SRC_FILTER:
        continue
    rs = [r for r in rows if r.get('src') == src]
    ev = collections.Counter(r.get('ev') for r in rs)
    print('== src=%s events=%s' % (src, dict(ev)))
    starts = [r for r in rs if r.get('ev') == 'START']
    armed = [r for r in rs if r.get('ev') in ('ARMED', 'PINNING_ARMED')]
    errs = [r for r in rs if r.get('ev') == 'ERROR']
    if not starts:
        print('  [判定] 无 START：脚本从未开始记录（未运行，或 vlog 写入失败）')
    elif errs:
        print('  [判定] 运行中出现 %d 个 ERROR（见下）—— 有钩子未装载成功' % len(errs))
    elif not armed:
        print('  [判定] START 后无 ARMED/PINNING_ARMED：钩子未装载（介于崩溃与无数据之间）')
    else:
        print('  [判定] 钩子已装载（ARMED）。以下是事件内容：')
    reads = [r for r in rs if r.get('ev') == 'VHAL_READ']
    if reads:
        print('  VHAL_READ 共 %d 条:' % len(reads))
        bykey = collections.Counter((r.get('pkg'), r.get('prop_name'), r.get('outcome')) for r in reads)
        for k, c in sorted(bykey.items()):
            print('    pkg=%-28s prop=%-18s outcome=%-11s x%d' % (k[0], k[1], k[2], c))
        sample = reads[0]
        print('  示例 ts=%s api=%s value=%s' % (sample.get('ts'), sample.get('api'), str(sample.get('value'))[:100]))
        st = sample.get('stack') or ''
        print('  示例栈(头200字符): ' + st.replace('\n', ' | ')[:200])
    elif armed:
        print('  （无 VHAL_READ：白名单内无读取发生 —— 这是“无数据”，不是“崩溃”，见 ARMED 判定）')
    for r in errs[:5]:
        print('  ERROR: where=%s msg=%s' % (r.get('where'), str(r.get('msg'))[:200]))
    for r in rs:
        if r.get('ev') in ('GET_PROP_LIST', 'GET_PROP_TEST', 'GET_FLOAT_TEST', 'PROP_CONSTANTS',
                           'CPS_METHODS', 'CPS_ABSENT', 'NOT_TARGET', 'NOT_PRESENT', 'SKIP_CALLER',
                           'BRIDGE_FAIL', 'PINNING_BYPASS'):
            print('  ' + json.dumps(r, ensure_ascii=False)[:400])
