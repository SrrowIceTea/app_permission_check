"""只读 join 规则库标题 + 展示层中文映射；绝不改写 rules.db。

同一 rule_id 在库内有 4 个 android_version 行（13/14/15/16）。取值按本轮 android_version 优先；
取不到唯一标题时返回 None 并写明原因，不用任何语言版本"翻译"或兜底标题。
中文标题只来自同目录的 rule_titles.zh.json（人工映射），不改库、不机器翻译。
"""
import json
import re
import sqlite3
from pathlib import Path

DEFAULT_VERSION = '15'
ZH = Path(__file__).with_name('rule_titles.zh.json')
CJK = re.compile(r'[\u4e00-\u9fff]')
_CACHE = {}


def _stamp(path):
    try:
        stat = Path(path).stat()
        return stat.st_mtime_ns, stat.st_size
    except OSError:
        return None


def _connect(path):
    # mode=ro：哪怕路径写错也不会创建空库，避免"看起来查到了 0 条"。
    uri = Path(path).resolve().as_uri() + '?mode=ro'
    return sqlite3.connect(uri, uri=True, timeout=5)


def _rows(path):
    connection = _connect(path)
    try:
        return connection.execute(
            'select rule_id, android_version, title from risk_rules').fetchall()
    finally:
        connection.close()


def _zh(path):
    stamp = _stamp(path)
    if stamp is None:
        return {}
    key = ('zh', str(path), stamp)
    if key not in _CACHE:
        try:
            data = json.loads(Path(path).read_text(encoding='utf-8'))
        except (OSError, ValueError):
            data = {}
        _CACHE[key] = {k: v for k, v in data.items()
                       if isinstance(k, str) and isinstance(v, str) and v.strip()} \
            if isinstance(data, dict) else {}
    return _CACHE[key]


def resolve(path, version=None, zh_path=None):
    """返回 ({rule_id: {title, locale, source}}, {rule_id: 原因}, 依据说明)。"""
    path = Path(path) if path else None
    if path is None or not path.is_file():
        return {}, {}, '规则库不存在，无法 join 标题。'
    try:
        rows = _rows(path)
    except sqlite3.Error as error:
        return {}, {}, '规则库不可读（%s），无法 join 标题。' % type(error).__name__
    version = str(version or DEFAULT_VERSION)
    grouped = {}
    for rule_id, android_version, title in rows:
        grouped.setdefault(rule_id, {})[str(android_version)] = title
    zh = _zh(zh_path or ZH)
    basis = 'rules.db risk_rules（只读，按 android_version=%s 取值）' % version
    resolved, reasons = {}, {}
    for rule_id, by_version in grouped.items():
        if version in by_version:
            english = by_version[version]
        else:
            distinct = {value for value in by_version.values() if value}
            if len(distinct) != 1:
                reasons[rule_id] = ('规则库没有 android_version=%s 行，且各版本标题不一致，无法确定。'
                                    % version)
                continue
            english = distinct.pop()
            reasons[rule_id] = '规则库没有 android_version=%s 行；各版本标题一致，取其唯一标题。' % version
        if rule_id in zh:
            resolved[rule_id] = {'title': zh[rule_id], 'locale': 'zh',
                                 'source': 'rule_titles.zh.json 人工映射'}
        elif english:
            resolved[rule_id] = {'title': english,
                                 'locale': 'zh' if CJK.search(english) else 'en',
                                 'source': basis}
        else:
            reasons[rule_id] = '规则库里该 rule_id 的标题为空，无法展示。'
    return resolved, reasons, basis
