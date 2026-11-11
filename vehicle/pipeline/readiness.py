"""Single capture/preflight readiness contract. 仅用于授权测试（自有设备与自有 APK）。

2026-11-11 P0: the capture entry accepted TLS_BYPASS_DISABLED when the bypass
was switched off, while preflight still demanded PINNING_ARMED. A legitimate G0
control run was therefore rejected by the audit. Sample bundles intentionally
contain no ssl_pinning_bypass.js, so they must not be asked for a TLS marker --
but that exception is declared here, in one place, instead of being an implicit
side effect of ``sample_mode`` in two different files.

Rules:
  * switching TLS off never removes egress / privacy / VHAL / sample readiness;
  * switching TLS off is not a hook failure, but must be positively evidenced by
    TLS_BYPASS_DISABLED plus a matching TLS_SWITCH{tls_bypass:false};
  * a legacy capture without TLS_SWITCH is not upgraded to "verified".
"""
TLS_ARMED = ('tls', 'PINNING_ARMED')
TLS_DISABLED = ('tls', 'TLS_BYPASS_DISABLED')
NO_TLS_SCRIPT_GAP = ('专用样本 bundle 不含 TLS 校验收宽脚本；本轮不产生 TLS 就绪事件，'
                     'tls_bypass 开关对该 bundle 不生效。')
LEGACY_SWITCH_GAP = '旧会话未记录 TLS_SWITCH，不能确认本轮校验收宽开关是否生效。'


def required_events(*, tls_bypass=True, scope='all', sample_mode=None,
                    privacy_required=False, extra=()):
    """The one set of (src, ev) pairs both entry points must agree on."""
    required = set()
    if sample_mode is None:
        required.add(('egress', 'ARMED'))
        # 关闭是合法对照，不是失败，但仍必须有"确实未武装"的正向证据。
        required.add(TLS_ARMED if tls_bypass else TLS_DISABLED)
    else:
        required.update(sample_mode.REQUIRED)
    if scope == 'all':
        required.add(('vhal', 'ARMED'))
    if privacy_required:
        required.add(('privacy', 'ARMED'))
    required.update(extra)
    return frozenset(required)


def tls_capable(sample_mode):
    """Dedicated sample bundles ship without ssl_pinning_bypass.js."""
    return sample_mode is None


def ready(rows, *, tls_bypass=True, scope='all', sample_mode=None,
          catalog_hash_value=None, extra=()):
    """Capture-side wait predicate; catalog binding stays part of readiness."""
    required = required_events(tls_bypass=tls_bypass, scope=scope,
                               sample_mode=sample_mode, privacy_required=True,
                               extra=extra)
    armed = {(r.get('src'), r.get('ev')) for r in rows}
    catalog_ok = any(r.get('src') == 'privacy' and r.get('ev') == 'ARMED'
                     and r.get('privacy_catalog_sha256') == catalog_hash_value
                     for r in rows)
    # 新采集必须留下 TLS_SWITCH 启动行；只有 armed/disabled 标记不足以证明开关生效。
    switch_present = any(r.get('src') == 'tls' and r.get('ev') == 'TLS_SWITCH' for r in rows)
    return bool(required <= armed and catalog_ok
                and (not tls_capable(sample_mode) or switch_present))


def switch_state(rows, session):
    """Return (declared_value, state) for TLS_SWITCH rows of this session."""
    values = [r.get('tls_bypass') for r in rows
              if isinstance(r, dict) and r.get('src') == 'tls'
              and r.get('ev') == 'TLS_SWITCH' and r.get('session_id') == session]
    if not values:
        return None, 'missing'
    if any(type(value) is not bool for value in values):
        return None, 'invalid'
    if len(set(values)) != 1:
        return None, 'conflict'
    return values[0], 'declared'


def check_switch(rows, *, tls_bypass, session, sample_mode=None, require_switch=False):
    """Return (error_code_or_None, diagnostics). Never mutates rows.

    ``require_switch`` is set for captures that explicitly declare the switch in
    verification.json: those must contain a TLS_SWITCH line, while a genuine
    legacy capture (no declaration on either side) only gets a named gap.
    """
    declared, state = switch_state(rows, session)
    armed = {(r.get('src'), r.get('ev')) for r in rows if isinstance(r, dict)}
    diagnostics = {'tls_bypass_expected': bool(tls_bypass),
                   'tls_switch_state': state, 'tls_switch_declared': declared,
                   'tls_capable': tls_capable(sample_mode),
                   'switch_declared_in_verification': bool(require_switch),
                   'gaps': []}
    if not tls_capable(sample_mode):
        # 专用 bundle 不含 TLS 脚本；仍不得残留"已武装/已禁用"标记，否则说明
        # 加载的脚本与声明的模式不符。
        diagnostics['gaps'].append(NO_TLS_SCRIPT_GAP)
        if not tls_bypass and TLS_ARMED in armed:
            return 'tls_armed_while_disabled', diagnostics
        if tls_bypass and TLS_DISABLED in armed:
            return 'tls_disabled_while_armed', diagnostics
        return None, diagnostics
    if state == 'missing':
        if require_switch:
            return 'tls_switch_missing', diagnostics
        diagnostics['gaps'].append(LEGACY_SWITCH_GAP)
    elif state in ('invalid', 'conflict'):
        return 'tls_switch_' + state, diagnostics
    elif declared != tls_bypass:
        return 'tls_switch_mismatch', diagnostics
    if tls_bypass and TLS_DISABLED in armed:
        return 'tls_disabled_while_armed', diagnostics
    if not tls_bypass and TLS_ARMED in armed:
        return 'tls_armed_while_disabled', diagnostics
    return None, diagnostics


def resolve_switch(verification, manifest):
    """Resolve the authoritative switch value; legacy captures default to armed.

    A new capture declares the same value in both files; disagreement or a
    non-dict switch declaration is a contract error, never an AttributeError.
    """
    if not isinstance(verification, dict) or not isinstance(manifest, dict):
        return None, 'tls_switch_declaration_mismatch'
    value = verification.get('tls_bypass', True)
    switches = manifest.get('capture_switches')
    if switches is not None and not isinstance(switches, dict):
        return None, 'tls_switch_declaration_mismatch'
    declared = switches.get('tls_bypass') if isinstance(switches, dict) else None
    if type(value) is not bool or (declared is not None
                                   and (type(declared) is not bool or declared != value)):
        return None, 'tls_switch_declaration_mismatch'
    return value, 'legacy_default' if 'tls_bypass' not in verification else 'declared'
