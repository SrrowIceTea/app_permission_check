"""Android app/user identity helpers. Authorized auditing only."""


def uid_of(record):
    value = record.get('uid')
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def user_of(record):
    uid = uid_of(record)
    if uid is not None:
        return uid // 100000
    value = record.get('user_id')
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def compatible(left, right):
    """Reject conflicting known UID/user/device identity; unknown is not verified."""
    for extract in (uid_of, user_of):
        a, b = extract(left), extract(right)
        if a is not None and b is not None and a != b:
            return False
    for key in ('device_serial', 'device_fingerprint'):
        if left.get(key) and right.get(key) and left[key] != right[key]:
            return False
    return True


def identity_scope(read, flow):
    return ('uid_verified' if uid_of(read) is not None and uid_of(flow) is not None
            else 'user_verified' if user_of(read) is not None and user_of(flow) is not None
            else 'legacy_package_session_only')
