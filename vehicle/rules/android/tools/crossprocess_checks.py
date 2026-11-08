"""Verify actual kernel waiting locks and independent fixture identities."""


def waiting_lock(text, owner, waiter):
    if type(owner) is not int or type(waiter) is not int or owner <= 1 or waiter <= 1 or owner == waiter:
        raise ValueError('two distinct positive process identities required')
    rows = []
    for line in text.splitlines():
        fields = line.split()
        blocked = len(fields) > 1 and fields[1] == '->'
        if blocked:
            fields.pop(1)
        if len(fields) != 8 or fields[1:4] != ['POSIX', 'ADVISORY', 'WRITE'] or fields[6:] != ['0', 'EOF']:
            continue
        if not fields[4].isdigit():
            continue
        rows.append({'pid': int(fields[4]), 'blocked': blocked, 'inode': fields[5], 'line': line})
    for held in rows:
        for pending in rows:
            if (held['pid'] == owner and not held['blocked'] and pending['pid'] == waiter
                    and pending['blocked'] and held['inode'] == pending['inode']):
                return {'owner': held, 'waiter': pending}
    return None


def identity_pair(a, b, user):
    return (type(a.get('pid')) is int and type(b.get('pid')) is int and a['pid'] != b['pid']
            and a['pid'] > 1 and b['pid'] > 1 and type(a.get('uid')) is int
            and a['uid'] == b.get('uid') and a['uid'] // 100000 == user
            and a.get('user_id') == b.get('user_id') == user
            and a.get('database_path') == b.get('database_path')
            and a.get('boot_id') == b.get('boot_id') and bool(a.get('boot_id')))
