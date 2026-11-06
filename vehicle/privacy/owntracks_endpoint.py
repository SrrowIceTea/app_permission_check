"""Explicit owned HTTP receiver addresses. 仅用于授权测试。Historical default stays unchanged."""
import ipaddress


def allowed_host(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        return False
    return str(address) == '198.18.0.1' or any(address in ipaddress.IPv4Network(net)
        for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
