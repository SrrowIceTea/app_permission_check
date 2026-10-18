"""Retain observed local reverse-proxy target, never substitute an arbitrary host."""
from urllib.parse import urlsplit


def local_target(host_header, expected_port):
    try:
        url = urlsplit('http://' + str(host_header))
        if (url.hostname != '10.0.2.2' or url.port != int(expected_port) or
                url.username or url.password or url.path or url.query or url.fragment):
            return None
        return {'host': url.hostname, 'ip': url.hostname}
    except (ValueError, TypeError):
        return None
