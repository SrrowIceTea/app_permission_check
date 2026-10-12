"""设置 frida-compile 包内白名单占位符，保持 bundle UTF-8 字节长度头正确。"""
import json

MARKER = '__VSCAN_SESSION_PACKAGES__'


def configure(body, packages):
    replacement = json.dumps(json.dumps(packages))[1:-1]
    if body.startswith('📦\n'):
        header, rest = body.split('\n✄\n', 1)
        modules = rest.split('\n✄\n')
        entries = header.splitlines()[1:]
        if len(modules) != len(entries):
            raise ValueError('不支持的 Frida bundle 模块结构')
        new_entries, new_modules = [], []
        for entry, module in zip(entries, modules):
            size, name = entry.split(' ', 1)
            if len(module.encode('utf-8')) != int(size):
                raise ValueError('Frida bundle 长度校验失败')
            changed = module.replace(MARKER, replacement)
            new_entries.append(f'{len(changed.encode("utf-8"))} {name}')
            new_modules.append(changed)
        return '📦\n' + '\n'.join(new_entries) + '\n✄\n' + '\n✄\n'.join(new_modules)
    return body.replace(MARKER, replacement)
