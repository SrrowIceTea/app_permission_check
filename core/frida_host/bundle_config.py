"""设置 frida-compile 包内白名单/分档占位符，保持 bundle UTF-8 字节长度头正确。

四个占位符都必须是 bundle 里的**字面量**——替换在注入前一刻发生，且会改变字节
长度，必须重算每个模块的长度头（📦 格式）。未替换时字面量原样保留，脚本侧按
"没设开关"处理（见 mobile/hooks/runtime.js 与 hook_privacy.js 的注释）。

  __VSCAN_SESSION_PACKAGES__  白名单包名（JSON 字符串；两条路径都替换）
  __VSCAN_WATCH_LIMIT__       分档定位（A1/H2）：只挂前 N 条监视项
  __VSCAN_NO_STACK__          分档定位（A1/H1）：'1' 关掉事件里的线程/栈字段
  __VSCAN_ARGS_ONLY__         分档定位（A1/H5）：'1' 时事件不带任何返回值字段
"""
import json

MARKER = '__VSCAN_SESSION_PACKAGES__'
WATCH_LIMIT_MARKER = '__VSCAN_WATCH_LIMIT__'
NO_STACK_MARKER = '__VSCAN_NO_STACK__'
ARGS_ONLY_MARKER = '__VSCAN_ARGS_ONLY__'


def configure(body, packages, watch_limit=None, no_stack=None, args_only=None):
    replacements = [(MARKER, json.dumps(json.dumps(packages))[1:-1])]
    if watch_limit is not None:
        replacements.append((WATCH_LIMIT_MARKER, str(int(watch_limit))))
    if no_stack is not None:
        replacements.append((NO_STACK_MARKER, '1' if no_stack else '0'))
    if args_only is not None:
        replacements.append((ARGS_ONLY_MARKER, '1' if args_only else '0'))

    def substitute(text):
        for marker, value in replacements:
            text = text.replace(marker, value)
        return text

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
            changed = substitute(module)
            new_entries.append(f'{len(changed.encode("utf-8"))} {name}')
            new_modules.append(changed)
        return '📦\n' + '\n'.join(new_entries) + '\n✄\n' + '\n✄\n'.join(new_modules)
    return substitute(body)
