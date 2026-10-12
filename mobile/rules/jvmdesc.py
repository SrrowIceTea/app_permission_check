#!/usr/bin/env python3
"""JVM 描述符解析 —— 把 android.jar 抽出的描述符还原成 Frida overload() 需要的类型名。

为什么需要它：钩子要按**精确签名**包裹重载（`Java.use(cls)[m].overload('int','int')`），
而库里的描述符是 `(II)Landroid/car/...;` 这种形式。手写类型名会出错，
且出错的表现是「钩子挂到另一个重载上」——静默、难查。所以类型名一律由描述符解析得出。
"""
from __future__ import annotations

PRIMITIVES = {"Z": "boolean", "B": "byte", "C": "char", "S": "short",
              "I": "int", "J": "long", "F": "float", "D": "double", "V": "void"}


def _parse_one(desc: str, i: int) -> tuple[str, int]:
    ch = desc[i]
    if ch in PRIMITIVES:
        return PRIMITIVES[ch], i + 1
    if ch == "[":
        # 数组**必须保留 JVM 形态**，不能拼成 `[java.lang.String`：
        # Frida 的 overload() 认的是 `[Ljava.lang.String;`（实测：写成前者，
        # ContentResolver.query 三个重载全部挂不上，报 "specified argument types
        # do not match any of"，而钩子其它部分照常工作——很难注意到某一类 API 整个哑了）。
        j = i + 1
        while desc[j] == "[":
            j += 1
        if desc[j] == "L":
            end = desc.index(";", j)
            return desc[i:end + 1].replace("/", "."), end + 1
        return desc[i:j + 1], j + 1
    if ch == "L":
        end = desc.index(";", i)
        return desc[i + 1:end].replace("/", "."), end + 1
    raise ValueError(f"无法解析的描述符片段: {desc[i:]!r}")


def param_types(descriptor: str) -> list[str]:
    """`(Landroid/net/Uri;[Ljava/lang/String;I)V` → ['android.net.Uri', '[java.lang.String', 'int']"""
    if not descriptor.startswith("("):
        raise ValueError(f"不是方法描述符: {descriptor!r}")
    i, params = 1, []
    while descriptor[i] != ")":
        t, i = _parse_one(descriptor, i)
        params.append(t)
    return params


def return_type(descriptor: str) -> str:
    i = descriptor.index(")")
    t, _ = _parse_one(descriptor, i + 1)
    return t


def method_key(class_name: str, method_name: str, descriptor: str) -> str:
    """与 vehicle/workbench/dexfacts 相同的引用形态：com.x.Y.method(desc)"""
    return f"{class_name}.{method_name}{descriptor}"
