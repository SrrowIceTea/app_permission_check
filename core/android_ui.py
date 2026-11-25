"""Parse Android UI hierarchy and find click targets without device I/O."""
import re
import xml.etree.ElementTree as ET


_NODE_RE = re.compile(r"<node\b[^>]*/?>")
_BOUNDS_RE = re.compile(r"bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"")


def nodes(xml: str, *, strict: bool = False) -> list[dict]:
    """把 XML 拍平成节点列表。只保留有意义的字段。

    用 ElementTree 而不是正则（2026-10-19）：**必须知道父子关系**。
    Compose / Flutter 风格的界面把 `clickable=true` 放在一个**无文案的容器 View** 上，
    文案节点（"Skip"/"Next"）自身 `clickable=false`。只按 `clickable` 过滤会得到
    "界面上没有可点候选"——实测 11-app-securecamera 的首启页就是这样被判死的
    （Skip/Next 明明在屏幕上）。`parent` 用于回溯到最近的可点祖先。

    返回字段保持向后兼容（text/rid/desc/cls/pkg/clickable/enabled/bounds/center/area），
    新增 `parent`（列表下标，根为 None）与 `idx`。
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        if strict:
            raise
        return _nodes_regex(xml)
    out: list[dict] = []

    def walk(el, parent: int | None) -> None:
        a = el.attrib
        b = _BOUNDS_RE.search(f'bounds="{a.get("bounds", "")}"')
        if b:
            x1, y1, x2, y2 = (int(g) for g in b.groups())
            out.append({
                "idx": len(out),
                "parent": parent,
                "text": a.get("text", ""),
                "rid": a.get("resource-id", ""),
                "desc": a.get("content-desc", ""),
                "cls": a.get("class", ""),
                "pkg": a.get("package", ""),
                "clickable": a.get("clickable") == "true",
                "enabled": a.get("enabled", "true") == "true",
                "scrollable": a.get("scrollable") == "true",
                "bounds": (x1, y1, x2, y2),
                "center": ((x1 + x2) // 2, (y1 + y2) // 2),
                "area": max(0, x2 - x1) * max(0, y2 - y1),
            })
            parent = len(out) - 1
        for child in el:
            walk(child, parent)

    walk(root, None)
    return out


def _nodes_regex(xml: str) -> list[dict]:
    """兜底解析（XML 不合法时）。没有父子关系，`parent` 全为 None。"""
    out = []
    for raw in _NODE_RE.findall(xml):
        def attr(name: str) -> str:
            m = re.search(name + r'="([^"]*)"', raw)
            return m.group(1) if m else ""
        b = _BOUNDS_RE.search(raw)
        if not b:
            continue
        x1, y1, x2, y2 = (int(g) for g in b.groups())
        out.append({
            "idx": len(out), "parent": None,
            "text": attr("text"), "rid": attr("resource-id"), "desc": attr("content-desc"),
            "cls": attr("class"), "pkg": attr("package"),
            "clickable": attr("clickable") == "true",
            "enabled": attr("enabled") == "true",
            "scrollable": attr("scrollable") == "true",
            "bounds": (x1, y1, x2, y2),
            "center": ((x1 + x2) // 2, (y1 + y2) // 2),
            "area": max(0, x2 - x1) * max(0, y2 - y1),
        })
    return out


def tap_target(n: dict, ns: list[dict]) -> dict:
    """点击目标：自己可点就点自己，否则回溯到最近的可点祖先。

    Compose 把点击挂在容器 View 上、把文案放在不可点的子节点里；
    对子节点中心 `input tap` 一样能命中（触摸事件会冒泡到容器），
    但坐标取容器中心更稳——容器往往比文字大得多，边缘误差不会脱靶。
    """
    if n.get("clickable"):
        return n
    cur = n
    while cur.get("parent") is not None:
        p = ns[cur["parent"]]
        if p.get("clickable") and p.get("enabled") and p.get("area", 0) > 0:
            return p
        cur = p
    return n


def label(n: dict) -> str:
    return n["text"] or n["desc"] or n["rid"] or n["cls"]
