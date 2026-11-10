"""Conservative source extraction. No Android constants or eval() embedded."""
import ast
import hashlib
import json
import operator
import re
import xml.etree.ElementTree as ET
from pathlib import Path


def packed(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def source_ref(path, revision, symbol, fields, line=None):
    path = Path(path)
    return packed([{
        "kind": "source", "path": str(path.resolve()), "revision": revision,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "symbol": symbol, "line": line, "fields": fields,
    }])


def parse_permissions(path, android_version, revision, names=None):
    """Return permission rows; textual protection flags are not guessed.

    `names=None` keeps the original behaviour (every `android.car.*` declaration).
    Passing an explicit name list is how the generic Android privacy permissions in
    `frameworks/base/core/res/AndroidManifest.xml` are read without widening the
    Car baseline to every platform permission.
    """
    ns = "{http://schemas.android.com/apk/res/android}"
    root = ET.parse(path).getroot()
    if root.tag != "manifest":
        raise ValueError("Expected an Android manifest root")
    rows = []
    for node in root.findall("permission"):
        name = node.get(ns + "name", "")
        if names is None:
            if not name.startswith("android.car."):
                continue
        elif name not in names:
            continue
        raw = node.get(ns + "protectionLevel")
        numeric = None
        if raw and re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", raw):
            numeric = int(raw, 16 if raw.lower().startswith("0x") else 10)
        row = {
            "permission_name": name, "android_version": android_version,
            "protection_level_raw": raw, "protection_level_value": numeric,
            "permission_group": node.get(ns + "permissionGroup"),
            "description": node.get(ns + "description"),
            "definition_status": "source_verified",
            "notes": "Resource strings remain unresolved; flags are not decoded. "
                     "Source definition only; device applicability requires calibration.",
        }
        fields = [k for k in ("permission_name", "protection_level_raw",
                  "protection_level_value", "permission_group", "description")
                  if row[k] is not None]
        row["source_refs_json"] = source_ref(path, revision, name, fields)
        rows.append(row)
    if not rows:
        raise ValueError("No android.car.* permission declarations found")
    return rows


def strip_comments(text):
    # Preserve line offsets for source locators. This parser targets integer declarations.
    return re.sub(r"/\*.*?\*/|//[^\n]*",
                  lambda m: "".join("\n" if c == "\n" else " " for c in m[0]),
                  text, flags=re.S)


def constant_value(expression, symbols):
    """Only integer literals, known names and bounded integer operators."""
    if not expression or len(expression) > 4096:
        raise ValueError("Empty or oversized expression")
    expression = re.sub(r"\b[A-Za-z_]\w*(?:(?:::|:|\.)[A-Za-z_]\w*)*",
                        lambda m: str(symbols[m[0]]) if m[0] in symbols else m[0],
                        expression)
    tree = ast.parse(" ".join(expression.split()), mode="eval")
    if sum(1 for _ in ast.walk(tree)) > 128:
        raise ValueError("Expression too complex")
    operations = {ast.Add: operator.add, ast.Sub: operator.sub,
                  ast.BitOr: operator.or_, ast.BitAnd: operator.and_,
                  ast.BitXor: operator.xor, ast.LShift: operator.lshift,
                  ast.RShift: operator.rshift}

    def visit(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            value = node.value
        elif isinstance(node, ast.UnaryOp) and type(node.op) in (ast.UAdd, ast.USub, ast.Invert):
            value = {ast.UAdd: operator.pos, ast.USub: operator.neg,
                     ast.Invert: operator.invert}[type(node.op)](visit(node.operand))
        elif isinstance(node, ast.BinOp) and type(node.op) in operations:
            left, right = visit(node.left), visit(node.right)
            if isinstance(node.op, (ast.LShift, ast.RShift)) and not 0 <= right <= 31:
                raise ValueError("Shift outside supported range")
            value = operations[type(node.op)](left, right)
        else:
            raise ValueError("Unsupported expression or unresolved symbol")
        if not -(2**63) <= value < 2**63:
            raise ValueError("Integer outside supported range")
        return value

    return visit(tree.body)


def declarations(text, java):
    if java:
        if not re.search(r"\bclass\s+VehiclePropertyIds\b", text):
            raise ValueError("Expected VehiclePropertyIds Java class")
        pattern = r"\bpublic\s+static\s+final\s+int\s+(\w+)\s*=\s*([^;]+);"
        return [("VehiclePropertyIds", m[1], m[2], m.start())
                for m in re.finditer(pattern, text)]
    result = []
    for enum in re.finditer(r"\benum\s+(\w+)[^{]*\{([^{}]*)\}", text, re.S):
        offset = enum.start(2)
        for part in enum[2].split(","):
            # Implicit enum values stay unresolved; never infer auto-increment.
            match = re.fullmatch(r"\s*(\w+)\s*(?:=\s*(.*?))?\s*", part, re.S)
            if match:
                result.append((enum[1], match[1], match[2], offset + match.start(1)))
            elif part.strip():
                raise ValueError("Unsupported enum declaration near offset " + str(offset))
            offset += len(part) + 1
    return result


def parse_properties(path, android_version, revision):
    """Handle HIDL types.hal, AIDL VehicleProperty, or Java constants conservatively.

    Return (rows, diagnostics). Unknown expressions yield NULL + pending + TODO.
    Access/unit/type/permission mappings intentionally remain NULL in this skeleton.
    """
    path = Path(path)
    text = strip_comments(path.read_text(encoding="utf-8-sig"))
    java = path.suffix == ".java"
    target = "VehiclePropertyIds" if java else "VehicleProperty"
    items = declarations(text, java)
    symbols, values, errors = {}, {}, {}
    pending = list(items)
    # Support aliases and forward references without executing source code.
    for _ in range(len(items) + 1):
        unresolved = []
        for enum, name, expression, offset in pending:
            key = (enum, name)
            try:
                local = dict(symbols)
                local.update({n: v for (e, n), v in values.items() if e == enum})
                value = constant_value(expression, local)
                values[key] = value
                for separator in (":", "::", "."):
                    symbols[enum + separator + name] = value
            except (ValueError, SyntaxError) as exc:
                errors[key] = str(exc)
                unresolved.append((enum, name, expression, offset))
        if len(unresolved) == len(pending):
            break
        pending = unresolved
    rows, diagnostics, seen = [], [], set()
    for enum, name, expression, offset in items:
        if enum != target:
            continue
        if name in seen:
            raise ValueError("Duplicate property symbol: " + name)
        seen.add(name)
        line = text.count("\n", 0, offset) + 1
        value = values.get((enum, name))
        if value is not None and not -(2**31) <= value <= 0xffffffff:
            errors[(enum, name)] = "Property ID outside 32-bit range"
            value = None
        fields = ["property_name"] + (["property_id"] if value is not None else [])
        notes = "TODO: extract type/access/unit and permission mappings; device calibration required."
        if value is None:
            diagnostic = {"symbol": name, "line": line,
                          "expression": expression, "error": errors.get((enum, name), "Unresolved")}
            diagnostics.append(diagnostic)
            notes += " TODO: " + diagnostic["error"]
        rows.append({
            "property_key": "property:" + name, "android_version": android_version,
            "property_name": name, "property_id": value,
            "definition_status": "pending",
            "source_refs_json": source_ref(path, revision, name, fields, line),
            "notes": notes,
        })
    if not rows:
        raise ValueError("No supported property declarations found")
    return rows, diagnostics
