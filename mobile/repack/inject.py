"""Minimal manifest and Application smali transformation, never signature spoofing."""
from __future__ import annotations
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID = "{http://schemas.android.com/apk/res/android}"
HELPER = "__vscannerLoadAuthorizedGadget"
CLASS = "com.vscanner.audit.GadgetApplication"


def smali_name(name: str, package: str) -> str:
    if name.startswith("."):
        name = package + name
    elif "." not in name:
        name = package + "." + name
    if not re.fullmatch(r"[\w.$]+", name):
        raise ValueError("Unsupported Application class name")
    return "L" + name.replace(".", "/") + ";"


def patch_smali(text: str, descriptor: str) -> tuple[str, str]:
    if HELPER in text:
        raise ValueError("APK already contains the Gadget loader marker")
    super_match = re.search(r"(?m)^\.super (L[^;]+;)", text)
    if not super_match:
        raise ValueError("Application smali has no superclass")
    superclass = super_match[1]
    call = f"    invoke-static {{}}, {descriptor}->{HELPER}()V\n"
    pattern = r"(?ms)^\.method [^\n]*attachBaseContext\(Landroid/content/Context;\)V\n.*?^\.end method"
    match = re.search(pattern, text)
    if match:
        method = match[0]
        if re.search(r"(?m)^\.method .*\b(native|abstract)\b", method):
            raise ValueError("Native/abstract Application.attachBaseContext requires sample-specific adaptation")
        # Preserve register counts and original instructions by a no-argument helper.
        super_call = re.search(r"(?m)^\s*invoke-super(?:/range)?[^\n]*->attachBaseContext\(Landroid/content/Context;\)V[^\n]*\n", method)
        if not super_call:
            raise ValueError("Custom attachBaseContext has no identifiable super call")
        method = method[:super_call.end()] + call + method[super_call.end():]
        text = text[:match.start()] + method + text[match.end():]
        placement = "after_existing_super_attachBaseContext"
    else:
        text += ("\n.method protected attachBaseContext(Landroid/content/Context;)V\n"
                 "    .locals 0\n"
                 f"    invoke-super {{p0, p1}}, {superclass}->attachBaseContext(Landroid/content/Context;)V\n"
                 + call + "    return-void\n.end method\n")
        placement = "added_attachBaseContext_after_super"
    text += (f"\n.method private static {HELPER}()V\n    .locals 1\n"
             '    const-string v0, "gadget"\n'
             "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
             "    return-void\n.end method\n")
    return text, placement


def transform(decoded: Path, backup: Path, abi: str) -> dict:
    manifest = decoded / "AndroidManifest.xml"
    tree = ET.parse(manifest)
    root = tree.getroot()
    package = root.get("package", "")
    if root.get("split") or root.get(ANDROID + "isSplitRequired") == "true":
        raise ValueError("Split APK is not supported by single-APK repacking")
    if root.get(ANDROID + "sharedUserId"):
        raise ValueError("sharedUserId requires original signer compatibility; refusing generic repack")
    app = root.find("application")
    if app is None:
        raise ValueError("APK has no application manifest node")
    if app.get(ANDROID + "isSplitRequired") == "true":
        raise ValueError("Split APK is not supported by single-APK repacking")
    if app.get(ANDROID + "isolatedProcess") == "true":
        raise ValueError("Isolated application process requires a dedicated transport")
    native = decoded / "lib"
    abis = sorted(p.name for p in native.iterdir() if p.is_dir()) if native.exists() else []
    if abis and abi not in abis:
        raise ValueError(f"ABI incompatible: APK has {abis}, requested {abi}")
    packers = [p.name for p in native.rglob("*.so") if any(s in p.name.lower()
               for s in ("jiagu", "secneo", "dexhelper", "dexguard", "shell-super"))] if native.exists() else []
    if packers:
        raise ValueError(f"Packed loader needs sample-specific timing: {packers}")
    name = app.get(ANDROID + "name")
    if not name or name == "android.app.Application":
        descriptor = smali_name(CLASS, package)
        location = decoded / "smali" / (descriptor[1:-1] + ".smali")
        if location.exists():
            raise ValueError("Injected Application class already exists")
        location.parent.mkdir(parents=True, exist_ok=True)
        text = (f".class public {descriptor}\n.super Landroid/app/Application;\n"
                ".method public constructor <init>()V\n    .locals 0\n"
                "    invoke-direct {p0}, Landroid/app/Application;-><init>()V\n"
                "    return-void\n.end method\n")
        app.set(ANDROID + "name", CLASS)
    else:
        descriptor = smali_name(name, package)
        locations = list(decoded.glob("smali*/" + descriptor[1:-1] + ".smali"))
        if len(locations) != 1:
            raise ValueError(f"Application smali must resolve once, found {len(locations)}: {descriptor}")
        location = locations[0]
        text = location.read_text(encoding="utf-8")
        target = backup / location.relative_to(decoded)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(location, target)
    patched, placement = patch_smali(text, descriptor)
    temporary = location.with_suffix(".tmp")
    temporary.write_text(patched, encoding="utf-8")
    temporary.replace(location)
    backup.mkdir(parents=True, exist_ok=True)
    shutil.copy2(manifest, backup / "AndroidManifest.xml")
    app.set(ANDROID + "extractNativeLibs", "true")
    permissions = {node.get(ANDROID + "name") for node in root.findall("uses-permission")}
    transport_permission_added = "android.permission.INTERNET" not in permissions
    if transport_permission_added:
        permission = ET.Element("uses-permission", {ANDROID + "name": "android.permission.INTERNET"})
        root.insert(0, permission)
    ET.register_namespace("android", ANDROID[1:-1])
    temporary = manifest.with_suffix(".tmp")
    tree.write(temporary, encoding="utf-8", xml_declaration=True)
    temporary.replace(manifest)
    return {"package": package, "original_application": name, "application_descriptor": descriptor,
            "smali": str(location.relative_to(decoded)), "load_placement": placement,
            "original_native_abis": abis, "extraction": "extractNativeLibs=true",
            "transport_permission_added": "android.permission.INTERNET" if transport_permission_added else None,
            "business_api_rewriting": False, "signature_spoofing": False}
