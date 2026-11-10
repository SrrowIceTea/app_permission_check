#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 L2 目标集 `mobile/rules/targets/sensitive_surface_v1.json`（带版本号与 sha256）。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

**枚举在这里，产出的 JSON 是运行期唯一依据。** 复现方式：

    .\\tools\\python313.ps1 mobile/tools/target_set_build.py --verify   # 重算并与仓库文件比对
    .\\tools\\python313.ps1 mobile/tools/target_set_build.py            # 重写文件

两类来源，可信度不同，逐条写进 JSON 的 `source` 字段：
  * `android.*` / `java.*` 类 —— 本机 `android.jar`（API 36）实测存在，方法数由
    `javap -public -s` 数出来。这是**可核对**的来源。
  * `androidx.*` / GMS / 国内 SDK —— 本机 `android.jar` **不含**这些类，只能按公开
    命名空间枚举；方法面只能从样本 dex 实测（没有 jar 可对照）。

**不做方法级挑选**（挑方法等于提前假定该挑哪些），唯一例外是 `ContentResolver`：
只算取数/写数的 10 个方法，不算 `registerContentObserver` 之类（理由见目标集 note）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from core import sdk_paths  # noqa: E402
from mobile.tools.surface_target import DEFAULT_TARGET_SET, canonical_sha256  # noqa: E402

JAR = Path(sdk_paths.sdk_dir("platforms", "android-36", "android.jar"))
JAVAP = Path(sdk_paths.jdk_tool("bin", "javap.exe"))

CATEGORIES = [
    ("location", "定位", [
        ("prefix", "android.location.LocationManager"),
        ("exact", "android.location.Geocoder"),
        ("exact", "androidx.core.location.LocationManagerCompat"),
        ("prefix", "com.google.android.gms.location."),
        ("prefix", "com.amap.api.location."),
        ("prefix", "com.baidu.location."),
        ("prefix", "com.tencent.map.geolocation."),
        ("prefix", "com.autonavi."),
    ]),
    ("contacts", "通讯录", [
        ("prefix", "android.provider.ContactsContract"),
        ("exact", "android.accounts.AccountManager"),
    ]),
    ("camera", "相机", [
        ("prefix", "android.hardware.Camera"),
        ("prefix", "android.hardware.camera2.CameraManager"),
        ("prefix", "android.hardware.camera2.CameraDevice"),
        ("prefix", "android.hardware.camera2.CameraCaptureSession"),
        ("exact", "androidx.camera.lifecycle.ProcessCameraProvider"),
    ]),
    ("microphone", "麦克风", [
        ("prefix", "android.media.AudioRecord"),
        ("prefix", "android.media.MediaRecorder"),
    ]),
    ("sensor", "传感器", [
        ("prefix", "android.hardware.SensorManager"),
        ("exact", "android.hardware.TriggerEventListener"),
    ]),
    ("clipboard", "剪贴板", [
        ("prefix", "android.content.ClipboardManager"),
        ("prefix", "android.content.ClipData"),
        ("exact", "android.text.ClipboardManager"),
    ]),
    ("device_id", "设备标识", [
        ("prefix", "android.telephony.TelephonyManager"),
        ("exact", "android.os.Build"),
        ("prefix", "android.os.Build$"),
        ("prefix", "android.provider.Settings$Secure"),
        ("prefix", "android.provider.Settings$System"),
        ("prefix", "android.provider.Settings$Global"),
        ("prefix", "android.net.wifi.WifiInfo"),
        ("prefix", "android.net.wifi.WifiManager"),
        ("exact", "java.net.NetworkInterface"),
        ("prefix", "com.google.android.gms.ads.identifier."),
    ]),
    ("installed_apps", "已装应用", [
        ("prefix", "android.content.pm.PackageManager"),
        ("exact", "android.app.ActivityManager"),
        ("exact", "android.app.usage.UsageStatsManager"),
    ]),
    ("storage", "存储", [
        ("prefix", "android.provider.MediaStore"),
        ("prefix", "android.provider.DocumentsContract"),
        ("exact", "android.os.Environment"),
        ("exact", "androidx.documentfile.provider.DocumentFile"),
        ("exact", "android.content.ContentResolver"),
    ]),
]
CONTENT_RESOLVER_METHODS = ["query", "openInputStream", "openOutputStream",
                            "openFileDescriptor", "openAssetFileDescriptor",
                            "insert", "update", "delete", "bulkInsert", "call"]
GROUPS = [
    {"key": "platform", "zh": "平台 android/androidx/java",
     "prefixes": ["android.", "androidx.", "java.", "javax."]},
    {"key": "gms", "zh": "Google Play 服务", "prefixes": ["com.google.android.gms."]},
    {"key": "cn", "zh": "国内 SDK", "prefixes": ["com.amap.", "com.tencent.", "com.baidu.",
                                                "com.autonavi.", "com.iflytek.", "com.qq."]},
]
DECL_RE = re.compile(r"^\s+(?:public|protected)\s.*;\s*$")
DESC_RE = re.compile(r"^\s+descriptor:\s*\S+\s*$")
SCOPE_RULE = {
    "unit": "敏感类上的全部 invoke 目标 (类, 方法, 描述符)",
    "class_source": ("本文件的 categories 是**独立枚举**（品类 → 类名/前缀），"
                     "不从 dangerous_apis 反推——反推会让分母被闭集定义，比例永远 100%"),
    "signature_source": ("样本 APK 的 dex（dexdump -d 的实测 invoke 目标）。"
                         "不取 android.jar 的方法全表，因为那会把几百个从未被调用的重载也算进分母，"
                         "得到的比例不对应任何真实行为"),
    "why_not_aosp": ("AOSP 源码树版本与本机 API 36 不一致，且 androidx 不在 AOSP platform 里；"
                     "只有 android.jar 能一对一核对，故 android.jar 只用于**核对类是否存在**"),
    "distortion": [
        "混入「样本没碰过的 API 就不在分母里」：分母是样本内口径，跨样本只能比各自比例，不能比大小。",
        "方法句柄 / invoke-custom / invoke-polymorphic 不展开，经它们发起的敏感调用不可见（低估分母）。",
        "静态 final 字段值会被编译期内联（Build.MODEL 等），字段通道单列、不进本分母。",
        "只扫 classes*.dex；assets/ 内的二次 dex（加固、动态加载）不在内，加固样本会失真。",
        "androidx / GMS / 国内 SDK 的类不在 android.jar 里，类是否敏感只能靠命名空间枚举。",
    ],
}


def _jar_methods(class_name: str) -> int | None:
    """该类在 android.jar 里的 public/protected 方法数；类不存在返回 None。"""
    proc = subprocess.run([str(JAVAP), "-classpath", str(JAR), "-public", "-s", class_name],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=120)
    if proc.returncode != 0:
        return None
    lines = proc.stdout.splitlines()
    return sum(1 for i, line in enumerate(lines)
               if DECL_RE.match(line) and any(DESC_RE.match(lines[j])
                                              for j in range(i + 1, min(i + 4, len(lines)))))


def build() -> dict:
    jar_sha = hashlib.sha256(JAR.read_bytes()).hexdigest()
    cache: dict[str, int | None] = {}
    cats = []
    for key, zh, entries in CATEGORIES:
        out = []
        for kind, value in entries:
            probe = value[:-1] if value.endswith("$") else value.rstrip(".")
            if probe not in cache:
                cache[probe] = _jar_methods(probe)
            n = cache[probe]
            item = {"kind": kind, "value": value}
            if probe != value:
                item["probe_class"] = probe
            if n is None:
                item["in_android_jar"] = False
                item["source"] = ("公开命名空间枚举；本机 android.jar(API 36) 不含该类，"
                                  "方法面只能从样本 dex 实测")
            else:
                item["in_android_jar"] = True
                item["jar_method_count"] = n
                item["source"] = f"android.jar:android-36（javap -public -s 实测存在，方法 {n} 个）"
            out.append(item)
        cats.append({"key": key, "zh": zh, "entries": out})
    doc = {
        "target_set_id": "MOB-SURFACE-V1",
        "version": "1",
        "status": "frozen",
        "generated_at": "2026-11-10",
        "generated_by": "mobile/tools/target_set_build.py",
        "purpose": ("L2 只读覆盖统计（observed_surface）的作用域：哪些类算「敏感面」。"
                    "给 observed_surface 用，规则引擎不读它；不进 dangerous_apis、不碰 rules.db。"),
        "scope_rule": {**SCOPE_RULE,
                       "android_jar": str(JAR), "android_jar_sha256": jar_sha,
                       "javap": str(JAVAP)},
        "groups": GROUPS,
        "method_allowlists": {"android.content.ContentResolver": CONTENT_RESOLVER_METHODS},
        "method_allowlist_note": ("ContentResolver 只算取数/写数的 10 个方法；"
                                  "registerContentObserver / notifyChange 之类不算读取"),
        "categories": cats,
        "not_in_scope": [
            "字段读取（Build.MODEL / Settings$Secure.ANDROID_ID 等）：闭集是方法签名表，"
            "字段本就不在它的表达力内，单列在 observed_surface.field_reads",
            "写操作与覆写型服务（ContentResolver.insert/update 已按 allowlist 部分计入；"
            "无障碍/通知监听未计入）",
            "GMS 之外的商业 SDK（Firebase、广告、归因）：本地池子里 0 样本，无法评估",
        ],
    }
    doc["sha256"] = canonical_sha256(doc)
    return doc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(DEFAULT_TARGET_SET))
    ap.add_argument("--verify", action="store_true", help="重算并与仓库文件比对，不写文件")
    args = ap.parse_args()
    if not JAR.exists() or not JAVAP.exists():
        print(f"[fatal] 缺 android.jar / javap：{JAR} / {JAVAP}", file=sys.stderr)
        return 2
    doc = build()
    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    path = Path(args.out)
    if args.verify:
        if not path.exists():
            print(f"[verify] FAIL 缺少 {path}", file=sys.stderr)
            return 1
        old = json.loads(path.read_text(encoding="utf-8"))
        if old.get("sha256") != doc["sha256"]:
            print(f"[verify] FAIL sha256 不一致：文件 {old.get('sha256')} / 实算 {doc['sha256']}",
                  file=sys.stderr)
            return 1
        print(json.dumps({"status": "ok", "target_set": doc["target_set_id"],
                          "sha256": doc["sha256"],
                          "entries": sum(len(c["entries"]) for c in doc["categories"])},
                         ensure_ascii=False))
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    entries = sum(len(c["entries"]) for c in doc["categories"])
    print(json.dumps({"status": "written", "path": str(path), "sha256": doc["sha256"],
                      "entries": entries,
                      "in_android_jar": sum(1 for c in doc["categories"] for e in c["entries"]
                                            if e.get("in_android_jar"))},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
