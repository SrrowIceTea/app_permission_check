#!/usr/bin/env python3
"""生成一个**合成演示会话**，用于离线验证「规则库 → 关联 → 证据包 → AI → 报告」整条链。

仅用于授权测试（已获授权的样本与设备）。

⚠️ 这是合成数据，不是真实采集。每个文件头部都有 SYNTHETIC_DEMO 标记，
   值也是明显的假值（460001234567890 这类）。它的用途只有一个：
   在没有设备的时候验证下游链路能跑通、字段对得上、值级匹配能命中。
   **它不能当作任何 App 的行为证据。**

时间线（主机时间基准，ms）刻意覆盖几种典型形态：
    T+1000  应用启动、钩子挂载（START/ARMED）
    T+2000  请求 READ_PHONE_STATE / READ_CONTACTS / ACCESS_FINE_LOCATION
    T+3000  用户选择：前两项**授予**，定位**拒绝**（部分授权）
    T+4000  读取 IMEI              → 有同意，合规读取
    T+5000  读取剪贴板              → 剪贴板无需运行时权限，全程无同意事件
    T+6000  读取应用列表            → QUERY_ALL_PACKAGES 是安装期权限，无运行时同意
    T+7000  再次尝试定位（outcome=denied）→ **不计入收集**，走 denied 路径
    T+8000  打开隐私政策页          → 同意链里的政策代理信号
    T+12000 HTTP 明文外发（含 IMEI）→ 与 T+4000 的读取**值级匹配**
    T+20000 HTTPS 外发（含坐标）    → 仅形态匹配
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

IMEI = "460001234567890"
ANDROID_ID = "9f2c1ab34de56789"
CONTACT_URI = "content://com.android.contacts/data/phones"
PKG = "com.vscanner.privacydemo"

SYNTH = "SYNTHETIC_DEMO — 合成数据，不是真实采集，不得作为任何 App 的行为证据"


def h16(v: str) -> str:
    return hashlib.sha256(v.encode("utf-8")).hexdigest()[:16]


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def build(base: int) -> dict[str, list[dict]]:
    def ts(off: int) -> int:
        return base + off

    reads = [
        {"v": "1", "src": "privacy", "ev": "START", "evt_id": 1, "ts": ts(1000),
         "pkg": PKG, "uid": 10250, "whitelist": [PKG], "watch_apis": 33, "data_types": 16,
         "rules_sha256": "SYNTHETIC", "frida": "17.18.0", "synthetic": SYNTH},
        {"v": "1", "src": "privacy", "ev": "ARMED", "evt_id": 2, "ts": ts(1000),
         "pkg": PKG, "hooks": 33, "failed": 0, "synthetic": SYNTH},

        {"v": "1", "src": "privacy", "ev": "PRIVACY_READ", "evt_id": 3, "ts": ts(4000),
         "pkg": PKG, "uid": 10250, "api": "android.telephony.TelephonyManager.getImei()Ljava/lang/String;",
         "api_role": "read", "data_types": ["imei"], "data_types_zh": ["IMEI 国际移动设备识别码"],
         "max_sensitivity": "sensitive_personal", "outcome": "ok",
         "value_kind": "string", "value_len": len(IMEI), "value_hash": h16(IMEI),
         "value_preview": IMEI[:6] + "…",
         "stack": ("java.lang.Thread.getStackTrace(Thread.java:1012)\n"
                   "com.vscanner.privacydemo.DeviceInfo.readImei(DeviceInfo.kt:42)\n"
                   "com.vscanner.privacydemo.MainActivity.onBtnRead(MainActivity.kt:88)"),
         "synthetic": SYNTH},

        {"v": "1", "src": "privacy", "ev": "PRIVACY_READ", "evt_id": 4, "ts": ts(5000),
         "pkg": PKG, "uid": 10250,
         "api": "android.content.ClipboardManager.getPrimaryClip()Landroid/content/ClipData;",
         "api_role": "read", "data_types": ["clipboard"], "data_types_zh": ["剪贴板内容"],
         "max_sensitivity": "sensitive_personal", "outcome": "ok",
         "value_kind": "clip", "item_count": 1, "text_len": 11,
         "stack": ("java.lang.Thread.getStackTrace(Thread.java:1012)\n"
                   "com.vscanner.privacydemo.ClipReader.read(ClipReader.kt:19)"),
         "synthetic": SYNTH},

        {"v": "1", "src": "privacy", "ev": "PRIVACY_READ", "evt_id": 5, "ts": ts(6000),
         "pkg": PKG, "uid": 10250,
         "api": "android.content.pm.PackageManager.getInstalledPackages(I)Ljava/util/List;",
         "api_role": "query", "data_types": ["installed_apps"], "data_types_zh": ["应用安装列表"],
         "max_sensitivity": "personal", "outcome": "ok",
         "value_kind": "count", "value_count": 137,
         "stack": ("java.lang.Thread.getStackTrace(Thread.java:1012)\n"
                   "com.vscanner.privacydemo.AppListReader.read(AppListReader.kt:27)"),
         "synthetic": SYNTH},

        {"v": "1", "src": "privacy", "ev": "PRIVACY_READ", "evt_id": 6, "ts": ts(7000),
         "pkg": PKG, "uid": 10250,
         "api": "android.location.LocationManager.getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;",
         "api_role": "read", "data_types": ["precise_location"], "data_types_zh": ["精确定位（行踪轨迹）"],
         "max_sensitivity": "sensitive_personal", "outcome": "denied", "arg_disc": "gps",
         "exc_class": "java.lang.SecurityException", "exc_msg": "gps provider requires ACCESS_FINE_LOCATION",
         "stack": ("java.lang.Thread.getStackTrace(Thread.java:1012)\n"
                   "com.vscanner.privacydemo.LocReader.read(LocReader.kt:33)"),
         "synthetic": SYNTH},
    ]

    consent = [
        {"v": "1", "src": "consent", "ev": "START", "evt_id": 1, "ts": ts(1000), "pkg": PKG,
         "consent_apis": 8, "synthetic": SYNTH},
        {"v": "1", "src": "consent", "ev": "ARMED", "evt_id": 2, "ts": ts(1000), "pkg": PKG,
         "hooks": 8, "failed": 0, "synthetic": SYNTH},
        {"v": "1", "src": "consent", "ev": "PERM_REQ", "evt_id": 3, "ts": ts(2000), "pkg": PKG,
         "api": "android.app.Activity.requestPermissions([Ljava/lang/String;I)V",
         "permissions": ["android.permission.READ_PHONE_STATE", "android.permission.READ_CONTACTS",
                         "android.permission.ACCESS_FINE_LOCATION"],
         "permissions_short": ["READ_PHONE_STATE", "READ_CONTACTS", "ACCESS_FINE_LOCATION"],
         "request_code": 100, "synthetic": SYNTH},
        {"v": "1", "src": "consent", "ev": "PERM_RESULT", "evt_id": 4, "ts": ts(3000), "pkg": PKG,
         "api": "android.app.Activity.onRequestPermissionsResult(I[Ljava/lang/String;[I)V",
         "permissions": ["android.permission.READ_PHONE_STATE", "android.permission.READ_CONTACTS",
                         "android.permission.ACCESS_FINE_LOCATION"],
         "grant_results": [0, 0, -1], "granted": ["READ_PHONE_STATE", "READ_CONTACTS"],
         "denied": ["ACCESS_FINE_LOCATION"], "request_code": 100, "synthetic": SYNTH},
        {"v": "1", "src": "consent", "ev": "POLICY_VIEW", "evt_id": 5, "ts": ts(8000), "pkg": PKG,
         "api": "android.webkit.WebView.loadUrl(Ljava/lang/String;)V",
         "url": "https://demo.invalid/privacy-policy.html", "synthetic": SYNTH},
    ]

    contact_read = {
        "v": "1", "src": "privacy", "ev": "PRIVACY_READ", "evt_id": 7, "ts": ts(4500),
        "pkg": PKG, "uid": 10250,
        "api": "android.content.ContentResolver.query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
        "api_role": "query", "data_types": ["contacts"], "data_types_zh": ["通讯录"],
        "max_sensitivity": "sensitive_personal", "outcome": "ok", "arg_disc": CONTACT_URI,
        "value_kind": "cursor", "column_count": 4,
        "stack": ("java.lang.Thread.getStackTrace(Thread.java:1012)\n"
                  "com.vscanner.privacydemo.ContactReader.query(ContactReader.kt:51)"),
        "synthetic": SYNTH,
    }
    reads.insert(4, contact_read)

    flows = [
        {"v": "1", "src": "proxy", "evt_id": 1, "ts": ts(12000), "package": PKG,
         "scheme": "http", "method": "POST", "host": "api.demo.invalid", "path": "/collect",
         "status_code": 200, "intercepted_tls": False, "attribution": "app_process_hook",
         "attribution_ambiguous": False,
         "request_tags": ["digit15_shape", "android_id_shape", "json_key_personal"],
         "request_tokens": [f"digit15_shape:{h16(IMEI)}",
                            f"android_id_shape:{h16(ANDROID_ID)}"],
         "response_tags": [], "request_bytes": 412, "synthetic": SYNTH},
        {"v": "1", "src": "proxy", "evt_id": 2, "ts": ts(20000), "package": PKG,
         "scheme": "https", "method": "POST", "host": "sdk.tracker.invalid", "path": "/v1/event",
         "status_code": 204, "intercepted_tls": True, "attribution": "app_process_hook",
         "attribution_ambiguous": False,
         "request_tags": ["coordinate_shape", "json_key_personal"],
         "request_tokens": [f"coordinate_shape:{h16('39.904,116.407')}"],
         "response_tags": [], "request_bytes": 288, "synthetic": SYNTH},
    ]

    egress = [
        {"v": "1", "src": "egress", "ev": "EGRESS_CONNECT", "evt_id": 1, "ts": ts(11980),
         "pkg": PKG, "uid": 10250, "host": "api.demo.invalid", "port": 80,
         "outcome": "ok", "synthetic": SYNTH},
        {"v": "1", "src": "egress", "ev": "EGRESS_CONNECT", "evt_id": 2, "ts": ts(19980),
         "pkg": PKG, "uid": 10250, "host": "sdk.tracker.invalid", "port": 443,
         "outcome": "ok", "synthetic": SYNTH},
    ]
    for r in reads + consent + flows + egress:
        r["host_received_ts"] = r["ts"]
    return {"reads": reads, "consent": consent, "flows": flows, "egress": egress}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--base-ts", type=int, default=1758600000000)
    args = ap.parse_args()
    out = Path(args.out)
    data = build(args.base_ts)
    write_jsonl(out / "reads.jsonl", data["reads"])
    write_jsonl(out / "consent.jsonl", data["consent"])
    write_jsonl(out / "flows.jsonl", data["flows"])
    write_jsonl(out / "egress.jsonl", data["egress"])
    (out / "requested-permissions.txt").write_text(
        "\n".join([
            "android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.READ_PHONE_STATE", "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.QUERY_ALL_PACKAGES", "android.permission.ACCESS_WIFI_STATE",
        ]) + "\n", encoding="utf-8")
    (out / "README.txt").write_text(
        f"{SYNTH}\n\n本目录由 mobile/tools/make_demo_session.py 生成，"
        "用于离线验证下游链路（关联 → 证据包 → AI → 报告）。\n"
        "包名 com.vscanner.privacydemo 是自有夹具的包名；其中的标识符是明显的假值。\n",
        encoding="utf-8")
    print(json.dumps({"status": "ok", "out": str(out),
                      "files": sorted(p.name for p in out.iterdir())},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
