"""Download pinned official APKs for local audit; do not install or redistribute."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone

MAX_APK = 350 * 1024**2
MAX_CORPUS = 3 * 1024**3
LOCK = threading.Lock()


def save(path, obj):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp, path)


def parse_min_sdk(badging):
    match = re.search(r"^(?:sdkVersion|minSdkVersion):'(\d+)'", badging, re.MULTILINE)
    return int(match.group(1)) if match else None


def inspect(apk, entry, args):
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        if "AndroidManifest.xml" not in names or not any(n.endswith(".dex") for n in names):
            raise ValueError("ZIP lacks Android manifest or DEX")
        entry["abi"] = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.endswith(".so")})
    run = subprocess.run([args.aapt2, "dump", "badging", str(apk)], capture_output=True,
                         text=True, encoding="utf-8", errors="replace", timeout=90)
    (apk.parent / "badging.txt").write_text(run.stdout + run.stderr, encoding="utf-8")
    if run.returncode:
        raise ValueError("aapt2 failed: " + run.stderr[-300:])
    package = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'", run.stdout)
    if not package:
        raise ValueError("aapt2 did not report package identity")
    entry.update(dict(zip(("package", "version_code", "version_name"), package.groups())))
    if entry.get("expected_package") and entry["package"] != entry["expected_package"]:
        raise ValueError("downloaded package differs from catalog selection")
    entry["min_sdk"] = parse_min_sdk(run.stdout)
    target = re.search(r"targetSdkVersion:'(\d+)'", run.stdout)
    entry["target_sdk"] = int(target.group(1)) if target else None
    verify = subprocess.run([args.java, "-jar", args.apksigner, "verify", "--verbose", "--print-certs", str(apk)],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    (apk.parent / "signature.txt").write_text(verify.stdout + verify.stderr, encoding="utf-8")
    entry["artifact_checks"] = {"zip": True, "manifest": True, "signature": verify.returncode == 0}
    entry["signer_sha256"] = re.findall(r"certificate SHA-256 digest: ([0-9a-fA-F]+)", verify.stdout)
    if verify.returncode:
        raise ValueError("APK signature verification failed")


def fetch(entry, args):
    entry = dict(entry)
    folder = args.out / entry["sample_id"]
    folder.mkdir(exist_ok=True)
    apk = folder / "original.apk"
    part = folder / "original.apk.part"
    metadata = folder / "metadata.json"
    if apk.exists() and metadata.exists():
        previous = json.loads(metadata.read_text(encoding="utf-8"))
        entry = {**previous, **entry}
    entry.update({"retrieved_at": datetime.now(timezone.utc).isoformat(), "download_status": "failed",
                  "apk_path": str(apk.resolve()), "test_scope": "Public official artifact; local security analysis only; no redistribution or account use"})
    try:
        if not apk.exists():
            headers = {"User-Agent": "Mozilla/5.0 VScanner-local-audit", "Referer": entry["official_page"]}
            url = entry["download_url"]
            if "api.github.com/repos/" in url:
                headers["Accept"] = "application/octet-stream"
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=60) as response:
                total = int(response.headers.get("Content-Length", "0"))
                if total > MAX_APK:
                    raise ValueError("official APK exceeds 350 MiB budget")
                with LOCK:
                    used = sum(p.stat().st_size for p in args.out.glob("*/original.apk*"))
                    if used + total > MAX_CORPUS:
                        raise ValueError("3 GiB corpus budget exhausted")
                entry["resolved_download_url"] = response.url
                entry["http_content_type"] = response.headers.get("Content-Type")
                size = 0
                started = time.monotonic()
                with part.open("wb") as stream:
                    while chunk := response.read(65536):
                        if time.monotonic() - started > 300:
                            raise TimeoutError("download exceeded five-minute budget")
                        size += len(chunk)
                        if size > MAX_APK:
                            raise ValueError("stream exceeded 350 MiB budget")
                        stream.write(chunk)
                if total and size != total:
                    raise ValueError("incomplete Content-Length")
            os.replace(part, apk)
        digest = hashlib.file_digest(apk.open("rb"), "sha256").hexdigest()
        entry.update({"sha256": digest, "size_bytes": apk.stat().st_size})
        expected = entry.get("publisher_digest")
        entry["publisher_digest_verified"] = None if not expected else expected == "sha256:" + digest
        if expected and not entry["publisher_digest_verified"]:
            raise ValueError("publisher SHA-256 mismatch")
        inspect(apk, entry, args)
        entry["download_status"] = "downloaded"
        entry.pop("failure", None)
    except Exception as error:
        entry["failure"] = str(error)
        if part.exists():
            part.unlink()
    save(folder / "metadata.json", entry)
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=Path(__file__).with_name("catalog.json"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--ids", nargs="*")
    sdk = Path(os.environ.get("LOCALAPPDATA", "")) / "Android/Sdk/build-tools/36.0.0"
    parser.add_argument("--aapt2", default=str(sdk / "aapt2.exe"))
    parser.add_argument("--java", default=r"C:\Program Files\Java\jdk-17\bin\java.exe")
    parser.add_argument("--apksigner", default=str(sdk / "lib/apksigner.jar"))
    args = parser.parse_args()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    selected = [e for e in catalog if not args.ids or e["sample_id"] in args.ids]
    entries = {e["sample_id"]: e for e in json.loads((args.out / "manifest.json").read_text(encoding="utf-8"))} if (args.out / "manifest.json").exists() else {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(fetch, entry, args) for entry in selected]
        for future in concurrent.futures.as_completed(futures):
            entry = future.result()
            entries[entry["sample_id"]] = entry
            save(args.out / "manifest.json", list(entries.values()))
            print(json.dumps({k: entry.get(k) for k in ("sample_id", "name", "package", "size_bytes", "download_status", "failure")}, ensure_ascii=False), flush=True)
    return 0 if all(entries[e["sample_id"]]["download_status"] == "downloaded" for e in selected) else 1


if __name__ == "__main__":
    raise SystemExit(main())
