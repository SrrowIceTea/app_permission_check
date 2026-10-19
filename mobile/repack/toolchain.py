"""Pinned official tools, signing and artifact inspection; no device operations."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SDK = Path(os.environ.get("ANDROID_HOME", Path.home() / "AppData/Local/Android/Sdk"))
JAVA = Path(os.environ.get("JAVA_HOME", "C:/Program Files/Java/jdk-17")) / "bin/java.exe"
BUILD = SDK / "build-tools/36.0.0"
APKTOOL = {"version": "3.0.3", "sha256":
           "dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423"}


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(args: list, log: Path, timeout: int = 300) -> str:
    result = subprocess.run([str(v) for v in args], capture_output=True, timeout=timeout)
    raw = result.stdout + b"\n" + result.stderr
    log.write_bytes(raw)
    if result.returncode:
        raise RuntimeError(f"Command exited {result.returncode}: {log}\n{raw.decode('utf-8', 'replace')[-1800:]}")
    return raw.decode("utf-8", "replace")


def apktool(cache: Path) -> tuple[Path, dict]:
    name = f"apktool_{APKTOOL['version']}.jar"
    url = f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL['version']}/{name}"
    target = cache / name
    if not target.exists():
        cache.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request(url, headers={"User-Agent": "vscanner-authorized-repack"})
        with urllib.request.urlopen(request, timeout=120) as response:
            raw = response.read(40 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != APKTOOL["sha256"]:
            raise ValueError("Official Apktool release SHA256 mismatch")
        temporary = target.with_suffix(".tmp")
        temporary.write_bytes(raw)
        temporary.replace(target)
    if sha(target) != APKTOOL["sha256"]:
        raise ValueError("Cached Apktool SHA256 mismatch")
    return target, {**APKTOOL, "url": url, "digest_source": "official GitHub release asset digest"}


def gadget(abi: str, version: str) -> tuple[bytes, dict]:
    source = ROOT / "mobile/fixture-app/gadget_release.py"
    spec = importlib.util.spec_from_file_location("vscanner_gadget_release", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    import frida
    if version != frida.__version__:
        raise ValueError("Gadget version must match the installed Frida host")
    raw, origin = module.download_library(version, abi, source.parent / "gadget-cache")
    module.validate_library(raw, abi)
    return raw, origin


def certificate(apk: Path, log: Path) -> dict:
    text = run([JAVA, "-jar", BUILD / "lib/apksigner.jar", "verify", "--verbose",
                "--print-certs", apk], log)
    digests = re.findall(r"Signer(?: #\d+| \(minSdkVersion=\d+, maxSdkVersion=\d+\)) certificate SHA-256 digest: ([0-9a-fA-F]{64})", text)
    digests = list(dict.fromkeys(value.lower() for value in digests))
    if not digests:
        raise ValueError("Verified APK has no signer certificate digest")
    return {"signature_valid": True, "certificate_sha256": digests, "evidence": str(log)}


def sign(unsigned: Path, out: Path, keystore: Path, log_dir: Path, name: str) -> None:
    aligned = log_dir / f"{name}-aligned.apk"
    run([BUILD / "zipalign.exe", "-P", "16", "-f", "4", unsigned, aligned],
        log_dir / f"{name}-zipalign.log")
    run([JAVA, "-jar", BUILD / "lib/apksigner.jar", "sign", "--ks", keystore,
         "--ks-pass", "pass:android", "--key-pass", "pass:android", "--ks-key-alias", "vscanner",
         "--out", out, aligned], log_dir / f"{name}-sign.log")
    run([BUILD / "zipalign.exe", "-c", "-P", "16", "4", out],
        log_dir / f"{name}-align-verify.log")


def test_key(path: Path, log: Path) -> None:
    run([JAVA.parent / "keytool.exe", "-genkeypair", "-keystore", path,
         "-storetype", "PKCS12", "-storepass", "android", "-keypass", "android",
         "-alias", "vscanner", "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650",
         "-dname", "CN=VScanner Authorized Lab,OU=Testing,O=VScanner,C=CN"], log)


def payload(apk: Path) -> dict[str, str]:
    with zipfile.ZipFile(apk) as archive:
        return {name: hashlib.sha256(archive.read(name)).hexdigest()
                for name in archive.namelist() if not name.upper().startswith("META-INF/")
                and not name.endswith("/")}


def metadata(apk: Path, log: Path) -> dict:
    text = run([BUILD / "aapt2.exe", "dump", "badging", apk], log)
    match = re.search(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'", text)
    if not match:
        raise ValueError("aapt2 did not return APK identity")
    return {"package": match[1], "version_code": match[2], "version_name": match[3]}
