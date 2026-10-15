"""Verified Frida release retrieval for the owned fixture only; no device operations."""
from __future__ import annotations

import hashlib
import json
import lzma
import re
import time
from http.client import IncompleteRead
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ABIS = {"x86_64": ("x86_64", 62), "arm64-v8a": ("arm64", 183)}
MAX_DOWNLOAD = 100 * 1024 * 1024


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class DownloadError(RuntimeError):
    """A bounded official download failed; no incomplete response is trusted."""


def read_url(url: str, *, json_response: bool = False) -> bytes:
    headers = {"User-Agent": "mobile-owned-fixture-gadget-prepare"}
    if json_response:
        headers.update({"Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"})
    # One initial attempt plus at most two transport retries. Validation failures
    # below are deliberately not retried (especially size, URL and SHA256 checks).
    for attempt in range(3):
        try:
            with urlopen(Request(url, headers=headers), timeout=90) as response:
                raw = response.read(MAX_DOWNLOAD + 1)
        except (HTTPError, URLError, IncompleteRead, OSError) as exc:
            if attempt == 2:
                raise DownloadError(
                    f"Official download failed after 3 attempts ({type(exc).__name__}): {url}"
                ) from exc
            time.sleep(0.5 * (attempt + 1))
            continue
        if len(raw) > MAX_DOWNLOAD:
            raise ValueError("Official release response exceeds the size limit")
        return raw
    raise DownloadError("Official download exhausted its bounded attempts")


def official_asset(version: str, abi: str) -> dict:
    """GitHub's release-asset digest is the expected hash, not a self-derived hash."""
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Frida version must be explicit x.y.z")
    name = f"frida-gadget-{version}-android-{ABIS[abi][0]}.so.xz"
    api_url = f"https://api.github.com/repos/frida/frida/releases/tags/{version}"
    release = json.loads(read_url(api_url, json_response=True))
    if release.get("tag_name") != version:
        raise ValueError("Official release tag does not match requested version")
    matches = [a for a in release.get("assets", []) if a.get("name") == name]
    if len(matches) != 1:
        raise ValueError(f"Official release must contain exactly one asset: {name}")
    asset = matches[0]
    expected_url = f"https://github.com/frida/frida/releases/download/{version}/{name}"
    if asset.get("browser_download_url") != expected_url:
        raise ValueError("Unexpected release asset download URL")
    expected = asset.get("digest", "") or ""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
        raise ValueError("Official release has no SHA256 digest; do not silently trust a download")
    return {"source_kind": "official_release", "source_url": expected_url,
            "release_asset": name, "expected_compressed_sha256": expected[7:]}


def download_library(version: str, abi: str, cache: Path) -> tuple[bytes, dict]:
    record = official_asset(version, abi)
    archive = cache / record["release_asset"]
    packed = archive.read_bytes() if archive.exists() else read_url(record["source_url"])
    actual = digest(packed)
    if actual != record["expected_compressed_sha256"]:
        raise ValueError(f"Official archive SHA256 mismatch: {record['release_asset']}")
    cache.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        temporary = archive.with_suffix(archive.suffix + ".tmp")
        temporary.write_bytes(packed)
        temporary.replace(archive)
    record["compressed_sha256"] = actual
    decompressor = lzma.LZMADecompressor()
    raw = decompressor.decompress(packed, max_length=MAX_DOWNLOAD + 1)
    if len(raw) > MAX_DOWNLOAD or not decompressor.eof:
        raise ValueError("Gadget decompression exceeded the limit or archive was truncated")
    return raw, record


def validate_library(raw: bytes, abi: str) -> None:
    """Check ELF class, byte order, DYN type and machine; not a claim of runtime success."""
    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        raise ValueError("Gadget must be a decompressed Android ELF shared library")
    if raw[4:6] != b"\x02\x01" or int.from_bytes(raw[16:18], "little") != 3:
        raise ValueError("Expected a 64-bit, little-endian ELF shared library")
    if int.from_bytes(raw[18:20], "little") != ABIS[abi][1]:
        raise ValueError("Gadget ELF architecture does not match --abi")
