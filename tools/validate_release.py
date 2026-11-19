#!/usr/bin/env python3
"""Validate public update manifests and files. Android APK signatures need apksigner."""
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = "https://darrtah.github.io/vpn-pulse-lite-updates/"
PACKAGES = {"beta": "ru.vpnpulse.lite.beta", "stable": "ru.vpnpulse.lite"}
MAX = 80 * 1024 * 1024

def reject(message):
    raise ValueError(message)

def no_duplicate_keys(items):
    result = {}
    for key, value in items:
        if key in result:
            reject("Duplicate JSON field: " + key)
        result[key] = value
    return result

def validate(channel):
    directory = ROOT / channel
    manifest = directory / "latest.json"
    if not manifest.exists():
        print(channel + ": no published release (expected)")
        return
    if manifest.stat().st_size > 32768:
        reject(channel + ": metadata too large")
    data = json.loads(manifest.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_keys)
    if not isinstance(data, dict):
        reject(channel + ": manifest is not an object")
    code = data.get("versionCode")
    size = data.get("sizeBytes")
    if type(code) is not int or code <= 0:
        reject(channel + ": invalid versionCode")
    if type(size) is not int or not (10000 <= size <= MAX):
        reject(channel + ": invalid sizeBytes")
    if data.get("schema") != 1 or data.get("packageName") != PACKAGES[channel]:
        reject(channel + ": wrong schema or packageName")
    if not isinstance(data.get("versionName"), str) or not (1 <= len(data["versionName"]) <= 80):
        reject(channel + ": invalid versionName")
    notes = data.get("notes")
    if not isinstance(notes, str) or len(notes) > 1000:
        reject(channel + ": invalid release notes")
    sha = data.get("sha256")
    if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha):
        reject(channel + ": invalid sha256")
    name = "vpn-pulse-lite-" + str(code) + ".apk"
    expected = BASE + channel + "/" + name
    if data.get("apkUrl") != expected:
        reject(channel + ": APK URL does not match this HTTPS channel")
    apk = directory / name
    if not apk.is_file():
        reject(channel + ": APK not found: " + name)
    if apk.stat().st_size != size:
        reject(channel + ": file length differs from manifest")
    digest = hashlib.sha256()
    with apk.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    if digest.hexdigest() != sha:
        reject(channel + ": APK SHA-256 mismatch")
    if not zipfile.is_zipfile(apk):
        reject(channel + ": APK is not a ZIP archive")
    print(channel + ": metadata, digest and APK structure PASS (" + name + ")")

def main():
    for channel in PACKAGES:
        validate(channel)
    print("Metadata validation PASS. Verify Android APK signatures separately with apksigner.")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("INVALID RELEASE:", exc, file=sys.stderr)
        sys.exit(1)
