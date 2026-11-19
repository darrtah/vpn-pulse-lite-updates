#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

apk_count=0
for channel in beta stable; do
  apks=("$channel"/*.apk)
  if [ "${#apks[@]}" -eq 0 ]; then
    echo "$channel: no signed APK published"
    continue
  fi
  apk_count=$((apk_count + ${#apks[@]}))
  fingerprint_file="$channel/signing-cert-sha256.txt"
  if [ ! -f "$fingerprint_file" ]; then
    echo "ERROR: missing pinned signing certificate: $fingerprint_file" >&2
    exit 1
  fi
  expected=$(tr -d '\r\n ' < "$fingerprint_file" | tr 'A-F' 'a-f')
  if ! [[ "$expected" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ERROR: invalid signing certificate fingerprint: $fingerprint_file" >&2
    exit 1
  fi
done

if [ "$apk_count" -eq 0 ]; then
  echo "No APK to validate: signature checks intentionally skipped"
  exit 0
fi

: "${ANDROID_HOME:?ANDROID_HOME is required to validate APK signatures}"
signer="$ANDROID_HOME/build-tools/35.0.0/apksigner"
if [ ! -x "$signer" ]; then
  sdkmanager --install 'build-tools;35.0.0' >/dev/null
fi
if [ ! -x "$signer" ]; then
  echo "ERROR: Android apksigner 35.0.0 not available" >&2
  exit 1
fi

for channel in beta stable; do
  apks=("$channel"/*.apk)
  if [ "${#apks[@]}" -eq 0 ]; then continue; fi
  expected=$(tr -d '\r\n ' < "$channel/signing-cert-sha256.txt" | tr 'A-F' 'a-f')
  for apk in "${apks[@]}"; do
    report=$("$signer" verify --min-sdk-version 26 --print-certs "$apk")
    actual=$(printf '%s\n' "$report" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -n 1 | tr 'A-F' 'a-f')
    if [ -z "$actual" ] || [ "$expected" != "$actual" ]; then
      echo "ERROR: APK certificate fingerprint mismatch: $apk" >&2
      exit 1
    fi
    echo "Android signature + pinned fingerprint PASS: $apk"
  done
done
