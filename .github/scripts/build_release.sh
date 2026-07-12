#!/usr/bin/env bash

set -euo pipefail

rm -f flic_ble.zip

(
  cd custom_components/flic_ble
  zip -r ../../flic_ble.zip . -x '*__pycache__*' '*.pyc'
)

archive_contents="$(unzip -Z1 flic_ble.zip)"
grep -qx "manifest.json" <<<"${archive_contents}"

if grep -q '^flic_ble/' <<<"${archive_contents}"; then
  echo "Release archive must contain integration files at its root." >&2
  exit 1
fi
