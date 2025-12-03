#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS="$(date +%Y%m%d-%H%M)"
OUT_TAR="verzia_v020-complete-${TS}.tar.gz"

echo "════════════════════════════════════════════════════"
echo " CLEAN REPACKAGE v0.20"
echo " ROOT: $ROOT_DIR"
echo " Date: $(date)"
echo "════════════════════════════════════════════════════"
echo ""

echo "[INFO] Using current files in verzia_v019 (bez ďalších patchov)"
echo "[INFO] Excluding backup adresáre a dočasné veci"
echo ""

cd "$ROOT_DIR/.."

tar -czf "$OUT_TAR" \
  --exclude='verzia_v019/backup-*' \
  --exclude='verzia_v019/*.tar.gz' \
  --exclude='verzia_v019/*.tar.gz.sha256' \
  verzia_v019

sha256sum "$OUT_TAR" > "${OUT_TAR}.sha256"

echo "[OK] New full package: $OUT_TAR"
echo "[OK] SHA256: $(cat "${OUT_TAR}.sha256")"
echo ""
echo "Hotovo. Tento tarball je komplet balík v0.20 (bez backup adresárov)."
