#!/bin/bash
# ═══════════════════════════════════════════════════════════
# FULL PACKAGE FIX & REPACKAGE - verzia_v019 → v0.20
# Fixuje všetky wrappery + vytvorí nový distribučný tar.gz
# ═══════════════════════════════════════════════════════════

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$ROOT_DIR/backup-full-$(date +%Y%m%d-%H%M)"

echo "════════════════════════════════════════════════════"
echo " FULL PACKAGE FIX & REPACKAGE (v0.19 → v0.20)"
echo " ROOT: $ROOT_DIR"
echo " Date: $(date)"
echo "════════════════════════════════════════════════════"
echo ""

# 1) Backup celej distribúcie
mkdir -p "$BACKUP_DIR"
cd "$ROOT_DIR"

for item in *; do
  # preskoč backup adresáre
  [ "$item" = "$(basename "$BACKUP_DIR")" ] && continue
  cp -a "$item" "$BACKUP_DIR"/
done

cd "$ROOT_DIR"
echo ""

# 2) Nájdime všetky wrapper skripty na úpravu
echo "[INFO] Searching for wrapper scripts..."
WRAPPERS=$(grep -Rl "F2BTABLE=\"inet" "$ROOT_DIR" | grep -E 'f2b-wrapper|f2b' || true)

if [ -z "$WRAPPERS" ]; then
  echo "[WARN] No wrapper scripts found to patch."
else
  echo "[INFO] Found wrapper files:"
  echo "$WRAPPERS"
  echo ""
fi

# 3) Aplikuj patchy na všetky nájdené wrapper skripty
for W in $WRAPPERS; do
  echo "────────────────────────────────────────"
  echo "[INFO] Patching wrapper: $W"

  # Fix F2BTABLE
  sed -i 's/F2BTABLE="inet fail2ban-filter"/F2BTABLE="inet f2b-table"/' "$W"

  # Fix SETMAP
  sed -i '/declare -A SETMAP=/,/)/{
s|"sshd"]="f2b-sshd"|"sshd"]="addr-set-sshd"|
s|"manualblock"]="f2b-manualblock"|"manualblock"]="addr-set-manualblock"|
s|"nginx-recon-bonus"]="f2b-nginx-recon-bonus"|"nginx-recon-bonus"]="addr-set-nginx-recon-bonus"|
s|"recidive"]="f2b-recidive"|"recidive"]="addr-set-recidive"|
s|"f2b-exploit-critical"]="f2b-exploit-critical"|"f2b-exploit-critical"]="addr-set-f2b-exploit-critical"|
s|"f2b-dos-high"]="f2b-dos-high"|"f2b-dos-high"]="addr-set-f2b-dos-high"|
s|"f2b-web-medium"]="f2b-web-medium"|"f2b-web-medium"]="addr-set-f2b-web-medium"|
s|"f2b-fuzzing-payloads"]="f2b-fuzzing-payloads"|"f2b-fuzzing-payloads"]="addr-set-f2b-fuzzing-payloads"|
s|"f2b-botnet-signatures"]="f2b-botnet-signatures"|"f2b-botnet-signatures"]="addr-set-f2b-botnet-signatures"|
s|"f2b-anomaly-detection"]="f2b-anomaly-detection"|"f2b-anomaly-detection"]="addr-set-f2b-anomaly-detection"|
}' "$W"

  # Fix grep -qE → grep -qF
  sed -i 's/grep -qE "\$IP"/grep -qF "\$IP"/g' "$W"

  # Bump verzia v0.19 → v0.20 (len v komentároch / banneri)
  sed -i 's/v0\.19/v0.20/g' "$W"

  # Syntax check
  if bash -n "$W"; then
    echo "[OK] Syntax OK: $W"
  else
    echo "[ERROR] Syntax ERROR in $W, restoring backup..."
    cp "$BACKUP_DIR/$(realpath --relative-to="$ROOT_DIR" "$W")" "$W"
    exit 1
  fi
done

echo ""
echo "────────────────────────────────────────"
echo "[INFO] Wrapper patching done."
echo ""

# 4) Aktualizuj názvy tar.gz a referencie vo vnútri balíka

echo "[INFO] Renaming wrapper tarballs (v0.19 → v0.20)..."

cd "$ROOT_DIR"

if [ -f "f2b-wrapper-v0.19-production-ready.tar.gz" ]; then
  mv f2b-wrapper-v0.19-production-ready.tar.gz f2b-wrapper-v0.20-production-ready.tar.gz
fi

if [ -f "f2b-wrapper-v0.19-production-ready.tar.gz.sha256" ]; then
  mv f2b-wrapper-v0.19-production-ready.tar.gz.sha256 f2b-wrapper-v0.20-production-ready.tar.gz.sha256
fi

# Pre istotu pregeneruj sha256 pre nový tar (ak si ho už vytvoril zvlášť, toto len prepíše)
if [ -f "f2b-wrapper-v0.20-production-ready.tar.gz" ]; then
  sha256sum f2b-wrapper-v0.20-production-ready.tar.gz > f2b-wrapper-v0.20-production-ready.tar.gz.sha256
fi

echo "[OK] Tarball names updated (if present)"
echo ""

# 5) Upraviť INSTALL-ALL a 04-install-wrapper referencie na v0.20

echo "[INFO] Updating installer scripts references (v0.19 → v0.20)..."

# 04-install-wrapper skript
if [ -f "04-install-wrapper-v019.sh" ]; then
  sed -i 's/f2b-wrapper-v0.19-production-ready.tar.gz/f2b-wrapper-v0.20-production-ready.tar.gz/g' 04-install-wrapper-v019.sh
  sed -i 's/v0.19/v0.20/g' 04-install-wrapper-v019.sh
fi

# Ak máš v INSTALL-ALL textovú zmienku o verzii wrappera:
if [ -f "INSTALL-ALL-v019.sh" ]; then
  sed -i 's/v0.19/v0.20/g' INSTALL-ALL-v019.sh
fi

echo "[OK] Installer references updated (where applicable)"
echo ""

# 6) Vytvor kompletný distribučný archív

cd "$ROOT_DIR/.."
OUT_TAR="verzia_v020-complete-$(date +%Y%m%d-%H%M).tar.gz"

echo "[INFO] Creating full package tarball: $OUT_TAR"
tar -czf "$OUT_TAR" "verzia_v019"

sha256sum "$OUT_TAR" > "$OUT_TAR.sha256"

echo "[OK] New full package: $OUT_TAR"
echo "[OK] SHA256: $(cat "$OUT_TAR.sha256")"
echo ""
echo "════════════════════════════════════════════════════"
echo " FULL PACKAGE FIX & REPACKAGE DONE"
echo "  - Source dir : $ROOT_DIR"
echo "  - Backup     : $BACKUP_DIR"
echo "  - New tar.gz : $OUT_TAR"
echo "════════════════════════════════════════════════════"
